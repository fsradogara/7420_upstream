// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2016-2018 Oracle. All rights reserved.
 * Copyright (c) 2014 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2005-2006 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Tom Tucker <tom@opengridcomputing.com>
 */

/* Operation
 *
 * The main entry point is svc_rdma_sendto. This is called by the
 * RPC server when an RPC Reply is ready to be transmitted to a client.
 *
 * The passed-in svc_rqst contains a struct xdr_buf which holds an
 * XDR-encoded RPC Reply message. sendto must construct the RPC-over-RDMA
 * transport header, post all Write WRs needed for this Reply, then post
 * a Send WR conveying the transport header and the RPC message itself to
 * the client.
 *
 * svc_rdma_sendto must fully transmit the Reply before returning, as
 * the svc_rqst will be recycled as soon as sendto returns. Remaining
 * resources referred to by the svc_rqst are also recycled at that time.
 * Therefore any resources that must remain longer must be detached
 * from the svc_rqst and released later.
 *
 * Page Management
 *
 * The I/O that performs Reply transmission is asynchronous, and may
 * complete well after sendto returns. Thus pages under I/O must be
 * removed from the svc_rqst before sendto returns.
 *
 * The logic here depends on Send Queue and completion ordering. Since
 * the Send WR is always posted last, it will always complete last. Thus
 * when it completes, it is guaranteed that all previous Write WRs have
 * also completed.
 *
 * Write WRs are constructed and posted. Each Write segment gets its own
 * svc_rdma_rw_ctxt, allowing the Write completion handler to find and
 * DMA-unmap the pages under I/O for that Write segment. The Write
 * completion handler does not release any pages.
 *
 * When the Send WR is constructed, it also gets its own svc_rdma_send_ctxt.
 * The ownership of all of the Reply's pages are transferred into that
 * ctxt, the Send WR is posted, and sendto returns.
 *
 * The svc_rdma_send_ctxt is presented when the Send WR completes. The
 * Send completion handler finally releases the Reply's pages.
 *
 * This mechanism also assumes that completions on the transport's Send
 * Completion Queue do not run in parallel. Otherwise a Write completion
 * and Send completion running at the same time could release pages that
 * are still DMA-mapped.
 *
 * Error Handling
 *
 * - If the Send WR is posted successfully, it will either complete
 *   successfully, or get flushed. Either way, the Send completion
 *   handler releases the Reply's pages.
 * - If the Send WR cannot be not posted, the forward path releases
 *   the Reply's pages.
 *
 * This handles the case, without the use of page reference counting,
 * where two different Write segments send portions of the same page.
 */

#include <linux/spinlock.h>
#include <asm/unaligned.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include <linux/sunrpc/debug.h>
#include <linux/sunrpc/rpc_rdma.h>
#include <linux/sunrpc/svc_rdma.h>

#include "xprt_rdma.h"
#include <trace/events/rpcrdma.h>

#define RPCDBG_FACILITY	RPCDBG_SVCXPRT

/* Encode an XDR as an array of IB SGE
 *
 * Assumptions:
 * - head[0] is physically contiguous.
 * - tail[0] is physically contiguous.
 * - pages[] is not physically or virtually contigous and consists of
 *   PAGE_SIZE elements.
 *
 * Output:
 * SGE[0]              reserved for RCPRDMA header
 * SGE[1]              data from xdr->head[]
 * SGE[2..sge_count-2] data from xdr->pages[]
 * SGE[sge_count-1]    data from xdr->tail.
 *
 * The max SGE we need is the length of the XDR / pagesize + one for
 * head + one for tail + one for RPCRDMA header. Since RPCSVC_MAXPAGES
 * reserves a page for both the request and the reply header, and this
 * array is only concerned with the reply we are assured that we have
 * on extra page for the RPCRMDA header.
 */
static void xdr_to_sge(struct svcxprt_rdma *xprt,
		       struct xdr_buf *xdr,
		       struct svc_rdma_req_map *vec)
{
	int sge_max = (xdr->len+PAGE_SIZE-1) / PAGE_SIZE + 3;
static int map_xdr(struct svcxprt_rdma *xprt,
		   struct xdr_buf *xdr,
		   struct svc_rdma_req_map *vec)
{
	int sge_no;
	u32 sge_bytes;
	u32 page_bytes;
	u32 page_off;
	int page_no;

	BUG_ON(xdr->len !=
	       (xdr->head[0].iov_len + xdr->page_len + xdr->tail[0].iov_len));
	if (xdr->len !=
	    (xdr->head[0].iov_len + xdr->page_len + xdr->tail[0].iov_len)) {
		pr_err("svcrdma: map_xdr: XDR buffer length error\n");
		return -EIO;
	}

	/* Skip the first sge, this is for the RPCRDMA header */
	sge_no = 1;

	/* Head SGE */
	vec->sge[sge_no].iov_base = xdr->head[0].iov_base;
	vec->sge[sge_no].iov_len = xdr->head[0].iov_len;
	sge_no++;

	/* pages SGE */
	page_no = 0;
	page_bytes = xdr->page_len;
	page_off = xdr->page_base;
	while (page_bytes) {
		vec->sge[sge_no].iov_base =
			page_address(xdr->pages[page_no]) + page_off;
		sge_bytes = min_t(u32, page_bytes, (PAGE_SIZE - page_off));
		page_bytes -= sge_bytes;
		vec->sge[sge_no].iov_len = sge_bytes;

		sge_no++;
		page_no++;
		page_off = 0; /* reset for next time through loop */
	}

	/* Tail SGE */
	if (xdr->tail[0].iov_len) {
		vec->sge[sge_no].iov_base = xdr->tail[0].iov_base;
		vec->sge[sge_no].iov_len = xdr->tail[0].iov_len;
		sge_no++;
	}

	BUG_ON(sge_no > sge_max);
	vec->count = sge_no;
	dprintk("svcrdma: map_xdr: sge_no %d page_no %d "
		"page_base %u page_len %u head_len %zu tail_len %zu\n",
		sge_no, page_no, xdr->page_base, xdr->page_len,
		xdr->head[0].iov_len, xdr->tail[0].iov_len);

	vec->count = sge_no;
	return 0;
static void svc_rdma_wc_send(struct ib_cq *cq, struct ib_wc *wc);

static inline struct svc_rdma_send_ctxt *
svc_rdma_next_send_ctxt(struct list_head *list)
{
	return list_first_entry_or_null(list, struct svc_rdma_send_ctxt,
					sc_list);
}

static struct svc_rdma_send_ctxt *
svc_rdma_send_ctxt_alloc(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_send_ctxt *ctxt;
	dma_addr_t addr;
	void *buffer;
	size_t size;
	int i;

	size = sizeof(*ctxt);
	size += rdma->sc_max_send_sges * sizeof(struct ib_sge);
	ctxt = kmalloc(size, GFP_KERNEL);
	if (!ctxt)
		goto fail0;
	buffer = kmalloc(rdma->sc_max_req_size, GFP_KERNEL);
	if (!buffer)
		goto fail1;
	addr = ib_dma_map_single(rdma->sc_pd->device, buffer,
				 rdma->sc_max_req_size, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(rdma->sc_pd->device, addr))
		goto fail2;

	ctxt->sc_send_wr.next = NULL;
	ctxt->sc_send_wr.wr_cqe = &ctxt->sc_cqe;
	ctxt->sc_send_wr.sg_list = ctxt->sc_sges;
	ctxt->sc_send_wr.send_flags = IB_SEND_SIGNALED;
	ctxt->sc_cqe.done = svc_rdma_wc_send;
	ctxt->sc_xprt_buf = buffer;
	ctxt->sc_sges[0].addr = addr;

	for (i = 0; i < rdma->sc_max_send_sges; i++)
		ctxt->sc_sges[i].lkey = rdma->sc_pd->local_dma_lkey;
	return ctxt;

fail2:
	kfree(buffer);
fail1:
	kfree(ctxt);
fail0:
	return NULL;
}

/**
 * svc_rdma_send_ctxts_destroy - Release all send_ctxt's for an xprt
 * @rdma: svcxprt_rdma being torn down
 *
 */
void svc_rdma_send_ctxts_destroy(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_send_ctxt *ctxt;

	while ((ctxt = svc_rdma_next_send_ctxt(&rdma->sc_send_ctxts))) {
		list_del(&ctxt->sc_list);
		ib_dma_unmap_single(rdma->sc_pd->device,
				    ctxt->sc_sges[0].addr,
				    rdma->sc_max_req_size,
				    DMA_TO_DEVICE);
		kfree(ctxt->sc_xprt_buf);
		kfree(ctxt);
	}
}

/**
 * svc_rdma_send_ctxt_get - Get a free send_ctxt
 * @rdma: controlling svcxprt_rdma
 *
 * Returns a ready-to-use send_ctxt, or NULL if none are
 * available and a fresh one cannot be allocated.
 */
struct svc_rdma_send_ctxt *svc_rdma_send_ctxt_get(struct svcxprt_rdma *rdma)
{
	struct svc_rdma_send_ctxt *ctxt;

	spin_lock(&rdma->sc_send_lock);
	ctxt = svc_rdma_next_send_ctxt(&rdma->sc_send_ctxts);
	if (!ctxt)
		goto out_empty;
	list_del(&ctxt->sc_list);
	spin_unlock(&rdma->sc_send_lock);

out:
	ctxt->sc_send_wr.num_sge = 0;
	ctxt->sc_cur_sge_no = 0;
	ctxt->sc_page_count = 0;
	return ctxt;

out_empty:
	spin_unlock(&rdma->sc_send_lock);
	ctxt = svc_rdma_send_ctxt_alloc(rdma);
	if (!ctxt)
		return NULL;
	goto out;
}

/**
 * svc_rdma_send_ctxt_put - Return send_ctxt to free list
 * @rdma: controlling svcxprt_rdma
 * @ctxt: object to return to the free list
 *
 * Pages left in sc_pages are DMA unmapped and released.
 */
void svc_rdma_send_ctxt_put(struct svcxprt_rdma *rdma,
			    struct svc_rdma_send_ctxt *ctxt)
{
	struct ib_device *device = rdma->sc_cm_id->device;
	unsigned int i;

	/* The first SGE contains the transport header, which
	 * remains mapped until @ctxt is destroyed.
	 */
	for (i = 1; i < ctxt->sc_send_wr.num_sge; i++)
		ib_dma_unmap_page(device,
				  ctxt->sc_sges[i].addr,
				  ctxt->sc_sges[i].length,
				  DMA_TO_DEVICE);

	for (i = 0; i < ctxt->sc_page_count; ++i)
		put_page(ctxt->sc_pages[i]);

	spin_lock(&rdma->sc_send_lock);
	list_add(&ctxt->sc_list, &rdma->sc_send_ctxts);
	spin_unlock(&rdma->sc_send_lock);
}

/**
 * svc_rdma_wc_send - Invoked by RDMA provider for each polled Send WC
 * @cq: Completion Queue context
 * @wc: Work Completion object
 *
 * NB: The svc_xprt/svcxprt_rdma is pinned whenever it's possible that
 * the Send completion handler could be running.
 */
static void svc_rdma_wc_send(struct ib_cq *cq, struct ib_wc *wc)
{
	struct svcxprt_rdma *rdma = cq->cq_context;
	struct ib_cqe *cqe = wc->wr_cqe;
	struct svc_rdma_send_ctxt *ctxt;

	trace_svcrdma_wc_send(wc);

	atomic_inc(&rdma->sc_sq_avail);
	wake_up(&rdma->sc_send_wait);

	ctxt = container_of(cqe, struct svc_rdma_send_ctxt, sc_cqe);
	svc_rdma_send_ctxt_put(rdma, ctxt);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		set_bit(XPT_CLOSE, &rdma->sc_xprt.xpt_flags);
		svc_xprt_enqueue(&rdma->sc_xprt);
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			pr_err("svcrdma: Send: %s (%u/0x%x)\n",
			       ib_wc_status_msg(wc->status),
			       wc->status, wc->vendor_err);
	}

	svc_xprt_put(&rdma->sc_xprt);
}

/**
 * svc_rdma_send - Post a single Send WR
 * @rdma: transport on which to post the WR
 * @wr: prepared Send WR to post
 *
 * Returns zero the Send WR was posted successfully. Otherwise, a
 * negative errno is returned.
 */
int svc_rdma_send(struct svcxprt_rdma *rdma, struct ib_send_wr *wr)
{
	int ret;

	might_sleep();

	/* If the SQ is full, wait until an SQ entry is available */
	while (1) {
		if ((atomic_dec_return(&rdma->sc_sq_avail) < 0)) {
			atomic_inc(&rdma_stat_sq_starve);
			trace_svcrdma_sq_full(rdma);
			atomic_inc(&rdma->sc_sq_avail);
			wait_event(rdma->sc_send_wait,
				   atomic_read(&rdma->sc_sq_avail) > 1);
			if (test_bit(XPT_CLOSE, &rdma->sc_xprt.xpt_flags))
				return -ENOTCONN;
			trace_svcrdma_sq_retry(rdma);
			continue;
		}

		svc_xprt_get(&rdma->sc_xprt);
		ret = ib_post_send(rdma->sc_qp, wr, NULL);
		trace_svcrdma_post_send(wr, ret);
		if (ret) {
			set_bit(XPT_CLOSE, &rdma->sc_xprt.xpt_flags);
			svc_xprt_put(&rdma->sc_xprt);
			wake_up(&rdma->sc_send_wait);
		}
		break;
	}
	return ret;
}

static u32 xdr_padsize(u32 len)
{
	return (len & 3) ? (4 - (len & 3)) : 0;
}

/* Returns length of transport header, in bytes.
 */
static unsigned int svc_rdma_reply_hdr_len(__be32 *rdma_resp)
{
	unsigned int nsegs;
	__be32 *p;

	p = rdma_resp;

	/* RPC-over-RDMA V1 replies never have a Read list. */
	p += rpcrdma_fixed_maxsz + 1;

	/* Skip Write list. */
	while (*p++ != xdr_zero) {
		nsegs = be32_to_cpup(p++);
		p += nsegs * rpcrdma_segment_maxsz;
	}

	/* Skip Reply chunk. */
	if (*p++ != xdr_zero) {
		nsegs = be32_to_cpup(p++);
		p += nsegs * rpcrdma_segment_maxsz;
	}

	return (unsigned long)p - (unsigned long)rdma_resp;
}

/* One Write chunk is copied from Call transport header to Reply
 * transport header. Each segment's length field is updated to
 * reflect number of bytes consumed in the segment.
 *
 * Returns number of segments in this chunk.
 */
static unsigned int xdr_encode_write_chunk(__be32 *dst, __be32 *src,
					   unsigned int remaining)
{
	unsigned int i, nsegs;
	u32 seg_len;

	/* Write list discriminator */
	*dst++ = *src++;

	/* number of segments in this chunk */
	nsegs = be32_to_cpup(src);
	*dst++ = *src++;

	for (i = nsegs; i; i--) {
		/* segment's RDMA handle */
		*dst++ = *src++;

		/* bytes returned in this segment */
		seg_len = be32_to_cpu(*src);
		if (remaining >= seg_len) {
			/* entire segment was consumed */
			*dst = *src;
			remaining -= seg_len;
		} else {
			/* segment only partly filled */
			*dst = cpu_to_be32(remaining);
			remaining = 0;
		}
		dst++; src++;

		/* segment's RDMA offset */
		*dst++ = *src++;
		*dst++ = *src++;
	}

	return nsegs;
}

/* The client provided a Write list in the Call message. Fill in
 * the segments in the first Write chunk in the Reply's transport
 * header with the number of bytes consumed in each segment.
 * Remaining chunks are returned unused.
 *
 * Assumptions:
 *  - Client has provided only one Write chunk
 */
static void svc_rdma_xdr_encode_write_list(__be32 *rdma_resp, __be32 *wr_ch,
					   unsigned int consumed)
{
	unsigned int nsegs;
	__be32 *p, *q;

	/* RPC-over-RDMA V1 replies never have a Read list. */
	p = rdma_resp + rpcrdma_fixed_maxsz + 1;

	q = wr_ch;
	while (*q != xdr_zero) {
		nsegs = xdr_encode_write_chunk(p, q, consumed);
		q += 2 + nsegs * rpcrdma_segment_maxsz;
		p += 2 + nsegs * rpcrdma_segment_maxsz;
		consumed = 0;
	}

	/* Terminate Write list */
	*p++ = xdr_zero;

	/* Reply chunk discriminator; may be replaced later */
	*p = xdr_zero;
}

/* The client provided a Reply chunk in the Call message. Fill in
 * the segments in the Reply chunk in the Reply message with the
 * number of bytes consumed in each segment.
 *
 * Assumptions:
 * - Reply can always fit in the provided Reply chunk
 */
static void svc_rdma_xdr_encode_reply_chunk(__be32 *rdma_resp, __be32 *rp_ch,
					    unsigned int consumed)
{
	__be32 *p;

	/* Find the Reply chunk in the Reply's xprt header.
	 * RPC-over-RDMA V1 replies never have a Read list.
	 */
	p = rdma_resp + rpcrdma_fixed_maxsz + 1;

	/* Skip past Write list */
	while (*p++ != xdr_zero)
		p += 1 + be32_to_cpup(p) * rpcrdma_segment_maxsz;

	xdr_encode_write_chunk(p, rp_ch, consumed);
}

/* Parse the RPC Call's transport header.
 */
static void svc_rdma_get_write_arrays(__be32 *rdma_argp,
				      __be32 **write, __be32 **reply)
{
	struct ib_send_wr write_wr;
	struct ib_rdma_wr write_wr;
	struct ib_sge *sge;
	int xdr_sge_no;
	int sge_no;
	int sge_bytes;
	int sge_off;
	int bc;
	struct svc_rdma_op_ctxt *ctxt;

	BUG_ON(vec->count > RPCSVC_MAXPAGES);
	if (vec->count > RPCSVC_MAXPAGES) {
		pr_err("svcrdma: Too many pages (%lu)\n", vec->count);
		return -EIO;
	__be32 *p;

	p = rdma_argp + rpcrdma_fixed_maxsz;

	/* Read list */
	while (*p++ != xdr_zero)
		p += 5;

	/* Write list */
	if (*p != xdr_zero) {
		*write = p;
		while (*p++ != xdr_zero)
			p += 1 + be32_to_cpu(*p) * 4;
	} else {
		*write = NULL;
		p++;
	}

	/* Reply chunk */
	if (*p != xdr_zero)
		*reply = p;
	else
		*reply = NULL;
}

/* RPC-over-RDMA Version One private extension: Remote Invalidation.
 * Responder's choice: requester signals it can handle Send With
 * Invalidate, and responder chooses one rkey to invalidate.
 *
 * Find a candidate rkey to invalidate when sending a reply.  Picks the
 * first R_key it finds in the chunk lists.
 *
 * Returns zero if RPC's chunk lists are empty.
 */
static u32 svc_rdma_get_inv_rkey(__be32 *rdma_argp,
				 __be32 *wr_lst, __be32 *rp_ch)
{
	__be32 *p;

	p = rdma_argp + rpcrdma_fixed_maxsz;
	if (*p != xdr_zero)
		p += 2;
	else if (wr_lst && be32_to_cpup(wr_lst + 1))
		p = wr_lst + 2;
	else if (rp_ch && be32_to_cpup(rp_ch + 1))
		p = rp_ch + 2;
	else
		return 0;
	return be32_to_cpup(p);
}

/* ib_dma_map_page() is used here because svc_rdma_dma_unmap()
 * is used during completion to DMA-unmap this memory, and
 * it uses ib_dma_unmap_page() exclusively.
 */
static int svc_rdma_dma_map_buf(struct svcxprt_rdma *rdma,
				struct svc_rdma_op_ctxt *ctxt,
				unsigned int sge_no,
				unsigned char *base,
				unsigned int len)
{
	unsigned long offset = (unsigned long)base & ~PAGE_MASK;
	struct ib_device *dev = rdma->sc_cm_id->device;
	dma_addr_t dma_addr;

	/* Copy the remaining SGE */
	while (bc != 0 && xdr_sge_no < vec->count) {
		sge[sge_no].lkey = xprt->sc_phys_mr->lkey;
		sge_bytes = min((size_t)bc,
				(size_t)(vec->sge[xdr_sge_no].iov_len-sge_off));
		sge[sge_no].length = sge_bytes;
		atomic_inc(&xprt->sc_dma_used);
		sge[sge_no].addr =
			ib_dma_map_single(xprt->sc_cm_id->device,
					  (void *)
					  vec->sge[xdr_sge_no].iov_base + sge_off,
					  sge_bytes, DMA_TO_DEVICE);
		if (dma_mapping_error(xprt->sc_cm_id->device->dma_device,
					sge[sge_no].addr))
			goto err;
		sge_off = 0;
		sge_no++;
		ctxt->count++;
		xdr_sge_no++;
		bc -= sge_bytes;
	}

	BUG_ON(bc != 0);
	BUG_ON(xdr_sge_no > vec->count);

	/* Prepare WRITE WR */
	memset(&write_wr, 0, sizeof write_wr);
	ctxt->wr_op = IB_WR_RDMA_WRITE;
	write_wr.wr_id = (unsigned long)ctxt;
	write_wr.sg_list = &sge[0];
	write_wr.num_sge = sge_no;
	write_wr.opcode = IB_WR_RDMA_WRITE;
	write_wr.send_flags = IB_SEND_SIGNALED;
	write_wr.wr.rdma.rkey = rmr;
	write_wr.wr.rdma.remote_addr = to;

	/* Post It */
	atomic_inc(&rdma_stat_write);
	if (svc_rdma_send(xprt, &write_wr))
		goto err;
	return 0;
 err:
	while (bc != 0) {
		sge_bytes = min_t(size_t,
			  bc, vec->sge[xdr_sge_no].iov_len-sge_off);
		sge[sge_no].length = sge_bytes;
		sge[sge_no].addr =
			dma_map_xdr(xprt, &rqstp->rq_res, xdr_off,
				    sge_bytes, DMA_TO_DEVICE);
		xdr_off += sge_bytes;
		if (ib_dma_mapping_error(xprt->sc_cm_id->device,
					 sge[sge_no].addr))
			goto err;
		atomic_inc(&xprt->sc_dma_used);
		sge[sge_no].lkey = xprt->sc_dma_lkey;
		ctxt->count++;
		sge_off = 0;
		sge_no++;
		xdr_sge_no++;
		if (xdr_sge_no > vec->count) {
			pr_err("svcrdma: Too many sges (%d)\n", xdr_sge_no);
			goto err;
		}
		bc -= sge_bytes;
		if (sge_no == xprt->sc_max_sge)
			break;
	}
	dma_addr = ib_dma_map_page(dev, virt_to_page(base),
				   offset, len, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, dma_addr))
		goto out_maperr;

	ctxt->sge[sge_no].addr = dma_addr;
	ctxt->sge[sge_no].length = len;
	ctxt->sge[sge_no].lkey = rdma->sc_pd->local_dma_lkey;
	svc_rdma_count_mappings(rdma, ctxt);
	return 0;

out_maperr:
	pr_err("svcrdma: failed to map buffer\n");
	return -EIO;
}

static int svc_rdma_dma_map_page(struct svcxprt_rdma *rdma,
				 struct svc_rdma_send_ctxt *ctxt,
				 struct page *page,
				 unsigned long offset,
				 unsigned int len)
{
	u32 xfer_len = rqstp->rq_res.page_len + rqstp->rq_res.tail[0].iov_len;
	int write_len;
	int max_write;
	u32 xdr_off;
	int chunk_off;
	int chunk_no;
	u32 xdr_off;
	int chunk_off;
	int chunk_no;
	int nchunks;
	struct rpcrdma_write_array *arg_ary;
	struct rpcrdma_write_array *res_ary;
	int ret;
	struct ib_device *dev = rdma->sc_cm_id->device;
	dma_addr_t dma_addr;

	dma_addr = ib_dma_map_page(dev, page, offset, len, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(dev, dma_addr))
		goto out_maperr;

	max_write = xprt->sc_max_sge * PAGE_SIZE;

	/* Write chunks start at the pagelist */
	for (xdr_off = rqstp->rq_res.head[0].iov_len, chunk_no = 0;
	     xfer_len && chunk_no < arg_ary->wc_nchunks;
	/* Write chunks start at the pagelist */
	nchunks = be32_to_cpu(arg_ary->wc_nchunks);
	for (xdr_off = rqstp->rq_res.head[0].iov_len, chunk_no = 0;
	     xfer_len && chunk_no < nchunks;
	     chunk_no++) {
		struct rpcrdma_segment *arg_ch;
		u64 rs_offset;

		arg_ch = &arg_ary->wc_array[chunk_no].wc_target;
		write_len = min(xfer_len, arg_ch->rs_length);

		/* Prepare the response chunk given the length actually
		 * written */
		rs_offset = get_unaligned(&(arg_ch->rs_offset));
		svc_rdma_xdr_encode_array_chunk(res_ary, chunk_no,
					    arg_ch->rs_handle,
					    rs_offset,
					    write_len);
		chunk_off = 0;
		while (write_len) {
			int this_write;
			this_write = min(write_len, max_write);
			ret = send_write(xprt, rqstp,
					 arg_ch->rs_handle,
					 rs_offset + chunk_off,
					 xdr_off,
					 this_write,
					 vec);
			if (ret) {
		write_len = min(xfer_len, be32_to_cpu(arg_ch->rs_length));

		/* Prepare the response chunk given the length actually
		 * written */
		xdr_decode_hyper((__be32 *)&arg_ch->rs_offset, &rs_offset);
		svc_rdma_xdr_encode_array_chunk(res_ary, chunk_no,
						arg_ch->rs_handle,
						arg_ch->rs_offset,
						write_len);
		chunk_off = 0;
		while (write_len) {
			ret = send_write(xprt, rqstp,
					 be32_to_cpu(arg_ch->rs_handle),
					 rs_offset + chunk_off,
					 xdr_off,
					 write_len,
					 vec);
			if (ret <= 0) {
				dprintk("svcrdma: RDMA_WRITE failed, ret=%d\n",
					ret);
				return -EIO;
			}
			chunk_off += this_write;
			xdr_off += this_write;
			xfer_len -= this_write;
			write_len -= this_write;
			chunk_off += ret;
			xdr_off += ret;
			xfer_len -= ret;
			write_len -= ret;
		}
	}
	/* Update the req with the number of chunks actually used */
	svc_rdma_xdr_encode_write_list(rdma_resp, chunk_no);

	return rqstp->rq_res.page_len + rqstp->rq_res.tail[0].iov_len;
}

static int send_reply_chunks(struct svcxprt_rdma *xprt,
			     struct rpcrdma_msg *rdma_argp,
			     struct rpcrdma_msg *rdma_resp,
			     struct svc_rqst *rqstp,
			     struct svc_rdma_req_map *vec)
{
	u32 xfer_len = rqstp->rq_res.len;
	int write_len;
	int max_write;
	u32 xdr_off;
	int chunk_no;
	int chunk_off;
	u32 xdr_off;
	int chunk_no;
	int chunk_off;
	int nchunks;
	struct rpcrdma_segment *ch;
	struct rpcrdma_write_array *arg_ary;
	struct rpcrdma_write_array *res_ary;
	int ret;

	arg_ary = svc_rdma_get_reply_array(rdma_argp);
	if (!arg_ary)
		return 0;
	/* XXX: need to fix when reply lists occur with read-list and or
	 * write-list */
	res_ary = (struct rpcrdma_write_array *)
		&rdma_resp->rm_body.rm_chunks[2];

	max_write = xprt->sc_max_sge * PAGE_SIZE;

	/* xdr offset starts at RPC message */
	for (xdr_off = 0, chunk_no = 0;
	     xfer_len && chunk_no < arg_ary->wc_nchunks;
	     chunk_no++) {
		u64 rs_offset;
		ch = &arg_ary->wc_array[chunk_no].wc_target;
		write_len = min(xfer_len, ch->rs_length);


		/* Prepare the reply chunk given the length actually
		 * written */
		rs_offset = get_unaligned(&(ch->rs_offset));
		svc_rdma_xdr_encode_array_chunk(res_ary, chunk_no,
					    ch->rs_handle, rs_offset,
					    write_len);
		chunk_off = 0;
		while (write_len) {
			int this_write;

			this_write = min(write_len, max_write);
			ret = send_write(xprt, rqstp,
					 ch->rs_handle,
					 rs_offset + chunk_off,
					 xdr_off,
					 this_write,
					 vec);
			if (ret) {
	/* xdr offset starts at RPC message */
	nchunks = be32_to_cpu(arg_ary->wc_nchunks);
	for (xdr_off = 0, chunk_no = 0;
	     xfer_len && chunk_no < nchunks;
	     chunk_no++) {
		u64 rs_offset;
		ch = &arg_ary->wc_array[chunk_no].wc_target;
		write_len = min(xfer_len, be32_to_cpu(ch->rs_length));

		/* Prepare the reply chunk given the length actually
		 * written */
		xdr_decode_hyper((__be32 *)&ch->rs_offset, &rs_offset);
		svc_rdma_xdr_encode_array_chunk(res_ary, chunk_no,
						ch->rs_handle, ch->rs_offset,
						write_len);
		chunk_off = 0;
		while (write_len) {
			ret = send_write(xprt, rqstp,
					 be32_to_cpu(ch->rs_handle),
					 rs_offset + chunk_off,
					 xdr_off,
					 write_len,
					 vec);
			if (ret <= 0) {
				dprintk("svcrdma: RDMA_WRITE failed, ret=%d\n",
					ret);
				return -EIO;
			}
			chunk_off += this_write;
			xdr_off += this_write;
			xfer_len -= this_write;
			write_len -= this_write;
			chunk_off += ret;
			xdr_off += ret;
			xfer_len -= ret;
			write_len -= ret;
		}
	}
	/* Update the req with the number of chunks actually used */
	svc_rdma_xdr_encode_reply_array(res_ary, chunk_no);

	return rqstp->rq_res.len;
}

/* This function prepares the portion of the RPCRDMA message to be
 * sent in the RDMA_SEND. This function is called after data sent via
 * RDMA has already been transmitted. There are three cases:
 * - The RPCRDMA header, RPC header, and payload are all sent in a
 *   single RDMA_SEND. This is the "inline" case.
 * - The RPCRDMA header and some portion of the RPC header and data
 *   are sent via this RDMA_SEND and another portion of the data is
 *   sent via RDMA.
 * - The RPCRDMA header [NOMSG] is sent in this RDMA_SEND and the RPC
 *   header and data are all transmitted via RDMA.
 * In all three cases, this function prepares the RPCRDMA header in
 * sge[0], the 'type' parameter indicates the type to place in the
 * RPCRDMA header, and the 'byte_count' field indicates how much of
 * the XDR to include in this RDMA_SEND.
 * the XDR to include in this RDMA_SEND. NB: The offset of the payload
 * to send is zero in the XDR.
	ctxt->sge[sge_no].addr = dma_addr;
	ctxt->sge[sge_no].length = len;
	ctxt->sge[sge_no].lkey = rdma->sc_pd->local_dma_lkey;
	svc_rdma_count_mappings(rdma, ctxt);
	ctxt->sc_sges[ctxt->sc_cur_sge_no].addr = dma_addr;
	ctxt->sc_sges[ctxt->sc_cur_sge_no].length = len;
	ctxt->sc_send_wr.num_sge++;
	return 0;

out_maperr:
	trace_svcrdma_dma_map_page(rdma, page);
	return -EIO;
}

/* ib_dma_map_page() is used here because svc_rdma_dma_unmap()
 * handles DMA-unmap and it uses ib_dma_unmap_page() exclusively.
 */
static int svc_rdma_dma_map_buf(struct svcxprt_rdma *rdma,
				struct svc_rdma_send_ctxt *ctxt,
				unsigned char *base,
				unsigned int len)
{
	struct ib_send_wr send_wr;
	int sge_no;
	int sge_bytes;
	int page_no;
	u32 xdr_off;
	int sge_no;
	int sge_bytes;
	int page_no;
	int pages;
	ctxt->direction = DMA_TO_DEVICE;
	ctxt->pages[0] = virt_to_page(rdma_resp);
	ctxt->count = 1;
	return svc_rdma_dma_map_page(rdma, ctxt, 0, ctxt->pages[0], 0, len);
	return svc_rdma_dma_map_page(rdma, ctxt, virt_to_page(base),
				     offset_in_page(base), len);
}

/**
 * svc_rdma_sync_reply_hdr - DMA sync the transport header buffer
 * @rdma: controlling transport
 * @ctxt: send_ctxt for the Send WR
 * @len: length of transport header
 *
 */
void svc_rdma_sync_reply_hdr(struct svcxprt_rdma *rdma,
			     struct svc_rdma_send_ctxt *ctxt,
			     unsigned int len)
{
	ctxt->sc_sges[0].length = len;
	ctxt->sc_send_wr.num_sge++;
	ib_dma_sync_single_for_device(rdma->sc_pd->device,
				      ctxt->sc_sges[0].addr, len,
				      DMA_TO_DEVICE);
}

/* svc_rdma_map_reply_msg - Map the buffer holding RPC message
 * @rdma: controlling transport
 * @ctxt: send_ctxt for the Send WR
 * @xdr: prepared xdr_buf containing RPC message
 * @wr_lst: pointer to Call header's Write list, or NULL
 *
 * Load the xdr_buf into the ctxt's sge array, and DMA map each
 * element as it is added.
 *
 * Returns zero on success, or a negative errno on failure.
 */
int svc_rdma_map_reply_msg(struct svcxprt_rdma *rdma,
			   struct svc_rdma_send_ctxt *ctxt,
			   struct xdr_buf *xdr, __be32 *wr_lst)
{
	unsigned int len, remaining;
	unsigned long page_off;
	struct page **ppages;
	unsigned char *base;
	u32 xdr_pad;
	int ret;

	if (++ctxt->sc_cur_sge_no >= rdma->sc_max_send_sges)
		return -EIO;
	ret = svc_rdma_dma_map_buf(rdma, ctxt,
				   xdr->head[0].iov_base,
				   xdr->head[0].iov_len);
	if (ret < 0)
		return ret;

	/* Prepare the SGE for the RPCRDMA Header */
	atomic_inc(&rdma->sc_dma_used);
	ctxt->sge[0].addr =
		ib_dma_map_page(rdma->sc_cm_id->device,
				page, 0, PAGE_SIZE, DMA_TO_DEVICE);
	ctxt->direction = DMA_TO_DEVICE;
	ctxt->sge[0].length = svc_rdma_xdr_get_reply_hdr_len(rdma_resp);
	ctxt->sge[0].lkey = rdma->sc_phys_mr->lkey;

	/* Determine how many of our SGE are to be transmitted */
	for (sge_no = 1; byte_count && sge_no < vec->count; sge_no++) {
		sge_bytes = min_t(size_t, vec->sge[sge_no].iov_len, byte_count);
		byte_count -= sge_bytes;
		atomic_inc(&rdma->sc_dma_used);
		ctxt->sge[sge_no].addr =
			ib_dma_map_single(rdma->sc_cm_id->device,
					  vec->sge[sge_no].iov_base,
					  sge_bytes, DMA_TO_DEVICE);
		ctxt->sge[sge_no].length = sge_bytes;
		ctxt->sge[sge_no].lkey = rdma->sc_phys_mr->lkey;
	}
	BUG_ON(byte_count != 0);
	ctxt->sge[0].lkey = rdma->sc_dma_lkey;
	ctxt->sge[0].length = svc_rdma_xdr_get_reply_hdr_len(rdma_resp);
	ctxt->sge[0].addr =
	    ib_dma_map_page(rdma->sc_cm_id->device, page, 0,
			    ctxt->sge[0].length, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(rdma->sc_cm_id->device, ctxt->sge[0].addr))
		goto err;
	atomic_inc(&rdma->sc_dma_used);

	ctxt->direction = DMA_TO_DEVICE;

	/* Map the payload indicated by 'byte_count' */
	xdr_off = 0;
	for (sge_no = 1; byte_count && sge_no < vec->count; sge_no++) {
		sge_bytes = min_t(size_t, vec->sge[sge_no].iov_len, byte_count);
		byte_count -= sge_bytes;
		ctxt->sge[sge_no].addr =
			dma_map_xdr(rdma, &rqstp->rq_res, xdr_off,
				    sge_bytes, DMA_TO_DEVICE);
		xdr_off += sge_bytes;
		if (ib_dma_mapping_error(rdma->sc_cm_id->device,
					 ctxt->sge[sge_no].addr))
			goto err;
		atomic_inc(&rdma->sc_dma_used);
		ctxt->sge[sge_no].lkey = rdma->sc_dma_lkey;
		ctxt->sge[sge_no].length = sge_bytes;
	}
	if (byte_count != 0) {
		pr_err("svcrdma: Could not map %d bytes\n", byte_count);
		goto err;
	}

	/* Save all respages in the ctxt and remove them from the
	 * respages array. They are our pages until the I/O
	 * completes.
	 */
	for (page_no = 0; page_no < rqstp->rq_resused; page_no++) {
		ctxt->pages[page_no+1] = rqstp->rq_respages[page_no];
		ctxt->count++;
		rqstp->rq_respages[page_no] = NULL;
		/* If there are more pages than SGE, terminate SGE list */
		if (page_no+1 >= sge_no)
			ctxt->sge[page_no+1].length = 0;
	}
	BUG_ON(sge_no > rdma->sc_max_sge);
	pages = rqstp->rq_next_page - rqstp->rq_respages;
	for (page_no = 0; page_no < pages; page_no++) {
		ctxt->pages[page_no+1] = rqstp->rq_respages[page_no];
		ctxt->count++;
		rqstp->rq_respages[page_no] = NULL;
		/*
		 * If there are more pages than SGE, terminate SGE
		 * list so that svc_rdma_unmap_dma doesn't attempt to
		 * unmap garbage.
		 */
		if (page_no+1 >= sge_no)
			ctxt->sge[page_no+1].length = 0;
	/* If a Write chunk is present, the xdr_buf's page list
	 * is not included inline. However the Upper Layer may
	 * have added XDR padding in the tail buffer, and that
	 * should not be included inline.
	 */
	if (wr_lst) {
		base = xdr->tail[0].iov_base;
		len = xdr->tail[0].iov_len;
		xdr_pad = xdr_padsize(xdr->page_len);

		if (len && xdr_pad) {
			base += xdr_pad;
			len -= xdr_pad;
		}

		goto tail;
	}

	ppages = xdr->pages + (xdr->page_base >> PAGE_SHIFT);
	page_off = xdr->page_base & ~PAGE_MASK;
	remaining = xdr->page_len;
	while (remaining) {
		len = min_t(u32, PAGE_SIZE - page_off, remaining);

		if (++ctxt->sc_cur_sge_no >= rdma->sc_max_send_sges)
			return -EIO;
		ret = svc_rdma_dma_map_page(rdma, ctxt, *ppages++,
					    page_off, len);
		if (ret < 0)
			return ret;

		remaining -= len;
		page_off = 0;
	}

	base = xdr->tail[0].iov_base;
	len = xdr->tail[0].iov_len;
tail:
	if (len) {
		if (++ctxt->sc_cur_sge_no >= rdma->sc_max_send_sges)
			return -EIO;
		ret = svc_rdma_dma_map_buf(rdma, ctxt, base, len);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/* The svc_rqst and all resources it owns are released as soon as
 * svc_rdma_sendto returns. Transfer pages under I/O to the ctxt
 * so they are released by the Send completion handler.
 */
static void svc_rdma_save_io_pages(struct svc_rqst *rqstp,
				   struct svc_rdma_send_ctxt *ctxt)
{
	int i, pages = rqstp->rq_next_page - rqstp->rq_respages;

	ctxt->sc_page_count += pages;
	for (i = 0; i < pages; i++) {
		ctxt->sc_pages[i] = rqstp->rq_respages[i];
		rqstp->rq_respages[i] = NULL;
	}

	/* Prevent svc_xprt_release from releasing pages in rq_pages */
	rqstp->rq_next_page = rqstp->rq_respages;
}

/* Prepare the portion of the RPC Reply that will be transmitted
 * via RDMA Send. The RPC-over-RDMA transport header is prepared
 * in sc_sges[0], and the RPC xdr_buf is prepared in following sges.
 *
 * Depending on whether a Write list or Reply chunk is present,
 * the server may send all, a portion of, or none of the xdr_buf.
 * In the latter case, only the transport header (sc_sges[0]) is
 * transmitted.
 *
 * RDMA Send is the last step of transmitting an RPC reply. Pages
 * involved in the earlier RDMA Writes are here transferred out
 * of the rqstp and into the ctxt's page array. These pages are
 * DMA unmapped by each Write completion, but the subsequent Send
 * completion finally releases these pages.
 *
 * Assumptions:
 * - The Reply's transport header will never be larger than a page.
 */
static int svc_rdma_send_reply_msg(struct svcxprt_rdma *rdma,
				   struct svc_rdma_send_ctxt *ctxt,
				   __be32 *rdma_argp,
				   struct svc_rqst *rqstp,
				   __be32 *wr_lst, __be32 *rp_ch)
{
	int ret;

	if (!rp_ch) {
		ret = svc_rdma_map_reply_msg(rdma, ctxt,
					     &rqstp->rq_res, wr_lst);
		if (ret < 0)
			return ret;
	}

	svc_rdma_save_io_pages(rqstp, ctxt);

	inv_rkey = 0;
	if (rdma->sc_snd_w_inv)
		inv_rkey = svc_rdma_get_inv_rkey(rdma_argp, wr_lst, rp_ch);
	ret = svc_rdma_post_send_wr(rdma, ctxt, 1 + ret, inv_rkey);
	if (ret)
		svc_rdma_put_context(ctxt, 1);

	return ret;
		goto err;

	return 0;

err:
	svc_rdma_unmap_dma(ctxt);
	svc_rdma_put_context(ctxt, 1);
	return ret;
	ctxt->sc_send_wr.opcode = IB_WR_SEND;
	if (rdma->sc_snd_w_inv) {
		ctxt->sc_send_wr.ex.invalidate_rkey =
			svc_rdma_get_inv_rkey(rdma_argp, wr_lst, rp_ch);
		if (ctxt->sc_send_wr.ex.invalidate_rkey)
			ctxt->sc_send_wr.opcode = IB_WR_SEND_WITH_INV;
	}
	dprintk("svcrdma: posting Send WR with %u sge(s)\n",
		ctxt->sc_send_wr.num_sge);
	return svc_rdma_send(rdma, &ctxt->sc_send_wr);
}

/* Given the client-provided Write and Reply chunks, the server was not
 * able to form a complete reply. Return an RDMA_ERROR message so the
 * client can retire this RPC transaction. As above, the Send completion
 * routine releases payload pages that were part of a previous RDMA Write.
 *
 * Remote Invalidation is skipped for simplicity.
 */
static int svc_rdma_send_error_msg(struct svcxprt_rdma *rdma,
				   struct svc_rdma_send_ctxt *ctxt,
				   struct svc_rqst *rqstp)
{
	__be32 *p;
	int ret;

	p = ctxt->sc_xprt_buf;
	trace_svcrdma_err_chunk(*p);
	p += 3;
	*p++ = rdma_error;
	*p   = err_chunk;
	svc_rdma_sync_reply_hdr(rdma, ctxt, RPCRDMA_HDRLEN_ERR);

	svc_rdma_save_io_pages(rqstp, ctxt);

	ctxt->sc_send_wr.opcode = IB_WR_SEND;
	ret = svc_rdma_send(rdma, &ctxt->sc_send_wr);
	if (ret) {
		svc_rdma_send_ctxt_put(rdma, ctxt);
		return ret;
	}

	return 0;
}

void svc_rdma_prep_reply_hdr(struct svc_rqst *rqstp)
{
}

/*
 * Return the start of an xdr buffer.
 */
static void *xdr_start(struct xdr_buf *xdr)
{
	return xdr->head[0].iov_base -
		(xdr->len -
		 xdr->page_len -
		 xdr->tail[0].iov_len -
		 xdr->head[0].iov_len);
}

/**
 * svc_rdma_sendto - Transmit an RPC reply
 * @rqstp: processed RPC request, reply XDR already in ::rq_res
 *
 * Any resources still associated with @rqstp are released upon return.
 * If no reply message was possible, the connection is closed.
 *
 * Returns:
 *	%0 if an RPC reply has been successfully posted,
 *	%-ENOMEM if a resource shortage occurred (connection is lost),
 *	%-ENOTCONN if posting failed (connection is lost).
 */
int svc_rdma_sendto(struct svc_rqst *rqstp)
{
	struct svc_xprt *xprt = rqstp->rq_xprt;
	struct svcxprt_rdma *rdma =
		container_of(xprt, struct svcxprt_rdma, sc_xprt);
	struct svc_rdma_recv_ctxt *rctxt = rqstp->rq_xprt_ctxt;
	__be32 *p, *rdma_argp, *rdma_resp, *wr_lst, *rp_ch;
	struct xdr_buf *xdr = &rqstp->rq_res;
	struct svc_rdma_send_ctxt *sctxt;
	int ret;

	dprintk("svcrdma: sending response for rqstp=%p\n", rqstp);

	/* Get the RDMA request header. */
	rdma_argp = xdr_start(&rqstp->rq_arg);
	/* Get the RDMA request header. The receive logic always
	 * places this at the start of page 0.
	/* Find the call's chunk lists to decide how to send the reply.
	 * Receive places the Call's xprt header at the start of page 0.
	 */
	rdma_argp = page_address(rqstp->rq_pages[0]);
	svc_rdma_get_write_arrays(rdma_argp, &wr_lst, &rp_ch);

	/* Build an req vec for the XDR */
	ctxt = svc_rdma_get_context(rdma);
	ctxt->direction = DMA_TO_DEVICE;
	vec = svc_rdma_get_req_map();
	xdr_to_sge(rdma, &rqstp->rq_res, vec);

	inline_bytes = rqstp->rq_res.len;

	/* Create the RDMA response header */
	res_page = svc_rdma_get_page();
	ret = map_xdr(rdma, &rqstp->rq_res, vec);
	if (ret)
	dprintk("svcrdma: preparing response for XID 0x%08x\n",
		be32_to_cpup(rdma_argp));

	rdma_argp = rctxt->rc_recv_buf;
	svc_rdma_get_write_arrays(rdma_argp, &wr_lst, &rp_ch);

	/* Create the RDMA response header. xprt->xpt_mutex,
	 * acquired in svc_send(), serializes RPC replies. The
	 * code path below that inserts the credit grant value
	 * into each transport header runs only inside this
	 * critical section.
	 */
	ret = -ENOMEM;
	sctxt = svc_rdma_send_ctxt_get(rdma);
	if (!sctxt)
		goto err0;
	rdma_resp = sctxt->sc_xprt_buf;

	/* Send any write-chunk data and build resp write-list */
	ret = send_write_chunks(rdma, rdma_argp, rdma_resp,
				rqstp, vec);
	if (ret < 0) {
		printk(KERN_ERR "svcrdma: failed to send write chunks, rc=%d\n",
		       ret);
		goto error;
		goto err1;
	}
	inline_bytes -= ret;

	/* Send any reply-list data and update resp reply-list */
	ret = send_reply_chunks(rdma, rdma_argp, rdma_resp,
				rqstp, vec);
	if (ret < 0) {
		printk(KERN_ERR "svcrdma: failed to send reply chunks, rc=%d\n",
		       ret);
		goto error;
		goto err1;
	p = rdma_resp;
	*p++ = *rdma_argp;
	*p++ = *(rdma_argp + 1);
	*p++ = rdma->sc_fc_credits;
	*p++ = rp_ch ? rdma_nomsg : rdma_msg;

	/* Start with empty chunks */
	*p++ = xdr_zero;
	*p++ = xdr_zero;
	*p   = xdr_zero;

	if (wr_lst) {
		/* XXX: Presume the client sent only one Write chunk */
		ret = svc_rdma_send_write_chunk(rdma, wr_lst, xdr);
		if (ret < 0)
			goto err2;
		svc_rdma_xdr_encode_write_list(rdma_resp, wr_lst, ret);
	}
	if (rp_ch) {
		ret = svc_rdma_send_reply_chunk(rdma, rp_ch, wr_lst, xdr);
		if (ret < 0)
			goto err2;
		svc_rdma_xdr_encode_reply_chunk(rdma_resp, rp_ch, ret);
	}

	ret = send_reply(rdma, rqstp, res_page, rdma_resp, ctxt, vec,
			 inline_bytes);
	svc_rdma_put_req_map(vec);
	dprintk("svcrdma: send_reply returns %d\n", ret);
	return ret;
 error:
	svc_rdma_put_req_map(vec);
	svc_rdma_put_context(ctxt, 0);
	put_page(res_page);
	ret = svc_rdma_post_recv(rdma, GFP_KERNEL);
	if (ret)
		goto err1;
	ret = svc_rdma_send_reply_msg(rdma, rdma_argp, rdma_resp, rqstp,
	svc_rdma_sync_reply_hdr(rdma, sctxt, svc_rdma_reply_hdr_len(rdma_resp));
	ret = svc_rdma_send_reply_msg(rdma, sctxt, rdma_argp, rqstp,
				      wr_lst, rp_ch);
	if (ret < 0)
		goto err1;
	ret = 0;

out:
	rqstp->rq_xprt_ctxt = NULL;
	svc_rdma_recv_ctxt_put(rdma, rctxt);
	return ret;

 err2:
	if (ret != -E2BIG && ret != -EINVAL)
		goto err1;

	ret = svc_rdma_send_error_msg(rdma, sctxt, rqstp);
	if (ret < 0)
		goto err1;
	ret = 0;
	goto out;

 err1:
	svc_rdma_send_ctxt_put(rdma, sctxt);
 err0:
	trace_svcrdma_send_failed(rqstp, ret);
	set_bit(XPT_CLOSE, &xprt->xpt_flags);
	ret = -ENOTCONN;
	goto out;
}
