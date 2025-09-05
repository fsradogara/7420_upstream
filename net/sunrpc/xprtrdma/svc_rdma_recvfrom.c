/*
 * Copyright (c) 2016, 2017 Oracle. All rights reserved.
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
 * The main entry point is svc_rdma_recvfrom. This is called from
 * svc_recv when the transport indicates there is incoming data to
 * be read. "Data Ready" is signaled when an RDMA Receive completes,
 * or when a set of RDMA Reads complete.
 *
 * An svc_rqst is passed in. This structure contains an array of
 * free pages (rq_pages) that will contain the incoming RPC message.
 *
 * Short messages are moved directly into svc_rqst::rq_arg, and
 * the RPC Call is ready to be processed by the Upper Layer.
 * svc_rdma_recvfrom returns the length of the RPC Call message,
 * completing the reception of the RPC Call.
 *
 * However, when an incoming message has Read chunks,
 * svc_rdma_recvfrom must post RDMA Reads to pull the RPC Call's
 * data payload from the client. svc_rdma_recvfrom sets up the
 * RDMA Reads using pages in svc_rqst::rq_pages, which are
 * transferred to an svc_rdma_op_ctxt for the duration of the
 * I/O. svc_rdma_recvfrom then returns zero, since the RPC message
 * is still not yet ready.
 *
 * When the Read chunk payloads have become available on the
 * server, "Data Ready" is raised again, and svc_recv calls
 * svc_rdma_recvfrom again. This second call may use a different
 * svc_rqst than the first one, thus any information that needs
 * to be preserved across these two calls is kept in an
 * svc_rdma_op_ctxt.
 *
 * The second call to svc_rdma_recvfrom performs final assembly
 * of the RPC Call message, using the RDMA Read sink pages kept in
 * the svc_rdma_op_ctxt. The xdr_buf is copied from the
 * svc_rdma_op_ctxt to the second svc_rqst. The second call returns
 * the length of the completed RPC Call message.
 *
 * Page Management
 *
 * Pages under I/O must be transferred from the first svc_rqst to an
 * svc_rdma_op_ctxt before the first svc_rdma_recvfrom call returns.
 *
 * The first svc_rqst supplies pages for RDMA Reads. These are moved
 * from rqstp::rq_pages into ctxt::pages. The consumed elements of
 * the rq_pages array are set to NULL and refilled with the first
 * svc_rdma_recvfrom call returns.
 *
 * During the second svc_rdma_recvfrom call, RDMA Read sink pages
 * are transferred from the svc_rdma_op_ctxt to the second svc_rqst
 * (see rdma_read_complete() below).
 */

#include <asm/unaligned.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include <linux/spinlock.h>

#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/debug.h>
#include <linux/sunrpc/rpc_rdma.h>
#include <linux/sunrpc/svc_rdma.h>

#define RPCDBG_FACILITY	RPCDBG_SVCXPRT

/*
 * Replace the pages in the rq_argpages array with the pages from the SGE in
 * the RDMA_RECV completion. The SGL should contain full pages up until the
 * last one.
 */
static void rdma_build_arg_xdr(struct svc_rqst *rqstp,
			       struct svc_rdma_op_ctxt *ctxt,
			       u32 byte_count)
{
	struct page *page;
	u32 bc;
	int sge_no;

	/* Swap the page in the SGE with the page in argpages */
	page = ctxt->pages[0];
	put_page(rqstp->rq_pages[0]);
	rqstp->rq_pages[0] = page;

	/* Set up the XDR head */
	rqstp->rq_arg.head[0].iov_base = page_address(page);
	rqstp->rq_arg.head[0].iov_len = min(byte_count, ctxt->sge[0].length);
	rqstp->rq_arg.head[0].iov_len =
		min_t(size_t, byte_count, ctxt->sge[0].length);
	rqstp->rq_arg.len = byte_count;
	rqstp->rq_arg.buflen = byte_count;

	/* Compute bytes past head in the SGL */
	bc = byte_count - rqstp->rq_arg.head[0].iov_len;

	/* If data remains, store it in the pagelist */
	rqstp->rq_arg.page_len = bc;
	rqstp->rq_arg.page_base = 0;
	rqstp->rq_arg.pages = &rqstp->rq_pages[1];

	sge_no = 1;
	while (bc && sge_no < ctxt->count) {
		page = ctxt->pages[sge_no];
		put_page(rqstp->rq_pages[sge_no]);
		rqstp->rq_pages[sge_no] = page;
		bc -= min(bc, ctxt->sge[sge_no].length);
		bc -= min_t(u32, bc, ctxt->sge[sge_no].length);
		sge_no++;
	}
	rqstp->rq_respages = &rqstp->rq_pages[sge_no];

	/* We should never run out of SGE because the limit is defined to
	 * support the max allowed RPC data length
	 */
	BUG_ON(bc && (sge_no == ctxt->count));
	BUG_ON((rqstp->rq_arg.head[0].iov_len + rqstp->rq_arg.page_len)
	       != byte_count);
	BUG_ON(rqstp->rq_arg.len != byte_count);
	rqstp->rq_next_page = rqstp->rq_respages + 1;

	/* If not all pages were used from the SGL, free the remaining ones */
	bc = sge_no;
	while (sge_no < ctxt->count) {
		page = ctxt->pages[sge_no++];
		put_page(page);
	}
	ctxt->count = bc;

	/* Set up tail */
	rqstp->rq_arg.tail[0].iov_base = NULL;
	rqstp->rq_arg.tail[0].iov_len = 0;
}

/* Encode a read-chunk-list as an array of IB SGE
 *
 * Assumptions:
 * - chunk[0]->position points to pages[0] at an offset of 0
 * - pages[] is not physically or virtually contigous and consists of
 *   PAGE_SIZE elements.
 *
 * Output:
 * - sge array pointing into pages[] array.
 * - chunk_sge array specifying sge index and count for each
 *   chunk in the read list
 *
 */
static int rdma_rcl_to_sge(struct svcxprt_rdma *xprt,
			   struct svc_rqst *rqstp,
			   struct svc_rdma_op_ctxt *head,
			   struct rpcrdma_msg *rmsgp,
			   struct svc_rdma_req_map *rpl_map,
			   struct svc_rdma_req_map *chl_map,
			   int ch_count,
			   int byte_count)
{
	int sge_no;
	int sge_bytes;
	int page_off;
	int page_no;
	int ch_bytes;
	int ch_no;
	struct rpcrdma_read_chunk *ch;

	sge_no = 0;
	page_no = 0;
	page_off = 0;
	ch = (struct rpcrdma_read_chunk *)&rmsgp->rm_body.rm_chunks[0];
	ch_no = 0;
	ch_bytes = ch->rc_target.rs_length;
	head->arg.head[0] = rqstp->rq_arg.head[0];
	head->arg.tail[0] = rqstp->rq_arg.tail[0];
	head->arg.pages = &head->pages[head->count];
	head->hdr_count = head->count; /* save count of hdr pages */
	head->arg.page_base = 0;
	head->arg.page_len = ch_bytes;
	head->arg.len = rqstp->rq_arg.len + ch_bytes;
	head->arg.buflen = rqstp->rq_arg.buflen + ch_bytes;
	head->count++;
	chl_map->ch[0].start = 0;
	while (byte_count) {
		rpl_map->sge[sge_no].iov_base =
			page_address(rqstp->rq_arg.pages[page_no]) + page_off;
		sge_bytes = min_t(int, PAGE_SIZE-page_off, ch_bytes);
		rpl_map->sge[sge_no].iov_len = sge_bytes;
		/*
		 * Don't bump head->count here because the same page
		 * may be used by multiple SGE.
		 */
		head->arg.pages[page_no] = rqstp->rq_arg.pages[page_no];
		rqstp->rq_respages = &rqstp->rq_arg.pages[page_no+1];

		byte_count -= sge_bytes;
		ch_bytes -= sge_bytes;
		sge_no++;
		/*
		 * If all bytes for this chunk have been mapped to an
		 * SGE, move to the next SGE
		 */
		if (ch_bytes == 0) {
			chl_map->ch[ch_no].count =
				sge_no - chl_map->ch[ch_no].start;
			ch_no++;
			ch++;
			chl_map->ch[ch_no].start = sge_no;
			ch_bytes = ch->rc_target.rs_length;
			/* If bytes remaining account for next chunk */
			if (byte_count) {
				head->arg.page_len += ch_bytes;
				head->arg.len += ch_bytes;
				head->arg.buflen += ch_bytes;
			}
		}
		/*
		 * If this SGE consumed all of the page, move to the
		 * next page
		 */
		if ((sge_bytes + page_off) == PAGE_SIZE) {
			page_no++;
			page_off = 0;
			/*
			 * If there are still bytes left to map, bump
			 * the page count
			 */
			if (byte_count)
				head->count++;
		} else
			page_off += sge_bytes;
	}
	BUG_ON(byte_count != 0);
	return sge_no;
}

static void rdma_set_ctxt_sge(struct svcxprt_rdma *xprt,
			      struct svc_rdma_op_ctxt *ctxt,
			      struct kvec *vec,
			      u64 *sgl_offset,
			      int count)
{
	int i;

	ctxt->count = count;
	ctxt->direction = DMA_FROM_DEVICE;
	for (i = 0; i < count; i++) {
		atomic_inc(&xprt->sc_dma_used);
		ctxt->sge[i].addr =
			ib_dma_map_single(xprt->sc_cm_id->device,
					  vec[i].iov_base, vec[i].iov_len,
					  DMA_FROM_DEVICE);
		ctxt->sge[i].length = vec[i].iov_len;
		ctxt->sge[i].lkey = xprt->sc_phys_mr->lkey;
		*sgl_offset = *sgl_offset + vec[i].iov_len;
	}
}

static int rdma_read_max_sge(struct svcxprt_rdma *xprt, int sge_count)
{
	if ((RDMA_TRANSPORT_IWARP ==
	     rdma_node_get_transport(xprt->sc_cm_id->
				     device->node_type))
	    && sge_count > 1)
		return 1;
	else
		return min_t(int, sge_count, xprt->sc_max_sge);
}

/*
 * Use RDMA_READ to read data from the advertised client buffer into the
 * XDR stream starting at rq_arg.head[0].iov_base.
 * Each chunk in the array
 * contains the following fields:
 * discrim      - '1', This isn't used for data placement
 * position     - The xdr stream offset (the same for every chunk)
 * handle       - RMR for client memory region
 * length       - data transfer length
 * offset       - 64 bit tagged offset in remote memory region
 *
 * On our side, we need to read into a pagelist. The first page immediately
 * follows the RPC header.
 *
 * This function returns:
 * 0 - No error and no read-list found.
 *
 * 1 - Successful read-list processing. The data is not yet in
 * the pagelist and therefore the RPC request must be deferred. The
 * I/O completion will enqueue the transport again and
 * svc_rdma_recvfrom will complete the request.
 *
 * <0 - Error processing/posting read-list.
 *
 * NOTE: The ctxt must not be touched after the last WR has been posted
 * because the I/O completion processing may occur on another
 * processor and free / modify the context. Ne touche pas!
 */
static int rdma_read_xdr(struct svcxprt_rdma *xprt,
			 struct rpcrdma_msg *rmsgp,
			 struct svc_rqst *rqstp,
			 struct svc_rdma_op_ctxt *hdr_ctxt)
{
	struct ib_send_wr read_wr;
	int err = 0;
	int ch_no;
	int ch_count;
	int byte_count;
	int sge_count;
	u64 sgl_offset;
	struct rpcrdma_read_chunk *ch;
	struct svc_rdma_op_ctxt *ctxt = NULL;
	struct svc_rdma_req_map *rpl_map;
	struct svc_rdma_req_map *chl_map;
/* Issue an RDMA_READ using the local lkey to map the data sink */
int rdma_read_chunk_lcl(struct svcxprt_rdma *xprt,
			struct svc_rqst *rqstp,
			struct svc_rdma_op_ctxt *head,
			int *page_no,
			u32 *page_offset,
			u32 rs_handle,
			u32 rs_length,
			u64 rs_offset,
			bool last)
{
	struct ib_rdma_wr read_wr;
	int pages_needed = PAGE_ALIGN(*page_offset + rs_length) >> PAGE_SHIFT;
	struct svc_rdma_op_ctxt *ctxt = svc_rdma_get_context(xprt);
	int ret, read, pno;
	u32 pg_off = *page_offset;
	u32 pg_no = *page_no;

	ctxt->direction = DMA_FROM_DEVICE;
	ctxt->read_hdr = head;
	pages_needed = min_t(int, pages_needed, xprt->sc_max_sge_rd);
	read = min_t(int, (pages_needed << PAGE_SHIFT) - *page_offset,
		     rs_length);

	for (pno = 0; pno < pages_needed; pno++) {
		int len = min_t(int, rs_length, PAGE_SIZE - pg_off);

		head->arg.pages[pg_no] = rqstp->rq_arg.pages[pg_no];
		head->arg.page_len += len;
		head->arg.len += len;
		if (!pg_off)
			head->count++;
		rqstp->rq_respages = &rqstp->rq_arg.pages[pg_no+1];
		rqstp->rq_next_page = rqstp->rq_respages + 1;
		ctxt->sge[pno].addr =
			ib_dma_map_page(xprt->sc_cm_id->device,
					head->arg.pages[pg_no], pg_off,
					PAGE_SIZE - pg_off,
					DMA_FROM_DEVICE);
		ret = ib_dma_mapping_error(xprt->sc_cm_id->device,
					   ctxt->sge[pno].addr);
		if (ret)
			goto err;
		atomic_inc(&xprt->sc_dma_used);

		/* The lkey here is either a local dma lkey or a dma_mr lkey */
		ctxt->sge[pno].lkey = xprt->sc_dma_lkey;
		ctxt->sge[pno].length = len;
		ctxt->count++;

		/* adjust offset and wrap to next page if needed */
		pg_off += len;
		if (pg_off == PAGE_SIZE) {
			pg_off = 0;
			pg_no++;
		}
		rs_length -= len;
	}

	if (last && rs_length == 0)
		set_bit(RDMACTXT_F_LAST_CTXT, &ctxt->flags);
	else
		clear_bit(RDMACTXT_F_LAST_CTXT, &ctxt->flags);

	memset(&read_wr, 0, sizeof(read_wr));
	read_wr.wr.wr_id = (unsigned long)ctxt;
	read_wr.wr.opcode = IB_WR_RDMA_READ;
	ctxt->wr_op = read_wr.wr.opcode;
	read_wr.wr.send_flags = IB_SEND_SIGNALED;
	read_wr.rkey = rs_handle;
	read_wr.remote_addr = rs_offset;
	read_wr.wr.sg_list = ctxt->sge;
	read_wr.wr.num_sge = pages_needed;

	ret = svc_rdma_send(xprt, &read_wr.wr);
	if (ret) {
		pr_err("svcrdma: Error %d posting RDMA_READ\n", ret);
		set_bit(XPT_CLOSE, &xprt->sc_xprt.xpt_flags);
		goto err;
	}

	/* return current location in page array */
	*page_no = pg_no;
	*page_offset = pg_off;
	ret = read;
	atomic_inc(&rdma_stat_read);
	return ret;
 err:
	svc_rdma_unmap_dma(ctxt);
	svc_rdma_put_context(ctxt, 0);
	return ret;
}

/* Issue an RDMA_READ using an FRMR to map the data sink */
int rdma_read_chunk_frmr(struct svcxprt_rdma *xprt,
			 struct svc_rqst *rqstp,
			 struct svc_rdma_op_ctxt *head,
			 int *page_no,
			 u32 *page_offset,
			 u32 rs_handle,
			 u32 rs_length,
			 u64 rs_offset,
			 bool last)
{
	struct ib_rdma_wr read_wr;
	struct ib_send_wr inv_wr;
	struct ib_reg_wr reg_wr;
	u8 key;
	int nents = PAGE_ALIGN(*page_offset + rs_length) >> PAGE_SHIFT;
	struct svc_rdma_op_ctxt *ctxt = svc_rdma_get_context(xprt);
	struct svc_rdma_fastreg_mr *frmr = svc_rdma_get_frmr(xprt);
	int ret, read, pno, dma_nents, n;
	u32 pg_off = *page_offset;
	u32 pg_no = *page_no;

	if (IS_ERR(frmr))
		return -ENOMEM;

	ctxt->direction = DMA_FROM_DEVICE;
	ctxt->frmr = frmr;
	nents = min_t(unsigned int, nents, xprt->sc_frmr_pg_list_len);
	read = min_t(int, (nents << PAGE_SHIFT) - *page_offset, rs_length);

	frmr->direction = DMA_FROM_DEVICE;
	frmr->access_flags = (IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_WRITE);
	frmr->sg_nents = nents;

	for (pno = 0; pno < nents; pno++) {
		int len = min_t(int, rs_length, PAGE_SIZE - pg_off);

		head->arg.pages[pg_no] = rqstp->rq_arg.pages[pg_no];
		head->arg.page_len += len;
		head->arg.len += len;
		if (!pg_off)
			head->count++;

		sg_set_page(&frmr->sg[pno], rqstp->rq_arg.pages[pg_no],
			    len, pg_off);

		rqstp->rq_respages = &rqstp->rq_arg.pages[pg_no+1];
		rqstp->rq_next_page = rqstp->rq_respages + 1;

		/* adjust offset and wrap to next page if needed */
		pg_off += len;
		if (pg_off == PAGE_SIZE) {
			pg_off = 0;
			pg_no++;
		}
		rs_length -= len;
	}

	if (last && rs_length == 0)
		set_bit(RDMACTXT_F_LAST_CTXT, &ctxt->flags);
	else
		clear_bit(RDMACTXT_F_LAST_CTXT, &ctxt->flags);

	dma_nents = ib_dma_map_sg(xprt->sc_cm_id->device,
				  frmr->sg, frmr->sg_nents,
				  frmr->direction);
	if (!dma_nents) {
		pr_err("svcrdma: failed to dma map sg %p\n",
		       frmr->sg);
		return -ENOMEM;
	}
	atomic_inc(&xprt->sc_dma_used);

	n = ib_map_mr_sg(frmr->mr, frmr->sg, frmr->sg_nents, PAGE_SIZE);
	if (unlikely(n != frmr->sg_nents)) {
		pr_err("svcrdma: failed to map mr %p (%d/%d elements)\n",
		       frmr->mr, n, frmr->sg_nents);
		return n < 0 ? n : -EINVAL;
	}

	/* Bump the key */
	key = (u8)(frmr->mr->lkey & 0x000000FF);
	ib_update_fast_reg_key(frmr->mr, ++key);

	ctxt->sge[0].addr = frmr->mr->iova;
	ctxt->sge[0].lkey = frmr->mr->lkey;
	ctxt->sge[0].length = frmr->mr->length;
	ctxt->count = 1;
	ctxt->read_hdr = head;

	/* Prepare REG WR */
	reg_wr.wr.opcode = IB_WR_REG_MR;
	reg_wr.wr.wr_id = 0;
	reg_wr.wr.send_flags = IB_SEND_SIGNALED;
	reg_wr.wr.num_sge = 0;
	reg_wr.mr = frmr->mr;
	reg_wr.key = frmr->mr->lkey;
	reg_wr.access = frmr->access_flags;
	reg_wr.wr.next = &read_wr.wr;

	/* Prepare RDMA_READ */
	memset(&read_wr, 0, sizeof(read_wr));
	read_wr.wr.send_flags = IB_SEND_SIGNALED;
	read_wr.rkey = rs_handle;
	read_wr.remote_addr = rs_offset;
	read_wr.wr.sg_list = ctxt->sge;
	read_wr.wr.num_sge = 1;
	if (xprt->sc_dev_caps & SVCRDMA_DEVCAP_READ_W_INV) {
		read_wr.wr.opcode = IB_WR_RDMA_READ_WITH_INV;
		read_wr.wr.wr_id = (unsigned long)ctxt;
		read_wr.wr.ex.invalidate_rkey = ctxt->frmr->mr->lkey;
	} else {
		read_wr.wr.opcode = IB_WR_RDMA_READ;
		read_wr.wr.next = &inv_wr;
		/* Prepare invalidate */
		memset(&inv_wr, 0, sizeof(inv_wr));
		inv_wr.wr_id = (unsigned long)ctxt;
		inv_wr.opcode = IB_WR_LOCAL_INV;
		inv_wr.send_flags = IB_SEND_SIGNALED | IB_SEND_FENCE;
		inv_wr.ex.invalidate_rkey = frmr->mr->lkey;
	}
	ctxt->wr_op = read_wr.wr.opcode;

	/* Post the chain */
	ret = svc_rdma_send(xprt, &reg_wr.wr);
	if (ret) {
		pr_err("svcrdma: Error %d posting RDMA_READ\n", ret);
		set_bit(XPT_CLOSE, &xprt->sc_xprt.xpt_flags);
		goto err;
	}

	/* return current location in page array */
	*page_no = pg_no;
	*page_offset = pg_off;
	ret = read;
	atomic_inc(&rdma_stat_read);
	return ret;
 err:
	ib_dma_unmap_sg(xprt->sc_cm_id->device,
			frmr->sg, frmr->sg_nents, frmr->direction);
	svc_rdma_put_context(ctxt, 0);
	svc_rdma_put_frmr(xprt, frmr);
	return ret;
}

static unsigned int
rdma_rcl_chunk_count(struct rpcrdma_read_chunk *ch)
{
	unsigned int count;

	for (count = 0; ch->rc_discrim != xdr_zero; ch++)
		count++;
	return count;
}

/* If there was additional inline content, append it to the end of arg.pages.
 * Tail copy has to be done after the reader function has determined how many
 * pages are needed for RDMA READ.
/* This accommodates the largest possible Write chunk,
 * in one segment.
 */
#define MAX_BYTES_WRITE_SEG	((u32)(RPCSVC_MAXPAGES << PAGE_SHIFT))

/* This accommodates the largest possible Position-Zero
 * Read chunk or Reply chunk, in one segment.
 */
#define MAX_BYTES_SPECIAL_SEG	((u32)((RPCSVC_MAXPAGES + 2) << PAGE_SHIFT))

/* Sanity check the Read list.
 *
 * Implementation limits:
 * - This implementation supports only one Read chunk.
 *
 * Sanity checks:
 * - Read list does not overflow buffer.
 * - Segment size limited by largest NFS data payload.
 *
 * The segment count is limited to how many segments can
 * fit in the transport header without overflowing the
 * buffer. That's about 40 Read segments for a 1KB inline
 * threshold.
 *
 * Returns pointer to the following Write list.
 */
static __be32 *xdr_check_read_list(__be32 *p, const __be32 *end)
{
	u32 position;
	bool first;

	/* If no read list is present, return 0 */
	ch = svc_rdma_get_read_chunk(rmsgp);
	if (!ch)
		return 0;

	/* Allocate temporary reply and chunk maps */
	rpl_map = svc_rdma_get_req_map();
	chl_map = svc_rdma_get_req_map();

	svc_rdma_rcl_chunk_counts(ch, &ch_count, &byte_count);
	if (ch_count > RPCSVC_MAXPAGES)
		return -EINVAL;
	sge_count = rdma_rcl_to_sge(xprt, rqstp, hdr_ctxt, rmsgp,
				    rpl_map, chl_map,
				    ch_count, byte_count);
	sgl_offset = 0;
	ch_no = 0;

	for (ch = (struct rpcrdma_read_chunk *)&rmsgp->rm_body.rm_chunks[0];
	     ch->rc_discrim != 0; ch++, ch_no++) {
next_sge:
		ctxt = svc_rdma_get_context(xprt);
		ctxt->direction = DMA_FROM_DEVICE;
		clear_bit(RDMACTXT_F_LAST_CTXT, &ctxt->flags);

		/* Prepare READ WR */
		memset(&read_wr, 0, sizeof read_wr);
		ctxt->wr_op = IB_WR_RDMA_READ;
		read_wr.wr_id = (unsigned long)ctxt;
		read_wr.opcode = IB_WR_RDMA_READ;
		read_wr.send_flags = IB_SEND_SIGNALED;
		read_wr.wr.rdma.rkey = ch->rc_target.rs_handle;
		read_wr.wr.rdma.remote_addr =
			get_unaligned(&(ch->rc_target.rs_offset)) +
			sgl_offset;
		read_wr.sg_list = ctxt->sge;
		read_wr.num_sge =
			rdma_read_max_sge(xprt, chl_map->ch[ch_no].count);
		rdma_set_ctxt_sge(xprt, ctxt,
				  &rpl_map->sge[chl_map->ch[ch_no].start],
				  &sgl_offset,
				  read_wr.num_sge);
		if (((ch+1)->rc_discrim == 0) &&
		    (read_wr.num_sge == chl_map->ch[ch_no].count)) {
			/*
			 * Mark the last RDMA_READ with a bit to
			 * indicate all RPC data has been fetched from
			 * the client and the RPC needs to be enqueued.
			 */
			set_bit(RDMACTXT_F_LAST_CTXT, &ctxt->flags);
			ctxt->read_hdr = hdr_ctxt;
		}
		/* Post the read */
		err = svc_rdma_send(xprt, &read_wr);
		if (err) {
			printk(KERN_ERR "svcrdma: Error %d posting RDMA_READ\n",
			       err);
			set_bit(XPT_CLOSE, &xprt->sc_xprt.xpt_flags);
			svc_rdma_put_context(ctxt, 0);
			goto out;
		}
		atomic_inc(&rdma_stat_read);

		if (read_wr.num_sge < chl_map->ch[ch_no].count) {
			chl_map->ch[ch_no].count -= read_wr.num_sge;
			chl_map->ch[ch_no].start += read_wr.num_sge;
			goto next_sge;
		}
		sgl_offset = 0;
		err = 1;
	}

 out:
	svc_rdma_put_req_map(rpl_map);
	svc_rdma_put_req_map(chl_map);

	/* Detach arg pages. svc_recv will replenish them */
	for (ch_no = 0; &rqstp->rq_pages[ch_no] < rqstp->rq_respages; ch_no++)
		rqstp->rq_pages[ch_no] = NULL;

	/*
	 * Detach res pages. svc_release must see a resused count of
	 * zero or it will attempt to put them.
	 */
	while (rqstp->rq_resused)
		rqstp->rq_respages[--rqstp->rq_resused] = NULL;

	return err;
	if (rdma_rcl_chunk_count(ch) > RPCSVC_MAXPAGES)
		return -EINVAL;

	/* The request is completed when the RDMA_READs complete. The
	 * head context keeps all the pages that comprise the
	 * request.
	 */
	head->arg.head[0] = rqstp->rq_arg.head[0];
	head->arg.tail[0] = rqstp->rq_arg.tail[0];
	head->hdr_count = head->count;
	head->arg.page_base = 0;
	head->arg.page_len = 0;
	head->arg.len = rqstp->rq_arg.len;
	head->arg.buflen = rqstp->rq_arg.buflen;

	ch = (struct rpcrdma_read_chunk *)&rmsgp->rm_body.rm_chunks[0];
	position = be32_to_cpu(ch->rc_position);

	/* RDMA_NOMSG: RDMA READ data should land just after RDMA RECV data */
	if (position == 0) {
		head->arg.pages = &head->pages[0];
		page_offset = head->byte_len;
	} else {
		head->arg.pages = &head->pages[head->count];
		page_offset = 0;
	}

	ret = 0;
	page_no = 0;
	for (; ch->rc_discrim != xdr_zero; ch++) {
		if (be32_to_cpu(ch->rc_position) != position)
			goto err;

		handle = be32_to_cpu(ch->rc_target.rs_handle),
		byte_count = be32_to_cpu(ch->rc_target.rs_length);
		xdr_decode_hyper((__be32 *)&ch->rc_target.rs_offset,
				 &rs_offset);

		while (byte_count > 0) {
			last = (ch + 1)->rc_discrim == xdr_zero;
			ret = xprt->sc_reader(xprt, rqstp, head,
					      &page_no, &page_offset,
					      handle, byte_count,
					      rs_offset, last);
			if (ret < 0)
				goto err;
			byte_count -= ret;
			rs_offset += ret;
			head->arg.buflen += ret;
	first = true;
	while (*p++ != xdr_zero) {
		if (first) {
			position = be32_to_cpup(p++);
			first = false;
		} else if (be32_to_cpup(p++) != position) {
			return NULL;
		}
		p++;	/* handle */
		if (be32_to_cpup(p++) > MAX_BYTES_SPECIAL_SEG)
			return NULL;
		p += 2;	/* offset */

		if (p > end)
			return NULL;
	}
	return p;
}

/* The segment count is limited to how many segments can
 * fit in the transport header without overflowing the
 * buffer. That's about 60 Write segments for a 1KB inline
 * threshold.
 */
static __be32 *xdr_check_write_chunk(__be32 *p, const __be32 *end,
				     u32 maxlen)
{
	u32 i, segcount;

	segcount = be32_to_cpup(p++);
	for (i = 0; i < segcount; i++) {
		p++;	/* handle */
		if (be32_to_cpup(p++) > maxlen)
			return NULL;
		p += 2;	/* offset */

		if (p > end)
			return NULL;
	}

	return p;
}

/* Sanity check the Write list.
 *
 * Implementation limits:
 * - This implementation supports only one Write chunk.
 *
 * Sanity checks:
 * - Write list does not overflow buffer.
 * - Segment size limited by largest NFS data payload.
 *
 * Returns pointer to the following Reply chunk.
 */
static __be32 *xdr_check_write_list(__be32 *p, const __be32 *end)
{
	u32 chcount;

	chcount = 0;
	while (*p++ != xdr_zero) {
		p = xdr_check_write_chunk(p, end, MAX_BYTES_WRITE_SEG);
		if (!p)
			return NULL;
		if (chcount++ > 1)
			return NULL;
	}
	return p;
}

/* Sanity check the Reply chunk.
 *
 * Sanity checks:
 * - Reply chunk does not overflow buffer.
 * - Segment size limited by largest NFS data payload.
 *
 * Returns pointer to the following RPC header.
 */
static __be32 *xdr_check_reply_chunk(__be32 *p, const __be32 *end)
{
	if (*p++ != xdr_zero) {
		p = xdr_check_write_chunk(p, end, MAX_BYTES_SPECIAL_SEG);
		if (!p)
			return NULL;
	}
	return p;
}

/* On entry, xdr->head[0].iov_base points to first byte in the
 * RPC-over-RDMA header.
 *
 * On successful exit, head[0] points to first byte past the
 * RPC-over-RDMA header. For RDMA_MSG, this is the RPC message.
 * The length of the RPC-over-RDMA header is returned.
 *
 * Assumptions:
 * - The transport header is entirely contained in the head iovec.
 */
static int svc_rdma_xdr_decode_req(struct xdr_buf *rq_arg)
{
	__be32 *p, *end, *rdma_argp;
	unsigned int hdr_len;
	char *proc;

	/* Verify that there's enough bytes for header + something */
	if (rq_arg->len <= RPCRDMA_HDRLEN_ERR)
		goto out_short;

	rdma_argp = rq_arg->head[0].iov_base;
	if (*(rdma_argp + 1) != rpcrdma_version)
		goto out_version;

	switch (*(rdma_argp + 3)) {
	case rdma_msg:
		proc = "RDMA_MSG";
		break;
	case rdma_nomsg:
		proc = "RDMA_NOMSG";
		break;

	case rdma_done:
		goto out_drop;

	case rdma_error:
		goto out_drop;

	default:
		goto out_proc;
	}

	end = (__be32 *)((unsigned long)rdma_argp + rq_arg->len);
	p = xdr_check_read_list(rdma_argp + 4, end);
	if (!p)
		goto out_inval;
	p = xdr_check_write_list(p, end);
	if (!p)
		goto out_inval;
	p = xdr_check_reply_chunk(p, end);
	if (!p)
		goto out_inval;
	if (p > end)
		goto out_inval;

	rq_arg->head[0].iov_base = p;
	hdr_len = (unsigned long)p - (unsigned long)rdma_argp;
	rq_arg->head[0].iov_len -= hdr_len;
	rq_arg->len -= hdr_len;
	dprintk("svcrdma: received %s request for XID 0x%08x, hdr_len=%u\n",
		proc, be32_to_cpup(rdma_argp), hdr_len);
	return hdr_len;

out_short:
	dprintk("svcrdma: header too short = %d\n", rq_arg->len);
	return -EINVAL;

out_version:
	dprintk("svcrdma: bad xprt version: %u\n",
		be32_to_cpup(rdma_argp + 1));
	return -EPROTONOSUPPORT;

out_drop:
	dprintk("svcrdma: dropping RDMA_DONE/ERROR message\n");
	return 0;

out_proc:
	dprintk("svcrdma: bad rdma procedure (%u)\n",
		be32_to_cpup(rdma_argp + 3));
	return -EINVAL;

out_inval:
	dprintk("svcrdma: failed to parse transport header\n");
	return -EINVAL;
}

static void rdma_read_complete(struct svc_rqst *rqstp,
			       struct svc_rdma_op_ctxt *head)
{
	int page_no;

	BUG_ON(!head);

	/* Copy RPC pages */
	for (page_no = 0; page_no < head->count; page_no++) {
		put_page(rqstp->rq_pages[page_no]);
		rqstp->rq_pages[page_no] = head->pages[page_no];
	}

	/* Point rq_arg.pages past header */
	rqstp->rq_arg.pages = &rqstp->rq_pages[head->hdr_count];
	rqstp->rq_arg.page_len = head->arg.page_len;

	/* rq_respages starts after the last arg page */
	rqstp->rq_respages = &rqstp->rq_arg.pages[page_no];
	rqstp->rq_resused = 0;
	rqstp->rq_respages = &rqstp->rq_pages[page_no];
	rqstp->rq_next_page = rqstp->rq_respages + 1;

	/* Rebuild rq_arg head and tail. */
	rqstp->rq_arg.head[0] = head->arg.head[0];
	rqstp->rq_arg.tail[0] = head->arg.tail[0];
	rqstp->rq_arg.len = head->arg.len;
	rqstp->rq_arg.buflen = head->arg.buflen;

	/* Free the context */
	svc_rdma_put_context(head, 0);

	/* XXX: What should this be? */
	rqstp->rq_prot = IPPROTO_MAX;
	svc_xprt_copy_addrs(rqstp, rqstp->rq_xprt);

	ret = rqstp->rq_arg.head[0].iov_len
		+ rqstp->rq_arg.page_len
		+ rqstp->rq_arg.tail[0].iov_len;
	dprintk("svcrdma: deferred read ret=%d, rq_arg.len =%d, "
		"rq_arg.head[0].iov_base=%p, rq_arg.head[0].iov_len = %zd\n",
		ret, rqstp->rq_arg.len,	rqstp->rq_arg.head[0].iov_base,
		rqstp->rq_arg.head[0].iov_len);

	svc_xprt_received(rqstp->rq_xprt);
	dprintk("svcrdma: deferred read ret=%d, rq_arg.len=%u, "
		"rq_arg.head[0].iov_base=%p, rq_arg.head[0].iov_len=%zu\n",
		ret, rqstp->rq_arg.len,	rqstp->rq_arg.head[0].iov_base,
		rqstp->rq_arg.head[0].iov_len);

	return ret;
}

static void svc_rdma_send_error(struct svcxprt_rdma *xprt,
				__be32 *rdma_argp, int status)
{
	struct svc_rdma_op_ctxt *ctxt;
	__be32 *p, *err_msgp;
	unsigned int length;
	struct page *page;
	int ret;

	ret = svc_rdma_repost_recv(xprt, GFP_KERNEL);
	if (ret)
		return;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return;
	err_msgp = page_address(page);

	p = err_msgp;
	*p++ = *rdma_argp;
	*p++ = *(rdma_argp + 1);
	*p++ = xprt->sc_fc_credits;
	*p++ = rdma_error;
	if (status == -EPROTONOSUPPORT) {
		*p++ = err_vers;
		*p++ = rpcrdma_version;
		*p++ = rpcrdma_version;
	} else {
		*p++ = err_chunk;
	}
	length = (unsigned long)p - (unsigned long)err_msgp;

	/* Map transport header; no RPC message payload */
	ctxt = svc_rdma_get_context(xprt);
	ret = svc_rdma_map_reply_hdr(xprt, ctxt, err_msgp, length);
	if (ret) {
		dprintk("svcrdma: Error %d mapping send for protocol error\n",
			ret);
		return;
	}

	ret = svc_rdma_post_send_wr(xprt, ctxt, 1, 0);
	if (ret) {
		dprintk("svcrdma: Error %d posting send for protocol error\n",
			ret);
		svc_rdma_unmap_dma(ctxt);
		svc_rdma_put_context(ctxt, 1);
	}
}

/* By convention, backchannel calls arrive via rdma_msg type
 * messages, and never populate the chunk lists. This makes
 * the RPC/RDMA header small and fixed in size, so it is
 * straightforward to check the RPC header's direction field.
 */
static bool svc_rdma_is_backchannel_reply(struct svc_xprt *xprt,
					  __be32 *rdma_resp)
{
	__be32 *p;

	if (!xprt->xpt_bc_xprt)
		return false;

	p = rdma_resp + 3;
	if (*p++ != rdma_msg)
		return false;

	if (*p++ != xdr_zero)
		return false;
	if (*p++ != xdr_zero)
		return false;
	if (*p++ != xdr_zero)
		return false;

	/* XID sanity */
	if (*p++ != *rdma_resp)
		return false;
	/* call direction */
	if (*p == cpu_to_be32(RPC_CALL))
		return false;

	return true;
}

/**
 * svc_rdma_recvfrom - Receive an RPC call
 * @rqstp: request structure into which to receive an RPC Call
 *
 * Returns:
 *	The positive number of bytes in the RPC Call message,
 *	%0 if there were no Calls ready to return,
 *	%-EINVAL if the Read chunk data is too large,
 *	%-ENOMEM if rdma_rw context pool was exhausted,
 *	%-ENOTCONN if posting failed (connection is lost),
 *	%-EIO if rdma_rw initialization failed (DMA mapping, etc).
 *
 * Called in a loop when XPT_DATA is set. XPT_DATA is cleared only
 * when there are no remaining ctxt's to process.
 *
 * The next ctxt is removed from the "receive" lists.
 *
 * - If the ctxt completes a Read, then finish assembling the Call
 *   message and return the number of bytes in the message.
 *
 * - If the ctxt completes a Receive, then construct the Call
 *   message from the contents of the Receive buffer.
 *
 *   - If there are no Read chunks in this message, then finish
 *     assembling the Call message and return the number of bytes
 *     in the message.
 *
 *   - If there are Read chunks in this message, post Read WRs to
 *     pull that payload and return 0.
 */
int svc_rdma_recvfrom(struct svc_rqst *rqstp)
{
	struct svc_xprt *xprt = rqstp->rq_xprt;
	struct svcxprt_rdma *rdma_xprt =
		container_of(xprt, struct svcxprt_rdma, sc_xprt);
	struct svc_rdma_op_ctxt *ctxt;
	__be32 *p;
	int ret;

	spin_lock(&rdma_xprt->sc_rq_dto_lock);
	if (!list_empty(&rdma_xprt->sc_read_complete_q)) {
		ctxt = list_entry(rdma_xprt->sc_read_complete_q.next,
				  struct svc_rdma_op_ctxt,
				  dto_q);
		list_del_init(&ctxt->dto_q);
	}
	if (ctxt) {
		spin_unlock_bh(&rdma_xprt->sc_rq_dto_lock);
		return rdma_read_complete(rqstp, ctxt);
	}

	if (!list_empty(&rdma_xprt->sc_rq_dto_q)) {
		spin_unlock_bh(&rdma_xprt->sc_rq_dto_lock);
		return rdma_read_complete(rqstp, ctxt);
		ctxt = list_first_entry(&rdma_xprt->sc_read_complete_q,
					struct svc_rdma_op_ctxt, list);
		list_del(&ctxt->list);
		spin_unlock(&rdma_xprt->sc_rq_dto_lock);
		rdma_read_complete(rqstp, ctxt);
		goto complete;
	} else if (!list_empty(&rdma_xprt->sc_rq_dto_q)) {
		ctxt = list_first_entry(&rdma_xprt->sc_rq_dto_q,
					struct svc_rdma_op_ctxt, list);
		list_del(&ctxt->list);
	} else {
		/* No new incoming requests, terminate the loop */
		clear_bit(XPT_DATA, &xprt->xpt_flags);
		spin_unlock(&rdma_xprt->sc_rq_dto_lock);
		return 0;
	}
	spin_unlock(&rdma_xprt->sc_rq_dto_lock);

		BUG_ON(ret);
		goto out;
	}
	dprintk("svcrdma: processing ctxt=%p on xprt=%p, rqstp=%p, status=%d\n",
		ctxt, rdma_xprt, rqstp, ctxt->wc_status);
	BUG_ON(ctxt->wc_status != IB_WC_SUCCESS);
	dprintk("svcrdma: recvfrom: ctxt=%p on xprt=%p, rqstp=%p\n",
		ctxt, rdma_xprt, rqstp);
	atomic_inc(&rdma_stat_recv);

	/* Build up the XDR from the receive buffers. */
	rdma_build_arg_xdr(rqstp, ctxt, ctxt->byte_len);

	/* Decode the RDMA header. */
	p = (__be32 *)rqstp->rq_arg.head[0].iov_base;
	ret = svc_rdma_xdr_decode_req(&rqstp->rq_arg);
	if (ret < 0)
		goto out_err;
	if (ret == 0)
		goto out_drop;
	rqstp->rq_xprt_hlen = ret;

	if (svc_rdma_is_backchannel_reply(xprt, p)) {
		ret = svc_rdma_handle_bc_reply(xprt->xpt_bc_xprt, p,
					       &rqstp->rq_arg);
		svc_rdma_put_context(ctxt, 0);
		if (ret)
			goto repost;
		return ret;
	}

	/* Read read-list data. */
	ret = rdma_read_xdr(rdma_xprt, rmsgp, rqstp, ctxt);
	if (ret > 0) {
		/* read-list posted, defer until data received from client. */
		svc_xprt_received(xprt);
		return 0;
	}
	if (ret < 0) {
	ret = rdma_read_chunks(rdma_xprt, rmsgp, rqstp, ctxt);
	if (ret > 0) {
		/* read-list posted, defer until data received from client. */
		goto defer;
	} else if (ret < 0) {
		/* Post of read-list failed, free context. */
		svc_rdma_put_context(ctxt, 1);
		return 0;
	}
	p += rpcrdma_fixed_maxsz;
	if (*p != xdr_zero)
		goto out_readchunk;

complete:
	svc_rdma_put_context(ctxt, 0);
 out:
	dprintk("svcrdma: ret = %d, rq_arg.len =%d, "
		"rq_arg.head[0].iov_base=%p, rq_arg.head[0].iov_len = %zd\n",
	dprintk("svcrdma: ret=%d, rq_arg.len=%u, "
		"rq_arg.head[0].iov_base=%p, rq_arg.head[0].iov_len=%zd\n",
		ret, rqstp->rq_arg.len,
		rqstp->rq_arg.head[0].iov_base,
		rqstp->rq_arg.head[0].iov_len);
	rqstp->rq_prot = IPPROTO_MAX;
	svc_xprt_copy_addrs(rqstp, xprt);
	svc_xprt_received(xprt);
	return ret;

 close_out:
	if (ctxt)
		svc_rdma_put_context(ctxt, 1);
	dprintk("svcrdma: transport %p is closing\n", xprt);
	/*
	 * Set the close bit and enqueue it. svc_recv will see the
	 * close bit and call svc_xprt_delete
	 */
	set_bit(XPT_CLOSE, &xprt->xpt_flags);
	svc_xprt_received(xprt);
defer:
	return 0;
	dprintk("svcrdma: recvfrom: xprt=%p, rqstp=%p, rq_arg.len=%u\n",
		rdma_xprt, rqstp, rqstp->rq_arg.len);
	rqstp->rq_prot = IPPROTO_MAX;
	svc_xprt_copy_addrs(rqstp, xprt);
	return rqstp->rq_arg.len;

out_readchunk:
	ret = svc_rdma_recv_read_chunk(rdma_xprt, rqstp, ctxt, p);
	if (ret < 0)
		goto out_postfail;
	return 0;

out_err:
	svc_rdma_send_error(rdma_xprt, p, ret);
	svc_rdma_put_context(ctxt, 0);
	return 0;

out_postfail:
	if (ret == -EINVAL)
		svc_rdma_send_error(rdma_xprt, p, ret);
	svc_rdma_put_context(ctxt, 1);
	return ret;

out_drop:
	svc_rdma_put_context(ctxt, 1);
repost:
	return svc_rdma_repost_recv(rdma_xprt, GFP_KERNEL);
}
