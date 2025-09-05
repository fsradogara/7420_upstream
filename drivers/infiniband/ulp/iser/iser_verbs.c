/*
 * Copyright (c) 2004, 2005, 2006 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
 * Copyright (c) 2013-2014 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "iscsi_iser.h"

#define ISCSI_ISER_MAX_CONN	8
#define ISER_MAX_CQ_LEN		((ISER_QP_MAX_RECV_DTOS + \
				ISER_QP_MAX_REQ_DTOS) *   \
				 ISCSI_ISER_MAX_CONN)

#define ISER_MAX_RX_LEN		(ISER_QP_MAX_RECV_DTOS * ISCSI_ISER_MAX_CONN)
#define ISER_MAX_TX_LEN		(ISER_QP_MAX_REQ_DTOS  * ISCSI_ISER_MAX_CONN)
#define ISER_MAX_CQ_LEN		(ISER_MAX_RX_LEN + ISER_MAX_TX_LEN + \
				 ISCSI_ISER_MAX_CONN)

static int iser_cq_poll_limit = 512;

static void iser_cq_tasklet_fn(unsigned long data);
static void iser_cq_callback(struct ib_cq *cq, void *cq_context);

static void iser_cq_event_callback(struct ib_event *cause, void *context)
{
	iser_err("got cq event %d \n", cause->event);
	iser_err("cq event %s (%d)\n",
		 ib_event_msg(cause->event), cause->event);
}

static void iser_qp_event_callback(struct ib_event *cause, void *context)
{
	iser_err("got qp event %d\n",cause->event);
	iser_err("qp event %s (%d)\n",
		 ib_event_msg(cause->event), cause->event);
}

static void iser_event_handler(struct ib_event_handler *handler,
				struct ib_event *event)
{
	iser_err("async event %s (%d) on device %s port %d\n",
		 ib_event_msg(event->event), event->event,
		 event->device->name, event->element.port_num);
}

/**
 * iser_create_device_ib_res - creates Protection Domain (PD), Completion
 * Queue (CQ), DMA Memory Region (DMA MR) with the device associated with
 * the adapator.
 *
 * returns 0 on success, -1 on failure
 */
static int iser_create_device_ib_res(struct iser_device *device)
{
	struct ib_device *ib_dev = device->ib_device;
	int ret, i, max_cqe;

	ret = iser_assign_reg_ops(device);
	if (ret)
		return ret;

	device->comps_used = min_t(int, num_online_cpus(),
				 ib_dev->num_comp_vectors);

	device->comps = kcalloc(device->comps_used, sizeof(*device->comps),
				GFP_KERNEL);
	if (!device->comps)
		goto comps_err;

	max_cqe = min(ISER_MAX_CQ_LEN, ib_dev->attrs.max_cqe);

	iser_info("using %d CQs, device %s supports %d vectors max_cqe %d\n",
		  device->comps_used, ib_dev->name,
		  ib_dev->num_comp_vectors, max_cqe);

	device->pd = ib_alloc_pd(ib_dev,
		iser_always_reg ? 0 : IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(device->pd))
		goto pd_err;

	device->cq = ib_create_cq(device->ib_device,
				  iser_cq_callback,
				  iser_cq_event_callback,
				  (void *)device,
				  ISER_MAX_CQ_LEN, 0);
	if (IS_ERR(device->cq))
		goto cq_err;

	if (ib_req_notify_cq(device->cq, IB_CQ_NEXT_COMP))
		goto cq_arm_err;

	tasklet_init(&device->cq_tasklet,
		     iser_cq_tasklet_fn,
		     (unsigned long)device);

	device->mr = ib_get_dma_mr(device->pd, IB_ACCESS_LOCAL_WRITE |
				   IB_ACCESS_REMOTE_WRITE |
				   IB_ACCESS_REMOTE_READ);
	if (IS_ERR(device->mr))
		goto dma_mr_err;

	return 0;

dma_mr_err:
	tasklet_kill(&device->cq_tasklet);
cq_arm_err:
	ib_destroy_cq(device->cq);
cq_err:
	ib_dealloc_pd(device->pd);
pd_err:
	for (i = 0; i < device->comps_used; i++) {
		struct iser_comp *comp = &device->comps[i];

		comp->cq = ib_alloc_cq(ib_dev, comp, max_cqe, i,
				       IB_POLL_SOFTIRQ);
		if (IS_ERR(comp->cq)) {
			comp->cq = NULL;
			goto cq_err;
		}
	}

	INIT_IB_EVENT_HANDLER(&device->event_handler, ib_dev,
			      iser_event_handler);
	ib_register_event_handler(&device->event_handler);
	return 0;

cq_err:
	for (i = 0; i < device->comps_used; i++) {
		struct iser_comp *comp = &device->comps[i];

		if (comp->cq)
			ib_free_cq(comp->cq);
	}
	ib_dealloc_pd(device->pd);
pd_err:
	kfree(device->comps);
comps_err:
	iser_err("failed to allocate an IB resource\n");
	return -1;
}

/**
 * iser_free_device_ib_res - destroy/dealloc/dereg the DMA MR,
 * CQ and PD created with the device associated with the adapator.
 */
static void iser_free_device_ib_res(struct iser_device *device)
{
	BUG_ON(device->mr == NULL);

	tasklet_kill(&device->cq_tasklet);

	(void)ib_dereg_mr(device->mr);
	(void)ib_destroy_cq(device->cq);
	(void)ib_dealloc_pd(device->pd);

	device->mr = NULL;
	device->cq = NULL;
	int i;

	for (i = 0; i < device->comps_used; i++) {
		struct iser_comp *comp = &device->comps[i];

		ib_free_cq(comp->cq);
		comp->cq = NULL;
	}

	ib_unregister_event_handler(&device->event_handler);
	ib_dealloc_pd(device->pd);

	kfree(device->comps);
	device->comps = NULL;
	device->pd = NULL;
}

/**
 * iser_create_ib_conn_res - Creates FMR pool and Queue-Pair (QP)
 *
 * returns 0 on success, -1 on failure
 */
static int iser_create_ib_conn_res(struct iser_conn *ib_conn)
{
	struct iser_device	*device;
	struct ib_qp_init_attr	init_attr;
	int			ret;
	struct ib_fmr_pool_param params;

	BUG_ON(ib_conn->device == NULL);

	device = ib_conn->device;

	ib_conn->page_vec = kmalloc(sizeof(struct iser_page_vec) +
				    (sizeof(u64) * (ISCSI_ISER_SG_TABLESIZE +1)),
				    GFP_KERNEL);
	if (!ib_conn->page_vec) {
		ret = -ENOMEM;
		goto alloc_err;
	}
	ib_conn->page_vec->pages = (u64 *) (ib_conn->page_vec + 1);

	params.page_shift        = SHIFT_4K;
	/* when the first/last SG element are not start/end *
	 * page aligned, the map whould be of N+1 pages     */
	params.max_pages_per_fmr = ISCSI_ISER_SG_TABLESIZE + 1;
	/* make the pool size twice the max number of SCSI commands *
	 * the ML is expected to queue, watermark for unmap at 50%  */
	params.pool_size	 = ISCSI_DEF_XMIT_CMDS_MAX * 2;
	params.dirty_watermark	 = ISCSI_DEF_XMIT_CMDS_MAX;
 * iser_alloc_fmr_pool - Creates FMR pool and page_vector
 *
 * returns 0 on success, or errno code on failure
 */
int iser_alloc_fmr_pool(struct ib_conn *ib_conn,
			unsigned cmds_max,
			unsigned int size)
{
	struct iser_device *device = ib_conn->device;
	struct iser_fr_pool *fr_pool = &ib_conn->fr_pool;
	struct iser_page_vec *page_vec;
	struct iser_fr_desc *desc;
	struct ib_fmr_pool *fmr_pool;
	struct ib_fmr_pool_param params;
	int ret;

	INIT_LIST_HEAD(&fr_pool->list);
	spin_lock_init(&fr_pool->lock);

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	page_vec = kmalloc(sizeof(*page_vec) + (sizeof(u64) * size),
			   GFP_KERNEL);
	if (!page_vec) {
		ret = -ENOMEM;
		goto err_frpl;
	}

	page_vec->pages = (u64 *)(page_vec + 1);

	params.page_shift        = SHIFT_4K;
	params.max_pages_per_fmr = size;
	/* make the pool size twice the max number of SCSI commands *
	 * the ML is expected to queue, watermark for unmap at 50%  */
	params.pool_size	 = cmds_max * 2;
	params.dirty_watermark	 = cmds_max;
	params.cache		 = 0;
	params.flush_function	 = NULL;
	params.access		 = (IB_ACCESS_LOCAL_WRITE  |
				    IB_ACCESS_REMOTE_WRITE |
				    IB_ACCESS_REMOTE_READ);

	ib_conn->fmr_pool = ib_create_fmr_pool(device->pd, &params);
	if (IS_ERR(ib_conn->fmr_pool)) {
		ret = PTR_ERR(ib_conn->fmr_pool);
		goto fmr_pool_err;
	}

	memset(&init_attr, 0, sizeof init_attr);

	init_attr.event_handler = iser_qp_event_callback;
	init_attr.qp_context	= (void *)ib_conn;
	init_attr.send_cq	= device->cq;
	init_attr.recv_cq	= device->cq;
	init_attr.cap.max_send_wr  = ISER_QP_MAX_REQ_DTOS;
	init_attr.cap.max_recv_wr  = ISER_QP_MAX_RECV_DTOS;
	init_attr.cap.max_send_sge = MAX_REGD_BUF_VECTOR_LEN;
	init_attr.cap.max_recv_sge = 2;
	init_attr.sq_sig_type	= IB_SIGNAL_REQ_WR;
	init_attr.qp_type	= IB_QPT_RC;

	ret = rdma_create_qp(ib_conn->cma_id, device->pd, &init_attr);
	if (ret)
		goto qp_err;

	ib_conn->qp = ib_conn->cma_id->qp;
	iser_err("setting conn %p cma_id %p: fmr_pool %p qp %p\n",
		 ib_conn, ib_conn->cma_id,
		 ib_conn->fmr_pool, ib_conn->cma_id->qp);
	return ret;

qp_err:
	(void)ib_destroy_fmr_pool(ib_conn->fmr_pool);
fmr_pool_err:
	kfree(ib_conn->page_vec);
alloc_err:
	iser_err("unable to alloc mem or create resource, err %d\n", ret);
	fmr_pool = ib_create_fmr_pool(device->pd, &params);
	if (IS_ERR(fmr_pool)) {
		ret = PTR_ERR(fmr_pool);
		iser_err("FMR allocation failed, err %d\n", ret);
		goto err_fmr;
	}

	desc->rsc.page_vec = page_vec;
	desc->rsc.fmr_pool = fmr_pool;
	list_add(&desc->list, &fr_pool->list);

	return 0;

err_fmr:
	kfree(page_vec);
err_frpl:
	kfree(desc);

	return ret;
}

/**
 * releases the FMR pool, QP and CMA ID objects, returns 0 on success,
 * -1 on failure
 */
static int iser_free_ib_conn_res(struct iser_conn *ib_conn)
{
	BUG_ON(ib_conn == NULL);

	iser_err("freeing conn %p cma_id %p fmr pool %p qp %p\n",
		 ib_conn, ib_conn->cma_id,
		 ib_conn->fmr_pool, ib_conn->qp);

	/* qp is created only once both addr & route are resolved */
	if (ib_conn->fmr_pool != NULL)
		ib_destroy_fmr_pool(ib_conn->fmr_pool);

	if (ib_conn->qp != NULL)
		rdma_destroy_qp(ib_conn->cma_id);

	if (ib_conn->cma_id != NULL)
		rdma_destroy_id(ib_conn->cma_id);

	ib_conn->fmr_pool = NULL;
	ib_conn->qp	  = NULL;
	ib_conn->cma_id   = NULL;
	kfree(ib_conn->page_vec);
 * iser_free_fmr_pool - releases the FMR pool and page vec
 */
void iser_free_fmr_pool(struct ib_conn *ib_conn)
{
	struct iser_fr_pool *fr_pool = &ib_conn->fr_pool;
	struct iser_fr_desc *desc;

	desc = list_first_entry(&fr_pool->list,
				struct iser_fr_desc, list);
	list_del(&desc->list);

	iser_info("freeing conn %p fmr pool %p\n",
		  ib_conn, desc->rsc.fmr_pool);

	ib_destroy_fmr_pool(desc->rsc.fmr_pool);
	kfree(desc->rsc.page_vec);
	kfree(desc);
}

static int
iser_alloc_reg_res(struct iser_device *device,
		   struct ib_pd *pd,
		   struct iser_reg_resources *res,
		   unsigned int size)
{
	struct ib_device *ib_dev = device->ib_device;
	enum ib_mr_type mr_type;
	int ret;

	if (ib_dev->attrs.device_cap_flags & IB_DEVICE_SG_GAPS_REG)
		mr_type = IB_MR_TYPE_SG_GAPS;
	else
		mr_type = IB_MR_TYPE_MEM_REG;

	res->mr = ib_alloc_mr(pd, mr_type, size);
	if (IS_ERR(res->mr)) {
		ret = PTR_ERR(res->mr);
		iser_err("Failed to allocate ib_fast_reg_mr err=%d\n", ret);
		return ret;
	}
	res->mr_valid = 0;

	return 0;
}

static void
iser_free_reg_res(struct iser_reg_resources *rsc)
{
	ib_dereg_mr(rsc->mr);
}

static int
iser_alloc_pi_ctx(struct iser_device *device,
		  struct ib_pd *pd,
		  struct iser_fr_desc *desc,
		  unsigned int size)
{
	struct iser_pi_context *pi_ctx = NULL;
	int ret;

	desc->pi_ctx = kzalloc(sizeof(*desc->pi_ctx), GFP_KERNEL);
	if (!desc->pi_ctx)
		return -ENOMEM;

	pi_ctx = desc->pi_ctx;

	ret = iser_alloc_reg_res(device, pd, &pi_ctx->rsc, size);
	if (ret) {
		iser_err("failed to allocate reg_resources\n");
		goto alloc_reg_res_err;
	}

	pi_ctx->sig_mr = ib_alloc_mr(pd, IB_MR_TYPE_SIGNATURE, 2);
	if (IS_ERR(pi_ctx->sig_mr)) {
		ret = PTR_ERR(pi_ctx->sig_mr);
		goto sig_mr_failure;
	}
	pi_ctx->sig_mr_valid = 0;
	desc->pi_ctx->sig_protected = 0;

	return 0;

sig_mr_failure:
	iser_free_reg_res(&pi_ctx->rsc);
alloc_reg_res_err:
	kfree(desc->pi_ctx);

	return ret;
}

static void
iser_free_pi_ctx(struct iser_pi_context *pi_ctx)
{
	iser_free_reg_res(&pi_ctx->rsc);
	ib_dereg_mr(pi_ctx->sig_mr);
	kfree(pi_ctx);
}

static struct iser_fr_desc *
iser_create_fastreg_desc(struct iser_device *device,
			 struct ib_pd *pd,
			 bool pi_enable,
			 unsigned int size)
{
	struct iser_fr_desc *desc;
	int ret;

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return ERR_PTR(-ENOMEM);

	ret = iser_alloc_reg_res(device, pd, &desc->rsc, size);
	if (ret)
		goto reg_res_alloc_failure;

	if (pi_enable) {
		ret = iser_alloc_pi_ctx(device, pd, desc, size);
		if (ret)
			goto pi_ctx_alloc_failure;
	}

	return desc;

pi_ctx_alloc_failure:
	iser_free_reg_res(&desc->rsc);
reg_res_alloc_failure:
	kfree(desc);

	return ERR_PTR(ret);
}

/**
 * iser_alloc_fastreg_pool - Creates pool of fast_reg descriptors
 * for fast registration work requests.
 * returns 0 on success, or errno code on failure
 */
int iser_alloc_fastreg_pool(struct ib_conn *ib_conn,
			    unsigned cmds_max,
			    unsigned int size)
{
	struct iser_device *device = ib_conn->device;
	struct iser_fr_pool *fr_pool = &ib_conn->fr_pool;
	struct iser_fr_desc *desc;
	int i, ret;

	INIT_LIST_HEAD(&fr_pool->list);
	INIT_LIST_HEAD(&fr_pool->all_list);
	spin_lock_init(&fr_pool->lock);
	fr_pool->size = 0;
	for (i = 0; i < cmds_max; i++) {
		desc = iser_create_fastreg_desc(device, device->pd,
						ib_conn->pi_support, size);
		if (IS_ERR(desc)) {
			ret = PTR_ERR(desc);
			goto err;
		}

		list_add_tail(&desc->list, &fr_pool->list);
		list_add_tail(&desc->all_list, &fr_pool->all_list);
		fr_pool->size++;
	}

	return 0;

err:
	iser_free_fastreg_pool(ib_conn);
	return ret;
}

/**
 * iser_free_fastreg_pool - releases the pool of fast_reg descriptors
 */
void iser_free_fastreg_pool(struct ib_conn *ib_conn)
{
	struct iser_fr_pool *fr_pool = &ib_conn->fr_pool;
	struct iser_fr_desc *desc, *tmp;
	int i = 0;

	if (list_empty(&fr_pool->all_list))
		return;

	iser_info("freeing conn %p fr pool\n", ib_conn);

	list_for_each_entry_safe(desc, tmp, &fr_pool->all_list, all_list) {
		list_del(&desc->all_list);
		iser_free_reg_res(&desc->rsc);
		if (desc->pi_ctx)
			iser_free_pi_ctx(desc->pi_ctx);
		kfree(desc);
		++i;
	}

	if (i < fr_pool->size)
		iser_warn("pool still has %d regions registered\n",
			  fr_pool->size - i);
}

/**
 * iser_create_ib_conn_res - Queue-Pair (QP)
 *
 * returns 0 on success, -1 on failure
 */
static int iser_create_ib_conn_res(struct ib_conn *ib_conn)
{
	struct iser_conn *iser_conn = to_iser_conn(ib_conn);
	struct iser_device	*device;
	struct ib_device	*ib_dev;
	struct ib_qp_init_attr	init_attr;
	int			ret = -ENOMEM;
	int index, min_index = 0;

	BUG_ON(ib_conn->device == NULL);

	device = ib_conn->device;
	ib_dev = device->ib_device;

	memset(&init_attr, 0, sizeof init_attr);

	mutex_lock(&ig.connlist_mutex);
	/* select the CQ with the minimal number of usages */
	for (index = 0; index < device->comps_used; index++) {
		if (device->comps[index].active_qps <
		    device->comps[min_index].active_qps)
			min_index = index;
	}
	ib_conn->comp = &device->comps[min_index];
	ib_conn->comp->active_qps++;
	mutex_unlock(&ig.connlist_mutex);
	iser_info("cq index %d used for ib_conn %p\n", min_index, ib_conn);

	init_attr.event_handler = iser_qp_event_callback;
	init_attr.qp_context	= (void *)ib_conn;
	init_attr.send_cq	= ib_conn->comp->cq;
	init_attr.recv_cq	= ib_conn->comp->cq;
	init_attr.cap.max_recv_wr  = ISER_QP_MAX_RECV_DTOS;
	init_attr.cap.max_send_sge = 2;
	init_attr.cap.max_recv_sge = 1;
	init_attr.sq_sig_type	= IB_SIGNAL_REQ_WR;
	init_attr.qp_type	= IB_QPT_RC;
	if (ib_conn->pi_support) {
		init_attr.cap.max_send_wr = ISER_QP_SIG_MAX_REQ_DTOS + 1;
		init_attr.create_flags |= IB_QP_CREATE_SIGNATURE_EN;
		iser_conn->max_cmds =
			ISER_GET_MAX_XMIT_CMDS(ISER_QP_SIG_MAX_REQ_DTOS);
	} else {
		if (ib_dev->attrs.max_qp_wr > ISER_QP_MAX_REQ_DTOS) {
			init_attr.cap.max_send_wr  = ISER_QP_MAX_REQ_DTOS + 1;
			iser_conn->max_cmds =
				ISER_GET_MAX_XMIT_CMDS(ISER_QP_MAX_REQ_DTOS);
		} else {
			init_attr.cap.max_send_wr = ib_dev->attrs.max_qp_wr;
			iser_conn->max_cmds =
				ISER_GET_MAX_XMIT_CMDS(ib_dev->attrs.max_qp_wr);
			iser_dbg("device %s supports max_send_wr %d\n",
				 device->ib_device->name, ib_dev->attrs.max_qp_wr);
		}
	}

	ret = rdma_create_qp(ib_conn->cma_id, device->pd, &init_attr);
	if (ret)
		goto out_err;

	ib_conn->qp = ib_conn->cma_id->qp;
	iser_info("setting conn %p cma_id %p qp %p\n",
		  ib_conn, ib_conn->cma_id,
		  ib_conn->cma_id->qp);
	return ret;

out_err:
	mutex_lock(&ig.connlist_mutex);
	ib_conn->comp->active_qps--;
	mutex_unlock(&ig.connlist_mutex);
	iser_err("unable to alloc mem or create resource, err %d\n", ret);

	return ret;
}

/**
 * based on the resolved device node GUID see if there already allocated
 * device for this device. If there's no such, create one.
 */
static
struct iser_device *iser_device_find_by_ib_device(struct rdma_cm_id *cma_id)
{
	struct iser_device *device;

	mutex_lock(&ig.device_list_mutex);

	list_for_each_entry(device, &ig.device_list, ig_list)
		/* find if there's a match using the node GUID */
		if (device->ib_device->node_guid == cma_id->device->node_guid)
			goto inc_refcnt;

	device = kzalloc(sizeof *device, GFP_KERNEL);
	if (device == NULL)
		goto out;

	/* assign this device to the device */
	device->ib_device = cma_id->device;
	/* init the device and link it into ig device list */
	if (iser_create_device_ib_res(device)) {
		kfree(device);
		device = NULL;
		goto out;
	}
	list_add(&device->ig_list, &ig.device_list);

inc_refcnt:
	device->refcount++;
out:
	mutex_unlock(&ig.device_list_mutex);
	return device;
}

/* if there's no demand for this device, release it */
static void iser_device_try_release(struct iser_device *device)
{
	mutex_lock(&ig.device_list_mutex);
	device->refcount--;
	iser_err("device %p refcount %d\n",device,device->refcount);
	iser_info("device %p refcount %d\n", device, device->refcount);
	if (!device->refcount) {
		iser_free_device_ib_res(device);
		list_del(&device->ig_list);
		kfree(device);
	}
	mutex_unlock(&ig.device_list_mutex);
}

int iser_conn_state_comp(struct iser_conn *ib_conn,
			enum iser_ib_conn_state comp)
{
	int ret;

	spin_lock_bh(&ib_conn->lock);
	ret = (ib_conn->state == comp);
	spin_unlock_bh(&ib_conn->lock);
	return ret;
}

static int iser_conn_state_comp_exch(struct iser_conn *ib_conn,
				     enum iser_ib_conn_state comp,
				     enum iser_ib_conn_state exch)
{
	int ret;

	spin_lock_bh(&ib_conn->lock);
	if ((ret = (ib_conn->state == comp)))
		ib_conn->state = exch;
	spin_unlock_bh(&ib_conn->lock);
	return ret;
/**
 * Called with state mutex held
 **/
static int iser_conn_state_comp_exch(struct iser_conn *iser_conn,
				     enum iser_conn_state comp,
				     enum iser_conn_state exch)
{
	int ret;

	ret = (iser_conn->state == comp);
	if (ret)
		iser_conn->state = exch;

	return ret;
}

void iser_release_work(struct work_struct *work)
{
	struct iser_conn *iser_conn;

	iser_conn = container_of(work, struct iser_conn, release_work);

	/* Wait for conn_stop to complete */
	wait_for_completion(&iser_conn->stop_completion);
	/* Wait for IB resouces cleanup to complete */
	wait_for_completion(&iser_conn->ib_completion);

	mutex_lock(&iser_conn->state_mutex);
	iser_conn->state = ISER_CONN_DOWN;
	mutex_unlock(&iser_conn->state_mutex);

	iser_conn_release(iser_conn);
}

/**
 * iser_free_ib_conn_res - release IB related resources
 * @iser_conn: iser connection struct
 * @destroy: indicator if we need to try to release the
 *     iser device and memory regoins pool (only iscsi
 *     shutdown and DEVICE_REMOVAL will use this).
 *
 * This routine is called with the iser state mutex held
 * so the cm_id removal is out of here. It is Safe to
 * be invoked multiple times.
 */
static void iser_free_ib_conn_res(struct iser_conn *iser_conn,
				  bool destroy)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;
	struct iser_device *device = ib_conn->device;

	iser_info("freeing conn %p cma_id %p qp %p\n",
		  iser_conn, ib_conn->cma_id, ib_conn->qp);

	if (ib_conn->qp != NULL) {
		mutex_lock(&ig.connlist_mutex);
		ib_conn->comp->active_qps--;
		mutex_unlock(&ig.connlist_mutex);
		rdma_destroy_qp(ib_conn->cma_id);
		ib_conn->qp = NULL;
	}

	if (destroy) {
		if (iser_conn->rx_descs)
			iser_free_rx_descriptors(iser_conn);

		if (device != NULL) {
			iser_device_try_release(device);
			ib_conn->device = NULL;
		}
	}
}

/**
 * Frees all conn objects and deallocs conn descriptor
 */
static void iser_conn_release(struct iser_conn *ib_conn)
{
	struct iser_device  *device = ib_conn->device;

	BUG_ON(ib_conn->state != ISER_CONN_DOWN);

	mutex_lock(&ig.connlist_mutex);
	list_del(&ib_conn->conn_list);
	mutex_unlock(&ig.connlist_mutex);

	iser_free_ib_conn_res(ib_conn);
	ib_conn->device = NULL;
	/* on EVENT_ADDR_ERROR there's no device yet for this conn */
	if (device != NULL)
		iser_device_try_release(device);
	if (ib_conn->iser_conn)
		ib_conn->iser_conn->ib_conn = NULL;
	iscsi_destroy_endpoint(ib_conn->ep);
}

void iser_conn_get(struct iser_conn *ib_conn)
{
	atomic_inc(&ib_conn->refcount);
}

void iser_conn_put(struct iser_conn *ib_conn)
{
	if (atomic_dec_and_test(&ib_conn->refcount))
		iser_conn_release(ib_conn);
void iser_conn_release(struct iser_conn *iser_conn)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;

	mutex_lock(&ig.connlist_mutex);
	list_del(&iser_conn->conn_list);
	mutex_unlock(&ig.connlist_mutex);

	mutex_lock(&iser_conn->state_mutex);
	/* In case we endup here without ep_disconnect being invoked. */
	if (iser_conn->state != ISER_CONN_DOWN) {
		iser_warn("iser conn %p state %d, expected state down.\n",
			  iser_conn, iser_conn->state);
		iscsi_destroy_endpoint(iser_conn->ep);
		iser_conn->state = ISER_CONN_DOWN;
	}
	/*
	 * In case we never got to bind stage, we still need to
	 * release IB resources (which is safe to call more than once).
	 */
	iser_free_ib_conn_res(iser_conn, true);
	mutex_unlock(&iser_conn->state_mutex);

	if (ib_conn->cma_id != NULL) {
		rdma_destroy_id(ib_conn->cma_id);
		ib_conn->cma_id = NULL;
	}

	kfree(iser_conn);
}

/**
 * triggers start of the disconnect procedures and wait for them to be done
 */
void iser_conn_terminate(struct iser_conn *ib_conn)
{
	int err = 0;

	/* change the ib conn state only if the conn is UP, however always call
	 * rdma_disconnect since this is the only way to cause the CMA to change
	 * the QP state to ERROR
	 */

	iser_conn_state_comp_exch(ib_conn, ISER_CONN_UP, ISER_CONN_TERMINATING);
	err = rdma_disconnect(ib_conn->cma_id);
	if (err)
		iser_err("Failed to disconnect, conn: 0x%p err %d\n",
			 ib_conn,err);

	wait_event_interruptible(ib_conn->wait,
				 ib_conn->state == ISER_CONN_DOWN);

	iser_conn_put(ib_conn);
}

static void iser_connect_error(struct rdma_cm_id *cma_id)
{
	struct iser_conn *ib_conn;
	ib_conn = (struct iser_conn *)cma_id->context;

	ib_conn->state = ISER_CONN_DOWN;
	wake_up_interruptible(&ib_conn->wait);
}

static void iser_addr_handler(struct rdma_cm_id *cma_id)
{
	struct iser_device *device;
	struct iser_conn   *ib_conn;
	int    ret;

 * Called with state mutex held
 */
int iser_conn_terminate(struct iser_conn *iser_conn)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;
	int err = 0;

	/* terminate the iser conn only if the conn state is UP */
	if (!iser_conn_state_comp_exch(iser_conn, ISER_CONN_UP,
				       ISER_CONN_TERMINATING))
		return 0;

	iser_info("iser_conn %p state %d\n", iser_conn, iser_conn->state);

	/* suspend queuing of new iscsi commands */
	if (iser_conn->iscsi_conn)
		iscsi_suspend_queue(iser_conn->iscsi_conn);

	/*
	 * In case we didn't already clean up the cma_id (peer initiated
	 * a disconnection), we need to Cause the CMA to change the QP
	 * state to ERROR.
	 */
	if (ib_conn->cma_id) {
		err = rdma_disconnect(ib_conn->cma_id);
		if (err)
			iser_err("Failed to disconnect, conn: 0x%p err %d\n",
				 iser_conn, err);

		/* block until all flush errors are consumed */
		ib_drain_sq(ib_conn->qp);
	}

	return 1;
}

/**
 * Called with state mutex held
 **/
static void iser_connect_error(struct rdma_cm_id *cma_id)
{
	struct iser_conn *iser_conn;

	iser_conn = (struct iser_conn *)cma_id->context;
	iser_conn->state = ISER_CONN_TERMINATING;
}

static void
iser_calc_scsi_params(struct iser_conn *iser_conn,
		      unsigned int max_sectors)
{
	struct iser_device *device = iser_conn->ib_conn.device;
	struct ib_device_attr *attr = &device->ib_device->attrs;
	unsigned short sg_tablesize, sup_sg_tablesize;
	unsigned short reserved_mr_pages;

	/*
	 * FRs without SG_GAPS or FMRs can only map up to a (device) page per
	 * entry, but if the first entry is misaligned we'll end up using two
	 * entries (head and tail) for a single page worth data, so one
	 * additional entry is required.
	 */
	if ((attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS) &&
	    (attr->device_cap_flags & IB_DEVICE_SG_GAPS_REG))
		reserved_mr_pages = 0;
	else
		reserved_mr_pages = 1;

	sg_tablesize = DIV_ROUND_UP(max_sectors * 512, SIZE_4K);
	if (attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS)
		sup_sg_tablesize =
			min_t(
			 uint, ISCSI_ISER_MAX_SG_TABLESIZE,
			 attr->max_fast_reg_page_list_len - reserved_mr_pages);
	else
		sup_sg_tablesize = ISCSI_ISER_MAX_SG_TABLESIZE;

	iser_conn->scsi_sg_tablesize = min(sg_tablesize, sup_sg_tablesize);
	iser_conn->pages_per_mr =
		iser_conn->scsi_sg_tablesize + reserved_mr_pages;
}

/**
 * Called with state mutex held
 **/
static void iser_addr_handler(struct rdma_cm_id *cma_id)
{
	struct iser_device *device;
	struct iser_conn   *iser_conn;
	struct ib_conn   *ib_conn;
	int    ret;

	iser_conn = (struct iser_conn *)cma_id->context;
	if (iser_conn->state != ISER_CONN_PENDING)
		/* bailout */
		return;

	ib_conn = &iser_conn->ib_conn;
	device = iser_device_find_by_ib_device(cma_id);
	if (!device) {
		iser_err("device lookup/creation failed\n");
		iser_connect_error(cma_id);
		return;
	}

	ib_conn = (struct iser_conn *)cma_id->context;
	ib_conn->device = device;

	ib_conn->device = device;

	/* connection T10-PI support */
	if (iser_pi_enable) {
		if (!(device->ib_device->attrs.device_cap_flags &
		      IB_DEVICE_SIGNATURE_HANDOVER)) {
			iser_warn("T10-PI requested but not supported on %s, "
				  "continue without T10-PI\n",
				  ib_conn->device->ib_device->name);
			ib_conn->pi_support = false;
		} else {
			ib_conn->pi_support = true;
		}
	}

	iser_calc_scsi_params(iser_conn, iser_max_sectors);

	ret = rdma_resolve_route(cma_id, 1000);
	if (ret) {
		iser_err("resolve route failed: %d\n", ret);
		iser_connect_error(cma_id);
	}
}

		return;
	}
}

/**
 * Called with state mutex held
 **/
static void iser_route_handler(struct rdma_cm_id *cma_id)
{
	struct rdma_conn_param conn_param;
	int    ret;

	ret = iser_create_ib_conn_res((struct iser_conn *)cma_id->context);
	if (ret)
		goto failure;

	iser_dbg("path.mtu is %d setting it to %d\n",
		 cma_id->route.path_rec->mtu, IB_MTU_1024);

	/* we must set the MTU to 1024 as this is what the target is assuming */
	if (cma_id->route.path_rec->mtu > IB_MTU_1024)
		cma_id->route.path_rec->mtu = IB_MTU_1024;

	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 4;
	struct iser_cm_hdr req_hdr;
	struct iser_conn *iser_conn = (struct iser_conn *)cma_id->context;
	struct ib_conn *ib_conn = &iser_conn->ib_conn;
	struct iser_device *device = ib_conn->device;

	if (iser_conn->state != ISER_CONN_PENDING)
		/* bailout */
		return;

	ret = iser_create_ib_conn_res(ib_conn);
	if (ret)
		goto failure;

	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = device->ib_device->attrs.max_qp_rd_atom;
	conn_param.initiator_depth     = 1;
	conn_param.retry_count	       = 7;
	conn_param.rnr_retry_count     = 6;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.flags = ISER_ZBVA_NOT_SUP;
	if (!device->remote_inv_sup)
		req_hdr.flags |= ISER_SEND_W_INV_NOT_SUP;
	conn_param.private_data	= (void *)&req_hdr;
	conn_param.private_data_len = sizeof(struct iser_cm_hdr);

	ret = rdma_connect(cma_id, &conn_param);
	if (ret) {
		iser_err("failure connecting: %d\n", ret);
		goto failure;
	}

	return;
failure:
	iser_connect_error(cma_id);
}

static void iser_connected_handler(struct rdma_cm_id *cma_id,
				   const void *private_data)
{
	struct iser_conn *ib_conn;

	ib_conn = (struct iser_conn *)cma_id->context;
	ib_conn->state = ISER_CONN_UP;
	wake_up_interruptible(&ib_conn->wait);
	struct iser_conn *iser_conn;
	struct ib_qp_attr attr;
	struct ib_qp_init_attr init_attr;

	iser_conn = (struct iser_conn *)cma_id->context;
	if (iser_conn->state != ISER_CONN_PENDING)
		/* bailout */
		return;

	(void)ib_query_qp(cma_id->qp, &attr, ~0, &init_attr);
	iser_info("remote qpn:%x my qpn:%x\n", attr.dest_qp_num, cma_id->qp->qp_num);

	if (private_data) {
		u8 flags = *(u8 *)private_data;

		iser_conn->snd_w_inv = !(flags & ISER_SEND_W_INV_NOT_SUP);
	}

	iser_info("conn %p: negotiated %s invalidation\n",
		  iser_conn, iser_conn->snd_w_inv ? "remote" : "local");

	iser_conn->state = ISER_CONN_UP;
	complete(&iser_conn->up_completion);
}

static void iser_disconnected_handler(struct rdma_cm_id *cma_id)
{
	struct iser_conn *ib_conn;

	ib_conn = (struct iser_conn *)cma_id->context;
	ib_conn->disc_evt_flag = 1;

	/* getting here when the state is UP means that the conn is being *
	 * terminated asynchronously from the iSCSI layer's perspective.  */
	if (iser_conn_state_comp_exch(ib_conn, ISER_CONN_UP,
				      ISER_CONN_TERMINATING))
		iscsi_conn_failure(ib_conn->iser_conn->iscsi_conn,
				   ISCSI_ERR_CONN_FAILED);

	/* Complete the termination process if no posts are pending */
	if ((atomic_read(&ib_conn->post_recv_buf_count) == 0) &&
	    (atomic_read(&ib_conn->post_send_buf_count) == 0)) {
		ib_conn->state = ISER_CONN_DOWN;
		wake_up_interruptible(&ib_conn->wait);
	}
}

static int iser_cma_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	int ret = 0;

	iser_err("event %d conn %p id %p\n",event->event,cma_id->context,cma_id);

	struct iser_conn *iser_conn = (struct iser_conn *)cma_id->context;

	if (iser_conn_terminate(iser_conn)) {
		if (iser_conn->iscsi_conn)
			iscsi_conn_failure(iser_conn->iscsi_conn,
					   ISCSI_ERR_CONN_FAILED);
		else
			iser_err("iscsi_iser connection isn't bound\n");
	}
}

static void iser_cleanup_handler(struct rdma_cm_id *cma_id,
				 bool destroy)
{
	struct iser_conn *iser_conn = (struct iser_conn *)cma_id->context;

	/*
	 * We are not guaranteed that we visited disconnected_handler
	 * by now, call it here to be safe that we handle CM drep
	 * and flush errors.
	 */
	iser_disconnected_handler(cma_id);
	iser_free_ib_conn_res(iser_conn, destroy);
	complete(&iser_conn->ib_completion);
};

static int iser_cma_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	struct iser_conn *iser_conn;
	int ret = 0;

	iser_conn = (struct iser_conn *)cma_id->context;
	iser_info("%s (%d): status %d conn %p id %p\n",
		  rdma_event_msg(event->event), event->event,
		  event->status, cma_id->context, cma_id);

	mutex_lock(&iser_conn->state_mutex);
	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		iser_addr_handler(cma_id);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		iser_route_handler(cma_id);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		iser_connected_handler(cma_id, event->param.conn.private_data);
		break;
	case RDMA_CM_EVENT_REJECTED:
		iser_info("Connection rejected: %s\n",
			 rdma_reject_msg(cma_id, event->status));
		/* FALLTHROUGH */
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		iser_err("event: %d, error: %d\n", event->event, event->status);
		iser_connect_error(cma_id);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_ADDR_CHANGE:
		iser_disconnected_handler(cma_id);
		break;
	default:
		iser_err("Unexpected RDMA CM event (%d)\n", event->event);
		break;
	}
	return ret;
}

void iser_conn_init(struct iser_conn *ib_conn)
{
	ib_conn->state = ISER_CONN_INIT;
	init_waitqueue_head(&ib_conn->wait);
	atomic_set(&ib_conn->post_recv_buf_count, 0);
	atomic_set(&ib_conn->post_send_buf_count, 0);
	atomic_set(&ib_conn->refcount, 1);
	INIT_LIST_HEAD(&ib_conn->conn_list);
	spin_lock_init(&ib_conn->lock);
		iser_connect_error(cma_id);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		iser_cleanup_handler(cma_id, false);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/*
		 * we *must* destroy the device as we cannot rely
		 * on iscsid to be around to initiate error handling.
		 * also if we are not in state DOWN implicitly destroy
		 * the cma_id.
		 */
		iser_cleanup_handler(cma_id, true);
		if (iser_conn->state != ISER_CONN_DOWN) {
			iser_conn->ib_conn.cma_id = NULL;
			ret = 1;
		}
		break;
	default:
		iser_err("Unexpected RDMA CM event: %s (%d)\n",
			 rdma_event_msg(event->event), event->event);
		break;
	}
	mutex_unlock(&iser_conn->state_mutex);

	return ret;
}

void iser_conn_init(struct iser_conn *iser_conn)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;

	iser_conn->state = ISER_CONN_INIT;
	init_completion(&iser_conn->stop_completion);
	init_completion(&iser_conn->ib_completion);
	init_completion(&iser_conn->up_completion);
	INIT_LIST_HEAD(&iser_conn->conn_list);
	mutex_init(&iser_conn->state_mutex);

	ib_conn->post_recv_buf_count = 0;
	ib_conn->reg_cqe.done = iser_reg_comp;
}

 /**
 * starts the process of connecting to the target
 * sleeps untill the connection is established or rejected
 */
int iser_connect(struct iser_conn   *ib_conn,
		 struct sockaddr_in *src_addr,
		 struct sockaddr_in *dst_addr,
		 int                 non_blocking)
{
	struct sockaddr *src, *dst;
	int err = 0;

	sprintf(ib_conn->name,"%d.%d.%d.%d:%d",
		NIPQUAD(dst_addr->sin_addr.s_addr), dst_addr->sin_port);
 * sleeps until the connection is established or rejected
 */
int iser_connect(struct iser_conn   *iser_conn,
		 struct sockaddr    *src_addr,
		 struct sockaddr    *dst_addr,
		 int                 non_blocking)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;
	int err = 0;

	mutex_lock(&iser_conn->state_mutex);

	sprintf(iser_conn->name, "%pISp", dst_addr);

	iser_info("connecting to: %s\n", iser_conn->name);

	/* the device is known only --after-- address resolution */
	ib_conn->device = NULL;

	iser_err("connecting to: %d.%d.%d.%d, port 0x%x\n",
		 NIPQUAD(dst_addr->sin_addr), dst_addr->sin_port);

	ib_conn->state = ISER_CONN_PENDING;

	ib_conn->cma_id = rdma_create_id(iser_cma_handler,
					     (void *)ib_conn,
					     RDMA_PS_TCP);
	iser_conn->state = ISER_CONN_PENDING;

	ib_conn->cma_id = rdma_create_id(&init_net, iser_cma_handler,
					 (void *)iser_conn,
					 RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(ib_conn->cma_id)) {
		err = PTR_ERR(ib_conn->cma_id);
		iser_err("rdma_create_id failed: %d\n", err);
		goto id_failure;
	}

	src = (struct sockaddr *)src_addr;
	dst = (struct sockaddr *)dst_addr;
	err = rdma_resolve_addr(ib_conn->cma_id, src, dst, 1000);
	err = rdma_resolve_addr(ib_conn->cma_id, src_addr, dst_addr, 1000);
	if (err) {
		iser_err("rdma_resolve_addr failed: %d\n", err);
		goto addr_failure;
	}

	if (!non_blocking) {
		wait_event_interruptible(ib_conn->wait,
					 (ib_conn->state != ISER_CONN_PENDING));

		if (ib_conn->state != ISER_CONN_UP) {
		wait_for_completion_interruptible(&iser_conn->up_completion);

		if (iser_conn->state != ISER_CONN_UP) {
			err =  -EIO;
			goto connect_failure;
		}
	}

	mutex_lock(&ig.connlist_mutex);
	list_add(&ib_conn->conn_list, &ig.connlist);
	mutex_unlock(&iser_conn->state_mutex);

	mutex_lock(&ig.connlist_mutex);
	list_add(&iser_conn->conn_list, &ig.connlist);
	mutex_unlock(&ig.connlist_mutex);
	return 0;

id_failure:
	ib_conn->cma_id = NULL;
addr_failure:
	ib_conn->state = ISER_CONN_DOWN;
connect_failure:
	iser_conn_release(ib_conn);
	return err;
}

/**
 * iser_reg_page_vec - Register physical memory
 *
 * returns: 0 on success, errno code on failure
 */
int iser_reg_page_vec(struct iser_conn     *ib_conn,
		      struct iser_page_vec *page_vec,
		      struct iser_mem_reg  *mem_reg)
{
	struct ib_pool_fmr *mem;
	u64		   io_addr;
	u64		   *page_list;
	int		   status;

	page_list = page_vec->pages;
	io_addr	  = page_list[0];

	mem  = ib_fmr_pool_map_phys(ib_conn->fmr_pool,
				    page_list,
				    page_vec->length,
				    io_addr);

	if (IS_ERR(mem)) {
		status = (int)PTR_ERR(mem);
		iser_err("ib_fmr_pool_map_phys failed: %d\n", status);
		return status;
	}

	mem_reg->lkey  = mem->fmr->lkey;
	mem_reg->rkey  = mem->fmr->rkey;
	mem_reg->len   = page_vec->length * SIZE_4K;
	mem_reg->va    = io_addr;
	mem_reg->is_fmr = 1;
	mem_reg->mem_h = (void *)mem;

	mem_reg->va   += page_vec->offset;
	mem_reg->len   = page_vec->data_size;

	iser_dbg("PHYSICAL Mem.register, [PHYS p_array: 0x%p, sz: %d, "
		 "entry[0]: (0x%08lx,%ld)] -> "
		 "[lkey: 0x%08X mem_h: 0x%p va: 0x%08lX sz: %ld]\n",
		 page_vec, page_vec->length,
		 (unsigned long)page_vec->pages[0],
		 (unsigned long)page_vec->data_size,
		 (unsigned int)mem_reg->lkey, mem_reg->mem_h,
		 (unsigned long)mem_reg->va, (unsigned long)mem_reg->len);
	return 0;
}

/**
 * Unregister (previosuly registered) memory.
 */
void iser_unreg_mem(struct iser_mem_reg *reg)
{
	int ret;

	iser_dbg("PHYSICAL Mem.Unregister mem_h %p\n",reg->mem_h);

	ret = ib_fmr_pool_unmap((struct ib_pool_fmr *)reg->mem_h);
	if (ret)
		iser_err("ib_fmr_pool_unmap failed %d\n", ret);

	reg->mem_h = NULL;
}

/**
 * iser_dto_to_iov - builds IOV from a dto descriptor
 */
static void iser_dto_to_iov(struct iser_dto *dto, struct ib_sge *iov, int iov_len)
{
	int		     i;
	struct ib_sge	     *sge;
	struct iser_regd_buf *regd_buf;

	if (dto->regd_vector_len > iov_len) {
		iser_err("iov size %d too small for posting dto of len %d\n",
			 iov_len, dto->regd_vector_len);
		BUG();
	}

	for (i = 0; i < dto->regd_vector_len; i++) {
		sge	    = &iov[i];
		regd_buf  = dto->regd[i];

		sge->addr   = regd_buf->reg.va;
		sge->length = regd_buf->reg.len;
		sge->lkey   = regd_buf->reg.lkey;

		if (dto->used_sz[i] > 0)  /* Adjust size */
			sge->length = dto->used_sz[i];

		/* offset and length should not exceed the regd buf length */
		if (sge->length + dto->offset[i] > regd_buf->reg.len) {
			iser_err("Used len:%ld + offset:%d, exceed reg.buf.len:"
				 "%ld in dto:0x%p [%d], va:0x%08lX\n",
				 (unsigned long)sge->length, dto->offset[i],
				 (unsigned long)regd_buf->reg.len, dto, i,
				 (unsigned long)sge->addr);
			BUG();
		}

		sge->addr += dto->offset[i]; /* Adjust offset */
	}
}

/**
 * iser_post_recv - Posts a receive buffer.
 *
 * returns 0 on success, -1 on failure
 */
int iser_post_recv(struct iser_desc *rx_desc)
{
	int		  ib_ret, ret_val = 0;
	struct ib_recv_wr recv_wr, *recv_wr_failed;
	struct ib_sge	  iov[2];
	struct iser_conn  *ib_conn;
	struct iser_dto   *recv_dto = &rx_desc->dto;

	/* Retrieve conn */
	ib_conn = recv_dto->ib_conn;

	iser_dto_to_iov(recv_dto, iov, 2);

	recv_wr.next	= NULL;
	recv_wr.sg_list = iov;
	recv_wr.num_sge = recv_dto->regd_vector_len;
	recv_wr.wr_id	= (unsigned long)rx_desc;

	atomic_inc(&ib_conn->post_recv_buf_count);
	ib_ret	= ib_post_recv(ib_conn->qp, &recv_wr, &recv_wr_failed);
	if (ib_ret) {
		iser_err("ib_post_recv failed ret=%d\n", ib_ret);
		atomic_dec(&ib_conn->post_recv_buf_count);
		ret_val = -1;
	}

	return ret_val;
}

	iser_conn->state = ISER_CONN_DOWN;
connect_failure:
	mutex_unlock(&iser_conn->state_mutex);
	iser_conn_release(iser_conn);
	return err;
}

int iser_post_recvl(struct iser_conn *iser_conn)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;
	struct iser_login_desc *desc = &iser_conn->login_desc;
	struct ib_recv_wr wr;
	int ib_ret;

	desc->sge.addr = desc->rsp_dma;
	desc->sge.length = ISER_RX_LOGIN_SIZE;
	desc->sge.lkey = ib_conn->device->pd->local_dma_lkey;

	desc->cqe.done = iser_login_rsp;
	wr.wr_cqe = &desc->cqe;
	wr.sg_list = &desc->sge;
	wr.num_sge = 1;
	wr.next = NULL;

	ib_conn->post_recv_buf_count++;
	ib_ret = ib_post_recv(ib_conn->qp, &wr, NULL);
	if (ib_ret) {
		iser_err("ib_post_recv failed ret=%d\n", ib_ret);
		ib_conn->post_recv_buf_count--;
	}

	return ib_ret;
}

int iser_post_recvm(struct iser_conn *iser_conn, int count)
{
	struct ib_conn *ib_conn = &iser_conn->ib_conn;
	unsigned int my_rx_head = iser_conn->rx_desc_head;
	struct iser_rx_desc *rx_desc;
	struct ib_recv_wr *wr;
	int i, ib_ret;

	for (wr = ib_conn->rx_wr, i = 0; i < count; i++, wr++) {
		rx_desc = &iser_conn->rx_descs[my_rx_head];
		rx_desc->cqe.done = iser_task_rsp;
		wr->wr_cqe = &rx_desc->cqe;
		wr->sg_list = &rx_desc->rx_sg;
		wr->num_sge = 1;
		wr->next = wr + 1;
		my_rx_head = (my_rx_head + 1) & iser_conn->qp_max_recv_dtos_mask;
	}

	wr--;
	wr->next = NULL; /* mark end of work requests list */

	ib_conn->post_recv_buf_count += count;
	ib_ret = ib_post_recv(ib_conn->qp, ib_conn->rx_wr, NULL);
	if (ib_ret) {
		iser_err("ib_post_recv failed ret=%d\n", ib_ret);
		ib_conn->post_recv_buf_count -= count;
	} else
		iser_conn->rx_desc_head = my_rx_head;

	return ib_ret;
}


/**
 * iser_start_send - Initiate a Send DTO operation
 *
 * returns 0 on success, -1 on failure
 */
int iser_post_send(struct iser_desc *tx_desc)
{
	int		  ib_ret, ret_val = 0;
	struct ib_send_wr send_wr, *send_wr_failed;
	struct ib_sge	  iov[MAX_REGD_BUF_VECTOR_LEN];
	struct iser_conn  *ib_conn;
	struct iser_dto   *dto = &tx_desc->dto;

	ib_conn = dto->ib_conn;

	iser_dto_to_iov(dto, iov, MAX_REGD_BUF_VECTOR_LEN);

	send_wr.next	   = NULL;
	send_wr.wr_id	   = (unsigned long)tx_desc;
	send_wr.sg_list	   = iov;
	send_wr.num_sge	   = dto->regd_vector_len;
	send_wr.opcode	   = IB_WR_SEND;
	send_wr.send_flags = dto->notify_enable ? IB_SEND_SIGNALED : 0;

	atomic_inc(&ib_conn->post_send_buf_count);

	ib_ret = ib_post_send(ib_conn->qp, &send_wr, &send_wr_failed);
	if (ib_ret) {
		iser_err("Failed to start SEND DTO, dto: 0x%p, IOV len: %d\n",
			 dto, dto->regd_vector_len);
		iser_err("ib_post_send failed, ret:%d\n", ib_ret);
		atomic_dec(&ib_conn->post_send_buf_count);
		ret_val = -1;
	}

	return ret_val;
}

static void iser_handle_comp_error(struct iser_desc *desc)
{
	struct iser_dto  *dto     = &desc->dto;
	struct iser_conn *ib_conn = dto->ib_conn;

	iser_dto_buffs_release(dto);

	if (desc->type == ISCSI_RX) {
		kfree(desc->data);
		kmem_cache_free(ig.desc_cache, desc);
		atomic_dec(&ib_conn->post_recv_buf_count);
	} else { /* type is TX control/command/dataout */
		if (desc->type == ISCSI_TX_DATAOUT)
			kmem_cache_free(ig.desc_cache, desc);
		atomic_dec(&ib_conn->post_send_buf_count);
	}

	if (atomic_read(&ib_conn->post_recv_buf_count) == 0 &&
	    atomic_read(&ib_conn->post_send_buf_count) == 0) {
		/* getting here when the state is UP means that the conn is *
		 * being terminated asynchronously from the iSCSI layer's   *
		 * perspective.                                             */
		if (iser_conn_state_comp_exch(ib_conn, ISER_CONN_UP,
		    ISER_CONN_TERMINATING))
			iscsi_conn_failure(ib_conn->iser_conn->iscsi_conn,
					   ISCSI_ERR_CONN_FAILED);

		/* complete the termination process if disconnect event was delivered *
		 * note there are no more non completed posts to the QP               */
		if (ib_conn->disc_evt_flag) {
			ib_conn->state = ISER_CONN_DOWN;
			wake_up_interruptible(&ib_conn->wait);
		}
	}
}

static void iser_cq_tasklet_fn(unsigned long data)
{
	 struct iser_device  *device = (struct iser_device *)data;
	 struct ib_cq	     *cq = device->cq;
	 struct ib_wc	     wc;
	 struct iser_desc    *desc;
	 unsigned long	     xfer_len;

	while (ib_poll_cq(cq, 1, &wc) == 1) {
		desc	 = (struct iser_desc *) (unsigned long) wc.wr_id;
		BUG_ON(desc == NULL);

		if (wc.status == IB_WC_SUCCESS) {
			if (desc->type == ISCSI_RX) {
				xfer_len = (unsigned long)wc.byte_len;
				iser_rcv_completion(desc, xfer_len);
			} else /* type == ISCSI_TX_CONTROL/SCSI_CMD/DOUT */
				iser_snd_completion(desc);
		} else {
			iser_err("comp w. error op %d status %d\n",desc->type,wc.status);
			iser_handle_comp_error(desc);
		}
	}
	/* #warning "it is assumed here that arming CQ only once its empty" *
	 * " would not cause interrupts to be missed"                       */
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
int iser_post_send(struct ib_conn *ib_conn, struct iser_tx_desc *tx_desc,
		   bool signal)
{
	struct ib_send_wr *wr = iser_tx_next_wr(tx_desc);
	int ib_ret;

	ib_dma_sync_single_for_device(ib_conn->device->ib_device,
				      tx_desc->dma_addr, ISER_HEADERS_LEN,
				      DMA_TO_DEVICE);

	wr->next = NULL;
	wr->wr_cqe = &tx_desc->cqe;
	wr->sg_list = tx_desc->tx_sg;
	wr->num_sge = tx_desc->num_sge;
	wr->opcode = IB_WR_SEND;
	wr->send_flags = signal ? IB_SEND_SIGNALED : 0;

	ib_ret = ib_post_send(ib_conn->qp, &tx_desc->wrs[0].send, NULL);
	if (ib_ret)
		iser_err("ib_post_send failed, ret:%d opcode:%d\n",
			 ib_ret, wr->opcode);

	return ib_ret;
}

/**
 * is_iser_tx_desc - Indicate if the completion wr_id
 *     is a TX descriptor or not.
 * @iser_conn: iser connection
 * @wr_id: completion WR identifier
 *
 * Since we cannot rely on wc opcode in FLUSH errors
 * we must work around it by checking if the wr_id address
 * falls in the iser connection rx_descs buffer. If so
 * it is an RX descriptor, otherwize it is a TX.
 */
static inline bool
is_iser_tx_desc(struct iser_conn *iser_conn, void *wr_id)
{
	void *start = iser_conn->rx_descs;
	int len = iser_conn->num_rx_descs * sizeof(*iser_conn->rx_descs);

	if (wr_id >= start && wr_id < start + len)
		return false;

	return true;
}

/**
 * iser_handle_comp_error() - Handle error completion
 * @ib_conn:   connection RDMA resources
 * @wc:        work completion
 *
 * Notes: We may handle a FLUSH error completion and in this case
 *        we only cleanup in case TX type was DATAOUT. For non-FLUSH
 *        error completion we should also notify iscsi layer that
 *        connection is failed (in case we passed bind stage).
 */
static void
iser_handle_comp_error(struct ib_conn *ib_conn,
		       struct ib_wc *wc)
{
	void *wr_id = (void *)(uintptr_t)wc->wr_id;
	struct iser_conn *iser_conn = container_of(ib_conn, struct iser_conn,
						   ib_conn);

	if (wc->status != IB_WC_WR_FLUSH_ERR)
		if (iser_conn->iscsi_conn)
			iscsi_conn_failure(iser_conn->iscsi_conn,
					   ISCSI_ERR_CONN_FAILED);

	if (wc->wr_id == ISER_FASTREG_LI_WRID)
		return;

	if (is_iser_tx_desc(iser_conn, wr_id)) {
		struct iser_tx_desc *desc = wr_id;

		if (desc->type == ISCSI_TX_DATAOUT)
			kmem_cache_free(ig.desc_cache, desc);
	} else {
		ib_conn->post_recv_buf_count--;
	}
}

/**
 * iser_handle_wc - handle a single work completion
 * @wc: work completion
 *
 * Soft-IRQ context, work completion can be either
 * SEND or RECV, and can turn out successful or
 * with error (or flush error).
 */
static void iser_handle_wc(struct ib_wc *wc)
{
	struct ib_conn *ib_conn;
	struct iser_tx_desc *tx_desc;
	struct iser_rx_desc *rx_desc;

	ib_conn = wc->qp->qp_context;
	if (likely(wc->status == IB_WC_SUCCESS)) {
		if (wc->opcode == IB_WC_RECV) {
			rx_desc = (struct iser_rx_desc *)(uintptr_t)wc->wr_id;
			iser_rcv_completion(rx_desc, wc->byte_len,
					    ib_conn);
		} else
		if (wc->opcode == IB_WC_SEND) {
			tx_desc = (struct iser_tx_desc *)(uintptr_t)wc->wr_id;
			iser_snd_completion(tx_desc, ib_conn);
		} else {
			iser_err("Unknown wc opcode %d\n", wc->opcode);
		}
	} else {
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			iser_err("%s (%d): wr id %llx vend_err %x\n",
				 ib_wc_status_msg(wc->status), wc->status,
				 wc->wr_id, wc->vendor_err);
		else
			iser_dbg("%s (%d): wr id %llx\n",
				 ib_wc_status_msg(wc->status), wc->status,
				 wc->wr_id);

		if (wc->wr_id == ISER_BEACON_WRID)
			/* all flush errors were consumed */
			complete(&ib_conn->flush_comp);
		else
			iser_handle_comp_error(ib_conn, wc);
	}
}

/**
 * iser_cq_tasklet_fn - iSER completion polling loop
 * @data: iSER completion context
 *
 * Soft-IRQ context, polling connection CQ until
 * either CQ was empty or we exausted polling budget
 */
static void iser_cq_tasklet_fn(unsigned long data)
{
	struct iser_comp *comp = (struct iser_comp *)data;
	struct ib_cq *cq = comp->cq;
	struct ib_wc *const wcs = comp->wcs;
	int i, n, completed = 0;

	while ((n = ib_poll_cq(cq, ARRAY_SIZE(comp->wcs), wcs)) > 0) {
		for (i = 0; i < n; i++)
			iser_handle_wc(&wcs[i]);

		completed += n;
		if (completed >= iser_cq_poll_limit)
			break;
	}

	/*
	 * It is assumed here that arming CQ only once its empty
	 * would not cause interrupts to be missed.
	 */
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);

	iser_dbg("got %d completions\n", completed);
}

static void iser_cq_callback(struct ib_cq *cq, void *cq_context)
{
	struct iser_device  *device = (struct iser_device *)cq_context;

	tasklet_schedule(&device->cq_tasklet);
	struct iser_comp *comp = cq_context;

	tasklet_schedule(&comp->tasklet);
}

u8 iser_check_task_pi_status(struct iscsi_iser_task *iser_task,
			     enum iser_data_dir cmd_dir, sector_t *sector)
{
	struct iser_mem_reg *reg = &iser_task->rdma_reg[cmd_dir];
	struct iser_fr_desc *desc = reg->mem_h;
	unsigned long sector_size = iser_task->sc->device->sector_size;
	struct ib_mr_status mr_status;
	int ret;

	if (desc && desc->pi_ctx->sig_protected) {
		desc->pi_ctx->sig_protected = 0;
		ret = ib_check_mr_status(desc->pi_ctx->sig_mr,
					 IB_MR_CHECK_SIG_STATUS, &mr_status);
		if (ret) {
			pr_err("ib_check_mr_status failed, ret %d\n", ret);
			/* Not a lot we can do, return ambiguous guard error */
			*sector = 0;
			return 0x1;
		}

		if (mr_status.fail_status & IB_MR_CHECK_SIG_STATUS) {
			sector_t sector_off = mr_status.sig_err.sig_err_offset;

			sector_div(sector_off, sector_size + 8);
			*sector = scsi_get_lba(iser_task->sc) + sector_off;

			pr_err("PI error found type %d at sector %llx "
			       "expected %x vs actual %x\n",
			       mr_status.sig_err.err_type,
			       (unsigned long long)*sector,
			       mr_status.sig_err.expected,
			       mr_status.sig_err.actual);

			switch (mr_status.sig_err.err_type) {
			case IB_SIG_BAD_GUARD:
				return 0x1;
			case IB_SIG_BAD_REFTAG:
				return 0x3;
			case IB_SIG_BAD_APPTAG:
				return 0x2;
			}
		}
	}

	return 0;
}

void iser_err_comp(struct ib_wc *wc, const char *type)
{
	if (wc->status != IB_WC_WR_FLUSH_ERR) {
		struct iser_conn *iser_conn = to_iser_conn(wc->qp->qp_context);

		iser_err("%s failure: %s (%d) vend_err %#x\n", type,
			 ib_wc_status_msg(wc->status), wc->status,
			 wc->vendor_err);

		if (iser_conn->iscsi_conn)
			iscsi_conn_failure(iser_conn->iscsi_conn,
					   ISCSI_ERR_CONN_FAILED);
	} else {
		iser_dbg("%s failure: %s (%d)\n", type,
			 ib_wc_status_msg(wc->status), wc->status);
	}
}
