/*
 * bsg.c - block layer implementation of the sg v4 interface
 *
 * Copyright (C) 2004 Jens Axboe <axboe@suse.de> SUSE Labs
 * Copyright (C) 2004 Peter M. Jones <pjones@redhat.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License version 2.  See the file "COPYING" in the main directory of this
 *  archive for more details.
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/jiffies.h>
#include <linux/percpu.h>
#include <linux/idr.h>
#include <linux/bsg.h>
#include <linux/smp_lock.h>
#include <linux/slab.h>

#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/sg.h>

#define BSG_DESCRIPTION	"Block layer SCSI generic (bsg) driver"
#define BSG_VERSION	"0.4"

#define bsg_dbg(bd, fmt, ...) \
	pr_debug("%s: " fmt, (bd)->name, ##__VA_ARGS__)

struct bsg_device {
	struct request_queue *queue;
	spinlock_t lock;
	struct hlist_node dev_list;
	atomic_t ref_count;
	int queued_cmds;
	int done_cmds;
	wait_queue_head_t wq_done;
	wait_queue_head_t wq_free;
	char name[BUS_ID_SIZE];
	refcount_t ref_count;
	char name[20];
	int max_queue;
};

#define BSG_DEFAULT_CMDS	64
#define BSG_MAX_DEVS		32768

static DEFINE_MUTEX(bsg_mutex);
static DEFINE_IDR(bsg_minor_idr);

#define BSG_LIST_ARRAY_SIZE	8
static struct hlist_head bsg_device_list[BSG_LIST_ARRAY_SIZE];

static struct class *bsg_class;
static int bsg_major;

static inline struct hlist_head *bsg_dev_idx_hash(int index)
{
	return &bsg_device_list[index & (BSG_LIST_ARRAY_SIZE - 1)];
}

static int bsg_io_schedule(struct bsg_device *bd)
{
	DEFINE_WAIT(wait);
	int ret = 0;

	spin_lock_irq(&bd->lock);

	BUG_ON(bd->done_cmds > bd->queued_cmds);

	/*
	 * -ENOSPC or -ENODATA?  I'm going for -ENODATA, meaning "I have no
	 * work to do", even though we return -ENOSPC after this same test
	 * during bsg_write() -- there, it means our buffer can't have more
	 * bsg_commands added to it, thus has no space left.
	 */
	if (bd->done_cmds == bd->queued_cmds) {
		ret = -ENODATA;
		goto unlock;
	}

	if (!test_bit(BSG_F_BLOCK, &bd->flags)) {
		ret = -EAGAIN;
		goto unlock;
	}

	prepare_to_wait(&bd->wq_done, &wait, TASK_UNINTERRUPTIBLE);
	spin_unlock_irq(&bd->lock);
	io_schedule();
	finish_wait(&bd->wq_done, &wait);

	return ret;
unlock:
	spin_unlock_irq(&bd->lock);
	return ret;
}

static int blk_fill_sgv4_hdr_rq(struct request_queue *q, struct request *rq,
				struct sg_io_v4 *hdr, struct bsg_device *bd,
				int has_write_perm)
static int blk_fill_sgv4_hdr_rq(struct request_queue *q, struct request *rq,
				struct sg_io_v4 *hdr, struct bsg_device *bd,
				fmode_t has_write_perm)
{
	struct scsi_request *req = scsi_req(rq);
#define uptr64(val) ((void __user *)(uintptr_t)(val))

static int bsg_scsi_check_proto(struct sg_io_v4 *hdr)
{
	if (hdr->protocol != BSG_PROTOCOL_SCSI  ||
	    hdr->subprotocol != BSG_SUB_PROTOCOL_SCSI_CMD)
		return -EINVAL;
	return 0;
}

static int bsg_scsi_fill_hdr(struct request *rq, struct sg_io_v4 *hdr,
		fmode_t mode)
{
	struct scsi_request *sreq = scsi_req(rq);

	sreq->cmd_len = hdr->request_len;
	if (sreq->cmd_len > BLK_MAX_CDB) {
		sreq->cmd = kzalloc(sreq->cmd_len, GFP_KERNEL);
		if (!sreq->cmd)
			return -ENOMEM;
	}

	if (copy_from_user(rq->cmd, (void *)(unsigned long)hdr->request,
	if (copy_from_user(rq->cmd, (void __user *)(unsigned long)hdr->request,
	if (copy_from_user(req->cmd, (void __user *)(unsigned long)hdr->request,
			   hdr->request_len))
		return -EFAULT;

	if (hdr->subprotocol == BSG_SUB_PROTOCOL_SCSI_CMD) {
		if (blk_verify_command(&q->cmd_filter, rq->cmd, has_write_perm))
		if (blk_verify_command(rq->cmd, has_write_perm))
		if (blk_verify_command(req->cmd, has_write_perm))
			return -EPERM;
	} else if (!capable(CAP_SYS_RAWIO))
	if (copy_from_user(sreq->cmd, uptr64(hdr->request), sreq->cmd_len))
		return -EFAULT;
	if (blk_verify_command(sreq->cmd, mode))
		return -EPERM;
	return 0;
}

static int bsg_scsi_complete_rq(struct request *rq, struct sg_io_v4 *hdr)
{
	struct scsi_request *sreq = scsi_req(rq);
	int ret = 0;

	/*
	 * fill in all the output members
	 */
	rq->cmd_len = hdr->request_len;
	rq->cmd_type = REQ_TYPE_BLOCK_PC;

	rq->timeout = (hdr->timeout * HZ) / 1000;
	req->cmd_len = hdr->request_len;
	hdr->device_status = sreq->result & 0xff;
	hdr->transport_status = host_byte(sreq->result);
	hdr->driver_status = driver_byte(sreq->result);
	hdr->info = 0;
	if (hdr->device_status || hdr->transport_status || hdr->driver_status)
		hdr->info |= SG_INFO_CHECK;
	hdr->response_len = 0;

	if (sreq->sense_len && hdr->response) {
		int len = min_t(unsigned int, hdr->max_response_len,
					sreq->sense_len);

		if (copy_to_user(uptr64(hdr->response), sreq->sense, len))
			ret = -EFAULT;
		else
			hdr->response_len = len;
	}

	if (rq->next_rq) {
		hdr->dout_resid = sreq->resid_len;
		hdr->din_resid = scsi_req(rq->next_rq)->resid_len;
	} else if (rq_data_dir(rq) == READ) {
		hdr->din_resid = sreq->resid_len;
	} else {
		hdr->dout_resid = sreq->resid_len;
	}

	return ret;
}

static void bsg_scsi_free_rq(struct request *rq)
{
	scsi_req_free_cmd(scsi_req(rq));
}

static const struct bsg_ops bsg_scsi_ops = {
	.check_proto		= bsg_scsi_check_proto,
	.fill_hdr		= bsg_scsi_fill_hdr,
	.complete_rq		= bsg_scsi_complete_rq,
	.free_rq		= bsg_scsi_free_rq,
};

static struct request *
bsg_map_hdr(struct request_queue *q, struct sg_io_v4 *hdr, fmode_t mode)
{
	struct request *rq, *next_rq = NULL;
	int ret;

	if (!q->bsg_dev.class_dev)
		return ERR_PTR(-ENXIO);

	if (hdr->guard != 'Q')
		return ERR_PTR(-EINVAL);

	ret = q->bsg_dev.ops->check_proto(hdr);
	if (ret)
		return ERR_PTR(ret);

	rq = blk_get_request(q, hdr->dout_xfer_len ?
			REQ_OP_SCSI_OUT : REQ_OP_SCSI_IN, 0);
	if (IS_ERR(rq))
		return rq;

	ret = q->bsg_dev.ops->fill_hdr(rq, hdr, mode);
	if (ret)
		goto out;

	rq->timeout = msecs_to_jiffies(hdr->timeout);
	if (!rq->timeout)
		rq->timeout = q->sg_timeout;
	if (!rq->timeout)
		rq->timeout = BLK_DEFAULT_SG_TIMEOUT;
	if (rq->timeout < BLK_MIN_SG_TIMEOUT)
		rq->timeout = BLK_MIN_SG_TIMEOUT;

	return 0;
}

/*
 * Check if sg_io_v4 from user is allowed and valid
 */
static int
bsg_validate_sgv4_hdr(struct sg_io_v4 *hdr, int *op)
{
	int ret = 0;

	if (hdr->guard != 'Q')
		return -EINVAL;
	if (hdr->dout_xfer_len > (q->max_sectors << 9) ||
	    hdr->din_xfer_len > (q->max_sectors << 9))
		return -EIO;

	switch (hdr->protocol) {
	case BSG_PROTOCOL_SCSI:
		switch (hdr->subprotocol) {
		case BSG_SUB_PROTOCOL_SCSI_CMD:
		case BSG_SUB_PROTOCOL_SCSI_TRANSPORT:
			break;
		default:
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
	}

	*op = hdr->dout_xfer_len ? REQ_OP_SCSI_OUT : REQ_OP_SCSI_IN;
	return ret;
}

/*
 * map sg_io_v4 to a request.
 */
static struct request *
bsg_map_hdr(struct bsg_device *bd, struct sg_io_v4 *hdr, int has_write_perm)
bsg_map_hdr(struct bsg_device *bd, struct sg_io_v4 *hdr, fmode_t has_write_perm,
	    u8 *sense)
{
	struct request_queue *q = bd->queue;
	struct request *rq, *next_rq = NULL;
	int ret, rw;
	unsigned int dxfer_len;
	void *dxferp = NULL;
bsg_map_hdr(struct bsg_device *bd, struct sg_io_v4 *hdr, fmode_t has_write_perm)
{
	struct request_queue *q = bd->queue;
	struct request *rq, *next_rq = NULL;
	int ret;
	unsigned int op, dxfer_len;
	void __user *dxferp = NULL;
	struct bsg_class_device *bcd = &q->bsg_dev;

	/* if the LLD has been removed then the bsg_unregister_queue will
	 * eventually be called and the class_dev was freed, so we can no
	 * longer use this request_queue. Return no such address.
	 */
	if (!bcd->class_dev)
		return ERR_PTR(-ENXIO);

	dprintk("map hdr %llx/%u %llx/%u\n", (unsigned long long) hdr->dout_xferp,
		hdr->dout_xfer_len, (unsigned long long) hdr->din_xferp,
		hdr->din_xfer_len);

	ret = bsg_validate_sgv4_hdr(hdr, &op);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * map scatter-gather elements seperately and string them to request
	 */
	rq = blk_get_request(q, rw, GFP_KERNEL);
	if (!rq)
		return ERR_PTR(-ENOMEM);
	 * map scatter-gather elements separately and string them to request
	 */
	rq = blk_get_request(q, op, GFP_KERNEL);
	if (IS_ERR(rq))
		return rq;

	ret = blk_fill_sgv4_hdr_rq(q, rq, hdr, bd, has_write_perm);
	if (ret)
		goto out;

	if (op == REQ_OP_SCSI_OUT && hdr->din_xfer_len) {
	if (hdr->dout_xfer_len && hdr->din_xfer_len) {
		if (!test_bit(QUEUE_FLAG_BIDI, &q->queue_flags)) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		next_rq = blk_get_request(q, READ, GFP_KERNEL);
		if (!next_rq) {
			ret = -ENOMEM;
		next_rq = blk_get_request(q, REQ_OP_SCSI_IN, GFP_KERNEL);
		next_rq = blk_get_request(q, REQ_OP_SCSI_IN, 0);
		if (IS_ERR(next_rq)) {
			ret = PTR_ERR(next_rq);
			goto out;
		}

		dxferp = (void*)(unsigned long)hdr->din_xferp;
		ret =  blk_rq_map_user(q, next_rq, dxferp, hdr->din_xfer_len);
		dxferp = (void __user *)(unsigned long)hdr->din_xferp;
		ret =  blk_rq_map_user(q, next_rq, NULL, dxferp,
		rq->next_rq = next_rq;
		ret = blk_rq_map_user(q, next_rq, NULL, uptr64(hdr->din_xferp),
				       hdr->din_xfer_len, GFP_KERNEL);
		if (ret)
			goto out_free_nextrq;
	}

	if (hdr->dout_xfer_len) {
		dxfer_len = hdr->dout_xfer_len;
		dxferp = (void*)(unsigned long)hdr->dout_xferp;
	} else if (hdr->din_xfer_len) {
		dxfer_len = hdr->din_xfer_len;
		dxferp = (void*)(unsigned long)hdr->din_xferp;
		dxferp = (void __user *)(unsigned long)hdr->dout_xferp;
	} else if (hdr->din_xfer_len) {
		dxfer_len = hdr->din_xfer_len;
		dxferp = (void __user *)(unsigned long)hdr->din_xferp;
	} else
		dxfer_len = 0;

	if (dxfer_len) {
		ret = blk_rq_map_user(q, rq, dxferp, dxfer_len);
		if (ret)
			goto out;
	}
		ret = blk_rq_map_user(q, rq, NULL, dxferp, dxfer_len,
				      GFP_KERNEL);
		if (ret)
			goto out;
		ret = blk_rq_map_user(q, rq, NULL, uptr64(hdr->dout_xferp),
				hdr->dout_xfer_len, GFP_KERNEL);
	} else if (hdr->din_xfer_len) {
		ret = blk_rq_map_user(q, rq, NULL, uptr64(hdr->din_xferp),
				hdr->din_xfer_len, GFP_KERNEL);
	}

	if (ret)
		goto out_unmap_nextrq;
	return rq;

/*
 * async completion call-back from the block layer, when scsi/ide/whatever
 * calls end_that_request_last() on a request
 */
static void bsg_rq_end_io(struct request *rq, blk_status_t status)
{
	struct bsg_command *bc = rq->end_io_data;
	struct bsg_device *bd = bc->bd;
	unsigned long flags;

	dprintk("%s: finished rq %p bc %p, bio %p\n",
		bd->name, rq, bc, bc->bio);

	bc->hdr.duration = jiffies_to_msecs(jiffies - bc->hdr.duration);

	spin_lock_irqsave(&bd->lock, flags);
	list_move_tail(&bc->list, &bd->done_list);
	bd->done_cmds++;
	spin_unlock_irqrestore(&bd->lock, flags);

	wake_up(&bd->wq_done);
}

/*
 * do final setup of a 'bc' and submit the matching 'rq' to the block
 * layer for io
 */
static void bsg_add_command(struct bsg_device *bd, struct request_queue *q,
			    struct bsg_command *bc, struct request *rq)
{
	rq->sense = bc->sense;
	rq->sense_len = 0;
	int at_head = (0 == (bc->hdr.flags & BSG_FLAG_Q_AT_TAIL));

	/*
	 * add bc command to busy queue and submit rq for io
	 */
	bc->rq = rq;
	bc->bio = rq->bio;
	if (rq->next_rq)
		bc->bidi_bio = rq->next_rq->bio;
	bc->hdr.duration = jiffies;
	spin_lock_irq(&bd->lock);
	list_add_tail(&bc->list, &bd->busy_list);
	spin_unlock_irq(&bd->lock);

	dprintk("%s: queueing rq %p, bc %p\n", bd->name, rq, bc);

	rq->end_io_data = bc;
	blk_execute_rq_nowait(q, NULL, rq, 1, bsg_rq_end_io);
	blk_execute_rq_nowait(q, NULL, rq, at_head, bsg_rq_end_io);
}

static struct bsg_command *bsg_next_done_cmd(struct bsg_device *bd)
{
	struct bsg_command *bc = NULL;

	spin_lock_irq(&bd->lock);
	if (bd->done_cmds) {
		bc = list_first_entry(&bd->done_list, struct bsg_command, list);
		list_del(&bc->list);
		bd->done_cmds--;
	}
	spin_unlock_irq(&bd->lock);

	return bc;
}

/*
 * Get a finished command from the done list
 */
static struct bsg_command *bsg_get_done_cmd(struct bsg_device *bd)
{
	struct bsg_command *bc;
	int ret;

	do {
		bc = bsg_next_done_cmd(bd);
		if (bc)
			break;

		if (!test_bit(BSG_F_BLOCK, &bd->flags)) {
			bc = ERR_PTR(-EAGAIN);
			break;
		}

		ret = wait_event_interruptible(bd->wq_done, bd->done_cmds);
		if (ret) {
			bc = ERR_PTR(-ERESTARTSYS);
			break;
		}
	} while (1);

	dprintk("%s: returning done %p\n", bd->name, bc);

	return bc;
out_unmap_nextrq:
	if (rq->next_rq)
		blk_rq_unmap_user(rq->next_rq->bio);
out_free_nextrq:
	if (rq->next_rq)
		blk_put_request(rq->next_rq);
out:
	q->bsg_dev.ops->free_rq(rq);
	blk_put_request(rq);
	return ERR_PTR(ret);
}

static int blk_complete_sgv4_hdr_rq(struct request *rq, struct sg_io_v4 *hdr,
				    struct bio *bio, struct bio *bidi_bio)
{
	int ret;

	dprintk("rq %p bio %p %u\n", rq, bio, rq->errors);
	/*
	 * fill in all the output members
	 */
	hdr->device_status = status_byte(rq->errors);
	dprintk("rq %p bio %p 0x%x\n", rq, bio, rq->errors);
	dprintk("rq %p bio %p 0x%x\n", rq, bio, req->result);
	/*
	 * fill in all the output members
	 */
	hdr->device_status = req->result & 0xff;
	hdr->transport_status = host_byte(req->result);
	hdr->driver_status = driver_byte(req->result);
	hdr->info = 0;
	if (hdr->device_status || hdr->transport_status || hdr->driver_status)
		hdr->info |= SG_INFO_CHECK;
	hdr->response_len = 0;

	if (req->sense_len && hdr->response) {
		int len = min_t(unsigned int, hdr->max_response_len,
					req->sense_len);

		ret = copy_to_user((void*)(unsigned long)hdr->response,
		ret = copy_to_user((void __user *)(unsigned long)hdr->response,
				   req->sense, len);
		if (!ret)
			hdr->response_len = len;
		else
			ret = -EFAULT;
	}

	if (rq->next_rq) {
		hdr->dout_resid = rq->data_len;
		hdr->din_resid = rq->next_rq->data_len;
		blk_rq_unmap_user(bidi_bio);
		blk_put_request(rq->next_rq);
	} else if (rq_data_dir(rq) == READ)
		hdr->din_resid = rq->data_len;
	else
		hdr->dout_resid = rq->data_len;
		hdr->dout_resid = rq->resid_len;
		hdr->din_resid = rq->next_rq->resid_len;
		hdr->dout_resid = req->resid_len;
		hdr->din_resid = scsi_req(rq->next_rq)->resid_len;
	ret = rq->q->bsg_dev.ops->complete_rq(rq, hdr);

	if (rq->next_rq) {
		blk_rq_unmap_user(bidi_bio);
		blk_put_request(rq->next_rq);
	}

	blk_rq_unmap_user(bio);
	rq->q->bsg_dev.ops->free_rq(rq);
	blk_put_request(rq);
	return ret;
}

static bool bsg_complete(struct bsg_device *bd)
{
	bool ret = false;
	bool spin;

	do {
		spin_lock_irq(&bd->lock);

		BUG_ON(bd->done_cmds > bd->queued_cmds);

		/*
		 * All commands consumed.
		 */
		if (bd->done_cmds == bd->queued_cmds)
			ret = true;

		spin = !test_bit(BSG_F_BLOCK, &bd->flags);

		spin_unlock_irq(&bd->lock);
	} while (!ret && spin);

	return ret;
}

static int bsg_complete_all_commands(struct bsg_device *bd)
{
	struct bsg_command *bc;
	int ret, tret;

	dprintk("%s: entered\n", bd->name);

	/*
	 * wait for all commands to complete
	 */
	ret = 0;
	do {
		ret = bsg_io_schedule(bd);
		/*
		 * look for -ENODATA specifically -- we'll sometimes get
		 * -ERESTARTSYS when we've taken a signal, but we can't
		 * return until we're done freeing the queue, so ignore
		 * it.  The signal will get handled when we're done freeing
		 * the bsg_device.
		 */
	} while (ret != -ENODATA);
	io_wait_event(bd->wq_done, bsg_complete(bd));

	/*
	 * discard done commands
	 */
	ret = 0;
	do {
		spin_lock_irq(&bd->lock);
		if (!bd->queued_cmds) {
			spin_unlock_irq(&bd->lock);
			break;
		}
		spin_unlock_irq(&bd->lock);

		bc = bsg_get_done_cmd(bd);
		if (IS_ERR(bc))
			break;

		tret = blk_complete_sgv4_hdr_rq(bc->rq, &bc->hdr, bc->bio,
						bc->bidi_bio);
		if (!ret)
			ret = tret;

		bsg_free_command(bc);
	} while (1);

	return ret;
}

static int
__bsg_read(char __user *buf, size_t count, struct bsg_device *bd,
	   const struct iovec *iov, ssize_t *bytes_read)
{
	struct bsg_command *bc;
	int nr_commands, ret;

	if (count % sizeof(struct sg_io_v4))
		return -EINVAL;

	ret = 0;
	nr_commands = count / sizeof(struct sg_io_v4);
	while (nr_commands) {
		bc = bsg_get_done_cmd(bd);
		if (IS_ERR(bc)) {
			ret = PTR_ERR(bc);
			break;
		}

		/*
		 * this is the only case where we need to copy data back
		 * after completing the request. so do that here,
		 * bsg_complete_work() cannot do that for us
		 */
		ret = blk_complete_sgv4_hdr_rq(bc->rq, &bc->hdr, bc->bio,
					       bc->bidi_bio);

		if (copy_to_user(buf, &bc->hdr, sizeof(bc->hdr)))
			ret = -EFAULT;

		bsg_free_command(bc);

		if (ret)
			break;

		buf += sizeof(struct sg_io_v4);
		*bytes_read += sizeof(struct sg_io_v4);
		nr_commands--;
	}

	return ret;
}

static inline void bsg_set_block(struct bsg_device *bd, struct file *file)
{
	if (file->f_flags & O_NONBLOCK)
		clear_bit(BSG_F_BLOCK, &bd->flags);
	else
		set_bit(BSG_F_BLOCK, &bd->flags);
}

/*
 * Check if the error is a "real" error that we should return.
 */
static inline int err_block_err(int ret)
{
	if (ret && ret != -ENOSPC && ret != -ENODATA && ret != -EAGAIN)
		return 1;

	return 0;
}

static ssize_t
bsg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct bsg_device *bd = file->private_data;
	int ret;
	ssize_t bytes_read;

	dprintk("%s: read %zd bytes\n", bd->name, count);

	bsg_set_block(bd, file);

	bytes_read = 0;
	ret = __bsg_read(buf, count, bd, NULL, &bytes_read);
	*ppos = bytes_read;

	if (!bytes_read || (bytes_read && err_block_err(ret)))
	if (!bytes_read || err_block_err(ret))
		bytes_read = ret;

	return bytes_read;
}

static int __bsg_write(struct bsg_device *bd, const char __user *buf,
		       size_t count, ssize_t *bytes_written, int has_write_perm)
		       size_t count, ssize_t *bytes_written,
		       fmode_t has_write_perm)
{
	struct bsg_command *bc;
	struct request *rq;
	int ret, nr_commands;

	if (count % sizeof(struct sg_io_v4))
		return -EINVAL;

	nr_commands = count / sizeof(struct sg_io_v4);
	rq = NULL;
	bc = NULL;
	ret = 0;
	while (nr_commands) {
		struct request_queue *q = bd->queue;

		bc = bsg_alloc_command(bd);
		if (IS_ERR(bc)) {
			ret = PTR_ERR(bc);
			bc = NULL;
			break;
		}

		if (copy_from_user(&bc->hdr, buf, sizeof(bc->hdr))) {
			ret = -EFAULT;
			break;
		}

		/*
		 * get a request, fill in the blanks, and add to request queue
		 */
		rq = bsg_map_hdr(bd, &bc->hdr, has_write_perm);
		rq = bsg_map_hdr(bd, &bc->hdr, has_write_perm, bc->sense);
		if (IS_ERR(rq)) {
			ret = PTR_ERR(rq);
			rq = NULL;
			break;
		}

		bsg_add_command(bd, q, bc, rq);
		bc = NULL;
		rq = NULL;
		nr_commands--;
		buf += sizeof(struct sg_io_v4);
		*bytes_written += sizeof(struct sg_io_v4);
	}

	if (bc)
		bsg_free_command(bc);

	return ret;
}

static ssize_t
bsg_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct bsg_device *bd = file->private_data;
	ssize_t bytes_written;
	int ret;

	dprintk("%s: write %zd bytes\n", bd->name, count);

	if (unlikely(uaccess_kernel()))
		return -EINVAL;

	bsg_set_block(bd, file);

	bytes_written = 0;
	ret = __bsg_write(bd, buf, count, &bytes_written,
			  file->f_mode & FMODE_WRITE);

	*ppos = bytes_written;

	/*
	 * return bytes written on non-fatal errors
	 */
	if (!bytes_written || (bytes_written && err_block_err(ret)))
	if (!bytes_written || err_block_err(ret))
		bytes_written = ret;

	dprintk("%s: returning %zd\n", bd->name, bytes_written);
	return bytes_written;
}

static struct bsg_device *bsg_alloc_device(void)
{
	struct bsg_device *bd;

	bd = kzalloc(sizeof(struct bsg_device), GFP_KERNEL);
	if (unlikely(!bd))
		return NULL;

	spin_lock_init(&bd->lock);
	bd->max_queue = BSG_DEFAULT_CMDS;
	INIT_HLIST_NODE(&bd->dev_list);
	return bd;
}

static int bsg_put_device(struct bsg_device *bd)
{
	struct request_queue *q = bd->queue;

	mutex_lock(&bsg_mutex);

	if (!refcount_dec_and_test(&bd->ref_count)) {
		mutex_unlock(&bsg_mutex);
		return 0;
	}

	hlist_del(&bd->dev_list);
	mutex_unlock(&bsg_mutex);

	bsg_dbg(bd, "tearing down\n");

	/*
	 * close can always block
	 */
	kfree(bd);
	blk_put_queue(q);
	return 0;
}

static struct bsg_device *bsg_add_device(struct inode *inode,
					 struct request_queue *rq,
					 struct file *file)
{
	struct bsg_device *bd;
	int ret;
#ifdef BSG_DEBUG
	unsigned char buf[32];
#endif
	ret = blk_get_queue(rq);
	if (ret)
#ifdef BSG_DEBUG
	unsigned char buf[32];

	lockdep_assert_held(&bsg_mutex);

	if (!blk_get_queue(rq))
		return ERR_PTR(-ENXIO);

	bd = bsg_alloc_device();
	if (!bd) {
		blk_put_queue(rq);
		return ERR_PTR(-ENOMEM);
	}

	bd->queue = rq;

	refcount_set(&bd->ref_count, 1);
	hlist_add_head(&bd->dev_list, bsg_dev_idx_hash(iminor(inode)));

	strncpy(bd->name, rq->bsg_dev.class_dev->bus_id, sizeof(bd->name) - 1);
	strncpy(bd->name, dev_name(rq->bsg_dev.class_dev), sizeof(bd->name) - 1);
	bsg_dbg(bd, "bound to <%s>, max queue %d\n",
		format_dev_t(buf, inode->i_rdev), bd->max_queue);

	return bd;
}

static struct bsg_device *__bsg_get_device(int minor, struct request_queue *q)
{
	struct bsg_device *bd;
	struct hlist_node *entry;

	mutex_lock(&bsg_mutex);

	hlist_for_each_entry(bd, entry, bsg_dev_idx_hash(minor), dev_list) {

	lockdep_assert_held(&bsg_mutex);

	hlist_for_each_entry(bd, bsg_dev_idx_hash(minor), dev_list) {
		if (bd->queue == q) {
			refcount_inc(&bd->ref_count);
			goto found;
		}
	}
	bd = NULL;
found:
	return bd;
}

static struct bsg_device *bsg_get_device(struct inode *inode, struct file *file)
{
	struct bsg_device *bd;
	struct bsg_class_device *bcd;

	/*
	 * find the class device
	 */
	mutex_lock(&bsg_mutex);
	bcd = idr_find(&bsg_minor_idr, iminor(inode));

	if (!bcd) {
		bd = ERR_PTR(-ENODEV);
		goto out_unlock;
	}

	bd = __bsg_get_device(iminor(inode), bcd->queue);
	if (!bd)
		bd = bsg_add_device(inode, bcd->queue, file);

out_unlock:
	mutex_unlock(&bsg_mutex);
	return bd;
}

static int bsg_open(struct inode *inode, struct file *file)
{
	struct bsg_device *bd;

	lock_kernel();
	bd = bsg_get_device(inode, file);
	unlock_kernel();
	bd = bsg_get_device(inode, file);

	if (IS_ERR(bd))
		return PTR_ERR(bd);

	file->private_data = bd;
	return 0;
}

static int bsg_release(struct inode *inode, struct file *file)
{
	struct bsg_device *bd = file->private_data;

	file->private_data = NULL;
	return bsg_put_device(bd);
}

static unsigned int bsg_poll(struct file *file, poll_table *wait)
{
	struct bsg_device *bd = file->private_data;
	unsigned int mask = 0;

	poll_wait(file, &bd->wq_done, wait);
	poll_wait(file, &bd->wq_free, wait);

	spin_lock_irq(&bd->lock);
	if (!list_empty(&bd->done_list))
		mask |= POLLIN | POLLRDNORM;
	if (bd->queued_cmds >= bd->max_queue)
	if (bd->queued_cmds < bd->max_queue)
		mask |= POLLOUT;
	spin_unlock_irq(&bd->lock);

	return mask;
}

static long bsg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct bsg_device *bd = file->private_data;
	int __user *uarg = (int __user *) arg;
	int ret;

	switch (cmd) {
		/*
		 * our own ioctls
		 */
	case SG_GET_COMMAND_Q:
		return put_user(bd->max_queue, uarg);
	case SG_SET_COMMAND_Q: {
		int queue;

		if (get_user(queue, uarg))
			return -EFAULT;
		if (queue < 1)
			return -EINVAL;

		spin_lock_irq(&bd->lock);
		bd->max_queue = queue;
		spin_unlock_irq(&bd->lock);
		return 0;
	}

	/*
	 * SCSI/sg ioctls
	 */
	case SG_GET_VERSION_NUM:
	case SCSI_IOCTL_GET_IDLUN:
	case SCSI_IOCTL_GET_BUS_NUMBER:
	case SG_SET_TIMEOUT:
	case SG_GET_TIMEOUT:
	case SG_GET_RESERVED_SIZE:
	case SG_SET_RESERVED_SIZE:
	case SG_EMULATED_HOST:
	case SCSI_IOCTL_SEND_COMMAND: {
		void __user *uarg = (void __user *) arg;
		return scsi_cmd_ioctl(file, bd->queue, NULL, cmd, uarg);
		return scsi_cmd_ioctl(bd->queue, NULL, file->f_mode, cmd, uarg);
	}
	case SG_IO: {
		struct request *rq;
		struct bio *bio, *bidi_bio = NULL;
		struct sg_io_v4 hdr;
		int at_head;

		if (copy_from_user(&hdr, uarg, sizeof(hdr)))
			return -EFAULT;

		rq = bsg_map_hdr(bd, &hdr, file->f_mode & FMODE_WRITE);
		rq = bsg_map_hdr(bd, &hdr, file->f_mode & FMODE_WRITE, sense);
		rq = bsg_map_hdr(bd->queue, &hdr, file->f_mode);
		if (IS_ERR(rq))
			return PTR_ERR(rq);

		bio = rq->bio;
		if (rq->next_rq)
			bidi_bio = rq->next_rq->bio;
		blk_execute_rq(bd->queue, NULL, rq, 0);

		at_head = (0 == (hdr.flags & BSG_FLAG_Q_AT_TAIL));
		blk_execute_rq(bd->queue, NULL, rq, at_head);
		ret = blk_complete_sgv4_hdr_rq(rq, &hdr, bio, bidi_bio);

		if (copy_to_user(uarg, &hdr, sizeof(hdr)))
			return -EFAULT;

		return ret;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations bsg_fops = {
	.open		=	bsg_open,
	.release	=	bsg_release,
	.unlocked_ioctl	=	bsg_ioctl,
	.owner		=	THIS_MODULE,
	.llseek		=	default_llseek,
};

void bsg_unregister_queue(struct request_queue *q)
{
	struct bsg_class_device *bcd = &q->bsg_dev;

	if (!bcd->class_dev)
		return;

	mutex_lock(&bsg_mutex);
	idr_remove(&bsg_minor_idr, bcd->minor);
	sysfs_remove_link(&q->kobj, "bsg");
	if (q->kobj.sd)
		sysfs_remove_link(&q->kobj, "bsg");
	device_unregister(bcd->class_dev);
	bcd->class_dev = NULL;
	mutex_unlock(&bsg_mutex);
}
EXPORT_SYMBOL_GPL(bsg_unregister_queue);

int bsg_register_queue(struct request_queue *q, struct device *parent,
		const char *name, const struct bsg_ops *ops)
{
	struct bsg_class_device *bcd;
	dev_t dev;
	int ret, minor;
	int ret;
	struct device *class_dev = NULL;
	const char *devname;

	if (name)
		devname = name;
	else
		devname = parent->bus_id;
		devname = dev_name(parent);

	/*
	 * we need a proper transport to send commands, not a stacked device
	 */
	if (!q->request_fn)
	if (!queue_is_rq_based(q))
		return 0;

	bcd = &q->bsg_dev;
	memset(bcd, 0, sizeof(*bcd));

	mutex_lock(&bsg_mutex);

	ret = idr_pre_get(&bsg_minor_idr, GFP_KERNEL);
	if (!ret) {
		ret = -ENOMEM;
		goto unlock;
	}

	ret = idr_get_new(&bsg_minor_idr, bcd, &minor);
	if (ret < 0)
		goto unlock;

	if (minor >= BSG_MAX_DEVS) {
		printk(KERN_ERR "bsg: too many bsg devices\n");
		ret = -EINVAL;
		goto remove_idr;
	}

	bcd->minor = minor;
	ret = idr_alloc(&bsg_minor_idr, bcd, 0, BSG_MAX_DEVS, GFP_KERNEL);
	if (ret < 0) {
		if (ret == -ENOSPC) {
			printk(KERN_ERR "bsg: too many bsg devices\n");
			ret = -EINVAL;
		}
		goto unlock;
	}

	bcd->minor = ret;
	bcd->queue = q;
	bcd->ops = ops;
	dev = MKDEV(bsg_major, bcd->minor);
	class_dev = device_create_drvdata(bsg_class, parent, dev, NULL,
					  "%s", devname);
	class_dev = device_create(bsg_class, parent, dev, NULL, "%s", devname);
	class_dev = device_create(bsg_class, parent, dev, NULL, "%s", name);
	if (IS_ERR(class_dev)) {
		ret = PTR_ERR(class_dev);
		goto idr_remove;
	}
	bcd->class_dev = class_dev;

	if (q->kobj.sd) {
		ret = sysfs_create_link(&q->kobj, &bcd->class_dev->kobj, "bsg");
		if (ret)
			goto unregister_class_dev;
	}

	mutex_unlock(&bsg_mutex);
	return 0;

unregister_class_dev:
	device_unregister(class_dev);
put_dev:
	put_device(parent);
remove_idr:
	idr_remove(&bsg_minor_idr, minor);
idr_remove:
	idr_remove(&bsg_minor_idr, bcd->minor);
unlock:
	mutex_unlock(&bsg_mutex);
	return ret;
}

int bsg_scsi_register_queue(struct request_queue *q, struct device *parent)
{
	if (!blk_queue_scsi_passthrough(q)) {
		WARN_ONCE(true, "Attempt to register a non-SCSI queue\n");
		return -EINVAL;
	}

	return bsg_register_queue(q, parent, dev_name(parent), &bsg_scsi_ops);
}
EXPORT_SYMBOL_GPL(bsg_scsi_register_queue);

static struct cdev bsg_cdev;

static char *bsg_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "bsg/%s", dev_name(dev));
}

static int __init bsg_init(void)
{
	int ret, i;
	dev_t devid;

	for (i = 0; i < BSG_LIST_ARRAY_SIZE; i++)
		INIT_HLIST_HEAD(&bsg_device_list[i]);

	bsg_class = class_create(THIS_MODULE, "bsg");
	if (IS_ERR(bsg_class))
		return PTR_ERR(bsg_class);
	bsg_class->devnode = bsg_devnode;

	ret = alloc_chrdev_region(&devid, 0, BSG_MAX_DEVS, "bsg");
	if (ret)
		goto destroy_bsg_class;

	bsg_major = MAJOR(devid);

	cdev_init(&bsg_cdev, &bsg_fops);
	ret = cdev_add(&bsg_cdev, MKDEV(bsg_major, 0), BSG_MAX_DEVS);
	if (ret)
		goto unregister_chrdev;

	printk(KERN_INFO BSG_DESCRIPTION " version " BSG_VERSION
	       " loaded (major %d)\n", bsg_major);
	return 0;
unregister_chrdev:
	unregister_chrdev_region(MKDEV(bsg_major, 0), BSG_MAX_DEVS);
destroy_bsg_class:
	class_destroy(bsg_class);
	return ret;
}

MODULE_AUTHOR("Jens Axboe");
MODULE_DESCRIPTION(BSG_DESCRIPTION);
MODULE_LICENSE("GPL");

device_initcall(bsg_init);
