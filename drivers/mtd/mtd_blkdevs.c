/*
 * (C) 2003 David Woodhouse <dwmw2@infradead.org>
 *
 * Interface to Linux 2.5 block layer for MTD 'translation layers'.
 * Interface to Linux block layer for MTD 'translation layers'.
 *
 * Copyright © 2003-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/mtd/blktrans.h>
#include <linux/mtd/mtd.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/freezer.h>
#include <linux/spinlock.h>
#include <linux/hdreg.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/hdreg.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#include "mtdcore.h"

static LIST_HEAD(blktrans_majors);

struct mtd_blkcore_priv {
	struct task_struct *thread;
	struct request_queue *rq;
	spinlock_t queue_lock;
};
static DEFINE_MUTEX(blktrans_ref_mutex);

static void blktrans_dev_release(struct kref *kref)
{
	struct mtd_blktrans_dev *dev =
		container_of(kref, struct mtd_blktrans_dev, ref);

	dev->disk->private_data = NULL;
	blk_cleanup_queue(dev->rq);
	put_disk(dev->disk);
	list_del(&dev->list);
	kfree(dev);
}

static struct mtd_blktrans_dev *blktrans_dev_get(struct gendisk *disk)
{
	struct mtd_blktrans_dev *dev;

	mutex_lock(&blktrans_ref_mutex);
	dev = disk->private_data;

	if (!dev)
		goto unlock;
	kref_get(&dev->ref);
unlock:
	mutex_unlock(&blktrans_ref_mutex);
	return dev;
}

static void blktrans_dev_put(struct mtd_blktrans_dev *dev)
{
	mutex_lock(&blktrans_ref_mutex);
	kref_put(&dev->ref, blktrans_dev_release);
	mutex_unlock(&blktrans_ref_mutex);
}


static blk_status_t do_blktrans_request(struct mtd_blktrans_ops *tr,
			       struct mtd_blktrans_dev *dev,
			       struct request *req)
{
	unsigned long block, nsect;
	char *buf;

	block = req->sector << 9 >> tr->blkshift;
	nsect = req->current_nr_sectors << 9 >> tr->blkshift;

	buf = req->buffer;

	if (!blk_fs_request(req))
		return 0;

	if (req->sector + req->current_nr_sectors > get_capacity(req->rq_disk))
		return 0;

	switch(rq_data_dir(req)) {
	case READ:
		for (; nsect > 0; nsect--, block++, buf += tr->blksize)
			if (tr->readsect(dev, block, buf))
				return 0;
		return 1;

	case WRITE:
		if (!tr->writesect)
			return 0;

		for (; nsect > 0; nsect--, block++, buf += tr->blksize)
			if (tr->writesect(dev, block, buf))
				return 0;
		return 1;

	default:
		printk(KERN_NOTICE "Unknown request %u\n", rq_data_dir(req));
	block = blk_rq_pos(req) << 9 >> tr->blkshift;
	nsect = blk_rq_cur_bytes(req) >> tr->blkshift;
	buf = bio_data(req->bio);

	if (req_op(req) == REQ_OP_FLUSH) {
		if (tr->flush(dev))
			return BLK_STS_IOERR;
		return BLK_STS_OK;
	}

	if (blk_rq_pos(req) + blk_rq_cur_sectors(req) >
	    get_capacity(req->rq_disk))
		return BLK_STS_IOERR;

	switch (req_op(req)) {
	case REQ_OP_DISCARD:
		if (tr->discard(dev, block, nsect))
			return BLK_STS_IOERR;
		return BLK_STS_OK;
	case REQ_OP_READ:
		for (; nsect > 0; nsect--, block++, buf += tr->blksize)
			if (tr->readsect(dev, block, buf))
				return BLK_STS_IOERR;
		rq_flush_dcache_pages(req);
		return BLK_STS_OK;
	case REQ_OP_WRITE:
		if (!tr->writesect)
			return BLK_STS_IOERR;

		rq_flush_dcache_pages(req);
		for (; nsect > 0; nsect--, block++, buf += tr->blksize)
			if (tr->writesect(dev, block, buf))
				return BLK_STS_IOERR;
		return BLK_STS_OK;
	default:
		return BLK_STS_IOERR;
	}
}

static int mtd_blktrans_thread(void *arg)
{
	struct mtd_blktrans_ops *tr = arg;
	struct request_queue *rq = tr->blkcore_priv->rq;

	/* we might get involved when memory gets low, so use PF_MEMALLOC */
	current->flags |= PF_MEMALLOC;

	spin_lock_irq(rq->queue_lock);
	while (!kthread_should_stop()) {
		struct request *req;
		struct mtd_blktrans_dev *dev;
		int res = 0;

		req = elv_next_request(rq);

		if (!req) {
			set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(rq->queue_lock);
			schedule();
			spin_lock_irq(rq->queue_lock);
			continue;
		}

		dev = req->rq_disk->private_data;
		tr = dev->tr;

		spin_unlock_irq(rq->queue_lock);

		mutex_lock(&dev->lock);
		res = do_blktrans_request(tr, dev, req);
int mtd_blktrans_cease_background(struct mtd_blktrans_dev *dev)
{
	return dev->bg_stop;
}
EXPORT_SYMBOL_GPL(mtd_blktrans_cease_background);

static void mtd_blktrans_work(struct work_struct *work)
{
	struct mtd_blktrans_dev *dev =
		container_of(work, struct mtd_blktrans_dev, work);
	struct mtd_blktrans_ops *tr = dev->tr;
	struct request_queue *rq = dev->rq;
	struct request *req = NULL;
	int background_done = 0;

	spin_lock_irq(rq->queue_lock);

	while (1) {
		blk_status_t res;

		dev->bg_stop = false;
		if (!req && !(req = blk_fetch_request(rq))) {
			if (tr->background && !background_done) {
				spin_unlock_irq(rq->queue_lock);
				mutex_lock(&dev->lock);
				tr->background(dev);
				mutex_unlock(&dev->lock);
				spin_lock_irq(rq->queue_lock);
				/*
				 * Do background processing just once per idle
				 * period.
				 */
				background_done = !dev->bg_stop;
				continue;
			}
			break;
		}

		spin_unlock_irq(rq->queue_lock);

		mutex_lock(&dev->lock);
		res = do_blktrans_request(dev->tr, dev, req);
		mutex_unlock(&dev->lock);

		spin_lock_irq(rq->queue_lock);

		end_request(req, res);
	}
	spin_unlock_irq(rq->queue_lock);

	return 0;
		if (!__blk_end_request_cur(req, res))
			req = NULL;

		background_done = 0;
	}

	spin_unlock_irq(rq->queue_lock);
}

static void mtd_blktrans_request(struct request_queue *rq)
{
	struct mtd_blktrans_ops *tr = rq->queuedata;
	wake_up_process(tr->blkcore_priv->thread);
}


static int blktrans_open(struct inode *i, struct file *f)
{
	struct mtd_blktrans_dev *dev;
	struct mtd_blktrans_ops *tr;
	int ret = -ENODEV;

	dev = i->i_bdev->bd_disk->private_data;
	tr = dev->tr;

	if (!try_module_get(dev->mtd->owner))
		goto out;

	if (!try_module_get(tr->owner))
		goto out_tr;

	/* FIXME: Locking. A hot pluggable device can go away
	   (del_mtd_device can be called for it) without its module
	   being unloaded. */
	dev->mtd->usecount++;

	ret = 0;
	if (tr->open && (ret = tr->open(dev))) {
		dev->mtd->usecount--;
		module_put(dev->mtd->owner);
	out_tr:
		module_put(tr->owner);
	}
 out:
	return ret;
}

static int blktrans_release(struct inode *i, struct file *f)
{
	struct mtd_blktrans_dev *dev;
	struct mtd_blktrans_ops *tr;
	int ret = 0;

	dev = i->i_bdev->bd_disk->private_data;
	tr = dev->tr;

	if (tr->release)
		ret = tr->release(dev);

	if (!ret) {
		dev->mtd->usecount--;
		module_put(dev->mtd->owner);
		module_put(tr->owner);
	}

	return ret;
	struct mtd_blktrans_dev *dev;
	struct request *req = NULL;

	dev = rq->queuedata;

	if (!dev)
		while ((req = blk_fetch_request(rq)) != NULL)
			__blk_end_request_all(req, BLK_STS_IOERR);
	else
		queue_work(dev->wq, &dev->work);
}

static int blktrans_open(struct block_device *bdev, fmode_t mode)
{
	struct mtd_blktrans_dev *dev = blktrans_dev_get(bdev->bd_disk);
	int ret = 0;

	if (!dev)
		return -ERESTARTSYS; /* FIXME: busy loop! -arnd*/

	mutex_lock(&mtd_table_mutex);
	mutex_lock(&dev->lock);

	if (dev->open)
		goto unlock;

	kref_get(&dev->ref);
	__module_get(dev->tr->owner);

	if (!dev->mtd)
		goto unlock;

	if (dev->tr->open) {
		ret = dev->tr->open(dev);
		if (ret)
			goto error_put;
	}

	ret = __get_mtd_device(dev->mtd);
	if (ret)
		goto error_release;
	dev->file_mode = mode;

unlock:
	dev->open++;
	mutex_unlock(&dev->lock);
	mutex_unlock(&mtd_table_mutex);
	blktrans_dev_put(dev);
	return ret;

error_release:
	if (dev->tr->release)
		dev->tr->release(dev);
error_put:
	module_put(dev->tr->owner);
	kref_put(&dev->ref, blktrans_dev_release);
	mutex_unlock(&dev->lock);
	mutex_unlock(&mtd_table_mutex);
	blktrans_dev_put(dev);
	return ret;
}

static void blktrans_release(struct gendisk *disk, fmode_t mode)
{
	struct mtd_blktrans_dev *dev = blktrans_dev_get(disk);

	if (!dev)
		return;

	mutex_lock(&mtd_table_mutex);
	mutex_lock(&dev->lock);

	if (--dev->open)
		goto unlock;

	kref_put(&dev->ref, blktrans_dev_release);
	module_put(dev->tr->owner);

	if (dev->mtd) {
		if (dev->tr->release)
			dev->tr->release(dev);
		__put_mtd_device(dev->mtd);
	}
unlock:
	mutex_unlock(&dev->lock);
	mutex_unlock(&mtd_table_mutex);
	blktrans_dev_put(dev);
}

static int blktrans_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct mtd_blktrans_dev *dev = bdev->bd_disk->private_data;

	if (dev->tr->getgeo)
		return dev->tr->getgeo(dev, geo);
	return -ENOTTY;
}

static int blktrans_ioctl(struct inode *inode, struct file *file,
			      unsigned int cmd, unsigned long arg)
{
	struct mtd_blktrans_dev *dev = inode->i_bdev->bd_disk->private_data;
	struct mtd_blktrans_ops *tr = dev->tr;

	switch (cmd) {
	case BLKFLSBUF:
		if (tr->flush)
			return tr->flush(dev);
		/* The core code did the work, we had nothing to do. */
		return 0;
	default:
		return -ENOTTY;
	}
}

static struct block_device_operations mtd_blktrans_ops = {
	struct mtd_blktrans_dev *dev = blktrans_dev_get(bdev->bd_disk);
	int ret = -ENXIO;

	if (!dev)
		return ret;

	mutex_lock(&dev->lock);

	if (!dev->mtd)
		goto unlock;

	ret = dev->tr->getgeo ? dev->tr->getgeo(dev, geo) : -ENOTTY;
unlock:
	mutex_unlock(&dev->lock);
	blktrans_dev_put(dev);
	return ret;
}

static int blktrans_ioctl(struct block_device *bdev, fmode_t mode,
			      unsigned int cmd, unsigned long arg)
{
	struct mtd_blktrans_dev *dev = blktrans_dev_get(bdev->bd_disk);
	int ret = -ENXIO;

	if (!dev)
		return ret;

	mutex_lock(&dev->lock);

	if (!dev->mtd)
		goto unlock;

	switch (cmd) {
	case BLKFLSBUF:
		ret = dev->tr->flush ? dev->tr->flush(dev) : 0;
		break;
	default:
		ret = -ENOTTY;
	}
unlock:
	mutex_unlock(&dev->lock);
	blktrans_dev_put(dev);
	return ret;
}

static const struct block_device_operations mtd_block_ops = {
	.owner		= THIS_MODULE,
	.open		= blktrans_open,
	.release	= blktrans_release,
	.ioctl		= blktrans_ioctl,
	.getgeo		= blktrans_getgeo,
};

int add_mtd_blktrans_dev(struct mtd_blktrans_dev *new)
{
	struct mtd_blktrans_ops *tr = new->tr;
	struct mtd_blktrans_dev *d;
	int last_devnum = -1;
	struct gendisk *gd;
	int ret;

	if (mutex_trylock(&mtd_table_mutex)) {
		mutex_unlock(&mtd_table_mutex);
		BUG();
	}

	mutex_lock(&blktrans_ref_mutex);
	list_for_each_entry(d, &tr->devs, list) {
		if (new->devnum == -1) {
			/* Use first free number */
			if (d->devnum != last_devnum+1) {
				/* Found a free devnum. Plug it in here */
				new->devnum = last_devnum+1;
				list_add_tail(&new->list, &d->list);
				goto added;
			}
		} else if (d->devnum == new->devnum) {
			/* Required number taken */
			mutex_unlock(&blktrans_ref_mutex);
			return -EBUSY;
		} else if (d->devnum > new->devnum) {
			/* Required number was free */
			list_add_tail(&new->list, &d->list);
			goto added;
		}
		last_devnum = d->devnum;
	}
	if (new->devnum == -1)
		new->devnum = last_devnum+1;

	if ((new->devnum << tr->part_bits) > 256) {
		return -EBUSY;

	ret = -EBUSY;
	if (new->devnum == -1)
		new->devnum = last_devnum+1;

	/* Check that the device and any partitions will get valid
	 * minor numbers and that the disk naming code below can cope
	 * with this number. */
	if (new->devnum > (MINORMASK >> tr->part_bits) ||
	    (tr->part_bits && new->devnum >= 27 * 26)) {
		mutex_unlock(&blktrans_ref_mutex);
		goto error1;
	}

	list_add_tail(&new->list, &tr->devs);
 added:
	mutex_init(&new->lock);
	if (!tr->writesect)
		new->readonly = 1;

	gd = alloc_disk(1 << tr->part_bits);
	if (!gd) {
		list_del(&new->list);
		return -ENOMEM;
	}
	gd->major = tr->major;
	gd->first_minor = (new->devnum) << tr->part_bits;
	gd->fops = &mtd_blktrans_ops;
	mutex_unlock(&blktrans_ref_mutex);

	mutex_init(&new->lock);
	kref_init(&new->ref);
	if (!tr->writesect)
		new->readonly = 1;

	/* Create gendisk */
	ret = -ENOMEM;
	gd = alloc_disk(1 << tr->part_bits);

	if (!gd)
		goto error2;

	new->disk = gd;
	gd->private_data = new;
	gd->major = tr->major;
	gd->first_minor = (new->devnum) << tr->part_bits;
	gd->fops = &mtd_block_ops;

	if (tr->part_bits)
		if (new->devnum < 26)
			snprintf(gd->disk_name, sizeof(gd->disk_name),
				 "%s%c", tr->name, 'a' + new->devnum);
		else
			snprintf(gd->disk_name, sizeof(gd->disk_name),
				 "%s%c%c", tr->name,
				 'a' - 1 + new->devnum / 26,
				 'a' + new->devnum % 26);
	else
		snprintf(gd->disk_name, sizeof(gd->disk_name),
			 "%s%d", tr->name, new->devnum);

	/* 2.5 has capacity in units of 512 bytes while still
	   having BLOCK_SIZE_BITS set to 10. Just to keep us amused. */
	set_capacity(gd, (new->size * tr->blksize) >> 9);

	gd->private_data = new;
	new->blkcore_priv = gd;
	gd->queue = tr->blkcore_priv->rq;
	set_capacity(gd, ((u64)new->size * tr->blksize) >> 9);

	/* Create the request queue */
	spin_lock_init(&new->queue_lock);
	new->rq = blk_init_queue(mtd_blktrans_request, &new->queue_lock);

	if (!new->rq)
		goto error3;

	if (tr->flush)
		blk_queue_write_cache(new->rq, true, false);

	new->rq->queuedata = new;
	blk_queue_logical_block_size(new->rq, tr->blksize);

	blk_queue_bounce_limit(new->rq, BLK_BOUNCE_HIGH);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, new->rq);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, new->rq);

	if (tr->discard) {
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, new->rq);
		blk_queue_max_discard_sectors(new->rq, UINT_MAX);
	}

	gd->queue = new->rq;

	/* Create processing workqueue */
	new->wq = alloc_workqueue("%s%d", 0, 0,
				  tr->name, new->mtd->index);
	if (!new->wq)
		goto error4;
	INIT_WORK(&new->work, mtd_blktrans_work);

	if (new->readonly)
		set_disk_ro(gd, 1);

	device_add_disk(&new->mtd->dev, gd);

	return 0;
	if (new->disk_attributes) {
		ret = sysfs_create_group(&disk_to_dev(gd)->kobj,
					new->disk_attributes);
		WARN_ON(ret);
	}
	return 0;
error4:
	blk_cleanup_queue(new->rq);
error3:
	put_disk(new->disk);
error2:
	list_del(&new->list);
error1:
	return ret;
}

int del_mtd_blktrans_dev(struct mtd_blktrans_dev *old)
{
	unsigned long flags;

	if (mutex_trylock(&mtd_table_mutex)) {
		mutex_unlock(&mtd_table_mutex);
		BUG();
	}

	list_del(&old->list);

	del_gendisk(old->blkcore_priv);
	put_disk(old->blkcore_priv);

	if (old->disk_attributes)
		sysfs_remove_group(&disk_to_dev(old->disk)->kobj,
						old->disk_attributes);

	/* Stop new requests to arrive */
	del_gendisk(old->disk);

	/* Stop workqueue. This will perform any pending request. */
	destroy_workqueue(old->wq);

	/* Kill current requests */
	spin_lock_irqsave(&old->queue_lock, flags);
	old->rq->queuedata = NULL;
	blk_start_queue(old->rq);
	spin_unlock_irqrestore(&old->queue_lock, flags);

	/* If the device is currently open, tell trans driver to close it,
		then put mtd device, and don't touch it again */
	mutex_lock(&old->lock);
	if (old->open) {
		if (old->tr->release)
			old->tr->release(old);
		__put_mtd_device(old->mtd);
	}

	old->mtd = NULL;

	mutex_unlock(&old->lock);
	blktrans_dev_put(old);
	return 0;
}

static void blktrans_notify_remove(struct mtd_info *mtd)
{
	struct mtd_blktrans_ops *tr;
	struct mtd_blktrans_dev *dev, *next;

	list_for_each_entry(tr, &blktrans_majors, list)
		list_for_each_entry_safe(dev, next, &tr->devs, list)
			if (dev->mtd == mtd)
				tr->remove_dev(dev);
}

static void blktrans_notify_add(struct mtd_info *mtd)
{
	struct mtd_blktrans_ops *tr;

	if (mtd->type == MTD_ABSENT)
		return;

	list_for_each_entry(tr, &blktrans_majors, list)
		tr->add_mtd(tr, mtd);
}

static struct mtd_notifier blktrans_notifier = {
	.add = blktrans_notify_add,
	.remove = blktrans_notify_remove,
};

int register_mtd_blktrans(struct mtd_blktrans_ops *tr)
{
	int ret, i;
	struct mtd_info *mtd;
	int ret;

	/* Register the notifier if/when the first device type is
	   registered, to prevent the link/init ordering from fucking
	   us over. */
	if (!blktrans_notifier.list.next)
		register_mtd_user(&blktrans_notifier);

	tr->blkcore_priv = kzalloc(sizeof(*tr->blkcore_priv), GFP_KERNEL);
	if (!tr->blkcore_priv)
		return -ENOMEM;

	mutex_lock(&mtd_table_mutex);

	ret = register_blkdev(tr->major, tr->name);
	if (ret) {
		printk(KERN_WARNING "Unable to register %s block device on major %d: %d\n",
		       tr->name, tr->major, ret);
		kfree(tr->blkcore_priv);
		mutex_unlock(&mtd_table_mutex);
		return ret;
	}
	spin_lock_init(&tr->blkcore_priv->queue_lock);

	tr->blkcore_priv->rq = blk_init_queue(mtd_blktrans_request, &tr->blkcore_priv->queue_lock);
	if (!tr->blkcore_priv->rq) {
		unregister_blkdev(tr->major, tr->name);
		kfree(tr->blkcore_priv);
		mutex_unlock(&mtd_table_mutex);
		return -ENOMEM;
	}

	tr->blkcore_priv->rq->queuedata = tr;
	blk_queue_hardsect_size(tr->blkcore_priv->rq, tr->blksize);
	tr->blkshift = ffs(tr->blksize) - 1;

	tr->blkcore_priv->thread = kthread_run(mtd_blktrans_thread, tr,
			"%sd", tr->name);
	if (IS_ERR(tr->blkcore_priv->thread)) {
		blk_cleanup_queue(tr->blkcore_priv->rq);
		unregister_blkdev(tr->major, tr->name);
		kfree(tr->blkcore_priv);
		mutex_unlock(&mtd_table_mutex);
		return PTR_ERR(tr->blkcore_priv->thread);
	}

	INIT_LIST_HEAD(&tr->devs);
	list_add(&tr->list, &blktrans_majors);

	for (i=0; i<MAX_MTD_DEVICES; i++) {
		if (mtd_table[i] && mtd_table[i]->type != MTD_ABSENT)
			tr->add_mtd(tr, mtd_table[i]);
	}

	mutex_unlock(&mtd_table_mutex);

	if (ret < 0) {
		printk(KERN_WARNING "Unable to register %s block device on major %d: %d\n",
		       tr->name, tr->major, ret);
		mutex_unlock(&mtd_table_mutex);
		return ret;
	}

	if (ret)
		tr->major = ret;

	tr->blkshift = ffs(tr->blksize) - 1;

	INIT_LIST_HEAD(&tr->devs);
	list_add(&tr->list, &blktrans_majors);

	mtd_for_each_device(mtd)
		if (mtd->type != MTD_ABSENT)
			tr->add_mtd(tr, mtd);

	mutex_unlock(&mtd_table_mutex);
	return 0;
}

int deregister_mtd_blktrans(struct mtd_blktrans_ops *tr)
{
	struct mtd_blktrans_dev *dev, *next;

	mutex_lock(&mtd_table_mutex);

	/* Clean up the kernel thread */
	kthread_stop(tr->blkcore_priv->thread);

	/* Remove it from the list of active majors */
	list_del(&tr->list);

	list_for_each_entry_safe(dev, next, &tr->devs, list)
		tr->remove_dev(dev);

	blk_cleanup_queue(tr->blkcore_priv->rq);
	unregister_blkdev(tr->major, tr->name);

	mutex_unlock(&mtd_table_mutex);

	kfree(tr->blkcore_priv);

	unregister_blkdev(tr->major, tr->name);
	mutex_unlock(&mtd_table_mutex);

	BUG_ON(!list_empty(&tr->devs));
	return 0;
}

static void __exit mtd_blktrans_exit(void)
{
	/* No race here -- if someone's currently in register_mtd_blktrans
	   we're screwed anyway. */
	if (blktrans_notifier.list.next)
		unregister_mtd_user(&blktrans_notifier);
}

module_exit(mtd_blktrans_exit);

EXPORT_SYMBOL_GPL(register_mtd_blktrans);
EXPORT_SYMBOL_GPL(deregister_mtd_blktrans);
EXPORT_SYMBOL_GPL(add_mtd_blktrans_dev);
EXPORT_SYMBOL_GPL(del_mtd_blktrans_dev);

MODULE_AUTHOR("David Woodhouse <dwmw2@infradead.org>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Common interface to block layer for MTD 'translation layers'");
