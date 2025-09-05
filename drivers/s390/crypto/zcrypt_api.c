// SPDX-License-Identifier: GPL-2.0+
/*
 *  linux/drivers/s390/crypto/zcrypt_api.c
 *
 *  zcrypt 2.1.0
 *
 *  Copyright (C)  2001, 2006 IBM Corporation
 *  zcrypt 2.1.0
 *
 *  Copyright IBM Corp. 2001, 2012
 *  Author(s): Robert Burroughs
 *	       Eric Rossman (edrossma@us.ibm.com)
 *	       Cornelia Huck <cornelia.huck@de.ibm.com>
 *
 *  Hotplug & misc device support: Jochen Roehrig (roehrig@de.ibm.com)
 *  Major cleanup & driver split: Martin Schwidefsky <schwidefsky@de.ibm.com>
 *				  Ralph Wuerthner <rwuerthn@de.ibm.com>
 *  MSGTYPE restruct:		  Holger Dengler <hd@linux.vnet.ibm.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/compat.h>
#include <linux/smp_lock.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/hw_random.h>

#include "zcrypt_api.h"

#include <linux/seq_file.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/hw_random.h>
#include <linux/debugfs.h>
#include <asm/debug.h>

#define CREATE_TRACE_POINTS
#include <asm/trace/zcrypt.h>

#include "zcrypt_api.h"
#include "zcrypt_debug.h"

#include "zcrypt_msgtype6.h"
#include "zcrypt_msgtype50.h"

/*
 * Module description.
 */
MODULE_AUTHOR("IBM Corporation");
MODULE_DESCRIPTION("Cryptographic Coprocessor interface, "
		   "Copyright 2001, 2006 IBM Corporation");
MODULE_LICENSE("GPL");

MODULE_DESCRIPTION("Cryptographic Coprocessor interface, " \
		   "Copyright IBM Corp. 2001, 2012");
MODULE_LICENSE("GPL");

/*
 * zcrypt tracepoint functions
 */
EXPORT_TRACEPOINT_SYMBOL(s390_zcrypt_req);
EXPORT_TRACEPOINT_SYMBOL(s390_zcrypt_rep);

static int zcrypt_hwrng_seed = 1;
module_param_named(hwrng_seed, zcrypt_hwrng_seed, int, 0440);
MODULE_PARM_DESC(hwrng_seed, "Turn on/off hwrng auto seed, default is 1 (on).");

DEFINE_SPINLOCK(zcrypt_list_lock);
LIST_HEAD(zcrypt_card_list);
int zcrypt_device_count;

static atomic_t zcrypt_open_count = ATOMIC_INIT(0);
static atomic_t zcrypt_rescan_count = ATOMIC_INIT(0);

atomic_t zcrypt_rescan_req = ATOMIC_INIT(0);
EXPORT_SYMBOL(zcrypt_rescan_req);

static LIST_HEAD(zcrypt_ops_list);

/* Zcrypt related debug feature stuff. */
debug_info_t *zcrypt_dbf_info;

/**
 * Process a rescan of the transport layer.
 *
 * Returns 1, if the rescan has been processed, otherwise 0.
 */
static inline int zcrypt_process_rescan(void)
{
	if (atomic_read(&zcrypt_rescan_req)) {
		atomic_set(&zcrypt_rescan_req, 0);
		atomic_inc(&zcrypt_rescan_count);
		ap_bus_force_rescan();
		ZCRYPT_DBF(DBF_INFO, "rescan count=%07d\n",
			   atomic_inc_return(&zcrypt_rescan_count));
		return 1;
	}
	return 0;
}

/**
 * __zcrypt_increase_preference(): Increase preference of a crypto device.
 * @zdev: Pointer the crypto device
 *
 * Move the device towards the head of the device list.
 * Need to be called while holding the zcrypt device list lock.
 * Note: cards with speed_rating of 0 are kept at the end of the list.
 */
static void __zcrypt_increase_preference(struct zcrypt_device *zdev)
{
	struct zcrypt_device *tmp;
	struct list_head *l;

	if (zdev->speed_rating == 0)
		return;
	for (l = zdev->list.prev; l != &zcrypt_device_list; l = l->prev) {
		tmp = list_entry(l, struct zcrypt_device, list);
		if ((tmp->request_count + 1) * tmp->speed_rating <=
		    (zdev->request_count + 1) * zdev->speed_rating &&
		    tmp->speed_rating != 0)
			break;
	}
	if (l == zdev->list.prev)
		return;
	/* Move zdev behind l */
	list_del(&zdev->list);
	list_add(&zdev->list, l);
	list_move(&zdev->list, l);
}

/**
 * __zcrypt_decrease_preference(): Decrease preference of a crypto device.
 * @zdev: Pointer to a crypto device.
 *
 * Move the device towards the tail of the device list.
 * Need to be called while holding the zcrypt device list lock.
 * Note: cards with speed_rating of 0 are kept at the end of the list.
 */
static void __zcrypt_decrease_preference(struct zcrypt_device *zdev)
{
	struct zcrypt_device *tmp;
	struct list_head *l;

	if (zdev->speed_rating == 0)
		return;
	for (l = zdev->list.next; l != &zcrypt_device_list; l = l->next) {
		tmp = list_entry(l, struct zcrypt_device, list);
		if ((tmp->request_count + 1) * tmp->speed_rating >
		    (zdev->request_count + 1) * zdev->speed_rating ||
		    tmp->speed_rating == 0)
			break;
	}
	if (l == zdev->list.next)
		return;
	/* Move zdev before l */
	list_del(&zdev->list);
	list_add_tail(&zdev->list, l);
	list_move_tail(&zdev->list, l);
}

static void zcrypt_device_release(struct kref *kref)
{
	struct zcrypt_device *zdev =
		container_of(kref, struct zcrypt_device, refcount);
	zcrypt_device_free(zdev);
}

void zcrypt_device_get(struct zcrypt_device *zdev)
{
	kref_get(&zdev->refcount);
}
EXPORT_SYMBOL(zcrypt_device_get);

int zcrypt_device_put(struct zcrypt_device *zdev)
{
	return kref_put(&zdev->refcount, zcrypt_device_release);
}
EXPORT_SYMBOL(zcrypt_device_put);

struct zcrypt_device *zcrypt_device_alloc(size_t max_response_size)
{
	struct zcrypt_device *zdev;

	zdev = kzalloc(sizeof(struct zcrypt_device), GFP_KERNEL);
	if (!zdev)
		return NULL;
	zdev->reply.message = kmalloc(max_response_size, GFP_KERNEL);
	if (!zdev->reply.message)
		goto out_free;
	zdev->reply.length = max_response_size;
	spin_lock_init(&zdev->lock);
	INIT_LIST_HEAD(&zdev->list);
	zdev->dbf_area = zcrypt_dbf_devices;
	return zdev;

out_free:
	kfree(zdev);
	return NULL;
}
EXPORT_SYMBOL(zcrypt_device_alloc);

void zcrypt_device_free(struct zcrypt_device *zdev)
{
	kfree(zdev->reply.message);
	kfree(zdev);
}
EXPORT_SYMBOL(zcrypt_device_free);

/**
 * zcrypt_device_register() - Register a crypto device.
 * @zdev: Pointer to a crypto device
 *
 * Register a crypto device. Returns 0 if successful.
 */
int zcrypt_device_register(struct zcrypt_device *zdev)
{
	int rc;

	if (!zdev->ops)
		return -ENODEV;
	rc = sysfs_create_group(&zdev->ap_dev->device.kobj,
				&zcrypt_device_attr_group);
	if (rc)
		goto out;
	get_device(&zdev->ap_dev->device);
	kref_init(&zdev->refcount);
	spin_lock_bh(&zcrypt_device_lock);
	zdev->online = 1;	/* New devices are online by default. */
	ZCRYPT_DBF_DEV(DBF_INFO, zdev, "dev%04xo%dreg", zdev->ap_dev->qid,
		       zdev->online);
	list_add_tail(&zdev->list, &zcrypt_device_list);
	__zcrypt_increase_preference(zdev);
	zcrypt_device_count++;
	spin_unlock_bh(&zcrypt_device_lock);
	if (zdev->ops->rng) {
		rc = zcrypt_rng_device_add();
		if (rc)
			goto out_unregister;
	}
	return 0;

out_unregister:
	spin_lock_bh(&zcrypt_device_lock);
	zcrypt_device_count--;
	list_del_init(&zdev->list);
	spin_unlock_bh(&zcrypt_device_lock);
	sysfs_remove_group(&zdev->ap_dev->device.kobj,
			   &zcrypt_device_attr_group);
	put_device(&zdev->ap_dev->device);
	zcrypt_device_put(zdev);
out:
	return rc;
}
EXPORT_SYMBOL(zcrypt_device_register);

/**
 * zcrypt_device_unregister(): Unregister a crypto device.
 * @zdev: Pointer to crypto device
 *
 * Unregister a crypto device.
 */
void zcrypt_device_unregister(struct zcrypt_device *zdev)
{
	if (zdev->ops->rng)
		zcrypt_rng_device_remove();
	spin_lock_bh(&zcrypt_device_lock);
	zcrypt_device_count--;
	list_del_init(&zdev->list);
	spin_unlock_bh(&zcrypt_device_lock);
	sysfs_remove_group(&zdev->ap_dev->device.kobj,
			   &zcrypt_device_attr_group);
	put_device(&zdev->ap_dev->device);
	zcrypt_device_put(zdev);
}
EXPORT_SYMBOL(zcrypt_device_unregister);

void zcrypt_msgtype_register(struct zcrypt_ops *zops)
{
	list_add_tail(&zops->list, &zcrypt_ops_list);
}

void zcrypt_msgtype_unregister(struct zcrypt_ops *zops)
{
	list_del_init(&zops->list);
}

struct zcrypt_ops *zcrypt_msgtype(unsigned char *name, int variant)
{
	struct zcrypt_ops *zops;

	list_for_each_entry(zops, &zcrypt_ops_list, list)
		if ((zops->variant == variant) &&
		    (!strncmp(zops->name, name, sizeof(zops->name))))
			return zops;
	return NULL;
}
EXPORT_SYMBOL(zcrypt_msgtype);

/**
 * zcrypt_read (): Not supported beyond zcrypt 1.3.1.
 *
 * This function is not supported beyond zcrypt 1.3.1.
 */
static ssize_t zcrypt_read(struct file *filp, char __user *buf,
			   size_t count, loff_t *f_pos)
{
	return -EPERM;
}

/**
 * zcrypt_write(): Not allowed.
 *
 * Write is is not allowed
 */
static ssize_t zcrypt_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *f_pos)
{
	return -EPERM;
}

/**
 * zcrypt_open(): Count number of users.
 *
 * Device open function to count number of users.
 */
static int zcrypt_open(struct inode *inode, struct file *filp)
{
	lock_kernel();
	atomic_inc(&zcrypt_open_count);
	unlock_kernel();
	return 0;
	atomic_inc(&zcrypt_open_count);
	return nonseekable_open(inode, filp);
}

/**
 * zcrypt_release(): Count number of users.
 *
 * Device close function to count number of users.
 */
static int zcrypt_release(struct inode *inode, struct file *filp)
{
	atomic_dec(&zcrypt_open_count);
	return 0;
}

static inline struct zcrypt_queue *zcrypt_pick_queue(struct zcrypt_card *zc,
						     struct zcrypt_queue *zq,
						     unsigned int weight)
{
	if (!zq || !try_module_get(zq->queue->ap_dev.drv->driver.owner))
		return NULL;
	zcrypt_queue_get(zq);
	get_device(&zq->queue->ap_dev.device);
	atomic_add(weight, &zc->load);
	atomic_add(weight, &zq->load);
	zq->request_count++;
	return zq;
}

static inline void zcrypt_drop_queue(struct zcrypt_card *zc,
				     struct zcrypt_queue *zq,
				     unsigned int weight)
{
	struct module *mod = zq->queue->ap_dev.drv->driver.owner;

	zq->request_count--;
	atomic_sub(weight, &zc->load);
	atomic_sub(weight, &zq->load);
	put_device(&zq->queue->ap_dev.device);
	zcrypt_queue_put(zq);
	module_put(mod);
}

static inline bool zcrypt_card_compare(struct zcrypt_card *zc,
				       struct zcrypt_card *pref_zc,
				       unsigned int weight,
				       unsigned int pref_weight)
{
	if (!pref_zc)
		return false;
	weight += atomic_read(&zc->load);
	pref_weight += atomic_read(&pref_zc->load);
	if (weight == pref_weight)
		return atomic_read(&zc->card->total_request_count) >
			atomic_read(&pref_zc->card->total_request_count);
	return weight > pref_weight;
}

static inline bool zcrypt_queue_compare(struct zcrypt_queue *zq,
					struct zcrypt_queue *pref_zq,
					unsigned int weight,
					unsigned int pref_weight)
{
	if (!pref_zq)
		return false;
	weight += atomic_read(&zq->load);
	pref_weight += atomic_read(&pref_zq->load);
	if (weight == pref_weight)
		return zq->queue->total_request_count >
			pref_zq->queue->total_request_count;
	return weight > pref_weight;
}

/*
 * zcrypt ioctls.
 */
static long zcrypt_rsa_modexpo(struct ica_rsa_modexpo *mex)
{
	struct zcrypt_card *zc, *pref_zc;
	struct zcrypt_queue *zq, *pref_zq;
	unsigned int weight, pref_weight;
	unsigned int func_code;
	int qid = 0, rc = -ENODEV;

	trace_s390_zcrypt_req(mex, TP_ICARSAMODEXPO);

	if (mex->outputdatalength < mex->inputdatalength) {
		rc = -EINVAL;
		goto out;
	}

	/*
	 * As long as outputdatalength is big enough, we can set the
	 * outputdatalength equal to the inputdatalength, since that is the
	 * number of bytes we will copy in any case
	 */
	mex->outputdatalength = mex->inputdatalength;

	rc = get_rsa_modex_fc(mex, &func_code);
	if (rc)
		goto out;

	pref_zc = NULL;
	pref_zq = NULL;
	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		/* Check for online accelarator and CCA cards */
		if (!zc->online || !(zc->card->functions & 0x18000000))
			continue;
		/* Check for size limits */
		if (zc->min_mod_size > mex->inputdatalength ||
		    zc->max_mod_size < mex->inputdatalength)
			continue;
		/* get weight index of the card device	*/
		weight = zc->speed_rating[func_code];
		if (zcrypt_card_compare(zc, pref_zc, weight, pref_weight))
			continue;
		for_each_zcrypt_queue(zq, zc) {
			/* check if device is online and eligible */
			if (!zq->online || !zq->ops->rsa_modexpo)
				continue;
			if (zcrypt_queue_compare(zq, pref_zq,
						 weight, pref_weight))
				continue;
			pref_zc = zc;
			pref_zq = zq;
			pref_weight = weight;
		}
	}
	pref_zq = zcrypt_pick_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

	if (!pref_zq) {
		rc = -ENODEV;
		goto out;
	}

	qid = pref_zq->queue->qid;
	rc = pref_zq->ops->rsa_modexpo(pref_zq, mex);

	spin_lock(&zcrypt_list_lock);
	zcrypt_drop_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

out:
	trace_s390_zcrypt_rep(mex, func_code, rc,
			      AP_QID_CARD(qid), AP_QID_QUEUE(qid));
	return rc;
}

static long zcrypt_rsa_crt(struct ica_rsa_modexpo_crt *crt)
{
	struct zcrypt_card *zc, *pref_zc;
	struct zcrypt_queue *zq, *pref_zq;
	unsigned int weight, pref_weight;
	unsigned int func_code;
	int qid = 0, rc = -ENODEV;

	trace_s390_zcrypt_req(crt, TP_ICARSACRT);

	if (crt->outputdatalength < crt->inputdatalength) {
		rc = -EINVAL;
		goto out;
	}

	if (crt->outputdatalength < crt->inputdatalength ||
	    (crt->inputdatalength & 1))
	if (crt->outputdatalength < crt->inputdatalength)
		return -EINVAL;
	/*
	 * As long as outputdatalength is big enough, we can set the
	 * outputdatalength equal to the inputdatalength, since that is the
	 * number of bytes we will copy in any case
	 */
	crt->outputdatalength = crt->inputdatalength;

	rc = get_rsa_crt_fc(crt, &func_code);
	if (rc)
		goto out;

	pref_zc = NULL;
	pref_zq = NULL;
	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		/* Check for online accelarator and CCA cards */
		if (!zc->online || !(zc->card->functions & 0x18000000))
			continue;
		if (zdev->short_crt && crt->inputdatalength > 240) {
			/*
			 * Check inputdata for leading zeros for cards
			 * that can't handle np_prime, bp_key, or
			 * u_mult_inv > 128 bytes.
			 */
			if (copied == 0) {
				int len;
				spin_unlock_bh(&zcrypt_device_lock);
				/* len is max 256 / 2 - 120 = 8 */
				len = crt->inputdatalength / 2 - 120;
				unsigned int len;
				spin_unlock_bh(&zcrypt_device_lock);
				/* len is max 256 / 2 - 120 = 8
				 * For bigger device just assume len of leading
				 * 0s is 8 as stated in the requirements for
				 * ica_rsa_modexpo_crt struct in zcrypt.h.
				 */
				if (crt->inputdatalength <= 256)
					len = crt->inputdatalength / 2 - 120;
				else
					len = 8;
				if (len > sizeof(z1))
					return -EFAULT;
				z1 = z2 = z3 = 0;
				if (copy_from_user(&z1, crt->np_prime, len) ||
				    copy_from_user(&z2, crt->bp_key, len) ||
				    copy_from_user(&z3, crt->u_mult_inv, len))
					return -EFAULT;
				z1 = z2 = z3 = 0;
				copied = 1;
				/*
				 * We have to restart device lookup -
				 * the device list may have changed by now.
				 */
				goto restart;
			}
			if (z1 != 0ULL || z2 != 0ULL || z3 != 0ULL)
				/* The device can't handle this request. */
		/* Check for size limits */
		if (zc->min_mod_size > crt->inputdatalength ||
		    zc->max_mod_size < crt->inputdatalength)
			continue;
		/* get weight index of the card device	*/
		weight = zc->speed_rating[func_code];
		if (zcrypt_card_compare(zc, pref_zc, weight, pref_weight))
			continue;
		for_each_zcrypt_queue(zq, zc) {
			/* check if device is online and eligible */
			if (!zq->online || !zq->ops->rsa_modexpo_crt)
				continue;
			if (zcrypt_queue_compare(zq, pref_zq,
						 weight, pref_weight))
				continue;
			pref_zc = zc;
			pref_zq = zq;
			pref_weight = weight;
		}
	}
	pref_zq = zcrypt_pick_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

	if (!pref_zq) {
		rc = -ENODEV;
		goto out;
	}

	qid = pref_zq->queue->qid;
	rc = pref_zq->ops->rsa_modexpo_crt(pref_zq, crt);

	spin_lock(&zcrypt_list_lock);
	zcrypt_drop_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

out:
	trace_s390_zcrypt_rep(crt, func_code, rc,
			      AP_QID_CARD(qid), AP_QID_QUEUE(qid));
	return rc;
}

long zcrypt_send_cprb(struct ica_xcRB *xcRB)
{
	struct zcrypt_card *zc, *pref_zc;
	struct zcrypt_queue *zq, *pref_zq;
	struct ap_message ap_msg;
	unsigned int weight, pref_weight;
	unsigned int func_code;
	unsigned short *domain;
	int qid = 0, rc = -ENODEV;

	spin_lock_bh(&zcrypt_device_lock);
	list_for_each_entry(zdev, &zcrypt_device_list, list) {
		if (!zdev->online || !zdev->ops->send_cprb ||
		    (xcRB->user_defined != AUTOSELECT &&
			AP_QID_DEVICE(zdev->ap_dev->qid) != xcRB->user_defined)
		    )
		   (zdev->ops->variant == MSGTYPE06_VARIANT_EP11) ||
		   (xcRB->user_defined != AUTOSELECT &&
		    AP_QID_DEVICE(zdev->ap_dev->qid) != xcRB->user_defined))
	trace_s390_zcrypt_req(xcRB, TB_ZSECSENDCPRB);

	ap_init_message(&ap_msg);
	rc = get_cprb_fc(xcRB, &ap_msg, &func_code, &domain);
	if (rc)
		goto out;

	pref_zc = NULL;
	pref_zq = NULL;
	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		/* Check for online CCA cards */
		if (!zc->online || !(zc->card->functions & 0x10000000))
			continue;
		/* Check for user selected CCA card */
		if (xcRB->user_defined != AUTOSELECT &&
		    xcRB->user_defined != zc->card->id)
			continue;
		/* get weight index of the card device	*/
		weight = speed_idx_cca(func_code) * zc->speed_rating[SECKEY];
		if (zcrypt_card_compare(zc, pref_zc, weight, pref_weight))
			continue;
		for_each_zcrypt_queue(zq, zc) {
			/* check if device is online and eligible */
			if (!zq->online ||
			    !zq->ops->send_cprb ||
			    ((*domain != (unsigned short) AUTOSELECT) &&
			     (*domain != AP_QID_QUEUE(zq->queue->qid))))
				continue;
			if (zcrypt_queue_compare(zq, pref_zq,
						 weight, pref_weight))
				continue;
			pref_zc = zc;
			pref_zq = zq;
			pref_weight = weight;
		}
	}
	pref_zq = zcrypt_pick_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

	if (!pref_zq) {
		rc = -ENODEV;
		goto out;
	}

	/* in case of auto select, provide the correct domain */
	qid = pref_zq->queue->qid;
	if (*domain == (unsigned short) AUTOSELECT)
		*domain = AP_QID_QUEUE(qid);

	rc = pref_zq->ops->send_cprb(pref_zq, xcRB, &ap_msg);

	spin_lock(&zcrypt_list_lock);
	zcrypt_drop_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

out:
	ap_release_message(&ap_msg);
	trace_s390_zcrypt_rep(xcRB, func_code, rc,
			      AP_QID_CARD(qid), AP_QID_QUEUE(qid));
	return rc;
}
EXPORT_SYMBOL(zcrypt_send_cprb);

static bool is_desired_ep11_card(unsigned int dev_id,
				 unsigned short target_num,
				 struct ep11_target_dev *targets)
{
	while (target_num-- > 0) {
		if (dev_id == targets->ap_id)
			return true;
		targets++;
	}
	return false;
}

static bool is_desired_ep11_queue(unsigned int dev_qid,
				  unsigned short target_num,
				  struct ep11_target_dev *targets)
{
	while (target_num-- > 0) {
		if (AP_MKQID(targets->ap_id, targets->dom_id) == dev_qid)
			return true;
		targets++;
	}
	return false;
}

static long zcrypt_send_ep11_cprb(struct ep11_urb *xcrb)
{
	struct zcrypt_card *zc, *pref_zc;
	struct zcrypt_queue *zq, *pref_zq;
	struct ep11_target_dev *targets;
	unsigned short target_num;
	unsigned int weight, pref_weight;
	unsigned int func_code;
	struct ap_message ap_msg;
	int qid = 0, rc = -ENODEV;

	trace_s390_zcrypt_req(xcrb, TP_ZSENDEP11CPRB);

	ap_init_message(&ap_msg);

	target_num = (unsigned short) xcrb->targets_num;

	/* empty list indicates autoselect (all available targets) */
	targets = NULL;
	if (target_num != 0) {
		struct ep11_target_dev __user *uptr;

		targets = kcalloc(target_num, sizeof(*targets), GFP_KERNEL);
		if (!targets) {
			rc = -ENOMEM;
			goto out;
		}

		uptr = (struct ep11_target_dev __force __user *) xcrb->targets;
		if (copy_from_user(targets, uptr,
				   target_num * sizeof(*targets))) {
			rc = -EFAULT;
			goto out_free;
		}
	}

	rc = get_ep11cprb_fc(xcrb, &ap_msg, &func_code);
	if (rc)
		goto out_free;

	pref_zc = NULL;
	pref_zq = NULL;
	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		/* Check for online EP11 cards */
		if (!zc->online || !(zc->card->functions & 0x04000000))
			continue;
		/* Check for user selected EP11 card */
		if (targets &&
		    !is_desired_ep11_card(zc->card->id, target_num, targets))
			continue;
		/* get weight index of the card device	*/
		weight = speed_idx_ep11(func_code) * zc->speed_rating[SECKEY];
		if (zcrypt_card_compare(zc, pref_zc, weight, pref_weight))
			continue;
		for_each_zcrypt_queue(zq, zc) {
			/* check if device is online and eligible */
			if (!zq->online ||
			    !zq->ops->send_ep11_cprb ||
			    (targets &&
			     !is_desired_ep11_queue(zq->queue->qid,
						    target_num, targets)))
				continue;
			if (zcrypt_queue_compare(zq, pref_zq,
						 weight, pref_weight))
				continue;
			pref_zc = zc;
			pref_zq = zq;
			pref_weight = weight;
		}
	}
	pref_zq = zcrypt_pick_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

	if (!pref_zq) {
		rc = -ENODEV;
		goto out_free;
	}

	qid = pref_zq->queue->qid;
	rc = pref_zq->ops->send_ep11_cprb(pref_zq, xcrb, &ap_msg);

	spin_lock(&zcrypt_list_lock);
	zcrypt_drop_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

out_free:
	kfree(targets);
out:
	ap_release_message(&ap_msg);
	trace_s390_zcrypt_rep(xcrb, func_code, rc,
			      AP_QID_CARD(qid), AP_QID_QUEUE(qid));
	return rc;
}

static long zcrypt_rng(char *buffer)
{
	struct zcrypt_card *zc, *pref_zc;
	struct zcrypt_queue *zq, *pref_zq;
	unsigned int weight, pref_weight;
	unsigned int func_code;
	struct ap_message ap_msg;
	unsigned int domain;
	int qid = 0, rc = -ENODEV;

	trace_s390_zcrypt_req(buffer, TP_HWRNGCPRB);

	ap_init_message(&ap_msg);
	rc = get_rng_fc(&ap_msg, &func_code, &domain);
	if (rc)
		goto out;

	pref_zc = NULL;
	pref_zq = NULL;
	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		/* Check for online CCA cards */
		if (!zc->online || !(zc->card->functions & 0x10000000))
			continue;
		/* get weight index of the card device	*/
		weight = zc->speed_rating[func_code];
		if (zcrypt_card_compare(zc, pref_zc, weight, pref_weight))
			continue;
		for_each_zcrypt_queue(zq, zc) {
			/* check if device is online and eligible */
			if (!zq->online || !zq->ops->rng)
				continue;
			if (zcrypt_queue_compare(zq, pref_zq,
						 weight, pref_weight))
				continue;
			pref_zc = zc;
			pref_zq = zq;
			pref_weight = weight;
		}
	}
	pref_zq = zcrypt_pick_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

	if (!pref_zq) {
		rc = -ENODEV;
		goto out;
	}

	qid = pref_zq->queue->qid;
	rc = pref_zq->ops->rng(pref_zq, buffer, &ap_msg);

	spin_lock(&zcrypt_list_lock);
	zcrypt_drop_queue(pref_zc, pref_zq, weight);
	spin_unlock(&zcrypt_list_lock);

out:
	ap_release_message(&ap_msg);
	trace_s390_zcrypt_rep(buffer, func_code, rc,
			      AP_QID_CARD(qid), AP_QID_QUEUE(qid));
	return rc;
}

static void zcrypt_device_status_mask(struct zcrypt_device_status *devstatus)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	struct zcrypt_device_status *stat;
	int card, queue;

	memset(devstatus, 0, MAX_ZDEV_ENTRIES
	       * sizeof(struct zcrypt_device_status));

	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			card = AP_QID_CARD(zq->queue->qid);
			if (card >= MAX_ZDEV_CARDIDS)
				continue;
			queue = AP_QID_QUEUE(zq->queue->qid);
			stat = &devstatus[card * AP_DOMAINS + queue];
			stat->hwtype = zc->card->ap_dev.device_type;
			stat->functions = zc->card->functions >> 26;
			stat->qid = zq->queue->qid;
			stat->online = zq->online ? 0x01 : 0x00;
		}
	}
	spin_unlock(&zcrypt_list_lock);
}

void zcrypt_device_status_mask_ext(struct zcrypt_device_status_ext *devstatus)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	struct zcrypt_device_status_ext *stat;
	int card, queue;

	memset(devstatus, 0, MAX_ZDEV_ENTRIES_EXT
	       * sizeof(struct zcrypt_device_status_ext));

	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			card = AP_QID_CARD(zq->queue->qid);
			queue = AP_QID_QUEUE(zq->queue->qid);
			stat = &devstatus[card * AP_DOMAINS + queue];
			stat->hwtype = zc->card->ap_dev.device_type;
			stat->functions = zc->card->functions >> 26;
			stat->qid = zq->queue->qid;
			stat->online = zq->online ? 0x01 : 0x00;
		}
	}
	spin_unlock(&zcrypt_list_lock);
}
EXPORT_SYMBOL(zcrypt_device_status_mask_ext);

static void zcrypt_status_mask(char status[], size_t max_adapters)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	int card;

	memset(status, 0, max_adapters);
	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			card = AP_QID_CARD(zq->queue->qid);
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index
			    || card >= max_adapters)
				continue;
			status[card] = zc->online ? zc->user_space_type : 0x0d;
		}
	}
	spin_unlock(&zcrypt_list_lock);
}

static void zcrypt_qdepth_mask(char qdepth[], size_t max_adapters)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	int card;

	memset(qdepth, 0, max_adapters);
	spin_lock(&zcrypt_list_lock);
	local_bh_disable();
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			card = AP_QID_CARD(zq->queue->qid);
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index
			    || card >= max_adapters)
				continue;
			spin_lock(&zq->queue->lock);
			qdepth[card] =
				zq->queue->pendingq_count +
				zq->queue->requestq_count;
			spin_unlock(&zq->queue->lock);
		}
	}
	local_bh_enable();
	spin_unlock(&zcrypt_list_lock);
}

static void zcrypt_perdev_reqcnt(int reqcnt[], size_t max_adapters)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	int card;

	memset(reqcnt, 0, sizeof(int) * max_adapters);
	spin_lock(&zcrypt_list_lock);
	local_bh_disable();
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			card = AP_QID_CARD(zq->queue->qid);
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index
			    || card >= max_adapters)
				continue;
			spin_lock(&zq->queue->lock);
			reqcnt[card] = zq->queue->total_request_count;
			spin_unlock(&zq->queue->lock);
		}
	}
	local_bh_enable();
	spin_unlock(&zcrypt_list_lock);
}

static int zcrypt_pendingq_count(void)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	int pendingq_count;

	pendingq_count = 0;
	spin_lock(&zcrypt_list_lock);
	local_bh_disable();
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index)
				continue;
			spin_lock(&zq->queue->lock);
			pendingq_count += zq->queue->pendingq_count;
			spin_unlock(&zq->queue->lock);
		}
	}
	local_bh_enable();
	spin_unlock(&zcrypt_list_lock);
	return pendingq_count;
}

static int zcrypt_requestq_count(void)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;
	int requestq_count;

	requestq_count = 0;
	spin_lock(&zcrypt_list_lock);
	local_bh_disable();
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index)
				continue;
			spin_lock(&zq->queue->lock);
			requestq_count += zq->queue->requestq_count;
			spin_unlock(&zq->queue->lock);
		}
	}
	local_bh_enable();
	spin_unlock(&zcrypt_list_lock);
	return requestq_count;
}

static long zcrypt_unlocked_ioctl(struct file *filp, unsigned int cmd,
				  unsigned long arg)
{
	int rc = 0;

	switch (cmd) {
	case ICARSAMODEXPO: {
		struct ica_rsa_modexpo __user *umex = (void __user *) arg;
		struct ica_rsa_modexpo mex;

		if (copy_from_user(&mex, umex, sizeof(mex)))
			return -EFAULT;
		do {
			rc = zcrypt_rsa_modexpo(&mex);
		} while (rc == -EAGAIN);
		/* on failure: retry once again after a requested rescan */
		if ((rc == -ENODEV) && (zcrypt_process_rescan()))
			do {
				rc = zcrypt_rsa_modexpo(&mex);
			} while (rc == -EAGAIN);
		if (rc) {
			ZCRYPT_DBF(DBF_DEBUG, "ioctl ICARSAMODEXPO rc=%d\n", rc);
			return rc;
		}
		return put_user(mex.outputdatalength, &umex->outputdatalength);
	}
	case ICARSACRT: {
		struct ica_rsa_modexpo_crt __user *ucrt = (void __user *) arg;
		struct ica_rsa_modexpo_crt crt;

		if (copy_from_user(&crt, ucrt, sizeof(crt)))
			return -EFAULT;
		do {
			rc = zcrypt_rsa_crt(&crt);
		} while (rc == -EAGAIN);
		/* on failure: retry once again after a requested rescan */
		if ((rc == -ENODEV) && (zcrypt_process_rescan()))
			do {
				rc = zcrypt_rsa_crt(&crt);
			} while (rc == -EAGAIN);
		if (rc) {
			ZCRYPT_DBF(DBF_DEBUG, "ioctl ICARSACRT rc=%d\n", rc);
			return rc;
		}
		return put_user(crt.outputdatalength, &ucrt->outputdatalength);
	}
	case ZSECSENDCPRB: {
		struct ica_xcRB __user *uxcRB = (void __user *) arg;
		struct ica_xcRB xcRB;

		if (copy_from_user(&xcRB, uxcRB, sizeof(xcRB)))
			return -EFAULT;
		do {
			rc = zcrypt_send_cprb(&xcRB);
		} while (rc == -EAGAIN);
		/* on failure: retry once again after a requested rescan */
		if ((rc == -ENODEV) && (zcrypt_process_rescan()))
			do {
				rc = zcrypt_send_cprb(&xcRB);
			} while (rc == -EAGAIN);
		if (rc)
			ZCRYPT_DBF(DBF_DEBUG, "ioctl ZSENDCPRB rc=%d\n", rc);
		if (copy_to_user(uxcRB, &xcRB, sizeof(xcRB)))
			return -EFAULT;
		return rc;
	}
	case ZSENDEP11CPRB: {
		struct ep11_urb __user *uxcrb = (void __user *)arg;
		struct ep11_urb xcrb;

		if (copy_from_user(&xcrb, uxcrb, sizeof(xcrb)))
			return -EFAULT;
		do {
			rc = zcrypt_send_ep11_cprb(&xcrb);
		} while (rc == -EAGAIN);
		/* on failure: retry once again after a requested rescan */
		if ((rc == -ENODEV) && (zcrypt_process_rescan()))
			do {
				rc = zcrypt_send_ep11_cprb(&xcrb);
			} while (rc == -EAGAIN);
		if (rc)
			ZCRYPT_DBF(DBF_DEBUG, "ioctl ZSENDEP11CPRB rc=%d\n", rc);
		if (copy_to_user(uxcrb, &xcrb, sizeof(xcrb)))
			return -EFAULT;
		return rc;
	}
	case ZCRYPT_DEVICE_STATUS: {
		struct zcrypt_device_status_ext *device_status;
		size_t total_size = MAX_ZDEV_ENTRIES_EXT
			* sizeof(struct zcrypt_device_status_ext);

		device_status = kzalloc(total_size, GFP_KERNEL);
		if (!device_status)
			return -ENOMEM;
		zcrypt_device_status_mask_ext(device_status);
		if (copy_to_user((char __user *) arg, device_status,
				 total_size))
			rc = -EFAULT;
		kfree(device_status);
		return rc;
	}
	case ZCRYPT_STATUS_MASK: {
		char status[AP_DEVICES];

		zcrypt_status_mask(status, AP_DEVICES);
		if (copy_to_user((char __user *) arg, status, sizeof(status)))
			return -EFAULT;
		return 0;
	}
	case ZCRYPT_QDEPTH_MASK: {
		char qdepth[AP_DEVICES];

		zcrypt_qdepth_mask(qdepth, AP_DEVICES);
		if (copy_to_user((char __user *) arg, qdepth, sizeof(qdepth)))
			return -EFAULT;
		return 0;
	}
	case ZCRYPT_PERDEV_REQCNT: {
		int *reqcnt;

		reqcnt = kcalloc(AP_DEVICES, sizeof(int), GFP_KERNEL);
		if (!reqcnt)
			return -ENOMEM;
		zcrypt_perdev_reqcnt(reqcnt, AP_DEVICES);
		if (copy_to_user((int __user *) arg, reqcnt, sizeof(reqcnt)))
			rc = -EFAULT;
		kfree(reqcnt);
		return rc;
	}
	case Z90STAT_REQUESTQ_COUNT:
		return put_user(zcrypt_requestq_count(), (int __user *) arg);
	case Z90STAT_PENDINGQ_COUNT:
		return put_user(zcrypt_pendingq_count(), (int __user *) arg);
	case Z90STAT_TOTALOPEN_COUNT:
		return put_user(atomic_read(&zcrypt_open_count),
				(int __user *) arg);
	case Z90STAT_DOMAIN_INDEX:
		return put_user(ap_domain_index, (int __user *) arg);
	/*
	 * Deprecated ioctls
	 */
	case ZDEVICESTATUS: {
		/* the old ioctl supports only 64 adapters */
		struct zcrypt_device_status *device_status;
		size_t total_size = MAX_ZDEV_ENTRIES
			* sizeof(struct zcrypt_device_status);

		device_status = kzalloc(total_size, GFP_KERNEL);
		if (!device_status)
			return -ENOMEM;
		zcrypt_device_status_mask(device_status);
		if (copy_to_user((char __user *) arg, device_status,
				 total_size))
			rc = -EFAULT;
		kfree(device_status);
		return rc;
	}
	case Z90STAT_STATUS_MASK: {
		/* the old ioctl supports only 64 adapters */
		char status[MAX_ZDEV_CARDIDS];

		zcrypt_status_mask(status, MAX_ZDEV_CARDIDS);
		if (copy_to_user((char __user *) arg, status, sizeof(status)))
			return -EFAULT;
		return 0;
	}
	case Z90STAT_QDEPTH_MASK: {
		/* the old ioctl supports only 64 adapters */
		char qdepth[MAX_ZDEV_CARDIDS];

		zcrypt_qdepth_mask(qdepth, MAX_ZDEV_CARDIDS);
		if (copy_to_user((char __user *) arg, qdepth, sizeof(qdepth)))
			return -EFAULT;
		return 0;
	}
	case Z90STAT_PERDEV_REQCNT: {
		/* the old ioctl supports only 64 adapters */
		int reqcnt[MAX_ZDEV_CARDIDS];

		zcrypt_perdev_reqcnt(reqcnt, MAX_ZDEV_CARDIDS);
		if (copy_to_user((int __user *) arg, reqcnt, sizeof(reqcnt)))
			return -EFAULT;
		return 0;
	}
	/* unknown ioctl number */
	default:
		ZCRYPT_DBF(DBF_DEBUG, "unknown ioctl 0x%08x\n", cmd);
		return -ENOIOCTLCMD;
	}
}

#ifdef CONFIG_COMPAT
/*
 * ioctl32 conversion routines
 */
struct compat_ica_rsa_modexpo {
	compat_uptr_t	inputdata;
	unsigned int	inputdatalength;
	compat_uptr_t	outputdata;
	unsigned int	outputdatalength;
	compat_uptr_t	b_key;
	compat_uptr_t	n_modulus;
};

static long trans_modexpo32(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct compat_ica_rsa_modexpo __user *umex32 = compat_ptr(arg);
	struct compat_ica_rsa_modexpo mex32;
	struct ica_rsa_modexpo mex64;
	long rc;

	if (copy_from_user(&mex32, umex32, sizeof(mex32)))
		return -EFAULT;
	mex64.inputdata = compat_ptr(mex32.inputdata);
	mex64.inputdatalength = mex32.inputdatalength;
	mex64.outputdata = compat_ptr(mex32.outputdata);
	mex64.outputdatalength = mex32.outputdatalength;
	mex64.b_key = compat_ptr(mex32.b_key);
	mex64.n_modulus = compat_ptr(mex32.n_modulus);
	do {
		rc = zcrypt_rsa_modexpo(&mex64);
	} while (rc == -EAGAIN);
	if (!rc)
		rc = put_user(mex64.outputdatalength,
			      &umex32->outputdatalength);
	return rc;
	/* on failure: retry once again after a requested rescan */
	if ((rc == -ENODEV) && (zcrypt_process_rescan()))
		do {
			rc = zcrypt_rsa_modexpo(&mex64);
		} while (rc == -EAGAIN);
	if (rc)
		return rc;
	return put_user(mex64.outputdatalength,
			&umex32->outputdatalength);
}

struct compat_ica_rsa_modexpo_crt {
	compat_uptr_t	inputdata;
	unsigned int	inputdatalength;
	compat_uptr_t	outputdata;
	unsigned int	outputdatalength;
	compat_uptr_t	bp_key;
	compat_uptr_t	bq_key;
	compat_uptr_t	np_prime;
	compat_uptr_t	nq_prime;
	compat_uptr_t	u_mult_inv;
};

static long trans_modexpo_crt32(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	struct compat_ica_rsa_modexpo_crt __user *ucrt32 = compat_ptr(arg);
	struct compat_ica_rsa_modexpo_crt crt32;
	struct ica_rsa_modexpo_crt crt64;
	long rc;

	if (copy_from_user(&crt32, ucrt32, sizeof(crt32)))
		return -EFAULT;
	crt64.inputdata = compat_ptr(crt32.inputdata);
	crt64.inputdatalength = crt32.inputdatalength;
	crt64.outputdata = compat_ptr(crt32.outputdata);
	crt64.outputdatalength = crt32.outputdatalength;
	crt64.bp_key = compat_ptr(crt32.bp_key);
	crt64.bq_key = compat_ptr(crt32.bq_key);
	crt64.np_prime = compat_ptr(crt32.np_prime);
	crt64.nq_prime = compat_ptr(crt32.nq_prime);
	crt64.u_mult_inv = compat_ptr(crt32.u_mult_inv);
	do {
		rc = zcrypt_rsa_crt(&crt64);
	} while (rc == -EAGAIN);
	if (!rc)
		rc = put_user(crt64.outputdatalength,
			      &ucrt32->outputdatalength);
	return rc;
	/* on failure: retry once again after a requested rescan */
	if ((rc == -ENODEV) && (zcrypt_process_rescan()))
		do {
			rc = zcrypt_rsa_crt(&crt64);
		} while (rc == -EAGAIN);
	if (rc)
		return rc;
	return put_user(crt64.outputdatalength,
			&ucrt32->outputdatalength);
}

struct compat_ica_xcRB {
	unsigned short	agent_ID;
	unsigned int	user_defined;
	unsigned short	request_ID;
	unsigned int	request_control_blk_length;
	unsigned char	padding1[16 - sizeof(compat_uptr_t)];
	compat_uptr_t	request_control_blk_addr;
	unsigned int	request_data_length;
	char		padding2[16 - sizeof(compat_uptr_t)];
	compat_uptr_t	request_data_address;
	unsigned int	reply_control_blk_length;
	char		padding3[16 - sizeof(compat_uptr_t)];
	compat_uptr_t	reply_control_blk_addr;
	unsigned int	reply_data_length;
	char		padding4[16 - sizeof(compat_uptr_t)];
	compat_uptr_t	reply_data_addr;
	unsigned short	priority_window;
	unsigned int	status;
} __packed;

static long trans_xcRB32(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	struct compat_ica_xcRB __user *uxcRB32 = compat_ptr(arg);
	struct compat_ica_xcRB xcRB32;
	struct ica_xcRB xcRB64;
	long rc;

	if (copy_from_user(&xcRB32, uxcRB32, sizeof(xcRB32)))
		return -EFAULT;
	xcRB64.agent_ID = xcRB32.agent_ID;
	xcRB64.user_defined = xcRB32.user_defined;
	xcRB64.request_ID = xcRB32.request_ID;
	xcRB64.request_control_blk_length =
		xcRB32.request_control_blk_length;
	xcRB64.request_control_blk_addr =
		compat_ptr(xcRB32.request_control_blk_addr);
	xcRB64.request_data_length =
		xcRB32.request_data_length;
	xcRB64.request_data_address =
		compat_ptr(xcRB32.request_data_address);
	xcRB64.reply_control_blk_length =
		xcRB32.reply_control_blk_length;
	xcRB64.reply_control_blk_addr =
		compat_ptr(xcRB32.reply_control_blk_addr);
	xcRB64.reply_data_length = xcRB32.reply_data_length;
	xcRB64.reply_data_addr =
		compat_ptr(xcRB32.reply_data_addr);
	xcRB64.priority_window = xcRB32.priority_window;
	xcRB64.status = xcRB32.status;
	do {
		rc = zcrypt_send_cprb(&xcRB64);
	} while (rc == -EAGAIN);
	/* on failure: retry once again after a requested rescan */
	if ((rc == -ENODEV) && (zcrypt_process_rescan()))
		do {
			rc = zcrypt_send_cprb(&xcRB64);
		} while (rc == -EAGAIN);
	xcRB32.reply_control_blk_length = xcRB64.reply_control_blk_length;
	xcRB32.reply_data_length = xcRB64.reply_data_length;
	xcRB32.status = xcRB64.status;
	if (copy_to_user(uxcRB32, &xcRB32, sizeof(xcRB32)))
		return -EFAULT;
	return rc;
}

static long zcrypt_compat_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	if (cmd == ICARSAMODEXPO)
		return trans_modexpo32(filp, cmd, arg);
	if (cmd == ICARSACRT)
		return trans_modexpo_crt32(filp, cmd, arg);
	if (cmd == ZSECSENDCPRB)
		return trans_xcRB32(filp, cmd, arg);
	return zcrypt_unlocked_ioctl(filp, cmd, arg);
}
#endif

/*
 * Misc device file operations.
 */
static const struct file_operations zcrypt_fops = {
	.owner		= THIS_MODULE,
	.read		= zcrypt_read,
	.write		= zcrypt_write,
	.unlocked_ioctl	= zcrypt_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= zcrypt_compat_ioctl,
#endif
	.open		= zcrypt_open,
	.release	= zcrypt_release
	.release	= zcrypt_release,
	.llseek		= no_llseek,
};

/*
 * Misc device.
 */
static struct miscdevice zcrypt_misc_device = {
	.minor	    = MISC_DYNAMIC_MINOR,
	.name	    = "z90crypt",
	.fops	    = &zcrypt_fops,
};

/*
 * Deprecated /proc entry support.
 */
static struct proc_dir_entry *zcrypt_entry;

static int sprintcl(unsigned char *outaddr, unsigned char *addr,
		    unsigned int len)
{
	int hl, i;

	hl = 0;
	for (i = 0; i < len; i++)
		hl += sprintf(outaddr+hl, "%01x", (unsigned int) addr[i]);
	hl += sprintf(outaddr+hl, " ");
	return hl;
}

static int sprintrw(unsigned char *outaddr, unsigned char *addr,
		    unsigned int len)
{
	int hl, inl, c, cx;

	hl = sprintf(outaddr, "	   ");
	inl = 0;
	for (c = 0; c < (len / 16); c++) {
		hl += sprintcl(outaddr+hl, addr+inl, 16);
static void sprintcl(struct seq_file *m, unsigned char *addr, unsigned int len)
{
	int i;

	for (i = 0; i < len; i++)
		seq_printf(m, "%01x", (unsigned int) addr[i]);
	seq_putc(m, ' ');
}

static void sprintrw(struct seq_file *m, unsigned char *addr, unsigned int len)
{
	int inl, c, cx;

	seq_printf(m, "	   ");
	inl = 0;
	for (c = 0; c < (len / 16); c++) {
		sprintcl(m, addr+inl, 16);
		inl += 16;
	}
	cx = len%16;
	if (cx) {
		hl += sprintcl(outaddr+hl, addr+inl, cx);
		inl += cx;
	}
	hl += sprintf(outaddr+hl, "\n");
	return hl;
}

static int sprinthx(unsigned char *title, unsigned char *outaddr,
		    unsigned char *addr, unsigned int len)
{
	int hl, inl, r, rx;

	hl = sprintf(outaddr, "\n%s\n", title);
	inl = 0;
	for (r = 0; r < (len / 64); r++) {
		hl += sprintrw(outaddr+hl, addr+inl, 64);
		sprintcl(m, addr+inl, cx);
		inl += cx;
	}
	seq_putc(m, '\n');
}

static void sprinthx(unsigned char *title, struct seq_file *m,
		     unsigned char *addr, unsigned int len)
{
	int inl, r, rx;

	seq_printf(m, "\n%s\n", title);
	inl = 0;
	for (r = 0; r < (len / 64); r++) {
		sprintrw(m, addr+inl, 64);
		inl += 64;
	}
	rx = len % 64;
	if (rx) {
		hl += sprintrw(outaddr+hl, addr+inl, rx);
		inl += rx;
	}
	hl += sprintf(outaddr+hl, "\n");
	return hl;
}

static int sprinthx4(unsigned char *title, unsigned char *outaddr,
		     unsigned int *array, unsigned int len)
{
	int hl, r;

	hl = sprintf(outaddr, "\n%s\n", title);
	for (r = 0; r < len; r++) {
		if ((r % 8) == 0)
			hl += sprintf(outaddr+hl, "    ");
		hl += sprintf(outaddr+hl, "%08X ", array[r]);
		if ((r % 8) == 7)
			hl += sprintf(outaddr+hl, "\n");
	}
	hl += sprintf(outaddr+hl, "\n");
	return hl;
}

static int zcrypt_status_read(char *resp_buff, char **start, off_t offset,
			      int count, int *eof, void *data)
{
	unsigned char *workarea;
	int len;

	len = 0;

	/* resp_buff is a page. Use the right half for a work area */
	workarea = resp_buff + 2000;
	len += sprintf(resp_buff + len, "\nzcrypt version: %d.%d.%d\n",
		ZCRYPT_VERSION, ZCRYPT_RELEASE, ZCRYPT_VARIANT);
	len += sprintf(resp_buff + len, "Cryptographic domain: %d\n",
		       ap_domain_index);
	len += sprintf(resp_buff + len, "Total device count: %d\n",
		       zcrypt_device_count);
	len += sprintf(resp_buff + len, "PCICA count: %d\n",
		       zcrypt_count_type(ZCRYPT_PCICA));
	len += sprintf(resp_buff + len, "PCICC count: %d\n",
		       zcrypt_count_type(ZCRYPT_PCICC));
	len += sprintf(resp_buff + len, "PCIXCC MCL2 count: %d\n",
		       zcrypt_count_type(ZCRYPT_PCIXCC_MCL2));
	len += sprintf(resp_buff + len, "PCIXCC MCL3 count: %d\n",
		       zcrypt_count_type(ZCRYPT_PCIXCC_MCL3));
	len += sprintf(resp_buff + len, "CEX2C count: %d\n",
		       zcrypt_count_type(ZCRYPT_CEX2C));
	len += sprintf(resp_buff + len, "CEX2A count: %d\n",
		       zcrypt_count_type(ZCRYPT_CEX2A));
	len += sprintf(resp_buff + len, "requestq count: %d\n",
		       zcrypt_requestq_count());
	len += sprintf(resp_buff + len, "pendingq count: %d\n",
		       zcrypt_pendingq_count());
	len += sprintf(resp_buff + len, "Total open handles: %d\n\n",
		       atomic_read(&zcrypt_open_count));
	zcrypt_status_mask(workarea);
	len += sprinthx("Online devices: 1=PCICA 2=PCICC 3=PCIXCC(MCL2) "
			"4=PCIXCC(MCL3) 5=CEX2C 6=CEX2A",
			resp_buff+len, workarea, AP_DEVICES);
	zcrypt_qdepth_mask(workarea);
	len += sprinthx("Waiting work element counts",
			resp_buff+len, workarea, AP_DEVICES);
	zcrypt_perdev_reqcnt((int *) workarea);
	len += sprinthx4("Per-device successfully completed request counts",
			 resp_buff+len,(unsigned int *) workarea, AP_DEVICES);
	*eof = 1;
	memset((void *) workarea, 0x00, AP_DEVICES * sizeof(unsigned int));
	return len;
		sprintrw(m, addr+inl, rx);
		inl += rx;
	}
	seq_putc(m, '\n');
}

static void sprinthx4(unsigned char *title, struct seq_file *m,
		      unsigned int *array, unsigned int len)
{
	seq_printf(m, "\n%s\n", title);
	seq_hex_dump(m, "    ", DUMP_PREFIX_NONE, 32, 4, array, len, false);
	seq_putc(m, '\n');
}

static int zcrypt_proc_show(struct seq_file *m, void *v)
{
	char workarea[sizeof(int) * AP_DEVICES];

	seq_printf(m, "\nzcrypt version: %d.%d.%d\n",
		   ZCRYPT_VERSION, ZCRYPT_RELEASE, ZCRYPT_VARIANT);
	seq_printf(m, "Cryptographic domain: %d\n", ap_domain_index);
	seq_printf(m, "Total device count: %d\n", zcrypt_device_count);
	seq_printf(m, "PCICA count: %d\n", zcrypt_count_type(ZCRYPT_PCICA));
	seq_printf(m, "PCICC count: %d\n", zcrypt_count_type(ZCRYPT_PCICC));
	seq_printf(m, "PCIXCC MCL2 count: %d\n",
		   zcrypt_count_type(ZCRYPT_PCIXCC_MCL2));
	seq_printf(m, "PCIXCC MCL3 count: %d\n",
		   zcrypt_count_type(ZCRYPT_PCIXCC_MCL3));
	seq_printf(m, "CEX2C count: %d\n", zcrypt_count_type(ZCRYPT_CEX2C));
	seq_printf(m, "CEX2A count: %d\n", zcrypt_count_type(ZCRYPT_CEX2A));
	seq_printf(m, "CEX3C count: %d\n", zcrypt_count_type(ZCRYPT_CEX3C));
	seq_printf(m, "CEX3A count: %d\n", zcrypt_count_type(ZCRYPT_CEX3A));
	seq_printf(m, "requestq count: %d\n", zcrypt_requestq_count());
	seq_printf(m, "pendingq count: %d\n", zcrypt_pendingq_count());
	seq_printf(m, "Total open handles: %d\n\n",
		   atomic_read(&zcrypt_open_count));
	zcrypt_status_mask(workarea);
	sprinthx("Online devices: 1=PCICA 2=PCICC 3=PCIXCC(MCL2) "
		 "4=PCIXCC(MCL3) 5=CEX2C 6=CEX2A 7=CEX3C 8=CEX3A",
		 m, workarea, AP_DEVICES);
	zcrypt_qdepth_mask(workarea);
	sprinthx("Waiting work element counts", m, workarea, AP_DEVICES);
	zcrypt_perdev_reqcnt((int *) workarea);
	sprinthx4("Per-device successfully completed request counts",
		  m, (unsigned int *) workarea, AP_DEVICES);
	return 0;
}

static int zcrypt_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, zcrypt_proc_show, NULL);
}

static void zcrypt_disable_card(int index)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;

	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index)
				continue;
			zq->online = 0;
			ap_flush_queue(zq->queue);
		}
	}
	spin_unlock(&zcrypt_list_lock);
}

static void zcrypt_enable_card(int index)
{
	struct zcrypt_card *zc;
	struct zcrypt_queue *zq;

	spin_lock(&zcrypt_list_lock);
	for_each_zcrypt_card(zc) {
		for_each_zcrypt_queue(zq, zc) {
			if (AP_QID_QUEUE(zq->queue->qid) != ap_domain_index)
				continue;
			zq->online = 1;
			ap_flush_queue(zq->queue);
		}
	}
	spin_unlock(&zcrypt_list_lock);
}

static int zcrypt_status_write(struct file *file, const char __user *buffer,
			       unsigned long count, void *data)
{
	unsigned char *lbuf, *ptr;
	unsigned long local_count;
static ssize_t zcrypt_proc_write(struct file *file, const char __user *buffer,
				 size_t count, loff_t *pos)
{
	unsigned char *lbuf, *ptr;
	size_t local_count;
	int j;

	if (count <= 0)
		return 0;

#define LBUFSIZE 1200UL
	lbuf = kmalloc(LBUFSIZE, GFP_KERNEL);
	if (!lbuf)
		return 0;

	local_count = min(LBUFSIZE - 1, count);
	if (copy_from_user(lbuf, buffer, local_count) != 0) {
		kfree(lbuf);
		return -EFAULT;
	}
	lbuf[local_count] = '\0';

	ptr = strstr(lbuf, "Online devices");
	if (!ptr)
		goto out;
	ptr = strstr(ptr, "\n");
	if (!ptr)
		goto out;
	ptr++;

	if (strstr(ptr, "Waiting work element counts") == NULL)
		goto out;

	for (j = 0; j < 64 && *ptr; ptr++) {
		/*
		 * '0' for no device, '1' for PCICA, '2' for PCICC,
		 * '3' for PCIXCC_MCL2, '4' for PCIXCC_MCL3,
		 * '5' for CEX2C and '6' for CEX2A'
		 */
		if (*ptr >= '0' && *ptr <= '6')
		 * '7' for CEX3C and '8' for CEX3A
		 */
		if (*ptr >= '0' && *ptr <= '8')
			j++;
		else if (*ptr == 'd' || *ptr == 'D')
			zcrypt_disable_card(j++);
		else if (*ptr == 'e' || *ptr == 'E')
			zcrypt_enable_card(j++);
		else if (*ptr != ' ' && *ptr != '\t')
			break;
	}
out:
	kfree(lbuf);
	return count;
}

static const struct file_operations zcrypt_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= zcrypt_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= zcrypt_proc_write,
};

static int zcrypt_rng_device_count;
static u32 *zcrypt_rng_buffer;
static int zcrypt_rng_buffer_index;
static DEFINE_MUTEX(zcrypt_rng_mutex);

static int zcrypt_rng_data_read(struct hwrng *rng, u32 *data)
{
	int rc;

	/*
	 * We don't need locking here because the RNG API guarantees serialized
	 * read method calls.
	 */
	if (zcrypt_rng_buffer_index == 0) {
		rc = zcrypt_rng((char *) zcrypt_rng_buffer);
		/* on failure: retry once again after a requested rescan */
		if ((rc == -ENODEV) && (zcrypt_process_rescan()))
			rc = zcrypt_rng((char *) zcrypt_rng_buffer);
		if (rc < 0)
			return -EIO;
		zcrypt_rng_buffer_index = rc / sizeof(*data);
	}
	*data = zcrypt_rng_buffer[--zcrypt_rng_buffer_index];
	return sizeof(*data);
}

static struct hwrng zcrypt_rng_dev = {
	.name		= "zcrypt",
	.data_read	= zcrypt_rng_data_read,
	.quality	= 990,
};

int zcrypt_rng_device_add(void)
{
	int rc = 0;

	mutex_lock(&zcrypt_rng_mutex);
	if (zcrypt_rng_device_count == 0) {
		zcrypt_rng_buffer = (u32 *) get_zeroed_page(GFP_KERNEL);
		if (!zcrypt_rng_buffer) {
			rc = -ENOMEM;
			goto out;
		}
		zcrypt_rng_buffer_index = 0;
		if (!zcrypt_hwrng_seed)
			zcrypt_rng_dev.quality = 0;
		rc = hwrng_register(&zcrypt_rng_dev);
		if (rc)
			goto out_free;
		zcrypt_rng_device_count = 1;
	} else
		zcrypt_rng_device_count++;
	mutex_unlock(&zcrypt_rng_mutex);
	return 0;

out_free:
	free_page((unsigned long) zcrypt_rng_buffer);
out:
	mutex_unlock(&zcrypt_rng_mutex);
	return rc;
}

void zcrypt_rng_device_remove(void)
{
	mutex_lock(&zcrypt_rng_mutex);
	zcrypt_rng_device_count--;
	if (zcrypt_rng_device_count == 0) {
		hwrng_unregister(&zcrypt_rng_dev);
		free_page((unsigned long) zcrypt_rng_buffer);
	}
	mutex_unlock(&zcrypt_rng_mutex);
}

int __init zcrypt_debug_init(void)
{
	zcrypt_dbf_info = debug_register("zcrypt", 1, 1,
					 DBF_MAX_SPRINTF_ARGS * sizeof(long));
	debug_register_view(zcrypt_dbf_info, &debug_sprintf_view);
	debug_set_level(zcrypt_dbf_info, DBF_ERR);

	return 0;
}

void zcrypt_debug_exit(void)
{
	debug_unregister(zcrypt_dbf_info);
}

/**
 * zcrypt_api_init(): Module initialization.
 *
 * The module initialization code.
 */
int __init zcrypt_api_init(void)
{
	int rc;

	rc = zcrypt_debug_init();
	if (rc)
		goto out;

	/* Register the request sprayer. */
	rc = misc_register(&zcrypt_misc_device);
	if (rc < 0)
		goto out;

	/* Set up the proc file system */
	zcrypt_entry = create_proc_entry("driver/z90crypt", 0644, NULL);
	zcrypt_entry = proc_create("driver/z90crypt", 0644, NULL, &zcrypt_proc_fops);
	zcrypt_entry = proc_create("driver/z90crypt", 0644, NULL,
				   &zcrypt_proc_fops);
	if (!zcrypt_entry) {
		rc = -ENOMEM;
		goto out_misc;
	}
	zcrypt_entry->data = NULL;
	zcrypt_entry->read_proc = zcrypt_status_read;
	zcrypt_entry->write_proc = zcrypt_status_write;

	zcrypt_msgtype6_init();
	zcrypt_msgtype50_init();
	return 0;

out:
	return rc;
}

/**
 * zcrypt_api_exit(): Module termination.
 *
 * The module termination code.
 */
void __exit zcrypt_api_exit(void)
{
	misc_deregister(&zcrypt_misc_device);
}

#ifndef CONFIG_ZCRYPT_MONOLITHIC
module_init(zcrypt_api_init);
module_exit(zcrypt_api_exit);
#endif
	zcrypt_msgtype6_exit();
	zcrypt_msgtype50_exit();
	zcrypt_debug_exit();
}

module_init(zcrypt_api_init);
module_exit(zcrypt_api_exit);
