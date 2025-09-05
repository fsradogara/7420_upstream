// SPDX-License-Identifier: GPL-2.0+
/*
 * linux/drivers/s390/crypto/ap_bus.c
 *
 * Copyright (C) 2006 IBM Corporation
 * Author(s): Cornelia Huck <cornelia.huck@de.ibm.com>
 *	      Martin Schwidefsky <schwidefsky@de.ibm.com>
 *	      Ralph Wuerthner <rwuerthn@de.ibm.com>
 * Copyright IBM Corp. 2006, 2012
 * Author(s): Cornelia Huck <cornelia.huck@de.ibm.com>
 *	      Martin Schwidefsky <schwidefsky@de.ibm.com>
 *	      Ralph Wuerthner <rwuerthn@de.ibm.com>
 *	      Felix Beck <felix.beck@de.ibm.com>
 *	      Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Adjunct processor bus.
 */

#define KMSG_COMPONENT "ap"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel_stat.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <asm/s390_rdev.h>
#include <asm/reset.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>

#include "ap_bus.h"

/* Some prototypes. */
static void ap_scan_bus(struct work_struct *);
static void ap_poll_all(unsigned long);
static enum hrtimer_restart ap_poll_timeout(struct hrtimer *);
static int ap_poll_thread_start(void);
static void ap_poll_thread_stop(void);
static void ap_request_timeout(unsigned long);

#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/suspend.h>
#include <asm/airq.h>
#include <linux/atomic.h>
#include <asm/isc.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <asm/facility.h>
#include <linux/crypto.h>
#include <linux/mod_devicetable.h>
#include <linux/debugfs.h>
#include <linux/ctype.h>

#include "ap_bus.h"
#include "ap_debug.h"

/*
 * Module description.
 */
MODULE_AUTHOR("IBM Corporation");
MODULE_DESCRIPTION("Adjunct Processor Bus driver, "
		   "Copyright 2006 IBM Corporation");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Adjunct Processor Bus driver, " \
		   "Copyright IBM Corp. 2006, 2012");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("z90crypt");

/*
 * Module parameter
 */
int ap_domain_index = -1;	/* Adjunct Processor Domain Index */
module_param_named(domain, ap_domain_index, int, 0000);
 * Module parameters; note though this file itself isn't modular.
 */
int ap_domain_index = -1;	/* Adjunct Processor Domain Index */
static DEFINE_SPINLOCK(ap_domain_lock);
module_param_named(domain, ap_domain_index, int, 0440);
MODULE_PARM_DESC(domain, "domain index for ap devices");
EXPORT_SYMBOL(ap_domain_index);

static int ap_thread_flag = 0;
module_param_named(poll_thread, ap_thread_flag, int, 0000);
MODULE_PARM_DESC(poll_thread, "Turn on/off poll thread, default is 0 (off).");

static struct device *ap_root_device = NULL;
static DEFINE_SPINLOCK(ap_device_lock);
static LIST_HEAD(ap_device_list);

/*
 * Workqueue & timer for bus rescan.
 */
static struct workqueue_struct *ap_work_queue;
static struct timer_list ap_config_timer;
static int ap_config_time = AP_CONFIG_TIME;
static DECLARE_WORK(ap_config_work, ap_scan_bus);

/*
 * Tasklet & timer for AP request polling.
 */
static DECLARE_TASKLET(ap_tasklet, ap_poll_all, 0);
module_param_named(poll_thread, ap_thread_flag, int, S_IRUSR|S_IRGRP);
static int ap_thread_flag;
module_param_named(poll_thread, ap_thread_flag, int, 0440);
MODULE_PARM_DESC(poll_thread, "Turn on/off poll thread, default is 0 (off).");

static char *apm_str;
module_param_named(apmask, apm_str, charp, 0440);
MODULE_PARM_DESC(apmask, "AP bus adapter mask.");

static char *aqm_str;
module_param_named(aqmask, aqm_str, charp, 0440);
MODULE_PARM_DESC(aqmask, "AP bus domain mask.");

static struct device *ap_root_device;

DEFINE_SPINLOCK(ap_list_lock);
LIST_HEAD(ap_card_list);

/* Default permissions (card and domain masking) */
static struct ap_perms {
	DECLARE_BITMAP(apm, AP_DEVICES);
	DECLARE_BITMAP(aqm, AP_DOMAINS);
} ap_perms;
static DEFINE_MUTEX(ap_perms_mutex);

static struct ap_config_info *ap_configuration;
static bool initialised;

/*
 * AP bus related debug feature things.
 */
debug_info_t *ap_dbf_info;

/*
 * Workqueue timer for bus rescan.
 */
static struct timer_list ap_config_timer;
static int ap_config_time = AP_CONFIG_TIME;
static void ap_scan_bus(struct work_struct *);
static DECLARE_WORK(ap_scan_work, ap_scan_bus);

/*
 * Tasklet & timer for AP request polling and interrupts
 */
static void ap_tasklet_fn(unsigned long);
static DECLARE_TASKLET(ap_tasklet, ap_tasklet_fn, 0);
static DECLARE_WAIT_QUEUE_HEAD(ap_poll_wait);
static struct task_struct *ap_poll_kthread;
static DEFINE_MUTEX(ap_poll_thread_mutex);
static DEFINE_SPINLOCK(ap_poll_timer_lock);
static struct hrtimer ap_poll_timer;
/*
 * In LPAR poll with 4kHz frequency. Poll every 250000 nanoseconds.
 * If z/VM change to 1500000 nanoseconds to adjust to z/VM polling.
 */
static unsigned long long poll_timeout = 250000;

/* Suspend flag */
static int ap_suspend_flag;
/* Maximum domain id */
static int ap_max_domain_id;
/*
 * Flag to check if domain was set through module parameter domain=. This is
 * important when supsend and resume is done in a z/VM environment where the
 * domain might change.
 */
static int user_set_domain;
static struct bus_type ap_bus_type;

/* Adapter interrupt definitions */
static void ap_interrupt_handler(struct airq_struct *airq);

static int ap_airq_flag;

static struct airq_struct ap_airq = {
	.handler = ap_interrupt_handler,
	.isc = AP_ISC,
};

/**
 * ap_using_interrupts() - Returns non-zero if interrupt support is
 * available.
 */
static inline int ap_using_interrupts(void)
{
	return ap_airq_flag;
}

/**
 * ap_airq_ptr() - Get the address of the adapter interrupt indicator
 *
 * Returns the address of the local-summary-indicator of the adapter
 * interrupt handler for AP, or NULL if adapter interrupts are not
 * available.
 */
void *ap_airq_ptr(void)
{
	if (ap_using_interrupts())
		return ap_airq.lsi_ptr;
	return NULL;
}

/**
 * ap_test_queue(): Test adjunct processor queue.
 * @qid: The AP queue number
 * @queue_depth: Pointer to queue depth value
 * @device_type: Pointer to device type value
 * ap_interrupts_available(): Test if AP interrupts are available.
 *
 * Returns 1 if AP interrupts are available.
 */
static int ap_interrupts_available(void)
{
	return test_facility(65);
}

/**
 * ap_configuration_available(): Test if AP configuration
 * information is available.
 *
 * Returns 1 if AP configuration information is available.
 */
static int ap_configuration_available(void)
{
	return test_facility(12);
}

/**
 * ap_apft_available(): Test if AP facilities test (APFT)
 * facility is available.
 *
 * Returns 1 if APFT is is available.
 */
static int ap_apft_available(void)
{
	return test_facility(15);
}

/*
 * ap_qact_available(): Test if the PQAP(QACT) subfunction is available.
 *
 * Returns 1 if the QACT subfunction is available.
 */
static inline struct ap_queue_status
ap_test_queue(ap_qid_t qid, int *queue_depth, int *device_type)
ap_test_queue(ap_qid_t qid, unsigned long *info)
{
	register unsigned long reg0 asm ("0") = qid;
	register struct ap_queue_status reg1 asm ("1");
	register unsigned long reg2 asm ("2") = 0UL;

	asm volatile(".long 0xb2af0000"		/* PQAP(TAPQ) */
		     : "+d" (reg0), "=d" (reg1), "+d" (reg2) : : "cc");
	*device_type = (int) (reg2 >> 24);
	*queue_depth = (int) (reg2 & 0xff);
	if (test_facility(15))
		reg0 |= 1UL << 23;		/* set APFT T bit*/
	asm volatile(".long 0xb2af0000"		/* PQAP(TAPQ) */
		     : "+d" (reg0), "=d" (reg1), "+d" (reg2) : : "cc");
	if (info)
		*info = reg2;
	return reg1;
struct ap_queue_status ap_test_queue(ap_qid_t qid,
				     int tbit,
				     unsigned long *info)
static inline int ap_qact_available(void)
{
	if (ap_configuration)
		return ap_configuration->qact;
	return 0;
}

/*
 * ap_query_configuration(): Fetch cryptographic config info
 *
 * Returns the ap configuration info fetched via PQAP(QCI).
 * On success 0 is returned, on failure a negative errno
 * is returned, e.g. if the PQAP(QCI) instruction is not
 * available, the return value will be -EOPNOTSUPP.
 */
static inline int ap_query_configuration(struct ap_config_info *info)
{
	if (!ap_configuration_available())
		return -EOPNOTSUPP;
	if (!info)
		return -EINVAL;
	return ap_qci(info);
}
EXPORT_SYMBOL(ap_query_configuration);

/**
 * ap_init_configuration(): Allocate and query configuration array.
 */
static void ap_init_configuration(void)
{
	if (!ap_configuration_available())
		return;

	ap_configuration = kzalloc(sizeof(*ap_configuration), GFP_KERNEL);
	if (!ap_configuration)
		return;
	if (ap_query_configuration(ap_configuration) != 0) {
		kfree(ap_configuration);
		ap_configuration = NULL;
		return;
	}
}

/*
 * ap_test_config(): helper function to extract the nrth bit
 *		     within the unsigned int array field.
 */
static inline int ap_test_config(unsigned int *field, unsigned int nr)
{
	return ap_test_bit((field + (nr >> 5)), (nr & 0x1f));
}

/*
 * ap_test_config_card_id(): Test, whether an AP card ID is configured.
 * @id AP card ID
 *
 * Returns 0 if the card is not configured
 *	   1 if the card is configured or
 *	     if the configuration information is not available
 */
static inline int ap_test_config_card_id(unsigned int id)
{
	if (!ap_configuration)	/* QCI not supported */
		return 1;
	return ap_test_config(ap_configuration->apm, id);
}

/*
 * ap_test_config_domain(): Test, whether an AP usage domain is configured.
 * @domain AP usage domain ID
 *
 * Returns 0 if the usage domain is not configured
 *	   1 if the usage domain is configured or
 *	     if the configuration information is not available
 */
static inline int ap_test_config_domain(unsigned int domain)
{
	if (!ap_configuration)	/* QCI not supported */
		return domain < 16;
	return ap_test_config(ap_configuration->aqm, domain);
}

/**
 * ap_queue_enable_interruption(): Enable interruption on an AP.
 * @qid: The AP queue number
 * @ind: the notification indicator byte
 *
 * Enables interruption on AP queue via ap_queue_interruption_control(). Based
 * on the return value it waits a while and tests the AP queue if interrupts
 * have been switched on using ap_test_queue().
 */
static int ap_queue_enable_interruption(struct ap_device *ap_dev, void *ind)
{
	struct ap_queue_status status;

	status = ap_queue_interruption_control(ap_dev->qid, ind);
	switch (status.response_code) {
	case AP_RESPONSE_NORMAL:
	case AP_RESPONSE_OTHERWISE_CHANGED:
		return 0;
	case AP_RESPONSE_Q_NOT_AVAIL:
	case AP_RESPONSE_DECONFIGURED:
	case AP_RESPONSE_CHECKSTOPPED:
	case AP_RESPONSE_INVALID_ADDRESS:
		pr_err("Registering adapter interrupts for AP %d failed\n",
		       AP_QID_DEVICE(ap_dev->qid));
		return -EOPNOTSUPP;
	case AP_RESPONSE_RESET_IN_PROGRESS:
	case AP_RESPONSE_BUSY:
	default:
		return -EBUSY;
	}
}

/**
 * __ap_send(): Send message to adjunct processor queue.
 * @qid: The AP queue number
 * @psmid: The program supplied message identifier
 * @msg: The message text
 * @length: The message length
 * @special: Special Bit
 *
 * Returns AP queue status structure.
 * Condition code 1 on NQAP can't happen because the L bit is 1.
 * Condition code 2 on NQAP also means the send is incomplete,
 * because a segment boundary was reached. The NQAP is repeated.
 */
static inline struct ap_queue_status
__ap_send(ap_qid_t qid, unsigned long long psmid, void *msg, size_t length)
__ap_send(ap_qid_t qid, unsigned long long psmid, void *msg, size_t length,
	  unsigned int special)
{
	typedef struct { char _[length]; } msgblock;
	register unsigned long reg0 asm ("0") = qid | 0x40000000UL;
	register struct ap_queue_status reg1 asm ("1");
	register unsigned long reg2 asm ("2") = (unsigned long) msg;
	register unsigned long reg3 asm ("3") = (unsigned long) length;
	register unsigned long reg4 asm ("4") = (unsigned int) (psmid >> 32);
	register unsigned long reg5 asm ("5") = (unsigned int) psmid;

	asm volatile (
		"0: .long 0xb2ad0042\n"		/* DQAP */
	register unsigned long reg5 asm ("5") = psmid & 0xffffffff;

	if (special == 1)
		reg0 |= 0x400000UL;

	asm volatile (
		"0: .long 0xb2ad0042\n"		/* NQAP */
		"   brc   2,0b"
		: "+d" (reg0), "=d" (reg1), "+d" (reg2), "+d" (reg3)
		: "d" (reg4), "d" (reg5), "m" (*(msgblock *) msg)
		: "cc" );
	return reg1;
}

int ap_send(ap_qid_t qid, unsigned long long psmid, void *msg, size_t length)
{
	struct ap_queue_status status;

	status = __ap_send(qid, psmid, msg, length);
	status = __ap_send(qid, psmid, msg, length, 0);
	switch (status.response_code) {
	case AP_RESPONSE_NORMAL:
		return 0;
	case AP_RESPONSE_Q_FULL:
	case AP_RESPONSE_RESET_IN_PROGRESS:
		return -EBUSY;
	case AP_RESPONSE_REQ_FAC_NOT_INST:
		return -EINVAL;
	default:	/* Device is gone. */
		return -ENODEV;
	}
}
EXPORT_SYMBOL(ap_send);

/**
 * __ap_recv(): Receive message from adjunct processor queue.
 * @qid: The AP queue number
 * @psmid: Pointer to program supplied message identifier
 * @msg: The message text
 * @length: The message length
 *
 * Returns AP queue status structure.
 * Condition code 1 on DQAP means the receive has taken place
 * but only partially.	The response is incomplete, hence the
 * DQAP is repeated.
 * Condition code 2 on DQAP also means the receive is incomplete,
 * this time because a segment boundary was reached. Again, the
 * DQAP is repeated.
 * Note that gpr2 is used by the DQAP instruction to keep track of
 * any 'residual' length, in case the instruction gets interrupted.
 * Hence it gets zeroed before the instruction.
 */
static inline struct ap_queue_status
__ap_recv(ap_qid_t qid, unsigned long long *psmid, void *msg, size_t length)
{
	typedef struct { char _[length]; } msgblock;
	register unsigned long reg0 asm("0") = qid | 0x80000000UL;
	register struct ap_queue_status reg1 asm ("1");
	register unsigned long reg2 asm("2") = 0UL;
	register unsigned long reg4 asm("4") = (unsigned long) msg;
	register unsigned long reg5 asm("5") = (unsigned long) length;
	register unsigned long reg6 asm("6") = 0UL;
	register unsigned long reg7 asm("7") = 0UL;


	asm volatile(
		"0: .long 0xb2ae0064\n"
		"0: .long 0xb2ae0064\n"		/* DQAP */
		"   brc   6,0b\n"
		: "+d" (reg0), "=d" (reg1), "+d" (reg2),
		"+d" (reg4), "+d" (reg5), "+d" (reg6), "+d" (reg7),
		"=m" (*(msgblock *) msg) : : "cc" );
	*psmid = (((unsigned long long) reg6) << 32) + reg7;
	return reg1;
}

int ap_recv(ap_qid_t qid, unsigned long long *psmid, void *msg, size_t length)
{
	struct ap_queue_status status;

	status = __ap_recv(qid, psmid, msg, length);
	switch (status.response_code) {
	case AP_RESPONSE_NORMAL:
		return 0;
	case AP_RESPONSE_NO_PENDING_REPLY:
		if (status.queue_empty)
			return -ENOENT;
		return -EBUSY;
	case AP_RESPONSE_RESET_IN_PROGRESS:
		return -EBUSY;
	default:
		return -ENODEV;
	}
}
EXPORT_SYMBOL(ap_recv);

/**
 * ap_query_queue(): Check if an AP queue is available.
 * @qid: The AP queue number
 * @queue_depth: Pointer to queue depth value
 * @device_type: Pointer to device type value
 *
 * The test is repeated for AP_MAX_RESET times.
 */
static int ap_query_queue(ap_qid_t qid, int *queue_depth, int *device_type)
{
	struct ap_queue_status status;
	int t_depth, t_device_type, rc, i;

	rc = -EBUSY;
	for (i = 0; i < AP_MAX_RESET; i++) {
		status = ap_test_queue(qid, &t_depth, &t_device_type);
		switch (status.response_code) {
		case AP_RESPONSE_NORMAL:
			*queue_depth = t_depth + 1;
			*device_type = t_device_type;
			rc = 0;
			break;
		case AP_RESPONSE_Q_NOT_AVAIL:
			rc = -ENODEV;
			break;
		case AP_RESPONSE_RESET_IN_PROGRESS:
			break;
		case AP_RESPONSE_DECONFIGURED:
			rc = -ENODEV;
			break;
		case AP_RESPONSE_CHECKSTOPPED:
			rc = -ENODEV;
			break;
		case AP_RESPONSE_BUSY:
			break;
		default:
			BUG();
		}
		if (rc != -EBUSY)
			break;
		if (i < AP_MAX_RESET - 1)
			udelay(5);
	}
	return rc;
}

/**
 * ap_init_queue(): Reset an AP queue.
 * @qid: The AP queue number
 *
 * Reset an AP queue and wait for it to become available again.
 */
static int ap_init_queue(ap_qid_t qid)
{
	struct ap_queue_status status;
	int rc, dummy, i;

	rc = -ENODEV;
	status = ap_reset_queue(qid);
	for (i = 0; i < AP_MAX_RESET; i++) {
		switch (status.response_code) {
		case AP_RESPONSE_NORMAL:
			if (status.queue_empty)
				rc = 0;
			break;
		case AP_RESPONSE_Q_NOT_AVAIL:
		case AP_RESPONSE_DECONFIGURED:
		case AP_RESPONSE_CHECKSTOPPED:
			i = AP_MAX_RESET;	/* return with -ENODEV */
			break;
		case AP_RESPONSE_RESET_IN_PROGRESS:
			rc = -EBUSY;
		case AP_RESPONSE_BUSY:
		default:
			break;
		}
		if (rc != -ENODEV && rc != -EBUSY)
			break;
		if (i < AP_MAX_RESET - 1) {
			udelay(5);
			status = ap_test_queue(qid, &dummy, &dummy);
		}
	}
	return rc;
}

/**
 * ap_increase_queue_count(): Arm request timeout.
 * @ap_dev: Pointer to an AP device.
 *
 * Arm request timeout if an AP device was idle and a new request is submitted.
 */
static void ap_increase_queue_count(struct ap_device *ap_dev)
{
	int timeout = ap_dev->drv->request_timeout;

	ap_dev->queue_count++;
	if (ap_dev->queue_count == 1) {
		mod_timer(&ap_dev->timeout, jiffies + timeout);
		ap_dev->reset = AP_RESET_ARMED;
	}
}

/**
 * ap_decrease_queue_count(): Decrease queue count.
 * @ap_dev: Pointer to an AP device.
 *
 * If AP device is still alive, re-schedule request timeout if there are still
 * pending requests.
 */
static void ap_decrease_queue_count(struct ap_device *ap_dev)
{
	int timeout = ap_dev->drv->request_timeout;

	ap_dev->queue_count--;
	if (ap_dev->queue_count > 0)
		mod_timer(&ap_dev->timeout, jiffies + timeout);
	else
		/*
		 * The timeout timer should to be disabled now - since
		 * del_timer_sync() is very expensive, we just tell via the
		 * reset flag to ignore the pending timeout timer.
		 */
		ap_dev->reset = AP_RESET_IGNORE;
}
 * @facilities: Pointer to facility indicator
 */
static int ap_query_queue(ap_qid_t qid, int *queue_depth, int *device_type,
			  unsigned int *facilities)
{
	struct ap_queue_status status;
	unsigned long info;
	int nd;

	if (!ap_test_config_card_id(AP_QID_CARD(qid)))
		return -ENODEV;

	status = ap_test_queue(qid, ap_apft_available(), &info);
	switch (status.response_code) {
	case AP_RESPONSE_NORMAL:
		*queue_depth = (int)(info & 0xff);
		*device_type = (int)((info >> 24) & 0xff);
		*facilities = (unsigned int)(info >> 32);
		/* Update maximum domain id */
		nd = (info >> 16) & 0xff;
		/* if N bit is available, z13 and newer */
		if ((info & (1UL << 57)) && nd > 0)
			ap_max_domain_id = nd;
		else /* older machine types */
			ap_max_domain_id = 15;
		switch (*device_type) {
			/* For CEX2 and CEX3 the available functions
			 * are not refrected by the facilities bits.
			 * Instead it is coded into the type. So here
			 * modify the function bits based on the type.
			 */
		case AP_DEVICE_TYPE_CEX2A:
		case AP_DEVICE_TYPE_CEX3A:
			*facilities |= 0x08000000;
			break;
		case AP_DEVICE_TYPE_CEX2C:
		case AP_DEVICE_TYPE_CEX3C:
			*facilities |= 0x10000000;
			break;
		default:
			break;
		}
		return 0;
	case AP_RESPONSE_Q_NOT_AVAIL:
	case AP_RESPONSE_DECONFIGURED:
	case AP_RESPONSE_CHECKSTOPPED:
	case AP_RESPONSE_INVALID_ADDRESS:
		return -ENODEV;
	case AP_RESPONSE_RESET_IN_PROGRESS:
	case AP_RESPONSE_OTHERWISE_CHANGED:
	case AP_RESPONSE_BUSY:
		return -EBUSY;
	default:
		BUG();
	}
}

void ap_wait(enum ap_wait wait)
{
	ktime_t hr_time;

	switch (wait) {
	case AP_WAIT_AGAIN:
	case AP_WAIT_INTERRUPT:
		if (ap_using_interrupts())
			break;
		if (ap_poll_kthread) {
			wake_up(&ap_poll_wait);
			break;
		}
		/* Fall through */
	case AP_WAIT_TIMEOUT:
		spin_lock_bh(&ap_poll_timer_lock);
		if (!hrtimer_is_queued(&ap_poll_timer)) {
			hr_time = poll_timeout;
			hrtimer_forward_now(&ap_poll_timer, hr_time);
			hrtimer_restart(&ap_poll_timer);
		}
		spin_unlock_bh(&ap_poll_timer_lock);
		break;
	case AP_WAIT_NONE:
	default:
		break;
	}
}

/**
 * ap_request_timeout(): Handling of request timeouts
 * @t: timer making this callback
 *
 * Handles request timeouts.
 */
void ap_request_timeout(struct timer_list *t)
{
	struct ap_queue *aq = from_timer(aq, t, timeout);

	if (ap_suspend_flag)
		return;
	spin_lock_bh(&aq->lock);
	ap_wait(ap_sm_event(aq, AP_EVENT_TIMEOUT));
	spin_unlock_bh(&aq->lock);
}

/**
 * ap_poll_timeout(): AP receive polling for finished AP requests.
 * @unused: Unused pointer.
 *
 * Schedules the AP tasklet using a high resolution timer.
 */
static enum hrtimer_restart ap_poll_timeout(struct hrtimer *unused)
{
	if (!ap_suspend_flag)
		tasklet_schedule(&ap_tasklet);
	return HRTIMER_NORESTART;
}

/**
 * ap_interrupt_handler() - Schedule ap_tasklet on interrupt
 * @airq: pointer to adapter interrupt descriptor
 */
static void ap_interrupt_handler(struct airq_struct *airq)
{
	inc_irq_stat(IRQIO_APB);
	if (!ap_suspend_flag)
		tasklet_schedule(&ap_tasklet);
}

/**
 * ap_tasklet_fn(): Tasklet to poll all AP devices.
 * @dummy: Unused variable
 *
 * Poll all AP devices on the bus.
 */
static void ap_tasklet_fn(unsigned long dummy)
{
	struct ap_card *ac;
	struct ap_queue *aq;
	enum ap_wait wait = AP_WAIT_NONE;

	/* Reset the indicator if interrupts are used. Thus new interrupts can
	 * be received. Doing it in the beginning of the tasklet is therefor
	 * important that no requests on any AP get lost.
	 */
	if (ap_using_interrupts())
		xchg(ap_airq.lsi_ptr, 0);

	spin_lock_bh(&ap_list_lock);
	for_each_ap_card(ac) {
		for_each_ap_queue(aq, ac) {
			spin_lock_bh(&aq->lock);
			wait = min(wait, ap_sm_event_loop(aq, AP_EVENT_POLL));
			spin_unlock_bh(&aq->lock);
		}
	}
	spin_unlock_bh(&ap_list_lock);

	ap_wait(wait);
}

static int ap_pending_requests(void)
{
	struct ap_card *ac;
	struct ap_queue *aq;

	spin_lock_bh(&ap_list_lock);
	for_each_ap_card(ac) {
		for_each_ap_queue(aq, ac) {
			if (aq->queue_count == 0)
				continue;
			spin_unlock_bh(&ap_list_lock);
			return 1;
		}
	}
	spin_unlock_bh(&ap_list_lock);
	return 0;
}

/**
 * ap_poll_thread(): Thread that polls for finished requests.
 * @data: Unused pointer
 *
 * AP bus poll thread. The purpose of this thread is to poll for
 * finished requests in a loop if there is a "free" cpu - that is
 * a cpu that doesn't have anything better to do. The polling stops
 * as soon as there is another task or if all messages have been
 * delivered.
 */
static int ap_poll_thread(void *data)
{
	DECLARE_WAITQUEUE(wait, current);

	set_user_nice(current, MAX_NICE);
	set_freezable();
	while (!kthread_should_stop()) {
		add_wait_queue(&ap_poll_wait, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		if (ap_suspend_flag || !ap_pending_requests()) {
			schedule();
			try_to_freeze();
		}
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&ap_poll_wait, &wait);
		if (need_resched()) {
			schedule();
			try_to_freeze();
			continue;
		}
		ap_tasklet_fn(0);
	}

	return 0;
}

static int ap_poll_thread_start(void)
{
	int rc;

	if (ap_using_interrupts() || ap_poll_kthread)
		return 0;
	mutex_lock(&ap_poll_thread_mutex);
	ap_poll_kthread = kthread_run(ap_poll_thread, NULL, "appoll");
	rc = PTR_ERR_OR_ZERO(ap_poll_kthread);
	if (rc)
		ap_poll_kthread = NULL;
	mutex_unlock(&ap_poll_thread_mutex);
	return rc;
}

static void ap_poll_thread_stop(void)
{
	if (!ap_poll_kthread)
		return;
	mutex_lock(&ap_poll_thread_mutex);
	kthread_stop(ap_poll_kthread);
	ap_poll_kthread = NULL;
	mutex_unlock(&ap_poll_thread_mutex);
}

/**
 * ap_queue_message(): Queue a request to an AP device.
 * @ap_dev: The AP device to queue the message to
 * @ap_msg: The message that is to be added
 */
void ap_queue_message(struct ap_device *ap_dev, struct ap_message *ap_msg)
{
	/* For asynchronous message handling a valid receive-callback
	 * is required. */
	BUG_ON(!ap_msg->receive);

	spin_lock_bh(&ap_dev->lock);
	/* Queue the message. */
	list_add_tail(&ap_msg->list, &ap_dev->requestq);
	ap_dev->requestq_count++;
	ap_dev->total_request_count++;
	/* Send/receive as many request from the queue as possible. */
	ap_sm_wait(ap_sm_event_loop(ap_dev, AP_EVENT_POLL));
	spin_unlock_bh(&ap_dev->lock);
}
EXPORT_SYMBOL(ap_queue_message);

/**
 * ap_cancel_message(): Cancel a crypto request.
 * @ap_dev: The AP device that has the message queued
 * @ap_msg: The message that is to be removed
 *
 * Cancel a crypto request. This is done by removing the request
 * from the device pending or request queue. Note that the
 * request stays on the AP queue. When it finishes the message
 * reply will be discarded because the psmid can't be found.
 */
void ap_cancel_message(struct ap_device *ap_dev, struct ap_message *ap_msg)
{
	struct ap_message *tmp;

	spin_lock_bh(&ap_dev->lock);
	if (!list_empty(&ap_msg->list)) {
		list_for_each_entry(tmp, &ap_dev->pendingq, list)
			if (tmp->psmid == ap_msg->psmid) {
				ap_dev->pendingq_count--;
				goto found;
			}
		ap_dev->requestq_count--;
found:
		list_del_init(&ap_msg->list);
	}
	spin_unlock_bh(&ap_dev->lock);
}
EXPORT_SYMBOL(ap_cancel_message);

/*
 * AP device related attributes.
 */
static ssize_t ap_hwtype_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	return snprintf(buf, PAGE_SIZE, "%d\n", ap_dev->device_type);
}
static DEVICE_ATTR(hwtype, 0444, ap_hwtype_show, NULL);


static DEVICE_ATTR(hwtype, 0444, ap_hwtype_show, NULL);

static ssize_t ap_raw_hwtype_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", ap_dev->raw_hwtype);
}

static DEVICE_ATTR(raw_hwtype, 0444, ap_raw_hwtype_show, NULL);

static ssize_t ap_depth_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	return snprintf(buf, PAGE_SIZE, "%d\n", ap_dev->queue_depth);
}
static DEVICE_ATTR(depth, 0444, ap_depth_show, NULL);


static DEVICE_ATTR(depth, 0444, ap_depth_show, NULL);
static ssize_t ap_request_count_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	int rc;

	spin_lock_bh(&ap_dev->lock);
	rc = snprintf(buf, PAGE_SIZE, "%d\n", ap_dev->total_request_count);
	spin_unlock_bh(&ap_dev->lock);
	return rc;
}

static DEVICE_ATTR(request_count, 0444, ap_request_count_show, NULL);

static ssize_t ap_modalias_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "ap:t%02X", to_ap_dev(dev)->device_type);
static ssize_t ap_requestq_count_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	int rc;

	spin_lock_bh(&ap_dev->lock);
	rc = snprintf(buf, PAGE_SIZE, "%d\n", ap_dev->requestq_count);
	spin_unlock_bh(&ap_dev->lock);
	return rc;
}

static DEVICE_ATTR(requestq_count, 0444, ap_requestq_count_show, NULL);

static ssize_t ap_pendingq_count_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	int rc;

	spin_lock_bh(&ap_dev->lock);
	rc = snprintf(buf, PAGE_SIZE, "%d\n", ap_dev->pendingq_count);
	spin_unlock_bh(&ap_dev->lock);
	return rc;
}

static DEVICE_ATTR(pendingq_count, 0444, ap_pendingq_count_show, NULL);

static ssize_t ap_reset_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	int rc = 0;

	spin_lock_bh(&ap_dev->lock);
	switch (ap_dev->state) {
	case AP_STATE_RESET_START:
	case AP_STATE_RESET_WAIT:
		rc = snprintf(buf, PAGE_SIZE, "Reset in progress.\n");
		break;
	case AP_STATE_WORKING:
	case AP_STATE_QUEUE_FULL:
		rc = snprintf(buf, PAGE_SIZE, "Reset Timer armed.\n");
		break;
	default:
		rc = snprintf(buf, PAGE_SIZE, "No Reset Timer set.\n");
	}
	spin_unlock_bh(&ap_dev->lock);
	return rc;
}

static DEVICE_ATTR(reset, 0444, ap_reset_show, NULL);

static ssize_t ap_interrupt_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	int rc = 0;

	spin_lock_bh(&ap_dev->lock);
	if (ap_dev->state == AP_STATE_SETIRQ_WAIT)
		rc = snprintf(buf, PAGE_SIZE, "Enable Interrupt pending.\n");
	else if (ap_dev->interrupt == AP_INTR_ENABLED)
		rc = snprintf(buf, PAGE_SIZE, "Interrupts enabled.\n");
	else
		rc = snprintf(buf, PAGE_SIZE, "Interrupts disabled.\n");
	spin_unlock_bh(&ap_dev->lock);
	return rc;
}

static DEVICE_ATTR(interrupt, 0444, ap_interrupt_show, NULL);

static ssize_t ap_modalias_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "ap:t%02X\n", to_ap_dev(dev)->device_type);
}

static DEVICE_ATTR(modalias, 0444, ap_modalias_show, NULL);

static struct attribute *ap_dev_attrs[] = {
	&dev_attr_hwtype.attr,
	&dev_attr_depth.attr,
	&dev_attr_request_count.attr,
	&dev_attr_modalias.attr,
static ssize_t ap_functions_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	return snprintf(buf, PAGE_SIZE, "0x%08X\n", ap_dev->functions);
}

static DEVICE_ATTR(ap_functions, 0444, ap_functions_show, NULL);

static struct attribute *ap_dev_attrs[] = {
	&dev_attr_hwtype.attr,
	&dev_attr_raw_hwtype.attr,
	&dev_attr_depth.attr,
	&dev_attr_request_count.attr,
	&dev_attr_requestq_count.attr,
	&dev_attr_pendingq_count.attr,
	&dev_attr_reset.attr,
	&dev_attr_interrupt.attr,
	&dev_attr_modalias.attr,
	&dev_attr_ap_functions.attr,
	NULL
};
static struct attribute_group ap_dev_attr_group = {
	.attrs = ap_dev_attrs
};
#define is_card_dev(x) ((x)->parent == ap_root_device)
#define is_queue_dev(x) ((x)->parent != ap_root_device)

/**
 * ap_bus_match()
 * @dev: Pointer to device
 * @drv: Pointer to device_driver
 *
 * AP bus driver registration/unregistration.
 */
static int ap_bus_match(struct device *dev, struct device_driver *drv)
{
	struct ap_driver *ap_drv = to_ap_drv(drv);
	struct ap_device_id *id;

	/*
	 * Compare device type of the device with the list of
	 * supported types of the device_driver.
	 */
	for (id = ap_drv->ids; id->match_flags; id++) {
		if (is_card_dev(dev) &&
		    id->match_flags & AP_DEVICE_ID_MATCH_CARD_TYPE &&
		    id->dev_type == to_ap_dev(dev)->device_type)
			return 1;
		if (is_queue_dev(dev) &&
		    id->match_flags & AP_DEVICE_ID_MATCH_QUEUE_TYPE &&
		    id->dev_type == to_ap_dev(dev)->device_type)
			return 1;
	}
	return 0;
}

/**
 * ap_uevent(): Uevent function for AP devices.
 * @dev: Pointer to device
 * @env: Pointer to kobj_uevent_env
 *
 * It sets up a single environment variable DEV_TYPE which contains the
 * hardware device type.
 */
static int ap_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	int retval = 0;

	if (!ap_dev)
		return -ENODEV;

	/* Set up DEV_TYPE environment variable. */
	retval = add_uevent_var(env, "DEV_TYPE=%04X", ap_dev->device_type);
	if (retval)
		return retval;

	/* Add MODALIAS= */
	retval = add_uevent_var(env, "MODALIAS=ap:t%02X", ap_dev->device_type);

	return retval;
}

static int ap_dev_suspend(struct device *dev)
{
	struct ap_device *ap_dev = to_ap_dev(dev);

	if (ap_dev->drv && ap_dev->drv->suspend)
		ap_dev->drv->suspend(ap_dev);
	return 0;
}

static int ap_dev_resume(struct device *dev)
{
	struct ap_device *ap_dev = to_ap_dev(dev);

	if (ap_dev->drv && ap_dev->drv->resume)
		ap_dev->drv->resume(ap_dev);
	return 0;
}

static void ap_bus_suspend(void)
{
	AP_DBF(DBF_DEBUG, "%s running\n", __func__);

	ap_suspend_flag = 1;
	/*
	 * Disable scanning for devices, thus we do not want to scan
	 * for them after removing.
	 */
	flush_work(&ap_scan_work);
	tasklet_disable(&ap_tasklet);
}

static int __ap_card_devices_unregister(struct device *dev, void *dummy)
{
	if (is_card_dev(dev))
		device_unregister(dev);
	return 0;
}

static int __ap_queue_devices_unregister(struct device *dev, void *dummy)
{
	if (is_queue_dev(dev))
		device_unregister(dev);
	return 0;
}

static int __ap_queue_devices_with_id_unregister(struct device *dev, void *data)
{
	if (is_queue_dev(dev) &&
	    AP_QID_CARD(to_ap_queue(dev)->qid) == (int)(long) data)
		device_unregister(dev);
	return 0;
}

static void ap_bus_resume(void)
{
	int rc;

	AP_DBF(DBF_DEBUG, "%s running\n", __func__);

	/* remove all queue devices */
	bus_for_each_dev(&ap_bus_type, NULL, NULL,
			 __ap_queue_devices_unregister);
	/* remove all card devices */
	bus_for_each_dev(&ap_bus_type, NULL, NULL,
			 __ap_card_devices_unregister);

	/* Reset thin interrupt setting */
	if (ap_interrupts_available() && !ap_using_interrupts()) {
		rc = register_adapter_interrupt(&ap_airq);
		ap_airq_flag = (rc == 0);
	}
	if (!ap_interrupts_available() && ap_using_interrupts()) {
		unregister_adapter_interrupt(&ap_airq);
		ap_airq_flag = 0;
	}
	/* Reset domain */
	if (!user_set_domain)
		ap_domain_index = -1;
	/* Get things going again */
	ap_suspend_flag = 0;
	if (ap_airq_flag)
		xchg(ap_airq.lsi_ptr, 0);
	tasklet_enable(&ap_tasklet);
	queue_work(system_long_wq, &ap_scan_work);
}

static int ap_power_event(struct notifier_block *this, unsigned long event,
			  void *ptr)
{
	switch (event) {
	case PM_HIBERNATION_PREPARE:
	case PM_SUSPEND_PREPARE:
		ap_bus_suspend();
		break;
	case PM_POST_HIBERNATION:
	case PM_POST_SUSPEND:
		ap_bus_resume();
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}
static struct notifier_block ap_power_notifier = {
	.notifier_call = ap_power_event,
};

static SIMPLE_DEV_PM_OPS(ap_bus_pm_ops, ap_dev_suspend, ap_dev_resume);

static struct bus_type ap_bus_type = {
	.name = "ap",
	.match = &ap_bus_match,
	.uevent = &ap_uevent,
	.pm = &ap_bus_pm_ops,
};

static int __ap_revise_reserved(struct device *dev, void *dummy)
{
	int rc, card, queue, devres, drvres;

	if (is_queue_dev(dev)) {
		card = AP_QID_CARD(to_ap_queue(dev)->qid);
		queue = AP_QID_QUEUE(to_ap_queue(dev)->qid);
		mutex_lock(&ap_perms_mutex);
		devres = test_bit_inv(card, ap_perms.apm)
			&& test_bit_inv(queue, ap_perms.aqm);
		mutex_unlock(&ap_perms_mutex);
		drvres = to_ap_drv(dev->driver)->flags
			& AP_DRIVER_FLAG_DEFAULT;
		if (!!devres != !!drvres) {
			AP_DBF(DBF_DEBUG, "reprobing queue=%02x.%04x\n",
			       card, queue);
			rc = device_reprobe(dev);
		}
	}

	return 0;
}

static void ap_bus_revise_bindings(void)
{
	bus_for_each_dev(&ap_bus_type, NULL, NULL, __ap_revise_reserved);
}

int ap_owned_by_def_drv(int card, int queue)
{
	int rc = 0;

	if (card < 0 || card >= AP_DEVICES || queue < 0 || queue >= AP_DOMAINS)
		return -EINVAL;

	mutex_lock(&ap_perms_mutex);

	if (test_bit_inv(card, ap_perms.apm)
	    && test_bit_inv(queue, ap_perms.aqm))
		rc = 1;

	mutex_unlock(&ap_perms_mutex);

	return rc;
}
EXPORT_SYMBOL(ap_owned_by_def_drv);

int ap_apqn_in_matrix_owned_by_def_drv(unsigned long *apm,
				       unsigned long *aqm)
{
	int card, queue, rc = 0;

	mutex_lock(&ap_perms_mutex);

	for (card = 0; !rc && card < AP_DEVICES; card++)
		if (test_bit_inv(card, apm) &&
		    test_bit_inv(card, ap_perms.apm))
			for (queue = 0; !rc && queue < AP_DOMAINS; queue++)
				if (test_bit_inv(queue, aqm) &&
				    test_bit_inv(queue, ap_perms.aqm))
					rc = 1;

	mutex_unlock(&ap_perms_mutex);

	return rc;
}
EXPORT_SYMBOL(ap_apqn_in_matrix_owned_by_def_drv);

static int ap_device_probe(struct device *dev)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	struct ap_driver *ap_drv = to_ap_drv(dev->driver);
	int card, queue, devres, drvres, rc;

	if (is_queue_dev(dev)) {
		/*
		 * If the apqn is marked as reserved/used by ap bus and
		 * default drivers, only probe with drivers with the default
		 * flag set. If it is not marked, only probe with drivers
		 * with the default flag not set.
		 */
		card = AP_QID_CARD(to_ap_queue(dev)->qid);
		queue = AP_QID_QUEUE(to_ap_queue(dev)->qid);
		mutex_lock(&ap_perms_mutex);
		devres = test_bit_inv(card, ap_perms.apm)
			&& test_bit_inv(queue, ap_perms.aqm);
		mutex_unlock(&ap_perms_mutex);
		drvres = ap_drv->flags & AP_DRIVER_FLAG_DEFAULT;
		if (!!devres != !!drvres)
			return -ENODEV;
	}

	/* Add queue/card to list of active queues/cards */
	spin_lock_bh(&ap_list_lock);
	if (is_card_dev(dev))
		list_add(&to_ap_card(dev)->list, &ap_card_list);
	else
		list_add(&to_ap_queue(dev)->list,
			 &to_ap_queue(dev)->card->queues);
	spin_unlock_bh(&ap_list_lock);

	ap_dev->drv = ap_drv;
	rc = ap_drv->probe ? ap_drv->probe(ap_dev) : -ENODEV;
	if (!rc) {
		spin_lock_bh(&ap_device_lock);
		list_add(&ap_dev->list, &ap_device_list);
		spin_unlock_bh(&ap_device_lock);
	}
	if (rc)

	if (rc) {
		spin_lock_bh(&ap_list_lock);
		if (is_card_dev(dev))
			list_del_init(&to_ap_card(dev)->list);
		else
			list_del_init(&to_ap_queue(dev)->list);
		spin_unlock_bh(&ap_list_lock);
		ap_dev->drv = NULL;
	}

	return rc;
}

/**
 * __ap_flush_queue(): Flush requests.
 * @ap_dev: Pointer to the AP device
 *
 * Flush all requests from the request/pending queue of an AP device.
 */
static void __ap_flush_queue(struct ap_device *ap_dev)
{
	struct ap_message *ap_msg, *next;

	list_for_each_entry_safe(ap_msg, next, &ap_dev->pendingq, list) {
		list_del_init(&ap_msg->list);
		ap_dev->pendingq_count--;
		ap_dev->drv->receive(ap_dev, ap_msg, ERR_PTR(-ENODEV));
		ap_msg->rc = -EAGAIN;
		ap_msg->receive(ap_dev, ap_msg, NULL);
	}
	list_for_each_entry_safe(ap_msg, next, &ap_dev->requestq, list) {
		list_del_init(&ap_msg->list);
		ap_dev->requestq_count--;
		ap_dev->drv->receive(ap_dev, ap_msg, ERR_PTR(-ENODEV));
		ap_msg->rc = -EAGAIN;
		ap_msg->receive(ap_dev, ap_msg, NULL);
	}
}

void ap_flush_queue(struct ap_device *ap_dev)
{
	spin_lock_bh(&ap_dev->lock);
	__ap_flush_queue(ap_dev);
	spin_unlock_bh(&ap_dev->lock);
}
EXPORT_SYMBOL(ap_flush_queue);

static int ap_device_remove(struct device *dev)
{
	struct ap_device *ap_dev = to_ap_dev(dev);
	struct ap_driver *ap_drv = ap_dev->drv;

	ap_flush_queue(ap_dev);
	del_timer_sync(&ap_dev->timeout);
	spin_lock_bh(&ap_device_lock);
	list_del_init(&ap_dev->list);
	spin_unlock_bh(&ap_device_lock);
	spin_lock_bh(&ap_device_list_lock);
	list_del_init(&ap_dev->list);
	spin_unlock_bh(&ap_device_list_lock);
	if (ap_drv->remove)
		ap_drv->remove(ap_dev);

	/* Remove queue/card from list of active queues/cards */
	spin_lock_bh(&ap_list_lock);
	if (is_card_dev(dev))
		list_del_init(&to_ap_card(dev)->list);
	else
		list_del_init(&to_ap_queue(dev)->list);
	spin_unlock_bh(&ap_list_lock);

	return 0;
}

int ap_driver_register(struct ap_driver *ap_drv, struct module *owner,
		       char *name)
{
	struct device_driver *drv = &ap_drv->driver;

	if (!initialised)
		return -ENODEV;

	drv->bus = &ap_bus_type;
	drv->probe = ap_device_probe;
	drv->remove = ap_device_remove;
	drv->owner = owner;
	drv->name = name;
	return driver_register(drv);
}
EXPORT_SYMBOL(ap_driver_register);

void ap_driver_unregister(struct ap_driver *ap_drv)
{
	driver_unregister(&ap_drv->driver);
}
EXPORT_SYMBOL(ap_driver_unregister);

void ap_bus_force_rescan(void)
{
	if (ap_suspend_flag)
		return;
	/* processing a asynchronous bus rescan */
	del_timer(&ap_config_timer);
	queue_work(system_long_wq, &ap_scan_work);
	flush_work(&ap_scan_work);
}
EXPORT_SYMBOL(ap_bus_force_rescan);

/*
 * hex2bitmap() - parse hex mask string and set bitmap.
 * Valid strings are "0x012345678" with at least one valid hex number.
 * Rest of the bitmap to the right is padded with 0. No spaces allowed
 * within the string, the leading 0x may be omitted.
 * Returns the bitmask with exactly the bits set as given by the hex
 * string (both in big endian order).
 */
static int hex2bitmap(const char *str, unsigned long *bitmap, int bits)
{
	int i, n, b;

	/* bits needs to be a multiple of 8 */
	if (bits & 0x07)
		return -EINVAL;

	if (str[0] == '0' && str[1] == 'x')
		str++;
	if (*str == 'x')
		str++;

	for (i = 0; isxdigit(*str) && i < bits; str++) {
		b = hex_to_bin(*str);
		for (n = 0; n < 4; n++)
			if (b & (0x08 >> n))
				set_bit_inv(i + n, bitmap);
		i += 4;
	}

	if (*str == '\n')
		str++;
	if (*str)
		return -EINVAL;
	return 0;
}

/*
 * modify_bitmap() - parse bitmask argument and modify an existing
 * bit mask accordingly. A concatenation (done with ',') of these
 * terms is recognized:
 *   +<bitnr>[-<bitnr>] or -<bitnr>[-<bitnr>]
 * <bitnr> may be any valid number (hex, decimal or octal) in the range
 * 0...bits-1; the leading + or - is required. Here are some examples:
 *   +0-15,+32,-128,-0xFF
 *   -0-255,+1-16,+0x128
 *   +1,+2,+3,+4,-5,-7-10
 * Returns the new bitmap after all changes have been applied. Every
 * positive value in the string will set a bit and every negative value
 * in the string will clear a bit. As a bit may be touched more than once,
 * the last 'operation' wins:
 * +0-255,-128 = first bits 0-255 will be set, then bit 128 will be
 * cleared again. All other bits are unmodified.
 */
static int modify_bitmap(const char *str, unsigned long *bitmap, int bits)
{
	int a, i, z;
	char *np, sign;

	/* bits needs to be a multiple of 8 */
	if (bits & 0x07)
		return -EINVAL;

	while (*str) {
		sign = *str++;
		if (sign != '+' && sign != '-')
			return -EINVAL;
		a = z = simple_strtoul(str, &np, 0);
		if (str == np || a >= bits)
			return -EINVAL;
		str = np;
		if (*str == '-') {
			z = simple_strtoul(++str, &np, 0);
			if (str == np || a > z || z >= bits)
				return -EINVAL;
			str = np;
		}
		for (i = a; i <= z; i++)
			if (sign == '+')
				set_bit_inv(i, bitmap);
			else
				clear_bit_inv(i, bitmap);
		while (*str == ',' || *str == '\n')
			str++;
	}

	return 0;
}

/*
 * process_mask_arg() - parse a bitmap string and clear/set the
 * bits in the bitmap accordingly. The string may be given as
 * absolute value, a hex string like 0x1F2E3D4C5B6A" simple over-
 * writing the current content of the bitmap. Or as relative string
 * like "+1-16,-32,-0x40,+128" where only single bits or ranges of
 * bits are cleared or set. Distinction is done based on the very
 * first character which may be '+' or '-' for the relative string
 * and othewise assume to be an absolute value string. If parsing fails
 * a negative errno value is returned. All arguments and bitmaps are
 * big endian order.
 */
static int process_mask_arg(const char *str,
			    unsigned long *bitmap, int bits,
			    struct mutex *lock)
{
	unsigned long *newmap, size;
	int rc;

	/* bits needs to be a multiple of 8 */
	if (bits & 0x07)
		return -EINVAL;

	size = BITS_TO_LONGS(bits)*sizeof(unsigned long);
	newmap = kmalloc(size, GFP_KERNEL);
	if (!newmap)
		return -ENOMEM;
	if (mutex_lock_interruptible(lock)) {
		kfree(newmap);
		return -ERESTARTSYS;
	}

	if (*str == '+' || *str == '-') {
		memcpy(newmap, bitmap, size);
		rc = modify_bitmap(str, newmap, bits);
	} else {
		memset(newmap, 0, size);
		rc = hex2bitmap(str, newmap, bits);
	}
	if (rc == 0)
		memcpy(bitmap, newmap, size);
	mutex_unlock(lock);
	kfree(newmap);
	return rc;
}

/*
 * AP bus attributes.
 */

static ssize_t ap_domain_show(struct bus_type *bus, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", ap_domain_index);
}

static ssize_t ap_domain_store(struct bus_type *bus,
			       const char *buf, size_t count)
{
	int domain;

	if (sscanf(buf, "%i\n", &domain) != 1 ||
	    domain < 0 || domain > ap_max_domain_id ||
	    !test_bit_inv(domain, ap_perms.aqm))
		return -EINVAL;
	spin_lock_bh(&ap_domain_lock);
	ap_domain_index = domain;
	spin_unlock_bh(&ap_domain_lock);

	AP_DBF(DBF_DEBUG, "stored new default domain=%d\n", domain);

	return count;
}

static BUS_ATTR_RW(ap_domain);

static ssize_t ap_control_domain_mask_show(struct bus_type *bus, char *buf)
{
	if (!ap_configuration)	/* QCI not supported */
		return snprintf(buf, PAGE_SIZE, "not supported\n");

	return snprintf(buf, PAGE_SIZE,
			"0x%08x%08x%08x%08x%08x%08x%08x%08x\n",
			ap_configuration->adm[0], ap_configuration->adm[1],
			ap_configuration->adm[2], ap_configuration->adm[3],
			ap_configuration->adm[4], ap_configuration->adm[5],
			ap_configuration->adm[6], ap_configuration->adm[7]);
}

static BUS_ATTR_RO(ap_control_domain_mask);

static ssize_t ap_usage_domain_mask_show(struct bus_type *bus, char *buf)
{
	if (!ap_configuration)	/* QCI not supported */
		return snprintf(buf, PAGE_SIZE, "not supported\n");

	return snprintf(buf, PAGE_SIZE,
			"0x%08x%08x%08x%08x%08x%08x%08x%08x\n",
			ap_configuration->aqm[0], ap_configuration->aqm[1],
			ap_configuration->aqm[2], ap_configuration->aqm[3],
			ap_configuration->aqm[4], ap_configuration->aqm[5],
			ap_configuration->aqm[6], ap_configuration->aqm[7]);
}

static BUS_ATTR_RO(ap_usage_domain_mask);

static ssize_t ap_interrupts_show(struct bus_type *bus, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			ap_using_interrupts() ? 1 : 0);
}

static BUS_ATTR_RO(ap_interrupts);

static ssize_t config_time_show(struct bus_type *bus, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", ap_config_time);
}

static ssize_t config_time_store(struct bus_type *bus,
				 const char *buf, size_t count)
{
	int time;

	if (sscanf(buf, "%d\n", &time) != 1 || time < 5 || time > 120)
		return -EINVAL;
	ap_config_time = time;
	if (!timer_pending(&ap_config_timer) ||
	    !mod_timer(&ap_config_timer, jiffies + ap_config_time * HZ)) {
		ap_config_timer.expires = jiffies + ap_config_time * HZ;
		add_timer(&ap_config_timer);
	}
	mod_timer(&ap_config_timer, jiffies + ap_config_time * HZ);
	return count;
}

static BUS_ATTR_RW(config_time);

static ssize_t poll_thread_show(struct bus_type *bus, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", ap_poll_kthread ? 1 : 0);
}

static ssize_t poll_thread_store(struct bus_type *bus,
				 const char *buf, size_t count)
{
	int flag, rc;

	if (sscanf(buf, "%d\n", &flag) != 1)
		return -EINVAL;
	if (flag) {
		rc = ap_poll_thread_start();
		if (rc)
			return rc;
	}
	else
			count = rc;
	} else
		ap_poll_thread_stop();
	return count;
}

static BUS_ATTR_RW(poll_thread);

static ssize_t poll_timeout_show(struct bus_type *bus, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", poll_timeout);
}

static ssize_t poll_timeout_store(struct bus_type *bus, const char *buf,
				  size_t count)
{
	unsigned long long time;
	ktime_t hr_time;

	/* 120 seconds = maximum poll interval */
	if (sscanf(buf, "%llu\n", &time) != 1 || time < 1 || time > 120000000000)
	if (sscanf(buf, "%llu\n", &time) != 1 || time < 1 ||
	    time > 120000000000ULL)
		return -EINVAL;
	poll_timeout = time;
	hr_time = poll_timeout;

	if (!hrtimer_is_queued(&ap_poll_timer) ||
	    !hrtimer_forward(&ap_poll_timer, ap_poll_timer.expires, hr_time)) {
		ap_poll_timer.expires = hr_time;
		hrtimer_start(&ap_poll_timer, hr_time, HRTIMER_MODE_ABS);
	}
	spin_lock_bh(&ap_poll_timer_lock);
	hrtimer_cancel(&ap_poll_timer);
	hrtimer_set_expires(&ap_poll_timer, hr_time);
	hrtimer_start_expires(&ap_poll_timer, HRTIMER_MODE_ABS);
	spin_unlock_bh(&ap_poll_timer_lock);

	return count;
}

static BUS_ATTR_RW(poll_timeout);

static struct bus_attribute *const ap_bus_attrs[] = {
	&bus_attr_ap_domain,
	&bus_attr_config_time,
	&bus_attr_poll_thread,
	&bus_attr_poll_timeout,
static ssize_t ap_max_domain_id_show(struct bus_type *bus, char *buf)
{
	int max_domain_id;

	if (ap_configuration)
		max_domain_id = ap_max_domain_id ? : -1;
	else
		max_domain_id = 15;
	return snprintf(buf, PAGE_SIZE, "%d\n", max_domain_id);
}

static BUS_ATTR_RO(ap_max_domain_id);

static ssize_t apmask_show(struct bus_type *bus, char *buf)
{
	int rc;

	if (mutex_lock_interruptible(&ap_perms_mutex))
		return -ERESTARTSYS;
	rc = snprintf(buf, PAGE_SIZE,
		      "0x%016lx%016lx%016lx%016lx\n",
		      ap_perms.apm[0], ap_perms.apm[1],
		      ap_perms.apm[2], ap_perms.apm[3]);
	mutex_unlock(&ap_perms_mutex);

	return rc;
}

static ssize_t apmask_store(struct bus_type *bus, const char *buf,
			    size_t count)
{
	int rc;

	rc = process_mask_arg(buf, ap_perms.apm, AP_DEVICES, &ap_perms_mutex);
	if (rc)
		return rc;

	ap_bus_revise_bindings();

	return count;
}

static BUS_ATTR_RW(apmask);

static ssize_t aqmask_show(struct bus_type *bus, char *buf)
{
	int rc;

	if (mutex_lock_interruptible(&ap_perms_mutex))
		return -ERESTARTSYS;
	rc = snprintf(buf, PAGE_SIZE,
		      "0x%016lx%016lx%016lx%016lx\n",
		      ap_perms.aqm[0], ap_perms.aqm[1],
		      ap_perms.aqm[2], ap_perms.aqm[3]);
	mutex_unlock(&ap_perms_mutex);

	return rc;
}

static ssize_t aqmask_store(struct bus_type *bus, const char *buf,
			    size_t count)
{
	int rc;

	rc = process_mask_arg(buf, ap_perms.aqm, AP_DOMAINS, &ap_perms_mutex);
	if (rc)
		return rc;

	ap_bus_revise_bindings();

	return count;
}

static BUS_ATTR_RW(aqmask);

static struct bus_attribute *const ap_bus_attrs[] = {
	&bus_attr_ap_domain,
	&bus_attr_ap_control_domain_mask,
	&bus_attr_ap_usage_domain_mask,
	&bus_attr_config_time,
	&bus_attr_poll_thread,
	&bus_attr_ap_interrupts,
	&bus_attr_poll_timeout,
	&bus_attr_ap_max_domain_id,
	&bus_attr_apmask,
	&bus_attr_aqmask,
	NULL,
};

/**
 * ap_select_domain(): Select an AP domain.
 *
 * Pick one of the 16 AP domains.
 */
static int ap_select_domain(void)
{
	int queue_depth, device_type, count, max_count, best_domain;
	int rc, i, j;
	int count, max_count, best_domain;
	struct ap_queue_status status;
	int i, j;

	/*
	 * We want to use a single domain. Either the one specified with
	 * the "domain=" parameter or the domain with the maximum number
	 * of devices.
	 */
	if (ap_domain_index >= 0 && ap_domain_index < AP_DOMAINS)
	if (ap_domain_index >= 0)
	spin_lock_bh(&ap_domain_lock);
	if (ap_domain_index >= 0) {
		/* Domain has already been selected. */
		spin_unlock_bh(&ap_domain_lock);
		return 0;
	}
	best_domain = -1;
	max_count = 0;
	for (i = 0; i < AP_DOMAINS; i++) {
		count = 0;
		for (j = 0; j < AP_DEVICES; j++) {
			ap_qid_t qid = AP_MKQID(j, i);
			rc = ap_query_queue(qid, &queue_depth, &device_type);
			if (rc)
		if (!ap_test_config_domain(i))
		if (!ap_test_config_domain(i) ||
		    !test_bit_inv(i, ap_perms.aqm))
			continue;
		count = 0;
		for (j = 0; j < AP_DEVICES; j++) {
			if (!ap_test_config_card_id(j))
				continue;
			status = ap_test_queue(AP_MKQID(j, i),
					       ap_apft_available(),
					       NULL);
			if (status.response_code != AP_RESPONSE_NORMAL)
				continue;
			count++;
		}
		if (count > max_count) {
			max_count = count;
			best_domain = i;
		}
	}
	if (best_domain >= 0) {
		ap_domain_index = best_domain;
		AP_DBF(DBF_DEBUG, "new ap_domain_index=%d\n", ap_domain_index);
		spin_unlock_bh(&ap_domain_lock);
		return 0;
	}
	spin_unlock_bh(&ap_domain_lock);
	return -ENODEV;
}

/**
 * ap_probe_device_type(): Find the device type of an AP.
 * @ap_dev: pointer to the AP device.
 *
 * Find the device type if query queue returned a device type of 0.
 */
static int ap_probe_device_type(struct ap_device *ap_dev)
{
	static unsigned char msg[] = {
		0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x58,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x01,0x00,0x43,0x43,0x41,0x2d,0x41,0x50,
		0x50,0x4c,0x20,0x20,0x20,0x01,0x01,0x01,
		0x00,0x00,0x00,0x00,0x50,0x4b,0x00,0x00,
		0x00,0x00,0x01,0x1c,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x05,0xb8,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x70,0x00,0x41,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x54,0x32,0x01,0x00,0xa0,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0xb8,0x05,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x0a,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
		0x49,0x43,0x53,0x46,0x20,0x20,0x20,0x20,
		0x50,0x4b,0x0a,0x00,0x50,0x4b,0x43,0x53,
		0x2d,0x31,0x2e,0x32,0x37,0x00,0x11,0x22,
		0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x99,0x00,0x11,0x22,0x33,0x44,0x55,0x66,
		0x77,0x88,0x99,0x00,0x11,0x22,0x33,0x44,
		0x55,0x66,0x77,0x88,0x99,0x00,0x11,0x22,
		0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
		0x11,0x22,0x33,0x5d,0x00,0x5b,0x00,0x77,
		0x88,0x1e,0x00,0x00,0x57,0x00,0x00,0x00,
		0x00,0x04,0x00,0x00,0x4f,0x00,0x00,0x00,
		0x03,0x02,0x00,0x00,0x40,0x01,0x00,0x01,
		0xce,0x02,0x68,0x2d,0x5f,0xa9,0xde,0x0c,
		0xf6,0xd2,0x7b,0x58,0x4b,0xf9,0x28,0x68,
		0x3d,0xb4,0xf4,0xef,0x78,0xd5,0xbe,0x66,
		0x63,0x42,0xef,0xf8,0xfd,0xa4,0xf8,0xb0,
		0x8e,0x29,0xc2,0xc9,0x2e,0xd8,0x45,0xb8,
		0x53,0x8c,0x6f,0x4e,0x72,0x8f,0x6c,0x04,
		0x9c,0x88,0xfc,0x1e,0xc5,0x83,0x55,0x57,
		0xf7,0xdd,0xfd,0x4f,0x11,0x36,0x95,0x5d,
	};
	struct ap_queue_status status;
	unsigned long long psmid;
	char *reply;
	int rc, i;

	reply = (void *) get_zeroed_page(GFP_KERNEL);
	if (!reply) {
		rc = -ENOMEM;
		goto out;
	}

	status = __ap_send(ap_dev->qid, 0x0102030405060708ULL,
			   msg, sizeof(msg));
	if (status.response_code != AP_RESPONSE_NORMAL) {
		rc = -ENODEV;
		goto out_free;
	}

	/* Wait for the test message to complete. */
	for (i = 0; i < 6; i++) {
		mdelay(300);
		status = __ap_recv(ap_dev->qid, &psmid, reply, 4096);
		if (status.response_code == AP_RESPONSE_NORMAL &&
		    psmid == 0x0102030405060708ULL)
			break;
	}
	if (i < 6) {
		/* Got an answer. */
		if (reply[0] == 0x00 && reply[1] == 0x86)
			ap_dev->device_type = AP_DEVICE_TYPE_PCICC;
		else
			ap_dev->device_type = AP_DEVICE_TYPE_PCICA;
		rc = 0;
	} else
		rc = -ENODEV;

out_free:
	free_page((unsigned long) reply);
out:
	return rc;
}

/**
 * __ap_scan_bus(): Scan the AP bus.
 * @dev: Pointer to device
 * @data: Pointer to data
 *
 * Scan the AP bus for new devices.
/*
 * This function checks the type and returns either 0 for not
 * supported or the highest compatible type value (which may
 * include the input type value).
 */
static int ap_get_compatible_type(ap_qid_t qid, int rawtype, unsigned int func)
{
	int comp_type = 0;

	/* < CEX2A is not supported */
	if (rawtype < AP_DEVICE_TYPE_CEX2A)
		return 0;
	/* up to CEX6 known and fully supported */
	if (rawtype <= AP_DEVICE_TYPE_CEX6)
		return rawtype;
	/*
	 * unknown new type > CEX6, check for compatibility
	 * to the highest known and supported type which is
	 * currently CEX6 with the help of the QACT function.
	 */
	if (ap_qact_available()) {
		struct ap_queue_status status;
		union ap_qact_ap_info apinfo = {0};

		apinfo.mode = (func >> 26) & 0x07;
		apinfo.cat = AP_DEVICE_TYPE_CEX6;
		status = ap_qact(qid, 0, &apinfo);
		if (status.response_code == AP_RESPONSE_NORMAL
		    && apinfo.cat >= AP_DEVICE_TYPE_CEX2A
		    && apinfo.cat <= AP_DEVICE_TYPE_CEX6)
			comp_type = apinfo.cat;
	}
	if (!comp_type)
		AP_DBF(DBF_WARN, "queue=%02x.%04x unable to map type %d\n",
		       AP_QID_CARD(qid), AP_QID_QUEUE(qid), rawtype);
	else if (comp_type != rawtype)
		AP_DBF(DBF_INFO, "queue=%02x.%04x map type %d to %d\n",
		       AP_QID_CARD(qid), AP_QID_QUEUE(qid), rawtype, comp_type);
	return comp_type;
}

/*
 * helper function to be used with bus_find_dev
 * matches for the card device with the given id
 */
static int __match_card_device_with_id(struct device *dev, void *data)
{
	return is_card_dev(dev) && to_ap_card(dev)->id == (int)(long) data;
}

static void ap_device_release(struct device *dev)
{
	struct ap_device *ap_dev = to_ap_dev(dev);

	kfree(ap_dev);
}

/* helper function to be used with bus_find_dev
 * matches for the queue device with a given qid
 */
static int __match_queue_device_with_qid(struct device *dev, void *data)
{
	return is_queue_dev(dev) && to_ap_queue(dev)->qid == (int)(long) data;
}

/**
 * ap_scan_bus(): Scan the AP bus for new devices
 * Runs periodically, workqueue timer (ap_config_time)
 */
static void ap_scan_bus(struct work_struct *unused)
{
	struct ap_queue *aq;
	struct ap_card *ac;
	struct device *dev;
	ap_qid_t qid;
	int queue_depth, device_type;
	int rc, i;

	if (ap_select_domain() != 0)
		return;
	int queue_depth = 0, device_type = 0;
	unsigned int device_functions = 0;
	int rc, i, borked;
	int depth = 0, type = 0;
	unsigned int functions = 0;
	int comp_type, depth = 0, type = 0;
	unsigned int func = 0;
	int rc, id, dom, borked, domains, defdomdevs = 0;

	AP_DBF(DBF_DEBUG, "%s running\n", __func__);

	ap_query_configuration(ap_configuration);
	if (ap_select_domain() != 0)
		goto out;

	for (id = 0; id < AP_DEVICES; id++) {
		/* check if device is registered */
		dev = bus_find_device(&ap_bus_type, NULL,
				      (void *)(unsigned long)qid,
				      __ap_scan_bus);
		rc = ap_query_queue(qid, &queue_depth, &device_type);
		if (dev) {
			if (rc == -EBUSY) {
				set_current_state(TASK_UNINTERRUPTIBLE);
				schedule_timeout(AP_RESET_TIMEOUT);
				rc = ap_query_queue(qid, &queue_depth,
						    &device_type);
			}
			ap_dev = to_ap_dev(dev);
			spin_lock_bh(&ap_dev->lock);
			if (rc || ap_dev->unregistered) {
				spin_unlock_bh(&ap_dev->lock);
				device_unregister(dev);
				put_device(dev);
				continue;
			}
			spin_unlock_bh(&ap_dev->lock);
			put_device(dev);
			continue;
		}
		if (rc)
			continue;
		rc = ap_init_queue(qid);
		if (rc)
			continue;
		rc = ap_query_queue(qid, &queue_depth, &device_type,
				    &device_functions);
		if (dev) {
			ap_dev = to_ap_dev(dev);
			spin_lock_bh(&ap_dev->lock);
			if (rc == -ENODEV)
				ap_dev->state = AP_STATE_BORKED;
			borked = ap_dev->state == AP_STATE_BORKED;
			spin_unlock_bh(&ap_dev->lock);
			if (borked)	/* Remove broken device */
				      (void *)(long) id,
				      __match_card_device_with_id);
		ac = dev ? to_ap_card(dev) : NULL;
		if (!ap_test_config_card_id(id)) {
			if (dev) {
				/* Card device has been removed from
				 * configuration, remove the belonging
				 * queue devices.
				 */
				bus_for_each_dev(&ap_bus_type, NULL,
					(void *)(long) id,
					__ap_queue_devices_with_id_unregister);
				/* now remove the card device */
				device_unregister(dev);
				put_device(dev);
			}
			continue;
		}
		/* According to the configuration there should be a card
		 * device, so check if there is at least one valid queue
		 * and maybe create queue devices and the card device.
		 */
		domains = 0;
		for (dom = 0; dom < AP_DOMAINS; dom++) {
			qid = AP_MKQID(id, dom);
			dev = bus_find_device(&ap_bus_type, NULL,
					      (void *)(long) qid,
					      __match_queue_device_with_qid);
			aq = dev ? to_ap_queue(dev) : NULL;
			if (!ap_test_config_domain(dom)) {
				if (dev) {
					/* Queue device exists but has been
					 * removed from configuration.
					 */
					device_unregister(dev);
					put_device(dev);
				}
				continue;
			}
			rc = ap_query_queue(qid, &depth, &type, &func);
			if (dev) {
				spin_lock_bh(&aq->lock);
				if (rc == -ENODEV ||
				    /* adapter reconfiguration */
				    (ac && ac->functions != func))
					aq->state = AP_STATE_BORKED;
				borked = aq->state == AP_STATE_BORKED;
				spin_unlock_bh(&aq->lock);
				if (borked)	/* Remove broken device */
					device_unregister(dev);
				put_device(dev);
				if (!borked) {
					domains++;
					if (dom == ap_domain_index)
						defdomdevs++;
					continue;
				}
			}
			if (rc)
				continue;
			/* a new queue device is needed, check out comp type */
			comp_type = ap_get_compatible_type(qid, type, func);
			if (!comp_type)
				continue;
			/* maybe a card device needs to be created first */
			if (!ac) {
				ac = ap_card_create(id, depth, type,
						    comp_type, func);
				if (!ac)
					continue;
				ac->ap_dev.device.bus = &ap_bus_type;
				ac->ap_dev.device.parent = ap_root_device;
				dev_set_name(&ac->ap_dev.device,
					     "card%02x", id);
				/* Register card with AP bus */
				rc = device_register(&ac->ap_dev.device);
				if (rc) {
					put_device(&ac->ap_dev.device);
					ac = NULL;
					break;
				}
				/* get it and thus adjust reference counter */
				get_device(&ac->ap_dev.device);
			}
			/* now create the new queue device */
			aq = ap_queue_create(qid, comp_type);
			if (!aq)
				continue;
			aq->card = ac;
			aq->ap_dev.device.bus = &ap_bus_type;
			aq->ap_dev.device.parent = &ac->ap_dev.device;
			dev_set_name(&aq->ap_dev.device,
				     "%02x.%04x", id, dom);
			/* Start with a device reset */
			spin_lock_bh(&aq->lock);
			ap_wait(ap_sm_event(aq, AP_EVENT_POLL));
			spin_unlock_bh(&aq->lock);
			/* Register device */
			rc = device_register(&aq->ap_dev.device);
			if (rc) {
				put_device(&aq->ap_dev.device);
				continue;
			}
			domains++;
			if (dom == ap_domain_index)
				defdomdevs++;
		} /* end domain loop */
		if (ac) {
			/* remove card dev if there are no queue devices */
			if (!domains)
				device_unregister(&ac->ap_dev.device);
			put_device(&ac->ap_dev.device);
		}
		if (rc)
			continue;
		ap_dev = kzalloc(sizeof(*ap_dev), GFP_KERNEL);
		if (!ap_dev)
			break;
		ap_dev->qid = qid;
		ap_dev->queue_depth = queue_depth;
		ap_dev->unregistered = 1;
		ap_dev->state = AP_STATE_RESET_START;
		ap_dev->interrupt = AP_INTR_DISABLED;
		ap_dev->queue_depth = queue_depth;
		ap_dev->raw_hwtype = device_type;
		ap_dev->device_type = device_type;
		ap_dev->functions = device_functions;
		spin_lock_init(&ap_dev->lock);
		INIT_LIST_HEAD(&ap_dev->pendingq);
		INIT_LIST_HEAD(&ap_dev->requestq);
		INIT_LIST_HEAD(&ap_dev->list);
		setup_timer(&ap_dev->timeout, ap_request_timeout,
			    (unsigned long) ap_dev);
		if (device_type == 0)
			ap_probe_device_type(ap_dev);
		else
			ap_dev->device_type = device_type;

		ap_dev->device.bus = &ap_bus_type;
		ap_dev->device.parent = ap_root_device;
		snprintf(ap_dev->device.bus_id, BUS_ID_SIZE, "card%02x",
			 AP_QID_DEVICE(ap_dev->qid));
		ap_dev->device.release = ap_device_release;
		rc = device_register(&ap_dev->device);
		if (rc) {
			kfree(ap_dev);

		ap_dev->device.bus = &ap_bus_type;
		ap_dev->device.parent = ap_root_device;
		rc = dev_set_name(&ap_dev->device, "card%02x",
				  AP_QID_DEVICE(ap_dev->qid));
		if (rc) {
			kfree(ap_dev);
			continue;
		}
		/* Add to list of devices */
		spin_lock_bh(&ap_device_list_lock);
		list_add(&ap_dev->list, &ap_device_list);
		spin_unlock_bh(&ap_device_list_lock);
		/* Start with a device reset */
		spin_lock_bh(&ap_dev->lock);
		ap_sm_wait(ap_sm_event(ap_dev, AP_EVENT_POLL));
		spin_unlock_bh(&ap_dev->lock);
		/* Register device */
		ap_dev->device.release = ap_device_release;
		rc = device_register(&ap_dev->device);
		if (rc) {
			spin_lock_bh(&ap_dev->lock);
			list_del_init(&ap_dev->list);
			spin_unlock_bh(&ap_dev->lock);
			put_device(&ap_dev->device);
			continue;
		}
		/* Add device attributes. */
		rc = sysfs_create_group(&ap_dev->device.kobj,
					&ap_dev_attr_group);
		if (!rc) {
			spin_lock_bh(&ap_dev->lock);
			ap_dev->unregistered = 0;
			spin_unlock_bh(&ap_dev->lock);
		}
		else
			device_unregister(&ap_dev->device);
	}
}

static void
ap_config_timeout(unsigned long ptr)
{
	queue_work(ap_work_queue, &ap_config_work);
	ap_config_timer.expires = jiffies + ap_config_time * HZ;
	add_timer(&ap_config_timer);
}

/**
 * ap_schedule_poll_timer(): Schedule poll timer.
 *
 * Set up the timer to run the poll tasklet
 */
static inline void ap_schedule_poll_timer(void)
{
	if (hrtimer_is_queued(&ap_poll_timer))
		return;
	hrtimer_start(&ap_poll_timer, ktime_set(0, poll_timeout),
		      HRTIMER_MODE_ABS);
}

/**
 * ap_poll_read(): Receive pending reply messages from an AP device.
 * @ap_dev: pointer to the AP device
 * @flags: pointer to control flags, bit 2^0 is set if another poll is
 *	   required, bit 2^1 is set if the poll timer needs to get armed
 *
 * Returns 0 if the device is still present, -ENODEV if not.
 */
static int ap_poll_read(struct ap_device *ap_dev, unsigned long *flags)
{
	struct ap_queue_status status;
	struct ap_message *ap_msg;

	if (ap_dev->queue_count <= 0)
		return 0;
	status = __ap_recv(ap_dev->qid, &ap_dev->reply->psmid,
			   ap_dev->reply->message, ap_dev->reply->length);
	switch (status.response_code) {
	case AP_RESPONSE_NORMAL:
		atomic_dec(&ap_poll_requests);
		ap_decrease_queue_count(ap_dev);
		list_for_each_entry(ap_msg, &ap_dev->pendingq, list) {
			if (ap_msg->psmid != ap_dev->reply->psmid)
				continue;
			list_del_init(&ap_msg->list);
			ap_dev->pendingq_count--;
			ap_dev->drv->receive(ap_dev, ap_msg, ap_dev->reply);
			break;
		}
		if (ap_dev->queue_count > 0)
			*flags |= 1;
		break;
	case AP_RESPONSE_NO_PENDING_REPLY:
		if (status.queue_empty) {
			/* The card shouldn't forget requests but who knows. */
			atomic_sub(ap_dev->queue_count, &ap_poll_requests);
			ap_dev->queue_count = 0;
			list_splice_init(&ap_dev->pendingq, &ap_dev->requestq);
			ap_dev->requestq_count += ap_dev->pendingq_count;
			ap_dev->pendingq_count = 0;
		} else
			*flags |= 2;
		break;
	default:
		return -ENODEV;
	}
	return 0;
}

/**
 * ap_poll_write(): Send messages from the request queue to an AP device.
 * @ap_dev: pointer to the AP device
 * @flags: pointer to control flags, bit 2^0 is set if another poll is
 *	   required, bit 2^1 is set if the poll timer needs to get armed
 *
 * Returns 0 if the device is still present, -ENODEV if not.
 */
static int ap_poll_write(struct ap_device *ap_dev, unsigned long *flags)
{
	struct ap_queue_status status;
	struct ap_message *ap_msg;

	if (ap_dev->requestq_count <= 0 ||
	    ap_dev->queue_count >= ap_dev->queue_depth)
		return 0;
	/* Start the next request on the queue. */
	ap_msg = list_entry(ap_dev->requestq.next, struct ap_message, list);
	status = __ap_send(ap_dev->qid, ap_msg->psmid,
			   ap_msg->message, ap_msg->length);
	switch (status.response_code) {
	case AP_RESPONSE_NORMAL:
		atomic_inc(&ap_poll_requests);
		ap_increase_queue_count(ap_dev);
		list_move_tail(&ap_msg->list, &ap_dev->pendingq);
		ap_dev->requestq_count--;
		ap_dev->pendingq_count++;
		if (ap_dev->queue_count < ap_dev->queue_depth &&
		    ap_dev->requestq_count > 0)
			*flags |= 1;
		*flags |= 2;
		break;
	case AP_RESPONSE_Q_FULL:
	case AP_RESPONSE_RESET_IN_PROGRESS:
		*flags |= 2;
		break;
	case AP_RESPONSE_MESSAGE_TOO_BIG:
		return -EINVAL;
	default:
		return -ENODEV;
	}
	return 0;
}

/**
 * ap_poll_queue(): Poll AP device for pending replies and send new messages.
 * @ap_dev: pointer to the bus device
 * @flags: pointer to control flags, bit 2^0 is set if another poll is
 *	   required, bit 2^1 is set if the poll timer needs to get armed
 *
 * Poll AP device for pending replies and send new messages. If either
 * ap_poll_read or ap_poll_write returns -ENODEV unregister the device.
 * Returns 0.
 */
static inline int ap_poll_queue(struct ap_device *ap_dev, unsigned long *flags)
{
	int rc;

	rc = ap_poll_read(ap_dev, flags);
	if (rc)
		return rc;
	return ap_poll_write(ap_dev, flags);
}

/**
 * __ap_queue_message(): Queue a message to a device.
 * @ap_dev: pointer to the AP device
 * @ap_msg: the message to be queued
 *
 * Queue a message to a device. Returns 0 if successful.
 */
static int __ap_queue_message(struct ap_device *ap_dev, struct ap_message *ap_msg)
{
	struct ap_queue_status status;

	if (list_empty(&ap_dev->requestq) &&
	    ap_dev->queue_count < ap_dev->queue_depth) {
		status = __ap_send(ap_dev->qid, ap_msg->psmid,
				   ap_msg->message, ap_msg->length);
		switch (status.response_code) {
		case AP_RESPONSE_NORMAL:
			list_add_tail(&ap_msg->list, &ap_dev->pendingq);
			atomic_inc(&ap_poll_requests);
			ap_dev->pendingq_count++;
			ap_increase_queue_count(ap_dev);
			ap_dev->total_request_count++;
			break;
		case AP_RESPONSE_Q_FULL:
		case AP_RESPONSE_RESET_IN_PROGRESS:
			list_add_tail(&ap_msg->list, &ap_dev->requestq);
			ap_dev->requestq_count++;
			ap_dev->total_request_count++;
			return -EBUSY;
		case AP_RESPONSE_MESSAGE_TOO_BIG:
			ap_dev->drv->receive(ap_dev, ap_msg, ERR_PTR(-EINVAL));
			return -EINVAL;
		default:	/* Device is gone. */
			ap_dev->drv->receive(ap_dev, ap_msg, ERR_PTR(-ENODEV));
			return -ENODEV;
		}
	} else {
		list_add_tail(&ap_msg->list, &ap_dev->requestq);
		ap_dev->requestq_count++;
		ap_dev->total_request_count++;
		return -EBUSY;
	}
	ap_schedule_poll_timer();
	return 0;
}

void ap_queue_message(struct ap_device *ap_dev, struct ap_message *ap_msg)
{
	unsigned long flags;
	int rc;

	spin_lock_bh(&ap_dev->lock);
	if (!ap_dev->unregistered) {
		/* Make room on the queue by polling for finished requests. */
		rc = ap_poll_queue(ap_dev, &flags);
		if (!rc)
			rc = __ap_queue_message(ap_dev, ap_msg);
		if (!rc)
			wake_up(&ap_poll_wait);
		if (rc == -ENODEV)
			ap_dev->unregistered = 1;
	} else {
		ap_dev->drv->receive(ap_dev, ap_msg, ERR_PTR(-ENODEV));
		rc = -ENODEV;
	}
	spin_unlock_bh(&ap_dev->lock);
	if (rc == -ENODEV)
		device_unregister(&ap_dev->device);
}
EXPORT_SYMBOL(ap_queue_message);

/**
 * ap_cancel_message(): Cancel a crypto request.
 * @ap_dev: The AP device that has the message queued
 * @ap_msg: The message that is to be removed
 *
 * Cancel a crypto request. This is done by removing the request
 * from the device pending or request queue. Note that the
 * request stays on the AP queue. When it finishes the message
 * reply will be discarded because the psmid can't be found.
 */
void ap_cancel_message(struct ap_device *ap_dev, struct ap_message *ap_msg)
{
	struct ap_message *tmp;

	spin_lock_bh(&ap_dev->lock);
	if (!list_empty(&ap_msg->list)) {
		list_for_each_entry(tmp, &ap_dev->pendingq, list)
			if (tmp->psmid == ap_msg->psmid) {
				ap_dev->pendingq_count--;
				goto found;
			}
		ap_dev->requestq_count--;
	found:
		list_del_init(&ap_msg->list);
	}
	spin_unlock_bh(&ap_dev->lock);
}
EXPORT_SYMBOL(ap_cancel_message);

/**
 * ap_poll_timeout(): AP receive polling for finished AP requests.
 * @unused: Unused pointer.
 *
 * Schedules the AP tasklet using a high resolution timer.
 */
static enum hrtimer_restart ap_poll_timeout(struct hrtimer *unused)
{
	tasklet_schedule(&ap_tasklet);
	return HRTIMER_NORESTART;
}

/**
 * ap_reset(): Reset a not responding AP device.
 * @ap_dev: Pointer to the AP device
 *
 * Reset a not responding AP device and move all requests from the
 * pending queue to the request queue.
 */
static void ap_reset(struct ap_device *ap_dev)
{
	int rc;

	ap_dev->reset = AP_RESET_IGNORE;
	atomic_sub(ap_dev->queue_count, &ap_poll_requests);
	ap_dev->queue_count = 0;
	list_splice_init(&ap_dev->pendingq, &ap_dev->requestq);
	ap_dev->requestq_count += ap_dev->pendingq_count;
	ap_dev->pendingq_count = 0;
	rc = ap_init_queue(ap_dev->qid);
	if (rc == -ENODEV)
		ap_dev->unregistered = 1;
}

static int __ap_poll_all(struct ap_device *ap_dev, unsigned long *flags)
{
	spin_lock(&ap_dev->lock);
	if (!ap_dev->unregistered) {
		if (ap_poll_queue(ap_dev, flags))
			ap_dev->unregistered = 1;
		if (ap_dev->reset == AP_RESET_DO)
			ap_reset(ap_dev);
	}
	spin_unlock(&ap_dev->lock);
	return 0;
}

/**
 * ap_poll_all(): Poll all AP devices.
 * @dummy: Unused variable
 *
 * Poll all AP devices on the bus in a round robin fashion. Continue
 * polling until bit 2^0 of the control flags is not set. If bit 2^1
 * of the control flags has been set arm the poll timer.
 */
static void ap_poll_all(unsigned long dummy)
{
	unsigned long flags;
	struct ap_device *ap_dev;

	do {
		flags = 0;
		spin_lock(&ap_device_lock);
		list_for_each_entry(ap_dev, &ap_device_list, list) {
			__ap_poll_all(ap_dev, &flags);
		}
		spin_unlock(&ap_device_lock);
	} while (flags & 1);
	if (flags & 2)
		ap_schedule_poll_timer();
}

/**
 * ap_poll_thread(): Thread that polls for finished requests.
 * @data: Unused pointer
 *
 * AP bus poll thread. The purpose of this thread is to poll for
 * finished requests in a loop if there is a "free" cpu - that is
 * a cpu that doesn't have anything better to do. The polling stops
 * as soon as there is another task or if all messages have been
 * delivered.
 */
static int ap_poll_thread(void *data)
{
	DECLARE_WAITQUEUE(wait, current);
	unsigned long flags;
	int requests;
	struct ap_device *ap_dev;

	set_user_nice(current, 19);
	while (1) {
		if (need_resched()) {
			schedule();
			continue;
		}
		add_wait_queue(&ap_poll_wait, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		requests = atomic_read(&ap_poll_requests);
		if (requests <= 0)
			schedule();
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&ap_poll_wait, &wait);

		flags = 0;
		spin_lock_bh(&ap_device_lock);
		list_for_each_entry(ap_dev, &ap_device_list, list) {
			__ap_poll_all(ap_dev, &flags);
		}
		spin_unlock_bh(&ap_device_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&ap_poll_wait, &wait);
	return 0;
}

static int ap_poll_thread_start(void)
{
	int rc;

	mutex_lock(&ap_poll_thread_mutex);
	if (!ap_poll_kthread) {
		ap_poll_kthread = kthread_run(ap_poll_thread, NULL, "appoll");
		rc = IS_ERR(ap_poll_kthread) ? PTR_ERR(ap_poll_kthread) : 0;
		if (rc)
			ap_poll_kthread = NULL;
	}
	else
		rc = 0;
	mutex_unlock(&ap_poll_thread_mutex);
	return rc;
}

static void ap_poll_thread_stop(void)
{
	mutex_lock(&ap_poll_thread_mutex);
	if (ap_poll_kthread) {
		kthread_stop(ap_poll_kthread);
		ap_poll_kthread = NULL;
	}
	mutex_unlock(&ap_poll_thread_mutex);
}

/**
 * ap_request_timeout(): Handling of request timeouts
 * @data: Holds the AP device.
 *
 * Handles request timeouts.
 */
static void ap_request_timeout(unsigned long data)
{
	struct ap_device *ap_dev = (struct ap_device *) data;

	if (ap_dev->reset == AP_RESET_ARMED)
		ap_dev->reset = AP_RESET_DO;
		if (rc) {
			device_unregister(&ap_dev->device);
			continue;
		}
	}
	} /* end device loop */

	if (defdomdevs < 1)
		AP_DBF(DBF_INFO,
		       "no queue device with default domain %d available\n",
		       ap_domain_index);

out:
	mod_timer(&ap_config_timer, jiffies + ap_config_time * HZ);
}

static void ap_config_timeout(struct timer_list *unused)
{
	if (ap_suspend_flag)
		return;
	queue_work(system_long_wq, &ap_scan_work);
}

static void ap_reset_domain(void)
{
	int i;

	if (ap_domain_index != -1)
		for (i = 0; i < AP_DEVICES; i++)
			ap_reset_queue(AP_MKQID(i, ap_domain_index));
	if (ap_domain_index == -1 || !ap_test_config_domain(ap_domain_index))
		return;
	for (i = 0; i < AP_DEVICES; i++)
		ap_reset_queue(AP_MKQID(i, ap_domain_index));
}

static void ap_reset_all(void)
{
	int i, j;

	for (i = 0; i < AP_DOMAINS; i++)
		for (j = 0; j < AP_DEVICES; j++)
			ap_reset_queue(AP_MKQID(j, i));
	for (i = 0; i < AP_DOMAINS; i++) {
		if (!ap_test_config_domain(i))
			continue;
		for (j = 0; j < AP_DEVICES; j++) {
			if (!ap_test_config_card_id(j))
				continue;
			ap_rapq(AP_MKQID(j, i));
		}
	}
}

static struct reset_call ap_reset_call = {
	.fn = ap_reset_all,
};

int __init ap_debug_init(void)
static int __init ap_debug_init(void)
{
	ap_dbf_info = debug_register("ap", 1, 1,
				     DBF_MAX_SPRINTF_ARGS * sizeof(long));
	debug_register_view(ap_dbf_info, &debug_sprintf_view);
	debug_set_level(ap_dbf_info, DBF_ERR);

	return 0;
}

static void __init ap_perms_init(void)
{
	/* all resources useable if no kernel parameter string given */
	memset(&ap_perms.apm, 0xFF, sizeof(ap_perms.apm));
	memset(&ap_perms.aqm, 0xFF, sizeof(ap_perms.aqm));

	/* apm kernel parameter string */
	if (apm_str) {
		memset(&ap_perms.apm, 0, sizeof(ap_perms.apm));
		process_mask_arg(apm_str, ap_perms.apm, AP_DEVICES,
				 &ap_perms_mutex);
	}

	/* aqm kernel parameter string */
	if (aqm_str) {
		memset(&ap_perms.aqm, 0, sizeof(ap_perms.aqm));
		process_mask_arg(aqm_str, ap_perms.aqm, AP_DOMAINS,
				 &ap_perms_mutex);
	}
}

/**
 * ap_module_init(): The module initialization code.
 *
 * Initializes the module.
 */
static int __init ap_module_init(void)
{
	int rc, i;

	if (ap_domain_index < -1 || ap_domain_index >= AP_DOMAINS) {
		printk(KERN_WARNING "Invalid param: domain = %d. "
		       " Not loading.\n", ap_domain_index);
		return -EINVAL;
	}
	if (ap_instructions_available() != 0) {
		printk(KERN_WARNING "AP instructions not installed.\n");
		return -ENODEV;
	}
	int max_domain_id;
	int rc, i;

	rc = ap_debug_init();
	if (rc)
		return rc;

	if (!ap_instructions_available()) {
		pr_warn("The hardware system does not support AP instructions\n");
		return -ENODEV;
	}

	/* set up the AP permissions (ap and aq masks) */
	ap_perms_init();

	/* Get AP configuration data if available */
	ap_init_configuration();

	if (ap_configuration)
		max_domain_id =
			ap_max_domain_id ? ap_max_domain_id : AP_DOMAINS - 1;
	else
		max_domain_id = 15;
	if (ap_domain_index < -1 || ap_domain_index > max_domain_id ||
	    (ap_domain_index >= 0 &&
	     !test_bit_inv(ap_domain_index, ap_perms.aqm))) {
		pr_warn("%d is not a valid cryptographic domain\n",
			ap_domain_index);
		ap_domain_index = -1;
	}
	/* In resume callback we need to know if the user had set the domain.
	 * If so, we can not just reset it.
	 */
	if (ap_domain_index >= 0)
		user_set_domain = 1;

	if (ap_interrupts_available()) {
		rc = register_adapter_interrupt(&ap_airq);
		ap_airq_flag = (rc == 0);
	}

	/* Create /sys/bus/ap. */
	rc = bus_register(&ap_bus_type);
	if (rc)
		goto out;
	for (i = 0; ap_bus_attrs[i]; i++) {
		rc = bus_create_file(&ap_bus_type, ap_bus_attrs[i]);
		if (rc)
			goto out_bus;
	}

	/* Create /sys/devices/ap. */
	ap_root_device = s390_root_dev_register("ap");
	rc = IS_ERR(ap_root_device) ? PTR_ERR(ap_root_device) : 0;
	if (rc)
		goto out_bus;

	ap_work_queue = create_singlethread_workqueue("kapwork");
	if (!ap_work_queue) {
		rc = -ENOMEM;
		goto out_root;
	}

	if (ap_select_domain() == 0)
		ap_scan_bus(NULL);

	/* Setup the AP bus rescan timer. */
	init_timer(&ap_config_timer);
	ap_config_timer.function = ap_config_timeout;
	ap_config_timer.data = 0;
	ap_config_timer.expires = jiffies + ap_config_time * HZ;
	add_timer(&ap_config_timer);

	/* Setup the high resultion poll timer.
	ap_root_device = root_device_register("ap");
	rc = PTR_ERR_OR_ZERO(ap_root_device);
	if (rc)
		goto out_bus;

	/* Setup the AP bus rescan timer. */
	timer_setup(&ap_config_timer, ap_config_timeout, 0);

	/*
	 * Setup the high resultion poll timer.
	 * If we are running under z/VM adjust polling to z/VM polling rate.
	 */
	if (MACHINE_IS_VM)
		poll_timeout = 1500000;
	spin_lock_init(&ap_poll_timer_lock);
	hrtimer_init(&ap_poll_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	ap_poll_timer.function = ap_poll_timeout;

	/* Start the low priority AP bus poll thread. */
	if (ap_thread_flag) {
		rc = ap_poll_thread_start();
		if (rc)
			goto out_work;
	}

	return 0;

out_work:
	del_timer_sync(&ap_config_timer);
	hrtimer_cancel(&ap_poll_timer);
	destroy_workqueue(ap_work_queue);
out_root:
	s390_root_dev_unregister(ap_root_device);
	rc = register_pm_notifier(&ap_power_notifier);
	if (rc)
		goto out_pm;

	queue_work(system_long_wq, &ap_scan_work);
	initialised = true;

	return 0;

out_pm:
	ap_poll_thread_stop();
out_work:
	hrtimer_cancel(&ap_poll_timer);
	root_device_unregister(ap_root_device);
out_bus:
	while (i--)
		bus_remove_file(&ap_bus_type, ap_bus_attrs[i]);
	bus_unregister(&ap_bus_type);
out:
	unregister_reset_call(&ap_reset_call);
	return rc;
}

static int __ap_match_all(struct device *dev, void *data)
{
	return 1;
}

	if (ap_using_interrupts())
		unregister_adapter_interrupt(&ap_airq);
	kfree(ap_configuration);
	return rc;
}

/**
 * ap_modules_exit(): The module termination code
 *
 * Terminates the module.
 */
void ap_module_exit(void)
{
	int i;
	struct device *dev;


	initialised = false;
	ap_reset_domain();
	ap_poll_thread_stop();
	del_timer_sync(&ap_config_timer);
	hrtimer_cancel(&ap_poll_timer);
	destroy_workqueue(ap_work_queue);
	tasklet_kill(&ap_tasklet);
	s390_root_dev_unregister(ap_root_device);
	while ((dev = bus_find_device(&ap_bus_type, NULL, NULL,
		    __ap_match_all)))
	{
		device_unregister(dev);
		put_device(dev);
	}
	for (i = 0; ap_bus_attrs[i]; i++)
		bus_remove_file(&ap_bus_type, ap_bus_attrs[i]);
	bus_unregister(&ap_bus_type);
	unregister_reset_call(&ap_reset_call);
}

#ifndef CONFIG_ZCRYPT_MONOLITHIC
module_init(ap_module_init);
module_exit(ap_module_exit);
#endif
	tasklet_kill(&ap_tasklet);
	bus_for_each_dev(&ap_bus_type, NULL, NULL, __ap_devices_unregister);
	for (i = 0; ap_bus_attrs[i]; i++)
		bus_remove_file(&ap_bus_type, ap_bus_attrs[i]);
	unregister_pm_notifier(&ap_power_notifier);
	root_device_unregister(ap_root_device);
	bus_unregister(&ap_bus_type);
	kfree(ap_configuration);
	unregister_reset_call(&ap_reset_call);
	if (ap_using_interrupts())
		unregister_adapter_interrupt(&ap_airq);
}

module_init(ap_module_init);
module_exit(ap_module_exit);
device_initcall(ap_module_init);
