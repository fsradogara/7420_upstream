/*
 * RTC subsystem, base class
 *
 * Copyright (C) 2005 Tower Technologies
 * Author: Alessandro Zummo <a.zummo@towertech.it>
 *
 * class skeleton from drivers/hwmon/hwmon.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/kdev_t.h>
#include <linux/idr.h>
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of.h>
#include <linux/rtc.h>
#include <linux/kdev_t.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "rtc-core.h"


static DEFINE_IDR(rtc_idr);
static DEFINE_MUTEX(idr_lock);
static DEFINE_IDA(rtc_ida);
struct class *rtc_class;

static void rtc_device_release(struct device *dev)
{
	struct rtc_device *rtc = to_rtc_device(dev);
	mutex_lock(&idr_lock);
	idr_remove(&rtc_idr, rtc->id);
	mutex_unlock(&idr_lock);
	kfree(rtc);
}

#if defined(CONFIG_PM) && defined(CONFIG_RTC_HCTOSYS_DEVICE)

	ida_simple_remove(&rtc_ida, rtc->id);
	kfree(rtc);
}

#ifdef CONFIG_RTC_HCTOSYS_DEVICE
/* Result of the last RTC to system clock attempt. */
int rtc_hctosys_ret = -ENODEV;
#endif

#if defined(CONFIG_PM_SLEEP) && defined(CONFIG_RTC_HCTOSYS_DEVICE)
/*
 * On suspend(), measure the delta between one RTC and the
 * system's wall clock; restore it on resume().
 */

static struct timespec	delta;
static time_t		oldtime;

static int rtc_suspend(struct device *dev, pm_message_t mesg)
{
	struct rtc_device	*rtc = to_rtc_device(dev);
	struct rtc_time		tm;
	struct timespec		ts = current_kernel_time();

	if (strncmp(rtc->dev.bus_id,
				CONFIG_RTC_HCTOSYS_DEVICE,
				BUS_ID_SIZE) != 0)
		return 0;

	rtc_read_time(rtc, &tm);
	rtc_tm_to_time(&tm, &oldtime);

	/* RTC precision is 1 second; adjust delta for avg 1/2 sec err */
	set_normalized_timespec(&delta,
				ts.tv_sec - oldtime,
				ts.tv_nsec - (NSEC_PER_SEC >> 1));
static struct timespec64 old_rtc, old_system, old_delta;


static int rtc_suspend(struct device *dev)
{
	struct rtc_device	*rtc = to_rtc_device(dev);
	struct rtc_time		tm;
	struct timespec64	delta, delta_delta;
	int err;

	if (timekeeping_rtc_skipsuspend())
		return 0;

	if (strcmp(dev_name(&rtc->dev), CONFIG_RTC_HCTOSYS_DEVICE) != 0)
		return 0;

	/* snapshot the current RTC and system time at suspend*/
	err = rtc_read_time(rtc, &tm);
	if (err < 0) {
		pr_debug("%s:  fail to read rtc time\n", dev_name(&rtc->dev));
		return 0;
	}

	getnstimeofday64(&old_system);
	old_rtc.tv_sec = rtc_tm_to_time64(&tm);


	/*
	 * To avoid drift caused by repeated suspend/resumes,
	 * which each can add ~1 second drift error,
	 * try to compensate so the difference in system time
	 * and rtc time stays close to constant.
	 */
	delta = timespec64_sub(old_system, old_rtc);
	delta_delta = timespec64_sub(delta, old_delta);
	if (delta_delta.tv_sec < -2 || delta_delta.tv_sec >= 2) {
		/*
		 * if delta_delta is too large, assume time correction
		 * has occured and set old_delta to the current delta.
		 */
		old_delta = delta;
	} else {
		/* Otherwise try to adjust old_system to compensate */
		old_system = timespec64_sub(old_system, delta_delta);
	}

	return 0;
}

static int rtc_resume(struct device *dev)
{
	struct rtc_device	*rtc = to_rtc_device(dev);
	struct rtc_time		tm;
	time_t			newtime;
	struct timespec		time;

	if (strncmp(rtc->dev.bus_id,
				CONFIG_RTC_HCTOSYS_DEVICE,
				BUS_ID_SIZE) != 0)
		return 0;

	rtc_read_time(rtc, &tm);
	if (rtc_valid_tm(&tm) != 0) {
		pr_debug("%s:  bogus resume time\n", rtc->dev.bus_id);
		return 0;
	}
	rtc_tm_to_time(&tm, &newtime);
	if (newtime <= oldtime) {
		if (newtime < oldtime)
			pr_debug("%s:  time travel!\n", rtc->dev.bus_id);
		return 0;
	}

	/* restore wall clock using delta against this RTC;
	 * adjust again for avg 1/2 second RTC sampling error
	 */
	set_normalized_timespec(&time,
				newtime + delta.tv_sec,
				(NSEC_PER_SEC >> 1) + delta.tv_nsec);
	do_settimeofday(&time);

	return 0;
}

#else
#define rtc_suspend	NULL
#define rtc_resume	NULL
	struct timespec64	new_system, new_rtc;
	struct timespec64	sleep_time;
	int err;

	if (timekeeping_rtc_skipresume())
		return 0;

	rtc_hctosys_ret = -ENODEV;
	if (strcmp(dev_name(&rtc->dev), CONFIG_RTC_HCTOSYS_DEVICE) != 0)
		return 0;

	/* snapshot the current rtc and system time at resume */
	getnstimeofday64(&new_system);
	err = rtc_read_time(rtc, &tm);
	if (err < 0) {
		pr_debug("%s:  fail to read rtc time\n", dev_name(&rtc->dev));
		return 0;
	}

	new_rtc.tv_sec = rtc_tm_to_time64(&tm);
	new_rtc.tv_nsec = 0;

	if (new_rtc.tv_sec < old_rtc.tv_sec) {
		pr_debug("%s:  time travel!\n", dev_name(&rtc->dev));
		return 0;
	}

	/* calculate the RTC time delta (sleep time)*/
	sleep_time = timespec64_sub(new_rtc, old_rtc);

	/*
	 * Since these RTC suspend/resume handlers are not called
	 * at the very end of suspend or the start of resume,
	 * some run-time may pass on either sides of the sleep time
	 * so subtract kernel run-time between rtc_suspend to rtc_resume
	 * to keep things accurate.
	 */
	sleep_time = timespec64_sub(sleep_time,
			timespec64_sub(new_system, old_system));

	if (sleep_time.tv_sec >= 0)
		timekeeping_inject_sleeptime64(&sleep_time);
	rtc_hctosys_ret = 0;
	return 0;
}

static SIMPLE_DEV_PM_OPS(rtc_class_dev_pm_ops, rtc_suspend, rtc_resume);
#define RTC_CLASS_DEV_PM_OPS	(&rtc_class_dev_pm_ops)
#else
#define RTC_CLASS_DEV_PM_OPS	NULL
#endif

/* Ensure the caller will set the id before releasing the device */
static struct rtc_device *rtc_allocate_device(void)
{
	struct rtc_device *rtc;
	int id, err;

	if (idr_pre_get(&rtc_idr, GFP_KERNEL) == 0) {
		err = -ENOMEM;
		goto exit;
	}


	mutex_lock(&idr_lock);
	err = idr_get_new(&rtc_idr, NULL, &id);
	mutex_unlock(&idr_lock);

	if (err < 0)
		goto exit;

	id = id & MAX_ID_MASK;
	struct rtc_wkalrm alrm;
	int of_id = -1, id = -1, err;

	rtc = kzalloc(sizeof(*rtc), GFP_KERNEL);
	if (!rtc)
		return NULL;

	device_initialize(&rtc->dev);

	if (id < 0) {
		id = ida_simple_get(&rtc_ida, 0, 0, GFP_KERNEL);
		if (id < 0) {
			err = id;
			goto exit;
		}
	}

	rtc = kzalloc(sizeof(struct rtc_device), GFP_KERNEL);
	if (rtc == NULL) {
		err = -ENOMEM;
		goto exit_idr;
		goto exit_ida;
	}

	rtc->id = id;
	rtc->ops = ops;
	rtc->owner = owner;
	rtc->max_user_freq = 64;
	rtc->dev.parent = dev;
	rtc->dev.class = rtc_class;
	rtc->irq_freq = 1;
	rtc->max_user_freq = 64;
	rtc->dev.class = rtc_class;
	rtc->dev.groups = rtc_get_dev_attribute_groups();
	rtc->dev.release = rtc_device_release;

	mutex_init(&rtc->ops_lock);
	spin_lock_init(&rtc->irq_lock);
	spin_lock_init(&rtc->irq_task_lock);
	init_waitqueue_head(&rtc->irq_queue);

	strlcpy(rtc->name, name, RTC_DEVICE_NAME_SIZE);
	snprintf(rtc->dev.bus_id, BUS_ID_SIZE, "rtc%d", id);
	/* Init timerqueue */
	timerqueue_init_head(&rtc->timerqueue);
	INIT_WORK(&rtc->irqwork, rtc_timer_do_work);
	/* Init aie timer */
	rtc_timer_init(&rtc->aie_timer, rtc_aie_update_irq, (void *)rtc);
	/* Init uie timer */
	rtc_timer_init(&rtc->uie_rtctimer, rtc_uie_update_irq, (void *)rtc);
	/* Init pie timer */
	hrtimer_init(&rtc->pie_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	rtc->pie_timer.function = rtc_pie_update_irq;
	rtc->pie_enabled = 0;

	return rtc;
}

static int rtc_device_get_id(struct device *dev)
{
	int of_id = -1, id = -1;

	if (dev->of_node)
		of_id = of_alias_get_id(dev->of_node, "rtc");
	else if (dev->parent && dev->parent->of_node)
		of_id = of_alias_get_id(dev->parent->of_node, "rtc");

	if (of_id >= 0) {
		id = ida_simple_get(&rtc_ida, of_id, of_id + 1, GFP_KERNEL);
		if (id < 0)
			dev_warn(dev, "/aliases ID %d not available\n", of_id);
	}

	if (id < 0)
		id = ida_simple_get(&rtc_ida, 0, 0, GFP_KERNEL);

	return id;
}

/**
 * rtc_device_register - register w/ RTC class
 * @dev: the device to register
 *
 * rtc_device_unregister() must be called when the class device is no
 * longer needed.
 *
 * Returns the pointer to the new struct class device.
 */
struct rtc_device *rtc_device_register(const char *name, struct device *dev,
					const struct rtc_class_ops *ops,
					struct module *owner)
{
	struct rtc_device *rtc;
	struct rtc_wkalrm alrm;
	int id, err;

	id = rtc_device_get_id(dev);
	if (id < 0) {
		err = id;
		goto exit;
	}

	rtc = rtc_allocate_device();
	if (!rtc) {
		err = -ENOMEM;
		goto exit_ida;
	}

	rtc->id = id;
	rtc->ops = ops;
	rtc->owner = owner;
	rtc->dev.parent = dev;

	dev_set_name(&rtc->dev, "rtc%d", id);

	/* Check to see if there is an ALARM already set in hw */
	err = __rtc_read_alarm(rtc, &alrm);

	if (!err && !rtc_valid_tm(&alrm.time))
		rtc_initialize_alarm(rtc, &alrm);

	rtc_dev_prepare(rtc);

	err = device_register(&rtc->dev);
	if (err)
		goto exit_kfree;

	rtc_dev_add_device(rtc);
	rtc_sysfs_add_device(rtc);
	rtc_proc_add_device(rtc);

	dev_info(dev, "rtc core: registered %s as %s\n",
			rtc->name, rtc->dev.bus_id);

	return rtc;

exit_kfree:
	kfree(rtc);

exit_idr:
	mutex_lock(&idr_lock);
	idr_remove(&rtc_idr, id);
	mutex_unlock(&idr_lock);
	err = cdev_device_add(&rtc->char_dev, &rtc->dev);
	if (err) {
		dev_warn(&rtc->dev, "%s: failed to add char device %d:%d\n",
			 name, MAJOR(rtc->dev.devt), rtc->id);

		/* This will free both memory and the ID */
		put_device(&rtc->dev);
		goto exit;
	} else {
		dev_dbg(&rtc->dev, "%s: dev (%d:%d)\n", name,
			MAJOR(rtc->dev.devt), rtc->id);
	}

	rtc_proc_add_device(rtc);

	dev_info(dev, "rtc core: registered %s as %s\n",
			name, dev_name(&rtc->dev));

	return rtc;

exit_ida:
	ida_simple_remove(&rtc_ida, id);

exit:
	dev_err(dev, "rtc core: unable to register %s, err = %d\n",
			name, err);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rtc_device_register);


/**
 * rtc_device_unregister - removes the previously registered RTC class device
 *
 * @rtc: the RTC class device to destroy
 */
void rtc_device_unregister(struct rtc_device *rtc)
{
	if (get_device(&rtc->dev) != NULL) {
		mutex_lock(&rtc->ops_lock);
		/* remove innards of this RTC, then disable it, before
		 * letting any rtc_class_open() users access it again
		 */
		rtc_sysfs_del_device(rtc);
		rtc_dev_del_device(rtc);
		rtc_proc_del_device(rtc);
		device_unregister(&rtc->dev);
		rtc->ops = NULL;
		mutex_unlock(&rtc->ops_lock);
		put_device(&rtc->dev);
	}
}
EXPORT_SYMBOL_GPL(rtc_device_unregister);
	rtc_nvmem_unregister(rtc);

	mutex_lock(&rtc->ops_lock);
	/*
	 * Remove innards of this RTC, then disable it, before
	 * letting any rtc_class_open() users access it again
	 */
	rtc_proc_del_device(rtc);
	cdev_device_del(&rtc->char_dev, &rtc->dev);
	rtc->ops = NULL;
	mutex_unlock(&rtc->ops_lock);
	put_device(&rtc->dev);
}
EXPORT_SYMBOL_GPL(rtc_device_unregister);

static void devm_rtc_device_release(struct device *dev, void *res)
{
	struct rtc_device *rtc = *(struct rtc_device **)res;

	rtc_device_unregister(rtc);
}

static int devm_rtc_device_match(struct device *dev, void *res, void *data)
{
	struct rtc **r = res;

	return *r == data;
}

/**
 * devm_rtc_device_register - resource managed rtc_device_register()
 * @dev: the device to register
 * @name: the name of the device
 * @ops: the rtc operations structure
 * @owner: the module owner
 *
 * @return a struct rtc on success, or an ERR_PTR on error
 *
 * Managed rtc_device_register(). The rtc_device returned from this function
 * are automatically freed on driver detach. See rtc_device_register()
 * for more information.
 */

struct rtc_device *devm_rtc_device_register(struct device *dev,
					const char *name,
					const struct rtc_class_ops *ops,
					struct module *owner)
{
	struct rtc_device **ptr, *rtc;

	ptr = devres_alloc(devm_rtc_device_release, sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	rtc = rtc_device_register(name, dev, ops, owner);
	if (!IS_ERR(rtc)) {
		*ptr = rtc;
		devres_add(dev, ptr);
	} else {
		devres_free(ptr);
	}

	return rtc;
}
EXPORT_SYMBOL_GPL(devm_rtc_device_register);

/**
 * devm_rtc_device_unregister - resource managed devm_rtc_device_unregister()
 * @dev: the device to unregister
 * @rtc: the RTC class device to unregister
 *
 * Deallocated a rtc allocated with devm_rtc_device_register(). Normally this
 * function will not need to be called and the resource management code will
 * ensure that the resource is freed.
 */
void devm_rtc_device_unregister(struct device *dev, struct rtc_device *rtc)
{
	int rc;

	rc = devres_release(dev, devm_rtc_device_release,
				devm_rtc_device_match, rtc);
	WARN_ON(rc);
}
EXPORT_SYMBOL_GPL(devm_rtc_device_unregister);

static void devm_rtc_release_device(struct device *dev, void *res)
{
	struct rtc_device *rtc = *(struct rtc_device **)res;

	if (rtc->registered)
		rtc_device_unregister(rtc);
	else
		put_device(&rtc->dev);
}

struct rtc_device *devm_rtc_allocate_device(struct device *dev)
{
	struct rtc_device **ptr, *rtc;
	int id, err;

	id = rtc_device_get_id(dev);
	if (id < 0)
		return ERR_PTR(id);

	ptr = devres_alloc(devm_rtc_release_device, sizeof(*ptr), GFP_KERNEL);
	if (!ptr) {
		err = -ENOMEM;
		goto exit_ida;
	}

	rtc = rtc_allocate_device();
	if (!rtc) {
		err = -ENOMEM;
		goto exit_devres;
	}

	*ptr = rtc;
	devres_add(dev, ptr);

	rtc->id = id;
	rtc->dev.parent = dev;
	dev_set_name(&rtc->dev, "rtc%d", id);

	return rtc;

exit_devres:
	devres_free(ptr);
exit_ida:
	ida_simple_remove(&rtc_ida, id);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(devm_rtc_allocate_device);

int __rtc_register_device(struct module *owner, struct rtc_device *rtc)
{
	struct rtc_wkalrm alrm;
	int err;

	if (!rtc->ops)
		return -EINVAL;

	rtc->owner = owner;

	/* Check to see if there is an ALARM already set in hw */
	err = __rtc_read_alarm(rtc, &alrm);
	if (!err && !rtc_valid_tm(&alrm.time))
		rtc_initialize_alarm(rtc, &alrm);

	rtc_dev_prepare(rtc);

	err = cdev_device_add(&rtc->char_dev, &rtc->dev);
	if (err)
		dev_warn(rtc->dev.parent, "failed to add char device %d:%d\n",
			 MAJOR(rtc->dev.devt), rtc->id);
	else
		dev_dbg(rtc->dev.parent, "char device (%d:%d)\n",
			MAJOR(rtc->dev.devt), rtc->id);

	rtc_proc_add_device(rtc);

	rtc_nvmem_register(rtc);

	rtc->registered = true;
	dev_info(rtc->dev.parent, "registered as %s\n",
		 dev_name(&rtc->dev));

	return 0;
}
EXPORT_SYMBOL_GPL(__rtc_register_device);

static int __init rtc_init(void)
{
	rtc_class = class_create(THIS_MODULE, "rtc");
	if (IS_ERR(rtc_class)) {
		printk(KERN_ERR "%s: couldn't create class\n", __FILE__);
		return PTR_ERR(rtc_class);
	}
	rtc_class->suspend = rtc_suspend;
	rtc_class->resume = rtc_resume;
	rtc_dev_init();
	rtc_sysfs_init(rtc_class);
		pr_err("couldn't create class\n");
		return PTR_ERR(rtc_class);
	}
	rtc_class->pm = RTC_CLASS_DEV_PM_OPS;
	rtc_dev_init();
	return 0;
}
subsys_initcall(rtc_init);
