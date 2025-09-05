/*
 * An RTC test device/driver
 * Copyright (C) 2005 Tower Technologies
 * Author: Alessandro Zummo <a.zummo@towertech.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/err.h>
#include <linux/rtc.h>
#include <linux/platform_device.h>

#define MAX_RTC_TEST 3

struct rtc_test_data {
	struct rtc_device *rtc;
	time64_t offset;
	struct timer_list alarm;
	bool alarm_en;
};

static struct platform_device *pdev[MAX_RTC_TEST];

static int test_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct rtc_test_data *rtd = dev_get_drvdata(dev);
	time64_t alarm;

	alarm = (rtd->alarm.expires - jiffies) / HZ;
	alarm += ktime_get_real_seconds() + rtd->offset;

	rtc_time64_to_tm(alarm, &alrm->time);
	alrm->enabled = rtd->alarm_en;

	return 0;
}

static int test_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct rtc_test_data *rtd = dev_get_drvdata(dev);
	ktime_t timeout;
	u64 expires;

	timeout = rtc_tm_to_time64(&alrm->time) - ktime_get_real_seconds();
	timeout -= rtd->offset;

	del_timer(&rtd->alarm);

	expires = jiffies + timeout * HZ;
	if (expires > U32_MAX)
		expires = U32_MAX;

	pr_err("ABE: %s +%d %s\n", __FILE__, __LINE__, __func__);
	rtd->alarm.expires = expires;

	if (alrm->enabled)
		add_timer(&rtd->alarm);

	rtd->alarm_en = alrm->enabled;

	return 0;
}

static int test_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	rtc_time_to_tm(get_seconds(), tm);
	return 0;
}

static int test_rtc_set_time(struct device *dev,
	struct rtc_time *tm)
{
	rtc_time64_to_tm(ktime_get_real_seconds(), tm);
	struct rtc_test_data *rtd = dev_get_drvdata(dev);

	rtc_time64_to_tm(ktime_get_real_seconds() + rtd->offset, tm);

	return 0;
}

static int test_rtc_set_mmss64(struct device *dev, time64_t secs)
{
	struct rtc_test_data *rtd = dev_get_drvdata(dev);

	rtd->offset = secs - ktime_get_real_seconds();

	return 0;
}

static int test_rtc_ioctl(struct device *dev, unsigned int cmd,
	unsigned long arg)
{
	/* We do support interrupts, they're generated
	 * using the sysfs interface.
	 */
	switch (cmd) {
	case RTC_PIE_ON:
	case RTC_PIE_OFF:
	case RTC_UIE_ON:
	case RTC_UIE_OFF:
	case RTC_AIE_ON:
	case RTC_AIE_OFF:
		return 0;

	default:
		return -ENOIOCTLCMD;
	}
}

static const struct rtc_class_ops test_rtc_ops = {
	.proc = test_rtc_proc,
	.read_time = test_rtc_read_time,
	.set_time = test_rtc_set_time,
	.read_alarm = test_rtc_read_alarm,
	.set_alarm = test_rtc_set_alarm,
	.set_mmss = test_rtc_set_mmss,
	.ioctl = test_rtc_ioctl,
static int test_rtc_alarm_irq_enable(struct device *dev, unsigned int enable)
{
	struct rtc_test_data *rtd = dev_get_drvdata(dev);

	rtd->alarm_en = enable;
	if (enable)
		add_timer(&rtd->alarm);
	else
		del_timer(&rtd->alarm);

	return 0;
}

static const struct rtc_class_ops test_rtc_ops_noalm = {
	.read_time = test_rtc_read_time,
	.set_mmss64 = test_rtc_set_mmss64,
	.alarm_irq_enable = test_rtc_alarm_irq_enable,
};

static const struct rtc_class_ops test_rtc_ops = {
	.read_time = test_rtc_read_time,
	.read_alarm = test_rtc_read_alarm,
	.set_alarm = test_rtc_set_alarm,
	.set_mmss64 = test_rtc_set_mmss64,
	.alarm_irq_enable = test_rtc_alarm_irq_enable,
};

static void test_rtc_alarm_handler(struct timer_list *t)
{
	struct rtc_test_data *rtd = from_timer(rtd, t, alarm);

	rtc_update_irq(rtd->rtc, 1, RTC_AF | RTC_IRQF);
}
static ssize_t test_irq_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int retval;
	struct platform_device *plat_dev = to_platform_device(dev);
	struct rtc_device *rtc = platform_get_drvdata(plat_dev);

	retval = count;
	local_irq_disable();
	if (strncmp(buf, "tick", 4) == 0)
		rtc_update_irq(rtc, 1, RTC_PF | RTC_IRQF);
	else if (strncmp(buf, "alarm", 5) == 0)
		rtc_update_irq(rtc, 1, RTC_AF | RTC_IRQF);
	else if (strncmp(buf, "update", 6) == 0)
		rtc_update_irq(rtc, 1, RTC_UF | RTC_IRQF);
	else
		retval = -EINVAL;
	local_irq_enable();
	if (strncmp(buf, "tick", 4) == 0 && rtc->pie_enabled)
		rtc_update_irq(rtc, 1, RTC_PF | RTC_IRQF);
	else if (strncmp(buf, "alarm", 5) == 0) {
		struct rtc_wkalrm alrm;
		int err = rtc_read_alarm(rtc, &alrm);

		if (!err && alrm.enabled)
			rtc_update_irq(rtc, 1, RTC_AF | RTC_IRQF);

	} else if (strncmp(buf, "update", 6) == 0 && rtc->uie_rtctimer.enabled)
		rtc_update_irq(rtc, 1, RTC_UF | RTC_IRQF);
	else
		retval = -EINVAL;

	return retval;
}
static DEVICE_ATTR(irq, S_IRUGO | S_IWUSR, test_irq_show, test_irq_store);

static int test_probe(struct platform_device *plat_dev)
{
	int err;
	struct rtc_device *rtc = rtc_device_register("test", &plat_dev->dev,
						&test_rtc_ops, THIS_MODULE);
	if (IS_ERR(rtc)) {
		err = PTR_ERR(rtc);
		return err;
	struct rtc_device *rtc;

static int test_probe(struct platform_device *plat_dev)
{
	struct rtc_test_data *rtd;

	rtd = devm_kzalloc(&plat_dev->dev, sizeof(*rtd), GFP_KERNEL);
	if (!rtd)
		return -ENOMEM;

	platform_set_drvdata(plat_dev, rtd);

	rtd->rtc = devm_rtc_allocate_device(&plat_dev->dev);
	if (IS_ERR(rtd->rtc))
		return PTR_ERR(rtd->rtc);

	switch (plat_dev->id) {
	case 0:
		rtd->rtc->ops = &test_rtc_ops_noalm;
		break;
	default:
		rtd->rtc->ops = &test_rtc_ops;
	}

	timer_setup(&rtd->alarm, test_rtc_alarm_handler, 0);
	rtd->alarm.expires = 0;

	err = device_create_file(&plat_dev->dev, &dev_attr_irq);
	if (err)
		goto err;
		dev_err(&plat_dev->dev, "Unable to create sysfs entry: %s\n",
			dev_attr_irq.attr.name);

	platform_set_drvdata(plat_dev, rtc);

	return 0;

err:
	rtc_device_unregister(rtc);
	return err;
}

static int __devexit test_remove(struct platform_device *plat_dev)
{
	struct rtc_device *rtc = platform_get_drvdata(plat_dev);

	rtc_device_unregister(rtc);
}

static int test_remove(struct platform_device *plat_dev)
{
	device_remove_file(&plat_dev->dev, &dev_attr_irq);

	return 0;
	return rtc_register_device(rtd->rtc);
}

static struct platform_driver test_driver = {
	.probe	= test_probe,
	.remove = __devexit_p(test_remove),
	.driver = {
		.name = "rtc-test",
		.owner = THIS_MODULE,
	.remove = test_remove,
	.driver = {
		.name = "rtc-test",
	},
};

static int __init test_init(void)
{
	int i, err;

	if ((err = platform_driver_register(&test_driver)))
		return err;

	err = -ENOMEM;
	for (i = 0; i < MAX_RTC_TEST; i++) {
		pdev[i] = platform_device_alloc("rtc-test", i);
		if (!pdev[i])
			goto exit_free_mem;
	}

	if ((test1 = platform_device_alloc("rtc-test", 1)) == NULL) {
		err = -ENOMEM;
		goto exit_free_test0;
	}

	if ((err = platform_device_add(test0)))
		goto exit_free_test1;

	if ((err = platform_device_add(test1)))
		goto exit_device_unregister;

	return 0;

exit_device_unregister:
	platform_device_unregister(test0);

exit_free_test1:
	platform_device_put(test1);

exit_free_test0:
		goto exit_put_test0;
	for (i = 0; i < MAX_RTC_TEST; i++) {
		err = platform_device_add(pdev[i]);
		if (err)
			goto exit_device_del;
	}

	return 0;

exit_device_del:
	for (; i > 0; i--)
		platform_device_del(pdev[i - 1]);

exit_free_mem:
	for (i = 0; i < MAX_RTC_TEST; i++)
		platform_device_put(pdev[i]);

	platform_driver_unregister(&test_driver);
	return err;
}

static void __exit test_exit(void)
{
	int i;

	for (i = 0; i < MAX_RTC_TEST; i++)
		platform_device_unregister(pdev[i]);

	platform_driver_unregister(&test_driver);
}

MODULE_AUTHOR("Alessandro Zummo <a.zummo@towertech.it>");
MODULE_DESCRIPTION("RTC test driver/device");
MODULE_LICENSE("GPL");

module_init(test_init);
module_exit(test_exit);
