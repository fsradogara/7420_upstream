/*
 *	i6300esb:	Watchdog timer driver for Intel 6300ESB chipset
 *
 *	(c) Copyright 2004 Google Inc.
 *	(c) Copyright 2005 David Härdeman <david@2gen.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *	based on i810-tco.c which is in turn based on softdog.c
 *
 *	The timer is implemented in the following I/O controller hubs:
 *	(See the intel documentation on http://developer.intel.com.)
 *	6300ESB chip : document number 300641-003
 *	6300ESB chip : document number 300641-004
 *
 *  2004YYZZ Ross Biro
 *	Initial version 0.01
 *  2004YYZZ Ross Biro
 *	Version 0.02
 *  20050210 David Härdeman <david@2gen.com>
 *	Ported driver to kernel 2.6
 *  20171016 Radu Rendec <rrendec@arista.com>
 *	Change driver to use the watchdog subsystem
 *	Add support for multiple 6300ESB devices
 */

/*
 *      Includes, defines, variables, module parameters, ...
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/watchdog.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/uaccess.h>
#include <linux/io.h>

/* Module and version information */
#define ESB_VERSION "0.03"
#define ESB_MODULE_NAME "i6300ESB timer"
#define ESB_DRIVER_NAME ESB_MODULE_NAME ", v" ESB_VERSION
#define PFX ESB_MODULE_NAME ": "
#define ESB_VERSION "0.05"
#define ESB_MODULE_NAME "i6300ESB timer"

/* PCI configuration registers */
#define ESB_CONFIG_REG  0x60            /* Config register                   */
#define ESB_LOCK_REG    0x68            /* WDT lock register                 */

/* Memory mapped registers */
#define ESB_TIMER1_REG  BASEADDR + 0x00 /* Timer1 value after each reset     */
#define ESB_TIMER2_REG  BASEADDR + 0x04 /* Timer2 value after each reset     */
#define ESB_GINTSR_REG  BASEADDR + 0x08 /* General Interrupt Status Register */
#define ESB_RELOAD_REG  BASEADDR + 0x0c /* Reload register                   */
#define ESB_TIMER1_REG (BASEADDR + 0x00)/* Timer1 value after each reset     */
#define ESB_TIMER2_REG (BASEADDR + 0x04)/* Timer2 value after each reset     */
#define ESB_GINTSR_REG (BASEADDR + 0x08)/* General Interrupt Status Register */
#define ESB_RELOAD_REG (BASEADDR + 0x0c)/* Reload register                   */
#define ESB_TIMER1_REG(w) ((w)->base + 0x00)/* Timer1 value after each reset */
#define ESB_TIMER2_REG(w) ((w)->base + 0x04)/* Timer2 value after each reset */
#define ESB_GINTSR_REG(w) ((w)->base + 0x08)/* General Interrupt Status Reg  */
#define ESB_RELOAD_REG(w) ((w)->base + 0x0c)/* Reload register               */

/* Lock register bits */
#define ESB_WDT_FUNC    (0x01 << 2)   /* Watchdog functionality            */
#define ESB_WDT_ENABLE  (0x01 << 1)   /* Enable WDT                        */
#define ESB_WDT_LOCK    (0x01 << 0)   /* Lock (nowayout)                   */

/* Config register bits */
#define ESB_WDT_REBOOT  (0x01 << 5)   /* Enable reboot on timeout          */
#define ESB_WDT_FREQ    (0x01 << 2)   /* Decrement frequency               */
#define ESB_WDT_INTTYPE (0x11 << 0)   /* Interrupt type on timer1 timeout  */

/* Reload register bits */
#define ESB_WDT_INTTYPE (0x03 << 0)   /* Interrupt type on timer1 timeout  */

/* Reload register bits */
#define ESB_WDT_TIMEOUT (0x01 << 9)    /* Watchdog timed out                */
#define ESB_WDT_RELOAD  (0x01 << 8)    /* prevent timeout                   */

/* Magic constants */
#define ESB_UNLOCK1     0x80            /* Step 1 to unlock reset registers  */
#define ESB_UNLOCK2     0x86            /* Step 2 to unlock reset registers  */

/* module parameters */
/* 30 sec default heartbeat (1 < heartbeat < 2*1023) */
#define WATCHDOG_HEARTBEAT 30
static int heartbeat = WATCHDOG_HEARTBEAT;  /* in seconds */

#define ESB_HEARTBEAT_MIN	1
#define ESB_HEARTBEAT_MAX	2046
#define ESB_HEARTBEAT_DEFAULT	30
#define ESB_HEARTBEAT_RANGE __MODULE_STRING(ESB_HEARTBEAT_MIN) \
	"<heartbeat<" __MODULE_STRING(ESB_HEARTBEAT_MAX)
static int heartbeat; /* in seconds */
module_param(heartbeat, int, 0);
MODULE_PARM_DESC(heartbeat,
	"Watchdog heartbeat in seconds. (" ESB_HEARTBEAT_RANGE
	", default=" __MODULE_STRING(ESB_HEARTBEAT_DEFAULT) ")");

static int nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, int, 0);
static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0);
MODULE_PARM_DESC(nowayout,
		"Watchdog cannot be stopped once started (default="
				__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

/* internal variables */
struct esb_dev {
	struct watchdog_device wdd;
	void __iomem *base;
	struct pci_dev *pdev;
};

#define to_esb_dev(wptr) container_of(wptr, struct esb_dev, wdd)

/*
 * Some i6300ESB specific functions
 */

/*
 * Prepare for reloading the timer by unlocking the proper registers.
 * This is performed by first writing 0x80 followed by 0x86 to the
 * reload register. After this the appropriate registers can be written
 * to once before they need to be unlocked again.
 */
static inline void esb_unlock_registers(struct esb_dev *edev)
{
	writeb(ESB_UNLOCK1, ESB_RELOAD_REG);
	writeb(ESB_UNLOCK2, ESB_RELOAD_REG);
}

static void esb_timer_start(void)
{
	u8 val;

	/* Enable or Enable + Lock? */
	val = 0x02 | (nowayout ? 0x01 : 0x00);
	pci_write_config_byte(esb_pci, ESB_LOCK_REG, val);
	writew(ESB_UNLOCK1, ESB_RELOAD_REG);
	writew(ESB_UNLOCK2, ESB_RELOAD_REG);
	writew(ESB_UNLOCK1, ESB_RELOAD_REG(edev));
	writew(ESB_UNLOCK2, ESB_RELOAD_REG(edev));
}

static int esb_timer_start(struct watchdog_device *wdd)
{
	struct esb_dev *edev = to_esb_dev(wdd);
	int _wdd_nowayout = test_bit(WDOG_NO_WAY_OUT, &wdd->status);
	u8 val;

	esb_unlock_registers(edev);
	writew(ESB_WDT_RELOAD, ESB_RELOAD_REG(edev));
	/* Enable or Enable + Lock? */
	val = ESB_WDT_ENABLE | (_wdd_nowayout ? ESB_WDT_LOCK : 0x00);
	pci_write_config_byte(edev->pdev, ESB_LOCK_REG, val);
	return 0;
}

static int esb_timer_stop(struct watchdog_device *wdd)
{
	struct esb_dev *edev = to_esb_dev(wdd);
	u8 val;

	/* First, reset timers as suggested by the docs */
	esb_unlock_registers(edev);
	writew(ESB_WDT_RELOAD, ESB_RELOAD_REG(edev));
	/* Then disable the WDT */
	pci_write_config_byte(edev->pdev, ESB_LOCK_REG, 0x0);
	pci_read_config_byte(edev->pdev, ESB_LOCK_REG, &val);

	/* Returns 0 if the timer was disabled, non-zero otherwise */
	return (val & 0x01);
	return val & ESB_WDT_ENABLE;
}

static int esb_timer_keepalive(struct watchdog_device *wdd)
{
	struct esb_dev *edev = to_esb_dev(wdd);

	esb_unlock_registers(edev);
	writew(ESB_WDT_RELOAD, ESB_RELOAD_REG(edev));
	/* FIXME: Do we need to flush anything here? */
	return 0;
}

static int esb_timer_set_heartbeat(struct watchdog_device *wdd,
		unsigned int time)
{
	struct esb_dev *edev = to_esb_dev(wdd);
	u32 val;

	/* We shift by 9, so if we are passed a value of 1 sec,
	 * val will be 1 << 9 = 512, then write that to two
	 * timers => 2 * 512 = 1024 (which is decremented at 1KHz)
	 */
	val = time << 9;

	/* Write timer 1 */
	esb_unlock_registers(edev);
	writel(val, ESB_TIMER1_REG(edev));

	/* Write timer 2 */
	esb_unlock_registers(edev);
	writel(val, ESB_TIMER2_REG(edev));

	/* Reload */
	esb_unlock_registers(edev);
	writew(ESB_WDT_RELOAD, ESB_RELOAD_REG(edev));

	/* FIXME: Do we need to flush everything out? */

	/* Done */
	wdd->timeout = time;
	return 0;
}

static int esb_timer_read(void)
{
	u32 count;

	/* This isn't documented, and doesn't take into
	 * acount which stage is running, but it looks
	 * like a 20 bit count down, so we might as well report it.
	 */
	pci_read_config_dword(esb_pci, 0x64, &count);
	return (int)count;
}

/*
 * Watchdog Subsystem Interfaces
 */

static int esb_open(struct inode *inode, struct file *file)
{
	/* /dev/watchdog can only be opened once */
	if (test_and_set_bit(0, &timer_alive))
		return -EBUSY;

	/* Reload and activate timer */
	esb_timer_keepalive();
	esb_timer_start();

	return nonseekable_open(inode, file);
}

static int esb_release(struct inode *inode, struct file *file)
{
	/* Shut off the timer. */
	if (esb_expect_close == 42)
		esb_timer_stop();
	else {
		printk(KERN_CRIT PFX
				"Unexpected close, not stopping watchdog!\n");
		pr_crit("Unexpected close, not stopping watchdog!\n");
		esb_timer_keepalive();
	}
	clear_bit(0, &timer_alive);
	esb_expect_close = 0;
	return 0;
}

static ssize_t esb_write(struct file *file, const char __user *data,
			  size_t len, loff_t *ppos)
{
	/* See if we got the magic character 'V' and reload the timer */
	if (len) {
		if (!nowayout) {
			size_t i;

			/* note: just in case someone wrote the magic character
			 * five months ago... */
			esb_expect_close = 0;

			/* scan to see whether or not we got the magic character */
			/* scan to see whether or not we got the
			 * magic character */
			for (i = 0; i != len; i++) {
				char c;
				if (get_user(c, data + i))
					return -EFAULT;
				if (c == 'V')
					esb_expect_close = 42;
			}
		}

		/* someone wrote to us, we should reload the timer */
		esb_timer_keepalive();
	}
	return len;
}

static long esb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int new_options, retval = -EINVAL;
	int new_heartbeat;
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	static struct watchdog_info ident = {
	static const struct watchdog_info ident = {
		.options =		WDIOF_SETTIMEOUT |
					WDIOF_KEEPALIVEPING |
					WDIOF_MAGICCLOSE,
		.firmware_version =	0,
		.identity =		ESB_MODULE_NAME,
	};

	switch (cmd) {
	case WDIOC_GETSUPPORT:
		return copy_to_user(argp, &ident,
					sizeof(ident)) ? -EFAULT : 0;

	case WDIOC_GETSTATUS:
		return put_user(esb_timer_read(), p);
		return put_user(0, p);

	case WDIOC_GETBOOTSTATUS:
		return put_user(triggered, p);

	case WDIOC_SETOPTIONS:
	{
		if (get_user(new_options, p))
			return -EFAULT;

		if (new_options & WDIOS_DISABLECARD) {
			esb_timer_stop();
			retval = 0;
		}

		if (new_options & WDIOS_ENABLECARD) {
			esb_timer_keepalive();
			esb_timer_start();
			retval = 0;
		}
		return retval;
	}
	case WDIOC_KEEPALIVE:
		esb_timer_keepalive();
		return 0;

	case WDIOC_SETTIMEOUT:
	{
		if (get_user(new_heartbeat, p))
			return -EFAULT;
		if (esb_timer_set_heartbeat(new_heartbeat))
			return -EINVAL;
		esb_timer_keepalive();
		/* Fall */
	}
	case WDIOC_GETTIMEOUT:
		return put_user(heartbeat, p);
	default:
		return -ENOTTY;
	}
}

/*
 *      Notify system
 */

static int esb_notify_sys(struct notifier_block *this,
					unsigned long code, void *unused)
{
	if (code == SYS_DOWN || code == SYS_HALT)
		esb_timer_stop();	/* Turn the WDT off */

	return NOTIFY_DONE;
}

/*
 *      Kernel Interfaces
 */

static const struct file_operations esb_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.write = esb_write,
	.unlocked_ioctl = esb_ioctl,
	.open = esb_open,
	.release = esb_release,
static struct watchdog_info esb_info = {
	.identity = ESB_MODULE_NAME,
	.options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
};

static const struct watchdog_ops esb_ops = {
	.owner = THIS_MODULE,
	.start = esb_timer_start,
	.stop = esb_timer_stop,
	.set_timeout = esb_timer_set_heartbeat,
	.ping = esb_timer_keepalive,
};

static struct notifier_block esb_notifier = {
	.notifier_call = esb_notify_sys,
};

/*
 * Data for PCI driver interface
 *
 * This data only exists for exporting the supported
 * PCI ids via MODULE_DEVICE_TABLE.  We do not actually
 * register a pci_driver, because someone else might one day
 * want to register another driver on the same PCI id.
 */
static struct pci_device_id esb_pci_tbl[] = {
/*
 * Data for PCI driver interface
 */
static const struct pci_device_id esb_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ESB_9), },
	{ 0, },                 /* End of list */
};
MODULE_DEVICE_TABLE(pci, esb_pci_tbl);

/*
 *      Init & exit routines
 */

static unsigned char __init esb_getdevice(void)
{
	u8 val1;
	unsigned short val2;
	/*
	 *      Find the PCI device
	 */

	esb_pci = pci_get_device(PCI_VENDOR_ID_INTEL,
					PCI_DEVICE_ID_INTEL_ESB_9, NULL);

	if (esb_pci) {
		if (pci_enable_device(esb_pci)) {
			printk(KERN_ERR PFX "failed to enable device\n");
			goto err_devput;
		}

		if (pci_request_region(esb_pci, 0, ESB_MODULE_NAME)) {
			printk(KERN_ERR PFX "failed to request region\n");
			goto err_disable;
		}

		BASEADDR = ioremap(pci_resource_start(esb_pci, 0),
				   pci_resource_len(esb_pci, 0));
		if (BASEADDR == NULL) {
			/* Something's wrong here, BASEADDR has to be set */
			printk(KERN_ERR PFX "failed to get BASEADDR\n");
			goto err_release;
		}

		/*
		 * The watchdog has two timers, it can be setup so that the
		 * expiry of timer1 results in an interrupt and the expiry of
		 * timer2 results in a reboot. We set it to not generate
		 * any interrupts as there is not much we can do with it
		 * right now.
		 *
		 * We also enable reboots and set the timer frequency to
		 * the PCI clock divided by 2^15 (approx 1KHz).
		 */
		pci_write_config_word(esb_pci, ESB_CONFIG_REG, 0x0003);

		/* Check that the WDT isn't already locked */
		pci_read_config_byte(esb_pci, ESB_LOCK_REG, &val1);
		if (val1 & ESB_WDT_LOCK)
			printk(KERN_WARNING PFX "nowayout already set\n");

		/* Set the timer to watchdog mode and disable it for now */
		pci_write_config_byte(esb_pci, ESB_LOCK_REG, 0x00);

		/* Check if the watchdog was previously triggered */
		esb_unlock_registers();
		val2 = readw(ESB_RELOAD_REG);
		triggered = (val2 & (0x01 << 9) >> 9);

		/* Reset trigger flag and timers */
		esb_unlock_registers();
		writew((0x11 << 8), ESB_RELOAD_REG);

		/* Done */
		return 1;

err_release:
		pci_release_region(esb_pci, 0);
err_disable:
		pci_disable_device(esb_pci);
err_devput:
		pci_dev_put(esb_pci);
	}
	return 0;
}

static int __init watchdog_init(void)
{
	int ret;

	/* Check whether or not the hardware watchdog is there */
	if (!esb_getdevice() || esb_pci == NULL)
static unsigned char esb_getdevice(struct pci_dev *pdev)
static unsigned char esb_getdevice(struct esb_dev *edev)
{
	if (pci_enable_device(edev->pdev)) {
		dev_err(&edev->pdev->dev, "failed to enable device\n");
		goto err_devput;
	}

	if (pci_request_region(edev->pdev, 0, ESB_MODULE_NAME)) {
		dev_err(&edev->pdev->dev, "failed to request region\n");
		goto err_disable;
	}

	edev->base = pci_ioremap_bar(edev->pdev, 0);
	if (edev->base == NULL) {
		/* Something's wrong here, BASEADDR has to be set */
		dev_err(&edev->pdev->dev, "failed to get BASEADDR\n");
		goto err_release;
	}

	/* Done */
	dev_set_drvdata(&edev->pdev->dev, edev);
	return 1;

err_release:
	pci_release_region(edev->pdev, 0);
err_disable:
	pci_disable_device(edev->pdev);
err_devput:
	return 0;
}

static void esb_initdevice(struct esb_dev *edev)
{
	u8 val1;
	u16 val2;

	/*
	 * Config register:
	 * Bit    5 : 0 = Enable WDT_OUTPUT
	 * Bit    2 : 0 = set the timer frequency to the PCI clock
	 * divided by 2^15 (approx 1KHz).
	 * Bits 1:0 : 11 = WDT_INT_TYPE Disabled.
	 * The watchdog has two timers, it can be setup so that the
	 * expiry of timer1 results in an interrupt and the expiry of
	 * timer2 results in a reboot. We set it to not generate
	 * any interrupts as there is not much we can do with it
	 * right now.
	 */
	pci_write_config_word(edev->pdev, ESB_CONFIG_REG, 0x0003);

	/* Check that the WDT isn't already locked */
	pci_read_config_byte(edev->pdev, ESB_LOCK_REG, &val1);
	if (val1 & ESB_WDT_LOCK)
		dev_warn(&edev->pdev->dev, "nowayout already set\n");

	/* Set the timer to watchdog mode and disable it for now */
	pci_write_config_byte(edev->pdev, ESB_LOCK_REG, 0x00);

	/* Check if the watchdog was previously triggered */
	esb_unlock_registers(edev);
	val2 = readw(ESB_RELOAD_REG(edev));
	if (val2 & ESB_WDT_TIMEOUT)
		edev->wdd.bootstatus = WDIOF_CARDRESET;

	/* Reset WDT_TIMEOUT flag and timers */
	esb_unlock_registers(edev);
	writew((ESB_WDT_TIMEOUT | ESB_WDT_RELOAD), ESB_RELOAD_REG(edev));

	/* And set the correct timeout value */
	esb_timer_set_heartbeat(&edev->wdd, edev->wdd.timeout);
}

static int esb_probe(struct pci_dev *pdev,
		const struct pci_device_id *ent)
{
	struct esb_dev *edev;
	int ret;

	edev = devm_kzalloc(&pdev->dev, sizeof(*edev), GFP_KERNEL);
	if (!edev)
		return -ENOMEM;

	/* Check whether or not the hardware watchdog is there */
	edev->pdev = pdev;
	if (!esb_getdevice(edev))
		return -ENODEV;

	/* Check that the heartbeat value is within it's range;
	   if not reset to the default */
	if (esb_timer_set_heartbeat(heartbeat)) {
		esb_timer_set_heartbeat(WATCHDOG_HEARTBEAT);
		printk(KERN_INFO PFX
			"heartbeat value must be 1<heartbeat<2046, using %d\n",
								heartbeat);
	}
	ret = register_reboot_notifier(&esb_notifier);
	if (ret != 0) {
		printk(KERN_ERR PFX
			"cannot register reboot notifier (err=%d)\n", ret);
		goto err_unmap;
	}

	ret = misc_register(&esb_miscdev);
	if (ret != 0) {
		printk(KERN_ERR PFX
			"cannot register miscdev on minor=%d (err=%d)\n",
							WATCHDOG_MINOR, ret);
		goto err_notifier;
	}
	esb_timer_stop();
	printk(KERN_INFO PFX
		"initialized (0x%p). heartbeat=%d sec (nowayout=%d)\n",
						BASEADDR, heartbeat, nowayout);
	return 0;

err_notifier:
	unregister_reboot_notifier(&esb_notifier);
err_unmap:
	iounmap(BASEADDR);
/* err_release: */
	pci_release_region(esb_pci, 0);
/* err_disable: */
	pci_disable_device(esb_pci);
/* err_devput: */
	pci_dev_put(esb_pci);
	return ret;
}

static void __exit watchdog_cleanup(void)
	if (heartbeat < 0x1 || heartbeat > 2 * 0x03ff) {
		heartbeat = WATCHDOG_HEARTBEAT;
		pr_info("heartbeat value must be 1<heartbeat<2046, using %d\n",
			heartbeat);
	}

	/* Initialize the watchdog and make sure it does not run */
	edev->wdd.info = &esb_info;
	edev->wdd.ops = &esb_ops;
	edev->wdd.min_timeout = ESB_HEARTBEAT_MIN;
	edev->wdd.max_timeout = ESB_HEARTBEAT_MAX;
	edev->wdd.timeout = ESB_HEARTBEAT_DEFAULT;
	if (watchdog_init_timeout(&edev->wdd, heartbeat, NULL))
		dev_info(&pdev->dev,
			"heartbeat value must be " ESB_HEARTBEAT_RANGE
			", using %u\n", edev->wdd.timeout);
	watchdog_set_nowayout(&edev->wdd, nowayout);
	watchdog_stop_on_reboot(&edev->wdd);
	watchdog_stop_on_unregister(&edev->wdd);
	esb_initdevice(edev);

	/* Register the watchdog so that userspace has access to it */
	ret = watchdog_register_device(&edev->wdd);
	if (ret != 0) {
		dev_err(&pdev->dev,
			"cannot register watchdog device (err=%d)\n", ret);
		goto err_unmap;
	}
	dev_info(&pdev->dev,
		"initialized (0x%p). heartbeat=%d sec (nowayout=%d)\n",
		edev->base, edev->wdd.timeout, nowayout);
	return 0;

err_unmap:
	iounmap(edev->base);
	pci_release_region(edev->pdev, 0);
	pci_disable_device(edev->pdev);
	return ret;
}

static void esb_remove(struct pci_dev *pdev)
{
	struct esb_dev *edev = dev_get_drvdata(&pdev->dev);

	/* Deregister */
	misc_deregister(&esb_miscdev);
	unregister_reboot_notifier(&esb_notifier);
	iounmap(BASEADDR);
	pci_release_region(esb_pci, 0);
	pci_disable_device(esb_pci);
	pci_dev_put(esb_pci);
}

module_init(watchdog_init);
module_exit(watchdog_cleanup);
	iounmap(BASEADDR);
	pci_release_region(esb_pci, 0);
	pci_disable_device(esb_pci);
	esb_pci = NULL;
}

static void esb_shutdown(struct pci_dev *pdev)
{
	esb_timer_stop();
	watchdog_unregister_device(&edev->wdd);
	iounmap(edev->base);
	pci_release_region(edev->pdev, 0);
	pci_disable_device(edev->pdev);
}

static struct pci_driver esb_driver = {
	.name		= ESB_MODULE_NAME,
	.id_table	= esb_pci_tbl,
	.probe          = esb_probe,
	.remove         = esb_remove,
};

module_pci_driver(esb_driver);

MODULE_AUTHOR("Ross Biro and David Härdeman");
MODULE_DESCRIPTION("Watchdog driver for Intel 6300ESB chipsets");
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(WATCHDOG_MINOR);
