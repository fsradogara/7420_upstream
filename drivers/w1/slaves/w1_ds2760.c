/*
 * 1-Wire implementation for the ds2760 chip
 *
 * Copyright © 2004-2005, Szabolcs Gyurko <szabolcs.gyurko@tlt.hu>
 *
 * Use consistent with the GNU GPL is permitted,
 * provided that this copyright notice is
 * preserved in its entirety in all copies and derived works.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/gfp.h>

#include <linux/w1.h>

#include "w1_ds2760.h"

#define W1_FAMILY_DS2760	0x30

static int w1_ds2760_io(struct device *dev, char *buf, int addr, size_t count,
			int io)
{
	struct w1_slave *sl = container_of(dev, struct w1_slave, dev);

	if (!dev)
		return 0;

	mutex_lock(&sl->master->mutex);
	mutex_lock(&sl->master->bus_mutex);

	if (addr > DS2760_DATA_SIZE || addr < 0) {
		count = 0;
		goto out;
	}
	if (addr + count > DS2760_DATA_SIZE)
		count = DS2760_DATA_SIZE - addr;

	if (!w1_reset_select_slave(sl)) {
		if (!io) {
			w1_write_8(sl->master, W1_DS2760_READ_DATA);
			w1_write_8(sl->master, addr);
			count = w1_read_block(sl->master, buf, count);
		} else {
			w1_write_8(sl->master, W1_DS2760_WRITE_DATA);
			w1_write_8(sl->master, addr);
			w1_write_block(sl->master, buf, count);
			/* XXX w1_write_block returns void, not n_written */
		}
	}

out:
	mutex_unlock(&sl->master->mutex);
	mutex_unlock(&sl->master->bus_mutex);

	return count;
}

int w1_ds2760_read(struct device *dev, char *buf, int addr, size_t count)
{
	return w1_ds2760_io(dev, buf, addr, count, 0);
}
EXPORT_SYMBOL(w1_ds2760_read);

int w1_ds2760_write(struct device *dev, char *buf, int addr, size_t count)
{
	return w1_ds2760_io(dev, buf, addr, count, 1);
}
EXPORT_SYMBOL(w1_ds2760_write);

static ssize_t w1_ds2760_read_bin(struct kobject *kobj,
				  struct bin_attribute *bin_attr,
				  char *buf, loff_t off, size_t count)
static int w1_ds2760_eeprom_cmd(struct device *dev, int addr, int cmd)
{
	struct w1_slave *sl = container_of(dev, struct w1_slave, dev);

	if (!dev)
		return -EINVAL;

	mutex_lock(&sl->master->bus_mutex);

	if (w1_reset_select_slave(sl) == 0) {
		w1_write_8(sl->master, cmd);
		w1_write_8(sl->master, addr);
	}

	mutex_unlock(&sl->master->bus_mutex);
	return 0;
}

int w1_ds2760_store_eeprom(struct device *dev, int addr)
{
	return w1_ds2760_eeprom_cmd(dev, addr, W1_DS2760_COPY_DATA);
}
EXPORT_SYMBOL(w1_ds2760_store_eeprom);

int w1_ds2760_recall_eeprom(struct device *dev, int addr)
{
	return w1_ds2760_eeprom_cmd(dev, addr, W1_DS2760_RECALL_DATA);
}
EXPORT_SYMBOL(w1_ds2760_recall_eeprom);

static ssize_t w1_slave_read(struct file *filp, struct kobject *kobj,
			     struct bin_attribute *bin_attr, char *buf,
			     loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	return w1_ds2760_read(dev, buf, off, count);
}

static struct bin_attribute w1_ds2760_bin_attr = {
	.attr = {
		.name = "w1_slave",
		.mode = S_IRUGO,
		.owner = THIS_MODULE,
	},
	.size = DS2760_DATA_SIZE,
	.read = w1_ds2760_read_bin,
};

static DEFINE_IDR(bat_idr);
static DEFINE_MUTEX(bat_idr_lock);

static int new_bat_id(void)
{
	int ret;

	while (1) {
		int id;

		ret = idr_pre_get(&bat_idr, GFP_KERNEL);
		if (ret == 0)
			return -ENOMEM;

		mutex_lock(&bat_idr_lock);
		ret = idr_get_new(&bat_idr, NULL, &id);
		mutex_unlock(&bat_idr_lock);

		if (ret == 0) {
			ret = id & MAX_ID_MASK;
			break;
		} else if (ret == -EAGAIN) {
			continue;
		} else {
			break;
		}
	}

	return ret;
}

static void release_bat_id(int id)
{
	mutex_lock(&bat_idr_lock);
	idr_remove(&bat_idr, id);
	mutex_unlock(&bat_idr_lock);
}
static BIN_ATTR_RO(w1_slave, DS2760_DATA_SIZE);

static struct bin_attribute *w1_ds2760_bin_attrs[] = {
	&bin_attr_w1_slave,
	NULL,
};

static const struct attribute_group w1_ds2760_group = {
	.bin_attrs = w1_ds2760_bin_attrs,
};

static const struct attribute_group *w1_ds2760_groups[] = {
	&w1_ds2760_group,
	NULL,
};

static int w1_ds2760_add_slave(struct w1_slave *sl)
{
	int ret;
	struct platform_device *pdev;

	id = new_bat_id();
	id = ida_simple_get(&bat_ida, 0, 0, GFP_KERNEL);
	if (id < 0) {
		ret = id;
		goto noid;
	}

	pdev = platform_device_alloc("ds2760-battery", id);
	if (!pdev) {
		ret = -ENOMEM;
		goto pdev_alloc_failed;
	}
	pdev = platform_device_alloc("ds2760-battery", PLATFORM_DEVID_AUTO);
	if (!pdev)
		return -ENOMEM;
	pdev->dev.parent = &sl->dev;

	ret = platform_device_add(pdev);
	if (ret)
		goto pdev_add_failed;

	ret = sysfs_create_bin_file(&sl->dev.kobj, &w1_ds2760_bin_attr);
	if (ret)
		goto bin_attr_failed;

	dev_set_drvdata(&sl->dev, pdev);

	return 0;

bin_attr_failed:
pdev_add_failed:
	platform_device_unregister(pdev);
pdev_alloc_failed:
	release_bat_id(id);
pdev_add_failed:
	platform_device_put(pdev);

	return ret;
}

static void w1_ds2760_remove_slave(struct w1_slave *sl)
{
	struct platform_device *pdev = dev_get_drvdata(&sl->dev);

	platform_device_unregister(pdev);
	release_bat_id(id);
	sysfs_remove_bin_file(&sl->dev.kobj, &w1_ds2760_bin_attr);
	ida_simple_remove(&bat_ida, id);
}

static struct w1_family_ops w1_ds2760_fops = {
	.add_slave    = w1_ds2760_add_slave,
	.remove_slave = w1_ds2760_remove_slave,
	.groups       = w1_ds2760_groups,
};

static struct w1_family w1_ds2760_family = {
	.fid = W1_FAMILY_DS2760,
	.fops = &w1_ds2760_fops,
};
module_w1_family(w1_ds2760_family);

static int __init w1_ds2760_init(void)
{
	printk(KERN_INFO "1-Wire driver for the DS2760 battery monitor "
	       " chip  - (c) 2004-2005, Szabolcs Gyurko\n");
	idr_init(&bat_idr);
	pr_info("1-Wire driver for the DS2760 battery monitor chip - (c) 2004-2005, Szabolcs Gyurko\n");
	ida_init(&bat_ida);
	return w1_register_family(&w1_ds2760_family);
}

static void __exit w1_ds2760_exit(void)
{
	w1_unregister_family(&w1_ds2760_family);
	idr_destroy(&bat_idr);
	ida_destroy(&bat_ida);
}

EXPORT_SYMBOL(w1_ds2760_read);
EXPORT_SYMBOL(w1_ds2760_write);
EXPORT_SYMBOL(w1_ds2760_store_eeprom);
EXPORT_SYMBOL(w1_ds2760_recall_eeprom);

module_init(w1_ds2760_init);
module_exit(w1_ds2760_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Szabolcs Gyurko <szabolcs.gyurko@tlt.hu>");
MODULE_DESCRIPTION("1-wire Driver Dallas 2760 battery monitor chip");
MODULE_LICENSE("GPL");
MODULE_ALIAS("w1-family-" __stringify(W1_FAMILY_DS2760));
