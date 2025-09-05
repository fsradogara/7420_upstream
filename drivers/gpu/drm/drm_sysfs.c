
/*
 * drm_sysfs.c - Modifications to drm_sysfs_class.c to support
 *               extra sysfs attribute from DRM. Normal drm_sysfs_class
 *               does not allow adding attributes.
 *
 * Copyright (c) 2004 Jon Smirl <jonsmirl@gmail.com>
 * Copyright (c) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2003-2004 IBM Corp.
 *
 * This file is released under the GPLv2
 *
 */

#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/err.h>

#include "drm_core.h"
#include "drmP.h"

#define to_drm_minor(d) container_of(d, struct drm_minor, kdev)

/**
 * drm_sysfs_suspend - DRM class suspend hook
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/export.h>

#include <drm/drm_sysfs.h>
#include <drm/drmP.h>
#include "drm_internal.h"

#define to_drm_minor(d) dev_get_drvdata(d)
#define to_drm_connector(d) dev_get_drvdata(d)

/**
 * DOC: overview
 *
 * DRM provides very little additional support to drivers for sysfs
 * interactions, beyond just all the standard stuff. Drivers who want to expose
 * additional sysfs properties and property groups can attach them at either
 * &drm_device.dev or &drm_connector.kdev.
 *
 * Registration is automatically handled when calling drm_dev_register(), or
 * drm_connector_register() in case of hot-plugged connectors. Unregistration is
 * also automatically handled by drm_dev_unregister() and
 * drm_connector_unregister().
 */

static struct device_type drm_sysfs_device_minor = {
	.name = "drm_minor"
};

struct class *drm_class;

/**
 * __drm_class_suspend - internal DRM class suspend routine
 * @dev: Linux device to suspend
 * @state: power state to enter
 *
 * Just figures out what the actual struct drm_device associated with
 * @dev is and calls its suspend hook, if present.
 */
static int drm_sysfs_suspend(struct device *dev, pm_message_t state)
{
	struct drm_minor *drm_minor = to_drm_minor(dev);
	struct drm_device *drm_dev = drm_minor->dev;

	if (drm_dev->driver->suspend)
		return drm_dev->driver->suspend(drm_dev, state);

static int __drm_class_suspend(struct device *dev, pm_message_t state)
{
	if (dev->type == &drm_sysfs_device_minor) {
		struct drm_minor *drm_minor = to_drm_minor(dev);
		struct drm_device *drm_dev = drm_minor->dev;

		if (drm_minor->type == DRM_MINOR_LEGACY &&
		    !drm_core_check_feature(drm_dev, DRIVER_MODESET) &&
		    drm_dev->driver->suspend)
			return drm_dev->driver->suspend(drm_dev, state);
	}
	return 0;
}

/**
 * drm_sysfs_resume - DRM class resume hook
 * drm_class_suspend - internal DRM class suspend hook. Simply calls
 * __drm_class_suspend() with the correct pm state.
 * @dev: Linux device to suspend
 */
static int drm_class_suspend(struct device *dev)
{
	return __drm_class_suspend(dev, PMSG_SUSPEND);
}

/**
 * drm_class_freeze - internal DRM class freeze hook. Simply calls
 * __drm_class_suspend() with the correct pm state.
 * @dev: Linux device to freeze
 */
static int drm_class_freeze(struct device *dev)
{
	return __drm_class_suspend(dev, PMSG_FREEZE);
}

/**
 * drm_class_resume - DRM class resume hook
 * @dev: Linux device to resume
 *
 * Just figures out what the actual struct drm_device associated with
 * @dev is and calls its resume hook, if present.
 */
static int drm_sysfs_resume(struct device *dev)
{
	struct drm_minor *drm_minor = to_drm_minor(dev);
	struct drm_device *drm_dev = drm_minor->dev;

	if (drm_dev->driver->resume)
		return drm_dev->driver->resume(drm_dev);

	return 0;
}

/* Display the version of drm_core. This doesn't work right in current design */
static ssize_t version_show(struct class *dev, char *buf)
{
	return sprintf(buf, "%s %d.%d.%d %s\n", CORE_NAME, CORE_MAJOR,
		       CORE_MINOR, CORE_PATCHLEVEL, CORE_DATE);
}

static CLASS_ATTR(version, S_IRUGO, version_show, NULL);

/**
 * drm_sysfs_create - create a struct drm_sysfs_class structure
 * @owner: pointer to the module that is to "own" this struct drm_sysfs_class
 * @name: pointer to a string for the name of this class.
 *
 * This is used to create DRM class pointer that can then be used
 * in calls to drm_sysfs_device_add().
 *
 * Note, the pointer created here is to be destroyed when finished by making a
 * call to drm_sysfs_destroy().
 */
struct class *drm_sysfs_create(struct module *owner, char *name)
{
	struct class *class;
	int err;

	class = class_create(owner, name);
	if (IS_ERR(class)) {
		err = PTR_ERR(class);
		goto err_out;
	}

	class->suspend = drm_sysfs_suspend;
	class->resume = drm_sysfs_resume;

	err = class_create_file(class, &class_attr_version);
	if (err)
		goto err_out_class;

	return class;

err_out_class:
	class_destroy(class);
err_out:
	return ERR_PTR(err);
static int drm_class_resume(struct device *dev)
{
	if (dev->type == &drm_sysfs_device_minor) {
		struct drm_minor *drm_minor = to_drm_minor(dev);
		struct drm_device *drm_dev = drm_minor->dev;

		if (drm_minor->type == DRM_MINOR_LEGACY &&
		    !drm_core_check_feature(drm_dev, DRIVER_MODESET) &&
		    drm_dev->driver->resume)
			return drm_dev->driver->resume(drm_dev);
	}
	return 0;
}

static const struct dev_pm_ops drm_class_dev_pm_ops = {
	.suspend	= drm_class_suspend,
	.resume		= drm_class_resume,
	.freeze		= drm_class_freeze,
};

static char *drm_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "dri/%s", dev_name(dev));
}

static CLASS_ATTR_STRING(version, S_IRUGO, "drm 1.1.0 20060810");

/**
 * drm_sysfs_init - initialize sysfs helpers
 *
 * This is used to create the DRM class, which is the implicit parent of any
 * other top-level DRM sysfs objects.
 *
 * You must call drm_sysfs_destroy() to release the allocated resources.
 *
 * Return: 0 on success, negative error code on failure.
 */
int drm_sysfs_init(void)
{
	int err;

	drm_class = class_create(THIS_MODULE, "drm");
	if (IS_ERR(drm_class))
		return PTR_ERR(drm_class);

	err = class_create_file(drm_class, &class_attr_version.attr);
	if (err) {
		class_destroy(drm_class);
		drm_class = NULL;
		return err;
	}

	drm_class->devnode = drm_devnode;
	return 0;
}

/**
 * drm_sysfs_destroy - destroys DRM class
 *
 * Destroy the DRM device class.
 */
void drm_sysfs_destroy(void)
{
	if ((drm_class == NULL) || (IS_ERR(drm_class)))
		return;
	class_remove_file(drm_class, &class_attr_version);
	class_destroy(drm_class);
}

static ssize_t show_dri(struct device *device, struct device_attribute *attr,
			char *buf)
{
	struct drm_minor *drm_minor = to_drm_minor(device);
	struct drm_device *drm_dev = drm_minor->dev;
	if (drm_dev->driver->dri_library_name)
		return drm_dev->driver->dri_library_name(drm_dev, buf);
	return snprintf(buf, PAGE_SIZE, "%s\n", drm_dev->driver->pci_driver.name);
}

static struct device_attribute device_attrs[] = {
	__ATTR(dri_library_name, S_IRUGO, show_dri, NULL),
};

/**
 * drm_sysfs_device_release - do nothing
 * @dev: Linux device
 *
 * Normally, this would free the DRM device associated with @dev, along
 * with cleaning up any other stuff.  But we do that in the DRM core, so
 * this function can just return and hope that the core does its job.
 */
static void drm_sysfs_device_release(struct device *dev)
{
	return;
}

/**
 * drm_sysfs_device_add - adds a class device to sysfs for a character driver
 * @dev: DRM device to be added
 * @head: DRM head in question
 *
 * Add a DRM device to the DRM's device model class.  We use @dev's PCI device
 * as the parent for the Linux device, and make sure it has a file containing
 * the driver we're using (for userspace compatibility).
 */
int drm_sysfs_device_add(struct drm_minor *minor)
{
	int err;
	int i, j;
	char *minor_str;

	minor->kdev.parent = &minor->dev->pdev->dev;
	minor->kdev.class = drm_class;
	minor->kdev.release = drm_sysfs_device_release;
	minor->kdev.devt = minor->device;
	minor_str = "card%d";

	snprintf(minor->kdev.bus_id, BUS_ID_SIZE, minor_str, minor->index);

	err = device_register(&minor->kdev);
	if (err) {
		DRM_ERROR("device add failed: %d\n", err);
		goto err_out;
	}

	for (i = 0; i < ARRAY_SIZE(device_attrs); i++) {
		err = device_create_file(&minor->kdev, &device_attrs[i]);
		if (err)
			goto err_out_files;
	}

	return 0;

err_out_files:
	if (i > 0)
		for (j = 0; j < i; j++)
			device_remove_file(&minor->kdev, &device_attrs[i]);
	device_unregister(&minor->kdev);
err_out:

	return err;
}

/**
 * drm_sysfs_device_remove - remove DRM device
 * @dev: DRM device to remove
 *
 * This call unregisters and cleans up a class device that was created with a
 * call to drm_sysfs_device_add()
 */
void drm_sysfs_device_remove(struct drm_minor *minor)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(device_attrs); i++)
		device_remove_file(&minor->kdev, &device_attrs[i]);
	device_unregister(&minor->kdev);
}
	if (IS_ERR_OR_NULL(drm_class))
		return;
	class_remove_file(drm_class, &class_attr_version.attr);
	class_destroy(drm_class);
	drm_class = NULL;
}

/*
 * Connector properties
 */
static ssize_t status_store(struct device *device,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct drm_connector *connector = to_drm_connector(device);
	struct drm_device *dev = connector->dev;
	enum drm_connector_force old_force;
	int ret;

	ret = mutex_lock_interruptible(&dev->mode_config.mutex);
	if (ret)
		return ret;

	old_force = connector->force;

	if (sysfs_streq(buf, "detect"))
		connector->force = 0;
	else if (sysfs_streq(buf, "on"))
		connector->force = DRM_FORCE_ON;
	else if (sysfs_streq(buf, "on-digital"))
		connector->force = DRM_FORCE_ON_DIGITAL;
	else if (sysfs_streq(buf, "off"))
		connector->force = DRM_FORCE_OFF;
	else
		ret = -EINVAL;

	if (old_force != connector->force || !connector->force) {
		DRM_DEBUG_KMS("[CONNECTOR:%d:%s] force updated from %d to %d or reprobing\n",
			      connector->base.id,
			      connector->name,
			      old_force, connector->force);

		connector->funcs->fill_modes(connector,
					     dev->mode_config.max_width,
					     dev->mode_config.max_height);
	}

	mutex_unlock(&dev->mode_config.mutex);

	return ret ? ret : count;
}

static ssize_t status_show(struct device *device,
			   struct device_attribute *attr,
			   char *buf)
{
	struct drm_connector *connector = to_drm_connector(device);
	enum drm_connector_status status;

	status = READ_ONCE(connector->status);

	return snprintf(buf, PAGE_SIZE, "%s\n",
			drm_get_connector_status_name(status));
}

static ssize_t dpms_show(struct device *device,
			   struct device_attribute *attr,
			   char *buf)
{
	struct drm_connector *connector = to_drm_connector(device);
	int dpms;

	dpms = READ_ONCE(connector->dpms);

	return snprintf(buf, PAGE_SIZE, "%s\n",
			drm_get_dpms_name(dpms));
}

static ssize_t enabled_show(struct device *device,
			    struct device_attribute *attr,
			   char *buf)
{
	struct drm_connector *connector = to_drm_connector(device);
	bool enabled;

	enabled = READ_ONCE(connector->encoder);

	return snprintf(buf, PAGE_SIZE, enabled ? "enabled\n" : "disabled\n");
}

static ssize_t edid_show(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *attr, char *buf, loff_t off,
			 size_t count)
{
	struct device *connector_dev = kobj_to_dev(kobj);
	struct drm_connector *connector = to_drm_connector(connector_dev);
	unsigned char *edid;
	size_t size;
	ssize_t ret = 0;

	mutex_lock(&connector->dev->mode_config.mutex);
	if (!connector->edid_blob_ptr)
		goto unlock;

	edid = connector->edid_blob_ptr->data;
	size = connector->edid_blob_ptr->length;
	if (!edid)
		goto unlock;

	if (off >= size)
		goto unlock;

	if (off + count > size)
		count = size - off;
	memcpy(buf, edid + off, count);

	ret = count;
unlock:
	mutex_unlock(&connector->dev->mode_config.mutex);

	return ret;
}

static ssize_t modes_show(struct device *device,
			   struct device_attribute *attr,
			   char *buf)
{
	struct drm_connector *connector = to_drm_connector(device);
	struct drm_display_mode *mode;
	int written = 0;

	mutex_lock(&connector->dev->mode_config.mutex);
	list_for_each_entry(mode, &connector->modes, head) {
		written += snprintf(buf + written, PAGE_SIZE - written, "%s\n",
				    mode->name);
	}
	mutex_unlock(&connector->dev->mode_config.mutex);

	return written;
}

static DEVICE_ATTR_RW(status);
static DEVICE_ATTR_RO(enabled);
static DEVICE_ATTR_RO(dpms);
static DEVICE_ATTR_RO(modes);

static struct attribute *connector_dev_attrs[] = {
	&dev_attr_status.attr,
	&dev_attr_enabled.attr,
	&dev_attr_dpms.attr,
	&dev_attr_modes.attr,
	NULL
};

static struct bin_attribute edid_attr = {
	.attr.name = "edid",
	.attr.mode = 0444,
	.size = 0,
	.read = edid_show,
};

static struct bin_attribute *connector_bin_attrs[] = {
	&edid_attr,
	NULL
};

static const struct attribute_group connector_dev_group = {
	.attrs = connector_dev_attrs,
	.bin_attrs = connector_bin_attrs,
};

static const struct attribute_group *connector_dev_groups[] = {
	&connector_dev_group,
	NULL
};

int drm_sysfs_connector_add(struct drm_connector *connector)
{
	struct drm_device *dev = connector->dev;

	if (connector->kdev)
		return 0;

	connector->kdev =
		device_create_with_groups(drm_class, dev->primary->kdev, 0,
					  connector, connector_dev_groups,
					  "card%d-%s", dev->primary->index,
					  connector->name);
	DRM_DEBUG("adding \"%s\" to sysfs\n",
		  connector->name);

	if (IS_ERR(connector->kdev)) {
		DRM_ERROR("failed to register connector device: %ld\n", PTR_ERR(connector->kdev));
		return PTR_ERR(connector->kdev);
	}

	/* Let userspace know we have a new connector */
	drm_sysfs_hotplug_event(dev);

	return 0;
}

void drm_sysfs_connector_remove(struct drm_connector *connector)
{
	if (!connector->kdev)
		return;
	DRM_DEBUG("removing \"%s\" from sysfs\n",
		  connector->name);

	device_unregister(connector->kdev);
	connector->kdev = NULL;
}

/**
 * drm_sysfs_hotplug_event - generate a DRM uevent
 * @dev: DRM device
 *
 * Send a uevent for the DRM device specified by @dev.  Currently we only
 * set HOTPLUG=1 in the uevent environment, but this could be expanded to
 * deal with other types of events.
 */
void drm_sysfs_hotplug_event(struct drm_device *dev)
{
	char *event_string = "HOTPLUG=1";
	char *envp[] = { event_string, NULL };

	DRM_DEBUG("generating hotplug event\n");

	kobject_uevent_env(&dev->primary->kdev->kobj, KOBJ_CHANGE, envp);
}
EXPORT_SYMBOL(drm_sysfs_hotplug_event);

static void drm_sysfs_release(struct device *dev)
{
	kfree(dev);
}

struct device *drm_sysfs_minor_alloc(struct drm_minor *minor)
{
	const char *minor_str;
	struct device *kdev;
	int r;

	if (minor->type == DRM_MINOR_CONTROL)
		minor_str = "controlD%d";
	else if (minor->type == DRM_MINOR_RENDER)
		minor_str = "renderD%d";
	else
		minor_str = "card%d";

	kdev = kzalloc(sizeof(*kdev), GFP_KERNEL);
	if (!kdev)
		return ERR_PTR(-ENOMEM);

	device_initialize(kdev);
	kdev->devt = MKDEV(DRM_MAJOR, minor->index);
	kdev->class = drm_class;
	kdev->type = &drm_sysfs_device_minor;
	kdev->parent = minor->dev->dev;
	kdev->release = drm_sysfs_release;
	dev_set_drvdata(kdev, minor);

	r = dev_set_name(kdev, minor_str, minor->index);
	if (r < 0)
		goto err_free;

	return kdev;

err_free:
	put_device(kdev);
	return ERR_PTR(r);
}

/**
 * drm_class_device_register - register new device with the DRM sysfs class
 * @dev: device to register
 *
 * Registers a new &struct device within the DRM sysfs class. Essentially only
 * used by ttm to have a place for its global settings. Drivers should never use
 * this.
 */
int drm_class_device_register(struct device *dev)
{
	if (!drm_class || IS_ERR(drm_class))
		return -ENOENT;

	dev->class = drm_class;
	return device_register(dev);
}
EXPORT_SYMBOL_GPL(drm_class_device_register);

/**
 * drm_class_device_unregister - unregister device with the DRM sysfs class
 * @dev: device to unregister
 *
 * Unregisters a &struct device from the DRM sysfs class. Essentially only used
 * by ttm to have a place for its global settings. Drivers should never use
 * this.
 */
void drm_class_device_unregister(struct device *dev)
{
	return device_unregister(dev);
}
EXPORT_SYMBOL_GPL(drm_class_device_unregister);
