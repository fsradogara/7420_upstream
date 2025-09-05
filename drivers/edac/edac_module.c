/*
 * edac_module.c
 *
 * (C) 2007 www.softwarebitmaker.com
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 * Author: Doug Thompson <dougthompson@xmission.com>
 *
 */
#include <linux/edac.h>

#include "edac_mc.h"
#include "edac_module.h"

#define EDAC_VERSION "Ver: 2.1.0 " __DATE__

#ifdef CONFIG_EDAC_DEBUG
/* Values of 0 to 4 will generate output */
int edac_debug_level = 2;
EXPORT_SYMBOL_GPL(edac_debug_level);
#define EDAC_VERSION "Ver: 3.0.0"

#ifdef CONFIG_EDAC_DEBUG

static int edac_set_debug_level(const char *buf,
				const struct kernel_param *kp)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	if (val > 4)
		return -EINVAL;

	return param_set_int(buf, kp);
}

/* Values of 0 to 4 will generate output */
int edac_debug_level = 2;
EXPORT_SYMBOL_GPL(edac_debug_level);

module_param_call(edac_debug_level, edac_set_debug_level, param_get_int,
		  &edac_debug_level, 0644);
MODULE_PARM_DESC(edac_debug_level, "EDAC debug level: [0-4], default: 2");
#endif

/*
 * sysfs object: /sys/devices/system/edac
 *	need to export to other files in this modules
 */
static struct sysdev_class edac_class = {
	.name = "edac",
};
static int edac_class_valid;

/*
 * edac_op_state_to_string()
 */
char *edac_op_state_to_string(int opstate)
{
	if (opstate == OP_RUNNING_POLL)
		return "POLLED";
	else if (opstate == OP_RUNNING_INTERRUPT)
		return "INTERRUPT";
	else if (opstate == OP_RUNNING_POLL_INTR)
		return "POLL-INTR";
	else if (opstate == OP_ALLOC)
		return "ALLOC";
	else if (opstate == OP_OFFLINE)
		return "OFFLINE";

	return "UNKNOWN";
}

/*
 * edac_get_edac_class()
 *
 *	return pointer to the edac class of 'edac'
 */
struct sysdev_class *edac_get_edac_class(void)
{
	struct sysdev_class *classptr = NULL;

	if (edac_class_valid)
		classptr = &edac_class;

	return classptr;
}

/*
 * edac_register_sysfs_edac_name()
 *
 *	register the 'edac' into /sys/devices/system
 *
 * return:
 *	0  success
 *	!0 error
 */
static int edac_register_sysfs_edac_name(void)
{
	int err;

	/* create the /sys/devices/system/edac directory */
	err = sysdev_class_register(&edac_class);

	if (err) {
		debugf1("%s() error=%d\n", __func__, err);
		return err;
	}

	edac_class_valid = 1;
	return 0;
}

/*
 * sysdev_class_unregister()
 *
 *	unregister the 'edac' from /sys/devices/system
 */
static void edac_unregister_sysfs_edac_name(void)
{
	/* only if currently registered, then unregister it */
	if (edac_class_valid)
		sysdev_class_unregister(&edac_class);

	edac_class_valid = 0;
}

/*
 * edac_workqueue_setup
 *	initialize the edac work queue for polling operations
 * sysfs object: /sys/devices/system/edac
 *	need to export to other files
 */
static struct bus_type edac_subsys = {
	.name = "edac",
	.dev_name = "edac",
};

static int edac_subsys_init(void)
{
	int err;

	/* create the /sys/devices/system/edac directory */
	err = subsys_system_register(&edac_subsys, NULL);
	if (err)
		printk(KERN_ERR "Error registering toplevel EDAC sysfs dir\n");

	return err;
}

static void edac_subsys_exit(void)
{
	bus_unregister(&edac_subsys);
}

/* return pointer to the 'edac' node in sysfs */
struct bus_type *edac_get_sysfs_subsys(void)
{
	return &edac_subsys;
}
EXPORT_SYMBOL_GPL(edac_get_sysfs_subsys);
/*
 * edac_init
 *      module initialization entry point
 */
static int __init edac_init(void)
{
	int err = 0;

	edac_printk(KERN_INFO, EDAC_MC, EDAC_VERSION "\n");

	err = edac_subsys_init();
	if (err)
		return err;

	/*
	 * Harvest and clear any boot/initialization PCI parity errors
	 *
	 * FIXME: This only clears errors logged by devices present at time of
	 *      module initialization.  We should also do an initial clear
	 *      of each newly hotplugged device.
	 */
	edac_pci_clear_parity_errors();

	/*
	 * perform the registration of the /sys/devices/system/edac class object
	 */
	if (edac_register_sysfs_edac_name()) {
		edac_printk(KERN_ERR, EDAC_MC,
			"Error initializing 'edac' kobject\n");
		err = -ENODEV;
		goto error;
	}

	/*
	 * now set up the mc_kset under the edac class object
	 */
	err = edac_sysfs_setup_mc_kset();
	if (err)
		goto sysfs_setup_fail;

	/* Setup/Initialize the workq for this core */
	err = edac_workqueue_setup();
	if (err) {
		edac_printk(KERN_ERR, EDAC_MC, "init WorkQueue failure\n");
		goto workq_fail;
	err = edac_mc_sysfs_init();
	if (err)
		goto err_sysfs;

	edac_debugfs_init();

	err = edac_workqueue_setup();
	if (err) {
		edac_printk(KERN_ERR, EDAC_MC, "Failure initializing workqueue\n");
		goto err_wq;
	}

	return 0;

	/* Error teardown stack */
workq_fail:
	edac_sysfs_teardown_mc_kset();

sysfs_setup_fail:
	edac_unregister_sysfs_edac_name();

error:
err_wq:
	edac_debugfs_exit();
	edac_mc_sysfs_exit();

err_sysfs:
	edac_subsys_exit();

	return err;
}

/*
 * edac_exit()
 *      module exit/termination function
 */
static void __exit edac_exit(void)
{
	debugf0("%s()\n", __func__);

	/* tear down the various subsystems */
	edac_workqueue_teardown();
	edac_sysfs_teardown_mc_kset();
	edac_unregister_sysfs_edac_name();
	edac_dbg(0, "\n");

	/* tear down the various subsystems */
	edac_workqueue_teardown();
	edac_mc_sysfs_exit();
	edac_debugfs_exit();
	edac_subsys_exit();
}

/*
 * Inform the kernel of our entry and exit points
 */
module_init(edac_init);
subsys_initcall(edac_init);
module_exit(edac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Doug Thompson www.softwarebitmaker.com, et al");
MODULE_DESCRIPTION("Core library routines for EDAC reporting");

/* refer to *_sysfs.c files for parameters that are exported via sysfs */

#ifdef CONFIG_EDAC_DEBUG
module_param(edac_debug_level, int, 0644);
MODULE_PARM_DESC(edac_debug_level, "Debug level");
#endif
