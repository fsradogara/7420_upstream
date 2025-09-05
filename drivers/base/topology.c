// SPDX-License-Identifier: GPL-2.0+
/*
 * driver/base/topology.c - Populate sysfs with cpu topology information
 *
 * Written by: Zhang Yanmin, Intel Corporation
 *
 * Copyright (C) 2006, Intel Corp.
 *
 * All rights reserved.
 */
#include <linux/sysdev.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/topology.h>

#define define_one_ro(_name) 		\
static SYSDEV_ATTR(_name, 0444, show_##_name, NULL)

#define define_id_show_func(name)				\
static ssize_t show_##name(struct sys_device *dev,		\
		struct sysdev_attribute *attr, char *buf)	\
{								\
	unsigned int cpu = dev->id;				\
	return sprintf(buf, "%d\n", topology_##name(cpu));	\
}

#if defined(topology_thread_siblings) || defined(topology_core_siblings)
static ssize_t show_cpumap(int type, cpumask_t *mask, char *buf)
{
	ptrdiff_t len = PTR_ALIGN(buf + PAGE_SIZE - 1, PAGE_SIZE) - buf;
	int n = 0;

	if (len > 1) {
		n = type?
			cpulist_scnprintf(buf, len-2, *mask):
			cpumask_scnprintf(buf, len-2, *mask);
		buf[n++] = '\n';
		buf[n] = '\0';
	}
	return n;
}
#endif

#ifdef arch_provides_topology_pointers
#define define_siblings_show_map(name)					\
static ssize_t show_##name(struct sys_device *dev,			\
			   struct sysdev_attribute *attr, char *buf)	\
{									\
	unsigned int cpu = dev->id;					\
	return show_cpumap(0, &(topology_##name(cpu)), buf);		\
}

#define define_siblings_show_list(name)					\
static ssize_t show_##name##_list(struct sys_device *dev,		\
				  struct sysdev_attribute *attr,	\
				  char *buf)				\
{									\
	unsigned int cpu = dev->id;					\
	return show_cpumap(1, &(topology_##name(cpu)), buf);		\
}

#else
#define define_siblings_show_map(name)					\
static ssize_t show_##name(struct sys_device *dev,			\
			   struct sysdev_attribute *attr, char *buf)	\
{									\
	unsigned int cpu = dev->id;					\
	cpumask_t mask = topology_##name(cpu);				\
	return show_cpumap(0, &mask, buf);				\
}

#define define_siblings_show_list(name)					\
static ssize_t show_##name##_list(struct sys_device *dev,		\
				  struct sysdev_attribute *attr,	\
				  char *buf)				\
{									\
	unsigned int cpu = dev->id;					\
	cpumask_t mask = topology_##name(cpu);				\
	return show_cpumap(1, &mask, buf);				\
}
#endif

#define define_siblings_show_func(name)		\
	define_siblings_show_map(name); define_siblings_show_list(name)

define_id_show_func(physical_package_id);
define_one_ro(physical_package_id);

define_id_show_func(core_id);
define_one_ro(core_id);

define_siblings_show_func(thread_siblings);
define_one_ro(thread_siblings);
define_one_ro(thread_siblings_list);

define_siblings_show_func(core_siblings);
define_one_ro(core_siblings);
define_one_ro(core_siblings_list);

static struct attribute *default_attrs[] = {
	&attr_physical_package_id.attr,
	&attr_core_id.attr,
	&attr_thread_siblings.attr,
	&attr_thread_siblings_list.attr,
	&attr_core_siblings.attr,
	&attr_core_siblings_list.attr,
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/hardirq.h>
#include <linux/topology.h>

#define define_id_show_func(name)				\
static ssize_t name##_show(struct device *dev,			\
		struct device_attribute *attr, char *buf)	\
{								\
	return sprintf(buf, "%d\n", topology_##name(dev->id));	\
}

#define define_siblings_show_map(name, mask)				\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr, char *buf)	\
{									\
	return cpumap_print_to_pagebuf(false, buf, topology_##mask(dev->id));\
}

#define define_siblings_show_list(name, mask)				\
static ssize_t name##_list_show(struct device *dev,			\
				struct device_attribute *attr,		\
				char *buf)				\
{									\
	return cpumap_print_to_pagebuf(true, buf, topology_##mask(dev->id));\
}

#define define_siblings_show_func(name, mask)	\
	define_siblings_show_map(name, mask);	\
	define_siblings_show_list(name, mask)

define_id_show_func(physical_package_id);
static DEVICE_ATTR_RO(physical_package_id);

define_id_show_func(core_id);
static DEVICE_ATTR_RO(core_id);

define_siblings_show_func(thread_siblings, sibling_cpumask);
static DEVICE_ATTR_RO(thread_siblings);
static DEVICE_ATTR_RO(thread_siblings_list);

define_siblings_show_func(core_siblings, core_cpumask);
static DEVICE_ATTR_RO(core_siblings);
static DEVICE_ATTR_RO(core_siblings_list);

#ifdef CONFIG_SCHED_BOOK
define_id_show_func(book_id);
static DEVICE_ATTR_RO(book_id);
define_siblings_show_func(book_siblings, book_cpumask);
static DEVICE_ATTR_RO(book_siblings);
static DEVICE_ATTR_RO(book_siblings_list);
#endif

#ifdef CONFIG_SCHED_DRAWER
define_id_show_func(drawer_id);
static DEVICE_ATTR_RO(drawer_id);
define_siblings_show_func(drawer_siblings, drawer_cpumask);
static DEVICE_ATTR_RO(drawer_siblings);
static DEVICE_ATTR_RO(drawer_siblings_list);
#endif

static struct attribute *default_attrs[] = {
	&dev_attr_physical_package_id.attr,
	&dev_attr_core_id.attr,
	&dev_attr_thread_siblings.attr,
	&dev_attr_thread_siblings_list.attr,
	&dev_attr_core_siblings.attr,
	&dev_attr_core_siblings_list.attr,
#ifdef CONFIG_SCHED_BOOK
	&dev_attr_book_id.attr,
	&dev_attr_book_siblings.attr,
	&dev_attr_book_siblings_list.attr,
#endif
#ifdef CONFIG_SCHED_DRAWER
	&dev_attr_drawer_id.attr,
	&dev_attr_drawer_siblings.attr,
	&dev_attr_drawer_siblings_list.attr,
#endif
	NULL
};

static const struct attribute_group topology_attr_group = {
	.attrs = default_attrs,
	.name = "topology"
};

/* Add/Remove cpu_topology interface for CPU device */
static int __cpuinit topology_add_dev(unsigned int cpu)
{
	struct sys_device *sys_dev = get_cpu_sysdev(cpu);

	return sysfs_create_group(&sys_dev->kobj, &topology_attr_group);
}

static void __cpuinit topology_remove_dev(unsigned int cpu)
{
	struct sys_device *sys_dev = get_cpu_sysdev(cpu);

	sysfs_remove_group(&sys_dev->kobj, &topology_attr_group);
}

static int __cpuinit topology_cpu_callback(struct notifier_block *nfb,
					   unsigned long action, void *hcpu)
static int topology_add_dev(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	return sysfs_create_group(&dev->kobj, &topology_attr_group);
}

static int topology_remove_dev(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	sysfs_remove_group(&dev->kobj, &topology_attr_group);
}

static int topology_cpu_callback(struct notifier_block *nfb,
				 unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	int rc = 0;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		rc = topology_add_dev(cpu);
		break;
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		topology_remove_dev(cpu);
		break;
	}
	return rc ? NOTIFY_BAD : NOTIFY_OK;
}

static int __cpuinit topology_sysfs_init(void)
{
	int cpu;
	int rc;
	return notifier_from_errno(rc);
	return 0;
}

static int topology_sysfs_init(void)
{
	int cpu;
	int rc = 0;

	cpu_notifier_register_begin();

	for_each_online_cpu(cpu) {
		rc = topology_add_dev(cpu);
		if (rc)
			return rc;
	}
	hotcpu_notifier(topology_cpu_callback, 0);

	return 0;
			goto out;
	}
	__hotcpu_notifier(topology_cpu_callback, 0);

out:
	cpu_notifier_register_done();
	return rc;
	return cpuhp_setup_state(CPUHP_TOPOLOGY_PREPARE,
				 "base/topology:prepare", topology_add_dev,
				 topology_remove_dev);
}

device_initcall(topology_sysfs_init);
