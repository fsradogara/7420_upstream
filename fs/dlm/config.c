/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
**  Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/configfs.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/dlmconstants.h>
#include <net/ipv6.h>
#include <net/sock.h>

#include "config.h"
#include "lowcomms.h"

/*
 * /config/dlm/<cluster>/spaces/<space>/nodes/<node>/nodeid
 * /config/dlm/<cluster>/spaces/<space>/nodes/<node>/weight
 * /config/dlm/<cluster>/comms/<comm>/nodeid
 * /config/dlm/<cluster>/comms/<comm>/local
 * /config/dlm/<cluster>/comms/<comm>/addr
 * /config/dlm/<cluster>/comms/<comm>/addr      (write only)
 * /config/dlm/<cluster>/comms/<comm>/addr_list (read only)
 * The <cluster> level is useless, but I haven't figured out how to avoid it.
 */

static struct config_group *space_list;
static struct config_group *comm_list;
static struct dlm_comm *local_comm;
static uint32_t dlm_comm_count;

struct dlm_clusters;
struct dlm_cluster;
struct dlm_spaces;
struct dlm_space;
struct dlm_comms;
struct dlm_comm;
struct dlm_nodes;
struct dlm_node;

static struct config_group *make_cluster(struct config_group *, const char *);
static void drop_cluster(struct config_group *, struct config_item *);
static void release_cluster(struct config_item *);
static struct config_group *make_space(struct config_group *, const char *);
static void drop_space(struct config_group *, struct config_item *);
static void release_space(struct config_item *);
static struct config_item *make_comm(struct config_group *, const char *);
static void drop_comm(struct config_group *, struct config_item *);
static void release_comm(struct config_item *);
static struct config_item *make_node(struct config_group *, const char *);
static void drop_node(struct config_group *, struct config_item *);
static void release_node(struct config_item *);

static ssize_t show_cluster(struct config_item *i, struct configfs_attribute *a,
			    char *buf);
static ssize_t store_cluster(struct config_item *i,
			     struct configfs_attribute *a,
			     const char *buf, size_t len);
static ssize_t show_comm(struct config_item *i, struct configfs_attribute *a,
			 char *buf);
static ssize_t store_comm(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len);
static ssize_t show_node(struct config_item *i, struct configfs_attribute *a,
			 char *buf);
static ssize_t store_node(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len);

static ssize_t comm_nodeid_read(struct dlm_comm *cm, char *buf);
static ssize_t comm_nodeid_write(struct dlm_comm *cm, const char *buf,
				size_t len);
static ssize_t comm_local_read(struct dlm_comm *cm, char *buf);
static ssize_t comm_local_write(struct dlm_comm *cm, const char *buf,
				size_t len);
static ssize_t comm_addr_write(struct dlm_comm *cm, const char *buf,
				size_t len);
static ssize_t node_nodeid_read(struct dlm_node *nd, char *buf);
static ssize_t node_nodeid_write(struct dlm_node *nd, const char *buf,
				size_t len);
static ssize_t node_weight_read(struct dlm_node *nd, char *buf);
static ssize_t node_weight_write(struct dlm_node *nd, const char *buf,
				size_t len);
static struct configfs_attribute *comm_attrs[];
static struct configfs_attribute *node_attrs[];

struct dlm_cluster {
	struct config_group group;
	unsigned int cl_tcp_port;
	unsigned int cl_buffer_size;
	unsigned int cl_rsbtbl_size;
	unsigned int cl_lkbtbl_size;
	unsigned int cl_dirtbl_size;
	unsigned int cl_recover_timer;
	unsigned int cl_toss_secs;
	unsigned int cl_scan_secs;
	unsigned int cl_log_debug;
	unsigned int cl_log_info;
	unsigned int cl_protocol;
	unsigned int cl_timewarn_cs;
};

	unsigned int cl_waitwarn_us;
	unsigned int cl_new_rsb_count;
	unsigned int cl_recover_callbacks;
	char cl_cluster_name[DLM_LOCKSPACE_LEN];
};

static struct dlm_cluster *config_item_to_cluster(struct config_item *i)
{
	return i ? container_of(to_config_group(i), struct dlm_cluster, group) :
		   NULL;
}

enum {
	CLUSTER_ATTR_TCP_PORT = 0,
	CLUSTER_ATTR_BUFFER_SIZE,
	CLUSTER_ATTR_RSBTBL_SIZE,
	CLUSTER_ATTR_LKBTBL_SIZE,
	CLUSTER_ATTR_DIRTBL_SIZE,
	CLUSTER_ATTR_RECOVER_TIMER,
	CLUSTER_ATTR_TOSS_SECS,
	CLUSTER_ATTR_SCAN_SECS,
	CLUSTER_ATTR_LOG_DEBUG,
	CLUSTER_ATTR_LOG_INFO,
	CLUSTER_ATTR_PROTOCOL,
	CLUSTER_ATTR_TIMEWARN_CS,
};

struct cluster_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct dlm_cluster *, char *);
	ssize_t (*store)(struct dlm_cluster *, const char *, size_t);
};
	CLUSTER_ATTR_WAITWARN_US,
	CLUSTER_ATTR_NEW_RSB_COUNT,
	CLUSTER_ATTR_RECOVER_CALLBACKS,
	CLUSTER_ATTR_CLUSTER_NAME,
};

static ssize_t cluster_cluster_name_show(struct config_item *item, char *buf)
{
	struct dlm_cluster *cl = config_item_to_cluster(item);
	return sprintf(buf, "%s\n", cl->cl_cluster_name);
}

static ssize_t cluster_cluster_name_store(struct config_item *item,
					  const char *buf, size_t len)
{
	struct dlm_cluster *cl = config_item_to_cluster(item);

	strlcpy(dlm_config.ci_cluster_name, buf,
				sizeof(dlm_config.ci_cluster_name));
	strlcpy(cl->cl_cluster_name, buf, sizeof(cl->cl_cluster_name));
	return len;
}

CONFIGFS_ATTR(cluster_, cluster_name);

static ssize_t cluster_set(struct dlm_cluster *cl, unsigned int *cl_field,
			   int *info_field, int check_zero,
			   const char *buf, size_t len)
{
	unsigned int x;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	x = simple_strtoul(buf, NULL, 0);
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	rc = kstrtouint(buf, 0, &x);
	if (rc)
		return rc;

	if (check_zero && !x)
		return -EINVAL;

	*cl_field = x;
	*info_field = x;

	return len;
}

#define CLUSTER_ATTR(name, check_zero)                                        \
static ssize_t name##_write(struct dlm_cluster *cl, const char *buf, size_t len) \
{                                                                             \
	return cluster_set(cl, &cl->cl_##name, &dlm_config.ci_##name,         \
			   check_zero, buf, len);                             \
}                                                                             \
static ssize_t name##_read(struct dlm_cluster *cl, char *buf)                 \
{                                                                             \
	return snprintf(buf, PAGE_SIZE, "%u\n", cl->cl_##name);               \
}                                                                             \
static struct cluster_attribute cluster_attr_##name =                         \
__CONFIGFS_ATTR(name, 0644, name##_read, name##_write)
static ssize_t cluster_##name##_store(struct config_item *item, \
		const char *buf, size_t len) \
{                                                                             \
	struct dlm_cluster *cl = config_item_to_cluster(item);		      \
	return cluster_set(cl, &cl->cl_##name, &dlm_config.ci_##name,         \
			   check_zero, buf, len);                             \
}                                                                             \
static ssize_t cluster_##name##_show(struct config_item *item, char *buf)     \
{                                                                             \
	struct dlm_cluster *cl = config_item_to_cluster(item);		      \
	return snprintf(buf, PAGE_SIZE, "%u\n", cl->cl_##name);               \
}                                                                             \
CONFIGFS_ATTR(cluster_, name);

CLUSTER_ATTR(tcp_port, 1);
CLUSTER_ATTR(buffer_size, 1);
CLUSTER_ATTR(rsbtbl_size, 1);
CLUSTER_ATTR(lkbtbl_size, 1);
CLUSTER_ATTR(dirtbl_size, 1);
CLUSTER_ATTR(recover_timer, 1);
CLUSTER_ATTR(toss_secs, 1);
CLUSTER_ATTR(scan_secs, 1);
CLUSTER_ATTR(log_debug, 0);
CLUSTER_ATTR(log_info, 0);
CLUSTER_ATTR(protocol, 0);
CLUSTER_ATTR(timewarn_cs, 1);

static struct configfs_attribute *cluster_attrs[] = {
	[CLUSTER_ATTR_TCP_PORT] = &cluster_attr_tcp_port.attr,
	[CLUSTER_ATTR_BUFFER_SIZE] = &cluster_attr_buffer_size.attr,
	[CLUSTER_ATTR_RSBTBL_SIZE] = &cluster_attr_rsbtbl_size.attr,
	[CLUSTER_ATTR_LKBTBL_SIZE] = &cluster_attr_lkbtbl_size.attr,
	[CLUSTER_ATTR_DIRTBL_SIZE] = &cluster_attr_dirtbl_size.attr,
	[CLUSTER_ATTR_RECOVER_TIMER] = &cluster_attr_recover_timer.attr,
	[CLUSTER_ATTR_TOSS_SECS] = &cluster_attr_toss_secs.attr,
	[CLUSTER_ATTR_SCAN_SECS] = &cluster_attr_scan_secs.attr,
	[CLUSTER_ATTR_LOG_DEBUG] = &cluster_attr_log_debug.attr,
	[CLUSTER_ATTR_PROTOCOL] = &cluster_attr_protocol.attr,
	[CLUSTER_ATTR_TIMEWARN_CS] = &cluster_attr_timewarn_cs.attr,
CLUSTER_ATTR(waitwarn_us, 0);
CLUSTER_ATTR(new_rsb_count, 0);
CLUSTER_ATTR(recover_callbacks, 0);

static struct configfs_attribute *cluster_attrs[] = {
	[CLUSTER_ATTR_TCP_PORT] = &cluster_attr_tcp_port,
	[CLUSTER_ATTR_BUFFER_SIZE] = &cluster_attr_buffer_size,
	[CLUSTER_ATTR_RSBTBL_SIZE] = &cluster_attr_rsbtbl_size,
	[CLUSTER_ATTR_RECOVER_TIMER] = &cluster_attr_recover_timer,
	[CLUSTER_ATTR_TOSS_SECS] = &cluster_attr_toss_secs,
	[CLUSTER_ATTR_SCAN_SECS] = &cluster_attr_scan_secs,
	[CLUSTER_ATTR_LOG_DEBUG] = &cluster_attr_log_debug,
	[CLUSTER_ATTR_LOG_INFO] = &cluster_attr_log_info,
	[CLUSTER_ATTR_PROTOCOL] = &cluster_attr_protocol,
	[CLUSTER_ATTR_TIMEWARN_CS] = &cluster_attr_timewarn_cs,
	[CLUSTER_ATTR_WAITWARN_US] = &cluster_attr_waitwarn_us,
	[CLUSTER_ATTR_NEW_RSB_COUNT] = &cluster_attr_new_rsb_count,
	[CLUSTER_ATTR_RECOVER_CALLBACKS] = &cluster_attr_recover_callbacks,
	[CLUSTER_ATTR_CLUSTER_NAME] = &cluster_attr_cluster_name,
	NULL,
};

enum {
	COMM_ATTR_NODEID = 0,
	COMM_ATTR_LOCAL,
	COMM_ATTR_ADDR,
};

struct comm_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct dlm_comm *, char *);
	ssize_t (*store)(struct dlm_comm *, const char *, size_t);
};

static struct comm_attribute comm_attr_nodeid = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "nodeid",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = comm_nodeid_read,
	.store  = comm_nodeid_write,
};

static struct comm_attribute comm_attr_local = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "local",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = comm_local_read,
	.store  = comm_local_write,
};

static struct comm_attribute comm_attr_addr = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "addr",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.store  = comm_addr_write,
};

static struct configfs_attribute *comm_attrs[] = {
	[COMM_ATTR_NODEID] = &comm_attr_nodeid.attr,
	[COMM_ATTR_LOCAL] = &comm_attr_local.attr,
	[COMM_ATTR_ADDR] = &comm_attr_addr.attr,
	NULL,
	COMM_ATTR_ADDR_LIST,
};

enum {
	NODE_ATTR_NODEID = 0,
	NODE_ATTR_WEIGHT,
};

struct node_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct dlm_node *, char *);
	ssize_t (*store)(struct dlm_node *, const char *, size_t);
};

static struct node_attribute node_attr_nodeid = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "nodeid",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = node_nodeid_read,
	.store  = node_nodeid_write,
};

static struct node_attribute node_attr_weight = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "weight",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = node_weight_read,
	.store  = node_weight_write,
};

static struct configfs_attribute *node_attrs[] = {
	[NODE_ATTR_NODEID] = &node_attr_nodeid.attr,
	[NODE_ATTR_WEIGHT] = &node_attr_weight.attr,
	NULL,
};

struct dlm_clusters {
	struct configfs_subsystem subsys;
};

struct dlm_spaces {
	struct config_group ss_group;
};

struct dlm_space {
	struct config_group group;
	struct list_head members;
	struct mutex members_lock;
	int members_count;
};

struct dlm_comms {
	struct config_group cs_group;
};

struct dlm_comm {
	struct config_item item;
	int seq;
	int nodeid;
	int local;
	int addr_count;
	struct sockaddr_storage *addr[DLM_MAX_ADDR_COUNT];
};

struct dlm_nodes {
	struct config_group ns_group;
};

struct dlm_node {
	struct config_item item;
	struct list_head list; /* space->members */
	int nodeid;
	int weight;
	int new;
	int comm_seq; /* copy of cm->seq when nd->nodeid is set */
};

static struct configfs_group_operations clusters_ops = {
	.make_group = make_cluster,
	.drop_item = drop_cluster,
};

static struct configfs_item_operations cluster_ops = {
	.release = release_cluster,
	.show_attribute = show_cluster,
	.store_attribute = store_cluster,
};

static struct configfs_group_operations spaces_ops = {
	.make_group = make_space,
	.drop_item = drop_space,
};

static struct configfs_item_operations space_ops = {
	.release = release_space,
};

static struct configfs_group_operations comms_ops = {
	.make_item = make_comm,
	.drop_item = drop_comm,
};

static struct configfs_item_operations comm_ops = {
	.release = release_comm,
	.show_attribute = show_comm,
	.store_attribute = store_comm,
};

static struct configfs_group_operations nodes_ops = {
	.make_item = make_node,
	.drop_item = drop_node,
};

static struct configfs_item_operations node_ops = {
	.release = release_node,
	.show_attribute = show_node,
	.store_attribute = store_node,
};

static const struct config_item_type clusters_type = {
	.ct_group_ops = &clusters_ops,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type cluster_type = {
	.ct_item_ops = &cluster_ops,
	.ct_attrs = cluster_attrs,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type spaces_type = {
	.ct_group_ops = &spaces_ops,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type space_type = {
	.ct_item_ops = &space_ops,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type comms_type = {
	.ct_group_ops = &comms_ops,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type comm_type = {
	.ct_item_ops = &comm_ops,
	.ct_attrs = comm_attrs,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type nodes_type = {
	.ct_group_ops = &nodes_ops,
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type node_type = {
	.ct_item_ops = &node_ops,
	.ct_attrs = node_attrs,
	.ct_owner = THIS_MODULE,
};

static struct dlm_cluster *to_cluster(struct config_item *i)
{
	return i ? container_of(to_config_group(i), struct dlm_cluster, group) :
		   NULL;
}

static struct dlm_space *to_space(struct config_item *i)
static struct dlm_space *config_item_to_space(struct config_item *i)
{
	return i ? container_of(to_config_group(i), struct dlm_space, group) :
		   NULL;
}

static struct dlm_comm *to_comm(struct config_item *i)
static struct dlm_comm *config_item_to_comm(struct config_item *i)
{
	return i ? container_of(i, struct dlm_comm, item) : NULL;
}

static struct dlm_node *to_node(struct config_item *i)
static struct dlm_node *config_item_to_node(struct config_item *i)
{
	return i ? container_of(i, struct dlm_node, item) : NULL;
}

static struct config_group *make_cluster(struct config_group *g,
					 const char *name)
{
	struct dlm_cluster *cl = NULL;
	struct dlm_spaces *sps = NULL;
	struct dlm_comms *cms = NULL;

	cl = kzalloc(sizeof(struct dlm_cluster), GFP_KERNEL);
	gps = kcalloc(3, sizeof(struct config_group *), GFP_KERNEL);
	sps = kzalloc(sizeof(struct dlm_spaces), GFP_KERNEL);
	cms = kzalloc(sizeof(struct dlm_comms), GFP_KERNEL);
	cl = kzalloc(sizeof(struct dlm_cluster), GFP_NOFS);
	sps = kzalloc(sizeof(struct dlm_spaces), GFP_NOFS);
	cms = kzalloc(sizeof(struct dlm_comms), GFP_NOFS);

	if (!cl || !sps || !cms)
		goto fail;

	config_group_init_type_name(&cl->group, name, &cluster_type);
	config_group_init_type_name(&sps->ss_group, "spaces", &spaces_type);
	config_group_init_type_name(&cms->cs_group, "comms", &comms_type);

	configfs_add_default_group(&sps->ss_group, &cl->group);
	configfs_add_default_group(&cms->cs_group, &cl->group);

	cl->cl_tcp_port = dlm_config.ci_tcp_port;
	cl->cl_buffer_size = dlm_config.ci_buffer_size;
	cl->cl_rsbtbl_size = dlm_config.ci_rsbtbl_size;
	cl->cl_lkbtbl_size = dlm_config.ci_lkbtbl_size;
	cl->cl_dirtbl_size = dlm_config.ci_dirtbl_size;
	cl->cl_recover_timer = dlm_config.ci_recover_timer;
	cl->cl_toss_secs = dlm_config.ci_toss_secs;
	cl->cl_scan_secs = dlm_config.ci_scan_secs;
	cl->cl_log_debug = dlm_config.ci_log_debug;
	cl->cl_log_info = dlm_config.ci_log_info;
	cl->cl_protocol = dlm_config.ci_protocol;
	cl->cl_timewarn_cs = dlm_config.ci_timewarn_cs;
	cl->cl_waitwarn_us = dlm_config.ci_waitwarn_us;
	cl->cl_new_rsb_count = dlm_config.ci_new_rsb_count;
	cl->cl_recover_callbacks = dlm_config.ci_recover_callbacks;
	memcpy(cl->cl_cluster_name, dlm_config.ci_cluster_name,
	       DLM_LOCKSPACE_LEN);

	space_list = &sps->ss_group;
	comm_list = &cms->cs_group;
	return &cl->group;

 fail:
	kfree(cl);
	kfree(sps);
	kfree(cms);
	return ERR_PTR(-ENOMEM);
}

static void drop_cluster(struct config_group *g, struct config_item *i)
{
	struct dlm_cluster *cl = to_cluster(i);
	struct dlm_cluster *cl = config_item_to_cluster(i);

	configfs_remove_default_groups(&cl->group);

	space_list = NULL;
	comm_list = NULL;

	config_item_put(i);
}

static void release_cluster(struct config_item *i)
{
	struct dlm_cluster *cl = to_cluster(i);
	struct dlm_cluster *cl = config_item_to_cluster(i);
	kfree(cl);
}

static struct config_group *make_space(struct config_group *g, const char *name)
{
	struct dlm_space *sp = NULL;
	struct dlm_nodes *nds = NULL;

	sp = kzalloc(sizeof(struct dlm_space), GFP_KERNEL);
	gps = kcalloc(2, sizeof(struct config_group *), GFP_KERNEL);
	nds = kzalloc(sizeof(struct dlm_nodes), GFP_KERNEL);
	sp = kzalloc(sizeof(struct dlm_space), GFP_NOFS);
	nds = kzalloc(sizeof(struct dlm_nodes), GFP_NOFS);

	if (!sp || !nds)
		goto fail;

	config_group_init_type_name(&sp->group, name, &space_type);

	config_group_init_type_name(&nds->ns_group, "nodes", &nodes_type);
	configfs_add_default_group(&nds->ns_group, &sp->group);

	INIT_LIST_HEAD(&sp->members);
	mutex_init(&sp->members_lock);
	sp->members_count = 0;
	return &sp->group;

 fail:
	kfree(sp);
	kfree(nds);
	return ERR_PTR(-ENOMEM);
}

static void drop_space(struct config_group *g, struct config_item *i)
{
	struct dlm_space *sp = to_space(i);
	struct dlm_space *sp = config_item_to_space(i);

	/* assert list_empty(&sp->members) */

	configfs_remove_default_groups(&sp->group);
	config_item_put(i);
}

static void release_space(struct config_item *i)
{
	struct dlm_space *sp = to_space(i);
	struct dlm_space *sp = config_item_to_space(i);
	kfree(sp);
}

static struct config_item *make_comm(struct config_group *g, const char *name)
{
	struct dlm_comm *cm;

	cm = kzalloc(sizeof(struct dlm_comm), GFP_KERNEL);
	cm = kzalloc(sizeof(struct dlm_comm), GFP_NOFS);
	if (!cm)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&cm->item, name, &comm_type);

	cm->seq = dlm_comm_count++;
	if (!cm->seq)
		cm->seq = dlm_comm_count++;

	cm->nodeid = -1;
	cm->local = 0;
	cm->addr_count = 0;
	return &cm->item;
}

static void drop_comm(struct config_group *g, struct config_item *i)
{
	struct dlm_comm *cm = to_comm(i);
	struct dlm_comm *cm = config_item_to_comm(i);
	if (local_comm == cm)
		local_comm = NULL;
	dlm_lowcomms_close(cm->nodeid);
	while (cm->addr_count--)
		kfree(cm->addr[cm->addr_count]);
	config_item_put(i);
}

static void release_comm(struct config_item *i)
{
	struct dlm_comm *cm = to_comm(i);
	struct dlm_comm *cm = config_item_to_comm(i);
	kfree(cm);
}

static struct config_item *make_node(struct config_group *g, const char *name)
{
	struct dlm_space *sp = to_space(g->cg_item.ci_parent);
	struct dlm_node *nd;

	nd = kzalloc(sizeof(struct dlm_node), GFP_KERNEL);
	struct dlm_space *sp = config_item_to_space(g->cg_item.ci_parent);
	struct dlm_node *nd;

	nd = kzalloc(sizeof(struct dlm_node), GFP_NOFS);
	if (!nd)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&nd->item, name, &node_type);
	nd->nodeid = -1;
	nd->weight = 1;  /* default weight of 1 if none is set */
	nd->new = 1;     /* set to 0 once it's been read by dlm_nodeid_list() */

	mutex_lock(&sp->members_lock);
	list_add(&nd->list, &sp->members);
	sp->members_count++;
	mutex_unlock(&sp->members_lock);

	return &nd->item;
}

static void drop_node(struct config_group *g, struct config_item *i)
{
	struct dlm_space *sp = to_space(g->cg_item.ci_parent);
	struct dlm_node *nd = to_node(i);
	struct dlm_space *sp = config_item_to_space(g->cg_item.ci_parent);
	struct dlm_node *nd = config_item_to_node(i);

	mutex_lock(&sp->members_lock);
	list_del(&nd->list);
	sp->members_count--;
	mutex_unlock(&sp->members_lock);

	config_item_put(i);
}

static void release_node(struct config_item *i)
{
	struct dlm_node *nd = to_node(i);
	struct dlm_node *nd = config_item_to_node(i);
	kfree(nd);
}

static struct dlm_clusters clusters_root = {
	.subsys = {
		.su_group = {
			.cg_item = {
				.ci_namebuf = "dlm",
				.ci_type = &clusters_type,
			},
		},
	},
};

int __init dlm_config_init(void)
{
	config_group_init(&clusters_root.subsys.su_group);
	mutex_init(&clusters_root.subsys.su_mutex);
	return configfs_register_subsystem(&clusters_root.subsys);
}

void dlm_config_exit(void)
{
	configfs_unregister_subsystem(&clusters_root.subsys);
}

/*
 * Functions for user space to read/write attributes
 */

static ssize_t show_cluster(struct config_item *i, struct configfs_attribute *a,
			    char *buf)
{
	struct dlm_cluster *cl = to_cluster(i);
	struct cluster_attribute *cla =
			container_of(a, struct cluster_attribute, attr);
	return cla->show ? cla->show(cl, buf) : 0;
}

static ssize_t store_cluster(struct config_item *i,
			     struct configfs_attribute *a,
			     const char *buf, size_t len)
{
	struct dlm_cluster *cl = to_cluster(i);
	struct cluster_attribute *cla =
		container_of(a, struct cluster_attribute, attr);
	return cla->store ? cla->store(cl, buf, len) : -EINVAL;
}

static ssize_t show_comm(struct config_item *i, struct configfs_attribute *a,
			 char *buf)
{
	struct dlm_comm *cm = to_comm(i);
	struct comm_attribute *cma =
			container_of(a, struct comm_attribute, attr);
	return cma->show ? cma->show(cm, buf) : 0;
}

static ssize_t store_comm(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len)
{
	struct dlm_comm *cm = to_comm(i);
	struct comm_attribute *cma =
		container_of(a, struct comm_attribute, attr);
	return cma->store ? cma->store(cm, buf, len) : -EINVAL;
}

static ssize_t comm_nodeid_read(struct dlm_comm *cm, char *buf)
{
	return sprintf(buf, "%d\n", cm->nodeid);
}

static ssize_t comm_nodeid_write(struct dlm_comm *cm, const char *buf,
				 size_t len)
{
	cm->nodeid = simple_strtol(buf, NULL, 0);
	return len;
}

static ssize_t comm_local_read(struct dlm_comm *cm, char *buf)
{
	return sprintf(buf, "%d\n", cm->local);
}

static ssize_t comm_local_write(struct dlm_comm *cm, const char *buf,
				size_t len)
{
	cm->local= simple_strtol(buf, NULL, 0);
static ssize_t comm_nodeid_show(struct config_item *item, char *buf)
{
	return sprintf(buf, "%d\n", config_item_to_comm(item)->nodeid);
}

static ssize_t comm_nodeid_store(struct config_item *item, const char *buf,
				 size_t len)
{
	int rc = kstrtoint(buf, 0, &config_item_to_comm(item)->nodeid);

	if (rc)
		return rc;
	return len;
}

static ssize_t comm_local_show(struct config_item *item, char *buf)
{
	return sprintf(buf, "%d\n", config_item_to_comm(item)->local);
}

static ssize_t comm_local_store(struct config_item *item, const char *buf,
				size_t len)
{
	struct dlm_comm *cm = config_item_to_comm(item);
	int rc = kstrtoint(buf, 0, &cm->local);

	if (rc)
		return rc;
	if (cm->local && !local_comm)
		local_comm = cm;
	return len;
}

static ssize_t comm_addr_write(struct dlm_comm *cm, const char *buf, size_t len)
{
	struct sockaddr_storage *addr;
static ssize_t comm_addr_store(struct config_item *item, const char *buf,
		size_t len)
{
	struct dlm_comm *cm = config_item_to_comm(item);
	struct sockaddr_storage *addr;
	int rv;

	if (len != sizeof(struct sockaddr_storage))
		return -EINVAL;

	if (cm->addr_count >= DLM_MAX_ADDR_COUNT)
		return -ENOSPC;

	addr = kzalloc(sizeof(*addr), GFP_KERNEL);
	addr = kzalloc(sizeof(*addr), GFP_NOFS);
	if (!addr)
		return -ENOMEM;

	memcpy(addr, buf, len);

	rv = dlm_lowcomms_addr(cm->nodeid, addr, len);
	if (rv) {
		kfree(addr);
		return rv;
	}

	cm->addr[cm->addr_count++] = addr;
	return len;
}

static ssize_t show_node(struct config_item *i, struct configfs_attribute *a,
			 char *buf)
{
	struct dlm_node *nd = to_node(i);
	struct node_attribute *nda =
			container_of(a, struct node_attribute, attr);
	return nda->show ? nda->show(nd, buf) : 0;
}

static ssize_t store_node(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len)
{
	struct dlm_node *nd = to_node(i);
	struct node_attribute *nda =
		container_of(a, struct node_attribute, attr);
	return nda->store ? nda->store(nd, buf, len) : -EINVAL;
}

static ssize_t node_nodeid_read(struct dlm_node *nd, char *buf)
{
	return sprintf(buf, "%d\n", nd->nodeid);
}

static ssize_t node_nodeid_write(struct dlm_node *nd, const char *buf,
				 size_t len)
{
	nd->nodeid = simple_strtol(buf, NULL, 0);
	return len;
}

static ssize_t node_weight_read(struct dlm_node *nd, char *buf)
{
	return sprintf(buf, "%d\n", nd->weight);
}

static ssize_t node_weight_write(struct dlm_node *nd, const char *buf,
				 size_t len)
{
	nd->weight = simple_strtol(buf, NULL, 0);
	return len;
}

static ssize_t comm_addr_list_show(struct config_item *item, char *buf)
{
	struct dlm_comm *cm = config_item_to_comm(item);
	ssize_t s;
	ssize_t allowance;
	int i;
	struct sockaddr_storage *addr;
	struct sockaddr_in *addr_in;
	struct sockaddr_in6 *addr_in6;
	
	/* Taken from ip6_addr_string() defined in lib/vsprintf.c */
	char buf0[sizeof("AF_INET6	xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255\n")];
	

	/* Derived from SIMPLE_ATTR_SIZE of fs/configfs/file.c */
	allowance = 4096;
	buf[0] = '\0';

	for (i = 0; i < cm->addr_count; i++) {
		addr = cm->addr[i];

		switch(addr->ss_family) {
		case AF_INET:
			addr_in = (struct sockaddr_in *)addr;
			s = sprintf(buf0, "AF_INET	%pI4\n", &addr_in->sin_addr.s_addr);
			break;
		case AF_INET6:
			addr_in6 = (struct sockaddr_in6 *)addr;
			s = sprintf(buf0, "AF_INET6	%pI6\n", &addr_in6->sin6_addr);
			break;
		default:
			s = sprintf(buf0, "%s\n", "<UNKNOWN>");
			break;
		}
		allowance -= s;
		if (allowance >= 0)
			strcat(buf, buf0);
		else {
			allowance += s;
			break;
		}
	}
	return 4096 - allowance;
}

CONFIGFS_ATTR(comm_, nodeid);
CONFIGFS_ATTR(comm_, local);
CONFIGFS_ATTR_WO(comm_, addr);
CONFIGFS_ATTR_RO(comm_, addr_list);

static struct configfs_attribute *comm_attrs[] = {
	[COMM_ATTR_NODEID] = &comm_attr_nodeid,
	[COMM_ATTR_LOCAL] = &comm_attr_local,
	[COMM_ATTR_ADDR] = &comm_attr_addr,
	[COMM_ATTR_ADDR_LIST] = &comm_attr_addr_list,
	NULL,
};

static ssize_t node_nodeid_show(struct config_item *item, char *buf)
{
	return sprintf(buf, "%d\n", config_item_to_node(item)->nodeid);
}

static ssize_t node_nodeid_store(struct config_item *item, const char *buf,
				 size_t len)
{
	struct dlm_node *nd = config_item_to_node(item);
	uint32_t seq = 0;
	int rc = kstrtoint(buf, 0, &nd->nodeid);

	if (rc)
		return rc;
	dlm_comm_seq(nd->nodeid, &seq);
	nd->comm_seq = seq;
	return len;
}

static ssize_t node_weight_show(struct config_item *item, char *buf)
{
	return sprintf(buf, "%d\n", config_item_to_node(item)->weight);
}

static ssize_t node_weight_store(struct config_item *item, const char *buf,
				 size_t len)
{
	int rc = kstrtoint(buf, 0, &config_item_to_node(item)->weight);

	if (rc)
		return rc;
	return len;
}

CONFIGFS_ATTR(node_, nodeid);
CONFIGFS_ATTR(node_, weight);

static struct configfs_attribute *node_attrs[] = {
	[NODE_ATTR_NODEID] = &node_attr_nodeid,
	[NODE_ATTR_WEIGHT] = &node_attr_weight,
	NULL,
};

/*
 * Functions for the dlm to get the info that's been configured
 */

static struct dlm_space *get_space(char *name)
{
	struct config_item *i;

	if (!space_list)
		return NULL;

	mutex_lock(&space_list->cg_subsys->su_mutex);
	i = config_group_find_item(space_list, name);
	mutex_unlock(&space_list->cg_subsys->su_mutex);

	return to_space(i);
	return config_item_to_space(i);
}

static void put_space(struct dlm_space *sp)
{
	config_item_put(&sp->group.cg_item);
}

static struct dlm_comm *get_comm(int nodeid, struct sockaddr_storage *addr)
static struct dlm_comm *get_comm(int nodeid)
{
	struct config_item *i;
	struct dlm_comm *cm = NULL;
	int found = 0;

	if (!comm_list)
		return NULL;

	mutex_lock(&clusters_root.subsys.su_mutex);

	list_for_each_entry(i, &comm_list->cg_children, ci_entry) {
		cm = to_comm(i);

		if (nodeid) {
			if (cm->nodeid != nodeid)
				continue;
			found = 1;
			config_item_get(i);
			break;
		} else {
			if (!cm->addr_count ||
			    memcmp(cm->addr[0], addr, sizeof(*addr)))
				continue;
			found = 1;
			config_item_get(i);
			break;
		}
		cm = config_item_to_comm(i);

		if (cm->nodeid != nodeid)
			continue;
		found = 1;
		config_item_get(i);
		break;
	}
	mutex_unlock(&clusters_root.subsys.su_mutex);

	if (!found)
		cm = NULL;
	return cm;
}

static void put_comm(struct dlm_comm *cm)
{
	config_item_put(&cm->item);
}

/* caller must free mem */
int dlm_nodeid_list(char *lsname, int **ids_out, int *ids_count_out,
		    int **new_out, int *new_count_out)
{
	struct dlm_space *sp;
	struct dlm_node *nd;
	int i = 0, rv = 0, ids_count = 0, new_count = 0;
	int *ids, *new;
int dlm_config_nodes(char *lsname, struct dlm_config_node **nodes_out,
		     int *count_out)
{
	struct dlm_space *sp;
	struct dlm_node *nd;
	struct dlm_config_node *nodes, *node;
	int rv, count;

	sp = get_space(lsname);
	if (!sp)
		return -EEXIST;

	mutex_lock(&sp->members_lock);
	if (!sp->members_count) {
		rv = -EINVAL;
		printk(KERN_ERR "dlm: zero members_count\n");
		goto out;
	}

	ids_count = sp->members_count;

	ids = kcalloc(ids_count, sizeof(int), GFP_KERNEL);
	if (!ids) {
	count = sp->members_count;

	nodes = kcalloc(count, sizeof(struct dlm_config_node), GFP_NOFS);
	if (!nodes) {
		rv = -ENOMEM;
		goto out;
	}

	list_for_each_entry(nd, &sp->members, list) {
		ids[i++] = nd->nodeid;
		if (nd->new)
			new_count++;
	}

	if (ids_count != i)
		printk(KERN_ERR "dlm: bad nodeid count %d %d\n", ids_count, i);

	if (!new_count)
		goto out_ids;

	new = kcalloc(new_count, sizeof(int), GFP_KERNEL);
	if (!new) {
		kfree(ids);
		rv = -ENOMEM;
		goto out;
	}

	i = 0;
	list_for_each_entry(nd, &sp->members, list) {
		if (nd->new) {
			new[i++] = nd->nodeid;
			nd->new = 0;
		}
	}
	*new_count_out = new_count;
	*new_out = new;

 out_ids:
	*ids_count_out = ids_count;
	*ids_out = ids;
	node = nodes;
	list_for_each_entry(nd, &sp->members, list) {
		node->nodeid = nd->nodeid;
		node->weight = nd->weight;
		node->new = nd->new;
		node->comm_seq = nd->comm_seq;
		node++;

		nd->new = 0;
	}

	*count_out = count;
	*nodes_out = nodes;
	rv = 0;
 out:
	mutex_unlock(&sp->members_lock);
	put_space(sp);
	return rv;
}

int dlm_node_weight(char *lsname, int nodeid)
{
	struct dlm_space *sp;
	struct dlm_node *nd;
	int w = -EEXIST;

	sp = get_space(lsname);
	if (!sp)
		goto out;

	mutex_lock(&sp->members_lock);
	list_for_each_entry(nd, &sp->members, list) {
		if (nd->nodeid != nodeid)
			continue;
		w = nd->weight;
		break;
	}
	mutex_unlock(&sp->members_lock);
	put_space(sp);
 out:
	return w;
}

int dlm_nodeid_to_addr(int nodeid, struct sockaddr_storage *addr)
{
	struct dlm_comm *cm = get_comm(nodeid, NULL);
	if (!cm)
		return -EEXIST;
	if (!cm->addr_count)
		return -ENOENT;
	memcpy(addr, cm->addr[0], sizeof(*addr));
	put_comm(cm);
	return 0;
}

int dlm_addr_to_nodeid(struct sockaddr_storage *addr, int *nodeid)
{
	struct dlm_comm *cm = get_comm(0, addr);
	if (!cm)
		return -EEXIST;
	*nodeid = cm->nodeid;
int dlm_comm_seq(int nodeid, uint32_t *seq)
{
	struct dlm_comm *cm = get_comm(nodeid);
	if (!cm)
		return -EEXIST;
	*seq = cm->seq;
	put_comm(cm);
	return 0;
}

int dlm_our_nodeid(void)
{
	return local_comm ? local_comm->nodeid : 0;
}

/* num 0 is first addr, num 1 is second addr */
int dlm_our_addr(struct sockaddr_storage *addr, int num)
{
	if (!local_comm)
		return -1;
	if (num + 1 > local_comm->addr_count)
		return -1;
	memcpy(addr, local_comm->addr[num], sizeof(*addr));
	return 0;
}

/* Config file defaults */
#define DEFAULT_TCP_PORT       21064
#define DEFAULT_BUFFER_SIZE     4096
#define DEFAULT_RSBTBL_SIZE      256
#define DEFAULT_LKBTBL_SIZE     1024
#define DEFAULT_DIRTBL_SIZE      512
#define DEFAULT_RSBTBL_SIZE     1024
#define DEFAULT_RECOVER_TIMER      5
#define DEFAULT_TOSS_SECS         10
#define DEFAULT_SCAN_SECS          5
#define DEFAULT_LOG_DEBUG          0
#define DEFAULT_LOG_INFO           1
#define DEFAULT_PROTOCOL           0
#define DEFAULT_TIMEWARN_CS      500 /* 5 sec = 500 centiseconds */
#define DEFAULT_WAITWARN_US	   0
#define DEFAULT_NEW_RSB_COUNT    128
#define DEFAULT_RECOVER_CALLBACKS  0
#define DEFAULT_CLUSTER_NAME      ""

struct dlm_config_info dlm_config = {
	.ci_tcp_port = DEFAULT_TCP_PORT,
	.ci_buffer_size = DEFAULT_BUFFER_SIZE,
	.ci_rsbtbl_size = DEFAULT_RSBTBL_SIZE,
	.ci_lkbtbl_size = DEFAULT_LKBTBL_SIZE,
	.ci_dirtbl_size = DEFAULT_DIRTBL_SIZE,
	.ci_recover_timer = DEFAULT_RECOVER_TIMER,
	.ci_toss_secs = DEFAULT_TOSS_SECS,
	.ci_scan_secs = DEFAULT_SCAN_SECS,
	.ci_log_debug = DEFAULT_LOG_DEBUG,
	.ci_log_info = DEFAULT_LOG_INFO,
	.ci_protocol = DEFAULT_PROTOCOL,
	.ci_timewarn_cs = DEFAULT_TIMEWARN_CS
	.ci_timewarn_cs = DEFAULT_TIMEWARN_CS,
	.ci_waitwarn_us = DEFAULT_WAITWARN_US,
	.ci_new_rsb_count = DEFAULT_NEW_RSB_COUNT,
	.ci_recover_callbacks = DEFAULT_RECOVER_CALLBACKS,
	.ci_cluster_name = DEFAULT_CLUSTER_NAME
};

