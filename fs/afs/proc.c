/* /proc interface for AFS
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include "internal.h"

static inline struct afs_net *afs_seq2net(struct seq_file *m)
{
	return afs_net(seq_file_net(m));
}

static inline struct afs_net *afs_seq2net_single(struct seq_file *m)
{
	return afs_net(seq_file_single_net(m));
}

/*
 * Display the list of cells known to the namespace.
 */
static int afs_proc_cells_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = list_entry(v, struct afs_cell, proc_link);

	if (v == SEQ_START_TOKEN) {
		/* display header on line 1 */
		seq_puts(m, "USE NAME\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%3u %s\n", atomic_read(&cell->usage), cell->name);
	return 0;
}

static void *afs_proc_cells_start(struct seq_file *m, loff_t *_pos)
	__acquires(rcu)
{
	rcu_read_lock();
	return seq_hlist_start_head_rcu(&afs_seq2net(m)->proc_cells, *_pos);
}

static void *afs_proc_cells_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_hlist_next_rcu(v, &afs_seq2net(m)->proc_cells, pos);
}

static void afs_proc_cells_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

static struct seq_operations afs_proc_cells_ops = {
static const struct seq_operations afs_proc_cells_ops = {
	.start	= afs_proc_cells_start,
	.next	= afs_proc_cells_next,
	.stop	= afs_proc_cells_stop,
	.show	= afs_proc_cells_show,
};

static const struct file_operations afs_proc_cells_fops = {
	.open		= afs_proc_cells_open,
	.read		= seq_read,
	.write		= afs_proc_cells_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.owner		= THIS_MODULE,
};

static int afs_proc_rootcell_open(struct inode *inode, struct file *file);
static int afs_proc_rootcell_release(struct inode *inode, struct file *file);
};

static ssize_t afs_proc_rootcell_read(struct file *file, char __user *buf,
				      size_t size, loff_t *_pos);
static ssize_t afs_proc_rootcell_write(struct file *file,
				       const char __user *buf,
				       size_t size, loff_t *_pos);

static const struct file_operations afs_proc_rootcell_fops = {
	.open		= afs_proc_rootcell_open,
	.read		= afs_proc_rootcell_read,
	.write		= afs_proc_rootcell_write,
	.llseek		= no_llseek,
	.release	= afs_proc_rootcell_release,
	.owner		= THIS_MODULE,
};

static int afs_proc_cell_volumes_open(struct inode *inode, struct file *file);
static int afs_proc_cell_volumes_release(struct inode *inode,
					 struct file *file);
	.read		= afs_proc_rootcell_read,
	.write		= afs_proc_rootcell_write,
	.llseek		= no_llseek,
};

static int afs_proc_cell_volumes_open(struct inode *inode, struct file *file);
static void *afs_proc_cell_volumes_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cell_volumes_next(struct seq_file *p, void *v,
					loff_t *pos);
static void afs_proc_cell_volumes_stop(struct seq_file *p, void *v);
static int afs_proc_cell_volumes_show(struct seq_file *m, void *v);

static struct seq_operations afs_proc_cell_volumes_ops = {
static const struct seq_operations afs_proc_cell_volumes_ops = {
	.start	= afs_proc_cell_volumes_start,
	.next	= afs_proc_cell_volumes_next,
	.stop	= afs_proc_cell_volumes_stop,
	.show	= afs_proc_cell_volumes_show,
};

static const struct file_operations afs_proc_cell_volumes_fops = {
	.open		= afs_proc_cell_volumes_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= afs_proc_cell_volumes_release,
	.owner		= THIS_MODULE,
	.release	= seq_release,
};

static int afs_proc_cell_vlservers_open(struct inode *inode,
					struct file *file);
static int afs_proc_cell_vlservers_release(struct inode *inode,
					   struct file *file);
static void *afs_proc_cell_vlservers_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cell_vlservers_next(struct seq_file *p, void *v,
					  loff_t *pos);
static void afs_proc_cell_vlservers_stop(struct seq_file *p, void *v);
static int afs_proc_cell_vlservers_show(struct seq_file *m, void *v);

static struct seq_operations afs_proc_cell_vlservers_ops = {
static const struct seq_operations afs_proc_cell_vlservers_ops = {
	.start	= afs_proc_cell_vlservers_start,
	.next	= afs_proc_cell_vlservers_next,
	.stop	= afs_proc_cell_vlservers_stop,
	.show	= afs_proc_cell_vlservers_show,
};

static const struct file_operations afs_proc_cell_vlservers_fops = {
	.open		= afs_proc_cell_vlservers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= afs_proc_cell_vlservers_release,
	.owner		= THIS_MODULE,
};

static int afs_proc_cell_servers_open(struct inode *inode, struct file *file);
static int afs_proc_cell_servers_release(struct inode *inode,
					 struct file *file);
	.release	= seq_release,
};

static int afs_proc_cell_servers_open(struct inode *inode, struct file *file);
static void *afs_proc_cell_servers_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cell_servers_next(struct seq_file *p, void *v,
					loff_t *pos);
static void afs_proc_cell_servers_stop(struct seq_file *p, void *v);
static int afs_proc_cell_servers_show(struct seq_file *m, void *v);

static struct seq_operations afs_proc_cell_servers_ops = {
static const struct seq_operations afs_proc_cell_servers_ops = {
	.start	= afs_proc_cell_servers_start,
	.next	= afs_proc_cell_servers_next,
	.stop	= afs_proc_cell_servers_stop,
	.show	= afs_proc_cell_servers_show,
};

static const struct file_operations afs_proc_cell_servers_fops = {
	.open		= afs_proc_cell_servers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= afs_proc_cell_servers_release,
	.owner		= THIS_MODULE,
	.release	= seq_release,
};

/*
 * initialise the /proc/fs/afs/ directory
 */
int afs_proc_init(void)
{
	struct proc_dir_entry *p;

	_enter("");

	proc_afs = proc_mkdir("fs/afs", NULL);
	if (!proc_afs)
		goto error_dir;
	proc_afs->owner = THIS_MODULE;

	p = proc_create("cells", 0, proc_afs, &afs_proc_cells_fops);
	if (!p)
		goto error_cells;

	p = proc_create("rootcell", 0, proc_afs, &afs_proc_rootcell_fops);
	if (!p)
		goto error_rootcell;

	if (!proc_create("cells", 0644, proc_afs, &afs_proc_cells_fops) ||
	    !proc_create("rootcell", 0644, proc_afs, &afs_proc_rootcell_fops))
		goto error_tree;

	_leave(" = 0");
	return 0;

error_rootcell:
 	remove_proc_entry("cells", proc_afs);
error_cells:
	remove_proc_entry("fs/afs", NULL);
error_tree:
	remove_proc_subtree("fs/afs", NULL);
error_dir:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * clean up the /proc/fs/afs/ directory
 */
void afs_proc_cleanup(void)
{
	remove_proc_entry("rootcell", proc_afs);
	remove_proc_entry("cells", proc_afs);
	remove_proc_entry("fs/afs", NULL);
	remove_proc_subtree("fs/afs", NULL);
}

/*
 * open "/proc/fs/afs/cells" which provides a summary of extant cells
 */
static int afs_proc_cells_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &afs_proc_cells_ops);
	if (ret < 0)
		return ret;

	m = file->private_data;
	m->private = PDE(inode)->data;
	m->private = PDE_DATA(inode);

	return 0;
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cells_start(struct seq_file *m, loff_t *_pos)
{
	/* lock the list against modification */
	down_read(&afs_proc_cells_sem);
	return seq_list_start_head(&afs_proc_cells, *_pos);
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cells_next(struct seq_file *p, void *v, loff_t *pos)
{
	return seq_list_next(v, &afs_proc_cells, pos);
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cells_stop(struct seq_file *p, void *v)
{
	up_read(&afs_proc_cells_sem);
}

/*
 * display a header line followed by a load of cell lines
 */
static int afs_proc_cells_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = list_entry(v, struct afs_cell, proc_link);

	if (v == &afs_proc_cells) {
		/* display header on line 1 */
		seq_puts(m, "USE NAME\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%3d %s\n",
		   atomic_read(&cell->usage), cell->name);
	return 0;
}

/*
 * handle writes to /proc/fs/afs/cells
 * - to add cells: echo "add <cellname> <IP>[:<IP>][:<IP>]"
 */
static int afs_proc_cells_write(struct file *file, char *buf, size_t size)
{
	struct seq_file *m = file->private_data;
	struct afs_net *net = afs_seq2net(m);
	char *name, *args;
	int ret;

	/* trim to first NL */
	name = memchr(buf, '\n', size);
	if (name)
		*name = 0;

	/* split into command, name and argslist */
	name = strchr(buf, ' ');
	if (!name)
		goto inval;
	do {
		*name++ = 0;
	} while(*name == ' ');
	if (!*name)
		goto inval;

	args = strchr(name, ' ');
	if (args) {
		do {
			*args++ = 0;
		} while(*args == ' ');
		if (!*args)
			goto inval;
	}

	/* determine command to perform */
	_debug("cmd=%s name=%s args=%s", buf, name, args);

	if (strcmp(buf, "add") == 0) {
		struct afs_cell *cell;

		cell = afs_cell_create(name, args);
		cell = afs_cell_create(name, strlen(name), args, false);
		cell = afs_lookup_cell(net, name, strlen(name), args, true);
		if (IS_ERR(cell)) {
			ret = PTR_ERR(cell);
			goto done;
		}

		if (test_and_set_bit(AFS_CELL_FL_NO_GC, &cell->flags))
			afs_put_cell(net, cell);
	} else {
		goto inval;
	}

	ret = 0;

done:
	_leave(" = %d", ret);
	return ret;

inval:
	ret = -EINVAL;
	printk("kAFS: Invalid Command on /proc/fs/afs/cells file\n");
	goto done;
}

/*
 * Stubs for /proc/fs/afs/rootcell
 */
static int afs_proc_rootcell_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int afs_proc_rootcell_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t afs_proc_rootcell_read(struct file *file, char __user *buf,
				      size_t size, loff_t *_pos)
 * Display the name of the current workstation cell.
 */
static int afs_proc_rootcell_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell;
	struct afs_net *net;

	net = afs_seq2net_single(m);
	if (rcu_access_pointer(net->ws_cell)) {
		rcu_read_lock();
		cell = rcu_dereference(net->ws_cell);
		if (cell)
			seq_printf(m, "%s\n", cell->name);
		rcu_read_unlock();
	}
	return 0;
}

/*
 * Set the current workstation cell and optionally supply its list of volume
 * location servers.
 *
 *	echo "cell.name:192.168.231.14" >/proc/fs/afs/rootcell
 */
static int afs_proc_rootcell_write(struct file *file, char *buf, size_t size)
{
	struct seq_file *m = file->private_data;
	struct afs_net *net = afs_seq2net_single(m);
	char *s;
	int ret;

	ret = -EINVAL;
	if (buf[0] == '.')
		goto out;
	if (memchr(buf, '/', size))
		goto out;

	/* trim to first NL */
	s = memchr(buf, '\n', size);
	if (s)
		*s = 0;

	/* determine command to perform */
	_debug("rootcell=%s", buf);

	ret = afs_cell_init(net, buf);

out:
	_leave(" = %d", ret);
	return ret;
}

static const char afs_vol_types[3][3] = {
	[AFSVL_RWVOL]	= "RW",
	[AFSVL_ROVOL]	= "RO",
	[AFSVL_BACKVOL]	= "BK",
};

/*
 * Display the list of volumes known to a cell.
 */
static int afs_proc_cell_volumes_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = PDE_DATA(file_inode(m->file));
	struct afs_volume *vol = list_entry(v, struct afs_volume, proc_link);

	/* Display header on line 1 */
	if (v == &cell->proc_volumes) {
		seq_puts(m, "USE VID      TY\n");
		return 0;
	}

	seq_printf(m, "%3d %08x %s\n",
		   atomic_read(&vol->usage), vol->vid,
		   afs_vol_types[vol->type]);

	return 0;
}

static void *afs_proc_cell_volumes_start(struct seq_file *m, loff_t *_pos)
	__acquires(cell->proc_lock)
{
	struct afs_cell *cell = PDE_DATA(file_inode(m->file));

	read_lock(&cell->proc_lock);
	return seq_list_start_head(&cell->proc_volumes, *_pos);
}

static void *afs_proc_cell_volumes_next(struct seq_file *m, void *v,
					loff_t *_pos)
{
	struct afs_cell *cell = PDE_DATA(file_inode(m->file));

	return seq_list_next(v, &cell->proc_volumes, _pos);
}

static void afs_proc_cell_volumes_stop(struct seq_file *m, void *v)
	__releases(cell->proc_lock)
{
	struct afs_cell *cell = PDE_DATA(file_inode(m->file));

	read_unlock(&cell->proc_lock);
}

static const struct seq_operations afs_proc_cell_volumes_ops = {
	.start	= afs_proc_cell_volumes_start,
	.next	= afs_proc_cell_volumes_next,
	.stop	= afs_proc_cell_volumes_stop,
	.show	= afs_proc_cell_volumes_show,
};

/*
 * Display the list of Volume Location servers we're using for a cell.
 */
static int afs_proc_cell_vlservers_show(struct seq_file *m, void *v)
{
	struct sockaddr_rxrpc *addr = v;

	/* display header on line 1 */
	if (v == (void *)1) {
		seq_puts(m, "ADDRESS\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%pISp\n", &addr->transport);
	return 0;
}

static void *afs_proc_cell_vlservers_start(struct seq_file *m, loff_t *_pos)
	__acquires(rcu)
{
	struct afs_addr_list *alist;
	struct afs_cell *cell = PDE_DATA(file_inode(m->file));
	loff_t pos = *_pos;

	rcu_read_lock();

	alist = rcu_dereference(cell->vl_addrs);

	/* allow for the header line */
	if (!pos)
		return (void *) 1;
	pos--;

	if (!alist || pos >= alist->nr_addrs)
		return NULL;

	return alist->addrs + pos;
}

static void *afs_proc_cell_vlservers_next(struct seq_file *m, void *v,
					  loff_t *_pos)
{
	struct afs_addr_list *alist;
	struct afs_cell *cell = PDE_DATA(file_inode(m->file));
	loff_t pos;

	alist = rcu_dereference(cell->vl_addrs);

	pos = *_pos;
	(*_pos)++;
	if (!alist || pos >= alist->nr_addrs)
		return NULL;

	return alist->addrs + pos;
}

static void afs_proc_cell_vlservers_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

static const struct seq_operations afs_proc_cell_vlservers_ops = {
	.start	= afs_proc_cell_vlservers_start,
	.next	= afs_proc_cell_vlservers_next,
	.stop	= afs_proc_cell_vlservers_stop,
	.show	= afs_proc_cell_vlservers_show,
};

/*
 * Display the list of fileservers we're using within a namespace.
 */
static int afs_proc_servers_show(struct seq_file *m, void *v)
{
	struct afs_server *server;
	struct afs_addr_list *alist;
	int i;

	if (v == SEQ_START_TOKEN) {
		seq_puts(m, "UUID                                 USE ADDR\n");
		return 0;
	}

	server = list_entry(v, struct afs_server, proc_link);
	alist = rcu_dereference(server->addresses);
	seq_printf(m, "%pU %3d %pISpc%s\n",
		   &server->uuid,
		   atomic_read(&server->usage),
		   &alist->addrs[0].transport,
		   alist->index == 0 ? "*" : "");
	for (i = 1; i < alist->nr_addrs; i++)
		seq_printf(m, "                                         %pISpc%s\n",
			   &alist->addrs[i].transport,
			   alist->index == i ? "*" : "");
	return 0;
}

static void *afs_proc_servers_start(struct seq_file *m, loff_t *_pos)
	__acquires(rcu)
{
	rcu_read_lock();
	return seq_hlist_start_head_rcu(&afs_seq2net(m)->fs_proc, *_pos);
}

static void *afs_proc_servers_next(struct seq_file *m, void *v, loff_t *_pos)
{
	return seq_hlist_next_rcu(v, &afs_seq2net(m)->fs_proc, _pos);
}

static void afs_proc_servers_stop(struct seq_file *m, void *v)
	__releases(rcu)
{
	rcu_read_unlock();
}

static const struct seq_operations afs_proc_servers_ops = {
	.start	= afs_proc_servers_start,
	.next	= afs_proc_servers_next,
	.stop	= afs_proc_servers_stop,
	.show	= afs_proc_servers_show,
};

/*
 * Display the list of strings that may be substituted for the @sys pathname
 * macro.
 */
static int afs_proc_sysname_show(struct seq_file *m, void *v)
{
	struct afs_net *net = afs_seq2net(m);
	struct afs_sysnames *sysnames = net->sysnames;
	unsigned int i = (unsigned long)v - 1;

	if (i < sysnames->nr)
		seq_printf(m, "%s\n", sysnames->subs[i]);
	return 0;
}

static void *afs_proc_sysname_start(struct seq_file *m, loff_t *pos)
	__acquires(&net->sysnames_lock)
{
	struct afs_net *net = afs_seq2net(m);
	struct afs_sysnames *names;

	read_lock(&net->sysnames_lock);

	names = net->sysnames;
	if (*pos >= names->nr)
		return NULL;
	return (void *)(unsigned long)(*pos + 1);
}

static void *afs_proc_sysname_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct afs_net *net = afs_seq2net(m);
	struct afs_sysnames *names = net->sysnames;

	*pos += 1;
	if (*pos >= names->nr)
		return NULL;
	return (void *)(unsigned long)(*pos + 1);
}

static void afs_proc_sysname_stop(struct seq_file *m, void *v)
	__releases(&net->sysnames_lock)
{
	struct afs_net *net = afs_seq2net(m);

	read_unlock(&net->sysnames_lock);
}

static const struct seq_operations afs_proc_sysname_ops = {
	.start	= afs_proc_sysname_start,
	.next	= afs_proc_sysname_next,
	.stop	= afs_proc_sysname_stop,
	.show	= afs_proc_sysname_show,
};

/*
 * Allow the @sys substitution to be configured.
 */
static int afs_proc_sysname_write(struct file *file, char *buf, size_t size)
{
	struct afs_sysnames *sysnames, *kill;
	struct seq_file *m = file->private_data;
	struct afs_net *net = afs_seq2net(m);
	char *s, *p, *sub;
	int ret, len;

	sysnames = kzalloc(sizeof(*sysnames), GFP_KERNEL);
	if (!sysnames)
		return -ENOMEM;
	refcount_set(&sysnames->usage, 1);
	kill = sysnames;

	p = buf;
	while ((s = strsep(&p, " \t\n"))) {
		len = strlen(s);
		if (len == 0)
			continue;
		ret = -ENAMETOOLONG;
		if (len >= AFSNAMEMAX)
			goto error;

		if (len >= 4 &&
		    s[len - 4] == '@' &&
		    s[len - 3] == 's' &&
		    s[len - 2] == 'y' &&
		    s[len - 1] == 's')
			/* Protect against recursion */
			goto invalid;

		if (s[0] == '.' &&
		    (len < 2 || (len == 2 && s[1] == '.')))
			goto invalid;

		if (memchr(s, '/', len))
			goto invalid;

		ret = -EFBIG;
		if (sysnames->nr >= AFS_NR_SYSNAME)
			goto out;

		if (strcmp(s, afs_init_sysname) == 0) {
			sub = (char *)afs_init_sysname;
		} else {
			ret = -ENOMEM;
			sub = kmemdup(s, len + 1, GFP_KERNEL);
			if (!sub)
				goto out;
		}

		sysnames->subs[sysnames->nr] = sub;
		sysnames->nr++;
	}

	if (sysnames->nr == 0) {
		sysnames->subs[0] = sysnames->blank;
		sysnames->nr++;
	}

	write_lock(&net->sysnames_lock);
	kill = net->sysnames;
	net->sysnames = sysnames;
	write_unlock(&net->sysnames_lock);
	ret = 0;
out:
	afs_put_sysnames(kill);
	return ret;

invalid:
	ret = -EINVAL;
error:
	goto out;
}

void afs_put_sysnames(struct afs_sysnames *sysnames)
{
	int i;

	if (sysnames && refcount_dec_and_test(&sysnames->usage)) {
		for (i = 0; i < sysnames->nr; i++)
			if (sysnames->subs[i] != afs_init_sysname &&
			    sysnames->subs[i] != sysnames->blank)
				kfree(sysnames->subs[i]);
	}
}

/*
 * Display general per-net namespace statistics
 */
static int afs_proc_stats_show(struct seq_file *m, void *v)
{
	struct afs_net *net = afs_seq2net_single(m);

	seq_puts(m, "kAFS statistics\n");

	seq_printf(m, "dir-mgmt: look=%u reval=%u inval=%u relpg=%u\n",
		   atomic_read(&net->n_lookup),
		   atomic_read(&net->n_reval),
		   atomic_read(&net->n_inval),
		   atomic_read(&net->n_relpg));

	seq_printf(m, "dir-data: rdpg=%u\n",
		   atomic_read(&net->n_read_dir));

	seq_printf(m, "dir-edit: cr=%u rm=%u\n",
		   atomic_read(&net->n_dir_cr),
		   atomic_read(&net->n_dir_rm));

	seq_printf(m, "file-rd : n=%u nb=%lu\n",
		   atomic_read(&net->n_fetches),
		   atomic_long_read(&net->n_fetch_bytes));
	seq_printf(m, "file-wr : n=%u nb=%lu\n",
		   atomic_read(&net->n_stores),
		   atomic_long_read(&net->n_store_bytes));
	return 0;
}

/*
 * initialise /proc/fs/afs/<cell>/
 */
int afs_proc_cell_setup(struct afs_cell *cell)
{
	struct proc_dir_entry *p;

	_enter("%p{%s}", cell, cell->name);

	cell->proc_dir = proc_mkdir(cell->name, proc_afs);
	if (!cell->proc_dir)
		goto error_dir;

	p = proc_create_data("servers", 0, cell->proc_dir,
			     &afs_proc_cell_servers_fops, cell);
	if (!p)
		goto error_servers;

	p = proc_create_data("vlservers", 0, cell->proc_dir,
			     &afs_proc_cell_vlservers_fops, cell);
	if (!p)
		goto error_vlservers;

	p = proc_create_data("volumes", 0, cell->proc_dir,
			     &afs_proc_cell_volumes_fops, cell);
	if (!p)
		goto error_volumes;
	struct proc_dir_entry *dir;
	struct afs_net *net = cell->net;

	_enter("%p{%s},%p", cell, cell->name, net->proc_afs);

	dir = proc_net_mkdir(net->net, cell->name, net->proc_afs);
	if (!dir)
		goto error_dir;

	if (!proc_create_net_data("vlservers", 0444, dir,
				  &afs_proc_cell_vlservers_ops,
				  sizeof(struct seq_net_private),
				  cell) ||
	    !proc_create_net_data("volumes", 0444, dir,
				  &afs_proc_cell_volumes_ops,
				  sizeof(struct seq_net_private),
				  cell))
		goto error_tree;

	_leave(" = 0");
	return 0;

error_volumes:
	remove_proc_entry("vlservers", cell->proc_dir);
error_vlservers:
	remove_proc_entry("servers", cell->proc_dir);
error_servers:
	remove_proc_entry(cell->name, proc_afs);
error_tree:
	remove_proc_subtree(cell->name, net->proc_afs);
error_dir:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * remove /proc/fs/afs/<cell>/
 */
void afs_proc_cell_remove(struct afs_cell *cell)
{
	struct afs_net *net = cell->net;

	_enter("");

	remove_proc_entry("volumes", cell->proc_dir);
	remove_proc_entry("vlservers", cell->proc_dir);
	remove_proc_entry("servers", cell->proc_dir);
	remove_proc_entry(cell->name, proc_afs);
	remove_proc_subtree(cell->name, proc_afs);

	remove_proc_subtree(cell->name, net->proc_afs);
	_leave("");
}

/*
 * initialise the /proc/fs/afs/ directory
 */
int afs_proc_init(struct afs_net *net)
{
	struct proc_dir_entry *p;

	cell = PDE(inode)->data;
	cell = PDE_DATA(inode);
	if (!cell)
		return -ENOENT;
	_enter("");

	p = proc_net_mkdir(net->net, "afs", net->net->proc_net);
	if (!p)
		goto error_dir;

	if (!proc_create_net_data_write("cells", 0644, p,
					&afs_proc_cells_ops,
					afs_proc_cells_write,
					sizeof(struct seq_net_private),
					NULL) ||
	    !proc_create_net_single_write("rootcell", 0644, p,
					  afs_proc_rootcell_show,
					  afs_proc_rootcell_write,
					  NULL) ||
	    !proc_create_net("servers", 0444, p, &afs_proc_servers_ops,
			     sizeof(struct seq_net_private)) ||
	    !proc_create_net_single("stats", 0444, p, afs_proc_stats_show, NULL) ||
	    !proc_create_net_data_write("sysname", 0644, p,
					&afs_proc_sysname_ops,
					afs_proc_sysname_write,
					sizeof(struct seq_net_private),
					NULL))
		goto error_tree;

	net->proc_afs = p;
	_leave(" = 0");
	return 0;

error_tree:
	proc_remove(p);
error_dir:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * close the file and release the ref to the cell
 */
static int afs_proc_cell_volumes_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 * clean up the /proc/fs/afs/ directory
 */
void afs_proc_cleanup(struct afs_net *net)
{
	struct afs_cell *cell = m->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);

	/* lock the list against modification */
	down_read(&cell->vl_sem);
	return seq_list_start_head(&cell->vl_list, *_pos);
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cell_volumes_next(struct seq_file *p, void *v,
					loff_t *_pos)
{
	struct afs_cell *cell = p->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);
	return seq_list_next(v, &cell->vl_list, _pos);
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cell_volumes_stop(struct seq_file *p, void *v)
{
	struct afs_cell *cell = p->private;

	up_read(&cell->vl_sem);
}

static const char afs_vlocation_states[][4] = {
	[AFS_VL_NEW]			= "New",
	[AFS_VL_CREATING]		= "Crt",
	[AFS_VL_VALID]			= "Val",
	[AFS_VL_NO_VOLUME]		= "NoV",
	[AFS_VL_UPDATING]		= "Upd",
	[AFS_VL_VOLUME_DELETED]		= "Del",
	[AFS_VL_UNCERTAIN]		= "Unc",
};

/*
 * display a header line followed by a load of volume lines
 */
static int afs_proc_cell_volumes_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = m->private;
	struct afs_vlocation *vlocation =
		list_entry(v, struct afs_vlocation, link);

	/* display header on line 1 */
	if (v == &cell->vl_list) {
		seq_puts(m, "USE STT VLID[0]  VLID[1]  VLID[2]  NAME\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%3d %s %08x %08x %08x %s\n",
		   atomic_read(&vlocation->usage),
		   afs_vlocation_states[vlocation->state],
		   vlocation->vldb.vid[0],
		   vlocation->vldb.vid[1],
		   vlocation->vldb.vid[2],
		   vlocation->vldb.name);

	return 0;
}

/*
 * open "/proc/fs/afs/<cell>/vlservers" which provides a list of volume
 * location server
 */
static int afs_proc_cell_vlservers_open(struct inode *inode, struct file *file)
{
	struct afs_cell *cell;
	struct seq_file *m;
	int ret;

	cell = PDE(inode)->data;
	cell = PDE_DATA(inode);
	if (!cell)
		return -ENOENT;

	ret = seq_open(file, &afs_proc_cell_vlservers_ops);
	if (ret<0)
		return ret;

	m = file->private_data;
	m->private = cell;

	return 0;
}

/*
 * close the file and release the ref to the cell
 */
static int afs_proc_cell_vlservers_release(struct inode *inode,
					   struct file *file)
{
	return seq_release(inode, file);
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cell_vlservers_start(struct seq_file *m, loff_t *_pos)
{
	struct afs_cell *cell = m->private;
	loff_t pos = *_pos;

	_enter("cell=%p pos=%Ld", cell, *_pos);

	/* lock the list against modification */
	down_read(&cell->vl_sem);

	/* allow for the header line */
	if (!pos)
		return (void *) 1;
	pos--;

	if (pos >= cell->vl_naddrs)
		return NULL;

	return &cell->vl_addrs[pos];
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cell_vlservers_next(struct seq_file *p, void *v,
					  loff_t *_pos)
{
	struct afs_cell *cell = p->private;
	loff_t pos;

	_enter("cell=%p{nad=%u} pos=%Ld", cell, cell->vl_naddrs, *_pos);

	pos = *_pos;
	(*_pos)++;
	if (pos >= cell->vl_naddrs)
		return NULL;

	return &cell->vl_addrs[pos];
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cell_vlservers_stop(struct seq_file *p, void *v)
{
	struct afs_cell *cell = p->private;

	up_read(&cell->vl_sem);
}

/*
 * display a header line followed by a load of volume lines
 */
static int afs_proc_cell_vlservers_show(struct seq_file *m, void *v)
{
	struct in_addr *addr = v;

	/* display header on line 1 */
	if (v == (struct in_addr *) 1) {
		seq_puts(m, "ADDRESS\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%u.%u.%u.%u\n", NIPQUAD(addr->s_addr));
	seq_printf(m, "%pI4\n", &addr->s_addr);
	return 0;
}

/*
 * open "/proc/fs/afs/<cell>/servers" which provides a summary of active
 * servers
 */
static int afs_proc_cell_servers_open(struct inode *inode, struct file *file)
{
	struct afs_cell *cell;
	struct seq_file *m;
	int ret;

	cell = PDE(inode)->data;
	cell = PDE_DATA(inode);
	if (!cell)
		return -ENOENT;

	ret = seq_open(file, &afs_proc_cell_servers_ops);
	if (ret < 0)
		return ret;

	m = file->private_data;
	m->private = cell;
	return 0;
}

/*
 * close the file and release the ref to the cell
 */
static int afs_proc_cell_servers_release(struct inode *inode,
					 struct file *file)
{
	return seq_release(inode, file);
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cell_servers_start(struct seq_file *m, loff_t *_pos)
	__acquires(m->private->servers_lock)
{
	struct afs_cell *cell = m->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);

	/* lock the list against modification */
	read_lock(&cell->servers_lock);
	return seq_list_start_head(&cell->servers, *_pos);
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cell_servers_next(struct seq_file *p, void *v,
					loff_t *_pos)
{
	struct afs_cell *cell = p->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);
	return seq_list_next(v, &cell->servers, _pos);
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cell_servers_stop(struct seq_file *p, void *v)
	__releases(p->private->servers_lock)
{
	struct afs_cell *cell = p->private;

	read_unlock(&cell->servers_lock);
}

/*
 * display a header line followed by a load of volume lines
 */
static int afs_proc_cell_servers_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = m->private;
	struct afs_server *server = list_entry(v, struct afs_server, link);
	char ipaddr[20];

	/* display header on line 1 */
	if (v == &cell->servers) {
		seq_puts(m, "USE ADDR            STATE\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	sprintf(ipaddr, "%u.%u.%u.%u", NIPQUAD(server->addr));
	sprintf(ipaddr, "%pI4", &server->addr);
	seq_printf(m, "%3d %-15.15s %5d\n",
		   atomic_read(&server->usage), ipaddr, server->fs_state);

	return 0;
	proc_remove(net->proc_afs);
	net->proc_afs = NULL;
}
