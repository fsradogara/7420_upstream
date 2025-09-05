/**
 * @file oprofilefs.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 *
 * A simple filesystem for configuration and
 * access of oprofile.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/oprofile.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>

#include "oprof.h"

#define OPROFILEFS_MAGIC 0x6f70726f

DEFINE_SPINLOCK(oprofilefs_lock);

static struct inode * oprofilefs_get_inode(struct super_block * sb, int mode)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = 0;
		inode->i_gid = 0;
		inode->i_blocks = 0;
DEFINE_RAW_SPINLOCK(oprofilefs_lock);

static struct inode *oprofilefs_get_inode(struct super_block *sb, int mode)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_mode = mode;
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	}
	return inode;
}


static struct super_operations s_ops = {
static const struct super_operations s_ops = {
	.statfs		= simple_statfs,
	.drop_inode 	= generic_delete_inode,
};


ssize_t oprofilefs_str_to_user(char const * str, char __user * buf, size_t count, loff_t * offset)
ssize_t oprofilefs_str_to_user(char const *str, char __user *buf, size_t count, loff_t *offset)
{
	return simple_read_from_buffer(buf, count, offset, str, strlen(str));
}


#define TMPBUFSIZE 50

ssize_t oprofilefs_ulong_to_user(unsigned long val, char __user * buf, size_t count, loff_t * offset)
ssize_t oprofilefs_ulong_to_user(unsigned long val, char __user *buf, size_t count, loff_t *offset)
{
	char tmpbuf[TMPBUFSIZE];
	size_t maxlen = snprintf(tmpbuf, TMPBUFSIZE, "%lu\n", val);
	if (maxlen > TMPBUFSIZE)
		maxlen = TMPBUFSIZE;
	return simple_read_from_buffer(buf, count, offset, tmpbuf, maxlen);
}


int oprofilefs_ulong_from_user(unsigned long * val, char const __user * buf, size_t count)
/*
 * Note: If oprofilefs_ulong_from_user() returns 0, then *val remains
 * unchanged and might be uninitialized. This follows write syscall
 * implementation when count is zero: "If count is zero ... [and if]
 * no errors are detected, 0 will be returned without causing any
 * other effect." (man 2 write)
 */
int oprofilefs_ulong_from_user(unsigned long *val, char const __user *buf, size_t count)
{
	char tmpbuf[TMPBUFSIZE];
	unsigned long flags;

	if (!count)
		return 0;

	if (count > TMPBUFSIZE - 1)
		return -EINVAL;

	memset(tmpbuf, 0x0, TMPBUFSIZE);

	if (copy_from_user(tmpbuf, buf, count))
		return -EFAULT;

	spin_lock_irqsave(&oprofilefs_lock, flags);
	*val = simple_strtoul(tmpbuf, NULL, 0);
	spin_unlock_irqrestore(&oprofilefs_lock, flags);
	return 0;
}


static ssize_t ulong_read_file(struct file * file, char __user * buf, size_t count, loff_t * offset)
{
	unsigned long * val = file->private_data;
	raw_spin_lock_irqsave(&oprofilefs_lock, flags);
	*val = simple_strtoul(tmpbuf, NULL, 0);
	raw_spin_unlock_irqrestore(&oprofilefs_lock, flags);
	return count;
}


static ssize_t ulong_read_file(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	unsigned long *val = file->private_data;
	return oprofilefs_ulong_to_user(*val, buf, count, offset);
}


static ssize_t ulong_write_file(struct file * file, char const __user * buf, size_t count, loff_t * offset)
{
	unsigned long * value = file->private_data;
static ssize_t ulong_write_file(struct file *file, char const __user *buf, size_t count, loff_t *offset)
{
	unsigned long value;
	int retval;

	if (*offset)
		return -EINVAL;

	retval = oprofilefs_ulong_from_user(value, buf, count);

	if (retval)
		return retval;
	retval = oprofilefs_ulong_from_user(&value, buf, count);
	if (retval <= 0)
		return retval;

	retval = oprofile_set_ulong(file->private_data, value);
	if (retval)
		return retval;

	return count;
}


static int default_open(struct inode * inode, struct file * filp)
{
	if (inode->i_private)
		filp->private_data = inode->i_private;
	return 0;
}


static const struct file_operations ulong_fops = {
	.read		= ulong_read_file,
	.write		= ulong_write_file,
	.open		= default_open,
static const struct file_operations ulong_fops = {
	.read		= ulong_read_file,
	.write		= ulong_write_file,
	.open		= simple_open,
	.llseek		= default_llseek,
};


static const struct file_operations ulong_ro_fops = {
	.read		= ulong_read_file,
	.open		= default_open,
};


static struct dentry * __oprofilefs_create_file(struct super_block * sb,
	struct dentry * root, char const * name, const struct file_operations * fops,
	int perm)
{
	struct dentry * dentry;
	struct inode * inode;

	dentry = d_alloc_name(root, name);
	if (!dentry)
		return NULL;
	inode = oprofilefs_get_inode(sb, S_IFREG | perm);
	if (!inode) {
		dput(dentry);
		return NULL;
	}
	inode->i_fop = fops;
	d_add(dentry, inode);
	return dentry;
}


int oprofilefs_create_ulong(struct super_block * sb, struct dentry * root,
	char const * name, unsigned long * val)
{
	struct dentry * d = __oprofilefs_create_file(sb, root, name,
						     &ulong_fops, 0644);
	if (!d)
		return -EFAULT;

	d->d_inode->i_private = val;
	.open		= simple_open,
	.llseek		= default_llseek,
};


static int __oprofilefs_create_file(struct dentry *root, char const *name,
	const struct file_operations *fops, int perm, void *priv)
{
	struct dentry *dentry;
	struct inode *inode;

	if (!root)
		return -ENOMEM;

	inode_lock(d_inode(root));
	dentry = d_alloc_name(root, name);
	if (!dentry) {
		inode_unlock(d_inode(root));
		return -ENOMEM;
	}
	inode = oprofilefs_get_inode(root->d_sb, S_IFREG | perm);
	if (!inode) {
		dput(dentry);
		inode_unlock(d_inode(root));
		return -ENOMEM;
	}
	inode->i_fop = fops;
	inode->i_private = priv;
	d_add(dentry, inode);
	inode_unlock(d_inode(root));
	return 0;
}


int oprofilefs_create_ro_ulong(struct super_block * sb, struct dentry * root,
	char const * name, unsigned long * val)
{
	struct dentry * d = __oprofilefs_create_file(sb, root, name,
						     &ulong_ro_fops, 0444);
	if (!d)
		return -EFAULT;

	d->d_inode->i_private = val;
	return 0;
}


static ssize_t atomic_read_file(struct file * file, char __user * buf, size_t count, loff_t * offset)
{
	atomic_t * val = file->private_data;
	return oprofilefs_ulong_to_user(atomic_read(val), buf, count, offset);
}
 

static const struct file_operations atomic_ro_fops = {
	.read		= atomic_read_file,
	.open		= default_open,
};
 

int oprofilefs_create_ro_atomic(struct super_block * sb, struct dentry * root,
	char const * name, atomic_t * val)
{
	struct dentry * d = __oprofilefs_create_file(sb, root, name,
						     &atomic_ro_fops, 0444);
	if (!d)
		return -EFAULT;

	d->d_inode->i_private = val;
	return 0;
}

 
int oprofilefs_create_file(struct super_block * sb, struct dentry * root,
	char const * name, const struct file_operations * fops)
{
	if (!__oprofilefs_create_file(sb, root, name, fops, 0644))
		return -EFAULT;
	return 0;
}


int oprofilefs_create_file_perm(struct super_block * sb, struct dentry * root,
	char const * name, const struct file_operations * fops, int perm)
{
	if (!__oprofilefs_create_file(sb, root, name, fops, perm))
		return -EFAULT;
	return 0;
}


struct dentry * oprofilefs_mkdir(struct super_block * sb,
	struct dentry * root, char const * name)
{
	struct dentry * dentry;
	struct inode * inode;

	dentry = d_alloc_name(root, name);
	if (!dentry)
		return NULL;
	inode = oprofilefs_get_inode(sb, S_IFDIR | 0755);
	if (!inode) {
		dput(dentry);
int oprofilefs_create_ulong(struct dentry *root,
	char const *name, unsigned long *val)
{
	return __oprofilefs_create_file(root, name,
					&ulong_fops, 0644, val);
}


int oprofilefs_create_ro_ulong(struct dentry *root,
	char const *name, unsigned long *val)
{
	return __oprofilefs_create_file(root, name,
					&ulong_ro_fops, 0444, val);
}


static ssize_t atomic_read_file(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	atomic_t *val = file->private_data;
	return oprofilefs_ulong_to_user(atomic_read(val), buf, count, offset);
}


static const struct file_operations atomic_ro_fops = {
	.read		= atomic_read_file,
	.open		= simple_open,
	.llseek		= default_llseek,
};


int oprofilefs_create_ro_atomic(struct dentry *root,
	char const *name, atomic_t *val)
{
	return __oprofilefs_create_file(root, name,
					&atomic_ro_fops, 0444, val);
}


int oprofilefs_create_file(struct dentry *root,
	char const *name, const struct file_operations *fops)
{
	return __oprofilefs_create_file(root, name, fops, 0644, NULL);
}


int oprofilefs_create_file_perm(struct dentry *root,
	char const *name, const struct file_operations *fops, int perm)
{
	return __oprofilefs_create_file(root, name, fops, perm, NULL);
}


struct dentry *oprofilefs_mkdir(struct dentry *parent, char const *name)
{
	struct dentry *dentry;
	struct inode *inode;

	inode_lock(d_inode(parent));
	dentry = d_alloc_name(parent, name);
	if (!dentry) {
		inode_unlock(d_inode(parent));
		return NULL;
	}
	inode = oprofilefs_get_inode(parent->d_sb, S_IFDIR | 0755);
	if (!inode) {
		dput(dentry);
		inode_unlock(d_inode(parent));
		return NULL;
	}
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	d_add(dentry, inode);
	inode_unlock(d_inode(parent));
	return dentry;
}


static int oprofilefs_fill_super(struct super_block * sb, void * data, int silent)
{
	struct inode * root_inode;
	struct dentry * root_dentry;
static int oprofilefs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;

	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = OPROFILEFS_MAGIC;
	sb->s_op = &s_ops;
	sb->s_time_gran = 1;

	root_inode = oprofilefs_get_inode(sb, S_IFDIR | 0755);
	if (!root_inode)
		return -ENOMEM;
	root_inode->i_op = &simple_dir_inode_operations;
	root_inode->i_fop = &simple_dir_operations;
	root_dentry = d_alloc_root(root_inode);
	if (!root_dentry) {
		iput(root_inode);
		return -ENOMEM;
	}

	sb->s_root = root_dentry;

	oprofile_create_files(sb, root_dentry);
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		return -ENOMEM;

	oprofile_create_files(sb->s_root);

	// FIXME: verify kill_litter_super removes our dentries
	return 0;
}


static int oprofilefs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, oprofilefs_fill_super, mnt);
static struct dentry *oprofilefs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, oprofilefs_fill_super);
}


static struct file_system_type oprofilefs_type = {
	.owner		= THIS_MODULE,
	.name		= "oprofilefs",
	.get_sb		= oprofilefs_get_sb,
	.kill_sb	= kill_litter_super,
};
	.mount		= oprofilefs_mount,
	.kill_sb	= kill_litter_super,
};
MODULE_ALIAS_FS("oprofilefs");


int __init oprofilefs_register(void)
{
	return register_filesystem(&oprofilefs_type);
}


void __exit oprofilefs_unregister(void)
{
	unregister_filesystem(&oprofilefs_type);
}
