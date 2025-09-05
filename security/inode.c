/*
 *  inode.c - securityfs
 *
 *  Copyright (C) 2005 Greg Kroah-Hartman <gregkh@suse.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 *  Based on fs/debugfs/inode.c which had the following copyright notice:
 *    Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *    Copyright (C) 2004 IBM Inc.
 */

/* #define DEBUG */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/security.h>

#define SECURITYFS_MAGIC	0x73636673
#include <linux/lsm_hooks.h>
#include <linux/magic.h>

static struct vfsmount *mount;
static int mount_count;

/*
 * TODO:
 *   I think I can get rid of these default_file_ops, but not quite sure...
 */
static ssize_t default_read_file(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t default_write_file(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	return count;
}

static int default_open(struct inode *inode, struct file *file)
{
	if (inode->i_private)
		file->private_data = inode->i_private;

	return 0;
}

static const struct file_operations default_file_ops = {
	.read =		default_read_file,
	.write =	default_write_file,
	.open =		default_open,
};

static struct inode *get_inode(struct super_block *sb, int mode, dev_t dev)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = 0;
		inode->i_gid = 0;
		inode->i_blocks = 0;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_fop = &default_file_ops;
			break;
		case S_IFDIR:
			inode->i_op = &simple_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		}
	}
	return inode;
}

/* SMP-safe */
static int mknod(struct inode *dir, struct dentry *dentry,
			 int mode, dev_t dev)
{
	struct inode *inode;
	int error = -EPERM;

	if (dentry->d_inode)
		return -EEXIST;

	inode = get_inode(dir->i_sb, mode, dev);
	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry);
		error = 0;
	}
	return error;
}

static int mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int res;

	mode = (mode & (S_IRWXUGO | S_ISVTX)) | S_IFDIR;
	res = mknod(dir, dentry, mode, 0);
	if (!res)
		inc_nlink(dir);
	return res;
}

static int create(struct inode *dir, struct dentry *dentry, int mode)
{
	mode = (mode & S_IALLUGO) | S_IFREG;
	return mknod(dir, dentry, mode, 0);
}

static inline int positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

static void securityfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
}

static const struct super_operations securityfs_super_operations = {
	.statfs		= simple_statfs,
	.evict_inode	= securityfs_evict_inode,
};

static int fill_super(struct super_block *sb, void *data, int silent)
{
	static const struct tree_descr files[] = {{""}};
	int error;

	error = simple_fill_super(sb, SECURITYFS_MAGIC, files);
	if (error)
		return error;

	sb->s_op = &securityfs_super_operations;

	return 0;
}

static int get_sb(struct file_system_type *fs_type,
		  int flags, const char *dev_name,
		  void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, fill_super, mnt);
static struct dentry *get_sb(struct file_system_type *fs_type,
		  int flags, const char *dev_name,
		  void *data)
{
	return mount_single(fs_type, flags, data, fill_super);
}

static struct file_system_type fs_type = {
	.owner =	THIS_MODULE,
	.name =		"securityfs",
	.get_sb =	get_sb,
	.kill_sb =	kill_litter_super,
};

static int create_by_name(const char *name, mode_t mode,
			  struct dentry *parent,
			  struct dentry **dentry)
{
	int error = 0;

	*dentry = NULL;

	/* If the parent is not specified, we create it in the root.
	 * We need the root dentry to do this, which is in the super
	 * block. A pointer to that is in the struct vfsmount that we
	 * have around.
	 */
	if (!parent ) {
		if (mount && mount->mnt_sb) {
			parent = mount->mnt_sb->s_root;
		}
	}
	if (!parent) {
		pr_debug("securityfs: Ah! can not find a parent!\n");
		return -EFAULT;
	}

	mutex_lock(&parent->d_inode->i_mutex);
	*dentry = lookup_one_len(name, parent, strlen(name));
	if (!IS_ERR(dentry)) {
		if ((mode & S_IFMT) == S_IFDIR)
			error = mkdir(parent->d_inode, *dentry, mode);
		else
			error = create(parent->d_inode, *dentry, mode);
	} else
		error = PTR_ERR(dentry);
	mutex_unlock(&parent->d_inode->i_mutex);

	return error;
}

	.mount =	get_sb,
	.kill_sb =	kill_litter_super,
};

/**
 * securityfs_create_dentry - create a dentry in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this paramater is NULL, then the
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          file will be created in the root of the securityfs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 * @iops: a point to a struct of inode_operations that should be used for
 *        this file/dir
 *
 * This is the basic "create a file" function for securityfs.  It allows for a
 * wide range of flexibility in createing a file, or a directory (if you
 * want to create a directory, the securityfs_create_dir() function is
 * recommended to be used instead.)
 *
 * This function will return a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here.)  If an error occurs, NULL will be returned.
 *
 * If securityfs is not enabled in the kernel, the value -ENODEV will be
 * returned.  It is not wise to check for this value, but rather, check for
 * NULL or !NULL instead as to eliminate the need for #ifdef in the calling
 * code.
 */
struct dentry *securityfs_create_file(const char *name, mode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops)
{
	struct dentry *dentry = NULL;
	int error;

	pr_debug("securityfs: creating file '%s'\n",name);

	error = simple_pin_fs(&fs_type, &mount, &mount_count);
	if (error) {
		dentry = ERR_PTR(error);
		goto exit;
	}

	error = create_by_name(name, mode, parent, &dentry);
	if (error) {
		dentry = ERR_PTR(error);
		simple_release_fs(&mount, &mount_count);
		goto exit;
	}

	if (dentry->d_inode) {
		if (fops)
			dentry->d_inode->i_fop = fops;
		if (data)
			dentry->d_inode->i_private = data;
	}
exit:
 * wide range of flexibility in creating a file, or a directory (if you
 * want to create a directory, the securityfs_create_dir() function is
 * recommended to be used instead).
 * This is the basic "create a file/dir/symlink" function for
 * securityfs.  It allows for a wide range of flexibility in creating
 * a file, or a directory (if you want to create a directory, the
 * securityfs_create_dir() function is recommended to be used
 * instead).
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the
 * file is to be removed (no automatic cleanup happens if your module
 * is unloaded, you are responsible here).  If an error occurs, the
 * function will return the error value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
static struct dentry *securityfs_create_dentry(const char *name, umode_t mode,
					struct dentry *parent, void *data,
					const struct file_operations *fops,
					const struct inode_operations *iops)
{
	struct dentry *dentry;
	struct inode *dir, *inode;
	int error;

	if (!(mode & S_IFMT))
		mode = (mode & S_IALLUGO) | S_IFREG;

	pr_debug("securityfs: creating file '%s'\n",name);

	error = simple_pin_fs(&fs_type, &mount, &mount_count);
	if (error)
		return ERR_PTR(error);

	if (!parent)
		parent = mount->mnt_root;

	dir = d_inode(parent);

	inode_lock(dir);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_really_is_positive(dentry)) {
		error = -EEXIST;
		goto out1;
	}

	inode = new_inode(dir->i_sb);
	if (!inode) {
		error = -ENOMEM;
		goto out1;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_private = data;
	if (S_ISDIR(mode)) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		inc_nlink(dir);
	} else if (S_ISLNK(mode)) {
		inode->i_op = iops ? iops : &simple_symlink_inode_operations;
		inode->i_link = data;
	} else {
		inode->i_fop = fops;
	}
	d_instantiate(dentry, inode);
	dget(dentry);
	inode_unlock(dir);
	return dentry;

out1:
	dput(dentry);
	dentry = ERR_PTR(error);
out:
	inode_unlock(dir);
	simple_release_fs(&mount, &mount_count);
	return dentry;
}

/**
 * securityfs_create_file - create a file in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          file will be created in the root of the securityfs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 *
 * This function creates a file in securityfs with the given @name.
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, the function will return
 * the error value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
struct dentry *securityfs_create_file(const char *name, umode_t mode,
				      struct dentry *parent, void *data,
				      const struct file_operations *fops)
{
	return securityfs_create_dentry(name, mode, parent, data, fops, NULL);
}
EXPORT_SYMBOL_GPL(securityfs_create_file);

/**
 * securityfs_create_dir - create a directory in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the directory to
 *        create.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this paramater is NULL, then the
 *          directory will be created in the root of the securityfs filesystem.
 *
 * This function creates a directory in securityfs with the given name.
 *
 * This function will return a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here.)  If an error occurs, NULL will be returned.
 *
 * If securityfs is not enabled in the kernel, the value -ENODEV will be
 * returned.  It is not wise to check for this value, but rather, check for
 * NULL or !NULL instead as to eliminate the need for #ifdef in the calling
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          directory will be created in the root of the securityfs filesystem.
 *
 * This function creates a directory in securityfs with the given @name.
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, the function will return
 * the error value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
struct dentry *securityfs_create_dir(const char *name, struct dentry *parent)
{
	return securityfs_create_file(name, S_IFDIR | 0755, parent, NULL, NULL);
}
EXPORT_SYMBOL_GPL(securityfs_create_dir);

/**
 * securityfs_create_symlink - create a symlink in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the symlink to
 *        create.
 * @parent: a pointer to the parent dentry for the symlink.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          directory will be created in the root of the securityfs filesystem.
 * @target: a pointer to a string containing the name of the symlink's target.
 *          If this parameter is %NULL, then the @iops parameter needs to be
 *          setup to handle .readlink and .get_link inode_operations.
 * @iops: a pointer to the struct inode_operations to use for the symlink. If
 *        this parameter is %NULL, then the default simple_symlink_inode
 *        operations will be used.
 *
 * This function creates a symlink in securityfs with the given @name.
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, the function will return
 * the error value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
struct dentry *securityfs_create_symlink(const char *name,
					 struct dentry *parent,
					 const char *target,
					 const struct inode_operations *iops)
{
	struct dentry *dent;
	char *link = NULL;

	if (target) {
		link = kstrdup(target, GFP_KERNEL);
		if (!link)
			return ERR_PTR(-ENOMEM);
	}
	dent = securityfs_create_dentry(name, S_IFLNK | 0444, parent,
					link, NULL, iops);
	if (IS_ERR(dent))
		kfree(link);

	return dent;
}
EXPORT_SYMBOL_GPL(securityfs_create_symlink);

/**
 * securityfs_remove - removes a file or directory from the securityfs filesystem
 *
 * @dentry: a pointer to a the dentry of the file or directory to be
 *          removed.
 * @dentry: a pointer to a the dentry of the file or directory to be removed.
 *
 * This function removes a file or directory in securityfs that was previously
 * created with a call to another securityfs function (like
 * securityfs_create_file() or variants thereof.)
 *
 * This function is required to be called in order for the file to be
 * removed, no automatic cleanup of files will happen when a module is
 * removed, you are responsible here.
 * removed. No automatic cleanup of files will happen when a module is
 * removed; you are responsible here.
 */
void securityfs_remove(struct dentry *dentry)
{
	struct inode *dir;

	if (!dentry)
		return;

	parent = dentry->d_parent;
	if (!parent || !parent->d_inode)
		return;

	mutex_lock(&parent->d_inode->i_mutex);
	if (positive(dentry)) {
		if (dentry->d_inode) {
			if (S_ISDIR(dentry->d_inode->i_mode))
				simple_rmdir(parent->d_inode, dentry);
			else
				simple_unlink(parent->d_inode, dentry);
			dput(dentry);
		}
	}
	mutex_unlock(&parent->d_inode->i_mutex);
	if (!dentry || IS_ERR(dentry))
		return;

	dir = d_inode(dentry->d_parent);
	inode_lock(dir);
	if (simple_positive(dentry)) {
		if (d_is_dir(dentry))
			simple_rmdir(dir, dentry);
		else
			simple_unlink(dir, dentry);
		dput(dentry);
	}
	inode_unlock(dir);
	simple_release_fs(&mount, &mount_count);
}
EXPORT_SYMBOL_GPL(securityfs_remove);

static struct kobject *security_kobj;
#ifdef CONFIG_SECURITY
static struct dentry *lsm_dentry;
static ssize_t lsm_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, lsm_names,
		strlen(lsm_names));
}

static const struct file_operations lsm_ops = {
	.read = lsm_read,
	.llseek = generic_file_llseek,
};
#endif

static int __init securityfs_init(void)
{
	int retval;

	security_kobj = kobject_create_and_add("security", kernel_kobj);
	if (!security_kobj)
		return -EINVAL;

	retval = register_filesystem(&fs_type);
	if (retval)
		kobject_put(security_kobj);
	retval = sysfs_create_mount_point(kernel_kobj, "security");
	if (retval)
		return retval;

	retval = register_filesystem(&fs_type);
	if (retval) {
		sysfs_remove_mount_point(kernel_kobj, "security");
		return retval;
	}
#ifdef CONFIG_SECURITY
	lsm_dentry = securityfs_create_file("lsm", 0444, NULL, NULL,
						&lsm_ops);
#endif
	return 0;
}

core_initcall(securityfs_init);
MODULE_LICENSE("GPL");

