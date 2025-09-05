/* -*- linux-c -*- --------------------------------------------------------- *
 *
 * linux/fs/devpts/inode.c
 *
 *  Copyright 1998-2004 H. Peter Anvin -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/mutex.h>
#include <linux/magic.h>
#include <linux/idr.h>
#include <linux/devpts_fs.h>
#include <linux/parser.h>
#include <linux/fsnotify.h>
#include <linux/seq_file.h>

#define DEVPTS_SUPER_MAGIC 0x1cd1

#define DEVPTS_DEFAULT_MODE 0600

extern int pty_limit;			/* Config limit on Unix98 ptys */
static DEFINE_IDA(allocated_ptys);
static DEFINE_MUTEX(allocated_ptys_lock);

static struct vfsmount *devpts_mnt;
static struct dentry *devpts_root;

static struct {
	int setuid;
	int setgid;
	uid_t   uid;
	gid_t   gid;
	umode_t mode;
} config = {.mode = DEVPTS_DEFAULT_MODE};

enum {
	Opt_uid, Opt_gid, Opt_mode,
	Opt_err
};

static match_table_t tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

static int devpts_remount(struct super_block *sb, int *flags, char *data)
{
	char *p;

	config.setuid  = 0;
	config.setgid  = 0;
	config.uid     = 0;
	config.gid     = 0;
	config.mode    = DEVPTS_DEFAULT_MODE;
#define DEVPTS_DEFAULT_MODE 0600
/*
 * ptmx is a new node in /dev/pts and will be unused in legacy (single-
 * instance) mode. To prevent surprises in user space, set permissions of
 * ptmx to 0. Use 'chmod' or remount with '-o ptmxmode' to set meaningful
 * permissions.
 */
#define DEVPTS_DEFAULT_PTMX_MODE 0000
#define PTMX_MINOR	2

/*
 * sysctl support for setting limits on the number of Unix98 ptys allocated.
 * Otherwise one can eat up all kernel memory by opening /dev/ptmx repeatedly.
 */
static int pty_limit = NR_UNIX98_PTY_DEFAULT;
static int pty_reserve = NR_UNIX98_PTY_RESERVE;
static int pty_limit_min;
static int pty_limit_max = INT_MAX;
static int pty_count;

static struct ctl_table pty_table[] = {
	{
		.procname	= "max",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.data		= &pty_limit,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &pty_limit_min,
		.extra2		= &pty_limit_max,
	}, {
		.procname	= "reserve",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.data		= &pty_reserve,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &pty_limit_min,
		.extra2		= &pty_limit_max,
	}, {
		.procname	= "nr",
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.data		= &pty_count,
		.proc_handler	= proc_dointvec,
	},
	{}
};

static struct ctl_table pty_kern_table[] = {
	{
		.procname	= "pty",
		.mode		= 0555,
		.child		= pty_table,
	},
	{}
};

static struct ctl_table pty_root_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= pty_kern_table,
	},
	{}
};

static DEFINE_MUTEX(allocated_ptys_lock);

struct pts_mount_opts {
	int setuid;
	int setgid;
	kuid_t   uid;
	kgid_t   gid;
	umode_t mode;
	umode_t ptmxmode;
	int reserve;
	int max;
};

enum {
	Opt_uid, Opt_gid, Opt_mode, Opt_ptmxmode, Opt_newinstance,  Opt_max,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_ptmxmode, "ptmxmode=%o"},
	{Opt_newinstance, "newinstance"},
	{Opt_max, "max=%d"},
	{Opt_err, NULL}
};

struct pts_fs_info {
	struct ida allocated_ptys;
	struct pts_mount_opts mount_opts;
	struct super_block *sb;
	struct dentry *ptmx_dentry;
};

static inline struct pts_fs_info *DEVPTS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static int devpts_ptmx_path(struct path *path)
{
	struct super_block *sb;
	int err;

	/* Has the devpts filesystem already been found? */
	if (path->mnt->mnt_sb->s_magic == DEVPTS_SUPER_MAGIC)
		return 0;

	/* Is a devpts filesystem at "pts" in the same directory? */
	err = path_pts(path);
	if (err)
		return err;

	/* Is the path the root of a devpts filesystem? */
	sb = path->mnt->mnt_sb;
	if ((sb->s_magic != DEVPTS_SUPER_MAGIC) ||
	    (path->mnt->mnt_root != sb->s_root))
		return -ENODEV;

	return 0;
}

struct vfsmount *devpts_mntget(struct file *filp, struct pts_fs_info *fsi)
{
	struct path path;
	int err;

	path = filp->f_path;
	path_get(&path);

	err = devpts_ptmx_path(&path);
	dput(path.dentry);
	if (err) {
		mntput(path.mnt);
		path.mnt = ERR_PTR(err);
	}
	if (DEVPTS_SB(path.mnt->mnt_sb) != fsi) {
		mntput(path.mnt);
		path.mnt = ERR_PTR(-ENODEV);
	}
	return path.mnt;
}

struct pts_fs_info *devpts_acquire(struct file *filp)
{
	struct pts_fs_info *result;
	struct path path;
	struct super_block *sb;
	int err;

	path = filp->f_path;
	path_get(&path);

	err = devpts_ptmx_path(&path);
	if (err) {
		result = ERR_PTR(err);
		goto out;
	}

	/*
	 * pty code needs to hold extra references in case of last /dev/tty close
	 */
	sb = path.mnt->mnt_sb;
	atomic_inc(&sb->s_active);
	result = DEVPTS_SB(sb);

out:
	path_put(&path);
	return result;
}

void devpts_release(struct pts_fs_info *fsi)
{
	deactivate_super(fsi->sb);
}

#define PARSE_MOUNT	0
#define PARSE_REMOUNT	1

/*
 * parse_mount_options():
 *	Set @opts to mount options specified in @data. If an option is not
 *	specified in @data, set it to its default value.
 *
 * Note: @data may be NULL (in which case all options are set to default).
 */
static int parse_mount_options(char *data, int op, struct pts_mount_opts *opts)
{
	char *p;
	kuid_t uid;
	kgid_t gid;

	opts->setuid  = 0;
	opts->setgid  = 0;
	opts->uid     = GLOBAL_ROOT_UID;
	opts->gid     = GLOBAL_ROOT_GID;
	opts->mode    = DEVPTS_DEFAULT_MODE;
	opts->ptmxmode = DEVPTS_DEFAULT_PTMX_MODE;
	opts->max     = NR_UNIX98_PTY_MAX;

	/* Only allow instances mounted from the initial mount
	 * namespace to tap the reserve pool of ptys.
	 */
	if (op == PARSE_MOUNT)
		opts->reserve =
			(current->nsproxy->mnt_ns == init_task.nsproxy->mnt_ns);

	while ((p = strsep(&data, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		int option;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			config.uid = option;
			config.setuid = 1;
			uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(uid))
				return -EINVAL;
			opts->uid = uid;
			opts->setuid = 1;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			config.gid = option;
			config.setgid = 1;
			gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(gid))
				return -EINVAL;
			opts->gid = gid;
			opts->setgid = 1;
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			config.mode = option & S_IALLUGO;
			break;
		default:
			printk(KERN_ERR "devpts: called with bogus options\n");
			opts->mode = option & S_IALLUGO;
			break;
		case Opt_ptmxmode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->ptmxmode = option & S_IALLUGO;
			break;
		case Opt_newinstance:
			break;
		case Opt_max:
			if (match_int(&args[0], &option) ||
			    option < 0 || option > NR_UNIX98_PTY_MAX)
				return -EINVAL;
			opts->max = option;
			break;
		default:
			pr_err("called with bogus options\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int devpts_show_options(struct seq_file *seq, struct vfsmount *vfs)
{
	if (config.setuid)
		seq_printf(seq, ",uid=%u", config.uid);
	if (config.setgid)
		seq_printf(seq, ",gid=%u", config.gid);
	seq_printf(seq, ",mode=%03o", config.mode);
#ifdef CONFIG_DEVPTS_MULTIPLE_INSTANCES
static int mknod_ptmx(struct super_block *sb)
{
	int mode;
	int rc = -ENOMEM;
	struct dentry *dentry;
	struct inode *inode;
	struct dentry *root = sb->s_root;
	struct pts_fs_info *fsi = DEVPTS_SB(sb);
	struct pts_mount_opts *opts = &fsi->mount_opts;
	kuid_t ptmx_uid = current_fsuid();
	kgid_t ptmx_gid = current_fsgid();

	inode_lock(d_inode(root));

	/* If we have already created ptmx node, return */
	if (fsi->ptmx_dentry) {
		rc = 0;
		goto out;
	}

	dentry = d_alloc_name(root, "ptmx");
	if (!dentry) {
		pr_err("Unable to alloc dentry for ptmx node\n");
		goto out;
	}

	/*
	 * Create a new 'ptmx' node in this mount of devpts.
	 */
	inode = new_inode(sb);
	if (!inode) {
		pr_err("Unable to alloc inode for ptmx node\n");
		dput(dentry);
		goto out;
	}

	inode->i_ino = 2;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

	mode = S_IFCHR|opts->ptmxmode;
	init_special_inode(inode, mode, MKDEV(TTYAUX_MAJOR, 2));
	inode->i_uid = ptmx_uid;
	inode->i_gid = ptmx_gid;

	d_add(dentry, inode);

	fsi->ptmx_dentry = dentry;
	rc = 0;
out:
	inode_unlock(d_inode(root));
	return rc;
}

static void update_ptmx_mode(struct pts_fs_info *fsi)
{
	struct inode *inode;
	if (fsi->ptmx_dentry) {
		inode = d_inode(fsi->ptmx_dentry);
		inode->i_mode = S_IFCHR|fsi->mount_opts.ptmxmode;
	}
}

static int devpts_remount(struct super_block *sb, int *flags, char *data)
{
	int err;
	struct pts_fs_info *fsi = DEVPTS_SB(sb);
	struct pts_mount_opts *opts = &fsi->mount_opts;

	err = parse_mount_options(data, PARSE_REMOUNT, opts);

	/*
	 * parse_mount_options() restores options to default values
	 * before parsing and may have changed ptmxmode. So, update the
	 * mode in the inode too. Bogus options don't fail the remount,
	 * so do this even on error return.
	 */
	update_ptmx_mode(fsi);

	return err;
}

static int devpts_show_options(struct seq_file *seq, struct dentry *root)
{
	struct pts_fs_info *fsi = DEVPTS_SB(root->d_sb);
	struct pts_mount_opts *opts = &fsi->mount_opts;

	if (opts->setuid)
		seq_printf(seq, ",uid=%u",
			   from_kuid_munged(&init_user_ns, opts->uid));
	if (opts->setgid)
		seq_printf(seq, ",gid=%u",
			   from_kgid_munged(&init_user_ns, opts->gid));
	seq_printf(seq, ",mode=%03o", opts->mode);
	seq_printf(seq, ",ptmxmode=%03o", opts->ptmxmode);
	if (opts->max < NR_UNIX98_PTY_MAX)
		seq_printf(seq, ",max=%d", opts->max);

	return 0;
}

static const struct super_operations devpts_sops = {
	.statfs		= simple_statfs,
	.remount_fs	= devpts_remount,
	.show_options	= devpts_show_options,
};

static int
devpts_fill_super(struct super_block *s, void *data, int silent)
{
	struct inode * inode;
static void *new_pts_fs_info(void)
static void *new_pts_fs_info(struct super_block *sb)
{
	struct pts_fs_info *fsi;

	fsi = kzalloc(sizeof(struct pts_fs_info), GFP_KERNEL);
	if (!fsi)
		return NULL;

	ida_init(&fsi->allocated_ptys);
	fsi->mount_opts.mode = DEVPTS_DEFAULT_MODE;
	fsi->mount_opts.ptmxmode = DEVPTS_DEFAULT_PTMX_MODE;
	fsi->sb = sb;

	return fsi;
}

static int
devpts_fill_super(struct super_block *s, void *data, int silent)
{
	struct inode *inode;
	int error;

	s->s_iflags &= ~SB_I_NODEV;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = DEVPTS_SUPER_MAGIC;
	s->s_op = &devpts_sops;
	s->s_time_gran = 1;

	error = -ENOMEM;
	s->s_fs_info = new_pts_fs_info(s);
	if (!s->s_fs_info)
		goto fail;

	error = parse_mount_options(data, PARSE_MOUNT, &DEVPTS_SB(s)->mount_opts);
	if (error)
		goto fail;

	error = -ENOMEM;
	inode = new_inode(s);
	if (!inode)
		goto fail;
	inode->i_ino = 1;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_blocks = 0;
	inode->i_uid = inode->i_gid = 0;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	inode->i_nlink = 2;

	devpts_root = s->s_root = d_alloc_root(inode);
	if (s->s_root)
		return 0;
	
	printk("devpts: get root dentry failed\n");
	iput(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	set_nlink(inode, 2);

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		pr_err("get root dentry failed\n");
		goto fail;
	}

	error = mknod_ptmx(s);
	if (error)
		goto fail_dput;

fail:
	return -ENOMEM;
}

static int devpts_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, devpts_fill_super, mnt);
}

static struct file_system_type devpts_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "devpts",
	.get_sb		= devpts_get_sb,
	.kill_sb	= kill_anon_super,
#ifdef CONFIG_DEVPTS_MULTIPLE_INSTANCES
static int compare_init_pts_sb(struct super_block *s, void *p)
{
	if (devpts_mnt)
		return devpts_mnt->mnt_sb == s;
	return 0;
fail_dput:
	dput(s->s_root);
	s->s_root = NULL;
fail:
	return error;
}

/*
 * devpts_mount()
 *
 *     Mount a new (private) instance of devpts.  PTYs created in this
 *     instance are independent of the PTYs in other devpts instances.
 */
static struct dentry *devpts_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, devpts_fill_super);
}

static void devpts_kill_sb(struct super_block *sb)
{
	struct pts_fs_info *fsi = DEVPTS_SB(sb);

	if (fsi)
		ida_destroy(&fsi->allocated_ptys);
	kfree(fsi);
	kill_litter_super(sb);
}

static struct file_system_type devpts_fs_type = {
	.name		= "devpts",
	.mount		= devpts_mount,
	.kill_sb	= devpts_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

/*
 * The normal naming convention is simply /dev/pts/<number>; this conforms
 * to the System V naming convention
 */

static struct dentry *get_node(int num)
{
	char s[12];
	struct dentry *root = devpts_root;
	mutex_lock(&root->d_inode->i_mutex);
	return lookup_one_len(s, root, sprintf(s, "%d", num));
}

int devpts_new_index(void)
{
	int index;
	int ida_ret;

retry:
	if (!ida_pre_get(&allocated_ptys, GFP_KERNEL)) {
		return -ENOMEM;
	}

	mutex_lock(&allocated_ptys_lock);
	ida_ret = ida_get_new(&allocated_ptys, &index);
int devpts_new_index(struct inode *ptmx_inode)
int devpts_new_index(struct pts_fs_info *fsi)
{
	int index;
	int ida_ret;

retry:
	if (!ida_pre_get(&fsi->allocated_ptys, GFP_KERNEL))
		return -ENOMEM;

	mutex_lock(&allocated_ptys_lock);
	if (pty_count >= (pty_limit -
			  (fsi->mount_opts.reserve ? 0 : pty_reserve))) {
		mutex_unlock(&allocated_ptys_lock);
		return -ENOSPC;
	}

	ida_ret = ida_get_new(&fsi->allocated_ptys, &index);
	if (ida_ret < 0) {
		mutex_unlock(&allocated_ptys_lock);
		if (ida_ret == -EAGAIN)
			goto retry;
		return -EIO;
	}

	if (index >= pty_limit) {
		ida_remove(&allocated_ptys, index);
		mutex_unlock(&allocated_ptys_lock);
		return -EIO;
	}
	if (index >= fsi->mount_opts.max) {
		ida_remove(&fsi->allocated_ptys, index);
		mutex_unlock(&allocated_ptys_lock);
		return -ENOSPC;
	}
	pty_count++;
	mutex_unlock(&allocated_ptys_lock);
	return index;
}

void devpts_kill_index(int idx)
{
	mutex_lock(&allocated_ptys_lock);
	ida_remove(&allocated_ptys, idx);
	mutex_unlock(&allocated_ptys_lock);
}

int devpts_pty_new(struct tty_struct *tty)
{
	int number = tty->index; /* tty layer puts index from devpts_new_index() in here */
	struct tty_driver *driver = tty->driver;
	dev_t device = MKDEV(driver->major, driver->minor_start+number);
	struct dentry *dentry;
	struct inode *inode = new_inode(devpts_mnt->mnt_sb);

	/* We're supposed to be given the slave end of a pty */
	BUG_ON(driver->type != TTY_DRIVER_TYPE_PTY);
	BUG_ON(driver->subtype != PTY_TYPE_SLAVE);

	if (!inode)
		return -ENOMEM;

	inode->i_ino = number+2;
	inode->i_uid = config.setuid ? config.uid : current->fsuid;
	inode->i_gid = config.setgid ? config.gid : current->fsgid;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	init_special_inode(inode, S_IFCHR|config.mode, device);
	inode->i_private = tty;

	dentry = get_node(number);
	if (!IS_ERR(dentry) && !dentry->d_inode) {
		d_instantiate(dentry, inode);
		fsnotify_create(devpts_root->d_inode, dentry);
	}

	mutex_unlock(&devpts_root->d_inode->i_mutex);

	return 0;
}

struct tty_struct *devpts_get_tty(int number)
{
	struct dentry *dentry = get_node(number);
	struct tty_struct *tty;

	tty = NULL;
	if (!IS_ERR(dentry)) {
		if (dentry->d_inode)
			tty = dentry->d_inode->i_private;
		dput(dentry);
	}

	mutex_unlock(&devpts_root->d_inode->i_mutex);

	return tty;
}

void devpts_pty_kill(int number)
{
	struct dentry *dentry = get_node(number);

	if (!IS_ERR(dentry)) {
		struct inode *inode = dentry->d_inode;
		if (inode) {
			inode->i_nlink--;
			d_delete(dentry);
			dput(dentry);
		}
		dput(dentry);
	}
	mutex_unlock(&devpts_root->d_inode->i_mutex);
void devpts_kill_index(struct inode *ptmx_inode, int idx)
void devpts_kill_index(struct pts_fs_info *fsi, int idx)
{
	mutex_lock(&allocated_ptys_lock);
	ida_remove(&fsi->allocated_ptys, idx);
	pty_count--;
	mutex_unlock(&allocated_ptys_lock);
}

/**
 * devpts_pty_new -- create a new inode in /dev/pts/
 * @ptmx_inode: inode of the master
 * @device: major+minor of the node to be created
 * @index: used as a name of the node
 * @priv: what's given back by devpts_get_priv
 *
 * The created inode is returned. Remove it from /dev/pts/ by devpts_pty_kill.
 */
struct dentry *devpts_pty_new(struct pts_fs_info *fsi, int index, void *priv)
{
	struct dentry *dentry;
	struct super_block *sb = fsi->sb;
	struct inode *inode;
	struct dentry *root;
	struct pts_mount_opts *opts;
	char s[12];

	root = sb->s_root;
	opts = &fsi->mount_opts;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = index + 3;
	inode->i_uid = opts->setuid ? opts->uid : current_fsuid();
	inode->i_gid = opts->setgid ? opts->gid : current_fsgid();
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	init_special_inode(inode, S_IFCHR|opts->mode, MKDEV(UNIX98_PTY_SLAVE_MAJOR, index));

	sprintf(s, "%d", index);

	dentry = d_alloc_name(root, s);
	if (dentry) {
		dentry->d_fsdata = priv;
		d_add(dentry, inode);
		fsnotify_create(d_inode(root), dentry);
	} else {
		iput(inode);
		dentry = ERR_PTR(-ENOMEM);
	}

	return dentry;
}

/**
 * devpts_get_priv -- get private data for a slave
 * @pts_inode: inode of the slave
 *
 * Returns whatever was passed as priv in devpts_pty_new for a given inode.
 */
void *devpts_get_priv(struct dentry *dentry)
{
	if (dentry->d_sb->s_magic != DEVPTS_SUPER_MAGIC)
		return NULL;
	return dentry->d_fsdata;
}

/**
 * devpts_pty_kill -- remove inode form /dev/pts/
 * @inode: inode of the slave to be removed
 *
 * This is an inverse operation of devpts_pty_new.
 */
void devpts_pty_kill(struct dentry *dentry)
{
	WARN_ON_ONCE(dentry->d_sb->s_magic != DEVPTS_SUPER_MAGIC);

	dentry->d_fsdata = NULL;
	drop_nlink(dentry->d_inode);
	d_delete(dentry);
	dput(dentry);	/* d_alloc_name() in devpts_pty_new() */
}

static int __init init_devpts_fs(void)
{
	int err = register_filesystem(&devpts_fs_type);
	if (!err) {
		devpts_mnt = kern_mount(&devpts_fs_type);
		if (IS_ERR(devpts_mnt))
			err = PTR_ERR(devpts_mnt);
	}
	return err;
}

static void __exit exit_devpts_fs(void)
{
	unregister_filesystem(&devpts_fs_type);
	mntput(devpts_mnt);
}

module_init(init_devpts_fs)
module_exit(exit_devpts_fs)
MODULE_LICENSE("GPL");
	struct ctl_table_header *table;

	if (!err) {
		register_sysctl_table(pty_root_table);
	}
	return err;
}
module_init(init_devpts_fs)
