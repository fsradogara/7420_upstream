/* -*- linux-c -*- ------------------------------------------------------- *
 *   
 * linux/fs/autofs/autofs_i.h
 *
 *   Copyright 1997-1998 Transmeta Corporation - All Rights Reserved
/*
 *  Copyright 1997-1998 Transmeta Corporation - All Rights Reserved
 *  Copyright 2005-2006 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/* Internal header file for autofs */

#include <linux/auto_fs.h>

/* This is the range of ioctl() numbers we claim as ours */
#define AUTOFS_IOC_FIRST     AUTOFS_IOC_READY
#define AUTOFS_IOC_COUNT     32
 */

/* Internal header file for autofs */

#include <linux/auto_fs4.h>
#include <linux/mutex.h>
#include <linux/auto_fs.h>
#include <linux/auto_dev-ioctl.h>

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/sched.h>

#include <asm/current.h>
#include <asm/uaccess.h>

#ifdef DEBUG
#define DPRINTK(D) (printk D)
#else
#define DPRINTK(D) ((void)0)
#endif

/*
 * If the daemon returns a negative response (AUTOFS_IOC_FAIL) then the
 * kernel will keep the negative response cached for up to the time given
 * here, although the time can be shorter if the kernel throws the dcache
 * entry away.  This probably should be settable from user space.
 */
#define AUTOFS_NEGATIVE_TIMEOUT (60*HZ)	/* 1 minute */

/* Structures associated with the root directory hash table */

#define AUTOFS_HASH_SIZE 67

struct autofs_dir_ent {
	int hash;
	char *name;
	int len;
	ino_t ino;
	struct dentry *dentry;
	/* Linked list of entries */
	struct autofs_dir_ent *next;
	struct autofs_dir_ent **back;
	/* The following entries are for the expiry system */
	unsigned long last_usage;
	struct list_head exp;
};

struct autofs_dirhash {
	struct autofs_dir_ent *h[AUTOFS_HASH_SIZE];
	struct list_head expiry_head;
};

#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/completion.h>
#include <linux/file.h>
#include <linux/magic.h>

/* This is the range of ioctl() numbers we claim as ours */
#define AUTOFS_IOC_FIRST     AUTOFS_IOC_READY
#define AUTOFS_IOC_COUNT     32

#ifdef DEBUG
#define DPRINTK(fmt,args...) do { printk(KERN_DEBUG "pid %d: %s: " fmt "\n" , current->pid , __func__ , ##args); } while(0)
#else
#define DPRINTK(fmt,args...) do {} while(0)
#endif
#define DPRINTK(fmt, ...)				\
	pr_debug("pid %d: %s: " fmt "\n",		\
		current->pid, __func__, ##__VA_ARGS__)
#define AUTOFS_DEV_IOCTL_IOC_FIRST	(AUTOFS_DEV_IOCTL_VERSION)
#define AUTOFS_DEV_IOCTL_IOC_COUNT \
	(AUTOFS_DEV_IOCTL_ISMOUNTPOINT_CMD - AUTOFS_DEV_IOCTL_VERSION_CMD)

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ":pid:%d:%s: " fmt, current->pid, __func__

/*
 * Unified info structure.  This is pointed to by both the dentry and
 * inode structures.  Each file in the filesystem has an instance of this
 * structure.  It holds a reference to the dentry, so dentries are never
 * flushed while the file exists.  All name lookups are dealt with at the
 * dentry level, although the filesystem can interfere in the validation
 * process.  Readdir is implemented by traversing the dentry lists.
 */
struct autofs_info {
	struct dentry	*dentry;
	struct inode	*inode;

	int		flags;

	struct completion expire_complete;

	struct list_head active;
	int active_count;

	struct list_head expiring;

	struct autofs_sb_info *sbi;
	unsigned long last_used;
	atomic_t count;

	mode_t	mode;
	size_t	size;

	void (*free)(struct autofs_info *);
	union {
		const char *symlink;
	} u;
};

#define AUTOFS_INF_EXPIRING	(1<<0) /* dentry is in the process of expiring */
#define AUTOFS_INF_MOUNTPOINT	(1<<1) /* mountpoint status for direct expire */
	kuid_t uid;
	kgid_t gid;
};

#define AUTOFS_INF_EXPIRING	(1<<0) /* dentry in the process of expiring */
#define AUTOFS_INF_WANT_EXPIRE	(1<<1) /* the dentry is being considered
					* for expiry, so RCU_walk is
					* not permitted.  If it progresses to
					* actual expiry attempt, the flag is
					* not cleared when EXPIRING is set -
					* in that case it gets cleared only
					* when it comes to clearing EXPIRING.
					*/
#define AUTOFS_INF_PENDING	(1<<2) /* dentry pending mount */

struct autofs_wait_queue {
	wait_queue_head_t queue;
	struct autofs_wait_queue *next;
	autofs_wqt_t wait_queue_token;
	/* We use the following to see what we are waiting for */
	int hash;
	int len;
	char *name;
	/* This is for status reporting upon return */
	int status;
	int wait_ctr;
};

struct autofs_symlink {
	char *data;
	int len;
	time_t mtime;
};

#define AUTOFS_MAX_SYMLINKS 256

#define AUTOFS_ROOT_INO      1
#define AUTOFS_FIRST_SYMLINK 2
#define AUTOFS_FIRST_DIR_INO (AUTOFS_FIRST_SYMLINK+AUTOFS_MAX_SYMLINKS)

#define AUTOFS_SYMLINK_BITMAP_LEN \
	((AUTOFS_MAX_SYMLINKS+((sizeof(long)*1)-1))/(sizeof(long)*8))

#define AUTOFS_SBI_MAGIC 0x6d4a556d

struct autofs_sb_info {
	u32 magic;
	struct file *pipe;
	struct pid *oz_pgrp;
	int catatonic;
	struct super_block *sb;
	unsigned long exp_timeout;
	ino_t next_dir_ino;
	struct autofs_wait_queue *queues; /* Wait queue pointer */
	struct autofs_dirhash dirhash; /* Root directory hash */
	struct autofs_symlink symlink[AUTOFS_MAX_SYMLINKS];
	unsigned long symlink_bitmap[AUTOFS_SYMLINK_BITMAP_LEN];
	struct qstr name;
	u32 dev;
	u64 ino;
	uid_t uid;
	gid_t gid;
	kuid_t uid;
	kgid_t gid;
	pid_t pid;
	pid_t tgid;
	/* This is for status reporting upon return */
	int status;
	unsigned int wait_ctr;
};

#define AUTOFS_SBI_MAGIC 0x6d4a556d

#define AUTOFS_TYPE_INDIRECT     0x0001
#define AUTOFS_TYPE_DIRECT       0x0002
#define AUTOFS_TYPE_OFFSET       0x0004

struct autofs_sb_info {
	u32 magic;
	int pipefd;
	struct file *pipe;
	pid_t oz_pgrp;
	struct pid *oz_pgrp;
	int catatonic;
	int version;
	int sub_version;
	int min_proto;
	int max_proto;
	unsigned long exp_timeout;
	unsigned int type;
	struct super_block *sb;
	struct mutex wq_mutex;
	struct mutex pipe_mutex;
	spinlock_t fs_lock;
	struct autofs_wait_queue *queues; /* Wait queue pointer */
	spinlock_t lookup_lock;
	struct list_head active_list;
	struct list_head expiring_list;
	struct rcu_head rcu;
};

static inline struct autofs_sb_info *autofs_sbi(struct super_block *sb)
{
	return (struct autofs_sb_info *)(sb->s_fs_info);
}

/* autofs_oz_mode(): do we see the man behind the curtain?  (The
   processes which do manipulations for us in user space sees the raw
   filesystem without "magic".) */

static inline int autofs_oz_mode(struct autofs_sb_info *sbi) {
	return sbi->catatonic || task_pgrp(current) == sbi->oz_pgrp;
}

/* Hash operations */

void autofs_initialize_hash(struct autofs_dirhash *);
struct autofs_dir_ent *autofs_hash_lookup(const struct autofs_dirhash *,struct qstr *);
void autofs_hash_insert(struct autofs_dirhash *,struct autofs_dir_ent *);
void autofs_hash_delete(struct autofs_dir_ent *);
struct autofs_dir_ent *autofs_hash_enum(const struct autofs_dirhash *,off_t *,struct autofs_dir_ent *);
void autofs_hash_dputall(struct autofs_dirhash *);
void autofs_hash_nuke(struct autofs_sb_info *);

/* Expiration-handling functions */

void autofs_update_usage(struct autofs_dirhash *,struct autofs_dir_ent *);
struct autofs_dir_ent *autofs_expire(struct super_block *,struct autofs_sb_info *, struct vfsmount *mnt);

/* Operations structures */

extern const struct inode_operations autofs_root_inode_operations;
extern const struct inode_operations autofs_symlink_inode_operations;
extern const struct file_operations autofs_root_operations;

/* Initializing function */

int autofs_fill_super(struct super_block *, void *, int);
void autofs_kill_sb(struct super_block *sb);
struct inode *autofs_iget(struct super_block *, unsigned long);

/* Queue management functions */

int autofs_wait(struct autofs_sb_info *,struct qstr *);
int autofs_wait_release(struct autofs_sb_info *,autofs_wqt_t,int);
void autofs_catatonic_mode(struct autofs_sb_info *);

#ifdef DEBUG
void autofs_say(const char *name, int len);
#else
#define autofs_say(n,l) ((void)0)
#endif
	return sb->s_magic != AUTOFS_SUPER_MAGIC ?
		NULL : (struct autofs_sb_info *)(sb->s_fs_info);
}

static inline struct autofs_info *autofs_dentry_ino(struct dentry *dentry)
{
	return (struct autofs_info *)(dentry->d_fsdata);
}

/* autofs4_oz_mode(): do we see the man behind the curtain?  (The
   processes which do manipulations for us in user space sees the raw
   filesystem without "magic".) */

static inline int autofs4_oz_mode(struct autofs_sb_info *sbi) {
	return sbi->catatonic || task_pgrp_nr(current) == sbi->oz_pgrp;
}

/* Does a dentry have some pending activity? */
static inline int autofs4_ispending(struct dentry *dentry)
{
	struct autofs_info *inf = autofs4_dentry_ino(dentry);

	if (dentry->d_flags & DCACHE_AUTOFS_PENDING)
		return 1;

	if (inf->flags & AUTOFS_INF_EXPIRING)
		return 1;

	return 0;
}

static inline void autofs4_copy_atime(struct file *src, struct file *dst)
{
	dst->f_path.dentry->d_inode->i_atime =
		src->f_path.dentry->d_inode->i_atime;
	return;
}

struct inode *autofs4_get_inode(struct super_block *, struct autofs_info *);
/* autofs_oz_mode(): do we see the man behind the curtain?  (The
 * processes which do manipulations for us in user space sees the raw
 * filesystem without "magic".)
 */
static inline int autofs_oz_mode(struct autofs_sb_info *sbi)
{
	return sbi->catatonic || task_pgrp(current) == sbi->oz_pgrp;
}

struct inode *autofs_get_inode(struct super_block *, umode_t);
void autofs_free_ino(struct autofs_info *);

/* Expiration */
int is_autofs4_dentry(struct dentry *);
int autofs4_expire_wait(struct dentry *dentry);
int autofs4_expire_run(struct super_block *, struct vfsmount *,
			struct autofs_sb_info *,
			struct autofs_packet_expire __user *);
int autofs4_expire_multi(struct super_block *, struct vfsmount *,
			struct autofs_sb_info *, int __user *);
int autofs4_expire_wait(struct dentry *dentry, int rcu_walk);
int autofs4_expire_wait(const struct path *path, int rcu_walk);
int autofs4_expire_run(struct super_block *, struct vfsmount *,
		       struct autofs_sb_info *,
		       struct autofs_packet_expire __user *);
int autofs4_do_expire_multi(struct super_block *sb, struct vfsmount *mnt,
			    struct autofs_sb_info *sbi, int when);
int autofs4_expire_multi(struct super_block *, struct vfsmount *,
			 struct autofs_sb_info *, int __user *);
struct dentry *autofs4_expire_direct(struct super_block *sb,
				     struct vfsmount *mnt,
				     struct autofs_sb_info *sbi, int how);
struct dentry *autofs4_expire_indirect(struct super_block *sb,
				       struct vfsmount *mnt,
				       struct autofs_sb_info *sbi, int how);
int is_autofs_dentry(struct dentry *);
int autofs_expire_wait(const struct path *path, int rcu_walk);
int autofs_expire_run(struct super_block *, struct vfsmount *,
		      struct autofs_sb_info *,
		      struct autofs_packet_expire __user *);
int autofs_do_expire_multi(struct super_block *sb, struct vfsmount *mnt,
			   struct autofs_sb_info *sbi, unsigned int how);
int autofs_expire_multi(struct super_block *, struct vfsmount *,
			struct autofs_sb_info *, int __user *);

/* Device node initialization */

int autofs_dev_ioctl_init(void);
void autofs_dev_ioctl_exit(void);

/* Operations structures */

extern const struct inode_operations autofs4_symlink_inode_operations;
extern const struct inode_operations autofs4_dir_inode_operations;
extern const struct inode_operations autofs4_root_inode_operations;
extern const struct inode_operations autofs4_indirect_root_inode_operations;
extern const struct inode_operations autofs4_direct_root_inode_operations;
extern const struct file_operations autofs4_dir_operations;
extern const struct file_operations autofs4_root_operations;
extern const struct file_operations autofs4_dir_operations;
extern const struct file_operations autofs4_root_operations;
extern const struct dentry_operations autofs4_dentry_operations;
extern const struct inode_operations autofs_symlink_inode_operations;
extern const struct inode_operations autofs_dir_inode_operations;
extern const struct file_operations autofs_dir_operations;
extern const struct file_operations autofs_root_operations;
extern const struct dentry_operations autofs_dentry_operations;

/* VFS automount flags management functions */
static inline void __managed_dentry_set_managed(struct dentry *dentry)
{
	dentry->d_flags |= (DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT);
}

static inline void managed_dentry_set_managed(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	__managed_dentry_set_managed(dentry);
	spin_unlock(&dentry->d_lock);
}

static inline void __managed_dentry_clear_managed(struct dentry *dentry)
{
	dentry->d_flags &= ~(DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT);
}

static inline void managed_dentry_clear_managed(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	__managed_dentry_clear_managed(dentry);
	spin_unlock(&dentry->d_lock);
}

/* Initializing function */

int autofs4_fill_super(struct super_block *, void *, int);
struct autofs_info *autofs4_init_ino(struct autofs_info *, struct autofs_sb_info *sbi, mode_t mode);
struct autofs_info *autofs4_new_ino(struct autofs_sb_info *);
void autofs4_clean_ino(struct autofs_info *);
int autofs_fill_super(struct super_block *, void *, int);
struct autofs_info *autofs_new_ino(struct autofs_sb_info *);
void autofs_clean_ino(struct autofs_info *);

static inline int autofs_prepare_pipe(struct file *pipe)
{
	if (!(pipe->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (!S_ISFIFO(file_inode(pipe)->i_mode))
		return -EINVAL;
	/* We want a packet pipe */
	pipe->f_flags |= O_DIRECT;
	return 0;
}

/* Queue management functions */

int autofs_wait(struct autofs_sb_info *,
		 const struct path *, enum autofs_notify);
int autofs_wait_release(struct autofs_sb_info *, autofs_wqt_t, int);
void autofs_catatonic_mode(struct autofs_sb_info *);

static inline int autofs4_follow_mount(struct vfsmount **mnt, struct dentry **dentry)
{
	int res = 0;

	while (d_mountpoint(*dentry)) {
		int followed = follow_down(mnt, dentry);
		if (!followed)
			break;
		res = 1;
	}
	return res;
}

static inline u32 autofs4_get_dev(struct autofs_sb_info *sbi)
static inline u32 autofs_get_dev(struct autofs_sb_info *sbi)
{
	return new_encode_dev(sbi->sb->s_dev);
}

static inline u64 autofs_get_ino(struct autofs_sb_info *sbi)
{
	return sbi->sb->s_root->d_inode->i_ino;
}

static inline int simple_positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

static inline int __simple_empty(struct dentry *dentry)
{
	struct dentry *child;
	int ret = 0;

	list_for_each_entry(child, &dentry->d_subdirs, d_u.d_child)
		if (simple_positive(child))
			goto out;
	ret = 1;
out:
	return ret;
}

void autofs4_dentry_release(struct dentry *);
	return d_inode(sbi->sb->s_root)->i_ino;
}

static inline void __autofs_add_expiring(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);

	if (ino) {
		if (list_empty(&ino->expiring))
			list_add(&ino->expiring, &sbi->expiring_list);
	}
}

static inline void autofs_add_expiring(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);

	if (ino) {
		spin_lock(&sbi->lookup_lock);
		if (list_empty(&ino->expiring))
			list_add(&ino->expiring, &sbi->expiring_list);
		spin_unlock(&sbi->lookup_lock);
	}
}

static inline void autofs_del_expiring(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);

	if (ino) {
		spin_lock(&sbi->lookup_lock);
		if (!list_empty(&ino->expiring))
			list_del_init(&ino->expiring);
		spin_unlock(&sbi->lookup_lock);
	}
}

void autofs_kill_sb(struct super_block *);
