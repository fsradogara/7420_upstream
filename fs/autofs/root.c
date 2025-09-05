/* -*- linux-c -*- --------------------------------------------------------- *
 *
 * linux/fs/autofs/root.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
/*
 * Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 * Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 * Copyright 2001-2006 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include <linux/capability.h>
 */

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/param.h>
#include <linux/time.h>
#include <linux/smp_lock.h>
#include "autofs_i.h"

static int autofs_root_readdir(struct file *,void *,filldir_t);
static struct dentry *autofs_root_lookup(struct inode *,struct dentry *, struct nameidata *);
static int autofs_root_symlink(struct inode *,struct dentry *,const char *);
static int autofs_root_unlink(struct inode *,struct dentry *);
static int autofs_root_rmdir(struct inode *,struct dentry *);
static int autofs_root_mkdir(struct inode *,struct dentry *,int);
static int autofs_root_ioctl(struct inode *, struct file *,unsigned int,unsigned long);

const struct file_operations autofs_root_operations = {
	.read		= generic_read_dir,
	.readdir	= autofs_root_readdir,
	.ioctl		= autofs_root_ioctl,
};

const struct inode_operations autofs_root_inode_operations = {
        .lookup		= autofs_root_lookup,
        .unlink		= autofs_root_unlink,
        .symlink	= autofs_root_symlink,
        .mkdir		= autofs_root_mkdir,
        .rmdir		= autofs_root_rmdir,
};

static int autofs_root_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct autofs_dir_ent *ent = NULL;
	struct autofs_dirhash *dirhash;
	struct autofs_sb_info *sbi;
	struct inode * inode = filp->f_path.dentry->d_inode;
	off_t onr, nr;

	lock_kernel();

	sbi = autofs_sbi(inode->i_sb);
	dirhash = &sbi->dirhash;
	nr = filp->f_pos;

	switch(nr)
	{
	case 0:
		if (filldir(dirent, ".", 1, nr, inode->i_ino, DT_DIR) < 0)
			goto out;
		filp->f_pos = ++nr;
		/* fall through */
	case 1:
		if (filldir(dirent, "..", 2, nr, inode->i_ino, DT_DIR) < 0)
			goto out;
		filp->f_pos = ++nr;
		/* fall through */
	default:
		while (onr = nr, ent = autofs_hash_enum(dirhash,&nr,ent)) {
			if (!ent->dentry || d_mountpoint(ent->dentry)) {
				if (filldir(dirent,ent->name,ent->len,onr,ent->ino,DT_UNKNOWN) < 0)
					goto out;
				filp->f_pos = nr;
			}
		}
		break;
	}

out:
	unlock_kernel();
	return 0;
}

static int try_to_fill_dentry(struct dentry *dentry, struct super_block *sb, struct autofs_sb_info *sbi)
{
	struct inode * inode;
	struct autofs_dir_ent *ent;
	int status = 0;

	if (!(ent = autofs_hash_lookup(&sbi->dirhash, &dentry->d_name))) {
		do {
			if (status && dentry->d_inode) {
				if (status != -ENOENT)
					printk("autofs warning: lookup failure on positive dentry, status = %d, name = %s\n", status, dentry->d_name.name);
				return 0; /* Try to get the kernel to invalidate this dentry */
			}

			/* Turn this into a real negative dentry? */
			if (status == -ENOENT) {
				dentry->d_time = jiffies + AUTOFS_NEGATIVE_TIMEOUT;
				dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
				return 1;
			} else if (status) {
				/* Return a negative dentry, but leave it "pending" */
				return 1;
			}
			status = autofs_wait(sbi, &dentry->d_name);
		} while (!(ent = autofs_hash_lookup(&sbi->dirhash, &dentry->d_name)));
	}

	/* Abuse this field as a pointer to the directory entry, used to
	   find the expire list pointers */
	dentry->d_time = (unsigned long) ent;
	
	if (!dentry->d_inode) {
		inode = autofs_iget(sb, ent->ino);
		if (IS_ERR(inode)) {
			/* Failed, but leave pending for next time */
			return 1;
		}
		dentry->d_inode = inode;
	}

	/* If this is a directory that isn't a mount point, bitch at the
	   daemon and fix it in user space */
	if (S_ISDIR(dentry->d_inode->i_mode) && !d_mountpoint(dentry)) {
		return !autofs_wait(sbi, &dentry->d_name);
	}

	/* We don't update the usages for the autofs daemon itself, this
	   is necessary for recursive autofs mounts */
	if (!autofs_oz_mode(sbi)) {
		autofs_update_usage(&sbi->dirhash,ent);
	}

	dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
	return 1;
}

#include <linux/slab.h>
#include <linux/param.h>
#include <linux/time.h>
#include <linux/compat.h>

#include "autofs_i.h"

static int autofs4_dir_symlink(struct inode *,struct dentry *,const char *);
static int autofs4_dir_unlink(struct inode *,struct dentry *);
static int autofs4_dir_rmdir(struct inode *,struct dentry *);
static int autofs4_dir_mkdir(struct inode *,struct dentry *,int);
static int autofs4_root_ioctl(struct inode *, struct file *,unsigned int,unsigned long);
static int autofs4_dir_open(struct inode *inode, struct file *file);
static struct dentry *autofs4_lookup(struct inode *,struct dentry *, struct nameidata *);
static void *autofs4_follow_link(struct dentry *, struct nameidata *);

#define TRIGGER_FLAGS   (LOOKUP_CONTINUE | LOOKUP_DIRECTORY)
#define TRIGGER_INTENTS (LOOKUP_OPEN | LOOKUP_CREATE)
static int autofs4_dir_mkdir(struct inode *,struct dentry *,umode_t);
static long autofs4_root_ioctl(struct file *,unsigned int,unsigned long);
static int autofs4_dir_symlink(struct inode *, struct dentry *, const char *);
static int autofs4_dir_unlink(struct inode *, struct dentry *);
static int autofs4_dir_rmdir(struct inode *, struct dentry *);
static int autofs4_dir_mkdir(struct inode *, struct dentry *, umode_t);
static long autofs4_root_ioctl(struct file *, unsigned int, unsigned long);
static int autofs_dir_symlink(struct inode *, struct dentry *, const char *);
static int autofs_dir_unlink(struct inode *, struct dentry *);
static int autofs_dir_rmdir(struct inode *, struct dentry *);
static int autofs_dir_mkdir(struct inode *, struct dentry *, umode_t);
static long autofs_root_ioctl(struct file *, unsigned int, unsigned long);
#ifdef CONFIG_COMPAT
static long autofs_root_compat_ioctl(struct file *,
				     unsigned int, unsigned long);
#endif
static int autofs_dir_open(struct inode *inode, struct file *file);
static struct dentry *autofs_lookup(struct inode *,
				    struct dentry *, unsigned int);
static struct vfsmount *autofs_d_automount(struct path *);
static int autofs_d_manage(const struct path *, bool);
static void autofs_dentry_release(struct dentry *);

const struct file_operations autofs_root_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.read		= generic_read_dir,
	.readdir	= dcache_readdir,
	.llseek		= dcache_dir_lseek,
	.ioctl		= autofs4_root_ioctl,
	.iterate	= dcache_readdir,
	.iterate_shared	= dcache_readdir,
	.llseek		= dcache_dir_lseek,
	.unlocked_ioctl	= autofs_root_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= autofs_root_compat_ioctl,
#endif
};

const struct file_operations autofs_dir_operations = {
	.open		= autofs_dir_open,
	.release	= dcache_dir_close,
	.read		= generic_read_dir,
	.readdir	= dcache_readdir,
	.llseek		= dcache_dir_lseek,
};

const struct inode_operations autofs4_indirect_root_inode_operations = {
	.lookup		= autofs4_lookup,
	.unlink		= autofs4_dir_unlink,
	.symlink	= autofs4_dir_symlink,
	.mkdir		= autofs4_dir_mkdir,
	.rmdir		= autofs4_dir_rmdir,
};

const struct inode_operations autofs4_direct_root_inode_operations = {
	.lookup		= autofs4_lookup,
	.unlink		= autofs4_dir_unlink,
	.mkdir		= autofs4_dir_mkdir,
	.rmdir		= autofs4_dir_rmdir,
	.follow_link	= autofs4_follow_link,
};

	.iterate	= dcache_readdir,
	.iterate_shared	= dcache_readdir,
	.llseek		= dcache_dir_lseek,
};

const struct inode_operations autofs_dir_inode_operations = {
	.lookup		= autofs_lookup,
	.unlink		= autofs_dir_unlink,
	.symlink	= autofs_dir_symlink,
	.mkdir		= autofs_dir_mkdir,
	.rmdir		= autofs_dir_rmdir,
};

const struct dentry_operations autofs_dentry_operations = {
	.d_automount	= autofs_d_automount,
	.d_manage	= autofs_d_manage,
	.d_release	= autofs_dentry_release,
};

static void autofs_add_active(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino;

	ino = autofs_dentry_ino(dentry);
	if (ino) {
		spin_lock(&sbi->lookup_lock);
		if (!ino->active_count) {
			if (list_empty(&ino->active))
				list_add(&ino->active, &sbi->active_list);
		}
		ino->active_count++;
		spin_unlock(&sbi->lookup_lock);
	}
}

static void autofs_del_active(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino;

	ino = autofs_dentry_ino(dentry);
	if (ino) {
		spin_lock(&sbi->lookup_lock);
		ino->active_count--;
		if (!ino->active_count) {
			if (!list_empty(&ino->active))
				list_del_init(&ino->active);
		}
		spin_unlock(&sbi->lookup_lock);
	}
}

static int autofs_dir_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);

	DPRINTK("file=%p dentry=%p %.*s",
		file, dentry, dentry->d_name.len, dentry->d_name.name);
	DPRINTK("file=%p dentry=%p %pd", file, dentry, dentry);
	pr_debug("file=%p dentry=%p %pd\n", file, dentry, dentry);

	if (autofs_oz_mode(sbi))
		goto out;

	/*
	 * An empty directory in an autofs file system is always a
	 * mount point. The daemon must have failed to mount this
	 * during lookup so it doesn't exist. This can happen, for
	 * example, if user space returns an incorrect status for a
	 * mount request. Otherwise we're doing a readdir on the
	 * autofs file system so just let the libfs routines handle
	 * it.
	 */
	spin_lock(&dcache_lock);
	if (!d_mountpoint(dentry) && __simple_empty(dentry)) {
		spin_unlock(&dcache_lock);
		return -ENOENT;
	}
	spin_unlock(&dcache_lock);
	spin_lock(&sbi->lookup_lock);
	if (!path_is_mountpoint(&file->f_path) && simple_empty(dentry)) {
		spin_unlock(&sbi->lookup_lock);
		return -ENOENT;
	}
	spin_unlock(&sbi->lookup_lock);

out:
	return dcache_dir_open(inode, file);
}

static int try_to_fill_dentry(struct dentry *dentry, int flags)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	int status;

	DPRINTK("dentry=%p %.*s ino=%p",
		 dentry, dentry->d_name.len, dentry->d_name.name, dentry->d_inode);

	/*
	 * Wait for a pending mount, triggering one if there
	 * isn't one already
	 */
	if (dentry->d_inode == NULL) {
		DPRINTK("waiting for mount name=%.*s",
			 dentry->d_name.len, dentry->d_name.name);

		status = autofs4_wait(sbi, dentry, NFY_MOUNT);

		DPRINTK("mount done status=%d", status);

		/* Turn this into a real negative dentry? */
		if (status == -ENOENT) {
			spin_lock(&dentry->d_lock);
			dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
			spin_unlock(&dentry->d_lock);
			return status;
		} else if (status) {
			/* Return a negative dentry, but leave it "pending" */
			return status;
		}
	/* Trigger mount for path component or follow link */
	} else if (dentry->d_flags & DCACHE_AUTOFS_PENDING ||
			flags & (TRIGGER_FLAGS | TRIGGER_INTENTS) ||
			current->link_count) {
		DPRINTK("waiting for mount name=%.*s",
			dentry->d_name.len, dentry->d_name.name);

		spin_lock(&dentry->d_lock);
		dentry->d_flags |= DCACHE_AUTOFS_PENDING;
		spin_unlock(&dentry->d_lock);
		status = autofs4_wait(sbi, dentry, NFY_MOUNT);

		DPRINTK("mount done status=%d", status);

		if (status) {
			spin_lock(&dentry->d_lock);
			dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
			spin_unlock(&dentry->d_lock);
			return status;
		}
	}

	/* Initialize expiry counter after successful mount */
	if (ino)
		ino->last_used = jiffies;

	spin_lock(&dentry->d_lock);
	dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
	spin_unlock(&dentry->d_lock);

	return 0;
}

/* For autofs direct mounts the follow link triggers the mount */
static void *autofs4_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	int oz_mode = autofs4_oz_mode(sbi);
	unsigned int lookup_type;
	int status;

	DPRINTK("dentry=%p %.*s oz_mode=%d nd->flags=%d",
		dentry, dentry->d_name.len, dentry->d_name.name, oz_mode,
		nd->flags);
	/*
	 * For an expire of a covered direct or offset mount we need
	 * to beeak out of follow_down() at the autofs mount trigger
	 * (d_mounted--), so we can see the expiring flag, and manage
	 * the blocking and following here until the expire is completed.
	 */
	if (oz_mode) {
		spin_lock(&sbi->fs_lock);
		if (ino->flags & AUTOFS_INF_EXPIRING) {
			spin_unlock(&sbi->fs_lock);
			/* Follow down to our covering mount. */
			if (!follow_down(&nd->path.mnt, &nd->path.dentry))
				goto done;
			goto follow;
		}
static void autofs4_dentry_release(struct dentry *de)
static void autofs_dentry_release(struct dentry *de)
{
	struct autofs_info *ino = autofs_dentry_ino(de);
	struct autofs_sb_info *sbi = autofs_sbi(de->d_sb);

	pr_debug("releasing %p\n", de);

	if (!ino)
		return;

	if (sbi) {
		spin_lock(&sbi->lookup_lock);
		if (!list_empty(&ino->active))
			list_del(&ino->active);
		if (!list_empty(&ino->expiring))
			list_del(&ino->expiring);
		spin_unlock(&sbi->lookup_lock);
	}

	autofs_free_ino(ino);
}

static struct dentry *autofs_lookup_active(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct dentry *parent = dentry->d_parent;
	const struct qstr *name = &dentry->d_name;
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct list_head *p, *head;

	head = &sbi->active_list;
	if (list_empty(head))
		return NULL;
	spin_lock(&sbi->lookup_lock);
	list_for_each(p, head) {
		struct autofs_info *ino;
		struct dentry *active;
		const struct qstr *qstr;

		ino = list_entry(p, struct autofs_info, active);
		active = ino->dentry;

		spin_lock(&active->d_lock);

		/* Already gone? */
		if ((int) d_count(active) <= 0)
			goto next;

		qstr = &active->d_name;

		if (active->d_name.hash != hash)
			goto next;
		if (active->d_parent != parent)
			goto next;

		if (qstr->len != len)
			goto next;
		if (memcmp(qstr->name, str, len))
			goto next;

		if (d_unhashed(active)) {
			dget_dlock(active);
			spin_unlock(&active->d_lock);
			spin_unlock(&sbi->lookup_lock);
			return active;
		}
next:
		spin_unlock(&active->d_lock);
	}
	spin_unlock(&sbi->lookup_lock);

	return NULL;
}

static struct dentry *autofs_lookup_expiring(struct dentry *dentry,
					     bool rcu_walk)
{
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct dentry *parent = dentry->d_parent;
	const struct qstr *name = &dentry->d_name;
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct list_head *p, *head;

	head = &sbi->expiring_list;
	if (list_empty(head))
		return NULL;
	spin_lock(&sbi->lookup_lock);
	list_for_each(p, head) {
		struct autofs_info *ino;
		struct dentry *expiring;
		const struct qstr *qstr;

		if (rcu_walk) {
			spin_unlock(&sbi->lookup_lock);
			return ERR_PTR(-ECHILD);
		}

		ino = list_entry(p, struct autofs_info, expiring);
		expiring = ino->dentry;

		spin_lock(&expiring->d_lock);

		/* We've already been dentry_iput or unlinked */
		if (d_really_is_negative(expiring))
			goto next;

		qstr = &expiring->d_name;

		if (expiring->d_name.hash != hash)
			goto next;
		if (expiring->d_parent != parent)
			goto next;

		if (qstr->len != len)
			goto next;
		if (memcmp(qstr->name, str, len))
			goto next;

		if (d_unhashed(expiring)) {
			dget_dlock(expiring);
			spin_unlock(&expiring->d_lock);
			spin_unlock(&sbi->lookup_lock);
			return expiring;
		}
next:
		spin_unlock(&expiring->d_lock);
	}
	spin_unlock(&sbi->lookup_lock);

	return NULL;
}

static int autofs_mount_wait(const struct path *path, bool rcu_walk)
{
	struct autofs_sb_info *sbi = autofs_sbi(path->dentry->d_sb);
	struct autofs_info *ino = autofs_dentry_ino(path->dentry);
	int status = 0;

	if (ino->flags & AUTOFS_INF_PENDING) {
		if (rcu_walk)
			return -ECHILD;
		pr_debug("waiting for mount name=%pd\n", path->dentry);
		status = autofs_wait(sbi, path, NFY_MOUNT);
		pr_debug("mount wait done status=%d\n", status);
	}
	ino->last_used = jiffies;
	return status;
}

static int do_expire_wait(const struct path *path, bool rcu_walk)
{
	struct dentry *dentry = path->dentry;
	struct dentry *expiring;

	expiring = autofs_lookup_expiring(dentry, rcu_walk);
	if (IS_ERR(expiring))
		return PTR_ERR(expiring);
	if (!expiring)
		return autofs_expire_wait(path, rcu_walk);
	else {
		const struct path this = { .mnt = path->mnt, .dentry = expiring };
		/*
		 * If we are racing with expire the request might not
		 * be quite complete, but the directory has been removed
		 * so it must have been successful, just wait for it.
		 */
		autofs_expire_wait(&this, 0);
		autofs_del_expiring(expiring);
		dput(expiring);
	}
	return 0;
}

static struct dentry *autofs_mountpoint_changed(struct path *path)
{
	struct dentry *dentry = path->dentry;
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);

	/*
	 * If this is an indirect mount the dentry could have gone away
	 * as a result of an expire and a new one created.
	 */
	if (autofs_type_indirect(sbi->type) && d_unhashed(dentry)) {
		struct dentry *parent = dentry->d_parent;
		struct autofs_info *ino;
		struct dentry *new;

		new = d_lookup(parent, &dentry->d_name);
		if (!new)
			return NULL;
		ino = autofs_dentry_ino(new);
		ino->last_used = jiffies;
		dput(path->dentry);
		path->dentry = new;
	}
	return path->dentry;
}

static struct vfsmount *autofs_d_automount(struct path *path)
{
	struct dentry *dentry = path->dentry;
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);
	int status;

	pr_debug("dentry=%p %pd\n", dentry, dentry);

	/* The daemon never triggers a mount. */
	if (autofs_oz_mode(sbi))
		return NULL;

	/*
	 * If an expire request is pending everyone must wait.
	 * If the expire fails we're still mounted so continue
	 * the follow and return. A return of -EAGAIN (which only
	 * happens with indirect mounts) means the expire completed
	 * and the directory was removed, so just go ahead and try
	 * the mount.
	 */
	status = do_expire_wait(path, 0);
	if (status && status != -EAGAIN)
		return NULL;

	/* Callback to the daemon to perform the mount or wait */
	spin_lock(&sbi->fs_lock);
	if (ino->flags & AUTOFS_INF_PENDING) {
		spin_unlock(&sbi->fs_lock);
		status = autofs_mount_wait(path, 0);
		if (status)
			return ERR_PTR(status);
		goto done;
	}

	/*
	 * If the dentry is a symlink it's equivalent to a directory
	 * having path_is_mountpoint() true, so there's no need to call
	 * back to the daemon.
	 */
	if (d_really_is_positive(dentry) && d_is_symlink(dentry)) {
		spin_unlock(&sbi->fs_lock);
		goto done;
	}

	/* If an expire request is pending everyone must wait. */
	autofs4_expire_wait(dentry);

	/* We trigger a mount for almost all flags */
	lookup_type = nd->flags & (TRIGGER_FLAGS | TRIGGER_INTENTS);
	if (!(lookup_type || dentry->d_flags & DCACHE_AUTOFS_PENDING))
		goto follow;

	/*
	 * If the dentry contains directories then it is an autofs
	 * multi-mount with no root mount offset. So don't try to
	 * mount it again.
	 */
	spin_lock(&dcache_lock);
	if (dentry->d_flags & DCACHE_AUTOFS_PENDING ||
	    (!d_mountpoint(dentry) && __simple_empty(dentry))) {
		spin_unlock(&dcache_lock);

		status = try_to_fill_dentry(dentry, 0);
		if (status)
			goto out_error;

		goto follow;
	}
	spin_unlock(&dcache_lock);
follow:
	/*
	 * If there is no root mount it must be an autofs
	 * multi-mount with no root offset so we don't need
	 * to follow it.
	 */
	if (d_mountpoint(dentry)) {
		if (!autofs4_follow_mount(&nd->path.mnt,
					  &nd->path.dentry)) {
			status = -ENOENT;
			goto out_error;
		}
	}

done:
	return NULL;

out_error:
	path_put(&nd->path);
	return ERR_PTR(status);
}

/*
 * Revalidate is called on every cache lookup.  Some of those
 * cache lookups may actually happen while the dentry is not
 * yet completely filled in, and revalidate has to delay such
 * lookups..
 */
static int autofs_revalidate(struct dentry * dentry, struct nameidata *nd)
{
	struct inode * dir;
	struct autofs_sb_info *sbi;
	struct autofs_dir_ent *ent;
	int res;

	lock_kernel();
	dir = dentry->d_parent->d_inode;
	sbi = autofs_sbi(dir->i_sb);

	/* Pending dentry */
	if (dentry->d_flags & DCACHE_AUTOFS_PENDING) {
		if (autofs_oz_mode(sbi))
			res = 1;
		else
			res = try_to_fill_dentry(dentry, dir->i_sb, sbi);
		unlock_kernel();
		return res;
	}

	/* Negative dentry.. invalidate if "old" */
	if (!dentry->d_inode) {
		unlock_kernel();
		return (dentry->d_time - jiffies <= AUTOFS_NEGATIVE_TIMEOUT);
	}
		
	/* Check for a non-mountpoint directory */
	if (S_ISDIR(dentry->d_inode->i_mode) && !d_mountpoint(dentry)) {
		if (autofs_oz_mode(sbi))
			res = 1;
		else
			res = try_to_fill_dentry(dentry, dir->i_sb, sbi);
		unlock_kernel();
		return res;
	}

	/* Update the usage list */
	if (!autofs_oz_mode(sbi)) {
		ent = (struct autofs_dir_ent *) dentry->d_time;
		if (ent)
			autofs_update_usage(&sbi->dirhash,ent);
	}
	unlock_kernel();
	return 1;
}

static struct dentry_operations autofs_dentry_operations = {
	.d_revalidate	= autofs_revalidate,
};

static struct dentry *autofs_root_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct autofs_sb_info *sbi;
	int oz_mode;

	DPRINTK(("autofs_root_lookup: name = "));
	lock_kernel();
	autofs_say(dentry->d_name.name,dentry->d_name.len);

	if (dentry->d_name.len > NAME_MAX) {
		unlock_kernel();
		return ERR_PTR(-ENAMETOOLONG);/* File name too long to exist */
	}

	sbi = autofs_sbi(dir->i_sb);

	oz_mode = autofs_oz_mode(sbi);
	DPRINTK(("autofs_lookup: pid = %u, pgrp = %u, catatonic = %d, "
				"oz_mode = %d\n", task_pid_nr(current),
				task_pgrp_nr(current), sbi->catatonic,
				oz_mode));

	/*
	 * Mark the dentry incomplete, but add it. This is needed so
	 * that the VFS layer knows about the dentry, and we can count
	 * on catching any lookups through the revalidate.
	 *
	 * Let all the hard work be done by the revalidate function that
	 * needs to be able to do this anyway..
	 *
	 * We need to do this before we release the directory semaphore.
	 */
	dentry->d_op = &autofs_dentry_operations;
	dentry->d_flags |= DCACHE_AUTOFS_PENDING;
	d_add(dentry, NULL);

	mutex_unlock(&dir->i_mutex);
	autofs_revalidate(dentry, nd);
	mutex_lock(&dir->i_mutex);
static int autofs4_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct autofs_sb_info *sbi = autofs4_sbi(dir->i_sb);
	int oz_mode = autofs4_oz_mode(sbi);
	int flags = nd ? nd->flags : 0;
	int status = 1;

	/* Pending dentry */
	spin_lock(&sbi->fs_lock);
	if (autofs4_ispending(dentry)) {
		/* The daemon never causes a mount to trigger */
		spin_unlock(&sbi->fs_lock);

		if (oz_mode)
			return 1;

		/*
		 * If the directory has gone away due to an expire
		 * we have been called as ->d_revalidate() and so
		 * we need to return false and proceed to ->lookup().
		 */
		if (autofs4_expire_wait(dentry) == -EAGAIN)
			return 0;

		/*
		 * A zero status is success otherwise we have a
		 * negative error code.
		 */
		status = try_to_fill_dentry(dentry, flags);
		if (status == 0)
			return 1;

		return status;
	}
	spin_unlock(&sbi->fs_lock);

	/* Negative dentry.. invalidate if "old" */
	if (dentry->d_inode == NULL)
		return 0;

	/* Check for a non-mountpoint directory with no contents */
	spin_lock(&dcache_lock);
	if (S_ISDIR(dentry->d_inode->i_mode) &&
	    !d_mountpoint(dentry) && 
	    __simple_empty(dentry)) {
		DPRINTK("dentry=%p %.*s, emptydir",
			 dentry, dentry->d_name.len, dentry->d_name.name);
		spin_unlock(&dcache_lock);

		/* The daemon never causes a mount to trigger */
		if (oz_mode)
			return 1;

		/*
		 * A zero status is success otherwise we have a
		 * negative error code.
		 */
		status = try_to_fill_dentry(dentry, flags);
		if (status == 0)
			return 1;

		return status;
	}
	spin_unlock(&dcache_lock);

	return 1;
}

void autofs4_dentry_release(struct dentry *de)
{
	struct autofs_info *inf;

	DPRINTK("releasing %p", de);

	inf = autofs4_dentry_ino(de);
	de->d_fsdata = NULL;

	if (inf) {
		struct autofs_sb_info *sbi = autofs4_sbi(de->d_sb);

		if (sbi) {
			spin_lock(&sbi->lookup_lock);
			if (!list_empty(&inf->active))
				list_del(&inf->active);
			if (!list_empty(&inf->expiring))
				list_del(&inf->expiring);
			spin_unlock(&sbi->lookup_lock);
		}

		inf->dentry = NULL;
		inf->inode = NULL;

		autofs4_free_ino(inf);
	}
}

/* For dentries of directories in the root dir */
static struct dentry_operations autofs4_root_dentry_operations = {
	.d_revalidate	= autofs4_revalidate,
	.d_release	= autofs4_dentry_release,
};

/* For other dentries */
static struct dentry_operations autofs4_dentry_operations = {
	.d_revalidate	= autofs4_revalidate,
	.d_release	= autofs4_dentry_release,
};

static struct dentry *autofs4_lookup_active(struct autofs_sb_info *sbi, struct dentry *parent, struct qstr *name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct list_head *p, *head;

	spin_lock(&dcache_lock);
	spin_lock(&sbi->lookup_lock);
	head = &sbi->active_list;
	list_for_each(p, head) {
		struct autofs_info *ino;
		struct dentry *dentry;
		struct qstr *qstr;

		ino = list_entry(p, struct autofs_info, active);
		dentry = ino->dentry;

		spin_lock(&dentry->d_lock);

		/* Already gone? */
		if (atomic_read(&dentry->d_count) == 0)
			goto next;

		qstr = &dentry->d_name;

		if (dentry->d_name.hash != hash)
			goto next;
		if (dentry->d_parent != parent)
			goto next;

		if (qstr->len != len)
			goto next;
		if (memcmp(qstr->name, str, len))
			goto next;

		if (d_unhashed(dentry)) {
			dget(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&sbi->lookup_lock);
			spin_unlock(&dcache_lock);
			return dentry;
		}
next:
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&sbi->lookup_lock);
	spin_unlock(&dcache_lock);

	return NULL;
}

static struct dentry *autofs4_lookup_expiring(struct autofs_sb_info *sbi, struct dentry *parent, struct qstr *name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct list_head *p, *head;

	spin_lock(&dcache_lock);
	spin_lock(&sbi->lookup_lock);
	head = &sbi->expiring_list;
	list_for_each(p, head) {
		struct autofs_info *ino;
		struct dentry *dentry;
		struct qstr *qstr;

		ino = list_entry(p, struct autofs_info, expiring);
		dentry = ino->dentry;

		spin_lock(&dentry->d_lock);

		/* Bad luck, we've already been dentry_iput */
		if (!dentry->d_inode)
			goto next;

		qstr = &dentry->d_name;

		if (dentry->d_name.hash != hash)
			goto next;
		if (dentry->d_parent != parent)
			goto next;

		if (qstr->len != len)
			goto next;
		if (memcmp(qstr->name, str, len))
			goto next;

		if (d_unhashed(dentry)) {
			dget(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&sbi->lookup_lock);
			spin_unlock(&dcache_lock);
			return dentry;
		}
next:
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&sbi->lookup_lock);
	spin_unlock(&dcache_lock);

	return NULL;
}

/* Lookups in the root directory */
static struct dentry *autofs4_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct autofs_sb_info *sbi;
	struct autofs_info *ino;
	struct dentry *expiring, *unhashed;
	int oz_mode;

	DPRINTK("name = %.*s",
		dentry->d_name.len, dentry->d_name.name);
	if (!d_mountpoint(dentry)) {
	if (!path_is_mountpoint(path)) {
		/*
		 * It's possible that user space hasn't removed directories
		 * after umounting a rootless multi-mount, although it
		 * should. For v5 path_has_submounts() is sufficient to
		 * handle this because the leaves of the directory tree under
		 * the mount never trigger mounts themselves (they have an
		 * autofs trigger mount mounted on them). But v4 pseudo direct
		 * mounts do need the leaves to trigger mounts. In this case
		 * we have no choice but to use the list_empty() check and
		 * require user space behave.
		 */
		if (sbi->version > 4) {
			if (path_has_submounts(path)) {
				spin_unlock(&sbi->fs_lock);
				goto done;
			}
		} else {
			if (!simple_empty(dentry)) {
				spin_unlock(&sbi->fs_lock);
				goto done;
			}
		}
		ino->flags |= AUTOFS_INF_PENDING;
		spin_unlock(&sbi->fs_lock);
		status = autofs_mount_wait(path, 0);
		spin_lock(&sbi->fs_lock);
		ino->flags &= ~AUTOFS_INF_PENDING;
		if (status) {
			spin_unlock(&sbi->fs_lock);
			return ERR_PTR(status);
		}
	}
	spin_unlock(&sbi->fs_lock);
done:
	/* Mount succeeded, check if we ended up with a new dentry */
	dentry = autofs_mountpoint_changed(path);
	if (!dentry)
		return ERR_PTR(-ENOENT);

	return NULL;
}

static int autofs_d_manage(const struct path *path, bool rcu_walk)
{
	struct dentry *dentry = path->dentry;
	struct autofs_sb_info *sbi = autofs_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);
	int status;

	pr_debug("dentry=%p %pd\n", dentry, dentry);

	/* The daemon never waits. */
	if (autofs_oz_mode(sbi)) {
		if (!path_is_mountpoint(path))
			return -EISDIR;
		return 0;
	}

	/* Wait for pending expires */
	if (do_expire_wait(path, rcu_walk) == -ECHILD)
		return -ECHILD;

	/*
	 * This dentry may be under construction so wait on mount
	 * completion.
	 */
	status = autofs_mount_wait(path, rcu_walk);
	if (status)
		return status;

	if (rcu_walk) {
		/* We don't need fs_lock in rcu_walk mode,
		 * just testing 'AUTOFS_INFO_NO_RCU' is enough.
		 * simple_empty() takes a spinlock, so leave it
		 * to last.
		 * We only return -EISDIR when certain this isn't
		 * a mount-trap.
		 */
		struct inode *inode;

		if (ino->flags & AUTOFS_INF_WANT_EXPIRE)
			return 0;
		if (path_is_mountpoint(path))
			return 0;
		inode = d_inode_rcu(dentry);
		if (inode && S_ISLNK(inode->i_mode))
			return -EISDIR;
		if (list_empty(&dentry->d_subdirs))
			return 0;
		if (!simple_empty(dentry))
			return -EISDIR;
		return 0;
	}

	spin_lock(&sbi->fs_lock);
	/*
	 * If the dentry has been selected for expire while we slept
	 * on the lock then it might go away. We'll deal with that in
	 * ->d_automount() and wait on a new mount if the expire
	 * succeeds or return here if it doesn't (since there's no
	 * mount to follow with a rootless multi-mount).
	 */
	if (!(ino->flags & AUTOFS_INF_EXPIRING)) {
		/*
		 * Any needed mounting has been completed and the path
		 * updated so check if this is a rootless multi-mount so
		 * we can avoid needless calls ->d_automount() and avoid
		 * an incorrect ELOOP error return.
		 */
		if ((!path_is_mountpoint(path) && !simple_empty(dentry)) ||
		    (d_really_is_positive(dentry) && d_is_symlink(dentry)))
			status = -EISDIR;
	}
	spin_unlock(&sbi->fs_lock);

	return status;
}

/* Lookups in the root directory */
static struct dentry *autofs_lookup(struct inode *dir,
				    struct dentry *dentry, unsigned int flags)
{
	struct autofs_sb_info *sbi;
	struct autofs_info *ino;
	struct dentry *active;

	pr_debug("name = %pd\n", dentry);

	/* File name too long to exist */
	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	sbi = autofs4_sbi(dir->i_sb);
	oz_mode = autofs4_oz_mode(sbi);

	DPRINTK("pid = %u, pgrp = %u, catatonic = %d, oz_mode = %d",
		 current->pid, task_pgrp_nr(current), sbi->catatonic, oz_mode);

	expiring = autofs4_lookup_expiring(sbi, dentry->d_parent, &dentry->d_name);
	if (expiring) {
		/*
		 * If we are racing with expire the request might not
		 * be quite complete but the directory has been removed
		 * so it must have been successful, so just wait for it.
		 */
		ino = autofs4_dentry_ino(expiring);
		autofs4_expire_wait(expiring);
		spin_lock(&sbi->lookup_lock);
		if (!list_empty(&ino->expiring))
			list_del_init(&ino->expiring);
		spin_unlock(&sbi->lookup_lock);
		dput(expiring);
	}

	unhashed = autofs4_lookup_active(sbi, dentry->d_parent, &dentry->d_name);
	if (unhashed)
		dentry = unhashed;
	else {
		/*
		 * Mark the dentry incomplete but don't hash it. We do this
		 * to serialize our inode creation operations (symlink and
		 * mkdir) which prevents deadlock during the callback to
		 * the daemon. Subsequent user space lookups for the same
		 * dentry are placed on the wait queue while the daemon
		 * itself is allowed passage unresticted so the create
		 * operation itself can then hash the dentry. Finally,
		 * we check for the hashed dentry and return the newly
		 * hashed dentry.
		 */
		dentry->d_op = &autofs4_root_dentry_operations;

		/*
		 * And we need to ensure that the same dentry is used for
		 * all following lookup calls until it is hashed so that
		 * the dentry flags are persistent throughout the request.
		 */
		ino = autofs4_init_ino(NULL, sbi, 0555);
	sbi = autofs_sbi(dir->i_sb);

	pr_debug("pid = %u, pgrp = %u, catatonic = %d, oz_mode = %d\n",
		 current->pid, task_pgrp_nr(current), sbi->catatonic,
		 autofs_oz_mode(sbi));

	active = autofs_lookup_active(dentry);
	if (active)
		return active;
	else {
		/*
		 * A dentry that is not within the root can never trigger a
		 * mount operation, unless the directory already exists, so we
		 * can return fail immediately.  The daemon however does need
		 * to create directories within the file system.
		 */
		if (!autofs_oz_mode(sbi) && !IS_ROOT(dentry->d_parent))
			return ERR_PTR(-ENOENT);

		/* Mark entries in the root as mount triggers */
		if (IS_ROOT(dentry->d_parent) &&
		    autofs_type_indirect(sbi->type))
			__managed_dentry_set_managed(dentry);

		ino = autofs_new_ino(sbi);
		if (!ino)
			return ERR_PTR(-ENOMEM);

		dentry->d_fsdata = ino;
		ino->dentry = dentry;

		spin_lock(&sbi->lookup_lock);
		list_add(&ino->active, &sbi->active_list);
		spin_unlock(&sbi->lookup_lock);

		d_instantiate(dentry, NULL);
	}

	if (!oz_mode) {
		spin_lock(&dentry->d_lock);
		dentry->d_flags |= DCACHE_AUTOFS_PENDING;
		spin_unlock(&dentry->d_lock);
		if (dentry->d_op && dentry->d_op->d_revalidate) {
			mutex_unlock(&dir->i_mutex);
			(dentry->d_op->d_revalidate)(dentry, nd);
			mutex_lock(&dir->i_mutex);
		}
	}

	/*
	 * If we are still pending, check if we had to handle
	 * a signal. If so we can force a restart..
	 */
	if (dentry->d_flags & DCACHE_AUTOFS_PENDING) {
		/* See if we were interrupted */
		if (signal_pending(current)) {
			sigset_t *sigset = &current->pending.signal;
			if (sigismember (sigset, SIGKILL) ||
			    sigismember (sigset, SIGQUIT) ||
			    sigismember (sigset, SIGINT)) {
				unlock_kernel();
				return ERR_PTR(-ERESTARTNOINTR);
			}
		}
	}
	unlock_kernel();

	/*
	 * If this dentry is unhashed, then we shouldn't honour this
	 * lookup even if the dentry is positive.  Returning ENOENT here
	 * doesn't do the right thing for all system calls, but it should
	 * be OK for the operations we permit from an autofs.
	 */
	if (dentry->d_inode && d_unhashed(dentry))
		return ERR_PTR(-ENOENT);

	return NULL;
}

static int autofs_root_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_dirhash *dh = &sbi->dirhash;
	struct autofs_dir_ent *ent;
	unsigned int n;
	int slsize;
	struct autofs_symlink *sl;
	struct inode *inode;

	DPRINTK(("autofs_root_symlink: %s <- ", symname));
	autofs_say(dentry->d_name.name,dentry->d_name.len);

	lock_kernel();
	if (!autofs_oz_mode(sbi)) {
		unlock_kernel();
		return -EACCES;
	}

	if (autofs_hash_lookup(dh, &dentry->d_name)) {
		unlock_kernel();
		return -EEXIST;
	}

	n = find_first_zero_bit(sbi->symlink_bitmap,AUTOFS_MAX_SYMLINKS);
	if (n >= AUTOFS_MAX_SYMLINKS) {
		unlock_kernel();
		return -ENOSPC;
	}

	set_bit(n,sbi->symlink_bitmap);
	sl = &sbi->symlink[n];
	sl->len = strlen(symname);
	sl->data = kmalloc(slsize = sl->len+1, GFP_KERNEL);
	if (!sl->data) {
		clear_bit(n,sbi->symlink_bitmap);
		unlock_kernel();
		return -ENOSPC;
	}

	ent = kmalloc(sizeof(struct autofs_dir_ent), GFP_KERNEL);
	if (!ent) {
		kfree(sl->data);
		clear_bit(n,sbi->symlink_bitmap);
		unlock_kernel();
		return -ENOSPC;
	}

	ent->name = kmalloc(dentry->d_name.len+1, GFP_KERNEL);
	if (!ent->name) {
		kfree(sl->data);
		kfree(ent);
		clear_bit(n,sbi->symlink_bitmap);
		unlock_kernel();
		return -ENOSPC;
	}

	memcpy(sl->data,symname,slsize);
	sl->mtime = get_seconds();

	ent->ino = AUTOFS_FIRST_SYMLINK + n;
	ent->hash = dentry->d_name.hash;
	memcpy(ent->name, dentry->d_name.name, 1+(ent->len = dentry->d_name.len));
	ent->dentry = NULL;	/* We don't keep the dentry for symlinks */

	autofs_hash_insert(dh,ent);

	inode = autofs_iget(dir->i_sb, ent->ino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	d_instantiate(dentry, inode);
	unlock_kernel();
			    if (unhashed)
				dput(unhashed);
			    return ERR_PTR(-ERESTARTNOINTR);
			}
		}
		if (!oz_mode) {
			spin_lock(&dentry->d_lock);
			dentry->d_flags &= ~DCACHE_AUTOFS_PENDING;
			spin_unlock(&dentry->d_lock);
		}
	}

	/*
	 * If this dentry is unhashed, then we shouldn't honour this
	 * lookup.  Returning ENOENT here doesn't do the right thing
	 * for all system calls, but it should be OK for the operations
	 * we permit from an autofs.
	 */
	if (!oz_mode && d_unhashed(dentry)) {
		/*
		 * A user space application can (and has done in the past)
		 * remove and re-create this directory during the callback.
		 * This can leave us with an unhashed dentry, but a
		 * successful mount!  So we need to perform another
		 * cached lookup in case the dentry now exists.
		 */
		struct dentry *parent = dentry->d_parent;
		struct dentry *new = d_lookup(parent, &dentry->d_name);
		if (new != NULL)
			dentry = new;
		else
			dentry = ERR_PTR(-ENOENT);

		if (unhashed)
			dput(unhashed);

		return dentry;
	}

	if (unhashed)
		return unhashed;

		autofs4_add_active(dentry);
		autofs_add_active(dentry);
	}
	return NULL;
}

static int autofs_dir_symlink(struct inode *dir,
			       struct dentry *dentry,
			       const char *symname)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);
	struct autofs_info *p_ino;
	struct inode *inode;
	char *cp;

	DPRINTK("%s <- %.*s", symname,
		dentry->d_name.len, dentry->d_name.name);
	size_t size = strlen(symname);
	char *cp;

	pr_debug("%s <- %pd\n", symname, dentry);

	if (!autofs_oz_mode(sbi))
		return -EACCES;

	/* autofs_oz_mode() needs to allow path walks when the
	 * autofs mount is catatonic but the state of an autofs
	 * file system needs to be preserved over restarts.
	 */
	if (sbi->catatonic)
		return -EACCES;

	ino = autofs4_init_ino(ino, sbi, S_IFLNK | 0555);
	if (!ino)
		return -ENOMEM;

	spin_lock(&sbi->lookup_lock);
	if (!list_empty(&ino->active))
		list_del_init(&ino->active);
	spin_unlock(&sbi->lookup_lock);

	ino->size = strlen(symname);
	cp = kmalloc(ino->size + 1, GFP_KERNEL);
	if (!cp) {
		if (!dentry->d_fsdata)
			kfree(ino);
		return -ENOMEM;
	}

	strcpy(cp, symname);

	inode = autofs4_get_inode(dir->i_sb, ino);
	BUG_ON(!ino);

	autofs_clean_ino(ino);

	autofs_del_active(dentry);

	cp = kmalloc(size + 1, GFP_KERNEL);
	if (!cp)
		return -ENOMEM;

	strcpy(cp, symname);

	inode = autofs_get_inode(dir->i_sb, S_IFLNK | 0555);
	if (!inode) {
		kfree(cp);
		return -ENOMEM;
	}
	d_add(dentry, inode);

	if (dir == dir->i_sb->s_root->d_inode)
		dentry->d_op = &autofs4_root_dentry_operations;
	else
		dentry->d_op = &autofs4_dentry_operations;

	dentry->d_fsdata = ino;
	ino->dentry = dget(dentry);
	atomic_inc(&ino->count);
	p_ino = autofs4_dentry_ino(dentry->d_parent);
	if (p_ino && dentry->d_parent != dentry)
		atomic_inc(&p_ino->count);
	ino->inode = inode;

	ino->u.symlink = cp;
	inode->i_private = cp;
	inode->i_size = size;
	d_add(dentry, inode);

	dget(dentry);
	atomic_inc(&ino->count);
	p_ino = autofs_dentry_ino(dentry->d_parent);
	if (p_ino && !IS_ROOT(dentry))
		atomic_inc(&p_ino->count);

	dir->i_mtime = current_time(dir);

	return 0;
}

/*
 * NOTE!
 *
 * Normal filesystems would do a "d_delete()" to tell the VFS dcache
 * that the file no longer exists. However, doing that means that the
 * VFS layer can turn the dentry into a negative dentry, which we
 * obviously do not want (we're dropping the entry not because it
 * doesn't exist, but because it has timed out).
 *
 * Also see autofs_root_rmdir()..
 */
static int autofs_root_unlink(struct inode *dir, struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_dirhash *dh = &sbi->dirhash;
	struct autofs_dir_ent *ent;
	unsigned int n;

	/* This allows root to remove symlinks */
	lock_kernel();
	if (!autofs_oz_mode(sbi) && !capable(CAP_SYS_ADMIN)) {
		unlock_kernel();
		return -EACCES;
	}

	ent = autofs_hash_lookup(dh, &dentry->d_name);
	if (!ent) {
		unlock_kernel();
		return -ENOENT;
	}

	n = ent->ino - AUTOFS_FIRST_SYMLINK;
	if (n >= AUTOFS_MAX_SYMLINKS) {
		unlock_kernel();
		return -EISDIR;	/* It's a directory, dummy */
	}
	if (!test_bit(n,sbi->symlink_bitmap)) {
		unlock_kernel();
		return -EINVAL;	/* Nonexistent symlink?  Shouldn't happen */
	}
	
	dentry->d_time = (unsigned long)(struct autofs_dirhash *)NULL;
	autofs_hash_delete(ent);
	clear_bit(n,sbi->symlink_bitmap);
	kfree(sbi->symlink[n].data);
	d_drop(dentry);
	
	unlock_kernel();
	return 0;
}

static int autofs_root_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_dirhash *dh = &sbi->dirhash;
	struct autofs_dir_ent *ent;

	lock_kernel();
	if (!autofs_oz_mode(sbi)) {
		unlock_kernel();
		return -EACCES;
	}

	ent = autofs_hash_lookup(dh, &dentry->d_name);
	if (!ent) {
		unlock_kernel();
		return -ENOENT;
	}

	if ((unsigned int)ent->ino < AUTOFS_FIRST_DIR_INO) {
		unlock_kernel();
		return -ENOTDIR; /* Not a directory */
	}

	if (ent->dentry != dentry) {
		printk("autofs_rmdir: odentry != dentry for entry %s\n", dentry->d_name.name);
	}

	dentry->d_time = (unsigned long)(struct autofs_dir_ent *)NULL;
	autofs_hash_delete(ent);
	drop_nlink(dir);
	d_drop(dentry);
	unlock_kernel();
 * VFS layer can turn the dentry into a negative dentry.  We don't want
 * this, because the unlink is probably the result of an expire.
 * We simply d_drop it and add it to a expiring list in the super block,
 * which allows the dentry lookup to check for an incomplete expire.
 *
 * If a process is blocked on the dentry waiting for the expire to finish,
 * it will invalidate the dentry and try to mount with a new one.
 *
 * Also see autofs_dir_rmdir()..
 */
static int autofs_dir_unlink(struct inode *dir, struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);
	struct autofs_info *p_ino;

	/* This allows root to remove symlinks */
	if (!autofs4_oz_mode(sbi) && !capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (atomic_dec_and_test(&ino->count)) {
		p_ino = autofs4_dentry_ino(dentry->d_parent);
		if (p_ino && dentry->d_parent != dentry)
		return -EPERM;
	if (!autofs_oz_mode(sbi))
		return -EACCES;

	/* autofs_oz_mode() needs to allow path walks when the
	 * autofs mount is catatonic but the state of an autofs
	 * file system needs to be preserved over restarts.
	 */
	if (sbi->catatonic)
		return -EACCES;

	if (atomic_dec_and_test(&ino->count)) {
		p_ino = autofs_dentry_ino(dentry->d_parent);
		if (p_ino && !IS_ROOT(dentry))
			atomic_dec(&p_ino->count);
	}
	dput(ino->dentry);

	dentry->d_inode->i_size = 0;
	clear_nlink(dentry->d_inode);

	dir->i_mtime = CURRENT_TIME;

	spin_lock(&dcache_lock);
	spin_lock(&sbi->lookup_lock);
	if (list_empty(&ino->expiring))
		list_add(&ino->expiring, &sbi->expiring_list);
	spin_unlock(&sbi->lookup_lock);
	spin_lock(&dentry->d_lock);
	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	d_inode(dentry)->i_size = 0;
	clear_nlink(d_inode(dentry));

	dir->i_mtime = current_time(dir);

	spin_lock(&sbi->lookup_lock);
	__autofs_add_expiring(dentry);
	d_drop(dentry);
	spin_unlock(&sbi->lookup_lock);

	return 0;
}

static int autofs_root_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_dirhash *dh = &sbi->dirhash;
	struct autofs_dir_ent *ent;
	struct inode *inode;
	ino_t ino;

	lock_kernel();
	if (!autofs_oz_mode(sbi)) {
		unlock_kernel();
		return -EACCES;
	}

	ent = autofs_hash_lookup(dh, &dentry->d_name);
	if (ent) {
		unlock_kernel();
		return -EEXIST;
	}

	if (sbi->next_dir_ino < AUTOFS_FIRST_DIR_INO) {
		printk("autofs: Out of inode numbers -- what the heck did you do??\n");
		unlock_kernel();
		return -ENOSPC;
	}
	ino = sbi->next_dir_ino++;

	ent = kmalloc(sizeof(struct autofs_dir_ent), GFP_KERNEL);
	if (!ent) {
		unlock_kernel();
		return -ENOSPC;
	}

	ent->name = kmalloc(dentry->d_name.len+1, GFP_KERNEL);
	if (!ent->name) {
		kfree(ent);
		unlock_kernel();
		return -ENOSPC;
	}

	ent->hash = dentry->d_name.hash;
	memcpy(ent->name, dentry->d_name.name, 1+(ent->len = dentry->d_name.len));
	ent->ino = ino;
	ent->dentry = dentry;
	autofs_hash_insert(dh,ent);

	inc_nlink(dir);

	inode = autofs_iget(dir->i_sb, ino);
	if (IS_ERR(inode)) {
		drop_nlink(dir);
		return PTR_ERR(inode);
	}

	d_instantiate(dentry, inode);
	unlock_kernel();
/*
 * Version 4 of autofs provides a pseudo direct mount implementation
 * that relies on directories at the leaves of a directory tree under
 * an indirect mount to trigger mounts. To allow for this we need to
 * set the DMANAGED_AUTOMOUNT and DMANAGED_TRANSIT flags on the leaves
 * of the directory tree. There is no need to clear the automount flag
 * following a mount or restore it after an expire because these mounts
 * are always covered. However, it is necessary to ensure that these
 * flags are clear on non-empty directories to avoid unnecessary calls
 * during path walks.
 */
static void autofs_set_leaf_automount_flags(struct dentry *dentry)
{
	struct dentry *parent;

	/* root and dentrys in the root are already handled */
	if (IS_ROOT(dentry->d_parent))
		return;

	managed_dentry_set_managed(dentry);

	parent = dentry->d_parent;
	/* only consider parents below dentrys in the root */
	if (IS_ROOT(parent->d_parent))
		return;
	managed_dentry_clear_managed(parent);
}

static void autofs_clear_leaf_automount_flags(struct dentry *dentry)
{
	struct list_head *d_child;
	struct dentry *parent;

	/* flags for dentrys in the root are handled elsewhere */
	if (IS_ROOT(dentry->d_parent))
		return;

	managed_dentry_clear_managed(dentry);

	parent = dentry->d_parent;
	/* only consider parents below dentrys in the root */
	if (IS_ROOT(parent->d_parent))
		return;
	d_child = &dentry->d_child;
	/* Set parent managed if it's becoming empty */
	if (d_child->next == &parent->d_subdirs &&
	    d_child->prev == &parent->d_subdirs)
		managed_dentry_set_managed(parent);
}

static int autofs_dir_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);
	struct autofs_info *p_ino;
	
	DPRINTK("dentry %p, removing %.*s",
		dentry, dentry->d_name.len, dentry->d_name.name);
	DPRINTK("dentry %p, removing %pd", dentry, dentry);

	pr_debug("dentry %p, removing %pd\n", dentry, dentry);

	if (!autofs_oz_mode(sbi))
		return -EACCES;

	/* autofs_oz_mode() needs to allow path walks when the
	 * autofs mount is catatonic but the state of an autofs
	 * file system needs to be preserved over restarts.
	 */
	if (sbi->catatonic)
		return -EACCES;

	spin_lock(&dcache_lock);
	if (!list_empty(&dentry->d_subdirs)) {
		spin_unlock(&dcache_lock);
		return -ENOTEMPTY;
	}
	spin_lock(&sbi->lookup_lock);
	if (list_empty(&ino->expiring))
		list_add(&ino->expiring, &sbi->expiring_list);
	spin_unlock(&sbi->lookup_lock);
	spin_lock(&dentry->d_lock);
	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	spin_lock(&sbi->lookup_lock);
	if (!simple_empty(dentry)) {
		spin_unlock(&sbi->lookup_lock);
		return -ENOTEMPTY;
	}
	__autofs_add_expiring(dentry);
	d_drop(dentry);
	spin_unlock(&sbi->lookup_lock);

	if (sbi->version < 5)
		autofs_clear_leaf_automount_flags(dentry);

	if (atomic_dec_and_test(&ino->count)) {
		p_ino = autofs_dentry_ino(dentry->d_parent);
		if (p_ino && dentry->d_parent != dentry)
			atomic_dec(&p_ino->count);
	}
	dput(ino->dentry);
	dentry->d_inode->i_size = 0;
	clear_nlink(dentry->d_inode);
	d_inode(dentry)->i_size = 0;
	clear_nlink(d_inode(dentry));

	if (dir->i_nlink)
		drop_nlink(dir);

	return 0;
}

static int autofs4_dir_mkdir(struct inode *dir, struct dentry *dentry, int mode)
static int autofs4_dir_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
static int autofs4_dir_mkdir(struct inode *dir,
			     struct dentry *dentry, umode_t mode)
static int autofs_dir_mkdir(struct inode *dir,
			    struct dentry *dentry, umode_t mode)
{
	struct autofs_sb_info *sbi = autofs_sbi(dir->i_sb);
	struct autofs_info *ino = autofs_dentry_ino(dentry);
	struct autofs_info *p_ino;
	struct inode *inode;

	if (!autofs_oz_mode(sbi))
		return -EACCES;

	/* autofs_oz_mode() needs to allow path walks when the
	 * autofs mount is catatonic but the state of an autofs
	 * file system needs to be preserved over restarts.
	 */
	if (sbi->catatonic)
		return -EACCES;

	DPRINTK("dentry %p, creating %.*s",
		dentry, dentry->d_name.len, dentry->d_name.name);

	ino = autofs4_init_ino(ino, sbi, S_IFDIR | 0555);
	if (!ino)
		return -ENOMEM;

	spin_lock(&sbi->lookup_lock);
	if (!list_empty(&ino->active))
		list_del_init(&ino->active);
	spin_unlock(&sbi->lookup_lock);

	inode = autofs4_get_inode(dir->i_sb, ino);
	if (!inode) {
		if (!dentry->d_fsdata)
			kfree(ino);
		return -ENOMEM;
	}
	d_add(dentry, inode);

	if (dir == dir->i_sb->s_root->d_inode)
		dentry->d_op = &autofs4_root_dentry_operations;
	else
		dentry->d_op = &autofs4_dentry_operations;

	dentry->d_fsdata = ino;
	ino->dentry = dget(dentry);
	atomic_inc(&ino->count);
	p_ino = autofs4_dentry_ino(dentry->d_parent);
	if (p_ino && dentry->d_parent != dentry)
		atomic_inc(&p_ino->count);
	ino->inode = inode;
	DPRINTK("dentry %p, creating %pd", dentry, dentry);
	pr_debug("dentry %p, creating %pd\n", dentry, dentry);

	BUG_ON(!ino);

	autofs_clean_ino(ino);

	autofs_del_active(dentry);

	inode = autofs_get_inode(dir->i_sb, S_IFDIR | mode);
	if (!inode)
		return -ENOMEM;
	d_add(dentry, inode);

	if (sbi->version < 5)
		autofs_set_leaf_automount_flags(dentry);

	dget(dentry);
	atomic_inc(&ino->count);
	p_ino = autofs_dentry_ino(dentry->d_parent);
	if (p_ino && !IS_ROOT(dentry))
		atomic_inc(&p_ino->count);
	inc_nlink(dir);
	dir->i_mtime = current_time(dir);

	return 0;
}

/* Get/set timeout ioctl() operation */
static inline int autofs_get_set_timeout(struct autofs_sb_info *sbi,
					 unsigned long __user *p)
{
	unsigned long ntimeout;

	if (get_user(ntimeout, p) ||
	    put_user(sbi->exp_timeout / HZ, p))
		return -EFAULT;
#ifdef CONFIG_COMPAT
static inline int autofs_compat_get_set_timeout(struct autofs_sb_info *sbi,
						 compat_ulong_t __user *p)
{
	unsigned long ntimeout;
	int rv;

	rv = get_user(ntimeout, p);
	if (rv)
		goto error;

	rv = put_user(sbi->exp_timeout/HZ, p);
	if (rv)
		goto error;

	if (ntimeout > UINT_MAX/HZ)
		sbi->exp_timeout = 0;
	else
		sbi->exp_timeout = ntimeout * HZ;

	return 0;
error:
	return rv;
}
#endif

static inline int autofs_get_set_timeout(struct autofs_sb_info *sbi,
					  unsigned long __user *p)
{
	unsigned long ntimeout;
	int rv;

	rv = get_user(ntimeout, p);
	if (rv)
		goto error;

	rv = put_user(sbi->exp_timeout/HZ, p);
	if (rv)
		goto error;

	if (ntimeout > ULONG_MAX/HZ)
		sbi->exp_timeout = 0;
	else
		sbi->exp_timeout = ntimeout * HZ;

	return 0;
}

/* Return protocol version */
static inline int autofs_get_protover(int __user *p)
{
	return put_user(AUTOFS_PROTO_VERSION, p);
}

/* Perform an expiry operation */
static inline int autofs_expire_run(struct super_block *sb,
				    struct autofs_sb_info *sbi,
				    struct vfsmount *mnt,
				    struct autofs_packet_expire __user *pkt_p)
{
	struct autofs_dir_ent *ent;
	struct autofs_packet_expire pkt;

	memset(&pkt,0,sizeof pkt);

	pkt.hdr.proto_version = AUTOFS_PROTO_VERSION;
	pkt.hdr.type = autofs_ptype_expire;

	if (!sbi->exp_timeout || !(ent = autofs_expire(sb,sbi,mnt)))
		return -EAGAIN;

	pkt.len = ent->len;
	memcpy(pkt.name, ent->name, pkt.len);
	pkt.name[pkt.len] = '\0';

	if (copy_to_user(pkt_p, &pkt, sizeof(struct autofs_packet_expire)))
		return -EFAULT;

	return 0;
error:
	return rv;
}

/* Return protocol version */
static inline int autofs_get_protover(struct autofs_sb_info *sbi,
				       int __user *p)
{
	return put_user(sbi->version, p);
}

/* Return protocol sub version */
static inline int autofs_get_protosubver(struct autofs_sb_info *sbi,
					  int __user *p)
{
	return put_user(sbi->sub_version, p);
}

/*
* Tells the daemon whether it can umount the autofs mount.
*/
static inline int autofs_ask_umount(struct vfsmount *mnt, int __user *p)
{
	int status = 0;

	if (may_umount(mnt))
		status = 1;

	pr_debug("may umount %d\n", status);

	status = put_user(status, p);

	return status;
}

/* Identify autofs_dentries - this is so we can tell if there's
 * an extra dentry refcount or not.  We only hold a refcount on the
 * dentry if its non-negative (ie, d_inode != NULL)
 */
int is_autofs_dentry(struct dentry *dentry)
{
	return dentry && dentry->d_inode &&
		(dentry->d_op == &autofs4_root_dentry_operations ||
		 dentry->d_op == &autofs4_dentry_operations) &&
	return dentry && d_really_is_positive(dentry) &&
		dentry->d_op == &autofs_dentry_operations &&
		dentry->d_fsdata != NULL;
}

/*
 * ioctl()'s on the root directory is the chief method for the daemon to
 * generate kernel reactions
 */
static int autofs_root_ioctl(struct inode *inode, struct file *filp,
			     unsigned int cmd, unsigned long arg)
{
	struct autofs_sb_info *sbi = autofs_sbi(inode->i_sb);
	void __user *argp = (void __user *)arg;

	DPRINTK(("autofs_ioctl: cmd = 0x%08x, arg = 0x%08lx, sbi = %p, pgrp = %u\n",cmd,arg,sbi,task_pgrp_nr(current)));
static int autofs4_root_ioctl(struct inode *inode, struct file *filp,
			     unsigned int cmd, unsigned long arg)
static int autofs4_root_ioctl_unlocked(struct inode *inode, struct file *filp,
static int autofs_root_ioctl_unlocked(struct inode *inode, struct file *filp,
				       unsigned int cmd, unsigned long arg)
{
	struct autofs_sb_info *sbi = autofs_sbi(inode->i_sb);
	void __user *p = (void __user *)arg;

	pr_debug("cmd = 0x%08x, arg = 0x%08lx, sbi = %p, pgrp = %u\n",
		 cmd, arg, sbi, task_pgrp_nr(current));

	if (_IOC_TYPE(cmd) != _IOC_TYPE(AUTOFS_IOC_FIRST) ||
	     _IOC_NR(cmd) - _IOC_NR(AUTOFS_IOC_FIRST) >= AUTOFS_IOC_COUNT)
		return -ENOTTY;
	
	if (!autofs_oz_mode(sbi) && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	
	switch(cmd) {
	case AUTOFS_IOC_READY:	/* Wait queue: go ahead and retry */
		return autofs_wait_release(sbi,(autofs_wqt_t)arg,0);
	case AUTOFS_IOC_FAIL:	/* Wait queue: fail with ENOENT */
		return autofs_wait_release(sbi,(autofs_wqt_t)arg,-ENOENT);

	if (!autofs_oz_mode(sbi) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (cmd) {
	case AUTOFS_IOC_READY:	/* Wait queue: go ahead and retry */
		return autofs_wait_release(sbi, (autofs_wqt_t) arg, 0);
	case AUTOFS_IOC_FAIL:	/* Wait queue: fail with ENOENT */
		return autofs_wait_release(sbi, (autofs_wqt_t) arg, -ENOENT);
	case AUTOFS_IOC_CATATONIC: /* Enter catatonic mode (daemon shutdown) */
		autofs_catatonic_mode(sbi);
		return 0;
	case AUTOFS_IOC_PROTOVER: /* Get protocol version */
		return autofs_get_protover(argp);
	case AUTOFS_IOC_SETTIMEOUT:
		return autofs_get_set_timeout(sbi, argp);
	case AUTOFS_IOC_EXPIRE:
		return autofs_expire_run(inode->i_sb, sbi, filp->f_path.mnt,
					 argp);
	default:
		return -ENOSYS;
	}
}
		return autofs_get_protover(sbi, p);
	case AUTOFS_IOC_PROTOSUBVER: /* Get protocol sub version */
		return autofs_get_protosubver(sbi, p);
	case AUTOFS_IOC_SETTIMEOUT:
		return autofs_get_set_timeout(sbi, p);
#ifdef CONFIG_COMPAT
	case AUTOFS_IOC_SETTIMEOUT32:
		return autofs_compat_get_set_timeout(sbi, p);
#endif

	case AUTOFS_IOC_ASKUMOUNT:
		return autofs_ask_umount(filp->f_path.mnt, p);

	/* return a single thing to expire */
	case AUTOFS_IOC_EXPIRE:
		return autofs_expire_run(inode->i_sb, filp->f_path.mnt, sbi, p);
	/* same as above, but can send multiple expires through pipe */
	case AUTOFS_IOC_EXPIRE_MULTI:
		return autofs_expire_multi(inode->i_sb,
					   filp->f_path.mnt, sbi, p);

	default:
		return -EINVAL;
	}
}

static long autofs_root_ioctl(struct file *filp,
			       unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	return autofs_root_ioctl_unlocked(inode, filp, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long autofs_root_compat_ioctl(struct file *filp,
				      unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (cmd == AUTOFS_IOC_READY || cmd == AUTOFS_IOC_FAIL)
		ret = autofs_root_ioctl_unlocked(inode, filp, cmd, arg);
	else
		ret = autofs_root_ioctl_unlocked(inode, filp, cmd,
					      (unsigned long) compat_ptr(arg));

	return ret;
}
#endif
