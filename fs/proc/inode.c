// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/proc/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/cache.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/completion.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/sysctl.h>

#include <asm/system.h>
#include <linux/sysctl.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/magic.h>

#include <linux/uaccess.h>

#include "internal.h"

struct proc_dir_entry *de_get(struct proc_dir_entry *de)
{
	atomic_inc(&de->count);
	return de;
}

/*
 * Decrements the use count and checks for deferred deletion.
 */
void de_put(struct proc_dir_entry *de)
{
	lock_kernel();
	if (!atomic_read(&de->count)) {
		printk("de_put: entry %s already free!\n", de->name);
		unlock_kernel();
		return;
	}

	if (atomic_dec_and_test(&de->count))
		free_proc_entry(de);
	unlock_kernel();
}

/*
 * Decrement the use count of the proc_dir_entry.
 */
static void proc_delete_inode(struct inode *inode)
{
	struct proc_dir_entry *de;

	truncate_inode_pages(&inode->i_data, 0);
static void proc_evict_inode(struct inode *inode)
{
	struct proc_dir_entry *de;
	struct ctl_table_header *head;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	/* Stop tracking associated processes */
	put_pid(PROC_I(inode)->pid);

	/* Let go of any associated proc directory entry */
	de = PROC_I(inode)->pde;
	if (de) {
		if (de->owner)
			module_put(de->owner);
		de_put(de);
	}
	if (PROC_I(inode)->sysctl)
		sysctl_head_put(PROC_I(inode)->sysctl);
	clear_inode(inode);
}

struct vfsmount *proc_mnt;

	de = PDE(inode);
	if (de)
		pde_put(de);

	head = PROC_I(inode)->sysctl;
	if (head) {
		RCU_INIT_POINTER(PROC_I(inode)->sysctl, NULL);
		proc_sys_evict_inode(inode, head);
	}
}

static struct kmem_cache *proc_inode_cachep __ro_after_init;
static struct kmem_cache *pde_opener_cache __ro_after_init;

static struct inode *proc_alloc_inode(struct super_block *sb)
{
	struct proc_inode *ei;
	struct inode *inode;

	ei = kmem_cache_alloc(proc_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	ei->pid = NULL;
	ei->fd = 0;
	ei->op.proc_get_link = NULL;
	ei->pde = NULL;
	ei->sysctl = NULL;
	ei->sysctl_entry = NULL;
	ei->ns_ops = NULL;
	inode = &ei->vfs_inode;
	return inode;
}

static void proc_destroy_inode(struct inode *inode)
{
	kmem_cache_free(proc_inode_cachep, PROC_I(inode));
static void proc_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(proc_inode_cachep, PROC_I(inode));
}

static void proc_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, proc_i_callback);
}

static void init_once(void *foo)
{
	struct proc_inode *ei = (struct proc_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

int __init proc_init_inodecache(void)
void __init proc_init_inodecache(void)
void __init proc_init_kmemcache(void)
{
	proc_inode_cachep = kmem_cache_create("proc_inode_cache",
					     sizeof(struct proc_inode),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD|SLAB_ACCOUNT|
						SLAB_PANIC),
					     init_once);
	pde_opener_cache =
		kmem_cache_create("pde_opener", sizeof(struct pde_opener), 0,
				  SLAB_ACCOUNT|SLAB_PANIC, NULL);
	proc_dir_entry_cache = kmem_cache_create_usercopy(
		"proc_dir_entry", SIZEOF_PDE, 0, SLAB_PANIC,
		offsetof(struct proc_dir_entry, inline_name),
		SIZEOF_PDE_INLINE_NAME, NULL);
	BUILD_BUG_ON(sizeof(struct proc_dir_entry) >= SIZEOF_PDE);
}

static int proc_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct pid_namespace *pid = sb->s_fs_info;

	if (!gid_eq(pid->pid_gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u", from_kgid_munged(&init_user_ns, pid->pid_gid));
	if (pid->hide_pid != HIDEPID_OFF)
		seq_printf(seq, ",hidepid=%u", pid->hide_pid);

	return 0;
}

static const struct super_operations proc_sops = {
	.alloc_inode	= proc_alloc_inode,
	.destroy_inode	= proc_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.delete_inode	= proc_delete_inode,
	.statfs		= simple_statfs,
};

static void __pde_users_dec(struct proc_dir_entry *pde)
{
	pde->pde_users--;
	if (pde->pde_unload_completion && pde->pde_users == 0)
		complete(pde->pde_unload_completion);
}

static void pde_users_dec(struct proc_dir_entry *pde)
{
	spin_lock(&pde->pde_unload_lock);
	__pde_users_dec(pde);
	spin_unlock(&pde->pde_unload_lock);
	.evict_inode	= proc_evict_inode,
	.statfs		= simple_statfs,
	.remount_fs	= proc_remount,
	.show_options	= proc_show_options,
};

enum {BIAS = -1U<<31};

static inline int use_pde(struct proc_dir_entry *pde)
{
	return likely(atomic_inc_unless_negative(&pde->in_use));
}

static void unuse_pde(struct proc_dir_entry *pde)
{
	if (unlikely(atomic_dec_return(&pde->in_use) == BIAS))
		complete(pde->pde_unload_completion);
}

/* pde is locked on entry, unlocked on exit */
static void close_pdeo(struct proc_dir_entry *pde, struct pde_opener *pdeo)
{
	/*
	 * close() (proc_reg_release()) can't delete an entry and proceed:
	 * ->release hook needs to be available at the right moment.
	 *
	 * rmmod (remove_proc_entry() et al) can't delete an entry and proceed:
	 * "struct file" needs to be available at the right moment.
	 *
	 * Therefore, first process to enter this function does ->release() and
	 * signals its completion to the other process which does nothing.
	 */
	if (pdeo->closing) {
		/* somebody else is doing that, just wait */
		DECLARE_COMPLETION_ONSTACK(c);
		pdeo->c = &c;
		spin_unlock(&pde->pde_unload_lock);
		wait_for_completion(&c);
	} else {
		struct file *file;
		struct completion *c;

		pdeo->closing = true;
		spin_unlock(&pde->pde_unload_lock);
		file = pdeo->file;
		pde->proc_fops->release(file_inode(file), file);
		spin_lock(&pde->pde_unload_lock);
		/* After ->release. */
		list_del(&pdeo->lh);
		c = pdeo->c;
		spin_unlock(&pde->pde_unload_lock);
		if (unlikely(c))
			complete(c);
		kmem_cache_free(pde_opener_cache, pdeo);
	}
}

void proc_entry_rundown(struct proc_dir_entry *de)
{
	DECLARE_COMPLETION_ONSTACK(c);
	/* Wait until all existing callers into module are done. */
	de->pde_unload_completion = &c;
	if (atomic_add_return(BIAS, &de->in_use) != BIAS)
		wait_for_completion(&c);

	/* ->pde_openers list can't grow from now on. */

	spin_lock(&de->pde_unload_lock);
	while (!list_empty(&de->pde_openers)) {
		struct pde_opener *pdeo;
		pdeo = list_first_entry(&de->pde_openers, struct pde_opener, lh);
		close_pdeo(de, pdeo);
		spin_lock(&de->pde_unload_lock);
	}
	spin_unlock(&de->pde_unload_lock);
}

static loff_t proc_reg_llseek(struct file *file, loff_t offset, int whence)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	loff_t rv = -EINVAL;
	loff_t (*llseek)(struct file *, loff_t, int);

	spin_lock(&pde->pde_unload_lock);
	/*
	 * remove_proc_entry() is going to delete PDE (as part of module
	 * cleanup sequence). No new callers into module allowed.
	 */
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	/*
	 * Bump refcount so that remove_proc_entry will wail for ->llseek to
	 * complete.
	 */
	pde->pde_users++;
	/*
	 * Save function pointer under lock, to protect against ->proc_fops
	 * NULL'ifying right after ->pde_unload_lock is dropped.
	 */
	llseek = pde->proc_fops->llseek;
	spin_unlock(&pde->pde_unload_lock);

	if (!llseek)
		llseek = default_llseek;
	rv = llseek(file, offset, whence);

	pde_users_dec(pde);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	loff_t rv = -EINVAL;
	if (use_pde(pde)) {
		loff_t (*llseek)(struct file *, loff_t, int);
		llseek = pde->proc_fops->llseek;
		if (!llseek)
			llseek = default_llseek;
		rv = llseek(file, offset, whence);
		unuse_pde(pde);
	}
	return rv;
}

static ssize_t proc_reg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	ssize_t rv = -EIO;
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	read = pde->proc_fops->read;
	spin_unlock(&pde->pde_unload_lock);

	if (read)
		rv = read(file, buf, count, ppos);

	pde_users_dec(pde);
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv = -EIO;
	if (use_pde(pde)) {
		read = pde->proc_fops->read;
		if (read)
			rv = read(file, buf, count, ppos);
		unuse_pde(pde);
	}
	return rv;
}

static ssize_t proc_reg_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	ssize_t rv = -EIO;
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	write = pde->proc_fops->write;
	spin_unlock(&pde->pde_unload_lock);

	if (write)
		rv = write(file, buf, count, ppos);

	pde_users_dec(pde);
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv = -EIO;
	if (use_pde(pde)) {
		write = pde->proc_fops->write;
		if (write)
			rv = write(file, buf, count, ppos);
		unuse_pde(pde);
	}
	return rv;
}

static __poll_t proc_reg_poll(struct file *file, struct poll_table_struct *pts)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	unsigned int rv = DEFAULT_POLLMASK;
	unsigned int (*poll)(struct file *, struct poll_table_struct *);

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	poll = pde->proc_fops->poll;
	spin_unlock(&pde->pde_unload_lock);

	if (poll)
		rv = poll(file, pts);

	pde_users_dec(pde);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	__poll_t rv = DEFAULT_POLLMASK;
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	if (use_pde(pde)) {
		poll = pde->proc_fops->poll;
		if (poll)
			rv = poll(file, pts);
		unuse_pde(pde);
	}
	return rv;
}

static long proc_reg_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	long rv = -ENOTTY;
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	int (*ioctl)(struct inode *, struct file *, unsigned int, unsigned long);

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	unlocked_ioctl = pde->proc_fops->unlocked_ioctl;
	ioctl = pde->proc_fops->ioctl;
	spin_unlock(&pde->pde_unload_lock);

	if (unlocked_ioctl) {
		rv = unlocked_ioctl(file, cmd, arg);
		if (rv == -ENOIOCTLCMD)
			rv = -EINVAL;
	} else if (ioctl) {
		lock_kernel();
		rv = ioctl(file->f_path.dentry->d_inode, file, cmd, arg);
		unlock_kernel();
	}

	pde_users_dec(pde);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	long rv = -ENOTTY;
	long (*ioctl)(struct file *, unsigned int, unsigned long);
	if (use_pde(pde)) {
		ioctl = pde->proc_fops->unlocked_ioctl;
		if (ioctl)
			rv = ioctl(file, cmd, arg);
		unuse_pde(pde);
	}
	return rv;
}

#ifdef CONFIG_COMPAT
static long proc_reg_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	long rv = -ENOTTY;
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	compat_ioctl = pde->proc_fops->compat_ioctl;
	spin_unlock(&pde->pde_unload_lock);

	if (compat_ioctl)
		rv = compat_ioctl(file, cmd, arg);

	pde_users_dec(pde);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	long rv = -ENOTTY;
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	if (use_pde(pde)) {
		compat_ioctl = pde->proc_fops->compat_ioctl;
		if (compat_ioctl)
			rv = compat_ioctl(file, cmd, arg);
		unuse_pde(pde);
	}
	return rv;
}
#endif

static int proc_reg_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	int rv = -EIO;
	int (*mmap)(struct file *, struct vm_area_struct *);

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	mmap = pde->proc_fops->mmap;
	spin_unlock(&pde->pde_unload_lock);

	if (mmap)
		rv = mmap(file, vma);

	pde_users_dec(pde);
	struct proc_dir_entry *pde = PDE(file_inode(file));
	int rv = -EIO;
	int (*mmap)(struct file *, struct vm_area_struct *);
	if (use_pde(pde)) {
		mmap = pde->proc_fops->mmap;
		if (mmap)
			rv = mmap(file, vma);
		unuse_pde(pde);
	}
	return rv;
}

static unsigned long
proc_reg_get_unmapped_area(struct file *file, unsigned long orig_addr,
			   unsigned long len, unsigned long pgoff,
			   unsigned long flags)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	unsigned long rv = -EIO;

	if (use_pde(pde)) {
		typeof(proc_reg_get_unmapped_area) *get_area;

		get_area = pde->proc_fops->get_unmapped_area;
#ifdef CONFIG_MMU
		if (!get_area)
			get_area = current->mm->get_unmapped_area;
#endif

		if (get_area)
			rv = get_area(file, orig_addr, len, pgoff, flags);
		else
			rv = orig_addr;
		unuse_pde(pde);
	}
	return rv;
}

static int proc_reg_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	int rv = 0;
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct file *);
	struct pde_opener *pdeo;

	/*
	 * Ensure that
	 * 1) PDE's ->release hook will be called no matter what
	 *    either normally by close()/->release, or forcefully by
	 *    rmmod/remove_proc_entry.
	 *
	 * 2) rmmod isn't blocked by opening file in /proc and sitting on
	 *    the descriptor (including "rmmod foo </proc/foo" scenario).
	 *
	 * Save every "struct file" with custom ->release hook.
	 */
	pdeo = kmalloc(sizeof(struct pde_opener), GFP_KERNEL);
	if (!pdeo)
		return -ENOMEM;

	spin_lock(&pde->pde_unload_lock);
	if (!pde->proc_fops) {
		spin_unlock(&pde->pde_unload_lock);
		kfree(pdeo);
		return rv;
	}
	pde->pde_users++;
	open = pde->proc_fops->open;
	release = pde->proc_fops->release;
	spin_unlock(&pde->pde_unload_lock);
	pdeo = kzalloc(sizeof(struct pde_opener), GFP_KERNEL);
	if (!pdeo)
		return -ENOMEM;

	if (!use_pde(pde)) {
		kfree(pdeo);
	if (!use_pde(pde))
		return -ENOENT;

	release = pde->proc_fops->release;
	if (release) {
		pdeo = kmem_cache_alloc(pde_opener_cache, GFP_KERNEL);
		if (!pdeo) {
			rv = -ENOMEM;
			goto out_unuse;
		}
	}

	open = pde->proc_fops->open;
	if (open)
		rv = open(inode, file);

	spin_lock(&pde->pde_unload_lock);
	if (rv == 0 && release) {
		/* To know what to release. */
		pdeo->inode = inode;
		pdeo->file = file;
		/* Strictly for "too late" ->release in proc_reg_release(). */
		pdeo->release = release;
		list_add(&pdeo->lh, &pde->pde_openers);
	} else
		kfree(pdeo);
	__pde_users_dec(pde);
	spin_unlock(&pde->pde_unload_lock);
	return rv;
}

static struct pde_opener *find_pde_opener(struct proc_dir_entry *pde,
					struct inode *inode, struct file *file)
{
	struct pde_opener *pdeo;

	list_for_each_entry(pdeo, &pde->pde_openers, lh) {
		if (pdeo->inode == inode && pdeo->file == file)
			return pdeo;
	}
	return NULL;
}

static int proc_reg_release(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	int rv = 0;
	int (*release)(struct inode *, struct file *);
	struct pde_opener *pdeo;

	spin_lock(&pde->pde_unload_lock);
	pdeo = find_pde_opener(pde, inode, file);
	if (!pde->proc_fops) {
		/*
		 * Can't simply exit, __fput() will think that everything is OK,
		 * and move on to freeing struct file. remove_proc_entry() will
		 * find slacker in opener's list and will try to do non-trivial
		 * things with struct file. Therefore, remove opener from list.
		 *
		 * But if opener is removed from list, who will ->release it?
		 */
		if (pdeo) {
			list_del(&pdeo->lh);
			spin_unlock(&pde->pde_unload_lock);
			rv = pdeo->release(inode, file);
			kfree(pdeo);
		} else
			spin_unlock(&pde->pde_unload_lock);
		return rv;
	}
	pde->pde_users++;
	release = pde->proc_fops->release;
	if (pdeo) {
		list_del(&pdeo->lh);
		kfree(pdeo);
	}
	spin_unlock(&pde->pde_unload_lock);

	if (release)
		rv = release(inode, file);

	pde_users_dec(pde);
	return rv;
	if (rv == 0 && release) {
		/* To know what to release. */
		pdeo->file = file;
		pdeo->closing = false;
		pdeo->c = NULL;
		spin_lock(&pde->pde_unload_lock);
		list_add(&pdeo->lh, &pde->pde_openers);
		spin_unlock(&pde->pde_unload_lock);
	} else
		kfree(pdeo);
	if (release) {
		if (rv == 0) {
			/* To know what to release. */
			pdeo->file = file;
			pdeo->closing = false;
			pdeo->c = NULL;
			spin_lock(&pde->pde_unload_lock);
			list_add(&pdeo->lh, &pde->pde_openers);
			spin_unlock(&pde->pde_unload_lock);
		} else
			kmem_cache_free(pde_opener_cache, pdeo);
	}

out_unuse:
	unuse_pde(pde);
	return rv;
}

static int proc_reg_release(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	struct pde_opener *pdeo;
	spin_lock(&pde->pde_unload_lock);
	list_for_each_entry(pdeo, &pde->pde_openers, lh) {
		if (pdeo->file == file) {
			close_pdeo(pde, pdeo);
			return 0;
		}
	}
	spin_unlock(&pde->pde_unload_lock);
	return 0;
}

static const struct file_operations proc_reg_file_ops = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write		= proc_reg_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= proc_reg_compat_ioctl,
#endif
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};

#ifdef CONFIG_COMPAT
static const struct file_operations proc_reg_file_ops_no_compat = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write		= proc_reg_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};
#endif

struct inode *proc_get_inode(struct super_block *sb, unsigned int ino,
				struct proc_dir_entry *de)
{
	struct inode * inode;

	if (!try_module_get(de->owner))
		goto out_mod;

	inode = iget_locked(sb, ino);
	if (!inode)
		goto out_ino;
	if (inode->i_state & I_NEW) {
		inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
		PROC_I(inode)->fd = 0;
		PROC_I(inode)->pde = de;

static const char *proc_follow_link(struct dentry *dentry, void **cookie)
{
	struct proc_dir_entry *pde = PDE(d_inode(dentry));
	if (unlikely(!use_pde(pde)))
		return ERR_PTR(-EINVAL);
	*cookie = pde;
	return pde->data;
}

static void proc_put_link(struct inode *unused, void *p)
static void proc_put_link(void *p)
{
	unuse_pde(p);
}

static const char *proc_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct proc_dir_entry *pde = PDE(inode);
	if (!use_pde(pde))
		return ERR_PTR(-EINVAL);
	set_delayed_call(done, proc_put_link, pde);
	return pde->data;
}

const struct inode_operations proc_link_inode_operations = {
	.get_link	= proc_get_link,
};

struct inode *proc_get_inode(struct super_block *sb, struct proc_dir_entry *de)
{
	struct inode *inode = new_inode_pseudo(sb);

	if (inode) {
		inode->i_ino = de->low_ino;
		inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
		PROC_I(inode)->pde = de;

		if (is_empty_pde(de)) {
			make_empty_dir_inode(inode);
			return inode;
		}
		if (de->mode) {
			inode->i_mode = de->mode;
			inode->i_uid = de->uid;
			inode->i_gid = de->gid;
		}
		if (de->size)
			inode->i_size = de->size;
		if (de->nlink)
			inode->i_nlink = de->nlink;
		if (de->proc_iops)
			inode->i_op = de->proc_iops;
			set_nlink(inode, de->nlink);
		WARN_ON(!de->proc_iops);
		inode->i_op = de->proc_iops;
		if (de->proc_fops) {
			if (S_ISREG(inode->i_mode)) {
#ifdef CONFIG_COMPAT
				if (!de->proc_fops->compat_ioctl)
					inode->i_fop =
						&proc_reg_file_ops_no_compat;
				else
#endif
					inode->i_fop = &proc_reg_file_ops;
			} else {
				inode->i_fop = de->proc_fops;
			}
		}
		unlock_new_inode(inode);
	} else
	       module_put(de->owner);
	return inode;

out_ino:
	module_put(de->owner);
out_mod:
	return NULL;
}			

int proc_fill_super(struct super_block *s)
{
	struct inode * root_inode;
	} else
	       pde_put(de);
	return inode;
}

int proc_fill_super(struct super_block *s, void *data, int silent)
{
	struct pid_namespace *ns = get_pid_ns(s->s_fs_info);
	struct inode *root_inode;
	int ret;

	if (!proc_parse_options(data, ns))
		return -EINVAL;

	/* User space would break if executables or devices appear on proc */
	s->s_iflags |= SB_I_USERNS_VISIBLE | SB_I_NOEXEC | SB_I_NODEV;
	s->s_flags |= SB_NODIRATIME | SB_NOSUID | SB_NOEXEC;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = PROC_SUPER_MAGIC;
	s->s_op = &proc_sops;
	s->s_time_gran = 1;

	/*
	 * procfs isn't actually a stacking filesystem; however, there is
	 * too much magic going on inside it to permit stacking things on
	 * top of it
	 */
	s->s_stack_depth = FILESYSTEM_MAX_STACK_DEPTH;
	
	de_get(&proc_root);
	root_inode = proc_get_inode(s, PROC_ROOT_INO, &proc_root);
	if (!root_inode)
		goto out_no_root;
	root_inode->i_uid = 0;
	root_inode->i_gid = 0;
	s->s_root = d_alloc_root(root_inode);
	if (!s->s_root)
		goto out_no_root;
	return 0;

out_no_root:
	printk("proc_read_super: get root inode failed\n");
	iput(root_inode);
	de_put(&proc_root);
	return -ENOMEM;
	pde_get(&proc_root);
	root_inode = proc_get_inode(s, &proc_root);
	if (!root_inode) {
		pr_err("proc_fill_super: get root inode failed\n");
		return -ENOMEM;
	}

	s->s_root = d_make_root(root_inode);
	if (!s->s_root) {
		pr_err("proc_fill_super: allocate dentry failed\n");
		return -ENOMEM;
	}

	ret = proc_setup_self(s);
	if (ret) {
		return ret;
	}
	return proc_setup_thread_self(s);
}
