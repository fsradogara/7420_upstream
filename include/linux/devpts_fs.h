/* -*- linux-c -*- --------------------------------------------------------- *
 *
 * linux/include/linux/devpts_fs.h
 *
 *  Copyright 1998-2004 H. Peter Anvin -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#ifndef _LINUX_DEVPTS_FS_H
#define _LINUX_DEVPTS_FS_H

#include <linux/errno.h>

#ifdef CONFIG_UNIX98_PTYS

int devpts_new_index(void);
void devpts_kill_index(int idx);
int devpts_pty_new(struct tty_struct *tty);      /* mknod in devpts */
struct tty_struct *devpts_get_tty(int number);	 /* get tty structure */
void devpts_pty_kill(int number);		 /* unlink */
int devpts_new_index(struct inode *ptmx_inode);
void devpts_kill_index(struct inode *ptmx_inode, int idx);
struct pts_fs_info;

struct vfsmount *devpts_mntget(struct file *, struct pts_fs_info *);
struct pts_fs_info *devpts_acquire(struct file *);
void devpts_release(struct pts_fs_info *);

int devpts_new_index(struct pts_fs_info *);
void devpts_kill_index(struct pts_fs_info *, int);

/* mknod in devpts */
struct dentry *devpts_pty_new(struct pts_fs_info *, int, void *);
/* get private structure */
void *devpts_get_priv(struct dentry *);
/* unlink */
void devpts_pty_kill(struct dentry *);

/* in pty.c */
int ptm_open_peer(struct file *master, struct tty_struct *tty, int flags);

#else

/* Dummy stubs in the no-pty case */
static inline int devpts_new_index(void) { return -EINVAL; }
static inline void devpts_kill_index(int idx) { }
static inline int devpts_pty_new(struct tty_struct *tty) { return -EINVAL; }
static inline struct tty_struct *devpts_get_tty(int number) { return NULL; }
static inline void devpts_pty_kill(int number) { }
static inline int devpts_new_index(struct inode *ptmx_inode) { return -EINVAL; }
static inline void devpts_kill_index(struct inode *ptmx_inode, int idx) { }
static inline struct inode *devpts_pty_new(struct inode *ptmx_inode,
		dev_t device, int index, void *priv)
static inline int
ptm_open_peer(struct file *master, struct tty_struct *tty, int flags)
{
	return -EIO;
}
#endif


#endif /* _LINUX_DEVPTS_FS_H */
