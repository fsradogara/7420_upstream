/* -*- linux-c -*- --------------------------------------------------------- *
 *
 * linux/fs/autofs/symlink.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
/*
 * Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include "autofs_i.h"

/* Nothing to release.. */
static void *autofs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *s=((struct autofs_symlink *)dentry->d_inode->i_private)->data;
	nd_set_link(nd, s);
	return NULL;
}

const struct inode_operations autofs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= autofs_follow_link
 */

#include "autofs_i.h"

static void *autofs4_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	nd_set_link(nd, (char *)ino->u.symlink);
	return NULL;
static const char *autofs4_follow_link(struct dentry *dentry, void **cookie)
static const char *autofs4_get_link(struct dentry *dentry,
				    struct inode *inode,
				    struct delayed_call *done)
static const char *autofs_get_link(struct dentry *dentry,
				   struct inode *inode,
				   struct delayed_call *done)
{
	struct autofs_sb_info *sbi;
	struct autofs_info *ino;

	if (!dentry)
		return ERR_PTR(-ECHILD);
	sbi = autofs_sbi(dentry->d_sb);
	ino = autofs_dentry_ino(dentry);
	if (ino && !autofs_oz_mode(sbi))
		ino->last_used = jiffies;
	return d_inode(dentry)->i_private;
}

const struct inode_operations autofs_symlink_inode_operations = {
	.get_link	= autofs_get_link
};
