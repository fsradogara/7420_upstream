/*
 * Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
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
{
	struct autofs_sb_info *sbi;
	struct autofs_info *ino;

	if (!dentry)
		return ERR_PTR(-ECHILD);
	sbi = autofs4_sbi(dentry->d_sb);
	ino = autofs4_dentry_ino(dentry);
	if (ino && !autofs4_oz_mode(sbi))
		ino->last_used = jiffies;
	return d_inode(dentry)->i_private;
}

const struct inode_operations autofs4_symlink_inode_operations = {
	.get_link	= autofs4_get_link
};
