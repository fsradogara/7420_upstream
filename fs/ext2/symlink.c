// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 symlink handling code
 */

#include "ext2.h"
#include "xattr.h"
#include <linux/namei.h>

static void *ext2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ext2_inode_info *ei = EXT2_I(dentry->d_inode);
	nd_set_link(nd, (char *)ei->i_data);
	return NULL;
}

const struct inode_operations ext2_symlink_inode_operations = {
	.get_link	= page_get_link,
	.setattr	= ext2_setattr,
#ifdef CONFIG_EXT2_FS_XATTR
	.listxattr	= ext2_listxattr,
#endif
};
 
const struct inode_operations ext2_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext2_follow_link,
	.follow_link	= simple_follow_link,
	.get_link	= simple_get_link,
	.setattr	= ext2_setattr,
#ifdef CONFIG_EXT2_FS_XATTR
	.listxattr	= ext2_listxattr,
#endif
};
