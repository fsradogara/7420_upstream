// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext2/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include "ext2.h"
#include <linux/security.h>
#include "xattr.h"

static size_t
ext2_xattr_security_list(struct inode *inode, char *list, size_t list_size,
ext2_xattr_security_list(const struct xattr_handler *handler,
			 struct dentry *dentry, char *list, size_t list_size,
			 const char *name, size_t name_len)
{
	const int prefix_len = XATTR_SECURITY_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;

	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
ext2_xattr_security_get(struct inode *inode, const char *name,
		       void *buffer, size_t size)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext2_xattr_get(inode, EXT2_XATTR_INDEX_SECURITY, name,
ext2_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return ext2_xattr_get(inode, EXT2_XATTR_INDEX_SECURITY, name,
			      buffer, size);
}

static int
ext2_xattr_security_set(struct inode *inode, const char *name,
		       const void *value, size_t size, int flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext2_xattr_set(inode, EXT2_XATTR_INDEX_SECURITY, name,
			      value, size, flags);
}

int
ext2_init_security(struct inode *inode, struct inode *dir)
{
	int err;
	size_t len;
	void *value;
	char *name;

	err = security_inode_init_security(inode, dir, &name, &value, &len);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	err = ext2_xattr_set(inode, EXT2_XATTR_INDEX_SECURITY,
			     name, value, len, 0);
	kfree(name);
	kfree(value);
	return err;
}

struct xattr_handler ext2_xattr_security_handler = {
ext2_xattr_security_set(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	return ext2_xattr_set(inode, EXT2_XATTR_INDEX_SECURITY, name,
			      value, size, flags);
}

static int ext2_initxattrs(struct inode *inode, const struct xattr *xattr_array,
			   void *fs_info)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = ext2_xattr_set(inode, EXT2_XATTR_INDEX_SECURITY,
				     xattr->name, xattr->value,
				     xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}

int
ext2_init_security(struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &ext2_initxattrs, NULL);
}

const struct xattr_handler ext2_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= ext2_xattr_security_get,
	.set	= ext2_xattr_security_set,
};
