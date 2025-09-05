// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext4/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"

static size_t
ext4_xattr_security_list(struct inode *inode, char *list, size_t list_size,
ext4_xattr_security_list(const struct xattr_handler *handler,
			 struct dentry *dentry, char *list, size_t list_size,
			 const char *name, size_t name_len)
{
	const size_t prefix_len = sizeof(XATTR_SECURITY_PREFIX)-1;
	const size_t total_len = prefix_len + name_len + 1;


	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
ext4_xattr_security_get(struct inode *inode, const char *name,
		       void *buffer, size_t size)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext4_xattr_get(inode, EXT4_XATTR_INDEX_SECURITY, name,
			      buffer, size);
}

static int
ext4_xattr_security_set(struct inode *inode, const char *name,
		       const void *value, size_t size, int flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext4_xattr_set(inode, EXT4_XATTR_INDEX_SECURITY, name,
			      value, size, flags);
}

int
ext4_init_security(handle_t *handle, struct inode *inode, struct inode *dir)
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
	err = ext4_xattr_set_handle(handle, inode, EXT4_XATTR_INDEX_SECURITY,
				    name, value, len, 0);
	kfree(name);
	kfree(value);
	return err;
}

struct xattr_handler ext4_xattr_security_handler = {
ext4_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return ext4_xattr_get(inode, EXT4_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

static int
ext4_xattr_security_set(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	return ext4_xattr_set(inode, EXT4_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

static int
ext4_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = ext4_xattr_set_handle(handle, inode,
					    EXT4_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, XATTR_CREATE);
		if (err < 0)
			break;
	}
	return err;
}

int
ext4_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &ext4_initxattrs, handle);
}

const struct xattr_handler ext4_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= ext4_xattr_security_get,
	.set	= ext4_xattr_security_set,
};
