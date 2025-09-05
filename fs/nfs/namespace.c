/*
 * linux/fs/nfs/namespace.c
 *
 * Copyright (C) 2005 Trond Myklebust <Trond.Myklebust@netapp.com>
 * - Modified by David Howells <dhowells@redhat.com>
 *
 * NFS namespace
 */

#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/gfp.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nfs_fs.h>
#include <linux/string.h>
#include <linux/sunrpc/clnt.h>
#include <linux/vfs.h>
#include <linux/sunrpc/gss_api.h>
#include "internal.h"

#define NFSDBG_FACILITY		NFSDBG_VFS

static void nfs_expire_automounts(struct work_struct *work);

static LIST_HEAD(nfs_automount_list);
static DECLARE_DELAYED_WORK(nfs_automount_task, nfs_expire_automounts);
int nfs_mountpoint_expiry_timeout = 500 * HZ;

static struct vfsmount *nfs_do_submount(const struct vfsmount *mnt_parent,
					const struct dentry *dentry,
					struct nfs_fh *fh,
					struct nfs_fattr *fattr);

/*
 * nfs_path - reconstruct the path given an arbitrary dentry
 * @base - arbitrary string to prepend to the path
 * @droot - pointer to root dentry for mountpoint
 * @dentry - pointer to dentry
 * @buffer - result buffer
 * @buflen - length of buffer
 *
 * Helper function for constructing the path from the
 * root dentry to an arbitrary hashed dentry.
 *
 * This is mainly for use in figuring out the path on the
 * server side when automounting on top of an existing partition.
 */
char *nfs_path(const char *base,
	       const struct dentry *droot,
	       const struct dentry *dentry,
	       char *buffer, ssize_t buflen)
{
	char *end = buffer+buflen;
	int namelen;

	*--end = '\0';
	buflen--;
	spin_lock(&dcache_lock);
	while (!IS_ROOT(dentry) && dentry != droot) {
/*
 * nfs_path - reconstruct the path given an arbitrary dentry
 * @base - used to return pointer to the end of devname part of path
 * @dentry - pointer to dentry
 * @buffer - result buffer
 * @buflen - length of buffer
 * @flags - options (see below)
 *
 * Helper function for constructing the server pathname
 * by arbitrary hashed dentry.
 *
 * This is mainly for use in figuring out the path on the
 * server side when automounting on top of an existing partition
 * and in generating /proc/mounts and friends.
 *
 * Supported flags:
 * NFS_PATH_CANONICAL: ensure there is exactly one slash after
 *		       the original device (export) name
 *		       (if unset, the original name is returned verbatim)
 */
char *nfs_path(char **p, struct dentry *dentry, char *buffer, ssize_t buflen,
	       unsigned flags)
{
	char *end;
	int namelen;
	unsigned seq;
	const char *base;

rename_retry:
	end = buffer+buflen;
	*--end = '\0';
	buflen--;

	seq = read_seqbegin(&rename_lock);
	rcu_read_lock();
	while (1) {
		spin_lock(&dentry->d_lock);
		if (IS_ROOT(dentry))
			break;
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto Elong_unlock;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		dentry = dentry->d_parent;
	}
	spin_unlock(&dcache_lock);
	namelen = strlen(base);
	/* Strip off excess slashes in base string */
	while (namelen > 0 && base[namelen - 1] == '/')
		namelen--;
	buflen -= namelen;
	if (buflen < 0)
		goto Elong;
	end -= namelen;
	memcpy(end, base, namelen);
	return end;
Elong_unlock:
	spin_unlock(&dcache_lock);
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

/*
 * nfs_follow_mountpoint - handle crossing a mountpoint on the server
 * @dentry - dentry of mountpoint
 * @nd - nameidata info
		spin_unlock(&dentry->d_lock);
		dentry = dentry->d_parent;
	}
	if (read_seqretry(&rename_lock, seq)) {
		spin_unlock(&dentry->d_lock);
		rcu_read_unlock();
		goto rename_retry;
	}
	if ((flags & NFS_PATH_CANONICAL) && *end != '/') {
		if (--buflen < 0) {
			spin_unlock(&dentry->d_lock);
			rcu_read_unlock();
			goto Elong;
		}
		*--end = '/';
	}
	*p = end;
	base = dentry->d_fsdata;
	if (!base) {
		spin_unlock(&dentry->d_lock);
		rcu_read_unlock();
		WARN_ON(1);
		return end;
	}
	namelen = strlen(base);
	if (*end == '/') {
		/* Strip off excess slashes in base string */
		while (namelen > 0 && base[namelen - 1] == '/')
			namelen--;
	}
	buflen -= namelen;
	if (buflen < 0) {
		spin_unlock(&dentry->d_lock);
		rcu_read_unlock();
		goto Elong;
	}
	end -= namelen;
	memcpy(end, base, namelen);
	spin_unlock(&dentry->d_lock);
	rcu_read_unlock();
	return end;
Elong_unlock:
	spin_unlock(&dentry->d_lock);
	rcu_read_unlock();
	if (read_seqretry(&rename_lock, seq))
		goto rename_retry;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}
EXPORT_SYMBOL_GPL(nfs_path);

/*
 * nfs_d_automount - Handle crossing a mountpoint on the server
 * @path - The mountpoint
 *
 * When we encounter a mountpoint on the server, we want to set up
 * a mountpoint on the client too, to prevent inode numbers from
 * colliding, and to allow "df" to work properly.
 * On NFSv4, we also want to allow for the fact that different
 * filesystems may be migrated to different servers in a failover
 * situation, and that different filesystems may want to use
 * different security flavours.
 */
static void * nfs_follow_mountpoint(struct dentry *dentry, struct nameidata *nd)
{
	struct vfsmount *mnt;
	struct nfs_server *server = NFS_SERVER(dentry->d_inode);
	struct dentry *parent;
	struct nfs_fh fh;
	struct nfs_fattr fattr;
	int err;

	dprintk("--> nfs_follow_mountpoint()\n");

	BUG_ON(IS_ROOT(dentry));
	dprintk("%s: enter\n", __func__);
	dput(nd->path.dentry);
	nd->path.dentry = dget(dentry);

	/* Look it up again */
	parent = dget_parent(nd->path.dentry);
	err = server->nfs_client->rpc_ops->lookup(parent->d_inode,
						  &nd->path.dentry->d_name,
						  &fh, &fattr);
	dput(parent);
	if (err != 0)
		goto out_err;

	if (fattr.valid & NFS_ATTR_FATTR_V4_REFERRAL)
		mnt = nfs_do_refmount(nd->path.mnt, nd->path.dentry);
	else
		mnt = nfs_do_submount(nd->path.mnt, nd->path.dentry, &fh,
				      &fattr);
	err = PTR_ERR(mnt);
	if (IS_ERR(mnt))
		goto out_err;

	mntget(mnt);
	err = do_add_mount(mnt, &nd->path, nd->path.mnt->mnt_flags|MNT_SHRINKABLE,
			   &nfs_automount_list);
	if (err < 0) {
		mntput(mnt);
		if (err == -EBUSY)
			goto out_follow;
		goto out_err;
	}
	path_put(&nd->path);
	nd->path.mnt = mnt;
	nd->path.dentry = dget(mnt->mnt_root);
	schedule_delayed_work(&nfs_automount_task, nfs_mountpoint_expiry_timeout);
out:
	dprintk("%s: done, returned %d\n", __func__, err);

	dprintk("<-- nfs_follow_mountpoint() = %d\n", err);
	return ERR_PTR(err);
out_err:
	path_put(&nd->path);
	goto out;
out_follow:
	while (d_mountpoint(nd->path.dentry) &&
	       follow_down(&nd->path.mnt, &nd->path.dentry))
		;
	err = 0;
	goto out;
}

const struct inode_operations nfs_mountpoint_inode_operations = {
	.follow_link	= nfs_follow_mountpoint,
	.getattr	= nfs_getattr,
};

const struct inode_operations nfs_referral_inode_operations = {
	.follow_link	= nfs_follow_mountpoint,
struct vfsmount *nfs_d_automount(struct path *path)
{
	struct vfsmount *mnt;
	struct nfs_server *server = NFS_SERVER(d_inode(path->dentry));
	struct nfs_fh *fh = NULL;
	struct nfs_fattr *fattr = NULL;

	if (IS_ROOT(path->dentry))
		return ERR_PTR(-ESTALE);

	mnt = ERR_PTR(-ENOMEM);
	fh = nfs_alloc_fhandle();
	fattr = nfs_alloc_fattr();
	if (fh == NULL || fattr == NULL)
		goto out;

	mnt = server->nfs_client->rpc_ops->submount(server, path->dentry, fh, fattr);
	if (IS_ERR(mnt))
		goto out;

	mntget(mnt); /* prevent immediate expiration */
	mnt_set_expiry(mnt, &nfs_automount_list);
	schedule_delayed_work(&nfs_automount_task, nfs_mountpoint_expiry_timeout);

out:
	nfs_free_fattr(fattr);
	nfs_free_fhandle(fh);
	return mnt;
}

static int
nfs_namespace_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags)
{
	if (NFS_FH(d_inode(path->dentry))->size != 0)
		return nfs_getattr(path, stat, request_mask, query_flags);
	generic_fillattr(d_inode(path->dentry), stat);
	return 0;
}

static int
nfs_namespace_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (NFS_FH(d_inode(dentry))->size != 0)
		return nfs_setattr(dentry, attr);
	return -EACCES;
}

const struct inode_operations nfs_mountpoint_inode_operations = {
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
};

const struct inode_operations nfs_referral_inode_operations = {
	.getattr	= nfs_namespace_getattr,
	.setattr	= nfs_namespace_setattr,
};

static void nfs_expire_automounts(struct work_struct *work)
{
	struct list_head *list = &nfs_automount_list;

	mark_mounts_for_expiry(list);
	if (!list_empty(list))
		schedule_delayed_work(&nfs_automount_task, nfs_mountpoint_expiry_timeout);
}

void nfs_release_automount_timer(void)
{
	if (list_empty(&nfs_automount_list))
		cancel_delayed_work(&nfs_automount_task);
}

/*
 * Clone a mountpoint of the appropriate type
 */
static struct vfsmount *nfs_do_clone_mount(struct nfs_server *server,
					   const char *devname,
					   struct nfs_clone_mount *mountdata)
{
#ifdef CONFIG_NFS_V4
	struct vfsmount *mnt = NULL;
	switch (server->nfs_client->rpc_ops->version) {
		case 2:
		case 3:
			mnt = vfs_kern_mount(&nfs_xdev_fs_type, 0, devname, mountdata);
			break;
		case 4:
			mnt = vfs_kern_mount(&nfs4_xdev_fs_type, 0, devname, mountdata);
	}
	return mnt;
#else
	return vfs_kern_mount(&nfs_xdev_fs_type, 0, devname, mountdata);
#endif
	return vfs_kern_mount(&nfs_xdev_fs_type, 0, devname, mountdata);
	return vfs_submount(mountdata->dentry, &nfs_xdev_fs_type, devname, mountdata);
}

/**
 * nfs_do_submount - set up mountpoint when crossing a filesystem boundary
 * @mnt_parent - mountpoint of parent directory
 * @dentry - parent directory
 * @fh - filehandle for new root dentry
 * @fattr - attributes for new root inode
 *
 */
static struct vfsmount *nfs_do_submount(const struct vfsmount *mnt_parent,
					const struct dentry *dentry,
					struct nfs_fh *fh,
					struct nfs_fattr *fattr)
{
	struct nfs_clone_mount mountdata = {
		.sb = mnt_parent->mnt_sb,
		.dentry = dentry,
		.fh = fh,
		.fattr = fattr,
 * @dentry - parent directory
 * @fh - filehandle for new root dentry
 * @fattr - attributes for new root inode
 * @authflavor - security flavor to use when performing the mount
 *
 */
struct vfsmount *nfs_do_submount(struct dentry *dentry, struct nfs_fh *fh,
				 struct nfs_fattr *fattr, rpc_authflavor_t authflavor)
{
	struct nfs_clone_mount mountdata = {
		.sb = dentry->d_sb,
		.dentry = dentry,
		.fh = fh,
		.fattr = fattr,
		.authflavor = authflavor,
	};
	struct vfsmount *mnt;
	char *page = (char *) __get_free_page(GFP_USER);
	char *devname;

	dprintk("--> nfs_do_submount()\n");

	dprintk("%s: submounting on %s/%s\n", __func__,
			dentry->d_parent->d_name.name,
			dentry->d_name.name);
	if (page == NULL)
		goto out;
	devname = nfs_devname(mnt_parent, dentry, page, PAGE_SIZE);
	mnt = (struct vfsmount *)devname;
	if (IS_ERR(devname))
		goto free_page;
	mnt = nfs_do_clone_mount(NFS_SB(mnt_parent->mnt_sb), devname, &mountdata);
	dprintk("%s: submounting on %pd2\n", __func__,
			dentry);
	if (page == NULL)
		return ERR_PTR(-ENOMEM);

	devname = nfs_devname(dentry, page, PAGE_SIZE);
	if (IS_ERR(devname))
		mnt = ERR_CAST(devname);
	else
		mnt = nfs_do_clone_mount(NFS_SB(dentry->d_sb), devname, &mountdata);

	free_page((unsigned long)page);
	return mnt;
}
EXPORT_SYMBOL_GPL(nfs_do_submount);

struct vfsmount *nfs_submount(struct nfs_server *server, struct dentry *dentry,
			      struct nfs_fh *fh, struct nfs_fattr *fattr)
{
	int err;
	struct dentry *parent = dget_parent(dentry);

	/* Look it up again to get its attributes */
	err = server->nfs_client->rpc_ops->lookup(d_inode(parent), &dentry->d_name, fh, fattr, NULL);
	dput(parent);
	if (err != 0)
		return ERR_PTR(err);

	return nfs_do_submount(dentry, fh, fattr, server->client->cl_auth->au_flavor);
}
EXPORT_SYMBOL_GPL(nfs_submount);
