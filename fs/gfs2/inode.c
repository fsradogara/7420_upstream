/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 * Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/posix_acl.h>
#include <linux/sort.h>
#include <linux/gfs2_ondisk.h>
#include <linux/crc32.h>
#include <linux/lm_interface.h>
#include <linux/security.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/gfs2_ondisk.h>
#include <linux/crc32.h>
#include <linux/iomap.h>
#include <linux/security.h>
#include <linux/uaccess.h>

#include "gfs2.h"
#include "incore.h"
#include "acl.h"
#include "bmap.h"
#include "dir.h"
#include "eattr.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "log.h"
#include "meta_io.h"
#include "ops_address.h"
#include "ops_inode.h"
#include "xattr.h"
#include "glock.h"
#include "inode.h"
#include "meta_io.h"
#include "quota.h"
#include "rgrp.h"
#include "trans.h"
#include "util.h"

struct gfs2_inum_range_host {
	u64 ir_start;
	u64 ir_length;
#include "super.h"
#include "glops.h"

static int iget_test(struct inode *inode, void *opaque)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	u64 *no_addr = opaque;

	if (ip->i_no_addr == *no_addr && test_bit(GIF_USER, &ip->i_flags))
		return 1;

	return 0;
}

static int iget_set(struct inode *inode, void *opaque)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	u64 *no_addr = opaque;

	inode->i_ino = (unsigned long)*no_addr;
	ip->i_no_addr = *no_addr;
	set_bit(GIF_USER, &ip->i_flags);
	return 0;
}

struct inode *gfs2_ilookup(struct super_block *sb, u64 no_addr)
{
	unsigned long hash = (unsigned long)no_addr;
	return ilookup5(sb, hash, iget_test, &no_addr);
}

static struct inode *gfs2_iget(struct super_block *sb, u64 no_addr)
{
	unsigned long hash = (unsigned long)no_addr;
	return iget5_locked(sb, hash, iget_test, iget_set, &no_addr);
}

struct gfs2_skip_data {
	u64	no_addr;
	int	skipped;
};

static int iget_skip_test(struct inode *inode, void *opaque)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_skip_data *data = opaque;

	if (ip->i_no_addr == data->no_addr && test_bit(GIF_USER, &ip->i_flags)){
		if (inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE)){
	struct gfs2_skip_data *data = opaque;
	u64 no_addr = *(u64 *)opaque;

	return GFS2_I(inode)->i_no_addr == no_addr;
}

static int iget_skip_set(struct inode *inode, void *opaque)
static int iget_set(struct inode *inode, void *opaque)
{
	u64 no_addr = *(u64 *)opaque;

	if (data->skipped)
		return 1;
	inode->i_ino = (unsigned long)(data->no_addr);
	ip->i_no_addr = data->no_addr;
	set_bit(GIF_USER, &ip->i_flags);
	return 0;
}

static struct inode *gfs2_iget_skip(struct super_block *sb,
				    u64 no_addr)
		return -ENOENT;
	inode->i_ino = (unsigned long)(data->no_addr);
	ip->i_no_addr = data->no_addr;
	GFS2_I(inode)->i_no_addr = no_addr;
	inode->i_ino = no_addr;
	return 0;
}

static struct inode *gfs2_iget(struct super_block *sb, u64 no_addr)
{
	struct inode *inode;

	data.no_addr = no_addr;
	data.skipped = 0;
	data.non_block = non_block;
	return ilookup5(sb, hash, iget_test, &data);
}

static struct inode *gfs2_iget(struct super_block *sb, u64 no_addr,
			       int non_block)
{
	struct gfs2_skip_data data;
	unsigned long hash = (unsigned long)no_addr;

	data.no_addr = no_addr;
	data.skipped = 0;
	return iget5_locked(sb, hash, iget_skip_test, iget_skip_set, &data);
}

/**
 * GFS2 lookup code fills in vfs inode contents based on info obtained
 * from directory entry inside gfs2_inode_lookup(). This has caused issues
 * with NFS code path since its get_dentry routine doesn't have the relevant
 * directory entry when gfs2_inode_lookup() is invoked. Part of the code
 * segment inside gfs2_inode_lookup code needs to get moved around.
 *
 * Clean up I_LOCK and I_NEW as well.
 **/

void gfs2_set_iop(struct inode *inode)
	data.non_block = non_block;
	return iget5_locked(sb, hash, iget_test, iget_set, &data);
repeat:
	inode = iget5_locked(sb, no_addr, iget_test, iget_set, &no_addr);
	if (!inode)
		return inode;
	if (is_bad_inode(inode)) {
		iput(inode);
		goto repeat;
	}
	return inode;
}

/**
 * gfs2_set_iop - Sets inode operations
 * @inode: The inode with correct i_mode filled in
 *
 * GFS2 lookup code fills in vfs inode contents based on info obtained
 * from directory entry inside gfs2_inode_lookup().
 */

static void gfs2_set_iop(struct inode *inode)
{
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	umode_t mode = inode->i_mode;

	if (S_ISREG(mode)) {
		inode->i_op = &gfs2_file_iops;
		if (sdp->sd_args.ar_localflocks)
		if (gfs2_localflocks(sdp))
			inode->i_fop = &gfs2_file_fops_nolock;
		else
			inode->i_fop = &gfs2_file_fops;
	} else if (S_ISDIR(mode)) {
		inode->i_op = &gfs2_dir_iops;
		if (sdp->sd_args.ar_localflocks)
		if (gfs2_localflocks(sdp))
			inode->i_fop = &gfs2_dir_fops_nolock;
		else
			inode->i_fop = &gfs2_dir_fops;
	} else if (S_ISLNK(mode)) {
		inode->i_op = &gfs2_symlink_iops;
	} else {
		inode->i_op = &gfs2_file_iops;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	}

	unlock_new_inode(inode);
}

/**
 * gfs2_inode_lookup - Lookup an inode
 * @sb: The super block
 * @type: The type of the inode
 * @skip_freeing: set this not return an inode if it is currently being freed.
 * non_block: Can we block on inodes that are being freed?
 * @no_addr: The inode number
 * @no_formal_ino: The inode generation number
 * @blktype: Requested block type (GFS2_BLKST_DINODE or GFS2_BLKST_UNLINKED;
 *           GFS2_BLKST_FREE to indicate not to verify)
 *
 * If @type is DT_UNKNOWN, the inode type is fetched from disk.
 *
 * If @blktype is anything other than GFS2_BLKST_FREE (which is used as a
 * placeholder because it doesn't otherwise make sense), the on-disk block type
 * is verified to be @blktype.
 *
 * Returns: A VFS inode, or an error
 */

struct inode *gfs2_inode_lookup(struct super_block *sb,
				unsigned int type,
				u64 no_addr,
				u64 no_formal_ino, int skip_freeing)
{
	struct inode *inode;
	struct gfs2_inode *ip;
	struct gfs2_glock *io_gl;
	int error;

	if (skip_freeing)
		inode = gfs2_iget_skip(sb, no_addr);
	else
		inode = gfs2_iget(sb, no_addr);
	ip = GFS2_I(inode);

	if (!inode)
		return ERR_PTR(-ENOBUFS);
struct inode *gfs2_inode_lookup(struct super_block *sb, unsigned int type,
				u64 no_addr, u64 no_formal_ino,
				unsigned int blktype)
{
	struct inode *inode;
	struct gfs2_inode *ip;
	struct gfs2_glock *io_gl = NULL;
	struct gfs2_holder i_gh;
	int error;

	gfs2_holder_mark_uninitialized(&i_gh);
	inode = gfs2_iget(sb, no_addr);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	ip = GFS2_I(inode);

	if (inode->i_state & I_NEW) {
		struct gfs2_sbd *sdp = GFS2_SB(inode);
		ip->i_no_formal_ino = no_formal_ino;

		error = gfs2_glock_get(sdp, no_addr, &gfs2_inode_glops, CREATE, &ip->i_gl);
		if (unlikely(error))
			goto fail;
		flush_delayed_work(&ip->i_gl->gl_work);

		error = gfs2_glock_get(sdp, no_addr, &gfs2_iopen_glops, CREATE, &io_gl);
		if (unlikely(error))
			goto fail_put;

		if (type == DT_UNKNOWN || blktype != GFS2_BLKST_FREE) {
			/*
			 * The GL_SKIP flag indicates to skip reading the inode
			 * block.  We read the inode with gfs2_inode_refresh
			 * after possibly checking the block type.
			 */
			error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE,
						   GL_SKIP, &i_gh);
			if (error)
				goto fail_put;

			if (blktype != GFS2_BLKST_FREE) {
				error = gfs2_check_blk_type(sdp, no_addr,
							    blktype);
				if (error)
					goto fail_put;
			}
		}

		glock_set_object(ip->i_gl, ip);
		set_bit(GIF_INVALID, &ip->i_flags);
		error = gfs2_glock_nq_init(io_gl, LM_ST_SHARED, GL_EXACT, &ip->i_iopen_gh);
		if (unlikely(error))
			goto fail_iopen;
		ip->i_iopen_gh.gh_gl->gl_object = ip;

		gfs2_glock_put(io_gl);

		if ((type == DT_UNKNOWN) && (no_formal_ino == 0))
			goto gfs2_nfsbypass;

		inode->i_mode = DT2IF(type);

		/*
		 * We must read the inode in order to work out its type in
		 * this case. Note that this doesn't happen often as we normally
		 * know the type beforehand. This code path only occurs during
		 * unlinked inode recovery (where it is safe to do this glock,
		 * which is not true in the general case).
		 */
		if (type == DT_UNKNOWN) {
			struct gfs2_holder gh;
			error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
			if (unlikely(error))
				goto fail_glock;
			/* Inode is now uptodate */
			gfs2_glock_dq_uninit(&gh);
		}

		gfs2_set_iop(inode);
	}

gfs2_nfsbypass:
	return inode;
fail_glock:
	gfs2_glock_dq(&ip->i_iopen_gh);
fail_iopen:
	gfs2_glock_put(io_gl);

		ip->i_iopen_gh.gh_gl->gl_object = ip;
			goto fail_put;
		glock_set_object(ip->i_iopen_gh.gh_gl, ip);
		gfs2_glock_put(io_gl);
		io_gl = NULL;

		if (type == DT_UNKNOWN) {
			/* Inode glock must be locked already */
			error = gfs2_inode_refresh(GFS2_I(inode));
			if (error)
				goto fail_refresh;
		} else {
			inode->i_mode = DT2IF(type);
		}

		gfs2_set_iop(inode);

		/* Lowest possible timestamp; will be overwritten in gfs2_dinode_in. */
		inode->i_atime.tv_sec = 1LL << (8 * sizeof(inode->i_atime.tv_sec) - 1);
		inode->i_atime.tv_nsec = 0;

		unlock_new_inode(inode);
	}

	if (gfs2_holder_initialized(&i_gh))
		gfs2_glock_dq_uninit(&i_gh);
	return inode;

fail_refresh:
	ip->i_iopen_gh.gh_flags |= GL_NOCACHE;
	glock_clear_object(ip->i_iopen_gh.gh_gl, ip);
	gfs2_glock_dq_uninit(&ip->i_iopen_gh);
fail_put:
	if (io_gl)
		gfs2_glock_put(io_gl);
	glock_clear_object(ip->i_gl, ip);
	if (gfs2_holder_initialized(&i_gh))
		gfs2_glock_dq_uninit(&i_gh);
fail:
	iget_failed(inode);
	return ERR_PTR(error);
}

static int gfs2_dinode_in(struct gfs2_inode *ip, const void *buf)
{
	struct gfs2_dinode_host *di = &ip->i_di;
	const struct gfs2_dinode *str = buf;
	u16 height, depth;

	if (unlikely(ip->i_no_addr != be64_to_cpu(str->di_num.no_addr)))
		goto corrupt;
	ip->i_no_formal_ino = be64_to_cpu(str->di_num.no_formal_ino);
	ip->i_inode.i_mode = be32_to_cpu(str->di_mode);
	ip->i_inode.i_rdev = 0;
	switch (ip->i_inode.i_mode & S_IFMT) {
	case S_IFBLK:
	case S_IFCHR:
		ip->i_inode.i_rdev = MKDEV(be32_to_cpu(str->di_major),
					   be32_to_cpu(str->di_minor));
		break;
	};

	ip->i_inode.i_uid = be32_to_cpu(str->di_uid);
	ip->i_inode.i_gid = be32_to_cpu(str->di_gid);
	/*
	 * We will need to review setting the nlink count here in the
	 * light of the forthcoming ro bind mount work. This is a reminder
	 * to do that.
	 */
	ip->i_inode.i_nlink = be32_to_cpu(str->di_nlink);
	di->di_size = be64_to_cpu(str->di_size);
	i_size_write(&ip->i_inode, di->di_size);
	gfs2_set_inode_blocks(&ip->i_inode, be64_to_cpu(str->di_blocks));
	ip->i_inode.i_atime.tv_sec = be64_to_cpu(str->di_atime);
	ip->i_inode.i_atime.tv_nsec = be32_to_cpu(str->di_atime_nsec);
	ip->i_inode.i_mtime.tv_sec = be64_to_cpu(str->di_mtime);
	ip->i_inode.i_mtime.tv_nsec = be32_to_cpu(str->di_mtime_nsec);
	ip->i_inode.i_ctime.tv_sec = be64_to_cpu(str->di_ctime);
	ip->i_inode.i_ctime.tv_nsec = be32_to_cpu(str->di_ctime_nsec);

	ip->i_goal = be64_to_cpu(str->di_goal_meta);
	di->di_generation = be64_to_cpu(str->di_generation);

	di->di_flags = be32_to_cpu(str->di_flags);
	gfs2_set_inode_flags(&ip->i_inode);
	height = be16_to_cpu(str->di_height);
	if (unlikely(height > GFS2_MAX_META_HEIGHT))
		goto corrupt;
	ip->i_height = (u8)height;

	depth = be16_to_cpu(str->di_depth);
	if (unlikely(depth > GFS2_DIR_MAX_DEPTH))
		goto corrupt;
	ip->i_depth = (u8)depth;
	di->di_entries = be32_to_cpu(str->di_entries);

	di->di_eattr = be64_to_cpu(str->di_eattr);
	if (S_ISREG(ip->i_inode.i_mode))
		gfs2_set_aops(&ip->i_inode);

	return 0;
corrupt:
	if (gfs2_consist_inode(ip))
		gfs2_dinode_print(ip);
	return -EIO;
}

/**
 * gfs2_inode_refresh - Refresh the incore copy of the dinode
 * @ip: The GFS2 inode
 *
 * Returns: errno
 */

int gfs2_inode_refresh(struct gfs2_inode *ip)
{
	struct buffer_head *dibh;
	int error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	if (gfs2_metatype_check(GFS2_SB(&ip->i_inode), dibh, GFS2_METATYPE_DI)) {
		brelse(dibh);
		return -EIO;
	}

	error = gfs2_dinode_in(ip, dibh->b_data);
	brelse(dibh);
	clear_bit(GIF_INVALID, &ip->i_flags);

	return error;
}

int gfs2_dinode_dealloc(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_alloc *al;
	struct gfs2_rgrpd *rgd;
	int error;

	if (gfs2_get_inode_blocks(&ip->i_inode) != 1) {
		if (gfs2_consist_inode(ip))
			gfs2_dinode_print(ip);
		return -EIO;
	}

	al = gfs2_alloc_get(ip);
	if (!al)
		return -ENOMEM;

	error = gfs2_quota_hold(ip, NO_QUOTA_CHANGE, NO_QUOTA_CHANGE);
	if (error)
		goto out;

	error = gfs2_rindex_hold(sdp, &al->al_ri_gh);
	if (error)
		goto out_qs;

	rgd = gfs2_blk2rgrpd(sdp, ip->i_no_addr);
	if (!rgd) {
		gfs2_consist_inode(ip);
		error = -EIO;
		goto out_rindex_relse;
	}

	error = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0,
				   &al->al_rgd_gh);
	if (error)
		goto out_rindex_relse;

	error = gfs2_trans_begin(sdp, RES_RG_BIT + RES_STATFS + RES_QUOTA, 1);
	if (error)
		goto out_rg_gunlock;

	set_bit(GLF_DIRTY, &ip->i_gl->gl_flags);
	set_bit(GLF_LFLUSH, &ip->i_gl->gl_flags);

	gfs2_free_di(rgd, ip);

	gfs2_trans_end(sdp);
	clear_bit(GLF_STICKY, &ip->i_gl->gl_flags);

out_rg_gunlock:
	gfs2_glock_dq_uninit(&al->al_rgd_gh);
out_rindex_relse:
	gfs2_glock_dq_uninit(&al->al_ri_gh);
out_qs:
	gfs2_quota_unhold(ip);
out:
	gfs2_alloc_put(ip);
	return error;
}

/**
 * gfs2_change_nlink - Change nlink count on inode
 * @ip: The GFS2 inode
 * @diff: The change in the nlink count required
 *
 * Returns: errno
 */
int gfs2_change_nlink(struct gfs2_inode *ip, int diff)
{
	struct buffer_head *dibh;
	u32 nlink;
	int error;

	BUG_ON(diff != 1 && diff != -1);
	nlink = ip->i_inode.i_nlink + diff;

	/* If we are reducing the nlink count, but the new value ends up being
	   bigger than the old one, we must have underflowed. */
	if (diff < 0 && nlink > ip->i_inode.i_nlink) {
		if (gfs2_consist_inode(ip))
			gfs2_dinode_print(ip);
		return -EIO;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	if (diff > 0)
		inc_nlink(&ip->i_inode);
	else
		drop_nlink(&ip->i_inode);

	ip->i_inode.i_ctime = CURRENT_TIME;

	gfs2_trans_add_bh(ip->i_gl, dibh, 1);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);
	mark_inode_dirty(&ip->i_inode);

	if (ip->i_inode.i_nlink == 0)
		gfs2_unlink_di(&ip->i_inode); /* mark inode unlinked */

	return error;
}
struct inode *gfs2_lookup_by_inum(struct gfs2_sbd *sdp, u64 no_addr,
				  u64 *no_formal_ino, unsigned int blktype)
{
	struct super_block *sb = sdp->sd_vfs;
	struct inode *inode;
	int error;

	inode = gfs2_inode_lookup(sb, DT_UNKNOWN, no_addr, 0, blktype);
	if (IS_ERR(inode))
		return inode;

	/* Two extra checks for NFS only */
	if (no_formal_ino) {
		error = -ESTALE;
		if (GFS2_I(inode)->i_no_formal_ino != *no_formal_ino)
			goto fail_iput;

		error = -EIO;
		if (GFS2_I(inode)->i_diskflags & GFS2_DIF_SYSTEM)
			goto fail_iput;
	}
	return inode;

fail_iput:
	iput(inode);
	return ERR_PTR(error);
}


struct inode *gfs2_lookup_simple(struct inode *dip, const char *name)
{
	struct qstr qstr;
	struct inode *inode;
	gfs2_str2qstr(&qstr, name);
	inode = gfs2_lookupi(dip, &qstr, 1);
	/* gfs2_lookupi has inconsistent callers: vfs
	 * related routines expect NULL for no entry found,
	 * gfs2_lookup_simple callers expect ENOENT
	 * and do not check for NULL.
	 */
	if (inode == NULL)
		return ERR_PTR(-ENOENT);
	else
		return inode;
}


/**
 * gfs2_lookupi - Look up a filename in a directory and return its inode
 * @d_gh: An initialized holder for the directory glock
 * @name: The name of the inode to look for
 * @is_root: If 1, ignore the caller's permissions
 * @i_gh: An uninitialized holder for the new inode glock
 *
 * This can be called via the VFS filldir function when NFS is doing
 * a readdirplus and the inode which its intending to stat isn't
 * already in cache. In this case we must not take the directory glock
 * again, since the readdir call will have already taken that lock.
 *
 * Returns: errno
 */

struct inode *gfs2_lookupi(struct inode *dir, const struct qstr *name,
			   int is_root)
{
	struct super_block *sb = dir->i_sb;
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_holder d_gh;
	int error = 0;
	struct inode *inode = NULL;

	gfs2_holder_mark_uninitialized(&d_gh);
	if (!name->len || name->len > GFS2_FNAMESIZE)
		return ERR_PTR(-ENAMETOOLONG);

	if ((name->len == 1 && memcmp(name->name, ".", 1) == 0) ||
	    (name->len == 2 && memcmp(name->name, "..", 2) == 0 &&
	     dir == sb->s_root->d_inode)) {
	     dir == d_inode(sb->s_root))) {
		igrab(dir);
		return dir;
	}

	if (gfs2_glock_is_locked_by_me(dip->i_gl) == NULL) {
		error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &d_gh);
		if (error)
			return ERR_PTR(error);
	}

	if (!is_root) {
		error = gfs2_permission(dir, MAY_EXEC);
		if (error)
			goto out;
	}

	inode = gfs2_dir_search(dir, name);
	inode = gfs2_dir_search(dir, name, false);
	if (IS_ERR(inode))
		error = PTR_ERR(inode);
out:
	if (gfs2_holder_initialized(&d_gh))
		gfs2_glock_dq_uninit(&d_gh);
	if (error == -ENOENT)
		return NULL;
	return inode ? inode : ERR_PTR(error);
}

static void gfs2_inum_range_in(struct gfs2_inum_range_host *ir, const void *buf)
{
	const struct gfs2_inum_range *str = buf;

	ir->ir_start = be64_to_cpu(str->ir_start);
	ir->ir_length = be64_to_cpu(str->ir_length);
}

static void gfs2_inum_range_out(const struct gfs2_inum_range_host *ir, void *buf)
{
	struct gfs2_inum_range *str = buf;

	str->ir_start = cpu_to_be64(ir->ir_start);
	str->ir_length = cpu_to_be64(ir->ir_length);
}

static int pick_formal_ino_1(struct gfs2_sbd *sdp, u64 *formal_ino)
{
	struct gfs2_inode *ip = GFS2_I(sdp->sd_ir_inode);
	struct buffer_head *bh;
	struct gfs2_inum_range_host ir;
	int error;

	error = gfs2_trans_begin(sdp, RES_DINODE, 0);
	if (error)
		return error;
	mutex_lock(&sdp->sd_inum_mutex);

	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error) {
		mutex_unlock(&sdp->sd_inum_mutex);
		gfs2_trans_end(sdp);
		return error;
	}

	gfs2_inum_range_in(&ir, bh->b_data + sizeof(struct gfs2_dinode));

	if (ir.ir_length) {
		*formal_ino = ir.ir_start++;
		ir.ir_length--;
		gfs2_trans_add_bh(ip->i_gl, bh, 1);
		gfs2_inum_range_out(&ir,
				    bh->b_data + sizeof(struct gfs2_dinode));
		brelse(bh);
		mutex_unlock(&sdp->sd_inum_mutex);
		gfs2_trans_end(sdp);
		return 0;
	}

	brelse(bh);

	mutex_unlock(&sdp->sd_inum_mutex);
	gfs2_trans_end(sdp);

	return 1;
}

static int pick_formal_ino_2(struct gfs2_sbd *sdp, u64 *formal_ino)
{
	struct gfs2_inode *ip = GFS2_I(sdp->sd_ir_inode);
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_inum_inode);
	struct gfs2_holder gh;
	struct buffer_head *bh;
	struct gfs2_inum_range_host ir;
	int error;

	error = gfs2_glock_nq_init(m_ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (error)
		return error;

	error = gfs2_trans_begin(sdp, 2 * RES_DINODE, 0);
	if (error)
		goto out;
	mutex_lock(&sdp->sd_inum_mutex);

	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		goto out_end_trans;

	gfs2_inum_range_in(&ir, bh->b_data + sizeof(struct gfs2_dinode));

	if (!ir.ir_length) {
		struct buffer_head *m_bh;
		u64 x, y;
		__be64 z;

		error = gfs2_meta_inode_buffer(m_ip, &m_bh);
		if (error)
			goto out_brelse;

		z = *(__be64 *)(m_bh->b_data + sizeof(struct gfs2_dinode));
		x = y = be64_to_cpu(z);
		ir.ir_start = x;
		ir.ir_length = GFS2_INUM_QUANTUM;
		x += GFS2_INUM_QUANTUM;
		if (x < y)
			gfs2_consist_inode(m_ip);
		z = cpu_to_be64(x);
		gfs2_trans_add_bh(m_ip->i_gl, m_bh, 1);
		*(__be64 *)(m_bh->b_data + sizeof(struct gfs2_dinode)) = z;

		brelse(m_bh);
	}

	*formal_ino = ir.ir_start++;
	ir.ir_length--;

	gfs2_trans_add_bh(ip->i_gl, bh, 1);
	gfs2_inum_range_out(&ir, bh->b_data + sizeof(struct gfs2_dinode));

out_brelse:
	brelse(bh);
out_end_trans:
	mutex_unlock(&sdp->sd_inum_mutex);
	gfs2_trans_end(sdp);
out:
	gfs2_glock_dq_uninit(&gh);
	return error;
}

static int pick_formal_ino(struct gfs2_sbd *sdp, u64 *inum)
{
	int error;

	error = pick_formal_ino_1(sdp, inum);
	if (error <= 0)
		return error;

	error = pick_formal_ino_2(sdp, inum);

	return error;
}

/**
 * create_ok - OK to create a new on-disk inode here?
 * @dip:  Directory in which dinode is to be created
 * @name:  Name of new dinode
 * @mode:
 *
 * Returns: errno
 */

static int create_ok(struct gfs2_inode *dip, const struct qstr *name,
		     unsigned int mode)
		     umode_t mode)
{
	int error;

	error = gfs2_permission(&dip->i_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	/*  Don't create entries in an unlinked directory  */
	if (!dip->i_inode.i_nlink)
		return -EPERM;

	error = gfs2_dir_check(&dip->i_inode, name, NULL);
	switch (error) {
	case -ENOENT:
		error = 0;
		break;
	case 0:
		return -EEXIST;
	default:
		return error;
	}

	if (dip->i_di.di_entries == (u32)-1)
		return -ENOENT;

	if (dip->i_entries == (u32)-1)
		return -EFBIG;
	if (S_ISDIR(mode) && dip->i_inode.i_nlink == (u32)-1)
		return -EMLINK;

	return 0;
}

static void munge_mode_uid_gid(struct gfs2_inode *dip, unsigned int *mode,
			       unsigned int *uid, unsigned int *gid)
{
	if (GFS2_SB(&dip->i_inode)->sd_args.ar_suiddir &&
	    (dip->i_inode.i_mode & S_ISUID) && dip->i_inode.i_uid) {
		if (S_ISDIR(*mode))
			*mode |= S_ISUID;
		else if (dip->i_inode.i_uid != current->fsuid)
			*mode &= ~07111;
		*uid = dip->i_inode.i_uid;
	} else
		*uid = current->fsuid;

	if (dip->i_inode.i_mode & S_ISGID) {
		if (S_ISDIR(*mode))
			*mode |= S_ISGID;
		*gid = dip->i_inode.i_gid;
	} else
		*gid = current->fsgid;
}

static int alloc_dinode(struct gfs2_inode *dip, u64 *no_addr, u64 *generation)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	int error;

	if (gfs2_alloc_get(dip) == NULL)
		return -ENOMEM;

	dip->i_alloc->al_requested = RES_DINODE;
	error = gfs2_inplace_reserve(dip);
	if (error)
		goto out;

	error = gfs2_trans_begin(sdp, RES_RG_BIT + RES_STATFS, 0);
	if (error)
		goto out_ipreserv;

	*no_addr = gfs2_alloc_di(dip, generation);
static void munge_mode_uid_gid(const struct gfs2_inode *dip,
			       struct inode *inode)
{
	if (GFS2_SB(&dip->i_inode)->sd_args.ar_suiddir &&
	    (dip->i_inode.i_mode & S_ISUID) &&
	    !uid_eq(dip->i_inode.i_uid, GLOBAL_ROOT_UID)) {
		if (S_ISDIR(inode->i_mode))
			inode->i_mode |= S_ISUID;
		else if (!uid_eq(dip->i_inode.i_uid, current_fsuid()))
			inode->i_mode &= ~07111;
		inode->i_uid = dip->i_inode.i_uid;
	} else
		inode->i_uid = current_fsuid();

	if (dip->i_inode.i_mode & S_ISGID) {
		if (S_ISDIR(inode->i_mode))
			inode->i_mode |= S_ISGID;
		inode->i_gid = dip->i_inode.i_gid;
	} else
		inode->i_gid = current_fsgid();
}

static int alloc_dinode(struct gfs2_inode *ip, u32 flags, unsigned *dblocks)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_alloc_parms ap = { .target = *dblocks, .aflags = flags, };
	int error;

	error = gfs2_quota_lock_check(ip, &ap);
	if (error)
		goto out;

	error = gfs2_inplace_reserve(ip, &ap);
	if (error)
		goto out_quota;

	error = gfs2_trans_begin(sdp, (*dblocks * RES_RG_BIT) + RES_STATFS + RES_QUOTA, 0);
	if (error)
		goto out_ipreserv;

	error = gfs2_alloc_blocks(ip, &ip->i_no_addr, dblocks, 1, &ip->i_generation);
	ip->i_no_formal_ino = ip->i_generation;
	ip->i_inode.i_ino = ip->i_no_addr;
	ip->i_goal = ip->i_no_addr;

	gfs2_trans_end(sdp);

out_ipreserv:
	gfs2_inplace_release(dip);
out:
	gfs2_alloc_put(dip);
	return error;
}

/**
 * init_dinode - Fill in a new dinode structure
 * @dip: the directory this inode is being created in
 * @gl: The glock covering the new inode
 * @inum: the inode number
 * @mode: the file permissions
 * @uid:
 * @gid:
 *
 */

static void init_dinode(struct gfs2_inode *dip, struct gfs2_glock *gl,
			const struct gfs2_inum_host *inum, unsigned int mode,
			unsigned int uid, unsigned int gid,
			const u64 *generation, dev_t dev, struct buffer_head **bhp)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_dinode *di;
	struct buffer_head *dibh;
	struct timespec tv = CURRENT_TIME;

	dibh = gfs2_meta_new(gl, inum->no_addr);
	gfs2_trans_add_bh(gl, dibh, 1);
	gfs2_metatype_set(dibh, GFS2_METATYPE_DI, GFS2_FORMAT_DI);
	gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode));
	di = (struct gfs2_dinode *)dibh->b_data;

	di->di_num.no_formal_ino = cpu_to_be64(inum->no_formal_ino);
	di->di_num.no_addr = cpu_to_be64(inum->no_addr);
	di->di_mode = cpu_to_be32(mode);
	di->di_uid = cpu_to_be32(uid);
	di->di_gid = cpu_to_be32(gid);
	di->di_nlink = 0;
	di->di_size = 0;
	di->di_blocks = cpu_to_be64(1);
	di->di_atime = di->di_mtime = di->di_ctime = cpu_to_be64(tv.tv_sec);
	di->di_major = cpu_to_be32(MAJOR(dev));
	di->di_minor = cpu_to_be32(MINOR(dev));
	di->di_goal_meta = di->di_goal_data = cpu_to_be64(inum->no_addr);
	di->di_generation = cpu_to_be64(*generation);
	di->di_flags = 0;

	if (S_ISREG(mode)) {
		if ((dip->i_di.di_flags & GFS2_DIF_INHERIT_JDATA) ||
		    gfs2_tune_get(sdp, gt_new_files_jdata))
			di->di_flags |= cpu_to_be32(GFS2_DIF_JDATA);
	} else if (S_ISDIR(mode)) {
		di->di_flags |= cpu_to_be32(dip->i_di.di_flags &
					    GFS2_DIF_INHERIT_JDATA);
	}

	di->__pad1 = 0;
	di->di_payload_format = cpu_to_be32(S_ISDIR(mode) ? GFS2_FORMAT_DE : 0);
	di->di_height = 0;
	di->__pad2 = 0;
	di->__pad3 = 0;
	di->di_depth = 0;
	di->di_entries = 0;
	memset(&di->__pad4, 0, sizeof(di->__pad4));
	di->di_eattr = 0;
	di->di_atime_nsec = cpu_to_be32(tv.tv_nsec);
	di->di_mtime_nsec = cpu_to_be32(tv.tv_nsec);
	di->di_ctime_nsec = cpu_to_be32(tv.tv_nsec);
	memset(&di->di_reserved, 0, sizeof(di->di_reserved));
	
	set_buffer_uptodate(dibh);

	*bhp = dibh;
}

static int make_dinode(struct gfs2_inode *dip, struct gfs2_glock *gl,
		       unsigned int mode, const struct gfs2_inum_host *inum,
		       const u64 *generation, dev_t dev, struct buffer_head **bhp)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	unsigned int uid, gid;
	int error;

	munge_mode_uid_gid(dip, &mode, &uid, &gid);
	if (!gfs2_alloc_get(dip))
		return -ENOMEM;

	error = gfs2_quota_lock(dip, uid, gid);
	if (error)
		goto out;

	error = gfs2_quota_check(dip, uid, gid);
	if (error)
		goto out_quota;

	error = gfs2_trans_begin(sdp, RES_DINODE + RES_QUOTA, 0);
	if (error)
		goto out_quota;

	init_dinode(dip, gl, inum, mode, uid, gid, generation, dev, bhp);
	gfs2_quota_change(dip, +1, uid, gid);
	gfs2_trans_end(sdp);

out_quota:
	gfs2_quota_unlock(dip);
out:
	gfs2_alloc_put(dip);
	return error;
}

static int link_dinode(struct gfs2_inode *dip, const struct qstr *name,
		       struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_alloc *al;
	int alloc_required;
	struct buffer_head *dibh;
	int error;

	al = gfs2_alloc_get(dip);
	if (!al)
		return -ENOMEM;

	error = gfs2_quota_lock(dip, NO_QUOTA_CHANGE, NO_QUOTA_CHANGE);
	if (error)
		goto fail;

	error = alloc_required = gfs2_diradd_alloc_required(&dip->i_inode, name);
	if (alloc_required < 0)
		goto fail_quota_locks;
	if (alloc_required) {
		error = gfs2_quota_check(dip, dip->i_inode.i_uid, dip->i_inode.i_gid);
		if (error)
			goto fail_quota_locks;

		al->al_requested = sdp->sd_max_dirres;

		error = gfs2_inplace_reserve(dip);
		if (error)
			goto fail_quota_locks;

		error = gfs2_trans_begin(sdp, sdp->sd_max_dirres +
					 al->al_rgd->rd_length +
					 2 * RES_DINODE +
					 RES_STATFS + RES_QUOTA, 0);
	gfs2_inplace_release(ip);
out_quota:
	gfs2_quota_unlock(ip);
out:
	return error;
}

static void gfs2_init_dir(struct buffer_head *dibh,
			  const struct gfs2_inode *parent)
{
	struct gfs2_dinode *di = (struct gfs2_dinode *)dibh->b_data;
	struct gfs2_dirent *dent = (struct gfs2_dirent *)(di+1);

	gfs2_qstr2dirent(&gfs2_qdot, GFS2_DIRENT_SIZE(gfs2_qdot.len), dent);
	dent->de_inum = di->di_num; /* already GFS2 endian */
	dent->de_type = cpu_to_be16(DT_DIR);

	dent = (struct gfs2_dirent *)((char*)dent + GFS2_DIRENT_SIZE(1));
	gfs2_qstr2dirent(&gfs2_qdotdot, dibh->b_size - GFS2_DIRENT_SIZE(1) - sizeof(struct gfs2_dinode), dent);
	gfs2_inum_out(parent, dent);
	dent->de_type = cpu_to_be16(DT_DIR);
	
}

/**
 * gfs2_init_xattr - Initialise an xattr block for a new inode
 * @ip: The inode in question
 *
 * This sets up an empty xattr block for a new inode, ready to
 * take any ACLs, LSM xattrs, etc.
 */

static void gfs2_init_xattr(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *bh;
	struct gfs2_ea_header *ea;

	bh = gfs2_meta_new(ip->i_gl, ip->i_eattr);
	gfs2_trans_add_meta(ip->i_gl, bh);
	gfs2_metatype_set(bh, GFS2_METATYPE_EA, GFS2_FORMAT_EA);
	gfs2_buffer_clear_tail(bh, sizeof(struct gfs2_meta_header));

	ea = GFS2_EA_BH2FIRST(bh);
	ea->ea_rec_len = cpu_to_be32(sdp->sd_jbsize);
	ea->ea_type = GFS2_EATYPE_UNUSED;
	ea->ea_flags = GFS2_EAFLAG_LAST;

	brelse(bh);
}

/**
 * init_dinode - Fill in a new dinode structure
 * @dip: The directory this inode is being created in
 * @ip: The inode
 * @symname: The symlink destination (if a symlink)
 * @bhp: The buffer head (returned to caller)
 *
 */

static void init_dinode(struct gfs2_inode *dip, struct gfs2_inode *ip,
			const char *symname)
{
	struct gfs2_dinode *di;
	struct buffer_head *dibh;

	dibh = gfs2_meta_new(ip->i_gl, ip->i_no_addr);
	gfs2_trans_add_meta(ip->i_gl, dibh);
	di = (struct gfs2_dinode *)dibh->b_data;
	gfs2_dinode_out(ip, di);

	di->di_major = cpu_to_be32(MAJOR(ip->i_inode.i_rdev));
	di->di_minor = cpu_to_be32(MINOR(ip->i_inode.i_rdev));
	di->__pad1 = 0;
	di->__pad2 = 0;
	di->__pad3 = 0;
	memset(&di->__pad4, 0, sizeof(di->__pad4));
	memset(&di->di_reserved, 0, sizeof(di->di_reserved));
	gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode));

	switch(ip->i_inode.i_mode & S_IFMT) {
	case S_IFDIR:
		gfs2_init_dir(dibh, dip);
		break;
	case S_IFLNK:
		memcpy(dibh->b_data + sizeof(struct gfs2_dinode), symname, ip->i_inode.i_size);
		break;
	}

	set_buffer_uptodate(dibh);
	brelse(dibh);
}

/**
 * gfs2_trans_da_blocks - Calculate number of blocks to link inode
 * @dip: The directory we are linking into
 * @da: The dir add information
 * @nr_inodes: The number of inodes involved
 *
 * This calculate the number of blocks we need to reserve in a
 * transaction to link @nr_inodes into a directory. In most cases
 * @nr_inodes will be 2 (the directory plus the inode being linked in)
 * but in case of rename, 4 may be required.
 *
 * Returns: Number of blocks
 */

static unsigned gfs2_trans_da_blks(const struct gfs2_inode *dip,
				   const struct gfs2_diradd *da,
				   unsigned nr_inodes)
{
	return da->nr_blocks + gfs2_rg_blocks(dip, da->nr_blocks) +
	       (nr_inodes * RES_DINODE) + RES_QUOTA + RES_STATFS;
}

static int link_dinode(struct gfs2_inode *dip, const struct qstr *name,
		       struct gfs2_inode *ip, struct gfs2_diradd *da)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_alloc_parms ap = { .target = da->nr_blocks, };
	int error;

	if (da->nr_blocks) {
		error = gfs2_quota_lock_check(dip, &ap);
		if (error)
			goto fail_quota_locks;

		error = gfs2_inplace_reserve(dip, &ap);
		if (error)
			goto fail_quota_locks;

		error = gfs2_trans_begin(sdp, gfs2_trans_da_blks(dip, da, 2), 0);
		if (error)
			goto fail_ipreserv;
	} else {
		error = gfs2_trans_begin(sdp, RES_LEAF + 2 * RES_DINODE, 0);
		if (error)
			goto fail_quota_locks;
	}

	error = gfs2_dir_add(&dip->i_inode, name, ip, IF2DT(ip->i_inode.i_mode));
	if (error)
		goto fail_end_trans;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto fail_end_trans;
	ip->i_inode.i_nlink = 1;
	gfs2_trans_add_bh(ip->i_gl, dibh, 1);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);
	return 0;

fail_end_trans:
	gfs2_trans_end(sdp);

fail_ipreserv:
	if (dip->i_alloc->al_rgd)
		gfs2_inplace_release(dip);

fail_quota_locks:
	gfs2_quota_unlock(dip);

fail:
	gfs2_alloc_put(dip);
	return error;
}

static int gfs2_security_init(struct gfs2_inode *dip, struct gfs2_inode *ip)
{
	int err;
	size_t len;
	void *value;
	char *name;
	struct gfs2_ea_request er;

	err = security_inode_init_security(&ip->i_inode, &dip->i_inode,
					   &name, &value, &len);

	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	memset(&er, 0, sizeof(struct gfs2_ea_request));

	er.er_type = GFS2_EATYPE_SECURITY;
	er.er_name = name;
	er.er_data = value;
	er.er_name_len = strlen(name);
	er.er_data_len = len;

	err = gfs2_ea_set_i(ip, &er);

	kfree(value);
	kfree(name);

	error = gfs2_dir_add(&dip->i_inode, name, ip, da);

	gfs2_trans_end(sdp);
fail_ipreserv:
	gfs2_inplace_release(dip);
fail_quota_locks:
	gfs2_quota_unlock(dip);
	return error;
}

static int gfs2_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		    void *fs_info)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = __gfs2_xattr_set(inode, xattr->name, xattr->value,
				       xattr->value_len, 0,
				       GFS2_EATYPE_SECURITY);
		if (err < 0)
			break;
	}
	return err;
}

/**
 * gfs2_createi - Create a new inode
 * @ghs: An array of two holders
 * @name: The name of the new file
 * @mode: the permissions on the new inode
 *
 * @ghs[0] is an initialized holder for the directory
 * @ghs[1] is the holder for the inode lock
 *
 * If the return value is not NULL, the glocks on both the directory and the new
 * file are held.  A transaction has been started and an inplace reservation
 * is held, as well.
 *
 * Returns: An inode
 */

struct inode *gfs2_createi(struct gfs2_holder *ghs, const struct qstr *name,
			   unsigned int mode, dev_t dev)
{
	struct inode *inode = NULL;
	struct gfs2_inode *dip = ghs->gh_gl->gl_object;
	struct inode *dir = &dip->i_inode;
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_inum_host inum = { .no_addr = 0, .no_formal_ino = 0 };
	int error;
	u64 generation;
	struct buffer_head *bh = NULL;

	if (!name->len || name->len > GFS2_FNAMESIZE)
		return ERR_PTR(-ENAMETOOLONG);

	gfs2_holder_reinit(LM_ST_EXCLUSIVE, 0, ghs);
	error = gfs2_glock_nq(ghs);
 * gfs2_create_inode - Create a new inode
 * @dir: The parent directory
 * @dentry: The new dentry
 * @file: If non-NULL, the file which is being opened
 * @mode: The permissions on the new inode
 * @dev: For device nodes, this is the device number
 * @symname: For symlinks, this is the link destination
 * @size: The initial size of the inode (ignored for directories)
 *
 * Returns: 0 on success, or error code
 */

static int gfs2_create_inode(struct inode *dir, struct dentry *dentry,
			     struct file *file,
			     umode_t mode, dev_t dev, const char *symname,
			     unsigned int size, int excl)
{
	const struct qstr *name = &dentry->d_name;
	struct posix_acl *default_acl, *acl;
	struct gfs2_holder ghs[2];
	struct inode *inode = NULL;
	struct gfs2_inode *dip = GFS2_I(dir), *ip;
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_glock *io_gl = NULL;
	int error, free_vfs_inode = 1;
	u32 aflags = 0;
	unsigned blocks = 1;
	struct gfs2_diradd da = { .bh = NULL, .save_loc = 1, };

	if (!name->len || name->len > GFS2_FNAMESIZE)
		return -ENAMETOOLONG;

	error = gfs2_rsqa_alloc(dip);
	if (error)
		return error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	if (error)
		goto fail;
	gfs2_holder_mark_uninitialized(ghs + 1);

	error = create_ok(dip, name, mode);
	if (error)
		goto fail_gunlock;

	error = pick_formal_ino(sdp, &inum.no_formal_ino);
	if (error)
		goto fail_gunlock;

	error = alloc_dinode(dip, &inum.no_addr, &generation);
	if (error)
		goto fail_gunlock;

	error = gfs2_glock_nq_num(sdp, inum.no_addr, &gfs2_inode_glops,
				  LM_ST_EXCLUSIVE, GL_SKIP, ghs + 1);
	if (error)
		goto fail_gunlock;

	error = make_dinode(dip, ghs[1].gh_gl, mode, &inum, &generation, dev, &bh);
	if (error)
		goto fail_gunlock2;

	inode = gfs2_inode_lookup(dir->i_sb, IF2DT(mode),
					inum.no_addr,
					inum.no_formal_ino, 0);
	if (IS_ERR(inode))
		goto fail_gunlock2;

	error = gfs2_inode_refresh(GFS2_I(inode));
	if (error)
		goto fail_gunlock2;

	error = gfs2_acl_create(dip, GFS2_I(inode));
	if (error)
		goto fail_gunlock2;

	error = gfs2_security_init(dip, GFS2_I(inode));
	if (error)
		goto fail_gunlock2;

	error = link_dinode(dip, name, GFS2_I(inode));
	if (error)
		goto fail_gunlock2;

	if (bh)
		brelse(bh);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	return inode;

fail_gunlock2:
	gfs2_glock_dq_uninit(ghs + 1);
	if (inode)
		iput(inode);
fail_gunlock:
	gfs2_glock_dq(ghs);
fail:
	if (bh)
		brelse(bh);
	return ERR_PTR(error);
}

/**
 * gfs2_rmdiri - Remove a directory
 * @dip: The parent directory of the directory to be removed
 * @name: The name of the directory to be removed
 * @ip: The GFS2 inode of the directory to be removed
 *
 * Assumes Glocks on dip and ip are held
	inode = gfs2_dir_search(dir, &dentry->d_name, !S_ISREG(mode) || excl);
	error = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		if (S_ISDIR(inode->i_mode)) {
			iput(inode);
			inode = ERR_PTR(-EISDIR);
			goto fail_gunlock;
		}
		d_instantiate(dentry, inode);
		error = 0;
		if (file) {
			if (S_ISREG(inode->i_mode))
				error = finish_open(file, dentry, gfs2_open_common);
			else
				error = finish_no_open(file, NULL);
		}
		gfs2_glock_dq_uninit(ghs);
		return error;
	} else if (error != -ENOENT) {
		goto fail_gunlock;
	}

	error = gfs2_diradd_alloc_required(dir, name, &da);
	if (error < 0)
		goto fail_gunlock;

	inode = new_inode(sdp->sd_vfs);
	error = -ENOMEM;
	if (!inode)
		goto fail_gunlock;

	error = posix_acl_create(dir, &mode, &default_acl, &acl);
	if (error)
		goto fail_gunlock;

	ip = GFS2_I(inode);
	error = gfs2_rsqa_alloc(ip);
	if (error)
		goto fail_free_acls;

	inode->i_mode = mode;
	set_nlink(inode, S_ISDIR(mode) ? 2 : 1);
	inode->i_rdev = dev;
	inode->i_size = size;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	gfs2_set_inode_blocks(inode, 1);
	munge_mode_uid_gid(dip, inode);
	check_and_update_goal(dip);
	ip->i_goal = dip->i_goal;
	ip->i_diskflags = 0;
	ip->i_eattr = 0;
	ip->i_height = 0;
	ip->i_depth = 0;
	ip->i_entries = 0;
	ip->i_no_addr = 0; /* Temporarily zero until real addr is assigned */

	switch(mode & S_IFMT) {
	case S_IFREG:
		if ((dip->i_diskflags & GFS2_DIF_INHERIT_JDATA) ||
		    gfs2_tune_get(sdp, gt_new_files_jdata))
			ip->i_diskflags |= GFS2_DIF_JDATA;
		gfs2_set_aops(inode);
		break;
	case S_IFDIR:
		ip->i_diskflags |= (dip->i_diskflags & GFS2_DIF_INHERIT_JDATA);
		ip->i_diskflags |= GFS2_DIF_JDATA;
		ip->i_entries = 2;
		break;
	}

	/* Force SYSTEM flag on all files and subdirs of a SYSTEM directory */
	if (dip->i_diskflags & GFS2_DIF_SYSTEM)
		ip->i_diskflags |= GFS2_DIF_SYSTEM;

	gfs2_set_inode_flags(inode);

	if ((GFS2_I(d_inode(sdp->sd_root_dir)) == dip) ||
	    (dip->i_diskflags & GFS2_DIF_TOPDIR))
		aflags |= GFS2_AF_ORLOV;

	if (default_acl || acl)
		blocks++;

	error = alloc_dinode(ip, aflags, &blocks);
	if (error)
		goto fail_free_inode;

	gfs2_set_inode_blocks(inode, blocks);

	error = gfs2_glock_get(sdp, ip->i_no_addr, &gfs2_inode_glops, CREATE, &ip->i_gl);
	if (error)
		goto fail_free_inode;
	flush_delayed_work(&ip->i_gl->gl_work);
	glock_set_object(ip->i_gl, ip);

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, GL_SKIP, ghs + 1);
	if (error)
		goto fail_free_inode;

	error = gfs2_trans_begin(sdp, blocks, 0);
	if (error)
		goto fail_gunlock2;

	if (blocks > 1) {
		ip->i_eattr = ip->i_no_addr + 1;
		gfs2_init_xattr(ip);
	}
	init_dinode(dip, ip, symname);
	gfs2_trans_end(sdp);

	error = gfs2_glock_get(sdp, ip->i_no_addr, &gfs2_iopen_glops, CREATE, &io_gl);
	if (error)
		goto fail_gunlock2;

	BUG_ON(test_and_set_bit(GLF_INODE_CREATING, &io_gl->gl_flags));

	error = gfs2_glock_nq_init(io_gl, LM_ST_SHARED, GL_EXACT, &ip->i_iopen_gh);
	if (error)
		goto fail_gunlock2;

	glock_set_object(ip->i_iopen_gh.gh_gl, ip);
	gfs2_glock_put(io_gl);
	gfs2_set_iop(inode);
	insert_inode_hash(inode);

	free_vfs_inode = 0; /* After this point, the inode is no longer
			       considered free. Any failures need to undo
			       the gfs2 structures. */
	if (default_acl) {
		error = __gfs2_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		if (error)
			goto fail_gunlock3;
		posix_acl_release(default_acl);
		default_acl = NULL;
	}
	if (acl) {
		error = __gfs2_set_acl(inode, acl, ACL_TYPE_ACCESS);
		if (error)
			goto fail_gunlock3;
		posix_acl_release(acl);
		acl = NULL;
	}

	error = security_inode_init_security(&ip->i_inode, &dip->i_inode, name,
					     &gfs2_initxattrs, NULL);
	if (error)
		goto fail_gunlock3;

	error = link_dinode(dip, name, ip, &da);
	if (error)
		goto fail_gunlock3;

	mark_inode_dirty(inode);
	d_instantiate(dentry, inode);
	if (file) {
		file->f_mode |= FMODE_CREATED;
		error = finish_open(file, dentry, gfs2_open_common);
	}
	gfs2_glock_dq_uninit(ghs);
	gfs2_glock_dq_uninit(ghs + 1);
	clear_bit(GLF_INODE_CREATING, &io_gl->gl_flags);
	return error;

fail_gunlock3:
	glock_clear_object(io_gl, ip);
	gfs2_glock_dq_uninit(&ip->i_iopen_gh);
	gfs2_glock_put(io_gl);
fail_gunlock2:
	if (io_gl)
		clear_bit(GLF_INODE_CREATING, &io_gl->gl_flags);
fail_free_inode:
	if (ip->i_gl) {
		glock_clear_object(ip->i_gl, ip);
		gfs2_glock_put(ip->i_gl);
	}
	gfs2_rsqa_delete(ip, NULL);
fail_free_acls:
	posix_acl_release(default_acl);
	posix_acl_release(acl);
fail_gunlock:
	gfs2_dir_no_add(&da);
	gfs2_glock_dq_uninit(ghs);
	if (inode && !IS_ERR(inode)) {
		clear_nlink(inode);
		if (!free_vfs_inode)
			mark_inode_dirty(inode);
		set_bit(free_vfs_inode ? GIF_FREE_VFS_INODE : GIF_ALLOC_FAILED,
			&GFS2_I(inode)->i_flags);
		iput(inode);
	}
	if (gfs2_holder_initialized(ghs + 1))
		gfs2_glock_dq_uninit(ghs + 1);
fail:
	return error;
}

/**
 * gfs2_create - Create a file
 * @dir: The directory in which to create the file
 * @dentry: The dentry of the new file
 * @mode: The mode of the new file
 *
 * Returns: errno
 */

int gfs2_rmdiri(struct gfs2_inode *dip, const struct qstr *name,
		struct gfs2_inode *ip)
{
	struct qstr dotname;
	int error;

	if (ip->i_di.di_entries != 2) {
		if (gfs2_consist_inode(ip))
			gfs2_dinode_print(ip);
		return -EIO;
	}

	error = gfs2_dir_del(dip, name);
	if (error)
		return error;

	error = gfs2_change_nlink(dip, -1);
	if (error)
		return error;

	gfs2_str2qstr(&dotname, ".");
	error = gfs2_dir_del(ip, &dotname);
	if (error)
		return error;

	gfs2_str2qstr(&dotname, "..");
	error = gfs2_dir_del(ip, &dotname);
	if (error)
		return error;

	/* It looks odd, but it really should be done twice */
	error = gfs2_change_nlink(ip, -1);
	if (error)
		return error;

	error = gfs2_change_nlink(ip, -1);
	if (error)
		return error;

static int gfs2_create(struct inode *dir, struct dentry *dentry,
		       umode_t mode, bool excl)
{
	return gfs2_create_inode(dir, dentry, NULL, S_IFREG | mode, 0, NULL, 0, excl);
}

/**
 * __gfs2_lookup - Look up a filename in a directory and return its inode
 * @dir: The directory inode
 * @dentry: The dentry of the new inode
 * @file: File to be opened
 *
 *
 * Returns: errno
 */

static struct dentry *__gfs2_lookup(struct inode *dir, struct dentry *dentry,
				    struct file *file)
{
	struct inode *inode;
	struct dentry *d;
	struct gfs2_holder gh;
	struct gfs2_glock *gl;
	int error;

	inode = gfs2_lookupi(dir, &dentry->d_name, 0);
	if (inode == NULL) {
		d_add(dentry, NULL);
		return NULL;
	}
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	gl = GFS2_I(inode)->i_gl;
	error = gfs2_glock_nq_init(gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
	if (error) {
		iput(inode);
		return ERR_PTR(error);
	}

	d = d_splice_alias(inode, dentry);
	if (IS_ERR(d)) {
		gfs2_glock_dq_uninit(&gh);
		return d;
	}
	if (file && S_ISREG(inode->i_mode))
		error = finish_open(file, dentry, gfs2_open_common);

	gfs2_glock_dq_uninit(&gh);
	if (error) {
		dput(d);
		return ERR_PTR(error);
	}
	return d;
}

static struct dentry *gfs2_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned flags)
{
	return __gfs2_lookup(dir, dentry, NULL);
}

/**
 * gfs2_link - Link to a file
 * @old_dentry: The inode to link
 * @dir: Add link to this directory
 * @dentry: The name of the link
 *
 * Link the inode in "old_dentry" into the directory "dir" with the
 * name in "dentry".
 *
 * Returns: errno
 */

static int gfs2_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	struct inode *inode = d_inode(old_dentry);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder ghs[2];
	struct buffer_head *dibh;
	struct gfs2_diradd da = { .bh = NULL, .save_loc = 1, };
	int error;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = gfs2_rsqa_alloc(dip);
	if (error)
		return error;

	gfs2_holder_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + 1);

	error = gfs2_glock_nq(ghs); /* parent */
	if (error)
		goto out_parent;

	error = gfs2_glock_nq(ghs + 1); /* child */
	if (error)
		goto out_child;

	error = -ENOENT;
	if (inode->i_nlink == 0)
		goto out_gunlock;

	error = gfs2_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out_gunlock;

	error = gfs2_dir_check(dir, &dentry->d_name, NULL);
	switch (error) {
	case -ENOENT:
		break;
	case 0:
		error = -EEXIST;
	default:
		goto out_gunlock;
	}

	error = -EINVAL;
	if (!dip->i_inode.i_nlink)
		goto out_gunlock;
	error = -EFBIG;
	if (dip->i_entries == (u32)-1)
		goto out_gunlock;
	error = -EPERM;
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		goto out_gunlock;
	error = -EINVAL;
	if (!ip->i_inode.i_nlink)
		goto out_gunlock;
	error = -EMLINK;
	if (ip->i_inode.i_nlink == (u32)-1)
		goto out_gunlock;

	error = gfs2_diradd_alloc_required(dir, &dentry->d_name, &da);
	if (error < 0)
		goto out_gunlock;

	if (da.nr_blocks) {
		struct gfs2_alloc_parms ap = { .target = da.nr_blocks, };
		error = gfs2_quota_lock_check(dip, &ap);
		if (error)
			goto out_gunlock;

		error = gfs2_inplace_reserve(dip, &ap);
		if (error)
			goto out_gunlock_q;

		error = gfs2_trans_begin(sdp, gfs2_trans_da_blks(dip, &da, 2), 0);
		if (error)
			goto out_ipres;
	} else {
		error = gfs2_trans_begin(sdp, 2 * RES_DINODE + RES_LEAF, 0);
		if (error)
			goto out_ipres;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_add(dir, &dentry->d_name, ip, &da);
	if (error)
		goto out_brelse;

	gfs2_trans_add_meta(ip->i_gl, dibh);
	inc_nlink(&ip->i_inode);
	ip->i_inode.i_ctime = current_time(&ip->i_inode);
	ihold(inode);
	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);

out_brelse:
	brelse(dibh);
out_end_trans:
	gfs2_trans_end(sdp);
out_ipres:
	if (da.nr_blocks)
		gfs2_inplace_release(dip);
out_gunlock_q:
	if (da.nr_blocks)
		gfs2_quota_unlock(dip);
out_gunlock:
	gfs2_dir_no_add(&da);
	gfs2_glock_dq(ghs + 1);
out_child:
	gfs2_glock_dq(ghs);
out_parent:
	gfs2_holder_uninit(ghs);
	gfs2_holder_uninit(ghs + 1);
	return error;
}

/*
 * gfs2_unlink_ok - check to see that a inode is still in a directory
 * @dip: the directory
 * @name: the name of the file
 * @ip: the inode
 *
 * Assumes that the lock on (at least) @dip is held.
 *
 * Returns: 0 if the parent/child relationship is correct, errno if it isn't
 */

int gfs2_unlink_ok(struct gfs2_inode *dip, const struct qstr *name,
		   const struct gfs2_inode *ip)
static int gfs2_unlink_ok(struct gfs2_inode *dip, const struct qstr *name,
			  const struct gfs2_inode *ip)
{
	int error;

	if (IS_IMMUTABLE(&ip->i_inode) || IS_APPEND(&ip->i_inode))
		return -EPERM;

	if ((dip->i_inode.i_mode & S_ISVTX) &&
	    dip->i_inode.i_uid != current->fsuid &&
	    ip->i_inode.i_uid != current->fsuid && !capable(CAP_FOWNER))
	    !uid_eq(dip->i_inode.i_uid, current_fsuid()) &&
	    !uid_eq(ip->i_inode.i_uid, current_fsuid()) && !capable(CAP_FOWNER))
		return -EPERM;

	if (IS_APPEND(&dip->i_inode))
		return -EPERM;

	error = gfs2_permission(&dip->i_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	error = gfs2_dir_check(&dip->i_inode, name, ip);
	if (error)
		return error;

	return 0;
}

	return gfs2_dir_check(&dip->i_inode, name, ip);
}

/**
 * gfs2_unlink_inode - Removes an inode from its parent dir and unlinks it
 * @dip: The parent directory
 * @name: The name of the entry in the parent directory
 * @inode: The inode to be removed
 *
 * Called with all the locks and in a transaction. This will only be
 * called for a directory after it has been checked to ensure it is empty.
 *
 * Returns: 0 on success, or an error
 */

static int gfs2_unlink_inode(struct gfs2_inode *dip,
			     const struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct gfs2_inode *ip = GFS2_I(inode);
	int error;

	error = gfs2_dir_del(dip, dentry);
	if (error)
		return error;

	ip->i_entries = 0;
	inode->i_ctime = current_time(inode);
	if (S_ISDIR(inode->i_mode))
		clear_nlink(inode);
	else
		drop_nlink(inode);
	mark_inode_dirty(inode);
	if (inode->i_nlink == 0)
		gfs2_unlink_di(inode);
	return 0;
}


/**
 * gfs2_unlink - Unlink an inode (this does rmdir as well)
 * @dir: The inode of the directory containing the inode to unlink
 * @dentry: The file itself
 *
 * This routine uses the type of the inode as a flag to figure out
 * whether this is an unlink or an rmdir.
 *
 * Returns: errno
 */

static int gfs2_unlink(struct inode *dir, struct dentry *dentry)
{
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	struct inode *inode = d_inode(dentry);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder ghs[3];
	struct gfs2_rgrpd *rgd;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = -EROFS;

	gfs2_holder_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	gfs2_holder_init(ip->i_gl,  LM_ST_EXCLUSIVE, 0, ghs + 1);

	rgd = gfs2_blk2rgrpd(sdp, ip->i_no_addr, 1);
	if (!rgd)
		goto out_inodes;

	gfs2_holder_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, ghs + 2);


	error = gfs2_glock_nq(ghs); /* parent */
	if (error)
		goto out_parent;

	error = gfs2_glock_nq(ghs + 1); /* child */
	if (error)
		goto out_child;

	error = -ENOENT;
	if (inode->i_nlink == 0)
		goto out_rgrp;

	if (S_ISDIR(inode->i_mode)) {
		error = -ENOTEMPTY;
		if (ip->i_entries > 2 || inode->i_nlink > 2)
			goto out_rgrp;
	}

	error = gfs2_glock_nq(ghs + 2); /* rgrp */
	if (error)
		goto out_rgrp;

	error = gfs2_unlink_ok(dip, &dentry->d_name, ip);
	if (error)
		goto out_gunlock;

	error = gfs2_trans_begin(sdp, 2*RES_DINODE + 3*RES_LEAF + RES_RG_BIT, 0);
	if (error)
		goto out_gunlock;

	error = gfs2_unlink_inode(dip, dentry);
	gfs2_trans_end(sdp);

out_gunlock:
	gfs2_glock_dq(ghs + 2);
out_rgrp:
	gfs2_glock_dq(ghs + 1);
out_child:
	gfs2_glock_dq(ghs);
out_parent:
	gfs2_holder_uninit(ghs + 2);
out_inodes:
	gfs2_holder_uninit(ghs + 1);
	gfs2_holder_uninit(ghs);
	return error;
}

/**
 * gfs2_symlink - Create a symlink
 * @dir: The directory to create the symlink in
 * @dentry: The dentry to put the symlink in
 * @symname: The thing which the link points to
 *
 * Returns: errno
 */

static int gfs2_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	unsigned int size;

	size = strlen(symname);
	if (size >= gfs2_max_stuffed_size(GFS2_I(dir)))
		return -ENAMETOOLONG;

	return gfs2_create_inode(dir, dentry, NULL, S_IFLNK | S_IRWXUGO, 0, symname, size, 0);
}

/**
 * gfs2_mkdir - Make a directory
 * @dir: The parent directory of the new one
 * @dentry: The dentry of the new directory
 * @mode: The mode of the new directory
 *
 * Returns: errno
 */

static int gfs2_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	unsigned dsize = gfs2_max_stuffed_size(GFS2_I(dir));
	return gfs2_create_inode(dir, dentry, NULL, S_IFDIR | mode, 0, NULL, dsize, 0);
}

/**
 * gfs2_mknod - Make a special file
 * @dir: The directory in which the special file will reside
 * @dentry: The dentry of the special file
 * @mode: The mode of the special file
 * @dev: The device specification of the special file
 *
 */

static int gfs2_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		      dev_t dev)
{
	return gfs2_create_inode(dir, dentry, NULL, mode, dev, NULL, 0, 0);
}

/**
 * gfs2_atomic_open - Atomically open a file
 * @dir: The directory
 * @dentry: The proposed new entry
 * @file: The proposed new struct file
 * @flags: open flags
 * @mode: File mode
 *
 * Returns: error code or 0 for success
 */

static int gfs2_atomic_open(struct inode *dir, struct dentry *dentry,
			    struct file *file, unsigned flags,
			    umode_t mode)
{
	struct dentry *d;
	bool excl = !!(flags & O_EXCL);

	if (!d_in_lookup(dentry))
		goto skip_lookup;

	d = __gfs2_lookup(dir, dentry, file);
	if (IS_ERR(d))
		return PTR_ERR(d);
	if (d != NULL)
		dentry = d;
	if (d_really_is_positive(dentry)) {
		if (!(file->f_mode & FMODE_OPENED))
			return finish_no_open(file, d);
		dput(d);
		return 0;
	}

	BUG_ON(d != NULL);

skip_lookup:
	if (!(flags & O_CREAT))
		return -ENOENT;

	return gfs2_create_inode(dir, dentry, file, S_IFREG | mode, 0, NULL, 0, excl);
}

/*
 * gfs2_ok_to_move - check if it's ok to move a directory to another directory
 * @this: move this
 * @to: to here
 *
 * Follow @to back to the root and make sure we don't encounter @this
 * Assumes we already hold the rename lock.
 *
 * Returns: errno
 */

int gfs2_ok_to_move(struct gfs2_inode *this, struct gfs2_inode *to)
static int gfs2_ok_to_move(struct gfs2_inode *this, struct gfs2_inode *to)
{
	struct inode *dir = &to->i_inode;
	struct super_block *sb = dir->i_sb;
	struct inode *tmp;
	struct qstr dotdot;
	int error = 0;

	gfs2_str2qstr(&dotdot, "..");

	int error = 0;

	igrab(dir);

	for (;;) {
		if (dir == &this->i_inode) {
			error = -EINVAL;
			break;
		}
		if (dir == sb->s_root->d_inode) {
		if (dir == d_inode(sb->s_root)) {
			error = 0;
			break;
		}

		tmp = gfs2_lookupi(dir, &dotdot, 1);
		tmp = gfs2_lookupi(dir, &gfs2_qdotdot, 1);
		if (!tmp) {
			error = -ENOENT;
			break;
		}
		if (IS_ERR(tmp)) {
			error = PTR_ERR(tmp);
			break;
		}

		iput(dir);
		dir = tmp;
	}

	iput(dir);

	return error;
}

/**
 * gfs2_readlinki - return the contents of a symlink
 * @ip: the symlink's inode
 * @buf: a pointer to the buffer to be filled
 * @len: a pointer to the length of @buf
 *
 * If @buf is too small, a piece of memory is kmalloc()ed and needs
 * to be freed by the caller.
 * update_moved_ino - Update an inode that's being moved
 * @ip: The inode being moved
 * @ndip: The parent directory of the new filename
 * @dir_rename: True of ip is a directory
 *
 * Returns: errno
 */

int gfs2_readlinki(struct gfs2_inode *ip, char **buf, unsigned int *len)
{
	struct gfs2_holder i_gh;
	struct buffer_head *dibh;
	unsigned int x;
	int error;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, GL_ATIME, &i_gh);
	error = gfs2_glock_nq_atime(&i_gh);
	if (error) {
		gfs2_holder_uninit(&i_gh);
		return error;
	}

	if (!ip->i_di.di_size) {
		gfs2_consist_inode(ip);
		error = -EIO;
		goto out;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out;

	x = ip->i_di.di_size + 1;
	if (x > *len) {
		*buf = kmalloc(x, GFP_NOFS);
		if (!*buf) {
			error = -ENOMEM;
			goto out_brelse;
		}
	}

	memcpy(*buf, dibh->b_data + sizeof(struct gfs2_dinode), x);
	*len = x;

out_brelse:
	brelse(dibh);
out:
	gfs2_glock_dq_uninit(&i_gh);
static int update_moved_ino(struct gfs2_inode *ip, struct gfs2_inode *ndip,
			    int dir_rename)
{
	if (dir_rename)
		return gfs2_dir_mvino(ip, &gfs2_qdotdot, ndip, DT_DIR);

	ip->i_inode.i_ctime = current_time(&ip->i_inode);
	mark_inode_dirty_sync(&ip->i_inode);
	return 0;
}


/**
 * gfs2_rename - Rename a file
 * @odir: Parent directory of old file name
 * @odentry: The old dentry of the file
 * @ndir: Parent directory of new file name
 * @ndentry: The new dentry of the file
 *
 * Returns: errno
 */

static int gfs2_rename(struct inode *odir, struct dentry *odentry,
		       struct inode *ndir, struct dentry *ndentry)
{
	struct gfs2_inode *odip = GFS2_I(odir);
	struct gfs2_inode *ndip = GFS2_I(ndir);
	struct gfs2_inode *ip = GFS2_I(d_inode(odentry));
	struct gfs2_inode *nip = NULL;
	struct gfs2_sbd *sdp = GFS2_SB(odir);
	struct gfs2_holder ghs[5], r_gh;
	struct gfs2_rgrpd *nrgd;
	unsigned int num_gh;
	int dir_rename = 0;
	struct gfs2_diradd da = { .nr_blocks = 0, .save_loc = 0, };
	unsigned int x;
	int error;

	gfs2_holder_mark_uninitialized(&r_gh);
	if (d_really_is_positive(ndentry)) {
		nip = GFS2_I(d_inode(ndentry));
		if (ip == nip)
			return 0;
	}

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_rsqa_alloc(ndip);
	if (error)
		return error;

	if (odip != ndip) {
		error = gfs2_glock_nq_init(sdp->sd_rename_gl, LM_ST_EXCLUSIVE,
					   0, &r_gh);
		if (error)
			goto out;

		if (S_ISDIR(ip->i_inode.i_mode)) {
			dir_rename = 1;
			/* don't move a directory into its subdir */
			error = gfs2_ok_to_move(ip, ndip);
			if (error)
				goto out_gunlock_r;
		}
	}

	num_gh = 1;
	gfs2_holder_init(odip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	if (odip != ndip) {
		gfs2_holder_init(ndip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
	}
	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
	num_gh++;

	if (nip) {
		gfs2_holder_init(nip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
		/* grab the resource lock for unlink flag twiddling 
		 * this is the case of the target file already existing
		 * so we unlink before doing the rename
		 */
		nrgd = gfs2_blk2rgrpd(sdp, nip->i_no_addr, 1);
		if (nrgd)
			gfs2_holder_init(nrgd->rd_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh++);
	}

	for (x = 0; x < num_gh; x++) {
		error = gfs2_glock_nq(ghs + x);
		if (error)
			goto out_gunlock;
	}

	error = -ENOENT;
	if (ip->i_inode.i_nlink == 0)
		goto out_gunlock;

	/* Check out the old directory */

	error = gfs2_unlink_ok(odip, &odentry->d_name, ip);
	if (error)
		goto out_gunlock;

	/* Check out the new directory */

	if (nip) {
		error = gfs2_unlink_ok(ndip, &ndentry->d_name, nip);
		if (error)
			goto out_gunlock;

		if (nip->i_inode.i_nlink == 0) {
			error = -EAGAIN;
			goto out_gunlock;
		}

		if (S_ISDIR(nip->i_inode.i_mode)) {
			if (nip->i_entries < 2) {
				gfs2_consist_inode(nip);
				error = -EIO;
				goto out_gunlock;
			}
			if (nip->i_entries > 2) {
				error = -ENOTEMPTY;
				goto out_gunlock;
			}
		}
	} else {
		error = gfs2_permission(ndir, MAY_WRITE | MAY_EXEC);
		if (error)
			goto out_gunlock;

		error = gfs2_dir_check(ndir, &ndentry->d_name, NULL);
		switch (error) {
		case -ENOENT:
			error = 0;
			break;
		case 0:
			error = -EEXIST;
		default:
			goto out_gunlock;
		};

		if (odip != ndip) {
			if (!ndip->i_inode.i_nlink) {
				error = -ENOENT;
				goto out_gunlock;
			}
			if (ndip->i_entries == (u32)-1) {
				error = -EFBIG;
				goto out_gunlock;
			}
			if (S_ISDIR(ip->i_inode.i_mode) &&
			    ndip->i_inode.i_nlink == (u32)-1) {
				error = -EMLINK;
				goto out_gunlock;
			}
		}
	}

	/* Check out the dir to be renamed */

	if (dir_rename) {
		error = gfs2_permission(d_inode(odentry), MAY_WRITE);
		if (error)
			goto out_gunlock;
	}

	if (nip == NULL) {
		error = gfs2_diradd_alloc_required(ndir, &ndentry->d_name, &da);
		if (error)
			goto out_gunlock;
	}

	if (da.nr_blocks) {
		struct gfs2_alloc_parms ap = { .target = da.nr_blocks, };
		error = gfs2_quota_lock_check(ndip, &ap);
		if (error)
			goto out_gunlock;

		error = gfs2_inplace_reserve(ndip, &ap);
		if (error)
			goto out_gunlock_q;

		error = gfs2_trans_begin(sdp, gfs2_trans_da_blks(ndip, &da, 4) +
					 4 * RES_LEAF + 4, 0);
		if (error)
			goto out_ipreserv;
	} else {
		error = gfs2_trans_begin(sdp, 4 * RES_DINODE +
					 5 * RES_LEAF + 4, 0);
		if (error)
			goto out_gunlock;
	}

	/* Remove the target file, if it exists */

	if (nip)
		error = gfs2_unlink_inode(ndip, ndentry);

	error = update_moved_ino(ip, ndip, dir_rename);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_del(odip, odentry);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_add(ndir, &ndentry->d_name, ip, &da);
	if (error)
		goto out_end_trans;

out_end_trans:
	gfs2_trans_end(sdp);
out_ipreserv:
	if (da.nr_blocks)
		gfs2_inplace_release(ndip);
out_gunlock_q:
	if (da.nr_blocks)
		gfs2_quota_unlock(ndip);
out_gunlock:
	gfs2_dir_no_add(&da);
	while (x--) {
		gfs2_glock_dq(ghs + x);
		gfs2_holder_uninit(ghs + x);
	}
out_gunlock_r:
	if (gfs2_holder_initialized(&r_gh))
		gfs2_glock_dq_uninit(&r_gh);
out:
	return error;
}

/**
 * gfs2_glock_nq_atime - Acquire a hold on an inode's glock, and
 *       conditionally update the inode's atime
 * @gh: the holder to acquire
 *
 * Tests atime (access time) for gfs2_read, gfs2_readdir and gfs2_mmap
 * Update if the difference between the current time and the inode's current
 * atime is greater than an interval specified at mount.
 * gfs2_exchange - exchange two files
 * @odir: Parent directory of old file name
 * @odentry: The old dentry of the file
 * @ndir: Parent directory of new file name
 * @ndentry: The new dentry of the file
 * @flags: The rename flags
 *
 * Returns: errno
 */

int gfs2_glock_nq_atime(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_inode *ip = gl->gl_object;
	s64 quantum = gfs2_tune_get(sdp, gt_atime_quantum);
	unsigned int state;
	int flags;
	int error;
	struct timespec tv = CURRENT_TIME;

	if (gfs2_assert_warn(sdp, gh->gh_flags & GL_ATIME) ||
	    gfs2_assert_warn(sdp, !(gh->gh_flags & GL_ASYNC)) ||
	    gfs2_assert_warn(sdp, gl->gl_ops == &gfs2_inode_glops))
		return -EINVAL;

	state = gh->gh_state;
	flags = gh->gh_flags;

	error = gfs2_glock_nq(gh);
	if (error)
		return error;

	if (test_bit(SDF_NOATIME, &sdp->sd_flags) ||
	    (sdp->sd_vfs->s_flags & MS_RDONLY))
		return 0;

	if (tv.tv_sec - ip->i_inode.i_atime.tv_sec >= quantum) {
		gfs2_glock_dq(gh);
		gfs2_holder_reinit(LM_ST_EXCLUSIVE, gh->gh_flags & ~LM_FLAG_ANY,
				   gh);
		error = gfs2_glock_nq(gh);
		if (error)
			return error;

		/* Verify that atime hasn't been updated while we were
		   trying to get exclusive lock. */

		tv = CURRENT_TIME;
		if (tv.tv_sec - ip->i_inode.i_atime.tv_sec >= quantum) {
			struct buffer_head *dibh;
			struct gfs2_dinode *di;

			error = gfs2_trans_begin(sdp, RES_DINODE, 0);
			if (error == -EROFS)
				return 0;
			if (error)
				goto fail;

			error = gfs2_meta_inode_buffer(ip, &dibh);
			if (error)
				goto fail_end_trans;

			ip->i_inode.i_atime = tv;

			gfs2_trans_add_bh(ip->i_gl, dibh, 1);
			di = (struct gfs2_dinode *)dibh->b_data;
			di->di_atime = cpu_to_be64(ip->i_inode.i_atime.tv_sec);
			di->di_atime_nsec = cpu_to_be32(ip->i_inode.i_atime.tv_nsec);
			brelse(dibh);

			gfs2_trans_end(sdp);
		}

		/* If someone else has asked for the glock,
		   unlock and let them have it. Then reacquire
		   in the original state. */
		if (gfs2_glock_is_blocking(gl)) {
			gfs2_glock_dq(gh);
			gfs2_holder_reinit(state, flags, gh);
			return gfs2_glock_nq(gh);
		}
	}

	return 0;

fail_end_trans:
	gfs2_trans_end(sdp);
fail:
	gfs2_glock_dq(gh);
	return error;
}

static int
__gfs2_setattr_simple(struct gfs2_inode *ip, struct iattr *attr)
{
	struct buffer_head *dibh;
	int error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		error = inode_setattr(&ip->i_inode, attr);
		gfs2_assert_warn(GFS2_SB(&ip->i_inode), !error);
		gfs2_trans_add_bh(ip->i_gl, dibh, 1);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}
	return error;
}

static int gfs2_exchange(struct inode *odir, struct dentry *odentry,
			 struct inode *ndir, struct dentry *ndentry,
			 unsigned int flags)
{
	struct gfs2_inode *odip = GFS2_I(odir);
	struct gfs2_inode *ndip = GFS2_I(ndir);
	struct gfs2_inode *oip = GFS2_I(odentry->d_inode);
	struct gfs2_inode *nip = GFS2_I(ndentry->d_inode);
	struct gfs2_sbd *sdp = GFS2_SB(odir);
	struct gfs2_holder ghs[5], r_gh;
	unsigned int num_gh;
	unsigned int x;
	umode_t old_mode = oip->i_inode.i_mode;
	umode_t new_mode = nip->i_inode.i_mode;
	int error;

	gfs2_holder_mark_uninitialized(&r_gh);
	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	if (odip != ndip) {
		error = gfs2_glock_nq_init(sdp->sd_rename_gl, LM_ST_EXCLUSIVE,
					   0, &r_gh);
		if (error)
			goto out;

		if (S_ISDIR(old_mode)) {
			/* don't move a directory into its subdir */
			error = gfs2_ok_to_move(oip, ndip);
			if (error)
				goto out_gunlock_r;
		}

		if (S_ISDIR(new_mode)) {
			/* don't move a directory into its subdir */
			error = gfs2_ok_to_move(nip, odip);
			if (error)
				goto out_gunlock_r;
		}
	}

	num_gh = 1;
	gfs2_holder_init(odip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	if (odip != ndip) {
		gfs2_holder_init(ndip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
	}
	gfs2_holder_init(oip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
	num_gh++;

	gfs2_holder_init(nip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
	num_gh++;

	for (x = 0; x < num_gh; x++) {
		error = gfs2_glock_nq(ghs + x);
		if (error)
			goto out_gunlock;
	}

	error = -ENOENT;
	if (oip->i_inode.i_nlink == 0 || nip->i_inode.i_nlink == 0)
		goto out_gunlock;

	error = gfs2_unlink_ok(odip, &odentry->d_name, oip);
	if (error)
		goto out_gunlock;
	error = gfs2_unlink_ok(ndip, &ndentry->d_name, nip);
	if (error)
		goto out_gunlock;

	if (S_ISDIR(old_mode)) {
		error = gfs2_permission(odentry->d_inode, MAY_WRITE);
		if (error)
			goto out_gunlock;
	}
	if (S_ISDIR(new_mode)) {
		error = gfs2_permission(ndentry->d_inode, MAY_WRITE);
		if (error)
			goto out_gunlock;
	}
	error = gfs2_trans_begin(sdp, 4 * RES_DINODE + 4 * RES_LEAF, 0);
	if (error)
		goto out_gunlock;

	error = update_moved_ino(oip, ndip, S_ISDIR(old_mode));
	if (error)
		goto out_end_trans;

	error = update_moved_ino(nip, odip, S_ISDIR(new_mode));
	if (error)
		goto out_end_trans;

	error = gfs2_dir_mvino(ndip, &ndentry->d_name, oip,
			       IF2DT(old_mode));
	if (error)
		goto out_end_trans;

	error = gfs2_dir_mvino(odip, &odentry->d_name, nip,
			       IF2DT(new_mode));
	if (error)
		goto out_end_trans;

	if (odip != ndip) {
		if (S_ISDIR(new_mode) && !S_ISDIR(old_mode)) {
			inc_nlink(&odip->i_inode);
			drop_nlink(&ndip->i_inode);
		} else if (S_ISDIR(old_mode) && !S_ISDIR(new_mode)) {
			inc_nlink(&ndip->i_inode);
			drop_nlink(&odip->i_inode);
		}
	}
	mark_inode_dirty(&ndip->i_inode);
	if (odip != ndip)
		mark_inode_dirty(&odip->i_inode);

out_end_trans:
	gfs2_trans_end(sdp);
out_gunlock:
	while (x--) {
		gfs2_glock_dq(ghs + x);
		gfs2_holder_uninit(ghs + x);
	}
out_gunlock_r:
	if (gfs2_holder_initialized(&r_gh))
		gfs2_glock_dq_uninit(&r_gh);
out:
	return error;
}

static int gfs2_rename2(struct inode *odir, struct dentry *odentry,
			struct inode *ndir, struct dentry *ndentry,
			unsigned int flags)
{
	flags &= ~RENAME_NOREPLACE;

	if (flags & ~RENAME_EXCHANGE)
		return -EINVAL;

	if (flags & RENAME_EXCHANGE)
		return gfs2_exchange(odir, odentry, ndir, ndentry, flags);

	return gfs2_rename(odir, odentry, ndir, ndentry);
}

/**
 * gfs2_get_link - Follow a symbolic link
 * @dentry: The dentry of the link
 * @inode: The inode of the link
 * @done: destructor for return value
 *
 * This can handle symlinks of any size.
 *
 * Returns: 0 on success or error code
 */

static const char *gfs2_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	struct buffer_head *dibh;
	unsigned int size;
	char *buf;
	int error;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &i_gh);
	error = gfs2_glock_nq(&i_gh);
	if (error) {
		gfs2_holder_uninit(&i_gh);
		return ERR_PTR(error);
	}

	size = (unsigned int)i_size_read(&ip->i_inode);
	if (size == 0) {
		gfs2_consist_inode(ip);
		buf = ERR_PTR(-EIO);
		goto out;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error) {
		buf = ERR_PTR(error);
		goto out;
	}

	buf = kzalloc(size + 1, GFP_NOFS);
	if (!buf)
		buf = ERR_PTR(-ENOMEM);
	else
		memcpy(buf, dibh->b_data + sizeof(struct gfs2_dinode), size);
	brelse(dibh);
out:
	gfs2_glock_dq_uninit(&i_gh);
	if (!IS_ERR(buf))
		set_delayed_call(done, kfree_link, buf);
	return buf;
}

/**
 * gfs2_permission -
 * @inode: The inode
 * @mask: The mask to be tested
 * @flags: Indicates whether this is an RCU path walk or not
 *
 * This may be called from the VFS directly, or from within GFS2 with the
 * inode locked, so we look to see if the glock is already locked and only
 * lock the glock if its not already been done.
 *
 * Returns: errno
 */

int gfs2_permission(struct inode *inode, int mask)
{
	struct gfs2_inode *ip;
	struct gfs2_holder i_gh;
	int error;

	gfs2_holder_mark_uninitialized(&i_gh);
	ip = GFS2_I(inode);
	if (gfs2_glock_is_locked_by_me(ip->i_gl) == NULL) {
		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &i_gh);
		if (error)
			return error;
	}

	if ((mask & MAY_WRITE) && IS_IMMUTABLE(inode))
		error = -EPERM;
	else
		error = generic_permission(inode, mask);
	if (gfs2_holder_initialized(&i_gh))
		gfs2_glock_dq_uninit(&i_gh);

	return error;
}

static int __gfs2_setattr_simple(struct inode *inode, struct iattr *attr)
{
	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

/**
 * gfs2_setattr_simple -
 * @ip:
 * @attr:
 *
 * Called with a reference on the vnode.
 *
 * Returns: errno
 */

int gfs2_setattr_simple(struct gfs2_inode *ip, struct iattr *attr)
 * Returns: errno
 */

int gfs2_setattr_simple(struct inode *inode, struct iattr *attr)
{
	int error;

	if (current->journal_info)
		return __gfs2_setattr_simple(ip, attr);

	error = gfs2_trans_begin(GFS2_SB(&ip->i_inode), RES_DINODE, 0);
	if (error)
		return error;

	error = __gfs2_setattr_simple(ip, attr);
	gfs2_trans_end(GFS2_SB(&ip->i_inode));
	return error;
}

void gfs2_dinode_out(const struct gfs2_inode *ip, void *buf)
{
	const struct gfs2_dinode_host *di = &ip->i_di;
	struct gfs2_dinode *str = buf;

	str->di_header.mh_magic = cpu_to_be32(GFS2_MAGIC);
	str->di_header.mh_type = cpu_to_be32(GFS2_METATYPE_DI);
	str->di_header.__pad0 = 0;
	str->di_header.mh_format = cpu_to_be32(GFS2_FORMAT_DI);
	str->di_header.__pad1 = 0;
	str->di_num.no_addr = cpu_to_be64(ip->i_no_addr);
	str->di_num.no_formal_ino = cpu_to_be64(ip->i_no_formal_ino);
	str->di_mode = cpu_to_be32(ip->i_inode.i_mode);
	str->di_uid = cpu_to_be32(ip->i_inode.i_uid);
	str->di_gid = cpu_to_be32(ip->i_inode.i_gid);
	str->di_nlink = cpu_to_be32(ip->i_inode.i_nlink);
	str->di_size = cpu_to_be64(di->di_size);
	str->di_blocks = cpu_to_be64(gfs2_get_inode_blocks(&ip->i_inode));
	str->di_atime = cpu_to_be64(ip->i_inode.i_atime.tv_sec);
	str->di_mtime = cpu_to_be64(ip->i_inode.i_mtime.tv_sec);
	str->di_ctime = cpu_to_be64(ip->i_inode.i_ctime.tv_sec);

	str->di_goal_meta = cpu_to_be64(ip->i_goal);
	str->di_goal_data = cpu_to_be64(ip->i_goal);
	str->di_generation = cpu_to_be64(di->di_generation);

	str->di_flags = cpu_to_be32(di->di_flags);
	str->di_height = cpu_to_be16(ip->i_height);
	str->di_payload_format = cpu_to_be32(S_ISDIR(ip->i_inode.i_mode) &&
					     !(ip->i_di.di_flags & GFS2_DIF_EXHASH) ?
					     GFS2_FORMAT_DE : 0);
	str->di_depth = cpu_to_be16(ip->i_depth);
	str->di_entries = cpu_to_be32(di->di_entries);

	str->di_eattr = cpu_to_be64(di->di_eattr);
	str->di_atime_nsec = cpu_to_be32(ip->i_inode.i_atime.tv_nsec);
	str->di_mtime_nsec = cpu_to_be32(ip->i_inode.i_mtime.tv_nsec);
	str->di_ctime_nsec = cpu_to_be32(ip->i_inode.i_ctime.tv_nsec);
}

void gfs2_dinode_print(const struct gfs2_inode *ip)
{
	const struct gfs2_dinode_host *di = &ip->i_di;

	printk(KERN_INFO "  no_formal_ino = %llu\n",
	       (unsigned long long)ip->i_no_formal_ino);
	printk(KERN_INFO "  no_addr = %llu\n",
	       (unsigned long long)ip->i_no_addr);
	printk(KERN_INFO "  di_size = %llu\n", (unsigned long long)di->di_size);
	printk(KERN_INFO "  blocks = %llu\n",
	       (unsigned long long)gfs2_get_inode_blocks(&ip->i_inode));
	printk(KERN_INFO "  i_goal = %llu\n",
	       (unsigned long long)ip->i_goal);
	printk(KERN_INFO "  di_flags = 0x%.8X\n", di->di_flags);
	printk(KERN_INFO "  i_height = %u\n", ip->i_height);
	printk(KERN_INFO "  i_depth = %u\n", ip->i_depth);
	printk(KERN_INFO "  di_entries = %u\n", di->di_entries);
	printk(KERN_INFO "  di_eattr = %llu\n",
	       (unsigned long long)di->di_eattr);
}

		return __gfs2_setattr_simple(inode, attr);

	error = gfs2_trans_begin(GFS2_SB(inode), RES_DINODE, 0);
	if (error)
		return error;

	error = __gfs2_setattr_simple(inode, attr);
	gfs2_trans_end(GFS2_SB(inode));
	return error;
}

static int setattr_chown(struct inode *inode, struct iattr *attr)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	kuid_t ouid, nuid;
	kgid_t ogid, ngid;
	int error;
	struct gfs2_alloc_parms ap;

	ouid = inode->i_uid;
	ogid = inode->i_gid;
	nuid = attr->ia_uid;
	ngid = attr->ia_gid;

	if (!(attr->ia_valid & ATTR_UID) || uid_eq(ouid, nuid))
		ouid = nuid = NO_UID_QUOTA_CHANGE;
	if (!(attr->ia_valid & ATTR_GID) || gid_eq(ogid, ngid))
		ogid = ngid = NO_GID_QUOTA_CHANGE;

	error = gfs2_rsqa_alloc(ip);
	if (error)
		goto out;

	error = gfs2_rindex_update(sdp);
	if (error)
		goto out;

	error = gfs2_quota_lock(ip, nuid, ngid);
	if (error)
		goto out;

	ap.target = gfs2_get_inode_blocks(&ip->i_inode);

	if (!uid_eq(ouid, NO_UID_QUOTA_CHANGE) ||
	    !gid_eq(ogid, NO_GID_QUOTA_CHANGE)) {
		error = gfs2_quota_check(ip, nuid, ngid, &ap);
		if (error)
			goto out_gunlock_q;
	}

	error = gfs2_trans_begin(sdp, RES_DINODE + 2 * RES_QUOTA, 0);
	if (error)
		goto out_gunlock_q;

	error = gfs2_setattr_simple(inode, attr);
	if (error)
		goto out_end_trans;

	if (!uid_eq(ouid, NO_UID_QUOTA_CHANGE) ||
	    !gid_eq(ogid, NO_GID_QUOTA_CHANGE)) {
		gfs2_quota_change(ip, -(s64)ap.target, ouid, ogid);
		gfs2_quota_change(ip, ap.target, nuid, ngid);
	}

out_end_trans:
	gfs2_trans_end(sdp);
out_gunlock_q:
	gfs2_quota_unlock(ip);
out:
	return error;
}

/**
 * gfs2_setattr - Change attributes on an inode
 * @dentry: The dentry which is changing
 * @attr: The structure describing the change
 *
 * The VFS layer wants to change one or more of an inodes attributes.  Write
 * that change out to disk.
 *
 * Returns: errno
 */

static int gfs2_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	int error;

	error = gfs2_rsqa_alloc(ip);
	if (error)
		return error;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &i_gh);
	if (error)
		return error;

	error = -EPERM;
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		goto out;

	error = setattr_prepare(dentry, attr);
	if (error)
		goto out;

	if (attr->ia_valid & ATTR_SIZE)
		error = gfs2_setattr_size(inode, attr->ia_size);
	else if (attr->ia_valid & (ATTR_UID | ATTR_GID))
		error = setattr_chown(inode, attr);
	else {
		error = gfs2_setattr_simple(inode, attr);
		if (!error && attr->ia_valid & ATTR_MODE)
			error = posix_acl_chmod(inode, inode->i_mode);
	}

out:
	if (!error)
		mark_inode_dirty(inode);
	gfs2_glock_dq_uninit(&i_gh);
	return error;
}

/**
 * gfs2_getattr - Read out an inode's attributes
 * @path: Object to query
 * @stat: The inode's stats
 * @request_mask: Mask of STATX_xxx flags indicating the caller's interests
 * @flags: AT_STATX_xxx setting
 *
 * This may be called from the VFS directly, or from within GFS2 with the
 * inode locked, so we look to see if the glock is already locked and only
 * lock the glock if its not already been done. Note that its the NFS
 * readdirplus operation which causes this to be called (from filldir)
 * with the glock already held.
 *
 * Returns: errno
 */

static int gfs2_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	u32 gfsflags;
	int error;

	gfs2_holder_mark_uninitialized(&gh);
	if (gfs2_glock_is_locked_by_me(ip->i_gl) == NULL) {
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
		if (error)
			return error;
	}

	gfsflags = ip->i_diskflags;
	if (gfsflags & GFS2_DIF_APPENDONLY)
		stat->attributes |= STATX_ATTR_APPEND;
	if (gfsflags & GFS2_DIF_IMMUTABLE)
		stat->attributes |= STATX_ATTR_IMMUTABLE;

	stat->attributes_mask |= (STATX_ATTR_APPEND |
				  STATX_ATTR_COMPRESSED |
				  STATX_ATTR_ENCRYPTED |
				  STATX_ATTR_IMMUTABLE |
				  STATX_ATTR_NODUMP);

	generic_fillattr(inode, stat);

	if (gfs2_holder_initialized(&gh))
		gfs2_glock_dq_uninit(&gh);

	return 0;
}

static int gfs2_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		       u64 start, u64 len)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	inode_lock_shared(inode);

	ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	if (ret)
		goto out;

	ret = iomap_fiemap(inode, fieinfo, start, len, &gfs2_iomap_ops);

	gfs2_glock_dq_uninit(&gh);

out:
	inode_unlock_shared(inode);
	return ret;
}

loff_t gfs2_seek_data(struct file *file, loff_t offset)
{
	struct inode *inode = file->f_mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	loff_t ret;

	inode_lock_shared(inode);
	ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	if (!ret)
		ret = iomap_seek_data(inode, offset, &gfs2_iomap_ops);
	gfs2_glock_dq_uninit(&gh);
	inode_unlock_shared(inode);

	if (ret < 0)
		return ret;
	return vfs_setpos(file, ret, inode->i_sb->s_maxbytes);
}

loff_t gfs2_seek_hole(struct file *file, loff_t offset)
{
	struct inode *inode = file->f_mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	loff_t ret;

	inode_lock_shared(inode);
	ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	if (!ret)
		ret = iomap_seek_hole(inode, offset, &gfs2_iomap_ops);
	gfs2_glock_dq_uninit(&gh);
	inode_unlock_shared(inode);

	if (ret < 0)
		return ret;
	return vfs_setpos(file, ret, inode->i_sb->s_maxbytes);
}

const struct inode_operations gfs2_file_iops = {
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.listxattr = gfs2_listxattr,
	.fiemap = gfs2_fiemap,
	.get_acl = gfs2_get_acl,
	.set_acl = gfs2_set_acl,
};

const struct inode_operations gfs2_dir_iops = {
	.create = gfs2_create,
	.lookup = gfs2_lookup,
	.link = gfs2_link,
	.unlink = gfs2_unlink,
	.symlink = gfs2_symlink,
	.mkdir = gfs2_mkdir,
	.rmdir = gfs2_unlink,
	.mknod = gfs2_mknod,
	.rename = gfs2_rename2,
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.listxattr = gfs2_listxattr,
	.fiemap = gfs2_fiemap,
	.get_acl = gfs2_get_acl,
	.set_acl = gfs2_set_acl,
	.atomic_open = gfs2_atomic_open,
};

const struct inode_operations gfs2_symlink_iops = {
	.get_link = gfs2_get_link,
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.listxattr = gfs2_listxattr,
	.fiemap = gfs2_fiemap,
};

