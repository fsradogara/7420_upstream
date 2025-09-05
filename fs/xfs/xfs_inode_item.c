// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_types.h"
#include "xfs_bit.h"
#include "xfs_log.h"
#include "xfs_inum.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_dir2.h"
#include "xfs_dmapi.h"
#include "xfs_mount.h"
#include "xfs_trans_priv.h"
#include "xfs_bmap_btree.h"
#include "xfs_alloc_btree.h"
#include "xfs_ialloc_btree.h"
#include "xfs_dir2_sf.h"
#include "xfs_attr_sf.h"
#include "xfs_dinode.h"
#include "xfs_inode.h"
#include "xfs_inode_item.h"
#include "xfs_btree.h"
#include "xfs_ialloc.h"
#include "xfs_rw.h"
#include "xfs_error.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_inode_item.h"
#include "xfs_error.h"
#include "xfs_trace.h"
#include "xfs_trans_priv.h"
#include "xfs_buf_item.h"
#include "xfs_log.h"

#include <linux/iversion.h>

kmem_zone_t	*xfs_ili_zone;		/* inode log item zone */

static inline struct xfs_inode_log_item *INODE_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_inode_log_item, ili_item);
}

STATIC void
xfs_inode_item_data_fork_size(
	struct xfs_inode_log_item *iip,
	int			*nvecs,
	int			*nbytes)
{
	struct xfs_inode	*ip = iip->ili_inode;

	switch (ip->i_d.di_format) {
	case XFS_DINODE_FMT_EXTENTS:
		if ((iip->ili_fields & XFS_ILOG_DEXT) &&
		    ip->i_d.di_nextents > 0 &&
		    ip->i_df.if_bytes > 0) {
			/* worst case, doesn't subtract delalloc extents */
			*nbytes += XFS_IFORK_DSIZE(ip);
			*nvecs += 1;
		}
		break;
	case XFS_DINODE_FMT_BTREE:
		if ((iip->ili_fields & XFS_ILOG_DBROOT) &&
		    ip->i_df.if_broot_bytes > 0) {
			*nbytes += ip->i_df.if_broot_bytes;
			*nvecs += 1;
		}
		break;
	case XFS_DINODE_FMT_LOCAL:
		if ((iip->ili_fields & XFS_ILOG_DDATA) &&
		    ip->i_df.if_bytes > 0) {
			*nbytes += roundup(ip->i_df.if_bytes, 4);
			*nvecs += 1;
		}
		break;

	case XFS_DINODE_FMT_DEV:
		break;
	default:
		ASSERT(0);
		break;
	}
}

STATIC void
xfs_inode_item_attr_fork_size(
	struct xfs_inode_log_item *iip,
	int			*nvecs,
	int			*nbytes)
{
	struct xfs_inode	*ip = iip->ili_inode;

	switch (ip->i_d.di_aformat) {
	case XFS_DINODE_FMT_EXTENTS:
		if ((iip->ili_fields & XFS_ILOG_AEXT) &&
		    ip->i_d.di_anextents > 0 &&
		    ip->i_afp->if_bytes > 0) {
			/* worst case, doesn't subtract unused space */
			*nbytes += XFS_IFORK_ASIZE(ip);
			*nvecs += 1;
		}
		break;
	case XFS_DINODE_FMT_BTREE:
		if ((iip->ili_fields & XFS_ILOG_ABROOT) &&
		    ip->i_afp->if_broot_bytes > 0) {
			*nbytes += ip->i_afp->if_broot_bytes;
			*nvecs += 1;
		}
		break;
	case XFS_DINODE_FMT_LOCAL:
		if ((iip->ili_fields & XFS_ILOG_ADATA) &&
		    ip->i_afp->if_bytes > 0) {
			*nbytes += roundup(ip->i_afp->if_bytes, 4);
			*nvecs += 1;
		}
		break;
	default:
		ASSERT(0);
		break;
	}
}

/*
 * This returns the number of iovecs needed to log the given inode item.
 *
 * We need one iovec for the inode log format structure, one for the
 * inode core, and possibly one for the inode data/extents/b-tree root
 * and one for the inode attribute data/extents/b-tree root.
 */
STATIC uint
xfs_inode_item_size(
	xfs_inode_log_item_t	*iip)
{
	uint		nvecs;
	xfs_inode_t	*ip;

	ip = iip->ili_inode;
	nvecs = 2;

	/*
	 * Only log the data/extents/b-tree root if there is something
	 * left to log.
	 */
	iip->ili_format.ilf_fields |= XFS_ILOG_CORE;

	switch (ip->i_d.di_format) {
	case XFS_DINODE_FMT_EXTENTS:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DBROOT |
			  XFS_ILOG_DEV | XFS_ILOG_UUID);
		if ((iip->ili_format.ilf_fields & XFS_ILOG_DEXT) &&
		    (ip->i_d.di_nextents > 0) &&
		    (ip->i_df.if_bytes > 0)) {
			ASSERT(ip->i_df.if_u1.if_extents != NULL);
			nvecs++;
		} else {
			iip->ili_format.ilf_fields &= ~XFS_ILOG_DEXT;
		}
		break;

	case XFS_DINODE_FMT_BTREE:
		ASSERT(ip->i_df.if_ext_max ==
		       XFS_IFORK_DSIZE(ip) / (uint)sizeof(xfs_bmbt_rec_t));
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DEXT |
			  XFS_ILOG_DEV | XFS_ILOG_UUID);
		if ((iip->ili_format.ilf_fields & XFS_ILOG_DBROOT) &&
		    (ip->i_df.if_broot_bytes > 0)) {
			ASSERT(ip->i_df.if_broot != NULL);
			nvecs++;
		} else {
			ASSERT(!(iip->ili_format.ilf_fields &
				 XFS_ILOG_DBROOT));
#ifdef XFS_TRANS_DEBUG
			if (iip->ili_root_size > 0) {
				ASSERT(iip->ili_root_size ==
				       ip->i_df.if_broot_bytes);
				ASSERT(memcmp(iip->ili_orig_root,
					    ip->i_df.if_broot,
					    iip->ili_root_size) == 0);
			} else {
				ASSERT(ip->i_df.if_broot_bytes == 0);
			}
#endif
			iip->ili_format.ilf_fields &= ~XFS_ILOG_DBROOT;
		}
		break;

	case XFS_DINODE_FMT_LOCAL:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_DEXT | XFS_ILOG_DBROOT |
			  XFS_ILOG_DEV | XFS_ILOG_UUID);
		if ((iip->ili_format.ilf_fields & XFS_ILOG_DDATA) &&
		    (ip->i_df.if_bytes > 0)) {
			ASSERT(ip->i_df.if_u1.if_data != NULL);
			ASSERT(ip->i_d.di_size > 0);
			nvecs++;
		} else {
			iip->ili_format.ilf_fields &= ~XFS_ILOG_DDATA;
		}
		break;

	case XFS_DINODE_FMT_DEV:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DBROOT |
			  XFS_ILOG_DEXT | XFS_ILOG_UUID);
		break;

	case XFS_DINODE_FMT_UUID:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DBROOT |
			  XFS_ILOG_DEXT | XFS_ILOG_DEV);
		break;

	default:
		ASSERT(0);
		break;
	}

	/*
	 * If there are no attributes associated with this file,
	 * then there cannot be anything more to log.
	 * Clear all attribute-related log flags.
	 */
	if (!XFS_IFORK_Q(ip)) {
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_ADATA | XFS_ILOG_ABROOT | XFS_ILOG_AEXT);
		return nvecs;
	}

	/*
	 * Log any necessary attribute data.
	 */
	switch (ip->i_d.di_aformat) {
	case XFS_DINODE_FMT_EXTENTS:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_ADATA | XFS_ILOG_ABROOT);
		if ((iip->ili_format.ilf_fields & XFS_ILOG_AEXT) &&
		    (ip->i_d.di_anextents > 0) &&
		    (ip->i_afp->if_bytes > 0)) {
			ASSERT(ip->i_afp->if_u1.if_extents != NULL);
			nvecs++;
		} else {
			iip->ili_format.ilf_fields &= ~XFS_ILOG_AEXT;
		}
		break;

	case XFS_DINODE_FMT_BTREE:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_ADATA | XFS_ILOG_AEXT);
		if ((iip->ili_format.ilf_fields & XFS_ILOG_ABROOT) &&
		    (ip->i_afp->if_broot_bytes > 0)) {
			ASSERT(ip->i_afp->if_broot != NULL);
			nvecs++;
		} else {
			iip->ili_format.ilf_fields &= ~XFS_ILOG_ABROOT;
		}
		break;

	case XFS_DINODE_FMT_LOCAL:
		iip->ili_format.ilf_fields &=
			~(XFS_ILOG_AEXT | XFS_ILOG_ABROOT);
		if ((iip->ili_format.ilf_fields & XFS_ILOG_ADATA) &&
		    (ip->i_afp->if_bytes > 0)) {
			ASSERT(ip->i_afp->if_u1.if_data != NULL);
			nvecs++;
		} else {
			iip->ili_format.ilf_fields &= ~XFS_ILOG_ADATA;
		}
		break;

	default:
		ASSERT(0);
		break;
	}

	return nvecs;
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given inode log item.  It fills the first item with an inode
 * log format structure, the second with the on-disk inode structure,
 * and a possible third and/or fourth with the inode data/extents/b-tree
 * root and inode attributes data/extents/b-tree root.
 */
STATIC void
xfs_inode_item_format(
	xfs_inode_log_item_t	*iip,
	xfs_log_iovec_t		*log_vector)
{
	uint			nvecs;
	xfs_log_iovec_t		*vecp;
	xfs_inode_t		*ip;
	size_t			data_bytes;
	xfs_bmbt_rec_t		*ext_buffer;
	int			nrecs;
	xfs_mount_t		*mp;

	ip = iip->ili_inode;
	vecp = log_vector;

	vecp->i_addr = (xfs_caddr_t)&iip->ili_format;
	vecp->i_len  = sizeof(xfs_inode_log_format_t);
	XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IFORMAT);
	vecp++;
	nvecs	     = 1;

	/*
	 * Clear i_update_core if the timestamps (or any other
	 * non-transactional modification) need flushing/logging
	 * and we're about to log them with the rest of the core.
	 *
	 * This is the same logic as xfs_iflush() but this code can't
	 * run at the same time as xfs_iflush because we're in commit
	 * processing here and so we have the inode lock held in
	 * exclusive mode.  Although it doesn't really matter
	 * for the timestamps if both routines were to grab the
	 * timestamps or not.  That would be ok.
	 *
	 * We clear i_update_core before copying out the data.
	 * This is for coordination with our timestamp updates
	 * that don't hold the inode lock. They will always
	 * update the timestamps BEFORE setting i_update_core,
	 * so if we clear i_update_core after they set it we
	 * are guaranteed to see their updates to the timestamps
	 * either here.  Likewise, if they set it after we clear it
	 * here, we'll see it either on the next commit of this
	 * inode or the next time the inode gets flushed via
	 * xfs_iflush().  This depends on strongly ordered memory
	 * semantics, but we have that.  We use the SYNCHRONIZE
	 * macro to make sure that the compiler does not reorder
	 * the i_update_core access below the data copy below.
	 */
	if (ip->i_update_core)  {
		ip->i_update_core = 0;
		SYNCHRONIZE();
	}

	/*
	 * We don't have to worry about re-ordering here because
	 * the update_size field is protected by the inode lock
	 * and we have that held in exclusive mode.
	 */
	if (ip->i_update_size)
		ip->i_update_size = 0;

	/*
	 * Make sure to get the latest atime from the Linux inode.
	 */
	xfs_synchronize_atime(ip);

	/*
	 * make sure the linux inode is dirty
	 */
	xfs_mark_inode_dirty_sync(ip);

	vecp->i_addr = (xfs_caddr_t)&ip->i_d;
	vecp->i_len  = sizeof(xfs_dinode_core_t);
	XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_ICORE);
	vecp++;
	nvecs++;
	iip->ili_format.ilf_fields |= XFS_ILOG_CORE;

	/*
	 * If this is really an old format inode, then we need to
	 * log it as such.  This means that we have to copy the link
	 * count from the new field to the old.  We don't have to worry
	 * about the new fields, because nothing trusts them as long as
	 * the old inode version number is there.  If the superblock already
	 * has a new version number, then we don't bother converting back.
	 */
	mp = ip->i_mount;
	ASSERT(ip->i_d.di_version == XFS_DINODE_VERSION_1 ||
	       xfs_sb_version_hasnlink(&mp->m_sb));
	if (ip->i_d.di_version == XFS_DINODE_VERSION_1) {
		if (!xfs_sb_version_hasnlink(&mp->m_sb)) {
			/*
			 * Convert it back.
			 */
			ASSERT(ip->i_d.di_nlink <= XFS_MAXLINK_1);
			ip->i_d.di_onlink = ip->i_d.di_nlink;
		} else {
			/*
			 * The superblock version has already been bumped,
			 * so just make the conversion to the new inode
			 * format permanent.
			 */
			ip->i_d.di_version = XFS_DINODE_VERSION_2;
			ip->i_d.di_onlink = 0;
			memset(&(ip->i_d.di_pad[0]), 0, sizeof(ip->i_d.di_pad));
		}
	}

	switch (ip->i_d.di_format) {
	case XFS_DINODE_FMT_EXTENTS:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_DDATA | XFS_ILOG_DBROOT |
			  XFS_ILOG_DEV | XFS_ILOG_UUID)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_DEXT) {
			ASSERT(ip->i_df.if_bytes > 0);
			ASSERT(ip->i_df.if_u1.if_extents != NULL);
			ASSERT(ip->i_d.di_nextents > 0);
			ASSERT(iip->ili_extents_buf == NULL);
			nrecs = ip->i_df.if_bytes /
				(uint)sizeof(xfs_bmbt_rec_t);
			ASSERT(nrecs > 0);
#ifdef XFS_NATIVE_HOST
			if (nrecs == ip->i_d.di_nextents) {
				/*
				 * There are no delayed allocation
				 * extents, so just point to the
				 * real extents array.
				 */
				vecp->i_addr =
					(char *)(ip->i_df.if_u1.if_extents);
				vecp->i_len = ip->i_df.if_bytes;
				XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IEXT);
			} else
#endif
			{
				/*
				 * There are delayed allocation extents
				 * in the inode, or we need to convert
				 * the extents to on disk format.
				 * Use xfs_iextents_copy()
				 * to copy only the real extents into
				 * a separate buffer.  We'll free the
				 * buffer in the unlock routine.
				 */
				ext_buffer = kmem_alloc(ip->i_df.if_bytes,
					KM_SLEEP);
				iip->ili_extents_buf = ext_buffer;
				vecp->i_addr = (xfs_caddr_t)ext_buffer;
				vecp->i_len = xfs_iextents_copy(ip, ext_buffer,
						XFS_DATA_FORK);
				XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IEXT);
			}
			ASSERT(vecp->i_len <= ip->i_df.if_bytes);
			iip->ili_format.ilf_dsize = vecp->i_len;
			vecp++;
			nvecs++;
		}
		break;

	case XFS_DINODE_FMT_BTREE:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_DDATA | XFS_ILOG_DEXT |
			  XFS_ILOG_DEV | XFS_ILOG_UUID)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_DBROOT) {
			ASSERT(ip->i_df.if_broot_bytes > 0);
			ASSERT(ip->i_df.if_broot != NULL);
			vecp->i_addr = (xfs_caddr_t)ip->i_df.if_broot;
			vecp->i_len = ip->i_df.if_broot_bytes;
			XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IBROOT);
			vecp++;
			nvecs++;
			iip->ili_format.ilf_dsize = ip->i_df.if_broot_bytes;
		}
		break;

	case XFS_DINODE_FMT_LOCAL:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_DBROOT | XFS_ILOG_DEXT |
			  XFS_ILOG_DEV | XFS_ILOG_UUID)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_DDATA) {
			ASSERT(ip->i_df.if_bytes > 0);
			ASSERT(ip->i_df.if_u1.if_data != NULL);
			ASSERT(ip->i_d.di_size > 0);

			vecp->i_addr = (xfs_caddr_t)ip->i_df.if_u1.if_data;
STATIC void
xfs_inode_item_size(
	struct xfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	struct xfs_inode_log_item *iip = INODE_ITEM(lip);
	struct xfs_inode	*ip = iip->ili_inode;

	*nvecs += 2;
	*nbytes += sizeof(struct xfs_inode_log_format) +
		   xfs_log_dinode_size(ip->i_d.di_version);

	xfs_inode_item_data_fork_size(iip, nvecs, nbytes);
	if (XFS_IFORK_Q(ip))
		xfs_inode_item_attr_fork_size(iip, nvecs, nbytes);
}

STATIC void
xfs_inode_item_format_data_fork(
	struct xfs_inode_log_item *iip,
	struct xfs_inode_log_format *ilf,
	struct xfs_log_vec	*lv,
	struct xfs_log_iovec	**vecp)
{
	struct xfs_inode	*ip = iip->ili_inode;
	size_t			data_bytes;

	switch (ip->i_d.di_format) {
	case XFS_DINODE_FMT_EXTENTS:
		iip->ili_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DBROOT | XFS_ILOG_DEV);

		if ((iip->ili_fields & XFS_ILOG_DEXT) &&
		    ip->i_d.di_nextents > 0 &&
		    ip->i_df.if_bytes > 0) {
			struct xfs_bmbt_rec *p;

			ASSERT(xfs_iext_count(&ip->i_df) > 0);

			p = xlog_prepare_iovec(lv, vecp, XLOG_REG_TYPE_IEXT);
			data_bytes = xfs_iextents_copy(ip, p, XFS_DATA_FORK);
			xlog_finish_iovec(lv, *vecp, data_bytes);

			ASSERT(data_bytes <= ip->i_df.if_bytes);

			ilf->ilf_dsize = data_bytes;
			ilf->ilf_size++;
		} else {
			iip->ili_fields &= ~XFS_ILOG_DEXT;
		}
		break;
	case XFS_DINODE_FMT_BTREE:
		iip->ili_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DEV);

		if ((iip->ili_fields & XFS_ILOG_DBROOT) &&
		    ip->i_df.if_broot_bytes > 0) {
			ASSERT(ip->i_df.if_broot != NULL);
			xlog_copy_iovec(lv, vecp, XLOG_REG_TYPE_IBROOT,
					ip->i_df.if_broot,
					ip->i_df.if_broot_bytes);
			ilf->ilf_dsize = ip->i_df.if_broot_bytes;
			ilf->ilf_size++;
		} else {
			ASSERT(!(iip->ili_fields &
				 XFS_ILOG_DBROOT));
			iip->ili_fields &= ~XFS_ILOG_DBROOT;
		}
		break;
	case XFS_DINODE_FMT_LOCAL:
		iip->ili_fields &=
			~(XFS_ILOG_DEXT | XFS_ILOG_DBROOT | XFS_ILOG_DEV);
		if ((iip->ili_fields & XFS_ILOG_DDATA) &&
		    ip->i_df.if_bytes > 0) {
			/*
			 * Round i_bytes up to a word boundary.
			 * The underlying memory is guaranteed to
			 * to be there by xfs_idata_realloc().
			 */
			data_bytes = roundup(ip->i_df.if_bytes, 4);
			ASSERT((ip->i_df.if_real_bytes == 0) ||
			       (ip->i_df.if_real_bytes == data_bytes));
			vecp->i_len = (int)data_bytes;
			XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_ILOCAL);
			vecp++;
			nvecs++;
			iip->ili_format.ilf_dsize = (unsigned)data_bytes;
		}
		break;

	case XFS_DINODE_FMT_DEV:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_DBROOT | XFS_ILOG_DEXT |
			  XFS_ILOG_DDATA | XFS_ILOG_UUID)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_DEV) {
			iip->ili_format.ilf_u.ilfu_rdev =
				ip->i_df.if_u2.if_rdev;
		}
		break;

	case XFS_DINODE_FMT_UUID:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_DBROOT | XFS_ILOG_DEXT |
			  XFS_ILOG_DDATA | XFS_ILOG_DEV)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_UUID) {
			iip->ili_format.ilf_u.ilfu_uuid =
				ip->i_df.if_u2.if_uuid;
		}
		break;

			ASSERT(ip->i_df.if_real_bytes == 0 ||
			       ip->i_df.if_real_bytes >= data_bytes);
			ASSERT(ip->i_df.if_u1.if_data != NULL);
			ASSERT(ip->i_d.di_size > 0);
			xlog_copy_iovec(lv, vecp, XLOG_REG_TYPE_ILOCAL,
					ip->i_df.if_u1.if_data, data_bytes);
			ilf->ilf_dsize = (unsigned)data_bytes;
			ilf->ilf_size++;
		} else {
			iip->ili_fields &= ~XFS_ILOG_DDATA;
		}
		break;
	case XFS_DINODE_FMT_DEV:
		iip->ili_fields &=
			~(XFS_ILOG_DDATA | XFS_ILOG_DBROOT | XFS_ILOG_DEXT);
		if (iip->ili_fields & XFS_ILOG_DEV)
			ilf->ilf_u.ilfu_rdev = sysv_encode_dev(VFS_I(ip)->i_rdev);
		break;
	default:
		ASSERT(0);
		break;
	}

	/*
	 * If there are no attributes associated with the file,
	 * then we're done.
	 * Assert that no attribute-related log flags are set.
	 */
	if (!XFS_IFORK_Q(ip)) {
		ASSERT(nvecs == iip->ili_item.li_desc->lid_size);
		iip->ili_format.ilf_size = nvecs;
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_ADATA | XFS_ILOG_ABROOT | XFS_ILOG_AEXT)));
		return;
	}

	switch (ip->i_d.di_aformat) {
	case XFS_DINODE_FMT_EXTENTS:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_ADATA | XFS_ILOG_ABROOT)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_AEXT) {
			ASSERT(ip->i_afp->if_bytes > 0);
			ASSERT(ip->i_afp->if_u1.if_extents != NULL);
			ASSERT(ip->i_d.di_anextents > 0);
#ifdef DEBUG
			nrecs = ip->i_afp->if_bytes /
				(uint)sizeof(xfs_bmbt_rec_t);
#endif
			ASSERT(nrecs > 0);
			ASSERT(nrecs == ip->i_d.di_anextents);
#ifdef XFS_NATIVE_HOST
			/*
			 * There are not delayed allocation extents
			 * for attributes, so just point at the array.
			 */
			vecp->i_addr = (char *)(ip->i_afp->if_u1.if_extents);
			vecp->i_len = ip->i_afp->if_bytes;
#else
			ASSERT(iip->ili_aextents_buf == NULL);
			/*
			 * Need to endian flip before logging
			 */
			ext_buffer = kmem_alloc(ip->i_afp->if_bytes,
				KM_SLEEP);
			iip->ili_aextents_buf = ext_buffer;
			vecp->i_addr = (xfs_caddr_t)ext_buffer;
			vecp->i_len = xfs_iextents_copy(ip, ext_buffer,
					XFS_ATTR_FORK);
#endif
			XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IATTR_EXT);
			iip->ili_format.ilf_asize = vecp->i_len;
			vecp++;
			nvecs++;
		}
		break;

	case XFS_DINODE_FMT_BTREE:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_ADATA | XFS_ILOG_AEXT)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_ABROOT) {
			ASSERT(ip->i_afp->if_broot_bytes > 0);
			ASSERT(ip->i_afp->if_broot != NULL);
			vecp->i_addr = (xfs_caddr_t)ip->i_afp->if_broot;
			vecp->i_len = ip->i_afp->if_broot_bytes;
			XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IATTR_BROOT);
			vecp++;
			nvecs++;
			iip->ili_format.ilf_asize = ip->i_afp->if_broot_bytes;
		}
		break;

	case XFS_DINODE_FMT_LOCAL:
		ASSERT(!(iip->ili_format.ilf_fields &
			 (XFS_ILOG_ABROOT | XFS_ILOG_AEXT)));
		if (iip->ili_format.ilf_fields & XFS_ILOG_ADATA) {
			ASSERT(ip->i_afp->if_bytes > 0);
			ASSERT(ip->i_afp->if_u1.if_data != NULL);

			vecp->i_addr = (xfs_caddr_t)ip->i_afp->if_u1.if_data;
}

STATIC void
xfs_inode_item_format_attr_fork(
	struct xfs_inode_log_item *iip,
	struct xfs_inode_log_format *ilf,
	struct xfs_log_vec	*lv,
	struct xfs_log_iovec	**vecp)
{
	struct xfs_inode	*ip = iip->ili_inode;
	size_t			data_bytes;

	switch (ip->i_d.di_aformat) {
	case XFS_DINODE_FMT_EXTENTS:
		iip->ili_fields &=
			~(XFS_ILOG_ADATA | XFS_ILOG_ABROOT);

		if ((iip->ili_fields & XFS_ILOG_AEXT) &&
		    ip->i_d.di_anextents > 0 &&
		    ip->i_afp->if_bytes > 0) {
			struct xfs_bmbt_rec *p;

			ASSERT(xfs_iext_count(ip->i_afp) ==
				ip->i_d.di_anextents);

			p = xlog_prepare_iovec(lv, vecp, XLOG_REG_TYPE_IATTR_EXT);
			data_bytes = xfs_iextents_copy(ip, p, XFS_ATTR_FORK);
			xlog_finish_iovec(lv, *vecp, data_bytes);

			ilf->ilf_asize = data_bytes;
			ilf->ilf_size++;
		} else {
			iip->ili_fields &= ~XFS_ILOG_AEXT;
		}
		break;
	case XFS_DINODE_FMT_BTREE:
		iip->ili_fields &=
			~(XFS_ILOG_ADATA | XFS_ILOG_AEXT);

		if ((iip->ili_fields & XFS_ILOG_ABROOT) &&
		    ip->i_afp->if_broot_bytes > 0) {
			ASSERT(ip->i_afp->if_broot != NULL);

			xlog_copy_iovec(lv, vecp, XLOG_REG_TYPE_IATTR_BROOT,
					ip->i_afp->if_broot,
					ip->i_afp->if_broot_bytes);
			ilf->ilf_asize = ip->i_afp->if_broot_bytes;
			ilf->ilf_size++;
		} else {
			iip->ili_fields &= ~XFS_ILOG_ABROOT;
		}
		break;
	case XFS_DINODE_FMT_LOCAL:
		iip->ili_fields &=
			~(XFS_ILOG_AEXT | XFS_ILOG_ABROOT);

		if ((iip->ili_fields & XFS_ILOG_ADATA) &&
		    ip->i_afp->if_bytes > 0) {
			/*
			 * Round i_bytes up to a word boundary.
			 * The underlying memory is guaranteed to
			 * to be there by xfs_idata_realloc().
			 */
			data_bytes = roundup(ip->i_afp->if_bytes, 4);
			ASSERT((ip->i_afp->if_real_bytes == 0) ||
			       (ip->i_afp->if_real_bytes == data_bytes));
			vecp->i_len = (int)data_bytes;
			XLOG_VEC_SET_TYPE(vecp, XLOG_REG_TYPE_IATTR_LOCAL);
			vecp++;
			nvecs++;
			iip->ili_format.ilf_asize = (unsigned)data_bytes;
		}
		break;

			ASSERT(ip->i_afp->if_real_bytes == 0 ||
			       ip->i_afp->if_real_bytes >= data_bytes);
			ASSERT(ip->i_afp->if_u1.if_data != NULL);
			xlog_copy_iovec(lv, vecp, XLOG_REG_TYPE_IATTR_LOCAL,
					ip->i_afp->if_u1.if_data,
					data_bytes);
			ilf->ilf_asize = (unsigned)data_bytes;
			ilf->ilf_size++;
		} else {
			iip->ili_fields &= ~XFS_ILOG_ADATA;
		}
		break;
	default:
		ASSERT(0);
		break;
	}

	ASSERT(nvecs == iip->ili_item.li_desc->lid_size);
	iip->ili_format.ilf_size = nvecs;
}


/*
 * This is called to pin the inode associated with the inode log
 * item in memory so it cannot be written out.  Do this by calling
 * xfs_ipin() to bump the pin count in the inode while holding the
 * inode pin lock.
 */
STATIC void
xfs_inode_item_pin(
	xfs_inode_log_item_t	*iip)
{
	ASSERT(xfs_isilocked(iip->ili_inode, XFS_ILOCK_EXCL));
	xfs_ipin(iip->ili_inode);
}

static void
xfs_inode_to_log_dinode(
	struct xfs_inode	*ip,
	struct xfs_log_dinode	*to,
	xfs_lsn_t		lsn)
{
	struct xfs_icdinode	*from = &ip->i_d;
	struct inode		*inode = VFS_I(ip);

	to->di_magic = XFS_DINODE_MAGIC;

	to->di_version = from->di_version;
	to->di_format = from->di_format;
	to->di_uid = from->di_uid;
	to->di_gid = from->di_gid;
	to->di_projid_lo = from->di_projid_lo;
	to->di_projid_hi = from->di_projid_hi;

	memset(to->di_pad, 0, sizeof(to->di_pad));
	memset(to->di_pad3, 0, sizeof(to->di_pad3));
	to->di_atime.t_sec = inode->i_atime.tv_sec;
	to->di_atime.t_nsec = inode->i_atime.tv_nsec;
	to->di_mtime.t_sec = inode->i_mtime.tv_sec;
	to->di_mtime.t_nsec = inode->i_mtime.tv_nsec;
	to->di_ctime.t_sec = inode->i_ctime.tv_sec;
	to->di_ctime.t_nsec = inode->i_ctime.tv_nsec;
	to->di_nlink = inode->i_nlink;
	to->di_gen = inode->i_generation;
	to->di_mode = inode->i_mode;

	to->di_size = from->di_size;
	to->di_nblocks = from->di_nblocks;
	to->di_extsize = from->di_extsize;
	to->di_nextents = from->di_nextents;
	to->di_anextents = from->di_anextents;
	to->di_forkoff = from->di_forkoff;
	to->di_aformat = from->di_aformat;
	to->di_dmevmask = from->di_dmevmask;
	to->di_dmstate = from->di_dmstate;
	to->di_flags = from->di_flags;

	/* log a dummy value to ensure log structure is fully initialised */
	to->di_next_unlinked = NULLAGINO;

	if (from->di_version == 3) {
		to->di_changecount = inode_peek_iversion(inode);
		to->di_crtime.t_sec = from->di_crtime.t_sec;
		to->di_crtime.t_nsec = from->di_crtime.t_nsec;
		to->di_flags2 = from->di_flags2;
		to->di_cowextsize = from->di_cowextsize;
		to->di_ino = ip->i_ino;
		to->di_lsn = lsn;
		memset(to->di_pad2, 0, sizeof(to->di_pad2));
		uuid_copy(&to->di_uuid, &ip->i_mount->m_sb.sb_meta_uuid);
		to->di_flushiter = 0;
	} else {
		to->di_flushiter = from->di_flushiter;
	}
}

/*
 * Format the inode core. Current timestamp data is only in the VFS inode
 * fields, so we need to grab them from there. Hence rather than just copying
 * the XFS inode core structure, format the fields directly into the iovec.
 */
static void
xfs_inode_item_format_core(
	struct xfs_inode	*ip,
	struct xfs_log_vec	*lv,
	struct xfs_log_iovec	**vecp)
{
	struct xfs_log_dinode	*dic;

	dic = xlog_prepare_iovec(lv, vecp, XLOG_REG_TYPE_ICORE);
	xfs_inode_to_log_dinode(ip, dic, ip->i_itemp->ili_item.li_lsn);
	xlog_finish_iovec(lv, *vecp, xfs_log_dinode_size(ip->i_d.di_version));
}

/*
 * This is called to fill in the vector of log iovecs for the given inode
 * log item.  It fills the first item with an inode log format structure,
 * the second with the on-disk inode structure, and a possible third and/or
 * fourth with the inode data/extents/b-tree root and inode attributes
 * data/extents/b-tree root.
 *
 * Note: Always use the 64 bit inode log format structure so we don't
 * leave an uninitialised hole in the format item on 64 bit systems. Log
 * recovery on 32 bit systems handles this just fine, so there's no reason
 * for not using an initialising the properly padded structure all the time.
 */
STATIC void
xfs_inode_item_format(
	struct xfs_log_item	*lip,
	struct xfs_log_vec	*lv)
{
	struct xfs_inode_log_item *iip = INODE_ITEM(lip);
	struct xfs_inode	*ip = iip->ili_inode;
	struct xfs_log_iovec	*vecp = NULL;
	struct xfs_inode_log_format *ilf;

	ASSERT(ip->i_d.di_version > 1);

	ilf = xlog_prepare_iovec(lv, &vecp, XLOG_REG_TYPE_IFORMAT);
	ilf->ilf_type = XFS_LI_INODE;
	ilf->ilf_ino = ip->i_ino;
	ilf->ilf_blkno = ip->i_imap.im_blkno;
	ilf->ilf_len = ip->i_imap.im_len;
	ilf->ilf_boffset = ip->i_imap.im_boffset;
	ilf->ilf_fields = XFS_ILOG_CORE;
	ilf->ilf_size = 2; /* format + core */

	/*
	 * make sure we don't leak uninitialised data into the log in the case
	 * when we don't log every field in the inode.
	 */
	ilf->ilf_dsize = 0;
	ilf->ilf_asize = 0;
	ilf->ilf_pad = 0;
	memset(&ilf->ilf_u, 0, sizeof(ilf->ilf_u));

	xlog_finish_iovec(lv, vecp, sizeof(*ilf));

	xfs_inode_item_format_core(ip, lv, &vecp);
	xfs_inode_item_format_data_fork(iip, ilf, lv, &vecp);
	if (XFS_IFORK_Q(ip)) {
		xfs_inode_item_format_attr_fork(iip, ilf, lv, &vecp);
	} else {
		iip->ili_fields &=
			~(XFS_ILOG_ADATA | XFS_ILOG_ABROOT | XFS_ILOG_AEXT);
	}

	/* update the format with the exact fields we actually logged */
	ilf->ilf_fields |= (iip->ili_fields & ~XFS_ILOG_TIMESTAMP);
}

/*
 * This is called to pin the inode associated with the inode log
 * item in memory so it cannot be written out.
 */
STATIC void
xfs_inode_item_pin(
	struct xfs_log_item	*lip)
{
	struct xfs_inode	*ip = INODE_ITEM(lip)->ili_inode;

	ASSERT(xfs_isilocked(ip, XFS_ILOCK_EXCL));

	trace_xfs_inode_pin(ip, _RET_IP_);
	atomic_inc(&ip->i_pincount);
}


/*
 * This is called to unpin the inode associated with the inode log
 * item which was previously pinned with a call to xfs_inode_item_pin().
 * Just call xfs_iunpin() on the inode to do this.
 */
/* ARGSUSED */
STATIC void
xfs_inode_item_unpin(
	xfs_inode_log_item_t	*iip,
	int			stale)
{
	xfs_iunpin(iip->ili_inode);
}

/* ARGSUSED */
STATIC void
xfs_inode_item_unpin_remove(
	xfs_inode_log_item_t	*iip,
	xfs_trans_t		*tp)
{
	xfs_iunpin(iip->ili_inode);
}

/*
 * This is called to attempt to lock the inode associated with this
 * inode log item, in preparation for the push routine which does the actual
 * iflush.  Don't sleep on the inode lock or the flush lock.
 *
 * If the flush lock is already held, indicating that the inode has
 * been or is in the process of being flushed, then (ideally) we'd like to
 * see if the inode's buffer is still incore, and if so give it a nudge.
 * We delay doing so until the pushbuf routine, though, to avoid holding
 * the AIL lock across a call to the blackhole which is the buffer cache.
 * Also we don't want to sleep in any device strategy routines, which can happen
 * if we do the subsequent bawrite in here.
 */
STATIC uint
xfs_inode_item_trylock(
	xfs_inode_log_item_t	*iip)
{
	register xfs_inode_t	*ip;

	ip = iip->ili_inode;

	if (xfs_ipincount(ip) > 0) {
		return XFS_ITEM_PINNED;
	}

	if (!xfs_ilock_nowait(ip, XFS_ILOCK_SHARED)) {
		return XFS_ITEM_LOCKED;
	}

	if (!xfs_iflock_nowait(ip)) {
		/*
		 * If someone else isn't already trying to push the inode
		 * buffer, we get to do it.
		 */
		if (iip->ili_pushbuf_flag == 0) {
			iip->ili_pushbuf_flag = 1;
#ifdef DEBUG
			iip->ili_push_owner = current_pid();
#endif
			/*
			 * Inode is left locked in shared mode.
			 * Pushbuf routine gets to unlock it.
			 */
			return XFS_ITEM_PUSHBUF;
		} else {
			/*
			 * We hold the AIL lock, so we must specify the
			 * NONOTIFY flag so that we won't double trip.
			 */
			xfs_iunlock(ip, XFS_ILOCK_SHARED|XFS_IUNLOCK_NONOTIFY);
			return XFS_ITEM_FLUSHING;
		}
		/* NOTREACHED */
	}

	/* Stale items should force out the iclog */
	if (ip->i_flags & XFS_ISTALE) {
		xfs_ifunlock(ip);
		xfs_iunlock(ip, XFS_ILOCK_SHARED|XFS_IUNLOCK_NONOTIFY);
		return XFS_ITEM_PINNED;
	}

#ifdef DEBUG
	if (!XFS_FORCED_SHUTDOWN(ip->i_mount)) {
		ASSERT(iip->ili_format.ilf_fields != 0);
		ASSERT(iip->ili_logged == 0);
		ASSERT(iip->ili_item.li_flags & XFS_LI_IN_AIL);
	}
#endif
	return XFS_ITEM_SUCCESS;
 *
 * Also wake up anyone in xfs_iunpin_wait() if the count goes to 0.
 */
STATIC void
xfs_inode_item_unpin(
	struct xfs_log_item	*lip,
	int			remove)
{
	struct xfs_inode	*ip = INODE_ITEM(lip)->ili_inode;

	trace_xfs_inode_unpin(ip, _RET_IP_);
	ASSERT(atomic_read(&ip->i_pincount) > 0);
	if (atomic_dec_and_test(&ip->i_pincount))
		wake_up_bit(&ip->i_flags, __XFS_IPINNED_BIT);
}

/*
 * Callback used to mark a buffer with XFS_LI_FAILED when items in the buffer
 * have been failed during writeback
 *
 * This informs the AIL that the inode is already flush locked on the next push,
 * and acquires a hold on the buffer to ensure that it isn't reclaimed before
 * dirty data makes it to disk.
 */
STATIC void
xfs_inode_item_error(
	struct xfs_log_item	*lip,
	struct xfs_buf		*bp)
{
	ASSERT(xfs_isiflocked(INODE_ITEM(lip)->ili_inode));
	xfs_set_li_failed(lip, bp);
}

STATIC uint
xfs_inode_item_push(
	struct xfs_log_item	*lip,
	struct list_head	*buffer_list)
		__releases(&lip->li_ailp->ail_lock)
		__acquires(&lip->li_ailp->ail_lock)
{
	struct xfs_inode_log_item *iip = INODE_ITEM(lip);
	struct xfs_inode	*ip = iip->ili_inode;
	struct xfs_buf		*bp = lip->li_buf;
	uint			rval = XFS_ITEM_SUCCESS;
	int			error;

	if (xfs_ipincount(ip) > 0)
		return XFS_ITEM_PINNED;

	/*
	 * The buffer containing this item failed to be written back
	 * previously. Resubmit the buffer for IO.
	 */
	if (test_bit(XFS_LI_FAILED, &lip->li_flags)) {
		if (!xfs_buf_trylock(bp))
			return XFS_ITEM_LOCKED;

		if (!xfs_buf_resubmit_failed_buffers(bp, buffer_list))
			rval = XFS_ITEM_FLUSHING;

		xfs_buf_unlock(bp);
		return rval;
	}

	if (!xfs_ilock_nowait(ip, XFS_ILOCK_SHARED))
		return XFS_ITEM_LOCKED;

	/*
	 * Re-check the pincount now that we stabilized the value by
	 * taking the ilock.
	 */
	if (xfs_ipincount(ip) > 0) {
		rval = XFS_ITEM_PINNED;
		goto out_unlock;
	}

	/*
	 * Stale inode items should force out the iclog.
	 */
	if (ip->i_flags & XFS_ISTALE) {
		rval = XFS_ITEM_PINNED;
		goto out_unlock;
	}

	/*
	 * Someone else is already flushing the inode.  Nothing we can do
	 * here but wait for the flush to finish and remove the item from
	 * the AIL.
	 */
	if (!xfs_iflock_nowait(ip)) {
		rval = XFS_ITEM_FLUSHING;
		goto out_unlock;
	}

	ASSERT(iip->ili_fields != 0 || XFS_FORCED_SHUTDOWN(ip->i_mount));
	ASSERT(iip->ili_logged == 0 || XFS_FORCED_SHUTDOWN(ip->i_mount));

	spin_unlock(&lip->li_ailp->ail_lock);

	error = xfs_iflush(ip, &bp);
	if (!error) {
		if (!xfs_buf_delwri_queue(bp, buffer_list))
			rval = XFS_ITEM_FLUSHING;
		xfs_buf_relse(bp);
	}

	spin_lock(&lip->li_ailp->ail_lock);
out_unlock:
	xfs_iunlock(ip, XFS_ILOCK_SHARED);
	return rval;
}

/*
 * Unlock the inode associated with the inode log item.
 */
STATIC void
xfs_inode_item_unlock(
	xfs_inode_log_item_t	*iip)
{
	uint		hold;
	uint		iolocked;
	uint		lock_flags;
	xfs_inode_t	*ip;

	ASSERT(iip != NULL);
	ASSERT(iip->ili_inode->i_itemp != NULL);
	ASSERT(xfs_isilocked(iip->ili_inode, XFS_ILOCK_EXCL));
	ASSERT((!(iip->ili_inode->i_itemp->ili_flags &
		  XFS_ILI_IOLOCKED_EXCL)) ||
	       xfs_isilocked(iip->ili_inode, XFS_IOLOCK_EXCL));
	ASSERT((!(iip->ili_inode->i_itemp->ili_flags &
		  XFS_ILI_IOLOCKED_SHARED)) ||
	       xfs_isilocked(iip->ili_inode, XFS_IOLOCK_SHARED));
	/*
	 * Clear the transaction pointer in the inode.
	 */
	ip = iip->ili_inode;
	ip->i_transp = NULL;

	/*
	 * If the inode needed a separate buffer with which to log
	 * its extents, then free it now.
	 */
	if (iip->ili_extents_buf != NULL) {
		ASSERT(ip->i_d.di_format == XFS_DINODE_FMT_EXTENTS);
		ASSERT(ip->i_d.di_nextents > 0);
		ASSERT(iip->ili_format.ilf_fields & XFS_ILOG_DEXT);
		ASSERT(ip->i_df.if_bytes > 0);
		kmem_free(iip->ili_extents_buf);
		iip->ili_extents_buf = NULL;
	}
	if (iip->ili_aextents_buf != NULL) {
		ASSERT(ip->i_d.di_aformat == XFS_DINODE_FMT_EXTENTS);
		ASSERT(ip->i_d.di_anextents > 0);
		ASSERT(iip->ili_format.ilf_fields & XFS_ILOG_AEXT);
		ASSERT(ip->i_afp->if_bytes > 0);
		kmem_free(iip->ili_aextents_buf);
		iip->ili_aextents_buf = NULL;
	}

	/*
	 * Figure out if we should unlock the inode or not.
	 */
	hold = iip->ili_flags & XFS_ILI_HOLD;

	/*
	 * Before clearing out the flags, remember whether we
	 * are holding the inode's IO lock.
	 */
	iolocked = iip->ili_flags & XFS_ILI_IOLOCKED_ANY;

	/*
	 * Clear out the fields of the inode log item particular
	 * to the current transaction.
	 */
	iip->ili_ilock_recur = 0;
	iip->ili_iolock_recur = 0;
	iip->ili_flags = 0;

	/*
	 * Unlock the inode if XFS_ILI_HOLD was not set.
	 */
	if (!hold) {
		lock_flags = XFS_ILOCK_EXCL;
		if (iolocked & XFS_ILI_IOLOCKED_EXCL) {
			lock_flags |= XFS_IOLOCK_EXCL;
		} else if (iolocked & XFS_ILI_IOLOCKED_SHARED) {
			lock_flags |= XFS_IOLOCK_SHARED;
		}
		xfs_iput(iip->ili_inode, lock_flags);
	}
}

/*
 * This is called to find out where the oldest active copy of the
 * inode log item in the on disk log resides now that the last log
 * write of it completed at the given lsn.  Since we always re-log
 * all dirty data in an inode, the latest copy in the on disk log
 * is the only one that matters.  Therefore, simply return the
 * given lsn.
 */
/*ARGSUSED*/
STATIC xfs_lsn_t
xfs_inode_item_committed(
	xfs_inode_log_item_t	*iip,
	xfs_lsn_t		lsn)
{
	return (lsn);
}

/*
 * This gets called by xfs_trans_push_ail(), when IOP_TRYLOCK
 * failed to get the inode flush lock but did get the inode locked SHARED.
 * Here we're trying to see if the inode buffer is incore, and if so whether it's
 * marked delayed write. If that's the case, we'll initiate a bawrite on that
 * buffer to expedite the process.
 *
 * We aren't holding the AIL lock (or the flush lock) when this gets called,
 * so it is inherently race-y.
 */
STATIC void
xfs_inode_item_pushbuf(
	xfs_inode_log_item_t	*iip)
{
	xfs_inode_t	*ip;
	xfs_mount_t	*mp;
	xfs_buf_t	*bp;
	uint		dopush;

	ip = iip->ili_inode;

	ASSERT(xfs_isilocked(ip, XFS_ILOCK_SHARED));

	/*
	 * The ili_pushbuf_flag keeps others from
	 * trying to duplicate our effort.
	 */
	ASSERT(iip->ili_pushbuf_flag != 0);
	ASSERT(iip->ili_push_owner == current_pid());

	/*
	 * If a flush is not in progress anymore, chances are that the
	 * inode was taken off the AIL. So, just get out.
	 */
	if (completion_done(&ip->i_flush) ||
	    ((iip->ili_item.li_flags & XFS_LI_IN_AIL) == 0)) {
		iip->ili_pushbuf_flag = 0;
		xfs_iunlock(ip, XFS_ILOCK_SHARED);
		return;
	}

	mp = ip->i_mount;
	bp = xfs_incore(mp->m_ddev_targp, iip->ili_format.ilf_blkno,
		    iip->ili_format.ilf_len, XFS_INCORE_TRYLOCK);

	if (bp != NULL) {
		if (XFS_BUF_ISDELAYWRITE(bp)) {
			/*
			 * We were racing with iflush because we don't hold
			 * the AIL lock or the flush lock. However, at this point,
			 * we have the buffer, and we know that it's dirty.
			 * So, it's possible that iflush raced with us, and
			 * this item is already taken off the AIL.
			 * If not, we can flush it async.
			 */
			dopush = ((iip->ili_item.li_flags & XFS_LI_IN_AIL) &&
				  !completion_done(&ip->i_flush));
			iip->ili_pushbuf_flag = 0;
			xfs_iunlock(ip, XFS_ILOCK_SHARED);
			xfs_buftrace("INODE ITEM PUSH", bp);
			if (XFS_BUF_ISPINNED(bp)) {
				xfs_log_force(mp, (xfs_lsn_t)0,
					      XFS_LOG_FORCE);
			}
			if (dopush) {
				int	error;
				error = xfs_bawrite(mp, bp);
				if (error)
					xfs_fs_cmn_err(CE_WARN, mp,
		"xfs_inode_item_pushbuf: pushbuf error %d on iip %p, bp %p",
							error, iip, bp);
			} else {
				xfs_buf_relse(bp);
			}
		} else {
			iip->ili_pushbuf_flag = 0;
			xfs_iunlock(ip, XFS_ILOCK_SHARED);
			xfs_buf_relse(bp);
		}
		return;
	}
	/*
	 * We have to be careful about resetting pushbuf flag too early (above).
	 * Even though in theory we can do it as soon as we have the buflock,
	 * we don't want others to be doing work needlessly. They'll come to
	 * this function thinking that pushing the buffer is their
	 * responsibility only to find that the buffer is still locked by
	 * another doing the same thing
	 */
	iip->ili_pushbuf_flag = 0;
	xfs_iunlock(ip, XFS_ILOCK_SHARED);
	return;
}


/*
 * This is called to asynchronously write the inode associated with this
 * inode log item out to disk. The inode will already have been locked by
 * a successful call to xfs_inode_item_trylock().
 */
STATIC void
xfs_inode_item_push(
	xfs_inode_log_item_t	*iip)
{
	xfs_inode_t	*ip;

	ip = iip->ili_inode;

	ASSERT(xfs_isilocked(ip, XFS_ILOCK_SHARED));
	ASSERT(!completion_done(&ip->i_flush));
	/*
	 * Since we were able to lock the inode's flush lock and
	 * we found it on the AIL, the inode must be dirty.  This
	 * is because the inode is removed from the AIL while still
	 * holding the flush lock in xfs_iflush_done().  Thus, if
	 * we found it in the AIL and were able to obtain the flush
	 * lock without sleeping, then there must not have been
	 * anyone in the process of flushing the inode.
	 */
	ASSERT(XFS_FORCED_SHUTDOWN(ip->i_mount) ||
	       iip->ili_format.ilf_fields != 0);

	/*
	 * Write out the inode.  The completion routine ('iflush_done') will
	 * pull it from the AIL, mark it clean, unlock the flush lock.
	 */
	(void) xfs_iflush(ip, XFS_IFLUSH_ASYNC);
	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	return;
	struct xfs_log_item	*lip)
{
	struct xfs_inode_log_item *iip = INODE_ITEM(lip);
	struct xfs_inode	*ip = iip->ili_inode;
	unsigned short		lock_flags;

	ASSERT(ip->i_itemp != NULL);
	ASSERT(xfs_isilocked(ip, XFS_ILOCK_EXCL));

	lock_flags = iip->ili_lock_flags;
	iip->ili_lock_flags = 0;
	if (lock_flags)
		xfs_iunlock(ip, lock_flags);
}

/*
 * This is called to find out where the oldest active copy of the inode log
 * item in the on disk log resides now that the last log write of it completed
 * at the given lsn.  Since we always re-log all dirty data in an inode, the
 * latest copy in the on disk log is the only one that matters.  Therefore,
 * simply return the given lsn.
 *
 * If the inode has been marked stale because the cluster is being freed, we
 * don't want to (re-)insert this inode into the AIL. There is a race condition
 * where the cluster buffer may be unpinned before the inode is inserted into
 * the AIL during transaction committed processing. If the buffer is unpinned
 * before the inode item has been committed and inserted, then it is possible
 * for the buffer to be written and IO completes before the inode is inserted
 * into the AIL. In that case, we'd be inserting a clean, stale inode into the
 * AIL which will never get removed. It will, however, get reclaimed which
 * triggers an assert in xfs_inode_free() complaining about freein an inode
 * still in the AIL.
 *
 * To avoid this, just unpin the inode directly and return a LSN of -1 so the
 * transaction committed code knows that it does not need to do any further
 * processing on the item.
 */
STATIC xfs_lsn_t
xfs_inode_item_committed(
	struct xfs_log_item	*lip,
	xfs_lsn_t		lsn)
{
	struct xfs_inode_log_item *iip = INODE_ITEM(lip);
	struct xfs_inode	*ip = iip->ili_inode;

	if (xfs_iflags_test(ip, XFS_ISTALE)) {
		xfs_inode_item_unpin(lip, 0);
		return -1;
	}
	return lsn;
}

/*
 * XXX rcc - this one really has to do something.  Probably needs
 * to stamp in a new field in the incore inode.
 */
/* ARGSUSED */
STATIC void
xfs_inode_item_committing(
	xfs_inode_log_item_t	*iip,
	xfs_lsn_t		lsn)
{
	iip->ili_last_lsn = lsn;
	return;
STATIC void
xfs_inode_item_committing(
	struct xfs_log_item	*lip,
	xfs_lsn_t		lsn)
{
	INODE_ITEM(lip)->ili_last_lsn = lsn;
}

/*
 * This is the ops vector shared by all buf log items.
 */
static struct xfs_item_ops xfs_inode_item_ops = {
	.iop_size	= (uint(*)(xfs_log_item_t*))xfs_inode_item_size,
	.iop_format	= (void(*)(xfs_log_item_t*, xfs_log_iovec_t*))
					xfs_inode_item_format,
	.iop_pin	= (void(*)(xfs_log_item_t*))xfs_inode_item_pin,
	.iop_unpin	= (void(*)(xfs_log_item_t*, int))xfs_inode_item_unpin,
	.iop_unpin_remove = (void(*)(xfs_log_item_t*, xfs_trans_t*))
					xfs_inode_item_unpin_remove,
	.iop_trylock	= (uint(*)(xfs_log_item_t*))xfs_inode_item_trylock,
	.iop_unlock	= (void(*)(xfs_log_item_t*))xfs_inode_item_unlock,
	.iop_committed	= (xfs_lsn_t(*)(xfs_log_item_t*, xfs_lsn_t))
					xfs_inode_item_committed,
	.iop_push	= (void(*)(xfs_log_item_t*))xfs_inode_item_push,
	.iop_pushbuf	= (void(*)(xfs_log_item_t*))xfs_inode_item_pushbuf,
	.iop_committing = (void(*)(xfs_log_item_t*, xfs_lsn_t))
					xfs_inode_item_committing
static const struct xfs_item_ops xfs_inode_item_ops = {
	.iop_size	= xfs_inode_item_size,
	.iop_format	= xfs_inode_item_format,
	.iop_pin	= xfs_inode_item_pin,
	.iop_unpin	= xfs_inode_item_unpin,
	.iop_unlock	= xfs_inode_item_unlock,
	.iop_committed	= xfs_inode_item_committed,
	.iop_push	= xfs_inode_item_push,
	.iop_committing = xfs_inode_item_committing,
	.iop_error	= xfs_inode_item_error
};


/*
 * Initialize the inode log item for a newly allocated (in-core) inode.
 */
void
xfs_inode_item_init(
	xfs_inode_t	*ip,
	xfs_mount_t	*mp)
{
	xfs_inode_log_item_t	*iip;
	struct xfs_inode	*ip,
	struct xfs_mount	*mp)
{
	struct xfs_inode_log_item *iip;

	ASSERT(ip->i_itemp == NULL);
	iip = ip->i_itemp = kmem_zone_zalloc(xfs_ili_zone, KM_SLEEP);

	iip->ili_item.li_type = XFS_LI_INODE;
	iip->ili_item.li_ops = &xfs_inode_item_ops;
	iip->ili_item.li_mountp = mp;
	iip->ili_inode = ip;

	/*
	   We have zeroed memory. No need ...
	   iip->ili_extents_buf = NULL;
	   iip->ili_pushbuf_flag = 0;
	 */

	iip->ili_format.ilf_type = XFS_LI_INODE;
	iip->ili_format.ilf_ino = ip->i_ino;
	iip->ili_format.ilf_blkno = ip->i_blkno;
	iip->ili_format.ilf_len = ip->i_len;
	iip->ili_format.ilf_boffset = ip->i_boffset;
	iip->ili_inode = ip;
	xfs_log_item_init(mp, &iip->ili_item, XFS_LI_INODE,
						&xfs_inode_item_ops);
}

/*
 * Free the inode log item and any memory hanging off of it.
 */
void
xfs_inode_item_destroy(
	xfs_inode_t	*ip)
{
#ifdef XFS_TRANS_DEBUG
	if (ip->i_itemp->ili_root_size != 0) {
		kmem_free(ip->i_itemp->ili_orig_root);
	}
#endif
	kmem_free(ip->i_itemp->ili_item.li_lv_shadow);
	kmem_zone_free(xfs_ili_zone, ip->i_itemp);
}


/*
 * This is the inode flushing I/O completion routine.  It is called
 * from interrupt level when the buffer containing the inode is
 * flushed to disk.  It is responsible for removing the inode item
 * from the AIL if it has not been re-logged, and unlocking the inode's
 * flush lock.
 */
/*ARGSUSED*/
void
xfs_iflush_done(
	xfs_buf_t		*bp,
	xfs_inode_log_item_t	*iip)
{
	xfs_inode_t	*ip;

	ip = iip->ili_inode;
 *
 * To reduce AIL lock traffic as much as possible, we scan the buffer log item
 * list for other inodes that will run this function. We remove them from the
 * buffer list so we can process all the inode IO completions in one AIL lock
 * traversal.
 */
void
xfs_iflush_done(
	struct xfs_buf		*bp,
	struct xfs_log_item	*lip)
{
	struct xfs_inode_log_item *iip;
	struct xfs_log_item	*blip, *n;
	struct xfs_ail		*ailp = lip->li_ailp;
	int			need_ail = 0;
	LIST_HEAD(tmp);

	/*
	 * Scan the buffer IO completions for other inodes being completed and
	 * attach them to the current inode log item.
	 */

	list_add_tail(&lip->li_bio_list, &tmp);

	list_for_each_entry_safe(blip, n, &bp->b_li_list, li_bio_list) {
		if (lip->li_cb != xfs_iflush_done)
			continue;

		list_move_tail(&blip->li_bio_list, &tmp);
		/*
		 * while we have the item, do the unlocked check for needing
		 * the AIL lock.
		 */
		iip = INODE_ITEM(blip);
		if ((iip->ili_logged && blip->li_lsn == iip->ili_flush_lsn) ||
		    test_bit(XFS_LI_FAILED, &blip->li_flags))
			need_ail++;
	}

	/* make sure we capture the state of the initial inode. */
	iip = INODE_ITEM(lip);
	if ((iip->ili_logged && lip->li_lsn == iip->ili_flush_lsn) ||
	    test_bit(XFS_LI_FAILED, &lip->li_flags))
		need_ail++;

	/*
	 * We only want to pull the item from the AIL if it is
	 * actually there and its location in the log has not
	 * changed since we started the flush.  Thus, we only bother
	 * if the ili_logged flag is set and the inode's lsn has not
	 * changed.  First we check the lsn outside
	 * the lock since it's cheaper, and then we recheck while
	 * holding the lock before removing the inode from the AIL.
	 */
	if (iip->ili_logged &&
	    (iip->ili_item.li_lsn == iip->ili_flush_lsn)) {
		spin_lock(&ip->i_mount->m_ail_lock);
		if (iip->ili_item.li_lsn == iip->ili_flush_lsn) {
			/*
			 * xfs_trans_delete_ail() drops the AIL lock.
			 */
			xfs_trans_delete_ail(ip->i_mount,
					     (xfs_log_item_t*)iip);
		} else {
			spin_unlock(&ip->i_mount->m_ail_lock);
		}
	}

	iip->ili_logged = 0;

	/*
	 * Clear the ili_last_fields bits now that we know that the
	 * data corresponding to them is safely on disk.
	 */
	iip->ili_last_fields = 0;

	/*
	 * Release the inode's flush lock since we're done with it.
	 */
	xfs_ifunlock(ip);

	return;
}

/*
 * This is the inode flushing abort routine.  It is called
 * from xfs_iflush when the filesystem is shutting down to clean
 * up the inode state.
 * It is responsible for removing the inode item
 * from the AIL if it has not been re-logged, and unlocking the inode's
 * flush lock.
 */
void
xfs_iflush_abort(
	xfs_inode_t		*ip)
{
	xfs_inode_log_item_t	*iip;
	xfs_mount_t		*mp;

	iip = ip->i_itemp;
	mp = ip->i_mount;
	if (iip) {
		if (iip->ili_item.li_flags & XFS_LI_IN_AIL) {
			spin_lock(&mp->m_ail_lock);
			if (iip->ili_item.li_flags & XFS_LI_IN_AIL) {
				/*
				 * xfs_trans_delete_ail() drops the AIL lock.
				 */
				xfs_trans_delete_ail(mp, (xfs_log_item_t *)iip);
			} else
				spin_unlock(&mp->m_ail_lock);
	if (need_ail) {
		bool			mlip_changed = false;

		/* this is an opencoded batch version of xfs_trans_ail_delete */
		spin_lock(&ailp->ail_lock);
		list_for_each_entry(blip, &tmp, li_bio_list) {
			if (INODE_ITEM(blip)->ili_logged &&
			    blip->li_lsn == INODE_ITEM(blip)->ili_flush_lsn)
				mlip_changed |= xfs_ail_delete_one(ailp, blip);
			else {
				xfs_clear_li_failed(blip);
			}
		}

		if (mlip_changed) {
			if (!XFS_FORCED_SHUTDOWN(ailp->ail_mount))
				xlog_assign_tail_lsn_locked(ailp->ail_mount);
			if (list_empty(&ailp->ail_head))
				wake_up_all(&ailp->ail_empty);
		}
		spin_unlock(&ailp->ail_lock);

		if (mlip_changed)
			xfs_log_space_wake(ailp->ail_mount);
	}

	/*
	 * clean up and unlock the flush lock now we are done. We can clear the
	 * ili_last_fields bits now that we know that the data corresponding to
	 * them is safely on disk.
	 */
	list_for_each_entry_safe(blip, n, &tmp, li_bio_list) {
		list_del_init(&blip->li_bio_list);
		iip = INODE_ITEM(blip);
		iip->ili_logged = 0;
		iip->ili_last_fields = 0;
		xfs_ifunlock(iip->ili_inode);
	}
	list_del(&tmp);
}

/*
 * This is the inode flushing abort routine.  It is called from xfs_iflush when
 * the filesystem is shutting down to clean up the inode state.  It is
 * responsible for removing the inode item from the AIL if it has not been
 * re-logged, and unlocking the inode's flush lock.
 */
void
xfs_iflush_abort(
	xfs_inode_t		*ip,
	bool			stale)
{
	xfs_inode_log_item_t	*iip = ip->i_itemp;

	if (iip) {
		if (test_bit(XFS_LI_IN_AIL, &iip->ili_item.li_flags)) {
			xfs_trans_ail_remove(&iip->ili_item,
					     stale ? SHUTDOWN_LOG_IO_ERROR :
						     SHUTDOWN_CORRUPT_INCORE);
		}
		iip->ili_logged = 0;
		/*
		 * Clear the ili_last_fields bits now that we know that the
		 * data corresponding to them is safely on disk.
		 */
		iip->ili_last_fields = 0;
		/*
		 * Clear the inode logging fields so no more flushes are
		 * attempted.
		 */
		iip->ili_format.ilf_fields = 0;
		iip->ili_fields = 0;
		iip->ili_fsync_fields = 0;
	}
	/*
	 * Release the inode's flush lock since we're done with it.
	 */
	xfs_ifunlock(ip);
}

void
xfs_istale_done(
	xfs_buf_t		*bp,
	xfs_inode_log_item_t	*iip)
{
	xfs_iflush_abort(iip->ili_inode);
	struct xfs_buf		*bp,
	struct xfs_log_item	*lip)
{
	xfs_iflush_abort(INODE_ITEM(lip)->ili_inode, true);
}

/*
 * convert an xfs_inode_log_format struct from the old 32 bit version
 * (which can have different field alignments) to the native 64 bit version
 */
int
xfs_inode_item_format_convert(
	struct xfs_log_iovec		*buf,
	struct xfs_inode_log_format	*in_f)
{
	if (buf->i_len == sizeof(xfs_inode_log_format_32_t)) {
		xfs_inode_log_format_32_t *in_f32;

		in_f32 = (xfs_inode_log_format_32_t *)buf->i_addr;
		xfs_inode_log_format_32_t *in_f32 = buf->i_addr;

		in_f->ilf_type = in_f32->ilf_type;
		in_f->ilf_size = in_f32->ilf_size;
		in_f->ilf_fields = in_f32->ilf_fields;
		in_f->ilf_asize = in_f32->ilf_asize;
		in_f->ilf_dsize = in_f32->ilf_dsize;
		in_f->ilf_ino = in_f32->ilf_ino;
		/* copy biggest field of ilf_u */
		memcpy(in_f->ilf_u.ilfu_uuid.__u_bits,
		       in_f32->ilf_u.ilfu_uuid.__u_bits,
		       sizeof(uuid_t));
		in_f->ilf_blkno = in_f32->ilf_blkno;
		in_f->ilf_len = in_f32->ilf_len;
		in_f->ilf_boffset = in_f32->ilf_boffset;
		return 0;
	} else if (buf->i_len == sizeof(xfs_inode_log_format_64_t)){
		xfs_inode_log_format_64_t *in_f64;

		in_f64 = (xfs_inode_log_format_64_t *)buf->i_addr;
		xfs_inode_log_format_64_t *in_f64 = buf->i_addr;

		in_f->ilf_type = in_f64->ilf_type;
		in_f->ilf_size = in_f64->ilf_size;
		in_f->ilf_fields = in_f64->ilf_fields;
		in_f->ilf_asize = in_f64->ilf_asize;
		in_f->ilf_dsize = in_f64->ilf_dsize;
		in_f->ilf_ino = in_f64->ilf_ino;
		/* copy biggest field of ilf_u */
		memcpy(in_f->ilf_u.ilfu_uuid.__u_bits,
		       in_f64->ilf_u.ilfu_uuid.__u_bits,
		       sizeof(uuid_t));
		in_f->ilf_blkno = in_f64->ilf_blkno;
		in_f->ilf_len = in_f64->ilf_len;
		in_f->ilf_boffset = in_f64->ilf_boffset;
		return 0;
	}
	return EFSCORRUPTED;
	return -EFSCORRUPTED;
	struct xfs_inode_log_format_32	*in_f32 = buf->i_addr;

	if (buf->i_len != sizeof(*in_f32))
		return -EFSCORRUPTED;

	in_f->ilf_type = in_f32->ilf_type;
	in_f->ilf_size = in_f32->ilf_size;
	in_f->ilf_fields = in_f32->ilf_fields;
	in_f->ilf_asize = in_f32->ilf_asize;
	in_f->ilf_dsize = in_f32->ilf_dsize;
	in_f->ilf_ino = in_f32->ilf_ino;
	memcpy(&in_f->ilf_u, &in_f32->ilf_u, sizeof(in_f->ilf_u));
	in_f->ilf_blkno = in_f32->ilf_blkno;
	in_f->ilf_len = in_f32->ilf_len;
	in_f->ilf_boffset = in_f32->ilf_boffset;
	return 0;
}
