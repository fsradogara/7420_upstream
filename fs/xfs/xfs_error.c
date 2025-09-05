/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_types.h"
#include "xfs_log.h"
#include "xfs_inum.h"
#include "xfs_trans.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_dir2.h"
#include "xfs_dmapi.h"
#include "xfs_mount.h"
#include "xfs_bmap_btree.h"
#include "xfs_dir2_sf.h"
#include "xfs_attr_sf.h"
#include "xfs_dinode.h"
#include "xfs_inode.h"
#include "xfs_utils.h"
#include "xfs_format.h"
#include "xfs_fs.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_error.h"
#include "xfs_sysfs.h"

#ifdef DEBUG

int	xfs_etrap[XFS_ERROR_NTRAP] = {
	0,
};

int
xfs_error_trap(int e)
{
	int i;

	if (!e)
		return 0;
	for (i = 0; i < XFS_ERROR_NTRAP; i++) {
		if (xfs_etrap[i] == 0)
			break;
		if (e != xfs_etrap[i])
			continue;
		cmn_err(CE_NOTE, "xfs_error_trap: error %d", e);
		BUG();
		break;
	}
	return e;
}

int	xfs_etest[XFS_NUM_INJECT_ERROR];
int64_t	xfs_etest_fsid[XFS_NUM_INJECT_ERROR];
char *	xfs_etest_fsname[XFS_NUM_INJECT_ERROR];
int	xfs_etest[XFS_NUM_INJECT_ERROR];
int64_t	xfs_etest_fsid[XFS_NUM_INJECT_ERROR];
char *	xfs_etest_fsname[XFS_NUM_INJECT_ERROR];
int	xfs_error_test_active;
static unsigned int xfs_errortag_random_default[] = {
	XFS_RANDOM_DEFAULT,
	XFS_RANDOM_IFLUSH_1,
	XFS_RANDOM_IFLUSH_2,
	XFS_RANDOM_IFLUSH_3,
	XFS_RANDOM_IFLUSH_4,
	XFS_RANDOM_IFLUSH_5,
	XFS_RANDOM_IFLUSH_6,
	XFS_RANDOM_DA_READ_BUF,
	XFS_RANDOM_BTREE_CHECK_LBLOCK,
	XFS_RANDOM_BTREE_CHECK_SBLOCK,
	XFS_RANDOM_ALLOC_READ_AGF,
	XFS_RANDOM_IALLOC_READ_AGI,
	XFS_RANDOM_ITOBP_INOTOBP,
	XFS_RANDOM_IUNLINK,
	XFS_RANDOM_IUNLINK_REMOVE,
	XFS_RANDOM_DIR_INO_VALIDATE,
	XFS_RANDOM_BULKSTAT_READ_CHUNK,
	XFS_RANDOM_IODONE_IOERR,
	XFS_RANDOM_STRATREAD_IOERR,
	XFS_RANDOM_STRATCMPL_IOERR,
	XFS_RANDOM_DIOWRITE_IOERR,
	XFS_RANDOM_BMAPIFORMAT,
	XFS_RANDOM_FREE_EXTENT,
	XFS_RANDOM_RMAP_FINISH_ONE,
	XFS_RANDOM_REFCOUNT_CONTINUE_UPDATE,
	XFS_RANDOM_REFCOUNT_FINISH_ONE,
	XFS_RANDOM_BMAP_FINISH_ONE,
	XFS_RANDOM_AG_RESV_CRITICAL,
	XFS_RANDOM_DROP_WRITES,
	XFS_RANDOM_LOG_BAD_CRC,
	XFS_RANDOM_LOG_ITEM_PIN,
};

struct xfs_errortag_attr {
	struct attribute	attr;
	unsigned int		tag;
};

static inline struct xfs_errortag_attr *
to_attr(struct attribute *attr)
{
	return container_of(attr, struct xfs_errortag_attr, attr);
}

	if (random32() % randfactor)
	if (prandom_u32() % randfactor)
		return 0;
static inline struct xfs_mount *
to_mp(struct kobject *kobject)
{
	struct xfs_kobj *kobj = to_kobj(kobject);

	return container_of(kobj, struct xfs_mount, m_errortag_kobj);
}

	for (i = 0; i < XFS_NUM_INJECT_ERROR; i++)  {
		if (xfs_etest[i] == error_tag && xfs_etest_fsid[i] == fsid) {
			cmn_err(CE_WARN,
			xfs_warn(NULL,
	"Injecting error (%s) at file %s, line %d, on filesystem \"%s\"",
				expression, file, line, xfs_etest_fsname[i]);
			return 1;
		}
STATIC ssize_t
xfs_errortag_attr_store(
	struct kobject		*kobject,
	struct attribute	*attr,
	const char		*buf,
	size_t			count)
{
	struct xfs_mount	*mp = to_mp(kobject);
	struct xfs_errortag_attr *xfs_attr = to_attr(attr);
	int			ret;
	unsigned int		val;

	if (strcmp(buf, "default") == 0) {
		val = xfs_errortag_random_default[xfs_attr->tag];
	} else {
		ret = kstrtouint(buf, 0, &val);
		if (ret)
			return ret;
	}

	ret = xfs_errortag_set(mp, xfs_attr->tag, val);
	if (ret)
		return ret;
	return count;
}

STATIC ssize_t
xfs_errortag_attr_show(
	struct kobject		*kobject,
	struct attribute	*attr,
	char			*buf)
{
	struct xfs_mount	*mp = to_mp(kobject);
	struct xfs_errortag_attr *xfs_attr = to_attr(attr);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			xfs_errortag_get(mp, xfs_attr->tag));
}

static const struct sysfs_ops xfs_errortag_sysfs_ops = {
	.show = xfs_errortag_attr_show,
	.store = xfs_errortag_attr_store,
};

#define XFS_ERRORTAG_ATTR_RW(_name, _tag) \
static struct xfs_errortag_attr xfs_errortag_attr_##_name = {		\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(S_IWUSR | S_IRUGO) },	\
	.tag	= (_tag),						\
}

#define XFS_ERRORTAG_ATTR_LIST(_name) &xfs_errortag_attr_##_name.attr

XFS_ERRORTAG_ATTR_RW(noerror,		XFS_ERRTAG_NOERROR);
XFS_ERRORTAG_ATTR_RW(iflush1,		XFS_ERRTAG_IFLUSH_1);
XFS_ERRORTAG_ATTR_RW(iflush2,		XFS_ERRTAG_IFLUSH_2);
XFS_ERRORTAG_ATTR_RW(iflush3,		XFS_ERRTAG_IFLUSH_3);
XFS_ERRORTAG_ATTR_RW(iflush4,		XFS_ERRTAG_IFLUSH_4);
XFS_ERRORTAG_ATTR_RW(iflush5,		XFS_ERRTAG_IFLUSH_5);
XFS_ERRORTAG_ATTR_RW(iflush6,		XFS_ERRTAG_IFLUSH_6);
XFS_ERRORTAG_ATTR_RW(dareadbuf,		XFS_ERRTAG_DA_READ_BUF);
XFS_ERRORTAG_ATTR_RW(btree_chk_lblk,	XFS_ERRTAG_BTREE_CHECK_LBLOCK);
XFS_ERRORTAG_ATTR_RW(btree_chk_sblk,	XFS_ERRTAG_BTREE_CHECK_SBLOCK);
XFS_ERRORTAG_ATTR_RW(readagf,		XFS_ERRTAG_ALLOC_READ_AGF);
XFS_ERRORTAG_ATTR_RW(readagi,		XFS_ERRTAG_IALLOC_READ_AGI);
XFS_ERRORTAG_ATTR_RW(itobp,		XFS_ERRTAG_ITOBP_INOTOBP);
XFS_ERRORTAG_ATTR_RW(iunlink,		XFS_ERRTAG_IUNLINK);
XFS_ERRORTAG_ATTR_RW(iunlinkrm,		XFS_ERRTAG_IUNLINK_REMOVE);
XFS_ERRORTAG_ATTR_RW(dirinovalid,	XFS_ERRTAG_DIR_INO_VALIDATE);
XFS_ERRORTAG_ATTR_RW(bulkstat,		XFS_ERRTAG_BULKSTAT_READ_CHUNK);
XFS_ERRORTAG_ATTR_RW(logiodone,		XFS_ERRTAG_IODONE_IOERR);
XFS_ERRORTAG_ATTR_RW(stratread,		XFS_ERRTAG_STRATREAD_IOERR);
XFS_ERRORTAG_ATTR_RW(stratcmpl,		XFS_ERRTAG_STRATCMPL_IOERR);
XFS_ERRORTAG_ATTR_RW(diowrite,		XFS_ERRTAG_DIOWRITE_IOERR);
XFS_ERRORTAG_ATTR_RW(bmapifmt,		XFS_ERRTAG_BMAPIFORMAT);
XFS_ERRORTAG_ATTR_RW(free_extent,	XFS_ERRTAG_FREE_EXTENT);
XFS_ERRORTAG_ATTR_RW(rmap_finish_one,	XFS_ERRTAG_RMAP_FINISH_ONE);
XFS_ERRORTAG_ATTR_RW(refcount_continue_update,	XFS_ERRTAG_REFCOUNT_CONTINUE_UPDATE);
XFS_ERRORTAG_ATTR_RW(refcount_finish_one,	XFS_ERRTAG_REFCOUNT_FINISH_ONE);
XFS_ERRORTAG_ATTR_RW(bmap_finish_one,	XFS_ERRTAG_BMAP_FINISH_ONE);
XFS_ERRORTAG_ATTR_RW(ag_resv_critical,	XFS_ERRTAG_AG_RESV_CRITICAL);
XFS_ERRORTAG_ATTR_RW(drop_writes,	XFS_ERRTAG_DROP_WRITES);
XFS_ERRORTAG_ATTR_RW(log_bad_crc,	XFS_ERRTAG_LOG_BAD_CRC);
XFS_ERRORTAG_ATTR_RW(log_item_pin,	XFS_ERRTAG_LOG_ITEM_PIN);

static struct attribute *xfs_errortag_attrs[] = {
	XFS_ERRORTAG_ATTR_LIST(noerror),
	XFS_ERRORTAG_ATTR_LIST(iflush1),
	XFS_ERRORTAG_ATTR_LIST(iflush2),
	XFS_ERRORTAG_ATTR_LIST(iflush3),
	XFS_ERRORTAG_ATTR_LIST(iflush4),
	XFS_ERRORTAG_ATTR_LIST(iflush5),
	XFS_ERRORTAG_ATTR_LIST(iflush6),
	XFS_ERRORTAG_ATTR_LIST(dareadbuf),
	XFS_ERRORTAG_ATTR_LIST(btree_chk_lblk),
	XFS_ERRORTAG_ATTR_LIST(btree_chk_sblk),
	XFS_ERRORTAG_ATTR_LIST(readagf),
	XFS_ERRORTAG_ATTR_LIST(readagi),
	XFS_ERRORTAG_ATTR_LIST(itobp),
	XFS_ERRORTAG_ATTR_LIST(iunlink),
	XFS_ERRORTAG_ATTR_LIST(iunlinkrm),
	XFS_ERRORTAG_ATTR_LIST(dirinovalid),
	XFS_ERRORTAG_ATTR_LIST(bulkstat),
	XFS_ERRORTAG_ATTR_LIST(logiodone),
	XFS_ERRORTAG_ATTR_LIST(stratread),
	XFS_ERRORTAG_ATTR_LIST(stratcmpl),
	XFS_ERRORTAG_ATTR_LIST(diowrite),
	XFS_ERRORTAG_ATTR_LIST(bmapifmt),
	XFS_ERRORTAG_ATTR_LIST(free_extent),
	XFS_ERRORTAG_ATTR_LIST(rmap_finish_one),
	XFS_ERRORTAG_ATTR_LIST(refcount_continue_update),
	XFS_ERRORTAG_ATTR_LIST(refcount_finish_one),
	XFS_ERRORTAG_ATTR_LIST(bmap_finish_one),
	XFS_ERRORTAG_ATTR_LIST(ag_resv_critical),
	XFS_ERRORTAG_ATTR_LIST(drop_writes),
	XFS_ERRORTAG_ATTR_LIST(log_bad_crc),
	XFS_ERRORTAG_ATTR_LIST(log_item_pin),
	NULL,
};

struct kobj_type xfs_errortag_ktype = {
	.release = xfs_sysfs_release,
	.sysfs_ops = &xfs_errortag_sysfs_ops,
	.default_attrs = xfs_errortag_attrs,
};

int
xfs_errortag_init(
	struct xfs_mount	*mp)
{
	mp->m_errortag = kmem_zalloc(sizeof(unsigned int) * XFS_ERRTAG_MAX,
			KM_SLEEP | KM_MAYFAIL);
	if (!mp->m_errortag)
		return -ENOMEM;

	return xfs_sysfs_init(&mp->m_errortag_kobj, &xfs_errortag_ktype,
			       &mp->m_kobj, "errortag");
}

void
xfs_errortag_del(
	struct xfs_mount	*mp)
{
	xfs_sysfs_del(&mp->m_errortag_kobj);
	kmem_free(mp->m_errortag);
}

bool
xfs_errortag_test(
	struct xfs_mount	*mp,
	const char		*expression,
	const char		*file,
	int			line,
	unsigned int		error_tag)
{
	unsigned int		randfactor;

	/*
	 * To be able to use error injection anywhere, we need to ensure error
	 * injection mechanism is already initialized.
	 *
	 * Code paths like I/O completion can be called before the
	 * initialization is complete, but be able to inject errors in such
	 * places is still useful.
	 */
	if (!mp->m_errortag)
		return false;

	ASSERT(error_tag < XFS_ERRTAG_MAX);
	randfactor = mp->m_errortag[error_tag];
	if (!randfactor || prandom_u32() % randfactor)
		return false;

	xfs_warn_ratelimited(mp,
"Injecting error (%s) at file %s, line %d, on filesystem \"%s\"",
			expression, file, line, mp->m_fsname);
	return true;
}

int
xfs_errortag_get(
	struct xfs_mount	*mp,
	unsigned int		error_tag)
{
	if (error_tag >= XFS_ERRTAG_MAX)
		return -EINVAL;

	return mp->m_errortag[error_tag];
}

int
xfs_errortag_set(
	struct xfs_mount	*mp,
	unsigned int		error_tag,
	unsigned int		tag_value)
{
	if (error_tag >= XFS_ERRTAG_MAX)
		return -EINVAL;

	mp->m_errortag[error_tag] = tag_value;
	return 0;
}

int
xfs_errortag_add(
	struct xfs_mount	*mp,
	unsigned int		error_tag)
{
	if (error_tag >= XFS_ERRTAG_MAX)
		return -EINVAL;

	memcpy(&fsid, mp->m_fixedfsid, sizeof(xfs_fsid_t));

	for (i = 0; i < XFS_NUM_INJECT_ERROR; i++)  {
		if (xfs_etest_fsid[i] == fsid && xfs_etest[i] == error_tag) {
			cmn_err(CE_WARN, "XFS error tag #%d on", error_tag);
			xfs_warn(mp, "error tag #%d on", error_tag);
			return 0;
		}
	}

	for (i = 0; i < XFS_NUM_INJECT_ERROR; i++)  {
		if (xfs_etest[i] == 0) {
			cmn_err(CE_WARN, "Turned on XFS error tag #%d",
			xfs_warn(mp, "Turned on XFS error tag #%d",
				error_tag);
			xfs_etest[i] = error_tag;
			xfs_etest_fsid[i] = fsid;
			len = strlen(mp->m_fsname);
			xfs_etest_fsname[i] = kmem_alloc(len + 1, KM_SLEEP);
			strcpy(xfs_etest_fsname[i], mp->m_fsname);
			xfs_error_test_active++;
			return 0;
		}
	}

	cmn_err(CE_WARN, "error tag overflow, too many turned on");
	xfs_warn(mp, "error tag overflow, too many turned on");

	return 1;
	return xfs_errortag_set(mp, error_tag,
			xfs_errortag_random_default[error_tag]);
}

int
xfs_errortag_clearall(
	struct xfs_mount	*mp)
{
	int64_t fsid;
	int cleared = 0;
	int i;

	memcpy(&fsid, mp->m_fixedfsid, sizeof(xfs_fsid_t));


	for (i = 0; i < XFS_NUM_INJECT_ERROR; i++) {
		if ((fsid == 0LL || xfs_etest_fsid[i] == fsid) &&
		     xfs_etest[i] != 0) {
			cleared = 1;
			cmn_err(CE_WARN, "Clearing XFS error tag #%d",
			xfs_warn(mp, "Clearing XFS error tag #%d",
				xfs_etest[i]);
			xfs_etest[i] = 0;
			xfs_etest_fsid[i] = 0LL;
			kmem_free(xfs_etest_fsname[i]);
			xfs_etest_fsname[i] = NULL;
			xfs_error_test_active--;
		}
	}

	if (loud || cleared)
		cmn_err(CE_WARN,
			"Cleared all XFS error tags for filesystem \"%s\"",
			mp->m_fsname);
		xfs_warn(mp, "Cleared all XFS error tags for filesystem");

	memset(mp->m_errortag, 0, sizeof(unsigned int) * XFS_ERRTAG_MAX);
	return 0;
}
#endif /* DEBUG */

static void
xfs_fs_vcmn_err(int level, xfs_mount_t *mp, char *fmt, va_list ap)
{
	if (mp != NULL) {
		char	*newfmt;
		int	len = 16 + mp->m_fsname_len + strlen(fmt);

		newfmt = kmem_alloc(len, KM_SLEEP);
		sprintf(newfmt, "Filesystem \"%s\": %s", mp->m_fsname, fmt);
		icmn_err(level, newfmt, ap);
		kmem_free(newfmt);
	} else {
		icmn_err(level, fmt, ap);
	}
}

void
xfs_fs_cmn_err(int level, xfs_mount_t *mp, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	xfs_fs_vcmn_err(level, mp, fmt, ap);
	va_end(ap);
}

void
xfs_cmn_err(int panic_tag, int level, xfs_mount_t *mp, char *fmt, ...)
{
	va_list ap;

#ifdef DEBUG
	xfs_panic_mask |= XFS_PTAG_SHUTDOWN_CORRUPT;
#endif

	if (xfs_panic_mask && (xfs_panic_mask & panic_tag)
	    && (level & CE_ALERT)) {
		level &= ~CE_ALERT;
		level |= CE_PANIC;
		cmn_err(CE_ALERT, "XFS: Transforming an alert into a BUG.");
	}
	va_start(ap, fmt);
	xfs_fs_vcmn_err(level, mp, fmt, ap);
	va_end(ap);
}

void
xfs_error_report(
	char		*tag,
	int		level,
	xfs_mount_t	*mp,
	char		*fname,
	int		linenum,
	inst_t		*ra)
{
	if (level <= xfs_error_level) {
		xfs_cmn_err(XFS_PTAG_ERROR_REPORT,
			    CE_ALERT, mp,
		"XFS internal error %s at line %d of file %s.  Caller 0x%p\n",
			    tag, linenum, fname, ra);
void
xfs_error_report(
	const char		*tag,
	int			level,
	struct xfs_mount	*mp,
	const char		*filename,
	int			linenum,
	void			*ra)
{
	if (level <= xfs_error_level) {
		xfs_alert_tag(mp, XFS_PTAG_ERROR_REPORT,
		"Internal error %s at line %d of file %s.  Caller %pS",
			    tag, linenum, filename, ra);

		xfs_stack_trace();
	}
}

void
xfs_corruption_error(
	char		*tag,
	int		level,
	xfs_mount_t	*mp,
	void		*p,
	char		*fname,
	int		linenum,
	inst_t		*ra)
{
	if (level <= xfs_error_level)
		xfs_hex_dump(p, 16);
	xfs_error_report(tag, level, mp, fname, linenum, ra);
	const char		*tag,
	int			level,
	struct xfs_mount	*mp,
	void			*p,
	const char		*filename,
	int			linenum,
	void			*ra)
{
	if (level <= xfs_error_level)
		xfs_hex_dump(p, 64);
	xfs_error_report(tag, level, mp, filename, linenum, ra);
	xfs_alert(mp, "Corruption detected. Unmount and run xfs_repair");
}

/*
 * Warnings specifically for verifier errors.  Differentiate CRC vs. invalid
 * values, and omit the stack trace unless the error level is tuned high.
 */
void
xfs_verifier_error(
	struct xfs_buf		*bp)
{
	struct xfs_mount *mp = bp->b_target->bt_mount;

	xfs_alert(mp, "Metadata %s detected at %pS, %s block 0x%llx",
		  bp->b_error == -EFSBADCRC ? "CRC error" : "corruption",
		  __return_address, bp->b_ops->name, bp->b_bn);

	xfs_alert(mp, "Unmount and run xfs_repair");

	if (xfs_error_level >= XFS_ERRLEVEL_LOW) {
		xfs_alert(mp, "First 64 bytes of corrupted metadata buffer:");
		xfs_hex_dump(xfs_buf_offset(bp, 0), 64);
	}

	if (xfs_error_level >= XFS_ERRLEVEL_HIGH)
		xfs_stack_trace();
}
