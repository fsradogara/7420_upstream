/* Updated: Karl MacMillan <kmacmillan@tresys.com>
 *
 *	Added conditional policy language extensions
 *
 *  Updated: Hewlett-Packard <paul.moore@hp.com>
 *  Updated: Hewlett-Packard <paul@paul-moore.com>
 *
 *	Added support for the policy capability bitmap
 *
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 * Copyright (C) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/security.h>
#include <linux/major.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/audit.h>
#include <linux/uaccess.h>
#include <linux/kobject.h>
#include <linux/ctype.h>

/* selinuxfs pseudo filesystem for exporting the security policy API.
   Based on the proc code and the fs/nfsd/nfsctl.c code. */

#include "flask.h"
#include "avc.h"
#include "avc_ss.h"
#include "security.h"
#include "objsec.h"
#include "conditional.h"

/* Policy capability filenames */
static char *policycap_names[] = {
	"network_peer_controls",
	"open_perms"
	"open_perms",
	"redhat1",
	"always_check_network"
};

unsigned int selinux_checkreqprot = CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE;

#ifdef CONFIG_SECURITY_SELINUX_ENABLE_SECMARK_DEFAULT
#define SELINUX_COMPAT_NET_VALUE 0
#else
#define SELINUX_COMPAT_NET_VALUE 1
#endif

int selinux_compat_net = SELINUX_COMPAT_NET_VALUE;

static int __init checkreqprot_setup(char *str)
{
	unsigned long checkreqprot;
	if (!strict_strtoul(str, 0, &checkreqprot))
static int __init checkreqprot_setup(char *str)
{
	unsigned long checkreqprot;
	if (!kstrtoul(str, 0, &checkreqprot))
		selinux_checkreqprot = checkreqprot ? 1 : 0;
	return 1;
}
__setup("checkreqprot=", checkreqprot_setup);

static int __init selinux_compat_net_setup(char *str)
{
	unsigned long compat_net;
	if (!strict_strtoul(str, 0, &compat_net))
		selinux_compat_net = compat_net ? 1 : 0;
	return 1;
}
__setup("selinux_compat_net=", selinux_compat_net_setup);


static DEFINE_MUTEX(sel_mutex);

/* global data for booleans */
static struct dentry *bool_dir;
static int bool_num;
static char **bool_pending_names;
static int *bool_pending_values;

/* global data for classes */
static struct dentry *class_dir;
static unsigned long last_class_ino;

/* global data for policy capabilities */
static struct dentry *policycap_dir;

extern void selnl_notify_setenforce(int val);

static char policy_opened;

/* global data for policy capabilities */
static struct dentry *policycap_dir;

/* Check whether a task is allowed to use a security operation. */
static int task_has_security(struct task_struct *tsk,
			     u32 perms)
{
	struct task_security_struct *tsec;

	tsec = tsk->security;
	if (!tsec)
		return -EACCES;

	return avc_has_perm(tsec->sid, SECINITSID_SECURITY,
	const struct task_security_struct *tsec;
	u32 sid = 0;

	rcu_read_lock();
	tsec = __task_cred(tsk)->security;
	if (tsec)
		sid = tsec->sid;
	rcu_read_unlock();
	if (!tsec)
		return -EACCES;

	return avc_has_perm(sid, SECINITSID_SECURITY,
			    SECCLASS_SECURITY, perms, NULL);
}

enum sel_inos {
	SEL_ROOT_INO = 2,
	SEL_LOAD,	/* load policy */
	SEL_ENFORCE,	/* get or set enforcing status */
	SEL_CONTEXT,	/* validate context */
	SEL_ACCESS,	/* compute access decision */
	SEL_CREATE,	/* compute create labeling decision */
	SEL_RELABEL,	/* compute relabeling decision */
	SEL_USER,	/* compute reachable user contexts */
	SEL_POLICYVERS,	/* return policy version for this kernel */
	SEL_COMMIT_BOOLS, /* commit new boolean values */
	SEL_MLS,	/* return if MLS policy is enabled */
	SEL_DISABLE,	/* disable SELinux until next reboot */
	SEL_MEMBER,	/* compute polyinstantiation membership decision */
	SEL_CHECKREQPROT, /* check requested protection, not kernel-applied one */
	SEL_COMPAT_NET,	/* whether to use old compat network packet controls */
	SEL_REJECT_UNKNOWN, /* export unknown reject handling to userspace */
	SEL_DENY_UNKNOWN, /* export unknown deny handling to userspace */
	SEL_STATUS,	/* export current status using mmap() */
	SEL_POLICY,	/* allow userspace to read the in kernel policy */
	SEL_VALIDATE_TRANS, /* compute validatetrans decision */
	SEL_INO_NEXT,	/* The next inode number to use */
};

struct selinux_fs_info {
	struct dentry *bool_dir;
	unsigned int bool_num;
	char **bool_pending_names;
	unsigned int *bool_pending_values;
	struct dentry *class_dir;
	unsigned long last_class_ino;
	bool policy_opened;
	struct dentry *policycap_dir;
	struct mutex mutex;
	unsigned long last_ino;
	struct selinux_state *state;
	struct super_block *sb;
};

static int selinux_fs_info_create(struct super_block *sb)
{
	struct selinux_fs_info *fsi;

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	mutex_init(&fsi->mutex);
	fsi->last_ino = SEL_INO_NEXT - 1;
	fsi->state = &selinux_state;
	fsi->sb = sb;
	sb->s_fs_info = fsi;
	return 0;
}

static void selinux_fs_info_free(struct super_block *sb)
{
	struct selinux_fs_info *fsi = sb->s_fs_info;
	int i;

	if (fsi) {
		for (i = 0; i < fsi->bool_num; i++)
			kfree(fsi->bool_pending_names[i]);
		kfree(fsi->bool_pending_names);
		kfree(fsi->bool_pending_values);
	}
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}

#define SEL_INITCON_INO_OFFSET		0x01000000
#define SEL_BOOL_INO_OFFSET		0x02000000
#define SEL_CLASS_INO_OFFSET		0x04000000
#define SEL_POLICYCAP_INO_OFFSET	0x08000000
#define SEL_INO_MASK			0x00ffffff

#define TMPBUFLEN	12
static ssize_t sel_read_enforce(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d",
			   enforcing_enabled(fsi->state));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
static ssize_t sel_write_enforce(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	char *page;
	ssize_t length;
	int new_value;

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page = NULL;
	ssize_t length;
	int old_value, new_value;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	new_value = !!new_value;

	old_value = enforcing_enabled(state);
	if (new_value != old_value) {
		length = avc_has_perm(&selinux_state,
				      current_sid(), SECINITSID_SECURITY,
				      SECCLASS_SECURITY, SECURITY__SETENFORCE,
				      NULL);
		if (length)
			goto out;
		audit_log(current->audit_context, GFP_KERNEL, AUDIT_MAC_STATUS,
			"enforcing=%d old_enforcing=%d auid=%u ses=%u",
			new_value, selinux_enforcing,
			audit_get_loginuid(current),
		audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_STATUS,
			"enforcing=%d old_enforcing=%d auid=%u ses=%u"
			" enabled=%d old-enabled=%d lsm=selinux res=1",
			new_value, old_value,
			from_kuid(&init_user_ns, audit_get_loginuid(current)),
			audit_get_sessionid(current),
			selinux_enabled, selinux_enabled);
		enforcing_set(state, new_value);
		if (new_value)
			avc_ss_reset(state->avc, 0);
		selnl_notify_setenforce(new_value);
		selinux_status_update_setenforce(state, new_value);
		if (!new_value)
			call_lsm_notifier(LSM_POLICY_CHANGE, NULL);
	}
	length = count;
out:
	kfree(page);
	return length;
}
#else
#define sel_write_enforce NULL
#endif

static const struct file_operations sel_enforce_ops = {
	.read		= sel_read_enforce,
	.write		= sel_write_enforce,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_read_handle_unknown(struct file *filp, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	ino_t ino = filp->f_path.dentry->d_inode->i_ino;
	ino_t ino = file_inode(filp)->i_ino;
	int handle_unknown = (ino == SEL_REJECT_UNKNOWN) ?
		security_get_reject_unknown(state) :
		!security_get_allow_unknown(state);

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", handle_unknown);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_handle_unknown_ops = {
	.read		= sel_read_handle_unknown,
	.llseek		= generic_file_llseek,
};

static int sel_open_handle_status(struct inode *inode, struct file *filp)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct page    *status = selinux_kernel_status_page(fsi->state);

	if (!status)
		return -ENOMEM;

	filp->private_data = status;

	return 0;
}

static ssize_t sel_read_handle_status(struct file *filp, char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct page    *status = filp->private_data;

	BUG_ON(!status);

	return simple_read_from_buffer(buf, count, ppos,
				       page_address(status),
				       sizeof(struct selinux_kernel_status));
}

static int sel_mmap_handle_status(struct file *filp,
				  struct vm_area_struct *vma)
{
	struct page    *status = filp->private_data;
	unsigned long	size = vma->vm_end - vma->vm_start;

	BUG_ON(!status);

	/* only allows one page from the head */
	if (vma->vm_pgoff > 0 || size != PAGE_SIZE)
		return -EIO;
	/* disallow writable mapping */
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;
	/* disallow mprotect() turns it into writable */
	vma->vm_flags &= ~VM_MAYWRITE;

	return remap_pfn_range(vma, vma->vm_start,
			       page_to_pfn(status),
			       size, vma->vm_page_prot);
}

static const struct file_operations sel_handle_status_ops = {
	.open		= sel_open_handle_status,
	.read		= sel_read_handle_status,
	.mmap		= sel_mmap_handle_status,
	.llseek		= generic_file_llseek,
};

#ifdef CONFIG_SECURITY_SELINUX_DISABLE
static ssize_t sel_write_disable(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	char *page;
	ssize_t length;
	int new_value;
	extern int selinux_disable(void);

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	char *page = NULL;
	ssize_t length;
	int new_value;
	int enforcing;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	if (new_value) {
		length = selinux_disable();
		if (length < 0)
			goto out;
		audit_log(current->audit_context, GFP_KERNEL, AUDIT_MAC_STATUS,
			"selinux=0 auid=%u ses=%u",
			audit_get_loginuid(current),
		enforcing = enforcing_enabled(fsi->state);
		length = selinux_disable(fsi->state);
		if (length)
			goto out;
		audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_STATUS,
			"enforcing=%d old_enforcing=%d auid=%u ses=%u"
			" enabled=%d old-enabled=%d lsm=selinux res=1",
			enforcing, enforcing,
			from_kuid(&init_user_ns, audit_get_loginuid(current)),
			audit_get_sessionid(current), 0, 1);
	}

	length = count;
out:
	kfree(page);
	return length;
}
#else
#define sel_write_disable NULL
#endif

static const struct file_operations sel_disable_ops = {
	.write		= sel_write_disable,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_read_policyvers(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u", POLICYDB_VERSION_MAX);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_policyvers_ops = {
	.read		= sel_read_policyvers,
	.llseek		= generic_file_llseek,
};

/* declaration for sel_write_load */
static int sel_make_bools(struct selinux_fs_info *fsi);
static int sel_make_classes(struct selinux_fs_info *fsi);
static int sel_make_policycap(struct selinux_fs_info *fsi);

/* declaration for sel_make_class_dirs */
static int sel_make_dir(struct inode *dir, struct dentry *dentry,
static struct dentry *sel_make_dir(struct dentry *dir, const char *name,
			unsigned long *ino);

static ssize_t sel_read_mls(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", selinux_mls_enabled);
	length = scnprintf(tmpbuf, TMPBUFLEN, "%d",
			   security_mls_enabled(fsi->state));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_mls_ops = {
	.read		= sel_read_mls,
	.llseek		= generic_file_llseek,
};

struct policy_load_memory {
	size_t len;
	void *data;
};

static int sel_open_policy(struct inode *inode, struct file *filp)
{
	struct selinux_fs_info *fsi = inode->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	struct policy_load_memory *plm = NULL;
	int rc;

	BUG_ON(filp->private_data);

	mutex_lock(&fsi->mutex);

	rc = avc_has_perm(&selinux_state,
			  current_sid(), SECINITSID_SECURITY,
			  SECCLASS_SECURITY, SECURITY__READ_POLICY, NULL);
	if (rc)
		goto err;

	rc = -EBUSY;
	if (fsi->policy_opened)
		goto err;

	rc = -ENOMEM;
	plm = kzalloc(sizeof(*plm), GFP_KERNEL);
	if (!plm)
		goto err;

	if (i_size_read(inode) != security_policydb_len(state)) {
		inode_lock(inode);
		i_size_write(inode, security_policydb_len(state));
		inode_unlock(inode);
	}

	rc = security_read_policy(state, &plm->data, &plm->len);
	if (rc)
		goto err;

	fsi->policy_opened = 1;

	filp->private_data = plm;

	mutex_unlock(&fsi->mutex);

	return 0;
err:
	mutex_unlock(&fsi->mutex);

	if (plm)
		vfree(plm->data);
	kfree(plm);
	return rc;
}

static int sel_release_policy(struct inode *inode, struct file *filp)
{
	struct selinux_fs_info *fsi = inode->i_sb->s_fs_info;
	struct policy_load_memory *plm = filp->private_data;

	BUG_ON(!plm);

	fsi->policy_opened = 0;

	vfree(plm->data);
	kfree(plm);

	return 0;
}

static ssize_t sel_read_policy(struct file *filp, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct policy_load_memory *plm = filp->private_data;
	int ret;

	ret = avc_has_perm(&selinux_state,
			   current_sid(), SECINITSID_SECURITY,
			  SECCLASS_SECURITY, SECURITY__READ_POLICY, NULL);
	if (ret)
		return ret;

	return simple_read_from_buffer(buf, count, ppos, plm->data, plm->len);
}

static vm_fault_t sel_mmap_policy_fault(struct vm_fault *vmf)
{
	struct policy_load_memory *plm = vmf->vma->vm_file->private_data;
	unsigned long offset;
	struct page *page;

	if (vmf->flags & (FAULT_FLAG_MKWRITE | FAULT_FLAG_WRITE))
		return VM_FAULT_SIGBUS;

	offset = vmf->pgoff << PAGE_SHIFT;
	if (offset >= roundup(plm->len, PAGE_SIZE))
		return VM_FAULT_SIGBUS;

	page = vmalloc_to_page(plm->data + offset);
	get_page(page);

	vmf->page = page;

	return 0;
}

static const struct vm_operations_struct sel_mmap_policy_ops = {
	.fault = sel_mmap_policy_fault,
	.page_mkwrite = sel_mmap_policy_fault,
};

static int sel_mmap_policy(struct file *filp, struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_SHARED) {
		/* do not allow mprotect to make mapping writable */
		vma->vm_flags &= ~VM_MAYWRITE;

		if (vma->vm_flags & VM_WRITE)
			return -EACCES;
	}

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &sel_mmap_policy_ops;

	return 0;
}

static const struct file_operations sel_policy_ops = {
	.open		= sel_open_policy,
	.read		= sel_read_policy,
	.mmap		= sel_mmap_policy,
	.release	= sel_release_policy,
	.llseek		= generic_file_llseek,
};

static int sel_make_policy_nodes(struct selinux_fs_info *fsi)
{
	int ret;

	ret = sel_make_bools(fsi);
	if (ret) {
		pr_err("SELinux: failed to load policy booleans\n");
		return ret;
	}

	ret = sel_make_classes(fsi);
	if (ret) {
		pr_err("SELinux: failed to load policy classes\n");
		return ret;
	}

	ret = sel_make_policycap(fsi);
	if (ret) {
		pr_err("SELinux: failed to load policy capabilities\n");
		return ret;
	}

	return 0;
}

static ssize_t sel_write_load(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)

{
	int ret;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	ssize_t length;
	void *data = NULL;

	mutex_lock(&fsi->mutex);

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL);
	if (length)
		goto out;

	if (*ppos != 0) {
		/* No partial writes. */
		length = -EINVAL;
		goto out;
	}

	if ((count > 64 * 1024 * 1024)
	    || (data = vmalloc(count)) == NULL) {
		length = -ENOMEM;
		goto out;
	}
	/* No partial writes. */
	length = -EINVAL;
	if (*ppos != 0)
		goto out;

	length = -EFBIG;
	if (count > 64 * 1024 * 1024)
		goto out;

	length = -ENOMEM;
	data = vmalloc(count);
	if (!data)
		goto out;

	length = -EFAULT;
	if (copy_from_user(data, buf, count) != 0)
		goto out;

	length = security_load_policy(fsi->state, data, count);
	if (length) {
		pr_warn_ratelimited("SELinux: failed to load policy\n");
		goto out;
	}

	ret = sel_make_bools();
	if (ret) {
		length = ret;
		goto out1;
	}

	ret = sel_make_classes();
	if (ret) {
		length = ret;
		goto out1;
	}

	ret = sel_make_policycap();
	if (ret)
		length = ret;
	else
		length = count;
	length = sel_make_bools();
	if (length) {
		pr_err("SELinux: failed to load policy booleans\n");
	length = sel_make_policy_nodes(fsi);
	if (length)
		goto out1;

	length = count;

out1:
	audit_log(current->audit_context, GFP_KERNEL, AUDIT_MAC_POLICY_LOAD,
		"policy loaded auid=%u ses=%u",
		audit_get_loginuid(current),
	audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_POLICY_LOAD,
		"auid=%u ses=%u lsm=selinux res=1",
		from_kuid(&init_user_ns, audit_get_loginuid(current)),
		audit_get_sessionid(current));
out:
	mutex_unlock(&fsi->mutex);
	vfree(data);
	return length;
}

static const struct file_operations sel_load_ops = {
	.write		= sel_write_load,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_write_context(struct file *file, char *buf, size_t size)
{
	char *canon;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *canon = NULL;
	u32 sid, len;
	ssize_t length;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
	if (length)
		return length;

	length = security_context_to_sid(buf, size, &sid);
	if (length < 0)
		return length;

	length = security_sid_to_context(sid, &canon, &len);
	if (length < 0)
		return length;

	if (len > SIMPLE_TRANSACTION_LIMIT) {
		printk(KERN_ERR "SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		length = -ERANGE;
		goto out;

	length = security_context_to_sid(state, buf, size, &sid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_sid_to_context(state, sid, &canon, &len);
	if (length)
		goto out;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		goto out;
	}

	memcpy(buf, canon, len);
	length = len;
out:
	kfree(canon);
	return length;
}

static ssize_t sel_read_checkreqprot(struct file *filp, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u", fsi->state->checkreqprot);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t sel_write_checkreqprot(struct file *file, const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	char *page;
	char *page = NULL;
	ssize_t length;
	unsigned int new_value;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETCHECKREQPROT,
			      NULL);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
		goto out;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = -EINVAL;
	if (sscanf(page, "%u", &new_value) != 1)
		goto out;

	fsi->state->checkreqprot = new_value ? 1 : 0;
	length = count;
out:
	kfree(page);
	return length;
}
static const struct file_operations sel_checkreqprot_ops = {
	.read		= sel_read_checkreqprot,
	.write		= sel_write_checkreqprot,
};

static ssize_t sel_read_compat_net(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", selinux_compat_net);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t sel_write_compat_net(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	char *page;
	ssize_t length;
	int new_value;

	length = task_has_security(current, SECURITY__LOAD_POLICY);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;
	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	selinux_compat_net = new_value ? 1 : 0;
	length = count;
out:
	free_page((unsigned long) page);
	return length;
}
static const struct file_operations sel_compat_net_ops = {
	.read		= sel_read_compat_net,
	.write		= sel_write_compat_net,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_write_validatetrans(struct file *file,
					const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *oldcon = NULL, *newcon = NULL, *taskcon = NULL;
	char *req = NULL;
	u32 osid, nsid, tsid;
	u16 tclass;
	int rc;

	rc = avc_has_perm(&selinux_state,
			  current_sid(), SECINITSID_SECURITY,
			  SECCLASS_SECURITY, SECURITY__VALIDATE_TRANS, NULL);
	if (rc)
		goto out;

	rc = -ENOMEM;
	if (count >= PAGE_SIZE)
		goto out;

	/* No partial writes. */
	rc = -EINVAL;
	if (*ppos != 0)
		goto out;

	req = memdup_user_nul(buf, count);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		req = NULL;
		goto out;
	}

	rc = -ENOMEM;
	oldcon = kzalloc(count + 1, GFP_KERNEL);
	if (!oldcon)
		goto out;

	newcon = kzalloc(count + 1, GFP_KERNEL);
	if (!newcon)
		goto out;

	taskcon = kzalloc(count + 1, GFP_KERNEL);
	if (!taskcon)
		goto out;

	rc = -EINVAL;
	if (sscanf(req, "%s %s %hu %s", oldcon, newcon, &tclass, taskcon) != 4)
		goto out;

	rc = security_context_str_to_sid(state, oldcon, &osid, GFP_KERNEL);
	if (rc)
		goto out;

	rc = security_context_str_to_sid(state, newcon, &nsid, GFP_KERNEL);
	if (rc)
		goto out;

	rc = security_context_str_to_sid(state, taskcon, &tsid, GFP_KERNEL);
	if (rc)
		goto out;

	rc = security_validate_transition_user(state, osid, nsid, tsid, tclass);
	if (!rc)
		rc = count;
out:
	kfree(req);
	kfree(oldcon);
	kfree(newcon);
	kfree(taskcon);
	return rc;
}

static const struct file_operations sel_transition_ops = {
	.write		= sel_write_validatetrans,
	.llseek		= generic_file_llseek,
};

/*
 * Remaining nodes use transaction based IO methods like nfsd/nfsctl.c
 */
static ssize_t sel_write_access(struct file *file, char *buf, size_t size);
static ssize_t sel_write_create(struct file *file, char *buf, size_t size);
static ssize_t sel_write_relabel(struct file *file, char *buf, size_t size);
static ssize_t sel_write_user(struct file *file, char *buf, size_t size);
static ssize_t sel_write_member(struct file *file, char *buf, size_t size);

static ssize_t (*const write_op[])(struct file *, char *, size_t) = {
	[SEL_ACCESS] = sel_write_access,
	[SEL_CREATE] = sel_write_create,
	[SEL_RELABEL] = sel_write_relabel,
	[SEL_USER] = sel_write_user,
	[SEL_MEMBER] = sel_write_member,
	[SEL_CONTEXT] = sel_write_context,
};

static ssize_t selinux_transaction_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	ino_t ino = file->f_path.dentry->d_inode->i_ino;
	ino_t ino = file_inode(file)->i_ino;
	char *data;
	ssize_t rv;

	if (ino >= ARRAY_SIZE(write_op) || !write_op[ino])
		return -EINVAL;

	data = simple_transaction_get(file, buf, size);
	if (IS_ERR(data))
		return PTR_ERR(data);

	rv = write_op[ino](file, data, size);
	if (rv > 0) {
		simple_transaction_set(file, rv);
		rv = size;
	}
	return rv;
}

static const struct file_operations transaction_ops = {
	.write		= selinux_transaction_write,
	.read		= simple_transaction_read,
	.release	= simple_transaction_release,
	.llseek		= generic_file_llseek,
};

/*
 * payload - write methods
 * If the method has a response, the response should be put in buf,
 * and the length returned.  Otherwise return 0 or and -error.
 */

static ssize_t sel_write_access(struct file *file, char *buf, size_t size)
{
	char *scon, *tcon;
	u32 ssid, tsid;
	u16 tclass;
	u32 req;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid;
	u16 tclass;
	struct av_decision avd;
	ssize_t length;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
	if (length)
		return length;

	length = -ENOMEM;
	scon = kzalloc(size+1, GFP_KERNEL);
	if (!scon)
		return length;

	tcon = kzalloc(size+1, GFP_KERNEL);
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu %x", scon, tcon, &tclass, &req) != 4)
		goto out2;

	length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
	if (length < 0)
		goto out2;
	length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
	if (length < 0)
		goto out2;

	length = security_compute_av(ssid, tsid, tclass, req, &avd);
	if (length < 0)
		goto out2;

	length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,
			  "%x %x %x %x %u",
			  avd.allowed, avd.decided,
			  avd.auditallow, avd.auditdeny,
			  avd.seqno);
out2:
	kfree(tcon);
out:
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	length = security_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	security_compute_av_user(state, ssid, tsid, tclass, &avd);

	length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,
			  "%x %x %x %x %u %x",
			  avd.allowed, 0xffffffff,
			  avd.auditallow, avd.auditdeny,
			  avd.seqno, avd.flags);
out:
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t sel_write_create(struct file *file, char *buf, size_t size)
{
	char *scon, *tcon;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	char *newcon;
	u32 len;

	length = task_has_security(current, SECURITY__COMPUTE_CREATE);
	if (length)
		return length;

	length = -ENOMEM;
	scon = kzalloc(size+1, GFP_KERNEL);
	if (!scon)
		return length;

	tcon = kzalloc(size+1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out2;

	length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
	if (length < 0)
		goto out2;
	length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
	if (length < 0)
		goto out2;

	length = security_transition_sid(ssid, tsid, tclass, &newsid);
	if (length < 0)
		goto out2;

	length = security_sid_to_context(newsid, &newcon, &len);
	if (length < 0)
		goto out2;

	if (len > SIMPLE_TRANSACTION_LIMIT) {
		printk(KERN_ERR "SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		length = -ERANGE;
		goto out3;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	char *namebuf = NULL, *objname = NULL;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	char *newcon = NULL;
	u32 len;
	int nargs;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_CREATE,
			      NULL);
	if (length)
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -ENOMEM;
	namebuf = kzalloc(size + 1, GFP_KERNEL);
	if (!namebuf)
		goto out;

	length = -EINVAL;
	nargs = sscanf(buf, "%s %s %hu %s", scon, tcon, &tclass, namebuf);
	if (nargs < 3 || nargs > 4)
		goto out;
	if (nargs == 4) {
		/*
		 * If and when the name of new object to be queried contains
		 * either whitespace or multibyte characters, they shall be
		 * encoded based on the percentage-encoding rule.
		 * If not encoded, the sscanf logic picks up only left-half
		 * of the supplied name; splitted by a whitespace unexpectedly.
		 */
		char   *r, *w;
		int     c1, c2;

		r = w = namebuf;
		do {
			c1 = *r++;
			if (c1 == '+')
				c1 = ' ';
			else if (c1 == '%') {
				c1 = hex_to_bin(*r++);
				if (c1 < 0)
					goto out;
				c2 = hex_to_bin(*r++);
				if (c2 < 0)
					goto out;
				c1 = (c1 << 4) | c2;
			}
			*w++ = c1;
		} while (c1 != '\0');

		objname = namebuf;
	}

	length = security_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_transition_sid_user(state, ssid, tsid, tclass,
					      objname, &newsid);
	if (length)
		goto out;

	length = security_sid_to_context(state, newsid, &newcon, &len);
	if (length)
		goto out;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		goto out;
	}

	memcpy(buf, newcon, len);
	length = len;
out3:
	kfree(newcon);
out2:
	kfree(tcon);
out:
out:
	kfree(newcon);
	kfree(namebuf);
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t sel_write_relabel(struct file *file, char *buf, size_t size)
{
	char *scon, *tcon;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	char *newcon;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	char *newcon = NULL;
	u32 len;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_RELABEL,
			      NULL);
	if (length)
		return length;

	length = -ENOMEM;
	scon = kzalloc(size+1, GFP_KERNEL);
	if (!scon)
		return length;

	tcon = kzalloc(size+1, GFP_KERNEL);
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out2;

	length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
	if (length < 0)
		goto out2;
	length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
	if (length < 0)
		goto out2;

	length = security_change_sid(ssid, tsid, tclass, &newsid);
	if (length < 0)
		goto out2;

	length = security_sid_to_context(newsid, &newcon, &len);
	if (length < 0)
		goto out2;

	if (len > SIMPLE_TRANSACTION_LIMIT) {
		length = -ERANGE;
		goto out3;
	}

	memcpy(buf, newcon, len);
	length = len;
out3:
	kfree(newcon);
out2:
	kfree(tcon);
out:
		goto out;

	length = security_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_change_sid(state, ssid, tsid, tclass, &newsid);
	if (length)
		goto out;

	length = security_sid_to_context(state, newsid, &newcon, &len);
	if (length)
		goto out;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT)
		goto out;

	memcpy(buf, newcon, len);
	length = len;
out:
	kfree(newcon);
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t sel_write_user(struct file *file, char *buf, size_t size)
{
	char *con, *user, *ptr;
	u32 sid, *sids;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *con = NULL, *user = NULL, *ptr;
	u32 sid, *sids = NULL;
	ssize_t length;
	char *newcon;
	int i, rc;
	u32 len, nsids;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_USER,
			      NULL);
	if (length)
		return length;

	length = -ENOMEM;
	con = kzalloc(size+1, GFP_KERNEL);
	if (!con)
		return length;

	user = kzalloc(size+1, GFP_KERNEL);
		goto out;

	length = -ENOMEM;
	con = kzalloc(size + 1, GFP_KERNEL);
	if (!con)
		goto out;

	length = -ENOMEM;
	user = kzalloc(size + 1, GFP_KERNEL);
	if (!user)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s", con, user) != 2)
		goto out2;

	length = security_context_to_sid(con, strlen(con)+1, &sid);
	if (length < 0)
		goto out2;

	length = security_get_user_sids(sid, user, &sids, &nsids);
	if (length < 0)
		goto out2;
		goto out;

	length = security_context_str_to_sid(state, con, &sid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_get_user_sids(state, sid, user, &sids, &nsids);
	if (length)
		goto out;

	length = sprintf(buf, "%u", nsids) + 1;
	ptr = buf + length;
	for (i = 0; i < nsids; i++) {
		rc = security_sid_to_context(state, sids[i], &newcon, &len);
		if (rc) {
			length = rc;
			goto out3;
			goto out;
		}
		if ((length + len) >= SIMPLE_TRANSACTION_LIMIT) {
			kfree(newcon);
			length = -ERANGE;
			goto out3;
			goto out;
		}
		memcpy(ptr, newcon, len);
		kfree(newcon);
		ptr += len;
		length += len;
	}
out3:
	kfree(sids);
out2:
	kfree(user);
out:
out:
	kfree(sids);
	kfree(user);
	kfree(con);
	return length;
}

static ssize_t sel_write_member(struct file *file, char *buf, size_t size)
{
	char *scon, *tcon;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	char *newcon;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	char *newcon = NULL;
	u32 len;

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_MEMBER,
			      NULL);
	if (length)
		return length;

	length = -ENOMEM;
	scon = kzalloc(size+1, GFP_KERNEL);
	if (!scon)
		return length;

	tcon = kzalloc(size+1, GFP_KERNEL);
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out2;

	length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
	if (length < 0)
		goto out2;
	length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
	if (length < 0)
		goto out2;

	length = security_member_sid(ssid, tsid, tclass, &newsid);
	if (length < 0)
		goto out2;

	length = security_sid_to_context(newsid, &newcon, &len);
	if (length < 0)
		goto out2;

	if (len > SIMPLE_TRANSACTION_LIMIT) {
		printk(KERN_ERR "SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		length = -ERANGE;
		goto out3;
		goto out;

	length = security_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_member_sid(state, ssid, tsid, tclass, &newsid);
	if (length)
		goto out;

	length = security_sid_to_context(state, newsid, &newcon, &len);
	if (length)
		goto out;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		goto out;
	}

	memcpy(buf, newcon, len);
	length = len;
out3:
	kfree(newcon);
out2:
	kfree(tcon);
out:
out:
	kfree(newcon);
	kfree(tcon);
	kfree(scon);
	return length;
}

static struct inode *sel_make_inode(struct super_block *sb, int mode)
{
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_mode = mode;
		ret->i_uid = ret->i_gid = 0;
		ret->i_blocks = 0;
		ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
		ret->i_atime = ret->i_mtime = ret->i_ctime = current_time(ret);
	}
	return ret;
}

static ssize_t sel_read_bool(struct file *filep, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
	char *page = NULL;
	ssize_t length;
	ssize_t ret;
	int cur_enforcing;
	struct inode *inode = filep->f_path.dentry->d_inode;
	unsigned index = inode->i_ino & SEL_INO_MASK;
	unsigned index = file_inode(filep)->i_ino & SEL_INO_MASK;
	const char *name = filep->f_path.dentry->d_name.name;

	mutex_lock(&fsi->mutex);

	if (index >= bool_num || strcmp(name, bool_pending_names[index])) {
		ret = -EINVAL;
		goto out;
	}

	if (count > PAGE_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	ret = -EINVAL;
	if (index >= fsi->bool_num || strcmp(name,
					     fsi->bool_pending_names[index]))
		goto out_unlock;

	ret = -ENOMEM;
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		goto out_unlock;

	cur_enforcing = security_get_bool_value(fsi->state, index);
	if (cur_enforcing < 0) {
		ret = cur_enforcing;
		goto out_unlock;
	}
	length = scnprintf(page, PAGE_SIZE, "%d %d", cur_enforcing,
			  fsi->bool_pending_values[index]);
	mutex_unlock(&fsi->mutex);
	ret = simple_read_from_buffer(buf, count, ppos, page, length);
out:
	mutex_unlock(&sel_mutex);
	if (page)
		free_page((unsigned long)page);
out_free:
	free_page((unsigned long)page);
	return ret;

out_unlock:
	mutex_unlock(&fsi->mutex);
	goto out_free;
}

static ssize_t sel_write_bool(struct file *filep, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
	char *page = NULL;
	ssize_t length;
	int new_value;
	struct inode *inode = filep->f_path.dentry->d_inode;
	unsigned index = inode->i_ino & SEL_INO_MASK;
	unsigned index = file_inode(filep)->i_ino & SEL_INO_MASK;
	const char *name = filep->f_path.dentry->d_name.name;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	mutex_lock(&fsi->mutex);

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETBOOL,
			      NULL);
	if (length)
		goto out;

	if (index >= bool_num || strcmp(name, bool_pending_names[index])) {
		length = -EINVAL;
		goto out;
	}

	if (count >= PAGE_SIZE) {
		length = -ENOMEM;
		goto out;
	}

	if (*ppos != 0) {
		/* No partial writes. */
		length = -EINVAL;
		goto out;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page) {
		length = -ENOMEM;
		goto out;
	}
	length = -EINVAL;
	if (index >= fsi->bool_num || strcmp(name,
					     fsi->bool_pending_names[index]))
		goto out;

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	if (new_value)
		new_value = 1;

	fsi->bool_pending_values[index] = new_value;
	length = count;

out:
	mutex_unlock(&sel_mutex);
	if (page)
		free_page((unsigned long) page);
	free_page((unsigned long) page);
	mutex_unlock(&fsi->mutex);
	kfree(page);
	return length;
}

static const struct file_operations sel_bool_ops = {
	.read		= sel_read_bool,
	.write		= sel_write_bool,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_commit_bools_write(struct file *filep,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
	char *page = NULL;
	ssize_t length;
	int new_value;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	mutex_lock(&fsi->mutex);

	length = avc_has_perm(&selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETBOOL,
			      NULL);
	if (length)
		goto out;

	if (count >= PAGE_SIZE) {
		length = -ENOMEM;
		goto out;
	}
	if (*ppos != 0) {
		/* No partial writes. */
		goto out;
	}
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page) {
		length = -ENOMEM;
		goto out;
	}
	length = -ENOMEM;
	if (count >= PAGE_SIZE)
		goto out;

	/* No partial writes. */
	length = -EINVAL;
	if (*ppos != 0)
		goto out;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page)) {
		length = PTR_ERR(page);
		page = NULL;
		goto out;
	}

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	if (new_value && bool_pending_values)
		security_set_bools(bool_num, bool_pending_values);

	length = count;

out:
	mutex_unlock(&sel_mutex);
	if (page)
		free_page((unsigned long) page);
	length = 0;
	if (new_value && fsi->bool_pending_values)
		length = security_set_bools(fsi->state, fsi->bool_num,
					    fsi->bool_pending_values);

	if (!length)
		length = count;

out:
	mutex_unlock(&fsi->mutex);
	kfree(page);
	return length;
}

static const struct file_operations sel_commit_bools_ops = {
	.write		= sel_commit_bools_write,
	.llseek		= generic_file_llseek,
};

static void sel_remove_entries(struct dentry *de)
{
	struct list_head *node;

	spin_lock(&dcache_lock);
	node = de->d_subdirs.next;
	while (node != &de->d_subdirs) {
		struct dentry *d = list_entry(node, struct dentry, d_u.d_child);
		list_del_init(node);

		if (d->d_inode) {
			d = dget_locked(d);
			spin_unlock(&dcache_lock);
			d_delete(d);
			simple_unlink(de->d_inode, d);
			dput(d);
			spin_lock(&dcache_lock);
		}
		node = de->d_subdirs.next;
	}

	spin_unlock(&dcache_lock);
	d_genocide(de);
	shrink_dcache_parent(de);
}

#define BOOL_DIR_NAME "booleans"

static int sel_make_bools(struct selinux_fs_info *fsi)
{
	int i, ret = 0;
	int i, ret;
	ssize_t len;
	struct dentry *dentry = NULL;
	struct dentry *dir = fsi->bool_dir;
	struct inode *inode = NULL;
	struct inode_security_struct *isec;
	char **names = NULL, *page;
	int num;
	int *values = NULL;
	u32 sid;

	/* remove any existing files */
	kfree(bool_pending_names);
	kfree(bool_pending_values);
	for (i = 0; i < bool_num; i++)
		kfree(bool_pending_names[i]);
	kfree(bool_pending_names);
	kfree(bool_pending_values);
	bool_num = 0;
	bool_pending_names = NULL;
	bool_pending_values = NULL;
	for (i = 0; i < fsi->bool_num; i++)
		kfree(fsi->bool_pending_names[i]);
	kfree(fsi->bool_pending_names);
	kfree(fsi->bool_pending_values);
	fsi->bool_num = 0;
	fsi->bool_pending_names = NULL;
	fsi->bool_pending_values = NULL;

	sel_remove_entries(dir);

	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = security_get_bools(&num, &names, &values);
	if (ret != 0)
		goto out;

	for (i = 0; i < num; i++) {
		dentry = d_alloc_name(dir, names[i]);
		if (!dentry) {
			ret = -ENOMEM;
			goto err;
		}
		inode = sel_make_inode(dir->d_sb, S_IFREG | S_IRUGO | S_IWUSR);
		if (!inode) {
			ret = -ENOMEM;
			goto err;
		}

		len = snprintf(page, PAGE_SIZE, "/%s/%s", BOOL_DIR_NAME, names[i]);
		if (len < 0) {
			ret = -EINVAL;
			goto err;
		} else if (len >= PAGE_SIZE) {
			ret = -ENAMETOOLONG;
			goto err;
		}
		isec = (struct inode_security_struct *)inode->i_security;
		ret = security_genfs_sid("selinuxfs", page, SECCLASS_FILE, &sid);
		if (ret)
			goto err;
	ret = -ENOMEM;
	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		goto out;

	ret = security_get_bools(fsi->state, &num, &names, &values);
	if (ret)
		goto out;

	for (i = 0; i < num; i++) {
		ret = -ENOMEM;
		dentry = d_alloc_name(dir, names[i]);
		if (!dentry)
			goto out;

		ret = -ENOMEM;
		inode = sel_make_inode(dir->d_sb, S_IFREG | S_IRUGO | S_IWUSR);
		if (!inode) {
			dput(dentry);
			goto out;
		}

		ret = -ENAMETOOLONG;
		len = snprintf(page, PAGE_SIZE, "/%s/%s", BOOL_DIR_NAME, names[i]);
		if (len >= PAGE_SIZE) {
			dput(dentry);
			iput(inode);
			goto out;
		}

		isec = (struct inode_security_struct *)inode->i_security;
		ret = security_genfs_sid(fsi->state, "selinuxfs", page,
					 SECCLASS_FILE, &sid);
		if (ret) {
			pr_warn_ratelimited("SELinux: no sid found, defaulting to security isid for %s\n",
					   page);
			sid = SECINITSID_SECURITY;
		}

		isec->sid = sid;
		isec->initialized = LABEL_INITIALIZED;
		inode->i_fop = &sel_bool_ops;
		inode->i_ino = i|SEL_BOOL_INO_OFFSET;
		d_add(dentry, inode);
	}
	bool_num = num;
	bool_pending_names = names;
	bool_pending_values = values;
out:
	free_page((unsigned long)page);
	return ret;
err:
	fsi->bool_num = num;
	fsi->bool_pending_names = names;
	fsi->bool_pending_values = values;

	free_page((unsigned long)page);
	return 0;
out:
	free_page((unsigned long)page);

	if (names) {
		for (i = 0; i < num; i++)
			kfree(names[i]);
		kfree(names);
	}
	kfree(values);
	sel_remove_entries(dir);
	ret = -ENOMEM;
	goto out;

	return ret;
}

#define NULL_FILE_NAME "null"

struct dentry *selinux_null;
struct path selinux_null;

static ssize_t sel_read_avc_cache_threshold(struct file *filp, char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
			   avc_get_cache_threshold(state->avc));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t sel_write_avc_cache_threshold(struct file *file,
					     const char __user *buf,
					     size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page;
	ssize_t ret;
	int new_value;

	if (count >= PAGE_SIZE) {
		ret = -ENOMEM;
		goto out;
	}

	if (*ppos != 0) {
		/* No partial writes. */
		ret = -EINVAL;
		goto out;
	}

	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(page, buf, count)) {
		ret = -EFAULT;
		goto out_free;
	}

	if (sscanf(page, "%u", &new_value) != 1) {
		ret = -EINVAL;
		goto out;
	}

	if (new_value != avc_cache_threshold) {
		ret = task_has_security(current, SECURITY__SETSECPARAM);
		if (ret)
			goto out_free;
		avc_cache_threshold = new_value;
	}
	ret = count;
out_free:
	free_page((unsigned long)page);
out:
	char *page = NULL;
	ssize_t ret;
	unsigned int new_value;

	ret = avc_has_perm(&selinux_state,
			   current_sid(), SECINITSID_SECURITY,
			   SECCLASS_SECURITY, SECURITY__SETSECPARAM,
			   NULL);
	if (ret)
		return ret;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	ret = -EINVAL;
	if (sscanf(page, "%u", &new_value) != 1)
		goto out;

	avc_set_cache_threshold(state->avc, new_value);

	ret = count;
out:
	kfree(page);
	return ret;
}

static ssize_t sel_read_avc_hash_stats(struct file *filp, char __user *buf,
				       size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page;
	ssize_t ret = 0;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	ret = avc_get_hash_stats(page);
	if (ret >= 0)
		ret = simple_read_from_buffer(buf, count, ppos, page, ret);
	free_page((unsigned long)page);
out:
	return ret;
	ssize_t length;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	length = avc_get_hash_stats(state->avc, page);
	if (length >= 0)
		length = simple_read_from_buffer(buf, count, ppos, page, length);
	free_page((unsigned long)page);

	return length;
}

static const struct file_operations sel_avc_cache_threshold_ops = {
	.read		= sel_read_avc_cache_threshold,
	.write		= sel_write_avc_cache_threshold,
	.llseek		= generic_file_llseek,
};

static const struct file_operations sel_avc_hash_stats_ops = {
	.read		= sel_read_avc_hash_stats,
	.llseek		= generic_file_llseek,
};

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
static struct avc_cache_stats *sel_avc_get_stat_idx(loff_t *idx)
{
	int cpu;

	for (cpu = *idx; cpu < NR_CPUS; ++cpu) {
	for (cpu = *idx; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*idx = cpu + 1;
		return &per_cpu(avc_cache_stats, cpu);
	}
	return NULL;
}

static void *sel_avc_stats_seq_start(struct seq_file *seq, loff_t *pos)
{
	loff_t n = *pos - 1;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	return sel_avc_get_stat_idx(&n);
}

static void *sel_avc_stats_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return sel_avc_get_stat_idx(pos);
}

static int sel_avc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct avc_cache_stats *st = v;

	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "lookups hits misses allocations reclaims "
			   "frees\n");
	else
		seq_printf(seq, "%u %u %u %u %u %u\n", st->lookups,
			   st->hits, st->misses, st->allocations,
			   st->reclaims, st->frees);
	else {
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq,
			 "lookups hits misses allocations reclaims frees\n");
	} else {
		unsigned int lookups = st->lookups;
		unsigned int misses = st->misses;
		unsigned int hits = lookups - misses;
		seq_printf(seq, "%u %u %u %u %u %u\n", lookups,
			   hits, misses, st->allocations,
			   st->reclaims, st->frees);
	}
	return 0;
}

static void sel_avc_stats_seq_stop(struct seq_file *seq, void *v)
{ }

static const struct seq_operations sel_avc_cache_stats_seq_ops = {
	.start		= sel_avc_stats_seq_start,
	.next		= sel_avc_stats_seq_next,
	.show		= sel_avc_stats_seq_show,
	.stop		= sel_avc_stats_seq_stop,
};

static int sel_open_avc_cache_stats(struct inode *inode, struct file *file)
{
	return seq_open(file, &sel_avc_cache_stats_seq_ops);
}

static const struct file_operations sel_avc_cache_stats_ops = {
	.open		= sel_open_avc_cache_stats,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif

static int sel_make_avc_files(struct dentry *dir)
{
	int i, ret = 0;
	struct super_block *sb = dir->d_sb;
	struct selinux_fs_info *fsi = sb->s_fs_info;
	int i;
	static const struct tree_descr files[] = {
		{ "cache_threshold",
		  &sel_avc_cache_threshold_ops, S_IRUGO|S_IWUSR },
		{ "hash_stats", &sel_avc_hash_stats_ops, S_IRUGO },
#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
		{ "cache_stats", &sel_avc_cache_stats_ops, S_IRUGO },
#endif
	};

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		struct inode *inode;
		struct dentry *dentry;

		dentry = d_alloc_name(dir, files[i].name);
		if (!dentry) {
			ret = -ENOMEM;
			goto out;
		}

		inode = sel_make_inode(dir->d_sb, S_IFREG|files[i].mode);
		if (!inode) {
			ret = -ENOMEM;
			goto out;
		}
		if (!dentry)
			return -ENOMEM;

		inode = sel_make_inode(dir->d_sb, S_IFREG|files[i].mode);
		if (!inode) {
			dput(dentry);
			return -ENOMEM;
		}

		inode->i_fop = files[i].ops;
		inode->i_ino = ++fsi->last_ino;
		d_add(dentry, inode);
	}
out:
	return ret;

	return 0;
}

static ssize_t sel_read_initcon(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct inode *inode;
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	char *con;
	u32 sid, len;
	ssize_t ret;

	inode = file->f_path.dentry->d_inode;
	sid = inode->i_ino&SEL_INO_MASK;
	ret = security_sid_to_context(sid, &con, &len);
	if (ret < 0)
	sid = file_inode(file)->i_ino&SEL_INO_MASK;
	ret = security_sid_to_context(fsi->state, sid, &con, &len);
	if (ret)
		return ret;

	ret = simple_read_from_buffer(buf, count, ppos, con, len);
	kfree(con);
	return ret;
}

static const struct file_operations sel_initcon_ops = {
	.read		= sel_read_initcon,
	.llseek		= generic_file_llseek,
};

static int sel_make_initcon_files(struct dentry *dir)
{
	int i, ret = 0;
	int i;

	for (i = 1; i <= SECINITSID_NUM; i++) {
		struct inode *inode;
		struct dentry *dentry;
		dentry = d_alloc_name(dir, security_get_initial_sid_context(i));
		if (!dentry) {
			ret = -ENOMEM;
			goto out;
		}

		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
		if (!inode) {
			ret = -ENOMEM;
			goto out;
		}
		if (!dentry)
			return -ENOMEM;

		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
		if (!inode) {
			dput(dentry);
			return -ENOMEM;
		}

		inode->i_fop = &sel_initcon_ops;
		inode->i_ino = i|SEL_INITCON_INO_OFFSET;
		d_add(dentry, inode);
	}
out:
	return ret;
}

static inline unsigned int sel_div(unsigned long a, unsigned long b)
{
	return a / b - (a % b < 0);

	return 0;
}

static inline unsigned long sel_class_to_ino(u16 class)
{
	return (class * (SEL_VEC_MAX + 1)) | SEL_CLASS_INO_OFFSET;
}

static inline u16 sel_ino_to_class(unsigned long ino)
{
	return sel_div(ino & SEL_INO_MASK, SEL_VEC_MAX + 1);
	return (ino & SEL_INO_MASK) / (SEL_VEC_MAX + 1);
}

static inline unsigned long sel_perm_to_ino(u16 class, u32 perm)
{
	return (class * (SEL_VEC_MAX + 1) + perm) | SEL_CLASS_INO_OFFSET;
}

static inline u32 sel_ino_to_perm(unsigned long ino)
{
	return (ino & SEL_INO_MASK) % (SEL_VEC_MAX + 1);
}

static ssize_t sel_read_class(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t rc, len;
	char *page;
	unsigned long ino = file->f_path.dentry->d_inode->i_ino;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		rc = -ENOMEM;
		goto out;
	}

	len = snprintf(page, PAGE_SIZE, "%d", sel_ino_to_class(ino));
	rc = simple_read_from_buffer(buf, count, ppos, page, len);
	free_page((unsigned long)page);
out:
	return rc;
	unsigned long ino = file_inode(file)->i_ino;
	char res[TMPBUFLEN];
	ssize_t len = snprintf(res, sizeof(res), "%d", sel_ino_to_class(ino));
	return simple_read_from_buffer(buf, count, ppos, res, len);
}

static const struct file_operations sel_class_ops = {
	.read		= sel_read_class,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_read_perm(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t rc, len;
	char *page;
	unsigned long ino = file->f_path.dentry->d_inode->i_ino;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		rc = -ENOMEM;
		goto out;
	}

	len = snprintf(page, PAGE_SIZE, "%d", sel_ino_to_perm(ino));
	rc = simple_read_from_buffer(buf, count, ppos, page, len);
	free_page((unsigned long)page);
out:
	return rc;
	unsigned long ino = file_inode(file)->i_ino;
	char res[TMPBUFLEN];
	ssize_t len = snprintf(res, sizeof(res), "%d", sel_ino_to_perm(ino));
	return simple_read_from_buffer(buf, count, ppos, res, len);
}

static const struct file_operations sel_perm_ops = {
	.read		= sel_read_perm,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_read_policycap(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	int value;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	unsigned long i_ino = file->f_path.dentry->d_inode->i_ino;
	unsigned long i_ino = file_inode(file)->i_ino;

	value = security_policycap_supported(fsi->state, i_ino & SEL_INO_MASK);
	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", value);

	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_policycap_ops = {
	.read		= sel_read_policycap,
	.llseek		= generic_file_llseek,
};

static int sel_make_perm_files(char *objclass, int classvalue,
				struct dentry *dir)
{
	int i, rc = 0, nperms;
	struct selinux_fs_info *fsi = dir->d_sb->s_fs_info;
	int i, rc, nperms;
	char **perms;

	rc = security_get_permissions(fsi->state, objclass, &perms, &nperms);
	if (rc)
		goto out;
		return rc;

	for (i = 0; i < nperms; i++) {
		struct inode *inode;
		struct dentry *dentry;

		dentry = d_alloc_name(dir, perms[i]);
		if (!dentry) {
			rc = -ENOMEM;
			goto out1;
		}

		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
		if (!inode) {
			rc = -ENOMEM;
			goto out1;
		}
		inode->i_fop = &sel_perm_ops;
		/* i+1 since perm values are 1-indexed */
		inode->i_ino = sel_perm_to_ino(classvalue, i+1);
		d_add(dentry, inode);
	}

out1:
	for (i = 0; i < nperms; i++)
		kfree(perms[i]);
	kfree(perms);
out:
		rc = -ENOMEM;
		dentry = d_alloc_name(dir, perms[i]);
		if (!dentry)
			goto out;

		rc = -ENOMEM;
		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
		if (!inode) {
			dput(dentry);
			goto out;
		}

		inode->i_fop = &sel_perm_ops;
		/* i+1 since perm values are 1-indexed */
		inode->i_ino = sel_perm_to_ino(classvalue, i + 1);
		d_add(dentry, inode);
	}
	rc = 0;
out:
	for (i = 0; i < nperms; i++)
		kfree(perms[i]);
	kfree(perms);
	return rc;
}

static int sel_make_class_dir_entries(char *classname, int index,
					struct dentry *dir)
{
	struct super_block *sb = dir->d_sb;
	struct selinux_fs_info *fsi = sb->s_fs_info;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	int rc;

	dentry = d_alloc_name(dir, "index");
	if (!dentry) {
		rc = -ENOMEM;
		goto out;
	}

	inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
	if (!inode) {
		rc = -ENOMEM;
		goto out;
	}
	if (!dentry)
		return -ENOMEM;

	inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
	if (!inode) {
		dput(dentry);
		return -ENOMEM;
	}

	inode->i_fop = &sel_class_ops;
	inode->i_ino = sel_class_to_ino(index);
	d_add(dentry, inode);

	dentry = d_alloc_name(dir, "perms");
	if (!dentry) {
		rc = -ENOMEM;
		goto out;
	}

	rc = sel_make_dir(dir->d_inode, dentry, &last_class_ino);
	if (rc)
		goto out;

	rc = sel_make_perm_files(classname, index, dentry);

out:
	return rc;
}

static void sel_remove_classes(void)
{
	struct list_head *class_node;

	list_for_each(class_node, &class_dir->d_subdirs) {
		struct dentry *class_subdir = list_entry(class_node,
					struct dentry, d_u.d_child);
		struct list_head *class_subdir_node;

		list_for_each(class_subdir_node, &class_subdir->d_subdirs) {
			struct dentry *d = list_entry(class_subdir_node,
						struct dentry, d_u.d_child);

			if (d->d_inode)
				if (d->d_inode->i_mode & S_IFDIR)
					sel_remove_entries(d);
		}

		sel_remove_entries(class_subdir);
	}

	sel_remove_entries(class_dir);
}

static int sel_make_classes(void)
{
	int rc = 0, nclasses, i;
	char **classes;

	/* delete any existing entries */
	sel_remove_classes();

	rc = security_get_classes(&classes, &nclasses);
	if (rc < 0)
		goto out;

	/* +2 since classes are 1-indexed */
	last_class_ino = sel_class_to_ino(nclasses+2);
	dentry = sel_make_dir(dir, "perms", &last_class_ino);
	dentry = sel_make_dir(dir, "perms", &fsi->last_class_ino);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	rc = sel_make_perm_files(classname, index, dentry);

	return rc;
}

static int sel_make_classes(struct selinux_fs_info *fsi)
{

	int rc, nclasses, i;
	char **classes;

	/* delete any existing entries */
	sel_remove_entries(fsi->class_dir);

	rc = security_get_classes(fsi->state, &classes, &nclasses);
	if (rc)
		return rc;

	/* +2 since classes are 1-indexed */
	fsi->last_class_ino = sel_class_to_ino(nclasses + 2);

	for (i = 0; i < nclasses; i++) {
		struct dentry *class_name_dir;

		class_name_dir = d_alloc_name(class_dir, classes[i]);
		if (!class_name_dir) {
			rc = -ENOMEM;
			goto out1;
		}

		rc = sel_make_dir(class_dir->d_inode, class_name_dir,
				&last_class_ino);
		if (rc)
			goto out1;

		/* i+1 since class values are 1-indexed */
		rc = sel_make_class_dir_entries(classes[i], i+1,
				class_name_dir);
		if (rc)
			goto out1;
	}

out1:
	for (i = 0; i < nclasses; i++)
		kfree(classes[i]);
	kfree(classes);
out:
		class_name_dir = sel_make_dir(class_dir, classes[i],
				&last_class_ino);
		class_name_dir = sel_make_dir(fsi->class_dir, classes[i],
					      &fsi->last_class_ino);
		if (IS_ERR(class_name_dir)) {
			rc = PTR_ERR(class_name_dir);
			goto out;
		}

		/* i+1 since class values are 1-indexed */
		rc = sel_make_class_dir_entries(classes[i], i + 1,
				class_name_dir);
		if (rc)
			goto out;
	}
	rc = 0;
out:
	for (i = 0; i < nclasses; i++)
		kfree(classes[i]);
	kfree(classes);
	return rc;
}

static int sel_make_policycap(struct selinux_fs_info *fsi)
{
	unsigned int iter;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;

	sel_remove_entries(fsi->policycap_dir);

	for (iter = 0; iter <= POLICYDB_CAPABILITY_MAX; iter++) {
		if (iter < ARRAY_SIZE(selinux_policycap_names))
			dentry = d_alloc_name(fsi->policycap_dir,
					      selinux_policycap_names[iter]);
		else
			dentry = d_alloc_name(fsi->policycap_dir, "unknown");

		if (dentry == NULL)
			return -ENOMEM;

		inode = sel_make_inode(fsi->sb, S_IFREG | 0444);
		if (inode == NULL) {
			dput(dentry);
			return -ENOMEM;
		}

		inode->i_fop = &sel_policycap_ops;
		inode->i_ino = iter | SEL_POLICYCAP_INO_OFFSET;
		d_add(dentry, inode);
	}

	return 0;
}

static int sel_make_dir(struct inode *dir, struct dentry *dentry,
			unsigned long *ino)
{
	int ret = 0;
	struct inode *inode;

	inode = sel_make_inode(dir->i_sb, S_IFDIR | S_IRUGO | S_IXUGO);
	if (!inode) {
		ret = -ENOMEM;
		goto out;
	}
static struct dentry *sel_make_dir(struct dentry *dir, const char *name,
			unsigned long *ino)
{
	struct dentry *dentry = d_alloc_name(dir, name);
	struct inode *inode;

	if (!dentry)
		return ERR_PTR(-ENOMEM);

	inode = sel_make_inode(dir->d_sb, S_IFDIR | S_IRUGO | S_IXUGO);
	if (!inode) {
		dput(dentry);
		return ERR_PTR(-ENOMEM);
	}

	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	inode->i_ino = ++(*ino);
	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	d_add(dentry, inode);
	/* bump link count on parent directory, too */
	inc_nlink(dir);
out:
	return ret;
	inc_nlink(d_inode(dir));

	return dentry;
}

#define NULL_FILE_NAME "null"

static int sel_fill_super(struct super_block *sb, void *data, int silent)
{
	struct selinux_fs_info *fsi;
	int ret;
	struct dentry *dentry;
	struct inode *inode, *root_inode;
	struct inode *inode;
	struct inode_security_struct *isec;

	static const struct tree_descr selinux_files[] = {
		[SEL_LOAD] = {"load", &sel_load_ops, S_IRUSR|S_IWUSR},
		[SEL_ENFORCE] = {"enforce", &sel_enforce_ops, S_IRUGO|S_IWUSR},
		[SEL_CONTEXT] = {"context", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_ACCESS] = {"access", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_CREATE] = {"create", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_RELABEL] = {"relabel", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_USER] = {"user", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_POLICYVERS] = {"policyvers", &sel_policyvers_ops, S_IRUGO},
		[SEL_COMMIT_BOOLS] = {"commit_pending_bools", &sel_commit_bools_ops, S_IWUSR},
		[SEL_MLS] = {"mls", &sel_mls_ops, S_IRUGO},
		[SEL_DISABLE] = {"disable", &sel_disable_ops, S_IWUSR},
		[SEL_MEMBER] = {"member", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_CHECKREQPROT] = {"checkreqprot", &sel_checkreqprot_ops, S_IRUGO|S_IWUSR},
		[SEL_COMPAT_NET] = {"compat_net", &sel_compat_net_ops, S_IRUGO|S_IWUSR},
		[SEL_REJECT_UNKNOWN] = {"reject_unknown", &sel_handle_unknown_ops, S_IRUGO},
		[SEL_DENY_UNKNOWN] = {"deny_unknown", &sel_handle_unknown_ops, S_IRUGO},
		[SEL_REJECT_UNKNOWN] = {"reject_unknown", &sel_handle_unknown_ops, S_IRUGO},
		[SEL_DENY_UNKNOWN] = {"deny_unknown", &sel_handle_unknown_ops, S_IRUGO},
		[SEL_STATUS] = {"status", &sel_handle_status_ops, S_IRUGO},
		[SEL_POLICY] = {"policy", &sel_policy_ops, S_IRUGO},
		[SEL_VALIDATE_TRANS] = {"validatetrans", &sel_transition_ops,
					S_IWUGO},
		/* last one */ {""}
	};

	ret = selinux_fs_info_create(sb);
	if (ret)
		goto err;

	ret = simple_fill_super(sb, SELINUX_MAGIC, selinux_files);
	if (ret)
		goto err;

	root_inode = sb->s_root->d_inode;

	dentry = d_alloc_name(sb->s_root, BOOL_DIR_NAME);
	if (!dentry) {
		ret = -ENOMEM;
		goto err;
	}

	ret = sel_make_dir(root_inode, dentry, &sel_last_ino);
	if (ret)
		goto err;

	bool_dir = dentry;

	dentry = d_alloc_name(sb->s_root, NULL_FILE_NAME);
	if (!dentry) {
		ret = -ENOMEM;
		goto err;
	}

	inode = sel_make_inode(sb, S_IFCHR | S_IRUGO | S_IWUGO);
	if (!inode) {
		ret = -ENOMEM;
		goto err;
	}
	bool_dir = sel_make_dir(sb->s_root, BOOL_DIR_NAME, &sel_last_ino);
	if (IS_ERR(bool_dir)) {
		ret = PTR_ERR(bool_dir);
		bool_dir = NULL;
	fsi = sb->s_fs_info;
	fsi->bool_dir = sel_make_dir(sb->s_root, BOOL_DIR_NAME, &fsi->last_ino);
	if (IS_ERR(fsi->bool_dir)) {
		ret = PTR_ERR(fsi->bool_dir);
		fsi->bool_dir = NULL;
		goto err;
	}

	ret = -ENOMEM;
	dentry = d_alloc_name(sb->s_root, NULL_FILE_NAME);
	if (!dentry)
		goto err;

	ret = -ENOMEM;
	inode = sel_make_inode(sb, S_IFCHR | S_IRUGO | S_IWUGO);
	if (!inode) {
		dput(dentry);
		goto err;
	}

	inode->i_ino = ++fsi->last_ino;
	isec = (struct inode_security_struct *)inode->i_security;
	isec->sid = SECINITSID_DEVNULL;
	isec->sclass = SECCLASS_CHR_FILE;
	isec->initialized = LABEL_INITIALIZED;

	init_special_inode(inode, S_IFCHR | S_IRUGO | S_IWUGO, MKDEV(MEM_MAJOR, 3));
	d_add(dentry, inode);
	selinux_null = dentry;

	dentry = d_alloc_name(sb->s_root, "avc");
	if (!dentry) {
		ret = -ENOMEM;
		goto err;
	}

	ret = sel_make_dir(root_inode, dentry, &sel_last_ino);
	if (ret)
		goto err;

	selinux_null.dentry = dentry;

	dentry = sel_make_dir(sb->s_root, "avc", &fsi->last_ino);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err;
	}

	ret = sel_make_avc_files(dentry);
	if (ret)
		goto err;

	dentry = d_alloc_name(sb->s_root, "initial_contexts");
	if (!dentry) {
		ret = -ENOMEM;
		goto err;
	}

	ret = sel_make_dir(root_inode, dentry, &sel_last_ino);
	if (ret)
		goto err;

	dentry = sel_make_dir(sb->s_root, "initial_contexts", &sel_last_ino);
	dentry = sel_make_dir(sb->s_root, "initial_contexts", &fsi->last_ino);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err;
	}

	ret = sel_make_initcon_files(dentry);
	if (ret)
		goto err;

	dentry = d_alloc_name(sb->s_root, "class");
	if (!dentry) {
		ret = -ENOMEM;
		goto err;
	}

	ret = sel_make_dir(root_inode, dentry, &sel_last_ino);
	if (ret)
		goto err;

	class_dir = dentry;

	dentry = d_alloc_name(sb->s_root, "policy_capabilities");
	if (!dentry) {
		ret = -ENOMEM;
		goto err;
	}

	ret = sel_make_dir(root_inode, dentry, &sel_last_ino);
	if (ret)
		goto err;

	policycap_dir = dentry;

out:
	return ret;
err:
	printk(KERN_ERR "SELinux: %s:  failed while creating inodes\n",
		__func__);
	goto out;
}

static int sel_get_sb(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *data,
		      struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, sel_fill_super, mnt);
	class_dir = sel_make_dir(sb->s_root, "class", &sel_last_ino);
	if (IS_ERR(class_dir)) {
		ret = PTR_ERR(class_dir);
		class_dir = NULL;
	fsi->class_dir = sel_make_dir(sb->s_root, "class", &fsi->last_ino);
	if (IS_ERR(fsi->class_dir)) {
		ret = PTR_ERR(fsi->class_dir);
		fsi->class_dir = NULL;
		goto err;
	}

	fsi->policycap_dir = sel_make_dir(sb->s_root, "policy_capabilities",
					  &fsi->last_ino);
	if (IS_ERR(fsi->policycap_dir)) {
		ret = PTR_ERR(fsi->policycap_dir);
		fsi->policycap_dir = NULL;
		goto err;
	}

	ret = sel_make_policy_nodes(fsi);
	if (ret)
		goto err;
	return 0;
err:
	pr_err("SELinux: %s:  failed while creating inodes\n",
		__func__);

	selinux_fs_info_free(sb);

	return ret;
}

static struct dentry *sel_mount(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, sel_fill_super);
}

static void sel_kill_sb(struct super_block *sb)
{
	selinux_fs_info_free(sb);
	kill_litter_super(sb);
}

static struct file_system_type sel_fs_type = {
	.name		= "selinuxfs",
	.get_sb		= sel_get_sb,
	.mount		= sel_mount,
	.kill_sb	= sel_kill_sb,
};

struct vfsmount *selinuxfs_mount;
struct path selinux_null;

static int __init init_sel_fs(void)
{
	struct qstr null_name = QSTR_INIT(NULL_FILE_NAME,
					  sizeof(NULL_FILE_NAME)-1);
	int err;

	if (!selinux_enabled)
		return 0;
	err = register_filesystem(&sel_fs_type);
	if (!err) {
		selinuxfs_mount = kern_mount(&sel_fs_type);
		if (IS_ERR(selinuxfs_mount)) {
			printk(KERN_ERR "selinuxfs:  could not mount!\n");
			err = PTR_ERR(selinuxfs_mount);
			selinuxfs_mount = NULL;
		}
	}

	err = sysfs_create_mount_point(fs_kobj, "selinux");
	if (err)
		return err;

	err = register_filesystem(&sel_fs_type);
	if (err) {
		sysfs_remove_mount_point(fs_kobj, "selinux");
		return err;
	}

	selinux_null.mnt = selinuxfs_mount = kern_mount(&sel_fs_type);
	if (IS_ERR(selinuxfs_mount)) {
		pr_err("selinuxfs:  could not mount!\n");
		err = PTR_ERR(selinuxfs_mount);
		selinuxfs_mount = NULL;
	}
	selinux_null.dentry = d_hash_and_lookup(selinux_null.mnt->mnt_root,
						&null_name);
	if (IS_ERR(selinux_null.dentry)) {
		pr_err("selinuxfs:  could not lookup null!\n");
		err = PTR_ERR(selinux_null.dentry);
		selinux_null.dentry = NULL;
	}

	return err;
}

__initcall(init_sel_fs);

#ifdef CONFIG_SECURITY_SELINUX_DISABLE
void exit_sel_fs(void)
{
	sysfs_remove_mount_point(fs_kobj, "selinux");
	dput(selinux_null.dentry);
	kern_unmount(selinuxfs_mount);
	unregister_filesystem(&sel_fs_type);
}
#endif
