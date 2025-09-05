/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * mmap.c
 *
 * Code to deal with the mess that is clustered mmap.
 *
 * Copyright (C) 2002, 2004 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/signal.h>
#include <linux/rbtree.h>

#define MLOG_MASK_PREFIX ML_FILE_IO
#include <cluster/masklog.h>

#include "ocfs2.h"

#include "aops.h"
#include "dlmglue.h"
#include "file.h"
#include "inode.h"
#include "mmap.h"

static inline int ocfs2_vm_op_block_sigs(sigset_t *blocked, sigset_t *oldset)
{
	/* The best way to deal with signals in the vm path is
	 * to block them upfront, rather than allowing the
	 * locking paths to return -ERESTARTSYS. */
	sigfillset(blocked);

	/* We should technically never get a bad return value
	 * from sigprocmask */
	return sigprocmask(SIG_BLOCK, blocked, oldset);
}

static inline int ocfs2_vm_op_unblock_sigs(sigset_t *oldset)
{
	return sigprocmask(SIG_SETMASK, oldset, NULL);
}

static int ocfs2_fault(struct vm_area_struct *area, struct vm_fault *vmf)
{
	sigset_t blocked, oldset;
	int error, ret;

	mlog_entry("(area=%p, page offset=%lu)\n", area, vmf->pgoff);

	error = ocfs2_vm_op_block_sigs(&blocked, &oldset);
	if (error < 0) {
		mlog_errno(error);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	ret = filemap_fault(area, vmf);

	error = ocfs2_vm_op_unblock_sigs(&oldset);
	if (error < 0)
		mlog_errno(error);
out:
	mlog_exit_ptr(vmf->page);
	return ret;
}

static int __ocfs2_page_mkwrite(struct inode *inode, struct buffer_head *di_bh,
				struct page *page)
{
	int ret;
#include "super.h"
#include "ocfs2_trace.h"


static vm_fault_t ocfs2_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	sigset_t oldset;
	vm_fault_t ret;

	ocfs2_block_signals(&oldset);
	ret = filemap_fault(vmf);
	ocfs2_unblock_signals(&oldset);

	trace_ocfs2_fault(OCFS2_I(vma->vm_file->f_mapping->host)->ip_blkno,
			  vma, vmf->page, vmf->pgoff);
	return ret;
}

static vm_fault_t __ocfs2_page_mkwrite(struct file *file,
			struct buffer_head *di_bh, struct page *page)
{
	int err;
	vm_fault_t ret = VM_FAULT_NOPAGE;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	loff_t pos = page_offset(page);
	unsigned int len = PAGE_SIZE;
	pgoff_t last_index;
	struct page *locked_page = NULL;
	void *fsdata;
	loff_t size = i_size_read(inode);

	/*
	 * Another node might have truncated while we were waiting on
	 * cluster locks.
	 */
	last_index = size >> PAGE_CACHE_SHIFT;
	if (page->index > last_index) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * The i_size check above doesn't catch the case where nodes
	 * truncated and then re-extended the file. We'll re-check the
	 * page mapping after taking the page lock inside of
	 * ocfs2_write_begin_nolock().
	 */
	if (!PageUptodate(page) || page->mapping != inode->i_mapping) {
		ret = -EINVAL;
		goto out;
	}
	last_index = (size - 1) >> PAGE_CACHE_SHIFT;
	last_index = (size - 1) >> PAGE_SHIFT;

	/*
	 * There are cases that lead to the page no longer bebongs to the
	 * mapping.
	 * 1) pagecache truncates locally due to memory pressure.
	 * 2) pagecache truncates when another is taking EX lock against 
	 * inode lock. see ocfs2_data_convert_worker.
	 * 
	 * The i_size check doesn't catch the case where nodes truncated and
	 * then re-extended the file. We'll re-check the page mapping after
	 * taking the page lock inside of ocfs2_write_begin_nolock().
	 *
	 * Let VM retry with these cases.
	 */
	if ((page->mapping != inode->i_mapping) ||
	    (!PageUptodate(page)) ||
	    (page_offset(page) >= size))
		goto out;

	/*
	 * Call ocfs2_write_begin() and ocfs2_write_end() to take
	 * advantage of the allocation code there. We pass a write
	 * length of the whole page (chopped to i_size) to make sure
	 * the whole thing is allocated.
	 *
	 * Since we know the page is up to date, we don't have to
	 * worry about ocfs2_write_begin() skipping some buffer reads
	 * because the "write" would invalidate their data.
	 */
	if (page->index == last_index)
		len = size & ~PAGE_CACHE_MASK;

	ret = ocfs2_write_begin_nolock(mapping, pos, len, 0, &locked_page,
		len = ((size - 1) & ~PAGE_CACHE_MASK) + 1;
		len = ((size - 1) & ~PAGE_MASK) + 1;

	err = ocfs2_write_begin_nolock(mapping, pos, len, OCFS2_WRITE_MMAP,
				       &locked_page, &fsdata, di_bh, page);
	if (ret) {
		if (ret != -ENOSPC)
			mlog_errno(ret);
		goto out;
	}

	ret = ocfs2_write_end_nolock(mapping, pos, len, len, locked_page,
				     fsdata);
	if (ret < 0) {
		mlog_errno(ret);
		goto out;
	}
	BUG_ON(ret != len);
	ret = 0;
		if (ret == -ENOMEM)
			ret = VM_FAULT_OOM;
		else
			ret = VM_FAULT_SIGBUS;
	if (err) {
		if (err != -ENOSPC)
			mlog_errno(err);
		ret = vmf_error(err);
		goto out;
	}

	if (!locked_page) {
		ret = VM_FAULT_NOPAGE;
		goto out;
	}
	err = ocfs2_write_end_nolock(mapping, pos, len, len, fsdata);
	BUG_ON(err != len);
	ret = VM_FAULT_LOCKED;
out:
	return ret;
}

static int ocfs2_page_mkwrite(struct vm_area_struct *vma, struct page *page)
{
	struct inode *inode = vma->vm_file->f_path.dentry->d_inode;
	struct buffer_head *di_bh = NULL;
	sigset_t blocked, oldset;
	int ret, ret2;

	ret = ocfs2_vm_op_block_sigs(&blocked, &oldset);
	if (ret < 0) {
		mlog_errno(ret);
		return ret;
	}
static int ocfs2_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
static int ocfs2_page_mkwrite(struct vm_fault *vmf)
static vm_fault_t ocfs2_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct buffer_head *di_bh = NULL;
	sigset_t oldset;
	int err;
	vm_fault_t ret;

	sb_start_pagefault(inode->i_sb);
	ocfs2_block_signals(&oldset);

	/*
	 * The cluster locks taken will block a truncate from another
	 * node. Taking the data lock will also ensure that we don't
	 * attempt page truncation as part of a downconvert.
	 */
	err = ocfs2_inode_lock(inode, &di_bh, 1);
	if (err < 0) {
		mlog_errno(err);
		ret = vmf_error(err);
		goto out;
	}

	/*
	 * The alloc sem should be enough to serialize with
	 * ocfs2_truncate_file() changing i_size as well as any thread
	 * modifying the inode btree.
	 */
	down_write(&OCFS2_I(inode)->ip_alloc_sem);

	ret = __ocfs2_page_mkwrite(inode, di_bh, page);
	ret = __ocfs2_page_mkwrite(vma->vm_file, di_bh, page);
	ret = __ocfs2_page_mkwrite(vmf->vma->vm_file, di_bh, page);

	up_write(&OCFS2_I(inode)->ip_alloc_sem);

	brelse(di_bh);
	ocfs2_inode_unlock(inode, 1);

out:
	ret2 = ocfs2_vm_op_unblock_sigs(&oldset);
	if (ret2 < 0)
		mlog_errno(ret2);

	return ret;
}

static struct vm_operations_struct ocfs2_file_vm_ops = {
	ocfs2_unblock_signals(&oldset);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

static const struct vm_operations_struct ocfs2_file_vm_ops = {
	.fault		= ocfs2_fault,
	.page_mkwrite	= ocfs2_page_mkwrite,
};

int ocfs2_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret = 0, lock_level = 0;

	ret = ocfs2_inode_lock_atime(file->f_dentry->d_inode,
				    file->f_vfsmnt, &lock_level);
	ret = ocfs2_inode_lock_atime(file_inode(file),
				    file->f_path.mnt, &lock_level, 1);
	if (ret < 0) {
		mlog_errno(ret);
		goto out;
	}
	ocfs2_inode_unlock(file->f_dentry->d_inode, lock_level);
out:
	vma->vm_ops = &ocfs2_file_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;
	ocfs2_inode_unlock(file_inode(file), lock_level);
out:
	vma->vm_ops = &ocfs2_file_vm_ops;
	return 0;
}

