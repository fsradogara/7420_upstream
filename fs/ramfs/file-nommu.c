/* file-nommu.c: no-MMU version of ramfs
 *
 * Copyright (C) 2005 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/mman.h>
#include <linux/pagevec.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <linux/uaccess.h>
#include "internal.h"

static int ramfs_nommu_setattr(struct dentry *, struct iattr *);

const struct address_space_operations ramfs_aops = {
	.readpage		= simple_readpage,
	.write_begin		= simple_write_begin,
	.write_end		= simple_write_end,
	.set_page_dirty		= __set_page_dirty_no_writeback,
};

const struct file_operations ramfs_file_operations = {
	.mmap			= ramfs_nommu_mmap,
	.get_unmapped_area	= ramfs_nommu_get_unmapped_area,
	.read			= do_sync_read,
	.aio_read		= generic_file_aio_read,
	.write			= do_sync_write,
	.aio_write		= generic_file_aio_write,
	.fsync			= simple_sync_file,
	.splice_read		= generic_file_splice_read,
	.splice_write		= generic_file_splice_write,
static unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
						   unsigned long addr,
						   unsigned long len,
						   unsigned long pgoff,
						   unsigned long flags);
static int ramfs_nommu_mmap(struct file *file, struct vm_area_struct *vma);

static unsigned ramfs_mmap_capabilities(struct file *file)
{
	return NOMMU_MAP_DIRECT | NOMMU_MAP_COPY | NOMMU_MAP_READ |
		NOMMU_MAP_WRITE | NOMMU_MAP_EXEC;
}

const struct file_operations ramfs_file_operations = {
	.mmap_capabilities	= ramfs_mmap_capabilities,
	.mmap			= ramfs_nommu_mmap,
	.get_unmapped_area	= ramfs_nommu_get_unmapped_area,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.fsync			= noop_fsync,
	.splice_read		= generic_file_splice_read,
	.splice_write		= iter_file_splice_write,
	.llseek			= generic_file_llseek,
};

const struct inode_operations ramfs_file_inode_operations = {
	.setattr		= ramfs_nommu_setattr,
	.getattr		= simple_getattr,
};

/*****************************************************************************/
/*
 * add a contiguous set of pages into a ramfs inode when it's truncated from
 * size 0 on the assumption that it's going to be used for an mmap of shared
 * memory
 */
int ramfs_nommu_expand_for_mapping(struct inode *inode, size_t newsize)
{
	struct pagevec lru_pvec;
	unsigned long npages, xpages, loop, limit;
	unsigned long npages, xpages, loop;
	struct page *pages;
	unsigned order;
	void *data;
	int ret;
	gfp_t gfp = mapping_gfp_mask(inode->i_mapping);

	/* make various checks */
	order = get_order(newsize);
	if (unlikely(order >= MAX_ORDER))
		goto too_big;

	limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
	if (limit != RLIM_INFINITY && newsize > limit)
		goto fsize_exceeded;

	if (newsize > inode->i_sb->s_maxbytes)
		goto too_big;
		return -EFBIG;

	ret = inode_newsize_ok(inode, newsize);
	if (ret)
		return ret;

	i_size_write(inode, newsize);

	/* allocate enough contiguous pages to be able to satisfy the
	 * request */
	pages = alloc_pages(mapping_gfp_mask(inode->i_mapping), order);
	pages = alloc_pages(gfp, order);
	if (!pages)
		return -ENOMEM;

	/* split the high-order page into an array of single pages */
	xpages = 1UL << order;
	npages = (newsize + PAGE_SIZE - 1) >> PAGE_SHIFT;

	split_page(pages, order);

	/* trim off any pages we don't actually require */
	for (loop = npages; loop < xpages; loop++)
		__free_page(pages + loop);

	/* clear the memory we allocated */
	newsize = PAGE_SIZE * npages;
	data = page_address(pages);
	memset(data, 0, newsize);

	/* attach all the pages to the inode's address space */
	pagevec_init(&lru_pvec, 0);
	for (loop = 0; loop < npages; loop++) {
		struct page *page = pages + loop;

		ret = add_to_page_cache(page, inode->i_mapping, loop, GFP_KERNEL);
		if (ret < 0)
			goto add_error;

		if (!pagevec_add(&lru_pvec, page))
			__pagevec_lru_add(&lru_pvec);

		unlock_page(page);
	}

	pagevec_lru_add(&lru_pvec);
	return 0;

 fsize_exceeded:
	send_sig(SIGXFSZ, current, 0);
 too_big:
	return -EFBIG;

 add_error:
	page_cache_release(pages + loop);
	for (loop++; loop < npages; loop++)
		__free_page(pages + loop);
	for (loop = 0; loop < npages; loop++) {
		struct page *page = pages + loop;

		ret = add_to_page_cache_lru(page, inode->i_mapping, loop,
					gfp);
		if (ret < 0)
			goto add_error;

		/* prevent the page from being discarded on memory pressure */
		SetPageDirty(page);
		SetPageUptodate(page);

		unlock_page(page);
		put_page(page);
	}

	return 0;

add_error:
	while (loop < npages)
		__free_page(pages + loop++);
	return ret;
}

/*****************************************************************************/
/*
 * check that file shrinkage doesn't leave any VMAs dangling in midair
 */
static int ramfs_nommu_check_mappings(struct inode *inode,
				      size_t newsize, size_t size)
{
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;

	/* search for VMAs that fall within the dead zone */
	vma_prio_tree_foreach(vma, &iter, &inode->i_mapping->i_mmap,
			      newsize >> PAGE_SHIFT,
			      (size + PAGE_SIZE - 1) >> PAGE_SHIFT
			      ) {
		/* found one - only interested if it's shared out of the page
		 * cache */
		if (vma->vm_flags & VM_SHARED)
			return -ETXTBSY; /* not quite true, but near enough */
	}

	return 0;
}

/*****************************************************************************/
/*
 *
 */
static int ramfs_nommu_resize(struct inode *inode, loff_t newsize, loff_t size)
{
	int ret;

	/* assume a truncate from zero size is going to be for the purposes of
	 * shared mmap */
	if (size == 0) {
		if (unlikely(newsize >> 32))
			return -EFBIG;

		return ramfs_nommu_expand_for_mapping(inode, newsize);
	}

	/* check that a decrease in size doesn't cut off any shared mappings */
	if (newsize < size) {
		ret = ramfs_nommu_check_mappings(inode, newsize, size);
		ret = nommu_shrink_inode_mappings(inode, size, newsize);
		if (ret < 0)
			return ret;
	}

	ret = vmtruncate(inode, newsize);

	return ret;
	truncate_setsize(inode, newsize);
	return 0;
}

/*****************************************************************************/
/*
 * handle a change of attributes
 * - we're specifically interested in a change of size
 */
static int ramfs_nommu_setattr(struct dentry *dentry, struct iattr *ia)
{
	struct inode *inode = dentry->d_inode;
	struct inode *inode = d_inode(dentry);
	unsigned int old_ia_valid = ia->ia_valid;
	int ret = 0;

	/* POSIX UID/GID verification for setting inode attributes */
	ret = setattr_prepare(dentry, ia);
	if (ret)
		return ret;

	/* by providing our own setattr() method, we skip this quotaism */
	if ((old_ia_valid & ATTR_UID && ia->ia_uid != inode->i_uid) ||
	    (old_ia_valid & ATTR_GID && ia->ia_gid != inode->i_gid))
		ret = DQUOT_TRANSFER(inode, ia) ? -EDQUOT : 0;

	/* pick out size-changing events */
	if (ia->ia_valid & ATTR_SIZE) {
		loff_t size = i_size_read(inode);
	/* pick out size-changing events */
	if (ia->ia_valid & ATTR_SIZE) {
		loff_t size = inode->i_size;

		if (ia->ia_size != size) {
			ret = ramfs_nommu_resize(inode, ia->ia_size, size);
			if (ret < 0 || ia->ia_valid == ATTR_SIZE)
				goto out;
		} else {
			/* we skipped the truncate but must still update
			 * timestamps
			 */
			ia->ia_valid |= ATTR_MTIME|ATTR_CTIME;
		}
	}

	ret = inode_setattr(inode, ia);
	setattr_copy(inode, ia);
 out:
	ia->ia_valid = old_ia_valid;
	return ret;
}

/*****************************************************************************/
/*
 * try to determine where a shared mapping can be made
 * - we require that:
 *   - the pages to be mapped must exist
 *   - the pages be physically contiguous in sequence
 */
unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
static unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
					    unsigned long addr, unsigned long len,
					    unsigned long pgoff, unsigned long flags)
{
	unsigned long maxpages, lpages, nr, loop, ret;
	struct inode *inode = file->f_path.dentry->d_inode;
	struct inode *inode = file_inode(file);
	struct page **pages = NULL, **ptr, *page;
	loff_t isize;

	/* the mapping mustn't extend beyond the EOF */
	lpages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	isize = i_size_read(inode);

	ret = -ENOSYS;
	maxpages = (isize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (pgoff >= maxpages)
		goto out;

	if (maxpages - pgoff < lpages)
		goto out;

	/* gang-find the pages */
	ret = -ENOMEM;
	pages = kzalloc(lpages * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		goto out;

	nr = find_get_pages(inode->i_mapping, pgoff, lpages, pages);
	if (nr != lpages)
		goto out; /* leave if some pages were missing */
	pages = kcalloc(lpages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		goto out_free;

	nr = find_get_pages(inode->i_mapping, &pgoff, lpages, pages);
	if (nr != lpages)
		goto out_free_pages; /* leave if some pages were missing */

	/* check the pages for physical adjacency */
	ptr = pages;
	page = *ptr++;
	page++;
	for (loop = lpages; loop > 1; loop--)
		if (*ptr++ != page++)
			goto out;
			goto out_free_pages;

	/* okay - all conditions fulfilled */
	ret = (unsigned long) page_address(pages[0]);

 out:
	if (pages) {
		ptr = pages;
		for (loop = lpages; loop > 0; loop--)
			put_page(*ptr++);
		kfree(pages);
	}

out_free_pages:
	ptr = pages;
	for (loop = nr; loop > 0; loop--)
		put_page(*ptr++);
out_free:
	kfree(pages);
out:
	return ret;
}

/*****************************************************************************/
/*
 * set up a mapping for shared memory segments
 */
int ramfs_nommu_mmap(struct file *file, struct vm_area_struct *vma)
static int ramfs_nommu_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (!(vma->vm_flags & (VM_SHARED | VM_MAYSHARE)))
		return -ENOSYS;

	file_accessed(file);
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}
