/*
 * arch/xtensa/kernel/pci-dma.c
 *
 * DMA coherent memory allocation.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Copyright (C) 2002 - 2005 Tensilica Inc.
 * Copyright (C) 2015 Cadence Design Systems Inc.
 *
 * Based on version for i386.
 *
 * Chris Zankel <chris@zankel.net>
 * Joe Taylor <joe@tensilica.com, joetylr@yahoo.com>
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <asm/io.h>
#include <asm/cacheflush.h>
#include <linux/dma-contiguous.h>
#include <linux/dma-noncoherent.h>
#include <linux/dma-direct.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/platform.h>

static void do_cache_op(phys_addr_t paddr, size_t size,
			void (*fn)(unsigned long, unsigned long))
{
	unsigned long off = paddr & (PAGE_SIZE - 1);
	unsigned long pfn = PFN_DOWN(paddr);
	struct page *page = pfn_to_page(pfn);

	if (!PageHighMem(page))
		fn((unsigned long)phys_to_virt(paddr), size);
	else
		while (size > 0) {
			size_t sz = min_t(size_t, size, PAGE_SIZE - off);
			void *vaddr = kmap_atomic(page);

			fn((unsigned long)vaddr + off, sz);
			kunmap_atomic(vaddr);
			off = 0;
			++page;
			size -= sz;
		}
}

void arch_sync_dma_for_cpu(struct device *dev, phys_addr_t paddr,
		size_t size, enum dma_data_direction dir)
{
	switch (dir) {
	case DMA_BIDIRECTIONAL:
	case DMA_FROM_DEVICE:
		do_cache_op(paddr, size, __invalidate_dcache_range);
		break;

	case DMA_NONE:
		BUG();
		break;

	default:
		break;
	}
}

void arch_sync_dma_for_device(struct device *dev, phys_addr_t paddr,
		size_t size, enum dma_data_direction dir)
{
	switch (dir) {
	case DMA_BIDIRECTIONAL:
	case DMA_TO_DEVICE:
		if (XCHAL_DCACHE_IS_WRITEBACK)
			do_cache_op(paddr, size, __flush_dcache_range);
		break;

	case DMA_NONE:
		BUG();
		break;

	default:
		break;
	}
}

#ifdef CONFIG_MMU
bool platform_vaddr_cached(const void *p)
{
	unsigned long addr = (unsigned long)p;

	return addr >= XCHAL_KSEG_CACHED_VADDR &&
	       addr - XCHAL_KSEG_CACHED_VADDR < XCHAL_KSEG_SIZE;
}

bool platform_vaddr_uncached(const void *p)
{
	unsigned long addr = (unsigned long)p;

	return addr >= XCHAL_KSEG_BYPASS_VADDR &&
	       addr - XCHAL_KSEG_BYPASS_VADDR < XCHAL_KSEG_SIZE;
}

void *platform_vaddr_to_uncached(void *p)
{
	return p + XCHAL_KSEG_BYPASS_VADDR - XCHAL_KSEG_CACHED_VADDR;
}

void *platform_vaddr_to_cached(void *p)
{
	return p + XCHAL_KSEG_CACHED_VADDR - XCHAL_KSEG_BYPASS_VADDR;
}
#else
bool __attribute__((weak)) platform_vaddr_cached(const void *p)
{
	WARN_ONCE(1, "Default %s implementation is used\n", __func__);
	return true;
}

bool __attribute__((weak)) platform_vaddr_uncached(const void *p)
{
	WARN_ONCE(1, "Default %s implementation is used\n", __func__);
	return false;
}

void __attribute__((weak)) *platform_vaddr_to_uncached(void *p)
{
	WARN_ONCE(1, "Default %s implementation is used\n", __func__);
	return p;
}

void __attribute__((weak)) *platform_vaddr_to_cached(void *p)
{
	WARN_ONCE(1, "Default %s implementation is used\n", __func__);
	return p;
}
#endif

/*
 * Note: We assume that the full memory space is always mapped to 'kseg'
 *	 Otherwise we have to use page attributes (not implemented).
 */

void *
dma_alloc_coherent(struct device *dev,size_t size,dma_addr_t *handle,gfp_t flag)
static void *xtensa_dma_alloc(struct device *dev, size_t size,
			      dma_addr_t *handle, gfp_t flag,
			      unsigned long attrs)
void *arch_dma_alloc(struct device *dev, size_t size, dma_addr_t *handle,
		gfp_t flag, unsigned long attrs)
{
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page *page = NULL;

	/* ignore region speicifiers */

	flag &= ~(__GFP_DMA | __GFP_HIGHMEM);

	if (dev == NULL || (dev->coherent_dma_mask < 0xffffffff))
		flag |= GFP_DMA;

	if (gfpflags_allow_blocking(flag))
		page = dma_alloc_from_contiguous(dev, count, get_order(size),
						 flag & __GFP_NOWARN);

	if (!page)
		page = alloc_pages(flag, get_order(size));

	if (!page)
		return NULL;

	*handle = phys_to_dma(dev, page_to_phys(page));

	if (attrs & DMA_ATTR_NO_KERNEL_MAPPING) {
		return page;
	}

	if (ret < XCHAL_KSEG_CACHED_VADDR
	    || ret >= XCHAL_KSEG_CACHED_VADDR + XCHAL_KSEG_SIZE)
		BUG();


	if (ret != 0) {
		memset((void*) ret, 0, size);
		uncached = ret+XCHAL_KSEG_BYPASS_VADDR-XCHAL_KSEG_CACHED_VADDR;
		*handle = virt_to_bus((void*)ret);
		__flush_invalidate_dcache_range(ret, size);
	}

	return (void*)uncached;
}

void dma_free_coherent(struct device *hwdev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
	long addr=(long)vaddr+XCHAL_KSEG_CACHED_VADDR-XCHAL_KSEG_BYPASS_VADDR;

	if (addr < 0 || addr >= XCHAL_KSEG_SIZE)
		BUG();
	BUG_ON(ret < XCHAL_KSEG_CACHED_VADDR ||
	       ret > XCHAL_KSEG_CACHED_VADDR + XCHAL_KSEG_SIZE - 1);
#ifdef CONFIG_MMU
	if (PageHighMem(page)) {
		void *p;

		p = dma_common_contiguous_remap(page, size, VM_MAP,
						pgprot_noncached(PAGE_KERNEL),
						__builtin_return_address(0));
		if (!p) {
			if (!dma_release_from_contiguous(dev, page, count))
				__free_pages(page, get_order(size));
		}
		return p;
	}
#endif
	BUG_ON(!platform_vaddr_cached(page_address(page)));
	__invalidate_dcache_range((unsigned long)page_address(page), size);
	return platform_vaddr_to_uncached(page_address(page));
}

void arch_dma_free(struct device *dev, size_t size, void *vaddr,
		dma_addr_t dma_handle, unsigned long attrs)
{
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page *page;

	if (attrs & DMA_ATTR_NO_KERNEL_MAPPING) {
		page = vaddr;
	} else if (platform_vaddr_uncached(vaddr)) {
		page = virt_to_page(platform_vaddr_to_cached(vaddr));
	} else {
#ifdef CONFIG_MMU
		dma_common_free_remap(vaddr, size, VM_MAP);
#endif
		page = pfn_to_page(PHYS_PFN(dma_to_phys(dev, dma_handle)));
	}

	if (!dma_release_from_contiguous(dev, page, count))
		__free_pages(page, get_order(size));
}


void consistent_sync(void *vaddr, size_t size, int direction)
{
	switch (direction) {
	case PCI_DMA_NONE:
		BUG();
	case PCI_DMA_FROMDEVICE:        /* invalidate only */
		__invalidate_dcache_range((unsigned long)vaddr,
				          (unsigned long)size);
		break;

	case PCI_DMA_TODEVICE:          /* writeback only */
	case PCI_DMA_BIDIRECTIONAL:     /* writeback and invalidate */
		__flush_invalidate_dcache_range((unsigned long)vaddr,
				    		(unsigned long)size);
		break;
	}
}
static dma_addr_t xtensa_map_page(struct device *dev, struct page *page,
				  unsigned long offset, size_t size,
				  enum dma_data_direction dir,
				  unsigned long attrs)
{
	dma_addr_t dma_handle = page_to_phys(page) + offset;

	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		xtensa_sync_single_for_device(dev, dma_handle, size, dir);

	return dma_handle;
}

static void xtensa_unmap_page(struct device *dev, dma_addr_t dma_handle,
			      size_t size, enum dma_data_direction dir,
			      unsigned long attrs)
{
	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		xtensa_sync_single_for_cpu(dev, dma_handle, size, dir);
}

static int xtensa_map_sg(struct device *dev, struct scatterlist *sg,
			 int nents, enum dma_data_direction dir,
			 unsigned long attrs)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		s->dma_address = xtensa_map_page(dev, sg_page(s), s->offset,
						 s->length, dir, attrs);
	}
	return nents;
}

static void xtensa_unmap_sg(struct device *dev,
			    struct scatterlist *sg, int nents,
			    enum dma_data_direction dir,
			    unsigned long attrs)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		xtensa_unmap_page(dev, sg_dma_address(s),
				  sg_dma_len(s), dir, attrs);
	}
}

int xtensa_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	return 0;
}

const struct dma_map_ops xtensa_dma_map_ops = {
	.alloc = xtensa_dma_alloc,
	.free = xtensa_dma_free,
	.map_page = xtensa_map_page,
	.unmap_page = xtensa_unmap_page,
	.map_sg = xtensa_map_sg,
	.unmap_sg = xtensa_unmap_sg,
	.sync_single_for_cpu = xtensa_sync_single_for_cpu,
	.sync_single_for_device = xtensa_sync_single_for_device,
	.sync_sg_for_cpu = xtensa_sync_sg_for_cpu,
	.sync_sg_for_device = xtensa_sync_sg_for_device,
	.mapping_error = xtensa_dma_mapping_error,
};
EXPORT_SYMBOL(xtensa_dma_map_ops);

#define PREALLOC_DMA_DEBUG_ENTRIES (1 << 16)

static int __init xtensa_dma_init(void)
{
	dma_debug_init(PREALLOC_DMA_DEBUG_ENTRIES);
	return 0;
}
fs_initcall(xtensa_dma_init);
