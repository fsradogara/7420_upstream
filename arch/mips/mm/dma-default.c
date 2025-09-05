/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2000  Ani Joshi <ajoshi@unixbox.com>
 * Copyright (C) 2000, 2001, 06  Ralf Baechle <ralf@linux-mips.org>
 * Copyright (C) 2000, 2001, 06	 Ralf Baechle <ralf@linux-mips.org>
 * swiped from i386, and cloned for MIPS by Geert, polished by Ralf.
 */

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#include <asm/cache.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/dma-contiguous.h>

#include <asm/cache.h>
#include <asm/cpu-type.h>
#include <asm/io.h>

#include <dma-coherence.h>

static inline unsigned long dma_addr_to_virt(dma_addr_t dma_addr)
{
	unsigned long addr = plat_dma_addr_to_phys(dma_addr);

	return (unsigned long)phys_to_virt(addr);
}

/*
 * Warning on the terminology - Linux calls an uncached area coherent;
 * MIPS terminology calls memory areas with hardware maintained coherency
 * coherent.
 */

static inline int cpu_is_noncoherent_r10000(struct device *dev)
{
	return !plat_device_is_coherent(dev) &&
	       (current_cpu_type() == CPU_R10000 ||
	       current_cpu_type() == CPU_R12000);
#ifdef CONFIG_DMA_MAYBE_COHERENT
int coherentio = 0;	/* User defined DMA coherency from command line. */
#if defined(CONFIG_DMA_MAYBE_COHERENT) && !defined(CONFIG_DMA_PERDEV_COHERENT)
/* User defined DMA coherency from command line. */
enum coherent_io_user_state coherentio = IO_COHERENCE_DEFAULT;
EXPORT_SYMBOL_GPL(coherentio);
int hw_coherentio = 0;	/* Actual hardware supported DMA coherency setting. */

static int __init setcoherentio(char *str)
{
	coherentio = IO_COHERENCE_ENABLED;
	pr_info("Hardware DMA cache coherency (command line)\n");
	return 0;
}
early_param("coherentio", setcoherentio);

static int __init setnocoherentio(char *str)
{
	coherentio = IO_COHERENCE_DISABLED;
	pr_info("Software DMA cache coherency (command line)\n");
	return 0;
}
early_param("nocoherentio", setnocoherentio);
#endif

static inline struct page *dma_addr_to_page(struct device *dev,
	dma_addr_t dma_addr)
{
	return pfn_to_page(
		plat_dma_addr_to_phys(dev, dma_addr) >> PAGE_SHIFT);
}

/*
 * The affected CPUs below in 'cpu_needs_post_dma_flush()' can
 * speculatively fill random cachelines with stale data at any time,
 * requiring an extra flush post-DMA.
 *
 * Warning on the terminology - Linux calls an uncached area coherent;
 * MIPS terminology calls memory areas with hardware maintained coherency
 * coherent.
 *
 * Note that the R14000 and R16000 should also be checked for in this
 * condition.  However this function is only called on non-I/O-coherent
 * systems and only the R10000 and R12000 are used in such systems, the
 * SGI IP28 Indigo² rsp. SGI IP32 aka O2.
 */
static inline bool cpu_needs_post_dma_flush(struct device *dev)
{
	if (plat_device_is_coherent(dev))
		return false;

	switch (boot_cpu_type()) {
	case CPU_R10000:
	case CPU_R12000:
	case CPU_BMIPS5000:
		return true;

	default:
		/*
		 * Presence of MAARs suggests that the CPU supports
		 * speculatively prefetching data, and therefore requires
		 * the post-DMA flush/invalidate.
		 */
		return cpu_has_maar;
	}
}

static gfp_t massage_gfp_flags(const struct device *dev, gfp_t gfp)
{
	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM);

#ifdef CONFIG_ZONE_DMA
	if (dev == NULL)
		gfp |= __GFP_DMA;
	else if (dev->coherent_dma_mask < DMA_BIT_MASK(24))
		gfp |= __GFP_DMA;
	else
#endif
#ifdef CONFIG_ZONE_DMA32
	     if (dev->coherent_dma_mask < DMA_BIT_MASK(32))
		gfp |= __GFP_DMA32;
	else
#endif
		;
	gfp_t dma_flag;

	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM);

#ifdef CONFIG_ISA
	if (dev == NULL)
		dma_flag = __GFP_DMA;
	else
#endif
#if defined(CONFIG_ZONE_DMA32) && defined(CONFIG_ZONE_DMA)
	     if (dev == NULL || dev->coherent_dma_mask < DMA_BIT_MASK(32))
			dma_flag = __GFP_DMA;
	else if (dev->coherent_dma_mask < DMA_BIT_MASK(64))
			dma_flag = __GFP_DMA32;
	else
#endif
#if defined(CONFIG_ZONE_DMA32) && !defined(CONFIG_ZONE_DMA)
	     if (dev == NULL || dev->coherent_dma_mask < DMA_BIT_MASK(64))
		dma_flag = __GFP_DMA32;
	else
#endif
#if defined(CONFIG_ZONE_DMA) && !defined(CONFIG_ZONE_DMA32)
	     if (dev == NULL ||
		 dev->coherent_dma_mask < DMA_BIT_MASK(sizeof(phys_addr_t) * 8))
		dma_flag = __GFP_DMA;
	else
#endif
		dma_flag = 0;

	/* Don't invoke OOM killer */
	gfp |= __GFP_NORETRY;

	return gfp;
}

void *dma_alloc_noncoherent(struct device *dev, size_t size,
	return gfp | dma_flag;
}

static void *mips_dma_alloc_noncoherent(struct device *dev, size_t size,
	dma_addr_t * dma_handle, gfp_t gfp)
{
	void *ret;

	gfp = massage_gfp_flags(dev, gfp);

	ret = (void *) __get_free_pages(gfp, get_order(size));

	if (ret != NULL) {
		memset(ret, 0, size);
		*dma_handle = plat_map_dma_mem(dev, ret, size);
	}

	return ret;
}

EXPORT_SYMBOL(dma_alloc_noncoherent);

void *dma_alloc_coherent(struct device *dev, size_t size,
	dma_addr_t * dma_handle, gfp_t gfp)
{
	void *ret;

	gfp = massage_gfp_flags(dev, gfp);

	ret = (void *) __get_free_pages(gfp, get_order(size));

	if (ret) {
		memset(ret, 0, size);
		*dma_handle = plat_map_dma_mem(dev, ret, size);

		if (!plat_device_is_coherent(dev)) {
			dma_cache_wback_inv((unsigned long) ret, size);
			ret = UNCAC_ADDR(ret);
		}
static void *mips_dma_alloc_coherent(struct device *dev, size_t size,
	dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
	void *ret;
	struct page *page = NULL;
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;

	gfp = massage_gfp_flags(dev, gfp);

	if (IS_ENABLED(CONFIG_DMA_CMA) && gfpflags_allow_blocking(gfp))
		page = dma_alloc_from_contiguous(dev, count, get_order(size),
						 gfp);
	if (!page)
		page = alloc_pages(gfp, get_order(size));

	if (!page)
		return NULL;

	ret = page_address(page);
	memset(ret, 0, size);
	*dma_handle = plat_map_dma_mem(dev, ret, size);
	if (!(attrs & DMA_ATTR_NON_CONSISTENT) &&
	    !plat_device_is_coherent(dev)) {
		dma_cache_wback_inv((unsigned long) ret, size);
		ret = UNCAC_ADDR(ret);
	}

	return ret;
}

EXPORT_SYMBOL(dma_alloc_coherent);

void dma_free_noncoherent(struct device *dev, size_t size, void *vaddr,
	dma_addr_t dma_handle)
{
	free_pages((unsigned long) vaddr, get_order(size));
}

EXPORT_SYMBOL(dma_free_noncoherent);

void dma_free_coherent(struct device *dev, size_t size, void *vaddr,
	dma_addr_t dma_handle)
{
	unsigned long addr = (unsigned long) vaddr;

	if (!plat_device_is_coherent(dev))
		addr = CAC_ADDR(addr);

	free_pages(addr, get_order(size));
}

EXPORT_SYMBOL(dma_free_coherent);

static inline void __dma_sync(unsigned long addr, size_t size,

static void mips_dma_free_noncoherent(struct device *dev, size_t size,
		void *vaddr, dma_addr_t dma_handle)
{
	plat_unmap_dma_mem(dev, dma_handle, size, DMA_BIDIRECTIONAL);
	free_pages((unsigned long) vaddr, get_order(size));
}

static void mips_dma_free_coherent(struct device *dev, size_t size, void *vaddr,
	dma_addr_t dma_handle, unsigned long attrs)
{
	unsigned long addr = (unsigned long) vaddr;
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page *page = NULL;

	plat_unmap_dma_mem(dev, dma_handle, size, DMA_BIDIRECTIONAL);

	if (!(attrs & DMA_ATTR_NON_CONSISTENT) && !plat_device_is_coherent(dev))
		addr = CAC_ADDR(addr);

	page = virt_to_page((void *) addr);

	if (!dma_release_from_contiguous(dev, page, count))
		__free_pages(page, get_order(size));
}

static int mips_dma_mmap(struct device *dev, struct vm_area_struct *vma,
	void *cpu_addr, dma_addr_t dma_addr, size_t size,
	unsigned long attrs)
{
	unsigned long user_count = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long addr = (unsigned long)cpu_addr;
	unsigned long off = vma->vm_pgoff;
	unsigned long pfn;
	int ret = -ENXIO;

	if (!plat_device_is_coherent(dev))
		addr = CAC_ADDR(addr);

	pfn = page_to_pfn(virt_to_page((void *)addr));

	if (attrs & DMA_ATTR_WRITE_COMBINE)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (dma_mmap_from_dev_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;

	if (off < count && user_count <= (count - off)) {
		ret = remap_pfn_range(vma, vma->vm_start,
				      pfn + off,
				      user_count << PAGE_SHIFT,
				      vma->vm_page_prot);
	}

	return ret;
}

static inline void __dma_sync_virtual(void *addr, size_t size,
	enum dma_data_direction direction)
{
	switch (direction) {
	case DMA_TO_DEVICE:
		dma_cache_wback(addr, size);
		break;

	case DMA_FROM_DEVICE:
		dma_cache_inv(addr, size);
		break;

	case DMA_BIDIRECTIONAL:
		dma_cache_wback_inv(addr, size);
		dma_cache_wback((unsigned long)addr, size);
		break;

	case DMA_FROM_DEVICE:
		dma_cache_inv((unsigned long)addr, size);
		break;

	case DMA_BIDIRECTIONAL:
		dma_cache_wback_inv((unsigned long)addr, size);
		break;

	default:
		BUG();
	}
}

dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size,
	enum dma_data_direction direction)
{
	unsigned long addr = (unsigned long) ptr;

	if (!plat_device_is_coherent(dev))
		__dma_sync(addr, size, direction);

	return plat_map_dma_mem(dev, ptr, size);
}

EXPORT_SYMBOL(dma_map_single);

void dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
	enum dma_data_direction direction)
{
	if (cpu_is_noncoherent_r10000(dev))
		__dma_sync(dma_addr_to_virt(dma_addr), size,
		           direction);

	plat_unmap_dma_mem(dma_addr);
}

EXPORT_SYMBOL(dma_unmap_single);

int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
	enum dma_data_direction direction)
{
	int i;

	BUG_ON(direction == DMA_NONE);

	for (i = 0; i < nents; i++, sg++) {
		unsigned long addr;

		addr = (unsigned long) sg_virt(sg);
		if (!plat_device_is_coherent(dev) && addr)
			__dma_sync(addr, sg->length, direction);
		sg->dma_address = plat_map_dma_mem(dev,
				                   (void *)addr, sg->length);
/*
 * A single sg entry may refer to multiple physically contiguous
 * pages. But we still need to process highmem pages individually.
 * If highmem is not configured then the bulk of this loop gets
 * optimized out.
 */
static inline void __dma_sync(struct page *page,
	unsigned long offset, size_t size, enum dma_data_direction direction)
{
	size_t left = size;

	do {
		size_t len = left;

		if (PageHighMem(page)) {
			void *addr;

			if (offset + len > PAGE_SIZE) {
				if (offset >= PAGE_SIZE) {
					page += offset >> PAGE_SHIFT;
					offset &= ~PAGE_MASK;
				}
				len = PAGE_SIZE - offset;
			}

			addr = kmap_atomic(page);
			__dma_sync_virtual(addr + offset, len, direction);
			kunmap_atomic(addr);
		} else
			__dma_sync_virtual(page_address(page) + offset,
					   size, direction);
		offset = 0;
		page++;
		left -= len;
	} while (left);
}

static void mips_dma_unmap_page(struct device *dev, dma_addr_t dma_addr,
	size_t size, enum dma_data_direction direction, unsigned long attrs)
{
	if (cpu_needs_post_dma_flush(dev) && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		__dma_sync(dma_addr_to_page(dev, dma_addr),
			   dma_addr & ~PAGE_MASK, size, direction);
	plat_post_dma_flush(dev);
	plat_unmap_dma_mem(dev, dma_addr, size, direction);
}

static int mips_dma_map_sg(struct device *dev, struct scatterlist *sglist,
	int nents, enum dma_data_direction direction, unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sglist, sg, nents, i) {
		if (!plat_device_is_coherent(dev) &&
		    !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
			__dma_sync(sg_page(sg), sg->offset, sg->length,
				   direction);
#ifdef CONFIG_NEED_SG_DMA_LENGTH
		sg->dma_length = sg->length;
#endif
		sg->dma_address = plat_map_dma_mem_page(dev, sg_page(sg)) +
				  sg->offset;
	}

	return nents;
}

EXPORT_SYMBOL(dma_map_sg);

dma_addr_t dma_map_page(struct device *dev, struct page *page,
	unsigned long offset, size_t size, enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (!plat_device_is_coherent(dev)) {
		unsigned long addr;

		addr = (unsigned long) page_address(page) + offset;
		dma_cache_wback_inv(addr, size);
	}
static dma_addr_t mips_dma_map_page(struct device *dev, struct page *page,
	unsigned long offset, size_t size, enum dma_data_direction direction,
	unsigned long attrs)
{
	if (!plat_device_is_coherent(dev) && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		__dma_sync(page, offset, size, direction);

	return plat_map_dma_mem_page(dev, page) + offset;
}

EXPORT_SYMBOL(dma_map_page);

void dma_unmap_page(struct device *dev, dma_addr_t dma_address, size_t size,
	enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (!plat_device_is_coherent(dev) && direction != DMA_TO_DEVICE) {
		unsigned long addr;

		addr = plat_dma_addr_to_phys(dma_address);
		dma_cache_wback_inv(addr, size);
	}

	plat_unmap_dma_mem(dma_address);
}

EXPORT_SYMBOL(dma_unmap_page);

void dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nhwentries,
	enum dma_data_direction direction)
{
	unsigned long addr;
	int i;

	BUG_ON(direction == DMA_NONE);

	for (i = 0; i < nhwentries; i++, sg++) {
		if (!plat_device_is_coherent(dev) &&
		    direction != DMA_TO_DEVICE) {
			addr = (unsigned long) sg_virt(sg);
			if (addr)
				__dma_sync(addr, sg->length, direction);
		}
		plat_unmap_dma_mem(sg->dma_address);
	}
}

EXPORT_SYMBOL(dma_unmap_sg);

void dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
	size_t size, enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (cpu_is_noncoherent_r10000(dev)) {
		unsigned long addr;

		addr = dma_addr_to_virt(dma_handle);
		__dma_sync(addr, size, direction);
	}
}

EXPORT_SYMBOL(dma_sync_single_for_cpu);

void dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle,
	size_t size, enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (!plat_device_is_coherent(dev)) {
		unsigned long addr;

		addr = dma_addr_to_virt(dma_handle);
		__dma_sync(addr, size, direction);
	}
}

EXPORT_SYMBOL(dma_sync_single_for_device);

void dma_sync_single_range_for_cpu(struct device *dev, dma_addr_t dma_handle,
	unsigned long offset, size_t size, enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (cpu_is_noncoherent_r10000(dev)) {
		unsigned long addr;

		addr = dma_addr_to_virt(dma_handle);
		__dma_sync(addr + offset, size, direction);
	}
}

EXPORT_SYMBOL(dma_sync_single_range_for_cpu);

void dma_sync_single_range_for_device(struct device *dev, dma_addr_t dma_handle,
	unsigned long offset, size_t size, enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (!plat_device_is_coherent(dev)) {
		unsigned long addr;

		addr = dma_addr_to_virt(dma_handle);
		__dma_sync(addr + offset, size, direction);
	}
}

EXPORT_SYMBOL(dma_sync_single_range_for_device);

void dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg, int nelems,
	enum dma_data_direction direction)
{
	int i;

	BUG_ON(direction == DMA_NONE);

	/* Make sure that gcc doesn't leave the empty loop body.  */
	for (i = 0; i < nelems; i++, sg++) {
		if (cpu_is_noncoherent_r10000(dev))
			__dma_sync((unsigned long)page_address(sg_page(sg)),
			           sg->length, direction);
		plat_unmap_dma_mem(sg->dma_address);
	}
}

EXPORT_SYMBOL(dma_sync_sg_for_cpu);

void dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg, int nelems,
	enum dma_data_direction direction)
{
	int i;

	BUG_ON(direction == DMA_NONE);

	/* Make sure that gcc doesn't leave the empty loop body.  */
	for (i = 0; i < nelems; i++, sg++) {
		if (!plat_device_is_coherent(dev))
			__dma_sync((unsigned long)page_address(sg_page(sg)),
			           sg->length, direction);
		plat_unmap_dma_mem(sg->dma_address);
	}
}

EXPORT_SYMBOL(dma_sync_sg_for_device);

int dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
static void mips_dma_unmap_sg(struct device *dev, struct scatterlist *sglist,
	int nhwentries, enum dma_data_direction direction,
	unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sglist, sg, nhwentries, i) {
		if (!plat_device_is_coherent(dev) &&
		    !(attrs & DMA_ATTR_SKIP_CPU_SYNC) &&
		    direction != DMA_TO_DEVICE)
			__dma_sync(sg_page(sg), sg->offset, sg->length,
				   direction);
		plat_unmap_dma_mem(dev, sg->dma_address, sg->length, direction);
	}
}

static void mips_dma_sync_single_for_cpu(struct device *dev,
	dma_addr_t dma_handle, size_t size, enum dma_data_direction direction)
{
	if (cpu_needs_post_dma_flush(dev))
		__dma_sync(dma_addr_to_page(dev, dma_handle),
			   dma_handle & ~PAGE_MASK, size, direction);
	plat_post_dma_flush(dev);
}

static void mips_dma_sync_single_for_device(struct device *dev,
	dma_addr_t dma_handle, size_t size, enum dma_data_direction direction)
{
	if (!plat_device_is_coherent(dev))
		__dma_sync(dma_addr_to_page(dev, dma_handle),
			   dma_handle & ~PAGE_MASK, size, direction);
}

static void mips_dma_sync_sg_for_cpu(struct device *dev,
	struct scatterlist *sglist, int nelems,
	enum dma_data_direction direction)
{
	int i;
	struct scatterlist *sg;

	if (cpu_needs_post_dma_flush(dev)) {
		for_each_sg(sglist, sg, nelems, i) {
			__dma_sync(sg_page(sg), sg->offset, sg->length,
				   direction);
		}
	}
	plat_post_dma_flush(dev);
}

static void mips_dma_sync_sg_for_device(struct device *dev,
	struct scatterlist *sglist, int nelems,
	enum dma_data_direction direction)
{
	int i;
	struct scatterlist *sg;

	if (!plat_device_is_coherent(dev)) {
		for_each_sg(sglist, sg, nelems, i) {
			__dma_sync(sg_page(sg), sg->offset, sg->length,
				   direction);
		}
	}
}

static int mips_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	return 0;
}

EXPORT_SYMBOL(dma_mapping_error);

int dma_supported(struct device *dev, u64 mask)
{
	/*
	 * we fall back to GFP_DMA when the mask isn't all 1s,
	 * so we can't guarantee allocations that must be
	 * within a tighter range than GFP_DMA..
	 */
	if (mask < DMA_BIT_MASK(24))
		return 0;

	return 1;
}

EXPORT_SYMBOL(dma_supported);

int dma_is_consistent(struct device *dev, dma_addr_t dma_addr)
{
	return plat_device_is_coherent(dev);
}

EXPORT_SYMBOL(dma_is_consistent);

void dma_cache_sync(struct device *dev, void *vaddr, size_t size,
	       enum dma_data_direction direction)
int mips_dma_supported(struct device *dev, u64 mask)
static int mips_dma_supported(struct device *dev, u64 mask)
{
	return plat_dma_supported(dev, mask);
}

void dma_cache_sync(struct device *dev, void *vaddr, size_t size,
			 enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	if (!plat_device_is_coherent(dev))
		__dma_sync((unsigned long)vaddr, size, direction);
}

EXPORT_SYMBOL(dma_cache_sync);
		__dma_sync_virtual(vaddr, size, direction);
}

EXPORT_SYMBOL(dma_cache_sync);

static const struct dma_map_ops mips_default_dma_map_ops = {
	.alloc = mips_dma_alloc_coherent,
	.free = mips_dma_free_coherent,
	.mmap = mips_dma_mmap,
	.map_page = mips_dma_map_page,
	.unmap_page = mips_dma_unmap_page,
	.map_sg = mips_dma_map_sg,
	.unmap_sg = mips_dma_unmap_sg,
	.sync_single_for_cpu = mips_dma_sync_single_for_cpu,
	.sync_single_for_device = mips_dma_sync_single_for_device,
	.sync_sg_for_cpu = mips_dma_sync_sg_for_cpu,
	.sync_sg_for_device = mips_dma_sync_sg_for_device,
	.mapping_error = mips_dma_mapping_error,
	.dma_supported = mips_dma_supported
};

const struct dma_map_ops *mips_dma_map_ops = &mips_default_dma_map_ops;
EXPORT_SYMBOL(mips_dma_map_ops);

#define PREALLOC_DMA_DEBUG_ENTRIES (1 << 16)

static int __init mips_dma_init(void)
{
	dma_debug_init(PREALLOC_DMA_DEBUG_ENTRIES);

	return 0;
}
fs_initcall(mips_dma_init);
