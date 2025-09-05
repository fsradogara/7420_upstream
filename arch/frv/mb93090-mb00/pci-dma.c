/* pci-dma.c: Dynamic DMA mapping support for the FRV CPUs that have MMUs
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/export.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>
#include <asm/io.h>

static void *frv_dma_alloc(struct device *hwdev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
	void *ret;

	ret = consistent_alloc(gfp, size, dma_handle);
	if (ret)
		memset(ret, 0, size);

	return ret;
}

static void frv_dma_free(struct device *hwdev, size_t size, void *vaddr,
		dma_addr_t dma_handle, unsigned long attrs)
{
	consistent_free(vaddr);
}

EXPORT_SYMBOL(dma_free_coherent);

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.
 * The 32-bit bus address to use is returned.
 *
 * Once the device is given the dma address, the device owns this memory
 * until either pci_unmap_single or pci_dma_sync_single is performed.
 */
dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size,
			  enum dma_data_direction direction)
{
	if (direction == DMA_NONE)
                BUG();
dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size,
			  enum dma_data_direction direction)
{
	BUG_ON(direction == DMA_NONE);

	frv_cache_wback_inv((unsigned long) ptr, (unsigned long) ptr + size);

	return virt_to_bus(ptr);
}

EXPORT_SYMBOL(dma_map_single);

/*
 * Map a set of buffers described by scatterlist in streaming
 * mode for DMA.  This is the scather-gather version of the
 * above pci_map_single interface.  Here the scatter gather list
 * elements are each tagged with the appropriate dma address
 * and length.  They are obtained via sg_dma_{address,length}(SG).
 *
 * NOTE: An implementation may be able to use a smaller number of
 *       DMA address/length pairs than there are SG table elements.
 *       (for example via virtual mapping capabilities)
 *       The routine returns the number of addr/length pairs actually
 *       used, at most nents.
 *
 * Device ownership issues as mentioned above for pci_map_single are
 * the same here.
 */
int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
int dma_map_sg(struct device *dev, struct scatterlist *sglist, int nents,
	       enum dma_data_direction direction)
static int frv_dma_map_sg(struct device *dev, struct scatterlist *sglist,
		int nents, enum dma_data_direction direction,
		unsigned long attrs)
{
	struct scatterlist *sg;
	unsigned long dampr2;
	void *vaddr;
	int i;

	if (direction == DMA_NONE)
                BUG();

	dampr2 = __get_DAMPR(2);

	for (i = 0; i < nents; i++) {
		vaddr = kmap_atomic(sg_page(&sg[i]), __KM_CACHE);
	struct scatterlist *sg;

	BUG_ON(direction == DMA_NONE);

	if (attrs & DMA_ATTR_SKIP_CPU_SYNC)
		return nents;

	dampr2 = __get_DAMPR(2);

	for_each_sg(sglist, sg, nents, i) {
		vaddr = kmap_atomic_primary(sg_page(sg));

		frv_dcache_writeback((unsigned long) vaddr,
				     (unsigned long) vaddr + PAGE_SIZE);

	}

	kunmap_atomic(vaddr, __KM_CACHE);
	kunmap_atomic_primary(vaddr);
	if (dampr2) {
		__set_DAMPR(2, dampr2);
		__set_IAMPR(2, dampr2);
	}

	return nents;
}

static dma_addr_t frv_dma_map_page(struct device *dev, struct page *page,
		unsigned long offset, size_t size,
		enum dma_data_direction direction, unsigned long attrs)
{
	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		flush_dcache_page(page);

	return (dma_addr_t) page_to_phys(page) + offset;
}

static void frv_dma_sync_single_for_device(struct device *dev,
		dma_addr_t dma_handle, size_t size,
		enum dma_data_direction direction)
{
	flush_write_buffers();
}

static void frv_dma_sync_sg_for_device(struct device *dev,
		struct scatterlist *sg, int nelems,
		enum dma_data_direction direction)
{
	flush_write_buffers();
}


static int frv_dma_supported(struct device *dev, u64 mask)
{
        /*
         * we fall back to GFP_DMA when the mask isn't all 1s,
         * so we can't guarantee allocations that must be
         * within a tighter range than GFP_DMA..
         */
        if (mask < 0x00ffffff)
                return 0;
	return 1;
}

const struct dma_map_ops frv_dma_ops = {
	.alloc			= frv_dma_alloc,
	.free			= frv_dma_free,
	.map_page		= frv_dma_map_page,
	.map_sg			= frv_dma_map_sg,
	.sync_single_for_device	= frv_dma_sync_single_for_device,
	.sync_sg_for_device	= frv_dma_sync_sg_for_device,
	.dma_supported		= frv_dma_supported,
};
EXPORT_SYMBOL(frv_dma_ops);
