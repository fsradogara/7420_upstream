// SPDX-License-Identifier: GPL-2.0
/*
 *  arch/s390/mm/vmem.c
 *
 *    Copyright IBM Corp. 2006
 *    Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 */

#include <linux/bootmem.h>
#include <linux/pfn.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <asm/cacheflush.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/set_memory.h>

static DEFINE_MUTEX(vmem_mutex);

struct memory_segment {
	struct list_head list;
	unsigned long start;
	unsigned long size;
};

static LIST_HEAD(mem_segs);

static void __ref *vmem_alloc_pages(unsigned int order)
{
	unsigned long size = PAGE_SIZE << order;

	if (slab_is_available())
		return (void *)__get_free_pages(GFP_KERNEL, order);
	return (void *) memblock_alloc(size, size);
}

void *vmem_crst_alloc(unsigned long val)
{
	unsigned long *table;

#ifdef CONFIG_64BIT
	pud = vmem_alloc_pages(2);
	if (!pud)
		return NULL;
	clear_table((unsigned long *) pud, _REGION3_ENTRY_EMPTY, PAGE_SIZE * 4);
#endif
	return pud;
}

static inline pmd_t *vmem_pmd_alloc(void)
{
	pmd_t *pmd = NULL;

#ifdef CONFIG_64BIT
	pmd = vmem_alloc_pages(2);
	if (!pmd)
		return NULL;
	clear_table((unsigned long *) pmd, _SEGMENT_ENTRY_EMPTY, PAGE_SIZE * 4);
#endif
	return pmd;
}

static pte_t __ref *vmem_pte_alloc(void)
	return pmd;
}

static pte_t __ref *vmem_pte_alloc(unsigned long address)
	table = vmem_alloc_pages(CRST_ALLOC_ORDER);
	if (table)
		crst_table_init(table, val);
	return table;
}

pte_t __ref *vmem_pte_alloc(void)
{
	unsigned long size = PTRS_PER_PTE * sizeof(pte_t);
	pte_t *pte;

	if (slab_is_available())
		pte = (pte_t *) page_table_alloc(&init_mm);
	else
		pte = alloc_bootmem(PTRS_PER_PTE * sizeof(pte_t));
	if (!pte)
		return NULL;
	clear_table((unsigned long *) pte, _PAGE_TYPE_EMPTY,
		pte = alloc_bootmem_align(PTRS_PER_PTE * sizeof(pte_t),
					  PTRS_PER_PTE * sizeof(pte_t));
		pte = (pte_t *) memblock_alloc(size, size);
	if (!pte)
		return NULL;
	clear_table((unsigned long *) pte, _PAGE_INVALID, size);
	return pte;
}

/*
 * Add a physical memory range to the 1:1 mapping.
 */
static int vmem_add_mem(unsigned long start, unsigned long size)
{
	unsigned long address;
	unsigned long pgt_prot, sgt_prot, r3_prot;
	unsigned long pages4k, pages1m, pages2g;
	unsigned long end = start + size;
	unsigned long address = start;
	pgd_t *pg_dir;
	p4d_t *p4_dir;
	pud_t *pu_dir;
	pmd_t *pm_dir;
	pte_t *pt_dir;
	pte_t  pte;
	int ret = -ENOMEM;

	for (address = start; address < start + size; address += PAGE_SIZE) {
	int ret = -ENOMEM;

	pgt_prot = pgprot_val(PAGE_KERNEL);
	sgt_prot = pgprot_val(SEGMENT_KERNEL);
	r3_prot = pgprot_val(REGION3_KERNEL);
	if (!MACHINE_HAS_NX) {
		pgt_prot &= ~_PAGE_NOEXEC;
		sgt_prot &= ~_SEGMENT_ENTRY_NOEXEC;
		r3_prot &= ~_REGION_ENTRY_NOEXEC;
	}
	pages4k = pages1m = pages2g = 0;
	while (address < end) {
		pg_dir = pgd_offset_k(address);
		if (pgd_none(*pg_dir)) {
			p4_dir = vmem_crst_alloc(_REGION2_ENTRY_EMPTY);
			if (!p4_dir)
				goto out;
			pgd_populate(&init_mm, pg_dir, p4_dir);
		}
		p4_dir = p4d_offset(pg_dir, address);
		if (p4d_none(*p4_dir)) {
			pu_dir = vmem_crst_alloc(_REGION3_ENTRY_EMPTY);
			if (!pu_dir)
				goto out;
			pgd_populate_kernel(&init_mm, pg_dir, pu_dir);
		}

		pu_dir = pud_offset(pg_dir, address);
			pgd_populate(&init_mm, pg_dir, pu_dir);
			p4d_populate(&init_mm, p4_dir, pu_dir);
		}
		pu_dir = pud_offset(p4_dir, address);
		if (MACHINE_HAS_EDAT2 && pud_none(*pu_dir) && address &&
		    !(address & ~PUD_MASK) && (address + PUD_SIZE <= end) &&
		     !debug_pagealloc_enabled()) {
			pud_val(*pu_dir) = address | r3_prot;
			address += PUD_SIZE;
			pages2g++;
			continue;
		}
		if (pud_none(*pu_dir)) {
			pm_dir = vmem_crst_alloc(_SEGMENT_ENTRY_EMPTY);
			if (!pm_dir)
				goto out;
			pud_populate_kernel(&init_mm, pu_dir, pm_dir);
		}

		pte = mk_pte_phys(address, __pgprot(ro ? _PAGE_RO : 0));
		pm_dir = pmd_offset(pu_dir, address);

#ifdef __s390x__
		if (MACHINE_HAS_HPAGE && !(address & ~HPAGE_MASK) &&
		    (address + HPAGE_SIZE <= start + size) &&
		    (address >= HPAGE_SIZE)) {
			pte_val(pte) |= _SEGMENT_ENTRY_LARGE;
			pmd_val(*pm_dir) = pte_val(pte);
			address += HPAGE_SIZE - PAGE_SIZE;
			pud_populate(&init_mm, pu_dir, pm_dir);
		}
		pm_dir = pmd_offset(pu_dir, address);
		if (MACHINE_HAS_EDAT1 && pmd_none(*pm_dir) && address &&
		    !(address & ~PMD_MASK) && (address + PMD_SIZE <= end) &&
		    !debug_pagealloc_enabled()) {
			pmd_val(*pm_dir) = address | sgt_prot;
			address += PMD_SIZE;
			pages1m++;
			continue;
		}
		if (pmd_none(*pm_dir)) {
			pt_dir = vmem_pte_alloc();
			if (!pt_dir)
				goto out;
			pmd_populate_kernel(&init_mm, pm_dir, pt_dir);
		}

		pt_dir = pte_offset_kernel(pm_dir, address);
		*pt_dir = pte;
	}
	ret = 0;
out:
	flush_tlb_kernel_range(start, start + size);
			pt_dir = vmem_pte_alloc(address);
			if (!pt_dir)
				goto out;
			pmd_populate(&init_mm, pm_dir, pt_dir);
		}

		pt_dir = pte_offset_kernel(pm_dir, address);
		pte_val(*pt_dir) = address | pgt_prot;
		address += PAGE_SIZE;
		pages4k++;
	}
	ret = 0;
out:
	update_page_count(PG_DIRECT_MAP_4K, pages4k);
	update_page_count(PG_DIRECT_MAP_1M, pages1m);
	update_page_count(PG_DIRECT_MAP_2G, pages2g);
	return ret;
}

/*
 * Remove a physical memory range from the 1:1 mapping.
 * Currently only invalidates page table entries.
 */
static void vmem_remove_range(unsigned long start, unsigned long size)
{
	unsigned long address;
	unsigned long pages4k, pages1m, pages2g;
	unsigned long end = start + size;
	unsigned long address = start;
	pgd_t *pg_dir;
	p4d_t *p4_dir;
	pud_t *pu_dir;
	pmd_t *pm_dir;
	pte_t *pt_dir;

	pte_val(pte) = _PAGE_TYPE_EMPTY;
	for (address = start; address < start + size; address += PAGE_SIZE) {
		pg_dir = pgd_offset_k(address);
		pu_dir = pud_offset(pg_dir, address);
		if (pud_none(*pu_dir))
			continue;
		pm_dir = pmd_offset(pu_dir, address);
		if (pmd_none(*pm_dir))
			continue;

		if (pmd_huge(*pm_dir)) {
			pmd_clear_kernel(pm_dir);
			address += HPAGE_SIZE - PAGE_SIZE;
			continue;
		}

		pt_dir = pte_offset_kernel(pm_dir, address);
		*pt_dir = pte;
	}
	flush_tlb_kernel_range(start, start + size);
	pte_val(pte) = _PAGE_INVALID;
	pages4k = pages1m = pages2g = 0;
	while (address < end) {
		pg_dir = pgd_offset_k(address);
		if (pgd_none(*pg_dir)) {
			address += PGDIR_SIZE;
			continue;
		}
		p4_dir = p4d_offset(pg_dir, address);
		if (p4d_none(*p4_dir)) {
			address += P4D_SIZE;
			continue;
		}
		pu_dir = pud_offset(p4_dir, address);
		if (pud_none(*pu_dir)) {
			address += PUD_SIZE;
			continue;
		}
		if (pud_large(*pu_dir)) {
			pud_clear(pu_dir);
			address += PUD_SIZE;
			pages2g++;
			continue;
		}
		pm_dir = pmd_offset(pu_dir, address);
		if (pmd_none(*pm_dir)) {
			address += PMD_SIZE;
			continue;
		}
		if (pmd_large(*pm_dir)) {
			pmd_clear(pm_dir);
			address += PMD_SIZE;
			pages1m++;
			continue;
		}
		pt_dir = pte_offset_kernel(pm_dir, address);
		pte_clear(&init_mm, address, pt_dir);
		address += PAGE_SIZE;
		pages4k++;
	}
	flush_tlb_kernel_range(start, end);
	update_page_count(PG_DIRECT_MAP_4K, -pages4k);
	update_page_count(PG_DIRECT_MAP_1M, -pages1m);
	update_page_count(PG_DIRECT_MAP_2G, -pages2g);
}

/*
 * Add a backed mem_map array to the virtual mem_map array.
 */
int __meminit vmemmap_populate(struct page *start, unsigned long nr, int node)
{
	unsigned long address, start_addr, end_addr;
int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node)
{
	unsigned long pgt_prot, sgt_prot;
	unsigned long address = start;
	pgd_t *pg_dir;
	p4d_t *p4_dir;
	pud_t *pu_dir;
	pmd_t *pm_dir;
	pte_t *pt_dir;
	pte_t  pte;
	int ret = -ENOMEM;

	start_addr = (unsigned long) start;
	end_addr = (unsigned long) (start + nr);

	for (address = start_addr; address < end_addr; address += PAGE_SIZE) {
	int ret = -ENOMEM;

	pgt_prot = pgprot_val(PAGE_KERNEL);
	sgt_prot = pgprot_val(SEGMENT_KERNEL);
	if (!MACHINE_HAS_NX) {
		pgt_prot &= ~_PAGE_NOEXEC;
		sgt_prot &= ~_SEGMENT_ENTRY_NOEXEC;
	}
	for (address = start; address < end;) {
		pg_dir = pgd_offset_k(address);
		if (pgd_none(*pg_dir)) {
			p4_dir = vmem_crst_alloc(_REGION2_ENTRY_EMPTY);
			if (!p4_dir)
				goto out;
			pgd_populate_kernel(&init_mm, pg_dir, pu_dir);
			pgd_populate(&init_mm, pg_dir, pu_dir);
			pgd_populate(&init_mm, pg_dir, p4_dir);
		}

		p4_dir = p4d_offset(pg_dir, address);
		if (p4d_none(*p4_dir)) {
			pu_dir = vmem_crst_alloc(_REGION3_ENTRY_EMPTY);
			if (!pu_dir)
				goto out;
			p4d_populate(&init_mm, p4_dir, pu_dir);
		}

		pu_dir = pud_offset(p4_dir, address);
		if (pud_none(*pu_dir)) {
			pm_dir = vmem_crst_alloc(_SEGMENT_ENTRY_EMPTY);
			if (!pm_dir)
				goto out;
			pud_populate_kernel(&init_mm, pu_dir, pm_dir);
			pud_populate(&init_mm, pu_dir, pm_dir);
		}

		pm_dir = pmd_offset(pu_dir, address);
		if (pmd_none(*pm_dir)) {
			pt_dir = vmem_pte_alloc();
			if (!pt_dir)
				goto out;
			pmd_populate_kernel(&init_mm, pm_dir, pt_dir);
			/* Use 1MB frames for vmemmap if available. We always
			 * use large frames even if they are only partially
			 * used.
			 * Otherwise we would have also page tables since
			 * vmemmap_populate gets called for each section
			 * separately. */
			if (MACHINE_HAS_EDAT1) {
				void *new_page;

				new_page = vmemmap_alloc_block(PMD_SIZE, node);
				if (!new_page)
					goto out;
				pmd_val(*pm_dir) = __pa(new_page) | sgt_prot;
				address = (address + PMD_SIZE) & PMD_MASK;
				continue;
			}
			pt_dir = vmem_pte_alloc();
			if (!pt_dir)
				goto out;
			pmd_populate(&init_mm, pm_dir, pt_dir);
		} else if (pmd_large(*pm_dir)) {
			address = (address + PMD_SIZE) & PMD_MASK;
			continue;
		}

		pt_dir = pte_offset_kernel(pm_dir, address);
		if (pte_none(*pt_dir)) {
			unsigned long new_page;

			new_page =__pa(vmem_alloc_pages(0));
			if (!new_page)
				goto out;
			pte = pfn_pte(new_page >> PAGE_SHIFT, PAGE_KERNEL);
			*pt_dir = pte;
		}
	}
	memset(start, 0, nr * sizeof(struct page));
	ret = 0;
out:
	flush_tlb_kernel_range(start_addr, end_addr);
	return ret;
}

			void *new_page;

			new_page = vmemmap_alloc_block(PAGE_SIZE, node);
			if (!new_page)
				goto out;
			pte_val(*pt_dir) = __pa(new_page) | pgt_prot;
		}
		address += PAGE_SIZE;
	}
	ret = 0;
out:
	return ret;
}

void vmemmap_free(unsigned long start, unsigned long end)
{
}

/*
 * Add memory segment to the segment list if it doesn't overlap with
 * an already present segment.
 */
static int insert_memory_segment(struct memory_segment *seg)
{
	struct memory_segment *tmp;

	if (seg->start + seg->size > VMEM_MAX_PHYS ||
	    seg->start + seg->size < seg->start)
		return -ERANGE;

	list_for_each_entry(tmp, &mem_segs, list) {
		if (seg->start >= tmp->start + tmp->size)
			continue;
		if (seg->start + seg->size <= tmp->start)
			continue;
		return -ENOSPC;
	}
	list_add(&seg->list, &mem_segs);
	return 0;
}

/*
 * Remove memory segment from the segment list.
 */
static void remove_memory_segment(struct memory_segment *seg)
{
	list_del(&seg->list);
}

static void __remove_shared_memory(struct memory_segment *seg)
{
	remove_memory_segment(seg);
	vmem_remove_range(seg->start, seg->size);
}

int vmem_remove_mapping(unsigned long start, unsigned long size)
{
	struct memory_segment *seg;
	int ret;

	mutex_lock(&vmem_mutex);

	ret = -ENOENT;
	list_for_each_entry(seg, &mem_segs, list) {
		if (seg->start == start && seg->size == size)
			break;
	}

	if (seg->start != start || seg->size != size)
		goto out;

	ret = 0;
	__remove_shared_memory(seg);
	kfree(seg);
out:
	mutex_unlock(&vmem_mutex);
	return ret;
}

int vmem_add_mapping(unsigned long start, unsigned long size)
{
	struct memory_segment *seg;
	int ret;

	mutex_lock(&vmem_mutex);
	ret = -ENOMEM;
	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		goto out;
	seg->start = start;
	seg->size = size;

	ret = insert_memory_segment(seg);
	if (ret)
		goto out_free;

	ret = vmem_add_mem(start, size);
	if (ret)
		goto out_remove;
	goto out;

out_remove:
	__remove_shared_memory(seg);
out_free:
	kfree(seg);
out:
	mutex_unlock(&vmem_mutex);
	return ret;
}

/*
 * map whole physical memory to virtual memory (identity mapping)
 * we reserve enough space in the vmalloc area for vmemmap to hotplug
 * additional memory segments.
 */
void __init vmem_map_init(void)
{
	unsigned long ro_start, ro_end;
	unsigned long start, end;
	int i;

	INIT_LIST_HEAD(&init_mm.context.crst_list);
	INIT_LIST_HEAD(&init_mm.context.pgtable_list);
	init_mm.context.noexec = 0;
	ro_start = ((unsigned long)&_stext) & PAGE_MASK;
	ro_end = PFN_ALIGN((unsigned long)&_eshared);
	for (i = 0; i < MEMORY_CHUNKS && memory_chunk[i].size > 0; i++) {
		start = memory_chunk[i].addr;
		end = memory_chunk[i].addr + memory_chunk[i].size;
	struct memblock_region *reg;

	for_each_memblock(memory, reg)
		vmem_add_mem(reg->base, reg->size);
	__set_memory((unsigned long) _stext,
		     (_etext - _stext) >> PAGE_SHIFT,
		     SET_MEMORY_RO | SET_MEMORY_X);
	__set_memory((unsigned long) _etext,
		     (_eshared - _etext) >> PAGE_SHIFT,
		     SET_MEMORY_RO);
	__set_memory((unsigned long) _sinittext,
		     (_einittext - _sinittext) >> PAGE_SHIFT,
		     SET_MEMORY_RO | SET_MEMORY_X);
	pr_info("Write protected kernel read-only data: %luk\n",
		(_eshared - _stext) >> 10);
}

/*
 * Convert memory chunk array to a memory segment list so there is a single
 * list that contains both r/w memory and shared memory segments.
 */
static int __init vmem_convert_memory_chunk(void)
{
	struct memory_segment *seg;
	int i;

	mutex_lock(&vmem_mutex);
	for (i = 0; i < MEMORY_CHUNKS; i++) {
		if (!memory_chunk[i].size)
			continue;
		seg = kzalloc(sizeof(*seg), GFP_KERNEL);
		if (!seg)
			panic("Out of memory...\n");
		seg->start = memory_chunk[i].addr;
		seg->size = memory_chunk[i].size;
 * Convert memblock.memory  to a memory segment list so there is a single
 * list that contains all memory segments.
 */
static int __init vmem_convert_memory_chunk(void)
{
	struct memblock_region *reg;
	struct memory_segment *seg;

	mutex_lock(&vmem_mutex);
	for_each_memblock(memory, reg) {
		seg = kzalloc(sizeof(*seg), GFP_KERNEL);
		if (!seg)
			panic("Out of memory...\n");
		seg->start = reg->base;
		seg->size = reg->size;
		insert_memory_segment(seg);
	}
	mutex_unlock(&vmem_mutex);
	return 0;
}

core_initcall(vmem_convert_memory_chunk);
