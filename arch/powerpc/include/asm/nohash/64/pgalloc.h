#ifndef _ASM_POWERPC_PGALLOC_64_H
#define _ASM_POWERPC_PGALLOC_64_H
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>

#ifndef CONFIG_PPC_SUBPAGE_PROT
static inline void subpage_prot_free(pgd_t *pgd) {}
#endif

extern struct kmem_cache *pgtable_cache[];

#define PGD_CACHE_NUM		0
#define PUD_CACHE_NUM		1
#define PMD_CACHE_NUM		1
#define HUGEPTE_CACHE_NUM	2
#define PTE_NONCACHE_NUM	7  /* from GFP rather than kmem_cache */

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	return kmem_cache_alloc(pgtable_cache[PGD_CACHE_NUM], GFP_KERNEL);
struct vmemmap_backing {
	struct vmemmap_backing *list;
	unsigned long phys;
	unsigned long virt_addr;
};
extern struct vmemmap_backing *vmemmap_list;

/*
 * Functions that deal with pagetables that could be at any level of
 * the table need to be passed an "index_size" so they know how to
 * handle allocation.  For PTE pages (which are linked to a struct
 * page for now, and drawn from the main get_free_pages() pool), the
 * allocation size will be (2^index_size * sizeof(pointer)) and
 * allocations are drawn from the kmem_cache in PGT_CACHE(index_size).
 *
 * The maximum index size needs to be big enough to allow any
 * pagetable sizes we need, but small enough to fit in the low bits of
 * any page table pointer.  In other words all pagetables, even tiny
 * ones, must be aligned to allow at least enough low 0 bits to
 * contain this value.  This value is also used as a mask, so it must
 * be one less than a power of two.
 */
#define MAX_PGTABLE_INDEX_SIZE	0xf

extern struct kmem_cache *pgtable_cache[];
#define PGT_CACHE(shift) ({				\
			BUG_ON(!(shift));		\
			pgtable_cache[(shift) - 1];	\
		})

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	return kmem_cache_alloc(PGT_CACHE(PGD_INDEX_SIZE),
			pgtable_gfp_flags(mm, GFP_KERNEL));
}

static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	subpage_prot_free(pgd);
	kmem_cache_free(pgtable_cache[PGD_CACHE_NUM], pgd);
	kmem_cache_free(PGT_CACHE(PGD_INDEX_SIZE), pgd);
}

#define pgd_populate(MM, PGD, PUD)	pgd_set(PGD, (unsigned long)PUD)

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(pgtable_cache[PUD_CACHE_NUM],
	return kmem_cache_alloc(PGT_CACHE(PUD_INDEX_SIZE),
			pgtable_gfp_flags(mm, GFP_KERNEL));
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	kmem_cache_free(pgtable_cache[PUD_CACHE_NUM], pud);
	kmem_cache_free(PGT_CACHE(PUD_INDEX_SIZE), pud);
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set(pud, (unsigned long)pmd);
}

static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
				       pte_t *pte)
{
	pmd_set(pmd, (unsigned long)pte);
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
				pgtable_t pte_page)
{
	pmd_set(pmd, (unsigned long)page_address(pte_page));
}

#define pmd_pgtable(pmd) pmd_page(pmd)


#else /* CONFIG_PPC_64K_PAGES */

#define pud_populate(mm, pud, pmd)	pud_set(pud, (unsigned long)pmd)

static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
				       pte_t *pte)
{
	pmd_set(pmd, (unsigned long)pte);
}

#define pmd_populate(mm, pmd, pte_page) \
	pmd_populate_kernel(mm, pmd, page_address(pte_page))
#define pmd_pgtable(pmd) pmd_page(pmd)

#endif /* CONFIG_PPC_64K_PAGES */

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(pgtable_cache[PMD_CACHE_NUM],
				GFP_KERNEL|__GFP_REPEAT);
static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(PGT_CACHE(PMD_CACHE_INDEX),
			pgtable_gfp_flags(mm, GFP_KERNEL));
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	kmem_cache_free(pgtable_cache[PMD_CACHE_NUM], pmd);
}

static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm,
					  unsigned long address)
{
        return (pte_t *)__get_free_page(GFP_KERNEL | __GFP_REPEAT | __GFP_ZERO);
}

static inline pgtable_t pte_alloc_one(struct mm_struct *mm,
					unsigned long address)
	kmem_cache_free(PGT_CACHE(PMD_CACHE_INDEX), pmd);
}


static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm,
					  unsigned long address)
{
	return (pte_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
}

static inline pgtable_t pte_alloc_one(struct mm_struct *mm,
				      unsigned long address)
{
	struct page *page;
	pte_t *pte;

	pte = (pte_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO | __GFP_ACCOUNT);
	if (!pte)
		return NULL;
	page = virt_to_page(pte);
	pgtable_page_ctor(page);
	if (!pgtable_page_ctor(page)) {
		__free_page(page);
		return NULL;
	}
	return page;
}

static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	free_page((unsigned long)pte);
}

static inline void pte_free(struct mm_struct *mm, pgtable_t ptepage)
{
	pgtable_page_dtor(ptepage);
	__free_page(ptepage);
}

#define PGF_CACHENUM_MASK	0x7

typedef struct pgtable_free {
	unsigned long val;
} pgtable_free_t;

static inline pgtable_free_t pgtable_free_cache(void *p, int cachenum,
						unsigned long mask)
{
	BUG_ON(cachenum > PGF_CACHENUM_MASK);

	return (pgtable_free_t){.val = ((unsigned long) p & ~mask) | cachenum};
}

static inline void pgtable_free(pgtable_free_t pgf)
{
	void *p = (void *)(pgf.val & ~PGF_CACHENUM_MASK);
	int cachenum = pgf.val & PGF_CACHENUM_MASK;

	if (cachenum == PTE_NONCACHE_NUM)
		free_page((unsigned long)p);
	else
		kmem_cache_free(pgtable_cache[cachenum], p);
}

extern void pgtable_free_tlb(struct mmu_gather *tlb, pgtable_free_t pgf);

#define __pte_free_tlb(tlb,ptepage)	\
do { \
	pgtable_page_dtor(ptepage); \
	pgtable_free_tlb(tlb, pgtable_free_cache(page_address(ptepage), \
		PTE_NONCACHE_NUM, PTE_TABLE_SIZE-1)); \
} while (0)
#define __pmd_free_tlb(tlb, pmd) 	\
	pgtable_free_tlb(tlb, pgtable_free_cache(pmd, \
		PMD_CACHE_NUM, PMD_TABLE_SIZE-1))
#ifndef CONFIG_PPC_64K_PAGES
#define __pud_free_tlb(tlb, pud)	\
	pgtable_free_tlb(tlb, pgtable_free_cache(pud, \
		PUD_CACHE_NUM, PUD_TABLE_SIZE-1))
static inline void pgtable_free(void *table, unsigned index_size)
{
	if (!index_size)
		free_page((unsigned long)table);
	else {
		BUG_ON(index_size > MAX_PGTABLE_INDEX_SIZE);
		kmem_cache_free(PGT_CACHE(index_size), table);
	}
}

extern void pgtable_free_tlb(struct mmu_gather *tlb, void *table, int shift);
static inline void pgtable_free(void *table, int shift)
{
	if (!shift) {
		pgtable_page_dtor(virt_to_page(table));
		free_page((unsigned long)table);
	} else {
		BUG_ON(shift > MAX_PGTABLE_INDEX_SIZE);
		kmem_cache_free(PGT_CACHE(shift), table);
	}
}

#define get_hugepd_cache_index(x)	(x)
#ifdef CONFIG_SMP
static inline void pgtable_free_tlb(struct mmu_gather *tlb, void *table, int shift)
{
	unsigned long pgf = (unsigned long)table;

	BUG_ON(shift > MAX_PGTABLE_INDEX_SIZE);
	pgf |= shift;
	tlb_remove_table(tlb, (void *)pgf);
}

static inline void __tlb_remove_table(void *_table)
{
	void *table = (void *)((unsigned long)_table & ~MAX_PGTABLE_INDEX_SIZE);
	unsigned shift = (unsigned long)_table & MAX_PGTABLE_INDEX_SIZE;

	pgtable_free(table, shift);
}

#else
static inline void pgtable_free_tlb(struct mmu_gather *tlb, void *table, int shift)
{
	pgtable_free(table, shift);
}
#endif

static inline void __pte_free_tlb(struct mmu_gather *tlb, pgtable_t table,
				  unsigned long address)
{
	tlb_flush_pgtable(tlb, address);
	pgtable_free_tlb(tlb, page_address(table), 0);
}

#define __pmd_free_tlb(tlb, pmd, addr)		      \
	pgtable_free_tlb(tlb, pmd, PMD_CACHE_INDEX)
#ifndef CONFIG_PPC_64K_PAGES
#define __pud_free_tlb(tlb, pud, addr)		      \
	pgtable_free_tlb(tlb, pud, PUD_INDEX_SIZE)

#endif /* CONFIG_PPC_64K_PAGES */

#define check_pgt_cache()	do { } while (0)

#endif /* _ASM_POWERPC_PGALLOC_64_H */
