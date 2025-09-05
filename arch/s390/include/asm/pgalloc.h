/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/asm-s390/pgalloc.h
 *
 *  S390 version
 *    Copyright (C) 1999,2000 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *  S390 version
 *    Copyright IBM Corp. 1999, 2000
 *    Author(s): Hartmut Penner (hp@de.ibm.com)
 *               Martin Schwidefsky (schwidefsky@de.ibm.com)
 *
 *  Derived from "include/asm-i386/pgalloc.h"
 *    Copyright (C) 1994  Linus Torvalds
 */

#ifndef _S390_PGALLOC_H
#define _S390_PGALLOC_H

#include <linux/threads.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#define check_pgt_cache()	do {} while (0)

unsigned long *crst_table_alloc(struct mm_struct *, int);
#define CRST_ALLOC_ORDER 2

unsigned long *crst_table_alloc(struct mm_struct *);
void crst_table_free(struct mm_struct *, unsigned long *);

unsigned long *page_table_alloc(struct mm_struct *);
struct page *page_table_alloc_pgste(struct mm_struct *mm);
void page_table_free(struct mm_struct *, unsigned long *);
void disable_noexec(struct mm_struct *, struct task_struct *);

static inline void clear_table(unsigned long *s, unsigned long val, size_t n)
{
	*s = val;
	n = (n / 256) - 1;
	asm volatile(
#ifdef CONFIG_64BIT
		"	mvc	8(248,%0),0(%0)\n"
#else
		"	mvc	4(252,%0),0(%0)\n"
#endif
		"0:	mvc	256(256,%0),0(%0)\n"
		"	la	%0,256(%0)\n"
		"	brct	%1,0b\n"
		: "+a" (s), "+d" (n));
void page_table_free_rcu(struct mmu_gather *, unsigned long *, unsigned long);
void page_table_free_pgste(struct page *page);
extern int page_table_allocate_pgste;

static inline void crst_table_init(unsigned long *crst, unsigned long entry)
{
	clear_table(crst, entry, sizeof(unsigned long)*2048);
	crst = get_shadow_table(crst);
	if (crst)
		clear_table(crst, entry, sizeof(unsigned long)*2048);
}

#ifndef __s390x__

static inline unsigned long pgd_entry_type(struct mm_struct *mm)
{
	return _SEGMENT_ENTRY_EMPTY;
}

#define pud_alloc_one(mm,address)		({ BUG(); ((pud_t *)2); })
#define pud_free(mm, x)				do { } while (0)

#define pmd_alloc_one(mm,address)		({ BUG(); ((pmd_t *)2); })
#define pmd_free(mm, x)				do { } while (0)

#define pgd_populate(mm, pgd, pud)		BUG()
#define pgd_populate_kernel(mm, pgd, pud)	BUG()

#define pud_populate(mm, pud, pmd)		BUG()
#define pud_populate_kernel(mm, pud, pmd)	BUG()

#else /* __s390x__ */

	clear_table(crst, entry, _CRST_TABLE_SIZE);
	memset64((u64 *)crst, entry, _CRST_ENTRIES);
}

static inline unsigned long pgd_entry_type(struct mm_struct *mm)
{
	if (mm_pmd_folded(mm))
		return _SEGMENT_ENTRY_EMPTY;
	if (mm_pud_folded(mm))
		return _REGION3_ENTRY_EMPTY;
	if (mm_p4d_folded(mm))
		return _REGION2_ENTRY_EMPTY;
	return _REGION1_ENTRY_EMPTY;
}

int crst_table_upgrade(struct mm_struct *mm, unsigned long limit);
void crst_table_downgrade(struct mm_struct *);

static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long address)
{
	unsigned long *table = crst_table_alloc(mm);

	if (table)
		crst_table_init(table, _REGION2_ENTRY_EMPTY);
	return (p4d_t *) table;
}
#define p4d_free(mm, p4d) crst_table_free(mm, (unsigned long *) p4d)

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long address)
{
	unsigned long *table = crst_table_alloc(mm, mm->context.noexec);
	unsigned long *table = crst_table_alloc(mm);
	if (table)
		crst_table_init(table, _REGION3_ENTRY_EMPTY);
	return (pud_t *) table;
}
#define pud_free(mm, pud) crst_table_free(mm, (unsigned long *) pud)

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long vmaddr)
{
	unsigned long *table = crst_table_alloc(mm, mm->context.noexec);
	if (table)
		crst_table_init(table, _SEGMENT_ENTRY_EMPTY);
	return (pmd_t *) table;
}
#define pmd_free(mm, pmd) crst_table_free(mm, (unsigned long *) pmd)

static inline void pgd_populate_kernel(struct mm_struct *mm,
				       pgd_t *pgd, pud_t *pud)
{
	pgd_val(*pgd) = _REGION2_ENTRY | __pa(pud);
	unsigned long *table = crst_table_alloc(mm);

	if (!table)
		return NULL;
	crst_table_init(table, _SEGMENT_ENTRY_EMPTY);
	if (!pgtable_pmd_page_ctor(virt_to_page(table))) {
		crst_table_free(mm, table);
		return NULL;
	}
	return (pmd_t *) table;
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	pgtable_pmd_page_dtor(virt_to_page(pmd));
	crst_table_free(mm, (unsigned long *) pmd);
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	pgd_populate_kernel(mm, pgd, pud);
	if (mm->context.noexec) {
		pgd = get_shadow_table(pgd);
		pud = get_shadow_table(pud);
		pgd_populate_kernel(mm, pgd, pud);
	}
}

static inline void pud_populate_kernel(struct mm_struct *mm,
				       pud_t *pud, pmd_t *pmd)
{
	pud_val(*pud) = _REGION3_ENTRY | __pa(pmd);
	pgd_val(*pgd) = _REGION2_ENTRY | __pa(pud);
	pgd_val(*pgd) = _REGION1_ENTRY | __pa(p4d);
}

static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	p4d_val(*p4d) = _REGION2_ENTRY | __pa(pud);
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_populate_kernel(mm, pud, pmd);
	if (mm->context.noexec) {
		pud = get_shadow_table(pud);
		pmd = get_shadow_table(pmd);
		pud_populate_kernel(mm, pud, pmd);
	}
}

#endif /* __s390x__ */

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	INIT_LIST_HEAD(&mm->context.crst_list);
	INIT_LIST_HEAD(&mm->context.pgtable_list);
	return (pgd_t *) crst_table_alloc(mm, s390_noexec);
}
#define pgd_free(mm, pgd) crst_table_free(mm, (unsigned long *) pgd)

static inline void pmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	pmd_val(*pmd) = _SEGMENT_ENTRY + __pa(pte);
}

static inline void pmd_populate(struct mm_struct *mm,
				pmd_t *pmd, pgtable_t pte)
{
	pmd_populate_kernel(mm, pmd, pte);
	if (mm->context.noexec) {
		pmd = get_shadow_table(pmd);
		pmd_populate_kernel(mm, pmd, pte + PTRS_PER_PTE);
	}
}

	pud_val(*pud) = _REGION3_ENTRY | __pa(pmd);
}

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	unsigned long *table = crst_table_alloc(mm);

	if (!table)
		return NULL;
	if (mm->context.asce_limit == _REGION3_SIZE) {
		/* Forking a compat process with 2 page table levels */
		if (!pgtable_pmd_page_ctor(virt_to_page(table))) {
			crst_table_free(mm, table);
			return NULL;
		}
	}
	return (pgd_t *) table;
}

static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (mm->context.asce_limit == _REGION3_SIZE)
		pgtable_pmd_page_dtor(virt_to_page(pgd));
	crst_table_free(mm, (unsigned long *) pgd);
}

static inline void pmd_populate(struct mm_struct *mm,
				pmd_t *pmd, pgtable_t pte)
{
	pmd_val(*pmd) = _SEGMENT_ENTRY + __pa(pte);
}

#define pmd_populate_kernel(mm, pmd, pte) pmd_populate(mm, pmd, pte)

#define pmd_pgtable(pmd) \
	(pgtable_t)(pmd_val(pmd) & -sizeof(pte_t)*PTRS_PER_PTE)

/*
 * page table entry allocation/free routines.
 */
#define pte_alloc_one_kernel(mm, vmaddr) ((pte_t *) page_table_alloc(mm))
#define pte_alloc_one(mm, vmaddr) ((pte_t *) page_table_alloc(mm))

#define pte_free_kernel(mm, pte) page_table_free(mm, (unsigned long *) pte)
#define pte_free(mm, pte) page_table_free(mm, (unsigned long *) pte)

extern void rcu_table_freelist_finish(void);

void vmem_map_init(void);
void *vmem_crst_alloc(unsigned long val);
pte_t *vmem_pte_alloc(void);

unsigned long base_asce_alloc(unsigned long addr, unsigned long num_pages);
void base_asce_free(unsigned long asce);

#endif /* _S390_PGALLOC_H */
