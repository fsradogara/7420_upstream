/*
 *  arch/s390/mm/pgtable.c
 *
 *    Copyright IBM Corp. 2007
 *    Copyright IBM Corp. 2007, 2011
 *    Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/quicklist.h>

#include <asm/system.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/swapops.h>
#include <linux/sysctl.h>
#include <linux/ksm.h>
#include <linux/mman.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/page-states.h>

#ifndef CONFIG_64BIT
#define ALLOC_ORDER	1
#define TABLES_PER_PAGE	4
#define FRAG_MASK	15UL
#define SECOND_HALVES	10UL

void clear_table_pgstes(unsigned long *table)
{
	clear_table(table, _PAGE_TYPE_EMPTY, PAGE_SIZE/4);
	memset(table + 256, 0, PAGE_SIZE/4);
	clear_table(table + 512, _PAGE_TYPE_EMPTY, PAGE_SIZE/4);
	memset(table + 768, 0, PAGE_SIZE/4);
}

#else
#define ALLOC_ORDER	2
#define TABLES_PER_PAGE	2
#define FRAG_MASK	3UL
#define SECOND_HALVES	2UL

void clear_table_pgstes(unsigned long *table)
{
	clear_table(table, _PAGE_TYPE_EMPTY, PAGE_SIZE/2);
	memset(table + 256, 0, PAGE_SIZE/2);
}

#endif

unsigned long *crst_table_alloc(struct mm_struct *mm, int noexec)
{
	struct page *page = alloc_pages(GFP_KERNEL, ALLOC_ORDER);

	if (!page)
		return NULL;
	page->index = 0;
	if (noexec) {
		struct page *shadow = alloc_pages(GFP_KERNEL, ALLOC_ORDER);
		if (!shadow) {
			__free_pages(page, ALLOC_ORDER);
			return NULL;
		}
		page->index = page_to_phys(shadow);
	}
	spin_lock(&mm->page_table_lock);
	list_add(&page->lru, &mm->context.crst_list);
	spin_unlock(&mm->page_table_lock);
unsigned long *crst_table_alloc(struct mm_struct *mm)
static inline void ptep_ipte_local(struct mm_struct *mm, unsigned long addr,
				   pte_t *ptep, int nodat)
{
	unsigned long opt, asce;

	if (!page)
		return NULL;
	return (unsigned long *) page_to_phys(page);
}

void crst_table_free(struct mm_struct *mm, unsigned long *table)
{
	unsigned long *shadow = get_shadow_table(table);
	struct page *page = virt_to_page(table);

	spin_lock(&mm->page_table_lock);
	list_del(&page->lru);
	spin_unlock(&mm->page_table_lock);
	if (shadow)
		free_pages((unsigned long) shadow, ALLOC_ORDER);
	free_pages((unsigned long) table, ALLOC_ORDER);
}

#ifdef CONFIG_64BIT
	free_pages((unsigned long) table, 2);
}

static void __crst_table_upgrade(void *arg)
{
	struct mm_struct *mm = arg;

	if (current->active_mm == mm) {
		clear_user_asce();
		set_user_asce(mm);
	}
	__tlb_flush_local();
}

int crst_table_upgrade(struct mm_struct *mm, unsigned long limit)
{
	unsigned long *table, *pgd;
	unsigned long entry;

	BUG_ON(limit > (1UL << 53));
repeat:
	table = crst_table_alloc(mm, mm->context.noexec);
	if (!table)
		return -ENOMEM;
	spin_lock(&mm->page_table_lock);
	int flush;

	BUG_ON(limit > (1UL << 53));
	flush = 0;
repeat:
	table = crst_table_alloc(mm);
	if (!table)
		return -ENOMEM;
	spin_lock_bh(&mm->page_table_lock);
	if (mm->context.asce_limit < limit) {
		pgd = (unsigned long *) mm->pgd;
		if (mm->context.asce_limit <= (1UL << 31)) {
			entry = _REGION3_ENTRY_EMPTY;
			mm->context.asce_limit = 1UL << 42;
			mm->context.asce_bits = _ASCE_TABLE_LENGTH |
						_ASCE_USER_BITS |
						_ASCE_TYPE_REGION3;
		} else {
			entry = _REGION2_ENTRY_EMPTY;
			mm->context.asce_limit = 1UL << 53;
			mm->context.asce_bits = _ASCE_TABLE_LENGTH |
						_ASCE_USER_BITS |
						_ASCE_TYPE_REGION2;
		}
		crst_table_init(table, entry);
		pgd_populate(mm, (pgd_t *) table, (pud_t *) pgd);
		mm->pgd = (pgd_t *) table;
		table = NULL;
	}
	spin_unlock(&mm->page_table_lock);
		mm->task_size = mm->context.asce_limit;
		table = NULL;
		flush = 1;
	}
	spin_unlock_bh(&mm->page_table_lock);
	if (table)
		crst_table_free(mm, table);
	if (mm->context.asce_limit < limit)
		goto repeat;
	update_mm(mm, current);
	if (flush)
		on_each_cpu(__crst_table_upgrade, mm, 0);
	return 0;
}

void crst_table_downgrade(struct mm_struct *mm, unsigned long limit)
{
	pgd_t *pgd;

	if (mm->context.asce_limit <= limit)
		return;
	__tlb_flush_mm(mm);
	if (current->active_mm == mm) {
		clear_user_asce();
		__tlb_flush_mm(mm);
	}
	while (mm->context.asce_limit > limit) {
		pgd = mm->pgd;
		switch (pgd_val(*pgd) & _REGION_ENTRY_TYPE_MASK) {
		case _REGION_ENTRY_TYPE_R2:
			mm->context.asce_limit = 1UL << 42;
			mm->context.asce_bits = _ASCE_TABLE_LENGTH |
						_ASCE_USER_BITS |
						_ASCE_TYPE_REGION3;
			break;
		case _REGION_ENTRY_TYPE_R3:
			mm->context.asce_limit = 1UL << 31;
			mm->context.asce_bits = _ASCE_TABLE_LENGTH |
						_ASCE_USER_BITS |
						_ASCE_TYPE_SEGMENT;
			break;
		default:
			BUG();
		}
		mm->pgd = (pgd_t *) (pgd_val(*pgd) & _REGION_ENTRY_ORIGIN);
		crst_table_free(mm, (unsigned long *) pgd);
	}
	update_mm(mm, current);
}
#endif
		mm->task_size = mm->context.asce_limit;
		crst_table_free(mm, (unsigned long *) pgd);
	}
	if (current->active_mm == mm)
		set_user_asce(mm);
}

#ifdef CONFIG_PGSTE

/**
 * gmap_alloc - allocate a guest address space
 * @mm: pointer to the parent mm_struct
 * @limit: maximum size of the gmap address space
 *
 * Returns a guest address space structure.
 */
struct gmap *gmap_alloc(struct mm_struct *mm, unsigned long limit)
{
	struct gmap *gmap;
	struct page *page;
	unsigned long *table;
	unsigned long etype, atype;

	if (limit < (1UL << 31)) {
		limit = (1UL << 31) - 1;
		atype = _ASCE_TYPE_SEGMENT;
		etype = _SEGMENT_ENTRY_EMPTY;
	} else if (limit < (1UL << 42)) {
		limit = (1UL << 42) - 1;
		atype = _ASCE_TYPE_REGION3;
		etype = _REGION3_ENTRY_EMPTY;
	} else if (limit < (1UL << 53)) {
		limit = (1UL << 53) - 1;
		atype = _ASCE_TYPE_REGION2;
		etype = _REGION2_ENTRY_EMPTY;
	if (MACHINE_HAS_TLB_GUEST) {
		opt = 0;
		asce = READ_ONCE(mm->context.gmap_asce);
		if (asce == 0UL || nodat)
			opt |= IPTE_NODAT;
		if (asce != -1UL) {
			asce = asce ? : mm->context.asce;
			opt |= IPTE_GUEST_ASCE;
		}
		__ptep_ipte(addr, ptep, opt, asce, IPTE_LOCAL);
	} else {
		__ptep_ipte(addr, ptep, 0, 0, IPTE_LOCAL);
	}
}

static inline void ptep_ipte_global(struct mm_struct *mm, unsigned long addr,
				    pte_t *ptep, int nodat)
{
	unsigned long opt, asce;

	if (MACHINE_HAS_TLB_GUEST) {
		opt = 0;
		asce = READ_ONCE(mm->context.gmap_asce);
		if (asce == 0UL || nodat)
			opt |= IPTE_NODAT;
		if (asce != -1UL) {
			asce = asce ? : mm->context.asce;
			opt |= IPTE_GUEST_ASCE;
		}
		__ptep_ipte(addr, ptep, opt, asce, IPTE_GLOBAL);
	} else {
		__ptep_ipte(addr, ptep, 0, 0, IPTE_GLOBAL);
	}
}

static inline pte_t ptep_flush_direct(struct mm_struct *mm,
				      unsigned long addr, pte_t *ptep,
				      int nodat)
{
	pte_t old;

	old = *ptep;
	if (unlikely(pte_val(old) & _PAGE_INVALID))
		return old;
	atomic_inc(&mm->context.flush_count);
	if (MACHINE_HAS_TLB_LC &&
	    cpumask_equal(mm_cpumask(mm), cpumask_of(smp_processor_id())))
		ptep_ipte_local(mm, addr, ptep, nodat);
	else
		ptep_ipte_global(mm, addr, ptep, nodat);
	atomic_dec(&mm->context.flush_count);
	return old;
}

static inline pte_t ptep_flush_lazy(struct mm_struct *mm,
				    unsigned long addr, pte_t *ptep,
				    int nodat)
{
	pte_t old;

	old = *ptep;
	if (unlikely(pte_val(old) & _PAGE_INVALID))
		return old;
	atomic_inc(&mm->context.flush_count);
	if (cpumask_equal(&mm->context.cpu_attach_mask,
			  cpumask_of(smp_processor_id()))) {
		pte_val(*ptep) |= _PAGE_INVALID;
		mm->context.flush_mm = 1;
	} else
		ptep_ipte_global(mm, addr, ptep, nodat);
	atomic_dec(&mm->context.flush_count);
	return old;
}

static inline pgste_t pgste_get_lock(pte_t *ptep)
{
	unsigned long new = 0;
#ifdef CONFIG_PGSTE
	unsigned long old;

	asm(
		"	lg	%0,%2\n"
		"0:	lgr	%1,%0\n"
		"	nihh	%0,0xff7f\n"	/* clear PCL bit in old */
		"	oihh	%1,0x0080\n"	/* set PCL bit in new */
		"	csg	%0,%1,%2\n"
		"	jl	0b\n"
		: "=&d" (old), "=&d" (new), "=Q" (ptep[PTRS_PER_PTE])
		: "Q" (ptep[PTRS_PER_PTE]) : "cc", "memory");
#endif
	return __pgste(new);
}

static inline void pgste_set_unlock(pte_t *ptep, pgste_t pgste)
{
#ifdef CONFIG_PGSTE
	asm(
		"	nihh	%1,0xff7f\n"	/* clear PCL bit */
		"	stg	%1,%0\n"
		: "=Q" (ptep[PTRS_PER_PTE])
		: "d" (pgste_val(pgste)), "Q" (ptep[PTRS_PER_PTE])
		: "cc", "memory");
#endif
}

static inline pgste_t pgste_get(pte_t *ptep)
{
	unsigned long pgste = 0;
#ifdef CONFIG_PGSTE
	pgste = *(unsigned long *)(ptep + PTRS_PER_PTE);
#endif
	return __pgste(pgste);
}

static inline void pgste_set(pte_t *ptep, pgste_t pgste)
{
#ifdef CONFIG_PGSTE
	*(pgste_t *)(ptep + PTRS_PER_PTE) = pgste;
#endif
}

static inline pgste_t pgste_update_all(pte_t pte, pgste_t pgste,
				       struct mm_struct *mm)
{
#ifdef CONFIG_PGSTE
	unsigned long address, bits, skey;

	if (!mm_use_skey(mm) || pte_val(pte) & _PAGE_INVALID)
		return pgste;
	address = pte_val(pte) & PAGE_MASK;
	skey = (unsigned long) page_get_storage_key(address);
	bits = skey & (_PAGE_CHANGED | _PAGE_REFERENCED);
	/* Transfer page changed & referenced bit to guest bits in pgste */
	pgste_val(pgste) |= bits << 48;		/* GR bit & GC bit */
	/* Copy page access key and fetch protection bit to pgste */
	pgste_val(pgste) &= ~(PGSTE_ACC_BITS | PGSTE_FP_BIT);
	pgste_val(pgste) |= (skey & (_PAGE_ACC_BITS | _PAGE_FP_BIT)) << 56;
#endif
	return pgste;

}

static inline void pgste_set_key(pte_t *ptep, pgste_t pgste, pte_t entry,
				 struct mm_struct *mm)
{
#ifdef CONFIG_PGSTE
	unsigned long address;
	unsigned long nkey;

	if (!mm_use_skey(mm) || pte_val(entry) & _PAGE_INVALID)
		return;
	VM_BUG_ON(!(pte_val(*ptep) & _PAGE_INVALID));
	address = pte_val(entry) & PAGE_MASK;
	/*
	 * Set page access key and fetch protection bit from pgste.
	 * The guest C/R information is still in the PGSTE, set real
	 * key C/R to 0.
	 */
	nkey = (pgste_val(pgste) & (PGSTE_ACC_BITS | PGSTE_FP_BIT)) >> 56;
	nkey |= (pgste_val(pgste) & (PGSTE_GR_BIT | PGSTE_GC_BIT)) >> 48;
	page_set_storage_key(address, nkey, 0);
#endif
}

static inline pgste_t pgste_set_pte(pte_t *ptep, pgste_t pgste, pte_t entry)
{
#ifdef CONFIG_PGSTE
	if ((pte_val(entry) & _PAGE_PRESENT) &&
	    (pte_val(entry) & _PAGE_WRITE) &&
	    !(pte_val(entry) & _PAGE_INVALID)) {
		if (!MACHINE_HAS_ESOP) {
			/*
			 * Without enhanced suppression-on-protection force
			 * the dirty bit on for all writable ptes.
			 */
			pte_val(entry) |= _PAGE_DIRTY;
			pte_val(entry) &= ~_PAGE_PROTECT;
		}
		if (!(pte_val(entry) & _PAGE_PROTECT))
			/* This pte allows write access, set user-dirty */
			pgste_val(pgste) |= PGSTE_UC_BIT;
	}
#endif
	*ptep = entry;
	return pgste;
}

static inline pgste_t pgste_pte_notify(struct mm_struct *mm,
				       unsigned long addr,
				       pte_t *ptep, pgste_t pgste)
{
#ifdef CONFIG_PGSTE
	unsigned long bits;

	bits = pgste_val(pgste) & (PGSTE_IN_BIT | PGSTE_VSIE_BIT);
	if (bits) {
		pgste_val(pgste) ^= bits;
		ptep_notify(mm, addr, ptep, bits);
	}
#endif
	return pgste;
}

static inline pgste_t ptep_xchg_start(struct mm_struct *mm,
				      unsigned long addr, pte_t *ptep)
{
	pgste_t pgste = __pgste(0);

	if (mm_has_pgste(mm)) {
		pgste = pgste_get_lock(ptep);
		pgste = pgste_pte_notify(mm, addr, ptep, pgste);
	}
	return pgste;
}

static inline pte_t ptep_xchg_commit(struct mm_struct *mm,
				    unsigned long addr, pte_t *ptep,
				    pgste_t pgste, pte_t old, pte_t new)
{
	if (mm_has_pgste(mm)) {
		if (pte_val(old) & _PAGE_INVALID)
			pgste_set_key(ptep, pgste, new, mm);
		if (pte_val(new) & _PAGE_INVALID) {
			pgste = pgste_update_all(old, pgste, mm);
			if ((pgste_val(pgste) & _PGSTE_GPS_USAGE_MASK) ==
			    _PGSTE_GPS_USAGE_UNUSED)
				pte_val(old) |= _PAGE_UNUSED;
		}
		pgste = pgste_set_pte(ptep, pgste, new);
		pgste_set_unlock(ptep, pgste);
	} else {
		*ptep = new;
	}
	return old;
}

pte_t ptep_xchg_direct(struct mm_struct *mm, unsigned long addr,
		       pte_t *ptep, pte_t new)
{
	pgste_t pgste;
	pte_t old;
	int nodat;

	preempt_disable();
	pgste = ptep_xchg_start(mm, addr, ptep);
	nodat = !!(pgste_val(pgste) & _PGSTE_GPS_NODAT);
	old = ptep_flush_direct(mm, addr, ptep, nodat);
	old = ptep_xchg_commit(mm, addr, ptep, pgste, old, new);
	preempt_enable();
	return old;
}
EXPORT_SYMBOL(ptep_xchg_direct);

pte_t ptep_xchg_lazy(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t new)
{
	struct page *page;
	unsigned long *table;
	unsigned long bits;

	bits = (mm->context.noexec || mm->context.pgstes) ? 3UL : 1UL;
	spin_lock(&mm->page_table_lock);
	page = NULL;
	if (!list_empty(&mm->context.pgtable_list)) {
		page = list_first_entry(&mm->context.pgtable_list,
					struct page, lru);
		if ((page->flags & FRAG_MASK) == ((1UL << TABLES_PER_PAGE) - 1))
			page = NULL;
	}
	if (!page) {
		spin_unlock(&mm->page_table_lock);
		page = alloc_page(GFP_KERNEL|__GFP_REPEAT);
		if (!page)
			return NULL;
		pgtable_page_ctor(page);
		page->flags &= ~FRAG_MASK;
		table = (unsigned long *) page_to_phys(page);
		if (mm->context.pgstes)
			clear_table_pgstes(table);
		else
			clear_table(table, _PAGE_TYPE_EMPTY, PAGE_SIZE);
		spin_lock(&mm->page_table_lock);
		list_add(&page->lru, &mm->context.pgtable_list);
	}
	table = (unsigned long *) page_to_phys(page);
	while (page->flags & bits) {
		table += 256;
		bits <<= 1;
	}
	page->flags |= bits;
	if ((page->flags & FRAG_MASK) == ((1UL << TABLES_PER_PAGE) - 1))
		list_move_tail(&page->lru, &mm->context.pgtable_list);
	spin_unlock(&mm->page_table_lock);
	unsigned long *table;
	struct page *page;
	unsigned int mask, bit;
	pgste_t pgste;
	pte_t old;
	int nodat;

	preempt_disable();
	pgste = ptep_xchg_start(mm, addr, ptep);
	nodat = !!(pgste_val(pgste) & _PGSTE_GPS_NODAT);
	old = ptep_flush_lazy(mm, addr, ptep, nodat);
	old = ptep_xchg_commit(mm, addr, ptep, pgste, old, new);
	preempt_enable();
	return old;
}
EXPORT_SYMBOL(ptep_xchg_lazy);

pte_t ptep_modify_prot_start(struct mm_struct *mm, unsigned long addr,
			     pte_t *ptep)
{
	pgste_t pgste;
	pte_t old;
	int nodat;

	preempt_disable();
	pgste = ptep_xchg_start(mm, addr, ptep);
	nodat = !!(pgste_val(pgste) & _PGSTE_GPS_NODAT);
	old = ptep_flush_lazy(mm, addr, ptep, nodat);
	if (mm_has_pgste(mm)) {
		pgste = pgste_update_all(old, pgste, mm);
		pgste_set(ptep, pgste);
	}
	return old;
}
EXPORT_SYMBOL(ptep_modify_prot_start);

void ptep_modify_prot_commit(struct mm_struct *mm, unsigned long addr,
			     pte_t *ptep, pte_t pte)
{
	pgste_t pgste;

	if (!MACHINE_HAS_NX)
		pte_val(pte) &= ~_PAGE_NOEXEC;
	if (mm_has_pgste(mm)) {
		pgste = pgste_get(ptep);
		pgste_set_key(ptep, pgste, pte, mm);
		pgste = pgste_set_pte(ptep, pgste, pte);
		pgste_set_unlock(ptep, pgste);
	} else {
		*ptep = pte;
	}
	preempt_enable();
}
EXPORT_SYMBOL(ptep_modify_prot_commit);

static inline void pmdp_idte_local(struct mm_struct *mm,
				   unsigned long addr, pmd_t *pmdp)
{
	struct page *page;
	unsigned long bits;

	bits = (mm->context.noexec || mm->context.pgstes) ? 3UL : 1UL;
	bits <<= (__pa(table) & (PAGE_SIZE - 1)) / 256 / sizeof(unsigned long);
	page = pfn_to_page(__pa(table) >> PAGE_SHIFT);
	spin_lock(&mm->page_table_lock);
	page->flags ^= bits;
	if (page->flags & FRAG_MASK) {
		/* Page now has some free pgtable fragments. */
		list_move(&page->lru, &mm->context.pgtable_list);
		page = NULL;
	} else
		/* All fragments of the 4K page have been freed. */
		list_del(&page->lru);
	spin_unlock(&mm->page_table_lock);
	if (page) {
		pgtable_page_dtor(page);
		__free_page(page);
	}
}

void disable_noexec(struct mm_struct *mm, struct task_struct *tsk)
{
	struct page *page;

	spin_lock(&mm->page_table_lock);
	/* Free shadow region and segment tables. */
	list_for_each_entry(page, &mm->context.crst_list, lru)
		if (page->index) {
			free_pages((unsigned long) page->index, ALLOC_ORDER);
			page->index = 0;
		}
	/* "Free" second halves of page tables. */
	list_for_each_entry(page, &mm->context.pgtable_list, lru)
		page->flags &= ~SECOND_HALVES;
	spin_unlock(&mm->page_table_lock);
	mm->context.noexec = 0;
	update_mm(mm, tsk);
}

	unsigned int bit, mask;

	page = pfn_to_page(__pa(table) >> PAGE_SHIFT);
	if (!mm_alloc_pgste(mm)) {
		/* Free 2K page table fragment of a 4K page */
		bit = (__pa(table) & ~PAGE_MASK)/(PTRS_PER_PTE*sizeof(pte_t));
		spin_lock_bh(&mm->context.list_lock);
		mask = atomic_xor_bits(&page->_mapcount, 1U << bit);
		if (mask & 3)
			list_add(&page->lru, &mm->context.pgtable_list);
		else
			list_del(&page->lru);
		spin_unlock_bh(&mm->context.list_lock);
		if (mask != 0)
			return;
	}

	pgtable_page_dtor(page);
	atomic_set(&page->_mapcount, -1);
	__free_page(page);
}

void page_table_free_rcu(struct mmu_gather *tlb, unsigned long *table,
			 unsigned long vmaddr)
{
	struct mm_struct *mm;
	struct page *page;
	unsigned int bit, mask;

	mm = tlb->mm;
	page = pfn_to_page(__pa(table) >> PAGE_SHIFT);
	if (mm_alloc_pgste(mm)) {
		gmap_unlink(mm, table, vmaddr);
		table = (unsigned long *) (__pa(table) | 3);
		tlb_remove_table(tlb, table);
		return;
	}
	bit = (__pa(table) & ~PAGE_MASK) / (PTRS_PER_PTE*sizeof(pte_t));
	spin_lock_bh(&mm->context.list_lock);
	mask = atomic_xor_bits(&page->_mapcount, 0x11U << bit);
	if (mask & 3)
		list_add_tail(&page->lru, &mm->context.pgtable_list);
	if (MACHINE_HAS_TLB_GUEST)
		__pmdp_idte(addr, pmdp, IDTE_NODAT | IDTE_GUEST_ASCE,
			    mm->context.asce, IDTE_LOCAL);
	else
		__pmdp_idte(addr, pmdp, 0, 0, IDTE_LOCAL);
}

static inline void pmdp_idte_global(struct mm_struct *mm,
				    unsigned long addr, pmd_t *pmdp)
{
	if (MACHINE_HAS_TLB_GUEST)
		__pmdp_idte(addr, pmdp, IDTE_NODAT | IDTE_GUEST_ASCE,
			    mm->context.asce, IDTE_GLOBAL);
	else if (MACHINE_HAS_IDTE)
		__pmdp_idte(addr, pmdp, 0, 0, IDTE_GLOBAL);
	else
		__pmdp_csp(pmdp);
}

static inline pmd_t pmdp_flush_direct(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	pmd_t old;

	old = *pmdp;
	if (pmd_val(old) & _SEGMENT_ENTRY_INVALID)
		return old;
	atomic_inc(&mm->context.flush_count);
	if (MACHINE_HAS_TLB_LC &&
	    cpumask_equal(mm_cpumask(mm), cpumask_of(smp_processor_id())))
		pmdp_idte_local(mm, addr, pmdp);
	else
		pmdp_idte_global(mm, addr, pmdp);
	atomic_dec(&mm->context.flush_count);
	return old;
}

static inline pmd_t pmdp_flush_lazy(struct mm_struct *mm,
				    unsigned long addr, pmd_t *pmdp)
{
	pmd_t old;

	old = *pmdp;
	if (pmd_val(old) & _SEGMENT_ENTRY_INVALID)
		return old;
	atomic_inc(&mm->context.flush_count);
	if (cpumask_equal(&mm->context.cpu_attach_mask,
			  cpumask_of(smp_processor_id()))) {
		pmd_val(*pmdp) |= _SEGMENT_ENTRY_INVALID;
		mm->context.flush_mm = 1;
	} else {
		pmdp_idte_global(mm, addr, pmdp);
	}
	atomic_dec(&mm->context.flush_count);
	return old;
}

pmd_t pmdp_xchg_direct(struct mm_struct *mm, unsigned long addr,
		       pmd_t *pmdp, pmd_t new)
{
	pmd_t old;

	preempt_disable();
	old = pmdp_flush_direct(mm, addr, pmdp);
	*pmdp = new;
	preempt_enable();
	return old;
}
EXPORT_SYMBOL(pmdp_xchg_direct);

pmd_t pmdp_xchg_lazy(struct mm_struct *mm, unsigned long addr,
		     pmd_t *pmdp, pmd_t new)
{
	pmd_t old;

	preempt_disable();
	old = pmdp_flush_lazy(mm, addr, pmdp);
	*pmdp = new;
	preempt_enable();
	return old;
}
EXPORT_SYMBOL(pmdp_xchg_lazy);

static inline void pudp_idte_local(struct mm_struct *mm,
				   unsigned long addr, pud_t *pudp)
{
	if (MACHINE_HAS_TLB_GUEST)
		__pudp_idte(addr, pudp, IDTE_NODAT | IDTE_GUEST_ASCE,
			    mm->context.asce, IDTE_LOCAL);
	else
		__pudp_idte(addr, pudp, 0, 0, IDTE_LOCAL);
}

static inline void pudp_idte_global(struct mm_struct *mm,
				    unsigned long addr, pud_t *pudp)
{
	if (MACHINE_HAS_TLB_GUEST)
		__pudp_idte(addr, pudp, IDTE_NODAT | IDTE_GUEST_ASCE,
			    mm->context.asce, IDTE_GLOBAL);
	else if (MACHINE_HAS_IDTE)
		__pudp_idte(addr, pudp, 0, 0, IDTE_GLOBAL);
	else
		/*
		 * Invalid bit position is the same for pmd and pud, so we can
		 * re-use _pmd_csp() here
		 */
		__pmdp_csp((pmd_t *) pudp);
}

static inline pud_t pudp_flush_direct(struct mm_struct *mm,
				      unsigned long addr, pud_t *pudp)
{
	pud_t old;

	old = *pudp;
	if (pud_val(old) & _REGION_ENTRY_INVALID)
		return old;
	atomic_inc(&mm->context.flush_count);
	if (MACHINE_HAS_TLB_LC &&
	    cpumask_equal(mm_cpumask(mm), cpumask_of(smp_processor_id())))
		pudp_idte_local(mm, addr, pudp);
	else
		pudp_idte_global(mm, addr, pudp);
	atomic_dec(&mm->context.flush_count);
	return old;
}

pud_t pudp_xchg_direct(struct mm_struct *mm, unsigned long addr,
		       pud_t *pudp, pud_t new)
{
	pud_t old;

	preempt_disable();
	old = pudp_flush_direct(mm, addr, pudp);
	*pudp = new;
	preempt_enable();
	return old;
}
EXPORT_SYMBOL(pudp_xchg_direct);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline void thp_split_vma(struct vm_area_struct *vma)
{
	unsigned long addr;

	for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE)
		follow_page(vma, addr, FOLL_SPLIT);
}

static inline void thp_split_mm(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
		thp_split_vma(vma);
		vma->vm_flags &= ~VM_HUGEPAGE;
		vma->vm_flags |= VM_NOHUGEPAGE;
	}
	mm->def_flags |= VM_NOHUGEPAGE;
}
#else
static inline void thp_split_mm(struct mm_struct *mm)
{
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/*
 * switch on pgstes for its userspace process (for kvm)
 */
int s390_enable_sie(void)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm, *old_mm;

	/* Do we have pgstes? if yes, we are done */
	if (tsk->mm->context.pgstes)
		return 0;

	/* lets check if we are allowed to replace the mm */
	task_lock(tsk);
	if (!tsk->mm || atomic_read(&tsk->mm->mm_users) > 1 ||
	    tsk->mm != tsk->active_mm || tsk->mm->ioctx_list) {
		task_unlock(tsk);
		return -EINVAL;
	}
	task_unlock(tsk);

	/* we copy the mm with pgstes enabled */
	tsk->mm->context.pgstes = 1;
	mm = dup_mm(tsk);
	tsk->mm->context.pgstes = 0;
	if (!mm)
		return -ENOMEM;

	/* Now lets check again if somebody attached ptrace etc */
	task_lock(tsk);
	if (!tsk->mm || atomic_read(&tsk->mm->mm_users) > 1 ||
	    tsk->mm != tsk->active_mm || tsk->mm->ioctx_list) {
		mmput(mm);
		task_unlock(tsk);
		return -EINVAL;
	}

	/* ok, we are alone. No ptrace, no threads, etc. */
	old_mm = tsk->mm;
	tsk->mm = tsk->active_mm = mm;
	preempt_disable();
	update_mm(mm, tsk);
	cpu_set(smp_processor_id(), mm->cpu_vm_mask);
	preempt_enable();
	task_unlock(tsk);
	mmput(old_mm);
	return 0;
}
EXPORT_SYMBOL_GPL(s390_enable_sie);
	struct mm_struct *mm = current->mm;

	/* Do we have pgstes? if yes, we are done */
	if (mm_has_pgste(mm))
		return 0;
	/* Fail if the page tables are 2K */
	if (!mm_alloc_pgste(mm))
		return -EINVAL;
	down_write(&mm->mmap_sem);
	mm->context.has_pgste = 1;
	/* split thp mappings and disable thp for future mappings */
	thp_split_mm(mm);
	up_write(&mm->mmap_sem);
	return 0;
}
EXPORT_SYMBOL_GPL(s390_enable_sie);

/*
 * Enable storage key handling from now on and initialize the storage
 * keys with the default key.
 */
static int __s390_enable_skey(pte_t *pte, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	unsigned long ptev;
	pgste_t pgste;

	pgste = pgste_get_lock(pte);
	/*
	 * Remove all zero page mappings,
	 * after establishing a policy to forbid zero page mappings
	 * following faults for that page will get fresh anonymous pages
	 */
	if (is_zero_pfn(pte_pfn(*pte))) {
		ptep_flush_direct(walk->mm, addr, pte);
		pte_val(*pte) = _PAGE_INVALID;
	}
	/* Clear storage key */
	pgste_val(pgste) &= ~(PGSTE_ACC_BITS | PGSTE_FP_BIT |
			      PGSTE_GR_BIT | PGSTE_GC_BIT);
	ptev = pte_val(*pte);
	if (!(ptev & _PAGE_INVALID) && (ptev & _PAGE_WRITE))
		page_set_storage_key(ptev & PAGE_MASK, PAGE_DEFAULT_KEY, 1);
	pgste_set_unlock(pte, pgste);
	return 0;
}

int s390_enable_skey(void)
{
	struct mm_walk walk = { .pte_entry = __s390_enable_skey };
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int rc = 0;

	down_write(&mm->mmap_sem);
	if (mm_use_skey(mm))
		goto out_up;

	mm->context.use_skey = 1;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (ksm_madvise(vma, vma->vm_start, vma->vm_end,
				MADV_UNMERGEABLE, &vma->vm_flags)) {
			mm->context.use_skey = 0;
			rc = -ENOMEM;
			goto out_up;
		}
	}
	mm->def_flags &= ~VM_MERGEABLE;

	walk.mm = mm;
	walk_page_range(0, TASK_SIZE, &walk);

out_up:
	up_write(&mm->mmap_sem);
	return rc;
}
EXPORT_SYMBOL_GPL(s390_enable_skey);

/*
 * Reset CMMA state, make all pages stable again.
 */
static int __s390_reset_cmma(pte_t *pte, unsigned long addr,
			     unsigned long next, struct mm_walk *walk)
{
	pgste_t pgste;

	pgste = pgste_get_lock(pte);
	pgste_val(pgste) &= ~_PGSTE_GPS_USAGE_MASK;
	pgste_set_unlock(pte, pgste);
	return 0;
}

void s390_reset_cmma(struct mm_struct *mm)
{
	struct mm_walk walk = { .pte_entry = __s390_reset_cmma };

	down_write(&mm->mmap_sem);
	walk.mm = mm;
	walk_page_range(0, TASK_SIZE, &walk);
	up_write(&mm->mmap_sem);
}
EXPORT_SYMBOL_GPL(s390_reset_cmma);

/*
 * Test and reset if a guest page is dirty
 */
bool gmap_test_and_clear_dirty(unsigned long address, struct gmap *gmap)
{
	pte_t *pte;
	spinlock_t *ptl;
	bool dirty = false;

	pte = get_locked_pte(gmap->mm, address, &ptl);
	if (unlikely(!pte))
		return false;

	if (ptep_test_and_clear_user_dirty(gmap->mm, address, pte))
		dirty = true;

	spin_unlock(ptl);
	return dirty;
}
EXPORT_SYMBOL_GPL(gmap_test_and_clear_dirty);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int pmdp_clear_flush_young(struct vm_area_struct *vma, unsigned long address,
			   pmd_t *pmdp)
{
	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	/* No need to flush TLB
	 * On s390 reference bits are in storage key and never in TLB */
	return pmdp_test_and_clear_young(vma, address, pmdp);
}

int pmdp_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp,
			  pmd_t entry, int dirty)
{
	VM_BUG_ON(address & ~HPAGE_PMD_MASK);

	entry = pmd_mkyoung(entry);
	if (dirty)
		entry = pmd_mkdirty(entry);
	if (pmd_same(*pmdp, entry))
		return 0;
	pmdp_invalidate(vma, address, pmdp);
	set_pmd_at(vma->vm_mm, address, pmdp, entry);
	return 1;
}

static void pmdp_splitting_flush_sync(void *arg)
{
	/* Simply deliver the interrupt */
}

void pmdp_splitting_flush(struct vm_area_struct *vma, unsigned long address,
			  pmd_t *pmdp)
{
	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	if (!test_and_set_bit(_SEGMENT_ENTRY_SPLIT_BIT,
			      (unsigned long *) pmdp)) {
		/* need to serialize against gup-fast (IRQ disabled) */
		smp_call_function(pmdp_splitting_flush_sync, NULL, 1);
	}
}

void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable)
{
	struct list_head *lh = (struct list_head *) pgtable;

	assert_spin_locked(pmd_lockptr(mm, pmdp));

	/* FIFO */
	if (!pmd_huge_pte(mm, pmdp))
		INIT_LIST_HEAD(lh);
	else
		list_add(lh, (struct list_head *) pmd_huge_pte(mm, pmdp));
	pmd_huge_pte(mm, pmdp) = pgtable;
}

pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	struct list_head *lh;
	pgtable_t pgtable;
	pte_t *ptep;

	assert_spin_locked(pmd_lockptr(mm, pmdp));

	/* FIFO */
	pgtable = pmd_huge_pte(mm, pmdp);
	lh = (struct list_head *) pgtable;
	if (list_empty(lh))
		pmd_huge_pte(mm, pmdp) = NULL;
	else {
		pmd_huge_pte(mm, pmdp) = (pgtable_t) lh->next;
		list_del(lh);
	}
	ptep = (pte_t *) pgtable;
	pte_val(*ptep) = _PAGE_INVALID;
	ptep++;
	pte_val(*ptep) = _PAGE_INVALID;
	return pgtable;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#ifdef CONFIG_PGSTE
void ptep_set_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t entry)
{
	pgste_t pgste;

	/* the mm_has_pgste() check is done in set_pte_at() */
	preempt_disable();
	pgste = pgste_get_lock(ptep);
	pgste_val(pgste) &= ~_PGSTE_GPS_ZERO;
	pgste_set_key(ptep, pgste, entry, mm);
	pgste = pgste_set_pte(ptep, pgste, entry);
	pgste_set_unlock(ptep, pgste);
	preempt_enable();
}

void ptep_set_notify(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	pgste_t pgste;

	preempt_disable();
	pgste = pgste_get_lock(ptep);
	pgste_val(pgste) |= PGSTE_IN_BIT;
	pgste_set_unlock(ptep, pgste);
	preempt_enable();
}

/**
 * ptep_force_prot - change access rights of a locked pte
 * @mm: pointer to the process mm_struct
 * @addr: virtual address in the guest address space
 * @ptep: pointer to the page table entry
 * @prot: indicates guest access rights: PROT_NONE, PROT_READ or PROT_WRITE
 * @bit: pgste bit to set (e.g. for notification)
 *
 * Returns 0 if the access rights were changed and -EAGAIN if the current
 * and requested access rights are incompatible.
 */
int ptep_force_prot(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, int prot, unsigned long bit)
{
	pte_t entry;
	pgste_t pgste;
	int pte_i, pte_p, nodat;

	pgste = pgste_get_lock(ptep);
	entry = *ptep;
	/* Check pte entry after all locks have been acquired */
	pte_i = pte_val(entry) & _PAGE_INVALID;
	pte_p = pte_val(entry) & _PAGE_PROTECT;
	if ((pte_i && (prot != PROT_NONE)) ||
	    (pte_p && (prot & PROT_WRITE))) {
		pgste_set_unlock(ptep, pgste);
		return -EAGAIN;
	}
	/* Change access rights and set pgste bit */
	nodat = !!(pgste_val(pgste) & _PGSTE_GPS_NODAT);
	if (prot == PROT_NONE && !pte_i) {
		ptep_flush_direct(mm, addr, ptep, nodat);
		pgste = pgste_update_all(entry, pgste, mm);
		pte_val(entry) |= _PAGE_INVALID;
	}
	if (prot == PROT_READ && !pte_p) {
		ptep_flush_direct(mm, addr, ptep, nodat);
		pte_val(entry) &= ~_PAGE_INVALID;
		pte_val(entry) |= _PAGE_PROTECT;
	}
	pgste_val(pgste) |= bit;
	pgste = pgste_set_pte(ptep, pgste, entry);
	pgste_set_unlock(ptep, pgste);
	return 0;
}

int ptep_shadow_pte(struct mm_struct *mm, unsigned long saddr,
		    pte_t *sptep, pte_t *tptep, pte_t pte)
{
	pgste_t spgste, tpgste;
	pte_t spte, tpte;
	int rc = -EAGAIN;

	if (!(pte_val(*tptep) & _PAGE_INVALID))
		return 0;	/* already shadowed */
	spgste = pgste_get_lock(sptep);
	spte = *sptep;
	if (!(pte_val(spte) & _PAGE_INVALID) &&
	    !((pte_val(spte) & _PAGE_PROTECT) &&
	      !(pte_val(pte) & _PAGE_PROTECT))) {
		pgste_val(spgste) |= PGSTE_VSIE_BIT;
		tpgste = pgste_get_lock(tptep);
		pte_val(tpte) = (pte_val(spte) & PAGE_MASK) |
				(pte_val(pte) & _PAGE_PROTECT);
		/* don't touch the storage key - it belongs to parent pgste */
		tpgste = pgste_set_pte(tptep, tpgste, tpte);
		pgste_set_unlock(tptep, tpgste);
		rc = 1;
	}
	pgste_set_unlock(sptep, spgste);
	return rc;
}

void ptep_unshadow_pte(struct mm_struct *mm, unsigned long saddr, pte_t *ptep)
{
	pgste_t pgste;
	int nodat;

	pgste = pgste_get_lock(ptep);
	/* notifier is called by the caller */
	nodat = !!(pgste_val(pgste) & _PGSTE_GPS_NODAT);
	ptep_flush_direct(mm, saddr, ptep, nodat);
	/* don't touch the storage key - it belongs to parent pgste */
	pgste = pgste_set_pte(ptep, pgste, __pte(_PAGE_INVALID));
	pgste_set_unlock(ptep, pgste);
}

static void ptep_zap_swap_entry(struct mm_struct *mm, swp_entry_t entry)
{
	if (!non_swap_entry(entry))
		dec_mm_counter(mm, MM_SWAPENTS);
	else if (is_migration_entry(entry)) {
		struct page *page = migration_entry_to_page(entry);

		dec_mm_counter(mm, mm_counter(page));
	}
	free_swap_and_cache(entry);
}

void ptep_zap_unused(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, int reset)
{
	unsigned long pgstev;
	pgste_t pgste;
	pte_t pte;

	/* Zap unused and logically-zero pages */
	preempt_disable();
	pgste = pgste_get_lock(ptep);
	pgstev = pgste_val(pgste);
	pte = *ptep;
	if (!reset && pte_swap(pte) &&
	    ((pgstev & _PGSTE_GPS_USAGE_MASK) == _PGSTE_GPS_USAGE_UNUSED ||
	     (pgstev & _PGSTE_GPS_ZERO))) {
		ptep_zap_swap_entry(mm, pte_to_swp_entry(pte));
		pte_clear(mm, addr, ptep);
	}
	if (reset)
		pgste_val(pgste) &= ~_PGSTE_GPS_USAGE_MASK;
	pgste_set_unlock(ptep, pgste);
	preempt_enable();
}

void ptep_zap_key(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	unsigned long ptev;
	pgste_t pgste;

	/* Clear storage key ACC and F, but set R/C */
	preempt_disable();
	pgste = pgste_get_lock(ptep);
	pgste_val(pgste) &= ~(PGSTE_ACC_BITS | PGSTE_FP_BIT);
	pgste_val(pgste) |= PGSTE_GR_BIT | PGSTE_GC_BIT;
	ptev = pte_val(*ptep);
	if (!(ptev & _PAGE_INVALID) && (ptev & _PAGE_WRITE))
		page_set_storage_key(ptev & PAGE_MASK, PAGE_DEFAULT_KEY, 1);
	pgste_set_unlock(ptep, pgste);
	preempt_enable();
}

/*
 * Test and reset if a guest page is dirty
 */
bool test_and_clear_guest_dirty(struct mm_struct *mm, unsigned long addr)
{
	spinlock_t *ptl;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pgste_t pgste;
	pte_t *ptep;
	pte_t pte;
	bool dirty;
	int nodat;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return false;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return false;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return false;
	/* We can't run guests backed by huge pages, but userspace can
	 * still set them up and then try to migrate them without any
	 * migration support.
	 */
	if (pmd_large(*pmd))
		return true;

	ptep = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (unlikely(!ptep))
		return false;

	pgste = pgste_get_lock(ptep);
	dirty = !!(pgste_val(pgste) & PGSTE_UC_BIT);
	pgste_val(pgste) &= ~PGSTE_UC_BIT;
	pte = *ptep;
	if (dirty && (pte_val(pte) & _PAGE_PRESENT)) {
		pgste = pgste_pte_notify(mm, addr, ptep, pgste);
		nodat = !!(pgste_val(pgste) & _PGSTE_GPS_NODAT);
		ptep_ipte_global(mm, addr, ptep, nodat);
		if (MACHINE_HAS_ESOP || !(pte_val(pte) & _PAGE_WRITE))
			pte_val(pte) |= _PAGE_PROTECT;
		else
			pte_val(pte) |= _PAGE_INVALID;
		*ptep = pte;
	}
	pgste_set_unlock(ptep, pgste);

	spin_unlock(ptl);
	return dirty;
}
EXPORT_SYMBOL_GPL(test_and_clear_guest_dirty);

int set_guest_storage_key(struct mm_struct *mm, unsigned long addr,
			  unsigned char key, bool nq)
{
	unsigned long keyul;
	spinlock_t *ptl;
	pgste_t old, new;
	pte_t *ptep;

	ptep = get_locked_pte(mm, addr, &ptl);
	if (unlikely(!ptep))
		return -EFAULT;

	new = old = pgste_get_lock(ptep);
	pgste_val(new) &= ~(PGSTE_GR_BIT | PGSTE_GC_BIT |
			    PGSTE_ACC_BITS | PGSTE_FP_BIT);
	keyul = (unsigned long) key;
	pgste_val(new) |= (keyul & (_PAGE_CHANGED | _PAGE_REFERENCED)) << 48;
	pgste_val(new) |= (keyul & (_PAGE_ACC_BITS | _PAGE_FP_BIT)) << 56;
	if (!(pte_val(*ptep) & _PAGE_INVALID)) {
		unsigned long address, bits, skey;

		address = pte_val(*ptep) & PAGE_MASK;
		skey = (unsigned long) page_get_storage_key(address);
		bits = skey & (_PAGE_CHANGED | _PAGE_REFERENCED);
		skey = key & (_PAGE_ACC_BITS | _PAGE_FP_BIT);
		/* Set storage key ACC and FP */
		page_set_storage_key(address, skey, !nq);
		/* Merge host changed & referenced into pgste  */
		pgste_val(new) |= bits << 52;
	}
	/* changing the guest storage key is considered a change of the page */
	if ((pgste_val(new) ^ pgste_val(old)) &
	    (PGSTE_ACC_BITS | PGSTE_FP_BIT | PGSTE_GR_BIT | PGSTE_GC_BIT))
		pgste_val(new) |= PGSTE_UC_BIT;

	pgste_set_unlock(ptep, new);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(set_guest_storage_key);

/**
 * Conditionally set a guest storage key (handling csske).
 * oldkey will be updated when either mr or mc is set and a pointer is given.
 *
 * Returns 0 if a guests storage key update wasn't necessary, 1 if the guest
 * storage key was updated and -EFAULT on access errors.
 */
int cond_set_guest_storage_key(struct mm_struct *mm, unsigned long addr,
			       unsigned char key, unsigned char *oldkey,
			       bool nq, bool mr, bool mc)
{
	unsigned char tmp, mask = _PAGE_ACC_BITS | _PAGE_FP_BIT;
	int rc;

	/* we can drop the pgste lock between getting and setting the key */
	if (mr | mc) {
		rc = get_guest_storage_key(current->mm, addr, &tmp);
		if (rc)
			return rc;
		if (oldkey)
			*oldkey = tmp;
		if (!mr)
			mask |= _PAGE_REFERENCED;
		if (!mc)
			mask |= _PAGE_CHANGED;
		if (!((tmp ^ key) & mask))
			return 0;
	}
	rc = set_guest_storage_key(current->mm, addr, key, nq);
	return rc < 0 ? rc : 1;
}
EXPORT_SYMBOL(cond_set_guest_storage_key);

/**
 * Reset a guest reference bit (rrbe), returning the reference and changed bit.
 *
 * Returns < 0 in case of error, otherwise the cc to be reported to the guest.
 */
int reset_guest_reference_bit(struct mm_struct *mm, unsigned long addr)
{
	spinlock_t *ptl;
	pgste_t old, new;
	pte_t *ptep;
	int cc = 0;

	ptep = get_locked_pte(mm, addr, &ptl);
	if (unlikely(!ptep))
		return -EFAULT;

	new = old = pgste_get_lock(ptep);
	/* Reset guest reference bit only */
	pgste_val(new) &= ~PGSTE_GR_BIT;

	if (!(pte_val(*ptep) & _PAGE_INVALID)) {
		cc = page_reset_referenced(pte_val(*ptep) & PAGE_MASK);
		/* Merge real referenced bit into host-set */
		pgste_val(new) |= ((unsigned long) cc << 53) & PGSTE_HR_BIT;
	}
	/* Reflect guest's logical view, not physical */
	cc |= (pgste_val(old) & (PGSTE_GR_BIT | PGSTE_GC_BIT)) >> 49;
	/* Changing the guest storage key is considered a change of the page */
	if ((pgste_val(new) ^ pgste_val(old)) & PGSTE_GR_BIT)
		pgste_val(new) |= PGSTE_UC_BIT;

	pgste_set_unlock(ptep, new);
	pte_unmap_unlock(ptep, ptl);
	return cc;
}
EXPORT_SYMBOL(reset_guest_reference_bit);

int get_guest_storage_key(struct mm_struct *mm, unsigned long addr,
			  unsigned char *key)
{
	spinlock_t *ptl;
	pgste_t pgste;
	pte_t *ptep;

	ptep = get_locked_pte(mm, addr, &ptl);
	if (unlikely(!ptep))
		return -EFAULT;

	pgste = pgste_get_lock(ptep);
	*key = (pgste_val(pgste) & (PGSTE_ACC_BITS | PGSTE_FP_BIT)) >> 56;
	if (!(pte_val(*ptep) & _PAGE_INVALID))
		*key = page_get_storage_key(pte_val(*ptep) & PAGE_MASK);
	/* Reflect guest's logical view, not physical */
	*key |= (pgste_val(pgste) & (PGSTE_GR_BIT | PGSTE_GC_BIT)) >> 48;
	pgste_set_unlock(ptep, pgste);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(get_guest_storage_key);

/**
 * pgste_perform_essa - perform ESSA actions on the PGSTE.
 * @mm: the memory context. It must have PGSTEs, no check is performed here!
 * @hva: the host virtual address of the page whose PGSTE is to be processed
 * @orc: the specific action to perform, see the ESSA_SET_* macros.
 * @oldpte: the PTE will be saved there if the pointer is not NULL.
 * @oldpgste: the old PGSTE will be saved there if the pointer is not NULL.
 *
 * Return: 1 if the page is to be added to the CBRL, otherwise 0,
 *	   or < 0 in case of error. -EINVAL is returned for invalid values
 *	   of orc, -EFAULT for invalid addresses.
 */
int pgste_perform_essa(struct mm_struct *mm, unsigned long hva, int orc,
			unsigned long *oldpte, unsigned long *oldpgste)
{
	unsigned long pgstev;
	spinlock_t *ptl;
	pgste_t pgste;
	pte_t *ptep;
	int res = 0;

	WARN_ON_ONCE(orc > ESSA_MAX);
	if (unlikely(orc > ESSA_MAX))
		return -EINVAL;
	ptep = get_locked_pte(mm, hva, &ptl);
	if (unlikely(!ptep))
		return -EFAULT;
	pgste = pgste_get_lock(ptep);
	pgstev = pgste_val(pgste);
	if (oldpte)
		*oldpte = pte_val(*ptep);
	if (oldpgste)
		*oldpgste = pgstev;

	switch (orc) {
	case ESSA_GET_STATE:
		break;
	case ESSA_SET_STABLE:
		pgstev &= ~(_PGSTE_GPS_USAGE_MASK | _PGSTE_GPS_NODAT);
		pgstev |= _PGSTE_GPS_USAGE_STABLE;
		break;
	case ESSA_SET_UNUSED:
		pgstev &= ~_PGSTE_GPS_USAGE_MASK;
		pgstev |= _PGSTE_GPS_USAGE_UNUSED;
		if (pte_val(*ptep) & _PAGE_INVALID)
			res = 1;
		break;
	case ESSA_SET_VOLATILE:
		pgstev &= ~_PGSTE_GPS_USAGE_MASK;
		pgstev |= _PGSTE_GPS_USAGE_VOLATILE;
		if (pte_val(*ptep) & _PAGE_INVALID)
			res = 1;
		break;
	case ESSA_SET_POT_VOLATILE:
		pgstev &= ~_PGSTE_GPS_USAGE_MASK;
		if (!(pte_val(*ptep) & _PAGE_INVALID)) {
			pgstev |= _PGSTE_GPS_USAGE_POT_VOLATILE;
			break;
		}
		if (pgstev & _PGSTE_GPS_ZERO) {
			pgstev |= _PGSTE_GPS_USAGE_VOLATILE;
			break;
		}
		if (!(pgstev & PGSTE_GC_BIT)) {
			pgstev |= _PGSTE_GPS_USAGE_VOLATILE;
			res = 1;
			break;
		}
		break;
	case ESSA_SET_STABLE_RESIDENT:
		pgstev &= ~_PGSTE_GPS_USAGE_MASK;
		pgstev |= _PGSTE_GPS_USAGE_STABLE;
		/*
		 * Since the resident state can go away any time after this
		 * call, we will not make this page resident. We can revisit
		 * this decision if a guest will ever start using this.
		 */
		break;
	case ESSA_SET_STABLE_IF_RESIDENT:
		if (!(pte_val(*ptep) & _PAGE_INVALID)) {
			pgstev &= ~_PGSTE_GPS_USAGE_MASK;
			pgstev |= _PGSTE_GPS_USAGE_STABLE;
		}
		break;
	case ESSA_SET_STABLE_NODAT:
		pgstev &= ~_PGSTE_GPS_USAGE_MASK;
		pgstev |= _PGSTE_GPS_USAGE_STABLE | _PGSTE_GPS_NODAT;
		break;
	default:
		/* we should never get here! */
		break;
	}
	/* If we are discarding a page, set it to logical zero */
	if (res)
		pgstev |= _PGSTE_GPS_ZERO;

	pgste_val(pgste) = pgstev;
	pgste_set_unlock(ptep, pgste);
	pte_unmap_unlock(ptep, ptl);
	return res;
}
EXPORT_SYMBOL(pgste_perform_essa);

/**
 * set_pgste_bits - set specific PGSTE bits.
 * @mm: the memory context. It must have PGSTEs, no check is performed here!
 * @hva: the host virtual address of the page whose PGSTE is to be processed
 * @bits: a bitmask representing the bits that will be touched
 * @value: the values of the bits to be written. Only the bits in the mask
 *	   will be written.
 *
 * Return: 0 on success, < 0 in case of error.
 */
int set_pgste_bits(struct mm_struct *mm, unsigned long hva,
			unsigned long bits, unsigned long value)
{
	spinlock_t *ptl;
	pgste_t new;
	pte_t *ptep;

	ptep = get_locked_pte(mm, hva, &ptl);
	if (unlikely(!ptep))
		return -EFAULT;
	new = pgste_get_lock(ptep);

	pgste_val(new) &= ~bits;
	pgste_val(new) |= value & bits;

	pgste_set_unlock(ptep, new);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(set_pgste_bits);

/**
 * get_pgste - get the current PGSTE for the given address.
 * @mm: the memory context. It must have PGSTEs, no check is performed here!
 * @hva: the host virtual address of the page whose PGSTE is to be processed
 * @pgstep: will be written with the current PGSTE for the given address.
 *
 * Return: 0 on success, < 0 in case of error.
 */
int get_pgste(struct mm_struct *mm, unsigned long hva, unsigned long *pgstep)
{
	spinlock_t *ptl;
	pte_t *ptep;

	ptep = get_locked_pte(mm, hva, &ptl);
	if (unlikely(!ptep))
		return -EFAULT;
	*pgstep = pgste_val(pgste_get(ptep));
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(get_pgste);
#endif
