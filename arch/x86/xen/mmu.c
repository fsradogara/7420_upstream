/*
 * Xen mmu operations
 *
 * This file contains the various mmu fetch and update operations.
 * The most important job they must perform is the mapping between the
 * domain's pfn and the overall machine mfns.
 *
 * Xen allows guests to directly update the pagetable, in a controlled
 * fashion.  In other words, the guest modifies the same pagetable
 * that the CPU actually uses, which eliminates the overhead of having
 * a separate shadow pagetable.
 *
 * In order to allow this, it falls on the guest domain to map its
 * notion of a "physical" pfn - which is just a domain-local linear
 * address - into a real "machine address" which the CPU's MMU can
 * use.
 *
 * A pgd_t/pmd_t/pte_t will typically contain an mfn, and so can be
 * inserted directly into the pagetable.  When creating a new
 * pte/pmd/pgd, it converts the passed pfn into an mfn.  Conversely,
 * when reading the content back with __(pgd|pmd|pte)_val, it converts
 * the mfn back into a pfn.
 *
 * The other constraint is that all pages which make up a pagetable
 * must be mapped read-only in the guest.  This prevents uncontrolled
 * guest updates to the pagetable.  Xen strictly enforces this, and
 * will disallow any pagetable update which will end up mapping a
 * pagetable page RW, and will disallow using any writable page as a
 * pagetable.
 *
 * Naively, when loading %cr3 with the base of a new pagetable, Xen
 * would need to validate the whole pagetable before going on.
 * Naturally, this is quite slow.  The solution is to "pin" a
 * pagetable, which enforces all the constraints on the pagetable even
 * when it is not actively in use.  This menas that Xen can be assured
 * that it is still valid when you do load it into %cr3, and doesn't
 * need to revalidate it.
 *
 * Jeremy Fitzhardinge <jeremy@xensource.com>, XenSource Inc, 2007
 */
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/bug.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/seq_file.h>
#include <linux/crash_dump.h>

#include <trace/events/xen.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/fixmap.h>
#include <asm/mmu_context.h>
#include <asm/paravirt.h>
#include <asm/linkage.h>
#include <asm/setup.h>
#include <asm/paravirt.h>
#include <asm/e820.h>
#include <asm/linkage.h>
#include <asm/page.h>
#include <asm/init.h>
#include <asm/pat.h>
#include <asm/smp.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

#include <xen/page.h>
#include <xen/interface/xen.h>

#include "multicalls.h"
#include "mmu.h"
#include <xen/xen.h>
#include <xen/page.h>
#include <xen/interface/xen.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/version.h>
#include <linux/pfn.h>
#include <asm/xen/page.h>
#include <asm/xen/hypercall.h>
#include <xen/interface/memory.h>

#include "multicalls.h"
#include "mmu.h"

/*
 * Protects atomic reservation decrease/increase against concurrent increases.
 * Also protects non-atomic updates of current_pages and balloon lists.
 */
DEFINE_SPINLOCK(xen_reservation_lock);

#ifdef CONFIG_X86_32
/*
 * Identity map, in addition to plain kernel map.  This needs to be
 * large enough to allocate page table pages to allocate the rest.
 * Each page can map 2MB.
 */
#define LEVEL1_IDENT_ENTRIES	(PTRS_PER_PTE * 4)
static RESERVE_BRK_ARRAY(pte_t, level1_ident_pgt, LEVEL1_IDENT_ENTRIES);
#endif
#ifdef CONFIG_X86_64
/* l3 pud for userspace vsyscall mapping */
static pud_t level3_user_vsyscall[PTRS_PER_PUD] __page_aligned_bss;
#endif /* CONFIG_X86_64 */

/*
 * Note about cr3 (pagetable base) values:
 *
 * xen_cr3 contains the current logical cr3 value; it contains the
 * last set cr3.  This may not be the current effective cr3, because
 * its update may be being lazily deferred.  However, a vcpu looking
 * at its own cr3 can use this value knowing that it everything will
 * be self-consistent.
 *
 * xen_current_cr3 contains the actual vcpu cr3; it is set once the
 * hypercall to set the vcpu cr3 is complete (so it may be a little
 * out of date, but it will never be set early).  If one vcpu is
 * looking at another vcpu's cr3 value, it should use this variable.
 */
DEFINE_PER_CPU(unsigned long, xen_cr3);	 /* cr3 stored as physaddr */
DEFINE_PER_CPU(unsigned long, xen_current_cr3);	 /* actual vcpu cr3 */

static phys_addr_t xen_pt_base, xen_pt_size __initdata;

/*
 * Just beyond the highest usermode address.  STACK_TOP_MAX has a
 * redzone above it, so round it up to a PGD boundary.
 */
#define USER_LIMIT	((STACK_TOP_MAX + PGDIR_SIZE - 1) & PGDIR_MASK)


#define P2M_ENTRIES_PER_PAGE	(PAGE_SIZE / sizeof(unsigned long))
#define TOP_ENTRIES		(MAX_DOMAIN_PAGES / P2M_ENTRIES_PER_PAGE)

/* Placeholder for holes in the address space */
static unsigned long p2m_missing[P2M_ENTRIES_PER_PAGE] __page_aligned_data =
		{ [ 0 ... P2M_ENTRIES_PER_PAGE-1 ] = ~0UL };

 /* Array of pointers to pages containing p2m entries */
static unsigned long *p2m_top[TOP_ENTRIES] __page_aligned_data =
		{ [ 0 ... TOP_ENTRIES - 1] = &p2m_missing[0] };

/* Arrays of p2m arrays expressed in mfns used for save/restore */
static unsigned long p2m_top_mfn[TOP_ENTRIES] __page_aligned_bss;

static unsigned long p2m_top_mfn_list[TOP_ENTRIES / P2M_ENTRIES_PER_PAGE]
	__page_aligned_bss;

static inline unsigned p2m_top_index(unsigned long pfn)
{
	BUG_ON(pfn >= MAX_DOMAIN_PAGES);
	return pfn / P2M_ENTRIES_PER_PAGE;
}

static inline unsigned p2m_index(unsigned long pfn)
{
	return pfn % P2M_ENTRIES_PER_PAGE;
}

/* Build the parallel p2m_top_mfn structures */
void xen_setup_mfn_list_list(void)
{
	unsigned pfn, idx;

	for(pfn = 0; pfn < MAX_DOMAIN_PAGES; pfn += P2M_ENTRIES_PER_PAGE) {
		unsigned topidx = p2m_top_index(pfn);

		p2m_top_mfn[topidx] = virt_to_mfn(p2m_top[topidx]);
	}

	for(idx = 0; idx < ARRAY_SIZE(p2m_top_mfn_list); idx++) {
		unsigned topidx = idx * P2M_ENTRIES_PER_PAGE;
		p2m_top_mfn_list[idx] = virt_to_mfn(&p2m_top_mfn[topidx]);
	}

	BUG_ON(HYPERVISOR_shared_info == &xen_dummy_shared_info);

	HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
		virt_to_mfn(p2m_top_mfn_list);
	HYPERVISOR_shared_info->arch.max_pfn = xen_start_info->nr_pages;
}

/* Set up p2m_top to point to the domain-builder provided p2m pages */
void __init xen_build_dynamic_phys_to_machine(void)
{
	unsigned long *mfn_list = (unsigned long *)xen_start_info->mfn_list;
	unsigned long max_pfn = min(MAX_DOMAIN_PAGES, xen_start_info->nr_pages);
	unsigned pfn;

	for(pfn = 0; pfn < max_pfn; pfn += P2M_ENTRIES_PER_PAGE) {
		unsigned topidx = p2m_top_index(pfn);

		p2m_top[topidx] = &mfn_list[pfn];
	}
}

unsigned long get_phys_to_machine(unsigned long pfn)
{
	unsigned topidx, idx;

	if (unlikely(pfn >= MAX_DOMAIN_PAGES))
		return INVALID_P2M_ENTRY;

	topidx = p2m_top_index(pfn);
	idx = p2m_index(pfn);
	return p2m_top[topidx][idx];
}
EXPORT_SYMBOL_GPL(get_phys_to_machine);

static void alloc_p2m(unsigned long **pp, unsigned long *mfnp)
{
	unsigned long *p;
	unsigned i;

	p = (void *)__get_free_page(GFP_KERNEL | __GFP_NOFAIL);
	BUG_ON(p == NULL);

	for(i = 0; i < P2M_ENTRIES_PER_PAGE; i++)
		p[i] = INVALID_P2M_ENTRY;

	if (cmpxchg(pp, p2m_missing, p) != p2m_missing)
		free_page((unsigned long)p);
	else
		*mfnp = virt_to_mfn(p);
}

void set_phys_to_machine(unsigned long pfn, unsigned long mfn)
{
	unsigned topidx, idx;

	if (unlikely(xen_feature(XENFEAT_auto_translated_physmap))) {
		BUG_ON(pfn != mfn && mfn != INVALID_P2M_ENTRY);
		return;
	}

	if (unlikely(pfn >= MAX_DOMAIN_PAGES)) {
		BUG_ON(mfn != INVALID_P2M_ENTRY);
		return;
	}

	topidx = p2m_top_index(pfn);
	if (p2m_top[topidx] == p2m_missing) {
		/* no need to allocate a page to store an invalid entry */
		if (mfn == INVALID_P2M_ENTRY)
			return;
		alloc_p2m(&p2m_top[topidx], &p2m_top_mfn[topidx]);
	}

	idx = p2m_index(pfn);
	p2m_top[topidx][idx] = mfn;
unsigned long arbitrary_virt_to_mfn(void *vaddr)
{
	xmaddr_t maddr = arbitrary_virt_to_machine(vaddr);

	return PFN_DOWN(maddr.maddr);
}

xmaddr_t arbitrary_virt_to_machine(void *vaddr)
{
	unsigned long address = (unsigned long)vaddr;
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	unsigned offset = address & ~PAGE_MASK;

	BUG_ON(pte == NULL);

	return XMADDR(((phys_addr_t)pte_mfn(*pte) << PAGE_SHIFT) + offset);
}
	pte_t *pte;
	unsigned offset;

	/*
	 * if the PFN is in the linear mapped vaddr range, we can just use
	 * the (quick) virt_to_machine() p2m lookup
	 */
	if (virt_addr_valid(vaddr))
		return virt_to_machine(vaddr);

	/* otherwise we have to do a (slower) full page-table walk */

	pte = lookup_address(address, &level);
	BUG_ON(pte == NULL);
	offset = address & ~PAGE_MASK;
	return XMADDR(((phys_addr_t)pte_mfn(*pte) << PAGE_SHIFT) + offset);
}
EXPORT_SYMBOL_GPL(arbitrary_virt_to_machine);

void make_lowmem_page_readonly(void *vaddr)
{
	pte_t *pte, ptev;
	unsigned long address = (unsigned long)vaddr;
	unsigned int level;

	pte = lookup_address(address, &level);
	BUG_ON(pte == NULL);
	if (pte == NULL)
		return;		/* vaddr missing */

	ptev = pte_wrprotect(*pte);

	if (HYPERVISOR_update_va_mapping(address, ptev, 0))
		BUG();
}

void make_lowmem_page_readwrite(void *vaddr)
{
	pte_t *pte, ptev;
	unsigned long address = (unsigned long)vaddr;
	unsigned int level;

	pte = lookup_address(address, &level);
	BUG_ON(pte == NULL);
	if (pte == NULL)
		return;		/* vaddr missing */

	ptev = pte_mkwrite(*pte);

	if (HYPERVISOR_update_va_mapping(address, ptev, 0))
		BUG();
}


static bool page_pinned(void *ptr)
static bool xen_page_pinned(void *ptr)
{
	struct page *page = virt_to_page(ptr);

	return PagePinned(page);
}

static void extend_mmu_update(const struct mmu_update *update)
void xen_set_domain_pte(pte_t *ptep, pte_t pteval, unsigned domid)
{
	struct multicall_space mcs;
	struct mmu_update *u;

	trace_xen_mmu_set_domain_pte(ptep, pteval, domid);

	mcs = xen_mc_entry(sizeof(*u));
	u = mcs.args;

	/* ptep might be kmapped when using 32-bit HIGHPTE */
	u->ptr = virt_to_machine(ptep).maddr;
	u->val = pte_val_ma(pteval);

	MULTI_mmu_update(mcs.mc, mcs.args, 1, NULL, domid);

	xen_mc_issue(PARAVIRT_LAZY_MMU);
}
EXPORT_SYMBOL_GPL(xen_set_domain_pte);

static void xen_extend_mmu_update(const struct mmu_update *update)
{
	struct multicall_space mcs;
	struct mmu_update *u;

	mcs = xen_mc_extend_args(__HYPERVISOR_mmu_update, sizeof(*u));

	if (mcs.mc != NULL)
		mcs.mc->args[1]++;
	else {
	if (mcs.mc != NULL) {
		mcs.mc->args[1]++;
	} else {
		mcs = __xen_mc_entry(sizeof(*u));
		MULTI_mmu_update(mcs.mc, mcs.args, 1, NULL, DOMID_SELF);
	}

	u = mcs.args;
	*u = *update;
}

void xen_set_pmd_hyper(pmd_t *ptr, pmd_t val)
static void xen_extend_mmuext_op(const struct mmuext_op *op)
{
	struct multicall_space mcs;
	struct mmuext_op *u;

	mcs = xen_mc_extend_args(__HYPERVISOR_mmuext_op, sizeof(*u));

	if (mcs.mc != NULL) {
		mcs.mc->args[1]++;
	} else {
		mcs = __xen_mc_entry(sizeof(*u));
		MULTI_mmuext_op(mcs.mc, mcs.args, 1, NULL, DOMID_SELF);
	}

	u = mcs.args;
	*u = *op;
}

static void xen_set_pmd_hyper(pmd_t *ptr, pmd_t val)
{
	struct mmu_update u;

	preempt_disable();

	xen_mc_batch();

	/* ptr may be ioremapped for 64-bit pagetable setup */
	u.ptr = arbitrary_virt_to_machine(ptr).maddr;
	u.val = pmd_val_ma(val);
	extend_mmu_update(&u);
	xen_extend_mmu_update(&u);

	xen_mc_issue(PARAVIRT_LAZY_MMU);

	preempt_enable();
}

void xen_set_pmd(pmd_t *ptr, pmd_t val)
{
	/* If page is not pinned, we can just update the entry
	   directly */
	if (!page_pinned(ptr)) {
static void xen_set_pmd(pmd_t *ptr, pmd_t val)
{
	trace_xen_mmu_set_pmd(ptr, val);

	/* If page is not pinned, we can just update the entry
	   directly */
	if (!xen_page_pinned(ptr)) {
		*ptr = val;
		return;
	}

	xen_set_pmd_hyper(ptr, val);
}

/*
 * Associate a virtual page frame with a given physical page frame
 * and protection flags for that frame.
 */
void set_pte_mfn(unsigned long vaddr, unsigned long mfn, pgprot_t flags)
{
	set_pte_vaddr(vaddr, mfn_pte(mfn, flags));
}

void xen_set_pte_at(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, pte_t pteval)
{
	/* updates to init_mm may be done without lock */
	if (mm == &init_mm)
		preempt_disable();

	if (mm == current->mm || mm == &init_mm) {
		if (paravirt_get_lazy_mode() == PARAVIRT_LAZY_MMU) {
			struct multicall_space mcs;
			mcs = xen_mc_entry(0);

			MULTI_update_va_mapping(mcs.mc, addr, pteval, 0);
			xen_mc_issue(PARAVIRT_LAZY_MMU);
			goto out;
		} else
			if (HYPERVISOR_update_va_mapping(addr, pteval, 0) == 0)
				goto out;
	}
	xen_set_pte(ptep, pteval);

out:
	if (mm == &init_mm)
		preempt_enable();
}

pte_t xen_ptep_modify_prot_start(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	/* Just return the pte as-is.  We preserve the bits on commit */
static bool xen_batched_set_pte(pte_t *ptep, pte_t pteval)
{
	struct mmu_update u;

	if (paravirt_get_lazy_mode() != PARAVIRT_LAZY_MMU)
		return false;

	xen_mc_batch();

	u.ptr = virt_to_machine(ptep).maddr | MMU_NORMAL_PT_UPDATE;
	u.val = pte_val_ma(pteval);
	xen_extend_mmu_update(&u);

	xen_mc_issue(PARAVIRT_LAZY_MMU);

	return true;
}

static inline void __xen_set_pte(pte_t *ptep, pte_t pteval)
{
	if (!xen_batched_set_pte(ptep, pteval)) {
		/*
		 * Could call native_set_pte() here and trap and
		 * emulate the PTE write but with 32-bit guests this
		 * needs two traps (one for each of the two 32-bit
		 * words in the PTE) so do one hypercall directly
		 * instead.
		 */
		struct mmu_update u;

		u.ptr = virt_to_machine(ptep).maddr | MMU_NORMAL_PT_UPDATE;
		u.val = pte_val_ma(pteval);
		HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF);
	}
}

static void xen_set_pte(pte_t *ptep, pte_t pteval)
{
	trace_xen_mmu_set_pte(ptep, pteval);
	__xen_set_pte(ptep, pteval);
}

static void xen_set_pte_at(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, pte_t pteval)
{
	trace_xen_mmu_set_pte_at(mm, addr, ptep, pteval);
	__xen_set_pte(ptep, pteval);
}

pte_t xen_ptep_modify_prot_start(struct mm_struct *mm,
				 unsigned long addr, pte_t *ptep)
{
	/* Just return the pte as-is.  We preserve the bits on commit */
	trace_xen_mmu_ptep_modify_prot_start(mm, addr, ptep, *ptep);
	return *ptep;
}

void xen_ptep_modify_prot_commit(struct mm_struct *mm, unsigned long addr,
				 pte_t *ptep, pte_t pte)
{
	struct mmu_update u;

	trace_xen_mmu_ptep_modify_prot_commit(mm, addr, ptep, pte);
	xen_mc_batch();

	u.ptr = virt_to_machine(ptep).maddr | MMU_PT_UPDATE_PRESERVE_AD;
	u.val = pte_val_ma(pte);
	extend_mmu_update(&u);
	xen_extend_mmu_update(&u);

	xen_mc_issue(PARAVIRT_LAZY_MMU);
}

/* Assume pteval_t is equivalent to all the other *val_t types. */
static pteval_t pte_mfn_to_pfn(pteval_t val)
{
	if (val & _PAGE_PRESENT) {
		unsigned long mfn = (val & PTE_PFN_MASK) >> PAGE_SHIFT;
		pteval_t flags = val & PTE_FLAGS_MASK;
		val = ((pteval_t)mfn_to_pfn(mfn) << PAGE_SHIFT) | flags;
		unsigned long pfn = mfn_to_pfn(mfn);

		pteval_t flags = val & PTE_FLAGS_MASK;
		if (unlikely(pfn == ~0))
			val = flags & ~_PAGE_PRESENT;
		else
			val = ((pteval_t)pfn << PAGE_SHIFT) | flags;
	}

	return val;
}

static pteval_t pte_pfn_to_mfn(pteval_t val)
{
	if (val & _PAGE_PRESENT) {
		unsigned long pfn = (val & PTE_PFN_MASK) >> PAGE_SHIFT;
		pteval_t flags = val & PTE_FLAGS_MASK;
		val = ((pteval_t)pfn_to_mfn(pfn) << PAGE_SHIFT) | flags;
		unsigned long mfn;

		if (!xen_feature(XENFEAT_auto_translated_physmap))
			mfn = __pfn_to_mfn(pfn);
		else
			mfn = pfn;
		/*
		 * If there's no mfn for the pfn, then just create an
		 * empty non-present pte.  Unfortunately this loses
		 * information about the original pfn, so
		 * pte_mfn_to_pfn is asymmetric.
		 */
		if (unlikely(mfn == INVALID_P2M_ENTRY)) {
			mfn = 0;
			flags = 0;
		} else
			mfn &= ~(FOREIGN_FRAME_BIT | IDENTITY_FRAME_BIT);
		val = ((pteval_t)mfn << PAGE_SHIFT) | flags;
	}

	return val;
}

pteval_t xen_pte_val(pte_t pte)
{
	return pte_mfn_to_pfn(pte.pte);
}

pgdval_t xen_pgd_val(pgd_t pgd)
{
	return pte_mfn_to_pfn(pgd.pgd);
}

pte_t xen_make_pte(pteval_t pte)
{
	pte = pte_pfn_to_mfn(pte);
	return native_make_pte(pte);
}

pgd_t xen_make_pgd(pgdval_t pgd)
__visible pteval_t xen_pte_val(pte_t pte)
{
	pteval_t pteval = pte.pte;

	return pte_mfn_to_pfn(pteval);
}
PV_CALLEE_SAVE_REGS_THUNK(xen_pte_val);

__visible pgdval_t xen_pgd_val(pgd_t pgd)
{
	return pte_mfn_to_pfn(pgd.pgd);
}
PV_CALLEE_SAVE_REGS_THUNK(xen_pgd_val);

__visible pte_t xen_make_pte(pteval_t pte)
{
	pte = pte_pfn_to_mfn(pte);

	return native_make_pte(pte);
}
PV_CALLEE_SAVE_REGS_THUNK(xen_make_pte);

__visible pgd_t xen_make_pgd(pgdval_t pgd)
{
	pgd = pte_pfn_to_mfn(pgd);
	return native_make_pgd(pgd);
}

pmdval_t xen_pmd_val(pmd_t pmd)
{
	return pte_mfn_to_pfn(pmd.pmd);
}

void xen_set_pud_hyper(pud_t *ptr, pud_t val)
PV_CALLEE_SAVE_REGS_THUNK(xen_make_pgd);

__visible pmdval_t xen_pmd_val(pmd_t pmd)
{
	return pte_mfn_to_pfn(pmd.pmd);
}
PV_CALLEE_SAVE_REGS_THUNK(xen_pmd_val);

static void xen_set_pud_hyper(pud_t *ptr, pud_t val)
{
	struct mmu_update u;

	preempt_disable();

	xen_mc_batch();

	/* ptr may be ioremapped for 64-bit pagetable setup */
	u.ptr = arbitrary_virt_to_machine(ptr).maddr;
	u.val = pud_val_ma(val);
	extend_mmu_update(&u);
	xen_extend_mmu_update(&u);

	xen_mc_issue(PARAVIRT_LAZY_MMU);

	preempt_enable();
}

void xen_set_pud(pud_t *ptr, pud_t val)
{
	/* If page is not pinned, we can just update the entry
	   directly */
	if (!page_pinned(ptr)) {
static void xen_set_pud(pud_t *ptr, pud_t val)
{
	trace_xen_mmu_set_pud(ptr, val);

	/* If page is not pinned, we can just update the entry
	   directly */
	if (!xen_page_pinned(ptr)) {
		*ptr = val;
		return;
	}

	xen_set_pud_hyper(ptr, val);
}

void xen_set_pte(pte_t *ptep, pte_t pte)
{
#ifdef CONFIG_X86_PAE
	ptep->pte_high = pte.pte_high;
	smp_wmb();
	ptep->pte_low = pte.pte_low;
#else
	*ptep = pte;
#endif
}

#ifdef CONFIG_X86_PAE
void xen_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	set_64bit((u64 *)ptep, native_pte_val(pte));
}

void xen_pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	ptep->pte_low = 0;
	smp_wmb();		/* make sure low gets written first */
	ptep->pte_high = 0;
}

void xen_pmd_clear(pmd_t *pmdp)
{
#ifdef CONFIG_X86_PAE
static void xen_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	trace_xen_mmu_set_pte_atomic(ptep, pte);
	set_64bit((u64 *)ptep, native_pte_val(pte));
}

static void xen_pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	trace_xen_mmu_pte_clear(mm, addr, ptep);
	if (!xen_batched_set_pte(ptep, native_make_pte(0)))
		native_pte_clear(mm, addr, ptep);
}

static void xen_pmd_clear(pmd_t *pmdp)
{
	trace_xen_mmu_pmd_clear(pmdp);
	set_pmd(pmdp, __pmd(0));
}
#endif	/* CONFIG_X86_PAE */

pmd_t xen_make_pmd(pmdval_t pmd)
__visible pmd_t xen_make_pmd(pmdval_t pmd)
{
	pmd = pte_pfn_to_mfn(pmd);
	return native_make_pmd(pmd);
}

#if PAGETABLE_LEVELS == 4
pudval_t xen_pud_val(pud_t pud)
{
	return pte_mfn_to_pfn(pud.pud);
}

pud_t xen_make_pud(pudval_t pud)
PV_CALLEE_SAVE_REGS_THUNK(xen_make_pmd);

#if CONFIG_PGTABLE_LEVELS == 4
__visible pudval_t xen_pud_val(pud_t pud)
{
	return pte_mfn_to_pfn(pud.pud);
}
PV_CALLEE_SAVE_REGS_THUNK(xen_pud_val);

__visible pud_t xen_make_pud(pudval_t pud)
{
	pud = pte_pfn_to_mfn(pud);

	return native_make_pud(pud);
}

pgd_t *xen_get_user_pgd(pgd_t *pgd)
PV_CALLEE_SAVE_REGS_THUNK(xen_make_pud);

static pgd_t *xen_get_user_pgd(pgd_t *pgd)
{
	pgd_t *pgd_page = (pgd_t *)(((unsigned long)pgd) & PAGE_MASK);
	unsigned offset = pgd - pgd_page;
	pgd_t *user_ptr = NULL;

	if (offset < pgd_index(USER_LIMIT)) {
		struct page *page = virt_to_page(pgd_page);
		user_ptr = (pgd_t *)page->private;
		if (user_ptr)
			user_ptr += offset;
	}

	return user_ptr;
}

static void __xen_set_pgd_hyper(pgd_t *ptr, pgd_t val)
{
	struct mmu_update u;

	u.ptr = virt_to_machine(ptr).maddr;
	u.val = pgd_val_ma(val);
	extend_mmu_update(&u);
	xen_extend_mmu_update(&u);
}

/*
 * Raw hypercall-based set_pgd, intended for in early boot before
 * there's a page structure.  This implies:
 *  1. The only existing pagetable is the kernel's
 *  2. It is always pinned
 *  3. It has no user pagetable attached to it
 */
void __init xen_set_pgd_hyper(pgd_t *ptr, pgd_t val)
static void __init xen_set_pgd_hyper(pgd_t *ptr, pgd_t val)
{
	preempt_disable();

	xen_mc_batch();

	__xen_set_pgd_hyper(ptr, val);

	xen_mc_issue(PARAVIRT_LAZY_MMU);

	preempt_enable();
}

void xen_set_pgd(pgd_t *ptr, pgd_t val)
{
	pgd_t *user_ptr = xen_get_user_pgd(ptr);

	/* If page is not pinned, we can just update the entry
	   directly */
	if (!page_pinned(ptr)) {
		*ptr = val;
		if (user_ptr) {
			WARN_ON(page_pinned(user_ptr));
static void xen_set_pgd(pgd_t *ptr, pgd_t val)
{
	pgd_t *user_ptr = xen_get_user_pgd(ptr);

	trace_xen_mmu_set_pgd(ptr, user_ptr, val);

	/* If page is not pinned, we can just update the entry
	   directly */
	if (!xen_page_pinned(ptr)) {
		*ptr = val;
		if (user_ptr) {
			WARN_ON(xen_page_pinned(user_ptr));
			*user_ptr = val;
		}
		return;
	}

	/* If it's pinned, then we can at least batch the kernel and
	   user updates together. */
	xen_mc_batch();

	__xen_set_pgd_hyper(ptr, val);
	if (user_ptr)
		__xen_set_pgd_hyper(user_ptr, val);

	xen_mc_issue(PARAVIRT_LAZY_MMU);
}
#endif	/* PAGETABLE_LEVELS == 4 */
#endif	/* CONFIG_PGTABLE_LEVELS == 4 */

/*
 * (Yet another) pagetable walker.  This one is intended for pinning a
 * pagetable.  This means that it walks a pagetable and calls the
 * callback function on each page it finds making up the page table,
 * at every level.  It walks the entire pagetable, but it only bothers
 * pinning pte pages which are below limit.  In the normal case this
 * will be STACK_TOP_MAX, but at boot we need to pin up to
 * FIXADDR_TOP.
 *
 * For 32-bit the important bit is that we don't pin beyond there,
 * because then we start getting into Xen's ptes.
 *
 * For 64-bit, we must skip the Xen hole in the middle of the address
 * space, just after the big x86-64 virtual hole.
 */
static int pgd_walk(pgd_t *pgd, int (*func)(struct page *, enum pt_level),
		    unsigned long limit)
static int __xen_pgd_walk(struct mm_struct *mm, pgd_t *pgd,
			  int (*func)(struct mm_struct *mm, struct page *,
				      enum pt_level),
			  unsigned long limit)
{
	int flush = 0;
	unsigned hole_low, hole_high;
	unsigned pgdidx_limit, pudidx_limit, pmdidx_limit;
	unsigned pgdidx, pudidx, pmdidx;

	/* The limit is the last byte to be touched */
	limit--;
	BUG_ON(limit >= FIXADDR_TOP);

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return 0;

	/*
	 * 64-bit has a great big hole in the middle of the address
	 * space, which contains the Xen mappings.  On 32-bit these
	 * will end up making a zero-sized hole and so is a no-op.
	 */
	hole_low = pgd_index(USER_LIMIT);
	hole_high = pgd_index(PAGE_OFFSET);

	pgdidx_limit = pgd_index(limit);
#if PTRS_PER_PUD > 1
	pudidx_limit = pud_index(limit);
#else
	pudidx_limit = 0;
#endif
#if PTRS_PER_PMD > 1
	pmdidx_limit = pmd_index(limit);
#else
	pmdidx_limit = 0;
#endif

	flush |= (*func)(virt_to_page(pgd), PT_PGD);

	for (pgdidx = 0; pgdidx <= pgdidx_limit; pgdidx++) {
		pud_t *pud;

		if (pgdidx >= hole_low && pgdidx < hole_high)
			continue;

		if (!pgd_val(pgd[pgdidx]))
			continue;

		pud = pud_offset(&pgd[pgdidx], 0);

		if (PTRS_PER_PUD > 1) /* not folded */
			flush |= (*func)(virt_to_page(pud), PT_PUD);
			flush |= (*func)(mm, virt_to_page(pud), PT_PUD);

		for (pudidx = 0; pudidx < PTRS_PER_PUD; pudidx++) {
			pmd_t *pmd;

			if (pgdidx == pgdidx_limit &&
			    pudidx > pudidx_limit)
				goto out;

			if (pud_none(pud[pudidx]))
				continue;

			pmd = pmd_offset(&pud[pudidx], 0);

			if (PTRS_PER_PMD > 1) /* not folded */
				flush |= (*func)(virt_to_page(pmd), PT_PMD);
				flush |= (*func)(mm, virt_to_page(pmd), PT_PMD);

			for (pmdidx = 0; pmdidx < PTRS_PER_PMD; pmdidx++) {
				struct page *pte;

				if (pgdidx == pgdidx_limit &&
				    pudidx == pudidx_limit &&
				    pmdidx > pmdidx_limit)
					goto out;

				if (pmd_none(pmd[pmdidx]))
					continue;

				pte = pmd_page(pmd[pmdidx]);
				flush |= (*func)(pte, PT_PTE);
			}
		}
	}
out:
				flush |= (*func)(mm, pte, PT_PTE);
			}
		}
	}

out:
	/* Do the top level last, so that the callbacks can use it as
	   a cue to do final things like tlb flushes. */
	flush |= (*func)(mm, virt_to_page(pgd), PT_PGD);

	return flush;
}

static spinlock_t *lock_pte(struct page *page)
{
	spinlock_t *ptl = NULL;

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
	ptl = __pte_lockptr(page);
	spin_lock(ptl);
static int xen_pgd_walk(struct mm_struct *mm,
			int (*func)(struct mm_struct *mm, struct page *,
				    enum pt_level),
			unsigned long limit)
{
	return __xen_pgd_walk(mm, mm->pgd, func, limit);
}

/* If we're using split pte locks, then take the page's lock and
   return a pointer to it.  Otherwise return NULL. */
static spinlock_t *xen_pte_lock(struct page *page, struct mm_struct *mm)
{
	spinlock_t *ptl = NULL;

#if USE_SPLIT_PTE_PTLOCKS
	ptl = ptlock_ptr(page);
	spin_lock_nest_lock(ptl, &mm->page_table_lock);
#endif

	return ptl;
}

static void do_unlock(void *v)
static void xen_pte_unlock(void *v)
{
	spinlock_t *ptl = v;
	spin_unlock(ptl);
}

static void xen_do_pin(unsigned level, unsigned long pfn)
{
	struct mmuext_op *op;
	struct multicall_space mcs;

	mcs = __xen_mc_entry(sizeof(*op));
	op = mcs.args;
	op->cmd = level;
	op->arg1.mfn = pfn_to_mfn(pfn);
	MULTI_mmuext_op(mcs.mc, op, 1, NULL, DOMID_SELF);
}

static int pin_page(struct page *page, enum pt_level level)
	struct mmuext_op op;

	op.cmd = level;
	op.arg1.mfn = pfn_to_mfn(pfn);

	xen_extend_mmuext_op(&op);
}

static int xen_pin_page(struct mm_struct *mm, struct page *page,
			enum pt_level level)
{
	unsigned pgfl = TestSetPagePinned(page);
	int flush;

	if (pgfl)
		flush = 0;		/* already pinned */
	else if (PageHighMem(page))
		/* kmaps need flushing if we found an unpinned
		   highpage */
		flush = 1;
	else {
		void *pt = lowmem_page_address(page);
		unsigned long pfn = page_to_pfn(page);
		struct multicall_space mcs = __xen_mc_entry(0);
		spinlock_t *ptl;

		flush = 0;

		ptl = NULL;
		if (level == PT_PTE)
			ptl = lock_pte(page);
		/*
		 * We need to hold the pagetable lock between the time
		 * we make the pagetable RO and when we actually pin
		 * it.  If we don't, then other users may come in and
		 * attempt to update the pagetable by writing it,
		 * which will fail because the memory is RO but not
		 * pinned, so Xen won't do the trap'n'emulate.
		 *
		 * If we're using split pte locks, we can't hold the
		 * entire pagetable's worth of locks during the
		 * traverse, because we may wrap the preempt count (8
		 * bits).  The solution is to mark RO and pin each PTE
		 * page while holding the lock.  This means the number
		 * of locks we end up holding is never more than a
		 * batch size (~32 entries, at present).
		 *
		 * If we're not using split pte locks, we needn't pin
		 * the PTE pages independently, because we're
		 * protected by the overall pagetable lock.
		 */
		ptl = NULL;
		if (level == PT_PTE)
			ptl = xen_pte_lock(page, mm);

		MULTI_update_va_mapping(mcs.mc, (unsigned long)pt,
					pfn_pte(pfn, PAGE_KERNEL_RO),
					level == PT_PGD ? UVMF_TLB_FLUSH : 0);

		if (level == PT_PTE)
			xen_do_pin(MMUEXT_PIN_L1_TABLE, pfn);

		if (ptl) {
			/* Queue a deferred unlock for when this batch
			   is completed. */
			xen_mc_callback(do_unlock, ptl);
		if (ptl) {
			xen_do_pin(MMUEXT_PIN_L1_TABLE, pfn);

			/* Queue a deferred unlock for when this batch
			   is completed. */
			xen_mc_callback(xen_pte_unlock, ptl);
		}
	}

	return flush;
}

/* This is called just after a mm has been created, but it has not
   been used yet.  We need to make sure that its pagetable is all
   read-only, and can be pinned. */
void xen_pgd_pin(pgd_t *pgd)
{
	xen_mc_batch();

	if (pgd_walk(pgd, pin_page, USER_LIMIT)) {
		/* re-enable interrupts for kmap_flush_unused */
		xen_mc_issue(0);
		kmap_flush_unused();
static void __xen_pgd_pin(struct mm_struct *mm, pgd_t *pgd)
{
	trace_xen_mmu_pgd_pin(mm, pgd);

	xen_mc_batch();

	if (__xen_pgd_walk(mm, pgd, xen_pin_page, USER_LIMIT)) {
		/* re-enable interrupts for flushing */
		xen_mc_issue(0);

		kmap_flush_unused();

		xen_mc_batch();
	}

#ifdef CONFIG_X86_64
	{
		pgd_t *user_pgd = xen_get_user_pgd(pgd);

		xen_do_pin(MMUEXT_PIN_L4_TABLE, PFN_DOWN(__pa(pgd)));

		if (user_pgd) {
			pin_page(virt_to_page(user_pgd), PT_PGD);
			xen_do_pin(MMUEXT_PIN_L4_TABLE, PFN_DOWN(__pa(user_pgd)));
			xen_pin_page(mm, virt_to_page(user_pgd), PT_PGD);
			xen_do_pin(MMUEXT_PIN_L4_TABLE,
				   PFN_DOWN(__pa(user_pgd)));
		}
	}
#else /* CONFIG_X86_32 */
#ifdef CONFIG_X86_PAE
	/* Need to make sure unshared kernel PMD is pinnable */
	pin_page(virt_to_page(pgd_page(pgd[pgd_index(TASK_SIZE)])), PT_PMD);
	xen_pin_page(mm, pgd_page(pgd[pgd_index(TASK_SIZE)]),
		     PT_PMD);
#endif
	xen_do_pin(MMUEXT_PIN_L3_TABLE, PFN_DOWN(__pa(pgd)));
#endif /* CONFIG_X86_64 */
	xen_mc_issue(0);
}

static void xen_pgd_pin(struct mm_struct *mm)
{
	__xen_pgd_pin(mm, mm->pgd);
}

/*
 * On save, we need to pin all pagetables to make sure they get their
 * mfns turned into pfns.  Search the list for any unpinned pgds and pin
 * them (unpinned pgds are not currently in use, probably because the
 * process is under construction or destruction).
 */
void xen_mm_pin_all(void)
{
	unsigned long flags;
	struct page *page;

	spin_lock_irqsave(&pgd_lock, flags);

	list_for_each_entry(page, &pgd_list, lru) {
		if (!PagePinned(page)) {
			xen_pgd_pin((pgd_t *)page_address(page));
 *
 * Expected to be called in stop_machine() ("equivalent to taking
 * every spinlock in the system"), so the locking doesn't really
 * matter all that much.
 */
void xen_mm_pin_all(void)
{
	struct page *page;

	spin_lock(&pgd_lock);

	list_for_each_entry(page, &pgd_list, lru) {
		if (!PagePinned(page)) {
			__xen_pgd_pin(&init_mm, (pgd_t *)page_address(page));
			SetPageSavePinned(page);
		}
	}

	spin_unlock_irqrestore(&pgd_lock, flags);
	spin_unlock(&pgd_lock);
}

/*
 * The init_mm pagetable is really pinned as soon as its created, but
 * that's before we have page structures to store the bits.  So do all
 * the book-keeping now.
 */
static __init int mark_pinned(struct page *page, enum pt_level level)
static int __init xen_mark_pinned(struct mm_struct *mm, struct page *page,
				  enum pt_level level)
{
	SetPagePinned(page);
	return 0;
}

void __init xen_mark_init_mm_pinned(void)
{
	pgd_walk(init_mm.pgd, mark_pinned, FIXADDR_TOP);
}

static int unpin_page(struct page *page, enum pt_level level)
static void __init xen_mark_init_mm_pinned(void)
{
	xen_pgd_walk(&init_mm, xen_mark_pinned, FIXADDR_TOP);
}

static int xen_unpin_page(struct mm_struct *mm, struct page *page,
			  enum pt_level level)
{
	unsigned pgfl = TestClearPagePinned(page);

	if (pgfl && !PageHighMem(page)) {
		void *pt = lowmem_page_address(page);
		unsigned long pfn = page_to_pfn(page);
		spinlock_t *ptl = NULL;
		struct multicall_space mcs;

		if (level == PT_PTE) {
			ptl = lock_pte(page);

			xen_do_pin(MMUEXT_UNPIN_TABLE, pfn);
		/*
		 * Do the converse to pin_page.  If we're using split
		 * pte locks, we must be holding the lock for while
		 * the pte page is unpinned but still RO to prevent
		 * concurrent updates from seeing it in this
		 * partially-pinned state.
		 */
		if (level == PT_PTE) {
			ptl = xen_pte_lock(page, mm);

			if (ptl)
				xen_do_pin(MMUEXT_UNPIN_TABLE, pfn);
		}

		mcs = __xen_mc_entry(0);

		MULTI_update_va_mapping(mcs.mc, (unsigned long)pt,
					pfn_pte(pfn, PAGE_KERNEL),
					level == PT_PGD ? UVMF_TLB_FLUSH : 0);

		if (ptl) {
			/* unlock when batch completed */
			xen_mc_callback(do_unlock, ptl);
			xen_mc_callback(xen_pte_unlock, ptl);
		}
	}

	return 0;		/* never need to flush on unpin */
}

/* Release a pagetables pages back as normal RW */
static void xen_pgd_unpin(pgd_t *pgd)
{
static void __xen_pgd_unpin(struct mm_struct *mm, pgd_t *pgd)
{
	trace_xen_mmu_pgd_unpin(mm, pgd);

	xen_mc_batch();

	xen_do_pin(MMUEXT_UNPIN_TABLE, PFN_DOWN(__pa(pgd)));

#ifdef CONFIG_X86_64
	{
		pgd_t *user_pgd = xen_get_user_pgd(pgd);

		if (user_pgd) {
			xen_do_pin(MMUEXT_UNPIN_TABLE, PFN_DOWN(__pa(user_pgd)));
			unpin_page(virt_to_page(user_pgd), PT_PGD);
			xen_do_pin(MMUEXT_UNPIN_TABLE,
				   PFN_DOWN(__pa(user_pgd)));
			xen_unpin_page(mm, virt_to_page(user_pgd), PT_PGD);
		}
	}
#endif

#ifdef CONFIG_X86_PAE
	/* Need to make sure unshared kernel PMD is unpinned */
	pin_page(virt_to_page(pgd_page(pgd[pgd_index(TASK_SIZE)])), PT_PMD);
#endif

	pgd_walk(pgd, unpin_page, USER_LIMIT);
	xen_unpin_page(mm, pgd_page(pgd[pgd_index(TASK_SIZE)]),
		       PT_PMD);
#endif

	__xen_pgd_walk(mm, pgd, xen_unpin_page, USER_LIMIT);

	xen_mc_issue(0);
}

static void xen_pgd_unpin(struct mm_struct *mm)
{
	__xen_pgd_unpin(mm, mm->pgd);
}

/*
 * On resume, undo any pinning done at save, so that the rest of the
 * kernel doesn't see any unexpected pinned pagetables.
 */
void xen_mm_unpin_all(void)
{
	unsigned long flags;
	struct page *page;

	spin_lock_irqsave(&pgd_lock, flags);
	struct page *page;

	spin_lock(&pgd_lock);

	list_for_each_entry(page, &pgd_list, lru) {
		if (PageSavePinned(page)) {
			BUG_ON(!PagePinned(page));
			xen_pgd_unpin((pgd_t *)page_address(page));
			__xen_pgd_unpin(&init_mm, (pgd_t *)page_address(page));
			ClearPageSavePinned(page);
		}
	}

	spin_unlock_irqrestore(&pgd_lock, flags);
}

void xen_activate_mm(struct mm_struct *prev, struct mm_struct *next)
{
	spin_lock(&next->page_table_lock);
	xen_pgd_pin(next->pgd);
	spin_unlock(&next->page_table_lock);
}

void xen_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm)
{
	spin_lock(&mm->page_table_lock);
	xen_pgd_pin(mm->pgd);
	spin_unlock(&pgd_lock);
}

static void xen_activate_mm(struct mm_struct *prev, struct mm_struct *next)
{
	spin_lock(&next->page_table_lock);
	xen_pgd_pin(next);
	spin_unlock(&next->page_table_lock);
}

static void xen_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm)
{
	spin_lock(&mm->page_table_lock);
	xen_pgd_pin(mm);
	spin_unlock(&mm->page_table_lock);
}


#ifdef CONFIG_SMP
/* Another cpu may still have their %cr3 pointing at the pagetable, so
   we need to repoint it somewhere else before we can unpin it. */
static void drop_other_mm_ref(void *info)
{
	struct mm_struct *mm = info;
	struct mm_struct *active_mm;

#ifdef CONFIG_X86_64
	active_mm = read_pda(active_mm);
#else
	active_mm = __get_cpu_var(cpu_tlbstate).active_mm;
#endif

	if (active_mm == mm)
	active_mm = this_cpu_read(cpu_tlbstate.active_mm);

	if (active_mm == mm && this_cpu_read(cpu_tlbstate.state) != TLBSTATE_OK)
		leave_mm(smp_processor_id());

	/* If this cpu still has a stale cr3 reference, then make sure
	   it has been flushed. */
	if (x86_read_percpu(xen_current_cr3) == __pa(mm->pgd)) {
		load_cr3(swapper_pg_dir);
		arch_flush_lazy_cpu_mode();
	}
}

static void drop_mm_ref(struct mm_struct *mm)
{
	cpumask_t mask;
	if (this_cpu_read(xen_current_cr3) == __pa(mm->pgd))
		load_cr3(swapper_pg_dir);
}

static void xen_drop_mm_ref(struct mm_struct *mm)
{
	cpumask_var_t mask;
	unsigned cpu;

	if (current->active_mm == mm) {
		if (current->mm == mm)
			load_cr3(swapper_pg_dir);
		else
			leave_mm(smp_processor_id());
		arch_flush_lazy_cpu_mode();
	}

	/* Get the "official" set of cpus referring to our pagetable. */
	mask = mm->cpu_vm_mask;
	}

	/* Get the "official" set of cpus referring to our pagetable. */
	if (!alloc_cpumask_var(&mask, GFP_ATOMIC)) {
		for_each_online_cpu(cpu) {
			if (!cpumask_test_cpu(cpu, mm_cpumask(mm))
			    && per_cpu(xen_current_cr3, cpu) != __pa(mm->pgd))
				continue;
			smp_call_function_single(cpu, drop_other_mm_ref, mm, 1);
		}
		return;
	}
	cpumask_copy(mask, mm_cpumask(mm));

	/* It's possible that a vcpu may have a stale reference to our
	   cr3, because its in lazy mode, and it hasn't yet flushed
	   its set of pending hypercalls yet.  In this case, we can
	   look at its actual current cr3 value, and force it to flush
	   if needed. */
	for_each_online_cpu(cpu) {
		if (per_cpu(xen_current_cr3, cpu) == __pa(mm->pgd))
			cpu_set(cpu, mask);
	}

	if (!cpus_empty(mask))
		smp_call_function_mask(mask, drop_other_mm_ref, mm, 1);
}
#else
static void drop_mm_ref(struct mm_struct *mm)
			cpumask_set_cpu(cpu, mask);
	}

	if (!cpumask_empty(mask))
		smp_call_function_many(mask, drop_other_mm_ref, mm, 1);
	free_cpumask_var(mask);
}
#else
static void xen_drop_mm_ref(struct mm_struct *mm)
{
	if (current->active_mm == mm)
		load_cr3(swapper_pg_dir);
}
#endif

/*
 * While a process runs, Xen pins its pagetables, which means that the
 * hypervisor forces it to be read-only, and it controls all updates
 * to it.  This means that all pagetable updates have to go via the
 * hypervisor, which is moderately expensive.
 *
 * Since we're pulling the pagetable down, we switch to use init_mm,
 * unpin old process pagetable and mark it all read-write, which
 * allows further operations on it to be simple memory accesses.
 *
 * The only subtle point is that another CPU may be still using the
 * pagetable because of lazy tlb flushing.  This means we need need to
 * switch all CPUs off this pagetable before we can unpin it.
 */
void xen_exit_mmap(struct mm_struct *mm)
{
	get_cpu();		/* make sure we don't move around */
	drop_mm_ref(mm);
static void xen_exit_mmap(struct mm_struct *mm)
{
	get_cpu();		/* make sure we don't move around */
	xen_drop_mm_ref(mm);
	put_cpu();

	spin_lock(&mm->page_table_lock);

	/* pgd may not be pinned in the error exit path of execve */
	if (page_pinned(mm->pgd))
		xen_pgd_unpin(mm->pgd);

	spin_unlock(&mm->page_table_lock);
}
	if (xen_page_pinned(mm->pgd))
		xen_pgd_unpin(mm);

	spin_unlock(&mm->page_table_lock);
}

static void xen_post_allocator_init(void);

static void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
{
	struct mmuext_op op;

	op.cmd = cmd;
	op.arg1.mfn = pfn_to_mfn(pfn);
	if (HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF))
		BUG();
}

#ifdef CONFIG_X86_64
static void __init xen_cleanhighmap(unsigned long vaddr,
				    unsigned long vaddr_end)
{
	unsigned long kernel_end = roundup((unsigned long)_brk_end, PMD_SIZE) - 1;
	pmd_t *pmd = level2_kernel_pgt + pmd_index(vaddr);

	/* NOTE: The loop is more greedy than the cleanup_highmap variant.
	 * We include the PMD passed in on _both_ boundaries. */
	for (; vaddr <= vaddr_end && (pmd < (level2_kernel_pgt + PAGE_SIZE));
			pmd++, vaddr += PMD_SIZE) {
		if (pmd_none(*pmd))
			continue;
		if (vaddr < (unsigned long) _text || vaddr > kernel_end)
			set_pmd(pmd, __pmd(0));
	}
	/* In case we did something silly, we should crash in this function
	 * instead of somewhere later and be confusing. */
	xen_mc_flush();
}

/*
 * Make a page range writeable and free it.
 */
static void __init xen_free_ro_pages(unsigned long paddr, unsigned long size)
{
	void *vaddr = __va(paddr);
	void *vaddr_end = vaddr + size;

	for (; vaddr < vaddr_end; vaddr += PAGE_SIZE)
		make_lowmem_page_readwrite(vaddr);

	memblock_free(paddr, size);
}

static void __init xen_cleanmfnmap_free_pgtbl(void *pgtbl, bool unpin)
{
	unsigned long pa = __pa(pgtbl) & PHYSICAL_PAGE_MASK;

	if (unpin)
		pin_pagetable_pfn(MMUEXT_UNPIN_TABLE, PFN_DOWN(pa));
	ClearPagePinned(virt_to_page(__va(pa)));
	xen_free_ro_pages(pa, PAGE_SIZE);
}

/*
 * Since it is well isolated we can (and since it is perhaps large we should)
 * also free the page tables mapping the initial P->M table.
 */
static void __init xen_cleanmfnmap(unsigned long vaddr)
{
	unsigned long va = vaddr & PMD_MASK;
	unsigned long pa;
	pgd_t *pgd = pgd_offset_k(va);
	pud_t *pud_page = pud_offset(pgd, 0);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned int i;
	bool unpin;

	unpin = (vaddr == 2 * PGDIR_SIZE);
	set_pgd(pgd, __pgd(0));
	do {
		pud = pud_page + pud_index(va);
		if (pud_none(*pud)) {
			va += PUD_SIZE;
		} else if (pud_large(*pud)) {
			pa = pud_val(*pud) & PHYSICAL_PAGE_MASK;
			xen_free_ro_pages(pa, PUD_SIZE);
			va += PUD_SIZE;
		} else {
			pmd = pmd_offset(pud, va);
			if (pmd_large(*pmd)) {
				pa = pmd_val(*pmd) & PHYSICAL_PAGE_MASK;
				xen_free_ro_pages(pa, PMD_SIZE);
			} else if (!pmd_none(*pmd)) {
				pte = pte_offset_kernel(pmd, va);
				set_pmd(pmd, __pmd(0));
				for (i = 0; i < PTRS_PER_PTE; ++i) {
					if (pte_none(pte[i]))
						break;
					pa = pte_pfn(pte[i]) << PAGE_SHIFT;
					xen_free_ro_pages(pa, PAGE_SIZE);
				}
				xen_cleanmfnmap_free_pgtbl(pte, unpin);
			}
			va += PMD_SIZE;
			if (pmd_index(va))
				continue;
			set_pud(pud, __pud(0));
			xen_cleanmfnmap_free_pgtbl(pmd, unpin);
		}

	} while (pud_index(va) || pmd_index(va));
	xen_cleanmfnmap_free_pgtbl(pud_page, unpin);
}

static void __init xen_pagetable_p2m_free(void)
{
	unsigned long size;
	unsigned long addr;

	size = PAGE_ALIGN(xen_start_info->nr_pages * sizeof(unsigned long));

	/* No memory or already called. */
	if ((unsigned long)xen_p2m_addr == xen_start_info->mfn_list)
		return;

	/* using __ka address and sticking INVALID_P2M_ENTRY! */
	memset((void *)xen_start_info->mfn_list, 0xff, size);

	addr = xen_start_info->mfn_list;
	/*
	 * We could be in __ka space.
	 * We roundup to the PMD, which means that if anybody at this stage is
	 * using the __ka address of xen_start_info or
	 * xen_start_info->shared_info they are in going to crash. Fortunatly
	 * we have already revectored in xen_setup_kernel_pagetable and in
	 * xen_setup_shared_info.
	 */
	size = roundup(size, PMD_SIZE);

	if (addr >= __START_KERNEL_map) {
		xen_cleanhighmap(addr, addr + size);
		size = PAGE_ALIGN(xen_start_info->nr_pages *
				  sizeof(unsigned long));
		memblock_free(__pa(addr), size);
	} else {
		xen_cleanmfnmap(addr);
	}
}

static void __init xen_pagetable_cleanhighmap(void)
{
	unsigned long size;
	unsigned long addr;

	/* At this stage, cleanup_highmap has already cleaned __ka space
	 * from _brk_limit way up to the max_pfn_mapped (which is the end of
	 * the ramdisk). We continue on, erasing PMD entries that point to page
	 * tables - do note that they are accessible at this stage via __va.
	 * For good measure we also round up to the PMD - which means that if
	 * anybody is using __ka address to the initial boot-stack - and try
	 * to use it - they are going to crash. The xen_start_info has been
	 * taken care of already in xen_setup_kernel_pagetable. */
	addr = xen_start_info->pt_base;
	size = roundup(xen_start_info->nr_pt_frames * PAGE_SIZE, PMD_SIZE);

	xen_cleanhighmap(addr, addr + size);
	xen_start_info->pt_base = (unsigned long)__va(__pa(xen_start_info->pt_base));
#ifdef DEBUG
	/* This is superflous and is not neccessary, but you know what
	 * lets do it. The MODULES_VADDR -> MODULES_END should be clear of
	 * anything at this stage. */
	xen_cleanhighmap(MODULES_VADDR, roundup(MODULES_VADDR, PUD_SIZE) - 1);
#endif
}
#endif

static void __init xen_pagetable_p2m_setup(void)
{
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return;

	xen_vmalloc_p2m_tree();

#ifdef CONFIG_X86_64
	xen_pagetable_p2m_free();

	xen_pagetable_cleanhighmap();
#endif
	/* And revector! Bye bye old array */
	xen_start_info->mfn_list = (unsigned long)xen_p2m_addr;
}

static void __init xen_pagetable_init(void)
{
	paging_init();
	xen_post_allocator_init();

	xen_pagetable_p2m_setup();

	/* Allocate and initialize top and mid mfn levels for p2m structure */
	xen_build_mfn_list_list();

	/* Remap memory freed due to conflicts with E820 map */
	if (!xen_feature(XENFEAT_auto_translated_physmap))
		xen_remap_memory();

	xen_setup_shared_info();
}
static void xen_write_cr2(unsigned long cr2)
{
	this_cpu_read(xen_vcpu)->arch.cr2 = cr2;
}

static unsigned long xen_read_cr2(void)
{
	return this_cpu_read(xen_vcpu)->arch.cr2;
}

unsigned long xen_read_cr2_direct(void)
{
	return this_cpu_read(xen_vcpu_info.arch.cr2);
}

void xen_flush_tlb_all(void)
static void xen_flush_tlb_all(void)
{
	struct mmuext_op *op;
	struct multicall_space mcs;

	trace_xen_mmu_flush_tlb_all(0);

	preempt_disable();

	mcs = xen_mc_entry(sizeof(*op));

	op = mcs.args;
	op->cmd = MMUEXT_TLB_FLUSH_ALL;
	MULTI_mmuext_op(mcs.mc, op, 1, NULL, DOMID_SELF);

	xen_mc_issue(PARAVIRT_LAZY_MMU);

	preempt_enable();
}

#define REMAP_BATCH_SIZE 16

struct remap_data {
	xen_pfn_t *mfn;
	bool contiguous;
	pgprot_t prot;
	struct mmu_update *mmu_update;
};

static int remap_area_mfn_pte_fn(pte_t *ptep, pgtable_t token,
				 unsigned long addr, void *data)
{
	struct remap_data *rmd = data;
	pte_t pte = pte_mkspecial(mfn_pte(*rmd->mfn, rmd->prot));

	/* If we have a contiguous range, just update the mfn itself,
	   else update pointer to be "next mfn". */
	if (rmd->contiguous)
		(*rmd->mfn)++;
	else
		rmd->mfn++;

	rmd->mmu_update->ptr = virt_to_machine(ptep).maddr | MMU_NORMAL_PT_UPDATE;
	rmd->mmu_update->val = pte_val_ma(pte);
	rmd->mmu_update++;

	return 0;
}

static int do_remap_gfn(struct vm_area_struct *vma,
			unsigned long addr,
			xen_pfn_t *gfn, int nr,
			int *err_ptr, pgprot_t prot,
			unsigned domid,
			struct page **pages)
{
	int err = 0;
	struct remap_data rmd;
	struct mmu_update mmu_update[REMAP_BATCH_SIZE];
	unsigned long range;
	int mapped = 0;

	BUG_ON(!((vma->vm_flags & (VM_PFNMAP | VM_IO)) == (VM_PFNMAP | VM_IO)));

	rmd.mfn = gfn;
	rmd.prot = prot;
	/* We use the err_ptr to indicate if there we are doing a contiguous
	 * mapping or a discontigious mapping. */
	rmd.contiguous = !err_ptr;

	while (nr) {
		int index = 0;
		int done = 0;
		int batch = min(REMAP_BATCH_SIZE, nr);
		int batch_left = batch;
		range = (unsigned long)batch << PAGE_SHIFT;

		rmd.mmu_update = mmu_update;
		err = apply_to_page_range(vma->vm_mm, addr, range,
					  remap_area_mfn_pte_fn, &rmd);
		if (err)
			goto out;

		/* We record the error for each page that gives an error, but
		 * continue mapping until the whole set is done */
		do {
			int i;

			err = HYPERVISOR_mmu_update(&mmu_update[index],
						    batch_left, &done, domid);

			/*
			 * @err_ptr may be the same buffer as @gfn, so
			 * only clear it after each chunk of @gfn is
			 * used.
			 */
			if (err_ptr) {
				for (i = index; i < index + done; i++)
					err_ptr[i] = 0;
			}
			if (err < 0) {
				if (!err_ptr)
					goto out;
				err_ptr[i] = err;
				done++; /* Skip failed frame. */
			} else
				mapped += done;
			batch_left -= done;
			index += done;
		} while (batch_left);

		nr -= batch;
		addr += range;
		if (err_ptr)
			err_ptr += batch;
		cond_resched();
	}
out:

	xen_flush_tlb_all();

	return err < 0 ? err : mapped;
}

int xen_remap_domain_gfn_range(struct vm_area_struct *vma,
			       unsigned long addr,
			       xen_pfn_t gfn, int nr,
			       pgprot_t prot, unsigned domid,
			       struct page **pages)
{
	return do_remap_gfn(vma, addr, &gfn, nr, NULL, prot, domid, pages);
}
EXPORT_SYMBOL_GPL(xen_remap_domain_gfn_range);

int xen_remap_domain_gfn_array(struct vm_area_struct *vma,
			       unsigned long addr,
			       xen_pfn_t *gfn, int nr,
			       int *err_ptr, pgprot_t prot,
			       unsigned domid, struct page **pages)
{
	/* We BUG_ON because it's a programmer error to pass a NULL err_ptr,
	 * and the consequences later is quite hard to detect what the actual
	 * cause of "wrong memory was mapped in".
	 */
	BUG_ON(err_ptr == NULL);
	return do_remap_gfn(vma, addr, gfn, nr, err_ptr, prot, domid, pages);
}
EXPORT_SYMBOL_GPL(xen_remap_domain_gfn_array);

/* Returns: 0 success */
int xen_unmap_domain_gfn_range(struct vm_area_struct *vma,
			       int numpgs, struct page **pages)
{
	if (!pages || !xen_feature(XENFEAT_auto_translated_physmap))
		return 0;

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(xen_unmap_domain_gfn_range);
