/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins <hugh@veritas.com> 2003, 2004
 * Contributions by Hugh Dickins 2003, 2004
 */

/*
 * Lock ordering in mm:
 *
 * inode->i_mutex	(while writing or truncating, not reading or faulting)
 *   inode->i_alloc_sem (vmtruncate_range)
 *   mm->mmap_sem
 *     page->flags PG_locked (lock_page)
 *       mapping->i_mmap_lock
 *         anon_vma->lock
 *   mm->mmap_sem
 *     page->flags PG_locked (lock_page)
 *       mapping->i_mmap_rwsem
 *         anon_vma->rwsem
 *           mm->page_table_lock or pte_lock
 *             zone->lru_lock (in mark_page_accessed, isolate_lru_page)
 *             swap_lock (in swap_duplicate, swap_info_get)
 *               mmlist_lock (in mmput, drain_mmlist and others)
 *               mapping->private_lock (in __set_page_dirty_buffers)
 *               inode_lock (in set_page_dirty's __mark_inode_dirty)
 *                 sb_lock (within inode_lock in fs/fs-writeback.c)
 *                 mapping->tree_lock (widely used, in set_page_dirty,
 *                           in arch-dependent flush_dcache_mmap_lock,
 *                           within inode_lock in __sync_single_inode)
 *                 mem_cgroup_{begin,end}_page_stat (memcg->move_lock)
 *                   mapping->tree_lock (widely used)
 *               inode->i_lock (in set_page_dirty's __mark_inode_dirty)
 *               bdi.wb->list_lock (in set_page_dirty's __mark_inode_dirty)
 *                 sb_lock (within inode_lock in fs/fs-writeback.c)
 *                 mapping->tree_lock (widely used, in set_page_dirty,
 *                           in arch-dependent flush_dcache_mmap_lock,
 *                           within bdi.wb->list_lock in __sync_single_inode)
 *       hugetlbfs_i_mmap_rwsem_key (in huge_pmd_share)
 *         mapping->i_mmap_rwsem
 *           anon_vma->rwsem
 *             mm->page_table_lock or pte_lock
 *               zone_lru_lock (in mark_page_accessed, isolate_lru_page)
 *               swap_lock (in swap_duplicate, swap_info_get)
 *                 mmlist_lock (in mmput, drain_mmlist and others)
 *                 mapping->private_lock (in __set_page_dirty_buffers)
 *                   mem_cgroup_{begin,end}_page_stat (memcg->move_lock)
 *                     mapping->tree_lock (widely used)
 *                 inode->i_lock (in set_page_dirty's __mark_inode_dirty)
 *                 bdi.wb->list_lock (in set_page_dirty's __mark_inode_dirty)
 *                   sb_lock (within inode_lock in fs/fs-writeback.c)
 *                   mapping->tree_lock (widely used, in set_page_dirty,
 *                             in arch-dependent flush_dcache_mmap_lock,
 *                             within bdi.wb->list_lock in __sync_single_inode)
 *
 * anon_vma->rwsem,mapping->i_mutex      (memory_failure, collect_procs_anon)
 *   ->tasklist_lock
 *     pte map lock
 */

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>

#include <asm/tlbflush.h>

struct kmem_cache *anon_vma_cachep;

/* This must be called under the mmap_sem. */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/backing-dev.h>
#include <linux/page_idle.h>
#include <linux/memremap.h>

#include <asm/tlbflush.h>

#include <trace/events/tlb.h>

#include "internal.h"

static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;

static inline struct anon_vma *anon_vma_alloc(void)
{
	struct anon_vma *anon_vma;

	anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_KERNEL);
	if (anon_vma) {
		atomic_set(&anon_vma->refcount, 1);
		anon_vma->degree = 1;	/* Reference for first vma */
		anon_vma->parent = anon_vma;
		/*
		 * Initialise the anon_vma root to point to itself. If called
		 * from fork, the root will be reset to the parents anon_vma.
		 */
		anon_vma->root = anon_vma;
	}

	return anon_vma;
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
	VM_BUG_ON(atomic_read(&anon_vma->refcount));

	/*
	 * Synchronize against page_lock_anon_vma_read() such that
	 * we can safely hold the lock without the anon_vma getting
	 * freed.
	 *
	 * Relies on the full mb implied by the atomic_dec_and_test() from
	 * put_anon_vma() against the acquire barrier implied by
	 * down_read_trylock() from page_lock_anon_vma_read(). This orders:
	 *
	 * page_lock_anon_vma_read()	VS	put_anon_vma()
	 *   down_read_trylock()		  atomic_dec_and_test()
	 *   LOCK				  MB
	 *   atomic_read()			  rwsem_is_locked()
	 *
	 * LOCK should suffice since the actual taking of the lock must
	 * happen _before_ what follows.
	 */
	might_sleep();
	if (rwsem_is_locked(&anon_vma->root->rwsem)) {
		anon_vma_lock_write(anon_vma);
		anon_vma_unlock_write(anon_vma);
	}

	kmem_cache_free(anon_vma_cachep, anon_vma);
}

static inline struct anon_vma_chain *anon_vma_chain_alloc(gfp_t gfp)
{
	return kmem_cache_alloc(anon_vma_chain_cachep, gfp);
}

static void anon_vma_chain_free(struct anon_vma_chain *anon_vma_chain)
{
	kmem_cache_free(anon_vma_chain_cachep, anon_vma_chain);
}

static void anon_vma_chain_link(struct vm_area_struct *vma,
				struct anon_vma_chain *avc,
				struct anon_vma *anon_vma)
{
	avc->vma = vma;
	avc->anon_vma = anon_vma;
	list_add(&avc->same_vma, &vma->anon_vma_chain);
	anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
}

/**
 * __anon_vma_prepare - attach an anon_vma to a memory region
 * @vma: the memory region in question
 *
 * This makes sure the memory mapping described by 'vma' has
 * an 'anon_vma' attached to it, so that we can associate the
 * anonymous pages mapped into it with that anon_vma.
 *
 * The common case will be that we already have one, which
 * is handled inline by anon_vma_prepare(). But if
 * not we either need to find an adjacent mapping that we
 * can re-use the anon_vma from (very common when the only
 * reason for splitting a vma has been mprotect()), or we
 * allocate a new one.
 *
 * Anon-vma allocations are very subtle, because we may have
 * optimistically looked up an anon_vma in page_lock_anon_vma_read()
 * and that may actually touch the spinlock even in the newly
 * allocated vma (it depends on RCU to make sure that the
 * anon_vma isn't actually destroyed).
 *
 * As a result, we need to do proper anon_vma locking even
 * for the new allocation. At the same time, we do not want
 * to do any locking for the common case of already having
 * an anon_vma.
 *
 * This must be called with the mmap_sem held for reading.
 */
int __anon_vma_prepare(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct anon_vma *anon_vma, *allocated;
	struct anon_vma_chain *avc;

	might_sleep();
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated, *locked;

		anon_vma = find_mergeable_anon_vma(vma);
		if (anon_vma) {
			allocated = NULL;
			locked = anon_vma;
			spin_lock(&locked->lock);
		} else {
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				return -ENOMEM;
			allocated = anon_vma;
			locked = NULL;
		}

		struct anon_vma *allocated;

	avc = anon_vma_chain_alloc(GFP_KERNEL);
	if (!avc)
		goto out_enomem;

		anon_vma = find_mergeable_anon_vma(vma);
		allocated = NULL;
		if (!anon_vma) {
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				goto out_enomem_free_avc;
			allocated = anon_vma;
		}

		anon_vma_lock_write(anon_vma);
		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);
		if (likely(!vma->anon_vma)) {
			vma->anon_vma = anon_vma;
			list_add_tail(&vma->anon_vma_node, &anon_vma->head);
			allocated = NULL;
		}
		spin_unlock(&mm->page_table_lock);

		if (locked)
			spin_unlock(&locked->lock);
		if (unlikely(allocated))
			anon_vma_free(allocated);
	}
	return 0;
}

void __anon_vma_merge(struct vm_area_struct *vma, struct vm_area_struct *next)
{
	BUG_ON(vma->anon_vma != next->anon_vma);
	list_del(&next->anon_vma_node);
}

void __anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma)
		list_add_tail(&vma->anon_vma_node, &anon_vma->head);
}

void anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		list_add_tail(&vma->anon_vma_node, &anon_vma->head);
		spin_unlock(&anon_vma->lock);
	}
}

void anon_vma_unlink(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int empty;

	if (!anon_vma)
		return;

	spin_lock(&anon_vma->lock);
	list_del(&vma->anon_vma_node);

	/* We must garbage collect the anon_vma if it's empty */
	empty = list_empty(&anon_vma->head);
	spin_unlock(&anon_vma->lock);

	if (empty)
		anon_vma_free(anon_vma);
			anon_vma_chain_link(vma, avc, anon_vma);
			/* vma reference or self-parent link for new root */
			anon_vma->degree++;
			allocated = NULL;
			avc = NULL;
		}
		spin_unlock(&mm->page_table_lock);
		anon_vma_unlock_write(anon_vma);

		if (unlikely(allocated))
			put_anon_vma(allocated);
		if (unlikely(avc))
			anon_vma_chain_free(avc);
	anon_vma = find_mergeable_anon_vma(vma);
	allocated = NULL;
	if (!anon_vma) {
		anon_vma = anon_vma_alloc();
		if (unlikely(!anon_vma))
			goto out_enomem_free_avc;
		allocated = anon_vma;
	}

	anon_vma_lock_write(anon_vma);
	/* page_table_lock to protect against threads */
	spin_lock(&mm->page_table_lock);
	if (likely(!vma->anon_vma)) {
		vma->anon_vma = anon_vma;
		anon_vma_chain_link(vma, avc, anon_vma);
		/* vma reference or self-parent link for new root */
		anon_vma->degree++;
		allocated = NULL;
		avc = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	anon_vma_unlock_write(anon_vma);

	if (unlikely(allocated))
		put_anon_vma(allocated);
	if (unlikely(avc))
		anon_vma_chain_free(avc);

	return 0;

 out_enomem_free_avc:
	anon_vma_chain_free(avc);
 out_enomem:
	return -ENOMEM;
}

/*
 * This is a useful helper function for locking the anon_vma root as
 * we traverse the vma->anon_vma_chain, looping over anon_vma's that
 * have the same vma.
 *
 * Such anon_vma's should have the same root, so you'd expect to see
 * just a single mutex_lock for the whole traversal.
 */
static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
	struct anon_vma *new_root = anon_vma->root;
	if (new_root != root) {
		if (WARN_ON_ONCE(root))
			up_write(&root->rwsem);
		root = new_root;
		down_write(&root->rwsem);
	}
	return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
	if (root)
		up_write(&root->rwsem);
}

/*
 * Attach the anon_vmas from src to dst.
 * Returns 0 on success, -ENOMEM on failure.
 *
 * If dst->anon_vma is NULL this function tries to find and reuse existing
 * anon_vma which has no vmas and only one child anon_vma. This prevents
 * degradation of anon_vma hierarchy to endless linear chain in case of
 * constantly forking task. On the other hand, an anon_vma with more than one
 * child isn't reused even if there was no alive vma, thus rmap walker has a
 * good chance of avoiding scanning the whole hierarchy when it searches where
 * page is mapped.
 */
int anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct anon_vma_chain *avc, *pavc;
	struct anon_vma *root = NULL;

	list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma;

		avc = anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
		if (unlikely(!avc)) {
			unlock_anon_vma_root(root);
			root = NULL;
			avc = anon_vma_chain_alloc(GFP_KERNEL);
			if (!avc)
				goto enomem_failure;
		}
		anon_vma = pavc->anon_vma;
		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_chain_link(dst, avc, anon_vma);

		/*
		 * Reuse existing anon_vma if its degree lower than two,
		 * that means it has no vma and only one anon_vma child.
		 *
		 * Do not chose parent anon_vma, otherwise first child
		 * will always reuse it. Root anon_vma is never reused:
		 * it has self-parent reference and at least one child.
		 */
		if (!dst->anon_vma && anon_vma != src->anon_vma &&
				anon_vma->degree < 2)
			dst->anon_vma = anon_vma;
	}
	if (dst->anon_vma)
		dst->anon_vma->degree++;
	unlock_anon_vma_root(root);
	return 0;

 enomem_failure:
	/*
	 * dst->anon_vma is dropped here otherwise its degree can be incorrectly
	 * decremented in unlink_anon_vmas().
	 * We can safely do this because callers of anon_vma_clone() don't care
	 * about dst->anon_vma if anon_vma_clone() failed.
	 */
	dst->anon_vma = NULL;
	unlink_anon_vmas(dst);
	return -ENOMEM;
}

/*
 * Attach vma to its own anon_vma, as well as to the anon_vmas that
 * the corresponding VMA in the parent process is attached to.
 * Returns 0 on success, non-zero on failure.
 */
int anon_vma_fork(struct vm_area_struct *vma, struct vm_area_struct *pvma)
{
	struct anon_vma_chain *avc;
	struct anon_vma *anon_vma;
	int error;

	/* Don't bother if the parent process has no anon_vma here. */
	if (!pvma->anon_vma)
		return 0;

	/* Drop inherited anon_vma, we'll reuse existing or allocate new. */
	vma->anon_vma = NULL;

	/*
	 * First, attach the new VMA to the parent VMA's anon_vmas,
	 * so rmap can find non-COWed pages in child processes.
	 */
	error = anon_vma_clone(vma, pvma);
	if (error)
		return error;

	/* An existing anon_vma has been reused, all done then. */
	if (vma->anon_vma)
		return 0;

	/* Then add our own anon_vma. */
	anon_vma = anon_vma_alloc();
	if (!anon_vma)
		goto out_error;
	avc = anon_vma_chain_alloc(GFP_KERNEL);
	if (!avc)
		goto out_error_free_anon_vma;

	/*
	 * The root anon_vma's spinlock is the lock actually used when we
	 * lock any of the anon_vmas in this anon_vma tree.
	 */
	anon_vma->root = pvma->anon_vma->root;
	anon_vma->parent = pvma->anon_vma;
	/*
	 * With refcounts, an anon_vma can stay around longer than the
	 * process it belongs to. The root anon_vma needs to be pinned until
	 * this anon_vma is freed, because the lock lives in the root.
	 */
	get_anon_vma(anon_vma->root);
	/* Mark this anon_vma as the one where our new (COWed) pages go. */
	vma->anon_vma = anon_vma;
	anon_vma_lock_write(anon_vma);
	anon_vma_chain_link(vma, avc, anon_vma);
	anon_vma->parent->degree++;
	anon_vma_unlock_write(anon_vma);

	return 0;

 out_error_free_anon_vma:
	put_anon_vma(anon_vma);
 out_error:
	unlink_anon_vmas(vma);
	return -ENOMEM;
}

void unlink_anon_vmas(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc, *next;
	struct anon_vma *root = NULL;

	/*
	 * Unlink each anon_vma chained to the VMA.  This list is ordered
	 * from newest to oldest, ensuring the root anon_vma gets freed last.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_interval_tree_remove(avc, &anon_vma->rb_root);

		/*
		 * Leave empty anon_vmas on the list - we'll need
		 * to free them outside the lock.
		 */
		if (RB_EMPTY_ROOT(&anon_vma->rb_root.rb_root)) {
			anon_vma->parent->degree--;
			continue;
		}

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
	if (vma->anon_vma)
		vma->anon_vma->degree--;
	unlock_anon_vma_root(root);

	/*
	 * Iterate the list once more, it now only contains empty and unlinked
	 * anon_vmas, destroy them. Could not do before due to __put_anon_vma()
	 * needing to write-acquire the anon_vma->root->rwsem.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		VM_WARN_ON(anon_vma->degree);
		put_anon_vma(anon_vma);

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
}

static void anon_vma_ctor(void *data)
{
	struct anon_vma *anon_vma = data;

	spin_lock_init(&anon_vma->lock);
	INIT_LIST_HEAD(&anon_vma->head);
	init_rwsem(&anon_vma->rwsem);
	atomic_set(&anon_vma->refcount, 0);
	anon_vma->rb_root = RB_ROOT_CACHED;
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is
 * tricky: page_lock_anon_vma rely on RCU to guard against the races.
 */
static struct anon_vma *page_lock_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long) page->mapping;
	if (!(anon_mapping & PAGE_MAPPING_ANON))
	anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain, SLAB_PANIC);
			0, SLAB_TYPESAFE_BY_RCU|SLAB_PANIC|SLAB_ACCOUNT,
			anon_vma_ctor);
	anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain,
			SLAB_PANIC|SLAB_ACCOUNT);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is tricky!
 *
 * Since there is no serialization what so ever against page_remove_rmap()
 * the best this function can do is return a locked anon_vma that might
 * have been relevant to this page.
 *
 * The page might have been remapped to a different anon_vma or the anon_vma
 * returned may already be freed (and even reused).
 *
 * In case it was remapped to a different anon_vma, the new anon_vma will be a
 * child of the old anon_vma, and the anon_vma lifetime rules will therefore
 * ensure that any anon_vma obtained from the page will still be valid for as
 * long as we observe page_mapped() [ hence all those page_mapped() tests ].
 *
 * All users of this function must be very careful when walking the anon_vma
 * chain and verify that the page in question is indeed mapped in it
 * [ something equivalent to page_mapped_in_vma() ].
 *
 * Since anon_vma's slab is DESTROY_BY_RCU and we know from page_remove_rmap()
 * that the anon_vma pointer from page->mapping is valid if there is a
 * mapcount, we can dereference the anon_vma after observing those.
 */
struct anon_vma *page_get_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long)READ_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	spin_lock(&anon_vma->lock);
	return anon_vma;
out:
	rcu_read_unlock();
	return NULL;
}

static void page_unlock_anon_vma(struct anon_vma *anon_vma)
{
	spin_unlock(&anon_vma->lock);
	rcu_read_unlock();
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	/*
	 * If this page is still mapped, then its anon_vma cannot have been
	 * freed.  But if it has been unmapped, we have no security against the
	 * anon_vma structure being freed and reused (for another anon_vma:
	 * SLAB_TYPESAFE_BY_RCU guarantees that - so the atomic_inc_not_zero()
	 * above cannot corrupt).
	 */
	if (!page_mapped(page)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}
out:
	rcu_read_unlock();

	return anon_vma;
}

/*
 * Similar to page_get_anon_vma() except it locks the anon_vma.
 *
 * Its a little more complex as it tries to keep the fast path to a single
 * atomic op -- the trylock. If we fail the trylock, we fall back to getting a
 * reference like with page_get_anon_vma() and then block on the mutex.
 */
struct anon_vma *page_lock_anon_vma_read(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	struct anon_vma *root_anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long)READ_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	root_anon_vma = READ_ONCE(anon_vma->root);
	if (down_read_trylock(&root_anon_vma->rwsem)) {
		/*
		 * If the page is still mapped, then this anon_vma is still
		 * its anon_vma, and holding the mutex ensures that it will
		 * not go away, see anon_vma_free().
		 */
		if (!page_mapped(page)) {
			up_read(&root_anon_vma->rwsem);
			anon_vma = NULL;
		}
		goto out;
	}

	/* trylock failed, we got to sleep */
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	if (!page_mapped(page)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}

	/* we pinned the anon_vma, its safe to sleep */
	rcu_read_unlock();
	anon_vma_lock_read(anon_vma);

	if (atomic_dec_and_test(&anon_vma->refcount)) {
		/*
		 * Oops, we held the last refcount, release the lock
		 * and bail -- can't simply use put_anon_vma() because
		 * we'll deadlock on the anon_vma_lock_write() recursion.
		 */
		anon_vma_unlock_read(anon_vma);
		__put_anon_vma(anon_vma);
		anon_vma = NULL;
	}

	return anon_vma;

out:
	rcu_read_unlock();
	return anon_vma;
}

void page_unlock_anon_vma_read(struct anon_vma *anon_vma)
{
	anon_vma_unlock_read(anon_vma);
}

/*
 * At what user virtual address is page expected in @vma?
 * Returns virtual address or -EFAULT if page's index/offset is not
 * within the range mapped the @vma.
 */
static inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	unsigned long address;

	address = vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end)) {
		/* page should be within @vma mapping range */
		return -EFAULT;
	}
	return address;
}

/*
 * At what user virtual address is page expected in vma? checking that the
 * page matches the vma: currently only used on anon pages, by unuse_vma;
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	if (PageAnon(page)) {
		if ((void *)vma->anon_vma !=
		    (void *)page->mapping - PAGE_MAPPING_ANON)
			return -EFAULT;
	} else if (page->mapping && !(vma->vm_flags & VM_NONLINEAR)) {
		if (!vma->vm_file ||
		    vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	return vma_address(page, vma);
 */
static inline unsigned long
__vma_address(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page_to_pgoff(page);
	return vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
}

inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address = __vma_address(page, vma);

	/* page should be within @vma mapping range */
	VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);

	return address;
}

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
/*
 * Flush TLB entries for recently unmapped pages from remote CPUs. It is
 * important if a PTE was dirty when it was unmapped that it's flushed
 * before any IO is initiated on the page to prevent lost writes. Similarly,
 * it must be flushed before freeing to prevent data leakage.
 */
void try_to_unmap_flush(void)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	if (!tlb_ubc->flush_required)
		return;

	arch_tlbbatch_flush(&tlb_ubc->arch);
	tlb_ubc->flush_required = false;
	tlb_ubc->writable = false;
}

/* Flush iff there are potentially writable TLB entries that can race with IO */
void try_to_unmap_flush_dirty(void)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	if (tlb_ubc->writable)
		try_to_unmap_flush();
}

static void set_tlb_ubc_flush_pending(struct mm_struct *mm, bool writable)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	arch_tlbbatch_add_mm(&tlb_ubc->arch, mm);
	tlb_ubc->flush_required = true;

	/*
	 * Ensure compiler does not re-order the setting of tlb_flush_batched
	 * before the PTE is cleared.
	 */
	barrier();
	mm->tlb_flush_batched = true;

	/*
	 * If the PTE was dirty then it's best to assume it's writable. The
	 * caller must use try_to_unmap_flush_dirty() or try_to_unmap_flush()
	 * before the page is queued for IO.
	 */
	if (writable)
		tlb_ubc->writable = true;
}

/*
 * Returns true if the TLB flush should be deferred to the end of a batch of
 * unmap operations to reduce IPIs.
 */
static bool should_defer_flush(struct mm_struct *mm, enum ttu_flags flags)
{
	bool should_defer = false;

	if (!(flags & TTU_BATCH_FLUSH))
		return false;

	/* If remote CPUs need to be flushed then defer batch the flush */
	if (cpumask_any_but(mm_cpumask(mm), get_cpu()) < nr_cpu_ids)
		should_defer = true;
	put_cpu();

	return should_defer;
}

/*
 * Reclaim unmaps pages under the PTL but do not flush the TLB prior to
 * releasing the PTL if TLB flushes are batched. It's possible for a parallel
 * operation such as mprotect or munmap to race between reclaim unmapping
 * the page and flushing the page. If this race occurs, it potentially allows
 * access to data via a stale TLB entry. Tracking all mm's that have TLB
 * batching in flight would be expensive during reclaim so instead track
 * whether TLB batching occurred in the past and if so then do a flush here
 * if required. This will cost one additional flush per reclaim cycle paid
 * by the first operation at risk such as mprotect and mumap.
 *
 * This must be called under the PTL so that an access to tlb_flush_batched
 * that is potentially a "reclaim vs mprotect/munmap/etc" race will synchronise
 * via the PTL.
 */
void flush_tlb_batched_pending(struct mm_struct *mm)
{
	if (mm->tlb_flush_batched) {
		flush_tlb_mm(mm);

		/*
		 * Do not allow the compiler to re-order the clearing of
		 * tlb_flush_batched before the tlb is flushed.
		 */
		barrier();
		mm->tlb_flush_batched = false;
	}
}
#else
static void set_tlb_ubc_flush_pending(struct mm_struct *mm, bool writable)
{
}

static bool should_defer_flush(struct mm_struct *mm, enum ttu_flags flags)
{
	return false;
}
#endif /* CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH */

/*
 * At what user virtual address is page expected in vma?
 * Caller should check the page is actually part of the vma.
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	if (PageAnon(page)) {
		struct anon_vma *page__anon_vma = page_anon_vma(page);
		/*
		 * Note: swapoff's unuse_vma() is more efficient with this
		 * check, and needs it to match anon_vma when KSM is active.
		 */
		if (!vma->anon_vma || !page__anon_vma ||
		    vma->anon_vma->root != page__anon_vma->root)
			return -EFAULT;
	} else if (page->mapping) {
		if (!vma->vm_file || vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	address = __vma_address(page, vma);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		return -EFAULT;
	return address;
}

pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd = NULL;
	pmd_t pmde;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	/*
	 * Some THP functions use the sequence pmdp_huge_clear_flush(), set_pmd_at()
	 * without holding anon_vma lock for write.  So when looking for a
	 * genuine pmde (in which to find pte), test present and !THP together.
	 */
	pmde = *pmd;
	barrier();
	if (!pmd_present(pmde) || pmd_trans_huge(pmde))
		pmd = NULL;
out:
	return pmd;
}

/*
 * Check that @page is mapped at @address into @mm.
 *
 * If @sync is false, page_check_address may perform a racy check to avoid
 * the page table lock when the pte is not present (helpful when reclaiming
 * highly shared pages).
 *
 * On success returns with pte mapped and locked.
 */
pte_t *page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync)
{
	pgd_t *pgd;
	pud_t *pud;
pte_t *__page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync)
{
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
	if (unlikely(PageHuge(page))) {
		/* when pud is not present, pte will be NULL */
		pte = huge_pte_offset(mm, address);
		if (!pte)
			return NULL;

		ptl = huge_pte_lockptr(page_hstate(page), mm, pte);
		goto check;
	}

	pmd = mm_find_pmd(mm, address);
	if (!pmd)
		return NULL;

	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	if (!sync && !pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	ptl = pte_lockptr(mm, pmd);
check:
	spin_lock(ptl);
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		return pte;
	}
	pte_unmap_unlock(pte, ptl);
	return NULL;
}

/*
 * Subfunctions of page_referenced: page_referenced_one called
 * repeatedly from either page_referenced_anon or page_referenced_file.
 */
static int page_referenced_one(struct page *page,
	struct vm_area_struct *vma, unsigned int *mapcount)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;
	int referenced = 0;

	address = vma_address(page, vma);
	if (address == -EFAULT)
		goto out;

	pte = page_check_address(page, mm, address, &ptl, 0);
	if (!pte)
		goto out;

	if (vma->vm_flags & VM_LOCKED) {
		referenced++;
		*mapcount = 1;	/* break early from loop */
	} else if (ptep_clear_flush_young_notify(vma, address, pte))
		referenced++;

	/* Pretend the page is referenced if the task has the
	   swap token and is in the middle of a page fault. */
	if (mm != current->mm && has_swap_token(mm) &&
			rwsem_is_locked(&mm->mmap_sem))
		referenced++;

	(*mapcount)--;
	pte_unmap_unlock(pte, ptl);
out:
	return referenced;
}

static int page_referenced_anon(struct page *page,
				struct mem_cgroup *mem_cont)
{
	unsigned int mapcount;
	struct anon_vma *anon_vma;
	struct vm_area_struct *vma;
	int referenced = 0;

	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return referenced;

	mapcount = page_mapcount(page);
	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
		/*
		 * If we are reclaiming on behalf of a cgroup, skip
		 * counting on behalf of references from different
		 * cgroups
		 */
		if (mem_cont && !mm_match_cgroup(vma->vm_mm, mem_cont))
			continue;
		referenced += page_referenced_one(page, vma, &mapcount);
		if (!mapcount)
			break;
	}

	page_unlock_anon_vma(anon_vma);
	return referenced;
}

/**
 * page_referenced_file - referenced check for object-based rmap
 * @page: the page we're checking references on.
 * @mem_cont: target memory controller
 *
 * For an object-based mapped page, find all the places it is mapped and
 * check/clear the referenced flag.  This is done by following the page->mapping
 * pointer, then walking the chain of vmas it holds.  It returns the number
 * of references it found.
 *
 * This function is only called from page_referenced for object-based pages.
 */
static int page_referenced_file(struct page *page,
				struct mem_cgroup *mem_cont)
{
	unsigned int mapcount;
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int referenced = 0;

	/*
	 * The caller's checks on page->mapping and !PageAnon have made
	 * sure that this is a file page: the check for page->mapping
	 * excludes the case just before it gets set on an anon page.
	 */
	BUG_ON(PageAnon(page));

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_lock.
	 */
	BUG_ON(!PageLocked(page));

	spin_lock(&mapping->i_mmap_lock);

	/*
	 * i_mmap_lock does not stabilize mapcount at all, but mapcount
	 * is more likely to be accurate if we note it after spinning.
	 */
	mapcount = page_mapcount(page);

	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		/*
		 * If we are reclaiming on behalf of a cgroup, skip
		 * counting on behalf of references from different
		 * cgroups
		 */
		if (mem_cont && !mm_match_cgroup(vma->vm_mm, mem_cont))
			continue;
		if ((vma->vm_flags & (VM_LOCKED|VM_MAYSHARE))
				  == (VM_LOCKED|VM_MAYSHARE)) {
			referenced++;
			break;
		}
		referenced += page_referenced_one(page, vma, &mapcount);
		if (!mapcount)
			break;
	}

	spin_unlock(&mapping->i_mmap_lock);
	return referenced;
/**
 * page_mapped_in_vma - check whether a page is really mapped in a VMA
 * @page: the page to test
 * @vma: the VMA to test
 *
 * Returns 1 if the page is mapped into the page tables of the VMA, 0
 * if the page is not mapped into the page tables of this VMA.  Only
 * valid for normal file or anonymous VMAs.
 */
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;

	address = __vma_address(page, vma);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		return 0;
	pte = page_check_address(page, vma->vm_mm, address, &ptl, 1);
	if (!pte)			/* the page is not in this mm */
		return 0;
	pte_unmap_unlock(pte, ptl);

	return 1;
}

struct page_referenced_arg {
	int mapcount;
	int referenced;
	unsigned long vm_flags;
	struct mem_cgroup *memcg;
};
/*
 * arg: page_referenced_arg will be passed
 */
static bool page_referenced_one(struct page *page, struct vm_area_struct *vma,
			unsigned long address, void *arg)
{
	struct page_referenced_arg *pra = arg;
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
	int referenced = 0;

	while (page_vma_mapped_walk(&pvmw)) {
		address = pvmw.address;

		if (vma->vm_flags & VM_LOCKED) {
			page_vma_mapped_walk_done(&pvmw);
			pra->vm_flags |= VM_LOCKED;
			return false; /* To break the loop */
		}

		if (pvmw.pte) {
			if (ptep_clear_flush_young_notify(vma, address,
						pvmw.pte)) {
				/*
				 * Don't treat a reference through
				 * a sequentially read mapping as such.
				 * If the page has been used in another mapping,
				 * we will catch it; if this other mapping is
				 * already gone, the unmap path will have set
				 * PG_referenced or activated the page.
				 */
				if (likely(!(vma->vm_flags & VM_SEQ_READ)))
					referenced++;
			}
		} else if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)) {
			if (pmdp_clear_flush_young_notify(vma, address,
						pvmw.pmd))
				referenced++;
		} else {
			/* unexpected pmd-mapped page? */
			WARN_ON_ONCE(1);
		}

		pra->mapcount--;
	}

	if (referenced)
		clear_page_idle(page);
	if (test_and_clear_page_young(page))
		referenced++;

	if (referenced) {
		pra->referenced++;
		pra->vm_flags |= vma->vm_flags;
	}

	if (!pra->mapcount)
		return false; /* To break the loop */

	return true;
}

static bool invalid_page_referenced_vma(struct vm_area_struct *vma, void *arg)
{
	struct page_referenced_arg *pra = arg;
	struct mem_cgroup *memcg = pra->memcg;

	if (!mm_match_cgroup(vma->vm_mm, memcg))
		return true;

	return false;
}

/**
 * page_referenced - test if the page was referenced
 * @page: the page to test
 * @is_locked: caller holds lock on the page
 * @mem_cont: target memory controller
 * @memcg: target memory cgroup
 * @vm_flags: collect encountered vma->vm_flags who actually referenced the page
 *
 * Quick test_and_clear_referenced for all mappings to a page,
 * returns the number of ptes which referenced the page.
 */
int page_referenced(struct page *page, int is_locked,
			struct mem_cgroup *mem_cont)
{
	int referenced = 0;

	if (TestClearPageReferenced(page))
		referenced++;

	if (page_mapped(page) && page->mapping) {
		if (PageAnon(page))
			referenced += page_referenced_anon(page, mem_cont);
		else if (is_locked)
			referenced += page_referenced_file(page, mem_cont);
		else if (!trylock_page(page))
			referenced++;
		else {
			if (page->mapping)
				referenced +=
					page_referenced_file(page, mem_cont);
			unlock_page(page);
		}
	}

	if (page_test_and_clear_young(page))
		referenced++;

	return referenced;
}

static int page_mkclean_one(struct page *page, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;
	int ret = 0;

	address = vma_address(page, vma);
	if (address == -EFAULT)
		goto out;
int page_referenced(struct page *page,
		    int is_locked,
		    struct mem_cgroup *memcg,
		    unsigned long *vm_flags)
{
	int we_locked = 0;
	struct page_referenced_arg pra = {
		.mapcount = total_mapcount(page),
		.memcg = memcg,
	};
	struct rmap_walk_control rwc = {
		.rmap_one = page_referenced_one,
		.arg = (void *)&pra,
		.anon_lock = page_lock_anon_vma_read,
	};

	*vm_flags = 0;
	if (!page_mapped(page))
		return 0;

	if (!page_rmapping(page))
		return 0;

	if (!is_locked && (!PageAnon(page) || PageKsm(page))) {
		we_locked = trylock_page(page);
		if (!we_locked)
			return 1;
	}

	/*
	 * If we are reclaiming on behalf of a cgroup, skip
	 * counting on behalf of references from different
	 * cgroups
	 */
	if (memcg) {
		rwc.invalid_vma = invalid_page_referenced_vma;
	}

	rmap_walk(page, &rwc);
	*vm_flags = pra.vm_flags;

	if (we_locked)
		unlock_page(page);

	return pra.referenced;
}

static bool page_mkclean_one(struct page *page, struct vm_area_struct *vma,
			    unsigned long address, void *arg)
{
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
		.flags = PVMW_SYNC,
	};
	unsigned long start = address, end;
	int *cleaned = arg;

	/*
	 * We have to assume the worse case ie pmd for invalidation. Note that
	 * the page can not be free from this function.
	 */
	end = min(vma->vm_end, start + (PAGE_SIZE << compound_order(page)));
	mmu_notifier_invalidate_range_start(vma->vm_mm, start, end);

	while (page_vma_mapped_walk(&pvmw)) {
		unsigned long cstart, cend;
		int ret = 0;

		flush_cache_page(vma, address, pte_pfn(*pte));
		entry = ptep_clear_flush_notify(vma, address, pte);
		entry = ptep_clear_flush(vma, address, pte);
		entry = pte_wrprotect(entry);
		entry = pte_mkclean(entry);
		set_pte_at(mm, address, pte, entry);
		ret = 1;
	}

	pte_unmap_unlock(pte, ptl);
out:
	return ret;
}

static int page_mkclean_file(struct address_space *mapping, struct page *page)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = 0;

	BUG_ON(PageAnon(page));

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		if (vma->vm_flags & VM_SHARED)
			ret += page_mkclean_one(page, vma);
	}
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
		cstart = address = pvmw.address;
		if (pvmw.pte) {
			pte_t entry;
			pte_t *pte = pvmw.pte;

			if (!pte_dirty(*pte) && !pte_write(*pte))
				continue;

			flush_cache_page(vma, address, pte_pfn(*pte));
			entry = ptep_clear_flush(vma, address, pte);
			entry = pte_wrprotect(entry);
			entry = pte_mkclean(entry);
			set_pte_at(vma->vm_mm, address, pte, entry);
			cend = cstart + PAGE_SIZE;
			ret = 1;
		} else {
#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
			pmd_t *pmd = pvmw.pmd;
			pmd_t entry;

			if (!pmd_dirty(*pmd) && !pmd_write(*pmd))
				continue;

			flush_cache_page(vma, address, page_to_pfn(page));
			entry = pmdp_huge_clear_flush(vma, address, pmd);
			entry = pmd_wrprotect(entry);
			entry = pmd_mkclean(entry);
			set_pmd_at(vma->vm_mm, address, pmd, entry);
			cstart &= PMD_MASK;
			cend = cstart + PMD_SIZE;
			ret = 1;
#else
			/* unexpected pmd-mapped page? */
			WARN_ON_ONCE(1);
#endif
		}

		if (ret) {
			mmu_notifier_invalidate_range(vma->vm_mm, cstart, cend);
			(*cleaned)++;
		}
	}

	mmu_notifier_invalidate_range_end(vma->vm_mm, start, end);

	return true;
}

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
	if (vma->vm_flags & VM_SHARED)
		return false;

	return true;
}

int page_mkclean(struct page *page)
{
	int ret = 0;

	BUG_ON(!PageLocked(page));

	if (page_mapped(page)) {
		struct address_space *mapping = page_mapping(page);
		if (mapping) {
			ret = page_mkclean_file(mapping, page);
			if (page_test_dirty(page)) {
				page_clear_dirty(page);
				ret = 1;
			}
		}
	}

	return ret;
	int cleaned = 0;
	struct address_space *mapping;
	struct rmap_walk_control rwc = {
		.arg = (void *)&cleaned,
		.rmap_one = page_mkclean_one,
		.invalid_vma = invalid_mkclean_vma,
	};

	BUG_ON(!PageLocked(page));

	if (!page_mapped(page))
		return 0;

	mapping = page_mapping(page);
	if (!mapping)
		return 0;

	rmap_walk(page, &rwc);

	return cleaned;
}
EXPORT_SYMBOL_GPL(page_mkclean);

/**
 * __page_set_anon_rmap - setup new anonymous rmap
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 */
static void __page_set_anon_rmap(struct page *page,
 * page_move_anon_rmap - move a page to our anon_vma
 * @page:	the page to move to our anon_vma
 * @vma:	the vma the page belongs to
 *
 * When a page belongs exclusively to one process after a COW event,
 * that page can be moved into the anon_vma that belongs to just that
 * process, so the rmap code will not search the parent or sibling
 * processes.
 */
void page_move_anon_rmap(struct page *page, struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;

	page->index = linear_page_index(vma, address);

	/*
	 * nr_mapped state can be updated without turning off
	 * interrupts because it is not modified via interrupt.
	 */
	__inc_zone_page_state(page, NR_ANON_PAGES);
	page = compound_head(page);

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_VMA(!anon_vma, vma);

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	/*
	 * Ensure that anon_vma and the PAGE_MAPPING_ANON bit are written
	 * simultaneously, so a concurrent reader (eg page_referenced()'s
	 * PageAnon()) will not see one without the other.
	 */
	WRITE_ONCE(page->mapping, (struct address_space *) anon_vma);
}

/**
 * __page_set_anon_rmap - set up new anonymous rmap
 * @page:	Page to add to rmap	
 * @vma:	VM area to add page to.
 * @address:	User virtual address of the mapping	
 * @exclusive:	the page is exclusively owned by the current process
 */
static void __page_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		return;

	/*
	 * If the page isn't exclusively mapped into this vma,
	 * we must use the _oldest_ possible anon_vma for the
	 * page mapping!
	 */
	if (!exclusive)
		anon_vma = anon_vma->root;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	page->index = linear_page_index(vma, address);
}

/**
 * __page_check_anon_rmap - sanity check anonymous rmap addition
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 */
static void __page_check_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
#ifdef CONFIG_DEBUG_VM
	/*
	 * The page's anon-rmap details (mapping and index) are guaranteed to
	 * be set up correctly at this point.
	 *
	 * We have exclusion against page_add_anon_rmap because the caller
	 * always holds the page locked, except if called from page_dup_rmap,
	 * in which case the page is already known to be setup.
	 *
	 * We have exclusion against page_add_new_anon_rmap because those pages
	 * are initially only visible via the pagetables, and the pte is locked
	 * over the call to page_add_new_anon_rmap.
	 */
	struct anon_vma *anon_vma = vma->anon_vma;
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	BUG_ON(page->mapping != (struct address_space *)anon_vma);
	BUG_ON(page_anon_vma(page)->root != vma->anon_vma->root);
	BUG_ON(page_to_pgoff(page) != linear_page_index(vma, address));
#endif
}

/**
 * page_add_anon_rmap - add pte mapping to an anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 * @compound:	charge the page as compound or small page
 *
 * The caller needs to hold the pte lock and the page must be locked.
 * The caller needs to hold the pte lock, and the page must be locked in
 * the anon_vma case: to serialize mapping,index checking after setting,
 * and to ensure that PageAnon is not being upgraded racily to PageKsm
 * (but PageKsm is never downgraded to PageAnon).
 */
void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, bool compound)
{
	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	if (atomic_inc_and_test(&page->_mapcount))
		__page_set_anon_rmap(page, vma, address);
	do_page_add_anon_rmap(page, vma, address, 0);
	do_page_add_anon_rmap(page, vma, address, compound ? RMAP_COMPOUND : 0);
}

/*
 * Special version of the above for do_swap_page, which often runs
 * into pages that are exclusively owned by the current process.
 * Everybody else should continue to use page_add_anon_rmap above.
 */
void do_page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int flags)
{
	bool compound = flags & RMAP_COMPOUND;
	bool first;

	if (compound) {
		atomic_t *mapcount;
		VM_BUG_ON_PAGE(!PageLocked(page), page);
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		mapcount = compound_mapcount_ptr(page);
		first = atomic_inc_and_test(mapcount);
	} else {
		first = atomic_inc_and_test(&page->_mapcount);
	}

	if (first) {
		int nr = compound ? hpage_nr_pages(page) : 1;
		/*
		 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
		 * these counters are not modified in interrupt context, and
		 * pte lock(a spinlock) is held, which implies preemption
		 * disabled.
		 */
		if (compound)
			__inc_node_page_state(page, NR_ANON_THPS);
		__mod_node_page_state(page_pgdat(page), NR_ANON_MAPPED, nr);
	}
	if (unlikely(PageKsm(page)))
		return;

	VM_BUG_ON_PAGE(!PageLocked(page), page);

	/* address might be in next vma when migration races vma_adjust */
	if (first)
		__page_set_anon_rmap(page, vma, address,
				flags & RMAP_EXCLUSIVE);
	else
		__page_check_anon_rmap(page, vma, address);
}

/**
 * page_add_new_anon_rmap - add pte mapping to a new anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 * @compound:	charge the page as compound or small page
 *
 * Same as page_add_anon_rmap but must only be called on *new* pages.
 * This means the inc-and-test can be bypassed.
 * Page does not have to be locked.
 */
void page_add_new_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, bool compound)
{
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	atomic_set(&page->_mapcount, 0); /* elevate count by 1 (starts at -1) */
	__page_set_anon_rmap(page, vma, address);
	int nr = compound ? hpage_nr_pages(page) : 1;

	VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);
	__SetPageSwapBacked(page);
	if (compound) {
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		/* increment count (starts at -1) */
		atomic_set(compound_mapcount_ptr(page), 0);
		__inc_node_page_state(page, NR_ANON_THPS);
	} else {
		/* Anon THP always mapped first with PMD */
		VM_BUG_ON_PAGE(PageTransCompound(page), page);
		/* increment count (starts at -1) */
		atomic_set(&page->_mapcount, 0);
	}
	__mod_node_page_state(page_pgdat(page), NR_ANON_MAPPED, nr);
	__page_set_anon_rmap(page, vma, address, 1);
}

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page: the page to add the mapping to
 *
 * The caller needs to hold the pte lock.
 */
void page_add_file_rmap(struct page *page, bool compound)
{
	if (atomic_inc_and_test(&page->_mapcount))
		__inc_zone_page_state(page, NR_FILE_MAPPED);
}

#ifdef CONFIG_DEBUG_VM
/**
 * page_dup_rmap - duplicate pte mapping to a page
 * @page:	the page to add the mapping to
 * @vma:	the vm area being duplicated
 * @address:	the user virtual address mapped
 *
 * For copy_page_range only: minimal extract from page_add_file_rmap /
 * page_add_anon_rmap, avoiding unnecessary tests (already checked) so it's
 * quicker.
 *
 * The caller needs to hold the pte lock.
 */
void page_dup_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(page_mapcount(page) == 0);
	if (PageAnon(page))
		__page_check_anon_rmap(page, vma, address);
	atomic_inc(&page->_mapcount);
}
#endif
	struct mem_cgroup *memcg;
	int i, nr = 1;

	VM_BUG_ON_PAGE(compound && !PageTransHuge(page), page);
	lock_page_memcg(page);
	if (compound && PageTransHuge(page)) {
		for (i = 0, nr = 0; i < HPAGE_PMD_NR; i++) {
			if (atomic_inc_and_test(&page[i]._mapcount))
				nr++;
		}
		if (!atomic_inc_and_test(compound_mapcount_ptr(page)))
			goto out;
		VM_BUG_ON_PAGE(!PageSwapBacked(page), page);
		__inc_node_page_state(page, NR_SHMEM_PMDMAPPED);
	} else {
		if (PageTransCompound(page) && page_mapping(page)) {
			VM_WARN_ON_ONCE(!PageLocked(page));

			SetPageDoubleMap(compound_head(page));
			if (PageMlocked(page))
				clear_page_mlock(compound_head(page));
		}
		if (!atomic_inc_and_test(&page->_mapcount))
			goto out;
	}
	__mod_lruvec_page_state(page, NR_FILE_MAPPED, nr);
out:
	unlock_page_memcg(page);
}

static void page_remove_file_rmap(struct page *page, bool compound)
{
	int i, nr = 1;

	VM_BUG_ON_PAGE(compound && !PageHead(page), page);
	lock_page_memcg(page);

	/* Hugepages are not counted in NR_FILE_MAPPED for now. */
	if (unlikely(PageHuge(page))) {
		/* hugetlb pages are always mapped with pmds */
		atomic_dec(compound_mapcount_ptr(page));
		goto out;
	}

	/* page still mapped by someone else? */
	if (compound && PageTransHuge(page)) {
		for (i = 0, nr = 0; i < HPAGE_PMD_NR; i++) {
			if (atomic_add_negative(-1, &page[i]._mapcount))
				nr++;
		}
		if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
			goto out;
		VM_BUG_ON_PAGE(!PageSwapBacked(page), page);
		__dec_node_page_state(page, NR_SHMEM_PMDMAPPED);
	} else {
		if (!atomic_add_negative(-1, &page->_mapcount))
			goto out;
	}

	/*
	 * We use the irq-unsafe __{inc|mod}_lruvec_page_state because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	__mod_lruvec_page_state(page, NR_FILE_MAPPED, -nr);

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);
out:
	unlock_page_memcg(page);
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page: page to remove mapping from
 * @vma: the vm area in which the mapping is removed
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page, struct vm_area_struct *vma)
{
	if (atomic_add_negative(-1, &page->_mapcount)) {
		if (unlikely(page_mapcount(page) < 0)) {
			printk (KERN_EMERG "Eeek! page_mapcount(page) went negative! (%d)\n", page_mapcount(page));
			printk (KERN_EMERG "  page pfn = %lx\n", page_to_pfn(page));
			printk (KERN_EMERG "  page->flags = %lx\n", page->flags);
			printk (KERN_EMERG "  page->count = %x\n", page_count(page));
			printk (KERN_EMERG "  page->mapping = %p\n", page->mapping);
			print_symbol (KERN_EMERG "  vma->vm_ops = %s\n", (unsigned long)vma->vm_ops);
			if (vma->vm_ops) {
				print_symbol (KERN_EMERG "  vma->vm_ops->fault = %s\n", (unsigned long)vma->vm_ops->fault);
			}
			if (vma->vm_file && vma->vm_file->f_op)
				print_symbol (KERN_EMERG "  vma->vm_file->f_op->mmap = %s\n", (unsigned long)vma->vm_file->f_op->mmap);
			BUG();
		}

		/*
		 * Now that the last pte has gone, s390 must transfer dirty
		 * flag from storage key to struct page.  We can usually skip
		 * this if the page is anon, so about to be freed; but perhaps
		 * not if it's in swapcache - there might be another pte slot
		 * containing the swap entry, but page not yet written to swap.
		 */
		if ((!PageAnon(page) || PageSwapCache(page)) &&
		    page_test_dirty(page)) {
			page_clear_dirty(page);
			set_page_dirty(page);
		}

		mem_cgroup_uncharge_page(page);
		__dec_zone_page_state(page,
			PageAnon(page) ? NR_ANON_PAGES : NR_FILE_MAPPED);
		/*
		 * It would be tidy to reset the PageAnon mapping here,
		 * but that might overwrite a racing page_add_anon_rmap
		 * which increments mapcount after us but sets mapping
		 * before us: so leave the reset to free_hot_cold_page,
		 * and remember that it's only reliable while mapped.
		 * Leaving it set also helps swapoff to reinstate ptes
		 * faster for those pages still in swapcache.
		 */
	}
}

/*
 * Subfunctions of try_to_unmap: try_to_unmap_one called
 * repeatedly from either try_to_unmap_anon or try_to_unmap_file.
 */
static int try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
				int migration)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page)
static void page_remove_anon_compound_rmap(struct page *page)
{
	int i, nr;

	if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
		return;

	/* Hugepages are not counted in NR_ANON_PAGES for now. */
	if (unlikely(PageHuge(page)))
		return;

	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return;

	__dec_node_page_state(page, NR_ANON_THPS);

	if (TestClearPageDoubleMap(page)) {
		/*
		 * Subpages can be mapped with PTEs too. Check how many of
		 * themi are still mapped.
		 */
		for (i = 0, nr = 0; i < HPAGE_PMD_NR; i++) {
			if (atomic_add_negative(-1, &page[i]._mapcount))
				nr++;
		}
	} else {
		nr = HPAGE_PMD_NR;
	}

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);

	if (nr) {
		__mod_node_page_state(page_pgdat(page), NR_ANON_MAPPED, -nr);
		deferred_split_huge_page(page);
	}
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page:	page to remove mapping from
 * @compound:	uncharge the page as compound or small page
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page, bool compound)
{
	if (!PageAnon(page))
		return page_remove_file_rmap(page, compound);

	if (compound)
		return page_remove_anon_compound_rmap(page);

	/* page still mapped by someone else? */
	if (!atomic_add_negative(-1, &page->_mapcount))
		return;

	/*
	 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	__dec_node_page_state(page, NR_ANON_MAPPED);

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);

	if (PageTransCompound(page))
		deferred_split_huge_page(compound_head(page));

	/*
	 * It would be tidy to reset the PageAnon mapping here,
	 * but that might overwrite a racing page_add_anon_rmap
	 * which increments mapcount after us but sets mapping
	 * before us: so leave the reset to free_hot_cold_page,
	 * and remember that it's only reliable while mapped.
	 * Leaving it set also helps swapoff to reinstate ptes
	 * faster for those pages still in swapcache.
	 */
}

/*
 * @arg: enum ttu_flags will be passed to this argument
 */
static bool try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
	pte_t pteval;
	spinlock_t *ptl;
	int ret = SWAP_AGAIN;

	address = vma_address(page, vma);
	if (address == -EFAULT)
	struct page *subpage;
	bool ret = true;
	unsigned long start = address, end;
	enum ttu_flags flags = (enum ttu_flags)arg;

	/* munlock has nothing to gain from examining un-locked vmas */
	if ((flags & TTU_MUNLOCK) && !(vma->vm_flags & VM_LOCKED))
		return true;

	if (IS_ENABLED(CONFIG_MIGRATION) && (flags & TTU_MIGRATION) &&
	    is_zone_device_page(page) && !is_device_private_page(page))
		return true;

	if (flags & TTU_SPLIT_HUGE_PMD) {
		split_huge_pmd_address(vma, address,
				flags & TTU_SPLIT_FREEZE, page);
	}

	/*
	 * We have to assume the worse case ie pmd for invalidation. Note that
	 * the page can not be free in this function as call of try_to_unmap()
	 * must hold a reference on the page.
	 */
	if (!migration && ((vma->vm_flags & VM_LOCKED) ||
			(ptep_clear_flush_young_notify(vma, address, pte)))) {
		ret = SWAP_FAIL;
		goto out_unmap;
	}

	/* Nuke the page table entry. */
	flush_cache_page(vma, address, page_to_pfn(page));
	pteval = ptep_clear_flush_notify(vma, address, pte);
	if (!(flags & TTU_IGNORE_MLOCK)) {
		if (vma->vm_flags & VM_LOCKED) {
			/* Holding pte lock, we do *not* need mmap_sem here */
			mlock_vma_page(page);
			ret = SWAP_MLOCK;
			goto out_unmap;
		}
		if (flags & TTU_MUNLOCK)
			goto out_unmap;
	}
	if (!(flags & TTU_IGNORE_ACCESS)) {
		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			ret = SWAP_FAIL;
			goto out_unmap;
		}
  	}
	end = min(vma->vm_end, start + (PAGE_SIZE << compound_order(page)));
	mmu_notifier_invalidate_range_start(vma->vm_mm, start, end);

	while (page_vma_mapped_walk(&pvmw)) {
#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
		/* PMD-mapped THP migration entry */
		if (!pvmw.pte && (flags & TTU_MIGRATION)) {
			VM_BUG_ON_PAGE(PageHuge(page) || !PageTransCompound(page), page);

			if (!PageAnon(page))
				continue;

			set_pmd_migration_entry(&pvmw, page);
			continue;
		}
#endif

		/*
		 * If the page is mlock()d, we cannot swap it out.
		 * If it's recently referenced (perhaps page_referenced
		 * skipped over this mm) then we should reactivate it.
		 */
		if (!(flags & TTU_IGNORE_MLOCK)) {
			if (vma->vm_flags & VM_LOCKED) {
				/* PTE-mapped THP are never mlocked */
				if (!PageTransCompound(page)) {
					/*
					 * Holding pte lock, we do *not* need
					 * mmap_sem here
					 */
					mlock_vma_page(page);
				}
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			if (flags & TTU_MUNLOCK)
				continue;
		}

		/* Unexpected PMD-mapped THP? */
		VM_BUG_ON_PAGE(!pvmw.pte, page);

		subpage = page - page_to_pfn(page) + pte_pfn(*pvmw.pte);
		address = pvmw.address;


	if (PageAnon(page)) {
		swp_entry_t entry = { .val = page_private(page) };

		if (PageSwapCache(page)) {
			/*
			 * Store the swap location in the pte.
			 * See handle_pte_fault() ...
			 */
			swap_duplicate(entry);
			if (list_empty(&mm->mmlist)) {
				spin_lock(&mmlist_lock);
				if (list_empty(&mm->mmlist))
					list_add(&mm->mmlist, &init_mm.mmlist);
				spin_unlock(&mmlist_lock);
			}
			dec_mm_counter(mm, anon_rss);
#ifdef CONFIG_MIGRATION
		} else {
		if (IS_ENABLED(CONFIG_MIGRATION) &&
		    (flags & TTU_MIGRATION) &&
		    is_zone_device_page(page)) {
			swp_entry_t entry;
			pte_t swp_pte;

			pteval = ptep_get_and_clear(mm, pvmw.address, pvmw.pte);

			/*
			 * Store the pfn of the page in a special migration
			 * pte. do_swap_page() will wait until the migration
			 * pte is removed and then restart fault handling.
			 */
			BUG_ON(!migration);
			entry = make_migration_entry(page, pte_write(pteval));
#endif
		}
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
		BUG_ON(pte_file(*pte));
	} else
#ifdef CONFIG_MIGRATION
	if (migration) {
		/* Establish migration entry for a file page */
		swp_entry_t entry;
		entry = make_migration_entry(page, pte_write(pteval));
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
	} else
#endif
		dec_mm_counter(mm, file_rss);


	page_remove_rmap(page, vma);
	if (PageHWPoison(page) && !(flags & TTU_IGNORE_HWPOISON)) {
		if (PageHuge(page)) {
			hugetlb_count_sub(1 << compound_order(page), mm);
			entry = make_migration_entry(page, 0);
			swp_pte = swp_entry_to_pte(entry);
			if (pte_soft_dirty(pteval))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			set_pte_at(mm, pvmw.address, pvmw.pte, swp_pte);
			goto discard;
		}

		if (!(flags & TTU_IGNORE_ACCESS)) {
			if (ptep_clear_flush_young_notify(vma, address,
						pvmw.pte)) {
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
		}

		/* Nuke the page table entry. */
		flush_cache_page(vma, address, pte_pfn(*pvmw.pte));
		if (should_defer_flush(mm, flags)) {
			/*
			 * We clear the PTE but do not flush so potentially
			 * a remote CPU could still be writing to the page.
			 * If the entry was previously clean then the
			 * architecture must guarantee that a clear->dirty
			 * transition on a cached TLB entry is written through
			 * and traps if the PTE is unmapped.
			 */
			pteval = ptep_get_and_clear(mm, address, pvmw.pte);

			set_tlb_ubc_flush_pending(mm, pte_dirty(pteval));
		} else {
			pteval = ptep_clear_flush(vma, address, pvmw.pte);
		}

		/* Move the dirty bit to the page. Now the pte is gone. */
		if (pte_dirty(pteval))
			set_page_dirty(page);

		/* Update high watermark before we lower rss */
		update_hiwater_rss(mm);

		if (PageHWPoison(page) && !(flags & TTU_IGNORE_HWPOISON)) {
			pteval = swp_entry_to_pte(make_hwpoison_entry(subpage));
			if (PageHuge(page)) {
				int nr = 1 << compound_order(page);
				hugetlb_count_sub(nr, mm);
				set_huge_swap_pte_at(mm, address,
						     pvmw.pte, pteval,
						     vma_mmu_pagesize(vma));
			} else {
				dec_mm_counter(mm, mm_counter(page));
				set_pte_at(mm, address, pvmw.pte, pteval);
			}

		} else if (pte_unused(pteval)) {
			/*
			 * The guest indicated that the page content is of no
			 * interest anymore. Simply discard the pte, vmscan
			 * will take care of the rest.
			 */
			dec_mm_counter(mm, mm_counter(page));
		} else if (IS_ENABLED(CONFIG_MIGRATION) &&
				(flags & (TTU_MIGRATION|TTU_SPLIT_FREEZE))) {
			swp_entry_t entry;
			pte_t swp_pte;
			/*
			 * Store the pfn of the page in a special migration
			 * pte. do_swap_page() will wait until the migration
			 * pte is removed and then restart fault handling.
			 */
			entry = make_migration_entry(subpage,
					pte_write(pteval));
			swp_pte = swp_entry_to_pte(entry);
			if (pte_soft_dirty(pteval))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			set_pte_at(mm, address, pvmw.pte, swp_pte);
		} else if (PageAnon(page)) {
			swp_entry_t entry = { .val = page_private(subpage) };
			pte_t swp_pte;
			/*
			 * Store the swap location in the pte.
			 * See handle_pte_fault() ...
			 */
			if (unlikely(PageSwapBacked(page) != PageSwapCache(page))) {
				WARN_ON_ONCE(1);
				ret = false;
				/* We have to invalidate as we cleared the pte */
				page_vma_mapped_walk_done(&pvmw);
				break;
			}

			/* MADV_FREE page check */
			if (!PageSwapBacked(page)) {
				if (!PageDirty(page)) {
					dec_mm_counter(mm, MM_ANONPAGES);
					goto discard;
				}

				/*
				 * If the page was redirtied, it cannot be
				 * discarded. Remap the page to page table.
				 */
				set_pte_at(mm, address, pvmw.pte, pteval);
				SetPageSwapBacked(page);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}

			if (swap_duplicate(entry) < 0) {
				set_pte_at(mm, address, pvmw.pte, pteval);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			if (list_empty(&mm->mmlist)) {
				spin_lock(&mmlist_lock);
				if (list_empty(&mm->mmlist))
					list_add(&mm->mmlist, &init_mm.mmlist);
				spin_unlock(&mmlist_lock);
			}
			dec_mm_counter(mm, MM_ANONPAGES);
			inc_mm_counter(mm, MM_SWAPENTS);
			swp_pte = swp_entry_to_pte(entry);
			if (pte_soft_dirty(pteval))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			set_pte_at(mm, address, pvmw.pte, swp_pte);
		} else
			dec_mm_counter(mm, mm_counter_file(page));
discard:
		page_remove_rmap(subpage, PageHuge(page));
		put_page(page);
		mmu_notifier_invalidate_range(mm, address,
					      address + PAGE_SIZE);
	}

	mmu_notifier_invalidate_range_end(vma->vm_mm, start, end);

	return ret;
}

/*
 * objrmap doesn't work for nonlinear VMAs because the assumption that
 * offset-into-file correlates with offset-into-virtual-addresses does not hold.
 * Consequently, given a particular page and its ->index, we cannot locate the
 * ptes which are mapping that page without an exhaustive linear search.
 *
 * So what this code does is a mini "virtual scan" of each nonlinear VMA which
 * maps the file to which the target page belongs.  The ->vm_private_data field
 * holds the current cursor into that scan.  Successive searches will circulate
 * around the vma's virtual address space.
 *
 * So as more replacement pressure is applied to the pages in a nonlinear VMA,
 * more scanning pressure is placed against them as well.   Eventually pages
 * will become fully unmapped and are eligible for eviction.
 *
 * For very sparsely populated VMAs this is a little inefficient - chances are
 * there there won't be many ptes located within the scan cluster.  In this case
 * maybe we could scan further - to the end of the pte page, perhaps.
 */
#define CLUSTER_SIZE	min(32*PAGE_SIZE, PMD_SIZE)
#define CLUSTER_MASK	(~(CLUSTER_SIZE - 1))

static void try_to_unmap_cluster(unsigned long cursor,
	unsigned int *mapcount, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	struct page *page;
	unsigned long address;
	unsigned long end;

	address = (vma->vm_start + cursor) & CLUSTER_MASK;
	end = address + CLUSTER_SIZE;
	if (address < vma->vm_start)
		address = vma->vm_start;
	if (end > vma->vm_end)
		end = vma->vm_end;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return;

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	for (; address < end; pte++, address += PAGE_SIZE) {
		if (!pte_present(*pte))
			continue;
		page = vm_normal_page(vma, address, *pte);
		BUG_ON(!page || PageAnon(page));

		if (ptep_clear_flush_young_notify(vma, address, pte))
			continue;

		/* Nuke the page table entry. */
		flush_cache_page(vma, address, pte_pfn(*pte));
		pteval = ptep_clear_flush_notify(vma, address, pte);

		/* If nonlinear, store the file page offset in the pte. */
		if (page->index != linear_page_index(vma, address))
			set_pte_at(mm, address, pte, pgoff_to_pte(page->index));

		/* Move the dirty bit to the physical page now the pte is gone. */
		if (pte_dirty(pteval))
			set_page_dirty(page);

		page_remove_rmap(page, vma);
		page_cache_release(page);
		dec_mm_counter(mm, file_rss);
		(*mapcount)--;
	}
	pte_unmap_unlock(pte - 1, ptl);
}

static int try_to_unmap_anon(struct page *page, int migration)
{
	struct anon_vma *anon_vma;
	struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;

	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return ret;

	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
		ret = try_to_unmap_one(page, vma, migration);
		if (ret == SWAP_FAIL || !page_mapped(page))
			break;
	}

	page_unlock_anon_vma(anon_vma);
	return ret;
}

/**
 * try_to_unmap_file - unmap file page using the object-based rmap method
 * @page: the page to unmap
 * @migration: migration flag
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * This function is only called from try_to_unmap for object-based pages.
 */
static int try_to_unmap_file(struct page *page, int migration)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = SWAP_AGAIN;
	unsigned long cursor;
	unsigned long max_nl_cursor = 0;
	unsigned long max_nl_size = 0;
	unsigned int mapcount;

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		ret = try_to_unmap_one(page, vma, migration);
		if (ret == SWAP_FAIL || !page_mapped(page))
			goto out;
	}

	if (list_empty(&mapping->i_mmap_nonlinear))
		goto out;

	list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
		if ((vma->vm_flags & VM_LOCKED) && !migration)
			continue;
		cursor = (unsigned long) vma->vm_private_data;
		if (cursor > max_nl_cursor)
			max_nl_cursor = cursor;
		cursor = vma->vm_end - vma->vm_start;
		if (cursor > max_nl_size)
			max_nl_size = cursor;
	}

	if (max_nl_size == 0) {	/* any nonlinears locked or reserved */
		ret = SWAP_FAIL;
		goto out;
	}

	/*
	 * We don't try to search for this page in the nonlinear vmas,
	 * and page_referenced wouldn't have found it anyway.  Instead
	 * just walk the nonlinear vmas trying to age and unmap some.
	 * The mapcount of the page we came in with is irrelevant,
	 * but even so use it as a guide to how hard we should try?
	 */
	mapcount = page_mapcount(page);
	if (!mapcount)
		goto out;
	cond_resched_lock(&mapping->i_mmap_lock);

	max_nl_size = (max_nl_size + CLUSTER_SIZE - 1) & CLUSTER_MASK;
	if (max_nl_cursor == 0)
		max_nl_cursor = CLUSTER_SIZE;

	do {
		list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
			if ((vma->vm_flags & VM_LOCKED) && !migration)
				continue;
			cursor = (unsigned long) vma->vm_private_data;
			while ( cursor < max_nl_cursor &&
				cursor < vma->vm_end - vma->vm_start) {
				try_to_unmap_cluster(cursor, &mapcount, vma);
				cursor += CLUSTER_SIZE;
				vma->vm_private_data = (void *) cursor;
				if ((int)mapcount <= 0)
					goto out;
			}
			vma->vm_private_data = (void *) max_nl_cursor;
		}
		cond_resched_lock(&mapping->i_mmap_lock);
		max_nl_cursor += CLUSTER_SIZE;
	} while (max_nl_cursor <= max_nl_size);

	/*
	 * Don't loop forever (perhaps all the remaining pages are
	 * in locked vmas).  Reset cursor on all unreserved nonlinear
	 * vmas, now forgetting on which ones it had fallen behind.
	 */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear, shared.vm_set.list)
		vma->vm_private_data = NULL;
out:
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}
bool is_vma_temporary_stack(struct vm_area_struct *vma)
{
	int maybe_stack = vma->vm_flags & (VM_GROWSDOWN | VM_GROWSUP);

	if (!maybe_stack)
		return false;

	if ((vma->vm_flags & VM_STACK_INCOMPLETE_SETUP) ==
						VM_STACK_INCOMPLETE_SETUP)
		return true;

	return false;
}

static bool invalid_migration_vma(struct vm_area_struct *vma, void *arg)
{
	return is_vma_temporary_stack(vma);
}

static int page_mapcount_is_zero(struct page *page)
{
	return !total_mapcount(page);
}

/**
 * try_to_unmap - try to remove all page table mappings to a page
 * @page: the page to get unmapped
 * @migration: migration flag
 * @flags: action and flags
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used in the pageout path.  Caller must hold the page lock.
 *
 * SWAP_SUCCESS	- we succeeded in removing all mappings
 * SWAP_AGAIN	- we missed a mapping, try again later
 * SWAP_FAIL	- the page is unswappable
 */
int try_to_unmap(struct page *page, int migration)
{
	int ret;

	BUG_ON(!PageLocked(page));

	if (PageAnon(page))
		ret = try_to_unmap_anon(page, migration);
	else
		ret = try_to_unmap_file(page, migration);

	if (!page_mapped(page))
 * SWAP_MLOCK	- page is mlocked.
 * If unmap is successful, return true. Otherwise, false.
 */
bool try_to_unmap(struct page *page, enum ttu_flags flags)
{
	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one,
		.arg = (void *)flags,
		.done = page_mapcount_is_zero,
		.anon_lock = page_lock_anon_vma_read,
	};

	/*
	 * During exec, a temporary VMA is setup and later moved.
	 * The VMA is moved under the anon_vma lock but not the
	 * page tables leading to a race where migration cannot
	 * find the migration ptes. Rather than increasing the
	 * locking requirements of exec(), migration skips
	 * temporary VMAs until after exec() completes.
	 */
	if ((flags & (TTU_MIGRATION|TTU_SPLIT_FREEZE))
	    && !PageKsm(page) && PageAnon(page))
		rwc.invalid_vma = invalid_migration_vma;

	if (flags & TTU_RMAP_LOCKED)
		rmap_walk_locked(page, &rwc);
	else
		rmap_walk(page, &rwc);

	return !page_mapcount(page) ? true : false;
}

static int page_not_mapped(struct page *page)
{
	return !page_mapped(page);
};

/**
 * try_to_munlock - try to munlock a page
 * @page: the page to be munlocked
 *
 * Called from munlock code.  Checks all of the VMAs mapping the page
 * to make sure nobody else has this page mlocked. The page will be
 * returned with PG_mlocked cleared if no other vmas have it mlocked.
 */

void try_to_munlock(struct page *page)
{
	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one,
		.arg = (void *)TTU_MUNLOCK,
		.done = page_not_mapped,
		.anon_lock = page_lock_anon_vma_read,

	};

	VM_BUG_ON_PAGE(!PageLocked(page) || PageLRU(page), page);
	VM_BUG_ON_PAGE(PageCompound(page) && PageDoubleMap(page), page);

	rmap_walk(page, &rwc);
}

void __put_anon_vma(struct anon_vma *anon_vma)
{
	struct anon_vma *root = anon_vma->root;

	anon_vma_free(anon_vma);
	if (root != anon_vma && atomic_dec_and_test(&root->refcount))
		anon_vma_free(root);
}

static struct anon_vma *rmap_walk_anon_lock(struct page *page,
					struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma;

	if (rwc->anon_lock)
		return rwc->anon_lock(page);

	/*
	 * Note: remove_migration_ptes() cannot use page_lock_anon_vma_read()
	 * because that depends on page_mapped(); but not all its usages
	 * are holding mmap_sem. Users without mmap_sem are required to
	 * take a reference count to prevent the anon_vma disappearing
	 */
	anon_vma = page_anon_vma(page);
	if (!anon_vma)
		return NULL;

	anon_vma_lock_read(anon_vma);
	return anon_vma;
}

/*
 * rmap_walk_anon - do something to anonymous page using the object-based
 * rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the anon_vma struct it points to.
 *
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * LOCKED.
 */
static void rmap_walk_anon(struct page *page, struct rmap_walk_control *rwc,
		bool locked)
{
	struct anon_vma *anon_vma;
	pgoff_t pgoff_start, pgoff_end;
	struct anon_vma_chain *avc;

	if (locked) {
		anon_vma = page_anon_vma(page);
		/* anon_vma disappear under us? */
		VM_BUG_ON_PAGE(!anon_vma, page);
	} else {
		anon_vma = rmap_walk_anon_lock(page, rwc);
	}
	if (!anon_vma)
		return;

	pgoff_start = page_to_pgoff(page);
	pgoff_end = pgoff_start + hpage_nr_pages(page) - 1;
	anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root,
			pgoff_start, pgoff_end) {
		struct vm_area_struct *vma = avc->vma;
		unsigned long address = vma_address(page, vma);

		cond_resched();

		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		if (!rwc->rmap_one(page, vma, address, rwc->arg))
			break;
		if (rwc->done && rwc->done(page))
			break;
	}

	if (!locked)
		anon_vma_unlock_read(anon_vma);
}

/*
 * rmap_walk_file - do something to file page using the object-based rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * LOCKED.
 */
static void rmap_walk_file(struct page *page, struct rmap_walk_control *rwc,
		bool locked)
{
	struct address_space *mapping = page_mapping(page);
	pgoff_t pgoff_start, pgoff_end;
	struct vm_area_struct *vma;

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_rwsem.
	 */
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!mapping)
		return;

	pgoff_start = page_to_pgoff(page);
	pgoff_end = pgoff_start + hpage_nr_pages(page) - 1;
	if (!locked)
		i_mmap_lock_read(mapping);
	vma_interval_tree_foreach(vma, &mapping->i_mmap,
			pgoff_start, pgoff_end) {
		unsigned long address = vma_address(page, vma);

		cond_resched();

		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		if (!rwc->rmap_one(page, vma, address, rwc->arg))
			goto done;
		if (rwc->done && rwc->done(page))
			goto done;
	}

done:
	if (!locked)
		i_mmap_unlock_read(mapping);
}

void rmap_walk(struct page *page, struct rmap_walk_control *rwc)
{
	if (unlikely(PageKsm(page)))
		rmap_walk_ksm(page, rwc);
	else if (PageAnon(page))
		rmap_walk_anon(page, rwc, false);
	else
		rmap_walk_file(page, rwc, false);
}

/* Like rmap_walk, but caller holds relevant rmap lock */
void rmap_walk_locked(struct page *page, struct rmap_walk_control *rwc)
{
	/* no ksm support for now */
	VM_BUG_ON_PAGE(PageKsm(page), page);
	if (PageAnon(page))
		rmap_walk_anon(page, rwc, true);
	else
		rmap_walk_file(page, rwc, true);
}

#ifdef CONFIG_HUGETLB_PAGE
/*
 * The following three functions are for anonymous (private mapped) hugepages.
 * Unlike common anonymous pages, anonymous hugepages have no accounting code
 * and no lru code, because we handle hugepages differently from common pages.
 */
static void __hugepage_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		return;
	if (!exclusive)
		anon_vma = anon_vma->root;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	page->index = linear_page_index(vma, address);
}

void hugepage_add_anon_rmap(struct page *page,
			    struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int first;

	BUG_ON(!PageLocked(page));
	BUG_ON(!anon_vma);
	/* address might be in next vma when migration races vma_adjust */
	first = atomic_inc_and_test(compound_mapcount_ptr(page));
	if (first)
		__hugepage_set_anon_rmap(page, vma, address, 0);
}

void hugepage_add_new_anon_rmap(struct page *page,
			struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	atomic_set(compound_mapcount_ptr(page), 0);
	__hugepage_set_anon_rmap(page, vma, address, 1);
}
#endif /* CONFIG_HUGETLB_PAGE */
