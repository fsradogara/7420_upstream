/*
 * fs/dcache.c
 *
 * Complete reimplementation
 * (C) 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

/*
 * Notes on the allocation strategy:
 *
 * The dcache is a master of the icache - whenever a dcache entry
 * exists, the inode will always exist. "iput()" is done either when
 * the dcache entry is deleted or garbage collected.
 */

#include <linux/ratelimit.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/bootmem.h>
#include "internal.h"


int sysctl_vfs_cache_pressure __read_mostly = 100;
EXPORT_SYMBOL_GPL(sysctl_vfs_cache_pressure);

 __cacheline_aligned_in_smp DEFINE_SPINLOCK(dcache_lock);
__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

EXPORT_SYMBOL(dcache_lock);

static struct kmem_cache *dentry_cache __read_mostly;

#define DNAME_INLINE_LEN (sizeof(struct dentry)-offsetof(struct dentry,d_iname))

#include <linux/fs_struct.h>
#include <linux/hardirq.h>
#include <linux/bit_spinlock.h>
#include <linux/rculist_bl.h>
#include <linux/list_lru.h>
#include "internal.h"
#include "mount.h"

/*
 * Usage:
 * dcache->d_inode->i_lock protects:
 *   - i_dentry, d_u.d_alias, d_inode of aliases
 * dcache_hash_bucket lock protects:
 *   - the dcache hash table
 * s_roots bl list spinlock protects:
 *   - the s_roots list (see __d_drop)
 * dentry->d_sb->s_dentry_lru_lock protects:
 *   - the dcache lru lists and counters
 * d_lock protects:
 *   - d_flags
 *   - d_name
 *   - d_lru
 *   - d_count
 *   - d_unhashed()
 *   - d_parent and d_subdirs
 *   - childrens' d_child and d_parent
 *   - d_u.d_alias, d_inode
 *
 * Ordering:
 * dentry->d_inode->i_lock
 *   dentry->d_lock
 *     dentry->d_sb->s_dentry_lru_lock
 *     dcache_hash_bucket lock
 *     s_roots lock
 *
 * If there is an ancestor relationship:
 * dentry->d_parent->...->d_parent->d_lock
 *   ...
 *     dentry->d_parent->d_lock
 *       dentry->d_lock
 *
 * If no ancestor relationship:
 * arbitrary, since it's serialized on rename_lock
 */
int sysctl_vfs_cache_pressure __read_mostly = 100;
EXPORT_SYMBOL_GPL(sysctl_vfs_cache_pressure);

__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

EXPORT_SYMBOL(rename_lock);

static struct kmem_cache *dentry_cache __read_mostly;

const struct qstr empty_name = QSTR_INIT("", 0);
EXPORT_SYMBOL(empty_name);
const struct qstr slash_name = QSTR_INIT("/", 1);
EXPORT_SYMBOL(slash_name);

/*
 * This is the single most critical data structure when it comes
 * to the dcache: the hashtable for lookups. Somebody should try
 * to make this good - I've just made it work.
 *
 * This hash-function tries to avoid losing too many bits of hash
 * information, yet avoid using a prime hash-size or similar.
 */
#define D_HASHBITS     d_hash_shift
#define D_HASHMASK     d_hash_mask

static unsigned int d_hash_mask __read_mostly;
static unsigned int d_hash_shift __read_mostly;
static struct hlist_head *dentry_hashtable __read_mostly;

static unsigned int d_hash_shift __read_mostly;

static struct hlist_bl_head *dentry_hashtable __read_mostly;

static inline struct hlist_bl_head *d_hash(unsigned int hash)
{
	return dentry_hashtable + (hash >> d_hash_shift);
}

#define IN_LOOKUP_SHIFT 10
static struct hlist_bl_head in_lookup_hashtable[1 << IN_LOOKUP_SHIFT];

static inline struct hlist_bl_head *in_lookup_hash(const struct dentry *parent,
					unsigned int hash)
{
	hash += (unsigned long) parent / L1_CACHE_BYTES;
	return in_lookup_hashtable + hash_32(hash, IN_LOOKUP_SHIFT);
}


/* Statistics gathering. */
struct dentry_stat_t dentry_stat = {
	.age_limit = 45,
};

static void __d_free(struct dentry *dentry)
{
	if (dname_external(dentry))
		kfree(dentry->d_name.name);
	kmem_cache_free(dentry_cache, dentry); 
}

static void d_callback(struct rcu_head *head)
{
	struct dentry * dentry = container_of(head, struct dentry, d_u.d_rcu);
	__d_free(dentry);
}

/*
 * no dcache_lock, please.  The caller must decrement dentry_stat.nr_dentry
 * inside dcache_lock.
 */
static void d_free(struct dentry *dentry)
{
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);
	/* if dentry was never inserted into hash, immediate free is OK */
	if (hlist_unhashed(&dentry->d_hash))
		__d_free(dentry);
	else
		call_rcu(&dentry->d_u.d_rcu, d_callback);
static DEFINE_PER_CPU(long, nr_dentry);
static DEFINE_PER_CPU(long, nr_dentry_unused);

#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)

/*
 * Here we resort to our own counters instead of using generic per-cpu counters
 * for consistency with what the vfs inode code does. We are expected to harvest
 * better code and performance by having our own specialized counters.
 *
 * Please note that the loop is done over all possible CPUs, not over all online
 * CPUs. The reason for this is that we don't want to play games with CPUs going
 * on and off. If one of them goes off, we will just keep their counters.
 *
 * glommer: See cffbc8a for details, and if you ever intend to change this,
 * please update all vfs counters to match.
 */
static long get_nr_dentry(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_dentry, i);
	return sum < 0 ? 0 : sum;
}

static long get_nr_dentry_unused(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_dentry_unused, i);
	return sum < 0 ? 0 : sum;
}

int proc_nr_dentry(struct ctl_table *table, int write, void __user *buffer,
		   size_t *lenp, loff_t *ppos)
{
	dentry_stat.nr_dentry = get_nr_dentry();
	dentry_stat.nr_unused = get_nr_dentry_unused();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
#endif

/*
 * Compare 2 name strings, return 0 if they match, otherwise non-zero.
 * The strings are both count bytes long, and count is non-zero.
 */
#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>
/*
 * NOTE! 'cs' and 'scount' come from a dentry, so it has a
 * aligned allocation for this particular component. We don't
 * strictly need the load_unaligned_zeropad() safety, but it
 * doesn't hurt either.
 *
 * In contrast, 'ct' and 'tcount' can be from a pathname, and do
 * need the careful unaligned handling.
 */
static inline int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
	unsigned long a,b,mask;

	for (;;) {
		a = read_word_at_a_time(cs);
		b = load_unaligned_zeropad(ct);
		if (tcount < sizeof(unsigned long))
			break;
		if (unlikely(a != b))
			return 1;
		cs += sizeof(unsigned long);
		ct += sizeof(unsigned long);
		tcount -= sizeof(unsigned long);
		if (!tcount)
			return 0;
	}
	mask = bytemask_from_count(tcount);
	return unlikely(!!((a ^ b) & mask));
}

#else

static inline int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
	do {
		if (*cs != *ct)
			return 1;
		cs++;
		ct++;
		tcount--;
	} while (tcount);
	return 0;
}

#endif

static inline int dentry_cmp(const struct dentry *dentry, const unsigned char *ct, unsigned tcount)
{
	/*
	 * Be careful about RCU walk racing with rename:
	 * use 'READ_ONCE' to fetch the name pointer.
	 *
	 * NOTE! Even if a rename will mean that the length
	 * was not loaded atomically, we don't care. The
	 * RCU walk will check the sequence count eventually,
	 * and catch it. And we won't overrun the buffer,
	 * because we're reading the name pointer atomically,
	 * and a dentry name is guaranteed to be properly
	 * terminated with a NUL byte.
	 *
	 * End result: even if 'len' is wrong, we'll exit
	 * early because the data cannot match (there can
	 * be no NUL in the ct/tcount data)
	 */
	const unsigned char *cs = READ_ONCE(dentry->d_name.name);

	return dentry_string_cmp(cs, ct, tcount);
}

struct external_name {
	union {
		atomic_t count;
		struct rcu_head head;
	} u;
	unsigned char name[];
};

static inline struct external_name *external_name(struct dentry *dentry)
{
	return container_of(dentry->d_name.name, struct external_name, name[0]);
}

static void __d_free(struct rcu_head *head)
{
	struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);

	kmem_cache_free(dentry_cache, dentry); 
}

static void __d_free_external_name(struct rcu_head *head)
{
	struct external_name *name = container_of(head, struct external_name,
						  u.head);

	mod_node_page_state(page_pgdat(virt_to_page(name)),
			    NR_INDIRECTLY_RECLAIMABLE_BYTES,
			    -ksize(name));

	kfree(name);
}

static void __d_free_external(struct rcu_head *head)
{
	struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);

	__d_free_external_name(&external_name(dentry)->u.head);

	kmem_cache_free(dentry_cache, dentry);
}

static inline int dname_external(const struct dentry *dentry)
{
	return dentry->d_name.name != dentry->d_iname;
}

void take_dentry_name_snapshot(struct name_snapshot *name, struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	if (unlikely(dname_external(dentry))) {
		struct external_name *p = external_name(dentry);
		atomic_inc(&p->u.count);
		spin_unlock(&dentry->d_lock);
		name->name = p->name;
	} else {
		memcpy(name->inline_name, dentry->d_iname,
		       dentry->d_name.len + 1);
		spin_unlock(&dentry->d_lock);
		name->name = name->inline_name;
	}
}
EXPORT_SYMBOL(take_dentry_name_snapshot);

void release_dentry_name_snapshot(struct name_snapshot *name)
{
	if (unlikely(name->name != name->inline_name)) {
		struct external_name *p;
		p = container_of(name->name, struct external_name, name[0]);
		if (unlikely(atomic_dec_and_test(&p->u.count)))
			call_rcu(&p->u.head, __d_free_external_name);
	}
}
EXPORT_SYMBOL(release_dentry_name_snapshot);

static inline void __d_set_inode_and_type(struct dentry *dentry,
					  struct inode *inode,
					  unsigned type_flags)
{
	unsigned flags;

	dentry->d_inode = inode;
	flags = READ_ONCE(dentry->d_flags);
	flags &= ~(DCACHE_ENTRY_TYPE | DCACHE_FALLTHRU);
	flags |= type_flags;
	WRITE_ONCE(dentry->d_flags, flags);
}

static inline void __d_clear_type_and_inode(struct dentry *dentry)
{
	unsigned flags = READ_ONCE(dentry->d_flags);

	flags &= ~(DCACHE_ENTRY_TYPE | DCACHE_FALLTHRU);
	WRITE_ONCE(dentry->d_flags, flags);
	dentry->d_inode = NULL;
}

static void dentry_free(struct dentry *dentry)
{
	WARN_ON(!hlist_unhashed(&dentry->d_u.d_alias));
	if (unlikely(dname_external(dentry))) {
		struct external_name *p = external_name(dentry);
		if (likely(atomic_dec_and_test(&p->u.count))) {
			call_rcu(&dentry->d_u.d_rcu, __d_free_external);
			return;
		}
	}
	/* if dentry was never visible to RCU, immediate free is OK */
	if (!(dentry->d_flags & DCACHE_RCUACCESS))
		__d_free(&dentry->d_u.d_rcu);
	else
		call_rcu(&dentry->d_u.d_rcu, __d_free);
}

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined.
 */
static void dentry_iput(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
{
	struct inode *inode = dentry->d_inode;
	if (inode) {
		dentry->d_inode = NULL;
		list_del_init(&dentry->d_alias);
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
 * d_iput() operation if defined. Dentry has no refcount
 * and is unhashed.
 */
static void dentry_iput(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dentry->d_inode->i_lock)
{
	struct inode *inode = dentry->d_inode;
	if (inode) {
		__d_clear_type_and_inode(dentry);
		hlist_del_init(&dentry->d_u.d_alias);
		spin_unlock(&dentry->d_lock);
		spin_unlock(&inode->i_lock);
		if (!inode->i_nlink)
			fsnotify_inoderemove(inode);
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		else
			iput(inode);
	} else {
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
	}
}

/*
 * dentry_lru_(add|add_tail|del|del_init) must be called with dcache_lock held.
 */
static void dentry_lru_add(struct dentry *dentry)
{
	list_add(&dentry->d_lru, &dentry->d_sb->s_dentry_lru);
	dentry->d_sb->s_nr_dentry_unused++;
	dentry_stat.nr_unused++;
}

static void dentry_lru_add_tail(struct dentry *dentry)
{
	list_add_tail(&dentry->d_lru, &dentry->d_sb->s_dentry_lru);
	dentry->d_sb->s_nr_dentry_unused++;
	dentry_stat.nr_unused++;
}

static void dentry_lru_del(struct dentry *dentry)
{
	if (!list_empty(&dentry->d_lru)) {
		list_del(&dentry->d_lru);
		dentry->d_sb->s_nr_dentry_unused--;
		dentry_stat.nr_unused--;
	}
}

static void dentry_lru_del_init(struct dentry *dentry)
{
	if (likely(!list_empty(&dentry->d_lru))) {
		list_del_init(&dentry->d_lru);
		dentry->d_sb->s_nr_dentry_unused--;
		dentry_stat.nr_unused--;
	}
}

/**
 * d_kill - kill dentry and return parent
 * @dentry: dentry to kill
 *
 * The dentry must already be unhashed and removed from the LRU.
 *
 * If this is the root of the dentry tree, return NULL.
 */
static struct dentry *d_kill(struct dentry *dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
{
	struct dentry *parent;

	list_del(&dentry->d_u.d_child);
	dentry_stat.nr_dentry--;	/* For d_free, below */
	/*drops the locks, at that point nobody can reach this dentry */
	dentry_iput(dentry);
	parent = dentry->d_parent;
	d_free(dentry);
	return dentry == parent ? NULL : parent;
}
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined. dentry remains in-use.
 */
static void dentry_unlink_inode(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dentry->d_inode->i_lock)
{
	struct inode *inode = dentry->d_inode;

	raw_write_seqcount_begin(&dentry->d_seq);
	__d_clear_type_and_inode(dentry);
	hlist_del_init(&dentry->d_u.d_alias);
	raw_write_seqcount_end(&dentry->d_seq);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&inode->i_lock);
	if (!inode->i_nlink)
		fsnotify_inoderemove(inode);
	if (dentry->d_op && dentry->d_op->d_iput)
		dentry->d_op->d_iput(dentry, inode);
	else
		iput(inode);
}

/*
 * The DCACHE_LRU_LIST bit is set whenever the 'd_lru' entry
 * is in use - which includes both the "real" per-superblock
 * LRU list _and_ the DCACHE_SHRINK_LIST use.
 *
 * The DCACHE_SHRINK_LIST bit is set whenever the dentry is
 * on the shrink list (ie not on the superblock LRU list).
 *
 * The per-cpu "nr_dentry_unused" counters are updated with
 * the DCACHE_LRU_LIST bit.
 *
 * These helper functions make sure we always follow the
 * rules. d_lock must be held by the caller.
 */
#define D_FLAG_VERIFY(dentry,x) WARN_ON_ONCE(((dentry)->d_flags & (DCACHE_LRU_LIST | DCACHE_SHRINK_LIST)) != (x))
static void d_lru_add(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, 0);
	dentry->d_flags |= DCACHE_LRU_LIST;
	this_cpu_inc(nr_dentry_unused);
	WARN_ON_ONCE(!list_lru_add(&dentry->d_sb->s_dentry_lru, &dentry->d_lru));
}

static void d_lru_del(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
	dentry->d_flags &= ~DCACHE_LRU_LIST;
	this_cpu_dec(nr_dentry_unused);
	WARN_ON_ONCE(!list_lru_del(&dentry->d_sb->s_dentry_lru, &dentry->d_lru));
}

static void d_shrink_del(struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, DCACHE_SHRINK_LIST | DCACHE_LRU_LIST);
	list_del_init(&dentry->d_lru);
	dentry->d_flags &= ~(DCACHE_SHRINK_LIST | DCACHE_LRU_LIST);
	this_cpu_dec(nr_dentry_unused);
}

static void d_shrink_add(struct dentry *dentry, struct list_head *list)
{
	D_FLAG_VERIFY(dentry, 0);
	list_add(&dentry->d_lru, list);
	dentry->d_flags |= DCACHE_SHRINK_LIST | DCACHE_LRU_LIST;
	this_cpu_inc(nr_dentry_unused);
}

/*
 * These can only be called under the global LRU lock, ie during the
 * callback for freeing the LRU list. "isolate" removes it from the
 * LRU lists entirely, while shrink_move moves it to the indicated
 * private list.
 */
static void d_lru_isolate(struct list_lru_one *lru, struct dentry *dentry)
{
	D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
	dentry->d_flags &= ~DCACHE_LRU_LIST;
	this_cpu_dec(nr_dentry_unused);
	list_lru_isolate(lru, &dentry->d_lru);
}

static void d_lru_shrink_move(struct list_lru_one *lru, struct dentry *dentry,
			      struct list_head *list)
{
	D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
	dentry->d_flags |= DCACHE_SHRINK_LIST;
	list_lru_isolate_move(lru, &dentry->d_lru, list);
}

/**
 * d_drop - drop a dentry
 * @dentry: dentry to drop
 *
 * d_drop() unhashes the entry from the parent dentry hashes, so that it won't
 * be found through a VFS lookup any more. Note that this is different from
 * deleting the dentry - d_delete will try to mark the dentry negative if
 * possible, giving a successful _negative_ lookup, while d_drop will
 * just make the cache lookup fail.
 *
 * d_drop() is used mainly for stuff that wants to invalidate a dentry for some
 * reason (NFS timeouts or autofs deletes).
 *
 * __d_drop requires dentry->d_lock
 * ___d_drop doesn't mark dentry as "unhashed"
 *   (dentry->d_hash.pprev will be LIST_POISON2, not NULL).
 */
static void ___d_drop(struct dentry *dentry)
{
	struct hlist_bl_head *b;
	/*
	 * Hashed dentries are normally on the dentry hashtable,
	 * with the exception of those newly allocated by
	 * d_obtain_root, which are always IS_ROOT:
	 */
	if (unlikely(IS_ROOT(dentry)))
		b = &dentry->d_sb->s_roots;
	else
		b = d_hash(dentry->d_name.hash);

	hlist_bl_lock(b);
	__hlist_bl_del(&dentry->d_hash);
	hlist_bl_unlock(b);
}

void __d_drop(struct dentry *dentry)
{
	if (!d_unhashed(dentry)) {
		___d_drop(dentry);
		dentry->d_hash.pprev = NULL;
		write_seqcount_invalidate(&dentry->d_seq);
	}
}
EXPORT_SYMBOL(__d_drop);

void d_drop(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
}
EXPORT_SYMBOL(d_drop);

static inline void dentry_unlist(struct dentry *dentry, struct dentry *parent)
{
	struct dentry *next;
	/*
	 * Inform d_walk() and shrink_dentry_list() that we are no longer
	 * attached to the dentry tree
	 */
	dentry->d_flags |= DCACHE_DENTRY_KILLED;
	if (unlikely(list_empty(&dentry->d_child)))
		return;
	__list_del_entry(&dentry->d_child);
	/*
	 * Cursors can move around the list of children.  While we'd been
	 * a normal list member, it didn't matter - ->d_child.next would've
	 * been updated.  However, from now on it won't be and for the
	 * things like d_walk() it might end up with a nasty surprise.
	 * Normally d_walk() doesn't care about cursors moving around -
	 * ->d_lock on parent prevents that and since a cursor has no children
	 * of its own, we get through it without ever unlocking the parent.
	 * There is one exception, though - if we ascend from a child that
	 * gets killed as soon as we unlock it, the next sibling is found
	 * using the value left in its ->d_child.next.  And if _that_
	 * pointed to a cursor, and cursor got moved (e.g. by lseek())
	 * before d_walk() regains parent->d_lock, we'll end up skipping
	 * everything the cursor had been moved past.
	 *
	 * Solution: make sure that the pointer left behind in ->d_child.next
	 * points to something that won't be moving around.  I.e. skip the
	 * cursors.
	 */
	while (dentry->d_child.next != &parent->d_subdirs) {
		next = list_entry(dentry->d_child.next, struct dentry, d_child);
		if (likely(!(next->d_flags & DCACHE_DENTRY_CURSOR)))
			break;
		dentry->d_child.next = next->d_child.next;
	}
}

static void __dentry_kill(struct dentry *dentry)
{
	struct dentry *parent = NULL;
	bool can_free = true;
	if (!IS_ROOT(dentry))
		parent = dentry->d_parent;

	/*
	 * The dentry is now unrecoverably dead to the world.
	 */
	lockref_mark_dead(&dentry->d_lockref);

	/*
	 * inform the fs via d_prune that this dentry is about to be
	 * unhashed and destroyed.
	 */
	if (dentry->d_flags & DCACHE_OP_PRUNE)
		dentry->d_op->d_prune(dentry);

	if (dentry->d_flags & DCACHE_LRU_LIST) {
		if (!(dentry->d_flags & DCACHE_SHRINK_LIST))
			d_lru_del(dentry);
	}
	/* if it was on the hash then remove it */
	__d_drop(dentry);
	dentry_unlist(dentry, parent);
	if (parent)
		spin_unlock(&parent->d_lock);
	if (dentry->d_inode)
		dentry_unlink_inode(dentry);
	else
		spin_unlock(&dentry->d_lock);
	this_cpu_dec(nr_dentry);
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);

	spin_lock(&dentry->d_lock);
	if (dentry->d_flags & DCACHE_SHRINK_LIST) {
		dentry->d_flags |= DCACHE_MAY_FREE;
		can_free = false;
	}
	spin_unlock(&dentry->d_lock);
	if (likely(can_free))
		dentry_free(dentry);
	cond_resched();
}

static struct dentry *__lock_parent(struct dentry *dentry)
{
	struct dentry *parent;
	rcu_read_lock();
	spin_unlock(&dentry->d_lock);
again:
	parent = READ_ONCE(dentry->d_parent);
	spin_lock(&parent->d_lock);
	/*
	 * We can't blindly lock dentry until we are sure
	 * that we won't violate the locking order.
	 * Any changes of dentry->d_parent must have
	 * been done with parent->d_lock held, so
	 * spin_lock() above is enough of a barrier
	 * for checking if it's still our child.
	 */
	if (unlikely(parent != dentry->d_parent)) {
		spin_unlock(&parent->d_lock);
		goto again;
	}
	rcu_read_unlock();
	if (parent != dentry)
		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	else
		parent = NULL;
	return parent;
}

static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *parent = dentry->d_parent;
	if (IS_ROOT(dentry))
		return NULL;
	if (likely(spin_trylock(&parent->d_lock)))
		return parent;
	return __lock_parent(dentry);
}

static inline bool retain_dentry(struct dentry *dentry)
{
	WARN_ON(d_in_lookup(dentry));

	/* Unreachable? Get rid of it */
	if (unlikely(d_unhashed(dentry)))
		return false;

	if (unlikely(dentry->d_flags & DCACHE_DISCONNECTED))
		return false;

	if (unlikely(dentry->d_flags & DCACHE_OP_DELETE)) {
		if (dentry->d_op->d_delete(dentry))
			return false;
	}
	/* retain; LRU fodder */
	dentry->d_lockref.count--;
	if (unlikely(!(dentry->d_flags & DCACHE_LRU_LIST)))
		d_lru_add(dentry);
	else if (unlikely(!(dentry->d_flags & DCACHE_REFERENCED)))
		dentry->d_flags |= DCACHE_REFERENCED;
	return true;
}

/*
 * Finish off a dentry we've decided to kill.
 * dentry->d_lock must be held, returns with it unlocked.
 * Returns dentry requiring refcount drop, or NULL if we're done.
 */
static struct dentry *dentry_kill(struct dentry *dentry)
	__releases(dentry->d_lock)
{
	struct inode *inode = dentry->d_inode;
	struct dentry *parent = NULL;

	if (inode && unlikely(!spin_trylock(&inode->i_lock)))
		goto slow_positive;

	if (!IS_ROOT(dentry)) {
		parent = dentry->d_parent;
		if (unlikely(!spin_trylock(&parent->d_lock))) {
			parent = __lock_parent(dentry);
			if (likely(inode || !dentry->d_inode))
				goto got_locks;
			/* negative that became positive */
			if (parent)
				spin_unlock(&parent->d_lock);
			inode = dentry->d_inode;
			goto slow_positive;
		}
	}
	__dentry_kill(dentry);
	return parent;

slow_positive:
	spin_unlock(&dentry->d_lock);
	spin_lock(&inode->i_lock);
	spin_lock(&dentry->d_lock);
	parent = lock_parent(dentry);
got_locks:
	if (unlikely(dentry->d_lockref.count != 1)) {
		dentry->d_lockref.count--;
	} else if (likely(!retain_dentry(dentry))) {
		__dentry_kill(dentry);
		return parent;
	}
	/* we are keeping it, after all */
	if (inode)
		spin_unlock(&inode->i_lock);
	if (parent)
		spin_unlock(&parent->d_lock);
	spin_unlock(&dentry->d_lock);
	return NULL;
}

/*
 * Try to do a lockless dput(), and return whether that was successful.
 *
 * If unsuccessful, we return false, having already taken the dentry lock.
 *
 * The caller needs to hold the RCU read lock, so that the dentry is
 * guaranteed to stay around even if the refcount goes down to zero!
 */
static inline bool fast_dput(struct dentry *dentry)
{
	int ret;
	unsigned int d_flags;

	/*
	 * If we have a d_op->d_delete() operation, we sould not
	 * let the dentry count go to zero, so use "put_or_lock".
	 */
	if (unlikely(dentry->d_flags & DCACHE_OP_DELETE))
		return lockref_put_or_lock(&dentry->d_lockref);

	/*
	 * .. otherwise, we can try to just decrement the
	 * lockref optimistically.
	 */
	ret = lockref_put_return(&dentry->d_lockref);

	/*
	 * If the lockref_put_return() failed due to the lock being held
	 * by somebody else, the fast path has failed. We will need to
	 * get the lock, and then check the count again.
	 */
	if (unlikely(ret < 0)) {
		spin_lock(&dentry->d_lock);
		if (dentry->d_lockref.count > 1) {
			dentry->d_lockref.count--;
			spin_unlock(&dentry->d_lock);
			return true;
		}
		return false;
	}

	/*
	 * If we weren't the last ref, we're done.
	 */
	if (ret)
		return true;

	/*
	 * Careful, careful. The reference count went down
	 * to zero, but we don't hold the dentry lock, so
	 * somebody else could get it again, and do another
	 * dput(), and we need to not race with that.
	 *
	 * However, there is a very special and common case
	 * where we don't care, because there is nothing to
	 * do: the dentry is still hashed, it does not have
	 * a 'delete' op, and it's referenced and already on
	 * the LRU list.
	 *
	 * NOTE! Since we aren't locked, these values are
	 * not "stable". However, it is sufficient that at
	 * some point after we dropped the reference the
	 * dentry was hashed and the flags had the proper
	 * value. Other dentry users may have re-gotten
	 * a reference to the dentry and change that, but
	 * our work is done - we can leave the dentry
	 * around with a zero refcount.
	 */
	smp_rmb();
	d_flags = READ_ONCE(dentry->d_flags);
	d_flags &= DCACHE_REFERENCED | DCACHE_LRU_LIST | DCACHE_DISCONNECTED;

	/* Nothing to do? Dropping the reference was all we needed? */
	if (d_flags == (DCACHE_REFERENCED | DCACHE_LRU_LIST) && !d_unhashed(dentry))
		return true;

	/*
	 * Not the fast normal case? Get the lock. We've already decremented
	 * the refcount, but we'll need to re-check the situation after
	 * getting the lock.
	 */
	spin_lock(&dentry->d_lock);

	/*
	 * Did somebody else grab a reference to it in the meantime, and
	 * we're no longer the last user after all? Alternatively, somebody
	 * else could have killed it and marked it dead. Either way, we
	 * don't need to do anything else.
	 */
	if (dentry->d_lockref.count) {
		spin_unlock(&dentry->d_lock);
		return true;
	}

	/*
	 * Re-get the reference we optimistically dropped. We hold the
	 * lock, and we just tested that it was zero, so we can just
	 * set it to 1.
	 */
	dentry->d_lockref.count = 1;
	return false;
}


/* 
 * This is dput
 *
 * This is complicated by the fact that we do not want to put
 * dentries that are no longer on any hash chain on the unused
 * list: we'd much rather just get rid of them immediately.
 *
 * However, that implies that we have to traverse the dentry
 * tree upwards to the parents which might _also_ now be
 * scheduled for deletion (it may have been only waiting for
 * its last child to go away).
 *
 * This tail recursion is done by hand as we don't want to depend
 * on the compiler to always get this right (gcc generally doesn't).
 * Real recursion would eat up our stack space.
 */

/*
 * dput - release a dentry
 * @dentry: dentry to release 
 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 *
 * no dcache lock, please.
 */

void dput(struct dentry *dentry)
{
	if (!dentry)
		return;

repeat:
	if (atomic_read(&dentry->d_count) == 1)
		might_sleep();
	if (!atomic_dec_and_lock(&dentry->d_count, &dcache_lock))
		return;

	spin_lock(&dentry->d_lock);
	if (atomic_read(&dentry->d_count)) {
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
		return;
	}

	/*
	 * AV: ->d_delete() is _NOT_ allowed to block now.
	 */
	if (dentry->d_op && dentry->d_op->d_delete) {
		if (dentry->d_op->d_delete(dentry))
			goto unhash_it;
	}
	/* Unreachable? Get rid of it */
 	if (d_unhashed(dentry))
		goto kill_it;
  	if (list_empty(&dentry->d_lru)) {
  		dentry->d_flags |= DCACHE_REFERENCED;
		dentry_lru_add(dentry);
  	}
 	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	return;

unhash_it:
	__d_drop(dentry);
kill_it:
	/* if dentry was on the d_lru list delete it from there */
	dentry_lru_del(dentry);
	dentry = d_kill(dentry);
	if (dentry)
		goto repeat;
}

/**
 * d_invalidate - invalidate a dentry
 * @dentry: dentry to invalidate
 *
 * Try to invalidate the dentry if it turns out to be
 * possible. If there are other dentries that can be
 * reached through this one we can't delete it and we
 * return -EBUSY. On success we return 0.
 *
 * no dcache lock.
 */
 
int d_invalidate(struct dentry * dentry)
{
	/*
	 * If it's already been dropped, return OK.
	 */
	spin_lock(&dcache_lock);
	if (d_unhashed(dentry)) {
		spin_unlock(&dcache_lock);
		return 0;
	}
	/*
	 * Check whether to do a partial shrink_dcache
	 * to get rid of unused child entries.
	 */
	if (!list_empty(&dentry->d_subdirs)) {
		spin_unlock(&dcache_lock);
		shrink_dcache_parent(dentry);
		spin_lock(&dcache_lock);
	}

	/*
	 * Somebody else still using it?
	 *
	 * If it's a directory, we can't drop it
	 * for fear of somebody re-populating it
	 * with children (even though dropping it
	 * would make it unreachable from the root,
	 * we might still populate it if it was a
	 * working directory or similar).
	 */
	spin_lock(&dentry->d_lock);
	if (atomic_read(&dentry->d_count) > 1) {
		if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)) {
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			return -EBUSY;
		}
	}

	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	return 0;
}

/* This should be called _only_ with dcache_lock held */

static inline struct dentry * __dget_locked(struct dentry *dentry)
{
	atomic_inc(&dentry->d_count);
	dentry_lru_del_init(dentry);
	return dentry;
}

struct dentry * dget_locked(struct dentry *dentry)
{
	return __dget_locked(dentry);
}
 */
void dput(struct dentry *dentry)
{
	while (dentry) {
		might_sleep();

		rcu_read_lock();
		if (likely(fast_dput(dentry))) {
			rcu_read_unlock();
			return;
		}

		/* Slow case: now with the dentry lock held */
		rcu_read_unlock();

		if (likely(retain_dentry(dentry))) {
			spin_unlock(&dentry->d_lock);
			return;
		}

		dentry = dentry_kill(dentry);
	}
}
EXPORT_SYMBOL(dput);


/* This must be called with d_lock held */
static inline void __dget_dlock(struct dentry *dentry)
{
	dentry->d_lockref.count++;
}

static inline void __dget(struct dentry *dentry)
{
	lockref_get(&dentry->d_lockref);
}

struct dentry *dget_parent(struct dentry *dentry)
{
	int gotref;
	struct dentry *ret;

	/*
	 * Do optimistic parent lookup without any
	 * locking.
	 */
	rcu_read_lock();
	ret = READ_ONCE(dentry->d_parent);
	gotref = lockref_get_not_zero(&ret->d_lockref);
	rcu_read_unlock();
	if (likely(gotref)) {
		if (likely(ret == READ_ONCE(dentry->d_parent)))
			return ret;
		dput(ret);
	}

repeat:
	/*
	 * Don't need rcu_dereference because we re-check it was correct under
	 * the lock.
	 */
	rcu_read_lock();
	ret = dentry->d_parent;
	spin_lock(&ret->d_lock);
	if (unlikely(ret != dentry->d_parent)) {
		spin_unlock(&ret->d_lock);
		rcu_read_unlock();
		goto repeat;
	}
	rcu_read_unlock();
	BUG_ON(!ret->d_lockref.count);
	ret->d_lockref.count++;
	spin_unlock(&ret->d_lock);
	return ret;
}
EXPORT_SYMBOL(dget_parent);

static struct dentry * __d_find_any_alias(struct inode *inode)
{
	struct dentry *alias;

	if (hlist_empty(&inode->i_dentry))
		return NULL;
	alias = hlist_entry(inode->i_dentry.first, struct dentry, d_u.d_alias);
	__dget(alias);
	return alias;
}

/**
 * d_find_any_alias - find any alias for a given inode
 * @inode: inode to find an alias for
 *
 * If any aliases exist for the given inode, take and return a
 * reference for one of them.  If no aliases exist, return %NULL.
 */
struct dentry *d_find_any_alias(struct inode *inode)
{
	struct dentry *de;

	spin_lock(&inode->i_lock);
	de = __d_find_any_alias(inode);
	spin_unlock(&inode->i_lock);
	return de;
}
EXPORT_SYMBOL(d_find_any_alias);

/**
 * d_find_alias - grab a hashed alias of inode
 * @inode: inode in question
 * @want_discon:  flag, used by d_splice_alias, to request
 *          that only a DISCONNECTED alias be returned.
 *
 * If inode has a hashed alias, or is a directory and has any alias,
 * acquire the reference to alias and return it. Otherwise return NULL.
 * Notice that if inode is a directory there can be only one alias and
 * it can be unhashed only if it has no children, or if it is the root
 * of a filesystem.
 *
 * If the inode has an IS_ROOT, DCACHE_DISCONNECTED alias, then prefer
 * any other hashed alias over that one unless @want_discon is set,
 * in which case only return an IS_ROOT, DCACHE_DISCONNECTED alias.
 */

static struct dentry * __d_find_alias(struct inode *inode, int want_discon)
{
	struct list_head *head, *next, *tmp;
	struct dentry *alias, *discon_alias=NULL;

	head = &inode->i_dentry;
	next = inode->i_dentry.next;
	while (next != head) {
		tmp = next;
		next = tmp->next;
		prefetch(next);
		alias = list_entry(tmp, struct dentry, d_alias);
 		if (S_ISDIR(inode->i_mode) || !d_unhashed(alias)) {
			if (IS_ROOT(alias) &&
			    (alias->d_flags & DCACHE_DISCONNECTED))
				discon_alias = alias;
			else if (!want_discon) {
				__dget_locked(alias);
				return alias;
			}
		}
	}
	if (discon_alias)
		__dget_locked(discon_alias);
	return discon_alias;
}

struct dentry * d_find_alias(struct inode *inode)
{
	struct dentry *de = NULL;

	if (!list_empty(&inode->i_dentry)) {
		spin_lock(&dcache_lock);
		de = __d_find_alias(inode, 0);
		spin_unlock(&dcache_lock);
	}
	return de;
}
 * of a filesystem, or if the directory was renamed and d_revalidate
 * was the first vfs operation to notice.
 *
 * If the inode has an IS_ROOT, DCACHE_DISCONNECTED alias, then prefer
 * any other hashed alias over that one.
 */
static struct dentry *__d_find_alias(struct inode *inode)
{
	struct dentry *alias;

	if (S_ISDIR(inode->i_mode))
		return __d_find_any_alias(inode);

	hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) {
		spin_lock(&alias->d_lock);
 		if (!d_unhashed(alias)) {
			__dget_dlock(alias);
			spin_unlock(&alias->d_lock);
			return alias;
		}
		spin_unlock(&alias->d_lock);
	}
	return NULL;
}

struct dentry *d_find_alias(struct inode *inode)
{
	struct dentry *de = NULL;

	if (!hlist_empty(&inode->i_dentry)) {
		spin_lock(&inode->i_lock);
		de = __d_find_alias(inode);
		spin_unlock(&inode->i_lock);
	}
	return de;
}
EXPORT_SYMBOL(d_find_alias);

/*
 *	Try to kill dentries associated with this inode.
 * WARNING: you must own a reference to inode.
 */
void d_prune_aliases(struct inode *inode)
{
	struct dentry *dentry;
restart:
	spin_lock(&dcache_lock);
	list_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		spin_lock(&dentry->d_lock);
		if (!atomic_read(&dentry->d_count)) {
			__dget_locked(dentry);
			__d_drop(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			dput(dentry);
			goto restart;
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&dcache_lock);
}

/*
 * Throw away a dentry - free the inode, dput the parent.  This requires that
 * the LRU list has already been removed.
 *
 * Try to prune ancestors as well.  This is necessary to prevent
 * quadratic behavior of shrink_dcache_parent(), but is also expected
 * to be beneficial in reducing dentry cache fragmentation.
 */
static void prune_one_dentry(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
	__acquires(dcache_lock)
{
	__d_drop(dentry);
	dentry = d_kill(dentry);

	/*
	 * Prune ancestors.  Locking is simpler than in dput(),
	 * because dcache_lock needs to be taken anyway.
	 */
	spin_lock(&dcache_lock);
	while (dentry) {
		if (!atomic_dec_and_lock(&dentry->d_count, &dentry->d_lock))
			return;

		if (dentry->d_op && dentry->d_op->d_delete)
			dentry->d_op->d_delete(dentry);
		dentry_lru_del_init(dentry);
		__d_drop(dentry);
		dentry = d_kill(dentry);
		spin_lock(&dcache_lock);
	}
}

/*
 * Shrink the dentry LRU on a given superblock.
 * @sb   : superblock to shrink dentry LRU.
 * @count: If count is NULL, we prune all dentries on superblock.
 * @flags: If flags is non-zero, we need to do special processing based on
 * which flags are set. This means we don't need to maintain multiple
 * similar copies of this loop.
 */
static void __shrink_dcache_sb(struct super_block *sb, int *count, int flags)
{
	LIST_HEAD(referenced);
	LIST_HEAD(tmp);
	struct dentry *dentry;
	int cnt = 0;

	BUG_ON(!sb);
	BUG_ON((flags & DCACHE_REFERENCED) && count == NULL);
	spin_lock(&dcache_lock);
	if (count != NULL)
		/* called from prune_dcache() and shrink_dcache_parent() */
		cnt = *count;
restart:
	if (count == NULL)
		list_splice_init(&sb->s_dentry_lru, &tmp);
	else {
		while (!list_empty(&sb->s_dentry_lru)) {
			dentry = list_entry(sb->s_dentry_lru.prev,
					struct dentry, d_lru);
			BUG_ON(dentry->d_sb != sb);

			spin_lock(&dentry->d_lock);
			/*
			 * If we are honouring the DCACHE_REFERENCED flag and
			 * the dentry has this flag set, don't free it. Clear
			 * the flag and put it back on the LRU.
			 */
			if ((flags & DCACHE_REFERENCED)
				&& (dentry->d_flags & DCACHE_REFERENCED)) {
				dentry->d_flags &= ~DCACHE_REFERENCED;
				list_move_tail(&dentry->d_lru, &referenced);
				spin_unlock(&dentry->d_lock);
			} else {
				list_move_tail(&dentry->d_lru, &tmp);
				spin_unlock(&dentry->d_lock);
				cnt--;
				if (!cnt)
					break;
			}
			cond_resched_lock(&dcache_lock);
		}
	}
	while (!list_empty(&tmp)) {
		dentry = list_entry(tmp.prev, struct dentry, d_lru);
		dentry_lru_del_init(dentry);
		spin_lock(&dentry->d_lock);
		/*
		 * We found an inuse dentry which was not removed from
		 * the LRU because of laziness during lookup.  Do not free
		 * it - just keep it off the LRU list.
		 */
		if (atomic_read(&dentry->d_count)) {
			spin_unlock(&dentry->d_lock);
			continue;
		}
		prune_one_dentry(dentry);
		/* dentry->d_lock was dropped in prune_one_dentry() */
		cond_resched_lock(&dcache_lock);
	}
	if (count == NULL && !list_empty(&sb->s_dentry_lru))
		goto restart;
	if (count != NULL)
		*count = cnt;
	if (!list_empty(&referenced))
		list_splice(&referenced, &sb->s_dentry_lru);
	spin_unlock(&dcache_lock);
}

/**
 * prune_dcache - shrink the dcache
 * @count: number of entries to try to free
 *
 * Shrink the dcache. This is done when we need more memory, or simply when we
 * need to unmount something (at which point we need to unuse all dentries).
 *
 * This function may fail to free any resources if all the dentries are in use.
 */
static void prune_dcache(int count)
{
	struct super_block *sb;
	int w_count;
	int unused = dentry_stat.nr_unused;
	int prune_ratio;
	int pruned;

	if (unused == 0 || count == 0)
		return;
	spin_lock(&dcache_lock);
restart:
	if (count >= unused)
		prune_ratio = 1;
	else
		prune_ratio = unused / count;
	spin_lock(&sb_lock);
	list_for_each_entry(sb, &super_blocks, s_list) {
		if (sb->s_nr_dentry_unused == 0)
			continue;
		sb->s_count++;
		/* Now, we reclaim unused dentrins with fairness.
		 * We reclaim them same percentage from each superblock.
		 * We calculate number of dentries to scan on this sb
		 * as follows, but the implementation is arranged to avoid
		 * overflows:
		 * number of dentries to scan on this sb =
		 * count * (number of dentries on this sb /
		 * number of dentries in the machine)
		 */
		spin_unlock(&sb_lock);
		if (prune_ratio != 1)
			w_count = (sb->s_nr_dentry_unused / prune_ratio) + 1;
		else
			w_count = sb->s_nr_dentry_unused;
		pruned = w_count;
		/*
		 * We need to be sure this filesystem isn't being unmounted,
		 * otherwise we could race with generic_shutdown_super(), and
		 * end up holding a reference to an inode while the filesystem
		 * is unmounted.  So we try to get s_umount, and make sure
		 * s_root isn't NULL.
		 */
		if (down_read_trylock(&sb->s_umount)) {
			if ((sb->s_root != NULL) &&
			    (!list_empty(&sb->s_dentry_lru))) {
				spin_unlock(&dcache_lock);
				__shrink_dcache_sb(sb, &w_count,
						DCACHE_REFERENCED);
				pruned -= w_count;
				spin_lock(&dcache_lock);
			}
			up_read(&sb->s_umount);
		}
		spin_lock(&sb_lock);
		count -= pruned;
		/*
		 * restart only when sb is no longer on the list and
		 * we have more work to do.
		 */
		if (__put_super_and_need_restart(sb) && count > 0) {
			spin_unlock(&sb_lock);
			goto restart;
		}
	}
	spin_unlock(&sb_lock);
	spin_unlock(&dcache_lock);
}

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias) {
		spin_lock(&dentry->d_lock);
		if (!dentry->d_lockref.count) {
			struct dentry *parent = lock_parent(dentry);
			if (likely(!dentry->d_lockref.count)) {
				__dentry_kill(dentry);
				dput(parent);
				goto restart;
			}
			if (parent)
				spin_unlock(&parent->d_lock);
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL(d_prune_aliases);

/*
 * Lock a dentry from shrink list.
 * Called under rcu_read_lock() and dentry->d_lock; the former
 * guarantees that nothing we access will be freed under us.
 * Note that dentry is *not* protected from concurrent dentry_kill(),
 * d_delete(), etc.
 *
 * Return false if dentry has been disrupted or grabbed, leaving
 * the caller to kick it off-list.  Otherwise, return true and have
 * that dentry's inode and parent both locked.
 */
static bool shrink_lock_dentry(struct dentry *dentry)
{
	struct inode *inode;
	struct dentry *parent;

	if (dentry->d_lockref.count)
		return false;

	inode = dentry->d_inode;
	if (inode && unlikely(!spin_trylock(&inode->i_lock))) {
		spin_unlock(&dentry->d_lock);
		spin_lock(&inode->i_lock);
		spin_lock(&dentry->d_lock);
		if (unlikely(dentry->d_lockref.count))
			goto out;
		/* changed inode means that somebody had grabbed it */
		if (unlikely(inode != dentry->d_inode))
			goto out;
	}

	parent = dentry->d_parent;
	if (IS_ROOT(dentry) || likely(spin_trylock(&parent->d_lock)))
		return true;

	spin_unlock(&dentry->d_lock);
	spin_lock(&parent->d_lock);
	if (unlikely(parent != dentry->d_parent)) {
		spin_unlock(&parent->d_lock);
		spin_lock(&dentry->d_lock);
		goto out;
	}
	spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	if (likely(!dentry->d_lockref.count))
		return true;
	spin_unlock(&parent->d_lock);
out:
	if (inode)
		spin_unlock(&inode->i_lock);
	return false;
}

static void shrink_dentry_list(struct list_head *list)
{
	while (!list_empty(list)) {
		struct dentry *dentry, *parent;

		dentry = list_entry(list->prev, struct dentry, d_lru);
		spin_lock(&dentry->d_lock);
		rcu_read_lock();
		if (!shrink_lock_dentry(dentry)) {
			bool can_free = false;
			rcu_read_unlock();
			d_shrink_del(dentry);
			if (dentry->d_lockref.count < 0)
				can_free = dentry->d_flags & DCACHE_MAY_FREE;
			spin_unlock(&dentry->d_lock);
			if (can_free)
				dentry_free(dentry);
			continue;
		}
		rcu_read_unlock();
		d_shrink_del(dentry);
		parent = dentry->d_parent;
		__dentry_kill(dentry);
		if (parent == dentry)
			continue;
		/*
		 * We need to prune ancestors too. This is necessary to prevent
		 * quadratic behavior of shrink_dcache_parent(), but is also
		 * expected to be beneficial in reducing dentry cache
		 * fragmentation.
		 */
		dentry = parent;
		while (dentry && !lockref_put_or_lock(&dentry->d_lockref))
			dentry = dentry_kill(dentry);
	}
}

static enum lru_status dentry_lru_isolate(struct list_head *item,
		struct list_lru_one *lru, spinlock_t *lru_lock, void *arg)
{
	struct list_head *freeable = arg;
	struct dentry	*dentry = container_of(item, struct dentry, d_lru);


	/*
	 * we are inverting the lru lock/dentry->d_lock here,
	 * so use a trylock. If we fail to get the lock, just skip
	 * it
	 */
	if (!spin_trylock(&dentry->d_lock))
		return LRU_SKIP;

	/*
	 * Referenced dentries are still in use. If they have active
	 * counts, just remove them from the LRU. Otherwise give them
	 * another pass through the LRU.
	 */
	if (dentry->d_lockref.count) {
		d_lru_isolate(lru, dentry);
		spin_unlock(&dentry->d_lock);
		return LRU_REMOVED;
	}

	if (dentry->d_flags & DCACHE_REFERENCED) {
		dentry->d_flags &= ~DCACHE_REFERENCED;
		spin_unlock(&dentry->d_lock);

		/*
		 * The list move itself will be made by the common LRU code. At
		 * this point, we've dropped the dentry->d_lock but keep the
		 * lru lock. This is safe to do, since every list movement is
		 * protected by the lru lock even if both locks are held.
		 *
		 * This is guaranteed by the fact that all LRU management
		 * functions are intermediated by the LRU API calls like
		 * list_lru_add and list_lru_del. List movement in this file
		 * only ever occur through this functions or through callbacks
		 * like this one, that are called from the LRU API.
		 *
		 * The only exceptions to this are functions like
		 * shrink_dentry_list, and code that first checks for the
		 * DCACHE_SHRINK_LIST flag.  Those are guaranteed to be
		 * operating only with stack provided lists after they are
		 * properly isolated from the main list.  It is thus, always a
		 * local access.
		 */
		return LRU_ROTATE;
	}

	d_lru_shrink_move(lru, dentry, freeable);
	spin_unlock(&dentry->d_lock);

	return LRU_REMOVED;
}

/**
 * prune_dcache_sb - shrink the dcache
 * @sb: superblock
 * @sc: shrink control, passed to list_lru_shrink_walk()
 *
 * Attempt to shrink the superblock dcache LRU by @sc->nr_to_scan entries. This
 * is done when we need more memory and called from the superblock shrinker
 * function.
 *
 * This function may fail to free any resources if all the dentries are in
 * use.
 */
long prune_dcache_sb(struct super_block *sb, struct shrink_control *sc)
{
	LIST_HEAD(dispose);
	long freed;

	freed = list_lru_shrink_walk(&sb->s_dentry_lru, sc,
				     dentry_lru_isolate, &dispose);
	shrink_dentry_list(&dispose);
	return freed;
}

static enum lru_status dentry_lru_isolate_shrink(struct list_head *item,
		struct list_lru_one *lru, spinlock_t *lru_lock, void *arg)
{
	struct list_head *freeable = arg;
	struct dentry	*dentry = container_of(item, struct dentry, d_lru);

	/*
	 * we are inverting the lru lock/dentry->d_lock here,
	 * so use a trylock. If we fail to get the lock, just skip
	 * it
	 */
	if (!spin_trylock(&dentry->d_lock))
		return LRU_SKIP;

	d_lru_shrink_move(lru, dentry, freeable);
	spin_unlock(&dentry->d_lock);

	return LRU_REMOVED;
}


/**
 * shrink_dcache_sb - shrink dcache for a superblock
 * @sb: superblock
 *
 * Shrink the dcache for the specified super block. This
 * is used to free the dcache before unmounting a file
 * system
 */
void shrink_dcache_sb(struct super_block * sb)
{
	__shrink_dcache_sb(sb, NULL, 0);
}

/*
 * destroy a single subtree of dentries for unmount
 * - see the comments on shrink_dcache_for_umount() for a description of the
 *   locking
 */
static void shrink_dcache_for_umount_subtree(struct dentry *dentry)
{
	struct dentry *parent;
	unsigned detached = 0;

	BUG_ON(!IS_ROOT(dentry));

	/* detach this root from the system */
	spin_lock(&dcache_lock);
	dentry_lru_del_init(dentry);
	__d_drop(dentry);
	spin_unlock(&dcache_lock);

	for (;;) {
		/* descend to the first leaf in the current subtree */
		while (!list_empty(&dentry->d_subdirs)) {
			struct dentry *loop;

			/* this is a branch with children - detach all of them
			 * from the system in one go */
			spin_lock(&dcache_lock);
			list_for_each_entry(loop, &dentry->d_subdirs,
					    d_u.d_child) {
				dentry_lru_del_init(loop);
				__d_drop(loop);
				cond_resched_lock(&dcache_lock);
			}
			spin_unlock(&dcache_lock);

			/* move to the first child */
			dentry = list_entry(dentry->d_subdirs.next,
					    struct dentry, d_u.d_child);
		}

		/* consume the dentries from this leaf up through its parents
		 * until we find one with children or run out altogether */
		do {
			struct inode *inode;

			if (atomic_read(&dentry->d_count) != 0) {
				printk(KERN_ERR
				       "BUG: Dentry %p{i=%lx,n=%s}"
				       " still in use (%d)"
				       " [unmount of %s %s]\n",
				       dentry,
				       dentry->d_inode ?
				       dentry->d_inode->i_ino : 0UL,
				       dentry->d_name.name,
				       atomic_read(&dentry->d_count),
				       dentry->d_sb->s_type->name,
				       dentry->d_sb->s_id);
				BUG();
			}

			parent = dentry->d_parent;
			if (parent == dentry)
				parent = NULL;
			else
				atomic_dec(&parent->d_count);

			list_del(&dentry->d_u.d_child);
			detached++;

			inode = dentry->d_inode;
			if (inode) {
				dentry->d_inode = NULL;
				list_del_init(&dentry->d_alias);
				if (dentry->d_op && dentry->d_op->d_iput)
					dentry->d_op->d_iput(dentry, inode);
				else
					iput(inode);
			}

			d_free(dentry);

			/* finished when we fall off the top of the tree,
			 * otherwise we ascend to the parent and move to the
			 * next sibling if there is one */
			if (!parent)
				goto out;

			dentry = parent;

		} while (list_empty(&dentry->d_subdirs));

		dentry = list_entry(dentry->d_subdirs.next,
				    struct dentry, d_u.d_child);
	}
out:
	/* several dentries were freed, need to correct nr_dentry */
	spin_lock(&dcache_lock);
	dentry_stat.nr_dentry -= detached;
	spin_unlock(&dcache_lock);
}

/*
 * destroy the dentries attached to a superblock on unmounting
 * - we don't need to use dentry->d_lock, and only need dcache_lock when
 *   removing the dentry from the system lists and hashes because:
 *   - the superblock is detached from all mountings and open files, so the
 *     dentry trees will not be rearranged by the VFS
 *   - s_umount is write-locked, so the memory pressure shrinker will ignore
 *     any dentries belonging to this superblock that it comes across
 *   - the filesystem itself is no longer permitted to rearrange the dentries
 *     in this superblock
 */
void shrink_dcache_for_umount(struct super_block *sb)
{
	struct dentry *dentry;

	if (down_read_trylock(&sb->s_umount))
		BUG();

	dentry = sb->s_root;
	sb->s_root = NULL;
	atomic_dec(&dentry->d_count);
	shrink_dcache_for_umount_subtree(dentry);

	while (!hlist_empty(&sb->s_anon)) {
		dentry = hlist_entry(sb->s_anon.first, struct dentry, d_hash);
		shrink_dcache_for_umount_subtree(dentry);
	}
 * Shrink the dcache for the specified super block. This is used to free
 * the dcache before unmounting a file system.
 */
void shrink_dcache_sb(struct super_block *sb)
{
	do {
		LIST_HEAD(dispose);

		list_lru_walk(&sb->s_dentry_lru,
			dentry_lru_isolate_shrink, &dispose, 1024);
		shrink_dentry_list(&dispose);
	} while (list_lru_count(&sb->s_dentry_lru) > 0);
}
EXPORT_SYMBOL(shrink_dcache_sb);

/**
 * enum d_walk_ret - action to talke during tree walk
 * @D_WALK_CONTINUE:	contrinue walk
 * @D_WALK_QUIT:	quit walk
 * @D_WALK_NORETRY:	quit when retry is needed
 * @D_WALK_SKIP:	skip this dentry and its children
 */
enum d_walk_ret {
	D_WALK_CONTINUE,
	D_WALK_QUIT,
	D_WALK_NORETRY,
	D_WALK_SKIP,
};

/**
 * d_walk - walk the dentry tree
 * @parent:	start of walk
 * @data:	data passed to @enter() and @finish()
 * @enter:	callback when first entering the dentry
 *
 * The @enter() callbacks are called with d_lock held.
 */
static void d_walk(struct dentry *parent, void *data,
		   enum d_walk_ret (*enter)(void *, struct dentry *))
{
	struct dentry *this_parent;
	struct list_head *next;
	unsigned seq = 0;
	enum d_walk_ret ret;
	bool retry = true;

again:
	read_seqbegin_or_lock(&rename_lock, &seq);
	this_parent = parent;
	spin_lock(&this_parent->d_lock);

	ret = enter(data, this_parent);
	switch (ret) {
	case D_WALK_CONTINUE:
		break;
	case D_WALK_QUIT:
	case D_WALK_SKIP:
		goto out_unlock;
	case D_WALK_NORETRY:
		retry = false;
		break;
	}
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_child);
		next = tmp->next;

		if (unlikely(dentry->d_flags & DCACHE_DENTRY_CURSOR))
			continue;

		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);

		ret = enter(data, dentry);
		switch (ret) {
		case D_WALK_CONTINUE:
			break;
		case D_WALK_QUIT:
			spin_unlock(&dentry->d_lock);
			goto out_unlock;
		case D_WALK_NORETRY:
			retry = false;
			break;
		case D_WALK_SKIP:
			spin_unlock(&dentry->d_lock);
			continue;
		}

		if (!list_empty(&dentry->d_subdirs)) {
			spin_unlock(&this_parent->d_lock);
			spin_release(&dentry->d_lock.dep_map, 1, _RET_IP_);
			this_parent = dentry;
			spin_acquire(&this_parent->d_lock.dep_map, 0, 1, _RET_IP_);
			goto repeat;
		}
		spin_unlock(&dentry->d_lock);
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	rcu_read_lock();
ascend:
	if (this_parent != parent) {
		struct dentry *child = this_parent;
		this_parent = child->d_parent;

		spin_unlock(&child->d_lock);
		spin_lock(&this_parent->d_lock);

		/* might go back up the wrong parent if we have had a rename. */
		if (need_seqretry(&rename_lock, seq))
			goto rename_retry;
		/* go into the first sibling still alive */
		do {
			next = child->d_child.next;
			if (next == &this_parent->d_subdirs)
				goto ascend;
			child = list_entry(next, struct dentry, d_child);
		} while (unlikely(child->d_flags & DCACHE_DENTRY_KILLED));
		rcu_read_unlock();
		goto resume;
	}
	if (need_seqretry(&rename_lock, seq))
		goto rename_retry;
	rcu_read_unlock();

out_unlock:
	spin_unlock(&this_parent->d_lock);
	done_seqretry(&rename_lock, seq);
	return;

rename_retry:
	spin_unlock(&this_parent->d_lock);
	rcu_read_unlock();
	BUG_ON(seq & 1);
	if (!retry)
		return;
	seq = 1;
	goto again;
}

/*
 * Search for at least 1 mount point in the dentry's subdirs.
 * We descend to the next level whenever the d_subdirs
 * list is non-empty and continue searching.
 */
 
struct check_mount {
	struct vfsmount *mnt;
	unsigned int mounted;
};

static enum d_walk_ret path_check_mount(void *data, struct dentry *dentry)
{
	struct check_mount *info = data;
	struct path path = { .mnt = info->mnt, .dentry = dentry };

	if (likely(!d_mountpoint(dentry)))
		return D_WALK_CONTINUE;
	if (__path_is_mountpoint(&path)) {
		info->mounted = 1;
		return D_WALK_QUIT;
	}
	return D_WALK_CONTINUE;
}

/**
 * path_has_submounts - check for mounts over a dentry in the
 *                      current namespace.
 * @parent: path to check.
 *
 * Return true if the parent or its subdirectories contain
 * a mount point in the current namespace.
 */
 
int have_submounts(struct dentry *parent)
{
	struct dentry *this_parent = parent;
	struct list_head *next;

	spin_lock(&dcache_lock);
	if (d_mountpoint(parent))
		goto positive;
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		/* Have we found a mount point ? */
		if (d_mountpoint(dentry))
			goto positive;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
	return 0; /* No mount points found in tree */
positive:
	spin_unlock(&dcache_lock);
	return 1;
}

/*
 * Search the dentry child list for the specified parent,
int have_submounts(struct dentry *parent)
int path_has_submounts(const struct path *parent)
{
	struct check_mount data = { .mnt = parent->mnt, .mounted = 0 };

	read_seqlock_excl(&mount_lock);
	d_walk(parent->dentry, &data, path_check_mount);
	read_sequnlock_excl(&mount_lock);

	return data.mounted;
}
EXPORT_SYMBOL(path_has_submounts);

/*
 * Called by mount code to set a mountpoint and check if the mountpoint is
 * reachable (e.g. NFS can unhash a directory dentry and then the complete
 * subtree can become unreachable).
 *
 * Only one of d_invalidate() and d_set_mounted() must succeed.  For
 * this reason take rename_lock and d_lock on dentry and ancestors.
 */
int d_set_mounted(struct dentry *dentry)
{
	struct dentry *p;
	int ret = -ENOENT;
	write_seqlock(&rename_lock);
	for (p = dentry->d_parent; !IS_ROOT(p); p = p->d_parent) {
		/* Need exclusion wrt. d_invalidate() */
		spin_lock(&p->d_lock);
		if (unlikely(d_unhashed(p))) {
			spin_unlock(&p->d_lock);
			goto out;
		}
		spin_unlock(&p->d_lock);
	}
	spin_lock(&dentry->d_lock);
	if (!d_unlinked(dentry)) {
		ret = -EBUSY;
		if (!d_mountpoint(dentry)) {
			dentry->d_flags |= DCACHE_MOUNTED;
			ret = 0;
		}
	}
 	spin_unlock(&dentry->d_lock);
out:
	write_sequnlock(&rename_lock);
	return ret;
}

/*
 * Search the dentry child list of the specified parent,
 * and move any unused dentries to the end of the unused
 * list for prune_dcache(). We descend to the next level
 * whenever the d_subdirs list is non-empty and continue
 * searching.
 *
 * It returns zero iff there are no unused children,
 * otherwise  it returns the number of children moved to
 * the end of the unused list. This may not be the total
 * number of unused children, because select_parent can
 * drop the lock and return early due to latency
 * constraints.
 */
static int select_parent(struct dentry * parent)
{
	struct dentry *this_parent = parent;
	struct list_head *next;
	int found = 0;

	spin_lock(&dcache_lock);
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;

		dentry_lru_del_init(dentry);
		/* 
		 * move only zero ref count dentries to the end 
		 * of the unused list for prune_dcache
		 */
		if (!atomic_read(&dentry->d_count)) {
			dentry_lru_add_tail(dentry);
			found++;
		}

		/*
		 * We can return to the caller if we have found some (this
		 * ensures forward progress). We'll be coming back to find
		 * the rest.
		 */
		if (found && need_resched())
			goto out;

		/*
		 * Descend a level if the d_subdirs list is non-empty.
		 */
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
out:
	spin_unlock(&dcache_lock);
	return found;

struct select_data {
	struct dentry *start;
	struct list_head dispose;
	int found;
};

static enum d_walk_ret select_collect(void *_data, struct dentry *dentry)
{
	struct select_data *data = _data;
	enum d_walk_ret ret = D_WALK_CONTINUE;

	if (data->start == dentry)
		goto out;

	if (dentry->d_flags & DCACHE_SHRINK_LIST) {
		data->found++;
	} else {
		if (dentry->d_flags & DCACHE_LRU_LIST)
			d_lru_del(dentry);
		if (!dentry->d_lockref.count) {
			d_shrink_add(dentry, &data->dispose);
			data->found++;
		}
	}
	/*
	 * We can return to the caller if we have found some (this
	 * ensures forward progress). We'll be coming back to find
	 * the rest.
	 */
	if (!list_empty(&data->dispose))
		ret = need_resched() ? D_WALK_QUIT : D_WALK_NORETRY;
out:
	return ret;
}

/**
 * shrink_dcache_parent - prune dcache
 * @parent: parent of entries to prune
 *
 * Prune the dcache to remove unused children of the parent dentry.
 */
 
void shrink_dcache_parent(struct dentry * parent)
{
	struct super_block *sb = parent->d_sb;
	int found;

	while ((found = select_parent(parent)) != 0)
		__shrink_dcache_sb(sb, &found, 0);
}

/*
 * Scan `nr' dentries and return the number which remain.
 *
 * We need to avoid reentering the filesystem if the caller is performing a
 * GFP_NOFS allocation attempt.  One example deadlock is:
 *
 * ext2_new_block->getblk->GFP->shrink_dcache_memory->prune_dcache->
 * prune_one_dentry->dput->dentry_iput->iput->inode->i_sb->s_op->put_inode->
 * ext2_discard_prealloc->ext2_free_blocks->lock_super->DEADLOCK.
 *
 * In this case we return -1 to tell the caller that we baled.
 */
static int shrink_dcache_memory(int nr, gfp_t gfp_mask)
{
	if (nr) {
		if (!(gfp_mask & __GFP_FS))
			return -1;
		prune_dcache(nr);
	}
	return (dentry_stat.nr_unused / 100) * sysctl_vfs_cache_pressure;
}

static struct shrinker dcache_shrinker = {
	.shrink = shrink_dcache_memory,
	.seeks = DEFAULT_SEEKS,
};
void shrink_dcache_parent(struct dentry *parent)
{
	for (;;) {
		struct select_data data;

		INIT_LIST_HEAD(&data.dispose);
		data.start = parent;
		data.found = 0;

		d_walk(parent, &data, select_collect);

		if (!list_empty(&data.dispose)) {
			shrink_dentry_list(&data.dispose);
			continue;
		}

		cond_resched();
		if (!data.found)
			break;
	}
}
EXPORT_SYMBOL(shrink_dcache_parent);

static enum d_walk_ret umount_check(void *_data, struct dentry *dentry)
{
	/* it has busy descendents; complain about those instead */
	if (!list_empty(&dentry->d_subdirs))
		return D_WALK_CONTINUE;

	/* root with refcount 1 is fine */
	if (dentry == _data && dentry->d_lockref.count == 1)
		return D_WALK_CONTINUE;

	printk(KERN_ERR "BUG: Dentry %p{i=%lx,n=%pd} "
			" still in use (%d) [unmount of %s %s]\n",
		       dentry,
		       dentry->d_inode ?
		       dentry->d_inode->i_ino : 0UL,
		       dentry,
		       dentry->d_lockref.count,
		       dentry->d_sb->s_type->name,
		       dentry->d_sb->s_id);
	WARN_ON(1);
	return D_WALK_CONTINUE;
}

static void do_one_tree(struct dentry *dentry)
{
	shrink_dcache_parent(dentry);
	d_walk(dentry, dentry, umount_check);
	d_drop(dentry);
	dput(dentry);
}

/*
 * destroy the dentries attached to a superblock on unmounting
 */
void shrink_dcache_for_umount(struct super_block *sb)
{
	struct dentry *dentry;

	WARN(down_read_trylock(&sb->s_umount), "s_umount should've been locked");

	dentry = sb->s_root;
	sb->s_root = NULL;
	do_one_tree(dentry);

	while (!hlist_bl_empty(&sb->s_roots)) {
		dentry = dget(hlist_bl_entry(hlist_bl_first(&sb->s_roots), struct dentry, d_hash));
		do_one_tree(dentry);
	}
}

static enum d_walk_ret find_submount(void *_data, struct dentry *dentry)
{
	struct dentry **victim = _data;
	if (d_mountpoint(dentry)) {
		__dget_dlock(dentry);
		*victim = dentry;
		return D_WALK_QUIT;
	}
	return D_WALK_CONTINUE;
}

/**
 * d_invalidate - detach submounts, prune dcache, and drop
 * @dentry: dentry to invalidate (aka detach, prune and drop)
 */
void d_invalidate(struct dentry *dentry)
{
	bool had_submounts = false;
	spin_lock(&dentry->d_lock);
	if (d_unhashed(dentry)) {
		spin_unlock(&dentry->d_lock);
		return;
	}
	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);

	/* Negative dentries can be dropped without further checks */
	if (!dentry->d_inode)
		return;

	shrink_dcache_parent(dentry);
	for (;;) {
		struct dentry *victim = NULL;
		d_walk(dentry, &victim, find_submount);
		if (!victim) {
			if (had_submounts)
				shrink_dcache_parent(dentry);
			return;
		}
		had_submounts = true;
		detach_mounts(victim);
		dput(victim);
	}
}
EXPORT_SYMBOL(d_invalidate);

/**
 * __d_alloc	-	allocate a dcache entry
 * @sb: filesystem it will belong to
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
 
struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
{
	struct external_name *ext = NULL;
	struct dentry *dentry;
	char *dname;
	int err;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	if (!dentry)
		return NULL;

	/*
	 * We guarantee that the inline name is always NUL-terminated.
	 * This way the memcpy() done by the name switching in rename
	 * will still always have a NUL at the end, even if we might
	 * be overwriting an internal NUL character
	 */
	dentry->d_iname[DNAME_INLINE_LEN-1] = 0;
	if (unlikely(!name)) {
		name = &slash_name;
		dname = dentry->d_iname;
	} else if (name->len > DNAME_INLINE_LEN-1) {
		size_t size = offsetof(struct external_name, name[1]);

		ext = kmalloc(size + name->len, GFP_KERNEL_ACCOUNT);
		if (!ext) {
			kmem_cache_free(dentry_cache, dentry); 
			return NULL;
		}
		atomic_set(&ext->u.count, 1);
		dname = ext->name;
	} else  {
		dname = dentry->d_iname;
	}	

	dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	/* Make sure we always see the terminating NUL character */
	smp_store_release(&dentry->d_name.name, dname); /* ^^^ */

	dentry->d_lockref.count = 1;
	dentry->d_flags = 0;
	spin_lock_init(&dentry->d_lock);
	seqcount_init(&dentry->d_seq);
	dentry->d_inode = NULL;
	dentry->d_parent = dentry;
	dentry->d_sb = sb;
	dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	INIT_HLIST_BL_NODE(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_LIST_HEAD(&dentry->d_subdirs);
	INIT_HLIST_NODE(&dentry->d_u.d_alias);
	INIT_LIST_HEAD(&dentry->d_child);
	d_set_d_op(dentry, dentry->d_sb->s_d_op);

	if (dentry->d_op && dentry->d_op->d_init) {
		err = dentry->d_op->d_init(dentry);
		if (err) {
			if (dname_external(dentry))
				kfree(external_name(dentry));
			kmem_cache_free(dentry_cache, dentry);
			return NULL;
		}
	}

	if (unlikely(ext)) {
		pg_data_t *pgdat = page_pgdat(virt_to_page(ext));
		mod_node_page_state(pgdat, NR_INDIRECTLY_RECLAIMABLE_BYTES,
				    ksize(ext));
	}

	this_cpu_inc(nr_dentry);

	return dentry;
}

/**
 * d_alloc	-	allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
 
struct dentry *d_alloc(struct dentry * parent, const struct qstr *name)
{
	struct dentry *dentry;
	char *dname;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	if (!dentry)
		return NULL;

	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname) {
			kmem_cache_free(dentry_cache, dentry); 
			return NULL;
		}
	} else  {
		dname = dentry->d_iname;
	}	
	dentry->d_name.name = dname;

	dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	atomic_set(&dentry->d_count, 1);
	dentry->d_flags = DCACHE_UNHASHED;
	spin_lock_init(&dentry->d_lock);
	dentry->d_inode = NULL;
	dentry->d_parent = NULL;
	dentry->d_sb = NULL;
	dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	dentry->d_mounted = 0;
#ifdef CONFIG_PROFILING
	dentry->d_cookie = NULL;
#endif
	INIT_HLIST_NODE(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_LIST_HEAD(&dentry->d_subdirs);
	INIT_LIST_HEAD(&dentry->d_alias);

	if (parent) {
		dentry->d_parent = dget(parent);
		dentry->d_sb = parent->d_sb;
	} else {
		INIT_LIST_HEAD(&dentry->d_u.d_child);
	}

	spin_lock(&dcache_lock);
	if (parent)
		list_add(&dentry->d_u.d_child, &parent->d_subdirs);
	dentry_stat.nr_dentry++;
	spin_unlock(&dcache_lock);

	return dentry;
}
struct dentry *d_alloc(struct dentry * parent, const struct qstr *name)
{
	struct dentry *dentry = __d_alloc(parent->d_sb, name);
	if (!dentry)
		return NULL;
	dentry->d_flags |= DCACHE_RCUACCESS;
	spin_lock(&parent->d_lock);
	/*
	 * don't need child lock because it is not subject
	 * to concurrency here
	 */
	__dget_dlock(parent);
	dentry->d_parent = parent;
	list_add(&dentry->d_child, &parent->d_subdirs);
	spin_unlock(&parent->d_lock);

	return dentry;
}
EXPORT_SYMBOL(d_alloc);

struct dentry *d_alloc_anon(struct super_block *sb)
{
	return __d_alloc(sb, NULL);
}
EXPORT_SYMBOL(d_alloc_anon);

struct dentry *d_alloc_cursor(struct dentry * parent)
{
	struct dentry *dentry = d_alloc_anon(parent->d_sb);
	if (dentry) {
		dentry->d_flags |= DCACHE_RCUACCESS | DCACHE_DENTRY_CURSOR;
		dentry->d_parent = dget(parent);
	}
	return dentry;
}

/**
 * d_alloc_pseudo - allocate a dentry (for lookup-less filesystems)
 * @sb: the superblock
 * @name: qstr of the name
 *
 * For a filesystem that just pins its dentries in memory and never
 * performs lookups at all, return an unhashed IS_ROOT dentry.
 */
struct dentry *d_alloc_pseudo(struct super_block *sb, const struct qstr *name)
{
	return __d_alloc(sb, name);
}
EXPORT_SYMBOL(d_alloc_pseudo);

struct dentry *d_alloc_name(struct dentry *parent, const char *name)
{
	struct qstr q;

	q.name = name;
	q.hash_len = hashlen_string(parent, name);
	return d_alloc(parent, &q);
}
EXPORT_SYMBOL(d_alloc_name);

void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op)
{
	WARN_ON_ONCE(dentry->d_op);
	WARN_ON_ONCE(dentry->d_flags & (DCACHE_OP_HASH	|
				DCACHE_OP_COMPARE	|
				DCACHE_OP_REVALIDATE	|
				DCACHE_OP_WEAK_REVALIDATE	|
				DCACHE_OP_DELETE	|
				DCACHE_OP_REAL));
	dentry->d_op = op;
	if (!op)
		return;
	if (op->d_hash)
		dentry->d_flags |= DCACHE_OP_HASH;
	if (op->d_compare)
		dentry->d_flags |= DCACHE_OP_COMPARE;
	if (op->d_revalidate)
		dentry->d_flags |= DCACHE_OP_REVALIDATE;
	if (op->d_weak_revalidate)
		dentry->d_flags |= DCACHE_OP_WEAK_REVALIDATE;
	if (op->d_delete)
		dentry->d_flags |= DCACHE_OP_DELETE;
	if (op->d_prune)
		dentry->d_flags |= DCACHE_OP_PRUNE;
	if (op->d_real)
		dentry->d_flags |= DCACHE_OP_REAL;

}
EXPORT_SYMBOL(d_set_d_op);


/*
 * d_set_fallthru - Mark a dentry as falling through to a lower layer
 * @dentry - The dentry to mark
 *
 * Mark a dentry as falling through to the lower layer (as set with
 * d_pin_lower()).  This flag may be recorded on the medium.
 */
void d_set_fallthru(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_flags |= DCACHE_FALLTHRU;
	spin_unlock(&dentry->d_lock);
}
EXPORT_SYMBOL(d_set_fallthru);

static unsigned d_flags_for_inode(struct inode *inode)
{
	unsigned add_flags = DCACHE_REGULAR_TYPE;

	if (!inode)
		return DCACHE_MISS_TYPE;

	if (S_ISDIR(inode->i_mode)) {
		add_flags = DCACHE_DIRECTORY_TYPE;
		if (unlikely(!(inode->i_opflags & IOP_LOOKUP))) {
			if (unlikely(!inode->i_op->lookup))
				add_flags = DCACHE_AUTODIR_TYPE;
			else
				inode->i_opflags |= IOP_LOOKUP;
		}
		goto type_determined;
	}

	if (unlikely(!(inode->i_opflags & IOP_NOFOLLOW))) {
		if (unlikely(inode->i_op->get_link)) {
			add_flags = DCACHE_SYMLINK_TYPE;
			goto type_determined;
		}
		inode->i_opflags |= IOP_NOFOLLOW;
	}

	if (unlikely(!S_ISREG(inode->i_mode)))
		add_flags = DCACHE_SPECIAL_TYPE;

type_determined:
	if (unlikely(IS_AUTOMOUNT(inode)))
		add_flags |= DCACHE_NEED_AUTOMOUNT;
	return add_flags;
}

static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
	unsigned add_flags = d_flags_for_inode(inode);
	WARN_ON(d_in_lookup(dentry));

	spin_lock(&dentry->d_lock);
	hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
	raw_write_seqcount_begin(&dentry->d_seq);
	__d_set_inode_and_type(dentry, inode, add_flags);
	raw_write_seqcount_end(&dentry->d_seq);
	fsnotify_update_flags(dentry);
	spin_unlock(&dentry->d_lock);
}

/**
 * d_instantiate - fill in inode information for a dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.
 *
 * This turns negative dentries into productive full members
 * of society.
 *
 * NOTE! This assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
 
void d_instantiate(struct dentry *entry, struct inode * inode)
{
	BUG_ON(!list_empty(&entry->d_alias));
	spin_lock(&dcache_lock);
	if (inode)
		list_add(&entry->d_alias, &inode->i_dentry);
	entry->d_inode = inode;
	fsnotify_d_instantiate(entry, inode);
	spin_unlock(&dcache_lock);
	security_d_instantiate(entry, inode);
}
	BUG_ON(!hlist_unhashed(&entry->d_u.d_alias));
	if (inode) {
		security_d_instantiate(entry, inode);
		spin_lock(&inode->i_lock);
		__d_instantiate(entry, inode);
		spin_unlock(&inode->i_lock);
	}
}
EXPORT_SYMBOL(d_instantiate);

/**
 * d_instantiate_unique - instantiate a non-aliased dentry
 * @entry: dentry to instantiate
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry. On success, it returns NULL.
 * If an unhashed alias of "entry" already exists, then we return the
 * aliased dentry instead and drop one reference to inode.
 *
 * Note that in order to avoid conflicts with rename() etc, the caller
 * had better be holding the parent directory semaphore.
 *
 * This also assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
static struct dentry *__d_instantiate_unique(struct dentry *entry,
					     struct inode *inode)
{
	struct dentry *alias;
	int len = entry->d_name.len;
	const char *name = entry->d_name.name;
	unsigned int hash = entry->d_name.hash;

	if (!inode) {
		entry->d_inode = NULL;
		return NULL;
	}

	list_for_each_entry(alias, &inode->i_dentry, d_alias) {
		struct qstr *qstr = &alias->d_name;

		if (qstr->hash != hash)
			continue;
		if (alias->d_parent != entry->d_parent)
			continue;
		if (qstr->len != len)
			continue;
		if (memcmp(qstr->name, name, len))
			continue;
		dget_locked(alias);
		return alias;
	}

	list_add(&entry->d_alias, &inode->i_dentry);
	entry->d_inode = inode;
	fsnotify_d_instantiate(entry, inode);
		__d_instantiate(entry, NULL);
		return NULL;
	}

	hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) {
		/*
		 * Don't need alias->d_lock here, because aliases with
		 * d_parent == entry->d_parent are not subject to name or
		 * parent changes, because the parent inode i_mutex is held.
		 */
		if (alias->d_name.hash != hash)
			continue;
		if (alias->d_parent != entry->d_parent)
			continue;
		if (alias->d_name.len != len)
			continue;
		if (dentry_cmp(alias, name, len))
			continue;
		__dget(alias);
		return alias;
	}

	__d_instantiate(entry, inode);
	return NULL;
}

struct dentry *d_instantiate_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *result;

	BUG_ON(!list_empty(&entry->d_alias));

	spin_lock(&dcache_lock);
	result = __d_instantiate_unique(entry, inode);
	spin_unlock(&dcache_lock);
	BUG_ON(!hlist_unhashed(&entry->d_u.d_alias));

	if (inode)
		spin_lock(&inode->i_lock);
	result = __d_instantiate_unique(entry, inode);
	if (inode)
		spin_unlock(&inode->i_lock);

	if (!result) {
		security_d_instantiate(entry, inode);
		return NULL;
	}

	BUG_ON(!d_unhashed(result));
	iput(inode);
	return result;
}

EXPORT_SYMBOL(d_instantiate_unique);

/**
 * d_alloc_root - allocate root dentry
 * @root_inode: inode to allocate the root for
 *
 * Allocate a root ("/") dentry for the inode given. The inode is
 * instantiated and returned. %NULL is returned if there is insufficient
 * memory or the inode passed is %NULL.
 */
 
struct dentry * d_alloc_root(struct inode * root_inode)
 * d_instantiate_no_diralias - instantiate a non-aliased dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.  If a directory alias is found, then
 * return an error (and drop inode).  Together with d_materialise_unique() this
 * guarantees that a directory inode may never have more than one alias.
/*
 * This should be equivalent to d_instantiate() + unlock_new_inode(),
 * with lockdep-related part of unlock_new_inode() done before
 * anything else.  Use that instead of open-coding d_instantiate()/
 * unlock_new_inode() combinations.
 */
void d_instantiate_new(struct dentry *entry, struct inode *inode)
{
	BUG_ON(!hlist_unhashed(&entry->d_u.d_alias));
	BUG_ON(!inode);
	lockdep_annotate_inode_mutex_key(inode);
	security_d_instantiate(entry, inode);
	spin_lock(&inode->i_lock);
	__d_instantiate(entry, inode);
	WARN_ON(!(inode->i_state & I_NEW));
	inode->i_state &= ~I_NEW & ~I_CREATING;
	smp_mb();
	wake_up_bit(&inode->i_state, __I_NEW);
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL(d_instantiate_new);

struct dentry *d_make_root(struct inode *root_inode)
{
	struct dentry *res = NULL;

	if (root_inode) {
		static const struct qstr name = { .name = "/", .len = 1 };

		res = d_alloc(NULL, &name);
		if (res) {
			res->d_sb = root_inode->i_sb;
			res->d_parent = res;
			d_instantiate(res, root_inode);
		}
	}
	return res;
}

static inline struct hlist_head *d_hash(struct dentry *parent,
					unsigned long hash)
{
	hash += ((unsigned long) parent ^ GOLDEN_RATIO_PRIME) / L1_CACHE_BYTES;
	hash = hash ^ ((hash ^ GOLDEN_RATIO_PRIME) >> D_HASHBITS);
	return dentry_hashtable + (hash & D_HASHMASK);
}

/**
 * d_alloc_anon - allocate an anonymous dentry
 * @inode: inode to allocate the dentry for
 *
 * This is similar to d_alloc_root.  It is used by filesystems when
 * creating a dentry for a given inode, often in the process of 
 * mapping a filehandle to a dentry.  The returned dentry may be
 * anonymous, or may have a full name (if the inode was already
 * in the cache).  The file system may need to make further
 * efforts to connect this dentry into the dcache properly.
 *
 * When called on a directory inode, we must ensure that
 * the inode only ever has one dentry.  If a dentry is
 * found, that is returned instead of allocating a new one.
 *
 * On successful return, the reference to the inode has been transferred
 * to the dentry.  If %NULL is returned (indicating kmalloc failure),
 * the reference on the inode has not been released.
 */

struct dentry * d_alloc_anon(struct inode *inode)
{
	static const struct qstr anonstring = { .name = "" };
	struct dentry *tmp;
	struct dentry *res;

	if ((res = d_find_alias(inode))) {
		iput(inode);
		return res;
	}

	tmp = d_alloc(NULL, &anonstring);
	if (!tmp)
		return NULL;

	tmp->d_parent = tmp; /* make sure dput doesn't croak */
	
	spin_lock(&dcache_lock);
	res = __d_find_alias(inode, 0);
	if (!res) {
		/* attach a disconnected dentry */
		res = tmp;
		tmp = NULL;
		spin_lock(&res->d_lock);
		res->d_sb = inode->i_sb;
		res->d_parent = res;
		res->d_inode = inode;
		res->d_flags |= DCACHE_DISCONNECTED;
		res->d_flags &= ~DCACHE_UNHASHED;
		list_add(&res->d_alias, &inode->i_dentry);
		hlist_add_head(&res->d_hash, &inode->i_sb->s_anon);
		spin_unlock(&res->d_lock);

		inode = NULL; /* don't drop reference */
	}
	spin_unlock(&dcache_lock);

	if (inode)
		iput(inode);
	if (tmp)
		dput(tmp);
	return res;
}


/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has a 'disconnected' dentry (i.e. IS_ROOT and
 * DCACHE_DISCONNECTED), then d_move that in place of the given dentry
 * and return it, else simply d_add the inode to the dentry and return NULL.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 */
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	struct dentry *new = NULL;

	if (inode && S_ISDIR(inode->i_mode)) {
		spin_lock(&dcache_lock);
		new = __d_find_alias(inode, 1);
		if (new) {
			BUG_ON(!(new->d_flags & DCACHE_DISCONNECTED));
			fsnotify_d_instantiate(new, inode);
			spin_unlock(&dcache_lock);
			security_d_instantiate(new, inode);
			d_rehash(dentry);
			d_move(new, dentry);
			iput(inode);
		} else {
			/* d_instantiate takes dcache_lock, so we do it by hand */
			list_add(&dentry->d_alias, &inode->i_dentry);
			dentry->d_inode = inode;
			fsnotify_d_instantiate(dentry, inode);
			spin_unlock(&dcache_lock);
			security_d_instantiate(dentry, inode);
			d_rehash(dentry);
		}
	} else
		d_add(dentry, inode);
	return new;
}
		static const struct qstr name = QSTR_INIT("/", 1);

		res = __d_alloc(root_inode->i_sb, &name);
		res = __d_alloc(root_inode->i_sb, NULL);
		if (res)
		res = d_alloc_anon(root_inode->i_sb);
		if (res) {
			res->d_flags |= DCACHE_RCUACCESS;
			d_instantiate(res, root_inode);
		} else {
			iput(root_inode);
		}
	}
	return res;
}
EXPORT_SYMBOL(d_make_root);

static struct dentry *__d_instantiate_anon(struct dentry *dentry,
					   struct inode *inode,
					   bool disconnected)
{
	struct dentry *res;
	unsigned add_flags;

	security_d_instantiate(dentry, inode);
	spin_lock(&inode->i_lock);
	res = __d_find_any_alias(inode);
	if (res) {
		spin_unlock(&inode->i_lock);
		dput(dentry);
		goto out_iput;
	}

	/* attach a disconnected dentry */
	add_flags = d_flags_for_inode(inode);

	if (disconnected)
		add_flags |= DCACHE_DISCONNECTED;

	spin_lock(&dentry->d_lock);
	__d_set_inode_and_type(dentry, inode, add_flags);
	hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
	if (!disconnected) {
		hlist_bl_lock(&dentry->d_sb->s_roots);
		hlist_bl_add_head(&dentry->d_hash, &dentry->d_sb->s_roots);
		hlist_bl_unlock(&dentry->d_sb->s_roots);
	}
	spin_unlock(&dentry->d_lock);
	spin_unlock(&inode->i_lock);

	return dentry;

 out_iput:
	iput(inode);
	return res;
}

struct dentry *d_instantiate_anon(struct dentry *dentry, struct inode *inode)
{
	return __d_instantiate_anon(dentry, inode, true);
}
EXPORT_SYMBOL(d_instantiate_anon);

static struct dentry *__d_obtain_alias(struct inode *inode, bool disconnected)
{
	struct dentry *tmp;
	struct dentry *res;

	if (!inode)
		return ERR_PTR(-ESTALE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	res = d_find_any_alias(inode);
	if (res)
		goto out_iput;

	tmp = d_alloc_anon(inode->i_sb);
	if (!tmp) {
		res = ERR_PTR(-ENOMEM);
		goto out_iput;
	}

	return __d_instantiate_anon(tmp, inode, disconnected);

out_iput:
	iput(inode);
	return res;
}

/**
 * d_obtain_alias - find or allocate a DISCONNECTED dentry for a given inode
 * @inode: inode to allocate the dentry for
 *
 * Obtain a dentry for an inode resulting from NFS filehandle conversion or
 * similar open by handle operations.  The returned dentry may be anonymous,
 * or may have a full name (if the inode was already in the cache).
 *
 * When called on a directory inode, we must ensure that the inode only ever
 * has one dentry.  If a dentry is found, that is returned instead of
 * allocating a new one.
 *
 * On successful return, the reference to the inode has been transferred
 * to the dentry.  In case of an error the reference on the inode is released.
 * To make it easier to use in export operations a %NULL or IS_ERR inode may
 * be passed in and the error will be propagated to the return value,
 * with a %NULL @inode replaced by ERR_PTR(-ESTALE).
 */
struct dentry *d_obtain_alias(struct inode *inode)
{
	return __d_obtain_alias(inode, true);
}
EXPORT_SYMBOL(d_obtain_alias);

/**
 * d_obtain_root - find or allocate a dentry for a given inode
 * @inode: inode to allocate the dentry for
 *
 * Obtain an IS_ROOT dentry for the root of a filesystem.
 *
 * We must ensure that directory inodes only ever have one dentry.  If a
 * dentry is found, that is returned instead of allocating a new one.
 *
 * On successful return, the reference to the inode has been transferred
 * to the dentry.  In case of an error the reference on the inode is
 * released.  A %NULL or IS_ERR inode may be passed in and will be the
 * error will be propagate to the return value, with a %NULL @inode
 * replaced by ERR_PTR(-ESTALE).
 */
struct dentry *d_obtain_root(struct inode *inode)
{
	return __d_obtain_alias(inode, false);
}
EXPORT_SYMBOL(d_obtain_root);

/**
 * d_add_ci - lookup or allocate new dentry with case-exact name
 * @inode:  the inode case-insensitive lookup has found
 * @dentry: the negative dentry that was passed to the parent's lookup func
 * @name:   the case-exact name to be associated with the returned dentry
 *
 * This is to avoid filling the dcache with case-insensitive names to the
 * same inode, only the actual correct case is stored in the dcache for
 * case-insensitive filesystems.
 *
 * For a case-insensitive lookup match and if the the case-exact dentry
 * already exists in in the dcache, use it and return it.
 *
 * If no entry exists with the exact case name, allocate new dentry with
 * the exact case, and return the spliced entry.
 */
struct dentry *d_add_ci(struct dentry *dentry, struct inode *inode,
			struct qstr *name)
{
	int error;
	struct dentry *found;
	struct dentry *new;

	/* Does a dentry matching the name exist already? */
	found = d_hash_and_lookup(dentry->d_parent, name);
	/* If not, create it now and return */
	if (!found) {
		new = d_alloc(dentry->d_parent, name);
		if (!new) {
			error = -ENOMEM;
			goto err_out;
		}
		found = d_splice_alias(inode, new);
		if (found) {
			dput(new);
			return found;
		}
		return new;
	}
	/* Matching dentry exists, check if it is negative. */
	if (found->d_inode) {
		if (unlikely(found->d_inode != inode)) {
			/* This can't happen because bad inodes are unhashed. */
			BUG_ON(!is_bad_inode(inode));
			BUG_ON(!is_bad_inode(found->d_inode));
		}
		/*
		 * Already have the inode and the dentry attached, decrement
		 * the reference count to balance the iget() done
		 * earlier on.  We found the dentry using d_lookup() so it
		 * cannot be disconnected and thus we do not need to worry
		 * about any NFS/disconnectedness issues here.
		 */
		iput(inode);
		return found;
	}
	/*
	 * Negative dentry: instantiate it unless the inode is a directory and
	 * has a 'disconnected' dentry (i.e. IS_ROOT and DCACHE_DISCONNECTED),
	 * in which case d_move() that in place of the found dentry.
	 */
	if (!S_ISDIR(inode->i_mode)) {
		/* Not a directory; everything is easy. */
		d_instantiate(found, inode);
		return found;
	}
	spin_lock(&dcache_lock);
	if (list_empty(&inode->i_dentry)) {
		/*
		 * Directory without a 'disconnected' dentry; we need to do
		 * d_instantiate() by hand because it takes dcache_lock which
		 * we already hold.
		 */
		list_add(&found->d_alias, &inode->i_dentry);
		found->d_inode = inode;
		spin_unlock(&dcache_lock);
		security_d_instantiate(found, inode);
		return found;
	}
	/*
	 * Directory with a 'disconnected' dentry; get a reference to the
	 * 'disconnected' dentry.
	 */
	new = list_entry(inode->i_dentry.next, struct dentry, d_alias);
	dget_locked(new);
	spin_unlock(&dcache_lock);
	/* Do security vodoo. */
	security_d_instantiate(found, inode);
	/* Move new in place of found. */
	d_move(new, found);
	/* Balance the iget() we did above. */
	iput(inode);
	/* Throw away found. */
	dput(found);
	/* Use new as the actual dentry. */
	return new;

err_out:
	iput(inode);
	return ERR_PTR(error);
	struct dentry *found;
	struct dentry *new;
	struct dentry *found, *res;

	/*
	 * First check if a dentry matching the name already exists,
	 * if not go ahead and create it now.
	 */
	found = d_hash_and_lookup(dentry->d_parent, name);
	if (found) {
		iput(inode);
		return found;
	}
	if (d_in_lookup(dentry)) {
		found = d_alloc_parallel(dentry->d_parent, name,
					dentry->d_wait);
		if (IS_ERR(found) || !d_in_lookup(found)) {
			iput(inode);
			return found;
		}
	} else {
		found = d_alloc(dentry->d_parent, name);
		if (!found) {
			iput(inode);
			return ERR_PTR(-ENOMEM);
		} 
	}
	res = d_splice_alias(inode, found);
	if (res) {
		dput(found);
		return res;
	}
	return found;
}
EXPORT_SYMBOL(d_add_ci);


static inline bool d_same_name(const struct dentry *dentry,
				const struct dentry *parent,
				const struct qstr *name)
{
	if (likely(!(parent->d_flags & DCACHE_OP_COMPARE))) {
		if (dentry->d_name.len != name->len)
			return false;
		return dentry_cmp(dentry, name->name, name->len) == 0;
	}
	return parent->d_op->d_compare(dentry,
				       dentry->d_name.len, dentry->d_name.name,
				       name) == 0;
}

/**
 * __d_lookup_rcu - search for a dentry (racy, store-free)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * @seqp: returns d_seq value at the point where the dentry was found
 * Returns: dentry, or NULL
 *
 * __d_lookup_rcu is the dcache lookup function for rcu-walk name
 * resolution (store-free path walking) design described in
 * Documentation/filesystems/path-lookup.txt.
 *
 * This is not to be used outside core vfs.
 *
 * __d_lookup_rcu must only be used in rcu-walk mode, ie. with vfsmount lock
 * held, and rcu_read_lock held. The returned dentry must not be stored into
 * without taking d_lock and checking d_seq sequence count against @seq
 * returned here.
 *
 * A refcount may be taken on the found dentry with the d_rcu_to_refcount
 * function.
 *
 * Alternatively, __d_lookup_rcu may be called again to look up the child of
 * the returned dentry, so long as its parent's seqlock is checked after the
 * child is looked up. Thus, an interlocking stepping of sequence lock checks
 * is formed, giving integrity down the path walk.
 *
 * NOTE! The caller *has* to check the resulting dentry against the sequence
 * number we've returned before using any of the resulting dentry state!
 */
struct dentry *__d_lookup_rcu(const struct dentry *parent,
				const struct qstr *name,
				unsigned *seqp)
{
	u64 hashlen = name->hash_len;
	const unsigned char *str = name->name;
	struct hlist_bl_head *b = d_hash(hashlen_hash(hashlen));
	struct hlist_bl_node *node;
	struct dentry *dentry;

	/*
	 * Note: There is significant duplication with __d_lookup_rcu which is
	 * required to prevent single threaded performance regressions
	 * especially on architectures where smp_rmb (in seqcounts) are costly.
	 * Keep the two functions in sync.
	 */

	/*
	 * The hash list is protected using RCU.
	 *
	 * Carefully use d_seq when comparing a candidate dentry, to avoid
	 * races with d_move().
	 *
	 * It is possible that concurrent renames can mess up our list
	 * walk here and result in missing our dentry, resulting in the
	 * false-negative result. d_lookup() protects against concurrent
	 * renames using rename_lock seqlock.
	 *
	 * See Documentation/filesystems/path-lookup.txt for more details.
	 */
	hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
		unsigned seq;

seqretry:
		/*
		 * The dentry sequence count protects us from concurrent
		 * renames, and thus protects parent and name fields.
		 *
		 * The caller must perform a seqcount check in order
		 * to do anything useful with the returned dentry.
		 *
		 * NOTE! We do a "raw" seqcount_begin here. That means that
		 * we don't wait for the sequence count to stabilize if it
		 * is in the middle of a sequence change. If we do the slow
		 * dentry compare, we will do seqretries until it is stable,
		 * and if we end up with a successful lookup, we actually
		 * want to exit RCU lookup anyway.
		 *
		 * Note that raw_seqcount_begin still *does* smp_rmb(), so
		 * we are still guaranteed NUL-termination of ->d_name.name.
		 */
		seq = raw_seqcount_begin(&dentry->d_seq);
		if (dentry->d_parent != parent)
			continue;
		if (d_unhashed(dentry))
			continue;

		if (unlikely(parent->d_flags & DCACHE_OP_COMPARE)) {
			int tlen;
			const char *tname;
			if (dentry->d_name.hash != hashlen_hash(hashlen))
				continue;
			tlen = dentry->d_name.len;
			tname = dentry->d_name.name;
			/* we want a consistent (name,len) pair */
			if (read_seqcount_retry(&dentry->d_seq, seq)) {
				cpu_relax();
				goto seqretry;
			}
			if (parent->d_op->d_compare(dentry,
						    tlen, tname, name) != 0)
				continue;
		} else {
			if (dentry->d_name.hash_len != hashlen)
				continue;
			if (dentry_cmp(dentry, str, hashlen_len(hashlen)) != 0)
				continue;
		}
		*seqp = seq;
		return dentry;
	}
	return NULL;
}

/**
 * d_lookup - search for a dentry
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 *
 * Searches the children of the parent dentry for the name in question. If
 * the dentry is found its reference count is incremented and the dentry
 * is returned. The caller must use d_put to free the entry when it has
 * finished using it. %NULL is returned on failure.
 *
 * __d_lookup is dcache_lock free. The hash list is protected using RCU.
 * Memory barriers are used while updating and doing lockless traversal. 
 * To avoid races with d_move while rename is happening, d_lock is used.
 *
 * Overflows in memcmp(), while d_move, are avoided by keeping the length
 * and name pointer in one structure pointed by d_qstr.
 *
 * rcu_read_lock() and rcu_read_unlock() are used to disable preemption while
 * lookup is going on.
 *
 * The dentry unused LRU is not updated even if lookup finds the required dentry
 * in there. It is updated in places such as prune_dcache, shrink_dcache_sb,
 * select_parent and __dget_locked. This laziness saves lookup from dcache_lock
 * acquisition.
 *
 * d_lookup() is protected against the concurrent renames in some unrelated
 * directory using the seqlockt_t rename_lock.
 */

struct dentry * d_lookup(struct dentry * parent, struct qstr * name)
{
	struct dentry * dentry = NULL;
	unsigned long seq;

        do {
                seq = read_seqbegin(&rename_lock);
                dentry = __d_lookup(parent, name);
                if (dentry)
 * Returns: dentry, or NULL
 *
 * d_lookup searches the children of the parent dentry for the name in
 * question. If the dentry is found its reference count is incremented and the
 * dentry is returned. The caller must use dput to free the entry when it has
 * finished using it. %NULL is returned if the dentry does not exist.
 */
struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
{
	struct dentry *dentry;
	unsigned seq;

	do {
		seq = read_seqbegin(&rename_lock);
		dentry = __d_lookup(parent, name);
		if (dentry)
			break;
	} while (read_seqretry(&rename_lock, seq));
	return dentry;
}

struct dentry * __d_lookup(struct dentry * parent, struct qstr * name)
EXPORT_SYMBOL(d_lookup);

/**
 * __d_lookup - search for a dentry (racy)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * __d_lookup is like d_lookup, however it may (rarely) return a
 * false-negative result due to unrelated rename activity.
 *
 * __d_lookup is slightly faster by avoiding rename_lock read seqlock,
 * however it must be used carefully, eg. with a following d_lookup in
 * the case of failure.
 *
 * __d_lookup callers must be commented.
 */
struct dentry *__d_lookup(const struct dentry *parent, const struct qstr *name)
{
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct hlist_head *head = d_hash(parent,hash);
	struct dentry *found = NULL;
	struct hlist_node *node;
	struct dentry *dentry;

	rcu_read_lock();
	
	hlist_for_each_entry_rcu(dentry, node, head, d_hash) {
		struct qstr *qstr;

		if (dentry->d_name.hash != hash)
			continue;
		if (dentry->d_parent != parent)
			continue;

		spin_lock(&dentry->d_lock);

		/*
		 * Recheck the dentry after taking the lock - d_move may have
		 * changed things.  Don't bother checking the hash because we're
		 * about to compare the whole name anyway.
		 */
		if (dentry->d_parent != parent)
			goto next;

		/* non-existing due to RCU? */
	struct hlist_bl_head *b = d_hash(parent, hash);
	struct hlist_bl_head *b = d_hash(hash);
	struct hlist_bl_node *node;
	struct dentry *found = NULL;
	struct dentry *dentry;

	/*
	 * Note: There is significant duplication with __d_lookup_rcu which is
	 * required to prevent single threaded performance regressions
	 * especially on architectures where smp_rmb (in seqcounts) are costly.
	 * Keep the two functions in sync.
	 */

	/*
	 * The hash list is protected using RCU.
	 *
	 * Take d_lock when comparing a candidate dentry, to avoid races
	 * with d_move().
	 *
	 * It is possible that concurrent renames can mess up our list
	 * walk here and result in missing our dentry, resulting in the
	 * false-negative result. d_lookup() protects against concurrent
	 * renames using rename_lock seqlock.
	 *
	 * See Documentation/filesystems/path-lookup.txt for more details.
	 */
	rcu_read_lock();
	
	hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {

		if (dentry->d_name.hash != hash)
			continue;

		spin_lock(&dentry->d_lock);
		if (dentry->d_parent != parent)
			goto next;
		if (d_unhashed(dentry))
			goto next;

		/*
		 * It is safe to compare names since d_move() cannot
		 * change the qstr (protected by d_lock).
		 */
		qstr = &dentry->d_name;
		if (parent->d_op && parent->d_op->d_compare) {
			if (parent->d_op->d_compare(parent, qstr, name))
				goto next;
		} else {
			if (qstr->len != len)
				goto next;
			if (memcmp(qstr->name, str, len))
				goto next;
		}

		atomic_inc(&dentry->d_count);
		if (parent->d_flags & DCACHE_OP_COMPARE) {
			int tlen = dentry->d_name.len;
			const char *tname = dentry->d_name.name;
			if (parent->d_op->d_compare(parent, dentry, tlen, tname, name))
				goto next;
		} else {
			if (dentry->d_name.len != len)
				goto next;
			if (dentry_cmp(dentry, str, len))
				goto next;
		}
		if (!d_same_name(dentry, parent, name))
			goto next;

		dentry->d_lockref.count++;
		found = dentry;
		spin_unlock(&dentry->d_lock);
		break;
next:
		spin_unlock(&dentry->d_lock);
 	}
 	rcu_read_unlock();

 	return found;
}

/**
 * d_hash_and_lookup - hash the qstr then search for a dentry
 * @dir: Directory to search in
 * @name: qstr of name we wish to find
 *
 * On hash failure or on lookup failure NULL is returned.
 */
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	struct dentry *dentry = NULL;

 * On lookup failure NULL is returned; on bad name - ERR_PTR(-error)
 */
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	/*
	 * Check for a fs-specific hash function. Note that we must
	 * calculate the standard hash first, as the d_op->d_hash()
	 * routine may choose to leave the hash value unchanged.
	 */
	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_op && dir->d_op->d_hash) {
		if (dir->d_op->d_hash(dir, name) < 0)
			goto out;
	}
	dentry = d_lookup(dir, name);
out:
	return dentry;
}

/**
 * d_validate - verify dentry provided from insecure source
 * @dentry: The dentry alleged to be valid child of @dparent
 * @dparent: The parent dentry (known to be valid)
 * @hash: Hash of the dentry
 * @len: Length of the name
 *
 * An insecure source has sent us a dentry, here we verify it and dget() it.
 * This is used by ncpfs in its readdir implementation.
 * Zero is returned in the dentry is invalid.
 */
 
int d_validate(struct dentry *dentry, struct dentry *dparent)
{
	struct hlist_head *base;
	struct hlist_node *lhp;

	/* Check whether the ptr might be valid at all.. */
	if (!kmem_ptr_validate(dentry_cache, dentry))
		goto out;

	if (dentry->d_parent != dparent)
		goto out;

	spin_lock(&dcache_lock);
	base = d_hash(dparent, dentry->d_name.hash);
	hlist_for_each(lhp,base) { 
		/* hlist_for_each_entry_rcu() not required for d_hash list
		 * as it is parsed under dcache_lock
		 */
		if (dentry == hlist_entry(lhp, struct dentry, d_hash)) {
			__dget_locked(dentry);
			spin_unlock(&dcache_lock);
			return 1;
		}
	}
	spin_unlock(&dcache_lock);
out:
	return 0;
}
	name->hash = full_name_hash(dir, name->name, name->len);
	if (dir->d_flags & DCACHE_OP_HASH) {
		int err = dir->d_op->d_hash(dir, name);
		if (unlikely(err < 0))
			return ERR_PTR(err);
	}
	return d_lookup(dir, name);
}
EXPORT_SYMBOL(d_hash_and_lookup);

/*
 * When a file is deleted, we have two options:
 * - turn this dentry into a negative dentry
 * - unhash this dentry and free it.
 *
 * Usually, we want to just turn this into
 * a negative dentry, but if anybody else is
 * currently using the dentry or the inode
 * we can't do that and we fall back on removing
 * it from the hash queues and waiting for
 * it to be deleted later when it has no users
 */
 
/**
 * d_delete - delete a dentry
 * @dentry: The dentry to delete
 *
 * Turn the dentry into a negative dentry if possible, otherwise
 * remove it from the hash queues so it can be deleted later
 */
 
void d_delete(struct dentry * dentry)
{
	struct inode *inode = dentry->d_inode;
	int isdir = d_is_dir(dentry);

	spin_lock(&inode->i_lock);
	spin_lock(&dentry->d_lock);
	/*
	 * Are we the only user?
	 */
	spin_lock(&dcache_lock);
	spin_lock(&dentry->d_lock);
	isdir = S_ISDIR(dentry->d_inode->i_mode);
	if (atomic_read(&dentry->d_count) == 1) {
		dentry_iput(dentry);
again:
	spin_lock(&dentry->d_lock);
	inode = dentry->d_inode;
	isdir = S_ISDIR(inode->i_mode);
	if (dentry->d_lockref.count == 1) {
		dentry->d_flags &= ~DCACHE_CANT_MOUNT;
		dentry_unlink_inode(dentry);
	} else {
		__d_drop(dentry);

	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);

	fsnotify_nameremove(dentry, isdir);
}

static void __d_rehash(struct dentry * entry, struct hlist_head *list)
{

 	entry->d_flags &= ~DCACHE_UNHASHED;
 	hlist_add_head_rcu(&entry->d_hash, list);

		spin_unlock(&dentry->d_lock);
		spin_unlock(&inode->i_lock);
	}
	fsnotify_nameremove(dentry, isdir);
}
EXPORT_SYMBOL(d_delete);

static void __d_rehash(struct dentry *entry)
{
	struct hlist_bl_head *b = d_hash(entry->d_name.hash);

	hlist_bl_lock(b);
	hlist_bl_add_head_rcu(&entry->d_hash, b);
	hlist_bl_unlock(b);
}

/**
 * d_rehash	- add an entry back to the hash
 * @entry: dentry to add to the hash
 *
 * Adds a dentry to the hash according to its name.
 */
 
void d_rehash(struct dentry * entry)
{
	spin_lock(&dcache_lock);
	spin_lock(&entry->d_lock);
	_d_rehash(entry);
	spin_unlock(&entry->d_lock);
	spin_unlock(&dcache_lock);
}

#define do_switch(x,y) do { \
	__typeof__ (x) __tmp = x; \
	x = y; y = __tmp; } while (0)

/*
 * When switching names, the actual string doesn't strictly have to
 * be preserved in the target - because we're dropping the target
 * anyway. As such, we can just do a simple memcpy() to copy over
 * the new name before we switch.
 *
 * Note that we have to be a lot more careful about getting the hash
 * switched - we have to switch the hash value properly even if it
 * then no longer matches the actual (corrupted) string of the target.
 * The hash value has to match the hash queue that the dentry is on..
 */
static void switch_names(struct dentry *dentry, struct dentry *target)
{
	if (dname_external(target)) {
		if (dname_external(dentry)) {
			/*
			 * Both external: swap the pointers
			 */
			do_switch(target->d_name.name, dentry->d_name.name);
	spin_lock(&entry->d_lock);
	__d_rehash(entry);
	spin_unlock(&entry->d_lock);
}
EXPORT_SYMBOL(d_rehash);

static inline unsigned start_dir_add(struct inode *dir)
{

	for (;;) {
		unsigned n = dir->i_dir_seq;
		if (!(n & 1) && cmpxchg(&dir->i_dir_seq, n, n + 1) == n)
			return n;
		cpu_relax();
	}
}

static inline void end_dir_add(struct inode *dir, unsigned n)
{
	smp_store_release(&dir->i_dir_seq, n + 2);
}

static void d_wait_lookup(struct dentry *dentry)
{
	if (d_in_lookup(dentry)) {
		DECLARE_WAITQUEUE(wait, current);
		add_wait_queue(dentry->d_wait, &wait);
		do {
			set_current_state(TASK_UNINTERRUPTIBLE);
			spin_unlock(&dentry->d_lock);
			schedule();
			spin_lock(&dentry->d_lock);
		} while (d_in_lookup(dentry));
	}
}

struct dentry *d_alloc_parallel(struct dentry *parent,
				const struct qstr *name,
				wait_queue_head_t *wq)
{
	unsigned int hash = name->hash;
	struct hlist_bl_head *b = in_lookup_hash(parent, hash);
	struct hlist_bl_node *node;
	struct dentry *new = d_alloc(parent, name);
	struct dentry *dentry;
	unsigned seq, r_seq, d_seq;

	if (unlikely(!new))
		return ERR_PTR(-ENOMEM);

retry:
	rcu_read_lock();
	seq = smp_load_acquire(&parent->d_inode->i_dir_seq);
	r_seq = read_seqbegin(&rename_lock);
	dentry = __d_lookup_rcu(parent, name, &d_seq);
	if (unlikely(dentry)) {
		if (!lockref_get_not_dead(&dentry->d_lockref)) {
			rcu_read_unlock();
			goto retry;
		}
		if (read_seqcount_retry(&dentry->d_seq, d_seq)) {
			rcu_read_unlock();
			dput(dentry);
			goto retry;
		}
		rcu_read_unlock();
		dput(new);
		return dentry;
	}
	if (unlikely(read_seqretry(&rename_lock, r_seq))) {
		rcu_read_unlock();
		goto retry;
	}

	if (unlikely(seq & 1)) {
		rcu_read_unlock();
		goto retry;
	}

	hlist_bl_lock(b);
	if (unlikely(READ_ONCE(parent->d_inode->i_dir_seq) != seq)) {
		hlist_bl_unlock(b);
		rcu_read_unlock();
		goto retry;
	}
	/*
	 * No changes for the parent since the beginning of d_lookup().
	 * Since all removals from the chain happen with hlist_bl_lock(),
	 * any potential in-lookup matches are going to stay here until
	 * we unlock the chain.  All fields are stable in everything
	 * we encounter.
	 */
	hlist_bl_for_each_entry(dentry, node, b, d_u.d_in_lookup_hash) {
		if (dentry->d_name.hash != hash)
			continue;
		if (dentry->d_parent != parent)
			continue;
		if (!d_same_name(dentry, parent, name))
			continue;
		hlist_bl_unlock(b);
		/* now we can try to grab a reference */
		if (!lockref_get_not_dead(&dentry->d_lockref)) {
			rcu_read_unlock();
			goto retry;
		}

		rcu_read_unlock();
		/*
		 * somebody is likely to be still doing lookup for it;
		 * wait for them to finish
		 */
		spin_lock(&dentry->d_lock);
		d_wait_lookup(dentry);
		/*
		 * it's not in-lookup anymore; in principle we should repeat
		 * everything from dcache lookup, but it's likely to be what
		 * d_lookup() would've found anyway.  If it is, just return it;
		 * otherwise we really have to repeat the whole thing.
		 */
		if (unlikely(dentry->d_name.hash != hash))
			goto mismatch;
		if (unlikely(dentry->d_parent != parent))
			goto mismatch;
		if (unlikely(d_unhashed(dentry)))
			goto mismatch;
		if (unlikely(!d_same_name(dentry, parent, name)))
			goto mismatch;
		/* OK, it *is* a hashed match; return it */
		spin_unlock(&dentry->d_lock);
		dput(new);
		return dentry;
	}
	rcu_read_unlock();
	/* we can't take ->d_lock here; it's OK, though. */
	new->d_flags |= DCACHE_PAR_LOOKUP;
	new->d_wait = wq;
	hlist_bl_add_head_rcu(&new->d_u.d_in_lookup_hash, b);
	hlist_bl_unlock(b);
	return new;
mismatch:
	spin_unlock(&dentry->d_lock);
	dput(dentry);
	goto retry;
}
EXPORT_SYMBOL(d_alloc_parallel);

void __d_lookup_done(struct dentry *dentry)
{
	struct hlist_bl_head *b = in_lookup_hash(dentry->d_parent,
						 dentry->d_name.hash);
	hlist_bl_lock(b);
	dentry->d_flags &= ~DCACHE_PAR_LOOKUP;
	__hlist_bl_del(&dentry->d_u.d_in_lookup_hash);
	wake_up_all(dentry->d_wait);
	dentry->d_wait = NULL;
	hlist_bl_unlock(b);
	INIT_HLIST_NODE(&dentry->d_u.d_alias);
	INIT_LIST_HEAD(&dentry->d_lru);
}
EXPORT_SYMBOL(__d_lookup_done);

/* inode->i_lock held if inode is non-NULL */

static inline void __d_add(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = NULL;
	unsigned n;
	spin_lock(&dentry->d_lock);
	if (unlikely(d_in_lookup(dentry))) {
		dir = dentry->d_parent->d_inode;
		n = start_dir_add(dir);
		__d_lookup_done(dentry);
	}
	if (inode) {
		unsigned add_flags = d_flags_for_inode(inode);
		hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
		raw_write_seqcount_begin(&dentry->d_seq);
		__d_set_inode_and_type(dentry, inode, add_flags);
		raw_write_seqcount_end(&dentry->d_seq);
		fsnotify_update_flags(dentry);
	}
	__d_rehash(dentry);
	if (dir)
		end_dir_add(dir, n);
	spin_unlock(&dentry->d_lock);
	if (inode)
		spin_unlock(&inode->i_lock);
}

/**
 * d_add - add dentry to hash queues
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */

void d_add(struct dentry *entry, struct inode *inode)
{
	if (inode) {
		security_d_instantiate(entry, inode);
		spin_lock(&inode->i_lock);
	}
	__d_add(entry, inode);
}
EXPORT_SYMBOL(d_add);

/**
 * d_exact_alias - find and hash an exact unhashed alias
 * @entry: dentry to add
 * @inode: The inode to go with this dentry
 *
 * If an unhashed dentry with the same name/parent and desired
 * inode already exists, hash and return it.  Otherwise, return
 * NULL.
 *
 * Parent directory should be locked.
 */
struct dentry *d_exact_alias(struct dentry *entry, struct inode *inode)
{
	struct dentry *alias;
	unsigned int hash = entry->d_name.hash;

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) {
		/*
		 * Don't need alias->d_lock here, because aliases with
		 * d_parent == entry->d_parent are not subject to name or
		 * parent changes, because the parent inode i_mutex is held.
		 */
		if (alias->d_name.hash != hash)
			continue;
		if (alias->d_parent != entry->d_parent)
			continue;
		if (!d_same_name(alias, entry->d_parent, &entry->d_name))
			continue;
		spin_lock(&alias->d_lock);
		if (!d_unhashed(alias)) {
			spin_unlock(&alias->d_lock);
			alias = NULL;
		} else {
			__dget_dlock(alias);
			__d_rehash(alias);
			spin_unlock(&alias->d_lock);
		}
		spin_unlock(&inode->i_lock);
		return alias;
	}
	spin_unlock(&inode->i_lock);
	return NULL;
}
EXPORT_SYMBOL(d_exact_alias);

static void swap_names(struct dentry *dentry, struct dentry *target)
{
	if (unlikely(dname_external(target))) {
		if (unlikely(dname_external(dentry))) {
			/*
			 * Both external: swap the pointers
			 */
			swap(target->d_name.name, dentry->d_name.name);
		} else {
			/*
			 * dentry:internal, target:external.  Steal target's
			 * storage and make target internal.
			 */
			memcpy(target->d_iname, dentry->d_name.name,
					dentry->d_name.len + 1);
			dentry->d_name.name = target->d_name.name;
			target->d_name.name = target->d_iname;
		}
	} else {
		if (dname_external(dentry)) {
		if (unlikely(dname_external(dentry))) {
			/*
			 * dentry:external, target:internal.  Give dentry's
			 * storage to target and make dentry internal
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			target->d_name.name = dentry->d_name.name;
			dentry->d_name.name = dentry->d_iname;
		} else {
			/*
			 * Both are internal.  Just copy target to dentry
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
		}
	}
}

/*
 * We cannibalize "target" when moving dentry on top of it,
 * because it's going to be thrown away anyway. We could be more
 * polite about it, though.
 *
 * This forceful removal will result in ugly /proc output if
 * somebody holds a file open that got deleted due to a rename.
 * We could be nicer about the deleted file, and let it show
 * up under the name it had before it was deleted rather than
 * under the original name of the file that was moved on top of it.
 */
 
/*
 * d_move_locked - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way.
 */
static void d_move_locked(struct dentry * dentry, struct dentry * target)
{
	struct hlist_head *list;

	if (!dentry->d_inode)
		printk(KERN_WARNING "VFS: moving negative dcache entry\n");

	write_seqlock(&rename_lock);
	/*
	 * XXXX: do we really need to take target->d_lock?
	 */
	if (target < dentry) {
		spin_lock(&target->d_lock);
		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	} else {
		spin_lock(&dentry->d_lock);
		spin_lock_nested(&target->d_lock, DENTRY_D_LOCK_NESTED);
	}

	/* Move the dentry to the target hash queue, if on different bucket */
	if (d_unhashed(dentry))
		goto already_unhashed;

	hlist_del_rcu(&dentry->d_hash);

already_unhashed:
	list = d_hash(target->d_parent, target->d_name.hash);
	__d_rehash(dentry, list);

	/* Unhash the target: dput() will then get rid of it */
	__d_drop(target);

	list_del(&dentry->d_u.d_child);
	list_del(&target->d_u.d_child);

	/* Switch the names.. */
	switch_names(dentry, target);
	do_switch(dentry->d_name.len, target->d_name.len);
	do_switch(dentry->d_name.hash, target->d_name.hash);

	/* ... and switch the parents */
	if (IS_ROOT(dentry)) {
		dentry->d_parent = target->d_parent;
		target->d_parent = target;
		INIT_LIST_HEAD(&target->d_u.d_child);
	} else {
		do_switch(dentry->d_parent, target->d_parent);

		/* And add them back to the (new) parent lists */
		list_add(&target->d_u.d_child, &target->d_parent->d_subdirs);
	}

	list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);
	spin_unlock(&target->d_lock);
	fsnotify_d_move(dentry);
	spin_unlock(&dentry->d_lock);
	write_sequnlock(&rename_lock);
}

/**
			 * Both are internal.
			 */
			unsigned int i;
			BUILD_BUG_ON(!IS_ALIGNED(DNAME_INLINE_LEN, sizeof(long)));
			for (i = 0; i < DNAME_INLINE_LEN / sizeof(long); i++) {
				swap(((long *) &dentry->d_iname)[i],
				     ((long *) &target->d_iname)[i]);
			}
		}
	}
	swap(dentry->d_name.hash_len, target->d_name.hash_len);
}

static void copy_name(struct dentry *dentry, struct dentry *target)
{
	struct external_name *old_name = NULL;
	if (unlikely(dname_external(dentry)))
		old_name = external_name(dentry);
	if (unlikely(dname_external(target))) {
		atomic_inc(&external_name(target)->u.count);
		dentry->d_name = target->d_name;
	} else {
		memcpy(dentry->d_iname, target->d_name.name,
				target->d_name.len + 1);
		dentry->d_name.name = dentry->d_iname;
		dentry->d_name.hash_len = target->d_name.hash_len;
	}
	if (old_name && likely(atomic_dec_and_test(&old_name->u.count)))
		call_rcu(&old_name->u.head, __d_free_external_name);
}

/*
 * __d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 * @exchange: exchange the two dentries
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way. Caller must hold
 * rename_lock, the i_mutex of the source and target directories,
 * and the sb->s_vfs_rename_mutex if they differ. See lock_rename().
 */
static void __d_move(struct dentry *dentry, struct dentry *target,
		     bool exchange)
{
	struct dentry *old_parent, *p;
	struct inode *dir = NULL;
	unsigned n;

	WARN_ON(!dentry->d_inode);
	if (WARN_ON(dentry == target))
		return;

	BUG_ON(d_ancestor(target, dentry));
	old_parent = dentry->d_parent;
	p = d_ancestor(old_parent, target);
	if (IS_ROOT(dentry)) {
		BUG_ON(p);
		spin_lock(&target->d_parent->d_lock);
	} else if (!p) {
		/* target is not a descendent of dentry->d_parent */
		spin_lock(&target->d_parent->d_lock);
		spin_lock_nested(&old_parent->d_lock, DENTRY_D_LOCK_NESTED);
	} else {
		BUG_ON(p == dentry);
		spin_lock(&old_parent->d_lock);
		if (p != target)
			spin_lock_nested(&target->d_parent->d_lock,
					DENTRY_D_LOCK_NESTED);
	}
	spin_lock_nested(&dentry->d_lock, 2);
	spin_lock_nested(&target->d_lock, 3);

	if (unlikely(d_in_lookup(target))) {
		dir = target->d_parent->d_inode;
		n = start_dir_add(dir);
		__d_lookup_done(target);
	}

	write_seqcount_begin(&dentry->d_seq);
	write_seqcount_begin_nested(&target->d_seq, DENTRY_D_LOCK_NESTED);

	/* unhash both */
	if (!d_unhashed(dentry))
		___d_drop(dentry);
	if (!d_unhashed(target))
		___d_drop(target);

	/* ... and switch them in the tree */
	dentry->d_parent = target->d_parent;
	if (!exchange) {
		copy_name(dentry, target);
		target->d_hash.pprev = NULL;
		dentry->d_parent->d_lockref.count++;
		if (dentry == old_parent)
			dentry->d_flags |= DCACHE_RCUACCESS;
		else
			WARN_ON(!--old_parent->d_lockref.count);
	} else {
		target->d_parent = old_parent;
		swap_names(dentry, target);
		list_move(&target->d_child, &target->d_parent->d_subdirs);
		__d_rehash(target);
		fsnotify_update_flags(target);
	}
	list_move(&dentry->d_child, &dentry->d_parent->d_subdirs);
	__d_rehash(dentry);
	fsnotify_update_flags(dentry);

	write_seqcount_end(&target->d_seq);
	write_seqcount_end(&dentry->d_seq);

	if (dir)
		end_dir_add(dir, n);

	if (dentry->d_parent != old_parent)
		spin_unlock(&dentry->d_parent->d_lock);
	if (dentry != old_parent)
		spin_unlock(&old_parent->d_lock);
	spin_unlock(&target->d_lock);
	spin_unlock(&dentry->d_lock);
}

/*
 * d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way.
 */

void d_move(struct dentry * dentry, struct dentry * target)
{
	spin_lock(&dcache_lock);
	d_move_locked(dentry, target);
	spin_unlock(&dcache_lock);
}

/*
 * Helper that returns 1 if p1 is a parent of p2, else 0
 */
static int d_isparent(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	for (p = p2; p->d_parent != p; p = p->d_parent) {
		if (p->d_parent == p1)
			return 1;
	}
	return 0;
 * dcache entries should not be moved in this way. See the locking
 * requirements for __d_move.
 */
void d_move(struct dentry *dentry, struct dentry *target)
{
	write_seqlock(&rename_lock);
	__d_move(dentry, target, false);
	write_sequnlock(&rename_lock);
}
EXPORT_SYMBOL(d_move);

/*
 * d_exchange - exchange two dentries
 * @dentry1: first dentry
 * @dentry2: second dentry
 */
void d_exchange(struct dentry *dentry1, struct dentry *dentry2)
{
	write_seqlock(&rename_lock);

	WARN_ON(!dentry1->d_inode);
	WARN_ON(!dentry2->d_inode);
	WARN_ON(IS_ROOT(dentry1));
	WARN_ON(IS_ROOT(dentry2));

	__d_move(dentry1, dentry2, true);

	write_sequnlock(&rename_lock);
}

/**
 * d_ancestor - search for an ancestor
 * @p1: ancestor dentry
 * @p2: child dentry
 *
 * Returns the ancestor dentry of p2 which is a child of p1, if p1 is
 * an ancestor of p2, else NULL.
 */
struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	for (p = p2; !IS_ROOT(p); p = p->d_parent) {
		if (p->d_parent == p1)
			return p;
	}
	return NULL;
}

/*
 * This helper attempts to cope with remotely renamed directories
 *
 * It assumes that the caller is already holding
 * dentry->d_parent->d_inode->i_mutex and the dcache_lock
 * dentry->d_parent->d_inode->i_mutex, and rename_lock
 *
 * Note: If ever the locking in lock_rename() changes, then please
 * remember to update this too...
 */
static struct dentry *__d_unalias(struct dentry *dentry, struct dentry *alias)
	__releases(dcache_lock)
{
	struct mutex *m1 = NULL, *m2 = NULL;
	struct dentry *ret;
static int __d_unalias(struct inode *inode,
		struct dentry *dentry, struct dentry *alias)
{
	struct mutex *m1 = NULL;
	struct rw_semaphore *m2 = NULL;
	int ret = -ESTALE;

	/* If alias and dentry share a parent, then no extra locks required */
	if (alias->d_parent == dentry->d_parent)
		goto out_unalias;

	/* Check for loops */
	ret = ERR_PTR(-ELOOP);
	if (d_isparent(alias, dentry))
		goto out_err;

	/* See lock_rename() */
	ret = ERR_PTR(-EBUSY);
	/* See lock_rename() */
	if (!mutex_trylock(&dentry->d_sb->s_vfs_rename_mutex))
		goto out_err;
	m1 = &dentry->d_sb->s_vfs_rename_mutex;
	if (!inode_trylock_shared(alias->d_parent->d_inode))
		goto out_err;
	m2 = &alias->d_parent->d_inode->i_rwsem;
out_unalias:
	d_move_locked(alias, dentry);
	ret = alias;
out_err:
	spin_unlock(&dcache_lock);
	__d_move(alias, dentry, false);
	ret = 0;
out_err:
	if (m2)
		up_read(m2);
	if (m1)
		mutex_unlock(m1);
	return ret;
}

/*
 * Prepare an anonymous dentry for life in the superblock's dentry tree as a
 * named dentry in place of the dentry to be replaced.
 */
static void __d_materialise_dentry(struct dentry *dentry, struct dentry *anon)
{
	struct dentry *dparent, *aparent;

	switch_names(dentry, anon);
	do_switch(dentry->d_name.len, anon->d_name.len);
	do_switch(dentry->d_name.hash, anon->d_name.hash);

	dparent = dentry->d_parent;
	aparent = anon->d_parent;

	dentry->d_parent = (aparent == anon) ? dentry : aparent;
	list_del(&dentry->d_u.d_child);
	if (!IS_ROOT(dentry))
		list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);
	else
		INIT_LIST_HEAD(&dentry->d_u.d_child);

	anon->d_parent = (dparent == dentry) ? anon : dparent;
	list_del(&anon->d_u.d_child);
	if (!IS_ROOT(anon))
		list_add(&anon->d_u.d_child, &anon->d_parent->d_subdirs);
	else
		INIT_LIST_HEAD(&anon->d_u.d_child);

	anon->d_flags &= ~DCACHE_DISCONNECTED;
}

/**
 * d_materialise_unique - introduce an inode into the tree
 * @dentry: candidate dentry
 * @inode: inode to bind to the dentry, to which aliases may be attached
 *
 * Introduces an dentry into the tree, substituting an extant disconnected
 * root directory alias in its place if there is one
 */
struct dentry *d_materialise_unique(struct dentry *dentry, struct inode *inode)
{
	struct dentry *actual;

	BUG_ON(!d_unhashed(dentry));

	spin_lock(&dcache_lock);

	if (!inode) {
		actual = dentry;
		dentry->d_inode = NULL;
		goto found_lock;
	}

	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;

		/* Does an aliased dentry already exist? */
		alias = __d_find_alias(inode, 0);
		if (alias) {
			actual = alias;
			/* Is this an anonymous mountpoint that we could splice
			 * into our tree? */
			if (IS_ROOT(alias)) {
				spin_lock(&alias->d_lock);
				__d_materialise_dentry(dentry, alias);
				__d_drop(alias);
				goto found;
			}
			/* Nope, but we must(!) avoid directory aliasing */
			actual = __d_unalias(dentry, alias);
			if (IS_ERR(actual))
				dput(alias);
			goto out_nolock;
		}
	}

	/* Add a unique reference */
	actual = __d_instantiate_unique(dentry, inode);
	if (!actual)
		actual = dentry;
	else if (unlikely(!d_unhashed(actual)))
		goto shouldnt_be_hashed;

found_lock:
	spin_lock(&actual->d_lock);
found:
	_d_rehash(actual);
	spin_unlock(&actual->d_lock);
	spin_unlock(&dcache_lock);
out_nolock:
	if (actual == dentry) {
		security_d_instantiate(dentry, inode);
		return NULL;
	}

	iput(inode);
	return actual;

shouldnt_be_hashed:
	spin_unlock(&dcache_lock);
	BUG();
}
/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has an IS_ROOT alias, then d_move that in
 * place of the given dentry and return it, else simply d_add the inode
 * to the dentry and return NULL.
 *
 * If a non-IS_ROOT directory is found, the filesystem is corrupt, and
 * we should error out: directories can't have multiple aliases.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 * Cluster filesystems may call this function with a negative, hashed dentry.
 * In that case, we know that the inode will be a regular file, and also this
 * will only occur during atomic_open. So we need to check for the dentry
 * being already hashed only in the final case.
 */
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	BUG_ON(!d_unhashed(dentry));

	if (!inode)
		goto out;

	security_d_instantiate(dentry, inode);
	spin_lock(&inode->i_lock);
	if (S_ISDIR(inode->i_mode)) {
		struct dentry *new = __d_find_any_alias(inode);
		if (unlikely(new)) {
			/* The reference to new ensures it remains an alias */
			spin_unlock(&inode->i_lock);
			write_seqlock(&rename_lock);
			if (unlikely(d_ancestor(new, dentry))) {
				write_sequnlock(&rename_lock);
				dput(new);
				new = ERR_PTR(-ELOOP);
				pr_warn_ratelimited(
					"VFS: Lookup of '%s' in %s %s"
					" would have caused loop\n",
					dentry->d_name.name,
					inode->i_sb->s_type->name,
					inode->i_sb->s_id);
			} else if (!IS_ROOT(new)) {
				struct dentry *old_parent = dget(new->d_parent);
				int err = __d_unalias(inode, dentry, new);
				write_sequnlock(&rename_lock);
				if (err) {
					dput(new);
					new = ERR_PTR(err);
				}
				dput(old_parent);
			} else {
				__d_move(new, dentry, false);
				write_sequnlock(&rename_lock);
			}
			iput(inode);
			return new;
		}
	}
out:
	__d_add(dentry, inode);
	return NULL;
}
EXPORT_SYMBOL(d_splice_alias);

static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

static int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
	return prepend(buffer, buflen, name->name, name->len);
/**
 * prepend_name - prepend a pathname in front of current buffer pointer
 * @buffer: buffer pointer
 * @buflen: allocated length of the buffer
 * @name:   name string and length qstr structure
 *
 * With RCU path tracing, it may race with d_move(). Use ACCESS_ONCE() to
 * make sure that either the old or the new name pointer and length are
 * fetched. However, there may be mismatch between length and pointer.
 * The length cannot be trusted, we need to copy it byte-by-byte until
 * the length is reached or a null byte is found. It also prepends "/" at
 * the beginning of the name. The sequence number check at the caller will
 * retry it again when a d_move() does happen. So any garbage in the buffer
 * due to mismatched pointer and length will be discarded.
 *
 * Data dependency barrier is needed to make sure that we see that terminating
 * NUL.  Alpha strikes again, film at 11...
 */
static int prepend_name(char **buffer, int *buflen, const struct qstr *name)
{
	const char *dname = ACCESS_ONCE(name->name);
	u32 dlen = ACCESS_ONCE(name->len);
	char *p;

	smp_read_barrier_depends();

	*buflen -= dlen + 1;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	p = *buffer -= dlen + 1;
	*p++ = '/';
	while (dlen--) {
		char c = *dname++;
		if (!c)
			break;
		*p++ = c;
	}
	return 0;
}

/**
 * prepend_path - Prepend path string to a buffer
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @buffer: pointer to the end of the buffer
 * @buflen: pointer to buffer length
 *
 * The function will first try to write out the pathname without taking any
 * lock other than the RCU read lock to make sure that dentries won't go away.
 * It only checks the sequence number of the global rename_lock as any change
 * in the dentry's d_seq will be preceded by changes in the rename_lock
 * sequence number. If the sequence number had been changed, it will restart
 * the whole pathname back-tracing sequence again by taking the rename_lock.
 * In this case, there is no need to take the RCU read lock as the recursive
 * parent pointer references will keep the dentry chain alive as long as no
 * rename operation is performed.
 */
static int prepend_path(const struct path *path,
			const struct path *root,
			char **buffer, int *buflen)
{
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	int error = 0;
	unsigned seq, m_seq = 0;
	char *bptr;
	int blen;

	rcu_read_lock();
restart_mnt:
	read_seqbegin_or_lock(&mount_lock, &m_seq);
	seq = 0;
	rcu_read_lock();
restart:
	bptr = *buffer;
	blen = *buflen;
	error = 0;
	dentry = path->dentry;
	vfsmnt = path->mnt;
	mnt = real_mount(vfsmnt);
	read_seqbegin_or_lock(&rename_lock, &seq);
	while (dentry != root->dentry || vfsmnt != root->mnt) {
		struct dentry * parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			struct mount *parent = ACCESS_ONCE(mnt->mnt_parent);
			/* Escaped? */
			if (dentry != vfsmnt->mnt_root) {
				bptr = *buffer;
				blen = *buflen;
				error = 3;
				break;
			}
			/* Global root? */
			if (mnt != parent) {
				dentry = ACCESS_ONCE(mnt->mnt_mountpoint);
				mnt = parent;
				vfsmnt = &mnt->mnt;
				continue;
			}
			if (!error)
				error = is_mounted(vfsmnt) ? 1 : 2;
			break;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		error = prepend_name(&bptr, &blen, &dentry->d_name);
		if (error)
			break;

		dentry = parent;
	}
	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);

	if (!(m_seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&mount_lock, m_seq)) {
		m_seq = 1;
		goto restart_mnt;
	}
	done_seqretry(&mount_lock, m_seq);

	if (error >= 0 && bptr == *buffer) {
		if (--blen < 0)
			error = -ENAMETOOLONG;
		else
			*--bptr = '/';
	}
	*buffer = bptr;
	*buflen = blen;
	return error;
}

/**
 * __d_path - return the path of a dentry
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry (may be modified by this function)
 * @buffer: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns the buffer or an error code if the path was too long.
 *
 * "buflen" should be positive. Caller holds the dcache_lock.
 *
 * If path is not reachable from the supplied root, then the value of
 * root is changed (without modifying refcounts).
 */
char *__d_path(const struct path *path, struct path *root,
	       char *buffer, int buflen)
{
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	char *end = buffer + buflen;
	char *retval;

	spin_lock(&vfsmount_lock);
	prepend(&end, &buflen, "\0", 1);
	if (!IS_ROOT(dentry) && d_unhashed(dentry) &&
		(prepend(&end, &buflen, " (deleted)", 10) != 0))
			goto Elong;

	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == root->dentry && vfsmnt == root->mnt)
			break;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			if (vfsmnt->mnt_parent == vfsmnt) {
				goto global_root;
			}
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		if ((prepend_name(&end, &buflen, &dentry->d_name) != 0) ||
		    (prepend(&end, &buflen, "/", 1) != 0))
			goto Elong;
		retval = end;
		dentry = parent;
	}

out:
	spin_unlock(&vfsmount_lock);
	return retval;

global_root:
	retval += 1;	/* hit the slash */
	if (prepend_name(&retval, &buflen, &dentry->d_name) != 0)
		goto Elong;
	root->mnt = vfsmnt;
	root->dentry = dentry;
	goto out;

Elong:
	retval = ERR_PTR(-ENAMETOOLONG);
	goto out;
 * @root: root vfsmnt/dentry
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name.
 *
 * Returns a pointer into the buffer or an error code if the
 * path was too long.
 *
 * "buflen" should be positive.
 *
 * If the path is not reachable from the supplied root, return %NULL.
 */
char *__d_path(const struct path *path,
	       const struct path *root,
	       char *buf, int buflen)
{
	char *res = buf + buflen;
	int error;

	prepend(&res, &buflen, "\0", 1);
	error = prepend_path(path, root, &res, &buflen);

	if (error < 0)
		return ERR_PTR(error);
	if (error > 0)
		return NULL;
	return res;
}

char *d_absolute_path(const struct path *path,
	       char *buf, int buflen)
{
	struct path root = {};
	char *res = buf + buflen;
	int error;

	prepend(&res, &buflen, "\0", 1);
	error = prepend_path(path, &root, &res, &buflen);

	if (error > 1)
		error = -EINVAL;
	if (error < 0)
		return ERR_PTR(error);
	return res;
}

/*
 * same as __d_path but appends "(deleted)" for unlinked files.
 */
static int path_with_deleted(const struct path *path,
			     const struct path *root,
			     char **buf, int *buflen)
{
	prepend(buf, buflen, "\0", 1);
	if (d_unlinked(path->dentry)) {
		int error = prepend(buf, buflen, " (deleted)", 10);
		if (error)
			return error;
	}

	return prepend_path(path, root, buf, buflen);
}

static int prepend_unreachable(char **buffer, int *buflen)
{
	return prepend(buffer, buflen, "(unreachable)", 13);
}

static void get_fs_root_rcu(struct fs_struct *fs, struct path *root)
{
	unsigned seq;

	do {
		seq = read_seqcount_begin(&fs->seq);
		*root = fs->root;
	} while (read_seqcount_retry(&fs->seq, seq));
}

/**
 * d_path - return the path of a dentry
 * @path: path to report
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns the buffer or an error code if the path was too long.
 * Returns a pointer into the buffer or an error code if the path was
 * too long. Note: Callers should use the returned pointer, not the passed
 * in buffer, to use the name! The implementation often starts at an offset
 * into the buffer, and may leave 0 bytes at the start.
 *
 * "buflen" should be positive.
 */
char *d_path(const struct path *path, char *buf, int buflen)
{
	char *res;
	struct path root;
	struct path tmp;
	char *res = buf + buflen;
	struct path root;
	int error;

	/*
	 * We have various synthetic filesystems that never get mounted.  On
	 * these filesystems dentries are never used for lookup purposes, and
	 * thus don't need to be hashed.  They also don't need a name until a
	 * user wants to identify the object in /proc/pid/fd/.  The little hack
	 * below allows us to generate a name for these objects on demand:
	 */
	if (path->dentry->d_op && path->dentry->d_op->d_dname)
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);
	spin_lock(&dcache_lock);
	tmp = root;
	res = __d_path(path, &tmp, buf, buflen);
	spin_unlock(&dcache_lock);
	path_put(&root);
	return res;
}
	 *
	 * Some pseudo inodes are mountable.  When they are mounted
	 * path->dentry == path->mnt->mnt_root.  In that case don't call d_dname
	 * and instead have d_path return the mounted path.
	 */
	if (path->dentry->d_op && path->dentry->d_op->d_dname &&
	    (!IS_ROOT(path->dentry) || path->dentry != path->mnt->mnt_root))
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	rcu_read_lock();
	get_fs_root_rcu(current->fs, &root);
	error = path_with_deleted(path, &root, &res, &buflen);
	rcu_read_unlock();

	if (error < 0)
		res = ERR_PTR(error);
	return res;
}
EXPORT_SYMBOL(d_path);

/*
 * Helper function for dentry_operations.d_dname() members
 */
char *dynamic_dname(struct dentry *dentry, char *buffer, int buflen,
			const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
char *dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *end = buf + buflen;
	char *retval;

	spin_lock(&dcache_lock);
	prepend(&end, &buflen, "\0", 1);
	if (!IS_ROOT(dentry) && d_unhashed(dentry) &&
		(prepend(&end, &buflen, "//deleted", 9) != 0))
			goto Elong;
	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

char *simple_dname(struct dentry *dentry, char *buffer, int buflen)
{
	char *end = buffer + buflen;
	/* these dentries are never renamed, so d_lock is not needed */
	if (prepend(&end, &buflen, " (deleted)", 11) ||
	    prepend(&end, &buflen, dentry->d_name.name, dentry->d_name.len) ||
	    prepend(&end, &buflen, "/", 1))  
		end = ERR_PTR(-ENAMETOOLONG);
	return end;
}
EXPORT_SYMBOL(simple_dname);

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
static char *__dentry_path(struct dentry *d, char *buf, int buflen)
{
	struct dentry *dentry;
	char *end, *retval;
	int len, seq = 0;
	int error = 0;

	if (buflen < 2)
		goto Elong;

	rcu_read_lock();
restart:
	dentry = d;
	end = buf + buflen;
	len = buflen;
	prepend(&end, &len, "\0", 1);
	/* Get '/' right */
	retval = end-1;
	*retval = '/';
	read_seqbegin_or_lock(&rename_lock, &seq);
	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;

		prefetch(parent);
		if ((prepend_name(&end, &buflen, &dentry->d_name) != 0) ||
		    (prepend(&end, &buflen, "/", 1) != 0))
			goto Elong;
		error = prepend_name(&end, &len, &dentry->d_name);
		if (error)
			break;

		retval = end;
		dentry = parent;
	}
	spin_unlock(&dcache_lock);
	return retval;
Elong:
	spin_unlock(&dcache_lock);
	return ERR_PTR(-ENAMETOOLONG);
}

	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);
	if (error)
		goto Elong;
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

char *dentry_path_raw(struct dentry *dentry, char *buf, int buflen)
{
	return __dentry_path(dentry, buf, buflen);
}
EXPORT_SYMBOL(dentry_path_raw);

char *dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *p = NULL;
	char *retval;

	if (d_unlinked(dentry)) {
		p = buf + buflen;
		if (prepend(&p, &buflen, "//deleted", 10) != 0)
			goto Elong;
		buflen++;
	}
	retval = __dentry_path(dentry, buf, buflen);
	if (!IS_ERR(retval) && p)
		*p = '/';	/* restore '/' overriden with '\0' */
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

static void get_fs_root_and_pwd_rcu(struct fs_struct *fs, struct path *root,
				    struct path *pwd)
{
	unsigned seq;

	do {
		seq = read_seqcount_begin(&fs->seq);
		*root = fs->root;
		*pwd = fs->pwd;
	} while (read_seqcount_retry(&fs->seq, seq));
}

/*
 * NOTE! The user-level library version returns a
 * character pointer. The kernel system call just
 * returns the length of the buffer filled (which
 * includes the ending '\0' character), or a negative
 * error value. So libc would do something like
 *
 *	char *getcwd(char * buf, size_t size)
 *	{
 *		int retval;
 *
 *		retval = sys_getcwd(buf, size);
 *		if (retval >= 0)
 *			return buf;
 *		errno = -retval;
 *		return NULL;
 *	}
 */
asmlinkage long sys_getcwd(char __user *buf, unsigned long size)
{
	int error;
	struct path pwd, root;
	char *page = (char *) __get_free_page(GFP_USER);
SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	int error;
	struct path pwd, root;
	char *page = __getname();

	if (!page)
		return -ENOMEM;

	read_lock(&current->fs->lock);
	pwd = current->fs->pwd;
	path_get(&pwd);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);

	error = -ENOENT;
	/* Has the current directory has been unlinked? */
	spin_lock(&dcache_lock);
	if (IS_ROOT(pwd.dentry) || !d_unhashed(pwd.dentry)) {
		unsigned long len;
		struct path tmp = root;
		char * cwd;

		cwd = __d_path(&pwd, &tmp, page, PAGE_SIZE);
		spin_unlock(&dcache_lock);

		error = PTR_ERR(cwd);
		if (IS_ERR(cwd))
			goto out;

		error = -ERANGE;
		len = PAGE_SIZE + page - cwd;
	rcu_read_lock();
	get_fs_root_and_pwd_rcu(current->fs, &root, &pwd);

	error = -ENOENT;
	if (!d_unlinked(pwd.dentry)) {
		unsigned long len;
		char *cwd = page + PATH_MAX;
		int buflen = PATH_MAX;

		prepend(&cwd, &buflen, "\0", 1);
		error = prepend_path(&pwd, &root, &cwd, &buflen);
		rcu_read_unlock();

		if (error < 0)
			goto out;

		/* Unreachable from current root */
		if (error > 0) {
			error = prepend_unreachable(&cwd, &buflen);
			if (error)
				goto out;
		}

		error = -ERANGE;
		len = PATH_MAX + page - cwd;
		if (len <= size) {
			error = len;
			if (copy_to_user(buf, cwd, len))
				error = -EFAULT;
		}
	} else
		spin_unlock(&dcache_lock);

out:
	path_put(&pwd);
	path_put(&root);
	free_page((unsigned long) page);
	} else {
		rcu_read_unlock();
	}

out:
	__putname(page);
	return error;
}

/*
 * Test whether new_dentry is a subdirectory of old_dentry.
 *
 * Trivially implemented using the dcache structure
 */

/**
 * is_subdir - is new dentry a subdirectory of old_dentry
 * @new_dentry: new dentry
 * @old_dentry: old dentry
 *
 * Returns true if new_dentry is a subdirectory of the parent (at any depth).
 * Returns false otherwise.
 * Caller must ensure that "new_dentry" is pinned before calling is_subdir()
 */
  
int is_subdir(struct dentry * new_dentry, struct dentry * old_dentry)
{
	int result;
	struct dentry * saved = new_dentry;
	unsigned long seq;

	/* need rcu_readlock to protect against the d_parent trashing due to
	 * d_move
	 */
	rcu_read_lock();
        do {
		/* for restarting inner loop in case of seq retry */
		new_dentry = saved;
		result = 0;
		seq = read_seqbegin(&rename_lock);
		for (;;) {
			if (new_dentry != old_dentry) {
				struct dentry * parent = new_dentry->d_parent;
				if (parent == new_dentry)
					break;
				new_dentry = parent;
				continue;
			}
			result = 1;
			break;
		}
	} while (read_seqretry(&rename_lock, seq));
	rcu_read_unlock();
int is_subdir(struct dentry *new_dentry, struct dentry *old_dentry)
bool is_subdir(struct dentry *new_dentry, struct dentry *old_dentry)
{
	bool result;
	unsigned seq;

	if (new_dentry == old_dentry)
		return true;

	do {
		/* for restarting inner loop in case of seq retry */
		seq = read_seqbegin(&rename_lock);
		/*
		 * Need rcu_readlock to protect against the d_parent trashing
		 * due to d_move
		 */
		rcu_read_lock();
		if (d_ancestor(old_dentry, new_dentry))
			result = true;
		else
			result = false;
		rcu_read_unlock();
	} while (read_seqretry(&rename_lock, seq));

	return result;
}
EXPORT_SYMBOL(is_subdir);

void d_genocide(struct dentry *root)
{
	struct dentry *this_parent = root;
	struct list_head *next;

	spin_lock(&dcache_lock);
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		if (d_unhashed(dentry)||!dentry->d_inode)
			continue;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
		atomic_dec(&dentry->d_count);
	}
	if (this_parent != root) {
		next = this_parent->d_u.d_child.next;
		atomic_dec(&this_parent->d_count);
		this_parent = this_parent->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
}

/**
 * find_inode_number - check for dentry with name
 * @dir: directory to check
 * @name: Name to find.
 *
 * Check whether a dentry already exists for the given name,
 * and return the inode number if it has an inode. Otherwise
 * 0 is returned.
 *
 * This routine is used to post-process directory listings for
 * filesystems using synthetic inode numbers, and is necessary
 * to keep getcwd() working.
 */
 
ino_t find_inode_number(struct dentry *dir, struct qstr *name)
{
	struct dentry * dentry;
	ino_t ino = 0;

	dentry = d_hash_and_lookup(dir, name);
	if (dentry) {
		if (dentry->d_inode)
			ino = dentry->d_inode->i_ino;
		dput(dentry);
	}
	return ino;
}

static enum d_walk_ret d_genocide_kill(void *data, struct dentry *dentry)
{
	struct dentry *root = data;
	if (dentry != root) {
		if (d_unhashed(dentry) || !dentry->d_inode)
			return D_WALK_SKIP;

		if (!(dentry->d_flags & DCACHE_GENOCIDE)) {
			dentry->d_flags |= DCACHE_GENOCIDE;
			dentry->d_lockref.count--;
		}
	}
	return D_WALK_CONTINUE;
}

void d_genocide(struct dentry *parent)
{
	d_walk(parent, parent, d_genocide_kill);
}

EXPORT_SYMBOL(d_genocide);

void d_tmpfile(struct dentry *dentry, struct inode *inode)
{
	inode_dec_link_count(inode);
	BUG_ON(dentry->d_name.name != dentry->d_iname ||
		!hlist_unhashed(&dentry->d_u.d_alias) ||
		!d_unlinked(dentry));
	spin_lock(&dentry->d_parent->d_lock);
	spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	dentry->d_name.len = sprintf(dentry->d_iname, "#%llu",
				(unsigned long long)inode->i_ino);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dentry->d_parent->d_lock);
	d_instantiate(dentry, inode);
}
EXPORT_SYMBOL(d_tmpfile);

static __initdata unsigned long dhash_entries;
static int __init set_dhash_entries(char *str)
{
	if (!str)
		return 0;
	dhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("dhash_entries=", set_dhash_entries);

static void __init dcache_init_early(void)
{
	int loop;
	unsigned int loop;

	/* If hashes are distributed across NUMA nodes, defer
	 * hash allocation until vmalloc space is available.
	 */
	if (hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					sizeof(struct hlist_bl_head),
					dhash_entries,
					13,
					HASH_EARLY | HASH_ZERO,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
					NULL,
					0,
					0);
	d_hash_shift = 32 - d_hash_shift;
}

static void __init dcache_init(void)
{
	int loop;
	unsigned int loop;

	/* 
	/*
	 * A constructor could be added for stable state like the lists,
	 * but it is probably not worth it because of the cache nature
	 * of the dcache.
	 */
	dentry_cache = KMEM_CACHE(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);
	
	register_shrinker(&dcache_shrinker);
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD|SLAB_ACCOUNT);
	dentry_cache = KMEM_CACHE_USERCOPY(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD|SLAB_ACCOUNT,
		d_iname);

	/* Hash may have been set up in dcache_init_early */
	if (!hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					sizeof(struct hlist_bl_head),
					dhash_entries,
					13,
					HASH_ZERO,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
					NULL,
					0,
					0);
	d_hash_shift = 32 - d_hash_shift;
}

/* SLAB cache for __getname() consumers */
struct kmem_cache *names_cachep __read_mostly;

/* SLAB cache for file structures */
struct kmem_cache *filp_cachep __read_mostly;
EXPORT_SYMBOL(names_cachep);

void __init vfs_caches_init_early(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(in_lookup_hashtable); i++)
		INIT_HLIST_BL_HEAD(&in_lookup_hashtable[i]);

	dcache_init_early();
	inode_init_early();
}

void __init vfs_caches_init(unsigned long mempages)
{
	unsigned long reserve;

	/* Base hash sizes on available memory, with a reserve equal to
           150% of current kernel size */

	reserve = min((mempages - nr_free_pages()) * 3/2, mempages - 1);
	mempages -= reserve;

	names_cachep = kmem_cache_create("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	filp_cachep = kmem_cache_create("filp", sizeof(struct file), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	dcache_init();
	inode_init();
	files_init(mempages);
void __init vfs_caches_init(void)
{
	names_cachep = kmem_cache_create_usercopy("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, 0, PATH_MAX, NULL);

	dcache_init();
	inode_init();
	files_init();
	files_maxfiles_init();
	mnt_init();
	bdev_cache_init();
	chrdev_init();
}

EXPORT_SYMBOL(d_alloc);
EXPORT_SYMBOL(d_alloc_anon);
EXPORT_SYMBOL(d_alloc_root);
EXPORT_SYMBOL(d_delete);
EXPORT_SYMBOL(d_find_alias);
EXPORT_SYMBOL(d_instantiate);
EXPORT_SYMBOL(d_invalidate);
EXPORT_SYMBOL(d_lookup);
EXPORT_SYMBOL(d_move);
EXPORT_SYMBOL_GPL(d_materialise_unique);
EXPORT_SYMBOL(d_path);
EXPORT_SYMBOL(d_prune_aliases);
EXPORT_SYMBOL(d_rehash);
EXPORT_SYMBOL(d_splice_alias);
EXPORT_SYMBOL(d_add_ci);
EXPORT_SYMBOL(d_validate);
EXPORT_SYMBOL(dget_locked);
EXPORT_SYMBOL(dput);
EXPORT_SYMBOL(find_inode_number);
EXPORT_SYMBOL(have_submounts);
EXPORT_SYMBOL(names_cachep);
EXPORT_SYMBOL(shrink_dcache_parent);
EXPORT_SYMBOL(shrink_dcache_sb);
