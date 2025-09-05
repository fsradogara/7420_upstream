#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/mbcache.h>

#include <linux/list.h>
#include <linux/list_bl.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mbcache.h>
#include <linux/init.h>
#include <linux/blockgroup_lock.h>
#include <linux/log2.h>

#ifdef MB_CACHE_DEBUG
# define mb_debug(f...) do { \
		printk(KERN_DEBUG f); \
		printk("\n"); \
	} while (0)
#define mb_assert(c) do { if (!(c)) \
		printk(KERN_ERR "assertion " #c " failed\n"); \
	} while(0)
#else
# define mb_debug(f...) do { } while(0)
# define mb_assert(c) do { } while(0)
#endif
#define mb_error(f...) do { \
		printk(KERN_ERR f); \
		printk("\n"); \
	} while(0)

#define MB_CACHE_WRITER ((unsigned short)~0U >> 1)

static DECLARE_WAIT_QUEUE_HEAD(mb_cache_queue);
		
#define MB_CACHE_ENTRY_LOCK_BITS	ilog2(NR_BG_LOCKS)
#define	MB_CACHE_ENTRY_LOCK_INDEX(ce)			\
	(hash_long((unsigned long)ce, MB_CACHE_ENTRY_LOCK_BITS))

static DECLARE_WAIT_QUEUE_HEAD(mb_cache_queue);
static struct blockgroup_lock *mb_cache_bg_lock;
static struct kmem_cache *mb_cache_kmem_cache;

MODULE_AUTHOR("Andreas Gruenbacher <a.gruenbacher@computer.org>");
MODULE_DESCRIPTION("Meta block cache (for extended attributes)");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mb_cache_create);
EXPORT_SYMBOL(mb_cache_shrink);
EXPORT_SYMBOL(mb_cache_destroy);
EXPORT_SYMBOL(mb_cache_entry_alloc);
EXPORT_SYMBOL(mb_cache_entry_insert);
EXPORT_SYMBOL(mb_cache_entry_release);
EXPORT_SYMBOL(mb_cache_entry_free);
EXPORT_SYMBOL(mb_cache_entry_get);
#if !defined(MB_CACHE_INDEXES_COUNT) || (MB_CACHE_INDEXES_COUNT > 0)
EXPORT_SYMBOL(mb_cache_entry_find_first);
EXPORT_SYMBOL(mb_cache_entry_find_next);
#endif

struct mb_cache {
	struct list_head		c_cache_list;
	const char			*c_name;
	struct mb_cache_op		c_op;
	atomic_t			c_entry_count;
	int				c_bucket_bits;
#ifndef MB_CACHE_INDEXES_COUNT
	int				c_indexes_count;
#endif
	struct kmem_cache			*c_entry_cache;
	struct list_head		*c_block_hash;
	struct list_head		*c_indexes_hash[0];
};


/*
 * Mbcache is a simple key-value store. Keys need not be unique, however
 * key-value pairs are expected to be unique (we use this fact in
 * mb_cache_entry_delete()).
 *
 * Ext2 and ext4 use this cache for deduplication of extended attribute blocks.
 * Ext4 also uses it for deduplication of xattr values stored in inodes.
 * They use hash of data as a key and provide a value that may represent a
 * block or inode number. That's why keys need not be unique (hash of different
 * data may be the same). However user provided value always uniquely
 * identifies a cache entry.
 *
 * We provide functions for creation and removal of entries, search by key,
 * and a special "delete entry with given key-value pair" operation. Fixed
 * size hash table is used for fast key lookups.
 */

static LIST_HEAD(mb_cache_list);
static LIST_HEAD(mb_cache_lru_list);
static DEFINE_SPINLOCK(mb_cache_spinlock);

static inline int
mb_cache_indexes(struct mb_cache *cache)
{
#ifdef MB_CACHE_INDEXES_COUNT
	return MB_CACHE_INDEXES_COUNT;
#else
	return cache->c_indexes_count;
#endif
}

/*
 * What the mbcache registers as to get shrunk dynamically.
 */

static int mb_cache_shrink_fn(int nr_to_scan, gfp_t gfp_mask);

static struct shrinker mb_cache_shrinker = {
	.shrink = mb_cache_shrink_fn,
	.seeks = DEFAULT_SEEKS,
};

static inline int
__mb_cache_entry_is_hashed(struct mb_cache_entry *ce)
{
	return !list_empty(&ce->e_block_list);
}


static void
__mb_cache_entry_unhash(struct mb_cache_entry *ce)
{
	int n;

	if (__mb_cache_entry_is_hashed(ce)) {
		list_del_init(&ce->e_block_list);
		for (n=0; n<mb_cache_indexes(ce->e_cache); n++)
			list_del(&ce->e_indexes[n].o_list);
	}
}


static inline void
__spin_lock_mb_cache_entry(struct mb_cache_entry *ce)
{
	spin_lock(bgl_lock_ptr(mb_cache_bg_lock,
		MB_CACHE_ENTRY_LOCK_INDEX(ce)));
}

static inline void
__spin_unlock_mb_cache_entry(struct mb_cache_entry *ce)
{
	spin_unlock(bgl_lock_ptr(mb_cache_bg_lock,
		MB_CACHE_ENTRY_LOCK_INDEX(ce)));
}

static inline int
__mb_cache_entry_is_block_hashed(struct mb_cache_entry *ce)
{
	return !hlist_bl_unhashed(&ce->e_block_list);
}


static inline void
__mb_cache_entry_unhash_block(struct mb_cache_entry *ce)
{
	if (__mb_cache_entry_is_block_hashed(ce))
		hlist_bl_del_init(&ce->e_block_list);
}

static inline int
__mb_cache_entry_is_index_hashed(struct mb_cache_entry *ce)
{
	return !hlist_bl_unhashed(&ce->e_index.o_list);
}

static inline void
__mb_cache_entry_unhash_index(struct mb_cache_entry *ce)
{
	if (__mb_cache_entry_is_index_hashed(ce))
		hlist_bl_del_init(&ce->e_index.o_list);
}

/*
 * __mb_cache_entry_unhash_unlock()
 *
 * This function is called to unhash both the block and index hash
 * chain.
 * It assumes both the block and index hash chain is locked upon entry.
 * It also unlock both hash chains both exit
 */
static inline void
__mb_cache_entry_unhash_unlock(struct mb_cache_entry *ce)
{
	__mb_cache_entry_unhash_index(ce);
	hlist_bl_unlock(ce->e_index_hash_p);
	__mb_cache_entry_unhash_block(ce);
	hlist_bl_unlock(ce->e_block_hash_p);
}

static void
__mb_cache_entry_forget(struct mb_cache_entry *ce, gfp_t gfp_mask)
{
	struct mb_cache *cache = ce->e_cache;

	mb_assert(!(ce->e_used || ce->e_queued));
	if (cache->c_op.free && cache->c_op.free(ce, gfp_mask)) {
		/* free failed -- put back on the lru list
		   for freeing later. */
		spin_lock(&mb_cache_spinlock);
		list_add(&ce->e_lru_list, &mb_cache_lru_list);
		spin_unlock(&mb_cache_spinlock);
	} else {
		kmem_cache_free(cache->c_entry_cache, ce);
		atomic_dec(&cache->c_entry_count);
	}
}


static void
__mb_cache_entry_release_unlock(struct mb_cache_entry *ce)
	__releases(mb_cache_spinlock)
{
	mb_assert(!(ce->e_used || ce->e_queued || atomic_read(&ce->e_refcnt)));
	kmem_cache_free(cache->c_entry_cache, ce);
	atomic_dec(&cache->c_entry_count);
}

static void
__mb_cache_entry_release(struct mb_cache_entry *ce)
{
	/* First lock the entry to serialize access to its local data. */
	__spin_lock_mb_cache_entry(ce);
	/* Wake up all processes queuing for this cache entry. */
	if (ce->e_queued)
		wake_up_all(&mb_cache_queue);
	if (ce->e_used >= MB_CACHE_WRITER)
		ce->e_used -= MB_CACHE_WRITER;
	ce->e_used--;
	if (!(ce->e_used || ce->e_queued)) {
		if (!__mb_cache_entry_is_hashed(ce))
			goto forget;
		mb_assert(list_empty(&ce->e_lru_list));
		list_add_tail(&ce->e_lru_list, &mb_cache_lru_list);
	}
	spin_unlock(&mb_cache_spinlock);
	return;
forget:
	spin_unlock(&mb_cache_spinlock);
	__mb_cache_entry_forget(ce, GFP_KERNEL);
}


/*
 * mb_cache_shrink_fn()  memory pressure callback
	/*
	 * Make sure that all cache entries on lru_list have
	 * both e_used and e_qued of 0s.
	 */
	ce->e_used--;
	if (!(ce->e_used || ce->e_queued || atomic_read(&ce->e_refcnt))) {
		if (!__mb_cache_entry_is_block_hashed(ce)) {
			__spin_unlock_mb_cache_entry(ce);
			goto forget;
		}
		/*
		 * Need access to lru list, first drop entry lock,
		 * then reacquire the lock in the proper order.
		 */
		spin_lock(&mb_cache_spinlock);
		if (list_empty(&ce->e_lru_list))
			list_add_tail(&ce->e_lru_list, &mb_cache_lru_list);
		spin_unlock(&mb_cache_spinlock);
	}
	__spin_unlock_mb_cache_entry(ce);
	return;
forget:
	mb_assert(list_empty(&ce->e_lru_list));
	__mb_cache_entry_forget(ce, GFP_KERNEL);
}

/*
 * mb_cache_shrink_scan()  memory pressure callback
 *
 * This function is called by the kernel memory management when memory
 * gets low.
 *
 * @nr_to_scan: Number of objects to scan
 * @gfp_mask: (ignored)
 *
 * Returns the number of objects which are present in the cache.
 */
static int
mb_cache_shrink_fn(int nr_to_scan, gfp_t gfp_mask)
{
	LIST_HEAD(free_list);
	struct list_head *l, *ltmp;
	int count = 0;

	spin_lock(&mb_cache_spinlock);
	list_for_each(l, &mb_cache_list) {
		struct mb_cache *cache =
			list_entry(l, struct mb_cache, c_cache_list);
 * @shrink: (ignored)
 * @sc: shrink_control passed from reclaim
 *
 * Returns the number of objects freed.
 */
static unsigned long
mb_cache_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	LIST_HEAD(free_list);
	struct mb_cache_entry *entry, *tmp;
	int nr_to_scan = sc->nr_to_scan;
	gfp_t gfp_mask = sc->gfp_mask;
	unsigned long freed = 0;

	mb_debug("trying to free %d entries", nr_to_scan);
	spin_lock(&mb_cache_spinlock);
	while ((nr_to_scan-- > 0) && !list_empty(&mb_cache_lru_list)) {
		struct mb_cache_entry *ce =
			list_entry(mb_cache_lru_list.next,
				struct mb_cache_entry, e_lru_list);
		list_del_init(&ce->e_lru_list);
		if (ce->e_used || ce->e_queued || atomic_read(&ce->e_refcnt))
			continue;
		spin_unlock(&mb_cache_spinlock);
		/* Prevent any find or get operation on the entry */
		hlist_bl_lock(ce->e_block_hash_p);
		hlist_bl_lock(ce->e_index_hash_p);
		/* Ignore if it is touched by a find/get */
		if (ce->e_used || ce->e_queued || atomic_read(&ce->e_refcnt) ||
			!list_empty(&ce->e_lru_list)) {
			hlist_bl_unlock(ce->e_index_hash_p);
			hlist_bl_unlock(ce->e_block_hash_p);
			spin_lock(&mb_cache_spinlock);
			continue;
		}
		__mb_cache_entry_unhash_unlock(ce);
		list_add_tail(&ce->e_lru_list, &free_list);
		spin_lock(&mb_cache_spinlock);
	}
	spin_unlock(&mb_cache_spinlock);

	list_for_each_entry_safe(entry, tmp, &free_list, e_lru_list) {
		__mb_cache_entry_forget(entry, gfp_mask);
		freed++;
	}
	return freed;
}

static unsigned long
mb_cache_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	struct mb_cache *cache;
	unsigned long count = 0;

	spin_lock(&mb_cache_spinlock);
	list_for_each_entry(cache, &mb_cache_list, c_cache_list) {
		mb_debug("cache %s (%d)", cache->c_name,
			  atomic_read(&cache->c_entry_count));
		count += atomic_read(&cache->c_entry_count);
	}
	mb_debug("trying to free %d entries", nr_to_scan);
	if (nr_to_scan == 0) {
		spin_unlock(&mb_cache_spinlock);
		goto out;
	}
	while (nr_to_scan-- && !list_empty(&mb_cache_lru_list)) {
		struct mb_cache_entry *ce =
			list_entry(mb_cache_lru_list.next,
				   struct mb_cache_entry, e_lru_list);
		list_move_tail(&ce->e_lru_list, &free_list);
		__mb_cache_entry_unhash(ce);
	}
	spin_unlock(&mb_cache_spinlock);
	list_for_each_safe(l, ltmp, &free_list) {
		__mb_cache_entry_forget(list_entry(l, struct mb_cache_entry,
						   e_lru_list), gfp_mask);
	}
out:
	return (count / 100) * sysctl_vfs_cache_pressure;
}

	spin_unlock(&mb_cache_spinlock);

	return vfs_pressure_ratio(count);
}

static struct shrinker mb_cache_shrinker = {
	.count_objects = mb_cache_shrink_count,
	.scan_objects = mb_cache_shrink_scan,
	.seeks = DEFAULT_SEEKS,
};

/*
 * mb_cache_create()  create a new cache
 *
 * All entries in one cache are equal size. Cache entries may be from
 * multiple devices. If this is the first mbcache created, registers
 * the cache with kernel memory management. Returns NULL if no more
 * memory was available.
 *
 * @name: name of the cache (informal)
 * @cache_op: contains the callback called when freeing a cache entry
 * @entry_size: The size of a cache entry, including
 *              struct mb_cache_entry
 * @indexes_count: number of additional indexes in the cache. Must equal
 *                 MB_CACHE_INDEXES_COUNT if the number of indexes is
 *                 hardwired.
 * @bucket_bits: log2(number of hash buckets)
 */
struct mb_cache *
mb_cache_create(const char *name, struct mb_cache_op *cache_op,
		size_t entry_size, int indexes_count, int bucket_bits)
{
	int m=0, n, bucket_count = 1 << bucket_bits;
	struct mb_cache *cache = NULL;

	if(entry_size < sizeof(struct mb_cache_entry) +
	   indexes_count * sizeof(((struct mb_cache_entry *) 0)->e_indexes[0]))
		return NULL;

	cache = kmalloc(sizeof(struct mb_cache) +
	                indexes_count * sizeof(struct list_head), GFP_KERNEL);
	if (!cache)
		goto fail;
	cache->c_name = name;
	cache->c_op.free = NULL;
	if (cache_op)
		cache->c_op.free = cache_op->free;
	atomic_set(&cache->c_entry_count, 0);
	cache->c_bucket_bits = bucket_bits;
#ifdef MB_CACHE_INDEXES_COUNT
	mb_assert(indexes_count == MB_CACHE_INDEXES_COUNT);
#else
	cache->c_indexes_count = indexes_count;
#endif
	cache->c_block_hash = kmalloc(bucket_count * sizeof(struct list_head),
	                              GFP_KERNEL);
	if (!cache->c_block_hash)
		goto fail;
	for (n=0; n<bucket_count; n++)
		INIT_LIST_HEAD(&cache->c_block_hash[n]);
	for (m=0; m<indexes_count; m++) {
		cache->c_indexes_hash[m] = kmalloc(bucket_count *
		                                 sizeof(struct list_head),
		                                 GFP_KERNEL);
		if (!cache->c_indexes_hash[m])
			goto fail;
		for (n=0; n<bucket_count; n++)
			INIT_LIST_HEAD(&cache->c_indexes_hash[m][n]);
	}
	cache->c_entry_cache = kmem_cache_create(name, entry_size, 0,
		SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD, NULL);
	if (!cache->c_entry_cache)
		goto fail;
 * @bucket_bits: log2(number of hash buckets)
 */
struct mb_cache *
mb_cache_create(const char *name, int bucket_bits)
{
	int n, bucket_count = 1 << bucket_bits;
	struct mb_cache *cache = NULL;

	if (!mb_cache_bg_lock) {
		mb_cache_bg_lock = kmalloc(sizeof(struct blockgroup_lock),
			GFP_KERNEL);
		if (!mb_cache_bg_lock)
			return NULL;
		bgl_lock_init(mb_cache_bg_lock);
	}

	cache = kmalloc(sizeof(struct mb_cache), GFP_KERNEL);
	if (!cache)
		return NULL;
	cache->c_name = name;
	atomic_set(&cache->c_entry_count, 0);
	cache->c_bucket_bits = bucket_bits;
	cache->c_block_hash = kmalloc(bucket_count *
		sizeof(struct hlist_bl_head), GFP_KERNEL);
	if (!cache->c_block_hash)
		goto fail;
	for (n=0; n<bucket_count; n++)
		INIT_HLIST_BL_HEAD(&cache->c_block_hash[n]);
	cache->c_index_hash = kmalloc(bucket_count *
		sizeof(struct hlist_bl_head), GFP_KERNEL);
	if (!cache->c_index_hash)
		goto fail;
	for (n=0; n<bucket_count; n++)
		INIT_HLIST_BL_HEAD(&cache->c_index_hash[n]);
	if (!mb_cache_kmem_cache) {
		mb_cache_kmem_cache = kmem_cache_create(name,
			sizeof(struct mb_cache_entry), 0,
			SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD, NULL);
		if (!mb_cache_kmem_cache)
			goto fail2;
	}
	cache->c_entry_cache = mb_cache_kmem_cache;

	/*
	 * Set an upper limit on the number of cache entries so that the hash
	 * chains won't grow too long.
	 */
	cache->c_max_entries = bucket_count << 4;

	spin_lock(&mb_cache_spinlock);
	list_add(&cache->c_cache_list, &mb_cache_list);
	spin_unlock(&mb_cache_spinlock);
	return cache;

fail:
	if (cache) {
		while (--m >= 0)
			kfree(cache->c_indexes_hash[m]);
		kfree(cache->c_block_hash);
		kfree(cache);
	}
fail2:
	kfree(cache->c_index_hash);

fail:
	kfree(cache->c_block_hash);
	kfree(cache);
	return NULL;
}


/*
 * mb_cache_shrink()
 *
 * Removes all cache entries of a device from the cache. All cache entries
 * currently in use cannot be freed, and thus remain in the cache. All others
 * are freed.
 *
 * @bdev: which device's cache entries to shrink
 */
void
mb_cache_shrink(struct block_device *bdev)
{
	LIST_HEAD(free_list);
	struct list_head *l, *ltmp;

	spin_lock(&mb_cache_spinlock);
	list_for_each_safe(l, ltmp, &mb_cache_lru_list) {
		struct mb_cache_entry *ce =
			list_entry(l, struct mb_cache_entry, e_lru_list);
		if (ce->e_bdev == bdev) {
			list_move_tail(&ce->e_lru_list, &free_list);
			__mb_cache_entry_unhash(ce);
		}
	}
	spin_unlock(&mb_cache_spinlock);
	list_for_each_safe(l, ltmp, &free_list) {
		__mb_cache_entry_forget(list_entry(l, struct mb_cache_entry,
						   e_lru_list), GFP_KERNEL);
	struct list_head *l;
	struct mb_cache_entry *ce, *tmp;

	l = &mb_cache_lru_list;
	spin_lock(&mb_cache_spinlock);
	while (!list_is_last(l, &mb_cache_lru_list)) {
		l = l->next;
		ce = list_entry(l, struct mb_cache_entry, e_lru_list);
		if (ce->e_bdev == bdev) {
			list_del_init(&ce->e_lru_list);
			if (ce->e_used || ce->e_queued ||
				atomic_read(&ce->e_refcnt))
				continue;
			spin_unlock(&mb_cache_spinlock);
			/*
			 * Prevent any find or get operation on the entry.
			 */
			hlist_bl_lock(ce->e_block_hash_p);
			hlist_bl_lock(ce->e_index_hash_p);
			/* Ignore if it is touched by a find/get */
			if (ce->e_used || ce->e_queued ||
				atomic_read(&ce->e_refcnt) ||
				!list_empty(&ce->e_lru_list)) {
				hlist_bl_unlock(ce->e_index_hash_p);
				hlist_bl_unlock(ce->e_block_hash_p);
				l = &mb_cache_lru_list;
				spin_lock(&mb_cache_spinlock);
				continue;
			}
			__mb_cache_entry_unhash_unlock(ce);
			mb_assert(!(ce->e_used || ce->e_queued ||
				atomic_read(&ce->e_refcnt)));
			list_add_tail(&ce->e_lru_list, &free_list);
			l = &mb_cache_lru_list;
			spin_lock(&mb_cache_spinlock);
		}
	}
	spin_unlock(&mb_cache_spinlock);

	list_for_each_entry_safe(ce, tmp, &free_list, e_lru_list) {
		__mb_cache_entry_forget(ce, GFP_KERNEL);
	}
}


/*
 * mb_cache_destroy()
 *
 * Shrinks the cache to its minimum possible size (hopefully 0 entries),
 * and then destroys it. If this was the last mbcache, un-registers the
 * mbcache from kernel memory management.
 */
void
mb_cache_destroy(struct mb_cache *cache)
{
	LIST_HEAD(free_list);
	struct list_head *l, *ltmp;
	int n;

	spin_lock(&mb_cache_spinlock);
	list_for_each_safe(l, ltmp, &mb_cache_lru_list) {
		struct mb_cache_entry *ce =
			list_entry(l, struct mb_cache_entry, e_lru_list);
		if (ce->e_cache == cache) {
			list_move_tail(&ce->e_lru_list, &free_list);
			__mb_cache_entry_unhash(ce);
		}
	struct mb_cache_entry *ce, *tmp;

	spin_lock(&mb_cache_spinlock);
	list_for_each_entry_safe(ce, tmp, &mb_cache_lru_list, e_lru_list) {
		if (ce->e_cache == cache)
			list_move_tail(&ce->e_lru_list, &free_list);
	}
	list_del(&cache->c_cache_list);
	spin_unlock(&mb_cache_spinlock);

	list_for_each_safe(l, ltmp, &free_list) {
		__mb_cache_entry_forget(list_entry(l, struct mb_cache_entry,
						   e_lru_list), GFP_KERNEL);
	list_for_each_entry_safe(ce, tmp, &free_list, e_lru_list) {
		list_del_init(&ce->e_lru_list);
		/*
		 * Prevent any find or get operation on the entry.
		 */
		hlist_bl_lock(ce->e_block_hash_p);
		hlist_bl_lock(ce->e_index_hash_p);
		mb_assert(!(ce->e_used || ce->e_queued ||
			atomic_read(&ce->e_refcnt)));
		__mb_cache_entry_unhash_unlock(ce);
		__mb_cache_entry_forget(ce, GFP_KERNEL);
	}

	if (atomic_read(&cache->c_entry_count) > 0) {
		mb_error("cache %s: %d orphaned entries",
			  cache->c_name,
			  atomic_read(&cache->c_entry_count));
	}

	kmem_cache_destroy(cache->c_entry_cache);

	for (n=0; n < mb_cache_indexes(cache); n++)
		kfree(cache->c_indexes_hash[n]);
	if (list_empty(&mb_cache_list)) {
		kmem_cache_destroy(mb_cache_kmem_cache);
		mb_cache_kmem_cache = NULL;
	}
	kfree(cache->c_index_hash);
	kfree(cache->c_block_hash);
	kfree(cache);
struct mb_cache {
	/* Hash table of entries */
	struct hlist_bl_head	*c_hash;
	/* log2 of hash table size */
	int			c_bucket_bits;
	/* Maximum entries in cache to avoid degrading hash too much */
	unsigned long		c_max_entries;
	/* Protects c_list, c_entry_count */
	spinlock_t		c_list_lock;
	struct list_head	c_list;
	/* Number of entries in cache */
	unsigned long		c_entry_count;
	struct shrinker		c_shrink;
	/* Work for shrinking when the cache has too many entries */
	struct work_struct	c_shrink_work;
};

static struct kmem_cache *mb_entry_cache;

static unsigned long mb_cache_shrink(struct mb_cache *cache,
				     unsigned long nr_to_scan);

static inline struct hlist_bl_head *mb_cache_entry_head(struct mb_cache *cache,
							u32 key)
{
	return &cache->c_hash[hash_32(key, cache->c_bucket_bits)];
}


/*
 * Number of entries to reclaim synchronously when there are too many entries
 * in cache
 */
struct mb_cache_entry *
mb_cache_entry_alloc(struct mb_cache *cache, gfp_t gfp_flags)
{
	struct mb_cache_entry *ce;

	ce = kmem_cache_alloc(cache->c_entry_cache, gfp_flags);
	if (ce) {
		atomic_inc(&cache->c_entry_count);
		INIT_LIST_HEAD(&ce->e_lru_list);
		INIT_LIST_HEAD(&ce->e_block_list);
		ce->e_cache = cache;
		ce->e_used = 1 + MB_CACHE_WRITER;
		ce->e_queued = 0;
	}
	if (atomic_read(&cache->c_entry_count) >= cache->c_max_entries) {
		struct list_head *l;

		l = &mb_cache_lru_list;
		spin_lock(&mb_cache_spinlock);
		while (!list_is_last(l, &mb_cache_lru_list)) {
			l = l->next;
			ce = list_entry(l, struct mb_cache_entry, e_lru_list);
			if (ce->e_cache == cache) {
				list_del_init(&ce->e_lru_list);
				if (ce->e_used || ce->e_queued ||
					atomic_read(&ce->e_refcnt))
					continue;
				spin_unlock(&mb_cache_spinlock);
				/*
				 * Prevent any find or get operation on the
				 * entry.
				 */
				hlist_bl_lock(ce->e_block_hash_p);
				hlist_bl_lock(ce->e_index_hash_p);
				/* Ignore if it is touched by a find/get */
				if (ce->e_used || ce->e_queued ||
					atomic_read(&ce->e_refcnt) ||
					!list_empty(&ce->e_lru_list)) {
					hlist_bl_unlock(ce->e_index_hash_p);
					hlist_bl_unlock(ce->e_block_hash_p);
					l = &mb_cache_lru_list;
					spin_lock(&mb_cache_spinlock);
					continue;
				}
				mb_assert(list_empty(&ce->e_lru_list));
				mb_assert(!(ce->e_used || ce->e_queued ||
					atomic_read(&ce->e_refcnt)));
				__mb_cache_entry_unhash_unlock(ce);
				goto found;
			}
		}
		spin_unlock(&mb_cache_spinlock);
	}

	ce = kmem_cache_alloc(cache->c_entry_cache, gfp_flags);
	if (!ce)
		return NULL;
	atomic_inc(&cache->c_entry_count);
	INIT_LIST_HEAD(&ce->e_lru_list);
	INIT_HLIST_BL_NODE(&ce->e_block_list);
	INIT_HLIST_BL_NODE(&ce->e_index.o_list);
	ce->e_cache = cache;
	ce->e_queued = 0;
	atomic_set(&ce->e_refcnt, 0);
found:
	ce->e_block_hash_p = &cache->c_block_hash[0];
	ce->e_index_hash_p = &cache->c_index_hash[0];
	ce->e_used = 1 + MB_CACHE_WRITER;
	return ce;
}

#define SYNC_SHRINK_BATCH 64

/*
 * mb_cache_entry_create - create entry in cache
 * @cache - cache where the entry should be created
 * @mask - gfp mask with which the entry should be allocated
 * @key - key of the entry
 * @value - value of the entry
 * @reusable - is the entry reusable by others?
 *
 * Inserts an entry that was allocated using mb_cache_entry_alloc() into
 * the cache. After this, the cache entry can be looked up, but is not yet
 * in the lru list as the caller still holds a handle to it. Returns 0 on
 * success, or -EBUSY if a cache entry for that device + inode exists
 * already (this may happen after a failed lookup, but when another process
 * has inserted the same cache entry in the meantime).
 *
 * @bdev: device the cache entry belongs to
 * @block: block number
 * @keys: array of additional keys. There must be indexes_count entries
 *        in the array (as specified when creating the cache).
 */
int
mb_cache_entry_insert(struct mb_cache_entry *ce, struct block_device *bdev,
		      sector_t block, unsigned int keys[])
{
	struct mb_cache *cache = ce->e_cache;
	unsigned int bucket;
	struct list_head *l;
	int error = -EBUSY, n;

	bucket = hash_long((unsigned long)bdev + (block & 0xffffffff), 
			   cache->c_bucket_bits);
	spin_lock(&mb_cache_spinlock);
	list_for_each_prev(l, &cache->c_block_hash[bucket]) {
		struct mb_cache_entry *ce =
			list_entry(l, struct mb_cache_entry, e_block_list);
		if (ce->e_bdev == bdev && ce->e_block == block)
			goto out;
	}
	__mb_cache_entry_unhash(ce);
	ce->e_bdev = bdev;
	ce->e_block = block;
	list_add(&ce->e_block_list, &cache->c_block_hash[bucket]);
	for (n=0; n<mb_cache_indexes(cache); n++) {
		ce->e_indexes[n].o_key = keys[n];
		bucket = hash_long(keys[n], cache->c_bucket_bits);
		list_add(&ce->e_indexes[n].o_list,
			 &cache->c_indexes_hash[n][bucket]);
	}
	error = 0;
out:
	spin_unlock(&mb_cache_spinlock);
	return error;
 * @key: lookup key
 * Creates entry in @cache with key @key and value @value. The function returns
 * -EBUSY if entry with the same key and value already exists in cache.
 * Otherwise 0 is returned.
 */
int mb_cache_entry_create(struct mb_cache *cache, gfp_t mask, u32 key,
			  u64 value, bool reusable)
{
	struct mb_cache_entry *entry, *dup;
	struct hlist_bl_node *dup_node;
	struct hlist_bl_head *head;

	/* Schedule background reclaim if there are too many entries */
	if (cache->c_entry_count >= cache->c_max_entries)
		schedule_work(&cache->c_shrink_work);
	/* Do some sync reclaim if background reclaim cannot keep up */
	if (cache->c_entry_count >= 2*cache->c_max_entries)
		mb_cache_shrink(cache, SYNC_SHRINK_BATCH);

	entry = kmem_cache_alloc(mb_entry_cache, mask);
	if (!entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&entry->e_list);
	/* One ref for hash, one ref returned */
	atomic_set(&entry->e_refcnt, 1);
	entry->e_key = key;
	entry->e_value = value;
	entry->e_reusable = reusable;
	head = mb_cache_entry_head(cache, key);
	hlist_bl_lock(head);
	hlist_bl_for_each_entry(dup, dup_node, head, e_hash_list) {
		if (dup->e_key == key && dup->e_value == value) {
			hlist_bl_unlock(head);
			kmem_cache_free(mb_entry_cache, entry);
			return -EBUSY;
		}
	}
	hlist_bl_add_head(&entry->e_hash_list, head);
	hlist_bl_unlock(head);

	spin_lock(&cache->c_list_lock);
	list_add_tail(&entry->e_list, &cache->c_list);
	/* Grab ref for LRU list */
	atomic_inc(&entry->e_refcnt);
	cache->c_entry_count++;
	spin_unlock(&cache->c_list_lock);

	return 0;
}
EXPORT_SYMBOL(mb_cache_entry_create);

void __mb_cache_entry_free(struct mb_cache_entry *entry)
{
	spin_lock(&mb_cache_spinlock);
	__mb_cache_entry_release_unlock(ce);
	__mb_cache_entry_release(ce);
	kmem_cache_free(mb_entry_cache, entry);
}
EXPORT_SYMBOL(__mb_cache_entry_free);

static struct mb_cache_entry *__entry_find(struct mb_cache *cache,
					   struct mb_cache_entry *entry,
					   u32 key)
{
	struct mb_cache_entry *old_entry = entry;
	struct hlist_bl_node *node;
	struct hlist_bl_head *head;

	head = mb_cache_entry_head(cache, key);
	hlist_bl_lock(head);
	if (entry && !hlist_bl_unhashed(&entry->e_hash_list))
		node = entry->e_hash_list.next;
	else
		node = hlist_bl_first(head);
	while (node) {
		entry = hlist_bl_entry(node, struct mb_cache_entry,
				       e_hash_list);
		if (entry->e_key == key && entry->e_reusable) {
			atomic_inc(&entry->e_refcnt);
			goto out;
		}
		node = node->next;
	}
	entry = NULL;
out:
	hlist_bl_unlock(head);
	if (old_entry)
		mb_cache_entry_put(cache, old_entry);

	return entry;
}

/*
 * mb_cache_entry_find_first - find the first reusable entry with the given key
 * @cache: cache where we should search
 * @key: key to look for
 *
 * This is equivalent to the sequence mb_cache_entry_takeout() --
 * mb_cache_entry_release().
 * Search in @cache for a reusable entry with key @key. Grabs reference to the
 * first reusable entry found and returns the entry.
 */
struct mb_cache_entry *mb_cache_entry_find_first(struct mb_cache *cache,
						 u32 key)
{
	spin_lock(&mb_cache_spinlock);
	mb_assert(list_empty(&ce->e_lru_list));
	__mb_cache_entry_unhash(ce);
	__mb_cache_entry_release_unlock(ce);
	mb_assert(ce);
	mb_assert(list_empty(&ce->e_lru_list));
	hlist_bl_lock(ce->e_index_hash_p);
	__mb_cache_entry_unhash_index(ce);
	hlist_bl_unlock(ce->e_index_hash_p);
	hlist_bl_lock(ce->e_block_hash_p);
	__mb_cache_entry_unhash_block(ce);
	hlist_bl_unlock(ce->e_block_hash_p);
	__mb_cache_entry_release(ce);
	return __entry_find(cache, NULL, key);
}
EXPORT_SYMBOL(mb_cache_entry_find_first);

/*
 * mb_cache_entry_find_next - find next reusable entry with the same key
 * @cache: cache where we should search
 * @entry: entry to start search from
 *
 * Finds next reusable entry in the hash chain which has the same key as @entry.
 * If @entry is unhashed (which can happen when deletion of entry races with the
 * search), finds the first reusable entry in the hash chain. The function drops
 * reference to @entry and returns with a reference to the found entry.
 */
struct mb_cache_entry *mb_cache_entry_find_next(struct mb_cache *cache,
						struct mb_cache_entry *entry)
{
	unsigned int bucket;
	struct list_head *l;
	struct mb_cache_entry *ce;

	bucket = hash_long((unsigned long)bdev + (block & 0xffffffff),
			   cache->c_bucket_bits);
	spin_lock(&mb_cache_spinlock);
	list_for_each(l, &cache->c_block_hash[bucket]) {
		ce = list_entry(l, struct mb_cache_entry, e_block_list);
		if (ce->e_bdev == bdev && ce->e_block == block) {
			DEFINE_WAIT(wait);

			if (!list_empty(&ce->e_lru_list))
				list_del_init(&ce->e_lru_list);

			while (ce->e_used > 0) {
				ce->e_queued++;
				prepare_to_wait(&mb_cache_queue, &wait,
						TASK_UNINTERRUPTIBLE);
				spin_unlock(&mb_cache_spinlock);
				schedule();
				spin_lock(&mb_cache_spinlock);
				ce->e_queued--;
			}
			finish_wait(&mb_cache_queue, &wait);
			ce->e_used += 1 + MB_CACHE_WRITER;

			if (!__mb_cache_entry_is_hashed(ce)) {
				__mb_cache_entry_release_unlock(ce);
				return NULL;
			}
			goto cleanup;
		}
	}
	ce = NULL;

cleanup:
	spin_unlock(&mb_cache_spinlock);
	return ce;
	struct hlist_bl_node *l;
	struct mb_cache_entry *ce;
	struct hlist_bl_head *block_hash_p;
	return __entry_find(cache, entry, entry->e_key);
}
EXPORT_SYMBOL(mb_cache_entry_find_next);

/*
 * mb_cache_entry_get - get a cache entry by value (and key)
 * @cache - cache we work with
 * @key - key
 * @value - value
 */
struct mb_cache_entry *mb_cache_entry_get(struct mb_cache *cache, u32 key,
					  u64 value)
{
	struct hlist_bl_node *node;
	struct hlist_bl_head *head;
	struct mb_cache_entry *entry;

	head = mb_cache_entry_head(cache, key);
	hlist_bl_lock(head);
	hlist_bl_for_each_entry(entry, node, head, e_hash_list) {
		if (entry->e_key == key && entry->e_value == value) {
			atomic_inc(&entry->e_refcnt);
			goto out;
		}
	}
	entry = NULL;
out:
	hlist_bl_unlock(head);
	return entry;
}
EXPORT_SYMBOL(mb_cache_entry_get);

#if !defined(MB_CACHE_INDEXES_COUNT) || (MB_CACHE_INDEXES_COUNT > 0)

static struct mb_cache_entry *
__mb_cache_entry_find(struct list_head *l, struct list_head *head,
		      int index, struct block_device *bdev, unsigned int key)
{
	while (l != head) {
		struct mb_cache_entry *ce =
			list_entry(l, struct mb_cache_entry,
			           e_indexes[index].o_list);
		if (ce->e_bdev == bdev && ce->e_indexes[index].o_key == key) {
			DEFINE_WAIT(wait);

			if (!list_empty(&ce->e_lru_list))
				list_del_init(&ce->e_lru_list);

			/* Incrementing before holding the lock gives readers
			   priority over writers. */
			ce->e_used++;
			while (ce->e_used >= MB_CACHE_WRITER) {
				ce->e_queued++;
				prepare_to_wait(&mb_cache_queue, &wait,
						TASK_UNINTERRUPTIBLE);
				spin_unlock(&mb_cache_spinlock);
				schedule();
				spin_lock(&mb_cache_spinlock);
				ce->e_queued--;
			}
			finish_wait(&mb_cache_queue, &wait);

			if (!__mb_cache_entry_is_hashed(ce)) {
				__mb_cache_entry_release_unlock(ce);
				spin_lock(&mb_cache_spinlock);
__mb_cache_entry_find(struct hlist_bl_node *l, struct hlist_bl_head *head,
		      struct block_device *bdev, unsigned int key)
/* mb_cache_entry_delete - remove a cache entry
 * @cache - cache we work with
 * @key - key
 * @value - value
 *
 * Remove entry from cache @cache with key @key and value @value.
 */
void mb_cache_entry_delete(struct mb_cache *cache, u32 key, u64 value)
{
	struct hlist_bl_node *node;
	struct hlist_bl_head *head;
	struct mb_cache_entry *entry;

	head = mb_cache_entry_head(cache, key);
	hlist_bl_lock(head);
	hlist_bl_for_each_entry(entry, node, head, e_hash_list) {
		if (entry->e_key == key && entry->e_value == value) {
			/* We keep hash list reference to keep entry alive */
			hlist_bl_del_init(&entry->e_hash_list);
			hlist_bl_unlock(head);
			spin_lock(&cache->c_list_lock);
			if (!list_empty(&entry->e_list)) {
				list_del_init(&entry->e_list);
				cache->c_entry_count--;
				atomic_dec(&entry->e_refcnt);
			}
			spin_unlock(&cache->c_list_lock);
			mb_cache_entry_put(cache, entry);
			return;
		}
	}
	hlist_bl_unlock(head);
}
EXPORT_SYMBOL(mb_cache_entry_delete);

/* mb_cache_entry_touch - cache entry got used
 * @cache - cache the entry belongs to
 * @entry - entry that got used
 *
 * Marks entry as used to give hit higher chances of surviving in cache.
 */
void mb_cache_entry_touch(struct mb_cache *cache,
			  struct mb_cache_entry *entry)
{
	entry->e_referenced = 1;
}
EXPORT_SYMBOL(mb_cache_entry_touch);

static unsigned long mb_cache_count(struct shrinker *shrink,
				    struct shrink_control *sc)
{
	struct mb_cache *cache = container_of(shrink, struct mb_cache,
					      c_shrink);

	return cache->c_entry_count;
}

/* Shrink number of entries in cache */
static unsigned long mb_cache_shrink(struct mb_cache *cache,
				     unsigned long nr_to_scan)
{
	struct mb_cache_entry *entry;
	struct hlist_bl_head *head;
	unsigned long shrunk = 0;

	spin_lock(&cache->c_list_lock);
	while (nr_to_scan-- && !list_empty(&cache->c_list)) {
		entry = list_first_entry(&cache->c_list,
					 struct mb_cache_entry, e_list);
		if (entry->e_referenced) {
			entry->e_referenced = 0;
			list_move_tail(&entry->e_list, &cache->c_list);
			continue;
		}
		list_del_init(&entry->e_list);
		cache->c_entry_count--;
		/*
		 * We keep LRU list reference so that entry doesn't go away
		 * from under us.
		 */
		spin_unlock(&cache->c_list_lock);
		head = mb_cache_entry_head(cache, entry->e_key);
		hlist_bl_lock(head);
		if (!hlist_bl_unhashed(&entry->e_hash_list)) {
			hlist_bl_del_init(&entry->e_hash_list);
			atomic_dec(&entry->e_refcnt);
		}
		hlist_bl_unlock(head);
		if (mb_cache_entry_put(cache, entry))
			shrunk++;
		cond_resched();
		spin_lock(&cache->c_list_lock);
	}
	spin_unlock(&cache->c_list_lock);

	return shrunk;
}

static unsigned long mb_cache_scan(struct shrinker *shrink,
				   struct shrink_control *sc)
{
	struct mb_cache *cache = container_of(shrink, struct mb_cache,
					      c_shrink);
	return mb_cache_shrink(cache, sc->nr_to_scan);
}

/* We shrink 1/X of the cache when we have too many entries in it */
#define SHRINK_DIVISOR 16

static void mb_cache_shrink_worker(struct work_struct *work)
{
	struct mb_cache *cache = container_of(work, struct mb_cache,
					      c_shrink_work);
	mb_cache_shrink(cache, cache->c_max_entries / SHRINK_DIVISOR);
}

/*
 * mb_cache_create - create cache
 * @bucket_bits: log2 of the hash table size
 *
 * Create cache for keys with 2^bucket_bits hash entries.
 */
struct mb_cache *mb_cache_create(int bucket_bits)
{
	struct mb_cache *cache;
	unsigned long bucket_count = 1UL << bucket_bits;
	unsigned long i;

	cache = kzalloc(sizeof(struct mb_cache), GFP_KERNEL);
	if (!cache)
		goto err_out;
	cache->c_bucket_bits = bucket_bits;
	cache->c_max_entries = bucket_count << 4;
	INIT_LIST_HEAD(&cache->c_list);
	spin_lock_init(&cache->c_list_lock);
	cache->c_hash = kmalloc(bucket_count * sizeof(struct hlist_bl_head),
				GFP_KERNEL);
	if (!cache->c_hash) {
		kfree(cache);
		goto err_out;
	}
	for (i = 0; i < bucket_count; i++)
		INIT_HLIST_BL_HEAD(&cache->c_hash[i]);

	cache->c_shrink.count_objects = mb_cache_count;
	cache->c_shrink.scan_objects = mb_cache_scan;
	cache->c_shrink.seeks = DEFAULT_SEEKS;
	if (register_shrinker(&cache->c_shrink)) {
		kfree(cache->c_hash);
		kfree(cache);
		goto err_out;
	}

	INIT_WORK(&cache->c_shrink_work, mb_cache_shrink_worker);

	return cache;

err_out:
	return NULL;
}
EXPORT_SYMBOL(mb_cache_create);

/*
 * mb_cache_destroy - destroy cache
 * @cache: the cache to destroy
 *
 * Find the first cache entry on a given device with a certain key in
 * an additional index. Additonal matches can be found with
 * an additional index. Additional matches can be found with
 * mb_cache_entry_find_next(). Returns NULL if no match was found. The
 * returned cache entry is locked for shared access ("multiple readers").
 *
 * @cache: the cache to search
 * @index: the number of the additonal index to search (0<=index<indexes_count)
 * @bdev: the device the cache entry should belong to
 * @key: the key in the index
 */
struct mb_cache_entry *
mb_cache_entry_find_first(struct mb_cache *cache, int index,
			  struct block_device *bdev, unsigned int key)
{
	unsigned int bucket = hash_long(key, cache->c_bucket_bits);
	struct list_head *l;
	struct mb_cache_entry *ce;

	mb_assert(index < mb_cache_indexes(cache));
	spin_lock(&mb_cache_spinlock);
	l = cache->c_indexes_hash[index][bucket].next;
	ce = __mb_cache_entry_find(l, &cache->c_indexes_hash[index][bucket],
	                           index, bdev, key);
	spin_unlock(&mb_cache_spinlock);
mb_cache_entry_find_first(struct mb_cache *cache, struct block_device *bdev,
			  unsigned int key)
 * Free all entries in cache and cache itself. Caller must make sure nobody
 * (except shrinker) can reach @cache when calling this.
 */
void mb_cache_destroy(struct mb_cache *cache)
{
	struct mb_cache_entry *entry, *next;

	unregister_shrinker(&cache->c_shrink);

	/*
	 * We don't bother with any locking. Cache must not be used at this
	 * point.
	 */
	list_for_each_entry_safe(entry, next, &cache->c_list, e_list) {
		if (!hlist_bl_unhashed(&entry->e_hash_list)) {
			hlist_bl_del_init(&entry->e_hash_list);
			atomic_dec(&entry->e_refcnt);
		} else
			WARN_ON(1);
		list_del(&entry->e_list);
		WARN_ON(atomic_read(&entry->e_refcnt) != 1);
		mb_cache_entry_put(cache, entry);
	}
	kfree(cache->c_hash);
	kfree(cache);
}
EXPORT_SYMBOL(mb_cache_destroy);


/*
 * mb_cache_entry_find_next()
 *
 * Find the next cache entry on a given device with a certain key in an
 * additional index. Returns NULL if no match could be found. The previous
 * entry is atomatically released, so that mb_cache_entry_find_next() can
 * be called like this:
 *
 * entry = mb_cache_entry_find_first();
 * while (entry) {
 * 	...
 *	entry = mb_cache_entry_find_next(entry, ...);
 * }
 *
 * @prev: The previous match
 * @index: the number of the additonal index to search (0<=index<indexes_count)
 * @bdev: the device the cache entry should belong to
 * @key: the key in the index
 */
struct mb_cache_entry *
mb_cache_entry_find_next(struct mb_cache_entry *prev, int index,
mb_cache_entry_find_next(struct mb_cache_entry *prev,
			 struct block_device *bdev, unsigned int key)
{
	struct mb_cache *cache = prev->e_cache;
	unsigned int bucket = hash_long(key, cache->c_bucket_bits);
	struct list_head *l;
	struct mb_cache_entry *ce;

	mb_assert(index < mb_cache_indexes(cache));
	spin_lock(&mb_cache_spinlock);
	l = prev->e_indexes[index].o_list.next;
	ce = __mb_cache_entry_find(l, &cache->c_indexes_hash[index][bucket],
	                           index, bdev, key);
	__mb_cache_entry_release_unlock(prev);
	struct hlist_bl_node *l;
	struct mb_cache_entry *ce;
	struct hlist_bl_head *index_hash_p;

	index_hash_p = &cache->c_index_hash[bucket];
	mb_assert(prev->e_index_hash_p == index_hash_p);
	hlist_bl_lock(index_hash_p);
	mb_assert(!hlist_bl_empty(index_hash_p));
	l = prev->e_index.o_list.next;
	ce = __mb_cache_entry_find(l, index_hash_p, bdev, key);
	__mb_cache_entry_release(prev);
	return ce;
}

#endif  /* !defined(MB_CACHE_INDEXES_COUNT) || (MB_CACHE_INDEXES_COUNT > 0) */

static int __init init_mbcache(void)
{
	register_shrinker(&mb_cache_shrinker);
static int __init mbcache_init(void)
{
	mb_entry_cache = kmem_cache_create("mbcache",
				sizeof(struct mb_cache_entry), 0,
				SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD, NULL);
	if (!mb_entry_cache)
		return -ENOMEM;
	return 0;
}

static void __exit mbcache_exit(void)
{
	kmem_cache_destroy(mb_entry_cache);
}

module_init(mbcache_init)
module_exit(mbcache_exit)

MODULE_AUTHOR("Jan Kara <jack@suse.cz>");
MODULE_DESCRIPTION("Meta block cache (for extended attributes)");
MODULE_LICENSE("GPL");
