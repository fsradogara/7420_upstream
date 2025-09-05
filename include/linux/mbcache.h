/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MBCACHE_H
#define _LINUX_MBCACHE_H

#include <linux/hash.h>
#include <linux/list_bl.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/fs.h>

struct mb_cache;

  (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

/* Hardwire the number of additional indexes */
#define MB_CACHE_INDEXES_COUNT 1

struct mb_cache_entry {
	struct list_head		e_lru_list;
	struct mb_cache			*e_cache;
	unsigned short			e_used;
	unsigned short			e_queued;
	struct block_device		*e_bdev;
	sector_t			e_block;
	struct list_head		e_block_list;
	struct {
		struct list_head	o_list;
		unsigned int		o_key;
	} e_indexes[0];
};

struct mb_cache_op {
	int (*free)(struct mb_cache_entry *, gfp_t);
	atomic_t			e_refcnt;
	struct block_device		*e_bdev;
	sector_t			e_block;
	struct hlist_bl_node		e_block_list;
	struct {
		struct hlist_bl_node	o_list;
		unsigned int		o_key;
	} e_index;
	struct hlist_bl_head		*e_block_hash_p;
	struct hlist_bl_head		*e_index_hash_p;
struct mb_cache_entry {
	/* List of entries in cache - protected by cache->c_list_lock */
	struct list_head	e_list;
	/* Hash table list - protected by hash chain bitlock */
	struct hlist_bl_node	e_hash_list;
	atomic_t		e_refcnt;
	/* Key in hash - stable during lifetime of the entry */
	u32			e_key;
	u32			e_referenced:1;
	u32			e_reusable:1;
	/* User provided value - stable during lifetime of the entry */
	u64			e_value;
};

struct mb_cache *mb_cache_create(int bucket_bits);
void mb_cache_destroy(struct mb_cache *cache);

int mb_cache_entry_create(struct mb_cache *cache, gfp_t mask, u32 key,
			  u64 value, bool reusable);
void __mb_cache_entry_free(struct mb_cache_entry *entry);
static inline int mb_cache_entry_put(struct mb_cache *cache,
				     struct mb_cache_entry *entry)
{
	if (!atomic_dec_and_test(&entry->e_refcnt))
		return 0;
	__mb_cache_entry_free(entry);
	return 1;
}

struct mb_cache * mb_cache_create(const char *, struct mb_cache_op *, size_t,
				  int, int);
struct mb_cache *mb_cache_create(const char *, int);
void mb_cache_shrink(struct block_device *);
void mb_cache_destroy(struct mb_cache *);

/* Functions on cache entries */

struct mb_cache_entry *mb_cache_entry_alloc(struct mb_cache *, gfp_t);
int mb_cache_entry_insert(struct mb_cache_entry *, struct block_device *,
			  sector_t, unsigned int[]);
			  sector_t, unsigned int);
void mb_cache_entry_release(struct mb_cache_entry *);
void mb_cache_entry_free(struct mb_cache_entry *);
struct mb_cache_entry *mb_cache_entry_get(struct mb_cache *,
					  struct block_device *,
					  sector_t);
#if !defined(MB_CACHE_INDEXES_COUNT) || (MB_CACHE_INDEXES_COUNT > 0)
struct mb_cache_entry *mb_cache_entry_find_first(struct mb_cache *cache, int,
						 struct block_device *, 
						 unsigned int);
struct mb_cache_entry *mb_cache_entry_find_next(struct mb_cache_entry *, int,
						struct block_device *, 
						unsigned int);
#endif
void mb_cache_entry_delete(struct mb_cache *cache, u32 key, u64 value);
struct mb_cache_entry *mb_cache_entry_get(struct mb_cache *cache, u32 key,
					  u64 value);
struct mb_cache_entry *mb_cache_entry_find_first(struct mb_cache *cache,
						 u32 key);
struct mb_cache_entry *mb_cache_entry_find_next(struct mb_cache *cache,
						struct mb_cache_entry *entry);
void mb_cache_entry_touch(struct mb_cache *cache,
			  struct mb_cache_entry *entry);

#endif	/* _LINUX_MBCACHE_H */
