/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/nfs/iostat.h
 *
 *  Declarations for NFS client per-mount statistics
 *
 *  Copyright (C) 2005, 2006 Chuck Lever <cel@netapp.com>
 *
 */

#ifndef _NFS_IOSTAT
#define _NFS_IOSTAT

#include <linux/percpu.h>
#include <linux/cache.h>
#include <linux/nfs_iostat.h>

struct nfs_iostats {
	unsigned long long	bytes[__NFSIOS_BYTESMAX];
#ifdef CONFIG_NFS_FSCACHE
	unsigned long long	fscache[__NFSIOS_FSCACHEMAX];
#endif
	unsigned long		events[__NFSIOS_COUNTSMAX];
} ____cacheline_aligned;

static inline void nfs_inc_server_stats(const struct nfs_server *server,
					enum nfs_stat_eventcounters stat)
{
	struct nfs_iostats *iostats;
	int cpu;

	cpu = get_cpu();
	iostats = per_cpu_ptr(server->io_stats, cpu);
	iostats->events[stat]++;
	put_cpu_no_resched();
	this_cpu_inc(server->io_stats->events[stat]);
}

static inline void nfs_inc_stats(const struct inode *inode,
				 enum nfs_stat_eventcounters stat)
{
	nfs_inc_server_stats(NFS_SERVER(inode), stat);
}

static inline void nfs_add_server_stats(const struct nfs_server *server,
					enum nfs_stat_bytecounters stat,
					unsigned long addend)
{
	struct nfs_iostats *iostats;
	int cpu;

	cpu = get_cpu();
	iostats = per_cpu_ptr(server->io_stats, cpu);
	iostats->bytes[stat] += addend;
	put_cpu_no_resched();
					long addend)
{
	this_cpu_add(server->io_stats->bytes[stat], addend);
}

static inline void nfs_add_stats(const struct inode *inode,
				 enum nfs_stat_bytecounters stat,
				 unsigned long addend)
				 long addend)
{
	nfs_add_server_stats(NFS_SERVER(inode), stat, addend);
}

static inline struct nfs_iostats *nfs_alloc_iostats(void)
#ifdef CONFIG_NFS_FSCACHE
static inline void nfs_add_fscache_stats(struct inode *inode,
					 enum nfs_stat_fscachecounters stat,
					 long addend)
{
	this_cpu_add(NFS_SERVER(inode)->io_stats->fscache[stat], addend);
}
static inline void nfs_inc_fscache_stats(struct inode *inode,
					 enum nfs_stat_fscachecounters stat)
{
	this_cpu_inc(NFS_SERVER(inode)->io_stats->fscache[stat]);
}
#endif

static inline struct nfs_iostats __percpu *nfs_alloc_iostats(void)
{
	return alloc_percpu(struct nfs_iostats);
}

static inline void nfs_free_iostats(struct nfs_iostats *stats)
static inline void nfs_free_iostats(struct nfs_iostats __percpu *stats)
{
	if (stats != NULL)
		free_percpu(stats);
}

#endif /* _NFS_IOSTAT */
