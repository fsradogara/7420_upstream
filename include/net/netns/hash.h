/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_NS_HASH_H__
#define __NET_NS_HASH_H__

#include <asm/cache.h>

struct net;

static inline unsigned net_hash_mix(struct net *net)
static inline u32 net_hash_mix(const struct net *net)
{
#ifdef CONFIG_NET_NS
	/*
	 * shift this right to eliminate bits, that are
	 * always zeroed
	 */

	return (unsigned)(((unsigned long)net) >> L1_CACHE_SHIFT);
	return (u32)(((unsigned long)net) >> L1_CACHE_SHIFT);
	return (u32)(((unsigned long)net) >> ilog2(sizeof(*net)));
#else
	return 0;
#endif
}
#endif
