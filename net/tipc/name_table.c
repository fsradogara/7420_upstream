/*
 * net/tipc/name_table.c: TIPC name table code
 *
 * Copyright (c) 2000-2006, Ericsson AB
 * Copyright (c) 2004-2008, Wind River Systems
 * Copyright (c) 2000-2006, 2014-2015, Ericsson AB
 * Copyright (c) 2004-2008, 2010-2014, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "core.h"
#include "config.h"
#include "dbg.h"
#include "name_table.h"
#include "name_distr.h"
#include "addr.h"
#include "node_subscr.h"
#include "subscr.h"
#include "port.h"
#include "cluster.h"
#include "bcast.h"

static int tipc_nametbl_size = 1024;		/* must be a power of 2 */

/**
 * struct sub_seq - container for all published instances of a name sequence
 * @lower: name sequence lower bound
 * @upper: name sequence upper bound
#include <net/sock.h>
#include "core.h"
#include "netlink.h"
#include "name_table.h"
#include "name_distr.h"
#include "subscr.h"
#include "bcast.h"
#include "addr.h"
#include "node.h"
#include <net/genetlink.h>

#define TIPC_NAMETBL_SIZE 1024		/* must be a power of 2 */

/**
 * struct name_info - name sequence publication info
 * @node_list: circular list of publications made by own node
 * @cluster_list: circular list of publications made by own cluster
 * @zone_list: circular list of publications made by own zone
 * @node_list_size: number of entries in "node_list"
 * @cluster_list_size: number of entries in "cluster_list"
 * @zone_list_size: number of entries in "zone_list"
 *
 * Note: The zone list always contains at least one entry, since all
 *       publications of the associated name sequence belong to it.
 *       (The cluster and node lists may be empty.)
 */

struct sub_seq {
	u32 lower;
	u32 upper;
	struct publication *node_list;
	struct publication *cluster_list;
	struct publication *zone_list;
struct name_info {
	struct list_head node_list;
	struct list_head cluster_list;
	struct list_head zone_list;
	u32 node_list_size;
	u32 cluster_list_size;
	u32 zone_list_size;
};

/**
 * struct sub_seq - container for all published instances of a name sequence
 * @lower: name sequence lower bound
 * @upper: name sequence upper bound
 * @info: pointer to name sequence publication info
 */
struct sub_seq {
	u32 lower;
	u32 upper;
	struct name_info *info;
};

/**
 * struct name_seq - container for all published instances of a name type
 * @type: 32 bit 'type' value for name sequence
 * @sseq: pointer to dynamically-sized array of sub-sequences of this 'type';
 *        sub-sequences are sorted in ascending order
 * @alloc: number of sub-sequences currently in array
 * @first_free: array index of first unused sub-sequence entry
 * @ns_list: links to adjacent name sequences in hash chain
 * @subscriptions: list of subscriptions for this 'type'
 * @lock: spinlock controlling access to publication lists of all sub-sequences
 */

 * @rcu: RCU callback head used for deferred freeing
 */
struct name_seq {
	u32 type;
	struct sub_seq *sseqs;
	u32 alloc;
	u32 first_free;
	struct hlist_node ns_list;
	struct list_head subscriptions;
	spinlock_t lock;
};

/**
 * struct name_table - table containing all existing port name publications
 * @types: pointer to fixed-sized array of name sequence lists,
 *         accessed via hashing on 'type'; name sequence lists are *not* sorted
 * @local_publ_count: number of publications issued by this node
 */

struct name_table {
	struct hlist_head *types;
	u32 local_publ_count;
};

static struct name_table table = { NULL } ;
static atomic_t rsv_publ_ok = ATOMIC_INIT(0);
DEFINE_RWLOCK(tipc_nametbl_lock);


static int hash(int x)
{
	return(x & (tipc_nametbl_size - 1));
	struct rcu_head rcu;
};

static int hash(int x)
{
	return x & (TIPC_NAMETBL_SIZE - 1);
}

/**
 * publ_create - create a publication structure
 */

static struct publication *publ_create(u32 type, u32 lower, u32 upper,
				       u32 scope, u32 node, u32 port_ref,
				       u32 key)
{
	struct publication *publ = kzalloc(sizeof(*publ), GFP_ATOMIC);
	if (publ == NULL) {
		warn("Publication creation failure, no memory\n");
		pr_warn("Publication creation failure, no memory\n");
		return NULL;
	}

	publ->type = type;
	publ->lower = lower;
	publ->upper = upper;
	publ->scope = scope;
	publ->node = node;
	publ->ref = port_ref;
	publ->key = key;
	INIT_LIST_HEAD(&publ->local_list);
	INIT_LIST_HEAD(&publ->pport_list);
	INIT_LIST_HEAD(&publ->subscr.nodesub_list);
	INIT_LIST_HEAD(&publ->pport_list);
	return publ;
}

/**
 * tipc_subseq_alloc - allocate a specified number of sub-sequence structures
 */

static struct sub_seq *tipc_subseq_alloc(u32 cnt)
{
	struct sub_seq *sseq = kcalloc(cnt, sizeof(struct sub_seq), GFP_ATOMIC);
	return sseq;
static struct sub_seq *tipc_subseq_alloc(u32 cnt)
{
	return kcalloc(cnt, sizeof(struct sub_seq), GFP_ATOMIC);
}

/**
 * tipc_nameseq_create - create a name sequence structure for the specified 'type'
 *
 * Allocates a single sub-sequence structure and sets it to all 0's.
 */

static struct name_seq *tipc_nameseq_create(u32 type, struct hlist_head *seq_head)
{
	struct name_seq *nseq = kzalloc(sizeof(*nseq), GFP_ATOMIC);
	struct sub_seq *sseq = tipc_subseq_alloc(1);

	if (!nseq || !sseq) {
		warn("Name sequence creation failed, no memory\n");
		pr_warn("Name sequence creation failed, no memory\n");
		kfree(nseq);
		kfree(sseq);
		return NULL;
	}

	spin_lock_init(&nseq->lock);
	nseq->type = type;
	nseq->sseqs = sseq;
	dbg("tipc_nameseq_create(): nseq = %p, type %u, ssseqs %p, ff: %u\n",
	    nseq, type, nseq->sseqs, nseq->first_free);
	nseq->alloc = 1;
	INIT_HLIST_NODE(&nseq->ns_list);
	INIT_LIST_HEAD(&nseq->subscriptions);
	hlist_add_head(&nseq->ns_list, seq_head);
	nseq->alloc = 1;
	INIT_HLIST_NODE(&nseq->ns_list);
	INIT_LIST_HEAD(&nseq->subscriptions);
	hlist_add_head_rcu(&nseq->ns_list, seq_head);
	return nseq;
}

/**
 * nameseq_find_subseq - find sub-sequence (if any) matching a name instance
 *
 * Very time-critical, so binary searches through sub-sequence array.
 */

static struct sub_seq *nameseq_find_subseq(struct name_seq *nseq,
					   u32 instance)
{
	struct sub_seq *sseqs = nseq->sseqs;
	int low = 0;
	int high = nseq->first_free - 1;
	int mid;

	while (low <= high) {
		mid = (low + high) / 2;
		if (instance < sseqs[mid].lower)
			high = mid - 1;
		else if (instance > sseqs[mid].upper)
			low = mid + 1;
		else
			return &sseqs[mid];
	}
	return NULL;
}

/**
 * nameseq_locate_subseq - determine position of name instance in sub-sequence
 *
 * Returns index in sub-sequence array of the entry that contains the specified
 * instance value; if no entry contains that value, returns the position
 * where a new entry for it would be inserted in the array.
 *
 * Note: Similar to binary search code for locating a sub-sequence.
 */

static u32 nameseq_locate_subseq(struct name_seq *nseq, u32 instance)
{
	struct sub_seq *sseqs = nseq->sseqs;
	int low = 0;
	int high = nseq->first_free - 1;
	int mid;

	while (low <= high) {
		mid = (low + high) / 2;
		if (instance < sseqs[mid].lower)
			high = mid - 1;
		else if (instance > sseqs[mid].upper)
			low = mid + 1;
		else
			return mid;
	}
	return low;
}

/**
 * tipc_nameseq_insert_publ -
 */

static struct publication *tipc_nameseq_insert_publ(struct name_seq *nseq,
						    u32 type, u32 lower, u32 upper,
						    u32 scope, u32 node, u32 port, u32 key)
{
	struct subscription *s;
	struct subscription *st;
	struct publication *publ;
	struct sub_seq *sseq;
	int created_subseq = 0;

	sseq = nameseq_find_subseq(nseq, lower);
	dbg("nameseq_ins: for seq %p, {%u,%u}, found sseq %p\n",
	    nseq, type, lower, sseq);
	if (sseq) {

		/* Lower end overlaps existing entry => need an exact match */

		if ((sseq->lower != lower) || (sseq->upper != upper)) {
			warn("Cannot publish {%u,%u,%u}, overlap error\n",
			     type, lower, upper);
			return NULL;
		}
 * tipc_nameseq_insert_publ
 */
static struct publication *tipc_nameseq_insert_publ(struct net *net,
						    struct name_seq *nseq,
						    u32 type, u32 lower,
						    u32 upper, u32 scope,
						    u32 node, u32 port, u32 key)
{
	struct tipc_subscription *s;
	struct tipc_subscription *st;
	struct publication *publ;
	struct sub_seq *sseq;
	struct name_info *info;
	int created_subseq = 0;

	sseq = nameseq_find_subseq(nseq, lower);
	if (sseq) {

		/* Lower end overlaps existing entry => need an exact match */
		if ((sseq->lower != lower) || (sseq->upper != upper)) {
			return NULL;
		}

		info = sseq->info;

		/* Check if an identical publication already exists */
		list_for_each_entry(publ, &info->zone_list, zone_list) {
			if ((publ->ref == port) && (publ->key == key) &&
			    (!publ->node || (publ->node == node)))
				return NULL;
		}
	} else {
		u32 inspos;
		struct sub_seq *freesseq;

		/* Find where lower end should be inserted */

		inspos = nameseq_locate_subseq(nseq, lower);

		/* Fail if upper end overlaps into an existing entry */

		if ((inspos < nseq->first_free) &&
		    (upper >= nseq->sseqs[inspos].lower)) {
			warn("Cannot publish {%u,%u,%u}, overlap error\n",
			     type, lower, upper);
		inspos = nameseq_locate_subseq(nseq, lower);

		/* Fail if upper end overlaps into an existing entry */
		if ((inspos < nseq->first_free) &&
		    (upper >= nseq->sseqs[inspos].lower)) {
			return NULL;
		}

		/* Ensure there is space for new sub-sequence */

		if (nseq->first_free == nseq->alloc) {
			struct sub_seq *sseqs = tipc_subseq_alloc(nseq->alloc * 2);

			if (!sseqs) {
				warn("Cannot publish {%u,%u,%u}, no memory\n",
				     type, lower, upper);
				return NULL;
			}
			dbg("Allocated %u more sseqs\n", nseq->alloc);
				pr_warn("Cannot publish {%u,%u,%u}, no memory\n",
					type, lower, upper);
				return NULL;
			}
			memcpy(sseqs, nseq->sseqs,
			       nseq->alloc * sizeof(struct sub_seq));
			kfree(nseq->sseqs);
			nseq->sseqs = sseqs;
			nseq->alloc *= 2;
		}
		dbg("Have %u sseqs for type %u\n", nseq->alloc, type);

		/* Insert new sub-sequence */

		dbg("ins in pos %u, ff = %u\n", inspos, nseq->first_free);
		sseq = &nseq->sseqs[inspos];
		freesseq = &nseq->sseqs[nseq->first_free];
		memmove(sseq + 1, sseq, (freesseq - sseq) * sizeof (*sseq));
		memset(sseq, 0, sizeof (*sseq));
		nseq->first_free++;
		sseq->lower = lower;
		sseq->upper = upper;
		created_subseq = 1;
	}
	dbg("inserting {%u,%u,%u} from <0x%x:%u> into sseq %p(%u,%u) of seq %p\n",
	    type, lower, upper, node, port, sseq,
	    sseq->lower, sseq->upper, nseq);

	/* Insert a publication: */

	publ = publ_create(type, lower, upper, scope, node, port, key);
	if (!publ)
		return NULL;
	dbg("inserting publ %p, node=0x%x publ->node=0x%x, subscr->node=%p\n",
	    publ, node, publ->node, publ->subscr.node);

	sseq->zone_list_size++;
	if (!sseq->zone_list)
		sseq->zone_list = publ->zone_list_next = publ;
	else {
		publ->zone_list_next = sseq->zone_list->zone_list_next;
		sseq->zone_list->zone_list_next = publ;
	}

	if (in_own_cluster(node)) {
		sseq->cluster_list_size++;
		if (!sseq->cluster_list)
			sseq->cluster_list = publ->cluster_list_next = publ;
		else {
			publ->cluster_list_next =
			sseq->cluster_list->cluster_list_next;
			sseq->cluster_list->cluster_list_next = publ;
		}
	}

	if (node == tipc_own_addr) {
		sseq->node_list_size++;
		if (!sseq->node_list)
			sseq->node_list = publ->node_list_next = publ;
		else {
			publ->node_list_next = sseq->node_list->node_list_next;
			sseq->node_list->node_list_next = publ;
		}
	}

	/*
	 * Any subscriptions waiting for notification?
	 */
	list_for_each_entry_safe(s, st, &nseq->subscriptions, nameseq_list) {
		dbg("calling report_overlap()\n");
		tipc_subscr_report_overlap(s,
					   publ->lower,
					   publ->upper,
					   TIPC_PUBLISHED,
					   publ->ref,
					   publ->node,
					   created_subseq);

		info = kzalloc(sizeof(*info), GFP_ATOMIC);
		if (!info) {
			pr_warn("Cannot publish {%u,%u,%u}, no memory\n",
				type, lower, upper);
			return NULL;
		}

		INIT_LIST_HEAD(&info->node_list);
		INIT_LIST_HEAD(&info->cluster_list);
		INIT_LIST_HEAD(&info->zone_list);

		/* Insert new sub-sequence */
		sseq = &nseq->sseqs[inspos];
		freesseq = &nseq->sseqs[nseq->first_free];
		memmove(sseq + 1, sseq, (freesseq - sseq) * sizeof(*sseq));
		memset(sseq, 0, sizeof(*sseq));
		nseq->first_free++;
		sseq->lower = lower;
		sseq->upper = upper;
		sseq->info = info;
		created_subseq = 1;
	}

	/* Insert a publication */
	publ = publ_create(type, lower, upper, scope, node, port, key);
	if (!publ)
		return NULL;

	list_add(&publ->zone_list, &info->zone_list);
	info->zone_list_size++;

	if (in_own_cluster(net, node)) {
		list_add(&publ->cluster_list, &info->cluster_list);
		info->cluster_list_size++;
	}

	if (in_own_node(net, node)) {
		list_add(&publ->node_list, &info->node_list);
		info->node_list_size++;
	}

	/* Any subscriptions waiting for notification?  */
	list_for_each_entry_safe(s, st, &nseq->subscriptions, nameseq_list) {
		tipc_subscrp_report_overlap(s, publ->lower, publ->upper,
					    TIPC_PUBLISHED, publ->ref,
					    publ->node, created_subseq);
	}
	return publ;
}

/**
 * tipc_nameseq_remove_publ -
 * tipc_nameseq_remove_publ
 *
 * NOTE: There may be cases where TIPC is asked to remove a publication
 * that is not in the name table.  For example, if another node issues a
 * publication for a name sequence that overlaps an existing name sequence
 * the publication will not be recorded, which means the publication won't
 * be found when the name sequence is later withdrawn by that node.
 * A failed withdraw request simply returns a failure indication and lets the
 * caller issue any error or warning messages associated with such a problem.
 */

static struct publication *tipc_nameseq_remove_publ(struct name_seq *nseq, u32 inst,
						    u32 node, u32 ref, u32 key)
{
	struct publication *publ;
	struct publication *curr;
	struct publication *prev;
	struct sub_seq *sseq = nameseq_find_subseq(nseq, inst);
	struct sub_seq *free;
	struct subscription *s, *st;
static struct publication *tipc_nameseq_remove_publ(struct net *net,
						    struct name_seq *nseq,
						    u32 inst, u32 node,
						    u32 ref, u32 key)
{
	struct publication *publ;
	struct sub_seq *sseq = nameseq_find_subseq(nseq, inst);
	struct name_info *info;
	struct sub_seq *free;
	struct tipc_subscription *s, *st;
	int removed_subseq = 0;

	if (!sseq)
		return NULL;

	dbg("tipc_nameseq_remove_publ: seq: %p, sseq %p, {%u,%u}, key %u\n",
	    nseq, sseq, nseq->type, inst, key);

	/* Remove publication from zone scope list */

	prev = sseq->zone_list;
	publ = sseq->zone_list->zone_list_next;
	while ((publ->key != key) || (publ->ref != ref) ||
	       (publ->node && (publ->node != node))) {
		prev = publ;
		publ = publ->zone_list_next;
		if (prev == sseq->zone_list) {

			/* Prevent endless loop if publication not found */

			return NULL;
		}
	}
	if (publ != sseq->zone_list)
		prev->zone_list_next = publ->zone_list_next;
	else if (publ->zone_list_next != publ) {
		prev->zone_list_next = publ->zone_list_next;
		sseq->zone_list = publ->zone_list_next;
	} else {
		sseq->zone_list = NULL;
	}
	sseq->zone_list_size--;

	/* Remove publication from cluster scope list, if present */

	if (in_own_cluster(node)) {
		prev = sseq->cluster_list;
		curr = sseq->cluster_list->cluster_list_next;
		while (curr != publ) {
			prev = curr;
			curr = curr->cluster_list_next;
			if (prev == sseq->cluster_list) {

				/* Prevent endless loop for malformed list */

				err("Unable to de-list cluster publication\n"
				    "{%u%u}, node=0x%x, ref=%u, key=%u)\n",
				    publ->type, publ->lower, publ->node,
				    publ->ref, publ->key);
				goto end_cluster;
			}
		}
		if (publ != sseq->cluster_list)
			prev->cluster_list_next = publ->cluster_list_next;
		else if (publ->cluster_list_next != publ) {
			prev->cluster_list_next = publ->cluster_list_next;
			sseq->cluster_list = publ->cluster_list_next;
		} else {
			sseq->cluster_list = NULL;
		}
		sseq->cluster_list_size--;
	}
end_cluster:

	/* Remove publication from node scope list, if present */

	if (node == tipc_own_addr) {
		prev = sseq->node_list;
		curr = sseq->node_list->node_list_next;
		while (curr != publ) {
			prev = curr;
			curr = curr->node_list_next;
			if (prev == sseq->node_list) {

				/* Prevent endless loop for malformed list */

				err("Unable to de-list node publication\n"
				    "{%u%u}, node=0x%x, ref=%u, key=%u)\n",
				    publ->type, publ->lower, publ->node,
				    publ->ref, publ->key);
				goto end_node;
			}
		}
		if (publ != sseq->node_list)
			prev->node_list_next = publ->node_list_next;
		else if (publ->node_list_next != publ) {
			prev->node_list_next = publ->node_list_next;
			sseq->node_list = publ->node_list_next;
		} else {
			sseq->node_list = NULL;
		}
		sseq->node_list_size--;
	}
end_node:

	/* Contract subseq list if no more publications for that subseq */

	if (!sseq->zone_list) {
		free = &nseq->sseqs[nseq->first_free--];
		memmove(sseq, sseq + 1, (free - (sseq + 1)) * sizeof (*sseq));
	info = sseq->info;

	/* Locate publication, if it exists */
	list_for_each_entry(publ, &info->zone_list, zone_list) {
		if ((publ->key == key) && (publ->ref == ref) &&
		    (!publ->node || (publ->node == node)))
			goto found;
	}
	return NULL;

found:
	/* Remove publication from zone scope list */
	list_del(&publ->zone_list);
	info->zone_list_size--;

	/* Remove publication from cluster scope list, if present */
	if (in_own_cluster(net, node)) {
		list_del(&publ->cluster_list);
		info->cluster_list_size--;
	}

	/* Remove publication from node scope list, if present */
	if (in_own_node(net, node)) {
		list_del(&publ->node_list);
		info->node_list_size--;
	}

	/* Contract subseq list if no more publications for that subseq */
	if (list_empty(&info->zone_list)) {
		kfree(info);
		free = &nseq->sseqs[nseq->first_free--];
		memmove(sseq, sseq + 1, (free - (sseq + 1)) * sizeof(*sseq));
		removed_subseq = 1;
	}

	/* Notify any waiting subscriptions */

	list_for_each_entry_safe(s, st, &nseq->subscriptions, nameseq_list) {
		tipc_subscr_report_overlap(s,
					   publ->lower,
					   publ->upper,
					   TIPC_WITHDRAWN,
					   publ->ref,
					   publ->node,
					   removed_subseq);
	list_for_each_entry_safe(s, st, &nseq->subscriptions, nameseq_list) {
		tipc_subscrp_report_overlap(s, publ->lower, publ->upper,
					    TIPC_WITHDRAWN, publ->ref,
					    publ->node, removed_subseq);
	}

	return publ;
}

/**
 * tipc_nameseq_subscribe: attach a subscription, and issue
 * the prescribed number of events if there is any sub-
 * sequence overlapping with the requested sequence
 */

static void tipc_nameseq_subscribe(struct name_seq *nseq, struct subscription *s)
 * tipc_nameseq_subscribe - attach a subscription, and issue
 * the prescribed number of events if there is any sub-
 * sequence overlapping with the requested sequence
 */
static void tipc_nameseq_subscribe(struct name_seq *nseq,
				   struct tipc_subscription *s)
{
	struct sub_seq *sseq = nseq->sseqs;
	struct tipc_name_seq ns;

	tipc_subscrp_convert_seq(&s->evt.s.seq, s->swap, &ns);

	tipc_subscrp_get(s);
	list_add(&s->nameseq_list, &nseq->subscriptions);

	if (!sseq)
		return;

	while (sseq != &nseq->sseqs[nseq->first_free]) {
		struct publication *zl = sseq->zone_list;
		if (zl && tipc_subscr_overlap(s,sseq->lower,sseq->upper)) {
			struct publication *crs = zl;
			int must_report = 1;

			do {
				tipc_subscr_report_overlap(s,
							   sseq->lower,
							   sseq->upper,
							   TIPC_PUBLISHED,
							   crs->ref,
							   crs->node,
							   must_report);
				must_report = 0;
				crs = crs->zone_list_next;
			} while (crs != zl);
		if (tipc_subscrp_check_overlap(s, sseq->lower, sseq->upper)) {
		if (tipc_subscrp_check_overlap(&ns, sseq->lower, sseq->upper)) {
			struct publication *crs;
			struct name_info *info = sseq->info;
			int must_report = 1;

			list_for_each_entry(crs, &info->zone_list, zone_list) {
				tipc_subscrp_report_overlap(s, sseq->lower,
							    sseq->upper,
							    TIPC_PUBLISHED,
							    crs->ref, crs->node,
							    must_report);
				must_report = 0;
			}
		}
		sseq++;
	}
}

static struct name_seq *nametbl_find_seq(u32 type)
{
	struct hlist_head *seq_head;
	struct hlist_node *seq_node;
	struct name_seq *ns;

	dbg("find_seq %u,(%u,0x%x) table = %p, hash[type] = %u\n",
	    type, ntohl(type), type, table.types, hash(type));

	seq_head = &table.types[hash(type)];
	hlist_for_each_entry(ns, seq_node, seq_head, ns_list) {
		if (ns->type == type) {
			dbg("found %p\n", ns);
			return ns;
		}
static struct name_seq *nametbl_find_seq(struct net *net, u32 type)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct hlist_head *seq_head;
	struct name_seq *ns;

	seq_head = &tn->nametbl->seq_hlist[hash(type)];
	hlist_for_each_entry_rcu(ns, seq_head, ns_list) {
		if (ns->type == type)
			return ns;
	}

	return NULL;
};

struct publication *tipc_nametbl_insert_publ(u32 type, u32 lower, u32 upper,
					     u32 scope, u32 node, u32 port, u32 key)
{
	struct name_seq *seq = nametbl_find_seq(type);

	dbg("tipc_nametbl_insert_publ: {%u,%u,%u} found %p\n", type, lower, upper, seq);
	if (lower > upper) {
		warn("Failed to publish illegal {%u,%u,%u}\n",
		     type, lower, upper);
		return NULL;
	}

	dbg("Publishing {%u,%u,%u} from 0x%x\n", type, lower, upper, node);
	if (!seq) {
		seq = tipc_nameseq_create(type, &table.types[hash(type)]);
		dbg("tipc_nametbl_insert_publ: created %p\n", seq);
	}
	if (!seq)
		return NULL;

	return tipc_nameseq_insert_publ(seq, type, lower, upper,
					scope, node, port, key);
}

struct publication *tipc_nametbl_remove_publ(u32 type, u32 lower,
					     u32 node, u32 ref, u32 key)
{
	struct publication *publ;
	struct name_seq *seq = nametbl_find_seq(type);

	if (!seq)
		return NULL;

	dbg("Withdrawing {%u,%u} from 0x%x\n", type, lower, node);
	publ = tipc_nameseq_remove_publ(seq, lower, node, ref, key);

	if (!seq->first_free && list_empty(&seq->subscriptions)) {
		hlist_del_init(&seq->ns_list);
		kfree(seq->sseqs);
		kfree(seq);
	}
	return publ;
}

/*
 * tipc_nametbl_translate(): Translate tipc_name -> tipc_portid.
 *                      Very time-critical.
 *
 * Note: on entry 'destnode' is the search domain used during translation;
 *       on exit it passes back the node address of the matching port (if any)
 */

u32 tipc_nametbl_translate(u32 type, u32 instance, u32 *destnode)
{
	struct sub_seq *sseq;
	struct publication *publ = NULL;
	struct name_seq *seq;
	u32 ref;

	if (!in_scope(*destnode, tipc_own_addr))
		return 0;

	read_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(type);
	if (unlikely(!seq))
		goto not_found;
	sseq = nameseq_find_subseq(seq, instance);
	if (unlikely(!sseq))
		goto not_found;
	spin_lock_bh(&seq->lock);

	/* Closest-First Algorithm: */
	if (likely(!*destnode)) {
		publ = sseq->node_list;
		if (publ) {
			sseq->node_list = publ->node_list_next;
found:
			ref = publ->ref;
			*destnode = publ->node;
			spin_unlock_bh(&seq->lock);
			read_unlock_bh(&tipc_nametbl_lock);
			return ref;
		}
		publ = sseq->cluster_list;
		if (publ) {
			sseq->cluster_list = publ->cluster_list_next;
			goto found;
		}
		publ = sseq->zone_list;
		if (publ) {
			sseq->zone_list = publ->zone_list_next;
			goto found;
		}
	}

	/* Round-Robin Algorithm: */
	else if (*destnode == tipc_own_addr) {
		publ = sseq->node_list;
		if (publ) {
			sseq->node_list = publ->node_list_next;
			goto found;
		}
	} else if (in_own_cluster(*destnode)) {
		publ = sseq->cluster_list;
		if (publ) {
			sseq->cluster_list = publ->cluster_list_next;
			goto found;
		}
	} else {
		publ = sseq->zone_list;
		if (publ) {
			sseq->zone_list = publ->zone_list_next;
			goto found;
		}
	}
	spin_unlock_bh(&seq->lock);
not_found:
	*destnode = 0;
	read_unlock_bh(&tipc_nametbl_lock);
	return 0;
struct publication *tipc_nametbl_insert_publ(struct net *net, u32 type,
					     u32 lower, u32 upper, u32 scope,
					     u32 node, u32 port, u32 key)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct publication *publ;
	struct name_seq *seq = nametbl_find_seq(net, type);
	int index = hash(type);

	if ((scope < TIPC_ZONE_SCOPE) || (scope > TIPC_NODE_SCOPE) ||
	    (lower > upper)) {
		pr_debug("Failed to publish illegal {%u,%u,%u} with scope %u\n",
			 type, lower, upper, scope);
		return NULL;
	}

	if (!seq)
		seq = tipc_nameseq_create(type, &tn->nametbl->seq_hlist[index]);
	if (!seq)
		return NULL;

	spin_lock_bh(&seq->lock);
	publ = tipc_nameseq_insert_publ(net, seq, type, lower, upper,
					scope, node, port, key);
	spin_unlock_bh(&seq->lock);
	return publ;
}

struct publication *tipc_nametbl_remove_publ(struct net *net, u32 type,
					     u32 lower, u32 node, u32 ref,
					     u32 key)
{
	struct publication *publ;
	struct name_seq *seq = nametbl_find_seq(net, type);

	if (!seq)
		return NULL;

	spin_lock_bh(&seq->lock);
	publ = tipc_nameseq_remove_publ(net, seq, lower, node, ref, key);
	if (!seq->first_free && list_empty(&seq->subscriptions)) {
		hlist_del_init_rcu(&seq->ns_list);
		kfree(seq->sseqs);
		spin_unlock_bh(&seq->lock);
		kfree_rcu(seq, rcu);
		return publ;
	}
	spin_unlock_bh(&seq->lock);
	return publ;
}

/**
 * tipc_nametbl_translate - perform name translation
 *
 * On entry, 'destnode' is the search domain used during translation.
 *
 * On exit:
 * - if name translation is deferred to another node/cluster/zone,
 *   leaves 'destnode' unchanged (will be non-zero) and returns 0
 * - if name translation is attempted and succeeds, sets 'destnode'
 *   to publishing node and returns port reference (will be non-zero)
 * - if name translation is attempted and fails, sets 'destnode' to 0
 *   and returns 0
 */
u32 tipc_nametbl_translate(struct net *net, u32 type, u32 instance,
			   u32 *destnode)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct sub_seq *sseq;
	struct name_info *info;
	struct publication *publ;
	struct name_seq *seq;
	u32 ref = 0;
	u32 node = 0;

	if (!tipc_in_scope(*destnode, tn->own_addr))
		return 0;

	rcu_read_lock();
	seq = nametbl_find_seq(net, type);
	if (unlikely(!seq))
		goto not_found;
	spin_lock_bh(&seq->lock);
	sseq = nameseq_find_subseq(seq, instance);
	if (unlikely(!sseq))
		goto no_match;
	info = sseq->info;

	/* Closest-First Algorithm */
	if (likely(!*destnode)) {
		if (!list_empty(&info->node_list)) {
			publ = list_first_entry(&info->node_list,
						struct publication,
						node_list);
			list_move_tail(&publ->node_list,
				       &info->node_list);
		} else if (!list_empty(&info->cluster_list)) {
			publ = list_first_entry(&info->cluster_list,
						struct publication,
						cluster_list);
			list_move_tail(&publ->cluster_list,
				       &info->cluster_list);
		} else {
			publ = list_first_entry(&info->zone_list,
						struct publication,
						zone_list);
			list_move_tail(&publ->zone_list,
				       &info->zone_list);
		}
	}

	/* Round-Robin Algorithm */
	else if (*destnode == tn->own_addr) {
		if (list_empty(&info->node_list))
			goto no_match;
		publ = list_first_entry(&info->node_list, struct publication,
					node_list);
		list_move_tail(&publ->node_list, &info->node_list);
	} else if (in_own_cluster_exact(net, *destnode)) {
		if (list_empty(&info->cluster_list))
			goto no_match;
		publ = list_first_entry(&info->cluster_list, struct publication,
					cluster_list);
		list_move_tail(&publ->cluster_list, &info->cluster_list);
	} else {
		publ = list_first_entry(&info->zone_list, struct publication,
					zone_list);
		list_move_tail(&publ->zone_list, &info->zone_list);
	}

	ref = publ->ref;
	node = publ->node;
no_match:
	spin_unlock_bh(&seq->lock);
not_found:
	rcu_read_unlock();
	*destnode = node;
	return ref;
}

/**
 * tipc_nametbl_mc_translate - find multicast destinations
 *
 * Creates list of all local ports that overlap the given multicast address;
 * also determines if any off-node ports overlap.
 *
 * Note: Publications with a scope narrower than 'limit' are ignored.
 * (i.e. local node-scope publications mustn't receive messages arriving
 * from another node, even if the multcast link brought it here)
 *
 * Returns non-zero if any off-node ports overlap
 */

int tipc_nametbl_mc_translate(u32 type, u32 lower, u32 upper, u32 limit,
			      struct port_list *dports)
int tipc_nametbl_mc_translate(struct net *net, u32 type, u32 lower, u32 upper,
			      u32 limit, struct list_head *dports)
{
	struct name_seq *seq;
	struct sub_seq *sseq;
	struct sub_seq *sseq_stop;
	int res = 0;

	read_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(type);
	struct name_info *info;
	int res = 0;

	rcu_read_lock();
	seq = nametbl_find_seq(net, type);
	if (!seq)
		goto exit;

	spin_lock_bh(&seq->lock);

	sseq = seq->sseqs + nameseq_locate_subseq(seq, lower);
	sseq_stop = seq->sseqs + seq->first_free;
	for (; sseq != sseq_stop; sseq++) {
		struct publication *publ;

		if (sseq->lower > upper)
			break;

		publ = sseq->node_list;
		if (publ) {
			do {
				if (publ->scope <= limit)
					tipc_port_list_add(dports, publ->ref);
				publ = publ->node_list_next;
			} while (publ != sseq->node_list);
		}

		if (sseq->cluster_list_size != sseq->node_list_size)
			res = 1;
	}

	spin_unlock_bh(&seq->lock);
exit:
	read_unlock_bh(&tipc_nametbl_lock);
	return res;
}

/**
 * tipc_nametbl_publish_rsv - publish port name using a reserved name type
 */

int tipc_nametbl_publish_rsv(u32 ref, unsigned int scope,
			struct tipc_name_seq const *seq)
{
	int res;

	atomic_inc(&rsv_publ_ok);
	res = tipc_publish(ref, scope, seq);
	atomic_dec(&rsv_publ_ok);
	return res;
}

/**
 * tipc_nametbl_publish - add name publication to network name tables
 */

struct publication *tipc_nametbl_publish(u32 type, u32 lower, u32 upper,
				    u32 scope, u32 port_ref, u32 key)
{
	struct publication *publ;

	if (table.local_publ_count >= tipc_max_publications) {
		warn("Publication failed, local publication limit reached (%u)\n",
		     tipc_max_publications);
		return NULL;
	}
	if ((type < TIPC_RESERVED_TYPES) && !atomic_read(&rsv_publ_ok)) {
		warn("Publication failed, reserved name {%u,%u,%u}\n",
		     type, lower, upper);
		return NULL;
	}

	write_lock_bh(&tipc_nametbl_lock);
	table.local_publ_count++;
	publ = tipc_nametbl_insert_publ(type, lower, upper, scope,
				   tipc_own_addr, port_ref, key);
	if (publ && (scope != TIPC_NODE_SCOPE)) {
		tipc_named_publish(publ);
	}
	write_unlock_bh(&tipc_nametbl_lock);
		info = sseq->info;
		list_for_each_entry(publ, &info->node_list, node_list) {
			if (publ->scope <= limit)
				u32_push(dports, publ->ref);
		}

		if (info->cluster_list_size != info->node_list_size)
			res = 1;
	}
	spin_unlock_bh(&seq->lock);
exit:
	rcu_read_unlock();
	return res;
}

/* tipc_nametbl_lookup_dst_nodes - find broadcast destination nodes
 * - Creates list of nodes that overlap the given multicast address
 * - Determines if any node local ports overlap
 */
void tipc_nametbl_lookup_dst_nodes(struct net *net, u32 type, u32 lower,
				   u32 upper, u32 domain,
				   struct tipc_nlist *nodes)
{
	struct sub_seq *sseq, *stop;
	struct publication *publ;
	struct name_info *info;
	struct name_seq *seq;

	rcu_read_lock();
	seq = nametbl_find_seq(net, type);
	if (!seq)
		goto exit;

	spin_lock_bh(&seq->lock);
	sseq = seq->sseqs + nameseq_locate_subseq(seq, lower);
	stop = seq->sseqs + seq->first_free;
	for (; sseq->lower <= upper && sseq != stop; sseq++) {
		info = sseq->info;
		list_for_each_entry(publ, &info->zone_list, zone_list) {
			if (tipc_in_scope(domain, publ->node))
				tipc_nlist_add(nodes, publ->node);
		}
	}
	spin_unlock_bh(&seq->lock);
exit:
	rcu_read_unlock();
}

/*
 * tipc_nametbl_publish - add name publication to network name tables
 */
struct publication *tipc_nametbl_publish(struct net *net, u32 type, u32 lower,
					 u32 upper, u32 scope, u32 port_ref,
					 u32 key)
{
	struct publication *publ;
	struct sk_buff *buf = NULL;
	struct tipc_net *tn = net_generic(net, tipc_net_id);

	spin_lock_bh(&tn->nametbl_lock);
	if (tn->nametbl->local_publ_count >= TIPC_MAX_PUBLICATIONS) {
		pr_warn("Publication failed, local publication limit reached (%u)\n",
			TIPC_MAX_PUBLICATIONS);
		spin_unlock_bh(&tn->nametbl_lock);
		return NULL;
	}

	publ = tipc_nametbl_insert_publ(net, type, lower, upper, scope,
					tn->own_addr, port_ref, key);
	if (likely(publ)) {
		tn->nametbl->local_publ_count++;
		buf = tipc_named_publish(net, publ);
		/* Any pending external events? */
		tipc_named_process_backlog(net);
	}
	spin_unlock_bh(&tn->nametbl_lock);

	if (buf)
		tipc_node_broadcast(net, buf);
	return publ;
}

/**
 * tipc_nametbl_withdraw - withdraw name publication from network name tables
 */

int tipc_nametbl_withdraw(u32 type, u32 lower, u32 ref, u32 key)
{
	struct publication *publ;

	dbg("tipc_nametbl_withdraw: {%u,%u}, key=%u\n", type, lower, key);
	write_lock_bh(&tipc_nametbl_lock);
	publ = tipc_nametbl_remove_publ(type, lower, tipc_own_addr, ref, key);
	if (likely(publ)) {
		table.local_publ_count--;
		if (publ->scope != TIPC_NODE_SCOPE)
			tipc_named_withdraw(publ);
		write_unlock_bh(&tipc_nametbl_lock);
		list_del_init(&publ->pport_list);
		kfree(publ);
		return 1;
	}
	write_unlock_bh(&tipc_nametbl_lock);
	err("Unable to remove local publication\n"
	    "(type=%u, lower=%u, ref=%u, key=%u)\n",
	    type, lower, ref, key);
int tipc_nametbl_withdraw(struct net *net, u32 type, u32 lower, u32 ref,
			  u32 key)
{
	struct publication *publ;
	struct sk_buff *skb = NULL;
	struct tipc_net *tn = net_generic(net, tipc_net_id);

	spin_lock_bh(&tn->nametbl_lock);
	publ = tipc_nametbl_remove_publ(net, type, lower, tn->own_addr,
					ref, key);
	if (likely(publ)) {
		tn->nametbl->local_publ_count--;
		skb = tipc_named_withdraw(net, publ);
		/* Any pending external events? */
		tipc_named_process_backlog(net);
		list_del_init(&publ->pport_list);
		kfree_rcu(publ, rcu);
	} else {
		pr_err("Unable to remove local publication\n"
		       "(type=%u, lower=%u, ref=%u, key=%u)\n",
		       type, lower, ref, key);
	}
	spin_unlock_bh(&tn->nametbl_lock);

	if (skb) {
		tipc_node_broadcast(net, skb);
		return 1;
	}
	return 0;
}

/**
 * tipc_nametbl_subscribe - add a subscription object to the name table
 */

void tipc_nametbl_subscribe(struct subscription *s)
{
	u32 type = s->seq.type;
	struct name_seq *seq;

	write_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(type);
	if (!seq) {
		seq = tipc_nameseq_create(type, &table.types[hash(type)]);
	}
	if (seq){
		spin_lock_bh(&seq->lock);
		dbg("tipc_nametbl_subscribe:found %p for {%u,%u,%u}\n",
		    seq, type, s->seq.lower, s->seq.upper);
		tipc_nameseq_subscribe(seq, s);
		spin_unlock_bh(&seq->lock);
	} else {
		warn("Failed to create subscription for {%u,%u,%u}\n",
		     s->seq.type, s->seq.lower, s->seq.upper);
	}
	write_unlock_bh(&tipc_nametbl_lock);
void tipc_nametbl_subscribe(struct tipc_subscription *s)
{
	struct tipc_net *tn = net_generic(s->net, tipc_net_id);
	u32 type = tipc_subscrp_convert_seq_type(s->evt.s.seq.type, s->swap);
	int index = hash(type);
	struct name_seq *seq;
	struct tipc_name_seq ns;

	spin_lock_bh(&tn->nametbl_lock);
	seq = nametbl_find_seq(s->net, type);
	if (!seq)
		seq = tipc_nameseq_create(type, &tn->nametbl->seq_hlist[index]);
	if (seq) {
		spin_lock_bh(&seq->lock);
		tipc_nameseq_subscribe(seq, s);
		spin_unlock_bh(&seq->lock);
	} else {
		tipc_subscrp_convert_seq(&s->evt.s.seq, s->swap, &ns);
		pr_warn("Failed to create subscription for {%u,%u,%u}\n",
			ns.type, ns.lower, ns.upper);
	}
	spin_unlock_bh(&tn->nametbl_lock);
}

/**
 * tipc_nametbl_unsubscribe - remove a subscription object from name table
 */

void tipc_nametbl_unsubscribe(struct subscription *s)
{
	struct name_seq *seq;

	write_lock_bh(&tipc_nametbl_lock);
	seq = nametbl_find_seq(s->seq.type);
	if (seq != NULL){
		spin_lock_bh(&seq->lock);
		list_del_init(&s->nameseq_list);
		spin_unlock_bh(&seq->lock);
		if ((seq->first_free == 0) && list_empty(&seq->subscriptions)) {
			hlist_del_init(&seq->ns_list);
			kfree(seq->sseqs);
			kfree(seq);
		}
	}
	write_unlock_bh(&tipc_nametbl_lock);
}


/**
 * subseq_list: print specified sub-sequence contents into the given buffer
 */

static void subseq_list(struct sub_seq *sseq, struct print_buf *buf, u32 depth,
			u32 index)
{
	char portIdStr[27];
	char *scopeStr;
	struct publication *publ = sseq->zone_list;

	tipc_printf(buf, "%-10u %-10u ", sseq->lower, sseq->upper);

	if (depth == 2 || !publ) {
		tipc_printf(buf, "\n");
		return;
	}

	do {
		sprintf (portIdStr, "<%u.%u.%u:%u>",
			 tipc_zone(publ->node), tipc_cluster(publ->node),
			 tipc_node(publ->node), publ->ref);
		tipc_printf(buf, "%-26s ", portIdStr);
		if (depth > 3) {
			if (publ->node != tipc_own_addr)
				scopeStr = "";
			else if (publ->scope == TIPC_NODE_SCOPE)
				scopeStr = "node";
			else if (publ->scope == TIPC_CLUSTER_SCOPE)
				scopeStr = "cluster";
			else
				scopeStr = "zone";
			tipc_printf(buf, "%-10u %s", publ->key, scopeStr);
		}

		publ = publ->zone_list_next;
		if (publ == sseq->zone_list)
			break;

		tipc_printf(buf, "\n%33s", " ");
	} while (1);

	tipc_printf(buf, "\n");
}

/**
 * nameseq_list: print specified name sequence contents into the given buffer
 */

static void nameseq_list(struct name_seq *seq, struct print_buf *buf, u32 depth,
			 u32 type, u32 lowbound, u32 upbound, u32 index)
{
	struct sub_seq *sseq;
	char typearea[11];

	if (seq->first_free == 0)
		return;

	sprintf(typearea, "%-10u", seq->type);

	if (depth == 1) {
		tipc_printf(buf, "%s\n", typearea);
		return;
	}

	for (sseq = seq->sseqs; sseq != &seq->sseqs[seq->first_free]; sseq++) {
		if ((lowbound <= sseq->upper) && (upbound >= sseq->lower)) {
			tipc_printf(buf, "%s ", typearea);
			spin_lock_bh(&seq->lock);
			subseq_list(sseq, buf, depth, index);
			spin_unlock_bh(&seq->lock);
			sprintf(typearea, "%10s", " ");
		}
	}
}

/**
 * nametbl_header - print name table header into the given buffer
 */

static void nametbl_header(struct print_buf *buf, u32 depth)
{
	tipc_printf(buf, "Type       ");

	if (depth > 1)
		tipc_printf(buf, "Lower      Upper      ");
	if (depth > 2)
		tipc_printf(buf, "Port Identity              ");
	if (depth > 3)
		tipc_printf(buf, "Publication");

	tipc_printf(buf, "\n-----------");

	if (depth > 1)
		tipc_printf(buf, "--------------------- ");
	if (depth > 2)
		tipc_printf(buf, "-------------------------- ");
	if (depth > 3)
		tipc_printf(buf, "------------------");

	tipc_printf(buf, "\n");
}

/**
 * nametbl_list - print specified name table contents into the given buffer
 */

static void nametbl_list(struct print_buf *buf, u32 depth_info,
			 u32 type, u32 lowbound, u32 upbound)
{
	struct hlist_head *seq_head;
	struct hlist_node *seq_node;
	struct name_seq *seq;
	int all_types;
	u32 depth;
	u32 i;

	all_types = (depth_info & TIPC_NTQ_ALLTYPES);
	depth = (depth_info & ~TIPC_NTQ_ALLTYPES);

	if (depth == 0)
		return;

	if (all_types) {
		/* display all entries in name table to specified depth */
		nametbl_header(buf, depth);
		lowbound = 0;
		upbound = ~0;
		for (i = 0; i < tipc_nametbl_size; i++) {
			seq_head = &table.types[i];
			hlist_for_each_entry(seq, seq_node, seq_head, ns_list) {
				nameseq_list(seq, buf, depth, seq->type,
					     lowbound, upbound, i);
			}
		}
	} else {
		/* display only the sequence that matches the specified type */
		if (upbound < lowbound) {
			tipc_printf(buf, "invalid name sequence specified\n");
			return;
		}
		nametbl_header(buf, depth);
		i = hash(type);
		seq_head = &table.types[i];
		hlist_for_each_entry(seq, seq_node, seq_head, ns_list) {
			if (seq->type == type) {
				nameseq_list(seq, buf, depth, type,
					     lowbound, upbound, i);
				break;
			}
		}
	}
}

#if 0
void tipc_nametbl_print(struct print_buf *buf, const char *str)
{
	tipc_printf(buf, str);
	read_lock_bh(&tipc_nametbl_lock);
	nametbl_list(buf, 0, 0, 0, 0);
	read_unlock_bh(&tipc_nametbl_lock);
}
#endif

#define MAX_NAME_TBL_QUERY 32768

struct sk_buff *tipc_nametbl_get(const void *req_tlv_area, int req_tlv_space)
{
	struct sk_buff *buf;
	struct tipc_name_table_query *argv;
	struct tlv_desc *rep_tlv;
	struct print_buf b;
	int str_len;

	if (!TLV_CHECK(req_tlv_area, req_tlv_space, TIPC_TLV_NAME_TBL_QUERY))
		return tipc_cfg_reply_error_string(TIPC_CFG_TLV_ERROR);

	buf = tipc_cfg_reply_alloc(TLV_SPACE(MAX_NAME_TBL_QUERY));
	if (!buf)
		return NULL;

	rep_tlv = (struct tlv_desc *)buf->data;
	tipc_printbuf_init(&b, TLV_DATA(rep_tlv), MAX_NAME_TBL_QUERY);
	argv = (struct tipc_name_table_query *)TLV_DATA(req_tlv_area);
	read_lock_bh(&tipc_nametbl_lock);
	nametbl_list(&b, ntohl(argv->depth), ntohl(argv->type),
		     ntohl(argv->lowbound), ntohl(argv->upbound));
	read_unlock_bh(&tipc_nametbl_lock);
	str_len = tipc_printbuf_validate(&b);

	skb_put(buf, TLV_SPACE(str_len));
	TLV_SET(rep_tlv, TIPC_TLV_ULTRA_STRING, NULL, str_len);

	return buf;
}

#if 0
void tipc_nametbl_dump(void)
{
	nametbl_list(TIPC_CONS, 0, 0, 0, 0);
}
#endif

int tipc_nametbl_init(void)
{
	table.types = kcalloc(tipc_nametbl_size, sizeof(struct hlist_head),
			      GFP_ATOMIC);
	if (!table.types)
		return -ENOMEM;

	table.local_publ_count = 0;
	return 0;
}

void tipc_nametbl_stop(void)
{
	u32 i;

	if (!table.types)
		return;

	/* Verify name table is empty, then release it */

	write_lock_bh(&tipc_nametbl_lock);
	for (i = 0; i < tipc_nametbl_size; i++) {
		if (!hlist_empty(&table.types[i]))
			err("tipc_nametbl_stop(): hash chain %u is non-null\n", i);
	}
	kfree(table.types);
	table.types = NULL;
	write_unlock_bh(&tipc_nametbl_lock);
}

void tipc_nametbl_unsubscribe(struct tipc_subscription *s)
{
	struct tipc_net *tn = net_generic(s->net, tipc_net_id);
	struct name_seq *seq;
	u32 type = tipc_subscrp_convert_seq_type(s->evt.s.seq.type, s->swap);

	spin_lock_bh(&tn->nametbl_lock);
	seq = nametbl_find_seq(s->net, type);
	if (seq != NULL) {
		spin_lock_bh(&seq->lock);
		list_del_init(&s->nameseq_list);
		tipc_subscrp_put(s);
		if (!seq->first_free && list_empty(&seq->subscriptions)) {
			hlist_del_init_rcu(&seq->ns_list);
			kfree(seq->sseqs);
			spin_unlock_bh(&seq->lock);
			kfree_rcu(seq, rcu);
		} else {
			spin_unlock_bh(&seq->lock);
		}
	}
	spin_unlock_bh(&tn->nametbl_lock);
}

int tipc_nametbl_init(struct net *net)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct name_table *tipc_nametbl;
	int i;

	tipc_nametbl = kzalloc(sizeof(*tipc_nametbl), GFP_ATOMIC);
	if (!tipc_nametbl)
		return -ENOMEM;

	for (i = 0; i < TIPC_NAMETBL_SIZE; i++)
		INIT_HLIST_HEAD(&tipc_nametbl->seq_hlist[i]);

	INIT_LIST_HEAD(&tipc_nametbl->publ_list[TIPC_ZONE_SCOPE]);
	INIT_LIST_HEAD(&tipc_nametbl->publ_list[TIPC_CLUSTER_SCOPE]);
	INIT_LIST_HEAD(&tipc_nametbl->publ_list[TIPC_NODE_SCOPE]);
	tn->nametbl = tipc_nametbl;
	spin_lock_init(&tn->nametbl_lock);
	return 0;
}

/**
 * tipc_purge_publications - remove all publications for a given type
 *
 * tipc_nametbl_lock must be held when calling this function
 */
static void tipc_purge_publications(struct net *net, struct name_seq *seq)
{
	struct publication *publ, *safe;
	struct sub_seq *sseq;
	struct name_info *info;

	spin_lock_bh(&seq->lock);
	sseq = seq->sseqs;
	info = sseq->info;
	list_for_each_entry_safe(publ, safe, &info->zone_list, zone_list) {
		tipc_nameseq_remove_publ(net, seq, publ->lower, publ->node,
					 publ->ref, publ->key);
		kfree_rcu(publ, rcu);
	}
	hlist_del_init_rcu(&seq->ns_list);
	kfree(seq->sseqs);
	spin_unlock_bh(&seq->lock);

	kfree_rcu(seq, rcu);
}

void tipc_nametbl_stop(struct net *net)
{
	u32 i;
	struct name_seq *seq;
	struct hlist_head *seq_head;
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct name_table *tipc_nametbl = tn->nametbl;

	/* Verify name table is empty and purge any lingering
	 * publications, then release the name table
	 */
	spin_lock_bh(&tn->nametbl_lock);
	for (i = 0; i < TIPC_NAMETBL_SIZE; i++) {
		if (hlist_empty(&tipc_nametbl->seq_hlist[i]))
			continue;
		seq_head = &tipc_nametbl->seq_hlist[i];
		hlist_for_each_entry_rcu(seq, seq_head, ns_list) {
			tipc_purge_publications(net, seq);
		}
	}
	spin_unlock_bh(&tn->nametbl_lock);

	synchronize_net();
	kfree(tipc_nametbl);

}

static int __tipc_nl_add_nametable_publ(struct tipc_nl_msg *msg,
					struct name_seq *seq,
					struct sub_seq *sseq, u32 *last_publ)
{
	void *hdr;
	struct nlattr *attrs;
	struct nlattr *publ;
	struct publication *p;

	if (*last_publ) {
		list_for_each_entry(p, &sseq->info->zone_list, zone_list)
			if (p->key == *last_publ)
				break;
		if (p->key != *last_publ)
			return -EPIPE;
	} else {
		p = list_first_entry(&sseq->info->zone_list, struct publication,
				     zone_list);
	}

	list_for_each_entry_from(p, &sseq->info->zone_list, zone_list) {
		*last_publ = p->key;

		hdr = genlmsg_put(msg->skb, msg->portid, msg->seq,
				  &tipc_genl_family, NLM_F_MULTI,
				  TIPC_NL_NAME_TABLE_GET);
		if (!hdr)
			return -EMSGSIZE;

		attrs = nla_nest_start(msg->skb, TIPC_NLA_NAME_TABLE);
		if (!attrs)
			goto msg_full;

		publ = nla_nest_start(msg->skb, TIPC_NLA_NAME_TABLE_PUBL);
		if (!publ)
			goto attr_msg_full;

		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_TYPE, seq->type))
			goto publ_msg_full;
		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_LOWER, sseq->lower))
			goto publ_msg_full;
		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_UPPER, sseq->upper))
			goto publ_msg_full;
		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_SCOPE, p->scope))
			goto publ_msg_full;
		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_NODE, p->node))
			goto publ_msg_full;
		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_REF, p->ref))
			goto publ_msg_full;
		if (nla_put_u32(msg->skb, TIPC_NLA_PUBL_KEY, p->key))
			goto publ_msg_full;

		nla_nest_end(msg->skb, publ);
		nla_nest_end(msg->skb, attrs);
		genlmsg_end(msg->skb, hdr);
	}
	*last_publ = 0;

	return 0;

publ_msg_full:
	nla_nest_cancel(msg->skb, publ);
attr_msg_full:
	nla_nest_cancel(msg->skb, attrs);
msg_full:
	genlmsg_cancel(msg->skb, hdr);

	return -EMSGSIZE;
}

static int __tipc_nl_subseq_list(struct tipc_nl_msg *msg, struct name_seq *seq,
				 u32 *last_lower, u32 *last_publ)
{
	struct sub_seq *sseq;
	struct sub_seq *sseq_start;
	int err;

	if (*last_lower) {
		sseq_start = nameseq_find_subseq(seq, *last_lower);
		if (!sseq_start)
			return -EPIPE;
	} else {
		sseq_start = seq->sseqs;
	}

	for (sseq = sseq_start; sseq != &seq->sseqs[seq->first_free]; sseq++) {
		err = __tipc_nl_add_nametable_publ(msg, seq, sseq, last_publ);
		if (err) {
			*last_lower = sseq->lower;
			return err;
		}
	}
	*last_lower = 0;

	return 0;
}

static int tipc_nl_seq_list(struct net *net, struct tipc_nl_msg *msg,
			    u32 *last_type, u32 *last_lower, u32 *last_publ)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct hlist_head *seq_head;
	struct name_seq *seq = NULL;
	int err;
	int i;

	if (*last_type)
		i = hash(*last_type);
	else
		i = 0;

	for (; i < TIPC_NAMETBL_SIZE; i++) {
		seq_head = &tn->nametbl->seq_hlist[i];

		if (*last_type) {
			seq = nametbl_find_seq(net, *last_type);
			if (!seq)
				return -EPIPE;
		} else {
			hlist_for_each_entry_rcu(seq, seq_head, ns_list)
				break;
			if (!seq)
				continue;
		}

		hlist_for_each_entry_from_rcu(seq, ns_list) {
			spin_lock_bh(&seq->lock);
			err = __tipc_nl_subseq_list(msg, seq, last_lower,
						    last_publ);

			if (err) {
				*last_type = seq->type;
				spin_unlock_bh(&seq->lock);
				return err;
			}
			spin_unlock_bh(&seq->lock);
		}
		*last_type = 0;
	}
	return 0;
}

int tipc_nl_name_table_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int err;
	int done = cb->args[3];
	u32 last_type = cb->args[0];
	u32 last_lower = cb->args[1];
	u32 last_publ = cb->args[2];
	struct net *net = sock_net(skb->sk);
	struct tipc_nl_msg msg;

	if (done)
		return 0;

	msg.skb = skb;
	msg.portid = NETLINK_CB(cb->skb).portid;
	msg.seq = cb->nlh->nlmsg_seq;

	rcu_read_lock();
	err = tipc_nl_seq_list(net, &msg, &last_type, &last_lower, &last_publ);
	if (!err) {
		done = 1;
	} else if (err != -EMSGSIZE) {
		/* We never set seq or call nl_dump_check_consistent() this
		 * means that setting prev_seq here will cause the consistence
		 * check to fail in the netlink callback handler. Resulting in
		 * the NLMSG_DONE message having the NLM_F_DUMP_INTR flag set if
		 * we got an error.
		 */
		cb->prev_seq = 1;
	}
	rcu_read_unlock();

	cb->args[0] = last_type;
	cb->args[1] = last_lower;
	cb->args[2] = last_publ;
	cb->args[3] = done;

	return skb->len;
}

bool u32_find(struct list_head *l, u32 value)
{
	struct u32_item *item;

	list_for_each_entry(item, l, list) {
		if (item->value == value)
			return true;
	}
	return false;
}

bool u32_push(struct list_head *l, u32 value)
{
	struct u32_item *item;

	list_for_each_entry(item, l, list) {
		if (item->value == value)
			return false;
	}
	item = kmalloc(sizeof(*item), GFP_ATOMIC);
	if (unlikely(!item))
		return false;

	item->value = value;
	list_add(&item->list, l);
	return true;
}

u32 u32_pop(struct list_head *l)
{
	struct u32_item *item;
	u32 value = 0;

	if (list_empty(l))
		return 0;
	item = list_first_entry(l, typeof(*item), list);
	value = item->value;
	list_del(&item->list);
	kfree(item);
	return value;
}

bool u32_del(struct list_head *l, u32 value)
{
	struct u32_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, l, list) {
		if (item->value != value)
			continue;
		list_del(&item->list);
		kfree(item);
		return true;
	}
	return false;
}

void u32_list_purge(struct list_head *l)
{
	struct u32_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, l, list) {
		list_del(&item->list);
		kfree(item);
	}
}

int u32_list_len(struct list_head *l)
{
	struct u32_item *item;
	int i = 0;

	list_for_each_entry(item, l, list) {
		i++;
	}
	return i;
}
