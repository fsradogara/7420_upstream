/*
 * Copyright (c) 2008 open80211s Ltd.
 * Copyright (c) 2008, 2009 open80211s Ltd.
 * Authors:    Luis Carlos Cobo <luisca@cozybit.com>
 *             Javier Cardona <javier@cozybit.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef IEEE80211S_H
#define IEEE80211S_H

#include <linux/types.h>
#include <linux/jhash.h>
#include <asm/unaligned.h>
#include "ieee80211_i.h"


/* Data structures */

/**
 * enum mesh_path_flags - mac80211 mesh path flags
 *
 *
 *
 * @MESH_PATH_ACTIVE: the mesh path is can be used for forwarding
 * @MESH_PATH_RESOLVED: the discovery process is running for this mesh path
 * @MESH_PATH_DSN_VALID: the mesh path contains a valid destination sequence
 * 	number
 * @MESH_PATH_FIXED: the mesh path has been manually set and should not be
 * 	modified
 * @MESH_PATH_RESOLVED: the mesh path can has been resolved
 *
 * MESH_PATH_RESOLVED and MESH_PATH_DELETE are used by the mesh path timer to
 * @MESH_PATH_ACTIVE: the mesh path can be used for forwarding
 * @MESH_PATH_RESOLVING: the discovery process is running for this mesh path
 * @MESH_PATH_SN_VALID: the mesh path contains a valid destination sequence
 *	number
 * @MESH_PATH_FIXED: the mesh path has been manually set and should not be
 *	modified
 * @MESH_PATH_RESOLVED: the mesh path can has been resolved
 * @MESH_PATH_REQ_QUEUED: there is an unsent path request for this destination
 *	already queued up, waiting for the discovery process to start.
 * @MESH_PATH_DELETED: the mesh path has been deleted and should no longer
 *	be used
 *
 * MESH_PATH_RESOLVED is used by the mesh path timer to
 * decide when to stop or cancel the mesh path discovery.
 */
enum mesh_path_flags {
	MESH_PATH_ACTIVE =	BIT(0),
	MESH_PATH_RESOLVING =	BIT(1),
	MESH_PATH_DSN_VALID =	BIT(2),
	MESH_PATH_FIXED	=	BIT(3),
	MESH_PATH_RESOLVED =	BIT(4),
	MESH_PATH_SN_VALID =	BIT(2),
	MESH_PATH_FIXED	=	BIT(3),
	MESH_PATH_RESOLVED =	BIT(4),
	MESH_PATH_REQ_QUEUED =	BIT(5),
	MESH_PATH_DELETED =	BIT(6),
};

/**
 * enum mesh_deferred_task_flags - mac80211 mesh deferred tasks
 *
 *
 *
 * @MESH_WORK_HOUSEKEEPING: run the periodic mesh housekeeping tasks
 * @MESH_WORK_ROOT: the mesh root station needs to send a frame
 * @MESH_WORK_DRIFT_ADJUST: time to compensate for clock drift relative to other
 * mesh nodes
 * @MESH_WORK_MBSS_CHANGED: rebuild beacon and notify driver of BSS changes
 */
enum mesh_deferred_task_flags {
	MESH_WORK_HOUSEKEEPING,
	MESH_WORK_ROOT,
	MESH_WORK_DRIFT_ADJUST,
	MESH_WORK_MBSS_CHANGED,
};

/**
 * struct mesh_path - mac80211 mesh path structure
 *
 * @dst: mesh path destination mac address
 * @dev: mesh path device
 * @next_hop: mesh neighbor to which frames for this destination will be
 * 	forwarded
 * @timer: mesh path discovery timer
 * @frame_queue: pending queue for frames sent to this destination while the
 * 	path is unresolved
 * @dsn: destination sequence number of the destination
 * @mpp: mesh proxy mac address
 * @rhash: rhashtable list pointer
 * @gate_list: list pointer for known gates list
 * @sdata: mesh subif
 * @next_hop: mesh neighbor to which frames for this destination will be
 *	forwarded
 * @timer: mesh path discovery timer
 * @frame_queue: pending queue for frames sent to this destination while the
 *	path is unresolved
 * @rcu: rcu head for freeing mesh path
 * @sn: target sequence number
 * @metric: current metric to this destination
 * @hop_count: hops to destination
 * @exp_time: in jiffies, when the path will expire or when it expired
 * @discovery_timeout: timeout (lapse in jiffies) used for the last discovery
 * 	retry
 * @discovery_retries: number of discovery retries
 * @flags: mesh path flags, as specified on &enum mesh_path_flags
 * @state_lock: mesh pat state lock
 *
 *
 * The combination of dst and dev is unique in the mesh path table. Since the
 *	retry
 * @discovery_retries: number of discovery retries
 * @flags: mesh path flags, as specified on &enum mesh_path_flags
 * @state_lock: mesh path state lock used to protect changes to the
 * mpath itself.  No need to take this lock when adding or removing
 * an mpath to a hash bucket on a path table.
 * @rann_snd_addr: the RANN sender address
 * @rann_metric: the aggregated path metric towards the root node
 * @last_preq_to_root: Timestamp of last PREQ sent to root
 * @is_root: the destination station of this path is a root node
 * @is_gate: the destination station of this path is a mesh gate
 *
 *
 * The dst address is unique in the mesh path table. Since the mesh_path is
 * protected by RCU, deleting the next_hop STA must remove / substitute the
 * mesh_path structure and wait until that is no longer reachable before
 * destroying the STA completely.
 */
struct mesh_path {
	u8 dst[ETH_ALEN];
	struct net_device *dev;
	struct sta_info *next_hop;
	struct timer_list timer;
	struct sk_buff_head frame_queue;
	struct rcu_head rcu;
	u32 dsn;
	u8 mpp[ETH_ALEN];	/* used for MPP or MAP */
	struct rhash_head rhash;
	struct hlist_node gate_list;
	struct ieee80211_sub_if_data *sdata;
	struct sta_info __rcu *next_hop;
	struct timer_list timer;
	struct sk_buff_head frame_queue;
	struct rcu_head rcu;
	u32 sn;
	u32 metric;
	u8 hop_count;
	unsigned long exp_time;
	u32 discovery_timeout;
	u8 discovery_retries;
	enum mesh_path_flags flags;
	spinlock_t state_lock;
	u8 rann_snd_addr[ETH_ALEN];
	u32 rann_metric;
	unsigned long last_preq_to_root;
	bool is_root;
	bool is_gate;
};

/**
 * struct mesh_table
 *
 * @hash_buckets: array of hash buckets of the table
 * @hashwlock: array of locks to protect write operations, one per bucket
 * @hash_mask: 2^size_order - 1, used to compute hash idx
 * @hash_rnd: random value used for hash computations
 * @entries: number of entries in the table
 * @free_node: function to free nodes of the table
 * @copy_node: fuction to copy nodes of the table
 * @copy_node: function to copy nodes of the table
 * @size_order: determines size of the table, there will be 2^size_order hash
 *	buckets
 * @mean_chain_len: maximum average length for the hash buckets' list, if it is
 *	reached, the table will grow
 * @known_gates: list of known mesh gates and their mpaths by the station. The
 * gate's mpath may or may not be resolved and active.
 * @gates_lock: protects updates to known_gates
 * @rhead: the rhashtable containing struct mesh_paths, keyed by dest addr
 * @entries: number of entries in the table
 */
struct mesh_table {
	struct hlist_head known_gates;
	spinlock_t gates_lock;
	struct rhashtable rhead;
	atomic_t entries;		/* Up to MAX_MESH_NEIGHBOURS */
};

/* Recent multicast cache */
/* RMC_BUCKETS must be a power of 2, maximum 256 */
#define RMC_BUCKETS		256
#define RMC_QUEUE_MAX_LEN	4
#define RMC_TIMEOUT		(3 * HZ)

/**
 * struct rmc_entry - entry in the Recent Multicast Cache
 *
 * @seqnum: mesh sequence number of the frame
 * @exp_time: expiration time of the entry, in jiffies
 * @sa: source address of the frame
 * @list: hashtable list pointer
 *
 * The Recent Multicast Cache keeps track of the latest multicast frames that
 * have been received by a mesh interface and discards received multicast frames
 * that are found in the cache.
 */
struct rmc_entry {
	struct hlist_node list;
	unsigned long exp_time;
	u32 seqnum;
	u8 sa[ETH_ALEN];
};

struct mesh_rmc {
	struct rmc_entry bucket[RMC_BUCKETS];
	u32 idx_mask;
};


/* Mesh IEs constants */
#define MESH_CFG_LEN		19

/*
 * MESH_CFG_COMP_LEN Includes:
 * 	- Active path selection protocol ID.
 * 	- Active path selection metric ID.
 * 	- Congestion control mode identifier.
 * 	- Channel precedence.
 * Does not include mesh capabilities, which may vary across nodes in the same
 * mesh
 */
#define MESH_CFG_CMP_LEN 	17

/* Default values, timeouts in ms */
#define MESH_TTL 		5
#define MESH_MAX_RETR	 	3
#define MESH_RET_T 		100
#define MESH_CONF_T 		100
#define MESH_HOLD_T 		100

#define MESH_PATH_TIMEOUT	5000
/* Minimum interval between two consecutive PREQs originated by the same
 * interface
 */
#define MESH_PREQ_MIN_INT	10
#define MESH_DIAM_TRAVERSAL_TIME 50
/* Paths will be refreshed if they are closer than PATH_REFRESH_TIME to their
 * expiration
 */
#define MESH_PATH_REFRESH_TIME			1000
#define MESH_MIN_DISCOVERY_TIMEOUT (2 * MESH_DIAM_TRAVERSAL_TIME)

#define MESH_MAX_PREQ_RETRIES 4
#define MESH_PATH_EXPIRE (600 * HZ)

/* Default maximum number of established plinks per interface */
#define MESH_MAX_ESTAB_PLINKS	32

	struct list_head bucket[RMC_BUCKETS];
	struct hlist_head bucket[RMC_BUCKETS];
	u32 idx_mask;
};

#define IEEE80211_MESH_HOUSEKEEPING_INTERVAL (60 * HZ)

#define MESH_PATH_EXPIRE (600 * HZ)

/* Default maximum number of plinks per interface */
#define MESH_MAX_PLINKS		256

/* Maximum number of paths per interface */
#define MESH_MAX_MPATHS		1024

/* Pending ANA approval */
#define PLINK_CATEGORY		30
#define MESH_PATH_SEL_CATEGORY	32

/* Mesh Header Flags */
#define IEEE80211S_FLAGS_AE	0x3

/* Public interfaces */
/* Various */
u8 mesh_id_hash(u8 *mesh_id, int mesh_id_len);
int ieee80211_get_mesh_hdrlen(struct ieee80211s_hdr *meshhdr);
int ieee80211_new_mesh_header(struct ieee80211s_hdr *meshhdr,
		struct ieee80211_sub_if_data *sdata);
int mesh_rmc_check(u8 *addr, struct ieee80211s_hdr *mesh_hdr,
		struct net_device *dev);
bool mesh_matches_local(struct ieee802_11_elems *ie, struct net_device *dev);
void mesh_ids_set_default(struct ieee80211_if_sta *sta);
void mesh_mgmt_ies_add(struct sk_buff *skb, struct net_device *dev);
void mesh_rmc_free(struct net_device *dev);
int mesh_rmc_init(struct net_device *dev);
void ieee80211s_init(void);
void ieee80211s_stop(void);
void ieee80211_mesh_init_sdata(struct ieee80211_sub_if_data *sdata);

/* Mesh paths */
int mesh_nexthop_lookup(struct sk_buff *skb, struct net_device *dev);
void mesh_path_start_discovery(struct net_device *dev);
struct mesh_path *mesh_path_lookup(u8 *dst, struct net_device *dev);
struct mesh_path *mesh_path_lookup_by_idx(int idx, struct net_device *dev);
void mesh_path_fix_nexthop(struct mesh_path *mpath, struct sta_info *next_hop);
void mesh_path_expire(struct net_device *dev);
void mesh_path_flush(struct net_device *dev);
void mesh_rx_path_sel_frame(struct net_device *dev, struct ieee80211_mgmt *mgmt,
		size_t len);
int mesh_path_add(u8 *dst, struct net_device *dev);
/* Mesh plinks */
void mesh_neighbour_update(u8 *hw_addr, u64 rates, struct net_device *dev,
		bool add);
bool mesh_peer_accepts_plinks(struct ieee802_11_elems *ie,
			      struct net_device *dev);
void mesh_accept_plinks_update(struct ieee80211_sub_if_data *sdata);
void mesh_plink_broken(struct sta_info *sta);
void mesh_plink_deactivate(struct sta_info *sta);
int mesh_plink_open(struct sta_info *sta);
int mesh_plink_close(struct sta_info *sta);
void mesh_plink_block(struct sta_info *sta);
void mesh_rx_plink_frame(struct net_device *dev, struct ieee80211_mgmt *mgmt,
			 size_t len, struct ieee80211_rx_status *rx_status);

/* Private interfaces */
/* Mesh tables */
struct mesh_table *mesh_table_alloc(int size_order);
void mesh_table_free(struct mesh_table *tbl, bool free_leafs);
struct mesh_table *mesh_table_grow(struct mesh_table *tbl);
u32 mesh_table_hash(u8 *addr, struct net_device *dev, struct mesh_table *tbl);
/* Mesh paths */
int mesh_path_error_tx(u8 *dest, __le32 dest_dsn, u8 *ra,
		struct net_device *dev);
/* Number of frames buffered per destination for unresolved destinations */
#define MESH_FRAME_QUEUE_LEN	10

/* Public interfaces */
/* Various */
int ieee80211_fill_mesh_addresses(struct ieee80211_hdr *hdr, __le16 *fc,
				  const u8 *da, const u8 *sa);
unsigned int ieee80211_new_mesh_header(struct ieee80211_sub_if_data *sdata,
				       struct ieee80211s_hdr *meshhdr,
				       const char *addr4or5, const char *addr6);
int mesh_rmc_check(struct ieee80211_sub_if_data *sdata,
		   const u8 *addr, struct ieee80211s_hdr *mesh_hdr);
bool mesh_matches_local(struct ieee80211_sub_if_data *sdata,
			struct ieee802_11_elems *ie);
void mesh_ids_set_default(struct ieee80211_if_mesh *mesh);
int mesh_add_meshconf_ie(struct ieee80211_sub_if_data *sdata,
			 struct sk_buff *skb);
int mesh_add_meshid_ie(struct ieee80211_sub_if_data *sdata,
		       struct sk_buff *skb);
int mesh_add_rsn_ie(struct ieee80211_sub_if_data *sdata,
		    struct sk_buff *skb);
int mesh_add_vendor_ies(struct ieee80211_sub_if_data *sdata,
			struct sk_buff *skb);
int mesh_add_ht_cap_ie(struct ieee80211_sub_if_data *sdata,
		       struct sk_buff *skb);
int mesh_add_ht_oper_ie(struct ieee80211_sub_if_data *sdata,
			struct sk_buff *skb);
int mesh_add_vht_cap_ie(struct ieee80211_sub_if_data *sdata,
			struct sk_buff *skb);
int mesh_add_vht_oper_ie(struct ieee80211_sub_if_data *sdata,
			 struct sk_buff *skb);
void mesh_rmc_free(struct ieee80211_sub_if_data *sdata);
int mesh_rmc_init(struct ieee80211_sub_if_data *sdata);
void ieee80211s_init(void);
void ieee80211s_update_metric(struct ieee80211_local *local,
			      struct sta_info *sta, struct sk_buff *skb);
void ieee80211_mesh_init_sdata(struct ieee80211_sub_if_data *sdata);
void ieee80211_mesh_teardown_sdata(struct ieee80211_sub_if_data *sdata);
int ieee80211_start_mesh(struct ieee80211_sub_if_data *sdata);
void ieee80211_stop_mesh(struct ieee80211_sub_if_data *sdata);
void ieee80211_mesh_root_setup(struct ieee80211_if_mesh *ifmsh);
const struct ieee80211_mesh_sync_ops *ieee80211_mesh_sync_ops_get(u8 method);
/* wrapper for ieee80211_bss_info_change_notify() */
void ieee80211_mbss_info_change_notify(struct ieee80211_sub_if_data *sdata,
				       u32 changed);

/* mesh power save */
u32 ieee80211_mps_local_status_update(struct ieee80211_sub_if_data *sdata);
u32 ieee80211_mps_set_sta_local_pm(struct sta_info *sta,
				   enum nl80211_mesh_power_mode pm);
void ieee80211_mps_set_frame_flags(struct ieee80211_sub_if_data *sdata,
				   struct sta_info *sta,
				   struct ieee80211_hdr *hdr);
void ieee80211_mps_sta_status_update(struct sta_info *sta);
void ieee80211_mps_rx_h_sta_process(struct sta_info *sta,
				    struct ieee80211_hdr *hdr);
void ieee80211_mpsp_trigger_process(u8 *qc, struct sta_info *sta,
				    bool tx, bool acked);
void ieee80211_mps_frame_release(struct sta_info *sta,
				 struct ieee802_11_elems *elems);

/* Mesh paths */
int mesh_nexthop_lookup(struct ieee80211_sub_if_data *sdata,
			struct sk_buff *skb);
int mesh_nexthop_resolve(struct ieee80211_sub_if_data *sdata,
			 struct sk_buff *skb);
void mesh_path_start_discovery(struct ieee80211_sub_if_data *sdata);
struct mesh_path *mesh_path_lookup(struct ieee80211_sub_if_data *sdata,
				   const u8 *dst);
struct mesh_path *mpp_path_lookup(struct ieee80211_sub_if_data *sdata,
				  const u8 *dst);
int mpp_path_add(struct ieee80211_sub_if_data *sdata,
		 const u8 *dst, const u8 *mpp);
struct mesh_path *
mesh_path_lookup_by_idx(struct ieee80211_sub_if_data *sdata, int idx);
struct mesh_path *
mpp_path_lookup_by_idx(struct ieee80211_sub_if_data *sdata, int idx);
void mesh_path_fix_nexthop(struct mesh_path *mpath, struct sta_info *next_hop);
void mesh_path_expire(struct ieee80211_sub_if_data *sdata);
void mesh_rx_path_sel_frame(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_mgmt *mgmt, size_t len);
struct mesh_path *
mesh_path_add(struct ieee80211_sub_if_data *sdata, const u8 *dst);

int mesh_path_add_gate(struct mesh_path *mpath);
int mesh_path_send_to_gates(struct mesh_path *mpath);
int mesh_gate_num(struct ieee80211_sub_if_data *sdata);

/* Mesh plinks */
void mesh_neighbour_update(struct ieee80211_sub_if_data *sdata,
			   u8 *hw_addr, struct ieee802_11_elems *ie);
bool mesh_peer_accepts_plinks(struct ieee802_11_elems *ie);
u32 mesh_accept_plinks_update(struct ieee80211_sub_if_data *sdata);
void mesh_plink_broken(struct sta_info *sta);
u32 mesh_plink_deactivate(struct sta_info *sta);
u32 mesh_plink_open(struct sta_info *sta);
u32 mesh_plink_block(struct sta_info *sta);
void mesh_rx_plink_frame(struct ieee80211_sub_if_data *sdata,
			 struct ieee80211_mgmt *mgmt, size_t len,
			 struct ieee80211_rx_status *rx_status);
void mesh_sta_cleanup(struct sta_info *sta);

/* Private interfaces */
/* Mesh paths */
int mesh_path_error_tx(struct ieee80211_sub_if_data *sdata,
		       u8 ttl, const u8 *target, u32 target_sn,
		       u16 target_rcode, const u8 *ra);
void mesh_path_assign_nexthop(struct mesh_path *mpath, struct sta_info *sta);
void mesh_path_flush_pending(struct mesh_path *mpath);
void mesh_path_tx_pending(struct mesh_path *mpath);
int mesh_pathtbl_init(void);
void mesh_pathtbl_unregister(void);
int mesh_path_del(u8 *addr, struct net_device *dev);
void mesh_path_timer(unsigned long data);
void mesh_path_flush_by_nexthop(struct sta_info *sta);
void mesh_path_discard_frame(struct sk_buff *skb, struct net_device *dev);

#ifdef CONFIG_MAC80211_MESH
extern int mesh_allocated;

static inline int mesh_plink_free_count(struct ieee80211_sub_if_data *sdata)
{
	return sdata->u.sta.mshcfg.dot11MeshMaxPeerLinks -
	       atomic_read(&sdata->u.sta.mshstats.estab_plinks);
int mesh_pathtbl_init(struct ieee80211_sub_if_data *sdata);
void mesh_pathtbl_unregister(struct ieee80211_sub_if_data *sdata);
int mesh_path_del(struct ieee80211_sub_if_data *sdata, const u8 *addr);
void mesh_path_timer(unsigned long data);
void mesh_path_flush_by_nexthop(struct sta_info *sta);
void mesh_path_discard_frame(struct ieee80211_sub_if_data *sdata,
			     struct sk_buff *skb);
void mesh_path_tx_root_frame(struct ieee80211_sub_if_data *sdata);

bool mesh_action_is_path_sel(struct ieee80211_mgmt *mgmt);

#ifdef CONFIG_MAC80211_MESH
static inline
u32 mesh_plink_inc_estab_count(struct ieee80211_sub_if_data *sdata)
{
	atomic_inc(&sdata->u.mesh.estab_plinks);
	return mesh_accept_plinks_update(sdata) | BSS_CHANGED_BEACON;
}

static inline
u32 mesh_plink_dec_estab_count(struct ieee80211_sub_if_data *sdata)
{
	atomic_dec(&sdata->u.mesh.estab_plinks);
	return mesh_accept_plinks_update(sdata) | BSS_CHANGED_BEACON;
}

static inline int mesh_plink_free_count(struct ieee80211_sub_if_data *sdata)
{
	return sdata->u.mesh.mshcfg.dot11MeshMaxPeerLinks -
	       atomic_read(&sdata->u.mesh.estab_plinks);
}

static inline bool mesh_plink_availables(struct ieee80211_sub_if_data *sdata)
{
	return (min_t(long, mesh_plink_free_count(sdata),
		   MESH_MAX_PLINKS - sdata->local->num_sta)) > 0;
}

static inline void mesh_path_activate(struct mesh_path *mpath)
{
	mpath->flags |= MESH_PATH_ACTIVE | MESH_PATH_RESOLVED;
}

#define for_each_mesh_entry(x, p, node, i) \
	for (i = 0; i <= x->hash_mask; i++) \
		hlist_for_each_entry_rcu(node, p, &x->hash_buckets[i], list)

#else
#define mesh_allocated	0
static inline bool mesh_path_sel_is_hwmp(struct ieee80211_sub_if_data *sdata)
{
	return sdata->u.mesh.mesh_pp_id == IEEE80211_PATH_PROTOCOL_HWMP;
}

void mesh_path_flush_by_iface(struct ieee80211_sub_if_data *sdata);
void mesh_sync_adjust_tsf(struct ieee80211_sub_if_data *sdata);
void ieee80211s_stop(void);
#else
static inline bool mesh_path_sel_is_hwmp(struct ieee80211_sub_if_data *sdata)
{ return false; }
static inline void mesh_path_flush_by_iface(struct ieee80211_sub_if_data *sdata)
{}
static inline void ieee80211s_stop(void) {}
#endif

#endif /* IEEE80211S_H */
