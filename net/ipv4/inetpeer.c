/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  This source is covered by the GNU GPL, the same as all kernel sources.
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#include <linux/cache.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <net/ip.h>
#include <net/inetpeer.h>
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/inetpeer.h>
#include <net/secure_seq.h>

/*
 *  Theory of operations.
 *  We keep one entry for each peer IP address.  The nodes contains long-living
 *  information about the peer which doesn't depend on routes.
 *  At this moment this information consists only of ID field for the next
 *  outgoing IP packet.  This field is incremented with each packet as encoded
 *  in inet_getid() function (include/net/inetpeer.h).
 *  At the moment of writing this notes identifier of IP packets is generated
 *  to be unpredictable using this code only for packets subjected
 *  (actually or potentially) to defragmentation.  I.e. DF packets less than
 *  PMTU in size uses a constant ID and do not use this code (see
 *  ip_select_ident() in include/net/ip.h).
 *
 *  Route cache entries hold references to our nodes.
 *  New cache entries get references via lookup by destination IP address in
 *  the avl tree.  The reference is grabbed only when it's needed i.e. only
 *  when we try to output IP packet which needs an unpredictable ID (see
 *  __ip_select_ident() in net/ipv4/route.c).
 *
 *  Nodes are removed only when reference counter goes to 0.
 *  When it's happened the node may be removed when a sufficient amount of
 *  time has been passed since its last use.  The less-recently-used entry can
 *  also be removed if the pool is overloaded i.e. if the total amount of
 *  entries is greater-or-equal than the threshold.
 *
 *  Node pool is organised as an RB tree.
 *  Such an implementation has been chosen not just for fun.  It's a way to
 *  prevent easy and efficient DoS attacks by creating hash collisions.  A huge
 *  amount of long living nodes in a single hash slot would significantly delay
 *  lookups performed with disabled BHs.
 *
 *  Serialisation issues.
 *  1.  Nodes may appear in the tree only with the pool write lock held.
 *  2.  Nodes may disappear from the tree only with the pool write lock held
 *      AND reference count being 0.
 *  3.  Nodes appears and disappears from unused node list only under
 *      "inet_peer_unused_lock".
 *  4.  Global variable peer_total is modified under the pool lock.
 *  5.  struct inet_peer fields modification:
 *		avl_left, avl_right, avl_parent, avl_height: pool lock
 *		unused: unused node list lock
 *		refcnt: atomically against modifications on other CPU;
 *		   usually under some other lock to prevent node disappearing
 *		dtime: unused node list lock
 *		v4daddr: unchangeable
 *		ip_id_count: idlock
 */

/* Exported for inet_getid inline function.  */
DEFINE_SPINLOCK(inet_peer_idlock);

static struct kmem_cache *peer_cachep __read_mostly;

#define node_height(x) x->avl_height
static struct inet_peer peer_fake_node = {
	.avl_left	= &peer_fake_node,
	.avl_right	= &peer_fake_node,
	.avl_height	= 0
};
#define peer_avl_empty (&peer_fake_node)
static struct inet_peer *peer_root = peer_avl_empty;
static DEFINE_RWLOCK(peer_pool_lock);
#define PEER_MAXDEPTH 40 /* sufficient for about 2^27 nodes */

static int peer_total;
 *  1.  Nodes may appear in the tree only with the pool lock held.
 *  2.  Nodes may disappear from the tree only with the pool lock held
 *      AND reference count being 0.
 *  3.  Global variable peer_total is modified under the pool lock.
 *  4.  struct inet_peer fields modification:
 *		rb_node: pool lock
 *		refcnt: atomically against modifications on other CPU;
 *		   usually under some other lock to prevent node disappearing
 *		daddr: unchangeable
 */

static struct kmem_cache *peer_cachep __ro_after_init;

void inet_peer_base_init(struct inet_peer_base *bp)
{
	bp->rb_root = RB_ROOT;
	seqlock_init(&bp->lock);
	bp->total = 0;
}
EXPORT_SYMBOL_GPL(inet_peer_base_init);

#define PEER_MAX_GC 32

/* Exported for sysctl_net_ipv4.  */
int inet_peer_threshold __read_mostly = 65536 + 128;	/* start to throw entries more
					 * aggressively at this stage */
int inet_peer_minttl __read_mostly = 120 * HZ;	/* TTL under high load: 120 sec */
int inet_peer_maxttl __read_mostly = 10 * 60 * HZ;	/* usual time to live: 10 min */
int inet_peer_gc_mintime __read_mostly = 10 * HZ;
int inet_peer_gc_maxtime __read_mostly = 120 * HZ;

static LIST_HEAD(unused_peers);
static DEFINE_SPINLOCK(inet_peer_unused_lock);

static void peer_check_expire(unsigned long dummy);
static DEFINE_TIMER(peer_periodic_timer, peer_check_expire, 0, 0);


/* Called from ip_output.c:ip_init  */
void __init inet_initpeers(void)
{
	struct sysinfo si;

	/* Use the straight interface to information about memory. */
	si_meminfo(&si);
	/* The values below were suggested by Alexey Kuznetsov
	 * <kuznet@ms2.inr.ac.ru>.  I don't have any opinion about the values
	 * myself.  --SAW
	 */
	if (si.totalram <= (32768*1024)/PAGE_SIZE)
		inet_peer_threshold >>= 1; /* max pool size about 1MB on IA32 */
	if (si.totalram <= (16384*1024)/PAGE_SIZE)
		inet_peer_threshold >>= 1; /* about 512KB */
	if (si.totalram <= (8192*1024)/PAGE_SIZE)
		inet_peer_threshold >>= 2; /* about 128KB */

	peer_cachep = kmem_cache_create("inet_peer_cache",
			sizeof(struct inet_peer),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC,
			NULL);

	/* All the timers, started at system startup tend
	   to synchronize. Perturb it a bit.
	 */
	peer_periodic_timer.expires = jiffies
		+ net_random() % inet_peer_gc_maxtime
		+ inet_peer_gc_maxtime;
	add_timer(&peer_periodic_timer);
}

/* Called with or without local BH being disabled. */
static void unlink_from_unused(struct inet_peer *p)
{
	spin_lock_bh(&inet_peer_unused_lock);
	list_del_init(&p->unused);
	spin_unlock_bh(&inet_peer_unused_lock);
}

/*
 * Called with local BH disabled and the pool lock held.
 * _stack is known to be NULL or not at compile time,
 * so compiler will optimize the if (_stack) tests.
 */
#define lookup(_daddr,_stack) 					\
({								\
	struct inet_peer *u, **v;				\
	if (_stack != NULL) {					\
		stackptr = _stack;				\
		*stackptr++ = &peer_root;			\
	}							\
	for (u = peer_root; u != peer_avl_empty; ) {		\
		if (_daddr == u->v4daddr)			\
			break;					\
		if ((__force __u32)_daddr < (__force __u32)u->v4daddr)	\
			v = &u->avl_left;			\
		else						\
			v = &u->avl_right;			\
		if (_stack != NULL)				\
			*stackptr++ = v;			\
		u = *v;						\
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC,
			NULL);
}

#define rcu_deref_locked(X, BASE)				\
	rcu_dereference_protected(X, lockdep_is_held(&(BASE)->lock.lock))

/*
 * Called with local BH disabled and the pool lock held.
 */
#define lookup(_daddr, _stack, _base)				\
({								\
	struct inet_peer *u;					\
	struct inet_peer __rcu **v;				\
								\
	stackptr = _stack;					\
	*stackptr++ = &_base->root;				\
	for (u = rcu_deref_locked(_base->root, _base);		\
	     u != peer_avl_empty;) {				\
		int cmp = inetpeer_addr_cmp(_daddr, &u->daddr);	\
		if (cmp == 0)					\
			break;					\
		if (cmp == -1)					\
			v = &u->avl_left;			\
		else						\
			v = &u->avl_right;			\
		*stackptr++ = v;				\
		u = rcu_deref_locked(*v, _base);		\
	}							\
	u;							\
})

/* Called with local BH disabled and the pool write lock held. */
#define lookup_rightempty(start)				\
({								\
	struct inet_peer *u, **v;				\
	*stackptr++ = &start->avl_left;				\
	v = &start->avl_left;					\
	for (u = *v; u->avl_right != peer_avl_empty; ) {	\
		v = &u->avl_right;				\
		*stackptr++ = v;				\
		u = *v;						\
/*
 * Called with rcu_read_lock()
 * Because we hold no lock against a writer, its quite possible we fall
 * in an endless loop.
 * But every pointer we follow is guaranteed to be valid thanks to RCU.
 * We exit from this function if number of links exceeds PEER_MAXDEPTH
 */
static struct inet_peer *lookup_rcu(const struct inetpeer_addr *daddr,
				    struct inet_peer_base *base)
/* Called with rcu_read_lock() or base->lock held */
static struct inet_peer *lookup(const struct inetpeer_addr *daddr,
				struct inet_peer_base *base,
				unsigned int seq,
				struct inet_peer *gc_stack[],
				unsigned int *gc_cnt,
				struct rb_node **parent_p,
				struct rb_node ***pp_p)
{
	struct rb_node **pp, *parent, *next;
	struct inet_peer *p;

	pp = &base->rb_root.rb_node;
	parent = NULL;
	while (1) {
		int cmp;

		next = rcu_dereference_raw(*pp);
		if (!next)
			break;
		parent = next;
		p = rb_entry(parent, struct inet_peer, rb_node);
		cmp = inetpeer_addr_cmp(daddr, &p->daddr);
		if (cmp == 0) {
			if (!refcount_inc_not_zero(&p->refcnt))
				break;
			return p;
		}
		if (gc_stack) {
			if (*gc_cnt < PEER_MAX_GC)
				gc_stack[(*gc_cnt)++] = p;
		} else if (unlikely(read_seqretry(&base->lock, seq))) {
			break;
		}
		if (cmp == -1)
			pp = &next->rb_left;
		else
			pp = &next->rb_right;
	}
	*parent_p = parent;
	*pp_p = pp;
	return NULL;
}

/* Called with local BH disabled and the pool lock held. */
#define lookup_rightempty(start, base)				\
({								\
	struct inet_peer *u;					\
	struct inet_peer __rcu **v;				\
	*stackptr++ = &start->avl_left;				\
	v = &start->avl_left;					\
	for (u = rcu_deref_locked(*v, base);			\
	     u->avl_right != peer_avl_empty_rcu;) {		\
		v = &u->avl_right;				\
		*stackptr++ = v;				\
		u = rcu_deref_locked(*v, base);			\
	}							\
	u;							\
})

/* Called with local BH disabled and the pool write lock held.
 * Variable names are the proof of operation correctness.
 * Look into mm/map_avl.c for more detail description of the ideas.  */
static void peer_avl_rebalance(struct inet_peer **stack[],
		struct inet_peer ***stackend)
{
	struct inet_peer **nodep, *node, *l, *r;
/* Called with local BH disabled and the pool lock held.
 * Variable names are the proof of operation correctness.
 * Look into mm/map_avl.c for more detail description of the ideas.
 */
static void peer_avl_rebalance(struct inet_peer __rcu **stack[],
			       struct inet_peer __rcu ***stackend,
			       struct inet_peer_base *base)
{
	struct inet_peer __rcu **nodep;
	struct inet_peer *node, *l, *r;
	int lh, rh;

	while (stackend > stack) {
		nodep = *--stackend;
		node = *nodep;
		l = node->avl_left;
		r = node->avl_right;
		node = rcu_deref_locked(*nodep, base);
		l = rcu_deref_locked(node->avl_left, base);
		r = rcu_deref_locked(node->avl_right, base);
		lh = node_height(l);
		rh = node_height(r);
		if (lh > rh + 1) { /* l: RH+2 */
			struct inet_peer *ll, *lr, *lrl, *lrr;
			int lrh;
			ll = l->avl_left;
			lr = l->avl_right;
			lrh = node_height(lr);
			if (lrh <= node_height(ll)) {	/* ll: RH+1 */
				node->avl_left = lr;	/* lr: RH or RH+1 */
				node->avl_right = r;	/* r: RH */
				node->avl_height = lrh + 1; /* RH+1 or RH+2 */
				l->avl_left = ll;	/* ll: RH+1 */
				l->avl_right = node;	/* node: RH+1 or RH+2 */
				l->avl_height = node->avl_height + 1;
				*nodep = l;
			} else { /* ll: RH, lr: RH+1 */
				lrl = lr->avl_left;	/* lrl: RH or RH-1 */
				lrr = lr->avl_right;	/* lrr: RH or RH-1 */
				node->avl_left = lrr;	/* lrr: RH or RH-1 */
				node->avl_right = r;	/* r: RH */
				node->avl_height = rh + 1; /* node: RH+1 */
				l->avl_left = ll;	/* ll: RH */
				l->avl_right = lrl;	/* lrl: RH or RH-1 */
				l->avl_height = rh + 1;	/* l: RH+1 */
				lr->avl_left = l;	/* l: RH+1 */
				lr->avl_right = node;	/* node: RH+1 */
				lr->avl_height = rh + 2;
				*nodep = lr;
			ll = rcu_deref_locked(l->avl_left, base);
			lr = rcu_deref_locked(l->avl_right, base);
			lrh = node_height(lr);
			if (lrh <= node_height(ll)) {	/* ll: RH+1 */
				RCU_INIT_POINTER(node->avl_left, lr);	/* lr: RH or RH+1 */
				RCU_INIT_POINTER(node->avl_right, r);	/* r: RH */
				node->avl_height = lrh + 1; /* RH+1 or RH+2 */
				RCU_INIT_POINTER(l->avl_left, ll);       /* ll: RH+1 */
				RCU_INIT_POINTER(l->avl_right, node);	/* node: RH+1 or RH+2 */
				l->avl_height = node->avl_height + 1;
				RCU_INIT_POINTER(*nodep, l);
			} else { /* ll: RH, lr: RH+1 */
				lrl = rcu_deref_locked(lr->avl_left, base);/* lrl: RH or RH-1 */
				lrr = rcu_deref_locked(lr->avl_right, base);/* lrr: RH or RH-1 */
				RCU_INIT_POINTER(node->avl_left, lrr);	/* lrr: RH or RH-1 */
				RCU_INIT_POINTER(node->avl_right, r);	/* r: RH */
				node->avl_height = rh + 1; /* node: RH+1 */
				RCU_INIT_POINTER(l->avl_left, ll);	/* ll: RH */
				RCU_INIT_POINTER(l->avl_right, lrl);	/* lrl: RH or RH-1 */
				l->avl_height = rh + 1;	/* l: RH+1 */
				RCU_INIT_POINTER(lr->avl_left, l);	/* l: RH+1 */
				RCU_INIT_POINTER(lr->avl_right, node);	/* node: RH+1 */
				lr->avl_height = rh + 2;
				RCU_INIT_POINTER(*nodep, lr);
			}
		} else if (rh > lh + 1) { /* r: LH+2 */
			struct inet_peer *rr, *rl, *rlr, *rll;
			int rlh;
			rr = r->avl_right;
			rl = r->avl_left;
			rlh = node_height(rl);
			if (rlh <= node_height(rr)) {	/* rr: LH+1 */
				node->avl_right = rl;	/* rl: LH or LH+1 */
				node->avl_left = l;	/* l: LH */
				node->avl_height = rlh + 1; /* LH+1 or LH+2 */
				r->avl_right = rr;	/* rr: LH+1 */
				r->avl_left = node;	/* node: LH+1 or LH+2 */
				r->avl_height = node->avl_height + 1;
				*nodep = r;
			} else { /* rr: RH, rl: RH+1 */
				rlr = rl->avl_right;	/* rlr: LH or LH-1 */
				rll = rl->avl_left;	/* rll: LH or LH-1 */
				node->avl_right = rll;	/* rll: LH or LH-1 */
				node->avl_left = l;	/* l: LH */
				node->avl_height = lh + 1; /* node: LH+1 */
				r->avl_right = rr;	/* rr: LH */
				r->avl_left = rlr;	/* rlr: LH or LH-1 */
				r->avl_height = lh + 1;	/* r: LH+1 */
				rl->avl_right = r;	/* r: LH+1 */
				rl->avl_left = node;	/* node: LH+1 */
				rl->avl_height = lh + 2;
				*nodep = rl;
			rr = rcu_deref_locked(r->avl_right, base);
			rl = rcu_deref_locked(r->avl_left, base);
			rlh = node_height(rl);
			if (rlh <= node_height(rr)) {	/* rr: LH+1 */
				RCU_INIT_POINTER(node->avl_right, rl);	/* rl: LH or LH+1 */
				RCU_INIT_POINTER(node->avl_left, l);	/* l: LH */
				node->avl_height = rlh + 1; /* LH+1 or LH+2 */
				RCU_INIT_POINTER(r->avl_right, rr);	/* rr: LH+1 */
				RCU_INIT_POINTER(r->avl_left, node);	/* node: LH+1 or LH+2 */
				r->avl_height = node->avl_height + 1;
				RCU_INIT_POINTER(*nodep, r);
			} else { /* rr: RH, rl: RH+1 */
				rlr = rcu_deref_locked(rl->avl_right, base);/* rlr: LH or LH-1 */
				rll = rcu_deref_locked(rl->avl_left, base);/* rll: LH or LH-1 */
				RCU_INIT_POINTER(node->avl_right, rll);	/* rll: LH or LH-1 */
				RCU_INIT_POINTER(node->avl_left, l);	/* l: LH */
				node->avl_height = lh + 1; /* node: LH+1 */
				RCU_INIT_POINTER(r->avl_right, rr);	/* rr: LH */
				RCU_INIT_POINTER(r->avl_left, rlr);	/* rlr: LH or LH-1 */
				r->avl_height = lh + 1;	/* r: LH+1 */
				RCU_INIT_POINTER(rl->avl_right, r);	/* r: LH+1 */
				RCU_INIT_POINTER(rl->avl_left, node);	/* node: LH+1 */
				rl->avl_height = lh + 2;
				RCU_INIT_POINTER(*nodep, rl);
			}
		} else {
			node->avl_height = (lh > rh ? lh : rh) + 1;
		}
	}
}

/* Called with local BH disabled and the pool write lock held. */
#define link_to_pool(n)						\
do {								\
	n->avl_height = 1;					\
	n->avl_left = peer_avl_empty;				\
	n->avl_right = peer_avl_empty;				\
	**--stackptr = n;					\
	peer_avl_rebalance(stack, stackptr);			\
} while(0)

/* May be called with local BH enabled. */
static void unlink_from_pool(struct inet_peer *p)
{
	int do_free;

	do_free = 0;

	write_lock_bh(&peer_pool_lock);
	/* Check the reference counter.  It was artificially incremented by 1
	 * in cleanup() function to prevent sudden disappearing.  If the
	 * reference count is still 1 then the node is referenced only as `p'
	 * here and from the pool.  So under the exclusive pool lock it's safe
	 * to remove the node and free it later. */
	if (atomic_read(&p->refcnt) == 1) {
		struct inet_peer **stack[PEER_MAXDEPTH];
		struct inet_peer ***stackptr, ***delp;
		if (lookup(p->v4daddr, stack) != p)
			BUG();
		delp = stackptr - 1; /* *delp[0] == p */
		if (p->avl_left == peer_avl_empty) {
			*delp[0] = p->avl_right;
			--stackptr;
		} else {
			/* look for a node to insert instead of p */
			struct inet_peer *t;
			t = lookup_rightempty(p);
			BUG_ON(*stackptr[-1] != t);
			**--stackptr = t->avl_left;
			/* t is removed, t->v4daddr > x->v4daddr for any
			 * x in p->avl_left subtree.
			 * Put t in the old place of p. */
			*delp[0] = t;
			t->avl_left = p->avl_left;
			t->avl_right = p->avl_right;
			t->avl_height = p->avl_height;
			BUG_ON(delp[1] != &p->avl_left);
			delp[1] = &t->avl_left; /* was &p->avl_left */
		}
		peer_avl_rebalance(stack, stackptr);
		peer_total--;
		do_free = 1;
	}
	write_unlock_bh(&peer_pool_lock);

	if (do_free)
		kmem_cache_free(peer_cachep, p);
	else
		/* The node is used again.  Decrease the reference counter
		 * back.  The loop "cleanup -> unlink_from_unused
		 *   -> unlink_from_pool -> putpeer -> link_to_unused
		 *   -> cleanup (for the same node)"
		 * doesn't really exist because the entry will have a
		 * recent deletion time and will not be cleaned again soon. */
		inet_putpeer(p);
}

/* May be called with local BH enabled. */
static int cleanup_once(unsigned long ttl)
{
	struct inet_peer *p = NULL;

	/* Remove the first entry from the list of unused nodes. */
	spin_lock_bh(&inet_peer_unused_lock);
	if (!list_empty(&unused_peers)) {
		__u32 delta;

		p = list_first_entry(&unused_peers, struct inet_peer, unused);
		delta = (__u32)jiffies - p->dtime;

		if (delta < ttl) {
			/* Do not prune fresh entries. */
			spin_unlock_bh(&inet_peer_unused_lock);
			return -1;
		}

		list_del_init(&p->unused);

		/* Grab an extra reference to prevent node disappearing
		 * before unlink_from_pool() call. */
		atomic_inc(&p->refcnt);
	}
	spin_unlock_bh(&inet_peer_unused_lock);

	if (p == NULL)
		/* It means that the total number of USED entries has
		 * grown over inet_peer_threshold.  It shouldn't really
		 * happen because of entry limits in route cache. */
		return -1;

	unlink_from_pool(p);
	return 0;
}

/* Called with or without local BH being disabled. */
struct inet_peer *inet_getpeer(__be32 daddr, int create)
{
	struct inet_peer *p, *n;
	struct inet_peer **stack[PEER_MAXDEPTH], ***stackptr;

	/* Look up for the address quickly. */
	read_lock_bh(&peer_pool_lock);
	p = lookup(daddr, NULL);
	if (p != peer_avl_empty)
		atomic_inc(&p->refcnt);
	read_unlock_bh(&peer_pool_lock);

	if (p != peer_avl_empty) {
		/* The existing node has been found. */
		/* Remove the entry from unused list if it was there. */
		unlink_from_unused(p);
		return p;
	}

	if (!create)
		return NULL;

	/* Allocate the space outside the locked region. */
	n = kmem_cache_alloc(peer_cachep, GFP_ATOMIC);
	if (n == NULL)
		return NULL;
	n->v4daddr = daddr;
	atomic_set(&n->refcnt, 1);
	atomic_set(&n->rid, 0);
	n->ip_id_count = secure_ip_id(daddr);
	n->tcp_ts_stamp = 0;

	write_lock_bh(&peer_pool_lock);
	/* Check if an entry has suddenly appeared. */
	p = lookup(daddr, stack);
	if (p != peer_avl_empty)
		goto out_free;

	/* Link the node. */
	link_to_pool(n);
	INIT_LIST_HEAD(&n->unused);
	peer_total++;
	write_unlock_bh(&peer_pool_lock);

	if (peer_total >= inet_peer_threshold)
		/* Remove one less-recently-used entry. */
		cleanup_once(0);

	return n;

out_free:
	/* The appropriate node is already in the pool. */
	atomic_inc(&p->refcnt);
	write_unlock_bh(&peer_pool_lock);
	/* Remove the entry from unused list if it was there. */
	unlink_from_unused(p);
	/* Free preallocated the preallocated node. */
	kmem_cache_free(peer_cachep, n);
	return p;
}

/* Called with local BH disabled. */
static void peer_check_expire(unsigned long dummy)
{
	unsigned long now = jiffies;
	int ttl;

	if (peer_total >= inet_peer_threshold)
		ttl = inet_peer_minttl;
	else
		ttl = inet_peer_maxttl
				- (inet_peer_maxttl - inet_peer_minttl) / HZ *
					peer_total / inet_peer_threshold * HZ;
	while (!cleanup_once(ttl)) {
		if (jiffies != now)
			break;
	}

	/* Trigger the timer after inet_peer_gc_mintime .. inet_peer_gc_maxtime
	 * interval depending on the total number of entries (more entries,
	 * less interval). */
	if (peer_total >= inet_peer_threshold)
		peer_periodic_timer.expires = jiffies + inet_peer_gc_mintime;
	else
		peer_periodic_timer.expires = jiffies
			+ inet_peer_gc_maxtime
			- (inet_peer_gc_maxtime - inet_peer_gc_mintime) / HZ *
				peer_total / inet_peer_threshold * HZ;
	add_timer(&peer_periodic_timer);
}

void inet_putpeer(struct inet_peer *p)
{
	spin_lock_bh(&inet_peer_unused_lock);
	if (atomic_dec_and_test(&p->refcnt)) {
		list_add_tail(&p->unused, &unused_peers);
		p->dtime = (__u32)jiffies;
	}
	spin_unlock_bh(&inet_peer_unused_lock);
}
/* Called with local BH disabled and the pool lock held. */
#define link_to_pool(n, base)					\
do {								\
	n->avl_height = 1;					\
	n->avl_left = peer_avl_empty_rcu;			\
	n->avl_right = peer_avl_empty_rcu;			\
	/* lockless readers can catch us now */			\
	rcu_assign_pointer(**--stackptr, n);			\
	peer_avl_rebalance(stack, stackptr, base);		\
} while (0)

static void inetpeer_free_rcu(struct rcu_head *head)
{
	kmem_cache_free(peer_cachep, container_of(head, struct inet_peer, rcu));
}

/* perform garbage collect on all items stacked during a lookup */
static void inet_peer_gc(struct inet_peer_base *base,
			 struct inet_peer *gc_stack[],
			 unsigned int gc_cnt)
{
	struct inet_peer *p;
	__u32 delta, ttl;
	int i;

	if (base->total >= inet_peer_threshold)
		ttl = 0; /* be aggressive */
	else
		ttl = inet_peer_maxttl
				- (inet_peer_maxttl - inet_peer_minttl) / HZ *
					base->total / inet_peer_threshold * HZ;
	for (i = 0; i < gc_cnt; i++) {
		p = gc_stack[i];
		delta = (__u32)jiffies - p->dtime;
		if (delta < ttl || !refcount_dec_if_one(&p->refcnt))
			gc_stack[i] = NULL;
	}
	for (i = 0; i < gc_cnt; i++) {
		p = gc_stack[i];
		if (p) {
			rb_erase(&p->rb_node, &base->rb_root);
			base->total--;
			call_rcu(&p->rcu, inetpeer_free_rcu);
		}
	}
}

struct inet_peer *inet_getpeer(struct inet_peer_base *base,
			       const struct inetpeer_addr *daddr,
			       int create)
{
	struct inet_peer *p, *gc_stack[PEER_MAX_GC];
	struct rb_node **pp, *parent;
	unsigned int gc_cnt, seq;
	int invalidated;

	/* Attempt a lockless lookup first.
	 * Because of a concurrent writer, we might not find an existing entry.
	 */
	rcu_read_lock();
	seq = read_seqbegin(&base->lock);
	p = lookup(daddr, base, seq, NULL, &gc_cnt, &parent, &pp);
	invalidated = read_seqretry(&base->lock, seq);
	rcu_read_unlock();

	if (p)
		return p;

	/* If no writer did a change during our lookup, we can return early. */
	if (!create && !invalidated)
		return NULL;

	/* retry an exact lookup, taking the lock before.
	 * At least, nodes should be hot in our cache.
	 */
	parent = NULL;
	write_seqlock_bh(&base->lock);

	gc_cnt = 0;
	p = lookup(daddr, base, seq, gc_stack, &gc_cnt, &parent, &pp);
	if (!p && create) {
		p = kmem_cache_alloc(peer_cachep, GFP_ATOMIC);
		if (p) {
			p->daddr = *daddr;
			p->dtime = (__u32)jiffies;
			refcount_set(&p->refcnt, 2);
			atomic_set(&p->rid, 0);
			p->metrics[RTAX_LOCK-1] = INETPEER_METRICS_NEW;
			p->rate_tokens = 0;
			p->n_redirects = 0;
			/* 60*HZ is arbitrary, but chosen enough high so that the first
			 * calculation of tokens is at its maximum.
			 */
			p->rate_last = jiffies - 60*HZ;

			rb_link_node(&p->rb_node, parent, pp);
			rb_insert_color(&p->rb_node, &base->rb_root);
			base->total++;
		}
	}
	if (gc_cnt)
		inet_peer_gc(base, gc_stack, gc_cnt);
	write_sequnlock_bh(&base->lock);

	return p;
}
EXPORT_SYMBOL_GPL(inet_getpeer);

void inet_putpeer(struct inet_peer *p)
{
	p->dtime = (__u32)jiffies;

	if (refcount_dec_and_test(&p->refcnt))
		call_rcu(&p->rcu, inetpeer_free_rcu);
}
EXPORT_SYMBOL_GPL(inet_putpeer);

/*
 *	Check transmit rate limitation for given message.
 *	The rate information is held in the inet_peer entries now.
 *	This function is generic and could be used for other purposes
 *	too. It uses a Token bucket filter as suggested by Alexey Kuznetsov.
 *
 *	Note that the same inet_peer fields are modified by functions in
 *	route.c too, but these work for packet destinations while xrlim_allow
 *	works for icmp destinations. This means the rate limiting information
 *	for one "ip object" is shared - and these ICMPs are twice limited:
 *	by source and by destination.
 *
 *	RFC 1812: 4.3.2.8 SHOULD be able to limit error message rate
 *			  SHOULD allow setting of rate limits
 *
 * 	Shared between ICMPv4 and ICMPv6.
 */
#define XRLIM_BURST_FACTOR 6
bool inet_peer_xrlim_allow(struct inet_peer *peer, int timeout)
{
	unsigned long now, token;
	bool rc = false;

	if (!peer)
		return true;

	token = peer->rate_tokens;
	now = jiffies;
	token += now - peer->rate_last;
	peer->rate_last = now;
	if (token > XRLIM_BURST_FACTOR * timeout)
		token = XRLIM_BURST_FACTOR * timeout;
	if (token >= timeout) {
		token -= timeout;
		rc = true;
	}
	peer->rate_tokens = token;
	return rc;
}
EXPORT_SYMBOL(inet_peer_xrlim_allow);

void inetpeer_invalidate_tree(struct inet_peer_base *base)
{
	struct rb_node *p = rb_first(&base->rb_root);

	while (p) {
		struct inet_peer *peer = rb_entry(p, struct inet_peer, rb_node);

		p = rb_next(p);
		rb_erase(&peer->rb_node, &base->rb_root);
		inet_putpeer(peer);
		cond_resched();
	}

	base->total = 0;
}
EXPORT_SYMBOL(inetpeer_invalidate_tree);
