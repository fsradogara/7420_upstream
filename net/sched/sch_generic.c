/*
 * net/sched/sch_generic.c	Generic packet scheduler routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *              Jamal Hadi Salim, <hadi@cyberus.ca> 990601
 *              - Ingress support
 */

#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <net/pkt_sched.h>
#include <linux/slab.h>
#include <linux/if_vlan.h>
#include <linux/skb_array.h>
#include <linux/if_macvlan.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/dst.h>
#include <trace/events/qdisc.h>
#include <net/xfrm.h>

/* Qdisc to use by default */
const struct Qdisc_ops *default_qdisc_ops = &pfifo_fast_ops;
EXPORT_SYMBOL(default_qdisc_ops);

/* Main transmission queue. */

/* Modifications to data participating in scheduling must be protected with
 * qdisc_lock(qdisc) spinlock.
 *
 * The idea is the following:
 * - enqueue, dequeue are serialized via qdisc root lock
 * - ingress filtering is also serialized via qdisc root lock
 * - updates to tree and tree walking are only done under the rtnl mutex.
 */

static inline int qdisc_qlen(struct Qdisc *q)
{
	return q->q.qlen;
}

static inline int dev_requeue_skb(struct sk_buff *skb, struct Qdisc *q)
{
	if (unlikely(skb->next))
		q->gso_skb = skb;
	else
		q->ops->requeue(skb, q);

	__netif_schedule(q);
	return 0;
}

static inline struct sk_buff *dequeue_skb(struct Qdisc *q)
{
	struct sk_buff *skb;

	if ((skb = q->gso_skb))
		q->gso_skb = NULL;
	else
		skb = q->dequeue(q);

static inline int dev_requeue_skb(struct sk_buff *skb, struct Qdisc *q)
static inline struct sk_buff *__skb_dequeue_bad_txq(struct Qdisc *q)
{
	const struct netdev_queue *txq = q->dev_queue;
	spinlock_t *lock = NULL;
	struct sk_buff *skb;

	if (q->flags & TCQ_F_NOLOCK) {
		lock = qdisc_lock(q);
		spin_lock(lock);
	}

	skb = skb_peek(&q->skb_bad_txq);
	if (skb) {
		/* check the reason of requeuing without tx lock first */
		txq = skb_get_tx_queue(txq->dev, skb);
		if (!netif_xmit_frozen_or_stopped(txq)) {
			skb = __skb_dequeue(&q->skb_bad_txq);
			if (qdisc_is_percpu_stats(q)) {
				qdisc_qstats_cpu_backlog_dec(q, skb);
				qdisc_qstats_atomic_qlen_dec(q);
			} else {
				qdisc_qstats_backlog_dec(q, skb);
				q->q.qlen--;
			}
		} else {
			skb = NULL;
		}
	}

	if (lock)
		spin_unlock(lock);

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_skb_bad_txq(struct Qdisc *q)
{
	struct sk_buff *skb = skb_peek(&q->skb_bad_txq);

	if (unlikely(skb))
		skb = __skb_dequeue_bad_txq(q);

	return skb;
}

static inline void qdisc_enqueue_skb_bad_txq(struct Qdisc *q,
					     struct sk_buff *skb)
{
	spinlock_t *lock = NULL;

	if (q->flags & TCQ_F_NOLOCK) {
		lock = qdisc_lock(q);
		spin_lock(lock);
	}

	__skb_queue_tail(&q->skb_bad_txq, skb);

	if (qdisc_is_percpu_stats(q)) {
		qdisc_qstats_cpu_backlog_inc(q, skb);
		qdisc_qstats_atomic_qlen_inc(q);
	} else {
		qdisc_qstats_backlog_inc(q, skb);
		q->q.qlen++;
	}

	if (lock)
		spin_unlock(lock);
}

static inline int __dev_requeue_skb(struct sk_buff *skb, struct Qdisc *q)
{
	while (skb) {
		struct sk_buff *next = skb->next;

		__skb_queue_tail(&q->gso_skb, skb);
		q->qstats.requeues++;
		qdisc_qstats_backlog_inc(q, skb);
		q->q.qlen++;	/* it's still part of the queue */

		skb = next;
	}
	__netif_schedule(q);

	return 0;
}

static inline int dev_requeue_skb_locked(struct sk_buff *skb, struct Qdisc *q)
{
	spinlock_t *lock = qdisc_lock(q);

	spin_lock(lock);
	while (skb) {
		struct sk_buff *next = skb->next;

		__skb_queue_tail(&q->gso_skb, skb);

		qdisc_qstats_cpu_requeues_inc(q);
		qdisc_qstats_cpu_backlog_inc(q, skb);
		qdisc_qstats_atomic_qlen_inc(q);

		skb = next;
	}
	spin_unlock(lock);

	__netif_schedule(q);

	return 0;
}

static inline int dev_requeue_skb(struct sk_buff *skb, struct Qdisc *q)
{
	if (q->flags & TCQ_F_NOLOCK)
		return dev_requeue_skb_locked(skb, q);
	else
		return __dev_requeue_skb(skb, q);
}

static void try_bulk_dequeue_skb(struct Qdisc *q,
				 struct sk_buff *skb,
				 const struct netdev_queue *txq,
				 int *packets)
{
	int bytelimit = qdisc_avail_bulklimit(txq) - skb->len;

	while (bytelimit > 0) {
		struct sk_buff *nskb = q->dequeue(q);

		if (!nskb)
			break;

		bytelimit -= nskb->len; /* covers GSO len */
		skb->next = nskb;
		skb = nskb;
		(*packets)++; /* GSO counts as one pkt */
	}
	skb->next = NULL;
}

/* This variant of try_bulk_dequeue_skb() makes sure
 * all skbs in the chain are for the same txq
 */
static void try_bulk_dequeue_skb_slow(struct Qdisc *q,
				      struct sk_buff *skb,
				      int *packets)
{
	int mapping = skb_get_queue_mapping(skb);
	struct sk_buff *nskb;
	int cnt = 0;

	do {
		nskb = q->dequeue(q);
		if (!nskb)
			break;
		if (unlikely(skb_get_queue_mapping(nskb) != mapping)) {
			qdisc_enqueue_skb_bad_txq(q, nskb);
			break;
		}
		skb->next = nskb;
		skb = nskb;
	} while (++cnt < 8);
	(*packets) += cnt;
	skb->next = NULL;
}

/* Note that dequeue_skb can possibly return a SKB list (via skb->next).
 * A requeued skb (via q->gso_skb) can also be a SKB list.
 */
static struct sk_buff *dequeue_skb(struct Qdisc *q, bool *validate,
				   int *packets)
{
	const struct netdev_queue *txq = q->dev_queue;
	struct sk_buff *skb = NULL;

	*packets = 1;
	if (unlikely(!skb_queue_empty(&q->gso_skb))) {
		spinlock_t *lock = NULL;

		if (q->flags & TCQ_F_NOLOCK) {
			lock = qdisc_lock(q);
			spin_lock(lock);
		}

		skb = skb_peek(&q->gso_skb);

		/* skb may be null if another cpu pulls gso_skb off in between
		 * empty check and lock.
		 */
		if (!skb) {
			if (lock)
				spin_unlock(lock);
			goto validate;
		}

		/* skb in gso_skb were already validated */
		*validate = false;
		if (xfrm_offload(skb))
			*validate = true;
		/* check the reason of requeuing without tx lock first */
		txq = skb_get_tx_queue(txq->dev, skb);
		if (!netif_xmit_frozen_or_stopped(txq)) {
			skb = __skb_dequeue(&q->gso_skb);
			if (qdisc_is_percpu_stats(q)) {
				qdisc_qstats_cpu_backlog_dec(q, skb);
				qdisc_qstats_atomic_qlen_dec(q);
			} else {
				qdisc_qstats_backlog_dec(q, skb);
				q->q.qlen--;
			}
		} else {
			skb = NULL;
		}
		if (lock)
			spin_unlock(lock);
		goto trace;
	}
validate:
	*validate = true;

	if ((q->flags & TCQ_F_ONETXQUEUE) &&
	    netif_xmit_frozen_or_stopped(txq))
		return skb;

	skb = qdisc_dequeue_skb_bad_txq(q);
	if (unlikely(skb))
		goto bulk;
	skb = q->dequeue(q);
	if (skb) {
bulk:
		if (qdisc_may_bulk(q))
			try_bulk_dequeue_skb(q, skb, txq, packets);
		else
			try_bulk_dequeue_skb_slow(q, skb, packets);
	}
trace:
	trace_qdisc_dequeue(q, txq, *packets, skb);
	return skb;
}

static inline int handle_dev_cpu_collision(struct sk_buff *skb,
					   struct netdev_queue *dev_queue,
					   struct Qdisc *q)
{
	int ret;

	if (unlikely(dev_queue->xmit_lock_owner == smp_processor_id())) {
		/*
		 * Same CPU holding the lock. It may be a transient
		 * configuration error, when hard_start_xmit() recurses. We
		 * detect it by checking xmit owner and drop the packet when
		 * deadloop is detected. Return OK to try the next skb.
		 */
		kfree_skb(skb);
		if (net_ratelimit())
			printk(KERN_WARNING "Dead loop on netdevice %s, "
			       "fix it urgently!\n", dev_queue->dev->name);
		kfree_skb_list(skb);
		net_warn_ratelimited("Dead loop on netdevice %s, fix it urgently!\n",
				     dev_queue->dev->name);
		ret = qdisc_qlen(q);
	} else {
		/*
		 * Another cpu is holding lock, requeue & delay xmits for
		 * some time.
		 */
		__get_cpu_var(netdev_rx_stat).cpu_collision++;
		__this_cpu_inc(softnet_data.cpu_collision);
		ret = dev_requeue_skb(skb, q);
	}

	return ret;
}

/*
 * NOTE: Called under qdisc_lock(q) with locally disabled BH.
 *
 * __QDISC_STATE_RUNNING guarantees only one CPU can process
 * Transmit possibly several skbs, and handle the return status as
 * required. Owning running seqcount bit guarantees that
 * only one CPU can execute this function.
 *
 * Returns to the caller:
 *				false  - hardware queue frozen backoff
 *				true   - feel free to send more pkts
 */
bool sch_direct_xmit(struct sk_buff *skb, struct Qdisc *q,
		     struct net_device *dev, struct netdev_queue *txq,
		     spinlock_t *root_lock, bool validate)
{
	int ret = NETDEV_TX_BUSY;
	bool again = false;

	/* And release qdisc */
	if (root_lock)
		spin_unlock(root_lock);

	/* Note that we validate skb (GSO, checksum, ...) outside of locks */
	if (validate)
		skb = validate_xmit_skb_list(skb, dev, &again);

#ifdef CONFIG_XFRM_OFFLOAD
	if (unlikely(again)) {
		if (root_lock)
			spin_lock(root_lock);

		dev_requeue_skb(skb, q);
		return false;
	}
#endif

	if (likely(skb)) {
		HARD_TX_LOCK(dev, txq, smp_processor_id());
		if (!netif_xmit_frozen_or_stopped(txq))
			skb = dev_hard_start_xmit(skb, dev, txq, &ret);

		HARD_TX_UNLOCK(dev, txq);
	} else {
		if (root_lock)
			spin_lock(root_lock);
		return true;
	}

	if (root_lock)
		spin_lock(root_lock);

	if (!dev_xmit_complete(ret)) {
		/* Driver returned NETDEV_TX_BUSY - requeue skb */
		if (unlikely(ret != NETDEV_TX_BUSY))
			net_warn_ratelimited("BUG %s code %d qlen %d\n",
					     dev->name, ret, q->q.qlen);

		dev_requeue_skb(skb, q);
		return false;
	}

	return true;
}

/*
 * NOTE: Called under qdisc_lock(q) with locally disabled BH.
 *
 * running seqcount guarantees only one CPU can process
 * this qdisc at a time. qdisc_lock(q) serializes queue accesses for
 * this queue.
 *
 *  netif_tx_lock serializes accesses to device driver.
 *
 *  qdisc_lock(q) and netif_tx_lock are mutually exclusive,
 *  if one is grabbed, another must be free.
 *
 * Note, that this procedure can be called by a watchdog timer
 *
 * Returns to the caller:
 *				0  - queue is empty or throttled.
 *				>0 - queue is not empty.
 *
 */
static inline int qdisc_restart(struct Qdisc *q)
{
	struct netdev_queue *txq;
	int ret = NETDEV_TX_BUSY;
	struct net_device *dev;
	spinlock_t *root_lock;
	struct sk_buff *skb;

	/* Dequeue packet */
	if (unlikely((skb = dequeue_skb(q)) == NULL))
		return 0;

	root_lock = qdisc_lock(q);

	/* And release qdisc */
	spin_unlock(root_lock);

	dev = qdisc_dev(q);
	txq = netdev_get_tx_queue(dev, skb_get_queue_mapping(skb));

	HARD_TX_LOCK(dev, txq, smp_processor_id());
	if (!netif_tx_queue_stopped(txq) &&
	    !netif_tx_queue_frozen(txq))
		ret = dev_hard_start_xmit(skb, dev, txq);
	HARD_TX_UNLOCK(dev, txq);

	spin_lock(root_lock);

	switch (ret) {
	case NETDEV_TX_OK:
		/* Driver sent out skb successfully */
		ret = qdisc_qlen(q);
		break;

	case NETDEV_TX_LOCKED:
		/* Driver try lock failed */
		ret = handle_dev_cpu_collision(skb, txq, q);
		break;

	default:
		/* Driver returned NETDEV_TX_BUSY - requeue skb */
		if (unlikely (ret != NETDEV_TX_BUSY && net_ratelimit()))
			printk(KERN_WARNING "BUG %s code %d qlen %d\n",
			       dev->name, ret, q->q.qlen);

		ret = dev_requeue_skb(skb, q);
		break;
	}

	if (ret && (netif_tx_queue_stopped(txq) ||
		    netif_tx_queue_frozen(txq)))
		ret = 0;

	return ret;
static inline int qdisc_restart(struct Qdisc *q, int *packets)
static inline bool qdisc_restart(struct Qdisc *q, int *packets)
{
	spinlock_t *root_lock = NULL;
	struct netdev_queue *txq;
	struct net_device *dev;
	struct sk_buff *skb;
	bool validate;

	/* Dequeue packet */
	skb = dequeue_skb(q, &validate, packets);
	if (unlikely(!skb))
		return false;

	if (!(q->flags & TCQ_F_NOLOCK))
		root_lock = qdisc_lock(q);

	dev = qdisc_dev(q);
	txq = skb_get_tx_queue(dev, skb);

	return sch_direct_xmit(skb, q, dev, txq, root_lock, validate);
}

void __qdisc_run(struct Qdisc *q)
{
	unsigned long start_time = jiffies;

	while (qdisc_restart(q)) {
		/*
		 * Postpone processing if
		 * 1. another process needs the CPU;
		 * 2. we've been doing it for too long.
		 */
		if (need_resched() || jiffies != start_time) {
	int quota = weight_p;
	int quota = dev_tx_weight;
	int packets;

	while (qdisc_restart(q, &packets)) {
		/*
		 * Ordered by possible occurrence: Postpone processing if
		 * 1. we've exceeded packet quota
		 * 2. another process needs the CPU;
		 */
		quota -= packets;
		if (quota <= 0 || need_resched()) {
			__netif_schedule(q);
			break;
		}
	}

	clear_bit(__QDISC_STATE_RUNNING, &q->state);
}

	qdisc_run_end(q);
}

unsigned long dev_trans_start(struct net_device *dev)
{
	unsigned long val, res;
	unsigned int i;

	if (is_vlan_dev(dev))
		dev = vlan_dev_real_dev(dev);
	else if (netif_is_macvlan(dev))
		dev = macvlan_dev_real_dev(dev);
	res = netdev_get_tx_queue(dev, 0)->trans_start;
	for (i = 1; i < dev->num_tx_queues; i++) {
		val = netdev_get_tx_queue(dev, i)->trans_start;
		if (val && time_after(val, res))
			res = val;
	}

	return res;
}
EXPORT_SYMBOL(dev_trans_start);

static void dev_watchdog(struct timer_list *t)
{
	struct net_device *dev = from_timer(dev, t, watchdog_timer);

	netif_tx_lock(dev);
	if (!qdisc_tx_is_noop(dev)) {
		if (netif_device_present(dev) &&
		    netif_running(dev) &&
		    netif_carrier_ok(dev)) {
			int some_queue_stopped = 0;
			unsigned int i;
			int some_queue_timedout = 0;
			unsigned int i;
			unsigned long trans_start;

			for (i = 0; i < dev->num_tx_queues; i++) {
				struct netdev_queue *txq;

				txq = netdev_get_tx_queue(dev, i);
				if (netif_tx_queue_stopped(txq)) {
					some_queue_stopped = 1;
				/*
				 * old device drivers set dev->trans_start
				 */
				trans_start = txq->trans_start ? : dev->trans_start;
				trans_start = txq->trans_start;
				if (netif_xmit_stopped(txq) &&
				    time_after(jiffies, (trans_start +
							 dev->watchdog_timeo))) {
					some_queue_timedout = 1;
					txq->trans_timeout++;
					break;
				}
			}

			if (some_queue_stopped &&
			    time_after(jiffies, (dev->trans_start +
						 dev->watchdog_timeo))) {
				char drivername[64];
				WARN_ONCE(1, KERN_INFO "NETDEV WATCHDOG: %s (%s): transmit timed out\n",
				       dev->name, netdev_drivername(dev, drivername, 64));
				dev->tx_timeout(dev);
			if (some_queue_timedout) {
				WARN_ONCE(1, KERN_INFO "NETDEV WATCHDOG: %s (%s): transmit queue %u timed out\n",
				       dev->name, netdev_drivername(dev), i);
				dev->netdev_ops->ndo_tx_timeout(dev);
			}
			if (!mod_timer(&dev->watchdog_timer,
				       round_jiffies(jiffies +
						     dev->watchdog_timeo)))
				dev_hold(dev);
		}
	}
	netif_tx_unlock(dev);

	dev_put(dev);
}

void __netdev_watchdog_up(struct net_device *dev)
{
	if (dev->tx_timeout) {
	if (dev->netdev_ops->ndo_tx_timeout) {
		if (dev->watchdog_timeo <= 0)
			dev->watchdog_timeo = 5*HZ;
		if (!mod_timer(&dev->watchdog_timer,
			       round_jiffies(jiffies + dev->watchdog_timeo)))
			dev_hold(dev);
	}
}

static void dev_watchdog_up(struct net_device *dev)
{
	__netdev_watchdog_up(dev);
}

static void dev_watchdog_down(struct net_device *dev)
{
	netif_tx_lock_bh(dev);
	if (del_timer(&dev->watchdog_timer))
		dev_put(dev);
	netif_tx_unlock_bh(dev);
}

/**
 *	netif_carrier_on - set carrier
 *	@dev: network device
 *
 * Device has detected that carrier.
 */
void netif_carrier_on(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_NOCARRIER, &dev->state)) {
		if (dev->reg_state == NETREG_UNINITIALIZED)
			return;
		atomic_inc(&dev->carrier_up_count);
		linkwatch_fire_event(dev);
		if (netif_running(dev))
			__netdev_watchdog_up(dev);
	}
}
EXPORT_SYMBOL(netif_carrier_on);

/**
 *	netif_carrier_off - clear carrier
 *	@dev: network device
 *
 * Device has detected loss of carrier.
 */
void netif_carrier_off(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_NOCARRIER, &dev->state))
		linkwatch_fire_event(dev);
	if (!test_and_set_bit(__LINK_STATE_NOCARRIER, &dev->state)) {
		if (dev->reg_state == NETREG_UNINITIALIZED)
			return;
		atomic_inc(&dev->carrier_down_count);
		linkwatch_fire_event(dev);
	}
}
EXPORT_SYMBOL(netif_carrier_off);

/* "NOOP" scheduler: the best scheduler, recommended for all interfaces
   under all circumstances. It is difficult to invent anything faster or
   cheaper.
 */

static int noop_enqueue(struct sk_buff *skb, struct Qdisc * qdisc)
static int noop_enqueue(struct sk_buff *skb, struct Qdisc *qdisc)
static int noop_enqueue(struct sk_buff *skb, struct Qdisc *qdisc,
			struct sk_buff **to_free)
{
	__qdisc_drop(skb, to_free);
	return NET_XMIT_CN;
}

static struct sk_buff *noop_dequeue(struct Qdisc * qdisc)
static struct sk_buff *noop_dequeue(struct Qdisc *qdisc)
{
	return NULL;
}

static int noop_requeue(struct sk_buff *skb, struct Qdisc* qdisc)
{
	if (net_ratelimit())
		printk(KERN_DEBUG "%s deferred output. It is buggy.\n",
		       skb->dev->name);
	kfree_skb(skb);
	return NET_XMIT_CN;
}

struct Qdisc_ops noop_qdisc_ops __read_mostly = {
	.id		=	"noop",
	.priv_size	=	0,
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.requeue	=	noop_requeue,
	.peek		=	noop_dequeue,
	.owner		=	THIS_MODULE,
};

static struct netdev_queue noop_netdev_queue = {
	.qdisc		=	&noop_qdisc,
	.qdisc_sleeping	=	&noop_qdisc,
};

struct Qdisc noop_qdisc = {
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.flags		=	TCQ_F_BUILTIN,
	.ops		=	&noop_qdisc_ops,
	.q.lock		=	__SPIN_LOCK_UNLOCKED(noop_qdisc.q.lock),
	.dev_queue	=	&noop_netdev_queue,
};
EXPORT_SYMBOL(noop_qdisc);

static struct Qdisc_ops noqueue_qdisc_ops __read_mostly = {
	.id		=	"noqueue",
	.priv_size	=	0,
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.requeue	=	noop_requeue,
	.owner		=	THIS_MODULE,
};

static struct Qdisc noqueue_qdisc;
static struct netdev_queue noqueue_netdev_queue = {
	.qdisc		=	&noqueue_qdisc,
};

static struct Qdisc noqueue_qdisc = {
	.enqueue	=	NULL,
	.dequeue	=	noop_dequeue,
	.flags		=	TCQ_F_BUILTIN,
	.ops		=	&noqueue_qdisc_ops,
	.list		=	LIST_HEAD_INIT(noqueue_qdisc.list),
	.q.lock		=	__SPIN_LOCK_UNLOCKED(noqueue_qdisc.q.lock),
	.dev_queue	=	&noqueue_netdev_queue,
};


static const u8 prio2band[TC_PRIO_MAX+1] =
	{ 1, 2, 2, 2, 1, 2, 0, 0 , 1, 1, 1, 1, 1, 1, 1, 1 };

	.running	=	SEQCNT_ZERO(noop_qdisc.running),
	.busylock	=	__SPIN_LOCK_UNLOCKED(noop_qdisc.busylock),
};
EXPORT_SYMBOL(noop_qdisc);

static int noqueue_init(struct Qdisc *qdisc, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	/* register_qdisc() assigns a default of noop_enqueue if unset,
	 * but __dev_queue_xmit() treats noqueue only as such
	 * if this is NULL - so clear it here. */
	qdisc->enqueue = NULL;
	return 0;
}

struct Qdisc_ops noqueue_qdisc_ops __read_mostly = {
	.id		=	"noqueue",
	.priv_size	=	0,
	.init		=	noqueue_init,
	.enqueue	=	noop_enqueue,
	.dequeue	=	noop_dequeue,
	.peek		=	noop_dequeue,
	.owner		=	THIS_MODULE,
};

static const u8 prio2band[TC_PRIO_MAX + 1] = {
	1, 2, 2, 2, 1, 2, 0, 0 , 1, 1, 1, 1, 1, 1, 1, 1
};

/* 3-band FIFO queue: old style, but should be a bit faster than
   generic prio+fifo combination.
 */

#define PFIFO_FAST_BANDS 3

static inline struct sk_buff_head *prio2list(struct sk_buff *skb,
					     struct Qdisc *qdisc)
{
	struct sk_buff_head *list = qdisc_priv(qdisc);
	return list + prio2band[skb->priority & TC_PRIO_MAX];
}

static int pfifo_fast_enqueue(struct sk_buff *skb, struct Qdisc* qdisc)
{
	struct sk_buff_head *list = prio2list(skb, qdisc);

	if (skb_queue_len(list) < qdisc_dev(qdisc)->tx_queue_len) {
/*
 * Private data for a pfifo_fast scheduler containing:
 *	- rings for priority bands
 */
struct pfifo_fast_priv {
	struct skb_array q[PFIFO_FAST_BANDS];
};

static inline struct skb_array *band2list(struct pfifo_fast_priv *priv,
					  int band)
{
	return &priv->q[band];
}

static int pfifo_fast_enqueue(struct sk_buff *skb, struct Qdisc *qdisc,
			      struct sk_buff **to_free)
{
	int band = prio2band[skb->priority & TC_PRIO_MAX];
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	struct skb_array *q = band2list(priv, band);
	unsigned int pkt_len = qdisc_pkt_len(skb);
	int err;

	err = skb_array_produce(q, skb);

	if (unlikely(err))
		return qdisc_drop_cpu(skb, qdisc, to_free);

	qdisc_qstats_atomic_qlen_inc(qdisc);
	/* Note: skb can not be used after skb_array_produce(),
	 * so we better not use qdisc_qstats_cpu_backlog_inc()
	 */
	this_cpu_add(qdisc->cpu_qstats->backlog, pkt_len);
	return NET_XMIT_SUCCESS;
}

static struct sk_buff *pfifo_fast_dequeue(struct Qdisc* qdisc)
{
	int prio;
	struct sk_buff_head *list = qdisc_priv(qdisc);

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++) {
		if (!skb_queue_empty(list + prio)) {
			qdisc->q.qlen--;
			return __qdisc_dequeue_head(qdisc, list + prio);
		}
static struct sk_buff *pfifo_fast_dequeue(struct Qdisc *qdisc)
{
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	struct sk_buff *skb = NULL;
	int band;

	for (band = 0; band < PFIFO_FAST_BANDS && !skb; band++) {
		struct skb_array *q = band2list(priv, band);

		if (__skb_array_empty(q))
			continue;

		skb = __skb_array_consume(q);
	}
	if (likely(skb)) {
		qdisc_qstats_cpu_backlog_dec(qdisc, skb);
		qdisc_bstats_cpu_update(qdisc, skb);
		qdisc_qstats_atomic_qlen_dec(qdisc);
	}

	return skb;
}

static int pfifo_fast_requeue(struct sk_buff *skb, struct Qdisc* qdisc)
{
	qdisc->q.qlen++;
	return __qdisc_requeue(skb, qdisc, prio2list(skb, qdisc));
}

static void pfifo_fast_reset(struct Qdisc* qdisc)
{
	int prio;
	struct sk_buff_head *list = qdisc_priv(qdisc);

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++)
		__qdisc_reset_queue(qdisc, list + prio);

static struct sk_buff *pfifo_fast_peek(struct Qdisc *qdisc)
{
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	struct sk_buff *skb = NULL;
	int band;

	for (band = 0; band < PFIFO_FAST_BANDS && !skb; band++) {
		struct skb_array *q = band2list(priv, band);

		skb = __skb_array_peek(q);
	}

	return skb;
}

static void pfifo_fast_reset(struct Qdisc *qdisc)
{
	int i, band;
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);

	for (band = 0; band < PFIFO_FAST_BANDS; band++) {
		struct skb_array *q = band2list(priv, band);
		struct sk_buff *skb;

		/* NULL ring is possible if destroy path is due to a failed
		 * skb_array_init() in pfifo_fast_init() case.
		 */
		if (!q->ring.queue)
			continue;

		while ((skb = __skb_array_consume(q)) != NULL)
			kfree_skb(skb);
	}

	for_each_possible_cpu(i) {
		struct gnet_stats_queue *q = per_cpu_ptr(qdisc->cpu_qstats, i);

		q->backlog = 0;
	}
}

static int pfifo_fast_dump(struct Qdisc *qdisc, struct sk_buff *skb)
{
	struct tc_prio_qopt opt = { .bands = PFIFO_FAST_BANDS };

	memcpy(&opt.priomap, prio2band, TC_PRIO_MAX+1);
	NLA_PUT(skb, TCA_OPTIONS, sizeof(opt), &opt);
	memcpy(&opt.priomap, prio2band, TC_PRIO_MAX + 1);
	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	return -1;
}

static int pfifo_fast_init(struct Qdisc *qdisc, struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	int prio;
	struct sk_buff_head *list = qdisc_priv(qdisc);

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++)
		skb_queue_head_init(list + prio);

	return 0;
}

static struct Qdisc_ops pfifo_fast_ops __read_mostly = {
	.id		=	"pfifo_fast",
	.priv_size	=	PFIFO_FAST_BANDS * sizeof(struct sk_buff_head),
	.enqueue	=	pfifo_fast_enqueue,
	.dequeue	=	pfifo_fast_dequeue,
	.requeue	=	pfifo_fast_requeue,
	unsigned int qlen = qdisc_dev(qdisc)->tx_queue_len;
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	int prio;

	/* guard against zero length rings */
	if (!qlen)
		return -EINVAL;

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++) {
		struct skb_array *q = band2list(priv, prio);
		int err;

		err = skb_array_init(q, qlen, GFP_KERNEL);
		if (err)
			return -ENOMEM;
	}

	/* Can by-pass the queue discipline */
	qdisc->flags |= TCQ_F_CAN_BYPASS;
	return 0;
}

static void pfifo_fast_destroy(struct Qdisc *sch)
{
	struct pfifo_fast_priv *priv = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++) {
		struct skb_array *q = band2list(priv, prio);

		/* NULL ring is possible if destroy path is due to a failed
		 * skb_array_init() in pfifo_fast_init() case.
		 */
		if (!q->ring.queue)
			continue;
		/* Destroy ring but no need to kfree_skb because a call to
		 * pfifo_fast_reset() has already done that work.
		 */
		ptr_ring_cleanup(&q->ring, NULL);
	}
}

static int pfifo_fast_change_tx_queue_len(struct Qdisc *sch,
					  unsigned int new_len)
{
	struct pfifo_fast_priv *priv = qdisc_priv(sch);
	struct skb_array *bands[PFIFO_FAST_BANDS];
	int prio;

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++) {
		struct skb_array *q = band2list(priv, prio);

		bands[prio] = q;
	}

	return skb_array_resize_multiple(bands, PFIFO_FAST_BANDS, new_len,
					 GFP_KERNEL);
}

struct Qdisc_ops pfifo_fast_ops __read_mostly = {
	.id		=	"pfifo_fast",
	.priv_size	=	sizeof(struct pfifo_fast_priv),
	.enqueue	=	pfifo_fast_enqueue,
	.dequeue	=	pfifo_fast_dequeue,
	.peek		=	pfifo_fast_peek,
	.init		=	pfifo_fast_init,
	.destroy	=	pfifo_fast_destroy,
	.reset		=	pfifo_fast_reset,
	.dump		=	pfifo_fast_dump,
	.change_tx_queue_len =  pfifo_fast_change_tx_queue_len,
	.owner		=	THIS_MODULE,
	.static_flags	=	TCQ_F_NOLOCK | TCQ_F_CPUSTATS,
};
EXPORT_SYMBOL(pfifo_fast_ops);

struct Qdisc *qdisc_alloc(struct netdev_queue *dev_queue,
			  struct Qdisc_ops *ops)
{
	void *p;
	struct Qdisc *sch;
	unsigned int size;
	int err = -ENOBUFS;

	/* ensure that the Qdisc and the private data are 32-byte aligned */
	size = QDISC_ALIGN(sizeof(*sch));
	size += ops->priv_size + (QDISC_ALIGNTO - 1);

	p = kzalloc(size, GFP_KERNEL);
	if (!p)
		goto errout;
	sch = (struct Qdisc *) QDISC_ALIGN((unsigned long) p);
	sch->padded = (char *) sch - (char *) p;

	INIT_LIST_HEAD(&sch->list);
	skb_queue_head_init(&sch->q);
static struct lock_class_key qdisc_tx_busylock;
static struct lock_class_key qdisc_running_key;

struct Qdisc *qdisc_alloc(struct netdev_queue *dev_queue,
			  const struct Qdisc_ops *ops,
			  struct netlink_ext_ack *extack)
{
	void *p;
	struct Qdisc *sch;
	unsigned int size = QDISC_ALIGN(sizeof(*sch)) + ops->priv_size;
	int err = -ENOBUFS;
	struct net_device *dev;

	if (!dev_queue) {
		NL_SET_ERR_MSG(extack, "No device queue given");
		err = -EINVAL;
		goto errout;
	}

	dev = dev_queue->dev;
	p = kzalloc_node(size, GFP_KERNEL,
			 netdev_queue_numa_node_read(dev_queue));

	if (!p)
		goto errout;
	sch = (struct Qdisc *) QDISC_ALIGN((unsigned long) p);
	/* if we got non aligned memory, ask more and do alignment ourself */
	if (sch != p) {
		kfree(p);
		p = kzalloc_node(size + QDISC_ALIGNTO - 1, GFP_KERNEL,
				 netdev_queue_numa_node_read(dev_queue));
		if (!p)
			goto errout;
		sch = (struct Qdisc *) QDISC_ALIGN((unsigned long) p);
		sch->padded = (char *) sch - (char *) p;
	}
	__skb_queue_head_init(&sch->gso_skb);
	__skb_queue_head_init(&sch->skb_bad_txq);
	qdisc_skb_head_init(&sch->q);
	spin_lock_init(&sch->q.lock);

	if (ops->static_flags & TCQ_F_CPUSTATS) {
		sch->cpu_bstats =
			netdev_alloc_pcpu_stats(struct gnet_stats_basic_cpu);
		if (!sch->cpu_bstats)
			goto errout1;

		sch->cpu_qstats = alloc_percpu(struct gnet_stats_queue);
		if (!sch->cpu_qstats) {
			free_percpu(sch->cpu_bstats);
			goto errout1;
		}
	}

	spin_lock_init(&sch->busylock);
	lockdep_set_class(&sch->busylock,
			  dev->qdisc_tx_busylock ?: &qdisc_tx_busylock);

	/* seqlock has the same scope of busylock, for NOLOCK qdisc */
	spin_lock_init(&sch->seqlock);
	lockdep_set_class(&sch->busylock,
			  dev->qdisc_tx_busylock ?: &qdisc_tx_busylock);

	seqcount_init(&sch->running);
	lockdep_set_class(&sch->running,
			  dev->qdisc_running_key ?: &qdisc_running_key);

	sch->ops = ops;
	sch->flags = ops->static_flags;
	sch->enqueue = ops->enqueue;
	sch->dequeue = ops->dequeue;
	sch->dev_queue = dev_queue;
	dev_hold(qdisc_dev(sch));
	dev_hold(dev);
	refcount_set(&sch->refcnt, 1);

	return sch;
errout1:
	kfree(p);
errout:
	return ERR_PTR(err);
}

struct Qdisc * qdisc_create_dflt(struct net_device *dev,
				 struct netdev_queue *dev_queue,
				 struct Qdisc_ops *ops,
				 unsigned int parentid)
{
	struct Qdisc *sch;

struct Qdisc *qdisc_create_dflt(struct netdev_queue *dev_queue,
				const struct Qdisc_ops *ops,
				unsigned int parentid,
				struct netlink_ext_ack *extack)
{
	struct Qdisc *sch;

	if (!try_module_get(ops->owner)) {
		NL_SET_ERR_MSG(extack, "Failed to increase module reference counter");
		return NULL;
	}

	sch = qdisc_alloc(dev_queue, ops, extack);
	if (IS_ERR(sch)) {
		module_put(ops->owner);
		return NULL;
	}
	sch->parent = parentid;

	if (!ops->init || ops->init(sch, NULL, extack) == 0)
		return sch;

	qdisc_destroy(sch);
	return NULL;
}
EXPORT_SYMBOL(qdisc_create_dflt);

/* Under qdisc_lock(qdisc) and BH! */

void qdisc_reset(struct Qdisc *qdisc)
{
	const struct Qdisc_ops *ops = qdisc->ops;
	struct sk_buff *skb, *tmp;

	if (ops->reset)
		ops->reset(qdisc);
}
EXPORT_SYMBOL(qdisc_reset);


	skb_queue_walk_safe(&qdisc->gso_skb, skb, tmp) {
		__skb_unlink(skb, &qdisc->gso_skb);
		kfree_skb_list(skb);
	}

	skb_queue_walk_safe(&qdisc->skb_bad_txq, skb, tmp) {
		__skb_unlink(skb, &qdisc->skb_bad_txq);
		kfree_skb_list(skb);
	}

	qdisc->q.qlen = 0;
	qdisc->qstats.backlog = 0;
}
EXPORT_SYMBOL(qdisc_reset);

void qdisc_free(struct Qdisc *qdisc)
{
	if (qdisc_is_percpu_stats(qdisc)) {
		free_percpu(qdisc->cpu_bstats);
		free_percpu(qdisc->cpu_qstats);
	}

	kfree((char *) qdisc - qdisc->padded);
}

void qdisc_destroy(struct Qdisc *qdisc)
{
	const struct Qdisc_ops  *ops = qdisc->ops;
	struct sk_buff *skb, *tmp;

	if (qdisc->flags & TCQ_F_BUILTIN ||
	    !refcount_dec_and_test(&qdisc->refcnt))
		return;

#ifdef CONFIG_NET_SCHED
	qdisc_hash_del(qdisc);

	qdisc_put_stab(qdisc->stab);
	qdisc_put_stab(rtnl_dereference(qdisc->stab));
#endif
	gen_kill_estimator(&qdisc->rate_est);
	if (ops->reset)
		ops->reset(qdisc);
	if (ops->destroy)
		ops->destroy(qdisc);

	module_put(ops->owner);
	dev_put(qdisc_dev(qdisc));

	kfree_skb(qdisc->gso_skb);

	kfree((char *) qdisc - qdisc->padded);
}
EXPORT_SYMBOL(qdisc_destroy);

static bool dev_all_qdisc_sleeping_noop(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		if (txq->qdisc_sleeping != &noop_qdisc)
			return false;
	}
	return true;
}
	kfree_skb_list(qdisc->gso_skb);
	kfree_skb(qdisc->skb_bad_txq);
	/*
	 * gen_estimator est_timer() might access qdisc->q.lock,
	 * wait a RCU grace period before freeing qdisc.
	 */
	call_rcu(&qdisc->rcu_head, qdisc_rcu_free);
	skb_queue_walk_safe(&qdisc->gso_skb, skb, tmp) {
		__skb_unlink(skb, &qdisc->gso_skb);
		kfree_skb_list(skb);
	}

	skb_queue_walk_safe(&qdisc->skb_bad_txq, skb, tmp) {
		__skb_unlink(skb, &qdisc->skb_bad_txq);
		kfree_skb_list(skb);
	}

	qdisc_free(qdisc);
}
EXPORT_SYMBOL(qdisc_destroy);

/* Attach toplevel qdisc to device queue. */
struct Qdisc *dev_graft_qdisc(struct netdev_queue *dev_queue,
			      struct Qdisc *qdisc)
{
	struct Qdisc *oqdisc = dev_queue->qdisc_sleeping;
	spinlock_t *root_lock;

	root_lock = qdisc_lock(oqdisc);
	spin_lock_bh(root_lock);

	/* ... and graft new one */
	if (qdisc == NULL)
		qdisc = &noop_qdisc;
	dev_queue->qdisc_sleeping = qdisc;
	rcu_assign_pointer(dev_queue->qdisc, &noop_qdisc);

	spin_unlock_bh(root_lock);

	return oqdisc;
}
EXPORT_SYMBOL(dev_graft_qdisc);

static void attach_one_default_qdisc(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_unused)
{
	struct Qdisc *qdisc;

	if (dev->tx_queue_len) {
		qdisc = qdisc_create_dflt(dev, dev_queue,
					  &pfifo_fast_ops, TC_H_ROOT);
		if (!qdisc) {
			printk(KERN_INFO "%s: activation failed\n", dev->name);
			return;
		}
	} else {
		qdisc =  &noqueue_qdisc;
	}
	dev_queue->qdisc_sleeping = qdisc;
}

	const struct Qdisc_ops *ops = default_qdisc_ops;

	if (dev->priv_flags & IFF_NO_QUEUE)
		ops = &noqueue_qdisc_ops;

	qdisc = qdisc_create_dflt(dev_queue, ops, TC_H_ROOT, NULL);
	if (!qdisc) {
		netdev_info(dev, "activation failed\n");
		return;
	}
	if (!netif_is_multiqueue(dev))
		qdisc->flags |= TCQ_F_ONETXQUEUE | TCQ_F_NOPARENT;
	dev_queue->qdisc_sleeping = qdisc;
}

static void attach_default_qdiscs(struct net_device *dev)
{
	struct netdev_queue *txq;
	struct Qdisc *qdisc;

	txq = netdev_get_tx_queue(dev, 0);

	if (!netif_is_multiqueue(dev) ||
	    dev->priv_flags & IFF_NO_QUEUE) {
		netdev_for_each_tx_queue(dev, attach_one_default_qdisc, NULL);
		dev->qdisc = txq->qdisc_sleeping;
		qdisc_refcount_inc(dev->qdisc);
	} else {
		qdisc = qdisc_create_dflt(txq, &mq_qdisc_ops, TC_H_ROOT, NULL);
		if (qdisc) {
			dev->qdisc = qdisc;
			qdisc->ops->attach(qdisc);
		}
	}
#ifdef CONFIG_NET_SCHED
	if (dev->qdisc != &noop_qdisc)
		qdisc_hash_add(dev->qdisc, false);
#endif
}

static void transition_one_qdisc(struct net_device *dev,
				 struct netdev_queue *dev_queue,
				 void *_need_watchdog)
{
	struct Qdisc *new_qdisc = dev_queue->qdisc_sleeping;
	int *need_watchdog_p = _need_watchdog;

	if (!(new_qdisc->flags & TCQ_F_BUILTIN))
		clear_bit(__QDISC_STATE_DEACTIVATED, &new_qdisc->state);

	rcu_assign_pointer(dev_queue->qdisc, new_qdisc);
	if (need_watchdog_p && new_qdisc != &noqueue_qdisc)
		*need_watchdog_p = 1;
	if (need_watchdog_p) {
		dev_queue->trans_start = 0;
		*need_watchdog_p = 1;
	}
}

void dev_activate(struct net_device *dev)
{
	int need_watchdog;

	/* No queueing discipline is attached to device;
	   create default one i.e. pfifo_fast for devices,
	   which need queueing and noqueue_qdisc for
	   virtual interfaces
	 */

	if (dev_all_qdisc_sleeping_noop(dev))
		netdev_for_each_tx_queue(dev, attach_one_default_qdisc, NULL);
	 * create default one for devices, which need queueing
	 * and noqueue_qdisc for virtual interfaces
	 */

	if (dev->qdisc == &noop_qdisc)
		attach_default_qdiscs(dev);

	if (!netif_carrier_ok(dev))
		/* Delay activation until next carrier-on event */
		return;

	need_watchdog = 0;
	netdev_for_each_tx_queue(dev, transition_one_qdisc, &need_watchdog);
	transition_one_qdisc(dev, &dev->rx_queue, NULL);
	if (dev_ingress_queue(dev))
		transition_one_qdisc(dev, dev_ingress_queue(dev), NULL);

	if (need_watchdog) {
		netif_trans_update(dev);
		dev_watchdog_up(dev);
	}
}
EXPORT_SYMBOL(dev_activate);

static void dev_deactivate_queue(struct net_device *dev,
				 struct netdev_queue *dev_queue,
				 void *_qdisc_default)
{
	struct Qdisc *qdisc_default = _qdisc_default;
	struct Qdisc *qdisc;

	qdisc = dev_queue->qdisc;
	qdisc = rtnl_dereference(dev_queue->qdisc);
	if (qdisc) {
		bool nolock = qdisc->flags & TCQ_F_NOLOCK;

		if (nolock)
			spin_lock_bh(&qdisc->seqlock);
		spin_lock_bh(qdisc_lock(qdisc));

		if (!(qdisc->flags & TCQ_F_BUILTIN))
			set_bit(__QDISC_STATE_DEACTIVATED, &qdisc->state);

		rcu_assign_pointer(dev_queue->qdisc, qdisc_default);
		qdisc_reset(qdisc);

		spin_unlock_bh(qdisc_lock(qdisc));
		if (nolock)
			spin_unlock_bh(&qdisc->seqlock);
	}
}

static bool some_qdisc_is_busy(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *dev_queue;
		spinlock_t *root_lock;
		struct Qdisc *q;
		int val;

		dev_queue = netdev_get_tx_queue(dev, i);
		q = dev_queue->qdisc_sleeping;

		root_lock = qdisc_lock(q);
		spin_lock_bh(root_lock);

		val = (test_bit(__QDISC_STATE_RUNNING, &q->state) ||
		val = (qdisc_is_running(q) ||
		       test_bit(__QDISC_STATE_SCHED, &q->state));

		spin_unlock_bh(root_lock);

		if (val)
			return true;
	}
	return false;
}

void dev_deactivate(struct net_device *dev)
{
	netdev_for_each_tx_queue(dev, dev_deactivate_queue, &noop_qdisc);
	dev_deactivate_queue(dev, &dev->rx_queue, &noop_qdisc);

	dev_watchdog_down(dev);

	/* Wait for outstanding qdisc-less dev_queue_xmit calls. */
	synchronize_rcu();

	/* Wait for outstanding qdisc_run calls. */
	while (some_qdisc_is_busy(dev))
		yield();
static void dev_qdisc_reset(struct net_device *dev,
			    struct netdev_queue *dev_queue,
			    void *none)
{
	struct Qdisc *qdisc = dev_queue->qdisc_sleeping;

	if (qdisc)
		qdisc_reset(qdisc);
}

/**
 * 	dev_deactivate_many - deactivate transmissions on several devices
 * 	@head: list of devices to deactivate
 *
 *	This function returns only when all outstanding transmissions
 *	have completed, unless all devices are in dismantle phase.
 */
void dev_deactivate_many(struct list_head *head)
{
	struct net_device *dev;

	list_for_each_entry(dev, head, close_list) {
		netdev_for_each_tx_queue(dev, dev_deactivate_queue,
					 &noop_qdisc);
		if (dev_ingress_queue(dev))
			dev_deactivate_queue(dev, dev_ingress_queue(dev),
					     &noop_qdisc);

		dev_watchdog_down(dev);
	}

	/* Wait for outstanding qdisc-less dev_queue_xmit calls.
	 * This is avoided if all devices are in dismantle phase :
	 * Caller will call synchronize_net() for us
	 */
	synchronize_net();

	/* Wait for outstanding qdisc_run calls. */
	list_for_each_entry(dev, head, close_list) {
		while (some_qdisc_is_busy(dev))
			yield();
		/* The new qdisc is assigned at this point so we can safely
		 * unwind stale skb lists and qdisc statistics
		 */
		netdev_for_each_tx_queue(dev, dev_qdisc_reset, NULL);
		if (dev_ingress_queue(dev))
			dev_qdisc_reset(dev, dev_ingress_queue(dev), NULL);
	}
}

void dev_deactivate(struct net_device *dev)
{
	LIST_HEAD(single);

	list_add(&dev->close_list, &single);
	dev_deactivate_many(&single);
	list_del(&single);
}
EXPORT_SYMBOL(dev_deactivate);

static int qdisc_change_tx_queue_len(struct net_device *dev,
				     struct netdev_queue *dev_queue)
{
	struct Qdisc *qdisc = dev_queue->qdisc_sleeping;
	const struct Qdisc_ops *ops = qdisc->ops;

	if (ops->change_tx_queue_len)
		return ops->change_tx_queue_len(qdisc, dev->tx_queue_len);
	return 0;
}

int dev_qdisc_change_tx_queue_len(struct net_device *dev)
{
	bool up = dev->flags & IFF_UP;
	unsigned int i;
	int ret = 0;

	if (up)
		dev_deactivate(dev);

	for (i = 0; i < dev->num_tx_queues; i++) {
		ret = qdisc_change_tx_queue_len(dev, &dev->_tx[i]);

		/* TODO: revert changes on a partial failure */
		if (ret)
			break;
	}

	if (up)
		dev_activate(dev);
	return ret;
}

static void dev_init_scheduler_queue(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_qdisc)
{
	struct Qdisc *qdisc = _qdisc;

	dev_queue->qdisc = qdisc;
	rcu_assign_pointer(dev_queue->qdisc, qdisc);
	dev_queue->qdisc_sleeping = qdisc;
	__skb_queue_head_init(&qdisc->gso_skb);
	__skb_queue_head_init(&qdisc->skb_bad_txq);
}

void dev_init_scheduler(struct net_device *dev)
{
	netdev_for_each_tx_queue(dev, dev_init_scheduler_queue, &noop_qdisc);
	dev_init_scheduler_queue(dev, &dev->rx_queue, &noop_qdisc);
	dev->qdisc = &noop_qdisc;
	netdev_for_each_tx_queue(dev, dev_init_scheduler_queue, &noop_qdisc);
	if (dev_ingress_queue(dev))
		dev_init_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);

	timer_setup(&dev->watchdog_timer, dev_watchdog, 0);
}

static void shutdown_scheduler_queue(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_qdisc_default)
{
	struct Qdisc *qdisc = dev_queue->qdisc_sleeping;
	struct Qdisc *qdisc_default = _qdisc_default;

	if (qdisc) {
		rcu_assign_pointer(dev_queue->qdisc, qdisc_default);
		dev_queue->qdisc_sleeping = qdisc_default;

		qdisc_destroy(qdisc);
	}
}

void dev_shutdown(struct net_device *dev)
{
	netdev_for_each_tx_queue(dev, shutdown_scheduler_queue, &noop_qdisc);
	shutdown_scheduler_queue(dev, &dev->rx_queue, &noop_qdisc);
	WARN_ON(timer_pending(&dev->watchdog_timer));
}
	if (dev_ingress_queue(dev))
		shutdown_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);
	qdisc_destroy(dev->qdisc);
	dev->qdisc = &noop_qdisc;

	WARN_ON(timer_pending(&dev->watchdog_timer));
}

void psched_ratecfg_precompute(struct psched_ratecfg *r,
			       const struct tc_ratespec *conf,
			       u64 rate64)
{
	memset(r, 0, sizeof(*r));
	r->overhead = conf->overhead;
	r->rate_bytes_ps = max_t(u64, conf->rate, rate64);
	r->linklayer = (conf->linklayer & TC_LINKLAYER_MASK);
	r->mult = 1;
	/*
	 * The deal here is to replace a divide by a reciprocal one
	 * in fast path (a reciprocal divide is a multiply and a shift)
	 *
	 * Normal formula would be :
	 *  time_in_ns = (NSEC_PER_SEC * len) / rate_bps
	 *
	 * We compute mult/shift to use instead :
	 *  time_in_ns = (len * mult) >> shift;
	 *
	 * We try to get the highest possible mult value for accuracy,
	 * but have to make sure no overflows will ever happen.
	 */
	if (r->rate_bytes_ps > 0) {
		u64 factor = NSEC_PER_SEC;

		for (;;) {
			r->mult = div64_u64(factor, r->rate_bytes_ps);
			if (r->mult & (1U << 31) || factor & (1ULL << 63))
				break;
			factor <<= 1;
			r->shift++;
		}
	}
}
EXPORT_SYMBOL(psched_ratecfg_precompute);

static void mini_qdisc_rcu_func(struct rcu_head *head)
{
}

void mini_qdisc_pair_swap(struct mini_Qdisc_pair *miniqp,
			  struct tcf_proto *tp_head)
{
	struct mini_Qdisc *miniq_old = rtnl_dereference(*miniqp->p_miniq);
	struct mini_Qdisc *miniq;

	if (!tp_head) {
		RCU_INIT_POINTER(*miniqp->p_miniq, NULL);
		/* Wait for flying RCU callback before it is freed. */
		rcu_barrier_bh();
		return;
	}

	miniq = !miniq_old || miniq_old == &miniqp->miniq2 ?
		&miniqp->miniq1 : &miniqp->miniq2;

	/* We need to make sure that readers won't see the miniq
	 * we are about to modify. So wait until previous call_rcu_bh callback
	 * is done.
	 */
	rcu_barrier_bh();
	miniq->filter_list = tp_head;
	rcu_assign_pointer(*miniqp->p_miniq, miniq);

	if (miniq_old)
		/* This is counterpart of the rcu barriers above. We need to
		 * block potential new user of miniq_old until all readers
		 * are not seeing it.
		 */
		call_rcu_bh(&miniq_old->rcu, mini_qdisc_rcu_func);
}
EXPORT_SYMBOL(mini_qdisc_pair_swap);

void mini_qdisc_pair_init(struct mini_Qdisc_pair *miniqp, struct Qdisc *qdisc,
			  struct mini_Qdisc __rcu **p_miniq)
{
	miniqp->miniq1.cpu_bstats = qdisc->cpu_bstats;
	miniqp->miniq1.cpu_qstats = qdisc->cpu_qstats;
	miniqp->miniq2.cpu_bstats = qdisc->cpu_bstats;
	miniqp->miniq2.cpu_qstats = qdisc->cpu_qstats;
	miniqp->p_miniq = p_miniq;
}
EXPORT_SYMBOL(mini_qdisc_pair_init);
