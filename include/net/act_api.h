/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_ACT_API_H
#define __NET_ACT_API_H

/*
 * Public action API for classifiers/qdiscs
*/

#include <linux/refcount.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

struct tcf_common {
	struct tcf_common		*tcfc_next;
	struct hlist_node		tcfc_head;
	u32				tcfc_index;
	int				tcfc_refcnt;
	int				tcfc_bindcnt;
	u32				tcfc_capab;
	int				tcfc_action;
	struct tcf_t			tcfc_tm;
	struct gnet_stats_basic		tcfc_bstats;
	struct gnet_stats_queue		tcfc_qstats;
	struct gnet_stats_rate_est	tcfc_rate_est;
	spinlock_t			tcfc_lock;
};
#define tcf_next	common.tcfc_next
	struct gnet_stats_basic_packed	tcfc_bstats;
	struct gnet_stats_queue		tcfc_qstats;
	struct gnet_stats_rate_est64	tcfc_rate_est;
	spinlock_t			tcfc_lock;
	struct rcu_head			tcfc_rcu;
struct tcf_idrinfo {
	spinlock_t	lock;
	struct idr	action_idr;
};

struct tc_action_ops;

struct tc_action {
	const struct tc_action_ops	*ops;
	__u32				type; /* for backward compat(TCA_OLD_COMPAT) */
	__u32				order;
	struct tcf_idrinfo		*idrinfo;

	u32				tcfa_index;
	refcount_t			tcfa_refcnt;
	atomic_t			tcfa_bindcnt;
	int				tcfa_action;
	struct tcf_t			tcfa_tm;
	struct gnet_stats_basic_packed	tcfa_bstats;
	struct gnet_stats_queue		tcfa_qstats;
	struct net_rate_estimator __rcu *tcfa_rate_est;
	spinlock_t			tcfa_lock;
	struct gnet_stats_basic_cpu __percpu *cpu_bstats;
	struct gnet_stats_queue __percpu *cpu_qstats;
	struct tc_cookie	__rcu *act_cookie;
	struct tcf_chain	*goto_chain;
};
#define tcf_head	common.tcfc_head
#define tcf_index	common.tcfc_index
#define tcf_refcnt	common.tcfc_refcnt
#define tcf_bindcnt	common.tcfc_bindcnt
#define tcf_capab	common.tcfc_capab
#define tcf_action	common.tcfc_action
#define tcf_tm		common.tcfc_tm
#define tcf_bstats	common.tcfc_bstats
#define tcf_qstats	common.tcfc_qstats
#define tcf_rate_est	common.tcfc_rate_est
#define tcf_lock	common.tcfc_lock

struct tcf_police {
	struct tcf_common	common;
	int			tcfp_result;
	u32			tcfp_ewma_rate;
	u32			tcfp_burst;
	u32			tcfp_mtu;
	u32			tcfp_toks;
	u32			tcfp_ptoks;
	psched_time_t		tcfp_t_c;
	struct qdisc_rate_table	*tcfp_R_tab;
	struct qdisc_rate_table	*tcfp_P_tab;
};
#define to_police(pc)	\
	container_of(pc, struct tcf_police, common)

struct tcf_hashinfo {
	struct tcf_common	**htab;
	unsigned int		hmask;
	rwlock_t		*lock;
#define tcf_rcu		common.tcfc_rcu

struct tcf_hashinfo {
	struct hlist_head	*htab;
	unsigned int		hmask;
	spinlock_t		lock;
	u32			index;
};

static inline unsigned int tcf_hash(u32 index, unsigned int hmask)
{
	return index & hmask;
}

static inline int tcf_hashinfo_init(struct tcf_hashinfo *hf, unsigned int mask)
{
	int i;

	spin_lock_init(&hf->lock);
	hf->index = 0;
	hf->hmask = mask;
	hf->htab = kzalloc((mask + 1) * sizeof(struct hlist_head),
			   GFP_KERNEL);
	if (!hf->htab)
		return -ENOMEM;
	for (i = 0; i < mask + 1; i++)
		INIT_HLIST_HEAD(&hf->htab[i]);
	return 0;
}

static inline void tcf_hashinfo_destroy(struct tcf_hashinfo *hf)
{
	kfree(hf->htab);
}
#define tcf_index	common.tcfa_index
#define tcf_refcnt	common.tcfa_refcnt
#define tcf_bindcnt	common.tcfa_bindcnt
#define tcf_action	common.tcfa_action
#define tcf_tm		common.tcfa_tm
#define tcf_bstats	common.tcfa_bstats
#define tcf_qstats	common.tcfa_qstats
#define tcf_rate_est	common.tcfa_rate_est
#define tcf_lock	common.tcfa_lock

/* Update lastuse only if needed, to avoid dirtying a cache line.
 * We use a temp variable to avoid fetching jiffies twice.
 */
static inline void tcf_lastuse_update(struct tcf_t *tm)
{
	unsigned long now = jiffies;

	if (tm->lastuse != now)
		tm->lastuse = now;
	if (unlikely(!tm->firstuse))
		tm->firstuse = now;
}

static inline void tcf_tm_dump(struct tcf_t *dtm, const struct tcf_t *stm)
{
	dtm->install = jiffies_to_clock_t(jiffies - stm->install);
	dtm->lastuse = jiffies_to_clock_t(jiffies - stm->lastuse);
	dtm->firstuse = jiffies_to_clock_t(jiffies - stm->firstuse);
	dtm->expires = jiffies_to_clock_t(stm->expires);
}

#ifdef CONFIG_NET_CLS_ACT

#define ACT_P_CREATED 1
#define ACT_P_DELETED 1

struct tcf_act_hdr {
	struct tcf_common	common;
};

struct tc_action {
	void			*priv;
	struct tc_action_ops	*ops;
	__u32			type; /* for backward compat(TCA_OLD_COMPAT) */
	__u32			order;
	struct tc_action	*next;
};

#define TCA_CAP_NONE 0
struct tc_action_ops {
	struct tc_action_ops *next;
	struct tcf_hashinfo *hinfo;
	char    kind[IFNAMSIZ];
	__u32   type; /* TBD to match kind */
	__u32 	capab;  /* capabilities includes 4 bit version */
	struct module		*owner;
	int     (*act)(struct sk_buff *, struct tc_action *, struct tcf_result *);
	int     (*get_stats)(struct sk_buff *, struct tc_action *);
	int     (*dump)(struct sk_buff *, struct tc_action *, int, int);
	int     (*cleanup)(struct tc_action *, int bind);
	int     (*lookup)(struct tc_action *, u32);
	int     (*init)(struct nlattr *, struct nlattr *, struct tc_action *, int , int);
	int     (*walk)(struct sk_buff *, struct netlink_callback *, int, struct tc_action *);
};

extern struct tcf_common *tcf_hash_lookup(u32 index,
					  struct tcf_hashinfo *hinfo);
extern void tcf_hash_destroy(struct tcf_common *p, struct tcf_hashinfo *hinfo);
extern int tcf_hash_release(struct tcf_common *p, int bind,
			    struct tcf_hashinfo *hinfo);
extern int tcf_generic_walker(struct sk_buff *skb, struct netlink_callback *cb,
			      int type, struct tc_action *a);
extern u32 tcf_hash_new_index(u32 *idx_gen, struct tcf_hashinfo *hinfo);
extern int tcf_hash_search(struct tc_action *a, u32 index);
extern struct tcf_common *tcf_hash_check(u32 index, struct tc_action *a,
					 int bind, struct tcf_hashinfo *hinfo);
extern struct tcf_common *tcf_hash_create(u32 index, struct nlattr *est,
					  struct tc_action *a, int size,
					  int bind, u32 *idx_gen,
					  struct tcf_hashinfo *hinfo);
extern void tcf_hash_insert(struct tcf_common *p, struct tcf_hashinfo *hinfo);

extern int tcf_register_action(struct tc_action_ops *a);
extern int tcf_unregister_action(struct tc_action_ops *a);
extern void tcf_action_destroy(struct tc_action *a, int bind);
extern int tcf_action_exec(struct sk_buff *skb, struct tc_action *a, struct tcf_result *res);
extern struct tc_action *tcf_action_init(struct nlattr *nla, struct nlattr *est, char *n, int ovr, int bind);
extern struct tc_action *tcf_action_init_1(struct nlattr *nla, struct nlattr *est, char *n, int ovr, int bind);
extern int tcf_action_dump(struct sk_buff *skb, struct tc_action *a, int, int);
extern int tcf_action_dump_old(struct sk_buff *skb, struct tc_action *a, int, int);
extern int tcf_action_dump_1(struct sk_buff *skb, struct tc_action *a, int, int);
extern int tcf_action_copy_stats (struct sk_buff *,struct tc_action *, int);
struct tc_action {
	void			*priv;
	const struct tc_action_ops	*ops;
	__u32			type; /* for backward compat(TCA_OLD_COMPAT) */
	__u32			order;
	struct list_head	list;
};

struct tc_action_ops {
	struct list_head head;
	char    kind[IFNAMSIZ];
	__u32   type; /* TBD to match kind */
	size_t	size;
	struct module		*owner;
	int     (*act)(struct sk_buff *, const struct tc_action *,
		       struct tcf_result *); /* called under RCU BH lock*/
	int     (*dump)(struct sk_buff *, struct tc_action *, int, int);
	void	(*cleanup)(struct tc_action *);
	int     (*lookup)(struct net *net, struct tc_action **a, u32 index,
			  struct netlink_ext_ack *extack);
	int     (*init)(struct net *net, struct nlattr *nla,
			struct nlattr *est, struct tc_action **act, int ovr,
			int bind, bool rtnl_held,
			struct netlink_ext_ack *extack);
	int     (*walk)(struct net *, struct sk_buff *,
			struct netlink_callback *, int,
			const struct tc_action_ops *,
			struct netlink_ext_ack *);
	void	(*stats_update)(struct tc_action *, u64, u32, u64);
	size_t  (*get_fill_size)(const struct tc_action *act);
	struct net_device *(*get_dev)(const struct tc_action *a);
	void	(*put_dev)(struct net_device *dev);
};

struct tc_action_net {
	struct tcf_idrinfo *idrinfo;
	const struct tc_action_ops *ops;
};

static inline
int tc_action_net_init(struct tc_action_net *tn,
		       const struct tc_action_ops *ops)
{
	int err = 0;

	tn->idrinfo = kmalloc(sizeof(*tn->idrinfo), GFP_KERNEL);
	if (!tn->idrinfo)
		return -ENOMEM;
	tn->ops = ops;
	spin_lock_init(&tn->idrinfo->lock);
	idr_init(&tn->idrinfo->action_idr);
	return err;
}

void tcf_idrinfo_destroy(const struct tc_action_ops *ops,
			 struct tcf_idrinfo *idrinfo);

static inline void tc_action_net_exit(struct list_head *net_list,
				      unsigned int id)
{
	struct net *net;

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list) {
		struct tc_action_net *tn = net_generic(net, id);

		tcf_idrinfo_destroy(tn->ops, tn->idrinfo);
		kfree(tn->idrinfo);
	}
	rtnl_unlock();
}

int tcf_generic_walker(struct tc_action_net *tn, struct sk_buff *skb,
		       struct netlink_callback *cb, int type,
		       const struct tc_action_ops *ops,
		       struct netlink_ext_ack *extack);
int tcf_idr_search(struct tc_action_net *tn, struct tc_action **a, u32 index);
int tcf_idr_create(struct tc_action_net *tn, u32 index, struct nlattr *est,
		   struct tc_action **a, const struct tc_action_ops *ops,
		   int bind, bool cpustats);
void tcf_idr_insert(struct tc_action_net *tn, struct tc_action *a);

void tcf_idr_cleanup(struct tc_action_net *tn, u32 index);
int tcf_idr_check_alloc(struct tc_action_net *tn, u32 *index,
			struct tc_action **a, int bind);
int __tcf_idr_release(struct tc_action *a, bool bind, bool strict);

static inline int tcf_idr_release(struct tc_action *a, bool bind)
{
	return __tcf_idr_release(a, bind, false);
}

int tcf_register_action(struct tc_action_ops *a, struct pernet_operations *ops);
int tcf_unregister_action(struct tc_action_ops *a,
			  struct pernet_operations *ops);
int tcf_action_destroy(struct tc_action *actions[], int bind);
int tcf_action_exec(struct sk_buff *skb, struct tc_action **actions,
		    int nr_actions, struct tcf_result *res);
int tcf_action_init(struct net *net, struct tcf_proto *tp, struct nlattr *nla,
		    struct nlattr *est, char *name, int ovr, int bind,
		    struct tc_action *actions[], size_t *attr_size,
		    bool rtnl_held, struct netlink_ext_ack *extack);
struct tc_action *tcf_action_init_1(struct net *net, struct tcf_proto *tp,
				    struct nlattr *nla, struct nlattr *est,
				    char *name, int ovr, int bind,
				    bool rtnl_held,
				    struct netlink_ext_ack *extack);
int tcf_action_dump(struct sk_buff *skb, struct tc_action *actions[], int bind,
		    int ref);
int tcf_action_dump_old(struct sk_buff *skb, struct tc_action *a, int, int);
int tcf_action_dump_1(struct sk_buff *skb, struct tc_action *a, int, int);
int tcf_action_copy_stats(struct sk_buff *, struct tc_action *, int);

#endif /* CONFIG_NET_CLS_ACT */

static inline void tcf_action_stats_update(struct tc_action *a, u64 bytes,
					   u64 packets, u64 lastuse)
{
#ifdef CONFIG_NET_CLS_ACT
	if (!a->ops->stats_update)
		return;

	a->ops->stats_update(a, bytes, packets, lastuse);
#endif
}

#ifdef CONFIG_NET_CLS_ACT
int tc_setup_cb_egdev_register(const struct net_device *dev,
			       tc_setup_cb_t *cb, void *cb_priv);
void tc_setup_cb_egdev_unregister(const struct net_device *dev,
				  tc_setup_cb_t *cb, void *cb_priv);
int tc_setup_cb_egdev_call(const struct net_device *dev,
			   enum tc_setup_type type, void *type_data,
			   bool err_stop);
#else
static inline
int tc_setup_cb_egdev_register(const struct net_device *dev,
			       tc_setup_cb_t *cb, void *cb_priv)
{
	return 0;
}

static inline
void tc_setup_cb_egdev_unregister(const struct net_device *dev,
				  tc_setup_cb_t *cb, void *cb_priv)
{
}

static inline
int tc_setup_cb_egdev_call(const struct net_device *dev,
			   enum tc_setup_type type, void *type_data,
			   bool err_stop)
{
	return 0;
}
#endif

#endif
