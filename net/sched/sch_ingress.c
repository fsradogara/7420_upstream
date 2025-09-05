/* net/sched/sch_ingress.c - Ingress and clsact qdisc
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jamal Hadi Salim 1999
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>


struct ingress_qdisc_data {
	struct tcf_proto	*filter_list;
};

/* ------------------------- Class/flow operations ------------------------- */

static int ingress_graft(struct Qdisc *sch, unsigned long arg,
			 struct Qdisc *new, struct Qdisc **old)
{
	return -EOPNOTSUPP;
}


#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct ingress_sched_data {
	struct tcf_block *block;
};

static struct Qdisc *ingress_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long ingress_find(struct Qdisc *sch, u32 classid)
{
	return TC_H_MIN(classid) + 1;
}

static unsigned long ingress_bind_filter(struct Qdisc *sch,
					 unsigned long parent, u32 classid)
{
	return ingress_find(sch, classid);
}

static void ingress_unbind_filter(struct Qdisc *sch, unsigned long cl)
{
}

static int ingress_change(struct Qdisc *sch, u32 classid, u32 parent,
			  struct nlattr **tca, unsigned long *arg)
{
	return 0;
}

static void ingress_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	return;
}

static struct tcf_proto **ingress_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	struct ingress_qdisc_data *p = qdisc_priv(sch);

	return &p->filter_list;
}

/* --------------------------- Qdisc operations ---------------------------- */

static int ingress_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct ingress_qdisc_data *p = qdisc_priv(sch);
	struct tcf_result res;
	int result;

	result = tc_classify(skb, p->filter_list, &res);

	sch->bstats.packets++;
	sch->bstats.bytes += qdisc_pkt_len(skb);
	switch (result) {
	case TC_ACT_SHOT:
		result = TC_ACT_SHOT;
		sch->qstats.drops++;
		break;
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
		result = TC_ACT_STOLEN;
		break;
	case TC_ACT_RECLASSIFY:
	case TC_ACT_OK:
		skb->tc_index = TC_H_MIN(res.classid);
	default:
		result = TC_ACT_OK;
		break;
	}

	return result;
}

/* ------------------------------------------------------------- */

static void ingress_destroy(struct Qdisc *sch)
{
	struct ingress_qdisc_data *p = qdisc_priv(sch);

	tcf_destroy_chain(&p->filter_list);
static void ingress_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
}

static struct tcf_block *ingress_tcf_block(struct Qdisc *sch, unsigned long cl)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	return q->block;
}

static int ingress_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int err;

	net_inc_ingress_queue();

	err = tcf_block_get(&q->block, &dev->ingress_cl_list);
	if (err)
		return err;

	sch->flags |= TCQ_F_CPUSTATS;

	return 0;
}

static void ingress_destroy(struct Qdisc *sch)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	tcf_block_put(q->block);
	net_dec_ingress_queue();
}

static int ingress_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return skb->len;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops ingress_class_ops = {
	.graft		=	ingress_graft,
	.leaf		=	ingress_leaf,
	.get		=	ingress_get,
	.put		=	ingress_put,
	.change		=	ingress_change,
	.leaf		=	ingress_leaf,
	.find		=	ingress_find,
	.walk		=	ingress_walk,
	.tcf_block	=	ingress_tcf_block,
	.bind_tcf	=	ingress_bind_filter,
	.unbind_tcf	=	ingress_unbind_filter,
};

static struct Qdisc_ops ingress_qdisc_ops __read_mostly = {
	.cl_ops		=	&ingress_class_ops,
	.id		=	"ingress",
	.priv_size	=	sizeof(struct ingress_qdisc_data),
	.enqueue	=	ingress_enqueue,
	.priv_size	=	sizeof(struct ingress_sched_data),
	.init		=	ingress_init,
	.destroy	=	ingress_destroy,
	.dump		=	ingress_dump,
	.owner		=	THIS_MODULE,
};

struct clsact_sched_data {
	struct tcf_block *ingress_block;
	struct tcf_block *egress_block;
};

static unsigned long clsact_find(struct Qdisc *sch, u32 classid)
{
	switch (TC_H_MIN(classid)) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return TC_H_MIN(classid);
	default:
		return 0;
	}
}

static unsigned long clsact_bind_filter(struct Qdisc *sch,
					unsigned long parent, u32 classid)
{
	return clsact_find(sch, classid);
}

static struct tcf_block *clsact_tcf_block(struct Qdisc *sch, unsigned long cl)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	switch (cl) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
		return q->ingress_block;
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return q->egress_block;
	default:
		return NULL;
	}
}

static int clsact_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int err;

	net_inc_ingress_queue();
	net_inc_egress_queue();

	err = tcf_block_get(&q->ingress_block, &dev->ingress_cl_list);
	if (err)
		return err;

	err = tcf_block_get(&q->egress_block, &dev->egress_cl_list);
	if (err)
		return err;

	sch->flags |= TCQ_F_CPUSTATS;

	return 0;
}

static void clsact_destroy(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	tcf_block_put(q->egress_block);
	tcf_block_put(q->ingress_block);

	net_dec_ingress_queue();
	net_dec_egress_queue();
}

static const struct Qdisc_class_ops clsact_class_ops = {
	.leaf		=	ingress_leaf,
	.find		=	clsact_find,
	.walk		=	ingress_walk,
	.tcf_block	=	clsact_tcf_block,
	.bind_tcf	=	clsact_bind_filter,
	.unbind_tcf	=	ingress_unbind_filter,
};

static struct Qdisc_ops clsact_qdisc_ops __read_mostly = {
	.cl_ops		=	&clsact_class_ops,
	.id		=	"clsact",
	.priv_size	=	sizeof(struct clsact_sched_data),
	.init		=	clsact_init,
	.destroy	=	clsact_destroy,
	.dump		=	ingress_dump,
	.owner		=	THIS_MODULE,
};

static int __init ingress_module_init(void)
{
	int ret;

	ret = register_qdisc(&ingress_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&clsact_qdisc_ops);
		if (ret)
			unregister_qdisc(&ingress_qdisc_ops);
	}

	return ret;
}

static void __exit ingress_module_exit(void)
{
	unregister_qdisc(&ingress_qdisc_ops);
	unregister_qdisc(&clsact_qdisc_ops);
}

module_init(ingress_module_init)
module_exit(ingress_module_exit)
module_init(ingress_module_init);
module_exit(ingress_module_exit);

MODULE_ALIAS("sch_clsact");
MODULE_LICENSE("GPL");
