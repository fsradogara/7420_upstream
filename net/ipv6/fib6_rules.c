/*
 * net/ipv6/fib6_rules.c	IPv6 Routing Policy Rules
 *
 * Copyright (C)2003-2006 Helsinki University of Technology
 * Copyright (C)2003-2006 USAGI/WIDE Project
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * Authors
 *	Thomas Graf		<tgraf@suug.ch>
 *	Ville Nuorvala		<vnuorval@tcs.hut.fi>
 */

#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/export.h>

#include <net/fib_rules.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/netlink.h>

struct fib6_rule
{
struct fib6_rule {
	struct fib_rule		common;
	struct rt6key		src;
	struct rt6key		dst;
	u8			tclass;
};

struct dst_entry *fib6_rule_lookup(struct net *net, struct flowi *fl,
				   int flags, pol_lookup_t lookup)
{
	struct fib_lookup_arg arg = {
		.lookup_ptr = lookup,
	};

	fib_rules_lookup(net->ipv6.fib6_rules_ops, fl, flags, &arg);
	if (arg.rule)
		fib_rule_put(arg.rule);

	if (arg.result)
		return arg.result;

	dst_hold(&net->ipv6.ip6_null_entry->u.dst);
	return &net->ipv6.ip6_null_entry->u.dst;
static bool fib6_rule_matchall(const struct fib_rule *rule)
{
	struct fib6_rule *r = container_of(rule, struct fib6_rule, common);

	if (r->dst.plen || r->src.plen || r->tclass)
		return false;
	return fib_rule_matchall(rule);
}

bool fib6_rule_default(const struct fib_rule *rule)
{
	if (!fib6_rule_matchall(rule) || rule->action != FR_ACT_TO_TBL ||
	    rule->l3mdev)
		return false;
	if (rule->table != RT6_TABLE_LOCAL && rule->table != RT6_TABLE_MAIN)
		return false;
	return true;
}
EXPORT_SYMBOL_GPL(fib6_rule_default);

int fib6_rules_dump(struct net *net, struct notifier_block *nb)
{
	return fib_rules_dump(net, nb, AF_INET6);
}

unsigned int fib6_rules_seq_read(struct net *net)
{
	return fib_rules_seq_read(net, AF_INET6);
}

/* called with rcu lock held; no reference taken on fib6_info */
struct fib6_info *fib6_lookup(struct net *net, int oif, struct flowi6 *fl6,
			      int flags)
{
	struct fib6_info *f6i;
	int err;

	if (net->ipv6.fib6_has_custom_rules) {
		struct fib_lookup_arg arg = {
			.lookup_ptr = fib6_table_lookup,
			.lookup_data = &oif,
			.flags = FIB_LOOKUP_NOREF,
		};

		l3mdev_update_flow(net, flowi6_to_flowi(fl6));

		err = fib_rules_lookup(net->ipv6.fib6_rules_ops,
				       flowi6_to_flowi(fl6), flags, &arg);
		if (err)
			return ERR_PTR(err);

		f6i = arg.result ? : net->ipv6.fib6_null_entry;
	} else {
		f6i = fib6_table_lookup(net, net->ipv6.fib6_local_tbl,
					oif, fl6, flags);
		if (!f6i || f6i == net->ipv6.fib6_null_entry)
			f6i = fib6_table_lookup(net, net->ipv6.fib6_main_tbl,
						oif, fl6, flags);
	}

	return f6i;
}

struct dst_entry *fib6_rule_lookup(struct net *net, struct flowi6 *fl6,
				   const struct sk_buff *skb,
				   int flags, pol_lookup_t lookup)
{
	if (net->ipv6.fib6_has_custom_rules) {
		struct fib_lookup_arg arg = {
			.lookup_ptr = lookup,
			.lookup_data = skb,
			.flags = FIB_LOOKUP_NOREF,
		};

		/* update flow if oif or iif point to device enslaved to l3mdev */
		l3mdev_update_flow(net, flowi6_to_flowi(fl6));

		fib_rules_lookup(net->ipv6.fib6_rules_ops,
				 flowi6_to_flowi(fl6), flags, &arg);

		if (arg.result)
			return arg.result;
	} else {
		struct rt6_info *rt;

		rt = lookup(net, net->ipv6.fib6_local_tbl, fl6, skb, flags);
		if (rt != net->ipv6.ip6_null_entry && rt->dst.error != -EAGAIN)
			return &rt->dst;
		ip6_rt_put(rt);
		rt = lookup(net, net->ipv6.fib6_main_tbl, fl6, skb, flags);
		if (rt->dst.error != -EAGAIN)
			return &rt->dst;
		ip6_rt_put(rt);
	}

	dst_hold(&net->ipv6.ip6_null_entry->dst);
	return &net->ipv6.ip6_null_entry->dst;
}

static int fib6_rule_saddr(struct net *net, struct fib_rule *rule, int flags,
			   struct flowi6 *flp6, const struct net_device *dev)
{
	struct fib6_rule *r = (struct fib6_rule *)rule;

	/* If we need to find a source address for this traffic,
	 * we check the result if it meets requirement of the rule.
	 */
	if ((rule->flags & FIB_RULE_FIND_SADDR) &&
	    r->src.plen && !(flags & RT6_LOOKUP_F_HAS_SADDR)) {
		struct in6_addr saddr;

		if (ipv6_dev_get_saddr(net, dev, &flp6->daddr,
				       rt6_flags2srcprefs(flags), &saddr))
			return -EAGAIN;

		if (!ipv6_prefix_equal(&saddr, &r->src.addr, r->src.plen))
			return -EAGAIN;

		flp6->saddr = saddr;
	}

	return 0;
}

static int fib6_rule_action_alt(struct fib_rule *rule, struct flowi *flp,
				int flags, struct fib_lookup_arg *arg)
{
	struct flowi6 *flp6 = &flp->u.ip6;
	struct net *net = rule->fr_net;
	struct fib6_table *table;
	struct fib6_info *f6i;
	int err = -EAGAIN, *oif;
	u32 tb_id;

	switch (rule->action) {
	case FR_ACT_TO_TBL:
		break;
	case FR_ACT_UNREACHABLE:
		return -ENETUNREACH;
	case FR_ACT_PROHIBIT:
		return -EACCES;
	case FR_ACT_BLACKHOLE:
	default:
		return -EINVAL;
	}

	tb_id = fib_rule_get_table(rule, arg);
	table = fib6_get_table(net, tb_id);
	if (!table)
		return -EAGAIN;

	oif = (int *)arg->lookup_data;
	f6i = fib6_table_lookup(net, table, *oif, flp6, flags);
	if (f6i != net->ipv6.fib6_null_entry) {
		err = fib6_rule_saddr(net, rule, flags, flp6,
				      fib6_info_nh_dev(f6i));

		if (likely(!err))
			arg->result = f6i;
	}

	return err;
}

static int __fib6_rule_action(struct fib_rule *rule, struct flowi *flp,
			      int flags, struct fib_lookup_arg *arg)
{
	struct flowi6 *flp6 = &flp->u.ip6;
	struct rt6_info *rt = NULL;
	struct fib6_table *table;
	struct net *net = rule->fr_net;
	pol_lookup_t lookup = arg->lookup_ptr;
	int err = 0;
	u32 tb_id;

	switch (rule->action) {
	case FR_ACT_TO_TBL:
		break;
	case FR_ACT_UNREACHABLE:
		err = -ENETUNREACH;
		rt = net->ipv6.ip6_null_entry;
		goto discard_pkt;
	default:
	case FR_ACT_BLACKHOLE:
		rt = net->ipv6.ip6_blk_hole_entry;
		goto discard_pkt;
	case FR_ACT_PROHIBIT:
		err = -EINVAL;
		rt = net->ipv6.ip6_blk_hole_entry;
		goto discard_pkt;
	case FR_ACT_PROHIBIT:
		err = -EACCES;
		rt = net->ipv6.ip6_prohibit_entry;
		goto discard_pkt;
	}

	table = fib6_get_table(net, rule->table);
	if (table)
		rt = lookup(net, table, flp, flags);

	tb_id = fib_rule_get_table(rule, arg);
	table = fib6_get_table(net, tb_id);
	if (!table) {
		err = -EAGAIN;
		goto out;
	}

	rt = lookup(net, table, flp6, arg->lookup_data, flags);
	if (rt != net->ipv6.ip6_null_entry) {
		err = fib6_rule_saddr(net, rule, flags, flp6,
				      ip6_dst_idev(&rt->dst)->dev);

		/*
		 * If we need to find a source address for this traffic,
		 * we check the result if it meets requirement of the rule.
		 */
		if ((rule->flags & FIB_RULE_FIND_SADDR) &&
		    r->src.plen && !(flags & RT6_LOOKUP_F_HAS_SADDR)) {
			struct in6_addr saddr;
			unsigned int srcprefs = 0;

			if (flags & RT6_LOOKUP_F_SRCPREF_TMP)
				srcprefs |= IPV6_PREFER_SRC_TMP;
			if (flags & RT6_LOOKUP_F_SRCPREF_PUBLIC)
				srcprefs |= IPV6_PREFER_SRC_PUBLIC;
			if (flags & RT6_LOOKUP_F_SRCPREF_COA)
				srcprefs |= IPV6_PREFER_SRC_COA;

			if (ipv6_dev_get_saddr(net,
					       ip6_dst_idev(&rt->u.dst)->dev,
					       &flp->fl6_dst, srcprefs,

			if (ipv6_dev_get_saddr(net,
					       ip6_dst_idev(&rt->dst)->dev,
					       &flp6->daddr,
					       rt6_flags2srcprefs(flags),
					       &saddr))
				goto again;
			if (!ipv6_prefix_equal(&saddr, &r->src.addr,
					       r->src.plen))
				goto again;
			ipv6_addr_copy(&flp->fl6_src, &saddr);
		}
		goto out;
	}
again:
	dst_release(&rt->u.dst);
			flp6->saddr = saddr;
		}
		if (err == -EAGAIN)
			goto again;

		err = rt->dst.error;
		if (err != -EAGAIN)
			goto out;
	}
again:
	ip6_rt_put(rt);
	err = -EAGAIN;
	rt = NULL;
	goto out;

discard_pkt:
	dst_hold(&rt->u.dst);
out:
	arg->result = rt;
	return rt == NULL ? -EAGAIN : 0;
}

	dst_hold(&rt->dst);
out:
	arg->result = rt;
	return err;
}

static int fib6_rule_action(struct fib_rule *rule, struct flowi *flp,
			    int flags, struct fib_lookup_arg *arg)
{
	if (arg->lookup_ptr == fib6_table_lookup)
		return fib6_rule_action_alt(rule, flp, flags, arg);

	return __fib6_rule_action(rule, flp, flags, arg);
}

static bool fib6_rule_suppress(struct fib_rule *rule, struct fib_lookup_arg *arg)
{
	struct rt6_info *rt = (struct rt6_info *) arg->result;
	struct net_device *dev = NULL;

	if (rt->rt6i_idev)
		dev = rt->rt6i_idev->dev;

	/* do not accept result if the route does
	 * not meet the required prefix length
	 */
	if (rt->rt6i_dst.plen <= rule->suppress_prefixlen)
		goto suppress_route;

	/* do not accept result if the route uses a device
	 * belonging to a forbidden interface group
	 */
	if (rule->suppress_ifgroup != -1 && dev && dev->group == rule->suppress_ifgroup)
		goto suppress_route;

	return false;

suppress_route:
	ip6_rt_put(rt);
	return true;
}

static int fib6_rule_match(struct fib_rule *rule, struct flowi *fl, int flags)
{
	struct fib6_rule *r = (struct fib6_rule *) rule;

	if (r->dst.plen &&
	    !ipv6_prefix_equal(&fl->fl6_dst, &r->dst.addr, r->dst.plen))
	struct flowi6 *fl6 = &fl->u.ip6;

	if (r->dst.plen &&
	    !ipv6_prefix_equal(&fl6->daddr, &r->dst.addr, r->dst.plen))
		return 0;

	/*
	 * If FIB_RULE_FIND_SADDR is set and we do not have a
	 * source address for the traffic, we defer check for
	 * source address.
	 */
	if (r->src.plen) {
		if (flags & RT6_LOOKUP_F_HAS_SADDR) {
			if (!ipv6_prefix_equal(&fl->fl6_src, &r->src.addr,
			if (!ipv6_prefix_equal(&fl6->saddr, &r->src.addr,
					       r->src.plen))
				return 0;
		} else if (!(r->common.flags & FIB_RULE_FIND_SADDR))
			return 0;
	}

	if (r->tclass && r->tclass != ((ntohl(fl->fl6_flowlabel) >> 20) & 0xff))
	if (r->tclass && r->tclass != ip6_tclass(fl6->flowlabel))
		return 0;

	if (rule->ip_proto && (rule->ip_proto != fl6->flowi6_proto))
		return 0;

	if (fib_rule_port_range_set(&rule->sport_range) &&
	    !fib_rule_port_inrange(&rule->sport_range, fl6->fl6_sport))
		return 0;

	if (fib_rule_port_range_set(&rule->dport_range) &&
	    !fib_rule_port_inrange(&rule->dport_range, fl6->fl6_dport))
		return 0;

	return 1;
}

static const struct nla_policy fib6_rule_policy[FRA_MAX+1] = {
	FRA_GENERIC_POLICY,
};

static int fib6_rule_configure(struct fib_rule *rule, struct sk_buff *skb,
			       struct nlmsghdr *nlh, struct fib_rule_hdr *frh,
			       struct fib_rule_hdr *frh,
			       struct nlattr **tb,
			       struct netlink_ext_ack *extack)
{
	int err = -EINVAL;
	struct net *net = sock_net(skb->sk);
	struct fib6_rule *rule6 = (struct fib6_rule *) rule;

	if (rule->action == FR_ACT_TO_TBL && !rule->l3mdev) {
		if (rule->table == RT6_TABLE_UNSPEC) {
			NL_SET_ERR_MSG(extack, "Invalid table");
			goto errout;
		}

		if (fib6_new_table(net, rule->table) == NULL) {
			err = -ENOBUFS;
			goto errout;
		}
	}

	if (frh->src_len)
		nla_memcpy(&rule6->src.addr, tb[FRA_SRC],
			   sizeof(struct in6_addr));

	if (frh->dst_len)
		nla_memcpy(&rule6->dst.addr, tb[FRA_DST],
			   sizeof(struct in6_addr));
		rule6->src.addr = nla_get_in6_addr(tb[FRA_SRC]);

	if (frh->dst_len)
		rule6->dst.addr = nla_get_in6_addr(tb[FRA_DST]);

	rule6->src.plen = frh->src_len;
	rule6->dst.plen = frh->dst_len;
	rule6->tclass = frh->tos;

	if (fib_rule_requires_fldissect(rule))
		net->ipv6.fib6_rules_require_fldissect++;

	net->ipv6.fib6_has_custom_rules = true;
	err = 0;
errout:
	return err;
}

static int fib6_rule_delete(struct fib_rule *rule)
{
	struct net *net = rule->fr_net;

	if (net->ipv6.fib6_rules_require_fldissect &&
	    fib_rule_requires_fldissect(rule))
		net->ipv6.fib6_rules_require_fldissect--;

	return 0;
}

static int fib6_rule_compare(struct fib_rule *rule, struct fib_rule_hdr *frh,
			     struct nlattr **tb)
{
	struct fib6_rule *rule6 = (struct fib6_rule *) rule;

	if (frh->src_len && (rule6->src.plen != frh->src_len))
		return 0;

	if (frh->dst_len && (rule6->dst.plen != frh->dst_len))
		return 0;

	if (frh->tos && (rule6->tclass != frh->tos))
		return 0;

	if (frh->src_len &&
	    nla_memcmp(tb[FRA_SRC], &rule6->src.addr, sizeof(struct in6_addr)))
		return 0;

	if (frh->dst_len &&
	    nla_memcmp(tb[FRA_DST], &rule6->dst.addr, sizeof(struct in6_addr)))
		return 0;

	return 1;
}

static int fib6_rule_fill(struct fib_rule *rule, struct sk_buff *skb,
			  struct nlmsghdr *nlh, struct fib_rule_hdr *frh)
{
	struct fib6_rule *rule6 = (struct fib6_rule *) rule;

	frh->family = AF_INET6;
			  struct fib_rule_hdr *frh)
{
	struct fib6_rule *rule6 = (struct fib6_rule *) rule;

	frh->dst_len = rule6->dst.plen;
	frh->src_len = rule6->src.plen;
	frh->tos = rule6->tclass;

	if (rule6->dst.plen)
		NLA_PUT(skb, FRA_DST, sizeof(struct in6_addr),
			&rule6->dst.addr);

	if (rule6->src.plen)
		NLA_PUT(skb, FRA_SRC, sizeof(struct in6_addr),
			&rule6->src.addr);

	if ((rule6->dst.plen &&
	     nla_put_in6_addr(skb, FRA_DST, &rule6->dst.addr)) ||
	    (rule6->src.plen &&
	     nla_put_in6_addr(skb, FRA_SRC, &rule6->src.addr)))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

static u32 fib6_rule_default_pref(struct fib_rules_ops *ops)
{
	return 0x3FFF;
}

static size_t fib6_rule_nlmsg_payload(struct fib_rule *rule)
{
	return nla_total_size(16) /* dst */
	       + nla_total_size(16); /* src */
}

static struct fib_rules_ops fib6_rules_ops_template = {
static const struct fib_rules_ops __net_initconst fib6_rules_ops_template = {
	.family			= AF_INET6,
	.rule_size		= sizeof(struct fib6_rule),
	.addr_size		= sizeof(struct in6_addr),
	.action			= fib6_rule_action,
	.match			= fib6_rule_match,
	.configure		= fib6_rule_configure,
	.compare		= fib6_rule_compare,
	.fill			= fib6_rule_fill,
	.default_pref		= fib6_rule_default_pref,
	.suppress		= fib6_rule_suppress,
	.configure		= fib6_rule_configure,
	.delete			= fib6_rule_delete,
	.compare		= fib6_rule_compare,
	.fill			= fib6_rule_fill,
	.nlmsg_payload		= fib6_rule_nlmsg_payload,
	.nlgroup		= RTNLGRP_IPV6_RULE,
	.policy			= fib6_rule_policy,
	.owner			= THIS_MODULE,
	.fro_net		= &init_net,
};

static int fib6_rules_net_init(struct net *net)
{
	int err = -ENOMEM;

	net->ipv6.fib6_rules_ops = kmemdup(&fib6_rules_ops_template,
					   sizeof(*net->ipv6.fib6_rules_ops),
					   GFP_KERNEL);
	if (!net->ipv6.fib6_rules_ops)
		goto out;

	net->ipv6.fib6_rules_ops->fro_net = net;
	INIT_LIST_HEAD(&net->ipv6.fib6_rules_ops->rules_list);

	err = fib_default_rule_add(net->ipv6.fib6_rules_ops, 0,
				   RT6_TABLE_LOCAL, FIB_RULE_PERMANENT);
	if (err)
		goto out_fib6_rules_ops;

	err = fib_default_rule_add(net->ipv6.fib6_rules_ops,
				   0x7FFE, RT6_TABLE_MAIN, 0);
	if (err)
		goto out_fib6_default_rule_add;

	err = fib_rules_register(net->ipv6.fib6_rules_ops);
	if (err)
		goto out_fib6_default_rule_add;
out:
	return err;

out_fib6_default_rule_add:
	fib_rules_cleanup_ops(net->ipv6.fib6_rules_ops);
out_fib6_rules_ops:
	kfree(net->ipv6.fib6_rules_ops);
	goto out;
}

static void fib6_rules_net_exit(struct net *net)
{
	fib_rules_unregister(net->ipv6.fib6_rules_ops);
	kfree(net->ipv6.fib6_rules_ops);
static int __net_init fib6_rules_net_init(struct net *net)
{
	struct fib_rules_ops *ops;
	int err = -ENOMEM;

	ops = fib_rules_register(&fib6_rules_ops_template, net);
	if (IS_ERR(ops))
		return PTR_ERR(ops);

	err = fib_default_rule_add(ops, 0, RT6_TABLE_LOCAL, 0);
	if (err)
		goto out_fib6_rules_ops;

	err = fib_default_rule_add(ops, 0x7FFE, RT6_TABLE_MAIN, 0);
	if (err)
		goto out_fib6_rules_ops;

	net->ipv6.fib6_rules_ops = ops;
	net->ipv6.fib6_rules_require_fldissect = 0;
out:
	return err;

out_fib6_rules_ops:
	fib_rules_unregister(ops);
	goto out;
}

static void __net_exit fib6_rules_net_exit(struct net *net)
{
	rtnl_lock();
	fib_rules_unregister(net->ipv6.fib6_rules_ops);
	rtnl_unlock();
}

static struct pernet_operations fib6_rules_net_ops = {
	.init = fib6_rules_net_init,
	.exit = fib6_rules_net_exit,
};

int __init fib6_rules_init(void)
{
	return register_pernet_subsys(&fib6_rules_net_ops);
}


void fib6_rules_cleanup(void)
{
	unregister_pernet_subsys(&fib6_rules_net_ops);
}
