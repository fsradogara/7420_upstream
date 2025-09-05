/* Kernel module to match the bridge port in and
 * out device for IP packets coming into contact with a bridge. */

/* (C) 2001-2003 Bart De Schuymer <bdschuym@pandora.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/br_netfilter.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bart De Schuymer <bdschuym@pandora.be>");
MODULE_DESCRIPTION("Xtables: Bridge physical device match");
MODULE_ALIAS("ipt_physdev");
MODULE_ALIAS("ip6t_physdev");

static bool
physdev_mt(const struct sk_buff *skb, const struct net_device *in,
           const struct net_device *out, const struct xt_match *match,
           const void *matchinfo, int offset, unsigned int protoff,
           bool *hotdrop)
{
	int i;
	static const char nulldevname[IFNAMSIZ];
	const struct xt_physdev_info *info = matchinfo;
	bool ret;
	const char *indev, *outdev;
	const struct nf_bridge_info *nf_bridge;

static bool
physdev_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_physdev_info *info = par->matchinfo;
	const struct net_device *physdev;
	unsigned long ret;
	const char *indev, *outdev;

	/* Not a bridged IP packet or no info available yet:
	 * LOCAL_OUT/mangle and LOCAL_OUT/nat don't know if
	 * the destination device will be a bridge. */
	if (!(nf_bridge = skb->nf_bridge)) {
	if (!skb->nf_bridge) {
		/* Return MATCH if the invert flags of the used options are on */
		if ((info->bitmask & XT_PHYSDEV_OP_BRIDGED) &&
		    !(info->invert & XT_PHYSDEV_OP_BRIDGED))
			return false;
		if ((info->bitmask & XT_PHYSDEV_OP_ISIN) &&
		    !(info->invert & XT_PHYSDEV_OP_ISIN))
			return false;
		if ((info->bitmask & XT_PHYSDEV_OP_ISOUT) &&
		    !(info->invert & XT_PHYSDEV_OP_ISOUT))
			return false;
		if ((info->bitmask & XT_PHYSDEV_OP_IN) &&
		    !(info->invert & XT_PHYSDEV_OP_IN))
			return false;
		if ((info->bitmask & XT_PHYSDEV_OP_OUT) &&
		    !(info->invert & XT_PHYSDEV_OP_OUT))
			return false;
		return true;
	}

	/* This only makes sense in the FORWARD and POSTROUTING chains */
	if ((info->bitmask & XT_PHYSDEV_OP_BRIDGED) &&
	    (!!(nf_bridge->mask & BRNF_BRIDGED) ^
	    !(info->invert & XT_PHYSDEV_OP_BRIDGED)))
		return false;

	if ((info->bitmask & XT_PHYSDEV_OP_ISIN &&
	    (!nf_bridge->physindev ^ !!(info->invert & XT_PHYSDEV_OP_ISIN))) ||
	    (info->bitmask & XT_PHYSDEV_OP_ISOUT &&
	    (!nf_bridge->physoutdev ^ !!(info->invert & XT_PHYSDEV_OP_ISOUT))))
	physdev = nf_bridge_get_physoutdev(skb);
	outdev = physdev ? physdev->name : NULL;

	/* This only makes sense in the FORWARD and POSTROUTING chains */
	if ((info->bitmask & XT_PHYSDEV_OP_BRIDGED) &&
	    (!!outdev ^ !(info->invert & XT_PHYSDEV_OP_BRIDGED)))
		return false;

	physdev = nf_bridge_get_physindev(skb);
	indev = physdev ? physdev->name : NULL;

	if ((info->bitmask & XT_PHYSDEV_OP_ISIN &&
	    (!indev ^ !!(info->invert & XT_PHYSDEV_OP_ISIN))) ||
	    (info->bitmask & XT_PHYSDEV_OP_ISOUT &&
	    (!outdev ^ !!(info->invert & XT_PHYSDEV_OP_ISOUT))))
		return false;

	if (!(info->bitmask & XT_PHYSDEV_OP_IN))
		goto match_outdev;
	indev = nf_bridge->physindev ? nf_bridge->physindev->name : nulldevname;
	for (i = 0, ret = false; i < IFNAMSIZ/sizeof(unsigned int); i++) {
		ret |= (((const unsigned int *)indev)[i]
			^ ((const unsigned int *)info->physindev)[i])
			& ((const unsigned int *)info->in_mask)[i];
	}

	if (!ret ^ !(info->invert & XT_PHYSDEV_OP_IN))
		return false;

	if (indev) {
		ret = ifname_compare_aligned(indev, info->physindev,
					     info->in_mask);

		if (!ret ^ !(info->invert & XT_PHYSDEV_OP_IN))
			return false;
	}

match_outdev:
	if (!(info->bitmask & XT_PHYSDEV_OP_OUT))
		return true;
	outdev = nf_bridge->physoutdev ?
		 nf_bridge->physoutdev->name : nulldevname;
	for (i = 0, ret = false; i < IFNAMSIZ/sizeof(unsigned int); i++) {
		ret |= (((const unsigned int *)outdev)[i]
			^ ((const unsigned int *)info->physoutdev)[i])
			& ((const unsigned int *)info->out_mask)[i];
	}

	return ret ^ !(info->invert & XT_PHYSDEV_OP_OUT);
}

static bool
physdev_mt_check(const char *tablename, const void *ip,
                 const struct xt_match *match, void *matchinfo,
                 unsigned int hook_mask)
{
	const struct xt_physdev_info *info = matchinfo;

	if (!(info->bitmask & XT_PHYSDEV_OP_MASK) ||
	    info->bitmask & ~XT_PHYSDEV_OP_MASK)
		return false;
	if (info->bitmask & XT_PHYSDEV_OP_OUT &&
	    (!(info->bitmask & XT_PHYSDEV_OP_BRIDGED) ||
	     info->invert & XT_PHYSDEV_OP_BRIDGED) &&
	    hook_mask & ((1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD) |
			 (1 << NF_INET_POST_ROUTING))) {
		printk(KERN_WARNING "physdev match: using --physdev-out in the "
		       "OUTPUT, FORWARD and POSTROUTING chains for non-bridged "
		       "traffic is not supported anymore.\n");
		if (hook_mask & (1 << NF_INET_LOCAL_OUT))
			return false;
	}
	return true;
}

static struct xt_match physdev_mt_reg[] __read_mostly = {
	{
		.name		= "physdev",
		.family		= AF_INET,
		.checkentry	= physdev_mt_check,
		.match		= physdev_mt,
		.matchsize	= sizeof(struct xt_physdev_info),
		.me		= THIS_MODULE,
	},
	{
		.name		= "physdev",
		.family		= AF_INET6,
		.checkentry	= physdev_mt_check,
		.match		= physdev_mt,
		.matchsize	= sizeof(struct xt_physdev_info),
		.me		= THIS_MODULE,
	},

	if (!outdev)
		return false;

	ret = ifname_compare_aligned(outdev, info->physoutdev, info->out_mask);

	return (!!ret ^ !(info->invert & XT_PHYSDEV_OP_OUT));
}

static int physdev_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_physdev_info *info = par->matchinfo;
	static bool brnf_probed __read_mostly;

	if (!(info->bitmask & XT_PHYSDEV_OP_MASK) ||
	    info->bitmask & ~XT_PHYSDEV_OP_MASK)
		return -EINVAL;
	if (info->bitmask & (XT_PHYSDEV_OP_OUT | XT_PHYSDEV_OP_ISOUT) &&
	    (!(info->bitmask & XT_PHYSDEV_OP_BRIDGED) ||
	     info->invert & XT_PHYSDEV_OP_BRIDGED) &&
	    par->hook_mask & ((1 << NF_INET_LOCAL_OUT) |
	    (1 << NF_INET_FORWARD) | (1 << NF_INET_POST_ROUTING))) {
		pr_info_ratelimited("--physdev-out and --physdev-is-out only supported in the FORWARD and POSTROUTING chains with bridged traffic\n");
		if (par->hook_mask & (1 << NF_INET_LOCAL_OUT))
			return -EINVAL;
	}

	if (!brnf_probed) {
		brnf_probed = true;
		request_module("br_netfilter");
	}

	return 0;
}

static struct xt_match physdev_mt_reg __read_mostly = {
	.name       = "physdev",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = physdev_mt_check,
	.match      = physdev_mt,
	.matchsize  = sizeof(struct xt_physdev_info),
	.me         = THIS_MODULE,
};

static int __init physdev_mt_init(void)
{
	return xt_register_matches(physdev_mt_reg, ARRAY_SIZE(physdev_mt_reg));
	return xt_register_match(&physdev_mt_reg);
}

static void __exit physdev_mt_exit(void)
{
	xt_unregister_matches(physdev_mt_reg, ARRAY_SIZE(physdev_mt_reg));
	xt_unregister_match(&physdev_mt_reg);
}

module_init(physdev_mt_init);
module_exit(physdev_mt_exit);
