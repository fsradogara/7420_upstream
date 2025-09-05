/*
 * Filtering ARP tables module.
 *
 * Copyright (C) 2002 David S. Miller (davem@redhat.com)
 *
 */

#include <linux/module.h>
#include <linux/netfilter_arp/arp_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_arp/arp_tables.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David S. Miller <davem@redhat.com>");
MODULE_DESCRIPTION("arptables filter table");

#define FILTER_VALID_HOOKS ((1 << NF_ARP_IN) | (1 << NF_ARP_OUT) | \
			   (1 << NF_ARP_FORWARD))

static struct
{
	struct arpt_replace repl;
	struct arpt_standard entries[3];
	struct arpt_error term;
} initial_table __net_initdata = {
	.repl = {
		.name = "filter",
		.valid_hooks = FILTER_VALID_HOOKS,
		.num_entries = 4,
		.size = sizeof(struct arpt_standard) * 3 + sizeof(struct arpt_error),
		.hook_entry = {
			[NF_ARP_IN] = 0,
			[NF_ARP_OUT] = sizeof(struct arpt_standard),
			[NF_ARP_FORWARD] = 2 * sizeof(struct arpt_standard),
		},
		.underflow = {
			[NF_ARP_IN] = 0,
			[NF_ARP_OUT] = sizeof(struct arpt_standard),
			[NF_ARP_FORWARD] = 2 * sizeof(struct arpt_standard),
		},
	},
	.entries = {
		ARPT_STANDARD_INIT(NF_ACCEPT),	/* ARP_IN */
		ARPT_STANDARD_INIT(NF_ACCEPT),	/* ARP_OUT */
		ARPT_STANDARD_INIT(NF_ACCEPT),	/* ARP_FORWARD */
	},
	.term = ARPT_ERROR_INIT,
};

static struct xt_table packet_filter = {
	.name		= "filter",
	.valid_hooks	= FILTER_VALID_HOOKS,
	.lock		= __RW_LOCK_UNLOCKED(packet_filter.lock),
	.private	= NULL,
	.me		= THIS_MODULE,
	.af		= NF_ARP,
};

/* The work comes in here from netfilter.c */
static unsigned int arpt_in_hook(unsigned int hook,
				 struct sk_buff *skb,
				 const struct net_device *in,
				 const struct net_device *out,
				 int (*okfn)(struct sk_buff *))
{
	return arpt_do_table(skb, hook, in, out,
			     dev_net(in)->ipv4.arptable_filter);
}

static unsigned int arpt_out_hook(unsigned int hook,
				  struct sk_buff *skb,
				  const struct net_device *in,
				  const struct net_device *out,
				  int (*okfn)(struct sk_buff *))
{
	return arpt_do_table(skb, hook, in, out,
			     dev_net(out)->ipv4.arptable_filter);
}

static unsigned int arpt_forward_hook(unsigned int hook,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
	return arpt_do_table(skb, hook, in, out,
			     dev_net(in)->ipv4.arptable_filter);
}

static struct nf_hook_ops arpt_ops[] __read_mostly = {
	{
		.hook		= arpt_in_hook,
		.owner		= THIS_MODULE,
		.pf		= NF_ARP,
		.hooknum	= NF_ARP_IN,
		.priority	= NF_IP_PRI_FILTER,
	},
	{
		.hook		= arpt_out_hook,
		.owner		= THIS_MODULE,
		.pf		= NF_ARP,
		.hooknum	= NF_ARP_OUT,
		.priority	= NF_IP_PRI_FILTER,
	},
	{
		.hook		= arpt_forward_hook,
		.owner		= THIS_MODULE,
		.pf		= NF_ARP,
		.hooknum	= NF_ARP_FORWARD,
		.priority	= NF_IP_PRI_FILTER,
	},
};

static int __net_init arptable_filter_net_init(struct net *net)
{
	/* Register table */
	net->ipv4.arptable_filter =
		arpt_register_table(net, &packet_filter, &initial_table.repl);
	if (IS_ERR(net->ipv4.arptable_filter))
		return PTR_ERR(net->ipv4.arptable_filter);
	return 0;
static int __net_init arptable_filter_table_init(struct net *net);

static const struct xt_table packet_filter = {
	.name		= "filter",
	.valid_hooks	= FILTER_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_ARP,
	.priority	= NF_IP_PRI_FILTER,
	.table_init	= arptable_filter_table_init,
};

/* The work comes in here from netfilter.c */
static unsigned int
arptable_filter_hook(void *priv, struct sk_buff *skb,
		     const struct nf_hook_state *state)
{
	return arpt_do_table(skb, state, state->net->ipv4.arptable_filter);
}

static struct nf_hook_ops *arpfilter_ops __read_mostly;

static int __net_init arptable_filter_table_init(struct net *net)
{
	struct arpt_replace *repl;
	int err;

	if (net->ipv4.arptable_filter)
		return 0;

	repl = arpt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
	err = arpt_register_table(net, &packet_filter, repl, arpfilter_ops,
				  &net->ipv4.arptable_filter);
	kfree(repl);
	return err;
}

static void __net_exit arptable_filter_net_exit(struct net *net)
{
	if (!net->ipv4.arptable_filter)
		return;
	arpt_unregister_table(net, net->ipv4.arptable_filter, arpfilter_ops);
	net->ipv4.arptable_filter = NULL;
}

static struct pernet_operations arptable_filter_net_ops = {
	.exit = arptable_filter_net_exit,
};

static int __init arptable_filter_init(void)
{
	int ret;

	arpfilter_ops = xt_hook_ops_alloc(&packet_filter, arptable_filter_hook);
	if (IS_ERR(arpfilter_ops))
		return PTR_ERR(arpfilter_ops);

	ret = register_pernet_subsys(&arptable_filter_net_ops);
	if (ret < 0) {
		kfree(arpfilter_ops);
		return ret;

	ret = nf_register_hooks(arpt_ops, ARRAY_SIZE(arpt_ops));
	if (ret < 0)
		goto cleanup_table;
	arpfilter_ops = xt_hook_link(&packet_filter, arptable_filter_hook);
	if (IS_ERR(arpfilter_ops)) {
		ret = PTR_ERR(arpfilter_ops);
		goto cleanup_table;
	}

	ret = arptable_filter_table_init(&init_net);
	if (ret) {
		unregister_pernet_subsys(&arptable_filter_net_ops);
		kfree(arpfilter_ops);
	}

	return ret;
}

static void __exit arptable_filter_fini(void)
{
	nf_unregister_hooks(arpt_ops, ARRAY_SIZE(arpt_ops));
	xt_hook_unlink(&packet_filter, arpfilter_ops);
	unregister_pernet_subsys(&arptable_filter_net_ops);
	kfree(arpfilter_ops);
}

module_init(arptable_filter_init);
module_exit(arptable_filter_fini);
