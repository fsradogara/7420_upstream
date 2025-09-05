/*
 * "security" table
 *
 * This is for use by Mandatory Access Control (MAC) security models,
 * which need to be able to manage security policy in separate context
 * to DAC.
 *
 * Based on iptable_mangle.c
 *
 * Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 * Copyright (C) 2000-2004 Netfilter Core Team <coreteam <at> netfilter.org>
 * Copyright (C) 2008 Red Hat, Inc., James Morris <jmorris <at> redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James Morris <jmorris <at> redhat.com>");
MODULE_DESCRIPTION("iptables security table, for MAC rules");

#define SECURITY_VALID_HOOKS	(1 << NF_INET_LOCAL_IN) | \
				(1 << NF_INET_FORWARD) | \
				(1 << NF_INET_LOCAL_OUT)

static struct
{
	struct ipt_replace repl;
	struct ipt_standard entries[3];
	struct ipt_error term;
} initial_table __net_initdata = {
	.repl = {
		.name = "security",
		.valid_hooks = SECURITY_VALID_HOOKS,
		.num_entries = 4,
		.size = sizeof(struct ipt_standard) * 3 + sizeof(struct ipt_error),
		.hook_entry = {
			[NF_INET_LOCAL_IN] 	= 0,
			[NF_INET_FORWARD] 	= sizeof(struct ipt_standard),
			[NF_INET_LOCAL_OUT] 	= sizeof(struct ipt_standard) * 2,
		},
		.underflow = {
			[NF_INET_LOCAL_IN] 	= 0,
			[NF_INET_FORWARD] 	= sizeof(struct ipt_standard),
			[NF_INET_LOCAL_OUT] 	= sizeof(struct ipt_standard) * 2,
		},
	},
	.entries = {
		IPT_STANDARD_INIT(NF_ACCEPT),	/* LOCAL_IN */
		IPT_STANDARD_INIT(NF_ACCEPT),	/* FORWARD */
		IPT_STANDARD_INIT(NF_ACCEPT),	/* LOCAL_OUT */
	},
	.term = IPT_ERROR_INIT,			/* ERROR */
};

static struct xt_table security_table = {
	.name		= "security",
	.valid_hooks	= SECURITY_VALID_HOOKS,
	.lock		= __RW_LOCK_UNLOCKED(security_table.lock),
	.me		= THIS_MODULE,
	.af		= AF_INET,
};

static unsigned int
ipt_local_in_hook(unsigned int hook,
		  struct sk_buff *skb,
		  const struct net_device *in,
		  const struct net_device *out,
		  int (*okfn)(struct sk_buff *))
{
	return ipt_do_table(skb, hook, in, out,
			    nf_local_in_net(in, out)->ipv4.iptable_security);
}

static unsigned int
ipt_forward_hook(unsigned int hook,
		 struct sk_buff *skb,
		 const struct net_device *in,
		 const struct net_device *out,
		 int (*okfn)(struct sk_buff *))
{
	return ipt_do_table(skb, hook, in, out,
			    nf_forward_net(in, out)->ipv4.iptable_security);
}

static unsigned int
ipt_local_out_hook(unsigned int hook,
		   struct sk_buff *skb,
		   const struct net_device *in,
		   const struct net_device *out,
		   int (*okfn)(struct sk_buff *))
{
	/* Somebody is playing with raw sockets. */
	if (skb->len < sizeof(struct iphdr)
	    || ip_hdrlen(skb) < sizeof(struct iphdr)) {
		if (net_ratelimit())
			printk(KERN_INFO "iptable_security: ignoring short "
			       "SOCK_RAW packet.\n");
		return NF_ACCEPT;
	}
	return ipt_do_table(skb, hook, in, out,
			    nf_local_out_net(in, out)->ipv4.iptable_security);
}

static struct nf_hook_ops ipt_ops[] __read_mostly = {
	{
		.hook		= ipt_local_in_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_SECURITY,
	},
	{
		.hook		= ipt_forward_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_SECURITY,
	},
	{
		.hook		= ipt_local_out_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_SECURITY,
	},
};

static int __net_init iptable_security_net_init(struct net *net)
{
	net->ipv4.iptable_security =
		ipt_register_table(net, &security_table, &initial_table.repl);

	if (IS_ERR(net->ipv4.iptable_security))
		return PTR_ERR(net->ipv4.iptable_security);

	return 0;
static int __net_init iptable_security_table_init(struct net *net);

static const struct xt_table security_table = {
	.name		= "security",
	.valid_hooks	= SECURITY_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_IPV4,
	.priority	= NF_IP_PRI_SECURITY,
	.table_init	= iptable_security_table_init,
};

static unsigned int
iptable_security_hook(void *priv, struct sk_buff *skb,
		      const struct nf_hook_state *state)
{
	return ipt_do_table(skb, state, state->net->ipv4.iptable_security);
}

static struct nf_hook_ops *sectbl_ops __read_mostly;

static int __net_init iptable_security_table_init(struct net *net)
{
	struct ipt_replace *repl;
	int ret;

	if (net->ipv4.iptable_security)
		return 0;

	repl = ipt_alloc_initial_table(&security_table);
	if (repl == NULL)
		return -ENOMEM;
	ret = ipt_register_table(net, &security_table, repl, sectbl_ops,
				 &net->ipv4.iptable_security);
	kfree(repl);
	return ret;
}

static void __net_exit iptable_security_net_exit(struct net *net)
{
	ipt_unregister_table(net->ipv4.iptable_security);
	ipt_unregister_table(net, net->ipv4.iptable_security);
	if (!net->ipv4.iptable_security)
		return;

	ipt_unregister_table(net, net->ipv4.iptable_security, sectbl_ops);
	net->ipv4.iptable_security = NULL;
}

static struct pernet_operations iptable_security_net_ops = {
	.exit = iptable_security_net_exit,
};

static int __init iptable_security_init(void)
{
	int ret;

	ret = register_pernet_subsys(&iptable_security_net_ops);
        if (ret < 0)
		return ret;

	ret = nf_register_hooks(ipt_ops, ARRAY_SIZE(ipt_ops));
	if (ret < 0)
		goto cleanup_table;
	if (ret < 0)
		return ret;
	sectbl_ops = xt_hook_ops_alloc(&security_table, iptable_security_hook);
	if (IS_ERR(sectbl_ops))
		return PTR_ERR(sectbl_ops);

	ret = register_pernet_subsys(&iptable_security_net_ops);
	if (ret < 0) {
		kfree(sectbl_ops);
		return ret;
	}

	ret = iptable_security_table_init(&init_net);
	if (ret) {
		unregister_pernet_subsys(&iptable_security_net_ops);
		kfree(sectbl_ops);
	}

	return ret;
}

static void __exit iptable_security_fini(void)
{
	nf_unregister_hooks(ipt_ops, ARRAY_SIZE(ipt_ops));
	xt_hook_unlink(&security_table, sectbl_ops);
	unregister_pernet_subsys(&iptable_security_net_ops);
	kfree(sectbl_ops);
}

module_init(iptable_security_init);
module_exit(iptable_security_fini);
