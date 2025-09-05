/*
 *	IPv6 tunneling device
 *	Linux INET6 implementation
 *
 *	Authors:
 *	Ville Nuorvala		<vnuorval@tcs.hut.fi>
 *	Yasuyuki Kozakai	<kozakai@linux-ipv6.org>
 *
 *      Based on:
 *      linux/net/ipv6/sit.c and linux/net/ipv4/ipip.c
 *
 *      RFC 2473
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/route.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter_ipv6.h>

#include <asm/uaccess.h>
#include <asm/atomic.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/etherdevice.h>

#include <linux/uaccess.h>
#include <linux/atomic.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ip6_tunnel.h>
#include <net/xfrm.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/dst_metadata.h>

MODULE_AUTHOR("Ville Nuorvala");
MODULE_DESCRIPTION("IPv6 tunneling device");
MODULE_LICENSE("GPL");

#define IPV6_TLV_TEL_DST_SIZE 8

#ifdef IP6_TNL_DEBUG
#define IP6_TNL_TRACE(x...) printk(KERN_DEBUG "%s:" x "\n", __func__)
#else
#define IP6_TNL_TRACE(x...) do {;} while(0)
#endif

#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT 20

#define HASH_SIZE  32

#define HASH(addr) ((__force u32)((addr)->s6_addr32[0] ^ (addr)->s6_addr32[1] ^ \
		     (addr)->s6_addr32[2] ^ (addr)->s6_addr32[3]) & \
		    (HASH_SIZE - 1))

static int ip6_fb_tnl_dev_init(struct net_device *dev);
static int ip6_tnl_dev_init(struct net_device *dev);
static void ip6_tnl_dev_setup(struct net_device *dev);

static int ip6_tnl_net_id;
MODULE_ALIAS_RTNL_LINK("ip6tnl");
MODULE_ALIAS_NETDEV("ip6tnl0");

#define IP6_TUNNEL_HASH_SIZE_SHIFT  5
#define IP6_TUNNEL_HASH_SIZE (1 << IP6_TUNNEL_HASH_SIZE_SHIFT)

static bool log_ecn_error = true;
module_param(log_ecn_error, bool, 0644);
MODULE_PARM_DESC(log_ecn_error, "Log packets received with corrupted ECN");

static u32 HASH(const struct in6_addr *addr1, const struct in6_addr *addr2)
{
	u32 hash = ipv6_addr_hash(addr1) ^ ipv6_addr_hash(addr2);

	return hash_32(hash, IP6_TUNNEL_HASH_SIZE_SHIFT);
}

static int ip6_tnl_dev_init(struct net_device *dev);
static void ip6_tnl_dev_setup(struct net_device *dev);
static struct rtnl_link_ops ip6_link_ops __read_mostly;

static unsigned int ip6_tnl_net_id __read_mostly;
struct ip6_tnl_net {
	/* the IPv6 tunnel fallback device */
	struct net_device *fb_tnl_dev;
	/* lists for storing tunnels in use */
	struct ip6_tnl *tnls_r_l[HASH_SIZE];
	struct ip6_tnl *tnls_wc[1];
	struct ip6_tnl **tnls[2];
};

/* lock for the tunnel lists */
static DEFINE_RWLOCK(ip6_tnl_lock);

static inline struct dst_entry *ip6_tnl_dst_check(struct ip6_tnl *t)
{
	struct dst_entry *dst = t->dst_cache;

	if (dst && dst->obsolete &&
	    dst->ops->check(dst, t->dst_cookie) == NULL) {
		t->dst_cache = NULL;
		dst_release(dst);
		return NULL;
	}

	return dst;
}

static inline void ip6_tnl_dst_reset(struct ip6_tnl *t)
{
	dst_release(t->dst_cache);
	t->dst_cache = NULL;
}

static inline void ip6_tnl_dst_store(struct ip6_tnl *t, struct dst_entry *dst)
{
	struct rt6_info *rt = (struct rt6_info *) dst;
	t->dst_cookie = rt->rt6i_node ? rt->rt6i_node->fn_sernum : 0;
	dst_release(t->dst_cache);
	t->dst_cache = dst;
}
	struct ip6_tnl __rcu *tnls_r_l[HASH_SIZE];
	struct ip6_tnl __rcu *tnls_r_l[IP6_TUNNEL_HASH_SIZE];
	struct ip6_tnl __rcu *tnls_wc[1];
	struct ip6_tnl __rcu **tnls[2];
	struct ip6_tnl __rcu *collect_md_tun;
};

static struct net_device_stats *ip6_get_stats(struct net_device *dev)
{
	struct pcpu_sw_netstats tmp, sum = { 0 };
	int i;

	for_each_possible_cpu(i) {
		unsigned int start;
		const struct pcpu_sw_netstats *tstats =
						   per_cpu_ptr(dev->tstats, i);

		do {
			start = u64_stats_fetch_begin_irq(&tstats->syncp);
			tmp.rx_packets = tstats->rx_packets;
			tmp.rx_bytes = tstats->rx_bytes;
			tmp.tx_packets = tstats->tx_packets;
			tmp.tx_bytes =  tstats->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&tstats->syncp, start));

		sum.rx_packets += tmp.rx_packets;
		sum.rx_bytes   += tmp.rx_bytes;
		sum.tx_packets += tmp.tx_packets;
		sum.tx_bytes   += tmp.tx_bytes;
	}
	dev->stats.rx_packets = sum.rx_packets;
	dev->stats.rx_bytes   = sum.rx_bytes;
	dev->stats.tx_packets = sum.tx_packets;
	dev->stats.tx_bytes   = sum.tx_bytes;
	return &dev->stats;
}

/**
 * ip6_tnl_lookup - fetch tunnel matching the end-point addresses
 *   @remote: the address of the tunnel exit-point
 *   @local: the address of the tunnel entry-point
 *
 * Return:
 *   tunnel matching given end-points if found,
 *   else fallback tunnel if its device is up,
 *   else %NULL
 **/

static struct ip6_tnl *
ip6_tnl_lookup(struct net *net, struct in6_addr *remote, struct in6_addr *local)
{
	unsigned h0 = HASH(remote);
	unsigned h1 = HASH(local);
	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	for (t = ip6n->tnls_r_l[h0 ^ h1]; t; t = t->next) {
#define for_each_ip6_tunnel_rcu(start) \
	for (t = rcu_dereference(start); t; t = rcu_dereference(t->next))

static struct ip6_tnl *
ip6_tnl_lookup(struct net *net, const struct in6_addr *remote, const struct in6_addr *local)
{
	unsigned int hash = HASH(remote, local);
	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	struct in6_addr any;

	for_each_ip6_tunnel_rcu(ip6n->tnls_r_l[hash]) {
		if (ipv6_addr_equal(local, &t->parms.laddr) &&
		    ipv6_addr_equal(remote, &t->parms.raddr) &&
		    (t->dev->flags & IFF_UP))
			return t;
	}
	if ((t = ip6n->tnls_wc[0]) != NULL && (t->dev->flags & IFF_UP))

	memset(&any, 0, sizeof(any));
	hash = HASH(&any, local);
	for_each_ip6_tunnel_rcu(ip6n->tnls_r_l[hash]) {
		if (ipv6_addr_equal(local, &t->parms.laddr) &&
		    ipv6_addr_any(&t->parms.raddr) &&
		    (t->dev->flags & IFF_UP))
			return t;
	}

	hash = HASH(remote, &any);
	for_each_ip6_tunnel_rcu(ip6n->tnls_r_l[hash]) {
		if (ipv6_addr_equal(remote, &t->parms.raddr) &&
		    ipv6_addr_any(&t->parms.laddr) &&
		    (t->dev->flags & IFF_UP))
			return t;
	}

	t = rcu_dereference(ip6n->collect_md_tun);
	if (t && t->dev->flags & IFF_UP)
		return t;

	t = rcu_dereference(ip6n->tnls_wc[0]);
	if (t && (t->dev->flags & IFF_UP))
		return t;

	return NULL;
}

/**
 * ip6_tnl_bucket - get head of list matching given tunnel parameters
 *   @p: parameters containing tunnel end-points
 *
 * Description:
 *   ip6_tnl_bucket() returns the head of the list matching the
 *   &struct in6_addr entries laddr and raddr in @p.
 *
 * Return: head of IPv6 tunnel list
 **/

static struct ip6_tnl **
ip6_tnl_bucket(struct ip6_tnl_net *ip6n, struct ip6_tnl_parm *p)
{
	struct in6_addr *remote = &p->raddr;
	struct in6_addr *local = &p->laddr;
	unsigned h = 0;
static struct ip6_tnl __rcu **
ip6_tnl_bucket(struct ip6_tnl_net *ip6n, const struct __ip6_tnl_parm *p)
{
	const struct in6_addr *remote = &p->raddr;
	const struct in6_addr *local = &p->laddr;
	unsigned int h = 0;
	int prio = 0;

	if (!ipv6_addr_any(remote) || !ipv6_addr_any(local)) {
		prio = 1;
		h = HASH(remote) ^ HASH(local);
		h = HASH(remote, local);
	}
	return &ip6n->tnls[prio][h];
}

/**
 * ip6_tnl_link - add tunnel to hash table
 *   @t: tunnel to be added
 **/

static void
ip6_tnl_link(struct ip6_tnl_net *ip6n, struct ip6_tnl *t)
{
	struct ip6_tnl **tp = ip6_tnl_bucket(ip6n, &t->parms);

	t->next = *tp;
	write_lock_bh(&ip6_tnl_lock);
	*tp = t;
	write_unlock_bh(&ip6_tnl_lock);
	struct ip6_tnl __rcu **tp = ip6_tnl_bucket(ip6n, &t->parms);

	if (t->parms.collect_md)
		rcu_assign_pointer(ip6n->collect_md_tun, t);
	rcu_assign_pointer(t->next , rtnl_dereference(*tp));
	rcu_assign_pointer(*tp, t);
}

/**
 * ip6_tnl_unlink - remove tunnel from hash table
 *   @t: tunnel to be removed
 **/

static void
ip6_tnl_unlink(struct ip6_tnl_net *ip6n, struct ip6_tnl *t)
{
	struct ip6_tnl **tp;

	for (tp = ip6_tnl_bucket(ip6n, &t->parms); *tp; tp = &(*tp)->next) {
		if (t == *tp) {
			write_lock_bh(&ip6_tnl_lock);
			*tp = t->next;
			write_unlock_bh(&ip6_tnl_lock);
	struct ip6_tnl __rcu **tp;
	struct ip6_tnl *iter;

	if (t->parms.collect_md)
		rcu_assign_pointer(ip6n->collect_md_tun, NULL);

	for (tp = ip6_tnl_bucket(ip6n, &t->parms);
	     (iter = rtnl_dereference(*tp)) != NULL;
	     tp = &iter->next) {
		if (t == iter) {
			rcu_assign_pointer(*tp, t->next);
			break;
		}
	}
}

/**
 * ip6_tnl_create() - create a new tunnel
static void ip6_dev_free(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);

	gro_cells_destroy(&t->gro_cells);
	dst_cache_destroy(&t->dst_cache);
	free_percpu(dev->tstats);
}

static int ip6_tnl_create2(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	int err;

	t = netdev_priv(dev);

	dev->rtnl_link_ops = &ip6_link_ops;
	err = register_netdevice(dev);
	if (err < 0)
		goto out;

	strcpy(t->parms.name, dev->name);

	dev_hold(dev);
	ip6_tnl_link(ip6n, t);
	return 0;

out:
	return err;
}

/**
 * ip6_tnl_create - create a new tunnel
 *   @p: tunnel parameters
 *   @pt: pointer to new tunnel
 *
 * Description:
 *   Create tunnel matching given parameters.
 *
 * Return:
 *   created tunnel or NULL
 **/

static struct ip6_tnl *ip6_tnl_create(struct net *net, struct ip6_tnl_parm *p)
 *   created tunnel or error pointer
 **/

static struct ip6_tnl *ip6_tnl_create(struct net *net, struct __ip6_tnl_parm *p)
{
	struct net_device *dev;
	struct ip6_tnl *t;
	char name[IFNAMSIZ];
	int err;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	int err = -ENOMEM;
	int err = -E2BIG;

	if (p->name[0]) {
		if (!dev_valid_name(p->name))
			goto failed;
		strlcpy(name, p->name, IFNAMSIZ);
	} else {
		sprintf(name, "ip6tnl%%d");

	dev = alloc_netdev(sizeof (*t), name, ip6_tnl_dev_setup);
	if (dev == NULL)
	}
	err = -ENOMEM;
	dev = alloc_netdev(sizeof(*t), name, NET_NAME_UNKNOWN,
			   ip6_tnl_dev_setup);
	if (!dev)
		goto failed;

	dev_net_set(dev, net);

	if (strchr(name, '%')) {
		if (dev_alloc_name(dev, name) < 0)
			goto failed_free;
	}

	t = netdev_priv(dev);
	dev->init = ip6_tnl_dev_init;
	t->parms = *p;

	if ((err = register_netdevice(dev)) < 0)
		goto failed_free;

	dev_hold(dev);
	ip6_tnl_link(ip6n, t);
	return t;

failed_free:
	free_netdev(dev);
failed:
	return NULL;
	t = netdev_priv(dev);
	t->parms = *p;
	t->net = dev_net(dev);
	err = ip6_tnl_create2(dev);
	if (err < 0)
		goto failed_free;

	return t;

failed_free:
	free_netdev(dev);
failed:
	return ERR_PTR(err);
}

/**
 * ip6_tnl_locate - find or create tunnel matching given parameters
 *   @p: tunnel parameters
 *   @create: != 0 if allowed to create new tunnel if no match found
 *
 * Description:
 *   ip6_tnl_locate() first tries to locate an existing tunnel
 *   based on @parms. If this is unsuccessful, but @create is set a new
 *   tunnel device is created and registered for use.
 *
 * Return:
 *   matching tunnel or NULL
 **/

static struct ip6_tnl *ip6_tnl_locate(struct net *net,
		struct ip6_tnl_parm *p, int create)
{
	struct in6_addr *remote = &p->raddr;
	struct in6_addr *local = &p->laddr;
	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	for (t = *ip6_tnl_bucket(ip6n, p); t; t = t->next) {
		if (ipv6_addr_equal(local, &t->parms.laddr) &&
		    ipv6_addr_equal(remote, &t->parms.raddr))
			return t;
	}
	if (!create)
		return NULL;
 *   matching tunnel or error pointer
 **/

static struct ip6_tnl *ip6_tnl_locate(struct net *net,
		struct __ip6_tnl_parm *p, int create)
{
	const struct in6_addr *remote = &p->raddr;
	const struct in6_addr *local = &p->laddr;
	struct ip6_tnl __rcu **tp;
	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	for (tp = ip6_tnl_bucket(ip6n, p);
	     (t = rtnl_dereference(*tp)) != NULL;
	     tp = &t->next) {
		if (ipv6_addr_equal(local, &t->parms.laddr) &&
		    ipv6_addr_equal(remote, &t->parms.raddr)) {
			if (create)
				return ERR_PTR(-EEXIST);

			return t;
		}
	}
	if (!create)
		return ERR_PTR(-ENODEV);
	return ip6_tnl_create(net, p);
}

/**
 * ip6_tnl_dev_uninit - tunnel device uninitializer
 *   @dev: the device to be destroyed
 *
 * Description:
 *   ip6_tnl_dev_uninit() removes tunnel from its list
 **/

static void
ip6_tnl_dev_uninit(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	if (dev == ip6n->fb_tnl_dev) {
		write_lock_bh(&ip6_tnl_lock);
		ip6n->tnls_wc[0] = NULL;
		write_unlock_bh(&ip6_tnl_lock);
	} else {
		ip6_tnl_unlink(ip6n, t);
	}
	struct net *net = t->net;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	if (dev == ip6n->fb_tnl_dev)
		RCU_INIT_POINTER(ip6n->tnls_wc[0], NULL);
	else
		ip6_tnl_unlink(ip6n, t);
	dst_cache_reset(&t->dst_cache);
	dev_put(dev);
}

/**
 * parse_tvl_tnl_enc_lim - handle encapsulation limit option
 *   @skb: received socket buffer
 *
 * Return:
 *   0 if none was found,
 *   else index to encapsulation limit
 **/

static __u16
parse_tlv_tnl_enc_lim(struct sk_buff *skb, __u8 * raw)
{
	struct ipv6hdr *ipv6h = (struct ipv6hdr *) raw;
	__u8 nexthdr = ipv6h->nexthdr;
	__u16 off = sizeof (*ipv6h);
__u16 ip6_tnl_parse_tlv_enc_lim(struct sk_buff *skb, __u8 *raw)
{
	const struct ipv6hdr *ipv6h = (const struct ipv6hdr *)raw;
	unsigned int nhoff = raw - skb->data;
	unsigned int off = nhoff + sizeof(*ipv6h);
	u8 next, nexthdr = ipv6h->nexthdr;

	while (ipv6_ext_hdr(nexthdr) && nexthdr != NEXTHDR_NONE) {
		struct ipv6_opt_hdr *hdr;
		if (raw + off + sizeof (*hdr) > skb->data &&
		if (raw + off + sizeof(*hdr) > skb->data &&
		    !pskb_may_pull(skb, raw - skb->data + off + sizeof (*hdr)))
		u16 optlen;

		if (!pskb_may_pull(skb, off + sizeof(*hdr)))
			break;

		hdr = (struct ipv6_opt_hdr *)(skb->data + off);
		if (nexthdr == NEXTHDR_FRAGMENT) {
			struct frag_hdr *frag_hdr = (struct frag_hdr *) hdr;
			if (frag_hdr->frag_off)
				break;
			optlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH) {
			optlen = (hdr->hdrlen + 2) << 2;
		} else {
			optlen = ipv6_optlen(hdr);
		}
		/* cache hdr->nexthdr, since pskb_may_pull() might
		 * invalidate hdr
		 */
		next = hdr->nexthdr;
		if (nexthdr == NEXTHDR_DEST) {
			u16 i = 2;

			/* Remember : hdr is no longer valid at this point. */
			if (!pskb_may_pull(skb, off + optlen))
				break;

			while (1) {
				struct ipv6_tlv_tnl_enc_lim *tel;

				/* No more room for encapsulation limit */
				if (i + sizeof(*tel) > optlen)
					break;

				tel = (struct ipv6_tlv_tnl_enc_lim *)(skb->data + off + i);
				/* return index of option if found and valid */
				if (tel->type == IPV6_TLV_TNL_ENCAP_LIMIT &&
				    tel->length == 1)
					return i + off - nhoff;
				/* else jump to next option */
				if (tel->type)
					i += tel->length + 2;
				else
					i++;
			}
		}
		nexthdr = next;
		off += optlen;
	}
	return 0;
}
EXPORT_SYMBOL(ip6_tnl_parse_tlv_enc_lim);

/**
 * ip6_tnl_err - tunnel error handler
 *
 * Description:
 *   ip6_tnl_err() should handle errors in the tunnel according
 *   to the specifications in RFC 2473.
 **/

static int
ip6_tnl_err(struct sk_buff *skb, __u8 ipproto, struct inet6_skb_parm *opt,
	    int *type, int *code, int *msg, __u32 *info, int offset)
{
	struct ipv6hdr *ipv6h = (struct ipv6hdr *) skb->data;
	struct ip6_tnl *t;
	int rel_msg = 0;
	int rel_type = ICMPV6_DEST_UNREACH;
	int rel_code = ICMPV6_ADDR_UNREACH;
	    u8 *type, u8 *code, int *msg, __u32 *info, int offset)
{
	const struct ipv6hdr *ipv6h = (const struct ipv6hdr *) skb->data;
	struct ip6_tnl *t;
	int rel_msg = 0;
	u8 rel_type = ICMPV6_DEST_UNREACH;
	u8 rel_code = ICMPV6_ADDR_UNREACH;
	u8 tproto;
	__u32 rel_info = 0;
	__u16 len;
	int err = -ENOENT;

	/* If the packet doesn't contain the original IPv6 header we are
	   in trouble since we might need the source address for further
	   processing of the error. */

	read_lock(&ip6_tnl_lock);
	if ((t = ip6_tnl_lookup(dev_net(skb->dev), &ipv6h->daddr,
					&ipv6h->saddr)) == NULL)
		goto out;

	if (t->parms.proto != ipproto && t->parms.proto != 0)
	rcu_read_lock();
	t = ip6_tnl_lookup(dev_net(skb->dev), &ipv6h->daddr, &ipv6h->saddr);
	if (!t)
		goto out;

	tproto = ACCESS_ONCE(t->parms.proto);
	if (tproto != ipproto && tproto != 0)
		goto out;

	err = 0;

	switch (*type) {
		__u32 teli;
		struct ipv6_tlv_tnl_enc_lim *tel;
		__u32 mtu;
	case ICMPV6_DEST_UNREACH:
		if (net_ratelimit())
			printk(KERN_WARNING
			       "%s: Path to destination invalid "
			       "or inactive!\n", t->parms.name);
		net_dbg_ratelimited("%s: Path to destination invalid or inactive!\n",
				    t->parms.name);
		rel_msg = 1;
		break;
	case ICMPV6_TIME_EXCEED:
		if ((*code) == ICMPV6_EXC_HOPLIMIT) {
			if (net_ratelimit())
				printk(KERN_WARNING
				       "%s: Too small hop limit or "
				       "routing loop in tunnel!\n",
				       t->parms.name);
			net_dbg_ratelimited("%s: Too small hop limit or routing loop in tunnel!\n",
					    t->parms.name);
			rel_msg = 1;
		}
		break;
	case ICMPV6_PARAMPROB:
		teli = 0;
		if ((*code) == ICMPV6_HDR_FIELD)
			teli = parse_tlv_tnl_enc_lim(skb, skb->data);
			teli = ip6_tnl_parse_tlv_enc_lim(skb, skb->data);

		if (teli && teli == *info - 2) {
			tel = (struct ipv6_tlv_tnl_enc_lim *) &skb->data[teli];
			if (tel->encap_limit == 0) {
				if (net_ratelimit())
					printk(KERN_WARNING
					       "%s: Too small encapsulation "
					       "limit or routing loop in "
					       "tunnel!\n", t->parms.name);
				rel_msg = 1;
			}
		} else if (net_ratelimit()) {
			printk(KERN_WARNING
			       "%s: Recipient unable to parse tunneled "
			       "packet!\n ", t->parms.name);
				net_dbg_ratelimited("%s: Too small encapsulation limit or routing loop in tunnel!\n",
						    t->parms.name);
				rel_msg = 1;
			}
		} else {
			net_dbg_ratelimited("%s: Recipient unable to parse tunneled packet!\n",
					    t->parms.name);
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		mtu = *info - offset;
		if (mtu < IPV6_MIN_MTU)
			mtu = IPV6_MIN_MTU;
		t->dev->mtu = mtu;

		if ((len = sizeof (*ipv6h) + ntohs(ipv6h->payload_len)) > mtu) {
		len = sizeof(*ipv6h) + ntohs(ipv6h->payload_len);
		if (len > mtu) {
			rel_type = ICMPV6_PKT_TOOBIG;
			rel_code = 0;
			rel_info = mtu;
			rel_msg = 1;
		}
		break;
	}

	*type = rel_type;
	*code = rel_code;
	*info = rel_info;
	*msg = rel_msg;

out:
	read_unlock(&ip6_tnl_lock);
	rcu_read_unlock();
	return err;
}

static int
ip4ip6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
	   int type, int code, int offset, __be32 info)
{
	int rel_msg = 0;
	int rel_type = type;
	int rel_code = code;
	__u32 rel_info = ntohl(info);
	int err;
	struct sk_buff *skb2;
	struct iphdr *eiph;
	struct flowi fl;
	struct rtable *rt;
	   u8 type, u8 code, int offset, __be32 info)
{
	int rel_msg = 0;
	u8 rel_type = type;
	u8 rel_code = code;
	__u32 rel_info = ntohl(info);
	int err;
	struct sk_buff *skb2;
	const struct iphdr *eiph;
	struct rtable *rt;
	struct flowi4 fl4;

	err = ip6_tnl_err(skb, IPPROTO_IPIP, opt, &rel_type, &rel_code,
			  &rel_msg, &rel_info, offset);
	if (err < 0)
		return err;

	if (rel_msg == 0)
		return 0;

	switch (rel_type) {
	case ICMPV6_DEST_UNREACH:
		if (rel_code != ICMPV6_ADDR_UNREACH)
			return 0;
		rel_type = ICMP_DEST_UNREACH;
		rel_code = ICMP_HOST_UNREACH;
		break;
	case ICMPV6_PKT_TOOBIG:
		if (rel_code != 0)
			return 0;
		rel_type = ICMP_DEST_UNREACH;
		rel_code = ICMP_FRAG_NEEDED;
		break;
	case NDISC_REDIRECT:
		rel_type = ICMP_REDIRECT;
		rel_code = ICMP_REDIR_HOST;
	default:
		return 0;
	}

	if (!pskb_may_pull(skb, offset + sizeof(struct iphdr)))
		return 0;

	skb2 = skb_clone(skb, GFP_ATOMIC);
	if (!skb2)
		return 0;

	dst_release(skb2->dst);
	skb2->dst = NULL;
	skb_dst_drop(skb2);

	skb_pull(skb2, offset);
	skb_reset_network_header(skb2);
	eiph = ip_hdr(skb2);

	/* Try to guess incoming interface */
	memset(&fl, 0, sizeof(fl));
	fl.fl4_dst = eiph->saddr;
	fl.fl4_tos = RT_TOS(eiph->tos);
	fl.proto = IPPROTO_IPIP;
	if (ip_route_output_key(dev_net(skb->dev), &rt, &fl))
		goto out;

	skb2->dev = rt->u.dst.dev;
	rt = ip_route_output_ports(dev_net(skb->dev), &fl4, NULL,
				   eiph->saddr, 0,
				   0, 0,
				   IPPROTO_IPIP, RT_TOS(eiph->tos), 0);
	if (IS_ERR(rt))
		goto out;

	skb2->dev = rt->dst.dev;

	/* route "incoming" packet */
	if (rt->rt_flags & RTCF_LOCAL) {
		ip_rt_put(rt);
		rt = NULL;
		fl.fl4_dst = eiph->daddr;
		fl.fl4_src = eiph->saddr;
		fl.fl4_tos = eiph->tos;
		if (ip_route_output_key(dev_net(skb->dev), &rt, &fl) ||
		    rt->u.dst.dev->type != ARPHRD_TUNNEL) {
			ip_rt_put(rt);
			goto out;
		}
		skb2->dst = (struct dst_entry *)rt;
		rt = ip_route_output_ports(dev_net(skb->dev), &fl4, NULL,
					   eiph->daddr, eiph->saddr,
					   0, 0,
					   IPPROTO_IPIP,
					   RT_TOS(eiph->tos), 0);
		if (IS_ERR(rt) ||
		    rt->dst.dev->type != ARPHRD_TUNNEL) {
			if (!IS_ERR(rt))
				ip_rt_put(rt);
			goto out;
		}
		skb_dst_set(skb2, &rt->dst);
	} else {
		ip_rt_put(rt);
		if (ip_route_input(skb2, eiph->daddr, eiph->saddr, eiph->tos,
				   skb2->dev) ||
		    skb2->dst->dev->type != ARPHRD_TUNNEL)
		    skb_dst(skb2)->dev->type != ARPHRD_TUNNEL)
			goto out;
	}

	/* change mtu on this route */
	if (rel_type == ICMP_DEST_UNREACH && rel_code == ICMP_FRAG_NEEDED) {
		if (rel_info > dst_mtu(skb2->dst))
			goto out;

		skb2->dst->ops->update_pmtu(skb2->dst, rel_info);
	}
		if (rel_info > dst_mtu(skb_dst(skb2)))
			goto out;

		skb_dst_update_pmtu(skb2, rel_info);
	}
	if (rel_type == ICMP_REDIRECT)
		skb_dst(skb2)->ops->redirect(skb_dst(skb2), NULL, skb2);

	icmp_send(skb2, rel_type, rel_code, htonl(rel_info));

out:
	kfree_skb(skb2);
	return 0;
}

static int
ip6ip6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
	   int type, int code, int offset, __be32 info)
{
	int rel_msg = 0;
	int rel_type = type;
	int rel_code = code;
	   u8 type, u8 code, int offset, __be32 info)
{
	int rel_msg = 0;
	u8 rel_type = type;
	u8 rel_code = code;
	__u32 rel_info = ntohl(info);
	int err;

	err = ip6_tnl_err(skb, IPPROTO_IPV6, opt, &rel_type, &rel_code,
			  &rel_msg, &rel_info, offset);
	if (err < 0)
		return err;

	if (rel_msg && pskb_may_pull(skb, offset + sizeof(struct ipv6hdr))) {
		struct rt6_info *rt;
		struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);

		if (!skb2)
			return 0;

		dst_release(skb2->dst);
		skb2->dst = NULL;
		skb_dst_drop(skb2);
		skb_pull(skb2, offset);
		skb_reset_network_header(skb2);

		/* Try to guess incoming interface */
		rt = rt6_lookup(dev_net(skb->dev), &ipv6_hdr(skb2)->saddr,
				NULL, 0, 0);

		if (rt && rt->rt6i_dev)
			skb2->dev = rt->rt6i_dev;

		icmpv6_send(skb2, rel_type, rel_code, rel_info, skb2->dev);

		if (rt)
			dst_release(&rt->u.dst);
		if (rt && rt->dst.dev)
			skb2->dev = rt->dst.dev;

		icmpv6_send(skb2, rel_type, rel_code, rel_info);

		ip6_rt_put(rt);

		kfree_skb(skb2);
	}

	return 0;
}

static void ip4ip6_dscp_ecn_decapsulate(struct ip6_tnl *t,
					struct ipv6hdr *ipv6h,
					struct sk_buff *skb)
static int ip4ip6_dscp_ecn_decapsulate(const struct ip6_tnl *t,
				       const struct ipv6hdr *ipv6h,
				       struct sk_buff *skb)
{
	__u8 dsfield = ipv6_get_dsfield(ipv6h) & ~INET_ECN_MASK;

	if (t->parms.flags & IP6_TNL_F_RCV_DSCP_COPY)
		ipv4_change_dsfield(ip_hdr(skb), INET_ECN_MASK, dsfield);

	if (INET_ECN_is_ce(dsfield))
		IP_ECN_set_ce(ip_hdr(skb));
}

static void ip6ip6_dscp_ecn_decapsulate(struct ip6_tnl *t,
					struct ipv6hdr *ipv6h,
					struct sk_buff *skb)
	return IP6_ECN_decapsulate(ipv6h, skb);
}

static int ip6ip6_dscp_ecn_decapsulate(const struct ip6_tnl *t,
				       const struct ipv6hdr *ipv6h,
				       struct sk_buff *skb)
{
	if (t->parms.flags & IP6_TNL_F_RCV_DSCP_COPY)
		ipv6_copy_dscp(ipv6_get_dsfield(ipv6h), ipv6_hdr(skb));

	if (INET_ECN_is_ce(ipv6_get_dsfield(ipv6h)))
		IP6_ECN_set_ce(ipv6_hdr(skb));
}

static inline int ip6_tnl_rcv_ctl(struct ip6_tnl *t)
{
	struct ip6_tnl_parm *p = &t->parms;
	int ret = 0;
	struct net *net = dev_net(t->dev);

	if (p->flags & IP6_TNL_F_CAP_RCV) {
		struct net_device *ldev = NULL;

		if (p->link)
			ldev = dev_get_by_index(net, p->link);

		if ((ipv6_addr_is_multicast(&p->laddr) ||
		     likely(ipv6_chk_addr(net, &p->laddr, ldev, 0))) &&
		    likely(!ipv6_chk_addr(net, &p->raddr, NULL, 0)))
			ret = 1;

		if (ldev)
			dev_put(ldev);
	}
	return ret;
}
	return IP6_ECN_decapsulate(ipv6h, skb);
}

__u32 ip6_tnl_get_cap(struct ip6_tnl *t,
			     const struct in6_addr *laddr,
			     const struct in6_addr *raddr)
{
	struct __ip6_tnl_parm *p = &t->parms;
	int ltype = ipv6_addr_type(laddr);
	int rtype = ipv6_addr_type(raddr);
	__u32 flags = 0;

	if (ltype == IPV6_ADDR_ANY || rtype == IPV6_ADDR_ANY) {
		flags = IP6_TNL_F_CAP_PER_PACKET;
	} else if (ltype & (IPV6_ADDR_UNICAST|IPV6_ADDR_MULTICAST) &&
		   rtype & (IPV6_ADDR_UNICAST|IPV6_ADDR_MULTICAST) &&
		   !((ltype|rtype) & IPV6_ADDR_LOOPBACK) &&
		   (!((ltype|rtype) & IPV6_ADDR_LINKLOCAL) || p->link)) {
		if (ltype&IPV6_ADDR_UNICAST)
			flags |= IP6_TNL_F_CAP_XMIT;
		if (rtype&IPV6_ADDR_UNICAST)
			flags |= IP6_TNL_F_CAP_RCV;
	}
	return flags;
}
EXPORT_SYMBOL(ip6_tnl_get_cap);

/* called with rcu_read_lock() */
int ip6_tnl_rcv_ctl(struct ip6_tnl *t,
				  const struct in6_addr *laddr,
				  const struct in6_addr *raddr)
{
	struct __ip6_tnl_parm *p = &t->parms;
	int ret = 0;
	struct net *net = t->net;

	if ((p->flags & IP6_TNL_F_CAP_RCV) ||
	    ((p->flags & IP6_TNL_F_CAP_PER_PACKET) &&
	     (ip6_tnl_get_cap(t, laddr, raddr) & IP6_TNL_F_CAP_RCV))) {
		struct net_device *ldev = NULL;

		if (p->link)
			ldev = dev_get_by_index_rcu(net, p->link);

		if ((ipv6_addr_is_multicast(laddr) ||
		     likely(ipv6_chk_addr(net, laddr, ldev, 0))) &&
		    likely(!ipv6_chk_addr(net, raddr, NULL, 0)))
			ret = 1;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(ip6_tnl_rcv_ctl);

static int __ip6_tnl_rcv(struct ip6_tnl *tunnel, struct sk_buff *skb,
			 const struct tnl_ptk_info *tpi,
			 struct metadata_dst *tun_dst,
			 int (*dscp_ecn_decapsulate)(const struct ip6_tnl *t,
						const struct ipv6hdr *ipv6h,
						struct sk_buff *skb),
			 bool log_ecn_err)
{
	struct pcpu_sw_netstats *tstats;
	const struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	int err;

static int ip6_tnl_rcv(struct sk_buff *skb, __u16 protocol,
		       __u8 ipproto,
		       void (*dscp_ecn_decapsulate)(struct ip6_tnl *t,
						    struct ipv6hdr *ipv6h,
						    struct sk_buff *skb))
{
	struct ip6_tnl *t;
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);

	read_lock(&ip6_tnl_lock);

	if ((t = ip6_tnl_lookup(dev_net(skb->dev), &ipv6h->saddr,
					&ipv6h->daddr)) != NULL) {
		if (t->parms.proto != ipproto && t->parms.proto != 0) {
			read_unlock(&ip6_tnl_lock);
		       int (*dscp_ecn_decapsulate)(const struct ip6_tnl *t,
						   const struct ipv6hdr *ipv6h,
						   struct sk_buff *skb))
	if ((!(tpi->flags & TUNNEL_CSUM) &&
	     (tunnel->parms.i_flags & TUNNEL_CSUM)) ||
	    ((tpi->flags & TUNNEL_CSUM) &&
	     !(tunnel->parms.i_flags & TUNNEL_CSUM))) {
		tunnel->dev->stats.rx_crc_errors++;
		tunnel->dev->stats.rx_errors++;
		goto drop;
	}

	if (tunnel->parms.i_flags & TUNNEL_SEQ) {
		if (!(tpi->flags & TUNNEL_SEQ) ||
		    (tunnel->i_seqno &&
		     (s32)(ntohl(tpi->seq) - tunnel->i_seqno) < 0)) {
			tunnel->dev->stats.rx_fifo_errors++;
			tunnel->dev->stats.rx_errors++;
			goto drop;
		}
		tunnel->i_seqno = ntohl(tpi->seq) + 1;
	}

	skb->protocol = tpi->proto;

	/* Warning: All skb pointers will be invalidated! */
	if (tunnel->dev->type == ARPHRD_ETHER) {
		if (!pskb_may_pull(skb, ETH_HLEN)) {
			tunnel->dev->stats.rx_length_errors++;
			tunnel->dev->stats.rx_errors++;
			goto drop;
		}

		ipv6h = ipv6_hdr(skb);
		skb->protocol = eth_type_trans(skb, tunnel->dev);
		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
	} else {
		skb->dev = tunnel->dev;
	}

	skb_reset_network_header(skb);
	memset(skb->cb, 0, sizeof(struct inet6_skb_parm));

	__skb_tunnel_rx(skb, tunnel->dev, tunnel->net);

	err = dscp_ecn_decapsulate(tunnel, ipv6h, skb);
	if (unlikely(err)) {
		if (log_ecn_err)
			net_info_ratelimited("non-ECT from %pI6 with DS=%#x\n",
					     &ipv6h->saddr,
					     ipv6_get_dsfield(ipv6h));
		if (err > 1) {
			++tunnel->dev->stats.rx_frame_errors;
			++tunnel->dev->stats.rx_errors;
			goto drop;
		}
	}

	tstats = this_cpu_ptr(tunnel->dev->tstats);
	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_packets++;
	tstats->rx_bytes += skb->len;
	u64_stats_update_end(&tstats->syncp);

	skb_scrub_packet(skb, !net_eq(tunnel->net, dev_net(tunnel->dev)));

	if (tun_dst)
		skb_dst_set(skb, (struct dst_entry *)tun_dst);

	gro_cells_receive(&tunnel->gro_cells, skb);
	return 0;

drop:
	if (tun_dst)
		dst_release((struct dst_entry *)tun_dst);
	kfree_skb(skb);
	return 0;
}

int ip6_tnl_rcv(struct ip6_tnl *t, struct sk_buff *skb,
		const struct tnl_ptk_info *tpi,
		struct metadata_dst *tun_dst,
		bool log_ecn_err)
{
	return __ip6_tnl_rcv(t, skb, tpi, NULL, ip6ip6_dscp_ecn_decapsulate,
			     log_ecn_err);
}
EXPORT_SYMBOL(ip6_tnl_rcv);

static const struct tnl_ptk_info tpi_v6 = {
	/* no tunnel info required for ipxip6. */
	.proto = htons(ETH_P_IPV6),
};

static const struct tnl_ptk_info tpi_v4 = {
	/* no tunnel info required for ipxip6. */
	.proto = htons(ETH_P_IP),
};

static int ipxip6_rcv(struct sk_buff *skb, u8 ipproto,
		      const struct tnl_ptk_info *tpi,
		      int (*dscp_ecn_decapsulate)(const struct ip6_tnl *t,
						  const struct ipv6hdr *ipv6h,
						  struct sk_buff *skb))
{
	struct ip6_tnl *t;
	const struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct metadata_dst *tun_dst = NULL;
	int ret = -1;

	rcu_read_lock();
	t = ip6_tnl_lookup(dev_net(skb->dev), &ipv6h->saddr, &ipv6h->daddr);

	if (t) {
		u8 tproto = ACCESS_ONCE(t->parms.proto);

		if (tproto != ipproto && tproto != 0)
			goto drop;
		if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto drop;
		if (!ip6_tnl_rcv_ctl(t, &ipv6h->daddr, &ipv6h->saddr))
			goto drop;
		if (iptunnel_pull_header(skb, 0, tpi->proto, false))
			goto drop;
		if (t->parms.collect_md) {
			tun_dst = ipv6_tun_rx_dst(skb, 0, 0, 0);
			if (!tun_dst)
				goto drop;
		}

		if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb)) {
			read_unlock(&ip6_tnl_lock);
			goto discard;
		}

		if (!ip6_tnl_rcv_ctl(t)) {
			t->dev->stats.rx_dropped++;
			read_unlock(&ip6_tnl_lock);
			goto discard;
		}
		secpath_reset(skb);
		skb->mac_header = skb->network_header;
		skb_reset_network_header(skb);
		skb->protocol = htons(protocol);
		skb->pkt_type = PACKET_HOST;
		memset(skb->cb, 0, sizeof(struct inet6_skb_parm));
		skb->dev = t->dev;
		dst_release(skb->dst);
		skb->dst = NULL;
		nf_reset(skb);

		dscp_ecn_decapsulate(t, ipv6h, skb);

		t->dev->stats.rx_packets++;
		t->dev->stats.rx_bytes += skb->len;
		netif_rx(skb);
		read_unlock(&ip6_tnl_lock);
		return 0;
	}
	read_unlock(&ip6_tnl_lock);
			rcu_read_unlock();
			goto discard;
		}

		if (!ip6_tnl_rcv_ctl(t, &ipv6h->daddr, &ipv6h->saddr)) {
			t->dev->stats.rx_dropped++;
			rcu_read_unlock();
			goto discard;
		}
		skb->mac_header = skb->network_header;
		skb_reset_network_header(skb);
		skb->protocol = htons(protocol);
		memset(skb->cb, 0, sizeof(struct inet6_skb_parm));

		__skb_tunnel_rx(skb, t->dev, t->net);

		err = dscp_ecn_decapsulate(t, ipv6h, skb);
		if (unlikely(err)) {
			if (log_ecn_error)
				net_info_ratelimited("non-ECT from %pI6 with dsfield=%#x\n",
						     &ipv6h->saddr,
						     ipv6_get_dsfield(ipv6h));
			if (err > 1) {
				++t->dev->stats.rx_frame_errors;
				++t->dev->stats.rx_errors;
				rcu_read_unlock();
				goto discard;
			}
		}

		tstats = this_cpu_ptr(t->dev->tstats);
		u64_stats_update_begin(&tstats->syncp);
		tstats->rx_packets++;
		tstats->rx_bytes += skb->len;
		u64_stats_update_end(&tstats->syncp);

		netif_rx(skb);

		rcu_read_unlock();
		return 0;
		ret = __ip6_tnl_rcv(t, skb, tpi, tun_dst, dscp_ecn_decapsulate,
				    log_ecn_error);
	}

	rcu_read_unlock();

	return ret;

drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}

static int ip4ip6_rcv(struct sk_buff *skb)
{
	return ipxip6_rcv(skb, IPPROTO_IPIP, &tpi_v4,
			  ip4ip6_dscp_ecn_decapsulate);
}

static int ip6ip6_rcv(struct sk_buff *skb)
{
	return ipxip6_rcv(skb, IPPROTO_IPV6, &tpi_v6,
			  ip6ip6_dscp_ecn_decapsulate);
}

struct ipv6_tel_txoption {
	struct ipv6_txoptions ops;
	__u8 dst_opt[8];
};

static void init_tel_txopt(struct ipv6_tel_txoption *opt, __u8 encap_limit)
{
	memset(opt, 0, sizeof(struct ipv6_tel_txoption));

	opt->dst_opt[2] = IPV6_TLV_TNL_ENCAP_LIMIT;
	opt->dst_opt[3] = 1;
	opt->dst_opt[4] = encap_limit;
	opt->dst_opt[5] = IPV6_TLV_PADN;
	opt->dst_opt[6] = 1;

	opt->ops.dst1opt = (struct ipv6_opt_hdr *) opt->dst_opt;
	opt->ops.opt_nflen = 8;
}

/**
 * ip6_tnl_addr_conflict - compare packet addresses to tunnel's own
 *   @t: the outgoing tunnel device
 *   @hdr: IPv6 header from the incoming packet
 *
 * Description:
 *   Avoid trivial tunneling loop by checking that tunnel exit-point
 *   doesn't match source of incoming packet.
 *
 * Return:
 *   1 if conflict,
 *   0 else
 **/

static inline int
ip6_tnl_addr_conflict(struct ip6_tnl *t, struct ipv6hdr *hdr)
static inline bool
ip6_tnl_addr_conflict(const struct ip6_tnl *t, const struct ipv6hdr *hdr)
{
	return ipv6_addr_equal(&t->parms.raddr, &hdr->saddr);
}

static inline int ip6_tnl_xmit_ctl(struct ip6_tnl *t)
{
	struct ip6_tnl_parm *p = &t->parms;
	int ret = 0;
	struct net *net = dev_net(t->dev);

	if (p->flags & IP6_TNL_F_CAP_XMIT) {
		struct net_device *ldev = NULL;

		if (p->link)
			ldev = dev_get_by_index(net, p->link);

		if (unlikely(!ipv6_chk_addr(net, &p->laddr, ldev, 0)))
			printk(KERN_WARNING
			       "%s xmit: Local address not yet configured!\n",
			       p->name);
		else if (!ipv6_addr_is_multicast(&p->raddr) &&
			 unlikely(ipv6_chk_addr(net, &p->raddr, NULL, 0)))
			printk(KERN_WARNING
			       "%s xmit: Routing loop! "
			       "Remote address found on this node!\n",
			       p->name);
		else
			ret = 1;
		if (ldev)
			dev_put(ldev);
	}
	return ret;
}
int ip6_tnl_xmit_ctl(struct ip6_tnl *t,
		     const struct in6_addr *laddr,
		     const struct in6_addr *raddr)
{
	struct __ip6_tnl_parm *p = &t->parms;
	int ret = 0;
	struct net *net = t->net;

	if ((p->flags & IP6_TNL_F_CAP_XMIT) ||
	    ((p->flags & IP6_TNL_F_CAP_PER_PACKET) &&
	     (ip6_tnl_get_cap(t, laddr, raddr) & IP6_TNL_F_CAP_XMIT))) {
		struct net_device *ldev = NULL;

		rcu_read_lock();
		if (p->link)
			ldev = dev_get_by_index_rcu(net, p->link);

		if (unlikely(!ipv6_chk_addr(net, laddr, ldev, 0)))
			pr_warn("%s xmit: Local address not yet configured!\n",
				p->name);
		else if (!ipv6_addr_is_multicast(raddr) &&
			 unlikely(ipv6_chk_addr(net, raddr, NULL, 0)))
			pr_warn("%s xmit: Routing loop! Remote address found on this node!\n",
				p->name);
		else
			ret = 1;
		rcu_read_unlock();
	}
	return ret;
}
EXPORT_SYMBOL_GPL(ip6_tnl_xmit_ctl);

/**
 * ip6_tnl_xmit - encapsulate packet and send
 *   @skb: the outgoing socket buffer
 *   @dev: the outgoing tunnel device
 *   @dsfield: dscp code for outer header
 *   @fl6: flow of tunneled packet
 *   @encap_limit: encapsulation limit
 *   @pmtu: Path MTU is stored if packet is too big
 *   @proto: next header value
 *
 * Description:
 *   Build new header and do some sanity checks on the packet before sending
 *   it.
 *
 * Return:
 *   0 on success
 *   -1 fail
 *   %-EMSGSIZE message too big. return mtu in this case.
 **/

static int ip6_tnl_xmit2(struct sk_buff *skb,
			 struct net_device *dev,
			 __u8 dsfield,
			 struct flowi *fl,
			 struct flowi6 *fl6,
			 int encap_limit,
			 __u32 *pmtu)
int ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev, __u8 dsfield,
		 struct flowi6 *fl6, int encap_limit, __u32 *pmtu,
		 __u8 proto)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct ipv6_tel_txoption opt;
	struct dst_entry *dst;
	struct net *net = t->net;
	struct net_device_stats *stats = &t->dev->stats;
	struct ipv6hdr *ipv6h;
	struct ipv6_tel_txoption opt;
	struct dst_entry *dst = NULL, *ndst = NULL;
	struct net_device *tdev;
	int mtu;
	unsigned int eth_hlen = t->dev->type == ARPHRD_ETHER ? ETH_HLEN : 0;
	unsigned int psh_hlen = sizeof(struct ipv6hdr) + t->encap_hlen;
	unsigned int max_headroom = psh_hlen;
	bool use_cache = false;
	u8 hop_limit;
	int err = -1;
	int pkt_len;

	if ((dst = ip6_tnl_dst_check(t)) != NULL)
		dst_hold(dst);
	else {
		dst = ip6_route_output(dev_net(dev), NULL, fl);

		if (dst->error || xfrm_lookup(&dst, fl, NULL, 0) < 0)
			goto tx_err_link_failure;

	if (t->parms.collect_md) {
		hop_limit = skb_tunnel_info(skb)->key.ttl;
		goto route_lookup;
	} else {
		hop_limit = t->parms.hop_limit;
	}

	/* NBMA tunnel */
	if (ipv6_addr_any(&t->parms.raddr)) {
		if (skb->protocol == htons(ETH_P_IPV6)) {
			struct in6_addr *addr6;
			struct neighbour *neigh;
			int addr_type;

			if (!skb_dst(skb))
				goto tx_err_link_failure;

			neigh = dst_neigh_lookup(skb_dst(skb),
						 &ipv6_hdr(skb)->daddr);
			if (!neigh)
				goto tx_err_link_failure;

			addr6 = (struct in6_addr *)&neigh->primary_key;
			addr_type = ipv6_addr_type(addr6);

			if (addr_type == IPV6_ADDR_ANY)
				addr6 = &ipv6_hdr(skb)->daddr;

			memcpy(&fl6->daddr, addr6, sizeof(fl6->daddr));
			neigh_release(neigh);
		}
	} else if (t->parms.proto != 0 && !(t->parms.flags &
					    (IP6_TNL_F_USE_ORIG_TCLASS |
					     IP6_TNL_F_USE_ORIG_FWMARK))) {
		/* enable the cache only if neither the outer protocol nor the
		 * routing decision depends on the current inner header value
		 */
		use_cache = true;
	}

	if (use_cache)
		dst = dst_cache_get(&t->dst_cache);

	if (!ip6_tnl_xmit_ctl(t, &fl6->saddr, &fl6->daddr))
		goto tx_err_link_failure;

	if (!dst) {
route_lookup:
		/* add dsfield to flowlabel for route lookup */
		fl6->flowlabel = ip6_make_flowinfo(dsfield, fl6->flowlabel);

		dst = ip6_route_output(net, NULL, fl6);

		if (dst->error)
			goto tx_err_link_failure;
		dst = xfrm_lookup(net, dst, flowi6_to_flowi(fl6), NULL, 0);
		if (IS_ERR(dst)) {
			err = PTR_ERR(dst);
			dst = NULL;
			goto tx_err_link_failure;
		}
		if (t->parms.collect_md &&
		    ipv6_dev_get_saddr(net, ip6_dst_idev(dst)->dev,
				       &fl6->daddr, 0, &fl6->saddr))
			goto tx_err_link_failure;
		ndst = dst;
	}

	tdev = dst->dev;

	if (tdev == dev) {
		stats->collisions++;
		if (net_ratelimit())
			printk(KERN_WARNING
			       "%s: Local routing loop detected!\n",
			       t->parms.name);
		goto tx_err_dst_release;
	}
	mtu = dst_mtu(dst) - sizeof (*ipv6h);
		net_warn_ratelimited("%s: Local routing loop detected!\n",
				     t->parms.name);
		goto tx_err_dst_release;
	}
	mtu = dst_mtu(dst) - eth_hlen - psh_hlen - t->tun_hlen;
	if (encap_limit >= 0) {
		max_headroom += 8;
		mtu -= 8;
	}
	if (mtu < IPV6_MIN_MTU)
		mtu = IPV6_MIN_MTU;
	if (skb->dst)
		skb->dst->ops->update_pmtu(skb->dst, mtu);
	if (skb_dst(skb))
	if (skb_dst(skb) && !t->parms.collect_md)
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);
	if (skb->protocol == htons(ETH_P_IPV6)) {
		if (mtu < IPV6_MIN_MTU)
			mtu = IPV6_MIN_MTU;
	} else if (mtu < 576) {
		mtu = 576;
	}

	skb_dst_update_pmtu(skb, mtu);
	if (skb->len - t->tun_hlen - eth_hlen > mtu && !skb_is_gso(skb)) {
		*pmtu = mtu;
		err = -EMSGSIZE;
		goto tx_err_dst_release;
	}

	if (t->err_count > 0) {
		if (time_before(jiffies,
				t->err_time + IP6TUNNEL_ERR_TIMEO)) {
			t->err_count--;

			dst_link_failure(skb);
		} else {
			t->err_count = 0;
		}
	}

	skb_scrub_packet(skb, !net_eq(t->net, dev_net(dev)));

	/*
	 * Okay, now see if we can stuff it in the buffer as-is.
	 */
	max_headroom += LL_RESERVED_SPACE(tdev);

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *new_skb;

		if (!(new_skb = skb_realloc_headroom(skb, max_headroom)))
		new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb)
			goto tx_err_dst_release;

		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		kfree_skb(skb);
		skb = new_skb;
	}
	dst_release(skb->dst);
	skb->dst = dst_clone(dst);

	skb->transport_header = skb->network_header;

	proto = fl->proto;
		consume_skb(skb);
		skb = new_skb;
	}

	if (t->parms.collect_md) {
		if (t->encap.type != TUNNEL_ENCAP_NONE)
			goto tx_err_dst_release;
	} else {
		if (use_cache && ndst)
			dst_cache_set_ip6(&t->dst_cache, ndst, &fl6->saddr);
	}
	skb_dst_set(skb, dst);

	if (encap_limit >= 0) {
		init_tel_txopt(&opt, encap_limit);
		ipv6_push_frag_opts(skb, &opt.ops, &proto);
	}
	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	ipv6h = ipv6_hdr(skb);
	*(__be32*)ipv6h = fl->fl6_flowlabel | htonl(0x60000000);
	dsfield = INET_ECN_encapsulate(0, dsfield);
	ipv6_change_dsfield(ipv6h, ~INET_ECN_MASK, dsfield);
	ipv6h->hop_limit = t->parms.hop_limit;
	ipv6h->nexthdr = proto;
	ipv6_addr_copy(&ipv6h->saddr, &fl->fl6_src);
	ipv6_addr_copy(&ipv6h->daddr, &fl->fl6_dst);
	nf_reset(skb);
	pkt_len = skb->len;
	err = ip6_local_out(skb);

	if (net_xmit_eval(err) == 0) {
		stats->tx_bytes += pkt_len;
		stats->tx_packets++;
	} else {
		stats->tx_errors++;
		stats->tx_aborted_errors++;
	}
	ip6_tnl_dst_store(t, dst);
	hop_limit = hop_limit ? : ip6_dst_hoplimit(dst);

	/* Calculate max headroom for all the headers and adjust
	 * needed_headroom if necessary.
	 */
	max_headroom = LL_RESERVED_SPACE(dst->dev) + sizeof(struct ipv6hdr)
			+ dst->header_len + t->hlen;
	if (max_headroom > dev->needed_headroom)
		dev->needed_headroom = max_headroom;

	err = ip6_tnl_encap(skb, t, &proto, fl6);
	if (err)
		return err;

	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	ipv6h = ipv6_hdr(skb);
	ip6_flow_hdr(ipv6h, dsfield,
		     ip6_make_flowlabel(net, skb, fl6->flowlabel, true, fl6));
	ipv6h->hop_limit = hop_limit;
	ipv6h->nexthdr = proto;
	ipv6h->saddr = fl6->saddr;
	ipv6h->daddr = fl6->daddr;
	ip6tunnel_xmit(NULL, skb, dev);
	return 0;
tx_err_link_failure:
	stats->tx_carrier_errors++;
	dst_link_failure(skb);
tx_err_dst_release:
	dst_release(dst);
	return err;
}
EXPORT_SYMBOL(ip6_tnl_xmit);

static inline int
ip4ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct iphdr  *iph = ip_hdr(skb);
	int encap_limit = -1;
	struct flowi fl;
	__u8 dsfield;
	__u32 mtu;
	int err;

	if ((t->parms.proto != IPPROTO_IPIP && t->parms.proto != 0) ||
	    !ip6_tnl_xmit_ctl(t))
	const struct iphdr  *iph = ip_hdr(skb);
	int encap_limit = -1;
	struct flowi6 fl6;
	__u8 dsfield;
	__u32 mtu;
	u8 tproto;
	int err;

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	tproto = ACCESS_ONCE(t->parms.proto);
	if (tproto != IPPROTO_IPIP && tproto != 0)
		return -1;

	if (t->parms.collect_md) {
		struct ip_tunnel_info *tun_info;
		const struct ip_tunnel_key *key;

	memcpy(&fl, &t->fl, sizeof (fl));
	fl.proto = IPPROTO_IPIP;

	dsfield = ipv4_get_dsfield(iph);

	if ((t->parms.flags & IP6_TNL_F_USE_ORIG_TCLASS))
		fl.fl6_flowlabel |= htonl((__u32)iph->tos << IPV6_TCLASS_SHIFT)
					  & IPV6_TCLASS_MASK;

	err = ip6_tnl_xmit2(skb, dev, dsfield, &fl, encap_limit, &mtu);
	memcpy(&fl6, &t->fl.u.ip6, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_IPIP;
		tun_info = skb_tunnel_info(skb);
		if (unlikely(!tun_info || !(tun_info->mode & IP_TUNNEL_INFO_TX) ||
			     ip_tunnel_info_af(tun_info) != AF_INET6))
			return -1;
		key = &tun_info->key;
		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_IPIP;
		fl6.daddr = key->u.ipv6.dst;
		fl6.flowlabel = key->label;
		dsfield =  key->tos;
	} else {
		if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
			encap_limit = t->parms.encap_limit;

		memcpy(&fl6, &t->fl.u.ip6, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_IPIP;

		if (t->parms.flags & IP6_TNL_F_USE_ORIG_TCLASS)
			dsfield = ipv4_get_dsfield(iph);
		else
			dsfield = ip6_tclass(t->parms.flowinfo);
		if (t->parms.flags & IP6_TNL_F_USE_ORIG_FWMARK)
			fl6.flowi6_mark = skb->mark;
		else
			fl6.flowi6_mark = t->parms.fwmark;
	}

	fl6.flowi6_uid = sock_net_uid(dev_net(dev), NULL);

	if (iptunnel_handle_offloads(skb, SKB_GSO_IPXIP6))
		return -1;

	dsfield = INET_ECN_encapsulate(dsfield, ipv4_get_dsfield(iph));

	skb_set_inner_ipproto(skb, IPPROTO_IPIP);

	err = ip6_tnl_xmit(skb, dev, dsfield, &fl6, encap_limit, &mtu,
			   IPPROTO_IPIP);
	if (err != 0) {
		/* XXX: send ICMP error even if DF is not set. */
		if (err == -EMSGSIZE)
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu));
		return -1;
	}

	return 0;
}

static inline int
ip6ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	int encap_limit = -1;
	__u16 offset;
	struct flowi fl;
	__u8 dsfield;
	__u32 mtu;
	int err;

	if ((t->parms.proto != IPPROTO_IPV6 && t->parms.proto != 0) ||
	    !ip6_tnl_xmit_ctl(t) || ip6_tnl_addr_conflict(t, ipv6h))
		return -1;

	offset = parse_tlv_tnl_enc_lim(skb, skb_network_header(skb));
	struct flowi6 fl6;
	__u8 dsfield;
	__u32 mtu;
	u8 tproto;
	int err;

	tproto = ACCESS_ONCE(t->parms.proto);
	if ((tproto != IPPROTO_IPV6 && tproto != 0) ||
	    ip6_tnl_addr_conflict(t, ipv6h))
		return -1;

	offset = ip6_tnl_parse_tlv_enc_lim(skb, skb_network_header(skb));
	if (offset > 0) {
		struct ipv6_tlv_tnl_enc_lim *tel;
		tel = (struct ipv6_tlv_tnl_enc_lim *)&skb_network_header(skb)[offset];
		if (tel->encap_limit == 0) {
			icmpv6_send(skb, ICMPV6_PARAMPROB,
				    ICMPV6_HDR_FIELD, offset + 2, skb->dev);
				    ICMPV6_HDR_FIELD, offset + 2);
	if (t->parms.collect_md) {
		struct ip_tunnel_info *tun_info;
		const struct ip_tunnel_key *key;

		tun_info = skb_tunnel_info(skb);
		if (unlikely(!tun_info || !(tun_info->mode & IP_TUNNEL_INFO_TX) ||
			     ip_tunnel_info_af(tun_info) != AF_INET6))
			return -1;
		key = &tun_info->key;
		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_IPV6;
		fl6.daddr = key->u.ipv6.dst;
		fl6.flowlabel = key->label;
		dsfield = key->tos;
	} else {
		offset = ip6_tnl_parse_tlv_enc_lim(skb, skb_network_header(skb));
		/* ip6_tnl_parse_tlv_enc_lim() might have reallocated skb->head */
		ipv6h = ipv6_hdr(skb);
		if (offset > 0) {
			struct ipv6_tlv_tnl_enc_lim *tel;

			tel = (void *)&skb_network_header(skb)[offset];
			if (tel->encap_limit == 0) {
				icmpv6_send(skb, ICMPV6_PARAMPROB,
					    ICMPV6_HDR_FIELD, offset + 2);
				return -1;
			}
			encap_limit = tel->encap_limit - 1;
		} else if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT)) {
			encap_limit = t->parms.encap_limit;
		}

	memcpy(&fl, &t->fl, sizeof (fl));
	fl.proto = IPPROTO_IPV6;

	dsfield = ipv6_get_dsfield(ipv6h);
	if ((t->parms.flags & IP6_TNL_F_USE_ORIG_TCLASS))
		fl.fl6_flowlabel |= (*(__be32 *) ipv6h & IPV6_TCLASS_MASK);
	if ((t->parms.flags & IP6_TNL_F_USE_ORIG_FLOWLABEL))
		fl.fl6_flowlabel |= (*(__be32 *) ipv6h & IPV6_FLOWLABEL_MASK);

	err = ip6_tnl_xmit2(skb, dev, dsfield, &fl, encap_limit, &mtu);
	if (err != 0) {
		if (err == -EMSGSIZE)
			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, dev);
	memcpy(&fl6, &t->fl.u.ip6, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_IPV6;
		memcpy(&fl6, &t->fl.u.ip6, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_IPV6;

		if (t->parms.flags & IP6_TNL_F_USE_ORIG_TCLASS)
			dsfield = ipv6_get_dsfield(ipv6h);
		else
			dsfield = ip6_tclass(t->parms.flowinfo);
		if (t->parms.flags & IP6_TNL_F_USE_ORIG_FLOWLABEL)
			fl6.flowlabel |= ip6_flowlabel(ipv6h);
		if (t->parms.flags & IP6_TNL_F_USE_ORIG_FWMARK)
			fl6.flowi6_mark = skb->mark;
		else
			fl6.flowi6_mark = t->parms.fwmark;
	}

	fl6.flowi6_uid = sock_net_uid(dev_net(dev), NULL);

	if (iptunnel_handle_offloads(skb, SKB_GSO_IPXIP6))
		return -1;

	dsfield = INET_ECN_encapsulate(dsfield, ipv6_get_dsfield(ipv6h));

	skb_set_inner_ipproto(skb, IPPROTO_IPV6);

	err = ip6_tnl_xmit(skb, dev, dsfield, &fl6, encap_limit, &mtu,
			   IPPROTO_IPV6);
	if (err != 0) {
		if (err == -EMSGSIZE)
			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
		return -1;
	}

	return 0;
}

static int
static netdev_tx_t
ip6_tnl_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	int ret;

	if (t->recursion++) {
		stats->collisions++;
		goto tx_err;
	}

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		ret = ip4ip6_tnl_xmit(skb, dev);
		break;
	case __constant_htons(ETH_P_IPV6):
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ret = ip4ip6_tnl_xmit(skb, dev);
		break;
	case htons(ETH_P_IPV6):
		ret = ip6ip6_tnl_xmit(skb, dev);
		break;
	default:
		goto tx_err;
	}

	if (ret < 0)
		goto tx_err;

	t->recursion--;
	return 0;
	return NETDEV_TX_OK;

tx_err:
	stats->tx_errors++;
	stats->tx_dropped++;
	kfree_skb(skb);
	t->recursion--;
	return 0;
}

static void ip6_tnl_set_cap(struct ip6_tnl *t)
{
	struct ip6_tnl_parm *p = &t->parms;
	int ltype = ipv6_addr_type(&p->laddr);
	int rtype = ipv6_addr_type(&p->raddr);

	p->flags &= ~(IP6_TNL_F_CAP_XMIT|IP6_TNL_F_CAP_RCV);

	if (ltype & (IPV6_ADDR_UNICAST|IPV6_ADDR_MULTICAST) &&
	    rtype & (IPV6_ADDR_UNICAST|IPV6_ADDR_MULTICAST) &&
	    !((ltype|rtype) & IPV6_ADDR_LOOPBACK) &&
	    (!((ltype|rtype) & IPV6_ADDR_LINKLOCAL) || p->link)) {
		if (ltype&IPV6_ADDR_UNICAST)
			p->flags |= IP6_TNL_F_CAP_XMIT;
		if (rtype&IPV6_ADDR_UNICAST)
			p->flags |= IP6_TNL_F_CAP_RCV;
	}
	return NETDEV_TX_OK;
}

static void ip6_tnl_link_config(struct ip6_tnl *t)
{
	struct net_device *dev = t->dev;
	struct ip6_tnl_parm *p = &t->parms;
	struct flowi *fl = &t->fl;

	memcpy(&dev->dev_addr, &p->laddr, sizeof(struct in6_addr));
	memcpy(&dev->broadcast, &p->raddr, sizeof(struct in6_addr));

	/* Set up flowi template */
	ipv6_addr_copy(&fl->fl6_src, &p->laddr);
	ipv6_addr_copy(&fl->fl6_dst, &p->raddr);
	fl->oif = p->link;
	fl->fl6_flowlabel = 0;

	if (!(p->flags&IP6_TNL_F_USE_ORIG_TCLASS))
		fl->fl6_flowlabel |= IPV6_TCLASS_MASK & p->flowinfo;
	if (!(p->flags&IP6_TNL_F_USE_ORIG_FLOWLABEL))
		fl->fl6_flowlabel |= IPV6_FLOWLABEL_MASK & p->flowinfo;

	ip6_tnl_set_cap(t);
	struct __ip6_tnl_parm *p = &t->parms;
	struct flowi6 *fl6 = &t->fl.u.ip6;
	int t_hlen;

	memcpy(dev->dev_addr, &p->laddr, sizeof(struct in6_addr));
	memcpy(dev->broadcast, &p->raddr, sizeof(struct in6_addr));

	/* Set up flowi template */
	fl6->saddr = p->laddr;
	fl6->daddr = p->raddr;
	fl6->flowi6_oif = p->link;
	fl6->flowlabel = 0;

	if (!(p->flags&IP6_TNL_F_USE_ORIG_TCLASS))
		fl6->flowlabel |= IPV6_TCLASS_MASK & p->flowinfo;
	if (!(p->flags&IP6_TNL_F_USE_ORIG_FLOWLABEL))
		fl6->flowlabel |= IPV6_FLOWLABEL_MASK & p->flowinfo;

	p->flags &= ~(IP6_TNL_F_CAP_XMIT|IP6_TNL_F_CAP_RCV|IP6_TNL_F_CAP_PER_PACKET);
	p->flags |= ip6_tnl_get_cap(t, &p->laddr, &p->raddr);

	if (p->flags&IP6_TNL_F_CAP_XMIT && p->flags&IP6_TNL_F_CAP_RCV)
		dev->flags |= IFF_POINTOPOINT;
	else
		dev->flags &= ~IFF_POINTOPOINT;

	dev->iflink = p->link;
	t->tun_hlen = 0;
	t->hlen = t->encap_hlen + t->tun_hlen;
	t_hlen = t->hlen + sizeof(struct ipv6hdr);

	if (p->flags & IP6_TNL_F_CAP_XMIT) {
		int strict = (ipv6_addr_type(&p->raddr) &
			      (IPV6_ADDR_MULTICAST|IPV6_ADDR_LINKLOCAL));

		struct rt6_info *rt = rt6_lookup(dev_net(dev),
						 &p->raddr, &p->laddr,
						 p->link, strict);

		if (rt == NULL)
			return;

		if (rt->rt6i_dev) {
			dev->hard_header_len = rt->rt6i_dev->hard_header_len +
				sizeof (struct ipv6hdr);

			dev->mtu = rt->rt6i_dev->mtu - sizeof (struct ipv6hdr);
		struct rt6_info *rt = rt6_lookup(t->net,
						 &p->raddr, &p->laddr,
						 p->link, strict);

		if (!rt)
			return;

		if (rt->dst.dev) {
			dev->hard_header_len = rt->dst.dev->hard_header_len +
				t_hlen;

			dev->mtu = rt->dst.dev->mtu - t_hlen;
			if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
				dev->mtu -= 8;

			if (dev->mtu < IPV6_MIN_MTU)
				dev->mtu = IPV6_MIN_MTU;
		}
		dst_release(&rt->u.dst);
		ip6_rt_put(rt);
	}
}

/**
 * ip6_tnl_change - update the tunnel parameters
 *   @t: tunnel to be changed
 *   @p: tunnel configuration parameters
 *   @active: != 0 if tunnel is ready for use
 *
 * Description:
 *   ip6_tnl_change() updates the tunnel parameters
 **/

static int
ip6_tnl_change(struct ip6_tnl *t, struct ip6_tnl_parm *p)
{
	ipv6_addr_copy(&t->parms.laddr, &p->laddr);
	ipv6_addr_copy(&t->parms.raddr, &p->raddr);
ip6_tnl_change(struct ip6_tnl *t, const struct __ip6_tnl_parm *p)
{
	t->parms.laddr = p->laddr;
	t->parms.raddr = p->raddr;
	t->parms.flags = p->flags;
	t->parms.hop_limit = p->hop_limit;
	t->parms.encap_limit = p->encap_limit;
	t->parms.flowinfo = p->flowinfo;
	t->parms.link = p->link;
	t->parms.proto = p->proto;
	t->parms.fwmark = p->fwmark;
	dst_cache_reset(&t->dst_cache);
	ip6_tnl_link_config(t);
	return 0;
}

static int ip6_tnl_update(struct ip6_tnl *t, struct __ip6_tnl_parm *p)
{
	struct net *net = t->net;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	int err;

	ip6_tnl_unlink(ip6n, t);
	synchronize_net();
	err = ip6_tnl_change(t, p);
	ip6_tnl_link(ip6n, t);
	netdev_state_change(t->dev);
	return err;
}

static int ip6_tnl0_update(struct ip6_tnl *t, struct __ip6_tnl_parm *p)
{
	/* for default tnl0 device allow to change only the proto */
	t->parms.proto = p->proto;
	netdev_state_change(t->dev);
	return 0;
}

static void
ip6_tnl_parm_from_user(struct __ip6_tnl_parm *p, const struct ip6_tnl_parm *u)
{
	p->laddr = u->laddr;
	p->raddr = u->raddr;
	p->flags = u->flags;
	p->hop_limit = u->hop_limit;
	p->encap_limit = u->encap_limit;
	p->flowinfo = u->flowinfo;
	p->link = u->link;
	p->proto = u->proto;
	memcpy(p->name, u->name, sizeof(u->name));
}

static void
ip6_tnl_parm_to_user(struct ip6_tnl_parm *u, const struct __ip6_tnl_parm *p)
{
	u->laddr = p->laddr;
	u->raddr = p->raddr;
	u->flags = p->flags;
	u->hop_limit = p->hop_limit;
	u->encap_limit = p->encap_limit;
	u->flowinfo = p->flowinfo;
	u->link = p->link;
	u->proto = p->proto;
	memcpy(u->name, p->name, sizeof(u->name));
}

/**
 * ip6_tnl_ioctl - configure ipv6 tunnels from userspace
 *   @dev: virtual device associated with tunnel
 *   @ifr: parameters passed from userspace
 *   @cmd: command to be performed
 *
 * Description:
 *   ip6_tnl_ioctl() is used for managing IPv6 tunnels
 *   from userspace.
 *
 *   The possible commands are the following:
 *     %SIOCGETTUNNEL: get tunnel parameters for device
 *     %SIOCADDTUNNEL: add tunnel matching given tunnel parameters
 *     %SIOCCHGTUNNEL: change tunnel parameters to those given
 *     %SIOCDELTUNNEL: delete tunnel
 *
 *   The fallback device "ip6tnl0", created during module
 *   initialization, can be used for creating other tunnel devices.
 *
 * Return:
 *   0 on success,
 *   %-EFAULT if unable to copy data to or from userspace,
 *   %-EPERM if current process hasn't %CAP_NET_ADMIN set
 *   %-EINVAL if passed tunnel parameters are invalid,
 *   %-EEXIST if changing a tunnel's parameters would cause a conflict
 *   %-ENODEV if attempting to change or delete a nonexisting device
 **/

static int
ip6_tnl_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int err = 0;
	struct ip6_tnl_parm p;
	struct ip6_tnl *t = NULL;
	struct net *net = dev_net(dev);
	struct __ip6_tnl_parm p1;
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = t->net;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	memset(&p1, 0, sizeof(p1));

	switch (cmd) {
	case SIOCGETTUNNEL:
		if (dev == ip6n->fb_tnl_dev) {
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p))) {
				err = -EFAULT;
				break;
			}
			t = ip6_tnl_locate(net, &p, 0);
		}
		if (t == NULL)
			t = netdev_priv(dev);
		memcpy(&p, &t->parms, sizeof (p));
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof (p))) {
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p))) {
				err = -EFAULT;
				break;
			}
			ip6_tnl_parm_from_user(&p1, &p);
			t = ip6_tnl_locate(net, &p1, 0);
			if (IS_ERR(t))
				t = netdev_priv(dev);
		} else {
			memset(&p, 0, sizeof(p));
		}
		ip6_tnl_parm_to_user(&p, &t->parms);
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p))) {
			err = -EFAULT;
		}
		break;
	case SIOCADDTUNNEL:
	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;
		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p)))
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			break;
		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
			break;
		err = -EINVAL;
		if (p.proto != IPPROTO_IPV6 && p.proto != IPPROTO_IPIP &&
		    p.proto != 0)
			break;
		t = ip6_tnl_locate(net, &p, cmd == SIOCADDTUNNEL);
		if (dev != ip6n->fb_tnl_dev && cmd == SIOCCHGTUNNEL) {
			if (t != NULL) {
		ip6_tnl_parm_from_user(&p1, &p);
		t = ip6_tnl_locate(net, &p1, cmd == SIOCADDTUNNEL);
		if (cmd == SIOCCHGTUNNEL) {
			if (!IS_ERR(t)) {
				if (t->dev != dev) {
					err = -EEXIST;
					break;
				}
			} else
				t = netdev_priv(dev);

			ip6_tnl_unlink(ip6n, t);
			err = ip6_tnl_change(t, &p);
			ip6_tnl_link(ip6n, t);
			netdev_state_change(dev);
		}
		if (t) {
			err = 0;
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &t->parms, sizeof (p)))
				err = -EFAULT;

		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);
		break;
	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			if (dev == ip6n->fb_tnl_dev)
				err = ip6_tnl0_update(t, &p1);
			else
				err = ip6_tnl_update(t, &p1);
		}
		if (!IS_ERR(t)) {
			err = 0;
			ip6_tnl_parm_to_user(&p, &t->parms);
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p)))
				err = -EFAULT;

		} else {
			err = PTR_ERR(t);
		}
		break;
	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			break;

		if (dev == ip6n->fb_tnl_dev) {
			err = -EFAULT;
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p)))
				break;
			err = -ENOENT;
			if ((t = ip6_tnl_locate(net, &p, 0)) == NULL)
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
				break;
			err = -ENOENT;
			ip6_tnl_parm_from_user(&p1, &p);
			t = ip6_tnl_locate(net, &p1, 0);
			if (IS_ERR(t))
				break;
			err = -EPERM;
			if (t->dev == ip6n->fb_tnl_dev)
				break;
			dev = t->dev;
		}
		err = 0;
		unregister_netdevice(dev);
		break;
	default:
		err = -EINVAL;
	}
	return err;
}

/**
 * ip6_tnl_change_mtu - change mtu manually for tunnel device
 *   @dev: virtual device associated with tunnel
 *   @new_mtu: the new mtu
 *
 * Return:
 *   0 on success,
 *   %-EINVAL if mtu too small
 **/

int ip6_tnl_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < IPV6_MIN_MTU) {
		return -EINVAL;
	}
	struct ip6_tnl *tnl = netdev_priv(dev);

	if (tnl->parms.proto == IPPROTO_IPV6) {
		if (new_mtu < IPV6_MIN_MTU)
			return -EINVAL;
	} else {
		if (new_mtu < ETH_MIN_MTU)
			return -EINVAL;
	}
	if (tnl->parms.proto == IPPROTO_IPV6 || tnl->parms.proto == 0) {
		if (new_mtu > IP6_MAX_MTU - dev->hard_header_len)
			return -EINVAL;
	} else {
		if (new_mtu > IP_MAX_MTU - dev->hard_header_len)
			return -EINVAL;
	}
	dev->mtu = new_mtu;
	return 0;
}
EXPORT_SYMBOL(ip6_tnl_change_mtu);

int ip6_tnl_get_iflink(const struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);

	return t->parms.link;
}
EXPORT_SYMBOL(ip6_tnl_get_iflink);

int ip6_tnl_encap_add_ops(const struct ip6_tnl_encap_ops *ops,
			  unsigned int num)
{
	if (num >= MAX_IPTUN_ENCAP_OPS)
		return -ERANGE;

	return !cmpxchg((const struct ip6_tnl_encap_ops **)
			&ip6tun_encaps[num],
			NULL, ops) ? 0 : -1;
}
EXPORT_SYMBOL(ip6_tnl_encap_add_ops);

int ip6_tnl_encap_del_ops(const struct ip6_tnl_encap_ops *ops,
			  unsigned int num)
{
	int ret;

	if (num >= MAX_IPTUN_ENCAP_OPS)
		return -ERANGE;

	ret = (cmpxchg((const struct ip6_tnl_encap_ops **)
		       &ip6tun_encaps[num],
		       ops, NULL) == ops) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(ip6_tnl_encap_del_ops);

int ip6_tnl_encap_setup(struct ip6_tnl *t,
			struct ip_tunnel_encap *ipencap)
{
	int hlen;

	memset(&t->encap, 0, sizeof(t->encap));

	hlen = ip6_encap_hlen(ipencap);
	if (hlen < 0)
		return hlen;

	t->encap.type = ipencap->type;
	t->encap.sport = ipencap->sport;
	t->encap.dport = ipencap->dport;
	t->encap.flags = ipencap->flags;

	t->encap_hlen = hlen;
	t->hlen = t->encap_hlen + t->tun_hlen;

	return 0;
}
EXPORT_SYMBOL_GPL(ip6_tnl_encap_setup);

static const struct net_device_ops ip6_tnl_netdev_ops = {
	.ndo_init	= ip6_tnl_dev_init,
	.ndo_uninit	= ip6_tnl_dev_uninit,
	.ndo_start_xmit = ip6_tnl_start_xmit,
	.ndo_do_ioctl	= ip6_tnl_ioctl,
	.ndo_change_mtu = ip6_tnl_change_mtu,
	.ndo_get_stats	= ip6_get_stats,
	.ndo_get_iflink = ip6_tnl_get_iflink,
};

#define IPXIPX_FEATURES (NETIF_F_SG |		\
			 NETIF_F_FRAGLIST |	\
			 NETIF_F_HIGHDMA |	\
			 NETIF_F_GSO_SOFTWARE |	\
			 NETIF_F_HW_CSUM)

/**
 * ip6_tnl_dev_setup - setup virtual tunnel device
 *   @dev: virtual device associated with tunnel
 *
 * Description:
 *   Initialize function pointers and device parameters
 **/

static void ip6_tnl_dev_setup(struct net_device *dev)
{
	dev->uninit = ip6_tnl_dev_uninit;
	dev->destructor = free_netdev;
	dev->hard_start_xmit = ip6_tnl_xmit;
	dev->do_ioctl = ip6_tnl_ioctl;
	dev->change_mtu = ip6_tnl_change_mtu;

	dev->type = ARPHRD_TUNNEL6;
	dev->hard_header_len = LL_MAX_HEADER + sizeof (struct ipv6hdr);
	dev->mtu = ETH_DATA_LEN - sizeof (struct ipv6hdr);
	dev->flags |= IFF_NOARP;
	dev->addr_len = sizeof(struct in6_addr);
	dev->features |= NETIF_F_NETNS_LOCAL;
	struct ip6_tnl *t;

	dev->netdev_ops = &ip6_tnl_netdev_ops;
	dev->needs_free_netdev = true;
	dev->priv_destructor = ip6_dev_free;

	dev->type = ARPHRD_TUNNEL6;
	dev->flags |= IFF_NOARP;
	dev->addr_len = sizeof(struct in6_addr);
	dev->features |= NETIF_F_LLTX;
	netif_keep_dst(dev);

	dev->features		|= IPXIPX_FEATURES;
	dev->hw_features	|= IPXIPX_FEATURES;

	/* This perm addr will be used as interface identifier by IPv6 */
	dev->addr_assign_type = NET_ADDR_RANDOM;
	eth_random_addr(dev->perm_addr);
}


/**
 * ip6_tnl_dev_init_gen - general initializer for all tunnel devices
 *   @dev: virtual device associated with tunnel
 **/

static inline void
ip6_tnl_dev_init_gen(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	t->dev = dev;
	strcpy(t->parms.name, dev->name);
static inline int
ip6_tnl_dev_init_gen(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	int ret;
	int t_hlen;

	t->dev = dev;
	t->net = dev_net(dev);
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	ret = dst_cache_init(&t->dst_cache, GFP_KERNEL);
	if (ret)
		goto free_stats;

	ret = gro_cells_init(&t->gro_cells, dev);
	if (ret)
		goto destroy_dst;

	t->tun_hlen = 0;
	t->hlen = t->encap_hlen + t->tun_hlen;
	t_hlen = t->hlen + sizeof(struct ipv6hdr);

	dev->type = ARPHRD_TUNNEL6;
	dev->hard_header_len = LL_MAX_HEADER + t_hlen;
	dev->mtu = ETH_DATA_LEN - t_hlen;
	if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
		dev->mtu -= 8;
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = IP6_MAX_MTU - dev->hard_header_len;

	return 0;

destroy_dst:
	dst_cache_destroy(&t->dst_cache);
free_stats:
	free_percpu(dev->tstats);
	dev->tstats = NULL;

	return ret;
}

/**
 * ip6_tnl_dev_init - initializer for all non fallback tunnel devices
 *   @dev: virtual device associated with tunnel
 **/

static int
ip6_tnl_dev_init(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	ip6_tnl_dev_init_gen(dev);
static int ip6_tnl_dev_init(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	int err = ip6_tnl_dev_init_gen(dev);

	if (err)
		return err;
	ip6_tnl_link_config(t);
	if (t->parms.collect_md) {
		dev->features |= NETIF_F_NETNS_LOCAL;
		netif_keep_dst(dev);
	}
	return 0;
}

/**
 * ip6_fb_tnl_dev_init - initializer for fallback tunnel device
 *   @dev: fallback device
 *
 * Return: 0
 **/

static int
ip6_fb_tnl_dev_init(struct net_device *dev)
static int __net_init ip6_fb_tnl_dev_init(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	ip6_tnl_dev_init_gen(dev);
	t->parms.proto = IPPROTO_IPV6;
	dev_hold(dev);
	ip6n->tnls_wc[0] = t;
	return 0;
}

static struct xfrm6_tunnel ip4ip6_handler = {
	t->parms.proto = IPPROTO_IPV6;
	dev_hold(dev);

	rcu_assign_pointer(ip6n->tnls_wc[0], t);
	return 0;
}

static int ip6_tnl_validate(struct nlattr *tb[], struct nlattr *data[],
			    struct netlink_ext_ack *extack)
{
	u8 proto;

	if (!data || !data[IFLA_IPTUN_PROTO])
		return 0;

	proto = nla_get_u8(data[IFLA_IPTUN_PROTO]);
	if (proto != IPPROTO_IPV6 &&
	    proto != IPPROTO_IPIP &&
	    proto != 0)
		return -EINVAL;

	return 0;
}

static void ip6_tnl_netlink_parms(struct nlattr *data[],
				  struct __ip6_tnl_parm *parms)
{
	memset(parms, 0, sizeof(*parms));

	if (!data)
		return;

	if (data[IFLA_IPTUN_LINK])
		parms->link = nla_get_u32(data[IFLA_IPTUN_LINK]);

	if (data[IFLA_IPTUN_LOCAL])
		parms->laddr = nla_get_in6_addr(data[IFLA_IPTUN_LOCAL]);

	if (data[IFLA_IPTUN_REMOTE])
		parms->raddr = nla_get_in6_addr(data[IFLA_IPTUN_REMOTE]);

	if (data[IFLA_IPTUN_TTL])
		parms->hop_limit = nla_get_u8(data[IFLA_IPTUN_TTL]);

	if (data[IFLA_IPTUN_ENCAP_LIMIT])
		parms->encap_limit = nla_get_u8(data[IFLA_IPTUN_ENCAP_LIMIT]);

	if (data[IFLA_IPTUN_FLOWINFO])
		parms->flowinfo = nla_get_be32(data[IFLA_IPTUN_FLOWINFO]);

	if (data[IFLA_IPTUN_FLAGS])
		parms->flags = nla_get_u32(data[IFLA_IPTUN_FLAGS]);

	if (data[IFLA_IPTUN_PROTO])
		parms->proto = nla_get_u8(data[IFLA_IPTUN_PROTO]);

	if (data[IFLA_IPTUN_COLLECT_METADATA])
		parms->collect_md = true;

	if (data[IFLA_IPTUN_FWMARK])
		parms->fwmark = nla_get_u32(data[IFLA_IPTUN_FWMARK]);
}

static bool ip6_tnl_netlink_encap_parms(struct nlattr *data[],
					struct ip_tunnel_encap *ipencap)
{
	bool ret = false;

	memset(ipencap, 0, sizeof(*ipencap));

	if (!data)
		return ret;

	if (data[IFLA_IPTUN_ENCAP_TYPE]) {
		ret = true;
		ipencap->type = nla_get_u16(data[IFLA_IPTUN_ENCAP_TYPE]);
	}

	if (data[IFLA_IPTUN_ENCAP_FLAGS]) {
		ret = true;
		ipencap->flags = nla_get_u16(data[IFLA_IPTUN_ENCAP_FLAGS]);
	}

	if (data[IFLA_IPTUN_ENCAP_SPORT]) {
		ret = true;
		ipencap->sport = nla_get_be16(data[IFLA_IPTUN_ENCAP_SPORT]);
	}

	if (data[IFLA_IPTUN_ENCAP_DPORT]) {
		ret = true;
		ipencap->dport = nla_get_be16(data[IFLA_IPTUN_ENCAP_DPORT]);
	}

	return ret;
}

static int ip6_tnl_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[],
			   struct netlink_ext_ack *extack)
{
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	struct ip_tunnel_encap ipencap;
	struct ip6_tnl *nt, *t;
	int err;

	nt = netdev_priv(dev);

	if (ip6_tnl_netlink_encap_parms(data, &ipencap)) {
		err = ip6_tnl_encap_setup(nt, &ipencap);
		if (err < 0)
			return err;
	}

	ip6_tnl_netlink_parms(data, &nt->parms);

	if (nt->parms.collect_md) {
		if (rtnl_dereference(ip6n->collect_md_tun))
			return -EEXIST;
	} else {
		t = ip6_tnl_locate(net, &nt->parms, 0);
		if (!IS_ERR(t))
			return -EEXIST;
	}

	err = ip6_tnl_create2(dev);
	if (!err && tb[IFLA_MTU])
		ip6_tnl_change_mtu(dev, nla_get_u32(tb[IFLA_MTU]));

	return err;
}

static int ip6_tnl_changelink(struct net_device *dev, struct nlattr *tb[],
			      struct nlattr *data[],
			      struct netlink_ext_ack *extack)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct __ip6_tnl_parm p;
	struct net *net = t->net;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	struct ip_tunnel_encap ipencap;

	if (dev == ip6n->fb_tnl_dev)
		return -EINVAL;

	if (ip6_tnl_netlink_encap_parms(data, &ipencap)) {
		int err = ip6_tnl_encap_setup(t, &ipencap);

		if (err < 0)
			return err;
	}
	ip6_tnl_netlink_parms(data, &p);
	if (p.collect_md)
		return -EINVAL;

	t = ip6_tnl_locate(net, &p, 0);
	if (!IS_ERR(t)) {
		if (t->dev != dev)
			return -EEXIST;
	} else
		t = netdev_priv(dev);

	return ip6_tnl_update(t, &p);
}

static void ip6_tnl_dellink(struct net_device *dev, struct list_head *head)
{
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	if (dev != ip6n->fb_tnl_dev)
		unregister_netdevice_queue(dev, head);
}

static size_t ip6_tnl_get_size(const struct net_device *dev)
{
	return
		/* IFLA_IPTUN_LINK */
		nla_total_size(4) +
		/* IFLA_IPTUN_LOCAL */
		nla_total_size(sizeof(struct in6_addr)) +
		/* IFLA_IPTUN_REMOTE */
		nla_total_size(sizeof(struct in6_addr)) +
		/* IFLA_IPTUN_TTL */
		nla_total_size(1) +
		/* IFLA_IPTUN_ENCAP_LIMIT */
		nla_total_size(1) +
		/* IFLA_IPTUN_FLOWINFO */
		nla_total_size(4) +
		/* IFLA_IPTUN_FLAGS */
		nla_total_size(4) +
		/* IFLA_IPTUN_PROTO */
		nla_total_size(1) +
		/* IFLA_IPTUN_ENCAP_TYPE */
		nla_total_size(2) +
		/* IFLA_IPTUN_ENCAP_FLAGS */
		nla_total_size(2) +
		/* IFLA_IPTUN_ENCAP_SPORT */
		nla_total_size(2) +
		/* IFLA_IPTUN_ENCAP_DPORT */
		nla_total_size(2) +
		/* IFLA_IPTUN_COLLECT_METADATA */
		nla_total_size(0) +
		/* IFLA_IPTUN_FWMARK */
		nla_total_size(4) +
		0;
}

static int ip6_tnl_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct ip6_tnl *tunnel = netdev_priv(dev);
	struct __ip6_tnl_parm *parm = &tunnel->parms;

	if (nla_put_u32(skb, IFLA_IPTUN_LINK, parm->link) ||
	    nla_put_in6_addr(skb, IFLA_IPTUN_LOCAL, &parm->laddr) ||
	    nla_put_in6_addr(skb, IFLA_IPTUN_REMOTE, &parm->raddr) ||
	    nla_put_u8(skb, IFLA_IPTUN_TTL, parm->hop_limit) ||
	    nla_put_u8(skb, IFLA_IPTUN_ENCAP_LIMIT, parm->encap_limit) ||
	    nla_put_be32(skb, IFLA_IPTUN_FLOWINFO, parm->flowinfo) ||
	    nla_put_u32(skb, IFLA_IPTUN_FLAGS, parm->flags) ||
	    nla_put_u8(skb, IFLA_IPTUN_PROTO, parm->proto) ||
	    nla_put_u32(skb, IFLA_IPTUN_FWMARK, parm->fwmark))
		goto nla_put_failure;

	if (nla_put_u16(skb, IFLA_IPTUN_ENCAP_TYPE, tunnel->encap.type) ||
	    nla_put_be16(skb, IFLA_IPTUN_ENCAP_SPORT, tunnel->encap.sport) ||
	    nla_put_be16(skb, IFLA_IPTUN_ENCAP_DPORT, tunnel->encap.dport) ||
	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_FLAGS, tunnel->encap.flags))
		goto nla_put_failure;

	if (parm->collect_md)
		if (nla_put_flag(skb, IFLA_IPTUN_COLLECT_METADATA))
			goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

struct net *ip6_tnl_get_link_net(const struct net_device *dev)
{
	struct ip6_tnl *tunnel = netdev_priv(dev);

	return tunnel->net;
}
EXPORT_SYMBOL(ip6_tnl_get_link_net);

static const struct nla_policy ip6_tnl_policy[IFLA_IPTUN_MAX + 1] = {
	[IFLA_IPTUN_LINK]		= { .type = NLA_U32 },
	[IFLA_IPTUN_LOCAL]		= { .len = sizeof(struct in6_addr) },
	[IFLA_IPTUN_REMOTE]		= { .len = sizeof(struct in6_addr) },
	[IFLA_IPTUN_TTL]		= { .type = NLA_U8 },
	[IFLA_IPTUN_ENCAP_LIMIT]	= { .type = NLA_U8 },
	[IFLA_IPTUN_FLOWINFO]		= { .type = NLA_U32 },
	[IFLA_IPTUN_FLAGS]		= { .type = NLA_U32 },
	[IFLA_IPTUN_PROTO]		= { .type = NLA_U8 },
	[IFLA_IPTUN_ENCAP_TYPE]		= { .type = NLA_U16 },
	[IFLA_IPTUN_ENCAP_FLAGS]	= { .type = NLA_U16 },
	[IFLA_IPTUN_ENCAP_SPORT]	= { .type = NLA_U16 },
	[IFLA_IPTUN_ENCAP_DPORT]	= { .type = NLA_U16 },
	[IFLA_IPTUN_COLLECT_METADATA]	= { .type = NLA_FLAG },
	[IFLA_IPTUN_FWMARK]		= { .type = NLA_U32 },
};

static struct rtnl_link_ops ip6_link_ops __read_mostly = {
	.kind		= "ip6tnl",
	.maxtype	= IFLA_IPTUN_MAX,
	.policy		= ip6_tnl_policy,
	.priv_size	= sizeof(struct ip6_tnl),
	.setup		= ip6_tnl_dev_setup,
	.validate	= ip6_tnl_validate,
	.newlink	= ip6_tnl_newlink,
	.changelink	= ip6_tnl_changelink,
	.dellink	= ip6_tnl_dellink,
	.get_size	= ip6_tnl_get_size,
	.fill_info	= ip6_tnl_fill_info,
	.get_link_net	= ip6_tnl_get_link_net,
};

static struct xfrm6_tunnel ip4ip6_handler __read_mostly = {
	.handler	= ip4ip6_rcv,
	.err_handler	= ip4ip6_err,
	.priority	=	1,
};

static struct xfrm6_tunnel ip6ip6_handler = {
static struct xfrm6_tunnel ip6ip6_handler __read_mostly = {
	.handler	= ip6ip6_rcv,
	.err_handler	= ip6ip6_err,
	.priority	=	1,
};

static void ip6_tnl_destroy_tunnels(struct ip6_tnl_net *ip6n)
{
	int h;
	struct ip6_tnl *t;

	for (h = 0; h < HASH_SIZE; h++) {
		while ((t = ip6n->tnls_r_l[h]) != NULL)
			unregister_netdevice(t->dev);
	}

	t = ip6n->tnls_wc[0];
	unregister_netdevice(t->dev);
}

static int ip6_tnl_init_net(struct net *net)
{
	int err;
	struct ip6_tnl_net *ip6n;

	err = -ENOMEM;
	ip6n = kzalloc(sizeof(struct ip6_tnl_net), GFP_KERNEL);
	if (ip6n == NULL)
		goto err_alloc;

	err = net_assign_generic(net, ip6_tnl_net_id, ip6n);
	if (err < 0)
		goto err_assign;
static void __net_exit ip6_tnl_destroy_tunnels(struct net *net)
{
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	struct net_device *dev, *aux;
	int h;
	struct ip6_tnl *t;
	LIST_HEAD(list);

	for_each_netdev_safe(net, dev, aux)
		if (dev->rtnl_link_ops == &ip6_link_ops)
			unregister_netdevice_queue(dev, &list);

	for (h = 0; h < IP6_TUNNEL_HASH_SIZE; h++) {
		t = rtnl_dereference(ip6n->tnls_r_l[h]);
		while (t) {
			/* If dev is in the same netns, it has already
			 * been added to the list by the previous loop.
			 */
			if (!net_eq(dev_net(t->dev), net))
				unregister_netdevice_queue(t->dev, &list);
			t = rtnl_dereference(t->next);
		}
	}

	unregister_netdevice_many(&list);
}

static int __net_init ip6_tnl_init_net(struct net *net)
{
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	struct ip6_tnl *t = NULL;
	int err;

	ip6n->tnls[0] = ip6n->tnls_wc;
	ip6n->tnls[1] = ip6n->tnls_r_l;

	err = -ENOMEM;
	ip6n->fb_tnl_dev = alloc_netdev(sizeof(struct ip6_tnl), "ip6tnl0",
				      ip6_tnl_dev_setup);

	if (!ip6n->fb_tnl_dev)
		goto err_alloc_dev;

	ip6n->fb_tnl_dev->init = ip6_fb_tnl_dev_init;
	dev_net_set(ip6n->fb_tnl_dev, net);
					NET_NAME_UNKNOWN, ip6_tnl_dev_setup);

	if (!ip6n->fb_tnl_dev)
		goto err_alloc_dev;
	dev_net_set(ip6n->fb_tnl_dev, net);
	ip6n->fb_tnl_dev->rtnl_link_ops = &ip6_link_ops;
	/* FB netdevice is special: we have one, and only one per netns.
	 * Allowing to move it to another netns is clearly unsafe.
	 */
	ip6n->fb_tnl_dev->features |= NETIF_F_NETNS_LOCAL;

	err = ip6_fb_tnl_dev_init(ip6n->fb_tnl_dev);
	if (err < 0)
		goto err_register;

	err = register_netdev(ip6n->fb_tnl_dev);
	if (err < 0)
		goto err_register;
	return 0;

err_register:
	free_netdev(ip6n->fb_tnl_dev);
err_alloc_dev:
	/* nothing */
err_assign:
	kfree(ip6n);
err_alloc:
	return err;
}

static void ip6_tnl_exit_net(struct net *net)
{
	struct ip6_tnl_net *ip6n;

	ip6n = net_generic(net, ip6_tnl_net_id);
	rtnl_lock();
	ip6_tnl_destroy_tunnels(ip6n);
	rtnl_unlock();
	kfree(ip6n);

	t = netdev_priv(ip6n->fb_tnl_dev);

	strcpy(t->parms.name, ip6n->fb_tnl_dev->name);
	return 0;

err_register:
	free_netdev(ip6n->fb_tnl_dev);
err_alloc_dev:
	return err;
}

static void __net_exit ip6_tnl_exit_net(struct net *net)
{
	rtnl_lock();
	ip6_tnl_destroy_tunnels(net);
	rtnl_unlock();
}

static struct pernet_operations ip6_tnl_net_ops = {
	.init = ip6_tnl_init_net,
	.exit = ip6_tnl_exit_net,
	.id   = &ip6_tnl_net_id,
	.size = sizeof(struct ip6_tnl_net),
};

/**
 * ip6_tunnel_init - register protocol and reserve needed resources
 *
 * Return: 0 on success
 **/

static int __init ip6_tunnel_init(void)
{
	int  err;

	if (xfrm6_tunnel_register(&ip4ip6_handler, AF_INET)) {
		printk(KERN_ERR "ip6_tunnel init: can't register ip4ip6\n");
		err = -EAGAIN;
		goto out;
	}

	if (xfrm6_tunnel_register(&ip6ip6_handler, AF_INET6)) {
		printk(KERN_ERR "ip6_tunnel init: can't register ip6ip6\n");
		err = -EAGAIN;
		goto unreg_ip4ip6;
	}

	err = register_pernet_gen_device(&ip6_tnl_net_id, &ip6_tnl_net_ops);
	if (err < 0)
		goto err_pernet;
	return 0;
err_pernet:
	xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6);
unreg_ip4ip6:
	xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET);
out:
	if (!ipv6_mod_enabled())
		return -EOPNOTSUPP;

	err = register_pernet_device(&ip6_tnl_net_ops);
	if (err < 0)
		goto out_pernet;

	err = xfrm6_tunnel_register(&ip4ip6_handler, AF_INET);
	if (err < 0) {
		pr_err("%s: can't register ip4ip6\n", __func__);
		goto out_ip4ip6;
	}

	err = xfrm6_tunnel_register(&ip6ip6_handler, AF_INET6);
	if (err < 0) {
		pr_err("%s: can't register ip6ip6\n", __func__);
		goto out_ip6ip6;
	}
	err = rtnl_link_register(&ip6_link_ops);
	if (err < 0)
		goto rtnl_link_failed;

	return 0;

rtnl_link_failed:
	xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6);
out_ip6ip6:
	xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET);
out_ip4ip6:
	unregister_pernet_device(&ip6_tnl_net_ops);
out_pernet:
	return err;
}

/**
 * ip6_tunnel_cleanup - free resources and unregister protocol
 **/

static void __exit ip6_tunnel_cleanup(void)
{
	if (xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET))
		printk(KERN_INFO "ip6_tunnel close: can't deregister ip4ip6\n");

	if (xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6))
		printk(KERN_INFO "ip6_tunnel close: can't deregister ip6ip6\n");

	unregister_pernet_gen_device(ip6_tnl_net_id, &ip6_tnl_net_ops);
	rtnl_link_unregister(&ip6_link_ops);
	if (xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET))
		pr_info("%s: can't deregister ip4ip6\n", __func__);

	if (xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6))
		pr_info("%s: can't deregister ip6ip6\n", __func__);

	unregister_pernet_device(&ip6_tnl_net_ops);
}

module_init(ip6_tunnel_init);
module_exit(ip6_tunnel_cleanup);
