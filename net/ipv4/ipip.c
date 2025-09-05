/*
 *	Linux NET3:	IP/IP protocol decoder.
 *
 *	Authors:
 *		Sam Lantinga (slouken@cs.ucdavis.edu)  02/01/95
 *
 *	Fixes:
 *		Alan Cox	:	Merged and made usable non modular (its so tiny its silly as
 *					a module taking up 2 pages).
 *		Alan Cox	: 	Fixed bug with 1.3.18 and IPIP not working (now needs to set skb->h.iph)
 *					to keep ip_forward happy.
 *		Alan Cox	:	More fixes for 1.3.21, and firewall fix. Maybe this will work soon 8).
 *		Kai Schulte	:	Fixed #defines for IP_FIREWALL->FIREWALL
 *              David Woodhouse :       Perform some basic ICMP handling.
 *                                      IPIP Routing without decapsulation.
 *              Carlos Picoto   :       GRE over IP support
 *		Alexey Kuznetsov:	Reworked. Really, now it is truncated version of ipv4/ip_gre.c.
 *					I do not want to merge them together.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

/* tunnel.c: an IP tunnel driver

	The purpose of this driver is to provide an IP tunnel through
	which you can tunnel network traffic transparently across subnets.

	This was written by looking at Nick Holloway's dummy driver
	Thanks for the great code!

		-Sam Lantinga	(slouken@cs.ucdavis.edu)  02/01/95

	Minor tweaks:
		Cleaned up the code a little and added some pre-1.3.0 tweaks.
		dev->hard_header/hard_header_len changed to use no headers.
		Comments/bracketing tweaked.
		Made the tunnels use dev->name not tunnel: when error reporting.
		Added tx_dropped stat

		-Alan Cox	(Alan.Cox@linux.org) 21 March 95
		-Alan Cox	(alan@lxorguk.ukuu.org.uk) 21 March 95

	Reworked:
		Changed to tunnel to destination gateway in addition to the
			tunnel's pointopoint address
		Almost completely rewritten
		Note:  There is currently no firewall or ICMP handling done.

		-Sam Lantinga	(slouken@cs.ucdavis.edu) 02/13/96

*/

/* Things I wish I had known when writing the tunnel driver:

	When the tunnel_xmit() function is called, the skb contains the
	packet to be sent (plus a great deal of extra info), and dev
	contains the tunnel device that _we_ are.

	When we are passed a packet, we are expected to fill in the
	source address with our source IP address.

	What is the proper way to allocate, copy and free a buffer?
	After you allocate it, it is a "0 length" chunk of memory
	starting at zero.  If you want to add headers to the buffer
	later, you'll have to call "skb_reserve(skb, amount)" with
	the amount of memory you want reserved.  Then, you call
	"skb_put(skb, amount)" with the amount of space you want in
	the buffer.  skb_put() returns a pointer to the top (#0) of
	that buffer.  skb->len is set to the amount of space you have
	"allocated" with skb_put().  You can then write up to skb->len
	bytes to that buffer.  If you need more, you can call skb_put()
	again with the additional amount of space you need.  You can
	find out how much more space you can allocate by calling
	"skb_tailroom(skb)".
	Now, to add header space, call "skb_push(skb, header_len)".
	This creates space at the beginning of the buffer and returns
	a pointer to this new space.  If later you need to strip a
	header from a buffer, call "skb_pull(skb, header_len)".
	skb_headroom() will return how much space is left at the top
	of the buffer (before the main data).  Remember, this headroom
	space must be reserved before the skb_put() function is called.
	*/

/*
   This version of net/ipv4/ipip.c is cloned of net/ipv4/ip_gre.c

   For comments look at net/ipv4/ip_gre.c --ANK
 */


#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/ipip.h>
#include <net/ip_tunnels.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/dst_metadata.h>

#define HASH_SIZE  16
#define HASH(addr) (((__force u32)addr^((__force u32)addr>>4))&0xF)

static int ipip_net_id;
struct ipip_net {
	struct ip_tunnel *tunnels_r_l[HASH_SIZE];
	struct ip_tunnel *tunnels_r[HASH_SIZE];
	struct ip_tunnel *tunnels_l[HASH_SIZE];
	struct ip_tunnel *tunnels_wc[1];
	struct ip_tunnel **tunnels[4];

	struct net_device *fb_tunnel_dev;
};

static int ipip_fb_tunnel_init(struct net_device *dev);
static int ipip_tunnel_init(struct net_device *dev);
static void ipip_tunnel_setup(struct net_device *dev);

static DEFINE_RWLOCK(ipip_lock);

static struct ip_tunnel * ipip_tunnel_lookup(struct net *net,
		__be32 remote, __be32 local)
{
	unsigned h0 = HASH(remote);
	unsigned h1 = HASH(local);
	struct ip_tunnel *t;
	struct ipip_net *ipn = net_generic(net, ipip_net_id);

	for (t = ipn->tunnels_r_l[h0^h1]; t; t = t->next) {
		if (local == t->parms.iph.saddr &&
		    remote == t->parms.iph.daddr && (t->dev->flags&IFF_UP))
			return t;
	}
	for (t = ipn->tunnels_r[h0]; t; t = t->next) {
		if (remote == t->parms.iph.daddr && (t->dev->flags&IFF_UP))
			return t;
	}
	for (t = ipn->tunnels_l[h1]; t; t = t->next) {
		if (local == t->parms.iph.saddr && (t->dev->flags&IFF_UP))
			return t;
	}
	if ((t = ipn->tunnels_wc[0]) != NULL && (t->dev->flags&IFF_UP))
		return t;
	return NULL;
}

static struct ip_tunnel **__ipip_bucket(struct ipip_net *ipn,
		struct ip_tunnel_parm *parms)
{
	__be32 remote = parms->iph.daddr;
	__be32 local = parms->iph.saddr;
	unsigned h = 0;
	int prio = 0;

	if (remote) {
		prio |= 2;
		h ^= HASH(remote);
	}
	if (local) {
		prio |= 1;
		h ^= HASH(local);
	}
	return &ipn->tunnels[prio][h];
}

static inline struct ip_tunnel **ipip_bucket(struct ipip_net *ipn,
		struct ip_tunnel *t)
{
	return __ipip_bucket(ipn, &t->parms);
}

static void ipip_tunnel_unlink(struct ipip_net *ipn, struct ip_tunnel *t)
{
	struct ip_tunnel **tp;

	for (tp = ipip_bucket(ipn, t); *tp; tp = &(*tp)->next) {
		if (t == *tp) {
			write_lock_bh(&ipip_lock);
			*tp = t->next;
			write_unlock_bh(&ipip_lock);
			break;
		}
	}
}

static void ipip_tunnel_link(struct ipip_net *ipn, struct ip_tunnel *t)
{
	struct ip_tunnel **tp = ipip_bucket(ipn, t);

	t->next = *tp;
	write_lock_bh(&ipip_lock);
	*tp = t;
	write_unlock_bh(&ipip_lock);
}

static struct ip_tunnel * ipip_tunnel_locate(struct net *net,
		struct ip_tunnel_parm *parms, int create)
{
	__be32 remote = parms->iph.daddr;
	__be32 local = parms->iph.saddr;
	struct ip_tunnel *t, **tp, *nt;
	struct net_device *dev;
	char name[IFNAMSIZ];
	struct ipip_net *ipn = net_generic(net, ipip_net_id);

	for (tp = __ipip_bucket(ipn, parms); (t = *tp) != NULL; tp = &t->next) {
		if (local == t->parms.iph.saddr && remote == t->parms.iph.daddr)
			return t;
	}
	if (!create)
		return NULL;

	if (parms->name[0])
		strlcpy(name, parms->name, IFNAMSIZ);
	else
		sprintf(name, "tunl%%d");

	dev = alloc_netdev(sizeof(*t), name, ipip_tunnel_setup);
	if (dev == NULL)
		return NULL;

	dev_net_set(dev, net);

	if (strchr(name, '%')) {
		if (dev_alloc_name(dev, name) < 0)
			goto failed_free;
	}

	nt = netdev_priv(dev);
	dev->init = ipip_tunnel_init;
	nt->parms = *parms;

	if (register_netdevice(dev) < 0)
		goto failed_free;

	dev_hold(dev);
	ipip_tunnel_link(ipn, nt);
	return nt;

failed_free:
	free_netdev(dev);
	return NULL;
}

static void ipip_tunnel_uninit(struct net_device *dev)
{
	struct net *net = dev_net(dev);
	struct ipip_net *ipn = net_generic(net, ipip_net_id);

	if (dev == ipn->fb_tunnel_dev) {
		write_lock_bh(&ipip_lock);
		ipn->tunnels_wc[0] = NULL;
		write_unlock_bh(&ipip_lock);
	} else
		ipip_tunnel_unlink(ipn, netdev_priv(dev));
	dev_put(dev);
}
static bool log_ecn_error = true;
module_param(log_ecn_error, bool, 0644);
MODULE_PARM_DESC(log_ecn_error, "Log packets received with corrupted ECN");

static unsigned int ipip_net_id __read_mostly;

static int ipip_tunnel_init(struct net_device *dev);
static struct rtnl_link_ops ipip_link_ops __read_mostly;

static int ipip_err(struct sk_buff *skb, u32 info)
{

/* All the routers (except for Linux) return only
   8 bytes of packet payload. It means, that precise relaying of
   ICMP in the real Internet is absolutely infeasible.
 */
	struct iphdr *iph = (struct iphdr*)skb->data;
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	struct ip_tunnel *t;
	int err;

	switch (type) {
	default:
	case ICMP_PARAMETERPROB:
		return 0;

	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_SR_FAILED:
		case ICMP_PORT_UNREACH:
			/* Impossible event. */
			return 0;
		case ICMP_FRAG_NEEDED:
			/* Soft state for pmtu is maintained by IP core. */
			return 0;
		default:
			/* All others are translated to HOST_UNREACH.
			   rfc2003 contains "deep thoughts" about NET_UNREACH,
			   I believe they are just ether pollution. --ANK
			 */
			break;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		if (code != ICMP_EXC_TTL)
			return 0;
		break;
	}

	err = -ENOENT;

	read_lock(&ipip_lock);
	t = ipip_tunnel_lookup(dev_net(skb->dev), iph->daddr, iph->saddr);
	if (t == NULL || t->parms.iph.daddr == 0)
	/* All the routers (except for Linux) return only
	 * 8 bytes of packet payload. It means, that precise relaying of
	 * ICMP in the real Internet is absolutely infeasible.
	 */
	struct net *net = dev_net(skb->dev);
	struct ip_tunnel_net *itn = net_generic(net, ipip_net_id);
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	struct ip_tunnel *t;
	int err = 0;

	switch (type) {
	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_SR_FAILED:
			/* Impossible event. */
			goto out;
		default:
			/* All others are translated to HOST_UNREACH.
			 * rfc2003 contains "deep thoughts" about NET_UNREACH,
			 * I believe they are just ether pollution. --ANK
			 */
			break;
		}
		break;

	case ICMP_TIME_EXCEEDED:
		if (code != ICMP_EXC_TTL)
			goto out;
		break;

	case ICMP_REDIRECT:
		break;

	default:
		goto out;
	}

	t = ip_tunnel_lookup(itn, skb->dev->ifindex, TUNNEL_NO_KEY,
			     iph->daddr, iph->saddr, 0);
	if (!t) {
		err = -ENOENT;
		goto out;
	}

	if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED) {
		ipv4_update_pmtu(skb, net, info, t->parms.link, 0,
				 iph->protocol, 0);
		goto out;
	}

	if (type == ICMP_REDIRECT) {
		ipv4_redirect(skb, net, t->parms.link, 0, iph->protocol, 0);
		goto out;
	}

	if (t->parms.iph.daddr == 0) {
		err = -ENOENT;
		goto out;
	}

	if (t->parms.iph.ttl == 0 && type == ICMP_TIME_EXCEEDED)
		goto out;

	if (jiffies - t->err_time < IPTUNNEL_ERR_TIMEO)
	if (time_before(jiffies, t->err_time + IPTUNNEL_ERR_TIMEO))
		t->err_count++;
	else
		t->err_count = 1;
	t->err_time = jiffies;
out:
	read_unlock(&ipip_lock);
	return err;
}

static inline void ipip_ecn_decapsulate(const struct iphdr *outer_iph,
					struct sk_buff *skb)
{
	struct iphdr *inner_iph = ip_hdr(skb);

	if (INET_ECN_is_ce(outer_iph->tos))
		IP_ECN_set_ce(inner_iph);
}

static int ipip_rcv(struct sk_buff *skb)
{
	struct ip_tunnel *tunnel;
	const struct iphdr *iph = ip_hdr(skb);

	read_lock(&ipip_lock);
	if ((tunnel = ipip_tunnel_lookup(dev_net(skb->dev),
					iph->saddr, iph->daddr)) != NULL) {
		if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
			read_unlock(&ipip_lock);
			kfree_skb(skb);
			return 0;
		}

		secpath_reset(skb);

		skb->mac_header = skb->network_header;
		skb_reset_network_header(skb);
		skb->protocol = htons(ETH_P_IP);
		skb->pkt_type = PACKET_HOST;

		tunnel->dev->stats.rx_packets++;
		tunnel->dev->stats.rx_bytes += skb->len;
		skb->dev = tunnel->dev;
		dst_release(skb->dst);
		skb->dst = NULL;
		nf_reset(skb);
		ipip_ecn_decapsulate(iph, skb);
		netif_rx(skb);
		read_unlock(&ipip_lock);
		return 0;
	}
	read_unlock(&ipip_lock);

	return -1;

out:
	return err;
}

static const struct tnl_ptk_info ipip_tpi = {
	/* no tunnel info required for ipip. */
	.proto = htons(ETH_P_IP),
};

#if IS_ENABLED(CONFIG_MPLS)
static const struct tnl_ptk_info mplsip_tpi = {
	/* no tunnel info required for mplsip. */
	.proto = htons(ETH_P_MPLS_UC),
};
#endif

static int ipip_tunnel_rcv(struct sk_buff *skb, u8 ipproto)
{
	struct net *net = dev_net(skb->dev);
	struct ip_tunnel_net *itn = net_generic(net, ipip_net_id);
	struct metadata_dst *tun_dst = NULL;
	struct ip_tunnel *tunnel;
	const struct iphdr *iph;

	iph = ip_hdr(skb);
	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex, TUNNEL_NO_KEY,
			iph->saddr, iph->daddr, 0);
	if (tunnel) {
		const struct tnl_ptk_info *tpi;

		if (tunnel->parms.iph.protocol != ipproto &&
		    tunnel->parms.iph.protocol != 0)
			goto drop;

		if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto drop;
#if IS_ENABLED(CONFIG_MPLS)
		if (ipproto == IPPROTO_MPLS)
			tpi = &mplsip_tpi;
		else
#endif
			tpi = &ipip_tpi;
		if (iptunnel_pull_header(skb, 0, tpi->proto, false))
			goto drop;
		if (tunnel->collect_md) {
			tun_dst = ip_tun_rx_dst(skb, 0, 0, 0);
			if (!tun_dst)
				return 0;
		}
		return ip_tunnel_rcv(tunnel, skb, tpi, tun_dst, log_ecn_error);
	}

	return -1;

drop:
	kfree_skb(skb);
	return 0;
}

static int ipip_rcv(struct sk_buff *skb)
{
	return ipip_tunnel_rcv(skb, IPPROTO_IPIP);
}

#if IS_ENABLED(CONFIG_MPLS)
static int mplsip_rcv(struct sk_buff *skb)
{
	return ipip_tunnel_rcv(skb, IPPROTO_MPLS);
}
#endif

/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */

static int ipip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct net_device_stats *stats = &tunnel->dev->stats;
	struct iphdr  *tiph = &tunnel->parms.iph;
	u8     tos = tunnel->parms.iph.tos;
	__be16 df = tiph->frag_off;
	struct rtable *rt;     			/* Route to the other host */
	struct net_device *tdev;			/* Device to other host */
	struct iphdr  *old_iph = ip_hdr(skb);
	struct iphdr  *iph;			/* Our new IP header */
	unsigned int max_headroom;		/* The extra header space needed */
	__be32 dst = tiph->daddr;
	int    mtu;

	if (tunnel->recursion++) {
		stats->collisions++;
		goto tx_error;
	}

	if (skb->protocol != htons(ETH_P_IP))
		goto tx_error;

	if (tos&1)
		tos = old_iph->tos;

	if (!dst) {
		/* NBMA tunnel */
		if ((rt = skb->rtable) == NULL) {
			stats->tx_fifo_errors++;
			goto tx_error;
		}
		if ((dst = rt->rt_gateway) == 0)
			goto tx_error_icmp;
	}

	{
		struct flowi fl = { .oif = tunnel->parms.link,
				    .nl_u = { .ip4_u =
					      { .daddr = dst,
						.saddr = tiph->saddr,
						.tos = RT_TOS(tos) } },
				    .proto = IPPROTO_IPIP };
		if (ip_route_output_key(dev_net(dev), &rt, &fl)) {
			stats->tx_carrier_errors++;
			goto tx_error_icmp;
		}
	}
	tdev = rt->u.dst.dev;

	if (tdev == dev) {
		ip_rt_put(rt);
		stats->collisions++;
		goto tx_error;
	}

	if (tiph->frag_off)
		mtu = dst_mtu(&rt->u.dst) - sizeof(struct iphdr);
	else
		mtu = skb->dst ? dst_mtu(skb->dst) : dev->mtu;

	if (mtu < 68) {
		stats->collisions++;
		ip_rt_put(rt);
		goto tx_error;
	}
	if (skb->dst)
		skb->dst->ops->update_pmtu(skb->dst, mtu);

	df |= (old_iph->frag_off&htons(IP_DF));

	if ((old_iph->frag_off&htons(IP_DF)) && mtu < ntohs(old_iph->tot_len)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		ip_rt_put(rt);
		goto tx_error;
	}

	if (tunnel->err_count > 0) {
		if (jiffies - tunnel->err_time < IPTUNNEL_ERR_TIMEO) {
			tunnel->err_count--;
			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	/*
	 * Okay, now see if we can stuff it in the buffer as-is.
	 */
	max_headroom = (LL_RESERVED_SPACE(tdev)+sizeof(struct iphdr));

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
			stats->tx_dropped++;
			dev_kfree_skb(skb);
			tunnel->recursion--;
			return 0;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
		old_iph = ip_hdr(skb);
	}

	skb->transport_header = skb->network_header;
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	/*
	 *	Push down and install the IPIP header.
	 */

	iph 			=	ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr)>>2;
	iph->frag_off		=	df;
	iph->protocol		=	IPPROTO_IPIP;
	iph->tos		=	INET_ECN_encapsulate(tos, old_iph->tos);
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;

	if ((iph->ttl = tiph->ttl) == 0)
		iph->ttl	=	old_iph->ttl;

	nf_reset(skb);

	IPTUNNEL_XMIT();
	tunnel->recursion--;
	return 0;

tx_error_icmp:
	dst_link_failure(skb);
tx_error:
	stats->tx_errors++;
	dev_kfree_skb(skb);
	tunnel->recursion--;
	return 0;
}

static void ipip_tunnel_bind_dev(struct net_device *dev)
{
	struct net_device *tdev = NULL;
	struct ip_tunnel *tunnel;
	struct iphdr *iph;

	tunnel = netdev_priv(dev);
	iph = &tunnel->parms.iph;

	if (iph->daddr) {
		struct flowi fl = { .oif = tunnel->parms.link,
				    .nl_u = { .ip4_u =
					      { .daddr = iph->daddr,
						.saddr = iph->saddr,
						.tos = RT_TOS(iph->tos) } },
				    .proto = IPPROTO_IPIP };
		struct rtable *rt;
		if (!ip_route_output_key(dev_net(dev), &rt, &fl)) {
			tdev = rt->u.dst.dev;
			ip_rt_put(rt);
		}
		dev->flags |= IFF_POINTOPOINT;
	}

	if (!tdev && tunnel->parms.link)
		tdev = __dev_get_by_index(dev_net(dev), tunnel->parms.link);

	if (tdev) {
		dev->hard_header_len = tdev->hard_header_len + sizeof(struct iphdr);
		dev->mtu = tdev->mtu - sizeof(struct iphdr);
	}
	dev->iflink = tunnel->parms.link;
}

static int
ipip_tunnel_ioctl (struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int err = 0;
	struct ip_tunnel_parm p;
	struct ip_tunnel *t;
	struct net *net = dev_net(dev);
	struct ipip_net *ipn = net_generic(net, ipip_net_id);

	switch (cmd) {
	case SIOCGETTUNNEL:
		t = NULL;
		if (dev == ipn->fb_tunnel_dev) {
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p))) {
				err = -EFAULT;
				break;
			}
			t = ipip_tunnel_locate(net, &p, 0);
		}
		if (t == NULL)
			t = netdev_priv(dev);
		memcpy(&p, &t->parms, sizeof(p));
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p)))
			err = -EFAULT;
		break;

	case SIOCADDTUNNEL:
	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
			goto done;

		err = -EINVAL;
		if (p.iph.version != 4 || p.iph.protocol != IPPROTO_IPIP ||
		    p.iph.ihl != 5 || (p.iph.frag_off&htons(~IP_DF)))
			goto done;
		if (p.iph.ttl)
			p.iph.frag_off |= htons(IP_DF);

		t = ipip_tunnel_locate(net, &p, cmd == SIOCADDTUNNEL);

		if (dev != ipn->fb_tunnel_dev && cmd == SIOCCHGTUNNEL) {
			if (t != NULL) {
				if (t->dev != dev) {
					err = -EEXIST;
					break;
				}
			} else {
				if (((dev->flags&IFF_POINTOPOINT) && !p.iph.daddr) ||
				    (!(dev->flags&IFF_POINTOPOINT) && p.iph.daddr)) {
					err = -EINVAL;
					break;
				}
				t = netdev_priv(dev);
				ipip_tunnel_unlink(ipn, t);
				t->parms.iph.saddr = p.iph.saddr;
				t->parms.iph.daddr = p.iph.daddr;
				memcpy(dev->dev_addr, &p.iph.saddr, 4);
				memcpy(dev->broadcast, &p.iph.daddr, 4);
				ipip_tunnel_link(ipn, t);
				netdev_state_change(dev);
			}
		}

		if (t) {
			err = 0;
			if (cmd == SIOCCHGTUNNEL) {
				t->parms.iph.ttl = p.iph.ttl;
				t->parms.iph.tos = p.iph.tos;
				t->parms.iph.frag_off = p.iph.frag_off;
				if (t->parms.link != p.link) {
					t->parms.link = p.link;
					ipip_tunnel_bind_dev(dev);
					netdev_state_change(dev);
				}
			}
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &t->parms, sizeof(p)))
				err = -EFAULT;
		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);
		break;

	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		if (dev == ipn->fb_tunnel_dev) {
			err = -EFAULT;
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
				goto done;
			err = -ENOENT;
			if ((t = ipip_tunnel_locate(net, &p, 0)) == NULL)
				goto done;
			err = -EPERM;
			if (t->dev == ipn->fb_tunnel_dev)
				goto done;
			dev = t->dev;
		}
		unregister_netdevice(dev);
		err = 0;
		break;

	default:
		err = -EINVAL;
	}

done:
	return err;
}

static int ipip_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > 0xFFF8 - sizeof(struct iphdr))
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static void ipip_tunnel_setup(struct net_device *dev)
{
	dev->uninit		= ipip_tunnel_uninit;
	dev->hard_start_xmit	= ipip_tunnel_xmit;
	dev->do_ioctl		= ipip_tunnel_ioctl;
	dev->change_mtu		= ipip_tunnel_change_mtu;
	dev->destructor		= free_netdev;

	dev->type		= ARPHRD_TUNNEL;
	dev->hard_header_len 	= LL_MAX_HEADER + sizeof(struct iphdr);
	dev->mtu		= ETH_DATA_LEN - sizeof(struct iphdr);
	dev->flags		= IFF_NOARP;
	dev->iflink		= 0;
	dev->addr_len		= 4;
	dev->features		|= NETIF_F_NETNS_LOCAL;
static netdev_tx_t ipip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
static netdev_tx_t ipip_tunnel_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr  *tiph = &tunnel->parms.iph;
	u8 ipproto;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipproto = IPPROTO_IPIP;
		break;
#if IS_ENABLED(CONFIG_MPLS)
	case htons(ETH_P_MPLS_UC):
		ipproto = IPPROTO_MPLS;
		break;
#endif
	default:
		goto tx_error;
	}

	if (tiph->protocol != ipproto && tiph->protocol != 0)
		goto tx_error;

	if (iptunnel_handle_offloads(skb, SKB_GSO_IPXIP4))
		goto tx_error;

	skb_set_inner_ipproto(skb, ipproto);

	if (tunnel->collect_md)
		ip_md_tunnel_xmit(skb, dev, ipproto);
	else
		ip_tunnel_xmit(skb, dev, tiph, ipproto);
	return NETDEV_TX_OK;

tx_error:
	kfree_skb(skb);

	dev->stats.tx_errors++;
	return NETDEV_TX_OK;
}

static bool ipip_tunnel_ioctl_verify_protocol(u8 ipproto)
{
	switch (ipproto) {
	case 0:
	case IPPROTO_IPIP:
#if IS_ENABLED(CONFIG_MPLS)
	case IPPROTO_MPLS:
#endif
		return true;
	}

	return false;
}

static int
ipip_tunnel_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int err = 0;
	struct ip_tunnel_parm p;

	if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
		return -EFAULT;

	if (cmd == SIOCADDTUNNEL || cmd == SIOCCHGTUNNEL) {
		if (p.iph.version != 4 ||
		    !ipip_tunnel_ioctl_verify_protocol(p.iph.protocol) ||
		    p.iph.ihl != 5 || (p.iph.frag_off&htons(~IP_DF)))
			return -EINVAL;
	}

	p.i_key = p.o_key = 0;
	p.i_flags = p.o_flags = 0;
	err = ip_tunnel_ioctl(dev, &p, cmd);
	if (err)
		return err;

	if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p)))
		return -EFAULT;

	return 0;
}

static const struct net_device_ops ipip_netdev_ops = {
	.ndo_init       = ipip_tunnel_init,
	.ndo_uninit     = ip_tunnel_uninit,
	.ndo_start_xmit	= ipip_tunnel_xmit,
	.ndo_do_ioctl	= ipip_tunnel_ioctl,
	.ndo_change_mtu = ip_tunnel_change_mtu,
	.ndo_get_stats64 = ip_tunnel_get_stats64,
	.ndo_get_iflink = ip_tunnel_get_iflink,
};

#define IPIP_FEATURES (NETIF_F_SG |		\
		       NETIF_F_FRAGLIST |	\
		       NETIF_F_HIGHDMA |	\
		       NETIF_F_GSO_SOFTWARE |	\
		       NETIF_F_HW_CSUM)

static void ipip_tunnel_setup(struct net_device *dev)
{
	dev->netdev_ops		= &ipip_netdev_ops;

	dev->type		= ARPHRD_TUNNEL;
	dev->flags		= IFF_NOARP;
	dev->addr_len		= 4;
	dev->features		|= NETIF_F_LLTX;
	netif_keep_dst(dev);

	dev->features		|= IPIP_FEATURES;
	dev->hw_features	|= IPIP_FEATURES;
	ip_tunnel_setup(dev, ipip_net_id);
}

static int ipip_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel;

	tunnel = netdev_priv(dev);

	tunnel->dev = dev;
	strcpy(tunnel->parms.name, dev->name);
	struct ip_tunnel *tunnel = netdev_priv(dev);

	memcpy(dev->dev_addr, &tunnel->parms.iph.saddr, 4);
	memcpy(dev->broadcast, &tunnel->parms.iph.daddr, 4);

	ipip_tunnel_bind_dev(dev);

	return 0;
}

static int ipip_fb_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;
	struct ipip_net *ipn = net_generic(dev_net(dev), ipip_net_id);

	tunnel->dev = dev;
	strcpy(tunnel->parms.name, dev->name);

	iph->version		= 4;
	iph->protocol		= IPPROTO_IPIP;
	iph->ihl		= 5;

	dev_hold(dev);
	ipn->tunnels_wc[0]	= tunnel;
	return 0;
}

static struct xfrm_tunnel ipip_handler = {
	tunnel->tun_hlen = 0;
	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;
	return ip_tunnel_init(dev);
}

static int ipip_tunnel_validate(struct nlattr *tb[], struct nlattr *data[],
				struct netlink_ext_ack *extack)
{
	u8 proto;

	if (!data || !data[IFLA_IPTUN_PROTO])
		return 0;

	proto = nla_get_u8(data[IFLA_IPTUN_PROTO]);
	if (proto != IPPROTO_IPIP && proto != IPPROTO_MPLS && proto != 0)
		return -EINVAL;

	return 0;
}

static void ipip_netlink_parms(struct nlattr *data[],
			       struct ip_tunnel_parm *parms, bool *collect_md,
			       __u32 *fwmark)
{
	memset(parms, 0, sizeof(*parms));

	parms->iph.version = 4;
	parms->iph.protocol = IPPROTO_IPIP;
	parms->iph.ihl = 5;
	*collect_md = false;

	if (!data)
		return;

	if (data[IFLA_IPTUN_LINK])
		parms->link = nla_get_u32(data[IFLA_IPTUN_LINK]);

	if (data[IFLA_IPTUN_LOCAL])
		parms->iph.saddr = nla_get_in_addr(data[IFLA_IPTUN_LOCAL]);

	if (data[IFLA_IPTUN_REMOTE])
		parms->iph.daddr = nla_get_in_addr(data[IFLA_IPTUN_REMOTE]);

	if (data[IFLA_IPTUN_TTL]) {
		parms->iph.ttl = nla_get_u8(data[IFLA_IPTUN_TTL]);
		if (parms->iph.ttl)
			parms->iph.frag_off = htons(IP_DF);
	}

	if (data[IFLA_IPTUN_TOS])
		parms->iph.tos = nla_get_u8(data[IFLA_IPTUN_TOS]);

	if (data[IFLA_IPTUN_PROTO])
		parms->iph.protocol = nla_get_u8(data[IFLA_IPTUN_PROTO]);

	if (!data[IFLA_IPTUN_PMTUDISC] || nla_get_u8(data[IFLA_IPTUN_PMTUDISC]))
		parms->iph.frag_off = htons(IP_DF);

	if (data[IFLA_IPTUN_COLLECT_METADATA])
		*collect_md = true;

	if (data[IFLA_IPTUN_FWMARK])
		*fwmark = nla_get_u32(data[IFLA_IPTUN_FWMARK]);
}

/* This function returns true when ENCAP attributes are present in the nl msg */
static bool ipip_netlink_encap_parms(struct nlattr *data[],
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

static int ipip_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	struct ip_tunnel *t = netdev_priv(dev);
	struct ip_tunnel_parm p;
	struct ip_tunnel_encap ipencap;
	__u32 fwmark = 0;

	if (ipip_netlink_encap_parms(data, &ipencap)) {
		int err = ip_tunnel_encap_setup(t, &ipencap);

		if (err < 0)
			return err;
	}

	ipip_netlink_parms(data, &p, &t->collect_md, &fwmark);
	return ip_tunnel_newlink(dev, tb, &p, fwmark);
}

static int ipip_changelink(struct net_device *dev, struct nlattr *tb[],
			   struct nlattr *data[],
			   struct netlink_ext_ack *extack)
{
	struct ip_tunnel *t = netdev_priv(dev);
	struct ip_tunnel_parm p;
	struct ip_tunnel_encap ipencap;
	bool collect_md;
	__u32 fwmark = t->fwmark;

	if (ipip_netlink_encap_parms(data, &ipencap)) {
		int err = ip_tunnel_encap_setup(t, &ipencap);

		if (err < 0)
			return err;
	}

	ipip_netlink_parms(data, &p, &collect_md, &fwmark);
	if (collect_md)
		return -EINVAL;

	if (((dev->flags & IFF_POINTOPOINT) && !p.iph.daddr) ||
	    (!(dev->flags & IFF_POINTOPOINT) && p.iph.daddr))
		return -EINVAL;

	return ip_tunnel_changelink(dev, tb, &p, fwmark);
}

static size_t ipip_get_size(const struct net_device *dev)
{
	return
		/* IFLA_IPTUN_LINK */
		nla_total_size(4) +
		/* IFLA_IPTUN_LOCAL */
		nla_total_size(4) +
		/* IFLA_IPTUN_REMOTE */
		nla_total_size(4) +
		/* IFLA_IPTUN_TTL */
		nla_total_size(1) +
		/* IFLA_IPTUN_TOS */
		nla_total_size(1) +
		/* IFLA_IPTUN_PROTO */
		nla_total_size(1) +
		/* IFLA_IPTUN_PMTUDISC */
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

static int ipip_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct ip_tunnel_parm *parm = &tunnel->parms;

	if (nla_put_u32(skb, IFLA_IPTUN_LINK, parm->link) ||
	    nla_put_in_addr(skb, IFLA_IPTUN_LOCAL, parm->iph.saddr) ||
	    nla_put_in_addr(skb, IFLA_IPTUN_REMOTE, parm->iph.daddr) ||
	    nla_put_u8(skb, IFLA_IPTUN_TTL, parm->iph.ttl) ||
	    nla_put_u8(skb, IFLA_IPTUN_TOS, parm->iph.tos) ||
	    nla_put_u8(skb, IFLA_IPTUN_PROTO, parm->iph.protocol) ||
	    nla_put_u8(skb, IFLA_IPTUN_PMTUDISC,
		       !!(parm->iph.frag_off & htons(IP_DF))) ||
	    nla_put_u32(skb, IFLA_IPTUN_FWMARK, tunnel->fwmark))
		goto nla_put_failure;

	if (nla_put_u16(skb, IFLA_IPTUN_ENCAP_TYPE,
			tunnel->encap.type) ||
	    nla_put_be16(skb, IFLA_IPTUN_ENCAP_SPORT,
			 tunnel->encap.sport) ||
	    nla_put_be16(skb, IFLA_IPTUN_ENCAP_DPORT,
			 tunnel->encap.dport) ||
	    nla_put_u16(skb, IFLA_IPTUN_ENCAP_FLAGS,
			tunnel->encap.flags))
		goto nla_put_failure;

	if (tunnel->collect_md)
		if (nla_put_flag(skb, IFLA_IPTUN_COLLECT_METADATA))
			goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static const struct nla_policy ipip_policy[IFLA_IPTUN_MAX + 1] = {
	[IFLA_IPTUN_LINK]		= { .type = NLA_U32 },
	[IFLA_IPTUN_LOCAL]		= { .type = NLA_U32 },
	[IFLA_IPTUN_REMOTE]		= { .type = NLA_U32 },
	[IFLA_IPTUN_TTL]		= { .type = NLA_U8 },
	[IFLA_IPTUN_TOS]		= { .type = NLA_U8 },
	[IFLA_IPTUN_PROTO]		= { .type = NLA_U8 },
	[IFLA_IPTUN_PMTUDISC]		= { .type = NLA_U8 },
	[IFLA_IPTUN_ENCAP_TYPE]		= { .type = NLA_U16 },
	[IFLA_IPTUN_ENCAP_FLAGS]	= { .type = NLA_U16 },
	[IFLA_IPTUN_ENCAP_SPORT]	= { .type = NLA_U16 },
	[IFLA_IPTUN_ENCAP_DPORT]	= { .type = NLA_U16 },
	[IFLA_IPTUN_COLLECT_METADATA]	= { .type = NLA_FLAG },
	[IFLA_IPTUN_FWMARK]		= { .type = NLA_U32 },
};

static struct rtnl_link_ops ipip_link_ops __read_mostly = {
	.kind		= "ipip",
	.maxtype	= IFLA_IPTUN_MAX,
	.policy		= ipip_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= ipip_tunnel_setup,
	.validate	= ipip_tunnel_validate,
	.newlink	= ipip_newlink,
	.changelink	= ipip_changelink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipip_get_size,
	.fill_info	= ipip_fill_info,
	.get_link_net	= ip_tunnel_get_link_net,
};

static struct xfrm_tunnel ipip_handler __read_mostly = {
	.handler	=	ipip_rcv,
	.err_handler	=	ipip_err,
	.priority	=	1,
};

static char banner[] __initdata =
	KERN_INFO "IPv4 over IPv4 tunneling driver\n";

static void ipip_destroy_tunnels(struct ipip_net *ipn)
{
	int prio;

	for (prio = 1; prio < 4; prio++) {
		int h;
		for (h = 0; h < HASH_SIZE; h++) {
			struct ip_tunnel *t;
			while ((t = ipn->tunnels[prio][h]) != NULL)
				unregister_netdevice(t->dev);
		}
	}
}

static int ipip_init_net(struct net *net)
{
	int err;
	struct ipip_net *ipn;

	err = -ENOMEM;
	ipn = kzalloc(sizeof(struct ipip_net), GFP_KERNEL);
	if (ipn == NULL)
		goto err_alloc;

	err = net_assign_generic(net, ipip_net_id, ipn);
	if (err < 0)
		goto err_assign;

	ipn->tunnels[0] = ipn->tunnels_wc;
	ipn->tunnels[1] = ipn->tunnels_l;
	ipn->tunnels[2] = ipn->tunnels_r;
	ipn->tunnels[3] = ipn->tunnels_r_l;

	ipn->fb_tunnel_dev = alloc_netdev(sizeof(struct ip_tunnel),
					   "tunl0",
					   ipip_tunnel_setup);
	if (!ipn->fb_tunnel_dev) {
		err = -ENOMEM;
		goto err_alloc_dev;
	}

	ipn->fb_tunnel_dev->init = ipip_fb_tunnel_init;
	dev_net_set(ipn->fb_tunnel_dev, net);

	if ((err = register_netdev(ipn->fb_tunnel_dev)))
		goto err_reg_dev;

	return 0;

err_reg_dev:
	free_netdev(ipn->fb_tunnel_dev);
err_alloc_dev:
	/* nothing */
err_assign:
	kfree(ipn);
err_alloc:
	return err;
}

static void ipip_exit_net(struct net *net)
{
	struct ipip_net *ipn;

	ipn = net_generic(net, ipip_net_id);
	rtnl_lock();
	ipip_destroy_tunnels(ipn);
	unregister_netdevice(ipn->fb_tunnel_dev);
	rtnl_unlock();
	kfree(ipn);
#if IS_ENABLED(CONFIG_MPLS)
static struct xfrm_tunnel mplsip_handler __read_mostly = {
	.handler	=	mplsip_rcv,
	.err_handler	=	ipip_err,
	.priority	=	1,
};
#endif

static int __net_init ipip_init_net(struct net *net)
{
	return ip_tunnel_init_net(net, ipip_net_id, &ipip_link_ops, "tunl0");
}

static void __net_exit ipip_exit_net(struct net *net)
{
	struct ip_tunnel_net *itn = net_generic(net, ipip_net_id);
	ip_tunnel_delete_net(itn, &ipip_link_ops);
}

static struct pernet_operations ipip_net_ops = {
	.init = ipip_init_net,
	.exit = ipip_exit_net,
	.id   = &ipip_net_id,
	.size = sizeof(struct ip_tunnel_net),
};

static int __init ipip_init(void)
{
	int err;

	printk(banner);

	if (xfrm4_tunnel_register(&ipip_handler, AF_INET)) {
		printk(KERN_INFO "ipip init: can't register tunnel\n");
		return -EAGAIN;
	}

	err = register_pernet_gen_device(&ipip_net_id, &ipip_net_ops);
	if (err)
		xfrm4_tunnel_deregister(&ipip_handler, AF_INET);

	return err;
	pr_info("ipip: IPv4 over IPv4 tunneling driver\n");
	pr_info("ipip: IPv4 and MPLS over IPv4 tunneling driver\n");

	err = register_pernet_device(&ipip_net_ops);
	if (err < 0)
		return err;
	err = xfrm4_tunnel_register(&ipip_handler, AF_INET);
	if (err < 0) {
		pr_info("%s: can't register tunnel\n", __func__);
		goto xfrm_tunnel_ipip_failed;
	}
#if IS_ENABLED(CONFIG_MPLS)
	err = xfrm4_tunnel_register(&mplsip_handler, AF_MPLS);
	if (err < 0) {
		pr_info("%s: can't register tunnel\n", __func__);
		goto xfrm_tunnel_mplsip_failed;
	}
#endif
	err = rtnl_link_register(&ipip_link_ops);
	if (err < 0)
		goto rtnl_link_failed;

out:
	return err;

rtnl_link_failed:
#if IS_ENABLED(CONFIG_MPLS)
	xfrm4_tunnel_deregister(&mplsip_handler, AF_INET);
xfrm_tunnel_mplsip_failed:

#endif
	xfrm4_tunnel_deregister(&ipip_handler, AF_INET);
xfrm_tunnel_ipip_failed:
	unregister_pernet_device(&ipip_net_ops);
	goto out;
}

static void __exit ipip_fini(void)
{
	if (xfrm4_tunnel_deregister(&ipip_handler, AF_INET))
		printk(KERN_INFO "ipip close: can't deregister tunnel\n");

	unregister_pernet_gen_device(ipip_net_id, &ipip_net_ops);
	rtnl_link_unregister(&ipip_link_ops);
	if (xfrm4_tunnel_deregister(&ipip_handler, AF_INET))
		pr_info("%s: can't deregister tunnel\n", __func__);
#if IS_ENABLED(CONFIG_MPLS)
	if (xfrm4_tunnel_deregister(&mplsip_handler, AF_MPLS))
		pr_info("%s: can't deregister tunnel\n", __func__);
#endif
	unregister_pernet_device(&ipip_net_ops);
}

module_init(ipip_init);
module_exit(ipip_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("ipip");
MODULE_ALIAS_NETDEV("tunl0");
