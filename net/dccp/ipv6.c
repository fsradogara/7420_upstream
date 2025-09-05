/*
 *	DCCP over IPv6
 *	Linux INET6 implementation
 *
 *	Based on net/dccp6/ipv6.c
 *
 *	Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/xfrm.h>
#include <linux/string.h>

#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/inet6_connection_sock.h>
#include <net/inet6_hashtables.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/ip6_checksum.h>
#include <net/xfrm.h>
#include <net/secure_seq.h>
#include <net/sock.h>

#include "dccp.h"
#include "ipv6.h"
#include "feat.h"

/* The per-net dccp.v6_ctl_sk is used for sending RSTs and ACKs */

static struct inet_connection_sock_af_ops dccp_ipv6_mapped;
static struct inet_connection_sock_af_ops dccp_ipv6_af_ops;

static void dccp_v6_hash(struct sock *sk)
{
	if (sk->sk_state != DCCP_CLOSED) {
		if (inet_csk(sk)->icsk_af_ops == &dccp_ipv6_mapped) {
			inet_hash(sk);
			return;
		}
		local_bh_disable();
		__inet6_hash(sk);
		local_bh_enable();
	}
}

/* add pseudo-header to DCCP checksum stored in skb->csum */
static inline __sum16 dccp_v6_csum_finish(struct sk_buff *skb,
				      struct in6_addr *saddr,
				      struct in6_addr *daddr)
static const struct inet_connection_sock_af_ops dccp_ipv6_mapped;
static const struct inet_connection_sock_af_ops dccp_ipv6_af_ops;

/* add pseudo-header to DCCP checksum stored in skb->csum */
static inline __sum16 dccp_v6_csum_finish(struct sk_buff *skb,
				      const struct in6_addr *saddr,
				      const struct in6_addr *daddr)
{
	return csum_ipv6_magic(saddr, daddr, skb->len, IPPROTO_DCCP, skb->csum);
}

static inline void dccp_v6_send_check(struct sock *sk, int unused_value,
				      struct sk_buff *skb)
static inline void dccp_v6_send_check(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct dccp_hdr *dh = dccp_hdr(skb);

	dccp_csum_outgoing(skb);
	dh->dccph_checksum = dccp_v6_csum_finish(skb, &np->saddr, &np->daddr);
}

static inline __u32 secure_dccpv6_sequence_number(__be32 *saddr, __be32 *daddr,
						  __be16 sport, __be16 dport   )
{
	return secure_tcpv6_sequence_number(saddr, daddr, sport, dport);
}

static inline __u32 dccp_v6_init_sequence(struct sk_buff *skb)
	dh->dccph_checksum = dccp_v6_csum_finish(skb, &np->saddr, &sk->sk_v6_daddr);
}

static inline __u64 dccp_v6_init_sequence(struct sk_buff *skb)
{
	return secure_dccpv6_sequence_number(ipv6_hdr(skb)->daddr.s6_addr32,
					     ipv6_hdr(skb)->saddr.s6_addr32,
					     dccp_hdr(skb)->dccph_dport,
					     dccp_hdr(skb)->dccph_sport     );

}

static void dccp_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			int type, int code, int offset, __be32 info)
{
	struct ipv6hdr *hdr = (struct ipv6hdr *)skb->data;
			u8 type, u8 code, int offset, __be32 info)
{
	const struct ipv6hdr *hdr = (const struct ipv6hdr *)skb->data;
	const struct dccp_hdr *dh;
	struct dccp_sock *dp;
	struct ipv6_pinfo *np;
	struct sock *sk;
	int err;
	__u64 seq;
	struct net *net = dev_net(skb->dev);

	if (skb->len < offset + sizeof(*dh) ||
	    skb->len < offset + __dccp_basic_hdr_len(dh)) {
		ICMP6_INC_STATS_BH(__in6_dev_get(skb->dev), ICMP6_MIB_INERRORS);
		return;
	}

	sk = inet6_lookup(net, &dccp_hashinfo,
			&hdr->daddr, dh->dccph_dport,
			&hdr->saddr, dh->dccph_sport, inet6_iif(skb));

	if (sk == NULL) {
		ICMP6_INC_STATS_BH(__in6_dev_get(skb->dev), ICMP6_MIB_INERRORS);
		ICMP6_INC_STATS_BH(net, __in6_dev_get(skb->dev),
				   ICMP6_MIB_INERRORS);
		return;
	}
	/* Only need dccph_dport & dccph_sport which are the first
	 * 4 bytes in dccp header.
	 * Our caller (icmpv6_notify()) already pulled 8 bytes for us.
	 */
	BUILD_BUG_ON(offsetofend(struct dccp_hdr, dccph_sport) > 8);
	BUILD_BUG_ON(offsetofend(struct dccp_hdr, dccph_dport) > 8);
	dh = (struct dccp_hdr *)(skb->data + offset);

	sk = __inet6_lookup_established(net, &dccp_hashinfo,
					&hdr->daddr, dh->dccph_dport,
					&hdr->saddr, ntohs(dh->dccph_sport),
					inet6_iif(skb), 0);

	if (!sk) {
		__ICMP6_INC_STATS(net, __in6_dev_get(skb->dev),
				  ICMP6_MIB_INERRORS);
		return;
	}

	if (sk->sk_state == DCCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
		return;
	}
	seq = dccp_hdr_seq(dh);
	if (sk->sk_state == DCCP_NEW_SYN_RECV)
		return dccp_req_err(sk, seq);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk))
		__NET_INC_STATS(net, LINUX_MIB_LOCKDROPPEDICMPS);

	if (sk->sk_state == DCCP_CLOSED)
		goto out;

	dp = dccp_sk(sk);
	seq = dccp_hdr_seq(dh);
	if ((1 << sk->sk_state) & ~(DCCPF_REQUESTING | DCCPF_LISTEN) &&
	    !between48(seq, dp->dccps_awl, dp->dccps_awh)) {
		__NET_INC_STATS(net, LINUX_MIB_OUTOFWINDOWICMPS);
		goto out;
	}

	np = inet6_sk(sk);

	if (type == ICMPV6_PKT_TOOBIG) {
		struct dst_entry *dst = NULL;

	if (type == NDISC_REDIRECT) {
		if (!sock_owned_by_user(sk)) {
			struct dst_entry *dst = __sk_dst_check(sk, np->dst_cookie);

			if (dst)
				dst->ops->redirect(dst, sk, skb);
		}
		goto out;
	}

	if (type == ICMPV6_PKT_TOOBIG) {
		struct dst_entry *dst = NULL;

		if (!ip6_sk_accept_pmtu(sk))
			goto out;

		if (sock_owned_by_user(sk))
			goto out;
		if ((1 << sk->sk_state) & (DCCPF_LISTEN | DCCPF_CLOSED))
			goto out;

		/* icmp should have updated the destination cache entry */
		dst = __sk_dst_check(sk, np->dst_cookie);
		if (dst == NULL) {
			struct inet_sock *inet = inet_sk(sk);
			struct flowi fl;

			/* BUGGG_FUTURE: Again, it is not clear how
			   to handle rthdr case. Ignore this complexity
			   for now.
			 */
			memset(&fl, 0, sizeof(fl));
			fl.proto = IPPROTO_DCCP;
			ipv6_addr_copy(&fl.fl6_dst, &np->daddr);
			ipv6_addr_copy(&fl.fl6_src, &np->saddr);
			fl.oif = sk->sk_bound_dev_if;
			fl.fl_ip_dport = inet->dport;
			fl.fl_ip_sport = inet->sport;
			security_sk_classify_flow(sk, &fl);

			err = ip6_dst_lookup(sk, &dst, &fl);
			if (err) {
				sk->sk_err_soft = -err;
				goto out;
			}

			err = xfrm_lookup(&dst, &fl, sk, 0);
			if (err < 0) {
				sk->sk_err_soft = -err;
				goto out;
			}
		} else
			dst_hold(dst);

		if (inet_csk(sk)->icsk_pmtu_cookie > dst_mtu(dst)) {
			dccp_sync_mss(sk, dst_mtu(dst));
		} /* else let the usual retransmit timer handle it */
		dst_release(dst);
		dst = inet6_csk_update_pmtu(sk, ntohl(info));
		if (!dst)
			goto out;

		if (inet_csk(sk)->icsk_pmtu_cookie > dst_mtu(dst))
			dccp_sync_mss(sk, dst_mtu(dst));
		goto out;
	}

	icmpv6_err_convert(type, code, &err);

	/* Might be for an request_sock */
	switch (sk->sk_state) {
		struct request_sock *req, **prev;
	case DCCP_LISTEN:
		if (sock_owned_by_user(sk))
			goto out;

		req = inet6_csk_search_req(sk, &prev, dh->dccph_dport,
					   &hdr->daddr, &hdr->saddr,
					   inet6_iif(skb));
		if (req == NULL)
			goto out;

		/*
		 * ICMPs are not backlogged, hence we cannot get an established
		 * socket here.
		 */
		WARN_ON(req->sk != NULL);

		if (seq != dccp_rsk(req)->dreq_iss) {
			NET_INC_STATS_BH(net, LINUX_MIB_OUTOFWINDOWICMPS);
			goto out;
		}

		inet_csk_reqsk_queue_drop(sk, req, prev);
		goto out;

	case DCCP_REQUESTING:
	case DCCP_RESPOND:  /* Cannot happen.
			       It can, it SYNs are crossed. --ANK */
		if (!sock_owned_by_user(sk)) {
			__DCCP_INC_STATS(DCCP_MIB_ATTEMPTFAILS);
			sk->sk_err = err;
			/*
			 * Wake people up to see the error
			 * (see connect in sock.c)
			 */
			sk->sk_error_report(sk);
			dccp_done(sk);
		} else
			sk->sk_err_soft = err;
		goto out;
	}

	if (!sock_owned_by_user(sk) && np->recverr) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	} else
		sk->sk_err_soft = err;

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}


static int dccp_v6_send_response(struct sock *sk, struct request_sock *req)
{
	struct inet6_request_sock *ireq6 = inet6_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *skb;
	struct ipv6_txoptions *opt = NULL;
	struct in6_addr *final_p = NULL, final;
	struct flowi fl;
	int err = -1;
	struct dst_entry *dst;

	memset(&fl, 0, sizeof(fl));
	fl.proto = IPPROTO_DCCP;
	ipv6_addr_copy(&fl.fl6_dst, &ireq6->rmt_addr);
	ipv6_addr_copy(&fl.fl6_src, &ireq6->loc_addr);
	fl.fl6_flowlabel = 0;
	fl.oif = ireq6->iif;
	fl.fl_ip_dport = inet_rsk(req)->rmt_port;
	fl.fl_ip_sport = inet_sk(sk)->sport;
	security_req_classify_flow(req, &fl);

	opt = np->opt;

	if (opt != NULL && opt->srcrt != NULL) {
		const struct rt0_hdr *rt0 = (struct rt0_hdr *)opt->srcrt;

		ipv6_addr_copy(&final, &fl.fl6_dst);
		ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
		final_p = &final;
	}

	err = ip6_dst_lookup(sk, &dst, &fl);
	if (err)
		goto done;

	if (final_p)
		ipv6_addr_copy(&fl.fl6_dst, final_p);

	err = xfrm_lookup(&dst, &fl, sk, 0);
	if (err < 0)
		goto done;

static int dccp_v6_send_response(const struct sock *sk, struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *skb;
	struct in6_addr *final_p, final;
	struct flowi6 fl6;
	int err = -1;
	struct dst_entry *dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.daddr = ireq->ir_v6_rmt_addr;
	fl6.saddr = ireq->ir_v6_loc_addr;
	fl6.flowlabel = 0;
	fl6.flowi6_oif = ireq->ir_iif;
	fl6.fl6_dport = ireq->ir_rmt_port;
	fl6.fl6_sport = htons(ireq->ir_num);
	security_req_classify_flow(req, flowi6_to_flowi(&fl6));


	rcu_read_lock();
	final_p = fl6_update_dst(&fl6, rcu_dereference(np->opt), &final);
	rcu_read_unlock();

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto done;
	}

	skb = dccp_make_response(sk, dst, req);
	if (skb != NULL) {
		struct dccp_hdr *dh = dccp_hdr(skb);
		struct ipv6_txoptions *opt;

		dh->dccph_checksum = dccp_v6_csum_finish(skb,
							 &ireq6->loc_addr,
							 &ireq6->rmt_addr);
		ipv6_addr_copy(&fl.fl6_dst, &ireq6->rmt_addr);
		err = ip6_xmit(sk, skb, &fl, opt, 0);
							 &ireq->ir_v6_loc_addr,
							 &ireq->ir_v6_rmt_addr);
		fl6.daddr = ireq->ir_v6_rmt_addr;
		rcu_read_lock();
		opt = ireq->ipv6_opt;
		if (!opt)
			opt = rcu_dereference(np->opt);
		err = ip6_xmit(sk, skb, &fl6, sk->sk_mark, opt, np->tclass);
		rcu_read_unlock();
		err = net_xmit_eval(err);
	}

done:
	if (opt != NULL && opt != np->opt)
		sock_kfree_s(sk, opt, opt->tot_len);
	dst_release(dst);
	return err;
}

static void dccp_v6_reqsk_destructor(struct request_sock *req)
{
	if (inet6_rsk(req)->pktopts != NULL)
		kfree_skb(inet6_rsk(req)->pktopts);
}

static void dccp_v6_ctl_send_reset(struct sock *sk, struct sk_buff *rxskb)
{
	struct ipv6hdr *rxip6h;
	struct sk_buff *skb;
	struct flowi fl;
	struct net *net = dev_net(rxskb->dst->dev);
	struct sock *ctl_sk = net->dccp.v6_ctl_sk;
	dccp_feat_list_purge(&dccp_rsk(req)->dreq_featneg);
	kfree(inet_rsk(req)->ipv6_opt);
	kfree_skb(inet_rsk(req)->pktopts);
}

static void dccp_v6_ctl_send_reset(const struct sock *sk, struct sk_buff *rxskb)
{
	const struct ipv6hdr *rxip6h;
	struct sk_buff *skb;
	struct flowi6 fl6;
	struct net *net = dev_net(skb_dst(rxskb)->dev);
	struct sock *ctl_sk = net->dccp.v6_ctl_sk;
	struct dst_entry *dst;

	if (dccp_hdr(rxskb)->dccph_type == DCCP_PKT_RESET)
		return;

	if (!ipv6_unicast_destination(rxskb))
		return;

	skb = dccp_ctl_make_reset(ctl_sk, rxskb);
	if (skb == NULL)
		return;

	rxip6h = ipv6_hdr(rxskb);
	dccp_hdr(skb)->dccph_checksum = dccp_v6_csum_finish(skb, &rxip6h->saddr,
							    &rxip6h->daddr);

	memset(&fl, 0, sizeof(fl));
	ipv6_addr_copy(&fl.fl6_dst, &rxip6h->saddr);
	ipv6_addr_copy(&fl.fl6_src, &rxip6h->daddr);

	fl.proto = IPPROTO_DCCP;
	fl.oif = inet6_iif(rxskb);
	fl.fl_ip_dport = dccp_hdr(skb)->dccph_dport;
	fl.fl_ip_sport = dccp_hdr(skb)->dccph_sport;
	security_skb_classify_flow(rxskb, &fl);

	/* sk = NULL, but it is safe for now. RST socket required. */
	if (!ip6_dst_lookup(ctl_sk, &skb->dst, &fl)) {
		if (xfrm_lookup(&skb->dst, &fl, NULL, 0) >= 0) {
			ip6_xmit(ctl_sk, skb, &fl, NULL, 0);
			DCCP_INC_STATS_BH(DCCP_MIB_OUTSEGS);
			DCCP_INC_STATS_BH(DCCP_MIB_OUTRSTS);
			return;
		}
	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = rxip6h->saddr;
	fl6.saddr = rxip6h->daddr;

	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.flowi6_oif = inet6_iif(rxskb);
	fl6.fl6_dport = dccp_hdr(skb)->dccph_dport;
	fl6.fl6_sport = dccp_hdr(skb)->dccph_sport;
	security_skb_classify_flow(rxskb, flowi6_to_flowi(&fl6));

	/* sk = NULL, but it is safe for now. RST socket required. */
	dst = ip6_dst_lookup_flow(ctl_sk, &fl6, NULL);
	if (!IS_ERR(dst)) {
		skb_dst_set(skb, dst);
		ip6_xmit(ctl_sk, skb, &fl6, 0, NULL, 0);
		DCCP_INC_STATS(DCCP_MIB_OUTSEGS);
		DCCP_INC_STATS(DCCP_MIB_OUTRSTS);
		return;
	}

	kfree_skb(skb);
}

static struct request_sock_ops dccp6_request_sock_ops = {
	.family		= AF_INET6,
	.obj_size	= sizeof(struct dccp6_request_sock),
	.rtx_syn_ack	= dccp_v6_send_response,
	.send_ack	= dccp_reqsk_send_ack,
	.destructor	= dccp_v6_reqsk_destructor,
	.send_reset	= dccp_v6_ctl_send_reset,
};

static struct sock *dccp_v6_hnd_req(struct sock *sk,struct sk_buff *skb)
{
	const struct dccp_hdr *dh = dccp_hdr(skb);
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct sock *nsk;
	struct request_sock **prev;
	/* Find possible connection requests. */
	struct request_sock *req = inet6_csk_search_req(sk, &prev,
							dh->dccph_sport,
							&iph->saddr,
							&iph->daddr,
							inet6_iif(skb));
	if (req != NULL)
		return dccp_check_req(sk, skb, req, prev);

	nsk = __inet6_lookup_established(sock_net(sk), &dccp_hashinfo,
					 &iph->saddr, dh->dccph_sport,
					 &iph->daddr, ntohs(dh->dccph_dport),
					 inet6_iif(skb));
	if (nsk != NULL) {
		if (nsk->sk_state != DCCP_TIME_WAIT) {
			bh_lock_sock(nsk);
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	}

	return sk;
}

	.syn_ack_timeout = dccp_syn_ack_timeout,
};

static int dccp_v6_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct request_sock *req;
	struct dccp_request_sock *dreq;
	struct inet6_request_sock *ireq6;
	struct inet_request_sock *ireq;
	struct ipv6_pinfo *np = inet6_sk(sk);
	const __be32 service = dccp_hdr_request(skb)->dccph_req_service;
	struct dccp_skb_cb *dcb = DCCP_SKB_CB(skb);

	if (skb->protocol == htons(ETH_P_IP))
		return dccp_v4_conn_request(sk, skb);

	if (!ipv6_unicast_destination(skb))
		return 0;	/* discard, don't send a reset here */

	if (dccp_bad_service_code(sk, service)) {
		dcb->dccpd_reset_code = DCCP_RESET_CODE_BAD_SERVICE_CODE;
		goto drop;
	}
	/*
	 * There are no SYN attacks on IPv6, yet...
	 */
	dcb->dccpd_reset_code = DCCP_RESET_CODE_TOO_BUSY;
	if (inet_csk_reqsk_queue_is_full(sk))
		goto drop;

	if (sk_acceptq_is_full(sk))
		goto drop;

	req = inet6_reqsk_alloc(&dccp6_request_sock_ops);
	if (req == NULL)
		goto drop;

	dccp_reqsk_init(req, skb);
	req = inet_reqsk_alloc(&dccp6_request_sock_ops, sk, true);
	if (req == NULL)
		goto drop;

	if (dccp_reqsk_init(req, dccp_sk(sk), skb))
		goto drop_and_free;

	dreq = dccp_rsk(req);
	if (dccp_parse_options(sk, dreq, skb))
		goto drop_and_free;

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	ireq6 = inet6_rsk(req);
	ipv6_addr_copy(&ireq6->rmt_addr, &ipv6_hdr(skb)->saddr);
	ipv6_addr_copy(&ireq6->loc_addr, &ipv6_hdr(skb)->daddr);

	if (ipv6_opt_accepted(sk, skb) ||
	    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
	    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim) {
		atomic_inc(&skb->users);
		ireq6->pktopts = skb;
	}
	ireq6->iif = sk->sk_bound_dev_if;

	/* So that link locals have meaning */
	if (!sk->sk_bound_dev_if &&
	    ipv6_addr_type(&ireq6->rmt_addr) & IPV6_ADDR_LINKLOCAL)
		ireq6->iif = inet6_iif(skb);
	ireq = inet_rsk(req);
	ireq->ir_v6_rmt_addr = ipv6_hdr(skb)->saddr;
	ireq->ir_v6_loc_addr = ipv6_hdr(skb)->daddr;
	ireq->ireq_family = AF_INET6;
	ireq->ir_mark = inet_request_mark(sk, skb);

	if (ipv6_opt_accepted(sk, skb, IP6CB(skb)) ||
	    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
	    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim) {
		refcount_inc(&skb->users);
		ireq->pktopts = skb;
	}
	ireq->ir_iif = sk->sk_bound_dev_if;

	/* So that link locals have meaning */
	if (!sk->sk_bound_dev_if &&
	    ipv6_addr_type(&ireq->ir_v6_rmt_addr) & IPV6_ADDR_LINKLOCAL)
		ireq->ir_iif = inet6_iif(skb);

	/*
	 * Step 3: Process LISTEN state
	 *
	 *   Set S.ISR, S.GSR, S.SWL, S.SWH from packet or Init Cookie
	 *
	 *   In fact we defer setting S.GSR, S.SWL, S.SWH to
	 *   dccp_create_openreq_child.
	 */
	dreq->dreq_isr	   = dcb->dccpd_seq;
	dreq->dreq_iss	   = dccp_v6_init_sequence(skb);
	 * Setting S.SWL/S.SWH to is deferred to dccp_create_openreq_child().
	 */
	dreq->dreq_isr	   = dcb->dccpd_seq;
	dreq->dreq_gsr     = dreq->dreq_isr;
	dreq->dreq_iss	   = dccp_v6_init_sequence(skb);
	dreq->dreq_gss     = dreq->dreq_iss;
	dreq->dreq_service = service;

	if (dccp_v6_send_response(sk, req))
		goto drop_and_free;

	inet6_csk_reqsk_queue_hash_add(sk, req, DCCP_TIMEOUT_INIT);
	inet_csk_reqsk_queue_hash_add(sk, req, DCCP_TIMEOUT_INIT);
	reqsk_put(req);
	return 0;

drop_and_free:
	reqsk_free(req);
drop:
	__DCCP_INC_STATS(DCCP_MIB_ATTEMPTFAILS);
	return -1;
}

static struct sock *dccp_v6_request_recv_sock(struct sock *sk,
					      struct sk_buff *skb,
					      struct request_sock *req,
					      struct dst_entry *dst)
{
	struct inet6_request_sock *ireq6 = inet6_rsk(req);
	struct ipv6_pinfo *newnp, *np = inet6_sk(sk);
	struct inet_sock *newinet;
	struct dccp_sock *newdp;
	struct dccp6_sock *newdp6;
	struct sock *newsk;
	struct ipv6_txoptions *opt;
static struct sock *dccp_v6_request_recv_sock(const struct sock *sk,
					      struct sk_buff *skb,
					      struct request_sock *req,
					      struct dst_entry *dst,
					      struct request_sock *req_unhash,
					      bool *own_req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *newnp;
	const struct ipv6_pinfo *np = inet6_sk(sk);
	struct ipv6_txoptions *opt;
	struct inet_sock *newinet;
	struct dccp6_sock *newdp6;
	struct sock *newsk;

	if (skb->protocol == htons(ETH_P_IP)) {
		/*
		 *	v6 mapped
		 */
		newsk = dccp_v4_request_recv_sock(sk, skb, req, dst);
		newsk = dccp_v4_request_recv_sock(sk, skb, req, dst,
						  req_unhash, own_req);
		if (newsk == NULL)
			return NULL;

		newdp6 = (struct dccp6_sock *)newsk;
		newdp = dccp_sk(newsk);
		newinet = inet_sk(newsk);
		newinet->pinet6 = &newdp6->inet6;
		newnp = inet6_sk(newsk);

		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		ipv6_addr_set(&newnp->daddr, 0, 0, htonl(0x0000FFFF),
			      newinet->daddr);

		ipv6_addr_set(&newnp->saddr, 0, 0, htonl(0x0000FFFF),
			      newinet->saddr);

		ipv6_addr_copy(&newnp->rcv_saddr, &newnp->saddr);
		newnp->saddr = newsk->sk_v6_rcv_saddr;

		inet_csk(newsk)->icsk_af_ops = &dccp_ipv6_mapped;
		newsk->sk_backlog_rcv = dccp_v4_do_rcv;
		newnp->pktoptions  = NULL;
		newnp->opt	   = NULL;
		newnp->ipv6_mc_list = NULL;
		newnp->ipv6_ac_list = NULL;
		newnp->ipv6_fl_list = NULL;
		newnp->mcast_oif   = inet_iif(skb);
		newnp->mcast_hops  = ip_hdr(skb)->ttl;

		/*
		 * No need to charge this sock to the relevant IPv6 refcnt debug socks count
		 * here, dccp_create_openreq_child now does this for us, see the comment in
		 * that function for the gory details. -acme
		 */

		/* It is tricky place. Until this moment IPv4 tcp
		   worked with IPv6 icsk.icsk_af_ops.
		   Sync it now.
		 */
		dccp_sync_mss(newsk, inet_csk(newsk)->icsk_pmtu_cookie);

		return newsk;
	}

	opt = np->opt;

	if (sk_acceptq_is_full(sk))
		goto out_overflow;

	if (dst == NULL) {
		struct in6_addr *final_p = NULL, final;
		struct flowi fl;

		memset(&fl, 0, sizeof(fl));
		fl.proto = IPPROTO_DCCP;
		ipv6_addr_copy(&fl.fl6_dst, &ireq6->rmt_addr);
		if (opt != NULL && opt->srcrt != NULL) {
			const struct rt0_hdr *rt0 = (struct rt0_hdr *)opt->srcrt;

			ipv6_addr_copy(&final, &fl.fl6_dst);
			ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
			final_p = &final;
		}
		ipv6_addr_copy(&fl.fl6_src, &ireq6->loc_addr);
		fl.oif = sk->sk_bound_dev_if;
		fl.fl_ip_dport = inet_rsk(req)->rmt_port;
		fl.fl_ip_sport = inet_sk(sk)->sport;
		security_sk_classify_flow(sk, &fl);

		if (ip6_dst_lookup(sk, &dst, &fl))
			goto out;

		if (final_p)
			ipv6_addr_copy(&fl.fl6_dst, final_p);

		if ((xfrm_lookup(&dst, &fl, sk, 0)) < 0)
	if (!dst) {
		struct flowi6 fl6;

		dst = inet6_csk_route_req(sk, &fl6, req, IPPROTO_DCCP);
		if (!dst)
			goto out;
	}

	newsk = dccp_create_openreq_child(sk, req, skb);
	if (newsk == NULL)
		goto out;
		goto out_nonewsk;

	/*
	 * No need to charge this sock to the relevant IPv6 refcnt debug socks
	 * count here, dccp_create_openreq_child now does this for us, see the
	 * comment in that function for the gory details. -acme
	 */

	__ip6_dst_store(newsk, dst, NULL, NULL);
	ip6_dst_store(newsk, dst, NULL, NULL);
	newsk->sk_route_caps = dst->dev->features & ~(NETIF_F_IP_CSUM |
						      NETIF_F_TSO);
	newdp6 = (struct dccp6_sock *)newsk;
	newinet = inet_sk(newsk);
	newinet->pinet6 = &newdp6->inet6;
	newdp = dccp_sk(newsk);
	newnp = inet6_sk(newsk);

	memcpy(newnp, np, sizeof(struct ipv6_pinfo));

	ipv6_addr_copy(&newnp->daddr, &ireq6->rmt_addr);
	ipv6_addr_copy(&newnp->saddr, &ireq6->loc_addr);
	ipv6_addr_copy(&newnp->rcv_saddr, &ireq6->loc_addr);
	newsk->sk_bound_dev_if = ireq6->iif;
	newsk->sk_v6_daddr	= ireq->ir_v6_rmt_addr;
	newnp->saddr		= ireq->ir_v6_loc_addr;
	newsk->sk_v6_rcv_saddr	= ireq->ir_v6_loc_addr;
	newsk->sk_bound_dev_if	= ireq->ir_iif;

	/* Now IPv6 options...

	   First: no IPv4 options.
	 */
	newinet->opt = NULL;
	newinet->inet_opt = NULL;

	/* Clone RX bits */
	newnp->rxopt.all = np->rxopt.all;

	/* Clone pktoptions received with SYN */
	newnp->pktoptions = NULL;
	if (ireq6->pktopts != NULL) {
		newnp->pktoptions = skb_clone(ireq6->pktopts, GFP_ATOMIC);
		kfree_skb(ireq6->pktopts);
		ireq6->pktopts = NULL;
		if (newnp->pktoptions)
			skb_set_owner_r(newnp->pktoptions, newsk);
	}
	newnp->ipv6_mc_list = NULL;
	newnp->ipv6_ac_list = NULL;
	newnp->ipv6_fl_list = NULL;
	newnp->pktoptions = NULL;
	newnp->opt	  = NULL;
	newnp->mcast_oif  = inet6_iif(skb);
	newnp->mcast_hops = ipv6_hdr(skb)->hop_limit;

	/*
	 * Clone native IPv6 options from listening socket (if any)
	 *
	 * Yes, keeping reference count would be much more clever, but we make
	 * one more one thing there: reattach optmem to newsk.
	 */
	if (opt != NULL) {
		newnp->opt = ipv6_dup_options(newsk, opt);
		if (opt != np->opt)
			sock_kfree_s(sk, opt, opt->tot_len);
	}

	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (newnp->opt != NULL)
		inet_csk(newsk)->icsk_ext_hdr_len = (newnp->opt->opt_nflen +
						     newnp->opt->opt_flen);

	dccp_sync_mss(newsk, dst_mtu(dst));

	newinet->daddr = newinet->saddr = newinet->rcv_saddr = LOOPBACK4_IPV6;

	__inet6_hash(newsk);
	__inet_inherit_port(sk, newsk);
	opt = rcu_dereference(np->opt);
	opt = ireq->ipv6_opt;
	if (!opt)
		opt = rcu_dereference(np->opt);
	if (opt) {
		opt = ipv6_dup_options(newsk, opt);
		RCU_INIT_POINTER(newnp->opt, opt);
	}
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (opt)
		inet_csk(newsk)->icsk_ext_hdr_len = opt->opt_nflen +
						    opt->opt_flen;

	dccp_sync_mss(newsk, dst_mtu(dst));

	newinet->inet_daddr = newinet->inet_saddr = LOOPBACK4_IPV6;
	newinet->inet_rcv_saddr = LOOPBACK4_IPV6;

	if (__inet_inherit_port(sk, newsk) < 0) {
		inet_csk_prepare_forced_close(newsk);
		dccp_done(newsk);
		goto out;
	}
	*own_req = inet_ehash_nolisten(newsk, req_to_sk(req_unhash));
	/* Clone pktoptions received with SYN, if we own the req */
	if (*own_req && ireq->pktopts) {
		newnp->pktoptions = skb_clone(ireq->pktopts, GFP_ATOMIC);
		consume_skb(ireq->pktopts);
		ireq->pktopts = NULL;
		if (newnp->pktoptions)
			skb_set_owner_r(newnp->pktoptions, newsk);
	}

	return newsk;

out_overflow:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
out:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	if (opt != NULL && opt != np->opt)
		sock_kfree_s(sk, opt, opt->tot_len);
	dst_release(dst);
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
out_nonewsk:
	dst_release(dst);
out:
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return NULL;
}

/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
static int dccp_v6_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *opt_skb = NULL;

	/* Imagine: socket is IPv6. IPv4 packet arrives,
	   goes to IPv4 receive handler and backlogged.
	   From backlog it always goes here. Kerboom...
	   Fortunately, dccp_rcv_established and rcv_established
	   handle them correctly, but it is not case with
	   dccp_v6_hnd_req and dccp_v6_ctl_send_reset().   --ANK
	 */

	if (skb->protocol == htons(ETH_P_IP))
		return dccp_v4_do_rcv(sk, skb);

	if (sk_filter(sk, skb))
		goto discard;

	/*
	 * socket locking is here for SMP purposes as backlog rcv is currently
	 * called with bh processing disabled.
	 */

	/* Do Stevens' IPV6_PKTOPTIONS.

	   Yes, guys, it is the only place in our code, where we
	   may make it not affecting IPv4.
	   The rest of code is protocol independent,
	   and I do not like idea to uglify IPv4.

	   Actually, all the idea behind IPV6_PKTOPTIONS
	   looks not very well thought. For now we latch
	   options, received in the last packet, enqueued
	   by tcp. Feel free to propose better solution.
					       --ANK (980728)
	 */
	if (np->rxopt.all)
		opt_skb = skb_clone(skb, GFP_ATOMIC);

	if (sk->sk_state == DCCP_OPEN) { /* Fast path */
		if (dccp_rcv_established(sk, skb, dccp_hdr(skb), skb->len))
			goto reset;
		if (opt_skb)
			goto ipv6_pktoptions;
		return 0;
	}

	/*
	 *  Step 3: Process LISTEN state
	 *     If S.state == LISTEN,
	 *	 If P.type == Request or P contains a valid Init Cookie option,
	 *	      (* Must scan the packet's options to check for Init
	 *		 Cookies.  Only Init Cookies are processed here,
	 *		 however; other options are processed in Step 8.  This
	 *		 scan need only be performed if the endpoint uses Init
	 *		 Cookies *)
	 *	      (* Generate a new socket and switch to that socket *)
	 *	      Set S := new socket for this port pair
	 *	      S.state = RESPOND
	 *	      Choose S.ISS (initial seqno) or set from Init Cookies
	 *	      Initialize S.GAR := S.ISS
	 *	      Set S.ISR, S.GSR, S.SWL, S.SWH from packet or Init Cookies
	 *	      Continue with S.state == RESPOND
	 *	      (* A Response packet will be generated in Step 11 *)
	 *	 Otherwise,
	 *	      Generate Reset(No Connection) unless P.type == Reset
	 *	      Drop packet and return
	 *
	 * NOTE: the check for the packet types is done in
	 *	 dccp_rcv_state_process
	 */
	if (sk->sk_state == DCCP_LISTEN) {
		struct sock *nsk = dccp_v6_hnd_req(sk, skb);

		if (nsk == NULL)
			goto discard;
		/*
		 * Queue it on the new socket if the new socket is active,
		 * otherwise we just shortcircuit this and continue with
		 * the new socket..
		 */
		if (nsk != sk) {
			if (dccp_child_process(sk, nsk, skb))
				goto reset;
			if (opt_skb != NULL)
				__kfree_skb(opt_skb);
			return 0;
		}
	}

	if (dccp_rcv_state_process(sk, skb, dccp_hdr(skb), skb->len))
		goto reset;
	if (opt_skb)
		goto ipv6_pktoptions;
	return 0;

reset:
	dccp_v6_ctl_send_reset(sk, skb);
discard:
	if (opt_skb != NULL)
		__kfree_skb(opt_skb);
	kfree_skb(skb);
	return 0;

/* Handling IPV6_PKTOPTIONS skb the similar
 * way it's done for net/ipv6/tcp_ipv6.c
 */
ipv6_pktoptions:
	if (!((1 << sk->sk_state) & (DCCPF_CLOSED | DCCPF_LISTEN))) {
		if (np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo)
			np->mcast_oif = inet6_iif(opt_skb);
		if (np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim)
			np->mcast_hops = ipv6_hdr(opt_skb)->hop_limit;
		if (np->rxopt.bits.rxflow || np->rxopt.bits.rxtclass)
			np->rcv_flowinfo = ip6_flowinfo(ipv6_hdr(opt_skb));
		if (np->repflow)
			np->flow_label = ip6_flowlabel(ipv6_hdr(opt_skb));
		if (ipv6_opt_accepted(sk, opt_skb,
				      &DCCP_SKB_CB(opt_skb)->header.h6)) {
			skb_set_owner_r(opt_skb, sk);
			memmove(IP6CB(opt_skb),
				&DCCP_SKB_CB(opt_skb)->header.h6,
				sizeof(struct inet6_skb_parm));
			opt_skb = xchg(&np->pktoptions, opt_skb);
		} else {
			__kfree_skb(opt_skb);
			opt_skb = xchg(&np->pktoptions, NULL);
		}
	}

	kfree_skb(opt_skb);
	return 0;
}

static int dccp_v6_rcv(struct sk_buff *skb)
{
	const struct dccp_hdr *dh;
	bool refcounted;
	struct sock *sk;
	int min_cov;

	/* Step 1: Check header basics */

	if (dccp_invalid_packet(skb))
		goto discard_it;

	/* Step 1: If header checksum is incorrect, drop packet and return. */
	if (dccp_v6_csum_finish(skb, &ipv6_hdr(skb)->saddr,
				     &ipv6_hdr(skb)->daddr)) {
		DCCP_WARN("dropped packet with invalid checksum\n");
		goto discard_it;
	}

	dh = dccp_hdr(skb);

	DCCP_SKB_CB(skb)->dccpd_seq  = dccp_hdr_seq(dh);
	DCCP_SKB_CB(skb)->dccpd_type = dh->dccph_type;

	if (dccp_packet_without_ack(skb))
		DCCP_SKB_CB(skb)->dccpd_ack_seq = DCCP_PKT_WITHOUT_ACK_SEQ;
	else
		DCCP_SKB_CB(skb)->dccpd_ack_seq = dccp_hdr_ack_seq(skb);

	/* Step 2:
	 *	Look up flow ID in table and get corresponding socket */
	sk = __inet6_lookup(dev_net(skb->dst->dev), &dccp_hashinfo,
			    &ipv6_hdr(skb)->saddr, dh->dccph_sport,
			    &ipv6_hdr(skb)->daddr, ntohs(dh->dccph_dport),
			    inet6_iif(skb));
	/*
	 * Step 2:
	 *	If no socket ...
	 */
	if (sk == NULL) {
lookup:
	sk = __inet6_lookup_skb(&dccp_hashinfo, skb, __dccp_hdr_len(dh),
			        dh->dccph_sport, dh->dccph_dport,
				inet6_iif(skb), 0, &refcounted);
	if (!sk) {
		dccp_pr_debug("failed to look up flow ID in table and "
			      "get corresponding socket\n");
		goto no_dccp_socket;
	}

	/*
	 * Step 2:
	 *	... or S.state == TIMEWAIT,
	 *		Generate Reset(No Connection) unless P.type == Reset
	 *		Drop packet and return
	 */
	if (sk->sk_state == DCCP_TIME_WAIT) {
		dccp_pr_debug("sk->sk_state == DCCP_TIME_WAIT: do_time_wait\n");
		inet_twsk_put(inet_twsk(sk));
		goto no_dccp_socket;
	}

	if (sk->sk_state == DCCP_NEW_SYN_RECV) {
		struct request_sock *req = inet_reqsk(sk);
		struct sock *nsk;

		sk = req->rsk_listener;
		if (unlikely(sk->sk_state != DCCP_LISTEN)) {
			inet_csk_reqsk_queue_drop_and_put(sk, req);
			goto lookup;
		}
		sock_hold(sk);
		refcounted = true;
		nsk = dccp_check_req(sk, skb, req);
		if (!nsk) {
			reqsk_put(req);
			goto discard_and_relse;
		}
		if (nsk == sk) {
			reqsk_put(req);
		} else if (dccp_child_process(sk, nsk, skb)) {
			dccp_v6_ctl_send_reset(sk, skb);
			goto discard_and_relse;
		} else {
			sock_put(sk);
			return 0;
		}
	}
	/*
	 * RFC 4340, sec. 9.2.1: Minimum Checksum Coverage
	 *	o if MinCsCov = 0, only packets with CsCov = 0 are accepted
	 *	o if MinCsCov > 0, also accept packets with CsCov >= MinCsCov
	 */
	min_cov = dccp_sk(sk)->dccps_pcrlen;
	if (dh->dccph_cscov  &&  (min_cov == 0 || dh->dccph_cscov < min_cov))  {
		dccp_pr_debug("Packet CsCov %d does not satisfy MinCsCov %d\n",
			      dh->dccph_cscov, min_cov);
		/* FIXME: send Data Dropped option (see also dccp_v4_rcv) */
		goto discard_and_relse;
	}

	if (!xfrm6_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_relse;

	return __sk_receive_skb(sk, skb, 1, dh->dccph_doff * 4,
				refcounted) ? -1 : 0;

no_dccp_socket:
	if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;
	/*
	 * Step 2:
	 *	If no socket ...
	 *		Generate Reset(No Connection) unless P.type == Reset
	 *		Drop packet and return
	 */
	if (dh->dccph_type != DCCP_PKT_RESET) {
		DCCP_SKB_CB(skb)->dccpd_reset_code =
					DCCP_RESET_CODE_NO_CONNECTION;
		dccp_v6_ctl_send_reset(sk, skb);
	}

discard_it:
	kfree_skb(skb);
	return 0;

discard_and_relse:
	if (refcounted)
		sock_put(sk);
	goto discard_it;
}

static int dccp_v6_connect(struct sock *sk, struct sockaddr *uaddr,
			   int addr_len)
{
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *)uaddr;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	struct in6_addr *saddr = NULL, *final_p = NULL, final;
	struct flowi fl;
	struct in6_addr *saddr = NULL, *final_p, final;
	struct ipv6_txoptions *opt;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int addr_type;
	int err;

	dp->dccps_role = DCCP_ROLE_CLIENT;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	if (usin->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	memset(&fl, 0, sizeof(fl));

	if (np->sndflow) {
		fl.fl6_flowlabel = usin->sin6_flowinfo & IPV6_FLOWINFO_MASK;
		IP6_ECN_flow_init(fl.fl6_flowlabel);
		if (fl.fl6_flowlabel & IPV6_FLOWLABEL_MASK) {
			struct ip6_flowlabel *flowlabel;
			flowlabel = fl6_sock_lookup(sk, fl.fl6_flowlabel);
			if (flowlabel == NULL)
				return -EINVAL;
			ipv6_addr_copy(&usin->sin6_addr, &flowlabel->dst);
	memset(&fl6, 0, sizeof(fl6));

	if (np->sndflow) {
		fl6.flowlabel = usin->sin6_flowinfo & IPV6_FLOWINFO_MASK;
		IP6_ECN_flow_init(fl6.flowlabel);
		if (fl6.flowlabel & IPV6_FLOWLABEL_MASK) {
			struct ip6_flowlabel *flowlabel;
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (flowlabel == NULL)
				return -EINVAL;
			fl6_sock_release(flowlabel);
		}
	}
	/*
	 * connect() to INADDR_ANY means loopback (BSD'ism).
	 */
	if (ipv6_addr_any(&usin->sin6_addr))
		usin->sin6_addr.s6_addr[15] = 1;

	addr_type = ipv6_addr_type(&usin->sin6_addr);

	if (addr_type & IPV6_ADDR_MULTICAST)
		return -ENETUNREACH;

	if (addr_type & IPV6_ADDR_LINKLOCAL) {
		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    usin->sin6_scope_id) {
			/* If interface is set while binding, indices
			 * must coincide.
			 */
			if (sk->sk_bound_dev_if &&
			    sk->sk_bound_dev_if != usin->sin6_scope_id)
				return -EINVAL;

			sk->sk_bound_dev_if = usin->sin6_scope_id;
		}

		/* Connect to link-local address requires an interface */
		if (!sk->sk_bound_dev_if)
			return -EINVAL;
	}

	ipv6_addr_copy(&np->daddr, &usin->sin6_addr);
	np->flow_label = fl.fl6_flowlabel;
	sk->sk_v6_daddr = usin->sin6_addr;
	np->flow_label = fl6.flowlabel;

	/*
	 * DCCP over IPv4
	 */
	if (addr_type == IPV6_ADDR_MAPPED) {
		u32 exthdrlen = icsk->icsk_ext_hdr_len;
		struct sockaddr_in sin;

		SOCK_DEBUG(sk, "connect: ipv4 mapped\n");

		if (__ipv6_only_sock(sk))
			return -ENETUNREACH;

		sin.sin_family = AF_INET;
		sin.sin_port = usin->sin6_port;
		sin.sin_addr.s_addr = usin->sin6_addr.s6_addr32[3];

		icsk->icsk_af_ops = &dccp_ipv6_mapped;
		sk->sk_backlog_rcv = dccp_v4_do_rcv;

		err = dccp_v4_connect(sk, (struct sockaddr *)&sin, sizeof(sin));
		if (err) {
			icsk->icsk_ext_hdr_len = exthdrlen;
			icsk->icsk_af_ops = &dccp_ipv6_af_ops;
			sk->sk_backlog_rcv = dccp_v6_do_rcv;
			goto failure;
		} else {
			ipv6_addr_set(&np->saddr, 0, 0, htonl(0x0000FFFF),
				      inet->saddr);
			ipv6_addr_set(&np->rcv_saddr, 0, 0, htonl(0x0000FFFF),
				      inet->rcv_saddr);
		}

		return err;
	}

	if (!ipv6_addr_any(&np->rcv_saddr))
		saddr = &np->rcv_saddr;

	fl.proto = IPPROTO_DCCP;
	ipv6_addr_copy(&fl.fl6_dst, &np->daddr);
	ipv6_addr_copy(&fl.fl6_src, saddr ? saddr : &np->saddr);
	fl.oif = sk->sk_bound_dev_if;
	fl.fl_ip_dport = usin->sin6_port;
	fl.fl_ip_sport = inet->sport;
	security_sk_classify_flow(sk, &fl);

	if (np->opt != NULL && np->opt->srcrt != NULL) {
		const struct rt0_hdr *rt0 = (struct rt0_hdr *)np->opt->srcrt;

		ipv6_addr_copy(&final, &fl.fl6_dst);
		ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
		final_p = &final;
	}

	err = ip6_dst_lookup(sk, &dst, &fl);
	if (err)
		goto failure;

	if (final_p)
		ipv6_addr_copy(&fl.fl6_dst, final_p);

	err = __xfrm_lookup(&dst, &fl, sk, XFRM_LOOKUP_WAIT);
	if (err < 0) {
		if (err == -EREMOTE)
			err = ip6_dst_blackhole(sk, &dst, &fl);
		if (err < 0)
			goto failure;
	}

	if (saddr == NULL) {
		saddr = &fl.fl6_src;
		ipv6_addr_copy(&np->rcv_saddr, saddr);
	}

	/* set the source address */
	ipv6_addr_copy(&np->saddr, saddr);
	inet->rcv_saddr = LOOPBACK4_IPV6;

	__ip6_dst_store(sk, dst, NULL, NULL);

	icsk->icsk_ext_hdr_len = 0;
	if (np->opt != NULL)
		icsk->icsk_ext_hdr_len = (np->opt->opt_flen +
					  np->opt->opt_nflen);

	inet->dport = usin->sin6_port;
		}
		np->saddr = sk->sk_v6_rcv_saddr;
		return err;
	}

	if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr))
		saddr = &sk->sk_v6_rcv_saddr;

	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.daddr = sk->sk_v6_daddr;
	fl6.saddr = saddr ? *saddr : np->saddr;
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.fl6_dport = usin->sin6_port;
	fl6.fl6_sport = inet->inet_sport;
	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	opt = rcu_dereference_protected(np->opt, lockdep_sock_is_held(sk));
	final_p = fl6_update_dst(&fl6, opt, &final);

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto failure;
	}

	if (saddr == NULL) {
		saddr = &fl6.saddr;
		sk->sk_v6_rcv_saddr = *saddr;
	}

	/* set the source address */
	np->saddr = *saddr;
	inet->inet_rcv_saddr = LOOPBACK4_IPV6;

	ip6_dst_store(sk, dst, NULL, NULL);

	icsk->icsk_ext_hdr_len = 0;
	if (opt)
		icsk->icsk_ext_hdr_len = opt->opt_flen + opt->opt_nflen;

	inet->inet_dport = usin->sin6_port;

	dccp_set_state(sk, DCCP_REQUESTING);
	err = inet6_hash_connect(&dccp_death_row, sk);
	if (err)
		goto late_failure;

	dp->dccps_iss = secure_dccpv6_sequence_number(np->saddr.s6_addr32,
						      np->daddr.s6_addr32,
						      inet->sport, inet->dport);
						      sk->sk_v6_daddr.s6_addr32,
						      inet->inet_sport,
						      inet->inet_dport);
	err = dccp_connect(sk);
	if (err)
		goto late_failure;

	return 0;

late_failure:
	dccp_set_state(sk, DCCP_CLOSED);
	__sk_dst_reset(sk);
failure:
	inet->dport = 0;
	inet->inet_dport = 0;
	sk->sk_route_caps = 0;
	return err;
}

static struct inet_connection_sock_af_ops dccp_ipv6_af_ops = {
static const struct inet_connection_sock_af_ops dccp_ipv6_af_ops = {
	.queue_xmit	   = inet6_csk_xmit,
	.send_check	   = dccp_v6_send_check,
	.rebuild_header	   = inet6_sk_rebuild_header,
	.conn_request	   = dccp_v6_conn_request,
	.syn_recv_sock	   = dccp_v6_request_recv_sock,
	.net_header_len	   = sizeof(struct ipv6hdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

/*
 *	DCCP over IPv4 via INET6 API
 */
static struct inet_connection_sock_af_ops dccp_ipv6_mapped = {
static const struct inet_connection_sock_af_ops dccp_ipv6_mapped = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = dccp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.conn_request	   = dccp_v6_conn_request,
	.syn_recv_sock	   = dccp_v6_request_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
static int dccp_v6_init_sock(struct sock *sk)
{
	static __u8 dccp_v6_ctl_sock_initialized;
	int err = dccp_init_sock(sk, dccp_v6_ctl_sock_initialized);

	if (err == 0) {
		if (unlikely(!dccp_v6_ctl_sock_initialized))
			dccp_v6_ctl_sock_initialized = 1;
		inet_csk(sk)->icsk_af_ops = &dccp_ipv6_af_ops;
	}

	return err;
}

static void dccp_v6_destroy_sock(struct sock *sk)
{
	dccp_destroy_sock(sk);
	inet6_destroy_sock(sk);
}

static struct timewait_sock_ops dccp6_timewait_sock_ops = {
	.twsk_obj_size	= sizeof(struct dccp6_timewait_sock),
};

static struct proto dccp_v6_prot = {
	.name		   = "DCCPv6",
	.owner		   = THIS_MODULE,
	.close		   = dccp_close,
	.connect	   = dccp_v6_connect,
	.disconnect	   = dccp_disconnect,
	.ioctl		   = dccp_ioctl,
	.init		   = dccp_v6_init_sock,
	.setsockopt	   = dccp_setsockopt,
	.getsockopt	   = dccp_getsockopt,
	.sendmsg	   = dccp_sendmsg,
	.recvmsg	   = dccp_recvmsg,
	.backlog_rcv	   = dccp_v6_do_rcv,
	.hash		   = dccp_v6_hash,
	.hash		   = inet_hash,
	.hash		   = inet6_hash,
	.unhash		   = inet_unhash,
	.accept		   = inet_csk_accept,
	.get_port	   = inet_csk_get_port,
	.shutdown	   = dccp_shutdown,
	.destroy	   = dccp_v6_destroy_sock,
	.orphan_count	   = &dccp_orphan_count,
	.max_header	   = MAX_DCCP_HEADER,
	.obj_size	   = sizeof(struct dccp6_sock),
	.slab_flags	   = SLAB_TYPESAFE_BY_RCU,
	.rsk_prot	   = &dccp6_request_sock_ops,
	.twsk_prot	   = &dccp6_timewait_sock_ops,
	.h.hashinfo	   = &dccp_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_dccp_setsockopt,
	.compat_getsockopt = compat_dccp_getsockopt,
#endif
};

static struct inet6_protocol dccp_v6_protocol = {
static const struct inet6_protocol dccp_v6_protocol = {
	.handler	= dccp_v6_rcv,
	.err_handler	= dccp_v6_err,
	.flags		= INET6_PROTO_NOPOLICY | INET6_PROTO_FINAL,
};

static struct proto_ops inet6_dccp_ops = {
static const struct proto_ops inet6_dccp_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = inet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet6_getname,
	.poll		   = dccp_poll,
	.ioctl		   = inet6_ioctl,
	.listen		   = inet_dccp_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

static struct inet_protosw dccp_v6_protosw = {
	.type		= SOCK_DCCP,
	.protocol	= IPPROTO_DCCP,
	.prot		= &dccp_v6_prot,
	.ops		= &inet6_dccp_ops,
	.capability	= -1,
	.flags		= INET_PROTOSW_ICSK,
};

static int dccp_v6_init_net(struct net *net)
{
	int err;

	err = inet_ctl_sock_create(&net->dccp.v6_ctl_sk, PF_INET6,
				   SOCK_DCCP, IPPROTO_DCCP, net);
	return err;
}

static void dccp_v6_exit_net(struct net *net)
	.flags		= INET_PROTOSW_ICSK,
};

static int __net_init dccp_v6_init_net(struct net *net)
{
	if (dccp_hashinfo.bhash == NULL)
		return -ESOCKTNOSUPPORT;

	return inet_ctl_sock_create(&net->dccp.v6_ctl_sk, PF_INET6,
				    SOCK_DCCP, IPPROTO_DCCP, net);
}

static void __net_exit dccp_v6_exit_net(struct net *net)
{
	inet_ctl_sock_destroy(net->dccp.v6_ctl_sk);
}

static void __net_exit dccp_v6_exit_batch(struct list_head *net_exit_list)
{
	inet_twsk_purge(&dccp_hashinfo, AF_INET6);
}

static struct pernet_operations dccp_v6_ops = {
	.init   = dccp_v6_init_net,
	.exit   = dccp_v6_exit_net,
	.exit_batch = dccp_v6_exit_batch,
};

static int __init dccp_v6_init(void)
{
	int err = proto_register(&dccp_v6_prot, 1);

	if (err)
		goto out;

	inet6_register_protosw(&dccp_v6_protosw);

	err = register_pernet_subsys(&dccp_v6_ops);
	if (err)
		goto out_destroy_ctl_sock;

	err = inet6_add_protocol(&dccp_v6_protocol, IPPROTO_DCCP);
	if (err)
		goto out_unregister_proto;

out:
	return err;
out_unregister_proto:
	unregister_pernet_subsys(&dccp_v6_ops);
out_destroy_ctl_sock:
	inet6_unregister_protosw(&dccp_v6_protosw);
	proto_unregister(&dccp_v6_prot);
	goto out;
}

static void __exit dccp_v6_exit(void)
{
	inet6_del_protocol(&dccp_v6_protocol, IPPROTO_DCCP);
	unregister_pernet_subsys(&dccp_v6_ops);
	inet6_unregister_protosw(&dccp_v6_protosw);
	proto_unregister(&dccp_v6_prot);
}

module_init(dccp_v6_init);
module_exit(dccp_v6_exit);

/*
 * __stringify doesn't likes enums, so use SOCK_DCCP (6) and IPPROTO_DCCP (33)
 * values directly, Also cover the case where the protocol is not specified,
 * i.e. net-pf-PF_INET6-proto-0-type-SOCK_DCCP
 */
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_INET6, 33, 6);
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_INET6, 0, 6);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnaldo Carvalho de Melo <acme@mandriva.com>");
MODULE_DESCRIPTION("DCCPv6 - Datagram Congestion Controlled Protocol");
