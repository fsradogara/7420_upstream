/*
 *  Syncookies implementation for the Linux kernel
 *
 *  Copyright (C) 1997 Andi Kleen
 *  Based on ideas by D.J.Bernstein and Eric Schenk.
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/kernel.h>
#include <net/tcp.h>

/* Timestamps: lowest 9 bits store TCP options */
#define TSBITS 9
#define TSMASK (((__u32)1 << TSBITS) - 1)

extern int sysctl_tcp_syncookies;

__u32 syncookie_secret[2][16-4+SHA_DIGEST_WORDS];
EXPORT_SYMBOL(syncookie_secret);

static __init int init_syncookies(void)
{
	get_random_bytes(syncookie_secret, sizeof(syncookie_secret));
	return 0;
}
__initcall(init_syncookies);
#include <linux/export.h>
#include <net/secure_seq.h>
#include <net/tcp.h>
#include <net/route.h>

static siphash_key_t syncookie_secret[2] __read_mostly;

#define COOKIEBITS 24	/* Upper bits store count */
#define COOKIEMASK (((__u32)1 << COOKIEBITS) - 1)

static DEFINE_PER_CPU(__u32, cookie_scratch)[16 + 5 + SHA_WORKSPACE_WORDS];
/* TCP Timestamp: 6 lowest bits of timestamp sent in the cookie SYN-ACK
 * stores TCP options:
 *
 * MSB                               LSB
 * | 31 ...   6 |  5  |  4   | 3 2 1 0 |
 * |  Timestamp | ECN | SACK | WScale  |
 *
 * When we receive a valid cookie-ACK, we look at the echoed tsval (if
 * any) to figure out which TCP options we should use for the rebuilt
 * connection.
 *
 * A WScale setting of '0xf' (which is an invalid scaling value)
 * means that original syn did not include the TCP window scaling option.
 */
#define TS_OPT_WSCALE_MASK	0xf
#define TS_OPT_SACK		BIT(4)
#define TS_OPT_ECN		BIT(5)
/* There is no TS_OPT_TIMESTAMP:
 * if ACK contains timestamp option, we already know it was
 * requested/supported by the syn/synack exchange.
 */
#define TSBITS	6
#define TSMASK	(((__u32)1 << TSBITS) - 1)

static u32 cookie_hash(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
		       u32 count, int c)
{
	__u32 *tmp = __get_cpu_var(cookie_scratch);

	__u32 *tmp;

	net_get_random_once(syncookie_secret, sizeof(syncookie_secret));
	return siphash_4u32((__force u32)saddr, (__force u32)daddr,
			    (__force u32)sport << 16 | (__force u32)dport,
			    count, &syncookie_secret[c]);
}


/*
 * when syncookies are in effect and tcp timestamps are enabled we encode
 * tcp options in the lowest 9 bits of the timestamp value that will be
 * tcp options in the lower bits of the timestamp value that will be
 * sent in the syn-ack.
 * Since subsequent timestamps use the normal tcp_time_stamp value, we
 * must make sure that the resulting initial timestamp is <= tcp_time_stamp.
 */
u64 cookie_init_timestamp(struct request_sock *req)
{
	struct inet_request_sock *ireq;
	u32 ts, ts_now = tcp_time_stamp_raw();
	u32 options = 0;

	ireq = inet_rsk(req);
	if (ireq->wscale_ok) {
		options = ireq->snd_wscale;
		options |= ireq->rcv_wscale << 4;
	}
	options |= ireq->sack_ok << 8;

	options = ireq->wscale_ok ? ireq->snd_wscale : TS_OPT_WSCALE_MASK;
	if (ireq->sack_ok)
		options |= TS_OPT_SACK;
	if (ireq->ecn_ok)
		options |= TS_OPT_ECN;

	ts = ts_now & ~TSMASK;
	ts |= options;
	if (ts > ts_now) {
		ts >>= TSBITS;
		ts--;
		ts <<= TSBITS;
		ts |= options;
	}
	return (u64)ts * (USEC_PER_SEC / TCP_TS_HZ);
}


static __u32 secure_tcp_syn_cookie(__be32 saddr, __be32 daddr, __be16 sport,
				   __be16 dport, __u32 sseq, __u32 count,
				   __u32 data)
				   __be16 dport, __u32 sseq, __u32 data)
{
	/*
	 * Compute the secure sequence number.
	 * The output should be:
	 *   HASH(sec1,saddr,sport,daddr,dport,sec1) + sseq + (count * 2^24)
	 *      + (HASH(sec2,saddr,sport,daddr,dport,count,sec2) % 2^24).
	 * Where sseq is their sequence number and count increases every
	 * minute by 1.
	 * As an extra hack, we add a small "data" value that encodes the
	 * MSS into the second hash value.
	 */

	u32 count = tcp_cookie_time();
	return (cookie_hash(saddr, daddr, sport, dport, 0, 0) +
		sseq + (count << COOKIEBITS) +
		((cookie_hash(saddr, daddr, sport, dport, count, 1) + data)
		 & COOKIEMASK));
}

/*
 * This retrieves the small "data" value from the syncookie.
 * If the syncookie is bad, the data returned will be out of
 * range.  This must be checked by the caller.
 *
 * The count value used to generate the cookie must be within
 * "maxdiff" if the current (passed-in) "count".  The return value
 * is (__u32)-1 if this test fails.
 */
static __u32 check_tcp_syn_cookie(__u32 cookie, __be32 saddr, __be32 daddr,
				  __be16 sport, __be16 dport, __u32 sseq,
				  __u32 count, __u32 maxdiff)
{
	__u32 diff;
 * The count value used to generate the cookie must be less than
 * MAX_SYNCOOKIE_AGE minutes in the past.
 * The return value (__u32)-1 if this test fails.
 */
static __u32 check_tcp_syn_cookie(__u32 cookie, __be32 saddr, __be32 daddr,
				  __be16 sport, __be16 dport, __u32 sseq)
{
	u32 diff, count = tcp_cookie_time();

	/* Strip away the layers from the cookie */
	cookie -= cookie_hash(saddr, daddr, sport, dport, 0, 0) + sseq;

	/* Cookie is now reduced to (count * 2^24) ^ (hash % 2^24) */
	diff = (count - (cookie >> COOKIEBITS)) & ((__u32) - 1 >> COOKIEBITS);
	if (diff >= maxdiff)
	diff = (count - (cookie >> COOKIEBITS)) & ((__u32) -1 >> COOKIEBITS);
	if (diff >= MAX_SYNCOOKIE_AGE)
		return (__u32)-1;

	return (cookie -
		cookie_hash(saddr, daddr, sport, dport, count - diff, 1))
		& COOKIEMASK;	/* Leaving the data behind */
}

/*
 * This table has to be sorted and terminated with (__u16)-1.
 * XXX generate a better table.
 * Unresolved Issues: HIPPI with a 64k MSS is not well supported.
 */
static __u16 const msstab[] = {
	64 - 1,
	256 - 1,
	512 - 1,
	536 - 1,
	1024 - 1,
	1440 - 1,
	1460 - 1,
	4312 - 1,
	(__u16)-1
};
/* The number doesn't include the -1 terminator */
#define NUM_MSS (ARRAY_SIZE(msstab) - 1)
 * MSS Values are chosen based on the 2011 paper
 * 'An Analysis of TCP Maximum Segement Sizes' by S. Alcock and R. Nelson.
 * Values ..
 *  .. lower than 536 are rare (< 0.2%)
 *  .. between 537 and 1299 account for less than < 1.5% of observed values
 *  .. in the 1300-1349 range account for about 15 to 20% of observed mss values
 *  .. exceeding 1460 are very rare (< 0.04%)
 *
 *  1460 is the single most frequently announced mss value (30 to 46% depending
 *  on monitor location).  Table must be sorted.
 */
static __u16 const msstab[] = {
	536,
	1300,
	1440,	/* 1440, 1452: PPPoE */
	1460,
};

/*
 * Generate a syncookie.  mssp points to the mss, which is returned
 * rounded down to the value encoded in the cookie.
 */
__u32 cookie_v4_init_sequence(struct sock *sk, struct sk_buff *skb, __u16 *mssp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);
	int mssind;
	const __u16 mss = *mssp;

	tp->last_synq_overflow = jiffies;

	/* XXX sort msstab[] by probability?  Binary search? */
	for (mssind = 0; mss > msstab[mssind + 1]; mssind++)
		;
	*mssp = msstab[mssind] + 1;

	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_SYNCOOKIESSENT);

	return secure_tcp_syn_cookie(iph->saddr, iph->daddr,
				     th->source, th->dest, ntohl(th->seq),
				     jiffies / (HZ * 60), mssind);
}

/*
 * This (misnamed) value is the age of syncookie which is permitted.
 * Its ideal value should be dependent on TCP_TIMEOUT_INIT and
 * sysctl_tcp_retries1. It's a rather complicated formula (exponential
 * backoff) to compute at runtime so it's currently hardcoded here.
 */
#define COUNTER_TRIES 4
/*
 * Check if a ack sequence number is a valid syncookie.
 * Return the decoded mss if it is, or 0 if not.
 */
static inline int cookie_check(struct sk_buff *skb, __u32 cookie)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);
	__u32 seq = ntohl(th->seq) - 1;
	__u32 mssind = check_tcp_syn_cookie(cookie, iph->saddr, iph->daddr,
					    th->source, th->dest, seq,
					    jiffies / (HZ * 60),
					    COUNTER_TRIES);

	return mssind < NUM_MSS ? msstab[mssind] + 1 : 0;
}

static inline struct sock *get_cookie_sock(struct sock *sk, struct sk_buff *skb,
					   struct request_sock *req,
					   struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sock *child;

	child = icsk->icsk_af_ops->syn_recv_sock(sk, skb, req, dst);
	if (child)
		inet_csk_reqsk_queue_add(sk, req, child);
	else
		reqsk_free(req);

	return child;
}

u32 __cookie_v4_init_sequence(const struct iphdr *iph, const struct tcphdr *th,
			      u16 *mssp)
{
	int mssind;
	const __u16 mss = *mssp;

	for (mssind = ARRAY_SIZE(msstab) - 1; mssind ; mssind--)
		if (mss >= msstab[mssind])
			break;
	*mssp = msstab[mssind];

	return secure_tcp_syn_cookie(iph->saddr, iph->daddr,
				     th->source, th->dest, ntohl(th->seq),
				     mssind);
}
EXPORT_SYMBOL_GPL(__cookie_v4_init_sequence);

__u32 cookie_v4_init_sequence(const struct sk_buff *skb, __u16 *mssp)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);

	return __cookie_v4_init_sequence(iph, th, mssp);
}

/*
 * Check if a ack sequence number is a valid syncookie.
 * Return the decoded mss if it is, or 0 if not.
 */
int __cookie_v4_check(const struct iphdr *iph, const struct tcphdr *th,
		      u32 cookie)
{
	__u32 seq = ntohl(th->seq) - 1;
	__u32 mssind = check_tcp_syn_cookie(cookie, iph->saddr, iph->daddr,
					    th->source, th->dest, seq);

	return mssind < ARRAY_SIZE(msstab) ? msstab[mssind] : 0;
}
EXPORT_SYMBOL_GPL(__cookie_v4_check);

struct sock *tcp_get_cookie_sock(struct sock *sk, struct sk_buff *skb,
				 struct request_sock *req,
				 struct dst_entry *dst, u32 tsoff)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sock *child;
	bool own_req;

	child = icsk->icsk_af_ops->syn_recv_sock(sk, skb, req, dst,
						 NULL, &own_req);
	if (child) {
		refcount_set(&req->rsk_refcnt, 1);
		tcp_sk(child)->tsoffset = tsoff;
		sock_rps_save_rxhash(child, skb);
		inet_csk_reqsk_queue_add(sk, req, child);
	} else {
		reqsk_free(req);
	}
	return child;
}
EXPORT_SYMBOL(tcp_get_cookie_sock);

/*
 * when syncookies are in effect and tcp timestamps are enabled we stored
 * additional tcp options in the timestamp.
 * This extracts these options from the timestamp echo.
 *
 * The lowest 4 bits are for snd_wscale
 * The next 4 lsb are for rcv_wscale
 * The next lsb is for sack_ok
 */
void cookie_check_timestamp(struct tcp_options_received *tcp_opt)
{
	/* echoed timestamp, 9 lowest bits contain options */
	u32 options = tcp_opt->rcv_tsecr & TSMASK;

	tcp_opt->snd_wscale = options & 0xf;
	options >>= 4;
	tcp_opt->rcv_wscale = options & 0xf;

	tcp_opt->sack_ok = (options >> 4) & 0x1;

	if (tcp_opt->sack_ok)
		tcp_sack_reset(tcp_opt);

	if (tcp_opt->snd_wscale || tcp_opt->rcv_wscale)
		tcp_opt->wscale_ok = 1;
}
EXPORT_SYMBOL(cookie_check_timestamp);

struct sock *cookie_v4_check(struct sock *sk, struct sk_buff *skb,
			     struct ip_options *opt)
{
 * return false if we decode a tcp option that is disabled
 * on the host.
 */
bool cookie_timestamp_decode(const struct net *net,
			     struct tcp_options_received *tcp_opt)
{
	/* echoed timestamp, lowest bits contain options */
	u32 options = tcp_opt->rcv_tsecr;

	if (!tcp_opt->saw_tstamp)  {
		tcp_clear_options(tcp_opt);
		return true;
	}

	if (!net->ipv4.sysctl_tcp_timestamps)
		return false;

	tcp_opt->sack_ok = (options & TS_OPT_SACK) ? TCP_SACK_SEEN : 0;

	if (tcp_opt->sack_ok && !net->ipv4.sysctl_tcp_sack)
		return false;

	if ((options & TS_OPT_WSCALE_MASK) == TS_OPT_WSCALE_MASK)
		return true; /* no window scaling */

	tcp_opt->wscale_ok = 1;
	tcp_opt->snd_wscale = options & TS_OPT_WSCALE_MASK;

	return net->ipv4.sysctl_tcp_window_scaling != 0;
}
EXPORT_SYMBOL(cookie_timestamp_decode);

bool cookie_ecn_ok(const struct tcp_options_received *tcp_opt,
		   const struct net *net, const struct dst_entry *dst)
{
	bool ecn_ok = tcp_opt->rcv_tsecr & TS_OPT_ECN;

	if (!ecn_ok)
		return false;

	if (net->ipv4.sysctl_tcp_ecn)
		return true;

	return dst_feature(dst, RTAX_FEATURE_ECN);
}
EXPORT_SYMBOL(cookie_ecn_ok);

/* On input, sk is a listener.
 * Output is listener if incoming packet would not create a child
 *           NULL if memory could not be allocated.
 */
struct sock *cookie_v4_check(struct sock *sk, struct sk_buff *skb)
{
	struct ip_options *opt = &TCP_SKB_CB(skb)->header.h4.opt;
	struct tcp_options_received tcp_opt;
	struct inet_request_sock *ireq;
	struct tcp_request_sock *treq;
	struct tcp_sock *tp = tcp_sk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	__u32 cookie = ntohl(th->ack_seq) - 1;
	struct sock *ret = sk;
	struct request_sock *req;
	int mss;
	struct rtable *rt;
	__u8 rcv_wscale;
	struct tcp_options_received tcp_opt;

	if (!sysctl_tcp_syncookies || !th->ack)
		goto out;

	if (time_after(jiffies, tp->last_synq_overflow + TCP_TIMEOUT_INIT) ||
	    (mss = cookie_check(skb, cookie)) == 0) {
	struct flowi4 fl4;
	u32 tsoff = 0;

	if (!sock_net(sk)->ipv4.sysctl_tcp_syncookies || !th->ack || th->rst)
		goto out;

	if (tcp_synq_no_recent_overflow(sk))
		goto out;

	mss = __cookie_v4_check(ip_hdr(skb), th, cookie);
	if (mss == 0) {
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_SYNCOOKIESFAILED);
		goto out;
	}

	__NET_INC_STATS(sock_net(sk), LINUX_MIB_SYNCOOKIESRECV);

	/* check for timestamp cookie support */
	memset(&tcp_opt, 0, sizeof(tcp_opt));
	tcp_parse_options(skb, &tcp_opt, 0);

	if (tcp_opt.saw_tstamp)
		cookie_check_timestamp(&tcp_opt);

	ret = NULL;
	req = inet_reqsk_alloc(&tcp_request_sock_ops); /* for safety */
	if (!req)
		goto out;

	if (security_inet_conn_request(sk, skb, req)) {
		reqsk_free(req);
		goto out;
	}
	tcp_parse_options(skb, &tcp_opt, 0, NULL);
	tcp_parse_options(sock_net(sk), skb, &tcp_opt, 0, NULL);

	if (tcp_opt.saw_tstamp && tcp_opt.rcv_tsecr) {
		tsoff = secure_tcp_ts_off(sock_net(sk),
					  ip_hdr(skb)->daddr,
					  ip_hdr(skb)->saddr);
		tcp_opt.rcv_tsecr -= tsoff;
	}

	if (!cookie_timestamp_decode(sock_net(sk), &tcp_opt))
		goto out;

	ret = NULL;
	req = inet_reqsk_alloc(&tcp_request_sock_ops, sk, false); /* for safety */
	if (!req)
		goto out;

	ireq = inet_rsk(req);
	treq = tcp_rsk(req);
	treq->rcv_isn		= ntohl(th->seq) - 1;
	treq->snt_isn		= cookie;
	treq->ts_off		= 0;
	treq->txhash		= net_tx_rndhash();
	req->mss		= mss;
	ireq->rmt_port		= th->source;
	ireq->loc_addr		= ip_hdr(skb)->daddr;
	ireq->rmt_addr		= ip_hdr(skb)->saddr;
	ireq->ecn_ok		= 0;
	ireq->snd_wscale	= tcp_opt.snd_wscale;
	ireq->rcv_wscale	= tcp_opt.rcv_wscale;
	ireq->ir_num		= ntohs(th->dest);
	ireq->ir_rmt_port	= th->source;
	sk_rcv_saddr_set(req_to_sk(req), ip_hdr(skb)->daddr);
	sk_daddr_set(req_to_sk(req), ip_hdr(skb)->saddr);
	ireq->ir_mark		= inet_request_mark(sk, skb);
	ireq->snd_wscale	= tcp_opt.snd_wscale;
	ireq->sack_ok		= tcp_opt.sack_ok;
	ireq->wscale_ok		= tcp_opt.wscale_ok;
	ireq->tstamp_ok		= tcp_opt.saw_tstamp;
	req->ts_recent		= tcp_opt.saw_tstamp ? tcp_opt.rcv_tsval : 0;
	treq->snt_synack	= 0;
	treq->tfo_listener	= false;

	ireq->ir_iif = inet_request_bound_dev_if(sk, skb);

	/* We throwed the options of the initial SYN away, so we hope
	 * the ACK carries the same options again (see RFC1122 4.2.3.8)
	 */
	if (opt && opt->optlen) {
		int opt_size = sizeof(struct ip_options) + opt->optlen;

		ireq->opt = kmalloc(opt_size, GFP_ATOMIC);
		if (ireq->opt != NULL && ip_options_echo(ireq->opt, skb)) {
			kfree(ireq->opt);
			ireq->opt = NULL;
		}
	}

	req->expires	= 0UL;
	req->retrans	= 0;
	ireq->opt = tcp_v4_save_options(skb);
	RCU_INIT_POINTER(ireq->ireq_opt, tcp_v4_save_options(sock_net(sk), skb));

	if (security_inet_conn_request(sk, skb, req)) {
		reqsk_free(req);
		goto out;
	}

	req->num_retrans = 0;

	/*
	 * We need to lookup the route here to get at the correct
	 * window size. We should better make sure that the window size
	 * hasn't changed since we received the original syn, but I see
	 * no easy way to do this.
	 */
	{
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = ((opt && opt->srr) ?
							  opt->faddr :
							  ireq->rmt_addr),
						.saddr = ireq->loc_addr,
						.tos = RT_CONN_FLAGS(sk) } },
				    .proto = IPPROTO_TCP,
				    .uli_u = { .ports =
					       { .sport = th->dest,
						 .dport = th->source } } };
		security_req_classify_flow(req, &fl);
		if (ip_route_output_key(&init_net, &rt, &fl)) {
			reqsk_free(req);
			goto out;
		}
	}

	/* Try to redo what tcp_v4_send_synack did. */
	req->window_clamp = tp->window_clamp ? :dst_metric(&rt->u.dst, RTAX_WINDOW);

	tcp_select_initial_window(tcp_full_space(sk), req->mss,
				  &req->rcv_wnd, &req->window_clamp,
				  ireq->wscale_ok, &rcv_wscale);

	ireq->rcv_wscale  = rcv_wscale;

	ret = get_cookie_sock(sk, skb, req, &rt->u.dst);
	flowi4_init_output(&fl4, sk->sk_bound_dev_if, ireq->ir_mark,
	flowi4_init_output(&fl4, ireq->ir_iif, ireq->ir_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE, IPPROTO_TCP,
			   inet_sk_flowi_flags(sk),
			   opt->srr ? opt->faddr : ireq->ir_rmt_addr,
			   ireq->ir_loc_addr, th->source, th->dest, sk->sk_uid);
	security_req_classify_flow(req, flowi4_to_flowi(&fl4));
	rt = ip_route_output_key(sock_net(sk), &fl4);
	if (IS_ERR(rt)) {
		reqsk_free(req);
		goto out;
	}

	/* Try to redo what tcp_v4_send_synack did. */
	req->rsk_window_clamp = tp->window_clamp ? :dst_metric(&rt->dst, RTAX_WINDOW);

	tcp_select_initial_window(tcp_full_space(sk), req->mss,
				  &req->rsk_rcv_wnd, &req->rsk_window_clamp,
				  ireq->wscale_ok, &rcv_wscale,
				  dst_metric(&rt->dst, RTAX_INITRWND));

	ireq->rcv_wscale  = rcv_wscale;
	ireq->ecn_ok = cookie_ecn_ok(&tcp_opt, sock_net(sk), &rt->dst);

	ret = tcp_get_cookie_sock(sk, skb, req, &rt->dst, tsoff);
	/* ip_queue_xmit() depends on our flow being setup
	 * Normal sockets get it right from inet_csk_route_child_sock()
	 */
	if (ret)
		inet_sk(ret)->cork.fl.u.ip4 = fl4;
out:	return ret;
}
