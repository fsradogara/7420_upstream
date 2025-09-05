/*
 * net/tipc/discover.c
 *
 * Copyright (c) 2003-2006, Ericsson AB
 * Copyright (c) 2005-2006, Wind River Systems
 * Copyright (c) 2003-2006, 2014-2015, Ericsson AB
 * Copyright (c) 2003-2006, 2014-2018, Ericsson AB
 * Copyright (c) 2005-2006, 2010-2011, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "core.h"
#include "dbg.h"
#include "link.h"
#include "zone.h"
#include "discover.h"
#include "port.h"
#include "name_table.h"

#define TIPC_LINK_REQ_INIT	125	/* min delay during bearer start up */
#define TIPC_LINK_REQ_FAST	2000	/* normal delay if bearer has no links */
#define TIPC_LINK_REQ_SLOW	600000	/* normal delay if bearer has links */

#if 0
#define  GET_NODE_INFO         300
#define  GET_NODE_INFO_RESULT  301
#define  FORWARD_LINK_PROBE    302
#define  LINK_REQUEST_REJECTED 303
#define  LINK_REQUEST_ACCEPTED 304
#define  DROP_LINK_REQUEST     305
#define  CHECK_LINK_COUNT      306
#endif

/*
 * TODO: Most of the inter-cluster setup stuff should be
 * rewritten, and be made conformant with specification.
 */


/**
 * struct link_req - information about an ongoing link setup request
 * @bearer: bearer issuing requests
 * @dest: destination address for request messages
#include "node.h"
#include "discover.h"

/* min delay during bearer start up */
#define TIPC_DISC_INIT	msecs_to_jiffies(125)
/* max delay if bearer has no links */
#define TIPC_DISC_FAST	msecs_to_jiffies(1000)
/* max delay if bearer has links */
#define TIPC_DISC_SLOW	msecs_to_jiffies(60000)
/* indicates no timer in use */
#define TIPC_DISC_INACTIVE	0xffffffff

/**
 * struct tipc_discoverer - information about an ongoing link setup request
 * @bearer_id: identity of bearer issuing requests
 * @net: network namespace instance
 * @dest: destination address for request messages
 * @domain: network domain to which links can be established
 * @num_nodes: number of nodes currently discovered (i.e. with an active link)
 * @lock: spinlock for controlling access to requests
 * @skb: request message to be (repeatedly) sent
 * @timer: timer governing period between requests
 * @timer_intv: current interval between requests (in ms)
 */
struct link_req {
	struct bearer *bearer;
	struct tipc_media_addr dest;
	struct sk_buff *buf;
	struct timer_list timer;
	unsigned int timer_intv;
};


#if 0
int disc_create_link(const struct tipc_link_create *argv)
{
	/*
	 * Code for inter cluster link setup here
	 */
	return TIPC_OK;
}
#endif

/*
 * disc_lost_link(): A link has lost contact
 */

void tipc_disc_link_event(u32 addr, char *name, int up)
{
	if (in_own_cluster(addr))
		return;
	/*
	 * Code for inter cluster link setup here
	 */
}

/**
 * tipc_disc_init_msg - initialize a link setup message
 * @type: message type (request or response)
 * @req_links: number of links associated with message
 * @dest_domain: network domain of node(s) which should respond to message
 * @b_ptr: ptr to bearer issuing message
 */

static struct sk_buff *tipc_disc_init_msg(u32 type,
					  u32 req_links,
					  u32 dest_domain,
					  struct bearer *b_ptr)
{
	struct sk_buff *buf = buf_acquire(DSC_H_SIZE);
	struct tipc_msg *msg;

	if (buf) {
		msg = buf_msg(buf);
		msg_init(msg, LINK_CONFIG, type, DSC_H_SIZE, dest_domain);
		msg_set_non_seq(msg, 1);
		msg_set_req_links(msg, req_links);
		msg_set_dest_domain(msg, dest_domain);
		msg_set_bc_netid(msg, tipc_net_id);
		msg_set_media_addr(msg, &b_ptr->publ.addr);
	}
	return buf;
struct tipc_link_req {
struct tipc_discoverer {
	u32 bearer_id;
	struct tipc_media_addr dest;
	struct net *net;
	u32 domain;
	int num_nodes;
	spinlock_t lock;
	struct sk_buff *skb;
	struct timer_list timer;
	unsigned long timer_intv;
};

/**
 * tipc_disc_init_msg - initialize a link setup message
 * @net: the applicable net namespace
 * @type: message type (request or response)
 * @b: ptr to bearer issuing message
 */
static void tipc_disc_init_msg(struct net *net, struct sk_buff *skb,
			       u32 mtyp,  struct tipc_bearer *b)
{
	struct tipc_net *tn = tipc_net(net);
	u32 dest_domain = b->domain;
	struct tipc_msg *hdr;

	hdr = buf_msg(skb);
	tipc_msg_init(tn->trial_addr, hdr, LINK_CONFIG, mtyp,
		      MAX_H_SIZE, dest_domain);
	msg_set_size(hdr, MAX_H_SIZE + NODE_ID_LEN);
	msg_set_non_seq(hdr, 1);
	msg_set_node_sig(hdr, tn->random);
	msg_set_node_capabilities(hdr, TIPC_NODE_CAPABILITIES);
	msg_set_dest_domain(hdr, dest_domain);
	msg_set_bc_netid(hdr, tn->net_id);
	b->media->addr2msg(msg_media_addr(hdr), &b->addr);
	msg_set_node_id(hdr, tipc_own_id(net));
}

static void tipc_disc_msg_xmit(struct net *net, u32 mtyp, u32 dst,
			       u32 src, u32 sugg_addr,
			       struct tipc_media_addr *maddr,
			       struct tipc_bearer *b)
{
	struct tipc_msg *hdr;
	struct sk_buff *skb;

	skb = tipc_buf_acquire(MAX_H_SIZE + NODE_ID_LEN, GFP_ATOMIC);
	if (!skb)
		return;
	hdr = buf_msg(skb);
	tipc_disc_init_msg(net, skb, mtyp, b);
	msg_set_sugg_node_addr(hdr, sugg_addr);
	msg_set_dest_domain(hdr, dst);
	tipc_bearer_xmit_skb(net, b->identity, skb, maddr);
}

/**
 * disc_dupl_alert - issue node address duplication alert
 * @b: pointer to bearer detecting duplication
 * @node_addr: duplicated node address
 * @media_addr: media address advertised by duplicated node
 */

static void disc_dupl_alert(struct bearer *b_ptr, u32 node_addr,
static void disc_dupl_alert(struct tipc_bearer *b_ptr, u32 node_addr,
static void disc_dupl_alert(struct tipc_bearer *b, u32 node_addr,
			    struct tipc_media_addr *media_addr)
{
	char media_addr_str[64];
	struct print_buf pb;

	addr_string_fill(node_addr_str, node_addr);
	tipc_printbuf_init(&pb, media_addr_str, sizeof(media_addr_str));
	tipc_media_addr_printf(&pb, media_addr);
	tipc_printbuf_validate(&pb);
	warn("Duplicate %s using %s seen on <%s>\n",
	     node_addr_str, media_addr_str, b_ptr->publ.name);
}

/**
 * tipc_disc_recv_msg - handle incoming link setup message (request or response)
 * @buf: buffer containing message
 * @b_ptr: bearer that message arrived on
 */

void tipc_disc_recv_msg(struct sk_buff *buf, struct bearer *b_ptr)
{
	struct link *link;
	struct tipc_media_addr media_addr;
	struct tipc_msg *msg = buf_msg(buf);
	u32 dest = msg_dest_domain(msg);
	u32 orig = msg_prevnode(msg);
	u32 net_id = msg_bc_netid(msg);
	u32 type = msg_type(msg);

	msg_get_media_addr(msg,&media_addr);
	msg_dbg(msg, "RECV:");
	buf_discard(buf);

	if (net_id != tipc_net_id)
		return;
	if (!tipc_addr_domain_valid(dest))
		return;
	if (!tipc_addr_node_valid(orig))
		return;
	if (orig == tipc_own_addr) {
		if (memcmp(&media_addr, &b_ptr->publ.addr, sizeof(media_addr)))
			disc_dupl_alert(b_ptr, tipc_own_addr, &media_addr);
		return;
	}
	if (!in_scope(dest, tipc_own_addr))
		return;
	if (is_slave(tipc_own_addr) && is_slave(orig))
		return;
	if (is_slave(orig) && !in_own_cluster(orig))
		return;
	if (in_own_cluster(orig)) {
		/* Always accept link here */
		struct sk_buff *rbuf;
		struct tipc_media_addr *addr;
		struct tipc_node *n_ptr = tipc_node_find(orig);
		int link_fully_up;

		dbg(" in own cluster\n");
		if (n_ptr == NULL) {
			n_ptr = tipc_node_create(orig);
			if (!n_ptr)
				return;
		}
		spin_lock_bh(&n_ptr->lock);
		link = n_ptr->links[b_ptr->identity];
		if (!link) {
			dbg("creating link\n");
			link = tipc_link_create(b_ptr, orig, &media_addr);
			if (!link) {
				spin_unlock_bh(&n_ptr->lock);
				return;
			}
		}
		addr = &link->media_addr;
		if (memcmp(addr, &media_addr, sizeof(*addr))) {
			if (tipc_link_is_up(link) || (!link->started)) {
				disc_dupl_alert(b_ptr, orig, &media_addr);
				spin_unlock_bh(&n_ptr->lock);
				return;
			}
			warn("Resetting link <%s>, peer interface address changed\n",
			     link->name);
			memcpy(addr, &media_addr, sizeof(*addr));
			tipc_link_reset(link);
		}
		link_fully_up = (link->state == WORKING_WORKING);
		spin_unlock_bh(&n_ptr->lock);
		if ((type == DSC_RESP_MSG) || link_fully_up)
			return;
		rbuf = tipc_disc_init_msg(DSC_RESP_MSG, 1, orig, b_ptr);
		if (rbuf != NULL) {
			msg_dbg(buf_msg(rbuf),"SEND:");
			b_ptr->media->send_msg(rbuf, &b_ptr->publ, &media_addr);
			buf_discard(rbuf);

	tipc_media_addr_printf(media_addr_str, sizeof(media_addr_str),
			       media_addr);
	pr_warn("Duplicate %x using %s seen on <%s>\n", node_addr,
		media_addr_str, b->name);
}

/* tipc_disc_addr_trial(): - handle an address uniqueness trial from peer
 * Returns true if message should be dropped by caller, i.e., if it is a
 * trial message or we are inside trial period. Otherwise false.
 */
static bool tipc_disc_addr_trial_msg(struct tipc_discoverer *d,
				     struct tipc_media_addr *maddr,
				     struct tipc_bearer *b,
				     u32 dst, u32 src,
				     u32 sugg_addr,
				     u8 *peer_id,
				     int mtyp)
{
	struct net *net = d->net;
	struct tipc_net *tn = tipc_net(net);
	bool trial = time_before(jiffies, tn->addr_trial_end);
	u32 self = tipc_own_addr(net);

	if (mtyp == DSC_TRIAL_FAIL_MSG) {
		if (!trial)
			return true;

		/* Ignore if somebody else already gave new suggestion */
		if (dst != tn->trial_addr)
			return true;

		/* Otherwise update trial address and restart trial period */
		tn->trial_addr = sugg_addr;
		msg_set_prevnode(buf_msg(d->skb), sugg_addr);
		tn->addr_trial_end = jiffies + msecs_to_jiffies(1000);
		return true;
	}

	/* Apply trial address if we just left trial period */
	if (!trial && !self) {
		tipc_sched_net_finalize(net, tn->trial_addr);
		msg_set_prevnode(buf_msg(d->skb), tn->trial_addr);
		msg_set_type(buf_msg(d->skb), DSC_REQ_MSG);
	}

	/* Accept regular link requests/responses only after trial period */
	if (mtyp != DSC_TRIAL_MSG)
		return trial;

	sugg_addr = tipc_node_try_addr(net, peer_id, src);
	if (sugg_addr)
		tipc_disc_msg_xmit(net, DSC_TRIAL_FAIL_MSG, src,
				   self, sugg_addr, maddr, b);
	return true;
}

/**
 * tipc_disc_rcv - handle incoming discovery message (request or response)
 * @net: applicable net namespace
 * @skb: buffer containing message
 * @b: bearer that message arrived on
 */
void tipc_disc_rcv(struct net *net, struct sk_buff *skb,
		   struct tipc_bearer *b)
{
	struct tipc_net *tn = tipc_net(net);
	struct tipc_msg *hdr = buf_msg(skb);
	u16 caps = msg_node_capabilities(hdr);
	bool legacy = tn->legacy_addr_format;
	u32 sugg = msg_sugg_node_addr(hdr);
	u32 signature = msg_node_sig(hdr);
	u8 peer_id[NODE_ID_LEN] = {0,};
	u32 dst = msg_dest_domain(hdr);
	u32 net_id = msg_bc_netid(hdr);
	struct tipc_media_addr maddr;
	u32 src = msg_prevnode(hdr);
	u32 mtyp = msg_type(hdr);
	bool dupl_addr = false;
	bool respond = false;
	u32 self;
	int err;

	skb_linearize(skb);
	hdr = buf_msg(skb);

	if (caps & TIPC_NODE_ID128)
		memcpy(peer_id, msg_node_id(hdr), NODE_ID_LEN);
	else
		sprintf(peer_id, "%x", src);

	err = b->media->msg2addr(b, &maddr, msg_media_addr(hdr));
	kfree_skb(skb);
	if (err || maddr.broadcast) {
		pr_warn_ratelimited("Rcv corrupt discovery message\n");
		return;
	}
	/* Ignore discovery messages from own node */
	if (!memcmp(&maddr, &b->addr, sizeof(maddr)))
		return;
	if (net_id != tn->net_id)
		return;
	if (tipc_disc_addr_trial_msg(b->disc, &maddr, b, dst,
				     src, sugg, peer_id, mtyp))
		return;
	self = tipc_own_addr(net);

	/* Message from somebody using this node's address */
	if (in_own_node(net, src)) {
		disc_dupl_alert(b, self, &maddr);
		return;
	}
	if (!tipc_in_scope(legacy, dst, self))
		return;
	if (!tipc_in_scope(legacy, b->domain, src))
		return;
	tipc_node_check_dest(net, src, peer_id, b, caps, signature,
			     &maddr, &respond, &dupl_addr);
	if (dupl_addr)
		disc_dupl_alert(b, src, &maddr);
	if (!respond)
		return;
	if (mtyp != DSC_REQ_MSG)
		return;
	tipc_disc_msg_xmit(net, DSC_RESP_MSG, src, self, 0, &maddr, b);
}

/* tipc_disc_add_dest - increment set of discovered nodes
 */
void tipc_disc_add_dest(struct tipc_discoverer *d)
{
	spin_lock_bh(&d->lock);
	d->num_nodes++;
	spin_unlock_bh(&d->lock);
}

/* tipc_disc_remove_dest - decrement set of discovered nodes
 */
void tipc_disc_remove_dest(struct tipc_discoverer *d)
{
	int intv, num;

	spin_lock_bh(&d->lock);
	d->num_nodes--;
	num = d->num_nodes;
	intv = d->timer_intv;
	if (!num && (intv == TIPC_DISC_INACTIVE || intv > TIPC_DISC_FAST))  {
		d->timer_intv = TIPC_DISC_INIT;
		mod_timer(&d->timer, jiffies + d->timer_intv);
	}
	spin_unlock_bh(&d->lock);
}

/**
 * disc_update - update frequency of periodic link setup requests
 * @req: ptr to link request structure
 *
 * Reinitiates discovery process if discovery object has no associated nodes
 * and is either not currently searching or is searching at a slow rate
 */
static void disc_update(struct tipc_link_req *req)
{
	if (!req->num_nodes) {
		if ((req->timer_intv == TIPC_LINK_REQ_INACTIVE) ||
		    (req->timer_intv > TIPC_LINK_REQ_FAST)) {
			req->timer_intv = TIPC_LINK_REQ_INIT;
			mod_timer(&req->timer, jiffies + req->timer_intv);
		}
	}
}

/**
 * tipc_disc_stop_link_req - stop sending periodic link setup requests
 * @req: ptr to link request structure
 */

void tipc_disc_stop_link_req(struct link_req *req)
{
	if (!req)
		return;

	k_cancel_timer(&req->timer);
	k_term_timer(&req->timer);
	buf_discard(req->buf);
	kfree(req);
}

/**
 * tipc_disc_update_link_req - update frequency of periodic link setup requests
 * @req: ptr to link request structure
 */

void tipc_disc_update_link_req(struct link_req *req)
{
	if (!req)
		return;

	if (req->timer_intv == TIPC_LINK_REQ_SLOW) {
		if (!req->bearer->nodes.count) {
			req->timer_intv = TIPC_LINK_REQ_FAST;
			k_start_timer(&req->timer, req->timer_intv);
		}
	} else if (req->timer_intv == TIPC_LINK_REQ_FAST) {
		if (req->bearer->nodes.count) {
			req->timer_intv = TIPC_LINK_REQ_SLOW;
			k_start_timer(&req->timer, req->timer_intv);
		}
	} else {
		/* leave timer "as is" if haven't yet reached a "normal" rate */
	}
 * tipc_disc_add_dest - increment set of discovered nodes
 * @req: ptr to link request structure
 */
void tipc_disc_add_dest(struct tipc_link_req *req)
{
	spin_lock_bh(&req->lock);
	req->num_nodes++;
	spin_unlock_bh(&req->lock);
}

/**
 * tipc_disc_remove_dest - decrement set of discovered nodes
 * @req: ptr to link request structure
 */
void tipc_disc_remove_dest(struct tipc_link_req *req)
{
	spin_lock_bh(&req->lock);
	req->num_nodes--;
	disc_update(req);
	spin_unlock_bh(&req->lock);
}

/**
 * disc_timeout - send a periodic link setup request
 * @req: ptr to link request structure
 *
 * Called whenever a link setup request timer associated with a bearer expires.
 */

static void disc_timeout(struct link_req *req)
{
	spin_lock_bh(&req->bearer->publ.lock);

	req->bearer->media->send_msg(req->buf, &req->bearer->publ, &req->dest);

	if ((req->timer_intv == TIPC_LINK_REQ_SLOW) ||
	    (req->timer_intv == TIPC_LINK_REQ_FAST)) {
		/* leave timer interval "as is" if already at a "normal" rate */
	} else {
		req->timer_intv *= 2;
		if (req->timer_intv > TIPC_LINK_REQ_FAST)
			req->timer_intv = TIPC_LINK_REQ_FAST;
		if ((req->timer_intv == TIPC_LINK_REQ_FAST) &&
		    (req->bearer->nodes.count))
			req->timer_intv = TIPC_LINK_REQ_SLOW;
	}
	k_start_timer(&req->timer, req->timer_intv);

	spin_unlock_bh(&req->bearer->publ.lock);
}

/**
 * tipc_disc_init_link_req - start sending periodic link setup requests
 * @b_ptr: ptr to bearer issuing requests
 * @dest: destination address for request messages
 * @dest_domain: network domain of node(s) which should respond to message
 * @req_links: max number of desired links
 *
 * Returns pointer to link request structure, or NULL if unable to create.
 */

struct link_req *tipc_disc_init_link_req(struct bearer *b_ptr,
					 const struct tipc_media_addr *dest,
					 u32 dest_domain,
					 u32 req_links)
{
	struct link_req *req;

	req = kmalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return NULL;

	req->buf = tipc_disc_init_msg(DSC_REQ_MSG, req_links, dest_domain, b_ptr);
	if (!req->buf) {
		kfree(req);
		return NULL;
	}

	memcpy(&req->dest, dest, sizeof(*dest));
	req->bearer = b_ptr;
	req->timer_intv = TIPC_LINK_REQ_INIT;
	k_init_timer(&req->timer, (Handler)disc_timeout, (unsigned long)req);
	k_start_timer(&req->timer, req->timer_intv);
	return req;
}

 * @data: ptr to link request structure
 *
/* tipc_disc_timeout - send a periodic link setup request
 * Called whenever a link setup request timer associated with a bearer expires.
 * - Keep doubling time between sent request until limit is reached;
 * - Hold at fast polling rate if we don't have any associated nodes
 * - Otherwise hold at slow polling rate
 */
static void tipc_disc_timeout(struct timer_list *t)
{
	struct tipc_discoverer *d = from_timer(d, t, timer);
	struct tipc_net *tn = tipc_net(d->net);
	struct tipc_media_addr maddr;
	struct sk_buff *skb = NULL;
	struct net *net = d->net;
	u32 bearer_id;

	spin_lock_bh(&d->lock);

	/* Stop searching if only desired node has been found */
	if (tipc_node(d->domain) && d->num_nodes) {
		d->timer_intv = TIPC_DISC_INACTIVE;
		goto exit;
	}

	/* Did we just leave trial period ? */
	if (!time_before(jiffies, tn->addr_trial_end) && !tipc_own_addr(net)) {
		mod_timer(&d->timer, jiffies + TIPC_DISC_INIT);
		spin_unlock_bh(&d->lock);
		tipc_sched_net_finalize(net, tn->trial_addr);
		return;
	}

	/* Adjust timeout interval according to discovery phase */
	if (time_before(jiffies, tn->addr_trial_end)) {
		d->timer_intv = TIPC_DISC_INIT;
	} else {
		d->timer_intv *= 2;
		if (d->num_nodes && d->timer_intv > TIPC_DISC_SLOW)
			d->timer_intv = TIPC_DISC_SLOW;
		else if (!d->num_nodes && d->timer_intv > TIPC_DISC_FAST)
			d->timer_intv = TIPC_DISC_FAST;
		msg_set_type(buf_msg(d->skb), DSC_REQ_MSG);
		msg_set_prevnode(buf_msg(d->skb), tn->trial_addr);
	}

	mod_timer(&d->timer, jiffies + d->timer_intv);
	memcpy(&maddr, &d->dest, sizeof(maddr));
	skb = skb_clone(d->skb, GFP_ATOMIC);
	bearer_id = d->bearer_id;
exit:
	spin_unlock_bh(&d->lock);
	if (skb)
		tipc_bearer_xmit_skb(net, bearer_id, skb, &maddr);
}

/**
 * tipc_disc_create - create object to send periodic link setup requests
 * @net: the applicable net namespace
 * @b: ptr to bearer issuing requests
 * @dest: destination address for request messages
 * @dest_domain: network domain to which links can be established
 *
 * Returns 0 if successful, otherwise -errno.
 */
int tipc_disc_create(struct net *net, struct tipc_bearer *b,
		     struct tipc_media_addr *dest, struct sk_buff **skb)
{
	struct tipc_net *tn = tipc_net(net);
	struct tipc_discoverer *d;

	d = kmalloc(sizeof(*d), GFP_ATOMIC);
	if (!d)
		return -ENOMEM;
	d->skb = tipc_buf_acquire(MAX_H_SIZE + NODE_ID_LEN, GFP_ATOMIC);
	if (!d->skb) {
		kfree(d);
		return -ENOMEM;
	}
	tipc_disc_init_msg(net, d->skb, DSC_REQ_MSG, b);

	/* Do we need an address trial period first ? */
	if (!tipc_own_addr(net)) {
		tn->addr_trial_end = jiffies + msecs_to_jiffies(1000);
		msg_set_type(buf_msg(d->skb), DSC_TRIAL_MSG);
	}
	memcpy(&d->dest, dest, sizeof(*dest));
	d->net = net;
	d->bearer_id = b->identity;
	d->domain = b->domain;
	d->num_nodes = 0;
	d->timer_intv = TIPC_DISC_INIT;
	spin_lock_init(&d->lock);
	timer_setup(&d->timer, tipc_disc_timeout, 0);
	mod_timer(&d->timer, jiffies + d->timer_intv);
	b->disc = d;
	*skb = skb_clone(d->skb, GFP_ATOMIC);
	return 0;
}

/**
 * tipc_disc_delete - destroy object sending periodic link setup requests
 * @d: ptr to link duest structure
 */
void tipc_disc_delete(struct tipc_discoverer *d)
{
	del_timer_sync(&d->timer);
	kfree_skb(d->skb);
	kfree(d);
}

/**
 * tipc_disc_reset - reset object to send periodic link setup requests
 * @net: the applicable net namespace
 * @b: ptr to bearer issuing requests
 * @dest_domain: network domain to which links can be established
 */
void tipc_disc_reset(struct net *net, struct tipc_bearer *b)
{
	struct tipc_discoverer *d = b->disc;
	struct tipc_media_addr maddr;
	struct sk_buff *skb;

	spin_lock_bh(&d->lock);
	tipc_disc_init_msg(net, d->skb, DSC_REQ_MSG, b);
	d->net = net;
	d->bearer_id = b->identity;
	d->domain = b->domain;
	d->num_nodes = 0;
	d->timer_intv = TIPC_DISC_INIT;
	memcpy(&maddr, &d->dest, sizeof(maddr));
	mod_timer(&d->timer, jiffies + d->timer_intv);
	skb = skb_clone(d->skb, GFP_ATOMIC);
	spin_unlock_bh(&d->lock);
	if (skb)
		tipc_bearer_xmit_skb(net, b->identity, skb, &maddr);
}
