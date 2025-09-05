/*
 * net/tipc/subscr.c: TIPC network topology service
 *
 * Copyright (c) 2000-2006, Ericsson AB
 * Copyright (c) 2005-2007, Wind River Systems
 * Copyright (c) 2005-2007, 2010-2013, Wind River Systems
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
#include "name_table.h"
#include "port.h"
#include "ref.h"
#include "subscr.h"

/**
 * struct subscriber - TIPC network topology subscriber
 * @port_ref: object reference to server port connecting to subscriber
 * @lock: pointer to spinlock controlling access to subscriber's server port
 * @subscriber_list: adjacent subscribers in top. server's list of subscribers
 * @subscription_list: list of subscription objects for this subscriber
 */

struct subscriber {
	u32 port_ref;
	spinlock_t *lock;
	struct list_head subscriber_list;
	struct list_head subscription_list;
};

/**
 * struct top_srv - TIPC network topology subscription service
 * @user_ref: TIPC userid of subscription service
 * @setup_port: reference to TIPC port that handles subscription requests
 * @subscription_count: number of active subscriptions (not subscribers!)
 * @subscriber_list: list of ports subscribing to service
 * @lock: spinlock govering access to subscriber list
 */

struct top_srv {
	u32 user_ref;
	u32 setup_port;
	atomic_t subscription_count;
	struct list_head subscriber_list;
	spinlock_t lock;
};

static struct top_srv topsrv = { 0 };
#include "name_table.h"
#include "subscr.h"

/**
 * struct tipc_subscriber - TIPC network topology subscriber
 * @kref: reference counter to tipc_subscription object
 * @conid: connection identifier to server connecting to subscriber
 * @lock: control access to subscriber
 * @subscrp_list: list of subscription objects for this subscriber
 */
struct tipc_subscriber {
	struct kref kref;
	int conid;
	spinlock_t lock;
	struct list_head subscrp_list;
};

static void tipc_subscrb_put(struct tipc_subscriber *subscriber);

/**
 * htohl - convert value to endianness used by destination
 * @in: value to convert
 * @swap: non-zero if endianness must be reversed
 *
 * Returns converted value
 */

static u32 htohl(u32 in, int swap)
{
	return swap ? swab32(in) : in;
}

/**
 * subscr_send_event - send a message containing a tipc_event to the subscriber
 *
 * Note: Must not hold subscriber's server port lock, since tipc_send() will
 *       try to take the lock if the message is rejected and returned!
 */

static void subscr_send_event(struct subscription *sub,
			      u32 found_lower,
			      u32 found_upper,
			      u32 event,
			      u32 port_ref,
			      u32 node)
{
	struct iovec msg_sect;

	msg_sect.iov_base = (void *)&sub->evt;
	msg_sect.iov_len = sizeof(struct tipc_event);

static void tipc_subscrp_send_event(struct tipc_subscription *sub,
				    u32 found_lower, u32 found_upper,
				    u32 event, u32 port_ref, u32 node)
{
	struct tipc_net *tn = net_generic(sub->net, tipc_net_id);
	struct tipc_subscriber *subscriber = sub->subscriber;
	struct kvec msg_sect;

	msg_sect.iov_base = (void *)&sub->evt;
	msg_sect.iov_len = sizeof(struct tipc_event);
	sub->evt.event = htohl(event, sub->swap);
	sub->evt.found_lower = htohl(found_lower, sub->swap);
	sub->evt.found_upper = htohl(found_upper, sub->swap);
	sub->evt.port.ref = htohl(port_ref, sub->swap);
	sub->evt.port.node = htohl(node, sub->swap);
	tipc_send(sub->server_ref, 1, &msg_sect);
}

/**
 * tipc_subscr_overlap - test for subscription overlap with the given values
 *
 * Returns 1 if there is overlap, otherwise 0.
 */

int tipc_subscr_overlap(struct subscription *sub,
			u32 found_lower,
			u32 found_upper)

	tipc_conn_sendmsg(tn->topsrv, subscriber->conid, NULL,
			  msg_sect.iov_base, msg_sect.iov_len);
}

/**
 * tipc_subscrp_check_overlap - test for subscription overlap with the
 * given values
 *
 * Returns 1 if there is overlap, otherwise 0.
 */
int tipc_subscrp_check_overlap(struct tipc_name_seq *seq, u32 found_lower,
			       u32 found_upper)
{
	if (found_lower < seq->lower)
		found_lower = seq->lower;
	if (found_upper > seq->upper)
		found_upper = seq->upper;
	if (found_lower > found_upper)
		return 0;
	return 1;
}

/**
 * tipc_subscr_report_overlap - issue event if there is subscription overlap
 *
 * Protected by nameseq.lock in name_table.c
 */

void tipc_subscr_report_overlap(struct subscription *sub,
				u32 found_lower,
				u32 found_upper,
				u32 event,
				u32 port_ref,
				u32 node,
				int must)
{
	if (!tipc_subscr_overlap(sub, found_lower, found_upper))
u32 tipc_subscrp_convert_seq_type(u32 type, int swap)
{
	return htohl(type, swap);
}

void tipc_subscrp_convert_seq(struct tipc_name_seq *in, int swap,
			      struct tipc_name_seq *out)
{
	out->type = htohl(in->type, swap);
	out->lower = htohl(in->lower, swap);
	out->upper = htohl(in->upper, swap);
}

void tipc_subscrp_report_overlap(struct tipc_subscription *sub, u32 found_lower,
				 u32 found_upper, u32 event, u32 port_ref,
				 u32 node, int must)
{
	struct tipc_name_seq seq;

	tipc_subscrp_convert_seq(&sub->evt.s.seq, sub->swap, &seq);
	if (!tipc_subscrp_check_overlap(&seq, found_lower, found_upper))
		return;
	if (!must &&
	    !(htohl(sub->evt.s.filter, sub->swap) & TIPC_SUB_PORTS))
		return;

	sub->event_cb(sub, found_lower, found_upper, event, port_ref, node);
}

/**
 * subscr_timeout - subscription timeout has occurred
 */

static void subscr_timeout(struct subscription *sub)
{
	struct port *server_port;

	/* Validate server port reference (in case subscriber is terminating) */

	server_port = tipc_port_lock(sub->server_ref);
	if (server_port == NULL)
		return;

	/* Validate timeout (in case subscription is being cancelled) */

	if (sub->timeout == TIPC_WAIT_FOREVER) {
		tipc_port_unlock(server_port);
		return;
	}

	/* Unlink subscription from name table */

	tipc_nametbl_unsubscribe(sub);

	/* Unlink subscription from subscriber */

	list_del(&sub->subscription_list);

	/* Release subscriber's server port */

	tipc_port_unlock(server_port);

	/* Notify subscriber of timeout */

	subscr_send_event(sub, sub->evt.s.seq.lower, sub->evt.s.seq.upper,
			  TIPC_SUBSCR_TIMEOUT, 0, 0);

	/* Now destroy subscription */

	k_term_timer(&sub->timer);
	kfree(sub);
	atomic_dec(&topsrv.subscription_count);
}

/**
 * subscr_del - delete a subscription within a subscription list
 *
 * Called with subscriber port locked.
 */

static void subscr_del(struct subscription *sub)
{
	tipc_nametbl_unsubscribe(sub);
	list_del(&sub->subscription_list);
	kfree(sub);
	atomic_dec(&topsrv.subscription_count);
}

/**
 * subscr_terminate - terminate communication with a subscriber
 *
 * Called with subscriber port locked.  Routine must temporarily release lock
 * to enable subscription timeout routine(s) to finish without deadlocking;
 * the lock is then reclaimed to allow caller to release it upon return.
 * (This should work even in the unlikely event some other thread creates
 * a new object reference in the interim that uses this lock; this routine will
 * simply wait for it to be released, then claim it.)
 */

static void subscr_terminate(struct subscriber *subscriber)
{
	u32 port_ref;
	struct subscription *sub;
	struct subscription *sub_temp;

	/* Invalidate subscriber reference */

	port_ref = subscriber->port_ref;
	subscriber->port_ref = 0;
	spin_unlock_bh(subscriber->lock);

	/* Sever connection to subscriber */

	tipc_shutdown(port_ref);
	tipc_deleteport(port_ref);

	/* Destroy any existing subscriptions for subscriber */

	list_for_each_entry_safe(sub, sub_temp, &subscriber->subscription_list,
				 subscription_list) {
		if (sub->timeout != TIPC_WAIT_FOREVER) {
			k_cancel_timer(&sub->timer);
			k_term_timer(&sub->timer);
		}
		dbg("Term: Removing sub %u,%u,%u from subscriber %x list\n",
		    sub->seq.type, sub->seq.lower, sub->seq.upper, subscriber);
		subscr_del(sub);
	}

	/* Remove subscriber from topology server's subscriber list */

	spin_lock_bh(&topsrv.lock);
	list_del(&subscriber->subscriber_list);
	spin_unlock_bh(&topsrv.lock);

	/* Reclaim subscriber lock */

	spin_lock_bh(subscriber->lock);

	/* Now destroy subscriber */

	kfree(subscriber);
}

/**
 * subscr_cancel - handle subscription cancellation request
 *
 * Called with subscriber port locked.  Routine must temporarily release lock
 * to enable the subscription timeout routine to finish without deadlocking;
 * the lock is then reclaimed to allow caller to release it upon return.
 *
 * Note that fields of 's' use subscriber's endianness!
 */

static void subscr_cancel(struct tipc_subscr *s,
			  struct subscriber *subscriber)
{
	struct subscription *sub;
	struct subscription *sub_temp;
	int found = 0;

	/* Find first matching subscription, exit if not found */

	list_for_each_entry_safe(sub, sub_temp, &subscriber->subscription_list,
				 subscription_list) {
		if (!memcmp(s, &sub->evt.s, sizeof(struct tipc_subscr))) {
			found = 1;
			break;
		}
	}
	if (!found)
		return;

	/* Cancel subscription timer (if used), then delete subscription */

	if (sub->timeout != TIPC_WAIT_FOREVER) {
		sub->timeout = TIPC_WAIT_FOREVER;
		spin_unlock_bh(subscriber->lock);
		k_cancel_timer(&sub->timer);
		k_term_timer(&sub->timer);
		spin_lock_bh(subscriber->lock);
	}
	dbg("Cancel: removing sub %u,%u,%u from subscriber %x list\n",
	    sub->seq.type, sub->seq.lower, sub->seq.upper, subscriber);
	subscr_del(sub);
}

/**
 * subscr_subscribe - create subscription for subscriber
 *
 * Called with subscriber port locked.
 */

static struct subscription *subscr_subscribe(struct tipc_subscr *s,
					     struct subscriber *subscriber)
{
	struct subscription *sub;
	int swap;

	/* Determine subscriber's endianness */

	swap = !(s->filter & (TIPC_SUB_PORTS | TIPC_SUB_SERVICE));

	/* Detect & process a subscription cancellation request */

	if (s->filter & htohl(TIPC_SUB_CANCEL, swap)) {
		s->filter &= ~htohl(TIPC_SUB_CANCEL, swap);
		subscr_cancel(s, subscriber);
		return NULL;
	}

	/* Refuse subscription if global limit exceeded */

	if (atomic_read(&topsrv.subscription_count) >= tipc_max_subscriptions) {
		warn("Subscription rejected, subscription limit reached (%u)\n",
		     tipc_max_subscriptions);
		subscr_terminate(subscriber);
		return NULL;
	}

	/* Allocate subscription object */

	sub = kmalloc(sizeof(*sub), GFP_ATOMIC);
	if (!sub) {
		warn("Subscription rejected, no memory\n");
		subscr_terminate(subscriber);
		return NULL;
	}

	/* Initialize subscription object */

	sub->seq.type = htohl(s->seq.type, swap);
	sub->seq.lower = htohl(s->seq.lower, swap);
	sub->seq.upper = htohl(s->seq.upper, swap);
	sub->timeout = htohl(s->timeout, swap);
	sub->filter = htohl(s->filter, swap);
	if ((!(sub->filter & TIPC_SUB_PORTS)
	     == !(sub->filter & TIPC_SUB_SERVICE))
	    || (sub->seq.lower > sub->seq.upper)) {
		warn("Subscription rejected, illegal request\n");
		kfree(sub);
		subscr_terminate(subscriber);
		return NULL;
	}
	sub->event_cb = subscr_send_event;
	INIT_LIST_HEAD(&sub->nameseq_list);
	list_add(&sub->subscription_list, &subscriber->subscription_list);
	sub->server_ref = subscriber->port_ref;
	sub->swap = swap;
	memcpy(&sub->evt.s, s, sizeof(struct tipc_subscr));
	atomic_inc(&topsrv.subscription_count);
	if (sub->timeout != TIPC_WAIT_FOREVER) {
		k_init_timer(&sub->timer,
			     (Handler)subscr_timeout, (unsigned long)sub);
		k_start_timer(&sub->timer, sub->timeout);
	}

	return sub;
}

/**
 * subscr_conn_shutdown_event - handle termination request from subscriber
 *
 * Called with subscriber's server port unlocked.
 */

static void subscr_conn_shutdown_event(void *usr_handle,
				       u32 port_ref,
				       struct sk_buff **buf,
				       unsigned char const *data,
				       unsigned int size,
				       int reason)
{
	struct subscriber *subscriber = usr_handle;
	spinlock_t *subscriber_lock;

	if (tipc_port_lock(port_ref) == NULL)
		return;

	subscriber_lock = subscriber->lock;
	subscr_terminate(subscriber);
	spin_unlock_bh(subscriber_lock);
}

/**
 * subscr_conn_msg_event - handle new subscription request from subscriber
 *
 * Called with subscriber's server port unlocked.
 */

static void subscr_conn_msg_event(void *usr_handle,
				  u32 port_ref,
				  struct sk_buff **buf,
				  const unchar *data,
				  u32 size)
{
	struct subscriber *subscriber = usr_handle;
	spinlock_t *subscriber_lock;
	struct subscription *sub;

	/*
	 * Lock subscriber's server port (& make a local copy of lock pointer,
	 * in case subscriber is deleted while processing subscription request)
	 */

	if (tipc_port_lock(port_ref) == NULL)
		return;

	subscriber_lock = subscriber->lock;

	if (size != sizeof(struct tipc_subscr)) {
		subscr_terminate(subscriber);
		spin_unlock_bh(subscriber_lock);
	} else {
		sub = subscr_subscribe((struct tipc_subscr *)data, subscriber);
		spin_unlock_bh(subscriber_lock);
		if (sub != NULL) {

			/*
			 * We must release the server port lock before adding a
			 * subscription to the name table since TIPC needs to be
			 * able to (re)acquire the port lock if an event message
			 * issued by the subscription process is rejected and
			 * returned.  The subscription cannot be deleted while
			 * it is being added to the name table because:
			 * a) the single-threading of the native API port code
			 *    ensures the subscription cannot be cancelled and
			 *    the subscriber connection cannot be broken, and
			 * b) the name table lock ensures the subscription
			 *    timeout code cannot delete the subscription,
			 * so the subscription object is still protected.
			 */

			tipc_nametbl_subscribe(sub);
		}
	}
}

/**
 * subscr_named_msg_event - handle request to establish a new subscriber
 */

static void subscr_named_msg_event(void *usr_handle,
				   u32 port_ref,
				   struct sk_buff **buf,
				   const unchar *data,
				   u32 size,
				   u32 importance,
				   struct tipc_portid const *orig,
				   struct tipc_name_seq const *dest)
{
	static struct iovec msg_sect = {NULL, 0};

	struct subscriber *subscriber;
	u32 server_port_ref;

	/* Create subscriber object */

	subscriber = kzalloc(sizeof(struct subscriber), GFP_ATOMIC);
	if (subscriber == NULL) {
		warn("Subscriber rejected, no memory\n");
		return;
	}
	INIT_LIST_HEAD(&subscriber->subscription_list);
	INIT_LIST_HEAD(&subscriber->subscriber_list);

	/* Create server port & establish connection to subscriber */

	tipc_createport(topsrv.user_ref,
			subscriber,
			importance,
			NULL,
			NULL,
			subscr_conn_shutdown_event,
			NULL,
			NULL,
			subscr_conn_msg_event,
			NULL,
			&subscriber->port_ref);
	if (subscriber->port_ref == 0) {
		warn("Subscriber rejected, unable to create port\n");
		kfree(subscriber);
		return;
	}
	tipc_connect2port(subscriber->port_ref, orig);

	/* Lock server port (& save lock address for future use) */

	subscriber->lock = tipc_port_lock(subscriber->port_ref)->publ.lock;

	/* Add subscriber to topology server's subscriber list */

	spin_lock_bh(&topsrv.lock);
	list_add(&subscriber->subscriber_list, &topsrv.subscriber_list);
	spin_unlock_bh(&topsrv.lock);

	/* Unlock server port */

	server_port_ref = subscriber->port_ref;
	spin_unlock_bh(subscriber->lock);

	/* Send an ACK- to complete connection handshaking */

	tipc_send(server_port_ref, 1, &msg_sect);

	/* Handle optional subscription request */

	if (size != 0) {
		subscr_conn_msg_event(subscriber, server_port_ref,
				      buf, data, size);
	}
}

int tipc_subscr_start(void)
{
	struct tipc_name_seq seq = {TIPC_TOP_SRV, TIPC_TOP_SRV, TIPC_TOP_SRV};
	int res = -1;

	memset(&topsrv, 0, sizeof (topsrv));
	spin_lock_init(&topsrv.lock);
	INIT_LIST_HEAD(&topsrv.subscriber_list);

	spin_lock_bh(&topsrv.lock);
	res = tipc_attach(&topsrv.user_ref, NULL, NULL);
	if (res) {
		spin_unlock_bh(&topsrv.lock);
		return res;
	}

	res = tipc_createport(topsrv.user_ref,
			      NULL,
			      TIPC_CRITICAL_IMPORTANCE,
			      NULL,
			      NULL,
			      NULL,
			      NULL,
			      subscr_named_msg_event,
			      NULL,
			      NULL,
			      &topsrv.setup_port);
	if (res)
		goto failed;

	res = tipc_nametbl_publish_rsv(topsrv.setup_port, TIPC_NODE_SCOPE, &seq);
	if (res)
		goto failed;

	spin_unlock_bh(&topsrv.lock);
	return 0;

failed:
	err("Failed to create subscription service\n");
	tipc_detach(topsrv.user_ref);
	topsrv.user_ref = 0;
	spin_unlock_bh(&topsrv.lock);
	return res;
}

void tipc_subscr_stop(void)
{
	struct subscriber *subscriber;
	struct subscriber *subscriber_temp;
	spinlock_t *subscriber_lock;

	if (topsrv.user_ref) {
		tipc_deleteport(topsrv.setup_port);
		list_for_each_entry_safe(subscriber, subscriber_temp,
					 &topsrv.subscriber_list,
					 subscriber_list) {
			subscriber_lock = subscriber->lock;
			spin_lock_bh(subscriber_lock);
			subscr_terminate(subscriber);
			spin_unlock_bh(subscriber_lock);
		}
		tipc_detach(topsrv.user_ref);
		topsrv.user_ref = 0;
	}
}


int tipc_ispublished(struct tipc_name const *name)
{
	u32 domain = 0;

	return(tipc_nametbl_translate(name->type, name->instance,&domain) != 0);
}

	tipc_subscrp_send_event(sub, found_lower, found_upper, event, port_ref,
				node);
}

static void tipc_subscrp_timeout(unsigned long data)
{
	struct tipc_subscription *sub = (struct tipc_subscription *)data;
	struct tipc_subscriber *subscriber = sub->subscriber;

	spin_lock_bh(&subscriber->lock);
	tipc_nametbl_unsubscribe(sub);
	list_del(&sub->subscrp_list);
	spin_unlock_bh(&subscriber->lock);

	/* Notify subscriber of timeout */
	tipc_subscrp_send_event(sub, sub->evt.s.seq.lower, sub->evt.s.seq.upper,
				TIPC_SUBSCR_TIMEOUT, 0, 0);

	tipc_subscrp_put(sub);
}

static void tipc_subscrb_kref_release(struct kref *kref)
{
	kfree(container_of(kref,struct tipc_subscriber, kref));
}

static void tipc_subscrb_put(struct tipc_subscriber *subscriber)
{
	kref_put(&subscriber->kref, tipc_subscrb_kref_release);
}

static void tipc_subscrb_get(struct tipc_subscriber *subscriber)
{
	kref_get(&subscriber->kref);
}

static void tipc_subscrp_kref_release(struct kref *kref)
{
	struct tipc_subscription *sub = container_of(kref,
						     struct tipc_subscription,
						     kref);
	struct tipc_net *tn = net_generic(sub->net, tipc_net_id);
	struct tipc_subscriber *subscriber = sub->subscriber;

	atomic_dec(&tn->subscription_count);
	kfree(sub);
	tipc_subscrb_put(subscriber);
}

void tipc_subscrp_put(struct tipc_subscription *subscription)
{
	kref_put(&subscription->kref, tipc_subscrp_kref_release);
}

void tipc_subscrp_get(struct tipc_subscription *subscription)
{
	kref_get(&subscription->kref);
}

/* tipc_subscrb_subscrp_delete - delete a specific subscription or all
 * subscriptions for a given subscriber.
 */
static void tipc_subscrb_subscrp_delete(struct tipc_subscriber *subscriber,
					struct tipc_subscr *s)
{
	struct list_head *subscription_list = &subscriber->subscrp_list;
	struct tipc_subscription *sub, *temp;
	u32 timeout;

	spin_lock_bh(&subscriber->lock);
	list_for_each_entry_safe(sub, temp, subscription_list,  subscrp_list) {
		if (s && memcmp(s, &sub->evt.s, sizeof(struct tipc_subscr)))
			continue;

		timeout = htohl(sub->evt.s.timeout, sub->swap);
		if (timeout == TIPC_WAIT_FOREVER || del_timer(&sub->timer)) {
			tipc_nametbl_unsubscribe(sub);
			list_del(&sub->subscrp_list);
			tipc_subscrp_put(sub);
		}

		if (s)
			break;
	}
	spin_unlock_bh(&subscriber->lock);
}

static struct tipc_subscriber *tipc_subscrb_create(int conid)
{
	struct tipc_subscriber *subscriber;

	subscriber = kzalloc(sizeof(*subscriber), GFP_ATOMIC);
	if (!subscriber) {
		pr_warn("Subscriber rejected, no memory\n");
		return NULL;
	}
	INIT_LIST_HEAD(&subscriber->subscrp_list);
	kref_init(&subscriber->kref);
	subscriber->conid = conid;
	spin_lock_init(&subscriber->lock);

	return subscriber;
}

static void tipc_subscrb_delete(struct tipc_subscriber *subscriber)
{
	tipc_subscrb_subscrp_delete(subscriber, NULL);
	tipc_subscrb_put(subscriber);
}

static void tipc_subscrp_cancel(struct tipc_subscr *s,
				struct tipc_subscriber *subscriber)
{
	tipc_subscrb_get(subscriber);
	tipc_subscrb_subscrp_delete(subscriber, s);
	tipc_subscrb_put(subscriber);
}

static struct tipc_subscription *tipc_subscrp_create(struct net *net,
						     struct tipc_subscr *s,
						     int swap)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct tipc_subscription *sub;
	u32 filter = htohl(s->filter, swap);

	/* Refuse subscription if global limit exceeded */
	if (atomic_read(&tn->subscription_count) >= TIPC_MAX_SUBSCRIPTIONS) {
		pr_warn("Subscription rejected, limit reached (%u)\n",
			TIPC_MAX_SUBSCRIPTIONS);
		return NULL;
	}

	/* Allocate subscription object */
	sub = kmalloc(sizeof(*sub), GFP_ATOMIC);
	if (!sub) {
		pr_warn("Subscription rejected, no memory\n");
		return NULL;
	}

	/* Initialize subscription object */
	sub->net = net;
	if (((filter & TIPC_SUB_PORTS) && (filter & TIPC_SUB_SERVICE)) ||
	    (htohl(s->seq.lower, swap) > htohl(s->seq.upper, swap))) {
		pr_warn("Subscription rejected, illegal request\n");
		kfree(sub);
		return NULL;
	}

	sub->swap = swap;
	memcpy(&sub->evt.s, s, sizeof(*s));
	atomic_inc(&tn->subscription_count);
	kref_init(&sub->kref);
	return sub;
}

static void tipc_subscrp_subscribe(struct net *net, struct tipc_subscr *s,
				   struct tipc_subscriber *subscriber, int swap)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct tipc_subscription *sub = NULL;
	u32 timeout;

	sub = tipc_subscrp_create(net, s, swap);
	if (!sub)
		return tipc_conn_terminate(tn->topsrv, subscriber->conid);

	spin_lock_bh(&subscriber->lock);
	list_add(&sub->subscrp_list, &subscriber->subscrp_list);
	sub->subscriber = subscriber;
	tipc_nametbl_subscribe(sub);
	tipc_subscrb_get(subscriber);
	spin_unlock_bh(&subscriber->lock);

	setup_timer(&sub->timer, tipc_subscrp_timeout, (unsigned long)sub);
	timeout = htohl(sub->evt.s.timeout, swap);

	if (timeout != TIPC_WAIT_FOREVER)
		mod_timer(&sub->timer, jiffies + msecs_to_jiffies(timeout));
}

/* Handle one termination request for the subscriber */
static void tipc_subscrb_release_cb(int conid, void *usr_data)
{
	tipc_subscrb_delete((struct tipc_subscriber *)usr_data);
}

/* Handle one request to create a new subscription for the subscriber */
static void tipc_subscrb_rcv_cb(struct net *net, int conid,
				struct sockaddr_tipc *addr, void *usr_data,
				void *buf, size_t len)
{
	struct tipc_subscriber *subscriber = usr_data;
	struct tipc_subscr *s = (struct tipc_subscr *)buf;
	int swap;

	/* Determine subscriber's endianness */
	swap = !(s->filter & (TIPC_SUB_PORTS | TIPC_SUB_SERVICE |
			      TIPC_SUB_CANCEL));

	/* Detect & process a subscription cancellation request */
	if (s->filter & htohl(TIPC_SUB_CANCEL, swap)) {
		s->filter &= ~htohl(TIPC_SUB_CANCEL, swap);
		return tipc_subscrp_cancel(s, subscriber);
	}

	tipc_subscrp_subscribe(net, s, subscriber, swap);
}

/* Handle one request to establish a new subscriber */
static void *tipc_subscrb_connect_cb(int conid)
{
	return (void *)tipc_subscrb_create(conid);
}

int tipc_topsrv_start(struct net *net)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	const char name[] = "topology_server";
	struct tipc_server *topsrv;
	struct sockaddr_tipc *saddr;

	saddr = kzalloc(sizeof(*saddr), GFP_ATOMIC);
	if (!saddr)
		return -ENOMEM;
	saddr->family			= AF_TIPC;
	saddr->addrtype			= TIPC_ADDR_NAMESEQ;
	saddr->addr.nameseq.type	= TIPC_TOP_SRV;
	saddr->addr.nameseq.lower	= TIPC_TOP_SRV;
	saddr->addr.nameseq.upper	= TIPC_TOP_SRV;
	saddr->scope			= TIPC_NODE_SCOPE;

	topsrv = kzalloc(sizeof(*topsrv), GFP_ATOMIC);
	if (!topsrv) {
		kfree(saddr);
		return -ENOMEM;
	}
	topsrv->net			= net;
	topsrv->saddr			= saddr;
	topsrv->imp			= TIPC_CRITICAL_IMPORTANCE;
	topsrv->type			= SOCK_SEQPACKET;
	topsrv->max_rcvbuf_size		= sizeof(struct tipc_subscr);
	topsrv->tipc_conn_recvmsg	= tipc_subscrb_rcv_cb;
	topsrv->tipc_conn_new		= tipc_subscrb_connect_cb;
	topsrv->tipc_conn_release	= tipc_subscrb_release_cb;

	strncpy(topsrv->name, name, strlen(name) + 1);
	tn->topsrv = topsrv;
	atomic_set(&tn->subscription_count, 0);

	return tipc_server_start(topsrv);
}

void tipc_topsrv_stop(struct net *net)
{
	struct tipc_net *tn = net_generic(net, tipc_net_id);
	struct tipc_server *topsrv = tn->topsrv;

	tipc_server_stop(topsrv);
	kfree(topsrv->saddr);
	kfree(topsrv);
}
