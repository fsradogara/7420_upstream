// SPDX-License-Identifier: GPL-2.0
/*
 *  drivers/s390/net/qeth_l3_main.c
 *
 *    Copyright IBM Corp. 2007
 *    Copyright IBM Corp. 2007, 2009
 *    Author(s): Utz Bacher <utz.bacher@de.ibm.com>,
 *		 Frank Pavlic <fpavlic@de.ibm.com>,
 *		 Thomas Spatzier <tspat@de.ibm.com>,
 *		 Frank Blaschka <frank.blaschka@de.ibm.com>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#define KMSG_COMPONENT "qeth"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/reboot.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>

#include <net/ip.h>
#include <net/arp.h>

#include <asm/s390_rdev.h>

#include "qeth_l3.h"
#include "qeth_core_offl.h"
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/slab.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ip6_fib.h>
#include <net/ip6_checksum.h>
#include <net/iucv/af_iucv.h>
#include <linux/hashtable.h>

#include "qeth_l3.h"


static int qeth_l3_set_offline(struct ccwgroup_device *);
static int qeth_l3_stop(struct net_device *);
static void qeth_l3_set_rx_mode(struct net_device *dev);
static int qeth_l3_register_addr_entry(struct qeth_card *,
		struct qeth_ipaddr *);
static int qeth_l3_deregister_addr_entry(struct qeth_card *,
		struct qeth_ipaddr *);


static int qeth_l3_isxdigit(char *buf)
{
	while (*buf) {
		if (!isxdigit(*buf++))
			return 0;
	}
	return 1;
}

void qeth_l3_ipaddr4_to_string(const __u8 *addr, char *buf)
static void qeth_l3_ipaddr4_to_string(const __u8 *addr, char *buf)
{
	sprintf(buf, "%pI4", addr);
}

int qeth_l3_string_to_ipaddr4(const char *buf, __u8 *addr)
{
	int count = 0, rc = 0;
	int in[4];
static int qeth_l3_string_to_ipaddr4(const char *buf, __u8 *addr)
{
	int count = 0, rc = 0;
	unsigned int in[4];
	char c;

	rc = sscanf(buf, "%u.%u.%u.%u%c",
		    &in[0], &in[1], &in[2], &in[3], &c);
	if (rc != 4 && (rc != 5 || c != '\n'))
		return -EINVAL;
	for (count = 0; count < 4; count++) {
		if (in[count] > 255)
			return -EINVAL;
		addr[count] = in[count];
	}
	return 0;
}

void qeth_l3_ipaddr6_to_string(const __u8 *addr, char *buf)
{
	sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
		     ":%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		     addr[0], addr[1], addr[2], addr[3],
		     addr[4], addr[5], addr[6], addr[7],
		     addr[8], addr[9], addr[10], addr[11],
		     addr[12], addr[13], addr[14], addr[15]);
}

int qeth_l3_string_to_ipaddr6(const char *buf, __u8 *addr)
static void qeth_l3_ipaddr6_to_string(const __u8 *addr, char *buf)
{
	sprintf(buf, "%pI6", addr);
}

void qeth_l3_ipaddr_to_string(enum qeth_prot_versions proto, const __u8 *addr,
				char *buf)
{
	if (proto == QETH_PROT_IPV4)
		qeth_l3_ipaddr4_to_string(addr, buf);
	else if (proto == QETH_PROT_IPV6)
		qeth_l3_ipaddr6_to_string(addr, buf);
}

static struct qeth_ipaddr *qeth_l3_get_addr_buffer(enum qeth_prot_versions prot)
{
	struct qeth_ipaddr *addr = kmalloc(sizeof(*addr), GFP_ATOMIC);

	if (addr)
		qeth_l3_init_ipaddr(addr, QETH_IP_TYPE_NORMAL, prot);
	return addr;
}

static struct qeth_ipaddr *qeth_l3_find_addr_by_ip(struct qeth_card *card,
						   struct qeth_ipaddr *query)
{
	u64 key = qeth_l3_ipaddr_hash(query);
	struct qeth_ipaddr *addr;

	if (query->is_multicast) {
		hash_for_each_possible(card->ip_mc_htable, addr, hnode, key)
			if (qeth_l3_addr_match_ip(addr, query))
				return addr;
	} else {
		hash_for_each_possible(card->ip_htable,  addr, hnode, key)
			if (qeth_l3_addr_match_ip(addr, query))
				return addr;
	}
	return NULL;
}

static void qeth_l3_convert_addr_to_bits(u8 *addr, u8 *bits, int len)
{
	int i, j;
	u8 octet;

	for (i = 0; i < len; ++i) {
		octet = addr[i];
		for (j = 7; j >= 0; --j) {
			bits[i*8 + j] = octet & 1;
			octet >>= 1;
		}
	}
}

static int qeth_l3_is_addr_covered_by_ipato(struct qeth_card *card,
int qeth_l3_is_addr_covered_by_ipato(struct qeth_card *card,
						struct qeth_ipaddr *addr)
static bool qeth_l3_is_addr_covered_by_ipato(struct qeth_card *card,
					     struct qeth_ipaddr *addr)
{
	struct qeth_ipato_entry *ipatoe;
	u8 addr_bits[128] = {0, };
	u8 ipatoe_bits[128] = {0, };
	int rc = 0;

	if (!card->ipato.enabled)
		return false;
	if (addr->type != QETH_IP_TYPE_NORMAL)
		return false;

	qeth_l3_convert_addr_to_bits((u8 *) &addr->u, addr_bits,
				  (addr->proto == QETH_PROT_IPV4)? 4:16);
	list_for_each_entry(ipatoe, &card->ipato.entries, entry) {
		if (addr->proto != ipatoe->proto)
			continue;
		qeth_l3_convert_addr_to_bits(ipatoe->addr, ipatoe_bits,
					  (ipatoe->proto == QETH_PROT_IPV4) ?
					  4 : 16);
		if (addr->proto == QETH_PROT_IPV4)
			rc = !memcmp(addr_bits, ipatoe_bits,
				     min(32, ipatoe->mask_bits));
		else
			rc = !memcmp(addr_bits, ipatoe_bits,
				     min(128, ipatoe->mask_bits));
		if (rc)
			break;
	}
	/* invert? */
	if ((addr->proto == QETH_PROT_IPV4) && card->ipato.invert4)
		rc = !rc;
	else if ((addr->proto == QETH_PROT_IPV6) && card->ipato.invert6)
		rc = !rc;

	return rc;
}

inline int
qeth_l3_ipaddrs_is_equal(struct qeth_ipaddr *addr1, struct qeth_ipaddr *addr2)
{
	struct qeth_ipaddr *tmp, *t;
	int found = 0;

	if (card->options.sniffer)
		return 0;
	list_for_each_entry_safe(tmp, t, card->ip_tbd_list, entry) {
		if ((addr->type == QETH_IP_TYPE_DEL_ALL_MC) &&
		    (tmp->type == QETH_IP_TYPE_DEL_ALL_MC))
			return 0;
		if ((tmp->proto        == QETH_PROT_IPV4)     &&
		    (addr->proto       == QETH_PROT_IPV4)     &&
		    (tmp->type         == addr->type)         &&
		    (tmp->is_multicast == addr->is_multicast) &&
		    (tmp->u.a4.addr    == addr->u.a4.addr)    &&
		    (tmp->u.a4.mask    == addr->u.a4.mask)) {
			found = 1;
			break;
		}
		if ((tmp->proto        == QETH_PROT_IPV6)      &&
		    (addr->proto       == QETH_PROT_IPV6)      &&
		    (tmp->type         == addr->type)          &&
		    (tmp->is_multicast == addr->is_multicast)  &&
		    (tmp->u.a6.pfxlen  == addr->u.a6.pfxlen)   &&
		    (memcmp(&tmp->u.a6.addr, &addr->u.a6.addr,
			    sizeof(struct in6_addr)) == 0)) {
			found = 1;
			break;
		}
	}
	if (found) {
		if (addr->users != 0)
			tmp->users += addr->users;
		else
			tmp->users += add ? 1 : -1;
		if (tmp->users == 0) {
			list_del(&tmp->entry);
			kfree(tmp);
		}
		return 0;
	} else {
		if (addr->type == QETH_IP_TYPE_DEL_ALL_MC)
			list_add(&addr->entry, card->ip_tbd_list);
		else {
			if (addr->users == 0)
				addr->users += add ? 1 : -1;
			if (add && (addr->type == QETH_IP_TYPE_NORMAL) &&
			    qeth_l3_is_addr_covered_by_ipato(card, addr)) {
				QETH_DBF_TEXT(TRACE, 2, "tkovaddr");
				QETH_CARD_TEXT(card, 2, "tkovaddr");
				addr->set_flags |= QETH_IPA_SETIP_TAKEOVER_FLAG;
			}
			list_add_tail(&addr->entry, card->ip_tbd_list);
		}
		return 1;
	}
}

static int qeth_l3_delete_ip(struct qeth_card *card, struct qeth_ipaddr *addr)
int qeth_l3_delete_ip(struct qeth_card *card, struct qeth_ipaddr *addr)
	return addr1->proto == addr2->proto &&
		!memcmp(&addr1->u, &addr2->u, sizeof(addr1->u))  &&
		!memcmp(&addr1->mac, &addr2->mac, sizeof(addr1->mac));
}

static struct qeth_ipaddr *
qeth_l3_ip_from_hash(struct qeth_card *card, struct qeth_ipaddr *tmp_addr)
{
	struct qeth_ipaddr *addr;

	if (tmp_addr->is_multicast) {
		hash_for_each_possible(card->ip_mc_htable,  addr,
				hnode, qeth_l3_ipaddr_hash(tmp_addr))
			if (qeth_l3_ipaddrs_is_equal(tmp_addr, addr))
				return addr;
	} else {
		hash_for_each_possible(card->ip_htable,  addr,
				hnode, qeth_l3_ipaddr_hash(tmp_addr))
			if (qeth_l3_ipaddrs_is_equal(tmp_addr, addr))
				return addr;
	}

	return NULL;
}

int qeth_l3_delete_ip(struct qeth_card *card, struct qeth_ipaddr *tmp_addr)
static int qeth_l3_delete_ip(struct qeth_card *card,
			     struct qeth_ipaddr *tmp_addr)
{
	int rc = 0;
	struct qeth_ipaddr *addr;

	QETH_DBF_TEXT(TRACE, 4, "delip");

	if (addr->proto == QETH_PROT_IPV4)
		QETH_DBF_HEX(TRACE, 4, &addr->u.a4.addr, 4);
	else {
		QETH_DBF_HEX(TRACE, 4, &addr->u.a6.addr, 8);
		QETH_DBF_HEX(TRACE, 4, ((char *)&addr->u.a6.addr) + 8, 8);
	QETH_CARD_TEXT(card, 4, "delip");
	if (tmp_addr->type == QETH_IP_TYPE_RXIP)
		QETH_CARD_TEXT(card, 2, "delrxip");
	else if (tmp_addr->type == QETH_IP_TYPE_VIPA)
		QETH_CARD_TEXT(card, 2, "delvipa");
	else
		QETH_CARD_TEXT(card, 2, "delip");

	if (tmp_addr->proto == QETH_PROT_IPV4)
		QETH_CARD_HEX(card, 4, &tmp_addr->u.a4.addr, 4);
	else {
		QETH_CARD_HEX(card, 4, &tmp_addr->u.a6.addr, 8);
		QETH_CARD_HEX(card, 4, ((char *)&tmp_addr->u.a6.addr) + 8, 8);
	}

	addr = qeth_l3_find_addr_by_ip(card, tmp_addr);
	if (!addr || !qeth_l3_addr_match_all(addr, tmp_addr))
		return -ENOENT;

	addr->ref_counter--;
	if (addr->type == QETH_IP_TYPE_NORMAL && addr->ref_counter > 0)
		return rc;
	if (addr->in_progress)
		return -EINPROGRESS;

	if (qeth_card_hw_is_reachable(card))
		rc = qeth_l3_deregister_addr_entry(card, addr);

	hash_del(&addr->hnode);
	kfree(addr);

	return rc;
}

static int qeth_l3_add_ip(struct qeth_card *card, struct qeth_ipaddr *addr)
int qeth_l3_add_ip(struct qeth_card *card, struct qeth_ipaddr *addr)
int qeth_l3_add_ip(struct qeth_card *card, struct qeth_ipaddr *tmp_addr)
static int qeth_l3_add_ip(struct qeth_card *card, struct qeth_ipaddr *tmp_addr)
{
	int rc = 0;
	struct qeth_ipaddr *addr;
	char buf[40];

	QETH_DBF_TEXT(TRACE, 4, "addip");
	if (addr->proto == QETH_PROT_IPV4)
		QETH_DBF_HEX(TRACE, 4, &addr->u.a4.addr, 4);
	else {
		QETH_DBF_HEX(TRACE, 4, &addr->u.a6.addr, 8);
		QETH_DBF_HEX(TRACE, 4, ((char *)&addr->u.a6.addr) + 8, 8);
	QETH_CARD_TEXT(card, 4, "addip");
	if (tmp_addr->type == QETH_IP_TYPE_RXIP)
		QETH_CARD_TEXT(card, 2, "addrxip");
	else if (tmp_addr->type == QETH_IP_TYPE_VIPA)
		QETH_CARD_TEXT(card, 2, "addvipa");
	else
		QETH_CARD_TEXT(card, 2, "addip");

	if (tmp_addr->proto == QETH_PROT_IPV4)
		QETH_CARD_HEX(card, 4, &tmp_addr->u.a4.addr, 4);
	else {
		QETH_CARD_HEX(card, 4, &tmp_addr->u.a6.addr, 8);
		QETH_CARD_HEX(card, 4, ((char *)&tmp_addr->u.a6.addr) + 8, 8);
	}

	addr = qeth_l3_find_addr_by_ip(card, tmp_addr);
	if (addr) {
		if (tmp_addr->type != QETH_IP_TYPE_NORMAL)
			return -EADDRINUSE;
		if (qeth_l3_addr_match_all(addr, tmp_addr)) {
			addr->ref_counter++;
			return 0;
		}
		qeth_l3_ipaddr_to_string(tmp_addr->proto, (u8 *)&tmp_addr->u,
					 buf);
		dev_warn(&card->gdev->dev,
			 "Registering IP address %s failed\n", buf);
		return -EADDRINUSE;
	} else {
		addr = qeth_l3_get_addr_buffer(tmp_addr->proto);
		if (!addr)
			return -ENOMEM;

		memcpy(addr, tmp_addr, sizeof(struct qeth_ipaddr));
		addr->ref_counter = 1;

		if (qeth_l3_is_addr_covered_by_ipato(card, addr)) {
			QETH_CARD_TEXT(card, 2, "tkovaddr");
			addr->ipato = 1;
		}
		hash_add(card->ip_htable, &addr->hnode,
				qeth_l3_ipaddr_hash(addr));

		if (!qeth_card_hw_is_reachable(card)) {
			addr->disp_flag = QETH_DISP_ADDR_ADD;
			return 0;
		}

		/* qeth_l3_register_addr_entry can go to sleep
		 * if we add a IPV4 addr. It is caused by the reason
		 * that SETIP ipa cmd starts ARP staff for IPV4 addr.
		 * Thus we should unlock spinlock, and make a protection
		 * using in_progress variable to indicate that there is
		 * an hardware operation with this IPV4 address
		 */
		if (addr->proto == QETH_PROT_IPV4) {
			addr->in_progress = 1;
			spin_unlock_bh(&card->ip_lock);
			rc = qeth_l3_register_addr_entry(card, addr);
			spin_lock_bh(&card->ip_lock);
			addr->in_progress = 0;
		} else
			rc = qeth_l3_register_addr_entry(card, addr);

		if (!rc || (rc == IPA_RC_DUPLICATE_IP_ADDRESS) ||
				(rc == IPA_RC_LAN_OFFLINE)) {
			addr->disp_flag = QETH_DISP_ADDR_DO_NOTHING;
			if (addr->ref_counter < 1) {
				qeth_l3_deregister_addr_entry(card, addr);
				hash_del(&addr->hnode);
				kfree(addr);
			}
		} else {
			hash_del(&addr->hnode);
			kfree(addr);
		}
	}
	return rc;
}


static struct qeth_ipaddr *qeth_l3_get_addr_buffer(
struct qeth_ipaddr *qeth_l3_get_addr_buffer(
				enum qeth_prot_versions prot)
{
	struct qeth_ipaddr *addr;

	addr = kzalloc(sizeof(struct qeth_ipaddr), GFP_ATOMIC);
	if (!addr)
		return NULL;

	addr->type = QETH_IP_TYPE_NORMAL;
	addr->disp_flag = QETH_DISP_ADDR_DO_NOTHING;
	addr->proto = prot;

	return addr;
}

static void qeth_l3_delete_mc_addresses(struct qeth_card *card)
{
	struct qeth_ipaddr *iptodo;
	unsigned long flags;

	QETH_DBF_TEXT(TRACE, 4, "delmc");
	iptodo = qeth_l3_get_addr_buffer(QETH_PROT_IPV4);
	if (!iptodo) {
		QETH_DBF_TEXT(TRACE, 2, "dmcnomem");
	QETH_CARD_TEXT(card, 4, "delmc");
	iptodo = qeth_l3_get_addr_buffer(QETH_PROT_IPV4);
	if (!iptodo) {
		QETH_CARD_TEXT(card, 2, "dmcnomem");
		return;
	}
	iptodo->type = QETH_IP_TYPE_DEL_ALL_MC;
	spin_lock_irqsave(&card->ip_lock, flags);
	if (!__qeth_l3_insert_ip_todo(card, iptodo, 0))
		kfree(iptodo);
	spin_unlock_irqrestore(&card->ip_lock, flags);
}

/*
 * Add/remove address to/from card's ip list, i.e. try to add or remove
 * reference to/from an IP address that is already registered on the card.
 * Returns:
 *	0  address was on card and its reference count has been adjusted,
 *	   but is still > 0, so nothing has to be done
 *	   also returns 0 if card was not on card and the todo was to delete
 *	   the address -> there is also nothing to be done
 *	1  address was not on card and the todo is to add it to the card's ip
 *	   list
 *	-1 address was on card and its reference count has been decremented
 *	   to <= 0 by the todo -> address must be removed from card
 */
static int __qeth_l3_ref_ip_on_card(struct qeth_card *card,
		struct qeth_ipaddr *todo, struct qeth_ipaddr **__addr)
{
	struct qeth_ipaddr *addr;
	int found = 0;

	list_for_each_entry(addr, &card->ip_list, entry) {
		if ((addr->proto == QETH_PROT_IPV4) &&
		    (todo->proto == QETH_PROT_IPV4) &&
		    (addr->type == todo->type) &&
		    (addr->u.a4.addr == todo->u.a4.addr) &&
		    (addr->u.a4.mask == todo->u.a4.mask)) {
			found = 1;
			break;
		}
		if ((addr->proto == QETH_PROT_IPV6) &&
		    (todo->proto == QETH_PROT_IPV6) &&
		    (addr->type == todo->type) &&
		    (addr->u.a6.pfxlen == todo->u.a6.pfxlen) &&
		    (memcmp(&addr->u.a6.addr, &todo->u.a6.addr,
			    sizeof(struct in6_addr)) == 0)) {
			found = 1;
			break;
		}
	}
	if (found) {
		addr->users += todo->users;
		if (addr->users <= 0) {
			*__addr = addr;
			return -1;
		} else {
			/* for VIPA and RXIP limit refcount to 1 */
			if (addr->type != QETH_IP_TYPE_NORMAL)
				addr->users = 1;
			return 0;
		}
	}
	if (todo->users > 0) {
		/* for VIPA and RXIP limit refcount to 1 */
		if (todo->type != QETH_IP_TYPE_NORMAL)
			todo->users = 1;
		return 1;
	} else
		return 0;
}

static void __qeth_l3_delete_all_mc(struct qeth_card *card,
					unsigned long *flags)
{
	struct list_head fail_list;
	struct qeth_ipaddr *addr, *tmp;
	int rc;

	INIT_LIST_HEAD(&fail_list);
again:
	list_for_each_entry_safe(addr, tmp, &card->ip_list, entry) {
		if (addr->is_multicast) {
			list_del(&addr->entry);
			spin_unlock_irqrestore(&card->ip_lock, *flags);
			rc = qeth_l3_deregister_addr_entry(card, addr);
			spin_lock_irqsave(&card->ip_lock, *flags);
			if (!rc || (rc == IPA_RC_MC_ADDR_NOT_FOUND))
				kfree(addr);
			else
				list_add_tail(&addr->entry, &fail_list);
			goto again;
		}
	}
	list_splice(&fail_list, &card->ip_list);
}

static void qeth_l3_set_ip_addr_list(struct qeth_card *card)
void qeth_l3_set_ip_addr_list(struct qeth_card *card)
{
	struct list_head *tbd_list;
	struct qeth_ipaddr *todo, *addr;
	unsigned long flags;
	int rc;

	QETH_DBF_TEXT(TRACE, 2, "sdiplist");
	QETH_DBF_HEX(TRACE, 2, &card, sizeof(void *));

	spin_lock_irqsave(&card->ip_lock, flags);
	tbd_list = card->ip_tbd_list;
	card->ip_tbd_list = kmalloc(sizeof(struct list_head), GFP_ATOMIC);
	if (!card->ip_tbd_list) {
		QETH_DBF_TEXT(TRACE, 0, "silnomem");
	QETH_CARD_TEXT(card, 2, "sdiplist");
	QETH_CARD_HEX(card, 2, &card, sizeof(void *));

	if (!qeth_card_hw_is_reachable(card) || card->options.sniffer)
		return;

	spin_lock_irqsave(&card->ip_lock, flags);
	tbd_list = card->ip_tbd_list;
	card->ip_tbd_list = kzalloc(sizeof(struct list_head), GFP_ATOMIC);
	if (!card->ip_tbd_list) {
		QETH_CARD_TEXT(card, 0, "silnomem");
		card->ip_tbd_list = tbd_list;
		spin_unlock_irqrestore(&card->ip_lock, flags);
		return;
	} else
		INIT_LIST_HEAD(card->ip_tbd_list);

	while (!list_empty(tbd_list)) {
		todo = list_entry(tbd_list->next, struct qeth_ipaddr, entry);
		list_del(&todo->entry);
		if (todo->type == QETH_IP_TYPE_DEL_ALL_MC) {
			__qeth_l3_delete_all_mc(card, &flags);
			kfree(todo);
			continue;
		}
		rc = __qeth_l3_ref_ip_on_card(card, todo, &addr);
		if (rc == 0) {
			/* nothing to be done; only adjusted refcount */
			kfree(todo);
		} else if (rc == 1) {
			/* new entry to be added to on-card list */
			spin_unlock_irqrestore(&card->ip_lock, flags);
			rc = qeth_l3_register_addr_entry(card, todo);
			spin_lock_irqsave(&card->ip_lock, flags);
			if (!rc || (rc == IPA_RC_LAN_OFFLINE))
				list_add_tail(&todo->entry, &card->ip_list);
			else
				kfree(todo);
		} else if (rc == -1) {
			/* on-card entry to be removed */
			list_del_init(&addr->entry);
			spin_unlock_irqrestore(&card->ip_lock, flags);
			rc = qeth_l3_deregister_addr_entry(card, addr);
			spin_lock_irqsave(&card->ip_lock, flags);
			if (!rc || (rc == IPA_RC_PRIMARY_ALREADY_DEFINED))
			if (!rc || (rc == IPA_RC_IP_ADDRESS_NOT_DEFINED))
				kfree(addr);
			else
				list_add_tail(&addr->entry, &card->ip_list);
			kfree(todo);
		}
	}
	spin_unlock_irqrestore(&card->ip_lock, flags);
	kfree(tbd_list);
}

static void qeth_l3_clear_ip_list(struct qeth_card *card, int clean,
					int recover)
static void qeth_l3_clear_ip_list(struct qeth_card *card, int recover)
{
	struct qeth_ipaddr *addr, *tmp;
	unsigned long flags;
static void qeth_l3_clear_ip_htable(struct qeth_card *card, int recover)
{
	struct qeth_ipaddr *addr;
	struct hlist_node *tmp;
	int i;

	QETH_DBF_TEXT(TRACE, 4, "clearip");
	QETH_CARD_TEXT(card, 4, "clearip");

	if (recover && card->options.sniffer)
		return;

	while (!list_empty(&card->ip_list)) {
		addr = list_entry(card->ip_list.next,
				  struct qeth_ipaddr, entry);
		list_del_init(&addr->entry);
		if (clean) {
			spin_unlock_irqrestore(&card->ip_lock, flags);
			qeth_l3_deregister_addr_entry(card, addr);
			spin_lock_irqsave(&card->ip_lock, flags);
		}
		if (!recover || addr->is_multicast) {
	spin_lock_bh(&card->ip_lock);

	hash_for_each_safe(card->ip_htable, i, tmp, addr, hnode) {
		if (!recover) {
			hash_del(&addr->hnode);
			kfree(addr);
			continue;
		}
		addr->disp_flag = QETH_DISP_ADDR_ADD;
	}

	spin_unlock_bh(&card->ip_lock);

	spin_lock_bh(&card->mclock);

	hash_for_each_safe(card->ip_mc_htable, i, tmp, addr, hnode) {
		hash_del(&addr->hnode);
		kfree(addr);
	}

	spin_unlock_bh(&card->mclock);


}
static void qeth_l3_recover_ip(struct qeth_card *card)
{
	struct qeth_ipaddr *addr;
	struct hlist_node *tmp;
	int i;
	int rc;

	QETH_CARD_TEXT(card, 4, "recovrip");

	spin_lock_bh(&card->ip_lock);

	hash_for_each_safe(card->ip_htable, i, tmp, addr, hnode) {
		if (addr->disp_flag == QETH_DISP_ADDR_ADD) {
			if (addr->proto == QETH_PROT_IPV4) {
				addr->in_progress = 1;
				spin_unlock_bh(&card->ip_lock);
				rc = qeth_l3_register_addr_entry(card, addr);
				spin_lock_bh(&card->ip_lock);
				addr->in_progress = 0;
			} else
				rc = qeth_l3_register_addr_entry(card, addr);

			if (!rc) {
				addr->disp_flag = QETH_DISP_ADDR_DO_NOTHING;
				if (addr->ref_counter < 1)
					qeth_l3_delete_ip(card, addr);
			} else {
				hash_del(&addr->hnode);
				kfree(addr);
			}
		}
	}

	spin_unlock_bh(&card->ip_lock);

}

static int qeth_l3_send_setdelmc(struct qeth_card *card,
			struct qeth_ipaddr *addr, int ipacmd)
{
	int rc;
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(TRACE, 4, "setdelmc");

	iob = qeth_get_ipacmd_buffer(card, ipacmd, addr->proto);
	QETH_CARD_TEXT(card, 4, "setdelmc");

	iob = qeth_get_ipacmd_buffer(card, ipacmd, addr->proto);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);
	ether_addr_copy(cmd->data.setdelipm.mac, addr->mac);
	if (addr->proto == QETH_PROT_IPV6)
		memcpy(cmd->data.setdelipm.ip6, &addr->u.a6.addr,
		       sizeof(struct in6_addr));
	else
		memcpy(&cmd->data.setdelipm.ip4, &addr->u.a4.addr, 4);

	rc = qeth_send_ipa_cmd(card, iob, NULL, NULL);

	return rc;
}

static void qeth_l3_fill_netmask(u8 *netmask, unsigned int len)
{
	int i, j;
	for (i = 0; i < 16; i++) {
		j = (len) - (i * 8);
		if (j >= 8)
			netmask[i] = 0xff;
		else if (j > 0)
			netmask[i] = (u8)(0xFF00 >> j);
		else
			netmask[i] = 0;
	}
}

static u32 qeth_l3_get_setdelip_flags(struct qeth_ipaddr *addr, bool set)
{
	switch (addr->type) {
	case QETH_IP_TYPE_RXIP:
		return (set) ? QETH_IPA_SETIP_TAKEOVER_FLAG : 0;
	case QETH_IP_TYPE_VIPA:
		return (set) ? QETH_IPA_SETIP_VIPA_FLAG :
			       QETH_IPA_DELIP_VIPA_FLAG;
	default:
		return (set && addr->ipato) ? QETH_IPA_SETIP_TAKEOVER_FLAG : 0;
	}
}

static int qeth_l3_send_setdelip(struct qeth_card *card,
				 struct qeth_ipaddr *addr,
				 enum qeth_ipa_cmds ipacmd)
{
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;
	__u8 netmask[16];
	u32 flags;

	QETH_DBF_TEXT(TRACE, 4, "setdelip");
	QETH_DBF_TEXT_(TRACE, 4, "flags%02X", flags);

	iob = qeth_get_ipacmd_buffer(card, ipacmd, addr->proto);
	QETH_CARD_TEXT(card, 4, "setdelip");

	iob = qeth_get_ipacmd_buffer(card, ipacmd, addr->proto);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);

	flags = qeth_l3_get_setdelip_flags(addr, ipacmd == IPA_CMD_SETIP);
	QETH_CARD_TEXT_(card, 4, "flags%02X", flags);

	if (addr->proto == QETH_PROT_IPV6) {
		memcpy(cmd->data.setdelip6.ip_addr, &addr->u.a6.addr,
		       sizeof(struct in6_addr));
		qeth_l3_fill_netmask(netmask, addr->u.a6.pfxlen);
		memcpy(cmd->data.setdelip6.mask, netmask,
		       sizeof(struct in6_addr));
		cmd->data.setdelip6.flags = flags;
	} else {
		memcpy(cmd->data.setdelip4.ip_addr, &addr->u.a4.addr, 4);
		memcpy(cmd->data.setdelip4.mask, &addr->u.a4.mask, 4);
		cmd->data.setdelip4.flags = flags;
	}

	return qeth_send_ipa_cmd(card, iob, NULL, NULL);
}

static int qeth_l3_send_setrouting(struct qeth_card *card,
	enum qeth_routing_types type, enum qeth_prot_versions prot)
{
	int rc;
	struct qeth_ipa_cmd *cmd;
	struct qeth_cmd_buffer *iob;

	QETH_DBF_TEXT(TRACE, 4, "setroutg");
	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_SETRTG, prot);
	QETH_CARD_TEXT(card, 4, "setroutg");
	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_SETRTG, prot);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);
	cmd->data.setrtg.type = (type);
	rc = qeth_send_ipa_cmd(card, iob, NULL, NULL);

	return rc;
}

static void qeth_l3_correct_routing_type(struct qeth_card *card,
static int qeth_l3_correct_routing_type(struct qeth_card *card,
		enum qeth_routing_types *type, enum qeth_prot_versions prot)
{
	if (card->info.type == QETH_CARD_TYPE_IQD) {
		switch (*type) {
		case NO_ROUTER:
		case PRIMARY_CONNECTOR:
		case SECONDARY_CONNECTOR:
		case MULTICAST_ROUTER:
			return;
			return 0;
		default:
			goto out_inval;
		}
	} else {
		switch (*type) {
		case NO_ROUTER:
		case PRIMARY_ROUTER:
		case SECONDARY_ROUTER:
			return;
		case MULTICAST_ROUTER:
			if (qeth_is_ipafunc_supported(card, prot,
						      IPA_OSA_MC_ROUTER))
				return;
			return 0;
		case MULTICAST_ROUTER:
			if (qeth_is_ipafunc_supported(card, prot,
						      IPA_OSA_MC_ROUTER))
				return 0;
		default:
			goto out_inval;
		}
	}
out_inval:
	*type = NO_ROUTER;
	return -EINVAL;
}

int qeth_l3_setrouting_v4(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "setrtg4");

	qeth_l3_correct_routing_type(card, &card->options.route4.type,
				  QETH_PROT_IPV4);
	QETH_CARD_TEXT(card, 3, "setrtg4");

	rc = qeth_l3_correct_routing_type(card, &card->options.route4.type,
				  QETH_PROT_IPV4);
	if (rc)
		return rc;

	rc = qeth_l3_send_setrouting(card, card->options.route4.type,
				  QETH_PROT_IPV4);
	if (rc) {
		card->options.route4.type = NO_ROUTER;
		QETH_DBF_MESSAGE(2, "Error (0x%04x) while setting routing type"
			" on %s. Type set to 'no router'.\n", rc,
			QETH_CARD_IFNAME(card));
	}
	return rc;
}

int qeth_l3_setrouting_v6(struct qeth_card *card)
{
	int rc = 0;

	QETH_DBF_TEXT(TRACE, 3, "setrtg6");
	QETH_CARD_TEXT(card, 3, "setrtg6");

	if (!qeth_is_supported(card, IPA_IPV6))
		return 0;
	qeth_l3_correct_routing_type(card, &card->options.route6.type,
				  QETH_PROT_IPV6);
	rc = qeth_l3_correct_routing_type(card, &card->options.route6.type,
				  QETH_PROT_IPV6);
	if (rc)
		return rc;

	rc = qeth_l3_send_setrouting(card, card->options.route6.type,
				  QETH_PROT_IPV6);
	if (rc) {
		card->options.route6.type = NO_ROUTER;
		QETH_DBF_MESSAGE(2, "Error (0x%04x) while setting routing type"
			" on %s. Type set to 'no router'.\n", rc,
			QETH_CARD_IFNAME(card));
	}
	return rc;
}

/*
 * IP address takeover related functions
 */

/**
 * qeth_l3_update_ipato() - Update 'takeover' property, for all NORMAL IPs.
 *
 * Caller must hold ip_lock.
 */
void qeth_l3_update_ipato(struct qeth_card *card)
{
	struct qeth_ipaddr *addr;
	unsigned int i;

	hash_for_each(card->ip_htable, i, addr, hnode) {
		if (addr->type != QETH_IP_TYPE_NORMAL)
			continue;
		addr->ipato = qeth_l3_is_addr_covered_by_ipato(card, addr);
	}
}

static void qeth_l3_clear_ipato_list(struct qeth_card *card)
{
	struct qeth_ipato_entry *ipatoe, *tmp;

	spin_lock_bh(&card->ip_lock);

	list_for_each_entry_safe(ipatoe, tmp, &card->ipato.entries, entry) {
		list_del(&ipatoe->entry);
		kfree(ipatoe);
	}

	qeth_l3_update_ipato(card);
	spin_unlock_bh(&card->ip_lock);
}

int qeth_l3_add_ipato_entry(struct qeth_card *card,
				struct qeth_ipato_entry *new)
{
	struct qeth_ipato_entry *ipatoe;
	int rc = 0;

	QETH_DBF_TEXT(TRACE, 2, "addipato");
	QETH_CARD_TEXT(card, 2, "addipato");

	spin_lock_bh(&card->ip_lock);

	list_for_each_entry(ipatoe, &card->ipato.entries, entry) {
		if (ipatoe->proto != new->proto)
			continue;
		if (!memcmp(ipatoe->addr, new->addr,
			    (ipatoe->proto == QETH_PROT_IPV4)? 4:16) &&
		    (ipatoe->mask_bits == new->mask_bits)) {
			rc = -EEXIST;
			break;
		}
	}

	if (!rc) {
		list_add_tail(&new->entry, &card->ipato.entries);
		qeth_l3_update_ipato(card);
	}

	spin_unlock_bh(&card->ip_lock);

	return rc;
}

int qeth_l3_del_ipato_entry(struct qeth_card *card,
			    enum qeth_prot_versions proto, u8 *addr,
			    int mask_bits)
{
	struct qeth_ipato_entry *ipatoe, *tmp;
	int rc = -ENOENT;

	QETH_DBF_TEXT(TRACE, 2, "delipato");
	QETH_CARD_TEXT(card, 2, "delipato");

	spin_lock_bh(&card->ip_lock);

	list_for_each_entry_safe(ipatoe, tmp, &card->ipato.entries, entry) {
		if (ipatoe->proto != proto)
			continue;
		if (!memcmp(ipatoe->addr, addr,
			    (proto == QETH_PROT_IPV4)? 4:16) &&
		    (ipatoe->mask_bits == mask_bits)) {
			list_del(&ipatoe->entry);
			qeth_l3_update_ipato(card);
			kfree(ipatoe);
			rc = 0;
		}
	}

	spin_unlock_bh(&card->ip_lock);
}

/*
 * VIPA related functions
 */
int qeth_l3_add_vipa(struct qeth_card *card, enum qeth_prot_versions proto,
	      const u8 *addr)
{
	struct qeth_ipaddr *ipaddr;
	int rc = 0;

	ipaddr = qeth_l3_get_addr_buffer(proto);
	if (ipaddr) {
		if (proto == QETH_PROT_IPV4) {
			QETH_DBF_TEXT(TRACE, 2, "addvipa4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_DBF_TEXT(TRACE, 2, "addvipa6");
			QETH_CARD_TEXT(card, 2, "addvipa4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_CARD_TEXT(card, 2, "addvipa6");
			memcpy(&ipaddr->u.a6.addr, addr, 16);
			ipaddr->u.a6.pfxlen = 0;
		}
		ipaddr->type = QETH_IP_TYPE_VIPA;
		ipaddr->set_flags = QETH_IPA_SETIP_VIPA_FLAG;
		ipaddr->del_flags = QETH_IPA_DELIP_VIPA_FLAG;
	} else
		return -ENOMEM;

	spin_lock_bh(&card->ip_lock);

	if (qeth_l3_ip_from_hash(card, ipaddr))
		rc = -EEXIST;
	else
		qeth_l3_add_ip(card, ipaddr);

	spin_unlock_bh(&card->ip_lock);

	kfree(ipaddr);

	return rc;
}

int qeth_l3_modify_rxip_vipa(struct qeth_card *card, bool add, const u8 *ip,
			     enum qeth_ip_types type,
			     enum qeth_prot_versions proto)
{
	struct qeth_ipaddr addr;
	int rc;

	ipaddr = qeth_l3_get_addr_buffer(proto);
	if (ipaddr) {
		if (proto == QETH_PROT_IPV4) {
			QETH_DBF_TEXT(TRACE, 2, "delvipa4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_DBF_TEXT(TRACE, 2, "delvipa6");
			QETH_CARD_TEXT(card, 2, "delvipa4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_CARD_TEXT(card, 2, "delvipa6");
			memcpy(&ipaddr->u.a6.addr, addr, 16);
			ipaddr->u.a6.pfxlen = 0;
		}
		ipaddr->type = QETH_IP_TYPE_VIPA;
	} else
		return;

	spin_lock_bh(&card->ip_lock);
	qeth_l3_delete_ip(card, ipaddr);
	spin_unlock_bh(&card->ip_lock);

	kfree(ipaddr);
}

/*
 * proxy ARP related functions
 */
int qeth_l3_add_rxip(struct qeth_card *card, enum qeth_prot_versions proto,
	      const u8 *addr)
{
	struct qeth_ipaddr *ipaddr;
	int rc = 0;

	ipaddr = qeth_l3_get_addr_buffer(proto);
	if (ipaddr) {
		if (proto == QETH_PROT_IPV4) {
			QETH_DBF_TEXT(TRACE, 2, "addrxip4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_DBF_TEXT(TRACE, 2, "addrxip6");
			QETH_CARD_TEXT(card, 2, "addrxip4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_CARD_TEXT(card, 2, "addrxip6");
			memcpy(&ipaddr->u.a6.addr, addr, 16);
			ipaddr->u.a6.pfxlen = 0;
		}

		ipaddr->type = QETH_IP_TYPE_RXIP;
		ipaddr->set_flags = QETH_IPA_SETIP_TAKEOVER_FLAG;
		ipaddr->del_flags = 0;
	} else
		return -ENOMEM;

	spin_lock_bh(&card->ip_lock);

	if (qeth_l3_ip_from_hash(card, ipaddr))
		rc = -EEXIST;
	qeth_l3_init_ipaddr(&addr, type, proto);
	if (proto == QETH_PROT_IPV4)
		memcpy(&addr.u.a4.addr, ip, 4);
	else
		memcpy(&addr.u.a6.addr, ip, 16);

	spin_lock_bh(&card->ip_lock);
	rc = add ? qeth_l3_add_ip(card, &addr) : qeth_l3_delete_ip(card, &addr);
	spin_unlock_bh(&card->ip_lock);
	return rc;
}

int qeth_l3_modify_hsuid(struct qeth_card *card, bool add)
{
	struct qeth_ipaddr addr;
	int rc, i;

	ipaddr = qeth_l3_get_addr_buffer(proto);
	if (ipaddr) {
		if (proto == QETH_PROT_IPV4) {
			QETH_DBF_TEXT(TRACE, 2, "addrxip4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_DBF_TEXT(TRACE, 2, "addrxip6");
			QETH_CARD_TEXT(card, 2, "addrxip4");
			QETH_CARD_TEXT(card, 2, "delrxip4");
			memcpy(&ipaddr->u.a4.addr, addr, 4);
			ipaddr->u.a4.mask = 0;
		} else if (proto == QETH_PROT_IPV6) {
			QETH_CARD_TEXT(card, 2, "delrxip6");
			memcpy(&ipaddr->u.a6.addr, addr, 16);
			ipaddr->u.a6.pfxlen = 0;
		}
		ipaddr->type = QETH_IP_TYPE_RXIP;
	} else
		return;
	qeth_l3_init_ipaddr(&addr, QETH_IP_TYPE_NORMAL, QETH_PROT_IPV6);
	addr.u.a6.addr.s6_addr[0] = 0xfe;
	addr.u.a6.addr.s6_addr[1] = 0x80;
	for (i = 0; i < 8; i++)
		addr.u.a6.addr.s6_addr[8+i] = card->options.hsuid[i];

	spin_lock_bh(&card->ip_lock);
	rc = add ? qeth_l3_add_ip(card, &addr) : qeth_l3_delete_ip(card, &addr);
	spin_unlock_bh(&card->ip_lock);
	return rc;
}

static int qeth_l3_register_addr_entry(struct qeth_card *card,
				struct qeth_ipaddr *addr)
{
	char buf[50];
	int rc = 0;
	int cnt = 3;

	if (card->options.sniffer)
		return 0;

	if (addr->proto == QETH_PROT_IPV4) {
		QETH_DBF_TEXT(TRACE, 2, "setaddr4");
		QETH_DBF_HEX(TRACE, 3, &addr->u.a4.addr, sizeof(int));
	} else if (addr->proto == QETH_PROT_IPV6) {
		QETH_DBF_TEXT(TRACE, 2, "setaddr6");
		QETH_DBF_HEX(TRACE, 3, &addr->u.a6.addr, 8);
		QETH_DBF_HEX(TRACE, 3, ((char *)&addr->u.a6.addr) + 8, 8);
	} else {
		QETH_DBF_TEXT(TRACE, 2, "setaddr?");
		QETH_DBF_HEX(TRACE, 3, addr, sizeof(struct qeth_ipaddr));
		QETH_CARD_TEXT(card, 2, "setaddr4");
		QETH_CARD_HEX(card, 3, &addr->u.a4.addr, sizeof(int));
	} else if (addr->proto == QETH_PROT_IPV6) {
		QETH_CARD_TEXT(card, 2, "setaddr6");
		QETH_CARD_HEX(card, 3, &addr->u.a6.addr, 8);
		QETH_CARD_HEX(card, 3, ((char *)&addr->u.a6.addr) + 8, 8);
	} else {
		QETH_CARD_TEXT(card, 2, "setaddr?");
		QETH_CARD_HEX(card, 3, addr, sizeof(struct qeth_ipaddr));
	}
	do {
		if (addr->is_multicast)
			rc =  qeth_l3_send_setdelmc(card, addr, IPA_CMD_SETIPM);
		else
			rc = qeth_l3_send_setdelip(card, addr, IPA_CMD_SETIP);
		if (rc)
			QETH_DBF_TEXT(TRACE, 2, "failed");
	} while ((--cnt > 0) && rc);
	if (rc) {
		QETH_DBF_TEXT(TRACE, 2, "FAILED");
		qeth_l3_ipaddr_to_string(addr->proto, (u8 *)&addr->u, buf);
		PRINT_WARN("Could not register IP address %s (rc=0x%x/%d)\n",
			   buf, rc, rc);
			QETH_CARD_TEXT(card, 2, "failed");
	} while ((--cnt > 0) && rc);
	if (rc) {
		QETH_CARD_TEXT(card, 2, "FAILED");
		qeth_l3_ipaddr_to_string(addr->proto, (u8 *)&addr->u, buf);
		dev_warn(&card->gdev->dev,
			"Registering IP address %s failed\n", buf);
	}
	return rc;
}

static int qeth_l3_deregister_addr_entry(struct qeth_card *card,
						struct qeth_ipaddr *addr)
{
	int rc = 0;

	if (card->options.sniffer)
		return 0;

	if (addr->proto == QETH_PROT_IPV4) {
		QETH_DBF_TEXT(TRACE, 2, "deladdr4");
		QETH_DBF_HEX(TRACE, 3, &addr->u.a4.addr, sizeof(int));
	} else if (addr->proto == QETH_PROT_IPV6) {
		QETH_DBF_TEXT(TRACE, 2, "deladdr6");
		QETH_DBF_HEX(TRACE, 3, &addr->u.a6.addr, 8);
		QETH_DBF_HEX(TRACE, 3, ((char *)&addr->u.a6.addr) + 8, 8);
	} else {
		QETH_DBF_TEXT(TRACE, 2, "deladdr?");
		QETH_DBF_HEX(TRACE, 3, addr, sizeof(struct qeth_ipaddr));
		QETH_CARD_TEXT(card, 2, "deladdr4");
		QETH_CARD_HEX(card, 3, &addr->u.a4.addr, sizeof(int));
	} else if (addr->proto == QETH_PROT_IPV6) {
		QETH_CARD_TEXT(card, 2, "deladdr6");
		QETH_CARD_HEX(card, 3, &addr->u.a6.addr, 8);
		QETH_CARD_HEX(card, 3, ((char *)&addr->u.a6.addr) + 8, 8);
	} else {
		QETH_CARD_TEXT(card, 2, "deladdr?");
		QETH_CARD_HEX(card, 3, addr, sizeof(struct qeth_ipaddr));
	}
	if (addr->is_multicast)
		rc = qeth_l3_send_setdelmc(card, addr, IPA_CMD_DELIPM);
	else
		rc = qeth_l3_send_setdelip(card, addr, IPA_CMD_DELIP);
	if (rc)
		QETH_DBF_TEXT(TRACE, 2, "failed");
		QETH_CARD_TEXT(card, 2, "failed");

	return rc;
}

static u8 qeth_l3_get_qeth_hdr_flags4(int cast_type)
{
	if (cast_type == RTN_MULTICAST)
		return QETH_CAST_MULTICAST;
	if (cast_type == RTN_BROADCAST)
		return QETH_CAST_BROADCAST;
	return QETH_CAST_UNICAST;
}

static u8 qeth_l3_get_qeth_hdr_flags6(int cast_type)
{
	u8 ct = QETH_HDR_PASSTHRU | QETH_HDR_IPV6;
	if (cast_type == RTN_MULTICAST)
		return ct | QETH_CAST_MULTICAST;
	if (cast_type == RTN_ANYCAST)
		return ct | QETH_CAST_ANYCAST;
	if (cast_type == RTN_BROADCAST)
		return ct | QETH_CAST_BROADCAST;
	return ct | QETH_CAST_UNICAST;
}

static int qeth_l3_send_setadp_mode(struct qeth_card *card, __u32 command,
					__u32 mode)
{
	int rc;
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(TRACE, 4, "adpmode");

	iob = qeth_get_adapter_cmd(card, command,
				   sizeof(struct qeth_ipacmd_setadpparms));
	cmd = (struct qeth_ipa_cmd *)(iob->data+IPA_PDU_HEADER_SIZE);
	cmd->data.setadapterparms.data.mode = mode;
	rc = qeth_send_ipa_cmd(card, iob, qeth_default_setadapterparms_cb,
			       NULL);
	return rc;
}

static int qeth_l3_setadapter_hstr(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 4, "adphstr");

	if (qeth_adp_supported(card, IPA_SETADP_SET_BROADCAST_MODE)) {
		rc = qeth_l3_send_setadp_mode(card,
					IPA_SETADP_SET_BROADCAST_MODE,
					card->options.broadcast_mode);
		if (rc)
			QETH_DBF_MESSAGE(2, "couldn't set broadcast mode on "
				   "device %s: x%x\n",
				   CARD_BUS_ID(card), rc);
		rc = qeth_l3_send_setadp_mode(card,
					IPA_SETADP_ALTER_MAC_ADDRESS,
					card->options.macaddr_mode);
		if (rc)
			QETH_DBF_MESSAGE(2, "couldn't set macaddr mode on "
				   "device %s: x%x\n", CARD_BUS_ID(card), rc);
		return rc;
	}
	if (card->options.broadcast_mode == QETH_TR_BROADCAST_LOCAL)
		QETH_DBF_MESSAGE(2, "set adapter parameters not available "
			   "to set broadcast mode, using ALLRINGS "
			   "on device %s:\n", CARD_BUS_ID(card));
	if (card->options.macaddr_mode == QETH_TR_MACADDR_CANONICAL)
		QETH_DBF_MESSAGE(2, "set adapter parameters not available "
			   "to set macaddr mode, using NONCANONICAL "
			   "on device %s:\n", CARD_BUS_ID(card));
	return 0;
}

static int qeth_l3_setadapter_parms(struct qeth_card *card)
{
	int rc = 0;

	QETH_DBF_TEXT(SETUP, 2, "setadprm");

	if (!qeth_is_supported(card, IPA_SETADAPTERPARMS)) {
		PRINT_WARN("set adapter parameters not supported "
			   "on device %s.\n",
			   CARD_BUS_ID(card));
		dev_info(&card->gdev->dev,
			"set adapter parameters not supported.\n");
		QETH_DBF_TEXT(SETUP, 2, " notsupp");
		return 0;
	}
	rc = qeth_query_setadapterparms(card);
	if (rc) {
		PRINT_WARN("couldn't set adapter parameters on device %s: "
			   "x%x\n", CARD_BUS_ID(card), rc);
		QETH_DBF_MESSAGE(2, "%s couldn't set adapter parameters: "
			"0x%x\n", dev_name(&card->gdev->dev), rc);
		return rc;
	}
	if (qeth_adp_supported(card, IPA_SETADP_ALTER_MAC_ADDRESS)) {
		rc = qeth_setadpparms_change_macaddr(card);
		if (rc)
			PRINT_WARN("couldn't get MAC address on "
				   "device %s: x%x\n",
				   CARD_BUS_ID(card), rc);
	}

	if ((card->info.link_type == QETH_LINK_TYPE_HSTR) ||
	    (card->info.link_type == QETH_LINK_TYPE_LANE_TR))
		rc = qeth_l3_setadapter_hstr(card);

			dev_warn(&card->gdev->dev, "Reading the adapter MAC"
				" address failed\n");
	}

	return rc;
}

static int qeth_l3_default_setassparms_cb(struct qeth_card *card,
			struct qeth_reply *reply, unsigned long data)
{
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(TRACE, 4, "defadpcb");
	QETH_CARD_TEXT(card, 4, "defadpcb");

	cmd = (struct qeth_ipa_cmd *) data;
	if (cmd->hdr.return_code == 0) {
		cmd->hdr.return_code = cmd->data.setassparms.hdr.return_code;
		if (cmd->hdr.prot_version == QETH_PROT_IPV4)
			card->options.ipa4.enabled_funcs = cmd->hdr.ipa_enabled;
		if (cmd->hdr.prot_version == QETH_PROT_IPV6)
			card->options.ipa6.enabled_funcs = cmd->hdr.ipa_enabled;
	}
	if (cmd->data.setassparms.hdr.assist_no == IPA_INBOUND_CHECKSUM &&
	    cmd->data.setassparms.hdr.command_code == IPA_CMD_ASS_START) {
		card->info.csum_mask = cmd->data.setassparms.data.flags_32bit;
		QETH_DBF_TEXT_(TRACE, 3, "csum:%d", card->info.csum_mask);
	}
		QETH_CARD_TEXT_(card, 3, "csum:%d", card->info.csum_mask);
	}
	if (cmd->data.setassparms.hdr.assist_no == IPA_OUTBOUND_CHECKSUM &&
	    cmd->data.setassparms.hdr.command_code == IPA_CMD_ASS_START) {
		card->info.tx_csum_mask =
			cmd->data.setassparms.data.flags_32bit;
		QETH_CARD_TEXT_(card, 3, "tcsu:%d", card->info.tx_csum_mask);
	}

	return 0;
}

static struct qeth_cmd_buffer *qeth_l3_get_setassparms_cmd(
	struct qeth_card *card, enum qeth_ipa_funcs ipa_func, __u16 cmd_code,
	__u16 len, enum qeth_prot_versions prot)
{
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(TRACE, 4, "getasscm");
	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_SETASSPARMS, prot);

	cmd = (struct qeth_ipa_cmd *)(iob->data+IPA_PDU_HEADER_SIZE);
	cmd->data.setassparms.hdr.assist_no = ipa_func;
	cmd->data.setassparms.hdr.length = 8 + len;
	cmd->data.setassparms.hdr.command_code = cmd_code;
	cmd->data.setassparms.hdr.return_code = 0;
	cmd->data.setassparms.hdr.seq_no = 0;
	QETH_CARD_TEXT(card, 4, "getasscm");
	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_SETASSPARMS, prot);

	if (iob) {
		cmd = (struct qeth_ipa_cmd *)(iob->data+IPA_PDU_HEADER_SIZE);
		cmd->data.setassparms.hdr.assist_no = ipa_func;
		cmd->data.setassparms.hdr.length = 8 + len;
		cmd->data.setassparms.hdr.command_code = cmd_code;
		cmd->data.setassparms.hdr.return_code = 0;
		cmd->data.setassparms.hdr.seq_no = 0;
	}

	return iob;
}

static int qeth_l3_send_setassparms(struct qeth_card *card,
	struct qeth_cmd_buffer *iob, __u16 len, long data,
	int (*reply_cb)(struct qeth_card *, struct qeth_reply *,
		unsigned long),
	void *reply_param)
{
	int rc;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(TRACE, 4, "sendassp");

	cmd = (struct qeth_ipa_cmd *)(iob->data+IPA_PDU_HEADER_SIZE);
	if (len <= sizeof(__u32))
		cmd->data.setassparms.data.flags_32bit = (__u32) data;
	else   /* (len > sizeof(__u32)) */
		memcpy(&cmd->data.setassparms.data, (void *) data, len);

	rc = qeth_send_ipa_cmd(card, iob, reply_cb, reply_param);
	return rc;
}

#ifdef CONFIG_QETH_IPV6
static int qeth_l3_send_simple_setassparms_ipv6(struct qeth_card *card,
		enum qeth_ipa_funcs ipa_func, __u16 cmd_code)
{
	int rc;
	struct qeth_cmd_buffer *iob;

	QETH_DBF_TEXT(TRACE, 4, "simassp6");
	iob = qeth_l3_get_setassparms_cmd(card, ipa_func, cmd_code,
				       0, QETH_PROT_IPV6);
	rc = qeth_l3_send_setassparms(card, iob, 0, 0,
	QETH_CARD_TEXT(card, 4, "simassp6");
	iob = qeth_get_setassparms_cmd(card, ipa_func, cmd_code,
				       0, QETH_PROT_IPV6);
	if (!iob)
		return -ENOMEM;
	rc = qeth_send_setassparms(card, iob, 0, 0,
				   qeth_setassparms_cb, NULL);
	return rc;
}
#endif

static int qeth_l3_send_simple_setassparms(struct qeth_card *card,
		enum qeth_ipa_funcs ipa_func, __u16 cmd_code, long data)
{
	int rc;
	int length = 0;
	struct qeth_cmd_buffer *iob;

	QETH_DBF_TEXT(TRACE, 4, "simassp4");
	if (data)
		length = sizeof(__u32);
	iob = qeth_l3_get_setassparms_cmd(card, ipa_func, cmd_code,
				       length, QETH_PROT_IPV4);
	rc = qeth_l3_send_setassparms(card, iob, length, data,
				   qeth_l3_default_setassparms_cb, NULL);
	return rc;
}

static int qeth_l3_start_ipa_arp_processing(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "ipaarp");

	if (!qeth_is_supported(card, IPA_ARP_PROCESSING)) {
		PRINT_WARN("ARP processing not supported "
			   "on %s!\n", QETH_CARD_IFNAME(card));
		return 0;
	}
	rc = qeth_l3_send_simple_setassparms(card, IPA_ARP_PROCESSING,
					IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Could not start ARP processing "
			   "assist on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
	QETH_CARD_TEXT(card, 3, "ipaarp");

	if (!qeth_is_supported(card, IPA_ARP_PROCESSING)) {
		dev_info(&card->gdev->dev,
			"ARP processing not supported on %s!\n",
			QETH_CARD_IFNAME(card));
		return 0;
	}
	rc = qeth_send_simple_setassparms(card, IPA_ARP_PROCESSING,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		dev_warn(&card->gdev->dev,
			"Starting ARP processing support for %s failed\n",
			QETH_CARD_IFNAME(card));
	}
	return rc;
}

static int qeth_l3_start_ipa_ip_fragmentation(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "ipaipfrg");

	if (!qeth_is_supported(card, IPA_IP_FRAGMENTATION)) {
		PRINT_INFO("Hardware IP fragmentation not supported on %s\n",
			   QETH_CARD_IFNAME(card));
		return  -EOPNOTSUPP;
	}

	rc = qeth_l3_send_simple_setassparms(card, IPA_IP_FRAGMENTATION,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Could not start Hardware IP fragmentation "
			   "assist on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
	} else
		PRINT_INFO("Hardware IP fragmentation enabled \n");
	QETH_CARD_TEXT(card, 3, "ipaipfrg");

	if (!qeth_is_supported(card, IPA_IP_FRAGMENTATION)) {
		dev_info(&card->gdev->dev,
			"Hardware IP fragmentation not supported on %s\n",
			QETH_CARD_IFNAME(card));
		return  -EOPNOTSUPP;
	}

	rc = qeth_send_simple_setassparms(card, IPA_IP_FRAGMENTATION,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		dev_warn(&card->gdev->dev,
			"Starting IP fragmentation support for %s failed\n",
			QETH_CARD_IFNAME(card));
	} else
		dev_info(&card->gdev->dev,
			"Hardware IP fragmentation enabled \n");
	return rc;
}

static int qeth_l3_start_ipa_source_mac(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "stsrcmac");

	if (!card->options.fake_ll)
		return -EOPNOTSUPP;

	if (!qeth_is_supported(card, IPA_SOURCE_MAC)) {
		PRINT_INFO("Inbound source address not "
			   "supported on %s\n", QETH_CARD_IFNAME(card));
		return -EOPNOTSUPP;
	}

	rc = qeth_l3_send_simple_setassparms(card, IPA_SOURCE_MAC,
					  IPA_CMD_ASS_START, 0);
	if (rc)
		PRINT_WARN("Could not start inbound source "
			   "assist on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
	QETH_CARD_TEXT(card, 3, "stsrcmac");

	if (!qeth_is_supported(card, IPA_SOURCE_MAC)) {
		dev_info(&card->gdev->dev,
			"Inbound source MAC-address not supported on %s\n",
			QETH_CARD_IFNAME(card));
		return -EOPNOTSUPP;
	}

	rc = qeth_send_simple_setassparms(card, IPA_SOURCE_MAC,
					  IPA_CMD_ASS_START, 0);
	if (rc)
		dev_warn(&card->gdev->dev,
			"Starting source MAC-address support for %s failed\n",
			QETH_CARD_IFNAME(card));
	return rc;
}

static int qeth_l3_start_ipa_vlan(struct qeth_card *card)
{
	int rc = 0;

	QETH_DBF_TEXT(TRACE, 3, "strtvlan");

	if (!qeth_is_supported(card, IPA_FULL_VLAN)) {
		PRINT_WARN("VLAN not supported on %s\n",
				QETH_CARD_IFNAME(card));
		return -EOPNOTSUPP;
	}

	rc = qeth_l3_send_simple_setassparms(card, IPA_VLAN_PRIO,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Could not start vlan "
			   "assist on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
	} else {
		PRINT_INFO("VLAN enabled \n");
	QETH_CARD_TEXT(card, 3, "strtvlan");

	if (!qeth_is_supported(card, IPA_FULL_VLAN)) {
		dev_info(&card->gdev->dev,
			"VLAN not supported on %s\n", QETH_CARD_IFNAME(card));
		return -EOPNOTSUPP;
	}

	rc = qeth_send_simple_setassparms(card, IPA_VLAN_PRIO,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		dev_warn(&card->gdev->dev,
			"Starting VLAN support for %s failed\n",
			QETH_CARD_IFNAME(card));
	} else {
		dev_info(&card->gdev->dev, "VLAN enabled\n");
	}
	return rc;
}

static int qeth_l3_start_ipa_multicast(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "stmcast");

	if (!qeth_is_supported(card, IPA_MULTICASTING)) {
		PRINT_WARN("Multicast not supported on %s\n",
			   QETH_CARD_IFNAME(card));
		return -EOPNOTSUPP;
	}

	rc = qeth_l3_send_simple_setassparms(card, IPA_MULTICASTING,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Could not start multicast "
			   "assist on %s: rc=%i\n",
			   QETH_CARD_IFNAME(card), rc);
	} else {
		PRINT_INFO("Multicast enabled\n");
	QETH_CARD_TEXT(card, 3, "stmcast");

	if (!qeth_is_supported(card, IPA_MULTICASTING)) {
		dev_info(&card->gdev->dev,
			"Multicast not supported on %s\n",
			QETH_CARD_IFNAME(card));
		return -EOPNOTSUPP;
	}

	rc = qeth_send_simple_setassparms(card, IPA_MULTICASTING,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		dev_warn(&card->gdev->dev,
			"Starting multicast support for %s failed\n",
			QETH_CARD_IFNAME(card));
	} else {
		dev_info(&card->gdev->dev, "Multicast enabled\n");
		card->dev->flags |= IFF_MULTICAST;
	}
	return rc;
}

static int qeth_l3_query_ipassists_cb(struct qeth_card *card,
		struct qeth_reply *reply, unsigned long data)
{
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(SETUP, 2, "qipasscb");

	cmd = (struct qeth_ipa_cmd *) data;
	if (cmd->hdr.prot_version == QETH_PROT_IPV4) {
		card->options.ipa4.supported_funcs = cmd->hdr.ipa_supported;
		card->options.ipa4.enabled_funcs = cmd->hdr.ipa_enabled;
	} else {
		card->options.ipa6.supported_funcs = cmd->hdr.ipa_supported;
		card->options.ipa6.enabled_funcs = cmd->hdr.ipa_enabled;
	}
	QETH_DBF_TEXT(SETUP, 2, "suppenbl");
	QETH_DBF_TEXT_(SETUP, 2, "%x", cmd->hdr.ipa_supported);
	QETH_DBF_TEXT_(SETUP, 2, "%x", cmd->hdr.ipa_enabled);
	return 0;
}

static int qeth_l3_query_ipassists(struct qeth_card *card,
				enum qeth_prot_versions prot)
{
	int rc;
	struct qeth_cmd_buffer *iob;

	QETH_DBF_TEXT_(SETUP, 2, "qipassi%i", prot);
	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_QIPASSIST, prot);
	rc = qeth_send_ipa_cmd(card, iob, qeth_l3_query_ipassists_cb, NULL);
	return rc;
}

#ifdef CONFIG_QETH_IPV6
static int qeth_l3_softsetup_ipv6(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "softipv6");
	QETH_CARD_TEXT(card, 3, "softipv6");

	if (card->info.type == QETH_CARD_TYPE_IQD)
		goto out;

	rc = qeth_l3_query_ipassists(card, QETH_PROT_IPV6);
	if (rc) {
		PRINT_ERR("IPv6 query ipassist failed on %s\n",
			  QETH_CARD_IFNAME(card));
		return rc;
	}
	rc = qeth_l3_send_simple_setassparms(card, IPA_IPV6,
					  IPA_CMD_ASS_START, 3);
	if (rc) {
		PRINT_WARN("IPv6 start assist (version 4) failed "
			   "on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
	rc = qeth_query_ipassists(card, QETH_PROT_IPV6);
	if (rc) {
		dev_err(&card->gdev->dev,
			"Activating IPv6 support for %s failed\n",
			QETH_CARD_IFNAME(card));
		return rc;
	}

	if (card->info.type == QETH_CARD_TYPE_IQD)
		goto out;

	rc = qeth_send_simple_setassparms(card, IPA_IPV6,
					  IPA_CMD_ASS_START, 3);
	if (rc) {
		dev_err(&card->gdev->dev,
			"Activating IPv6 support for %s failed\n",
			QETH_CARD_IFNAME(card));
		return rc;
	}
	rc = qeth_send_simple_setassparms_v6(card, IPA_IPV6,
					     IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("IPV6 start assist (version 6) failed  "
			   "on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
		dev_err(&card->gdev->dev,
			"Activating IPv6 support for %s failed\n",
			 QETH_CARD_IFNAME(card));
		return rc;
	}
	rc = qeth_send_simple_setassparms_v6(card, IPA_PASSTHRU,
					     IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Could not enable passthrough "
			   "on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
		return rc;
	}
out:
	PRINT_INFO("IPV6 enabled \n");
		dev_warn(&card->gdev->dev,
			"Enabling the passthrough mode for %s failed\n",
			QETH_CARD_IFNAME(card));
		return rc;
	}
out:
	dev_info(&card->gdev->dev, "IPV6 enabled\n");
	return 0;
}

static int qeth_l3_start_ipa_ipv6(struct qeth_card *card)
{
	int rc = 0;

	QETH_DBF_TEXT(TRACE, 3, "strtipv6");

	if (!qeth_is_supported(card, IPA_IPV6)) {
		PRINT_WARN("IPv6 not supported on %s\n",
			   QETH_CARD_IFNAME(card));
	QETH_CARD_TEXT(card, 3, "strtipv6");

	if (!qeth_is_supported(card, IPA_IPV6)) {
		dev_info(&card->gdev->dev,
			"IPv6 not supported on %s\n", QETH_CARD_IFNAME(card));
		return 0;
	}
	return qeth_l3_softsetup_ipv6(card);
}

static int qeth_l3_start_ipa_broadcast(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "stbrdcst");
	card->info.broadcast_capable = 0;
	if (!qeth_is_supported(card, IPA_FILTERING)) {
		PRINT_WARN("Broadcast not supported on %s\n",
			   QETH_CARD_IFNAME(card));
		rc = -EOPNOTSUPP;
		goto out;
	}
	rc = qeth_l3_send_simple_setassparms(card, IPA_FILTERING,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Could not enable broadcasting filtering "
			   "on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
		goto out;
	}

	rc = qeth_l3_send_simple_setassparms(card, IPA_FILTERING,
					  IPA_CMD_ASS_CONFIGURE, 1);
	if (rc) {
		PRINT_WARN("Could not set up broadcast filtering on %s: 0x%x\n",
			   QETH_CARD_IFNAME(card), rc);
		goto out;
	}
	card->info.broadcast_capable = QETH_BROADCAST_WITH_ECHO;
	PRINT_INFO("Broadcast enabled \n");
	rc = qeth_l3_send_simple_setassparms(card, IPA_FILTERING,
					  IPA_CMD_ASS_ENABLE, 1);
	if (rc) {
		PRINT_WARN("Could not set up broadcast echo filtering on "
			   "%s: 0x%x\n", QETH_CARD_IFNAME(card), rc);
	QETH_CARD_TEXT(card, 3, "stbrdcst");
	card->info.broadcast_capable = 0;
	if (!qeth_is_supported(card, IPA_FILTERING)) {
		dev_info(&card->gdev->dev,
			"Broadcast not supported on %s\n",
			QETH_CARD_IFNAME(card));
		rc = -EOPNOTSUPP;
		goto out;
	}
	rc = qeth_send_simple_setassparms(card, IPA_FILTERING,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		dev_warn(&card->gdev->dev, "Enabling broadcast filtering for "
			"%s failed\n", QETH_CARD_IFNAME(card));
		goto out;
	}

	rc = qeth_send_simple_setassparms(card, IPA_FILTERING,
					  IPA_CMD_ASS_CONFIGURE, 1);
	if (rc) {
		dev_warn(&card->gdev->dev,
			"Setting up broadcast filtering for %s failed\n",
			QETH_CARD_IFNAME(card));
		goto out;
	}
	card->info.broadcast_capable = QETH_BROADCAST_WITH_ECHO;
	dev_info(&card->gdev->dev, "Broadcast enabled\n");
	rc = qeth_send_simple_setassparms(card, IPA_FILTERING,
					  IPA_CMD_ASS_ENABLE, 1);
	if (rc) {
		dev_warn(&card->gdev->dev, "Setting up broadcast echo "
			"filtering for %s failed\n", QETH_CARD_IFNAME(card));
		goto out;
	}
	card->info.broadcast_capable = QETH_BROADCAST_WITHOUT_ECHO;
out:
	if (card->info.broadcast_capable)
		card->dev->flags |= IFF_BROADCAST;
	else
		card->dev->flags &= ~IFF_BROADCAST;
	return rc;
}

static int qeth_l3_send_checksum_command(struct qeth_card *card)
{
	int rc;

	rc = qeth_l3_send_simple_setassparms(card, IPA_INBOUND_CHECKSUM,
					  IPA_CMD_ASS_START, 0);
	if (rc) {
		PRINT_WARN("Starting Inbound HW Checksumming failed on %s: "
			   "0x%x,\ncontinuing using Inbound SW Checksumming\n",
			   QETH_CARD_IFNAME(card), rc);
		return rc;
	}
	rc = qeth_l3_send_simple_setassparms(card, IPA_INBOUND_CHECKSUM,
					  IPA_CMD_ASS_ENABLE,
					  card->info.csum_mask);
	if (rc) {
		PRINT_WARN("Enabling Inbound HW Checksumming failed on %s: "
			   "0x%x,\ncontinuing using Inbound SW Checksumming\n",
			   QETH_CARD_IFNAME(card), rc);
		return rc;
	}
	return 0;
}

static int qeth_l3_start_ipa_checksum(struct qeth_card *card)
{
	int rc = 0;

	QETH_DBF_TEXT(TRACE, 3, "strtcsum");

	if (card->options.checksum_type == NO_CHECKSUMMING) {
		PRINT_WARN("Using no checksumming on %s.\n",
			   QETH_CARD_IFNAME(card));
		return 0;
	}
	if (card->options.checksum_type == SW_CHECKSUMMING) {
		PRINT_WARN("Using SW checksumming on %s.\n",
			   QETH_CARD_IFNAME(card));
		return 0;
	}
	if (!qeth_is_supported(card, IPA_INBOUND_CHECKSUM)) {
		PRINT_WARN("Inbound HW Checksumming not "
			   "supported on %s,\ncontinuing "
			   "using Inbound SW Checksumming\n",
			   QETH_CARD_IFNAME(card));
		card->options.checksum_type = SW_CHECKSUMMING;
		return 0;
	}
	rc = qeth_l3_send_checksum_command(card);
	if (!rc)
		PRINT_INFO("HW Checksumming (inbound) enabled \n");

	return rc;
static void qeth_l3_start_ipa_checksum(struct qeth_card *card)
{
	QETH_CARD_TEXT(card, 3, "strtcsum");
	if (qeth_is_supported(card, IPA_INBOUND_CHECKSUM)
	    && (card->dev->features & NETIF_F_RXCSUM))
		qeth_set_rx_csum(card, 1);
}

static void qeth_l3_start_ipa_tx_checksum(struct qeth_card *card)
{
	QETH_CARD_TEXT(card, 3, "strttxcs");
	qeth_start_ipa_tx_checksum(card);
}

static int qeth_l3_start_ipa_tso(struct qeth_card *card)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "sttso");

	if (!qeth_is_supported(card, IPA_OUTBOUND_TSO)) {
		PRINT_WARN("Outbound TSO not supported on %s\n",
			   QETH_CARD_IFNAME(card));
		rc = -EOPNOTSUPP;
	} else {
		rc = qeth_l3_send_simple_setassparms(card, IPA_OUTBOUND_TSO,
						IPA_CMD_ASS_START, 0);
		if (rc)
			PRINT_WARN("Could not start outbound TSO "
				   "assist on %s: rc=%i\n",
				   QETH_CARD_IFNAME(card), rc);
		else
			PRINT_INFO("Outbound TSO enabled\n");
	}
	if (rc && (card->options.large_send == QETH_LARGE_SEND_TSO)) {
		card->options.large_send = QETH_LARGE_SEND_NO;
		card->dev->features &= ~(NETIF_F_TSO | NETIF_F_SG);
	}
	QETH_CARD_TEXT(card, 3, "sttso");

	if (!qeth_is_supported(card, IPA_OUTBOUND_TSO)) {
		dev_info(&card->gdev->dev,
			"Outbound TSO not supported on %s\n",
			QETH_CARD_IFNAME(card));
		rc = -EOPNOTSUPP;
	} else {
		rc = qeth_send_simple_setassparms(card, IPA_OUTBOUND_TSO,
						  IPA_CMD_ASS_START, 0);
		if (rc)
			dev_warn(&card->gdev->dev, "Starting outbound TCP "
				"segmentation offload for %s failed\n",
				QETH_CARD_IFNAME(card));
		else
			dev_info(&card->gdev->dev,
				"Outbound TSO enabled\n");
	}
	if (rc)
		card->dev->features &= ~NETIF_F_TSO;
	return rc;
}

static int qeth_l3_start_ipassists(struct qeth_card *card)
{
	QETH_DBF_TEXT(TRACE, 3, "strtipas");
	QETH_CARD_TEXT(card, 3, "strtipas");

	if (qeth_set_access_ctrl_online(card, 0))
		return -EIO;
	qeth_l3_start_ipa_arp_processing(card);	/* go on*/
	qeth_l3_start_ipa_source_mac(card);	/* go on*/
	qeth_l3_start_ipa_vlan(card);		/* go on*/
	qeth_l3_start_ipa_multicast(card);		/* go on*/
	qeth_l3_start_ipa_ipv6(card);		/* go on*/
	qeth_l3_start_ipa_broadcast(card);		/* go on*/
	return 0;
}

static int qeth_l3_put_unique_id(struct qeth_card *card)
{

	int rc = 0;
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(TRACE, 2, "puniqeid");

	if ((card->info.unique_id & UNIQUE_ID_NOT_BY_CARD) ==
		UNIQUE_ID_NOT_BY_CARD)
		return -1;
	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_DESTROY_ADDR,
				     QETH_PROT_IPV6);
	cmd = (struct qeth_ipa_cmd *)(iob->data+IPA_PDU_HEADER_SIZE);
	*((__u16 *) &cmd->data.create_destroy_addr.unique_id[6]) =
				card->info.unique_id;
	memcpy(&cmd->data.create_destroy_addr.unique_id[0],
	       card->dev->dev_addr, OSA_ADDR_LEN);
	rc = qeth_send_ipa_cmd(card, iob, NULL, NULL);
	return rc;
}

static int qeth_l3_iqd_read_initial_mac_cb(struct qeth_card *card,
		struct qeth_reply *reply, unsigned long data)
{
	struct qeth_ipa_cmd *cmd;

	cmd = (struct qeth_ipa_cmd *) data;
	if (cmd->hdr.return_code == 0)
		ether_addr_copy(card->dev->dev_addr,
				cmd->data.create_destroy_addr.unique_id);
	else
		random_ether_addr(card->dev->dev_addr);
		eth_random_addr(card->dev->dev_addr);

	return 0;
}

static int qeth_l3_iqd_read_initial_mac(struct qeth_card *card)
{
	int rc = 0;
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(SETUP, 2, "hsrmac");

	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_CREATE_ADDR,
				     QETH_PROT_IPV6);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);
	*((__u16 *) &cmd->data.create_destroy_addr.unique_id[6]) =
			card->info.unique_id;

	rc = qeth_send_ipa_cmd(card, iob, qeth_l3_iqd_read_initial_mac_cb,
				NULL);
	return rc;
}

static int qeth_l3_get_unique_id_cb(struct qeth_card *card,
		struct qeth_reply *reply, unsigned long data)
{
	struct qeth_ipa_cmd *cmd;

	cmd = (struct qeth_ipa_cmd *) data;
	if (cmd->hdr.return_code == 0)
		card->info.unique_id = *((__u16 *)
				&cmd->data.create_destroy_addr.unique_id[6]);
	else {
		card->info.unique_id =  UNIQUE_ID_IF_CREATE_ADDR_FAILED |
					UNIQUE_ID_NOT_BY_CARD;
		PRINT_WARN("couldn't get a unique id from the card on device "
			   "%s (result=x%x), using default id. ipv6 "
			   "autoconfig on other lpars may lead to duplicate "
			   "ip addresses. please use manually "
			   "configured ones.\n",
			   CARD_BUS_ID(card), cmd->hdr.return_code);
		dev_warn(&card->gdev->dev, "The network adapter failed to "
			"generate a unique ID\n");
	}
	return 0;
}

static int qeth_l3_get_unique_id(struct qeth_card *card)
{
	int rc = 0;
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;

	QETH_DBF_TEXT(SETUP, 2, "guniqeid");

	if (!qeth_is_supported(card, IPA_IPV6)) {
		card->info.unique_id =  UNIQUE_ID_IF_CREATE_ADDR_FAILED |
					UNIQUE_ID_NOT_BY_CARD;
		return 0;
	}

	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_CREATE_ADDR,
				     QETH_PROT_IPV6);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);
	*((__u16 *) &cmd->data.create_destroy_addr.unique_id[6]) =
			card->info.unique_id;

	rc = qeth_send_ipa_cmd(card, iob, qeth_l3_get_unique_id_cb, NULL);
	return rc;
}

static void qeth_l3_get_mac_for_ipm(__u32 ipm, char *mac,
				struct net_device *dev)
{
	if (dev->type == ARPHRD_IEEE802_TR)
		ip_tr_mc_map(ipm, mac);
	else
		ip_eth_mc_map(ipm, mac);
static int
qeth_diags_trace_cb(struct qeth_card *card, struct qeth_reply *reply,
			    unsigned long data)
{
	struct qeth_ipa_cmd	   *cmd;
	__u16 rc;

	QETH_DBF_TEXT(SETUP, 2, "diastrcb");

	cmd = (struct qeth_ipa_cmd *)data;
	rc = cmd->hdr.return_code;
	if (rc)
		QETH_CARD_TEXT_(card, 2, "dxter%x", rc);
	switch (cmd->data.diagass.action) {
	case QETH_DIAGS_CMD_TRACE_QUERY:
		break;
	case QETH_DIAGS_CMD_TRACE_DISABLE:
		switch (rc) {
		case 0:
		case IPA_RC_INVALID_SUBCMD:
			card->info.promisc_mode = SET_PROMISC_MODE_OFF;
			dev_info(&card->gdev->dev, "The HiperSockets network "
				"traffic analyzer is deactivated\n");
			break;
		default:
			break;
		}
		break;
	case QETH_DIAGS_CMD_TRACE_ENABLE:
		switch (rc) {
		case 0:
			card->info.promisc_mode = SET_PROMISC_MODE_ON;
			dev_info(&card->gdev->dev, "The HiperSockets network "
				"traffic analyzer is activated\n");
			break;
		case IPA_RC_HARDWARE_AUTH_ERROR:
			dev_warn(&card->gdev->dev, "The device is not "
				"authorized to run as a HiperSockets network "
				"traffic analyzer\n");
			break;
		case IPA_RC_TRACE_ALREADY_ACTIVE:
			dev_warn(&card->gdev->dev, "A HiperSockets "
				"network traffic analyzer is already "
				"active in the HiperSockets LAN\n");
			break;
		default:
			break;
		}
		break;
	default:
		QETH_DBF_MESSAGE(2, "Unknown sniffer action (0x%04x) on %s\n",
			cmd->data.diagass.action, QETH_CARD_IFNAME(card));
	}

	return 0;
}

static int
qeth_diags_trace(struct qeth_card *card, enum qeth_diags_trace_cmds diags_cmd)
{
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd    *cmd;

	QETH_DBF_TEXT(SETUP, 2, "diagtrac");

	iob = qeth_get_ipacmd_buffer(card, IPA_CMD_SET_DIAG_ASS, 0);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);
	cmd->data.diagass.subcmd_len = 16;
	cmd->data.diagass.subcmd = QETH_DIAGS_CMD_TRACE;
	cmd->data.diagass.type = QETH_DIAGS_TYPE_HIPERSOCKET;
	cmd->data.diagass.action = diags_cmd;
	return qeth_send_ipa_cmd(card, iob, qeth_diags_trace_cb, NULL);
}

static void
qeth_l3_add_mc_to_hash(struct qeth_card *card, struct in_device *in4_dev)
{
	struct ip_mc_list *im4;
	struct qeth_ipaddr *tmp, *ipm;

	QETH_DBF_TEXT(TRACE, 4, "addmc");
	for (im4 = in4_dev->mc_list; im4; im4 = im4->next) {
	QETH_CARD_TEXT(card, 4, "addmc");

	tmp = qeth_l3_get_addr_buffer(QETH_PROT_IPV4);
	if (!tmp)
		return;

	for (im4 = rcu_dereference(in4_dev->mc_list); im4 != NULL;
	     im4 = rcu_dereference(im4->next_rcu)) {
		ip_eth_mc_map(im4->multiaddr, tmp->mac);
		tmp->u.a4.addr = be32_to_cpu(im4->multiaddr);
		tmp->is_multicast = 1;

		ipm = qeth_l3_find_addr_by_ip(card, tmp);
		if (ipm) {
			/* for mcast, by-IP match means full match */
			ipm->disp_flag = QETH_DISP_ADDR_DO_NOTHING;
		} else {
			ipm = qeth_l3_get_addr_buffer(QETH_PROT_IPV4);
			if (!ipm)
				continue;
			ether_addr_copy(ipm->mac, tmp->mac);
			ipm->u.a4.addr = be32_to_cpu(im4->multiaddr);
			ipm->is_multicast = 1;
			ipm->disp_flag = QETH_DISP_ADDR_ADD;
			hash_add(card->ip_mc_htable,
					&ipm->hnode, qeth_l3_ipaddr_hash(ipm));
		}
	}

	kfree(tmp);
}

static void qeth_l3_add_vlan_mc(struct qeth_card *card)
{
	struct in_device *in_dev;
	struct vlan_group *vg;
	int i;

	QETH_DBF_TEXT(TRACE, 4, "addmcvl");
	if (!qeth_is_supported(card, IPA_FULL_VLAN) || (card->vlangrp == NULL))
		return;

	vg = card->vlangrp;
	for (i = 0; i < VLAN_GROUP_ARRAY_LEN; i++) {
		struct net_device *netdev = vlan_group_get_device(vg, i);
		if (netdev == NULL ||
		    !(netdev->flags & IFF_UP))
			continue;
		in_dev = in_dev_get(netdev);
		if (!in_dev)
			continue;
		read_lock(&in_dev->mc_list_lock);
		qeth_l3_add_mc(card, in_dev);
		read_unlock(&in_dev->mc_list_lock);
		in_dev_put(in_dev);
/* called with rcu_read_lock */
static void qeth_l3_add_vlan_mc(struct qeth_card *card)
{
	struct in_device *in_dev;
	u16 vid;

	QETH_CARD_TEXT(card, 4, "addmcvl");

	if (!qeth_is_supported(card, IPA_FULL_VLAN))
		return;

	for_each_set_bit(vid, card->active_vlans, VLAN_N_VID) {
		struct net_device *netdev;

		netdev = __vlan_find_dev_deep_rcu(card->dev, htons(ETH_P_8021Q),
					      vid);
		if (netdev == NULL ||
		    !(netdev->flags & IFF_UP))
			continue;
		in_dev = __in_dev_get_rcu(netdev);
		if (!in_dev)
			continue;
		qeth_l3_add_mc_to_hash(card, in_dev);
	}
}

static void qeth_l3_add_multicast_ipv4(struct qeth_card *card)
{
	struct in_device *in4_dev;

	QETH_DBF_TEXT(TRACE, 4, "chkmcv4");
	in4_dev = in_dev_get(card->dev);
	if (in4_dev == NULL)
		return;
	read_lock(&in4_dev->mc_list_lock);
	qeth_l3_add_mc(card, in4_dev);
	qeth_l3_add_vlan_mc(card);
	read_unlock(&in4_dev->mc_list_lock);
	in_dev_put(in4_dev);
	QETH_CARD_TEXT(card, 4, "chkmcv4");

	rcu_read_lock();
	in4_dev = __in_dev_get_rcu(card->dev);
	if (in4_dev == NULL)
		goto unlock;
	qeth_l3_add_mc_to_hash(card, in4_dev);
	qeth_l3_add_vlan_mc(card);
unlock:
	rcu_read_unlock();
}

static void qeth_l3_add_mc6_to_hash(struct qeth_card *card,
				    struct inet6_dev *in6_dev)
{
	struct qeth_ipaddr *ipm;
	struct ifmcaddr6 *im6;
	struct qeth_ipaddr *tmp;

	QETH_DBF_TEXT(TRACE, 4, "addmc6");
	QETH_CARD_TEXT(card, 4, "addmc6");

	tmp = qeth_l3_get_addr_buffer(QETH_PROT_IPV6);
	if (!tmp)
		return;

	for (im6 = in6_dev->mc_list; im6 != NULL; im6 = im6->next) {
		ipv6_eth_mc_map(&im6->mca_addr, tmp->mac);
		memcpy(&tmp->u.a6.addr, &im6->mca_addr.s6_addr,
		       sizeof(struct in6_addr));
		tmp->is_multicast = 1;

		ipm = qeth_l3_find_addr_by_ip(card, tmp);
		if (ipm) {
			/* for mcast, by-IP match means full match */
			ipm->disp_flag = QETH_DISP_ADDR_DO_NOTHING;
			continue;
		}

		ipm = qeth_l3_get_addr_buffer(QETH_PROT_IPV6);
		if (!ipm)
			continue;

		ether_addr_copy(ipm->mac, tmp->mac);
		memcpy(&ipm->u.a6.addr, &im6->mca_addr.s6_addr,
		       sizeof(struct in6_addr));
		ipm->is_multicast = 1;
		ipm->disp_flag = QETH_DISP_ADDR_ADD;
		hash_add(card->ip_mc_htable,
				&ipm->hnode, qeth_l3_ipaddr_hash(ipm));

	}
	kfree(tmp);
}

static void qeth_l3_add_vlan_mc6(struct qeth_card *card)
{
	struct inet6_dev *in_dev;
	struct vlan_group *vg;
	int i;

	QETH_DBF_TEXT(TRACE, 4, "admc6vl");
	if (!qeth_is_supported(card, IPA_FULL_VLAN) || (card->vlangrp == NULL))
		return;

	vg = card->vlangrp;
	for (i = 0; i < VLAN_GROUP_ARRAY_LEN; i++) {
		struct net_device *netdev = vlan_group_get_device(vg, i);
/* called with rcu_read_lock */
static void qeth_l3_add_vlan_mc6(struct qeth_card *card)
{
	struct inet6_dev *in_dev;
	u16 vid;

	QETH_CARD_TEXT(card, 4, "admc6vl");

	if (!qeth_is_supported(card, IPA_FULL_VLAN))
		return;

	for_each_set_bit(vid, card->active_vlans, VLAN_N_VID) {
		struct net_device *netdev;

		netdev = __vlan_find_dev_deep_rcu(card->dev, htons(ETH_P_8021Q),
					      vid);
		if (netdev == NULL ||
		    !(netdev->flags & IFF_UP))
			continue;
		in_dev = in6_dev_get(netdev);
		if (!in_dev)
			continue;
		read_lock_bh(&in_dev->lock);
		qeth_l3_add_mc6_to_hash(card, in_dev);
		read_unlock_bh(&in_dev->lock);
		in6_dev_put(in_dev);
	}
}

static void qeth_l3_add_multicast_ipv6(struct qeth_card *card)
{
	struct inet6_dev *in6_dev;

	QETH_DBF_TEXT(TRACE, 4, "chkmcv6");
	QETH_CARD_TEXT(card, 4, "chkmcv6");

	if (!qeth_is_supported(card, IPA_IPV6))
		return ;
	in6_dev = in6_dev_get(card->dev);
	if (!in6_dev)
		return;

	rcu_read_lock();
	read_lock_bh(&in6_dev->lock);
	qeth_l3_add_mc6_to_hash(card, in6_dev);
	qeth_l3_add_vlan_mc6(card);
	read_unlock_bh(&in6_dev->lock);
	rcu_read_unlock();
	in6_dev_put(in6_dev);
}
#endif /* CONFIG_QETH_IPV6 */

static void qeth_l3_free_vlan_addresses4(struct qeth_card *card,
			unsigned short vid)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	struct qeth_ipaddr *addr;

	QETH_DBF_TEXT(TRACE, 4, "frvaddr4");

	in_dev = in_dev_get(vlan_group_get_device(card->vlangrp, vid));
	struct net_device *netdev;

	QETH_CARD_TEXT(card, 4, "frvaddr4");

	netdev = __vlan_find_dev_deep_rcu(card->dev, htons(ETH_P_8021Q), vid);
	if (!netdev)
		return;
	in_dev = in_dev_get(netdev);
	if (!in_dev)
		return;

	addr = qeth_l3_get_addr_buffer(QETH_PROT_IPV4);
	if (!addr)
		return;

	spin_lock_bh(&card->ip_lock);

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		addr->u.a4.addr = be32_to_cpu(ifa->ifa_address);
		addr->u.a4.mask = be32_to_cpu(ifa->ifa_mask);
		addr->type = QETH_IP_TYPE_NORMAL;
		qeth_l3_delete_ip(card, addr);
	}

	spin_unlock_bh(&card->ip_lock);

	kfree(addr);
	in_dev_put(in_dev);
}

static void qeth_l3_free_vlan_addresses6(struct qeth_card *card,
			unsigned short vid)
{
#ifdef CONFIG_QETH_IPV6
	struct inet6_dev *in6_dev;
	struct inet6_ifaddr *ifa;
	struct qeth_ipaddr *addr;

	QETH_DBF_TEXT(TRACE, 4, "frvaddr6");

	in6_dev = in6_dev_get(vlan_group_get_device(card->vlangrp, vid));
	if (!in6_dev)
		return;
	for (ifa = in6_dev->addr_list; ifa; ifa = ifa->lst_next) {
	struct net_device *netdev;

	QETH_CARD_TEXT(card, 4, "frvaddr6");

	netdev = __vlan_find_dev_deep_rcu(card->dev, htons(ETH_P_8021Q), vid);
	if (!netdev)
		return;

	in6_dev = in6_dev_get(netdev);
	if (!in6_dev)
		return;

	addr = qeth_l3_get_addr_buffer(QETH_PROT_IPV6);
	if (!addr)
		return;

	spin_lock_bh(&card->ip_lock);

	list_for_each_entry(ifa, &in6_dev->addr_list, if_list) {
		memcpy(&addr->u.a6.addr, &ifa->addr,
		       sizeof(struct in6_addr));
		addr->u.a6.pfxlen = ifa->prefix_len;
		addr->type = QETH_IP_TYPE_NORMAL;
		qeth_l3_delete_ip(card, addr);
	}

	spin_unlock_bh(&card->ip_lock);

	kfree(addr);
	in6_dev_put(in6_dev);
#endif /* CONFIG_QETH_IPV6 */
}

static void qeth_l3_free_vlan_addresses(struct qeth_card *card,
			unsigned short vid)
{
	if (!card->vlangrp)
		return;
	qeth_l3_free_vlan_addresses4(card, vid);
	qeth_l3_free_vlan_addresses6(card, vid);
}

static void qeth_l3_vlan_rx_register(struct net_device *dev,
			struct vlan_group *grp)
	rcu_read_lock();
	qeth_l3_free_vlan_addresses4(card, vid);
	qeth_l3_free_vlan_addresses6(card, vid);
	rcu_read_unlock();
}

static int qeth_l3_vlan_rx_add_vid(struct net_device *dev,
				   __be16 proto, u16 vid)
{
	struct qeth_card *card = dev->ml_priv;

	set_bit(vid, card->active_vlans);
	return 0;
}

static int qeth_l3_vlan_rx_kill_vid(struct net_device *dev,
				    __be16 proto, u16 vid)
{
	struct qeth_card *card = dev->ml_priv;

	QETH_DBF_TEXT(TRACE, 4, "vlanreg");
	spin_lock_irqsave(&card->vlanlock, flags);
	card->vlangrp = grp;
	spin_unlock_irqrestore(&card->vlanlock, flags);
}

static void qeth_l3_vlan_rx_add_vid(struct net_device *dev, unsigned short vid)
{
	struct net_device *vlandev;
	struct qeth_card *card = dev->ml_priv;
	struct in_device *in_dev;

	if (card->info.type == QETH_CARD_TYPE_IQD)
		return;

	vlandev = vlan_group_get_device(card->vlangrp, vid);
	vlandev->neigh_setup = qeth_l3_neigh_setup;

	in_dev = in_dev_get(vlandev);
#ifdef CONFIG_SYSCTL
	neigh_sysctl_unregister(in_dev->arp_parms);
#endif
	neigh_parms_release(&arp_tbl, in_dev->arp_parms);

	in_dev->arp_parms = neigh_parms_alloc(vlandev, &arp_tbl);
#ifdef CONFIG_SYSCTL
	neigh_sysctl_register(vlandev, in_dev->arp_parms, NET_IPV4,
			      NET_IPV4_NEIGH, "ipv4", NULL, NULL);
#endif
	in_dev_put(in_dev);
	return;
}

static void qeth_l3_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct qeth_card *card = dev->ml_priv;
	unsigned long flags;

	QETH_DBF_TEXT_(TRACE, 4, "kid:%d", vid);
	spin_lock_irqsave(&card->vlanlock, flags);
	/* unregister IP addresses of vlan device */
	qeth_l3_free_vlan_addresses(card, vid);
	vlan_group_set_device(card->vlangrp, vid, NULL);
	spin_unlock_irqrestore(&card->vlanlock, flags);
	qeth_l3_set_multicast_list(card->dev);
}

static inline __u16 qeth_l3_rebuild_skb(struct qeth_card *card,
			struct sk_buff *skb, struct qeth_hdr *hdr)
{
	unsigned short vlan_id = 0;
	__be16 prot;
	struct iphdr *ip_hdr;
	unsigned char tg_addr[MAX_ADDR_LEN];
	QETH_CARD_TEXT_(card, 4, "kid:%d", vid);

	if (qeth_wait_for_threads(card, QETH_RECOVER_THREAD)) {
		QETH_CARD_TEXT(card, 3, "kidREC");
		return 0;
	}
	clear_bit(vid, card->active_vlans);
	qeth_l3_set_rx_mode(dev);
	return 0;
}

static void qeth_l3_rebuild_skb(struct qeth_card *card, struct sk_buff *skb,
				struct qeth_hdr *hdr)
{
	if (!(hdr->hdr.l3.flags & QETH_HDR_PASSTHRU)) {
		u16 prot = (hdr->hdr.l3.flags & QETH_HDR_IPV6) ? ETH_P_IPV6 :
								 ETH_P_IP;
		unsigned char tg_addr[ETH_ALEN];

		skb_reset_network_header(skb);
		switch (hdr->hdr.l3.flags & QETH_HDR_CAST_MASK) {
		case QETH_CAST_MULTICAST:
			switch (prot) {
#ifdef CONFIG_QETH_IPV6
			case ETH_P_IPV6:
				ndisc_mc_map((struct in6_addr *)
				     skb->data + 24,
				     tg_addr, card->dev, 0);
				break;
#endif
			case ETH_P_IP:
				ip_hdr = (struct iphdr *)skb->data;
				(card->dev->type == ARPHRD_IEEE802_TR) ?
				ip_tr_mc_map(ip_hdr->daddr, tg_addr):
				ip_eth_mc_map(ip_hdr->daddr, tg_addr);
				break;
			default:
				memcpy(tg_addr, card->dev->broadcast,
					card->dev->addr_len);
			}
			if (prot == ETH_P_IP)
				ip_eth_mc_map(ip_hdr(skb)->daddr, tg_addr);
			else
				ipv6_eth_mc_map(&ipv6_hdr(skb)->daddr, tg_addr);

			card->stats.multicast++;
			break;
		case QETH_CAST_BROADCAST:
			ether_addr_copy(tg_addr, card->dev->broadcast);
			card->stats.multicast++;
			break;
		default:
			skb->pkt_type = PACKET_HOST;
			memcpy(tg_addr, card->dev->dev_addr,
				card->dev->addr_len);
		}
		card->dev->header_ops->create(skb, card->dev, prot, tg_addr,
					      "FAKELL", card->dev->addr_len);
	}

#ifdef CONFIG_TR
	if (card->dev->type == ARPHRD_IEEE802_TR)
		skb->protocol = tr_type_trans(skb, card->dev);
	else
#endif
		skb->protocol = eth_type_trans(skb, card->dev);

	if (hdr->hdr.l3.ext_flags &
	    (QETH_HDR_EXT_VLAN_FRAME | QETH_HDR_EXT_INCLUDE_VLAN_TAG)) {
		vlan_id = (hdr->hdr.l3.ext_flags & QETH_HDR_EXT_VLAN_FRAME)?
		 hdr->hdr.l3.vlan_id : *((u16 *)&hdr->hdr.l3.dest_addr[12]);
	}

	skb->ip_summed = card->options.checksum_type;
	if (card->options.checksum_type == HW_CHECKSUMMING) {
		if ((hdr->hdr.l3.ext_flags &
		      (QETH_HDR_EXT_CSUM_HDR_REQ |
		       QETH_HDR_EXT_CSUM_TRANSP_REQ)) ==
		     (QETH_HDR_EXT_CSUM_HDR_REQ |
		      QETH_HDR_EXT_CSUM_TRANSP_REQ))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = SW_CHECKSUMMING;
	}

	return vlan_id;
}

static void qeth_l3_process_inbound_buffer(struct qeth_card *card,
			    struct qeth_qdio_buffer *buf, int index)
{
	struct qdio_buffer_element *element;
	struct sk_buff *skb;
	struct qeth_hdr *hdr;
	int offset;
	__u16 vlan_tag = 0;
	unsigned int len;

	/* get first element of current buffer */
	element = (struct qdio_buffer_element *)&buf->buffer->element[0];
	offset = 0;
	if (card->options.performance_stats)
		card->perf_stats.bufs_rec++;
	while ((skb = qeth_core_get_next_skb(card, buf->buffer, &element,
				       &offset, &hdr))) {
		skb->dev = card->dev;
		/* is device UP ? */
		if (!(card->dev->flags & IFF_UP)) {
			dev_kfree_skb_any(skb);
			continue;
		}

		switch (hdr->hdr.l3.id) {
		case QETH_HEADER_TYPE_LAYER3:
			vlan_tag = qeth_l3_rebuild_skb(card, skb, hdr);
			len = skb->len;
			if (vlan_tag)
				if (card->vlangrp)
					vlan_hwaccel_rx(skb, card->vlangrp,
						vlan_tag);
				else {
					dev_kfree_skb_any(skb);
					continue;
				}
			else
				netif_rx(skb);
			break;
		default:
			dev_kfree_skb_any(skb);
			QETH_DBF_TEXT(TRACE, 3, "inbunkno");
			QETH_DBF_HEX(CTRL, 3, hdr, QETH_DBF_CTRL_LEN);
			continue;
		}

		card->dev->last_rx = jiffies;
		card->stats.rx_packets++;
		card->stats.rx_bytes += len;
	}
			if (card->options.sniffer)
				skb->pkt_type = PACKET_OTHERHOST;
			ether_addr_copy(tg_addr, card->dev->dev_addr);
		}

		if (hdr->hdr.l3.ext_flags & QETH_HDR_EXT_SRC_MAC_ADDR)
			card->dev->header_ops->create(skb, card->dev, prot,
				tg_addr, &hdr->hdr.l3.next_hop.rx.src_mac,
				skb->len);
		else
			card->dev->header_ops->create(skb, card->dev, prot,
				tg_addr, "FAKELL", skb->len);
	}

	skb->protocol = eth_type_trans(skb, card->dev);

	/* copy VLAN tag from hdr into skb */
	if (!card->options.sniffer &&
	    (hdr->hdr.l3.ext_flags & (QETH_HDR_EXT_VLAN_FRAME |
				      QETH_HDR_EXT_INCLUDE_VLAN_TAG))) {
		u16 tag = (hdr->hdr.l3.ext_flags & QETH_HDR_EXT_VLAN_FRAME) ?
				hdr->hdr.l3.vlan_id :
				hdr->hdr.l3.next_hop.rx.vlan_id;
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), tag);
	}

	qeth_rx_csum(card, skb, hdr->hdr.l3.ext_flags);
}

static int qeth_l3_process_inbound_buffer(struct qeth_card *card,
				int budget, int *done)
{
	int work_done = 0;
	struct sk_buff *skb;
	struct qeth_hdr *hdr;
	unsigned int len;
	__u16 magic;

	*done = 0;
	WARN_ON_ONCE(!budget);
	while (budget) {
		skb = qeth_core_get_next_skb(card,
			&card->qdio.in_q->bufs[card->rx.b_index],
			&card->rx.b_element, &card->rx.e_offset, &hdr);
		if (!skb) {
			*done = 1;
			break;
		}
		switch (hdr->hdr.l3.id) {
		case QETH_HEADER_TYPE_LAYER3:
			magic = *(__u16 *)skb->data;
			if ((card->info.type == QETH_CARD_TYPE_IQD) &&
			    (magic == ETH_P_AF_IUCV)) {
				skb->protocol = cpu_to_be16(ETH_P_AF_IUCV);
				len = skb->len;
				card->dev->header_ops->create(skb, card->dev, 0,
					card->dev->dev_addr, "FAKELL", len);
				skb_reset_mac_header(skb);
				netif_receive_skb(skb);
			} else {
				qeth_l3_rebuild_skb(card, skb, hdr);
				len = skb->len;
				napi_gro_receive(&card->napi, skb);
			}
			break;
		case QETH_HEADER_TYPE_LAYER2: /* for HiperSockets sniffer */
			skb->protocol = eth_type_trans(skb, skb->dev);
			len = skb->len;
			netif_receive_skb(skb);
			break;
		default:
			dev_kfree_skb_any(skb);
			QETH_CARD_TEXT(card, 3, "inbunkno");
			QETH_DBF_HEX(CTRL, 3, hdr, sizeof(*hdr));
			continue;
		}
		work_done++;
		budget--;
		card->stats.rx_packets++;
		card->stats.rx_bytes += len;
	}
	return work_done;
}

static int qeth_l3_verify_vlan_dev(struct net_device *dev,
			struct qeth_card *card)
{
	int rc = 0;
	struct vlan_group *vg;
	int i;

	vg = card->vlangrp;
	if (!vg)
		return rc;

	for (i = 0; i < VLAN_GROUP_ARRAY_LEN; i++) {
		if (vlan_group_get_device(vg, i) == dev) {
	u16 vid;

	for_each_set_bit(vid, card->active_vlans, VLAN_N_VID) {
		struct net_device *netdev;

		rcu_read_lock();
		netdev = __vlan_find_dev_deep_rcu(card->dev, htons(ETH_P_8021Q),
					      vid);
		rcu_read_unlock();
		if (netdev == dev) {
			rc = QETH_VLAN_CARD;
			break;
		}
	}

	if (rc && !(vlan_dev_real_dev(dev)->ml_priv == (void *)card))
		return 0;

	return rc;
}

static int qeth_l3_verify_dev(struct net_device *dev)
{
	struct qeth_card *card;
	int rc = 0;
	unsigned long flags;

	read_lock_irqsave(&qeth_core_card_list.rwlock, flags);
	list_for_each_entry(card, &qeth_core_card_list.list, list) {
		if (card->dev == dev) {
			rc = QETH_REAL_CARD;
			break;
		}
		rc = qeth_l3_verify_vlan_dev(dev, card);
		if (rc)
			break;
	}
	read_unlock_irqrestore(&qeth_core_card_list.rwlock, flags);

	return rc;
}

static struct qeth_card *qeth_l3_get_card_from_dev(struct net_device *dev)
{
	struct qeth_card *card = NULL;
	int rc;

	rc = qeth_l3_verify_dev(dev);
	if (rc == QETH_REAL_CARD)
		card = dev->ml_priv;
	else if (rc == QETH_VLAN_CARD)
		card = vlan_dev_real_dev(dev)->ml_priv;
	if (card && card->options.layer2)
		card = NULL;
	QETH_DBF_TEXT_(TRACE, 4, "%d", rc);
	return card ;
}

static int qeth_l3_stop_card(struct qeth_card *card, int recovery_mode)
{
	int rc = 0;

	if (card)
		QETH_CARD_TEXT_(card, 4, "%d", rc);
	return card ;
}

static void qeth_l3_stop_card(struct qeth_card *card, int recovery_mode)
{
	QETH_DBF_TEXT(SETUP, 2, "stopcard");
	QETH_DBF_HEX(SETUP, 2, &card, sizeof(void *));

	qeth_set_allowed_threads(card, 0, 1);
	if (qeth_wait_for_threads(card, ~QETH_RECOVER_THREAD))
		return -ERESTARTSYS;
	if (card->options.sniffer &&
	    (card->info.promisc_mode == SET_PROMISC_MODE_ON))
		qeth_diags_trace(card, QETH_DIAGS_CMD_TRACE_DISABLE);
	if (card->read.state == CH_STATE_UP &&
	    card->write.state == CH_STATE_UP &&
	    (card->state == CARD_STATE_UP)) {
		if (recovery_mode)
			qeth_l3_stop(card->dev);
		else {
			rtnl_lock();
			dev_close(card->dev);
			rtnl_unlock();
		}
		if (!card->use_hard_stop) {
			rc = qeth_send_stoplan(card);
			if (rc)
				QETH_DBF_TEXT_(SETUP, 2, "1err%d", rc);
		}
		card->state = CARD_STATE_SOFTSETUP;
	}
	if (card->state == CARD_STATE_SOFTSETUP) {
		qeth_l3_clear_ip_list(card, !card->use_hard_stop, 1);
		card->state = CARD_STATE_SOFTSETUP;
	}
	if (card->state == CARD_STATE_SOFTSETUP) {
		qeth_l3_clear_ip_htable(card, 1);
		qeth_clear_ipacmd_list(card);
		card->state = CARD_STATE_HARDSETUP;
	}
	if (card->state == CARD_STATE_HARDSETUP) {
		if (!card->use_hard_stop &&
		    (card->info.type != QETH_CARD_TYPE_IQD)) {
			rc = qeth_l3_put_unique_id(card);
			if (rc)
				QETH_DBF_TEXT_(SETUP, 2, "2err%d", rc);
		}
		qeth_qdio_clear_card(card, 0);
		qeth_clear_qdio_buffers(card);
		qeth_clear_working_pool_list(card);
		card->state = CARD_STATE_DOWN;
	}
	if (card->state == CARD_STATE_DOWN) {
		qeth_clear_cmd_buffers(&card->read);
		qeth_clear_cmd_buffers(&card->write);
	}
	card->use_hard_stop = 0;
	return rc;
}

/*
 * test for and Switch promiscuous mode (on or off)
 *  either for guestlan or HiperSocket Sniffer
 */
static void
qeth_l3_handle_promisc_mode(struct qeth_card *card)
{
	struct net_device *dev = card->dev;

	if (((dev->flags & IFF_PROMISC) &&
	     (card->info.promisc_mode == SET_PROMISC_MODE_ON)) ||
	    (!(dev->flags & IFF_PROMISC) &&
	     (card->info.promisc_mode == SET_PROMISC_MODE_OFF)))
		return;

	if (card->info.guestlan) {		/* Guestlan trace */
		if (qeth_adp_supported(card, IPA_SETADP_SET_PROMISC_MODE))
			qeth_setadp_promisc_mode(card);
	} else if (card->options.sniffer &&	/* HiperSockets trace */
		   qeth_adp_supported(card, IPA_SETADP_SET_DIAG_ASSIST)) {
		if (dev->flags & IFF_PROMISC) {
			QETH_CARD_TEXT(card, 3, "+promisc");
			qeth_diags_trace(card, QETH_DIAGS_CMD_TRACE_ENABLE);
		} else {
			QETH_CARD_TEXT(card, 3, "-promisc");
			qeth_diags_trace(card, QETH_DIAGS_CMD_TRACE_DISABLE);
		}
	}
}

static void qeth_l3_set_rx_mode(struct net_device *dev)
{
	struct qeth_card *card = dev->ml_priv;
	struct qeth_ipaddr *addr;
	struct hlist_node *tmp;
	int i, rc;

	QETH_DBF_TEXT(TRACE, 3, "setmulti");
	qeth_l3_delete_mc_addresses(card);
	qeth_l3_add_multicast_ipv4(card);
#ifdef CONFIG_QETH_IPV6
	qeth_l3_add_multicast_ipv6(card);
#endif
	qeth_l3_set_ip_addr_list(card);
	if (!qeth_adp_supported(card, IPA_SETADP_SET_PROMISC_MODE))
		return;
	qeth_setadp_promisc_mode(card);
	QETH_CARD_TEXT(card, 3, "setmulti");
	if (qeth_threads_running(card, QETH_RECOVER_THREAD) &&
	    (card->state != CARD_STATE_UP))
		return;
	if (!card->options.sniffer) {
		spin_lock_bh(&card->mclock);

		qeth_l3_add_multicast_ipv4(card);
		qeth_l3_add_multicast_ipv6(card);

		hash_for_each_safe(card->ip_mc_htable, i, tmp, addr, hnode) {
			switch (addr->disp_flag) {
			case QETH_DISP_ADDR_DELETE:
				rc = qeth_l3_deregister_addr_entry(card, addr);
				if (!rc || rc == IPA_RC_MC_ADDR_NOT_FOUND) {
					hash_del(&addr->hnode);
					kfree(addr);
				}
				break;
			case QETH_DISP_ADDR_ADD:
				rc = qeth_l3_register_addr_entry(card, addr);
				if (rc && rc != IPA_RC_LAN_OFFLINE) {
					hash_del(&addr->hnode);
					kfree(addr);
					break;
				}
				addr->ref_counter = 1;
				/* fall through */
			default:
				/* for next call to set_rx_mode(): */
				addr->disp_flag = QETH_DISP_ADDR_DELETE;
			}
		}

		spin_unlock_bh(&card->mclock);

		if (!qeth_adp_supported(card, IPA_SETADP_SET_PROMISC_MODE))
			return;
	}
	qeth_l3_handle_promisc_mode(card);
}

static const char *qeth_l3_arp_get_error_cause(int *rc)
{
	switch (*rc) {
	case QETH_IPA_ARP_RC_FAILED:
		*rc = -EIO;
		return "operation failed";
	case QETH_IPA_ARP_RC_NOTSUPP:
		*rc = -EOPNOTSUPP;
		return "operation not supported";
	case QETH_IPA_ARP_RC_OUT_OF_RANGE:
		*rc = -EINVAL;
		return "argument out of range";
	case QETH_IPA_ARP_RC_Q_NOTSUPP:
		*rc = -EOPNOTSUPP;
		return "query operation not supported";
	case QETH_IPA_ARP_RC_Q_NO_DATA:
		*rc = -ENOENT;
		return "no query data available";
	default:
		return "unknown error";
	}
}

static int qeth_l3_arp_set_no_entries(struct qeth_card *card, int no_entries)
{
	int tmp;
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "arpstnoe");
	QETH_CARD_TEXT(card, 3, "arpstnoe");

	/*
	 * currently GuestLAN only supports the ARP assist function
	 * IPA_CMD_ASS_ARP_QUERY_INFO, but not IPA_CMD_ASS_ARP_SET_NO_ENTRIES;
	 * thus we say EOPNOTSUPP for this ARP function
	 */
	if (card->info.guestlan)
		return -EOPNOTSUPP;
	if (!qeth_is_supported(card, IPA_ARP_PROCESSING)) {
		return -EOPNOTSUPP;
	}
	rc = qeth_l3_send_simple_setassparms(card, IPA_ARP_PROCESSING,
	rc = qeth_send_simple_setassparms(card, IPA_ARP_PROCESSING,
					  IPA_CMD_ASS_ARP_SET_NO_ENTRIES,
					  no_entries);
	if (rc) {
		tmp = rc;
		QETH_DBF_MESSAGE(2, "Could not set number of ARP entries on "
			"%s: %s (0x%x/%d)\n", QETH_CARD_IFNAME(card),
			qeth_l3_arp_get_error_cause(&rc), tmp, tmp);
	}
	return rc;
}

static void qeth_l3_copy_arp_entries_stripped(struct qeth_arp_query_info *qinfo,
		struct qeth_arp_query_data *qdata, int entry_size,
		int uentry_size)
{
	char *entry_ptr;
	char *uentry_ptr;
	int i;

	entry_ptr = (char *)&qdata->data;
	uentry_ptr = (char *)(qinfo->udata + qinfo->udata_offset);
	for (i = 0; i < qdata->no_entries; ++i) {
		/* strip off 32 bytes "media specific information" */
		memcpy(uentry_ptr, (entry_ptr + 32), entry_size - 32);
		entry_ptr += entry_size;
		uentry_ptr += uentry_size;
	}
static __u32 get_arp_entry_size(struct qeth_card *card,
			struct qeth_arp_query_data *qdata,
			struct qeth_arp_entrytype *type, __u8 strip_entries)
{
	__u32 rc;
	__u8 is_hsi;

	is_hsi = qdata->reply_bits == 5;
	if (type->ip == QETHARP_IP_ADDR_V4) {
		QETH_CARD_TEXT(card, 4, "arpev4");
		if (strip_entries) {
			rc = is_hsi ? sizeof(struct qeth_arp_qi_entry5_short) :
				sizeof(struct qeth_arp_qi_entry7_short);
		} else {
			rc = is_hsi ? sizeof(struct qeth_arp_qi_entry5) :
				sizeof(struct qeth_arp_qi_entry7);
		}
	} else if (type->ip == QETHARP_IP_ADDR_V6) {
		QETH_CARD_TEXT(card, 4, "arpev6");
		if (strip_entries) {
			rc = is_hsi ?
				sizeof(struct qeth_arp_qi_entry5_short_ipv6) :
				sizeof(struct qeth_arp_qi_entry7_short_ipv6);
		} else {
			rc = is_hsi ?
				sizeof(struct qeth_arp_qi_entry5_ipv6) :
				sizeof(struct qeth_arp_qi_entry7_ipv6);
		}
	} else {
		QETH_CARD_TEXT(card, 4, "arpinv");
		rc = 0;
	}

	return rc;
}

static int arpentry_matches_prot(struct qeth_arp_entrytype *type, __u16 prot)
{
	return (type->ip == QETHARP_IP_ADDR_V4 && prot == QETH_PROT_IPV4) ||
		(type->ip == QETHARP_IP_ADDR_V6 && prot == QETH_PROT_IPV6);
}

static int qeth_l3_arp_query_cb(struct qeth_card *card,
		struct qeth_reply *reply, unsigned long data)
{
	struct qeth_ipa_cmd *cmd;
	struct qeth_arp_query_data *qdata;
	struct qeth_arp_query_info *qinfo;
	int entry_size;
	int uentry_size;
	int i;

	QETH_DBF_TEXT(TRACE, 4, "arpquecb");

	qinfo = (struct qeth_arp_query_info *) reply->param;
	cmd = (struct qeth_ipa_cmd *) data;
	if (cmd->hdr.return_code) {
		QETH_DBF_TEXT_(TRACE, 4, "qaer1%i", cmd->hdr.return_code);
	int i;
	int e;
	int entrybytes_done;
	int stripped_bytes;
	__u8 do_strip_entries;

	QETH_CARD_TEXT(card, 3, "arpquecb");

	qinfo = (struct qeth_arp_query_info *) reply->param;
	cmd = (struct qeth_ipa_cmd *) data;
	QETH_CARD_TEXT_(card, 4, "%i", cmd->hdr.prot_version);
	if (cmd->hdr.return_code) {
		QETH_CARD_TEXT(card, 4, "arpcberr");
		QETH_CARD_TEXT_(card, 4, "%i", cmd->hdr.return_code);
		return 0;
	}
	if (cmd->data.setassparms.hdr.return_code) {
		cmd->hdr.return_code = cmd->data.setassparms.hdr.return_code;
		QETH_DBF_TEXT_(TRACE, 4, "qaer2%i", cmd->hdr.return_code);
		return 0;
	}
	qdata = &cmd->data.setassparms.data.query_arp;
	switch (qdata->reply_bits) {
	case 5:
		uentry_size = entry_size = sizeof(struct qeth_arp_qi_entry5);
		if (qinfo->mask_bits & QETH_QARP_STRIP_ENTRIES)
			uentry_size = sizeof(struct qeth_arp_qi_entry5_short);
		break;
	case 7:
		/* fall through to default */
	default:
		/* tr is the same as eth -> entry7 */
		uentry_size = entry_size = sizeof(struct qeth_arp_qi_entry7);
		if (qinfo->mask_bits & QETH_QARP_STRIP_ENTRIES)
			uentry_size = sizeof(struct qeth_arp_qi_entry7_short);
		break;
	}
	/* check if there is enough room in userspace */
	if ((qinfo->udata_len - qinfo->udata_offset) <
			qdata->no_entries * uentry_size){
		QETH_DBF_TEXT_(TRACE, 4, "qaer3%i", -ENOMEM);
		cmd->hdr.return_code = -ENOMEM;
		goto out_error;
	}
	QETH_DBF_TEXT_(TRACE, 4, "anore%i",
		       cmd->data.setassparms.hdr.number_of_replies);
	QETH_DBF_TEXT_(TRACE, 4, "aseqn%i", cmd->data.setassparms.hdr.seq_no);
	QETH_DBF_TEXT_(TRACE, 4, "anoen%i", qdata->no_entries);

	if (qinfo->mask_bits & QETH_QARP_STRIP_ENTRIES) {
		/* strip off "media specific information" */
		qeth_l3_copy_arp_entries_stripped(qinfo, qdata, entry_size,
					       uentry_size);
	} else
		/*copy entries to user buffer*/
		memcpy(qinfo->udata + qinfo->udata_offset,
		       (char *)&qdata->data, qdata->no_entries*uentry_size);

	qinfo->no_entries += qdata->no_entries;
	qinfo->udata_offset += (qdata->no_entries*uentry_size);
		QETH_CARD_TEXT(card, 4, "setaperr");
		QETH_CARD_TEXT_(card, 4, "%i", cmd->hdr.return_code);
		return 0;
	}
	qdata = &cmd->data.setassparms.data.query_arp;
	QETH_CARD_TEXT_(card, 4, "anoen%i", qdata->no_entries);

	do_strip_entries = (qinfo->mask_bits & QETH_QARP_STRIP_ENTRIES) > 0;
	stripped_bytes = do_strip_entries ? QETH_QARP_MEDIASPECIFIC_BYTES : 0;
	entrybytes_done = 0;
	for (e = 0; e < qdata->no_entries; ++e) {
		char *cur_entry;
		__u32 esize;
		struct qeth_arp_entrytype *etype;

		cur_entry = &qdata->data + entrybytes_done;
		etype = &((struct qeth_arp_qi_entry5 *) cur_entry)->type;
		if (!arpentry_matches_prot(etype, cmd->hdr.prot_version)) {
			QETH_CARD_TEXT(card, 4, "pmis");
			QETH_CARD_TEXT_(card, 4, "%i", etype->ip);
			break;
		}
		esize = get_arp_entry_size(card, qdata, etype,
			do_strip_entries);
		QETH_CARD_TEXT_(card, 5, "esz%i", esize);
		if (!esize)
			break;

		if ((qinfo->udata_len - qinfo->udata_offset) < esize) {
			QETH_CARD_TEXT_(card, 4, "qaer3%i", -ENOMEM);
			cmd->hdr.return_code = IPA_RC_ENOMEM;
			goto out_error;
		}

		memcpy(qinfo->udata + qinfo->udata_offset,
			&qdata->data + entrybytes_done + stripped_bytes,
			esize);
		entrybytes_done += esize + stripped_bytes;
		qinfo->udata_offset += esize;
		++qinfo->no_entries;
	}
	/* check if all replies received ... */
	if (cmd->data.setassparms.hdr.seq_no <
	    cmd->data.setassparms.hdr.number_of_replies)
		return 1;
	QETH_CARD_TEXT_(card, 4, "nove%i", qinfo->no_entries);
	memcpy(qinfo->udata, &qinfo->no_entries, 4);
	/* keep STRIP_ENTRIES flag so the user program can distinguish
	 * stripped entries from normal ones */
	if (qinfo->mask_bits & QETH_QARP_STRIP_ENTRIES)
		qdata->reply_bits |= QETH_QARP_STRIP_ENTRIES;
	memcpy(qinfo->udata + QETH_QARP_MASK_OFFSET, &qdata->reply_bits, 2);
	QETH_CARD_TEXT_(card, 4, "rc%i", 0);
	return 0;
out_error:
	i = 0;
	memcpy(qinfo->udata, &i, 4);
	return 0;
}

static int qeth_l3_send_ipa_arp_cmd(struct qeth_card *card,
		struct qeth_cmd_buffer *iob, int len,
		int (*reply_cb)(struct qeth_card *, struct qeth_reply *,
			unsigned long),
		void *reply_param)
{
	QETH_DBF_TEXT(TRACE, 4, "sendarp");
	QETH_CARD_TEXT(card, 4, "sendarp");

	memcpy(iob->data, IPA_PDU_HEADER, IPA_PDU_HEADER_SIZE);
	memcpy(QETH_IPA_CMD_DEST_ADDR(iob->data),
	       &card->token.ulp_connection_r, QETH_MPC_TOKEN_LENGTH);
	return qeth_send_control_data(card, IPA_PDU_HEADER_SIZE + len, iob,
				      reply_cb, reply_param);
}

static int qeth_l3_arp_query(struct qeth_card *card, char __user *udata)
{
	struct qeth_cmd_buffer *iob;
	struct qeth_arp_query_info qinfo = {0, };
	int tmp;
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "arpquery");

	if (!qeth_is_supported(card,/*IPA_QUERY_ARP_ADDR_INFO*/
			       IPA_ARP_PROCESSING)) {
		return -EOPNOTSUPP;
	}
	/* get size of userspace buffer and mask_bits -> 6 bytes */
	if (copy_from_user(&qinfo, udata, 6))
		return -EFAULT;
	qinfo.udata = kzalloc(qinfo.udata_len, GFP_KERNEL);
	if (!qinfo.udata)
		return -ENOMEM;
	qinfo.udata_offset = QETH_QARP_ENTRIES_OFFSET;
	iob = qeth_l3_get_setassparms_cmd(card, IPA_ARP_PROCESSING,
				       IPA_CMD_ASS_ARP_QUERY_INFO,
				       sizeof(int), QETH_PROT_IPV4);

	rc = qeth_l3_send_ipa_arp_cmd(card, iob,
				   QETH_SETASS_BASE_LEN+QETH_ARP_CMD_LEN,
				   qeth_l3_arp_query_cb, (void *)&qinfo);
	if (rc) {
		tmp = rc;
		QETH_DBF_MESSAGE(2, "Error while querying ARP cache on %s: %s "
			"(0x%x/%d)\n", QETH_CARD_IFNAME(card),
			qeth_l3_arp_get_error_cause(&rc), tmp, tmp);
		if (copy_to_user(udata, qinfo.udata, 4))
			rc = -EFAULT;
	} else {
		if (copy_to_user(udata, qinfo.udata, qinfo.udata_len))
			rc = -EFAULT;
	}
	kfree(qinfo.udata);
static int qeth_l3_query_arp_cache_info(struct qeth_card *card,
	enum qeth_prot_versions prot,
	struct qeth_arp_query_info *qinfo)
{
	struct qeth_cmd_buffer *iob;
	struct qeth_ipa_cmd *cmd;
	int tmp;
	int rc;

	QETH_CARD_TEXT_(card, 3, "qarpipv%i", prot);

	iob = qeth_get_setassparms_cmd(card, IPA_ARP_PROCESSING,
				       IPA_CMD_ASS_ARP_QUERY_INFO,
				       sizeof(struct qeth_arp_query_data)
						- sizeof(char),
				       prot);
	if (!iob)
		return -ENOMEM;
	cmd = __ipa_cmd(iob);
	cmd->data.setassparms.data.query_arp.request_bits = 0x000F;
	cmd->data.setassparms.data.query_arp.reply_bits = 0;
	cmd->data.setassparms.data.query_arp.no_entries = 0;
	rc = qeth_l3_send_ipa_arp_cmd(card, iob,
			   QETH_SETASS_BASE_LEN+QETH_ARP_CMD_LEN,
			   qeth_l3_arp_query_cb, (void *)qinfo);
	if (rc) {
		tmp = rc;
		QETH_DBF_MESSAGE(2,
			"Error while querying ARP cache on %s: %s "
			"(0x%x/%d)\n", QETH_CARD_IFNAME(card),
			qeth_l3_arp_get_error_cause(&rc), tmp, tmp);
	}

	return rc;
}

static int qeth_l3_arp_query(struct qeth_card *card, char __user *udata)
{
	struct qeth_arp_query_info qinfo = {0, };
	int rc;

	QETH_CARD_TEXT(card, 3, "arpquery");

	if (!qeth_is_supported(card,/*IPA_QUERY_ARP_ADDR_INFO*/
			       IPA_ARP_PROCESSING)) {
		QETH_CARD_TEXT(card, 3, "arpqnsup");
		rc = -EOPNOTSUPP;
		goto out;
	}
	/* get size of userspace buffer and mask_bits -> 6 bytes */
	if (copy_from_user(&qinfo, udata, 6)) {
		rc = -EFAULT;
		goto out;
	}
	qinfo.udata = kzalloc(qinfo.udata_len, GFP_KERNEL);
	if (!qinfo.udata) {
		rc = -ENOMEM;
		goto out;
	}
	qinfo.udata_offset = QETH_QARP_ENTRIES_OFFSET;
	rc = qeth_l3_query_arp_cache_info(card, QETH_PROT_IPV4, &qinfo);
	if (rc) {
		if (copy_to_user(udata, qinfo.udata, 4))
			rc = -EFAULT;
		goto free_and_out;
	}
	if (qinfo.mask_bits & QETH_QARP_WITH_IPV6) {
		/* fails in case of GuestLAN QDIO mode */
		qeth_l3_query_arp_cache_info(card, QETH_PROT_IPV6, &qinfo);
	}
	if (copy_to_user(udata, qinfo.udata, qinfo.udata_len)) {
		QETH_CARD_TEXT(card, 4, "qactf");
		rc = -EFAULT;
		goto free_and_out;
	}
	QETH_CARD_TEXT(card, 4, "qacts");

free_and_out:
	kfree(qinfo.udata);
out:
	return rc;
}

static int qeth_l3_arp_add_entry(struct qeth_card *card,
				struct qeth_arp_cache_entry *entry)
{
	struct qeth_cmd_buffer *iob;
	char buf[16];
	int tmp;
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "arpadent");
	QETH_CARD_TEXT(card, 3, "arpadent");

	/*
	 * currently GuestLAN only supports the ARP assist function
	 * IPA_CMD_ASS_ARP_QUERY_INFO, but not IPA_CMD_ASS_ARP_ADD_ENTRY;
	 * thus we say EOPNOTSUPP for this ARP function
	 */
	if (card->info.guestlan)
		return -EOPNOTSUPP;
	if (!qeth_is_supported(card, IPA_ARP_PROCESSING)) {
		return -EOPNOTSUPP;
	}

	iob = qeth_get_setassparms_cmd(card, IPA_ARP_PROCESSING,
				       IPA_CMD_ASS_ARP_ADD_ENTRY,
				       sizeof(struct qeth_arp_cache_entry),
				       QETH_PROT_IPV4);
	rc = qeth_l3_send_setassparms(card, iob,
	if (!iob)
		return -ENOMEM;
	rc = qeth_send_setassparms(card, iob,
				   sizeof(struct qeth_arp_cache_entry),
				   (unsigned long) entry,
				   qeth_setassparms_cb, NULL);
	if (rc) {
		tmp = rc;
		qeth_l3_ipaddr4_to_string((u8 *)entry->ipaddr, buf);
		QETH_DBF_MESSAGE(2, "Could not add ARP entry for address %s "
			"on %s: %s (0x%x/%d)\n", buf, QETH_CARD_IFNAME(card),
			qeth_l3_arp_get_error_cause(&rc), tmp, tmp);
	}
	return rc;
}

static int qeth_l3_arp_remove_entry(struct qeth_card *card,
				struct qeth_arp_cache_entry *entry)
{
	struct qeth_cmd_buffer *iob;
	char buf[16] = {0, };
	int tmp;
	int rc;

	QETH_DBF_TEXT(TRACE, 3, "arprment");
	QETH_CARD_TEXT(card, 3, "arprment");

	/*
	 * currently GuestLAN only supports the ARP assist function
	 * IPA_CMD_ASS_ARP_QUERY_INFO, but not IPA_CMD_ASS_ARP_REMOVE_ENTRY;
	 * thus we say EOPNOTSUPP for this ARP function
	 */
	if (card->info.guestlan)
		return -EOPNOTSUPP;
	if (!qeth_is_supported(card, IPA_ARP_PROCESSING)) {
		return -EOPNOTSUPP;
	}
	memcpy(buf, entry, 12);
	iob = qeth_get_setassparms_cmd(card, IPA_ARP_PROCESSING,
				       IPA_CMD_ASS_ARP_REMOVE_ENTRY,
				       12,
				       QETH_PROT_IPV4);
	rc = qeth_l3_send_setassparms(card, iob,
	if (!iob)
		return -ENOMEM;
	rc = qeth_send_setassparms(card, iob,
				   12, (unsigned long)buf,
				   qeth_setassparms_cb, NULL);
	if (rc) {
		tmp = rc;
		memset(buf, 0, 16);
		qeth_l3_ipaddr4_to_string((u8 *)entry->ipaddr, buf);
		QETH_DBF_MESSAGE(2, "Could not delete ARP entry for address %s"
			" on %s: %s (0x%x/%d)\n", buf, QETH_CARD_IFNAME(card),
			qeth_l3_arp_get_error_cause(&rc), tmp, tmp);
	}
	return rc;
}

static int qeth_l3_arp_flush_cache(struct qeth_card *card)
{
	int rc;
	int tmp;

	QETH_DBF_TEXT(TRACE, 3, "arpflush");
	QETH_CARD_TEXT(card, 3, "arpflush");

	/*
	 * currently GuestLAN only supports the ARP assist function
	 * IPA_CMD_ASS_ARP_QUERY_INFO, but not IPA_CMD_ASS_ARP_FLUSH_CACHE;
	 * thus we say EOPNOTSUPP for this ARP function
	*/
	if (card->info.guestlan || (card->info.type == QETH_CARD_TYPE_IQD))
		return -EOPNOTSUPP;
	if (!qeth_is_supported(card, IPA_ARP_PROCESSING)) {
		return -EOPNOTSUPP;
	}
	rc = qeth_l3_send_simple_setassparms(card, IPA_ARP_PROCESSING,
	rc = qeth_send_simple_setassparms(card, IPA_ARP_PROCESSING,
					  IPA_CMD_ASS_ARP_FLUSH_CACHE, 0);
	if (rc) {
		tmp = rc;
		QETH_DBF_MESSAGE(2, "Could not flush ARP cache on %s: %s "
			"(0x%x/%d)\n", QETH_CARD_IFNAME(card),
			qeth_l3_arp_get_error_cause(&rc), tmp, tmp);
	}
	return rc;
}

static int qeth_l3_do_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct qeth_card *card = dev->ml_priv;
	struct qeth_arp_cache_entry arp_entry;
	int rc = 0;

	if (!card)
		return -ENODEV;

	if ((card->state != CARD_STATE_UP) &&
		(card->state != CARD_STATE_SOFTSETUP))
	if (!qeth_card_hw_is_reachable(card))
		return -ENODEV;

	switch (cmd) {
	case SIOC_QETH_ARP_SET_NO_ENTRIES:
		if (!capable(CAP_NET_ADMIN)) {
			rc = -EPERM;
			break;
		}
		rc = qeth_l3_arp_set_no_entries(card, rq->ifr_ifru.ifru_ivalue);
		break;
	case SIOC_QETH_ARP_QUERY_INFO:
		if (!capable(CAP_NET_ADMIN)) {
			rc = -EPERM;
			break;
		}
		rc = qeth_l3_arp_query(card, rq->ifr_ifru.ifru_data);
		break;
	case SIOC_QETH_ARP_ADD_ENTRY:
		if (!capable(CAP_NET_ADMIN)) {
			rc = -EPERM;
			break;
		}
		if (copy_from_user(&arp_entry, rq->ifr_ifru.ifru_data,
				   sizeof(struct qeth_arp_cache_entry)))
			rc = -EFAULT;
		else
			rc = qeth_l3_arp_add_entry(card, &arp_entry);
		break;
	case SIOC_QETH_ARP_REMOVE_ENTRY:
		if (!capable(CAP_NET_ADMIN)) {
			rc = -EPERM;
			break;
		}
		if (copy_from_user(&arp_entry, rq->ifr_ifru.ifru_data,
				   sizeof(struct qeth_arp_cache_entry)))
			rc = -EFAULT;
		else
			rc = qeth_l3_arp_remove_entry(card, &arp_entry);
		break;
	case SIOC_QETH_ARP_FLUSH_CACHE:
		if (!capable(CAP_NET_ADMIN)) {
			rc = -EPERM;
			break;
		}
		rc = qeth_l3_arp_flush_cache(card);
		break;
	case SIOC_QETH_ADP_SET_SNMP_CONTROL:
		rc = qeth_snmp_command(card, rq->ifr_ifru.ifru_data);
		break;
	case SIOC_QETH_GET_CARD_TYPE:
		if ((card->info.type == QETH_CARD_TYPE_OSAE) &&
		if ((card->info.type == QETH_CARD_TYPE_OSD ||
		     card->info.type == QETH_CARD_TYPE_OSX) &&
		    !card->info.guestlan)
			return 1;
		return 0;
		break;
	case SIOCGMIIPHY:
		mii_data = if_mii(rq);
		mii_data->phy_id = 0;
		break;
	case SIOCGMIIREG:
		mii_data = if_mii(rq);
		if (mii_data->phy_id != 0)
			rc = -EINVAL;
		else
			mii_data->val_out = qeth_mdio_read(dev,
							mii_data->phy_id,
							mii_data->reg_num);
		break;
	case SIOC_QETH_QUERY_OAT:
		rc = qeth_query_oat_command(card, rq->ifr_ifru.ifru_data);
		break;
	default:
		rc = -EOPNOTSUPP;
	}
	if (rc)
		QETH_DBF_TEXT_(TRACE, 2, "ioce%d", rc);
	return rc;
}

static void qeth_l3_fill_header(struct qeth_card *card, struct qeth_hdr *hdr,
		struct sk_buff *skb, int ipv, int cast_type)
{
		QETH_CARD_TEXT_(card, 2, "ioce%d", rc);
	default:
		rc = -EOPNOTSUPP;
	}
	return rc;
}

static int qeth_l3_get_cast_type(struct sk_buff *skb)
{
	struct neighbour *n = NULL;
	struct dst_entry *dst;

	rcu_read_lock();
	dst = skb_dst(skb);
	if (dst)
		n = dst_neigh_lookup_skb(dst, skb);
	if (n) {
		int cast_type = n->type;

		rcu_read_unlock();
		neigh_release(n);
		if ((cast_type == RTN_BROADCAST) ||
		    (cast_type == RTN_MULTICAST) ||
		    (cast_type == RTN_ANYCAST))
			return cast_type;
		return RTN_UNICAST;
	}
	rcu_read_unlock();

	/* no neighbour (eg AF_PACKET), fall back to target's IP address ... */
	if (be16_to_cpu(skb->protocol) == ETH_P_IPV6)
		return ipv6_addr_is_multicast(&ipv6_hdr(skb)->daddr) ?
				RTN_MULTICAST : RTN_UNICAST;
	else if (be16_to_cpu(skb->protocol) == ETH_P_IP)
		return ipv4_is_multicast(ip_hdr(skb)->daddr) ?
				RTN_MULTICAST : RTN_UNICAST;

	/* ... and MAC address */
	if (ether_addr_equal_64bits(eth_hdr(skb)->h_dest, skb->dev->broadcast))
		return RTN_BROADCAST;
	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest))
		return RTN_MULTICAST;

	/* default to unicast */
	return RTN_UNICAST;
}

static void qeth_l3_fill_af_iucv_hdr(struct qeth_hdr *hdr, struct sk_buff *skb,
				     unsigned int data_len)
{
	char daddr[16];
	struct af_iucv_trans_hdr *iucv_hdr;

	memset(hdr, 0, sizeof(struct qeth_hdr));
	hdr->hdr.l3.id = QETH_HEADER_TYPE_LAYER3;
	hdr->hdr.l3.length = data_len;
	hdr->hdr.l3.flags = QETH_HDR_IPV6 | QETH_CAST_UNICAST;

	iucv_hdr = (struct af_iucv_trans_hdr *)(skb_mac_header(skb) + ETH_HLEN);
	memset(daddr, 0, sizeof(daddr));
	daddr[0] = 0xfe;
	daddr[1] = 0x80;
	memcpy(&daddr[8], iucv_hdr->destUserID, 8);
	memcpy(hdr->hdr.l3.next_hop.ipv6_addr, daddr, 16);
}

static u8 qeth_l3_cast_type_to_flag(int cast_type)
{
	if (cast_type == RTN_MULTICAST)
		return QETH_CAST_MULTICAST;
	if (cast_type == RTN_ANYCAST)
		return QETH_CAST_ANYCAST;
	if (cast_type == RTN_BROADCAST)
		return QETH_CAST_BROADCAST;
	return QETH_CAST_UNICAST;
}

static void qeth_l3_fill_header(struct qeth_card *card, struct qeth_hdr *hdr,
				struct sk_buff *skb, int ipv, int cast_type,
				unsigned int data_len)
{
	memset(hdr, 0, sizeof(struct qeth_hdr));
	hdr->hdr.l3.id = QETH_HEADER_TYPE_LAYER3;
	hdr->hdr.l3.length = data_len;

	/*
	 * before we're going to overwrite this location with next hop ip.
	 * v6 uses passthrough, v4 sets the tag in the QDIO header.
	 */
	if (card->vlangrp && vlan_tx_tag_present(skb)) {
	if (skb_vlan_tag_present(skb)) {
		if ((ipv == 4) || (card->info.type == QETH_CARD_TYPE_IQD))
			hdr->hdr.l3.ext_flags = QETH_HDR_EXT_VLAN_FRAME;
		else
			hdr->hdr.l3.ext_flags = QETH_HDR_EXT_INCLUDE_VLAN_TAG;
		hdr->hdr.l3.vlan_id = vlan_tx_tag_get(skb);
	}

	hdr->hdr.l3.length = skb->len - sizeof(struct qeth_hdr);
	if (ipv == 4) {
		/* IPv4 */
		hdr->hdr.l3.flags = qeth_l3_get_qeth_hdr_flags4(cast_type);
		memset(hdr->hdr.l3.dest_addr, 0, 12);
		if ((skb->dst) && (skb->dst->neighbour)) {
			*((u32 *) (&hdr->hdr.l3.dest_addr[12])) =
			    *((u32 *) skb->dst->neighbour->primary_key);
		} else {
			/* fill in destination address used in ip header */
			*((u32 *) (&hdr->hdr.l3.dest_addr[12])) =
							ip_hdr(skb)->daddr;
		}
	} else if (ipv == 6) {
		hdr->hdr.l3.vlan_id = skb_vlan_tag_get(skb);
	}

	if (!skb_is_gso(skb) && skb->ip_summed == CHECKSUM_PARTIAL) {
		qeth_tx_csum(skb, &hdr->hdr.l3.ext_flags, ipv);
		if (card->options.performance_stats)
			card->perf_stats.tx_csum++;
	}

	/* OSA only: */
	if (!ipv) {
		hdr->hdr.l3.flags = QETH_HDR_PASSTHRU;
		if (ether_addr_equal_64bits(eth_hdr(skb)->h_dest,
					    skb->dev->broadcast))
			hdr->hdr.l3.flags |= QETH_CAST_BROADCAST;
		else
			hdr->hdr.l3.flags |= (cast_type == RTN_MULTICAST) ?
				QETH_CAST_MULTICAST : QETH_CAST_UNICAST;
		return;
	}

	hdr->hdr.l3.flags = qeth_l3_cast_type_to_flag(cast_type);
	rcu_read_lock();
	if (ipv == 4) {
		struct rtable *rt = skb_rtable(skb);

		*((__be32 *) &hdr->hdr.l3.next_hop.ipv4.addr) = (rt) ?
				rt_nexthop(rt, ip_hdr(skb)->daddr) :
				ip_hdr(skb)->daddr;
	} else {
		/* IPv6 */
		const struct rt6_info *rt = skb_rt6_info(skb);
		const struct in6_addr *next_hop;

		if (rt && !ipv6_addr_any(&rt->rt6i_gateway))
			next_hop = &rt->rt6i_gateway;
		else
			next_hop = &ipv6_hdr(skb)->daddr;
		memcpy(hdr->hdr.l3.next_hop.ipv6_addr, next_hop, 16);

		/* IPv6 */
		hdr->hdr.l3.flags = qeth_l3_get_qeth_hdr_flags6(cast_type);
		if (card->info.type == QETH_CARD_TYPE_IQD)
			hdr->hdr.l3.flags &= ~QETH_HDR_PASSTHRU;
		if ((skb->dst) && (skb->dst->neighbour)) {
			memcpy(hdr->hdr.l3.dest_addr,
			       skb->dst->neighbour->primary_key, 16);
		} else {
			/* fill in destination address used in ip header */
			memcpy(hdr->hdr.l3.dest_addr,
			       &ipv6_hdr(skb)->daddr, 16);
		}
	} else {
		/* passthrough */
		if ((skb->dev->type == ARPHRD_IEEE802_TR) &&
			!memcmp(skb->data + sizeof(struct qeth_hdr) +
			sizeof(__u16), skb->dev->broadcast, 6)) {
			hdr->hdr.l3.flags = QETH_CAST_BROADCAST |
						QETH_HDR_PASSTHRU;
		} else if (!memcmp(skb->data + sizeof(struct qeth_hdr),
		memcpy(hdr->hdr.l3.dest_addr, pkey, 16);
	} else {
		if (!memcmp(skb->data + sizeof(struct qeth_hdr),
			    skb->dev->broadcast, 6)) {
			/* broadcast? */
			hdr->hdr.l3.flags = QETH_CAST_BROADCAST |
						QETH_HDR_PASSTHRU;
		} else {
			hdr->hdr.l3.flags = (cast_type == RTN_MULTICAST) ?
				QETH_CAST_MULTICAST | QETH_HDR_PASSTHRU :
				QETH_CAST_UNICAST | QETH_HDR_PASSTHRU;
		}
		hdr->hdr.l3.flags |= QETH_HDR_IPV6;
		if (card->info.type != QETH_CARD_TYPE_IQD)
			hdr->hdr.l3.flags |= QETH_HDR_PASSTHRU;
	}
	rcu_read_unlock();
}

static void qeth_tso_fill_header(struct qeth_card *card,
		struct qeth_hdr *qhdr, struct sk_buff *skb)
{
	struct qeth_hdr_tso *hdr = (struct qeth_hdr_tso *)qhdr;
	struct tcphdr *tcph = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct ipv6hdr *ip6h = ipv6_hdr(skb);

	/*fix header to TSO values ...*/
	hdr->hdr.hdr.l3.id = QETH_HEADER_TYPE_TSO;
	/*set values which are fix for the first approach ...*/
	hdr->ext.hdr_tot_len = (__u16) sizeof(struct qeth_hdr_ext_tso);
	hdr->ext.imb_hdr_no  = 1;
	hdr->ext.hdr_type    = 1;
	hdr->ext.hdr_version = 1;
	hdr->ext.hdr_len     = 28;
	/*insert non-fix values */
	hdr->ext.mss = skb_shinfo(skb)->gso_size;
	hdr->ext.dg_hdr_len = (__u16)(ip_hdrlen(skb) + tcp_hdrlen(skb));
	hdr->ext.payload_len = (__u16)(skb->len - hdr->ext.dg_hdr_len -
				       sizeof(struct qeth_hdr_tso));
	tcph->check = 0;
	if (be16_to_cpu(skb->protocol) == ETH_P_IPV6) {
		ip6h->payload_len = 0;
		tcph->check = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					       0, IPPROTO_TCP, 0);
	} else {
		/*OSA want us to set these values ...*/
		tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
					 0, IPPROTO_TCP, 0);
		iph->tot_len = 0;
		iph->check = 0;
	}
}

/**
 * qeth_l3_get_elements_no_tso() - find number of SBALEs for skb data for tso
 * @card:			   qeth card structure, to check max. elems.
 * @skb:			   SKB address
 * @extra_elems:		   extra elems needed, to check against max.
 *
 * Returns the number of pages, and thus QDIO buffer elements, needed to cover
 * skb data, including linear part and fragments, but excluding TCP header.
 * (Exclusion of TCP header distinguishes it from qeth_get_elements_no().)
 * Checks if the result plus extra_elems fits under the limit for the card.
 * Returns 0 if it does not.
 * Note: extra_elems is not included in the returned result.
 */
static int qeth_l3_get_elements_no_tso(struct qeth_card *card,
			struct sk_buff *skb, int extra_elems)
{
	addr_t start = (addr_t)tcp_hdr(skb) + tcp_hdrlen(skb);
	addr_t end = (addr_t)skb->data + skb_headlen(skb);
	int elements = qeth_get_elements_for_frags(skb);

	if (start != end)
		elements += qeth_get_elements_for_range(start, end);

	if ((elements + extra_elems) > QETH_MAX_BUFFER_ELEMENTS(card)) {
		QETH_DBF_MESSAGE(2,
	"Invalid size of TSO IP packet (Number=%d / Length=%d). Discarded.\n",
				elements + extra_elems, skb->len);
		return 0;
	}
	return elements;
}

static int qeth_l3_xmit_offload(struct qeth_card *card, struct sk_buff *skb,
				struct qeth_qdio_out_q *queue, int ipv,
				int cast_type)
{
	const unsigned int hw_hdr_len = sizeof(struct qeth_hdr);
	unsigned int frame_len, elements;
	unsigned char eth_hdr[ETH_HLEN];
	struct qeth_hdr *hdr = NULL;
	unsigned int hd_len = 0;
	int push_len, rc;
	bool is_sg;

	/* re-use the L2 header area for the HW header: */
	rc = skb_cow_head(skb, hw_hdr_len - ETH_HLEN);
	if (rc)
		return rc;
	skb_copy_from_linear_data(skb, eth_hdr, ETH_HLEN);
	skb_pull(skb, ETH_HLEN);
	frame_len = skb->len;

	push_len = qeth_add_hw_header(card, skb, &hdr, hw_hdr_len, 0,
				      &elements);
	if (push_len < 0)
		return push_len;
	if (!push_len) {
		/* hdr was added discontiguous from skb->data */
		hd_len = hw_hdr_len;
	}

	if (skb->protocol == htons(ETH_P_AF_IUCV))
		qeth_l3_fill_af_iucv_hdr(hdr, skb, frame_len);
	else
		qeth_l3_fill_header(card, hdr, skb, ipv, cast_type, frame_len);

	is_sg = skb_is_nonlinear(skb);
	if (IS_IQD(card)) {
		rc = qeth_do_send_packet_fast(queue, skb, hdr, 0, hd_len);
	} else {
		/* TODO: drop skb_orphan() once TX completion is fast enough */
		skb_orphan(skb);
		rc = qeth_do_send_packet(card, queue, skb, hdr, 0, hd_len,
					 elements);
	}

	if (!rc) {
		if (card->options.performance_stats) {
			card->perf_stats.buf_elements_sent += elements;
			if (is_sg)
				card->perf_stats.sg_skbs_sent++;
		}
	} else {
		if (!push_len)
			kmem_cache_free(qeth_core_header_cache, hdr);
		if (rc == -EBUSY) {
			/* roll back to ETH header */
			skb_pull(skb, push_len);
			skb_push(skb, ETH_HLEN);
			skb_copy_to_linear_data(skb, eth_hdr, ETH_HLEN);
		}
	}
	return rc;
}

static int qeth_l3_xmit(struct qeth_card *card, struct sk_buff *skb,
			struct qeth_qdio_out_q *queue, int ipv, int cast_type)
{
	int elements, len, rc;
	__be16 *tag;
	struct qeth_hdr *hdr = NULL;
	int elements_needed = 0;
	struct qeth_card *card = dev->ml_priv;
	struct sk_buff *new_skb = NULL;
	int ipv = qeth_get_ip_version(skb);
	int cast_type = qeth_get_cast_type(card, skb);
	struct qeth_qdio_out_q *queue = card->qdio.out_qs
		[qeth_get_priority_queue(card, skb, ipv, cast_type)];
	int tx_bytes = skb->len;
	enum qeth_large_send_types large_send = QETH_LARGE_SEND_NO;
	struct qeth_eddp_context *ctx = NULL;
	int data_offset = -1;

	if ((card->info.type == QETH_CARD_TYPE_IQD) &&
	    (skb->protocol != htons(ETH_P_IPV6)) &&
	    (skb->protocol != htons(ETH_P_IP)))
	int elems;
	int hdr_elements = 0;
	struct sk_buff *new_skb = NULL;
	int tx_bytes = skb->len;
	unsigned int hd_len;
	bool use_tso, is_sg;

	if (skb_is_gso(skb))
		large_send = card->options.large_send;
	large_send = skb_is_gso(skb);
	/* Ignore segment size from skb_is_gso(), 1 page is always used. */
	use_tso = skb_is_gso(skb) &&
		  (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4);

	if (card->info.type == QETH_CARD_TYPE_IQD) {
		new_skb = skb;
		data_offset = ETH_HLEN;
		if (new_skb->protocol == ETH_P_AF_IUCV)
			data_offset = 0;
		else
			data_offset = ETH_HLEN;
		hd_len = sizeof(*hdr);
		hdr = kmem_cache_alloc(qeth_core_header_cache, GFP_ATOMIC);
		if (!hdr)
			goto tx_drop;
		hdr_elements++;
	} else {
		/* create a clone with writeable headroom */
		new_skb = skb_realloc_headroom(skb, sizeof(struct qeth_hdr_tso)
					+ VLAN_HLEN);
		if (!new_skb)
			goto tx_drop;

	if (card->info.type == QETH_CARD_TYPE_IQD) {
		if (data_offset < 0)
			skb_pull(new_skb, ETH_HLEN);
	} else {
		if (new_skb->protocol == htons(ETH_P_IP)) {
			if (card->dev->type == ARPHRD_IEEE802_TR)
				skb_pull(new_skb, TR_HLEN);
			else
				skb_pull(new_skb, ETH_HLEN);
		}

		if (new_skb->protocol == ETH_P_IPV6 && card->vlangrp &&
				vlan_tx_tag_present(new_skb)) {
		if (ipv == 4) {
			skb_pull(new_skb, ETH_HLEN);
		}

		if (ipv != 4 && skb_vlan_tag_present(new_skb)) {
			skb_push(new_skb, VLAN_HLEN);
			skb_copy_to_linear_data(new_skb, new_skb->data + 4, 4);
			skb_copy_to_linear_data_offset(new_skb, 4,
				new_skb->data + 8, 4);
			skb_copy_to_linear_data_offset(new_skb, 8,
				new_skb->data + 12, 4);
			tag = (u16 *)(new_skb->data + 12);
			*tag = __constant_htons(ETH_P_8021Q);
			*(tag + 1) = htons(vlan_tx_tag_get(new_skb));
			new_skb->vlan_tci = 0;
			*(tag + 1) = htons(skb_vlan_tag_get(new_skb));
			tag = (__be16 *)(new_skb->data + 12);
			*tag = cpu_to_be16(ETH_P_8021Q);
			*(tag + 1) = cpu_to_be16(skb_vlan_tag_get(new_skb));
		}
	/* create a clone with writeable headroom */
	new_skb = skb_realloc_headroom(skb, sizeof(struct qeth_hdr_tso) +
					    VLAN_HLEN);
	if (!new_skb)
		return -ENOMEM;

	if (ipv == 4) {
		skb_pull(new_skb, ETH_HLEN);
	} else if (skb_vlan_tag_present(new_skb)) {
		skb_push(new_skb, VLAN_HLEN);
		skb_copy_to_linear_data(new_skb, new_skb->data + 4, 4);
		skb_copy_to_linear_data_offset(new_skb, 4,
					       new_skb->data + 8, 4);
		skb_copy_to_linear_data_offset(new_skb, 8,
					       new_skb->data + 12, 4);
		tag = (__be16 *)(new_skb->data + 12);
		*tag = cpu_to_be16(ETH_P_8021Q);
		*(tag + 1) = cpu_to_be16(skb_vlan_tag_get(new_skb));
	}

	/* fix hardware limitation: as long as we do not have sbal
	 * chaining we can not send long frag lists so we temporary
	 * switch to EDDP
	 */
	if ((large_send == QETH_LARGE_SEND_TSO) &&
		((skb_shinfo(new_skb)->nr_frags + 2) > 16))
		large_send = QETH_LARGE_SEND_EDDP;

	if ((large_send == QETH_LARGE_SEND_TSO) &&
	    (cast_type == RTN_UNSPEC)) {
	 * chaining we can not send long frag lists
	 */
	if ((use_tso && !qeth_l3_get_elements_no_tso(card, new_skb, 1)) ||
	    (!use_tso && !qeth_get_elements_no(card, new_skb, 0, 0))) {
		rc = skb_linearize(new_skb);

		if (card->options.performance_stats) {
			if (rc)
				card->perf_stats.tx_linfail++;
			else
				card->perf_stats.tx_lin++;
		}
		if (rc)
			goto out;
	}

	if (use_tso) {
		hdr = skb_push(new_skb, sizeof(struct qeth_hdr_tso));
		memset(hdr, 0, sizeof(struct qeth_hdr_tso));
		qeth_l3_fill_header(card, hdr, new_skb, ipv, cast_type,
				    new_skb->len - sizeof(struct qeth_hdr_tso));
		qeth_tso_fill_header(card, hdr, new_skb);
		hdr_elements++;
	} else {
		if (data_offset < 0) {
			hdr = skb_push(new_skb, sizeof(struct qeth_hdr));
			qeth_l3_fill_header(card, hdr, new_skb, ipv,
						cast_type);
		} else {
			qeth_l3_fill_header(card, hdr, new_skb, ipv,
						cast_type);
			hdr->hdr.l3.length = new_skb->len - data_offset;
		}
	}

	if (large_send == QETH_LARGE_SEND_EDDP) {
		/* new_skb is not owned by a socket so we use skb to get
		 * the protocol
		 */
		ctx = qeth_eddp_create_context(card, new_skb, hdr,
						skb->sk->sk_protocol);
		if (ctx == NULL) {
			QETH_DBF_MESSAGE(2, "could not create eddp context\n");
			goto tx_drop;
		}
	} else {
		int elems = qeth_get_elements_no(card, (void *)hdr, new_skb,
						 elements_needed);
		if (!elems) {
			if (data_offset >= 0)
				kmem_cache_free(qeth_core_header_cache, hdr);
			goto tx_drop;
		}
		elements_needed += elems;
	}

	if ((large_send == QETH_LARGE_SEND_NO) &&
	    (new_skb->ip_summed == CHECKSUM_PARTIAL))
		qeth_tx_csum(new_skb);

	if (card->info.type != QETH_CARD_TYPE_IQD)
		rc = qeth_do_send_packet(card, queue, new_skb, hdr,
					 elements_needed, ctx);
	else
		rc = qeth_do_send_packet_fast(card, queue, new_skb, hdr,
					elements_needed, ctx, data_offset, 0);
			if (new_skb->protocol == ETH_P_AF_IUCV)
			if (be16_to_cpu(new_skb->protocol) == ETH_P_AF_IUCV)
				qeth_l3_fill_af_iucv_hdr(card, hdr, new_skb);
			else {
				qeth_l3_fill_header(card, hdr, new_skb, ipv,
							cast_type);
				hdr->hdr.l3.length = new_skb->len - data_offset;
			}
		}

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			qeth_l3_hdr_csum(card, hdr, new_skb);
		hdr = skb_push(new_skb, sizeof(struct qeth_hdr));
		qeth_l3_fill_header(card, hdr, new_skb, ipv, cast_type,
				    new_skb->len - sizeof(struct qeth_hdr));
	}

	elements = use_tso ?
		   qeth_l3_get_elements_no_tso(card, new_skb, hdr_elements) :
		   qeth_get_elements_no(card, new_skb, hdr_elements, 0);
	if (!elements) {
		rc = -E2BIG;
		goto out;
	}
	elements += hdr_elements;

	if (use_tso) {
		hd_len = sizeof(struct qeth_hdr_tso) +
			 ip_hdrlen(new_skb) + tcp_hdrlen(new_skb);
		len = hd_len;
	} else {
		hd_len = 0;
		len = sizeof(struct qeth_hdr_layer3);
	}

	if (qeth_hdr_chk_and_bounce(new_skb, &hdr, len)) {
		rc = -EINVAL;
		goto out;
	}

	is_sg = skb_is_nonlinear(new_skb);
	rc = qeth_do_send_packet(card, queue, new_skb, hdr, hd_len, hd_len,
				 elements);
out:
	if (!rc) {
		if (new_skb != skb)
			dev_kfree_skb_any(skb);
		if (card->options.performance_stats) {
			if (large_send != QETH_LARGE_SEND_NO) {
				card->perf_stats.large_send_bytes += tx_bytes;
				card->perf_stats.large_send_cnt++;
			}
			if (skb_shinfo(new_skb)->nr_frags > 0) {
				card->perf_stats.sg_skbs_sent++;
				/* nr_frags + skb->data */
				card->perf_stats.sg_frags_sent +=
					skb_shinfo(new_skb)->nr_frags + 1;
			}
		}

		if (ctx != NULL) {
			qeth_eddp_put_context(ctx);
			dev_kfree_skb_any(new_skb);
		}
	} else {
		if (ctx != NULL)
			qeth_eddp_put_context(ctx);

			if (large_send) {
			card->perf_stats.buf_elements_sent += elements;
			if (is_sg)
				card->perf_stats.sg_skbs_sent++;
			if (use_tso) {
				card->perf_stats.large_send_bytes += tx_bytes;
				card->perf_stats.large_send_cnt++;
			}
		}
	} else {
		if (new_skb != skb)
			dev_kfree_skb_any(new_skb);
	}
	return rc;
}

static netdev_tx_t qeth_l3_hard_start_xmit(struct sk_buff *skb,
					   struct net_device *dev)
{
	int cast_type = qeth_l3_get_cast_type(skb);
	struct qeth_card *card = dev->ml_priv;
	int ipv = qeth_get_ip_version(skb);
	struct qeth_qdio_out_q *queue;
	int tx_bytes = skb->len;
	int rc;

	if (IS_IQD(card)) {
		if (card->options.sniffer)
			goto tx_drop;
		if ((card->options.cq != QETH_CQ_ENABLED && !ipv) ||
		    (card->options.cq == QETH_CQ_ENABLED &&
		     skb->protocol != htons(ETH_P_AF_IUCV)))
			goto tx_drop;
	}

	if (card->state != CARD_STATE_UP || !card->lan_online) {
		card->stats.tx_carrier_errors++;
		goto tx_drop;
	}

	if (cast_type == RTN_BROADCAST && !card->info.broadcast_capable)
		goto tx_drop;

	queue = qeth_get_tx_queue(card, skb, ipv, cast_type);

	if (card->options.performance_stats) {
		card->perf_stats.outbound_cnt++;
		card->perf_stats.outbound_start_time = qeth_get_micros();
	}
	netif_stop_queue(dev);

	if (IS_IQD(card) || (!skb_is_gso(skb) && ipv == 4))
		rc = qeth_l3_xmit_offload(card, skb, queue, ipv, cast_type);
	else
		rc = qeth_l3_xmit(card, skb, queue, ipv, cast_type);

	if (!rc) {
		card->stats.tx_packets++;
		card->stats.tx_bytes += tx_bytes;
		if (card->options.performance_stats)
			card->perf_stats.outbound_time += qeth_get_micros() -
				card->perf_stats.outbound_start_time;
		netif_wake_queue(dev);
		return NETDEV_TX_OK;
	} else if (rc == -EBUSY) {
		return NETDEV_TX_BUSY;
	} /* else fall through */

tx_drop:
	card->stats.tx_dropped++;
	card->stats.tx_errors++;
	dev_kfree_skb_any(skb);
	netif_wake_queue(dev);
	return NETDEV_TX_OK;
}

static int qeth_l3_open(struct net_device *dev)
{
	struct qeth_card *card = dev->ml_priv;

	QETH_DBF_TEXT(TRACE, 4, "qethopen");
static int __qeth_l3_open(struct net_device *dev)
{
	struct qeth_card *card = dev->ml_priv;
	int rc = 0;

	QETH_CARD_TEXT(card, 4, "qethopen");
	if (card->state == CARD_STATE_UP)
		return rc;
	if (card->state != CARD_STATE_SOFTSETUP)
		return -ENODEV;
	card->data.state = CH_STATE_UP;
	card->state = CARD_STATE_UP;
	card->dev->flags |= IFF_UP;
	netif_start_queue(dev);

	if (!card->lan_online && netif_carrier_ok(dev))
		netif_carrier_off(dev);
	return 0;
	netif_start_queue(dev);

	if (qdio_stop_irq(card->data.ccwdev, 0) >= 0) {
		napi_enable(&card->napi);
		napi_schedule(&card->napi);
	} else
		rc = -EIO;
	return rc;
}

static int qeth_l3_open(struct net_device *dev)
{
	struct qeth_card *card = dev->ml_priv;

	QETH_CARD_TEXT(card, 5, "qethope_");
	if (qeth_wait_for_threads(card, QETH_RECOVER_THREAD)) {
		QETH_CARD_TEXT(card, 3, "openREC");
		return -ERESTARTSYS;
	}
	return __qeth_l3_open(dev);
}

static int qeth_l3_stop(struct net_device *dev)
{
	struct qeth_card *card = dev->ml_priv;

	QETH_DBF_TEXT(TRACE, 4, "qethstop");
	netif_tx_disable(dev);
	card->dev->flags &= ~IFF_UP;
	if (card->state == CARD_STATE_UP)
		card->state = CARD_STATE_SOFTSETUP;
	return 0;
}

static u32 qeth_l3_ethtool_get_rx_csum(struct net_device *dev)
{
	struct qeth_card *card = dev->ml_priv;

	return (card->options.checksum_type == HW_CHECKSUMMING);
}

static int qeth_l3_ethtool_set_rx_csum(struct net_device *dev, u32 data)
{
	struct qeth_card *card = dev->ml_priv;
	enum qeth_card_states old_state;
	enum qeth_checksum_types csum_type;

	if ((card->state != CARD_STATE_UP) &&
	    (card->state != CARD_STATE_DOWN))
		return -EPERM;

	if (data)
		csum_type = HW_CHECKSUMMING;
	else
		csum_type = SW_CHECKSUMMING;

	if (card->options.checksum_type != csum_type) {
		old_state = card->state;
		if (card->state == CARD_STATE_UP)
			__qeth_l3_set_offline(card->gdev, 1);
		card->options.checksum_type = csum_type;
		if (old_state == CARD_STATE_UP)
			__qeth_l3_set_online(card->gdev, 1);
	QETH_CARD_TEXT(card, 4, "qethstop");
	netif_tx_disable(dev);
	if (card->state == CARD_STATE_UP) {
		card->state = CARD_STATE_SOFTSETUP;
		napi_disable(&card->napi);
	}
	return 0;
}

static int qeth_l3_ethtool_set_tso(struct net_device *dev, u32 data)
{
	struct qeth_card *card = dev->ml_priv;

	if (data) {
		if (card->options.large_send == QETH_LARGE_SEND_NO) {
			if (card->info.type == QETH_CARD_TYPE_IQD)
				card->options.large_send = QETH_LARGE_SEND_EDDP;
			else
				card->options.large_send = QETH_LARGE_SEND_TSO;
			dev->features |= NETIF_F_TSO;
		}
	} else {
		dev->features &= ~NETIF_F_TSO;
		card->options.large_send = QETH_LARGE_SEND_NO;
	}
	return 0;
}

static struct ethtool_ops qeth_l3_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = ethtool_op_set_tx_hw_csum,
	.get_rx_csum = qeth_l3_ethtool_get_rx_csum,
	.set_rx_csum = qeth_l3_ethtool_set_rx_csum,
	.get_sg      = ethtool_op_get_sg,
	.set_sg      = ethtool_op_set_sg,
	.get_tso     = ethtool_op_get_tso,
	.set_tso     = qeth_l3_ethtool_set_tso,
	.get_strings = qeth_core_get_strings,
	.get_ethtool_stats = qeth_core_get_ethtool_stats,
	.get_stats_count = qeth_core_get_stats_count,
static netdev_features_t qeth_l3_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	struct qeth_card *card = dev->ml_priv;

	if (!qeth_is_supported(card, IPA_OUTBOUND_CHECKSUM))
		features &= ~NETIF_F_IP_CSUM;
	if (!qeth_is_supported(card, IPA_OUTBOUND_TSO))
		features &= ~NETIF_F_TSO;
	if (!qeth_is_supported(card, IPA_INBOUND_CHECKSUM))
		features &= ~NETIF_F_RXCSUM;
	return features;
}

static int qeth_l3_set_features(struct net_device *dev,
	netdev_features_t features)
{
	struct qeth_card *card = dev->ml_priv;
	netdev_features_t changed = dev->features ^ features;

	if (!(changed & NETIF_F_RXCSUM))
		return 0;

	if (card->state == CARD_STATE_DOWN ||
	    card->state == CARD_STATE_RECOVER)
		return 0;

	return qeth_set_rx_csum(card, features & NETIF_F_RXCSUM ? 1 : 0);
}

static const struct ethtool_ops qeth_l3_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_strings = qeth_core_get_strings,
	.get_ethtool_stats = qeth_core_get_ethtool_stats,
	.get_sset_count = qeth_core_get_sset_count,
	.get_drvinfo = qeth_core_get_drvinfo,
	.get_link_ksettings = qeth_core_ethtool_get_link_ksettings,
};

/*
 * we need NOARP for IPv4 but we want neighbor solicitation for IPv6. Setting
 * NOARP on the netdevice is no option because it also turns off neighbor
 * solicitation. For IPv4 we install a neighbor_setup function. We don't want
 * arp resolution but we want the hard header (packet socket will work
 * e.g. tcpdump)
 */
static int qeth_l3_neigh_setup_noarp(struct neighbour *n)
{
	n->nud_state = NUD_NOARP;
	memcpy(n->ha, "FAKELL", 6);
	n->output = n->ops->connected_output;
	return 0;
}

static int
qeth_l3_neigh_setup(struct net_device *dev, struct neigh_parms *np)
{
	if (np->tbl->family == AF_INET)
		np->neigh_setup = qeth_l3_neigh_setup_noarp;

	return 0;
}

static int qeth_l3_setup_netdev(struct qeth_card *card)
{
	if (card->info.type == QETH_CARD_TYPE_OSAE) {
		if ((card->info.link_type == QETH_LINK_TYPE_LANE_TR) ||
		    (card->info.link_type == QETH_LINK_TYPE_HSTR)) {
#ifdef CONFIG_TR
			card->dev = alloc_trdev(0);
#endif
			if (!card->dev)
				return -ENODEV;
static const struct net_device_ops qeth_l3_netdev_ops = {
	.ndo_open		= qeth_l3_open,
	.ndo_stop		= qeth_l3_stop,
	.ndo_get_stats		= qeth_get_stats,
	.ndo_start_xmit		= qeth_l3_hard_start_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= qeth_l3_set_rx_mode,
	.ndo_do_ioctl		= qeth_do_ioctl,
	.ndo_fix_features	= qeth_fix_features,
	.ndo_set_features	= qeth_set_features,
	.ndo_vlan_rx_add_vid	= qeth_l3_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid   = qeth_l3_vlan_rx_kill_vid,
	.ndo_tx_timeout		= qeth_tx_timeout,
};

static const struct net_device_ops qeth_l3_osa_netdev_ops = {
	.ndo_open		= qeth_l3_open,
	.ndo_stop		= qeth_l3_stop,
	.ndo_get_stats		= qeth_get_stats,
	.ndo_start_xmit		= qeth_l3_hard_start_xmit,
	.ndo_features_check	= qeth_features_check,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= qeth_l3_set_rx_mode,
	.ndo_do_ioctl		= qeth_do_ioctl,
	.ndo_fix_features	= qeth_fix_features,
	.ndo_set_features	= qeth_set_features,
	.ndo_vlan_rx_add_vid	= qeth_l3_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid   = qeth_l3_vlan_rx_kill_vid,
	.ndo_tx_timeout		= qeth_tx_timeout,
	.ndo_neigh_setup	= qeth_l3_neigh_setup,
};

static int qeth_l3_setup_netdev(struct qeth_card *card)
{
	int rc;

	if (qeth_netdev_is_registered(card->dev))
		return 0;

	if (card->info.type == QETH_CARD_TYPE_OSD ||
	    card->info.type == QETH_CARD_TYPE_OSX) {
		if ((card->info.link_type == QETH_LINK_TYPE_LANE_TR) ||
		    (card->info.link_type == QETH_LINK_TYPE_HSTR)) {
			pr_info("qeth_l3: ignoring TR device\n");
			return -ENODEV;
		} else {
			card->dev = alloc_etherdev(0);
			if (!card->dev)
				return -ENODEV;
			card->dev->neigh_setup = qeth_l3_neigh_setup;
			card->dev->netdev_ops = &qeth_l3_osa_netdev_ops;

			/*IPv6 address autoconfiguration stuff*/
			qeth_l3_get_unique_id(card);
			if (!(card->info.unique_id & UNIQUE_ID_NOT_BY_CARD))
				card->dev->dev_id = card->info.unique_id &
							 0xffff;
		}
	} else if (card->info.type == QETH_CARD_TYPE_IQD) {
		card->dev = alloc_netdev(0, "hsi%d", ether_setup);
		if (!card->dev)
			return -ENODEV;
		card->dev->flags |= IFF_NOARP;
		qeth_l3_iqd_read_initial_mac(card);
	} else
		return -ENODEV;

	card->dev->hard_start_xmit = qeth_l3_hard_start_xmit;
	card->dev->ml_priv = card;
	card->dev->tx_timeout = &qeth_tx_timeout;
	card->dev->watchdog_timeo = QETH_TX_TIMEOUT;
	card->dev->open = qeth_l3_open;
	card->dev->stop = qeth_l3_stop;
	card->dev->do_ioctl = qeth_l3_do_ioctl;
	card->dev->get_stats = qeth_get_stats;
	card->dev->change_mtu = qeth_change_mtu;
	card->dev->set_multicast_list = qeth_l3_set_multicast_list;
	card->dev->vlan_rx_register = qeth_l3_vlan_rx_register;
	card->dev->vlan_rx_add_vid = qeth_l3_vlan_rx_add_vid;
	card->dev->vlan_rx_kill_vid = qeth_l3_vlan_rx_kill_vid;
	card->dev->mtu = card->info.initial_mtu;
	card->dev->set_mac_address = NULL;
	SET_ETHTOOL_OPS(card->dev, &qeth_l3_ethtool_ops);
	card->dev->features |=	NETIF_F_HW_VLAN_TX |
				NETIF_F_HW_VLAN_RX |
				NETIF_F_HW_VLAN_FILTER;

	SET_NETDEV_DEV(card->dev, &card->gdev->dev);
	return register_netdev(card->dev);
}

static void qeth_l3_qdio_input_handler(struct ccw_device *ccwdev,
		unsigned int qdio_err, unsigned int queue, int first_element,
		int count, unsigned long card_ptr)
{
	struct net_device *net_dev;
	struct qeth_card *card;
	struct qeth_qdio_buffer *buffer;
	int index;
	int i;

	card = (struct qeth_card *) card_ptr;
	net_dev = card->dev;
	if (card->options.performance_stats) {
		card->perf_stats.inbound_cnt++;
		card->perf_stats.inbound_start_time = qeth_get_micros();
	}
	if (qdio_err & QDIO_ERROR_ACTIVATE_CHECK_CONDITION) {
		QETH_DBF_TEXT(TRACE, 1, "qdinchk");
		QETH_DBF_TEXT_(TRACE, 1, "%s", CARD_BUS_ID(card));
		QETH_DBF_TEXT_(TRACE, 1, "%04X%04X",
				first_element, count);
		QETH_DBF_TEXT_(TRACE, 1, "%04X", queue);
		qeth_schedule_recovery(card);
		return;
	}
	for (i = first_element; i < (first_element + count); ++i) {
		index = i % QDIO_MAX_BUFFERS_PER_Q;
		buffer = &card->qdio.in_q->bufs[index];
		if (!(qdio_err &&
		      qeth_check_qdio_errors(buffer->buffer,
					     qdio_err, "qinerr")))
			qeth_l3_process_inbound_buffer(card, buffer, index);
		/* clear buffer and give back to hardware */
		qeth_put_buffer_pool_entry(card, buffer->pool_entry);
		qeth_queue_input_buffer(card, index);
	}
	if (card->options.performance_stats)
		card->perf_stats.inbound_time += qeth_get_micros() -
			card->perf_stats.inbound_start_time;
}

			if (!card->info.guestlan) {
				card->dev->hw_features = NETIF_F_SG |
					NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
					NETIF_F_TSO;
				card->dev->vlan_features = NETIF_F_SG |
					NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
					NETIF_F_TSO;
			}
		}

		card->dev->netdev_ops = &qeth_l3_osa_netdev_ops;

		/*IPv6 address autoconfiguration stuff*/
		qeth_l3_get_unique_id(card);
		if (!(card->info.unique_id & UNIQUE_ID_NOT_BY_CARD))
			card->dev->dev_id = card->info.unique_id & 0xffff;

		if (!card->info.guestlan) {
			card->dev->features |= NETIF_F_SG;
			card->dev->hw_features |= NETIF_F_TSO |
				NETIF_F_RXCSUM | NETIF_F_IP_CSUM;
			card->dev->vlan_features |= NETIF_F_TSO |
				NETIF_F_RXCSUM | NETIF_F_IP_CSUM;
		}

		if (qeth_is_supported6(card, IPA_OUTBOUND_CHECKSUM_V6)) {
			card->dev->hw_features |= NETIF_F_IPV6_CSUM;
			card->dev->vlan_features |= NETIF_F_IPV6_CSUM;
		}
	} else if (card->info.type == QETH_CARD_TYPE_IQD) {
		card->dev->flags |= IFF_NOARP;
		card->dev->netdev_ops = &qeth_l3_netdev_ops;

		rc = qeth_l3_iqd_read_initial_mac(card);
		if (rc)
			goto out;

		if (card->options.hsuid[0])
			memcpy(card->dev->perm_addr, card->options.hsuid, 9);
	} else
		return -ENODEV;

	card->dev->ethtool_ops = &qeth_l3_ethtool_ops;
	card->dev->needed_headroom = sizeof(struct qeth_hdr) - ETH_HLEN;
	card->dev->features |=	NETIF_F_HW_VLAN_CTAG_TX |
				NETIF_F_HW_VLAN_CTAG_RX |
				NETIF_F_HW_VLAN_CTAG_FILTER;

	netif_keep_dst(card->dev);
	if (card->dev->hw_features & NETIF_F_TSO)
		netif_set_gso_max_size(card->dev,
				       PAGE_SIZE * (QETH_MAX_BUFFER_ELEMENTS(card) - 1));

	netif_napi_add(card->dev, &card->napi, qeth_poll, QETH_NAPI_WEIGHT);
	rc = register_netdev(card->dev);
out:
	if (rc)
		card->dev->netdev_ops = NULL;
	return rc;
}

static const struct device_type qeth_l3_devtype = {
	.name = "qeth_layer3",
	.groups = qeth_l3_attr_groups,
};

static int qeth_l3_probe_device(struct ccwgroup_device *gdev)
{
	struct qeth_card *card = dev_get_drvdata(&gdev->dev);
	int rc;

	hash_init(card->ip_htable);

	if (gdev->dev.type == &qeth_generic_devtype) {
		rc = qeth_l3_create_device_attributes(&gdev->dev);
		if (rc)
			return rc;
	}

	hash_init(card->ip_mc_htable);
	card->options.layer2 = 0;
	card->discipline.input_handler = (qdio_handler_t *)
		qeth_l3_qdio_input_handler;
	card->discipline.output_handler = (qdio_handler_t *)
		qeth_qdio_output_handler;
	card->discipline.recover = qeth_l3_recover;
	card->info.hwtrap = 0;
	return 0;
}

static void qeth_l3_remove_device(struct ccwgroup_device *cgdev)
{
	struct qeth_card *card = dev_get_drvdata(&cgdev->dev);

	wait_event(card->wait_q, qeth_threads_running(card, 0xffffffff) == 0);

	if (cgdev->state == CCWGROUP_ONLINE) {
		card->use_hard_stop = 1;
		qeth_l3_set_offline(cgdev);
	}
	qeth_l3_remove_device_attributes(&cgdev->dev);
	if (cgdev->dev.type == &qeth_generic_devtype)
		qeth_l3_remove_device_attributes(&cgdev->dev);

	qeth_set_allowed_threads(card, 0, 1);
	wait_event(card->wait_q, qeth_threads_running(card, 0xffffffff) == 0);

	if (cgdev->state == CCWGROUP_ONLINE)
		qeth_l3_set_offline(cgdev);

	if (card->dev) {
		netif_napi_del(&card->napi);
		unregister_netdev(card->dev);
		card->dev = NULL;
	}

	qeth_l3_remove_device_attributes(&cgdev->dev);
	qeth_l3_clear_ip_list(card, 0, 0);
	qeth_l3_clear_ip_list(card, 0);
	unregister_netdev(card->dev);
	cancel_work_sync(&card->close_dev_work);
	if (qeth_netdev_is_registered(card->dev))
		unregister_netdev(card->dev);
	qeth_l3_clear_ip_htable(card, 0);
	qeth_l3_clear_ipato_list(card);
}

static int __qeth_l3_set_online(struct ccwgroup_device *gdev, int recovery_mode)
{
	struct qeth_card *card = dev_get_drvdata(&gdev->dev);
	int rc = 0;
	enum qeth_card_states recover_flag;

	BUG_ON(!card);
	QETH_DBF_TEXT(SETUP, 2, "setonlin");
	QETH_DBF_HEX(SETUP, 2, &card, sizeof(void *));

	qeth_set_allowed_threads(card, QETH_RECOVER_THREAD, 1);
	if (qeth_wait_for_threads(card, ~QETH_RECOVER_THREAD)) {
		PRINT_WARN("set_online of card %s interrupted by user!\n",
			   CARD_BUS_ID(card));
		return -ERESTARTSYS;
	}

	recover_flag = card->state;
	rc = ccw_device_set_online(CARD_RDEV(card));
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "1err%d", rc);
		return -EIO;
	}
	rc = ccw_device_set_online(CARD_WDEV(card));
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "1err%d", rc);
		return -EIO;
	}
	rc = ccw_device_set_online(CARD_DDEV(card));
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "1err%d", rc);
		return -EIO;
	}

	rc = qeth_core_hardsetup_card(card);
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "2err%d", rc);
		goto out_remove;
	}

	qeth_l3_query_ipassists(card, QETH_PROT_IPV4);

	if (!card->dev && qeth_l3_setup_netdev(card))
		goto out_remove;

	card->state = CARD_STATE_HARDSETUP;
	mutex_lock(&card->discipline_mutex);
	mutex_lock(&card->conf_mutex);
	QETH_DBF_TEXT(SETUP, 2, "setonlin");
	QETH_DBF_HEX(SETUP, 2, &card, sizeof(void *));

	recover_flag = card->state;
	rc = qeth_core_hardsetup_card(card);
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "2err%04x", rc);
		rc = -ENODEV;
		goto out_remove;
	}

	rc = qeth_l3_setup_netdev(card);
	if (rc)
		goto out_remove;

	if (qeth_is_diagass_supported(card, QETH_DIAGS_CMD_TRAP)) {
		if (card->info.hwtrap &&
		    qeth_hw_trap(card, QETH_DIAGS_TRAP_ARM))
			card->info.hwtrap = 0;
	} else
		card->info.hwtrap = 0;

	card->state = CARD_STATE_HARDSETUP;
	qeth_print_status_message(card);

	/* softsetup */
	QETH_DBF_TEXT(SETUP, 2, "softsetp");

	rc = qeth_send_startlan(card);
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "1err%d", rc);
		if (rc == 0xe080) {
			PRINT_WARN("LAN on card %s if offline! "
				   "Waiting for STARTLAN from card.\n",
				   CARD_BUS_ID(card));
			card->lan_online = 0;
		}
		return rc;
	} else
		card->lan_online = 1;
	qeth_set_large_send(card, card->options.large_send);

	rc = qeth_l3_setadapter_parms(card);
	if (rc)
		QETH_DBF_TEXT_(SETUP, 2, "2err%d", rc);
	rc = qeth_l3_start_ipassists(card);
	if (rc)
		QETH_DBF_TEXT_(SETUP, 2, "3err%d", rc);
	rc = qeth_l3_setrouting_v4(card);
	if (rc)
		QETH_DBF_TEXT_(SETUP, 2, "4err%d", rc);
	rc = qeth_l3_setrouting_v6(card);
	if (rc)
		QETH_DBF_TEXT_(SETUP, 2, "5err%d", rc);
			dev_warn(&card->gdev->dev,
				"The LAN is offline\n");
			card->lan_online = 0;
			goto contin;
		}
		rc = -ENODEV;
		goto out_remove;
	} else
		card->lan_online = 1;

contin:
	rc = qeth_l3_setadapter_parms(card);
	if (rc)
		QETH_DBF_TEXT_(SETUP, 2, "2err%04x", rc);
	if (!card->options.sniffer) {
		rc = qeth_l3_start_ipassists(card);
		if (rc) {
			QETH_DBF_TEXT_(SETUP, 2, "3err%d", rc);
			goto out_remove;
		}
		rc = qeth_l3_setrouting_v4(card);
		if (rc)
			QETH_DBF_TEXT_(SETUP, 2, "4err%04x", rc);
		rc = qeth_l3_setrouting_v6(card);
		if (rc)
			QETH_DBF_TEXT_(SETUP, 2, "5err%04x", rc);
	}
	netif_tx_disable(card->dev);

	rc = qeth_init_qdio_queues(card);
	if (rc) {
		QETH_DBF_TEXT_(SETUP, 2, "6err%d", rc);
		goto out_remove;
	}
	card->state = CARD_STATE_SOFTSETUP;
	netif_carrier_on(card->dev);

	qeth_set_allowed_threads(card, 0xffffffff, 0);
	if (recover_flag == CARD_STATE_RECOVER) {
		if (recovery_mode)
			qeth_l3_open(card->dev);
		else {
			rtnl_lock();
			dev_open(card->dev);
			rtnl_unlock();
		}
		qeth_l3_set_multicast_list(card->dev);
	}
	/* let user_space know that device is online */
	kobject_uevent(&gdev->dev.kobj, KOBJ_CHANGE);
	return 0;
out_remove:
	card->use_hard_stop = 1;
		rc = -ENODEV;
		goto out_remove;
	}
	card->state = CARD_STATE_SOFTSETUP;

	qeth_set_allowed_threads(card, 0xffffffff, 0);
	qeth_l3_recover_ip(card);
	if (card->lan_online)
		netif_carrier_on(card->dev);
	else
		netif_carrier_off(card->dev);

	qeth_enable_hw_features(card->dev);
	if (recover_flag == CARD_STATE_RECOVER) {
		rtnl_lock();
		if (recovery_mode) {
			__qeth_l3_open(card->dev);
			qeth_l3_set_rx_mode(card->dev);
		} else {
			dev_open(card->dev);
		}
		rtnl_unlock();
	}
	qeth_trace_features(card);
	/* let user_space know that device is online */
	kobject_uevent(&gdev->dev.kobj, KOBJ_CHANGE);
	mutex_unlock(&card->conf_mutex);
	mutex_unlock(&card->discipline_mutex);
	return 0;
out_remove:
	qeth_l3_stop_card(card, 0);
	ccw_device_set_offline(CARD_DDEV(card));
	ccw_device_set_offline(CARD_WDEV(card));
	ccw_device_set_offline(CARD_RDEV(card));
	qdio_free(CARD_DDEV(card));
	if (recover_flag == CARD_STATE_RECOVER)
		card->state = CARD_STATE_RECOVER;
	else
		card->state = CARD_STATE_DOWN;
	return -ENODEV;
	mutex_unlock(&card->conf_mutex);
	mutex_unlock(&card->discipline_mutex);
	return rc;
}

static int qeth_l3_set_online(struct ccwgroup_device *gdev)
{
	return __qeth_l3_set_online(gdev, 0);
}

static int __qeth_l3_set_offline(struct ccwgroup_device *cgdev,
			int recovery_mode)
{
	struct qeth_card *card = dev_get_drvdata(&cgdev->dev);
	int rc = 0, rc2 = 0, rc3 = 0;
	enum qeth_card_states recover_flag;

	mutex_lock(&card->discipline_mutex);
	mutex_lock(&card->conf_mutex);
	QETH_DBF_TEXT(SETUP, 3, "setoffl");
	QETH_DBF_HEX(SETUP, 3, &card, sizeof(void *));

	netif_carrier_off(card->dev);
	recover_flag = card->state;
	if (qeth_l3_stop_card(card, recovery_mode) == -ERESTARTSYS) {
		PRINT_WARN("Stopping card %s interrupted by user!\n",
			   CARD_BUS_ID(card));
		return -ERESTARTSYS;
	if ((!recovery_mode && card->info.hwtrap) || card->info.hwtrap == 2) {
		qeth_hw_trap(card, QETH_DIAGS_TRAP_DISARM);
		card->info.hwtrap = 1;
	}
	qeth_l3_stop_card(card, recovery_mode);
	if ((card->options.cq == QETH_CQ_ENABLED) && card->dev) {
		rtnl_lock();
		call_netdevice_notifiers(NETDEV_REBOOT, card->dev);
		rtnl_unlock();
	}
	rc  = ccw_device_set_offline(CARD_DDEV(card));
	rc2 = ccw_device_set_offline(CARD_WDEV(card));
	rc3 = ccw_device_set_offline(CARD_RDEV(card));
	if (!rc)
		rc = (rc2) ? rc2 : rc3;
	if (rc)
		QETH_DBF_TEXT_(SETUP, 2, "1err%d", rc);
	qdio_free(CARD_DDEV(card));
	if (recover_flag == CARD_STATE_UP)
		card->state = CARD_STATE_RECOVER;
	/* let user_space know that device is offline */
	kobject_uevent(&cgdev->dev.kobj, KOBJ_CHANGE);
	mutex_unlock(&card->conf_mutex);
	mutex_unlock(&card->discipline_mutex);
	return 0;
}

static int qeth_l3_set_offline(struct ccwgroup_device *cgdev)
{
	return __qeth_l3_set_offline(cgdev, 0);
}

static int qeth_l3_recover(void *ptr)
{
	struct qeth_card *card;
	int rc = 0;

	card = (struct qeth_card *) ptr;
	QETH_DBF_TEXT(TRACE, 2, "recover1");
	QETH_DBF_HEX(TRACE, 2, &card, sizeof(void *));
	if (!qeth_do_run_thread(card, QETH_RECOVER_THREAD))
		return 0;
	QETH_DBF_TEXT(TRACE, 2, "recover2");
	PRINT_WARN("Recovery of device %s started ...\n",
		   CARD_BUS_ID(card));
	card->use_hard_stop = 1;
	__qeth_l3_set_offline(card->gdev, 1);
	rc = __qeth_l3_set_online(card->gdev, 1);
	/* don't run another scheduled recovery */
	qeth_clear_thread_start_bit(card, QETH_RECOVER_THREAD);
	qeth_clear_thread_running_bit(card, QETH_RECOVER_THREAD);
	if (!rc)
		PRINT_INFO("Device %s successfully recovered!\n",
			   CARD_BUS_ID(card));
	else
		PRINT_INFO("Device %s could not be recovered!\n",
			   CARD_BUS_ID(card));
	QETH_CARD_TEXT(card, 2, "recover1");
	QETH_CARD_HEX(card, 2, &card, sizeof(void *));
	if (!qeth_do_run_thread(card, QETH_RECOVER_THREAD))
		return 0;
	QETH_CARD_TEXT(card, 2, "recover2");
	dev_warn(&card->gdev->dev,
		"A recovery process has been started for the device\n");
	qeth_set_recovery_task(card);
	__qeth_l3_set_offline(card->gdev, 1);
	rc = __qeth_l3_set_online(card->gdev, 1);
	if (!rc)
		dev_info(&card->gdev->dev,
			"Device successfully recovered!\n");
	else {
		qeth_close_dev(card);
		dev_warn(&card->gdev->dev, "The qeth device driver "
				"failed to recover an error on the device\n");
	}
	qeth_clear_recovery_task(card);
	qeth_clear_thread_start_bit(card, QETH_RECOVER_THREAD);
	qeth_clear_thread_running_bit(card, QETH_RECOVER_THREAD);
	return 0;
}

static void qeth_l3_shutdown(struct ccwgroup_device *gdev)
{
	struct qeth_card *card = dev_get_drvdata(&gdev->dev);
	qeth_l3_clear_ip_list(card, 0, 0);
	qeth_qdio_clear_card(card, 0);
	qeth_clear_qdio_buffers(card);
}

struct ccwgroup_driver qeth_l3_ccwgroup_driver = {
	.probe = qeth_l3_probe_device,
	qeth_set_allowed_threads(card, 0, 1);
	if ((gdev->state == CCWGROUP_ONLINE) && card->info.hwtrap)
		qeth_hw_trap(card, QETH_DIAGS_TRAP_DISARM);
	qeth_qdio_clear_card(card, 0);
	qeth_clear_qdio_buffers(card);
	qdio_free(CARD_DDEV(card));
}

static int qeth_l3_pm_suspend(struct ccwgroup_device *gdev)
{
	struct qeth_card *card = dev_get_drvdata(&gdev->dev);

	netif_device_detach(card->dev);
	qeth_set_allowed_threads(card, 0, 1);
	wait_event(card->wait_q, qeth_threads_running(card, 0xffffffff) == 0);
	if (gdev->state == CCWGROUP_OFFLINE)
		return 0;
	if (card->state == CARD_STATE_UP) {
		if (card->info.hwtrap)
			qeth_hw_trap(card, QETH_DIAGS_TRAP_DISARM);
		__qeth_l3_set_offline(card->gdev, 1);
	} else
		__qeth_l3_set_offline(card->gdev, 0);
	return 0;
}

static int qeth_l3_pm_resume(struct ccwgroup_device *gdev)
{
	struct qeth_card *card = dev_get_drvdata(&gdev->dev);
	int rc = 0;

	if (gdev->state == CCWGROUP_OFFLINE)
		goto out;

	if (card->state == CARD_STATE_RECOVER) {
		rc = __qeth_l3_set_online(card->gdev, 1);
		if (rc) {
			rtnl_lock();
			dev_close(card->dev);
			rtnl_unlock();
		}
	} else
		rc = __qeth_l3_set_online(card->gdev, 0);
out:
	qeth_set_allowed_threads(card, 0xffffffff, 0);
	netif_device_attach(card->dev);
	if (rc)
		dev_warn(&card->gdev->dev, "The qeth device driver "
			"failed to recover an error on the device\n");
	return rc;
}

/* Returns zero if the command is successfully "consumed" */
static int qeth_l3_control_event(struct qeth_card *card,
					struct qeth_ipa_cmd *cmd)
{
	return 1;
}

struct qeth_discipline qeth_l3_discipline = {
	.devtype = &qeth_l3_devtype,
	.process_rx_buffer = qeth_l3_process_inbound_buffer,
	.recover = qeth_l3_recover,
	.setup = qeth_l3_probe_device,
	.remove = qeth_l3_remove_device,
	.set_online = qeth_l3_set_online,
	.set_offline = qeth_l3_set_offline,
	.shutdown = qeth_l3_shutdown,
};
EXPORT_SYMBOL_GPL(qeth_l3_ccwgroup_driver);
	.freeze = qeth_l3_pm_suspend,
	.thaw = qeth_l3_pm_resume,
	.restore = qeth_l3_pm_resume,
	.do_ioctl = qeth_l3_do_ioctl,
	.control_event_handler = qeth_l3_control_event,
};
EXPORT_SYMBOL_GPL(qeth_l3_discipline);

static int qeth_l3_handle_ip_event(struct qeth_card *card,
				   struct qeth_ipaddr *addr,
				   unsigned long event)
{
	switch (event) {
	case NETDEV_UP:
		spin_lock_bh(&card->ip_lock);
		qeth_l3_add_ip(card, addr);
		spin_unlock_bh(&card->ip_lock);
		return NOTIFY_OK;
	case NETDEV_DOWN:
		spin_lock_bh(&card->ip_lock);
		qeth_l3_delete_ip(card, addr);
		spin_unlock_bh(&card->ip_lock);
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

static struct qeth_card *qeth_l3_get_card_from_dev(struct net_device *dev)
{
	if (is_vlan_dev(dev))
		dev = vlan_dev_real_dev(dev);
	if (dev->netdev_ops == &qeth_l3_osa_netdev_ops ||
	    dev->netdev_ops == &qeth_l3_netdev_ops)
		return (struct qeth_card *) dev->ml_priv;
	return NULL;
}

static int qeth_l3_ip_event(struct notifier_block *this,
			    unsigned long event, void *ptr)
{

	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct qeth_ipaddr addr;
	struct qeth_card *card;

	if (dev_net(dev) != &init_net)
		return NOTIFY_DONE;

	QETH_DBF_TEXT(TRACE, 3, "ipevent");
	card = qeth_l3_get_card_from_dev(dev);
	if (!card)
		return NOTIFY_DONE;
	card = qeth_l3_get_card_from_dev(dev);
	if (!card)
		return NOTIFY_DONE;
	QETH_CARD_TEXT(card, 3, "ipevent");

	qeth_l3_init_ipaddr(&addr, QETH_IP_TYPE_NORMAL, QETH_PROT_IPV4);
	addr.u.a4.addr = be32_to_cpu(ifa->ifa_address);
	addr.u.a4.mask = be32_to_cpu(ifa->ifa_mask);

	return qeth_l3_handle_ip_event(card, &addr, event);
}

static struct notifier_block qeth_l3_ip_notifier = {
	qeth_l3_ip_event,
	NULL,
};

static int qeth_l3_ip6_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)ptr;
	struct net_device *dev = ifa->idev->dev;
	struct qeth_ipaddr addr;
	struct qeth_card *card;

	QETH_DBF_TEXT(TRACE, 3, "ip6event");

	card = qeth_l3_get_card_from_dev(dev);
	if (!card)
		return NOTIFY_DONE;
	card = qeth_l3_get_card_from_dev(dev);
	if (!card)
		return NOTIFY_DONE;
	QETH_CARD_TEXT(card, 3, "ip6event");
	if (!qeth_is_supported(card, IPA_IPV6))
		return NOTIFY_DONE;

	qeth_l3_init_ipaddr(&addr, QETH_IP_TYPE_NORMAL, QETH_PROT_IPV6);
	addr.u.a6.addr = ifa->addr;
	addr.u.a6.pfxlen = ifa->prefix_len;

	return qeth_l3_handle_ip_event(card, &addr, event);
}

static struct notifier_block qeth_l3_ip6_notifier = {
	qeth_l3_ip6_event,
	NULL,
};

static int qeth_l3_register_notifiers(void)
{
	int rc;

	QETH_DBF_TEXT(TRACE, 5, "regnotif");
	QETH_DBF_TEXT(SETUP, 5, "regnotif");
	rc = register_inetaddr_notifier(&qeth_l3_ip_notifier);
	if (rc)
		return rc;
	rc = register_inet6addr_notifier(&qeth_l3_ip6_notifier);
	if (rc) {
		unregister_inetaddr_notifier(&qeth_l3_ip_notifier);
		return rc;
	}
#else
	PRINT_WARN("layer 3 discipline no IPv6 support\n");
	pr_warning("There is no IPv6 support for the layer 3 discipline\n");
	pr_warn("There is no IPv6 support for the layer 3 discipline\n");
#endif
	return 0;
}

static void qeth_l3_unregister_notifiers(void)
{

	QETH_DBF_TEXT(TRACE, 5, "unregnot");
	BUG_ON(unregister_inetaddr_notifier(&qeth_l3_ip_notifier));
#ifdef CONFIG_QETH_IPV6
	BUG_ON(unregister_inet6addr_notifier(&qeth_l3_ip6_notifier));
	QETH_DBF_TEXT(SETUP, 5, "unregnot");
	WARN_ON(unregister_inetaddr_notifier(&qeth_l3_ip_notifier));
	WARN_ON(unregister_inet6addr_notifier(&qeth_l3_ip6_notifier));
}

static int __init qeth_l3_init(void)
{
	int rc = 0;

	PRINT_INFO("register layer 3 discipline\n");
	pr_info("register layer 3 discipline\n");
	return qeth_l3_register_notifiers();
}

static void __exit qeth_l3_exit(void)
{
	qeth_l3_unregister_notifiers();
	PRINT_INFO("unregister layer 3 discipline\n");
	pr_info("unregister layer 3 discipline\n");
}

module_init(qeth_l3_init);
module_exit(qeth_l3_exit);
MODULE_AUTHOR("Frank Blaschka <frank.blaschka@de.ibm.com>");
MODULE_DESCRIPTION("qeth layer 3 discipline");
MODULE_LICENSE("GPL");
