/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_NAT_H
#define __NET_TC_NAT_H

#include <linux/types.h>
#include <net/act_api.h>

struct tcf_nat {
	struct tc_action common;

	__be32 old_addr;
	__be32 new_addr;
	__be32 mask;
	u32 flags;
};

static inline struct tcf_nat *to_tcf_nat(struct tcf_common *pc)
{
	return container_of(pc, struct tcf_nat, common);
static inline struct tcf_nat *to_tcf_nat(struct tc_action *a)
{
	return container_of(a->priv, struct tcf_nat, common);
}
#define to_tcf_nat(a) ((struct tcf_nat *)a)

#endif /* __NET_TC_NAT_H */
