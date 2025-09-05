/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_DEF_H
#define __NET_TC_DEF_H

#include <net/act_api.h>

struct tcf_defact {
	struct tc_action	common;
	u32		tcfd_datalen;
	void		*tcfd_defdata;
};
#define to_defact(pc) \
	container_of(pc, struct tcf_defact, common)
#define to_defact(a) \
	container_of(a->priv, struct tcf_defact, common)
#define to_defact(a) ((struct tcf_defact *)a)

#endif /* __NET_TC_DEF_H */
