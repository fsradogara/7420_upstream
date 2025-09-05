/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Access vector cache interface for the security server.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
#ifndef _SELINUX_AVC_SS_H_
#define _SELINUX_AVC_SS_H_

#include "flask.h"

int avc_ss_reset(u32 seqno);

struct av_perm_to_string {
	u16 tclass;
	u32 value;
	const char *name;
};

struct av_inherit {
	u16 tclass;
	const char **common_pts;
	u32 common_base;
};

struct selinux_class_perm {
	const struct av_perm_to_string *av_perm_to_string;
	u32 av_pts_len;
	const char **class_to_string;
	u32 cts_len;
	const struct av_inherit *av_inherit;
	u32 av_inherit_len;
};
/* Class/perm mapping support */
struct security_class_mapping {
	const char *name;
	const char *perms[sizeof(u32) * 8 + 1];
};

extern struct security_class_mapping secclass_map[];

/*
 * The security server must be initialized before
 * any labeling or access decisions can be provided.
 */
extern int ss_initialized;

#endif /* _SELINUX_AVC_SS_H_ */

