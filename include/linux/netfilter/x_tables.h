/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X_TABLES_H
#define _X_TABLES_H

#define XT_FUNCTION_MAXNAMELEN 30
#define XT_TABLE_MAXNAMELEN 32

struct xt_entry_match
{
	union {
		struct {
			u_int16_t match_size;

			/* Used by userspace */
			char name[XT_FUNCTION_MAXNAMELEN-1];

			u_int8_t revision;
		} user;
		struct {
			u_int16_t match_size;

			/* Used inside the kernel */
			struct xt_match *match;
		} kernel;

		/* Total length */
		u_int16_t match_size;
	} u;

	unsigned char data[0];
};

struct xt_entry_target
{
	union {
		struct {
			u_int16_t target_size;

			/* Used by userspace */
			char name[XT_FUNCTION_MAXNAMELEN-1];

			u_int8_t revision;
		} user;
		struct {
			u_int16_t target_size;

			/* Used inside the kernel */
			struct xt_target *target;
		} kernel;

		/* Total length */
		u_int16_t target_size;
	} u;

	unsigned char data[0];
};

#define XT_TARGET_INIT(__name, __size)					       \
{									       \
	.target.u.user = {						       \
		.target_size	= XT_ALIGN(__size),			       \
		.name		= __name,				       \
	},								       \
}

struct xt_standard_target
{
	struct xt_entry_target target;
	int verdict;
};

/* The argument to IPT_SO_GET_REVISION_*.  Returns highest revision
 * kernel supports, if >= revision. */
struct xt_get_revision
{
	char name[XT_FUNCTION_MAXNAMELEN-1];

	u_int8_t revision;
};

/* CONTINUE verdict for targets */
#define XT_CONTINUE 0xFFFFFFFF

/* For standard target */
#define XT_RETURN (-NF_REPEAT - 1)

/* this is a dummy structure to find out the alignment requirement for a struct
 * containing all the fundamental data types that are used in ipt_entry,
 * ip6t_entry and arpt_entry.  This sucks, and it is a hack.  It will be my
 * personal pleasure to remove it -HW
 */
struct _xt_align
{
	u_int8_t u8;
	u_int16_t u16;
	u_int32_t u32;
	u_int64_t u64;
};

#define XT_ALIGN(s) (((s) + (__alignof__(struct _xt_align)-1)) 	\
			& ~(__alignof__(struct _xt_align)-1))

/* Standard return verdict, or do jump. */
#define XT_STANDARD_TARGET ""
/* Error verdict. */
#define XT_ERROR_TARGET "ERROR"

#define SET_COUNTER(c,b,p) do { (c).bcnt = (b); (c).pcnt = (p); } while(0)
#define ADD_COUNTER(c,b,p) do { (c).bcnt += (b); (c).pcnt += (p); } while(0)

struct xt_counters
{
	u_int64_t pcnt, bcnt;			/* Packet and byte counters */
};

/* The argument to IPT_SO_ADD_COUNTERS. */
struct xt_counters_info
{
	/* Which table. */
	char name[XT_TABLE_MAXNAMELEN];

	unsigned int num_counters;

	/* The counters (actually `number' of these). */
	struct xt_counters counters[0];
};

#define XT_INV_PROTO		0x40	/* Invert the sense of PROTO. */

/* fn returns 0 to continue iteration */
#define XT_MATCH_ITERATE(type, e, fn, args...)			\
({								\
	unsigned int __i;					\
	int __ret = 0;						\
	struct xt_entry_match *__m;				\
								\
	for (__i = sizeof(type);				\
	     __i < (e)->target_offset;				\
	     __i += __m->u.match_size) {			\
		__m = (void *)e + __i;				\
								\
		__ret = fn(__m , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define XT_ENTRY_ITERATE_CONTINUE(type, entries, size, n, fn, args...) \
({								\
	unsigned int __i, __n;					\
	int __ret = 0;						\
	type *__entry;						\
								\
	for (__i = 0, __n = 0; __i < (size);			\
	     __i += __entry->next_offset, __n++) { 		\
		__entry = (void *)(entries) + __i;		\
		if (__n < n)					\
			continue;				\
								\
		__ret = fn(__entry , ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define XT_ENTRY_ITERATE(type, entries, size, fn, args...) \
	XT_ENTRY_ITERATE_CONTINUE(type, entries, size, 0, fn, args)

#ifdef __KERNEL__

#include <linux/netdevice.h>

struct xt_match
{
	struct list_head list;

	const char name[XT_FUNCTION_MAXNAMELEN-1];

#include <linux/netdevice.h>
#include <linux/static_key.h>
#include <linux/netfilter.h>
#include <uapi/linux/netfilter/x_tables.h>

/* Test a struct->invflags and a boolean for inequality */
#define NF_INVF(ptr, flag, boolean)					\
	((boolean) ^ !!((ptr)->invflags & (flag)))

/**
 * struct xt_action_param - parameters for matches/targets
 *
 * @match:	the match extension
 * @target:	the target extension
 * @matchinfo:	per-match data
 * @targetinfo:	per-target data
 * @state:	pointer to hook state this packet came from
 * @fragoff:	packet is a fragment, this is the data offset
 * @thoff:	position of transport header relative to skb->data
 *
 * Fields written to by extensions:
 *
 * @hotdrop:	drop packet if we had inspection problems
 */
struct xt_action_param {
	union {
		const struct xt_match *match;
		const struct xt_target *target;
	};
	union {
		const void *matchinfo, *targinfo;
	};
	const struct nf_hook_state *state;
	int fragoff;
	unsigned int thoff;
	bool hotdrop;
};

static inline struct net *xt_net(const struct xt_action_param *par)
{
	return par->state->net;
}

static inline struct net_device *xt_in(const struct xt_action_param *par)
{
	return par->state->in;
}

static inline const char *xt_inname(const struct xt_action_param *par)
{
	return par->state->in->name;
}

static inline struct net_device *xt_out(const struct xt_action_param *par)
{
	return par->state->out;
}

static inline const char *xt_outname(const struct xt_action_param *par)
{
	return par->state->out->name;
}

static inline unsigned int xt_hooknum(const struct xt_action_param *par)
{
	return par->state->hook;
}

static inline u_int8_t xt_family(const struct xt_action_param *par)
{
	return par->state->pf;
}

/**
 * struct xt_mtchk_param - parameters for match extensions'
 * checkentry functions
 *
 * @net:	network namespace through which the check was invoked
 * @table:	table the rule is tried to be inserted into
 * @entryinfo:	the family-specific rule data
 * 		(struct ipt_ip, ip6t_ip, arpt_arp or (note) ebt_entry)
 * @match:	struct xt_match through which this function was invoked
 * @matchinfo:	per-match data
 * @hook_mask:	via which hooks the new rule is reachable
 * Other fields as above.
 */
struct xt_mtchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_match *match;
	void *matchinfo;
	unsigned int hook_mask;
	u_int8_t family;
	bool nft_compat;
};

/**
 * struct xt_mdtor_param - match destructor parameters
 * Fields as above.
 */
struct xt_mtdtor_param {
	struct net *net;
	const struct xt_match *match;
	void *matchinfo;
	u_int8_t family;
};

/**
 * struct xt_tgchk_param - parameters for target extensions'
 * checkentry functions
 *
 * @entryinfo:	the family-specific rule data
 * 		(struct ipt_entry, ip6t_entry, arpt_entry, ebt_entry)
 *
 * Other fields see above.
 */
struct xt_tgchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_target *target;
	void *targinfo;
	unsigned int hook_mask;
	u_int8_t family;
	bool nft_compat;
};

/* Target destructor parameters */
struct xt_tgdtor_param {
	struct net *net;
	const struct xt_target *target;
	void *targinfo;
	u_int8_t family;
};

struct xt_match {
	struct list_head list;

	const char name[XT_EXTENSION_MAXNAMELEN];
	u_int8_t revision;

	/* Return true or false: return FALSE and set *hotdrop = 1 to
           force immediate packet drop. */
	/* Arguments changed since 2.6.9, as this must now handle
	   non-linear skb, using skb_header_pointer and
	   skb_ip_make_writable. */
	bool (*match)(const struct sk_buff *skb,
		      const struct net_device *in,
		      const struct net_device *out,
		      const struct xt_match *match,
		      const void *matchinfo,
		      int offset,
		      unsigned int protoff,
		      bool *hotdrop);

	/* Called when user tries to insert an entry of this type. */
	/* Should return true or false. */
	bool (*checkentry)(const char *tablename,
			   const void *ip,
			   const struct xt_match *match,
			   void *matchinfo,
			   unsigned int hook_mask);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_match *match, void *matchinfo);

	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, void *src);
	int (*compat_to_user)(void __user *dst, void *src);

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	/* Free to use by each match */
	unsigned long data;

	const char *table;
	unsigned int matchsize;
	unsigned int compatsize;
		      struct xt_action_param *);

	/* Called when user tries to insert an entry of this type. */
	int (*checkentry)(const struct xt_mtchk_param *);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_mtdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int matchsize;
	unsigned int usersize;
#ifdef CONFIG_COMPAT
	unsigned int compatsize;
#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
	u_int8_t revision;
};

/* Registration hooks for targets. */
struct xt_target
{
	struct list_head list;

	const char name[XT_FUNCTION_MAXNAMELEN-1];
};

/* Registration hooks for targets. */
struct xt_target {
	struct list_head list;

	const char name[XT_EXTENSION_MAXNAMELEN];
	u_int8_t revision;

	/* Returns verdict. Argument order changed since 2.6.9, as this
	   must now handle non-linear skbs, using skb_copy_bits and
	   skb_ip_make_writable. */
	unsigned int (*target)(struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       unsigned int hooknum,
			       const struct xt_target *target,
			       const void *targinfo);
			       const struct xt_action_param *);

	/* Called when user tries to insert an entry of this type:
           hook_mask is a bitmask of hooks from which it can be
           called. */
	/* Should return true or false. */
	bool (*checkentry)(const char *tablename,
			   const void *entry,
			   const struct xt_target *target,
			   void *targinfo,
			   unsigned int hook_mask);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_target *target, void *targinfo);

	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, void *src);
	int (*compat_to_user)(void __user *dst, void *src);

	/* Should return 0 on success or an error code otherwise (-Exxxx). */
	int (*checkentry)(const struct xt_tgchk_param *);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_tgdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int targetsize;
	unsigned int compatsize;
	unsigned int usersize;
#ifdef CONFIG_COMPAT
	unsigned int compatsize;
#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
	u_int8_t revision;
};

/* Furniture shopping... */
struct xt_table
{
	struct list_head list;

	/* A unique name... */
	const char name[XT_TABLE_MAXNAMELEN];

	/* What hooks you will enter on */
	unsigned int valid_hooks;

	/* Lock for the curtain */
	rwlock_t lock;

	/* Man behind the curtain... */
	//struct ip6t_table_info *private;
	void *private;
};

/* Furniture shopping... */
struct xt_table {
	struct list_head list;

	/* What hooks you will enter on */
	unsigned int valid_hooks;

	/* Man behind the curtain... */
	struct xt_table_info *private;

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	int af;		/* address/protocol family */
	u_int8_t af;		/* address/protocol family */
	int priority;		/* hook order */

	/* called when table is needed in the given netns */
	int (*table_init)(struct net *net);

	/* A unique name... */
	const char name[XT_TABLE_MAXNAMELEN];
};

#include <linux/netfilter_ipv4.h>

/* The table itself */
struct xt_table_info
{
struct xt_table_info {
	/* Size per table */
	unsigned int size;
	/* Number of entries: FIXME. --RR */
	unsigned int number;
	/* Initial number of entries. Needed for module usage count */
	unsigned int initial_entries;

	/* Entry points and underflows */
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* ipt_entry tables: one per CPU */
	/* Note : this field MUST be the last one, see XT_TABLE_INFO_SZ */
	char *entries[1];
};

#define XT_TABLE_INFO_SZ (offsetof(struct xt_table_info, entries) \
			  + nr_cpu_ids * sizeof(char *))
extern int xt_register_target(struct xt_target *target);
extern void xt_unregister_target(struct xt_target *target);
extern int xt_register_targets(struct xt_target *target, unsigned int n);
extern void xt_unregister_targets(struct xt_target *target, unsigned int n);

extern int xt_register_match(struct xt_match *target);
extern void xt_unregister_match(struct xt_match *target);
extern int xt_register_matches(struct xt_match *match, unsigned int n);
extern void xt_unregister_matches(struct xt_match *match, unsigned int n);

extern int xt_check_match(const struct xt_match *match, unsigned short family,
			  unsigned int size, const char *table, unsigned int hook,
			  unsigned short proto, int inv_proto);
extern int xt_check_target(const struct xt_target *target, unsigned short family,
			   unsigned int size, const char *table, unsigned int hook,
			   unsigned short proto, int inv_proto);

extern struct xt_table *xt_register_table(struct net *net,
					  struct xt_table *table,
					  struct xt_table_info *bootstrap,
					  struct xt_table_info *newinfo);
extern void *xt_unregister_table(struct xt_table *table);

extern struct xt_table_info *xt_replace_table(struct xt_table *table,
					      unsigned int num_counters,
					      struct xt_table_info *newinfo,
					      int *error);

extern struct xt_match *xt_find_match(int af, const char *name, u8 revision);
extern struct xt_target *xt_find_target(int af, const char *name, u8 revision);
extern struct xt_target *xt_request_find_target(int af, const char *name, 
						u8 revision);
extern int xt_find_revision(int af, const char *name, u8 revision, int target,
			    int *err);

extern struct xt_table *xt_find_table_lock(struct net *net, int af,
					   const char *name);
extern void xt_table_unlock(struct xt_table *t);

extern int xt_proto_init(struct net *net, int af);
extern void xt_proto_fini(struct net *net, int af);

extern struct xt_table_info *xt_alloc_table_info(unsigned int size);
extern void xt_free_table_info(struct xt_table_info *info);
	/*
	 * Number of user chains. Since tables cannot have loops, at most
	 * @stacksize jumps (number of user chains) can possibly be made.
	 */
	unsigned int stacksize;
	void ***jumpstack;

	unsigned char entries[0] __aligned(8);
};

int xt_register_target(struct xt_target *target);
void xt_unregister_target(struct xt_target *target);
int xt_register_targets(struct xt_target *target, unsigned int n);
void xt_unregister_targets(struct xt_target *target, unsigned int n);

int xt_register_match(struct xt_match *target);
void xt_unregister_match(struct xt_match *target);
int xt_register_matches(struct xt_match *match, unsigned int n);
void xt_unregister_matches(struct xt_match *match, unsigned int n);

int xt_check_entry_offsets(const void *base, const char *elems,
			   unsigned int target_offset,
			   unsigned int next_offset);

unsigned int *xt_alloc_entry_offsets(unsigned int size);
bool xt_find_jump_offset(const unsigned int *offsets,
			 unsigned int target, unsigned int size);

int xt_check_match(struct xt_mtchk_param *, unsigned int size, u_int8_t proto,
		   bool inv_proto);
int xt_check_target(struct xt_tgchk_param *, unsigned int size, u_int8_t proto,
		    bool inv_proto);

int xt_match_to_user(const struct xt_entry_match *m,
		     struct xt_entry_match __user *u);
int xt_target_to_user(const struct xt_entry_target *t,
		      struct xt_entry_target __user *u);
int xt_data_to_user(void __user *dst, const void *src,
		    int usersize, int size, int aligned_size);

void *xt_copy_counters_from_user(const void __user *user, unsigned int len,
				 struct xt_counters_info *info, bool compat);

struct xt_table *xt_register_table(struct net *net,
				   const struct xt_table *table,
				   struct xt_table_info *bootstrap,
				   struct xt_table_info *newinfo);
void *xt_unregister_table(struct xt_table *table);

struct xt_table_info *xt_replace_table(struct xt_table *table,
				       unsigned int num_counters,
				       struct xt_table_info *newinfo,
				       int *error);

struct xt_match *xt_find_match(u8 af, const char *name, u8 revision);
struct xt_target *xt_find_target(u8 af, const char *name, u8 revision);
struct xt_match *xt_request_find_match(u8 af, const char *name, u8 revision);
struct xt_target *xt_request_find_target(u8 af, const char *name, u8 revision);
int xt_find_revision(u8 af, const char *name, u8 revision, int target,
		     int *err);

struct xt_table *xt_find_table_lock(struct net *net, u_int8_t af,
				    const char *name);
void xt_table_unlock(struct xt_table *t);

int xt_proto_init(struct net *net, u_int8_t af);
void xt_proto_fini(struct net *net, u_int8_t af);

struct xt_table_info *xt_alloc_table_info(unsigned int size);
void xt_free_table_info(struct xt_table_info *info);

/**
 * xt_recseq - recursive seqcount for netfilter use
 * 
 * Packet processing changes the seqcount only if no recursion happened
 * get_counters() can use read_seqcount_begin()/read_seqcount_retry(),
 * because we use the normal seqcount convention :
 * Low order bit set to 1 if a writer is active.
 */
DECLARE_PER_CPU(seqcount_t, xt_recseq);

/* xt_tee_enabled - true if x_tables needs to handle reentrancy
 *
 * Enabled if current ip(6)tables ruleset has at least one -j TEE rule.
 */
extern struct static_key xt_tee_enabled;

/**
 * xt_write_recseq_begin - start of a write section
 *
 * Begin packet processing : all readers must wait the end
 * 1) Must be called with preemption disabled
 * 2) softirqs must be disabled too (or we should use this_cpu_add())
 * Returns :
 *  1 if no recursion on this cpu
 *  0 if recursion detected
 */
static inline unsigned int xt_write_recseq_begin(void)
{
	unsigned int addend;

	/*
	 * Low order bit of sequence is set if we already
	 * called xt_write_recseq_begin().
	 */
	addend = (__this_cpu_read(xt_recseq.sequence) + 1) & 1;

	/*
	 * This is kind of a write_seqcount_begin(), but addend is 0 or 1
	 * We dont check addend value to avoid a test and conditional jump,
	 * since addend is most likely 1
	 */
	__this_cpu_add(xt_recseq.sequence, addend);
	smp_wmb();

	return addend;
}

/**
 * xt_write_recseq_end - end of a write section
 * @addend: return value from previous xt_write_recseq_begin()
 *
 * End packet processing : all readers can proceed
 * 1) Must be called with preemption disabled
 * 2) softirqs must be disabled too (or we should use this_cpu_add())
 */
static inline void xt_write_recseq_end(unsigned int addend)
{
	/* this is kind of a write_seqcount_end(), but addend is 0 or 1 */
	smp_wmb();
	__this_cpu_add(xt_recseq.sequence, addend);
}

/*
 * This helper is performance critical and must be inlined
 */
static inline unsigned long ifname_compare_aligned(const char *_a,
						   const char *_b,
						   const char *_mask)
{
	const unsigned long *a = (const unsigned long *)_a;
	const unsigned long *b = (const unsigned long *)_b;
	const unsigned long *mask = (const unsigned long *)_mask;
	unsigned long ret;

	ret = (a[0] ^ b[0]) & mask[0];
	if (IFNAMSIZ > sizeof(unsigned long))
		ret |= (a[1] ^ b[1]) & mask[1];
	if (IFNAMSIZ > 2 * sizeof(unsigned long))
		ret |= (a[2] ^ b[2]) & mask[2];
	if (IFNAMSIZ > 3 * sizeof(unsigned long))
		ret |= (a[3] ^ b[3]) & mask[3];
	BUILD_BUG_ON(IFNAMSIZ > 4 * sizeof(unsigned long));
	return ret;
}

struct xt_percpu_counter_alloc_state {
	unsigned int off;
	const char __percpu *mem;
};

bool xt_percpu_counter_alloc(struct xt_percpu_counter_alloc_state *state,
			     struct xt_counters *counter);
void xt_percpu_counter_free(struct xt_counters *cnt);

static inline struct xt_counters *
xt_get_this_cpu_counter(struct xt_counters *cnt)
{
	if (nr_cpu_ids > 1)
		return this_cpu_ptr((void __percpu *) (unsigned long) cnt->pcnt);

	return cnt;
}

static inline struct xt_counters *
xt_get_per_cpu_counter(struct xt_counters *cnt, unsigned int cpu)
{
	if (nr_cpu_ids > 1)
		return per_cpu_ptr((void __percpu *) (unsigned long) cnt->pcnt, cpu);

	return cnt;
}

struct nf_hook_ops *xt_hook_ops_alloc(const struct xt_table *, nf_hookfn *);

#ifdef CONFIG_COMPAT
#include <net/compat.h>

struct compat_xt_entry_match
{
struct compat_xt_entry_match {
	union {
		struct {
			u_int16_t match_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t match_size;
			compat_uptr_t match;
		} kernel;
		u_int16_t match_size;
	} u;
	unsigned char data[0];
};

struct compat_xt_entry_target
{
struct compat_xt_entry_target {
	union {
		struct {
			u_int16_t target_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t target_size;
			compat_uptr_t target;
		} kernel;
		u_int16_t target_size;
	} u;
	unsigned char data[0];
};

/* FIXME: this works only on 32 bit tasks
 * need to change whole approach in order to calculate align as function of
 * current task alignment */

struct compat_xt_counters
{
#if defined(CONFIG_X86_64) || defined(CONFIG_IA64)
	u_int32_t cnt[4];
#else
	u_int64_t cnt[2];
#endif
};

struct compat_xt_counters_info
{
struct compat_xt_counters {
	compat_u64 pcnt, bcnt;			/* Packet and byte counters */
};

struct compat_xt_counters_info {
	char name[XT_TABLE_MAXNAMELEN];
	compat_uint_t num_counters;
	struct compat_xt_counters counters[0];
};

#define COMPAT_XT_ALIGN(s) (((s) + (__alignof__(struct compat_xt_counters)-1)) \
		& ~(__alignof__(struct compat_xt_counters)-1))

extern void xt_compat_lock(int af);
extern void xt_compat_unlock(int af);

extern int xt_compat_add_offset(int af, unsigned int offset, short delta);
extern void xt_compat_flush_offsets(int af);
extern short xt_compat_calc_jump(int af, unsigned int offset);

extern int xt_compat_match_offset(const struct xt_match *match);
extern int xt_compat_match_from_user(struct xt_entry_match *m,
				     void **dstptr, unsigned int *size);
extern int xt_compat_match_to_user(struct xt_entry_match *m,
				   void __user **dstptr, unsigned int *size);

extern int xt_compat_target_offset(const struct xt_target *target);
extern void xt_compat_target_from_user(struct xt_entry_target *t,
				       void **dstptr, unsigned int *size);
extern int xt_compat_target_to_user(struct xt_entry_target *t,
				    void __user **dstptr, unsigned int *size);

#endif /* CONFIG_COMPAT */
#endif /* __KERNEL__ */

struct _compat_xt_align {
	__u8 u8;
	__u16 u16;
	__u32 u32;
	compat_u64 u64;
};

#define COMPAT_XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _compat_xt_align))

void xt_compat_lock(u_int8_t af);
void xt_compat_unlock(u_int8_t af);

int xt_compat_add_offset(u_int8_t af, unsigned int offset, int delta);
void xt_compat_flush_offsets(u_int8_t af);
void xt_compat_init_offsets(u_int8_t af, unsigned int number);
int xt_compat_calc_jump(u_int8_t af, unsigned int offset);

int xt_compat_match_offset(const struct xt_match *match);
void xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			      unsigned int *size);
int xt_compat_match_to_user(const struct xt_entry_match *m,
			    void __user **dstptr, unsigned int *size);

int xt_compat_target_offset(const struct xt_target *target);
void xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size);
int xt_compat_target_to_user(const struct xt_entry_target *t,
			     void __user **dstptr, unsigned int *size);
int xt_compat_check_entry_offsets(const void *base, const char *elems,
				  unsigned int target_offset,
				  unsigned int next_offset);

#endif /* CONFIG_COMPAT */
#endif /* _X_TABLES_H */
