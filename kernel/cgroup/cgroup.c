/*
 *  Generic process-grouping system.
 *
 *  Based originally on the cpuset system, extracted by Paul Menage
 *  Copyright (C) 2006 Google, Inc
 *
 *  Notifications support
 *  Copyright (C) 2009 Nokia Corporation
 *  Author: Kirill A. Shutemov
 *
 *  Copyright notices from the original cpuset code:
 *  --------------------------------------------------
 *  Copyright (C) 2003 BULL SA.
 *  Copyright (C) 2004-2006 Silicon Graphics, Inc.
 *
 *  Portions derived from Patrick Mochel's sysfs code.
 *  sysfs is Copyright (c) 2001-3 Patrick Mochel
 *
 *  2003-10-10 Written by Simon Derr.
 *  2003-10-22 Updates by Stephen Hemminger.
 *  2004 May-July Rework by Paul Jackson.
 *  ---------------------------------------------------
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/cgroup.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "cgroup-internal.h"

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/backing-dev.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/spinlock.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/percpu-rwsem.h>
#include <linux/string.h>
#include <linux/sort.h>
#include <linux/kmod.h>
#include <linux/delayacct.h>
#include <linux/cgroupstats.h>
#include <linux/hash.h>
#include <linux/namei.h>

#include <asm/atomic.h>

static DEFINE_MUTEX(cgroup_mutex);

/* Generate an array of cgroup subsystem pointers */
#define SUBSYS(_x) &_x ## _subsys,

static struct cgroup_subsys *subsys[] = {
#include <linux/cgroup_subsys.h>
};

/*
 * A cgroupfs_root represents the root of a cgroup hierarchy,
 * and may be associated with a superblock to form an active
 * hierarchy
 */
struct cgroupfs_root {
	struct super_block *sb;

	/*
	 * The bitmask of subsystems intended to be attached to this
	 * hierarchy
	 */
	unsigned long subsys_bits;

	/* The bitmask of subsystems currently attached to this hierarchy */
	unsigned long actual_subsys_bits;

	/* A list running through the attached subsystems */
	struct list_head subsys_list;

	/* The root cgroup for this hierarchy */
	struct cgroup top_cgroup;

	/* Tracks how many cgroups are currently defined in hierarchy.*/
	int number_of_cgroups;

	/* A list running through the mounted hierarchies */
	struct list_head root_list;

	/* Hierarchy-specific flags */
	unsigned long flags;

	/* The path to use for release notifications. */
	char release_agent_path[PATH_MAX];
};


/*
 * The "rootnode" hierarchy is the "dummy hierarchy", reserved for the
 * subsystems that are otherwise unattached - it never has more than a
 * single cgroup, and all tasks are part of that cgroup.
 */
static struct cgroupfs_root rootnode;

/* The list of hierarchy roots */

static LIST_HEAD(roots);
static int root_count;

/* dummytop is a shorthand for the dummy hierarchy's top cgroup */
#define dummytop (&rootnode.top_cgroup)

/* This flag indicates whether tasks in the fork and exit paths should
 * check for fork/exit handlers to call. This avoids us having to do
 * extra work in the fork/exit path if none of the subsystems need to
 * be called.
 */
static int need_forkexit_callback __read_mostly;
static int need_mm_owner_callback __read_mostly;

/* convenient tests for these bits */
inline int cgroup_is_removed(const struct cgroup *cgrp)
{
	return test_bit(CGRP_REMOVED, &cgrp->flags);
}

/* bits in struct cgroupfs_root flags field */
enum {
	ROOT_NOPREFIX, /* mounted subsystems have no named prefix */
};

static int cgroup_is_releasable(const struct cgroup *cgrp)
{
	const int bits =
		(1 << CGRP_RELEASABLE) |
		(1 << CGRP_NOTIFY_ON_RELEASE);
	return (cgrp->flags & bits) == bits;
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/atomic.h>
#include <linux/cpuset.h>
#include <linux/proc_ns.h>
#include <linux/nsproxy.h>
#include <linux/file.h>
#include <net/sock.h>

#define CREATE_TRACE_POINTS
#include <trace/events/cgroup.h>

#define CGROUP_FILE_NAME_MAX		(MAX_CGROUP_TYPE_NAMELEN +	\
					 MAX_CFTYPE_NAME + 2)

/*
 * cgroup_mutex is the master lock.  Any modification to cgroup or its
 * hierarchy must be performed while holding it.
 *
 * css_set_lock protects task->cgroups pointer, the list of css_set
 * objects, and the chain of tasks off each css_set.
 *
 * These locks are exported if CONFIG_PROVE_RCU so that accessors in
 * cgroup.h can use them for lockdep annotations.
 */
DEFINE_MUTEX(cgroup_mutex);
DEFINE_SPINLOCK(css_set_lock);

#ifdef CONFIG_PROVE_RCU
EXPORT_SYMBOL_GPL(cgroup_mutex);
EXPORT_SYMBOL_GPL(css_set_lock);
#endif

/*
 * Protects cgroup_idr and css_idr so that IDs can be released without
 * grabbing cgroup_mutex.
 */
static DEFINE_SPINLOCK(cgroup_idr_lock);

/*
 * Protects cgroup_file->kn for !self csses.  It synchronizes notifications
 * against file removal/re-creation across css hiding.
 */
static DEFINE_SPINLOCK(cgroup_file_kn_lock);

struct percpu_rw_semaphore cgroup_threadgroup_rwsem;

#define cgroup_assert_mutex_or_rcu_locked()				\
	RCU_LOCKDEP_WARN(!rcu_read_lock_held() &&			\
			   !lockdep_is_held(&cgroup_mutex),		\
			   "cgroup_mutex or RCU read lock required");

/*
 * cgroup destruction makes heavy use of work items and there can be a lot
 * of concurrent destructions.  Use a separate workqueue so that cgroup
 * destruction work items don't end up filling up max_active of system_wq
 * which may lead to deadlock.
 */
static struct workqueue_struct *cgroup_destroy_wq;

/* generate an array of cgroup subsystem pointers */
#define SUBSYS(_x) [_x ## _cgrp_id] = &_x ## _cgrp_subsys,
struct cgroup_subsys *cgroup_subsys[] = {
#include <linux/cgroup_subsys.h>
};
#undef SUBSYS

/* array of cgroup subsystem names */
#define SUBSYS(_x) [_x ## _cgrp_id] = #_x,
static const char *cgroup_subsys_name[] = {
#include <linux/cgroup_subsys.h>
};
#undef SUBSYS

/* array of static_keys for cgroup_subsys_enabled() and cgroup_subsys_on_dfl() */
#define SUBSYS(_x)								\
	DEFINE_STATIC_KEY_TRUE(_x ## _cgrp_subsys_enabled_key);			\
	DEFINE_STATIC_KEY_TRUE(_x ## _cgrp_subsys_on_dfl_key);			\
	EXPORT_SYMBOL_GPL(_x ## _cgrp_subsys_enabled_key);			\
	EXPORT_SYMBOL_GPL(_x ## _cgrp_subsys_on_dfl_key);
#include <linux/cgroup_subsys.h>
#undef SUBSYS

#define SUBSYS(_x) [_x ## _cgrp_id] = &_x ## _cgrp_subsys_enabled_key,
static struct static_key_true *cgroup_subsys_enabled_key[] = {
#include <linux/cgroup_subsys.h>
};
#undef SUBSYS

#define SUBSYS(_x) [_x ## _cgrp_id] = &_x ## _cgrp_subsys_on_dfl_key,
static struct static_key_true *cgroup_subsys_on_dfl_key[] = {
#include <linux/cgroup_subsys.h>
};
#undef SUBSYS

/*
 * The default hierarchy, reserved for the subsystems that are otherwise
 * unattached - it never has more than a single cgroup, and all tasks are
 * part of that cgroup.
 */
struct cgroup_root cgrp_dfl_root;
EXPORT_SYMBOL_GPL(cgrp_dfl_root);

/*
 * The default hierarchy always exists but is hidden until mounted for the
 * first time.  This is for backward compatibility.
 */
static bool cgrp_dfl_visible;

/* some controllers are not supported in the default hierarchy */
static u16 cgrp_dfl_inhibit_ss_mask;

/* some controllers are implicitly enabled on the default hierarchy */
static u16 cgrp_dfl_implicit_ss_mask;

/* some controllers can be threaded on the default hierarchy */
static u16 cgrp_dfl_threaded_ss_mask;

/* The list of hierarchy roots */
LIST_HEAD(cgroup_roots);
static int cgroup_root_count;

/* hierarchy ID allocation and mapping, protected by cgroup_mutex */
static DEFINE_IDR(cgroup_hierarchy_idr);

/*
 * Assign a monotonically increasing serial number to csses.  It guarantees
 * cgroups with bigger numbers are newer than those with smaller numbers.
 * Also, as csses are always appended to the parent's ->children list, it
 * guarantees that sibling csses are always sorted in the ascending serial
 * number order on the list.  Protected by cgroup_mutex.
 */
static u64 css_serial_nr_next = 1;

/*
 * These bitmasks identify subsystems with specific features to avoid
 * having to do iterative checks repeatedly.
 */
static u16 have_fork_callback __read_mostly;
static u16 have_exit_callback __read_mostly;
static u16 have_free_callback __read_mostly;
static u16 have_canfork_callback __read_mostly;

/* cgroup namespace for init task */
struct cgroup_namespace init_cgroup_ns = {
	.count		= REFCOUNT_INIT(2),
	.user_ns	= &init_user_ns,
	.ns.ops		= &cgroupns_operations,
	.ns.inum	= PROC_CGROUP_INIT_INO,
	.root_cset	= &init_css_set,
};

static struct file_system_type cgroup2_fs_type;
static struct cftype cgroup_base_files[];

static int cgroup_apply_control(struct cgroup *cgrp);
static void cgroup_finalize_control(struct cgroup *cgrp, int ret);
static void css_task_iter_advance(struct css_task_iter *it);
static int cgroup_destroy_locked(struct cgroup *cgrp);
static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
					      struct cgroup_subsys *ss);
static void css_release(struct percpu_ref *ref);
static void kill_css(struct cgroup_subsys_state *css);
static int cgroup_addrm_files(struct cgroup_subsys_state *css,
			      struct cgroup *cgrp, struct cftype cfts[],
			      bool is_add);

/**
 * cgroup_ssid_enabled - cgroup subsys enabled test by subsys ID
 * @ssid: subsys ID of interest
 *
 * cgroup_subsys_enabled() can only be used with literal subsys names which
 * is fine for individual subsystems but unsuitable for cgroup core.  This
 * is slower static_key_enabled() based test indexed by @ssid.
 */
bool cgroup_ssid_enabled(int ssid)
{
	if (CGROUP_SUBSYS_COUNT == 0)
		return false;

	return static_key_enabled(cgroup_subsys_enabled_key[ssid]);
}

/**
 * cgroup_on_dfl - test whether a cgroup is on the default hierarchy
 * @cgrp: the cgroup of interest
 *
 * The default hierarchy is the v2 interface of cgroup and this function
 * can be used to test whether a cgroup is on the default hierarchy for
 * cases where a subsystem should behave differnetly depending on the
 * interface version.
 *
 * The set of behaviors which change on the default hierarchy are still
 * being determined and the mount option is prefixed with __DEVEL__.
 *
 * List of changed behaviors:
 *
 * - Mount options "noprefix", "xattr", "clone_children", "release_agent"
 *   and "name" are disallowed.
 *
 * - When mounting an existing superblock, mount options should match.
 *
 * - Remount is disallowed.
 *
 * - rename(2) is disallowed.
 *
 * - "tasks" is removed.  Everything should be at process granularity.  Use
 *   "cgroup.procs" instead.
 *
 * - "cgroup.procs" is not sorted.  pids will be unique unless they got
 *   recycled inbetween reads.
 *
 * - "release_agent" and "notify_on_release" are removed.  Replacement
 *   notification mechanism will be implemented.
 *
 * - "cgroup.clone_children" is removed.
 *
 * - "cgroup.subtree_populated" is available.  Its value is 0 if the cgroup
 *   and its descendants contain no task; otherwise, 1.  The file also
 *   generates kernfs notification which can be monitored through poll and
 *   [di]notify when the value of the file changes.
 *
 * - cpuset: tasks will be kept in empty cpusets when hotplug happens and
 *   take masks of ancestors with non-empty cpus/mems, instead of being
 *   moved to an ancestor.
 *
 * - cpuset: a task can be moved into an empty cpuset, and again it takes
 *   masks of ancestors.
 *
 * - memcg: use_hierarchy is on by default and the cgroup file for the flag
 *   is not created.
 *
 * - blkcg: blk-throttle becomes properly hierarchical.
 *
 * - debug: disallowed on the default hierarchy.
 */
bool cgroup_on_dfl(const struct cgroup *cgrp)
{
	return cgrp->root == &cgrp_dfl_root;
}

/* IDR wrappers which synchronize using cgroup_idr_lock */
static int cgroup_idr_alloc(struct idr *idr, void *ptr, int start, int end,
			    gfp_t gfp_mask)
{
	int ret;

	idr_preload(gfp_mask);
	spin_lock_bh(&cgroup_idr_lock);
	ret = idr_alloc(idr, ptr, start, end, gfp_mask & ~__GFP_DIRECT_RECLAIM);
	spin_unlock_bh(&cgroup_idr_lock);
	idr_preload_end();
	return ret;
}

static void *cgroup_idr_replace(struct idr *idr, void *ptr, int id)
{
	void *ret;

	spin_lock_bh(&cgroup_idr_lock);
	ret = idr_replace(idr, ptr, id);
	spin_unlock_bh(&cgroup_idr_lock);
	return ret;
}

static void cgroup_idr_remove(struct idr *idr, int id)
{
	spin_lock_bh(&cgroup_idr_lock);
	idr_remove(idr, id);
	spin_unlock_bh(&cgroup_idr_lock);
}

static bool cgroup_has_tasks(struct cgroup *cgrp)
{
	return cgrp->nr_populated_csets;
}

bool cgroup_is_threaded(struct cgroup *cgrp)
{
	return cgrp->dom_cgrp != cgrp;
}

/* can @cgrp host both domain and threaded children? */
static bool cgroup_is_mixable(struct cgroup *cgrp)
{
	/*
	 * Root isn't under domain level resource control exempting it from
	 * the no-internal-process constraint, so it can serve as a thread
	 * root and a parent of resource domains at the same time.
	 */
	return !cgroup_parent(cgrp);
}

/* can @cgrp become a thread root? should always be true for a thread root */
static bool cgroup_can_be_thread_root(struct cgroup *cgrp)
{
	/* mixables don't care */
	if (cgroup_is_mixable(cgrp))
		return true;

	/* domain roots can't be nested under threaded */
	if (cgroup_is_threaded(cgrp))
		return false;

	/* can only have either domain or threaded children */
	if (cgrp->nr_populated_domain_children)
		return false;

	/* and no domain controllers can be enabled */
	if (cgrp->subtree_control & ~cgrp_dfl_threaded_ss_mask)
		return false;

	return true;
}

/* is @cgrp root of a threaded subtree? */
bool cgroup_is_thread_root(struct cgroup *cgrp)
{
	/* thread root should be a domain */
	if (cgroup_is_threaded(cgrp))
		return false;

	/* a domain w/ threaded children is a thread root */
	if (cgrp->nr_threaded_children)
		return true;

	/*
	 * A domain which has tasks and explicit threaded controllers
	 * enabled is a thread root.
	 */
	if (cgroup_has_tasks(cgrp) &&
	    (cgrp->subtree_control & cgrp_dfl_threaded_ss_mask))
		return true;

	return false;
}

/* a domain which isn't connected to the root w/o brekage can't be used */
static bool cgroup_is_valid_domain(struct cgroup *cgrp)
{
	/* the cgroup itself can be a thread root */
	if (cgroup_is_threaded(cgrp))
		return false;

	/* but the ancestors can't be unless mixable */
	while ((cgrp = cgroup_parent(cgrp))) {
		if (!cgroup_is_mixable(cgrp) && cgroup_is_thread_root(cgrp))
			return false;
		if (cgroup_is_threaded(cgrp))
			return false;
	}

	return true;
}

/* subsystems visibly enabled on a cgroup */
static u16 cgroup_control(struct cgroup *cgrp)
{
	struct cgroup *parent = cgroup_parent(cgrp);
	u16 root_ss_mask = cgrp->root->subsys_mask;

	if (parent) {
		u16 ss_mask = parent->subtree_control;

		/* threaded cgroups can only have threaded controllers */
		if (cgroup_is_threaded(cgrp))
			ss_mask &= cgrp_dfl_threaded_ss_mask;
		return ss_mask;
	}

	if (cgroup_on_dfl(cgrp))
		root_ss_mask &= ~(cgrp_dfl_inhibit_ss_mask |
				  cgrp_dfl_implicit_ss_mask);
	return root_ss_mask;
}

/* subsystems enabled on a cgroup */
static u16 cgroup_ss_mask(struct cgroup *cgrp)
{
	struct cgroup *parent = cgroup_parent(cgrp);

	if (parent) {
		u16 ss_mask = parent->subtree_ss_mask;

		/* threaded cgroups can only have threaded controllers */
		if (cgroup_is_threaded(cgrp))
			ss_mask &= cgrp_dfl_threaded_ss_mask;
		return ss_mask;
	}

	return cgrp->root->subsys_mask;
}

/**
 * cgroup_css - obtain a cgroup's css for the specified subsystem
 * @cgrp: the cgroup of interest
 * @ss: the subsystem of interest (%NULL returns @cgrp->self)
 *
 * Return @cgrp's css (cgroup_subsys_state) associated with @ss.  This
 * function must be called either under cgroup_mutex or rcu_read_lock() and
 * the caller is responsible for pinning the returned css if it wants to
 * keep accessing it outside the said locks.  This function may return
 * %NULL if @cgrp doesn't have @subsys_id enabled.
 */
static struct cgroup_subsys_state *cgroup_css(struct cgroup *cgrp,
					      struct cgroup_subsys *ss)
{
	if (ss)
		return rcu_dereference_check(cgrp->subsys[ss->id],
					lockdep_is_held(&cgroup_mutex));
	else
		return &cgrp->self;
}

/**
 * cgroup_e_css - obtain a cgroup's effective css for the specified subsystem
 * @cgrp: the cgroup of interest
 * @ss: the subsystem of interest (%NULL returns @cgrp->self)
 *
 * Similar to cgroup_css() but returns the effective css, which is defined
 * as the matching css of the nearest ancestor including self which has @ss
 * enabled.  If @ss is associated with the hierarchy @cgrp is on, this
 * function is guaranteed to return non-NULL css.
 */
static struct cgroup_subsys_state *cgroup_e_css(struct cgroup *cgrp,
						struct cgroup_subsys *ss)
{
	lockdep_assert_held(&cgroup_mutex);

	if (!ss)
		return &cgrp->self;

	/*
	 * This function is used while updating css associations and thus
	 * can't test the csses directly.  Test ss_mask.
	 */
	while (!(cgroup_ss_mask(cgrp) & (1 << ss->id))) {
		cgrp = cgroup_parent(cgrp);
		if (!cgrp)
			return NULL;
	}

	return cgroup_css(cgrp, ss);
}

/**
 * cgroup_get_e_css - get a cgroup's effective css for the specified subsystem
 * @cgrp: the cgroup of interest
 * @ss: the subsystem of interest
 *
 * Find and get the effective css of @cgrp for @ss.  The effective css is
 * defined as the matching css of the nearest ancestor including self which
 * has @ss enabled.  If @ss is not mounted on the hierarchy @cgrp is on,
 * the root css is returned, so this function always returns a valid css.
 * The returned css must be put using css_put().
 */
struct cgroup_subsys_state *cgroup_get_e_css(struct cgroup *cgrp,
					     struct cgroup_subsys *ss)
{
	struct cgroup_subsys_state *css;

	rcu_read_lock();

	do {
		css = cgroup_css(cgrp, ss);

		if (css && css_tryget_online(css))
			goto out_unlock;
		cgrp = cgroup_parent(cgrp);
	} while (cgrp);

	css = init_css_set.subsys[ss->id];
	css_get(css);
out_unlock:
	rcu_read_unlock();
	return css;
}

static void cgroup_get_live(struct cgroup *cgrp)
{
	WARN_ON_ONCE(cgroup_is_dead(cgrp));
	css_get(&cgrp->self);
}

struct cgroup_subsys_state *of_css(struct kernfs_open_file *of)
{
	struct cgroup *cgrp = of->kn->parent->priv;
	struct cftype *cft = of_cft(of);

	/*
	 * This is open and unprotected implementation of cgroup_css().
	 * seq_css() is only called from a kernfs file operation which has
	 * an active reference on the file.  Because all the subsystem
	 * files are drained before a css is disassociated with a cgroup,
	 * the matching css from the cgroup's subsys table is guaranteed to
	 * be and stay valid until the enclosing operation is complete.
	 */
	if (cft->ss)
		return rcu_dereference_raw(cgrp->subsys[cft->ss->id]);
	else
		return &cgrp->self;
}
EXPORT_SYMBOL_GPL(of_css);

/**
 * cgroup_is_descendant - test ancestry
 * @cgrp: the cgroup to be tested
 * @ancestor: possible ancestor of @cgrp
 *
 * Test whether @cgrp is a descendant of @ancestor.  It also returns %true
 * if @cgrp == @ancestor.  This function is safe to call as long as @cgrp
 * and @ancestor are accessible.
 */
bool cgroup_is_descendant(struct cgroup *cgrp, struct cgroup *ancestor)
{
	while (cgrp) {
		if (cgrp == ancestor)
			return true;
		cgrp = cgroup_parent(cgrp);
	}
	return false;
}

static int notify_on_release(const struct cgroup *cgrp)
{
	return test_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
}

/*
 * for_each_subsys() allows you to iterate on each subsystem attached to
 * an active hierarchy
 */
#define for_each_subsys(_root, _ss) \
list_for_each_entry(_ss, &_root->subsys_list, sibling)

/* for_each_root() allows you to iterate across the active hierarchies */
#define for_each_root(_root) \
list_for_each_entry(_root, &roots, root_list)

/* the list of cgroups eligible for automatic release. Protected by
 * release_list_lock */
static LIST_HEAD(release_list);
static DEFINE_SPINLOCK(release_list_lock);
static void cgroup_release_agent(struct work_struct *work);
static DECLARE_WORK(release_agent_work, cgroup_release_agent);
static void check_for_release(struct cgroup *cgrp);

/* Link structure for associating css_set objects with cgroups */
struct cg_cgroup_link {
	/*
	 * List running through cg_cgroup_links associated with a
	 * cgroup, anchored on cgroup->css_sets
	 */
	struct list_head cgrp_link_list;
	/*
	 * List running through cg_cgroup_links pointing at a
	 * single css_set object, anchored on css_set->cg_links
	 */
	struct list_head cg_link_list;
	struct css_set *cg;
};

/* The default css_set - used by init and its children prior to any
/**
 * for_each_css - iterate all css's of a cgroup
 * @css: the iteration cursor
 * @ssid: the index of the subsystem, CGROUP_SUBSYS_COUNT after reaching the end
 * @cgrp: the target cgroup to iterate css's of
 *
 * Should be called under cgroup_[tree_]mutex.
 */
#define for_each_css(css, ssid, cgrp)					\
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT; (ssid)++)	\
		if (!((css) = rcu_dereference_check(			\
				(cgrp)->subsys[(ssid)],			\
				lockdep_is_held(&cgroup_mutex)))) { }	\
		else

/**
 * for_each_e_css - iterate all effective css's of a cgroup
 * @css: the iteration cursor
 * @ssid: the index of the subsystem, CGROUP_SUBSYS_COUNT after reaching the end
 * @cgrp: the target cgroup to iterate css's of
 *
 * Should be called under cgroup_[tree_]mutex.
 */
#define for_each_e_css(css, ssid, cgrp)					\
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT; (ssid)++)	\
		if (!((css) = cgroup_e_css(cgrp, cgroup_subsys[(ssid)]))) \
			;						\
		else

/**
 * do_each_subsys_mask - filter for_each_subsys with a bitmask
 * @ss: the iteration cursor
 * @ssid: the index of @ss, CGROUP_SUBSYS_COUNT after reaching the end
 * @ss_mask: the bitmask
 *
 * The block will only run for cases where the ssid-th bit (1 << ssid) of
 * @ss_mask is set.
 */
#define do_each_subsys_mask(ss, ssid, ss_mask) do {			\
	unsigned long __ss_mask = (ss_mask);				\
	if (!CGROUP_SUBSYS_COUNT) { /* to avoid spurious gcc warning */	\
		(ssid) = 0;						\
		break;							\
	}								\
	for_each_set_bit(ssid, &__ss_mask, CGROUP_SUBSYS_COUNT) {	\
		(ss) = cgroup_subsys[ssid];				\
		{

#define while_each_subsys_mask()					\
		}							\
	}								\
} while (false)

/* iterate over child cgrps, lock should be held throughout iteration */
#define cgroup_for_each_live_child(child, cgrp)				\
	list_for_each_entry((child), &(cgrp)->self.children, self.sibling) \
		if (({ lockdep_assert_held(&cgroup_mutex);		\
		       cgroup_is_dead(child); }))			\
			;						\
		else

/* walk live descendants in preorder */
#define cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp)		\
	css_for_each_descendant_pre((d_css), cgroup_css((cgrp), NULL))	\
		if (({ lockdep_assert_held(&cgroup_mutex);		\
		       (dsct) = (d_css)->cgroup;			\
		       cgroup_is_dead(dsct); }))			\
			;						\
		else

/* walk live descendants in postorder */
#define cgroup_for_each_live_descendant_post(dsct, d_css, cgrp)		\
	css_for_each_descendant_post((d_css), cgroup_css((cgrp), NULL))	\
		if (({ lockdep_assert_held(&cgroup_mutex);		\
		       (dsct) = (d_css)->cgroup;			\
		       cgroup_is_dead(dsct); }))			\
			;						\
		else

/*
 * The default css_set - used by init and its children prior to any
 * hierarchies being mounted. It contains a pointer to the root state
 * for each subsystem. Also used to anchor the list of css_sets. Not
 * reference-counted, to improve performance when child cgroups
 * haven't been created.
 */

static struct css_set init_css_set;
static struct cg_cgroup_link init_css_set_link;

/* css_set_lock protects the list of css_set objects, and the
 * chain of tasks off each css_set.  Nests outside task->alloc_lock
 * due to cgroup_iter_start() */
static DEFINE_RWLOCK(css_set_lock);
static int css_set_count;

/* hash table for cgroup groups. This improves the performance to
 * find an existing css_set */
#define CSS_SET_HASH_BITS	7
#define CSS_SET_TABLE_SIZE	(1 << CSS_SET_HASH_BITS)
static struct hlist_head css_set_table[CSS_SET_TABLE_SIZE];

static struct hlist_head *css_set_hash(struct cgroup_subsys_state *css[])
{
	int i;
	int index;
	unsigned long tmp = 0UL;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++)
		tmp += (unsigned long)css[i];
	tmp = (tmp >> 16) ^ tmp;

	index = hash_long(tmp, CSS_SET_HASH_BITS);

	return &css_set_table[index];
}

/* We don't maintain the lists running through each css_set to its
 * task until after the first call to cgroup_iter_start(). This
 * reduces the fork()/exit() overhead for people who have cgroups
 * compiled into their kernel but not actually in use */
static int use_task_css_set_links __read_mostly;

/* When we create or destroy a css_set, the operation simply
 * takes/releases a reference count on all the cgroups referenced
 * by subsystems in this css_set. This can end up multiple-counting
 * some cgroups, but that's OK - the ref-count is just a
 * busy/not-busy indicator; ensuring that we only count each cgroup
 * once would require taking a global lock to ensure that no
 * subsystems moved between hierarchies while we were doing so.
 *
 * Possible TODO: decide at boot time based on the number of
 * registered subsystems and the number of CPUs or NUMA nodes whether
 * it's better for performance to ref-count every subsystem, or to
 * take a global lock and only add one ref count to each hierarchy.
 */

/*
 * unlink a css_set from the list and free it
 */
static void unlink_css_set(struct css_set *cg)
{
	struct cg_cgroup_link *link;
	struct cg_cgroup_link *saved_link;

	write_lock(&css_set_lock);
	hlist_del(&cg->hlist);
	css_set_count--;

	list_for_each_entry_safe(link, saved_link, &cg->cg_links,
				 cg_link_list) {
		list_del(&link->cg_link_list);
		list_del(&link->cgrp_link_list);
		kfree(link);
	}

	write_unlock(&css_set_lock);
}

static void __release_css_set(struct kref *k, int taskexit)
{
	int i;
	struct css_set *cg = container_of(k, struct css_set, ref);

	unlink_css_set(cg);

	rcu_read_lock();
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup *cgrp = cg->subsys[i]->cgroup;
		if (atomic_dec_and_test(&cgrp->count) &&
		    notify_on_release(cgrp)) {
			if (taskexit)
				set_bit(CGRP_RELEASABLE, &cgrp->flags);
			check_for_release(cgrp);
		}
	}
	rcu_read_unlock();
	kfree(cg);
}

static void release_css_set(struct kref *k)
{
	__release_css_set(k, 0);
}

static void release_css_set_taskexit(struct kref *k)
{
	__release_css_set(k, 1);
struct css_set init_css_set = {
	.refcount		= REFCOUNT_INIT(1),
	.dom_cset		= &init_css_set,
	.tasks			= LIST_HEAD_INIT(init_css_set.tasks),
	.mg_tasks		= LIST_HEAD_INIT(init_css_set.mg_tasks),
	.task_iters		= LIST_HEAD_INIT(init_css_set.task_iters),
	.threaded_csets		= LIST_HEAD_INIT(init_css_set.threaded_csets),
	.cgrp_links		= LIST_HEAD_INIT(init_css_set.cgrp_links),
	.mg_preload_node	= LIST_HEAD_INIT(init_css_set.mg_preload_node),
	.mg_node		= LIST_HEAD_INIT(init_css_set.mg_node),
};

static int css_set_count	= 1;	/* 1 for init_css_set */

static bool css_set_threaded(struct css_set *cset)
{
	return cset->dom_cset != cset;
}

/**
 * css_set_populated - does a css_set contain any tasks?
 * @cset: target css_set
 *
 * css_set_populated() should be the same as !!cset->nr_tasks at steady
 * state. However, css_set_populated() can be called while a task is being
 * added to or removed from the linked list before the nr_tasks is
 * properly updated. Hence, we can't just look at ->nr_tasks here.
 */
static bool css_set_populated(struct css_set *cset)
{
	lockdep_assert_held(&css_set_lock);

	return !list_empty(&cset->tasks) || !list_empty(&cset->mg_tasks);
}

/**
 * cgroup_update_populated - update the populated count of a cgroup
 * @cgrp: the target cgroup
 * @populated: inc or dec populated count
 *
 * One of the css_sets associated with @cgrp is either getting its first
 * task or losing the last.  Update @cgrp->nr_populated_* accordingly.  The
 * count is propagated towards root so that a given cgroup's
 * nr_populated_children is zero iff none of its descendants contain any
 * tasks.
 *
 * @cgrp's interface file "cgroup.populated" is zero if both
 * @cgrp->nr_populated_csets and @cgrp->nr_populated_children are zero and
 * 1 otherwise.  When the sum changes from or to zero, userland is notified
 * that the content of the interface file has changed.  This can be used to
 * detect when @cgrp and its descendants become populated or empty.
 */
static void cgroup_update_populated(struct cgroup *cgrp, bool populated)
{
	struct cgroup *child = NULL;
	int adj = populated ? 1 : -1;

	lockdep_assert_held(&css_set_lock);

	do {
		bool was_populated = cgroup_is_populated(cgrp);

		if (!child) {
			cgrp->nr_populated_csets += adj;
		} else {
			if (cgroup_is_threaded(child))
				cgrp->nr_populated_threaded_children += adj;
			else
				cgrp->nr_populated_domain_children += adj;
		}

		if (was_populated == cgroup_is_populated(cgrp))
			break;

		cgroup1_check_for_release(cgrp);
		cgroup_file_notify(&cgrp->events_file);

		child = cgrp;
		cgrp = cgroup_parent(cgrp);
	} while (cgrp);
}

/**
 * css_set_update_populated - update populated state of a css_set
 * @cset: target css_set
 * @populated: whether @cset is populated or depopulated
 *
 * @cset is either getting the first task or losing the last.  Update the
 * populated counters of all associated cgroups accordingly.
 */
static void css_set_update_populated(struct css_set *cset, bool populated)
{
	struct cgrp_cset_link *link;

	lockdep_assert_held(&css_set_lock);

	list_for_each_entry(link, &cset->cgrp_links, cgrp_link)
		cgroup_update_populated(link->cgrp, populated);
}

/**
 * css_set_move_task - move a task from one css_set to another
 * @task: task being moved
 * @from_cset: css_set @task currently belongs to (may be NULL)
 * @to_cset: new css_set @task is being moved to (may be NULL)
 * @use_mg_tasks: move to @to_cset->mg_tasks instead of ->tasks
 *
 * Move @task from @from_cset to @to_cset.  If @task didn't belong to any
 * css_set, @from_cset can be NULL.  If @task is being disassociated
 * instead of moved, @to_cset can be NULL.
 *
 * This function automatically handles populated counter updates and
 * css_task_iter adjustments but the caller is responsible for managing
 * @from_cset and @to_cset's reference counts.
 */
static void css_set_move_task(struct task_struct *task,
			      struct css_set *from_cset, struct css_set *to_cset,
			      bool use_mg_tasks)
{
	lockdep_assert_held(&css_set_lock);

	if (to_cset && !css_set_populated(to_cset))
		css_set_update_populated(to_cset, true);

	if (from_cset) {
		struct css_task_iter *it, *pos;

		WARN_ON_ONCE(list_empty(&task->cg_list));

		/*
		 * @task is leaving, advance task iterators which are
		 * pointing to it so that they can resume at the next
		 * position.  Advancing an iterator might remove it from
		 * the list, use safe walk.  See css_task_iter_advance*()
		 * for details.
		 */
		list_for_each_entry_safe(it, pos, &from_cset->task_iters,
					 iters_node)
			if (it->task_pos == &task->cg_list)
				css_task_iter_advance(it);

		list_del_init(&task->cg_list);
		if (!css_set_populated(from_cset))
			css_set_update_populated(from_cset, false);
	} else {
		WARN_ON_ONCE(!list_empty(&task->cg_list));
	}

	if (to_cset) {
		/*
		 * We are synchronized through cgroup_threadgroup_rwsem
		 * against PF_EXITING setting such that we can't race
		 * against cgroup_exit() changing the css_set to
		 * init_css_set and dropping the old one.
		 */
		WARN_ON_ONCE(task->flags & PF_EXITING);

		rcu_assign_pointer(task->cgroups, to_cset);
		list_add_tail(&task->cg_list, use_mg_tasks ? &to_cset->mg_tasks :
							     &to_cset->tasks);
	}
}

/*
 * hash table for cgroup groups. This improves the performance to find
 * an existing css_set. This hash doesn't (currently) take into
 * account cgroups in empty hierarchies.
 */
#define CSS_SET_HASH_BITS	7
static DEFINE_HASHTABLE(css_set_table, CSS_SET_HASH_BITS);

static unsigned long css_set_hash(struct cgroup_subsys_state *css[])
{
	unsigned long key = 0UL;
	struct cgroup_subsys *ss;
	int i;

	for_each_subsys(ss, i)
		key += (unsigned long)css[i];
	key = (key >> 16) ^ key;

	return key;
}

void put_css_set_locked(struct css_set *cset)
{
	struct cgrp_cset_link *link, *tmp_link;
	struct cgroup_subsys *ss;
	int ssid;

	lockdep_assert_held(&css_set_lock);

	if (!refcount_dec_and_test(&cset->refcount))
		return;

	WARN_ON_ONCE(!list_empty(&cset->threaded_csets));

	/* This css_set is dead. unlink it and release cgroup and css refs */
	for_each_subsys(ss, ssid) {
		list_del(&cset->e_cset_node[ssid]);
		css_put(cset->subsys[ssid]);
	}
	hash_del(&cset->hlist);
	css_set_count--;

	list_for_each_entry_safe(link, tmp_link, &cset->cgrp_links, cgrp_link) {
		list_del(&link->cset_link);
		list_del(&link->cgrp_link);
		if (cgroup_parent(link->cgrp))
			cgroup_put(link->cgrp);
		kfree(link);
	}

	if (css_set_threaded(cset)) {
		list_del(&cset->threaded_csets_node);
		put_css_set_locked(cset->dom_cset);
	}

	kfree_rcu(cset, rcu_head);
}

static void put_css_set(struct css_set *cset)
{
	/*
	 * Ensure that the refcount doesn't hit zero while any readers
	 * can see it. Similar to atomic_dec_and_lock(), but for an
	 * rwlock
	 */
	if (atomic_add_unless(&cset->refcount, -1, 1))
		return;

	spin_lock_bh(&css_set_lock);
	put_css_set_locked(cset);
	spin_unlock_bh(&css_set_lock);
}

/*
 * refcounted get/put for css_set objects
 */
static inline void get_css_set(struct css_set *cg)
{
	kref_get(&cg->ref);
}

static inline void put_css_set(struct css_set *cg)
{
	kref_put(&cg->ref, release_css_set);
}

static inline void put_css_set_taskexit(struct css_set *cg)
{
	kref_put(&cg->ref, release_css_set_taskexit);
}

/*
 * find_existing_css_set() is a helper for
 * find_css_set(), and checks to see whether an existing
 * css_set is suitable.
 *
 * oldcg: the cgroup group that we're using before the cgroup
 * transition
 *
 * cgrp: the cgroup that we're moving into
 *
 * template: location in which to build the desired set of subsystem
 * state objects for the new cgroup group
 */
static struct css_set *find_existing_css_set(
	struct css_set *oldcg,
	struct cgroup *cgrp,
	struct cgroup_subsys_state *template[])
{
	int i;
	struct cgroupfs_root *root = cgrp->root;
	struct hlist_head *hhead;
	struct hlist_node *node;
	struct css_set *cg;

	/* Built the set of subsystem state objects that we want to
	 * see in the new css_set */
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		if (root->subsys_bits & (1UL << i)) {
			/* Subsystem is in this hierarchy. So we want
			 * the subsystem state from the new
			 * cgroup */
			template[i] = cgrp->subsys[i];
		} else {
			/* Subsystem is not in this hierarchy, so we
			 * don't want to change the subsystem state */
			template[i] = oldcg->subsys[i];
		}
	}

	hhead = css_set_hash(template);
	hlist_for_each_entry(cg, node, hhead, hlist) {
		if (!memcmp(template, cg->subsys, sizeof(cg->subsys))) {
			/* All subsystems matched */
			return cg;
		}
static inline void get_css_set(struct css_set *cset)
{
	atomic_inc(&cset->refcount);
}

/**
 * compare_css_sets - helper function for find_existing_css_set().
 * @cset: candidate css_set being tested
 * @old_cset: existing css_set for a task
 * @new_cgrp: cgroup that's being entered by the task
 * @template: desired set of css pointers in css_set (pre-calculated)
 *
 * Returns true if "cset" matches "old_cset" except for the hierarchy
 * which "new_cgrp" belongs to, for which it should match "new_cgrp".
 */
static bool compare_css_sets(struct css_set *cset,
			     struct css_set *old_cset,
			     struct cgroup *new_cgrp,
			     struct cgroup_subsys_state *template[])
{
	struct cgroup *new_dfl_cgrp;
	struct list_head *l1, *l2;

	/*
	 * On the default hierarchy, there can be csets which are
	 * associated with the same set of cgroups but different csses.
	 * Let's first ensure that csses match.
	 */
	if (memcmp(template, cset->subsys, sizeof(cset->subsys)))
		return false;


	/* @cset's domain should match the default cgroup's */
	if (cgroup_on_dfl(new_cgrp))
		new_dfl_cgrp = new_cgrp;
	else
		new_dfl_cgrp = old_cset->dfl_cgrp;

	if (new_dfl_cgrp->dom_cgrp != cset->dom_cset->dfl_cgrp)
		return false;

	/*
	 * Compare cgroup pointers in order to distinguish between
	 * different cgroups in hierarchies.  As different cgroups may
	 * share the same effective css, this comparison is always
	 * necessary.
	 */
	l1 = &cset->cgrp_links;
	l2 = &old_cset->cgrp_links;
	while (1) {
		struct cgrp_cset_link *link1, *link2;
		struct cgroup *cgrp1, *cgrp2;

		l1 = l1->next;
		l2 = l2->next;
		/* See if we reached the end - both lists are equal length. */
		if (l1 == &cset->cgrp_links) {
			BUG_ON(l2 != &old_cset->cgrp_links);
			break;
		} else {
			BUG_ON(l2 == &old_cset->cgrp_links);
		}
		/* Locate the cgroups associated with these links. */
		link1 = list_entry(l1, struct cgrp_cset_link, cgrp_link);
		link2 = list_entry(l2, struct cgrp_cset_link, cgrp_link);
		cgrp1 = link1->cgrp;
		cgrp2 = link2->cgrp;
		/* Hierarchies should be linked in the same order. */
		BUG_ON(cgrp1->root != cgrp2->root);

		/*
		 * If this hierarchy is the hierarchy of the cgroup
		 * that's changing, then we need to check that this
		 * css_set points to the new cgroup; if it's any other
		 * hierarchy, then this css_set should point to the
		 * same cgroup as the old css_set.
		 */
		if (cgrp1->root == new_cgrp->root) {
			if (cgrp1 != new_cgrp)
				return false;
		} else {
			if (cgrp1 != cgrp2)
				return false;
		}
	}
	return true;
}

/**
 * find_existing_css_set - init css array and find the matching css_set
 * @old_cset: the css_set that we're using before the cgroup transition
 * @cgrp: the cgroup that we're moving into
 * @template: out param for the new set of csses, should be clear on entry
 */
static struct css_set *find_existing_css_set(struct css_set *old_cset,
					struct cgroup *cgrp,
					struct cgroup_subsys_state *template[])
{
	struct cgroup_root *root = cgrp->root;
	struct cgroup_subsys *ss;
	struct css_set *cset;
	unsigned long key;
	int i;

	/*
	 * Build the set of subsystem state objects that we want to see in the
	 * new css_set. while subsystems can change globally, the entries here
	 * won't change, so no need for locking.
	 */
	for_each_subsys(ss, i) {
		if (root->subsys_mask & (1UL << i)) {
			/*
			 * @ss is in this hierarchy, so we want the
			 * effective css from @cgrp.
			 */
			template[i] = cgroup_e_css(cgrp, ss);
		} else {
			/*
			 * @ss is not in this hierarchy, so we don't want
			 * to change the css.
			 */
			template[i] = old_cset->subsys[i];
		}
	}

	key = css_set_hash(template);
	hash_for_each_possible(css_set_table, cset, hlist, key) {
		if (!compare_css_sets(cset, old_cset, cgrp, template))
			continue;

		/* This css_set matches what we need */
		return cset;
	}

	/* No existing cgroup group matched */
	return NULL;
}

static void free_cg_links(struct list_head *tmp)
{
	struct cg_cgroup_link *link;
	struct cg_cgroup_link *saved_link;

	list_for_each_entry_safe(link, saved_link, tmp, cgrp_link_list) {
		list_del(&link->cgrp_link_list);
static void free_cgrp_cset_links(struct list_head *links_to_free)
{
	struct cgrp_cset_link *link, *tmp_link;

	list_for_each_entry_safe(link, tmp_link, links_to_free, cset_link) {
		list_del(&link->cset_link);
		kfree(link);
	}
}

/*
 * allocate_cg_links() allocates "count" cg_cgroup_link structures
 * and chains them on tmp through their cgrp_link_list fields. Returns 0 on
 * success or a negative error
 */
static int allocate_cg_links(int count, struct list_head *tmp)
{
	struct cg_cgroup_link *link;
	int i;
	INIT_LIST_HEAD(tmp);
	for (i = 0; i < count; i++) {
		link = kmalloc(sizeof(*link), GFP_KERNEL);
		if (!link) {
			free_cg_links(tmp);
			return -ENOMEM;
		}
		list_add(&link->cgrp_link_list, tmp);
/**
 * allocate_cgrp_cset_links - allocate cgrp_cset_links
 * @count: the number of links to allocate
 * @tmp_links: list_head the allocated links are put on
 *
 * Allocate @count cgrp_cset_link structures and chain them on @tmp_links
 * through ->cset_link.  Returns 0 on success or -errno.
 */
static int allocate_cgrp_cset_links(int count, struct list_head *tmp_links)
{
	struct cgrp_cset_link *link;
	int i;

	INIT_LIST_HEAD(tmp_links);

	for (i = 0; i < count; i++) {
		link = kzalloc(sizeof(*link), GFP_KERNEL);
		if (!link) {
			free_cgrp_cset_links(tmp_links);
			return -ENOMEM;
		}
		list_add(&link->cset_link, tmp_links);
	}
	return 0;
}

/*
 * find_css_set() takes an existing cgroup group and a
 * cgroup object, and returns a css_set object that's
 * equivalent to the old group, but with the given cgroup
 * substituted into the appropriate hierarchy. Must be called with
 * cgroup_mutex held
 */
static struct css_set *find_css_set(
	struct css_set *oldcg, struct cgroup *cgrp)
{
	struct css_set *res;
	struct cgroup_subsys_state *template[CGROUP_SUBSYS_COUNT];
	int i;

	struct list_head tmp_cg_links;
	struct cg_cgroup_link *link;

	struct hlist_head *hhead;

	/* First see if we already have a cgroup group that matches
	 * the desired set */
	read_lock(&css_set_lock);
	res = find_existing_css_set(oldcg, cgrp, template);
	if (res)
		get_css_set(res);
	read_unlock(&css_set_lock);

	if (res)
		return res;

	res = kmalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return NULL;

	/* Allocate all the cg_cgroup_link objects that we'll need */
	if (allocate_cg_links(root_count, &tmp_cg_links) < 0) {
		kfree(res);
		return NULL;
	}

	kref_init(&res->ref);
	INIT_LIST_HEAD(&res->cg_links);
	INIT_LIST_HEAD(&res->tasks);
	INIT_HLIST_NODE(&res->hlist);

	/* Copy the set of subsystem state objects generated in
	 * find_existing_css_set() */
	memcpy(res->subsys, template, sizeof(res->subsys));

	write_lock(&css_set_lock);
	/* Add reference counts and links from the new css_set. */
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup *cgrp = res->subsys[i]->cgroup;
		struct cgroup_subsys *ss = subsys[i];
		atomic_inc(&cgrp->count);
		/*
		 * We want to add a link once per cgroup, so we
		 * only do it for the first subsystem in each
		 * hierarchy
		 */
		if (ss->root->subsys_list.next == &ss->sibling) {
			BUG_ON(list_empty(&tmp_cg_links));
			link = list_entry(tmp_cg_links.next,
					  struct cg_cgroup_link,
					  cgrp_link_list);
			list_del(&link->cgrp_link_list);
			list_add(&link->cgrp_link_list, &cgrp->css_sets);
			link->cg = res;
			list_add(&link->cg_link_list, &res->cg_links);
		}
	}
	if (list_empty(&rootnode.subsys_list)) {
		link = list_entry(tmp_cg_links.next,
				  struct cg_cgroup_link,
				  cgrp_link_list);
		list_del(&link->cgrp_link_list);
		list_add(&link->cgrp_link_list, &dummytop->css_sets);
		link->cg = res;
		list_add(&link->cg_link_list, &res->cg_links);
	}

	BUG_ON(!list_empty(&tmp_cg_links));

	css_set_count++;

	/* Add this cgroup group to the hash table */
	hhead = css_set_hash(res->subsys);
	hlist_add_head(&res->hlist, hhead);

	write_unlock(&css_set_lock);

/**
 * link_css_set - a helper function to link a css_set to a cgroup
 * @tmp_links: cgrp_cset_link objects allocated by allocate_cgrp_cset_links()
 * @cset: the css_set to be linked
 * @cgrp: the destination cgroup
 */
static void link_css_set(struct list_head *tmp_links, struct css_set *cset,
			 struct cgroup *cgrp)
{
	struct cgrp_cset_link *link;

	BUG_ON(list_empty(tmp_links));

	if (cgroup_on_dfl(cgrp))
		cset->dfl_cgrp = cgrp;

	link = list_first_entry(tmp_links, struct cgrp_cset_link, cset_link);
	link->cset = cset;
	link->cgrp = cgrp;

	/*
	 * Always add links to the tail of the lists so that the lists are
	 * in choronological order.
	 */
	list_move_tail(&link->cset_link, &cgrp->cset_links);
	list_add_tail(&link->cgrp_link, &cset->cgrp_links);

	if (cgroup_parent(cgrp))
		cgroup_get_live(cgrp);
}

/**
 * find_css_set - return a new css_set with one cgroup updated
 * @old_cset: the baseline css_set
 * @cgrp: the cgroup to be updated
 *
 * Return a new css_set that's equivalent to @old_cset, but with @cgrp
 * substituted into the appropriate hierarchy.
 */
static struct css_set *find_css_set(struct css_set *old_cset,
				    struct cgroup *cgrp)
{
	struct cgroup_subsys_state *template[CGROUP_SUBSYS_COUNT] = { };
	struct css_set *cset;
	struct list_head tmp_links;
	struct cgrp_cset_link *link;
	struct cgroup_subsys *ss;
	unsigned long key;
	int ssid;

	lockdep_assert_held(&cgroup_mutex);

	/* First see if we already have a cgroup group that matches
	 * the desired set */
	spin_lock_irq(&css_set_lock);
	cset = find_existing_css_set(old_cset, cgrp, template);
	if (cset)
		get_css_set(cset);
	spin_unlock_irq(&css_set_lock);

	if (cset)
		return cset;

	cset = kzalloc(sizeof(*cset), GFP_KERNEL);
	if (!cset)
		return NULL;

	/* Allocate all the cgrp_cset_link objects that we'll need */
	if (allocate_cgrp_cset_links(cgroup_root_count, &tmp_links) < 0) {
		kfree(cset);
		return NULL;
	}

	refcount_set(&cset->refcount, 1);
	cset->dom_cset = cset;
	INIT_LIST_HEAD(&cset->tasks);
	INIT_LIST_HEAD(&cset->mg_tasks);
	INIT_LIST_HEAD(&cset->task_iters);
	INIT_LIST_HEAD(&cset->threaded_csets);
	INIT_HLIST_NODE(&cset->hlist);
	INIT_LIST_HEAD(&cset->cgrp_links);
	INIT_LIST_HEAD(&cset->mg_preload_node);
	INIT_LIST_HEAD(&cset->mg_node);

	/* Copy the set of subsystem state objects generated in
	 * find_existing_css_set() */
	memcpy(cset->subsys, template, sizeof(cset->subsys));

	spin_lock_irq(&css_set_lock);
	/* Add reference counts and links from the new css_set. */
	list_for_each_entry(link, &old_cset->cgrp_links, cgrp_link) {
		struct cgroup *c = link->cgrp;

		if (c->root == cgrp->root)
			c = cgrp;
		link_css_set(&tmp_links, cset, c);
	}

	BUG_ON(!list_empty(&tmp_links));

	css_set_count++;

	/* Add @cset to the hash table */
	key = css_set_hash(cset->subsys);
	hash_add(css_set_table, &cset->hlist, key);

	for_each_subsys(ss, ssid) {
		struct cgroup_subsys_state *css = cset->subsys[ssid];

		list_add_tail(&cset->e_cset_node[ssid],
			      &css->cgroup->e_csets[ssid]);
		css_get(css);
	}

	spin_unlock_irq(&css_set_lock);

	/*
	 * If @cset should be threaded, look up the matching dom_cset and
	 * link them up.  We first fully initialize @cset then look for the
	 * dom_cset.  It's simpler this way and safe as @cset is guaranteed
	 * to stay empty until we return.
	 */
	if (cgroup_is_threaded(cset->dfl_cgrp)) {
		struct css_set *dcset;

		dcset = find_css_set(cset, cset->dfl_cgrp->dom_cgrp);
		if (!dcset) {
			put_css_set(cset);
			return NULL;
		}

		spin_lock_irq(&css_set_lock);
		cset->dom_cset = dcset;
		list_add_tail(&cset->threaded_csets_node,
			      &dcset->threaded_csets);
		spin_unlock_irq(&css_set_lock);
	}

	return cset;
}

struct cgroup_root *cgroup_root_from_kf(struct kernfs_root *kf_root)
{
	struct cgroup *root_cgrp = kf_root->kn->priv;

	return root_cgrp->root;
}

static int cgroup_init_root_id(struct cgroup_root *root)
{
	int id;

	lockdep_assert_held(&cgroup_mutex);

	id = idr_alloc_cyclic(&cgroup_hierarchy_idr, root, 0, 0, GFP_KERNEL);
	if (id < 0)
		return id;

	root->hierarchy_id = id;
	return 0;
}

static void cgroup_exit_root_id(struct cgroup_root *root)
{
	lockdep_assert_held(&cgroup_mutex);

	idr_remove(&cgroup_hierarchy_idr, root->hierarchy_id);
}

void cgroup_free_root(struct cgroup_root *root)
{
	if (root) {
		idr_destroy(&root->cgroup_idr);
		kfree(root);
	}
}

static void cgroup_destroy_root(struct cgroup_root *root)
{
	struct cgroup *cgrp = &root->cgrp;
	struct cgrp_cset_link *link, *tmp_link;

	trace_cgroup_destroy_root(root);

	cgroup_lock_and_drain_offline(&cgrp_dfl_root.cgrp);

	BUG_ON(atomic_read(&root->nr_cgrps));
	BUG_ON(!list_empty(&cgrp->self.children));

	/* Rebind all subsystems back to the default hierarchy */
	WARN_ON(rebind_subsystems(&cgrp_dfl_root, root->subsys_mask));

	/*
	 * Release all the links from cset_links to this hierarchy's
	 * root cgroup
	 */
	spin_lock_irq(&css_set_lock);

	list_for_each_entry_safe(link, tmp_link, &cgrp->cset_links, cset_link) {
		list_del(&link->cset_link);
		list_del(&link->cgrp_link);
		kfree(link);
	}

	spin_unlock_irq(&css_set_lock);

	if (!list_empty(&root->root_list)) {
		list_del(&root->root_list);
		cgroup_root_count--;
	}

	cgroup_exit_root_id(root);

	mutex_unlock(&cgroup_mutex);

	kernfs_destroy_root(root->kf_root);
	cgroup_free_root(root);
}

/*
 * look up cgroup associated with current task's cgroup namespace on the
 * specified hierarchy
 */
static struct cgroup *
current_cgns_cgroup_from_root(struct cgroup_root *root)
{
	struct cgroup *res = NULL;
	struct css_set *cset;

	lockdep_assert_held(&css_set_lock);

	rcu_read_lock();

	cset = current->nsproxy->cgroup_ns->root_cset;
	if (cset == &init_css_set) {
		res = &root->cgrp;
	} else {
		struct cgrp_cset_link *link;

		list_for_each_entry(link, &cset->cgrp_links, cgrp_link) {
			struct cgroup *c = link->cgrp;

			if (c->root == root) {
				res = c;
				break;
			}
		}
	}
	rcu_read_unlock();

	BUG_ON(!res);
	return res;
}

/* look up cgroup associated with given css_set on the specified hierarchy */
static struct cgroup *cset_cgroup_from_root(struct css_set *cset,
					    struct cgroup_root *root)
{
	struct cgroup *res = NULL;

	lockdep_assert_held(&cgroup_mutex);
	lockdep_assert_held(&css_set_lock);

	if (cset == &init_css_set) {
		res = &root->cgrp;
	} else if (root == &cgrp_dfl_root) {
		res = cset->dfl_cgrp;
	} else {
		struct cgrp_cset_link *link;

		list_for_each_entry(link, &cset->cgrp_links, cgrp_link) {
			struct cgroup *c = link->cgrp;

			if (c->root == root) {
				res = c;
				break;
			}
		}
	}

	BUG_ON(!res);
	return res;
}

/*
 * There is one global cgroup mutex. We also require taking
 * task_lock() when dereferencing a task's cgroup subsys pointers.
 * See "The task_lock() exception", at the end of this comment.
 *
 * Return the cgroup for "task" from the given hierarchy. Must be
 * called with cgroup_mutex and css_set_lock held.
 */
struct cgroup *task_cgroup_from_root(struct task_struct *task,
				     struct cgroup_root *root)
{
	/*
	 * No need to lock the task - since we hold cgroup_mutex the
	 * task can't change groups, so the only thing that can happen
	 * is that it exits and its css is set back to init_css_set.
	 */
	return cset_cgroup_from_root(task_css_set(task), root);
}

/*
 * A task must hold cgroup_mutex to modify cgroups.
 *
 * Any task can increment and decrement the count field without lock.
 * So in general, code holding cgroup_mutex can't rely on the count
 * field not changing.  However, if the count goes to zero, then only
 * cgroup_attach_task() can increment it again.  Because a count of zero
 * means that no tasks are currently attached, therefore there is no
 * way a task attached to that cgroup can fork (the other way to
 * increment the count).  So code holding cgroup_mutex can safely
 * assume that if the count is zero, it will stay zero. Similarly, if
 * a task holds cgroup_mutex on a cgroup with zero count, it
 * knows that the cgroup won't be removed, as cgroup_rmdir()
 * needs that mutex.
 *
 * The fork and exit callbacks cgroup_fork() and cgroup_exit(), don't
 * (usually) take cgroup_mutex.  These are the two most performance
 * critical pieces of code here.  The exception occurs on cgroup_exit(),
 * when a task in a notify_on_release cgroup exits.  Then cgroup_mutex
 * is taken, and if the cgroup count is zero, a usermode call made
 * to the release agent with the name of the cgroup (path relative to
 * the root of cgroup file system) as the argument.
 *
 * A cgroup can only be deleted if both its 'count' of using tasks
 * is zero, and its list of 'children' cgroups is empty.  Since all
 * tasks in the system use _some_ cgroup, and since there is always at
 * least one task in the system (init, pid == 1), therefore, top_cgroup
 * always has either children cgroups and/or using tasks.  So we don't
 * need a special hack to ensure that top_cgroup cannot be deleted.
 *
 *	The task_lock() exception
 *
 * The need for this exception arises from the action of
 * cgroup_attach_task(), which overwrites one tasks cgroup pointer with
 * another.  It does so using cgroup_mutex, however there are
 * several performance critical places that need to reference
 * task->cgroup without the expense of grabbing a system global
 * mutex.  Therefore except as noted below, when dereferencing or, as
 * in cgroup_attach_task(), modifying a task'ss cgroup pointer we use
 * task_lock(), which acts on a spinlock (task->alloc_lock) already in
 * the task_struct routinely used for such matters.
 * A cgroup can only be deleted if both its 'count' of using tasks
 * is zero, and its list of 'children' cgroups is empty.  Since all
 * tasks in the system use _some_ cgroup, and since there is always at
 * least one task in the system (init, pid == 1), therefore, root cgroup
 * always has either children cgroups and/or using tasks.  So we don't
 * need a special hack to ensure that root cgroup cannot be deleted.
 *
 * P.S.  One more locking exception.  RCU is used to guard the
 * update of a tasks cgroup pointer by cgroup_attach_task()
 */

/**
 * cgroup_lock - lock out any changes to cgroup structures
 *
 */
void cgroup_lock(void)
{
	mutex_lock(&cgroup_mutex);
}

/**
 * cgroup_unlock - release lock on cgroup changes
 *
 * Undo the lock taken in a previous cgroup_lock() call.
 */
void cgroup_unlock(void)
{
	mutex_unlock(&cgroup_mutex);
}

/*
 * A couple of forward declarations required, due to cyclic reference loop:
 * cgroup_mkdir -> cgroup_create -> cgroup_populate_dir ->
 * cgroup_add_file -> cgroup_create_file -> cgroup_dir_inode_operations
 * -> cgroup_mkdir.
 */

static int cgroup_mkdir(struct inode *dir, struct dentry *dentry, int mode);
static int cgroup_rmdir(struct inode *unused_dir, struct dentry *dentry);
static int cgroup_populate_dir(struct cgroup *cgrp);
static struct inode_operations cgroup_dir_inode_operations;
static struct file_operations proc_cgroupstats_operations;

static struct backing_dev_info cgroup_backing_dev_info = {
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK,
};

static struct inode *cgroup_new_inode(mode_t mode, struct super_block *sb)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current->fsuid;
		inode->i_gid = current->fsgid;
		inode->i_blocks = 0;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		inode->i_mapping->backing_dev_info = &cgroup_backing_dev_info;
	}
	return inode;
}

/*
 * Call subsys's pre_destroy handler.
 * This is called before css refcnt check.
 */
static void cgroup_call_pre_destroy(struct cgroup *cgrp)
{
	struct cgroup_subsys *ss;
	for_each_subsys(cgrp->root, ss)
		if (ss->pre_destroy && cgrp->subsys[ss->subsys_id])
			ss->pre_destroy(ss, cgrp);
	return;
}

static void cgroup_diput(struct dentry *dentry, struct inode *inode)
{
	/* is dentry a directory ? if so, kfree() associated cgroup */
	if (S_ISDIR(inode->i_mode)) {
		struct cgroup *cgrp = dentry->d_fsdata;
		struct cgroup_subsys *ss;
		BUG_ON(!(cgroup_is_removed(cgrp)));
		/* It's possible for external users to be holding css
		 * reference counts on a cgroup; css_put() needs to
		 * be able to access the cgroup after decrementing
		 * the reference count in order to know if it needs to
		 * queue the cgroup to be handled by the release
		 * agent */
		synchronize_rcu();

		mutex_lock(&cgroup_mutex);
		/*
		 * Release the subsystem state objects.
		 */
		for_each_subsys(cgrp->root, ss) {
			if (cgrp->subsys[ss->subsys_id])
				ss->destroy(ss, cgrp);
		}

		cgrp->root->number_of_cgroups--;
		mutex_unlock(&cgroup_mutex);

		/* Drop the active superblock reference that we took when we
		 * created the cgroup */
		deactivate_super(cgrp->root->sb);

		kfree(cgrp);
	}
	iput(inode);
}

static void remove_dir(struct dentry *d)
{
	struct dentry *parent = dget(d->d_parent);

	d_delete(d);
	simple_rmdir(parent->d_inode, d);
	dput(parent);
}

static void cgroup_clear_directory(struct dentry *dentry)
{
	struct list_head *node;

	BUG_ON(!mutex_is_locked(&dentry->d_inode->i_mutex));
	spin_lock(&dcache_lock);
	node = dentry->d_subdirs.next;
	while (node != &dentry->d_subdirs) {
		struct dentry *d = list_entry(node, struct dentry, d_u.d_child);
		list_del_init(node);
		if (d->d_inode) {
			/* This should never be called on a cgroup
			 * directory with child cgroups */
			BUG_ON(d->d_inode->i_mode & S_IFDIR);
			d = dget_locked(d);
			spin_unlock(&dcache_lock);
			d_delete(d);
			simple_unlink(dentry->d_inode, d);
			dput(d);
			spin_lock(&dcache_lock);
		}
		node = dentry->d_subdirs.next;
	}
	spin_unlock(&dcache_lock);
}

/*
 * NOTE : the dentry must have been dget()'ed
 */
static void cgroup_d_remove_dir(struct dentry *dentry)
{
	cgroup_clear_directory(dentry);

	spin_lock(&dcache_lock);
	list_del_init(&dentry->d_u.d_child);
	spin_unlock(&dcache_lock);
	remove_dir(dentry);
}

static int rebind_subsystems(struct cgroupfs_root *root,
			      unsigned long final_bits)
{
	unsigned long added_bits, removed_bits;
	struct cgroup *cgrp = &root->top_cgroup;
	int i;

	removed_bits = root->actual_subsys_bits & ~final_bits;
	added_bits = final_bits & ~root->actual_subsys_bits;
	/* Check that any added subsystems are currently free */
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		unsigned long bit = 1UL << i;
		struct cgroup_subsys *ss = subsys[i];
		if (!(bit & added_bits))
			continue;
		if (ss->root != &rootnode) {
			/* Subsystem isn't free */
			return -EBUSY;
		}
	}

	/* Currently we don't handle adding/removing subsystems when
	 * any child cgroups exist. This is theoretically supportable
	 * but involves complex error handling, so it's being left until
	 * later */
	if (!list_empty(&cgrp->children))
		return -EBUSY;

	/* Process each subsystem */
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *ss = subsys[i];
		unsigned long bit = 1UL << i;
		if (bit & added_bits) {
			/* We're binding this subsystem to this hierarchy */
			BUG_ON(cgrp->subsys[i]);
			BUG_ON(!dummytop->subsys[i]);
			BUG_ON(dummytop->subsys[i]->cgroup != dummytop);
			cgrp->subsys[i] = dummytop->subsys[i];
			cgrp->subsys[i]->cgroup = cgrp;
			list_add(&ss->sibling, &root->subsys_list);
			rcu_assign_pointer(ss->root, root);
			if (ss->bind)
				ss->bind(ss, cgrp);

		} else if (bit & removed_bits) {
			/* We're removing this subsystem */
			BUG_ON(cgrp->subsys[i] != dummytop->subsys[i]);
			BUG_ON(cgrp->subsys[i]->cgroup != cgrp);
			if (ss->bind)
				ss->bind(ss, dummytop);
			dummytop->subsys[i]->cgroup = dummytop;
			cgrp->subsys[i] = NULL;
			rcu_assign_pointer(subsys[i]->root, &rootnode);
			list_del(&ss->sibling);
		} else if (bit & final_bits) {
			/* Subsystem state should already exist */
			BUG_ON(!cgrp->subsys[i]);
		} else {
			/* Subsystem state shouldn't exist */
			BUG_ON(cgrp->subsys[i]);
		}
	}
	root->subsys_bits = root->actual_subsys_bits = final_bits;
	synchronize_rcu();

	return 0;
}

static int cgroup_show_options(struct seq_file *seq, struct vfsmount *vfs)
{
	struct cgroupfs_root *root = vfs->mnt_sb->s_fs_info;
	struct cgroup_subsys *ss;

	mutex_lock(&cgroup_mutex);
	for_each_subsys(root, ss)
		seq_printf(seq, ",%s", ss->name);
	if (test_bit(ROOT_NOPREFIX, &root->flags))
		seq_puts(seq, ",noprefix");
	if (strlen(root->release_agent_path))
		seq_printf(seq, ",release_agent=%s", root->release_agent_path);
	mutex_unlock(&cgroup_mutex);
static struct kernfs_syscall_ops cgroup_kf_syscall_ops;

static char *cgroup_file_name(struct cgroup *cgrp, const struct cftype *cft,
			      char *buf)
{
	struct cgroup_subsys *ss = cft->ss;

	if (cft->ss && !(cft->flags & CFTYPE_NO_PREFIX) &&
	    !(cgrp->root->flags & CGRP_ROOT_NOPREFIX))
		snprintf(buf, CGROUP_FILE_NAME_MAX, "%s.%s",
			 cgroup_on_dfl(cgrp) ? ss->name : ss->legacy_name,
			 cft->name);
	else
		strncpy(buf, cft->name, CGROUP_FILE_NAME_MAX);
	return buf;
}

/**
 * cgroup_file_mode - deduce file mode of a control file
 * @cft: the control file in question
 *
 * S_IRUGO for read, S_IWUSR for write.
 */
static umode_t cgroup_file_mode(const struct cftype *cft)
{
	umode_t mode = 0;

	if (cft->read_u64 || cft->read_s64 || cft->seq_show)
		mode |= S_IRUGO;

	if (cft->write_u64 || cft->write_s64 || cft->write) {
		if (cft->flags & CFTYPE_WORLD_WRITABLE)
			mode |= S_IWUGO;
		else
			mode |= S_IWUSR;
	}

	return mode;
}

/**
 * cgroup_calc_subtree_ss_mask - calculate subtree_ss_mask
 * @subtree_control: the new subtree_control mask to consider
 * @this_ss_mask: available subsystems
 *
 * On the default hierarchy, a subsystem may request other subsystems to be
 * enabled together through its ->depends_on mask.  In such cases, more
 * subsystems than specified in "cgroup.subtree_control" may be enabled.
 *
 * This function calculates which subsystems need to be enabled if
 * @subtree_control is to be applied while restricted to @this_ss_mask.
 */
static u16 cgroup_calc_subtree_ss_mask(u16 subtree_control, u16 this_ss_mask)
{
	u16 cur_ss_mask = subtree_control;
	struct cgroup_subsys *ss;
	int ssid;

	lockdep_assert_held(&cgroup_mutex);

	cur_ss_mask |= cgrp_dfl_implicit_ss_mask;

	while (true) {
		u16 new_ss_mask = cur_ss_mask;

		do_each_subsys_mask(ss, ssid, cur_ss_mask) {
			new_ss_mask |= ss->depends_on;
		} while_each_subsys_mask();

		/*
		 * Mask out subsystems which aren't available.  This can
		 * happen only if some depended-upon subsystems were bound
		 * to non-default hierarchies.
		 */
		new_ss_mask &= this_ss_mask;

		if (new_ss_mask == cur_ss_mask)
			break;
		cur_ss_mask = new_ss_mask;
	}

	return cur_ss_mask;
}

/**
 * cgroup_kn_unlock - unlocking helper for cgroup kernfs methods
 * @kn: the kernfs_node being serviced
 *
 * This helper undoes cgroup_kn_lock_live() and should be invoked before
 * the method finishes if locking succeeded.  Note that once this function
 * returns the cgroup returned by cgroup_kn_lock_live() may become
 * inaccessible any time.  If the caller intends to continue to access the
 * cgroup, it should pin it before invoking this function.
 */
void cgroup_kn_unlock(struct kernfs_node *kn)
{
	struct cgroup *cgrp;

	if (kernfs_type(kn) == KERNFS_DIR)
		cgrp = kn->priv;
	else
		cgrp = kn->parent->priv;

	mutex_unlock(&cgroup_mutex);

	kernfs_unbreak_active_protection(kn);
	cgroup_put(cgrp);
}

/**
 * cgroup_kn_lock_live - locking helper for cgroup kernfs methods
 * @kn: the kernfs_node being serviced
 * @drain_offline: perform offline draining on the cgroup
 *
 * This helper is to be used by a cgroup kernfs method currently servicing
 * @kn.  It breaks the active protection, performs cgroup locking and
 * verifies that the associated cgroup is alive.  Returns the cgroup if
 * alive; otherwise, %NULL.  A successful return should be undone by a
 * matching cgroup_kn_unlock() invocation.  If @drain_offline is %true, the
 * cgroup is drained of offlining csses before return.
 *
 * Any cgroup kernfs method implementation which requires locking the
 * associated cgroup should use this helper.  It avoids nesting cgroup
 * locking under kernfs active protection and allows all kernfs operations
 * including self-removal.
 */
struct cgroup *cgroup_kn_lock_live(struct kernfs_node *kn, bool drain_offline)
{
	struct cgroup *cgrp;

	if (kernfs_type(kn) == KERNFS_DIR)
		cgrp = kn->priv;
	else
		cgrp = kn->parent->priv;

	/*
	 * We're gonna grab cgroup_mutex which nests outside kernfs
	 * active_ref.  cgroup liveliness check alone provides enough
	 * protection against removal.  Ensure @cgrp stays accessible and
	 * break the active_ref protection.
	 */
	if (!cgroup_tryget(cgrp))
		return NULL;
	kernfs_break_active_protection(kn);

	if (drain_offline)
		cgroup_lock_and_drain_offline(cgrp);
	else
		mutex_lock(&cgroup_mutex);

	if (!cgroup_is_dead(cgrp))
		return cgrp;

	cgroup_kn_unlock(kn);
	return NULL;
}

static void cgroup_rm_file(struct cgroup *cgrp, const struct cftype *cft)
{
	char name[CGROUP_FILE_NAME_MAX];

	lockdep_assert_held(&cgroup_mutex);

	if (cft->file_offset) {
		struct cgroup_subsys_state *css = cgroup_css(cgrp, cft->ss);
		struct cgroup_file *cfile = (void *)css + cft->file_offset;

		spin_lock_irq(&cgroup_file_kn_lock);
		cfile->kn = NULL;
		spin_unlock_irq(&cgroup_file_kn_lock);
	}

	kernfs_remove_by_name(cgrp->kn, cgroup_file_name(cgrp, cft, name));
}

/**
 * css_clear_dir - remove subsys files in a cgroup directory
 * @css: taget css
 */
static void css_clear_dir(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = css->cgroup;
	struct cftype *cfts;

	if (!(css->flags & CSS_VISIBLE))
		return;

	css->flags &= ~CSS_VISIBLE;

	list_for_each_entry(cfts, &css->ss->cfts, node)
		cgroup_addrm_files(css, cgrp, cfts, false);
}

/**
 * css_populate_dir - create subsys files in a cgroup directory
 * @css: target css
 *
 * On failure, no file is added.
 */
static int css_populate_dir(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = css->cgroup;
	struct cftype *cfts, *failed_cfts;
	int ret;

	if ((css->flags & CSS_VISIBLE) || !cgrp->kn)
		return 0;

	if (!css->ss) {
		if (cgroup_on_dfl(cgrp))
			cfts = cgroup_base_files;
		else
			cfts = cgroup1_base_files;

		return cgroup_addrm_files(&cgrp->self, cgrp, cfts, true);
	}

	list_for_each_entry(cfts, &css->ss->cfts, node) {
		ret = cgroup_addrm_files(css, cgrp, cfts, true);
		if (ret < 0) {
			failed_cfts = cfts;
			goto err;
		}
	}

	css->flags |= CSS_VISIBLE;

	return 0;
err:
	list_for_each_entry(cfts, &css->ss->cfts, node) {
		if (cfts == failed_cfts)
			break;
		cgroup_addrm_files(css, cgrp, cfts, false);
	}
	return ret;
}

int rebind_subsystems(struct cgroup_root *dst_root, u16 ss_mask)
{
	struct cgroup *dcgrp = &dst_root->cgrp;
	struct cgroup_subsys *ss;
	int ssid, i, ret;

	lockdep_assert_held(&cgroup_mutex);

	do_each_subsys_mask(ss, ssid, ss_mask) {
		/*
		 * If @ss has non-root csses attached to it, can't move.
		 * If @ss is an implicit controller, it is exempt from this
		 * rule and can be stolen.
		 */
		if (css_next_child(NULL, cgroup_css(&ss->root->cgrp, ss)) &&
		    !ss->implicit_on_dfl)
			return -EBUSY;

		/* can't move between two non-dummy roots either */
		if (ss->root != &cgrp_dfl_root && dst_root != &cgrp_dfl_root)
			return -EBUSY;
	} while_each_subsys_mask();

	do_each_subsys_mask(ss, ssid, ss_mask) {
		struct cgroup_root *src_root = ss->root;
		struct cgroup *scgrp = &src_root->cgrp;
		struct cgroup_subsys_state *css = cgroup_css(scgrp, ss);
		struct css_set *cset;

		WARN_ON(!css || cgroup_css(dcgrp, ss));

		/* disable from the source */
		src_root->subsys_mask &= ~(1 << ssid);
		WARN_ON(cgroup_apply_control(scgrp));
		cgroup_finalize_control(scgrp, 0);

		/* rebind */
		RCU_INIT_POINTER(scgrp->subsys[ssid], NULL);
		rcu_assign_pointer(dcgrp->subsys[ssid], css);
		ss->root = dst_root;
		css->cgroup = dcgrp;

		spin_lock_irq(&css_set_lock);
		hash_for_each(css_set_table, i, cset, hlist)
			list_move_tail(&cset->e_cset_node[ss->id],
				       &dcgrp->e_csets[ss->id]);
		spin_unlock_irq(&css_set_lock);

		/* default hierarchy doesn't enable controllers by default */
		dst_root->subsys_mask |= 1 << ssid;
		if (dst_root == &cgrp_dfl_root) {
			static_branch_enable(cgroup_subsys_on_dfl_key[ssid]);
		} else {
			dcgrp->subtree_control |= 1 << ssid;
			static_branch_disable(cgroup_subsys_on_dfl_key[ssid]);
		}

		ret = cgroup_apply_control(dcgrp);
		if (ret)
			pr_warn("partial failure to rebind %s controller (err=%d)\n",
				ss->name, ret);

		if (ss->bind)
			ss->bind(css);
	} while_each_subsys_mask();

	kernfs_activate(dcgrp->kn);
	return 0;
}

int cgroup_show_path(struct seq_file *sf, struct kernfs_node *kf_node,
		     struct kernfs_root *kf_root)
{
	int len = 0;
	char *buf = NULL;
	struct cgroup_root *kf_cgroot = cgroup_root_from_kf(kf_root);
	struct cgroup *ns_cgroup;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	spin_lock_irq(&css_set_lock);
	ns_cgroup = current_cgns_cgroup_from_root(kf_cgroot);
	len = kernfs_path_from_node(kf_node, ns_cgroup->kn, buf, PATH_MAX);
	spin_unlock_irq(&css_set_lock);

	if (len >= PATH_MAX)
		len = -ERANGE;
	else if (len > 0) {
		seq_escape(sf, buf, " \t\n\\");
		len = 0;
	}
	kfree(buf);
	return len;
}

static int parse_cgroup_root_flags(char *data, unsigned int *root_flags)
{
	char *token;

	*root_flags = 0;

	if (!data)
		return 0;

	while ((token = strsep(&data, ",")) != NULL) {
		if (!strcmp(token, "nsdelegate")) {
			*root_flags |= CGRP_ROOT_NS_DELEGATE;
			continue;
		}

		pr_err("cgroup2: unknown option \"%s\"\n", token);
		return -EINVAL;
	}

	return 0;
}

struct cgroup_sb_opts {
	unsigned long subsys_bits;
	unsigned long flags;
	char *release_agent;
};

/* Convert a hierarchy specifier into a bitmask of subsystems and
 * flags. */
static int parse_cgroupfs_options(char *data,
				     struct cgroup_sb_opts *opts)
{
	char *token, *o = data ?: "all";

	opts->subsys_bits = 0;
	opts->flags = 0;
	opts->release_agent = NULL;

	while ((token = strsep(&o, ",")) != NULL) {
		if (!*token)
			return -EINVAL;
		if (!strcmp(token, "all")) {
			/* Add all non-disabled subsystems */
			int i;
			opts->subsys_bits = 0;
			for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
				struct cgroup_subsys *ss = subsys[i];
				if (!ss->disabled)
					opts->subsys_bits |= 1ul << i;
			}
		} else if (!strcmp(token, "noprefix")) {
			set_bit(ROOT_NOPREFIX, &opts->flags);
		} else if (!strncmp(token, "release_agent=", 14)) {
			/* Specifying two release agents is forbidden */
			if (opts->release_agent)
				return -EINVAL;
			opts->release_agent = kzalloc(PATH_MAX, GFP_KERNEL);
			if (!opts->release_agent)
				return -ENOMEM;
			strncpy(opts->release_agent, token + 14, PATH_MAX - 1);
			opts->release_agent[PATH_MAX - 1] = 0;
		} else {
			struct cgroup_subsys *ss;
			int i;
			for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
				ss = subsys[i];
				if (!strcmp(token, ss->name)) {
					if (!ss->disabled)
						set_bit(i, &opts->subsys_bits);
					break;
				}
			}
			if (i == CGROUP_SUBSYS_COUNT)
				return -ENOENT;
		}
	}

	/* We can't have an empty hierarchy */
	if (!opts->subsys_bits)
	unsigned long subsys_mask;
	unsigned int flags;
	char *release_agent;
	bool cpuset_clone_children;
	char *name;
	/* User explicitly requested empty subsystem */
	bool none;
};

static int parse_cgroupfs_options(char *data, struct cgroup_sb_opts *opts)
static void apply_cgroup_root_flags(unsigned int root_flags)
{
	if (current->nsproxy->cgroup_ns == &init_cgroup_ns) {
		if (root_flags & CGRP_ROOT_NS_DELEGATE)
			cgrp_dfl_root.flags |= CGRP_ROOT_NS_DELEGATE;
		else
			cgrp_dfl_root.flags &= ~CGRP_ROOT_NS_DELEGATE;
	}
}

static int cgroup_show_options(struct seq_file *seq, struct kernfs_root *kf_root)
{
	if (cgrp_dfl_root.flags & CGRP_ROOT_NS_DELEGATE)
		seq_puts(seq, ",nsdelegate");
	return 0;
}

static int cgroup_remount(struct super_block *sb, int *flags, char *data)
{
	int ret = 0;
	struct cgroupfs_root *root = sb->s_fs_info;
	struct cgroup *cgrp = &root->top_cgroup;
	struct cgroup_sb_opts opts;

	mutex_lock(&cgrp->dentry->d_inode->i_mutex);
static int cgroup_remount(struct kernfs_root *kf_root, int *flags, char *data)
{
	unsigned int root_flags;
	int ret;

	ret = parse_cgroup_root_flags(data, &root_flags);
	if (ret)
		return ret;

	/* Don't allow flags to change at remount */
	if (opts.flags != root->flags) {
	if (opts.subsys_mask != root->subsys_mask || opts.release_agent)
		pr_warn("option changes via remount are deprecated (pid=%d comm=%s)\n",
			task_tgid_nr(current), current->comm);

	added_mask = opts.subsys_mask & ~root->subsys_mask;
	removed_mask = root->subsys_mask & ~opts.subsys_mask;

	/* Don't allow flags or name to change at remount */
	if ((opts.flags ^ root->flags) ||
	    (opts.name && strcmp(opts.name, root->name))) {
		pr_err("option or name mismatch, new: 0x%x \"%s\", old: 0x%x \"%s\"\n",
		       opts.flags, opts.name ?: "", root->flags, root->name);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = rebind_subsystems(root, opts.subsys_bits);

	/* (re)populate subsystem files */
	if (!ret)
		cgroup_populate_dir(cgrp);

	if (opts.release_agent)
		strcpy(root->release_agent_path, opts.release_agent);
 out_unlock:
	if (opts.release_agent)
		kfree(opts.release_agent);
	mutex_unlock(&cgroup_mutex);
	mutex_unlock(&cgrp->dentry->d_inode->i_mutex);
	return ret;
}

static struct super_operations cgroup_ops = {
	.statfs = simple_statfs,
	.drop_inode = generic_delete_inode,
	.show_options = cgroup_show_options,
	.remount_fs = cgroup_remount,
};

static void init_cgroup_root(struct cgroupfs_root *root)
{
	struct cgroup *cgrp = &root->top_cgroup;
	INIT_LIST_HEAD(&root->subsys_list);
	INIT_LIST_HEAD(&root->root_list);
	root->number_of_cgroups = 1;
	cgrp->root = root;
	cgrp->top_cgroup = cgrp;
	INIT_LIST_HEAD(&cgrp->sibling);
	INIT_LIST_HEAD(&cgrp->children);
	INIT_LIST_HEAD(&cgrp->css_sets);
	INIT_LIST_HEAD(&cgrp->release_list);
}

static int cgroup_test_super(struct super_block *sb, void *data)
{
	struct cgroupfs_root *new = data;
	struct cgroupfs_root *root = sb->s_fs_info;

	/* First check subsystems */
	if (new->subsys_bits != root->subsys_bits)
	    return 0;

	/* Next check flags */
	if (new->flags != root->flags)
		return 0;

	return 1;
}

static int cgroup_set_super(struct super_block *sb, void *data)
{
	int ret;
	struct cgroupfs_root *root = data;

	ret = set_anon_super(sb, NULL);
	if (ret)
		return ret;

	sb->s_fs_info = root;
	root->sb = sb;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = CGROUP_SUPER_MAGIC;
	sb->s_op = &cgroup_ops;

	return 0;
}

static int cgroup_get_rootdir(struct super_block *sb)
{
	struct inode *inode =
		cgroup_new_inode(S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR, sb);
	struct dentry *dentry;

	if (!inode)
		return -ENOMEM;

	inode->i_fop = &simple_dir_operations;
	inode->i_op = &cgroup_dir_inode_operations;
	/* directories start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	dentry = d_alloc_root(inode);
	if (!dentry) {
		iput(inode);
		return -ENOMEM;
	}
	sb->s_root = dentry;
	return 0;
}

static int cgroup_get_sb(struct file_system_type *fs_type,
			 int flags, const char *unused_dev_name,
			 void *data, struct vfsmount *mnt)
{
	struct cgroup_sb_opts opts;
	int ret = 0;
	struct super_block *sb;
	struct cgroupfs_root *root;
	struct list_head tmp_cg_links;

	/* First find the desired set of subsystems */
	ret = parse_cgroupfs_options(data, &opts);
	if (ret) {
		if (opts.release_agent)
			kfree(opts.release_agent);
		return ret;
	/* remounting is not allowed for populated hierarchies */
	if (!list_empty(&root->cgrp.self.children)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = rebind_subsystems(root, added_mask);
	if (ret)
		goto out_unlock;

	rebind_subsystems(&cgrp_dfl_root, removed_mask);

	if (opts.release_agent) {
		spin_lock(&release_agent_path_lock);
		strcpy(root->release_agent_path, opts.release_agent);
		spin_unlock(&release_agent_path_lock);
	}
 out_unlock:
	kfree(opts.release_agent);
	kfree(opts.name);
	mutex_unlock(&cgroup_mutex);
	return ret;
	apply_cgroup_root_flags(root_flags);
	return 0;
}

/*
 * To reduce the fork() overhead for systems that are not actually using
 * their cgroups capability, we don't maintain the lists running through
 * each css_set to its tasks until we see the list actually used - in other
 * words after the first mount.
 */
static bool use_task_css_set_links __read_mostly;

static void cgroup_enable_task_cg_lists(void)
{
	struct task_struct *p, *g;

	spin_lock_irq(&css_set_lock);

	if (use_task_css_set_links)
		goto out_unlock;

	use_task_css_set_links = true;

	/*
	 * We need tasklist_lock because RCU is not safe against
	 * while_each_thread(). Besides, a forking task that has passed
	 * cgroup_post_fork() without seeing use_task_css_set_links = 1
	 * is not guaranteed to have its child immediately visible in the
	 * tasklist if we walk through it with RCU.
	 */
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		WARN_ON_ONCE(!list_empty(&p->cg_list) ||
			     task_css_set(p) != &init_css_set);

		/*
		 * We should check if the process is exiting, otherwise
		 * it will race with cgroup_exit() in that the list
		 * entry won't be deleted though the process has exited.
		 * Do it while holding siglock so that we don't end up
		 * racing against cgroup_exit().
		 *
		 * Interrupts were already disabled while acquiring
		 * the css_set_lock, so we do not need to disable it
		 * again when acquiring the sighand->siglock here.
		 */
		spin_lock(&p->sighand->siglock);
		if (!(p->flags & PF_EXITING)) {
			struct css_set *cset = task_css_set(p);

			if (!css_set_populated(cset))
				css_set_update_populated(cset, true);
			list_add_tail(&p->cg_list, &cset->tasks);
			get_css_set(cset);
			cset->nr_tasks++;
		}
		spin_unlock(&p->sighand->siglock);
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);
out_unlock:
	spin_unlock_irq(&css_set_lock);
}

static void init_cgroup_housekeeping(struct cgroup *cgrp)
{
	struct cgroup_subsys *ss;
	int ssid;

	INIT_LIST_HEAD(&cgrp->self.sibling);
	INIT_LIST_HEAD(&cgrp->self.children);
	INIT_LIST_HEAD(&cgrp->cset_links);
	INIT_LIST_HEAD(&cgrp->pidlists);
	mutex_init(&cgrp->pidlist_mutex);
	cgrp->self.cgroup = cgrp;
	cgrp->self.flags |= CSS_ONLINE;
	cgrp->dom_cgrp = cgrp;
	cgrp->max_descendants = INT_MAX;
	cgrp->max_depth = INT_MAX;

	for_each_subsys(ss, ssid)
		INIT_LIST_HEAD(&cgrp->e_csets[ssid]);

	init_waitqueue_head(&cgrp->offline_waitq);
	INIT_WORK(&cgrp->release_agent_work, cgroup1_release_agent);
}

void init_cgroup_root(struct cgroup_root *root, struct cgroup_sb_opts *opts)
{
	struct cgroup *cgrp = &root->cgrp;

	INIT_LIST_HEAD(&root->root_list);
	atomic_set(&root->nr_cgrps, 1);
	cgrp->root = root;
	init_cgroup_housekeeping(cgrp);
	idr_init(&root->cgroup_idr);

	root->flags = opts->flags;
	if (opts->release_agent)
		strcpy(root->release_agent_path, opts->release_agent);
	if (opts->name)
		strcpy(root->name, opts->name);
	if (opts->cpuset_clone_children)
		set_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->cgrp.flags);
}

int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask, int ref_flags)
{
	LIST_HEAD(tmp_links);
	struct cgroup *root_cgrp = &root->cgrp;
	struct kernfs_syscall_ops *kf_sops;
	struct css_set *cset;
	int i, ret;

	lockdep_assert_held(&cgroup_mutex);

	ret = cgroup_idr_alloc(&root->cgroup_idr, root_cgrp, 1, 2, GFP_KERNEL);
	if (ret < 0)
		goto out;
	root_cgrp->id = ret;
	root_cgrp->ancestor_ids[0] = ret;

	ret = percpu_ref_init(&root_cgrp->self.refcnt, css_release,
			      ref_flags, GFP_KERNEL);
	if (ret)
		goto out;

	/*
	 * We're accessing css_set_count without locking css_set_lock here,
	 * but that's OK - it can only be increased by someone holding
	 * cgroup_lock, and that's us.  Later rebinding may disable
	 * controllers on the default hierarchy and thus create new csets,
	 * which can't be more than the existing ones.  Allocate 2x.
	 */
	ret = allocate_cgrp_cset_links(2 * css_set_count, &tmp_links);
	if (ret)
		goto cancel_ref;

	ret = cgroup_init_root_id(root);
	if (ret)
		goto cancel_ref;

	kf_sops = root == &cgrp_dfl_root ?
		&cgroup_kf_syscall_ops : &cgroup1_kf_syscall_ops;

	root->kf_root = kernfs_create_root(kf_sops,
					   KERNFS_ROOT_CREATE_DEACTIVATED |
					   KERNFS_ROOT_SUPPORT_EXPORTOP,
					   root_cgrp);
	if (IS_ERR(root->kf_root)) {
		ret = PTR_ERR(root->kf_root);
		goto exit_root_id;
	}
	root_cgrp->kn = root->kf_root->kn;

	ret = css_populate_dir(&root_cgrp->self);
	if (ret)
		goto destroy_root;

	ret = rebind_subsystems(root, ss_mask);
	if (ret)
		goto destroy_root;

	trace_cgroup_setup_root(root);

	/*
	 * There must be no failure case after here, since rebinding takes
	 * care of subsystems' refcounts, which are explicitly dropped in
	 * the failure exit path.
	 */
	list_add(&root->root_list, &cgroup_roots);
	cgroup_root_count++;

	/*
	 * Link the root cgroup in this hierarchy into all the css_set
	 * objects.
	 */
	spin_lock_irq(&css_set_lock);
	hash_for_each(css_set_table, i, cset, hlist) {
		link_css_set(&tmp_links, cset, root_cgrp);
		if (css_set_populated(cset))
			cgroup_update_populated(root_cgrp, true);
	}
	spin_unlock_irq(&css_set_lock);

	BUG_ON(!list_empty(&root_cgrp->self.children));
	BUG_ON(atomic_read(&root->nr_cgrps) != 1);

	kernfs_activate(root_cgrp->kn);
	ret = 0;
	goto out;

destroy_root:
	kernfs_destroy_root(root->kf_root);
	root->kf_root = NULL;
exit_root_id:
	cgroup_exit_root_id(root);
cancel_ref:
	percpu_ref_exit(&root_cgrp->self.refcnt);
out:
	free_cgrp_cset_links(&tmp_links);
	return ret;
}

struct dentry *cgroup_do_mount(struct file_system_type *fs_type, int flags,
			       struct cgroup_root *root, unsigned long magic,
			       struct cgroup_namespace *ns)
{
	struct dentry *dentry;
	bool new_sb;

	dentry = kernfs_mount(fs_type, flags, root->kf_root, magic, &new_sb);

	/*
	 * In non-init cgroup namespace, instead of root cgroup's dentry,
	 * we return the dentry corresponding to the cgroupns->root_cgrp.
	 */
	if (!IS_ERR(dentry) && ns != &init_cgroup_ns) {
		struct dentry *nsdentry;
		struct cgroup *cgrp;

		mutex_lock(&cgroup_mutex);
		spin_lock_irq(&css_set_lock);

		cgrp = cset_cgroup_from_root(ns->root_cset, root);

		spin_unlock_irq(&css_set_lock);
		mutex_unlock(&cgroup_mutex);

		nsdentry = kernfs_node_dentry(cgrp->kn, dentry->d_sb);
		dput(dentry);
		dentry = nsdentry;
	}

	if (IS_ERR(dentry) || !new_sb)
		cgroup_put(&root->cgrp);

	return dentry;
}

static struct dentry *cgroup_mount(struct file_system_type *fs_type,
			 int flags, const char *unused_dev_name,
			 void *data)
{
	struct cgroup_namespace *ns = current->nsproxy->cgroup_ns;
	struct dentry *dentry;
	int ret;

	get_cgroup_ns(ns);

	/* Check if the caller has permission to mount. */
	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN)) {
		put_cgroup_ns(ns);
		return ERR_PTR(-EPERM);
	}

	/*
	 * The first time anyone tries to mount a cgroup, enable the list
	 * linking each css_set to its tasks and fix up all existing tasks.
	 */
	if (!use_task_css_set_links)
		cgroup_enable_task_cg_lists();

	if (fs_type == &cgroup2_fs_type) {
		unsigned int root_flags;

		ret = parse_cgroup_root_flags(data, &root_flags);
		if (ret) {
			put_cgroup_ns(ns);
			return ERR_PTR(ret);
		}

		cgrp_dfl_visible = true;
		cgroup_get_live(&cgrp_dfl_root.cgrp);

		if (root->flags ^ opts.flags)
			pr_warn("new mount options do not match the existing superblock, will be ignored\n");

		/*
		 * We want to reuse @root whose lifetime is governed by its
		 * ->cgrp.  Let's check whether @root is alive and keep it
		 * that way.  As cgroup_kill_sb() can happen anytime, we
		 * want to block it by pinning the sb so that @root doesn't
		 * get killed before mount is complete.
		 *
		 * With the sb pinned, tryget_live can reliably indicate
		 * whether @root can be reused.  If it's being killed,
		 * drain it.  We can use wait_queue for the wait but this
		 * path is super cold.  Let's just sleep a bit and retry.
		 */
		pinned_sb = kernfs_pin_sb(root->kf_root, NULL);
		if (IS_ERR(pinned_sb) ||
		    !percpu_ref_tryget_live(&root->cgrp.self.refcnt)) {
			mutex_unlock(&cgroup_mutex);
			if (!IS_ERR_OR_NULL(pinned_sb))
				deactivate_super(pinned_sb);
			msleep(10);
			ret = restart_syscall();
			goto out_free;
		}

		ret = 0;
		goto out_unlock;
	}

	/*
	 * No such thing, create a new one.  name= matching without subsys
	 * specification is allowed for already existing hierarchies but we
	 * can't create new one without subsys specification.
	 */
	if (!opts.subsys_mask && !opts.none) {
		ret = -EINVAL;
		goto out_unlock;
	}

	root = kzalloc(sizeof(*root), GFP_KERNEL);
	if (!root) {
		if (opts.release_agent)
			kfree(opts.release_agent);
		return -ENOMEM;
	}

	init_cgroup_root(root);
	root->subsys_bits = opts.subsys_bits;
	root->flags = opts.flags;
	if (opts.release_agent) {
		strcpy(root->release_agent_path, opts.release_agent);
		kfree(opts.release_agent);
	}

	sb = sget(fs_type, cgroup_test_super, cgroup_set_super, root);

	if (IS_ERR(sb)) {
		kfree(root);
		return PTR_ERR(sb);
	}

	if (sb->s_fs_info != root) {
		/* Reusing an existing superblock */
		BUG_ON(sb->s_root == NULL);
		kfree(root);
		root = NULL;
	} else {
		/* New superblock */
		struct cgroup *cgrp = &root->top_cgroup;
		struct inode *inode;
		int i;

		BUG_ON(sb->s_root != NULL);

		ret = cgroup_get_rootdir(sb);
		if (ret)
			goto drop_new_super;
		inode = sb->s_root->d_inode;

		mutex_lock(&inode->i_mutex);
		mutex_lock(&cgroup_mutex);

		/*
		 * We're accessing css_set_count without locking
		 * css_set_lock here, but that's OK - it can only be
		 * increased by someone holding cgroup_lock, and
		 * that's us. The worst that can happen is that we
		 * have some link structures left over
		 */
		ret = allocate_cg_links(css_set_count, &tmp_cg_links);
		if (ret) {
			mutex_unlock(&cgroup_mutex);
			mutex_unlock(&inode->i_mutex);
			goto drop_new_super;
		}

		ret = rebind_subsystems(root, root->subsys_bits);
		if (ret == -EBUSY) {
			mutex_unlock(&cgroup_mutex);
			mutex_unlock(&inode->i_mutex);
			goto drop_new_super;
		}

		/* EBUSY should be the only error here */
		BUG_ON(ret);

		list_add(&root->root_list, &roots);
		root_count++;

		sb->s_root->d_fsdata = &root->top_cgroup;
		root->top_cgroup.dentry = sb->s_root;

		/* Link the top cgroup in this hierarchy into all
		 * the css_set objects */
		write_lock(&css_set_lock);
		for (i = 0; i < CSS_SET_TABLE_SIZE; i++) {
			struct hlist_head *hhead = &css_set_table[i];
			struct hlist_node *node;
			struct css_set *cg;

			hlist_for_each_entry(cg, node, hhead, hlist) {
				struct cg_cgroup_link *link;

				BUG_ON(list_empty(&tmp_cg_links));
				link = list_entry(tmp_cg_links.next,
						  struct cg_cgroup_link,
						  cgrp_link_list);
				list_del(&link->cgrp_link_list);
				link->cg = cg;
				list_add(&link->cgrp_link_list,
					 &root->top_cgroup.css_sets);
				list_add(&link->cg_link_list, &cg->cg_links);
			}
		}
		write_unlock(&css_set_lock);

		free_cg_links(&tmp_cg_links);

		BUG_ON(!list_empty(&cgrp->sibling));
		BUG_ON(!list_empty(&cgrp->children));
		BUG_ON(root->number_of_cgroups != 1);

		cgroup_populate_dir(cgrp);
		mutex_unlock(&inode->i_mutex);
		mutex_unlock(&cgroup_mutex);
	}

	return simple_set_mnt(mnt, sb);

 drop_new_super:
	up_write(&sb->s_umount);
	deactivate_super(sb);
	free_cg_links(&tmp_cg_links);
	return ret;
}

static void cgroup_kill_sb(struct super_block *sb) {
	struct cgroupfs_root *root = sb->s_fs_info;
	struct cgroup *cgrp = &root->top_cgroup;
	int ret;
	struct cg_cgroup_link *link;
	struct cg_cgroup_link *saved_link;

	BUG_ON(!root);

	BUG_ON(root->number_of_cgroups != 1);
	BUG_ON(!list_empty(&cgrp->children));
	BUG_ON(!list_empty(&cgrp->sibling));

	mutex_lock(&cgroup_mutex);

	/* Rebind all subsystems back to the default hierarchy */
	ret = rebind_subsystems(root, 0);
	/* Shouldn't be able to fail ... */
	BUG_ON(ret);

	/*
	 * Release all the links from css_sets to this hierarchy's
	 * root cgroup
	 */
	write_lock(&css_set_lock);

	list_for_each_entry_safe(link, saved_link, &cgrp->css_sets,
				 cgrp_link_list) {
		list_del(&link->cg_link_list);
		list_del(&link->cgrp_link_list);
		kfree(link);
	}
	write_unlock(&css_set_lock);

	if (!list_empty(&root->root_list)) {
		list_del(&root->root_list);
		root_count--;
	}
	mutex_unlock(&cgroup_mutex);

	kfree(root);
	kill_litter_super(sb);
		ret = -ENOMEM;
		goto out_unlock;
	}

	init_cgroup_root(root, &opts);

	ret = cgroup_setup_root(root, opts.subsys_mask);
	if (ret)
		cgroup_free_root(root);

out_unlock:
	mutex_unlock(&cgroup_mutex);
out_free:
	kfree(opts.release_agent);
	kfree(opts.name);

	if (ret)
		return ERR_PTR(ret);

	dentry = kernfs_mount(fs_type, flags, root->kf_root,
				CGROUP_SUPER_MAGIC, &new_sb);
	if (IS_ERR(dentry) || !new_sb)
		cgroup_put(&root->cgrp);

	/*
	 * If @pinned_sb, we're reusing an existing root and holding an
	 * extra ref on its sb.  Mount is complete.  Put the extra ref.
	 */
	if (pinned_sb) {
		WARN_ON(new_sb);
		deactivate_super(pinned_sb);
		dentry = cgroup_do_mount(&cgroup2_fs_type, flags, &cgrp_dfl_root,
					 CGROUP2_SUPER_MAGIC, ns);
		if (!IS_ERR(dentry))
			apply_cgroup_root_flags(root_flags);
	} else {
		dentry = cgroup1_mount(&cgroup_fs_type, flags, data,
				       CGROUP_SUPER_MAGIC, ns);
	}

	put_cgroup_ns(ns);
	return dentry;
}

static void cgroup_kill_sb(struct super_block *sb)
{
	struct kernfs_root *kf_root = kernfs_root_from_sb(sb);
	struct cgroup_root *root = cgroup_root_from_kf(kf_root);

	/*
	 * If @root doesn't have any mounts or children, start killing it.
	 * This prevents new mounts by disabling percpu_ref_tryget_live().
	 * cgroup_mount() may wait for @root's release.
	 *
	 * And don't kill the default root.
	 */
	if (!list_empty(&root->cgrp.self.children) ||
	    root == &cgrp_dfl_root)
		cgroup_put(&root->cgrp);
	else
		percpu_ref_kill(&root->cgrp.self.refcnt);

	kernfs_kill_sb(sb);
}

struct file_system_type cgroup_fs_type = {
	.name = "cgroup",
	.get_sb = cgroup_get_sb,
	.kill_sb = cgroup_kill_sb,
};

static inline struct cgroup *__d_cgrp(struct dentry *dentry)
{
	return dentry->d_fsdata;
}

static inline struct cftype *__d_cft(struct dentry *dentry)
{
	return dentry->d_fsdata;
}

/**
 * cgroup_path - generate the path of a cgroup
 * @cgrp: the cgroup in question
 * @buf: the buffer to write the path into
 * @buflen: the length of the buffer
 *
 * Called with cgroup_mutex held. Writes path of cgroup into buf.
 * Returns 0 on success, -errno on error.
 */
int cgroup_path(const struct cgroup *cgrp, char *buf, int buflen)
{
	char *start;

	if (cgrp == dummytop) {
		/*
		 * Inactive subsystems have no dentry for their root
		 * cgroup
		 */
		strcpy(buf, "/");
		return 0;
	}

	start = buf + buflen;

	*--start = '\0';
	for (;;) {
		int len = cgrp->dentry->d_name.len;
		if ((start -= len) < buf)
			return -ENAMETOOLONG;
		memcpy(start, cgrp->dentry->d_name.name, len);
		cgrp = cgrp->parent;
		if (!cgrp)
			break;
		if (!cgrp->parent)
			continue;
		if (--start < buf)
			return -ENAMETOOLONG;
		*start = '/';
	}
	memmove(buf, start, buf + buflen - start);
	return 0;
}

/*
 * Return the first subsystem attached to a cgroup's hierarchy, and
 * its subsystem id.
 */

static void get_first_subsys(const struct cgroup *cgrp,
			struct cgroup_subsys_state **css, int *subsys_id)
{
	const struct cgroupfs_root *root = cgrp->root;
	const struct cgroup_subsys *test_ss;
	BUG_ON(list_empty(&root->subsys_list));
	test_ss = list_entry(root->subsys_list.next,
			     struct cgroup_subsys, sibling);
	if (css) {
		*css = cgrp->subsys[test_ss->subsys_id];
		BUG_ON(!*css);
	}
	if (subsys_id)
		*subsys_id = test_ss->subsys_id;
}

/**
 * cgroup_attach_task - attach task 'tsk' to cgroup 'cgrp'
 * @cgrp: the cgroup the task is attaching to
 * @tsk: the task to be attached
 *
 * Call holding cgroup_mutex. May take task_lock of
 * the task 'tsk' during call.
 */
int cgroup_attach_task(struct cgroup *cgrp, struct task_struct *tsk)
{
	int retval = 0;
	struct cgroup_subsys *ss;
	struct cgroup *oldcgrp;
	struct css_set *cg = tsk->cgroups;
	struct css_set *newcg;
	struct cgroupfs_root *root = cgrp->root;
	int subsys_id;

	get_first_subsys(cgrp, NULL, &subsys_id);

	/* Nothing to do if the task is already in that cgroup */
	oldcgrp = task_cgroup(tsk, subsys_id);
	if (cgrp == oldcgrp)
		return 0;

	for_each_subsys(root, ss) {
		if (ss->can_attach) {
			retval = ss->can_attach(ss, cgrp, tsk);
			if (retval)
				return retval;
	.mount = cgroup_mount,
	.kill_sb = cgroup_kill_sb,
	.fs_flags = FS_USERNS_MOUNT,
};

static struct file_system_type cgroup2_fs_type = {
	.name = "cgroup2",
	.mount = cgroup_mount,
	.kill_sb = cgroup_kill_sb,
	.fs_flags = FS_USERNS_MOUNT,
};

int cgroup_path_ns_locked(struct cgroup *cgrp, char *buf, size_t buflen,
			  struct cgroup_namespace *ns)
{
	struct cgroup *root = cset_cgroup_from_root(ns->root_cset, cgrp->root);

	return kernfs_path_from_node(cgrp->kn, root->kn, buf, buflen);
}

int cgroup_path_ns(struct cgroup *cgrp, char *buf, size_t buflen,
		   struct cgroup_namespace *ns)
{
	int ret;

	mutex_lock(&cgroup_mutex);
	spin_lock_irq(&css_set_lock);

	ret = cgroup_path_ns_locked(cgrp, buf, buflen, ns);

	spin_unlock_irq(&css_set_lock);
	mutex_unlock(&cgroup_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(cgroup_path_ns);

/**
 * task_cgroup_path - cgroup path of a task in the first cgroup hierarchy
 * @task: target task
 * @buf: the buffer to write the path into
 * @buflen: the length of the buffer
 *
 * Determine @task's cgroup on the first (the one with the lowest non-zero
 * hierarchy_id) cgroup hierarchy and copy its path into @buf.  This
 * function grabs cgroup_mutex and shouldn't be used inside locks used by
 * cgroup controller callbacks.
 *
 * Return value is the same as kernfs_path().
 */
int task_cgroup_path(struct task_struct *task, char *buf, size_t buflen)
{
	struct cgroup_root *root;
	struct cgroup *cgrp;
	int hierarchy_id = 1;
	int ret;

	mutex_lock(&cgroup_mutex);
	spin_lock_irq(&css_set_lock);

	root = idr_get_next(&cgroup_hierarchy_idr, &hierarchy_id);

	if (root) {
		cgrp = task_cgroup_from_root(task, root);
		ret = cgroup_path_ns_locked(cgrp, buf, buflen, &init_cgroup_ns);
	} else {
		/* if no hierarchy exists, everyone is in "/" */
		ret = strlcpy(buf, "/", buflen);
	}

	spin_unlock_irq(&css_set_lock);
	mutex_unlock(&cgroup_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(task_cgroup_path);

/**
 * cgroup_migrate_add_task - add a migration target task to a migration context
 * @task: target task
 * @mgctx: target migration context
 *
 * Add @task, which is a migration target, to @mgctx->tset.  This function
 * becomes noop if @task doesn't need to be migrated.  @task's css_set
 * should have been added as a migration source and @task->cg_list will be
 * moved from the css_set's tasks list to mg_tasks one.
 */
static void cgroup_migrate_add_task(struct task_struct *task,
				    struct cgroup_mgctx *mgctx)
{
	struct css_set *cset;

	lockdep_assert_held(&css_set_lock);

	/* @task either already exited or can't exit until the end */
	if (task->flags & PF_EXITING)
		return;

	/* leave @task alone if post_fork() hasn't linked it yet */
	if (list_empty(&task->cg_list))
		return;

	cset = task_css_set(task);
	if (!cset->mg_src_cgrp)
		return;

	mgctx->tset.nr_tasks++;

	list_move_tail(&task->cg_list, &cset->mg_tasks);
	if (list_empty(&cset->mg_node))
		list_add_tail(&cset->mg_node,
			      &mgctx->tset.src_csets);
	if (list_empty(&cset->mg_dst_cset->mg_node))
		list_add_tail(&cset->mg_dst_cset->mg_node,
			      &mgctx->tset.dst_csets);
}

/**
 * cgroup_taskset_first - reset taskset and return the first task
 * @tset: taskset of interest
 * @dst_cssp: output variable for the destination css
 *
 * @tset iteration is initialized and the first task is returned.
 */
struct task_struct *cgroup_taskset_first(struct cgroup_taskset *tset,
					 struct cgroup_subsys_state **dst_cssp)
{
	tset->cur_cset = list_first_entry(tset->csets, struct css_set, mg_node);
	tset->cur_task = NULL;

	return cgroup_taskset_next(tset, dst_cssp);
}

/**
 * cgroup_taskset_next - iterate to the next task in taskset
 * @tset: taskset of interest
 * @dst_cssp: output variable for the destination css
 *
 * Return the next task in @tset.  Iteration must have been initialized
 * with cgroup_taskset_first().
 */
struct task_struct *cgroup_taskset_next(struct cgroup_taskset *tset,
					struct cgroup_subsys_state **dst_cssp)
{
	struct css_set *cset = tset->cur_cset;
	struct task_struct *task = tset->cur_task;

	while (&cset->mg_node != tset->csets) {
		if (!task)
			task = list_first_entry(&cset->mg_tasks,
						struct task_struct, cg_list);
		else
			task = list_next_entry(task, cg_list);

		if (&task->cg_list != &cset->mg_tasks) {
			tset->cur_cset = cset;
			tset->cur_task = task;

			/*
			 * This function may be called both before and
			 * after cgroup_taskset_migrate().  The two cases
			 * can be distinguished by looking at whether @cset
			 * has its ->mg_dst_cset set.
			 */
			if (cset->mg_dst_cset)
				*dst_cssp = cset->mg_dst_cset->subsys[tset->ssid];
			else
				*dst_cssp = cset->subsys[tset->ssid];

			return task;
		}

		cset = list_next_entry(cset, mg_node);
		task = NULL;
	}

	return NULL;
}

/**
 * cgroup_taskset_migrate - migrate a taskset
 * @mgctx: migration context
 *
 * Migrate tasks in @mgctx as setup by migration preparation functions.
 * This function fails iff one of the ->can_attach callbacks fails and
 * guarantees that either all or none of the tasks in @mgctx are migrated.
 * @mgctx is consumed regardless of success.
 */
static int cgroup_migrate_execute(struct cgroup_mgctx *mgctx)
{
	struct cgroup_taskset *tset = &mgctx->tset;
	struct cgroup_subsys *ss;
	struct task_struct *task, *tmp_task;
	struct css_set *cset, *tmp_cset;
	int ssid, failed_ssid, ret;

	/* check that we can legitimately attach to the cgroup */
	if (tset->nr_tasks) {
		do_each_subsys_mask(ss, ssid, mgctx->ss_mask) {
			if (ss->can_attach) {
				tset->ssid = ssid;
				ret = ss->can_attach(tset);
				if (ret) {
					failed_ssid = ssid;
					goto out_cancel_attach;
				}
			}
		} while_each_subsys_mask();
	}

	/*
	 * Locate or allocate a new css_set for this task,
	 * based on its final set of cgroups
	 */
	newcg = find_css_set(cg, cgrp);
	if (!newcg)
		return -ENOMEM;

	task_lock(tsk);
	if (tsk->flags & PF_EXITING) {
		task_unlock(tsk);
		put_css_set(newcg);
		return -ESRCH;
	}
	rcu_assign_pointer(tsk->cgroups, newcg);
	task_unlock(tsk);

	/* Update the css_set linked lists if we're using them */
	write_lock(&css_set_lock);
	if (!list_empty(&tsk->cg_list)) {
		list_del(&tsk->cg_list);
		list_add(&tsk->cg_list, &newcg->tasks);
	}
	write_unlock(&css_set_lock);

	for_each_subsys(root, ss) {
		if (ss->attach)
			ss->attach(ss, cgrp, oldcgrp, tsk);
	}
	set_bit(CGRP_RELEASABLE, &oldcgrp->flags);
	synchronize_rcu();
	put_css_set(cg);
	return 0;
}

/*
 * Attach task with pid 'pid' to cgroup 'cgrp'. Call with cgroup_mutex
 * held. May take task_lock of task
 */
static int attach_task_by_pid(struct cgroup *cgrp, u64 pid)
{
	struct task_struct *tsk;
	int ret;

	if (pid) {
		rcu_read_lock();
		tsk = find_task_by_vpid(pid);
		if (!tsk || tsk->flags & PF_EXITING) {
			rcu_read_unlock();
			return -ESRCH;
		}
		get_task_struct(tsk);
		rcu_read_unlock();

		if ((current->euid) && (current->euid != tsk->uid)
		    && (current->euid != tsk->suid)) {
			put_task_struct(tsk);
			return -EACCES;
		}
	} else {
		tsk = current;
		get_task_struct(tsk);
	}

	ret = cgroup_attach_task(cgrp, tsk);
	put_task_struct(tsk);
	return ret;
}

static int cgroup_tasks_write(struct cgroup *cgrp, struct cftype *cft, u64 pid)
{
	int ret;
	if (!cgroup_lock_live_group(cgrp))
		return -ENODEV;
	ret = attach_task_by_pid(cgrp, pid);
	cgroup_unlock();
	return ret;
}

/* The various types of files and directories in a cgroup file system */
enum cgroup_filetype {
	FILE_ROOT,
	FILE_DIR,
	FILE_TASKLIST,
	FILE_NOTIFY_ON_RELEASE,
	FILE_RELEASE_AGENT,
};

/**
 * cgroup_lock_live_group - take cgroup_mutex and check that cgrp is alive.
 * @cgrp: the cgroup to be checked for liveness
 *
 * On success, returns true; the lock should be later released with
 * cgroup_unlock(). On failure returns false with no lock held.
 */
bool cgroup_lock_live_group(struct cgroup *cgrp)
{
	mutex_lock(&cgroup_mutex);
	if (cgroup_is_removed(cgrp)) {
		mutex_unlock(&cgroup_mutex);
		return false;
	}
	return true;
}

static int cgroup_release_agent_write(struct cgroup *cgrp, struct cftype *cft,
				      const char *buffer)
{
	BUILD_BUG_ON(sizeof(cgrp->root->release_agent_path) < PATH_MAX);
	if (!cgroup_lock_live_group(cgrp))
		return -ENODEV;
	strcpy(cgrp->root->release_agent_path, buffer);
	cgroup_unlock();
	return 0;
}

static int cgroup_release_agent_show(struct cgroup *cgrp, struct cftype *cft,
				     struct seq_file *seq)
{
	if (!cgroup_lock_live_group(cgrp))
		return -ENODEV;
	seq_puts(seq, cgrp->root->release_agent_path);
	seq_putc(seq, '\n');
	cgroup_unlock();
	return 0;
}

/* A buffer size big enough for numbers or short strings */
#define CGROUP_LOCAL_BUFFER_SIZE 64

static ssize_t cgroup_write_X64(struct cgroup *cgrp, struct cftype *cft,
				struct file *file,
				const char __user *userbuf,
				size_t nbytes, loff_t *unused_ppos)
{
	char buffer[CGROUP_LOCAL_BUFFER_SIZE];
	int retval = 0;
	char *end;

	if (!nbytes)
		return -EINVAL;
	if (nbytes >= sizeof(buffer))
		return -E2BIG;
	if (copy_from_user(buffer, userbuf, nbytes))
		return -EFAULT;

	buffer[nbytes] = 0;     /* nul-terminate */
	strstrip(buffer);
	if (cft->write_u64) {
		u64 val = simple_strtoull(buffer, &end, 0);
		if (*end)
			return -EINVAL;
		retval = cft->write_u64(cgrp, cft, val);
	} else {
		s64 val = simple_strtoll(buffer, &end, 0);
		if (*end)
			return -EINVAL;
		retval = cft->write_s64(cgrp, cft, val);
	}
	if (!retval)
		retval = nbytes;
	return retval;
}

static ssize_t cgroup_write_string(struct cgroup *cgrp, struct cftype *cft,
				   struct file *file,
				   const char __user *userbuf,
				   size_t nbytes, loff_t *unused_ppos)
{
	char local_buffer[CGROUP_LOCAL_BUFFER_SIZE];
	int retval = 0;
	size_t max_bytes = cft->max_write_len;
	char *buffer = local_buffer;

	if (!max_bytes)
		max_bytes = sizeof(local_buffer) - 1;
	if (nbytes >= max_bytes)
		return -E2BIG;
	/* Allocate a dynamic buffer if we need one */
	if (nbytes >= sizeof(local_buffer)) {
		buffer = kmalloc(nbytes + 1, GFP_KERNEL);
		if (buffer == NULL)
			return -ENOMEM;
	}
	if (nbytes && copy_from_user(buffer, userbuf, nbytes)) {
		retval = -EFAULT;
		goto out;
	}

	buffer[nbytes] = 0;     /* nul-terminate */
	strstrip(buffer);
	retval = cft->write_string(cgrp, cft, buffer);
	if (!retval)
		retval = nbytes;
out:
	if (buffer != local_buffer)
		kfree(buffer);
	return retval;
}

static ssize_t cgroup_file_write(struct file *file, const char __user *buf,
						size_t nbytes, loff_t *ppos)
{
	struct cftype *cft = __d_cft(file->f_dentry);
	struct cgroup *cgrp = __d_cgrp(file->f_dentry->d_parent);

	if (!cft || cgroup_is_removed(cgrp))
		return -ENODEV;
	if (cft->write)
		return cft->write(cgrp, cft, file, buf, nbytes, ppos);
	if (cft->write_u64 || cft->write_s64)
		return cgroup_write_X64(cgrp, cft, file, buf, nbytes, ppos);
	if (cft->write_string)
		return cgroup_write_string(cgrp, cft, file, buf, nbytes, ppos);
	if (cft->trigger) {
		int ret = cft->trigger(cgrp, (unsigned int)cft->private);
		return ret ? ret : nbytes;
	}
	return -EINVAL;
}

static ssize_t cgroup_read_u64(struct cgroup *cgrp, struct cftype *cft,
			       struct file *file,
			       char __user *buf, size_t nbytes,
			       loff_t *ppos)
{
	char tmp[CGROUP_LOCAL_BUFFER_SIZE];
	u64 val = cft->read_u64(cgrp, cft);
	int len = sprintf(tmp, "%llu\n", (unsigned long long) val);

	return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
}

static ssize_t cgroup_read_s64(struct cgroup *cgrp, struct cftype *cft,
			       struct file *file,
			       char __user *buf, size_t nbytes,
			       loff_t *ppos)
{
	char tmp[CGROUP_LOCAL_BUFFER_SIZE];
	s64 val = cft->read_s64(cgrp, cft);
	int len = sprintf(tmp, "%lld\n", (long long) val);

	return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
}

static ssize_t cgroup_file_read(struct file *file, char __user *buf,
				   size_t nbytes, loff_t *ppos)
{
	struct cftype *cft = __d_cft(file->f_dentry);
	struct cgroup *cgrp = __d_cgrp(file->f_dentry->d_parent);

	if (!cft || cgroup_is_removed(cgrp))
		return -ENODEV;

	if (cft->read)
		return cft->read(cgrp, cft, file, buf, nbytes, ppos);
	if (cft->read_u64)
		return cgroup_read_u64(cgrp, cft, file, buf, nbytes, ppos);
	if (cft->read_s64)
		return cgroup_read_s64(cgrp, cft, file, buf, nbytes, ppos);
	return -EINVAL;
}

/*
 * seqfile ops/methods for returning structured data. Currently just
 * supports string->u64 maps, but can be extended in future.
 */

struct cgroup_seqfile_state {
	struct cftype *cft;
	struct cgroup *cgroup;
};

static int cgroup_map_add(struct cgroup_map_cb *cb, const char *key, u64 value)
{
	struct seq_file *sf = cb->state;
	return seq_printf(sf, "%s %llu\n", key, (unsigned long long)value);
	 * Now that we're guaranteed success, proceed to move all tasks to
	 * the new cgroup.  There are no failure cases after here, so this
	 * is the commit point.
	 */
	spin_lock_irq(&css_set_lock);
	list_for_each_entry(cset, &tset->src_csets, mg_node) {
		list_for_each_entry_safe(task, tmp_task, &cset->mg_tasks, cg_list) {
			struct css_set *from_cset = task_css_set(task);
			struct css_set *to_cset = cset->mg_dst_cset;

			get_css_set(to_cset);
			to_cset->nr_tasks++;
			css_set_move_task(task, from_cset, to_cset, true);
			put_css_set_locked(from_cset);
			from_cset->nr_tasks--;
		}
	}
	spin_unlock_irq(&css_set_lock);

	/*
	 * Migration is committed, all target tasks are now on dst_csets.
	 * Nothing is sensitive to fork() after this point.  Notify
	 * controllers that migration is complete.
	 */
	tset->csets = &tset->dst_csets;

	if (tset->nr_tasks) {
		do_each_subsys_mask(ss, ssid, mgctx->ss_mask) {
			if (ss->attach) {
				tset->ssid = ssid;
				ss->attach(tset);
			}
		} while_each_subsys_mask();
	}

	ret = 0;
	goto out_release_tset;

out_cancel_attach:
	if (tset->nr_tasks) {
		do_each_subsys_mask(ss, ssid, mgctx->ss_mask) {
			if (ssid == failed_ssid)
				break;
			if (ss->cancel_attach) {
				tset->ssid = ssid;
				ss->cancel_attach(tset);
			}
		} while_each_subsys_mask();
	}
out_release_tset:
	spin_lock_irq(&css_set_lock);
	list_splice_init(&tset->dst_csets, &tset->src_csets);
	list_for_each_entry_safe(cset, tmp_cset, &tset->src_csets, mg_node) {
		list_splice_tail_init(&cset->mg_tasks, &cset->tasks);
		list_del_init(&cset->mg_node);
	}
	spin_unlock_irq(&css_set_lock);

	/*
	 * Re-initialize the cgroup_taskset structure in case it is reused
	 * again in another cgroup_migrate_add_task()/cgroup_migrate_execute()
	 * iteration.
	 */
	tset->nr_tasks = 0;
	tset->csets    = &tset->src_csets;
	return ret;
}

/**
 * cgroup_migrate_vet_dst - verify whether a cgroup can be migration destination
 * @dst_cgrp: destination cgroup to test
 *
 * On the default hierarchy, except for the mixable, (possible) thread root
 * and threaded cgroups, subtree_control must be zero for migration
 * destination cgroups with tasks so that child cgroups don't compete
 * against tasks.
 */
int cgroup_migrate_vet_dst(struct cgroup *dst_cgrp)
{
	/* v1 doesn't have any restriction */
	if (!cgroup_on_dfl(dst_cgrp))
		return 0;

	/* verify @dst_cgrp can host resources */
	if (!cgroup_is_valid_domain(dst_cgrp->dom_cgrp))
		return -EOPNOTSUPP;

	/* mixables don't care */
	if (cgroup_is_mixable(dst_cgrp))
		return 0;

	/*
	 * If @dst_cgrp is already or can become a thread root or is
	 * threaded, it doesn't matter.
	 */
	if (cgroup_can_be_thread_root(dst_cgrp) || cgroup_is_threaded(dst_cgrp))
		return 0;

	/* apply no-internal-process constraint */
	if (dst_cgrp->subtree_control)
		return -EBUSY;

	return 0;
}

/**
 * cgroup_migrate_finish - cleanup after attach
 * @mgctx: migration context
 *
 * Undo cgroup_migrate_add_src() and cgroup_migrate_prepare_dst().  See
 * those functions for details.
 */
void cgroup_migrate_finish(struct cgroup_mgctx *mgctx)
{
	LIST_HEAD(preloaded);
	struct css_set *cset, *tmp_cset;

	lockdep_assert_held(&cgroup_mutex);

	spin_lock_irq(&css_set_lock);

	list_splice_tail_init(&mgctx->preloaded_src_csets, &preloaded);
	list_splice_tail_init(&mgctx->preloaded_dst_csets, &preloaded);

	list_for_each_entry_safe(cset, tmp_cset, &preloaded, mg_preload_node) {
		cset->mg_src_cgrp = NULL;
		cset->mg_dst_cgrp = NULL;
		cset->mg_dst_cset = NULL;
		list_del_init(&cset->mg_preload_node);
		put_css_set_locked(cset);
	}

	spin_unlock_irq(&css_set_lock);
}

/**
 * cgroup_migrate_add_src - add a migration source css_set
 * @src_cset: the source css_set to add
 * @dst_cgrp: the destination cgroup
 * @mgctx: migration context
 *
 * Tasks belonging to @src_cset are about to be migrated to @dst_cgrp.  Pin
 * @src_cset and add it to @mgctx->src_csets, which should later be cleaned
 * up by cgroup_migrate_finish().
 *
 * This function may be called without holding cgroup_threadgroup_rwsem
 * even if the target is a process.  Threads may be created and destroyed
 * but as long as cgroup_mutex is not dropped, no new css_set can be put
 * into play and the preloaded css_sets are guaranteed to cover all
 * migrations.
 */
void cgroup_migrate_add_src(struct css_set *src_cset,
			    struct cgroup *dst_cgrp,
			    struct cgroup_mgctx *mgctx)
{
	struct cgroup *src_cgrp;

	lockdep_assert_held(&cgroup_mutex);
	lockdep_assert_held(&css_set_lock);

	/*
	 * If ->dead, @src_set is associated with one or more dead cgroups
	 * and doesn't contain any migratable tasks.  Ignore it early so
	 * that the rest of migration path doesn't get confused by it.
	 */
	if (src_cset->dead)
		return;

	src_cgrp = cset_cgroup_from_root(src_cset, dst_cgrp->root);

	if (!list_empty(&src_cset->mg_preload_node))
		return;

	WARN_ON(src_cset->mg_src_cgrp);
	WARN_ON(src_cset->mg_dst_cgrp);
	WARN_ON(!list_empty(&src_cset->mg_tasks));
	WARN_ON(!list_empty(&src_cset->mg_node));

	src_cset->mg_src_cgrp = src_cgrp;
	src_cset->mg_dst_cgrp = dst_cgrp;
	get_css_set(src_cset);
	list_add_tail(&src_cset->mg_preload_node, &mgctx->preloaded_src_csets);
}

/**
 * cgroup_migrate_prepare_dst - prepare destination css_sets for migration
 * @mgctx: migration context
 *
 * Tasks are about to be moved and all the source css_sets have been
 * preloaded to @mgctx->preloaded_src_csets.  This function looks up and
 * pins all destination css_sets, links each to its source, and append them
 * to @mgctx->preloaded_dst_csets.
 *
 * This function must be called after cgroup_migrate_add_src() has been
 * called on each migration source css_set.  After migration is performed
 * using cgroup_migrate(), cgroup_migrate_finish() must be called on
 * @mgctx.
 */
int cgroup_migrate_prepare_dst(struct cgroup_mgctx *mgctx)
{
	struct css_set *src_cset, *tmp_cset;

	lockdep_assert_held(&cgroup_mutex);

	/* look up the dst cset for each src cset and link it to src */
	list_for_each_entry_safe(src_cset, tmp_cset, &mgctx->preloaded_src_csets,
				 mg_preload_node) {
		struct css_set *dst_cset;
		struct cgroup_subsys *ss;
		int ssid;

		dst_cset = find_css_set(src_cset, src_cset->mg_dst_cgrp);
		if (!dst_cset)
			goto err;

		WARN_ON_ONCE(src_cset->mg_dst_cset || dst_cset->mg_dst_cset);

		/*
		 * If src cset equals dst, it's noop.  Drop the src.
		 * cgroup_migrate() will skip the cset too.  Note that we
		 * can't handle src == dst as some nodes are used by both.
		 */
		if (src_cset == dst_cset) {
			src_cset->mg_src_cgrp = NULL;
			src_cset->mg_dst_cgrp = NULL;
			list_del_init(&src_cset->mg_preload_node);
			put_css_set(src_cset);
			put_css_set(dst_cset);
			continue;
		}

		src_cset->mg_dst_cset = dst_cset;

		if (list_empty(&dst_cset->mg_preload_node))
			list_add_tail(&dst_cset->mg_preload_node,
				      &mgctx->preloaded_dst_csets);
		else
			put_css_set(dst_cset);

		for_each_subsys(ss, ssid)
			if (src_cset->subsys[ssid] != dst_cset->subsys[ssid])
				mgctx->ss_mask |= 1 << ssid;
	}

	return 0;
err:
	cgroup_migrate_finish(mgctx);
	return -ENOMEM;
}

/**
 * cgroup_migrate - migrate a process or task to a cgroup
 * @leader: the leader of the process or the task to migrate
 * @threadgroup: whether @leader points to the whole process or a single task
 * @mgctx: migration context
 *
 * Migrate a process or task denoted by @leader.  If migrating a process,
 * the caller must be holding cgroup_threadgroup_rwsem.  The caller is also
 * responsible for invoking cgroup_migrate_add_src() and
 * cgroup_migrate_prepare_dst() on the targets before invoking this
 * function and following up with cgroup_migrate_finish().
 *
 * As long as a controller's ->can_attach() doesn't fail, this function is
 * guaranteed to succeed.  This means that, excluding ->can_attach()
 * failure, when migrating multiple targets, the success or failure can be
 * decided for all targets by invoking group_migrate_prepare_dst() before
 * actually starting migrating.
 */
int cgroup_migrate(struct task_struct *leader, bool threadgroup,
		   struct cgroup_mgctx *mgctx)
{
	struct task_struct *task;

	/*
	 * Prevent freeing of tasks while we take a snapshot. Tasks that are
	 * already PF_EXITING could be freed from underneath us unless we
	 * take an rcu_read_lock.
	 */
	spin_lock_irq(&css_set_lock);
	rcu_read_lock();
	task = leader;
	do {
		cgroup_migrate_add_task(task, mgctx);
		if (!threadgroup)
			break;
	} while_each_thread(leader, task);
	rcu_read_unlock();
	spin_unlock_irq(&css_set_lock);

	return cgroup_migrate_execute(mgctx);
}

/**
 * cgroup_attach_task - attach a task or a whole threadgroup to a cgroup
 * @dst_cgrp: the cgroup to attach to
 * @leader: the task or the leader of the threadgroup to be attached
 * @threadgroup: attach the whole threadgroup?
 *
 * Call holding cgroup_mutex and cgroup_threadgroup_rwsem.
 */
int cgroup_attach_task(struct cgroup *dst_cgrp, struct task_struct *leader,
		       bool threadgroup)
{
	DEFINE_CGROUP_MGCTX(mgctx);
	struct task_struct *task;
	int ret;

	ret = cgroup_migrate_vet_dst(dst_cgrp);
	if (ret)
		return ret;

	/* look up all src csets */
	spin_lock_irq(&css_set_lock);
	rcu_read_lock();
	task = leader;
	do {
		cgroup_migrate_add_src(task_css_set(task), dst_cgrp, &mgctx);
		if (!threadgroup)
			break;
	} while_each_thread(leader, task);
	rcu_read_unlock();
	spin_unlock_irq(&css_set_lock);

	/* prepare dst csets and commit */
	ret = cgroup_migrate_prepare_dst(&mgctx);
	if (!ret)
		ret = cgroup_migrate(leader, threadgroup, &mgctx);

	cgroup_migrate_finish(&mgctx);

	if (!ret)
		trace_cgroup_attach_task(dst_cgrp, leader, threadgroup);

	return ret;
}

struct task_struct *cgroup_procs_write_start(char *buf, bool threadgroup)
	__acquires(&cgroup_threadgroup_rwsem)
{
	struct task_struct *tsk;
	pid_t pid;

	if (kstrtoint(strstrip(buf), 0, &pid) || pid < 0)
		return ERR_PTR(-EINVAL);

	percpu_down_write(&cgroup_threadgroup_rwsem);

	rcu_read_lock();
	if (pid) {
		tsk = find_task_by_vpid(pid);
		if (!tsk) {
			tsk = ERR_PTR(-ESRCH);
			goto out_unlock_threadgroup;
		}
	} else {
		tsk = current;
	}

	if (threadgroup)
		tsk = tsk->group_leader;

	/*
	 * kthreads may acquire PF_NO_SETAFFINITY during initialization.
	 * If userland migrates such a kthread to a non-root cgroup, it can
	 * become trapped in a cpuset, or RT kthread may be born in a
	 * cgroup with no rt_runtime allocated.  Just say no.
	 */
	if (tsk->no_cgroup_migration || (tsk->flags & PF_NO_SETAFFINITY)) {
		tsk = ERR_PTR(-EINVAL);
		goto out_unlock_threadgroup;
	}

	get_task_struct(tsk);
	goto out_unlock_rcu;

out_unlock_threadgroup:
	percpu_up_write(&cgroup_threadgroup_rwsem);
out_unlock_rcu:
	rcu_read_unlock();
	return tsk;
}

void cgroup_procs_write_finish(struct task_struct *task)
	__releases(&cgroup_threadgroup_rwsem)
{
	struct cgroup_subsys *ss;
	int ssid;

	/* release reference from cgroup_procs_write_start() */
	put_task_struct(task);

	percpu_up_write(&cgroup_threadgroup_rwsem);
	for_each_subsys(ss, ssid)
		if (ss->post_attach)
			ss->post_attach();
}

static void cgroup_print_ss_mask(struct seq_file *seq, u16 ss_mask)
{
	struct cgroup_subsys *ss;
	bool printed = false;
	int ssid;

	do_each_subsys_mask(ss, ssid, ss_mask) {
		if (printed)
			seq_putc(seq, ' ');
		seq_printf(seq, "%s", ss->name);
		printed = true;
	} while_each_subsys_mask();
	if (printed)
		seq_putc(seq, '\n');
}

/* show controllers which are enabled from the parent */
static int cgroup_controllers_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;

	cgroup_print_ss_mask(seq, cgroup_control(cgrp));
	return 0;
}

/* show controllers which are enabled for a given cgroup's children */
static int cgroup_subtree_control_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;

	cgroup_print_ss_mask(seq, cgrp->subtree_control);
	return 0;
}

/**
 * cgroup_update_dfl_csses - update css assoc of a subtree in default hierarchy
 * @cgrp: root of the subtree to update csses for
 *
 * @cgrp's control masks have changed and its subtree's css associations
 * need to be updated accordingly.  This function looks up all css_sets
 * which are attached to the subtree, creates the matching updated css_sets
 * and migrates the tasks to the new ones.
 */
static int cgroup_update_dfl_csses(struct cgroup *cgrp)
{
	DEFINE_CGROUP_MGCTX(mgctx);
	struct cgroup_subsys_state *d_css;
	struct cgroup *dsct;
	struct css_set *src_cset;
	int ret;

	lockdep_assert_held(&cgroup_mutex);

	percpu_down_write(&cgroup_threadgroup_rwsem);

	/* look up all csses currently attached to @cgrp's subtree */
	spin_lock_irq(&css_set_lock);
	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
		struct cgrp_cset_link *link;

		list_for_each_entry(link, &dsct->cset_links, cset_link)
			cgroup_migrate_add_src(link->cset, dsct, &mgctx);
	}
	spin_unlock_irq(&css_set_lock);

	/* NULL dst indicates self on default hierarchy */
	ret = cgroup_migrate_prepare_dst(&mgctx);
	if (ret)
		goto out_finish;

	spin_lock_irq(&css_set_lock);
	list_for_each_entry(src_cset, &mgctx.preloaded_src_csets, mg_preload_node) {
		struct task_struct *task, *ntask;

		/* all tasks in src_csets need to be migrated */
		list_for_each_entry_safe(task, ntask, &src_cset->tasks, cg_list)
			cgroup_migrate_add_task(task, &mgctx);
	}
	spin_unlock_irq(&css_set_lock);

	ret = cgroup_migrate_execute(&mgctx);
out_finish:
	cgroup_migrate_finish(&mgctx);
	percpu_up_write(&cgroup_threadgroup_rwsem);
	return ret;
}

/**
 * cgroup_lock_and_drain_offline - lock cgroup_mutex and drain offlined csses
 * @cgrp: root of the target subtree
 *
 * Because css offlining is asynchronous, userland may try to re-enable a
 * controller while the previous css is still around.  This function grabs
 * cgroup_mutex and drains the previous css instances of @cgrp's subtree.
 */
void cgroup_lock_and_drain_offline(struct cgroup *cgrp)
	__acquires(&cgroup_mutex)
{
	struct cgroup *dsct;
	struct cgroup_subsys_state *d_css;
	struct cgroup_subsys *ss;
	int ssid;

restart:
	mutex_lock(&cgroup_mutex);

	cgroup_for_each_live_descendant_post(dsct, d_css, cgrp) {
		for_each_subsys(ss, ssid) {
			struct cgroup_subsys_state *css = cgroup_css(dsct, ss);
			DEFINE_WAIT(wait);

			if (!css || !percpu_ref_is_dying(&css->refcnt))
				continue;

			cgroup_get_live(dsct);
			prepare_to_wait(&dsct->offline_waitq, &wait,
					TASK_UNINTERRUPTIBLE);

			mutex_unlock(&cgroup_mutex);
			schedule();
			finish_wait(&dsct->offline_waitq, &wait);

			cgroup_put(dsct);
			goto restart;
		}
	}
}

/**
 * cgroup_save_control - save control masks of a subtree
 * @cgrp: root of the target subtree
 *
 * Save ->subtree_control and ->subtree_ss_mask to the respective old_
 * prefixed fields for @cgrp's subtree including @cgrp itself.
 */
static void cgroup_save_control(struct cgroup *cgrp)
{
	struct cgroup *dsct;
	struct cgroup_subsys_state *d_css;

	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
		dsct->old_subtree_control = dsct->subtree_control;
		dsct->old_subtree_ss_mask = dsct->subtree_ss_mask;
	}
}

/**
 * cgroup_propagate_control - refresh control masks of a subtree
 * @cgrp: root of the target subtree
 *
 * For @cgrp and its subtree, ensure ->subtree_ss_mask matches
 * ->subtree_control and propagate controller availability through the
 * subtree so that descendants don't have unavailable controllers enabled.
 */
static void cgroup_propagate_control(struct cgroup *cgrp)
{
	struct cgroup *dsct;
	struct cgroup_subsys_state *d_css;

	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
		dsct->subtree_control &= cgroup_control(dsct);
		dsct->subtree_ss_mask =
			cgroup_calc_subtree_ss_mask(dsct->subtree_control,
						    cgroup_ss_mask(dsct));
	}
}

/**
 * cgroup_restore_control - restore control masks of a subtree
 * @cgrp: root of the target subtree
 *
 * Restore ->subtree_control and ->subtree_ss_mask from the respective old_
 * prefixed fields for @cgrp's subtree including @cgrp itself.
 */
static void cgroup_restore_control(struct cgroup *cgrp)
{
	struct cgroup *dsct;
	struct cgroup_subsys_state *d_css;

	cgroup_for_each_live_descendant_post(dsct, d_css, cgrp) {
		dsct->subtree_control = dsct->old_subtree_control;
		dsct->subtree_ss_mask = dsct->old_subtree_ss_mask;
	}
}

static bool css_visible(struct cgroup_subsys_state *css)
{
	struct cgroup_subsys *ss = css->ss;
	struct cgroup *cgrp = css->cgroup;

	if (cgroup_control(cgrp) & (1 << ss->id))
		return true;
	if (!(cgroup_ss_mask(cgrp) & (1 << ss->id)))
		return false;
	return cgroup_on_dfl(cgrp) && ss->implicit_on_dfl;
}

/**
 * cgroup_apply_control_enable - enable or show csses according to control
 * @cgrp: root of the target subtree
 *
 * Walk @cgrp's subtree and create new csses or make the existing ones
 * visible.  A css is created invisible if it's being implicitly enabled
 * through dependency.  An invisible css is made visible when the userland
 * explicitly enables it.
 *
 * Returns 0 on success, -errno on failure.  On failure, csses which have
 * been processed already aren't cleaned up.  The caller is responsible for
 * cleaning up with cgroup_apply_control_disable().
 */
static int cgroup_apply_control_enable(struct cgroup *cgrp)
{
	struct cgroup *dsct;
	struct cgroup_subsys_state *d_css;
	struct cgroup_subsys *ss;
	int ssid, ret;

	cgroup_for_each_live_descendant_pre(dsct, d_css, cgrp) {
		for_each_subsys(ss, ssid) {
			struct cgroup_subsys_state *css = cgroup_css(dsct, ss);

			WARN_ON_ONCE(css && percpu_ref_is_dying(&css->refcnt));

			if (!(cgroup_ss_mask(dsct) & (1 << ss->id)))
				continue;

			if (!css) {
				css = css_create(dsct, ss);
				if (IS_ERR(css))
					return PTR_ERR(css);
			}

			if (css_visible(css)) {
				ret = css_populate_dir(css);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

/**
 * cgroup_apply_control_disable - kill or hide csses according to control
 * @cgrp: root of the target subtree
 *
 * Walk @cgrp's subtree and kill and hide csses so that they match
 * cgroup_ss_mask() and cgroup_visible_mask().
 *
 * A css is hidden when the userland requests it to be disabled while other
 * subsystems are still depending on it.  The css must not actively control
 * resources and be in the vanilla state if it's made visible again later.
 * Controllers which may be depended upon should provide ->css_reset() for
 * this purpose.
 */
static void cgroup_apply_control_disable(struct cgroup *cgrp)
{
	struct cgroup *dsct;
	struct cgroup_subsys_state *d_css;
	struct cgroup_subsys *ss;
	int ssid;

	cgroup_for_each_live_descendant_post(dsct, d_css, cgrp) {
		for_each_subsys(ss, ssid) {
			struct cgroup_subsys_state *css = cgroup_css(dsct, ss);

			WARN_ON_ONCE(css && percpu_ref_is_dying(&css->refcnt));

			if (!css)
				continue;

			if (css->parent &&
			    !(cgroup_ss_mask(dsct) & (1 << ss->id))) {
				kill_css(css);
			} else if (!css_visible(css)) {
				css_clear_dir(css);
				if (ss->css_reset)
					ss->css_reset(css);
			}
		}
	}
}

/**
 * cgroup_apply_control - apply control mask updates to the subtree
 * @cgrp: root of the target subtree
 *
 * subsystems can be enabled and disabled in a subtree using the following
 * steps.
 *
 * 1. Call cgroup_save_control() to stash the current state.
 * 2. Update ->subtree_control masks in the subtree as desired.
 * 3. Call cgroup_apply_control() to apply the changes.
 * 4. Optionally perform other related operations.
 * 5. Call cgroup_finalize_control() to finish up.
 *
 * This function implements step 3 and propagates the mask changes
 * throughout @cgrp's subtree, updates csses accordingly and perform
 * process migrations.
 */
static int cgroup_apply_control(struct cgroup *cgrp)
{
	int ret;

	cgroup_propagate_control(cgrp);

	ret = cgroup_apply_control_enable(cgrp);
	if (ret)
		return ret;

	/*
	 * At this point, cgroup_e_css() results reflect the new csses
	 * making the following cgroup_update_dfl_csses() properly update
	 * css associations of all tasks in the subtree.
	 */
	ret = cgroup_update_dfl_csses(cgrp);
	if (ret)
		return ret;

	return 0;
}

/**
 * cgroup_finalize_control - finalize control mask update
 * @cgrp: root of the target subtree
 * @ret: the result of the update
 *
 * Finalize control mask update.  See cgroup_apply_control() for more info.
 */
static void cgroup_finalize_control(struct cgroup *cgrp, int ret)
{
	if (ret) {
		cgroup_restore_control(cgrp);
		cgroup_propagate_control(cgrp);
	}

	cgroup_apply_control_disable(cgrp);
}

static int cgroup_vet_subtree_control_enable(struct cgroup *cgrp, u16 enable)
{
	u16 domain_enable = enable & ~cgrp_dfl_threaded_ss_mask;

	/* if nothing is getting enabled, nothing to worry about */
	if (!enable)
		return 0;

	/* can @cgrp host any resources? */
	if (!cgroup_is_valid_domain(cgrp->dom_cgrp))
		return -EOPNOTSUPP;

	/* mixables don't care */
	if (cgroup_is_mixable(cgrp))
		return 0;

	if (domain_enable) {
		/* can't enable domain controllers inside a thread subtree */
		if (cgroup_is_thread_root(cgrp) || cgroup_is_threaded(cgrp))
			return -EOPNOTSUPP;
	} else {
		/*
		 * Threaded controllers can handle internal competitions
		 * and are always allowed inside a (prospective) thread
		 * subtree.
		 */
		if (cgroup_can_be_thread_root(cgrp) || cgroup_is_threaded(cgrp))
			return 0;
	}

	/*
	 * Controllers can't be enabled for a cgroup with tasks to avoid
	 * child cgroups competing against tasks.
	 */
	if (cgroup_has_tasks(cgrp))
		return -EBUSY;

	return 0;
}

/* change the enabled child controllers for a cgroup in the default hierarchy */
static ssize_t cgroup_subtree_control_write(struct kernfs_open_file *of,
					    char *buf, size_t nbytes,
					    loff_t off)
{
	u16 enable = 0, disable = 0;
	struct cgroup *cgrp, *child;
	struct cgroup_subsys *ss;
	char *tok;
	int ssid, ret;

	/*
	 * Parse input - space separated list of subsystem names prefixed
	 * with either + or -.
	 */
	buf = strstrip(buf);
	while ((tok = strsep(&buf, " "))) {
		if (tok[0] == '\0')
			continue;
		do_each_subsys_mask(ss, ssid, ~cgrp_dfl_inhibit_ss_mask) {
			if (!cgroup_ssid_enabled(ssid) ||
			    strcmp(tok + 1, ss->name))
				continue;

			if (*tok == '+') {
				enable |= 1 << ssid;
				disable &= ~(1 << ssid);
			} else if (*tok == '-') {
				disable |= 1 << ssid;
				enable &= ~(1 << ssid);
			} else {
				return -EINVAL;
			}
			break;
		} while_each_subsys_mask();
		if (ssid == CGROUP_SUBSYS_COUNT)
			return -EINVAL;
	}

	cgrp = cgroup_kn_lock_live(of->kn, true);
	if (!cgrp)
		return -ENODEV;

	for_each_subsys(ss, ssid) {
		if (enable & (1 << ssid)) {
			if (cgrp->subtree_control & (1 << ssid)) {
				enable &= ~(1 << ssid);
				continue;
			}

			if (!(cgroup_control(cgrp) & (1 << ssid))) {
				ret = -ENOENT;
				goto out_unlock;
			}
		} else if (disable & (1 << ssid)) {
			if (!(cgrp->subtree_control & (1 << ssid))) {
				disable &= ~(1 << ssid);
				continue;
			}

			/* a child has it enabled? */
			cgroup_for_each_live_child(child, cgrp) {
				if (child->subtree_control & (1 << ssid)) {
					ret = -EBUSY;
					goto out_unlock;
				}
			}
		}
	}

	if (!enable && !disable) {
		ret = 0;
		goto out_unlock;
	}

	ret = cgroup_vet_subtree_control_enable(cgrp, enable);
	if (ret)
		goto out_unlock;

	/* save and update control masks and prepare csses */
	cgroup_save_control(cgrp);

	cgrp->subtree_control |= enable;
	cgrp->subtree_control &= ~disable;

	ret = cgroup_apply_control(cgrp);
	cgroup_finalize_control(cgrp, ret);
	if (ret)
		goto out_unlock;

	kernfs_activate(cgrp->kn);
out_unlock:
	cgroup_kn_unlock(of->kn);
	return ret ?: nbytes;
}

/**
 * cgroup_enable_threaded - make @cgrp threaded
 * @cgrp: the target cgroup
 *
 * Called when "threaded" is written to the cgroup.type interface file and
 * tries to make @cgrp threaded and join the parent's resource domain.
 * This function is never called on the root cgroup as cgroup.type doesn't
 * exist on it.
 */
static int cgroup_enable_threaded(struct cgroup *cgrp)
{
	struct cgroup *parent = cgroup_parent(cgrp);
	struct cgroup *dom_cgrp = parent->dom_cgrp;
	int ret;

	lockdep_assert_held(&cgroup_mutex);

	/* noop if already threaded */
	if (cgroup_is_threaded(cgrp))
		return 0;

	/*
	 * If @cgroup is populated or has domain controllers enabled, it
	 * can't be switched.  While the below cgroup_can_be_thread_root()
	 * test can catch the same conditions, that's only when @parent is
	 * not mixable, so let's check it explicitly.
	 */
	if (cgroup_is_populated(cgrp) ||
	    cgrp->subtree_control & ~cgrp_dfl_threaded_ss_mask)
		return -EOPNOTSUPP;

	/* we're joining the parent's domain, ensure its validity */
	if (!cgroup_is_valid_domain(dom_cgrp) ||
	    !cgroup_can_be_thread_root(dom_cgrp))
		return -EOPNOTSUPP;

	/*
	 * The following shouldn't cause actual migrations and should
	 * always succeed.
	 */
	cgroup_save_control(cgrp);

	cgrp->dom_cgrp = dom_cgrp;
	ret = cgroup_apply_control(cgrp);
	if (!ret)
		parent->nr_threaded_children++;
	else
		cgrp->dom_cgrp = cgrp;

	cgroup_finalize_control(cgrp, ret);
	return ret;
}

static int cgroup_type_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;

	if (cgroup_is_threaded(cgrp))
		seq_puts(seq, "threaded\n");
	else if (!cgroup_is_valid_domain(cgrp))
		seq_puts(seq, "domain invalid\n");
	else if (cgroup_is_thread_root(cgrp))
		seq_puts(seq, "domain threaded\n");
	else
		seq_puts(seq, "domain\n");

	return 0;
}

static ssize_t cgroup_type_write(struct kernfs_open_file *of, char *buf,
				 size_t nbytes, loff_t off)
{
	struct cgroup *cgrp;
	int ret;

	/* only switching to threaded mode is supported */
	if (strcmp(strstrip(buf), "threaded"))
		return -EINVAL;

	cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!cgrp)
		return -ENOENT;

	/* threaded can only be enabled */
	ret = cgroup_enable_threaded(cgrp);

	cgroup_kn_unlock(of->kn);
	return ret ?: nbytes;
}

static int cgroup_max_descendants_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;
	int descendants = READ_ONCE(cgrp->max_descendants);

	if (descendants == INT_MAX)
		seq_puts(seq, "max\n");
	else
		seq_printf(seq, "%d\n", descendants);

	return 0;
}

static ssize_t cgroup_max_descendants_write(struct kernfs_open_file *of,
					   char *buf, size_t nbytes, loff_t off)
{
	struct cgroup *cgrp;
	int descendants;
	ssize_t ret;

	buf = strstrip(buf);
	if (!strcmp(buf, "max")) {
		descendants = INT_MAX;
	} else {
		ret = kstrtoint(buf, 0, &descendants);
		if (ret)
			return ret;
	}

	if (descendants < 0)
		return -ERANGE;

	cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!cgrp)
		return -ENOENT;

	cgrp->max_descendants = descendants;

	cgroup_kn_unlock(of->kn);

	return nbytes;
}

static int cgroup_max_depth_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgrp = seq_css(seq)->cgroup;
	int depth = READ_ONCE(cgrp->max_depth);

	if (depth == INT_MAX)
		seq_puts(seq, "max\n");
	else
		seq_printf(seq, "%d\n", depth);

	return 0;
}

static ssize_t cgroup_max_depth_write(struct kernfs_open_file *of,
				      char *buf, size_t nbytes, loff_t off)
{
	struct cgroup *cgrp;
	ssize_t ret;
	int depth;

	buf = strstrip(buf);
	if (!strcmp(buf, "max")) {
		depth = INT_MAX;
	} else {
		ret = kstrtoint(buf, 0, &depth);
		if (ret)
			return ret;
	}

	if (depth < 0)
		return -ERANGE;

	cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!cgrp)
		return -ENOENT;

	cgrp->max_depth = depth;

	cgroup_kn_unlock(of->kn);

	return nbytes;
}

static int cgroup_events_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "populated %d\n",
		   cgroup_is_populated(seq_css(seq)->cgroup));
	return 0;
}

static int cgroup_stat_show(struct seq_file *seq, void *v)
{
	struct cgroup *cgroup = seq_css(seq)->cgroup;

	seq_printf(seq, "nr_descendants %d\n",
		   cgroup->nr_descendants);
	seq_printf(seq, "nr_dying_descendants %d\n",
		   cgroup->nr_dying_descendants);

	return 0;
}

static int cgroup_file_open(struct kernfs_open_file *of)
{
	struct cftype *cft = of->kn->priv;

	if (cft->open)
		return cft->open(of);
	return 0;
}

static void cgroup_file_release(struct kernfs_open_file *of)
{
	struct cftype *cft = of->kn->priv;

	if (cft->release)
		cft->release(of);
}

static ssize_t cgroup_file_write(struct kernfs_open_file *of, char *buf,
				 size_t nbytes, loff_t off)
{
	struct cgroup_namespace *ns = current->nsproxy->cgroup_ns;
	struct cgroup *cgrp = of->kn->parent->priv;
	struct cftype *cft = of->kn->priv;
	struct cgroup_subsys_state *css;
	int ret;

	/*
	 * If namespaces are delegation boundaries, disallow writes to
	 * files in an non-init namespace root from inside the namespace
	 * except for the files explicitly marked delegatable -
	 * cgroup.procs and cgroup.subtree_control.
	 */
	if ((cgrp->root->flags & CGRP_ROOT_NS_DELEGATE) &&
	    !(cft->flags & CFTYPE_NS_DELEGATABLE) &&
	    ns != &init_cgroup_ns && ns->root_cset->dfl_cgrp == cgrp)
		return -EPERM;

	if (cft->write)
		return cft->write(of, buf, nbytes, off);

	/*
	 * kernfs guarantees that a file isn't deleted with operations in
	 * flight, which means that the matching css is and stays alive and
	 * doesn't need to be pinned.  The RCU locking is not necessary
	 * either.  It's just for the convenience of using cgroup_css().
	 */
	rcu_read_lock();
	css = cgroup_css(cgrp, cft->ss);
	rcu_read_unlock();

	if (cft->write_u64) {
		unsigned long long v;
		ret = kstrtoull(buf, 0, &v);
		if (!ret)
			ret = cft->write_u64(css, cft, v);
	} else if (cft->write_s64) {
		long long v;
		ret = kstrtoll(buf, 0, &v);
		if (!ret)
			ret = cft->write_s64(css, cft, v);
	} else {
		ret = -EINVAL;
	}

	return ret ?: nbytes;
}

static void *cgroup_seqfile_start(struct seq_file *seq, loff_t *ppos)
{
	return seq_cft(seq)->seq_start(seq, ppos);
}

static void *cgroup_seqfile_next(struct seq_file *seq, void *v, loff_t *ppos)
{
	return seq_cft(seq)->seq_next(seq, v, ppos);
}

static void cgroup_seqfile_stop(struct seq_file *seq, void *v)
{
	if (seq_cft(seq)->seq_stop)
		seq_cft(seq)->seq_stop(seq, v);
}

static int cgroup_seqfile_show(struct seq_file *m, void *arg)
{
	struct cgroup_seqfile_state *state = m->private;
	struct cftype *cft = state->cft;
	if (cft->read_map) {
		struct cgroup_map_cb cb = {
			.fill = cgroup_map_add,
			.state = m,
		};
		return cft->read_map(state->cgroup, cft, &cb);
	}
	return cft->read_seq_string(state->cgroup, cft, m);
}

static int cgroup_seqfile_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	kfree(seq->private);
	return single_release(inode, file);
}

static struct file_operations cgroup_seqfile_operations = {
	.read = seq_read,
	.write = cgroup_file_write,
	.llseek = seq_lseek,
	.release = cgroup_seqfile_release,
};

static int cgroup_file_open(struct inode *inode, struct file *file)
{
	int err;
	struct cftype *cft;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	cft = __d_cft(file->f_dentry);
	if (!cft)
		return -ENODEV;
	if (cft->read_map || cft->read_seq_string) {
		struct cgroup_seqfile_state *state =
			kzalloc(sizeof(*state), GFP_USER);
		if (!state)
			return -ENOMEM;
		state->cft = cft;
		state->cgroup = __d_cgrp(file->f_dentry->d_parent);
		file->f_op = &cgroup_seqfile_operations;
		err = single_open(file, cgroup_seqfile_show, state);
		if (err < 0)
			kfree(state);
	} else if (cft->open)
		err = cft->open(inode, file);
	else
		err = 0;

	return err;
}

static int cgroup_file_release(struct inode *inode, struct file *file)
{
	struct cftype *cft = __d_cft(file->f_dentry);
	if (cft->release)
		return cft->release(inode, file);
	return 0;
}

/*
 * cgroup_rename - Only allow simple rename of directories in place.
 */
static int cgroup_rename(struct inode *old_dir, struct dentry *old_dentry,
			    struct inode *new_dir, struct dentry *new_dentry)
{
	if (!S_ISDIR(old_dentry->d_inode->i_mode))
		return -ENOTDIR;
	if (new_dentry->d_inode)
		return -EEXIST;
	if (old_dir != new_dir)
		return -EIO;
	return simple_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static struct file_operations cgroup_file_operations = {
	.read = cgroup_file_read,
	.write = cgroup_file_write,
	.llseek = generic_file_llseek,
	.open = cgroup_file_open,
	.release = cgroup_file_release,
};

static struct inode_operations cgroup_dir_inode_operations = {
	.lookup = simple_lookup,
	.mkdir = cgroup_mkdir,
	.rmdir = cgroup_rmdir,
	.rename = cgroup_rename,
};

static int cgroup_create_file(struct dentry *dentry, int mode,
				struct super_block *sb)
{
	static struct dentry_operations cgroup_dops = {
		.d_iput = cgroup_diput,
	};

	struct inode *inode;

	if (!dentry)
		return -ENOENT;
	if (dentry->d_inode)
		return -EEXIST;

	inode = cgroup_new_inode(mode, sb);
	if (!inode)
		return -ENOMEM;

	if (S_ISDIR(mode)) {
		inode->i_op = &cgroup_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;

		/* start off with i_nlink == 2 (for "." entry) */
		inc_nlink(inode);

		/* start with the directory inode held, so that we can
		 * populate it without racing with another mkdir */
		mutex_lock_nested(&inode->i_mutex, I_MUTEX_CHILD);
	} else if (S_ISREG(mode)) {
		inode->i_size = 0;
		inode->i_fop = &cgroup_file_operations;
	}
	dentry->d_op = &cgroup_dops;
	d_instantiate(dentry, inode);
	dget(dentry);	/* Extra count - pin the dentry in core */
	return 0;
}

/*
 * cgroup_create_dir - create a directory for an object.
 * @cgrp: the cgroup we create the directory for. It must have a valid
 *        ->parent field. And we are going to fill its ->dentry field.
 * @dentry: dentry of the new cgroup
 * @mode: mode to set on new directory.
 */
static int cgroup_create_dir(struct cgroup *cgrp, struct dentry *dentry,
				int mode)
{
	struct dentry *parent;
	int error = 0;

	parent = cgrp->parent->dentry;
	error = cgroup_create_file(dentry, S_IFDIR | mode, cgrp->root->sb);
	if (!error) {
		dentry->d_fsdata = cgrp;
		inc_nlink(parent->d_inode);
		cgrp->dentry = dentry;
		dget(dentry);
	}
	dput(dentry);

	return error;
}

int cgroup_add_file(struct cgroup *cgrp,
		       struct cgroup_subsys *subsys,
		       const struct cftype *cft)
{
	struct dentry *dir = cgrp->dentry;
	struct dentry *dentry;
	int error;

	char name[MAX_CGROUP_TYPE_NAMELEN + MAX_CFTYPE_NAME + 2] = { 0 };
	if (subsys && !test_bit(ROOT_NOPREFIX, &cgrp->root->flags)) {
		strcpy(name, subsys->name);
		strcat(name, ".");
	}
	strcat(name, cft->name);
	BUG_ON(!mutex_is_locked(&dir->d_inode->i_mutex));
	dentry = lookup_one_len(name, dir, strlen(name));
	if (!IS_ERR(dentry)) {
		error = cgroup_create_file(dentry, 0644 | S_IFREG,
						cgrp->root->sb);
		if (!error)
			dentry->d_fsdata = (void *)cft;
		dput(dentry);
	} else
		error = PTR_ERR(dentry);
	return error;
}

int cgroup_add_files(struct cgroup *cgrp,
			struct cgroup_subsys *subsys,
			const struct cftype cft[],
			int count)
{
	int i, err;
	for (i = 0; i < count; i++) {
		err = cgroup_add_file(cgrp, subsys, &cft[i]);
		if (err)
			return err;
	struct cftype *cft = seq_cft(m);
	struct cgroup_subsys_state *css = seq_css(m);

	if (cft->seq_show)
		return cft->seq_show(m, arg);

	if (cft->read_u64)
		seq_printf(m, "%llu\n", cft->read_u64(css, cft));
	else if (cft->read_s64)
		seq_printf(m, "%lld\n", cft->read_s64(css, cft));
	else
		return -EINVAL;
	return 0;
}

static struct kernfs_ops cgroup_kf_single_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.open			= cgroup_file_open,
	.release		= cgroup_file_release,
	.write			= cgroup_file_write,
	.seq_show		= cgroup_seqfile_show,
};

static struct kernfs_ops cgroup_kf_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.open			= cgroup_file_open,
	.release		= cgroup_file_release,
	.write			= cgroup_file_write,
	.seq_start		= cgroup_seqfile_start,
	.seq_next		= cgroup_seqfile_next,
	.seq_stop		= cgroup_seqfile_stop,
	.seq_show		= cgroup_seqfile_show,
};

/* set uid and gid of cgroup dirs and files to that of the creator */
static int cgroup_kn_set_ugid(struct kernfs_node *kn)
{
	struct iattr iattr = { .ia_valid = ATTR_UID | ATTR_GID,
			       .ia_uid = current_fsuid(),
			       .ia_gid = current_fsgid(), };

	if (uid_eq(iattr.ia_uid, GLOBAL_ROOT_UID) &&
	    gid_eq(iattr.ia_gid, GLOBAL_ROOT_GID))
		return 0;

	return kernfs_setattr(kn, &iattr);
}

static int cgroup_add_file(struct cgroup_subsys_state *css, struct cgroup *cgrp,
			   struct cftype *cft)
{
	char name[CGROUP_FILE_NAME_MAX];
	struct kernfs_node *kn;
	struct lock_class_key *key = NULL;
	int ret;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	key = &cft->lockdep_key;
#endif
	kn = __kernfs_create_file(cgrp->kn, cgroup_file_name(cgrp, cft, name),
				  cgroup_file_mode(cft), 0, cft->kf_ops, cft,
				  NULL, key);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = cgroup_kn_set_ugid(kn);
	if (ret) {
		kernfs_remove(kn);
		return ret;
	}

	if (cft->file_offset) {
		struct cgroup_file *cfile = (void *)css + cft->file_offset;

		spin_lock_irq(&cgroup_file_kn_lock);
		cfile->kn = kn;
		spin_unlock_irq(&cgroup_file_kn_lock);
	}

	return 0;
}

/**
 * cgroup_addrm_files - add or remove files to a cgroup directory
 * @css: the target css
 * @cgrp: the target cgroup (usually css->cgroup)
 * @cfts: array of cftypes to be added
 * @is_add: whether to add or remove
 *
 * Depending on @is_add, add or remove files defined by @cfts on @cgrp.
 * For removals, this function never fails.
 */
static int cgroup_addrm_files(struct cgroup_subsys_state *css,
			      struct cgroup *cgrp, struct cftype cfts[],
			      bool is_add)
{
	struct cftype *cft, *cft_end = NULL;
	int ret = 0;

	lockdep_assert_held(&cgroup_mutex);

restart:
	for (cft = cfts; cft != cft_end && cft->name[0] != '\0'; cft++) {
		/* does cft->flags tell us to skip this file on @cgrp? */
		if ((cft->flags & __CFTYPE_ONLY_ON_DFL) && !cgroup_on_dfl(cgrp))
			continue;
		if ((cft->flags & __CFTYPE_NOT_ON_DFL) && cgroup_on_dfl(cgrp))
			continue;
		if ((cft->flags & CFTYPE_NOT_ON_ROOT) && !cgroup_parent(cgrp))
			continue;
		if ((cft->flags & CFTYPE_ONLY_ON_ROOT) && cgroup_parent(cgrp))
			continue;

		if (is_add) {
			ret = cgroup_add_file(css, cgrp, cft);
			if (ret) {
				pr_warn("%s: failed to add %s, err=%d\n",
					__func__, cft->name, ret);
				cft_end = cft;
				is_add = false;
				goto restart;
			}
		} else {
			cgroup_rm_file(cgrp, cft);
		}
	}
	return ret;
}

static int cgroup_apply_cftypes(struct cftype *cfts, bool is_add)
{
	struct cgroup_subsys *ss = cfts[0].ss;
	struct cgroup *root = &ss->root->cgrp;
	struct cgroup_subsys_state *css;
	int ret = 0;

	lockdep_assert_held(&cgroup_mutex);

	/* add/rm files for all cgroups created before */
	css_for_each_descendant_pre(css, cgroup_css(root, ss)) {
		struct cgroup *cgrp = css->cgroup;

		if (!(css->flags & CSS_VISIBLE))
			continue;

		ret = cgroup_addrm_files(css, cgrp, cfts, is_add);
		if (ret)
			break;
	}

	if (is_add && !ret)
		kernfs_activate(root->kn);
	return ret;
}

static void cgroup_exit_cftypes(struct cftype *cfts)
{
	struct cftype *cft;

	for (cft = cfts; cft->name[0] != '\0'; cft++) {
		/* free copy for custom atomic_write_len, see init_cftypes() */
		if (cft->max_write_len && cft->max_write_len != PAGE_SIZE)
			kfree(cft->kf_ops);
		cft->kf_ops = NULL;
		cft->ss = NULL;

		/* revert flags set by cgroup core while adding @cfts */
		cft->flags &= ~(__CFTYPE_ONLY_ON_DFL | __CFTYPE_NOT_ON_DFL);
	}
}

static int cgroup_init_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
{
	struct cftype *cft;

	for (cft = cfts; cft->name[0] != '\0'; cft++) {
		struct kernfs_ops *kf_ops;

		WARN_ON(cft->ss || cft->kf_ops);

		if (cft->seq_start)
			kf_ops = &cgroup_kf_ops;
		else
			kf_ops = &cgroup_kf_single_ops;

		/*
		 * Ugh... if @cft wants a custom max_write_len, we need to
		 * make a copy of kf_ops to set its atomic_write_len.
		 */
		if (cft->max_write_len && cft->max_write_len != PAGE_SIZE) {
			kf_ops = kmemdup(kf_ops, sizeof(*kf_ops), GFP_KERNEL);
			if (!kf_ops) {
				cgroup_exit_cftypes(cfts);
				return -ENOMEM;
			}
			kf_ops->atomic_write_len = cft->max_write_len;
		}

		cft->kf_ops = kf_ops;
		cft->ss = ss;
	}

	return 0;
}

static int cgroup_rm_cftypes_locked(struct cftype *cfts)
{
	lockdep_assert_held(&cgroup_mutex);

	if (!cfts || !cfts[0].ss)
		return -ENOENT;

	list_del(&cfts->node);
	cgroup_apply_cftypes(cfts, false);
	cgroup_exit_cftypes(cfts);
	return 0;
}

/**
 * cgroup_rm_cftypes - remove an array of cftypes from a subsystem
 * @cfts: zero-length name terminated array of cftypes
 *
 * Unregister @cfts.  Files described by @cfts are removed from all
 * existing cgroups and all future cgroups won't have them either.  This
 * function can be called anytime whether @cfts' subsys is attached or not.
 *
 * Returns 0 on successful unregistration, -ENOENT if @cfts is not
 * registered.
 */
int cgroup_rm_cftypes(struct cftype *cfts)
{
	int ret;

	mutex_lock(&cgroup_mutex);
	ret = cgroup_rm_cftypes_locked(cfts);
	mutex_unlock(&cgroup_mutex);
	return ret;
}

/**
 * cgroup_add_cftypes - add an array of cftypes to a subsystem
 * @ss: target cgroup subsystem
 * @cfts: zero-length name terminated array of cftypes
 *
 * Register @cfts to @ss.  Files described by @cfts are created for all
 * existing cgroups to which @ss is attached and all future cgroups will
 * have them too.  This function can be called anytime whether @ss is
 * attached or not.
 *
 * Returns 0 on successful registration, -errno on failure.  Note that this
 * function currently returns 0 as long as @cfts registration is successful
 * even if some file creation attempts on existing cgroups fail.
 */
static int cgroup_add_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
{
	int ret;

	if (!cgroup_ssid_enabled(ss->id))
		return 0;

	if (!cfts || cfts[0].name[0] == '\0')
		return 0;

	ret = cgroup_init_cftypes(ss, cfts);
	if (ret)
		return ret;

	mutex_lock(&cgroup_mutex);

	list_add_tail(&cfts->node, &ss->cfts);
	ret = cgroup_apply_cftypes(cfts, true);
	if (ret)
		cgroup_rm_cftypes_locked(cfts);

	mutex_unlock(&cgroup_mutex);
	return ret;
}

/**
 * cgroup_add_dfl_cftypes - add an array of cftypes for default hierarchy
 * @ss: target cgroup subsystem
 * @cfts: zero-length name terminated array of cftypes
 *
 * Similar to cgroup_add_cftypes() but the added files are only used for
 * the default hierarchy.
 */
int cgroup_add_dfl_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
{
	struct cftype *cft;

	for (cft = cfts; cft && cft->name[0] != '\0'; cft++)
		cft->flags |= __CFTYPE_ONLY_ON_DFL;
	return cgroup_add_cftypes(ss, cfts);
}

/**
 * cgroup_add_legacy_cftypes - add an array of cftypes for legacy hierarchies
 * @ss: target cgroup subsystem
 * @cfts: zero-length name terminated array of cftypes
 *
 * Similar to cgroup_add_cftypes() but the added files are only used for
 * the legacy hierarchies.
 */
int cgroup_add_legacy_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
{
	struct cftype *cft;

	for (cft = cfts; cft && cft->name[0] != '\0'; cft++)
		cft->flags |= __CFTYPE_NOT_ON_DFL;
	return cgroup_add_cftypes(ss, cfts);
}

/**
 * cgroup_file_notify - generate a file modified event for a cgroup_file
 * @cfile: target cgroup_file
 *
 * @cfile must have been obtained by setting cftype->file_offset.
 */
void cgroup_file_notify(struct cgroup_file *cfile)
{
	unsigned long flags;

	spin_lock_irqsave(&cgroup_file_kn_lock, flags);
	if (cfile->kn)
		kernfs_notify(cfile->kn);
	spin_unlock_irqrestore(&cgroup_file_kn_lock, flags);
}

/**
 * cgroup_task_count - count the number of tasks in a cgroup.
 * @cgrp: the cgroup in question
 *
 * Return the number of tasks in the cgroup.
 */
int cgroup_task_count(const struct cgroup *cgrp)
{
	int count = 0;
	struct cg_cgroup_link *link;

	read_lock(&css_set_lock);
	list_for_each_entry(link, &cgrp->css_sets, cgrp_link_list) {
		count += atomic_read(&link->cg->ref.refcount);
	}
	read_unlock(&css_set_lock);
	return count;
}

/*
 * Advance a list_head iterator.  The iterator should be positioned at
 * the start of a css_set
 */
static void cgroup_advance_iter(struct cgroup *cgrp,
					  struct cgroup_iter *it)
{
	struct list_head *l = it->cg_link;
	struct cg_cgroup_link *link;
	struct css_set *cg;
static int cgroup_task_count(const struct cgroup *cgrp)
{
	int count = 0;
	struct cgrp_cset_link *link;

	spin_lock_bh(&css_set_lock);
	list_for_each_entry(link, &cgrp->cset_links, cset_link)
		count += atomic_read(&link->cset->refcount);
	spin_unlock_bh(&css_set_lock);
	return count;
}

/**
 * css_next_child - find the next child of a given css
 * @pos: the current position (%NULL to initiate traversal)
 * @parent: css whose children to walk
 *
 * This function returns the next child of @parent and should be called
 * under either cgroup_mutex or RCU read lock.  The only requirement is
 * that @parent and @pos are accessible.  The next sibling is guaranteed to
 * be returned regardless of their states.
 *
 * If a subsystem synchronizes ->css_online() and the start of iteration, a
 * css which finished ->css_online() is guaranteed to be visible in the
 * future iterations and will stay visible until the last reference is put.
 * A css which hasn't finished ->css_online() or already finished
 * ->css_offline() may show up during traversal.  It's each subsystem's
 * responsibility to synchronize against on/offlining.
 */
struct cgroup_subsys_state *css_next_child(struct cgroup_subsys_state *pos,
					   struct cgroup_subsys_state *parent)
{
	struct cgroup_subsys_state *next;

	cgroup_assert_mutex_or_rcu_locked();

	/*
	 * @pos could already have been unlinked from the sibling list.
	 * Once a cgroup is removed, its ->sibling.next is no longer
	 * updated when its next sibling changes.  CSS_RELEASED is set when
	 * @pos is taken off list, at which time its next pointer is valid,
	 * and, as releases are serialized, the one pointed to by the next
	 * pointer is guaranteed to not have started release yet.  This
	 * implies that if we observe !CSS_RELEASED on @pos in this RCU
	 * critical section, the one pointed to by its next pointer is
	 * guaranteed to not have finished its RCU grace period even if we
	 * have dropped rcu_read_lock() inbetween iterations.
	 *
	 * If @pos has CSS_RELEASED set, its next pointer can't be
	 * dereferenced; however, as each css is given a monotonically
	 * increasing unique serial number and always appended to the
	 * sibling list, the next one can be found by walking the parent's
	 * children until the first css with higher serial number than
	 * @pos's.  While this path can be slower, it happens iff iteration
	 * races against release and the race window is very small.
	 */
	if (!pos) {
		next = list_entry_rcu(parent->children.next, struct cgroup_subsys_state, sibling);
	} else if (likely(!(pos->flags & CSS_RELEASED))) {
		next = list_entry_rcu(pos->sibling.next, struct cgroup_subsys_state, sibling);
	} else {
		list_for_each_entry_rcu(next, &parent->children, sibling)
			if (next->serial_nr > pos->serial_nr)
				break;
	}

	/*
	 * @next, if not pointing to the head, can be dereferenced and is
	 * the next sibling.
	 */
	if (&next->sibling != &parent->children)
		return next;
	return NULL;
}

/**
 * css_next_descendant_pre - find the next descendant for pre-order walk
 * @pos: the current position (%NULL to initiate traversal)
 * @root: css whose descendants to walk
 *
 * To be used by css_for_each_descendant_pre().  Find the next descendant
 * to visit for pre-order traversal of @root's descendants.  @root is
 * included in the iteration and the first node to be visited.
 *
 * While this function requires cgroup_mutex or RCU read locking, it
 * doesn't require the whole traversal to be contained in a single critical
 * section.  This function will return the correct next descendant as long
 * as both @pos and @root are accessible and @pos is a descendant of @root.
 *
 * If a subsystem synchronizes ->css_online() and the start of iteration, a
 * css which finished ->css_online() is guaranteed to be visible in the
 * future iterations and will stay visible until the last reference is put.
 * A css which hasn't finished ->css_online() or already finished
 * ->css_offline() may show up during traversal.  It's each subsystem's
 * responsibility to synchronize against on/offlining.
 */
struct cgroup_subsys_state *
css_next_descendant_pre(struct cgroup_subsys_state *pos,
			struct cgroup_subsys_state *root)
{
	struct cgroup_subsys_state *next;

	cgroup_assert_mutex_or_rcu_locked();

	/* if first iteration, visit @root */
	if (!pos)
		return root;

	/* visit the first child if exists */
	next = css_next_child(NULL, pos);
	if (next)
		return next;

	/* no child, visit my or the closest ancestor's next sibling */
	while (pos != root) {
		next = css_next_child(pos, pos->parent);
		if (next)
			return next;
		pos = pos->parent;
	}

	return NULL;
}

/**
 * css_rightmost_descendant - return the rightmost descendant of a css
 * @pos: css of interest
 *
 * Return the rightmost descendant of @pos.  If there's no descendant, @pos
 * is returned.  This can be used during pre-order traversal to skip
 * subtree of @pos.
 *
 * While this function requires cgroup_mutex or RCU read locking, it
 * doesn't require the whole traversal to be contained in a single critical
 * section.  This function will return the correct rightmost descendant as
 * long as @pos is accessible.
 */
struct cgroup_subsys_state *
css_rightmost_descendant(struct cgroup_subsys_state *pos)
{
	struct cgroup_subsys_state *last, *tmp;

	cgroup_assert_mutex_or_rcu_locked();

	do {
		last = pos;
		/* ->prev isn't RCU safe, walk ->next till the end */
		pos = NULL;
		css_for_each_child(tmp, last)
			pos = tmp;
	} while (pos);

	return last;
}

static struct cgroup_subsys_state *
css_leftmost_descendant(struct cgroup_subsys_state *pos)
{
	struct cgroup_subsys_state *last;

	do {
		last = pos;
		pos = css_next_child(NULL, pos);
	} while (pos);

	return last;
}

/**
 * css_next_descendant_post - find the next descendant for post-order walk
 * @pos: the current position (%NULL to initiate traversal)
 * @root: css whose descendants to walk
 *
 * To be used by css_for_each_descendant_post().  Find the next descendant
 * to visit for post-order traversal of @root's descendants.  @root is
 * included in the iteration and the last node to be visited.
 *
 * While this function requires cgroup_mutex or RCU read locking, it
 * doesn't require the whole traversal to be contained in a single critical
 * section.  This function will return the correct next descendant as long
 * as both @pos and @cgroup are accessible and @pos is a descendant of
 * @cgroup.
 *
 * If a subsystem synchronizes ->css_online() and the start of iteration, a
 * css which finished ->css_online() is guaranteed to be visible in the
 * future iterations and will stay visible until the last reference is put.
 * A css which hasn't finished ->css_online() or already finished
 * ->css_offline() may show up during traversal.  It's each subsystem's
 * responsibility to synchronize against on/offlining.
 */
struct cgroup_subsys_state *
css_next_descendant_post(struct cgroup_subsys_state *pos,
			 struct cgroup_subsys_state *root)
{
	struct cgroup_subsys_state *next;

	cgroup_assert_mutex_or_rcu_locked();

	/* if first iteration, visit leftmost descendant which may be @root */
	if (!pos)
		return css_leftmost_descendant(root);

	/* if we visited @root, we're done */
	if (pos == root)
		return NULL;

	/* if there's an unvisited sibling, visit its leftmost descendant */
	next = css_next_child(pos, pos->parent);
	if (next)
		return css_leftmost_descendant(next);

	/* no sibling left, visit parent */
	return pos->parent;
}

/**
 * css_has_online_children - does a css have online children
 * @css: the target css
 *
 * Returns %true if @css has any online children; otherwise, %false.  This
 * function can be called from any context but the caller is responsible
 * for synchronizing against on/offlining as necessary.
 */
bool css_has_online_children(struct cgroup_subsys_state *css)
{
	struct cgroup_subsys_state *child;
	bool ret = false;

	rcu_read_lock();
	css_for_each_child(child, css) {
		if (child->flags & CSS_ONLINE) {
			ret = true;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

static struct css_set *css_task_iter_next_css_set(struct css_task_iter *it)
{
	struct list_head *l;
	struct cgrp_cset_link *link;
	struct css_set *cset;

	lockdep_assert_held(&css_set_lock);

	/* find the next threaded cset */
	if (it->tcset_pos) {
		l = it->tcset_pos->next;

		if (l != it->tcset_head) {
			it->tcset_pos = l;
			return container_of(l, struct css_set,
					    threaded_csets_node);
		}

		it->tcset_pos = NULL;
	}

	/* find the next cset */
	l = it->cset_pos;
	l = l->next;
	if (l == it->cset_head) {
		it->cset_pos = NULL;
		return NULL;
	}

	if (it->ss) {
		cset = container_of(l, struct css_set, e_cset_node[it->ss->id]);
	} else {
		link = list_entry(l, struct cgrp_cset_link, cset_link);
		cset = link->cset;
	}

	it->cset_pos = l;

	/* initialize threaded css_set walking */
	if (it->flags & CSS_TASK_ITER_THREADED) {
		if (it->cur_dcset)
			put_css_set_locked(it->cur_dcset);
		it->cur_dcset = cset;
		get_css_set(cset);

		it->tcset_head = &cset->threaded_csets;
		it->tcset_pos = &cset->threaded_csets;
	}

	return cset;
}

/**
 * css_task_iter_advance_css_set - advance a task itererator to the next css_set
 * @it: the iterator to advance
 *
 * Advance @it to the next css_set to walk.
 */
static void css_task_iter_advance_css_set(struct css_task_iter *it)
{
	struct css_set *cset;

	lockdep_assert_held(&css_set_lock);

	/* Advance to the next non-empty css_set */
	do {
		l = l->next;
		if (l == &cgrp->css_sets) {
			it->cg_link = NULL;
			return;
		}
		link = list_entry(l, struct cg_cgroup_link, cgrp_link_list);
		cg = link->cg;
	} while (list_empty(&cg->tasks));
	it->cg_link = l;
	it->task = cg->tasks.next;
}

/*
 * To reduce the fork() overhead for systems that are not actually
 * using their cgroups capability, we don't maintain the lists running
 * through each css_set to its tasks until we see the list actually
 * used - in other words after the first call to cgroup_iter_start().
 *
 * The tasklist_lock is not held here, as do_each_thread() and
 * while_each_thread() are protected by RCU.
 */
static void cgroup_enable_task_cg_lists(void)
{
	struct task_struct *p, *g;
	write_lock(&css_set_lock);
	use_task_css_set_links = 1;
	do_each_thread(g, p) {
		task_lock(p);
		/*
		 * We should check if the process is exiting, otherwise
		 * it will race with cgroup_exit() in that the list
		 * entry won't be deleted though the process has exited.
		 */
		if (!(p->flags & PF_EXITING) && list_empty(&p->cg_list))
			list_add(&p->cg_list, &p->cgroups->tasks);
		task_unlock(p);
	} while_each_thread(g, p);
	write_unlock(&css_set_lock);
}

void cgroup_iter_start(struct cgroup *cgrp, struct cgroup_iter *it)
{
	/*
	 * The first time anyone tries to iterate across a cgroup,
	 * we need to enable the list linking each css_set to its
	 * tasks, and fix up all existing tasks.
	 */
	if (!use_task_css_set_links)
		cgroup_enable_task_cg_lists();

	read_lock(&css_set_lock);
	it->cg_link = &cgrp->css_sets;
	cgroup_advance_iter(cgrp, it);
}

struct task_struct *cgroup_iter_next(struct cgroup *cgrp,
					struct cgroup_iter *it)
{
	struct task_struct *res;
	struct list_head *l = it->task;

	/* If the iterator cg is NULL, we have no tasks */
	if (!it->cg_link)
		return NULL;
	res = list_entry(l, struct task_struct, cg_list);
	/* Advance iterator to find next entry */
	l = l->next;
	if (l == &res->cgroups->tasks) {
		/* We reached the end of this task list - move on to
		 * the next cg_cgroup_link */
		cgroup_advance_iter(cgrp, it);
	} else {
		it->task = l;
	}
	return res;
}

void cgroup_iter_end(struct cgroup *cgrp, struct cgroup_iter *it)
{
	read_unlock(&css_set_lock);
}

static inline int started_after_time(struct task_struct *t1,
				     struct timespec *time,
				     struct task_struct *t2)
{
	int start_diff = timespec_compare(&t1->start_time, time);
	if (start_diff > 0) {
		return 1;
	} else if (start_diff < 0) {
		return 0;
	} else {
		/*
		 * Arbitrarily, if two processes started at the same
		 * time, we'll say that the lower pointer value
		 * started first. Note that t2 may have exited by now
		 * so this may not be a valid pointer any longer, but
		 * that's fine - it still serves to distinguish
		 * between two tasks started (effectively) simultaneously.
		 */
		return t1 > t2;
	}
}

/*
 * This function is a callback from heap_insert() and is used to order
 * the heap.
 * In this case we order the heap in descending task start time.
 */
static inline int started_after(void *p1, void *p2)
{
	struct task_struct *t1 = p1;
	struct task_struct *t2 = p2;
	return started_after_time(t1, &t2->start_time, t2);
}

/**
 * cgroup_scan_tasks - iterate though all the tasks in a cgroup
 * @scan: struct cgroup_scanner containing arguments for the scan
 *
 * Arguments include pointers to callback functions test_task() and
 * process_task().
 * Iterate through all the tasks in a cgroup, calling test_task() for each,
 * and if it returns true, call process_task() for it also.
 * The test_task pointer may be NULL, meaning always true (select all tasks).
 * Effectively duplicates cgroup_iter_{start,next,end}()
 * but does not lock css_set_lock for the call to process_task().
 * The struct cgroup_scanner may be embedded in any structure of the caller's
 * creation.
 * It is guaranteed that process_task() will act on every task that
 * is a member of the cgroup for the duration of this call. This
 * function may or may not call process_task() for tasks that exit
 * or move to a different cgroup during the call, or are forked or
 * move into the cgroup during the call.
 *
 * Note that test_task() may be called with locks held, and may in some
 * situations be called multiple times for the same task, so it should
 * be cheap.
 * If the heap pointer in the struct cgroup_scanner is non-NULL, a heap has been
 * pre-allocated and will be used for heap operations (and its "gt" member will
 * be overwritten), else a temporary heap will be used (allocation of which
 * may cause this function to fail).
 */
int cgroup_scan_tasks(struct cgroup_scanner *scan)
{
	int retval, i;
	struct cgroup_iter it;
	struct task_struct *p, *dropped;
	/* Never dereference latest_task, since it's not refcounted */
	struct task_struct *latest_task = NULL;
	struct ptr_heap tmp_heap;
	struct ptr_heap *heap;
	struct timespec latest_time = { 0, 0 };

	if (scan->heap) {
		/* The caller supplied our heap and pre-allocated its memory */
		heap = scan->heap;
		heap->gt = &started_after;
	} else {
		/* We need to allocate our own heap memory */
		heap = &tmp_heap;
		retval = heap_init(heap, PAGE_SIZE, GFP_KERNEL, &started_after);
		if (retval)
			/* cannot allocate the heap */
			return retval;
	}

 again:
	/*
	 * Scan tasks in the cgroup, using the scanner's "test_task" callback
	 * to determine which are of interest, and using the scanner's
	 * "process_task" callback to process any of them that need an update.
	 * Since we don't want to hold any locks during the task updates,
	 * gather tasks to be processed in a heap structure.
	 * The heap is sorted by descending task start time.
	 * If the statically-sized heap fills up, we overflow tasks that
	 * started later, and in future iterations only consider tasks that
	 * started after the latest task in the previous pass. This
	 * guarantees forward progress and that we don't miss any tasks.
	 */
	heap->size = 0;
	cgroup_iter_start(scan->cg, &it);
	while ((p = cgroup_iter_next(scan->cg, &it))) {
		/*
		 * Only affect tasks that qualify per the caller's callback,
		 * if he provided one
		 */
		if (scan->test_task && !scan->test_task(p, scan))
			continue;
		/*
		 * Only process tasks that started after the last task
		 * we processed
		 */
		if (!started_after_time(p, &latest_time, latest_task))
			continue;
		dropped = heap_insert(heap, p);
		if (dropped == NULL) {
			/*
			 * The new task was inserted; the heap wasn't
			 * previously full
			 */
			get_task_struct(p);
		} else if (dropped != p) {
			/*
			 * The new task was inserted, and pushed out a
			 * different task
			 */
			get_task_struct(p);
			put_task_struct(dropped);
		}
		/*
		 * Else the new task was newer than anything already in
		 * the heap and wasn't inserted
		 */
	}
	cgroup_iter_end(scan->cg, &it);

	if (heap->size) {
		for (i = 0; i < heap->size; i++) {
			struct task_struct *q = heap->ptrs[i];
			if (i == 0) {
				latest_time = q->start_time;
				latest_task = q;
			}
			/* Process the task per the caller's callback */
			scan->process_task(q, scan);
			put_task_struct(q);
		}
		/*
		 * If we had to process any tasks at all, scan again
		 * in case some of them were in the middle of forking
		 * children that didn't get processed.
		 * Not the most efficient way to do it, but it avoids
		 * having to take callback_mutex in the fork path
		 */
		goto again;
	}
	if (heap == &tmp_heap)
		heap_free(&tmp_heap);
	return 0;
}

/*
 * Stuff for reading the 'tasks' file.
		if (l == it->cset_head) {
			it->cset_pos = NULL;
		cset = css_task_iter_next_css_set(it);
		if (!cset) {
			it->task_pos = NULL;
			return;
		}
	} while (!css_set_populated(cset));

	if (!list_empty(&cset->tasks))
		it->task_pos = cset->tasks.next;
	else
		it->task_pos = cset->mg_tasks.next;

	it->tasks_head = &cset->tasks;
	it->mg_tasks_head = &cset->mg_tasks;

	/*
	 * We don't keep css_sets locked across iteration steps and thus
	 * need to take steps to ensure that iteration can be resumed after
	 * the lock is re-acquired.  Iteration is performed at two levels -
	 * css_sets and tasks in them.
	 *
	 * Once created, a css_set never leaves its cgroup lists, so a
	 * pinned css_set is guaranteed to stay put and we can resume
	 * iteration afterwards.
	 *
	 * Tasks may leave @cset across iteration steps.  This is resolved
	 * by registering each iterator with the css_set currently being
	 * walked and making css_set_move_task() advance iterators whose
	 * next task is leaving.
	 */
	if (it->cur_cset) {
		list_del(&it->iters_node);
		put_css_set_locked(it->cur_cset);
	}
	get_css_set(cset);
	it->cur_cset = cset;
	list_add(&it->iters_node, &cset->task_iters);
}

static void css_task_iter_advance(struct css_task_iter *it)
{
	struct list_head *next;

	lockdep_assert_held(&css_set_lock);
repeat:
	/*
	 * Advance iterator to find next entry.  cset->tasks is consumed
	 * first and then ->mg_tasks.  After ->mg_tasks, we move onto the
	 * next cset.
	 */
	next = it->task_pos->next;

	if (next == it->tasks_head)
		next = it->mg_tasks_head->next;

	if (next == it->mg_tasks_head)
		css_task_iter_advance_css_set(it);
	else
		it->task_pos = next;

	/* if PROCS, skip over tasks which aren't group leaders */
	if ((it->flags & CSS_TASK_ITER_PROCS) && it->task_pos &&
	    !thread_group_leader(list_entry(it->task_pos, struct task_struct,
					    cg_list)))
		goto repeat;
}

/**
 * css_task_iter_start - initiate task iteration
 * @css: the css to walk tasks of
 * @flags: CSS_TASK_ITER_* flags
 * @it: the task iterator to use
 *
 * Initiate iteration through the tasks of @css.  The caller can call
 * css_task_iter_next() to walk through the tasks until the function
 * returns NULL.  On completion of iteration, css_task_iter_end() must be
 * called.
 */
void css_task_iter_start(struct cgroup_subsys_state *css, unsigned int flags,
			 struct css_task_iter *it)
{
	/* no one should try to iterate before mounting cgroups */
	WARN_ON_ONCE(!use_task_css_set_links);

	memset(it, 0, sizeof(*it));

	spin_lock_irq(&css_set_lock);

	it->ss = css->ss;
	it->flags = flags;

	if (it->ss)
		it->cset_pos = &css->cgroup->e_csets[css->ss->id];
	else
		it->cset_pos = &css->cgroup->cset_links;

	it->cset_head = it->cset_pos;

	css_task_iter_advance_css_set(it);

	spin_unlock_irq(&css_set_lock);
}

/**
 * css_task_iter_next - return the next task for the iterator
 * @it: the task iterator being iterated
 *
 * The "next" function for task iteration.  @it should have been
 * initialized via css_task_iter_start().  Returns NULL when the iteration
 * reaches the end.
 */
struct task_struct *css_task_iter_next(struct css_task_iter *it)
{
	if (it->cur_task) {
		put_task_struct(it->cur_task);
		it->cur_task = NULL;
	}

	spin_lock_irq(&css_set_lock);

	if (it->task_pos) {
		it->cur_task = list_entry(it->task_pos, struct task_struct,
					  cg_list);
		get_task_struct(it->cur_task);
		css_task_iter_advance(it);
	}

	spin_unlock_irq(&css_set_lock);

	return it->cur_task;
}

/**
 * css_task_iter_end - finish task iteration
 * @it: the task iterator to finish
 *
 * Finish task iteration started by css_task_iter_start().
 */
void css_task_iter_end(struct css_task_iter *it)
{
	if (it->cur_cset) {
		spin_lock_irq(&css_set_lock);
		list_del(&it->iters_node);
		put_css_set_locked(it->cur_cset);
		spin_unlock_irq(&css_set_lock);
	}

	if (it->cur_dcset)
		put_css_set(it->cur_dcset);

	if (it->cur_task)
		put_task_struct(it->cur_task);
}

static void cgroup_procs_release(struct kernfs_open_file *of)
{
	LIST_HEAD(preloaded_csets);
	struct cgrp_cset_link *link;
	struct css_task_iter it;
	struct task_struct *task;
	int ret;

	mutex_lock(&cgroup_mutex);

	/* all tasks in @from are being moved, all csets are source */
	spin_lock_bh(&css_set_lock);
	list_for_each_entry(link, &from->cset_links, cset_link)
		cgroup_migrate_add_src(link->cset, to, &preloaded_csets);
	spin_unlock_bh(&css_set_lock);

	ret = cgroup_migrate_prepare_dst(to, &preloaded_csets);
	if (ret)
		goto out_err;

	/*
	 * Migrate tasks one-by-one until @form is empty.  This fails iff
	 * ->can_attach() fails.
	 */
	do {
		css_task_iter_start(&from->self, &it);
		task = css_task_iter_next(&it);
		if (task)
			get_task_struct(task);
		css_task_iter_end(&it);

		if (task) {
			ret = cgroup_migrate(task, false, to);
			put_task_struct(task);
		}
	} while (task && !ret);
out_err:
	cgroup_migrate_finish(&preloaded_csets);
	mutex_unlock(&cgroup_mutex);
	return ret;
}

/*
 * Stuff for reading the 'tasks'/'procs' files.
 *
 * Reading this file can return large amounts of data if a cgroup has
 * *lots* of attached tasks. So it may need several calls to read(),
 * but we cannot guarantee that the information we produce is correct
 * unless we produce it entirely atomically.
 *
 * Upon tasks file open(), a struct ctr_struct is allocated, that
 * will have a pointer to an array (also allocated here).  The struct
 * ctr_struct * is stored in file->private_data.  Its resources will
 * be freed by release() when the file is closed.  The array is used
 * to sprintf the PIDs and then used by read().
 */
struct ctr_struct {
	char *buf;
	int bufsz;
};

/*
 * Load into 'pidarray' up to 'npids' of the tasks using cgroup
 * 'cgrp'.  Return actual number of pids loaded.  No need to
 * task_lock(p) when reading out p->cgroup, since we're in an RCU
 * read section, so the css_set can't go away, and is
 * immutable after creation.
 */
static int pid_array_load(pid_t *pidarray, int npids, struct cgroup *cgrp)
{
	int n = 0;
	struct cgroup_iter it;
	struct task_struct *tsk;
	cgroup_iter_start(cgrp, &it);
	while ((tsk = cgroup_iter_next(cgrp, &it))) {
		if (unlikely(n == npids))
			break;
		pidarray[n++] = task_pid_vnr(tsk);
	}
	cgroup_iter_end(cgrp, &it);
	return n;
 */

/* which pidlist file are we talking about? */
enum cgroup_filetype {
	CGROUP_FILE_PROCS,
	CGROUP_FILE_TASKS,
};

/*
 * A pidlist is a list of pids that virtually represents the contents of one
 * of the cgroup files ("procs" or "tasks"). We keep a list of such pidlists,
 * a pair (one each for procs, tasks) for each pid namespace that's relevant
 * to the cgroup.
 */
struct cgroup_pidlist {
	/*
	 * used to find which pidlist is wanted. doesn't change as long as
	 * this particular list stays in the list.
	*/
	struct { enum cgroup_filetype type; struct pid_namespace *ns; } key;
	/* array of xids */
	pid_t *list;
	/* how many elements the above list has */
	int length;
	/* each of these stored in a list by its cgroup */
	struct list_head links;
	/* pointer to the cgroup we belong to, for list removal purposes */
	struct cgroup *owner;
	/* for delayed destruction */
	struct delayed_work destroy_dwork;
};

/*
 * The following two functions "fix" the issue where there are more pids
 * than kmalloc will give memory for; in such cases, we use vmalloc/vfree.
 * TODO: replace with a kernel-wide solution to this problem
 */
#define PIDLIST_TOO_LARGE(c) ((c) * sizeof(pid_t) > (PAGE_SIZE * 2))
static void *pidlist_allocate(int count)
{
	if (PIDLIST_TOO_LARGE(count))
		return vmalloc(count * sizeof(pid_t));
	else
		return kmalloc(count * sizeof(pid_t), GFP_KERNEL);
}

static void pidlist_free(void *p)
{
	kvfree(p);
}

/*
 * Used to destroy all pidlists lingering waiting for destroy timer.  None
 * should be left afterwards.
 */
static void cgroup_pidlist_destroy_all(struct cgroup *cgrp)
{
	struct cgroup_pidlist *l, *tmp_l;

	mutex_lock(&cgrp->pidlist_mutex);
	list_for_each_entry_safe(l, tmp_l, &cgrp->pidlists, links)
		mod_delayed_work(cgroup_pidlist_destroy_wq, &l->destroy_dwork, 0);
	mutex_unlock(&cgrp->pidlist_mutex);

	flush_workqueue(cgroup_pidlist_destroy_wq);
	BUG_ON(!list_empty(&cgrp->pidlists));
}

static void cgroup_pidlist_destroy_work_fn(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct cgroup_pidlist *l = container_of(dwork, struct cgroup_pidlist,
						destroy_dwork);
	struct cgroup_pidlist *tofree = NULL;

	mutex_lock(&l->owner->pidlist_mutex);

	/*
	 * Destroy iff we didn't get queued again.  The state won't change
	 * as destroy_dwork can only be queued while locked.
	 */
	if (!delayed_work_pending(dwork)) {
		list_del(&l->links);
		pidlist_free(l->list);
		put_pid_ns(l->key.ns);
		tofree = l;
	if (of->priv) {
		css_task_iter_end(of->priv);
		kfree(of->priv);
	}
}

static void *cgroup_procs_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct kernfs_open_file *of = s->private;
	struct css_task_iter *it = of->priv;

	return css_task_iter_next(it);
}

static void *__cgroup_procs_start(struct seq_file *s, loff_t *pos,
				  unsigned int iter_flags)
{
	unsigned a = pid & 0x55555555;
	unsigned b = pid & 0xAAAAAAAA;

	return (a << 1) | (b >> 1);
}

static pid_t cgroup_pid_fry(struct cgroup *cgrp, pid_t pid)
{
	if (cgroup_on_dfl(cgrp))
		return pid_fry(pid);
	else
		return pid;
}

static int cmppid(const void *a, const void *b)
{
	return *(pid_t *)a - *(pid_t *)b;
}

static int fried_cmppid(const void *a, const void *b)
{
	return pid_fry(*(pid_t *)a) - pid_fry(*(pid_t *)b);
}

static struct cgroup_pidlist *cgroup_pidlist_find(struct cgroup *cgrp,
						  enum cgroup_filetype type)
{
	struct cgroup_pidlist *l;
	/* don't need task_nsproxy() if we're looking at ourself */
	struct pid_namespace *ns = task_active_pid_ns(current);

	lockdep_assert_held(&cgrp->pidlist_mutex);

	list_for_each_entry(l, &cgrp->pidlists, links)
		if (l->key.type == type && l->key.ns == ns)
			return l;
	return NULL;
}

/*
 * find the appropriate pidlist for our purpose (given procs vs tasks)
 * returns with the lock on that pidlist already held, and takes care
 * of the use count, or returns NULL with no locks held if we're out of
 * memory.
 */
static struct cgroup_pidlist *cgroup_pidlist_find_create(struct cgroup *cgrp,
						enum cgroup_filetype type)
{
	struct cgroup_pidlist *l;

	lockdep_assert_held(&cgrp->pidlist_mutex);

	l = cgroup_pidlist_find(cgrp, type);
	if (l)
		return l;

	/* entry not found; create a new one */
	l = kzalloc(sizeof(struct cgroup_pidlist), GFP_KERNEL);
	if (!l)
		return l;

	INIT_DELAYED_WORK(&l->destroy_dwork, cgroup_pidlist_destroy_work_fn);
	l->key.type = type;
	/* don't need task_nsproxy() if we're looking at ourself */
	l->key.ns = get_pid_ns(task_active_pid_ns(current));
	l->owner = cgrp;
	list_add(&l->links, &cgrp->pidlists);
	return l;
}

/*
 * Load a cgroup's pidarray with either procs' tgids or tasks' pids
 */
static int pidlist_array_load(struct cgroup *cgrp, enum cgroup_filetype type,
			      struct cgroup_pidlist **lp)
{
	pid_t *array;
	int length;
	int pid, n = 0; /* used for populating the array */
	struct css_task_iter it;
	struct task_struct *tsk;
	struct cgroup_pidlist *l;

	lockdep_assert_held(&cgrp->pidlist_mutex);

	/*
	 * If cgroup gets more users after we read count, we won't have
	 * enough space - tough.  This race is indistinguishable to the
	 * caller from the case that the additional cgroup users didn't
	 * show up until sometime later on.
	 */
	length = cgroup_task_count(cgrp);
	array = pidlist_allocate(length);
	if (!array)
		return -ENOMEM;
	/* now, populate the array */
	css_task_iter_start(&cgrp->self, &it);
	while ((tsk = css_task_iter_next(&it))) {
		if (unlikely(n == length))
			break;
		/* get tgid or pid for procs or tasks file respectively */
		if (type == CGROUP_FILE_PROCS)
			pid = task_tgid_vnr(tsk);
		else
			pid = task_pid_vnr(tsk);
		if (pid > 0) /* make sure to only use valid results */
			array[n++] = pid;
	}
	css_task_iter_end(&it);
	length = n;
	/* now sort & (if procs) strip out duplicates */
	if (cgroup_on_dfl(cgrp))
		sort(array, length, sizeof(pid_t), fried_cmppid, NULL);
	else
		sort(array, length, sizeof(pid_t), cmppid, NULL);
	if (type == CGROUP_FILE_PROCS)
		length = pidlist_uniq(array, length);

	l = cgroup_pidlist_find_create(cgrp, type);
	if (!l) {
		pidlist_free(array);
		return -ENOMEM;
	}

	/* store array, freeing old if necessary */
	pidlist_free(l->list);
	l->list = array;
	l->length = length;
	*lp = l;
	return 0;
}

/**
 * cgroupstats_build - build and fill cgroupstats
 * @stats: cgroupstats to fill information into
 * @dentry: A dentry entry belonging to the cgroup for which stats have
 * been requested.
 *
 * Build and fill cgroupstats so that taskstats can export it to user
 * space.
 */
int cgroupstats_build(struct cgroupstats *stats, struct dentry *dentry)
{
	int ret = -EINVAL;
	struct cgroup *cgrp;
	struct cgroup_iter it;
	struct task_struct *tsk;
	/*
	 * Validate dentry by checking the superblock operations
	 */
	if (dentry->d_sb->s_op != &cgroup_ops)
		 goto err;

	ret = 0;
	cgrp = dentry->d_fsdata;
	rcu_read_lock();

	cgroup_iter_start(cgrp, &it);
	while ((tsk = cgroup_iter_next(cgrp, &it))) {
	struct kernfs_node *kn = kernfs_node_from_dentry(dentry);
	struct cgroup *cgrp;
	struct css_task_iter it;
	struct task_struct *tsk;

	/* it should be kernfs_node belonging to cgroupfs and is a directory */
	if (dentry->d_sb->s_type != &cgroup_fs_type || !kn ||
	    kernfs_type(kn) != KERNFS_DIR)
		return -EINVAL;

	mutex_lock(&cgroup_mutex);

	/*
	 * We aren't being called from kernfs and there's no guarantee on
	 * @kn->priv's validity.  For this and css_tryget_online_from_dir(),
	 * @kn->priv is RCU safe.  Let's do the RCU dancing.
	 */
	rcu_read_lock();
	cgrp = rcu_dereference(kn->priv);
	if (!cgrp || cgroup_is_dead(cgrp)) {
		rcu_read_unlock();
		mutex_unlock(&cgroup_mutex);
		return -ENOENT;
	}
	rcu_read_unlock();

	css_task_iter_start(&cgrp->self, &it);
	while ((tsk = css_task_iter_next(&it))) {
		switch (tsk->state) {
		case TASK_RUNNING:
			stats->nr_running++;
			break;
		case TASK_INTERRUPTIBLE:
			stats->nr_sleeping++;
			break;
		case TASK_UNINTERRUPTIBLE:
			stats->nr_uninterruptible++;
			break;
		case TASK_STOPPED:
			stats->nr_stopped++;
			break;
		default:
			if (delayacct_is_task_waiting_on_io(tsk))
				stats->nr_io_wait++;
			break;
		}
	}
	cgroup_iter_end(cgrp, &it);

	rcu_read_unlock();
err:
	return ret;
}

static int cmppid(const void *a, const void *b)
{
	return *(pid_t *)a - *(pid_t *)b;
}

/*
 * Convert array 'a' of 'npids' pid_t's to a string of newline separated
 * decimal pids in 'buf'.  Don't write more than 'sz' chars, but return
 * count 'cnt' of how many chars would be written if buf were large enough.
 */
static int pid_array_to_buf(char *buf, int sz, pid_t *a, int npids)
{
	int cnt = 0;
	int i;

	for (i = 0; i < npids; i++)
		cnt += snprintf(buf + cnt, max(sz - cnt, 0), "%d\n", a[i]);
	return cnt;
}

/*
 * Handle an open on 'tasks' file.  Prepare a buffer listing the
 * process id's of tasks currently attached to the cgroup being opened.
 *
 * Does not require any specific cgroup mutexes, and does not take any.
 */
static int cgroup_tasks_open(struct inode *unused, struct file *file)
{
	struct cgroup *cgrp = __d_cgrp(file->f_dentry->d_parent);
	struct ctr_struct *ctr;
	pid_t *pidarray;
	int npids;
	char c;

	if (!(file->f_mode & FMODE_READ))
		return 0;

	ctr = kmalloc(sizeof(*ctr), GFP_KERNEL);
	if (!ctr)
		goto err0;

	/*
	 * If cgroup gets more users after we read count, we won't have
	 * enough space - tough.  This race is indistinguishable to the
	 * caller from the case that the additional cgroup users didn't
	 * show up until sometime later on.
	 */
	npids = cgroup_task_count(cgrp);
	if (npids) {
		pidarray = kmalloc(npids * sizeof(pid_t), GFP_KERNEL);
		if (!pidarray)
			goto err1;

		npids = pid_array_load(pidarray, npids, cgrp);
		sort(pidarray, npids, sizeof(pid_t), cmppid, NULL);

		/* Call pid_array_to_buf() twice, first just to get bufsz */
		ctr->bufsz = pid_array_to_buf(&c, sizeof(c), pidarray, npids) + 1;
		ctr->buf = kmalloc(ctr->bufsz, GFP_KERNEL);
		if (!ctr->buf)
			goto err2;
		ctr->bufsz = pid_array_to_buf(ctr->buf, ctr->bufsz, pidarray, npids);

		kfree(pidarray);
	} else {
		ctr->buf = NULL;
		ctr->bufsz = 0;
	}
	file->private_data = ctr;
	return 0;

err2:
	kfree(pidarray);
err1:
	kfree(ctr);
err0:
	return -ENOMEM;
}

static ssize_t cgroup_tasks_read(struct cgroup *cgrp,
				    struct cftype *cft,
				    struct file *file, char __user *buf,
				    size_t nbytes, loff_t *ppos)
{
	struct ctr_struct *ctr = file->private_data;

	return simple_read_from_buffer(buf, nbytes, ppos, ctr->buf, ctr->bufsz);
}

static int cgroup_tasks_release(struct inode *unused_inode,
					struct file *file)
{
	struct ctr_struct *ctr;

	if (file->f_mode & FMODE_READ) {
		ctr = file->private_data;
		kfree(ctr->buf);
		kfree(ctr);
	}
	return 0;
}

static u64 cgroup_read_notify_on_release(struct cgroup *cgrp,
					    struct cftype *cft)
{
	return notify_on_release(cgrp);
}

static int cgroup_write_notify_on_release(struct cgroup *cgrp,
					  struct cftype *cft,
					  u64 val)
{
	clear_bit(CGRP_RELEASABLE, &cgrp->flags);
	if (val)
		set_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
	else
		clear_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
	return 0;
}

/*
 * for the common functions, 'private' gives the type of file
 */
static struct cftype files[] = {
	{
		.name = "tasks",
		.open = cgroup_tasks_open,
		.read = cgroup_tasks_read,
		.write_u64 = cgroup_tasks_write,
		.release = cgroup_tasks_release,
		.private = FILE_TASKLIST,
	},

	css_task_iter_end(&it);

	mutex_unlock(&cgroup_mutex);
	return 0;
}


/*
 * seq_file methods for the tasks/procs files. The seq_file position is the
 * next pid to display; the seq_file iterator is a pointer to the pid
 * in the cgroup->l->list array.
 */

static void *cgroup_pidlist_start(struct seq_file *s, loff_t *pos)
{
	/*
	 * Initially we receive a position value that corresponds to
	 * one more than the last pid shown (or 0 on the first call or
	 * after a seek to the start). Use a binary-search to find the
	 * next pid to display, if any
	 */
	struct kernfs_open_file *of = s->private;
	struct cgroup *cgrp = seq_css(s)->cgroup;
	struct css_task_iter *it = of->priv;

	/*
	 * When a seq_file is seeked, it's always traversed sequentially
	 * from position 0, so we can simply keep iterating on !0 *pos.
	 */
	if (!it) {
		if (WARN_ON_ONCE((*pos)++))
			return ERR_PTR(-EINVAL);

		it = kzalloc(sizeof(*it), GFP_KERNEL);
		if (!it)
			return ERR_PTR(-ENOMEM);
		of->priv = it;
		css_task_iter_start(&cgrp->self, iter_flags, it);
	} else if (!(*pos)++) {
		css_task_iter_end(it);
		css_task_iter_start(&cgrp->self, iter_flags, it);
	}

	return cgroup_procs_next(s, NULL, NULL);
}

static void *cgroup_procs_start(struct seq_file *s, loff_t *pos)
{
	struct cgroup *cgrp = seq_css(s)->cgroup;

	/*
	 * All processes of a threaded subtree belong to the domain cgroup
	 * of the subtree.  Only threads can be distributed across the
	 * subtree.  Reject reads on cgroup.procs in the subtree proper.
	 * They're always empty anyway.
	 */
	if (cgroup_is_threaded(cgrp))
		return ERR_PTR(-EOPNOTSUPP);

	return __cgroup_procs_start(s, pos, CSS_TASK_ITER_PROCS |
					    CSS_TASK_ITER_THREADED);
}

static int cgroup_procs_show(struct seq_file *s, void *v)
{
	seq_printf(s, "%d\n", task_pid_vnr(v));
	return 0;
}

static int cgroup_procs_write_permission(struct cgroup *src_cgrp,
					 struct cgroup *dst_cgrp,
					 struct super_block *sb)
{
	struct cgroup_namespace *ns = current->nsproxy->cgroup_ns;
	struct cgroup *com_cgrp = src_cgrp;
	struct inode *inode;
	int ret;

	lockdep_assert_held(&cgroup_mutex);

	/* find the common ancestor */
	while (!cgroup_is_descendant(dst_cgrp, com_cgrp))
		com_cgrp = cgroup_parent(com_cgrp);

	/* %current should be authorized to migrate to the common ancestor */
	inode = kernfs_get_inode(sb, com_cgrp->procs_file.kn);
	if (!inode)
		return -ENOMEM;

	ret = inode_permission(inode, MAY_WRITE);
	iput(inode);
	if (ret)
		return ret;

	/*
	 * If namespaces are delegation boundaries, %current must be able
	 * to see both source and destination cgroups from its namespace.
	 */
	if ((cgrp_dfl_root.flags & CGRP_ROOT_NS_DELEGATE) &&
	    (!cgroup_is_descendant(src_cgrp, ns->root_cset->dfl_cgrp) ||
	     !cgroup_is_descendant(dst_cgrp, ns->root_cset->dfl_cgrp)))
		return -ENOENT;

	return 0;
}

static ssize_t cgroup_procs_write(struct kernfs_open_file *of,
				  char *buf, size_t nbytes, loff_t off)
{
	struct cgroup *src_cgrp, *dst_cgrp;
	struct task_struct *task;
	ssize_t ret;

	dst_cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!dst_cgrp)
		return -ENODEV;

	task = cgroup_procs_write_start(buf, true);
	ret = PTR_ERR_OR_ZERO(task);
	if (ret)
		goto out_unlock;

	/* find the source cgroup */
	spin_lock_irq(&css_set_lock);
	src_cgrp = task_cgroup_from_root(task, &cgrp_dfl_root);
	spin_unlock_irq(&css_set_lock);

	ret = cgroup_procs_write_permission(src_cgrp, dst_cgrp,
					    of->file->f_path.dentry->d_sb);
	if (ret)
		goto out_finish;

	ret = cgroup_attach_task(dst_cgrp, task, true);

out_finish:
	cgroup_procs_write_finish(task);
out_unlock:
	cgroup_kn_unlock(of->kn);

	return ret ?: nbytes;
}

static void *cgroup_threads_start(struct seq_file *s, loff_t *pos)
{
	return __cgroup_procs_start(s, pos, 0);
}

static ssize_t cgroup_threads_write(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	struct cgroup *src_cgrp, *dst_cgrp;
	struct task_struct *task;
	ssize_t ret;

	buf = strstrip(buf);

	dst_cgrp = cgroup_kn_lock_live(of->kn, false);
	if (!dst_cgrp)
		return -ENODEV;

	task = cgroup_procs_write_start(buf, false);
	ret = PTR_ERR_OR_ZERO(task);
	if (ret)
		goto out_unlock;

	/* find the source cgroup */
	spin_lock_irq(&css_set_lock);
	src_cgrp = task_cgroup_from_root(task, &cgrp_dfl_root);
	spin_unlock_irq(&css_set_lock);

	/* thread migrations follow the cgroup.procs delegation rule */
	ret = cgroup_procs_write_permission(src_cgrp, dst_cgrp,
					    of->file->f_path.dentry->d_sb);
	if (ret)
		goto out_finish;

	/* and must be contained in the same domain */
	ret = -EOPNOTSUPP;
	if (src_cgrp->dom_cgrp != dst_cgrp->dom_cgrp)
		goto out_finish;

	ret = cgroup_attach_task(dst_cgrp, task, false);

out_finish:
	cgroup_procs_write_finish(task);
out_unlock:
	cgroup_kn_unlock(of->kn);

	return ret ?: nbytes;
}

/* cgroup core interface files for the default hierarchy */
static struct cftype cgroup_base_files[] = {
	{
		.name = "cgroup.type",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = cgroup_type_show,
		.write = cgroup_type_write,
	},
	{
		.name = "cgroup.procs",
		.flags = CFTYPE_NS_DELEGATABLE,
		.file_offset = offsetof(struct cgroup, procs_file),
		.release = cgroup_procs_release,
		.seq_start = cgroup_procs_start,
		.seq_next = cgroup_procs_next,
		.seq_show = cgroup_procs_show,
		.write = cgroup_procs_write,
	},
	{
		.name = "cgroup.threads",
		.release = cgroup_procs_release,
		.seq_start = cgroup_threads_start,
		.seq_next = cgroup_procs_next,
		.seq_show = cgroup_procs_show,
		.write = cgroup_threads_write,
	},
	{
		.name = "cgroup.controllers",
		.seq_show = cgroup_controllers_show,
	},
	{
		.name = "cgroup.subtree_control",
		.flags = CFTYPE_NS_DELEGATABLE,
		.seq_show = cgroup_subtree_control_show,
		.write = cgroup_subtree_control_write,
	},
	{
		.name = "cgroup.events",
		.flags = CFTYPE_NOT_ON_ROOT,
		.file_offset = offsetof(struct cgroup, events_file),
		.seq_show = cgroup_events_show,
	},
	{
		.name = "cgroup.max.descendants",
		.seq_show = cgroup_max_descendants_show,
		.write = cgroup_max_descendants_write,
	},
	{
		.name = "cgroup.max.depth",
		.seq_show = cgroup_max_depth_show,
		.write = cgroup_max_depth_write,
	},
	{
		.name = "cgroup.sane_behavior",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = cgroup_sane_behavior_show,
	},
	{
		.name = "tasks",
		.seq_start = cgroup_pidlist_start,
		.seq_next = cgroup_pidlist_next,
		.seq_stop = cgroup_pidlist_stop,
		.seq_show = cgroup_pidlist_show,
		.private = CGROUP_FILE_TASKS,
		.write = cgroup_tasks_write,
	},
	{
		.name = "notify_on_release",
		.read_u64 = cgroup_read_notify_on_release,
		.write_u64 = cgroup_write_notify_on_release,
		.private = FILE_NOTIFY_ON_RELEASE,
	},
};

static struct cftype cft_release_agent = {
	.name = "release_agent",
	.read_seq_string = cgroup_release_agent_show,
	.write_string = cgroup_release_agent_write,
	.max_write_len = PATH_MAX,
	.private = FILE_RELEASE_AGENT,
};

static int cgroup_populate_dir(struct cgroup *cgrp)
{
	int err;
	struct cgroup_subsys *ss;

	/* First clear out any existing files */
	cgroup_clear_directory(cgrp->dentry);

	err = cgroup_add_files(cgrp, NULL, files, ARRAY_SIZE(files));
	if (err < 0)
		return err;

	if (cgrp == cgrp->top_cgroup) {
		if ((err = cgroup_add_file(cgrp, NULL, &cft_release_agent)) < 0)
			return err;
	}

	for_each_subsys(cgrp->root, ss) {
		if (ss->populate && (err = ss->populate(ss, cgrp)) < 0)
			return err;
	}

	return 0;
}

static void init_cgroup_css(struct cgroup_subsys_state *css,
			       struct cgroup_subsys *ss,
			       struct cgroup *cgrp)
{
	css->cgroup = cgrp;
	atomic_set(&css->refcnt, 0);
	css->flags = 0;
	if (cgrp == dummytop)
		set_bit(CSS_ROOT, &css->flags);
	BUG_ON(cgrp->subsys[ss->subsys_id]);
	cgrp->subsys[ss->subsys_id] = css;
}

/*
 * cgroup_create - create a cgroup
 * @parent: cgroup that will be parent of the new cgroup
 * @dentry: dentry of the new cgroup
 * @mode: mode to set on new inode
 *
 * Must be called with the mutex on the parent inode held
 */
static long cgroup_create(struct cgroup *parent, struct dentry *dentry,
			     int mode)
{
	struct cgroup *cgrp;
	struct cgroupfs_root *root = parent->root;
	int err = 0;
	struct cgroup_subsys *ss;
	struct super_block *sb = root->sb;

	cgrp = kzalloc(sizeof(*cgrp), GFP_KERNEL);
	if (!cgrp)
		return -ENOMEM;

	/* Grab a reference on the superblock so the hierarchy doesn't
	 * get deleted on unmount if there are child cgroups.  This
	 * can be done outside cgroup_mutex, since the sb can't
	 * disappear while someone has an open control file on the
	 * fs */
	atomic_inc(&sb->s_active);

	mutex_lock(&cgroup_mutex);

	INIT_LIST_HEAD(&cgrp->sibling);
	INIT_LIST_HEAD(&cgrp->children);
	INIT_LIST_HEAD(&cgrp->css_sets);
	INIT_LIST_HEAD(&cgrp->release_list);

	cgrp->parent = parent;
	cgrp->root = parent->root;
	cgrp->top_cgroup = parent->top_cgroup;
	},
	{
		.name = "release_agent",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = cgroup_release_agent_show,
		.write = cgroup_release_agent_write,
		.max_write_len = PATH_MAX - 1,
		.name = "cgroup.stat",
		.seq_show = cgroup_stat_show,
	},
	{ }	/* terminate */
};

/*
 * css destruction is four-stage process.
 *
 * 1. Destruction starts.  Killing of the percpu_ref is initiated.
 *    Implemented in kill_css().
 *
 * 2. When the percpu_ref is confirmed to be visible as killed on all CPUs
 *    and thus css_tryget_online() is guaranteed to fail, the css can be
 *    offlined by invoking offline_css().  After offlining, the base ref is
 *    put.  Implemented in css_killed_work_fn().
 *
 * 3. When the percpu_ref reaches zero, the only possible remaining
 *    accessors are inside RCU read sections.  css_release() schedules the
 *    RCU callback.
 *
 * 4. After the grace period, the css can be freed.  Implemented in
 *    css_free_work_fn().
 *
 * It is actually hairier because both step 2 and 4 require process context
 * and thus involve punting to css->destroy_work adding two additional
 * steps to the already complex sequence.
 */
static void css_free_work_fn(struct work_struct *work)
{
	struct cgroup_subsys_state *css =
		container_of(work, struct cgroup_subsys_state, destroy_work);
	struct cgroup_subsys *ss = css->ss;
	struct cgroup *cgrp = css->cgroup;

	percpu_ref_exit(&css->refcnt);

	if (ss) {
		/* css free path */
		struct cgroup_subsys_state *parent = css->parent;
		int id = css->id;

		ss->css_free(css);
		cgroup_idr_remove(&ss->css_idr, id);
		cgroup_put(cgrp);

		if (parent)
			css_put(parent);
	} else {
		/* cgroup free path */
		atomic_dec(&cgrp->root->nr_cgrps);
		cgroup1_pidlist_destroy_all(cgrp);
		cancel_work_sync(&cgrp->release_agent_work);

		if (cgroup_parent(cgrp)) {
			/*
			 * We get a ref to the parent, and put the ref when
			 * this cgroup is being freed, so it's guaranteed
			 * that the parent won't be destroyed before its
			 * children.
			 */
			cgroup_put(cgroup_parent(cgrp));
			kernfs_put(cgrp->kn);
			kfree(cgrp);
		} else {
			/*
			 * This is root cgroup's refcnt reaching zero,
			 * which indicates that the root should be
			 * released.
			 */
			cgroup_destroy_root(cgrp->root);
		}
	}
}

static void css_free_rcu_fn(struct rcu_head *rcu_head)
{
	struct cgroup_subsys_state *css =
		container_of(rcu_head, struct cgroup_subsys_state, rcu_head);

	INIT_WORK(&css->destroy_work, css_free_work_fn);
	queue_work(cgroup_destroy_wq, &css->destroy_work);
}

static void css_release_work_fn(struct work_struct *work)
{
	struct cgroup_subsys_state *css =
		container_of(work, struct cgroup_subsys_state, destroy_work);
	struct cgroup_subsys *ss = css->ss;
	struct cgroup *cgrp = css->cgroup;

	mutex_lock(&cgroup_mutex);

	css->flags |= CSS_RELEASED;
	list_del_rcu(&css->sibling);

	if (ss) {
		/* css release path */
		cgroup_idr_replace(&ss->css_idr, NULL, css->id);
		if (ss->css_released)
			ss->css_released(css);
	} else {
		struct cgroup *tcgrp;

		/* cgroup release path */
		trace_cgroup_release(cgrp);

		for (tcgrp = cgroup_parent(cgrp); tcgrp;
		     tcgrp = cgroup_parent(tcgrp))
			tcgrp->nr_dying_descendants--;

		cgroup_idr_remove(&cgrp->root->cgroup_idr, cgrp->id);
		cgrp->id = -1;

		/*
		 * There are two control paths which try to determine
		 * cgroup from dentry without going through kernfs -
		 * cgroupstats_build() and css_tryget_online_from_dir().
		 * Those are supported by RCU protecting clearing of
		 * cgrp->kn->priv backpointer.
		 */
		if (cgrp->kn)
			RCU_INIT_POINTER(*(void __rcu __force **)&cgrp->kn->priv,
					 NULL);

		cgroup_bpf_put(cgrp);
	}

	mutex_unlock(&cgroup_mutex);

	call_rcu(&css->rcu_head, css_free_rcu_fn);
}

static void css_release(struct percpu_ref *ref)
{
	struct cgroup_subsys_state *css =
		container_of(ref, struct cgroup_subsys_state, refcnt);

	INIT_WORK(&css->destroy_work, css_release_work_fn);
	queue_work(cgroup_destroy_wq, &css->destroy_work);
}

static void init_and_link_css(struct cgroup_subsys_state *css,
			      struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	lockdep_assert_held(&cgroup_mutex);

	cgroup_get_live(cgrp);

	memset(css, 0, sizeof(*css));
	css->cgroup = cgrp;
	css->ss = ss;
	css->id = -1;
	INIT_LIST_HEAD(&css->sibling);
	INIT_LIST_HEAD(&css->children);
	css->serial_nr = css_serial_nr_next++;
	atomic_set(&css->online_cnt, 0);

	if (cgroup_parent(cgrp)) {
		css->parent = cgroup_css(cgroup_parent(cgrp), ss);
		css_get(css->parent);
	}

	BUG_ON(cgroup_css(cgrp, ss));
}

/* invoke ->css_online() on a new CSS and mark it online if successful */
static int online_css(struct cgroup_subsys_state *css)
{
	struct cgroup_subsys *ss = css->ss;
	int ret = 0;

	lockdep_assert_held(&cgroup_mutex);

	if (ss->css_online)
		ret = ss->css_online(css);
	if (!ret) {
		css->flags |= CSS_ONLINE;
		rcu_assign_pointer(css->cgroup->subsys[ss->id], css);

		atomic_inc(&css->online_cnt);
		if (css->parent)
			atomic_inc(&css->parent->online_cnt);
	}
	return ret;
}

/* if the CSS is online, invoke ->css_offline() on it and mark it offline */
static void offline_css(struct cgroup_subsys_state *css)
{
	struct cgroup_subsys *ss = css->ss;

	lockdep_assert_held(&cgroup_mutex);

	if (!(css->flags & CSS_ONLINE))
		return;

	if (ss->css_offline)
		ss->css_offline(css);

	css->flags &= ~CSS_ONLINE;
	RCU_INIT_POINTER(css->cgroup->subsys[ss->id], NULL);

	wake_up_all(&css->cgroup->offline_waitq);
}

/**
 * css_create - create a cgroup_subsys_state
 * @cgrp: the cgroup new css will be associated with
 * @ss: the subsys of new css
 *
 * Create a new css associated with @cgrp - @ss pair.  On success, the new
 * css is online and installed in @cgrp.  This function doesn't create the
 * interface files.  Returns 0 on success, -errno on failure.
 */
static struct cgroup_subsys_state *css_create(struct cgroup *cgrp,
					      struct cgroup_subsys *ss)
{
	struct cgroup *parent = cgroup_parent(cgrp);
	struct cgroup_subsys_state *parent_css = cgroup_css(parent, ss);
	struct cgroup_subsys_state *css;
	int err;

	lockdep_assert_held(&cgroup_mutex);

	css = ss->css_alloc(parent_css);
	if (!css)
		css = ERR_PTR(-ENOMEM);
	if (IS_ERR(css))
		return css;

	init_and_link_css(css, ss, cgrp);

	err = percpu_ref_init(&css->refcnt, css_release, 0, GFP_KERNEL);
	if (err)
		goto err_free_css;

	err = cgroup_idr_alloc(&ss->css_idr, NULL, 2, 0, GFP_KERNEL);
	if (err < 0)
		goto err_free_css;
	css->id = err;

	/* @css is ready to be brought online now, make it visible */
	list_add_tail_rcu(&css->sibling, &parent_css->children);
	cgroup_idr_replace(&ss->css_idr, css, css->id);

	err = online_css(css);
	if (err)
		goto err_list_del;

	if (ss->broken_hierarchy && !ss->warned_broken_hierarchy &&
	    cgroup_parent(parent)) {
		pr_warn("%s (%d) created nested cgroup for controller \"%s\" which has incomplete hierarchy support. Nested cgroups may change behavior in the future.\n",
			current->comm, current->pid, ss->name);
		if (!strcmp(ss->name, "memory"))
			pr_warn("\"memory\" requires setting use_hierarchy to 1 on the root\n");
		ss->warned_broken_hierarchy = true;
	}

	return css;

err_list_del:
	list_del_rcu(&css->sibling);
err_free_css:
	call_rcu(&css->rcu_head, css_free_rcu_fn);
	return ERR_PTR(err);
}

/*
 * The returned cgroup is fully initialized including its control mask, but
 * it isn't associated with its kernfs_node and doesn't have the control
 * mask applied.
 */
static struct cgroup *cgroup_create(struct cgroup *parent)
{
	struct cgroup_root *root = parent->root;
	struct cgroup *cgrp, *tcgrp;
	int level = parent->level + 1;
	int ret;

	/* allocate the cgroup and its ID, 0 is reserved for the root */
	cgrp = kzalloc(sizeof(*cgrp) +
		       sizeof(cgrp->ancestor_ids[0]) * (level + 1), GFP_KERNEL);
	if (!cgrp)
		return ERR_PTR(-ENOMEM);

	ret = percpu_ref_init(&cgrp->self.refcnt, css_release, 0, GFP_KERNEL);
	if (ret)
		goto out_free_cgrp;

	/*
	 * Temporarily set the pointer to NULL, so idr_find() won't return
	 * a half-baked cgroup.
	 */
	cgrp->id = cgroup_idr_alloc(&root->cgroup_idr, NULL, 2, 0, GFP_KERNEL);
	if (cgrp->id < 0) {
		ret = -ENOMEM;
		goto out_cancel_ref;
	}

	init_cgroup_housekeeping(cgrp);

	cgrp->self.parent = &parent->self;
	cgrp->root = root;
	cgrp->level = level;

	for (tcgrp = cgrp; tcgrp; tcgrp = cgroup_parent(tcgrp)) {
		cgrp->ancestor_ids[tcgrp->level] = tcgrp->id;

		if (tcgrp != cgrp)
			tcgrp->nr_descendants++;
	}

	if (notify_on_release(parent))
		set_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);

	for_each_subsys(root, ss) {
		struct cgroup_subsys_state *css = ss->create(ss, cgrp);
		if (IS_ERR(css)) {
			err = PTR_ERR(css);
			goto err_destroy;
		}
		init_cgroup_css(css, ss, cgrp);
	}

	list_add(&cgrp->sibling, &cgrp->parent->children);
	root->number_of_cgroups++;

	err = cgroup_create_dir(cgrp, dentry, mode);
	if (err < 0)
		goto err_remove;

	/* The cgroup directory was pre-locked for us */
	BUG_ON(!mutex_is_locked(&cgrp->dentry->d_inode->i_mutex));

	err = cgroup_populate_dir(cgrp);
	/* If err < 0, we have a half-filled directory - oh well ;) */

	mutex_unlock(&cgroup_mutex);
	mutex_unlock(&cgrp->dentry->d_inode->i_mutex);

	return 0;

 err_remove:

	list_del(&cgrp->sibling);
	root->number_of_cgroups--;

 err_destroy:

	for_each_subsys(root, ss) {
		if (cgrp->subsys[ss->subsys_id])
			ss->destroy(ss, cgrp);
	}

	mutex_unlock(&cgroup_mutex);

	/* Release the reference count that we took on the superblock */
	deactivate_super(sb);

	kfree(cgrp);
	return err;
}

static int cgroup_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct cgroup *c_parent = dentry->d_parent->d_fsdata;

	/* the vfs holds inode->i_mutex already */
	return cgroup_create(c_parent, dentry, mode | S_IFDIR);
}

static int cgroup_has_css_refs(struct cgroup *cgrp)
{
	/* Check the reference count on each subsystem. Since we
	 * already established that there are no tasks in the
	 * cgroup, if the css refcount is also 0, then there should
	 * be no outstanding references, so the subsystem is safe to
	 * destroy. We scan across all subsystems rather than using
	 * the per-hierarchy linked list of mounted subsystems since
	 * we can be called via check_for_release() with no
	 * synchronization other than RCU, and the subsystem linked
	 * list isn't RCU-safe */
	int i;
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *ss = subsys[i];
		struct cgroup_subsys_state *css;
		/* Skip subsystems not in this hierarchy */
		if (ss->root != cgrp->root)
			continue;
		css = cgrp->subsys[ss->subsys_id];
		/* When called from check_for_release() it's possible
		 * that by this point the cgroup has been removed
		 * and the css deleted. But a false-positive doesn't
		 * matter, since it can only happen if the cgroup
		 * has been deleted and hence no longer needs the
		 * release agent to be called anyway. */
		if (css && atomic_read(&css->refcnt))
			return 1;
	}
	return 0;
}

static int cgroup_rmdir(struct inode *unused_dir, struct dentry *dentry)
{
	struct cgroup *cgrp = dentry->d_fsdata;
	struct dentry *d;
	struct cgroup *parent;
	struct super_block *sb;
	struct cgroupfs_root *root;

	/* the vfs holds both inode->i_mutex already */

	mutex_lock(&cgroup_mutex);
	if (atomic_read(&cgrp->count) != 0) {
		mutex_unlock(&cgroup_mutex);
		return -EBUSY;
	}
	if (!list_empty(&cgrp->children)) {
		mutex_unlock(&cgroup_mutex);
		return -EBUSY;
	}

	parent = cgrp->parent;
	root = cgrp->root;
	sb = root->sb;

	/*
	 * Call pre_destroy handlers of subsys. Notify subsystems
	 * that rmdir() request comes.
	 */
	cgroup_call_pre_destroy(cgrp);

	if (cgroup_has_css_refs(cgrp)) {
		mutex_unlock(&cgroup_mutex);
		return -EBUSY;
	}

	spin_lock(&release_list_lock);
	set_bit(CGRP_REMOVED, &cgrp->flags);
	if (!list_empty(&cgrp->release_list))
		list_del(&cgrp->release_list);
	spin_unlock(&release_list_lock);
	/* delete my sibling from parent->children */
	list_del(&cgrp->sibling);
	spin_lock(&cgrp->dentry->d_lock);
	d = dget(cgrp->dentry);
	cgrp->dentry = NULL;
	spin_unlock(&d->d_lock);

	cgroup_d_remove_dir(d);
	dput(d);

	set_bit(CGRP_RELEASABLE, &parent->flags);
	check_for_release(parent);

	mutex_unlock(&cgroup_mutex);
	return 0;
}

static void __init cgroup_init_subsys(struct cgroup_subsys *ss)
	if (test_bit(CGRP_CPUSET_CLONE_CHILDREN, &parent->flags))
		set_bit(CGRP_CPUSET_CLONE_CHILDREN, &cgrp->flags);

	cgrp->self.serial_nr = css_serial_nr_next++;

	/* allocation complete, commit to creation */
	list_add_tail_rcu(&cgrp->self.sibling, &cgroup_parent(cgrp)->self.children);
	atomic_inc(&root->nr_cgrps);
	cgroup_get_live(parent);

	/*
	 * @cgrp is now fully operational.  If something fails after this
	 * point, it'll be released via the normal destruction path.
	 */
	cgroup_idr_replace(&root->cgroup_idr, cgrp, cgrp->id);

	/*
	 * On the default hierarchy, a child doesn't automatically inherit
	 * subtree_control from the parent.  Each is configured manually.
	 */
	if (!cgroup_on_dfl(cgrp))
		cgrp->subtree_control = cgroup_control(cgrp);

	if (parent)
		cgroup_bpf_inherit(cgrp, parent);

	cgroup_propagate_control(cgrp);

	return cgrp;

out_cancel_ref:
	percpu_ref_exit(&cgrp->self.refcnt);
out_free_cgrp:
	kfree(cgrp);
	return ERR_PTR(ret);
}

static bool cgroup_check_hierarchy_limits(struct cgroup *parent)
{
	struct cgroup *cgroup;
	int ret = false;
	int level = 1;

	lockdep_assert_held(&cgroup_mutex);

	for (cgroup = parent; cgroup; cgroup = cgroup_parent(cgroup)) {
		if (cgroup->nr_descendants >= cgroup->max_descendants)
			goto fail;

		if (level > cgroup->max_depth)
			goto fail;

		level++;
	}

	ret = true;
fail:
	return ret;
}

int cgroup_mkdir(struct kernfs_node *parent_kn, const char *name, umode_t mode)
{
	struct cgroup *parent, *cgrp;
	struct kernfs_node *kn;
	int ret;

	/* do not accept '\n' to prevent making /proc/<pid>/cgroup unparsable */
	if (strchr(name, '\n'))
		return -EINVAL;

	parent = cgroup_kn_lock_live(parent_kn, false);
	if (!parent)
		return -ENODEV;

	if (!cgroup_check_hierarchy_limits(parent)) {
		ret = -EAGAIN;
		goto out_unlock;
	}

	cgrp = cgroup_create(parent);
	if (IS_ERR(cgrp)) {
		ret = PTR_ERR(cgrp);
		goto out_unlock;
	}

	/* create the directory */
	kn = kernfs_create_dir(parent->kn, name, mode, cgrp);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		goto out_destroy;
	}
	cgrp->kn = kn;

	/*
	 * This extra ref will be put in cgroup_free_fn() and guarantees
	 * that @cgrp->kn is always accessible.
	 */
	kernfs_get(kn);

	ret = cgroup_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;

	ret = css_populate_dir(&cgrp->self);
	if (ret)
		goto out_destroy;

	ret = cgroup_apply_control_enable(cgrp);
	if (ret)
		goto out_destroy;

	trace_cgroup_mkdir(cgrp);

	/* let's create and online css's */
	kernfs_activate(kn);

	ret = 0;
	goto out_unlock;

out_destroy:
	cgroup_destroy_locked(cgrp);
out_unlock:
	cgroup_kn_unlock(parent_kn);
	return ret;
}

/*
 * This is called when the refcnt of a css is confirmed to be killed.
 * css_tryget_online() is now guaranteed to fail.  Tell the subsystem to
 * initate destruction and put the css ref from kill_css().
 */
static void css_killed_work_fn(struct work_struct *work)
{
	struct cgroup_subsys_state *css =
		container_of(work, struct cgroup_subsys_state, destroy_work);

	mutex_lock(&cgroup_mutex);

	do {
		offline_css(css);
		css_put(css);
		/* @css can't go away while we're holding cgroup_mutex */
		css = css->parent;
	} while (css && atomic_dec_and_test(&css->online_cnt));

	mutex_unlock(&cgroup_mutex);
}

/* css kill confirmation processing requires process context, bounce */
static void css_killed_ref_fn(struct percpu_ref *ref)
{
	struct cgroup_subsys_state *css =
		container_of(ref, struct cgroup_subsys_state, refcnt);

	if (atomic_dec_and_test(&css->online_cnt)) {
		INIT_WORK(&css->destroy_work, css_killed_work_fn);
		queue_work(cgroup_destroy_wq, &css->destroy_work);
	}
}

/**
 * kill_css - destroy a css
 * @css: css to destroy
 *
 * This function initiates destruction of @css by removing cgroup interface
 * files and putting its base reference.  ->css_offline() will be invoked
 * asynchronously once css_tryget_online() is guaranteed to fail and when
 * the reference count reaches zero, @css will be released.
 */
static void kill_css(struct cgroup_subsys_state *css)
{
	lockdep_assert_held(&cgroup_mutex);

	if (css->flags & CSS_DYING)
		return;

	css->flags |= CSS_DYING;

	/*
	 * This must happen before css is disassociated with its cgroup.
	 * See seq_css() for details.
	 */
	css_clear_dir(css);

	/*
	 * Killing would put the base ref, but we need to keep it alive
	 * until after ->css_offline().
	 */
	css_get(css);

	/*
	 * cgroup core guarantees that, by the time ->css_offline() is
	 * invoked, no new css reference will be given out via
	 * css_tryget_online().  We can't simply call percpu_ref_kill() and
	 * proceed to offlining css's because percpu_ref_kill() doesn't
	 * guarantee that the ref is seen as killed on all CPUs on return.
	 *
	 * Use percpu_ref_kill_and_confirm() to get notifications as each
	 * css is confirmed to be seen as killed on all CPUs.
	 */
	percpu_ref_kill_and_confirm(&css->refcnt, css_killed_ref_fn);
}

/**
 * cgroup_destroy_locked - the first stage of cgroup destruction
 * @cgrp: cgroup to be destroyed
 *
 * css's make use of percpu refcnts whose killing latency shouldn't be
 * exposed to userland and are RCU protected.  Also, cgroup core needs to
 * guarantee that css_tryget_online() won't succeed by the time
 * ->css_offline() is invoked.  To satisfy all the requirements,
 * destruction is implemented in the following two steps.
 *
 * s1. Verify @cgrp can be destroyed and mark it dying.  Remove all
 *     userland visible parts and start killing the percpu refcnts of
 *     css's.  Set up so that the next stage will be kicked off once all
 *     the percpu refcnts are confirmed to be killed.
 *
 * s2. Invoke ->css_offline(), mark the cgroup dead and proceed with the
 *     rest of destruction.  Once all cgroup references are gone, the
 *     cgroup is RCU-freed.
 *
 * This function implements s1.  After this step, @cgrp is gone as far as
 * the userland is concerned and a new cgroup with the same name may be
 * created.  As cgroup doesn't care about the names internally, this
 * doesn't cause any problem.
 */
static int cgroup_destroy_locked(struct cgroup *cgrp)
	__releases(&cgroup_mutex) __acquires(&cgroup_mutex)
{
	struct cgroup *tcgrp, *parent = cgroup_parent(cgrp);
	struct cgroup_subsys_state *css;
	struct cgrp_cset_link *link;
	int ssid;

	lockdep_assert_held(&cgroup_mutex);

	/*
	 * Only migration can raise populated from zero and we're already
	 * holding cgroup_mutex.
	 */
	if (cgroup_is_populated(cgrp))
		return -EBUSY;

	/*
	 * Make sure there's no live children.  We can't test emptiness of
	 * ->self.children as dead children linger on it while being
	 * drained; otherwise, "rmdir parent/child parent" may fail.
	 */
	if (css_has_online_children(&cgrp->self))
		return -EBUSY;

	/*
	 * Mark @cgrp and the associated csets dead.  The former prevents
	 * further task migration and child creation by disabling
	 * cgroup_lock_live_group().  The latter makes the csets ignored by
	 * the migration path.
	 */
	cgrp->self.flags &= ~CSS_ONLINE;

	spin_lock_irq(&css_set_lock);
	list_for_each_entry(link, &cgrp->cset_links, cset_link)
		link->cset->dead = true;
	spin_unlock_irq(&css_set_lock);

	/* initiate massacre of all css's */
	for_each_css(css, ssid, cgrp)
		kill_css(css);

	/*
	 * Remove @cgrp directory along with the base files.  @cgrp has an
	 * extra ref on its kn.
	 */
	kernfs_remove(cgrp->kn);

	if (parent && cgroup_is_threaded(cgrp))
		parent->nr_threaded_children--;

	for (tcgrp = cgroup_parent(cgrp); tcgrp; tcgrp = cgroup_parent(tcgrp)) {
		tcgrp->nr_descendants--;
		tcgrp->nr_dying_descendants++;
	}

	cgroup1_check_for_release(parent);

	/* put the base reference */
	percpu_ref_kill(&cgrp->self.refcnt);

	return 0;
};

int cgroup_rmdir(struct kernfs_node *kn)
{
	struct cgroup *cgrp;
	int ret = 0;

	cgrp = cgroup_kn_lock_live(kn, false);
	if (!cgrp)
		return 0;

	ret = cgroup_destroy_locked(cgrp);

	if (!ret)
		trace_cgroup_rmdir(cgrp);

	cgroup_kn_unlock(kn);
	return ret;
}

static struct kernfs_syscall_ops cgroup_kf_syscall_ops = {
	.show_options		= cgroup_show_options,
	.remount_fs		= cgroup_remount,
	.mkdir			= cgroup_mkdir,
	.rmdir			= cgroup_rmdir,
	.show_path		= cgroup_show_path,
};

static void __init cgroup_init_subsys(struct cgroup_subsys *ss, bool early)
{
	struct cgroup_subsys_state *css;

	pr_debug("Initializing cgroup subsys %s\n", ss->name);

	/* Create the top cgroup state for this subsystem */
	ss->root = &rootnode;
	css = ss->create(ss, dummytop);
	/* We don't handle early failures gracefully */
	BUG_ON(IS_ERR(css));
	init_cgroup_css(css, ss, dummytop);
	mutex_lock(&cgroup_mutex);

	idr_init(&ss->css_idr);
	INIT_LIST_HEAD(&ss->cfts);

	/* Create the root cgroup state for this subsystem */
	ss->root = &cgrp_dfl_root;
	css = ss->css_alloc(cgroup_css(&cgrp_dfl_root.cgrp, ss));
	/* We don't handle early failures gracefully */
	BUG_ON(IS_ERR(css));
	init_and_link_css(css, ss, &cgrp_dfl_root.cgrp);

	/*
	 * Root csses are never destroyed and we can't initialize
	 * percpu_ref during early init.  Disable refcnting.
	 */
	css->flags |= CSS_NO_REF;

	if (early) {
		/* allocation can't be done safely during early init */
		css->id = 1;
	} else {
		css->id = cgroup_idr_alloc(&ss->css_idr, css, 1, 2, GFP_KERNEL);
		BUG_ON(css->id < 0);
	}

	/* Update the init_css_set to contain a subsys
	 * pointer to this state - since the subsystem is
	 * newly registered, all tasks and hence the
	 * init_css_set is in the subsystem's top cgroup. */
	init_css_set.subsys[ss->subsys_id] = dummytop->subsys[ss->subsys_id];

	need_forkexit_callback |= ss->fork || ss->exit;
	need_mm_owner_callback |= !!ss->mm_owner_changed;
	 * init_css_set is in the subsystem's root cgroup. */
	init_css_set.subsys[ss->id] = css;

	have_fork_callback |= (bool)ss->fork << ss->id;
	have_exit_callback |= (bool)ss->exit << ss->id;
	have_free_callback |= (bool)ss->free << ss->id;
	have_canfork_callback |= (bool)ss->can_fork << ss->id;

	/* At system boot, before all subsystems have been
	 * registered, no tasks have been forked, so we don't
	 * need to invoke fork callbacks here. */
	BUG_ON(!list_empty(&init_task.tasks));

	ss->active = 1;
	BUG_ON(online_css(css));

	mutex_unlock(&cgroup_mutex);
}

/**
 * cgroup_init_early - cgroup initialization at system boot
 *
 * Initialize cgroups at system boot, and initialize any
 * subsystems that request early init.
 */
int __init cgroup_init_early(void)
{
	int i;
	kref_init(&init_css_set.ref);
	kref_get(&init_css_set.ref);
	INIT_LIST_HEAD(&init_css_set.cg_links);
	INIT_LIST_HEAD(&init_css_set.tasks);
	INIT_HLIST_NODE(&init_css_set.hlist);
	css_set_count = 1;
	init_cgroup_root(&rootnode);
	list_add(&rootnode.root_list, &roots);
	root_count = 1;
	init_task.cgroups = &init_css_set;

	init_css_set_link.cg = &init_css_set;
	list_add(&init_css_set_link.cgrp_link_list,
		 &rootnode.top_cgroup.css_sets);
	list_add(&init_css_set_link.cg_link_list,
		 &init_css_set.cg_links);

	for (i = 0; i < CSS_SET_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&css_set_table[i]);

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *ss = subsys[i];

		BUG_ON(!ss->name);
		BUG_ON(strlen(ss->name) > MAX_CGROUP_TYPE_NAMELEN);
		BUG_ON(!ss->create);
		BUG_ON(!ss->destroy);
		if (ss->subsys_id != i) {
			printk(KERN_ERR "cgroup: Subsys %s id == %d\n",
			       ss->name, ss->subsys_id);
			BUG();
		}

		if (ss->early_init)
			cgroup_init_subsys(ss);
	static struct cgroup_sb_opts __initdata opts;
	struct cgroup_subsys *ss;
	int i;

	init_cgroup_root(&cgrp_dfl_root, &opts);
	cgrp_dfl_root.cgrp.self.flags |= CSS_NO_REF;

	RCU_INIT_POINTER(init_task.cgroups, &init_css_set);

	for_each_subsys(ss, i) {
		WARN(!ss->css_alloc || !ss->css_free || ss->name || ss->id,
		     "invalid cgroup_subsys %d:%s css_alloc=%p css_free=%p id:name=%d:%s\n",
		     i, cgroup_subsys_name[i], ss->css_alloc, ss->css_free,
		     ss->id, ss->name);
		WARN(strlen(cgroup_subsys_name[i]) > MAX_CGROUP_TYPE_NAMELEN,
		     "cgroup_subsys_name %s too long\n", cgroup_subsys_name[i]);

		ss->id = i;
		ss->name = cgroup_subsys_name[i];
		if (!ss->legacy_name)
			ss->legacy_name = cgroup_subsys_name[i];

		if (ss->early_init)
			cgroup_init_subsys(ss, true);
	}
	return 0;
}

static u16 cgroup_disable_mask __initdata;

/**
 * cgroup_init - cgroup initialization
 *
 * Register cgroup filesystem and /proc file, and initialize
 * any subsystems that didn't request early init.
 */
int __init cgroup_init(void)
{
	int err;
	int i;
	struct hlist_head *hhead;

	err = bdi_init(&cgroup_backing_dev_info);
	if (err)
		return err;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *ss = subsys[i];
		if (!ss->early_init)
			cgroup_init_subsys(ss);
	}

	/* Add init_css_set to the hash table */
	hhead = css_set_hash(init_css_set.subsys);
	hlist_add_head(&init_css_set.hlist, hhead);

	err = register_filesystem(&cgroup_fs_type);
	if (err < 0)
		goto out;

	proc_create("cgroups", 0, NULL, &proc_cgroupstats_operations);

out:
	if (err)
		bdi_destroy(&cgroup_backing_dev_info);

	return err;
}

	struct cgroup_subsys *ss;
	int ssid;

	BUILD_BUG_ON(CGROUP_SUBSYS_COUNT > 16);
	BUG_ON(percpu_init_rwsem(&cgroup_threadgroup_rwsem));
	BUG_ON(cgroup_init_cftypes(NULL, cgroup_base_files));
	BUG_ON(cgroup_init_cftypes(NULL, cgroup1_base_files));

	/*
	 * The latency of the synchronize_sched() is too high for cgroups,
	 * avoid it at the cost of forcing all readers into the slow path.
	 */
	rcu_sync_enter_start(&cgroup_threadgroup_rwsem.rss);

	get_user_ns(init_cgroup_ns.user_ns);

	mutex_lock(&cgroup_mutex);

	/*
	 * Add init_css_set to the hash table so that dfl_root can link to
	 * it during init.
	 */
	hash_add(css_set_table, &init_css_set.hlist,
		 css_set_hash(init_css_set.subsys));

	BUG_ON(cgroup_setup_root(&cgrp_dfl_root, 0, 0));

	mutex_unlock(&cgroup_mutex);

	for_each_subsys(ss, ssid) {
		if (ss->early_init) {
			struct cgroup_subsys_state *css =
				init_css_set.subsys[ss->id];

			css->id = cgroup_idr_alloc(&ss->css_idr, css, 1, 2,
						   GFP_KERNEL);
			BUG_ON(css->id < 0);
		} else {
			cgroup_init_subsys(ss, false);
		}

		list_add_tail(&init_css_set.e_cset_node[ssid],
			      &cgrp_dfl_root.cgrp.e_csets[ssid]);

		/*
		 * Setting dfl_root subsys_mask needs to consider the
		 * disabled flag and cftype registration needs kmalloc,
		 * both of which aren't available during early_init.
		 */
		if (cgroup_disable_mask & (1 << ssid)) {
			static_branch_disable(cgroup_subsys_enabled_key[ssid]);
			printk(KERN_INFO "Disabling %s control group subsystem\n",
			       ss->name);
			continue;
		}

		if (cgroup1_ssid_disabled(ssid))
			printk(KERN_INFO "Disabling %s control group subsystem in v1 mounts\n",
			       ss->name);

		cgrp_dfl_root.subsys_mask |= 1 << ss->id;

		/* implicit controllers must be threaded too */
		WARN_ON(ss->implicit_on_dfl && !ss->threaded);

		if (ss->implicit_on_dfl)
			cgrp_dfl_implicit_ss_mask |= 1 << ss->id;
		else if (!ss->dfl_cftypes)
			cgrp_dfl_inhibit_ss_mask |= 1 << ss->id;

		if (ss->threaded)
			cgrp_dfl_threaded_ss_mask |= 1 << ss->id;

		if (ss->dfl_cftypes == ss->legacy_cftypes) {
			WARN_ON(cgroup_add_cftypes(ss, ss->dfl_cftypes));
		} else {
			WARN_ON(cgroup_add_dfl_cftypes(ss, ss->dfl_cftypes));
			WARN_ON(cgroup_add_legacy_cftypes(ss, ss->legacy_cftypes));
		}

		if (ss->bind)
			ss->bind(init_css_set.subsys[ssid]);

		mutex_lock(&cgroup_mutex);
		css_populate_dir(init_css_set.subsys[ssid]);
		mutex_unlock(&cgroup_mutex);
	}

	/* init_css_set.subsys[] has been updated, re-hash */
	hash_del(&init_css_set.hlist);
	hash_add(css_set_table, &init_css_set.hlist,
		 css_set_hash(init_css_set.subsys));

	WARN_ON(sysfs_create_mount_point(fs_kobj, "cgroup"));
	WARN_ON(register_filesystem(&cgroup_fs_type));
	WARN_ON(register_filesystem(&cgroup2_fs_type));
	WARN_ON(!proc_create("cgroups", 0, NULL, &proc_cgroupstats_operations));

	return 0;
}

static int __init cgroup_wq_init(void)
{
	/*
	 * There isn't much point in executing destruction path in
	 * parallel.  Good chunk is serialized with cgroup_mutex anyway.
	 * Use 1 for @max_active.
	 *
	 * We would prefer to do this in cgroup_init() above, but that
	 * is called before init_workqueues(): so leave this until after.
	 */
	cgroup_destroy_wq = alloc_workqueue("cgroup_destroy", 0, 1);
	BUG_ON(!cgroup_destroy_wq);
	return 0;
}
core_initcall(cgroup_wq_init);

void cgroup_path_from_kernfs_id(const union kernfs_node_id *id,
					char *buf, size_t buflen)
{
	struct kernfs_node *kn;

	kn = kernfs_get_node_by_id(cgrp_dfl_root.kf_root, id);
	if (!kn)
		return;
	kernfs_path(kn, buf, buflen);
	kernfs_put(kn);
}

/*
 * proc_cgroup_show()
 *  - Print task's cgroup paths into seq_file, one line for each hierarchy
 *  - Used for /proc/<pid>/cgroup.
 *  - No need to task_lock(tsk) on this tsk->cgroup reference, as it
 *    doesn't really matter if tsk->cgroup changes after we read it,
 *    and we take cgroup_mutex, keeping cgroup_attach_task() from changing it
 *    anyway.  No need to check that tsk->cgroup != NULL, thanks to
 *    the_top_cgroup_hack in cgroup_exit(), which sets an exiting tasks
 *    cgroup to top_cgroup.
 */

/* TODO: Use a proper seq_file iterator */
static int proc_cgroup_show(struct seq_file *m, void *v)
{
	struct pid *pid;
	struct task_struct *tsk;
	char *buf;
	int retval;
	struct cgroupfs_root *root;

	retval = -ENOMEM;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		goto out;

	retval = -ESRCH;
	pid = m->private;
	tsk = get_pid_task(pid, PIDTYPE_PID);
	if (!tsk)
		goto out_free;

	retval = 0;

	mutex_lock(&cgroup_mutex);
 */
int proc_cgroup_show(struct seq_file *m, struct pid_namespace *ns,
		     struct pid *pid, struct task_struct *tsk)
{
	char *buf;
	int retval;
	struct cgroup_root *root;

	retval = -ENOMEM;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		goto out;

	mutex_lock(&cgroup_mutex);
	spin_lock_irq(&css_set_lock);

	for_each_root(root) {
		struct cgroup_subsys *ss;
		struct cgroup *cgrp;
		int subsys_id;
		int count = 0;

		/* Skip this hierarchy if it has no active subsystems */
		if (!root->actual_subsys_bits)
			continue;
		seq_printf(m, "%lu:", root->subsys_bits);
		for_each_subsys(root, ss)
			seq_printf(m, "%s%s", count++ ? "," : "", ss->name);
		seq_putc(m, ':');
		get_first_subsys(&root->top_cgroup, NULL, &subsys_id);
		cgrp = task_cgroup(tsk, subsys_id);
		retval = cgroup_path(cgrp, buf, PAGE_SIZE);
		if (retval < 0)
			goto out_unlock;
		seq_puts(m, buf);
		seq_putc(m, '\n');
	}

out_unlock:
	mutex_unlock(&cgroup_mutex);
	put_task_struct(tsk);
out_free:
		int ssid, count = 0;

		if (root == &cgrp_dfl_root && !cgrp_dfl_visible)
			continue;

		seq_printf(m, "%d:", root->hierarchy_id);
		if (root != &cgrp_dfl_root)
			for_each_subsys(ss, ssid)
				if (root->subsys_mask & (1 << ssid))
					seq_printf(m, "%s%s", count++ ? "," : "",
						   ss->legacy_name);
		if (strlen(root->name))
			seq_printf(m, "%sname=%s", count ? "," : "",
				   root->name);
		seq_putc(m, ':');

		cgrp = task_cgroup_from_root(tsk, root);

		/*
		 * On traditional hierarchies, all zombie tasks show up as
		 * belonging to the root cgroup.  On the default hierarchy,
		 * while a zombie doesn't show up in "cgroup.procs" and
		 * thus can't be migrated, its /proc/PID/cgroup keeps
		 * reporting the cgroup it belonged to before exiting.  If
		 * the cgroup is removed before the zombie is reaped,
		 * " (deleted)" is appended to the cgroup path.
		 */
		if (cgroup_on_dfl(cgrp) || !(tsk->flags & PF_EXITING)) {
			retval = cgroup_path_ns_locked(cgrp, buf, PATH_MAX,
						current->nsproxy->cgroup_ns);
			if (retval >= PATH_MAX)
				retval = -ENAMETOOLONG;
			if (retval < 0)
				goto out_unlock;

			seq_puts(m, buf);
		} else {
			seq_puts(m, "/");
		}

		if (cgroup_on_dfl(cgrp) && cgroup_is_dead(cgrp))
			seq_puts(m, " (deleted)\n");
		else
			seq_putc(m, '\n');
	}

	retval = 0;
out_unlock:
	spin_unlock_irq(&css_set_lock);
	mutex_unlock(&cgroup_mutex);
	kfree(buf);
out:
	return retval;
}

static int cgroup_open(struct inode *inode, struct file *file)
{
	struct pid *pid = PROC_I(inode)->pid;
	return single_open(file, proc_cgroup_show, pid);
}

struct file_operations proc_cgroup_operations = {
	.open		= cgroup_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* Display information about each subsystem and each hierarchy */
static int proc_cgroupstats_show(struct seq_file *m, void *v)
{
	int i;

	seq_puts(m, "#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
	mutex_lock(&cgroup_mutex);
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *ss = subsys[i];
		seq_printf(m, "%s\t%lu\t%d\t%d\n",
			   ss->name, ss->root->subsys_bits,
			   ss->root->number_of_cgroups, !ss->disabled);
	}
/* Display information about each subsystem and each hierarchy */
static int proc_cgroupstats_show(struct seq_file *m, void *v)
{
	struct cgroup_subsys *ss;
	int i;

	seq_puts(m, "#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
	/*
	 * ideally we don't want subsystems moving around while we do this.
	 * cgroup_mutex is also necessary to guarantee an atomic snapshot of
	 * subsys/hierarchy state.
	 */
	mutex_lock(&cgroup_mutex);

	for_each_subsys(ss, i)
		seq_printf(m, "%s\t%d\t%d\t%d\n",
			   ss->legacy_name, ss->root->hierarchy_id,
			   atomic_read(&ss->root->nr_cgrps),
			   cgroup_ssid_enabled(i));

	mutex_unlock(&cgroup_mutex);
	return 0;
}

static int cgroupstats_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_cgroupstats_show, NULL);
}

static struct file_operations proc_cgroupstats_operations = {
static const struct file_operations proc_cgroupstats_operations = {
	.open = cgroupstats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * cgroup_fork - attach newly forked task to its parents cgroup.
 * @child: pointer to task_struct of forking parent process.
 *
 * Description: A task inherits its parent's cgroup at fork().
 *
 * A pointer to the shared css_set was automatically copied in
 * fork.c by dup_task_struct().  However, we ignore that copy, since
 * it was not made under the protection of RCU or cgroup_mutex, so
 * might no longer be a valid cgroup pointer.  cgroup_attach_task() might
 * have already changed current->cgroups, allowing the previously
 * referenced cgroup group to be removed and freed.
 *
 * At the point that cgroup_fork() is called, 'current' is the parent
 * task, and the passed argument 'child' points to the child task.
 */
void cgroup_fork(struct task_struct *child)
{
	task_lock(current);
	child->cgroups = current->cgroups;
	get_css_set(child->cgroups);
	task_unlock(current);
static void **subsys_canfork_priv_p(void *ss_priv[CGROUP_CANFORK_COUNT], int i)
{
	if (CGROUP_CANFORK_START <= i && i < CGROUP_CANFORK_END)
		return &ss_priv[i - CGROUP_CANFORK_START];
	return NULL;
}

static void *subsys_canfork_priv(void *ss_priv[CGROUP_CANFORK_COUNT], int i)
{
	void **private = subsys_canfork_priv_p(ss_priv, i);
	return private ? *private : NULL;
}

/**
 * cgroup_fork - initialize cgroup related fields during copy_process()
 * @child: pointer to task_struct of forking parent process.
 *
 * A task is associated with the init_css_set until cgroup_post_fork()
 * attaches it to the parent's css_set.  Empty cg_list indicates that
 * @child isn't holding reference to its css_set.
 */
void cgroup_fork(struct task_struct *child)
{
	RCU_INIT_POINTER(child->cgroups, &init_css_set);
	INIT_LIST_HEAD(&child->cg_list);
}

/**
 * cgroup_fork_callbacks - run fork callbacks
 * @child: the new task
 *
 * Called on a new task very soon before adding it to the
 * tasklist. No need to take any locks since no-one can
 * be operating on this task.
 */
void cgroup_fork_callbacks(struct task_struct *child)
{
	if (need_forkexit_callback) {
		int i;
		for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
			struct cgroup_subsys *ss = subsys[i];
			if (ss->fork)
				ss->fork(ss, child);
		}
	}
}

#ifdef CONFIG_MM_OWNER
/**
 * cgroup_mm_owner_callbacks - run callbacks when the mm->owner changes
 * @p: the new owner
 *
 * Called on every change to mm->owner. mm_init_owner() does not
 * invoke this routine, since it assigns the mm->owner the first time
 * and does not change it.
 */
void cgroup_mm_owner_callbacks(struct task_struct *old, struct task_struct *new)
{
	struct cgroup *oldcgrp, *newcgrp = NULL;

	if (need_mm_owner_callback) {
		int i;
		for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
			struct cgroup_subsys *ss = subsys[i];
			oldcgrp = task_cgroup(old, ss->subsys_id);
			if (new)
				newcgrp = task_cgroup(new, ss->subsys_id);
			if (oldcgrp == newcgrp)
				continue;
			if (ss->mm_owner_changed)
				ss->mm_owner_changed(ss, oldcgrp, newcgrp);
		}
	}
}
#endif /* CONFIG_MM_OWNER */
 * cgroup_can_fork - called on a new task before the process is exposed
 * @child: the task in question.
 *
 * This calls the subsystem can_fork() callbacks. If the can_fork() callback
 * returns an error, the fork aborts with that error code. This allows for
 * a cgroup subsystem to conditionally allow or deny new forks.
 */
int cgroup_can_fork(struct task_struct *child)
{
	struct cgroup_subsys *ss;
	int i, j, ret;

	do_each_subsys_mask(ss, i, have_canfork_callback) {
		ret = ss->can_fork(child);
		if (ret)
			goto out_revert;
	} while_each_subsys_mask();

	return 0;

out_revert:
	for_each_subsys(ss, j) {
		if (j >= i)
			break;
		if (ss->cancel_fork)
			ss->cancel_fork(child);
	}

	return ret;
}

/**
 * cgroup_cancel_fork - called if a fork failed after cgroup_can_fork()
 * @child: the task in question
 *
 * This calls the cancel_fork() callbacks if a fork failed *after*
 * cgroup_can_fork() succeded.
 */
void cgroup_cancel_fork(struct task_struct *child)
{
	struct cgroup_subsys *ss;
	int i;

	for_each_subsys(ss, i)
		if (ss->cancel_fork)
			ss->cancel_fork(child);
}

/**
 * cgroup_post_fork - called on a new task after adding it to the task list
 * @child: the task in question
 *
 * Adds the task to the list running through its css_set if necessary.
 * Has to be after the task is visible on the task list in case we race
 * with the first call to cgroup_iter_start() - to guarantee that the
 * new task ends up on its list.
 */
void cgroup_post_fork(struct task_struct *child)
{
	if (use_task_css_set_links) {
		write_lock(&css_set_lock);
		if (list_empty(&child->cg_list))
			list_add(&child->cg_list, &child->cgroups->tasks);
		write_unlock(&css_set_lock);
	}
}
/**
 * cgroup_exit - detach cgroup from exiting task
 * @tsk: pointer to task_struct of exiting process
 * @run_callback: run exit callbacks?
 * Adds the task to the list running through its css_set if necessary and
 * call the subsystem fork() callbacks.  Has to be after the task is
 * visible on the task list in case we race with the first call to
 * cgroup_task_iter_start() - to guarantee that the new task ends up on its
 * list.
 */
void cgroup_post_fork(struct task_struct *child)
{
	struct cgroup_subsys *ss;
	int i;

	/*
	 * This may race against cgroup_enable_task_cg_lists().  As that
	 * function sets use_task_css_set_links before grabbing
	 * tasklist_lock and we just went through tasklist_lock to add
	 * @child, it's guaranteed that either we see the set
	 * use_task_css_set_links or cgroup_enable_task_cg_lists() sees
	 * @child during its iteration.
	 *
	 * If we won the race, @child is associated with %current's
	 * css_set.  Grabbing css_set_lock guarantees both that the
	 * association is stable, and, on completion of the parent's
	 * migration, @child is visible in the source of migration or
	 * already in the destination cgroup.  This guarantee is necessary
	 * when implementing operations which need to migrate all tasks of
	 * a cgroup to another.
	 *
	 * Note that if we lose to cgroup_enable_task_cg_lists(), @child
	 * will remain in init_css_set.  This is safe because all tasks are
	 * in the init_css_set before cg_links is enabled and there's no
	 * operation which transfers all tasks out of init_css_set.
	 */
	if (use_task_css_set_links) {
		struct css_set *cset;

		spin_lock_irq(&css_set_lock);
		cset = task_css_set(current);
		if (list_empty(&child->cg_list)) {
			get_css_set(cset);
			cset->nr_tasks++;
			css_set_move_task(child, NULL, cset, false);
		}
		spin_unlock_irq(&css_set_lock);
	}

	/*
	 * Call ss->fork().  This must happen after @child is linked on
	 * css_set; otherwise, @child might change state between ->fork()
	 * and addition to css_set.
	 */
	do_each_subsys_mask(ss, i, have_fork_callback) {
		ss->fork(child);
	} while_each_subsys_mask();
}

/**
 * cgroup_exit - detach cgroup from exiting task
 * @tsk: pointer to task_struct of exiting process
 *
 * Description: Detach cgroup from @tsk and release it.
 *
 * Note that cgroups marked notify_on_release force every task in
 * them to take the global cgroup_mutex mutex when exiting.
 * This could impact scaling on very large systems.  Be reluctant to
 * use notify_on_release cgroups where very high task exit scaling
 * is required on large systems.
 *
 * the_top_cgroup_hack:
 *
 *    Set the exiting tasks cgroup to the root cgroup (top_cgroup).
 *
 *    We call cgroup_exit() while the task is still competent to
 *    handle notify_on_release(), then leave the task attached to the
 *    root cgroup in each hierarchy for the remainder of its exit.
 *
 *    To do this properly, we would increment the reference count on
 *    top_cgroup, and near the very end of the kernel/exit.c do_exit()
 *    code we would add a second cgroup function call, to drop that
 *    reference.  This would just create an unnecessary hot spot on
 *    the top_cgroup reference count, to no avail.
 *
 *    Normally, holding a reference to a cgroup without bumping its
 *    count is unsafe.   The cgroup could go away, or someone could
 *    attach us to a different cgroup, decrementing the count on
 *    the first cgroup that we never incremented.  But in this case,
 *    top_cgroup isn't going away, and either task has PF_EXITING set,
 *    which wards off any cgroup_attach_task() attempts, or task is a failed
 *    fork, never visible to cgroup_attach_task.
 */
void cgroup_exit(struct task_struct *tsk, int run_callbacks)
{
	int i;
	struct css_set *cg;

	if (run_callbacks && need_forkexit_callback) {
		for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
			struct cgroup_subsys *ss = subsys[i];
			if (ss->exit)
				ss->exit(ss, tsk);
		}
	}

	/*
	 * Unlink from the css_set task list if necessary.
	 * Optimistically check cg_list before taking
	 * css_set_lock
	 */
	if (!list_empty(&tsk->cg_list)) {
		write_lock(&css_set_lock);
		if (!list_empty(&tsk->cg_list))
			list_del(&tsk->cg_list);
		write_unlock(&css_set_lock);
	}

	/* Reassign the task to the init_css_set. */
	task_lock(tsk);
	cg = tsk->cgroups;
	tsk->cgroups = &init_css_set;
	task_unlock(tsk);
	if (cg)
		put_css_set_taskexit(cg);
}

/**
 * cgroup_clone - clone the cgroup the given subsystem is attached to
 * @tsk: the task to be moved
 * @subsys: the given subsystem
 * @nodename: the name for the new cgroup
 *
 * Duplicate the current cgroup in the hierarchy that the given
 * subsystem is attached to, and move this task into the new
 * child.
 */
int cgroup_clone(struct task_struct *tsk, struct cgroup_subsys *subsys,
							char *nodename)
{
	struct dentry *dentry;
	int ret = 0;
	struct cgroup *parent, *child;
	struct inode *inode;
	struct css_set *cg;
	struct cgroupfs_root *root;
	struct cgroup_subsys *ss;

	/* We shouldn't be called by an unregistered subsystem */
	BUG_ON(!subsys->active);

	/* First figure out what hierarchy and cgroup we're dealing
	 * with, and pin them so we can drop cgroup_mutex */
	mutex_lock(&cgroup_mutex);
 again:
	root = subsys->root;
	if (root == &rootnode) {
		printk(KERN_INFO
		       "Not cloning cgroup for unused subsystem %s\n",
		       subsys->name);
		mutex_unlock(&cgroup_mutex);
		return 0;
	}
	cg = tsk->cgroups;
	parent = task_cgroup(tsk, subsys->subsys_id);

	/* Pin the hierarchy */
	atomic_inc(&parent->root->sb->s_active);

	/* Keep the cgroup alive */
	get_css_set(cg);
	mutex_unlock(&cgroup_mutex);

	/* Now do the VFS work to create a cgroup */
	inode = parent->dentry->d_inode;

	/* Hold the parent directory mutex across this operation to
	 * stop anyone else deleting the new cgroup */
	mutex_lock(&inode->i_mutex);
	dentry = lookup_one_len(nodename, parent->dentry, strlen(nodename));
	if (IS_ERR(dentry)) {
		printk(KERN_INFO
		       "cgroup: Couldn't allocate dentry for %s: %ld\n", nodename,
		       PTR_ERR(dentry));
		ret = PTR_ERR(dentry);
		goto out_release;
	}

	/* Create the cgroup directory, which also creates the cgroup */
	ret = vfs_mkdir(inode, dentry, S_IFDIR | 0755);
	child = __d_cgrp(dentry);
	dput(dentry);
	if (ret) {
		printk(KERN_INFO
		       "Failed to create cgroup %s: %d\n", nodename,
		       ret);
		goto out_release;
	}

	if (!child) {
		printk(KERN_INFO
		       "Couldn't find new cgroup %s\n", nodename);
		ret = -ENOMEM;
		goto out_release;
	}

	/* The cgroup now exists. Retake cgroup_mutex and check
	 * that we're still in the same state that we thought we
	 * were. */
	mutex_lock(&cgroup_mutex);
	if ((root != subsys->root) ||
	    (parent != task_cgroup(tsk, subsys->subsys_id))) {
		/* Aargh, we raced ... */
		mutex_unlock(&inode->i_mutex);
		put_css_set(cg);

		deactivate_super(parent->root->sb);
		/* The cgroup is still accessible in the VFS, but
		 * we're not going to try to rmdir() it at this
		 * point. */
		printk(KERN_INFO
		       "Race in cgroup_clone() - leaking cgroup %s\n",
		       nodename);
		goto again;
	}

	/* do any required auto-setup */
	for_each_subsys(root, ss) {
		if (ss->post_clone)
			ss->post_clone(ss, child);
	}

	/* All seems fine. Finish by moving the task into the new cgroup */
	ret = cgroup_attach_task(child, tsk);
	mutex_unlock(&cgroup_mutex);

 out_release:
	mutex_unlock(&inode->i_mutex);

	mutex_lock(&cgroup_mutex);
	put_css_set(cg);
	mutex_unlock(&cgroup_mutex);
	deactivate_super(parent->root->sb);
	return ret;
}

/**
 * cgroup_is_descendant - see if @cgrp is a descendant of current task's cgrp
 * @cgrp: the cgroup in question
 *
 * See if @cgrp is a descendant of the current task's cgroup in
 * the appropriate hierarchy.
 *
 * If we are sending in dummytop, then presumably we are creating
 * the top cgroup in the subsystem.
 *
 * Called only by the ns (nsproxy) cgroup.
 */
int cgroup_is_descendant(const struct cgroup *cgrp)
{
	int ret;
	struct cgroup *target;
	int subsys_id;

	if (cgrp == dummytop)
		return 1;

	get_first_subsys(cgrp, NULL, &subsys_id);
	target = task_cgroup(current, subsys_id);
	while (cgrp != target && cgrp!= cgrp->top_cgroup)
		cgrp = cgrp->parent;
	ret = (cgrp == target);
	return ret;
 * We set the exiting tasks cgroup to the root cgroup (top_cgroup).  We
 * call cgroup_exit() while the task is still competent to handle
 * notify_on_release(), then leave the task attached to the root cgroup in
 * each hierarchy for the remainder of its exit.  No need to bother with
 * init_css_set refcnting.  init_css_set never goes away and we can't race
 * with migration path - PF_EXITING is visible to migration path.
 */
void cgroup_exit(struct task_struct *tsk)
{
	struct cgroup_subsys *ss;
	struct css_set *cset;
	int i;

	/*
	 * Unlink from @tsk from its css_set.  As migration path can't race
	 * with us, we can check css_set and cg_list without synchronization.
	 */
	cset = task_css_set(tsk);

	if (!list_empty(&tsk->cg_list)) {
		spin_lock_irq(&css_set_lock);
		css_set_move_task(tsk, cset, NULL, false);
		cset->nr_tasks--;
		spin_unlock_irq(&css_set_lock);
	} else {
		get_css_set(cset);
	}

	/* see cgroup_post_fork() for details */
	do_each_subsys_mask(ss, i, have_exit_callback) {
		ss->exit(tsk);
	} while_each_subsys_mask();
}

void cgroup_free(struct task_struct *task)
{
	struct css_set *cset = task_css_set(task);
	struct cgroup_subsys *ss;
	int ssid;

	do_each_subsys_mask(ss, ssid, have_free_callback) {
		ss->free(task);
	} while_each_subsys_mask();

	put_css_set(cset);
}

static void check_for_release(struct cgroup *cgrp)
{
	/* All of these checks rely on RCU to keep the cgroup
	 * structure alive */
	if (cgroup_is_releasable(cgrp) && !atomic_read(&cgrp->count)
	    && list_empty(&cgrp->children) && !cgroup_has_css_refs(cgrp)) {
		/* Control Group is currently removeable. If it's not
		 * already queued for a userspace notification, queue
		 * it now */
		int need_schedule_work = 0;
		spin_lock(&release_list_lock);
		if (!cgroup_is_removed(cgrp) &&
		    list_empty(&cgrp->release_list)) {
			list_add(&cgrp->release_list, &release_list);
			need_schedule_work = 1;
		}
		spin_unlock(&release_list_lock);
		if (need_schedule_work)
			schedule_work(&release_agent_work);
	}
}

void __css_put(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = css->cgroup;
	rcu_read_lock();
	if (atomic_dec_and_test(&css->refcnt) && notify_on_release(cgrp)) {
		set_bit(CGRP_RELEASABLE, &cgrp->flags);
		check_for_release(cgrp);
	}
	rcu_read_unlock();
	if (notify_on_release(cgrp) && !cgroup_is_populated(cgrp) &&
	    !css_has_online_children(&cgrp->self) && !cgroup_is_dead(cgrp))
		schedule_work(&cgrp->release_agent_work);
}

/*
 * Notify userspace when a cgroup is released, by running the
 * configured release agent with the name of the cgroup (path
 * relative to the root of cgroup file system) as the argument.
 *
 * Most likely, this user command will try to rmdir this cgroup.
 *
 * This races with the possibility that some other task will be
 * attached to this cgroup before it is removed, or that some other
 * user task will 'mkdir' a child cgroup of this cgroup.  That's ok.
 * The presumed 'rmdir' will fail quietly if this cgroup is no longer
 * unused, and this cgroup will be reprieved from its death sentence,
 * to continue to serve a useful existence.  Next time it's released,
 * we will get notified again, if it still has 'notify_on_release' set.
 *
 * The final arg to call_usermodehelper() is UMH_WAIT_EXEC, which
 * means only wait until the task is successfully execve()'d.  The
 * separate release agent task is forked by call_usermodehelper(),
 * then control in this thread returns here, without waiting for the
 * release agent task.  We don't bother to wait because the caller of
 * this routine has no use for the exit status of the release agent
 * task, so no sense holding our caller up for that.
 */
static void cgroup_release_agent(struct work_struct *work)
{
	BUG_ON(work != &release_agent_work);
	mutex_lock(&cgroup_mutex);
	spin_lock(&release_list_lock);
	while (!list_empty(&release_list)) {
		char *argv[3], *envp[3];
		int i;
		char *pathbuf = NULL, *agentbuf = NULL;
		struct cgroup *cgrp = list_entry(release_list.next,
						    struct cgroup,
						    release_list);
		list_del_init(&cgrp->release_list);
		spin_unlock(&release_list_lock);
		pathbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!pathbuf)
			goto continue_free;
		if (cgroup_path(cgrp, pathbuf, PAGE_SIZE) < 0)
			goto continue_free;
		agentbuf = kstrdup(cgrp->root->release_agent_path, GFP_KERNEL);
		if (!agentbuf)
			goto continue_free;

		i = 0;
		argv[i++] = agentbuf;
		argv[i++] = pathbuf;
		argv[i] = NULL;

		i = 0;
		/* minimal command environment */
		envp[i++] = "HOME=/";
		envp[i++] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
		envp[i] = NULL;

		/* Drop the lock while we invoke the usermode helper,
		 * since the exec could involve hitting disk and hence
		 * be a slow process */
		mutex_unlock(&cgroup_mutex);
		call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
		mutex_lock(&cgroup_mutex);
 continue_free:
		kfree(pathbuf);
		kfree(agentbuf);
		spin_lock(&release_list_lock);
	}
	spin_unlock(&release_list_lock);
	mutex_unlock(&cgroup_mutex);
	struct cgroup *cgrp =
		container_of(work, struct cgroup, release_agent_work);
	char *pathbuf = NULL, *agentbuf = NULL, *path;
	char *argv[3], *envp[3];

	mutex_lock(&cgroup_mutex);

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	agentbuf = kstrdup(cgrp->root->release_agent_path, GFP_KERNEL);
	if (!pathbuf || !agentbuf)
		goto out;

	path = cgroup_path(cgrp, pathbuf, PATH_MAX);
	if (!path)
		goto out;

	argv[0] = agentbuf;
	argv[1] = path;
	argv[2] = NULL;

	/* minimal command environment */
	envp[0] = "HOME=/";
	envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;

	mutex_unlock(&cgroup_mutex);
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	goto out_free;
out:
	mutex_unlock(&cgroup_mutex);
out_free:
	kfree(agentbuf);
	kfree(pathbuf);
}

static int __init cgroup_disable(char *str)
{
	int i;
	char *token;
	struct cgroup_subsys *ss;
	char *token;
	int i;

	while ((token = strsep(&str, ",")) != NULL) {
		if (!*token)
			continue;

		for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
			struct cgroup_subsys *ss = subsys[i];

			if (!strcmp(token, ss->name)) {
				ss->disabled = 1;
				printk(KERN_INFO "Disabling %s control group"
					" subsystem\n", ss->name);
				break;
			}
		for_each_subsys(ss, i) {
			if (strcmp(token, ss->name) &&
			    strcmp(token, ss->legacy_name))
				continue;
			cgroup_disable_mask |= 1 << i;
		}
	}
	return 1;
}
__setup("cgroup_disable=", cgroup_disable);

/**
 * css_tryget_online_from_dir - get corresponding css from a cgroup dentry
 * @dentry: directory dentry of interest
 * @ss: subsystem of interest
 *
 * If @dentry is a directory for a cgroup which has @ss enabled on it, try
 * to get the corresponding css and return it.  If such css doesn't exist
 * or can't be pinned, an ERR_PTR value is returned.
 */
struct cgroup_subsys_state *css_tryget_online_from_dir(struct dentry *dentry,
						       struct cgroup_subsys *ss)
{
	struct kernfs_node *kn = kernfs_node_from_dentry(dentry);
	struct file_system_type *s_type = dentry->d_sb->s_type;
	struct cgroup_subsys_state *css = NULL;
	struct cgroup *cgrp;

	/* is @dentry a cgroup dir? */
	if ((s_type != &cgroup_fs_type && s_type != &cgroup2_fs_type) ||
	    !kn || kernfs_type(kn) != KERNFS_DIR)
		return ERR_PTR(-EBADF);

	rcu_read_lock();

	/*
	 * This path doesn't originate from kernfs and @kn could already
	 * have been or be removed at any point.  @kn->priv is RCU
	 * protected for this access.  See css_release_work_fn() for details.
	 */
	cgrp = rcu_dereference(*(void __rcu __force **)&kn->priv);
	if (cgrp)
		css = cgroup_css(cgrp, ss);

	if (!css || !css_tryget_online(css))
		css = ERR_PTR(-ENOENT);

	rcu_read_unlock();
	return css;
}

/**
 * css_from_id - lookup css by id
 * @id: the cgroup id
 * @ss: cgroup subsys to be looked into
 *
 * Returns the css if there's valid one with @id, otherwise returns NULL.
 * Should be called under rcu_read_lock().
 */
struct cgroup_subsys_state *css_from_id(int id, struct cgroup_subsys *ss)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return idr_find(&ss->css_idr, id);
}

/**
 * cgroup_get_from_path - lookup and get a cgroup from its default hierarchy path
 * @path: path on the default hierarchy
 *
 * Find the cgroup at @path on the default hierarchy, increment its
 * reference count and return it.  Returns pointer to the found cgroup on
 * success, ERR_PTR(-ENOENT) if @path doens't exist and ERR_PTR(-ENOTDIR)
 * if @path points to a non-directory.
 */
struct cgroup *cgroup_get_from_path(const char *path)
{
	struct kernfs_node *kn;
	struct cgroup *cgrp;

	mutex_lock(&cgroup_mutex);

	kn = kernfs_walk_and_get(cgrp_dfl_root.cgrp.kn, path);
	if (kn) {
		if (kernfs_type(kn) == KERNFS_DIR) {
			cgrp = kn->priv;
			cgroup_get_live(cgrp);
		} else {
			cgrp = ERR_PTR(-ENOTDIR);
		}
		kernfs_put(kn);
	} else {
		cgrp = ERR_PTR(-ENOENT);
	}

	mutex_unlock(&cgroup_mutex);
	return cgrp;
}
EXPORT_SYMBOL_GPL(cgroup_get_from_path);

/**
 * cgroup_get_from_fd - get a cgroup pointer from a fd
 * @fd: fd obtained by open(cgroup2_dir)
 *
 * Find the cgroup from a fd which should be obtained
 * by opening a cgroup directory.  Returns a pointer to the
 * cgroup on success. ERR_PTR is returned if the cgroup
 * cannot be found.
 */
struct cgroup *cgroup_get_from_fd(int fd)
{
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;
	struct file *f;

	f = fget_raw(fd);
	if (!f)
		return ERR_PTR(-EBADF);

	css = css_tryget_online_from_dir(f->f_path.dentry, NULL);
	fput(f);
	if (IS_ERR(css))
		return ERR_CAST(css);

	cgrp = css->cgroup;
	if (!cgroup_on_dfl(cgrp)) {
		cgroup_put(cgrp);
		return ERR_PTR(-EBADF);
	}

	return cgrp;
}
EXPORT_SYMBOL_GPL(cgroup_get_from_fd);

/*
 * sock->sk_cgrp_data handling.  For more info, see sock_cgroup_data
 * definition in cgroup-defs.h.
 */
#ifdef CONFIG_SOCK_CGROUP_DATA

#if defined(CONFIG_CGROUP_NET_PRIO) || defined(CONFIG_CGROUP_NET_CLASSID)

DEFINE_SPINLOCK(cgroup_sk_update_lock);
static bool cgroup_sk_alloc_disabled __read_mostly;

void cgroup_sk_alloc_disable(void)
{
	if (cgroup_sk_alloc_disabled)
		return;
	pr_info("cgroup: disabling cgroup2 socket matching due to net_prio or net_cls activation\n");
	cgroup_sk_alloc_disabled = true;
}

#else

#define cgroup_sk_alloc_disabled	false

#endif

void cgroup_sk_alloc(struct sock_cgroup_data *skcd)
{
	if (cgroup_sk_alloc_disabled)
		return;

	/* Socket clone path */
	if (skcd->val) {
		/*
		 * We might be cloning a socket which is left in an empty
		 * cgroup and the cgroup might have already been rmdir'd.
		 * Don't use cgroup_get_live().
		 */
		cgroup_get(sock_cgroup_ptr(skcd));
		return;
	}

	rcu_read_lock();

	while (true) {
		struct css_set *cset;

		cset = task_css_set(current);
		if (likely(cgroup_tryget(cset->dfl_cgrp))) {
			skcd->val = (unsigned long)cset->dfl_cgrp;
			break;
		}
		cpu_relax();
	}

	rcu_read_unlock();
}

void cgroup_sk_free(struct sock_cgroup_data *skcd)
{
	cgroup_put(sock_cgroup_ptr(skcd));
}

#endif	/* CONFIG_SOCK_CGROUP_DATA */

#ifdef CONFIG_CGROUP_BPF
int cgroup_bpf_update(struct cgroup *cgrp, struct bpf_prog *prog,
		      enum bpf_attach_type type, bool overridable)
{
	struct cgroup *parent = cgroup_parent(cgrp);
	int ret;

	mutex_lock(&cgroup_mutex);
	ret = __cgroup_bpf_update(cgrp, parent, prog, type, overridable);
	mutex_unlock(&cgroup_mutex);
	return ret;
}
#endif /* CONFIG_CGROUP_BPF */
