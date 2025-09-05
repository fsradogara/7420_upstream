/*
 * xfrm_state.c
 *
 * Changes:
 *	Mitsuru KANDA @USAGI
 * 	Kazunori MIYAZAWA @USAGI
 * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
 * 		IPv6 support
 * 	YOSHIFUJI Hideaki @USAGI
 * 		Split up af-specific functions
 *	Derek Atkins <derek@ihtfp.com>
 *		Add UDP Encapsulation
 *
 */

#include <linux/workqueue.h>
#include <net/xfrm.h>
#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <linux/audit.h>
#include <asm/uaccess.h>

#include "xfrm_hash.h"

struct sock *xfrm_nl;
EXPORT_SYMBOL(xfrm_nl);

u32 sysctl_xfrm_aevent_etime __read_mostly = XFRM_AE_ETIME;
EXPORT_SYMBOL(sysctl_xfrm_aevent_etime);

u32 sysctl_xfrm_aevent_rseqth __read_mostly = XFRM_AE_SEQT_SIZE;
EXPORT_SYMBOL(sysctl_xfrm_aevent_rseqth);

u32 sysctl_xfrm_acq_expires __read_mostly = 30;

#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>

#include "xfrm_hash.h"

#define xfrm_state_deref_prot(table, net) \
	rcu_dereference_protected((table), lockdep_is_held(&(net)->xfrm.xfrm_state_lock))

static void xfrm_state_gc_task(struct work_struct *work);

/* Each xfrm_state may be linked to two tables:

   1. Hash table by (spi,daddr,ah/esp) to find SA by SPI. (input,ctl)
   2. Hash table by (daddr,family,reqid) to find what SAs exist for given
      destination/tunnel endpoint. (output)
 */

static DEFINE_SPINLOCK(xfrm_state_lock);

/* Hash table to find appropriate SA towards given target (endpoint
 * of tunnel or destination of transport mode) allowed by selector.
 *
 * Main use is finding SA after policy selected tunnel or transport mode.
 * Also, it can be used by ah/esp icmp error handler to find offending SA.
 */
static LIST_HEAD(xfrm_state_all);
static struct hlist_head *xfrm_state_bydst __read_mostly;
static struct hlist_head *xfrm_state_bysrc __read_mostly;
static struct hlist_head *xfrm_state_byspi __read_mostly;
static unsigned int xfrm_state_hmask __read_mostly;
static unsigned int xfrm_state_hashmax __read_mostly = 1 * 1024 * 1024;
static unsigned int xfrm_state_num;
static unsigned int xfrm_state_genid;

static struct xfrm_state_afinfo *xfrm_state_get_afinfo(unsigned int family);
static void xfrm_state_put_afinfo(struct xfrm_state_afinfo *afinfo);

#ifdef CONFIG_AUDITSYSCALL
static void xfrm_audit_state_replay(struct xfrm_state *x,
				    struct sk_buff *skb, __be32 net_seq);
#else
#define xfrm_audit_state_replay(x, s, sq)	do { ; } while (0)
#endif /* CONFIG_AUDITSYSCALL */

static inline unsigned int xfrm_dst_hash(xfrm_address_t *daddr,
					 xfrm_address_t *saddr,
					 u32 reqid,
					 unsigned short family)
{
	return __xfrm_dst_hash(daddr, saddr, reqid, family, xfrm_state_hmask);
}

static inline unsigned int xfrm_src_hash(xfrm_address_t *daddr,
					 xfrm_address_t *saddr,
					 unsigned short family)
{
	return __xfrm_src_hash(daddr, saddr, family, xfrm_state_hmask);
}

static inline unsigned int
xfrm_spi_hash(xfrm_address_t *daddr, __be32 spi, u8 proto, unsigned short family)
{
	return __xfrm_spi_hash(daddr, spi, proto, family, xfrm_state_hmask);
static unsigned int xfrm_state_hashmax __read_mostly = 1 * 1024 * 1024;
static __read_mostly seqcount_t xfrm_state_hash_generation = SEQCNT_ZERO(xfrm_state_hash_generation);
static struct kmem_cache *xfrm_state_cache __ro_after_init;

static DECLARE_WORK(xfrm_state_gc_work, xfrm_state_gc_task);
static HLIST_HEAD(xfrm_state_gc_list);

static inline bool xfrm_state_hold_rcu(struct xfrm_state __rcu *x)
{
	return refcount_inc_not_zero(&x->refcnt);
}

static inline unsigned int xfrm_dst_hash(struct net *net,
					 const xfrm_address_t *daddr,
					 const xfrm_address_t *saddr,
					 u32 reqid,
					 unsigned short family)
{
	return __xfrm_dst_hash(daddr, saddr, reqid, family, net->xfrm.state_hmask);
}

static inline unsigned int xfrm_src_hash(struct net *net,
					 const xfrm_address_t *daddr,
					 const xfrm_address_t *saddr,
					 unsigned short family)
{
	return __xfrm_src_hash(daddr, saddr, family, net->xfrm.state_hmask);
}

static inline unsigned int
xfrm_spi_hash(struct net *net, const xfrm_address_t *daddr,
	      __be32 spi, u8 proto, unsigned short family)
{
	return __xfrm_spi_hash(daddr, spi, proto, family, net->xfrm.state_hmask);
}

static void xfrm_hash_transfer(struct hlist_head *list,
			       struct hlist_head *ndsttable,
			       struct hlist_head *nsrctable,
			       struct hlist_head *nspitable,
			       unsigned int nhashmask)
{
	struct hlist_node *entry, *tmp;
	struct xfrm_state *x;

	hlist_for_each_entry_safe(x, entry, tmp, list, bydst) {
	struct hlist_node *tmp;
	struct xfrm_state *x;

	hlist_for_each_entry_safe(x, tmp, list, bydst) {
		unsigned int h;

		h = __xfrm_dst_hash(&x->id.daddr, &x->props.saddr,
				    x->props.reqid, x->props.family,
				    nhashmask);
		hlist_add_head_rcu(&x->bydst, ndsttable + h);

		h = __xfrm_src_hash(&x->id.daddr, &x->props.saddr,
				    x->props.family,
				    nhashmask);
		hlist_add_head_rcu(&x->bysrc, nsrctable + h);

		if (x->id.spi) {
			h = __xfrm_spi_hash(&x->id.daddr, x->id.spi,
					    x->id.proto, x->props.family,
					    nhashmask);
			hlist_add_head_rcu(&x->byspi, nspitable + h);
		}
	}
}

static unsigned long xfrm_hash_new_size(void)
{
	return ((xfrm_state_hmask + 1) << 1) *
		sizeof(struct hlist_head);
}

static DEFINE_MUTEX(hash_resize_mutex);

static void xfrm_hash_resize(struct work_struct *__unused)
{
static unsigned long xfrm_hash_new_size(unsigned int state_hmask)
{
	return ((state_hmask + 1) << 1) * sizeof(struct hlist_head);
}

static void xfrm_hash_resize(struct work_struct *work)
{
	struct net *net = container_of(work, struct net, xfrm.state_hash_work);
	struct hlist_head *ndst, *nsrc, *nspi, *odst, *osrc, *ospi;
	unsigned long nsize, osize;
	unsigned int nhashmask, ohashmask;
	int i;

	mutex_lock(&hash_resize_mutex);

	nsize = xfrm_hash_new_size();
	ndst = xfrm_hash_alloc(nsize);
	if (!ndst)
		goto out_unlock;
	nsrc = xfrm_hash_alloc(nsize);
	if (!nsrc) {
		xfrm_hash_free(ndst, nsize);
		goto out_unlock;
	nsize = xfrm_hash_new_size(net->xfrm.state_hmask);
	ndst = xfrm_hash_alloc(nsize);
	if (!ndst)
		return;
	nsrc = xfrm_hash_alloc(nsize);
	if (!nsrc) {
		xfrm_hash_free(ndst, nsize);
		return;
	}
	nspi = xfrm_hash_alloc(nsize);
	if (!nspi) {
		xfrm_hash_free(ndst, nsize);
		xfrm_hash_free(nsrc, nsize);
		goto out_unlock;
	}

	spin_lock_bh(&xfrm_state_lock);

	nhashmask = (nsize / sizeof(struct hlist_head)) - 1U;
	for (i = xfrm_state_hmask; i >= 0; i--)
		xfrm_hash_transfer(xfrm_state_bydst+i, ndst, nsrc, nspi,
				   nhashmask);

	odst = xfrm_state_bydst;
	osrc = xfrm_state_bysrc;
	ospi = xfrm_state_byspi;
	ohashmask = xfrm_state_hmask;

	xfrm_state_bydst = ndst;
	xfrm_state_bysrc = nsrc;
	xfrm_state_byspi = nspi;
	xfrm_state_hmask = nhashmask;

	spin_unlock_bh(&xfrm_state_lock);
		return;
	}

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	write_seqcount_begin(&xfrm_state_hash_generation);

	nhashmask = (nsize / sizeof(struct hlist_head)) - 1U;
	odst = xfrm_state_deref_prot(net->xfrm.state_bydst, net);
	for (i = net->xfrm.state_hmask; i >= 0; i--)
		xfrm_hash_transfer(odst + i, ndst, nsrc, nspi, nhashmask);

	osrc = xfrm_state_deref_prot(net->xfrm.state_bysrc, net);
	ospi = xfrm_state_deref_prot(net->xfrm.state_byspi, net);
	ohashmask = net->xfrm.state_hmask;

	rcu_assign_pointer(net->xfrm.state_bydst, ndst);
	rcu_assign_pointer(net->xfrm.state_bysrc, nsrc);
	rcu_assign_pointer(net->xfrm.state_byspi, nspi);
	net->xfrm.state_hmask = nhashmask;

	write_seqcount_end(&xfrm_state_hash_generation);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	osize = (ohashmask + 1) * sizeof(struct hlist_head);

	synchronize_rcu();

	xfrm_hash_free(odst, osize);
	xfrm_hash_free(osrc, osize);
	xfrm_hash_free(ospi, osize);

out_unlock:
	mutex_unlock(&hash_resize_mutex);
}

static DECLARE_WORK(xfrm_hash_work, xfrm_hash_resize);

DECLARE_WAIT_QUEUE_HEAD(km_waitq);
EXPORT_SYMBOL(km_waitq);

static DEFINE_RWLOCK(xfrm_state_afinfo_lock);
static struct xfrm_state_afinfo *xfrm_state_afinfo[NPROTO];

static struct work_struct xfrm_state_gc_work;
static HLIST_HEAD(xfrm_state_gc_list);
}

static DEFINE_SPINLOCK(xfrm_state_afinfo_lock);
static struct xfrm_state_afinfo __rcu *xfrm_state_afinfo[NPROTO];

static DEFINE_SPINLOCK(xfrm_state_gc_lock);

int __xfrm_state_delete(struct xfrm_state *x);

int km_query(struct xfrm_state *x, struct xfrm_tmpl *t, struct xfrm_policy *pol);
void km_state_expired(struct xfrm_state *x, int hard, u32 pid);

static struct xfrm_state_afinfo *xfrm_state_lock_afinfo(unsigned int family)
{
	struct xfrm_state_afinfo *afinfo;
	if (unlikely(family >= NPROTO))
		return NULL;
	write_lock_bh(&xfrm_state_afinfo_lock);
	afinfo = xfrm_state_afinfo[family];
	if (unlikely(!afinfo))
		write_unlock_bh(&xfrm_state_afinfo_lock);
	return afinfo;
}

static void xfrm_state_unlock_afinfo(struct xfrm_state_afinfo *afinfo)
	__releases(xfrm_state_afinfo_lock)
{
	write_unlock_bh(&xfrm_state_afinfo_lock);
}

int xfrm_register_type(const struct xfrm_type *type, unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_lock_afinfo(family);
bool km_is_alive(const struct km_event *c);
void km_state_expired(struct xfrm_state *x, int hard, u32 portid);

static DEFINE_SPINLOCK(xfrm_type_lock);
int xfrm_register_type(const struct xfrm_type *type, unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	const struct xfrm_type **typemap;
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;
	typemap = afinfo->type_map;
	spin_lock_bh(&xfrm_type_lock);

	if (likely(typemap[type->proto] == NULL))
		typemap[type->proto] = type;
	else
		err = -EEXIST;
	xfrm_state_unlock_afinfo(afinfo);
	spin_unlock_bh(&xfrm_type_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_register_type);

int xfrm_unregister_type(const struct xfrm_type *type, unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_lock_afinfo(family);
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	const struct xfrm_type **typemap;
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;
	typemap = afinfo->type_map;
	spin_lock_bh(&xfrm_type_lock);

	if (unlikely(typemap[type->proto] != type))
		err = -ENOENT;
	else
		typemap[type->proto] = NULL;
	xfrm_state_unlock_afinfo(afinfo);
	spin_unlock_bh(&xfrm_type_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_unregister_type);

static const struct xfrm_type *xfrm_get_type(u8 proto, unsigned short family)
{
	struct xfrm_state_afinfo *afinfo;
	const struct xfrm_type **typemap;
	const struct xfrm_type *type;
	int modload_attempted = 0;

retry:
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return NULL;
	typemap = afinfo->type_map;

	type = READ_ONCE(typemap[proto]);
	if (unlikely(type && !try_module_get(type->owner)))
		type = NULL;

	rcu_read_unlock();

	if (!type && !modload_attempted) {
		request_module("xfrm-type-%d-%d", family, proto);
		modload_attempted = 1;
		goto retry;
	}

	return type;
}

static void xfrm_put_type(const struct xfrm_type *type)
{
	module_put(type->owner);
}

static DEFINE_SPINLOCK(xfrm_type_offload_lock);
int xfrm_register_type_offload(const struct xfrm_type_offload *type,
			       unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	const struct xfrm_type_offload **typemap;
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;
	typemap = afinfo->type_offload_map;
	spin_lock_bh(&xfrm_type_offload_lock);

	if (likely(typemap[type->proto] == NULL))
		typemap[type->proto] = type;
	else
		err = -EEXIST;
	spin_unlock_bh(&xfrm_type_offload_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_register_type_offload);

int xfrm_unregister_type_offload(const struct xfrm_type_offload *type,
				 unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	const struct xfrm_type_offload **typemap;
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;
	typemap = afinfo->type_offload_map;
	spin_lock_bh(&xfrm_type_offload_lock);

	if (unlikely(typemap[type->proto] != type))
		err = -ENOENT;
	else
		typemap[type->proto] = NULL;
	spin_unlock_bh(&xfrm_type_offload_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_unregister_type_offload);

static const struct xfrm_type_offload *
xfrm_get_type_offload(u8 proto, unsigned short family, bool try_load)
{
	struct xfrm_state_afinfo *afinfo;
	const struct xfrm_type_offload **typemap;
	const struct xfrm_type_offload *type;

retry:
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return NULL;
	typemap = afinfo->type_offload_map;

	type = typemap[proto];
	if ((type && !try_module_get(type->owner)))
		type = NULL;

	rcu_read_unlock();

	if (!type && try_load) {
		request_module("xfrm-offload-%d-%d", family, proto);
		try_load = false;
		goto retry;
	}

	return type;
}

static void xfrm_put_type_offload(const struct xfrm_type_offload *type)
{
	module_put(type->owner);
}

static DEFINE_SPINLOCK(xfrm_mode_lock);
int xfrm_register_mode(struct xfrm_mode *mode, int family)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode **modemap;
	int err;

	if (unlikely(mode->encap >= XFRM_MODE_MAX))
		return -EINVAL;

	afinfo = xfrm_state_lock_afinfo(family);
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;

	err = -EEXIST;
	modemap = afinfo->mode_map;
	spin_lock_bh(&xfrm_mode_lock);
	if (modemap[mode->encap])
		goto out;

	err = -ENOENT;
	if (!try_module_get(afinfo->owner))
		goto out;

	mode->afinfo = afinfo;
	modemap[mode->encap] = mode;
	err = 0;

out:
	xfrm_state_unlock_afinfo(afinfo);
	spin_unlock_bh(&xfrm_mode_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_register_mode);

int xfrm_unregister_mode(struct xfrm_mode *mode, int family)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode **modemap;
	int err;

	if (unlikely(mode->encap >= XFRM_MODE_MAX))
		return -EINVAL;

	afinfo = xfrm_state_lock_afinfo(family);
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return -EAFNOSUPPORT;

	err = -ENOENT;
	modemap = afinfo->mode_map;
	spin_lock_bh(&xfrm_mode_lock);
	if (likely(modemap[mode->encap] == mode)) {
		modemap[mode->encap] = NULL;
		module_put(mode->afinfo->owner);
		err = 0;
	}

	xfrm_state_unlock_afinfo(afinfo);
	spin_unlock_bh(&xfrm_mode_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_unregister_mode);

static struct xfrm_mode *xfrm_get_mode(unsigned int encap, int family)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode *mode;
	int modload_attempted = 0;

	if (unlikely(encap >= XFRM_MODE_MAX))
		return NULL;

retry:
	afinfo = xfrm_state_get_afinfo(family);
	if (unlikely(afinfo == NULL))
		return NULL;

	mode = READ_ONCE(afinfo->mode_map[encap]);
	if (unlikely(mode && !try_module_get(mode->owner)))
		mode = NULL;

	rcu_read_unlock();
	if (!mode && !modload_attempted) {
		request_module("xfrm-mode-%d-%d", family, encap);
		modload_attempted = 1;
		goto retry;
	}

	return mode;
}

static void xfrm_put_mode(struct xfrm_mode *mode)
{
	module_put(mode->owner);
}

static void xfrm_state_gc_destroy(struct xfrm_state *x)
{
	del_timer_sync(&x->timer);
	tasklet_hrtimer_cancel(&x->mtimer);
	del_timer_sync(&x->rtimer);
	kfree(x->aead);
	kfree(x->aalg);
	kfree(x->ealg);
	kfree(x->calg);
	kfree(x->encap);
	kfree(x->coaddr);
	kfree(x->replay_esn);
	kfree(x->preplay_esn);
	if (x->inner_mode)
		xfrm_put_mode(x->inner_mode);
	if (x->inner_mode_iaf)
		xfrm_put_mode(x->inner_mode_iaf);
	if (x->outer_mode)
		xfrm_put_mode(x->outer_mode);
	if (x->type_offload)
		xfrm_put_type_offload(x->type_offload);
	if (x->type) {
		x->type->destructor(x);
		xfrm_put_type(x->type);
	}
	xfrm_dev_state_free(x);
	security_xfrm_state_free(x);
	kmem_cache_free(xfrm_state_cache, x);
}

static void xfrm_state_gc_task(struct work_struct *data)
{
	struct xfrm_state *x;
	struct hlist_node *entry, *tmp;
	struct hlist_head gc_list;

	spin_lock_bh(&xfrm_state_gc_lock);
	gc_list.first = xfrm_state_gc_list.first;
	INIT_HLIST_HEAD(&xfrm_state_gc_list);
	spin_unlock_bh(&xfrm_state_gc_lock);

	hlist_for_each_entry_safe(x, entry, tmp, &gc_list, bydst)
		xfrm_state_gc_destroy(x);

	wake_up(&km_waitq);
static void xfrm_state_gc_task(struct work_struct *work)
{
	struct xfrm_state *x;
	struct hlist_node *tmp;
	struct hlist_head gc_list;

	spin_lock_bh(&xfrm_state_gc_lock);
	hlist_move_list(&xfrm_state_gc_list, &gc_list);
	spin_unlock_bh(&xfrm_state_gc_lock);

	synchronize_rcu();

	hlist_for_each_entry_safe(x, tmp, &gc_list, gclist)
		xfrm_state_gc_destroy(x);
}

static inline unsigned long make_jiffies(long secs)
{
	if (secs >= (MAX_SCHEDULE_TIMEOUT-1)/HZ)
		return MAX_SCHEDULE_TIMEOUT-1;
	else
		return secs*HZ;
}

static void xfrm_timer_handler(unsigned long data)
{
	struct xfrm_state *x = (struct xfrm_state*)data;
static enum hrtimer_restart xfrm_timer_handler(struct hrtimer *me)
{
	struct tasklet_hrtimer *thr = container_of(me, struct tasklet_hrtimer, timer);
	struct xfrm_state *x = container_of(thr, struct xfrm_state, mtimer);
	time64_t now = ktime_get_real_seconds();
	time64_t next = TIME64_MAX;
	int warn = 0;
	int err = 0;

	spin_lock(&x->lock);
	if (x->km.state == XFRM_STATE_DEAD)
		goto out;
	if (x->km.state == XFRM_STATE_EXPIRED)
		goto expired;
	if (x->lft.hard_add_expires_seconds) {
		long tmo = x->lft.hard_add_expires_seconds +
			x->curlft.add_time - now;
		if (tmo <= 0)
			goto expired;
		if (tmo <= 0) {
			if (x->xflags & XFRM_SOFT_EXPIRE) {
				/* enter hard expire without soft expire first?!
				 * setting a new date could trigger this.
				 * workaround: fix x->curflt.add_time by below:
				 */
				x->curlft.add_time = now - x->saved_tmo - 1;
				tmo = x->lft.hard_add_expires_seconds - x->saved_tmo;
			} else
				goto expired;
		}
		if (tmo < next)
			next = tmo;
	}
	if (x->lft.hard_use_expires_seconds) {
		long tmo = x->lft.hard_use_expires_seconds +
			(x->curlft.use_time ? : now) - now;
		if (tmo <= 0)
			goto expired;
		if (tmo < next)
			next = tmo;
	}
	if (x->km.dying)
		goto resched;
	if (x->lft.soft_add_expires_seconds) {
		long tmo = x->lft.soft_add_expires_seconds +
			x->curlft.add_time - now;
		if (tmo <= 0)
			warn = 1;
		else if (tmo < next)
			next = tmo;
		if (tmo <= 0) {
			warn = 1;
			x->xflags &= ~XFRM_SOFT_EXPIRE;
		} else if (tmo < next) {
			next = tmo;
			x->xflags |= XFRM_SOFT_EXPIRE;
			x->saved_tmo = tmo;
		}
	}
	if (x->lft.soft_use_expires_seconds) {
		long tmo = x->lft.soft_use_expires_seconds +
			(x->curlft.use_time ? : now) - now;
		if (tmo <= 0)
			warn = 1;
		else if (tmo < next)
			next = tmo;
	}

	x->km.dying = warn;
	if (warn)
		km_state_expired(x, 0, 0);
resched:
	if (next != LONG_MAX)
		mod_timer(&x->timer, jiffies + make_jiffies(next));
	if (next != LONG_MAX) {
	if (next != TIME64_MAX) {
		tasklet_hrtimer_start(&x->mtimer, ktime_set(next, 0), HRTIMER_MODE_REL);
	}

	goto out;

expired:
	if (x->km.state == XFRM_STATE_ACQ && x->id.spi == 0) {
		x->km.state = XFRM_STATE_EXPIRED;
		wake_up(&km_waitq);
		next = 2;
		goto resched;
	}

	err = __xfrm_state_delete(x);
	if (!err && x->id.spi)
		km_state_expired(x, 1, 0);

	xfrm_audit_state_delete(x, err ? 0 : 1,
				audit_get_loginuid(current),
				audit_get_sessionid(current), 0);

out:
	spin_unlock(&x->lock);
	if (x->km.state == XFRM_STATE_ACQ && x->id.spi == 0)
		x->km.state = XFRM_STATE_EXPIRED;

	err = __xfrm_state_delete(x);
	if (!err)
		km_state_expired(x, 1, 0);

	xfrm_audit_state_delete(x, err ? 0 : 1, true);

out:
	spin_unlock(&x->lock);
	return HRTIMER_NORESTART;
}

static void xfrm_replay_timer_handler(struct timer_list *t);

struct xfrm_state *xfrm_state_alloc(void)
struct xfrm_state *xfrm_state_alloc(struct net *net)
{
	struct xfrm_state *x;

	x = kmem_cache_alloc(xfrm_state_cache, GFP_ATOMIC | __GFP_ZERO);

	if (x) {
		atomic_set(&x->refcnt, 1);
		atomic_set(&x->tunnel_users, 0);
		INIT_LIST_HEAD(&x->all);
		INIT_HLIST_NODE(&x->bydst);
		INIT_HLIST_NODE(&x->bysrc);
		INIT_HLIST_NODE(&x->byspi);
		setup_timer(&x->timer, xfrm_timer_handler, (unsigned long)x);
		write_pnet(&x->xs_net, net);
		refcount_set(&x->refcnt, 1);
		atomic_set(&x->tunnel_users, 0);
		INIT_LIST_HEAD(&x->km.all);
		INIT_HLIST_NODE(&x->bydst);
		INIT_HLIST_NODE(&x->bysrc);
		INIT_HLIST_NODE(&x->byspi);
		tasklet_hrtimer_init(&x->mtimer, xfrm_timer_handler,
					CLOCK_BOOTTIME, HRTIMER_MODE_ABS);
		timer_setup(&x->rtimer, xfrm_replay_timer_handler, 0);
		x->curlft.add_time = ktime_get_real_seconds();
		x->lft.soft_byte_limit = XFRM_INF;
		x->lft.soft_packet_limit = XFRM_INF;
		x->lft.hard_byte_limit = XFRM_INF;
		x->lft.hard_packet_limit = XFRM_INF;
		x->replay_maxage = 0;
		x->replay_maxdiff = 0;
		x->inner_mode = NULL;
		x->inner_mode_iaf = NULL;
		spin_lock_init(&x->lock);
	}
	return x;
}
EXPORT_SYMBOL(xfrm_state_alloc);

void __xfrm_state_destroy(struct xfrm_state *x)
{
	WARN_ON(x->km.state != XFRM_STATE_DEAD);

	spin_lock_bh(&xfrm_state_lock);
	list_del(&x->all);
	spin_unlock_bh(&xfrm_state_lock);

	spin_lock_bh(&xfrm_state_gc_lock);
	hlist_add_head(&x->bydst, &xfrm_state_gc_list);
	spin_unlock_bh(&xfrm_state_gc_lock);
	schedule_work(&xfrm_state_gc_work);
	struct net *net = xs_net(x);

	WARN_ON(x->km.state != XFRM_STATE_DEAD);

	spin_lock_bh(&xfrm_state_gc_lock);
	hlist_add_head(&x->gclist, &xfrm_state_gc_list);
	spin_unlock_bh(&xfrm_state_gc_lock);
	schedule_work(&xfrm_state_gc_work);
}
EXPORT_SYMBOL(__xfrm_state_destroy);

int __xfrm_state_delete(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	int err = -ESRCH;

	if (x->km.state != XFRM_STATE_DEAD) {
		x->km.state = XFRM_STATE_DEAD;
		spin_lock(&xfrm_state_lock);
		spin_lock(&net->xfrm.xfrm_state_lock);
		list_del(&x->km.all);
		hlist_del_rcu(&x->bydst);
		hlist_del_rcu(&x->bysrc);
		if (x->id.spi)
			hlist_del(&x->byspi);
		xfrm_state_num--;
		spin_unlock(&xfrm_state_lock);
			hlist_del_rcu(&x->byspi);
		net->xfrm.state_num--;
		spin_unlock(&net->xfrm.xfrm_state_lock);

		xfrm_dev_state_delete(x);

		/* All xfrm_state objects are created by xfrm_state_alloc.
		 * The xfrm_state_alloc call gives a reference, and that
		 * is what we are dropping here.
		 */
		xfrm_state_put(x);
		err = 0;
	}

	return err;
}
EXPORT_SYMBOL(__xfrm_state_delete);

int xfrm_state_delete(struct xfrm_state *x)
{
	int err;

	spin_lock_bh(&x->lock);
	err = __xfrm_state_delete(x);
	spin_unlock_bh(&x->lock);

	return err;
}
EXPORT_SYMBOL(xfrm_state_delete);

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static inline int
xfrm_state_flush_secctx_check(u8 proto, struct xfrm_audit *audit_info)
{
	int i, err = 0;

	for (i = 0; i <= xfrm_state_hmask; i++) {
		struct hlist_node *entry;
		struct xfrm_state *x;

		hlist_for_each_entry(x, entry, xfrm_state_bydst+i, bydst) {
			if (xfrm_id_proto_match(x->id.proto, proto) &&
			   (err = security_xfrm_state_delete(x)) != 0) {
				xfrm_audit_state_delete(x, 0,
							audit_info->loginuid,
							audit_info->sessionid,
							audit_info->secid);
xfrm_state_flush_secctx_check(struct net *net, u8 proto, bool task_valid)
{
	int i, err = 0;

	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;

		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			if (xfrm_id_proto_match(x->id.proto, proto) &&
			   (err = security_xfrm_state_delete(x)) != 0) {
				xfrm_audit_state_delete(x, 0, task_valid);
				return err;
			}
		}
	}

	return err;
}

static inline int
xfrm_dev_state_flush_secctx_check(struct net *net, struct net_device *dev, bool task_valid)
{
	int i, err = 0;

	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;
		struct xfrm_state_offload *xso;

		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			xso = &x->xso;

			if (xso->dev == dev &&
			   (err = security_xfrm_state_delete(x)) != 0) {
				xfrm_audit_state_delete(x, 0, task_valid);
				return err;
			}
		}
	}

	return err;
}
#else
static inline int
xfrm_state_flush_secctx_check(u8 proto, struct xfrm_audit *audit_info)
xfrm_state_flush_secctx_check(struct net *net, u8 proto, bool task_valid)
{
	return 0;
}

static inline int
xfrm_dev_state_flush_secctx_check(struct net *net, struct net_device *dev, bool task_valid)
{
	return 0;
}
#endif

int xfrm_state_flush(u8 proto, struct xfrm_audit *audit_info)
{
	int i, err = 0;

	spin_lock_bh(&xfrm_state_lock);
	err = xfrm_state_flush_secctx_check(proto, audit_info);
	if (err)
		goto out;

	for (i = 0; i <= xfrm_state_hmask; i++) {
		struct hlist_node *entry;
		struct xfrm_state *x;
restart:
		hlist_for_each_entry(x, entry, xfrm_state_bydst+i, bydst) {
			if (!xfrm_state_kern(x) &&
			    xfrm_id_proto_match(x->id.proto, proto)) {
				xfrm_state_hold(x);
				spin_unlock_bh(&xfrm_state_lock);

				err = xfrm_state_delete(x);
				xfrm_audit_state_delete(x, err ? 0 : 1,
							audit_info->loginuid,
							audit_info->sessionid,
							audit_info->secid);
				xfrm_state_put(x);

				spin_lock_bh(&xfrm_state_lock);
int xfrm_state_flush(struct net *net, u8 proto, bool task_valid)
{
	int i, err = 0, cnt = 0;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	err = xfrm_state_flush_secctx_check(net, proto, task_valid);
	if (err)
		goto out;

	err = -ESRCH;
	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;
restart:
		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			if (!xfrm_state_kern(x) &&
			    xfrm_id_proto_match(x->id.proto, proto)) {
				xfrm_state_hold(x);
				spin_unlock_bh(&net->xfrm.xfrm_state_lock);

				err = xfrm_state_delete(x);
				xfrm_audit_state_delete(x, err ? 0 : 1,
							task_valid);
				xfrm_state_put(x);
				if (!err)
					cnt++;

				spin_lock_bh(&net->xfrm.xfrm_state_lock);
				goto restart;
			}
		}
	}
	err = 0;

out:
	spin_unlock_bh(&xfrm_state_lock);
	wake_up(&km_waitq);
out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	if (cnt)
		err = 0;

	return err;
}
EXPORT_SYMBOL(xfrm_state_flush);

int xfrm_dev_state_flush(struct net *net, struct net_device *dev, bool task_valid)
{
	int i, err = 0, cnt = 0;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	err = xfrm_dev_state_flush_secctx_check(net, dev, task_valid);
	if (err)
		goto out;

	err = -ESRCH;
	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;
		struct xfrm_state_offload *xso;
restart:
		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			xso = &x->xso;

			if (!xfrm_state_kern(x) && xso->dev == dev) {
				xfrm_state_hold(x);
				spin_unlock_bh(&net->xfrm.xfrm_state_lock);

				err = xfrm_state_delete(x);
				xfrm_audit_state_delete(x, err ? 0 : 1,
							task_valid);
				xfrm_state_put(x);
				if (!err)
					cnt++;

				spin_lock_bh(&net->xfrm.xfrm_state_lock);
				goto restart;
			}
		}
	}
	if (cnt)
		err = 0;

out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return err;
}
EXPORT_SYMBOL(xfrm_dev_state_flush);

void xfrm_sad_getinfo(struct xfrmk_sadinfo *si)
{
	spin_lock_bh(&xfrm_state_lock);
	si->sadcnt = xfrm_state_num;
	si->sadhcnt = xfrm_state_hmask;
	si->sadhmcnt = xfrm_state_hashmax;
	spin_unlock_bh(&xfrm_state_lock);
void xfrm_sad_getinfo(struct net *net, struct xfrmk_sadinfo *si)
{
	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	si->sadcnt = net->xfrm.state_num;
	si->sadhcnt = net->xfrm.state_hmask;
	si->sadhmcnt = xfrm_state_hashmax;
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_sad_getinfo);

static int
xfrm_init_tempsel(struct xfrm_state *x, struct flowi *fl,
		  struct xfrm_tmpl *tmpl,
		  xfrm_address_t *daddr, xfrm_address_t *saddr,
		  unsigned short family)
static void
xfrm_init_tempstate(struct xfrm_state *x, const struct flowi *fl,
		    const struct xfrm_tmpl *tmpl,
		    const xfrm_address_t *daddr, const xfrm_address_t *saddr,
		    unsigned short family)
{
	struct xfrm_state_afinfo *afinfo = xfrm_state_afinfo_get_rcu(family);

	if (!afinfo)
		return -1;
	afinfo->init_tempsel(x, fl, tmpl, daddr, saddr);
		return;

	afinfo->init_tempsel(&x->sel, fl);

	if (family != tmpl->encap_family) {
		afinfo = xfrm_state_afinfo_get_rcu(tmpl->encap_family);
		if (!afinfo)
			return;
	}
	afinfo->init_temprop(x, tmpl, daddr, saddr);
}

static struct xfrm_state *__xfrm_state_lookup(xfrm_address_t *daddr, __be32 spi, u8 proto, unsigned short family)
{
	unsigned int h = xfrm_spi_hash(daddr, spi, proto, family);
	struct xfrm_state *x;
	struct hlist_node *entry;

	hlist_for_each_entry(x, entry, xfrm_state_byspi+h, byspi) {
		if (x->props.family != family ||
		    x->id.spi       != spi ||
		    x->id.proto     != proto)
			continue;

		switch (family) {
		case AF_INET:
			if (x->id.daddr.a4 != daddr->a4)
				continue;
			break;
		case AF_INET6:
			if (!ipv6_addr_equal((struct in6_addr *)daddr,
					     (struct in6_addr *)
					     x->id.daddr.a6))
				continue;
			break;
		}

static struct xfrm_state *__xfrm_state_lookup(struct net *net, u32 mark,
					      const xfrm_address_t *daddr,
					      __be32 spi, u8 proto,
					      unsigned short family)
{
	unsigned int h = xfrm_spi_hash(net, daddr, spi, proto, family);
	struct xfrm_state *x;

	hlist_for_each_entry_rcu(x, net->xfrm.state_byspi + h, byspi) {
		if (x->props.family != family ||
		    x->id.spi       != spi ||
		    x->id.proto     != proto ||
		    !xfrm_addr_equal(&x->id.daddr, daddr, family))
			continue;

		if ((mark & x->mark.m) != x->mark.v)
			continue;
		if (!xfrm_state_hold_rcu(x))
			continue;
		return x;
	}

	return NULL;
}

static struct xfrm_state *__xfrm_state_lookup_byaddr(xfrm_address_t *daddr, xfrm_address_t *saddr, u8 proto, unsigned short family)
{
	unsigned int h = xfrm_src_hash(daddr, saddr, family);
	struct xfrm_state *x;
	struct hlist_node *entry;

	hlist_for_each_entry(x, entry, xfrm_state_bysrc+h, bysrc) {
		if (x->props.family != family ||
		    x->id.proto     != proto)
			continue;

		switch (family) {
		case AF_INET:
			if (x->id.daddr.a4 != daddr->a4 ||
			    x->props.saddr.a4 != saddr->a4)
				continue;
			break;
		case AF_INET6:
			if (!ipv6_addr_equal((struct in6_addr *)daddr,
					     (struct in6_addr *)
					     x->id.daddr.a6) ||
			    !ipv6_addr_equal((struct in6_addr *)saddr,
					     (struct in6_addr *)
					     x->props.saddr.a6))
				continue;
			break;
		}

static struct xfrm_state *__xfrm_state_lookup_byaddr(struct net *net, u32 mark,
						     const xfrm_address_t *daddr,
						     const xfrm_address_t *saddr,
						     u8 proto, unsigned short family)
{
	unsigned int h = xfrm_src_hash(net, daddr, saddr, family);
	struct xfrm_state *x;

	hlist_for_each_entry_rcu(x, net->xfrm.state_bysrc + h, bysrc) {
		if (x->props.family != family ||
		    x->id.proto     != proto ||
		    !xfrm_addr_equal(&x->id.daddr, daddr, family) ||
		    !xfrm_addr_equal(&x->props.saddr, saddr, family))
			continue;

		if ((mark & x->mark.m) != x->mark.v)
			continue;
		if (!xfrm_state_hold_rcu(x))
			continue;
		return x;
	}

	return NULL;
}

static inline struct xfrm_state *
__xfrm_state_locate(struct xfrm_state *x, int use_spi, int family)
{
	if (use_spi)
		return __xfrm_state_lookup(&x->id.daddr, x->id.spi,
					   x->id.proto, family);
	else
		return __xfrm_state_lookup_byaddr(&x->id.daddr,
	struct net *net = xs_net(x);
	u32 mark = x->mark.v & x->mark.m;

	if (use_spi)
		return __xfrm_state_lookup(net, mark, &x->id.daddr,
					   x->id.spi, x->id.proto, family);
	else
		return __xfrm_state_lookup_byaddr(net, mark,
						  &x->id.daddr,
						  &x->props.saddr,
						  x->id.proto, family);
}

static void xfrm_hash_grow_check(int have_hash_collision)
{
	if (have_hash_collision &&
	    (xfrm_state_hmask + 1) < xfrm_state_hashmax &&
	    xfrm_state_num > xfrm_state_hmask)
		schedule_work(&xfrm_hash_work);
}

struct xfrm_state *
xfrm_state_find(xfrm_address_t *daddr, xfrm_address_t *saddr,
		struct flowi *fl, struct xfrm_tmpl *tmpl,
		struct xfrm_policy *pol, int *err,
		unsigned short family)
{
	unsigned int h;
	struct hlist_node *entry;
static void xfrm_hash_grow_check(struct net *net, int have_hash_collision)
{
	if (have_hash_collision &&
	    (net->xfrm.state_hmask + 1) < xfrm_state_hashmax &&
	    net->xfrm.state_num > net->xfrm.state_hmask)
		schedule_work(&net->xfrm.state_hash_work);
}

static void xfrm_state_look_at(struct xfrm_policy *pol, struct xfrm_state *x,
			       const struct flowi *fl, unsigned short family,
			       struct xfrm_state **best, int *acq_in_progress,
			       int *error)
{
	/* Resolution logic:
	 * 1. There is a valid state with matching selector. Done.
	 * 2. Valid state with inappropriate selector. Skip.
	 *
	 * Entering area of "sysdeps".
	 *
	 * 3. If state is not valid, selector is temporary, it selects
	 *    only session which triggered previous resolution. Key
	 *    manager will do something to install a state with proper
	 *    selector.
	 */
	if (x->km.state == XFRM_STATE_VALID) {
		if ((x->sel.family &&
		     !xfrm_selector_match(&x->sel, fl, x->sel.family)) ||
		    !security_xfrm_state_pol_flow_match(x, pol, fl))
			return;

		if (!*best ||
		    (*best)->km.dying > x->km.dying ||
		    ((*best)->km.dying == x->km.dying &&
		     (*best)->curlft.add_time < x->curlft.add_time))
			*best = x;
	} else if (x->km.state == XFRM_STATE_ACQ) {
		*acq_in_progress = 1;
	} else if (x->km.state == XFRM_STATE_ERROR ||
		   x->km.state == XFRM_STATE_EXPIRED) {
		if (xfrm_selector_match(&x->sel, fl, x->sel.family) &&
		    security_xfrm_state_pol_flow_match(x, pol, fl))
			*error = -ESRCH;
	}
}

struct xfrm_state *
xfrm_state_find(const xfrm_address_t *daddr, const xfrm_address_t *saddr,
		const struct flowi *fl, struct xfrm_tmpl *tmpl,
		struct xfrm_policy *pol, int *err,
		unsigned short family, u32 if_id)
{
	static xfrm_address_t saddr_wildcard = { };
	struct net *net = xp_net(pol);
	unsigned int h, h_wildcard;
	struct xfrm_state *x, *x0, *to_put;
	int acquire_in_progress = 0;
	int error = 0;
	struct xfrm_state *best = NULL;

	to_put = NULL;

	spin_lock_bh(&xfrm_state_lock);
	h = xfrm_dst_hash(daddr, saddr, tmpl->reqid, family);
	hlist_for_each_entry(x, entry, xfrm_state_bydst+h, bydst) {
		if (x->props.family == family &&
		    x->props.reqid == tmpl->reqid &&
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    xfrm_state_addr_check(x, daddr, saddr, family) &&
		    tmpl->mode == x->props.mode &&
		    tmpl->id.proto == x->id.proto &&
		    (tmpl->id.spi == x->id.spi || !tmpl->id.spi)) {
			/* Resolution logic:
			   1. There is a valid state with matching selector.
			      Done.
			   2. Valid state with inappropriate selector. Skip.

			   Entering area of "sysdeps".

			   3. If state is not valid, selector is temporary,
			      it selects only session which triggered
			      previous resolution. Key manager will do
			      something to install a state with proper
			      selector.
			 */
			if (x->km.state == XFRM_STATE_VALID) {
				if ((x->sel.family && !xfrm_selector_match(&x->sel, fl, x->sel.family)) ||
				    !security_xfrm_state_pol_flow_match(x, pol, fl))
					continue;
				if (!best ||
				    best->km.dying > x->km.dying ||
				    (best->km.dying == x->km.dying &&
				     best->curlft.add_time < x->curlft.add_time))
					best = x;
			} else if (x->km.state == XFRM_STATE_ACQ) {
				acquire_in_progress = 1;
			} else if (x->km.state == XFRM_STATE_ERROR ||
				   x->km.state == XFRM_STATE_EXPIRED) {
				if (xfrm_selector_match(&x->sel, fl, x->sel.family) &&
				    security_xfrm_state_pol_flow_match(x, pol, fl))
					error = -ESRCH;
			}
		}
	}

	x = best;
	if (!x && !error && !acquire_in_progress) {
		if (tmpl->id.spi &&
		    (x0 = __xfrm_state_lookup(daddr, tmpl->id.spi,
					      tmpl->id.proto, family)) != NULL) {
	u32 mark = pol->mark.v & pol->mark.m;
	unsigned short encap_family = tmpl->encap_family;
	unsigned int sequence;
	struct km_event c;

	to_put = NULL;

	sequence = read_seqcount_begin(&xfrm_state_hash_generation);

	rcu_read_lock();
	h = xfrm_dst_hash(net, daddr, saddr, tmpl->reqid, encap_family);
	hlist_for_each_entry_rcu(x, net->xfrm.state_bydst + h, bydst) {
		if (x->props.family == encap_family &&
		    x->props.reqid == tmpl->reqid &&
		    (mark & x->mark.m) == x->mark.v &&
		    x->if_id == if_id &&
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    xfrm_state_addr_check(x, daddr, saddr, encap_family) &&
		    tmpl->mode == x->props.mode &&
		    tmpl->id.proto == x->id.proto &&
		    (tmpl->id.spi == x->id.spi || !tmpl->id.spi))
			xfrm_state_look_at(pol, x, fl, encap_family,
					   &best, &acquire_in_progress, &error);
	}
	if (best || acquire_in_progress)
		goto found;

	h_wildcard = xfrm_dst_hash(net, daddr, &saddr_wildcard, tmpl->reqid, encap_family);
	hlist_for_each_entry_rcu(x, net->xfrm.state_bydst + h_wildcard, bydst) {
		if (x->props.family == encap_family &&
		    x->props.reqid == tmpl->reqid &&
		    (mark & x->mark.m) == x->mark.v &&
		    x->if_id == if_id &&
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    xfrm_addr_equal(&x->id.daddr, daddr, encap_family) &&
		    tmpl->mode == x->props.mode &&
		    tmpl->id.proto == x->id.proto &&
		    (tmpl->id.spi == x->id.spi || !tmpl->id.spi))
			xfrm_state_look_at(pol, x, fl, encap_family,
					   &best, &acquire_in_progress, &error);
	}

found:
	x = best;
	if (!x && !error && !acquire_in_progress) {
		if (tmpl->id.spi &&
		    (x0 = __xfrm_state_lookup(net, mark, daddr, tmpl->id.spi,
					      tmpl->id.proto, encap_family)) != NULL) {
			to_put = x0;
			error = -EEXIST;
			goto out;
		}
		x = xfrm_state_alloc();

		c.net = net;
		/* If the KMs have no listeners (yet...), avoid allocating an SA
		 * for each and every packet - garbage collection might not
		 * handle the flood.
		 */
		if (!km_is_alive(&c)) {
			error = -ESRCH;
			goto out;
		}

		x = xfrm_state_alloc(net);
		if (x == NULL) {
			error = -ENOMEM;
			goto out;
		}
		/* Initialize temporary selector matching only
		 * to current session. */
		xfrm_init_tempsel(x, fl, tmpl, daddr, saddr, family);

		error = security_xfrm_state_alloc_acquire(x, pol->security, fl->secid);
		/* Initialize temporary state matching only
		 * to current session. */
		xfrm_init_tempstate(x, fl, tmpl, daddr, saddr, family);
		memcpy(&x->mark, &pol->mark, sizeof(x->mark));
		x->if_id = if_id;

		error = security_xfrm_state_alloc_acquire(x, pol->security, fl->flowi_secid);
		if (error) {
			x->km.state = XFRM_STATE_DEAD;
			to_put = x;
			x = NULL;
			goto out;
		}

		if (km_query(x, tmpl, pol) == 0) {
			spin_lock_bh(&net->xfrm.xfrm_state_lock);
			x->km.state = XFRM_STATE_ACQ;
			list_add_tail(&x->all, &xfrm_state_all);
			hlist_add_head(&x->bydst, xfrm_state_bydst+h);
			h = xfrm_src_hash(daddr, saddr, family);
			hlist_add_head(&x->bysrc, xfrm_state_bysrc+h);
			if (x->id.spi) {
				h = xfrm_spi_hash(&x->id.daddr, x->id.spi, x->id.proto, family);
				hlist_add_head(&x->byspi, xfrm_state_byspi+h);
			}
			x->lft.hard_add_expires_seconds = sysctl_xfrm_acq_expires;
			x->timer.expires = jiffies + sysctl_xfrm_acq_expires*HZ;
			add_timer(&x->timer);
			xfrm_state_num++;
			xfrm_hash_grow_check(x->bydst.next != NULL);
			list_add(&x->km.all, &net->xfrm.state_all);
			hlist_add_head_rcu(&x->bydst, net->xfrm.state_bydst + h);
			h = xfrm_src_hash(net, daddr, saddr, encap_family);
			hlist_add_head_rcu(&x->bysrc, net->xfrm.state_bysrc + h);
			if (x->id.spi) {
				h = xfrm_spi_hash(net, &x->id.daddr, x->id.spi, x->id.proto, encap_family);
				hlist_add_head_rcu(&x->byspi, net->xfrm.state_byspi + h);
			}
			x->lft.hard_add_expires_seconds = net->xfrm.sysctl_acq_expires;
			tasklet_hrtimer_start(&x->mtimer, ktime_set(net->xfrm.sysctl_acq_expires, 0), HRTIMER_MODE_REL);
			net->xfrm.state_num++;
			xfrm_hash_grow_check(net, x->bydst.next != NULL);
			spin_unlock_bh(&net->xfrm.xfrm_state_lock);
		} else {
			x->km.state = XFRM_STATE_DEAD;
			to_put = x;
			x = NULL;
			error = -ESRCH;
		}
	}
out:
	if (x) {
		if (!xfrm_state_hold_rcu(x)) {
			*err = -EAGAIN;
			x = NULL;
		}
	} else {
		*err = acquire_in_progress ? -EAGAIN : error;
	spin_unlock_bh(&xfrm_state_lock);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	}
	rcu_read_unlock();
	if (to_put)
		xfrm_state_put(to_put);

	if (read_seqcount_retry(&xfrm_state_hash_generation, sequence)) {
		*err = -EAGAIN;
		if (x) {
			xfrm_state_put(x);
			x = NULL;
		}
	}

	return x;
}

struct xfrm_state *
xfrm_stateonly_find(xfrm_address_t *daddr, xfrm_address_t *saddr,
xfrm_stateonly_find(struct net *net, u32 mark,
xfrm_stateonly_find(struct net *net, u32 mark, u32 if_id,
		    xfrm_address_t *daddr, xfrm_address_t *saddr,
		    unsigned short family, u8 mode, u8 proto, u32 reqid)
{
	unsigned int h;
	struct xfrm_state *rx = NULL, *x = NULL;
	struct hlist_node *entry;

	spin_lock(&xfrm_state_lock);
	h = xfrm_dst_hash(daddr, saddr, reqid, family);
	hlist_for_each_entry(x, entry, xfrm_state_bydst+h, bydst) {
		if (x->props.family == family &&
		    x->props.reqid == reqid &&

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	h = xfrm_dst_hash(net, daddr, saddr, reqid, family);
	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
		if (x->props.family == family &&
		    x->props.reqid == reqid &&
		    (mark & x->mark.m) == x->mark.v &&
		    x->if_id == if_id &&
		    !(x->props.flags & XFRM_STATE_WILDRECV) &&
		    xfrm_state_addr_check(x, daddr, saddr, family) &&
		    mode == x->props.mode &&
		    proto == x->id.proto &&
		    x->km.state == XFRM_STATE_VALID) {
			rx = x;
			break;
		}
	}

	if (rx)
		xfrm_state_hold(rx);
	spin_unlock(&xfrm_state_lock);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);


	return rx;
}
EXPORT_SYMBOL(xfrm_stateonly_find);

static void __xfrm_state_insert(struct xfrm_state *x)
{
	unsigned int h;

	x->genid = ++xfrm_state_genid;

	list_add_tail(&x->all, &xfrm_state_all);

	h = xfrm_dst_hash(&x->id.daddr, &x->props.saddr,
			  x->props.reqid, x->props.family);
	hlist_add_head(&x->bydst, xfrm_state_bydst+h);

	h = xfrm_src_hash(&x->id.daddr, &x->props.saddr, x->props.family);
	hlist_add_head(&x->bysrc, xfrm_state_bysrc+h);

	if (x->id.spi) {
		h = xfrm_spi_hash(&x->id.daddr, x->id.spi, x->id.proto,
				  x->props.family);

		hlist_add_head(&x->byspi, xfrm_state_byspi+h);
	}

	mod_timer(&x->timer, jiffies + HZ);
	if (x->replay_maxage)
		mod_timer(&x->rtimer, jiffies + x->replay_maxage);

	wake_up(&km_waitq);

	xfrm_state_num++;

	xfrm_hash_grow_check(x->bydst.next != NULL);
}

/* xfrm_state_lock is held */
static void __xfrm_state_bump_genids(struct xfrm_state *xnew)
{
	unsigned short family = xnew->props.family;
	u32 reqid = xnew->props.reqid;
	struct xfrm_state *x;
	struct hlist_node *entry;
	unsigned int h;

	h = xfrm_dst_hash(&xnew->id.daddr, &xnew->props.saddr, reqid, family);
	hlist_for_each_entry(x, entry, xfrm_state_bydst+h, bydst) {
		if (x->props.family	== family &&
		    x->props.reqid	== reqid &&
		    !xfrm_addr_cmp(&x->id.daddr, &xnew->id.daddr, family) &&
		    !xfrm_addr_cmp(&x->props.saddr, &xnew->props.saddr, family))
			x->genid = xfrm_state_genid;
struct xfrm_state *xfrm_state_lookup_byspi(struct net *net, __be32 spi,
					      unsigned short family)
{
	struct xfrm_state *x;
	struct xfrm_state_walk *w;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	list_for_each_entry(w, &net->xfrm.state_all, all) {
		x = container_of(w, struct xfrm_state, km);
		if (x->props.family != family ||
			x->id.spi != spi)
			continue;

		xfrm_state_hold(x);
		spin_unlock_bh(&net->xfrm.xfrm_state_lock);
		return x;
	}
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return NULL;
}
EXPORT_SYMBOL(xfrm_state_lookup_byspi);

static void __xfrm_state_insert(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	unsigned int h;

	list_add(&x->km.all, &net->xfrm.state_all);

	h = xfrm_dst_hash(net, &x->id.daddr, &x->props.saddr,
			  x->props.reqid, x->props.family);
	hlist_add_head_rcu(&x->bydst, net->xfrm.state_bydst + h);

	h = xfrm_src_hash(net, &x->id.daddr, &x->props.saddr, x->props.family);
	hlist_add_head_rcu(&x->bysrc, net->xfrm.state_bysrc + h);

	if (x->id.spi) {
		h = xfrm_spi_hash(net, &x->id.daddr, x->id.spi, x->id.proto,
				  x->props.family);

		hlist_add_head_rcu(&x->byspi, net->xfrm.state_byspi + h);
	}

	tasklet_hrtimer_start(&x->mtimer, ktime_set(1, 0), HRTIMER_MODE_REL);
	if (x->replay_maxage)
		mod_timer(&x->rtimer, jiffies + x->replay_maxage);

	net->xfrm.state_num++;

	xfrm_hash_grow_check(net, x->bydst.next != NULL);
}

/* net->xfrm.xfrm_state_lock is held */
static void __xfrm_state_bump_genids(struct xfrm_state *xnew)
{
	struct net *net = xs_net(xnew);
	unsigned short family = xnew->props.family;
	u32 reqid = xnew->props.reqid;
	struct xfrm_state *x;
	unsigned int h;
	u32 mark = xnew->mark.v & xnew->mark.m;
	u32 if_id = xnew->if_id;

	h = xfrm_dst_hash(net, &xnew->id.daddr, &xnew->props.saddr, reqid, family);
	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
		if (x->props.family	== family &&
		    x->props.reqid	== reqid &&
		    x->if_id		== if_id &&
		    (mark & x->mark.m) == x->mark.v &&
		    xfrm_addr_equal(&x->id.daddr, &xnew->id.daddr, family) &&
		    xfrm_addr_equal(&x->props.saddr, &xnew->props.saddr, family))
			x->genid++;
	}
}

void xfrm_state_insert(struct xfrm_state *x)
{
	spin_lock_bh(&xfrm_state_lock);
	__xfrm_state_bump_genids(x);
	__xfrm_state_insert(x);
	spin_unlock_bh(&xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_state_insert);

/* xfrm_state_lock is held */
static struct xfrm_state *__find_acq_core(unsigned short family, u8 mode, u32 reqid, u8 proto, xfrm_address_t *daddr, xfrm_address_t *saddr, int create)
{
	unsigned int h = xfrm_dst_hash(daddr, saddr, reqid, family);
	struct hlist_node *entry;
	struct xfrm_state *x;

	hlist_for_each_entry(x, entry, xfrm_state_bydst+h, bydst) {
	struct net *net = xs_net(x);

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	__xfrm_state_bump_genids(x);
	__xfrm_state_insert(x);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_state_insert);

/* net->xfrm.xfrm_state_lock is held */
static struct xfrm_state *__find_acq_core(struct net *net,
					  const struct xfrm_mark *m,
					  unsigned short family, u8 mode,
					  u32 reqid, u32 if_id, u8 proto,
					  const xfrm_address_t *daddr,
					  const xfrm_address_t *saddr,
					  int create)
{
	unsigned int h = xfrm_dst_hash(net, daddr, saddr, reqid, family);
	struct xfrm_state *x;
	u32 mark = m->v & m->m;

	hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
		if (x->props.reqid  != reqid ||
		    x->props.mode   != mode ||
		    x->props.family != family ||
		    x->km.state     != XFRM_STATE_ACQ ||
		    x->id.spi       != 0 ||
		    x->id.proto	    != proto)
			continue;

		switch (family) {
		case AF_INET:
			if (x->id.daddr.a4    != daddr->a4 ||
			    x->props.saddr.a4 != saddr->a4)
				continue;
			break;
		case AF_INET6:
			if (!ipv6_addr_equal((struct in6_addr *)x->id.daddr.a6,
					     (struct in6_addr *)daddr) ||
			    !ipv6_addr_equal((struct in6_addr *)
					     x->props.saddr.a6,
					     (struct in6_addr *)saddr))
				continue;
			break;
		}

		    x->id.proto	    != proto ||
		    (mark & x->mark.m) != x->mark.v ||
		    !xfrm_addr_equal(&x->id.daddr, daddr, family) ||
		    !xfrm_addr_equal(&x->props.saddr, saddr, family))
			continue;

		xfrm_state_hold(x);
		return x;
	}

	if (!create)
		return NULL;

	x = xfrm_state_alloc();
	x = xfrm_state_alloc(net);
	if (likely(x)) {
		switch (family) {
		case AF_INET:
			x->sel.daddr.a4 = daddr->a4;
			x->sel.saddr.a4 = saddr->a4;
			x->sel.prefixlen_d = 32;
			x->sel.prefixlen_s = 32;
			x->props.saddr.a4 = saddr->a4;
			x->id.daddr.a4 = daddr->a4;
			break;

		case AF_INET6:
			ipv6_addr_copy((struct in6_addr *)x->sel.daddr.a6,
				       (struct in6_addr *)daddr);
			ipv6_addr_copy((struct in6_addr *)x->sel.saddr.a6,
				       (struct in6_addr *)saddr);
			x->sel.prefixlen_d = 128;
			x->sel.prefixlen_s = 128;
			ipv6_addr_copy((struct in6_addr *)x->props.saddr.a6,
				       (struct in6_addr *)saddr);
			ipv6_addr_copy((struct in6_addr *)x->id.daddr.a6,
				       (struct in6_addr *)daddr);
			x->sel.daddr.in6 = daddr->in6;
			x->sel.saddr.in6 = saddr->in6;
			x->sel.prefixlen_d = 128;
			x->sel.prefixlen_s = 128;
			x->props.saddr.in6 = saddr->in6;
			x->id.daddr.in6 = daddr->in6;
			break;
		}

		x->km.state = XFRM_STATE_ACQ;
		x->id.proto = proto;
		x->props.family = family;
		x->props.mode = mode;
		x->props.reqid = reqid;
		x->lft.hard_add_expires_seconds = sysctl_xfrm_acq_expires;
		xfrm_state_hold(x);
		x->timer.expires = jiffies + sysctl_xfrm_acq_expires*HZ;
		add_timer(&x->timer);
		list_add_tail(&x->all, &xfrm_state_all);
		hlist_add_head(&x->bydst, xfrm_state_bydst+h);
		h = xfrm_src_hash(daddr, saddr, family);
		hlist_add_head(&x->bysrc, xfrm_state_bysrc+h);

		xfrm_state_num++;

		xfrm_hash_grow_check(x->bydst.next != NULL);
		x->if_id = if_id;
		x->mark.v = m->v;
		x->mark.m = m->m;
		x->lft.hard_add_expires_seconds = net->xfrm.sysctl_acq_expires;
		xfrm_state_hold(x);
		tasklet_hrtimer_start(&x->mtimer, ktime_set(net->xfrm.sysctl_acq_expires, 0), HRTIMER_MODE_REL);
		list_add(&x->km.all, &net->xfrm.state_all);
		hlist_add_head_rcu(&x->bydst, net->xfrm.state_bydst + h);
		h = xfrm_src_hash(net, daddr, saddr, family);
		hlist_add_head_rcu(&x->bysrc, net->xfrm.state_bysrc + h);

		net->xfrm.state_num++;

		xfrm_hash_grow_check(net, x->bydst.next != NULL);
	}

	return x;
}

static struct xfrm_state *__xfrm_find_acq_byseq(u32 seq);

int xfrm_state_add(struct xfrm_state *x)
{
	struct xfrm_state *x1, *to_put;
	int family;
	int err;
static struct xfrm_state *__xfrm_find_acq_byseq(struct net *net, u32 mark, u32 seq);

int xfrm_state_add(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	struct xfrm_state *x1, *to_put;
	int family;
	int err;
	u32 mark = x->mark.v & x->mark.m;
	int use_spi = xfrm_id_proto_match(x->id.proto, IPSEC_PROTO_ANY);

	family = x->props.family;

	to_put = NULL;

	spin_lock_bh(&xfrm_state_lock);
	spin_lock_bh(&net->xfrm.xfrm_state_lock);

	x1 = __xfrm_state_locate(x, use_spi, family);
	if (x1) {
		to_put = x1;
		x1 = NULL;
		err = -EEXIST;
		goto out;
	}

	if (use_spi && x->km.seq) {
		x1 = __xfrm_find_acq_byseq(x->km.seq);
		if (x1 && ((x1->id.proto != x->id.proto) ||
		    xfrm_addr_cmp(&x1->id.daddr, &x->id.daddr, family))) {
		x1 = __xfrm_find_acq_byseq(net, mark, x->km.seq);
		if (x1 && ((x1->id.proto != x->id.proto) ||
		    !xfrm_addr_equal(&x1->id.daddr, &x->id.daddr, family))) {
			to_put = x1;
			x1 = NULL;
		}
	}

	if (use_spi && !x1)
		x1 = __find_acq_core(family, x->props.mode, x->props.reqid,
				     x->id.proto,
		x1 = __find_acq_core(net, &x->mark, family, x->props.mode,
				     x->props.reqid, x->if_id, x->id.proto,
				     &x->id.daddr, &x->props.saddr, 0);

	__xfrm_state_bump_genids(x);
	__xfrm_state_insert(x);
	err = 0;

out:
	spin_unlock_bh(&xfrm_state_lock);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	if (x1) {
		xfrm_state_delete(x1);
		xfrm_state_put(x1);
	}

	if (to_put)
		xfrm_state_put(to_put);

	return err;
}
EXPORT_SYMBOL(xfrm_state_add);

#ifdef CONFIG_XFRM_MIGRATE
static struct xfrm_state *xfrm_state_clone(struct xfrm_state *orig, int *errp)
{
	int err = -ENOMEM;
	struct xfrm_state *x = xfrm_state_alloc();
	if (!x)
		goto error;
static struct xfrm_state *xfrm_state_clone(struct xfrm_state *orig)
static struct xfrm_state *xfrm_state_clone(struct xfrm_state *orig,
					   struct xfrm_encap_tmpl *encap)
{
	struct net *net = xs_net(orig);
	struct xfrm_state *x = xfrm_state_alloc(net);
	if (!x)
		goto out;

	memcpy(&x->id, &orig->id, sizeof(x->id));
	memcpy(&x->sel, &orig->sel, sizeof(x->sel));
	memcpy(&x->lft, &orig->lft, sizeof(x->lft));
	x->props.mode = orig->props.mode;
	x->props.replay_window = orig->props.replay_window;
	x->props.reqid = orig->props.reqid;
	x->props.family = orig->props.family;
	x->props.saddr = orig->props.saddr;

	if (orig->aalg) {
		x->aalg = xfrm_algo_clone(orig->aalg);
		x->aalg = xfrm_algo_auth_clone(orig->aalg);
		if (!x->aalg)
			goto error;
	}
	x->props.aalgo = orig->props.aalgo;

	if (orig->aead) {
		x->aead = xfrm_algo_aead_clone(orig->aead);
		x->geniv = orig->geniv;
		if (!x->aead)
			goto error;
	}
	if (orig->ealg) {
		x->ealg = xfrm_algo_clone(orig->ealg);
		if (!x->ealg)
			goto error;
	}
	x->props.ealgo = orig->props.ealgo;

	if (orig->calg) {
		x->calg = xfrm_algo_clone(orig->calg);
		if (!x->calg)
			goto error;
	}
	x->props.calgo = orig->props.calgo;

	if (encap || orig->encap) {
		if (encap)
			x->encap = kmemdup(encap, sizeof(*x->encap),
					GFP_KERNEL);
		else
			x->encap = kmemdup(orig->encap, sizeof(*x->encap),
					GFP_KERNEL);

		if (!x->encap)
			goto error;
	}

	if (orig->coaddr) {
		x->coaddr = kmemdup(orig->coaddr, sizeof(*x->coaddr),
				    GFP_KERNEL);
		if (!x->coaddr)
			goto error;
	}

	err = xfrm_init_state(x);
	if (err)
		goto error;

	x->props.flags = orig->props.flags;

	if (orig->replay_esn) {
		if (xfrm_replay_clone(x, orig))
			goto error;
	}

	memcpy(&x->mark, &orig->mark, sizeof(x->mark));

	if (xfrm_init_state(x) < 0)
		goto error;

	x->props.flags = orig->props.flags;
	x->props.extra_flags = orig->props.extra_flags;

	x->if_id = orig->if_id;
	x->tfcpad = orig->tfcpad;
	x->replay_maxdiff = orig->replay_maxdiff;
	x->replay_maxage = orig->replay_maxage;
	x->curlft.add_time = orig->curlft.add_time;
	x->km.state = orig->km.state;
	x->km.seq = orig->km.seq;
	x->replay = orig->replay;
	x->preplay = orig->preplay;

	return x;

 error:
	if (errp)
		*errp = err;
	if (x) {
		kfree(x->aalg);
		kfree(x->ealg);
		kfree(x->calg);
		kfree(x->encap);
		kfree(x->coaddr);
	}
	kfree(x);
	return NULL;
}

/* xfrm_state_lock is held */
struct xfrm_state * xfrm_migrate_state_find(struct xfrm_migrate *m)
{
	unsigned int h;
	struct xfrm_state *x;
	struct hlist_node *entry;

	if (m->reqid) {
		h = xfrm_dst_hash(&m->old_daddr, &m->old_saddr,
				  m->reqid, m->old_family);
		hlist_for_each_entry(x, entry, xfrm_state_bydst+h, bydst) {
	xfrm_state_put(x);
out:
	return NULL;
}

struct xfrm_state *xfrm_migrate_state_find(struct xfrm_migrate *m, struct net *net)
{
	unsigned int h;
	struct xfrm_state *x = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);

	if (m->reqid) {
		h = xfrm_dst_hash(net, &m->old_daddr, &m->old_saddr,
				  m->reqid, m->old_family);
		hlist_for_each_entry(x, net->xfrm.state_bydst+h, bydst) {
			if (x->props.mode != m->mode ||
			    x->id.proto != m->proto)
				continue;
			if (m->reqid && x->props.reqid != m->reqid)
				continue;
			if (xfrm_addr_cmp(&x->id.daddr, &m->old_daddr,
					  m->old_family) ||
			    xfrm_addr_cmp(&x->props.saddr, &m->old_saddr,
					  m->old_family))
				continue;
			xfrm_state_hold(x);
			return x;
		}
	} else {
		h = xfrm_src_hash(&m->old_daddr, &m->old_saddr,
				  m->old_family);
		hlist_for_each_entry(x, entry, xfrm_state_bysrc+h, bysrc) {
			if (x->props.mode != m->mode ||
			    x->id.proto != m->proto)
				continue;
			if (xfrm_addr_cmp(&x->id.daddr, &m->old_daddr,
					  m->old_family) ||
			    xfrm_addr_cmp(&x->props.saddr, &m->old_saddr,
					  m->old_family))
				continue;
			xfrm_state_hold(x);
			return x;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(xfrm_migrate_state_find);

struct xfrm_state * xfrm_state_migrate(struct xfrm_state *x,
				       struct xfrm_migrate *m)
{
	struct xfrm_state *xc;
	int err;

	xc = xfrm_state_clone(x, &err);
			if (!xfrm_addr_equal(&x->id.daddr, &m->old_daddr,
					     m->old_family) ||
			    !xfrm_addr_equal(&x->props.saddr, &m->old_saddr,
					     m->old_family))
				continue;
			xfrm_state_hold(x);
			break;
		}
	} else {
		h = xfrm_src_hash(net, &m->old_daddr, &m->old_saddr,
				  m->old_family);
		hlist_for_each_entry(x, net->xfrm.state_bysrc+h, bysrc) {
			if (x->props.mode != m->mode ||
			    x->id.proto != m->proto)
				continue;
			if (!xfrm_addr_equal(&x->id.daddr, &m->old_daddr,
					     m->old_family) ||
			    !xfrm_addr_equal(&x->props.saddr, &m->old_saddr,
					     m->old_family))
				continue;
			xfrm_state_hold(x);
			break;
		}
	}

	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	return x;
}
EXPORT_SYMBOL(xfrm_migrate_state_find);

struct xfrm_state *xfrm_state_migrate(struct xfrm_state *x,
				      struct xfrm_migrate *m,
				      struct xfrm_encap_tmpl *encap)
{
	struct xfrm_state *xc;

	xc = xfrm_state_clone(x, encap);
	if (!xc)
		return NULL;

	memcpy(&xc->id.daddr, &m->new_daddr, sizeof(xc->id.daddr));
	memcpy(&xc->props.saddr, &m->new_saddr, sizeof(xc->props.saddr));

	/* add state */
	if (!xfrm_addr_cmp(&x->id.daddr, &m->new_daddr, m->new_family)) {
	if (xfrm_addr_equal(&x->id.daddr, &m->new_daddr, m->new_family)) {
		/* a care is needed when the destination address of the
		   state is to be updated as it is a part of triplet */
		xfrm_state_insert(xc);
	} else {
		if ((err = xfrm_state_add(xc)) < 0)
		if (xfrm_state_add(xc) < 0)
			goto error;
	}

	return xc;
error:
	kfree(xc);
	xfrm_state_put(xc);
	return NULL;
}
EXPORT_SYMBOL(xfrm_state_migrate);
#endif

int xfrm_state_update(struct xfrm_state *x)
{
	struct xfrm_state *x1, *to_put;
	int err;
	int use_spi = xfrm_id_proto_match(x->id.proto, IPSEC_PROTO_ANY);

	to_put = NULL;

	spin_lock_bh(&xfrm_state_lock);
	struct net *net = xs_net(x);

	to_put = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x1 = __xfrm_state_locate(x, use_spi, x->props.family);

	err = -ESRCH;
	if (!x1)
		goto out;

	if (xfrm_state_kern(x1)) {
		to_put = x1;
		err = -EEXIST;
		goto out;
	}

	if (x1->km.state == XFRM_STATE_ACQ) {
		__xfrm_state_insert(x);
		x = NULL;
	}
	err = 0;

out:
	spin_unlock_bh(&xfrm_state_lock);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	if (to_put)
		xfrm_state_put(to_put);

	if (err)
		return err;

	if (!x) {
		xfrm_state_delete(x1);
		xfrm_state_put(x1);
		return 0;
	}

	err = -EINVAL;
	spin_lock_bh(&x1->lock);
	if (likely(x1->km.state == XFRM_STATE_VALID)) {
		if (x->encap && x1->encap &&
		    x->encap->encap_type == x1->encap->encap_type)
			memcpy(x1->encap, x->encap, sizeof(*x1->encap));
		else if (x->encap || x1->encap)
			goto fail;

		if (x->coaddr && x1->coaddr) {
			memcpy(x1->coaddr, x->coaddr, sizeof(*x1->coaddr));
		}
		if (!use_spi && memcmp(&x1->sel, &x->sel, sizeof(x1->sel)))
			memcpy(&x1->sel, &x->sel, sizeof(x1->sel));
		memcpy(&x1->lft, &x->lft, sizeof(x1->lft));
		x1->km.dying = 0;

		mod_timer(&x1->timer, jiffies + HZ);
		tasklet_hrtimer_start(&x1->mtimer, ktime_set(1, 0), HRTIMER_MODE_REL);
		if (x1->curlft.use_time)
			xfrm_state_check_expire(x1);

		if (x->props.smark.m || x->props.smark.v || x->if_id) {
			spin_lock_bh(&net->xfrm.xfrm_state_lock);

			if (x->props.smark.m || x->props.smark.v)
				x1->props.smark = x->props.smark;

			if (x->if_id)
				x1->if_id = x->if_id;

			__xfrm_state_bump_genids(x1);
			spin_unlock_bh(&net->xfrm.xfrm_state_lock);
		}

		err = 0;
		x->km.state = XFRM_STATE_DEAD;
		__xfrm_state_put(x);
	}

fail:
	spin_unlock_bh(&x1->lock);

	xfrm_state_put(x1);

	return err;
}
EXPORT_SYMBOL(xfrm_state_update);

int xfrm_state_check_expire(struct xfrm_state *x)
{
	if (!x->curlft.use_time)
		x->curlft.use_time = ktime_get_real_seconds();

	if (x->km.state != XFRM_STATE_VALID)
		return -EINVAL;

	if (x->curlft.bytes >= x->lft.hard_byte_limit ||
	    x->curlft.packets >= x->lft.hard_packet_limit) {
		x->km.state = XFRM_STATE_EXPIRED;
		mod_timer(&x->timer, jiffies);
	if (x->curlft.bytes >= x->lft.hard_byte_limit ||
	    x->curlft.packets >= x->lft.hard_packet_limit) {
		x->km.state = XFRM_STATE_EXPIRED;
		tasklet_hrtimer_start(&x->mtimer, 0, HRTIMER_MODE_REL);
		return -EINVAL;
	}

	if (!x->km.dying &&
	    (x->curlft.bytes >= x->lft.soft_byte_limit ||
	     x->curlft.packets >= x->lft.soft_packet_limit)) {
		x->km.dying = 1;
		km_state_expired(x, 0, 0);
	}
	return 0;
}
EXPORT_SYMBOL(xfrm_state_check_expire);

struct xfrm_state *
xfrm_state_lookup(xfrm_address_t *daddr, __be32 spi, u8 proto,
		  unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&xfrm_state_lock);
	x = __xfrm_state_lookup(daddr, spi, proto, family);
	spin_unlock_bh(&xfrm_state_lock);
xfrm_state_lookup(struct net *net, u32 mark, const xfrm_address_t *daddr, __be32 spi,
		  u8 proto, unsigned short family)
{
	struct xfrm_state *x;

	rcu_read_lock();
	x = __xfrm_state_lookup(net, mark, daddr, spi, proto, family);
	rcu_read_unlock();
	return x;
}
EXPORT_SYMBOL(xfrm_state_lookup);

struct xfrm_state *
xfrm_state_lookup_byaddr(xfrm_address_t *daddr, xfrm_address_t *saddr,
xfrm_state_lookup_byaddr(struct net *net, u32 mark,
			 const xfrm_address_t *daddr, const xfrm_address_t *saddr,
			 u8 proto, unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&xfrm_state_lock);
	x = __xfrm_state_lookup_byaddr(daddr, saddr, proto, family);
	spin_unlock_bh(&xfrm_state_lock);
	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __xfrm_state_lookup_byaddr(net, mark, daddr, saddr, proto, family);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return x;
}
EXPORT_SYMBOL(xfrm_state_lookup_byaddr);

struct xfrm_state *
xfrm_find_acq(u8 mode, u32 reqid, u8 proto,
	      xfrm_address_t *daddr, xfrm_address_t *saddr,
	      int create, unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&xfrm_state_lock);
	x = __find_acq_core(family, mode, reqid, proto, daddr, saddr, create);
	spin_unlock_bh(&xfrm_state_lock);
xfrm_find_acq(struct net *net, const struct xfrm_mark *mark, u8 mode, u32 reqid,
	      u32 if_id, u8 proto, const xfrm_address_t *daddr,
	      const xfrm_address_t *saddr, int create, unsigned short family)
{
	struct xfrm_state *x;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __find_acq_core(net, mark, family, mode, reqid, if_id, proto, daddr, saddr, create);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	return x;
}
EXPORT_SYMBOL(xfrm_find_acq);

#ifdef CONFIG_XFRM_SUB_POLICY
int
xfrm_tmpl_sort(struct xfrm_tmpl **dst, struct xfrm_tmpl **src, int n,
	       unsigned short family)
	       unsigned short family, struct net *net)
{
	int i;
	int err = 0;
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	if (!afinfo)
		return -EAFNOSUPPORT;

	spin_lock_bh(&xfrm_state_lock);
	if (afinfo->tmpl_sort)
		err = afinfo->tmpl_sort(dst, src, n);
	spin_unlock_bh(&xfrm_state_lock);
	spin_lock_bh(&net->xfrm.xfrm_state_lock); /*FIXME*/
	if (afinfo->tmpl_sort)
		err = afinfo->tmpl_sort(dst, src, n);
	else
		for (i = 0; i < n; i++)
			dst[i] = src[i];
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_tmpl_sort);

int
xfrm_state_sort(struct xfrm_state **dst, struct xfrm_state **src, int n,
		unsigned short family)
{
	int i;
	int err = 0;
	struct xfrm_state_afinfo *afinfo = xfrm_state_get_afinfo(family);
	if (!afinfo)
		return -EAFNOSUPPORT;

	spin_lock_bh(&xfrm_state_lock);
	if (afinfo->state_sort)
		err = afinfo->state_sort(dst, src, n);
	spin_unlock_bh(&xfrm_state_lock);
	struct net *net = xs_net(*src);

	if (!afinfo)
		return -EAFNOSUPPORT;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	if (afinfo->state_sort)
		err = afinfo->state_sort(dst, src, n);
	else
		for (i = 0; i < n; i++)
			dst[i] = src[i];
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(xfrm_state_sort);
#endif

/* Silly enough, but I'm lazy to build resolution list */

static struct xfrm_state *__xfrm_find_acq_byseq(u32 seq)
{
	int i;

	for (i = 0; i <= xfrm_state_hmask; i++) {
		struct hlist_node *entry;
		struct xfrm_state *x;

		hlist_for_each_entry(x, entry, xfrm_state_bydst+i, bydst) {
			if (x->km.seq == seq &&
static struct xfrm_state *__xfrm_find_acq_byseq(struct net *net, u32 mark, u32 seq)
{
	int i;

	for (i = 0; i <= net->xfrm.state_hmask; i++) {
		struct xfrm_state *x;

		hlist_for_each_entry(x, net->xfrm.state_bydst+i, bydst) {
			if (x->km.seq == seq &&
			    (mark & x->mark.m) == x->mark.v &&
			    x->km.state == XFRM_STATE_ACQ) {
				xfrm_state_hold(x);
				return x;
			}
		}
	}
	return NULL;
}

struct xfrm_state *xfrm_find_acq_byseq(u32 seq)
{
	struct xfrm_state *x;

	spin_lock_bh(&xfrm_state_lock);
	x = __xfrm_find_acq_byseq(seq);
	spin_unlock_bh(&xfrm_state_lock);
struct xfrm_state *xfrm_find_acq_byseq(struct net *net, u32 mark, u32 seq)
{
	struct xfrm_state *x;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	x = __xfrm_find_acq_byseq(net, mark, seq);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return x;
}
EXPORT_SYMBOL(xfrm_find_acq_byseq);

u32 xfrm_get_acqseq(void)
{
	u32 res;
	static u32 acqseq;
	static DEFINE_SPINLOCK(acqseq_lock);

	spin_lock_bh(&acqseq_lock);
	res = (++acqseq ? : ++acqseq);
	spin_unlock_bh(&acqseq_lock);
	static atomic_t acqseq;

	do {
		res = atomic_inc_return(&acqseq);
	} while (!res);

	return res;
}
EXPORT_SYMBOL(xfrm_get_acqseq);

int xfrm_alloc_spi(struct xfrm_state *x, u32 low, u32 high)
{
int verify_spi_info(u8 proto, u32 min, u32 max)
{
	switch (proto) {
	case IPPROTO_AH:
	case IPPROTO_ESP:
		break;

	case IPPROTO_COMP:
		/* IPCOMP spi is 16-bits. */
		if (max >= 0x10000)
			return -EINVAL;
		break;

	default:
		return -EINVAL;
	}

	if (min > max)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(verify_spi_info);

int xfrm_alloc_spi(struct xfrm_state *x, u32 low, u32 high)
{
	struct net *net = xs_net(x);
	unsigned int h;
	struct xfrm_state *x0;
	int err = -ENOENT;
	__be32 minspi = htonl(low);
	__be32 maxspi = htonl(high);
	u32 mark = x->mark.v & x->mark.m;

	spin_lock_bh(&x->lock);
	if (x->km.state == XFRM_STATE_DEAD)
		goto unlock;

	err = 0;
	if (x->id.spi)
		goto unlock;

	err = -ENOENT;

	if (minspi == maxspi) {
		x0 = xfrm_state_lookup(&x->id.daddr, minspi, x->id.proto, x->props.family);
		x0 = xfrm_state_lookup(net, mark, &x->id.daddr, minspi, x->id.proto, x->props.family);
		if (x0) {
			xfrm_state_put(x0);
			goto unlock;
		}
		x->id.spi = minspi;
	} else {
		u32 spi = 0;
		for (h=0; h<high-low+1; h++) {
			spi = low + net_random()%(high-low+1);
			x0 = xfrm_state_lookup(&x->id.daddr, htonl(spi), x->id.proto, x->props.family);
		for (h = 0; h < high-low+1; h++) {
			spi = low + prandom_u32()%(high-low+1);
			x0 = xfrm_state_lookup(net, mark, &x->id.daddr, htonl(spi), x->id.proto, x->props.family);
			if (x0 == NULL) {
				x->id.spi = htonl(spi);
				break;
			}
			xfrm_state_put(x0);
		}
	}
	if (x->id.spi) {
		spin_lock_bh(&xfrm_state_lock);
		h = xfrm_spi_hash(&x->id.daddr, x->id.spi, x->id.proto, x->props.family);
		hlist_add_head(&x->byspi, xfrm_state_byspi+h);
		spin_unlock_bh(&xfrm_state_lock);
		spin_lock_bh(&net->xfrm.xfrm_state_lock);
		h = xfrm_spi_hash(net, &x->id.daddr, x->id.spi, x->id.proto, x->props.family);
		hlist_add_head_rcu(&x->byspi, net->xfrm.state_byspi + h);
		spin_unlock_bh(&net->xfrm.xfrm_state_lock);

		err = 0;
	}

unlock:
	spin_unlock_bh(&x->lock);

	return err;
}
EXPORT_SYMBOL(xfrm_alloc_spi);

int xfrm_state_walk(struct xfrm_state_walk *walk,
		    int (*func)(struct xfrm_state *, int, void*),
		    void *data)
{
	struct xfrm_state *old, *x, *last = NULL;
	int err = 0;

	if (walk->state == NULL && walk->count != 0)
		return 0;

	old = x = walk->state;
	walk->state = NULL;
	spin_lock_bh(&xfrm_state_lock);
	if (x == NULL)
		x = list_first_entry(&xfrm_state_all, struct xfrm_state, all);
	list_for_each_entry_from(x, &xfrm_state_all, all) {
		if (x->km.state == XFRM_STATE_DEAD)
			continue;
		if (!xfrm_id_proto_match(x->id.proto, walk->proto))
			continue;
		if (last) {
			err = func(last, walk->count, data);
			if (err) {
				xfrm_state_hold(last);
				walk->state = last;
				goto out;
			}
		}
		last = x;
		walk->count++;
	}
	if (walk->count == 0) {
		err = -ENOENT;
		goto out;
	}
	if (last)
		err = func(last, 0, data);
out:
	spin_unlock_bh(&xfrm_state_lock);
	if (old != NULL)
		xfrm_state_put(old);
static bool __xfrm_state_filter_match(struct xfrm_state *x,
				      struct xfrm_address_filter *filter)
{
	if (filter) {
		if ((filter->family == AF_INET ||
		     filter->family == AF_INET6) &&
		    x->props.family != filter->family)
			return false;

		return addr_match(&x->props.saddr, &filter->saddr,
				  filter->splen) &&
		       addr_match(&x->id.daddr, &filter->daddr,
				  filter->dplen);
	}
	return true;
}

int xfrm_state_walk(struct net *net, struct xfrm_state_walk *walk,
		    int (*func)(struct xfrm_state *, int, void*),
		    void *data)
{
	struct xfrm_state *state;
	struct xfrm_state_walk *x;
	int err = 0;

	if (walk->seq != 0 && list_empty(&walk->all))
		return 0;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	if (list_empty(&walk->all))
		x = list_first_entry(&net->xfrm.state_all, struct xfrm_state_walk, all);
	else
		x = list_first_entry(&walk->all, struct xfrm_state_walk, all);
	list_for_each_entry_from(x, &net->xfrm.state_all, all) {
		if (x->state == XFRM_STATE_DEAD)
			continue;
		state = container_of(x, struct xfrm_state, km);
		if (!xfrm_id_proto_match(state->id.proto, walk->proto))
			continue;
		if (!__xfrm_state_filter_match(state, walk->filter))
			continue;
		err = func(state, walk->seq, data);
		if (err) {
			list_move_tail(&walk->all, &x->all);
			goto out;
		}
		walk->seq++;
	}
	if (walk->seq == 0) {
		err = -ENOENT;
		goto out;
	}
	list_del_init(&walk->all);
out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
	return err;
}
EXPORT_SYMBOL(xfrm_state_walk);


void xfrm_replay_notify(struct xfrm_state *x, int event)
{
	struct km_event c;
	/* we send notify messages in case
	 *  1. we updated on of the sequence numbers, and the seqno difference
	 *     is at least x->replay_maxdiff, in this case we also update the
	 *     timeout of our timer function
	 *  2. if x->replay_maxage has elapsed since last update,
	 *     and there were changes
	 *
	 *  The state structure must be locked!
	 */

	switch (event) {
	case XFRM_REPLAY_UPDATE:
		if (x->replay_maxdiff &&
		    (x->replay.seq - x->preplay.seq < x->replay_maxdiff) &&
		    (x->replay.oseq - x->preplay.oseq < x->replay_maxdiff)) {
			if (x->xflags & XFRM_TIME_DEFER)
				event = XFRM_REPLAY_TIMEOUT;
			else
				return;
		}

		break;

	case XFRM_REPLAY_TIMEOUT:
		if ((x->replay.seq == x->preplay.seq) &&
		    (x->replay.bitmap == x->preplay.bitmap) &&
		    (x->replay.oseq == x->preplay.oseq)) {
			x->xflags |= XFRM_TIME_DEFER;
			return;
		}

		break;
	}

	memcpy(&x->preplay, &x->replay, sizeof(struct xfrm_replay_state));
	c.event = XFRM_MSG_NEWAE;
	c.data.aevent = event;
	km_state_notify(x, &c);

	if (x->replay_maxage &&
	    !mod_timer(&x->rtimer, jiffies + x->replay_maxage))
		x->xflags &= ~XFRM_TIME_DEFER;
}

static void xfrm_replay_timer_handler(unsigned long data)
{
	struct xfrm_state *x = (struct xfrm_state*)data;
void xfrm_state_walk_init(struct xfrm_state_walk *walk, u8 proto,
			  struct xfrm_address_filter *filter)
{
	INIT_LIST_HEAD(&walk->all);
	walk->proto = proto;
	walk->state = XFRM_STATE_DEAD;
	walk->seq = 0;
	walk->filter = filter;
}
EXPORT_SYMBOL(xfrm_state_walk_init);

void xfrm_state_walk_done(struct xfrm_state_walk *walk, struct net *net)
{
	kfree(walk->filter);

	if (list_empty(&walk->all))
		return;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	list_del(&walk->all);
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);
}
EXPORT_SYMBOL(xfrm_state_walk_done);

static void xfrm_replay_timer_handler(struct timer_list *t)
{
	struct xfrm_state *x = from_timer(x, t, rtimer);

	spin_lock(&x->lock);

	if (x->km.state == XFRM_STATE_VALID) {
		if (xfrm_aevent_is_on())
			xfrm_replay_notify(x, XFRM_REPLAY_TIMEOUT);
		if (xfrm_aevent_is_on(xs_net(x)))
			x->repl->notify(x, XFRM_REPLAY_TIMEOUT);
		else
			x->xflags |= XFRM_TIME_DEFER;
	}

	spin_unlock(&x->lock);
}

int xfrm_replay_check(struct xfrm_state *x,
		      struct sk_buff *skb, __be32 net_seq)
{
	u32 diff;
	u32 seq = ntohl(net_seq);

	if (unlikely(seq == 0))
		goto err;

	if (likely(seq > x->replay.seq))
		return 0;

	diff = x->replay.seq - seq;
	if (diff >= min_t(unsigned int, x->props.replay_window,
			  sizeof(x->replay.bitmap) * 8)) {
		x->stats.replay_window++;
		goto err;
	}

	if (x->replay.bitmap & (1U << diff)) {
		x->stats.replay++;
		goto err;
	}
	return 0;

err:
	xfrm_audit_state_replay(x, skb, net_seq);
	return -EINVAL;
}

void xfrm_replay_advance(struct xfrm_state *x, __be32 net_seq)
{
	u32 diff;
	u32 seq = ntohl(net_seq);

	if (seq > x->replay.seq) {
		diff = seq - x->replay.seq;
		if (diff < x->props.replay_window)
			x->replay.bitmap = ((x->replay.bitmap) << diff) | 1;
		else
			x->replay.bitmap = 1;
		x->replay.seq = seq;
	} else {
		diff = x->replay.seq - seq;
		x->replay.bitmap |= (1U << diff);
	}

	if (xfrm_aevent_is_on())
		xfrm_replay_notify(x, XFRM_REPLAY_UPDATE);
}

static LIST_HEAD(xfrm_km_list);
static DEFINE_RWLOCK(xfrm_km_lock);

void km_policy_notify(struct xfrm_policy *xp, int dir, struct km_event *c)
{
	struct xfrm_mgr *km;

	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list)
		if (km->notify_policy)
			km->notify_policy(xp, dir, c);
	read_unlock(&xfrm_km_lock);
}

void km_state_notify(struct xfrm_state *x, struct km_event *c)
{
	struct xfrm_mgr *km;
	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list)
		if (km->notify)
			km->notify(x, c);
	read_unlock(&xfrm_km_lock);
static LIST_HEAD(xfrm_km_list);

void km_policy_notify(struct xfrm_policy *xp, int dir, const struct km_event *c)
{
	struct xfrm_mgr *km;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list)
		if (km->notify_policy)
			km->notify_policy(xp, dir, c);
	rcu_read_unlock();
}

void km_state_notify(struct xfrm_state *x, const struct km_event *c)
{
	struct xfrm_mgr *km;
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list)
		if (km->notify)
			km->notify(x, c);
	rcu_read_unlock();
}

EXPORT_SYMBOL(km_policy_notify);
EXPORT_SYMBOL(km_state_notify);

void km_state_expired(struct xfrm_state *x, int hard, u32 pid)
void km_state_expired(struct xfrm_state *x, int hard, u32 portid)
{
	struct km_event c;

	c.data.hard = hard;
	c.pid = pid;
	c.event = XFRM_MSG_EXPIRE;
	km_state_notify(x, &c);

	if (hard)
		wake_up(&km_waitq);
	c.portid = portid;
	c.event = XFRM_MSG_EXPIRE;
	km_state_notify(x, &c);
}

EXPORT_SYMBOL(km_state_expired);
/*
 * We send to all registered managers regardless of failure
 * We are happy with one success
*/
int km_query(struct xfrm_state *x, struct xfrm_tmpl *t, struct xfrm_policy *pol)
{
	int err = -EINVAL, acqret;
	struct xfrm_mgr *km;

	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list) {
		acqret = km->acquire(x, t, pol, XFRM_POLICY_OUT);
		if (!acqret)
			err = acqret;
	}
	read_unlock(&xfrm_km_lock);
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		acqret = km->acquire(x, t, pol);
		if (!acqret)
			err = acqret;
	}
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_query);

int km_new_mapping(struct xfrm_state *x, xfrm_address_t *ipaddr, __be16 sport)
{
	int err = -EINVAL;
	struct xfrm_mgr *km;

	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list) {
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->new_mapping)
			err = km->new_mapping(x, ipaddr, sport);
		if (!err)
			break;
	}
	read_unlock(&xfrm_km_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_new_mapping);

void km_policy_expired(struct xfrm_policy *pol, int dir, int hard, u32 pid)
void km_policy_expired(struct xfrm_policy *pol, int dir, int hard, u32 portid)
{
	struct km_event c;

	c.data.hard = hard;
	c.pid = pid;
	c.event = XFRM_MSG_POLEXPIRE;
	km_policy_notify(pol, dir, &c);

	if (hard)
		wake_up(&km_waitq);
	c.portid = portid;
	c.event = XFRM_MSG_POLEXPIRE;
	km_policy_notify(pol, dir, &c);
}
EXPORT_SYMBOL(km_policy_expired);

#ifdef CONFIG_XFRM_MIGRATE
int km_migrate(struct xfrm_selector *sel, u8 dir, u8 type,
	       struct xfrm_migrate *m, int num_migrate)
int km_migrate(const struct xfrm_selector *sel, u8 dir, u8 type,
	       const struct xfrm_migrate *m, int num_migrate,
	       const struct xfrm_kmaddress *k,
	       const struct xfrm_encap_tmpl *encap)
{
	int err = -EINVAL;
	int ret;
	struct xfrm_mgr *km;

	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list) {
		if (km->migrate) {
			ret = km->migrate(sel, dir, type, m, num_migrate);
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->migrate) {
			ret = km->migrate(sel, dir, type, m, num_migrate, k,
					  encap);
			if (!ret)
				err = ret;
		}
	}
	read_unlock(&xfrm_km_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_migrate);
#endif

int km_report(u8 proto, struct xfrm_selector *sel, xfrm_address_t *addr)
int km_report(struct net *net, u8 proto, struct xfrm_selector *sel, xfrm_address_t *addr)
{
	int err = -EINVAL;
	int ret;
	struct xfrm_mgr *km;

	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list) {
		if (km->report) {
			ret = km->report(proto, sel, addr);
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->report) {
			ret = km->report(net, proto, sel, addr);
			if (!ret)
				err = ret;
		}
	}
	read_unlock(&xfrm_km_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(km_report);

bool km_is_alive(const struct km_event *c)
{
	struct xfrm_mgr *km;
	bool is_alive = false;

	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		if (km->is_alive && km->is_alive(c)) {
			is_alive = true;
			break;
		}
	}
	rcu_read_unlock();

	return is_alive;
}
EXPORT_SYMBOL(km_is_alive);

int xfrm_user_policy(struct sock *sk, int optname, u8 __user *optval, int optlen)
{
	int err;
	u8 *data;
	struct xfrm_mgr *km;
	struct xfrm_policy *pol = NULL;

#ifdef CONFIG_COMPAT
	if (in_compat_syscall())
		return -EOPNOTSUPP;
#endif

	if (!optval && !optlen) {
		xfrm_sk_policy_insert(sk, XFRM_POLICY_IN, NULL);
		xfrm_sk_policy_insert(sk, XFRM_POLICY_OUT, NULL);
		__sk_dst_reset(sk);
		return 0;
	}

	if (optlen <= 0 || optlen > PAGE_SIZE)
		return -EMSGSIZE;

	data = memdup_user(optval, optlen);
	if (IS_ERR(data))
		return PTR_ERR(data);

	err = -EINVAL;
	read_lock(&xfrm_km_lock);
	list_for_each_entry(km, &xfrm_km_list, list) {
	rcu_read_lock();
	list_for_each_entry_rcu(km, &xfrm_km_list, list) {
		pol = km->compile_policy(sk, optname, data,
					 optlen, &err);
		if (err >= 0)
			break;
	}
	read_unlock(&xfrm_km_lock);
	rcu_read_unlock();

	if (err >= 0) {
		xfrm_sk_policy_insert(sk, err, pol);
		xfrm_pol_put(pol);
		__sk_dst_reset(sk);
		err = 0;
	}

	kfree(data);
	return err;
}
EXPORT_SYMBOL(xfrm_user_policy);

int xfrm_register_km(struct xfrm_mgr *km)
{
	write_lock_bh(&xfrm_km_lock);
	list_add_tail(&km->list, &xfrm_km_list);
	write_unlock_bh(&xfrm_km_lock);
static DEFINE_SPINLOCK(xfrm_km_lock);

int xfrm_register_km(struct xfrm_mgr *km)
{
	spin_lock_bh(&xfrm_km_lock);
	list_add_tail_rcu(&km->list, &xfrm_km_list);
	spin_unlock_bh(&xfrm_km_lock);
	return 0;
}
EXPORT_SYMBOL(xfrm_register_km);

int xfrm_unregister_km(struct xfrm_mgr *km)
{
	write_lock_bh(&xfrm_km_lock);
	list_del(&km->list);
	write_unlock_bh(&xfrm_km_lock);
	spin_lock_bh(&xfrm_km_lock);
	list_del_rcu(&km->list);
	spin_unlock_bh(&xfrm_km_lock);
	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL(xfrm_unregister_km);

int xfrm_state_register_afinfo(struct xfrm_state_afinfo *afinfo)
{
	int err = 0;

	if (WARN_ON(afinfo->family >= NPROTO))
		return -EAFNOSUPPORT;
	write_lock_bh(&xfrm_state_afinfo_lock);
	if (unlikely(xfrm_state_afinfo[afinfo->family] != NULL))
		err = -ENOBUFS;
	else
		xfrm_state_afinfo[afinfo->family] = afinfo;
	write_unlock_bh(&xfrm_state_afinfo_lock);

	spin_lock_bh(&xfrm_state_afinfo_lock);
	if (unlikely(xfrm_state_afinfo[afinfo->family] != NULL))
		err = -EEXIST;
	else
		rcu_assign_pointer(xfrm_state_afinfo[afinfo->family], afinfo);
	spin_unlock_bh(&xfrm_state_afinfo_lock);
	return err;
}
EXPORT_SYMBOL(xfrm_state_register_afinfo);

int xfrm_state_unregister_afinfo(struct xfrm_state_afinfo *afinfo)
{
	int err = 0, family = afinfo->family;

	if (WARN_ON(family >= NPROTO))
		return -EAFNOSUPPORT;
	write_lock_bh(&xfrm_state_afinfo_lock);

	spin_lock_bh(&xfrm_state_afinfo_lock);
	if (likely(xfrm_state_afinfo[afinfo->family] != NULL)) {
		if (rcu_access_pointer(xfrm_state_afinfo[family]) != afinfo)
			err = -EINVAL;
		else
			xfrm_state_afinfo[afinfo->family] = NULL;
	}
	write_unlock_bh(&xfrm_state_afinfo_lock);
			RCU_INIT_POINTER(xfrm_state_afinfo[afinfo->family], NULL);
	}
	spin_unlock_bh(&xfrm_state_afinfo_lock);
	synchronize_rcu();
	return err;
}
EXPORT_SYMBOL(xfrm_state_unregister_afinfo);

static struct xfrm_state_afinfo *xfrm_state_get_afinfo(unsigned int family)
struct xfrm_state_afinfo *xfrm_state_afinfo_get_rcu(unsigned int family)
{
	if (unlikely(family >= NPROTO))
		return NULL;

	return rcu_dereference(xfrm_state_afinfo[family]);
}

struct xfrm_state_afinfo *xfrm_state_get_afinfo(unsigned int family)
{
	struct xfrm_state_afinfo *afinfo;
	if (unlikely(family >= NPROTO))
		return NULL;
	read_lock(&xfrm_state_afinfo_lock);
	afinfo = xfrm_state_afinfo[family];
	if (unlikely(!afinfo))
		read_unlock(&xfrm_state_afinfo_lock);
	return afinfo;
}

static void xfrm_state_put_afinfo(struct xfrm_state_afinfo *afinfo)
	__releases(xfrm_state_afinfo_lock)
{
	read_unlock(&xfrm_state_afinfo_lock);
	rcu_read_lock();
	afinfo = rcu_dereference(xfrm_state_afinfo[family]);
	if (unlikely(!afinfo))
		rcu_read_unlock();
	return afinfo;
}

void xfrm_flush_gc(void)
{
	flush_work(&xfrm_state_gc_work);
}
EXPORT_SYMBOL(xfrm_flush_gc);

/* Temporarily located here until net/xfrm/xfrm_tunnel.c is created */
void xfrm_state_delete_tunnel(struct xfrm_state *x)
{
	if (x->tunnel) {
		struct xfrm_state *t = x->tunnel;

		if (atomic_read(&t->tunnel_users) == 2)
			xfrm_state_delete(t);
		atomic_dec(&t->tunnel_users);
		xfrm_state_put(t);
		x->tunnel = NULL;
	}
}
EXPORT_SYMBOL(xfrm_state_delete_tunnel);

int xfrm_state_mtu(struct xfrm_state *x, int mtu)
{
	const struct xfrm_type *type = READ_ONCE(x->type);

	if (x->km.state == XFRM_STATE_VALID &&
	    type && type->get_mtu)
		return type->get_mtu(x, mtu);

	return mtu - x->props.header_len;
}

int xfrm_init_state(struct xfrm_state *x)
int __xfrm_init_state(struct xfrm_state *x, bool init_replay)
int __xfrm_init_state(struct xfrm_state *x, bool init_replay, bool offload)
{
	struct xfrm_state_afinfo *afinfo;
	struct xfrm_mode *inner_mode;
	int family = x->props.family;
	int err;

	err = -EAFNOSUPPORT;
	afinfo = xfrm_state_get_afinfo(family);
	if (!afinfo)
		goto error;

	err = 0;
	if (afinfo->init_flags)
		err = afinfo->init_flags(x);

	rcu_read_unlock();

	if (err)
		goto error;

	err = -EPROTONOSUPPORT;

	if (x->sel.family != AF_UNSPEC) {
		inner_mode = xfrm_get_mode(x->props.mode, x->sel.family);
		if (inner_mode == NULL)
			goto error;

		if (!(inner_mode->flags & XFRM_MODE_FLAG_TUNNEL) &&
		    family != x->sel.family) {
			xfrm_put_mode(inner_mode);
			goto error;
		}

		x->inner_mode = inner_mode;
	} else {
		struct xfrm_mode *inner_mode_iaf;

		inner_mode = xfrm_get_mode(x->props.mode, AF_INET);
		int iafamily = AF_INET;

		inner_mode = xfrm_get_mode(x->props.mode, x->props.family);
		if (inner_mode == NULL)
			goto error;

		if (!(inner_mode->flags & XFRM_MODE_FLAG_TUNNEL)) {
			xfrm_put_mode(inner_mode);
			goto error;
		}

		inner_mode_iaf = xfrm_get_mode(x->props.mode, AF_INET6);
		if (inner_mode_iaf == NULL)
			goto error;

		if (!(inner_mode_iaf->flags & XFRM_MODE_FLAG_TUNNEL)) {
			xfrm_put_mode(inner_mode_iaf);
			goto error;
		}

		if (x->props.family == AF_INET) {
			x->inner_mode = inner_mode;
			x->inner_mode_iaf = inner_mode_iaf;
		} else {
			x->inner_mode = inner_mode_iaf;
			x->inner_mode_iaf = inner_mode;
		x->inner_mode = inner_mode;

		if (x->props.family == AF_INET)
			iafamily = AF_INET6;

		inner_mode_iaf = xfrm_get_mode(x->props.mode, iafamily);
		if (inner_mode_iaf) {
			if (inner_mode_iaf->flags & XFRM_MODE_FLAG_TUNNEL)
				x->inner_mode_iaf = inner_mode_iaf;
			else
				xfrm_put_mode(inner_mode_iaf);
		}
	}

	x->type = xfrm_get_type(x->id.proto, family);
	if (x->type == NULL)
		goto error;

	x->type_offload = xfrm_get_type_offload(x->id.proto, family, offload);

	err = x->type->init_state(x);
	if (err)
		goto error;

	x->outer_mode = xfrm_get_mode(x->props.mode, family);
	if (x->outer_mode == NULL)
		goto error;
	if (x->outer_mode == NULL) {
		err = -EPROTONOSUPPORT;
		goto error;
	}

	if (init_replay) {
		err = xfrm_init_replay(x);
		if (err)
			goto error;
	}

error:
	return err;
}

EXPORT_SYMBOL(xfrm_init_state);

void __init xfrm_state_init(void)
{
	unsigned int sz;

	sz = sizeof(struct hlist_head) * 8;

	xfrm_state_bydst = xfrm_hash_alloc(sz);
	xfrm_state_bysrc = xfrm_hash_alloc(sz);
	xfrm_state_byspi = xfrm_hash_alloc(sz);
	if (!xfrm_state_bydst || !xfrm_state_bysrc || !xfrm_state_byspi)
		panic("XFRM: Cannot allocate bydst/bysrc/byspi hashes.");
	xfrm_state_hmask = ((sz / sizeof(struct hlist_head)) - 1);

	INIT_WORK(&xfrm_state_gc_work, xfrm_state_gc_task);
EXPORT_SYMBOL(__xfrm_init_state);

int xfrm_init_state(struct xfrm_state *x)
{
	int err;

	err = __xfrm_init_state(x, true, false);
	if (!err)
		x->km.state = XFRM_STATE_VALID;

	return err;
}

EXPORT_SYMBOL(xfrm_init_state);

int __net_init xfrm_state_init(struct net *net)
{
	unsigned int sz;

	if (net_eq(net, &init_net))
		xfrm_state_cache = KMEM_CACHE(xfrm_state,
					      SLAB_HWCACHE_ALIGN | SLAB_PANIC);

	INIT_LIST_HEAD(&net->xfrm.state_all);

	sz = sizeof(struct hlist_head) * 8;

	net->xfrm.state_bydst = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_bydst)
		goto out_bydst;
	net->xfrm.state_bysrc = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_bysrc)
		goto out_bysrc;
	net->xfrm.state_byspi = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_byspi)
		goto out_byspi;
	net->xfrm.state_hmask = ((sz / sizeof(struct hlist_head)) - 1);

	net->xfrm.state_num = 0;
	INIT_WORK(&net->xfrm.state_hash_work, xfrm_hash_resize);
	spin_lock_init(&net->xfrm.xfrm_state_lock);
	return 0;

out_byspi:
	xfrm_hash_free(net->xfrm.state_bysrc, sz);
out_bysrc:
	xfrm_hash_free(net->xfrm.state_bydst, sz);
out_bydst:
	return -ENOMEM;
}

void xfrm_state_fini(struct net *net)
{
	unsigned int sz;

	flush_work(&net->xfrm.state_hash_work);
	xfrm_state_flush(net, IPSEC_PROTO_ANY, false);
	flush_work(&xfrm_state_gc_work);

	WARN_ON(!list_empty(&net->xfrm.state_all));

	sz = (net->xfrm.state_hmask + 1) * sizeof(struct hlist_head);
	WARN_ON(!hlist_empty(net->xfrm.state_byspi));
	xfrm_hash_free(net->xfrm.state_byspi, sz);
	WARN_ON(!hlist_empty(net->xfrm.state_bysrc));
	xfrm_hash_free(net->xfrm.state_bysrc, sz);
	WARN_ON(!hlist_empty(net->xfrm.state_bydst));
	xfrm_hash_free(net->xfrm.state_bydst, sz);
}

#ifdef CONFIG_AUDITSYSCALL
static void xfrm_audit_helper_sainfo(struct xfrm_state *x,
				     struct audit_buffer *audit_buf)
{
	struct xfrm_sec_ctx *ctx = x->security;
	u32 spi = ntohl(x->id.spi);

	if (ctx)
		audit_log_format(audit_buf, " sec_alg=%u sec_doi=%u sec_obj=%s",
				 ctx->ctx_alg, ctx->ctx_doi, ctx->ctx_str);

	switch(x->props.family) {
	case AF_INET:
		audit_log_format(audit_buf,
				 " src=" NIPQUAD_FMT " dst=" NIPQUAD_FMT,
				 NIPQUAD(x->props.saddr.a4),
				 NIPQUAD(x->id.daddr.a4));
		break;
	case AF_INET6:
		audit_log_format(audit_buf,
				 " src=" NIP6_FMT " dst=" NIP6_FMT,
				 NIP6(*(struct in6_addr *)x->props.saddr.a6),
				 NIP6(*(struct in6_addr *)x->id.daddr.a6));
	switch (x->props.family) {
	case AF_INET:
		audit_log_format(audit_buf, " src=%pI4 dst=%pI4",
				 &x->props.saddr.a4, &x->id.daddr.a4);
		break;
	case AF_INET6:
		audit_log_format(audit_buf, " src=%pI6 dst=%pI6",
				 x->props.saddr.a6, x->id.daddr.a6);
		break;
	}

	audit_log_format(audit_buf, " spi=%u(0x%x)", spi, spi);
}

static void xfrm_audit_helper_pktinfo(struct sk_buff *skb, u16 family,
				      struct audit_buffer *audit_buf)
{
	struct iphdr *iph4;
	struct ipv6hdr *iph6;
	const struct iphdr *iph4;
	const struct ipv6hdr *iph6;

	switch (family) {
	case AF_INET:
		iph4 = ip_hdr(skb);
		audit_log_format(audit_buf,
				 " src=" NIPQUAD_FMT " dst=" NIPQUAD_FMT,
				 NIPQUAD(iph4->saddr),
				 NIPQUAD(iph4->daddr));
		audit_log_format(audit_buf, " src=%pI4 dst=%pI4",
				 &iph4->saddr, &iph4->daddr);
		break;
	case AF_INET6:
		iph6 = ipv6_hdr(skb);
		audit_log_format(audit_buf,
				 " src=" NIP6_FMT " dst=" NIP6_FMT
				 " flowlbl=0x%x%02x%02x",
				 NIP6(iph6->saddr),
				 NIP6(iph6->daddr),
				 " src=%pI6 dst=%pI6 flowlbl=0x%x%02x%02x",
				 &iph6->saddr, &iph6->daddr,
				 iph6->flow_lbl[0] & 0x0f,
				 iph6->flow_lbl[1],
				 iph6->flow_lbl[2]);
		break;
	}
}

void xfrm_audit_state_add(struct xfrm_state *x, int result,
			  uid_t auid, u32 sessionid, u32 secid)
void xfrm_audit_state_add(struct xfrm_state *x, int result, bool task_valid)
{
	struct audit_buffer *audit_buf;

	audit_buf = xfrm_audit_start("SAD-add");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_usrinfo(auid, sessionid, secid, audit_buf);
	xfrm_audit_helper_usrinfo(task_valid, audit_buf);
	xfrm_audit_helper_sainfo(x, audit_buf);
	audit_log_format(audit_buf, " res=%u", result);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_add);

void xfrm_audit_state_delete(struct xfrm_state *x, int result,
			     uid_t auid, u32 sessionid, u32 secid)
void xfrm_audit_state_delete(struct xfrm_state *x, int result, bool task_valid)
{
	struct audit_buffer *audit_buf;

	audit_buf = xfrm_audit_start("SAD-delete");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_usrinfo(auid, sessionid, secid, audit_buf);
	xfrm_audit_helper_usrinfo(task_valid, audit_buf);
	xfrm_audit_helper_sainfo(x, audit_buf);
	audit_log_format(audit_buf, " res=%u", result);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_delete);

void xfrm_audit_state_replay_overflow(struct xfrm_state *x,
				      struct sk_buff *skb)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	audit_buf = xfrm_audit_start("SA-replay-overflow");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	/* don't record the sequence number because it's inherent in this kind
	 * of audit message */
	spi = ntohl(x->id.spi);
	audit_log_format(audit_buf, " spi=%u(0x%x)", spi, spi);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_replay_overflow);

static void xfrm_audit_state_replay(struct xfrm_state *x,
void xfrm_audit_state_replay(struct xfrm_state *x,
			     struct sk_buff *skb, __be32 net_seq)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	audit_buf = xfrm_audit_start("SA-replayed-pkt");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	spi = ntohl(x->id.spi);
	audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
			 spi, spi, ntohl(net_seq));
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_replay);

void xfrm_audit_state_notfound_simple(struct sk_buff *skb, u16 family)
{
	struct audit_buffer *audit_buf;

	audit_buf = xfrm_audit_start("SA-notfound");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, family, audit_buf);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_notfound_simple);

void xfrm_audit_state_notfound(struct sk_buff *skb, u16 family,
			       __be32 net_spi, __be32 net_seq)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	audit_buf = xfrm_audit_start("SA-notfound");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, family, audit_buf);
	spi = ntohl(net_spi);
	audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
			 spi, spi, ntohl(net_seq));
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_notfound);

void xfrm_audit_state_icvfail(struct xfrm_state *x,
			      struct sk_buff *skb, u8 proto)
{
	struct audit_buffer *audit_buf;
	__be32 net_spi;
	__be32 net_seq;

	audit_buf = xfrm_audit_start("SA-icv-failure");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	if (xfrm_parse_spi(skb, proto, &net_spi, &net_seq) == 0) {
		u32 spi = ntohl(net_spi);
		audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
				 spi, spi, ntohl(net_seq));
	}
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_icvfail);
#endif /* CONFIG_AUDITSYSCALL */
