/* Structure dynamic extension infrastructure
 * Copyright (C) 2004 Rusty Russell IBM Corporation
 * Copyright (C) 2007 Netfilter Core Team <coreteam@netfilter.org>
 * Copyright (C) 2007 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_extend.h>

static struct nf_ct_ext_type *nf_ct_ext_types[NF_CT_EXT_NUM];
static struct nf_ct_ext_type __rcu *nf_ct_ext_types[NF_CT_EXT_NUM];
static DEFINE_MUTEX(nf_ct_ext_type_mutex);
#define NF_CT_EXT_PREALLOC	128u /* conntrack events are on by default */

void nf_ct_ext_destroy(struct nf_conn *ct)
{
	unsigned int i;
	struct nf_ct_ext_type *t;

	for (i = 0; i < NF_CT_EXT_NUM; i++) {
		if (!nf_ct_ext_exist(ct, i))
	struct nf_ct_ext *ext = ct->ext;

	for (i = 0; i < NF_CT_EXT_NUM; i++) {
		rcu_read_lock();
		t = rcu_dereference(nf_ct_ext_types[i]);

		/* Here the nf_ct_ext_type might have been unregisterd.
		 * I.e., it has responsible to cleanup private
		 * area in all conntracks when it is unregisterd.
		 */
		if (t && t->destroy)
			t->destroy(ct);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(nf_ct_ext_destroy);

static void *
nf_ct_ext_create(struct nf_ct_ext **ext, enum nf_ct_ext_id id, gfp_t gfp)
{
	unsigned int off, len;
	struct nf_ct_ext_type *t;
nf_ct_ext_create(struct nf_ct_ext **ext, enum nf_ct_ext_id id,
		 size_t var_alloc_len, gfp_t gfp)
{
	unsigned int off, len;
	struct nf_ct_ext_type *t;
	size_t alloc_size;

	rcu_read_lock();
	t = rcu_dereference(nf_ct_ext_types[id]);
	BUG_ON(t == NULL);
	off = ALIGN(sizeof(struct nf_ct_ext), t->align);
	len = off + t->len;
	rcu_read_unlock();

	*ext = kzalloc(t->alloc_size, gfp);
	if (!*ext)
		return NULL;

	INIT_RCU_HEAD(&(*ext)->rcu);
	len = off + t->len + var_alloc_len;
	alloc_size = t->alloc_size + var_alloc_len;
	rcu_read_unlock();

	*ext = kzalloc(alloc_size, gfp);
	if (!*ext)
		return NULL;

	(*ext)->offset[id] = off;
	(*ext)->len = len;

	return (void *)(*ext) + off;
}

static void __nf_ct_ext_free_rcu(struct rcu_head *head)
{
	struct nf_ct_ext *ext = container_of(head, struct nf_ct_ext, rcu);
	kfree(ext);
}

void *__nf_ct_ext_add(struct nf_conn *ct, enum nf_ct_ext_id id, gfp_t gfp)
{
	struct nf_ct_ext *new;
void *__nf_ct_ext_add_length(struct nf_conn *ct, enum nf_ct_ext_id id,
			     size_t var_alloc_len, gfp_t gfp)
void *nf_ct_ext_add(struct nf_conn *ct, enum nf_ct_ext_id id, gfp_t gfp)
{
	unsigned int newlen, newoff, oldlen, alloc;
	struct nf_ct_ext *old, *new;
	struct nf_ct_ext_type *t;

	/* Conntrack must not be confirmed to avoid races on reallocation. */
	WARN_ON(nf_ct_is_confirmed(ct));

	if (!ct->ext)
		return nf_ct_ext_create(&ct->ext, id, gfp);

	if (nf_ct_ext_exist(ct, id))
	old = ct->ext;

	if (old) {
		if (__nf_ct_ext_exist(old, id))
			return NULL;
		oldlen = old->len;
	} else {
		oldlen = sizeof(*new);
	}

	rcu_read_lock();
	t = rcu_dereference(nf_ct_ext_types[id]);
	if (!t) {
		rcu_read_unlock();
		return NULL;
	}

	newoff = ALIGN(ct->ext->len, t->align);
	newlen = newoff + t->len;
	rcu_read_unlock();

	new = __krealloc(ct->ext, newlen, gfp);
	if (!new)
		return NULL;

	if (new != ct->ext) {
		for (i = 0; i < NF_CT_EXT_NUM; i++) {
			if (!nf_ct_ext_exist(ct, i))
	newoff = ALIGN(old->len, t->align);
	newlen = newoff + t->len + var_alloc_len;
	newoff = ALIGN(oldlen, t->align);
	newlen = newoff + t->len;
	rcu_read_unlock();

	alloc = max(newlen, NF_CT_EXT_PREALLOC);
	kmemleak_not_leak(old);
	new = __krealloc(old, alloc, gfp);
	if (!new)
		return NULL;

	if (new != old) {
		for (i = 0; i < NF_CT_EXT_NUM; i++) {
			if (!__nf_ct_ext_exist(old, i))
				continue;

			rcu_read_lock();
			t = rcu_dereference(nf_ct_ext_types[i]);
			if (t && t->move)
				t->move((void *)new + new->offset[i],
					(void *)ct->ext + ct->ext->offset[i]);
			rcu_read_unlock();
		}
		call_rcu(&ct->ext->rcu, __nf_ct_ext_free_rcu);
					(void *)old + old->offset[i]);
			rcu_read_unlock();
		}
		kfree_rcu(old, rcu);
	if (!old) {
		memset(new->offset, 0, sizeof(new->offset));
		ct->ext = new;
	} else if (new != old) {
		kfree_rcu(old, rcu);
		rcu_assign_pointer(ct->ext, new);
	}

	new->offset[id] = newoff;
	new->len = newlen;
	memset((void *)new + newoff, 0, newlen - newoff);
	return (void *)new + newoff;
}
EXPORT_SYMBOL(__nf_ct_ext_add);
EXPORT_SYMBOL(__nf_ct_ext_add_length);

static void update_alloc_size(struct nf_ct_ext_type *type)
{
	int i, j;
	struct nf_ct_ext_type *t1, *t2;
	enum nf_ct_ext_id min = 0, max = NF_CT_EXT_NUM - 1;

	/* unnecessary to update all types */
	if ((type->flags & NF_CT_EXT_F_PREALLOC) == 0) {
		min = type->id;
		max = type->id;
	}

	/* This assumes that extended areas in conntrack for the types
	   whose NF_CT_EXT_F_PREALLOC bit set are allocated in order */
	for (i = min; i <= max; i++) {
		t1 = nf_ct_ext_types[i];
		if (!t1)
			continue;

		t1->alloc_size = sizeof(struct nf_ct_ext)
				 + ALIGN(sizeof(struct nf_ct_ext), t1->align)
				 + t1->len;
		for (j = 0; j < NF_CT_EXT_NUM; j++) {
			t2 = nf_ct_ext_types[j];
		t1 = rcu_dereference_protected(nf_ct_ext_types[i],
				lockdep_is_held(&nf_ct_ext_type_mutex));
		if (!t1)
			continue;

		t1->alloc_size = ALIGN(sizeof(struct nf_ct_ext), t1->align) +
				 t1->len;
		for (j = 0; j < NF_CT_EXT_NUM; j++) {
			t2 = rcu_dereference_protected(nf_ct_ext_types[j],
				lockdep_is_held(&nf_ct_ext_type_mutex));
			if (t2 == NULL || t2 == t1 ||
			    (t2->flags & NF_CT_EXT_F_PREALLOC) == 0)
				continue;

			t1->alloc_size = ALIGN(t1->alloc_size, t2->align)
					 + t2->len;
		}
	}
}
EXPORT_SYMBOL(nf_ct_ext_add);

/* This MUST be called in process context. */
int nf_ct_extend_register(const struct nf_ct_ext_type *type)
{
	int ret = 0;

	mutex_lock(&nf_ct_ext_type_mutex);
	if (nf_ct_ext_types[type->id]) {
		ret = -EBUSY;
		goto out;
	}

	rcu_assign_pointer(nf_ct_ext_types[type->id], type);
out:
	mutex_unlock(&nf_ct_ext_type_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_extend_register);

/* This MUST be called in process context. */
void nf_ct_extend_unregister(const struct nf_ct_ext_type *type)
{
	mutex_lock(&nf_ct_ext_type_mutex);
	rcu_assign_pointer(nf_ct_ext_types[type->id], NULL);
	update_alloc_size(type);
	mutex_unlock(&nf_ct_ext_type_mutex);
	synchronize_rcu();
	RCU_INIT_POINTER(nf_ct_ext_types[type->id], NULL);
	mutex_unlock(&nf_ct_ext_type_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_ct_extend_unregister);
