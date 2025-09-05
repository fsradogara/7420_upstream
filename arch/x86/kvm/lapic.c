
/*
 * Local APIC virtualization
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright (C) 2007 Novell
 * Copyright (C) 2007 Intel
 * Copyright 2009 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Dor Laor <dor.laor@qumranet.com>
 *   Gregory Haskins <ghaskins@novell.com>
 *   Yaozu (Eddie) Dong <eddie.dong@intel.com>
 *
 * Based on Xen 3.1 code, Copyright (c) 2004, Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/smp.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/export.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/apicdef.h>
#include <asm/atomic.h>
#include "irq.h"
#include <asm/delay.h>
#include <linux/atomic.h>
#include <linux/jump_label.h>
#include "kvm_cache_regs.h"
#include "irq.h"
#include "trace.h"
#include "x86.h"
#include "cpuid.h"
#include "hyperv.h"

#ifndef CONFIG_X86_64
#define mod_64(x, y) ((x) - (y) * div64_u64(x, y))
#else
#define mod_64(x, y) ((x) % (y))
#endif

#define PRId64 "d"
#define PRIx64 "llx"
#define PRIu64 "u"
#define PRIo64 "o"

/* #define apic_debug(fmt,arg...) printk(KERN_WARNING fmt,##arg) */
#define apic_debug(fmt, arg...)

/* 14 is the version for Xeon and Pentium 8.4.8*/
#define APIC_VERSION			(0x14UL | ((KVM_APIC_LVT_NUM - 1) << 16))
#define LAPIC_MMIO_LENGTH		(1 << 12)
/* followed define is not in apicdef.h */
#define APIC_SHORT_MASK			0xc0000
#define APIC_DEST_NOSHORT		0x0
#define APIC_DEST_MASK			0x800
#define MAX_APIC_VECTOR			256
#define APIC_VECTORS_PER_REG		32

#define APIC_BROADCAST			0xFF
#define X2APIC_BROADCAST		0xFFFFFFFFul

#define VEC_POS(v) ((v) & (32 - 1))
#define REG_POS(v) (((v) >> 5) << 4)

static inline u32 apic_get_reg(struct kvm_lapic *apic, int reg_off)
{
	return *((u32 *) (apic->regs + reg_off));
}

static inline void apic_set_reg(struct kvm_lapic *apic, int reg_off, u32 val)
{
	*((u32 *) (apic->regs + reg_off)) = val;
}

static inline int apic_test_and_set_vector(int vec, void *bitmap)
{
	return test_and_set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline int apic_test_and_clear_vector(int vec, void *bitmap)
{
	return test_and_clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
static inline int apic_test_vector(int vec, void *bitmap)
{
	return test_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

bool kvm_apic_pending_eoi(struct kvm_vcpu *vcpu, int vector)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	return apic_test_vector(vector, apic->regs + APIC_ISR) ||
		apic_test_vector(vector, apic->regs + APIC_IRR);
}

static inline void apic_clear_vector(int vec, void *bitmap)
{
	clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline int apic_hw_enabled(struct kvm_lapic *apic)
{
	return (apic)->vcpu->arch.apic_base & MSR_IA32_APICBASE_ENABLE;
}

static inline int  apic_sw_enabled(struct kvm_lapic *apic)
{
	return apic_get_reg(apic, APIC_SPIV) & APIC_SPIV_APIC_ENABLED;
}

static inline int apic_enabled(struct kvm_lapic *apic)
{
	return apic_sw_enabled(apic) &&	apic_hw_enabled(apic);
static inline int __apic_test_and_set_vector(int vec, void *bitmap)
{
	return __test_and_set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline int __apic_test_and_clear_vector(int vec, void *bitmap)
{
	return __test_and_clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

struct static_key_deferred apic_hw_disabled __read_mostly;
struct static_key_deferred apic_sw_disabled __read_mostly;

static inline int apic_enabled(struct kvm_lapic *apic)
{
	return kvm_apic_sw_enabled(apic) &&	kvm_apic_hw_enabled(apic);
}

#define LVT_MASK	\
	(APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK)

#define LINT_MASK	\
	(LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY | \
	 APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER)

static inline u8 kvm_xapic_id(struct kvm_lapic *apic)
{
	return (apic_get_reg(apic, APIC_ID) >> 24) & 0xff;
	return (kvm_apic_get_reg(apic, APIC_ID) >> 24) & 0xff;
	return kvm_lapic_get_reg(apic, APIC_ID) >> 24;
}

static inline u32 kvm_x2apic_id(struct kvm_lapic *apic)
{
	return apic->vcpu->vcpu_id;
}

static inline bool kvm_apic_map_get_logical_dest(struct kvm_apic_map *map,
		u32 dest_id, struct kvm_lapic ***cluster, u16 *mask) {
	switch (map->mode) {
	case KVM_APIC_MODE_X2APIC: {
		u32 offset = (dest_id >> 16) * 16;
		u32 max_apic_id = map->max_apic_id;

		if (offset <= max_apic_id) {
			u8 cluster_size = min(max_apic_id - offset + 1, 16U);

			*cluster = &map->phys_map[offset];
			*mask = dest_id & (0xffff >> (16 - cluster_size));
		} else {
			*mask = 0;
		}

		return true;
		}
	case KVM_APIC_MODE_XAPIC_FLAT:
		*cluster = map->xapic_flat_map;
		*mask = dest_id & 0xff;
		return true;
	case KVM_APIC_MODE_XAPIC_CLUSTER:
		*cluster = map->xapic_cluster_map[(dest_id >> 4) & 0xf];
		*mask = dest_id & 0xf;
		return true;
	default:
		/* Not optimized. */
		return false;
	}
}

static void kvm_apic_map_free(struct rcu_head *rcu)
{
	struct kvm_apic_map *map = container_of(rcu, struct kvm_apic_map, rcu);

	kvfree(map);
}

static void recalculate_apic_map(struct kvm *kvm)
{
	struct kvm_apic_map *new, *old = NULL;
	struct kvm_vcpu *vcpu;
	int i;
	u32 max_id = 255; /* enough space for any xAPIC ID */

	mutex_lock(&kvm->arch.apic_map_lock);

	kvm_for_each_vcpu(i, vcpu, kvm)
		if (kvm_apic_present(vcpu))
			max_id = max(max_id, kvm_x2apic_id(vcpu->arch.apic));

	new = kvzalloc(sizeof(struct kvm_apic_map) +
	                   sizeof(struct kvm_lapic *) * ((u64)max_id + 1), GFP_KERNEL);

	if (!new)
		goto out;

	new->max_apic_id = max_id;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvm_lapic *apic = vcpu->arch.apic;
		struct kvm_lapic **cluster;
		u16 mask;
		u32 ldr;
		u8 xapic_id;
		u32 x2apic_id;

		if (!kvm_apic_present(vcpu))
			continue;

		xapic_id = kvm_xapic_id(apic);
		x2apic_id = kvm_x2apic_id(apic);

		/* Hotplug hack: see kvm_apic_match_physical_addr(), ... */
		if ((apic_x2apic_mode(apic) || x2apic_id > 0xff) &&
				x2apic_id <= new->max_apic_id)
			new->phys_map[x2apic_id] = apic;
		/*
		 * ... xAPIC ID of VCPUs with APIC ID > 0xff will wrap-around,
		 * prevent them from masking VCPUs with APIC ID <= 0xff.
		 */
		if (!apic_x2apic_mode(apic) && !new->phys_map[xapic_id])
			new->phys_map[xapic_id] = apic;

		ldr = kvm_lapic_get_reg(apic, APIC_LDR);

		if (apic_x2apic_mode(apic)) {
			new->mode |= KVM_APIC_MODE_X2APIC;
		} else if (ldr) {
			ldr = GET_APIC_LOGICAL_ID(ldr);
			if (kvm_lapic_get_reg(apic, APIC_DFR) == APIC_DFR_FLAT)
				new->mode |= KVM_APIC_MODE_XAPIC_FLAT;
			else
				new->mode |= KVM_APIC_MODE_XAPIC_CLUSTER;
		}

		if (!kvm_apic_map_get_logical_dest(new, ldr, &cluster, &mask))
			continue;

		if (mask)
			cluster[ffs(mask) - 1] = apic;
	}
out:
	old = rcu_dereference_protected(kvm->arch.apic_map,
			lockdep_is_held(&kvm->arch.apic_map_lock));
	rcu_assign_pointer(kvm->arch.apic_map, new);
	mutex_unlock(&kvm->arch.apic_map_lock);

	if (old)
		call_rcu(&old->rcu, kvm_apic_map_free);

	kvm_make_scan_ioapic_request(kvm);
}

static inline void apic_set_spiv(struct kvm_lapic *apic, u32 val)
{
	bool enabled = val & APIC_SPIV_APIC_ENABLED;

	kvm_lapic_set_reg(apic, APIC_SPIV, val);

	if (enabled != apic->sw_enabled) {
		apic->sw_enabled = enabled;
		if (enabled) {
			static_key_slow_dec_deferred(&apic_sw_disabled);
			recalculate_apic_map(apic->vcpu->kvm);
		} else
			static_key_slow_inc(&apic_sw_disabled.key);
	}
}

static inline void kvm_apic_set_xapic_id(struct kvm_lapic *apic, u8 id)
{
	kvm_lapic_set_reg(apic, APIC_ID, id << 24);
	recalculate_apic_map(apic->vcpu->kvm);
}

static inline void kvm_apic_set_ldr(struct kvm_lapic *apic, u32 id)
{
	kvm_lapic_set_reg(apic, APIC_LDR, id);
	recalculate_apic_map(apic->vcpu->kvm);
}

static inline void kvm_apic_set_x2apic_id(struct kvm_lapic *apic, u32 id)
{
	u32 ldr = ((id >> 4) << 16) | (1 << (id & 0xf));

	WARN_ON_ONCE(id != apic->vcpu->vcpu_id);

	kvm_lapic_set_reg(apic, APIC_ID, id);
	kvm_lapic_set_reg(apic, APIC_LDR, ldr);
	recalculate_apic_map(apic->vcpu->kvm);
}

static inline int apic_lvt_enabled(struct kvm_lapic *apic, int lvt_type)
{
	return !(apic_get_reg(apic, lvt_type) & APIC_LVT_MASKED);
	return !(kvm_apic_get_reg(apic, lvt_type) & APIC_LVT_MASKED);
	return !(kvm_lapic_get_reg(apic, lvt_type) & APIC_LVT_MASKED);
}

static inline int apic_lvt_vector(struct kvm_lapic *apic, int lvt_type)
{
	return apic_get_reg(apic, lvt_type) & APIC_VECTOR_MASK;
	return kvm_apic_get_reg(apic, lvt_type) & APIC_VECTOR_MASK;
	return kvm_lapic_get_reg(apic, lvt_type) & APIC_VECTOR_MASK;
}

static inline int apic_lvtt_oneshot(struct kvm_lapic *apic)
{
	return apic->lapic_timer.timer_mode == APIC_LVT_TIMER_ONESHOT;
}

static inline int apic_lvtt_period(struct kvm_lapic *apic)
{
	return apic_get_reg(apic, APIC_LVTT) & APIC_LVT_TIMER_PERIODIC;
}

static unsigned int apic_lvt_mask[APIC_LVT_NUM] = {
	LVT_MASK | APIC_LVT_TIMER_PERIODIC,	/* LVTT */
	return apic->lapic_timer.timer_mode == APIC_LVT_TIMER_PERIODIC;
}

static inline int apic_lvtt_tscdeadline(struct kvm_lapic *apic)
{
	return apic->lapic_timer.timer_mode == APIC_LVT_TIMER_TSCDEADLINE;
}

static inline int apic_lvt_nmi_mode(u32 lvt_val)
{
	return (lvt_val & (APIC_MODE_MASK | APIC_LVT_MASKED)) == APIC_DM_NMI;
}

void kvm_apic_set_version(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct kvm_cpuid_entry2 *feat;
	u32 v = APIC_VERSION;

	if (!lapic_in_kernel(vcpu))
		return;

	feat = kvm_find_cpuid_entry(apic->vcpu, 0x1, 0);
	if (feat && (feat->ecx & (1 << (X86_FEATURE_X2APIC & 31))))
		v |= APIC_LVR_DIRECTED_EOI;
	kvm_lapic_set_reg(apic, APIC_LVR, v);
}

static const unsigned int apic_lvt_mask[KVM_APIC_LVT_NUM] = {
	LVT_MASK ,      /* part LVTT mask, timer mode mask added at runtime */
	LVT_MASK | APIC_MODE_MASK,	/* LVTTHMR */
	LVT_MASK | APIC_MODE_MASK,	/* LVTPC */
	LINT_MASK, LINT_MASK,	/* LVT0-1 */
	LVT_MASK		/* LVTERR */
};

static int find_highest_vector(void *bitmap)
{
	u32 *word = bitmap;
	int word_offset = MAX_APIC_VECTOR >> 5;

	while ((word_offset != 0) && (word[(--word_offset) << 2] == 0))
		continue;

	if (likely(!word_offset && !word[0]))
		return -1;
	else
		return fls(word[word_offset << 2]) - 1 + (word_offset << 5);
}

static inline int apic_test_and_set_irr(int vec, struct kvm_lapic *apic)
{
	return apic_test_and_set_vector(vec, apic->regs + APIC_IRR);
}

static inline void apic_clear_irr(int vec, struct kvm_lapic *apic)
{
	apic_clear_vector(vec, apic->regs + APIC_IRR);
	int vec;
	u32 *reg;

	for (vec = MAX_APIC_VECTOR - APIC_VECTORS_PER_REG;
	     vec >= 0; vec -= APIC_VECTORS_PER_REG) {
		reg = bitmap + REG_POS(vec);
		if (*reg)
			return __fls(*reg) + vec;
	}

	return -1;
}

static u8 count_vectors(void *bitmap)
{
	int vec;
	u32 *reg;
	u8 count = 0;

	for (vec = 0; vec < MAX_APIC_VECTOR; vec += APIC_VECTORS_PER_REG) {
		reg = bitmap + REG_POS(vec);
		count += hweight32(*reg);
	}

	return count;
}

int __kvm_apic_update_irr(u32 *pir, void *regs)
{
	u32 i, vec;
	u32 pir_val, irr_val;
	int max_irr = -1;

	for (i = vec = 0; i <= 7; i++, vec += 32) {
		pir_val = READ_ONCE(pir[i]);
		irr_val = *((u32 *)(regs + APIC_IRR + i * 0x10));
		if (pir_val) {
			irr_val |= xchg(&pir[i], 0);
			*((u32 *)(regs + APIC_IRR + i * 0x10)) = irr_val;
		}
		if (irr_val)
			max_irr = __fls(irr_val) + vec;
	}

	return max_irr;
}
EXPORT_SYMBOL_GPL(__kvm_apic_update_irr);

int kvm_apic_update_irr(struct kvm_vcpu *vcpu, u32 *pir)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	return __kvm_apic_update_irr(pir, apic->regs);
}
EXPORT_SYMBOL_GPL(kvm_apic_update_irr);

static inline int apic_search_irr(struct kvm_lapic *apic)
{
	return find_highest_vector(apic->regs + APIC_IRR);
}

static inline int apic_find_highest_irr(struct kvm_lapic *apic)
{
	int result;

	result = find_highest_vector(apic->regs + APIC_IRR);
	/*
	 * Note that irr_pending is just a hint. It will be always
	 * true with virtual interrupt delivery enabled.
	 */
	if (!apic->irr_pending)
		return -1;

	result = apic_search_irr(apic);
	ASSERT(result == -1 || result >= 16);

	return result;
}

int kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;

	if (!apic)
		return 0;
	highest_irr = apic_find_highest_irr(apic);

	return highest_irr;
}
EXPORT_SYMBOL_GPL(kvm_lapic_find_highest_irr);

int kvm_apic_set_irq(struct kvm_vcpu *vcpu, u8 vec, u8 trig)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic_test_and_set_irr(vec, apic)) {
		/* a new pending irq is set in IRR */
		if (trig)
			apic_set_vector(vec, apic->regs + APIC_TMR);
		else
			apic_clear_vector(vec, apic->regs + APIC_TMR);
		kvm_vcpu_kick(apic->vcpu);
		return 1;
	}
	return 0;
static inline void apic_clear_irr(int vec, struct kvm_lapic *apic)
{
	struct kvm_vcpu *vcpu;

	vcpu = apic->vcpu;

	if (unlikely(vcpu->arch.apicv_active)) {
		/* need to update RVI */
		apic_clear_vector(vec, apic->regs + APIC_IRR);
		kvm_x86_ops->hwapic_irr_update(vcpu,
				apic_find_highest_irr(apic));
	} else {
		apic->irr_pending = false;
		apic_clear_vector(vec, apic->regs + APIC_IRR);
		if (apic_search_irr(apic) != -1)
			apic->irr_pending = true;
	}
}

static inline void apic_set_isr(int vec, struct kvm_lapic *apic)
{
	struct kvm_vcpu *vcpu;

	if (__apic_test_and_set_vector(vec, apic->regs + APIC_ISR))
		return;

	vcpu = apic->vcpu;

	/*
	 * With APIC virtualization enabled, all caching is disabled
	 * because the processor can modify ISR under the hood.  Instead
	 * just set SVI.
	 */
	if (unlikely(vcpu->arch.apicv_active))
		kvm_x86_ops->hwapic_isr_update(vcpu, vec);
	else {
		++apic->isr_count;
		BUG_ON(apic->isr_count > MAX_APIC_VECTOR);
		/*
		 * ISR (in service register) bit is set when injecting an interrupt.
		 * The highest vector is injected. Thus the latest bit set matches
		 * the highest bit in ISR.
		 */
		apic->highest_isr_cache = vec;
	}
}

static inline int apic_find_highest_isr(struct kvm_lapic *apic)
{
	int result;

	/*
	 * Note that isr_count is always 1, and highest_isr_cache
	 * is always -1, with APIC virtualization enabled.
	 */
	if (!apic->isr_count)
		return -1;
	if (likely(apic->highest_isr_cache != -1))
		return apic->highest_isr_cache;

	result = find_highest_vector(apic->regs + APIC_ISR);
	ASSERT(result == -1 || result >= 16);

	return result;
}

static void apic_update_ppr(struct kvm_lapic *apic)
{
	u32 tpr, isrv, ppr;
	int isr;

	tpr = apic_get_reg(apic, APIC_TASKPRI);
static inline void apic_clear_isr(int vec, struct kvm_lapic *apic)
{
	struct kvm_vcpu *vcpu;
	if (!__apic_test_and_clear_vector(vec, apic->regs + APIC_ISR))
		return;

	vcpu = apic->vcpu;

	/*
	 * We do get here for APIC virtualization enabled if the guest
	 * uses the Hyper-V APIC enlightenment.  In this case we may need
	 * to trigger a new interrupt delivery by writing the SVI field;
	 * on the other hand isr_count and highest_isr_cache are unused
	 * and must be left alone.
	 */
	if (unlikely(vcpu->arch.apicv_active))
		kvm_x86_ops->hwapic_isr_update(vcpu,
					       apic_find_highest_isr(apic));
	else {
		--apic->isr_count;
		BUG_ON(apic->isr_count < 0);
		apic->highest_isr_cache = -1;
	}
}

int kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	/* This may race with setting of irr in __apic_accept_irq() and
	 * value returned may be wrong, but kvm_vcpu_kick() in __apic_accept_irq
	 * will cause vmexit immediately and the value will be recalculated
	 * on the next vmentry.
	 */
	return apic_find_highest_irr(vcpu->arch.apic);
}
EXPORT_SYMBOL_GPL(kvm_lapic_find_highest_irr);

static int __apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
			     int vector, int level, int trig_mode,
			     struct dest_map *dest_map);

int kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq,
		     struct dest_map *dest_map)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	return __apic_accept_irq(apic, irq->delivery_mode, irq->vector,
			irq->level, irq->trig_mode, dest_map);
}

static int pv_eoi_put_user(struct kvm_vcpu *vcpu, u8 val)
{

	return kvm_write_guest_cached(vcpu->kvm, &vcpu->arch.pv_eoi.data, &val,
				      sizeof(val));
}

static int pv_eoi_get_user(struct kvm_vcpu *vcpu, u8 *val)
{

	return kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.pv_eoi.data, val,
				      sizeof(*val));
}

static inline bool pv_eoi_enabled(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.pv_eoi.msr_val & KVM_MSR_ENABLED;
}

static bool pv_eoi_get_pending(struct kvm_vcpu *vcpu)
{
	u8 val;
	if (pv_eoi_get_user(vcpu, &val) < 0)
		apic_debug("Can't read EOI MSR value: 0x%llx\n",
			   (unsigned long long)vcpu->arch.pv_eoi.msr_val);
	return val & 0x1;
}

static void pv_eoi_set_pending(struct kvm_vcpu *vcpu)
{
	if (pv_eoi_put_user(vcpu, KVM_PV_EOI_ENABLED) < 0) {
		apic_debug("Can't set EOI MSR value: 0x%llx\n",
			   (unsigned long long)vcpu->arch.pv_eoi.msr_val);
		return;
	}
	__set_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention);
}

static void pv_eoi_clr_pending(struct kvm_vcpu *vcpu)
{
	if (pv_eoi_put_user(vcpu, KVM_PV_EOI_DISABLED) < 0) {
		apic_debug("Can't clear EOI MSR value: 0x%llx\n",
			   (unsigned long long)vcpu->arch.pv_eoi.msr_val);
		return;
	}
	__clear_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention);
}

static int apic_has_interrupt_for_ppr(struct kvm_lapic *apic, u32 ppr)
{
	int highest_irr;
	if (kvm_x86_ops->sync_pir_to_irr && apic->vcpu->arch.apicv_active)
		highest_irr = kvm_x86_ops->sync_pir_to_irr(apic->vcpu);
	else
		highest_irr = apic_find_highest_irr(apic);
	if (highest_irr == -1 || (highest_irr & 0xF0) <= ppr)
		return -1;
	return highest_irr;
}

static bool __apic_update_ppr(struct kvm_lapic *apic, u32 *new_ppr)
{
	u32 tpr, isrv, ppr, old_ppr;
	int isr;

	old_ppr = kvm_lapic_get_reg(apic, APIC_PROCPRI);
	tpr = kvm_lapic_get_reg(apic, APIC_TASKPRI);
	isr = apic_find_highest_isr(apic);
	isrv = (isr != -1) ? isr : 0;

	if ((tpr & 0xf0) >= (isrv & 0xf0))
		ppr = tpr & 0xff;
	else
		ppr = isrv & 0xf0;

	apic_debug("vlapic %p, ppr 0x%x, isr 0x%x, isrv 0x%x",
		   apic, ppr, isr, isrv);

	apic_set_reg(apic, APIC_PROCPRI, ppr);
	if (old_ppr != ppr) {
		apic_set_reg(apic, APIC_PROCPRI, ppr);
		if (ppr < old_ppr)
			kvm_make_request(KVM_REQ_EVENT, apic->vcpu);
	}
	*new_ppr = ppr;
	if (old_ppr != ppr)
		kvm_lapic_set_reg(apic, APIC_PROCPRI, ppr);

	return ppr < old_ppr;
}

static void apic_update_ppr(struct kvm_lapic *apic)
{
	u32 ppr;

	if (__apic_update_ppr(apic, &ppr) &&
	    apic_has_interrupt_for_ppr(apic, ppr) != -1)
		kvm_make_request(KVM_REQ_EVENT, apic->vcpu);
}

void kvm_apic_update_ppr(struct kvm_vcpu *vcpu)
{
	apic_update_ppr(vcpu->arch.apic);
}
EXPORT_SYMBOL_GPL(kvm_apic_update_ppr);

static void apic_set_tpr(struct kvm_lapic *apic, u32 tpr)
{
	kvm_lapic_set_reg(apic, APIC_TASKPRI, tpr);
	apic_update_ppr(apic);
}

int kvm_apic_match_physical_addr(struct kvm_lapic *apic, u16 dest)
{
	return kvm_apic_id(apic) == dest;
}

int kvm_apic_match_logical_addr(struct kvm_lapic *apic, u8 mda)
{
	int result = 0;
	u8 logical_id;

	logical_id = GET_APIC_LOGICAL_ID(apic_get_reg(apic, APIC_LDR));

	switch (apic_get_reg(apic, APIC_DFR)) {
	case APIC_DFR_FLAT:
		if (logical_id & mda)
			result = 1;
		break;
	case APIC_DFR_CLUSTER:
		if (((logical_id >> 4) == (mda >> 0x4))
		    && (logical_id & mda & 0xf))
			result = 1;
		break;
	default:
		printk(KERN_WARNING "Bad DFR vcpu %d: %08x\n",
		       apic->vcpu->vcpu_id, apic_get_reg(apic, APIC_DFR));
		break;
	}

	return result;
}

static int apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
			   int short_hand, int dest, int dest_mode)
{
	int result = 0;
	struct kvm_lapic *target = vcpu->arch.apic;

	apic_debug("target %p, source %p, dest 0x%x, "
		   "dest_mode 0x%x, short_hand 0x%x",
		   target, source, dest, dest_mode, short_hand);

	ASSERT(!target);
	switch (short_hand) {
	case APIC_DEST_NOSHORT:
		if (dest_mode == 0) {
			/* Physical mode. */
			if ((dest == 0xFF) || (dest == kvm_apic_id(target)))
				result = 1;
		} else
			/* Logical mode. */
			result = kvm_apic_match_logical_addr(target, dest);
		break;
	case APIC_DEST_SELF:
		if (target == source)
			result = 1;
		break;
	case APIC_DEST_ALLINC:
		result = 1;
		break;
	case APIC_DEST_ALLBUT:
		if (target != source)
			result = 1;
		break;
	default:
		printk(KERN_WARNING "Bad dest shorthand value %x\n",
		       short_hand);
		break;
	}

	return result;
static bool kvm_apic_broadcast(struct kvm_lapic *apic, u32 mda)
{
	return mda == (apic_x2apic_mode(apic) ?
			X2APIC_BROADCAST : APIC_BROADCAST);
}

static bool kvm_apic_match_physical_addr(struct kvm_lapic *apic, u32 mda)
{
	if (kvm_apic_broadcast(apic, mda))
		return true;

	if (apic_x2apic_mode(apic))
		return mda == kvm_x2apic_id(apic);

	/*
	 * Hotplug hack: Make LAPIC in xAPIC mode also accept interrupts as if
	 * it were in x2APIC mode.  Hotplugged VCPUs start in xAPIC mode and
	 * this allows unique addressing of VCPUs with APIC ID over 0xff.
	 * The 0xff condition is needed because writeable xAPIC ID.
	 */
	if (kvm_x2apic_id(apic) > 0xff && mda == kvm_x2apic_id(apic))
		return true;

	return mda == kvm_xapic_id(apic);
}

static bool kvm_apic_match_logical_addr(struct kvm_lapic *apic, u32 mda)
{
	u32 logical_id;

	if (kvm_apic_broadcast(apic, mda))
		return true;

	logical_id = kvm_lapic_get_reg(apic, APIC_LDR);

	if (apic_x2apic_mode(apic))
		return ((logical_id >> 16) == (mda >> 16))
		       && (logical_id & mda & 0xffff) != 0;

	logical_id = GET_APIC_LOGICAL_ID(logical_id);

	switch (kvm_lapic_get_reg(apic, APIC_DFR)) {
	case APIC_DFR_FLAT:
		return (logical_id & mda) != 0;
	case APIC_DFR_CLUSTER:
		return ((logical_id >> 4) == (mda >> 4))
		       && (logical_id & mda & 0xf) != 0;
	default:
		apic_debug("Bad DFR vcpu %d: %08x\n",
			   apic->vcpu->vcpu_id, kvm_lapic_get_reg(apic, APIC_DFR));
		return false;
	}
}

/* The KVM local APIC implementation has two quirks:
 *
 *  - Real hardware delivers interrupts destined to x2APIC ID > 0xff to LAPICs
 *    in xAPIC mode if the "destination & 0xff" matches its xAPIC ID.
 *    KVM doesn't do that aliasing.
 *
 *  - in-kernel IOAPIC messages have to be delivered directly to
 *    x2APIC, because the kernel does not support interrupt remapping.
 *    In order to support broadcast without interrupt remapping, x2APIC
 *    rewrites the destination of non-IPI messages from APIC_BROADCAST
 *    to X2APIC_BROADCAST.
 *
 * The broadcast quirk can be disabled with KVM_CAP_X2APIC_API.  This is
 * important when userspace wants to use x2APIC-format MSIs, because
 * APIC_BROADCAST (0xff) is a legal route for "cluster 0, CPUs 0-7".
 */
static u32 kvm_apic_mda(struct kvm_vcpu *vcpu, unsigned int dest_id,
		struct kvm_lapic *source, struct kvm_lapic *target)
{
	bool ipi = source != NULL;

	if (!vcpu->kvm->arch.x2apic_broadcast_quirk_disabled &&
	    !ipi && dest_id == APIC_BROADCAST && apic_x2apic_mode(target))
		return X2APIC_BROADCAST;

	return dest_id;
}

bool kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
			   int short_hand, unsigned int dest, int dest_mode)
{
	struct kvm_lapic *target = vcpu->arch.apic;
	u32 mda = kvm_apic_mda(vcpu, dest, source, target);

	apic_debug("target %p, source %p, dest 0x%x, "
		   "dest_mode 0x%x, short_hand 0x%x\n",
		   target, source, dest, dest_mode, short_hand);

	ASSERT(target);
	switch (short_hand) {
	case APIC_DEST_NOSHORT:
		if (dest_mode == APIC_DEST_PHYSICAL)
			return kvm_apic_match_physical_addr(target, mda);
		else
			return kvm_apic_match_logical_addr(target, mda);
	case APIC_DEST_SELF:
		return target == source;
	case APIC_DEST_ALLINC:
		return true;
	case APIC_DEST_ALLBUT:
		return target != source;
	default:
		apic_debug("kvm: apic: Bad dest shorthand value %x\n",
			   short_hand);
		return false;
	}
}
EXPORT_SYMBOL_GPL(kvm_apic_match_dest);

int kvm_vector_to_index(u32 vector, u32 dest_vcpus,
		       const unsigned long *bitmap, u32 bitmap_size)
{
	u32 mod;
	int i, idx = -1;

	mod = vector % dest_vcpus;

	for (i = 0; i <= mod; i++) {
		idx = find_next_bit(bitmap, bitmap_size, idx + 1);
		BUG_ON(idx == bitmap_size);
	}

	return idx;
}

static void kvm_apic_disabled_lapic_found(struct kvm *kvm)
{
	if (!kvm->arch.disabled_lapic_found) {
		kvm->arch.disabled_lapic_found = true;
		printk(KERN_INFO
		       "Disabled LAPIC found during irq injection\n");
	}
}

static bool kvm_apic_is_broadcast_dest(struct kvm *kvm, struct kvm_lapic **src,
		struct kvm_lapic_irq *irq, struct kvm_apic_map *map)
{
	if (kvm->arch.x2apic_broadcast_quirk_disabled) {
		if ((irq->dest_id == APIC_BROADCAST &&
				map->mode != KVM_APIC_MODE_X2APIC))
			return true;
		if (irq->dest_id == X2APIC_BROADCAST)
			return true;
	} else {
		bool x2apic_ipi = src && *src && apic_x2apic_mode(*src);
		if (irq->dest_id == (x2apic_ipi ?
		                     X2APIC_BROADCAST : APIC_BROADCAST))
			return true;
	}

	return false;
}

/* Return true if the interrupt can be handled by using *bitmap as index mask
 * for valid destinations in *dst array.
 * Return false if kvm_apic_map_get_dest_lapic did nothing useful.
 * Note: we may have zero kvm_lapic destinations when we return true, which
 * means that the interrupt should be dropped.  In this case, *bitmap would be
 * zero and *dst undefined.
 */
static inline bool kvm_apic_map_get_dest_lapic(struct kvm *kvm,
		struct kvm_lapic **src, struct kvm_lapic_irq *irq,
		struct kvm_apic_map *map, struct kvm_lapic ***dst,
		unsigned long *bitmap)
{
	int i, lowest;

	if (irq->shorthand == APIC_DEST_SELF && src) {
		*dst = src;
		*bitmap = 1;
		return true;
	} else if (irq->shorthand)
		return false;

	if (!map || kvm_apic_is_broadcast_dest(kvm, src, irq, map))
		return false;

	if (irq->dest_mode == APIC_DEST_PHYSICAL) {
		if (irq->dest_id > map->max_apic_id) {
			*bitmap = 0;
		} else {
			*dst = &map->phys_map[irq->dest_id];
			*bitmap = 1;
		}
		return true;
	}

	*bitmap = 0;
	if (!kvm_apic_map_get_logical_dest(map, irq->dest_id, dst,
				(u16 *)bitmap))
		return false;

	if (!kvm_lowest_prio_delivery(irq))
		return true;

	if (!kvm_vector_hashing_enabled()) {
		lowest = -1;
		for_each_set_bit(i, bitmap, 16) {
			if (!(*dst)[i])
				continue;
			if (lowest < 0)
				lowest = i;
			else if (kvm_apic_compare_prio((*dst)[i]->vcpu,
						(*dst)[lowest]->vcpu) < 0)
				lowest = i;
		}
	} else {
		if (!*bitmap)
			return true;

		lowest = kvm_vector_to_index(irq->vector, hweight16(*bitmap),
				bitmap, 16);

		if (!(*dst)[lowest]) {
			kvm_apic_disabled_lapic_found(kvm);
			*bitmap = 0;
			return true;
		}
	}

	*bitmap = (lowest >= 0) ? 1 << lowest : 0;

	return true;
}

bool kvm_irq_delivery_to_apic_fast(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq, int *r, struct dest_map *dest_map)
{
	struct kvm_apic_map *map;
	unsigned long bitmap;
	struct kvm_lapic **dst = NULL;
	int i;
	bool ret;

	*r = -1;

	if (irq->shorthand == APIC_DEST_SELF) {
		*r = kvm_apic_set_irq(src->vcpu, irq, dest_map);
		return true;
	}

	rcu_read_lock();
	map = rcu_dereference(kvm->arch.apic_map);

	ret = kvm_apic_map_get_dest_lapic(kvm, &src, irq, map, &dst, &bitmap);
	if (ret)
		for_each_set_bit(i, &bitmap, 16) {
			if (!dst[i])
				continue;
			if (*r < 0)
				*r = 0;
			*r += kvm_apic_set_irq(dst[i]->vcpu, irq, dest_map);
		}

	rcu_read_unlock();
	return ret;
}

/*
 * This routine tries to handler interrupts in posted mode, here is how
 * it deals with different cases:
 * - For single-destination interrupts, handle it in posted mode
 * - Else if vector hashing is enabled and it is a lowest-priority
 *   interrupt, handle it in posted mode and use the following mechanism
 *   to find the destinaiton vCPU.
 *	1. For lowest-priority interrupts, store all the possible
 *	   destination vCPUs in an array.
 *	2. Use "guest vector % max number of destination vCPUs" to find
 *	   the right destination vCPU in the array for the lowest-priority
 *	   interrupt.
 * - Otherwise, use remapped mode to inject the interrupt.
 */
bool kvm_intr_is_single_vcpu_fast(struct kvm *kvm, struct kvm_lapic_irq *irq,
			struct kvm_vcpu **dest_vcpu)
{
	struct kvm_apic_map *map;
	unsigned long bitmap;
	struct kvm_lapic **dst = NULL;
	bool ret = false;

	if (irq->shorthand)
		return false;

	rcu_read_lock();
	map = rcu_dereference(kvm->arch.apic_map);

	if (kvm_apic_map_get_dest_lapic(kvm, NULL, irq, map, &dst, &bitmap) &&
			hweight16(bitmap) == 1) {
		unsigned long i = find_first_bit(&bitmap, 16);

		if (dst[i]) {
			*dest_vcpu = dst[i]->vcpu;
			ret = true;
		}
	}

	rcu_read_unlock();
	return ret;
}

/*
 * Add a pending IRQ into lapic.
 * Return 1 if successfully added and 0 if discarded.
 */
static int __apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
			     int vector, int level, int trig_mode)
{
	int orig_irr, result = 0;
	struct kvm_vcpu *vcpu = apic->vcpu;

	switch (delivery_mode) {
	case APIC_DM_FIXED:
	case APIC_DM_LOWEST:
			     int vector, int level, int trig_mode,
			     struct dest_map *dest_map)
{
	int result = 0;
	struct kvm_vcpu *vcpu = apic->vcpu;

	trace_kvm_apic_accept_irq(vcpu->vcpu_id, delivery_mode,
				  trig_mode, vector);
	switch (delivery_mode) {
	case APIC_DM_LOWEST:
		vcpu->arch.apic_arb_prio++;
	case APIC_DM_FIXED:
		if (unlikely(trig_mode && !level))
			break;

		/* FIXME add logic for vcpu on reset */
		if (unlikely(!apic_enabled(apic)))
			break;

		orig_irr = apic_test_and_set_irr(vector, apic);
		if (orig_irr && trig_mode) {
			apic_debug("level trig mode repeatedly for vector %d",
				   vector);
			break;
		}

		if (trig_mode) {
			apic_debug("level trig mode for vector %d", vector);
			apic_set_vector(vector, apic->regs + APIC_TMR);
		} else
			apic_clear_vector(vector, apic->regs + APIC_TMR);

		if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE)
			kvm_vcpu_kick(vcpu);
		else if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED) {
			vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
			if (waitqueue_active(&vcpu->wq))
				wake_up_interruptible(&vcpu->wq);
		}

		result = (orig_irr == 0);
		break;

	case APIC_DM_REMRD:
		printk(KERN_DEBUG "Ignoring delivery mode 3\n");
		break;

	case APIC_DM_SMI:
		printk(KERN_DEBUG "Ignoring guest SMI\n");
		break;

	case APIC_DM_NMI:
		kvm_inject_nmi(vcpu);
		break;

	case APIC_DM_INIT:
		if (level) {
			if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE)
				printk(KERN_DEBUG
				       "INIT on a runnable vcpu %d\n",
				       vcpu->vcpu_id);
			vcpu->arch.mp_state = KVM_MP_STATE_INIT_RECEIVED;
			kvm_vcpu_kick(vcpu);
		} else {
			printk(KERN_DEBUG
			       "Ignoring de-assert INIT to vcpu %d\n",
			       vcpu->vcpu_id);
		}

		break;

	case APIC_DM_STARTUP:
		printk(KERN_DEBUG "SIPI to vcpu %d vector 0x%02x\n",
		       vcpu->vcpu_id, vector);
		if (vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED) {
			vcpu->arch.sipi_vector = vector;
			vcpu->arch.mp_state = KVM_MP_STATE_SIPI_RECEIVED;
			if (waitqueue_active(&vcpu->wq))
				wake_up_interruptible(&vcpu->wq);
		}
		result = 1;

		if (dest_map) {
			__set_bit(vcpu->vcpu_id, dest_map->map);
			dest_map->vectors[vcpu->vcpu_id] = vector;
		}

		if (apic_test_vector(vector, apic->regs + APIC_TMR) != !!trig_mode) {
			if (trig_mode)
				kvm_lapic_set_vector(vector, apic->regs + APIC_TMR);
			else
				apic_clear_vector(vector, apic->regs + APIC_TMR);
		}

		if (vcpu->arch.apicv_active)
			kvm_x86_ops->deliver_posted_interrupt(vcpu, vector);
		else {
			kvm_lapic_set_irr(vector, apic);

			kvm_make_request(KVM_REQ_EVENT, vcpu);
			kvm_vcpu_kick(vcpu);
		}
		break;

	case APIC_DM_REMRD:
		result = 1;
		vcpu->arch.pv.pv_unhalted = 1;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_SMI:
		result = 1;
		kvm_make_request(KVM_REQ_SMI, vcpu);
		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_NMI:
		result = 1;
		kvm_inject_nmi(vcpu);
		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_INIT:
		if (!trig_mode || level) {
			result = 1;
			/* assumes that there are only KVM_APIC_INIT/SIPI */
			apic->pending_events = (1UL << KVM_APIC_INIT);
			/* make sure pending_events is visible before sending
			 * the request */
			smp_wmb();
			kvm_make_request(KVM_REQ_EVENT, vcpu);
			kvm_vcpu_kick(vcpu);
		} else {
			apic_debug("Ignoring de-assert INIT to vcpu %d\n",
				   vcpu->vcpu_id);
		}
		break;

	case APIC_DM_STARTUP:
		apic_debug("SIPI to vcpu %d vector 0x%02x\n",
			   vcpu->vcpu_id, vector);
		result = 1;
		apic->sipi_vector = vector;
		/* make sure sipi_vector is visible for the receiver */
		smp_wmb();
		set_bit(KVM_APIC_SIPI, &apic->pending_events);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_EXTINT:
		/*
		 * Should only be called by kvm_apic_local_deliver() with LVT0,
		 * before NMI watchdog was enabled. Already handled by
		 * kvm_apic_accept_pic_intr().
		 */
		break;

	default:
		printk(KERN_ERR "TODO: unsupported delivery mode %x\n",
		       delivery_mode);
		break;
	}
	return result;
}

static struct kvm_lapic *kvm_apic_round_robin(struct kvm *kvm, u8 vector,
				       unsigned long bitmap)
{
	int last;
	int next;
	struct kvm_lapic *apic = NULL;

	last = kvm->arch.round_robin_prev_vcpu;
	next = last;

	do {
		if (++next == KVM_MAX_VCPUS)
			next = 0;
		if (kvm->vcpus[next] == NULL || !test_bit(next, &bitmap))
			continue;
		apic = kvm->vcpus[next]->arch.apic;
		if (apic && apic_enabled(apic))
			break;
		apic = NULL;
	} while (next != last);
	kvm->arch.round_robin_prev_vcpu = next;

	if (!apic)
		printk(KERN_DEBUG "vcpu not ready for apic_round_robin\n");

	return apic;
}

struct kvm_vcpu *kvm_get_lowest_prio_vcpu(struct kvm *kvm, u8 vector,
		unsigned long bitmap)
{
	struct kvm_lapic *apic;

	apic = kvm_apic_round_robin(kvm, vector, bitmap);
	if (apic)
		return apic->vcpu;
	return NULL;
}

static void apic_set_eoi(struct kvm_lapic *apic)
{
	int vector = apic_find_highest_isr(apic);

int kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2)
{
	return vcpu1->arch.apic_arb_prio - vcpu2->arch.apic_arb_prio;
}

static bool kvm_ioapic_handles_vector(struct kvm_lapic *apic, int vector)
{
	return test_bit(vector, apic->vcpu->arch.ioapic_handled_vectors);
}

static void kvm_ioapic_send_eoi(struct kvm_lapic *apic, int vector)
{
	int trigger_mode;

	/* Eoi the ioapic only if the ioapic doesn't own the vector. */
	if (!kvm_ioapic_handles_vector(apic, vector))
		return;

	/* Request a KVM exit to inform the userspace IOAPIC. */
	if (irqchip_split(apic->vcpu->kvm)) {
		apic->vcpu->arch.pending_ioapic_eoi = vector;
		kvm_make_request(KVM_REQ_IOAPIC_EOI_EXIT, apic->vcpu);
		return;
	}

	if (apic_test_vector(vector, apic->regs + APIC_TMR))
		trigger_mode = IOAPIC_LEVEL_TRIG;
	else
		trigger_mode = IOAPIC_EDGE_TRIG;

	kvm_ioapic_update_eoi(apic->vcpu, vector, trigger_mode);
}

static int apic_set_eoi(struct kvm_lapic *apic)
{
	int vector = apic_find_highest_isr(apic);

	trace_kvm_eoi(apic, vector);

	/*
	 * Not every write EOI will has corresponding ISR,
	 * one example is when Kernel check timer on setup_IO_APIC
	 */
	if (vector == -1)
		return;

	apic_clear_vector(vector, apic->regs + APIC_ISR);
	apic_update_ppr(apic);

	if (apic_test_and_clear_vector(vector, apic->regs + APIC_TMR))
		kvm_ioapic_update_eoi(apic->vcpu->kvm, vector);
}

static void apic_send_ipi(struct kvm_lapic *apic)
{
	u32 icr_low = apic_get_reg(apic, APIC_ICR);
	u32 icr_high = apic_get_reg(apic, APIC_ICR2);

	unsigned int dest = GET_APIC_DEST_FIELD(icr_high);
	unsigned int short_hand = icr_low & APIC_SHORT_MASK;
	unsigned int trig_mode = icr_low & APIC_INT_LEVELTRIG;
	unsigned int level = icr_low & APIC_INT_ASSERT;
	unsigned int dest_mode = icr_low & APIC_DEST_MASK;
	unsigned int delivery_mode = icr_low & APIC_MODE_MASK;
	unsigned int vector = icr_low & APIC_VECTOR_MASK;

	struct kvm_vcpu *target;
	struct kvm_vcpu *vcpu;
	unsigned long lpr_map = 0;
	int i;

	apic_debug("icr_high 0x%x, icr_low 0x%x, "
		   "short_hand 0x%x, dest 0x%x, trig_mode 0x%x, level 0x%x, "
		   "dest_mode 0x%x, delivery_mode 0x%x, vector 0x%x\n",
		   icr_high, icr_low, short_hand, dest,
		   trig_mode, level, dest_mode, delivery_mode, vector);

	for (i = 0; i < KVM_MAX_VCPUS; i++) {
		vcpu = apic->vcpu->kvm->vcpus[i];
		if (!vcpu)
			continue;

		if (vcpu->arch.apic &&
		    apic_match_dest(vcpu, apic, short_hand, dest, dest_mode)) {
			if (delivery_mode == APIC_DM_LOWEST)
				set_bit(vcpu->vcpu_id, &lpr_map);
			else
				__apic_accept_irq(vcpu->arch.apic, delivery_mode,
						  vector, level, trig_mode);
		}
	}

	if (delivery_mode == APIC_DM_LOWEST) {
		target = kvm_get_lowest_prio_vcpu(vcpu->kvm, vector, lpr_map);
		if (target != NULL)
			__apic_accept_irq(target->arch.apic, delivery_mode,
					  vector, level, trig_mode);
	}
		return vector;

	apic_clear_isr(vector, apic);
	apic_update_ppr(apic);

	if (test_bit(vector, vcpu_to_synic(apic->vcpu)->vec_bitmap))
		kvm_hv_synic_send_eoi(apic->vcpu, vector);

	kvm_ioapic_send_eoi(apic, vector);
	kvm_make_request(KVM_REQ_EVENT, apic->vcpu);
	return vector;
}

/*
 * this interface assumes a trap-like exit, which has already finished
 * desired side effect including vISR and vPPR update.
 */
void kvm_apic_set_eoi_accelerated(struct kvm_vcpu *vcpu, int vector)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	trace_kvm_eoi(apic, vector);

	kvm_ioapic_send_eoi(apic, vector);
	kvm_make_request(KVM_REQ_EVENT, apic->vcpu);
}
EXPORT_SYMBOL_GPL(kvm_apic_set_eoi_accelerated);

static void apic_send_ipi(struct kvm_lapic *apic)
{
	u32 icr_low = kvm_lapic_get_reg(apic, APIC_ICR);
	u32 icr_high = kvm_lapic_get_reg(apic, APIC_ICR2);
	struct kvm_lapic_irq irq;

	irq.vector = icr_low & APIC_VECTOR_MASK;
	irq.delivery_mode = icr_low & APIC_MODE_MASK;
	irq.dest_mode = icr_low & APIC_DEST_MASK;
	irq.level = (icr_low & APIC_INT_ASSERT) != 0;
	irq.trig_mode = icr_low & APIC_INT_LEVELTRIG;
	irq.shorthand = icr_low & APIC_SHORT_MASK;
	irq.msi_redir_hint = false;
	if (apic_x2apic_mode(apic))
		irq.dest_id = icr_high;
	else
		irq.dest_id = GET_APIC_DEST_FIELD(icr_high);

	trace_kvm_apic_ipi(icr_low, irq.dest_id);

	apic_debug("icr_high 0x%x, icr_low 0x%x, "
		   "short_hand 0x%x, dest 0x%x, trig_mode 0x%x, level 0x%x, "
		   "dest_mode 0x%x, delivery_mode 0x%x, vector 0x%x, "
		   "msi_redir_hint 0x%x\n",
		   icr_high, icr_low, irq.shorthand, irq.dest_id,
		   irq.trig_mode, irq.level, irq.dest_mode, irq.delivery_mode,
		   irq.vector, irq.msi_redir_hint);

	kvm_irq_delivery_to_apic(apic->vcpu->kvm, apic, &irq, NULL);
}

static u32 apic_get_tmcct(struct kvm_lapic *apic)
{
	u64 counter_passed;
	ktime_t passed, now;
	ktime_t remaining;
	ktime_t remaining, now;
	s64 ns;
	u32 tmcct;

	ASSERT(apic != NULL);

	now = apic->timer.dev.base->get_time();
	tmcct = apic_get_reg(apic, APIC_TMICT);

	/* if initial count is 0, current count should also be 0 */
	if (tmcct == 0)
		return 0;

	if (unlikely(ktime_to_ns(now) <=
		ktime_to_ns(apic->timer.last_update))) {
		/* Wrap around */
		passed = ktime_add(( {
				    (ktime_t) {
				    .tv64 = KTIME_MAX -
				    (apic->timer.last_update).tv64}; }
				   ), now);
		apic_debug("time elapsed\n");
	} else
		passed = ktime_sub(now, apic->timer.last_update);

	counter_passed = div64_u64(ktime_to_ns(passed),
				   (APIC_BUS_CYCLE_NS * apic->timer.divide_count));

	if (counter_passed > tmcct) {
		if (unlikely(!apic_lvtt_period(apic))) {
			/* one-shot timers stick at 0 until reset */
			tmcct = 0;
		} else {
			/*
			 * periodic timers reset to APIC_TMICT when they
			 * hit 0. The while loop simulates this happening N
			 * times. (counter_passed %= tmcct) would also work,
			 * but might be slower or not work on 32-bit??
			 */
			while (counter_passed > tmcct)
				counter_passed -= tmcct;
			tmcct -= counter_passed;
		}
	} else {
		tmcct -= counter_passed;
	}
	/* if initial count is 0, current count should also be 0 */
	if (kvm_lapic_get_reg(apic, APIC_TMICT) == 0 ||
		apic->lapic_timer.period == 0)
		return 0;

	now = ktime_get();
	remaining = ktime_sub(apic->lapic_timer.target_expiration, now);
	if (ktime_to_ns(remaining) < 0)
		remaining = 0;

	ns = mod_64(ktime_to_ns(remaining), apic->lapic_timer.period);
	tmcct = div64_u64(ns,
			 (APIC_BUS_CYCLE_NS * apic->divide_count));

	return tmcct;
}

static void __report_tpr_access(struct kvm_lapic *apic, bool write)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct kvm_run *run = vcpu->run;

	set_bit(KVM_REQ_REPORT_TPR_ACCESS, &vcpu->requests);
	kvm_x86_ops->cache_regs(vcpu);
	run->tpr_access.rip = vcpu->arch.rip;
	kvm_make_request(KVM_REQ_REPORT_TPR_ACCESS, vcpu);
	run->tpr_access.rip = kvm_rip_read(vcpu);
	run->tpr_access.is_write = write;
}

static inline void report_tpr_access(struct kvm_lapic *apic, bool write)
{
	if (apic->vcpu->arch.tpr_access_reporting)
		__report_tpr_access(apic, write);
}

static u32 __apic_read(struct kvm_lapic *apic, unsigned int offset)
{
	u32 val = 0;

	KVMTRACE_1D(APIC_ACCESS, apic->vcpu, (u32)offset, handler);

	if (offset >= LAPIC_MMIO_LENGTH)
		return 0;

	switch (offset) {
	case APIC_ARBPRI:
		printk(KERN_WARNING "Access APIC ARBPRI register "
		       "which is for P6\n");
		break;

	case APIC_TMCCT:	/* Timer CCR */
		val = apic_get_tmcct(apic);
		break;

	case APIC_ID:
		if (apic_x2apic_mode(apic))
			val = kvm_apic_id(apic);
		else
			val = kvm_apic_id(apic) << 24;
		break;
	case APIC_ARBPRI:
		apic_debug("Access APIC ARBPRI register which is for P6\n");
		break;

	case APIC_TMCCT:	/* Timer CCR */
		if (apic_lvtt_tscdeadline(apic))
			return 0;

		val = apic_get_tmcct(apic);
		break;
	case APIC_PROCPRI:
		apic_update_ppr(apic);
		val = kvm_lapic_get_reg(apic, offset);
		break;
	case APIC_TASKPRI:
		report_tpr_access(apic, false);
		/* fall thru */
	default:
		apic_update_ppr(apic);
		val = apic_get_reg(apic, offset);
		val = kvm_apic_get_reg(apic, offset);
		val = kvm_lapic_get_reg(apic, offset);
		break;
	}

	return val;
}

static void apic_mmio_read(struct kvm_io_device *this,
			   gpa_t address, int len, void *data)
{
	struct kvm_lapic *apic = (struct kvm_lapic *)this->private;
	unsigned int offset = address - apic->base_address;
	unsigned char alignment = offset & 0xf;
	u32 result;

	if ((alignment + len) > 4) {
		printk(KERN_ERR "KVM_APIC_READ: alignment error %lx %d",
		       (unsigned long)address, len);
		return;
	}
	result = __apic_read(apic, offset & ~0xf);

static inline struct kvm_lapic *to_lapic(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_lapic, dev);
}

int kvm_lapic_reg_read(struct kvm_lapic *apic, u32 offset, int len,
		void *data)
{
	unsigned char alignment = offset & 0xf;
	u32 result;
	/* this bitmask has a bit cleared for each reserved register */
	static const u64 rmask = 0x43ff01ffffffe70cULL;

	if ((alignment + len) > 4) {
		apic_debug("KVM_APIC_READ: alignment error %x %d\n",
			   offset, len);
		return 1;
	}

	if (offset > 0x3f0 || !(rmask & (1ULL << (offset >> 4)))) {
		apic_debug("KVM_APIC_READ: read reserved register %x\n",
			   offset);
		return 1;
	}

	result = __apic_read(apic, offset & ~0xf);

	trace_kvm_apic_read(offset, result);

	switch (len) {
	case 1:
	case 2:
	case 4:
		memcpy(data, (char *)&result + alignment, len);
		break;
	default:
		printk(KERN_ERR "Local APIC read with len = %x, "
		       "should be 1,2, or 4 instead\n", len);
		break;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_lapic_reg_read);

static int apic_mmio_in_range(struct kvm_lapic *apic, gpa_t addr)
{
	return kvm_apic_hw_enabled(apic) &&
	    addr >= apic->base_address &&
	    addr < apic->base_address + LAPIC_MMIO_LENGTH;
}

static int apic_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
			   gpa_t address, int len, void *data)
{
	struct kvm_lapic *apic = to_lapic(this);
	u32 offset = address - apic->base_address;

	if (!apic_mmio_in_range(apic, address))
		return -EOPNOTSUPP;

	kvm_lapic_reg_read(apic, offset, len, data);

	return 0;
}

static void update_divide_count(struct kvm_lapic *apic)
{
	u32 tmp1, tmp2, tdcr;

	tdcr = apic_get_reg(apic, APIC_TDCR);
	tmp1 = tdcr & 0xf;
	tmp2 = ((tmp1 & 0x3) | ((tmp1 & 0x8) >> 1)) + 1;
	apic->timer.divide_count = 0x1 << (tmp2 & 0x7);

	apic_debug("timer divide count is 0x%x\n",
				   apic->timer.divide_count);
	tdcr = kvm_apic_get_reg(apic, APIC_TDCR);
	tdcr = kvm_lapic_get_reg(apic, APIC_TDCR);
	tmp1 = tdcr & 0xf;
	tmp2 = ((tmp1 & 0x3) | ((tmp1 & 0x8) >> 1)) + 1;
	apic->divide_count = 0x1 << (tmp2 & 0x7);

	apic_debug("timer divide count is 0x%x\n",
				   apic->divide_count);
}

static void apic_update_lvtt(struct kvm_lapic *apic)
{
	u32 timer_mode = kvm_lapic_get_reg(apic, APIC_LVTT) &
			apic->lapic_timer.timer_mode_mask;

	if (apic->lapic_timer.timer_mode != timer_mode) {
		apic->lapic_timer.timer_mode = timer_mode;
		hrtimer_cancel(&apic->lapic_timer.timer);
	}
}

static void apic_timer_expired(struct kvm_lapic *apic)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct swait_queue_head *q = &vcpu->wq;
	struct kvm_timer *ktimer = &apic->lapic_timer;

	if (atomic_read(&apic->lapic_timer.pending))
		return;

	atomic_inc(&apic->lapic_timer.pending);
	kvm_set_pending_timer(vcpu);

	/*
	 * For x86, the atomic_inc() is serialized, thus
	 * using swait_active() is safe.
	 */
	if (swait_active(q))
		swake_up(q);

	if (apic_lvtt_tscdeadline(apic))
		ktimer->expired_tscdeadline = ktimer->tscdeadline;
}

/*
 * On APICv, this test will cause a busy wait
 * during a higher-priority task.
 */

static bool lapic_timer_int_injected(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 reg = kvm_lapic_get_reg(apic, APIC_LVTT);

	if (kvm_apic_hw_enabled(apic)) {
		int vec = reg & APIC_VECTOR_MASK;
		void *bitmap = apic->regs + APIC_ISR;

		if (vcpu->arch.apicv_active)
			bitmap = apic->regs + APIC_IRR;

		if (apic_test_vector(vec, bitmap))
			return true;
	}
	return false;
}

void wait_lapic_expire(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u64 guest_tsc, tsc_deadline;

	if (!lapic_in_kernel(vcpu))
		return;

	if (apic->lapic_timer.expired_tscdeadline == 0)
		return;

	if (!lapic_timer_int_injected(vcpu))
		return;

	tsc_deadline = apic->lapic_timer.expired_tscdeadline;
	apic->lapic_timer.expired_tscdeadline = 0;
	guest_tsc = kvm_read_l1_tsc(vcpu, rdtsc());
	trace_kvm_wait_lapic_expire(vcpu->vcpu_id, guest_tsc - tsc_deadline);

	/* __delay is delay_tsc whenever the hardware has TSC, thus always.  */
	if (guest_tsc < tsc_deadline)
		__delay(min(tsc_deadline - guest_tsc,
			nsec_to_cycles(vcpu, lapic_timer_advance_ns)));
}

static void start_sw_tscdeadline(struct kvm_lapic *apic)
{
	u64 guest_tsc, tscdeadline = apic->lapic_timer.tscdeadline;
	u64 ns = 0;
	ktime_t expire;
	struct kvm_vcpu *vcpu = apic->vcpu;
	unsigned long this_tsc_khz = vcpu->arch.virtual_tsc_khz;
	unsigned long flags;
	ktime_t now;

	if (unlikely(!tscdeadline || !this_tsc_khz))
		return;

	local_irq_save(flags);

	now = ktime_get();
	guest_tsc = kvm_read_l1_tsc(vcpu, rdtsc());
	if (likely(tscdeadline > guest_tsc)) {
		ns = (tscdeadline - guest_tsc) * 1000000ULL;
		do_div(ns, this_tsc_khz);
		expire = ktime_add_ns(now, ns);
		expire = ktime_sub_ns(expire, lapic_timer_advance_ns);
		hrtimer_start(&apic->lapic_timer.timer,
				expire, HRTIMER_MODE_ABS_PINNED);
	} else
		apic_timer_expired(apic);

	local_irq_restore(flags);
}

static void start_sw_period(struct kvm_lapic *apic)
{
	if (!apic->lapic_timer.period)
		return;

	if (apic_lvtt_oneshot(apic) &&
	    ktime_after(ktime_get(),
			apic->lapic_timer.target_expiration)) {
		apic_timer_expired(apic);
		return;
	}

	hrtimer_start(&apic->lapic_timer.timer,
		apic->lapic_timer.target_expiration,
		HRTIMER_MODE_ABS_PINNED);
}

static bool set_target_expiration(struct kvm_lapic *apic)
{
	ktime_t now;
	u64 tscl = rdtsc();

	now = ktime_get();
	apic->lapic_timer.period = (u64)kvm_lapic_get_reg(apic, APIC_TMICT)
		* APIC_BUS_CYCLE_NS * apic->divide_count;

	if (!apic->lapic_timer.period)
		return false;

	/*
	 * Do not allow the guest to program periodic timers with small
	 * interval, since the hrtimers are not throttled by the host
	 * scheduler.
	 */
	if (apic_lvtt_period(apic)) {
		s64 min_period = min_timer_period_us * 1000LL;

		if (apic->lapic_timer.period < min_period) {
			pr_info_ratelimited(
			    "kvm: vcpu %i: requested %lld ns "
			    "lapic timer period limited to %lld ns\n",
			    apic->vcpu->vcpu_id,
			    apic->lapic_timer.period, min_period);
			apic->lapic_timer.period = min_period;
		}
	}

	apic_debug("%s: bus cycle is %" PRId64 "ns, now 0x%016"
		   PRIx64 ", "
		   "timer initial count 0x%x, period %lldns, "
		   "expire @ 0x%016" PRIx64 ".\n", __func__,
		   APIC_BUS_CYCLE_NS, ktime_to_ns(now),
		   kvm_lapic_get_reg(apic, APIC_TMICT),
		   apic->lapic_timer.period,
		   ktime_to_ns(ktime_add_ns(now,
				apic->lapic_timer.period)));

	apic->lapic_timer.tscdeadline = kvm_read_l1_tsc(apic->vcpu, tscl) +
		nsec_to_cycles(apic->vcpu, apic->lapic_timer.period);
	apic->lapic_timer.target_expiration = ktime_add_ns(now, apic->lapic_timer.period);

	return true;
}

static void advance_periodic_target_expiration(struct kvm_lapic *apic)
{
	apic->lapic_timer.tscdeadline +=
		nsec_to_cycles(apic->vcpu, apic->lapic_timer.period);
	apic->lapic_timer.target_expiration =
		ktime_add_ns(apic->lapic_timer.target_expiration,
				apic->lapic_timer.period);
}

bool kvm_lapic_hv_timer_in_use(struct kvm_vcpu *vcpu)
{
	if (!lapic_in_kernel(vcpu))
		return false;

	return vcpu->arch.apic->lapic_timer.hv_timer_in_use;
}
EXPORT_SYMBOL_GPL(kvm_lapic_hv_timer_in_use);

static void cancel_hv_timer(struct kvm_lapic *apic)
{
	WARN_ON(preemptible());
	WARN_ON(!apic->lapic_timer.hv_timer_in_use);
	kvm_x86_ops->cancel_hv_timer(apic->vcpu);
	apic->lapic_timer.hv_timer_in_use = false;
}

static bool start_hv_timer(struct kvm_lapic *apic)
{
	struct kvm_timer *ktimer = &apic->lapic_timer;
	int r;

	WARN_ON(preemptible());
	if (!kvm_x86_ops->set_hv_timer)
		return false;

	if (!apic_lvtt_period(apic) && atomic_read(&ktimer->pending))
		return false;

	r = kvm_x86_ops->set_hv_timer(apic->vcpu, ktimer->tscdeadline);
	if (r < 0)
		return false;

	ktimer->hv_timer_in_use = true;
	hrtimer_cancel(&ktimer->timer);

	/*
	 * Also recheck ktimer->pending, in case the sw timer triggered in
	 * the window.  For periodic timer, leave the hv timer running for
	 * simplicity, and the deadline will be recomputed on the next vmexit.
	 */
	if (!apic_lvtt_period(apic) && (r || atomic_read(&ktimer->pending))) {
		if (r)
			apic_timer_expired(apic);
		return false;
	}

	trace_kvm_hv_timer_state(apic->vcpu->vcpu_id, true);
	return true;
}

static void start_sw_timer(struct kvm_lapic *apic)
{
	struct kvm_timer *ktimer = &apic->lapic_timer;

	WARN_ON(preemptible());
	if (apic->lapic_timer.hv_timer_in_use)
		cancel_hv_timer(apic);
	if (!apic_lvtt_period(apic) && atomic_read(&ktimer->pending))
		return;

	if (apic_lvtt_period(apic) || apic_lvtt_oneshot(apic))
		start_sw_period(apic);
	else if (apic_lvtt_tscdeadline(apic))
		start_sw_tscdeadline(apic);
	trace_kvm_hv_timer_state(apic->vcpu->vcpu_id, false);
}

static void restart_apic_timer(struct kvm_lapic *apic)
{
	preempt_disable();
	if (!start_hv_timer(apic))
		start_sw_timer(apic);
	preempt_enable();
}

void kvm_lapic_expired_hv_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	preempt_disable();
	/* If the preempt notifier has already run, it also called apic_timer_expired */
	if (!apic->lapic_timer.hv_timer_in_use)
		goto out;
	WARN_ON(swait_active(&vcpu->wq));
	cancel_hv_timer(apic);
	apic_timer_expired(apic);

	if (apic_lvtt_period(apic) && apic->lapic_timer.period) {
		advance_periodic_target_expiration(apic);
		restart_apic_timer(apic);
	}
out:
	preempt_enable();
}
EXPORT_SYMBOL_GPL(kvm_lapic_expired_hv_timer);

void kvm_lapic_switch_to_hv_timer(struct kvm_vcpu *vcpu)
{
	restart_apic_timer(vcpu->arch.apic);
}
EXPORT_SYMBOL_GPL(kvm_lapic_switch_to_hv_timer);

void kvm_lapic_switch_to_sw_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	preempt_disable();
	/* Possibly the TSC deadline timer is not enabled yet */
	if (apic->lapic_timer.hv_timer_in_use)
		start_sw_timer(apic);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(kvm_lapic_switch_to_sw_timer);

void kvm_lapic_restart_hv_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	WARN_ON(!apic->lapic_timer.hv_timer_in_use);
	restart_apic_timer(apic);
}

static void start_apic_timer(struct kvm_lapic *apic)
{
	ktime_t now = apic->timer.dev.base->get_time();

	apic->timer.last_update = now;

	apic->timer.period = apic_get_reg(apic, APIC_TMICT) *
		    APIC_BUS_CYCLE_NS * apic->timer.divide_count;
	atomic_set(&apic->timer.pending, 0);

	if (!apic->timer.period)
		return;

	hrtimer_start(&apic->timer.dev,
		      ktime_add_ns(now, apic->timer.period),
		      HRTIMER_MODE_ABS);

	apic_debug("%s: bus cycle is %" PRId64 "ns, now 0x%016"
	ktime_t now;

	atomic_set(&apic->lapic_timer.pending, 0);

	if ((apic_lvtt_period(apic) || apic_lvtt_oneshot(apic))
	    && !set_target_expiration(apic))
		return;

		if (!apic->lapic_timer.period)
			return;
		/*
		 * Do not allow the guest to program periodic timers with small
		 * interval, since the hrtimers are not throttled by the host
		 * scheduler.
		 */
		if (apic_lvtt_period(apic)) {
			s64 min_period = min_timer_period_us * 1000LL;

			if (apic->lapic_timer.period < min_period) {
				pr_info_ratelimited(
				    "kvm: vcpu %i: requested %lld ns "
				    "lapic timer period limited to %lld ns\n",
				    apic->vcpu->vcpu_id,
				    apic->lapic_timer.period, min_period);
				apic->lapic_timer.period = min_period;
			}
		}

		hrtimer_start(&apic->lapic_timer.timer,
			      ktime_add_ns(now, apic->lapic_timer.period),
			      HRTIMER_MODE_ABS);

		apic_debug("%s: bus cycle is %" PRId64 "ns, now 0x%016"
			   PRIx64 ", "
			   "timer initial count 0x%x, period %lldns, "
			   "expire @ 0x%016" PRIx64 ".\n", __func__,
			   APIC_BUS_CYCLE_NS, ktime_to_ns(now),
			   apic_get_reg(apic, APIC_TMICT),
			   apic->timer.period,
			   ktime_to_ns(ktime_add_ns(now,
					apic->timer.period)));
}

static void apic_mmio_write(struct kvm_io_device *this,
			    gpa_t address, int len, const void *data)
{
	struct kvm_lapic *apic = (struct kvm_lapic *)this->private;
	unsigned int offset = address - apic->base_address;
	unsigned char alignment = offset & 0xf;
	u32 val;

	/*
	 * APIC register must be aligned on 128-bits boundary.
	 * 32/64/128 bits registers must be accessed thru 32 bits.
	 * Refer SDM 8.4.1
	 */
	if (len != 4 || alignment) {
		if (printk_ratelimit())
			printk(KERN_ERR "apic write: bad size=%d %lx\n",
			       len, (long)address);
		return;
	}

	val = *(u32 *) data;

	/* too common printing */
	if (offset != APIC_EOI)
		apic_debug("%s: offset 0x%x with length 0x%x, and value is "
			   "0x%x\n", __func__, offset, len, val);

	offset &= 0xff0;

	KVMTRACE_1D(APIC_ACCESS, apic->vcpu, (u32)offset, handler);

	switch (offset) {
	case APIC_ID:		/* Local APIC ID */
		apic_set_reg(apic, APIC_ID, val);
			   kvm_apic_get_reg(apic, APIC_TMICT),
			   apic->lapic_timer.period,
			   ktime_to_ns(ktime_add_ns(now,
					apic->lapic_timer.period)));
	} else if (apic_lvtt_tscdeadline(apic)) {
		/* lapic timer in tsc deadline mode */
		u64 guest_tsc, tscdeadline = apic->lapic_timer.tscdeadline;
		u64 ns = 0;
		ktime_t expire;
		struct kvm_vcpu *vcpu = apic->vcpu;
		unsigned long this_tsc_khz = vcpu->arch.virtual_tsc_khz;
		unsigned long flags;

		if (unlikely(!tscdeadline || !this_tsc_khz))
			return;

		local_irq_save(flags);

		now = apic->lapic_timer.timer.base->get_time();
		guest_tsc = kvm_read_l1_tsc(vcpu, rdtsc());
		if (likely(tscdeadline > guest_tsc)) {
			ns = (tscdeadline - guest_tsc) * 1000000ULL;
			do_div(ns, this_tsc_khz);
			expire = ktime_add_ns(now, ns);
			expire = ktime_sub_ns(expire, lapic_timer_advance_ns);
			hrtimer_start(&apic->lapic_timer.timer,
				      expire, HRTIMER_MODE_ABS);
		} else
			apic_timer_expired(apic);

		local_irq_restore(flags);
	}
	restart_apic_timer(apic);
}

static void apic_manage_nmi_watchdog(struct kvm_lapic *apic, u32 lvt0_val)
{
	bool lvt0_in_nmi_mode = apic_lvt_nmi_mode(lvt0_val);

	if (apic->lvt0_in_nmi_mode != lvt0_in_nmi_mode) {
		apic->lvt0_in_nmi_mode = lvt0_in_nmi_mode;
		if (lvt0_in_nmi_mode) {
			apic_debug("Receive NMI setting on APIC_LVT0 "
				   "for cpu %d\n", apic->vcpu->vcpu_id);
			atomic_inc(&apic->vcpu->kvm->arch.vapics_in_nmi_mode);
		} else
			atomic_dec(&apic->vcpu->kvm->arch.vapics_in_nmi_mode);
	}
}

int kvm_lapic_reg_write(struct kvm_lapic *apic, u32 reg, u32 val)
{
	int ret = 0;

	trace_kvm_apic_write(reg, val);

	switch (reg) {
	case APIC_ID:		/* Local APIC ID */
		if (!apic_x2apic_mode(apic))
			kvm_apic_set_xapic_id(apic, val >> 24);
		else
			ret = 1;
		break;

	case APIC_TASKPRI:
		report_tpr_access(apic, true);
		apic_set_tpr(apic, val & 0xff);
		break;

	case APIC_EOI:
		apic_set_eoi(apic);
		break;

	case APIC_LDR:
		apic_set_reg(apic, APIC_LDR, val & APIC_LDR_MASK);
		break;

	case APIC_DFR:
		apic_set_reg(apic, APIC_DFR, val | 0x0FFFFFFF);
		break;

	case APIC_SPIV:
		apic_set_reg(apic, APIC_SPIV, val & 0x3ff);
		if (!apic_x2apic_mode(apic))
			kvm_apic_set_ldr(apic, val & APIC_LDR_MASK);
		else
			ret = 1;
		break;

	case APIC_DFR:
		if (!apic_x2apic_mode(apic)) {
			kvm_lapic_set_reg(apic, APIC_DFR, val | 0x0FFFFFFF);
			recalculate_apic_map(apic->vcpu->kvm);
		} else
			ret = 1;
		break;

	case APIC_SPIV: {
		u32 mask = 0x3ff;
		if (kvm_lapic_get_reg(apic, APIC_LVR) & APIC_LVR_DIRECTED_EOI)
			mask |= APIC_SPIV_DIRECTED_EOI;
		apic_set_spiv(apic, val & mask);
		if (!(val & APIC_SPIV_APIC_ENABLED)) {
			int i;
			u32 lvt_val;

			for (i = 0; i < APIC_LVT_NUM; i++) {
				lvt_val = apic_get_reg(apic,
				lvt_val = kvm_apic_get_reg(apic,
			for (i = 0; i < KVM_APIC_LVT_NUM; i++) {
				lvt_val = kvm_lapic_get_reg(apic,
						       APIC_LVTT + 0x10 * i);
				kvm_lapic_set_reg(apic, APIC_LVTT + 0x10 * i,
					     lvt_val | APIC_LVT_MASKED);
			}
			atomic_set(&apic->timer.pending, 0);

		}
		break;

			apic_update_lvtt(apic);
			atomic_set(&apic->lapic_timer.pending, 0);

		}
		break;
	}
	case APIC_ICR:
		/* No delay here, so we always clear the pending bit */
		kvm_lapic_set_reg(apic, APIC_ICR, val & ~(1 << 12));
		apic_send_ipi(apic);
		break;

	case APIC_ICR2:
		apic_set_reg(apic, APIC_ICR2, val & 0xff000000);
		break;

	case APIC_LVTT:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
		/* TODO: Check vector */
		if (!apic_sw_enabled(apic))
			val |= APIC_LVT_MASKED;

		val &= apic_lvt_mask[(offset - APIC_LVTT) >> 4];
		apic_set_reg(apic, offset, val);

		break;

	case APIC_TMICT:
		hrtimer_cancel(&apic->timer.dev);
		apic_set_reg(apic, APIC_TMICT, val);
		start_apic_timer(apic);
		return;

	case APIC_TDCR:
		if (val & 4)
			printk(KERN_ERR "KVM_WRITE:TDCR %x\n", val);
		if (!apic_x2apic_mode(apic))
			val &= 0xff000000;
		kvm_lapic_set_reg(apic, APIC_ICR2, val);
		break;

	case APIC_LVT0:
		apic_manage_nmi_watchdog(apic, val);
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT1:
	case APIC_LVTERR:
		/* TODO: Check vector */
		if (!kvm_apic_sw_enabled(apic))
			val |= APIC_LVT_MASKED;

		val &= apic_lvt_mask[(reg - APIC_LVTT) >> 4];
		kvm_lapic_set_reg(apic, reg, val);

		break;

	case APIC_LVTT:
		if (!kvm_apic_sw_enabled(apic))
			val |= APIC_LVT_MASKED;
		val &= (apic_lvt_mask[0] | apic->lapic_timer.timer_mode_mask);
		kvm_lapic_set_reg(apic, APIC_LVTT, val);
		apic_update_lvtt(apic);
		break;

	case APIC_TMICT:
		if (apic_lvtt_tscdeadline(apic))
			break;

		hrtimer_cancel(&apic->lapic_timer.timer);
		kvm_lapic_set_reg(apic, APIC_TMICT, val);
		start_apic_timer(apic);
		break;

	case APIC_TDCR:
		if (val & 4)
			apic_debug("KVM_WRITE:TDCR %x\n", val);
		kvm_lapic_set_reg(apic, APIC_TDCR, val);
		update_divide_count(apic);
		break;

	default:
		apic_debug("Local APIC Write to read-only register %x\n",
			   offset);
		break;
	}

}

static int apic_mmio_range(struct kvm_io_device *this, gpa_t addr,
			   int len, int size)
{
	struct kvm_lapic *apic = (struct kvm_lapic *)this->private;
	int ret = 0;


	if (apic_hw_enabled(apic) &&
	    (addr >= apic->base_address) &&
	    (addr < (apic->base_address + LAPIC_MMIO_LENGTH)))
		ret = 1;

	return ret;
}

void kvm_free_lapic(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.apic)
		return;

	hrtimer_cancel(&vcpu->arch.apic->timer.dev);

	if (vcpu->arch.apic->regs_page)
		__free_page(vcpu->arch.apic->regs_page);

	kfree(vcpu->arch.apic);
	case APIC_ESR:
		if (apic_x2apic_mode(apic) && val != 0) {
			apic_debug("KVM_WRITE:ESR not zero %x\n", val);
			ret = 1;
		}
		break;

	case APIC_SELF_IPI:
		if (apic_x2apic_mode(apic)) {
			kvm_lapic_reg_write(apic, APIC_ICR, 0x40000 | (val & 0xff));
		} else
			ret = 1;
		break;
	default:
		ret = 1;
		break;
	}
	if (ret)
		apic_debug("Local APIC Write to read-only register %x\n", reg);
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_lapic_reg_write);

static int apic_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
			    gpa_t address, int len, const void *data)
{
	struct kvm_lapic *apic = to_lapic(this);
	unsigned int offset = address - apic->base_address;
	u32 val;

	if (!apic_mmio_in_range(apic, address))
		return -EOPNOTSUPP;

	/*
	 * APIC register must be aligned on 128-bits boundary.
	 * 32/64/128 bits registers must be accessed thru 32 bits.
	 * Refer SDM 8.4.1
	 */
	if (len != 4 || (offset & 0xf)) {
		/* Don't shout loud, $infamous_os would cause only noise. */
		apic_debug("apic write: bad size=%d %lx\n", len, (long)address);
		return 0;
	}

	val = *(u32*)data;

	/* too common printing */
	if (offset != APIC_EOI)
		apic_debug("%s: offset 0x%x with length 0x%x, and value is "
			   "0x%x\n", __func__, offset, len, val);

	kvm_lapic_reg_write(apic, offset & 0xff0, val);

	return 0;
}

void kvm_lapic_set_eoi(struct kvm_vcpu *vcpu)
{
	kvm_lapic_reg_write(vcpu->arch.apic, APIC_EOI, 0);
}
EXPORT_SYMBOL_GPL(kvm_lapic_set_eoi);

/* emulate APIC access in a trap manner */
void kvm_apic_write_nodecode(struct kvm_vcpu *vcpu, u32 offset)
{
	u32 val = 0;

	/* hw has done the conditional check and inst decode */
	offset &= 0xff0;

	kvm_lapic_reg_read(vcpu->arch.apic, offset, 4, &val);

	/* TODO: optimize to just emulate side effect w/o one more write */
	kvm_lapic_reg_write(vcpu->arch.apic, offset, val);
}
EXPORT_SYMBOL_GPL(kvm_apic_write_nodecode);

void kvm_free_lapic(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!vcpu->arch.apic)
		return;

	hrtimer_cancel(&apic->lapic_timer.timer);

	if (!(vcpu->arch.apic_base & MSR_IA32_APICBASE_ENABLE))
		static_key_slow_dec_deferred(&apic_hw_disabled);

	if (!apic->sw_enabled)
		static_key_slow_dec_deferred(&apic_sw_disabled);

	if (apic->regs)
		free_page((unsigned long)apic->regs);

	kfree(apic);
}

/*
 *----------------------------------------------------------------------
 * LAPIC interface
 *----------------------------------------------------------------------
 */
u64 kvm_get_lapic_tscdeadline_msr(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!lapic_in_kernel(vcpu) ||
		!apic_lvtt_tscdeadline(apic))
		return 0;

	return apic->lapic_timer.tscdeadline;
}

void kvm_set_lapic_tscdeadline_msr(struct kvm_vcpu *vcpu, u64 data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!lapic_in_kernel(vcpu) || apic_lvtt_oneshot(apic) ||
			apic_lvtt_period(apic))
		return;

	hrtimer_cancel(&apic->lapic_timer.timer);
	apic->lapic_timer.tscdeadline = data;
	start_apic_timer(apic);
}

void kvm_lapic_set_tpr(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic)
		return;
	apic_set_tpr(apic, ((cr8 & 0x0f) << 4)
		     | (apic_get_reg(apic, APIC_TASKPRI) & 4));
}
EXPORT_SYMBOL_GPL(kvm_lapic_set_tpr);

u64 kvm_lapic_get_cr8(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u64 tpr;

	if (!apic)
		return 0;
	tpr = (u64) apic_get_reg(apic, APIC_TASKPRI);

	return (tpr & 0xf0) >> 4;
}
EXPORT_SYMBOL_GPL(kvm_lapic_get_cr8);

void kvm_lapic_set_base(struct kvm_vcpu *vcpu, u64 value)
{
	if (!kvm_vcpu_has_lapic(vcpu))
		return;

	apic_set_tpr(apic, ((cr8 & 0x0f) << 4)
		     | (kvm_lapic_get_reg(apic, APIC_TASKPRI) & 4));
}

u64 kvm_lapic_get_cr8(struct kvm_vcpu *vcpu)
{
	u64 tpr;

	tpr = (u64) kvm_lapic_get_reg(vcpu->arch.apic, APIC_TASKPRI);

	return (tpr & 0xf0) >> 4;
}

void kvm_lapic_set_base(struct kvm_vcpu *vcpu, u64 value)
{
	u64 old_value = vcpu->arch.apic_base;
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic)
		value |= MSR_IA32_APICBASE_BSP;
		vcpu->arch.apic_base = value;
		return;
	}
	if (apic->vcpu->vcpu_id)
		value &= ~MSR_IA32_APICBASE_BSP;

	vcpu->arch.apic_base = value;
	apic->base_address = apic->vcpu->arch.apic_base &
			     MSR_IA32_APICBASE_BASE;


	vcpu->arch.apic_base = value;

	if ((old_value ^ value) & MSR_IA32_APICBASE_ENABLE)
		kvm_update_cpuid(vcpu);

	if (!apic)
		return;

	/* update jump label if enable bit changes */
	if ((old_value ^ value) & MSR_IA32_APICBASE_ENABLE) {
		if (value & MSR_IA32_APICBASE_ENABLE) {
			kvm_apic_set_xapic_id(apic, vcpu->vcpu_id);
			static_key_slow_dec_deferred(&apic_hw_disabled);
		} else {
			static_key_slow_inc(&apic_hw_disabled.key);
			recalculate_apic_map(vcpu->kvm);
		}
	}

	if ((old_value ^ value) & X2APIC_ENABLE) {
		if (value & X2APIC_ENABLE) {
			kvm_apic_set_x2apic_id(apic, vcpu->vcpu_id);
			kvm_x86_ops->set_virtual_x2apic_mode(vcpu, true);
		} else
			kvm_x86_ops->set_virtual_x2apic_mode(vcpu, false);
	}

	apic->base_address = apic->vcpu->arch.apic_base &
			     MSR_IA32_APICBASE_BASE;

	if ((value & MSR_IA32_APICBASE_ENABLE) &&
	     apic->base_address != APIC_DEFAULT_PHYS_BASE)
		pr_warn_once("APIC base relocation is unsupported by KVM");

	/* with FSB delivery interrupt, we can restart APIC functionality */
	apic_debug("apic base msr is 0x%016" PRIx64 ", and base address is "
		   "0x%lx.\n", apic->vcpu->arch.apic_base, apic->base_address);

}

u64 kvm_lapic_get_base(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.apic_base;
}
EXPORT_SYMBOL_GPL(kvm_lapic_get_base);

void kvm_lapic_reset(struct kvm_vcpu *vcpu)
void kvm_lapic_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_lapic *apic;
	int i;

	apic_debug("%s\n", __func__);

	ASSERT(vcpu);
	apic = vcpu->arch.apic;
	ASSERT(apic != NULL);

	/* Stop the timer in case it's a reset to an active apic */
	hrtimer_cancel(&apic->timer.dev);

	apic_set_reg(apic, APIC_ID, vcpu->vcpu_id << 24);
	apic_set_reg(apic, APIC_LVR, APIC_VERSION);

	for (i = 0; i < APIC_LVT_NUM; i++)
		apic_set_reg(apic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);
	apic_set_reg(apic, APIC_LVT0,
		     SET_APIC_DELIVERY_MODE(0, APIC_MODE_EXTINT));

	apic_set_reg(apic, APIC_DFR, 0xffffffffU);
	apic_set_reg(apic, APIC_SPIV, 0xff);
	apic_set_reg(apic, APIC_TASKPRI, 0);
	apic_set_reg(apic, APIC_LDR, 0);
	hrtimer_cancel(&apic->lapic_timer.timer);

	if (!init_event) {
		kvm_lapic_set_base(vcpu, APIC_DEFAULT_PHYS_BASE |
		                         MSR_IA32_APICBASE_ENABLE);
		kvm_apic_set_xapic_id(apic, vcpu->vcpu_id);
	}
	kvm_apic_set_version(apic->vcpu);

	for (i = 0; i < KVM_APIC_LVT_NUM; i++)
		kvm_lapic_set_reg(apic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);
	apic_update_lvtt(apic);
	if (kvm_vcpu_is_reset_bsp(vcpu) &&
	    kvm_check_has_quirk(vcpu->kvm, KVM_X86_QUIRK_LINT0_REENABLED))
		kvm_lapic_set_reg(apic, APIC_LVT0,
			     SET_APIC_DELIVERY_MODE(0, APIC_MODE_EXTINT));
	apic_manage_nmi_watchdog(apic, kvm_lapic_get_reg(apic, APIC_LVT0));

	kvm_lapic_set_reg(apic, APIC_DFR, 0xffffffffU);
	apic_set_spiv(apic, 0xff);
	kvm_lapic_set_reg(apic, APIC_TASKPRI, 0);
	if (!apic_x2apic_mode(apic))
		kvm_apic_set_ldr(apic, 0);
	kvm_lapic_set_reg(apic, APIC_ESR, 0);
	kvm_lapic_set_reg(apic, APIC_ICR, 0);
	kvm_lapic_set_reg(apic, APIC_ICR2, 0);
	kvm_lapic_set_reg(apic, APIC_TDCR, 0);
	kvm_lapic_set_reg(apic, APIC_TMICT, 0);
	for (i = 0; i < 8; i++) {
		kvm_lapic_set_reg(apic, APIC_IRR + 0x10 * i, 0);
		kvm_lapic_set_reg(apic, APIC_ISR + 0x10 * i, 0);
		kvm_lapic_set_reg(apic, APIC_TMR + 0x10 * i, 0);
	}
	update_divide_count(apic);
	atomic_set(&apic->timer.pending, 0);
	if (vcpu->vcpu_id == 0)
		vcpu->arch.apic_base |= MSR_IA32_APICBASE_BSP;
	apic_update_ppr(apic);

	apic_debug(KERN_INFO "%s: vcpu=%p, id=%d, base_msr="
	apic->irr_pending = kvm_vcpu_apic_vid_enabled(vcpu);
	apic->isr_count = kvm_x86_ops->hwapic_isr_update ? 1 : 0;
	apic->irr_pending = vcpu->arch.apicv_active;
	apic->isr_count = vcpu->arch.apicv_active ? 1 : 0;
	apic->highest_isr_cache = -1;
	update_divide_count(apic);
	atomic_set(&apic->lapic_timer.pending, 0);
	if (kvm_vcpu_is_bsp(vcpu))
		kvm_lapic_set_base(vcpu,
				vcpu->arch.apic_base | MSR_IA32_APICBASE_BSP);
	vcpu->arch.pv_eoi.msr_val = 0;
	apic_update_ppr(apic);
	if (vcpu->arch.apicv_active) {
		kvm_x86_ops->apicv_post_state_restore(vcpu);
		kvm_x86_ops->hwapic_irr_update(vcpu, -1);
		kvm_x86_ops->hwapic_isr_update(vcpu, -1);
	}

	vcpu->arch.apic_arb_prio = 0;
	vcpu->arch.apic_attention = 0;

	apic_debug("%s: vcpu=%p, id=0x%x, base_msr="
		   "0x%016" PRIx64 ", base_address=0x%0lx.\n", __func__,
		   vcpu, kvm_lapic_get_reg(apic, APIC_ID),
		   vcpu->arch.apic_base, apic->base_address);
}
EXPORT_SYMBOL_GPL(kvm_lapic_reset);

int kvm_lapic_enabled(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int ret = 0;

	if (!apic)
		return 0;
	ret = apic_enabled(apic);

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_lapic_enabled);

/*
 *----------------------------------------------------------------------
 * timer interface
 *----------------------------------------------------------------------
 */

/* TODO: make sure __apic_timer_fn runs in current pCPU */
static int __apic_timer_fn(struct kvm_lapic *apic)
{
	int result = 0;
	wait_queue_head_t *q = &apic->vcpu->wq;

	if(!atomic_inc_and_test(&apic->timer.pending))
		set_bit(KVM_REQ_PENDING_TIMER, &apic->vcpu->requests);
	if (waitqueue_active(q)) {
		apic->vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
		wake_up_interruptible(q);
	}
	if (apic_lvtt_period(apic)) {
		result = 1;
		apic->timer.dev.expires = ktime_add_ns(
					apic->timer.dev.expires,
					apic->timer.period);
	}
	return result;
static bool lapic_is_periodic(struct kvm_lapic *apic)
{
	return apic_lvtt_period(apic);
}

int apic_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *lapic = vcpu->arch.apic;

	if (lapic && apic_enabled(lapic) && apic_lvt_enabled(lapic, APIC_LVTT))
		return atomic_read(&lapic->timer.pending);
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic_enabled(apic) && apic_lvt_enabled(apic, APIC_LVTT))
		return atomic_read(&apic->lapic_timer.pending);

	return 0;
}

static int __inject_apic_timer_irq(struct kvm_lapic *apic)
{
	int vector;

	vector = apic_lvt_vector(apic, APIC_LVTT);
	return __apic_accept_irq(apic, APIC_DM_FIXED, vector, 1, 0);
}

static enum hrtimer_restart apic_timer_fn(struct hrtimer *data)
{
	struct kvm_lapic *apic;
	int restart_timer = 0;

	apic = container_of(data, struct kvm_lapic, timer.dev);

	restart_timer = __apic_timer_fn(apic);

	if (restart_timer)
		return HRTIMER_RESTART;
	else
int kvm_apic_local_deliver(struct kvm_lapic *apic, int lvt_type)
{
	u32 reg = kvm_lapic_get_reg(apic, lvt_type);
	int vector, mode, trig_mode;

	if (kvm_apic_hw_enabled(apic) && !(reg & APIC_LVT_MASKED)) {
		vector = reg & APIC_VECTOR_MASK;
		mode = reg & APIC_MODE_MASK;
		trig_mode = reg & APIC_LVT_LEVEL_TRIGGER;
		return __apic_accept_irq(apic, mode, vector, 1, trig_mode,
					NULL);
	}
	return 0;
}

void kvm_apic_nmi_wd_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic)
		kvm_apic_local_deliver(apic, APIC_LVT0);
}

static const struct kvm_io_device_ops apic_mmio_ops = {
	.read     = apic_mmio_read,
	.write    = apic_mmio_write,
};

static enum hrtimer_restart apic_timer_fn(struct hrtimer *data)
{
	struct kvm_timer *ktimer = container_of(data, struct kvm_timer, timer);
	struct kvm_lapic *apic = container_of(ktimer, struct kvm_lapic, lapic_timer);

	apic_timer_expired(apic);

	if (lapic_is_periodic(apic)) {
		advance_periodic_target_expiration(apic);
		hrtimer_add_expires_ns(&ktimer->timer, ktimer->period);
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}

int kvm_create_lapic(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;

	ASSERT(vcpu != NULL);
	apic_debug("apic_init %d\n", vcpu->vcpu_id);

	apic = kzalloc(sizeof(*apic), GFP_KERNEL);
	if (!apic)
		goto nomem;

	vcpu->arch.apic = apic;

	apic->regs_page = alloc_page(GFP_KERNEL);
	if (apic->regs_page == NULL) {
	apic->regs = (void *)get_zeroed_page(GFP_KERNEL);
	if (!apic->regs) {
		printk(KERN_ERR "malloc apic regs error for vcpu %x\n",
		       vcpu->vcpu_id);
		goto nomem_free_apic;
	}
	apic->regs = page_address(apic->regs_page);
	memset(apic->regs, 0, PAGE_SIZE);
	apic->vcpu = vcpu;

	hrtimer_init(&apic->timer.dev, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	apic->timer.dev.function = apic_timer_fn;
	apic->base_address = APIC_DEFAULT_PHYS_BASE;
	vcpu->arch.apic_base = APIC_DEFAULT_PHYS_BASE;

	kvm_lapic_reset(vcpu);
	apic->dev.read = apic_mmio_read;
	apic->dev.write = apic_mmio_write;
	apic->dev.in_range = apic_mmio_range;
	apic->dev.private = apic;
	apic->vcpu = vcpu;

	hrtimer_init(&apic->lapic_timer.timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	apic->lapic_timer.timer.function = apic_timer_fn;

	/*
	 * APIC is created enabled. This will prevent kvm_lapic_set_base from
	 * thinking that APIC satet has changed.
	 */
	vcpu->arch.apic_base = MSR_IA32_APICBASE_ENABLE;
	static_key_slow_inc(&apic_sw_disabled.key); /* sw disabled at reset */
	kvm_lapic_reset(vcpu, false);
	kvm_iodevice_init(&apic->dev, &apic_mmio_ops);

	return 0;
nomem_free_apic:
	kfree(apic);
nomem:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(kvm_create_lapic);

int kvm_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 ppr;

	if (!apic || !apic_enabled(apic))
	if (!kvm_vcpu_has_lapic(vcpu) || !apic_enabled(apic))
		return -1;

	apic_update_ppr(apic);
	highest_irr = apic_find_highest_irr(apic);
	if ((highest_irr == -1) ||
	    ((highest_irr & 0xF0) <= apic_get_reg(apic, APIC_PROCPRI)))
	    ((highest_irr & 0xF0) <= kvm_apic_get_reg(apic, APIC_PROCPRI)))
		return -1;
	return highest_irr;
	if (!apic_enabled(apic))
		return -1;

	__apic_update_ppr(apic, &ppr);
	return apic_has_interrupt_for_ppr(apic, ppr);
}

int kvm_apic_accept_pic_intr(struct kvm_vcpu *vcpu)
{
	u32 lvt0 = apic_get_reg(vcpu->arch.apic, APIC_LVT0);
	int r = 0;

	if (vcpu->vcpu_id == 0) {
		if (!apic_hw_enabled(vcpu->arch.apic))
			r = 1;
		if ((lvt0 & APIC_LVT_MASKED) == 0 &&
		    GET_APIC_DELIVERY_MODE(lvt0) == APIC_MODE_EXTINT)
			r = 1;
	}
	u32 lvt0 = kvm_apic_get_reg(vcpu->arch.apic, APIC_LVT0);
	u32 lvt0 = kvm_lapic_get_reg(vcpu->arch.apic, APIC_LVT0);
	int r = 0;

	if (!kvm_apic_hw_enabled(vcpu->arch.apic))
		r = 1;
	if ((lvt0 & APIC_LVT_MASKED) == 0 &&
	    GET_APIC_DELIVERY_MODE(lvt0) == APIC_MODE_EXTINT)
		r = 1;
	return r;
}

void kvm_inject_apic_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic && apic_lvt_enabled(apic, APIC_LVTT) &&
		atomic_read(&apic->timer.pending) > 0) {
		if (__inject_apic_timer_irq(apic))
			atomic_dec(&apic->timer.pending);
	}
}

void kvm_apic_timer_intr_post(struct kvm_vcpu *vcpu, int vec)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic && apic_lvt_vector(apic, APIC_LVTT) == vec)
		apic->timer.last_update = ktime_add_ns(
				apic->timer.last_update,
				apic->timer.period);
}

	if (!kvm_vcpu_has_lapic(vcpu))
		return;

	if (atomic_read(&apic->lapic_timer.pending) > 0) {
		kvm_apic_local_deliver(apic, APIC_LVTT);
		if (apic_lvtt_tscdeadline(apic))
			apic->lapic_timer.tscdeadline = 0;
		if (apic_lvtt_oneshot(apic)) {
			apic->lapic_timer.tscdeadline = 0;
			apic->lapic_timer.target_expiration = 0;
		}
		atomic_set(&apic->lapic_timer.pending, 0);
	}
}

int kvm_get_apic_interrupt(struct kvm_vcpu *vcpu)
{
	int vector = kvm_apic_has_interrupt(vcpu);
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 ppr;

	if (vector == -1)
		return -1;

	apic_set_vector(vector, apic->regs + APIC_ISR);
	/*
	 * We get here even with APIC virtualization enabled, if doing
	 * nested virtualization and L1 runs with the "acknowledge interrupt
	 * on exit" mode.  Then we cannot inject the interrupt via RVI,
	 * because the process would deliver it through the IDT.
	 */

	apic_clear_irr(vector, apic);
	if (test_bit(vector, vcpu_to_synic(vcpu)->auto_eoi_bitmap)) {
		/*
		 * For auto-EOI interrupts, there might be another pending
		 * interrupt above PPR, so check whether to raise another
		 * KVM_REQ_EVENT.
		 */
		apic_update_ppr(apic);
	} else {
		/*
		 * For normal interrupts, PPR has been raised and there cannot
		 * be a higher-priority pending interrupt---except if there was
		 * a concurrent interrupt injection, but that would have
		 * triggered KVM_REQ_EVENT already.
		 */
		apic_set_isr(vector, apic);
		__apic_update_ppr(apic, &ppr);
	}

	return vector;
}

void kvm_apic_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	apic->base_address = vcpu->arch.apic_base &
			     MSR_IA32_APICBASE_BASE;
	apic_set_reg(apic, APIC_LVR, APIC_VERSION);
	apic_update_ppr(apic);
	hrtimer_cancel(&apic->timer.dev);
	update_divide_count(apic);
	start_apic_timer(apic);
void kvm_apic_post_state_restore(struct kvm_vcpu *vcpu,
		struct kvm_lapic_state *s)
static int kvm_apic_state_fixup(struct kvm_vcpu *vcpu,
		struct kvm_lapic_state *s, bool set)
{
	if (apic_x2apic_mode(vcpu->arch.apic)) {
		u32 *id = (u32 *)(s->regs + APIC_ID);

		if (vcpu->kvm->arch.x2apic_format) {
			if (*id != vcpu->vcpu_id)
				return -EINVAL;
		} else {
			if (set)
				*id >>= 24;
			else
				*id <<= 24;
		}
	}

	return 0;
}

int kvm_apic_get_state(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s)
{
	memcpy(s->regs, vcpu->arch.apic->regs, sizeof(*s));
	return kvm_apic_state_fixup(vcpu, s, false);
}

int kvm_apic_set_state(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int r;


	kvm_lapic_set_base(vcpu, vcpu->arch.apic_base);
	/* set SPIV separately to get count of SW disabled APICs right */
	apic_set_spiv(apic, *((u32 *)(s->regs + APIC_SPIV)));

	r = kvm_apic_state_fixup(vcpu, s, true);
	if (r)
		return r;
	memcpy(vcpu->arch.apic->regs, s->regs, sizeof *s);

	recalculate_apic_map(vcpu->kvm);
	kvm_apic_set_version(vcpu);

	apic_update_ppr(apic);
	hrtimer_cancel(&apic->lapic_timer.timer);
	apic_update_lvtt(apic);
	apic_manage_nmi_watchdog(apic, kvm_lapic_get_reg(apic, APIC_LVT0));
	update_divide_count(apic);
	start_apic_timer(apic);
	apic->irr_pending = true;
	apic->isr_count = vcpu->arch.apicv_active ?
				1 : count_vectors(apic->regs + APIC_ISR);
	apic->highest_isr_cache = -1;
	if (vcpu->arch.apicv_active) {
		kvm_x86_ops->apicv_post_state_restore(vcpu);
		kvm_x86_ops->hwapic_irr_update(vcpu,
				apic_find_highest_irr(apic));
		kvm_x86_ops->hwapic_isr_update(vcpu,
				apic_find_highest_isr(apic));
	}
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	if (ioapic_in_kernel(vcpu->kvm))
		kvm_rtc_eoi_tracking_restore_one(vcpu);

	vcpu->arch.apic_arb_prio = 0;

	return 0;
}

void __kvm_migrate_apic_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct hrtimer *timer;

	if (!apic)
		return;

	timer = &apic->timer.dev;
	if (hrtimer_cancel(timer))
		hrtimer_start(timer, timer->expires, HRTIMER_MODE_ABS);
	struct hrtimer *timer;

	if (!lapic_in_kernel(vcpu))
		return;

	timer = &vcpu->arch.apic->lapic_timer.timer;
	if (hrtimer_cancel(timer))
		hrtimer_start_expires(timer, HRTIMER_MODE_ABS_PINNED);
}

/*
 * apic_sync_pv_eoi_from_guest - called on vmexit or cancel interrupt
 *
 * Detect whether guest triggered PV EOI since the
 * last entry. If yes, set EOI on guests's behalf.
 * Clear PV EOI in guest memory in any case.
 */
static void apic_sync_pv_eoi_from_guest(struct kvm_vcpu *vcpu,
					struct kvm_lapic *apic)
{
	bool pending;
	int vector;
	/*
	 * PV EOI state is derived from KVM_APIC_PV_EOI_PENDING in host
	 * and KVM_PV_EOI_ENABLED in guest memory as follows:
	 *
	 * KVM_APIC_PV_EOI_PENDING is unset:
	 * 	-> host disabled PV EOI.
	 * KVM_APIC_PV_EOI_PENDING is set, KVM_PV_EOI_ENABLED is set:
	 * 	-> host enabled PV EOI, guest did not execute EOI yet.
	 * KVM_APIC_PV_EOI_PENDING is set, KVM_PV_EOI_ENABLED is unset:
	 * 	-> host enabled PV EOI, guest executed EOI.
	 */
	BUG_ON(!pv_eoi_enabled(vcpu));
	pending = pv_eoi_get_pending(vcpu);
	/*
	 * Clear pending bit in any case: it will be set again on vmentry.
	 * While this might not be ideal from performance point of view,
	 * this makes sure pv eoi is only enabled when we know it's safe.
	 */
	pv_eoi_clr_pending(vcpu);
	if (pending)
		return;
	vector = apic_set_eoi(apic);
	trace_kvm_pv_eoi(apic, vector);
}

void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
{
	u32 data;
	void *vapic;

	if (!irqchip_in_kernel(vcpu->kvm) || !vcpu->arch.apic->vapic_addr)
		return;

	vapic = kmap_atomic(vcpu->arch.apic->vapic_page, KM_USER0);
	data = *(u32 *)(vapic + offset_in_page(vcpu->arch.apic->vapic_addr));
	kunmap_atomic(vapic, KM_USER0);

	if (test_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention))
		apic_sync_pv_eoi_from_guest(vcpu, vcpu->arch.apic);

	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
		return;

	if (kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.apic->vapic_cache, &data,
				  sizeof(u32)))
		return;

	apic_set_tpr(vcpu->arch.apic, data & 0xff);
}

/*
 * apic_sync_pv_eoi_to_guest - called before vmentry
 *
 * Detect whether it's safe to enable PV EOI and
 * if yes do so.
 */
static void apic_sync_pv_eoi_to_guest(struct kvm_vcpu *vcpu,
					struct kvm_lapic *apic)
{
	if (!pv_eoi_enabled(vcpu) ||
	    /* IRR set or many bits in ISR: could be nested. */
	    apic->irr_pending ||
	    /* Cache not set: could be safe but we don't bother. */
	    apic->highest_isr_cache == -1 ||
	    /* Need EOI to update ioapic. */
	    kvm_ioapic_handles_vector(apic, apic->highest_isr_cache)) {
		/*
		 * PV EOI was disabled by apic_sync_pv_eoi_from_guest
		 * so we need not do anything here.
		 */
		return;
	}

	pv_eoi_set_pending(apic->vcpu);
}

void kvm_lapic_sync_to_vapic(struct kvm_vcpu *vcpu)
{
	u32 data, tpr;
	int max_irr, max_isr;
	struct kvm_lapic *apic;
	void *vapic;

	if (!irqchip_in_kernel(vcpu->kvm) || !vcpu->arch.apic->vapic_addr)
		return;

	apic = vcpu->arch.apic;
	tpr = apic_get_reg(apic, APIC_TASKPRI) & 0xff;
	struct kvm_lapic *apic = vcpu->arch.apic;

	apic_sync_pv_eoi_to_guest(vcpu, apic);

	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
		return;

	tpr = kvm_lapic_get_reg(apic, APIC_TASKPRI) & 0xff;
	max_irr = apic_find_highest_irr(apic);
	if (max_irr < 0)
		max_irr = 0;
	max_isr = apic_find_highest_isr(apic);
	if (max_isr < 0)
		max_isr = 0;
	data = (tpr & 0xff) | ((max_isr & 0xf0) << 8) | (max_irr << 24);

	vapic = kmap_atomic(vcpu->arch.apic->vapic_page, KM_USER0);
	*(u32 *)(vapic + offset_in_page(vcpu->arch.apic->vapic_addr)) = data;
	kunmap_atomic(vapic, KM_USER0);
}

void kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
{
	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	vcpu->arch.apic->vapic_addr = vapic_addr;
	kvm_write_guest_cached(vcpu->kvm, &vcpu->arch.apic->vapic_cache, &data,
				sizeof(u32));
}

int kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
{
	if (vapic_addr) {
		if (kvm_gfn_to_hva_cache_init(vcpu->kvm,
					&vcpu->arch.apic->vapic_cache,
					vapic_addr, sizeof(u32)))
			return -EINVAL;
		__set_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
	} else {
		__clear_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
	}

	vcpu->arch.apic->vapic_addr = vapic_addr;
	return 0;
}

int kvm_x2apic_msr_write(struct kvm_vcpu *vcpu, u32 msr, u64 data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 reg = (msr - APIC_BASE_MSR) << 4;

	if (!lapic_in_kernel(vcpu) || !apic_x2apic_mode(apic))
		return 1;

	if (reg == APIC_ICR2)
		return 1;

	/* if this is ICR write vector before command */
	if (reg == APIC_ICR)
		kvm_lapic_reg_write(apic, APIC_ICR2, (u32)(data >> 32));
	return kvm_lapic_reg_write(apic, reg, (u32)data);
}

int kvm_x2apic_msr_read(struct kvm_vcpu *vcpu, u32 msr, u64 *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 reg = (msr - APIC_BASE_MSR) << 4, low, high = 0;

	if (!lapic_in_kernel(vcpu) || !apic_x2apic_mode(apic))
		return 1;

	if (reg == APIC_DFR || reg == APIC_ICR2) {
		apic_debug("KVM_APIC_READ: read x2apic reserved register %x\n",
			   reg);
		return 1;
	}

	if (kvm_lapic_reg_read(apic, reg, 4, &low))
		return 1;
	if (reg == APIC_ICR)
		kvm_lapic_reg_read(apic, APIC_ICR2, 4, &high);

	*data = (((u64)high) << 32) | low;

	return 0;
}

int kvm_hv_vapic_msr_write(struct kvm_vcpu *vcpu, u32 reg, u64 data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!lapic_in_kernel(vcpu))
		return 1;

	/* if this is ICR write vector before command */
	if (reg == APIC_ICR)
		kvm_lapic_reg_write(apic, APIC_ICR2, (u32)(data >> 32));
	return kvm_lapic_reg_write(apic, reg, (u32)data);
}

int kvm_hv_vapic_msr_read(struct kvm_vcpu *vcpu, u32 reg, u64 *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 low, high = 0;

	if (!lapic_in_kernel(vcpu))
		return 1;

	if (kvm_lapic_reg_read(apic, reg, 4, &low))
		return 1;
	if (reg == APIC_ICR)
		kvm_lapic_reg_read(apic, APIC_ICR2, 4, &high);

	*data = (((u64)high) << 32) | low;

	return 0;
}

int kvm_lapic_enable_pv_eoi(struct kvm_vcpu *vcpu, u64 data)
{
	u64 addr = data & ~KVM_MSR_ENABLED;
	if (!IS_ALIGNED(addr, 4))
		return 1;

	vcpu->arch.pv_eoi.msr_val = data;
	if (!pv_eoi_enabled(vcpu))
		return 0;
	return kvm_gfn_to_hva_cache_init(vcpu->kvm, &vcpu->arch.pv_eoi.data,
					 addr, sizeof(u8));
}

void kvm_apic_accept_events(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u8 sipi_vector;
	unsigned long pe;

	if (!lapic_in_kernel(vcpu) || !apic->pending_events)
		return;

	/*
	 * INITs are latched while in SMM.  Because an SMM CPU cannot
	 * be in KVM_MP_STATE_INIT_RECEIVED state, just eat SIPIs
	 * and delay processing of INIT until the next RSM.
	 */
	if (is_smm(vcpu)) {
		WARN_ON_ONCE(vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED);
		if (test_bit(KVM_APIC_SIPI, &apic->pending_events))
			clear_bit(KVM_APIC_SIPI, &apic->pending_events);
		return;
	}

	pe = xchg(&apic->pending_events, 0);
	if (test_bit(KVM_APIC_INIT, &pe)) {
		kvm_lapic_reset(vcpu, true);
		kvm_vcpu_reset(vcpu, true);
		if (kvm_vcpu_is_bsp(apic->vcpu))
			vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
		else
			vcpu->arch.mp_state = KVM_MP_STATE_INIT_RECEIVED;
	}
	if (test_bit(KVM_APIC_SIPI, &pe) &&
	    vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED) {
		/* evaluate pending_events before reading the vector */
		smp_rmb();
		sipi_vector = apic->sipi_vector;
		apic_debug("vcpu %d received sipi with vector # %x\n",
			 vcpu->vcpu_id, sipi_vector);
		kvm_vcpu_deliver_sipi_vector(vcpu, sipi_vector);
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	}
}

void kvm_lapic_init(void)
{
	/* do not patch jump label more than once per second */
	jump_label_rate_limit(&apic_hw_disabled, HZ);
	jump_label_rate_limit(&apic_sw_disabled, HZ);
}

void kvm_lapic_exit(void)
{
	static_key_deferred_flush(&apic_hw_disabled);
	static_key_deferred_flush(&apic_sw_disabled);
}
