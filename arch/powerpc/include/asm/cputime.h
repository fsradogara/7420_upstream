/*
 * Definitions for measuring cputime on powerpc machines.
 *
 * Copyright (C) 2006 Paul Mackerras, IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * If we have CONFIG_VIRT_CPU_ACCOUNTING, we measure cpu time in
 * If we have CONFIG_VIRT_CPU_ACCOUNTING_NATIVE, we measure cpu time in
 * the same units as the timebase.  Otherwise we measure cpu time
 * in jiffies using the generic definitions.
 */

#ifndef __POWERPC_CPUTIME_H
#define __POWERPC_CPUTIME_H

#ifndef CONFIG_VIRT_CPU_ACCOUNTING
#include <asm-generic/cputime.h>
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
#include <asm-generic/cputime.h>
#ifdef __KERNEL__
static inline void setup_cputime_one_jiffy(void) { }
#endif
#else
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE

#include <linux/types.h>
#include <linux/time.h>
#include <asm/div64.h>
#include <asm/time.h>
#include <asm/param.h>

typedef u64 cputime_t;
typedef u64 cputime64_t;

#define cputime_zero			((cputime_t)0)
#define cputime_max			((~((cputime_t)0) >> 1) - 1)
#define cputime_add(__a, __b)		((__a) +  (__b))
#define cputime_sub(__a, __b)		((__a) -  (__b))
#define cputime_div(__a, __n)		((__a) /  (__n))
#define cputime_halve(__a)		((__a) >> 1)
#define cputime_eq(__a, __b)		((__a) == (__b))
#define cputime_gt(__a, __b)		((__a) >  (__b))
#define cputime_ge(__a, __b)		((__a) >= (__b))
#define cputime_lt(__a, __b)		((__a) <  (__b))
#define cputime_le(__a, __b)		((__a) <= (__b))

#define cputime64_zero			((cputime64_t)0)
#define cputime64_add(__a, __b)		((__a) + (__b))
#define cputime64_sub(__a, __b)		((__a) - (__b))
#define cputime_to_cputime64(__ct)	(__ct)
typedef u64 __nocast cputime_t;
typedef u64 __nocast cputime64_t;

#define cmpxchg_cputime(ptr, old, new) cmpxchg(ptr, old, new)

#ifdef __KERNEL__

/*
 * One jiffy in timebase units computed during initialization
 */
extern cputime_t cputime_one_jiffy;

/*
 * Convert cputime <-> jiffies
 */
extern u64 __cputime_jiffies_factor;
DECLARE_PER_CPU(unsigned long, cputime_last_delta);
DECLARE_PER_CPU(unsigned long, cputime_scaled_last_delta);

static inline unsigned long cputime_to_jiffies(const cputime_t ct)
{
	return mulhdu(ct, __cputime_jiffies_factor);
	return mulhdu((__force u64) ct, __cputime_jiffies_factor);
}

/* Estimate the scaled cputime by scaling the real cputime based on
 * the last scaled to real ratio */
static inline cputime_t cputime_to_scaled(const cputime_t ct)
{
	if (cpu_has_feature(CPU_FTR_SPURR) &&
	    per_cpu(cputime_last_delta, smp_processor_id()))
		return ct *
			per_cpu(cputime_scaled_last_delta, smp_processor_id())/
			per_cpu(cputime_last_delta, smp_processor_id());
	    __this_cpu_read(cputime_last_delta))
		return (__force u64) ct *
			__this_cpu_read(cputime_scaled_last_delta) /
			__this_cpu_read(cputime_last_delta);
	return ct;
}

static inline cputime_t jiffies_to_cputime(const unsigned long jif)
{
	cputime_t ct;
	u64 ct;
	unsigned long sec;

	/* have to be a little careful about overflow */
	ct = jif % HZ;
	sec = jif / HZ;
	if (ct) {
		ct *= tb_ticks_per_sec;
		do_div(ct, HZ);
	}
	if (sec)
		ct += (cputime_t) sec * tb_ticks_per_sec;
	return ct;
	return (__force cputime_t) ct;
}

static inline void setup_cputime_one_jiffy(void)
{
	cputime_one_jiffy = jiffies_to_cputime(1);
}

static inline cputime64_t jiffies64_to_cputime64(const u64 jif)
{
	cputime_t ct;
	u64 ct;
	u64 sec;

	/* have to be a little careful about overflow */
	ct = jif % HZ;
	sec = jif / HZ;
	if (ct) {
		ct *= tb_ticks_per_sec;
		do_div(ct, HZ);
	}
	if (sec)
		ct += (cputime_t) sec * tb_ticks_per_sec;
	return ct;
		ct += (u64) sec * tb_ticks_per_sec;
	return (__force cputime64_t) ct;
}

static inline u64 cputime64_to_jiffies64(const cputime_t ct)
{
	return mulhdu(ct, __cputime_jiffies_factor);
}

/*
 * Convert cputime <-> milliseconds
 */
extern u64 __cputime_msec_factor;

static inline unsigned long cputime_to_msecs(const cputime_t ct)
{
	return mulhdu(ct, __cputime_msec_factor);
}

static inline cputime_t msecs_to_cputime(const unsigned long ms)
{
	cputime_t ct;
	unsigned long sec;

	/* have to be a little careful about overflow */
	ct = ms % 1000;
	sec = ms / 1000;
	if (ct) {
		ct *= tb_ticks_per_sec;
		do_div(ct, 1000);
	}
	if (sec)
		ct += (cputime_t) sec * tb_ticks_per_sec;
	return ct;
}

	return mulhdu((__force u64) ct, __cputime_jiffies_factor);
}

/*
 * Convert cputime <-> microseconds
 */
extern u64 __cputime_usec_factor;

static inline unsigned long cputime_to_usecs(const cputime_t ct)
{
	return mulhdu((__force u64) ct, __cputime_usec_factor);
}

/*
 * PPC64 uses PACA which is task independent for storing accounting data while
 * PPC32 uses struct thread_info, therefore at task switch the accounting data
 * has to be populated in the new task
 */
extern u64 __cputime_sec_factor;

static inline unsigned long cputime_to_secs(const cputime_t ct)
{
	return mulhdu(ct, __cputime_sec_factor);
	return mulhdu((__force u64) ct, __cputime_sec_factor);
}

static inline cputime_t secs_to_cputime(const unsigned long sec)
{
	return (cputime_t) sec * tb_ticks_per_sec;
	return (__force cputime_t)((u64) sec * tb_ticks_per_sec);
}

/*
 * Convert cputime <-> timespec
 */
static inline void cputime_to_timespec(const cputime_t ct, struct timespec *p)
{
	u64 x = ct;
	u64 x = (__force u64) ct;
	unsigned int frac;

	frac = do_div(x, tb_ticks_per_sec);
	p->tv_sec = x;
	x = (u64) frac * 1000000000;
	do_div(x, tb_ticks_per_sec);
	p->tv_nsec = x;
}

static inline cputime_t timespec_to_cputime(const struct timespec *p)
{
	cputime_t ct;

	ct = (u64) p->tv_nsec * tb_ticks_per_sec;
	do_div(ct, 1000000000);
	return ct + (u64) p->tv_sec * tb_ticks_per_sec;
	u64 ct;

	ct = (u64) p->tv_nsec * tb_ticks_per_sec;
	do_div(ct, 1000000000);
	return (__force cputime_t)(ct + (u64) p->tv_sec * tb_ticks_per_sec);
}

/*
 * Convert cputime <-> timeval
 */
static inline void cputime_to_timeval(const cputime_t ct, struct timeval *p)
{
	u64 x = ct;
	u64 x = (__force u64) ct;
	unsigned int frac;

	frac = do_div(x, tb_ticks_per_sec);
	p->tv_sec = x;
	x = (u64) frac * 1000000;
	do_div(x, tb_ticks_per_sec);
	p->tv_usec = x;
}

static inline cputime_t timeval_to_cputime(const struct timeval *p)
{
	cputime_t ct;

	ct = (u64) p->tv_usec * tb_ticks_per_sec;
	do_div(ct, 1000000);
	return ct + (u64) p->tv_sec * tb_ticks_per_sec;
	u64 ct;

	ct = (u64) p->tv_usec * tb_ticks_per_sec;
	do_div(ct, 1000000);
	return (__force cputime_t)(ct + (u64) p->tv_sec * tb_ticks_per_sec);
}

/*
 * Convert cputime <-> clock_t (units of 1/USER_HZ seconds)
 */
extern u64 __cputime_clockt_factor;

static inline unsigned long cputime_to_clock_t(const cputime_t ct)
{
	return mulhdu(ct, __cputime_clockt_factor);
	return mulhdu((__force u64) ct, __cputime_clockt_factor);
}

static inline cputime_t clock_t_to_cputime(const unsigned long clk)
{
	cputime_t ct;
	u64 ct;
	unsigned long sec;

	/* have to be a little careful about overflow */
	ct = clk % USER_HZ;
	sec = clk / USER_HZ;
	if (ct) {
		ct *= tb_ticks_per_sec;
		do_div(ct, USER_HZ);
	}
	if (sec)
		ct += (cputime_t) sec * tb_ticks_per_sec;
	return ct;
		ct += (u64) sec * tb_ticks_per_sec;
	return (__force cputime_t) ct;
}

#define cputime64_to_clock_t(ct)	cputime_to_clock_t((cputime_t)(ct))

#endif /* __KERNEL__ */
#endif /* CONFIG_VIRT_CPU_ACCOUNTING */
#ifdef CONFIG_PPC64
#define get_accounting(tsk)	(&get_paca()->accounting)
static inline void arch_vtime_task_switch(struct task_struct *tsk) { }
#else
#define get_accounting(tsk)	(&task_thread_info(tsk)->accounting)
/*
 * Called from the context switch with interrupts disabled, to charge all
 * accumulated times to the current process, and to prepare accounting on
 * the next process.
 */
static inline void arch_vtime_task_switch(struct task_struct *prev)
{
	struct cpu_accounting_data *acct = get_accounting(current);
	struct cpu_accounting_data *acct0 = get_accounting(prev);

	acct->starttime = acct0->starttime;
	acct->startspurr = acct0->startspurr;
}
#endif

#endif /* __KERNEL__ */
#endif /* CONFIG_VIRT_CPU_ACCOUNTING_NATIVE */
#endif /* __POWERPC_CPUTIME_H */
