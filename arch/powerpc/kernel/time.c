/*
 * Common time routines among all ppc machines.
 *
 * Written by Cort Dougan (cort@cs.nmt.edu) to merge
 * Paul Mackerras' version and mine for PReP and Pmac.
 * MPC8xx/MBX changes by Dan Malek (dmalek@jlc.net).
 * Converted for 64-bit by Mike Corrigan (mikejc@us.ibm.com)
 *
 * First round of bugfixes by Gabriel Paubert (paubert@iram.es)
 * to make clock more stable (2.4.0-test5). The only thing
 * that this code assumes is that the timebases have been synchronized
 * by firmware on SMP and are never stopped (never do sleep
 * on SMP then, nap and doze are OK).
 * 
 * Speeded up do_gettimeofday by getting rid of references to
 * xtime (which required locks for consistency). (mikejc@us.ibm.com)
 *
 * TODO (not necessarily in this file):
 * - improve precision and reproducibility of timebase frequency
 * measurement at boot time. (for iSeries, we calibrate the timebase
 * against the Titan chip's clock.)
 * measurement at boot time.
 * - for astronomical applications: add a new function to get
 * non ambiguous timestamps even around leap seconds. This needs
 * a new timestamp format and a good name.
 *
 * 1997-09-10  Updated NTP code according to technical memorandum Jan '96
 *             "A Kernel Model for Precision Timekeeping" by Dave Mills
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/timex.h>
#include <linux/kernel_stat.h>
#include <linux/time.h>
#include <linux/clockchips.h>
#include <linux/init.h>
#include <linux/profile.h>
#include <linux/cpu.h>
#include <linux/security.h>
#include <linux/percpu.h>
#include <linux/rtc.h>
#include <linux/jiffies.h>
#include <linux/posix-timers.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/irq_work.h>
#include <linux/clk-provider.h>
#include <linux/suspend.h>
#include <linux/rtc.h>
#include <linux/sched/cputime.h>
#include <linux/processor.h>
#include <asm/trace.h>

#include <asm/io.h>
#include <asm/nvram.h>
#include <asm/cache.h>
#include <asm/machdep.h>
#include <linux/uaccess.h>
#include <asm/time.h>
#include <asm/prom.h>
#include <asm/irq.h>
#include <asm/div64.h>
#include <asm/smp.h>
#include <asm/vdso_datapage.h>
#include <asm/firmware.h>
#include <asm/cputime.h>
#ifdef CONFIG_PPC_ISERIES
#include <asm/iseries/it_lp_queue.h>
#include <asm/iseries/hv_call_xm.h>
#endif
#include <asm/asm-prototypes.h>

/* powerpc clocksource/clockevent code */

#include <linux/clockchips.h>
#include <linux/clocksource.h>

static cycle_t rtc_read(void);
#include <linux/timekeeper_internal.h>

static u64 rtc_read(struct clocksource *);
static struct clocksource clocksource_rtc = {
	.name         = "rtc",
	.rating       = 400,
	.flags        = CLOCK_SOURCE_IS_CONTINUOUS,
	.mask         = CLOCKSOURCE_MASK(64),
	.shift        = 22,
	.mult         = 0,	/* To be filled in */
	.read         = rtc_read,
};

static cycle_t timebase_read(void);
	.read         = rtc_read,
};

static u64 timebase_read(struct clocksource *);
static struct clocksource clocksource_timebase = {
	.name         = "timebase",
	.rating       = 400,
	.flags        = CLOCK_SOURCE_IS_CONTINUOUS,
	.mask         = CLOCKSOURCE_MASK(64),
	.shift        = 22,
	.mult         = 0,	/* To be filled in */
	.read         = timebase_read,
};

#define DECREMENTER_DEFAULT_MAX 0x7FFFFFFF
u64 decrementer_max = DECREMENTER_DEFAULT_MAX;

static int decrementer_set_next_event(unsigned long evt,
				      struct clock_event_device *dev);
static void decrementer_set_mode(enum clock_event_mode mode,
				 struct clock_event_device *dev);

static struct clock_event_device decrementer_clockevent = {
       .name           = "decrementer",
       .rating         = 200,
       .shift          = 16,
       .mult           = 0,	/* To be filled in */
       .irq            = 0,
       .set_next_event = decrementer_set_next_event,
       .set_mode       = decrementer_set_mode,
       .features       = CLOCK_EVT_FEAT_ONESHOT,
};

struct decrementer_clock {
	struct clock_event_device event;
	u64 next_tb;
};

static DEFINE_PER_CPU(struct decrementer_clock, decrementers);

#ifdef CONFIG_PPC_ISERIES
static unsigned long __initdata iSeries_recal_titan;
static signed long __initdata iSeries_recal_tb;

/* Forward declaration is only needed for iSereis compiles */
static void __init clocksource_init(void);
#endif
static int decrementer_shutdown(struct clock_event_device *evt);

struct clock_event_device decrementer_clockevent = {
	.name			= "decrementer",
	.rating			= 200,
	.irq			= 0,
	.set_next_event		= decrementer_set_next_event,
	.set_state_shutdown	= decrementer_shutdown,
	.tick_resume		= decrementer_shutdown,
	.features		= CLOCK_EVT_FEAT_ONESHOT |
				  CLOCK_EVT_FEAT_C3STOP,
};
EXPORT_SYMBOL(decrementer_clockevent);

DEFINE_PER_CPU(u64, decrementers_next_tb);
static DEFINE_PER_CPU(struct clock_event_device, decrementers);

#define XSEC_PER_SEC (1024*1024)

#ifdef CONFIG_PPC64
#define SCALE_XSEC(xsec, max)	(((xsec) * max) / XSEC_PER_SEC)
#else
/* compute ((xsec << 12) * max) >> 32 */
#define SCALE_XSEC(xsec, max)	mulhwu((xsec) << 12, max)
#endif

unsigned long tb_ticks_per_jiffy;
unsigned long tb_ticks_per_usec = 100; /* sane default */
EXPORT_SYMBOL(tb_ticks_per_usec);
unsigned long tb_ticks_per_sec;
EXPORT_SYMBOL(tb_ticks_per_sec);	/* for cputime_t conversions */
u64 tb_to_xs;
unsigned tb_to_us;

#define TICKLEN_SCALE	NTP_SCALE_SHIFT
static u64 last_tick_len;	/* units are ns / 2^TICKLEN_SCALE */
static u64 ticklen_to_xs;	/* 0.64 fraction */

/* If last_tick_len corresponds to about 1/HZ seconds, then
   last_tick_len << TICKLEN_SHIFT will be about 2^63. */
#define TICKLEN_SHIFT	(63 - 30 - TICKLEN_SCALE + SHIFT_HZ)

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL_GPL(rtc_lock);

static u64 tb_to_ns_scale __read_mostly;
static unsigned tb_to_ns_shift __read_mostly;
static unsigned long boot_tb __read_mostly;

static struct gettimeofday_struct do_gtod;
static u64 boot_tb __read_mostly;

extern struct timezone sys_tz;
static long timezone_offset;

unsigned long ppc_proc_freq;
EXPORT_SYMBOL(ppc_proc_freq);
unsigned long ppc_tb_freq;

static u64 tb_last_jiffy __cacheline_aligned_in_smp;
static DEFINE_PER_CPU(u64, last_jiffy);

#ifdef CONFIG_VIRT_CPU_ACCOUNTING
/*
 * Factors for converting from cputime_t (timebase ticks) to
 * jiffies, milliseconds, seconds, and clock_t (1/USER_HZ seconds).
EXPORT_SYMBOL_GPL(ppc_proc_freq);
unsigned long ppc_tb_freq;
EXPORT_SYMBOL_GPL(ppc_tb_freq);

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
/*
 * Factor for converting from cputime_t (timebase ticks) to
 * microseconds. This is stored as 0.64 fixed-point binary fraction.
 */
u64 __cputime_jiffies_factor;
EXPORT_SYMBOL(__cputime_jiffies_factor);
u64 __cputime_msec_factor;
EXPORT_SYMBOL(__cputime_msec_factor);
u64 __cputime_usec_factor;
EXPORT_SYMBOL(__cputime_usec_factor);

#ifdef CONFIG_PPC_SPLPAR
void (*dtl_consumer)(struct dtl_entry *, u64);
#endif

static void calc_cputime_factors(void)
{
	struct div_result res;

	div128_by_32(HZ, 0, tb_ticks_per_sec, &res);
	__cputime_jiffies_factor = res.result_low;
	div128_by_32(1000, 0, tb_ticks_per_sec, &res);
	__cputime_msec_factor = res.result_low;
	div128_by_32(1000000, 0, tb_ticks_per_sec, &res);
	__cputime_usec_factor = res.result_low;
}

/*
 * Read the PURR on systems that have it, otherwise the timebase.
 */
static u64 read_purr(void)
{
	if (cpu_has_feature(CPU_FTR_PURR))
		return mfspr(SPRN_PURR);
	return mftb();
}

/*
 * Read the SPURR on systems that have it, otherwise the purr
 */
static u64 read_spurr(u64 purr)
{
	/*
	 * cpus without PURR won't have a SPURR
	 * We already know the former when we use this, so tell gcc
	 */
	if (cpu_has_feature(CPU_FTR_PURR) && cpu_has_feature(CPU_FTR_SPURR))
		return mfspr(SPRN_SPURR);
	return purr;
}

 * Read the SPURR on systems that have it, otherwise the PURR,
 * or if that doesn't exist return the timebase value passed in.
 */
static unsigned long read_spurr(unsigned long tb)
{
	if (cpu_has_feature(CPU_FTR_SPURR))
		return mfspr(SPRN_SPURR);
	if (cpu_has_feature(CPU_FTR_PURR))
		return mfspr(SPRN_PURR);
	return tb;
}

#ifdef CONFIG_PPC_SPLPAR

/*
 * Scan the dispatch trace log and count up the stolen time.
 * Should be called with interrupts disabled.
 */
static u64 scan_dispatch_log(u64 stop_tb)
{
	u64 i = local_paca->dtl_ridx;
	struct dtl_entry *dtl = local_paca->dtl_curr;
	struct dtl_entry *dtl_end = local_paca->dispatch_log_end;
	struct lppaca *vpa = local_paca->lppaca_ptr;
	u64 tb_delta;
	u64 stolen = 0;
	u64 dtb;

	if (!dtl)
		return 0;

	if (i == be64_to_cpu(vpa->dtl_idx))
		return 0;
	while (i < be64_to_cpu(vpa->dtl_idx)) {
		dtb = be64_to_cpu(dtl->timebase);
		tb_delta = be32_to_cpu(dtl->enqueue_to_dispatch_time) +
			be32_to_cpu(dtl->ready_to_enqueue_time);
		barrier();
		if (i + N_DISPATCH_LOG < be64_to_cpu(vpa->dtl_idx)) {
			/* buffer has overflowed */
			i = be64_to_cpu(vpa->dtl_idx) - N_DISPATCH_LOG;
			dtl = local_paca->dispatch_log + (i % N_DISPATCH_LOG);
			continue;
		}
		if (dtb > stop_tb)
			break;
		if (dtl_consumer)
			dtl_consumer(dtl, i);
		stolen += tb_delta;
		++i;
		++dtl;
		if (dtl == dtl_end)
			dtl = local_paca->dispatch_log;
	}
	local_paca->dtl_ridx = i;
	local_paca->dtl_curr = dtl;
	return stolen;
}

/*
 * Accumulate stolen time by scanning the dispatch trace log.
 * Called on entry from user mode.
 */
void accumulate_stolen_time(void)
{
	u64 sst, ust;
	unsigned long save_irq_soft_mask = irq_soft_mask_return();
	struct cpu_accounting_data *acct = &local_paca->accounting;

	/* We are called early in the exception entry, before
	 * soft/hard_enabled are sync'ed to the expected state
	 * for the exception. We are hard disabled but the PACA
	 * needs to reflect that so various debug stuff doesn't
	 * complain
	 */
	irq_soft_mask_set(IRQS_DISABLED);

	sst = scan_dispatch_log(acct->starttime_user);
	ust = scan_dispatch_log(acct->starttime);
	acct->stime -= sst;
	acct->utime -= ust;
	acct->steal_time += ust + sst;

	irq_soft_mask_set(save_irq_soft_mask);
}

static inline u64 calculate_stolen_time(u64 stop_tb)
{
	if (!firmware_has_feature(FW_FEATURE_SPLPAR))
		return 0;

	if (get_paca()->dtl_ridx != be64_to_cpu(get_lppaca()->dtl_idx))
		return scan_dispatch_log(stop_tb);

	return 0;
}

#else /* CONFIG_PPC_SPLPAR */
static inline u64 calculate_stolen_time(u64 stop_tb)
{
	return 0;
}

#endif /* CONFIG_PPC_SPLPAR */

/*
 * Account time for a transition between system, hard irq
 * or soft irq state.
 */
void account_system_vtime(struct task_struct *tsk)
{
	u64 now, nowscaled, delta, deltascaled, sys_time;
	unsigned long flags;

	local_irq_save(flags);
	now = read_purr();
	nowscaled = read_spurr(now);
	delta = now - get_paca()->startpurr;
	deltascaled = nowscaled - get_paca()->startspurr;
	get_paca()->startpurr = now;
	get_paca()->startspurr = nowscaled;
	if (!in_interrupt()) {
		/* deltascaled includes both user and system time.
		 * Hence scale it based on the purr ratio to estimate
		 * the system time */
		sys_time = get_paca()->system_time;
		if (get_paca()->user_time)
			deltascaled = deltascaled * sys_time /
			     (sys_time + get_paca()->user_time);
		delta += sys_time;
		get_paca()->system_time = 0;
	}
	account_system_time(tsk, 0, delta);
	account_system_time_scaled(tsk, deltascaled);
	per_cpu(cputime_last_delta, smp_processor_id()) = delta;
	per_cpu(cputime_scaled_last_delta, smp_processor_id()) = deltascaled;
	local_irq_restore(flags);
}

/*
 * Transfer the user and system times accumulated in the paca
 * by the exception entry and exit code to the generic process
 * user and system time records.
 * Must be called with interrupts disabled.
 */
void account_process_tick(struct task_struct *tsk, int user_tick)
static u64 vtime_delta(struct task_struct *tsk,
			u64 *sys_scaled, u64 *stolen)
static unsigned long vtime_delta(struct task_struct *tsk,
				 unsigned long *stime_scaled,
				 unsigned long *steal_time)
{
	unsigned long now, nowscaled, deltascaled;
	unsigned long stime;
	unsigned long utime, utime_scaled;
	struct cpu_accounting_data *acct = get_accounting(tsk);

	WARN_ON_ONCE(!irqs_disabled());

	now = mftb();
	nowscaled = read_spurr(now);
	stime = now - acct->starttime;
	acct->starttime = now;
	deltascaled = nowscaled - acct->startspurr;
	acct->startspurr = nowscaled;

	*steal_time = calculate_stolen_time(now);

	utime = acct->utime - acct->utime_sspurr;
	acct->utime_sspurr = acct->utime;

	/*
	 * Because we don't read the SPURR on every kernel entry/exit,
	 * deltascaled includes both user and system SPURR ticks.
	 * Apportion these ticks to system SPURR ticks and user
	 * SPURR ticks in the same ratio as the system time (delta)
	 * and user time (udelta) values obtained from the timebase
	 * over the same interval.  The system ticks get accounted here;
	 * the user ticks get saved up in paca->user_time_scaled to be
	 * used by account_process_tick.
	 */
	*stime_scaled = stime;
	utime_scaled = utime;
	if (deltascaled != stime + utime) {
		if (utime) {
			*stime_scaled = deltascaled * stime / (stime + utime);
			utime_scaled = deltascaled - *stime_scaled;
		} else {
			*stime_scaled = deltascaled;
		}
	}
	acct->utime_scaled += utime_scaled;

	return stime;
}

void vtime_account_system(struct task_struct *tsk)
{
	unsigned long stime, stime_scaled, steal_time;
	struct cpu_accounting_data *acct = get_accounting(tsk);

	stime = vtime_delta(tsk, &stime_scaled, &steal_time);

	stime -= min(stime, steal_time);
	acct->steal_time += steal_time;

	if ((tsk->flags & PF_VCPU) && !irq_count()) {
		acct->gtime += stime;
		acct->utime_scaled += stime_scaled;
	} else {
		if (hardirq_count())
			acct->hardirq_time += stime;
		else if (in_serving_softirq())
			acct->softirq_time += stime;
		else
			acct->stime += stime;

		acct->stime_scaled += stime_scaled;
	}
}
EXPORT_SYMBOL_GPL(vtime_account_system);

void vtime_account_idle(struct task_struct *tsk)
{
	unsigned long stime, stime_scaled, steal_time;
	struct cpu_accounting_data *acct = get_accounting(tsk);

	stime = vtime_delta(tsk, &stime_scaled, &steal_time);
	acct->idle_time += stime + steal_time;
}

/*
 * Account the whole cputime accumulated in the paca
 * Must be called with interrupts disabled.
 * Assumes that vtime_account_system/idle() has been called
 * recently (i.e. since the last entry from usermode) so that
 * get_paca()->user_time_scaled is up to date.
 */
void vtime_flush(struct task_struct *tsk)
{
	struct cpu_accounting_data *acct = get_accounting(tsk);

	utime = get_paca()->user_time;
	get_paca()->user_time = 0;
	account_user_time(tsk, utime);

	utimescaled = cputime_to_scaled(utime);
	account_user_time_scaled(tsk, utimescaled);
}

/*
 * Stuff for accounting stolen time.
 */
struct cpu_purr_data {
	int	initialized;			/* thread is running */
	u64	tb;			/* last TB value read */
	u64	purr;			/* last PURR value read */
	u64	spurr;			/* last SPURR value read */
};

/*
 * Each entry in the cpu_purr_data array is manipulated only by its
 * "owner" cpu -- usually in the timer interrupt but also occasionally
 * in process context for cpu online.  As long as cpus do not touch
 * each others' cpu_purr_data, disabling local interrupts is
 * sufficient to serialize accesses.
 */
static DEFINE_PER_CPU(struct cpu_purr_data, cpu_purr_data);

static void snapshot_tb_and_purr(void *data)
{
	unsigned long flags;
	struct cpu_purr_data *p = &__get_cpu_var(cpu_purr_data);

	local_irq_save(flags);
	p->tb = get_tb_or_rtc();
	p->purr = mfspr(SPRN_PURR);
	wmb();
	p->initialized = 1;
	local_irq_restore(flags);
}

/*
 * Called during boot when all cpus have come up.
 */
void snapshot_timebases(void)
{
	if (!cpu_has_feature(CPU_FTR_PURR))
		return;
	on_each_cpu(snapshot_tb_and_purr, NULL, 1);
}

/*
 * Must be called with interrupts disabled.
 */
void calculate_steal_time(void)
{
	u64 tb, purr;
	s64 stolen;
	struct cpu_purr_data *pme;

	pme = &__get_cpu_var(cpu_purr_data);
	if (!pme->initialized)
		return;		/* !CPU_FTR_PURR or early in early boot */
	tb = mftb();
	purr = mfspr(SPRN_PURR);
	stolen = (tb - pme->tb) - (purr - pme->purr);
	if (stolen > 0)
		account_steal_time(current, stolen);
	pme->tb = tb;
	pme->purr = purr;
}

#ifdef CONFIG_PPC_SPLPAR
/*
 * Must be called before the cpu is added to the online map when
 * a cpu is being brought up at runtime.
 */
static void snapshot_purr(void)
{
	struct cpu_purr_data *pme;
	unsigned long flags;

	if (!cpu_has_feature(CPU_FTR_PURR))
		return;
	local_irq_save(flags);
	pme = &__get_cpu_var(cpu_purr_data);
	pme->tb = mftb();
	pme->purr = mfspr(SPRN_PURR);
	pme->initialized = 1;
	local_irq_restore(flags);
}

#endif /* CONFIG_PPC_SPLPAR */

#else /* ! CONFIG_VIRT_CPU_ACCOUNTING */
#define calc_cputime_factors()
#define calculate_steal_time()		do { } while (0)
#endif

#if !(defined(CONFIG_VIRT_CPU_ACCOUNTING) && defined(CONFIG_PPC_SPLPAR))
#define snapshot_purr()			do { } while (0)
#endif

/*
 * Called when a cpu comes up after the system has finished booting,
 * i.e. as a result of a hotplug cpu action.
 */
void snapshot_timebase(void)
{
	__get_cpu_var(last_jiffy) = get_tb_or_rtc();
	snapshot_purr();
}

	utimescaled = get_paca()->user_time_scaled;
	get_paca()->user_time = 0;
	get_paca()->user_time_scaled = 0;
	get_paca()->utime_sspurr = 0;
	account_user_time(tsk, utime, utimescaled);
	if (acct->utime)
		account_user_time(tsk, cputime_to_nsecs(acct->utime));

	if (acct->utime_scaled)
		tsk->utimescaled += cputime_to_nsecs(acct->utime_scaled);

	if (acct->gtime)
		account_guest_time(tsk, cputime_to_nsecs(acct->gtime));

	if (acct->steal_time)
		account_steal_time(cputime_to_nsecs(acct->steal_time));

	if (acct->idle_time)
		account_idle_time(cputime_to_nsecs(acct->idle_time));

	if (acct->stime)
		account_system_index_time(tsk, cputime_to_nsecs(acct->stime),
					  CPUTIME_SYSTEM);
	if (acct->stime_scaled)
		tsk->stimescaled += cputime_to_nsecs(acct->stime_scaled);

	if (acct->hardirq_time)
		account_system_index_time(tsk, cputime_to_nsecs(acct->hardirq_time),
					  CPUTIME_IRQ);
	if (acct->softirq_time)
		account_system_index_time(tsk, cputime_to_nsecs(acct->softirq_time),
					  CPUTIME_SOFTIRQ);

	acct->utime = 0;
	acct->utime_scaled = 0;
	acct->utime_sspurr = 0;
	acct->gtime = 0;
	acct->steal_time = 0;
	acct->idle_time = 0;
	acct->stime = 0;
	acct->stime_scaled = 0;
	acct->hardirq_time = 0;
	acct->softirq_time = 0;
}

#else /* ! CONFIG_VIRT_CPU_ACCOUNTING_NATIVE */
#define calc_cputime_factors()
#endif

void __delay(unsigned long loops)
{
	unsigned long start;
	int diff;

	spin_begin();
	if (__USE_RTC()) {
		start = get_rtcl();
		do {
			/* the RTCL register wraps at 1000000000 */
			diff = get_rtcl() - start;
			if (diff < 0)
				diff += 1000000000;
			spin_cpu_relax();
		} while (diff < loops);
	} else {
		start = get_tbl();
		while (get_tbl() - start < loops)
			spin_cpu_relax();
	}
	spin_end();
}
EXPORT_SYMBOL(__delay);

void udelay(unsigned long usecs)
{
	__delay(tb_ticks_per_usec * usecs);
}
EXPORT_SYMBOL(udelay);


/*
 * There are two copies of tb_to_xs and stamp_xsec so that no
 * lock is needed to access and use these values in
 * do_gettimeofday.  We alternate the copies and as long as a
 * reasonable time elapses between changes, there will never
 * be inconsistent values.  ntpd has a minimum of one minute
 * between updates.
 */
static inline void update_gtod(u64 new_tb_stamp, u64 new_stamp_xsec,
			       u64 new_tb_to_xs)
{
	unsigned temp_idx;
	struct gettimeofday_vars *temp_varp;

	temp_idx = (do_gtod.var_idx == 0);
	temp_varp = &do_gtod.vars[temp_idx];

	temp_varp->tb_to_xs = new_tb_to_xs;
	temp_varp->tb_orig_stamp = new_tb_stamp;
	temp_varp->stamp_xsec = new_stamp_xsec;
	smp_mb();
	do_gtod.varp = temp_varp;
	do_gtod.var_idx = temp_idx;

	/*
	 * tb_update_count is used to allow the userspace gettimeofday code
	 * to assure itself that it sees a consistent view of the tb_to_xs and
	 * stamp_xsec variables.  It reads the tb_update_count, then reads
	 * tb_to_xs and stamp_xsec and then reads tb_update_count again.  If
	 * the two values of tb_update_count match and are even then the
	 * tb_to_xs and stamp_xsec values are consistent.  If not, then it
	 * loops back and reads them again until this criteria is met.
	 * We expect the caller to have done the first increment of
	 * vdso_data->tb_update_count already.
	 */
	vdso_data->tb_orig_stamp = new_tb_stamp;
	vdso_data->stamp_xsec = new_stamp_xsec;
	vdso_data->tb_to_xs = new_tb_to_xs;
	vdso_data->wtom_clock_sec = wall_to_monotonic.tv_sec;
	vdso_data->wtom_clock_nsec = wall_to_monotonic.tv_nsec;
	smp_wmb();
	++(vdso_data->tb_update_count);
}

#ifdef CONFIG_SMP
unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (in_lock_functions(pc))
		return regs->link;

	return pc;
}
EXPORT_SYMBOL(profile_pc);
#endif

#ifdef CONFIG_PPC_ISERIES

/* 
 * This function recalibrates the timebase based on the 49-bit time-of-day
 * value in the Titan chip.  The Titan is much more accurate than the value
 * returned by the service processor for the timebase frequency.  
 */

static int __init iSeries_tb_recal(void)
{
	struct div_result divres;
	unsigned long titan, tb;

	/* Make sure we only run on iSeries */
	if (!firmware_has_feature(FW_FEATURE_ISERIES))
		return -ENODEV;

	tb = get_tb();
	titan = HvCallXm_loadTod();
	if ( iSeries_recal_titan ) {
		unsigned long tb_ticks = tb - iSeries_recal_tb;
		unsigned long titan_usec = (titan - iSeries_recal_titan) >> 12;
		unsigned long new_tb_ticks_per_sec   = (tb_ticks * USEC_PER_SEC)/titan_usec;
		unsigned long new_tb_ticks_per_jiffy = (new_tb_ticks_per_sec+(HZ/2))/HZ;
		long tick_diff = new_tb_ticks_per_jiffy - tb_ticks_per_jiffy;
		char sign = '+';		
		/* make sure tb_ticks_per_sec and tb_ticks_per_jiffy are consistent */
		new_tb_ticks_per_sec = new_tb_ticks_per_jiffy * HZ;

		if ( tick_diff < 0 ) {
			tick_diff = -tick_diff;
			sign = '-';
		}
		if ( tick_diff ) {
			if ( tick_diff < tb_ticks_per_jiffy/25 ) {
				printk( "Titan recalibrate: new tb_ticks_per_jiffy = %lu (%c%ld)\n",
						new_tb_ticks_per_jiffy, sign, tick_diff );
				tb_ticks_per_jiffy = new_tb_ticks_per_jiffy;
				tb_ticks_per_sec   = new_tb_ticks_per_sec;
				calc_cputime_factors();
				div128_by_32( XSEC_PER_SEC, 0, tb_ticks_per_sec, &divres );
				do_gtod.tb_ticks_per_sec = tb_ticks_per_sec;
				tb_to_xs = divres.result_low;
				do_gtod.varp->tb_to_xs = tb_to_xs;
				vdso_data->tb_ticks_per_sec = tb_ticks_per_sec;
				vdso_data->tb_to_xs = tb_to_xs;
			}
			else {
				printk( "Titan recalibrate: FAILED (difference > 4 percent)\n"
					"                   new tb_ticks_per_jiffy = %lu\n"
					"                   old tb_ticks_per_jiffy = %lu\n",
					new_tb_ticks_per_jiffy, tb_ticks_per_jiffy );
			}
		}
	}
	iSeries_recal_titan = titan;
	iSeries_recal_tb = tb;

	/* Called here as now we know accurate values for the timebase */
	clocksource_init();
	return 0;
}
late_initcall(iSeries_tb_recal);

/* Called from platform early init */
void __init iSeries_time_init_early(void)
{
	iSeries_recal_tb = get_tb();
	iSeries_recal_titan = HvCallXm_loadTod();
}
#endif /* CONFIG_PPC_ISERIES */

/*
 * For iSeries shared processors, we have to let the hypervisor
 * set the hardware decrementer.  We set a virtual decrementer
 * in the lppaca and call the hypervisor if the virtual
 * decrementer is less than the current value in the hardware
 * decrementer. (almost always the new decrementer value will
 * be greater than the current hardware decementer so the hypervisor
 * call will not be needed)
 */
#ifdef CONFIG_IRQ_WORK

/*
 * 64-bit uses a byte in the PACA, 32-bit uses a per-cpu variable...
 */
#ifdef CONFIG_PPC64
static inline unsigned long test_irq_work_pending(void)
{
	unsigned long x;

	asm volatile("lbz %0,%1(13)"
		: "=r" (x)
		: "i" (offsetof(struct paca_struct, irq_work_pending)));
	return x;
}

static inline void set_irq_work_pending_flag(void)
{
	asm volatile("stb %0,%1(13)" : :
		"r" (1),
		"i" (offsetof(struct paca_struct, irq_work_pending)));
}

static inline void clear_irq_work_pending(void)
{
	asm volatile("stb %0,%1(13)" : :
		"r" (0),
		"i" (offsetof(struct paca_struct, irq_work_pending)));
}

void arch_irq_work_raise(void)
{
	preempt_disable();
	set_irq_work_pending_flag();
	/*
	 * Non-nmi code running with interrupts disabled will replay
	 * irq_happened before it re-enables interrupts, so setthe
	 * decrementer there instead of causing a hardware exception
	 * which would immediately hit the masked interrupt handler
	 * and have the net effect of setting the decrementer in
	 * irq_happened.
	 *
	 * NMI interrupts can not check this when they return, so the
	 * decrementer hardware exception is raised, which will fire
	 * when interrupts are next enabled.
	 *
	 * BookE does not support this yet, it must audit all NMI
	 * interrupt handlers to ensure they call nmi_enter() so this
	 * check would be correct.
	 */
	if (IS_ENABLED(CONFIG_BOOKE) || !irqs_disabled() || in_nmi()) {
		set_dec(1);
	} else {
		hard_irq_disable();
		local_paca->irq_happened |= PACA_IRQ_DEC;
	}
	preempt_enable();
}

#else /* 32-bit */

DEFINE_PER_CPU(u8, irq_work_pending);

#define set_irq_work_pending_flag()	__this_cpu_write(irq_work_pending, 1)
#define test_irq_work_pending()		__this_cpu_read(irq_work_pending)
#define clear_irq_work_pending()	__this_cpu_write(irq_work_pending, 0)

void arch_irq_work_raise(void)
{
	preempt_disable();
	set_irq_work_pending_flag();
	set_dec(1);
	preempt_enable();
}

#endif /* 32 vs 64 bit */

#else  /* CONFIG_IRQ_WORK */

#define test_irq_work_pending()	0
#define clear_irq_work_pending()

#endif /* CONFIG_IRQ_WORK */

/*
 * timer_interrupt - gets called when the decrementer overflows,
 * with interrupts disabled.
 */
void timer_interrupt(struct pt_regs *regs)
{
	struct clock_event_device *evt = this_cpu_ptr(&decrementers);
	u64 *next_tb = this_cpu_ptr(&decrementers_next_tb);
	struct pt_regs *old_regs;
	u64 now;

	/* Some implementations of hotplug will get timer interrupts while
	 * offline, just ignore these and we also need to set
	 * decrementers_next_tb as MAX to make sure __check_irq_replay
	 * don't replay timer interrupt when return, otherwise we'll trap
	 * here infinitely :(
	 */
	if (unlikely(!cpu_online(smp_processor_id()))) {
		*next_tb = ~(u64)0;
		set_dec(decrementer_max);
		return;
	}

	/* Ensure a positive value is written to the decrementer, or else
	 * some CPUs will continue to take decrementer exceptions. When the
	 * PPC_WATCHDOG (decrementer based) is configured, keep this at most
	 * 31 bits, which is about 4 seconds on most systems, which gives
	 * the watchdog a chance of catching timer interrupt hard lockups.
	 */
	if (IS_ENABLED(CONFIG_PPC_WATCHDOG))
		set_dec(0x7fffffff);
	else
		set_dec(decrementer_max);

	/* Conditionally hard-enable interrupts now that the DEC has been
	 * bumped to its maximum value
	 */
	may_hard_irq_enable();


#if defined(CONFIG_PPC32) && defined(CONFIG_PPC_PMAC)
	if (atomic_read(&ppc_n_lost_interrupts) != 0)
		do_IRQ(regs);
#endif

	old_regs = set_irq_regs(regs);
	irq_enter();
	trace_timer_interrupt_entry(regs);

	if (test_irq_work_pending()) {
		clear_irq_work_pending();
		irq_work_run();
	}

	now = get_tb_or_rtc();
	if (now >= *next_tb) {
		*next_tb = ~(u64)0;
		if (evt->event_handler)
			evt->event_handler(evt);
		__this_cpu_inc(irq_stat.timer_irqs_event);
	} else {
		now = *next_tb - now;
		if (now <= decrementer_max)
			set_dec(now);
		/* We may have raced with new irq work */
		if (test_irq_work_pending())
			set_dec(1);
		__this_cpu_inc(irq_stat.timer_irqs_others);
	}

	trace_timer_interrupt_exit(regs);
}

/*
 * timer_interrupt - gets called when the decrementer overflows,
 * with interrupts disabled.
 */
void timer_interrupt(struct pt_regs * regs)
{
	struct pt_regs *old_regs;
	struct decrementer_clock *decrementer =  &__get_cpu_var(decrementers);
	struct clock_event_device *evt = &decrementer->event;
	u64 now;

	/* Ensure a positive value is written to the decrementer, or else
	 * some CPUs will continuue to take decrementer exceptions */
	set_dec(DECREMENTER_MAX);

#ifdef CONFIG_PPC32
	u64 *next_tb = this_cpu_ptr(&decrementers_next_tb);

	/* Ensure a positive value is written to the decrementer, or else
	 * some CPUs will continue to take decrementer exceptions.
	 */
	set_dec(decrementer_max);

	/* Some implementations of hotplug will get timer interrupts while
	 * offline, just ignore these and we also need to set
	 * decrementers_next_tb as MAX to make sure __check_irq_replay
	 * don't replay timer interrupt when return, otherwise we'll trap
	 * here infinitely :(
	 */
	if (!cpu_online(smp_processor_id())) {
		*next_tb = ~(u64)0;
		return;
	}

	/* Conditionally hard-enable interrupts now that the DEC has been
	 * bumped to its maximum value
	 */
	may_hard_irq_enable();


#if defined(CONFIG_PPC32) && defined(CONFIG_PPC_PMAC)
	if (atomic_read(&ppc_n_lost_interrupts) != 0)
		do_IRQ(regs);
#endif

	now = get_tb_or_rtc();
	if (now < decrementer->next_tb) {
		/* not time for this event yet */
		now = decrementer->next_tb - now;
		if (now <= DECREMENTER_MAX)
			set_dec((int)now);
		return;
	}
	old_regs = set_irq_regs(regs);
	irq_enter();

	calculate_steal_time();

#ifdef CONFIG_PPC_ISERIES
	if (firmware_has_feature(FW_FEATURE_ISERIES))
		get_lppaca()->int_dword.fields.decr_int = 0;
#endif

	if (evt->event_handler)
		evt->event_handler(evt);

#ifdef CONFIG_PPC_ISERIES
	if (firmware_has_feature(FW_FEATURE_ISERIES) && hvlpevent_is_pending())
		process_hvlpevents();
#endif

#ifdef CONFIG_PPC64
	/* collect purr register values often, for accurate calculations */
	if (firmware_has_feature(FW_FEATURE_SPLPAR)) {
		struct cpu_usage *cu = &__get_cpu_var(cpu_usage_array);
		cu->current_tb = mfspr(SPRN_PURR);
	}
#endif

	old_regs = set_irq_regs(regs);
	irq_enter();

	__timer_interrupt();
	irq_exit();
	set_irq_regs(old_regs);
}
EXPORT_SYMBOL(timer_interrupt);

void wakeup_decrementer(void)
{
	unsigned long ticks;

	/*
	 * The timebase gets saved on sleep and restored on wakeup,
	 * so all we need to do is to reset the decrementer.
	 */
	ticks = tb_ticks_since(__get_cpu_var(last_jiffy));
	if (ticks < tb_ticks_per_jiffy)
		ticks = tb_ticks_per_jiffy - ticks;
	else
		ticks = 1;
	set_dec(ticks);
}

#ifdef CONFIG_SUSPEND
void generic_suspend_disable_irqs(void)
{
	preempt_disable();
#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
void timer_broadcast_interrupt(void)
{
	u64 *next_tb = this_cpu_ptr(&decrementers_next_tb);

	*next_tb = ~(u64)0;
	tick_receive_broadcast();
	__this_cpu_inc(irq_stat.broadcast_irqs_event);
}
#endif

/*
 * Hypervisor decrementer interrupts shouldn't occur but are sometimes
 * left pending on exit from a KVM guest.  We don't need to do anything
 * to clear them, as they are edge-triggered.
 */
void hdec_interrupt(struct pt_regs *regs)
{
}

#ifdef CONFIG_SUSPEND
static void generic_suspend_disable_irqs(void)
{
	/* Disable the decrementer, so that it doesn't interfere
	 * with suspending.
	 */

	set_dec(0x7fffffff);
	local_irq_disable();
	set_dec(0x7fffffff);
}

void generic_suspend_enable_irqs(void)
{
	wakeup_decrementer();

	local_irq_enable();
	preempt_enable();
	set_dec(DECREMENTER_MAX);
	set_dec(decrementer_max);
	local_irq_disable();
	set_dec(decrementer_max);
}

static void generic_suspend_enable_irqs(void)
{
	local_irq_enable();
}

/* Overrides the weak version in kernel/power/main.c */
void arch_suspend_disable_irqs(void)
{
	if (ppc_md.suspend_disable_irqs)
		ppc_md.suspend_disable_irqs();
	generic_suspend_disable_irqs();
}

/* Overrides the weak version in kernel/power/main.c */
void arch_suspend_enable_irqs(void)
{
	generic_suspend_enable_irqs();
	if (ppc_md.suspend_enable_irqs)
		ppc_md.suspend_enable_irqs();
}
#endif

#ifdef CONFIG_SMP
void __init smp_space_timers(unsigned int max_cpus)
{
	int i;
	u64 previous_tb = per_cpu(last_jiffy, boot_cpuid);

	/* make sure tb > per_cpu(last_jiffy, cpu) for all cpus always */
	previous_tb -= tb_ticks_per_jiffy;

	for_each_possible_cpu(i) {
		if (i == boot_cpuid)
			continue;
		per_cpu(last_jiffy, i) = previous_tb;
	}
}
#endif
unsigned long long tb_to_ns(unsigned long long ticks)
{
	return mulhdu(ticks, tb_to_ns_scale) << tb_to_ns_shift;
}
EXPORT_SYMBOL_GPL(tb_to_ns);

/*
 * Scheduler clock - returns current time in nanosec units.
 *
 * Note: mulhdu(a, b) (multiply high double unsigned) returns
 * the high 64 bits of a * b, i.e. (a * b) >> 64, where a and b
 * are 64-bit unsigned numbers.
 */
notrace unsigned long long sched_clock(void)
{
	if (__USE_RTC())
		return get_rtc();
	return mulhdu(get_tb() - boot_tb, tb_to_ns_scale) << tb_to_ns_shift;
}

static int __init get_freq(char *name, int cells, unsigned long *val)
{
	struct device_node *cpu;
	const unsigned int *fp;

#ifdef CONFIG_PPC_PSERIES

/*
 * Running clock - attempts to give a view of time passing for a virtualised
 * kernels.
 * Uses the VTB register if available otherwise a next best guess.
 */
unsigned long long running_clock(void)
{
	/*
	 * Don't read the VTB as a host since KVM does not switch in host
	 * timebase into the VTB when it takes a guest off the CPU, reading the
	 * VTB would result in reading 'last switched out' guest VTB.
	 *
	 * Host kernels are often compiled with CONFIG_PPC_PSERIES checked, it
	 * would be unsafe to rely only on the #ifdef above.
	 */
	if (firmware_has_feature(FW_FEATURE_LPAR) &&
	    cpu_has_feature(CPU_FTR_ARCH_207S))
		return mulhdu(get_vtb() - boot_tb, tb_to_ns_scale) << tb_to_ns_shift;

	/*
	 * This is a next best approximation without a VTB.
	 * On a host which is running bare metal there should never be any stolen
	 * time and on a host which doesn't do any virtualisation TB *should* equal
	 * VTB so it makes no difference anyway.
	 */
	return local_clock() - kcpustat_this_cpu->cpustat[CPUTIME_STEAL];
}
#endif

static int __init get_freq(char *name, int cells, unsigned long *val)
{
	struct device_node *cpu;
	const __be32 *fp;
	int found = 0;

	/* The cpu node should have timebase and clock frequency properties */
	cpu = of_find_node_by_type(NULL, "cpu");

	if (cpu) {
		fp = of_get_property(cpu, name, NULL);
		if (fp) {
			found = 1;
			*val = of_read_ulong(fp, cells);
		}

		of_node_put(cpu);
	}

	return found;
}

static void start_cpu_decrementer(void)
{
#if defined(CONFIG_BOOKE) || defined(CONFIG_40x)
	unsigned int tcr;

	/* Clear any pending timer interrupts */
	mtspr(SPRN_TSR, TSR_ENW | TSR_WIS | TSR_DIS | TSR_FIS);

	tcr = mfspr(SPRN_TCR);
	/*
	 * The watchdog may have already been enabled by u-boot. So leave
	 * TRC[WP] (Watchdog Period) alone.
	 */
	tcr &= TCR_WP_MASK;	/* Clear all bits except for TCR[WP] */
	tcr |= TCR_DIE;		/* Enable decrementer */
	mtspr(SPRN_TCR, tcr);
#endif
}

void __init generic_calibrate_decr(void)
{
	ppc_tb_freq = DEFAULT_TB_FREQ;		/* hardcoded default */

	if (!get_freq("ibm,extended-timebase-frequency", 2, &ppc_tb_freq) &&
	    !get_freq("timebase-frequency", 1, &ppc_tb_freq)) {

		printk(KERN_ERR "WARNING: Estimating decrementer frequency "
				"(not found)\n");
	}

	ppc_proc_freq = DEFAULT_PROC_FREQ;	/* hardcoded default */

	if (!get_freq("ibm,extended-clock-frequency", 2, &ppc_proc_freq) &&
	    !get_freq("clock-frequency", 1, &ppc_proc_freq)) {

		printk(KERN_ERR "WARNING: Estimating processor frequency "
				"(not found)\n");
	}

#if defined(CONFIG_BOOKE) || defined(CONFIG_40x)
	/* Clear any pending timer interrupts */
	mtspr(SPRN_TSR, TSR_ENW | TSR_WIS | TSR_DIS | TSR_FIS);

	/* Enable decrementer interrupt */
	mtspr(SPRN_TCR, TCR_DIE);
#endif
}

int update_persistent_clock64(struct timespec64 now)
{
	struct rtc_time tm;

	if (!ppc_md.set_rtc_time)
		return 0;
		return -ENODEV;

	rtc_time64_to_tm(now.tv_sec + 1 + timezone_offset, &tm);

	return ppc_md.set_rtc_time(&tm);
}

unsigned long read_persistent_clock(void)
static void __read_persistent_clock(struct timespec *ts)
static void __read_persistent_clock(struct timespec64 *ts)
{
	struct rtc_time tm;
	static int first = 1;

	ts->tv_nsec = 0;
	/* XXX this is a litle fragile but will work okay in the short term */
	if (first) {
		first = 0;
		if (ppc_md.time_init)
			timezone_offset = ppc_md.time_init();

		/* get_boot_time() isn't guaranteed to be safe to call late */
		if (ppc_md.get_boot_time)
			return ppc_md.get_boot_time() -timezone_offset;
	}
	if (!ppc_md.get_rtc_time)
		return 0;
	ppc_md.get_rtc_time(&tm);
	return mktime(tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		      tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* clocksource code */
static cycle_t rtc_read(void)
		if (ppc_md.get_boot_time) {
			ts->tv_sec = ppc_md.get_boot_time() - timezone_offset;
			return;
		}
	}
	if (!ppc_md.get_rtc_time) {
		ts->tv_sec = 0;
		return;
	}
	ppc_md.get_rtc_time(&tm);

	ts->tv_sec = rtc_tm_to_time64(&tm);
}

void read_persistent_clock64(struct timespec64 *ts)
{
	__read_persistent_clock(ts);

	/* Sanitize it in case real time clock is set below EPOCH */
	if (ts->tv_sec < 0) {
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
	}
		
}

/* clocksource code */
static notrace u64 rtc_read(struct clocksource *cs)
{
	return (u64)get_rtc();
}

static cycle_t timebase_read(void)
static cycle_t timebase_read(struct clocksource *cs)
static notrace u64 timebase_read(struct clocksource *cs)
{
	return (u64)get_tb();
}

void update_vsyscall(struct timespec *wall_time, struct clocksource *clock)
{
	u64 t2x, stamp_xsec;
void update_vsyscall_old(struct timespec *wall_time, struct timespec *wtm,
			 struct clocksource *clock, u32 mult, cycle_t cycle_last)

void update_vsyscall(struct timekeeper *tk)
{
	struct timespec xt;
	struct clocksource *clock = tk->tkr_mono.clock;
	u32 mult = tk->tkr_mono.mult;
	u32 shift = tk->tkr_mono.shift;
	u64 cycle_last = tk->tkr_mono.cycle_last;
	u64 new_tb_to_xs, new_stamp_xsec;
	u64 frac_sec;

	if (clock != &clocksource_timebase)
		return;

	xt.tv_sec = tk->xtime_sec;
	xt.tv_nsec = (long)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);

	/* Make userspace gettimeofday spin until we're done. */
	++vdso_data->tb_update_count;
	smp_mb();

	/* XXX this assumes clock->shift == 22 */
	/* 4611686018 ~= 2^(20+64-22) / 1e9 */
	t2x = (u64) clock->mult * 4611686018ULL;
	stamp_xsec = (u64) xtime.tv_nsec * XSEC_PER_SEC;
	do_div(stamp_xsec, 1000000000);
	stamp_xsec += (u64) xtime.tv_sec * XSEC_PER_SEC;
	update_gtod(clock->cycle_last, stamp_xsec, t2x);
	/* 19342813113834067 ~= 2^(20+64) / 1e9 */
	new_tb_to_xs = (u64) mult * (19342813113834067ULL >> clock->shift);
	new_stamp_xsec = (u64) wall_time->tv_nsec * XSEC_PER_SEC;
	do_div(new_stamp_xsec, 1000000000);
	new_stamp_xsec += (u64) wall_time->tv_sec * XSEC_PER_SEC;
	/*
	 * This computes ((2^20 / 1e9) * mult) >> shift as a
	 * 0.64 fixed-point fraction.
	 * The computation in the else clause below won't overflow
	 * (as long as the timebase frequency is >= 1.049 MHz)
	 * but loses precision because we lose the low bits of the constant
	 * in the shift.  Note that 19342813113834067 ~= 2^(20+64) / 1e9.
	 * For a shift of 24 the error is about 0.5e-9, or about 0.5ns
	 * over a second.  (Shift values are usually 22, 23 or 24.)
	 * For high frequency clocks such as the 512MHz timebase clock
	 * on POWER[6789], the mult value is small (e.g. 32768000)
	 * and so we can shift the constant by 16 initially
	 * (295147905179 ~= 2^(20+64-16) / 1e9) and then do the
	 * remaining shifts after the multiplication, which gives a
	 * more accurate result (e.g. with mult = 32768000, shift = 24,
	 * the error is only about 1.2e-12, or 0.7ns over 10 minutes).
	 */
	if (mult <= 62500000 && clock->shift >= 16)
		new_tb_to_xs = ((u64) mult * 295147905179ULL) >> (clock->shift - 16);
	else
		new_tb_to_xs = (u64) mult * (19342813113834067ULL >> clock->shift);

	/*
	 * Compute the fractional second in units of 2^-32 seconds.
	 * The fractional second is tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift
	 * in nanoseconds, so multiplying that by 2^32 / 1e9 gives
	 * it in units of 2^-32 seconds.
	 * We assume shift <= 32 because clocks_calc_mult_shift()
	 * generates shift values in the range 0 - 32.
	 */
	frac_sec = tk->tkr_mono.xtime_nsec << (32 - shift);
	do_div(frac_sec, NSEC_PER_SEC);

	/*
	 * Work out new stamp_xsec value for any legacy users of systemcfg.
	 * stamp_xsec is in units of 2^-20 seconds.
	 */
	new_stamp_xsec = frac_sec >> 12;
	new_stamp_xsec += tk->xtime_sec * XSEC_PER_SEC;

	/*
	 * tb_update_count is used to allow the userspace gettimeofday code
	 * to assure itself that it sees a consistent view of the tb_to_xs and
	 * stamp_xsec variables.  It reads the tb_update_count, then reads
	 * tb_to_xs and stamp_xsec and then reads tb_update_count again.  If
	 * the two values of tb_update_count match and are even then the
	 * tb_to_xs and stamp_xsec values are consistent.  If not, then it
	 * loops back and reads them again until this criteria is met.
	 */
	vdso_data->tb_orig_stamp = cycle_last;
	vdso_data->stamp_xsec = new_stamp_xsec;
	vdso_data->tb_to_xs = new_tb_to_xs;
	vdso_data->wtom_clock_sec = tk->wall_to_monotonic.tv_sec;
	vdso_data->wtom_clock_nsec = tk->wall_to_monotonic.tv_nsec;
	vdso_data->stamp_xtime = xt;
	vdso_data->stamp_sec_fraction = frac_sec;
	smp_wmb();
	++(vdso_data->tb_update_count);
}

void update_vsyscall_tz(void)
{
	/* Make userspace gettimeofday spin until we're done. */
	++vdso_data->tb_update_count;
	smp_mb();
	vdso_data->tz_minuteswest = sys_tz.tz_minuteswest;
	vdso_data->tz_dsttime = sys_tz.tz_dsttime;
	smp_mb();
	++vdso_data->tb_update_count;
	vdso_data->tz_minuteswest = sys_tz.tz_minuteswest;
	vdso_data->tz_dsttime = sys_tz.tz_dsttime;
}

static void __init clocksource_init(void)
{
	struct clocksource *clock;

	if (__USE_RTC())
		clock = &clocksource_rtc;
	else
		clock = &clocksource_timebase;

	clock->mult = clocksource_hz2mult(tb_ticks_per_sec, clock->shift);

	if (clocksource_register(clock)) {
	if (clocksource_register_hz(clock, tb_ticks_per_sec)) {
		printk(KERN_ERR "clocksource: %s is already registered\n",
		       clock->name);
		return;
	}

	printk(KERN_INFO "clocksource: %s mult[%x] shift[%d] registered\n",
	       clock->name, clock->mult, clock->shift);
}

static int decrementer_set_next_event(unsigned long evt,
				      struct clock_event_device *dev)
{
	__get_cpu_var(decrementers).next_tb = get_tb_or_rtc() + evt;
	set_dec(evt);
	return 0;
}

static void decrementer_set_mode(enum clock_event_mode mode,
				 struct clock_event_device *dev)
{
	if (mode != CLOCK_EVT_MODE_ONESHOT)
		decrementer_set_next_event(DECREMENTER_MAX, dev);
	__this_cpu_write(decrementers_next_tb, get_tb_or_rtc() + evt);
	set_dec(evt);

	/* We may have raced with new irq work */
	if (test_irq_work_pending())
		set_dec(1);

	return 0;
}

static int decrementer_shutdown(struct clock_event_device *dev)
{
	decrementer_set_next_event(decrementer_max, dev);
	return 0;
}

static void register_decrementer_clockevent(int cpu)
{
	struct clock_event_device *dec = &per_cpu(decrementers, cpu).event;

	*dec = decrementer_clockevent;
	dec->cpumask = cpumask_of_cpu(cpu);

	printk(KERN_DEBUG "clockevent: %s mult[%lx] shift[%d] cpu[%d]\n",
	       dec->name, dec->mult, dec->shift, cpu);
	struct clock_event_device *dec = &per_cpu(decrementers, cpu);

	*dec = decrementer_clockevent;
	dec->cpumask = cpumask_of(cpu);

	printk_once(KERN_DEBUG "clockevent: %s mult[%x] shift[%d] cpu[%d]\n",
		    dec->name, dec->mult, dec->shift, cpu);

	clockevents_register_device(dec);
}

static void enable_large_decrementer(void)
{
	if (!cpu_has_feature(CPU_FTR_ARCH_300))
		return;

	if (decrementer_max <= DECREMENTER_DEFAULT_MAX)
		return;

	/*
	 * If we're running as the hypervisor we need to enable the LD manually
	 * otherwise firmware should have done it for us.
	 */
	if (cpu_has_feature(CPU_FTR_HVMODE))
		mtspr(SPRN_LPCR, mfspr(SPRN_LPCR) | LPCR_LD);
}

static void __init set_decrementer_max(void)
{
	struct device_node *cpu;
	u32 bits = 32;

	/* Prior to ISAv3 the decrementer is always 32 bit */
	if (!cpu_has_feature(CPU_FTR_ARCH_300))
		return;

	cpu = of_find_node_by_type(NULL, "cpu");

	if (of_property_read_u32(cpu, "ibm,dec-bits", &bits) == 0) {
		if (bits > 64 || bits < 32) {
			pr_warn("time_init: firmware supplied invalid ibm,dec-bits");
			bits = 32;
		}

		/* calculate the signed maximum given this many bits */
		decrementer_max = (1ul << (bits - 1)) - 1;
	}

	of_node_put(cpu);

	pr_info("time_init: %u bit decrementer (max: %llx)\n",
		bits, decrementer_max);
}

static void __init init_decrementer_clockevent(void)
{
	int cpu = smp_processor_id();

	decrementer_clockevent.mult = div_sc(ppc_tb_freq, NSEC_PER_SEC,
					     decrementer_clockevent.shift);
	clockevents_calc_mult_shift(&decrementer_clockevent, ppc_tb_freq, 4);

	decrementer_clockevent.max_delta_ns =
		clockevent_delta2ns(decrementer_max, &decrementer_clockevent);
	decrementer_clockevent.max_delta_ticks = decrementer_max;
	decrementer_clockevent.min_delta_ns =
		clockevent_delta2ns(2, &decrementer_clockevent);
	decrementer_clockevent.min_delta_ticks = 2;

	register_decrementer_clockevent(cpu);
}

void secondary_cpu_time_init(void)
{
	/* Enable and test the large decrementer for this cpu */
	enable_large_decrementer();

	/* Start the decrementer on CPUs that have manual control
	 * such as BookE
	 */
	start_cpu_decrementer();

	/* FIME: Should make unrelatred change to move snapshot_timebase
	 * call here ! */
	register_decrementer_clockevent(smp_processor_id());
}

/* This function is only called on the boot processor */
void __init time_init(void)
{
	unsigned long flags;
	struct div_result res;
	u64 scale, x;
	struct div_result res;
	u64 scale;
	unsigned shift;

	if (__USE_RTC()) {
		/* 601 processor: dec counts down by 128 every 128ns */
		ppc_tb_freq = 1000000000;
		tb_last_jiffy = get_rtcl();
	} else {
		/* Normal PowerPC with timebase register */
		ppc_md.calibrate_decr();
		printk(KERN_DEBUG "time_init: decrementer frequency = %lu.%.6lu MHz\n",
		       ppc_tb_freq / 1000000, ppc_tb_freq % 1000000);
		printk(KERN_DEBUG "time_init: processor frequency   = %lu.%.6lu MHz\n",
		       ppc_proc_freq / 1000000, ppc_proc_freq % 1000000);
		tb_last_jiffy = get_tb();
	}

	tb_ticks_per_jiffy = ppc_tb_freq / HZ;
	tb_ticks_per_sec = ppc_tb_freq;
	tb_ticks_per_usec = ppc_tb_freq / 1000000;
	tb_to_us = mulhwu_scale_factor(ppc_tb_freq, 1000000);
	calc_cputime_factors();

	/*
	 * Calculate the length of each tick in ns.  It will not be
	 * exactly 1e9/HZ unless ppc_tb_freq is divisible by HZ.
	 * We compute 1e9 * tb_ticks_per_jiffy / ppc_tb_freq,
	 * rounded up.
	 */
	x = (u64) NSEC_PER_SEC * tb_ticks_per_jiffy + ppc_tb_freq - 1;
	do_div(x, ppc_tb_freq);
	tick_nsec = x;
	last_tick_len = x << TICKLEN_SCALE;

	/*
	 * Compute ticklen_to_xs, which is a factor which gets multiplied
	 * by (last_tick_len << TICKLEN_SHIFT) to get a tb_to_xs value.
	 * It is computed as:
	 * ticklen_to_xs = 2^N / (tb_ticks_per_jiffy * 1e9)
	 * where N = 64 + 20 - TICKLEN_SCALE - TICKLEN_SHIFT
	 * which turns out to be N = 51 - SHIFT_HZ.
	 * This gives the result as a 0.64 fixed-point fraction.
	 * That value is reduced by an offset amounting to 1 xsec per
	 * 2^31 timebase ticks to avoid problems with time going backwards
	 * by 1 xsec when we do timer_recalc_offset due to losing the
	 * fractional xsec.  That offset is equal to ppc_tb_freq/2^51
	 * since there are 2^20 xsec in a second.
	 */
	div128_by_32((1ULL << 51) - ppc_tb_freq, 0,
		     tb_ticks_per_jiffy << SHIFT_HZ, &res);
	div128_by_32(res.result_high, res.result_low, NSEC_PER_SEC, &res);
	ticklen_to_xs = res.result_low;

	/* Compute tb_to_xs from tick_nsec */
	tb_to_xs = mulhdu(last_tick_len << TICKLEN_SHIFT, ticklen_to_xs);
	calc_cputime_factors();

	/*
	 * Compute scale factor for sched_clock.
	 * The calibrate_decr() function has set tb_ticks_per_sec,
	 * which is the timebase frequency.
	 * We compute 1e9 * 2^64 / tb_ticks_per_sec and interpret
	 * the 128-bit result as a 64.64 fixed-point number.
	 * We then shift that number right until it is less than 1.0,
	 * giving us the scale factor and shift count to use in
	 * sched_clock().
	 */
	div128_by_32(1000000000, 0, tb_ticks_per_sec, &res);
	scale = res.result_low;
	for (shift = 0; res.result_high != 0; ++shift) {
		scale = (scale >> 1) | (res.result_high << 63);
		res.result_high >>= 1;
	}
	tb_to_ns_scale = scale;
	tb_to_ns_shift = shift;
	/* Save the current timebase to pretty up CONFIG_PRINTK_TIME */
	boot_tb = get_tb_or_rtc();

	write_seqlock_irqsave(&xtime_lock, flags);

	/* If platform provided a timezone (pmac), we correct the time */
        if (timezone_offset) {
		sys_tz.tz_minuteswest = -timezone_offset / 60;
		sys_tz.tz_dsttime = 0;
        }

	do_gtod.varp = &do_gtod.vars[0];
	do_gtod.var_idx = 0;
	do_gtod.varp->tb_orig_stamp = tb_last_jiffy;
	__get_cpu_var(last_jiffy) = tb_last_jiffy;
	do_gtod.varp->stamp_xsec = (u64) xtime.tv_sec * XSEC_PER_SEC;
	do_gtod.tb_ticks_per_sec = tb_ticks_per_sec;
	do_gtod.varp->tb_to_xs = tb_to_xs;
	do_gtod.tb_to_us = tb_to_us;

	vdso_data->tb_orig_stamp = tb_last_jiffy;
	vdso_data->tb_update_count = 0;
	vdso_data->tb_ticks_per_sec = tb_ticks_per_sec;
	vdso_data->stamp_xsec = (u64) xtime.tv_sec * XSEC_PER_SEC;
	vdso_data->tb_to_xs = tb_to_xs;

	write_sequnlock_irqrestore(&xtime_lock, flags);

	/* Register the clocksource, if we're not running on iSeries */
	if (!firmware_has_feature(FW_FEATURE_ISERIES))
		clocksource_init();

	init_decrementer_clockevent();
	/* If platform provided a timezone (pmac), we correct the time */
	if (timezone_offset) {
		sys_tz.tz_minuteswest = -timezone_offset / 60;
		sys_tz.tz_dsttime = 0;
	}

	vdso_data->tb_update_count = 0;
	vdso_data->tb_ticks_per_sec = tb_ticks_per_sec;

	/* initialise and enable the large decrementer (if we have one) */
	set_decrementer_max();
	enable_large_decrementer();

	/* Start the decrementer on CPUs that have manual control
	 * such as BookE
	 */
	start_cpu_decrementer();

	/* Register the clocksource */
	clocksource_init();

	init_decrementer_clockevent();
	tick_setup_hrtimer_broadcast();

#ifdef CONFIG_COMMON_CLK
	of_clk_init(NULL);
#endif
}


#define FEBRUARY	2
#define	STARTOFTIME	1970
#define SECDAY		86400L
#define SECYR		(SECDAY * 365)
#define	leapyear(year)		((year) % 4 == 0 && \
				 ((year) % 100 != 0 || (year) % 400 == 0))
#define	days_in_year(a) 	(leapyear(a) ? 366 : 365)
#define	days_in_month(a) 	(month_days[(a) - 1])

static int month_days[12] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

void to_tm(int tim, struct rtc_time * tm)
{
	register int    i;
	register long   hms, day;

	day = tim / SECDAY;
	hms = tim % SECDAY;

	/* Hours, minutes, seconds are easy */
	tm->tm_hour = hms / 3600;
	tm->tm_min = (hms % 3600) / 60;
	tm->tm_sec = (hms % 3600) % 60;

	/* Number of years in days */
	for (i = STARTOFTIME; day >= days_in_year(i); i++)
		day -= days_in_year(i);
	tm->tm_year = i;

	/* Number of months in days left */
	if (leapyear(tm->tm_year))
		days_in_month(FEBRUARY) = 29;
	for (i = 1; day >= days_in_month(i); i++)
		day -= days_in_month(i);
	days_in_month(FEBRUARY) = 28;
	tm->tm_mon = i;

	/* Days are what is left over (+1) from all that. */
	tm->tm_mday = day + 1;

	/*
	 * No-one uses the day of the week.
	 */
	tm->tm_wday = -1;
}

/* Auxiliary function to compute scaling factors */
/* Actually the choice of a timebase running at 1/4 the of the bus
 * frequency giving resolution of a few tens of nanoseconds is quite nice.
 * It makes this computation very precise (27-28 bits typically) which
 * is optimistic considering the stability of most processor clock
 * oscillators and the precision with which the timebase frequency
 * is measured but does not harm.
 */
unsigned mulhwu_scale_factor(unsigned inscale, unsigned outscale)
{
        unsigned mlt=0, tmp, err;
        /* No concern for performance, it's done once: use a stupid
         * but safe and compact method to find the multiplier.
         */
  
        for (tmp = 1U<<31; tmp != 0; tmp >>= 1) {
                if (mulhwu(inscale, mlt|tmp) < outscale)
			mlt |= tmp;
        }
  
        /* We might still be off by 1 for the best approximation.
         * A side effect of this is that if outscale is too large
         * the returned value will be zero.
         * Many corner cases have been checked and seem to work,
         * some might have been forgotten in the test however.
         */
  
        err = inscale * (mlt+1);
        if (err <= inscale/2)
		mlt++;
        return mlt;
}
EXPORT_SYMBOL(to_tm);

/*
 * Divide a 128-bit dividend by a 32-bit divisor, leaving a 128 bit
 * result.
 */
void div128_by_32(u64 dividend_high, u64 dividend_low,
		  unsigned divisor, struct div_result *dr)
{
	unsigned long a, b, c, d;
	unsigned long w, x, y, z;
	u64 ra, rb, rc;

	a = dividend_high >> 32;
	b = dividend_high & 0xffffffff;
	c = dividend_low >> 32;
	d = dividend_low & 0xffffffff;

	w = a / divisor;
	ra = ((u64)(a - (w * divisor)) << 32) + b;

	rb = ((u64) do_div(ra, divisor) << 32) + c;
	x = ra;

	rc = ((u64) do_div(rb, divisor) << 32) + d;
	y = rb;

	do_div(rc, divisor);
	z = rc;

	dr->result_high = ((u64)w << 32) + x;
	dr->result_low  = ((u64)y << 32) + z;

}

/* We don't need to calibrate delay, we use the CPU timebase for that */
void calibrate_delay(void)
{
	/* Some generic code (such as spinlock debug) use loops_per_jiffy
	 * as the number of __delay(1) in a jiffy, so make it so
	 */
	loops_per_jiffy = tb_ticks_per_jiffy;
}

#if IS_ENABLED(CONFIG_RTC_DRV_GENERIC)
static int rtc_generic_get_time(struct device *dev, struct rtc_time *tm)
{
	ppc_md.get_rtc_time(tm);
	return 0;
}

static int rtc_generic_set_time(struct device *dev, struct rtc_time *tm)
{
	if (!ppc_md.set_rtc_time)
		return -EOPNOTSUPP;

	if (ppc_md.set_rtc_time(tm) < 0)
		return -EOPNOTSUPP;

	return 0;
}

static const struct rtc_class_ops rtc_generic_ops = {
	.read_time = rtc_generic_get_time,
	.set_time = rtc_generic_set_time,
};

static int __init rtc_init(void)
{
	struct platform_device *pdev;

	if (!ppc_md.get_rtc_time)
		return -ENODEV;

	pdev = platform_device_register_data(NULL, "rtc-generic", -1,
					     &rtc_generic_ops,
					     sizeof(rtc_generic_ops));

	return PTR_ERR_OR_ZERO(pdev);
}

device_initcall(rtc_init);
#endif
