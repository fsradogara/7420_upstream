// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/parisc/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 *  Modifications for ARM (C) 1994, 1995, 1996,1997 Russell King
 *  Copyright (C) 1999 SuSE GmbH, (Philipp Rumpf, prumpf@tux.org)
 *
 * 1994-07-02  Alan Modra
 *             fixed set_rtc_mmss, fixed time.year for >= 2000, new mktime
 * 1998-12-20  Updated NTP code according to technical memorandum Jan '96
 *             "A Kernel Model for Precision Timekeeping" by Dave Mills
 */
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched_clock.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/clocksource.h>
#include <linux/platform_device.h>
#include <linux/ftrace.h>

#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/param.h>
#include <asm/pdc.h>
#include <asm/led.h>

#include <linux/timex.h>

static unsigned long clocktick __read_mostly;	/* timer cycles per tick */

/*
 * We keep time on PA-RISC Linux by using the Interval Timer which is
 * a pair of registers; one is read-only and one is write-only; both
 * accessed through CR16.  The read-only register is 32 or 64 bits wide,
 * and increments by 1 every CPU clock tick.  The architecture only
 * guarantees us a rate between 0.5 and 2, but all implementations use a
 * rate of 1.  The write-only register is 32-bits wide.  When the lowest
 * 32 bits of the read-only register compare equal to the write-only
 * register, it raises a maskable external interrupt.  Each processor has
 * an Interval Timer of its own and they are not synchronised.  
 *
 * We want to generate an interrupt every 1/HZ seconds.  So we program
 * CR16 to interrupt every @clocktick cycles.  The it_value in cpu_data
 * is programmed with the intended time of the next tick.  We can be
 * held off for an arbitrarily long period of time by interrupts being
 * disabled, so we may miss one or more ticks.
 */
irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	unsigned long now;
	unsigned long next_tick;
	unsigned long cycles_elapsed, ticks_elapsed;
	unsigned long cycles_remainder;
	unsigned int cpu = smp_processor_id();
	struct cpuinfo_parisc *cpuinfo = &cpu_data[cpu];
irqreturn_t __irq_entry timer_interrupt(int irq, void *dev_id)
{
	unsigned long now;
	unsigned long next_tick;
	unsigned long ticks_elapsed = 0;
	unsigned int cpu = smp_processor_id();
	struct cpuinfo_parisc *cpuinfo = &per_cpu(cpu_data, cpu);

	/* gcc can optimize for "read-only" case with a local clocktick */
	unsigned long cpt = clocktick;

	profile_tick(CPU_PROFILING);

	/* Initialize next_tick to the old expected tick time. */
	next_tick = cpuinfo->it_value;

	/* Get current interval timer.
	 * CR16 reads as 64 bits in CPU wide mode.
	 * CR16 reads as 32 bits in CPU narrow mode.
	 */
	/* Get current cycle counter (Control Register 16). */
	now = mfctl(16);

	cycles_elapsed = now - next_tick;

	if ((cycles_elapsed >> 5) < cpt) {
	if ((cycles_elapsed >> 6) < cpt) {
		/* use "cheap" math (add/subtract) instead
		 * of the more expensive div/mul method
		 */
		cycles_remainder = cycles_elapsed;
		ticks_elapsed = 1;
		while (cycles_remainder > cpt) {
			cycles_remainder -= cpt;
			ticks_elapsed++;
		}
	} else {
		cycles_remainder = cycles_elapsed % cpt;
		ticks_elapsed = 1 + cycles_elapsed / cpt;
	}

	/* Can we differentiate between "early CR16" (aka Scenario 1) and
	 * "long delay" (aka Scenario 3)? I don't think so.
	 *
	 * We expected timer_interrupt to be delivered at least a few hundred
	 * cycles after the IT fires. But it's arbitrary how much time passes
	 * before we call it "late". I've picked one second.
	 */
	if (unlikely(ticks_elapsed > HZ)) {
		/* Scenario 3: very long delay?  bad in any case */
		printk (KERN_CRIT "timer_interrupt(CPU %d): delayed!"
			" cycles %lX rem %lX "
			" next/now %lX/%lX\n",
			cpu,
			cycles_elapsed, cycles_remainder,
			next_tick, now );
		/* TODO: Reduce this to one fdiv op */
		cycles_remainder = cycles_elapsed % cpt;
		ticks_elapsed += cycles_elapsed / cpt;
	}

	/* convert from "division remainder" to "remainder of clock tick" */
	cycles_remainder = cpt - cycles_remainder;

	/* Determine when (in CR16 cycles) next IT interrupt will fire.
	 * We want IT to fire modulo clocktick even if we miss/skip some.
	 * But those interrupts don't in fact get delivered that regularly.
	 */
	next_tick = now + cycles_remainder;
	/* Calculate how many ticks have elapsed. */
	now = mfctl(16);
	do {
		++ticks_elapsed;
		next_tick += cpt;
	} while (next_tick - now > cpt);

	/* Store (in CR16 cycles) up to when we are accounting right now. */
	cpuinfo->it_value = next_tick;

	/* Skip one clocktick on purpose if we are likely to miss next_tick.
	 * We want to avoid the new next_tick being less than CR16.
	 * If that happened, itimer wouldn't fire until CR16 wrapped.
	 * We'll catch the tick we missed on the tick after that.
	 */
	if (!(cycles_remainder >> 13))
		next_tick += cpt;

	/* Program the IT when to deliver the next interrupt. */
	/* Only bottom 32-bits of next_tick are written to cr16.  */
	mtctl(next_tick, 16);

	/* Program the IT when to deliver the next interrupt.
	 * Only bottom 32-bits of next_tick are writable in CR16!
	 */
	mtctl(next_tick, 16);
	/* Go do system house keeping. */
	if (cpu == 0)
		xtime_update(ticks_elapsed);

	update_process_times(user_mode(get_irq_regs()));

	/* Skip clockticks on purpose if we know we would miss those.
	 * The new CR16 must be "later" than current CR16 otherwise
	 * itimer would not fire until CR16 wrapped - e.g 4 seconds
	 * later on a 1Ghz processor. We'll account for the missed
	 * ticks on the next timer interrupt.
	 * We want IT to fire modulo clocktick even if we miss/skip some.
	 * But those interrupts don't in fact get delivered that regularly.
	 *
	 * "next_tick - now" will always give the difference regardless
	 * if one or the other wrapped. If "now" is "bigger" we'll end up
	 * with a very large unsigned number.
	 */
	now = mfctl(16);
	while (next_tick - now > cpt)
		next_tick += cpt;

	/* Program the IT when to deliver the next interrupt.
	 * Only bottom 32-bits of next_tick are writable in CR16!
	 * Timer interrupt will be delivered at least a few hundred cycles
	 * after the IT fires, so if we are too close (<= 8000 cycles) to the
	 * next cycle, simply skip it.
	 */
	if (unlikely(ticks_elapsed > HZ)) {
		/* Scenario 3: very long delay?  bad in any case */
		printk (KERN_CRIT "timer_interrupt(CPU %d): delayed!"
			" cycles %lX rem %lX "
			" next/now %lX/%lX\n",
			cpu,
			cycles_elapsed, cycles_remainder,
			next_tick, now );
	}

	/* Done mucking with unreliable delivery of interrupts.
	 * Go do system house keeping.
	 */

	if (!--cpuinfo->prof_counter) {
		cpuinfo->prof_counter = cpuinfo->prof_multiplier;
		update_process_times(user_mode(get_irq_regs()));
	}

	if (cpu == 0) {
		write_seqlock(&xtime_lock);
		do_timer(ticks_elapsed);
		write_sequnlock(&xtime_lock);
	}
	if (cpu == 0)
		xtime_update(ticks_elapsed);
	if (next_tick - mfctl(16) <= 500)
	if (next_tick - now <= 8000)
		next_tick += cpt;
	mtctl(next_tick, 16);

	return IRQ_HANDLED;
}


unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (regs->gr[0] & PSW_N)
		pc -= 4;

#ifdef CONFIG_SMP
	if (in_lock_functions(pc))
		pc = regs->gr[2];
#endif

	return pc;
}
EXPORT_SYMBOL(profile_pc);


/* clock source code */

static cycle_t read_cr16(void)
static cycle_t read_cr16(struct clocksource *cs)
static u64 notrace read_cr16(struct clocksource *cs)
{
	return get_cycles();
}

static struct clocksource clocksource_cr16 = {
	.name			= "cr16",
	.rating			= 300,
	.read			= read_cr16,
	.mask			= CLOCKSOURCE_MASK(BITS_PER_LONG),
	.mult			= 0, /* to be set */
	.shift			= 22,
	.flags			= CLOCK_SOURCE_IS_CONTINUOUS,
};

#ifdef CONFIG_SMP
	.flags			= CLOCK_SOURCE_IS_CONTINUOUS,
};

int update_cr16_clocksource(void)
{
	/* since the cr16 cycle counters are not synchronized across CPUs,
	   we'll check if we should switch to a safe clocksource: */
	if (clocksource_cr16.rating != 0 && num_online_cpus() > 1) {
		clocksource_change_rating(&clocksource_cr16, 0);
		return 1;
	}

	return 0;
}
#else
int update_cr16_clocksource(void)
{
	return 0; /* no change */
}
#endif /*CONFIG_SMP*/

void __init start_cpu_itimer(void)
{
	unsigned int cpu = smp_processor_id();
	unsigned long next_tick = mfctl(16) + clocktick;

	mtctl(next_tick, 16);		/* kick off Interval Timer (CR16) */

	cpu_data[cpu].it_value = next_tick;
	per_cpu(cpu_data, cpu).it_value = next_tick;
}

#if IS_ENABLED(CONFIG_RTC_DRV_GENERIC)
static int rtc_generic_get_time(struct device *dev, struct rtc_time *tm)
{
	struct pdc_tod tod_data;

	memset(tm, 0, sizeof(*tm));
	if (pdc_tod_read(&tod_data) < 0)
		return -EOPNOTSUPP;

	/* we treat tod_sec as unsigned, so this can work until year 2106 */
	rtc_time64_to_tm(tod_data.tod_sec, tm);
	return rtc_valid_tm(tm);
}

static int rtc_generic_set_time(struct device *dev, struct rtc_time *tm)
{
	time64_t secs = rtc_tm_to_time64(tm);

	if (pdc_tod_set(secs, 0) < 0)
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

	pdev = platform_device_register_data(NULL, "rtc-generic", -1,
					     &rtc_generic_ops,
					     sizeof(rtc_generic_ops));

	return PTR_ERR_OR_ZERO(pdev);
}
device_initcall(rtc_init);
#endif

void read_persistent_clock64(struct timespec64 *ts)
{
	static struct pdc_tod tod_data;
	if (pdc_tod_read(&tod_data) == 0) {
		ts->tv_sec = tod_data.tod_sec;
		ts->tv_nsec = tod_data.tod_usec * 1000;
	} else {
		printk(KERN_ERR "Error reading tod clock\n");
	        ts->tv_sec = 0;
		ts->tv_nsec = 0;
	}
}


static u64 notrace read_cr16_sched_clock(void)
{
	return get_cycles();
}


/*
 * timer interrupt and sched_clock() initialization
 */

void __init time_init(void)
{
	static struct pdc_tod tod_data;
	unsigned long current_cr16_khz;
	unsigned long cr16_hz;

	clocktick = (100 * PAGE0->mem_10msec) / HZ;
	start_cpu_itimer();	/* get CPU 0 started */

	/* register at clocksource framework */
	current_cr16_khz = PAGE0->mem_10msec/10;  /* kHz */
	clocksource_cr16.mult = clocksource_khz2mult(current_cr16_khz,
						clocksource_cr16.shift);
	clocksource_register(&clocksource_cr16);

	if (pdc_tod_read(&tod_data) == 0) {
		unsigned long flags;

		write_seqlock_irqsave(&xtime_lock, flags);
		xtime.tv_sec = tod_data.tod_sec;
		xtime.tv_nsec = tod_data.tod_usec * 1000;
		set_normalized_timespec(&wall_to_monotonic,
		                        -xtime.tv_sec, -xtime.tv_nsec);
		write_sequnlock_irqrestore(&xtime_lock, flags);
	} else {
		printk(KERN_ERR "Error reading tod clock\n");
	        xtime.tv_sec = 0;
		xtime.tv_nsec = 0;
	}
}

	clocksource_register_khz(&clocksource_cr16, current_cr16_khz);
	cr16_hz = 100 * PAGE0->mem_10msec;  /* Hz */

	/* register as sched_clock source */
	sched_clock_register(read_cr16_sched_clock, BITS_PER_LONG, cr16_hz);
}

static int __init init_cr16_clocksource(void)
{
	/*
	 * The cr16 interval timers are not syncronized across CPUs on
	 * different sockets, so mark them unstable and lower rating on
	 * multi-socket SMP systems.
	 */
	if (num_online_cpus() > 1 && !running_on_qemu) {
		int cpu;
		unsigned long cpu0_loc;
		cpu0_loc = per_cpu(cpu_data, 0).cpu_loc;

		for_each_online_cpu(cpu) {
			if (cpu == 0)
				continue;
			if ((cpu0_loc != 0) &&
			    (cpu0_loc == per_cpu(cpu_data, cpu).cpu_loc))
				continue;

			clocksource_cr16.name = "cr16_unstable";
			clocksource_cr16.flags = CLOCK_SOURCE_UNSTABLE;
			clocksource_cr16.rating = 0;
			break;
		}
	}

	/* XXX: We may want to mark sched_clock stable here if cr16 clocks are
	 *	in sync:
	 *	(clocksource_cr16.flags == CLOCK_SOURCE_IS_CONTINUOUS) */

	/* register at clocksource framework */
	clocksource_register_hz(&clocksource_cr16,
		100 * PAGE0->mem_10msec);

	return 0;
}

device_initcall(init_cr16_clocksource);
