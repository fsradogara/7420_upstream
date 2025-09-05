/*
 * processor_idle - idle state submodule to the ACPI processor driver
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2004, 2005 Dominik Brodowski <linux@brodo.de>
 *  Copyright (C) 2004  Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *  			- Added processor hotplug support
 *  Copyright (C) 2005  Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *  			- Added support for C3 on SMP
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>	/* need_resched() */
#include <linux/pm_qos_params.h>
#include <linux/clockchips.h>
#include <linux/cpuidle.h>
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define pr_fmt(fmt) "ACPI: " fmt

#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/sched.h>       /* need_resched() */
#include <linux/tick.h>
#include <linux/cpuidle.h>
#include <linux/cpu.h>
#include <acpi/processor.h>

/*
 * Include the apic definitions for x86 to have the APIC timer related defines
 * available also for UP (on SMP it gets magically included via linux/smp.h).
 * asm/acpi.h is not an option, as it would require more include magic. Also
 * creating an empty asm-ia64/apic.h would just trade pest vs. cholera.
 */
#ifdef CONFIG_X86
#include <asm/apic.h>
#endif

#include <asm/io.h>
#include <asm/uaccess.h>

#include <acpi/acpi_bus.h>
#include <acpi/processor.h>
#include <asm/processor.h>

#define ACPI_PROCESSOR_COMPONENT        0x01000000
#define ACPI_PROCESSOR_CLASS            "processor"
#define _COMPONENT              ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME("processor_idle");
#define ACPI_PROCESSOR_FILE_POWER	"power"
#define US_TO_PM_TIMER_TICKS(t)		((t * (PM_TIMER_FREQUENCY/1000)) / 1000)
#define PM_TIMER_TICK_NS		(1000000000ULL/PM_TIMER_FREQUENCY)
#ifndef CONFIG_CPU_IDLE
#define C2_OVERHEAD			4	/* 1us (3.579 ticks per us) */
#define C3_OVERHEAD			4	/* 1us (3.579 ticks per us) */
static void (*pm_idle_save) (void) __read_mostly;
#else
#define C2_OVERHEAD			1	/* 1us */
#define C3_OVERHEAD			1	/* 1us */
#endif
#define PM_TIMER_TICKS_TO_US(p)		(((p) * 1000)/(PM_TIMER_FREQUENCY/1000))

static unsigned int max_cstate __read_mostly = ACPI_PROCESSOR_MAX_POWER;
#ifdef CONFIG_CPU_IDLE
module_param(max_cstate, uint, 0000);
#else
module_param(max_cstate, uint, 0644);
#endif
static unsigned int nocst __read_mostly;
module_param(nocst, uint, 0000);

#ifndef CONFIG_CPU_IDLE
/*
 * bm_history -- bit-mask with a bit per jiffy of bus-master activity
 * 1000 HZ: 0xFFFFFFFF: 32 jiffies = 32ms
 * 800 HZ: 0xFFFFFFFF: 32 jiffies = 40ms
 * 100 HZ: 0x0000000F: 4 jiffies = 40ms
 * reduce history for more aggressive entry into C3
 */
static unsigned int bm_history __read_mostly =
    (HZ >= 800 ? 0xFFFFFFFF : ((1U << (HZ / 25)) - 1));
module_param(bm_history, uint, 0644);

static int acpi_processor_set_power_policy(struct acpi_processor *pr);

#else	/* CONFIG_CPU_IDLE */
static unsigned int latency_factor __read_mostly = 2;
module_param(latency_factor, uint, 0644);
#endif
#define PREFIX "ACPI: "

#define ACPI_PROCESSOR_CLASS            "processor"
#define _COMPONENT              ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME("processor_idle");

#define ACPI_IDLE_STATE_START	(IS_ENABLED(CONFIG_ARCH_HAS_CPU_RELAX) ? 1 : 0)

static unsigned int max_cstate __read_mostly = ACPI_PROCESSOR_MAX_POWER;
module_param(max_cstate, uint, 0000);
static unsigned int nocst __read_mostly;
module_param(nocst, uint, 0000);
static int bm_check_disable __read_mostly;
module_param(bm_check_disable, uint, 0000);

static unsigned int latency_factor __read_mostly = 2;
module_param(latency_factor, uint, 0644);

static DEFINE_PER_CPU(struct cpuidle_device *, acpi_cpuidle_device);

struct cpuidle_driver acpi_idle_driver = {
	.name =		"acpi_idle",
	.owner =	THIS_MODULE,
};

#ifdef CONFIG_ACPI_PROCESSOR_CSTATE
static
DEFINE_PER_CPU(struct acpi_processor_cx * [CPUIDLE_STATE_MAX], acpi_cstate);

static int disabled_by_idle_boot_param(void)
{
	return boot_option_idle_override == IDLE_POLL ||
		boot_option_idle_override == IDLE_HALT;
}

/*
 * IBM ThinkPad R40e crashes mysteriously when going into C2 or C3.
 * For now disable this. Probably a bug somewhere else.
 *
 * To skip this limit, boot/load with a large max_cstate limit.
 */
static int set_max_cstate(const struct dmi_system_id *id)
{
	if (max_cstate > ACPI_PROCESSOR_MAX_POWER)
		return 0;

	pr_notice("%s detected - limiting to C%ld max_cstate."
		  " Override with \"processor.max_cstate=%d\"\n", id->ident,
		  (long)id->driver_data, ACPI_PROCESSOR_MAX_POWER + 1);

	max_cstate = (long)id->driver_data;

	return 0;
}

/* Actually this shouldn't be __cpuinitdata, would be better to fix the
   callers to only run once -AK */
static struct dmi_system_id __cpuinitdata processor_power_dmi_table[] = {
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET70WW")}, (void *)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET60WW")}, (void *)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET43WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET45WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET47WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET50WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET52WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET55WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET56WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET59WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET60WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET61WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET62WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET64WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET65WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET68WW") }, (void*)1},
	{ set_max_cstate, "Medion 41700", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"Phoenix Technologies LTD"),
	  DMI_MATCH(DMI_BIOS_VERSION,"R01-A1J")}, (void *)1},
static const struct dmi_system_id processor_power_dmi_table[] = {
	{ set_max_cstate, "Clevo 5600D", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"Phoenix Technologies LTD"),
	  DMI_MATCH(DMI_BIOS_VERSION,"SHE845M0.86C.0013.D.0302131307")},
	 (void *)2},
	{},
};

static inline u32 ticks_elapsed(u32 t1, u32 t2)
{
	if (t2 >= t1)
		return (t2 - t1);
	else if (!(acpi_gbl_FADT.flags & ACPI_FADT_32BIT_TIMER))
		return (((0x00FFFFFF - t1) + t2) & 0x00FFFFFF);
	else
		return ((0xFFFFFFFF - t1) + t2);
}

static inline u32 ticks_elapsed_in_us(u32 t1, u32 t2)
{
	if (t2 >= t1)
		return PM_TIMER_TICKS_TO_US(t2 - t1);
	else if (!(acpi_gbl_FADT.flags & ACPI_FADT_32BIT_TIMER))
		return PM_TIMER_TICKS_TO_US(((0x00FFFFFF - t1) + t2) & 0x00FFFFFF);
	else
		return PM_TIMER_TICKS_TO_US((0xFFFFFFFF - t1) + t2);
}
	{ set_max_cstate, "Pavilion zv5000", {
	  DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
	  DMI_MATCH(DMI_PRODUCT_NAME,"Pavilion zv5000 (DS502A#ABA)")},
	 (void *)1},
	{ set_max_cstate, "Asus L8400B", {
	  DMI_MATCH(DMI_SYS_VENDOR, "ASUSTeK Computer Inc."),
	  DMI_MATCH(DMI_PRODUCT_NAME,"L8400B series Notebook PC")},
	 (void *)1},
	{},
};


/*
 * Callers should disable interrupts before the call and enable
 * interrupts after return.
 */
static void __cpuidle acpi_safe_halt(void)
{
	current_thread_info()->status &= ~TS_POLLING;
	/*
	 * TS_POLLING-cleared state must be visible before we
	 * test NEED_RESCHED:
	 */
	smp_mb();
	if (!need_resched()) {
		safe_halt();
		local_irq_disable();
	}
	current_thread_info()->status |= TS_POLLING;
}

#ifndef CONFIG_CPU_IDLE

static void
acpi_processor_power_activate(struct acpi_processor *pr,
			      struct acpi_processor_cx *new)
{
	struct acpi_processor_cx *old;

	if (!pr || !new)
		return;

	old = pr->power.state;

	if (old)
		old->promotion.count = 0;
	new->demotion.count = 0;

	/* Cleanup from old state. */
	if (old) {
		switch (old->type) {
		case ACPI_STATE_C3:
			/* Disable bus master reload */
			if (new->type != ACPI_STATE_C3 && pr->flags.bm_check)
				acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
			break;
		}
	}

	/* Prepare to use new state. */
	switch (new->type) {
	case ACPI_STATE_C3:
		/* Enable bus master reload */
		if (old->type != ACPI_STATE_C3 && pr->flags.bm_check)
			acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 1);
		break;
	}

	pr->power.state = new;

	return;
}

static atomic_t c3_cpu_count;

/* Common C-state entry for C2, C3, .. */
static void acpi_cstate_enter(struct acpi_processor_cx *cstate)
{
	/* Don't trace irqs off for idle */
	stop_critical_timings();
	if (cstate->entry_method == ACPI_CSTATE_FFH) {
		/* Call into architectural FFH based C-state */
		acpi_processor_ffh_cstate_enter(cstate);
	} else {
		int unused;
		/* IO port based C-state */
		inb(cstate->address);
		/* Dummy wait op - must do something useless after P_LVL2 read
		   because chipsets cannot guarantee that STPCLK# signal
		   gets asserted in time to freeze execution properly. */
		unused = inl(acpi_gbl_FADT.xpm_timer_block.address);
	}
	start_critical_timings();
}
#endif /* !CONFIG_CPU_IDLE */

	if (!tif_need_resched()) {
		safe_halt();
		local_irq_disable();
	}
}

#ifdef ARCH_APICTIMER_STOPS_ON_C3

/*
 * Some BIOS implementations switch to C3 in the published C2 state.
 * This seems to be a common problem on AMD boxen, but other vendors
 * are affected too. We pick the most conservative approach: we assume
 * that the local APIC stops in both C2 and C3.
 */
static void acpi_timer_check_state(int state, struct acpi_processor *pr,
static void lapic_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cx)
{
	struct acpi_processor_power *pwr = &pr->power;
	u8 type = local_apic_timer_c2_ok ? ACPI_STATE_C3 : ACPI_STATE_C2;

	if (cpu_has(&cpu_data(pr->id), X86_FEATURE_ARAT))
		return;

	if (boot_cpu_has_bug(X86_BUG_AMD_APIC_C1E))
		type = ACPI_STATE_C1;

	/*
	 * Check, if one of the previous states already marked the lapic
	 * unstable
	 */
	if (pwr->timer_broadcast_on_state < state)
		return;

	if (cx->type >= type)
		pr->power.timer_broadcast_on_state = state;
}

static void acpi_propagate_timer_broadcast(struct acpi_processor *pr)
{
	unsigned long reason;

	reason = pr->power.timer_broadcast_on_state < INT_MAX ?
		CLOCK_EVT_NOTIFY_BROADCAST_ON : CLOCK_EVT_NOTIFY_BROADCAST_OFF;

	clockevents_notify(reason, &pr->id);
}

/* Power(C) State timer broadcast control */
static void acpi_state_timer_broadcast(struct acpi_processor *pr,
static void __lapic_timer_propagate_broadcast(void *arg)
{
	struct acpi_processor *pr = (struct acpi_processor *) arg;

	if (pr->power.timer_broadcast_on_state < INT_MAX)
		tick_broadcast_enable();
	else
		tick_broadcast_disable();
}

static void lapic_timer_propagate_broadcast(struct acpi_processor *pr)
{
	smp_call_function_single(pr->id, __lapic_timer_propagate_broadcast,
				 (void *)pr, 1);
}

/* Power(C) State timer broadcast control */
static void lapic_timer_state_broadcast(struct acpi_processor *pr,
				       struct acpi_processor_cx *cx,
				       int broadcast)
{
	int state = cx - pr->power.states;

	if (state >= pr->power.timer_broadcast_on_state) {
		unsigned long reason;

		reason = broadcast ?  CLOCK_EVT_NOTIFY_BROADCAST_ENTER :
			CLOCK_EVT_NOTIFY_BROADCAST_EXIT;
		clockevents_notify(reason, &pr->id);
		if (broadcast)
			tick_broadcast_enter();
		else
			tick_broadcast_exit();
	}
}

#else

static void acpi_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cstate) { }
static void acpi_propagate_timer_broadcast(struct acpi_processor *pr) { }
static void acpi_state_timer_broadcast(struct acpi_processor *pr,
static void lapic_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cstate) { }
static void lapic_timer_propagate_broadcast(struct acpi_processor *pr) { }
static void lapic_timer_state_broadcast(struct acpi_processor *pr,
				       struct acpi_processor_cx *cx,
				       int broadcast)
{
}

#endif

/*
 * Suspend / resume control
 */
static int acpi_idle_suspend;

int acpi_processor_suspend(struct acpi_device * device, pm_message_t state)
{
	acpi_idle_suspend = 1;
	return 0;
}

int acpi_processor_resume(struct acpi_device * device)
{
	acpi_idle_suspend = 0;
	return 0;
}

#if defined (CONFIG_GENERIC_TIME) && defined (CONFIG_X86)
static int tsc_halts_in_c(int state)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_AMD:
#ifdef CONFIG_PM_SLEEP
static u32 saved_bm_rld;

static int acpi_processor_suspend(void)
{
	acpi_read_bit_register(ACPI_BITREG_BUS_MASTER_RLD, &saved_bm_rld);
	return 0;
}

static void acpi_processor_resume(void)
{
	u32 resumed_bm_rld = 0;

	acpi_read_bit_register(ACPI_BITREG_BUS_MASTER_RLD, &resumed_bm_rld);
	if (resumed_bm_rld == saved_bm_rld)
		return;

	acpi_write_bit_register(ACPI_BITREG_BUS_MASTER_RLD, saved_bm_rld);
}

static struct syscore_ops acpi_processor_syscore_ops = {
	.suspend = acpi_processor_suspend,
	.resume = acpi_processor_resume,
};

void acpi_processor_syscore_init(void)
{
	register_syscore_ops(&acpi_processor_syscore_ops);
}

void acpi_processor_syscore_exit(void)
{
	unregister_syscore_ops(&acpi_processor_syscore_ops);
}
#endif /* CONFIG_PM_SLEEP */

#if defined(CONFIG_X86)
static void tsc_check_state(int state)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_INTEL:
		/*
		 * AMD Fam10h TSC will tick in all
		 * C/P/S0/S1 states when this bit is set.
		 */
		if (boot_cpu_has(X86_FEATURE_CONSTANT_TSC))
			return 0;
		/*FALL THROUGH*/
	case X86_VENDOR_INTEL:
		/* Several cases known where TSC halts in C2 too */
	default:
		return state > ACPI_STATE_C1;
	}
}
#endif

#ifndef CONFIG_CPU_IDLE
static void acpi_processor_idle(void)
{
	struct acpi_processor *pr = NULL;
	struct acpi_processor_cx *cx = NULL;
	struct acpi_processor_cx *next_state = NULL;
	int sleep_ticks = 0;
	u32 t1, t2 = 0;

	/*
	 * Interrupts must be disabled during bus mastering calculations and
	 * for C2/C3 transitions.
	 */
	local_irq_disable();

	pr = __get_cpu_var(processors);
	if (!pr) {
		local_irq_enable();
		return;
	}

	/*
	 * Check whether we truly need to go idle, or should
	 * reschedule:
	 */
	if (unlikely(need_resched())) {
		local_irq_enable();
		return;
	}

	cx = pr->power.state;
	if (!cx || acpi_idle_suspend) {
		if (pm_idle_save) {
			pm_idle_save(); /* enables IRQs */
		} else {
			acpi_safe_halt();
			local_irq_enable();
		}

		return;
	}

	/*
	 * Check BM Activity
	 * -----------------
	 * Check for bus mastering activity (if required), record, and check
	 * for demotion.
	 */
	if (pr->flags.bm_check) {
		u32 bm_status = 0;
		unsigned long diff = jiffies - pr->power.bm_check_timestamp;

		if (diff > 31)
			diff = 31;

		pr->power.bm_activity <<= diff;

		acpi_get_register(ACPI_BITREG_BUS_MASTER_STATUS, &bm_status);
		if (bm_status) {
			pr->power.bm_activity |= 0x1;
			acpi_set_register(ACPI_BITREG_BUS_MASTER_STATUS, 1);
		}
		/*
		 * PIIX4 Erratum #18: Note that BM_STS doesn't always reflect
		 * the true state of bus mastering activity; forcing us to
		 * manually check the BMIDEA bit of each IDE channel.
		 */
		else if (errata.piix4.bmisx) {
			if ((inb_p(errata.piix4.bmisx + 0x02) & 0x01)
			    || (inb_p(errata.piix4.bmisx + 0x0A) & 0x01))
				pr->power.bm_activity |= 0x1;
		}

		pr->power.bm_check_timestamp = jiffies;

		/*
		 * If bus mastering is or was active this jiffy, demote
		 * to avoid a faulty transition.  Note that the processor
		 * won't enter a low-power state during this call (to this
		 * function) but should upon the next.
		 *
		 * TBD: A better policy might be to fallback to the demotion
		 *      state (use it for this quantum only) istead of
		 *      demoting -- and rely on duration as our sole demotion
		 *      qualification.  This may, however, introduce DMA
		 *      issues (e.g. floppy DMA transfer overrun/underrun).
		 */
		if ((pr->power.bm_activity & 0x1) &&
		    cx->demotion.threshold.bm) {
			local_irq_enable();
			next_state = cx->demotion.state;
			goto end;
		}
	}

#ifdef CONFIG_HOTPLUG_CPU
	/*
	 * Check for P_LVL2_UP flag before entering C2 and above on
	 * an SMP system. We do it here instead of doing it at _CST/P_LVL
	 * detection phase, to work cleanly with logical CPU hotplug.
	 */
	if ((cx->type != ACPI_STATE_C1) && (num_online_cpus() > 1) &&
	    !pr->flags.has_cst && !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED))
		cx = &pr->power.states[ACPI_STATE_C1];
#endif

	/*
	 * Sleep:
	 * ------
	 * Invoke the current Cx state to put the processor to sleep.
	 */
	if (cx->type == ACPI_STATE_C2 || cx->type == ACPI_STATE_C3) {
		current_thread_info()->status &= ~TS_POLLING;
		/*
		 * TS_POLLING-cleared state must be visible before we
		 * test NEED_RESCHED:
		 */
		smp_mb();
		if (need_resched()) {
			current_thread_info()->status |= TS_POLLING;
			local_irq_enable();
			return;
		}
	}

	switch (cx->type) {

	case ACPI_STATE_C1:
		/*
		 * Invoke C1.
		 * Use the appropriate idle routine, the one that would
		 * be used without acpi C-states.
		 */
		if (pm_idle_save) {
			pm_idle_save(); /* enables IRQs */
		} else {
			acpi_safe_halt();
			local_irq_enable();
		}

		/*
		 * TBD: Can't get time duration while in C1, as resumes
		 *      go to an ISR rather than here.  Need to instrument
		 *      base interrupt handler.
		 *
		 * Note: the TSC better not stop in C1, sched_clock() will
		 *       skew otherwise.
		 */
		sleep_ticks = 0xFFFFFFFF;

		break;

	case ACPI_STATE_C2:
		/* Get start time (ticks) */
		t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
		/* Tell the scheduler that we are going deep-idle: */
		sched_clock_idle_sleep_event();
		/* Invoke C2 */
		acpi_state_timer_broadcast(pr, cx, 1);
		acpi_cstate_enter(cx);
		/* Get end time (ticks) */
		t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);

#if defined (CONFIG_GENERIC_TIME) && defined (CONFIG_X86)
		/* TSC halts in C2, so notify users */
		if (tsc_halts_in_c(ACPI_STATE_C2))
			mark_tsc_unstable("possible TSC halt in C2");
#endif
		/* Compute time (ticks) that we were actually asleep */
		sleep_ticks = ticks_elapsed(t1, t2);

		/* Tell the scheduler how much we idled: */
		sched_clock_idle_wakeup_event(sleep_ticks*PM_TIMER_TICK_NS);

		/* Re-enable interrupts */
		local_irq_enable();
		/* Do not account our idle-switching overhead: */
		sleep_ticks -= cx->latency_ticks + C2_OVERHEAD;

		current_thread_info()->status |= TS_POLLING;
		acpi_state_timer_broadcast(pr, cx, 0);
		break;

	case ACPI_STATE_C3:
		acpi_unlazy_tlb(smp_processor_id());
		/*
		 * Must be done before busmaster disable as we might
		 * need to access HPET !
		 */
		acpi_state_timer_broadcast(pr, cx, 1);
		/*
		 * disable bus master
		 * bm_check implies we need ARB_DIS
		 * !bm_check implies we need cache flush
		 * bm_control implies whether we can do ARB_DIS
		 *
		 * That leaves a case where bm_check is set and bm_control is
		 * not set. In that case we cannot do much, we enter C3
		 * without doing anything.
		 */
		if (pr->flags.bm_check && pr->flags.bm_control) {
			if (atomic_inc_return(&c3_cpu_count) ==
			    num_online_cpus()) {
				/*
				 * All CPUs are trying to go to C3
				 * Disable bus master arbitration
				 */
				acpi_set_register(ACPI_BITREG_ARB_DISABLE, 1);
			}
		} else if (!pr->flags.bm_check) {
			/* SMP with no shared cache... Invalidate cache  */
			ACPI_FLUSH_CPU_CACHE();
		}

		/* Get start time (ticks) */
		t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
		/* Invoke C3 */
		/* Tell the scheduler that we are going deep-idle: */
		sched_clock_idle_sleep_event();
		acpi_cstate_enter(cx);
		/* Get end time (ticks) */
		t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);
		if (pr->flags.bm_check && pr->flags.bm_control) {
			/* Enable bus master arbitration */
			atomic_dec(&c3_cpu_count);
			acpi_set_register(ACPI_BITREG_ARB_DISABLE, 0);
		}

#if defined (CONFIG_GENERIC_TIME) && defined (CONFIG_X86)
		/* TSC halts in C3, so notify users */
		if (tsc_halts_in_c(ACPI_STATE_C3))
			mark_tsc_unstable("TSC halts in C3");
#endif
		/* Compute time (ticks) that we were actually asleep */
		sleep_ticks = ticks_elapsed(t1, t2);
		/* Tell the scheduler how much we idled: */
		sched_clock_idle_wakeup_event(sleep_ticks*PM_TIMER_TICK_NS);

		/* Re-enable interrupts */
		local_irq_enable();
		/* Do not account our idle-switching overhead: */
		sleep_ticks -= cx->latency_ticks + C3_OVERHEAD;

		current_thread_info()->status |= TS_POLLING;
		acpi_state_timer_broadcast(pr, cx, 0);
		break;

	default:
		local_irq_enable();
		return;
	}
	cx->usage++;
	if ((cx->type != ACPI_STATE_C1) && (sleep_ticks > 0))
		cx->time += sleep_ticks;

	next_state = pr->power.state;

#ifdef CONFIG_HOTPLUG_CPU
	/* Don't do promotion/demotion */
	if ((cx->type == ACPI_STATE_C1) && (num_online_cpus() > 1) &&
	    !pr->flags.has_cst && !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED)) {
		next_state = cx;
		goto end;
	}
#endif

	/*
	 * Promotion?
	 * ----------
	 * Track the number of longs (time asleep is greater than threshold)
	 * and promote when the count threshold is reached.  Note that bus
	 * mastering activity may prevent promotions.
	 * Do not promote above max_cstate.
	 */
	if (cx->promotion.state &&
	    ((cx->promotion.state - pr->power.states) <= max_cstate)) {
		if (sleep_ticks > cx->promotion.threshold.ticks &&
		  cx->promotion.state->latency <=
				pm_qos_requirement(PM_QOS_CPU_DMA_LATENCY)) {
			cx->promotion.count++;
			cx->demotion.count = 0;
			if (cx->promotion.count >=
			    cx->promotion.threshold.count) {
				if (pr->flags.bm_check) {
					if (!
					    (pr->power.bm_activity & cx->
					     promotion.threshold.bm)) {
						next_state =
						    cx->promotion.state;
						goto end;
					}
				} else {
					next_state = cx->promotion.state;
					goto end;
				}
			}
		}
	}

	/*
	 * Demotion?
	 * ---------
	 * Track the number of shorts (time asleep is less than time threshold)
	 * and demote when the usage threshold is reached.
	 */
	if (cx->demotion.state) {
		if (sleep_ticks < cx->demotion.threshold.ticks) {
			cx->demotion.count++;
			cx->promotion.count = 0;
			if (cx->demotion.count >= cx->demotion.threshold.count) {
				next_state = cx->demotion.state;
				goto end;
			}
		}
	}

      end:
	/*
	 * Demote if current state exceeds max_cstate
	 * or if the latency of the current state is unacceptable
	 */
	if ((pr->power.state - pr->power.states) > max_cstate ||
		pr->power.state->latency >
				pm_qos_requirement(PM_QOS_CPU_DMA_LATENCY)) {
		if (cx->demotion.state)
			next_state = cx->demotion.state;
	}

	/*
	 * New Cx State?
	 * -------------
	 * If we're going to start using a new Cx state we must clean up
	 * from the previous and prepare to use the new.
	 */
	if (next_state != pr->power.state)
		acpi_processor_power_activate(pr, next_state);
}

static int acpi_processor_set_power_policy(struct acpi_processor *pr)
{
	unsigned int i;
	unsigned int state_is_set = 0;
	struct acpi_processor_cx *lower = NULL;
	struct acpi_processor_cx *higher = NULL;
	struct acpi_processor_cx *cx;


	if (!pr)
		return -EINVAL;

	/*
	 * This function sets the default Cx state policy (OS idle handler).
	 * Our scheme is to promote quickly to C2 but more conservatively
	 * to C3.  We're favoring C2  for its characteristics of low latency
	 * (quick response), good power savings, and ability to allow bus
	 * mastering activity.  Note that the Cx state policy is completely
	 * customizable and can be altered dynamically.
	 */

	/* startup state */
	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER; i++) {
		cx = &pr->power.states[i];
		if (!cx->valid)
			continue;

		if (!state_is_set)
			pr->power.state = cx;
		state_is_set++;
		break;
	}

	if (!state_is_set)
		return -ENODEV;

	/* demotion */
	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER; i++) {
		cx = &pr->power.states[i];
		if (!cx->valid)
			continue;

		if (lower) {
			cx->demotion.state = lower;
			cx->demotion.threshold.ticks = cx->latency_ticks;
			cx->demotion.threshold.count = 1;
			if (cx->type == ACPI_STATE_C3)
				cx->demotion.threshold.bm = bm_history;
		}

		lower = cx;
	}

	/* promotion */
	for (i = (ACPI_PROCESSOR_MAX_POWER - 1); i > 0; i--) {
		cx = &pr->power.states[i];
		if (!cx->valid)
			continue;

		if (higher) {
			cx->promotion.state = higher;
			cx->promotion.threshold.ticks = cx->latency_ticks;
			if (cx->type >= ACPI_STATE_C2)
				cx->promotion.threshold.count = 4;
			else
				cx->promotion.threshold.count = 10;
			if (higher->type == ACPI_STATE_C3)
				cx->promotion.threshold.bm = bm_history;
		}

		higher = cx;
	}

	return 0;
}
#endif /* !CONFIG_CPU_IDLE */

static int acpi_processor_get_power_info_fadt(struct acpi_processor *pr)
{

	if (!pr)
		return -EINVAL;

		if (boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
			return;

		/*FALL THROUGH*/
	default:
		/* TSC could halt in idle, so notify users */
		if (state > ACPI_STATE_C1)
			mark_tsc_unstable("TSC halts in idle");
	}
}
#else
static void tsc_check_state(int state) { return; }
#endif

static int acpi_processor_get_power_info_fadt(struct acpi_processor *pr)
{

	if (!pr->pblk)
		return -ENODEV;

	/* if info is obtained from pblk/fadt, type equals state */
	pr->power.states[ACPI_STATE_C2].type = ACPI_STATE_C2;
	pr->power.states[ACPI_STATE_C3].type = ACPI_STATE_C3;

#ifndef CONFIG_HOTPLUG_CPU
	/*
	 * Check for P_LVL2_UP flag before entering C2 and above on
	 * an SMP system.
	 */
	if ((num_online_cpus() > 1) &&
	    !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED))
		return -ENODEV;
#endif

	/* determine C2 and C3 address from pblk */
	pr->power.states[ACPI_STATE_C2].address = pr->pblk + 4;
	pr->power.states[ACPI_STATE_C3].address = pr->pblk + 5;

	/* determine latencies from FADT */
	pr->power.states[ACPI_STATE_C2].latency = acpi_gbl_FADT.C2latency;
	pr->power.states[ACPI_STATE_C3].latency = acpi_gbl_FADT.C3latency;
	pr->power.states[ACPI_STATE_C2].latency = acpi_gbl_FADT.c2_latency;
	pr->power.states[ACPI_STATE_C3].latency = acpi_gbl_FADT.c3_latency;

	/*
	 * FADT specified C2 latency must be less than or equal to
	 * 100 microseconds.
	 */
	if (acpi_gbl_FADT.c2_latency > ACPI_PROCESSOR_MAX_C2_LATENCY) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			"C2 latency too large [%d]\n", acpi_gbl_FADT.c2_latency));
		/* invalidate C2 */
		pr->power.states[ACPI_STATE_C2].address = 0;
	}

	/*
	 * FADT supplied C3 latency must be less than or equal to
	 * 1000 microseconds.
	 */
	if (acpi_gbl_FADT.c3_latency > ACPI_PROCESSOR_MAX_C3_LATENCY) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			"C3 latency too large [%d]\n", acpi_gbl_FADT.c3_latency));
		/* invalidate C3 */
		pr->power.states[ACPI_STATE_C3].address = 0;
	}

	ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			  "lvl2[0x%08x] lvl3[0x%08x]\n",
			  pr->power.states[ACPI_STATE_C2].address,
			  pr->power.states[ACPI_STATE_C3].address));

	return 0;
}

static int acpi_processor_get_power_info_default(struct acpi_processor *pr)
{
	if (!pr->power.states[ACPI_STATE_C1].valid) {
		/* set the first C-State to C1 */
		/* all processors need to support C1 */
		pr->power.states[ACPI_STATE_C1].type = ACPI_STATE_C1;
		pr->power.states[ACPI_STATE_C1].valid = 1;
		pr->power.states[ACPI_STATE_C1].entry_method = ACPI_CSTATE_HALT;
	}
	/* the C0 state only exists as a filler in our array */
	pr->power.states[ACPI_STATE_C0].valid = 1;
	return 0;
}

static int acpi_processor_get_power_info_cst(struct acpi_processor *pr)
{
	acpi_status status = 0;
	acpi_integer count;
	int current_count;
	int i;
	acpi_status status;
	u64 count;
	int current_count;
	int i, ret = 0;
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	union acpi_object *cst;

	if (nocst)
		return -ENODEV;

	current_count = 0;

	status = acpi_evaluate_object(pr->handle, "_CST", NULL, &buffer);
	if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO, "No _CST, giving up\n"));
		return -ENODEV;
	}

	cst = buffer.pointer;

	/* There must be at least 2 elements */
	if (!cst || (cst->type != ACPI_TYPE_PACKAGE) || cst->package.count < 2) {
		printk(KERN_ERR PREFIX "not enough elements in _CST\n");
		status = -EFAULT;
		pr_err("not enough elements in _CST\n");
		ret = -EFAULT;
		goto end;
	}

	count = cst->package.elements[0].integer.value;

	/* Validate number of power states. */
	if (count < 1 || count != cst->package.count - 1) {
		printk(KERN_ERR PREFIX "count given by _CST is not valid\n");
		status = -EFAULT;
		pr_err("count given by _CST is not valid\n");
		ret = -EFAULT;
		goto end;
	}

	/* Tell driver that at least _CST is supported. */
	pr->flags.has_cst = 1;

	for (i = 1; i <= count; i++) {
		union acpi_object *element;
		union acpi_object *obj;
		struct acpi_power_register *reg;
		struct acpi_processor_cx cx;

		memset(&cx, 0, sizeof(cx));

		element = &(cst->package.elements[i]);
		if (element->type != ACPI_TYPE_PACKAGE)
			continue;

		if (element->package.count != 4)
			continue;

		obj = &(element->package.elements[0]);

		if (obj->type != ACPI_TYPE_BUFFER)
			continue;

		reg = (struct acpi_power_register *)obj->buffer.pointer;

		if (reg->space_id != ACPI_ADR_SPACE_SYSTEM_IO &&
		    (reg->space_id != ACPI_ADR_SPACE_FIXED_HARDWARE))
			continue;

		/* There should be an easy way to extract an integer... */
		obj = &(element->package.elements[1]);
		if (obj->type != ACPI_TYPE_INTEGER)
			continue;

		cx.type = obj->integer.value;
		/*
		 * Some buggy BIOSes won't list C1 in _CST -
		 * Let acpi_processor_get_power_info_default() handle them later
		 */
		if (i == 1 && cx.type != ACPI_STATE_C1)
			current_count++;

		cx.address = reg->address;
		cx.index = current_count + 1;

		cx.entry_method = ACPI_CSTATE_SYSTEMIO;
		if (reg->space_id == ACPI_ADR_SPACE_FIXED_HARDWARE) {
			if (acpi_processor_ffh_cstate_probe
					(pr->id, &cx, reg) == 0) {
				cx.entry_method = ACPI_CSTATE_FFH;
			} else if (cx.type == ACPI_STATE_C1) {
				/*
				 * C1 is a special case where FIXED_HARDWARE
				 * can be handled in non-MWAIT way as well.
				 * In that case, save this _CST entry info.
				 * Otherwise, ignore this info and continue.
				 */
				cx.entry_method = ACPI_CSTATE_HALT;
				snprintf(cx.desc, ACPI_CX_DESC_LEN, "ACPI HLT");
			} else {
				continue;
			}
			if (cx.type == ACPI_STATE_C1 &&
					(idle_halt || idle_nomwait)) {
			    (boot_option_idle_override == IDLE_NOMWAIT)) {
				/*
				 * In most cases the C1 space_id obtained from
				 * _CST object is FIXED_HARDWARE access mode.
				 * But when the option of idle=halt is added,
				 * the entry_method type should be changed from
				 * CSTATE_FFH to CSTATE_HALT.
				 * When the option of idle=nomwait is added,
				 * the C1 entry_method type should be
				 * CSTATE_HALT.
				 */
				cx.entry_method = ACPI_CSTATE_HALT;
				snprintf(cx.desc, ACPI_CX_DESC_LEN, "ACPI HLT");
			}
		} else {
			snprintf(cx.desc, ACPI_CX_DESC_LEN, "ACPI IOPORT 0x%x",
				 cx.address);
		}

		if (cx.type == ACPI_STATE_C1) {
			cx.valid = 1;
		}

		obj = &(element->package.elements[2]);
		if (obj->type != ACPI_TYPE_INTEGER)
			continue;

		cx.latency = obj->integer.value;

		obj = &(element->package.elements[3]);
		if (obj->type != ACPI_TYPE_INTEGER)
			continue;

		cx.power = obj->integer.value;

		current_count++;
		memcpy(&(pr->power.states[current_count]), &cx, sizeof(cx));

		/*
		 * We support total ACPI_PROCESSOR_MAX_POWER - 1
		 * (From 1 through ACPI_PROCESSOR_MAX_POWER - 1)
		 */
		if (current_count >= (ACPI_PROCESSOR_MAX_POWER - 1)) {
			pr_warn("Limiting number of power states to max (%d)\n",
				ACPI_PROCESSOR_MAX_POWER);
			pr_warn("Please increase ACPI_PROCESSOR_MAX_POWER if needed.\n");
			break;
		}
	}

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Found %d power states\n",
			  current_count));

	/* Validate number of power states discovered */
	if (current_count < 2)
		status = -EFAULT;
		ret = -EFAULT;

      end:
	kfree(buffer.pointer);

	return status;
}

static void acpi_processor_power_verify_c2(struct acpi_processor_cx *cx)
{

	if (!cx->address)
		return;

	/*
	 * C2 latency must be less than or equal to 100
	 * microseconds.
	 */
	else if (cx->latency > ACPI_PROCESSOR_MAX_C2_LATENCY) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "latency too large [%d]\n", cx->latency));
		return;
	}

	/*
	 * Otherwise we've met all of our C2 requirements.
	 * Normalize the C2 latency to expidite policy
	 */
	cx->valid = 1;

#ifndef CONFIG_CPU_IDLE
	cx->latency_ticks = US_TO_PM_TIMER_TICKS(cx->latency);
#else
	cx->latency_ticks = cx->latency;
#endif

	return;
	return ret;
}

static void acpi_processor_power_verify_c3(struct acpi_processor *pr,
					   struct acpi_processor_cx *cx)
{
	static int bm_check_flag;
	static int bm_check_flag = -1;
	static int bm_control_flag = -1;


	if (!cx->address)
		return;

	/*
	 * C3 latency must be less than or equal to 1000
	 * microseconds.
	 */
	else if (cx->latency > ACPI_PROCESSOR_MAX_C3_LATENCY) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "latency too large [%d]\n", cx->latency));
		return;
	}

	/*
	 * PIIX4 Erratum #18: We don't support C3 when Type-F (fast)
	 * DMA transfers are used by any ISA device to avoid livelock.
	 * Note that we could disable Type-F DMA (as recommended by
	 * the erratum), but this is known to disrupt certain ISA
	 * devices thus we take the conservative approach.
	 */
	else if (errata.piix4.fdma) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "C3 not supported on PIIX4 with Type-F DMA\n"));
		return;
	}

	/* All the logic here assumes flags.bm_check is same across all CPUs */
	if (!bm_check_flag) {
		/* Determine whether bm_check is needed based on CPU  */
		acpi_processor_power_init_bm_check(&(pr->flags), pr->id);
		bm_check_flag = pr->flags.bm_check;
	} else {
		pr->flags.bm_check = bm_check_flag;
	if (bm_check_flag == -1) {
		/* Determine whether bm_check is needed based on CPU  */
		acpi_processor_power_init_bm_check(&(pr->flags), pr->id);
		bm_check_flag = pr->flags.bm_check;
		bm_control_flag = pr->flags.bm_control;
	} else {
		pr->flags.bm_check = bm_check_flag;
		pr->flags.bm_control = bm_control_flag;
	}

	if (pr->flags.bm_check) {
		if (!pr->flags.bm_control) {
			if (pr->flags.has_cst != 1) {
				/* bus mastering control is necessary */
				ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					"C3 support requires BM control\n"));
				return;
			} else {
				/* Here we enter C3 without bus mastering */
				ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					"C3 support without BM control\n"));
			}
		}
	} else {
		/*
		 * WBINVD should be set in fadt, for C3 state to be
		 * supported on when bm_check is not required.
		 */
		if (!(acpi_gbl_FADT.flags & ACPI_FADT_WBINVD)) {
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "Cache invalidation should work properly"
					  " for C3 to be enabled on SMP systems\n"));
			return;
		}
		acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
	}

	/*
	 * Otherwise we've met all of our C3 requirements.
	 * Normalize the C3 latency to expidite policy.  Enable
	 * checking of bus mastering status (bm_check) so we can
	 * use this in our C3 policy
	 */
	cx->valid = 1;

#ifndef CONFIG_CPU_IDLE
	cx->latency_ticks = US_TO_PM_TIMER_TICKS(cx->latency);
#else
	cx->latency_ticks = cx->latency;
#endif
	/*
	 * On older chipsets, BM_RLD needs to be set
	 * in order for Bus Master activity to wake the
	 * system from C3.  Newer chipsets handle DMA
	 * during C3 automatically and BM_RLD is a NOP.
	 * In either case, the proper way to
	 * handle BM_RLD is to set it and leave it set.
	 */
	acpi_write_bit_register(ACPI_BITREG_BUS_MASTER_RLD, 1);

	return;
}

static int acpi_processor_power_verify(struct acpi_processor *pr)
{
	unsigned int i;
	unsigned int working = 0;

	pr->power.timer_broadcast_on_state = INT_MAX;

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER; i++) {
	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		struct acpi_processor_cx *cx = &pr->power.states[i];

		switch (cx->type) {
		case ACPI_STATE_C1:
			cx->valid = 1;
			break;

		case ACPI_STATE_C2:
			acpi_processor_power_verify_c2(cx);
			if (cx->valid)
				acpi_timer_check_state(i, pr, cx);
			if (!cx->address)
				break;
			cx->valid = 1;
			break;

		case ACPI_STATE_C3:
			acpi_processor_power_verify_c3(pr, cx);
			if (cx->valid)
				acpi_timer_check_state(i, pr, cx);
			break;
		}

		if (cx->valid)
			working++;
	}

	acpi_propagate_timer_broadcast(pr);
			break;
		}
		if (!cx->valid)
			continue;

		lapic_timer_check_state(i, pr, cx);
		tsc_check_state(cx->type);
		working++;
	}

	lapic_timer_propagate_broadcast(pr);

	return (working);
}

static int acpi_processor_get_cstate_info(struct acpi_processor *pr)
{
	unsigned int i;
	int result;


	/* NOTE: the idle thread may not be running while calling
	 * this function */

	/* Zero initialize all the C-states info. */
	memset(pr->power.states, 0, sizeof(pr->power.states));

	result = acpi_processor_get_power_info_cst(pr);
	if (result == -ENODEV)
		result = acpi_processor_get_power_info_fadt(pr);

	if (result)
		return result;

	acpi_processor_get_power_info_default(pr);

	pr->power.count = acpi_processor_power_verify(pr);

#ifndef CONFIG_CPU_IDLE
	/*
	 * Set Default Policy
	 * ------------------
	 * Now that we know which states are supported, set the default
	 * policy.  Note that this policy can be changed dynamically
	 * (e.g. encourage deeper sleeps to conserve battery life when
	 * not on AC).
	 */
	result = acpi_processor_set_power_policy(pr);
	if (result)
		return result;
#endif

	/*
	 * if one state of type C2 or C3 is available, mark this
	 * CPU as being "idle manageable"
	 */
	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER; i++) {
		if (pr->power.states[i].valid) {
			pr->power.count = i;
			if (pr->power.states[i].type >= ACPI_STATE_C2)
				pr->flags.power = 1;
		}
	}

	return 0;
}

static int acpi_processor_power_seq_show(struct seq_file *seq, void *offset)
{
	struct acpi_processor *pr = seq->private;
	unsigned int i;


	if (!pr)
		goto end;

	seq_printf(seq, "active state:            C%zd\n"
		   "max_cstate:              C%d\n"
		   "bus master activity:     %08x\n"
		   "maximum allowed latency: %d usec\n",
		   pr->power.state ? pr->power.state - pr->power.states : 0,
		   max_cstate, (unsigned)pr->power.bm_activity,
		   pm_qos_requirement(PM_QOS_CPU_DMA_LATENCY));

	seq_puts(seq, "states:\n");

	for (i = 1; i <= pr->power.count; i++) {
		seq_printf(seq, "   %cC%d:                  ",
			   (&pr->power.states[i] ==
			    pr->power.state ? '*' : ' '), i);

		if (!pr->power.states[i].valid) {
			seq_puts(seq, "<not supported>\n");
			continue;
		}

		switch (pr->power.states[i].type) {
		case ACPI_STATE_C1:
			seq_printf(seq, "type[C1] ");
			break;
		case ACPI_STATE_C2:
			seq_printf(seq, "type[C2] ");
			break;
		case ACPI_STATE_C3:
			seq_printf(seq, "type[C3] ");
			break;
		default:
			seq_printf(seq, "type[--] ");
			break;
		}

		if (pr->power.states[i].promotion.state)
			seq_printf(seq, "promotion[C%zd] ",
				   (pr->power.states[i].promotion.state -
				    pr->power.states));
		else
			seq_puts(seq, "promotion[--] ");

		if (pr->power.states[i].demotion.state)
			seq_printf(seq, "demotion[C%zd] ",
				   (pr->power.states[i].demotion.state -
				    pr->power.states));
		else
			seq_puts(seq, "demotion[--] ");

		seq_printf(seq, "latency[%03d] usage[%08d] duration[%020llu]\n",
			   pr->power.states[i].latency,
			   pr->power.states[i].usage,
			   (unsigned long long)pr->power.states[i].time);
	}

      end:
	return 0;
}

static int acpi_processor_power_open_fs(struct inode *inode, struct file *file)
{
	return single_open(file, acpi_processor_power_seq_show,
			   PDE(inode)->data);
}

static const struct file_operations acpi_processor_power_fops = {
	.owner = THIS_MODULE,
	.open = acpi_processor_power_open_fs,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

#ifndef CONFIG_CPU_IDLE

int acpi_processor_cst_has_changed(struct acpi_processor *pr)
{
	int result = 0;

	if (boot_option_idle_override)
		return 0;

	if (!pr)
		return -EINVAL;

	if (nocst) {
		return -ENODEV;
	}

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	/*
	 * Fall back to the default idle loop, when pm_idle_save had
	 * been initialized.
	 */
	if (pm_idle_save) {
		pm_idle = pm_idle_save;
		/* Relies on interrupts forcing exit from idle. */
		synchronize_sched();
	}

	pr->flags.power = 0;
	result = acpi_processor_get_power_info(pr);
	if ((pr->flags.power == 1) && (pr->flags.power_setup_done))
		pm_idle = acpi_processor_idle;

	return result;
}

#ifdef CONFIG_SMP
static void smp_callback(void *v)
{
	/* we already woke the CPU up, nothing more to do */
}

/*
 * This function gets called when a part of the kernel has a new latency
 * requirement.  This means we need to get all processors out of their C-state,
 * and then recalculate a new suitable C-state. Just do a cross-cpu IPI; that
 * wakes them all right up.
 */
static int acpi_processor_latency_notify(struct notifier_block *b,
		unsigned long l, void *v)
{
	smp_call_function(smp_callback, NULL, 1);
	return NOTIFY_OK;
}

static struct notifier_block acpi_processor_latency_notifier = {
	.notifier_call = acpi_processor_latency_notify,
};

#endif

#else /* CONFIG_CPU_IDLE */

/**
 * acpi_idle_bm_check - checks if bus master activity was detected
 */
static int acpi_idle_bm_check(void)
{
	u32 bm_status = 0;

	acpi_get_register(ACPI_BITREG_BUS_MASTER_STATUS, &bm_status);
	if (bm_status)
		acpi_set_register(ACPI_BITREG_BUS_MASTER_STATUS, 1);
	if (bm_check_disable)
		return 0;

	acpi_read_bit_register(ACPI_BITREG_BUS_MASTER_STATUS, &bm_status);
	if (bm_status)
		acpi_write_bit_register(ACPI_BITREG_BUS_MASTER_STATUS, 1);
	/*
	 * PIIX4 Erratum #18: Note that BM_STS doesn't always reflect
	 * the true state of bus mastering activity; forcing us to
	 * manually check the BMIDEA bit of each IDE channel.
	 */
	else if (errata.piix4.bmisx) {
		if ((inb_p(errata.piix4.bmisx + 0x02) & 0x01)
		    || (inb_p(errata.piix4.bmisx + 0x0A) & 0x01))
			bm_status = 1;
	}
	return bm_status;
}

/**
 * acpi_idle_update_bm_rld - updates the BM_RLD bit depending on target state
 * @pr: the processor
 * @target: the new target state
 */
static inline void acpi_idle_update_bm_rld(struct acpi_processor *pr,
					   struct acpi_processor_cx *target)
{
	if (pr->flags.bm_rld_set && target->type != ACPI_STATE_C3) {
		acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
		pr->flags.bm_rld_set = 0;
	}

	if (!pr->flags.bm_rld_set && target->type == ACPI_STATE_C3) {
		acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 1);
		pr->flags.bm_rld_set = 1;
	}
}

/**
 * acpi_idle_do_entry - a helper function that does C2 and C3 type entry
 * acpi_idle_do_entry - enter idle state using the appropriate method
 * @cx: cstate data
 *
 * Caller disables interrupt before call and enables interrupt after return.
 */
static inline void acpi_idle_do_entry(struct acpi_processor_cx *cx)
{
	/* Don't trace irqs off for idle */
	stop_critical_timings();
static void acpi_idle_do_entry(struct acpi_processor_cx *cx)
static void __cpuidle acpi_idle_do_entry(struct acpi_processor_cx *cx)
{
	if (cx->entry_method == ACPI_CSTATE_FFH) {
		/* Call into architectural FFH based C-state */
		acpi_processor_ffh_cstate_enter(cx);
	} else if (cx->entry_method == ACPI_CSTATE_HALT) {
		acpi_safe_halt();
	} else {
		int unused;
		/* IO port based C-state */
		inb(cx->address);
		/* Dummy wait op - must do something useless after P_LVL2 read
		   because chipsets cannot guarantee that STPCLK# signal
		   gets asserted in time to freeze execution properly. */
		unused = inl(acpi_gbl_FADT.xpm_timer_block.address);
	}
	start_critical_timings();
}

/**
 * acpi_idle_enter_c1 - enters an ACPI C1 state-type
 * @dev: the target CPU
 * @state: the state data
 *
 * This is equivalent to the HALT instruction.
 */
static int acpi_idle_enter_c1(struct cpuidle_device *dev,
			      struct cpuidle_state *state)
{
	u32 t1, t2;
	struct acpi_processor *pr;
	struct acpi_processor_cx *cx = cpuidle_get_statedata(state);

	pr = __get_cpu_var(processors);

	if (unlikely(!pr))
		return 0;

	local_irq_disable();

	/* Do not access any ACPI IO ports in suspend path */
	if (acpi_idle_suspend) {
		acpi_safe_halt();
		local_irq_enable();
		return 0;
	}

	if (pr->flags.bm_check)
		acpi_idle_update_bm_rld(pr, cx);

	t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
	acpi_idle_do_entry(cx);
	t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);

	local_irq_enable();
	cx->usage++;

	return ticks_elapsed_in_us(t1, t2);
}

/**
 * acpi_idle_enter_simple - enters an ACPI state without BM handling
 * @dev: the target CPU
 * @state: the state data
 */
static int acpi_idle_enter_simple(struct cpuidle_device *dev,
				  struct cpuidle_state *state)
{
	struct acpi_processor *pr;
	struct acpi_processor_cx *cx = cpuidle_get_statedata(state);
	u32 t1, t2;
	int sleep_ticks = 0;

	pr = __get_cpu_var(processors);

	if (unlikely(!pr))
		return 0;

	if (acpi_idle_suspend)
		return(acpi_idle_enter_c1(dev, state));

	local_irq_disable();
	current_thread_info()->status &= ~TS_POLLING;
	/*
	 * TS_POLLING-cleared state must be visible before we test
	 * NEED_RESCHED:
	 */
	smp_mb();

	if (unlikely(need_resched())) {
		current_thread_info()->status |= TS_POLLING;
		local_irq_enable();
		return 0;
	}

	/*
	 * Must be done before busmaster disable as we might need to
	 * access HPET !
	 */
	acpi_state_timer_broadcast(pr, cx, 1);

	if (pr->flags.bm_check)
		acpi_idle_update_bm_rld(pr, cx);

	if (cx->type == ACPI_STATE_C3)
		ACPI_FLUSH_CPU_CACHE();

	t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
	/* Tell the scheduler that we are going deep-idle: */
	sched_clock_idle_sleep_event();
	acpi_idle_do_entry(cx);
	t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);

#if defined (CONFIG_GENERIC_TIME) && defined (CONFIG_X86)
	/* TSC could halt in idle, so notify users */
	if (tsc_halts_in_c(cx->type))
		mark_tsc_unstable("TSC halts in idle");;
#endif
	sleep_ticks = ticks_elapsed(t1, t2);

	/* Tell the scheduler how much we idled: */
	sched_clock_idle_wakeup_event(sleep_ticks*PM_TIMER_TICK_NS);

	local_irq_enable();
	current_thread_info()->status |= TS_POLLING;

	cx->usage++;

	acpi_state_timer_broadcast(pr, cx, 0);
	cx->time += sleep_ticks;
	return ticks_elapsed_in_us(t1, t2);
}

static int c3_cpu_count;
static DEFINE_SPINLOCK(c3_lock);

/**
 * acpi_idle_enter_bm - enters C3 with proper BM handling
 * @dev: the target CPU
 * @state: the state data
 *
 * If BM is detected, the deepest non-C3 idle state is entered instead.
 */
static int acpi_idle_enter_bm(struct cpuidle_device *dev,
			      struct cpuidle_state *state)
{
	struct acpi_processor *pr;
	struct acpi_processor_cx *cx = cpuidle_get_statedata(state);
	u32 t1, t2;
	int sleep_ticks = 0;

	pr = __get_cpu_var(processors);

	if (unlikely(!pr))
		return 0;

	if (acpi_idle_suspend)
		return(acpi_idle_enter_c1(dev, state));

	if (acpi_idle_bm_check()) {
		if (dev->safe_state) {
			return dev->safe_state->enter(dev, dev->safe_state);
		} else {
			local_irq_disable();
			acpi_safe_halt();
			local_irq_enable();
			return 0;
		}
	}

	local_irq_disable();
	current_thread_info()->status &= ~TS_POLLING;
	/*
	 * TS_POLLING-cleared state must be visible before we test
	 * NEED_RESCHED:
	 */
	smp_mb();

	if (unlikely(need_resched())) {
		current_thread_info()->status |= TS_POLLING;
		local_irq_enable();
		return 0;
	}

	acpi_unlazy_tlb(smp_processor_id());

	/* Tell the scheduler that we are going deep-idle: */
	sched_clock_idle_sleep_event();
		inl(acpi_gbl_FADT.xpm_timer_block.address);
	}
}

/**
 * acpi_idle_play_dead - enters an ACPI state for long-term idle (i.e. off-lining)
 * @dev: the target CPU
 * @index: the index of suggested state
 */
static int acpi_idle_play_dead(struct cpuidle_device *dev, int index)
{
	struct acpi_processor_cx *cx = per_cpu(acpi_cstate[index], dev->cpu);

	ACPI_FLUSH_CPU_CACHE();

	while (1) {

		if (cx->entry_method == ACPI_CSTATE_HALT)
			safe_halt();
		else if (cx->entry_method == ACPI_CSTATE_SYSTEMIO) {
			inb(cx->address);
			/* See comment in acpi_idle_do_entry() */
			inl(acpi_gbl_FADT.xpm_timer_block.address);
		} else
			return -ENODEV;
	}

	/* Never reached */
	return 0;
}

static bool acpi_idle_fallback_to_c1(struct acpi_processor *pr)
{
	return IS_ENABLED(CONFIG_HOTPLUG_CPU) && !pr->flags.has_cst &&
		!(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED);
}

static int c3_cpu_count;
static DEFINE_RAW_SPINLOCK(c3_lock);

/**
 * acpi_idle_enter_bm - enters C3 with proper BM handling
 * @pr: Target processor
 * @cx: Target state context
 * @timer_bc: Whether or not to change timer mode to broadcast
 */
static void acpi_idle_enter_bm(struct acpi_processor *pr,
			       struct acpi_processor_cx *cx, bool timer_bc)
{
	acpi_unlazy_tlb(smp_processor_id());

	/*
	 * Must be done before busmaster disable as we might need to
	 * access HPET !
	 */
	acpi_state_timer_broadcast(pr, cx, 1);

	acpi_idle_update_bm_rld(pr, cx);
	if (timer_bc)
		lapic_timer_state_broadcast(pr, cx, 1);

	/*
	 * disable bus master
	 * bm_check implies we need ARB_DIS
	 * !bm_check implies we need cache flush
	 * bm_control implies whether we can do ARB_DIS
	 *
	 * That leaves a case where bm_check is set and bm_control is
	 * not set. In that case we cannot do much, we enter C3
	 * without doing anything.
	 */
	if (pr->flags.bm_check && pr->flags.bm_control) {
		spin_lock(&c3_lock);
		c3_cpu_count++;
		/* Disable bus master arbitration when all CPUs are in C3 */
		if (c3_cpu_count == num_online_cpus())
			acpi_set_register(ACPI_BITREG_ARB_DISABLE, 1);
		spin_unlock(&c3_lock);
	} else if (!pr->flags.bm_check) {
		ACPI_FLUSH_CPU_CACHE();
	}

	t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
	acpi_idle_do_entry(cx);
	t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);

	/* Re-enable bus master arbitration */
	if (pr->flags.bm_check && pr->flags.bm_control) {
		spin_lock(&c3_lock);
		acpi_set_register(ACPI_BITREG_ARB_DISABLE, 0);
		c3_cpu_count--;
		spin_unlock(&c3_lock);
	}

#if defined (CONFIG_GENERIC_TIME) && defined (CONFIG_X86)
	/* TSC could halt in idle, so notify users */
	if (tsc_halts_in_c(ACPI_STATE_C3))
		mark_tsc_unstable("TSC halts in idle");
#endif
	sleep_ticks = ticks_elapsed(t1, t2);
	/* Tell the scheduler how much we idled: */
	sched_clock_idle_wakeup_event(sleep_ticks*PM_TIMER_TICK_NS);

	local_irq_enable();
	current_thread_info()->status |= TS_POLLING;

	cx->usage++;

	acpi_state_timer_broadcast(pr, cx, 0);
	cx->time += sleep_ticks;
	return ticks_elapsed_in_us(t1, t2);
	if (pr->flags.bm_control) {
		raw_spin_lock(&c3_lock);
		c3_cpu_count++;
		/* Disable bus master arbitration when all CPUs are in C3 */
		if (c3_cpu_count == num_online_cpus())
			acpi_write_bit_register(ACPI_BITREG_ARB_DISABLE, 1);
		raw_spin_unlock(&c3_lock);
	}

	acpi_idle_do_entry(cx);

	/* Re-enable bus master arbitration */
	if (pr->flags.bm_control) {
		raw_spin_lock(&c3_lock);
		acpi_write_bit_register(ACPI_BITREG_ARB_DISABLE, 0);
		c3_cpu_count--;
		raw_spin_unlock(&c3_lock);
	}

	if (timer_bc)
		lapic_timer_state_broadcast(pr, cx, 0);
}

static int acpi_idle_enter(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	struct acpi_processor_cx *cx = per_cpu(acpi_cstate[index], dev->cpu);
	struct acpi_processor *pr;

	pr = __this_cpu_read(processors);
	if (unlikely(!pr))
		return -EINVAL;

	if (cx->type != ACPI_STATE_C1) {
		if (acpi_idle_fallback_to_c1(pr) && num_online_cpus() > 1) {
			index = ACPI_IDLE_STATE_START;
			cx = per_cpu(acpi_cstate[index], dev->cpu);
		} else if (cx->type == ACPI_STATE_C3 && pr->flags.bm_check) {
			if (cx->bm_sts_skip || !acpi_idle_bm_check()) {
				acpi_idle_enter_bm(pr, cx, true);
				return index;
			} else if (drv->safe_state_index >= 0) {
				index = drv->safe_state_index;
				cx = per_cpu(acpi_cstate[index], dev->cpu);
			} else {
				acpi_safe_halt();
				return -EBUSY;
			}
		}
	}

	lapic_timer_state_broadcast(pr, cx, 1);

	if (cx->type == ACPI_STATE_C3)
		ACPI_FLUSH_CPU_CACHE();

	acpi_idle_do_entry(cx);

	lapic_timer_state_broadcast(pr, cx, 0);

	return index;
}

static void acpi_idle_enter_s2idle(struct cpuidle_device *dev,
				   struct cpuidle_driver *drv, int index)
{
	struct acpi_processor_cx *cx = per_cpu(acpi_cstate[index], dev->cpu);

	if (cx->type == ACPI_STATE_C3) {
		struct acpi_processor *pr = __this_cpu_read(processors);

		if (unlikely(!pr))
			return;

		if (pr->flags.bm_check) {
			acpi_idle_enter_bm(pr, cx, false);
			return;
		} else {
			ACPI_FLUSH_CPU_CACHE();
		}
	}
	acpi_idle_do_entry(cx);
}

struct cpuidle_driver acpi_idle_driver = {
	.name =		"acpi_idle",
	.owner =	THIS_MODULE,
};

/**
 * acpi_processor_setup_cpuidle - prepares and configures CPUIDLE
 * @pr: the ACPI processor
 */
static int acpi_processor_setup_cpuidle(struct acpi_processor *pr)
{
	int i, count = CPUIDLE_DRIVER_STATE_START;
	struct acpi_processor_cx *cx;
	struct cpuidle_state *state;
	struct cpuidle_device *dev = &pr->power.dev;
 * acpi_processor_setup_cpuidle_cx - prepares and configures CPUIDLE
 * device i.e. per-cpu data
 *
 * @pr: the ACPI processor
 * @dev : the cpuidle device
 */
static int acpi_processor_setup_cpuidle_cx(struct acpi_processor *pr,
					   struct cpuidle_device *dev)
{
	int i, count = ACPI_IDLE_STATE_START;
	struct acpi_processor_cx *cx;

	if (!pr->flags.power_setup_done)
		return -EINVAL;

	if (pr->flags.power == 0) {
		return -EINVAL;
	}

	dev->cpu = pr->id;
	for (i = 0; i < CPUIDLE_STATE_MAX; i++) {
		dev->states[i].name[0] = '\0';
		dev->states[i].desc[0] = '\0';
	}

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		cx = &pr->power.states[i];
		state = &dev->states[count];
	if (!dev)
		return -EINVAL;

	dev->cpu = pr->id;

	if (max_cstate == 0)
		max_cstate = 1;

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		cx = &pr->power.states[i];

		if (!cx->valid)
			continue;

#ifdef CONFIG_HOTPLUG_CPU
		if ((cx->type != ACPI_STATE_C1) && (num_online_cpus() > 1) &&
		    !pr->flags.has_cst &&
		    !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED))
			continue;
#endif
		cpuidle_set_statedata(state, cx);

		snprintf(state->name, CPUIDLE_NAME_LEN, "C%d", i);
		strncpy(state->desc, cx->desc, CPUIDLE_DESC_LEN);
		state->exit_latency = cx->latency;
		state->target_residency = cx->latency * latency_factor;
		state->power_usage = cx->power;

		state->flags = 0;
		switch (cx->type) {
			case ACPI_STATE_C1:
			state->flags |= CPUIDLE_FLAG_SHALLOW;
			if (cx->entry_method == ACPI_CSTATE_FFH)
				state->flags |= CPUIDLE_FLAG_TIME_VALID;

			state->enter = acpi_idle_enter_c1;
			dev->safe_state = state;
			break;

			case ACPI_STATE_C2:
			state->flags |= CPUIDLE_FLAG_BALANCED;
			state->flags |= CPUIDLE_FLAG_TIME_VALID;
			state->enter = acpi_idle_enter_simple;
			dev->safe_state = state;
			break;

			case ACPI_STATE_C3:
			state->flags |= CPUIDLE_FLAG_DEEP;
			state->flags |= CPUIDLE_FLAG_TIME_VALID;
			state->flags |= CPUIDLE_FLAG_CHECK_BM;
			state->enter = pr->flags.bm_check ?
					acpi_idle_enter_bm :
					acpi_idle_enter_simple;
			break;
		}
		per_cpu(acpi_cstate[count], dev->cpu) = cx;

		count++;
		if (count == CPUIDLE_STATE_MAX)
			break;
	}

	dev->state_count = count;

	if (!count)
		return -EINVAL;

	return 0;
}

int acpi_processor_cst_has_changed(struct acpi_processor *pr)
{
	int ret = 0;

	if (boot_option_idle_override)
		return 0;

	if (!pr)
		return -EINVAL;

	if (nocst) {
		return -ENODEV;
	}

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	cpuidle_pause_and_lock();
	cpuidle_disable_device(&pr->power.dev);
	acpi_processor_get_power_info(pr);
	if (pr->flags.power) {
		acpi_processor_setup_cpuidle(pr);
		ret = cpuidle_enable_device(&pr->power.dev);
/**
 * acpi_processor_setup_cpuidle states- prepares and configures cpuidle
 * global state data i.e. idle routines
 *
 * @pr: the ACPI processor
 */
static int acpi_processor_setup_cpuidle_states(struct acpi_processor *pr)
static int acpi_processor_setup_cstates(struct acpi_processor *pr)
{
	int i, count;
	struct acpi_processor_cx *cx;
	struct cpuidle_state *state;
	struct cpuidle_driver *drv = &acpi_idle_driver;

	if (max_cstate == 0)
		max_cstate = 1;

	if (IS_ENABLED(CONFIG_ARCH_HAS_CPU_RELAX)) {
		cpuidle_poll_state_init(drv);
		count = 1;
	} else {
		count = 0;
	}

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		cx = &pr->power.states[i];

		if (!cx->valid)
			continue;

		state = &drv->states[count];
		snprintf(state->name, CPUIDLE_NAME_LEN, "C%d", i);
		strlcpy(state->desc, cx->desc, CPUIDLE_DESC_LEN);
		state->exit_latency = cx->latency;
		state->target_residency = cx->latency * latency_factor;
		state->enter = acpi_idle_enter;

		state->flags = 0;
		if (cx->type == ACPI_STATE_C1 || cx->type == ACPI_STATE_C2) {
			state->enter_dead = acpi_idle_play_dead;
			drv->safe_state_index = count;
		}
		/*
		 * Halt-induced C1 is not good for ->enter_s2idle, because it
		 * re-enables interrupts on exit.  Moreover, C1 is generally not
		 * particularly interesting from the suspend-to-idle angle, so
		 * avoid C1 and the situations in which we may need to fall back
		 * to it altogether.
		 */
		if (cx->type != ACPI_STATE_C1 && !acpi_idle_fallback_to_c1(pr))
			state->enter_s2idle = acpi_idle_enter_s2idle;

		count++;
		if (count == CPUIDLE_STATE_MAX)
			break;
	}

	drv->state_count = count;

	if (!count)
		return -EINVAL;

	return 0;
}

static inline void acpi_processor_cstate_first_run_checks(void)
{
	acpi_status status;
	static int first_run;

	if (first_run)
		return;
	dmi_check_system(processor_power_dmi_table);
	max_cstate = acpi_processor_cstate_check(max_cstate);
	if (max_cstate < ACPI_C_STATES_MAX)
		pr_notice("ACPI: processor limited to max C-state %d\n",
			  max_cstate);
	first_run++;

	if (acpi_gbl_FADT.cst_control && !nocst) {
		status = acpi_os_write_port(acpi_gbl_FADT.smi_command,
					    acpi_gbl_FADT.cst_control, 8);
		if (ACPI_FAILURE(status))
			ACPI_EXCEPTION((AE_INFO, status,
					"Notifying BIOS of _CST ability failed"));
	}
}
#else

static inline int disabled_by_idle_boot_param(void) { return 0; }
static inline void acpi_processor_cstate_first_run_checks(void) { }
static int acpi_processor_get_cstate_info(struct acpi_processor *pr)
{
	return -ENODEV;
}

static int acpi_processor_setup_cpuidle_cx(struct acpi_processor *pr,
					   struct cpuidle_device *dev)
{
	return -EINVAL;
}

static int acpi_processor_setup_cstates(struct acpi_processor *pr)
{
	return -EINVAL;
}

#endif /* CONFIG_ACPI_PROCESSOR_CSTATE */

struct acpi_lpi_states_array {
	unsigned int size;
	unsigned int composite_states_size;
	struct acpi_lpi_state *entries;
	struct acpi_lpi_state *composite_states[ACPI_PROCESSOR_MAX_POWER];
};

static int obj_get_integer(union acpi_object *obj, u32 *value)
{
	if (obj->type != ACPI_TYPE_INTEGER)
		return -EINVAL;

	*value = obj->integer.value;
	return 0;
}

static int acpi_processor_evaluate_lpi(acpi_handle handle,
				       struct acpi_lpi_states_array *info)
{
	acpi_status status;
	int ret = 0;
	int pkg_count, state_idx = 1, loop;
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	union acpi_object *lpi_data;
	struct acpi_lpi_state *lpi_state;

	status = acpi_evaluate_object(handle, "_LPI", NULL, &buffer);
	if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO, "No _LPI, giving up\n"));
		return -ENODEV;
	}

	lpi_data = buffer.pointer;

	/* There must be at least 4 elements = 3 elements + 1 package */
	if (!lpi_data || lpi_data->type != ACPI_TYPE_PACKAGE ||
	    lpi_data->package.count < 4) {
		pr_debug("not enough elements in _LPI\n");
		ret = -ENODATA;
		goto end;
	}

	pkg_count = lpi_data->package.elements[2].integer.value;

	/* Validate number of power states. */
	if (pkg_count < 1 || pkg_count != lpi_data->package.count - 3) {
		pr_debug("count given by _LPI is not valid\n");
		ret = -ENODATA;
		goto end;
	}

	lpi_state = kcalloc(pkg_count, sizeof(*lpi_state), GFP_KERNEL);
	if (!lpi_state) {
		ret = -ENOMEM;
		goto end;
	}

	info->size = pkg_count;
	info->entries = lpi_state;

	/* LPI States start at index 3 */
	for (loop = 3; state_idx <= pkg_count; loop++, state_idx++, lpi_state++) {
		union acpi_object *element, *pkg_elem, *obj;

		element = &lpi_data->package.elements[loop];
		if (element->type != ACPI_TYPE_PACKAGE || element->package.count < 7)
			continue;

		pkg_elem = element->package.elements;

		obj = pkg_elem + 6;
		if (obj->type == ACPI_TYPE_BUFFER) {
			struct acpi_power_register *reg;

			reg = (struct acpi_power_register *)obj->buffer.pointer;
			if (reg->space_id != ACPI_ADR_SPACE_SYSTEM_IO &&
			    reg->space_id != ACPI_ADR_SPACE_FIXED_HARDWARE)
				continue;

			lpi_state->address = reg->address;
			lpi_state->entry_method =
				reg->space_id == ACPI_ADR_SPACE_FIXED_HARDWARE ?
				ACPI_CSTATE_FFH : ACPI_CSTATE_SYSTEMIO;
		} else if (obj->type == ACPI_TYPE_INTEGER) {
			lpi_state->entry_method = ACPI_CSTATE_INTEGER;
			lpi_state->address = obj->integer.value;
		} else {
			continue;
		}

		/* elements[7,8] skipped for now i.e. Residency/Usage counter*/

		obj = pkg_elem + 9;
		if (obj->type == ACPI_TYPE_STRING)
			strlcpy(lpi_state->desc, obj->string.pointer,
				ACPI_CX_DESC_LEN);

		lpi_state->index = state_idx;
		if (obj_get_integer(pkg_elem + 0, &lpi_state->min_residency)) {
			pr_debug("No min. residency found, assuming 10 us\n");
			lpi_state->min_residency = 10;
		}

		if (obj_get_integer(pkg_elem + 1, &lpi_state->wake_latency)) {
			pr_debug("No wakeup residency found, assuming 10 us\n");
			lpi_state->wake_latency = 10;
		}

		if (obj_get_integer(pkg_elem + 2, &lpi_state->flags))
			lpi_state->flags = 0;

		if (obj_get_integer(pkg_elem + 3, &lpi_state->arch_flags))
			lpi_state->arch_flags = 0;

		if (obj_get_integer(pkg_elem + 4, &lpi_state->res_cnt_freq))
			lpi_state->res_cnt_freq = 1;

		if (obj_get_integer(pkg_elem + 5, &lpi_state->enable_parent_state))
			lpi_state->enable_parent_state = 0;
	}

	acpi_handle_debug(handle, "Found %d power states\n", state_idx);
end:
	kfree(buffer.pointer);
	return ret;
}

/*
 * flat_state_cnt - the number of composite LPI states after the process of flattening
 */
static int flat_state_cnt;

/**
 * combine_lpi_states - combine local and parent LPI states to form a composite LPI state
 *
 * @local: local LPI state
 * @parent: parent LPI state
 * @result: composite LPI state
 */
static bool combine_lpi_states(struct acpi_lpi_state *local,
			       struct acpi_lpi_state *parent,
			       struct acpi_lpi_state *result)
{
	if (parent->entry_method == ACPI_CSTATE_INTEGER) {
		if (!parent->address) /* 0 means autopromotable */
			return false;
		result->address = local->address + parent->address;
	} else {
		result->address = parent->address;
	}

	result->min_residency = max(local->min_residency, parent->min_residency);
	result->wake_latency = local->wake_latency + parent->wake_latency;
	result->enable_parent_state = parent->enable_parent_state;
	result->entry_method = local->entry_method;

	result->flags = parent->flags;
	result->arch_flags = parent->arch_flags;
	result->index = parent->index;

	strlcpy(result->desc, local->desc, ACPI_CX_DESC_LEN);
	strlcat(result->desc, "+", ACPI_CX_DESC_LEN);
	strlcat(result->desc, parent->desc, ACPI_CX_DESC_LEN);
	return true;
}

#define ACPI_LPI_STATE_FLAGS_ENABLED			BIT(0)

static void stash_composite_state(struct acpi_lpi_states_array *curr_level,
				  struct acpi_lpi_state *t)
{
	curr_level->composite_states[curr_level->composite_states_size++] = t;
}

static int flatten_lpi_states(struct acpi_processor *pr,
			      struct acpi_lpi_states_array *curr_level,
			      struct acpi_lpi_states_array *prev_level)
{
	int i, j, state_count = curr_level->size;
	struct acpi_lpi_state *p, *t = curr_level->entries;

	curr_level->composite_states_size = 0;
	for (j = 0; j < state_count; j++, t++) {
		struct acpi_lpi_state *flpi;

		if (!(t->flags & ACPI_LPI_STATE_FLAGS_ENABLED))
			continue;

		if (flat_state_cnt >= ACPI_PROCESSOR_MAX_POWER) {
			pr_warn("Limiting number of LPI states to max (%d)\n",
				ACPI_PROCESSOR_MAX_POWER);
			pr_warn("Please increase ACPI_PROCESSOR_MAX_POWER if needed.\n");
			break;
		}

		flpi = &pr->power.lpi_states[flat_state_cnt];

		if (!prev_level) { /* leaf/processor node */
			memcpy(flpi, t, sizeof(*t));
			stash_composite_state(curr_level, flpi);
			flat_state_cnt++;
			continue;
		}

		for (i = 0; i < prev_level->composite_states_size; i++) {
			p = prev_level->composite_states[i];
			if (t->index <= p->enable_parent_state &&
			    combine_lpi_states(p, t, flpi)) {
				stash_composite_state(curr_level, flpi);
				flat_state_cnt++;
				flpi++;
			}
		}
	}

	kfree(curr_level->entries);
	return 0;
}

static int acpi_processor_get_lpi_info(struct acpi_processor *pr)
{
	int ret, i;
	acpi_status status;
	acpi_handle handle = pr->handle, pr_ahandle;
	struct acpi_device *d = NULL;
	struct acpi_lpi_states_array info[2], *tmp, *prev, *curr;

	if (!osc_pc_lpi_support_confirmed)
		return -EOPNOTSUPP;

	if (!acpi_has_method(handle, "_LPI"))
		return -EINVAL;

	flat_state_cnt = 0;
	prev = &info[0];
	curr = &info[1];
	handle = pr->handle;
	ret = acpi_processor_evaluate_lpi(handle, prev);
	if (ret)
		return ret;
	flatten_lpi_states(pr, prev, NULL);

	status = acpi_get_parent(handle, &pr_ahandle);
	while (ACPI_SUCCESS(status)) {
		acpi_bus_get_device(pr_ahandle, &d);
		handle = pr_ahandle;

		if (strcmp(acpi_device_hid(d), ACPI_PROCESSOR_CONTAINER_HID))
			break;

		/* can be optional ? */
		if (!acpi_has_method(handle, "_LPI"))
			break;

		ret = acpi_processor_evaluate_lpi(handle, curr);
		if (ret)
			break;

		/* flatten all the LPI states in this level of hierarchy */
		flatten_lpi_states(pr, curr, prev);

		tmp = prev, prev = curr, curr = tmp;

		status = acpi_get_parent(handle, &pr_ahandle);
	}

	pr->power.count = flat_state_cnt;
	/* reset the index after flattening */
	for (i = 0; i < pr->power.count; i++)
		pr->power.lpi_states[i].index = i;

	/* Tell driver that _LPI is supported. */
	pr->flags.has_lpi = 1;
	pr->flags.power = 1;

	return 0;
}

int __weak acpi_processor_ffh_lpi_probe(unsigned int cpu)
{
	return -ENODEV;
}

int __weak acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
{
	return -ENODEV;
}

/**
 * acpi_idle_lpi_enter - enters an ACPI any LPI state
 * @dev: the target CPU
 * @drv: cpuidle driver containing cpuidle state info
 * @index: index of target state
 *
 * Return: 0 for success or negative value for error
 */
static int acpi_idle_lpi_enter(struct cpuidle_device *dev,
			       struct cpuidle_driver *drv, int index)
{
	struct acpi_processor *pr;
	struct acpi_lpi_state *lpi;

	pr = __this_cpu_read(processors);

	if (unlikely(!pr))
		return -EINVAL;

	lpi = &pr->power.lpi_states[index];
	if (lpi->entry_method == ACPI_CSTATE_FFH)
		return acpi_processor_ffh_lpi_enter(lpi);

	return -EINVAL;
}

static int acpi_processor_setup_lpi_states(struct acpi_processor *pr)
{
	int i;
	struct acpi_lpi_state *lpi;
	struct cpuidle_state *state;
	struct cpuidle_driver *drv = &acpi_idle_driver;

	if (!pr->flags.has_lpi)
		return -EOPNOTSUPP;

	for (i = 0; i < pr->power.count && i < CPUIDLE_STATE_MAX; i++) {
		lpi = &pr->power.lpi_states[i];

		state = &drv->states[i];
		snprintf(state->name, CPUIDLE_NAME_LEN, "LPI-%d", i);
		strlcpy(state->desc, lpi->desc, CPUIDLE_DESC_LEN);
		state->exit_latency = lpi->wake_latency;
		state->target_residency = lpi->min_residency;
		if (lpi->arch_flags)
			state->flags |= CPUIDLE_FLAG_TIMER_STOP;
		state->enter = acpi_idle_lpi_enter;
		drv->safe_state_index = i;
	}

	drv->state_count = i;

	return 0;
}

/**
 * acpi_processor_setup_cpuidle_states- prepares and configures cpuidle
 * global state data i.e. idle routines
 *
 * @pr: the ACPI processor
 */
static int acpi_processor_setup_cpuidle_states(struct acpi_processor *pr)
{
	int i;
	struct cpuidle_driver *drv = &acpi_idle_driver;

	if (!pr->flags.power_setup_done || !pr->flags.power)
		return -EINVAL;

	drv->safe_state_index = -1;
	for (i = ACPI_IDLE_STATE_START; i < CPUIDLE_STATE_MAX; i++) {
		drv->states[i].name[0] = '\0';
		drv->states[i].desc[0] = '\0';
	}

	if (pr->flags.has_lpi)
		return acpi_processor_setup_lpi_states(pr);

	return acpi_processor_setup_cstates(pr);
}

/**
 * acpi_processor_setup_cpuidle_dev - prepares and configures CPUIDLE
 * device i.e. per-cpu data
 *
 * @pr: the ACPI processor
 * @dev : the cpuidle device
 */
static int acpi_processor_setup_cpuidle_dev(struct acpi_processor *pr,
					    struct cpuidle_device *dev)
{
	if (!pr->flags.power_setup_done || !pr->flags.power || !dev)
		return -EINVAL;

	dev->cpu = pr->id;
	if (pr->flags.has_lpi)
		return acpi_processor_ffh_lpi_probe(pr->id);

	return acpi_processor_setup_cpuidle_cx(pr, dev);
}

static int acpi_processor_get_power_info(struct acpi_processor *pr)
{
	int ret;

	ret = acpi_processor_get_lpi_info(pr);
	if (ret)
		ret = acpi_processor_get_cstate_info(pr);

	return ret;
}

int acpi_processor_hotplug(struct acpi_processor *pr)
{
	int ret = 0;
	struct cpuidle_device *dev;

	if (disabled_by_idle_boot_param())
		return 0;

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	dev = per_cpu(acpi_cpuidle_device, pr->id);
	cpuidle_pause_and_lock();
	cpuidle_disable_device(dev);
	ret = acpi_processor_get_power_info(pr);
	if (!ret && pr->flags.power) {
		acpi_processor_setup_cpuidle_dev(pr, dev);
		ret = cpuidle_enable_device(dev);
	}
	cpuidle_resume_and_unlock();

	return ret;
}

#endif /* CONFIG_CPU_IDLE */

int __cpuinit acpi_processor_power_init(struct acpi_processor *pr,
			      struct acpi_device *device)
{
	acpi_status status = 0;
	static int first_run;
	struct proc_dir_entry *entry = NULL;
	unsigned int i;

	if (boot_option_idle_override)
		return 0;

	if (!first_run) {
		if (idle_halt) {
			/*
			 * When the boot option of "idle=halt" is added, halt
			 * is used for CPU IDLE.
			 * In such case C2/C3 is meaningless. So the max_cstate
			 * is set to one.
			 */
			max_cstate = 1;
		}
int acpi_processor_cst_has_changed(struct acpi_processor *pr)
int acpi_processor_power_state_has_changed(struct acpi_processor *pr)
{
	int cpu;
	struct acpi_processor *_pr;
	struct cpuidle_device *dev;

	if (disabled_by_idle_boot_param())
		return 0;

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	/*
	 * FIXME:  Design the ACPI notification to make it once per
	 * system instead of once per-cpu.  This condition is a hack
	 * to make the code that updates C-States be called once.
	 */

	if (pr->id == 0 && cpuidle_get_driver() == &acpi_idle_driver) {

		/* Protect against cpu-hotplug */
		get_online_cpus();
		cpuidle_pause_and_lock();

		/* Disable all cpuidle devices */
		for_each_online_cpu(cpu) {
			_pr = per_cpu(processors, cpu);
			if (!_pr || !_pr->flags.power_setup_done)
				continue;
			dev = per_cpu(acpi_cpuidle_device, cpu);
			cpuidle_disable_device(dev);
		}

		/* Populate Updated C-state information */
		acpi_processor_get_power_info(pr);
		acpi_processor_setup_cpuidle_states(pr);

		/* Enable all cpuidle devices */
		for_each_online_cpu(cpu) {
			_pr = per_cpu(processors, cpu);
			if (!_pr || !_pr->flags.power_setup_done)
				continue;
			acpi_processor_get_power_info(_pr);
			if (_pr->flags.power) {
				dev = per_cpu(acpi_cpuidle_device, cpu);
				acpi_processor_setup_cpuidle_dev(_pr, dev);
				cpuidle_enable_device(dev);
			}
		}
		cpuidle_resume_and_unlock();
		put_online_cpus();
	}

	return 0;
}

static int acpi_processor_registered;

int acpi_processor_power_init(struct acpi_processor *pr)
{
	int retval;
	struct cpuidle_device *dev;

	if (disabled_by_idle_boot_param())
		return 0;

	if (!first_run) {
		dmi_check_system(processor_power_dmi_table);
		max_cstate = acpi_processor_cstate_check(max_cstate);
		if (max_cstate < ACPI_C_STATES_MAX)
			printk(KERN_NOTICE
			       "ACPI: processor limited to max C-state %d\n",
			       max_cstate);
		first_run++;
#if !defined(CONFIG_CPU_IDLE) && defined(CONFIG_SMP)
		pm_qos_add_notifier(PM_QOS_CPU_DMA_LATENCY,
				&acpi_processor_latency_notifier);
#endif
	}

	if (!pr)
		return -EINVAL;

	}
	acpi_processor_cstate_first_run_checks();

	if (!acpi_processor_get_power_info(pr))
		pr->flags.power_setup_done = 1;

	/*
	 * Install the idle handler if processor power management is supported.
	 * Note that we use previously set idle handler will be used on
	 * platforms that only support C1.
	 */
	if (pr->flags.power) {
#ifdef CONFIG_CPU_IDLE
		acpi_processor_setup_cpuidle(pr);
		if (cpuidle_register_device(&pr->power.dev))
			return -EIO;
#endif

		printk(KERN_INFO PREFIX "CPU%d (power states:", pr->id);
		for (i = 1; i <= pr->power.count; i++)
			if (pr->power.states[i].valid)
				printk(" C%d[C%d]", i,
				       pr->power.states[i].type);
		printk(")\n");

#ifndef CONFIG_CPU_IDLE
		if (pr->id == 0) {
			pm_idle_save = pm_idle;
			pm_idle = acpi_processor_idle;
		}
#endif
	}

	/* 'power' [R] */
	entry = proc_create_data(ACPI_PROCESSOR_FILE_POWER,
				 S_IRUGO, acpi_device_dir(device),
				 &acpi_processor_power_fops,
				 acpi_driver_data(device));
	if (!entry)
		return -EIO;
	return 0;
}

int acpi_processor_power_exit(struct acpi_processor *pr,
			      struct acpi_device *device)
{
	if (boot_option_idle_override)
		return 0;

#ifdef CONFIG_CPU_IDLE
	cpuidle_unregister_device(&pr->power.dev);
#endif
	pr->flags.power_setup_done = 0;

	if (acpi_device_dir(device))
		remove_proc_entry(ACPI_PROCESSOR_FILE_POWER,
				  acpi_device_dir(device));

#ifndef CONFIG_CPU_IDLE

	/* Unregister the idle handler when processor #0 is removed. */
	if (pr->id == 0) {
		if (pm_idle_save)
			pm_idle = pm_idle_save;

		/*
		 * We are about to unload the current idle thread pm callback
		 * (pm_idle), Wait for all processors to update cached/local
		 * copies of pm_idle before proceeding.
		 */
		cpu_idle_wait();
#ifdef CONFIG_SMP
		pm_qos_remove_notifier(PM_QOS_CPU_DMA_LATENCY,
				&acpi_processor_latency_notifier);
#endif
	}
#endif

		/* Register acpi_idle_driver if not already registered */
		if (!acpi_processor_registered) {
			acpi_processor_setup_cpuidle_states(pr);
			retval = cpuidle_register_driver(&acpi_idle_driver);
			if (retval)
				return retval;
			pr_debug("%s registered with cpuidle\n",
				 acpi_idle_driver.name);
		}

		dev = kzalloc(sizeof(*dev), GFP_KERNEL);
		if (!dev)
			return -ENOMEM;
		per_cpu(acpi_cpuidle_device, pr->id) = dev;

		acpi_processor_setup_cpuidle_dev(pr, dev);

		/* Register per-cpu cpuidle_device. Cpuidle driver
		 * must already be registered before registering device
		 */
		retval = cpuidle_register_device(dev);
		if (retval) {
			if (acpi_processor_registered == 0)
				cpuidle_unregister_driver(&acpi_idle_driver);
			return retval;
		}
		acpi_processor_registered++;
	}
	return 0;
}

int acpi_processor_power_exit(struct acpi_processor *pr)
{
	struct cpuidle_device *dev = per_cpu(acpi_cpuidle_device, pr->id);

	if (disabled_by_idle_boot_param())
		return 0;

	if (pr->flags.power) {
		cpuidle_unregister_device(dev);
		acpi_processor_registered--;
		if (acpi_processor_registered == 0)
			cpuidle_unregister_driver(&acpi_idle_driver);
	}

	pr->flags.power_setup_done = 0;
	return 0;
}
