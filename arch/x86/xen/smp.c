/*
 * Xen SMP support
 *
 * This file implements the Xen versions of smp_ops.  SMP under Xen is
 * very straightforward.  Bringing a CPU up is simply a matter of
 * loading its initial context and setting it running.
 *
 * IPIs are handled through the Xen event mechanism.
 *
 * Because virtual CPUs can be scheduled onto any real CPU, there's no
 * useful topology information for the kernel to make use of.  As a
 * result, all CPUs are treated as if they're single-core and
 * single-threaded.
 *
 * This does not handle HOTPLUG_CPU yet.
 */
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/err.h>
#include <linux/smp.h>
 */
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/slab.h>
// SPDX-License-Identifier: GPL-2.0
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>

#include <asm/paravirt.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/cpu.h>

#include <xen/interface/xen.h>
#include <xen/interface/vcpu.h>
#include <xen/interface/xenpmu.h>

#include <asm/xen/interface.h>
#include <asm/xen/hypercall.h>

#include <xen/page.h>
#include <xen/events.h>

#include "xen-ops.h"
#include "mmu.h"

static void __cpuinit xen_init_lock_cpu(int cpu);

cpumask_t xen_cpu_initialized_map;

static DEFINE_PER_CPU(int, resched_irq);
static DEFINE_PER_CPU(int, callfunc_irq);
static DEFINE_PER_CPU(int, callfuncsingle_irq);
static DEFINE_PER_CPU(int, debug_irq) = -1;

static irqreturn_t xen_call_function_interrupt(int irq, void *dev_id);
static irqreturn_t xen_call_function_single_interrupt(int irq, void *dev_id);

/*
 * Reschedule call back. Nothing to do,
 * all the work is done automatically when
 * we return from the interrupt.
 */
static irqreturn_t xen_reschedule_interrupt(int irq, void *dev_id)
{
#ifdef CONFIG_X86_32
	__get_cpu_var(irq_stat).irq_resched_count++;
#else
	add_pda(irq_resched_count, 1);
#endif
#include <xen/xen.h>
#include <xen/page.h>
#include <xen/events.h>

#include <xen/hvc-console.h>
#include "xen-ops.h"
#include "smp.h"

static DEFINE_PER_CPU(struct xen_common_irq, xen_resched_irq) = { .irq = -1 };
static DEFINE_PER_CPU(struct xen_common_irq, xen_callfunc_irq) = { .irq = -1 };
static DEFINE_PER_CPU(struct xen_common_irq, xen_callfuncsingle_irq) = { .irq = -1 };
static DEFINE_PER_CPU(struct xen_common_irq, xen_debug_irq) = { .irq = -1 };

static irqreturn_t xen_call_function_interrupt(int irq, void *dev_id);
static irqreturn_t xen_call_function_single_interrupt(int irq, void *dev_id);

/*
 * Reschedule call back.
 */
static irqreturn_t xen_reschedule_interrupt(int irq, void *dev_id)
{
	inc_irq_stat(irq_resched_count);
	scheduler_ipi();

	return IRQ_HANDLED;
}

static __cpuinit void cpu_bringup_and_idle(void)
{
	int cpu = smp_processor_id();

	cpu_init();
	preempt_disable();

	xen_enable_sysenter();
	xen_enable_syscall();

static void cpu_bringup(void)
{
	int cpu;

	cpu_init();
	touch_softlockup_watchdog();
	preempt_disable();

	/* PVH runs in ring 0 and allows us to do native syscalls. Yay! */
	if (!xen_feature(XENFEAT_supervisor_mode_kernel)) {
		xen_enable_sysenter();
		xen_enable_syscall();
	}
	cpu = smp_processor_id();
	smp_store_cpu_info(cpu);
	cpu_data(cpu).x86_max_cores = 1;
	set_cpu_sibling_map(cpu);

	xen_setup_cpu_clockevents();

	cpu_set(cpu, cpu_online_map);
	x86_write_percpu(cpu_state, CPU_ONLINE);
	wmb();

	/* We can take interrupts now: we're officially "up". */
	local_irq_enable();

	wmb();			/* make sure everything is out */
	cpu_idle();
}

static int xen_smp_intr_init(unsigned int cpu)
{
	int rc;
	const char *resched_name, *callfunc_name, *debug_name;
	notify_cpu_starting(cpu);

	set_cpu_online(cpu, true);

	cpu_set_state_online(cpu);  /* Implies full memory barrier. */

	/* We can take interrupts now: we're officially "up". */
	local_irq_enable();
}

/*
 * Note: cpu parameter is only relevant for PVH. The reason for passing it
 * is we can't do smp_processor_id until the percpu segments are loaded, for
 * which we need the cpu number! So we pass it in rdi as first parameter.
 */
asmlinkage __visible void cpu_bringup_and_idle(int cpu)
{
#ifdef CONFIG_XEN_PVH
	if (xen_feature(XENFEAT_auto_translated_physmap) &&
	    xen_feature(XENFEAT_supervisor_mode_kernel))
		xen_pvh_secondary_vcpu_init(cpu);
#endif
	cpu_bringup();
	cpu_startup_entry(CPUHP_ONLINE);
}

static void xen_smp_intr_free(unsigned int cpu)
void xen_smp_intr_free(unsigned int cpu)
{
	if (per_cpu(xen_resched_irq, cpu).irq >= 0) {
		unbind_from_irqhandler(per_cpu(xen_resched_irq, cpu).irq, NULL);
		per_cpu(xen_resched_irq, cpu).irq = -1;
		kfree(per_cpu(xen_resched_irq, cpu).name);
		per_cpu(xen_resched_irq, cpu).name = NULL;
	}
	if (per_cpu(xen_callfunc_irq, cpu).irq >= 0) {
		unbind_from_irqhandler(per_cpu(xen_callfunc_irq, cpu).irq, NULL);
		per_cpu(xen_callfunc_irq, cpu).irq = -1;
		kfree(per_cpu(xen_callfunc_irq, cpu).name);
		per_cpu(xen_callfunc_irq, cpu).name = NULL;
	}
	if (per_cpu(xen_debug_irq, cpu).irq >= 0) {
		unbind_from_irqhandler(per_cpu(xen_debug_irq, cpu).irq, NULL);
		per_cpu(xen_debug_irq, cpu).irq = -1;
		kfree(per_cpu(xen_debug_irq, cpu).name);
		per_cpu(xen_debug_irq, cpu).name = NULL;
	}
	if (per_cpu(xen_callfuncsingle_irq, cpu).irq >= 0) {
		unbind_from_irqhandler(per_cpu(xen_callfuncsingle_irq, cpu).irq,
				       NULL);
		per_cpu(xen_callfuncsingle_irq, cpu).irq = -1;
		kfree(per_cpu(xen_callfuncsingle_irq, cpu).name);
		per_cpu(xen_callfuncsingle_irq, cpu).name = NULL;
	}
}

int xen_smp_intr_init(unsigned int cpu)
{
	int rc;
	char *resched_name, *callfunc_name, *debug_name;

	resched_name = kasprintf(GFP_KERNEL, "resched%d", cpu);
	rc = bind_ipi_to_irqhandler(XEN_RESCHEDULE_VECTOR,
				    cpu,
				    xen_reschedule_interrupt,
				    IRQF_DISABLED|IRQF_PERCPU|IRQF_NOBALANCING,
				    IRQF_PERCPU|IRQF_NOBALANCING,
				    resched_name,
				    NULL);
	if (rc < 0)
		goto fail;
	per_cpu(resched_irq, cpu) = rc;
	per_cpu(xen_resched_irq, cpu).irq = rc;
	per_cpu(xen_resched_irq, cpu).name = resched_name;

	callfunc_name = kasprintf(GFP_KERNEL, "callfunc%d", cpu);
	rc = bind_ipi_to_irqhandler(XEN_CALL_FUNCTION_VECTOR,
				    cpu,
				    xen_call_function_interrupt,
				    IRQF_DISABLED|IRQF_PERCPU|IRQF_NOBALANCING,
				    IRQF_PERCPU|IRQF_NOBALANCING,
				    callfunc_name,
				    NULL);
	if (rc < 0)
		goto fail;
	per_cpu(callfunc_irq, cpu) = rc;

	debug_name = kasprintf(GFP_KERNEL, "debug%d", cpu);
	rc = bind_virq_to_irqhandler(VIRQ_DEBUG, cpu, xen_debug_interrupt,
				     IRQF_DISABLED | IRQF_PERCPU | IRQF_NOBALANCING,
				     debug_name, NULL);
	if (rc < 0)
		goto fail;
	per_cpu(debug_irq, cpu) = rc;
	per_cpu(xen_callfunc_irq, cpu).irq = rc;
	per_cpu(xen_callfunc_irq, cpu).name = callfunc_name;

	debug_name = kasprintf(GFP_KERNEL, "debug%d", cpu);
	rc = bind_virq_to_irqhandler(VIRQ_DEBUG, cpu, xen_debug_interrupt,
				     IRQF_PERCPU | IRQF_NOBALANCING,
				     debug_name, NULL);
	if (rc < 0)
		goto fail;
	per_cpu(xen_debug_irq, cpu).irq = rc;
	per_cpu(xen_debug_irq, cpu).name = debug_name;

	callfunc_name = kasprintf(GFP_KERNEL, "callfuncsingle%d", cpu);
	rc = bind_ipi_to_irqhandler(XEN_CALL_FUNCTION_SINGLE_VECTOR,
				    cpu,
				    xen_call_function_single_interrupt,
				    IRQF_DISABLED|IRQF_PERCPU|IRQF_NOBALANCING,
				    IRQF_PERCPU|IRQF_NOBALANCING,
				    callfunc_name,
				    NULL);
	if (rc < 0)
		goto fail;
	per_cpu(callfuncsingle_irq, cpu) = rc;
	per_cpu(xen_callfuncsingle_irq, cpu).irq = rc;
	per_cpu(xen_callfuncsingle_irq, cpu).name = callfunc_name;

	return 0;

 fail:
	if (per_cpu(resched_irq, cpu) >= 0)
		unbind_from_irqhandler(per_cpu(resched_irq, cpu), NULL);
	if (per_cpu(callfunc_irq, cpu) >= 0)
		unbind_from_irqhandler(per_cpu(callfunc_irq, cpu), NULL);
	if (per_cpu(debug_irq, cpu) >= 0)
		unbind_from_irqhandler(per_cpu(debug_irq, cpu), NULL);
	if (per_cpu(callfuncsingle_irq, cpu) >= 0)
		unbind_from_irqhandler(per_cpu(callfuncsingle_irq, cpu), NULL);

	xen_smp_intr_free(cpu);
	return rc;
}

void __init xen_smp_cpus_done(unsigned int max_cpus)
{
	int cpu, rc, count = 0;

	for (i = 0; i < NR_CPUS; i++) {
		rc = HYPERVISOR_vcpu_op(VCPUOP_is_up, i, NULL);
		if (rc >= 0) {
			num_processors++;
			cpu_set(i, cpu_possible_map);
	if (xen_initial_domain())
		return;

	for (i = 0; i < nr_cpu_ids; i++) {
		rc = HYPERVISOR_vcpu_op(VCPUOP_is_up, i, NULL);
		if (rc >= 0) {
			num_processors++;
			set_cpu_possible(i, true);
		}
	}
}

static void __init xen_filter_cpu_maps(void)
{
	int i, rc;
	unsigned int subtract = 0;

	if (!xen_initial_domain())
		return;

	num_processors = 0;
	disabled_cpus = 0;
	for (i = 0; i < nr_cpu_ids; i++) {
		rc = HYPERVISOR_vcpu_op(VCPUOP_is_up, i, NULL);
		if (rc >= 0) {
			num_processors++;
			set_cpu_possible(i, true);
		} else {
			set_cpu_possible(i, false);
			set_cpu_present(i, false);
			subtract++;
		}
	}
#ifdef CONFIG_HOTPLUG_CPU
	/* This is akin to using 'nr_cpus' on the Linux command line.
	 * Which is OK as when we use 'dom0_max_vcpus=X' we can only
	 * have up to X, while nr_cpu_ids is greater than X. This
	 * normally is not a problem, except when CPU hotplugging
	 * is involved and then there might be more than X CPUs
	 * in the guest - which will not work as there is no
	 * hypercall to expand the max number of VCPUs an already
	 * running guest has. So cap it up to X. */
	if (subtract)
		nr_cpu_ids = nr_cpu_ids - subtract;
#endif

}

static void __init xen_smp_prepare_boot_cpu(void)
{
	BUG_ON(smp_processor_id() != 0);
	native_smp_prepare_boot_cpu();

	/* We've switched to the "real" per-cpu gdt, so make sure the
	   old memory can be recycled */
	make_lowmem_page_readwrite(&per_cpu_var(gdt_page));

	xen_setup_vcpu_info_placement();
	if (xen_pv_domain()) {
		if (!xen_feature(XENFEAT_writable_page_tables))
			/* We've switched to the "real" per-cpu gdt, so make
			 * sure the old memory can be recycled. */
			make_lowmem_page_readwrite(xen_initial_gdt);

#ifdef CONFIG_X86_32
		/*
		 * Xen starts us with XEN_FLAT_RING1_DS, but linux code
		 * expects __USER_DS
		 */
		loadsegment(ds, __USER_DS);
		loadsegment(es, __USER_DS);
#endif

		xen_filter_cpu_maps();
		xen_setup_vcpu_info_placement();
	}
	/*
	 * The alternative logic (which patches the unlock/lock) runs before
	 * the smp bootup up code is activated. Hence we need to set this up
	 * the core kernel is being patched. Otherwise we will have only
	 * modules patched but not core code.
	 */
	xen_init_spinlocks();
}

static void __init xen_smp_prepare_cpus(unsigned int max_cpus)
{
	unsigned cpu;

	xen_init_lock_cpu(0);

	smp_store_cpu_info(0);
	cpu_data(0).x86_max_cores = 1;
	set_cpu_sibling_map(0);

	if (xen_smp_intr_init(0))
		BUG();

	xen_cpu_initialized_map = cpumask_of_cpu(0);

	/* Restrict the possible_map according to max_cpus. */
	while ((num_possible_cpus() > 1) && (num_possible_cpus() > max_cpus)) {
		for (cpu = NR_CPUS - 1; !cpu_possible(cpu); cpu--)
			continue;
		cpu_clear(cpu, cpu_possible_map);
	}

	for_each_possible_cpu (cpu) {
		struct task_struct *idle;

		if (cpu == 0)
			continue;

		idle = fork_idle(cpu);
		if (IS_ERR(idle))
			panic("failed fork for CPU %d", cpu);

		cpu_set(cpu, cpu_present_map);
	}

	//init_xenbus_allowed_cpumask();
}

static __cpuinit int
	unsigned int i;

	if (skip_ioapic_setup) {
		char *m = (max_cpus == 0) ?
			"The nosmp parameter is incompatible with Xen; " \
			"use Xen dom0_max_vcpus=1 parameter" :
			"The noapic parameter is incompatible with Xen";

		xen_raw_printk(m);
		panic(m);
	}
	xen_init_lock_cpu(0);

	smp_store_boot_cpu_info();
	cpu_data(0).x86_max_cores = 1;

	for_each_possible_cpu(i) {
		zalloc_cpumask_var(&per_cpu(cpu_sibling_map, i), GFP_KERNEL);
		zalloc_cpumask_var(&per_cpu(cpu_core_map, i), GFP_KERNEL);
		zalloc_cpumask_var(&per_cpu(cpu_llc_shared_map, i), GFP_KERNEL);
	}
	set_cpu_sibling_map(0);

	xen_pmu_init(0);

	if (xen_smp_intr_init(0))
		BUG();

	if (!alloc_cpumask_var(&xen_cpu_initialized_map, GFP_KERNEL))
		panic("could not allocate xen_cpu_initialized_map\n");

	cpumask_copy(xen_cpu_initialized_map, cpumask_of(0));

	/* Restrict the possible_map according to max_cpus. */
	while ((num_possible_cpus() > 1) && (num_possible_cpus() > max_cpus)) {
		for (cpu = nr_cpu_ids - 1; !cpu_possible(cpu); cpu--)
	if (xen_hvm_domain())
		native_smp_cpus_done(max_cpus);
	else
		calculate_max_logical_packages();

	if (xen_have_vcpu_info_placement)
		return;

	for_each_online_cpu(cpu) {
		if (xen_vcpu_nr(cpu) < MAX_VIRT_CPUS)
			continue;

		rc = cpu_down(cpu);

		if (rc == 0) {
			/*
			 * Reset vcpu_info so this cpu cannot be onlined again.
			 */
			xen_vcpu_info_reset(cpu);
			count++;
		} else {
			pr_warn("%s: failed to bring CPU %d down, error %d\n",
				__func__, cpu, rc);
		}
	}
	WARN(count, "%s: brought %d CPUs offline\n", __func__, count);
}

static int
cpu_initialize_context(unsigned int cpu, struct task_struct *idle)
{
	struct vcpu_guest_context *ctxt;
	struct desc_struct *gdt;

	if (cpu_test_and_set(cpu, xen_cpu_initialized_map))
	unsigned long gdt_mfn;

	/* used to tell cpu_init() that it can proceed with initialization */
	cpumask_set_cpu(cpu, cpu_callout_mask);
	if (cpumask_test_and_set_cpu(cpu, xen_cpu_initialized_map))
		return 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (ctxt == NULL)
		return -ENOMEM;

	gdt = get_cpu_gdt_table(cpu);

	ctxt->flags = VGCF_IN_KERNEL;
	ctxt->user_regs.ds = __USER_DS;
	ctxt->user_regs.es = __USER_DS;
	ctxt->user_regs.ss = __KERNEL_DS;
#ifdef CONFIG_X86_32
	ctxt->user_regs.fs = __KERNEL_PERCPU;
#endif
	ctxt->user_regs.eip = (unsigned long)cpu_bringup_and_idle;
	ctxt->user_regs.eflags = 0x1000; /* IOPL_RING1 */

	memset(&ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

	xen_copy_trap_info(ctxt->trap_ctxt);

	ctxt->ldt_ents = 0;

	BUG_ON((unsigned long)gdt & ~PAGE_MASK);
	make_lowmem_page_readonly(gdt);

	ctxt->gdt_frames[0] = virt_to_mfn(gdt);
	ctxt->gdt_ents      = GDT_ENTRIES;

	ctxt->user_regs.cs = __KERNEL_CS;
	ctxt->user_regs.esp = idle->thread.sp0 - sizeof(struct pt_regs);

	ctxt->kernel_ss = __KERNEL_DS;
	ctxt->kernel_sp = idle->thread.sp0;

#ifdef CONFIG_X86_32
	ctxt->event_callback_cs     = __KERNEL_CS;
	ctxt->failsafe_callback_cs  = __KERNEL_CS;
#endif
	ctxt->event_callback_eip    = (unsigned long)xen_hypervisor_callback;
	ctxt->failsafe_callback_eip = (unsigned long)xen_failsafe_callback;

	per_cpu(xen_cr3, cpu) = __pa(swapper_pg_dir);
	ctxt->ctrlreg[3] = xen_pfn_to_cr3(virt_to_mfn(swapper_pg_dir));

#ifdef CONFIG_X86_32
	/* Note: PVH is not yet supported on x86_32. */
	ctxt->user_regs.fs = __KERNEL_PERCPU;
	ctxt->user_regs.gs = __KERNEL_STACK_CANARY;
#endif
	memset(&ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

	if (!xen_feature(XENFEAT_auto_translated_physmap)) {
		ctxt->user_regs.eip = (unsigned long)cpu_bringup_and_idle;
		ctxt->flags = VGCF_IN_KERNEL;
		ctxt->user_regs.eflags = 0x1000; /* IOPL_RING1 */
		ctxt->user_regs.ds = __USER_DS;
		ctxt->user_regs.es = __USER_DS;
		ctxt->user_regs.ss = __KERNEL_DS;

		xen_copy_trap_info(ctxt->trap_ctxt);

		ctxt->ldt_ents = 0;

		BUG_ON((unsigned long)gdt & ~PAGE_MASK);

		gdt_mfn = arbitrary_virt_to_mfn(gdt);
		make_lowmem_page_readonly(gdt);
		make_lowmem_page_readonly(mfn_to_virt(gdt_mfn));

		ctxt->gdt_frames[0] = gdt_mfn;
		ctxt->gdt_ents      = GDT_ENTRIES;

		ctxt->kernel_ss = __KERNEL_DS;
		ctxt->kernel_sp = idle->thread.sp0;

#ifdef CONFIG_X86_32
		ctxt->event_callback_cs     = __KERNEL_CS;
		ctxt->failsafe_callback_cs  = __KERNEL_CS;
#else
		ctxt->gs_base_kernel = per_cpu_offset(cpu);
#endif
		ctxt->event_callback_eip    =
					(unsigned long)xen_hypervisor_callback;
		ctxt->failsafe_callback_eip =
					(unsigned long)xen_failsafe_callback;
		ctxt->user_regs.cs = __KERNEL_CS;
		per_cpu(xen_cr3, cpu) = __pa(swapper_pg_dir);
	}
#ifdef CONFIG_XEN_PVH
	else {
		/*
		 * The vcpu comes on kernel page tables which have the NX pte
		 * bit set. This means before DS/SS is touched, NX in
		 * EFER must be set. Hence the following assembly glue code.
		 */
		ctxt->user_regs.eip = (unsigned long)xen_pvh_early_cpu_init;
		ctxt->user_regs.rdi = cpu;
		ctxt->user_regs.rsi = true;  /* entry == true */
	}
#endif
	ctxt->user_regs.esp = idle->thread.sp0 - sizeof(struct pt_regs);
	ctxt->ctrlreg[3] = xen_pfn_to_cr3(virt_to_gfn(swapper_pg_dir));
	if (HYPERVISOR_vcpu_op(VCPUOP_initialise, cpu, ctxt))
		BUG();

	kfree(ctxt);
	return 0;
}

static int __cpuinit xen_cpu_up(unsigned int cpu)
{
	struct task_struct *idle = idle_task(cpu);
	int rc;

#if 0
	rc = cpu_up_check(cpu);
	if (rc)
		return rc;
#endif

#ifdef CONFIG_X86_64
	/* Allocate node local memory for AP pdas */
	WARN_ON(cpu == 0);
	if (cpu > 0) {
		rc = get_local_pda(cpu);
		if (rc)
			return rc;
	}
#endif

#ifdef CONFIG_X86_32
	init_gdt(cpu);
	per_cpu(current_task, cpu) = idle;
	irq_ctx_init(cpu);
#else
	cpu_pda(cpu)->pcurrent = idle;
	clear_tsk_thread_flag(idle, TIF_FORK);
#endif
	xen_setup_timer(cpu);
	xen_init_lock_cpu(cpu);

	per_cpu(cpu_state, cpu) = CPU_UP_PREPARE;
static int xen_cpu_up(unsigned int cpu, struct task_struct *idle)
{
	int rc;

	common_cpu_up(cpu, idle);

	xen_setup_runstate_info(cpu);
	xen_setup_timer(cpu);
	xen_init_lock_cpu(cpu);

	/*
	 * PV VCPUs are always successfully taken down (see 'while' loop
	 * in xen_cpu_die()), so -EBUSY is an error.
	 */
	rc = cpu_check_up_prepare(cpu);
	if (rc)
		return rc;

	/* make sure interrupts start blocked */
	per_cpu(xen_vcpu, cpu)->evtchn_upcall_mask = 1;

	rc = cpu_initialize_context(cpu, idle);
	if (rc)
		return rc;

	if (num_online_cpus() == 1)
		alternatives_smp_switch(1);
	xen_pmu_init(cpu);

	rc = xen_smp_intr_init(cpu);
	if (rc)
		return rc;

	rc = HYPERVISOR_vcpu_op(VCPUOP_up, cpu, NULL);
	BUG_ON(rc);

	while(per_cpu(cpu_state, cpu) != CPU_ONLINE) {
		HYPERVISOR_sched_op(SCHEDOP_yield, 0);
		barrier();
	}
	while (cpu_report_state(cpu) != CPU_ONLINE)
		HYPERVISOR_sched_op(SCHEDOP_yield, NULL);

	return 0;
}

static void xen_smp_cpus_done(unsigned int max_cpus)
{
}

#ifdef CONFIG_HOTPLUG_CPU
static int xen_cpu_disable(void)
{
	unsigned int cpu = smp_processor_id();
	if (cpu == 0)
		return -EBUSY;

	cpu_disable_common();

	load_cr3(swapper_pg_dir);
	return 0;
}

static void xen_cpu_die(unsigned int cpu)
{
	while (xen_pv_domain() && HYPERVISOR_vcpu_op(VCPUOP_is_up, cpu, NULL)) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ/10);
	}

	if (common_cpu_die(cpu) == 0) {
		xen_smp_intr_free(cpu);
		xen_uninit_lock_cpu(cpu);
		xen_teardown_timer(cpu);
		xen_pmu_finish(cpu);
	}
}

static void xen_play_dead(void) /* used only with HOTPLUG_CPU */
{
	play_dead_common();
	HYPERVISOR_vcpu_op(VCPUOP_down, smp_processor_id(), NULL);
	cpu_bringup();
	/*
	 * commit 4b0c0f294 (tick: Cleanup NOHZ per cpu data on cpu down)
	 * clears certain data that the cpu_idle loop (which called us
	 * and that we return from) expects. The only way to get that
	 * data back is to call:
	 */
	tick_nohz_idle_enter();
}

#else /* !CONFIG_HOTPLUG_CPU */
static int xen_cpu_disable(void)
{
	return -ENOSYS;
}

static void xen_cpu_die(unsigned int cpu)
{
	BUG();
}

static void xen_play_dead(void)
{
	BUG();
}

#endif
static void stop_self(void *v)
{
	int cpu = smp_processor_id();

	/* make sure we're not pinning something down */
	load_cr3(swapper_pg_dir);
	/* should set up a minimal gdt */

	set_cpu_online(cpu, false);

	HYPERVISOR_vcpu_op(VCPUOP_down, cpu, NULL);
	BUG();
}

static void xen_smp_send_stop(void)
{
	smp_call_function(stop_self, NULL, 0);
static void xen_stop_other_cpus(int wait)
{
	smp_call_function(stop_self, NULL, wait);
}

static void xen_smp_send_reschedule(int cpu)
void xen_smp_send_reschedule(int cpu)
{
	xen_send_IPI_one(cpu, XEN_RESCHEDULE_VECTOR);
}

static void xen_send_IPI_mask(cpumask_t mask, enum ipi_vector vector)
{
	unsigned cpu;

	cpus_and(mask, mask, cpu_online_map);

	for_each_cpu_mask_nr(cpu, mask)
		xen_send_IPI_one(cpu, vector);
}

static void xen_smp_send_call_function_ipi(cpumask_t mask)
{
	int cpu;

	xen_send_IPI_mask(mask, XEN_CALL_FUNCTION_VECTOR);

	/* Make sure other vcpus get a chance to run if they need to. */
	for_each_cpu_mask_nr(cpu, mask) {
		if (xen_vcpu_stolen(cpu)) {
			HYPERVISOR_sched_op(SCHEDOP_yield, 0);
static void __xen_send_IPI_mask(const struct cpumask *mask,
			      int vector)
{
	unsigned cpu;

	for_each_cpu_and(cpu, mask, cpu_online_mask)
		xen_send_IPI_one(cpu, vector);
}

void xen_smp_send_call_function_ipi(const struct cpumask *mask)
{
	int cpu;

	__xen_send_IPI_mask(mask, XEN_CALL_FUNCTION_VECTOR);

	/* Make sure other vcpus get a chance to run if they need to. */
	for_each_cpu(cpu, mask) {
		if (xen_vcpu_stolen(cpu)) {
			HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
			break;
		}
	}
}

void xen_smp_send_call_function_single_ipi(int cpu)
{
	xen_send_IPI_mask(cpumask_of_cpu(cpu), XEN_CALL_FUNCTION_SINGLE_VECTOR);
	__xen_send_IPI_mask(cpumask_of(cpu),
			  XEN_CALL_FUNCTION_SINGLE_VECTOR);
}

static inline int xen_map_vector(int vector)
{
	int xen_vector;

	switch (vector) {
	case RESCHEDULE_VECTOR:
		xen_vector = XEN_RESCHEDULE_VECTOR;
		break;
	case CALL_FUNCTION_VECTOR:
		xen_vector = XEN_CALL_FUNCTION_VECTOR;
		break;
	case CALL_FUNCTION_SINGLE_VECTOR:
		xen_vector = XEN_CALL_FUNCTION_SINGLE_VECTOR;
		break;
	case IRQ_WORK_VECTOR:
		xen_vector = XEN_IRQ_WORK_VECTOR;
		break;
#ifdef CONFIG_X86_64
	case NMI_VECTOR:
	case APIC_DM_NMI: /* Some use that instead of NMI_VECTOR */
		xen_vector = XEN_NMI_VECTOR;
		break;
#endif
	default:
		xen_vector = -1;
		printk(KERN_ERR "xen: vector 0x%x is not implemented\n",
			vector);
	}

	return xen_vector;
}

void xen_send_IPI_mask(const struct cpumask *mask,
			      int vector)
{
	int xen_vector = xen_map_vector(vector);

	if (xen_vector >= 0)
		__xen_send_IPI_mask(mask, xen_vector);
}

void xen_send_IPI_all(int vector)
{
	int xen_vector = xen_map_vector(vector);

	if (xen_vector >= 0)
		__xen_send_IPI_mask(cpu_online_mask, xen_vector);
}

void xen_send_IPI_self(int vector)
{
	int xen_vector = xen_map_vector(vector);

	if (xen_vector >= 0)
		xen_send_IPI_one(smp_processor_id(), xen_vector);
}

void xen_send_IPI_mask_allbutself(const struct cpumask *mask,
				int vector)
{
	unsigned cpu;
	unsigned int this_cpu = smp_processor_id();
	int xen_vector = xen_map_vector(vector);

	if (!(num_online_cpus() > 1) || (xen_vector < 0))
		return;

	for_each_cpu_and(cpu, mask, cpu_online_mask) {
		if (this_cpu == cpu)
			continue;

		xen_send_IPI_one(cpu, xen_vector);
	}
}

void xen_send_IPI_allbutself(int vector)
{
	xen_send_IPI_mask_allbutself(cpu_online_mask, vector);
}

static irqreturn_t xen_call_function_interrupt(int irq, void *dev_id)
{
	irq_enter();
	generic_smp_call_function_interrupt();
#ifdef CONFIG_X86_32
	__get_cpu_var(irq_stat).irq_call_count++;
#else
	add_pda(irq_call_count, 1);
#endif
	inc_irq_stat(irq_call_count);
	irq_exit();

	return IRQ_HANDLED;
}

static irqreturn_t xen_call_function_single_interrupt(int irq, void *dev_id)
{
	irq_enter();
	generic_smp_call_function_single_interrupt();
#ifdef CONFIG_X86_32
	__get_cpu_var(irq_stat).irq_call_count++;
#else
	add_pda(irq_call_count, 1);
#endif
	inc_irq_stat(irq_call_count);
	irq_exit();

	return IRQ_HANDLED;
}

struct xen_spinlock {
	unsigned char lock;		/* 0 -> free; 1 -> locked */
	unsigned short spinners;	/* count of waiting cpus */
};

static int xen_spin_is_locked(struct raw_spinlock *lock)
{
	struct xen_spinlock *xl = (struct xen_spinlock *)lock;

	return xl->lock != 0;
}

static int xen_spin_is_contended(struct raw_spinlock *lock)
{
	struct xen_spinlock *xl = (struct xen_spinlock *)lock;

	/* Not strictly true; this is only the count of contended
	   lock-takers entering the slow path. */
	return xl->spinners != 0;
}

static int xen_spin_trylock(struct raw_spinlock *lock)
{
	struct xen_spinlock *xl = (struct xen_spinlock *)lock;
	u8 old = 1;

	asm("xchgb %b0,%1"
	    : "+q" (old), "+m" (xl->lock) : : "memory");

	return old == 0;
}

static DEFINE_PER_CPU(int, lock_kicker_irq) = -1;
static DEFINE_PER_CPU(struct xen_spinlock *, lock_spinners);

static inline void spinning_lock(struct xen_spinlock *xl)
{
	__get_cpu_var(lock_spinners) = xl;
	wmb();			/* set lock of interest before count */
	asm(LOCK_PREFIX " incw %0"
	    : "+m" (xl->spinners) : : "memory");
}

static inline void unspinning_lock(struct xen_spinlock *xl)
{
	asm(LOCK_PREFIX " decw %0"
	    : "+m" (xl->spinners) : : "memory");
	wmb();			/* decrement count before clearing lock */
	__get_cpu_var(lock_spinners) = NULL;
}

static noinline int xen_spin_lock_slow(struct raw_spinlock *lock)
{
	struct xen_spinlock *xl = (struct xen_spinlock *)lock;
	int irq = __get_cpu_var(lock_kicker_irq);
	int ret;

	/* If kicker interrupts not initialized yet, just spin */
	if (irq == -1)
		return 0;

	/* announce we're spinning */
	spinning_lock(xl);

	/* clear pending */
	xen_clear_irq_pending(irq);

	/* check again make sure it didn't become free while
	   we weren't looking  */
	ret = xen_spin_trylock(lock);
	if (ret)
		goto out;

	/* block until irq becomes pending */
	xen_poll_irq(irq);
	kstat_this_cpu.irqs[irq]++;

out:
	unspinning_lock(xl);
	return ret;
}

static void xen_spin_lock(struct raw_spinlock *lock)
{
	struct xen_spinlock *xl = (struct xen_spinlock *)lock;
	int timeout;
	u8 oldval;

	do {
		timeout = 1 << 10;

		asm("1: xchgb %1,%0\n"
		    "   testb %1,%1\n"
		    "   jz 3f\n"
		    "2: rep;nop\n"
		    "   cmpb $0,%0\n"
		    "   je 1b\n"
		    "   dec %2\n"
		    "   jnz 2b\n"
		    "3:\n"
		    : "+m" (xl->lock), "=q" (oldval), "+r" (timeout)
		    : "1" (1)
		    : "memory");

	} while (unlikely(oldval != 0 && !xen_spin_lock_slow(lock)));
}

static noinline void xen_spin_unlock_slow(struct xen_spinlock *xl)
{
	int cpu;

	for_each_online_cpu(cpu) {
		/* XXX should mix up next cpu selection */
		if (per_cpu(lock_spinners, cpu) == xl) {
			xen_send_IPI_one(cpu, XEN_SPIN_UNLOCK_VECTOR);
			break;
		}
	}
}

static void xen_spin_unlock(struct raw_spinlock *lock)
{
	struct xen_spinlock *xl = (struct xen_spinlock *)lock;

	smp_wmb();		/* make sure no writes get moved after unlock */
	xl->lock = 0;		/* release lock */

	/* make sure unlock happens before kick */
	barrier();

	if (unlikely(xl->spinners))
		xen_spin_unlock_slow(xl);
}

static __cpuinit void xen_init_lock_cpu(int cpu)
{
	int irq;
	const char *name;

	name = kasprintf(GFP_KERNEL, "spinlock%d", cpu);
	irq = bind_ipi_to_irqhandler(XEN_SPIN_UNLOCK_VECTOR,
				     cpu,
				     xen_reschedule_interrupt,
				     IRQF_DISABLED|IRQF_PERCPU|IRQF_NOBALANCING,
				     name,
				     NULL);

	if (irq >= 0) {
		disable_irq(irq); /* make sure it's never delivered */
		per_cpu(lock_kicker_irq, cpu) = irq;
	}

	printk("cpu %d spinlock event irq %d\n", cpu, irq);
}

static void __init xen_init_spinlocks(void)
{
	pv_lock_ops.spin_is_locked = xen_spin_is_locked;
	pv_lock_ops.spin_is_contended = xen_spin_is_contended;
	pv_lock_ops.spin_lock = xen_spin_lock;
	pv_lock_ops.spin_trylock = xen_spin_trylock;
	pv_lock_ops.spin_unlock = xen_spin_unlock;
}

static const struct smp_ops xen_smp_ops __initdata = {
	.smp_prepare_boot_cpu = xen_smp_prepare_boot_cpu,
	.smp_prepare_cpus = xen_smp_prepare_cpus,
	.cpu_up = xen_cpu_up,
	.smp_cpus_done = xen_smp_cpus_done,

	.smp_send_stop = xen_smp_send_stop,
static irqreturn_t xen_irq_work_interrupt(int irq, void *dev_id)
{
	irq_enter();
	irq_work_run();
	inc_irq_stat(apic_irq_work_irqs);
	irq_exit();

	return IRQ_HANDLED;
}

static const struct smp_ops xen_smp_ops __initconst = {
	.smp_prepare_boot_cpu = xen_smp_prepare_boot_cpu,
	.smp_prepare_cpus = xen_smp_prepare_cpus,
	.smp_cpus_done = xen_smp_cpus_done,

	.cpu_up = xen_cpu_up,
	.cpu_die = xen_cpu_die,
	.cpu_disable = xen_cpu_disable,
	.play_dead = xen_play_dead,

	.stop_other_cpus = xen_stop_other_cpus,
	.smp_send_reschedule = xen_smp_send_reschedule,

	.send_call_func_ipi = xen_smp_send_call_function_ipi,
	.send_call_func_single_ipi = xen_smp_send_call_function_single_ipi,
};

void __init xen_smp_init(void)
{
	smp_ops = xen_smp_ops;
	xen_fill_possible_map();
	xen_init_spinlocks();
}

static void __init xen_hvm_smp_prepare_cpus(unsigned int max_cpus)
{
	native_smp_prepare_cpus(max_cpus);
	WARN_ON(xen_smp_intr_init(0));

	xen_init_lock_cpu(0);
}

static int xen_hvm_cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	int rc;

	/*
	 * This can happen if CPU was offlined earlier and
	 * offlining timed out in common_cpu_die().
	 */
	if (cpu_report_state(cpu) == CPU_DEAD_FROZEN) {
		xen_smp_intr_free(cpu);
		xen_uninit_lock_cpu(cpu);
	}

	/*
	 * xen_smp_intr_init() needs to run before native_cpu_up()
	 * so that IPI vectors are set up on the booting CPU before
	 * it is marked online in native_cpu_up().
	*/
	rc = xen_smp_intr_init(cpu);
	WARN_ON(rc);
	if (!rc)
		rc =  native_cpu_up(cpu, tidle);

	/*
	 * We must initialize the slowpath CPU kicker _after_ the native
	 * path has executed. If we initialized it before none of the
	 * unlocker IPI kicks would reach the booting CPU as the booting
	 * CPU had not set itself 'online' in cpu_online_mask. That mask
	 * is checked when IPIs are sent (on HVM at least).
	 */
	xen_init_lock_cpu(cpu);
	return rc;
}

void __init xen_hvm_smp_init(void)
{
	if (!xen_have_vector_callback)
		return;
	smp_ops.smp_prepare_cpus = xen_hvm_smp_prepare_cpus;
	smp_ops.smp_send_reschedule = xen_smp_send_reschedule;
	smp_ops.cpu_up = xen_hvm_cpu_up;
	smp_ops.cpu_die = xen_cpu_die;
	smp_ops.send_call_func_ipi = xen_smp_send_call_function_ipi;
	smp_ops.send_call_func_single_ipi = xen_smp_send_call_function_single_ipi;
	smp_ops.smp_prepare_boot_cpu = xen_smp_prepare_boot_cpu;
}
