/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 *
 *  X86-64 port
 *	Andi Kleen.
 *
 *	CPU hotplug support - ashok.raj@intel.com
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#include <stdarg.h>

#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/interrupt.h>
#include <linux/utsname.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/tick.h>
#include <linux/prctl.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/mmu_context.h>
#include <asm/pda.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/ptrace.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/prctl.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/ftrace.h>
#include <linux/syscalls.h>

#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/fpu/internal.h>
#include <asm/mmu_context.h>
#include <asm/prctl.h>
#include <asm/desc.h>
#include <asm/proto.h>
#include <asm/ia32.h>
#include <asm/idle.h>

asmlinkage extern void ret_from_fork(void);

unsigned long kernel_thread_flags = CLONE_VM | CLONE_UNTRACED;

static ATOMIC_NOTIFIER_HEAD(idle_notifier);

void idle_notifier_register(struct notifier_block *n)
{
	atomic_notifier_chain_register(&idle_notifier, n);
}

void enter_idle(void)
{
	write_pda(isidle, 1);
	atomic_notifier_call_chain(&idle_notifier, IDLE_START, NULL);
}

static void __exit_idle(void)
{
	if (test_and_clear_bit_pda(0, isidle) == 0)
		return;
	atomic_notifier_call_chain(&idle_notifier, IDLE_END, NULL);
}

/* Called from interrupts to signify idle end */
void exit_idle(void)
{
	/* idle loop has pid 0 */
	if (current->pid)
		return;
	__exit_idle();
}

#ifdef CONFIG_HOTPLUG_CPU
DECLARE_PER_CPU(int, cpu_state);

#include <asm/nmi.h>
/* We halt the CPU with physical CPU hotplug */
static inline void play_dead(void)
{
	idle_task_exit();
	c1e_remove_cpu(raw_smp_processor_id());

	mb();
	/* Ack it */
	__get_cpu_var(cpu_state) = CPU_DEAD;

	local_irq_disable();
	/* mask all interrupts, flush any and all caches, and halt */
	wbinvd_halt();
}
#else
static inline void play_dead(void)
{
	BUG();
}
#endif /* CONFIG_HOTPLUG_CPU */

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
void cpu_idle(void)
{
	current_thread_info()->status |= TS_POLLING;
	/* endless idle loop with no priority at all */
	while (1) {
		tick_nohz_stop_sched_tick(1);
		while (!need_resched()) {

			rmb();

			if (cpu_is_offline(smp_processor_id()))
				play_dead();
			/*
			 * Idle routines should keep interrupts disabled
			 * from here on, until they go to idle.
			 * Otherwise, idle callbacks can misfire.
			 */
			local_irq_disable();
			enter_idle();
			/* Don't trace irqs off for idle */
			stop_critical_timings();
			pm_idle();
			start_critical_timings();
			/* In many cases the interrupt that ended idle
			   has already called exit_idle. But some idle
			   loops can be woken up without interrupt. */
			__exit_idle();
		}

		tick_nohz_restart_sched_tick();
		preempt_enable_no_resched();
		schedule();
		preempt_disable();
	}
}

/* Prints also some state that isn't saved in the pt_regs */
void __show_regs(struct pt_regs * regs)
#include <asm/syscalls.h>
#include <asm/debugreg.h>
#include <asm/switch_to.h>
#include <asm/xen/hypervisor.h>
#include <asm/vdso.h>
#include <asm/intel_rdt_sched.h>
#include <asm/unistd.h>
#ifdef CONFIG_IA32_EMULATION
/* Not included via unistd.h */
#include <asm/unistd_32_ia32.h>
#endif

__visible DEFINE_PER_CPU(unsigned long, rsp_scratch);

/* Prints also some state that isn't saved in the pt_regs */
void __show_regs(struct pt_regs *regs, int all)
{
	unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L, fs, gs, shadowgs;
	unsigned long d0, d1, d2, d3, d6, d7;
	unsigned int fsindex, gsindex;
	unsigned int ds, cs, es;

	printk("\n");
	print_modules();
	printk("Pid: %d, comm: %.20s %s %s %.*s\n",
		current->pid, current->comm, print_tainted(),
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);
	printk("RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->ip);
	printk_address(regs->ip, 1);
	printk("RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss, regs->sp,
		regs->flags);
	printk("RAX: %016lx RBX: %016lx RCX: %016lx\n",
	       regs->ax, regs->bx, regs->cx);
	printk("RDX: %016lx RSI: %016lx RDI: %016lx\n",
	       regs->dx, regs->si, regs->di);
	printk("RBP: %016lx R08: %016lx R09: %016lx\n",
	       regs->bp, regs->r8, regs->r9);
	printk("R10: %016lx R11: %016lx R12: %016lx\n",
	       regs->r10, regs->r11, regs->r12); 
	printk("R13: %016lx R14: %016lx R15: %016lx\n",
	       regs->r13, regs->r14, regs->r15); 

	asm("movl %%ds,%0" : "=r" (ds)); 
	asm("movl %%cs,%0" : "=r" (cs)); 
	asm("movl %%es,%0" : "=r" (es)); 
	printk(KERN_DEFAULT "RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->ip);
	printk_address(regs->ip);
	printk(KERN_DEFAULT "RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss,
			regs->sp, regs->flags);
	printk(KERN_DEFAULT "RIP: %04lx:%pS\n", regs->cs, (void *)regs->ip);
	printk(KERN_DEFAULT "RSP: %04lx:%016lx EFLAGS: %08lx", regs->ss,
		regs->sp, regs->flags);
	show_iret_regs(regs);

	if (regs->orig_ax != -1)
		pr_cont(" ORIG_RAX: %016lx\n", regs->orig_ax);
	else
		pr_cont("\n");

	printk(KERN_DEFAULT "RAX: %016lx RBX: %016lx RCX: %016lx\n",
	       regs->ax, regs->bx, regs->cx);
	printk(KERN_DEFAULT "RDX: %016lx RSI: %016lx RDI: %016lx\n",
	       regs->dx, regs->si, regs->di);
	printk(KERN_DEFAULT "RBP: %016lx R08: %016lx R09: %016lx\n",
	       regs->bp, regs->r8, regs->r9);
	printk(KERN_DEFAULT "R10: %016lx R11: %016lx R12: %016lx\n",
	       regs->r10, regs->r11, regs->r12);
	printk(KERN_DEFAULT "R13: %016lx R14: %016lx R15: %016lx\n",
	       regs->r13, regs->r14, regs->r15);

	if (!all)
		return;

	asm("movl %%ds,%0" : "=r" (ds));
	asm("movl %%cs,%0" : "=r" (cs));
	asm("movl %%es,%0" : "=r" (es));
	asm("movl %%fs,%0" : "=r" (fsindex));
	asm("movl %%gs,%0" : "=r" (gsindex));

	rdmsrl(MSR_FS_BASE, fs);
	rdmsrl(MSR_GS_BASE, gs); 
	rdmsrl(MSR_KERNEL_GS_BASE, shadowgs); 
	rdmsrl(MSR_GS_BASE, gs);
	rdmsrl(MSR_KERNEL_GS_BASE, shadowgs);

	cr0 = read_cr0();
	cr2 = read_cr2();
	cr3 = read_cr3();
	cr4 = read_cr4();

	printk("FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n", 
	       fs,fsindex,gs,gsindex,shadowgs); 
	printk("CS:  %04x DS: %04x ES: %04x CR0: %016lx\n", cs, ds, es, cr0); 
	printk("CR2: %016lx CR3: %016lx CR4: %016lx\n", cr2, cr3, cr4);
	cr3 = __read_cr3();
	cr4 = __read_cr4();

	printk(KERN_DEFAULT "FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n",
	       fs, fsindex, gs, gsindex, shadowgs);
	printk(KERN_DEFAULT "CS:  %04x DS: %04x ES: %04x CR0: %016lx\n", cs, ds,
			es, cr0);
	printk(KERN_DEFAULT "CR2: %016lx CR3: %016lx CR4: %016lx\n", cr2, cr3,
			cr4);

	get_debugreg(d0, 0);
	get_debugreg(d1, 1);
	get_debugreg(d2, 2);
	printk("DR0: %016lx DR1: %016lx DR2: %016lx\n", d0, d1, d2);
	get_debugreg(d3, 3);
	get_debugreg(d6, 6);
	get_debugreg(d7, 7);
	printk("DR3: %016lx DR6: %016lx DR7: %016lx\n", d3, d6, d7);
}

void show_regs(struct pt_regs *regs)
{
	printk("CPU %d:", smp_processor_id());
	__show_regs(regs);
	show_trace(NULL, regs, (void *)(regs + 1), regs->bp);
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
	struct task_struct *me = current;
	struct thread_struct *t = &me->thread;

	if (me->thread.io_bitmap_ptr) {
		struct tss_struct *tss = &per_cpu(init_tss, get_cpu());

		kfree(t->io_bitmap_ptr);
		t->io_bitmap_ptr = NULL;
		clear_thread_flag(TIF_IO_BITMAP);
		/*
		 * Careful, clear this in the TSS too:
		 */
		memset(tss->io_bitmap, 0xff, t->io_bitmap_max);
		t->io_bitmap_max = 0;
		put_cpu();
	}
}

void flush_thread(void)
{
	struct task_struct *tsk = current;

	if (test_tsk_thread_flag(tsk, TIF_ABI_PENDING)) {
		clear_tsk_thread_flag(tsk, TIF_ABI_PENDING);
		if (test_tsk_thread_flag(tsk, TIF_IA32)) {
			clear_tsk_thread_flag(tsk, TIF_IA32);
		} else {
			set_tsk_thread_flag(tsk, TIF_IA32);
			current_thread_info()->status |= TS_COMPAT;
		}
	}
	clear_tsk_thread_flag(tsk, TIF_DEBUG);

	tsk->thread.debugreg0 = 0;
	tsk->thread.debugreg1 = 0;
	tsk->thread.debugreg2 = 0;
	tsk->thread.debugreg3 = 0;
	tsk->thread.debugreg6 = 0;
	tsk->thread.debugreg7 = 0;
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));
	/*
	 * Forget coprocessor state..
	 */
	tsk->fpu_counter = 0;
	clear_fpu(tsk);
	clear_used_math();
	get_debugreg(d3, 3);
	get_debugreg(d6, 6);
	get_debugreg(d7, 7);

	/* Only print out debug registers if they are in their non-default state. */
	if (!((d0 == 0) && (d1 == 0) && (d2 == 0) && (d3 == 0) &&
	    (d6 == DR6_RESERVED) && (d7 == 0x400))) {
		printk(KERN_DEFAULT "DR0: %016lx DR1: %016lx DR2: %016lx\n",
		       d0, d1, d2);
		printk(KERN_DEFAULT "DR3: %016lx DR6: %016lx DR7: %016lx\n",
		       d3, d6, d7);
	}

	if (boot_cpu_has(X86_FEATURE_OSPKE))
		printk(KERN_DEFAULT "PKRU: %08x\n", read_pkru());
}

void release_thread(struct task_struct *dead_task)
{
	if (dead_task->mm) {
		if (dead_task->mm->context.size) {
			printk("WARNING: dead process %8s still has LDT? <%p/%d>\n",
					dead_task->comm,
					dead_task->mm->context.ldt,
					dead_task->mm->context.size);
			BUG();
		}
#ifdef CONFIG_MODIFY_LDT_SYSCALL
		if (dead_task->mm->context.ldt) {
			pr_warn("WARNING: dead process %s still has LDT? <%p/%d>\n",
				dead_task->comm,
				dead_task->mm->context.ldt->entries,
				dead_task->mm->context.ldt->nr_entries);
			BUG();
		}
#endif
	}
}

enum which_selector {
	FS,
	GS
};

/*
 * Saves the FS or GS base for an outgoing thread if FSGSBASE extensions are
 * not available.  The goal is to be reasonably fast on non-FSGSBASE systems.
 * It's forcibly inlined because it'll generate better code and this function
 * is hot.
 */
static __always_inline void save_base_legacy(struct task_struct *prev_p,
					     unsigned short selector,
					     enum which_selector which)
{
	if (likely(selector == 0)) {
		/*
		 * On Intel (without X86_BUG_NULL_SEG), the segment base could
		 * be the pre-existing saved base or it could be zero.  On AMD
		 * (with X86_BUG_NULL_SEG), the segment base could be almost
		 * anything.
		 *
		 * This branch is very hot (it's hit twice on almost every
		 * context switch between 64-bit programs), and avoiding
		 * the RDMSR helps a lot, so we just assume that whatever
		 * value is already saved is correct.  This matches historical
		 * Linux behavior, so it won't break existing applications.
		 *
		 * To avoid leaking state, on non-X86_BUG_NULL_SEG CPUs, if we
		 * report that the base is zero, it needs to actually be zero:
		 * see the corresponding logic in load_seg_legacy.
		 */
	} else {
		/*
		 * If the selector is 1, 2, or 3, then the base is zero on
		 * !X86_BUG_NULL_SEG CPUs and could be anything on
		 * X86_BUG_NULL_SEG CPUs.  In the latter case, Linux
		 * has never attempted to preserve the base across context
		 * switches.
		 *
		 * If selector > 3, then it refers to a real segment, and
		 * saving the base isn't necessary.
		 */
		if (which == FS)
			prev_p->thread.fsbase = 0;
		else
			prev_p->thread.gsbase = 0;
	}
}

static __always_inline void save_fsgs(struct task_struct *task)
{
	savesegment(fs, task->thread.fsindex);
	savesegment(gs, task->thread.gsindex);
	save_base_legacy(task, task->thread.fsindex, FS);
	save_base_legacy(task, task->thread.gsindex, GS);
}

static __always_inline void loadseg(enum which_selector which,
				    unsigned short sel)
{
	if (which == FS)
		loadsegment(fs, sel);
	else
		load_gs_index(sel);
}

static __always_inline void load_seg_legacy(unsigned short prev_index,
					    unsigned long prev_base,
					    unsigned short next_index,
					    unsigned long next_base,
					    enum which_selector which)
{
	if (likely(next_index <= 3)) {
		/*
		 * The next task is using 64-bit TLS, is not using this
		 * segment at all, or is having fun with arcane CPU features.
		 */
		if (next_base == 0) {
			/*
			 * Nasty case: on AMD CPUs, we need to forcibly zero
			 * the base.
			 */
			if (static_cpu_has_bug(X86_BUG_NULL_SEG)) {
				loadseg(which, __USER_DS);
				loadseg(which, next_index);
			} else {
				/*
				 * We could try to exhaustively detect cases
				 * under which we can skip the segment load,
				 * but there's really only one case that matters
				 * for performance: if both the previous and
				 * next states are fully zeroed, we can skip
				 * the load.
				 *
				 * (This assumes that prev_base == 0 has no
				 * false positives.  This is the case on
				 * Intel-style CPUs.)
				 */
				if (likely(prev_index | next_index | prev_base))
					loadseg(which, next_index);
			}
		} else {
			if (prev_index != next_index)
				loadseg(which, next_index);
			wrmsrl(which == FS ? MSR_FS_BASE : MSR_KERNEL_GS_BASE,
			       next_base);
		}
	} else {
		/*
		 * The next task is using a real segment.  Loading the selector
		 * is sufficient.
		 */
		loadseg(which, next_index);
	}
}

/*
 * This gets called before we allocate a new thread and copy
 * the current task into it.
 */
void prepare_to_copy(struct task_struct *tsk)
{
	unlazy_fpu(tsk);
}

int copy_thread(int nr, unsigned long clone_flags, unsigned long sp,
		unsigned long unused,
	struct task_struct * p, struct pt_regs * regs)
{
	int err;
	struct pt_regs * childregs;
	struct task_struct *me = current;

	childregs = ((struct pt_regs *)
			(THREAD_SIZE + task_stack_page(p))) - 1;
	*childregs = *regs;

	childregs->ax = 0;
	childregs->sp = sp;
	if (sp == ~0UL)
		childregs->sp = (unsigned long)childregs;

	p->thread.sp = (unsigned long) childregs;
	p->thread.sp0 = (unsigned long) (childregs+1);
	p->thread.usersp = me->thread.usersp;

	set_tsk_thread_flag(p, TIF_FORK);

	p->thread.fs = me->thread.fs;
	p->thread.gs = me->thread.gs;

	savesegment(gs, p->thread.gsindex);
	savesegment(fs, p->thread.fsindex);
	savesegment(es, p->thread.es);
	savesegment(ds, p->thread.ds);

	if (unlikely(test_tsk_thread_flag(me, TIF_IO_BITMAP))) {
		p->thread.io_bitmap_ptr = kmalloc(IO_BITMAP_BYTES, GFP_KERNEL);
int copy_thread_tls(unsigned long clone_flags, unsigned long sp,
		unsigned long arg, struct task_struct *p, unsigned long tls)
{
	int err;
	struct pt_regs *childregs;
	struct fork_frame *fork_frame;
	struct inactive_task_frame *frame;
	struct task_struct *me = current;

	childregs = task_pt_regs(p);
	fork_frame = container_of(childregs, struct fork_frame, regs);
	frame = &fork_frame->frame;
	frame->bp = 0;
	frame->ret_addr = (unsigned long) ret_from_fork;
	p->thread.sp = (unsigned long) fork_frame;
	p->thread.io_bitmap_ptr = NULL;

	savesegment(gs, p->thread.gsindex);
	p->thread.gsbase = p->thread.gsindex ? 0 : me->thread.gsbase;
	savesegment(fs, p->thread.fsindex);
	p->thread.fsbase = p->thread.fsindex ? 0 : me->thread.fsbase;
	savesegment(es, p->thread.es);
	savesegment(ds, p->thread.ds);
	memset(p->thread.ptrace_bps, 0, sizeof(p->thread.ptrace_bps));

	if (unlikely(p->flags & PF_KTHREAD)) {
		/* kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		frame->bx = sp;		/* function */
		frame->r12 = arg;
		return 0;
	}
	frame->bx = 0;
	*childregs = *current_pt_regs();

	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;

	err = -ENOMEM;
	if (unlikely(test_tsk_thread_flag(me, TIF_IO_BITMAP))) {
		p->thread.io_bitmap_ptr = kmemdup(me->thread.io_bitmap_ptr,
						  IO_BITMAP_BYTES, GFP_KERNEL);
		if (!p->thread.io_bitmap_ptr) {
			p->thread.io_bitmap_max = 0;
			return -ENOMEM;
		}
		memcpy(p->thread.io_bitmap_ptr, me->thread.io_bitmap_ptr,
				IO_BITMAP_BYTES);
		set_tsk_thread_flag(p, TIF_IO_BITMAP);
	}

	/*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS) {
#ifdef CONFIG_IA32_EMULATION
		if (test_thread_flag(TIF_IA32))
			err = do_set_thread_area(p, -1,
				(struct user_desc __user *)childregs->si, 0);
		else 			
#endif	 
			err = do_arch_prctl(p, ARCH_SET_FS, childregs->r8); 
		if (err) 
		if (is_ia32_task())
		if (in_ia32_syscall())
			err = do_set_thread_area(p, -1,
				(struct user_desc __user *)tls, 0);
		else
#endif
			err = do_arch_prctl_64(p, ARCH_SET_FS, tls);
		if (err)
			goto out;
	}
	err = 0;
out:
	if (err && p->thread.io_bitmap_ptr) {
		kfree(p->thread.io_bitmap_ptr);
		p->thread.io_bitmap_max = 0;
	}
	return err;
}

void
start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
{
	loadsegment(fs, 0);
	loadsegment(es, 0);
	loadsegment(ds, 0);
	load_gs_index(0);
	regs->ip		= new_ip;
	regs->sp		= new_sp;
	write_pda(oldrsp, new_sp);
	regs->cs		= __USER_CS;
	regs->ss		= __USER_DS;
	regs->flags		= 0x200;
	set_fs(USER_DS);
	/*
	 * Free the old FP and other extended state
	 */
	free_thread_xstate(current);
}
EXPORT_SYMBOL_GPL(start_thread);

static void hard_disable_TSC(void)
{
	write_cr4(read_cr4() | X86_CR4_TSD);
}

void disable_TSC(void)
{
	preempt_disable();
	if (!test_and_set_thread_flag(TIF_NOTSC))
		/*
		 * Must flip the CPU state synchronously with
		 * TIF_NOTSC in the current running context.
		 */
		hard_disable_TSC();
	preempt_enable();
}

static void hard_enable_TSC(void)
{
	write_cr4(read_cr4() & ~X86_CR4_TSD);
}

static void enable_TSC(void)
{
	preempt_disable();
	if (test_and_clear_thread_flag(TIF_NOTSC))
		/*
		 * Must flip the CPU state synchronously with
		 * TIF_NOTSC in the current running context.
		 */
		hard_enable_TSC();
	preempt_enable();
}

int get_tsc_mode(unsigned long adr)
{
	unsigned int val;

	if (test_thread_flag(TIF_NOTSC))
		val = PR_TSC_SIGSEGV;
	else
		val = PR_TSC_ENABLE;

	return put_user(val, (unsigned int __user *)adr);
}

int set_tsc_mode(unsigned int val)
{
	if (val == PR_TSC_SIGSEGV)
		disable_TSC();
	else if (val == PR_TSC_ENABLE)
		enable_TSC();
	else
		return -EINVAL;

	return 0;
}

/*
 * This special macro can be used to load a debugging register
 */
#define loaddebug(thread, r) set_debugreg(thread->debugreg ## r, r)

static inline void __switch_to_xtra(struct task_struct *prev_p,
				    struct task_struct *next_p,
				    struct tss_struct *tss)
{
	struct thread_struct *prev, *next;
	unsigned long debugctl;

	prev = &prev_p->thread,
	next = &next_p->thread;

	debugctl = prev->debugctlmsr;
	if (next->ds_area_msr != prev->ds_area_msr) {
		/* we clear debugctl to make sure DS
		 * is not in use when we change it */
		debugctl = 0;
		update_debugctlmsr(0);
		wrmsrl(MSR_IA32_DS_AREA, next->ds_area_msr);
	}

	if (next->debugctlmsr != debugctl)
		update_debugctlmsr(next->debugctlmsr);

	if (test_tsk_thread_flag(next_p, TIF_DEBUG)) {
		loaddebug(next, 0);
		loaddebug(next, 1);
		loaddebug(next, 2);
		loaddebug(next, 3);
		/* no 4 and 5 */
		loaddebug(next, 6);
		loaddebug(next, 7);
	}

	if (test_tsk_thread_flag(prev_p, TIF_NOTSC) ^
	    test_tsk_thread_flag(next_p, TIF_NOTSC)) {
		/* prev and next are different */
		if (test_tsk_thread_flag(next_p, TIF_NOTSC))
			hard_disable_TSC();
		else
			hard_enable_TSC();
	}

	if (test_tsk_thread_flag(next_p, TIF_IO_BITMAP)) {
		/*
		 * Copy the relevant range of the IO bitmap.
		 * Normally this is 128 bytes or less:
		 */
		memcpy(tss->io_bitmap, next->io_bitmap_ptr,
		       max(prev->io_bitmap_max, next->io_bitmap_max));
	} else if (test_tsk_thread_flag(prev_p, TIF_IO_BITMAP)) {
		/*
		 * Clear any possible leftover bits:
		 */
		memset(tss->io_bitmap, 0xff, prev->io_bitmap_max);
	}

#ifdef X86_BTS
	if (test_tsk_thread_flag(prev_p, TIF_BTS_TRACE_TS))
		ptrace_bts_take_timestamp(prev_p, BTS_TASK_DEPARTS);

	if (test_tsk_thread_flag(next_p, TIF_BTS_TRACE_TS))
		ptrace_bts_take_timestamp(next_p, BTS_TASK_ARRIVES);
#endif
}

	return err;
}

static void
start_thread_common(struct pt_regs *regs, unsigned long new_ip,
		    unsigned long new_sp,
		    unsigned int _cs, unsigned int _ss, unsigned int _ds)
{
	WARN_ON_ONCE(regs != current_pt_regs());

	if (static_cpu_has(X86_BUG_NULL_SEG)) {
		/* Loading zero below won't clear the base. */
		loadsegment(fs, __USER_DS);
		load_gs_index(__USER_DS);
	}

	loadsegment(fs, 0);
	loadsegment(es, _ds);
	loadsegment(ds, _ds);
	load_gs_index(0);

	regs->ip		= new_ip;
	regs->sp		= new_sp;
	regs->cs		= _cs;
	regs->ss		= _ss;
	regs->flags		= X86_EFLAGS_IF;
	force_iret();
}

void
start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
{
	start_thread_common(regs, new_ip, new_sp,
			    __USER_CS, __USER_DS, 0);
}

#ifdef CONFIG_COMPAT
void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp)
{
	start_thread_common(regs, new_ip, new_sp,
			    test_thread_flag(TIF_X32)
			    ? __USER_CS : __USER32_CS,
			    __USER_DS, __USER_DS);
}
#endif

/*
 *	switch_to(x,y) should switch tasks from x to y.
 *
 * This could still be optimized:
 * - fold all the options into a flag word and test it with a single test.
 * - could test fs/gs bitsliced
 *
 * Kprobes not supported here. Set the probe on schedule instead.
 */
struct task_struct *
 * Function graph tracer not supported too.
 */
__visible __notrace_funcgraph struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread;
	struct thread_struct *next = &next_p->thread;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);
	unsigned fsindex, gsindex;

	/* we're going to use this soon, after a few expensive things */
	if (next_p->fpu_counter>5)
		prefetch(next->xstate);

	/*
	 * Reload esp0, LDT and the page table pointer:
	 */
	load_sp0(tss, next);

	/* 
	 * Switch DS and ES.
	 * This won't pick up thread selector changes, but I guess that is ok.
	 */
	savesegment(es, prev->es);
	if (unlikely(next->es | prev->es))
		loadsegment(es, next->es); 

	savesegment(ds, prev->ds);
	if (unlikely(next->ds | prev->ds))
		loadsegment(ds, next->ds);

	struct fpu *prev_fpu = &prev->fpu;
	struct fpu *next_fpu = &next->fpu;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(cpu_tss_rw, cpu);

	WARN_ON_ONCE(IS_ENABLED(CONFIG_DEBUG_ENTRY) &&
		     this_cpu_read(irq_count) != -1);

	switch_fpu_prepare(prev_fpu, cpu);

	/* We must save %fs and %gs before load_TLS() because
	 * %fs and %gs may be cleared by load_TLS().
	 *
	 * (e.g. xen_load_tls())
	 */
	save_fsgs(prev_p);

	load_TLS(next, cpu);

	/*
	 * Leave lazy mode, flushing any hypercalls made here.
	 * This must be done before restoring TLS segments so
	 * the GDT and LDT are properly updated, and must be
	 * done before math_state_restore, so the TS bit is up
	 * to date.
	 */
	arch_leave_lazy_cpu_mode();

	/* 
	 * Switch FS and GS.
	 *
	 * Segment register != 0 always requires a reload.  Also
	 * reload when it has changed.  When prev process used 64bit
	 * base always reload to avoid an information leak.
	 */
	if (unlikely(fsindex | next->fsindex | prev->fs)) {
		loadsegment(fs, next->fsindex);
		/* 
		 * Check if the user used a selector != 0; if yes
		 *  clear 64bit base, since overloaded base is always
		 *  mapped to the Null selector
		 */
		if (fsindex)
			prev->fs = 0;				
	}
	/* when next process has a 64bit base use it */
	/*
	 * Load TLS before restoring any segments so that segment loads
	 * reference the correct GDT entries.
	 */
	load_TLS(next, cpu);

	/*
	 * Leave lazy mode, flushing any hypercalls made here.  This
	 * must be done after loading TLS entries in the GDT but before
	 * loading segments that might reference them, and and it must
	 * be done before fpu__restore(), so the TS bit is up to
	 * date.
	 */
	arch_end_context_switch(next_p);

	/* Switch DS and ES.
	 *
	 * Reading them only returns the selectors, but writing them (if
	 * nonzero) loads the full descriptor from the GDT or LDT.  The
	 * LDT for next is loaded in switch_mm, and the GDT is loaded
	 * above.
	 *
	 * We therefore need to write new values to the segment
	 * registers on every context switch unless both the new and old
	 * values are zero.
	 *
	 * Note that we don't need to do anything for CS and SS, as
	 * those are saved and restored as part of pt_regs.
	 */
	savesegment(es, prev->es);
	if (unlikely(next->es | prev->es))
		loadsegment(es, next->es);

	savesegment(ds, prev->ds);
	if (unlikely(next->ds | prev->ds))
		loadsegment(ds, next->ds);

	load_seg_legacy(prev->fsindex, prev->fsbase,
			next->fsindex, next->fsbase, FS);
	load_seg_legacy(prev->gsindex, prev->gsbase,
			next->gsindex, next->gsbase, GS);

		/*
		 * If user code wrote a nonzero value to FS, then it also
		 * cleared the overridden base address.
		 *
		 * XXX: if user code wrote 0 to FS and cleared the base
		 * address itself, we won't notice and we'll incorrectly
		 * restore the prior base address next time we reschdule
		 * the process.
		 */
		if (fsindex)
			prev->fs = 0;
	}
	if (next->fs)
		wrmsrl(MSR_FS_BASE, next->fs);
	prev->fsindex = fsindex;

	if (unlikely(gsindex | next->gsindex | prev->gs)) {
		load_gs_index(next->gsindex);
		if (gsindex)
			prev->gs = 0;				

		/* This works (and fails) the same way as fsindex above. */
		if (gsindex)
			prev->gs = 0;
	}
	if (next->gs)
		wrmsrl(MSR_KERNEL_GS_BASE, next->gs);
	prev->gsindex = gsindex;

	/* Must be after DS reload */
	unlazy_fpu(prev_p);

	/* 
	 * Switch the PDA and FPU contexts.
	 */
	prev->usersp = read_pda(oldrsp);
	write_pda(oldrsp, next->usersp);
	write_pda(pcurrent, next_p); 

	write_pda(kernelstack,
		  (unsigned long)task_stack_page(next_p) +
		  THREAD_SIZE - PDA_STACKOFFSET);
#ifdef CONFIG_CC_STACKPROTECTOR
	write_pda(stack_canary, next_p->stack_canary);
	/*
	 * Build time only check to make sure the stack_canary is at
	 * offset 40 in the pda; this is a gcc ABI requirement
	 */
	BUILD_BUG_ON(offsetof(struct x8664_pda, stack_canary) != 40);
#endif
	switch_fpu_finish(next_fpu, fpu_switch);
	switch_fpu_finish(next_fpu, cpu);

	/*
	 * Switch the PDA and FPU contexts.
	 */
	this_cpu_write(current_task, next_p);
	this_cpu_write(cpu_current_top_of_stack, task_top_of_stack(next_p));

	/* Reload sp0. */
	update_sp0(next_p);

	/*
	 * Now maybe reload the debug registers and handle I/O bitmaps
	 */
	if (unlikely(task_thread_info(next_p)->flags & _TIF_WORK_CTXSW_NEXT ||
		     task_thread_info(prev_p)->flags & _TIF_WORK_CTXSW_PREV))
		__switch_to_xtra(prev_p, next_p, tss);

	/* If the task has used fpu the last 5 timeslices, just do a full
	 * restore of the math state immediately to avoid the trap; the
	 * chances of needing FPU soon are obviously high now
	 *
	 * tsk_used_math() checks prevent calling math_state_restore(),
	 * which can sleep in the case of !tsk_used_math()
	 */
	if (tsk_used_math(next_p) && next_p->fpu_counter > 5)
		math_state_restore();
	return prev_p;
}

/*
 * sys_execve() executes a new program.
 */
asmlinkage
long sys_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs)
{
	long error;
	char * filename;

	filename = getname(name);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		return error;
	error = do_execve(filename, argv, envp, regs);
	putname(filename);
	return error;
}
#ifdef CONFIG_XEN_PV
	/*
	 * On Xen PV, IOPL bits in pt_regs->flags have no effect, and
	 * current_pt_regs()->flags may not match the current task's
	 * intended IOPL.  We need to switch it manually.
	 */
	if (unlikely(static_cpu_has(X86_FEATURE_XENPV) &&
		     prev->iopl != next->iopl))
		xen_set_iopl_mask(next->iopl);
#endif

	if (static_cpu_has_bug(X86_BUG_SYSRET_SS_ATTRS)) {
		/*
		 * AMD CPUs have a misfeature: SYSRET sets the SS selector but
		 * does not update the cached descriptor.  As a result, if we
		 * do SYSRET while SS is NULL, we'll end up in user mode with
		 * SS apparently equal to __USER_DS but actually unusable.
		 *
		 * The straightforward workaround would be to fix it up just
		 * before SYSRET, but that would slow down the system call
		 * fast paths.  Instead, we ensure that SS is never NULL in
		 * system call context.  We do this by replacing NULL SS
		 * selectors at every context switch.  SYSCALL sets up a valid
		 * SS, so the only way to get NULL is to re-enter the kernel
		 * from CPL 3 through an interrupt.  Since that can't happen
		 * in the same task as a running syscall, we are guaranteed to
		 * context switch between every interrupt vector entry and a
		 * subsequent SYSRET.
		 *
		 * We read SS first because SS reads are much faster than
		 * writes.  Out of caution, we force SS to __KERNEL_DS even if
		 * it previously had a different non-NULL value.
		 */
		unsigned short ss_sel;
		savesegment(ss, ss_sel);
		if (ss_sel != __KERNEL_DS)
			loadsegment(ss, __KERNEL_DS);
	}

	/* Load the Intel cache allocation PQR MSR. */
	intel_rdt_sched_in();

	return prev_p;
}

void set_personality_64bit(void)
{
	/* inherit personality from parent */

	/* Make sure to be in 64bit mode */
	clear_thread_flag(TIF_IA32);
	clear_thread_flag(TIF_ADDR32);
	clear_thread_flag(TIF_X32);
	/* Pretend that this comes from a 64bit execve */
	task_pt_regs(current)->orig_ax = __NR_execve;
	current_thread_info()->status &= ~TS_COMPAT;

	/* Ensure the corresponding mm is not marked. */
	if (current->mm)
		current->mm->context.ia32_compat = 0;

	/* TBD: overwrites user setup. Should have two bits.
	   But 64bit processes have always behaved this way,
	   so it's not too bad. The main problem is just that
	   32bit childs are affected again. */
	current->personality &= ~READ_IMPLIES_EXEC;
}

asmlinkage long sys_fork(struct pt_regs *regs)
{
	return do_fork(SIGCHLD, regs->sp, regs, 0, NULL, NULL);
}

asmlinkage long
sys_clone(unsigned long clone_flags, unsigned long newsp,
	  void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
{
	if (!newsp)
		newsp = regs->sp;
	return do_fork(clone_flags, newsp, regs, 0, parent_tid, child_tid);
}

/*
 * This is trivial, and on the face of it looks like it
 * could equally well be done in user mode.
 *
 * Not so, for quite unobvious reasons - register pressure.
 * In user mode vfork() cannot have a stack frame, and if
 * done by calling the "clone()" system call directly, you
 * do not have enough call-clobbered registers to hold all
 * the information you need.
 */
asmlinkage long sys_vfork(struct pt_regs *regs)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->sp, regs, 0,
		    NULL, NULL);
}

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long stack;
	u64 fp,ip;
	int count = 0;

	if (!p || p == current || p->state==TASK_RUNNING)
		return 0; 
	stack = (unsigned long)task_stack_page(p);
	if (p->thread.sp < stack || p->thread.sp > stack+THREAD_SIZE)
		return 0;
	fp = *(u64 *)(p->thread.sp);
	do { 
		if (fp < (unsigned long)stack ||
		    fp > (unsigned long)stack+THREAD_SIZE)
			return 0; 
		ip = *(u64 *)(fp+8);
		if (!in_sched_functions(ip))
			return ip;
		fp = *(u64 *)fp; 
	} while (count++ < 16); 
	return 0;
}

long do_arch_prctl(struct task_struct *task, int code, unsigned long addr)
{ 
	int ret = 0; 
	int doit = task == current;
	int cpu;

	switch (code) { 
	case ARCH_SET_GS:
		if (addr >= TASK_SIZE_OF(task))
			return -EPERM; 
		cpu = get_cpu();
		/* handle small bases via the GDT because that's faster to 
		   switch. */
		if (addr <= 0xffffffff) {  
			set_32bit_tls(task, GS_TLS, addr); 
			if (doit) { 
				load_TLS(&task->thread, cpu);
				load_gs_index(GS_TLS_SEL); 
			}
			task->thread.gsindex = GS_TLS_SEL; 
			task->thread.gs = 0;
		} else { 
static void __set_personality_x32(void)
{
#ifdef CONFIG_X86_X32
	clear_thread_flag(TIF_IA32);
	set_thread_flag(TIF_X32);
	if (current->mm)
		current->mm->context.ia32_compat = TIF_X32;
	current->personality &= ~READ_IMPLIES_EXEC;
	/*
	 * in_compat_syscall() uses the presence of the x32 syscall bit
	 * flag to determine compat status.  The x86 mmap() code relies on
	 * the syscall bitness so set x32 syscall bit right here to make
	 * in_compat_syscall() work during exec().
	 *
	 * Pretend to come from a x32 execve.
	 */
	task_pt_regs(current)->orig_ax = __NR_x32_execve | __X32_SYSCALL_BIT;
	current_thread_info()->status &= ~TS_COMPAT;
#endif
}

static void __set_personality_ia32(void)
{
#ifdef CONFIG_IA32_EMULATION
	set_thread_flag(TIF_IA32);
	clear_thread_flag(TIF_X32);
	if (current->mm)
		current->mm->context.ia32_compat = TIF_IA32;
	current->personality |= force_personality32;
	/* Prepare the first "return" to user space */
	task_pt_regs(current)->orig_ax = __NR_ia32_execve;
	current_thread_info()->status |= TS_COMPAT;
#endif
}

void set_personality_ia32(bool x32)
{
	/* Make sure to be in 32bit mode */
	set_thread_flag(TIF_ADDR32);

	if (x32)
		__set_personality_x32();
	else
		__set_personality_ia32();
}
EXPORT_SYMBOL_GPL(set_personality_ia32);

#ifdef CONFIG_CHECKPOINT_RESTORE
static long prctl_map_vdso(const struct vdso_image *image, unsigned long addr)
{
	int ret;

	ret = map_vdso_once(image, addr);
	if (ret)
		return ret;

	return (long)image->size;
}
#endif

long do_arch_prctl_64(struct task_struct *task, int option, unsigned long arg2)
{
	int ret = 0;
	int doit = task == current;
	int cpu;

	switch (option) {
	case ARCH_SET_GS:
		if (arg2 >= TASK_SIZE_MAX)
			return -EPERM;
		cpu = get_cpu();
		/* handle small bases via the GDT because that's faster to
		   switch. */
		if (addr <= 0xffffffff) {
			set_32bit_tls(task, GS_TLS, addr);
			if (doit) {
				load_TLS(&task->thread, cpu);
				load_gs_index(GS_TLS_SEL);
			}
			task->thread.gsindex = GS_TLS_SEL;
			task->thread.gs = 0;
		} else {
			task->thread.gsindex = 0;
			task->thread.gs = addr;
			if (doit) {
				load_gs_index(0);
				ret = checking_wrmsrl(MSR_KERNEL_GS_BASE, addr);
			} 
				ret = wrmsrl_safe(MSR_KERNEL_GS_BASE, addr);
			}
		task->thread.gsindex = 0;
		task->thread.gsbase = arg2;
		if (doit) {
			load_gs_index(0);
			ret = wrmsrl_safe(MSR_KERNEL_GS_BASE, arg2);
		}
		put_cpu();
		break;
	case ARCH_SET_FS:
		/* Not strictly needed for fs, but do it for symmetry
		   with gs */
		if (arg2 >= TASK_SIZE_MAX)
			return -EPERM;
		cpu = get_cpu();
		/* handle small bases via the GDT because that's faster to
		   switch. */
		if (addr <= 0xffffffff) {
			set_32bit_tls(task, FS_TLS, addr);
			if (doit) {
				load_TLS(&task->thread, cpu);
				loadsegment(fs, FS_TLS_SEL);
			}
			task->thread.fsindex = FS_TLS_SEL;
			task->thread.fs = 0;
		} else {
			task->thread.fsindex = 0;
			task->thread.fs = addr;
			if (doit) {
				/* set the selector to 0 to not confuse
				   __switch_to */
				loadsegment(fs, 0);
				ret = checking_wrmsrl(MSR_FS_BASE, addr);
				ret = wrmsrl_safe(MSR_FS_BASE, addr);
			}
		task->thread.fsindex = 0;
		task->thread.fsbase = arg2;
		if (doit) {
			/* set the selector to 0 to not confuse __switch_to */
			loadsegment(fs, 0);
			ret = wrmsrl_safe(MSR_FS_BASE, arg2);
		}
		put_cpu();
		break;
	case ARCH_GET_FS: {
		unsigned long base;

		if (doit)
			rdmsrl(MSR_FS_BASE, base);
		else
			base = task->thread.fsbase;
		ret = put_user(base, (unsigned long __user *)arg2);
		break;
	}
	case ARCH_GET_GS: {
		unsigned long base;
		unsigned gsindex;
		if (task->thread.gsindex == GS_TLS_SEL)
			base = read_32bit_tls(task, GS_TLS);
		else if (doit) {
			savesegment(gs, gsindex);
			if (gsindex)
				rdmsrl(MSR_KERNEL_GS_BASE, base);
			else
				base = task->thread.gs;
		}
		else
		} else
			base = task->thread.gs;
		ret = put_user(base, (unsigned long __user *)addr);

		if (doit)
			rdmsrl(MSR_KERNEL_GS_BASE, base);
		else
			base = task->thread.gsbase;
		ret = put_user(base, (unsigned long __user *)arg2);
		break;
	}

#ifdef CONFIG_CHECKPOINT_RESTORE
# ifdef CONFIG_X86_X32_ABI
	case ARCH_MAP_VDSO_X32:
		return prctl_map_vdso(&vdso_image_x32, arg2);
# endif
# if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
	case ARCH_MAP_VDSO_32:
		return prctl_map_vdso(&vdso_image_32, arg2);
# endif
	case ARCH_MAP_VDSO_64:
		return prctl_map_vdso(&vdso_image_64, arg2);
#endif

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

SYSCALL_DEFINE2(arch_prctl, int, option, unsigned long, arg2)
{
	long ret;

	ret = do_arch_prctl_64(current, option, arg2);
	if (ret == -EINVAL)
		ret = do_arch_prctl_common(current, option, arg2);

	return ret;
}

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	unsigned long range_end = mm->brk + 0x02000000;
	return randomize_range(mm->brk, range_end, 0) ? : mm->brk;
#ifdef CONFIG_IA32_EMULATION
COMPAT_SYSCALL_DEFINE2(arch_prctl, int, option, unsigned long, arg2)
{
	return do_arch_prctl_common(current, option, arg2);
}
#endif

unsigned long KSTK_ESP(struct task_struct *task)
{
	return task_pt_regs(task)->sp;
}
