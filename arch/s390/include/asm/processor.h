/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/asm-s390/processor.h
 *
 *  S390 version
 *    Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *  S390 version
 *    Copyright IBM Corp. 1999
 *    Author(s): Hartmut Penner (hp@de.ibm.com),
 *               Martin Schwidefsky (schwidefsky@de.ibm.com)
 *
 *  Derived from "include/asm-i386/processor.h"
 *    Copyright (C) 1994, Linus Torvalds
 */

#ifndef __ASM_S390_PROCESSOR_H
#define __ASM_S390_PROCESSOR_H

#include <asm/ptrace.h>

#ifdef __KERNEL__
#include <linux/const.h>

#define CIF_MCCK_PENDING	0	/* machine check handling is pending */
#define CIF_ASCE_PRIMARY	1	/* primary asce needs fixup / uaccess */
#define CIF_ASCE_SECONDARY	2	/* secondary asce needs fixup / uaccess */
#define CIF_NOHZ_DELAY		3	/* delay HZ disable for a tick */
#define CIF_FPU			4	/* restore FPU registers */
#define CIF_IGNORE_IRQ		5	/* ignore interrupt (for udelay) */
#define CIF_ENABLED_WAIT	6	/* in enabled wait state */
#define CIF_MCCK_GUEST		7	/* machine check happening in guest */
#define CIF_DEDICATED_CPU	8	/* this CPU is dedicated */

#define _CIF_MCCK_PENDING	_BITUL(CIF_MCCK_PENDING)
#define _CIF_ASCE_PRIMARY	_BITUL(CIF_ASCE_PRIMARY)
#define _CIF_ASCE_SECONDARY	_BITUL(CIF_ASCE_SECONDARY)
#define _CIF_NOHZ_DELAY		_BITUL(CIF_NOHZ_DELAY)
#define _CIF_FPU		_BITUL(CIF_FPU)
#define _CIF_IGNORE_IRQ		_BITUL(CIF_IGNORE_IRQ)
#define _CIF_ENABLED_WAIT	_BITUL(CIF_ENABLED_WAIT)
#define _CIF_MCCK_GUEST		_BITUL(CIF_MCCK_GUEST)
#define _CIF_DEDICATED_CPU	_BITUL(CIF_DEDICATED_CPU)

#ifndef __ASSEMBLY__

#include <linux/linkage.h>
#include <linux/irqflags.h>
#include <asm/cpu.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/setup.h>
#include <asm/runtime_instr.h>
#include <asm/fpu/types.h>
#include <asm/fpu/internal.h>

static inline void set_cpu_flag(int flag)
{
	S390_lowcore.cpu_flags |= (1UL << flag);
}

static inline void clear_cpu_flag(int flag)
{
	S390_lowcore.cpu_flags &= ~(1UL << flag);
}

static inline int test_cpu_flag(int flag)
{
	return !!(S390_lowcore.cpu_flags & (1UL << flag));
}

/*
 * Test CIF flag of another CPU. The caller needs to ensure that
 * CPU hotplug can not happen, e.g. by disabling preemption.
 */
static inline int test_cpu_flag_of(int flag, int cpu)
{
	struct lowcore *lc = lowcore_ptr[cpu];
	return !!(lc->cpu_flags & (1UL << flag));
}

#define arch_needs_cpu() test_cpu_flag(CIF_NOHZ_DELAY)

/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() ({ void *pc; asm("basr %0,0" : "=a" (pc)); pc; })

/*
 *  CPU type and hardware bug flags. Kept separately for each CPU.
 *  Members of this structure are referenced in head.S, so think twice
 *  before touching them. [mj]
 */

typedef struct
{
        unsigned int version :  8;
        unsigned int ident   : 24;
        unsigned int machine : 16;
        unsigned int unused  : 16;
} __attribute__ ((packed)) cpuid_t;

static inline void get_cpu_id(cpuid_t *ptr)
{
	asm volatile("stidp 0(%1)" : "=m" (*ptr) : "a" (ptr));
}

struct cpuinfo_S390
{
        cpuid_t  cpu_id;
        __u16    cpu_addr;
        __u16    cpu_nr;
        unsigned long loops_per_jiffy;
        unsigned long *pgd_quick;
#ifdef __s390x__
        unsigned long *pmd_quick;
#endif /* __s390x__ */
        unsigned long *pte_quick;
        unsigned long pgtable_cache_sz;
};

extern void s390_adjust_jiffies(void);
extern void print_cpu_info(struct cpuinfo_S390 *);
extern int get_cpu_capability(unsigned int *);

/*
 * User space process size: 2GB for 31 bit, 4TB for 64 bit.
 */
#ifndef __s390x__

#define TASK_SIZE		(1UL << 31)
#define TASK_UNMAPPED_BASE	(1UL << 30)

#else /* __s390x__ */

#define TASK_SIZE_OF(tsk)	(test_tsk_thread_flag(tsk,TIF_31BIT) ? \
					(1UL << 31) : (1UL << 53))
#define TASK_UNMAPPED_BASE	(test_thread_flag(TIF_31BIT) ? \
					(1UL << 30) : (1UL << 41))
#define TASK_SIZE		TASK_SIZE_OF(current)

#endif /* __s390x__ */

#ifdef __KERNEL__

#ifndef __s390x__
#define STACK_TOP		(1UL << 31)
#define STACK_TOP_MAX		(1UL << 31)
#else /* __s390x__ */
#define STACK_TOP		(1UL << (test_thread_flag(TIF_31BIT) ? 31:42))
#define STACK_TOP_MAX		(1UL << 42)
#endif /* __s390x__ */


#endif
static inline void get_cpu_id(struct cpuid *ptr)
{
	asm volatile("stidp %0" : "=Q" (*ptr));
}

void s390_adjust_jiffies(void);
void s390_update_cpu_mhz(void);
void cpu_detect_mhz_feature(void);

extern const struct seq_operations cpuinfo_op;
extern int sysctl_ieee_emulation_warnings;
extern void execve_tail(void);
extern void __bpon(void);

/*
 * User space process size: 2GB for 31 bit, 4TB or 8PT for 64 bit.
 */

#define TASK_SIZE_OF(tsk)	(test_tsk_thread_flag(tsk, TIF_31BIT) ? \
					(1UL << 31) : -PAGE_SIZE)
#define TASK_UNMAPPED_BASE	(test_thread_flag(TIF_31BIT) ? \
					(1UL << 30) : (1UL << 41))
#define TASK_SIZE		TASK_SIZE_OF(current)
#define TASK_SIZE_MAX		(-PAGE_SIZE)

#define STACK_TOP		(test_thread_flag(TIF_31BIT) ? \
					(1UL << 31) : (1UL << 42))
#define STACK_TOP_MAX		(1UL << 42)

#define HAVE_ARCH_PICK_MMAP_LAYOUT

typedef unsigned int mm_segment_t;

/*
 * Thread structure
 */
struct thread_struct {
	s390_fp_regs fp_regs;
	unsigned int  acrs[NUM_ACRS];
        unsigned long ksp;              /* kernel stack pointer             */
	mm_segment_t mm_segment;
        unsigned long prot_addr;        /* address of protection-excep.     */
        unsigned int trap_no;
        per_struct per_info;
	/* Used to give failing instruction back to user for ieee exceptions */
	unsigned long ieee_instruction_pointer; 
        /* pfault_wait is used to block the process on a pfault event */
	unsigned long pfault_wait;
};

	struct fpu fpu;			/* FP and VX register save area */
	unsigned int  acrs[NUM_ACRS];
        unsigned long ksp;              /* kernel stack pointer             */
	unsigned long user_timer;	/* task cputime in user space */
	unsigned long guest_timer;	/* task cputime in kvm guest */
	unsigned long system_timer;	/* task cputime in kernel space */
	unsigned long hardirq_timer;	/* task cputime in hardirq context */
	unsigned long softirq_timer;	/* task cputime in softirq context */
	unsigned long sys_call_table;	/* system call table address */
	mm_segment_t mm_segment;
	unsigned long gmap_addr;	/* address of last gmap fault. */
	unsigned int gmap_write_flag;	/* gmap fault write indication */
	unsigned int gmap_int_code;	/* int code of last gmap fault */
	unsigned int gmap_pfault;	/* signal of a pending guest pfault */
	/* Per-thread information related to debugging */
	struct per_regs per_user;	/* User specified PER registers */
	struct per_event per_event;	/* Cause of the last PER trap */
	unsigned long per_flags;	/* Flags to control debug behavior */
	unsigned int system_call;	/* system call number in signal */
	unsigned long last_break;	/* last breaking-event-address. */
        /* pfault_wait is used to block the process on a pfault event */
	unsigned long pfault_wait;
	struct list_head list;
	/* cpu runtime instrumentation */
	struct runtime_instr_cb *ri_cb;
	struct gs_cb *gs_cb;		/* Current guarded storage cb */
	struct gs_cb *gs_bc_cb;		/* Broadcast guarded storage cb */
	unsigned char trap_tdb[256];	/* Transaction abort diagnose block */
	/*
	 * Warning: 'fpu' is dynamically-sized. It *MUST* be at
	 * the end.
	 */
	struct fpu fpu;			/* FP and VX register save area */
};

/* Flag to disable transactions. */
#define PER_FLAG_NO_TE			1UL
/* Flag to enable random transaction aborts. */
#define PER_FLAG_TE_ABORT_RAND		2UL
/* Flag to specify random transaction abort mode:
 * - abort each transaction at a random instruction before TEND if set.
 * - abort random transactions at a random instruction if cleared.
 */
#define PER_FLAG_TE_ABORT_RAND_TEND	4UL

typedef struct thread_struct thread_struct;

/*
 * Stack layout of a C stack frame.
 */
#ifndef __PACK_STACK
struct stack_frame {
	unsigned long back_chain;
	unsigned long empty1[5];
	unsigned long gprs[10];
	unsigned int  empty2[8];
};
#else
struct stack_frame {
	unsigned long empty1[5];
	unsigned int  empty2[8];
	unsigned long gprs[10];
	unsigned long back_chain;
};
#endif

#define ARCH_MIN_TASKALIGN	8

#define INIT_THREAD {							\
	.ksp = sizeof(init_stack) + (unsigned long) &init_stack,	\
extern __vector128 init_task_fpu_regs[__NUM_VXRS];
#define INIT_THREAD {							\
	.ksp = sizeof(init_stack) + (unsigned long) &init_stack,	\
	.fpu.regs = (void *) init_task.thread.fpu.fprs,			\
}

/*
 * Do necessary setup to start up a new thread.
 */
#define start_thread(regs, new_psw, new_stackp) do {		\
	set_fs(USER_DS);					\
	regs->psw.mask	= psw_user_bits;			\
	regs->psw.addr	= new_psw | PSW_ADDR_AMODE;		\
	regs->gprs[15]	= new_stackp;				\
} while (0)

#define start_thread31(regs, new_psw, new_stackp) do {		\
	set_fs(USER_DS);					\
	regs->psw.mask	= psw_user32_bits;			\
	regs->psw.addr	= new_psw | PSW_ADDR_AMODE;		\
	regs->gprs[15]	= new_stackp;				\
	crst_table_downgrade(current->mm, 1UL << 31);		\
#define start_thread(regs, new_psw, new_stackp) do {			\
	regs->psw.mask	= PSW_USER_BITS | PSW_MASK_EA | PSW_MASK_BA;	\
	regs->psw.addr	= new_psw;					\
	regs->gprs[15]	= new_stackp;					\
	execve_tail();							\
} while (0)

#define start_thread31(regs, new_psw, new_stackp) do {			\
	regs->psw.mask	= PSW_USER_BITS | PSW_MASK_BA;			\
	regs->psw.addr	= new_psw;					\
	regs->gprs[15]	= new_stackp;					\
	crst_table_downgrade(current->mm);				\
	execve_tail();							\
} while (0)

/* Forward declaration, a strange C thing */
struct task_struct;
struct mm_struct;
struct seq_file;
struct pt_regs;

typedef int (*dump_trace_func_t)(void *data, unsigned long address, int reliable);
void dump_trace(dump_trace_func_t func, void *data,
		struct task_struct *task, unsigned long sp);
void show_registers(struct pt_regs *regs);

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);
extern int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags);

/* Prepare to copy thread state - unlazy all lazy status */
#define prepare_to_copy(tsk)	do { } while (0)
void show_cacheinfo(struct seq_file *m);

/* Free all resources held by a thread. */
static inline void release_thread(struct task_struct *tsk) { }

/* Free guarded storage control block */
void guarded_storage_release(struct task_struct *tsk);

/*
 * Print register of task into buffer. Used in fs/proc/array.c.
 */
extern void task_show_regs(struct seq_file *m, struct task_struct *task);

extern void show_code(struct pt_regs *regs);

unsigned long get_wchan(struct task_struct *p);
#define task_pt_regs(tsk) ((struct pt_regs *) \
        (task_stack_page(tsk) + THREAD_SIZE) - 1)
#define KSTK_EIP(tsk)	(task_pt_regs(tsk)->psw.addr)
#define KSTK_ESP(tsk)	(task_pt_regs(tsk)->gprs[15])

/*
 * Give up the time slice of the virtual PU.
 */
static inline void cpu_relax(void)
{
	if (MACHINE_HAS_DIAG44)
		asm volatile("diag 0,0,68");
	barrier();
}
/* Has task runtime instrumentation enabled ? */
#define is_ri_task(tsk) (!!(tsk)->thread.ri_cb)

static inline unsigned long current_stack_pointer(void)
{
	unsigned long sp;

	asm volatile("la %0,0(15)" : "=a" (sp));
	return sp;
}

static inline unsigned short stap(void)
{
	unsigned short cpu_address;

	asm volatile("stap %0" : "=Q" (cpu_address));
	return cpu_address;
}

/*
 * Give up the time slice of the virtual PU.
 */
#define cpu_relax_yield cpu_relax_yield
void cpu_relax_yield(void);

#define cpu_relax() barrier()

#define ECAG_CACHE_ATTRIBUTE	0
#define ECAG_CPU_ATTRIBUTE	1

static inline unsigned long __ecag(unsigned int asi, unsigned char parm)
{
	unsigned long val;

	asm volatile(".insn	rsy,0xeb000000004c,%0,0,0(%1)" /* ecag */
		     : "=d" (val) : "a" (asi << 8 | parm));
	return val;
}

static inline void psw_set_key(unsigned int key)
{
	asm volatile("spka 0(%0)" : : "d" (key));
}

/*
 * Set PSW to specified value.
 */
static inline void __load_psw(psw_t psw)
{
#ifndef __s390x__
	asm volatile("lpsw  0(%0)" : : "a" (&psw), "m" (psw) : "cc");
#else
	asm volatile("lpswe 0(%0)" : : "a" (&psw), "m" (psw) : "cc");
#endif
	asm volatile("lpswe %0" : : "Q" (psw) : "cc");
}

/*
 * Set PSW mask to specified value, while leaving the
 * PSW addr pointing to the next instruction.
 */

static inline void __load_psw_mask (unsigned long mask)
static inline void __load_psw_mask(unsigned long mask)
{
	unsigned long addr;
	psw_t psw;

	psw.mask = mask;

#ifndef __s390x__
	asm volatile(
		"	basr	%0,0\n"
		"0:	ahi	%0,1f-0b\n"
		"	st	%0,4(%1)\n"
		"	lpsw	0(%1)\n"
		"1:"
		: "=&d" (addr) : "a" (&psw), "m" (psw) : "memory", "cc");
#else /* __s390x__ */
	asm volatile(
		"	larl	%0,1f\n"
		"	stg	%0,8(%1)\n"
		"	lpswe	0(%1)\n"
		"1:"
		: "=&d" (addr) : "a" (&psw), "m" (psw) : "memory", "cc");
#endif /* __s390x__ */
}
 
/*
 * Function to stop a processor until an interruption occurred
 */
static inline void enabled_wait(void)
{
	__load_psw_mask(PSW_BASE_BITS | PSW_MASK_IO | PSW_MASK_EXT |
			PSW_MASK_MCHECK | PSW_MASK_WAIT | PSW_DEFAULT_KEY);
}

/*
 * Function to drop a processor into disabled wait state
 */

static inline void disabled_wait(unsigned long code)
{
        unsigned long ctl_buf;
        psw_t dw_psw;

        dw_psw.mask = PSW_BASE_BITS | PSW_MASK_WAIT;
        dw_psw.addr = code;
        /* 
         * Store status and then load disabled wait psw,
         * the processor is dead afterwards
         */
#ifndef __s390x__
	asm volatile(
		"	stctl	0,0,0(%2)\n"
		"	ni	0(%2),0xef\n"	/* switch off protection */
		"	lctl	0,0,0(%2)\n"
		"	stpt	0xd8\n"		/* store timer */
		"	stckc	0xe0\n"		/* store clock comparator */
		"	stpx	0x108\n"	/* store prefix register */
		"	stam	0,15,0x120\n"	/* store access registers */
		"	std	0,0x160\n"	/* store f0 */
		"	std	2,0x168\n"	/* store f2 */
		"	std	4,0x170\n"	/* store f4 */
		"	std	6,0x178\n"	/* store f6 */
		"	stm	0,15,0x180\n"	/* store general registers */
		"	stctl	0,15,0x1c0\n"	/* store control registers */
		"	oi	0x1c0,0x10\n"	/* fake protection bit */
		"	lpsw	0(%1)"
		: "=m" (ctl_buf)
		: "a" (&dw_psw), "a" (&ctl_buf), "m" (dw_psw) : "cc");
#else /* __s390x__ */
	asm volatile(
		"	stctg	0,0,0(%2)\n"
		"	ni	4(%2),0xef\n"	/* switch off protection */
		"	lctlg	0,0,0(%2)\n"
		"	lghi	1,0x1000\n"
		"	stpt	0x328(1)\n"	/* store timer */
		"	stckc	0x330(1)\n"	/* store clock comparator */
		"	stpx	0x318(1)\n"	/* store prefix register */
		"	stam	0,15,0x340(1)\n"/* store access registers */
		"	stfpc	0x31c(1)\n"	/* store fpu control */
		"	std	0,0x200(1)\n"	/* store f0 */
		"	std	1,0x208(1)\n"	/* store f1 */
		"	std	2,0x210(1)\n"	/* store f2 */
		"	std	3,0x218(1)\n"	/* store f3 */
		"	std	4,0x220(1)\n"	/* store f4 */
		"	std	5,0x228(1)\n"	/* store f5 */
		"	std	6,0x230(1)\n"	/* store f6 */
		"	std	7,0x238(1)\n"	/* store f7 */
		"	std	8,0x240(1)\n"	/* store f8 */
		"	std	9,0x248(1)\n"	/* store f9 */
		"	std	10,0x250(1)\n"	/* store f10 */
		"	std	11,0x258(1)\n"	/* store f11 */
		"	std	12,0x260(1)\n"	/* store f12 */
		"	std	13,0x268(1)\n"	/* store f13 */
		"	std	14,0x270(1)\n"	/* store f14 */
		"	std	15,0x278(1)\n"	/* store f15 */
		"	stmg	0,15,0x280(1)\n"/* store general registers */
		"	stctg	0,15,0x380(1)\n"/* store control registers */
		"	oi	0x384(1),0x10\n"/* fake protection bit */
		"	lpswe	0(%1)"
		: "=m" (ctl_buf)
		: "a" (&dw_psw), "a" (&ctl_buf), "m" (dw_psw) : "cc", "0");
#endif /* __s390x__ */
	asm volatile(
		"	larl	%0,1f\n"
		"	stg	%0,%O1+8(%R1)\n"
		"	lpswe	%1\n"
		"1:"
		: "=&d" (addr), "=Q" (psw) : "Q" (psw) : "memory", "cc");
}

/*
 * Extract current PSW mask
 */
static inline unsigned long __extract_psw(void)
{
	unsigned int reg1, reg2;

	asm volatile("epsw %0,%1" : "=d" (reg1), "=a" (reg2));
	return (((unsigned long) reg1) << 32) | ((unsigned long) reg2);
}

static inline void local_mcck_enable(void)
{
	__load_psw_mask(__extract_psw() | PSW_MASK_MCHECK);
}

static inline void local_mcck_disable(void)
{
	__load_psw_mask(__extract_psw() & ~PSW_MASK_MCHECK);
}

/*
 * Rewind PSW instruction address by specified number of bytes.
 */
static inline unsigned long __rewind_psw(psw_t psw, unsigned long ilc)
{
	unsigned long mask;

	mask = (psw.mask & PSW_MASK_EA) ? -1UL :
	       (psw.mask & PSW_MASK_BA) ? (1UL << 31) - 1 :
					  (1UL << 24) - 1;
	return (psw.addr - ilc) & mask;
}

/*
 * Function to stop a processor until the next interrupt occurs
 */
void enabled_wait(void);

/*
 * Function to drop a processor into disabled wait state
 */
static inline void __noreturn disabled_wait(unsigned long code)
{
	psw_t psw;

	psw.mask = PSW_MASK_BASE | PSW_MASK_WAIT | PSW_MASK_BA | PSW_MASK_EA;
	psw.addr = code;
	__load_psw(psw);
	while (1);
}

/*
 * Basic Machine Check/Program Check Handler.
 */

extern void s390_base_mcck_handler(void);
extern void s390_base_pgm_handler(void);
extern void s390_base_ext_handler(void);

extern void (*s390_base_mcck_handler_fn)(void);
extern void (*s390_base_pgm_handler_fn)(void);
extern void (*s390_base_ext_handler_fn)(void);

#define ARCH_LOW_ADDRESS_LIMIT	0x7fffffffUL

#endif

/*
 * Helper macro for exception table entries
 */
#ifndef __s390x__
#define EX_TABLE(_fault,_target)			\
	".section __ex_table,\"a\"\n"			\
	"	.align 4\n"				\
	"	.long  " #_fault "," #_target "\n"	\
	".previous\n"
#else
#define EX_TABLE(_fault,_target)			\
	".section __ex_table,\"a\"\n"			\
	"	.align 8\n"				\
	"	.quad  " #_fault "," #_target "\n"	\
	".previous\n"
#endif

#endif                                 /* __ASM_S390_PROCESSOR_H           */
extern int memcpy_real(void *, void *, size_t);
extern void memcpy_absolute(void *, void *, size_t);

#define mem_assign_absolute(dest, val) do {			\
	__typeof__(dest) __tmp = (val);				\
								\
	BUILD_BUG_ON(sizeof(__tmp) != sizeof(val));		\
	memcpy_absolute(&(dest), &__tmp, sizeof(__tmp));	\
} while (0)

extern int s390_isolate_bp(void);
extern int s390_isolate_bp_guest(void);

#endif /* __ASSEMBLY__ */

#endif /* __ASM_S390_PROCESSOR_H */
