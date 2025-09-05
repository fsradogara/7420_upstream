/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

/*
 *	Generic SMP support
 *		Alan Cox. <alan@redhat.com>
 */

#include <linux/errno.h>
#include <linux/list.h>
#include <linux/cpumask.h>

extern void cpu_idle(void);

struct call_single_data {
	struct list_head list;
	void (*func) (void *info);
#include <linux/types.h>
#include <linux/list.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/llist.h>

typedef void (*smp_call_func_t)(void *info);
struct __call_single_data {
	struct llist_node llist;
	smp_call_func_t func;
	void *info;
	unsigned int flags;
};

/* Use __aligned() to avoid to use 2 cache lines for 1 csd */
typedef struct __call_single_data call_single_data_t
	__aligned(sizeof(struct __call_single_data));

/* total number of cpus in this system (may exceed NR_CPUS) */
extern unsigned int total_cpus;

int smp_call_function_single(int cpuid, smp_call_func_t func, void *info,
			     int wait);

/*
 * Call a function on all processors
 */
int on_each_cpu(smp_call_func_t func, void *info, int wait);

/*
 * Call a function on processors specified by mask, which might include
 * the local one.
 */
void on_each_cpu_mask(const struct cpumask *mask, smp_call_func_t func,
		void *info, bool wait);

/*
 * Call a function on each processor for which the supplied function
 * cond_func returns a positive value. This may include the local
 * processor.
 */
void on_each_cpu_cond(bool (*cond_func)(int cpu, void *info),
		smp_call_func_t func, void *info, bool wait,
		gfp_t gfp_flags);

int smp_call_function_single_async(int cpu, call_single_data_t *csd);

#ifdef CONFIG_SMP

#include <linux/preempt.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/thread_info.h>
#include <asm/smp.h>

/*
 * main cross-CPU interfaces, handles INIT, TLB flush, STOP, etc.
 * (defined in asm header):
 */ 
 */

/*
 * stops all CPUs but the current one:
 */
extern void smp_send_stop(void);

/*
 * sends a 'reschedule' event to another CPU:
 */
extern void smp_send_reschedule(int cpu);


/*
 * Prepare machine for booting other CPUs.
 */
extern void smp_prepare_cpus(unsigned int max_cpus);

/*
 * Bring a CPU up
 */
extern int __cpu_up(unsigned int cpunum);
extern int __cpu_up(unsigned int cpunum, struct task_struct *tidle);

/*
 * Final polishing of CPUs
 */
extern void smp_cpus_done(unsigned int max_cpus);

/*
 * Call a function on all other processors
 */
int smp_call_function(void(*func)(void *info), void *info, int wait);
int smp_call_function_mask(cpumask_t mask, void(*func)(void *info), void *info,
				int wait);
int smp_call_function_single(int cpuid, void (*func) (void *info), void *info,
				int wait);
void __smp_call_function_single(int cpuid, struct call_single_data *data);
int smp_call_function(smp_call_func_t func, void *info, int wait);
void smp_call_function_many(const struct cpumask *mask,
			    smp_call_func_t func, void *info, bool wait);

int smp_call_function_any(const struct cpumask *mask,
			  smp_call_func_t func, void *info, int wait);

void kick_all_cpus_sync(void);
void wake_up_all_idle_cpus(void);

/*
 * Generic and arch helpers
 */
#ifdef CONFIG_USE_GENERIC_SMP_HELPERS
void generic_smp_call_function_single_interrupt(void);
void generic_smp_call_function_interrupt(void);
void ipi_call_lock(void);
void ipi_call_unlock(void);
void ipi_call_lock_irq(void);
void ipi_call_unlock_irq(void);
#endif

/*
 * Call a function on all processors
 */
int on_each_cpu(void (*func) (void *info), void *info, int wait);

#define MSG_ALL_BUT_SELF	0x8000	/* Assume <32768 CPU's */
#define MSG_ALL			0x8001

#define MSG_INVALIDATE_TLB	0x0001	/* Remote processor TLB invalidate */
#define MSG_STOP_CPU		0x0002	/* Sent to shut down slave CPU's
					 * when rebooting
					 */
#define MSG_RESCHEDULE		0x0003	/* Reschedule request from master CPU*/
#define MSG_CALL_FUNCTION       0x0004  /* Call function on all other CPUs */
void __init call_function_init(void);
void generic_smp_call_function_single_interrupt(void);
#define generic_smp_call_function_interrupt \
	generic_smp_call_function_single_interrupt

/*
 * Mark the boot cpu "online" so that it can call console drivers in
 * printk() and can access its per-cpu storage.
 */
void smp_prepare_boot_cpu(void);

extern unsigned int setup_max_cpus;

#else /* !SMP */

extern void __init setup_nr_cpu_ids(void);
extern void __init smp_init(void);

extern int __boot_cpu_id;

static inline int get_boot_cpu_id(void)
{
	return __boot_cpu_id;
}

#else /* !SMP */

static inline void smp_send_stop(void) { }

/*
 *	These macros fold the SMP functionality into a single CPU system
 */
#define raw_smp_processor_id()			0
static inline int up_smp_call_function(void (*func)(void *), void *info)
static inline int up_smp_call_function(smp_call_func_t func, void *info)
{
	return 0;
}
#define smp_call_function(func, info, wait) \
			(up_smp_call_function(func, info))
#define on_each_cpu(func,info,wait)		\
	({					\
		local_irq_disable();		\
		func(info);			\
		local_irq_enable();		\
		0;				\
	})
static inline void smp_send_reschedule(int cpu) { }
#define num_booting_cpus()			1
#define smp_prepare_boot_cpu()			do {} while (0)
#define smp_call_function_single(cpuid, func, info, wait) \
({ \
	WARN_ON(cpuid != 0);	\
	local_irq_disable();	\
	(func)(info);		\
	local_irq_enable();	\
	0;			\
})
#define smp_call_function_mask(mask, func, info, wait) \
			(up_smp_call_function(func, info))
static inline void init_call_single_data(void)
{
}

static inline void smp_send_reschedule(int cpu) { }
#define smp_prepare_boot_cpu()			do {} while (0)
#define smp_call_function_many(mask, func, info, wait) \
			(up_smp_call_function(func, info))
static inline void call_function_init(void) { }

static inline int
smp_call_function_any(const struct cpumask *mask, smp_call_func_t func,
		      void *info, int wait)
{
	return smp_call_function_single(0, func, info, wait);
}

static inline void kick_all_cpus_sync(void) {  }
static inline void wake_up_all_idle_cpus(void) {  }

#ifdef CONFIG_UP_LATE_INIT
extern void __init up_late_init(void);
static inline void smp_init(void) { up_late_init(); }
#else
static inline void smp_init(void) { }
#endif

static inline int get_boot_cpu_id(void)
{
	return 0;
}

#endif /* !SMP */

/*
 * smp_processor_id(): get the current CPU ID.
 *
 * if DEBUG_PREEMPT is enabled the we check whether it is
 * if DEBUG_PREEMPT is enabled then we check whether it is
 * used in a preemption-safe way. (smp_processor_id() is safe
 * if it's used in a preemption-off critical section, or in
 * a thread that is bound to the current CPU.)
 *
 * NOTE: raw_smp_processor_id() is for internal use only
 * (smp_processor_id() is the preferred variant), but in rare
 * instances it might also be used to turn off false positives
 * (i.e. smp_processor_id() use that the debugging code reports but
 * which use for some reason is legal). Don't use this to hack around
 * the warning message, as your code might not work under PREEMPT.
 */
#ifdef CONFIG_DEBUG_PREEMPT
  extern unsigned int debug_smp_processor_id(void);
# define smp_processor_id() debug_smp_processor_id()
#else
# define smp_processor_id() raw_smp_processor_id()
#endif

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define put_cpu()		preempt_enable()
#define put_cpu_no_resched()	preempt_enable_no_resched()

/*
 * Callback to arch code if there's nosmp or maxcpus=0 on the
 * boot command line:
 */
extern void arch_disable_smp_support(void);

extern void arch_enable_nonboot_cpus_begin(void);
extern void arch_enable_nonboot_cpus_end(void);

void smp_setup_processor_id(void);

int smp_call_on_cpu(unsigned int cpu, int (*func)(void *), void *par,
		    bool phys);

/* SMP core functions */
int smpcfd_prepare_cpu(unsigned int cpu);
int smpcfd_dead_cpu(unsigned int cpu);
int smpcfd_dying_cpu(unsigned int cpu);

#endif /* __LINUX_SMP_H */
