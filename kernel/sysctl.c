/*
 * sysctl.c: General linux system control interface
 *
 * Begun 24 March 1995, Stephen Tweedie
 * Added /proc support, Dec 1995
 * Added bdflush entry and intvec min/max checking, 2/23/96, Tom Dyas.
 * Added hooks for /proc/sys/net (minor, minor patch), 96/4/1, Mike Shaver.
 * Added kernel/java-{interpreter,appletviewer}, 96/5/10, Mike Shaver.
 * Dynamic registration fixes, Stephen Tweedie.
 * Added kswapd-interval, ctrl-alt-del, printk stuff, 1/8/97, Chris Horn.
 * Made sysctl support optional via CONFIG_SYSCTL, 1/10/97, Chris
 *  Horn.
 * Added proc_doulongvec_ms_jiffies_minmax, 09/08/99, Carlos H. Bauer.
 * Added proc_doulongvec_minmax, 09/08/99, Carlos H. Bauer.
 * Changed linked lists to use list.h instead of lists.h, 02/24/00, Bill
 *  Wendling.
 * The list_for_each() macro wasn't appropriate for the sysctl loop.
 *  Removed it and replaced it with older style, 03/23/00, Bill Wendling
 */

#include <linux/module.h>
#include <linux/aio.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/ctype.h>
#include <linux/utsname.h>
#include <linux/smp_lock.h>
#include <linux/bitmap.h>
#include <linux/signal.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/ctype.h>
#include <linux/kmemcheck.h>
#include <linux/kmemleak.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/net.h>
#include <linux/sysrq.h>
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#include <linux/compaction.h>
#include <linux/hugetlb.h>
#include <linux/initrd.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/dnotify.h>
#include <linux/syscalls.h>
#include <linux/vmstat.h>
#include <linux/nfs_fs.h>
#include <linux/acpi.h>
#include <linux/reboot.h>
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/pipe_fs_i.h>
#include <linux/oom.h>
#include <linux/kmod.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/coredump.h>
#include <linux/kexec.h>
#include <linux/bpf.h>
#include <linux/mount.h>

#include <linux/uaccess.h>
#include <asm/processor.h>

#ifdef CONFIG_X86
#include <asm/nmi.h>
#include <asm/stacktrace.h>
#include <asm/io.h>
#endif

static int deprecated_sysctl_warning(struct __sysctl_args *args);
#ifdef CONFIG_SPARC
#include <asm/setup.h>
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT
#include <linux/acct.h>
#endif
#ifdef CONFIG_RT_MUTEXES
#include <linux/rtmutex.h>
#endif
#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_LOCK_STAT)
#include <linux/lockdep.h>
#endif
#ifdef CONFIG_CHR_DEV_SG
#include <scsi/sg.h>
#endif

#ifdef CONFIG_LOCKUP_DETECTOR
#include <linux/nmi.h>
#endif

#if defined(CONFIG_SYSCTL)

/* External variables not in a header file. */
extern int C_A_D;
extern int print_fatal_signals;
extern int sysctl_overcommit_memory;
extern int sysctl_overcommit_ratio;
extern int sysctl_panic_on_oom;
extern int sysctl_oom_kill_allocating_task;
extern int sysctl_oom_dump_tasks;
extern int max_threads;
extern int core_uses_pid;
extern int suid_dumpable;
extern char core_pattern[];
extern int pid_max;
extern int min_free_kbytes;
extern int pid_max_min, pid_max_max;
extern int sysctl_drop_caches;
extern int percpu_pagelist_fraction;
extern int compat_log;
extern int maps_protect;
extern int latencytop_enabled;
extern int sysctl_nr_open_min, sysctl_nr_open_max;
#ifdef CONFIG_RCU_TORTURE_TEST
extern int rcutorture_runnable;
#endif /* #ifdef CONFIG_RCU_TORTURE_TEST */

/* Constants used for minimum and  maximum */
#if defined(CONFIG_HIGHMEM) || defined(CONFIG_DETECT_SOFTLOCKUP)
static int one = 1;
#endif

#ifdef CONFIG_DETECT_SOFTLOCKUP
static int sixty = 60;
static int neg_one = -1;
#endif

#ifdef CONFIG_MMU
static int two = 2;
#endif

static int zero;
static int one_hundred = 100;
extern int suid_dumpable;
#ifdef CONFIG_COREDUMP
extern int core_uses_pid;
extern char core_pattern[];
extern unsigned int core_pipe_limit;
#endif
extern int pid_max;
extern int pid_max_min, pid_max_max;
extern int percpu_pagelist_fraction;
extern int latencytop_enabled;
extern unsigned int sysctl_nr_open_min, sysctl_nr_open_max;
#ifndef CONFIG_MMU
extern int sysctl_nr_trim_pages;
#endif

/* Constants used for minimum and  maximum */
#ifdef CONFIG_LOCKUP_DETECTOR
static int sixty = 60;
#endif

static int __maybe_unused neg_one = -1;

static int zero;
static int __maybe_unused one = 1;
static int __maybe_unused two = 2;
static int __maybe_unused four = 4;
static unsigned long one_ul = 1;
static int one_hundred = 100;
static int one_thousand = 1000;
#ifdef CONFIG_PRINTK
static int ten_thousand = 10000;
#endif
#ifdef CONFIG_PERF_EVENTS
static int six_hundred_forty_kb = 640 * 1024;
#endif

/* this is needed for the proc_doulongvec_minmax of vm_dirty_bytes */
static unsigned long dirty_bytes_min = 2 * PAGE_SIZE;

/* this is needed for the proc_dointvec_minmax for [fs_]overflow UID and GID */
static int maxolduid = 65535;
static int minolduid;
static int min_percpu_pagelist_fract = 8;

static int ngroups_max = NGROUPS_MAX;

#ifdef CONFIG_MODULES
extern char modprobe_path[];
#endif
#ifdef CONFIG_CHR_DEV_SG
extern int sg_big_buff;
#endif

#ifdef __sparc__
extern char reboot_command [];
extern int stop_a_enabled;
extern int scons_pwroff;

static int ngroups_max = NGROUPS_MAX;
static const int cap_last_cap = CAP_LAST_CAP;

/*this is needed for proc_doulongvec_minmax of sysctl_hung_task_timeout_secs */
#ifdef CONFIG_DETECT_HUNG_TASK
static unsigned long hung_task_timeout_max = (LONG_MAX/HZ);
#endif

#ifdef CONFIG_INOTIFY_USER
#include <linux/inotify.h>
#endif
#ifdef CONFIG_SPARC
#endif

#ifdef __hppa__
extern int pwrsw_enabled;
extern int unaligned_enabled;
#endif

#ifdef CONFIG_S390
#ifdef CONFIG_MATHEMU
extern int sysctl_ieee_emulation_warnings;
#endif
extern int sysctl_userprocess_debug;
extern int spin_retry;
#endif

#ifdef CONFIG_BSD_PROCESS_ACCT
extern int acct_parm[];
#endif

#ifdef CONFIG_IA64
extern int no_unaligned_warning;
#endif

#ifdef CONFIG_RT_MUTEXES
extern int max_lock_depth;
#endif

#ifdef CONFIG_PROC_SYSCTL
static int proc_do_cad_pid(struct ctl_table *table, int write, struct file *filp,
		  void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_dointvec_taint(struct ctl_table *table, int write, struct file *filp,
			       void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

static struct ctl_table root_table[];
static struct ctl_table_root sysctl_table_root;
static struct ctl_table_header root_table_header = {
	.count = 1,
	.ctl_table = root_table,
	.ctl_entry = LIST_HEAD_INIT(sysctl_table_root.default_set.list),
	.root = &sysctl_table_root,
	.set = &sysctl_table_root.default_set,
};
static struct ctl_table_root sysctl_table_root = {
	.root_list = LIST_HEAD_INIT(sysctl_table_root.root_list),
	.default_set.list = LIST_HEAD_INIT(root_table_header.ctl_entry),
};
#endif

#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_ALLOW
extern int unaligned_enabled;
#endif

#ifdef CONFIG_IA64
extern int unaligned_dump_stack;
#endif

#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_NO_WARN
extern int no_unaligned_warning;
#endif

#ifdef CONFIG_PROC_SYSCTL

/**
 * enum sysctl_writes_mode - supported sysctl write modes
 *
 * @SYSCTL_WRITES_LEGACY: each write syscall must fully contain the sysctl value
 * 	to be written, and multiple writes on the same sysctl file descriptor
 * 	will rewrite the sysctl value, regardless of file position. No warning
 * 	is issued when the initial position is not 0.
 * @SYSCTL_WRITES_WARN: same as above but warn when the initial file position is
 * 	not 0.
 * @SYSCTL_WRITES_STRICT: writes to numeric sysctl entries must always be at
 * 	file position 0 and the value must be fully contained in the buffer
 * 	sent to the write syscall. If dealing with strings respect the file
 * 	position, but restrict this to the max length of the buffer, anything
 * 	passed the max lenght will be ignored. Multiple writes will append
 * 	to the buffer.
 *
 * These write modes control how current file position affects the behavior of
 * updating sysctl values through the proc interface on each write.
 */
enum sysctl_writes_mode {
	SYSCTL_WRITES_LEGACY		= -1,
	SYSCTL_WRITES_WARN		= 0,
	SYSCTL_WRITES_STRICT		= 1,
};

static enum sysctl_writes_mode sysctl_writes_strict = SYSCTL_WRITES_STRICT;

static int proc_do_cad_pid(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_taint(struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

#ifdef CONFIG_PRINTK
static int proc_dointvec_minmax_sysadmin(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

static int proc_dointvec_minmax_coredump(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
#ifdef CONFIG_COREDUMP
static int proc_dostring_coredump(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

#ifdef CONFIG_MAGIC_SYSRQ
/* Note: sysrq code uses it's own private copy */
static int __sysrq_enabled = CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE;

static int sysrq_sysctl_handler(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp,
				loff_t *ppos)
{
	int error;

	error = proc_dointvec(table, write, buffer, lenp, ppos);
	if (error)
		return error;

	if (write)
		sysrq_toggle_support(__sysrq_enabled);

	return 0;
}

#endif

static struct ctl_table kern_table[];
static struct ctl_table vm_table[];
static struct ctl_table fs_table[];
static struct ctl_table debug_table[];
static struct ctl_table dev_table[];
extern struct ctl_table random_table[];
#ifdef CONFIG_INOTIFY_USER
extern struct ctl_table inotify_table[];
#ifdef CONFIG_EPOLL
extern struct ctl_table epoll_table[];
#endif

#ifdef HAVE_ARCH_PICK_MMAP_LAYOUT
int sysctl_legacy_va_layout;
#endif

extern int prove_locking;
extern int lock_stat;

/* The default sysctl tables: */

static struct ctl_table root_table[] = {
	{
		.ctl_name	= CTL_KERN,
/* The default sysctl tables: */

static struct ctl_table sysctl_base_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= kern_table,
	},
	{
		.ctl_name	= CTL_VM,
		.procname	= "vm",
		.mode		= 0555,
		.child		= vm_table,
	},
	{
		.ctl_name	= CTL_FS,
		.procname	= "fs",
		.mode		= 0555,
		.child		= fs_table,
	},
	{
		.ctl_name	= CTL_DEBUG,
		.procname	= "debug",
		.mode		= 0555,
		.child		= debug_table,
	},
	{
		.ctl_name	= CTL_DEV,
		.procname	= "dev",
		.mode		= 0555,
		.child		= dev_table,
	},
/*
 * NOTE: do not add new entries to this table unless you have read
 * Documentation/sysctl/ctl_unnumbered.txt
 */
	{ .ctl_name = 0 }
	{ }
};

#ifdef CONFIG_SCHED_DEBUG
static int min_sched_granularity_ns = 100000;		/* 100 usecs */
static int max_sched_granularity_ns = NSEC_PER_SEC;	/* 1 second */
static int min_wakeup_granularity_ns;			/* 0 usecs */
static int max_wakeup_granularity_ns = NSEC_PER_SEC;	/* 1 second */
#endif

static struct ctl_table kern_table[] = {
#ifdef CONFIG_SCHED_DEBUG
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_min_granularity_ns",
		.data		= &sysctl_sched_min_granularity,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &sched_nr_latency_handler,
		.strategy	= &sysctl_intvec,
		.extra1		= &min_sched_granularity_ns,
		.extra2		= &max_sched_granularity_ns,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_latency_ns",
		.data		= &sysctl_sched_latency,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &sched_nr_latency_handler,
		.strategy	= &sysctl_intvec,
		.extra1		= &min_sched_granularity_ns,
		.extra2		= &max_sched_granularity_ns,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_wakeup_granularity_ns",
		.data		= &sysctl_sched_wakeup_granularity,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &min_wakeup_granularity_ns,
		.extra2		= &max_wakeup_granularity_ns,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_shares_ratelimit",
		.data		= &sysctl_sched_shares_ratelimit,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
#ifdef CONFIG_SMP
static int min_sched_tunable_scaling = SCHED_TUNABLESCALING_NONE;
static int max_sched_tunable_scaling = SCHED_TUNABLESCALING_END-1;
#endif /* CONFIG_SMP */
#endif /* CONFIG_SCHED_DEBUG */

#ifdef CONFIG_COMPACTION
static int min_extfrag_threshold;
static int max_extfrag_threshold = 1000;
#endif

static struct ctl_table kern_table[] = {
	{
		.procname	= "sched_child_runs_first",
		.data		= &sysctl_sched_child_runs_first,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_features",
		.data		= &sysctl_sched_features,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_migration_cost",
		.data		= &sysctl_sched_migration_cost,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_SCHED_DEBUG
	{
		.procname	= "sched_min_granularity_ns",
		.data		= &sysctl_sched_min_granularity,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_sched_granularity_ns,
		.extra2		= &max_sched_granularity_ns,
	},
	{
		.procname	= "sched_latency_ns",
		.data		= &sysctl_sched_latency,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_sched_granularity_ns,
		.extra2		= &max_sched_granularity_ns,
	},
	{
		.procname	= "sched_wakeup_granularity_ns",
		.data		= &sysctl_sched_wakeup_granularity,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_wakeup_granularity_ns,
		.extra2		= &max_wakeup_granularity_ns,
	},
#ifdef CONFIG_SMP
	{
		.procname	= "sched_tunable_scaling",
		.data		= &sysctl_sched_tunable_scaling,
		.maxlen		= sizeof(enum sched_tunable_scaling),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_sched_tunable_scaling,
		.extra2		= &max_sched_tunable_scaling,
	},
	{
		.procname	= "sched_migration_cost_ns",
		.data		= &sysctl_sched_migration_cost,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_nr_migrate",
		.data		= &sysctl_sched_nr_migrate,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_time_avg_ms",
		.data		= &sysctl_sched_time_avg,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
#ifdef CONFIG_SCHEDSTATS
	{
		.procname	= "sched_schedstats",
		.data		= NULL,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_schedstats,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif /* CONFIG_SCHEDSTATS */
#endif /* CONFIG_SMP */
#ifdef CONFIG_NUMA_BALANCING
	{
		.procname	= "numa_balancing_scan_delay_ms",
		.data		= &sysctl_numa_balancing_scan_delay,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "numa_balancing_scan_period_min_ms",
		.data		= &sysctl_numa_balancing_scan_period_min,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "numa_balancing_scan_period_max_ms",
		.data		= &sysctl_numa_balancing_scan_period_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "numa_balancing_scan_size_mb",
		.data		= &sysctl_numa_balancing_scan_size,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
	{
		.procname	= "numa_balancing",
		.data		= NULL, /* filled in by handler */
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_numa_balancing,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif /* CONFIG_NUMA_BALANCING */
#endif /* CONFIG_SCHED_DEBUG */
	{
		.procname	= "sched_rt_period_us",
		.data		= &sysctl_sched_rt_period,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &sched_rt_handler,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= sched_rt_handler,
	},
	{
		.procname	= "sched_rt_runtime_us",
		.data		= &sysctl_sched_rt_runtime,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &sched_rt_handler,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sched_compat_yield",
		.data		= &sysctl_sched_compat_yield,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef CONFIG_PROVE_LOCKING
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= sched_rt_handler,
	},
	{
		.procname	= "sched_rr_timeslice_ms",
		.data		= &sysctl_sched_rr_timeslice,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sched_rr_handler,
	},
#ifdef CONFIG_SCHED_AUTOGROUP
	{
		.procname	= "sched_autogroup_enabled",
		.data		= &sysctl_sched_autogroup_enabled,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_CFS_BANDWIDTH
	{
		.procname	= "sched_cfs_bandwidth_slice_us",
		.data		= &sysctl_sched_cfs_bandwidth_slice,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
#endif
#ifdef CONFIG_PROVE_LOCKING
	{
		.procname	= "prove_locking",
		.data		= &prove_locking,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_LOCK_STAT
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "lock_stat",
		.data		= &lock_stat,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= KERN_PANIC,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "panic",
		.data		= &panic_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_CORE_USES_PID,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_COREDUMP
	{
		.procname	= "core_uses_pid",
		.data		= &core_uses_pid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_CORE_PATTERN,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "core_pattern",
		.data		= core_pattern,
		.maxlen		= CORENAME_MAX_SIZE,
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
		.strategy	= &sysctl_string,
	},
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "tainted",
		.data		= &tainted,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_taint,
		.proc_handler	= proc_dostring_coredump,
	},
	{
		.procname	= "core_pipe_limit",
		.data		= &core_pipe_limit,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "tainted",
		.maxlen 	= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_taint,
	},
	{
		.procname	= "sysctl_writes_strict",
		.data		= &sysctl_writes_strict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &neg_one,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_LATENCYTOP
	{
		.procname	= "latencytop",
		.data		= &latencytop_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
		.proc_handler	= sysctl_latencytop,
	},
#endif
#ifdef CONFIG_BLK_DEV_INITRD
	{
		.ctl_name	= KERN_REALROOTDEV,
		.procname	= "real-root-dev",
		.data		= &real_root_dev,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "print-fatal-signals",
		.data		= &print_fatal_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef __sparc__
	{
		.ctl_name	= KERN_SPARC_REBOOT,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_SPARC
	{
		.procname	= "reboot-cmd",
		.data		= reboot_command,
		.maxlen		= 256,
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
		.strategy	= &sysctl_string,
	},
	{
		.ctl_name	= KERN_SPARC_STOP_A,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "stop-a",
		.data		= &stop_a_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_SPARC_SCONS_PWROFF,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "scons-poweroff",
		.data		= &scons_pwroff,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SPARC64
	{
		.procname	= "tsb-ratio",
		.data		= &sysctl_tsb_ratio,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef __hppa__
	{
		.ctl_name	= KERN_HPPA_PWRSW,
		.procname	= "soft-power",
		.data		= &pwrsw_enabled,
		.maxlen		= sizeof (int),
	 	.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_HPPA_UNALIGNED,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_ALLOW
	{
		.procname	= "unaligned-trap",
		.data		= &unaligned_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= KERN_CTLALTDEL,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "ctrl-alt-del",
		.data		= &C_A_D,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef CONFIG_FTRACE
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_FUNCTION_TRACER
	{
		.procname	= "ftrace_enabled",
		.data		= &ftrace_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &ftrace_enable_sysctl,
		.proc_handler	= ftrace_enable_sysctl,
	},
#endif
#ifdef CONFIG_STACK_TRACER
	{
		.procname	= "stack_tracer_enabled",
		.data		= &stack_tracer_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= stack_trace_sysctl,
	},
#endif
#ifdef CONFIG_TRACING
	{
		.procname	= "ftrace_dump_on_oops",
		.data		= &ftrace_dump_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "traceoff_on_warning",
		.data		= &__disable_trace_on_warning,
		.maxlen		= sizeof(__disable_trace_on_warning),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tracepoint_printk",
		.data		= &tracepoint_printk,
		.maxlen		= sizeof(tracepoint_printk),
		.mode		= 0644,
		.proc_handler	= tracepoint_printk_sysctl,
	},
#endif
#ifdef CONFIG_KEXEC_CORE
	{
		.procname	= "kexec_load_disabled",
		.data		= &kexec_load_disabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		/* only handle a transition from default "0" to "1" */
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_MODULES
	{
		.ctl_name	= KERN_MODPROBE,
		.procname	= "modprobe",
		.data		= &modprobe_path,
		.maxlen		= KMOD_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
		.strategy	= &sysctl_string,
	},
#endif
#if defined(CONFIG_HOTPLUG) && defined(CONFIG_NET)
	{
		.ctl_name	= KERN_HOTPLUG,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "modules_disabled",
		.data		= &modules_disabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		/* only handle a transition from default "0" to "1" */
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_UEVENT_HELPER
	{
		.procname	= "hotplug",
		.data		= &uevent_helper,
		.maxlen		= UEVENT_HELPER_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
		.strategy	= &sysctl_string,
		.proc_handler	= proc_dostring,
	},
#endif
#ifdef CONFIG_CHR_DEV_SG
	{
		.ctl_name	= KERN_SG_BIG_BUFF,
		.procname	= "sg-big-buff",
		.data		= &sg_big_buff,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT
	{
		.ctl_name	= KERN_ACCT,
		.procname	= "acct",
		.data		= &acct_parm,
		.maxlen		= 3*sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_MAGIC_SYSRQ
	{
		.ctl_name	= KERN_SYSRQ,
		.procname	= "sysrq",
		.data		= &__sysrq_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= sysrq_sysctl_handler,
	},
#endif
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "cad_pid",
		.data		= NULL,
		.maxlen		= sizeof (int),
		.mode		= 0600,
		.proc_handler	= &proc_do_cad_pid,
	},
#endif
	{
		.ctl_name	= KERN_MAX_THREADS,
		.procname	= "threads-max",
		.data		= &max_threads,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_RANDOM,
		.proc_handler	= proc_do_cad_pid,
	},
#endif
	{
		.procname	= "threads-max",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_max_threads,
	},
	{
		.procname	= "random",
		.mode		= 0555,
		.child		= random_table,
	},
	{
		.ctl_name	= KERN_OVERFLOWUID,
		.procname	= "usermodehelper",
		.mode		= 0555,
		.child		= usermodehelper_table,
	},
	{
		.procname	= "overflowuid",
		.data		= &overflowuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &minolduid,
		.extra2		= &maxolduid,
	},
	{
		.ctl_name	= KERN_OVERFLOWGID,
		.procname	= "overflowgid",
		.data		= &overflowgid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &minolduid,
		.extra2		= &maxolduid,
	},
#ifdef CONFIG_S390
#ifdef CONFIG_MATHEMU
	{
		.ctl_name	= KERN_IEEE_EMULATION_WARNINGS,
		.procname	= "ieee_emulation_warnings",
		.data		= &sysctl_ieee_emulation_warnings,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= KERN_S390_USER_DEBUG_LOGGING,
		.procname	= "userprocess_debug",
		.data		= &sysctl_userprocess_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= KERN_PIDMAX,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "userprocess_debug",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "pid_max",
		.data		= &pid_max,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &pid_max_min,
		.extra2		= &pid_max_max,
	},
	{
		.ctl_name	= KERN_PANIC_ON_OOPS,
		.procname	= "panic_on_oops",
		.data		= &panic_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#if defined CONFIG_PRINTK
	{
		.ctl_name	= KERN_PRINTK,
		.proc_handler	= proc_dointvec,
	},
#if defined CONFIG_PRINTK
	{
		.procname	= "printk",
		.data		= &console_loglevel,
		.maxlen		= 4*sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_PRINTK_RATELIMIT,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "printk_ratelimit",
		.data		= &printk_ratelimit_state.interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= KERN_PRINTK_RATELIMIT_BURST,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "printk_ratelimit_burst",
		.data		= &printk_ratelimit_state.burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= KERN_NGROUPS_MAX,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "printk_delay",
		.data		= &printk_delay_msec,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &ten_thousand,
	},
	{
		.procname	= "printk_devkmsg",
		.data		= devkmsg_log_str,
		.maxlen		= DEVKMSG_STR_MAX_SIZE,
		.mode		= 0644,
		.proc_handler	= devkmsg_sysctl_set_loglvl,
	},
	{
		.procname	= "dmesg_restrict",
		.data		= &dmesg_restrict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax_sysadmin,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "kptr_restrict",
		.data		= &kptr_restrict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax_sysadmin,
		.extra1		= &zero,
		.extra2		= &two,
	},
#endif
	{
		.procname	= "ngroups_max",
		.data		= &ngroups_max,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
#if defined(CONFIG_X86_LOCAL_APIC) && defined(CONFIG_X86)
	{
		.ctl_name       = KERN_UNKNOWN_NMI_PANIC,
		.procname       = "unknown_nmi_panic",
		.data           = &unknown_nmi_panic,
		.maxlen         = sizeof (int),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cap_last_cap",
		.data		= (void *)&cap_last_cap,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
#if defined(CONFIG_LOCKUP_DETECTOR)
	{
		.procname       = "watchdog",
		.data		= &watchdog_user_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler   = proc_watchdog,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "watchdog_thresh",
		.data		= &watchdog_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_watchdog_thresh,
		.extra1		= &zero,
		.extra2		= &sixty,
	},
	{
		.procname       = "nmi_watchdog",
		.data           = &nmi_watchdog_enabled,
		.maxlen         = sizeof (int),
		.mode           = 0644,
		.proc_handler   = &proc_nmi_enabled,
		.data		= &nmi_watchdog_user_enabled,
		.maxlen		= sizeof(int),
		.mode		= NMI_WATCHDOG_SYSCTL_PERM,
		.proc_handler   = proc_nmi_watchdog,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "watchdog_cpumask",
		.data		= &watchdog_cpumask_bits,
		.maxlen		= NR_CPUS,
		.mode		= 0644,
		.proc_handler	= proc_watchdog_cpumask,
	},
#ifdef CONFIG_SOFTLOCKUP_DETECTOR
	{
		.procname       = "soft_watchdog",
		.data		= &soft_watchdog_user_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler   = proc_soft_watchdog,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "softlockup_panic",
		.data		= &softlockup_panic,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#ifdef CONFIG_SMP
	{
		.procname	= "softlockup_all_cpu_backtrace",
		.data		= &sysctl_softlockup_all_cpu_backtrace,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif /* CONFIG_SMP */
#endif
#ifdef CONFIG_HARDLOCKUP_DETECTOR
	{
		.procname	= "hardlockup_panic",
		.data		= &hardlockup_panic,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#ifdef CONFIG_SMP
	{
		.procname	= "hardlockup_all_cpu_backtrace",
		.data		= &sysctl_hardlockup_all_cpu_backtrace,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif /* CONFIG_SMP */
#endif
#endif

#if defined(CONFIG_X86_LOCAL_APIC) && defined(CONFIG_X86)
	{
		.procname       = "unknown_nmi_panic",
		.data           = &unknown_nmi_panic,
		.maxlen         = sizeof (int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
#endif
#if defined(CONFIG_X86)
	{
		.ctl_name	= KERN_PANIC_ON_NMI,
		.procname	= "panic_on_unrecovered_nmi",
		.data		= &panic_on_unrecovered_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= KERN_BOOTLOADER_TYPE,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_on_io_nmi",
		.data		= &panic_on_io_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_DEBUG_STACKOVERFLOW
	{
		.procname	= "panic_on_stackoverflow",
		.data		= &sysctl_panic_on_stackoverflow,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "bootloader_type",
		.data		= &bootloader_type,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "bootloader_version",
		.data		= &bootloader_version,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "kstack_depth_to_print",
		.data		= &kstack_depth_to_print,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "io_delay_type",
		.data		= &io_delay_type,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_MMU)
	{
		.ctl_name	= KERN_RANDOMIZE,
		.procname	= "randomize_va_space",
		.data		= &randomize_va_space,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_S390) && defined(CONFIG_SMP)
	{
		.ctl_name	= KERN_SPIN_RETRY,
		.procname	= "spin_retry",
		.data		= &spin_retry,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#if	defined(CONFIG_ACPI_SLEEP) && defined(CONFIG_X86)
	{
		.procname	= "acpi_video_flags",
		.data		= &acpi_realmode_flags,
		.maxlen		= sizeof (unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax,
	},
#endif
#ifdef CONFIG_IA64
	{
		.ctl_name	= KERN_IA64_UNALIGNED,
		.proc_handler	= proc_doulongvec_minmax,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_NO_WARN
	{
		.procname	= "ignore-unaligned-usertrap",
		.data		= &no_unaligned_warning,
		.maxlen		= sizeof (int),
	 	.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_DETECT_SOFTLOCKUP
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "softlockup_panic",
		.data		= &softlockup_panic,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_IA64
	{
		.procname	= "unaligned-dump-stack",
		.data		= &unaligned_dump_stack,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
	{
		.procname	= "hung_task_panic",
		.data		= &sysctl_hung_task_panic,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "softlockup_thresh",
		.data		= &softlockup_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &neg_one,
		.extra2		= &sixty,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "hung_task_check_count",
		.data		= &sysctl_hung_task_check_count,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "hung_task_check_count",
		.data		= &sysctl_hung_task_check_count,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
	{
		.procname	= "hung_task_timeout_secs",
		.data		= &sysctl_hung_task_timeout_secs,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "hung_task_warnings",
		.data		= &sysctl_hung_task_warnings,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dohung_task_timeout_secs,
		.extra2		= &hung_task_timeout_max,
	},
	{
		.procname	= "hung_task_warnings",
		.data		= &sysctl_hung_task_warnings,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &neg_one,
	},
#endif
#ifdef CONFIG_COMPAT
	{
		.ctl_name	= KERN_COMPAT_LOG,
		.procname	= "compat-log",
		.data		= &compat_log,
		.maxlen		= sizeof (int),
	 	.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_RT_MUTEXES
	{
		.ctl_name	= KERN_MAX_LOCK_DEPTH,
		.procname	= "max_lock_depth",
		.data		= &max_lock_depth,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_PROC_FS
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname       = "maps_protect",
		.data           = &maps_protect,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
#endif
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "poweroff_cmd",
		.data		= &poweroff_cmd,
		.maxlen		= POWEROFF_CMD_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
		.strategy	= &sysctl_string,
	},
#ifdef CONFIG_KEYS
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dostring,
	},
#ifdef CONFIG_KEYS
	{
		.procname	= "keys",
		.mode		= 0555,
		.child		= key_sysctls,
	},
#endif
#ifdef CONFIG_RCU_TORTURE_TEST
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname       = "rcutorture_runnable",
		.data           = &rcutorture_runnable,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
#endif
/*
 * NOTE: do not add new entries to this table unless you have read
 * Documentation/sysctl/ctl_unnumbered.txt
 */
	{ .ctl_name = 0 }
#ifdef CONFIG_PERF_EVENTS
	/*
	 * User-space scripts rely on the existence of this file
	 * as a feature check for perf_events being enabled.
	 *
	 * So it's an ABI, do not remove!
	 */
	{
		.procname	= "perf_event_paranoid",
		.data		= &sysctl_perf_event_paranoid,
		.maxlen		= sizeof(sysctl_perf_event_paranoid),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "perf_event_mlock_kb",
		.data		= &sysctl_perf_event_mlock,
		.maxlen		= sizeof(sysctl_perf_event_mlock),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "perf_event_max_sample_rate",
		.data		= &sysctl_perf_event_sample_rate,
		.maxlen		= sizeof(sysctl_perf_event_sample_rate),
		.mode		= 0644,
		.proc_handler	= perf_proc_update_handler,
		.extra1		= &one,
	},
	{
		.procname	= "perf_cpu_time_max_percent",
		.data		= &sysctl_perf_cpu_time_max_percent,
		.maxlen		= sizeof(sysctl_perf_cpu_time_max_percent),
		.mode		= 0644,
		.proc_handler	= perf_cpu_time_max_percent_handler,
		.extra1		= &zero,
		.extra2		= &one_hundred,
	},
	{
		.procname	= "perf_event_max_stack",
		.data		= &sysctl_perf_event_max_stack,
		.maxlen		= sizeof(sysctl_perf_event_max_stack),
		.mode		= 0644,
		.proc_handler	= perf_event_max_stack_handler,
		.extra1		= &zero,
		.extra2		= &six_hundred_forty_kb,
	},
	{
		.procname	= "perf_event_max_contexts_per_stack",
		.data		= &sysctl_perf_event_max_contexts_per_stack,
		.maxlen		= sizeof(sysctl_perf_event_max_contexts_per_stack),
		.mode		= 0644,
		.proc_handler	= perf_event_max_stack_handler,
		.extra1		= &zero,
		.extra2		= &one_thousand,
	},
#endif
#ifdef CONFIG_KMEMCHECK
	{
		.procname	= "kmemcheck",
		.data		= &kmemcheck_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "panic_on_warn",
		.data		= &panic_on_warn,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
	{
		.procname	= "timer_migration",
		.data		= &sysctl_timer_migration,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= timer_migration_handler,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_BPF_SYSCALL
	{
		.procname	= "unprivileged_bpf_disabled",
		.data		= &sysctl_unprivileged_bpf_disabled,
		.maxlen		= sizeof(sysctl_unprivileged_bpf_disabled),
		.mode		= 0644,
		/* only handle a transition from default "0" to "1" */
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &one,
	},
#endif
#if defined(CONFIG_TREE_RCU) || defined(CONFIG_PREEMPT_RCU)
	{
		.procname	= "panic_on_rcu_stall",
		.data		= &sysctl_panic_on_rcu_stall,
		.maxlen		= sizeof(sysctl_panic_on_rcu_stall),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
	{ }
};

static struct ctl_table vm_table[] = {
	{
		.ctl_name	= VM_OVERCOMMIT_MEMORY,
		.procname	= "overcommit_memory",
		.data		= &sysctl_overcommit_memory,
		.maxlen		= sizeof(sysctl_overcommit_memory),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= VM_PANIC_ON_OOM,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &two,
	},
	{
		.procname	= "panic_on_oom",
		.data		= &sysctl_panic_on_oom,
		.maxlen		= sizeof(sysctl_panic_on_oom),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &two,
	},
	{
		.procname	= "oom_kill_allocating_task",
		.data		= &sysctl_oom_kill_allocating_task,
		.maxlen		= sizeof(sysctl_oom_kill_allocating_task),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "oom_dump_tasks",
		.data		= &sysctl_oom_dump_tasks,
		.maxlen		= sizeof(sysctl_oom_dump_tasks),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= VM_OVERCOMMIT_RATIO,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "overcommit_ratio",
		.data		= &sysctl_overcommit_ratio,
		.maxlen		= sizeof(sysctl_overcommit_ratio),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= VM_PAGE_CLUSTER,
		.proc_handler	= overcommit_ratio_handler,
	},
	{
		.procname	= "overcommit_kbytes",
		.data		= &sysctl_overcommit_kbytes,
		.maxlen		= sizeof(sysctl_overcommit_kbytes),
		.mode		= 0644,
		.proc_handler	= overcommit_kbytes_handler,
	},
	{
		.procname	= "page-cluster", 
		.data		= &page_cluster,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= VM_DIRTY_BACKGROUND,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
	{
		.procname	= "dirty_background_ratio",
		.data		= &dirty_background_ratio,
		.maxlen		= sizeof(dirty_background_ratio),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= dirty_background_ratio_handler,
		.extra1		= &zero,
		.extra2		= &one_hundred,
	},
	{
		.ctl_name	= VM_DIRTY_RATIO,
		.procname	= "dirty_background_bytes",
		.data		= &dirty_background_bytes,
		.maxlen		= sizeof(dirty_background_bytes),
		.mode		= 0644,
		.proc_handler	= dirty_background_bytes_handler,
		.extra1		= &one_ul,
	},
	{
		.procname	= "dirty_ratio",
		.data		= &vm_dirty_ratio,
		.maxlen		= sizeof(vm_dirty_ratio),
		.mode		= 0644,
		.proc_handler	= &dirty_ratio_handler,
		.strategy	= &sysctl_intvec,
		.proc_handler	= dirty_ratio_handler,
		.extra1		= &zero,
		.extra2		= &one_hundred,
	},
	{
		.procname	= "dirty_bytes",
		.data		= &vm_dirty_bytes,
		.maxlen		= sizeof(vm_dirty_bytes),
		.mode		= 0644,
		.proc_handler	= dirty_bytes_handler,
		.extra1		= &dirty_bytes_min,
	},
	{
		.procname	= "dirty_writeback_centisecs",
		.data		= &dirty_writeback_interval,
		.maxlen		= sizeof(dirty_writeback_interval),
		.mode		= 0644,
		.proc_handler	= &dirty_writeback_centisecs_handler,
		.proc_handler	= dirty_writeback_centisecs_handler,
	},
	{
		.procname	= "dirty_expire_centisecs",
		.data		= &dirty_expire_interval,
		.maxlen		= sizeof(dirty_expire_interval),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_userhz_jiffies,
	},
	{
		.ctl_name	= VM_NR_PDFLUSH_THREADS,
		.procname	= "nr_pdflush_threads",
		.data		= &nr_pdflush_threads,
		.maxlen		= sizeof nr_pdflush_threads,
		.mode		= 0444 /* read-only*/,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= VM_SWAPPINESS,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
	{
		.procname	= "dirtytime_expire_seconds",
		.data		= &dirtytime_expire_interval,
		.maxlen		= sizeof(dirty_expire_interval),
		.mode		= 0644,
		.proc_handler	= dirtytime_interval_handler,
		.extra1		= &zero,
	},
	{
		.procname       = "nr_pdflush_threads",
		.mode           = 0444 /* read-only */,
		.proc_handler   = pdflush_proc_obsolete,
	},
	{
		.procname	= "swappiness",
		.data		= &vm_swappiness,
		.maxlen		= sizeof(vm_swappiness),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one_hundred,
	},
#ifdef CONFIG_HUGETLB_PAGE
	 {
	{
		.procname	= "nr_hugepages",
		.data		= NULL,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &hugetlb_sysctl_handler,
		.extra1		= (void *)&hugetlb_zero,
		.extra2		= (void *)&hugetlb_infinity,
	 },
	 {
		.ctl_name	= VM_HUGETLB_GROUP,
		.proc_handler	= hugetlb_sysctl_handler,
	},
#ifdef CONFIG_NUMA
	{
		.procname       = "nr_hugepages_mempolicy",
		.data           = NULL,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = &hugetlb_mempolicy_sysctl_handler,
	},
#endif
	 {
		.procname	= "hugetlb_shm_group",
		.data		= &sysctl_hugetlb_shm_group,
		.maxlen		= sizeof(gid_t),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	 },
	 {
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	 },
	 {
		.procname	= "hugepages_treat_as_movable",
		.data		= &hugepages_treat_as_movable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &hugetlb_treat_movable_handler,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "nr_overcommit_hugepages",
		.data		= NULL,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &hugetlb_overcommit_handler,
		.extra1		= (void *)&hugetlb_zero,
		.extra2		= (void *)&hugetlb_infinity,
	},
#endif
	{
		.ctl_name	= VM_LOWMEM_RESERVE_RATIO,
		.proc_handler	= hugetlb_overcommit_handler,
	},
#endif
	{
		.procname	= "lowmem_reserve_ratio",
		.data		= &sysctl_lowmem_reserve_ratio,
		.maxlen		= sizeof(sysctl_lowmem_reserve_ratio),
		.mode		= 0644,
		.proc_handler	= &lowmem_reserve_ratio_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= VM_DROP_PAGECACHE,
		.proc_handler	= lowmem_reserve_ratio_sysctl_handler,
	},
	{
		.procname	= "drop_caches",
		.data		= &sysctl_drop_caches,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= drop_caches_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= VM_MIN_FREE_KBYTES,
		.extra1		= &one,
		.extra2		= &four,
	},
#ifdef CONFIG_COMPACTION
	{
		.procname	= "compact_memory",
		.data		= &sysctl_compact_memory,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= sysctl_compaction_handler,
	},
	{
		.procname	= "extfrag_threshold",
		.data		= &sysctl_extfrag_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_extfrag_handler,
		.extra1		= &min_extfrag_threshold,
		.extra2		= &max_extfrag_threshold,
	},
	{
		.procname	= "compact_unevictable_allowed",
		.data		= &sysctl_compact_unevictable_allowed,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &zero,
		.extra2		= &one,
	},

#endif /* CONFIG_COMPACTION */
	{
		.procname	= "min_free_kbytes",
		.data		= &min_free_kbytes,
		.maxlen		= sizeof(min_free_kbytes),
		.mode		= 0644,
		.proc_handler	= &min_free_kbytes_sysctl_handler,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
	},
	{
		.ctl_name	= VM_PERCPU_PAGELIST_FRACTION,
		.proc_handler	= min_free_kbytes_sysctl_handler,
		.extra1		= &zero,
	},
	{
		.procname	= "watermark_scale_factor",
		.data		= &watermark_scale_factor,
		.maxlen		= sizeof(watermark_scale_factor),
		.mode		= 0644,
		.proc_handler	= watermark_scale_factor_sysctl_handler,
		.extra1		= &one,
		.extra2		= &one_thousand,
	},
	{
		.procname	= "percpu_pagelist_fraction",
		.data		= &percpu_pagelist_fraction,
		.maxlen		= sizeof(percpu_pagelist_fraction),
		.mode		= 0644,
		.proc_handler	= &percpu_pagelist_fraction_sysctl_handler,
		.strategy	= &sysctl_intvec,
		.extra1		= &min_percpu_pagelist_fract,
	},
#ifdef CONFIG_MMU
	{
		.ctl_name	= VM_MAX_MAP_COUNT,
		.proc_handler	= percpu_pagelist_fraction_sysctl_handler,
		.extra1		= &zero,
	},
#ifdef CONFIG_MMU
	{
		.procname	= "max_map_count",
		.data		= &sysctl_max_map_count,
		.maxlen		= sizeof(sysctl_max_map_count),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
#endif
	{
		.ctl_name	= VM_LAPTOP_MODE,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
#else
	{
		.procname	= "nr_trim_pages",
		.data		= &sysctl_nr_trim_pages,
		.maxlen		= sizeof(sysctl_nr_trim_pages),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
#endif
	{
		.procname	= "laptop_mode",
		.data		= &laptop_mode,
		.maxlen		= sizeof(laptop_mode),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= VM_BLOCK_DUMP,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "block_dump",
		.data		= &block_dump,
		.maxlen		= sizeof(block_dump),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
	},
	{
		.ctl_name	= VM_VFS_CACHE_PRESSURE,
		.proc_handler	= proc_dointvec,
		.extra1		= &zero,
	},
	{
		.procname	= "vfs_cache_pressure",
		.data		= &sysctl_vfs_cache_pressure,
		.maxlen		= sizeof(sysctl_vfs_cache_pressure),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec,
		.extra1		= &zero,
	},
#ifdef HAVE_ARCH_PICK_MMAP_LAYOUT
	{
		.ctl_name	= VM_LEGACY_VA_LAYOUT,
		.procname	= "legacy_va_layout",
		.data		= &sysctl_legacy_va_layout,
		.maxlen		= sizeof(sysctl_legacy_va_layout),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec,
		.extra1		= &zero,
	},
#endif
#ifdef CONFIG_NUMA
	{
		.ctl_name	= VM_ZONE_RECLAIM_MODE,
		.procname	= "zone_reclaim_mode",
		.data		= &node_reclaim_mode,
		.maxlen		= sizeof(node_reclaim_mode),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
	},
	{
		.ctl_name	= VM_MIN_UNMAPPED,
		.proc_handler	= proc_dointvec,
		.extra1		= &zero,
	},
	{
		.procname	= "min_unmapped_ratio",
		.data		= &sysctl_min_unmapped_ratio,
		.maxlen		= sizeof(sysctl_min_unmapped_ratio),
		.mode		= 0644,
		.proc_handler	= &sysctl_min_unmapped_ratio_sysctl_handler,
		.strategy	= &sysctl_intvec,
		.proc_handler	= sysctl_min_unmapped_ratio_sysctl_handler,
		.extra1		= &zero,
		.extra2		= &one_hundred,
	},
	{
		.ctl_name	= VM_MIN_SLAB,
		.procname	= "min_slab_ratio",
		.data		= &sysctl_min_slab_ratio,
		.maxlen		= sizeof(sysctl_min_slab_ratio),
		.mode		= 0644,
		.proc_handler	= &sysctl_min_slab_ratio_sysctl_handler,
		.strategy	= &sysctl_intvec,
		.proc_handler	= sysctl_min_slab_ratio_sysctl_handler,
		.extra1		= &zero,
		.extra2		= &one_hundred,
	},
#endif
#ifdef CONFIG_SMP
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "stat_interval",
		.data		= &sysctl_stat_interval,
		.maxlen		= sizeof(sysctl_stat_interval),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
#endif
#ifdef CONFIG_SECURITY
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "mmap_min_addr",
		.data		= &mmap_min_addr,
		.maxlen         = sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "stat_refresh",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0600,
		.proc_handler	= vmstat_refresh,
	},
#endif
#ifdef CONFIG_MMU
	{
		.procname	= "mmap_min_addr",
		.data		= &dac_mmap_min_addr,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= mmap_min_addr_handler,
	},
#endif
#ifdef CONFIG_NUMA
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "numa_zonelist_order",
		.data		= &numa_zonelist_order,
		.maxlen		= NUMA_ZONELIST_ORDER_LEN,
		.mode		= 0644,
		.proc_handler	= &numa_zonelist_order_handler,
		.strategy	= &sysctl_string,
		.proc_handler	= numa_zonelist_order_handler,
	},
#endif
#if (defined(CONFIG_X86_32) && !defined(CONFIG_UML))|| \
   (defined(CONFIG_SUPERH) && defined(CONFIG_VSYSCALL))
	{
		.ctl_name	= VM_VDSO_ENABLED,
		.procname	= "vdso_enabled",
		.data		= &vdso_enabled,
		.maxlen		= sizeof(vdso_enabled),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
		.strategy	= &sysctl_intvec,
		.procname	= "vdso_enabled",
#ifdef CONFIG_X86_32
		.data		= &vdso32_enabled,
		.maxlen		= sizeof(vdso32_enabled),
#else
		.data		= &vdso_enabled,
		.maxlen		= sizeof(vdso_enabled),
#endif
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= &zero,
	},
#endif
#ifdef CONFIG_HIGHMEM
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "highmem_is_dirtyable",
		.data		= &vm_highmem_is_dirtyable,
		.maxlen		= sizeof(vm_highmem_is_dirtyable),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
/*
 * NOTE: do not add new entries to this table unless you have read
 * Documentation/sysctl/ctl_unnumbered.txt
 */
	{ .ctl_name = 0 }
};

#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
static struct ctl_table binfmt_misc_table[] = {
	{ .ctl_name = 0 }
};
#endif

static struct ctl_table fs_table[] = {
	{
		.ctl_name	= FS_NRINODE,
		.procname	= "inode-nr",
		.data		= &inodes_stat,
		.maxlen		= 2*sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FS_STATINODE,
		.procname	= "inode-state",
		.data		= &inodes_stat,
		.maxlen		= 7*sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
#ifdef CONFIG_MEMORY_FAILURE
	{
		.procname	= "memory_failure_early_kill",
		.data		= &sysctl_memory_failure_early_kill,
		.maxlen		= sizeof(sysctl_memory_failure_early_kill),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "memory_failure_recovery",
		.data		= &sysctl_memory_failure_recovery,
		.maxlen		= sizeof(sysctl_memory_failure_recovery),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
	{
		.procname	= "user_reserve_kbytes",
		.data		= &sysctl_user_reserve_kbytes,
		.maxlen		= sizeof(sysctl_user_reserve_kbytes),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "admin_reserve_kbytes",
		.data		= &sysctl_admin_reserve_kbytes,
		.maxlen		= sizeof(sysctl_admin_reserve_kbytes),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
	{
		.procname	= "mmap_rnd_bits",
		.data		= &mmap_rnd_bits,
		.maxlen		= sizeof(mmap_rnd_bits),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&mmap_rnd_bits_min,
		.extra2		= (void *)&mmap_rnd_bits_max,
	},
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
	{
		.procname	= "mmap_rnd_compat_bits",
		.data		= &mmap_rnd_compat_bits,
		.maxlen		= sizeof(mmap_rnd_compat_bits),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&mmap_rnd_compat_bits_min,
		.extra2		= (void *)&mmap_rnd_compat_bits_max,
	},
#endif
	{ }
};

static struct ctl_table fs_table[] = {
	{
		.procname	= "inode-nr",
		.data		= &inodes_stat,
		.maxlen		= 2*sizeof(long),
		.mode		= 0444,
		.proc_handler	= proc_nr_inodes,
	},
	{
		.procname	= "inode-state",
		.data		= &inodes_stat,
		.maxlen		= 7*sizeof(long),
		.mode		= 0444,
		.proc_handler	= proc_nr_inodes,
	},
	{
		.procname	= "file-nr",
		.data		= &files_stat,
		.maxlen		= 3*sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_nr_files,
	},
	{
		.ctl_name	= FS_MAXFILE,
		.procname	= "file-max",
		.data		= &files_stat.max_files,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.maxlen		= sizeof(files_stat),
		.mode		= 0444,
		.proc_handler	= proc_nr_files,
	},
	{
		.procname	= "file-max",
		.data		= &files_stat.max_files,
		.maxlen		= sizeof(files_stat.max_files),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "nr_open",
		.data		= &sysctl_nr_open,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_nr_open_min,
		.extra2		= &sysctl_nr_open_max,
	},
	{
		.ctl_name	= FS_DENTRY,
		.procname	= "dentry-state",
		.data		= &dentry_stat,
		.maxlen		= 6*sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FS_OVERFLOWUID,
		.procname	= "dentry-state",
		.data		= &dentry_stat,
		.maxlen		= 6*sizeof(long),
		.mode		= 0444,
		.proc_handler	= proc_nr_dentry,
	},
	{
		.procname	= "overflowuid",
		.data		= &fs_overflowuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &minolduid,
		.extra2		= &maxolduid,
	},
	{
		.ctl_name	= FS_OVERFLOWGID,
		.procname	= "overflowgid",
		.data		= &fs_overflowgid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &minolduid,
		.extra2		= &maxolduid,
	},
	{
		.ctl_name	= FS_LEASES,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &minolduid,
		.extra2		= &maxolduid,
	},
#ifdef CONFIG_FILE_LOCKING
	{
		.procname	= "leases-enable",
		.data		= &leases_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef CONFIG_DNOTIFY
	{
		.ctl_name	= FS_DIR_NOTIFY,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_DNOTIFY
	{
		.procname	= "dir-notify-enable",
		.data		= &dir_notify_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_MMU
	{
		.ctl_name	= FS_LEASE_TIME,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_MMU
#ifdef CONFIG_FILE_LOCKING
	{
		.procname	= "lease-break-time",
		.data		= &lease_break_time,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
		.extra2		= &two,
	},
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_AIO
	{
		.procname	= "aio-nr",
		.data		= &aio_nr,
		.maxlen		= sizeof(aio_nr),
		.mode		= 0444,
		.proc_handler	= &proc_doulongvec_minmax,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "aio-max-nr",
		.data		= &aio_max_nr,
		.maxlen		= sizeof(aio_max_nr),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax,
	},
#ifdef CONFIG_INOTIFY_USER
	{
		.ctl_name	= FS_INOTIFY,
		.proc_handler	= proc_doulongvec_minmax,
	},
#endif /* CONFIG_AIO */
#ifdef CONFIG_INOTIFY_USER
	{
		.procname	= "inotify",
		.mode		= 0555,
		.child		= inotify_table,
	},
#endif	
#endif
	{
		.ctl_name	= KERN_SETUID_DUMPABLE,
#ifdef CONFIG_EPOLL
	{
		.procname	= "epoll",
		.mode		= 0555,
		.child		= epoll_table,
	},
#endif
#endif
	{
		.procname	= "protected_symlinks",
		.data		= &sysctl_protected_symlinks,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "protected_hardlinks",
		.data		= &sysctl_protected_hardlinks,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "suid_dumpable",
		.data		= &suid_dumpable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "binfmt_misc",
		.mode		= 0555,
		.child		= binfmt_misc_table,
	},
#endif
/*
 * NOTE: do not add new entries to this table unless you have read
 * Documentation/sysctl/ctl_unnumbered.txt
 */
	{ .ctl_name = 0 }
};

static struct ctl_table debug_table[] = {
#if defined(CONFIG_X86) || defined(CONFIG_PPC)
	{
		.ctl_name	= CTL_UNNUMBERED,
		.proc_handler	= proc_dointvec_minmax_coredump,
		.extra1		= &zero,
		.extra2		= &two,
	},
#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	{
		.procname	= "binfmt_misc",
		.mode		= 0555,
		.child		= sysctl_mount_point,
	},
#endif
	{
		.procname	= "pipe-max-size",
		.data		= &pipe_max_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &pipe_proc_fn,
		.extra1		= &pipe_min_size,
	},
	{
		.procname	= "pipe-user-pages-hard",
		.data		= &pipe_user_pages_hard,
		.maxlen		= sizeof(pipe_user_pages_hard),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "pipe-user-pages-soft",
		.data		= &pipe_user_pages_soft,
		.maxlen		= sizeof(pipe_user_pages_soft),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "mount-max",
		.data		= &sysctl_mount_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
	{ }
};

static struct ctl_table debug_table[] = {
#ifdef CONFIG_SYSCTL_EXCEPTION_TRACE
	{
		.procname	= "exception-trace",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
#endif
	{ .ctl_name = 0 }
};

static struct ctl_table dev_table[] = {
	{ .ctl_name = 0 }
};

static DEFINE_SPINLOCK(sysctl_lock);

/* called under sysctl_lock */
static int use_table(struct ctl_table_header *p)
{
	if (unlikely(p->unregistering))
		return 0;
	p->used++;
	return 1;
}

/* called under sysctl_lock */
static void unuse_table(struct ctl_table_header *p)
{
	if (!--p->used)
		if (unlikely(p->unregistering))
			complete(p->unregistering);
}

/* called under sysctl_lock, will reacquire if has to wait */
static void start_unregistering(struct ctl_table_header *p)
{
	/*
	 * if p->used is 0, nobody will ever touch that entry again;
	 * we'll eliminate all paths to it before dropping sysctl_lock
	 */
	if (unlikely(p->used)) {
		struct completion wait;
		init_completion(&wait);
		p->unregistering = &wait;
		spin_unlock(&sysctl_lock);
		wait_for_completion(&wait);
		spin_lock(&sysctl_lock);
	} else {
		/* anything non-NULL; we'll never dereference it */
		p->unregistering = ERR_PTR(-EINVAL);
	}
	/*
	 * do not remove from the list until nobody holds it; walking the
	 * list in do_sysctl() relies on that.
	 */
	list_del_init(&p->ctl_entry);
}

void sysctl_head_get(struct ctl_table_header *head)
{
	spin_lock(&sysctl_lock);
	head->count++;
	spin_unlock(&sysctl_lock);
}

void sysctl_head_put(struct ctl_table_header *head)
{
	spin_lock(&sysctl_lock);
	if (!--head->count)
		kfree(head);
	spin_unlock(&sysctl_lock);
}

struct ctl_table_header *sysctl_head_grab(struct ctl_table_header *head)
{
	if (!head)
		BUG();
	spin_lock(&sysctl_lock);
	if (!use_table(head))
		head = ERR_PTR(-ENOENT);
	spin_unlock(&sysctl_lock);
	return head;
}

void sysctl_head_finish(struct ctl_table_header *head)
{
	if (!head)
		return;
	spin_lock(&sysctl_lock);
	unuse_table(head);
	spin_unlock(&sysctl_lock);
}

static struct ctl_table_set *
lookup_header_set(struct ctl_table_root *root, struct nsproxy *namespaces)
{
	struct ctl_table_set *set = &root->default_set;
	if (root->lookup)
		set = root->lookup(root, namespaces);
	return set;
}

static struct list_head *
lookup_header_list(struct ctl_table_root *root, struct nsproxy *namespaces)
{
	struct ctl_table_set *set = lookup_header_set(root, namespaces);
	return &set->list;
}

struct ctl_table_header *__sysctl_head_next(struct nsproxy *namespaces,
					    struct ctl_table_header *prev)
{
	struct ctl_table_root *root;
	struct list_head *header_list;
	struct ctl_table_header *head;
	struct list_head *tmp;

	spin_lock(&sysctl_lock);
	if (prev) {
		head = prev;
		tmp = &prev->ctl_entry;
		unuse_table(prev);
		goto next;
	}
	tmp = &root_table_header.ctl_entry;
	for (;;) {
		head = list_entry(tmp, struct ctl_table_header, ctl_entry);

		if (!use_table(head))
			goto next;
		spin_unlock(&sysctl_lock);
		return head;
	next:
		root = head->root;
		tmp = tmp->next;
		header_list = lookup_header_list(root, namespaces);
		if (tmp != header_list)
			continue;

		do {
			root = list_entry(root->root_list.next,
					struct ctl_table_root, root_list);
			if (root == &sysctl_table_root)
				goto out;
			header_list = lookup_header_list(root, namespaces);
		} while (list_empty(header_list));
		tmp = header_list->next;
	}
out:
	spin_unlock(&sysctl_lock);
	return NULL;
}

struct ctl_table_header *sysctl_head_next(struct ctl_table_header *prev)
{
	return __sysctl_head_next(current->nsproxy, prev);
}

void register_sysctl_root(struct ctl_table_root *root)
{
	spin_lock(&sysctl_lock);
	list_add_tail(&root->root_list, &sysctl_table_root.root_list);
	spin_unlock(&sysctl_lock);
}

#ifdef CONFIG_SYSCTL_SYSCALL
/* Perform the actual read/write of a sysctl table entry. */
static int do_sysctl_strategy(struct ctl_table_root *root,
			struct ctl_table *table,
			int __user *name, int nlen,
			void __user *oldval, size_t __user *oldlenp,
			void __user *newval, size_t newlen)
{
	int op = 0, rc;

	if (oldval)
		op |= MAY_READ;
	if (newval)
		op |= MAY_WRITE;
	if (sysctl_perm(root, table, op))
		return -EPERM;

	if (table->strategy) {
		rc = table->strategy(table, name, nlen, oldval, oldlenp,
				     newval, newlen);
		if (rc < 0)
			return rc;
		if (rc > 0)
			return 0;
	}

	/* If there is no strategy routine, or if the strategy returns
	 * zero, proceed with automatic r/w */
	if (table->data && table->maxlen) {
		rc = sysctl_data(table, name, nlen, oldval, oldlenp,
				 newval, newlen);
		if (rc < 0)
			return rc;
	}
	return 0;
}

static int parse_table(int __user *name, int nlen,
		       void __user *oldval, size_t __user *oldlenp,
		       void __user *newval, size_t newlen,
		       struct ctl_table_root *root,
		       struct ctl_table *table)
{
	int n;
repeat:
	if (!nlen)
		return -ENOTDIR;
	if (get_user(n, name))
		return -EFAULT;
	for ( ; table->ctl_name || table->procname; table++) {
		if (!table->ctl_name)
			continue;
		if (n == table->ctl_name) {
			int error;
			if (table->child) {
				if (sysctl_perm(root, table, MAY_EXEC))
					return -EPERM;
				name++;
				nlen--;
				table = table->child;
				goto repeat;
			}
			error = do_sysctl_strategy(root, table, name, nlen,
						   oldval, oldlenp,
						   newval, newlen);
			return error;
		}
	}
	return -ENOTDIR;
}

int do_sysctl(int __user *name, int nlen, void __user *oldval, size_t __user *oldlenp,
	       void __user *newval, size_t newlen)
{
	struct ctl_table_header *head;
	int error = -ENOTDIR;

	if (nlen <= 0 || nlen >= CTL_MAXNAME)
		return -ENOTDIR;
	if (oldval) {
		int old_len;
		if (!oldlenp || get_user(old_len, oldlenp))
			return -EFAULT;
	}

	for (head = sysctl_head_next(NULL); head;
			head = sysctl_head_next(head)) {
		error = parse_table(name, nlen, oldval, oldlenp, 
					newval, newlen,
					head->root, head->ctl_table);
		if (error != -ENOTDIR) {
			sysctl_head_finish(head);
			break;
		}
	}
	return error;
}

asmlinkage long sys_sysctl(struct __sysctl_args __user *args)
{
	struct __sysctl_args tmp;
	int error;

	if (copy_from_user(&tmp, args, sizeof(tmp)))
		return -EFAULT;

	error = deprecated_sysctl_warning(&tmp);
	if (error)
		goto out;

	lock_kernel();
	error = do_sysctl(tmp.name, tmp.nlen, tmp.oldval, tmp.oldlenp,
			  tmp.newval, tmp.newlen);
	unlock_kernel();
out:
	return error;
}
#endif /* CONFIG_SYSCTL_SYSCALL */

/*
 * sysctl_perm does NOT grant the superuser all rights automatically, because
 * some sysctl variables are readonly even to root.
 */

static int test_perm(int mode, int op)
{
	if (!current->euid)
		mode >>= 6;
	else if (in_egroup_p(0))
		mode >>= 3;
	if ((op & ~mode & (MAY_READ|MAY_WRITE|MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}

int sysctl_perm(struct ctl_table_root *root, struct ctl_table *table, int op)
{
	int error;
	int mode;

	error = security_sysctl(table, op & (MAY_READ | MAY_WRITE | MAY_EXEC));
	if (error)
		return error;

	if (root->permissions)
		mode = root->permissions(root, current->nsproxy, table);
	else
		mode = table->mode;

	return test_perm(mode, op);
}

static void sysctl_set_parent(struct ctl_table *parent, struct ctl_table *table)
{
	for (; table->ctl_name || table->procname; table++) {
		table->parent = parent;
		if (table->child)
			sysctl_set_parent(table, table->child);
	}
}

static __init int sysctl_init(void)
{
	sysctl_set_parent(NULL, root_table);
#ifdef CONFIG_SYSCTL_SYSCALL_CHECK
	{
		int err;
		err = sysctl_check_table(current->nsproxy, root_table);
	}
#endif
	return 0;
}

core_initcall(sysctl_init);

static struct ctl_table *is_branch_in(struct ctl_table *branch,
				      struct ctl_table *table)
{
	struct ctl_table *p;
	const char *s = branch->procname;

	/* branch should have named subdirectory as its first element */
	if (!s || !branch->child)
		return NULL;

	/* ... and nothing else */
	if (branch[1].procname || branch[1].ctl_name)
		return NULL;

	/* table should contain subdirectory with the same name */
	for (p = table; p->procname || p->ctl_name; p++) {
		if (!p->child)
			continue;
		if (p->procname && strcmp(p->procname, s) == 0)
			return p;
	}
	return NULL;
}

/* see if attaching q to p would be an improvement */
static void try_attach(struct ctl_table_header *p, struct ctl_table_header *q)
{
	struct ctl_table *to = p->ctl_table, *by = q->ctl_table;
	struct ctl_table *next;
	int is_better = 0;
	int not_in_parent = !p->attached_by;

	while ((next = is_branch_in(by, to)) != NULL) {
		if (by == q->attached_by)
			is_better = 1;
		if (to == p->attached_by)
			not_in_parent = 1;
		by = by->child;
		to = next->child;
	}

	if (is_better && not_in_parent) {
		q->attached_by = by;
		q->attached_to = to;
		q->parent = p;
	}
}

/**
 * __register_sysctl_paths - register a sysctl hierarchy
 * @root: List of sysctl headers to register on
 * @namespaces: Data to compute which lists of sysctl entries are visible
 * @path: The path to the directory the sysctl table is in.
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * The members of the &struct ctl_table structure are used as follows:
 *
 * ctl_name - This is the numeric sysctl value used by sysctl(2). The number
 *            must be unique within that level of sysctl
 *
 * procname - the name of the sysctl file under /proc/sys. Set to %NULL to not
 *            enter a sysctl file
 *
 * data - a pointer to data for use by proc_handler
 *
 * maxlen - the maximum size in bytes of the data
 *
 * mode - the file permissions for the /proc/sys file, and for sysctl(2)
 *
 * child - a pointer to the child sysctl table if this entry is a directory, or
 *         %NULL.
 *
 * proc_handler - the text handler routine (described below)
 *
 * strategy - the strategy routine (described below)
 *
 * de - for internal use by the sysctl routines
 *
 * extra1, extra2 - extra pointers usable by the proc handler routines
 *
 * Leaf nodes in the sysctl tree will be represented by a single file
 * under /proc; non-leaf nodes will be represented by directories.
 *
 * sysctl(2) can automatically manage read and write requests through
 * the sysctl table.  The data and maxlen fields of the ctl_table
 * struct enable minimal validation of the values being written to be
 * performed, and the mode field allows minimal authentication.
 *
 * More sophisticated management can be enabled by the provision of a
 * strategy routine with the table entry.  This will be called before
 * any automatic read or write of the data is performed.
 *
 * The strategy routine may return
 *
 * < 0 - Error occurred (error is passed to user process)
 *
 * 0   - OK - proceed with automatic read or write.
 *
 * > 0 - OK - read or write has been done by the strategy routine, so
 *       return immediately.
 *
 * There must be a proc_handler routine for any terminal nodes
 * mirrored under /proc/sys (non-terminals are handled by a built-in
 * directory handler).  Several default handlers are available to
 * cover common cases -
 *
 * proc_dostring(), proc_dointvec(), proc_dointvec_jiffies(),
 * proc_dointvec_userhz_jiffies(), proc_dointvec_minmax(), 
 * proc_doulongvec_ms_jiffies_minmax(), proc_doulongvec_minmax()
 *
 * It is the handler's job to read the input buffer from user memory
 * and process it. The handler should return 0 on success.
 *
 * This routine returns %NULL on a failure to register, and a pointer
 * to the table header on success.
 */
struct ctl_table_header *__register_sysctl_paths(
	struct ctl_table_root *root,
	struct nsproxy *namespaces,
	const struct ctl_path *path, struct ctl_table *table)
{
	struct ctl_table_header *header;
	struct ctl_table *new, **prevp;
	unsigned int n, npath;
	struct ctl_table_set *set;

	/* Count the path components */
	for (npath = 0; path[npath].ctl_name || path[npath].procname; ++npath)
		;

	/*
	 * For each path component, allocate a 2-element ctl_table array.
	 * The first array element will be filled with the sysctl entry
	 * for this, the second will be the sentinel (ctl_name == 0).
	 *
	 * We allocate everything in one go so that we don't have to
	 * worry about freeing additional memory in unregister_sysctl_table.
	 */
	header = kzalloc(sizeof(struct ctl_table_header) +
			 (2 * npath * sizeof(struct ctl_table)), GFP_KERNEL);
	if (!header)
		return NULL;

	new = (struct ctl_table *) (header + 1);

	/* Now connect the dots */
	prevp = &header->ctl_table;
	for (n = 0; n < npath; ++n, ++path) {
		/* Copy the procname */
		new->procname = path->procname;
		new->ctl_name = path->ctl_name;
		new->mode     = 0555;

		*prevp = new;
		prevp = &new->child;

		new += 2;
	}
	*prevp = table;
	header->ctl_table_arg = table;

	INIT_LIST_HEAD(&header->ctl_entry);
	header->used = 0;
	header->unregistering = NULL;
	header->root = root;
	sysctl_set_parent(NULL, header->ctl_table);
	header->count = 1;
#ifdef CONFIG_SYSCTL_SYSCALL_CHECK
	if (sysctl_check_table(namespaces, header->ctl_table)) {
		kfree(header);
		return NULL;
	}
#endif
	spin_lock(&sysctl_lock);
	header->set = lookup_header_set(root, namespaces);
	header->attached_by = header->ctl_table;
	header->attached_to = root_table;
	header->parent = &root_table_header;
	for (set = header->set; set; set = set->parent) {
		struct ctl_table_header *p;
		list_for_each_entry(p, &set->list, ctl_entry) {
			if (p->unregistering)
				continue;
			try_attach(p, header);
		}
	}
	header->parent->count++;
	list_add_tail(&header->ctl_entry, &header->set->list);
	spin_unlock(&sysctl_lock);

	return header;
}

/**
 * register_sysctl_table_path - register a sysctl table hierarchy
 * @path: The path to the directory the sysctl table is in.
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * See __register_sysctl_paths for more details.
 */
struct ctl_table_header *register_sysctl_paths(const struct ctl_path *path,
						struct ctl_table *table)
{
	return __register_sysctl_paths(&sysctl_table_root, current->nsproxy,
					path, table);
}

/**
 * register_sysctl_table - register a sysctl table hierarchy
 * @table: the top-level table structure
 *
 * Register a sysctl table hierarchy. @table should be a filled in ctl_table
 * array. A completely 0 filled entry terminates the table.
 *
 * See register_sysctl_paths for more details.
 */
struct ctl_table_header *register_sysctl_table(struct ctl_table *table)
{
	static const struct ctl_path null_path[] = { {} };

	return register_sysctl_paths(null_path, table);
}

/**
 * unregister_sysctl_table - unregister a sysctl table hierarchy
 * @header: the header returned from register_sysctl_table
 *
 * Unregisters the sysctl table and all children. proc entries may not
 * actually be removed until they are no longer used by anyone.
 */
void unregister_sysctl_table(struct ctl_table_header * header)
{
	might_sleep();

	if (header == NULL)
		return;

	spin_lock(&sysctl_lock);
	start_unregistering(header);
	if (!--header->parent->count) {
		WARN_ON(1);
		kfree(header->parent);
	}
	if (!--header->count)
		kfree(header);
	spin_unlock(&sysctl_lock);
}

int sysctl_is_seen(struct ctl_table_header *p)
{
	struct ctl_table_set *set = p->set;
	int res;
	spin_lock(&sysctl_lock);
	if (p->unregistering)
		res = 0;
	else if (!set->is_seen)
		res = 1;
	else
		res = set->is_seen(set);
	spin_unlock(&sysctl_lock);
	return res;
}

void setup_sysctl_set(struct ctl_table_set *p,
	struct ctl_table_set *parent,
	int (*is_seen)(struct ctl_table_set *))
{
	INIT_LIST_HEAD(&p->list);
	p->parent = parent ? parent : &sysctl_table_root.default_set;
	p->is_seen = is_seen;
}

#else /* !CONFIG_SYSCTL */
struct ctl_table_header *register_sysctl_table(struct ctl_table * table)
{
	return NULL;
}

struct ctl_table_header *register_sysctl_paths(const struct ctl_path *path,
						    struct ctl_table *table)
{
	return NULL;
}

void unregister_sysctl_table(struct ctl_table_header * table)
{
}

void setup_sysctl_set(struct ctl_table_set *p,
	struct ctl_table_set *parent,
	int (*is_seen)(struct ctl_table_set *))
{
}

void sysctl_head_put(struct ctl_table_header *head)
{
}

#if defined(CONFIG_OPTPROBES)
	{
		.procname	= "kprobes-optimization",
		.data		= &sysctl_kprobes_optimization,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_kprobes_optimization_handler,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
	{ }
};

static struct ctl_table dev_table[] = {
	{ }
};

int __init sysctl_init(void)
{
	struct ctl_table_header *hdr;

	hdr = register_sysctl_table(sysctl_base_table);
	kmemleak_not_leak(hdr);
	return 0;
}

#endif /* CONFIG_SYSCTL */

/*
 * /proc/sys support
 */

#ifdef CONFIG_PROC_SYSCTL

static int _proc_do_string(void* data, int maxlen, int write,
			   struct file *filp, void __user *buffer,
static int _proc_do_string(char *data, int maxlen, int write,
			   char __user *buffer,
			   size_t *lenp, loff_t *ppos)
{
	size_t len;
	char __user *p;
	char c;

	if (!data || !maxlen || !*lenp) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		len = 0;
		p = buffer;
		while (len < *lenp) {
		if (sysctl_writes_strict == SYSCTL_WRITES_STRICT) {
			/* Only continue writes not past the end of buffer. */
			len = strlen(data);
			if (len > maxlen - 1)
				len = maxlen - 1;

			if (*ppos > len)
				return 0;
			len = *ppos;
		} else {
			/* Start writing from beginning of buffer. */
			len = 0;
		}

		*ppos += *lenp;
		p = buffer;
		while ((p - buffer) < *lenp && len < maxlen - 1) {
			if (get_user(c, p++))
				return -EFAULT;
			if (c == 0 || c == '\n')
				break;
			len++;
		}
		if (len >= maxlen)
			len = maxlen-1;
		if(copy_from_user(data, buffer, len))
			return -EFAULT;
		((char *) data)[len] = 0;
		*ppos += *lenp;
			data[len++] = c;
		}
		data[len] = 0;
	} else {
		len = strlen(data);
		if (len > maxlen)
			len = maxlen;

		if (*ppos > len) {
			*lenp = 0;
			return 0;
		}

		data += *ppos;
		len  -= *ppos;

		if (len > *lenp)
			len = *lenp;
		if (len)
			if(copy_to_user(buffer, data, len))
				return -EFAULT;
		if (len < *lenp) {
			if(put_user('\n', ((char __user *) buffer) + len))
			if (copy_to_user(buffer, data, len))
				return -EFAULT;
		if (len < *lenp) {
			if (put_user('\n', buffer + len))
				return -EFAULT;
			len++;
		}
		*lenp = len;
		*ppos += len;
	}
	return 0;
}

static void warn_sysctl_write(struct ctl_table *table)
{
	pr_warn_once("%s wrote to %s when file position was not 0!\n"
		"This will not be supported in the future. To silence this\n"
		"warning, set kernel.sysctl_writes_strict = -1\n",
		current->comm, table->procname);
}

/**
 * proc_first_pos_non_zero_ignore - check if firs position is allowed
 * @ppos: file position
 * @table: the sysctl table
 *
 * Returns true if the first position is non-zero and the sysctl_writes_strict
 * mode indicates this is not allowed for numeric input types. String proc
 * hadlers can ignore the return value.
 */
static bool proc_first_pos_non_zero_ignore(loff_t *ppos,
					   struct ctl_table *table)
{
	if (!*ppos)
		return false;

	switch (sysctl_writes_strict) {
	case SYSCTL_WRITES_STRICT:
		return true;
	case SYSCTL_WRITES_WARN:
		warn_sysctl_write(table);
		return false;
	default:
		return false;
	}
}

/**
 * proc_dostring - read a string sysctl
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes a string from/to the user buffer. If the kernel
 * buffer provided is not large enough to hold the string, the
 * string is truncated. The copied string is %NULL-terminated.
 * If the string is being read by the user process, it is copied
 * and a newline '\n' is added. It is truncated if the buffer is
 * not large enough.
 *
 * Returns 0 on success.
 */
int proc_dostring(struct ctl_table *table, int write, struct file *filp,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return _proc_do_string(table->data, table->maxlen, write, filp,
			       buffer, lenp, ppos);
}


static int do_proc_dointvec_conv(int *negp, unsigned long *lvalp,
int proc_dostring(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	if (write)
		proc_first_pos_non_zero_ignore(ppos, table);

	return _proc_do_string((char *)(table->data), table->maxlen, write,
			       (char __user *)buffer, lenp, ppos);
}

static size_t proc_skip_spaces(char **buf)
{
	size_t ret;
	char *tmp = skip_spaces(*buf);
	ret = tmp - *buf;
	*buf = tmp;
	return ret;
}

static void proc_skip_char(char **buf, size_t *size, const char v)
{
	while (*size) {
		if (**buf != v)
			break;
		(*size)--;
		(*buf)++;
	}
}

#define TMPBUFLEN 22
/**
 * proc_get_long - reads an ASCII formatted integer from a user buffer
 *
 * @buf: a kernel buffer
 * @size: size of the kernel buffer
 * @val: this is where the number will be stored
 * @neg: set to %TRUE if number is negative
 * @perm_tr: a vector which contains the allowed trailers
 * @perm_tr_len: size of the perm_tr vector
 * @tr: pointer to store the trailer character
 *
 * In case of success %0 is returned and @buf and @size are updated with
 * the amount of bytes read. If @tr is non-NULL and a trailing
 * character exists (size is non-zero after returning from this
 * function), @tr is updated with the trailing character.
 */
static int proc_get_long(char **buf, size_t *size,
			  unsigned long *val, bool *neg,
			  const char *perm_tr, unsigned perm_tr_len, char *tr)
{
	int len;
	char *p, tmp[TMPBUFLEN];

	if (!*size)
		return -EINVAL;

	len = *size;
	if (len > TMPBUFLEN - 1)
		len = TMPBUFLEN - 1;

	memcpy(tmp, *buf, len);

	tmp[len] = 0;
	p = tmp;
	if (*p == '-' && *size > 1) {
		*neg = true;
		p++;
	} else
		*neg = false;
	if (!isdigit(*p))
		return -EINVAL;

	*val = simple_strtoul(p, &p, 0);

	len = p - tmp;

	/* We don't know if the next char is whitespace thus we may accept
	 * invalid integers (e.g. 1234...a) or two integers instead of one
	 * (e.g. 123...1). So lets not allow such large numbers. */
	if (len == TMPBUFLEN - 1)
		return -EINVAL;

	if (len < *size && perm_tr_len && !memchr(perm_tr, *p, perm_tr_len))
		return -EINVAL;

	if (tr && (len < *size))
		*tr = *p;

	*buf += len;
	*size -= len;

	return 0;
}

/**
 * proc_put_long - converts an integer to a decimal ASCII formatted string
 *
 * @buf: the user buffer
 * @size: the size of the user buffer
 * @val: the integer to be converted
 * @neg: sign of the number, %TRUE for negative
 *
 * In case of success %0 is returned and @buf and @size are updated with
 * the amount of bytes written.
 */
static int proc_put_long(void __user **buf, size_t *size, unsigned long val,
			  bool neg)
{
	int len;
	char tmp[TMPBUFLEN], *p = tmp;

	sprintf(p, "%s%lu", neg ? "-" : "", val);
	len = strlen(tmp);
	if (len > *size)
		len = *size;
	if (copy_to_user(*buf, tmp, len))
		return -EFAULT;
	*size -= len;
	*buf += len;
	return 0;
}
#undef TMPBUFLEN

static int proc_put_char(void __user **buf, size_t *size, char c)
{
	if (*size) {
		char __user **buffer = (char __user **)buf;
		if (put_user(c, *buffer))
			return -EFAULT;
		(*size)--, (*buffer)++;
		*buf = *buffer;
	}
	return 0;
}

static int do_proc_dointvec_conv(bool *negp, unsigned long *lvalp,
				 int *valp,
				 int write, void *data)
{
	if (write) {
		*valp = *negp ? -*lvalp : *lvalp;
	} else {
		int val = *valp;
		if (val < 0) {
			*negp = -1;
			*lvalp = (unsigned long)-val;
		} else {
			*negp = 0;
		if (*negp) {
			if (*lvalp > (unsigned long) INT_MAX + 1)
				return -EINVAL;
			*valp = -*lvalp;
		} else {
			if (*lvalp > (unsigned long) INT_MAX)
				return -EINVAL;
			*valp = *lvalp;
		}
	} else {
		int val = *valp;
		if (val < 0) {
			*negp = true;
			*lvalp = -(unsigned long)val;
		} else {
			*negp = false;
			*lvalp = (unsigned long)val;
		}
	}
	return 0;
}

static int __do_proc_dointvec(void *tbl_data, struct ctl_table *table,
		  int write, struct file *filp, void __user *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(int *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
#define TMPBUFLEN 21
	int *i, vleft, first=1, neg, val;
	unsigned long lval;
	size_t left, len;
	
	char buf[TMPBUFLEN], *p;
	char __user *s = buffer;
	
	if (!tbl_data || !table->maxlen || !*lenp ||
	    (*ppos && !write)) {
static int do_proc_douintvec_conv(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data)
{
	if (write) {
		if (*lvalp > UINT_MAX)
			return -EINVAL;
		*valp = *lvalp;
	} else {
		unsigned int val = *valp;
		*lvalp = (unsigned long)val;
	}
	return 0;
}

static const char proc_wspace_sep[] = { ' ', '\t', '\n' };

static int __do_proc_dointvec(void *tbl_data, struct ctl_table *table,
		  int write, void __user *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	int *i, vleft, first = 1, err = 0;
	size_t left;
	char *kbuf = NULL, *p;
	
	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}
	
	i = (int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);
	left = *lenp;

	if (!conv)
		conv = do_proc_dointvec_conv;

	for (; left && vleft--; i++, first=0) {
		if (write) {
			while (left) {
				char c;
				if (get_user(c, s))
					return -EFAULT;
				if (!isspace(c))
					break;
				left--;
				s++;
			}
			if (!left)
				break;
			neg = 0;
			len = left;
			if (len > sizeof(buf) - 1)
				len = sizeof(buf) - 1;
			if (copy_from_user(buf, s, len))
				return -EFAULT;
			buf[len] = 0;
			p = buf;
			if (*p == '-' && left > 1) {
				neg = 1;
				p++;
			}
			if (*p < '0' || *p > '9')
				break;

			lval = simple_strtoul(p, &p, 0);

			len = p-buf;
			if ((len < left) && *p && !isspace(*p))
				break;
			if (neg)
				val = -val;
			s += len;
			left -= len;

			if (conv(&neg, &lval, i, 1, data))
				break;
		} else {
			p = buf;
			if (!first)
				*p++ = '\t';
	
			if (conv(&neg, &lval, i, 0, data))
				break;

			sprintf(p, "%s%lu", neg ? "-" : "", lval);
			len = strlen(buf);
			if (len > left)
				len = left;
			if(copy_to_user(s, buf, len))
				return -EFAULT;
			left -= len;
			s += len;
		}
	}

	if (!write && !first && left) {
		if(put_user('\n', s))
			return -EFAULT;
		left--, s++;
	}
	if (write) {
		while (left) {
			char c;
			if (get_user(c, s++))
				return -EFAULT;
			if (!isspace(c))
				break;
			left--;
		}
	}
	if (write && first)
		return -EINVAL;
	*lenp -= left;
	*ppos += *lenp;
	return 0;
#undef TMPBUFLEN
}

static int do_proc_dointvec(struct ctl_table *table, int write, struct file *filp,
		  void __user *buffer, size_t *lenp, loff_t *ppos,
		  int (*conv)(int *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	return __do_proc_dointvec(table->data, table, write, filp,
	if (write) {
		if (proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = kbuf = memdup_user_nul(buffer, left);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
	}

	for (; left && vleft--; i++, first=0) {
		unsigned long lval;
		bool neg;

		if (write) {
			left -= proc_skip_spaces(&p);

			if (!left)
				break;
			err = proc_get_long(&p, &left, &lval, &neg,
					     proc_wspace_sep,
					     sizeof(proc_wspace_sep), NULL);
			if (err)
				break;
			if (conv(&neg, &lval, i, 1, data)) {
				err = -EINVAL;
				break;
			}
		} else {
			if (conv(&neg, &lval, i, 0, data)) {
				err = -EINVAL;
				break;
			}
			if (!first)
				err = proc_put_char(&buffer, &left, '\t');
			if (err)
				break;
			err = proc_put_long(&buffer, &left, lval, neg);
			if (err)
				break;
		}
	}

	if (!write && !first && left && !err)
		err = proc_put_char(&buffer, &left, '\n');
	if (write && !err && left)
		left -= proc_skip_spaces(&p);
	if (write) {
		kfree(kbuf);
		if (first)
			return err ? : -EINVAL;
	}
	*lenp -= left;
out:
	*ppos += *lenp;
	return err;
}

static int do_proc_dointvec(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	return __do_proc_dointvec(table->data, table, write,
			buffer, lenp, ppos, conv, data);
}

static int do_proc_douintvec_w(unsigned int *tbl_data,
			       struct ctl_table *table,
			       void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;
	bool neg;
	char *kbuf = NULL, *p;

	left = *lenp;

	if (proc_first_pos_non_zero_ignore(ppos, table))
		goto bail_early;

	if (left > PAGE_SIZE - 1)
		left = PAGE_SIZE - 1;

	p = kbuf = memdup_user_nul(buffer, left);
	if (IS_ERR(kbuf))
		return -EINVAL;

	left -= proc_skip_spaces(&p);
	if (!left) {
		err = -EINVAL;
		goto out_free;
	}

	err = proc_get_long(&p, &left, &lval, &neg,
			     proc_wspace_sep,
			     sizeof(proc_wspace_sep), NULL);
	if (err || neg) {
		err = -EINVAL;
		goto out_free;
	}

	if (conv(&lval, tbl_data, 1, data)) {
		err = -EINVAL;
		goto out_free;
	}

	if (!err && left)
		left -= proc_skip_spaces(&p);

out_free:
	kfree(kbuf);
	if (err)
		return -EINVAL;

	return 0;

	/* This is in keeping with old __do_proc_dointvec() */
bail_early:
	*ppos += *lenp;
	return err;
}

static int do_proc_douintvec_r(unsigned int *tbl_data, void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;

	left = *lenp;

	if (conv(&lval, tbl_data, 0, data)) {
		err = -EINVAL;
		goto out;
	}

	err = proc_put_long(&buffer, &left, lval, false);
	if (err || !left)
		goto out;

	err = proc_put_char(&buffer, &left, '\n');

out:
	*lenp -= left;
	*ppos += *lenp;

	return err;
}

static int __do_proc_douintvec(void *tbl_data, struct ctl_table *table,
			       int write, void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned int *i, vleft;

	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);

	/*
	 * Arrays are not supported, keep this simple. *Do not* add
	 * support for them.
	 */
	if (vleft != 1) {
		*lenp = 0;
		return -EINVAL;
	}

	if (!conv)
		conv = do_proc_douintvec_conv;

	if (write)
		return do_proc_douintvec_w(i, table, buffer, lenp, ppos,
					   conv, data);
	return do_proc_douintvec_r(i, buffer, lenp, ppos, conv, data);
}

static int do_proc_douintvec(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos,
			     int (*conv)(unsigned long *lvalp,
					 unsigned int *valp,
					 int write, void *data),
			     void *data)
{
	return __do_proc_douintvec(table->data, table, write,
				   buffer, lenp, ppos, conv, data);
}

/**
 * proc_dointvec - read a vector of integers
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string. 
 *
 * Returns 0 on success.
 */
int proc_dointvec(struct ctl_table *table, int write, struct file *filp,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,filp,buffer,lenp,ppos,
		    	    NULL,NULL);
}

#define OP_SET	0
#define OP_AND	1
#define OP_OR	2

static int do_proc_dointvec_bset_conv(int *negp, unsigned long *lvalp,
				      int *valp,
				      int write, void *data)
{
	int op = *(int *)data;
	if (write) {
		int val = *negp ? -*lvalp : *lvalp;
		switch(op) {
		case OP_SET:	*valp = val; break;
		case OP_AND:	*valp &= val; break;
		case OP_OR:	*valp |= val; break;
		}
	} else {
		int val = *valp;
		if (val < 0) {
			*negp = -1;
			*lvalp = (unsigned long)-val;
		} else {
			*negp = 0;
			*lvalp = (unsigned long)val;
		}
	}
	return 0;
}

/*
 *	Taint values can only be increased
 */
static int proc_dointvec_taint(struct ctl_table *table, int write, struct file *filp,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int op;
int proc_dointvec(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos, NULL, NULL);
}

/**
 * proc_douintvec - read a vector of unsigned integers
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) unsigned integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * Returns 0 on success.
 */
int proc_douintvec(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_douintvec_conv, NULL);
}

/*
 * Taint values can only be increased
 * This means we can safely use a temporary.
 */
static int proc_taint(struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long tmptaint = get_taint();
	int err;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	op = OP_OR;
	return do_proc_dointvec(table,write,filp,buffer,lenp,ppos,
				do_proc_dointvec_bset_conv,&op);
}

	t = *table;
	t.data = &tmptaint;
	err = proc_doulongvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write) {
		/*
		 * Poor man's atomic or. Not worth adding a primitive
		 * to everyone's atomic.h for this
		 */
		int i;
		for (i = 0; i < BITS_PER_LONG && tmptaint >> i; i++) {
			if ((tmptaint >> i) & 1)
				add_taint(i, LOCKDEP_STILL_OK);
		}
	}

	return err;
}

#ifdef CONFIG_PRINTK
static int proc_dointvec_minmax_sysadmin(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return proc_dointvec_minmax(table, write, buffer, lenp, ppos);
}
#endif

struct do_proc_dointvec_minmax_conv_param {
	int *min;
	int *max;
};

static int do_proc_dointvec_minmax_conv(int *negp, unsigned long *lvalp, 
					int *valp, 
static int do_proc_dointvec_minmax_conv(bool *negp, unsigned long *lvalp,
					int *valp,
					int write, void *data)
{
	struct do_proc_dointvec_minmax_conv_param *param = data;
	if (write) {
		int val = *negp ? -*lvalp : *lvalp;
		if ((param->min && *param->min > val) ||
		    (param->max && *param->max < val))
			return -EINVAL;
		*valp = val;
	} else {
		int val = *valp;
		if (val < 0) {
			*negp = -1;
			*lvalp = (unsigned long)-val;
		} else {
			*negp = 0;
			*negp = true;
			*lvalp = -(unsigned long)val;
		} else {
			*negp = false;
			*lvalp = (unsigned long)val;
		}
	}
	return 0;
}

/**
 * proc_dointvec_minmax - read a vector of integers with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success.
 */
int proc_dointvec_minmax(struct ctl_table *table, int write, struct file *filp,
int proc_dointvec_minmax(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_dointvec_minmax_conv_param param = {
		.min = (int *) table->extra1,
		.max = (int *) table->extra2,
	};
	return do_proc_dointvec(table, write, filp, buffer, lenp, ppos,
				do_proc_dointvec_minmax_conv, &param);
}

static int __do_proc_doulongvec_minmax(void *data, struct ctl_table *table, int write,
				     struct file *filp,
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_minmax_conv, &param);
}

struct do_proc_douintvec_minmax_conv_param {
	unsigned int *min;
	unsigned int *max;
};

static int do_proc_douintvec_minmax_conv(unsigned long *lvalp,
					 unsigned int *valp,
					 int write, void *data)
{
	struct do_proc_douintvec_minmax_conv_param *param = data;

	if (write) {
		unsigned int val = *lvalp;

		if ((param->min && *param->min > val) ||
		    (param->max && *param->max < val))
			return -ERANGE;

		if (*lvalp > UINT_MAX)
			return -EINVAL;
		*valp = val;
	} else {
		unsigned int val = *valp;
		*lvalp = (unsigned long) val;
	}

	return 0;
}

/**
 * proc_douintvec_minmax - read a vector of unsigned ints with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) unsigned integer
 * values from/to the user buffer, treated as an ASCII string. Negative
 * strings are not allowed.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max). There is a final sanity
 * check for UINT_MAX to avoid having to support wrap around uses from
 * userspace.
 *
 * Returns 0 on success.
 */
int proc_douintvec_minmax(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_douintvec_minmax_conv_param param = {
		.min = (unsigned int *) table->extra1,
		.max = (unsigned int *) table->extra2,
	};
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_douintvec_minmax_conv, &param);
}

static void validate_coredump_safety(void)
{
#ifdef CONFIG_COREDUMP
	if (suid_dumpable == SUID_DUMP_ROOT &&
	    core_pattern[0] != '/' && core_pattern[0] != '|') {
		printk(KERN_WARNING
"Unsafe core_pattern used with fs.suid_dumpable=2.\n"
"Pipe handler or fully qualified core dump path required.\n"
"Set kernel.core_pattern before fs.suid_dumpable.\n"
		);
	}
#endif
}

static int proc_dointvec_minmax_coredump(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int error = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (!error)
		validate_coredump_safety();
	return error;
}

#ifdef CONFIG_COREDUMP
static int proc_dostring_coredump(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int error = proc_dostring(table, write, buffer, lenp, ppos);
	if (!error)
		validate_coredump_safety();
	return error;
}
#endif

static int __do_proc_doulongvec_minmax(void *data, struct ctl_table *table, int write,
				     void __user *buffer,
				     size_t *lenp, loff_t *ppos,
				     unsigned long convmul,
				     unsigned long convdiv)
{
#define TMPBUFLEN 21
	unsigned long *i, *min, *max, val;
	int vleft, first=1, neg;
	size_t len, left;
	char buf[TMPBUFLEN], *p;
	char __user *s = buffer;
	
	if (!data || !table->maxlen || !*lenp ||
	    (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}
	
	unsigned long *i, *min, *max;
	int vleft, first = 1, err = 0;
	size_t left;
	char *kbuf = NULL, *p;

	if (!data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned long *) data;
	min = (unsigned long *) table->extra1;
	max = (unsigned long *) table->extra2;
	vleft = table->maxlen / sizeof(unsigned long);
	left = *lenp;
	
	for (; left && vleft--; i++, min++, max++, first=0) {
		if (write) {
			while (left) {
				char c;
				if (get_user(c, s))
					return -EFAULT;
				if (!isspace(c))
					break;
				left--;
				s++;
			}
			if (!left)
				break;
			neg = 0;
			len = left;
			if (len > TMPBUFLEN-1)
				len = TMPBUFLEN-1;
			if (copy_from_user(buf, s, len))
				return -EFAULT;
			buf[len] = 0;
			p = buf;
			if (*p == '-' && left > 1) {
				neg = 1;
				p++;
			}
			if (*p < '0' || *p > '9')
				break;
			val = simple_strtoul(p, &p, 0) * convmul / convdiv ;
			len = p-buf;
			if ((len < left) && *p && !isspace(*p))
				break;
			if (neg)
				val = -val;
			s += len;
			left -= len;

			if(neg)

	if (write) {
		if (proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = kbuf = memdup_user_nul(buffer, left);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
	}

	for (; left && vleft--; i++, first = 0) {
		unsigned long val;

		if (write) {
			bool neg;

			left -= proc_skip_spaces(&p);

			err = proc_get_long(&p, &left, &val, &neg,
					     proc_wspace_sep,
					     sizeof(proc_wspace_sep), NULL);
			if (err)
				break;
			if (neg)
				continue;
			val = convmul * val / convdiv;
			if ((min && val < *min) || (max && val > *max))
				continue;
			*i = val;
		} else {
			p = buf;
			if (!first)
				*p++ = '\t';
			sprintf(p, "%lu", convdiv * (*i) / convmul);
			len = strlen(buf);
			if (len > left)
				len = left;
			if(copy_to_user(s, buf, len))
				return -EFAULT;
			left -= len;
			s += len;
		}
	}

	if (!write && !first && left) {
		if(put_user('\n', s))
			return -EFAULT;
		left--, s++;
	}
	if (write) {
		while (left) {
			char c;
			if (get_user(c, s++))
				return -EFAULT;
			if (!isspace(c))
				break;
			left--;
		}
	}
	if (write && first)
		return -EINVAL;
	*lenp -= left;
	*ppos += *lenp;
	return 0;
#undef TMPBUFLEN
}

static int do_proc_doulongvec_minmax(struct ctl_table *table, int write,
				     struct file *filp,
			val = convdiv * (*i) / convmul;
			if (!first) {
				err = proc_put_char(&buffer, &left, '\t');
				if (err)
					break;
			}
			err = proc_put_long(&buffer, &left, val, false);
			if (err)
				break;
		}
	}

	if (!write && !first && left && !err)
		err = proc_put_char(&buffer, &left, '\n');
	if (write && !err)
		left -= proc_skip_spaces(&p);
	if (write) {
		kfree(kbuf);
		if (first)
			return err ? : -EINVAL;
	}
	*lenp -= left;
out:
	*ppos += *lenp;
	return err;
}

static int do_proc_doulongvec_minmax(struct ctl_table *table, int write,
				     void __user *buffer,
				     size_t *lenp, loff_t *ppos,
				     unsigned long convmul,
				     unsigned long convdiv)
{
	return __do_proc_doulongvec_minmax(table->data, table, write,
			filp, buffer, lenp, ppos, convmul, convdiv);
			buffer, lenp, ppos, convmul, convdiv);
}

/**
 * proc_doulongvec_minmax - read a vector of long integers with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned long) unsigned long
 * values from/to the user buffer, treated as an ASCII string.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success.
 */
int proc_doulongvec_minmax(struct ctl_table *table, int write, struct file *filp,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, filp, buffer, lenp, ppos, 1l, 1l);
int proc_doulongvec_minmax(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, buffer, lenp, ppos, 1l, 1l);
}

/**
 * proc_doulongvec_ms_jiffies_minmax - read a vector of millisecond values with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned long) unsigned long
 * values from/to the user buffer, treated as an ASCII string. The values
 * are treated as milliseconds, and converted to jiffies when they are stored.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success.
 */
int proc_doulongvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				      struct file *filp,
				      void __user *buffer,
				      size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, filp, buffer,
				      void __user *buffer,
				      size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, buffer,
				     lenp, ppos, HZ, 1000l);
}


static int do_proc_dointvec_jiffies_conv(int *negp, unsigned long *lvalp,
static int do_proc_dointvec_jiffies_conv(bool *negp, unsigned long *lvalp,
					 int *valp,
					 int write, void *data)
{
	if (write) {
		if (*lvalp > INT_MAX / HZ)
			return 1;
		*valp = *negp ? -(*lvalp*HZ) : (*lvalp*HZ);
	} else {
		int val = *valp;
		unsigned long lval;
		if (val < 0) {
			*negp = -1;
			lval = (unsigned long)-val;
		} else {
			*negp = 0;
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = lval / HZ;
	}
	return 0;
}

static int do_proc_dointvec_userhz_jiffies_conv(int *negp, unsigned long *lvalp,
static int do_proc_dointvec_userhz_jiffies_conv(bool *negp, unsigned long *lvalp,
						int *valp,
						int write, void *data)
{
	if (write) {
		if (USER_HZ < HZ && *lvalp > (LONG_MAX / HZ) * USER_HZ)
			return 1;
		*valp = clock_t_to_jiffies(*negp ? -*lvalp : *lvalp);
	} else {
		int val = *valp;
		unsigned long lval;
		if (val < 0) {
			*negp = -1;
			lval = (unsigned long)-val;
		} else {
			*negp = 0;
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = jiffies_to_clock_t(lval);
	}
	return 0;
}

static int do_proc_dointvec_ms_jiffies_conv(int *negp, unsigned long *lvalp,
static int do_proc_dointvec_ms_jiffies_conv(bool *negp, unsigned long *lvalp,
					    int *valp,
					    int write, void *data)
{
	if (write) {
		*valp = msecs_to_jiffies(*negp ? -*lvalp : *lvalp);
		unsigned long jif = msecs_to_jiffies(*negp ? -*lvalp : *lvalp);

		if (jif > INT_MAX)
			return 1;
		*valp = (int)jif;
	} else {
		int val = *valp;
		unsigned long lval;
		if (val < 0) {
			*negp = -1;
			lval = (unsigned long)-val;
		} else {
			*negp = 0;
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = jiffies_to_msecs(lval);
	}
	return 0;
}

/**
 * proc_dointvec_jiffies - read a vector of integers as seconds
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string. 
 * The values read are assumed to be in seconds, and are converted into
 * jiffies.
 *
 * Returns 0 on success.
 */
int proc_dointvec_jiffies(struct ctl_table *table, int write, struct file *filp,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,filp,buffer,lenp,ppos,
int proc_dointvec_jiffies(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,buffer,lenp,ppos,
		    	    do_proc_dointvec_jiffies_conv,NULL);
}

/**
 * proc_dointvec_userhz_jiffies - read a vector of integers as 1/USER_HZ seconds
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: pointer to the file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string. 
 * The values read are assumed to be in 1/USER_HZ seconds, and 
 * are converted into jiffies.
 *
 * Returns 0 on success.
 */
int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write, struct file *filp,
				 void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,filp,buffer,lenp,ppos,
int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write,
				 void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,buffer,lenp,ppos,
		    	    do_proc_dointvec_userhz_jiffies_conv,NULL);
}

/**
 * proc_dointvec_ms_jiffies - read a vector of integers as 1 milliseconds
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 * @ppos: the current position in the file
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string. 
 * The values read are assumed to be in 1/1000 seconds, and 
 * are converted into jiffies.
 *
 * Returns 0 on success.
 */
int proc_dointvec_ms_jiffies(struct ctl_table *table, int write, struct file *filp,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, filp, buffer, lenp, ppos,
				do_proc_dointvec_ms_jiffies_conv, NULL);
}

static int proc_do_cad_pid(struct ctl_table *table, int write, struct file *filp,
int proc_dointvec_ms_jiffies(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_ms_jiffies_conv, NULL);
}

static int proc_do_cad_pid(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct pid *new_pid;
	pid_t tmp;
	int r;

	tmp = pid_vnr(cad_pid);

	r = __do_proc_dointvec(&tmp, table, write, filp, buffer,
	r = __do_proc_dointvec(&tmp, table, write, buffer,
			       lenp, ppos, NULL, NULL);
	if (r || !write)
		return r;

	new_pid = find_get_pid(tmp);
	if (!new_pid)
		return -ESRCH;

	put_pid(xchg(&cad_pid, new_pid));
	return 0;
}

#else /* CONFIG_PROC_FS */

int proc_dostring(struct ctl_table *table, int write, struct file *filp,
/**
 * proc_do_large_bitmap - read/write from/to a large bitmap
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * The bitmap is stored at table->data and the bitmap length (in bits)
 * in table->maxlen.
 *
 * We use a range comma separated format (e.g. 1,3-4,10-10) so that
 * large bitmaps may be represented in a compact manner. Writing into
 * the file will clear the bitmap then update it with the given input.
 *
 * Returns 0 on success.
 */
int proc_do_large_bitmap(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err = 0;
	bool first = 1;
	size_t left = *lenp;
	unsigned long bitmap_len = table->maxlen;
	unsigned long *bitmap = *(unsigned long **) table->data;
	unsigned long *tmp_bitmap = NULL;
	char tr_a[] = { '-', ',', '\n' }, tr_b[] = { ',', '\n', 0 }, c;

	if (!bitmap || !bitmap_len || !left || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *kbuf, *p;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;

		p = kbuf = memdup_user_nul(buffer, left);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);

		tmp_bitmap = kzalloc(BITS_TO_LONGS(bitmap_len) * sizeof(unsigned long),
				     GFP_KERNEL);
		if (!tmp_bitmap) {
			kfree(kbuf);
			return -ENOMEM;
		}
		proc_skip_char(&p, &left, '\n');
		while (!err && left) {
			unsigned long val_a, val_b;
			bool neg;

			err = proc_get_long(&p, &left, &val_a, &neg, tr_a,
					     sizeof(tr_a), &c);
			if (err)
				break;
			if (val_a >= bitmap_len || neg) {
				err = -EINVAL;
				break;
			}

			val_b = val_a;
			if (left) {
				p++;
				left--;
			}

			if (c == '-') {
				err = proc_get_long(&p, &left, &val_b,
						     &neg, tr_b, sizeof(tr_b),
						     &c);
				if (err)
					break;
				if (val_b >= bitmap_len || neg ||
				    val_a > val_b) {
					err = -EINVAL;
					break;
				}
				if (left) {
					p++;
					left--;
				}
			}

			bitmap_set(tmp_bitmap, val_a, val_b - val_a + 1);
			first = 0;
			proc_skip_char(&p, &left, '\n');
		}
		kfree(kbuf);
	} else {
		unsigned long bit_a, bit_b = 0;

		while (left) {
			bit_a = find_next_bit(bitmap, bitmap_len, bit_b);
			if (bit_a >= bitmap_len)
				break;
			bit_b = find_next_zero_bit(bitmap, bitmap_len,
						   bit_a + 1) - 1;

			if (!first) {
				err = proc_put_char(&buffer, &left, ',');
				if (err)
					break;
			}
			err = proc_put_long(&buffer, &left, bit_a, false);
			if (err)
				break;
			if (bit_a != bit_b) {
				err = proc_put_char(&buffer, &left, '-');
				if (err)
					break;
				err = proc_put_long(&buffer, &left, bit_b, false);
				if (err)
					break;
			}

			first = 0; bit_b++;
		}
		if (!err)
			err = proc_put_char(&buffer, &left, '\n');
	}

	if (!err) {
		if (write) {
			if (*ppos)
				bitmap_or(bitmap, bitmap, tmp_bitmap, bitmap_len);
			else
				bitmap_copy(bitmap, tmp_bitmap, bitmap_len);
		}
		kfree(tmp_bitmap);
		*lenp -= left;
		*ppos += *lenp;
		return 0;
	} else {
		kfree(tmp_bitmap);
		return err;
	}
}

#else /* CONFIG_PROC_SYSCTL */

int proc_dostring(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec(struct ctl_table *table, int write, struct file *filp,
int proc_dointvec(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_minmax(struct ctl_table *table, int write, struct file *filp,
int proc_douintvec(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_minmax(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_jiffies(struct ctl_table *table, int write, struct file *filp,
int proc_douintvec_minmax(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_jiffies(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write, struct file *filp,
int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_ms_jiffies(struct ctl_table *table, int write, struct file *filp,
int proc_dointvec_ms_jiffies(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_doulongvec_minmax(struct ctl_table *table, int write, struct file *filp,
int proc_doulongvec_minmax(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_doulongvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				      struct file *filp,
				      void __user *buffer,
				      size_t *lenp, loff_t *ppos)
{
    return -ENOSYS;
}


#endif /* CONFIG_PROC_FS */


#ifdef CONFIG_SYSCTL_SYSCALL
/*
 * General sysctl support routines 
 */

/* The generic sysctl data routine (used if no strategy routine supplied) */
int sysctl_data(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{
	size_t len;

	/* Get out of I don't have a variable */
	if (!table->data || !table->maxlen)
		return -ENOTDIR;

	if (oldval && oldlenp) {
		if (get_user(len, oldlenp))
			return -EFAULT;
		if (len) {
			if (len > table->maxlen)
				len = table->maxlen;
			if (copy_to_user(oldval, table->data, len))
				return -EFAULT;
			if (put_user(len, oldlenp))
				return -EFAULT;
		}
	}

	if (newval && newlen) {
		if (newlen > table->maxlen)
			newlen = table->maxlen;

		if (copy_from_user(table->data, newval, newlen))
			return -EFAULT;
	}
	return 1;
}

/* The generic string strategy routine: */
int sysctl_string(struct ctl_table *table, int __user *name, int nlen,
		  void __user *oldval, size_t __user *oldlenp,
		  void __user *newval, size_t newlen)
{
	if (!table->data || !table->maxlen) 
		return -ENOTDIR;
	
	if (oldval && oldlenp) {
		size_t bufsize;
		if (get_user(bufsize, oldlenp))
			return -EFAULT;
		if (bufsize) {
			size_t len = strlen(table->data), copied;

			/* This shouldn't trigger for a well-formed sysctl */
			if (len > table->maxlen)
				len = table->maxlen;

			/* Copy up to a max of bufsize-1 bytes of the string */
			copied = (len >= bufsize) ? bufsize - 1 : len;

			if (copy_to_user(oldval, table->data, copied) ||
			    put_user(0, (char __user *)(oldval + copied)))
				return -EFAULT;
			if (put_user(len, oldlenp))
				return -EFAULT;
		}
	}
	if (newval && newlen) {
		size_t len = newlen;
		if (len > table->maxlen)
			len = table->maxlen;
		if(copy_from_user(table->data, newval, len))
			return -EFAULT;
		if (len == table->maxlen)
			len--;
		((char *) table->data)[len] = 0;
	}
	return 1;
}

/*
 * This function makes sure that all of the integers in the vector
 * are between the minimum and maximum values given in the arrays
 * table->extra1 and table->extra2, respectively.
 */
int sysctl_intvec(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{

	if (newval && newlen) {
		int __user *vec = (int __user *) newval;
		int *min = (int *) table->extra1;
		int *max = (int *) table->extra2;
		size_t length;
		int i;

		if (newlen % sizeof(int) != 0)
			return -EINVAL;

		if (!table->extra1 && !table->extra2)
			return 0;

		if (newlen > table->maxlen)
			newlen = table->maxlen;
		length = newlen / sizeof(int);

		for (i = 0; i < length; i++) {
			int value;
			if (get_user(value, vec + i))
				return -EFAULT;
			if (min && value < min[i])
				return -EINVAL;
			if (max && value > max[i])
				return -EINVAL;
		}
	}
	return 0;
}

/* Strategy function to convert jiffies to seconds */ 
int sysctl_jiffies(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{
	if (oldval && oldlenp) {
		size_t olen;

		if (get_user(olen, oldlenp))
			return -EFAULT;
		if (olen) {
			int val;

			if (olen < sizeof(int))
				return -EINVAL;

			val = *(int *)(table->data) / HZ;
			if (put_user(val, (int __user *)oldval))
				return -EFAULT;
			if (put_user(sizeof(int), oldlenp))
				return -EFAULT;
		}
	}
	if (newval && newlen) { 
		int new;
		if (newlen != sizeof(int))
			return -EINVAL; 
		if (get_user(new, (int __user *)newval))
			return -EFAULT;
		*(int *)(table->data) = new*HZ; 
	}
	return 1;
}

/* Strategy function to convert jiffies to seconds */ 
int sysctl_ms_jiffies(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{
	if (oldval && oldlenp) {
		size_t olen;

		if (get_user(olen, oldlenp))
			return -EFAULT;
		if (olen) {
			int val;

			if (olen < sizeof(int))
				return -EINVAL;

			val = jiffies_to_msecs(*(int *)(table->data));
			if (put_user(val, (int __user *)oldval))
				return -EFAULT;
			if (put_user(sizeof(int), oldlenp))
				return -EFAULT;
		}
	}
	if (newval && newlen) { 
		int new;
		if (newlen != sizeof(int))
			return -EINVAL; 
		if (get_user(new, (int __user *)newval))
			return -EFAULT;
		*(int *)(table->data) = msecs_to_jiffies(new);
	}
	return 1;
}



#else /* CONFIG_SYSCTL_SYSCALL */


asmlinkage long sys_sysctl(struct __sysctl_args __user *args)
{
	struct __sysctl_args tmp;
	int error;

	if (copy_from_user(&tmp, args, sizeof(tmp)))
		return -EFAULT;

	error = deprecated_sysctl_warning(&tmp);

	/* If no error reading the parameters then just -ENOSYS ... */
	if (!error)
		error = -ENOSYS;

	return error;
}

int sysctl_data(struct ctl_table *table, int __user *name, int nlen,
		  void __user *oldval, size_t __user *oldlenp,
		  void __user *newval, size_t newlen)
{
	return -ENOSYS;
}

int sysctl_string(struct ctl_table *table, int __user *name, int nlen,
		  void __user *oldval, size_t __user *oldlenp,
		  void __user *newval, size_t newlen)
{
	return -ENOSYS;
}

int sysctl_intvec(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{
	return -ENOSYS;
}

int sysctl_jiffies(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{
	return -ENOSYS;
}

int sysctl_ms_jiffies(struct ctl_table *table, int __user *name, int nlen,
		void __user *oldval, size_t __user *oldlenp,
		void __user *newval, size_t newlen)
{
	return -ENOSYS;
}

#endif /* CONFIG_SYSCTL_SYSCALL */

static int deprecated_sysctl_warning(struct __sysctl_args *args)
{
	static int msg_count;
	int name[CTL_MAXNAME];
	int i;

	/* Check args->nlen. */
	if (args->nlen < 0 || args->nlen > CTL_MAXNAME)
		return -ENOTDIR;

	/* Read in the sysctl name for better debug message logging */
	for (i = 0; i < args->nlen; i++)
		if (get_user(name[i], args->name + i))
			return -EFAULT;

	/* Ignore accesses to kernel.version */
	if ((args->nlen == 2) && (name[0] == CTL_KERN) && (name[1] == KERN_VERSION))
		return 0;

	if (msg_count < 5) {
		msg_count++;
		printk(KERN_INFO
			"warning: process `%s' used the deprecated sysctl "
			"system call with ", current->comm);
		for (i = 0; i < args->nlen; i++)
			printk("%d.", name[i]);
		printk("\n");
	}
	return 0;
}
#endif /* CONFIG_PROC_SYSCTL */

/*
 * No sense putting this after each symbol definition, twice,
 * exception granted :-)
 */
EXPORT_SYMBOL(proc_dointvec);
EXPORT_SYMBOL(proc_douintvec);
EXPORT_SYMBOL(proc_dointvec_jiffies);
EXPORT_SYMBOL(proc_dointvec_minmax);
EXPORT_SYMBOL_GPL(proc_douintvec_minmax);
EXPORT_SYMBOL(proc_dointvec_userhz_jiffies);
EXPORT_SYMBOL(proc_dointvec_ms_jiffies);
EXPORT_SYMBOL(proc_dostring);
EXPORT_SYMBOL(proc_doulongvec_minmax);
EXPORT_SYMBOL(proc_doulongvec_ms_jiffies_minmax);
EXPORT_SYMBOL(register_sysctl_table);
EXPORT_SYMBOL(register_sysctl_paths);
EXPORT_SYMBOL(sysctl_intvec);
EXPORT_SYMBOL(sysctl_jiffies);
EXPORT_SYMBOL(sysctl_ms_jiffies);
EXPORT_SYMBOL(sysctl_string);
EXPORT_SYMBOL(sysctl_data);
EXPORT_SYMBOL(unregister_sysctl_table);
