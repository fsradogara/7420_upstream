// SPDX-License-Identifier: GPL-2.0
/*
 *  arch/s390/kernel/compat_signal.c
 *
 *    Copyright (C) IBM Corp. 2000,2006
 *    Copyright IBM Corp. 2000, 2006
 *    Author(s): Denis Joseph Barrow (djbarrow@de.ibm.com,barrow_dj@yahoo.com)
 *               Gerhard Tonn (ton@de.ibm.com)                  
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-11-28  Modified for POSIX.1b signals by Richard Henderson
 */

#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/tty.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <asm/ucontext.h>
#include <linux/uaccess.h>
#include <asm/lowcore.h>
#include <asm/switch_to.h>
#include "compat_linux.h"
#include "compat_ptrace.h"
#include "entry.h"

#define _BLOCKABLE (~(sigmask(SIGKILL) | sigmask(SIGSTOP)))

typedef struct 
{
	__u8 callee_used_stack[__SIGNAL_FRAMESIZE32];
	struct sigcontext32 sc;
	_sigregs32 sregs;
	int signo;
	__u8 retcode[S390_SYSCALL_SIZE];
	_sigregs_ext32 sregs_ext;
	__u16 svc_insn;		/* Offset of svc_insn is NOT fixed! */
} sigframe32;

typedef struct 
{
	__u8 callee_used_stack[__SIGNAL_FRAMESIZE32];
	__u8 retcode[S390_SYSCALL_SIZE];
	__u16 svc_insn;
	compat_siginfo_t info;
	struct ucontext32 uc;
} rt_sigframe32;

int copy_siginfo_to_user32(compat_siginfo_t __user *to, siginfo_t *from)
{
	int err;

	if (!access_ok (VERIFY_WRITE, to, sizeof(compat_siginfo_t)))
		return -EFAULT;

static inline void sigset_to_sigset32(unsigned long *set64,
				      compat_sigset_word *set32)
{
	set32[0] = (compat_sigset_word) set64[0];
	set32[1] = (compat_sigset_word)(set64[0] >> 32);
}

static inline void sigset32_to_sigset(compat_sigset_word *set32,
				      unsigned long *set64)
{
	set64[0] = (unsigned long) set32[0] | ((unsigned long) set32[1] << 32);
}

int copy_siginfo_to_user32(compat_siginfo_t __user *to, const siginfo_t *from)
{
	int err;

	/* If you change siginfo_t structure, please be sure
	   this code is fixed accordingly.
	   It should never copy any pad contained in the structure
	   to avoid security leaks, but must copy the generic
	   3 ints plus the relevant union member.  
	   This routine must convert siginfo from 64bit to 32bit as well
	   at the same time.  */
	err = __put_user(from->si_signo, &to->si_signo);
	err |= __put_user(from->si_errno, &to->si_errno);
	err |= __put_user(from->si_code, &to->si_code);
	if (from->si_code < 0)
		err |= __copy_to_user(&to->_sifields._pad, &from->_sifields._pad, SI_PAD_SIZE);
	else {
		switch (siginfo_layout(from->si_signo, from->si_code)) {
		case SIL_RT:
			err |= __put_user(from->si_int, &to->si_int);
			/* fallthrough */
		case SIL_KILL:
			err |= __put_user(from->si_pid, &to->si_pid);
			err |= __put_user(from->si_uid, &to->si_uid);
			break;
		case SIL_CHLD:
			err |= __put_user(from->si_pid, &to->si_pid);
			err |= __put_user(from->si_uid, &to->si_uid);
			err |= __put_user(from->si_utime, &to->si_utime);
			err |= __put_user(from->si_stime, &to->si_stime);
			err |= __put_user(from->si_status, &to->si_status);
			break;
		case SIL_FAULT:
			err |= __put_user((unsigned long) from->si_addr,
					  &to->si_addr);
			break;
		case SIL_POLL:
			err |= __put_user(from->si_band, &to->si_band);
			err |= __put_user(from->si_fd, &to->si_fd);
			break;
		case SIL_TIMER:
			err |= __put_user(from->si_tid, &to->si_tid);
			err |= __put_user(from->si_overrun, &to->si_overrun);
			err |= __put_user(from->si_int, &to->si_int);
			break;
		default:
			break;
		}
	}
	return err;
	return err ? -EFAULT : 0;
}

int copy_siginfo_from_user32(siginfo_t *to, compat_siginfo_t __user *from)
{
	int err;
	u32 tmp;

	if (!access_ok (VERIFY_READ, from, sizeof(compat_siginfo_t)))
		return -EFAULT;

	err = __get_user(to->si_signo, &from->si_signo);
	err |= __get_user(to->si_errno, &from->si_errno);
	err |= __get_user(to->si_code, &from->si_code);

	if (to->si_code < 0)
		err |= __copy_from_user(&to->_sifields._pad, &from->_sifields._pad, SI_PAD_SIZE);
	else {
		switch (siginfo_layout(to->si_signo, to->si_code)) {
		case SIL_RT:
			err |= __get_user(to->si_int, &from->si_int);
			/* fallthrough */
		case SIL_KILL:
			err |= __get_user(to->si_pid, &from->si_pid);
			err |= __get_user(to->si_uid, &from->si_uid);
			break;
		case SIL_CHLD:
			err |= __get_user(to->si_pid, &from->si_pid);
			err |= __get_user(to->si_uid, &from->si_uid);
			err |= __get_user(to->si_utime, &from->si_utime);
			err |= __get_user(to->si_stime, &from->si_stime);
			err |= __get_user(to->si_status, &from->si_status);
			break;
		case SIL_FAULT:
			err |= __get_user(tmp, &from->si_addr);
			to->si_addr = (void __user *)(u64) (tmp & PSW32_ADDR_INSN);
			to->si_addr = (void __force __user *)
				(u64) (tmp & PSW32_ADDR_INSN);
			break;
		case SIL_POLL:
			err |= __get_user(to->si_band, &from->si_band);
			err |= __get_user(to->si_fd, &from->si_fd);
			break;
		case SIL_TIMER:
			err |= __get_user(to->si_tid, &from->si_tid);
			err |= __get_user(to->si_overrun, &from->si_overrun);
			err |= __get_user(to->si_int, &from->si_int);
			break;
		default:
			break;
		}
	}
	return err;
}

asmlinkage long
sys32_sigaction(int sig, const struct old_sigaction32 __user *act,
		 struct old_sigaction32 __user *oact)
{
        struct k_sigaction new_ka, old_ka;
	unsigned long sa_handler, sa_restorer;
        int ret;

        if (act) {
		compat_old_sigset_t mask;
		if (!access_ok(VERIFY_READ, act, sizeof(*act)) ||
		    __get_user(sa_handler, &act->sa_handler) ||
		    __get_user(sa_restorer, &act->sa_restorer) ||
		    __get_user(new_ka.sa.sa_flags, &act->sa_flags) ||
		    __get_user(mask, &act->sa_mask))
			return -EFAULT;
		new_ka.sa.sa_handler = (__sighandler_t) sa_handler;
		new_ka.sa.sa_restorer = (void (*)(void)) sa_restorer;
		siginitset(&new_ka.sa.sa_mask, mask);
        }

        ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		sa_handler = (unsigned long) old_ka.sa.sa_handler;
		sa_restorer = (unsigned long) old_ka.sa.sa_restorer;
		if (!access_ok(VERIFY_WRITE, oact, sizeof(*oact)) ||
		    __put_user(sa_handler, &oact->sa_handler) ||
		    __put_user(sa_restorer, &oact->sa_restorer) ||
		    __put_user(old_ka.sa.sa_flags, &oact->sa_flags) ||
		    __put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask))
			return -EFAULT;
        }

	return ret;
}

asmlinkage long
sys32_rt_sigaction(int sig, const struct sigaction32 __user *act,
	   struct sigaction32 __user *oact,  size_t sigsetsize)
{
	struct k_sigaction new_ka, old_ka;
	unsigned long sa_handler;
	int ret;
	compat_sigset_t set32;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(compat_sigset_t))
		return -EINVAL;

	if (act) {
		ret = get_user(sa_handler, &act->sa_handler);
		ret |= __copy_from_user(&set32, &act->sa_mask,
					sizeof(compat_sigset_t));
		switch (_NSIG_WORDS) {
		case 4: new_ka.sa.sa_mask.sig[3] = set32.sig[6]
				| (((long)set32.sig[7]) << 32);
		case 3: new_ka.sa.sa_mask.sig[2] = set32.sig[4]
				| (((long)set32.sig[5]) << 32);
		case 2: new_ka.sa.sa_mask.sig[1] = set32.sig[2]
				| (((long)set32.sig[3]) << 32);
		case 1: new_ka.sa.sa_mask.sig[0] = set32.sig[0]
				| (((long)set32.sig[1]) << 32);
		}
		ret |= __get_user(new_ka.sa.sa_flags, &act->sa_flags);
		
		if (ret)
			return -EFAULT;
		new_ka.sa.sa_handler = (__sighandler_t) sa_handler;
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		switch (_NSIG_WORDS) {
		case 4:
			set32.sig[7] = (old_ka.sa.sa_mask.sig[3] >> 32);
			set32.sig[6] = old_ka.sa.sa_mask.sig[3];
		case 3:
			set32.sig[5] = (old_ka.sa.sa_mask.sig[2] >> 32);
			set32.sig[4] = old_ka.sa.sa_mask.sig[2];
		case 2:
			set32.sig[3] = (old_ka.sa.sa_mask.sig[1] >> 32);
			set32.sig[2] = old_ka.sa.sa_mask.sig[1];
		case 1:
			set32.sig[1] = (old_ka.sa.sa_mask.sig[0] >> 32);
			set32.sig[0] = old_ka.sa.sa_mask.sig[0];
		}
		ret = put_user((unsigned long)old_ka.sa.sa_handler, &oact->sa_handler);
		ret |= __copy_to_user(&oact->sa_mask, &set32,
				      sizeof(compat_sigset_t));
		ret |= __put_user(old_ka.sa.sa_flags, &oact->sa_flags);
	}

	return ret;
}

asmlinkage long
sys32_sigaltstack(const stack_t32 __user *uss, stack_t32 __user *uoss)
{
	struct pt_regs *regs = task_pt_regs(current);
	stack_t kss, koss;
	unsigned long ss_sp;
	int ret, err = 0;
	mm_segment_t old_fs = get_fs();

	if (uss) {
		if (!access_ok(VERIFY_READ, uss, sizeof(*uss)))
			return -EFAULT;
		err |= __get_user(ss_sp, &uss->ss_sp);
		err |= __get_user(kss.ss_size, &uss->ss_size);
		err |= __get_user(kss.ss_flags, &uss->ss_flags);
		if (err)
			return -EFAULT;
		kss.ss_sp = (void __user *) ss_sp;
	}

	set_fs (KERNEL_DS);
	ret = do_sigaltstack((stack_t __force __user *) (uss ? &kss : NULL),
			     (stack_t __force __user *) (uoss ? &koss : NULL),
			     regs->gprs[15]);
	set_fs (old_fs);

	if (!ret && uoss) {
		if (!access_ok(VERIFY_WRITE, uoss, sizeof(*uoss)))
			return -EFAULT;
		ss_sp = (unsigned long) koss.ss_sp;
		err |= __put_user(ss_sp, &uoss->ss_sp);
		err |= __put_user(koss.ss_size, &uoss->ss_size);
		err |= __put_user(koss.ss_flags, &uoss->ss_flags);
		if (err)
			return -EFAULT;
	}
	return ret;
	return err ? -EFAULT : 0;
}

/* Store registers needed to create the signal frame */
static void store_sigregs(void)
{
	save_access_regs(current->thread.acrs);
	save_fpu_regs();
}

/* Load registers after signal return */
static void load_sigregs(void)
{
	restore_access_regs(current->thread.acrs);
}

static int save_sigregs32(struct pt_regs *regs, _sigregs32 __user *sregs)
{
	_s390_regs_common32 regs32;
	int err, i;

	regs32.psw.mask = PSW32_MASK_MERGE(psw32_user_bits,
					   (__u32)(regs->psw.mask >> 32));
	regs32.psw.addr = PSW32_ADDR_AMODE31 | (__u32) regs->psw.addr;
	for (i = 0; i < NUM_GPRS; i++)
		regs32.gprs[i] = (__u32) regs->gprs[i];
	save_access_regs(current->thread.acrs);
	memcpy(regs32.acrs, current->thread.acrs, sizeof(regs32.acrs));
	err = __copy_to_user(&sregs->regs, &regs32, sizeof(regs32));
	if (err)
		return err;
	save_fp_regs(&current->thread.fp_regs);
	/* s390_fp_regs and _s390_fp_regs32 are the same ! */
	return __copy_to_user(&sregs->fpregs, &current->thread.fp_regs,
			      sizeof(_s390_fp_regs32));
	_sigregs32 user_sregs;
	int i;

	user_sregs.regs.psw.mask = (__u32)(regs->psw.mask >> 32);
	user_sregs.regs.psw.mask &= PSW32_MASK_USER | PSW32_MASK_RI;
	user_sregs.regs.psw.mask |= PSW32_USER_BITS;
	user_sregs.regs.psw.addr = (__u32) regs->psw.addr |
		(__u32)(regs->psw.mask & PSW_MASK_BA);
	for (i = 0; i < NUM_GPRS; i++)
		user_sregs.regs.gprs[i] = (__u32) regs->gprs[i];
	memcpy(&user_sregs.regs.acrs, current->thread.acrs,
	       sizeof(user_sregs.regs.acrs));
	fpregs_store((_s390_fp_regs *) &user_sregs.fpregs, &current->thread.fpu);
	if (__copy_to_user(sregs, &user_sregs, sizeof(_sigregs32)))
		return -EFAULT;
	return 0;
}

static int restore_sigregs32(struct pt_regs *regs,_sigregs32 __user *sregs)
{
	_s390_regs_common32 regs32;
	int err, i;

	/* Alwys make any pending restarted system call return -EINTR */
	current_thread_info()->restart_block.fn = do_no_restart_syscall;

	err = __copy_from_user(&regs32, &sregs->regs, sizeof(regs32));
	if (err)
		return err;
	regs->psw.mask = PSW_MASK_MERGE(regs->psw.mask,
				        (__u64)regs32.psw.mask << 32);
	regs->psw.addr = (__u64)(regs32.psw.addr & PSW32_ADDR_INSN);
	for (i = 0; i < NUM_GPRS; i++)
		regs->gprs[i] = (__u64) regs32.gprs[i];
	memcpy(current->thread.acrs, regs32.acrs, sizeof(current->thread.acrs));
	restore_access_regs(current->thread.acrs);

	err = __copy_from_user(&current->thread.fp_regs, &sregs->fpregs,
			       sizeof(_s390_fp_regs32));
	current->thread.fp_regs.fpc &= FPC_VALID_MASK;
	if (err)
		return err;

	restore_fp_regs(&current->thread.fp_regs);
	regs->trap = -1;	/* disable syscall checks */
	return 0;
}

asmlinkage long sys32_sigreturn(void)
{
	struct pt_regs *regs = task_pt_regs(current);
	sigframe32 __user *frame = (sigframe32 __user *)regs->gprs[15];
	sigset_t set;

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__copy_from_user(&set.sig, &frame->sc.oldmask, _SIGMASK_COPY_SIZE32))
		goto badframe;

	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	if (restore_sigregs32(regs, &frame->sregs))
		goto badframe;

	return regs->gprs[2];

	_sigregs32 user_sregs;
	int i;

	/* Alwys make any pending restarted system call return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	if (__copy_from_user(&user_sregs, &sregs->regs, sizeof(user_sregs)))
		return -EFAULT;

	if (!is_ri_task(current) && (user_sregs.regs.psw.mask & PSW32_MASK_RI))
		return -EINVAL;

	/* Test the floating-point-control word. */
	if (test_fp_ctl(user_sregs.fpregs.fpc))
		return -EINVAL;

	/* Use regs->psw.mask instead of PSW_USER_BITS to preserve PER bit. */
	regs->psw.mask = (regs->psw.mask & ~(PSW_MASK_USER | PSW_MASK_RI)) |
		(__u64)(user_sregs.regs.psw.mask & PSW32_MASK_USER) << 32 |
		(__u64)(user_sregs.regs.psw.mask & PSW32_MASK_RI) << 32 |
		(__u64)(user_sregs.regs.psw.addr & PSW32_ADDR_AMODE);
	/* Check for invalid user address space control. */
	if ((regs->psw.mask & PSW_MASK_ASC) == PSW_ASC_HOME)
		regs->psw.mask = PSW_ASC_PRIMARY |
			(regs->psw.mask & ~PSW_MASK_ASC);
	regs->psw.addr = (__u64)(user_sregs.regs.psw.addr & PSW32_ADDR_INSN);
	for (i = 0; i < NUM_GPRS; i++)
		regs->gprs[i] = (__u64) user_sregs.regs.gprs[i];
	memcpy(&current->thread.acrs, &user_sregs.regs.acrs,
	       sizeof(current->thread.acrs));
	fpregs_load((_s390_fp_regs *) &user_sregs.fpregs, &current->thread.fpu);

	clear_pt_regs_flag(regs, PIF_SYSCALL); /* No longer in a system call */
	return 0;
}

static int save_sigregs_ext32(struct pt_regs *regs,
			      _sigregs_ext32 __user *sregs_ext)
{
	__u32 gprs_high[NUM_GPRS];
	__u64 vxrs[__NUM_VXRS_LOW];
	int i;

	/* Save high gprs to signal stack */
	for (i = 0; i < NUM_GPRS; i++)
		gprs_high[i] = regs->gprs[i] >> 32;
	if (__copy_to_user(&sregs_ext->gprs_high, &gprs_high,
			   sizeof(sregs_ext->gprs_high)))
		return -EFAULT;

	/* Save vector registers to signal stack */
	if (MACHINE_HAS_VX) {
		for (i = 0; i < __NUM_VXRS_LOW; i++)
			vxrs[i] = *((__u64 *)(current->thread.fpu.vxrs + i) + 1);
		if (__copy_to_user(&sregs_ext->vxrs_low, vxrs,
				   sizeof(sregs_ext->vxrs_low)) ||
		    __copy_to_user(&sregs_ext->vxrs_high,
				   current->thread.fpu.vxrs + __NUM_VXRS_LOW,
				   sizeof(sregs_ext->vxrs_high)))
			return -EFAULT;
	}
	return 0;
}

static int restore_sigregs_ext32(struct pt_regs *regs,
				 _sigregs_ext32 __user *sregs_ext)
{
	__u32 gprs_high[NUM_GPRS];
	__u64 vxrs[__NUM_VXRS_LOW];
	int i;

	/* Restore high gprs from signal stack */
	if (__copy_from_user(&gprs_high, &sregs_ext->gprs_high,
			     sizeof(sregs_ext->gprs_high)))
		return -EFAULT;
	for (i = 0; i < NUM_GPRS; i++)
		*(__u32 *)&regs->gprs[i] = gprs_high[i];

	/* Restore vector registers from signal stack */
	if (MACHINE_HAS_VX) {
		if (__copy_from_user(vxrs, &sregs_ext->vxrs_low,
				     sizeof(sregs_ext->vxrs_low)) ||
		    __copy_from_user(current->thread.fpu.vxrs + __NUM_VXRS_LOW,
				     &sregs_ext->vxrs_high,
				     sizeof(sregs_ext->vxrs_high)))
			return -EFAULT;
		for (i = 0; i < __NUM_VXRS_LOW; i++)
			*((__u64 *)(current->thread.fpu.vxrs + i) + 1) = vxrs[i];
	}
	return 0;
}

COMPAT_SYSCALL_DEFINE0(sigreturn)
{
	struct pt_regs *regs = task_pt_regs(current);
	sigframe32 __user *frame = (sigframe32 __user *)regs->gprs[15];
	compat_sigset_t cset;
	sigset_t set;

	if (__copy_from_user(&cset.sig, &frame->sc.oldmask, _SIGMASK_COPY_SIZE32))
		goto badframe;
	sigset32_to_sigset(cset.sig, set.sig);
	set_current_blocked(&set);
	save_fpu_regs();
	if (restore_sigregs32(regs, &frame->sregs))
		goto badframe;
	if (restore_sigregs_ext32(regs, &frame->sregs_ext))
		goto badframe;
	load_sigregs();
	return regs->gprs[2];
badframe:
	force_sig(SIGSEGV, current);
	return 0;
}

asmlinkage long sys32_rt_sigreturn(void)
{
	struct pt_regs *regs = task_pt_regs(current);
	rt_sigframe32 __user *frame = (rt_sigframe32 __user *)regs->gprs[15];
	sigset_t set;
	stack_t st;
	__u32 ss_sp;
	int err;
	mm_segment_t old_fs = get_fs();

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)))
		goto badframe;

	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	if (restore_sigregs32(regs, &frame->uc.uc_mcontext))
		goto badframe;

	err = __get_user(ss_sp, &frame->uc.uc_stack.ss_sp);
	st.ss_sp = compat_ptr(ss_sp);
	err |= __get_user(st.ss_size, &frame->uc.uc_stack.ss_size);
	err |= __get_user(st.ss_flags, &frame->uc.uc_stack.ss_flags);
	if (err)
		goto badframe; 

	set_fs (KERNEL_DS);
	do_sigaltstack((stack_t __force __user *)&st, NULL, regs->gprs[15]);
	set_fs (old_fs);

	return regs->gprs[2];

COMPAT_SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = task_pt_regs(current);
	rt_sigframe32 __user *frame = (rt_sigframe32 __user *)regs->gprs[15];
	compat_sigset_t cset;
	sigset_t set;

	if (__copy_from_user(&cset, &frame->uc.uc_sigmask, sizeof(cset)))
		goto badframe;
	sigset32_to_sigset(cset.sig, set.sig);
	set_current_blocked(&set);
	if (compat_restore_altstack(&frame->uc.uc_stack))
		goto badframe;
	save_fpu_regs();
	if (restore_sigregs32(regs, &frame->uc.uc_mcontext))
		goto badframe;
	if (restore_sigregs_ext32(regs, &frame->uc.uc_mcontext_ext))
		goto badframe;
	load_sigregs();
	return regs->gprs[2];
badframe:
	force_sig(SIGSEGV, current);
	return 0;
}	

/*
 * Set up a signal frame.
 */


/*
 * Determine which stack to use..
 */
static inline void __user *
get_sigframe(struct k_sigaction *ka, struct pt_regs * regs, size_t frame_size)
{
	unsigned long sp;

	/* Default to using normal stack */
	sp = (unsigned long) A(regs->gprs[15]);

	/* Overflow on alternate signal stack gives SIGSEGV. */
	if (on_sig_stack(sp) && !on_sig_stack((sp - frame_size) & -8UL))
		return (void __user *) -1UL;

	/* This is the X/Open sanctioned signal stack switching.  */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (! sas_ss_flags(sp))
			sp = current->sas_ss_sp + current->sas_ss_size;
	}

	/* This is the legacy signal stack switching. */
	else if (!user_mode(regs) &&
		 !(ka->sa.sa_flags & SA_RESTORER) &&
		 ka->sa.sa_restorer) {
		sp = (unsigned long) ka->sa.sa_restorer;
	}

	return (void __user *)((sp - frame_size) & -8ul);
}

static inline int map_signal(int sig)
{
	if (current_thread_info()->exec_domain
	    && current_thread_info()->exec_domain->signal_invmap
	    && sig < 32)
		return current_thread_info()->exec_domain->signal_invmap[sig];
        else
		return sig;
}

static int setup_frame32(int sig, struct k_sigaction *ka,
			sigset_t *set, struct pt_regs * regs)
{
	sigframe32 __user *frame = get_sigframe(ka, regs, sizeof(sigframe32));
	if (!access_ok(VERIFY_WRITE, frame, sizeof(sigframe32)))
		goto give_sigsegv;

	if (frame == (void __user *) -1UL)
		goto give_sigsegv;

	if (__copy_to_user(&frame->sc.oldmask, &set->sig, _SIGMASK_COPY_SIZE32))
		goto give_sigsegv;

	if (save_sigregs32(regs, &frame->sregs))
		goto give_sigsegv;
	if (__put_user((unsigned long) &frame->sregs, &frame->sc.sregs))
		goto give_sigsegv;

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	if (ka->sa.sa_flags & SA_RESTORER) {
		regs->gprs[14] = (__u64) ka->sa.sa_restorer;
	} else {
		regs->gprs[14] = (__u64) frame->retcode;
		if (__put_user(S390_SYSCALL_OPCODE | __NR_sigreturn,
		               (u16 __user *)(frame->retcode)))
			goto give_sigsegv;
        }

	/* Set up backchain. */
	if (__put_user(regs->gprs[15], (unsigned int __user *) frame))
		goto give_sigsegv;

	/* Set up registers for signal handler */
	regs->gprs[15] = (__u64) frame;
	regs->psw.addr = (__u64) ka->sa.sa_handler;

	regs->gprs[2] = map_signal(sig);
	regs->gprs[3] = (__u64) &frame->sc;

	/* We forgot to include these in the sigcontext.
	   To avoid breaking binary compatibility, they are passed as args. */
	regs->gprs[4] = current->thread.trap_no;
	regs->gprs[5] = current->thread.prot_addr;

	/* Place signal number on stack to allow backtrace from handler.  */
	if (__put_user(regs->gprs[2], (int __user *) &frame->signo))
		goto give_sigsegv;
	return 0;

give_sigsegv:
	force_sigsegv(sig, current);
	return -EFAULT;
}

static int setup_rt_frame32(int sig, struct k_sigaction *ka, siginfo_t *info,
			   sigset_t *set, struct pt_regs * regs)
{
	int err = 0;
	rt_sigframe32 __user *frame = get_sigframe(ka, regs, sizeof(rt_sigframe32));
	if (!access_ok(VERIFY_WRITE, frame, sizeof(rt_sigframe32)))
		goto give_sigsegv;

	if (frame == (void __user *) -1UL)
		goto give_sigsegv;

	if (copy_siginfo_to_user32(&frame->info, info))
		goto give_sigsegv;

	/* Create the ucontext.  */
	err |= __put_user(0, &frame->uc.uc_flags);
	err |= __put_user(0, &frame->uc.uc_link);
	err |= __put_user(current->sas_ss_sp, &frame->uc.uc_stack.ss_sp);
	err |= __put_user(sas_ss_flags(regs->gprs[15]),
	                  &frame->uc.uc_stack.ss_flags);
	err |= __put_user(current->sas_ss_size, &frame->uc.uc_stack.ss_size);
	err |= save_sigregs32(regs, &frame->uc.uc_mcontext);
	err |= __copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));
	if (err)
		goto give_sigsegv;

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	if (ka->sa.sa_flags & SA_RESTORER) {
		regs->gprs[14] = (__u64) ka->sa.sa_restorer;
	} else {
		regs->gprs[14] = (__u64) frame->retcode;
		err |= __put_user(S390_SYSCALL_OPCODE | __NR_rt_sigreturn,
		                  (u16 __user *)(frame->retcode));
	}

	/* Set up backchain. */
	if (__put_user(regs->gprs[15], (unsigned int __user *) frame))
		goto give_sigsegv;

	/* Set up registers for signal handler */
	regs->gprs[15] = (__u64) frame;
	regs->psw.addr = (__u64) ka->sa.sa_handler;

	regs->gprs[2] = map_signal(sig);
	regs->gprs[3] = (__u64) &frame->info;
	regs->gprs[4] = (__u64) &frame->uc;
	return 0;

give_sigsegv:
	force_sigsegv(sig, current);
	return -EFAULT;
	return (void __user *)((sp - frame_size) & -8ul);
}

static int setup_frame32(struct ksignal *ksig, sigset_t *set,
			 struct pt_regs *regs)
{
	int sig = ksig->sig;
	sigframe32 __user *frame;
	struct sigcontext32 sc;
	unsigned long restorer;
	size_t frame_size;

	/*
	 * gprs_high are always present for 31-bit compat tasks.
	 * The space for vector registers is only allocated if
	 * the machine supports it
	 */
	frame_size = sizeof(*frame) - sizeof(frame->sregs_ext.__reserved);
	if (!MACHINE_HAS_VX)
		frame_size -= sizeof(frame->sregs_ext.vxrs_low) +
			      sizeof(frame->sregs_ext.vxrs_high);
	frame = get_sigframe(&ksig->ka, regs, frame_size);
	if (frame == (void __user *) -1UL)
		return -EFAULT;

	/* Set up backchain. */
	if (__put_user(regs->gprs[15], (unsigned int __user *) frame))
		return -EFAULT;

	/* Create struct sigcontext32 on the signal stack */
	sigset_to_sigset32(set->sig, sc.oldmask);
	sc.sregs = (__u32)(unsigned long __force) &frame->sregs;
	if (__copy_to_user(&frame->sc, &sc, sizeof(frame->sc)))
		return -EFAULT;

	/* Store registers needed to create the signal frame */
	store_sigregs();

	/* Create _sigregs32 on the signal stack */
	if (save_sigregs32(regs, &frame->sregs))
		return -EFAULT;

	/* Place signal number on stack to allow backtrace from handler.  */
	if (__put_user(regs->gprs[2], (int __force __user *) &frame->signo))
		return -EFAULT;

	/* Create _sigregs_ext32 on the signal stack */
	if (save_sigregs_ext32(regs, &frame->sregs_ext))
		return -EFAULT;

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	if (ksig->ka.sa.sa_flags & SA_RESTORER) {
		restorer = (unsigned long __force)
			ksig->ka.sa.sa_restorer | PSW32_ADDR_AMODE;
	} else {
		/* Signal frames without vectors registers are short ! */
		__u16 __user *svc = (void __user *) frame + frame_size - 2;
		if (__put_user(S390_SYSCALL_OPCODE | __NR_sigreturn, svc))
			return -EFAULT;
		restorer = (unsigned long __force) svc | PSW32_ADDR_AMODE;
        }

	/* Set up registers for signal handler */
	regs->gprs[14] = restorer;
	regs->gprs[15] = (__force __u64) frame;
	/* Force 31 bit amode and default user address space control. */
	regs->psw.mask = PSW_MASK_BA |
		(PSW_USER_BITS & PSW_MASK_ASC) |
		(regs->psw.mask & ~PSW_MASK_ASC);
	regs->psw.addr = (__force __u64) ksig->ka.sa.sa_handler;

	regs->gprs[2] = sig;
	regs->gprs[3] = (__force __u64) &frame->sc;

	/* We forgot to include these in the sigcontext.
	   To avoid breaking binary compatibility, they are passed as args. */
	if (sig == SIGSEGV || sig == SIGBUS || sig == SIGILL ||
	    sig == SIGTRAP || sig == SIGFPE) {
		/* set extra registers only for synchronous signals */
		regs->gprs[4] = regs->int_code & 127;
		regs->gprs[5] = regs->int_parm_long;
		regs->gprs[6] = current->thread.last_break;
	}

	return 0;
}

static int setup_rt_frame32(struct ksignal *ksig, sigset_t *set,
			    struct pt_regs *regs)
{
	compat_sigset_t cset;
	rt_sigframe32 __user *frame;
	unsigned long restorer;
	size_t frame_size;
	u32 uc_flags;

	frame_size = sizeof(*frame) -
		     sizeof(frame->uc.uc_mcontext_ext.__reserved);
	/*
	 * gprs_high are always present for 31-bit compat tasks.
	 * The space for vector registers is only allocated if
	 * the machine supports it
	 */
	uc_flags = UC_GPRS_HIGH;
	if (MACHINE_HAS_VX) {
		uc_flags |= UC_VXRS;
	} else
		frame_size -= sizeof(frame->uc.uc_mcontext_ext.vxrs_low) +
			      sizeof(frame->uc.uc_mcontext_ext.vxrs_high);
	frame = get_sigframe(&ksig->ka, regs, frame_size);
	if (frame == (void __user *) -1UL)
		return -EFAULT;

	/* Set up backchain. */
	if (__put_user(regs->gprs[15], (unsigned int __force __user *) frame))
		return -EFAULT;

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	if (ksig->ka.sa.sa_flags & SA_RESTORER) {
		restorer = (unsigned long __force)
			ksig->ka.sa.sa_restorer | PSW32_ADDR_AMODE;
	} else {
		__u16 __user *svc = &frame->svc_insn;
		if (__put_user(S390_SYSCALL_OPCODE | __NR_rt_sigreturn, svc))
			return -EFAULT;
		restorer = (unsigned long __force) svc | PSW32_ADDR_AMODE;
	}

	/* Create siginfo on the signal stack */
	if (copy_siginfo_to_user32(&frame->info, &ksig->info))
		return -EFAULT;

	/* Store registers needed to create the signal frame */
	store_sigregs();

	/* Create ucontext on the signal stack. */
	sigset_to_sigset32(set->sig, cset.sig);
	if (__put_user(uc_flags, &frame->uc.uc_flags) ||
	    __put_user(0, &frame->uc.uc_link) ||
	    __compat_save_altstack(&frame->uc.uc_stack, regs->gprs[15]) ||
	    save_sigregs32(regs, &frame->uc.uc_mcontext) ||
	    __copy_to_user(&frame->uc.uc_sigmask, &cset, sizeof(cset)) ||
	    save_sigregs_ext32(regs, &frame->uc.uc_mcontext_ext))
		return -EFAULT;

	/* Set up registers for signal handler */
	regs->gprs[14] = restorer;
	regs->gprs[15] = (__force __u64) frame;
	/* Force 31 bit amode and default user address space control. */
	regs->psw.mask = PSW_MASK_BA |
		(PSW_USER_BITS & PSW_MASK_ASC) |
		(regs->psw.mask & ~PSW_MASK_ASC);
	regs->psw.addr = (__u64 __force) ksig->ka.sa.sa_handler;

	regs->gprs[2] = ksig->sig;
	regs->gprs[3] = (__force __u64) &frame->info;
	regs->gprs[4] = (__force __u64) &frame->uc;
	regs->gprs[5] = current->thread.last_break;
	return 0;
}

/*
 * OK, we're invoking a handler
 */	

int
handle_signal32(unsigned long sig, struct k_sigaction *ka,
		siginfo_t *info, sigset_t *oldset, struct pt_regs * regs)
void handle_signal32(struct ksignal *ksig, sigset_t *oldset,
		     struct pt_regs *regs)
{
	int ret;

	/* Set up the stack frame */
	if (ka->sa.sa_flags & SA_SIGINFO)
		ret = setup_rt_frame32(sig, ka, info, oldset, regs);
	else
		ret = setup_frame32(sig, ka, oldset, regs);

	if (ret == 0) {
		spin_lock_irq(&current->sighand->siglock);
		sigorsets(&current->blocked,&current->blocked,&ka->sa.sa_mask);
		if (!(ka->sa.sa_flags & SA_NODEFER))
			sigaddset(&current->blocked,sig);
		recalc_sigpending();
		spin_unlock_irq(&current->sighand->siglock);
	}
	return ret;
	if (ksig->ka.sa.sa_flags & SA_SIGINFO)
		ret = setup_rt_frame32(ksig, oldset, regs);
	else
		ret = setup_frame32(ksig, oldset, regs);

	signal_setup_done(ret, ksig, test_thread_flag(TIF_SINGLE_STEP));
}

