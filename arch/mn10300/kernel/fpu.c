/* MN10300 FPU management
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <linux/uaccess.h>
#include <linux/sched/signal.h>

#include <asm/fpu.h>
#include <asm/elf.h>
#include <asm/exceptions.h>

struct task_struct *fpu_state_owner;

/*
 * handle an exception due to the FPU being disabled
 */
asmlinkage void fpu_disabled(struct pt_regs *regs, enum exception_code code)
{
	struct task_struct *tsk = current;

	if (!user_mode(regs))
		die_if_no_fixup("An FPU Disabled exception happened in"
				" kernel space\n",
				regs, code);

#ifdef CONFIG_FPU
	preempt_disable();

	/* transfer the last process's FPU state to memory */
	if (fpu_state_owner) {
		fpu_save(&fpu_state_owner->thread.fpu_state);
		fpu_state_owner->thread.uregs->epsw &= ~EPSW_FE;
	}

	/* the current process now owns the FPU state */
	fpu_state_owner = tsk;
	regs->epsw |= EPSW_FE;

	/* load the FPU with the current process's FPU state or invent a new
	 * clean one if the process doesn't have one */
	if (is_using_fpu(tsk)) {
		fpu_restore(&tsk->thread.fpu_state);
	} else {
		fpu_init_state();
		set_using_fpu(tsk);
	}

	preempt_enable();
#else
	{
		siginfo_t info;

		info.si_signo = SIGFPE;
		info.si_errno = 0;
		info.si_addr = (void *) tsk->thread.uregs->pc;
		info.si_code = FPE_FLTINV;

		force_sig_info(SIGFPE, &info, tsk);
	}
#endif  /* CONFIG_FPU */
#ifdef CONFIG_LAZY_SAVE_FPU
struct task_struct *fpu_state_owner;
#endif

/*
 * error functions in FPU disabled exception
 */
asmlinkage void fpu_disabled_in_kernel(struct pt_regs *regs)
{
	die_if_no_fixup("An FPU Disabled exception happened in kernel space\n",
			regs, EXCEP_FPU_DISABLED);
}

/*
 * handle an FPU operational exception
 * - there's a possibility that if the FPU is asynchronous, the signal might
 *   be meant for a process other than the current one
 */
asmlinkage void fpu_exception(struct pt_regs *regs, enum exception_code code)
{
	struct task_struct *tsk = fpu_state_owner;
	siginfo_t info;
	struct task_struct *tsk = current;
	siginfo_t info;
	u32 fpcr;

	if (!user_mode(regs))
		die_if_no_fixup("An FPU Operation exception happened in"
				" kernel space\n",
				regs, code);

	if (!tsk)
	if (!is_using_fpu(tsk))
		die_if_no_fixup("An FPU Operation exception happened,"
				" but the FPU is not in use",
				regs, code);

	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_addr = (void *) tsk->thread.uregs->pc;
	info.si_code = FPE_FLTINV;

#ifdef CONFIG_FPU
	{
		u32 fpcr;

		/* get FPCR (we need to enable the FPU whilst we do this) */
		asm volatile("	or	%1,epsw		\n"
#ifdef CONFIG_MN10300_PROC_MN103E010
			     "	nop			\n"
			     "	nop			\n"
			     "	nop			\n"
#endif
			     "	fmov	fpcr,%0		\n"
#ifdef CONFIG_MN10300_PROC_MN103E010
			     "	nop			\n"
			     "	nop			\n"
			     "	nop			\n"
#endif
			     "	and	%2,epsw		\n"
			     : "=&d"(fpcr)
			     : "i"(EPSW_FE), "i"(~EPSW_FE)
			     );

		if (fpcr & FPCR_EC_Z)
			info.si_code = FPE_FLTDIV;
		else if	(fpcr & FPCR_EC_O)
			info.si_code = FPE_FLTOVF;
		else if	(fpcr & FPCR_EC_U)
			info.si_code = FPE_FLTUND;
		else if	(fpcr & FPCR_EC_I)
			info.si_code = FPE_FLTRES;
	}
#endif
	unlazy_fpu(tsk);

	fpcr = tsk->thread.fpu_state.fpcr;

	if (fpcr & FPCR_EC_Z)
		info.si_code = FPE_FLTDIV;
	else if	(fpcr & FPCR_EC_O)
		info.si_code = FPE_FLTOVF;
	else if	(fpcr & FPCR_EC_U)
		info.si_code = FPE_FLTUND;
	else if	(fpcr & FPCR_EC_I)
		info.si_code = FPE_FLTRES;

	force_sig_info(SIGFPE, &info, tsk);
}

/*
 * save the FPU state to a signal context
 */
int fpu_setup_sigcontext(struct fpucontext *fpucontext)
{
#ifdef CONFIG_FPU
	struct task_struct *tsk = current;

	if (!is_using_fpu(tsk))
		return 0;

	/* transfer the current FPU state to memory and cause fpu_init() to be
	 * triggered by the next attempted FPU operation by the current
	 * process.
	 */
	preempt_disable();

#ifndef CONFIG_LAZY_SAVE_FPU
	if (tsk->thread.fpu_flags & THREAD_HAS_FPU) {
		fpu_save(&tsk->thread.fpu_state);
		tsk->thread.uregs->epsw &= ~EPSW_FE;
		tsk->thread.fpu_flags &= ~THREAD_HAS_FPU;
	}
#else /* !CONFIG_LAZY_SAVE_FPU */
	if (fpu_state_owner == tsk) {
		fpu_save(&tsk->thread.fpu_state);
		fpu_state_owner->thread.uregs->epsw &= ~EPSW_FE;
		fpu_state_owner = NULL;
	}
#endif /* !CONFIG_LAZY_SAVE_FPU */

	preempt_enable();

	/* we no longer have a valid current FPU state */
	clear_using_fpu(tsk);

	/* transfer the saved FPU state onto the userspace stack */
	if (copy_to_user(fpucontext,
			 &tsk->thread.fpu_state,
			 min(sizeof(struct fpu_state_struct),
			     sizeof(struct fpucontext))))
		return -1;

	return 1;
#else
	return 0;
#endif
}

/*
 * kill a process's FPU state during restoration after signal handling
 */
void fpu_kill_state(struct task_struct *tsk)
{
#ifdef CONFIG_FPU
	/* disown anything left in the FPU */
	preempt_disable();

	/* disown anything left in the FPU */
	preempt_disable();

#ifndef CONFIG_LAZY_SAVE_FPU
	if (tsk->thread.fpu_flags & THREAD_HAS_FPU) {
		tsk->thread.uregs->epsw &= ~EPSW_FE;
		tsk->thread.fpu_flags &= ~THREAD_HAS_FPU;
	}
#else /* !CONFIG_LAZY_SAVE_FPU */
	if (fpu_state_owner == tsk) {
		fpu_state_owner->thread.uregs->epsw &= ~EPSW_FE;
		fpu_state_owner = NULL;
	}

	preempt_enable();
#endif
#endif /* !CONFIG_LAZY_SAVE_FPU */

	preempt_enable();

	/* we no longer have a valid current FPU state */
	clear_using_fpu(tsk);
}

/*
 * restore the FPU state from a signal context
 */
int fpu_restore_sigcontext(struct fpucontext *fpucontext)
{
	struct task_struct *tsk = current;
	int ret;

	/* load up the old FPU state */
	ret = copy_from_user(&tsk->thread.fpu_state,
			     fpucontext,
	ret = copy_from_user(&tsk->thread.fpu_state, fpucontext,
			     min(sizeof(struct fpu_state_struct),
				 sizeof(struct fpucontext)));
	if (!ret)
		set_using_fpu(tsk);

	return ret;
}

/*
 * fill in the FPU structure for a core dump
 */
int dump_fpu(struct pt_regs *regs, elf_fpregset_t *fpreg)
{
	struct task_struct *tsk = current;
	int fpvalid;

	fpvalid = is_using_fpu(tsk);
	if (fpvalid) {
		unlazy_fpu(tsk);
		memcpy(fpreg, &tsk->thread.fpu_state, sizeof(*fpreg));
	}

	return fpvalid;
}
