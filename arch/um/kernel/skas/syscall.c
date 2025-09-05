/*
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include "linux/kernel.h"
#include "linux/ptrace.h"
#include "kern_util.h"
#include "sysdep/ptrace.h"
#include "sysdep/syscalls.h"

extern int syscall_table_size;
#define NR_syscalls (syscall_table_size / sizeof(void *))
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <kern_util.h>
#include <sysdep/ptrace.h>
#include <sysdep/ptrace_user.h>
#include <sysdep/syscalls.h>

void handle_syscall(struct uml_pt_regs *r)
{
	struct pt_regs *regs = container_of(r, struct pt_regs, regs);
	int syscall;

	syscall_trace(r, 0);

	/*
	 * This should go in the declaration of syscall, but when I do that,
	 * strace -f -c bash -c 'ls ; ls' breaks, sometimes not tracing
	 * children at all, sometimes hanging when bash doesn't see the first
	 * ls exit.
	 * The assembly looks functionally the same to me.  This is
	 *     gcc version 4.0.1 20050727 (Red Hat 4.0.1-5)
	 * in case it's a compiler bug.
	 */
	syscall = UPT_SYSCALL_NR(r);
	if ((syscall >= NR_syscalls) || (syscall < 0))
		result = -ENOSYS;
	else result = EXECUTE_SYSCALL(syscall, regs);

	REGS_SET_SYSCALL_RETURN(r->gp, result);

	syscall_trace(r, 1);
	if (syscall_trace_enter(regs)) {
		result = -ENOSYS;
	/* Initialize the syscall number and default return value. */
	UPT_SYSCALL_NR(r) = PT_SYSCALL_NR(r->gp);
	PT_REGS_SET_SYSCALL_RETURN(regs, -ENOSYS);

	if (syscall_trace_enter(regs))
		goto out;

	/* Do the seccomp check after ptrace; failures should be fast. */
	if (secure_computing(NULL) == -1)
		goto out;

	syscall = UPT_SYSCALL_NR(r);
	if (syscall >= 0 && syscall <= __NR_syscall_max)
		PT_REGS_SET_SYSCALL_RETURN(regs,
				EXECUTE_SYSCALL(syscall, regs));

out:
	syscall_trace_leave(regs);
}
