/**
 * arch/s390/oprofile/init.c
 *
 * S390 Version
 *   Copyright (C) 2003 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *   Author(s): Thomas Spatzier (tspat@de.ibm.com)
 *
 * @remark Copyright 2002 OProfile authors
 */

#include <linux/oprofile.h>
#include <linux/init.h>
#include <linux/errno.h>


extern void s390_backtrace(struct pt_regs * const regs, unsigned int depth);

int __init oprofile_arch_init(struct oprofile_operations* ops)
{
	ops->backtrace = s390_backtrace;
	return -ENODEV;
// SPDX-License-Identifier: GPL-2.0
/*
 * S390 Version
 *   Copyright IBM Corp. 2002, 2011
 *   Author(s): Thomas Spatzier (tspat@de.ibm.com)
 *   Author(s): Mahesh Salgaonkar (mahesh@linux.vnet.ibm.com)
 *   Author(s): Heinz Graalfs (graalfs@linux.vnet.ibm.com)
 *   Author(s): Andreas Krebbel (krebbel@linux.vnet.ibm.com)
 *
 * @remark Copyright 2002-2011 OProfile authors
 */

#include <linux/oprofile.h>
#include <linux/init.h>
#include <asm/processor.h>

static int __s390_backtrace(void *data, unsigned long address, int reliable)
{
	unsigned int *depth = data;

	if (*depth == 0)
		return 1;
	(*depth)--;
	oprofile_add_trace(address);
	return 0;
}

static void s390_backtrace(struct pt_regs *regs, unsigned int depth)
{
	if (user_mode(regs))
		return;
	dump_trace(__s390_backtrace, &depth, NULL, regs->gprs[15]);
}

int __init oprofile_arch_init(struct oprofile_operations *ops)
{
	ops->backtrace = s390_backtrace;
	return 0;
}

void oprofile_arch_exit(void)
{
}
