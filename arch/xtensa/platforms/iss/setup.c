/*
 *
 * arch/xtensa/platform-iss/setup.c
 *
 * Platform specific initialization.
 *
 * Authors: Chris Zankel <chris@zankel.net>
 *          Joe Taylor <joe@tensilica.com>
 *
 * Copyright 2001 - 2005 Tensilica Inc.
 * Copyright 2017 Cadence Design Systems Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */
#include <linux/bootmem.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/reboot.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/stringify.h>
#include <linux/notifier.h>

#include <asm/platform.h>
#include <asm/bootparam.h>
#include <asm/setup.h>

#include <platform/simcall.h>


void __init platform_init(bp_tag_t* bootparam)
{
}

void platform_halt(void)
{
	printk (" ** Called platform_halt(), looping forever! **\n");
	while (1);
	pr_info(" ** Called platform_halt() **\n");
	simc_exit(0);
}

void platform_power_off(void)
{
	printk (" ** Called platform_power_off(), looping forever! **\n");
	while (1);
	pr_info(" ** Called platform_power_off() **\n");
	simc_exit(0);
}
void platform_restart(void)
{
	/* Flush and reset the mmu, simulate a processor reset, and
	 * jump to the reset vector. */

	__asm__ __volatile__("movi	a2, 15\n\t"
			     "wsr	a2, " __stringify(ICOUNTLEVEL) "\n\t"
			     "movi	a2, 0\n\t"
			     "wsr	a2, " __stringify(ICOUNT) "\n\t"
			     "wsr	a2, " __stringify(IBREAKENABLE) "\n\t"
			     "wsr	a2, " __stringify(LCOUNT) "\n\t"
			     "movi	a2, 0x1f\n\t"
			     "wsr	a2, " __stringify(PS) "\n\t"
			     "wsr	a2, icountlevel\n\t"
			     "movi	a2, 0\n\t"
			     "wsr	a2, icount\n\t"
#if XCHAL_NUM_IBREAK > 0
			     "wsr	a2, ibreakenable\n\t"
#endif
#if XCHAL_HAVE_LOOPS
			     "wsr	a2, lcount\n\t"
#endif
			     "movi	a2, 0x1f\n\t"
			     "wsr	a2, ps\n\t"
			     "isync\n\t"
			     "jx	%0\n\t"
			     :
			     : "a" (XCHAL_RESET_VECTOR_VADDR)
			     : "a2");

	cpu_reset();
	/* control never gets here */
}

void platform_heartbeat(void)
{
}

static int
iss_panic_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	simc_exit(1);
	return NOTIFY_DONE;
}

static struct notifier_block iss_panic_block = {
	.notifier_call = iss_panic_event,
};

void __init platform_setup(char **p_cmdline)
{
	int argc = simc_argc();
	int argv_size = simc_argv_size();

	if (argc > 1) {
		void **argv = alloc_bootmem(argv_size);
		char *cmdline = alloc_bootmem(argv_size);
		int i;

		cmdline[0] = 0;
		simc_argv((void *)argv);

		for (i = 1; i < argc; ++i) {
			if (i > 1)
				strcat(cmdline, " ");
			strcat(cmdline, argv[i]);
		}
		*p_cmdline = cmdline;
	}

	atomic_notifier_chain_register(&panic_notifier_list, &iss_panic_block);
}
