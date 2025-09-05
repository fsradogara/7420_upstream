/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SH_BUGS_H
#define __ASM_SH_BUGS_H

/*
 * This is included by init/main.c to check for architecture-dependent bugs.
 *
 * Needs:
 *	void check_bugs(void);
 */

/*
 * I don't know of any Super-H bugs yet.
 */

#include <asm/processor.h>

extern void select_idle_routine(void);

static void __init check_bugs(void)
{
	extern unsigned long loops_per_jiffy;
	char *p = &init_utsname()->machine[2]; /* "sh" */

	current_cpu_data.loops_per_jiffy = loops_per_jiffy;

	switch (current_cpu_data.type) {
	case CPU_SH7619:
		*p++ = '2';
		break;
	case CPU_SH7203 ... CPU_MXG:
		*p++ = '2';
		*p++ = 'a';
		break;
	case CPU_SH7705 ... CPU_SH7729:
		*p++ = '3';
		break;
	case CPU_SH7750 ... CPU_SH4_501:
		*p++ = '4';
		break;
	case CPU_SH7763 ... CPU_SHX3:
		*p++ = '4';
		*p++ = 'a';
		break;
	case CPU_SH7343 ... CPU_SH7366:
	select_idle_routine();

	current_cpu_data.loops_per_jiffy = loops_per_jiffy;

	switch (current_cpu_data.family) {
	case CPU_FAMILY_SH2:
		*p++ = '2';
		break;
	case CPU_FAMILY_SH2A:
		*p++ = '2';
		*p++ = 'a';
		break;
	case CPU_FAMILY_SH3:
		*p++ = '3';
		break;
	case CPU_FAMILY_SH4:
		*p++ = '4';
		break;
	case CPU_FAMILY_SH4A:
		*p++ = '4';
		*p++ = 'a';
		break;
	case CPU_FAMILY_SH4AL_DSP:
		*p++ = '4';
		*p++ = 'a';
		*p++ = 'l';
		*p++ = '-';
		*p++ = 'd';
		*p++ = 's';
		*p++ = 'p';
		break;
	case CPU_SH5_101 ... CPU_SH5_103:
		*p++ = '6';
		*p++ = '4';
		break;
	case CPU_SH_NONE:
		/*
		 * Specifically use CPU_SH_NONE rather than default:,
		 * so we're able to have the compiler whine about
		 * unhandled enumerations.
	case CPU_FAMILY_SH5:
		*p++ = '6';
		*p++ = '4';
		break;
	case CPU_FAMILY_UNKNOWN:
		/*
		 * Specifically use CPU_FAMILY_UNKNOWN rather than
		 * default:, so we're able to have the compiler whine
		 * about unhandled enumerations.
		 */
		break;
	}

	printk("CPU: %s\n", get_cpu_subtype(&current_cpu_data));

#ifndef __LITTLE_ENDIAN__
	/* 'eb' means 'Endian Big' */
	*p++ = 'e';
	*p++ = 'b';
#endif
	*p = '\0';
}
#endif /* __ASM_SH_BUGS_H */
