#ifndef ___ASM_SPARC_SIGNAL_H
#define ___ASM_SPARC_SIGNAL_H
#if defined(__sparc__) && defined(__arch64__)
#include <asm/signal_64.h>
#else
#include <asm/signal_32.h>
#endif
#endif
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPARC_SIGNAL_H
#define __SPARC_SIGNAL_H

#ifndef __ASSEMBLY__
#include <linux/personality.h>
#include <linux/types.h>
#endif
#include <uapi/asm/signal.h>

#ifndef __ASSEMBLY__
/*
 * DJHR
 * SA_STATIC_ALLOC is used for the sparc32 system to indicate that this
 * interrupt handler's irq structure should be statically allocated
 * by the request_irq routine.
 * The alternative is that arch/sparc/kernel/irq.c has carnal knowledge
 * of interrupt usage and that sucks. Also without a flag like this
 * it may be possible for the free_irq routine to attempt to free
 * statically allocated data.. which is NOT GOOD.
 *
 */
#define SA_STATIC_ALLOC         0x8000

#define __ARCH_HAS_KA_RESTORER
#define __ARCH_HAS_SA_RESTORER

#endif /* !(__ASSEMBLY__) */
#endif /* !(__SPARC_SIGNAL_H) */
