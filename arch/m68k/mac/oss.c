// SPDX-License-Identifier: GPL-2.0
/*
 *	OSS handling
 *	Operating System Services (OSS) chip handling
 *	Written by Joshua M. Thompson (funaho@jurai.org)
 *
 *
 *	This chip is used in the IIfx in place of VIA #2. It acts like a fancy
 *	VIA chip with prorammable interrupt levels.
 *
 * 990502 (jmt) - Major rewrite for new interrupt architecture as well as some
 *		  recent insights into OSS operational details.
 * 990610 (jmt) - Now taking full advantage of the OSS. Interrupts are mapped
 *		  to mostly match the A/UX interrupt scheme supported on the
 *		  VIA side. Also added support for enabling the ISM irq again
 *		  since we now have a functional IOP manager.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/init.h>

#include <asm/bootinfo.h>
#include <asm/machw.h>
#include <linux/irq.h>

#include <asm/macintosh.h>
#include <asm/macints.h>
#include <asm/mac_via.h>
#include <asm/mac_oss.h>

int oss_present;
volatile struct mac_oss *oss;

static irqreturn_t oss_irq(int, void *);
static irqreturn_t oss_nubus_irq(int, void *);

extern irqreturn_t via1_irq(int, void *);
extern irqreturn_t mac_scc_dispatch(int, void *);

/*
 * Initialize the OSS
 */

void __init oss_init(void)
{
	int i;

	if (macintosh_config->ident != MAC_MODEL_IIFX)
		return;

	oss = (struct mac_oss *) OSS_BASE;
	pr_debug("OSS detected at %p", oss);
	oss_present = 1;

	/* Disable all interrupts. Unlike a VIA it looks like we    */
	/* do this by setting the source's interrupt level to zero. */

	for (i = 0; i <= OSS_NUM_SOURCES; i++) {
		oss->irq_level[i] = OSS_IRQLEV_DISABLED;
	}
	/* If we disable VIA1 here, we never really handle it... */
	oss->irq_level[OSS_VIA1] = OSS_IRQLEV_VIA1;
}

/*
 * Register the OSS and NuBus interrupt dispatchers.
 */

void __init oss_register_interrupts(void)
{
	request_irq(OSS_IRQLEV_SCSI, oss_irq, IRQ_FLG_LOCK,
			"scsi", (void *) oss);
	request_irq(OSS_IRQLEV_IOPSCC, mac_scc_dispatch, IRQ_FLG_LOCK,
			"scc", mac_scc_dispatch);
	request_irq(OSS_IRQLEV_NUBUS, oss_nubus_irq, IRQ_FLG_LOCK,
			"nubus", (void *) oss);
	request_irq(OSS_IRQLEV_SOUND, oss_irq, IRQ_FLG_LOCK,
			"sound", (void *) oss);
	request_irq(OSS_IRQLEV_VIA1, via1_irq, IRQ_FLG_LOCK,
			"via1", (void *) via1);
	for (i = 0; i < OSS_NUM_SOURCES; i++)
		oss->irq_level[i] = 0;
}

/*
 * Handle OSS interrupts.
 * XXX how do you clear a pending IRQ? is it even necessary?
 */

static void oss_iopism_irq(struct irq_desc *desc)
{
	generic_handle_irq(IRQ_MAC_ADB);
}

/*
 * Handle miscellaneous OSS interrupts. Right now that's just sound
 * and SCSI; everything else is routed to its own autovector IRQ.
 */

static irqreturn_t oss_irq(int irq, void *dev_id)
{
	int events;

	events = oss->irq_pending & (OSS_IP_SOUND|OSS_IP_SCSI);
	if (!events)
		return IRQ_NONE;

#ifdef DEBUG_IRQS
	if ((console_loglevel == 10) && !(events & OSS_IP_SCSI)) {
		printk("oss_irq: irq %d events = 0x%04X\n", irq,
			(int) oss->irq_pending);
	}
#endif
	/* FIXME: how do you clear a pending IRQ?    */

	if (events & OSS_IP_SOUND) {
		oss->irq_pending &= ~OSS_IP_SOUND;
		/* FIXME: call sound handler */
	} else if (events & OSS_IP_SCSI) {
		oss->irq_pending &= ~OSS_IP_SCSI;
		m68k_handle_int(IRQ_MAC_SCSI);
	} else {
		/* FIXME: error check here? */
	}
	return IRQ_HANDLED;
 * Handle miscellaneous OSS interrupts.
 */

static void oss_irq(struct irq_desc *desc)
static void oss_scsi_irq(struct irq_desc *desc)
{
	generic_handle_irq(IRQ_MAC_SCSI);
}

/*
 * Nubus IRQ handler, OSS style
 *
 * Unlike the VIA/RBV this is on its own autovector interrupt level.
 */

static irqreturn_t oss_nubus_irq(int irq, void *dev_id)
static void oss_nubus_irq(struct irq_desc *desc)
{
	u16 events, irq_bit;
	int irq_num;

	events = oss->irq_pending & OSS_IP_NUBUS;
	if (!events)
		return IRQ_NONE;
		return;

	/* There are only six slots on the OSS, not seven */

	i = 6;
	irq_bit = 0x40;
	irq_num = NUBUS_SOURCE_BASE + 5;
	irq_bit = OSS_IP_NUBUS5;
	do {
		if (events & irq_bit) {
			oss->irq_pending &= ~irq_bit;
			m68k_handle_int(NUBUS_SOURCE_BASE + i);
		}
	} while(events & (irq_bit - 1));
	return IRQ_HANDLED;
			generic_handle_irq(NUBUS_SOURCE_BASE + i);
			events &= ~irq_bit;
			generic_handle_irq(irq_num);
		}
		--irq_num;
		irq_bit >>= 1;
	} while (events);
}

static void oss_iopscc_irq(struct irq_desc *desc)
{
	generic_handle_irq(IRQ_MAC_SCC);
}

/*
 * Register the OSS and NuBus interrupt dispatchers.
 *
 * This IRQ mapping is laid out with two things in mind: first, we try to keep
 * things on their own levels to avoid having to do double-dispatches. Second,
 * the levels match as closely as possible the alternate IRQ mapping mode (aka
 * "A/UX mode") available on some VIA machines.
 */

#define OSS_IRQLEV_IOPISM    IRQ_AUTO_1
#define OSS_IRQLEV_SCSI      IRQ_AUTO_2
#define OSS_IRQLEV_NUBUS     IRQ_AUTO_3
#define OSS_IRQLEV_IOPSCC    IRQ_AUTO_4
#define OSS_IRQLEV_VIA1      IRQ_AUTO_6

void __init oss_register_interrupts(void)
{
	irq_set_chained_handler(OSS_IRQLEV_IOPISM, oss_iopism_irq);
	irq_set_chained_handler(OSS_IRQLEV_SCSI,   oss_scsi_irq);
	irq_set_chained_handler(OSS_IRQLEV_NUBUS,  oss_nubus_irq);
	irq_set_chained_handler(OSS_IRQLEV_IOPSCC, oss_iopscc_irq);
	irq_set_chained_handler(OSS_IRQLEV_VIA1,   via1_irq);

	/* OSS_VIA1 gets enabled here because it has no machspec interrupt. */
	oss->irq_level[OSS_VIA1] = OSS_IRQLEV_VIA1;
}

/*
 * Enable an OSS interrupt
 *
 * It looks messy but it's rather straightforward. The switch() statement
 * just maps the machspec interrupt numbers to the right OSS interrupt
 * source (if the OSS handles that interrupt) and then sets the interrupt
 * level for that source to nonzero, thus enabling the interrupt.
 */

void oss_irq_enable(int irq) {
	switch(irq) {
		case IRQ_SCC:
		case IRQ_SCCA:
		case IRQ_SCCB:
			oss->irq_level[OSS_IOPSCC] = OSS_IRQLEV_IOPSCC;
			break;
		case IRQ_MAC_ADB:
			oss->irq_level[OSS_IOPISM] = OSS_IRQLEV_IOPISM;
			break;
		case IRQ_MAC_SCSI:
			oss->irq_level[OSS_SCSI] = OSS_IRQLEV_SCSI;
			break;
		case IRQ_MAC_SCC:
			oss->irq_level[OSS_IOPSCC] = OSS_IRQLEV_IOPSCC;
			return;
		case IRQ_MAC_ADB:
			oss->irq_level[OSS_IOPISM] = OSS_IRQLEV_IOPISM;
			return;
		case IRQ_MAC_SCSI:
			oss->irq_level[OSS_SCSI] = OSS_IRQLEV_SCSI;
			return;
		case IRQ_NUBUS_9:
		case IRQ_NUBUS_A:
		case IRQ_NUBUS_B:
		case IRQ_NUBUS_C:
		case IRQ_NUBUS_D:
		case IRQ_NUBUS_E:
			irq -= NUBUS_SOURCE_BASE;
			oss->irq_level[irq] = OSS_IRQLEV_NUBUS;
			break;
#ifdef DEBUG_IRQUSE
		default:
			printk("%s unknown irq %d\n", __func__, irq);
			break;
#endif
	}
			return;
	}

	if (IRQ_SRC(irq) == 1)
		via_irq_enable(irq);
}

/*
 * Disable an OSS interrupt
 *
 * Same as above except we set the source's interrupt level to zero,
 * to disable the interrupt.
 */

void oss_irq_disable(int irq) {
	switch(irq) {
		case IRQ_SCC:
		case IRQ_SCCA:
		case IRQ_SCCB:
			oss->irq_level[OSS_IOPSCC] = OSS_IRQLEV_DISABLED;
			break;
		case IRQ_MAC_ADB:
			oss->irq_level[OSS_IOPISM] = OSS_IRQLEV_DISABLED;
			break;
		case IRQ_MAC_SCSI:
			oss->irq_level[OSS_SCSI] = OSS_IRQLEV_DISABLED;
			break;
		case IRQ_MAC_SCC:
			oss->irq_level[OSS_IOPSCC] = 0;
			return;
		case IRQ_MAC_ADB:
			oss->irq_level[OSS_IOPISM] = 0;
			return;
		case IRQ_MAC_SCSI:
			oss->irq_level[OSS_SCSI] = 0;
			return;
		case IRQ_NUBUS_9:
		case IRQ_NUBUS_A:
		case IRQ_NUBUS_B:
		case IRQ_NUBUS_C:
		case IRQ_NUBUS_D:
		case IRQ_NUBUS_E:
			irq -= NUBUS_SOURCE_BASE;
			oss->irq_level[irq] = OSS_IRQLEV_DISABLED;
			break;
#ifdef DEBUG_IRQUSE
		default:
			printk("%s unknown irq %d\n", __func__, irq);
			break;
#endif
	}
}

/*
 * Clear an OSS interrupt
 *
 * Not sure if this works or not but it's the only method I could
 * think of based on the contents of the mac_oss structure.
 */

void oss_irq_clear(int irq) {
	/* FIXME: how to do this on OSS? */
	switch(irq) {
		case IRQ_SCC:
		case IRQ_SCCA:
		case IRQ_SCCB:
			oss->irq_pending &= ~OSS_IP_IOPSCC;
			break;
		case IRQ_MAC_ADB:
			oss->irq_pending &= ~OSS_IP_IOPISM;
			break;
		case IRQ_MAC_SCSI:
			oss->irq_pending &= ~OSS_IP_SCSI;
			break;
		case IRQ_NUBUS_9:
		case IRQ_NUBUS_A:
		case IRQ_NUBUS_B:
		case IRQ_NUBUS_C:
		case IRQ_NUBUS_D:
		case IRQ_NUBUS_E:
			irq -= NUBUS_SOURCE_BASE;
			oss->irq_pending &= ~(1 << irq);
			break;
	}
}

/*
 * Check to see if a specific OSS interrupt is pending
 */

int oss_irq_pending(int irq)
{
	switch(irq) {
		case IRQ_SCC:
		case IRQ_SCCA:
		case IRQ_SCCB:
			return oss->irq_pending & OSS_IP_IOPSCC;
			break;
		case IRQ_MAC_ADB:
			return oss->irq_pending & OSS_IP_IOPISM;
			break;
		case IRQ_MAC_SCSI:
			return oss->irq_pending & OSS_IP_SCSI;
			break;
		case IRQ_NUBUS_9:
		case IRQ_NUBUS_A:
		case IRQ_NUBUS_B:
		case IRQ_NUBUS_C:
		case IRQ_NUBUS_D:
		case IRQ_NUBUS_E:
			irq -= NUBUS_SOURCE_BASE;
			return oss->irq_pending & (1 << irq);
			break;
	}
	return 0;
			oss->irq_level[irq] = 0;
			return;
	}

	if (IRQ_SRC(irq) == 1)
		via_irq_disable(irq);
}
