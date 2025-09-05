// SPDX-License-Identifier: GPL-2.0
/*
 * Universal Host Controller Interface driver for USB.
 *
 * Maintainer: Alan Stern <stern@rowland.harvard.edu>
 *
 * (C) Copyright 1999 Linus Torvalds
 * (C) Copyright 1999-2002 Johannes Erdfelt, johannes@erdfelt.com
 * (C) Copyright 1999 Randy Dunlap
 * (C) Copyright 1999 Georg Acher, acher@in.tum.de
 * (C) Copyright 1999 Deti Fliegl, deti@fliegl.de
 * (C) Copyright 1999 Thomas Sailer, sailer@ife.ee.ethz.ch
 * (C) Copyright 1999 Roman Weissgaerber, weissg@vienna.at
 * (C) Copyright 2000 Yggdrasil Computing, Inc. (port of new PCI interface
 *               support from usb-ohci.c by Adam Richter, adam@yggdrasil.com).
 * (C) Copyright 1999 Gregory P. Smith (from usb-ohci.c)
 * (C) Copyright 2004-2007 Alan Stern, stern@rowland.harvard.edu
 *
 * Intel documents this fairly well, and as far as I know there
 * are no royalties or anything like that, but even so there are
 * people who decided that they want to do the same thing in a
 * completely different way.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/pm.h>
#include <linux/dmapool.h>
#include <linux/dma-mapping.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/bitops.h>
#include <linux/dmi.h>

#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/system.h>

#include "../core/hcd.h"
#include "uhci-hcd.h"
#include "pci-quirks.h"

#include "uhci-hcd.h"

/*
 * Version Information
 */
#define DRIVER_VERSION "v3.0"
#define DRIVER_AUTHOR "Linus 'Frodo Rabbit' Torvalds, Johannes Erdfelt, \
Randy Dunlap, Georg Acher, Deti Fliegl, Thomas Sailer, Roman Weissgaerber, \
Alan Stern"
#define DRIVER_DESC "USB Universal Host Controller Interface driver"

/* for flakey hardware, ignore overcurrent indicators */
static int ignore_oc;
#define DRIVER_AUTHOR							\
	"Linus 'Frodo Rabbit' Torvalds, Johannes Erdfelt, "		\
	"Randy Dunlap, Georg Acher, Deti Fliegl, Thomas Sailer, "	\
	"Roman Weissgaerber, Alan Stern"
#define DRIVER_DESC "USB Universal Host Controller Interface driver"

/* for flakey hardware, ignore overcurrent indicators */
static bool ignore_oc;
module_param(ignore_oc, bool, S_IRUGO);
MODULE_PARM_DESC(ignore_oc, "ignore hardware overcurrent indications");

/*
 * debug = 0, no debugging messages
 * debug = 1, dump failed URBs except for stalls
 * debug = 2, dump all failed URBs (including stalls)
 *            show all queues in /debug/uhci/[pci_addr]
 * debug = 3, show all TDs in URBs when dumping
 */
#ifdef DEBUG
#define DEBUG_CONFIGURED	1
static int debug = 1;
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Debug level");

#else
#define DEBUG_CONFIGURED	0
#define debug			0
#endif

static char *errbuf;
 *            show all queues in /sys/kernel/debug/uhci/[pci_addr]
 * debug = 3, show all TDs in URBs when dumping
 */
#ifdef CONFIG_DYNAMIC_DEBUG

static int debug = 1;
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Debug level");
static char *errbuf;

#else

#define debug 0
#define errbuf NULL

#endif


#define ERRBUF_LEN    (32 * 1024)

static struct kmem_cache *uhci_up_cachep;	/* urb_priv */

static void suspend_rh(struct uhci_hcd *uhci, enum uhci_rh_state new_state);
static void wakeup_rh(struct uhci_hcd *uhci);
static void uhci_get_current_frame_number(struct uhci_hcd *uhci);

/*
 * Calculate the link pointer DMA value for the first Skeleton QH in a frame.
 */
static __le32 uhci_frame_skel_link(struct uhci_hcd *uhci, int frame)
static __hc32 uhci_frame_skel_link(struct uhci_hcd *uhci, int frame)
{
	int skelnum;

	/*
	 * The interrupt queues will be interleaved as evenly as possible.
	 * There's not much to be done about period-1 interrupts; they have
	 * to occur in every frame.  But we can schedule period-2 interrupts
	 * in odd-numbered frames, period-4 interrupts in frames congruent
	 * to 2 (mod 4), and so on.  This way each frame only has two
	 * interrupt QHs, which will help spread out bandwidth utilization.
	 *
	 * ffs (Find First bit Set) does exactly what we need:
	 * 1,3,5,...  => ffs = 0 => use period-2 QH = skelqh[8],
	 * 2,6,10,... => ffs = 1 => use period-4 QH = skelqh[7], etc.
	 * ffs >= 7 => not on any high-period queue, so use
	 *	period-1 QH = skelqh[9].
	 * Add in UHCI_NUMFRAMES to insure at least one bit is set.
	 */
	skelnum = 8 - (int) __ffs(frame | UHCI_NUMFRAMES);
	if (skelnum <= 1)
		skelnum = 9;
	return LINK_TO_QH(uhci->skelqh[skelnum]);
	return LINK_TO_QH(uhci, uhci->skelqh[skelnum]);
}

#include "uhci-debug.c"
#include "uhci-q.c"
#include "uhci-hub.c"

/*
 * Finish up a host controller reset and update the recorded state.
 */
static void finish_reset(struct uhci_hcd *uhci)
{
	int port;

	/* HCRESET doesn't affect the Suspend, Reset, and Resume Detect
	 * bits in the port status and control registers.
	 * We have to clear them by hand.
	 */
	for (port = 0; port < uhci->rh_numports; ++port)
		outw(0, uhci->io_addr + USBPORTSC1 + (port * 2));
		uhci_writew(uhci, 0, USBPORTSC1 + (port * 2));

	uhci->port_c_suspend = uhci->resuming_ports = 0;
	uhci->rh_state = UHCI_RH_RESET;
	uhci->is_stopped = UHCI_IS_STOPPED;
	uhci_to_hcd(uhci)->state = HC_STATE_HALT;
	uhci_to_hcd(uhci)->poll_rh = 0;

	uhci->dead = 0;		/* Full reset resurrects the controller */
	clear_bit(HCD_FLAG_POLL_RH, &uhci_to_hcd(uhci)->flags);
}

/*
 * Last rites for a defunct/nonfunctional controller
 * or one we don't want to use any more.
 */
static void uhci_hc_died(struct uhci_hcd *uhci)
{
	uhci_get_current_frame_number(uhci);
	uhci_reset_hc(to_pci_dev(uhci_dev(uhci)), uhci->io_addr);
	uhci->reset_hc(uhci);
	finish_reset(uhci);
	uhci->dead = 1;

	/* The current frame may already be partway finished */
	++uhci->frame_number;
}

/*
 * Initialize a controller that was newly discovered or has lost power
 * or otherwise been reset while it was suspended.  In none of these cases
 * can we be sure of its previous state.
 */
static void check_and_reset_hc(struct uhci_hcd *uhci)
{
	if (uhci_check_and_reset_hc(to_pci_dev(uhci_dev(uhci)), uhci->io_addr))
		finish_reset(uhci);
}

	if (uhci->check_and_reset_hc(uhci))
		finish_reset(uhci);
}

#if defined(CONFIG_USB_UHCI_SUPPORT_NON_PCI_HC)
/*
 * The two functions below are generic reset functions that are used on systems
 * that do not have keyboard and mouse legacy support. We assume that we are
 * running on such a system if CONFIG_USB_UHCI_SUPPORT_NON_PCI_HC is defined.
 */

/*
 * Make sure the controller is completely inactive, unable to
 * generate interrupts or do DMA.
 */
static void uhci_generic_reset_hc(struct uhci_hcd *uhci)
{
	/* Reset the HC - this will force us to get a
	 * new notification of any already connected
	 * ports due to the virtual disconnect that it
	 * implies.
	 */
	uhci_writew(uhci, USBCMD_HCRESET, USBCMD);
	mb();
	udelay(5);
	if (uhci_readw(uhci, USBCMD) & USBCMD_HCRESET)
		dev_warn(uhci_dev(uhci), "HCRESET not completed yet!\n");

	/* Just to be safe, disable interrupt requests and
	 * make sure the controller is stopped.
	 */
	uhci_writew(uhci, 0, USBINTR);
	uhci_writew(uhci, 0, USBCMD);
}

/*
 * Initialize a controller that was newly discovered or has just been
 * resumed.  In either case we can't be sure of its previous state.
 *
 * Returns: 1 if the controller was reset, 0 otherwise.
 */
static int uhci_generic_check_and_reset_hc(struct uhci_hcd *uhci)
{
	unsigned int cmd, intr;

	/*
	 * When restarting a suspended controller, we expect all the
	 * settings to be the same as we left them:
	 *
	 *	Controller is stopped and configured with EGSM set;
	 *	No interrupts enabled except possibly Resume Detect.
	 *
	 * If any of these conditions are violated we do a complete reset.
	 */

	cmd = uhci_readw(uhci, USBCMD);
	if ((cmd & USBCMD_RS) || !(cmd & USBCMD_CF) || !(cmd & USBCMD_EGSM)) {
		dev_dbg(uhci_dev(uhci), "%s: cmd = 0x%04x\n",
				__func__, cmd);
		goto reset_needed;
	}

	intr = uhci_readw(uhci, USBINTR);
	if (intr & (~USBINTR_RESUME)) {
		dev_dbg(uhci_dev(uhci), "%s: intr = 0x%04x\n",
				__func__, intr);
		goto reset_needed;
	}
	return 0;

reset_needed:
	dev_dbg(uhci_dev(uhci), "Performing full reset\n");
	uhci_generic_reset_hc(uhci);
	return 1;
}
#endif /* CONFIG_USB_UHCI_SUPPORT_NON_PCI_HC */

/*
 * Store the basic register settings needed by the controller.
 */
static void configure_hc(struct uhci_hcd *uhci)
{
	/* Set the frame length to the default: 1 ms exactly */
	outb(USBSOF_DEFAULT, uhci->io_addr + USBSOF);

	/* Store the frame list base address */
	outl(uhci->frame_dma_handle, uhci->io_addr + USBFLBASEADD);

	/* Set the current frame number */
	outw(uhci->frame_number & UHCI_MAX_SOF_NUMBER,
			uhci->io_addr + USBFRNUM);

	/* Mark controller as not halted before we enable interrupts */
	uhci_to_hcd(uhci)->state = HC_STATE_SUSPENDED;
	mb();

	/* Enable PIRQ */
	pci_write_config_word(to_pci_dev(uhci_dev(uhci)), USBLEGSUP,
			USBLEGSUP_DEFAULT);
}


static int resume_detect_interrupts_are_broken(struct uhci_hcd *uhci)
{
	int port;

	uhci_writeb(uhci, USBSOF_DEFAULT, USBSOF);

	/* Store the frame list base address */
	uhci_writel(uhci, uhci->frame_dma_handle, USBFLBASEADD);

	/* Set the current frame number */
	uhci_writew(uhci, uhci->frame_number & UHCI_MAX_SOF_NUMBER,
			USBFRNUM);

	/* perform any arch/bus specific configuration */
	if (uhci->configure_hc)
		uhci->configure_hc(uhci);
}

static int resume_detect_interrupts_are_broken(struct uhci_hcd *uhci)
{
	/*
	 * If we have to ignore overcurrent events then almost by definition
	 * we can't depend on resume-detect interrupts.
	 *
	 * Those interrupts also don't seem to work on ASpeed SoCs.
	 */
	if (ignore_oc || uhci_is_aspeed(uhci))
		return 1;

	switch (to_pci_dev(uhci_dev(uhci))->vendor) {
	    default:
		break;

	    case PCI_VENDOR_ID_GENESYS:
		/* Genesys Logic's GL880S controllers don't generate
		 * resume-detect interrupts.
		 */
		return 1;

	    case PCI_VENDOR_ID_INTEL:
		/* Some of Intel's USB controllers have a bug that causes
		 * resume-detect interrupts if any port has an over-current
		 * condition.  To make matters worse, some motherboards
		 * hardwire unused USB ports' over-current inputs active!
		 * To prevent problems, we will not enable resume-detect
		 * interrupts if any ports are OC.
		 */
		for (port = 0; port < uhci->rh_numports; ++port) {
			if (inw(uhci->io_addr + USBPORTSC1 + port * 2) &
					USBPORTSC_OC)
				return 1;
		}
		break;
	}
	return 0;
	return uhci->resume_detect_interrupts_are_broken ?
		uhci->resume_detect_interrupts_are_broken(uhci) : 0;
}

static int global_suspend_mode_is_broken(struct uhci_hcd *uhci)
{
	int port;
	const char *sys_info;
	static char bad_Asus_board[] = "A7V8X";

	/* One of Asus's motherboards has a bug which causes it to
	 * wake up immediately from suspend-to-RAM if any of the ports
	 * are connected.  In such cases we will not set EGSM.
	 */
	sys_info = dmi_get_system_info(DMI_BOARD_NAME);
	if (sys_info && !strcmp(sys_info, bad_Asus_board)) {
		for (port = 0; port < uhci->rh_numports; ++port) {
			if (inw(uhci->io_addr + USBPORTSC1 + port * 2) &
					USBPORTSC_CCS)
				return 1;
		}
	}

	return 0;
	return uhci->global_suspend_mode_is_broken ?
		uhci->global_suspend_mode_is_broken(uhci) : 0;
}

static void suspend_rh(struct uhci_hcd *uhci, enum uhci_rh_state new_state)
__releases(uhci->lock)
__acquires(uhci->lock)
{
	int auto_stop;
	int int_enable, egsm_enable, wakeup_enable;
	struct usb_device *rhdev = uhci_to_hcd(uhci)->self.root_hub;

	auto_stop = (new_state == UHCI_RH_AUTO_STOPPED);
	dev_dbg(&rhdev->dev, "%s%s\n", __func__,
			(auto_stop ? " (auto-stop)" : ""));

	/* Start off by assuming Resume-Detect interrupts and EGSM work
	 * and that remote wakeups should be enabled.
	 */
	egsm_enable = USBCMD_EGSM;
	uhci->RD_enable = 1;
	int_enable = USBINTR_RESUME;
	wakeup_enable = 1;

	/* In auto-stop mode wakeups must always be detected, but
	 * Resume-Detect interrupts may be prohibited.  (In the absence
	 * of CONFIG_PM, they are always disallowed.)
	 */
	if (auto_stop) {
		if (!device_may_wakeup(&rhdev->dev))
			int_enable = 0;

	/* In bus-suspend mode wakeups may be disabled, but if they are
	 * allowed then so are Resume-Detect interrupts.
	 */
	} else {
#ifdef CONFIG_PM
		if (!rhdev->do_remote_wakeup)
			wakeup_enable = 0;
#endif
	}

	/* EGSM causes the root hub to echo a 'K' signal (resume) out any
	 * port which requests a remote wakeup.  According to the USB spec,
	 * every hub is supposed to do this.  But if we are ignoring
	 * remote-wakeup requests anyway then there's no point to it.
	 * We also shouldn't enable EGSM if it's broken.
	 */
	if (!wakeup_enable || global_suspend_mode_is_broken(uhci))
		egsm_enable = 0;

	/* If we're ignoring wakeup events then there's no reason to
	 * enable Resume-Detect interrupts.  We also shouldn't enable
	 * them if they are broken or disallowed.
	 *
	 * This logic may lead us to enabling RD but not EGSM.  The UHCI
	 * spec foolishly says that RD works only when EGSM is on, but
	 * there's no harm in enabling it anyway -- perhaps some chips
	 * will implement it!
	 */
	if (!wakeup_enable || resume_detect_interrupts_are_broken(uhci) ||
			!int_enable)
		uhci->RD_enable = int_enable = 0;

	outw(int_enable, uhci->io_addr + USBINTR);
	outw(egsm_enable | USBCMD_CF, uhci->io_addr + USBCMD);
	int_enable = USBINTR_RESUME;
	wakeup_enable = 1;

	/*
	 * In auto-stop mode, we must be able to detect new connections.
	 * The user can force us to poll by disabling remote wakeup;
	 * otherwise we will use the EGSM/RD mechanism.
	 */
	if (auto_stop) {
		if (!device_may_wakeup(&rhdev->dev))
			egsm_enable = int_enable = 0;
	}

#ifdef CONFIG_PM
	/*
	 * In bus-suspend mode, we use the wakeup setting specified
	 * for the root hub.
	 */
	else {
		if (!rhdev->do_remote_wakeup)
			wakeup_enable = 0;
	}
#endif

	/*
	 * UHCI doesn't distinguish between wakeup requests from downstream
	 * devices and local connect/disconnect events.  There's no way to
	 * enable one without the other; both are controlled by EGSM.  Thus
	 * if wakeups are disallowed then EGSM must be turned off -- in which
	 * case remote wakeup requests from downstream during system sleep
	 * will be lost.
	 *
	 * In addition, if EGSM is broken then we can't use it.  Likewise,
	 * if Resume-Detect interrupts are broken then we can't use them.
	 *
	 * Finally, neither EGSM nor RD is useful by itself.  Without EGSM,
	 * the RD status bit will never get set.  Without RD, the controller
	 * won't generate interrupts to tell the system about wakeup events.
	 */
	if (!wakeup_enable || global_suspend_mode_is_broken(uhci) ||
			resume_detect_interrupts_are_broken(uhci))
		egsm_enable = int_enable = 0;

	uhci->RD_enable = !!int_enable;
	uhci_writew(uhci, int_enable, USBINTR);
	uhci_writew(uhci, egsm_enable | USBCMD_CF, USBCMD);
	mb();
	udelay(5);

	/* If we're auto-stopping then no devices have been attached
	 * for a while, so there shouldn't be any active URBs and the
	 * controller should stop after a few microseconds.  Otherwise
	 * we will give the controller one frame to stop.
	 */
	if (!auto_stop && !(inw(uhci->io_addr + USBSTS) & USBSTS_HCH)) {
	if (!auto_stop && !(uhci_readw(uhci, USBSTS) & USBSTS_HCH)) {
		uhci->rh_state = UHCI_RH_SUSPENDING;
		spin_unlock_irq(&uhci->lock);
		msleep(1);
		spin_lock_irq(&uhci->lock);
		if (uhci->dead)
			return;
	}
	if (!(inw(uhci->io_addr + USBSTS) & USBSTS_HCH))
	if (!(uhci_readw(uhci, USBSTS) & USBSTS_HCH))
		dev_warn(uhci_dev(uhci), "Controller not stopped yet!\n");

	uhci_get_current_frame_number(uhci);

	uhci->rh_state = new_state;
	uhci->is_stopped = UHCI_IS_STOPPED;

	/* If interrupts don't work and remote wakeup is enabled then
	 * the suspended root hub needs to be polled.
	 */
	uhci_to_hcd(uhci)->poll_rh = (!int_enable && wakeup_enable);
	/*
	 * If remote wakeup is enabled but either EGSM or RD interrupts
	 * doesn't work, then we won't get an interrupt when a wakeup event
	 * occurs.  Thus the suspended root hub needs to be polled.
	 */
	if (wakeup_enable && (!int_enable || !egsm_enable))
		set_bit(HCD_FLAG_POLL_RH, &uhci_to_hcd(uhci)->flags);
	else
		clear_bit(HCD_FLAG_POLL_RH, &uhci_to_hcd(uhci)->flags);

	uhci_scan_schedule(uhci);
	uhci_fsbr_off(uhci);
}

static void start_rh(struct uhci_hcd *uhci)
{
	uhci_to_hcd(uhci)->state = HC_STATE_RUNNING;
	uhci->is_stopped = 0;

	/*
	 * Clear stale status bits on Aspeed as we get a stale HCH
	 * which causes problems later on
	 */
	if (uhci_is_aspeed(uhci))
		uhci_writew(uhci, uhci_readw(uhci, USBSTS), USBSTS);

	/* Mark it configured and running with a 64-byte max packet.
	 * All interrupts are enabled, even though RESUME won't do anything.
	 */
	outw(USBCMD_RS | USBCMD_CF | USBCMD_MAXP, uhci->io_addr + USBCMD);
	outw(USBINTR_TIMEOUT | USBINTR_RESUME | USBINTR_IOC | USBINTR_SP,
			uhci->io_addr + USBINTR);
	mb();
	uhci->rh_state = UHCI_RH_RUNNING;
	uhci_to_hcd(uhci)->poll_rh = 1;
	uhci_writew(uhci, USBCMD_RS | USBCMD_CF | USBCMD_MAXP, USBCMD);
	uhci_writew(uhci, USBINTR_TIMEOUT | USBINTR_RESUME |
		USBINTR_IOC | USBINTR_SP, USBINTR);
	mb();
	uhci->rh_state = UHCI_RH_RUNNING;
	set_bit(HCD_FLAG_POLL_RH, &uhci_to_hcd(uhci)->flags);
}

static void wakeup_rh(struct uhci_hcd *uhci)
__releases(uhci->lock)
__acquires(uhci->lock)
{
	dev_dbg(&uhci_to_hcd(uhci)->self.root_hub->dev,
			"%s%s\n", __func__,
			uhci->rh_state == UHCI_RH_AUTO_STOPPED ?
				" (auto-start)" : "");

	/* If we are auto-stopped then no devices are attached so there's
	 * no need for wakeup signals.  Otherwise we send Global Resume
	 * for 20 ms.
	 */
	if (uhci->rh_state == UHCI_RH_SUSPENDED) {
		unsigned egsm;

		/* Keep EGSM on if it was set before */
		egsm = inw(uhci->io_addr + USBCMD) & USBCMD_EGSM;
		uhci->rh_state = UHCI_RH_RESUMING;
		outw(USBCMD_FGR | USBCMD_CF | egsm, uhci->io_addr + USBCMD);
		egsm = uhci_readw(uhci, USBCMD) & USBCMD_EGSM;
		uhci->rh_state = UHCI_RH_RESUMING;
		uhci_writew(uhci, USBCMD_FGR | USBCMD_CF | egsm, USBCMD);
		spin_unlock_irq(&uhci->lock);
		msleep(20);
		spin_lock_irq(&uhci->lock);
		if (uhci->dead)
			return;

		/* End Global Resume and wait for EOP to be sent */
		outw(USBCMD_CF, uhci->io_addr + USBCMD);
		mb();
		udelay(4);
		if (inw(uhci->io_addr + USBCMD) & USBCMD_FGR)
		uhci_writew(uhci, USBCMD_CF, USBCMD);
		mb();
		udelay(4);
		if (uhci_readw(uhci, USBCMD) & USBCMD_FGR)
			dev_warn(uhci_dev(uhci), "FGR not stopped yet!\n");
	}

	start_rh(uhci);

	/* Restart root hub polling */
	mod_timer(&uhci_to_hcd(uhci)->rh_timer, jiffies);
}

static irqreturn_t uhci_irq(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	unsigned short status;

	/*
	 * Read the interrupt status, and write it back to clear the
	 * interrupt cause.  Contrary to the UHCI specification, the
	 * "HC Halted" status bit is persistent: it is RO, not R/WC.
	 */
	status = inw(uhci->io_addr + USBSTS);
	if (!(status & ~USBSTS_HCH))	/* shared interrupt, not mine */
		return IRQ_NONE;
	outw(status, uhci->io_addr + USBSTS);		/* Clear it */

	if (status & ~(USBSTS_USBINT | USBSTS_ERROR | USBSTS_RD)) {
		if (status & USBSTS_HSE)
			dev_err(uhci_dev(uhci), "host system error, "
					"PCI problems?\n");
		if (status & USBSTS_HCPE)
			dev_err(uhci_dev(uhci), "host controller process "
					"error, something bad happened!\n");
		if (status & USBSTS_HCH) {
			spin_lock(&uhci->lock);
			if (uhci->rh_state >= UHCI_RH_RUNNING) {
				dev_err(uhci_dev(uhci),
					"host controller halted, "
					"very bad!\n");
				if (debug > 1 && errbuf) {
					/* Print the schedule for debugging */
					uhci_sprint_schedule(uhci,
							errbuf, ERRBUF_LEN);
					lprintk(errbuf);
				}
				uhci_hc_died(uhci);
	status = uhci_readw(uhci, USBSTS);
	if (!(status & ~USBSTS_HCH))	/* shared interrupt, not mine */
		return IRQ_NONE;
	uhci_writew(uhci, status, USBSTS);		/* Clear it */

	spin_lock(&uhci->lock);
	if (unlikely(!uhci->is_initialized))	/* not yet configured */
		goto done;

	if (status & ~(USBSTS_USBINT | USBSTS_ERROR | USBSTS_RD)) {
		if (status & USBSTS_HSE)
			dev_err(uhci_dev(uhci),
				"host system error, PCI problems?\n");
		if (status & USBSTS_HCPE)
			dev_err(uhci_dev(uhci),
				"host controller process error, something bad happened!\n");
		if (status & USBSTS_HCH) {
			if (uhci->rh_state >= UHCI_RH_RUNNING) {
				dev_err(uhci_dev(uhci),
					"host controller halted, very bad!\n");
				if (debug > 1 && errbuf) {
					/* Print the schedule for debugging */
					uhci_sprint_schedule(uhci, errbuf,
						ERRBUF_LEN - EXTRA_SPACE);
					lprintk(errbuf);
				}
				uhci_hc_died(uhci);
				usb_hc_died(hcd);

				/* Force a callback in case there are
				 * pending unlinks */
				mod_timer(&hcd->rh_timer, jiffies);
			}
			spin_unlock(&uhci->lock);
		}
	}

	if (status & USBSTS_RD)
		usb_hcd_poll_rh_status(hcd);
	else {
		spin_lock(&uhci->lock);
		uhci_scan_schedule(uhci);
		}
	}

	if (status & USBSTS_RD) {
		spin_unlock(&uhci->lock);
		usb_hcd_poll_rh_status(hcd);
	} else {
		uhci_scan_schedule(uhci);
 done:
		spin_unlock(&uhci->lock);
	}

	return IRQ_HANDLED;
}

/*
 * Store the current frame number in uhci->frame_number if the controller
 * is runnning.  Expand from 11 bits (of which we use only 10) to a
 * is running.  Expand from 11 bits (of which we use only 10) to a
 * full-sized integer.
 *
 * Like many other parts of the driver, this code relies on being polled
 * more than once per second as long as the controller is running.
 */
static void uhci_get_current_frame_number(struct uhci_hcd *uhci)
{
	if (!uhci->is_stopped) {
		unsigned delta;

		delta = (inw(uhci->io_addr + USBFRNUM) - uhci->frame_number) &
		delta = (uhci_readw(uhci, USBFRNUM) - uhci->frame_number) &
				(UHCI_NUMFRAMES - 1);
		uhci->frame_number += delta;
	}
}

/*
 * De-allocate all resources
 */
static void release_uhci(struct uhci_hcd *uhci)
{
	int i;

	if (DEBUG_CONFIGURED) {
		spin_lock_irq(&uhci->lock);
		uhci->is_initialized = 0;
		spin_unlock_irq(&uhci->lock);

		debugfs_remove(uhci->dentry);
	}

	spin_lock_irq(&uhci->lock);
	uhci->is_initialized = 0;
	spin_unlock_irq(&uhci->lock);

	debugfs_remove(uhci->dentry);

	for (i = 0; i < UHCI_NUM_SKELQH; i++)
		uhci_free_qh(uhci, uhci->skelqh[i]);

	uhci_free_td(uhci, uhci->term_td);

	dma_pool_destroy(uhci->qh_pool);

	dma_pool_destroy(uhci->td_pool);

	kfree(uhci->frame_cpu);

	dma_free_coherent(uhci_dev(uhci),
			UHCI_NUMFRAMES * sizeof(*uhci->frame),
			uhci->frame, uhci->frame_dma_handle);
}

static int uhci_init(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	unsigned io_size = (unsigned) hcd->rsrc_len;
	int port;

	uhci->io_addr = (unsigned long) hcd->rsrc_start;

	/* The UHCI spec says devices must have 2 ports, and goes on to say
	 * they may have more but gives no way to determine how many there
	 * are.  However according to the UHCI spec, Bit 7 of the port
	 * status and control register is always set to 1.  So we try to
	 * use this to our advantage.  Another common failure mode when
	 * a nonexistent register is addressed is to return all ones, so
	 * we test for that also.
	 */
	for (port = 0; port < (io_size - USBPORTSC1) / 2; port++) {
		unsigned int portstatus;

		portstatus = inw(uhci->io_addr + USBPORTSC1 + (port * 2));
		if (!(portstatus & 0x0080) || portstatus == 0xffff)
			break;
	}
	if (debug)
		dev_info(uhci_dev(uhci), "detected %d ports\n", port);

	/* Anything greater than 7 is weird so we'll ignore it. */
	if (port > UHCI_RH_MAXCHILD) {
		dev_info(uhci_dev(uhci), "port count misdetected? "
				"forcing to 2 ports\n");
		port = 2;
	}
	uhci->rh_numports = port;

	/* Kick BIOS off this hardware and reset if the controller
	 * isn't already safely quiescent.
	 */
	check_and_reset_hc(uhci);
	return 0;
}

/* Make sure the controller is quiescent and that we're not using it
 * any more.  This is mainly for the benefit of programs which, like kexec,
 * expect the hardware to be idle: not doing DMA or generating IRQs.
 *
 * This routine may be called in a damaged or failing kernel.  Hence we
 * do not acquire the spinlock before shutting down the controller.
 */
static void uhci_shutdown(struct pci_dev *pdev)
{
	struct usb_hcd *hcd = (struct usb_hcd *) pci_get_drvdata(pdev);

	uhci_hc_died(hcd_to_uhci(hcd));
}

/*
 * Allocate a frame list, and then setup the skeleton
 *
 * The hardware doesn't really know any difference
 * in the queues, but the order does matter for the
 * protocols higher up.  The order in which the queues
 * are encountered by the hardware is:
 *
 *  - All isochronous events are handled before any
 *    of the queues. We don't do that here, because
 *    we'll create the actual TD entries on demand.
 *  - The first queue is the high-period interrupt queue.
 *  - The second queue is the period-1 interrupt and async
 *    (low-speed control, full-speed control, then bulk) queue.
 *  - The third queue is the terminating bandwidth reclamation queue,
 *    which contains no members, loops back to itself, and is present
 *    only when FSBR is on and there are no full-speed control or bulk QHs.
 */
static int uhci_start(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	int retval = -EBUSY;
	int i;
	struct dentry *dentry;

	hcd->uses_new_polling = 1;
	struct dentry __maybe_unused *dentry;

	hcd->uses_new_polling = 1;
	/* Accept arbitrarily long scatter-gather lists */
	if (!(hcd->driver->flags & HCD_LOCAL_MEM))
		hcd->self.sg_tablesize = ~0;

	spin_lock_init(&uhci->lock);
	timer_setup(&uhci->fsbr_timer, uhci_fsbr_timeout, 0);
	INIT_LIST_HEAD(&uhci->idle_qh_list);
	init_waitqueue_head(&uhci->waitqh);

	if (DEBUG_CONFIGURED) {
		dentry = debugfs_create_file(hcd->self.bus_name,
				S_IFREG|S_IRUGO|S_IWUSR, uhci_debugfs_root,
				uhci, &uhci_debug_operations);
		if (!dentry) {
			dev_err(uhci_dev(uhci), "couldn't create uhci "
					"debugfs entry\n");
			retval = -ENOMEM;
			goto err_create_debug_entry;
		}
		uhci->dentry = dentry;
	}

	uhci->frame = dma_alloc_coherent(uhci_dev(uhci),
			UHCI_NUMFRAMES * sizeof(*uhci->frame),
			&uhci->frame_dma_handle, 0);
	if (!uhci->frame) {
		dev_err(uhci_dev(uhci), "unable to allocate "
				"consistent memory for frame list\n");
#ifdef UHCI_DEBUG_OPS
	uhci->dentry = debugfs_create_file(hcd->self.bus_name,
					   S_IFREG|S_IRUGO|S_IWUSR,
					   uhci_debugfs_root, uhci,
					   &uhci_debug_operations);
#endif

	uhci->frame = dma_zalloc_coherent(uhci_dev(uhci),
			UHCI_NUMFRAMES * sizeof(*uhci->frame),
			&uhci->frame_dma_handle, GFP_KERNEL);
	if (!uhci->frame) {
		dev_err(uhci_dev(uhci),
			"unable to allocate consistent memory for frame list\n");
		goto err_alloc_frame;
	}

	uhci->frame_cpu = kcalloc(UHCI_NUMFRAMES, sizeof(*uhci->frame_cpu),
			GFP_KERNEL);
	if (!uhci->frame_cpu) {
		dev_err(uhci_dev(uhci), "unable to allocate "
				"memory for frame pointers\n");
		dev_err(uhci_dev(uhci),
			"unable to allocate memory for frame pointers\n");
	if (!uhci->frame_cpu)
		goto err_alloc_frame_cpu;

	uhci->td_pool = dma_pool_create("uhci_td", uhci_dev(uhci),
			sizeof(struct uhci_td), 16, 0);
	if (!uhci->td_pool) {
		dev_err(uhci_dev(uhci), "unable to create td dma_pool\n");
		goto err_create_td_pool;
	}

	uhci->qh_pool = dma_pool_create("uhci_qh", uhci_dev(uhci),
			sizeof(struct uhci_qh), 16, 0);
	if (!uhci->qh_pool) {
		dev_err(uhci_dev(uhci), "unable to create qh dma_pool\n");
		goto err_create_qh_pool;
	}

	uhci->term_td = uhci_alloc_td(uhci);
	if (!uhci->term_td) {
		dev_err(uhci_dev(uhci), "unable to allocate terminating TD\n");
		goto err_alloc_term_td;
	}

	for (i = 0; i < UHCI_NUM_SKELQH; i++) {
		uhci->skelqh[i] = uhci_alloc_qh(uhci, NULL, NULL);
		if (!uhci->skelqh[i]) {
			dev_err(uhci_dev(uhci), "unable to allocate QH\n");
			goto err_alloc_skelqh;
		}
	}

	/*
	 * 8 Interrupt queues; link all higher int queues to int1 = async
	 */
	for (i = SKEL_ISO + 1; i < SKEL_ASYNC; ++i)
		uhci->skelqh[i]->link = LINK_TO_QH(uhci->skel_async_qh);
	uhci->skel_async_qh->link = UHCI_PTR_TERM;
	uhci->skel_term_qh->link = LINK_TO_QH(uhci->skel_term_qh);

	/* This dummy TD is to work around a bug in Intel PIIX controllers */
	uhci_fill_td(uhci->term_td, 0, uhci_explen(0) |
			(0x7f << TD_TOKEN_DEVADDR_SHIFT) | USB_PID_IN, 0);
	uhci->term_td->link = UHCI_PTR_TERM;
	uhci->skel_async_qh->element = uhci->skel_term_qh->element =
			LINK_TO_TD(uhci->term_td);
		uhci->skelqh[i]->link = LINK_TO_QH(uhci, uhci->skel_async_qh);
	uhci->skel_async_qh->link = UHCI_PTR_TERM(uhci);
	uhci->skel_term_qh->link = LINK_TO_QH(uhci, uhci->skel_term_qh);

	/* This dummy TD is to work around a bug in Intel PIIX controllers */
	uhci_fill_td(uhci, uhci->term_td, 0, uhci_explen(0) |
			(0x7f << TD_TOKEN_DEVADDR_SHIFT) | USB_PID_IN, 0);
	uhci->term_td->link = UHCI_PTR_TERM(uhci);
	uhci->skel_async_qh->element = uhci->skel_term_qh->element =
		LINK_TO_TD(uhci, uhci->term_td);

	/*
	 * Fill the frame list: make all entries point to the proper
	 * interrupt queue.
	 */
	for (i = 0; i < UHCI_NUMFRAMES; i++) {

		/* Only place we don't use the frame list routines */
		uhci->frame[i] = uhci_frame_skel_link(uhci, i);
	}

	/*
	 * Some architectures require a full mb() to enforce completion of
	 * the memory writes above before the I/O transfers in configure_hc().
	 */
	mb();

	configure_hc(uhci);
	uhci->is_initialized = 1;
	start_rh(uhci);
	spin_lock_irq(&uhci->lock);
	configure_hc(uhci);
	uhci->is_initialized = 1;
	start_rh(uhci);
	spin_unlock_irq(&uhci->lock);
	return 0;

/*
 * error exits:
 */
err_alloc_skelqh:
	for (i = 0; i < UHCI_NUM_SKELQH; i++) {
		if (uhci->skelqh[i])
			uhci_free_qh(uhci, uhci->skelqh[i]);
	}

	uhci_free_td(uhci, uhci->term_td);

err_alloc_term_td:
	dma_pool_destroy(uhci->qh_pool);

err_create_qh_pool:
	dma_pool_destroy(uhci->td_pool);

err_create_td_pool:
	kfree(uhci->frame_cpu);

err_alloc_frame_cpu:
	dma_free_coherent(uhci_dev(uhci),
			UHCI_NUMFRAMES * sizeof(*uhci->frame),
			uhci->frame, uhci->frame_dma_handle);

err_alloc_frame:
	debugfs_remove(uhci->dentry);

err_create_debug_entry:
	return retval;
}

static void uhci_stop(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);

	spin_lock_irq(&uhci->lock);
	if (test_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags) && !uhci->dead)
		uhci_hc_died(uhci);
	uhci_scan_schedule(uhci);
	spin_unlock_irq(&uhci->lock);
	if (HCD_HW_ACCESSIBLE(hcd) && !uhci->dead)
		uhci_hc_died(uhci);
	uhci_scan_schedule(uhci);
	spin_unlock_irq(&uhci->lock);
	synchronize_irq(hcd->irq);

	del_timer_sync(&uhci->fsbr_timer);
	release_uhci(uhci);
}

#ifdef CONFIG_PM
static int uhci_rh_suspend(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	int rc = 0;

	spin_lock_irq(&uhci->lock);
	if (!test_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags))
		rc = -ESHUTDOWN;
	else if (!uhci->dead)
	if (!HCD_HW_ACCESSIBLE(hcd))
		rc = -ESHUTDOWN;
	else if (uhci->dead)
		;		/* Dead controllers tell no tales */

	/* Once the controller is stopped, port resumes that are already
	 * in progress won't complete.  Hence if remote wakeup is enabled
	 * for the root hub and any ports are in the middle of a resume or
	 * remote wakeup, we must fail the suspend.
	 */
	else if (hcd->self.root_hub->do_remote_wakeup &&
			uhci->resuming_ports) {
		dev_dbg(uhci_dev(uhci),
			"suspend failed because a port is resuming\n");
		rc = -EBUSY;
	} else
		suspend_rh(uhci, UHCI_RH_SUSPENDED);
	spin_unlock_irq(&uhci->lock);
	return rc;
}

static int uhci_rh_resume(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	int rc = 0;

	spin_lock_irq(&uhci->lock);
	if (!test_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags))
	if (!HCD_HW_ACCESSIBLE(hcd))
		rc = -ESHUTDOWN;
	else if (!uhci->dead)
		wakeup_rh(uhci);
	spin_unlock_irq(&uhci->lock);
	return rc;
}

static int uhci_pci_suspend(struct usb_hcd *hcd, pm_message_t message)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	int rc = 0;

	dev_dbg(uhci_dev(uhci), "%s\n", __func__);

	spin_lock_irq(&uhci->lock);
	if (!test_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags) || uhci->dead)
		goto done_okay;		/* Already suspended or dead */

	if (uhci->rh_state > UHCI_RH_SUSPENDED) {
		dev_warn(uhci_dev(uhci), "Root hub isn't suspended!\n");
		rc = -EBUSY;
		goto done;
	};

	/* All PCI host controllers are required to disable IRQ generation
	 * at the source, so we must turn off PIRQ.
	 */
	pci_write_config_word(to_pci_dev(uhci_dev(uhci)), USBLEGSUP, 0);
	mb();
	hcd->poll_rh = 0;

	/* FIXME: Enable non-PME# remote wakeup? */

	/* make sure snapshot being resumed re-enumerates everything */
	if (message.event == PM_EVENT_PRETHAW)
		uhci_hc_died(uhci);

done_okay:
	clear_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
done:
	spin_unlock_irq(&uhci->lock);
	return rc;
}

static int uhci_pci_resume(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);

	dev_dbg(uhci_dev(uhci), "%s\n", __func__);

	/* Since we aren't in D3 any more, it's safe to set this flag
	 * even if the controller was dead.
	 */
	set_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	mb();

	spin_lock_irq(&uhci->lock);

	/* FIXME: Disable non-PME# remote wakeup? */

	/* The firmware or a boot kernel may have changed the controller
	 * settings during a system wakeup.  Check it and reconfigure
	 * to avoid problems.
	 */
	check_and_reset_hc(uhci);

	/* If the controller was dead before, it's back alive now */
	configure_hc(uhci);

	if (uhci->rh_state == UHCI_RH_RESET) {

		/* The controller had to be reset */
		usb_root_hub_lost_power(hcd->self.root_hub);
		suspend_rh(uhci, UHCI_RH_SUSPENDED);
	}

	spin_unlock_irq(&uhci->lock);

	/* If interrupts don't work and remote wakeup is enabled then
	 * the suspended root hub needs to be polled.
	 */
	if (!uhci->RD_enable && hcd->self.root_hub->do_remote_wakeup) {
		hcd->poll_rh = 1;
		usb_hcd_poll_rh_status(hcd);
	}
	return 0;
}
#endif

/* Wait until a particular device/endpoint's QH is idle, and free it */
static void uhci_hcd_endpoint_disable(struct usb_hcd *hcd,
		struct usb_host_endpoint *hep)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	struct uhci_qh *qh;

	spin_lock_irq(&uhci->lock);
	qh = (struct uhci_qh *) hep->hcpriv;
	if (qh == NULL)
		goto done;

	while (qh->state != QH_STATE_IDLE) {
		++uhci->num_waiting;
		spin_unlock_irq(&uhci->lock);
		wait_event_interruptible(uhci->waitqh,
				qh->state == QH_STATE_IDLE);
		spin_lock_irq(&uhci->lock);
		--uhci->num_waiting;
	}

	uhci_free_qh(uhci, qh);
done:
	spin_unlock_irq(&uhci->lock);
}

static int uhci_hcd_get_frame_number(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	unsigned frame_number;
	unsigned delta;

	/* Minimize latency by avoiding the spinlock */
	frame_number = uhci->frame_number;
	barrier();
	delta = (inw(uhci->io_addr + USBFRNUM) - frame_number) &
	delta = (uhci_readw(uhci, USBFRNUM) - frame_number) &
			(UHCI_NUMFRAMES - 1);
	return frame_number + delta;
}

static const char hcd_name[] = "uhci_hcd";

static const struct hc_driver uhci_driver = {
	.description =		hcd_name,
	.product_desc =		"UHCI Host Controller",
	.hcd_priv_size =	sizeof(struct uhci_hcd),

	/* Generic hardware linkage */
	.irq =			uhci_irq,
	.flags =		HCD_USB11,

	/* Basic lifecycle operations */
	.reset =		uhci_init,
	.start =		uhci_start,
#ifdef CONFIG_PM
	.pci_suspend =		uhci_pci_suspend,
	.pci_resume =		uhci_pci_resume,
	.bus_suspend =		uhci_rh_suspend,
	.bus_resume =		uhci_rh_resume,
#endif
	.stop =			uhci_stop,

	.urb_enqueue =		uhci_urb_enqueue,
	.urb_dequeue =		uhci_urb_dequeue,

	.endpoint_disable =	uhci_hcd_endpoint_disable,
	.get_frame_number =	uhci_hcd_get_frame_number,

	.hub_status_data =	uhci_hub_status_data,
	.hub_control =		uhci_hub_control,
};

static const struct pci_device_id uhci_pci_ids[] = { {
	/* handle any USB UHCI controller */
	PCI_DEVICE_CLASS(PCI_CLASS_SERIAL_USB_UHCI, ~0),
	.driver_data =	(unsigned long) &uhci_driver,
	}, { /* end: all zeroes */ }
};

MODULE_DEVICE_TABLE(pci, uhci_pci_ids);

static struct pci_driver uhci_pci_driver = {
	.name =		(char *)hcd_name,
	.id_table =	uhci_pci_ids,

	.probe =	usb_hcd_pci_probe,
	.remove =	usb_hcd_pci_remove,
	.shutdown =	uhci_shutdown,

#ifdef	CONFIG_PM
	.suspend =	usb_hcd_pci_suspend,
	.resume =	usb_hcd_pci_resume,
#endif	/* PM */
};
 
/* Determines number of ports on controller */
static int uhci_count_ports(struct usb_hcd *hcd)
{
	struct uhci_hcd *uhci = hcd_to_uhci(hcd);
	unsigned io_size = (unsigned) hcd->rsrc_len;
	int port;

	/* The UHCI spec says devices must have 2 ports, and goes on to say
	 * they may have more but gives no way to determine how many there
	 * are.  However according to the UHCI spec, Bit 7 of the port
	 * status and control register is always set to 1.  So we try to
	 * use this to our advantage.  Another common failure mode when
	 * a nonexistent register is addressed is to return all ones, so
	 * we test for that also.
	 */
	for (port = 0; port < (io_size - USBPORTSC1) / 2; port++) {
		unsigned int portstatus;

		portstatus = uhci_readw(uhci, USBPORTSC1 + (port * 2));
		if (!(portstatus & 0x0080) || portstatus == 0xffff)
			break;
	}
	if (debug)
		dev_info(uhci_dev(uhci), "detected %d ports\n", port);

	/* Anything greater than 7 is weird so we'll ignore it. */
	if (port > UHCI_RH_MAXCHILD) {
		dev_info(uhci_dev(uhci),
			"port count misdetected? forcing to 2 ports\n");
		port = 2;
	}

	return port;
}

static const char hcd_name[] = "uhci_hcd";

#ifdef CONFIG_USB_PCI
#include "uhci-pci.c"
#define	PCI_DRIVER		uhci_pci_driver
#endif

#ifdef CONFIG_SPARC_LEON
#include "uhci-grlib.c"
#define PLATFORM_DRIVER		uhci_grlib_driver
#endif

#ifdef CONFIG_USB_UHCI_PLATFORM
#include "uhci-platform.c"
#define PLATFORM_DRIVER		uhci_platform_driver
#endif

#if !defined(PCI_DRIVER) && !defined(PLATFORM_DRIVER)
#error "missing bus glue for uhci-hcd"
#endif

static int __init uhci_hcd_init(void)
{
	int retval = -ENOMEM;

	printk(KERN_INFO DRIVER_DESC " " DRIVER_VERSION "%s\n",
			ignore_oc ? ", overcurrent ignored" : "");

	if (usb_disabled())
		return -ENODEV;

	if (DEBUG_CONFIGURED) {
		errbuf = kmalloc(ERRBUF_LEN, GFP_KERNEL);
		if (!errbuf)
			goto errbuf_failed;
		uhci_debugfs_root = debugfs_create_dir("uhci", NULL);
		if (!uhci_debugfs_root)
			goto debug_failed;
	}
	if (usb_disabled())
		return -ENODEV;

	printk(KERN_INFO "uhci_hcd: " DRIVER_DESC "%s\n",
			ignore_oc ? ", overcurrent ignored" : "");
	set_bit(USB_UHCI_LOADED, &usb_hcds_loaded);

#ifdef CONFIG_DYNAMIC_DEBUG
	errbuf = kmalloc(ERRBUF_LEN, GFP_KERNEL);
	if (!errbuf)
		goto errbuf_failed;
	uhci_debugfs_root = debugfs_create_dir("uhci", usb_debug_root);
#endif

	uhci_up_cachep = kmem_cache_create("uhci_urb_priv",
		sizeof(struct urb_priv), 0, 0, NULL);
	if (!uhci_up_cachep)
		goto up_failed;

	retval = pci_register_driver(&uhci_pci_driver);
	if (retval)
		goto init_failed;

	return 0;

init_failed:
	kmem_cache_destroy(uhci_up_cachep);

up_failed:
#ifdef PLATFORM_DRIVER
	retval = platform_driver_register(&PLATFORM_DRIVER);
	if (retval < 0)
		goto clean0;
#endif

#ifdef PCI_DRIVER
	retval = pci_register_driver(&PCI_DRIVER);
	if (retval < 0)
		goto clean1;
#endif

	return 0;

#ifdef PCI_DRIVER
clean1:
#endif
#ifdef PLATFORM_DRIVER
	platform_driver_unregister(&PLATFORM_DRIVER);
clean0:
#endif
	kmem_cache_destroy(uhci_up_cachep);

up_failed:
#if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG)
	debugfs_remove(uhci_debugfs_root);

	kfree(errbuf);

errbuf_failed:

#endif

	clear_bit(USB_UHCI_LOADED, &usb_hcds_loaded);
	return retval;
}

static void __exit uhci_hcd_cleanup(void) 
{
	pci_unregister_driver(&uhci_pci_driver);
	kmem_cache_destroy(uhci_up_cachep);
	debugfs_remove(uhci_debugfs_root);
	kfree(errbuf);
#ifdef PLATFORM_DRIVER
	platform_driver_unregister(&PLATFORM_DRIVER);
#endif
#ifdef PCI_DRIVER
	pci_unregister_driver(&PCI_DRIVER);
#endif
	kmem_cache_destroy(uhci_up_cachep);
	debugfs_remove(uhci_debugfs_root);
#ifdef CONFIG_DYNAMIC_DEBUG
	kfree(errbuf);
#endif
	clear_bit(USB_UHCI_LOADED, &usb_hcds_loaded);
}

module_init(uhci_hcd_init);
module_exit(uhci_hcd_cleanup);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
