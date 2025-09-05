/*
 * Copyright (C) 2005-2007 by Texas Instruments
 * Some code has been taken from tusb6010.c
 * Copyrights for that are attributable to:
 * Copyright (C) 2006 Nokia Corporation
 * Jarkko Nikula <jarkko.nikula@nokia.com>
 * Tony Lindgren <tony@atomide.com>
 *
 * This file is part of the Inventra Controller Driver for Linux.
 *
 * The Inventra Controller Driver for Linux is free software; you
 * can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *
 * The Inventra Controller Driver for Linux is distributed in
 * the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with The Inventra Controller Driver for Linux ; if not,
 * write to the Free Software Foundation, Inc., 59 Temple Place,
 * Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/clk.h>
#include <linux/io.h>

#include <asm/mach-types.h>
#include <mach/hardware.h>
#include <mach/mux.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/pm_runtime.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/usb/musb.h>
#include <linux/phy/omap_control_phy.h>
#include <linux/of_platform.h>

#include "musb_core.h"
#include "omap2430.h"

#ifdef CONFIG_ARCH_OMAP3430
#define	get_cpu_rev()	2
#endif

#define MUSB_TIMEOUT_A_WAIT_BCON	1100
struct omap2430_glue {
	struct device		*dev;
	struct platform_device	*musb;
	enum musb_vbus_id_status status;
	struct work_struct	omap_musb_mailbox_work;
	struct device		*control_otghs;
};
#define glue_to_musb(g)		platform_get_drvdata(g->musb)

static struct omap2430_glue	*_glue;

static struct timer_list musb_idle_timer;

static void musb_do_idle(unsigned long _musb)
{
	struct musb	*musb = (void *)_musb;
	unsigned long	flags;
	u8	power;
	u8	devctl;

	devctl = musb_readb(musb->mregs, MUSB_DEVCTL);

	spin_lock_irqsave(&musb->lock, flags);

	switch (musb->xceiv.state) {
	case OTG_STATE_A_WAIT_BCON:
		devctl &= ~MUSB_DEVCTL_SESSION;
		musb_writeb(musb->mregs, MUSB_DEVCTL, devctl);

		devctl = musb_readb(musb->mregs, MUSB_DEVCTL);
		if (devctl & MUSB_DEVCTL_BDEVICE) {
			musb->xceiv.state = OTG_STATE_B_IDLE;
			MUSB_DEV_MODE(musb);
		} else {
			musb->xceiv.state = OTG_STATE_A_IDLE;
			MUSB_HST_MODE(musb);
		}
		break;
#ifdef CONFIG_USB_MUSB_HDRC_HCD
	spin_lock_irqsave(&musb->lock, flags);

	switch (musb->xceiv->otg->state) {
	case OTG_STATE_A_WAIT_BCON:

		devctl = musb_readb(musb->mregs, MUSB_DEVCTL);
		if (devctl & MUSB_DEVCTL_BDEVICE) {
			musb->xceiv->otg->state = OTG_STATE_B_IDLE;
			MUSB_DEV_MODE(musb);
		} else {
			musb->xceiv->otg->state = OTG_STATE_A_IDLE;
			MUSB_HST_MODE(musb);
		}
		break;
	case OTG_STATE_A_SUSPEND:
		/* finish RESUME signaling? */
		if (musb->port1_status & MUSB_PORT_STAT_RESUME) {
			power = musb_readb(musb->mregs, MUSB_POWER);
			power &= ~MUSB_POWER_RESUME;
			DBG(1, "root port resume stopped, power %02x\n", power);
			dev_dbg(musb->controller, "root port resume stopped, power %02x\n", power);
			musb_writeb(musb->mregs, MUSB_POWER, power);
			musb->is_active = 1;
			musb->port1_status &= ~(USB_PORT_STAT_SUSPEND
						| MUSB_PORT_STAT_RESUME);
			musb->port1_status |= USB_PORT_STAT_C_SUSPEND << 16;
			usb_hcd_poll_rh_status(musb_to_hcd(musb));
			/* NOTE: it might really be A_WAIT_BCON ... */
			musb->xceiv.state = OTG_STATE_A_HOST;
		}
		break;
#endif
#ifdef CONFIG_USB_MUSB_HDRC_HCD
	case OTG_STATE_A_HOST:
		devctl = musb_readb(musb->mregs, MUSB_DEVCTL);
		if (devctl &  MUSB_DEVCTL_BDEVICE)
			musb->xceiv.state = OTG_STATE_B_IDLE;
		else
			musb->xceiv.state = OTG_STATE_A_WAIT_BCON;
#endif
			usb_hcd_poll_rh_status(musb->hcd);
			/* NOTE: it might really be A_WAIT_BCON ... */
			musb->xceiv->otg->state = OTG_STATE_A_HOST;
		}
		break;
	case OTG_STATE_A_HOST:
		devctl = musb_readb(musb->mregs, MUSB_DEVCTL);
		if (devctl &  MUSB_DEVCTL_BDEVICE)
			musb->xceiv->otg->state = OTG_STATE_B_IDLE;
		else
			musb->xceiv->otg->state = OTG_STATE_A_WAIT_BCON;
	default:
		break;
	}
	spin_unlock_irqrestore(&musb->lock, flags);
}


void musb_platform_try_idle(struct musb *musb, unsigned long timeout)
static void omap2430_musb_try_idle(struct musb *musb, unsigned long timeout)
{
	unsigned long		default_timeout = jiffies + msecs_to_jiffies(3);
	static unsigned long	last_timer;

	if (timeout == 0)
		timeout = default_timeout;

	/* Never idle if active, or when VBUS timeout is not set as host */
	if (musb->is_active || ((musb->a_wait_bcon == 0)
			&& (musb->xceiv.state == OTG_STATE_A_WAIT_BCON))) {
		DBG(4, "%s active, deleting timer\n", otg_state_string(musb));
			&& (musb->xceiv->otg->state == OTG_STATE_A_WAIT_BCON))) {
		dev_dbg(musb->controller, "%s active, deleting timer\n",
			usb_otg_state_string(musb->xceiv->otg->state));
		del_timer(&musb_idle_timer);
		last_timer = jiffies;
		return;
	}

	if (time_after(last_timer, timeout)) {
		if (!timer_pending(&musb_idle_timer))
			last_timer = timeout;
		else {
			DBG(4, "Longer idle timer already pending, ignoring\n");
			dev_dbg(musb->controller, "Longer idle timer already pending, ignoring\n");
			return;
		}
	}
	last_timer = timeout;

	DBG(4, "%s inactive, for idle timer for %lu ms\n",
		otg_state_string(musb),
	dev_dbg(musb->controller, "%s inactive, for idle timer for %lu ms\n",
		usb_otg_state_string(musb->xceiv->otg->state),
		(unsigned long)jiffies_to_msecs(timeout - jiffies));
	mod_timer(&musb_idle_timer, timeout);
}

void musb_platform_enable(struct musb *musb)
{
}
void musb_platform_disable(struct musb *musb)
{
}
static void omap_vbus_power(struct musb *musb, int is_on, int sleeping)
{
}

static void omap_set_vbus(struct musb *musb, int is_on)
{
	u8		devctl;
static void omap2430_musb_set_vbus(struct musb *musb, int is_on)
{
	struct usb_otg	*otg = musb->xceiv->otg;
	u8		devctl;
	unsigned long timeout = jiffies + msecs_to_jiffies(1000);
	/* HDRC controls CPEN, but beware current surges during device
	 * connect.  They can trigger transient overcurrent conditions
	 * that must be ignored.
	 */

	devctl = musb_readb(musb->mregs, MUSB_DEVCTL);

	if (is_on) {
		musb->is_active = 1;
		musb->xceiv.default_a = 1;
		musb->xceiv.state = OTG_STATE_A_WAIT_VRISE;
		devctl |= MUSB_DEVCTL_SESSION;

		MUSB_HST_MODE(musb);
		if (musb->xceiv->otg->state == OTG_STATE_A_IDLE) {
			int loops = 100;
			/* start the session */
			devctl |= MUSB_DEVCTL_SESSION;
			musb_writeb(musb->mregs, MUSB_DEVCTL, devctl);
			/*
			 * Wait for the musb to set as A device to enable the
			 * VBUS
			 */
			while (musb_readb(musb->mregs, MUSB_DEVCTL) &
			       MUSB_DEVCTL_BDEVICE) {

				mdelay(5);
				cpu_relax();

				if (time_after(jiffies, timeout)
				    || loops-- <= 0) {
					dev_err(musb->controller,
					"configured as A device timeout");
					break;
				}
			}

			otg_set_vbus(otg, 1);
		} else {
			musb->is_active = 1;
			otg->default_a = 1;
			musb->xceiv->otg->state = OTG_STATE_A_WAIT_VRISE;
			devctl |= MUSB_DEVCTL_SESSION;
			MUSB_HST_MODE(musb);
		}
	} else {
		musb->is_active = 0;

		/* NOTE:  we're skipping A_WAIT_VFALL -> A_IDLE and
		 * jumping right to B_IDLE...
		 */

		musb->xceiv.default_a = 0;
		musb->xceiv.state = OTG_STATE_B_IDLE;
		otg->default_a = 0;
		musb->xceiv->otg->state = OTG_STATE_B_IDLE;
		devctl &= ~MUSB_DEVCTL_SESSION;

		MUSB_DEV_MODE(musb);
	}
	musb_writeb(musb->mregs, MUSB_DEVCTL, devctl);

	DBG(1, "VBUS %s, devctl %02x "
		/* otg %3x conf %08x prcm %08x */ "\n",
		otg_state_string(musb),
		musb_readb(musb->mregs, MUSB_DEVCTL));
}
static int omap_set_power(struct otg_transceiver *x, unsigned mA)
{
	return 0;
}

static int musb_platform_resume(struct musb *musb);

void musb_platform_set_mode(struct musb *musb, u8 musb_mode)
	dev_dbg(musb->controller, "VBUS %s, devctl %02x "
		/* otg %3x conf %08x prcm %08x */ "\n",
		usb_otg_state_string(musb->xceiv->otg->state),
		musb_readb(musb->mregs, MUSB_DEVCTL));
}

static int omap2430_musb_set_mode(struct musb *musb, u8 musb_mode)
{
	u8	devctl = musb_readb(musb->mregs, MUSB_DEVCTL);

	devctl |= MUSB_DEVCTL_SESSION;
	musb_writeb(musb->mregs, MUSB_DEVCTL, devctl);

	switch (musb_mode) {
	case MUSB_HOST:
		otg_set_host(&musb->xceiv, musb->xceiv.host);
		break;
	case MUSB_PERIPHERAL:
		otg_set_peripheral(&musb->xceiv, musb->xceiv.gadget);
		break;
	case MUSB_OTG:
	return 0;
}

static inline void omap2430_low_level_exit(struct musb *musb)
{
	u32 l;

	/* in any role */
	l = musb_readl(musb->mregs, OTG_FORCESTDBY);
	l |= ENABLEFORCE;	/* enable MSTANDBY */
	musb_writel(musb->mregs, OTG_FORCESTDBY, l);
}

static inline void omap2430_low_level_init(struct musb *musb)
{
	u32 l;

	l = musb_readl(musb->mregs, OTG_FORCESTDBY);
	l &= ~ENABLEFORCE;	/* disable MSTANDBY */
	musb_writel(musb->mregs, OTG_FORCESTDBY, l);
}

static int omap2430_musb_mailbox(enum musb_vbus_id_status status)
{
	struct omap2430_glue	*glue = _glue;

	if (!glue) {
		pr_err("%s: musb core is not yet initialized\n", __func__);
		return -EPROBE_DEFER;
	}
	glue->status = status;

	if (!glue_to_musb(glue)) {
		pr_err("%s: musb core is not yet ready\n", __func__);
		return -EPROBE_DEFER;
	}

	schedule_work(&glue->omap_musb_mailbox_work);

	return 0;
}

static void omap_musb_set_mailbox(struct omap2430_glue *glue)
{
	struct musb *musb = glue_to_musb(glue);
	struct musb_hdrc_platform_data *pdata =
		dev_get_platdata(musb->controller);
	struct omap_musb_board_data *data = pdata->board_data;
	struct usb_otg *otg = musb->xceiv->otg;

	pm_runtime_get_sync(musb->controller);
	switch (glue->status) {
	case MUSB_ID_GROUND:
		dev_dbg(musb->controller, "ID GND\n");

		otg->default_a = true;
		musb->xceiv->otg->state = OTG_STATE_A_IDLE;
		musb->xceiv->last_event = USB_EVENT_ID;
		if (musb->gadget_driver) {
			omap_control_usb_set_mode(glue->control_otghs,
				USB_MODE_HOST);
			omap2430_musb_set_vbus(musb, 1);
		}
		break;

	case MUSB_VBUS_VALID:
		dev_dbg(musb->controller, "VBUS Connect\n");

		otg->default_a = false;
		musb->xceiv->otg->state = OTG_STATE_B_IDLE;
		musb->xceiv->last_event = USB_EVENT_VBUS;
		omap_control_usb_set_mode(glue->control_otghs, USB_MODE_DEVICE);
		break;

	case MUSB_ID_FLOAT:
	case MUSB_VBUS_OFF:
		dev_dbg(musb->controller, "VBUS Disconnect\n");

		musb->xceiv->last_event = USB_EVENT_NONE;
		if (musb->gadget_driver)
			omap2430_musb_set_vbus(musb, 0);

		if (data->interface_type == MUSB_INTERFACE_UTMI)
			otg_set_vbus(musb->xceiv->otg, 0);

		omap_control_usb_set_mode(glue->control_otghs,
			USB_MODE_DISCONNECT);
		break;
	default:
		dev_dbg(musb->controller, "ID float\n");
	}
	pm_runtime_mark_last_busy(musb->controller);
	pm_runtime_put_autosuspend(musb->controller);
	atomic_notifier_call_chain(&musb->xceiv->notifier,
			musb->xceiv->last_event, NULL);
}


static void omap_musb_mailbox_work(struct work_struct *mailbox_work)
{
	struct omap2430_glue *glue = container_of(mailbox_work,
				struct omap2430_glue, omap_musb_mailbox_work);

	omap_musb_set_mailbox(glue);
}

static irqreturn_t omap2430_musb_interrupt(int irq, void *__hci)
{
	unsigned long   flags;
	irqreturn_t     retval = IRQ_NONE;
	struct musb     *musb = __hci;

	spin_lock_irqsave(&musb->lock, flags);

	musb->int_usb = musb_readb(musb->mregs, MUSB_INTRUSB);
	musb->int_tx = musb_readw(musb->mregs, MUSB_INTRTX);
	musb->int_rx = musb_readw(musb->mregs, MUSB_INTRRX);

	if (musb->int_usb || musb->int_tx || musb->int_rx)
		retval = musb_interrupt(musb);

	spin_unlock_irqrestore(&musb->lock, flags);

	return retval;
}

static int omap2430_musb_init(struct musb *musb)
{
	u32 l;
	int status = 0;
	struct device *dev = musb->controller;
	struct omap2430_glue *glue = dev_get_drvdata(dev->parent);
	struct musb_hdrc_platform_data *plat = dev_get_platdata(dev);
	struct omap_musb_board_data *data = plat->board_data;

	/* We require some kind of external transceiver, hooked
	 * up through ULPI.  TWL4030-family PMICs include one,
	 * which needs a driver, drivers aren't always needed.
	 */
	if (dev->parent->of_node) {
		musb->phy = devm_phy_get(dev->parent, "usb2-phy");

		/* We can't totally remove musb->xceiv as of now because
		 * musb core uses xceiv.state and xceiv.otg. Once we have
		 * a separate state machine to handle otg, these can be moved
		 * out of xceiv and then we can start using the generic PHY
		 * framework
		 */
		musb->xceiv = devm_usb_get_phy_by_phandle(dev->parent,
		    "usb-phy", 0);
	} else {
		musb->xceiv = devm_usb_get_phy_dev(dev, 0);
		musb->phy = devm_phy_get(dev, "usb");
	}

	if (IS_ERR(musb->xceiv)) {
		status = PTR_ERR(musb->xceiv);

		if (status == -ENXIO)
			return status;

		dev_dbg(dev, "HS USB OTG: no transceiver configured\n");
		return -EPROBE_DEFER;
	}

	if (IS_ERR(musb->phy)) {
		dev_err(dev, "HS USB OTG: no PHY configured\n");
		return PTR_ERR(musb->phy);
	}
	musb->isr = omap2430_musb_interrupt;
	phy_init(musb->phy);
	phy_power_on(musb->phy);

	l = musb_readl(musb->mregs, OTG_INTERFSEL);

	if (data->interface_type == MUSB_INTERFACE_UTMI) {
		/* OMAP4 uses Internal PHY GS70 which uses UTMI interface */
		l &= ~ULPI_12PIN;       /* Disable ULPI */
		l |= UTMI_8BIT;         /* Enable UTMI  */
	} else {
		l |= ULPI_12PIN;
	}

	musb_writel(musb->mregs, OTG_INTERFSEL, l);

	dev_dbg(dev, "HS USB OTG: revision 0x%x, sysconfig 0x%02x, "
			"sysstatus 0x%x, intrfsel 0x%x, simenable  0x%x\n",
			musb_readl(musb->mregs, OTG_REVISION),
			musb_readl(musb->mregs, OTG_SYSCONFIG),
			musb_readl(musb->mregs, OTG_SYSSTATUS),
			musb_readl(musb->mregs, OTG_INTERFSEL),
			musb_readl(musb->mregs, OTG_SIMENABLE));

	if (glue->status != MUSB_UNKNOWN)
		omap_musb_set_mailbox(glue);

	return 0;
}

static void omap2430_musb_enable(struct musb *musb)
{
	u8		devctl;
	unsigned long timeout = jiffies + msecs_to_jiffies(1000);
	struct device *dev = musb->controller;
	struct omap2430_glue *glue = dev_get_drvdata(dev->parent);
	struct musb_hdrc_platform_data *pdata = dev_get_platdata(dev);
	struct omap_musb_board_data *data = pdata->board_data;


	switch (glue->status) {

	case MUSB_ID_GROUND:
		omap_control_usb_set_mode(glue->control_otghs, USB_MODE_HOST);
		if (data->interface_type != MUSB_INTERFACE_UTMI)
			break;
		devctl = musb_readb(musb->mregs, MUSB_DEVCTL);
		/* start the session */
		devctl |= MUSB_DEVCTL_SESSION;
		musb_writeb(musb->mregs, MUSB_DEVCTL, devctl);
		while (musb_readb(musb->mregs, MUSB_DEVCTL) &
				MUSB_DEVCTL_BDEVICE) {
			cpu_relax();

			if (time_after(jiffies, timeout)) {
				dev_err(dev, "configured as A device timeout");
				break;
			}
		}
		break;

	case MUSB_VBUS_VALID:
		omap_control_usb_set_mode(glue->control_otghs, USB_MODE_DEVICE);
		break;

	default:
		break;
	}
}

int __init musb_platform_init(struct musb *musb)
{
	u32 l;

#if defined(CONFIG_ARCH_OMAP2430)
	omap_cfg_reg(AE5_2430_USB0HS_STP);
#endif

	musb_platform_resume(musb);

	l = omap_readl(OTG_SYSCONFIG);
	l &= ~ENABLEWAKEUP;	/* disable wakeup */
	l &= ~NOSTDBY;		/* remove possible nostdby */
	l |= SMARTSTDBY;	/* enable smart standby */
	l &= ~AUTOIDLE;		/* disable auto idle */
	l &= ~NOIDLE;		/* remove possible noidle */
	l |= SMARTIDLE;		/* enable smart idle */
	l |= AUTOIDLE;		/* enable auto idle */
	omap_writel(l, OTG_SYSCONFIG);

	l = omap_readl(OTG_INTERFSEL);
	l |= ULPI_12PIN;
	omap_writel(l, OTG_INTERFSEL);

	pr_debug("HS USB OTG: revision 0x%x, sysconfig 0x%02x, "
			"sysstatus 0x%x, intrfsel 0x%x, simenable  0x%x\n",
			omap_readl(OTG_REVISION), omap_readl(OTG_SYSCONFIG),
			omap_readl(OTG_SYSSTATUS), omap_readl(OTG_INTERFSEL),
			omap_readl(OTG_SIMENABLE));

	omap_vbus_power(musb, musb->board_mode == MUSB_HOST, 1);

	if (is_host_enabled(musb))
		musb->board_set_vbus = omap_set_vbus;
	if (is_peripheral_enabled(musb))
		musb->xceiv.set_power = omap_set_power;
	musb->a_wait_bcon = MUSB_TIMEOUT_A_WAIT_BCON;

	setup_timer(&musb_idle_timer, musb_do_idle, (unsigned long) musb);

	return 0;
}

int musb_platform_suspend(struct musb *musb)
{
	u32 l;

	if (!musb->clock)
		return 0;

	/* in any role */
	l = omap_readl(OTG_FORCESTDBY);
	l |= ENABLEFORCE;	/* enable MSTANDBY */
	omap_writel(l, OTG_FORCESTDBY);

	l = omap_readl(OTG_SYSCONFIG);
	l |= ENABLEWAKEUP;	/* enable wakeup */
	omap_writel(l, OTG_SYSCONFIG);

	if (musb->xceiv.set_suspend)
		musb->xceiv.set_suspend(&musb->xceiv, 1);

	if (musb->set_clock)
		musb->set_clock(musb->clock, 0);
	else
		clk_disable(musb->clock);

	return 0;
}

static int musb_platform_resume(struct musb *musb)
{
	u32 l;

	if (!musb->clock)
		return 0;

	if (musb->xceiv.set_suspend)
		musb->xceiv.set_suspend(&musb->xceiv, 0);

	if (musb->set_clock)
		musb->set_clock(musb->clock, 1);
	else
		clk_enable(musb->clock);

	l = omap_readl(OTG_SYSCONFIG);
	l &= ~ENABLEWAKEUP;	/* disable wakeup */
	omap_writel(l, OTG_SYSCONFIG);

	l = omap_readl(OTG_FORCESTDBY);
	l &= ~ENABLEFORCE;	/* disable MSTANDBY */
	omap_writel(l, OTG_FORCESTDBY);

	return 0;
}


int musb_platform_exit(struct musb *musb)
{

	omap_vbus_power(musb, 0 /*off*/, 1);

	musb_platform_suspend(musb);

	clk_put(musb->clock);
	musb->clock = 0;

	return 0;
}
static void omap2430_musb_disable(struct musb *musb)
{
	struct device *dev = musb->controller;
	struct omap2430_glue *glue = dev_get_drvdata(dev->parent);

	if (glue->status != MUSB_UNKNOWN)
		omap_control_usb_set_mode(glue->control_otghs,
			USB_MODE_DISCONNECT);
}

static int omap2430_musb_exit(struct musb *musb)
{
	struct device *dev = musb->controller;
	struct omap2430_glue *glue = dev_get_drvdata(dev->parent);

	omap2430_low_level_exit(musb);
	phy_power_off(musb->phy);
	phy_exit(musb->phy);
	musb->phy = NULL;
	cancel_work_sync(&glue->omap_musb_mailbox_work);

	return 0;
}

static const struct musb_platform_ops omap2430_ops = {
	.quirks		= MUSB_DMA_INVENTRA,
#ifdef CONFIG_USB_INVENTRA_DMA
	.dma_init	= musbhs_dma_controller_create,
	.dma_exit	= musbhs_dma_controller_destroy,
#endif
	.init		= omap2430_musb_init,
	.exit		= omap2430_musb_exit,

	.set_vbus	= omap2430_musb_set_vbus,

	.enable		= omap2430_musb_enable,
	.disable	= omap2430_musb_disable,

	.phy_callback	= omap2430_musb_mailbox,
};

static u64 omap2430_dmamask = DMA_BIT_MASK(32);

static int omap2430_probe(struct platform_device *pdev)
{
	struct resource			musb_resources[3];
	struct musb_hdrc_platform_data	*pdata = dev_get_platdata(&pdev->dev);
	struct omap_musb_board_data	*data;
	struct platform_device		*musb;
	struct omap2430_glue		*glue;
	struct device_node		*np = pdev->dev.of_node;
	struct musb_hdrc_config		*config;
	int				ret = -ENOMEM, val;

	glue = devm_kzalloc(&pdev->dev, sizeof(*glue), GFP_KERNEL);
	if (!glue)
		goto err0;

	musb = platform_device_alloc("musb-hdrc", PLATFORM_DEVID_AUTO);
	if (!musb) {
		dev_err(&pdev->dev, "failed to allocate musb device\n");
		goto err0;
	}

	musb->dev.parent		= &pdev->dev;
	musb->dev.dma_mask		= &omap2430_dmamask;
	musb->dev.coherent_dma_mask	= omap2430_dmamask;

	glue->dev			= &pdev->dev;
	glue->musb			= musb;
	glue->status			= MUSB_UNKNOWN;
	glue->control_otghs = ERR_PTR(-ENODEV);

	if (np) {
		struct device_node *control_node;
		struct platform_device *control_pdev;

		pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
		if (!pdata)
			goto err2;

		data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
		if (!data)
			goto err2;

		config = devm_kzalloc(&pdev->dev, sizeof(*config), GFP_KERNEL);
		if (!config)
			goto err2;

		of_property_read_u32(np, "mode", (u32 *)&pdata->mode);
		of_property_read_u32(np, "interface-type",
						(u32 *)&data->interface_type);
		of_property_read_u32(np, "num-eps", (u32 *)&config->num_eps);
		of_property_read_u32(np, "ram-bits", (u32 *)&config->ram_bits);
		of_property_read_u32(np, "power", (u32 *)&pdata->power);

		ret = of_property_read_u32(np, "multipoint", &val);
		if (!ret && val)
			config->multipoint = true;

		pdata->board_data	= data;
		pdata->config		= config;

		control_node = of_parse_phandle(np, "ctrl-module", 0);
		if (control_node) {
			control_pdev = of_find_device_by_node(control_node);
			if (!control_pdev) {
				dev_err(&pdev->dev, "Failed to get control device\n");
				ret = -EINVAL;
				goto err2;
			}
			glue->control_otghs = &control_pdev->dev;
		}
	}
	pdata->platform_ops		= &omap2430_ops;

	platform_set_drvdata(pdev, glue);

	/*
	 * REVISIT if we ever have two instances of the wrapper, we will be
	 * in big trouble
	 */
	_glue	= glue;

	INIT_WORK(&glue->omap_musb_mailbox_work, omap_musb_mailbox_work);

	memset(musb_resources, 0x00, sizeof(*musb_resources) *
			ARRAY_SIZE(musb_resources));

	musb_resources[0].name = pdev->resource[0].name;
	musb_resources[0].start = pdev->resource[0].start;
	musb_resources[0].end = pdev->resource[0].end;
	musb_resources[0].flags = pdev->resource[0].flags;

	musb_resources[1].name = pdev->resource[1].name;
	musb_resources[1].start = pdev->resource[1].start;
	musb_resources[1].end = pdev->resource[1].end;
	musb_resources[1].flags = pdev->resource[1].flags;

	musb_resources[2].name = pdev->resource[2].name;
	musb_resources[2].start = pdev->resource[2].start;
	musb_resources[2].end = pdev->resource[2].end;
	musb_resources[2].flags = pdev->resource[2].flags;

	ret = platform_device_add_resources(musb, musb_resources,
			ARRAY_SIZE(musb_resources));
	if (ret) {
		dev_err(&pdev->dev, "failed to add resources\n");
		goto err2;
	}

	ret = platform_device_add_data(musb, pdata, sizeof(*pdata));
	if (ret) {
		dev_err(&pdev->dev, "failed to add platform_data\n");
		goto err2;
	}

	pm_runtime_enable(glue->dev);

	ret = platform_device_add(musb);
	if (ret) {
		dev_err(&pdev->dev, "failed to register musb device\n");
		goto err3;
	}

	return 0;

err3:
	pm_runtime_disable(glue->dev);

err2:
	platform_device_put(musb);

err0:
	return ret;
}

static int omap2430_remove(struct platform_device *pdev)
{
	struct omap2430_glue *glue = platform_get_drvdata(pdev);

	platform_device_unregister(glue->musb);
	pm_runtime_disable(glue->dev);

	return 0;
}

#ifdef CONFIG_PM

static int omap2430_runtime_suspend(struct device *dev)
{
	struct omap2430_glue		*glue = dev_get_drvdata(dev);
	struct musb			*musb = glue_to_musb(glue);

	if (!musb)
		return 0;

	musb->context.otg_interfsel = musb_readl(musb->mregs,
						 OTG_INTERFSEL);

	omap2430_low_level_exit(musb);

	return 0;
}

static int omap2430_runtime_resume(struct device *dev)
{
	struct omap2430_glue		*glue = dev_get_drvdata(dev);
	struct musb			*musb = glue_to_musb(glue);

	if (!musb)
		return 0;

	omap2430_low_level_init(musb);
	musb_writel(musb->mregs, OTG_INTERFSEL,
		    musb->context.otg_interfsel);

	return 0;
}

static const struct dev_pm_ops omap2430_pm_ops = {
	.runtime_suspend = omap2430_runtime_suspend,
	.runtime_resume = omap2430_runtime_resume,
};

#define DEV_PM_OPS	(&omap2430_pm_ops)
#else
#define DEV_PM_OPS	NULL
#endif

#ifdef CONFIG_OF
static const struct of_device_id omap2430_id_table[] = {
	{
		.compatible = "ti,omap4-musb"
	},
	{
		.compatible = "ti,omap3-musb"
	},
	{},
};
MODULE_DEVICE_TABLE(of, omap2430_id_table);
#endif

static struct platform_driver omap2430_driver = {
	.probe		= omap2430_probe,
	.remove		= omap2430_remove,
	.driver		= {
		.name	= "musb-omap2430",
		.pm	= DEV_PM_OPS,
		.of_match_table = of_match_ptr(omap2430_id_table),
	},
};

module_platform_driver(omap2430_driver);

MODULE_DESCRIPTION("OMAP2PLUS MUSB Glue Layer");
MODULE_AUTHOR("Felipe Balbi <balbi@ti.com>");
MODULE_LICENSE("GPL v2");
