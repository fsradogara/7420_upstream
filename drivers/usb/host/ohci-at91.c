// SPDX-License-Identifier: GPL-1.0+
/*
 * OHCI HCD (Host Controller Driver) for USB.
 *
 *  Copyright (C) 2004 SAN People (Pty) Ltd.
 *  Copyright (C) 2005 Thibaut VARENE <varenet@parisc-linux.org>
 *
 * AT91 Bus Glue
 *
 * Based on fragments of 2.4 driver by Rick Bronson.
 * Based on ohci-omap.c
 *
 * This file is licenced under the GPL.
 */

#include <linux/clk.h>
#include <linux/platform_device.h>

#include <mach/hardware.h>
#include <asm/gpio.h>

#include <mach/board.h>
#include <mach/cpu.h>

#ifndef CONFIG_ARCH_AT91
#error "CONFIG_ARCH_AT91 must be defined."
#endif

/* interface and function clocks; sometimes also an AHB clock */
static struct clk *iclk, *fclk, *hclk;
static int clocked;
#include <linux/dma-mapping.h>
#include <linux/gpio/consumer.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/platform_data/atmel.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <soc/at91/atmel-sfr.h>

#include "ohci.h"

#define valid_port(index)	((index) >= 0 && (index) < AT91_MAX_USBH_PORTS)
#define at91_for_each_port(index)	\
		for ((index) = 0; (index) < AT91_MAX_USBH_PORTS; (index)++)

/* interface, function and usb clocks; sometimes also an AHB clock */
#define hcd_to_ohci_at91_priv(h) \
	((struct ohci_at91_priv *)hcd_to_ohci(h)->priv)

#define AT91_MAX_USBH_PORTS	3
struct at91_usbh_data {
	struct gpio_desc *vbus_pin[AT91_MAX_USBH_PORTS];
	struct gpio_desc *overcurrent_pin[AT91_MAX_USBH_PORTS];
	u8 ports;				/* number of ports on root hub */
	u8 overcurrent_supported;
	u8 overcurrent_status[AT91_MAX_USBH_PORTS];
	u8 overcurrent_changed[AT91_MAX_USBH_PORTS];
};

struct ohci_at91_priv {
	struct clk *iclk;
	struct clk *fclk;
	struct clk *hclk;
	bool clocked;
	bool wakeup;		/* Saved wake-up state for resume */
	struct regmap *sfr_regmap;
};
/* interface and function clocks; sometimes also an AHB clock */

#define DRIVER_DESC "OHCI Atmel driver"

static const char hcd_name[] = "ohci-atmel";

static struct hc_driver __read_mostly ohci_at91_hc_driver;

static const struct ohci_driver_overrides ohci_at91_drv_overrides __initconst = {
	.extra_priv_size = sizeof(struct ohci_at91_priv),
};

/*-------------------------------------------------------------------------*/

static void at91_start_clock(void)
{
	if (cpu_is_at91sam9261())
		clk_enable(hclk);
	clk_enable(iclk);
	clk_enable(fclk);
	clocked = 1;
}

static void at91_stop_clock(void)
{
	clk_disable(fclk);
	clk_disable(iclk);
	if (cpu_is_at91sam9261())
		clk_disable(hclk);
	clocked = 0;
static void at91_start_clock(struct ohci_at91_priv *ohci_at91)
{
	if (ohci_at91->clocked)
		return;

	clk_set_rate(ohci_at91->fclk, 48000000);
	clk_prepare_enable(ohci_at91->hclk);
	clk_prepare_enable(ohci_at91->iclk);
	clk_prepare_enable(ohci_at91->fclk);
	ohci_at91->clocked = true;
}

static void at91_stop_clock(struct ohci_at91_priv *ohci_at91)
{
	if (!ohci_at91->clocked)
		return;

	clk_disable_unprepare(ohci_at91->fclk);
	clk_disable_unprepare(ohci_at91->iclk);
	clk_disable_unprepare(ohci_at91->hclk);
	ohci_at91->clocked = false;
}

static void at91_start_hc(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct ohci_regs __iomem *regs = hcd->regs;
	struct ohci_at91_priv *ohci_at91 = hcd_to_ohci_at91_priv(hcd);

	dev_dbg(&pdev->dev, "start\n");

	/*
	 * Start the USB clocks.
	 */
	at91_start_clock();
	at91_start_clock(ohci_at91);

	/*
	 * The USB host controller must remain in reset.
	 */
	writel(0, &regs->control);
}

static void at91_stop_hc(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct ohci_regs __iomem *regs = hcd->regs;
	struct ohci_at91_priv *ohci_at91 = hcd_to_ohci_at91_priv(hcd);

	dev_dbg(&pdev->dev, "stop\n");

	/*
	 * Put the USB host controller into reset.
	 */
	writel(0, &regs->control);

	/*
	 * Stop the USB clocks.
	 */
	at91_stop_clock();
	at91_stop_clock(ohci_at91);
}


/*-------------------------------------------------------------------------*/

static void usb_hcd_at91_remove (struct usb_hcd *, struct platform_device *);

static struct regmap *at91_dt_syscon_sfr(void)
{
	struct regmap *regmap;

	regmap = syscon_regmap_lookup_by_compatible("atmel,sama5d2-sfr");
	if (IS_ERR(regmap))
		regmap = NULL;

	return regmap;
}

/* configure so an HC device and id are always provided */
/* always called with process context; sleeping is OK */


/**
 * usb_hcd_at91_probe - initialize AT91-based HCDs
 * Context: !in_interrupt()
 *
 * Allocates basic resources for this USB host controller, and
 * then invokes the start() method for the HCD associated with it
 * through the hotplug entry's driver_data.
 */
static int usb_hcd_at91_probe(const struct hc_driver *driver,
			struct platform_device *pdev)
{
	int retval;
	struct usb_hcd *hcd = NULL;

	if (pdev->num_resources != 2) {
		pr_debug("hcd probe: invalid num_resources");
		return -ENODEV;
	}

	if ((pdev->resource[0].flags != IORESOURCE_MEM)
			|| (pdev->resource[1].flags != IORESOURCE_IRQ)) {
		pr_debug("hcd probe: invalid resource type\n");
		return -ENODEV;
	}

	hcd = usb_create_hcd(driver, &pdev->dev, "at91");
	if (!hcd)
		return -ENOMEM;
	hcd->rsrc_start = pdev->resource[0].start;
	hcd->rsrc_len = pdev->resource[0].end - pdev->resource[0].start + 1;

	if (!request_mem_region(hcd->rsrc_start, hcd->rsrc_len, hcd_name)) {
		pr_debug("request_mem_region failed\n");
		retval = -EBUSY;
		goto err1;
	}

	hcd->regs = ioremap(hcd->rsrc_start, hcd->rsrc_len);
	if (!hcd->regs) {
		pr_debug("ioremap failed\n");
		retval = -EIO;
		goto err2;
	}

	iclk = clk_get(&pdev->dev, "ohci_clk");
	fclk = clk_get(&pdev->dev, "uhpck");
	if (cpu_is_at91sam9261())
		hclk = clk_get(&pdev->dev, "hck0");

	at91_start_hc(pdev);
	ohci_hcd_init(hcd_to_ohci(hcd));

	retval = usb_add_hcd(hcd, pdev->resource[1].start, IRQF_DISABLED);
	if (retval == 0)
		return retval;
	struct at91_usbh_data *board;
	struct ohci_hcd *ohci;
	int retval;
	struct usb_hcd *hcd;
	struct ohci_at91_priv *ohci_at91;
	struct device *dev = &pdev->dev;
	struct resource *res;
	int irq;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_dbg(dev, "hcd probe: missing irq resource\n");
		return irq;
	}

	hcd = usb_create_hcd(driver, dev, "at91");
	if (!hcd)
		return -ENOMEM;
	ohci_at91 = hcd_to_ohci_at91_priv(hcd);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	hcd->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(hcd->regs)) {
		retval = PTR_ERR(hcd->regs);
		goto err;
	}
	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);

	ohci_at91->iclk = devm_clk_get(dev, "ohci_clk");
	if (IS_ERR(ohci_at91->iclk)) {
		dev_err(dev, "failed to get ohci_clk\n");
		retval = PTR_ERR(ohci_at91->iclk);
		goto err;
	}
	ohci_at91->fclk = devm_clk_get(dev, "uhpck");
	if (IS_ERR(ohci_at91->fclk)) {
		dev_err(dev, "failed to get uhpck\n");
		retval = PTR_ERR(ohci_at91->fclk);
		goto err;
	}
	ohci_at91->hclk = devm_clk_get(dev, "hclk");
	if (IS_ERR(ohci_at91->hclk)) {
		dev_err(dev, "failed to get hclk\n");
		retval = PTR_ERR(ohci_at91->hclk);
		goto err;
	}

	ohci_at91->sfr_regmap = at91_dt_syscon_sfr();
	if (!ohci_at91->sfr_regmap)
		dev_dbg(dev, "failed to find sfr node\n");

	board = hcd->self.controller->platform_data;
	ohci = hcd_to_ohci(hcd);
	ohci->num_ports = board->ports;
	at91_start_hc(pdev);

	/*
	 * The RemoteWakeupConnected bit has to be set explicitly
	 * before calling ohci_run. The reset value of this bit is 0.
	 */
	ohci->hc_control = OHCI_CTRL_RWC;

	retval = usb_add_hcd(hcd, irq, IRQF_SHARED);
	if (retval == 0) {
		device_wakeup_enable(hcd->self.controller);
		return retval;
	}

	/* Error handling */
	at91_stop_hc(pdev);

	if (cpu_is_at91sam9261())
		clk_put(hclk);
	clk_put(fclk);
	clk_put(iclk);

	iounmap(hcd->regs);

 err2:
	release_mem_region(hcd->rsrc_start, hcd->rsrc_len);

 err1:
 err:
	usb_put_hcd(hcd);
	return retval;
}


/* may be called with controller, bus, and devices active */

/**
 * usb_hcd_at91_remove - shutdown processing for AT91-based HCDs
 * @dev: USB Host Controller being removed
 * Context: !in_interrupt()
 *
 * Reverses the effect of usb_hcd_at91_probe(), first invoking
 * the HCD's stop() method.  It is always called from a thread
 * context, "rmmod" or something similar.
 *
 */
static void usb_hcd_at91_remove(struct usb_hcd *hcd,
				struct platform_device *pdev)
{
	usb_remove_hcd(hcd);
	at91_stop_hc(pdev);
	iounmap(hcd->regs);
	release_mem_region(hcd->rsrc_start, hcd->rsrc_len);
	usb_put_hcd(hcd);

	if (cpu_is_at91sam9261())
		clk_put(hclk);
	clk_put(fclk);
	clk_put(iclk);
	fclk = iclk = hclk = NULL;

	dev_set_drvdata(&pdev->dev, NULL);
}

/*-------------------------------------------------------------------------*/

static int __devinit
ohci_at91_start (struct usb_hcd *hcd)
{
	struct at91_usbh_data	*board = hcd->self.controller->platform_data;
	struct ohci_hcd		*ohci = hcd_to_ohci (hcd);
	int			ret;

	if ((ret = ohci_init(ohci)) < 0)
		return ret;

	ohci->num_ports = board->ports;

	if ((ret = ohci_run(ohci)) < 0) {
		err("can't start %s", hcd->self.bus_name);
		ohci_stop(hcd);
		return ret;
	}
	return 0;
	usb_put_hcd(hcd);
}

/*-------------------------------------------------------------------------*/
static void ohci_at91_usb_set_power(struct at91_usbh_data *pdata, int port, int enable)
{
	if (!valid_port(port))
		return;

	gpiod_set_value(pdata->vbus_pin[port], enable);
}

static int ohci_at91_usb_get_power(struct at91_usbh_data *pdata, int port)
{
	if (!valid_port(port))
		return -EINVAL;

	return gpiod_get_value(pdata->vbus_pin[port]);
}

/*
 * Update the status data from the hub with the over-current indicator change.
 */
static int ohci_at91_hub_status_data(struct usb_hcd *hcd, char *buf)
{
	struct at91_usbh_data *pdata = hcd->self.controller->platform_data;
	int length = ohci_hub_status_data(hcd, buf);
	int port;

	at91_for_each_port(port) {
		if (pdata->overcurrent_changed[port]) {
			if (!length)
				length = 1;
			buf[0] |= 1 << (port + 1);
		}
	}

	return length;
}

static int ohci_at91_port_suspend(struct regmap *regmap, u8 set)
{
	u32 regval;
	int ret;

	if (!regmap)
		return 0;

	ret = regmap_read(regmap, AT91_SFR_OHCIICR, &regval);
	if (ret)
		return ret;

	if (set)
		regval |= AT91_OHCIICR_USB_SUSPEND;
	else
		regval &= ~AT91_OHCIICR_USB_SUSPEND;

	regmap_write(regmap, AT91_SFR_OHCIICR, regval);

	return 0;
}

/*
 * Look at the control requests to the root hub and see if we need to override.
 */
static int ohci_at91_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
				 u16 wIndex, char *buf, u16 wLength)
{
	struct at91_usbh_data *pdata = dev_get_platdata(hcd->self.controller);
	struct ohci_at91_priv *ohci_at91 = hcd_to_ohci_at91_priv(hcd);
	struct usb_hub_descriptor *desc;
	int ret = -EINVAL;
	u32 *data = (u32 *)buf;

	dev_dbg(hcd->self.controller,
		"ohci_at91_hub_control(%p,0x%04x,0x%04x,0x%04x,%p,%04x)\n",
		hcd, typeReq, wValue, wIndex, buf, wLength);

	wIndex--;

	switch (typeReq) {
	case SetPortFeature:
		switch (wValue) {
		case USB_PORT_FEAT_POWER:
			dev_dbg(hcd->self.controller, "SetPortFeat: POWER\n");
			if (valid_port(wIndex)) {
				ohci_at91_usb_set_power(pdata, wIndex, 1);
				ret = 0;
			}

			goto out;

		case USB_PORT_FEAT_SUSPEND:
			dev_dbg(hcd->self.controller, "SetPortFeat: SUSPEND\n");
			if (valid_port(wIndex) && ohci_at91->sfr_regmap) {
				ohci_at91_port_suspend(ohci_at91->sfr_regmap,
						       1);
				return 0;
			}
			break;
		}
		break;

	case ClearPortFeature:
		switch (wValue) {
		case USB_PORT_FEAT_C_OVER_CURRENT:
			dev_dbg(hcd->self.controller,
				"ClearPortFeature: C_OVER_CURRENT\n");

			if (valid_port(wIndex)) {
				pdata->overcurrent_changed[wIndex] = 0;
				pdata->overcurrent_status[wIndex] = 0;
			}

			goto out;

		case USB_PORT_FEAT_OVER_CURRENT:
			dev_dbg(hcd->self.controller,
				"ClearPortFeature: OVER_CURRENT\n");

			if (valid_port(wIndex))
				pdata->overcurrent_status[wIndex] = 0;

			goto out;

		case USB_PORT_FEAT_POWER:
			dev_dbg(hcd->self.controller,
				"ClearPortFeature: POWER\n");

			if (valid_port(wIndex)) {
				ohci_at91_usb_set_power(pdata, wIndex, 0);
				return 0;
			}
			break;

		case USB_PORT_FEAT_SUSPEND:
			dev_dbg(hcd->self.controller, "ClearPortFeature: SUSPEND\n");
			if (valid_port(wIndex) && ohci_at91->sfr_regmap) {
				ohci_at91_port_suspend(ohci_at91->sfr_regmap,
						       0);
				return 0;
			}
			break;
		}
		break;
	}

	ret = ohci_hub_control(hcd, typeReq, wValue, wIndex + 1, buf, wLength);
	if (ret)
		goto out;

	switch (typeReq) {
	case GetHubDescriptor:

		/* update the hub's descriptor */

		desc = (struct usb_hub_descriptor *)buf;

		dev_dbg(hcd->self.controller, "wHubCharacteristics 0x%04x\n",
			desc->wHubCharacteristics);

		/* remove the old configurations for power-switching, and
		 * over-current protection, and insert our new configuration
		 */

		desc->wHubCharacteristics &= ~cpu_to_le16(HUB_CHAR_LPSM);
		desc->wHubCharacteristics |=
			cpu_to_le16(HUB_CHAR_INDV_PORT_LPSM);

		if (pdata->overcurrent_supported) {
			desc->wHubCharacteristics &= ~cpu_to_le16(HUB_CHAR_OCPM);
			desc->wHubCharacteristics |=
				cpu_to_le16(HUB_CHAR_INDV_PORT_OCPM);
		}

		dev_dbg(hcd->self.controller, "wHubCharacteristics after 0x%04x\n",
			desc->wHubCharacteristics);

		return ret;

	case GetPortStatus:
		/* check port status */

		dev_dbg(hcd->self.controller, "GetPortStatus(%d)\n", wIndex);

		if (valid_port(wIndex)) {
			if (!ohci_at91_usb_get_power(pdata, wIndex))
				*data &= ~cpu_to_le32(RH_PS_PPS);

			if (pdata->overcurrent_changed[wIndex])
				*data |= cpu_to_le32(RH_PS_OCIC);

			if (pdata->overcurrent_status[wIndex])
				*data |= cpu_to_le32(RH_PS_POCI);
		}
	}

 out:
	return ret;
}

/*-------------------------------------------------------------------------*/

static const struct hc_driver ohci_at91_hc_driver = {
	.description =		hcd_name,
	.product_desc =		"AT91 OHCI",
	.hcd_priv_size =	sizeof(struct ohci_hcd),

	/*
	 * generic hardware linkage
	 */
	.irq =			ohci_irq,
	.flags =		HCD_USB11 | HCD_MEMORY,

	/*
	 * basic lifecycle operations
	 */
	.start =		ohci_at91_start,
	.stop =			ohci_stop,
	.shutdown =		ohci_shutdown,

	/*
	 * managing i/o requests and associated device resources
	 */
	.urb_enqueue =		ohci_urb_enqueue,
	.urb_dequeue =		ohci_urb_dequeue,
	.endpoint_disable =	ohci_endpoint_disable,

	/*
	 * scheduling support
	 */
	.get_frame_number =	ohci_get_frame,

	/*
	 * root hub support
	 */
	.hub_status_data =	ohci_hub_status_data,
	.hub_control =		ohci_hub_control,
#ifdef CONFIG_PM
	.bus_suspend =		ohci_bus_suspend,
	.bus_resume =		ohci_bus_resume,
#endif
	.start_port_reset =	ohci_start_port_reset,
};

static irqreturn_t ohci_hcd_at91_overcurrent_irq(int irq, void *data)
{
	struct platform_device *pdev = data;
	struct at91_usbh_data *pdata = dev_get_platdata(&pdev->dev);
	int val, port;

	/* From the GPIO notifying the over-current situation, find
	 * out the corresponding port */
	at91_for_each_port(port) {
		if (gpiod_to_irq(pdata->overcurrent_pin[port]) == irq)
			break;
	}

	if (port == AT91_MAX_USBH_PORTS) {
		dev_err(& pdev->dev, "overcurrent interrupt from unknown GPIO\n");
		return IRQ_HANDLED;
	}

	val = gpiod_get_value(pdata->overcurrent_pin[port]);

	/* When notified of an over-current situation, disable power
	   on the corresponding port, and mark this port in
	   over-current. */
	if (!val) {
		ohci_at91_usb_set_power(pdata, port, 0);
		pdata->overcurrent_status[port]  = 1;
		pdata->overcurrent_changed[port] = 1;
	}

	dev_dbg(& pdev->dev, "overcurrent situation %s\n",
		val ? "exited" : "notified");

	return IRQ_HANDLED;
}

static const struct of_device_id at91_ohci_dt_ids[] = {
	{ .compatible = "atmel,at91rm9200-ohci" },
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(of, at91_ohci_dt_ids);

/*-------------------------------------------------------------------------*/

static int ohci_hcd_at91_drv_probe(struct platform_device *pdev)
{
	struct at91_usbh_data	*pdata = pdev->dev.platform_data;
	int			i;

	if (pdata) {
		/* REVISIT make the driver support per-port power switching,
		 * and also overcurrent detection.  Here we assume the ports
		 * are always powered while this driver is active, and use
		 * active-low power switches.
		 */
		for (i = 0; i < pdata->ports; i++) {
			if (pdata->vbus_pin[i] <= 0)
				continue;
			gpio_request(pdata->vbus_pin[i], "ohci_vbus");
			gpio_direction_output(pdata->vbus_pin[i], 0);
	struct device_node *np = pdev->dev.of_node;
	struct at91_usbh_data	*pdata;
	int			i;
	int			ret;
	int			err;
	u32			ports;

	/* Right now device-tree probed devices don't get dma_mask set.
	 * Since shared usb code relies on it, set it here for now.
	 * Once we have dma capability bindings this can go away.
	 */
	ret = dma_coerce_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	pdev->dev.platform_data = pdata;

	if (!of_property_read_u32(np, "num-ports", &ports))
		pdata->ports = ports;

	at91_for_each_port(i) {
		if (i >= pdata->ports)
			break;

		pdata->vbus_pin[i] =
			devm_gpiod_get_index_optional(&pdev->dev, "atmel,vbus",
						      i, GPIOD_OUT_HIGH);
		if (IS_ERR(pdata->vbus_pin[i])) {
			err = PTR_ERR(pdata->vbus_pin[i]);
			dev_err(&pdev->dev, "unable to claim gpio \"vbus\": %d\n", err);
			continue;
		}
	}

	at91_for_each_port(i) {
		if (i >= pdata->ports)
			break;

		pdata->overcurrent_pin[i] =
			devm_gpiod_get_index_optional(&pdev->dev, "atmel,oc",
						      i, GPIOD_IN);
		if (!pdata->overcurrent_pin[i])
			continue;
		if (IS_ERR(pdata->overcurrent_pin[i])) {
			err = PTR_ERR(pdata->overcurrent_pin[i]);
			dev_err(&pdev->dev, "unable to claim gpio \"overcurrent\": %d\n", err);
			continue;
		}

		ret = devm_request_irq(&pdev->dev,
				       gpiod_to_irq(pdata->overcurrent_pin[i]),
				       ohci_hcd_at91_overcurrent_irq,
				       IRQF_SHARED,
				       "ohci_overcurrent", pdev);
		if (ret)
			dev_info(&pdev->dev, "failed to request gpio \"overcurrent\" IRQ\n");
	}

	device_init_wakeup(&pdev->dev, 1);
	return usb_hcd_at91_probe(&ohci_at91_hc_driver, pdev);
}

static int ohci_hcd_at91_drv_remove(struct platform_device *pdev)
{
	struct at91_usbh_data	*pdata = pdev->dev.platform_data;
	int			i;

	if (pdata) {
		for (i = 0; i < pdata->ports; i++) {
			if (pdata->vbus_pin[i] <= 0)
				continue;
			gpio_direction_output(pdata->vbus_pin[i], 1);
			gpio_free(pdata->vbus_pin[i]);
		}
	struct at91_usbh_data	*pdata = dev_get_platdata(&pdev->dev);
	int			i;

	if (pdata) {
		at91_for_each_port(i)
			ohci_at91_usb_set_power(pdata, i, 0);
	}

	device_init_wakeup(&pdev->dev, 0);
	usb_hcd_at91_remove(platform_get_drvdata(pdev), pdev);
	return 0;
}

#ifdef CONFIG_PM

static int
ohci_hcd_at91_drv_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	struct usb_hcd	*hcd = platform_get_drvdata(pdev);
	struct ohci_hcd	*ohci = hcd_to_ohci(hcd);

	if (device_may_wakeup(&pdev->dev))
		enable_irq_wake(hcd->irq);

static int __maybe_unused
ohci_hcd_at91_drv_suspend(struct device *dev)
{
	struct usb_hcd	*hcd = dev_get_drvdata(dev);
	struct ohci_hcd	*ohci = hcd_to_ohci(hcd);
	struct ohci_at91_priv *ohci_at91 = hcd_to_ohci_at91_priv(hcd);
	int		ret;

	/*
	 * Disable wakeup if we are going to sleep with slow clock mode
	 * enabled.
	 */
	ohci_at91->wakeup = device_may_wakeup(dev)
			&& !at91_suspend_entering_slow_clock();

	if (ohci_at91->wakeup)
		enable_irq_wake(hcd->irq);

	ohci_at91_port_suspend(ohci_at91->sfr_regmap, 1);

	ret = ohci_suspend(hcd, ohci_at91->wakeup);
	if (ret) {
		if (ohci_at91->wakeup)
			disable_irq_wake(hcd->irq);
		return ret;
	}
	/*
	 * The integrated transceivers seem unable to notice disconnect,
	 * reconnect, or wakeup without the 48 MHz clock active.  so for
	 * correctness, always discard connection state (using reset).
	 *
	 * REVISIT: some boards will be able to turn VBUS off...
	 */
	if (at91_suspend_entering_slow_clock()) {
		ohci_usb_reset (ohci);
		at91_stop_clock();
	}

	return 0;
}

static int ohci_hcd_at91_drv_resume(struct platform_device *pdev)
{
	struct usb_hcd	*hcd = platform_get_drvdata(pdev);

	if (device_may_wakeup(&pdev->dev))
		disable_irq_wake(hcd->irq);

	if (!clocked)
		at91_start_clock();

	ohci_finish_controller_resume(hcd);
	return 0;
}
#else
#define ohci_hcd_at91_drv_suspend NULL
#define ohci_hcd_at91_drv_resume  NULL
#endif

MODULE_ALIAS("platform:at91_ohci");
	if (!ohci_at91->wakeup) {
		ohci->rh_state = OHCI_RH_HALTED;

		/* flush the writes */
		(void) ohci_readl (ohci, &ohci->regs->control);
		at91_stop_clock(ohci_at91);
	}

	return ret;
}

static int __maybe_unused
ohci_hcd_at91_drv_resume(struct device *dev)
{
	struct usb_hcd	*hcd = dev_get_drvdata(dev);
	struct ohci_at91_priv *ohci_at91 = hcd_to_ohci_at91_priv(hcd);

	if (ohci_at91->wakeup)
		disable_irq_wake(hcd->irq);

	at91_start_clock(ohci_at91);

	ohci_resume(hcd, false);

	ohci_at91_port_suspend(ohci_at91->sfr_regmap, 0);

	return 0;
}

static SIMPLE_DEV_PM_OPS(ohci_hcd_at91_pm_ops, ohci_hcd_at91_drv_suspend,
					ohci_hcd_at91_drv_resume);

static struct platform_driver ohci_hcd_at91_driver = {
	.probe		= ohci_hcd_at91_drv_probe,
	.remove		= ohci_hcd_at91_drv_remove,
	.shutdown	= usb_hcd_platform_shutdown,
	.suspend	= ohci_hcd_at91_drv_suspend,
	.resume		= ohci_hcd_at91_drv_resume,
	.driver		= {
		.name	= "at91_ohci",
		.owner	= THIS_MODULE,
	},
};
	.driver		= {
		.name	= "at91_ohci",
		.pm	= &ohci_hcd_at91_pm_ops,
		.of_match_table	= at91_ohci_dt_ids,
	},
};

static int __init ohci_at91_init(void)
{
	if (usb_disabled())
		return -ENODEV;

	pr_info("%s: " DRIVER_DESC "\n", hcd_name);
	ohci_init_driver(&ohci_at91_hc_driver, &ohci_at91_drv_overrides);

	/*
	 * The Atmel HW has some unusual quirks, which require Atmel-specific
	 * workarounds. We override certain hc_driver functions here to
	 * achieve that. We explicitly do not enhance ohci_driver_overrides to
	 * allow this more easily, since this is an unusual case, and we don't
	 * want to encourage others to override these functions by making it
	 * too easy.
	 */

	ohci_at91_hc_driver.hub_status_data	= ohci_at91_hub_status_data;
	ohci_at91_hc_driver.hub_control		= ohci_at91_hub_control;

	return platform_driver_register(&ohci_hcd_at91_driver);
}
module_init(ohci_at91_init);

static void __exit ohci_at91_cleanup(void)
{
	platform_driver_unregister(&ohci_hcd_at91_driver);
}
module_exit(ohci_at91_cleanup);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:at91_ohci");
