/*
 * linux/arch/arm/mach-omap2/devices.c
 *
 * OMAP2 platform device setup/initialization
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>

#include <mach/hardware.h>
#include <asm/io.h>
#include <asm/mach-types.h>
#include <asm/mach/map.h>

#include <mach/tc.h>
#include <mach/board.h>
#include <mach/mux.h>
#include <mach/gpio.h>

#if	defined(CONFIG_I2C_OMAP) || defined(CONFIG_I2C_OMAP_MODULE)

#define OMAP2_I2C_BASE2		0x48072000
#define OMAP2_I2C_INT2		57

static struct resource i2c_resources2[] = {
	{
		.start		= OMAP2_I2C_BASE2,
		.end		= OMAP2_I2C_BASE2 + 0x3f,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= OMAP2_I2C_INT2,
		.flags		= IORESOURCE_IRQ,
	},
};

static struct platform_device omap_i2c_device2 = {
	.name           = "i2c_omap",
	.id             = 2,
	.num_resources	= ARRAY_SIZE(i2c_resources2),
	.resource	= i2c_resources2,
};

/* See also arch/arm/plat-omap/devices.c for first I2C on 24xx */
static void omap_init_i2c(void)
{
	/* REVISIT: Second I2C not in use on H4? */
	if (machine_is_omap_h4())
		return;

	if (!cpu_is_omap2430()) {
		omap_cfg_reg(J15_24XX_I2C2_SCL);
		omap_cfg_reg(H19_24XX_I2C2_SDA);
	}
	(void) platform_device_register(&omap_i2c_device2);
}

#else

static void omap_init_i2c(void) {}

#endif

#if defined(CONFIG_OMAP_DSP) || defined(CONFIG_OMAP_DSP_MODULE)
#define OMAP2_MBOX_BASE		IO_ADDRESS(OMAP24XX_MAILBOX_BASE)

static struct resource mbox_resources[] = {
	{
		.start		= OMAP2_MBOX_BASE,
		.end		= OMAP2_MBOX_BASE + 0x11f,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= INT_24XX_MAIL_U0_MPU,
		.flags		= IORESOURCE_IRQ,
	},
	{
		.start		= INT_24XX_MAIL_U3_MPU,
		.flags		= IORESOURCE_IRQ,
	},
};

static struct platform_device mbox_device = {
	.name		= "mailbox",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(mbox_resources),
	.resource	= mbox_resources,
};

static inline void omap_init_mbox(void)
{
	platform_device_register(&mbox_device);
}
#else
static inline void omap_init_mbox(void) { }
#endif

#if defined(CONFIG_OMAP_STI)

#define OMAP2_STI_BASE		IO_ADDRESS(0x48068000)
#define OMAP2_STI_CHANNEL_BASE	0x54000000
#define OMAP2_STI_IRQ		4

static struct resource sti_resources[] = {
	{
		.start		= OMAP2_STI_BASE,
		.end		= OMAP2_STI_BASE + 0x7ff,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= OMAP2_STI_CHANNEL_BASE,
		.end		= OMAP2_STI_CHANNEL_BASE + SZ_64K - 1,
		.flags		= IORESOURCE_MEM,
	},
	{
		.start		= OMAP2_STI_IRQ,
		.flags		= IORESOURCE_IRQ,
	}
};

static struct platform_device sti_device = {
	.name		= "sti",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(sti_resources),
	.resource	= sti_resources,
};

static inline void omap_init_sti(void)
{
	platform_device_register(&sti_device);
}
#else
static inline void omap_init_sti(void) {}
#endif

#if defined(CONFIG_SPI_OMAP24XX)

#include <mach/mcspi.h>

#define OMAP2_MCSPI1_BASE		0x48098000
#define OMAP2_MCSPI2_BASE		0x4809a000

static struct omap2_mcspi_platform_config omap2_mcspi1_config = {
	.num_cs		= 4,
};

static struct resource omap2_mcspi1_resources[] = {
	{
		.start		= OMAP2_MCSPI1_BASE,
		.end		= OMAP2_MCSPI1_BASE + 0xff,
		.flags		= IORESOURCE_MEM,
	},
};

struct platform_device omap2_mcspi1 = {
	.name		= "omap2_mcspi",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(omap2_mcspi1_resources),
	.resource	= omap2_mcspi1_resources,
	.dev		= {
		.platform_data = &omap2_mcspi1_config,
	},
};

static struct omap2_mcspi_platform_config omap2_mcspi2_config = {
	.num_cs		= 2,
};

static struct resource omap2_mcspi2_resources[] = {
	{
		.start		= OMAP2_MCSPI2_BASE,
		.end		= OMAP2_MCSPI2_BASE + 0xff,
		.flags		= IORESOURCE_MEM,
	},
};

struct platform_device omap2_mcspi2 = {
	.name		= "omap2_mcspi",
	.id		= 2,
	.num_resources	= ARRAY_SIZE(omap2_mcspi2_resources),
	.resource	= omap2_mcspi2_resources,
	.dev		= {
		.platform_data = &omap2_mcspi2_config,
	},
};

static void omap_init_mcspi(void)
{
	platform_device_register(&omap2_mcspi1);
	platform_device_register(&omap2_mcspi2);
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/pinctrl/machine.h>

#include <asm/mach-types.h>
#include <asm/mach/map.h>

#include <linux/omap-dma.h>

#include "iomap.h"
#include "omap_hwmod.h"
#include "omap_device.h"

#include "soc.h"
#include "common.h"
#include "control.h"
#include "display.h"

#define L3_MODULES_MAX_LEN 12
#define L3_MODULES 3

/*-------------------------------------------------------------------------*/

#if IS_ENABLED(CONFIG_VIDEO_OMAP2_VOUT)
#if IS_ENABLED(CONFIG_FB_OMAP2)
static struct resource omap_vout_resource[3 - CONFIG_FB_OMAP2_NUM_FBS] = {
};
#else
static struct resource omap_vout_resource[2] = {
};
#endif

static struct platform_device omap_vout_device = {
	.name		= "omap_vout",
	.num_resources	= ARRAY_SIZE(omap_vout_resource),
	.resource 	= &omap_vout_resource[0],
	.id		= -1,
};

int __init omap_init_vout(void)
{
	return platform_device_register(&omap_vout_device);
}
#else
int __init omap_init_vout(void) { return 0; }
#endif

/*-------------------------------------------------------------------------*/

static int __init omap2_init_devices(void)
{
	/* please keep these calls, and their implementations above,
	 * in alphabetical order so they're easier to sort through.
	 */
	omap_init_i2c();
	omap_init_mbox();
	omap_init_mcspi();
	/* Enable dummy states for those platforms without pinctrl support */
	if (!of_have_populated_dt())
		pinctrl_provide_dummies();

	/*
	 * please keep these calls, and their implementations above,
	 * in alphabetical order so they're easier to sort through.
	 */
	omap_init_audio();
	/* If dtb is there, the devices will be created dynamically */
	if (!of_have_populated_dt()) {
		omap_init_mbox();
		omap_init_mcspi();
		omap_init_sham();
		omap_init_aes();
		omap_init_rng();
	}
	omap_init_sti();

	return 0;
}
arch_initcall(omap2_init_devices);
omap_arch_initcall(omap2_init_devices);

static int __init omap_gpmc_init(void)
{
	struct omap_hwmod *oh;
	struct platform_device *pdev;
	char *oh_name = "gpmc";

	/*
	 * if the board boots up with a populated DT, do not
	 * manually add the device from this initcall
	 */
	if (of_have_populated_dt())
		return -ENODEV;

	oh = omap_hwmod_lookup(oh_name);
	if (!oh) {
		pr_err("Could not look up %s\n", oh_name);
		return -ENODEV;
	}

	pdev = omap_device_build("omap-gpmc", -1, oh, NULL, 0);
	WARN(IS_ERR(pdev), "could not build omap_device for %s\n", oh_name);

	return PTR_ERR_OR_ZERO(pdev);
}
omap_postcore_initcall(omap_gpmc_init);
