// SPDX-License-Identifier: GPL-2.0
/*
 * Static Memory Controller
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/sysdev.h>

#define SMEMC_PHYS_BASE	(0x4A000000)
#define SMEMC_PHYS_SIZE	(0x90)

#define MSC0		(0x08)	/* Static Memory Controller Register 0 */
#define MSC1		(0x0C)	/* Static Memory Controller Register 1 */
#define SXCNFG		(0x1C)	/* Synchronous Static Memory Control Register */
#define MEMCLKCFG	(0x68)	/* Clock Configuration */
#define CSADRCFG0	(0x80)	/* Address Configuration Register for CS0 */
#define CSADRCFG1	(0x84)	/* Address Configuration Register for CS1 */
#define CSADRCFG2	(0x88)	/* Address Configuration Register for CS2 */
#define CSADRCFG3	(0x8C)	/* Address Configuration Register for CS3 */

#ifdef CONFIG_PM
static void __iomem *smemc_mmio_base;

#include <linux/syscore_ops.h>

#include <mach/hardware.h>
#include <mach/smemc.h>

#ifdef CONFIG_PM
static unsigned long msc[2];
static unsigned long sxcnfg, memclkcfg;
static unsigned long csadrcfg[4];

static int pxa3xx_smemc_suspend(struct sys_device *dev, pm_message_t state)
{
	msc[0] = __raw_readl(smemc_mmio_base + MSC0);
	msc[1] = __raw_readl(smemc_mmio_base + MSC1);
	sxcnfg = __raw_readl(smemc_mmio_base + SXCNFG);
	memclkcfg = __raw_readl(smemc_mmio_base + MEMCLKCFG);
	csadrcfg[0] = __raw_readl(smemc_mmio_base + CSADRCFG0);
	csadrcfg[1] = __raw_readl(smemc_mmio_base + CSADRCFG1);
	csadrcfg[2] = __raw_readl(smemc_mmio_base + CSADRCFG2);
	csadrcfg[3] = __raw_readl(smemc_mmio_base + CSADRCFG3);
static int pxa3xx_smemc_suspend(void)
{
	msc[0] = __raw_readl(MSC0);
	msc[1] = __raw_readl(MSC1);
	sxcnfg = __raw_readl(SXCNFG);
	memclkcfg = __raw_readl(MEMCLKCFG);
	csadrcfg[0] = __raw_readl(CSADRCFG0);
	csadrcfg[1] = __raw_readl(CSADRCFG1);
	csadrcfg[2] = __raw_readl(CSADRCFG2);
	csadrcfg[3] = __raw_readl(CSADRCFG3);

	return 0;
}

static int pxa3xx_smemc_resume(struct sys_device *dev)
{
	__raw_writel(msc[0], smemc_mmio_base + MSC0);
	__raw_writel(msc[1], smemc_mmio_base + MSC1);
	__raw_writel(sxcnfg, smemc_mmio_base + SXCNFG);
	__raw_writel(memclkcfg, smemc_mmio_base + MEMCLKCFG);
	__raw_writel(csadrcfg[0], smemc_mmio_base + CSADRCFG0);
	__raw_writel(csadrcfg[1], smemc_mmio_base + CSADRCFG1);
	__raw_writel(csadrcfg[2], smemc_mmio_base + CSADRCFG2);
	__raw_writel(csadrcfg[3], smemc_mmio_base + CSADRCFG3);

	return 0;
}

static struct sysdev_class smemc_sysclass = {
	.name		= "smemc",
static void pxa3xx_smemc_resume(void)
{
	__raw_writel(msc[0], MSC0);
	__raw_writel(msc[1], MSC1);
	__raw_writel(sxcnfg, SXCNFG);
	__raw_writel(memclkcfg, MEMCLKCFG);
	__raw_writel(csadrcfg[0], CSADRCFG0);
	__raw_writel(csadrcfg[1], CSADRCFG1);
	__raw_writel(csadrcfg[2], CSADRCFG2);
	__raw_writel(csadrcfg[3], CSADRCFG3);
	/* CSMSADRCFG wakes up in its default state (0), so we need to set it */
	__raw_writel(0x2, CSMSADRCFG);
}

static struct syscore_ops smemc_syscore_ops = {
	.suspend	= pxa3xx_smemc_suspend,
	.resume		= pxa3xx_smemc_resume,
};

static struct sys_device smemc_sysdev = {
	.id		= 0,
	.cls		= &smemc_sysclass,
};

static int __init smemc_init(void)
{
	int ret = 0;

	if (cpu_is_pxa3xx()) {
		smemc_mmio_base = ioremap(SMEMC_PHYS_BASE, SMEMC_PHYS_SIZE);
		if (smemc_mmio_base == NULL)
			return -ENODEV;

		ret = sysdev_class_register(&smemc_sysclass);
		if (ret)
			return ret;

		ret = sysdev_register(&smemc_sysdev);
	}

	return ret;
static int __init smemc_init(void)
{
	if (cpu_is_pxa3xx()) {
		/*
		 * The only documentation we have on the
		 * Chip Select Configuration Register (CSMSADRCFG) is that
		 * it must be programmed to 0x2.
		 * Moreover, in the bit definitions, the second bit
		 * (CSMSADRCFG[1]) is called "SETALWAYS".
		 * Other bits are reserved in this register.
		 */
		__raw_writel(0x2, CSMSADRCFG);

		register_syscore_ops(&smemc_syscore_ops);
	}

	return 0;
}
subsys_initcall(smemc_init);
#endif
