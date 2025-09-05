/*
 * SH7206 Setup
 *
 *  Copyright (C) 2006  Yoshinori Sato
 *  Copyright (C) 2009  Paul Mundt
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/serial.h>
#include <linux/serial_sci.h>
#include <linux/sh_timer.h>
#include <linux/io.h>

enum {
	UNUSED = 0,

	/* interrupt sources */
	IRQ0, IRQ1, IRQ2, IRQ3, IRQ4, IRQ5, IRQ6, IRQ7,
	PINT0, PINT1, PINT2, PINT3, PINT4, PINT5, PINT6, PINT7,
	ADC_ADI0, ADC_ADI1,
	DMAC0_DEI, DMAC0_HEI, DMAC1_DEI, DMAC1_HEI,
	DMAC2_DEI, DMAC2_HEI, DMAC3_DEI, DMAC3_HEI,
	DMAC4_DEI, DMAC4_HEI, DMAC5_DEI, DMAC5_HEI,
	DMAC6_DEI, DMAC6_HEI, DMAC7_DEI, DMAC7_HEI,
	CMT0, CMT1, BSC, WDT,
	MTU2_TGI0A, MTU2_TGI0B, MTU2_TGI0C, MTU2_TGI0D,
	MTU2_TCI0V, MTU2_TGI0E, MTU2_TGI0F,
	MTU2_TGI1A, MTU2_TGI1B, MTU2_TCI1V, MTU2_TCI1U,
	MTU2_TGI2A, MTU2_TGI2B, MTU2_TCI2V, MTU2_TCI2U,
	MTU2_TGI3A, MTU2_TGI3B, MTU2_TGI3C, MTU2_TGI3D, MTU2_TCI3V,
	MTU2_TGI4A, MTU2_TGI4B, MTU2_TGI4C, MTU2_TGI4D, MTU2_TCI4V,
	MTU2_TGI5U, MTU2_TGI5V, MTU2_TGI5W,
	POE2_OEI1, POE2_OEI2,
	MTU2S_TGI3A, MTU2S_TGI3B, MTU2S_TGI3C, MTU2S_TGI3D, MTU2S_TCI3V,
	MTU2S_TGI4A, MTU2S_TGI4B, MTU2S_TGI4C, MTU2S_TGI4D, MTU2S_TCI4V,
	MTU2S_TGI5U, MTU2S_TGI5V, MTU2S_TGI5W,
	POE2_OEI3,
	IIC3_STPI, IIC3_NAKI, IIC3_RXI, IIC3_TXI, IIC3_TEI,
	SCIF0_BRI, SCIF0_ERI, SCIF0_RXI, SCIF0_TXI,
	SCIF1_BRI, SCIF1_ERI, SCIF1_RXI, SCIF1_TXI,
	SCIF2_BRI, SCIF2_ERI, SCIF2_RXI, SCIF2_TXI,
	SCIF3_BRI, SCIF3_ERI, SCIF3_RXI, SCIF3_TXI,

	/* interrupt groups */
	PINT, DMAC0, DMAC1, DMAC2, DMAC3, DMAC4, DMAC5, DMAC6, DMAC7,
	MTU0_ABCD, MTU0_VEF, MTU1_AB, MTU1_VU, MTU2_AB, MTU2_VU,
	MTU3_ABCD, MTU4_ABCD, MTU5, POE2_12, MTU3S_ABCD, MTU4S_ABCD, MTU5S,
	IIC3, SCIF0, SCIF1, SCIF2, SCIF3,

	DMAC0, DMAC1, DMAC2, DMAC3, DMAC4, DMAC5, DMAC6, DMAC7,

	MTU0_ABCD, MTU0_VEF, MTU1_AB, MTU1_VU, MTU2_AB, MTU2_VU,
	MTU3_ABCD, MTU4_ABCD, MTU5, POE2_12, MTU3S_ABCD, MTU4S_ABCD, MTU5S,
	IIC3,

	CMT0, CMT1, BSC, WDT,

	MTU2_TCI3V, MTU2_TCI4V, MTU2S_TCI3V, MTU2S_TCI4V,

	POE2_OEI3,

	SCIF0, SCIF1, SCIF2, SCIF3,

	/* interrupt groups */
	PINT,
};

static struct intc_vect vectors[] __initdata = {
	INTC_IRQ(IRQ0, 64), INTC_IRQ(IRQ1, 65),
	INTC_IRQ(IRQ2, 66), INTC_IRQ(IRQ3, 67),
	INTC_IRQ(IRQ4, 68), INTC_IRQ(IRQ5, 69),
	INTC_IRQ(IRQ6, 70), INTC_IRQ(IRQ7, 71),
	INTC_IRQ(PINT0, 80), INTC_IRQ(PINT1, 81),
	INTC_IRQ(PINT2, 82), INTC_IRQ(PINT3, 83),
	INTC_IRQ(PINT4, 84), INTC_IRQ(PINT5, 85),
	INTC_IRQ(PINT6, 86), INTC_IRQ(PINT7, 87),
	INTC_IRQ(ADC_ADI0, 92), INTC_IRQ(ADC_ADI1, 96),
	INTC_IRQ(DMAC0_DEI, 108), INTC_IRQ(DMAC0_HEI, 109),
	INTC_IRQ(DMAC1_DEI, 112), INTC_IRQ(DMAC1_HEI, 113),
	INTC_IRQ(DMAC2_DEI, 116), INTC_IRQ(DMAC2_HEI, 117),
	INTC_IRQ(DMAC3_DEI, 120), INTC_IRQ(DMAC3_HEI, 121),
	INTC_IRQ(DMAC4_DEI, 124), INTC_IRQ(DMAC4_HEI, 125),
	INTC_IRQ(DMAC5_DEI, 128), INTC_IRQ(DMAC5_HEI, 129),
	INTC_IRQ(DMAC6_DEI, 132), INTC_IRQ(DMAC6_HEI, 133),
	INTC_IRQ(DMAC7_DEI, 136), INTC_IRQ(DMAC7_HEI, 137),
	INTC_IRQ(CMT0, 140), INTC_IRQ(CMT1, 144),
	INTC_IRQ(BSC, 148), INTC_IRQ(WDT, 152),
	INTC_IRQ(MTU2_TGI0A, 156), INTC_IRQ(MTU2_TGI0B, 157),
	INTC_IRQ(MTU2_TGI0C, 158), INTC_IRQ(MTU2_TGI0D, 159),
	INTC_IRQ(MTU2_TCI0V, 160),
	INTC_IRQ(MTU2_TGI0E, 161), INTC_IRQ(MTU2_TGI0F, 162),
	INTC_IRQ(MTU2_TGI1A, 164), INTC_IRQ(MTU2_TGI1B, 165),
	INTC_IRQ(MTU2_TCI1V, 168), INTC_IRQ(MTU2_TCI1U, 169),
	INTC_IRQ(MTU2_TGI2A, 172), INTC_IRQ(MTU2_TGI2B, 173),
	INTC_IRQ(MTU2_TCI2V, 176), INTC_IRQ(MTU2_TCI2U, 177),
	INTC_IRQ(MTU2_TGI3A, 180), INTC_IRQ(MTU2_TGI3B, 181),
	INTC_IRQ(MTU2_TGI3C, 182), INTC_IRQ(MTU2_TGI3D, 183),
	INTC_IRQ(MTU2_TCI3V, 184),
	INTC_IRQ(MTU2_TGI4A, 188), INTC_IRQ(MTU2_TGI4B, 189),
	INTC_IRQ(MTU2_TGI4C, 190), INTC_IRQ(MTU2_TGI4D, 191),
	INTC_IRQ(MTU2_TCI4V, 192),
	INTC_IRQ(MTU2_TGI5U, 196), INTC_IRQ(MTU2_TGI5V, 197),
	INTC_IRQ(MTU2_TGI5W, 198),
	INTC_IRQ(POE2_OEI1, 200), INTC_IRQ(POE2_OEI2, 201),
	INTC_IRQ(MTU2S_TGI3A, 204), INTC_IRQ(MTU2S_TGI3B, 205),
	INTC_IRQ(MTU2S_TGI3C, 206), INTC_IRQ(MTU2S_TGI3D, 207),
	INTC_IRQ(MTU2S_TCI3V, 208),
	INTC_IRQ(MTU2S_TGI4A, 212), INTC_IRQ(MTU2S_TGI4B, 213),
	INTC_IRQ(MTU2S_TGI4C, 214), INTC_IRQ(MTU2S_TGI4D, 215),
	INTC_IRQ(MTU2S_TCI4V, 216),
	INTC_IRQ(MTU2S_TGI5U, 220), INTC_IRQ(MTU2S_TGI5V, 221),
	INTC_IRQ(MTU2S_TGI5W, 222),
	INTC_IRQ(POE2_OEI3, 224),
	INTC_IRQ(IIC3_STPI, 228), INTC_IRQ(IIC3_NAKI, 229),
	INTC_IRQ(IIC3_RXI, 230), INTC_IRQ(IIC3_TXI, 231),
	INTC_IRQ(IIC3_TEI, 232),
	INTC_IRQ(SCIF0_BRI, 240), INTC_IRQ(SCIF0_ERI, 241),
	INTC_IRQ(SCIF0_RXI, 242), INTC_IRQ(SCIF0_TXI, 243),
	INTC_IRQ(SCIF1_BRI, 244), INTC_IRQ(SCIF1_ERI, 245),
	INTC_IRQ(SCIF1_RXI, 246), INTC_IRQ(SCIF1_TXI, 247),
	INTC_IRQ(SCIF2_BRI, 248), INTC_IRQ(SCIF2_ERI, 249),
	INTC_IRQ(SCIF2_RXI, 250), INTC_IRQ(SCIF2_TXI, 251),
	INTC_IRQ(SCIF3_BRI, 252), INTC_IRQ(SCIF3_ERI, 253),
	INTC_IRQ(SCIF3_RXI, 254), INTC_IRQ(SCIF3_TXI, 255),
	INTC_IRQ(DMAC0, 108), INTC_IRQ(DMAC0, 109),
	INTC_IRQ(DMAC1, 112), INTC_IRQ(DMAC1, 113),
	INTC_IRQ(DMAC2, 116), INTC_IRQ(DMAC2, 117),
	INTC_IRQ(DMAC3, 120), INTC_IRQ(DMAC3, 121),
	INTC_IRQ(DMAC4, 124), INTC_IRQ(DMAC4, 125),
	INTC_IRQ(DMAC5, 128), INTC_IRQ(DMAC5, 129),
	INTC_IRQ(DMAC6, 132), INTC_IRQ(DMAC6, 133),
	INTC_IRQ(DMAC7, 136), INTC_IRQ(DMAC7, 137),
	INTC_IRQ(CMT0, 140), INTC_IRQ(CMT1, 144),
	INTC_IRQ(BSC, 148), INTC_IRQ(WDT, 152),
	INTC_IRQ(MTU0_ABCD, 156), INTC_IRQ(MTU0_ABCD, 157),
	INTC_IRQ(MTU0_ABCD, 158), INTC_IRQ(MTU0_ABCD, 159),
	INTC_IRQ(MTU0_VEF, 160), INTC_IRQ(MTU0_VEF, 161),
	INTC_IRQ(MTU0_VEF, 162),
	INTC_IRQ(MTU1_AB, 164), INTC_IRQ(MTU1_AB, 165),
	INTC_IRQ(MTU1_VU, 168), INTC_IRQ(MTU1_VU, 169),
	INTC_IRQ(MTU2_AB, 172), INTC_IRQ(MTU2_AB, 173),
	INTC_IRQ(MTU2_VU, 176), INTC_IRQ(MTU2_VU, 177),
	INTC_IRQ(MTU3_ABCD, 180), INTC_IRQ(MTU3_ABCD, 181),
	INTC_IRQ(MTU3_ABCD, 182), INTC_IRQ(MTU3_ABCD, 183),
	INTC_IRQ(MTU2_TCI3V, 184),
	INTC_IRQ(MTU4_ABCD, 188), INTC_IRQ(MTU4_ABCD, 189),
	INTC_IRQ(MTU4_ABCD, 190), INTC_IRQ(MTU4_ABCD, 191),
	INTC_IRQ(MTU2_TCI4V, 192),
	INTC_IRQ(MTU5, 196), INTC_IRQ(MTU5, 197),
	INTC_IRQ(MTU5, 198),
	INTC_IRQ(POE2_12, 200), INTC_IRQ(POE2_12, 201),
	INTC_IRQ(MTU3S_ABCD, 204), INTC_IRQ(MTU3S_ABCD, 205),
	INTC_IRQ(MTU3S_ABCD, 206), INTC_IRQ(MTU3S_ABCD, 207),
	INTC_IRQ(MTU2S_TCI3V, 208),
	INTC_IRQ(MTU4S_ABCD, 212), INTC_IRQ(MTU4S_ABCD, 213),
	INTC_IRQ(MTU4S_ABCD, 214), INTC_IRQ(MTU4S_ABCD, 215),
	INTC_IRQ(MTU2S_TCI4V, 216),
	INTC_IRQ(MTU5S, 220), INTC_IRQ(MTU5S, 221),
	INTC_IRQ(MTU5S, 222),
	INTC_IRQ(POE2_OEI3, 224),
	INTC_IRQ(IIC3, 228), INTC_IRQ(IIC3, 229),
	INTC_IRQ(IIC3, 230), INTC_IRQ(IIC3, 231),
	INTC_IRQ(IIC3, 232),
	INTC_IRQ(SCIF0, 240), INTC_IRQ(SCIF0, 241),
	INTC_IRQ(SCIF0, 242), INTC_IRQ(SCIF0, 243),
	INTC_IRQ(SCIF1, 244), INTC_IRQ(SCIF1, 245),
	INTC_IRQ(SCIF1, 246), INTC_IRQ(SCIF1, 247),
	INTC_IRQ(SCIF2, 248), INTC_IRQ(SCIF2, 249),
	INTC_IRQ(SCIF2, 250), INTC_IRQ(SCIF2, 251),
	INTC_IRQ(SCIF3, 252), INTC_IRQ(SCIF3, 253),
	INTC_IRQ(SCIF3, 254), INTC_IRQ(SCIF3, 255),
};

static struct intc_group groups[] __initdata = {
	INTC_GROUP(PINT, PINT0, PINT1, PINT2, PINT3,
		   PINT4, PINT5, PINT6, PINT7),
	INTC_GROUP(DMAC0, DMAC0_DEI, DMAC0_HEI),
	INTC_GROUP(DMAC1, DMAC1_DEI, DMAC1_HEI),
	INTC_GROUP(DMAC2, DMAC2_DEI, DMAC2_HEI),
	INTC_GROUP(DMAC3, DMAC3_DEI, DMAC3_HEI),
	INTC_GROUP(DMAC4, DMAC4_DEI, DMAC4_HEI),
	INTC_GROUP(DMAC5, DMAC5_DEI, DMAC5_HEI),
	INTC_GROUP(DMAC6, DMAC6_DEI, DMAC6_HEI),
	INTC_GROUP(DMAC7, DMAC7_DEI, DMAC7_HEI),
	INTC_GROUP(MTU0_ABCD, MTU2_TGI0A, MTU2_TGI0B, MTU2_TGI0C, MTU2_TGI0D),
	INTC_GROUP(MTU0_VEF, MTU2_TCI0V, MTU2_TGI0E, MTU2_TGI0F),
	INTC_GROUP(MTU1_AB, MTU2_TGI1A, MTU2_TGI1B),
	INTC_GROUP(MTU1_VU, MTU2_TCI1V, MTU2_TCI1U),
	INTC_GROUP(MTU2_AB, MTU2_TGI2A, MTU2_TGI2B),
	INTC_GROUP(MTU2_VU, MTU2_TCI2V, MTU2_TCI2U),
	INTC_GROUP(MTU3_ABCD, MTU2_TGI3A, MTU2_TGI3B, MTU2_TGI3C, MTU2_TGI3D),
	INTC_GROUP(MTU4_ABCD, MTU2_TGI4A, MTU2_TGI4B, MTU2_TGI4C, MTU2_TGI4D),
	INTC_GROUP(MTU5, MTU2_TGI5U, MTU2_TGI5V, MTU2_TGI5W),
	INTC_GROUP(POE2_12, POE2_OEI1, POE2_OEI2),
	INTC_GROUP(MTU3S_ABCD, MTU2S_TGI3A, MTU2S_TGI3B,
		   MTU2S_TGI3C, MTU2S_TGI3D),
	INTC_GROUP(MTU4S_ABCD, MTU2S_TGI4A, MTU2S_TGI4B,
		   MTU2S_TGI4C, MTU2S_TGI4D),
	INTC_GROUP(MTU5S, MTU2S_TGI5U, MTU2S_TGI5V, MTU2S_TGI5W),
	INTC_GROUP(IIC3, IIC3_STPI, IIC3_NAKI, IIC3_RXI, IIC3_TXI, IIC3_TEI),
	INTC_GROUP(SCIF0, SCIF0_BRI, SCIF0_ERI, SCIF0_RXI, SCIF0_TXI),
	INTC_GROUP(SCIF1, SCIF1_BRI, SCIF1_ERI, SCIF1_RXI, SCIF1_TXI),
	INTC_GROUP(SCIF2, SCIF2_BRI, SCIF2_ERI, SCIF2_RXI, SCIF2_TXI),
	INTC_GROUP(SCIF3, SCIF3_BRI, SCIF3_ERI, SCIF3_RXI, SCIF3_TXI),
};

static struct intc_prio_reg prio_registers[] __initdata = {
	{ 0xfffe0818, 0, 16, 4, /* IPR01 */ { IRQ0, IRQ1, IRQ2, IRQ3 } },
	{ 0xfffe081a, 0, 16, 4, /* IPR02 */ { IRQ4, IRQ5, IRQ6, IRQ7 } },
	{ 0xfffe0820, 0, 16, 4, /* IPR05 */ { PINT, 0, ADC_ADI0, ADC_ADI1 } },
	{ 0xfffe0c00, 0, 16, 4, /* IPR06 */ { DMAC0, DMAC1, DMAC2, DMAC3 } },
	{ 0xfffe0c02, 0, 16, 4, /* IPR07 */ { DMAC4, DMAC5, DMAC6, DMAC7 } },
	{ 0xfffe0c04, 0, 16, 4, /* IPR08 */ { CMT0, CMT1, BSC, WDT } },
	{ 0xfffe0c06, 0, 16, 4, /* IPR09 */ { MTU0_ABCD, MTU0_VEF,
					      MTU1_AB, MTU1_VU } },
	{ 0xfffe0c08, 0, 16, 4, /* IPR10 */ { MTU2_AB, MTU2_VU,
					      MTU3_ABCD, MTU2_TCI3V } },
	{ 0xfffe0c0a, 0, 16, 4, /* IPR11 */ { MTU4_ABCD, MTU2_TCI4V,
					      MTU5, POE2_12 } },
	{ 0xfffe0c0c, 0, 16, 4, /* IPR12 */ { MTU3S_ABCD, MTU2S_TCI3V,
					      MTU4S_ABCD, MTU2S_TCI4V } },
	{ 0xfffe0c0e, 0, 16, 4, /* IPR13 */ { MTU5S, POE2_OEI3, IIC3, 0 } },
	{ 0xfffe0c10, 0, 16, 4, /* IPR14 */ { SCIF0, SCIF1, SCIF2, SCIF3 } },
};

static struct intc_mask_reg mask_registers[] __initdata = {
	{ 0xfffe0808, 0, 16, /* PINTER */
	  { 0, 0, 0, 0, 0, 0, 0, 0,
	    PINT7, PINT6, PINT5, PINT4, PINT3, PINT2, PINT1, PINT0 } },
};

static DECLARE_INTC_DESC(intc_desc, "sh7206", vectors, groups,
			 mask_registers, prio_registers, NULL);

static struct plat_sci_port sci_platform_data[] = {
	{
		.mapbase	= 0xfffe8000,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		=  { 241, 242, 243, 240 },
	}, {
		.mapbase	= 0xfffe8800,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		=  { 245, 246, 247, 244 },
	}, {
		.mapbase	= 0xfffe9000,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		=  { 249, 250, 251, 248 },
	}, {
		.mapbase	= 0xfffe9800,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		=  { 253, 254, 255, 252 },
	}, {
		.flags = 0,
	}
};

static struct platform_device sci_device = {
	.name		= "sh-sci",
	.id		= -1,
	.dev		= {
		.platform_data	= sci_platform_data,
	},
};

static struct platform_device *sh7206_devices[] __initdata = {
	&sci_device,
static struct plat_sci_port scif0_platform_data = {
	.scscr		= SCSCR_REIE,
	.type		= PORT_SCIF,
};

static struct resource scif0_resources[] = {
	DEFINE_RES_MEM(0xfffe8000, 0x100),
	DEFINE_RES_IRQ(240),
};

static struct platform_device scif0_device = {
	.name		= "sh-sci",
	.id		= 0,
	.resource	= scif0_resources,
	.num_resources	= ARRAY_SIZE(scif0_resources),
	.dev		= {
		.platform_data	= &scif0_platform_data,
	},
};

static struct plat_sci_port scif1_platform_data = {
	.scscr		= SCSCR_REIE,
	.type		= PORT_SCIF,
};

static struct resource scif1_resources[] = {
	DEFINE_RES_MEM(0xfffe8800, 0x100),
	DEFINE_RES_IRQ(244),
};

static struct platform_device scif1_device = {
	.name		= "sh-sci",
	.id		= 1,
	.resource	= scif1_resources,
	.num_resources	= ARRAY_SIZE(scif1_resources),
	.dev		= {
		.platform_data	= &scif1_platform_data,
	},
};

static struct plat_sci_port scif2_platform_data = {
	.scscr		= SCSCR_REIE,
	.type		= PORT_SCIF,
};

static struct resource scif2_resources[] = {
	DEFINE_RES_MEM(0xfffe9000, 0x100),
	DEFINE_RES_IRQ(248),
};

static struct platform_device scif2_device = {
	.name		= "sh-sci",
	.id		= 2,
	.resource	= scif2_resources,
	.num_resources	= ARRAY_SIZE(scif2_resources),
	.dev		= {
		.platform_data	= &scif2_platform_data,
	},
};

static struct plat_sci_port scif3_platform_data = {
	.scscr		= SCSCR_REIE,
	.type		= PORT_SCIF,
};

static struct resource scif3_resources[] = {
	DEFINE_RES_MEM(0xfffe9800, 0x100),
	DEFINE_RES_IRQ(252),
};

static struct platform_device scif3_device = {
	.name		= "sh-sci",
	.id		= 3,
	.resource	= scif3_resources,
	.num_resources	= ARRAY_SIZE(scif3_resources),
	.dev		= {
		.platform_data	= &scif3_platform_data,
	},
};

static struct sh_timer_config cmt_platform_data = {
	.channels_mask = 3,
};

static struct resource cmt_resources[] = {
	DEFINE_RES_MEM(0xfffec000, 0x10),
	DEFINE_RES_IRQ(140),
	DEFINE_RES_IRQ(144),
};

static struct platform_device cmt_device = {
	.name		= "sh-cmt-16",
	.id		= 0,
	.dev = {
		.platform_data	= &cmt_platform_data,
	},
	.resource	= cmt_resources,
	.num_resources	= ARRAY_SIZE(cmt_resources),
};

static struct resource mtu2_resources[] = {
	DEFINE_RES_MEM(0xfffe4000, 0x400),
	DEFINE_RES_IRQ_NAMED(156, "tgi0a"),
	DEFINE_RES_IRQ_NAMED(164, "tgi1a"),
	DEFINE_RES_IRQ_NAMED(180, "tgi2a"),
};

static struct platform_device mtu2_device = {
	.name		= "sh-mtu2s",
	.id		= -1,
	.resource	= mtu2_resources,
	.num_resources	= ARRAY_SIZE(mtu2_resources),
};

static struct platform_device *sh7206_devices[] __initdata = {
	&scif0_device,
	&scif1_device,
	&scif2_device,
	&scif3_device,
	&cmt_device,
	&mtu2_device,
};

static int __init sh7206_devices_setup(void)
{
	return platform_add_devices(sh7206_devices,
				    ARRAY_SIZE(sh7206_devices));
}
__initcall(sh7206_devices_setup);
arch_initcall(sh7206_devices_setup);

void __init plat_irq_setup(void)
{
	register_intc_controller(&intc_desc);
}

static struct platform_device *sh7206_early_devices[] __initdata = {
	&scif0_device,
	&scif1_device,
	&scif2_device,
	&scif3_device,
	&cmt_device,
	&mtu2_device,
};

#define STBCR3 0xfffe0408
#define STBCR4 0xfffe040c

void __init plat_early_device_setup(void)
{
	/* enable CMT clock */
	__raw_writeb(__raw_readb(STBCR4) & ~0x04, STBCR4);

	/* enable MTU2 clock */
	__raw_writeb(__raw_readb(STBCR3) & ~0x20, STBCR3);

	early_platform_add_devices(sh7206_early_devices,
				   ARRAY_SIZE(sh7206_early_devices));
}
