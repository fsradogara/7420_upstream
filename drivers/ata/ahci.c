/*
 *  ahci.c - AHCI SATA support
 *
 *  Maintained by:  Jeff Garzik <jgarzik@pobox.com>
 *  Maintained by:  Tejun Heo <tj@kernel.org>
 *    		    Please ALWAYS copy linux-ide@vger.kernel.org
 *		    on emails.
 *
 *  Copyright 2004-2005 Red Hat, Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 * libata documentation is available via 'make {ps|pdf}docs',
 * as Documentation/driver-api/libata.rst
 *
 * AHCI hardware documentation:
 * http://www.intel.com/technology/serialata/pdf/rev1_0.pdf
 * http://www.intel.com/technology/serialata/pdf/rev1_1.pdf
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/dmi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <linux/libata.h>
#include <linux/gfp.h>
#include <linux/msi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <linux/libata.h>
#include <linux/ahci-remap.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include "ahci.h"

#define DRV_NAME	"ahci"
#define DRV_VERSION	"3.0"

static int ahci_skip_host_reset;
module_param_named(skip_host_reset, ahci_skip_host_reset, int, 0444);
MODULE_PARM_DESC(skip_host_reset, "skip global host reset (0=don't skip, 1=skip)");

static int ahci_enable_alpm(struct ata_port *ap,
		enum link_pm policy);
static void ahci_disable_alpm(struct ata_port *ap);
static ssize_t ahci_led_show(struct ata_port *ap, char *buf);
static ssize_t ahci_led_store(struct ata_port *ap, const char *buf,
			      size_t size);
static ssize_t ahci_transmit_led_message(struct ata_port *ap, u32 state,
					ssize_t size);
#define MAX_SLOTS 8

enum {
	AHCI_PCI_BAR		= 5,
	AHCI_MAX_PORTS		= 32,
	AHCI_MAX_SG		= 168, /* hardware max is 64K */
	AHCI_DMA_BOUNDARY	= 0xffffffff,
	AHCI_MAX_CMDS		= 32,
	AHCI_CMD_SZ		= 32,
	AHCI_CMD_SLOT_SZ	= AHCI_MAX_CMDS * AHCI_CMD_SZ,
	AHCI_RX_FIS_SZ		= 256,
	AHCI_CMD_TBL_CDB	= 0x40,
	AHCI_CMD_TBL_HDR_SZ	= 0x80,
	AHCI_CMD_TBL_SZ		= AHCI_CMD_TBL_HDR_SZ + (AHCI_MAX_SG * 16),
	AHCI_CMD_TBL_AR_SZ	= AHCI_CMD_TBL_SZ * AHCI_MAX_CMDS,
	AHCI_PORT_PRIV_DMA_SZ	= AHCI_CMD_SLOT_SZ + AHCI_CMD_TBL_AR_SZ +
				  AHCI_RX_FIS_SZ,
	AHCI_IRQ_ON_SG		= (1 << 31),
	AHCI_CMD_ATAPI		= (1 << 5),
	AHCI_CMD_WRITE		= (1 << 6),
	AHCI_CMD_PREFETCH	= (1 << 7),
	AHCI_CMD_RESET		= (1 << 8),
	AHCI_CMD_CLR_BUSY	= (1 << 10),

	RX_FIS_D2H_REG		= 0x40,	/* offset of D2H Register FIS data */
	RX_FIS_SDB		= 0x58, /* offset of SDB FIS data */
	RX_FIS_UNK		= 0x60, /* offset of Unknown FIS data */

	board_ahci		= 0,
	board_ahci_vt8251	= 1,
	board_ahci_ign_iferr	= 2,
	board_ahci_sb600	= 3,
	board_ahci_mv		= 4,
	board_ahci_sb700	= 5,
	board_ahci_mcp65	= 6,
	board_ahci_nopmp	= 7,

	/* global controller registers */
	HOST_CAP		= 0x00, /* host capabilities */
	HOST_CTL		= 0x04, /* global host control */
	HOST_IRQ_STAT		= 0x08, /* interrupt status */
	HOST_PORTS_IMPL		= 0x0c, /* bitmap of implemented ports */
	HOST_VERSION		= 0x10, /* AHCI spec. version compliancy */
	HOST_EM_LOC		= 0x1c, /* Enclosure Management location */
	HOST_EM_CTL		= 0x20, /* Enclosure Management Control */

	/* HOST_CTL bits */
	HOST_RESET		= (1 << 0),  /* reset controller; self-clear */
	HOST_IRQ_EN		= (1 << 1),  /* global IRQ enable */
	HOST_AHCI_EN		= (1 << 31), /* AHCI enabled */

	/* HOST_CAP bits */
	HOST_CAP_EMS		= (1 << 6),  /* Enclosure Management support */
	HOST_CAP_SSC		= (1 << 14), /* Slumber capable */
	HOST_CAP_PMP		= (1 << 17), /* Port Multiplier support */
	HOST_CAP_CLO		= (1 << 24), /* Command List Override support */
	HOST_CAP_ALPM		= (1 << 26), /* Aggressive Link PM support */
	HOST_CAP_SSS		= (1 << 27), /* Staggered Spin-up */
	HOST_CAP_SNTF		= (1 << 29), /* SNotification register */
	HOST_CAP_NCQ		= (1 << 30), /* Native Command Queueing */
	HOST_CAP_64		= (1 << 31), /* PCI DAC (64-bit DMA) support */

	/* registers for each SATA port */
	PORT_LST_ADDR		= 0x00, /* command list DMA addr */
	PORT_LST_ADDR_HI	= 0x04, /* command list DMA addr hi */
	PORT_FIS_ADDR		= 0x08, /* FIS rx buf addr */
	PORT_FIS_ADDR_HI	= 0x0c, /* FIS rx buf addr hi */
	PORT_IRQ_STAT		= 0x10, /* interrupt status */
	PORT_IRQ_MASK		= 0x14, /* interrupt enable/disable mask */
	PORT_CMD		= 0x18, /* port command */
	PORT_TFDATA		= 0x20,	/* taskfile data */
	PORT_SIG		= 0x24,	/* device TF signature */
	PORT_CMD_ISSUE		= 0x38, /* command issue */
	PORT_SCR_STAT		= 0x28, /* SATA phy register: SStatus */
	PORT_SCR_CTL		= 0x2c, /* SATA phy register: SControl */
	PORT_SCR_ERR		= 0x30, /* SATA phy register: SError */
	PORT_SCR_ACT		= 0x34, /* SATA phy register: SActive */
	PORT_SCR_NTF		= 0x3c, /* SATA phy register: SNotification */

	/* PORT_IRQ_{STAT,MASK} bits */
	PORT_IRQ_COLD_PRES	= (1 << 31), /* cold presence detect */
	PORT_IRQ_TF_ERR		= (1 << 30), /* task file error */
	PORT_IRQ_HBUS_ERR	= (1 << 29), /* host bus fatal error */
	PORT_IRQ_HBUS_DATA_ERR	= (1 << 28), /* host bus data error */
	PORT_IRQ_IF_ERR		= (1 << 27), /* interface fatal error */
	PORT_IRQ_IF_NONFATAL	= (1 << 26), /* interface non-fatal error */
	PORT_IRQ_OVERFLOW	= (1 << 24), /* xfer exhausted available S/G */
	PORT_IRQ_BAD_PMP	= (1 << 23), /* incorrect port multiplier */

	PORT_IRQ_PHYRDY		= (1 << 22), /* PhyRdy changed */
	PORT_IRQ_DEV_ILCK	= (1 << 7), /* device interlock */
	PORT_IRQ_CONNECT	= (1 << 6), /* port connect change status */
	PORT_IRQ_SG_DONE	= (1 << 5), /* descriptor processed */
	PORT_IRQ_UNK_FIS	= (1 << 4), /* unknown FIS rx'd */
	PORT_IRQ_SDB_FIS	= (1 << 3), /* Set Device Bits FIS rx'd */
	PORT_IRQ_DMAS_FIS	= (1 << 2), /* DMA Setup FIS rx'd */
	PORT_IRQ_PIOS_FIS	= (1 << 1), /* PIO Setup FIS rx'd */
	PORT_IRQ_D2H_REG_FIS	= (1 << 0), /* D2H Register FIS rx'd */

	PORT_IRQ_FREEZE		= PORT_IRQ_HBUS_ERR |
				  PORT_IRQ_IF_ERR |
				  PORT_IRQ_CONNECT |
				  PORT_IRQ_PHYRDY |
				  PORT_IRQ_UNK_FIS |
				  PORT_IRQ_BAD_PMP,
	PORT_IRQ_ERROR		= PORT_IRQ_FREEZE |
				  PORT_IRQ_TF_ERR |
				  PORT_IRQ_HBUS_DATA_ERR,
	DEF_PORT_IRQ		= PORT_IRQ_ERROR | PORT_IRQ_SG_DONE |
				  PORT_IRQ_SDB_FIS | PORT_IRQ_DMAS_FIS |
				  PORT_IRQ_PIOS_FIS | PORT_IRQ_D2H_REG_FIS,

	/* PORT_CMD bits */
	PORT_CMD_ASP		= (1 << 27), /* Aggressive Slumber/Partial */
	PORT_CMD_ALPE		= (1 << 26), /* Aggressive Link PM enable */
	PORT_CMD_ATAPI		= (1 << 24), /* Device is ATAPI */
	PORT_CMD_PMP		= (1 << 17), /* PMP attached */
	PORT_CMD_LIST_ON	= (1 << 15), /* cmd list DMA engine running */
	PORT_CMD_FIS_ON		= (1 << 14), /* FIS DMA engine running */
	PORT_CMD_FIS_RX		= (1 << 4), /* Enable FIS receive DMA engine */
	PORT_CMD_CLO		= (1 << 3), /* Command list override */
	PORT_CMD_POWER_ON	= (1 << 2), /* Power up device */
	PORT_CMD_SPIN_UP	= (1 << 1), /* Spin up device */
	PORT_CMD_START		= (1 << 0), /* Enable port DMA engine */

	PORT_CMD_ICC_MASK	= (0xf << 28), /* i/f ICC state mask */
	PORT_CMD_ICC_ACTIVE	= (0x1 << 28), /* Put i/f in active state */
	PORT_CMD_ICC_PARTIAL	= (0x2 << 28), /* Put i/f in partial state */
	PORT_CMD_ICC_SLUMBER	= (0x6 << 28), /* Put i/f in slumber state */

	/* hpriv->flags bits */
	AHCI_HFLAG_NO_NCQ		= (1 << 0),
	AHCI_HFLAG_IGN_IRQ_IF_ERR	= (1 << 1), /* ignore IRQ_IF_ERR */
	AHCI_HFLAG_IGN_SERR_INTERNAL	= (1 << 2), /* ignore SERR_INTERNAL */
	AHCI_HFLAG_32BIT_ONLY		= (1 << 3), /* force 32bit */
	AHCI_HFLAG_MV_PATA		= (1 << 4), /* PATA port */
	AHCI_HFLAG_NO_MSI		= (1 << 5), /* no PCI MSI */
	AHCI_HFLAG_NO_PMP		= (1 << 6), /* no PMP */
	AHCI_HFLAG_NO_HOTPLUG		= (1 << 7), /* ignore PxSERR.DIAG.N */
	AHCI_HFLAG_SECT255		= (1 << 8), /* max 255 sectors */
	AHCI_HFLAG_YES_NCQ		= (1 << 9), /* force NCQ cap on */

	/* ap->flags bits */

	AHCI_FLAG_COMMON		= ATA_FLAG_SATA | ATA_FLAG_NO_LEGACY |
					  ATA_FLAG_MMIO | ATA_FLAG_PIO_DMA |
					  ATA_FLAG_ACPI_SATA | ATA_FLAG_AN |
					  ATA_FLAG_IPM,

	ICH_MAP				= 0x90, /* ICH MAP register */

	/* em_ctl bits */
	EM_CTL_RST			= (1 << 9), /* Reset */
	EM_CTL_TM			= (1 << 8), /* Transmit Message */
	EM_CTL_ALHD			= (1 << 26), /* Activity LED */
};

struct ahci_cmd_hdr {
	__le32			opts;
	__le32			status;
	__le32			tbl_addr;
	__le32			tbl_addr_hi;
	__le32			reserved[4];
};

struct ahci_sg {
	__le32			addr;
	__le32			addr_hi;
	__le32			reserved;
	__le32			flags_size;
};

struct ahci_em_priv {
	enum sw_activity blink_policy;
	struct timer_list timer;
	unsigned long saved_activity;
	unsigned long activity;
	unsigned long led_state;
};

struct ahci_host_priv {
	unsigned int		flags;		/* AHCI_HFLAG_* */
	u32			cap;		/* cap to use */
	u32			port_map;	/* port map to use */
	u32			saved_cap;	/* saved initial cap */
	u32			saved_port_map;	/* saved initial port_map */
	u32 			em_loc; /* enclosure management location */
};

struct ahci_port_priv {
	struct ata_link		*active_link;
	struct ahci_cmd_hdr	*cmd_slot;
	dma_addr_t		cmd_slot_dma;
	void			*cmd_tbl;
	dma_addr_t		cmd_tbl_dma;
	void			*rx_fis;
	dma_addr_t		rx_fis_dma;
	/* for NCQ spurious interrupt analysis */
	unsigned int		ncq_saw_d2h:1;
	unsigned int		ncq_saw_dmas:1;
	unsigned int		ncq_saw_sdb:1;
	u32 			intr_mask;	/* interrupts to enable */
	struct ahci_em_priv	em_priv[MAX_SLOTS];/* enclosure management info
					 	 * per PM slot */
};

static int ahci_scr_read(struct ata_port *ap, unsigned int sc_reg, u32 *val);
static int ahci_scr_write(struct ata_port *ap, unsigned int sc_reg, u32 val);
static int ahci_init_one(struct pci_dev *pdev, const struct pci_device_id *ent);
static unsigned int ahci_qc_issue(struct ata_queued_cmd *qc);
static bool ahci_qc_fill_rtf(struct ata_queued_cmd *qc);
static int ahci_port_start(struct ata_port *ap);
static void ahci_port_stop(struct ata_port *ap);
static void ahci_qc_prep(struct ata_queued_cmd *qc);
static void ahci_freeze(struct ata_port *ap);
static void ahci_thaw(struct ata_port *ap);
static void ahci_pmp_attach(struct ata_port *ap);
static void ahci_pmp_detach(struct ata_port *ap);
static int ahci_softreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline);
static int ahci_sb600_softreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline);
static int ahci_hardreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline);
static int ahci_vt8251_hardreset(struct ata_link *link, unsigned int *class,
				 unsigned long deadline);
static int ahci_p5wdh_hardreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline);
static void ahci_postreset(struct ata_link *link, unsigned int *class);
static void ahci_error_handler(struct ata_port *ap);
static void ahci_post_internal_cmd(struct ata_queued_cmd *qc);
static int ahci_port_resume(struct ata_port *ap);
static void ahci_dev_config(struct ata_device *dev);
static unsigned int ahci_fill_sg(struct ata_queued_cmd *qc, void *cmd_tbl);
static void ahci_fill_cmd_slot(struct ahci_port_priv *pp, unsigned int tag,
			       u32 opts);
#ifdef CONFIG_PM
static int ahci_port_suspend(struct ata_port *ap, pm_message_t mesg);
static int ahci_pci_device_suspend(struct pci_dev *pdev, pm_message_t mesg);
static int ahci_pci_device_resume(struct pci_dev *pdev);
#endif
static ssize_t ahci_activity_show(struct ata_device *dev, char *buf);
static ssize_t ahci_activity_store(struct ata_device *dev,
				   enum sw_activity val);
static void ahci_init_sw_activity(struct ata_link *link);

static struct device_attribute *ahci_shost_attrs[] = {
	&dev_attr_link_power_management_policy,
	&dev_attr_em_message_type,
	&dev_attr_em_message,
	NULL
};

static struct device_attribute *ahci_sdev_attrs[] = {
	&dev_attr_sw_activity,
	NULL
};

static struct scsi_host_template ahci_sht = {
	ATA_NCQ_SHT(DRV_NAME),
	.can_queue		= AHCI_MAX_CMDS - 1,
	.sg_tablesize		= AHCI_MAX_SG,
	.dma_boundary		= AHCI_DMA_BOUNDARY,
	.shost_attrs		= ahci_shost_attrs,
	.sdev_attrs		= ahci_sdev_attrs,
};

static struct ata_port_operations ahci_ops = {
	.inherits		= &sata_pmp_port_ops,

	.qc_defer		= sata_pmp_qc_defer_cmd_switch,
	.qc_prep		= ahci_qc_prep,
	.qc_issue		= ahci_qc_issue,
	.qc_fill_rtf		= ahci_qc_fill_rtf,

	.freeze			= ahci_freeze,
	.thaw			= ahci_thaw,
	.softreset		= ahci_softreset,
	.hardreset		= ahci_hardreset,
	.postreset		= ahci_postreset,
	.pmp_softreset		= ahci_softreset,
	.error_handler		= ahci_error_handler,
	.post_internal_cmd	= ahci_post_internal_cmd,
	.dev_config		= ahci_dev_config,

	.scr_read		= ahci_scr_read,
	.scr_write		= ahci_scr_write,
	.pmp_attach		= ahci_pmp_attach,
	.pmp_detach		= ahci_pmp_detach,

	.enable_pm		= ahci_enable_alpm,
	.disable_pm		= ahci_disable_alpm,
	.em_show		= ahci_led_show,
	.em_store		= ahci_led_store,
	.sw_activity_show	= ahci_activity_show,
	.sw_activity_store	= ahci_activity_store,
#ifdef CONFIG_PM
	.port_suspend		= ahci_port_suspend,
	.port_resume		= ahci_port_resume,
#endif
	.port_start		= ahci_port_start,
	.port_stop		= ahci_port_stop,
enum {
	AHCI_PCI_BAR_STA2X11	= 0,
	AHCI_PCI_BAR_CAVIUM	= 0,
	AHCI_PCI_BAR_ENMOTUS	= 2,
	AHCI_PCI_BAR_STANDARD	= 5,
};

enum board_ids {
	/* board IDs by feature in alphabetical order */
	board_ahci,
	board_ahci_ign_iferr,
	board_ahci_nomsi,
	board_ahci_noncq,
	board_ahci_nosntf,
	board_ahci_yes_fbs,

	/* board IDs for specific chipsets in alphabetical order */
	board_ahci_avn,
	board_ahci_mcp65,
	board_ahci_mcp77,
	board_ahci_mcp89,
	board_ahci_mv,
	board_ahci_sb600,
	board_ahci_sb700,	/* for SB700 and SB800 */
	board_ahci_vt8251,

	/* aliases */
	board_ahci_mcp_linux	= board_ahci_mcp65,
	board_ahci_mcp67	= board_ahci_mcp65,
	board_ahci_mcp73	= board_ahci_mcp65,
	board_ahci_mcp79	= board_ahci_mcp77,
};

static int ahci_init_one(struct pci_dev *pdev, const struct pci_device_id *ent);
static void ahci_remove_one(struct pci_dev *dev);
static int ahci_vt8251_hardreset(struct ata_link *link, unsigned int *class,
				 unsigned long deadline);
static int ahci_avn_hardreset(struct ata_link *link, unsigned int *class,
			      unsigned long deadline);
static void ahci_mcp89_apple_enable(struct pci_dev *pdev);
static bool is_mcp89_apple(struct pci_dev *pdev);
static int ahci_p5wdh_hardreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline);
#ifdef CONFIG_PM
static int ahci_pci_device_runtime_suspend(struct device *dev);
static int ahci_pci_device_runtime_resume(struct device *dev);
#ifdef CONFIG_PM_SLEEP
static int ahci_pci_device_suspend(struct device *dev);
static int ahci_pci_device_resume(struct device *dev);
#endif
#endif /* CONFIG_PM */

static struct scsi_host_template ahci_sht = {
	AHCI_SHT("ahci"),
};

static struct ata_port_operations ahci_vt8251_ops = {
	.inherits		= &ahci_ops,
	.hardreset		= ahci_vt8251_hardreset,
};

static struct ata_port_operations ahci_p5wdh_ops = {
	.inherits		= &ahci_ops,
	.hardreset		= ahci_p5wdh_hardreset,
};

static struct ata_port_operations ahci_sb600_ops = {
	.inherits		= &ahci_ops,
	.softreset		= ahci_sb600_softreset,
	.pmp_softreset		= ahci_sb600_softreset,
};

#define AHCI_HFLAGS(flags)	.private_data	= (void *)(flags)

static const struct ata_port_info ahci_port_info[] = {
	/* board_ahci */
	{
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	/* board_ahci_vt8251 */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_NO_NCQ | AHCI_HFLAG_NO_PMP),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_vt8251_ops,
	},
	/* board_ahci_ign_iferr */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_IGN_IRQ_IF_ERR),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	/* board_ahci_sb600 */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_IGN_SERR_INTERNAL |
				 AHCI_HFLAG_32BIT_ONLY | AHCI_HFLAG_NO_MSI |
				 AHCI_HFLAG_SECT255),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_sb600_ops,
	},
	/* board_ahci_mv */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_NO_NCQ | AHCI_HFLAG_NO_MSI |
				 AHCI_HFLAG_MV_PATA | AHCI_HFLAG_NO_PMP),
		.flags		= ATA_FLAG_SATA | ATA_FLAG_NO_LEGACY |
				  ATA_FLAG_MMIO | ATA_FLAG_PIO_DMA,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	/* board_ahci_sb700 */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_IGN_SERR_INTERNAL),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_sb600_ops,
	},
	/* board_ahci_mcp65 */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_YES_NCQ),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	/* board_ahci_nopmp */
	{
		AHCI_HFLAGS	(AHCI_HFLAG_NO_PMP),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= 0x1f, /* pio0-4 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
static struct ata_port_operations ahci_avn_ops = {
	.inherits		= &ahci_ops,
	.hardreset		= ahci_avn_hardreset,
};

static const struct ata_port_info ahci_port_info[] = {
	/* by features */
	[board_ahci] = {
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_ign_iferr] = {
		AHCI_HFLAGS	(AHCI_HFLAG_IGN_IRQ_IF_ERR),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_nomsi] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_MSI),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_noncq] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_NCQ),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_nosntf] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_SNTF),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_yes_fbs] = {
		AHCI_HFLAGS	(AHCI_HFLAG_YES_FBS),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	/* by chipsets */
	[board_ahci_avn] = {
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_avn_ops,
	},
	[board_ahci_mcp65] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_FPDMA_AA | AHCI_HFLAG_NO_PMP |
				 AHCI_HFLAG_YES_NCQ),
		.flags		= AHCI_FLAG_COMMON | ATA_FLAG_NO_DIPM,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_mcp77] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_FPDMA_AA | AHCI_HFLAG_NO_PMP),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_mcp89] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_FPDMA_AA),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_mv] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_NCQ | AHCI_HFLAG_NO_MSI |
				 AHCI_HFLAG_MV_PATA | AHCI_HFLAG_NO_PMP),
		.flags		= ATA_FLAG_SATA | ATA_FLAG_PIO_DMA,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_ops,
	},
	[board_ahci_sb600] = {
		AHCI_HFLAGS	(AHCI_HFLAG_IGN_SERR_INTERNAL |
				 AHCI_HFLAG_NO_MSI | AHCI_HFLAG_SECT255 |
				 AHCI_HFLAG_32BIT_ONLY),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_pmp_retry_srst_ops,
	},
	[board_ahci_sb700] = {	/* for SB700 and SB800 */
		AHCI_HFLAGS	(AHCI_HFLAG_IGN_SERR_INTERNAL),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_pmp_retry_srst_ops,
	},
	[board_ahci_vt8251] = {
		AHCI_HFLAGS	(AHCI_HFLAG_NO_NCQ | AHCI_HFLAG_NO_PMP),
		.flags		= AHCI_FLAG_COMMON,
		.pio_mask	= ATA_PIO4,
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &ahci_vt8251_ops,
	},
};

static const struct pci_device_id ahci_pci_tbl[] = {
	/* Intel */
	{ PCI_VDEVICE(INTEL, 0x2652), board_ahci }, /* ICH6 */
	{ PCI_VDEVICE(INTEL, 0x2653), board_ahci }, /* ICH6M */
	{ PCI_VDEVICE(INTEL, 0x27c1), board_ahci }, /* ICH7 */
	{ PCI_VDEVICE(INTEL, 0x27c5), board_ahci }, /* ICH7M */
	{ PCI_VDEVICE(INTEL, 0x27c3), board_ahci }, /* ICH7R */
	{ PCI_VDEVICE(AL, 0x5288), board_ahci_ign_iferr }, /* ULi M5288 */
	{ PCI_VDEVICE(INTEL, 0x2681), board_ahci }, /* ESB2 */
	{ PCI_VDEVICE(INTEL, 0x2682), board_ahci }, /* ESB2 */
	{ PCI_VDEVICE(INTEL, 0x2683), board_ahci }, /* ESB2 */
	{ PCI_VDEVICE(INTEL, 0x27c6), board_ahci }, /* ICH7-M DH */
	{ PCI_VDEVICE(INTEL, 0x2821), board_ahci }, /* ICH8 */
	{ PCI_VDEVICE(INTEL, 0x2822), board_ahci }, /* ICH8 */
	{ PCI_VDEVICE(INTEL, 0x2822), board_ahci_nosntf }, /* ICH8 */
	{ PCI_VDEVICE(INTEL, 0x2824), board_ahci }, /* ICH8 */
	{ PCI_VDEVICE(INTEL, 0x2829), board_ahci }, /* ICH8M */
	{ PCI_VDEVICE(INTEL, 0x282a), board_ahci }, /* ICH8M */
	{ PCI_VDEVICE(INTEL, 0x2922), board_ahci }, /* ICH9 */
	{ PCI_VDEVICE(INTEL, 0x2923), board_ahci }, /* ICH9 */
	{ PCI_VDEVICE(INTEL, 0x2924), board_ahci }, /* ICH9 */
	{ PCI_VDEVICE(INTEL, 0x2925), board_ahci }, /* ICH9 */
	{ PCI_VDEVICE(INTEL, 0x2927), board_ahci }, /* ICH9 */
	{ PCI_VDEVICE(INTEL, 0x2929), board_ahci }, /* ICH9M */
	{ PCI_VDEVICE(INTEL, 0x292a), board_ahci }, /* ICH9M */
	{ PCI_VDEVICE(INTEL, 0x292b), board_ahci }, /* ICH9M */
	{ PCI_VDEVICE(INTEL, 0x292c), board_ahci }, /* ICH9M */
	{ PCI_VDEVICE(INTEL, 0x292f), board_ahci }, /* ICH9M */
	{ PCI_VDEVICE(INTEL, 0x294d), board_ahci }, /* ICH9 */
	{ PCI_VDEVICE(INTEL, 0x294e), board_ahci }, /* ICH9M */
	{ PCI_VDEVICE(INTEL, 0x502a), board_ahci }, /* Tolapai */
	{ PCI_VDEVICE(INTEL, 0x502b), board_ahci }, /* Tolapai */
	{ PCI_VDEVICE(INTEL, 0x3a05), board_ahci }, /* ICH10 */
	{ PCI_VDEVICE(INTEL, 0x3a25), board_ahci }, /* ICH10 */
	{ PCI_VDEVICE(INTEL, 0x3b24), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b25), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b2b), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b2c), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3a22), board_ahci }, /* ICH10 */
	{ PCI_VDEVICE(INTEL, 0x3a25), board_ahci }, /* ICH10 */
	{ PCI_VDEVICE(INTEL, 0x3b22), board_ahci }, /* PCH AHCI */
	{ PCI_VDEVICE(INTEL, 0x3b23), board_ahci }, /* PCH AHCI */
	{ PCI_VDEVICE(INTEL, 0x3b24), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b25), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b29), board_ahci }, /* PCH AHCI */
	{ PCI_VDEVICE(INTEL, 0x3b2b), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b2c), board_ahci }, /* PCH RAID */
	{ PCI_VDEVICE(INTEL, 0x3b2f), board_ahci }, /* PCH AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b0), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b1), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b2), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b3), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b4), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b5), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b6), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19b7), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19bE), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19bF), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c0), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c1), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c2), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c3), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c4), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c5), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c6), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19c7), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19cE), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x19cF), board_ahci }, /* DNV AHCI */
	{ PCI_VDEVICE(INTEL, 0x1c02), board_ahci }, /* CPT AHCI */
	{ PCI_VDEVICE(INTEL, 0x1c03), board_ahci }, /* CPT AHCI */
	{ PCI_VDEVICE(INTEL, 0x1c04), board_ahci }, /* CPT RAID */
	{ PCI_VDEVICE(INTEL, 0x1c05), board_ahci }, /* CPT RAID */
	{ PCI_VDEVICE(INTEL, 0x1c06), board_ahci }, /* CPT RAID */
	{ PCI_VDEVICE(INTEL, 0x1c07), board_ahci }, /* CPT RAID */
	{ PCI_VDEVICE(INTEL, 0x1d02), board_ahci }, /* PBG AHCI */
	{ PCI_VDEVICE(INTEL, 0x1d04), board_ahci }, /* PBG RAID */
	{ PCI_VDEVICE(INTEL, 0x1d06), board_ahci }, /* PBG RAID */
	{ PCI_VDEVICE(INTEL, 0x2826), board_ahci }, /* PBG RAID */
	{ PCI_VDEVICE(INTEL, 0x2323), board_ahci }, /* DH89xxCC AHCI */
	{ PCI_VDEVICE(INTEL, 0x1e02), board_ahci }, /* Panther Point AHCI */
	{ PCI_VDEVICE(INTEL, 0x1e03), board_ahci }, /* Panther Point AHCI */
	{ PCI_VDEVICE(INTEL, 0x1e04), board_ahci }, /* Panther Point RAID */
	{ PCI_VDEVICE(INTEL, 0x1e05), board_ahci }, /* Panther Point RAID */
	{ PCI_VDEVICE(INTEL, 0x1e06), board_ahci }, /* Panther Point RAID */
	{ PCI_VDEVICE(INTEL, 0x1e07), board_ahci }, /* Panther Point RAID */
	{ PCI_VDEVICE(INTEL, 0x1e0e), board_ahci }, /* Panther Point RAID */
	{ PCI_VDEVICE(INTEL, 0x8c02), board_ahci }, /* Lynx Point AHCI */
	{ PCI_VDEVICE(INTEL, 0x8c03), board_ahci }, /* Lynx Point AHCI */
	{ PCI_VDEVICE(INTEL, 0x8c04), board_ahci }, /* Lynx Point RAID */
	{ PCI_VDEVICE(INTEL, 0x8c05), board_ahci }, /* Lynx Point RAID */
	{ PCI_VDEVICE(INTEL, 0x8c06), board_ahci }, /* Lynx Point RAID */
	{ PCI_VDEVICE(INTEL, 0x8c07), board_ahci }, /* Lynx Point RAID */
	{ PCI_VDEVICE(INTEL, 0x8c0e), board_ahci }, /* Lynx Point RAID */
	{ PCI_VDEVICE(INTEL, 0x8c0f), board_ahci }, /* Lynx Point RAID */
	{ PCI_VDEVICE(INTEL, 0x9c02), board_ahci }, /* Lynx Point-LP AHCI */
	{ PCI_VDEVICE(INTEL, 0x9c03), board_ahci }, /* Lynx Point-LP AHCI */
	{ PCI_VDEVICE(INTEL, 0x9c04), board_ahci }, /* Lynx Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c05), board_ahci }, /* Lynx Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c06), board_ahci }, /* Lynx Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c07), board_ahci }, /* Lynx Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c0e), board_ahci }, /* Lynx Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c0f), board_ahci }, /* Lynx Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x1f22), board_ahci }, /* Avoton AHCI */
	{ PCI_VDEVICE(INTEL, 0x1f23), board_ahci }, /* Avoton AHCI */
	{ PCI_VDEVICE(INTEL, 0x1f24), board_ahci }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f25), board_ahci }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f26), board_ahci }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f27), board_ahci }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f2e), board_ahci }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f2f), board_ahci }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f32), board_ahci_avn }, /* Avoton AHCI */
	{ PCI_VDEVICE(INTEL, 0x1f33), board_ahci_avn }, /* Avoton AHCI */
	{ PCI_VDEVICE(INTEL, 0x1f34), board_ahci_avn }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f35), board_ahci_avn }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f36), board_ahci_avn }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f37), board_ahci_avn }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f3e), board_ahci_avn }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x1f3f), board_ahci_avn }, /* Avoton RAID */
	{ PCI_VDEVICE(INTEL, 0x2823), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x2827), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x8d02), board_ahci }, /* Wellsburg AHCI */
	{ PCI_VDEVICE(INTEL, 0x8d04), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x8d06), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x8d0e), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x8d62), board_ahci }, /* Wellsburg AHCI */
	{ PCI_VDEVICE(INTEL, 0x8d64), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x8d66), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x8d6e), board_ahci }, /* Wellsburg RAID */
	{ PCI_VDEVICE(INTEL, 0x23a3), board_ahci }, /* Coleto Creek AHCI */
	{ PCI_VDEVICE(INTEL, 0x9c83), board_ahci }, /* Wildcat Point-LP AHCI */
	{ PCI_VDEVICE(INTEL, 0x9c85), board_ahci }, /* Wildcat Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c87), board_ahci }, /* Wildcat Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9c8f), board_ahci }, /* Wildcat Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x8c82), board_ahci }, /* 9 Series AHCI */
	{ PCI_VDEVICE(INTEL, 0x8c83), board_ahci }, /* 9 Series AHCI */
	{ PCI_VDEVICE(INTEL, 0x8c84), board_ahci }, /* 9 Series RAID */
	{ PCI_VDEVICE(INTEL, 0x8c85), board_ahci }, /* 9 Series RAID */
	{ PCI_VDEVICE(INTEL, 0x8c86), board_ahci }, /* 9 Series RAID */
	{ PCI_VDEVICE(INTEL, 0x8c87), board_ahci }, /* 9 Series RAID */
	{ PCI_VDEVICE(INTEL, 0x8c8e), board_ahci }, /* 9 Series RAID */
	{ PCI_VDEVICE(INTEL, 0x8c8f), board_ahci }, /* 9 Series RAID */
	{ PCI_VDEVICE(INTEL, 0x9d03), board_ahci }, /* Sunrise Point-LP AHCI */
	{ PCI_VDEVICE(INTEL, 0x9d05), board_ahci }, /* Sunrise Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0x9d07), board_ahci }, /* Sunrise Point-LP RAID */
	{ PCI_VDEVICE(INTEL, 0xa102), board_ahci }, /* Sunrise Point-H AHCI */
	{ PCI_VDEVICE(INTEL, 0xa103), board_ahci }, /* Sunrise Point-H AHCI */
	{ PCI_VDEVICE(INTEL, 0xa105), board_ahci }, /* Sunrise Point-H RAID */
	{ PCI_VDEVICE(INTEL, 0xa106), board_ahci }, /* Sunrise Point-H RAID */
	{ PCI_VDEVICE(INTEL, 0xa107), board_ahci }, /* Sunrise Point-H RAID */
	{ PCI_VDEVICE(INTEL, 0xa10f), board_ahci }, /* Sunrise Point-H RAID */
	{ PCI_VDEVICE(INTEL, 0x2822), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0x2823), board_ahci }, /* Lewisburg AHCI*/
	{ PCI_VDEVICE(INTEL, 0x2826), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0x2827), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0xa182), board_ahci }, /* Lewisburg AHCI*/
	{ PCI_VDEVICE(INTEL, 0xa186), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0xa1d2), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0xa1d6), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0xa202), board_ahci }, /* Lewisburg AHCI*/
	{ PCI_VDEVICE(INTEL, 0xa206), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0xa252), board_ahci }, /* Lewisburg RAID*/
	{ PCI_VDEVICE(INTEL, 0xa256), board_ahci }, /* Lewisburg RAID*/

	/* JMicron 360/1/3/5/6, match class to avoid IDE function */
	{ PCI_VENDOR_ID_JMICRON, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID,
	  PCI_CLASS_STORAGE_SATA_AHCI, 0xffffff, board_ahci_ign_iferr },
	/* JMicron 362B and 362C have an AHCI function with IDE class code */
	{ PCI_VDEVICE(JMICRON, 0x2362), board_ahci_ign_iferr },
	{ PCI_VDEVICE(JMICRON, 0x236f), board_ahci_ign_iferr },
	/* May need to update quirk_jmicron_async_suspend() for additions */

	/* ATI */
	{ PCI_VDEVICE(ATI, 0x4380), board_ahci_sb600 }, /* ATI SB600 */
	{ PCI_VDEVICE(ATI, 0x4390), board_ahci_sb700 }, /* ATI SB700/800 */
	{ PCI_VDEVICE(ATI, 0x4391), board_ahci_sb700 }, /* ATI SB700/800 */
	{ PCI_VDEVICE(ATI, 0x4392), board_ahci_sb700 }, /* ATI SB700/800 */
	{ PCI_VDEVICE(ATI, 0x4393), board_ahci_sb700 }, /* ATI SB700/800 */
	{ PCI_VDEVICE(ATI, 0x4394), board_ahci_sb700 }, /* ATI SB700/800 */
	{ PCI_VDEVICE(ATI, 0x4395), board_ahci_sb700 }, /* ATI SB700/800 */

	/* AMD */
	{ PCI_VDEVICE(AMD, 0x7800), board_ahci }, /* AMD Hudson-2 */
	{ PCI_VDEVICE(AMD, 0x7900), board_ahci }, /* AMD CZ */
	/* AMD is using RAID class only for ahci controllers */
	{ PCI_VENDOR_ID_AMD, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID,
	  PCI_CLASS_STORAGE_RAID << 8, 0xffffff, board_ahci },

	/* VIA */
	{ PCI_VDEVICE(VIA, 0x3349), board_ahci_vt8251 }, /* VIA VT8251 */
	{ PCI_VDEVICE(VIA, 0x6287), board_ahci_vt8251 }, /* VIA VT8251 */

	/* NVIDIA */
	{ PCI_VDEVICE(NVIDIA, 0x044c), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x044d), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x044e), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x044f), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x045c), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x045d), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x045e), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x045f), board_ahci_mcp65 },	/* MCP65 */
	{ PCI_VDEVICE(NVIDIA, 0x0550), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0551), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0552), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0553), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0554), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0555), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0556), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0557), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0558), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0559), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x055a), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x055b), board_ahci },		/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x07f0), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f1), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f2), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f3), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f4), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f5), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f6), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f7), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f8), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f9), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07fa), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07fb), board_ahci },		/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad0), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad1), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad2), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad3), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad4), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad5), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad6), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad7), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad8), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad9), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ada), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0adb), board_ahci },		/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab4), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab5), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab6), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab7), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab8), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab9), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0aba), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abb), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abc), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abd), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abe), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abf), board_ahci },		/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0bc8), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bc9), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bca), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bcb), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bcc), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bcd), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bce), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bcf), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bc4), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bc5), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bc6), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0bc7), board_ahci },		/* MCP7B */
	{ PCI_VDEVICE(NVIDIA, 0x0550), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0551), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0552), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0553), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0554), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0555), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0556), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0557), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0558), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0559), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x055a), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x055b), board_ahci_mcp67 },	/* MCP67 */
	{ PCI_VDEVICE(NVIDIA, 0x0580), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0581), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0582), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0583), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0584), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0585), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0586), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0587), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0588), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x0589), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x058a), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x058b), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x058c), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x058d), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x058e), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x058f), board_ahci_mcp_linux },	/* Linux ID */
	{ PCI_VDEVICE(NVIDIA, 0x07f0), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f1), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f2), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f3), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f4), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f5), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f6), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f7), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f8), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07f9), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07fa), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x07fb), board_ahci_mcp73 },	/* MCP73 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad0), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad1), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad2), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad3), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad4), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad5), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad6), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad7), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad8), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ad9), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ada), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0adb), board_ahci_mcp77 },	/* MCP77 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab4), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab5), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab6), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab7), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab8), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0ab9), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0aba), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abb), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abc), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abd), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abe), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0abf), board_ahci_mcp79 },	/* MCP79 */
	{ PCI_VDEVICE(NVIDIA, 0x0d84), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d85), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d86), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d87), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d88), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d89), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d8a), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d8b), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d8c), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d8d), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d8e), board_ahci_mcp89 },	/* MCP89 */
	{ PCI_VDEVICE(NVIDIA, 0x0d8f), board_ahci_mcp89 },	/* MCP89 */

	/* SiS */
	{ PCI_VDEVICE(SI, 0x1184), board_ahci },		/* SiS 966 */
	{ PCI_VDEVICE(SI, 0x1185), board_ahci },		/* SiS 968 */
	{ PCI_VDEVICE(SI, 0x0186), board_ahci },		/* SiS 968 */

	/* Marvell */
	{ PCI_VDEVICE(MARVELL, 0x6145), board_ahci_mv },	/* 6145 */
	{ PCI_VDEVICE(MARVELL, 0x6121), board_ahci_mv },	/* 6121 */
	/* ST Microelectronics */
	{ PCI_VDEVICE(STMICRO, 0xCC06), board_ahci },		/* ST ConneXt */

	/* Marvell */
	{ PCI_VDEVICE(MARVELL, 0x6145), board_ahci_mv },	/* 6145 */
	{ PCI_VDEVICE(MARVELL, 0x6121), board_ahci_mv },	/* 6121 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x9123),
	  .class = PCI_CLASS_STORAGE_SATA_AHCI,
	  .class_mask = 0xffffff,
	  .driver_data = board_ahci_yes_fbs },			/* 88se9128 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x9125),
	  .driver_data = board_ahci_yes_fbs },			/* 88se9125 */
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_MARVELL_EXT, 0x9178,
			 PCI_VENDOR_ID_MARVELL_EXT, 0x9170),
	  .driver_data = board_ahci_yes_fbs },			/* 88se9170 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x917a),
	  .driver_data = board_ahci_yes_fbs },			/* 88se9172 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x9172),
	  .driver_data = board_ahci_yes_fbs },			/* 88se9182 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x9182),
	  .driver_data = board_ahci_yes_fbs },			/* 88se9172 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x9192),
	  .driver_data = board_ahci_yes_fbs },			/* 88se9172 on some Gigabyte */
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x91a0),
	  .driver_data = board_ahci_yes_fbs },
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x91a2), 	/* 88se91a2 */
	  .driver_data = board_ahci_yes_fbs },
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x91a3),
	  .driver_data = board_ahci_yes_fbs },
	{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL_EXT, 0x9230),
	  .driver_data = board_ahci_yes_fbs },
	{ PCI_DEVICE(PCI_VENDOR_ID_TTI, 0x0642),
	  .driver_data = board_ahci_yes_fbs },

	/* Promise */
	{ PCI_VDEVICE(PROMISE, 0x3f20), board_ahci },	/* PDC42819 */
	{ PCI_VDEVICE(PROMISE, 0x3781), board_ahci },   /* FastTrak TX8660 ahci-mode */

	/* Asmedia */
	{ PCI_VDEVICE(ASMEDIA, 0x0601), board_ahci },	/* ASM1060 */
	{ PCI_VDEVICE(ASMEDIA, 0x0602), board_ahci },	/* ASM1060 */
	{ PCI_VDEVICE(ASMEDIA, 0x0611), board_ahci },	/* ASM1061 */
	{ PCI_VDEVICE(ASMEDIA, 0x0612), board_ahci },	/* ASM1062 */
	{ PCI_VDEVICE(ASMEDIA, 0x0621), board_ahci },   /* ASM1061R */
	{ PCI_VDEVICE(ASMEDIA, 0x0622), board_ahci },   /* ASM1062R */

	/*
	 * Samsung SSDs found on some macbooks.  NCQ times out if MSI is
	 * enabled.  https://bugzilla.kernel.org/show_bug.cgi?id=60731
	 */
	{ PCI_VDEVICE(SAMSUNG, 0x1600), board_ahci_nomsi },
	{ PCI_VDEVICE(SAMSUNG, 0xa800), board_ahci_nomsi },

	/* Enmotus */
	{ PCI_DEVICE(0x1c44, 0x8000), board_ahci },

	/* Generic, PCI class code for AHCI */
	{ PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID,
	  PCI_CLASS_STORAGE_SATA_AHCI, 0xffffff, board_ahci },

	{ }	/* terminate list */
};

static const struct dev_pm_ops ahci_pci_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(ahci_pci_device_suspend, ahci_pci_device_resume)
	SET_RUNTIME_PM_OPS(ahci_pci_device_runtime_suspend,
			   ahci_pci_device_runtime_resume, NULL)
};

static struct pci_driver ahci_pci_driver = {
	.name			= DRV_NAME,
	.id_table		= ahci_pci_tbl,
	.probe			= ahci_init_one,
	.remove			= ahci_remove_one,
	.driver = {
		.pm		= &ahci_pci_pm_ops,
	},
};

static int ahci_em_messages = 1;
module_param(ahci_em_messages, int, 0444);
/* add other LED protocol types when they become supported */
MODULE_PARM_DESC(ahci_em_messages,
	"Set AHCI Enclosure Management Message type (0 = disabled, 1 = LED");

#if defined(CONFIG_PATA_MARVELL) || defined(CONFIG_PATA_MARVELL_MODULE)
#if IS_ENABLED(CONFIG_PATA_MARVELL)
static int marvell_enable;
#else
static int marvell_enable = 1;
#endif
module_param(marvell_enable, int, 0644);
MODULE_PARM_DESC(marvell_enable, "Marvell SATA via AHCI (1 = enabled)");


static inline int ahci_nr_ports(u32 cap)
{
	return (cap & 0x1f) + 1;
}

static inline void __iomem *__ahci_port_base(struct ata_host *host,
					     unsigned int port_no)
{
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];

	return mmio + 0x100 + (port_no * 0x80);
}

static inline void __iomem *ahci_port_base(struct ata_port *ap)
{
	return __ahci_port_base(ap->host, ap->port_no);
}

static void ahci_enable_ahci(void __iomem *mmio)
{
	int i;
	u32 tmp;

	/* turn on AHCI_EN */
	tmp = readl(mmio + HOST_CTL);
	if (tmp & HOST_AHCI_EN)
		return;

	/* Some controllers need AHCI_EN to be written multiple times.
	 * Try a few times before giving up.
	 */
	for (i = 0; i < 5; i++) {
		tmp |= HOST_AHCI_EN;
		writel(tmp, mmio + HOST_CTL);
		tmp = readl(mmio + HOST_CTL);	/* flush && sanity check */
		if (tmp & HOST_AHCI_EN)
			return;
		msleep(10);
	}

	WARN_ON(1);
}

/**
 *	ahci_save_initial_config - Save and fixup initial config values
 *	@pdev: target PCI device
 *	@hpriv: host private area to store config values
 *
 *	Some registers containing configuration info might be setup by
 *	BIOS and might be cleared on reset.  This function saves the
 *	initial values of those registers into @hpriv such that they
 *	can be restored after controller reset.
 *
 *	If inconsistent, config values are fixed up by this function.
 *
 *	LOCKING:
 *	None.
 */
static void ahci_save_initial_config(struct pci_dev *pdev,
				     struct ahci_host_priv *hpriv)
{
	void __iomem *mmio = pcim_iomap_table(pdev)[AHCI_PCI_BAR];
	u32 cap, port_map;
	int i;
	int mv;

	/* make sure AHCI mode is enabled before accessing CAP */
	ahci_enable_ahci(mmio);

	/* Values prefixed with saved_ are written back to host after
	 * reset.  Values without are used for driver operation.
	 */
	hpriv->saved_cap = cap = readl(mmio + HOST_CAP);
	hpriv->saved_port_map = port_map = readl(mmio + HOST_PORTS_IMPL);

	/* some chips have errata preventing 64bit use */
	if ((cap & HOST_CAP_64) && (hpriv->flags & AHCI_HFLAG_32BIT_ONLY)) {
		dev_printk(KERN_INFO, &pdev->dev,
			   "controller can't do 64bit DMA, forcing 32bit\n");
		cap &= ~HOST_CAP_64;
	}

	if ((cap & HOST_CAP_NCQ) && (hpriv->flags & AHCI_HFLAG_NO_NCQ)) {
		dev_printk(KERN_INFO, &pdev->dev,
			   "controller can't do NCQ, turning off CAP_NCQ\n");
		cap &= ~HOST_CAP_NCQ;
	}

	if (!(cap & HOST_CAP_NCQ) && (hpriv->flags & AHCI_HFLAG_YES_NCQ)) {
		dev_printk(KERN_INFO, &pdev->dev,
			   "controller can do NCQ, turning on CAP_NCQ\n");
		cap |= HOST_CAP_NCQ;
	}

	if ((cap & HOST_CAP_PMP) && (hpriv->flags & AHCI_HFLAG_NO_PMP)) {
		dev_printk(KERN_INFO, &pdev->dev,
			   "controller can't do PMP, turning off CAP_PMP\n");
		cap &= ~HOST_CAP_PMP;
	}

	if (pdev->vendor == PCI_VENDOR_ID_JMICRON && pdev->device == 0x2361 &&
	    port_map != 1) {
		dev_printk(KERN_INFO, &pdev->dev,
			   "JMB361 has only one port, port_map 0x%x -> 0x%x\n",
			   port_map, 1);
		port_map = 1;
static void ahci_pci_save_initial_config(struct pci_dev *pdev,
					 struct ahci_host_priv *hpriv)
{
	if (pdev->vendor == PCI_VENDOR_ID_JMICRON && pdev->device == 0x2361) {
		dev_info(&pdev->dev, "JMB361 has only one port\n");
		hpriv->force_port_map = 1;
	}

	/*
	 * Temporary Marvell 6145 hack: PATA port presence
	 * is asserted through the standard AHCI port
	 * presence register, as bit 4 (counting from 0)
	 */
	if (hpriv->flags & AHCI_HFLAG_MV_PATA) {
		if (pdev->device == 0x6121)
			mv = 0x3;
		else
			mv = 0xf;
		dev_printk(KERN_ERR, &pdev->dev,
			   "MV_AHCI HACK: port_map %x -> %x\n",
			   port_map,
			   port_map & mv);
		dev_printk(KERN_ERR, &pdev->dev,
			  "Disabling your PATA port. Use the boot option 'ahci.marvell_enable=0' to avoid this.\n");

		port_map &= mv;
	}

	/* cross check port_map and cap.n_ports */
	if (port_map) {
		int map_ports = 0;

		for (i = 0; i < AHCI_MAX_PORTS; i++)
			if (port_map & (1 << i))
				map_ports++;

		/* If PI has more ports than n_ports, whine, clear
		 * port_map and let it be generated from n_ports.
		 */
		if (map_ports > ahci_nr_ports(cap)) {
			dev_printk(KERN_WARNING, &pdev->dev,
				   "implemented port map (0x%x) contains more "
				   "ports than nr_ports (%u), using nr_ports\n",
				   port_map, ahci_nr_ports(cap));
			port_map = 0;
		}
	}

	/* fabricate port_map from cap.nr_ports */
	if (!port_map) {
		port_map = (1 << ahci_nr_ports(cap)) - 1;
		dev_printk(KERN_WARNING, &pdev->dev,
			   "forcing PORTS_IMPL to 0x%x\n", port_map);

		/* write the fixed up value to the PI register */
		hpriv->saved_port_map = port_map;
	}

	/* record values to use during operation */
	hpriv->cap = cap;
	hpriv->port_map = port_map;
}

/**
 *	ahci_restore_initial_config - Restore initial config
 *	@host: target ATA host
 *
 *	Restore initial config stored by ahci_save_initial_config().
 *
 *	LOCKING:
 *	None.
 */
static void ahci_restore_initial_config(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];

	writel(hpriv->saved_cap, mmio + HOST_CAP);
	writel(hpriv->saved_port_map, mmio + HOST_PORTS_IMPL);
	(void) readl(mmio + HOST_PORTS_IMPL);	/* flush */
}

static unsigned ahci_scr_offset(struct ata_port *ap, unsigned int sc_reg)
{
	static const int offset[] = {
		[SCR_STATUS]		= PORT_SCR_STAT,
		[SCR_CONTROL]		= PORT_SCR_CTL,
		[SCR_ERROR]		= PORT_SCR_ERR,
		[SCR_ACTIVE]		= PORT_SCR_ACT,
		[SCR_NOTIFICATION]	= PORT_SCR_NTF,
	};
	struct ahci_host_priv *hpriv = ap->host->private_data;

	if (sc_reg < ARRAY_SIZE(offset) &&
	    (sc_reg != SCR_NOTIFICATION || (hpriv->cap & HOST_CAP_SNTF)))
		return offset[sc_reg];
	return 0;
}

static int ahci_scr_read(struct ata_port *ap, unsigned int sc_reg, u32 *val)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	int offset = ahci_scr_offset(ap, sc_reg);

	if (offset) {
		*val = readl(port_mmio + offset);
		return 0;
	}
	return -EINVAL;
}

static int ahci_scr_write(struct ata_port *ap, unsigned int sc_reg, u32 val)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	int offset = ahci_scr_offset(ap, sc_reg);

	if (offset) {
		writel(val, port_mmio + offset);
		return 0;
	}
	return -EINVAL;
}

static void ahci_start_engine(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 tmp;

	/* start DMA */
	tmp = readl(port_mmio + PORT_CMD);
	tmp |= PORT_CMD_START;
	writel(tmp, port_mmio + PORT_CMD);
	readl(port_mmio + PORT_CMD); /* flush */
}

static int ahci_stop_engine(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 tmp;

	tmp = readl(port_mmio + PORT_CMD);

	/* check if the HBA is idle */
	if ((tmp & (PORT_CMD_START | PORT_CMD_LIST_ON)) == 0)
		return 0;

	/* setting HBA to idle */
	tmp &= ~PORT_CMD_START;
	writel(tmp, port_mmio + PORT_CMD);

	/* wait for engine to stop. This could be as long as 500 msec */
	tmp = ata_wait_register(port_mmio + PORT_CMD,
				PORT_CMD_LIST_ON, PORT_CMD_LIST_ON, 1, 500);
	if (tmp & PORT_CMD_LIST_ON)
		return -EIO;

	return 0;
}

static void ahci_start_fis_rx(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ahci_host_priv *hpriv = ap->host->private_data;
	struct ahci_port_priv *pp = ap->private_data;
	u32 tmp;

	/* set FIS registers */
	if (hpriv->cap & HOST_CAP_64)
		writel((pp->cmd_slot_dma >> 16) >> 16,
		       port_mmio + PORT_LST_ADDR_HI);
	writel(pp->cmd_slot_dma & 0xffffffff, port_mmio + PORT_LST_ADDR);

	if (hpriv->cap & HOST_CAP_64)
		writel((pp->rx_fis_dma >> 16) >> 16,
		       port_mmio + PORT_FIS_ADDR_HI);
	writel(pp->rx_fis_dma & 0xffffffff, port_mmio + PORT_FIS_ADDR);

	/* enable FIS reception */
	tmp = readl(port_mmio + PORT_CMD);
	tmp |= PORT_CMD_FIS_RX;
	writel(tmp, port_mmio + PORT_CMD);

	/* flush */
	readl(port_mmio + PORT_CMD);
}

static int ahci_stop_fis_rx(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 tmp;

	/* disable FIS reception */
	tmp = readl(port_mmio + PORT_CMD);
	tmp &= ~PORT_CMD_FIS_RX;
	writel(tmp, port_mmio + PORT_CMD);

	/* wait for completion, spec says 500ms, give it 1000 */
	tmp = ata_wait_register(port_mmio + PORT_CMD, PORT_CMD_FIS_ON,
				PORT_CMD_FIS_ON, 10, 1000);
	if (tmp & PORT_CMD_FIS_ON)
		return -EBUSY;

	return 0;
}

static void ahci_power_up(struct ata_port *ap)
{
	struct ahci_host_priv *hpriv = ap->host->private_data;
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 cmd;

	cmd = readl(port_mmio + PORT_CMD) & ~PORT_CMD_ICC_MASK;

	/* spin up device */
	if (hpriv->cap & HOST_CAP_SSS) {
		cmd |= PORT_CMD_SPIN_UP;
		writel(cmd, port_mmio + PORT_CMD);
	}

	/* wake up link */
	writel(cmd | PORT_CMD_ICC_ACTIVE, port_mmio + PORT_CMD);
}

static void ahci_disable_alpm(struct ata_port *ap)
{
	struct ahci_host_priv *hpriv = ap->host->private_data;
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 cmd;
	struct ahci_port_priv *pp = ap->private_data;

	/* IPM bits should be disabled by libata-core */
	/* get the existing command bits */
	cmd = readl(port_mmio + PORT_CMD);

	/* disable ALPM and ASP */
	cmd &= ~PORT_CMD_ASP;
	cmd &= ~PORT_CMD_ALPE;

	/* force the interface back to active */
	cmd |= PORT_CMD_ICC_ACTIVE;

	/* write out new cmd value */
	writel(cmd, port_mmio + PORT_CMD);
	cmd = readl(port_mmio + PORT_CMD);

	/* wait 10ms to be sure we've come out of any low power state */
	msleep(10);

	/* clear out any PhyRdy stuff from interrupt status */
	writel(PORT_IRQ_PHYRDY, port_mmio + PORT_IRQ_STAT);

	/* go ahead and clean out PhyRdy Change from Serror too */
	ahci_scr_write(ap, SCR_ERROR, ((1 << 16) | (1 << 18)));

	/*
 	 * Clear flag to indicate that we should ignore all PhyRdy
 	 * state changes
 	 */
	hpriv->flags &= ~AHCI_HFLAG_NO_HOTPLUG;

	/*
 	 * Enable interrupts on Phy Ready.
 	 */
	pp->intr_mask |= PORT_IRQ_PHYRDY;
	writel(pp->intr_mask, port_mmio + PORT_IRQ_MASK);

	/*
 	 * don't change the link pm policy - we can be called
 	 * just to turn of link pm temporarily
 	 */
}

static int ahci_enable_alpm(struct ata_port *ap,
	enum link_pm policy)
{
	struct ahci_host_priv *hpriv = ap->host->private_data;
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 cmd;
	struct ahci_port_priv *pp = ap->private_data;
	u32 asp;

	/* Make sure the host is capable of link power management */
	if (!(hpriv->cap & HOST_CAP_ALPM))
		return -EINVAL;

	switch (policy) {
	case MAX_PERFORMANCE:
	case NOT_AVAILABLE:
		/*
 		 * if we came here with NOT_AVAILABLE,
 		 * it just means this is the first time we
 		 * have tried to enable - default to max performance,
 		 * and let the user go to lower power modes on request.
 		 */
		ahci_disable_alpm(ap);
		return 0;
	case MIN_POWER:
		/* configure HBA to enter SLUMBER */
		asp = PORT_CMD_ASP;
		break;
	case MEDIUM_POWER:
		/* configure HBA to enter PARTIAL */
		asp = 0;
		break;
	default:
		return -EINVAL;
	}

	/*
 	 * Disable interrupts on Phy Ready. This keeps us from
 	 * getting woken up due to spurious phy ready interrupts
	 * TBD - Hot plug should be done via polling now, is
	 * that even supported?
 	 */
	pp->intr_mask &= ~PORT_IRQ_PHYRDY;
	writel(pp->intr_mask, port_mmio + PORT_IRQ_MASK);

	/*
 	 * Set a flag to indicate that we should ignore all PhyRdy
 	 * state changes since these can happen now whenever we
 	 * change link state
 	 */
	hpriv->flags |= AHCI_HFLAG_NO_HOTPLUG;

	/* get the existing command bits */
	cmd = readl(port_mmio + PORT_CMD);

	/*
 	 * Set ASP based on Policy
 	 */
	cmd |= asp;

	/*
 	 * Setting this bit will instruct the HBA to aggressively
 	 * enter a lower power link state when it's appropriate and
 	 * based on the value set above for ASP
 	 */
	cmd |= PORT_CMD_ALPE;

	/* write out new cmd value */
	writel(cmd, port_mmio + PORT_CMD);
	cmd = readl(port_mmio + PORT_CMD);

	/* IPM bits should be set by libata-core */
	return 0;
}

#ifdef CONFIG_PM
static void ahci_power_down(struct ata_port *ap)
{
	struct ahci_host_priv *hpriv = ap->host->private_data;
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 cmd, scontrol;

	if (!(hpriv->cap & HOST_CAP_SSS))
		return;

	/* put device into listen mode, first set PxSCTL.DET to 0 */
	scontrol = readl(port_mmio + PORT_SCR_CTL);
	scontrol &= ~0xf;
	writel(scontrol, port_mmio + PORT_SCR_CTL);

	/* then set PxCMD.SUD to 0 */
	cmd = readl(port_mmio + PORT_CMD) & ~PORT_CMD_ICC_MASK;
	cmd &= ~PORT_CMD_SPIN_UP;
	writel(cmd, port_mmio + PORT_CMD);
}
#endif

static void ahci_start_port(struct ata_port *ap)
{
	struct ahci_port_priv *pp = ap->private_data;
	struct ata_link *link;
	struct ahci_em_priv *emp;

	/* enable FIS reception */
	ahci_start_fis_rx(ap);

	/* enable DMA */
	ahci_start_engine(ap);

	/* turn on LEDs */
	if (ap->flags & ATA_FLAG_EM) {
		ata_port_for_each_link(link, ap) {
			emp = &pp->em_priv[link->pmp];
			ahci_transmit_led_message(ap, emp->led_state, 4);
		}
	}

	if (ap->flags & ATA_FLAG_SW_ACTIVITY)
		ata_port_for_each_link(link, ap)
			ahci_init_sw_activity(link);

}

static int ahci_deinit_port(struct ata_port *ap, const char **emsg)
{
	int rc;

	/* disable DMA */
	rc = ahci_stop_engine(ap);
	if (rc) {
		*emsg = "failed to stop engine";
		return rc;
	}

	/* disable FIS reception */
	rc = ahci_stop_fis_rx(ap);
	if (rc) {
		*emsg = "failed stop FIS RX";
		return rc;
	}

	return 0;
}

static int ahci_reset_controller(struct ata_host *host)
{
	struct pci_dev *pdev = to_pci_dev(host->dev);
	struct ahci_host_priv *hpriv = host->private_data;
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];
	u32 tmp;

	/* we must be in AHCI mode, before using anything
	 * AHCI-specific, such as HOST_RESET.
	 */
	ahci_enable_ahci(mmio);

	/* global controller reset */
	if (!ahci_skip_host_reset) {
		tmp = readl(mmio + HOST_CTL);
		if ((tmp & HOST_RESET) == 0) {
			writel(tmp | HOST_RESET, mmio + HOST_CTL);
			readl(mmio + HOST_CTL); /* flush */
		}

		/*
		 * to perform host reset, OS should set HOST_RESET
		 * and poll until this bit is read to be "0".
		 * reset must complete within 1 second, or
		 * the hardware should be considered fried.
		 */
		tmp = ata_wait_register(mmio + HOST_CTL, HOST_RESET,
					HOST_RESET, 10, 1000);

		if (tmp & HOST_RESET) {
			dev_printk(KERN_ERR, host->dev,
				   "controller reset failed (0x%x)\n", tmp);
			return -EIO;
		}

		/* turn on AHCI mode */
		ahci_enable_ahci(mmio);

		/* Some registers might be cleared on reset.  Restore
		 * initial values.
		 */
		ahci_restore_initial_config(host);
	} else
		dev_printk(KERN_INFO, host->dev,
			   "skipping global host reset\n");

	if (pdev->vendor == PCI_VENDOR_ID_INTEL) {
			hpriv->mask_port_map = 0x3;
		else
			hpriv->mask_port_map = 0xf;
		dev_info(&pdev->dev,
			  "Disabling your PATA port. Use the boot option 'ahci.marvell_enable=0' to avoid this.\n");
	}

	ahci_save_initial_config(&pdev->dev, hpriv);
}

static int ahci_pci_reset_controller(struct ata_host *host)
{
	struct pci_dev *pdev = to_pci_dev(host->dev);
	int rc;

	rc = ahci_reset_controller(host);
	if (rc)
		return rc;

	if (pdev->vendor == PCI_VENDOR_ID_INTEL) {
		struct ahci_host_priv *hpriv = host->private_data;
		u16 tmp16;

		/* configure PCS */
		pci_read_config_word(pdev, 0x92, &tmp16);
		if ((tmp16 & hpriv->port_map) != hpriv->port_map) {
			tmp16 |= hpriv->port_map;
			pci_write_config_word(pdev, 0x92, tmp16);
		}
	}

	return 0;
}

static void ahci_sw_activity(struct ata_link *link)
{
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_em_priv *emp = &pp->em_priv[link->pmp];

	if (!(link->flags & ATA_LFLAG_SW_ACTIVITY))
		return;

	emp->activity++;
	if (!timer_pending(&emp->timer))
		mod_timer(&emp->timer, jiffies + msecs_to_jiffies(10));
}

static void ahci_sw_activity_blink(unsigned long arg)
{
	struct ata_link *link = (struct ata_link *)arg;
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_em_priv *emp = &pp->em_priv[link->pmp];
	unsigned long led_message = emp->led_state;
	u32 activity_led_state;

	led_message &= 0xffff0000;
	led_message |= ap->port_no | (link->pmp << 8);

	/* check to see if we've had activity.  If so,
	 * toggle state of LED and reset timer.  If not,
	 * turn LED to desired idle state.
	 */
	if (emp->saved_activity != emp->activity) {
		emp->saved_activity = emp->activity;
		/* get the current LED state */
		activity_led_state = led_message & 0x00010000;

		if (activity_led_state)
			activity_led_state = 0;
		else
			activity_led_state = 1;

		/* clear old state */
		led_message &= 0xfff8ffff;

		/* toggle state */
		led_message |= (activity_led_state << 16);
		mod_timer(&emp->timer, jiffies + msecs_to_jiffies(100));
	} else {
		/* switch to idle */
		led_message &= 0xfff8ffff;
		if (emp->blink_policy == BLINK_OFF)
			led_message |= (1 << 16);
	}
	ahci_transmit_led_message(ap, led_message, 4);
}

static void ahci_init_sw_activity(struct ata_link *link)
{
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_em_priv *emp = &pp->em_priv[link->pmp];

	/* init activity stats, setup timer */
	emp->saved_activity = emp->activity = 0;
	setup_timer(&emp->timer, ahci_sw_activity_blink, (unsigned long)link);

	/* check our blink policy and set flag for link if it's enabled */
	if (emp->blink_policy)
		link->flags |= ATA_LFLAG_SW_ACTIVITY;
}

static int ahci_reset_em(struct ata_host *host)
{
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];
	u32 em_ctl;

	em_ctl = readl(mmio + HOST_EM_CTL);
	if ((em_ctl & EM_CTL_TM) || (em_ctl & EM_CTL_RST))
		return -EINVAL;

	writel(em_ctl | EM_CTL_RST, mmio + HOST_EM_CTL);
	return 0;
}

static ssize_t ahci_transmit_led_message(struct ata_port *ap, u32 state,
					ssize_t size)
{
	struct ahci_host_priv *hpriv = ap->host->private_data;
	struct ahci_port_priv *pp = ap->private_data;
	void __iomem *mmio = ap->host->iomap[AHCI_PCI_BAR];
	u32 em_ctl;
	u32 message[] = {0, 0};
	unsigned long flags;
	int pmp;
	struct ahci_em_priv *emp;

	/* get the slot number from the message */
	pmp = (state & 0x0000ff00) >> 8;
	if (pmp < MAX_SLOTS)
		emp = &pp->em_priv[pmp];
	else
		return -EINVAL;

	spin_lock_irqsave(ap->lock, flags);

	/*
	 * if we are still busy transmitting a previous message,
	 * do not allow
	 */
	em_ctl = readl(mmio + HOST_EM_CTL);
	if (em_ctl & EM_CTL_TM) {
		spin_unlock_irqrestore(ap->lock, flags);
		return -EINVAL;
	}

	/*
	 * create message header - this is all zero except for
	 * the message size, which is 4 bytes.
	 */
	message[0] |= (4 << 8);

	/* ignore 0:4 of byte zero, fill in port info yourself */
	message[1] = ((state & 0xfffffff0) | ap->port_no);

	/* write message to EM_LOC */
	writel(message[0], mmio + hpriv->em_loc);
	writel(message[1], mmio + hpriv->em_loc+4);

	/* save off new led state for port/slot */
	emp->led_state = message[1];

	/*
	 * tell hardware to transmit the message
	 */
	writel(em_ctl | EM_CTL_TM, mmio + HOST_EM_CTL);

	spin_unlock_irqrestore(ap->lock, flags);
	return size;
}

static ssize_t ahci_led_show(struct ata_port *ap, char *buf)
{
	struct ahci_port_priv *pp = ap->private_data;
	struct ata_link *link;
	struct ahci_em_priv *emp;
	int rc = 0;

	ata_port_for_each_link(link, ap) {
		emp = &pp->em_priv[link->pmp];
		rc += sprintf(buf, "%lx\n", emp->led_state);
	}
	return rc;
}

static ssize_t ahci_led_store(struct ata_port *ap, const char *buf,
				size_t size)
{
	int state;
	int pmp;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_em_priv *emp;

	state = simple_strtoul(buf, NULL, 0);

	/* get the slot number from the message */
	pmp = (state & 0x0000ff00) >> 8;
	if (pmp < MAX_SLOTS)
		emp = &pp->em_priv[pmp];
	else
		return -EINVAL;

	/* mask off the activity bits if we are in sw_activity
	 * mode, user should turn off sw_activity before setting
	 * activity led through em_message
	 */
	if (emp->blink_policy)
		state &= 0xfff8ffff;

	return ahci_transmit_led_message(ap, state, size);
}

static ssize_t ahci_activity_store(struct ata_device *dev, enum sw_activity val)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_em_priv *emp = &pp->em_priv[link->pmp];
	u32 port_led_state = emp->led_state;

	/* save the desired Activity LED behavior */
	if (val == OFF) {
		/* clear LFLAG */
		link->flags &= ~(ATA_LFLAG_SW_ACTIVITY);

		/* set the LED to OFF */
		port_led_state &= 0xfff80000;
		port_led_state |= (ap->port_no | (link->pmp << 8));
		ahci_transmit_led_message(ap, port_led_state, 4);
	} else {
		link->flags |= ATA_LFLAG_SW_ACTIVITY;
		if (val == BLINK_OFF) {
			/* set LED to ON for idle */
			port_led_state &= 0xfff80000;
			port_led_state |= (ap->port_no | (link->pmp << 8));
			port_led_state |= 0x00010000; /* check this */
			ahci_transmit_led_message(ap, port_led_state, 4);
		}
	}
	emp->blink_policy = val;
	return 0;
}

static ssize_t ahci_activity_show(struct ata_device *dev, char *buf)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_em_priv *emp = &pp->em_priv[link->pmp];

	/* display the saved value of activity behavior for this
	 * disk.
	 */
	return sprintf(buf, "%d\n", emp->blink_policy);
}

static void ahci_port_init(struct pci_dev *pdev, struct ata_port *ap,
			   int port_no, void __iomem *mmio,
			   void __iomem *port_mmio)
{
	const char *emsg = NULL;
	int rc;
	u32 tmp;

	/* make sure port is not active */
	rc = ahci_deinit_port(ap, &emsg);
	if (rc)
		dev_printk(KERN_WARNING, &pdev->dev,
			   "%s (%d)\n", emsg, rc);

	/* clear SError */
	tmp = readl(port_mmio + PORT_SCR_ERR);
	VPRINTK("PORT_SCR_ERR 0x%x\n", tmp);
	writel(tmp, port_mmio + PORT_SCR_ERR);

	/* clear port IRQ */
	tmp = readl(port_mmio + PORT_IRQ_STAT);
	VPRINTK("PORT_IRQ_STAT 0x%x\n", tmp);
	if (tmp)
		writel(tmp, port_mmio + PORT_IRQ_STAT);

	writel(1 << port_no, mmio + HOST_IRQ_STAT);
}

static void ahci_init_controller(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;
	struct pci_dev *pdev = to_pci_dev(host->dev);
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];
	int i;
static void ahci_pci_init_controller(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;
	struct pci_dev *pdev = to_pci_dev(host->dev);
	void __iomem *port_mmio;
	u32 tmp;
	int mv;

	if (hpriv->flags & AHCI_HFLAG_MV_PATA) {
		if (pdev->device == 0x6121)
			mv = 2;
		else
			mv = 4;
		port_mmio = __ahci_port_base(host, mv);

		writel(0, port_mmio + PORT_IRQ_MASK);

		/* clear port IRQ */
		tmp = readl(port_mmio + PORT_IRQ_STAT);
		VPRINTK("PORT_IRQ_STAT 0x%x\n", tmp);
		if (tmp)
			writel(tmp, port_mmio + PORT_IRQ_STAT);
	}

	for (i = 0; i < host->n_ports; i++) {
		struct ata_port *ap = host->ports[i];

		port_mmio = ahci_port_base(ap);
		if (ata_port_is_dummy(ap))
			continue;

		ahci_port_init(pdev, ap, i, mmio, port_mmio);
	}

	tmp = readl(mmio + HOST_CTL);
	VPRINTK("HOST_CTL 0x%x\n", tmp);
	writel(tmp | HOST_IRQ_EN, mmio + HOST_CTL);
	tmp = readl(mmio + HOST_CTL);
	VPRINTK("HOST_CTL 0x%x\n", tmp);
}

static void ahci_dev_config(struct ata_device *dev)
{
	struct ahci_host_priv *hpriv = dev->link->ap->host->private_data;

	if (hpriv->flags & AHCI_HFLAG_SECT255) {
		dev->max_sectors = 255;
		ata_dev_printk(dev, KERN_INFO,
			       "SB600 AHCI: limiting to 255 sectors per cmd\n");
	}
}

static unsigned int ahci_dev_classify(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ata_taskfile tf;
	u32 tmp;

	tmp = readl(port_mmio + PORT_SIG);
	tf.lbah		= (tmp >> 24)	& 0xff;
	tf.lbam		= (tmp >> 16)	& 0xff;
	tf.lbal		= (tmp >> 8)	& 0xff;
	tf.nsect	= (tmp)		& 0xff;

	return ata_dev_classify(&tf);
}

static void ahci_fill_cmd_slot(struct ahci_port_priv *pp, unsigned int tag,
			       u32 opts)
{
	dma_addr_t cmd_tbl_dma;

	cmd_tbl_dma = pp->cmd_tbl_dma + tag * AHCI_CMD_TBL_SZ;

	pp->cmd_slot[tag].opts = cpu_to_le32(opts);
	pp->cmd_slot[tag].status = 0;
	pp->cmd_slot[tag].tbl_addr = cpu_to_le32(cmd_tbl_dma & 0xffffffff);
	pp->cmd_slot[tag].tbl_addr_hi = cpu_to_le32((cmd_tbl_dma >> 16) >> 16);
}

static int ahci_kick_engine(struct ata_port *ap, int force_restart)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ahci_host_priv *hpriv = ap->host->private_data;
	u8 status = readl(port_mmio + PORT_TFDATA) & 0xFF;
	u32 tmp;
	int busy, rc;

	/* do we need to kick the port? */
	busy = status & (ATA_BUSY | ATA_DRQ);
	if (!busy && !force_restart)
		return 0;

	/* stop engine */
	rc = ahci_stop_engine(ap);
	if (rc)
		goto out_restart;

	/* need to do CLO? */
	if (!busy) {
		rc = 0;
		goto out_restart;
	}

	if (!(hpriv->cap & HOST_CAP_CLO)) {
		rc = -EOPNOTSUPP;
		goto out_restart;
	}

	/* perform CLO */
	tmp = readl(port_mmio + PORT_CMD);
	tmp |= PORT_CMD_CLO;
	writel(tmp, port_mmio + PORT_CMD);

	rc = 0;
	tmp = ata_wait_register(port_mmio + PORT_CMD,
				PORT_CMD_CLO, PORT_CMD_CLO, 1, 500);
	if (tmp & PORT_CMD_CLO)
		rc = -EIO;

	/* restart engine */
 out_restart:
	ahci_start_engine(ap);
	return rc;
}

static int ahci_exec_polled_cmd(struct ata_port *ap, int pmp,
				struct ata_taskfile *tf, int is_cmd, u16 flags,
				unsigned long timeout_msec)
{
	const u32 cmd_fis_len = 5; /* five dwords */
	struct ahci_port_priv *pp = ap->private_data;
	void __iomem *port_mmio = ahci_port_base(ap);
	u8 *fis = pp->cmd_tbl;
	u32 tmp;

	/* prep the command */
	ata_tf_to_fis(tf, pmp, is_cmd, fis);
	ahci_fill_cmd_slot(pp, 0, cmd_fis_len | flags | (pmp << 12));

	/* issue & wait */
	writel(1, port_mmio + PORT_CMD_ISSUE);

	if (timeout_msec) {
		tmp = ata_wait_register(port_mmio + PORT_CMD_ISSUE, 0x1, 0x1,
					1, timeout_msec);
		if (tmp & 0x1) {
			ahci_kick_engine(ap, 1);
			return -EBUSY;
		}
	} else
		readl(port_mmio + PORT_CMD_ISSUE);	/* flush */

	return 0;
}

static int ahci_do_softreset(struct ata_link *link, unsigned int *class,
			     int pmp, unsigned long deadline,
			     int (*check_ready)(struct ata_link *link))
{
	struct ata_port *ap = link->ap;
	const char *reason = NULL;
	unsigned long now, msecs;
	struct ata_taskfile tf;
	int rc;

	DPRINTK("ENTER\n");

	/* prepare for SRST (AHCI-1.1 10.4.1) */
	rc = ahci_kick_engine(ap, 1);
	if (rc && rc != -EOPNOTSUPP)
		ata_link_printk(link, KERN_WARNING,
				"failed to reset engine (errno=%d)\n", rc);

	ata_tf_init(link->device, &tf);

	/* issue the first D2H Register FIS */
	msecs = 0;
	now = jiffies;
	if (time_after(now, deadline))
		msecs = jiffies_to_msecs(deadline - now);

	tf.ctl |= ATA_SRST;
	if (ahci_exec_polled_cmd(ap, pmp, &tf, 0,
				 AHCI_CMD_RESET | AHCI_CMD_CLR_BUSY, msecs)) {
		rc = -EIO;
		reason = "1st FIS failed";
		goto fail;
	}

	/* spec says at least 5us, but be generous and sleep for 1ms */
	msleep(1);

	/* issue the second D2H Register FIS */
	tf.ctl &= ~ATA_SRST;
	ahci_exec_polled_cmd(ap, pmp, &tf, 0, 0, 0);

	/* wait for link to become ready */
	rc = ata_wait_after_reset(link, deadline, check_ready);
	/* link occupied, -ENODEV too is an error */
	if (rc) {
		reason = "device not ready";
		goto fail;
	}
	*class = ahci_dev_classify(ap);

	DPRINTK("EXIT, class=%u\n", *class);
	return 0;

 fail:
	ata_link_printk(link, KERN_ERR, "softreset failed (%s)\n", reason);
	return rc;
}

static int ahci_check_ready(struct ata_link *link)
{
	void __iomem *port_mmio = ahci_port_base(link->ap);
	u8 status = readl(port_mmio + PORT_TFDATA) & 0xFF;

	return ata_check_ready(status);
}

static int ahci_softreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline)
{
	int pmp = sata_srst_pmp(link);

	DPRINTK("ENTER\n");

	return ahci_do_softreset(link, class, pmp, deadline, ahci_check_ready);
}

static int ahci_sb600_check_ready(struct ata_link *link)
{
	void __iomem *port_mmio = ahci_port_base(link->ap);
	u8 status = readl(port_mmio + PORT_TFDATA) & 0xFF;
	u32 irq_status = readl(port_mmio + PORT_IRQ_STAT);

	/*
	 * There is no need to check TFDATA if BAD PMP is found due to HW bug,
	 * which can save timeout delay.
	 */
	if (irq_status & PORT_IRQ_BAD_PMP)
		return -EIO;

	return ata_check_ready(status);
}

static int ahci_sb600_softreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline)
{
	struct ata_port *ap = link->ap;
	void __iomem *port_mmio = ahci_port_base(ap);
	int pmp = sata_srst_pmp(link);
	int rc;
	u32 irq_sts;

	DPRINTK("ENTER\n");

	rc = ahci_do_softreset(link, class, pmp, deadline,
			       ahci_sb600_check_ready);

	/*
	 * Soft reset fails on some ATI chips with IPMS set when PMP
	 * is enabled but SATA HDD/ODD is connected to SATA port,
	 * do soft reset again to port 0.
	 */
	if (rc == -EIO) {
		irq_sts = readl(port_mmio + PORT_IRQ_STAT);
		if (irq_sts & PORT_IRQ_BAD_PMP) {
			ata_link_printk(link, KERN_WARNING,
					"failed due to HW bug, retry pmp=0\n");
			rc = ahci_do_softreset(link, class, 0, deadline,
					       ahci_check_ready);
		}
	}

	return rc;
}

static int ahci_hardreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline)
{
	const unsigned long *timing = sata_ehc_deb_timing(&link->eh_context);
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	u8 *d2h_fis = pp->rx_fis + RX_FIS_D2H_REG;
	struct ata_taskfile tf;
	bool online;
	int rc;

	DPRINTK("ENTER\n");

	ahci_stop_engine(ap);

	/* clear D2H reception area to properly wait for D2H FIS */
	ata_tf_init(link->device, &tf);
	tf.command = 0x80;
	ata_tf_to_fis(&tf, 0, 0, d2h_fis);

	rc = sata_link_hardreset(link, timing, deadline, &online,
				 ahci_check_ready);

	ahci_start_engine(ap);

	if (online)
		*class = ahci_dev_classify(ap);

	DPRINTK("EXIT, rc=%d, class=%u\n", rc, *class);
	return rc;
	ahci_init_controller(host);
}

static int ahci_vt8251_hardreset(struct ata_link *link, unsigned int *class,
				 unsigned long deadline)
{
	struct ata_port *ap = link->ap;
	struct ahci_host_priv *hpriv = ap->host->private_data;
	bool online;
	int rc;

	DPRINTK("ENTER\n");

	ahci_stop_engine(ap);

	rc = sata_link_hardreset(link, sata_ehc_deb_timing(&link->eh_context),
				 deadline, &online, NULL);

	ahci_start_engine(ap);
	hpriv->start_engine(ap);

	DPRINTK("EXIT, rc=%d, class=%u\n", rc, *class);

	/* vt8251 doesn't clear BSY on signature FIS reception,
	 * request follow-up softreset.
	 */
	return online ? -EAGAIN : rc;
}

static int ahci_p5wdh_hardreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline)
{
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_host_priv *hpriv = ap->host->private_data;
	u8 *d2h_fis = pp->rx_fis + RX_FIS_D2H_REG;
	struct ata_taskfile tf;
	bool online;
	int rc;

	ahci_stop_engine(ap);

	/* clear D2H reception area to properly wait for D2H FIS */
	ata_tf_init(link->device, &tf);
	tf.command = 0x80;
	tf.command = ATA_BUSY;
	ata_tf_to_fis(&tf, 0, 0, d2h_fis);

	rc = sata_link_hardreset(link, sata_ehc_deb_timing(&link->eh_context),
				 deadline, &online, NULL);

	ahci_start_engine(ap);
	hpriv->start_engine(ap);

	/* The pseudo configuration device on SIMG4726 attached to
	 * ASUS P5W-DH Deluxe doesn't send signature FIS after
	 * hardreset if no device is attached to the first downstream
	 * port && the pseudo device locks up on SRST w/ PMP==0.  To
	 * work around this, wait for !BSY only briefly.  If BSY isn't
	 * cleared, perform CLO and proceed to IDENTIFY (achieved by
	 * ATA_LFLAG_NO_SRST and ATA_LFLAG_ASSUME_ATA).
	 *
	 * Wait for two seconds.  Devices attached to downstream port
	 * which can't process the following IDENTIFY after this will
	 * have to be reset again.  For most cases, this should
	 * suffice while making probing snappish enough.
	 */
	if (online) {
		rc = ata_wait_after_reset(link, jiffies + 2 * HZ,
					  ahci_check_ready);
		if (rc)
			ahci_kick_engine(ap, 0);
			ahci_kick_engine(ap);
	}
	return rc;
}

static void ahci_postreset(struct ata_link *link, unsigned int *class)
{
	struct ata_port *ap = link->ap;
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 new_tmp, tmp;

	ata_std_postreset(link, class);

	/* Make sure port's ATAPI bit is set appropriately */
	new_tmp = tmp = readl(port_mmio + PORT_CMD);
	if (*class == ATA_DEV_ATAPI)
		new_tmp |= PORT_CMD_ATAPI;
	else
		new_tmp &= ~PORT_CMD_ATAPI;
	if (new_tmp != tmp) {
		writel(new_tmp, port_mmio + PORT_CMD);
		readl(port_mmio + PORT_CMD); /* flush */
	}
}

static unsigned int ahci_fill_sg(struct ata_queued_cmd *qc, void *cmd_tbl)
{
	struct scatterlist *sg;
	struct ahci_sg *ahci_sg = cmd_tbl + AHCI_CMD_TBL_HDR_SZ;
	unsigned int si;

	VPRINTK("ENTER\n");

	/*
	 * Next, the S/G list.
	 */
	for_each_sg(qc->sg, sg, qc->n_elem, si) {
		dma_addr_t addr = sg_dma_address(sg);
		u32 sg_len = sg_dma_len(sg);

		ahci_sg[si].addr = cpu_to_le32(addr & 0xffffffff);
		ahci_sg[si].addr_hi = cpu_to_le32((addr >> 16) >> 16);
		ahci_sg[si].flags_size = cpu_to_le32(sg_len - 1);
	}

	return si;
}

static void ahci_qc_prep(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct ahci_port_priv *pp = ap->private_data;
	int is_atapi = ata_is_atapi(qc->tf.protocol);
	void *cmd_tbl;
	u32 opts;
	const u32 cmd_fis_len = 5; /* five dwords */
	unsigned int n_elem;

	/*
	 * Fill in command table information.  First, the header,
	 * a SATA Register - Host to Device command FIS.
	 */
	cmd_tbl = pp->cmd_tbl + qc->tag * AHCI_CMD_TBL_SZ;

	ata_tf_to_fis(&qc->tf, qc->dev->link->pmp, 1, cmd_tbl);
	if (is_atapi) {
		memset(cmd_tbl + AHCI_CMD_TBL_CDB, 0, 32);
		memcpy(cmd_tbl + AHCI_CMD_TBL_CDB, qc->cdb, qc->dev->cdb_len);
	}

	n_elem = 0;
	if (qc->flags & ATA_QCFLAG_DMAMAP)
		n_elem = ahci_fill_sg(qc, cmd_tbl);

	/*
	 * Fill in command slot information.
	 */
	opts = cmd_fis_len | n_elem << 16 | (qc->dev->link->pmp << 12);
	if (qc->tf.flags & ATA_TFLAG_WRITE)
		opts |= AHCI_CMD_WRITE;
	if (is_atapi)
		opts |= AHCI_CMD_ATAPI | AHCI_CMD_PREFETCH;

	ahci_fill_cmd_slot(pp, qc->tag, opts);
}

static void ahci_error_intr(struct ata_port *ap, u32 irq_stat)
{
	struct ahci_host_priv *hpriv = ap->host->private_data;
	struct ahci_port_priv *pp = ap->private_data;
	struct ata_eh_info *host_ehi = &ap->link.eh_info;
	struct ata_link *link = NULL;
	struct ata_queued_cmd *active_qc;
	struct ata_eh_info *active_ehi;
	u32 serror;

	/* determine active link */
	ata_port_for_each_link(link, ap)
		if (ata_link_active(link))
			break;
	if (!link)
		link = &ap->link;

	active_qc = ata_qc_from_tag(ap, link->active_tag);
	active_ehi = &link->eh_info;

	/* record irq stat */
	ata_ehi_clear_desc(host_ehi);
	ata_ehi_push_desc(host_ehi, "irq_stat 0x%08x", irq_stat);

	/* AHCI needs SError cleared; otherwise, it might lock up */
	ahci_scr_read(ap, SCR_ERROR, &serror);
	ahci_scr_write(ap, SCR_ERROR, serror);
	host_ehi->serror |= serror;

	/* some controllers set IRQ_IF_ERR on device errors, ignore it */
	if (hpriv->flags & AHCI_HFLAG_IGN_IRQ_IF_ERR)
		irq_stat &= ~PORT_IRQ_IF_ERR;

	if (irq_stat & PORT_IRQ_TF_ERR) {
		/* If qc is active, charge it; otherwise, the active
		 * link.  There's no active qc on NCQ errors.  It will
		 * be determined by EH by reading log page 10h.
		 */
		if (active_qc)
			active_qc->err_mask |= AC_ERR_DEV;
		else
			active_ehi->err_mask |= AC_ERR_DEV;

		if (hpriv->flags & AHCI_HFLAG_IGN_SERR_INTERNAL)
			host_ehi->serror &= ~SERR_INTERNAL;
	}

	if (irq_stat & PORT_IRQ_UNK_FIS) {
		u32 *unk = (u32 *)(pp->rx_fis + RX_FIS_UNK);

		active_ehi->err_mask |= AC_ERR_HSM;
		active_ehi->action |= ATA_EH_RESET;
		ata_ehi_push_desc(active_ehi,
				  "unknown FIS %08x %08x %08x %08x" ,
				  unk[0], unk[1], unk[2], unk[3]);
	}

	if (sata_pmp_attached(ap) && (irq_stat & PORT_IRQ_BAD_PMP)) {
		active_ehi->err_mask |= AC_ERR_HSM;
		active_ehi->action |= ATA_EH_RESET;
		ata_ehi_push_desc(active_ehi, "incorrect PMP");
	}

	if (irq_stat & (PORT_IRQ_HBUS_ERR | PORT_IRQ_HBUS_DATA_ERR)) {
		host_ehi->err_mask |= AC_ERR_HOST_BUS;
		host_ehi->action |= ATA_EH_RESET;
		ata_ehi_push_desc(host_ehi, "host bus error");
	}

	if (irq_stat & PORT_IRQ_IF_ERR) {
		host_ehi->err_mask |= AC_ERR_ATA_BUS;
		host_ehi->action |= ATA_EH_RESET;
		ata_ehi_push_desc(host_ehi, "interface fatal error");
	}

	if (irq_stat & (PORT_IRQ_CONNECT | PORT_IRQ_PHYRDY)) {
		ata_ehi_hotplugged(host_ehi);
		ata_ehi_push_desc(host_ehi, "%s",
			irq_stat & PORT_IRQ_CONNECT ?
			"connection status changed" : "PHY RDY changed");
	}

	/* okay, let's hand over to EH */

	if (irq_stat & PORT_IRQ_FREEZE)
		ata_port_freeze(ap);
	else
		ata_port_abort(ap);
}

static void ahci_port_intr(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ata_eh_info *ehi = &ap->link.eh_info;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_host_priv *hpriv = ap->host->private_data;
	int resetting = !!(ap->pflags & ATA_PFLAG_RESETTING);
	u32 status, qc_active;
	int rc;

	status = readl(port_mmio + PORT_IRQ_STAT);
	writel(status, port_mmio + PORT_IRQ_STAT);

	/* ignore BAD_PMP while resetting */
	if (unlikely(resetting))
		status &= ~PORT_IRQ_BAD_PMP;

	/* If we are getting PhyRdy, this is
 	 * just a power state change, we should
 	 * clear out this, plus the PhyRdy/Comm
 	 * Wake bits from Serror
 	 */
	if ((hpriv->flags & AHCI_HFLAG_NO_HOTPLUG) &&
		(status & PORT_IRQ_PHYRDY)) {
		status &= ~PORT_IRQ_PHYRDY;
		ahci_scr_write(ap, SCR_ERROR, ((1 << 16) | (1 << 18)));
	}

	if (unlikely(status & PORT_IRQ_ERROR)) {
		ahci_error_intr(ap, status);
		return;
	}

	if (status & PORT_IRQ_SDB_FIS) {
		/* If SNotification is available, leave notification
		 * handling to sata_async_notification().  If not,
		 * emulate it by snooping SDB FIS RX area.
		 *
		 * Snooping FIS RX area is probably cheaper than
		 * poking SNotification but some constrollers which
		 * implement SNotification, ICH9 for example, don't
		 * store AN SDB FIS into receive area.
		 */
		if (hpriv->cap & HOST_CAP_SNTF)
			sata_async_notification(ap);
		else {
			/* If the 'N' bit in word 0 of the FIS is set,
			 * we just received asynchronous notification.
			 * Tell libata about it.
			 */
			const __le32 *f = pp->rx_fis + RX_FIS_SDB;
			u32 f0 = le32_to_cpu(f[0]);

			if (f0 & (1 << 15))
				sata_async_notification(ap);
		}
	}

	/* pp->active_link is valid iff any command is in flight */
	if (ap->qc_active && pp->active_link->sactive)
		qc_active = readl(port_mmio + PORT_SCR_ACT);
	else
		qc_active = readl(port_mmio + PORT_CMD_ISSUE);

	rc = ata_qc_complete_multiple(ap, qc_active);

	/* while resetting, invalid completions are expected */
	if (unlikely(rc < 0 && !resetting)) {
		ehi->err_mask |= AC_ERR_HSM;
		ehi->action |= ATA_EH_RESET;
		ata_port_freeze(ap);
	}
}

static irqreturn_t ahci_interrupt(int irq, void *dev_instance)
{
	struct ata_host *host = dev_instance;
	struct ahci_host_priv *hpriv;
	unsigned int i, handled = 0;
	void __iomem *mmio;
	u32 irq_stat, irq_masked;

	VPRINTK("ENTER\n");

	hpriv = host->private_data;
	mmio = host->iomap[AHCI_PCI_BAR];

	/* sigh.  0xffffffff is a valid return from h/w */
	irq_stat = readl(mmio + HOST_IRQ_STAT);
	if (!irq_stat)
		return IRQ_NONE;

	irq_masked = irq_stat & hpriv->port_map;

	spin_lock(&host->lock);

	for (i = 0; i < host->n_ports; i++) {
		struct ata_port *ap;

		if (!(irq_masked & (1 << i)))
			continue;

		ap = host->ports[i];
		if (ap) {
			ahci_port_intr(ap);
			VPRINTK("port %u\n", i);
		} else {
			VPRINTK("port %u (no irq)\n", i);
			if (ata_ratelimit())
				dev_printk(KERN_WARNING, host->dev,
					"interrupt on disabled port %u\n", i);
		}

		handled = 1;
	}

	/* HOST_IRQ_STAT behaves as level triggered latch meaning that
	 * it should be cleared after all the port events are cleared;
	 * otherwise, it will raise a spurious interrupt after each
	 * valid one.  Please read section 10.6.2 of ahci 1.1 for more
	 * information.
	 *
	 * Also, use the unmasked value to clear interrupt as spurious
	 * pending event on a dummy port might cause screaming IRQ.
	 */
	writel(irq_stat, mmio + HOST_IRQ_STAT);

	spin_unlock(&host->lock);

	VPRINTK("EXIT\n");

	return IRQ_RETVAL(handled);
}

static unsigned int ahci_qc_issue(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ahci_port_priv *pp = ap->private_data;

	/* Keep track of the currently active link.  It will be used
	 * in completion path to determine whether NCQ phase is in
	 * progress.
	 */
	pp->active_link = qc->dev->link;

	if (qc->tf.protocol == ATA_PROT_NCQ)
		writel(1 << qc->tag, port_mmio + PORT_SCR_ACT);
	writel(1 << qc->tag, port_mmio + PORT_CMD_ISSUE);

	ahci_sw_activity(qc->dev->link);

	return 0;
}

static bool ahci_qc_fill_rtf(struct ata_queued_cmd *qc)
{
	struct ahci_port_priv *pp = qc->ap->private_data;
	u8 *d2h_fis = pp->rx_fis + RX_FIS_D2H_REG;

	ata_tf_from_fis(d2h_fis, &qc->result_tf);
	return true;
}

static void ahci_freeze(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);

	/* turn IRQ off */
	writel(0, port_mmio + PORT_IRQ_MASK);
}

static void ahci_thaw(struct ata_port *ap)
{
	void __iomem *mmio = ap->host->iomap[AHCI_PCI_BAR];
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 tmp;
	struct ahci_port_priv *pp = ap->private_data;

	/* clear IRQ */
	tmp = readl(port_mmio + PORT_IRQ_STAT);
	writel(tmp, port_mmio + PORT_IRQ_STAT);
	writel(1 << ap->port_no, mmio + HOST_IRQ_STAT);

	/* turn IRQ back on */
	writel(pp->intr_mask, port_mmio + PORT_IRQ_MASK);
}

static void ahci_error_handler(struct ata_port *ap)
{
	if (!(ap->pflags & ATA_PFLAG_FROZEN)) {
		/* restart engine */
		ahci_stop_engine(ap);
		ahci_start_engine(ap);
	}

	sata_pmp_error_handler(ap);
}

static void ahci_post_internal_cmd(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;

	/* make DMA engine forget about the failed command */
	if (qc->flags & ATA_QCFLAG_FAILED)
		ahci_kick_engine(ap, 1);
}

static void ahci_pmp_attach(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ahci_port_priv *pp = ap->private_data;
	u32 cmd;

	cmd = readl(port_mmio + PORT_CMD);
	cmd |= PORT_CMD_PMP;
	writel(cmd, port_mmio + PORT_CMD);

	pp->intr_mask |= PORT_IRQ_BAD_PMP;
	writel(pp->intr_mask, port_mmio + PORT_IRQ_MASK);
}

static void ahci_pmp_detach(struct ata_port *ap)
{
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ahci_port_priv *pp = ap->private_data;
	u32 cmd;

	cmd = readl(port_mmio + PORT_CMD);
	cmd &= ~PORT_CMD_PMP;
	writel(cmd, port_mmio + PORT_CMD);

	pp->intr_mask &= ~PORT_IRQ_BAD_PMP;
	writel(pp->intr_mask, port_mmio + PORT_IRQ_MASK);
}

static int ahci_port_resume(struct ata_port *ap)
{
	ahci_power_up(ap);
	ahci_start_port(ap);

	if (sata_pmp_attached(ap))
		ahci_pmp_attach(ap);
	else
		ahci_pmp_detach(ap);

	return 0;
}

#ifdef CONFIG_PM
static int ahci_port_suspend(struct ata_port *ap, pm_message_t mesg)
{
	const char *emsg = NULL;
	int rc;

	rc = ahci_deinit_port(ap, &emsg);
	if (rc == 0)
		ahci_power_down(ap);
	else {
		ata_port_printk(ap, KERN_ERR, "%s (%d)\n", emsg, rc);
		ahci_start_port(ap);
	}

	return rc;
}

static int ahci_pci_device_suspend(struct pci_dev *pdev, pm_message_t mesg)
{
	struct ata_host *host = dev_get_drvdata(&pdev->dev);
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];
	u32 ctl;

/*
 * ahci_avn_hardreset - attempt more aggressive recovery of Avoton ports.
 *
 * It has been observed with some SSDs that the timing of events in the
 * link synchronization phase can leave the port in a state that can not
 * be recovered by a SATA-hard-reset alone.  The failing signature is
 * SStatus.DET stuck at 1 ("Device presence detected but Phy
 * communication not established").  It was found that unloading and
 * reloading the driver when this problem occurs allows the drive
 * connection to be recovered (DET advanced to 0x3).  The critical
 * component of reloading the driver is that the port state machines are
 * reset by bouncing "port enable" in the AHCI PCS configuration
 * register.  So, reproduce that effect by bouncing a port whenever we
 * see DET==1 after a reset.
 */
static int ahci_avn_hardreset(struct ata_link *link, unsigned int *class,
			      unsigned long deadline)
{
	const unsigned long *timing = sata_ehc_deb_timing(&link->eh_context);
	struct ata_port *ap = link->ap;
	struct ahci_port_priv *pp = ap->private_data;
	struct ahci_host_priv *hpriv = ap->host->private_data;
	u8 *d2h_fis = pp->rx_fis + RX_FIS_D2H_REG;
	unsigned long tmo = deadline - jiffies;
	struct ata_taskfile tf;
	bool online;
	int rc, i;

	DPRINTK("ENTER\n");

	ahci_stop_engine(ap);

	for (i = 0; i < 2; i++) {
		u16 val;
		u32 sstatus;
		int port = ap->port_no;
		struct ata_host *host = ap->host;
		struct pci_dev *pdev = to_pci_dev(host->dev);

		/* clear D2H reception area to properly wait for D2H FIS */
		ata_tf_init(link->device, &tf);
		tf.command = ATA_BUSY;
		ata_tf_to_fis(&tf, 0, 0, d2h_fis);

		rc = sata_link_hardreset(link, timing, deadline, &online,
				ahci_check_ready);

		if (sata_scr_read(link, SCR_STATUS, &sstatus) != 0 ||
				(sstatus & 0xf) != 1)
			break;

		ata_link_printk(link, KERN_INFO, "avn bounce port%d\n",
				port);

		pci_read_config_word(pdev, 0x92, &val);
		val &= ~(1 << port);
		pci_write_config_word(pdev, 0x92, val);
		ata_msleep(ap, 1000);
		val |= 1 << port;
		pci_write_config_word(pdev, 0x92, val);
		deadline += tmo;
	}

	hpriv->start_engine(ap);

	if (online)
		*class = ahci_dev_classify(ap);

	DPRINTK("EXIT, rc=%d, class=%u\n", rc, *class);
	return rc;
}


#ifdef CONFIG_PM
static void ahci_pci_disable_interrupts(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;
	void __iomem *mmio = hpriv->mmio;
	u32 ctl;

	/* AHCI spec rev1.1 section 8.3.3:
	 * Software must disable interrupts prior to requesting a
	 * transition of the HBA to D3 state.
	 */
	ctl = readl(mmio + HOST_CTL);
	ctl &= ~HOST_IRQ_EN;
	writel(ctl, mmio + HOST_CTL);
	readl(mmio + HOST_CTL); /* flush */
}

static int ahci_pci_device_runtime_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ata_host *host = pci_get_drvdata(pdev);

	ahci_pci_disable_interrupts(host);
	return 0;
}

static int ahci_pci_device_runtime_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ata_host *host = pci_get_drvdata(pdev);
	int rc;

	rc = ahci_pci_reset_controller(host);
	if (rc)
		return rc;
	ahci_pci_init_controller(host);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int ahci_pci_device_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ata_host *host = pci_get_drvdata(pdev);
	struct ahci_host_priv *hpriv = host->private_data;

	if (hpriv->flags & AHCI_HFLAG_NO_SUSPEND) {
		dev_err(&pdev->dev,
			"BIOS update required for suspend/resume\n");
		return -EIO;
	}

	ahci_pci_disable_interrupts(host);
	return ata_host_suspend(host, PMSG_SUSPEND);
}

static int ahci_pci_device_resume(struct device *dev)
{
	struct ata_host *host = dev_get_drvdata(&pdev->dev);
	struct ata_host *host = pci_get_drvdata(pdev);
	int rc;

	rc = ata_pci_device_do_resume(pdev);
	if (rc)
		return rc;

	if (pdev->dev.power.power_state.event == PM_EVENT_SUSPEND) {
		rc = ahci_reset_controller(host);
		if (rc)
			return rc;

		ahci_init_controller(host);
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ata_host *host = pci_get_drvdata(pdev);
	int rc;

	/* Apple BIOS helpfully mangles the registers on resume */
	if (is_mcp89_apple(pdev))
		ahci_mcp89_apple_enable(pdev);

	if (pdev->dev.power.power_state.event == PM_EVENT_SUSPEND) {
		rc = ahci_pci_reset_controller(host);
		if (rc)
			return rc;

		ahci_pci_init_controller(host);
	}

	ata_host_resume(host);

	return 0;
}
#endif

static int ahci_port_start(struct ata_port *ap)
{
	struct device *dev = ap->host->dev;
	struct ahci_port_priv *pp;
	void *mem;
	dma_addr_t mem_dma;

	pp = devm_kzalloc(dev, sizeof(*pp), GFP_KERNEL);
	if (!pp)
		return -ENOMEM;

	mem = dmam_alloc_coherent(dev, AHCI_PORT_PRIV_DMA_SZ, &mem_dma,
				  GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	memset(mem, 0, AHCI_PORT_PRIV_DMA_SZ);

	/*
	 * First item in chunk of DMA memory: 32-slot command table,
	 * 32 bytes each in size
	 */
	pp->cmd_slot = mem;
	pp->cmd_slot_dma = mem_dma;

	mem += AHCI_CMD_SLOT_SZ;
	mem_dma += AHCI_CMD_SLOT_SZ;

	/*
	 * Second item: Received-FIS area
	 */
	pp->rx_fis = mem;
	pp->rx_fis_dma = mem_dma;

	mem += AHCI_RX_FIS_SZ;
	mem_dma += AHCI_RX_FIS_SZ;

	/*
	 * Third item: data area for storing a single command
	 * and its scatter-gather table
	 */
	pp->cmd_tbl = mem;
	pp->cmd_tbl_dma = mem_dma;

	/*
	 * Save off initial list of interrupts to be enabled.
	 * This could be changed later
	 */
	pp->intr_mask = DEF_PORT_IRQ;

	ap->private_data = pp;

	/* engage engines, captain */
	return ahci_port_resume(ap);
}

static void ahci_port_stop(struct ata_port *ap)
{
	const char *emsg = NULL;
	int rc;

	/* de-initialize port */
	rc = ahci_deinit_port(ap, &emsg);
	if (rc)
		ata_port_printk(ap, KERN_WARNING, "%s (%d)\n", emsg, rc);
}
#endif /* CONFIG_PM */

static int ahci_configure_dma_masks(struct pci_dev *pdev, int using_dac)
{
	int rc;

	if (using_dac &&
	    !pci_set_dma_mask(pdev, DMA_64BIT_MASK)) {
		rc = pci_set_consistent_dma_mask(pdev, DMA_64BIT_MASK);
		if (rc) {
			rc = pci_set_consistent_dma_mask(pdev, DMA_32BIT_MASK);
			if (rc) {
				dev_printk(KERN_ERR, &pdev->dev,
					   "64-bit DMA enable failed\n");
	/*
	 * If the device fixup already set the dma_mask to some non-standard
	 * value, don't extend it here. This happens on STA2X11, for example.
	 */
	if (pdev->dma_mask && pdev->dma_mask < DMA_BIT_MASK(32))
		return 0;

	if (using_dac &&
	    !dma_set_mask(&pdev->dev, DMA_BIT_MASK(64))) {
		rc = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
		if (rc) {
			rc = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
			if (rc) {
				dev_err(&pdev->dev,
					"64-bit DMA enable failed\n");
				return rc;
			}
		}
	} else {
		rc = pci_set_dma_mask(pdev, DMA_32BIT_MASK);
		if (rc) {
			dev_printk(KERN_ERR, &pdev->dev,
				   "32-bit DMA enable failed\n");
			return rc;
		}
		rc = pci_set_consistent_dma_mask(pdev, DMA_32BIT_MASK);
		if (rc) {
			dev_printk(KERN_ERR, &pdev->dev,
				   "32-bit consistent DMA enable failed\n");
		rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (rc) {
			dev_err(&pdev->dev, "32-bit DMA enable failed\n");
			return rc;
		}
		rc = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (rc) {
			dev_err(&pdev->dev,
				"32-bit consistent DMA enable failed\n");
			return rc;
		}
	}
	return 0;
}

static void ahci_print_info(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;
	struct pci_dev *pdev = to_pci_dev(host->dev);
	void __iomem *mmio = host->iomap[AHCI_PCI_BAR];
	u32 vers, cap, impl, speed;
	const char *speed_s;
	u16 cc;
	const char *scc_s;

	vers = readl(mmio + HOST_VERSION);
	cap = hpriv->cap;
	impl = hpriv->port_map;

	speed = (cap >> 20) & 0xf;
	if (speed == 1)
		speed_s = "1.5";
	else if (speed == 2)
		speed_s = "3";
	else
		speed_s = "?";

static void ahci_pci_print_info(struct ata_host *host)
{
	struct pci_dev *pdev = to_pci_dev(host->dev);
	u16 cc;
	const char *scc_s;

	pci_read_config_word(pdev, 0x0a, &cc);
	if (cc == PCI_CLASS_STORAGE_IDE)
		scc_s = "IDE";
	else if (cc == PCI_CLASS_STORAGE_SATA)
		scc_s = "SATA";
	else if (cc == PCI_CLASS_STORAGE_RAID)
		scc_s = "RAID";
	else
		scc_s = "unknown";

	dev_printk(KERN_INFO, &pdev->dev,
		"AHCI %02x%02x.%02x%02x "
		"%u slots %u ports %s Gbps 0x%x impl %s mode\n"
		,

		(vers >> 24) & 0xff,
		(vers >> 16) & 0xff,
		(vers >> 8) & 0xff,
		vers & 0xff,

		((cap >> 8) & 0x1f) + 1,
		(cap & 0x1f) + 1,
		speed_s,
		impl,
		scc_s);

	dev_printk(KERN_INFO, &pdev->dev,
		"flags: "
		"%s%s%s%s%s%s%s"
		"%s%s%s%s%s%s%s"
		"%s\n"
		,

		cap & (1 << 31) ? "64bit " : "",
		cap & (1 << 30) ? "ncq " : "",
		cap & (1 << 29) ? "sntf " : "",
		cap & (1 << 28) ? "ilck " : "",
		cap & (1 << 27) ? "stag " : "",
		cap & (1 << 26) ? "pm " : "",
		cap & (1 << 25) ? "led " : "",

		cap & (1 << 24) ? "clo " : "",
		cap & (1 << 19) ? "nz " : "",
		cap & (1 << 18) ? "only " : "",
		cap & (1 << 17) ? "pmp " : "",
		cap & (1 << 15) ? "pio " : "",
		cap & (1 << 14) ? "slum " : "",
		cap & (1 << 13) ? "part " : "",
		cap & (1 << 6) ? "ems ": ""
		);
	ahci_print_info(host, scc_s);
}

/* On ASUS P5W DH Deluxe, the second port of PCI device 00:1f.2 is
 * hardwired to on-board SIMG 4726.  The chipset is ICH8 and doesn't
 * support PMP and the 4726 either directly exports the device
 * attached to the first downstream port or acts as a hardware storage
 * controller and emulate a single ATA device (can be RAID 0/1 or some
 * other configuration).
 *
 * When there's no device attached to the first downstream port of the
 * 4726, "Config Disk" appears, which is a pseudo ATA device to
 * configure the 4726.  However, ATA emulation of the device is very
 * lame.  It doesn't send signature D2H Reg FIS after the initial
 * hardreset, pukes on SRST w/ PMP==0 and has bunch of other issues.
 *
 * The following function works around the problem by always using
 * hardreset on the port and not depending on receiving signature FIS
 * afterward.  If signature FIS isn't received soon, ATA class is
 * assumed without follow-up softreset.
 */
static void ahci_p5wdh_workaround(struct ata_host *host)
{
	static struct dmi_system_id sysids[] = {
	static const struct dmi_system_id sysids[] = {
		{
			.ident = "P5W DH Deluxe",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR,
					  "ASUSTEK COMPUTER INC"),
				DMI_MATCH(DMI_PRODUCT_NAME, "P5W DH Deluxe"),
			},
		},
		{ }
	};
	struct pci_dev *pdev = to_pci_dev(host->dev);

	if (pdev->bus->number == 0 && pdev->devfn == PCI_DEVFN(0x1f, 2) &&
	    dmi_check_system(sysids)) {
		struct ata_port *ap = host->ports[1];

		dev_printk(KERN_INFO, &pdev->dev, "enabling ASUS P5W DH "
			   "Deluxe on-board SIMG4726 workaround\n");
		dev_info(&pdev->dev,
			 "enabling ASUS P5W DH Deluxe on-board SIMG4726 workaround\n");

		ap->ops = &ahci_p5wdh_ops;
		ap->link.flags |= ATA_LFLAG_NO_SRST | ATA_LFLAG_ASSUME_ATA;
	}
}

static int ahci_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	static int printed_version;
/*
 * Macbook7,1 firmware forcibly disables MCP89 AHCI and changes PCI ID when
 * booting in BIOS compatibility mode.  We restore the registers but not ID.
 */
static void ahci_mcp89_apple_enable(struct pci_dev *pdev)
{
	u32 val;

	printk(KERN_INFO "ahci: enabling MCP89 AHCI mode\n");

	pci_read_config_dword(pdev, 0xf8, &val);
	val |= 1 << 0x1b;
	/* the following changes the device ID, but appears not to affect function */
	/* val = (val & ~0xf0000000) | 0x80000000; */
	pci_write_config_dword(pdev, 0xf8, val);

	pci_read_config_dword(pdev, 0x54c, &val);
	val |= 1 << 0xc;
	pci_write_config_dword(pdev, 0x54c, val);

	pci_read_config_dword(pdev, 0x4a4, &val);
	val &= 0xff;
	val |= 0x01060100;
	pci_write_config_dword(pdev, 0x4a4, val);

	pci_read_config_dword(pdev, 0x54c, &val);
	val &= ~(1 << 0xc);
	pci_write_config_dword(pdev, 0x54c, val);

	pci_read_config_dword(pdev, 0xf8, &val);
	val &= ~(1 << 0x1b);
	pci_write_config_dword(pdev, 0xf8, val);
}

static bool is_mcp89_apple(struct pci_dev *pdev)
{
	return pdev->vendor == PCI_VENDOR_ID_NVIDIA &&
		pdev->device == PCI_DEVICE_ID_NVIDIA_NFORCE_MCP89_SATA &&
		pdev->subsystem_vendor == PCI_VENDOR_ID_APPLE &&
		pdev->subsystem_device == 0xcb89;
}

/* only some SB600 ahci controllers can do 64bit DMA */
static bool ahci_sb600_enable_64bit(struct pci_dev *pdev)
{
	static const struct dmi_system_id sysids[] = {
		/*
		 * The oldest version known to be broken is 0901 and
		 * working is 1501 which was released on 2007-10-26.
		 * Enable 64bit DMA on 1501 and anything newer.
		 *
		 * Please read bko#9412 for more info.
		 */
		{
			.ident = "ASUS M2A-VM",
			.matches = {
				DMI_MATCH(DMI_BOARD_VENDOR,
					  "ASUSTeK Computer INC."),
				DMI_MATCH(DMI_BOARD_NAME, "M2A-VM"),
			},
			.driver_data = "20071026",	/* yyyymmdd */
		},
		/*
		 * All BIOS versions for the MSI K9A2 Platinum (MS-7376)
		 * support 64bit DMA.
		 *
		 * BIOS versions earlier than 1.5 had the Manufacturer DMI
		 * fields as "MICRO-STAR INTERANTIONAL CO.,LTD".
		 * This spelling mistake was fixed in BIOS version 1.5, so
		 * 1.5 and later have the Manufacturer as
		 * "MICRO-STAR INTERNATIONAL CO.,LTD".
		 * So try to match on DMI_BOARD_VENDOR of "MICRO-STAR INTER".
		 *
		 * BIOS versions earlier than 1.9 had a Board Product Name
		 * DMI field of "MS-7376". This was changed to be
		 * "K9A2 Platinum (MS-7376)" in version 1.9, but we can still
		 * match on DMI_BOARD_NAME of "MS-7376".
		 */
		{
			.ident = "MSI K9A2 Platinum",
			.matches = {
				DMI_MATCH(DMI_BOARD_VENDOR,
					  "MICRO-STAR INTER"),
				DMI_MATCH(DMI_BOARD_NAME, "MS-7376"),
			},
		},
		/*
		 * All BIOS versions for the MSI K9AGM2 (MS-7327) support
		 * 64bit DMA.
		 *
		 * This board also had the typo mentioned above in the
		 * Manufacturer DMI field (fixed in BIOS version 1.5), so
		 * match on DMI_BOARD_VENDOR of "MICRO-STAR INTER" again.
		 */
		{
			.ident = "MSI K9AGM2",
			.matches = {
				DMI_MATCH(DMI_BOARD_VENDOR,
					  "MICRO-STAR INTER"),
				DMI_MATCH(DMI_BOARD_NAME, "MS-7327"),
			},
		},
		/*
		 * All BIOS versions for the Asus M3A support 64bit DMA.
		 * (all release versions from 0301 to 1206 were tested)
		 */
		{
			.ident = "ASUS M3A",
			.matches = {
				DMI_MATCH(DMI_BOARD_VENDOR,
					  "ASUSTeK Computer INC."),
				DMI_MATCH(DMI_BOARD_NAME, "M3A"),
			},
		},
		{ }
	};
	const struct dmi_system_id *match;
	int year, month, date;
	char buf[9];

	match = dmi_first_match(sysids);
	if (pdev->bus->number != 0 || pdev->devfn != PCI_DEVFN(0x12, 0) ||
	    !match)
		return false;

	if (!match->driver_data)
		goto enable_64bit;

	dmi_get_date(DMI_BIOS_DATE, &year, &month, &date);
	snprintf(buf, sizeof(buf), "%04d%02d%02d", year, month, date);

	if (strcmp(buf, match->driver_data) >= 0)
		goto enable_64bit;
	else {
		dev_warn(&pdev->dev,
			 "%s: BIOS too old, forcing 32bit DMA, update BIOS\n",
			 match->ident);
		return false;
	}

enable_64bit:
	dev_warn(&pdev->dev, "%s: enabling 64bit DMA\n", match->ident);
	return true;
}

static bool ahci_broken_system_poweroff(struct pci_dev *pdev)
{
	static const struct dmi_system_id broken_systems[] = {
		{
			.ident = "HP Compaq nx6310",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
				DMI_MATCH(DMI_PRODUCT_NAME, "HP Compaq nx6310"),
			},
			/* PCI slot number of the controller */
			.driver_data = (void *)0x1FUL,
		},
		{
			.ident = "HP Compaq 6720s",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
				DMI_MATCH(DMI_PRODUCT_NAME, "HP Compaq 6720s"),
			},
			/* PCI slot number of the controller */
			.driver_data = (void *)0x1FUL,
		},

		{ }	/* terminate list */
	};
	const struct dmi_system_id *dmi = dmi_first_match(broken_systems);

	if (dmi) {
		unsigned long slot = (unsigned long)dmi->driver_data;
		/* apply the quirk only to on-board controllers */
		return slot == PCI_SLOT(pdev->devfn);
	}

	return false;
}

static bool ahci_broken_suspend(struct pci_dev *pdev)
{
	static const struct dmi_system_id sysids[] = {
		/*
		 * On HP dv[4-6] and HDX18 with earlier BIOSen, link
		 * to the harddisk doesn't become online after
		 * resuming from STR.  Warn and fail suspend.
		 *
		 * http://bugzilla.kernel.org/show_bug.cgi?id=12276
		 *
		 * Use dates instead of versions to match as HP is
		 * apparently recycling both product and version
		 * strings.
		 *
		 * http://bugzilla.kernel.org/show_bug.cgi?id=15462
		 */
		{
			.ident = "dv4",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
				DMI_MATCH(DMI_PRODUCT_NAME,
					  "HP Pavilion dv4 Notebook PC"),
			},
			.driver_data = "20090105",	/* F.30 */
		},
		{
			.ident = "dv5",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
				DMI_MATCH(DMI_PRODUCT_NAME,
					  "HP Pavilion dv5 Notebook PC"),
			},
			.driver_data = "20090506",	/* F.16 */
		},
		{
			.ident = "dv6",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
				DMI_MATCH(DMI_PRODUCT_NAME,
					  "HP Pavilion dv6 Notebook PC"),
			},
			.driver_data = "20090423",	/* F.21 */
		},
		{
			.ident = "HDX18",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
				DMI_MATCH(DMI_PRODUCT_NAME,
					  "HP HDX18 Notebook PC"),
			},
			.driver_data = "20090430",	/* F.23 */
		},
		/*
		 * Acer eMachines G725 has the same problem.  BIOS
		 * V1.03 is known to be broken.  V3.04 is known to
		 * work.  Between, there are V1.06, V2.06 and V3.03
		 * that we don't have much idea about.  For now,
		 * blacklist anything older than V3.04.
		 *
		 * http://bugzilla.kernel.org/show_bug.cgi?id=15104
		 */
		{
			.ident = "G725",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "eMachines"),
				DMI_MATCH(DMI_PRODUCT_NAME, "eMachines G725"),
			},
			.driver_data = "20091216",	/* V3.04 */
		},
		{ }	/* terminate list */
	};
	const struct dmi_system_id *dmi = dmi_first_match(sysids);
	int year, month, date;
	char buf[9];

	if (!dmi || pdev->bus->number || pdev->devfn != PCI_DEVFN(0x1f, 2))
		return false;

	dmi_get_date(DMI_BIOS_DATE, &year, &month, &date);
	snprintf(buf, sizeof(buf), "%04d%02d%02d", year, month, date);

	return strcmp(buf, dmi->driver_data) < 0;
}

static bool ahci_broken_online(struct pci_dev *pdev)
{
#define ENCODE_BUSDEVFN(bus, slot, func)			\
	(void *)(unsigned long)(((bus) << 8) | PCI_DEVFN((slot), (func)))
	static const struct dmi_system_id sysids[] = {
		/*
		 * There are several gigabyte boards which use
		 * SIMG5723s configured as hardware RAID.  Certain
		 * 5723 firmware revisions shipped there keep the link
		 * online but fail to answer properly to SRST or
		 * IDENTIFY when no device is attached downstream
		 * causing libata to retry quite a few times leading
		 * to excessive detection delay.
		 *
		 * As these firmwares respond to the second reset try
		 * with invalid device signature, considering unknown
		 * sig as offline works around the problem acceptably.
		 */
		{
			.ident = "EP45-DQ6",
			.matches = {
				DMI_MATCH(DMI_BOARD_VENDOR,
					  "Gigabyte Technology Co., Ltd."),
				DMI_MATCH(DMI_BOARD_NAME, "EP45-DQ6"),
			},
			.driver_data = ENCODE_BUSDEVFN(0x0a, 0x00, 0),
		},
		{
			.ident = "EP45-DS5",
			.matches = {
				DMI_MATCH(DMI_BOARD_VENDOR,
					  "Gigabyte Technology Co., Ltd."),
				DMI_MATCH(DMI_BOARD_NAME, "EP45-DS5"),
			},
			.driver_data = ENCODE_BUSDEVFN(0x03, 0x00, 0),
		},
		{ }	/* terminate list */
	};
#undef ENCODE_BUSDEVFN
	const struct dmi_system_id *dmi = dmi_first_match(sysids);
	unsigned int val;

	if (!dmi)
		return false;

	val = (unsigned long)dmi->driver_data;

	return pdev->bus->number == (val >> 8) && pdev->devfn == (val & 0xff);
}

static bool ahci_broken_devslp(struct pci_dev *pdev)
{
	/* device with broken DEVSLP but still showing SDS capability */
	static const struct pci_device_id ids[] = {
		{ PCI_VDEVICE(INTEL, 0x0f23)}, /* Valleyview SoC */
		{}
	};

	return pci_match_id(ids, pdev);
}

#ifdef CONFIG_ATA_ACPI
static void ahci_gtf_filter_workaround(struct ata_host *host)
{
	static const struct dmi_system_id sysids[] = {
		/*
		 * Aspire 3810T issues a bunch of SATA enable commands
		 * via _GTF including an invalid one and one which is
		 * rejected by the device.  Among the successful ones
		 * is FPDMA non-zero offset enable which when enabled
		 * only on the drive side leads to NCQ command
		 * failures.  Filter it out.
		 */
		{
			.ident = "Aspire 3810T",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Acer"),
				DMI_MATCH(DMI_PRODUCT_NAME, "Aspire 3810T"),
			},
			.driver_data = (void *)ATA_ACPI_FILTER_FPDMA_OFFSET,
		},
		{ }
	};
	const struct dmi_system_id *dmi = dmi_first_match(sysids);
	unsigned int filter;
	int i;

	if (!dmi)
		return;

	filter = (unsigned long)dmi->driver_data;
	dev_info(host->dev, "applying extra ACPI _GTF filter 0x%x for %s\n",
		 filter, dmi->ident);

	for (i = 0; i < host->n_ports; i++) {
		struct ata_port *ap = host->ports[i];
		struct ata_link *link;
		struct ata_device *dev;

		ata_for_each_link(link, ap, EDGE)
			ata_for_each_dev(dev, link, ALL)
				dev->gtf_filter |= filter;
	}
}
#else
static inline void ahci_gtf_filter_workaround(struct ata_host *host)
{}
#endif

/*
 * On the Acer Aspire Switch Alpha 12, sometimes all SATA ports are detected
 * as DUMMY, or detected but eventually get a "link down" and never get up
 * again. When this happens, CAP.NP may hold a value of 0x00 or 0x01, and the
 * port_map may hold a value of 0x00.
 *
 * Overriding CAP.NP to 0x02 and the port_map to 0x7 will reveal all 3 ports
 * and can significantly reduce the occurrence of the problem.
 *
 * https://bugzilla.kernel.org/show_bug.cgi?id=189471
 */
static void acer_sa5_271_workaround(struct ahci_host_priv *hpriv,
				    struct pci_dev *pdev)
{
	static const struct dmi_system_id sysids[] = {
		{
			.ident = "Acer Switch Alpha 12",
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Acer"),
				DMI_MATCH(DMI_PRODUCT_NAME, "Switch SA5-271")
			},
		},
		{ }
	};

	if (dmi_check_system(sysids)) {
		dev_info(&pdev->dev, "enabling Acer Switch Alpha 12 workaround\n");
		if ((hpriv->saved_cap & 0xC734FF00) == 0xC734FF00) {
			hpriv->port_map = 0x7;
			hpriv->cap = 0xC734FF02;
		}
	}
}

#ifdef CONFIG_ARM64
/*
 * Due to ERRATA#22536, ThunderX needs to handle HOST_IRQ_STAT differently.
 * Workaround is to make sure all pending IRQs are served before leaving
 * handler.
 */
static irqreturn_t ahci_thunderx_irq_handler(int irq, void *dev_instance)
{
	struct ata_host *host = dev_instance;
	struct ahci_host_priv *hpriv;
	unsigned int rc = 0;
	void __iomem *mmio;
	u32 irq_stat, irq_masked;
	unsigned int handled = 1;

	VPRINTK("ENTER\n");
	hpriv = host->private_data;
	mmio = hpriv->mmio;
	irq_stat = readl(mmio + HOST_IRQ_STAT);
	if (!irq_stat)
		return IRQ_NONE;

	do {
		irq_masked = irq_stat & hpriv->port_map;
		spin_lock(&host->lock);
		rc = ahci_handle_port_intr(host, irq_masked);
		if (!rc)
			handled = 0;
		writel(irq_stat, mmio + HOST_IRQ_STAT);
		irq_stat = readl(mmio + HOST_IRQ_STAT);
		spin_unlock(&host->lock);
	} while (irq_stat);
	VPRINTK("EXIT\n");

	return IRQ_RETVAL(handled);
}
#endif

static void ahci_remap_check(struct pci_dev *pdev, int bar,
		struct ahci_host_priv *hpriv)
{
	int i, count = 0;
	u32 cap;

	/*
	 * Check if this device might have remapped nvme devices.
	 */
	if (pdev->vendor != PCI_VENDOR_ID_INTEL ||
	    pci_resource_len(pdev, bar) < SZ_512K ||
	    bar != AHCI_PCI_BAR_STANDARD ||
	    !(readl(hpriv->mmio + AHCI_VSCAP) & 1))
		return;

	cap = readq(hpriv->mmio + AHCI_REMAP_CAP);
	for (i = 0; i < AHCI_MAX_REMAP; i++) {
		if ((cap & (1 << i)) == 0)
			continue;
		if (readl(hpriv->mmio + ahci_remap_dcc(i))
				!= PCI_CLASS_STORAGE_EXPRESS)
			continue;

		/* We've found a remapped device */
		count++;
	}

	if (!count)
		return;

	dev_warn(&pdev->dev, "Found %d remapped NVMe devices.\n", count);
	dev_warn(&pdev->dev,
		 "Switch your BIOS from RAID to AHCI mode to use them.\n");

	/*
	 * Don't rely on the msi-x capability in the remap case,
	 * share the legacy interrupt across ahci and remapped devices.
	 */
	hpriv->flags |= AHCI_HFLAG_NO_MSI;
}

static int ahci_get_irq_vector(struct ata_host *host, int port)
{
	return pci_irq_vector(to_pci_dev(host->dev), port);
}

static int ahci_init_msi(struct pci_dev *pdev, unsigned int n_ports,
			struct ahci_host_priv *hpriv)
{
	int nvec;

	if (hpriv->flags & AHCI_HFLAG_NO_MSI)
		return -ENODEV;

	/*
	 * If number of MSIs is less than number of ports then Sharing Last
	 * Message mode could be enforced. In this case assume that advantage
	 * of multipe MSIs is negated and use single MSI mode instead.
	 */
	if (n_ports > 1) {
		nvec = pci_alloc_irq_vectors(pdev, n_ports, INT_MAX,
				PCI_IRQ_MSIX | PCI_IRQ_MSI);
		if (nvec > 0) {
			if (!(readl(hpriv->mmio + HOST_CTL) & HOST_MRSM)) {
				hpriv->get_irq_vector = ahci_get_irq_vector;
				hpriv->flags |= AHCI_HFLAG_MULTI_MSI;
				return nvec;
			}

			/*
			 * Fallback to single MSI mode if the controller
			 * enforced MRSM mode.
			 */
			printk(KERN_INFO
				"ahci: MRSM is on, fallback to single MSI\n");
			pci_free_irq_vectors(pdev);
		}
	}

	/*
	 * If the host is not capable of supporting per-port vectors, fall
	 * back to single MSI before finally attempting single MSI-X.
	 */
	nvec = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (nvec == 1)
		return nvec;
	return pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSIX);
}

static int ahci_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	unsigned int board_id = ent->driver_data;
	struct ata_port_info pi = ahci_port_info[board_id];
	const struct ata_port_info *ppi[] = { &pi, NULL };
	struct device *dev = &pdev->dev;
	struct ahci_host_priv *hpriv;
	struct ata_host *host;
	int n_ports, i, rc;

	VPRINTK("ENTER\n");

	WARN_ON(ATA_MAX_QUEUE > AHCI_MAX_CMDS);

	if (!printed_version++)
		dev_printk(KERN_DEBUG, &pdev->dev, "version " DRV_VERSION "\n");
	int ahci_pci_bar = AHCI_PCI_BAR_STANDARD;

	VPRINTK("ENTER\n");

	WARN_ON((int)ATA_MAX_QUEUE > AHCI_MAX_CMDS);

	ata_print_version_once(&pdev->dev, DRV_VERSION);

	/* The AHCI driver can only drive the SATA ports, the PATA driver
	   can drive them all so if both drivers are selected make sure
	   AHCI stays out of the way */
	if (pdev->vendor == PCI_VENDOR_ID_MARVELL && !marvell_enable)
		return -ENODEV;

	/* Apple BIOS on MCP89 prevents us using AHCI */
	if (is_mcp89_apple(pdev))
		ahci_mcp89_apple_enable(pdev);

	/* Promise's PDC42819 is a SAS/SATA controller that has an AHCI mode.
	 * At the moment, we can only use the AHCI mode. Let the users know
	 * that for SAS drives they're out of luck.
	 */
	if (pdev->vendor == PCI_VENDOR_ID_PROMISE)
		dev_info(&pdev->dev,
			 "PDC42819 can only drive SATA devices with this driver\n");

	/* Some devices use non-standard BARs */
	if (pdev->vendor == PCI_VENDOR_ID_STMICRO && pdev->device == 0xCC06)
		ahci_pci_bar = AHCI_PCI_BAR_STA2X11;
	else if (pdev->vendor == 0x1c44 && pdev->device == 0x8000)
		ahci_pci_bar = AHCI_PCI_BAR_ENMOTUS;
	else if (pdev->vendor == 0x177d && pdev->device == 0xa01c)
		ahci_pci_bar = AHCI_PCI_BAR_CAVIUM;

	/* acquire resources */
	rc = pcim_enable_device(pdev);
	if (rc)
		return rc;

	/* AHCI controllers often implement SFF compatible interface.
	 * Grab all PCI BARs just in case.
	 */
	rc = pcim_iomap_regions_request_all(pdev, 1 << AHCI_PCI_BAR, DRV_NAME);
	if (rc == -EBUSY)
		pcim_pin_device(pdev);
	if (rc)
		return rc;

	if (pdev->vendor == PCI_VENDOR_ID_INTEL &&
	    (pdev->device == 0x2652 || pdev->device == 0x2653)) {
		u8 map;

		/* ICH6s share the same PCI ID for both piix and ahci
		 * modes.  Enabling ahci mode while MAP indicates
		 * combined mode is a bad idea.  Yield to ata_piix.
		 */
		pci_read_config_byte(pdev, ICH_MAP, &map);
		if (map & 0x3) {
			dev_printk(KERN_INFO, &pdev->dev, "controller is in "
				   "combined mode, can't enable AHCI mode\n");
			dev_info(&pdev->dev,
				 "controller is in combined mode, can't enable AHCI mode\n");
			return -ENODEV;
		}
	}

	/* AHCI controllers often implement SFF compatible interface.
	 * Grab all PCI BARs just in case.
	 */
	rc = pcim_iomap_regions_request_all(pdev, 1 << ahci_pci_bar, DRV_NAME);
	if (rc == -EBUSY)
		pcim_pin_device(pdev);
	if (rc)
		return rc;

	hpriv = devm_kzalloc(dev, sizeof(*hpriv), GFP_KERNEL);
	if (!hpriv)
		return -ENOMEM;
	hpriv->flags |= (unsigned long)pi.private_data;

	/* MCP65 revision A1 and A2 can't do MSI */
	if (board_id == board_ahci_mcp65 &&
	    (pdev->revision == 0xa1 || pdev->revision == 0xa2))
		hpriv->flags |= AHCI_HFLAG_NO_MSI;

	if ((hpriv->flags & AHCI_HFLAG_NO_MSI) || pci_enable_msi(pdev))
		pci_intx(pdev, 1);

	/* save initial config */
	ahci_save_initial_config(pdev, hpriv);

	/* prepare host */
	if (hpriv->cap & HOST_CAP_NCQ)
		pi.flags |= ATA_FLAG_NCQ;
	/* SB800 does NOT need the workaround to ignore SERR_INTERNAL */
	if (board_id == board_ahci_sb700 && pdev->revision >= 0x40)
		hpriv->flags &= ~AHCI_HFLAG_IGN_SERR_INTERNAL;

	/* only some SB600s can do 64bit DMA */
	if (ahci_sb600_enable_64bit(pdev))
		hpriv->flags &= ~AHCI_HFLAG_32BIT_ONLY;

	hpriv->mmio = pcim_iomap_table(pdev)[ahci_pci_bar];

	/* detect remapped nvme devices */
	ahci_remap_check(pdev, ahci_pci_bar, hpriv);

	/* must set flag prior to save config in order to take effect */
	if (ahci_broken_devslp(pdev))
		hpriv->flags |= AHCI_HFLAG_NO_DEVSLP;

#ifdef CONFIG_ARM64
	if (pdev->vendor == 0x177d && pdev->device == 0xa01c)
		hpriv->irq_handler = ahci_thunderx_irq_handler;
#endif

	/* save initial config */
	ahci_pci_save_initial_config(pdev, hpriv);

	/* prepare host */
	if (hpriv->cap & HOST_CAP_NCQ) {
		pi.flags |= ATA_FLAG_NCQ;
		/*
		 * Auto-activate optimization is supposed to be
		 * supported on all AHCI controllers indicating NCQ
		 * capability, but it seems to be broken on some
		 * chipsets including NVIDIAs.
		 */
		if (!(hpriv->flags & AHCI_HFLAG_NO_FPDMA_AA))
			pi.flags |= ATA_FLAG_FPDMA_AA;

		/*
		 * All AHCI controllers should be forward-compatible
		 * with the new auxiliary field. This code should be
		 * conditionalized if any buggy AHCI controllers are
		 * encountered.
		 */
		pi.flags |= ATA_FLAG_FPDMA_AUX;
	}

	if (hpriv->cap & HOST_CAP_PMP)
		pi.flags |= ATA_FLAG_PMP;

	if (ahci_em_messages && (hpriv->cap & HOST_CAP_EMS)) {
		u8 messages;
		void __iomem *mmio = pcim_iomap_table(pdev)[AHCI_PCI_BAR];
		u32 em_loc = readl(mmio + HOST_EM_LOC);
		u32 em_ctl = readl(mmio + HOST_EM_CTL);

		messages = (em_ctl & 0x000f0000) >> 16;

		/* we only support LED message type right now */
		if ((messages & 0x01) && (ahci_em_messages == 1)) {
			/* store em_loc */
			hpriv->em_loc = ((em_loc >> 16) * 4);
			pi.flags |= ATA_FLAG_EM;
			if (!(em_ctl & EM_CTL_ALHD))
				pi.flags |= ATA_FLAG_SW_ACTIVITY;
		}
	ahci_set_em_messages(hpriv, &pi);

	if (ahci_broken_system_poweroff(pdev)) {
		pi.flags |= ATA_FLAG_NO_POWEROFF_SPINDOWN;
		dev_info(&pdev->dev,
			"quirky BIOS, skipping spindown on poweroff\n");
	}

	if (ahci_broken_suspend(pdev)) {
		hpriv->flags |= AHCI_HFLAG_NO_SUSPEND;
		dev_warn(&pdev->dev,
			 "BIOS update required for suspend/resume\n");
	}

	if (ahci_broken_online(pdev)) {
		hpriv->flags |= AHCI_HFLAG_SRST_TOUT_IS_OFFLINE;
		dev_info(&pdev->dev,
			 "online status unreliable, applying workaround\n");
	}


	/* Acer SA5-271 workaround modifies private_data */
	acer_sa5_271_workaround(hpriv, pdev);

	/* CAP.NP sometimes indicate the index of the last enabled
	 * port, at other times, that of the last possible port, so
	 * determining the maximum port number requires looking at
	 * both CAP.NP and port_map.
	 */
	n_ports = max(ahci_nr_ports(hpriv->cap), fls(hpriv->port_map));

	host = ata_host_alloc_pinfo(&pdev->dev, ppi, n_ports);
	if (!host)
		return -ENOMEM;
	host->iomap = pcim_iomap_table(pdev);
	host->private_data = hpriv;

	host->private_data = hpriv;

	if (ahci_init_msi(pdev, n_ports, hpriv) < 0) {
		/* legacy intx interrupts */
		pci_intx(pdev, 1);
	}
	hpriv->irq = pci_irq_vector(pdev, 0);

	if (!(hpriv->cap & HOST_CAP_SSS) || ahci_ignore_sss)
		host->flags |= ATA_HOST_PARALLEL_SCAN;
	else
		dev_info(&pdev->dev, "SSS flag set, parallel bus scan disabled\n");

	if (pi.flags & ATA_FLAG_EM)
		ahci_reset_em(host);

	for (i = 0; i < host->n_ports; i++) {
		struct ata_port *ap = host->ports[i];

		ata_port_pbar_desc(ap, AHCI_PCI_BAR, -1, "abar");
		ata_port_pbar_desc(ap, AHCI_PCI_BAR,
				   0x100 + ap->port_no * 0x80, "port");

		/* set initial link pm policy */
		ap->pm_policy = NOT_AVAILABLE;

		/* set enclosure management message type */
		if (ap->flags & ATA_FLAG_EM)
			ap->em_message_type = ahci_em_messages;
		ata_port_pbar_desc(ap, ahci_pci_bar, -1, "abar");
		ata_port_pbar_desc(ap, ahci_pci_bar,
				   0x100 + ap->port_no * 0x80, "port");

		/* set enclosure management message type */
		if (ap->flags & ATA_FLAG_EM)
			ap->em_message_type = hpriv->em_msg_type;


		/* disabled/not-implemented port */
		if (!(hpriv->port_map & (1 << i)))
			ap->ops = &ata_dummy_port_ops;
	}

	/* apply workaround for ASUS P5W DH Deluxe mainboard */
	ahci_p5wdh_workaround(host);

	/* apply gtf filter quirk */
	ahci_gtf_filter_workaround(host);

	/* initialize adapter */
	rc = ahci_configure_dma_masks(pdev, hpriv->cap & HOST_CAP_64);
	if (rc)
		return rc;

	rc = ahci_reset_controller(host);
	if (rc)
		return rc;

	ahci_init_controller(host);
	ahci_print_info(host);

	pci_set_master(pdev);
	return ata_host_activate(host, pdev->irq, ahci_interrupt, IRQF_SHARED,
				 &ahci_sht);
}

static int __init ahci_init(void)
{
	return pci_register_driver(&ahci_pci_driver);
}

static void __exit ahci_exit(void)
{
	pci_unregister_driver(&ahci_pci_driver);
}

	rc = ahci_pci_reset_controller(host);
	if (rc)
		return rc;

	ahci_pci_init_controller(host);
	ahci_pci_print_info(host);

	pci_set_master(pdev);

	rc = ahci_host_activate(host, &ahci_sht);
	if (rc)
		return rc;

	pm_runtime_put_noidle(&pdev->dev);
	return 0;
}

static void ahci_remove_one(struct pci_dev *pdev)
{
	pm_runtime_get_noresume(&pdev->dev);
	ata_pci_remove_one(pdev);
}

module_pci_driver(ahci_pci_driver);

MODULE_AUTHOR("Jeff Garzik");
MODULE_DESCRIPTION("AHCI SATA low-level driver");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, ahci_pci_tbl);
MODULE_VERSION(DRV_VERSION);

module_init(ahci_init);
module_exit(ahci_exit);
