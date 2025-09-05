/*
 * arch/sh/drivers/pci/pci.c
 *
 * Copyright (c) 2002 M. R. Brown  <mrbrown@linux-sh.org>
 * Copyright (c) 2004 - 2006 Paul Mundt  <lethal@linux-sh.org>
 *
 * These functions are collected here to reduce duplication of common
 * code amongst the many platform-specific PCI support code files.
 *
 * These routines require the following board-specific routines:
 * void pcibios_fixup_irqs();
 *
 * See include/asm-sh/pci.h for more information.
 * New-style PCI core.
 *
 * Copyright (c) 2004 - 2009  Paul Mundt
 * Copyright (c) 2002  M. R. Brown
 *
 * Modelled after arch/mips/pci/pci.c:
 *  Copyright (C) 2003, 04 Ralf Baechle (ralf@linux-mips.org)
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <asm/io.h>

static inline u8 bridge_swizzle(u8 pin, u8 slot)
{
	return (((pin - 1) + slot) % 4) + 1;
}

static u8 __init simple_swizzle(struct pci_dev *dev, u8 *pinp)
{
	u8 pin = *pinp;

	while (dev->bus->parent) {
		pin = bridge_swizzle(pin, PCI_SLOT(dev->devfn));
		/* Move up the chain of bridges. */
		dev = dev->bus->self;
	}
	*pinp = pin;

	/* The slot is the slot of the last bridge. */
	return PCI_SLOT(dev->devfn);
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/dma-debug.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/export.h>

unsigned long PCIBIOS_MIN_IO = 0x0000;
unsigned long PCIBIOS_MIN_MEM = 0;

/*
 * The PCI controller list.
 */
static struct pci_channel *hose_head, **hose_tail = &hose_head;

static int pci_initialized;

static void pcibios_scanbus(struct pci_channel *hose)
{
	static int next_busno;
	static int need_domain_info;
	LIST_HEAD(resources);
	struct resource *res;
	resource_size_t offset;
	int i, ret;
	struct pci_host_bridge *bridge;

	bridge = pci_alloc_host_bridge(0);
	if (!bridge)
		return;

	for (i = 0; i < hose->nr_resources; i++) {
		res = hose->resources + i;
		offset = 0;
		if (res->flags & IORESOURCE_DISABLED)
			continue;
		if (res->flags & IORESOURCE_IO)
			offset = hose->io_offset;
		else if (res->flags & IORESOURCE_MEM)
			offset = hose->mem_offset;
		pci_add_resource_offset(&resources, res, offset);
	}

	list_splice_init(&resources, &bridge->windows);
	bridge->dev.parent = NULL;
	bridge->sysdata = hose;
	bridge->busnr = next_busno;
	bridge->ops = hose->pci_ops;
	bridge->swizzle_irq = pci_common_swizzle;
	bridge->map_irq = pcibios_map_platform_irq;

	ret = pci_scan_root_bus_bridge(bridge);
	if (ret) {
		pci_free_host_bridge(bridge);
		return;
	}

	hose->bus = bridge->bus;

	need_domain_info = need_domain_info || hose->index;
	hose->need_domain_info = need_domain_info;

	next_busno = hose->bus->busn_res.end + 1;
	/* Don't allow 8-bit bus number overflow inside the hose -
	   reserve some space for bridges. */
	if (next_busno > 224) {
		next_busno = 0;
		need_domain_info = 1;
	}

	pci_bus_size_bridges(hose->bus);
	pci_bus_assign_resources(hose->bus);
	pci_bus_add_devices(hose->bus);
}

/*
 * This interrupt-safe spinlock protects all accesses to PCI
 * configuration space.
 */
DEFINE_RAW_SPINLOCK(pci_config_lock);
static DEFINE_MUTEX(pci_scan_mutex);

int register_pci_controller(struct pci_channel *hose)
{
	int i;

	for (i = 0; i < hose->nr_resources; i++) {
		struct resource *res = hose->resources + i;

		if (res->flags & IORESOURCE_DISABLED)
			continue;

		if (res->flags & IORESOURCE_IO) {
			if (request_resource(&ioport_resource, res) < 0)
				goto out;
		} else {
			if (request_resource(&iomem_resource, res) < 0)
				goto out;
		}
	}

	*hose_tail = hose;
	hose_tail = &hose->next;

	/*
	 * Do not panic here but later - this might happen before console init.
	 */
	if (!hose->io_map_base) {
		printk(KERN_WARNING
		       "registering PCI controller with io_map_base unset\n");
	}

	/*
	 * Setup the ERR/PERR and SERR timers, if available.
	 */
	pcibios_enable_timers(hose);

	/*
	 * Scan the bus if it is register after the PCI subsystem
	 * initialization.
	 */
	if (pci_initialized) {
		mutex_lock(&pci_scan_mutex);
		pcibios_scanbus(hose);
		mutex_unlock(&pci_scan_mutex);
	}

	return 0;

out:
	for (--i; i >= 0; i--)
		release_resource(&hose->resources[i]);

	printk(KERN_WARNING "Skipping PCI bus scan due to resource conflict\n");
	return -1;
}

static int __init pcibios_init(void)
{
	struct pci_channel *p;
	struct pci_bus *bus;
	int busno;

#ifdef CONFIG_PCI_AUTO
	/* assign resources */
	busno = 0;
	for (p = board_pci_channels; p->pci_ops != NULL; p++)
		busno = pciauto_assign_resources(busno, p) + 1;
#endif

	/* scan the buses */
	busno = 0;
	for (p = board_pci_channels; p->pci_ops != NULL; p++) {
		bus = pci_scan_bus(busno, p->pci_ops, p);
		busno = bus->subordinate + 1;
	}

	pci_fixup_irqs(simple_swizzle, pcibios_map_platform_irq);
	struct pci_channel *hose;

	/* Scan all of the recorded PCI controllers.  */
	for (hose = hose_head; hose; hose = hose->next)
		pcibios_scanbus(hose);

	pci_initialized = 1;

	return 0;
}
subsys_initcall(pcibios_init);

/*
 *  Called after each bus is probed, but before its children
 *  are examined.
 */
void __devinit __weak pcibios_fixup_bus(struct pci_bus *bus)
{
	pci_read_bridge_bases(bus);
}

void pcibios_align_resource(void *data, struct resource *res,
			    resource_size_t size, resource_size_t align)
			    __attribute__ ((weak));

void pcibios_fixup_bus(struct pci_bus *bus)
{
}

/*
 * We need to avoid collisions with `mirrored' VGA ports
 * and other strange ISA hardware, so we always want the
 * addresses to be allocated in the 0x000-0x0ff region
 * modulo 0x400.
 */
void pcibios_align_resource(void *data, struct resource *res,
			    resource_size_t size, resource_size_t align)
{
	if (res->flags & IORESOURCE_IO) {
		resource_size_t start = res->start;

		if (start & 0x300) {
			start = (start + 0x3ff) & ~0x3ff;
			res->start = start;
		}
	}
}

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	u16 cmd, old_cmd;
	int idx;
	struct resource *r;

	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	old_cmd = cmd;
	for(idx=0; idx<6; idx++) {
		if (!(mask & (1 << idx)))
			continue;
		r = &dev->resource[idx];
		if (!r->start && r->end) {
			printk(KERN_ERR "PCI: Device %s not available because "
			       "of resource collisions\n", pci_name(dev));
			return -EINVAL;
		}
		if (r->flags & IORESOURCE_IO)
			cmd |= PCI_COMMAND_IO;
		if (r->flags & IORESOURCE_MEM)
			cmd |= PCI_COMMAND_MEMORY;
	}
	if (dev->resource[PCI_ROM_RESOURCE].start)
		cmd |= PCI_COMMAND_MEMORY;
	if (cmd != old_cmd) {
		printk(KERN_INFO "PCI: Enabling device %s (%04x -> %04x)\n",
		       pci_name(dev), old_cmd, cmd);
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	return 0;
}

/*
 *  If we set up a device for bus mastering, we need to check and set
 *  the latency timer as it may not be properly set.
 */
static unsigned int pcibios_max_latency = 255;

void pcibios_set_master(struct pci_dev *dev)
{
	u8 lat;
	pci_read_config_byte(dev, PCI_LATENCY_TIMER, &lat);
	if (lat < 16)
		lat = (64 <= pcibios_max_latency) ? 64 : pcibios_max_latency;
	else if (lat > pcibios_max_latency)
		lat = pcibios_max_latency;
	else
		return;
	printk(KERN_INFO "PCI: Setting latency timer of device %s to %d\n",
	       pci_name(dev), lat);
	pci_write_config_byte(dev, PCI_LATENCY_TIMER, lat);
}

void __init pcibios_update_irq(struct pci_dev *dev, int irq)
{
	pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
}

void __iomem *pci_iomap(struct pci_dev *dev, int bar, unsigned long maxlen)
{
	resource_size_t start = pci_resource_start(dev, bar);
	resource_size_t len = pci_resource_len(dev, bar);
	unsigned long flags = pci_resource_flags(dev, bar);

	if (unlikely(!len || !start))
		return NULL;
	if (maxlen && len > maxlen)
		len = maxlen;

	/*
	 * Presently the IORESOURCE_MEM case is a bit special, most
	 * SH7751 style PCI controllers have PCI memory at a fixed
	 * location in the address space where no remapping is desired
	 * (typically at 0xfd000000, but is_pci_memaddr() will know
	 * best). With the IORESOURCE_MEM case more care has to be taken
	 * to inhibit page table mapping for legacy cores, but this is
	 * punted off to __ioremap().
	 *					-- PFM.
	 */
	if (flags & IORESOURCE_IO)
		return ioport_map(start, len);
	if (flags & IORESOURCE_MEM)
		return ioremap(start, len);

	return NULL;
}
EXPORT_SYMBOL(pci_iomap);
resource_size_t pcibios_align_resource(void *data, const struct resource *res,
				resource_size_t size, resource_size_t align)
{
	struct pci_dev *dev = data;
	struct pci_channel *hose = dev->sysdata;
	resource_size_t start = res->start;

	if (res->flags & IORESOURCE_IO) {
		if (start < PCIBIOS_MIN_IO + hose->resources[0].start)
			start = PCIBIOS_MIN_IO + hose->resources[0].start;

		/*
                 * Put everything into 0x00-0xff region modulo 0x400.
		 */
		if (start & 0x300)
			start = (start + 0x3ff) & ~0x3ff;
	}

	return start;
}

static void __init
pcibios_bus_report_status_early(struct pci_channel *hose,
				int top_bus, int current_bus,
				unsigned int status_mask, int warn)
{
	unsigned int pci_devfn;
	u16 status;
	int ret;

	for (pci_devfn = 0; pci_devfn < 0xff; pci_devfn++) {
		if (PCI_FUNC(pci_devfn))
			continue;
		ret = early_read_config_word(hose, top_bus, current_bus,
					     pci_devfn, PCI_STATUS, &status);
		if (ret != PCIBIOS_SUCCESSFUL)
			continue;
		if (status == 0xffff)
			continue;

		early_write_config_word(hose, top_bus, current_bus,
					pci_devfn, PCI_STATUS,
					status & status_mask);
		if (warn)
			printk("(%02x:%02x: %04X) ", current_bus,
			       pci_devfn, status);
	}
}

/*
 * We can't use pci_find_device() here since we are
 * called from interrupt context.
 */
static void __ref
pcibios_bus_report_status(struct pci_bus *bus, unsigned int status_mask,
			  int warn)
{
	struct pci_dev *dev;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		u16 status;

		/*
		 * ignore host bridge - we handle
		 * that separately
		 */
		if (dev->bus->number == 0 && dev->devfn == 0)
			continue;

		pci_read_config_word(dev, PCI_STATUS, &status);
		if (status == 0xffff)
			continue;

		if ((status & status_mask) == 0)
			continue;

		/* clear the status errors */
		pci_write_config_word(dev, PCI_STATUS, status & status_mask);

		if (warn)
			printk("(%s: %04X) ", pci_name(dev), status);
	}

	list_for_each_entry(dev, &bus->devices, bus_list)
		if (dev->subordinate)
			pcibios_bus_report_status(dev->subordinate, status_mask, warn);
}

void __ref pcibios_report_status(unsigned int status_mask, int warn)
{
	struct pci_channel *hose;

	for (hose = hose_head; hose; hose = hose->next) {
		if (unlikely(!hose->bus))
			pcibios_bus_report_status_early(hose, hose_head->index,
					hose->index, status_mask, warn);
		else
			pcibios_bus_report_status(hose->bus, status_mask, warn);
	}
}

#ifndef CONFIG_GENERIC_IOMAP

void __iomem *__pci_ioport_map(struct pci_dev *dev,
			       unsigned long port, unsigned int nr)
{
	struct pci_channel *chan = dev->sysdata;

	if (unlikely(!chan->io_map_base)) {
		chan->io_map_base = sh_io_port_base;

		if (pci_domains_supported)
			panic("To avoid data corruption io_map_base MUST be "
			      "set with multiple PCI domains.");
	}

	return (void __iomem *)(chan->io_map_base + port);
}

void pci_iounmap(struct pci_dev *dev, void __iomem *addr)
{
	iounmap(addr);
}
EXPORT_SYMBOL(pci_iounmap);

#endif /* CONFIG_GENERIC_IOMAP */

EXPORT_SYMBOL(PCIBIOS_MIN_IO);
EXPORT_SYMBOL(PCIBIOS_MIN_MEM);
