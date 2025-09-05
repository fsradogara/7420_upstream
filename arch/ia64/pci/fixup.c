// SPDX-License-Identifier: GPL-2.0
/*
 * Exceptions for specific devices. Usually work-arounds for fatal design flaws.
 * Derived from fixup.c of i386 tree.
 */

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/vgaarb.h>
#include <linux/screen_info.h>

#include <asm/machvec.h>

/*
 * Fixup to mark boot BIOS video selected by BIOS before it changes
 *
 * From information provided by "Jon Smirl" <jonsmirl@gmail.com>
 *
 * The standard boot ROM sequence for an x86 machine uses the BIOS
 * to select an initial video card for boot display. This boot video
 * card will have its BIOS copied to 0xC0000 in system RAM.
 * IORESOURCE_ROM_SHADOW is used to associate the boot video
 * card with this copy. On laptops this copy has to be used since
 * the main ROM may be compressed or combined with another image.
 * See pci_map_rom() for use of this flag. IORESOURCE_ROM_SHADOW
 * is marked here since the boot video device will be the only enabled
 * video device at this point.
 */

static void __devinit pci_fixup_video(struct pci_dev *pdev)
 * See pci_map_rom() for use of this flag. Before marking the device
 * with IORESOURCE_ROM_SHADOW check if a vga_default_device is already set
 * by either arch code or vga-arbitration; if so only apply the fixup to this
 * already-determined primary video card.
 */

static void pci_fixup_video(struct pci_dev *pdev)
{
	struct pci_dev *bridge;
	struct pci_bus *bus;
	u16 config;
	struct resource *res;

	if ((strcmp(platform_name, "dig") != 0)
	    && (strcmp(platform_name, "hpzx1")  != 0))
		return;
	/* Maybe, this machine supports legacy memory map. */

	if ((pdev->class >> 8) != PCI_CLASS_DISPLAY_VGA)
		return;

	if ((strcmp(ia64_platform_name, "dig") != 0)
	    && (strcmp(ia64_platform_name, "hpzx1")  != 0))
		return;
	/* Maybe, this machine supports legacy memory map. */

	/* Is VGA routed to us? */
	bus = pdev->bus;
	while (bus) {
		bridge = bus->self;

		/*
		 * From information provided by
		 * "David Miller" <davem@davemloft.net>
		 * The bridge control register is valid for PCI header
		 * type BRIDGE, or CARDBUS. Host to PCI controllers use
		 * PCI header type NORMAL.
		 */
		if (bridge
		    &&((bridge->hdr_type == PCI_HEADER_TYPE_BRIDGE)
		       ||(bridge->hdr_type == PCI_HEADER_TYPE_CARDBUS))) {
		if (bridge && (pci_is_bridge(bridge))) {
			pci_read_config_word(bridge, PCI_BRIDGE_CONTROL,
						&config);
			if (!(config & PCI_BRIDGE_CTL_VGA))
				return;
		}
		bus = bus->parent;
	}
	pci_read_config_word(pdev, PCI_COMMAND, &config);
	if (config & (PCI_COMMAND_IO | PCI_COMMAND_MEMORY)) {
		pdev->resource[PCI_ROM_RESOURCE].flags |= IORESOURCE_ROM_SHADOW;
		dev_printk(KERN_DEBUG, &pdev->dev, "Boot video device\n");
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_ANY_ID, PCI_ANY_ID, pci_fixup_video);
	if (!vga_default_device() || pdev == vga_default_device()) {
		pci_read_config_word(pdev, PCI_COMMAND, &config);
		if (config & (PCI_COMMAND_IO | PCI_COMMAND_MEMORY)) {
			res = &pdev->resource[PCI_ROM_RESOURCE];

			pci_disable_rom(pdev);
			if (res->parent)
				release_resource(res);

			res->start = 0xC0000;
			res->end = res->start + 0x20000 - 1;
			res->flags = IORESOURCE_MEM | IORESOURCE_ROM_SHADOW |
				     IORESOURCE_PCI_FIXED;
			dev_info(&pdev->dev, "Video device with shadowed ROM at %pR\n",
				 res);
		}
	}
}
DECLARE_PCI_FIXUP_CLASS_FINAL(PCI_ANY_ID, PCI_ANY_ID,
				PCI_CLASS_DISPLAY_VGA, 8, pci_fixup_video);
