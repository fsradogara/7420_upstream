// SPDX-License-Identifier: GPL-2.0
/*
 * File:	portdrv_core.c
 * Purpose:	PCI Express Port Bus Driver's Core Functions
 *
 * Copyright (C) 2004 Intel
 * Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/pcieport_if.h>

#include "portdrv.h"

extern int pcie_mch_quirk;	/* MSI-quirk Indicator */

static int pcie_port_probe_service(struct device *dev)
{
	struct pcie_device *pciedev;
	struct pcie_port_service_driver *driver;
	int status;

	if (!dev || !dev->driver)
		return -ENODEV;

 	driver = to_service_driver(dev->driver);
	if (!driver || !driver->probe)
		return -ENODEV;

	pciedev = to_pcie_device(dev);
	status = driver->probe(pciedev, driver->id_table);
	if (!status) {
		dev_printk(KERN_DEBUG, dev, "service driver %s loaded\n",
			driver->name);
		get_device(dev);
	}
	return status;
}

static int pcie_port_remove_service(struct device *dev)
{
	struct pcie_device *pciedev;
	struct pcie_port_service_driver *driver;

	if (!dev || !dev->driver)
		return 0;

	pciedev = to_pcie_device(dev);
 	driver = to_service_driver(dev->driver);
	if (driver && driver->remove) { 
		dev_printk(KERN_DEBUG, dev, "unloading service driver %s\n",
			driver->name);
		driver->remove(pciedev);
		put_device(dev);
	}
	return 0;
}

static void pcie_port_shutdown_service(struct device *dev) {}

static int pcie_port_suspend_service(struct device *dev, pm_message_t state)
{
	struct pcie_device *pciedev;
	struct pcie_port_service_driver *driver;

	if (!dev || !dev->driver)
		return 0;

	pciedev = to_pcie_device(dev);
 	driver = to_service_driver(dev->driver);
	if (driver && driver->suspend)
		driver->suspend(pciedev, state);
	return 0;
}

static int pcie_port_resume_service(struct device *dev)
{
	struct pcie_device *pciedev;
	struct pcie_port_service_driver *driver;

	if (!dev || !dev->driver)
		return 0;

	pciedev = to_pcie_device(dev);
 	driver = to_service_driver(dev->driver);

	if (driver && driver->resume)
		driver->resume(pciedev);
	return 0;
}

/*
 * release_pcie_device
 *	
 *	Being invoked automatically when device is being removed 
 *	in response to device_unregister(dev) call.
 *	Release all resources being claimed.
 */
static void release_pcie_device(struct device *dev)
{
	dev_printk(KERN_DEBUG, dev, "free port service\n");
	kfree(to_pcie_device(dev));			
}

static int is_msi_quirked(struct pci_dev *dev)
{
	int port_type, quirk = 0;
	u16 reg16;

	pci_read_config_word(dev, 
		pci_find_capability(dev, PCI_CAP_ID_EXP) + 
		PCIE_CAPABILITIES_REG, &reg16);
	port_type = (reg16 >> 4) & PORT_TYPE_MASK;
	switch(port_type) {
	case PCIE_RC_PORT:
		if (pcie_mch_quirk == 1)
			quirk = 1;
		break;
	case PCIE_SW_UPSTREAM_PORT:
	case PCIE_SW_DOWNSTREAM_PORT:
	default:
		break;	
	}
	return quirk;
}
	
static int assign_interrupt_mode(struct pci_dev *dev, int *vectors, int mask)
{
	int i, pos, nvec, status = -EINVAL;
	int interrupt_mode = PCIE_PORT_INTx_MODE;

	/* Set INTx as default */
	for (i = 0, nvec = 0; i < PCIE_PORT_DEVICE_MAXSERVICES; i++) {
		if (mask & (1 << i)) 
			nvec++;
		vectors[i] = dev->irq;
	}
	
	/* Check MSI quirk */
	if (is_msi_quirked(dev))
		return interrupt_mode;

	/* Select MSI-X over MSI if supported */		
	pos = pci_find_capability(dev, PCI_CAP_ID_MSIX);
	if (pos) {
		struct msix_entry msix_entries[PCIE_PORT_DEVICE_MAXSERVICES] = 
			{{0, 0}, {0, 1}, {0, 2}, {0, 3}};
		dev_info(&dev->dev, "found MSI-X capability\n");
		status = pci_enable_msix(dev, msix_entries, nvec);
		if (!status) {
			int j = 0;

			interrupt_mode = PCIE_PORT_MSIX_MODE;
			for (i = 0; i < PCIE_PORT_DEVICE_MAXSERVICES; i++) {
				if (mask & (1 << i)) 
					vectors[i] = msix_entries[j++].vector;
			}
		}
	} 
	if (status) {
		pos = pci_find_capability(dev, PCI_CAP_ID_MSI);
		if (pos) {
			dev_info(&dev->dev, "found MSI capability\n");
			status = pci_enable_msi(dev);
			if (!status) {
				interrupt_mode = PCIE_PORT_MSI_MODE;
				for (i = 0;i < PCIE_PORT_DEVICE_MAXSERVICES;i++)
					vectors[i] = dev->irq;
			}
		}
	} 
	return interrupt_mode;
}

static int get_port_device_capability(struct pci_dev *dev)
{
	int services = 0, pos;
	u16 reg16;
	u32 reg32;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	pci_read_config_word(dev, pos + PCIE_CAPABILITIES_REG, &reg16);
	/* Hot-Plug Capable */
	if (reg16 & PORT_TO_SLOT_MASK) {
		pci_read_config_dword(dev, 
			pos + PCIE_SLOT_CAPABILITIES_REG, &reg32);
		if (reg32 & SLOT_HP_CAPABLE_MASK)
			services |= PCIE_PORT_SERVICE_HP;
	} 
	/* PME Capable - root port capability */
	if (((reg16 >> 4) & PORT_TYPE_MASK) == PCIE_RC_PORT)
		services |= PCIE_PORT_SERVICE_PME;
	
	pos = PCI_CFG_SPACE_SIZE;
	while (pos) {
		pci_read_config_dword(dev, pos, &reg32);
		switch (reg32 & 0xffff) {
		case PCI_EXT_CAP_ID_ERR:
			services |= PCIE_PORT_SERVICE_AER;
			pos = reg32 >> 20;
			break;
		case PCI_EXT_CAP_ID_VC:
			services |= PCIE_PORT_SERVICE_VC;
			pos = reg32 >> 20;
			break;
		default:
			pos = 0;
			break;
		}
	}
#include <linux/aer.h>

#include "../pci.h"
#include "portdrv.h"

bool pciehp_msi_disabled;

static int __init pciehp_setup(char *str)
{
	if (!strncmp(str, "nomsi", 5))
		pciehp_msi_disabled = true;

	return 1;
}
__setup("pcie_hp=", pciehp_setup);

/**
 * release_pcie_device - free PCI Express port service device structure
 * @dev: Port service device to release
 *
 * Invoked automatically when device is being removed in response to
 * device_unregister(dev).  Release all resources being claimed.
 */
static void release_pcie_device(struct device *dev)
{
	kfree(to_pcie_device(dev));
}

/**
 * pcie_port_enable_irq_vec - try to set up MSI-X or MSI as interrupt mode
 * for given port
 * @dev: PCI Express port to handle
 * @irqs: Array of interrupt vectors to populate
 * @mask: Bitmask of port capabilities returned by get_port_device_capability()
 *
 * Return value: 0 on success, error code on failure
 */
static int pcie_port_enable_irq_vec(struct pci_dev *dev, int *irqs, int mask)
{
	int nr_entries, entry, nvec = 0;

	/*
	 * Allocate as many entries as the port wants, so that we can check
	 * which of them will be useful.  Moreover, if nr_entries is correctly
	 * equal to the number of entries this port actually uses, we'll happily
	 * go through without any tricks.
	 */
	nr_entries = pci_alloc_irq_vectors(dev, 1, PCIE_PORT_MAX_MSI_ENTRIES,
			PCI_IRQ_MSIX | PCI_IRQ_MSI);
	if (nr_entries < 0)
		return nr_entries;

	if (mask & (PCIE_PORT_SERVICE_PME | PCIE_PORT_SERVICE_HP)) {
		u16 reg16;

		/*
		 * Per PCIe r3.1, sec 6.1.6, "PME and Hot-Plug Event
		 * interrupts (when both are implemented) always share the
		 * same MSI or MSI-X vector, as indicated by the Interrupt
		 * Message Number field in the PCI Express Capabilities
		 * register".
		 *
		 * Per sec 7.8.2, "For MSI, the [Interrupt Message Number]
		 * indicates the offset between the base Message Data and
		 * the interrupt message that is generated."
		 *
		 * "For MSI-X, the [Interrupt Message Number] indicates
		 * which MSI-X Table entry is used to generate the
		 * interrupt message."
		 */
		pcie_capability_read_word(dev, PCI_EXP_FLAGS, &reg16);
		entry = (reg16 & PCI_EXP_FLAGS_IRQ) >> 9;
		if (entry >= nr_entries)
			goto out_free_irqs;

		irqs[PCIE_PORT_SERVICE_PME_SHIFT] = pci_irq_vector(dev, entry);
		irqs[PCIE_PORT_SERVICE_HP_SHIFT] = pci_irq_vector(dev, entry);

		nvec = max(nvec, entry + 1);
	}

	if (mask & PCIE_PORT_SERVICE_AER) {
		u32 reg32, pos;

		/*
		 * Per PCIe r3.1, sec 7.10.10, the Advanced Error Interrupt
		 * Message Number in the Root Error Status register
		 * indicates which MSI/MSI-X vector is used for AER.
		 *
		 * "For MSI, the [Advanced Error Interrupt Message Number]
		 * indicates the offset between the base Message Data and
		 * the interrupt message that is generated."
		 *
		 * "For MSI-X, the [Advanced Error Interrupt Message
		 * Number] indicates which MSI-X Table entry is used to
		 * generate the interrupt message."
		 */
		pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ERR);
		pci_read_config_dword(dev, pos + PCI_ERR_ROOT_STATUS, &reg32);
		entry = reg32 >> 27;
		if (entry >= nr_entries)
			goto out_free_irqs;

		irqs[PCIE_PORT_SERVICE_AER_SHIFT] = pci_irq_vector(dev, entry);

		nvec = max(nvec, entry + 1);
	}

	if (mask & PCIE_PORT_SERVICE_DPC) {
		u16 reg16, pos;

		/*
		 * Per PCIe r4.0 (v0.9), sec 7.9.15.2, the DPC Interrupt
		 * Message Number in the DPC Capability register indicates
		 * which MSI/MSI-X vector is used for DPC.
		 *
		 * "For MSI, the [DPC Interrupt Message Number] indicates
		 * the offset between the base Message Data and the
		 * interrupt message that is generated."
		 *
		 * "For MSI-X, the [DPC Interrupt Message Number] indicates
		 * which MSI-X Table entry is used to generate the
		 * interrupt message."
		 */
		pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_DPC);
		pci_read_config_word(dev, pos + PCI_EXP_DPC_CAP, &reg16);
		entry = reg16 & 0x1f;
		if (entry >= nr_entries)
			goto out_free_irqs;

		irqs[PCIE_PORT_SERVICE_DPC_SHIFT] = pci_irq_vector(dev, entry);

		nvec = max(nvec, entry + 1);
	}

	/*
	 * If nvec is equal to the allocated number of entries, we can just use
	 * what we have.  Otherwise, the port has some extra entries not for the
	 * services we know and we need to work around that.
	 */
	if (nvec != nr_entries) {
		/* Drop the temporary MSI-X setup */
		pci_free_irq_vectors(dev);

		/* Now allocate the MSI-X vectors for real */
		nr_entries = pci_alloc_irq_vectors(dev, nvec, nvec,
				PCI_IRQ_MSIX | PCI_IRQ_MSI);
		if (nr_entries < 0)
			return nr_entries;
	}

	return 0;

out_free_irqs:
	pci_free_irq_vectors(dev);
	return -EIO;
}

/**
 * pcie_init_service_irqs - initialize irqs for PCI Express port services
 * @dev: PCI Express port to handle
 * @irqs: Array of irqs to populate
 * @mask: Bitmask of port capabilities returned by get_port_device_capability()
 *
 * Return value: Interrupt mode associated with the port
 */
static int pcie_init_service_irqs(struct pci_dev *dev, int *irqs, int mask)
{
	int ret, i;

	for (i = 0; i < PCIE_PORT_DEVICE_MAXSERVICES; i++)
		irqs[i] = -1;

	/*
	 * If we support PME or hotplug, but we can't use MSI/MSI-X for
	 * them, we have to fall back to INTx or other interrupts, e.g., a
	 * system shared interrupt.
	 */
	if ((mask & PCIE_PORT_SERVICE_PME) && pcie_pme_no_msi())
		goto legacy_irq;

	if ((mask & PCIE_PORT_SERVICE_HP) && pciehp_no_msi())
		goto legacy_irq;

	/* Try to use MSI-X or MSI if supported */
	if (pcie_port_enable_irq_vec(dev, irqs, mask) == 0)
		return 0;

legacy_irq:
	/* fall back to legacy IRQ */
	ret = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_LEGACY);
	if (ret < 0)
		return -ENODEV;

	for (i = 0; i < PCIE_PORT_DEVICE_MAXSERVICES; i++) {
		if (i != PCIE_PORT_SERVICE_VC_SHIFT)
			irqs[i] = pci_irq_vector(dev, 0);
	}

	return 0;
}

/**
 * get_port_device_capability - discover capabilities of a PCI Express port
 * @dev: PCI Express port to examine
 *
 * The capabilities are read from the port's PCI Express configuration registers
 * as described in PCI Express Base Specification 1.0a sections 7.8.2, 7.8.9 and
 * 7.9 - 7.11.
 *
 * Return value: Bitmask of discovered port capabilities
 */
static int get_port_device_capability(struct pci_dev *dev)
{
	int services = 0;
	int cap_mask = 0;

	if (pcie_ports_disabled)
		return 0;

	cap_mask = PCIE_PORT_SERVICE_PME | PCIE_PORT_SERVICE_HP
			| PCIE_PORT_SERVICE_VC | PCIE_PORT_SERVICE_DPC;
	if (pci_aer_available())
		cap_mask |= PCIE_PORT_SERVICE_AER;

	if (pcie_ports_auto)
		pcie_port_platform_notify(dev, &cap_mask);

	/* Hot-Plug Capable */
	if ((cap_mask & PCIE_PORT_SERVICE_HP) && dev->is_hotplug_bridge) {
		services |= PCIE_PORT_SERVICE_HP;
		/*
		 * Disable hot-plug interrupts in case they have been enabled
		 * by the BIOS and the hot-plug service driver is not loaded.
		 */
		pcie_capability_clear_word(dev, PCI_EXP_SLTCTL,
			  PCI_EXP_SLTCTL_CCIE | PCI_EXP_SLTCTL_HPIE);
	}
	/* AER capable */
	if ((cap_mask & PCIE_PORT_SERVICE_AER)
	    && pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ERR)) {
		services |= PCIE_PORT_SERVICE_AER;
		/*
		 * Disable AER on this port in case it's been enabled by the
		 * BIOS (the AER service driver will enable it when necessary).
		 */
		pci_disable_pcie_error_reporting(dev);
	}
	/* VC support */
	if (pci_find_ext_capability(dev, PCI_EXT_CAP_ID_VC))
		services |= PCIE_PORT_SERVICE_VC;
	/* Root ports are capable of generating PME too */
	if ((cap_mask & PCIE_PORT_SERVICE_PME)
	    && pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT) {
		services |= PCIE_PORT_SERVICE_PME;
		/*
		 * Disable PME interrupt on this port in case it's been enabled
		 * by the BIOS (the PME service driver will enable it when
		 * necessary).
		 */
		pcie_pme_interrupt_enable(dev, false);
	}
	if (pci_find_ext_capability(dev, PCI_EXT_CAP_ID_DPC))
		services |= PCIE_PORT_SERVICE_DPC;

	return services;
}

static void pcie_device_init(struct pci_dev *parent, struct pcie_device *dev, 
	int port_type, int service_type, int irq, int irq_mode)
{
	struct device *device;

	dev->port = parent;
	dev->interrupt_mode = irq_mode;
	dev->irq = irq;
	dev->id.vendor = parent->vendor;
	dev->id.device = parent->device;
	dev->id.port_type = port_type;
	dev->id.service_type = (1 << service_type);

	/* Initialize generic device interface */
	device = &dev->device;
	memset(device, 0, sizeof(struct device));
	device->bus = &pcie_port_bus_type;
	device->driver = NULL;
	device->driver_data = NULL;
	device->release = release_pcie_device;	/* callback to free pcie dev */
	snprintf(device->bus_id, sizeof(device->bus_id), "%s:pcie%02x",
		 pci_name(parent), get_descriptor_id(port_type, service_type));
	device->parent = &parent->dev;
}

static struct pcie_device* alloc_pcie_device(struct pci_dev *parent,
	int port_type, int service_type, int irq, int irq_mode)
{
	struct pcie_device *device;

	device = kzalloc(sizeof(struct pcie_device), GFP_KERNEL);
	if (!device)
		return NULL;

	pcie_device_init(parent, device, port_type, service_type, irq,irq_mode);
	dev_printk(KERN_DEBUG, &device->device, "allocate port service\n");
	return device;
}

int pcie_port_device_probe(struct pci_dev *dev)
{
	int pos, type;
	u16 reg;

	if (!(pos = pci_find_capability(dev, PCI_CAP_ID_EXP)))
		return -ENODEV;

	pci_read_config_word(dev, pos + PCIE_CAPABILITIES_REG, &reg);
	type = (reg >> 4) & PORT_TYPE_MASK;
	if (	type == PCIE_RC_PORT || type == PCIE_SW_UPSTREAM_PORT ||
		type == PCIE_SW_DOWNSTREAM_PORT )
		return 0;

	return -ENODEV;
}

int pcie_port_device_register(struct pci_dev *dev)
{
	struct pcie_port_device_ext *p_ext;
	int status, type, capabilities, irq_mode, i;
	int vectors[PCIE_PORT_DEVICE_MAXSERVICES];
	u16 reg16;

	/* Allocate port device extension */
	if (!(p_ext = kmalloc(sizeof(struct pcie_port_device_ext), GFP_KERNEL)))
		return -ENOMEM;

	pci_set_drvdata(dev, p_ext);

	/* Get port type */
	pci_read_config_word(dev,
		pci_find_capability(dev, PCI_CAP_ID_EXP) +
		PCIE_CAPABILITIES_REG, &reg16);
	type = (reg16 >> 4) & PORT_TYPE_MASK;

	/* Now get port services */
	capabilities = get_port_device_capability(dev);
	irq_mode = assign_interrupt_mode(dev, vectors, capabilities);
	p_ext->interrupt_mode = irq_mode;

	/* Allocate child services if any */
	for (i = 0; i < PCIE_PORT_DEVICE_MAXSERVICES; i++) {
		struct pcie_device *child;

		if (capabilities & (1 << i)) {
			child = alloc_pcie_device(
				dev, 		/* parent */
				type,		/* port type */
				i,		/* service type */
				vectors[i],	/* irq */
				irq_mode	/* interrupt mode */);
			if (child) {
				status = device_register(&child->device);
				if (status) {
					kfree(child);
					continue;
				}
				get_device(&child->device);
			}
		}
	}
	return 0;
/**
 * pcie_device_init - allocate and initialize PCI Express port service device
 * @pdev: PCI Express port to associate the service device with
 * @service: Type of service to associate with the service device
 * @irq: Interrupt vector to associate with the service device
 */
static int pcie_device_init(struct pci_dev *pdev, int service, int irq)
{
	int retval;
	struct pcie_device *pcie;
	struct device *device;

	pcie = kzalloc(sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;
	pcie->port = pdev;
	pcie->irq = irq;
	pcie->service = service;

	/* Initialize generic device interface */
	device = &pcie->device;
	device->bus = &pcie_port_bus_type;
	device->release = release_pcie_device;	/* callback to free pcie dev */
	dev_set_name(device, "%s:pcie%03x",
		     pci_name(pdev),
		     get_descriptor_id(pci_pcie_type(pdev), service));
	device->parent = &pdev->dev;
	device_enable_async_suspend(device);

	retval = device_register(device);
	if (retval) {
		put_device(device);
		return retval;
	}

	pm_runtime_no_callbacks(device);

	return 0;
}

/**
 * pcie_port_device_register - register PCI Express port
 * @dev: PCI Express port to register
 *
 * Allocate the port extension structure and register services associated with
 * the port.
 */
int pcie_port_device_register(struct pci_dev *dev)
{
	int status, capabilities, i, nr_service;
	int irqs[PCIE_PORT_DEVICE_MAXSERVICES];

	/* Enable PCI Express port device */
	status = pci_enable_device(dev);
	if (status)
		return status;

	/* Get and check PCI Express port services */
	capabilities = get_port_device_capability(dev);
	if (!capabilities)
		return 0;

	pci_set_master(dev);
	/*
	 * Initialize service irqs. Don't use service devices that
	 * require interrupts if there is no way to generate them.
	 * However, some drivers may have a polling mode (e.g. pciehp_poll_mode)
	 * that can be used in the absence of irqs.  Allow them to determine
	 * if that is to be used.
	 */
	status = pcie_init_service_irqs(dev, irqs, capabilities);
	if (status) {
		capabilities &= PCIE_PORT_SERVICE_VC | PCIE_PORT_SERVICE_HP;
		if (!capabilities)
			goto error_disable;
	}

	/* Allocate child services if any */
	status = -ENODEV;
	nr_service = 0;
	for (i = 0; i < PCIE_PORT_DEVICE_MAXSERVICES; i++) {
		int service = 1 << i;
		if (!(capabilities & service))
			continue;
		if (!pcie_device_init(dev, service, irqs[i]))
			nr_service++;
	}
	if (!nr_service)
		goto error_cleanup_irqs;

	return 0;

error_cleanup_irqs:
	pci_free_irq_vectors(dev);
error_disable:
	pci_disable_device(dev);
	return status;
}

#ifdef CONFIG_PM
static int suspend_iter(struct device *dev, void *data)
{
	struct pcie_port_service_driver *service_driver;
	pm_message_t state = * (pm_message_t *) data;

 	if ((dev->bus == &pcie_port_bus_type) &&
 	    (dev->driver)) {
 		service_driver = to_service_driver(dev->driver);
 		if (service_driver->suspend)
 			service_driver->suspend(to_pcie_device(dev), state);
  	}
	return 0;
}

int pcie_port_device_suspend(struct pci_dev *dev, pm_message_t state)
{
	return device_for_each_child(&dev->dev, &state, suspend_iter);

	if ((dev->bus == &pcie_port_bus_type) && dev->driver) {
		service_driver = to_service_driver(dev->driver);
		if (service_driver->suspend)
			service_driver->suspend(to_pcie_device(dev));
	}
	return 0;
}

/**
 * pcie_port_device_suspend - suspend port services associated with a PCIe port
 * @dev: PCI Express port to handle
 */
int pcie_port_device_suspend(struct device *dev)
{
	return device_for_each_child(dev, NULL, suspend_iter);
}

static int resume_iter(struct device *dev, void *data)
{
	struct pcie_port_service_driver *service_driver;

	if ((dev->bus == &pcie_port_bus_type) &&
	    (dev->driver)) {
		service_driver = to_service_driver(dev->driver);
		if (service_driver->resume)
			service_driver->resume(to_pcie_device(dev));
	}
	return 0;
}

int pcie_port_device_resume(struct pci_dev *dev)
{
	return device_for_each_child(&dev->dev, NULL, resume_iter);
}
#endif

static int remove_iter(struct device *dev, void *data)
{
	struct pcie_port_service_driver *service_driver;

	if (dev->bus == &pcie_port_bus_type) {
		if (dev->driver) {
			service_driver = to_service_driver(dev->driver);
			if (service_driver->remove)
				service_driver->remove(to_pcie_device(dev));
		}
		*(unsigned long*)data = (unsigned long)dev;
		return 1;
/**
 * pcie_port_device_resume - resume port services associated with a PCIe port
 * @dev: PCI Express port to handle
 */
int pcie_port_device_resume(struct device *dev)
{
	return device_for_each_child(dev, NULL, resume_iter);
}
#endif /* PM */

static int remove_iter(struct device *dev, void *data)
{
	if (dev->bus == &pcie_port_bus_type)
		device_unregister(dev);
	return 0;
}

/**
 * pcie_port_device_remove - unregister PCI Express port service devices
 * @dev: PCI Express port the service devices to unregister are associated with
 *
 * Remove PCI Express port service devices associated with given port and
 * disable MSI-X or MSI for the port.
 */
void pcie_port_device_remove(struct pci_dev *dev)
{
	device_for_each_child(&dev->dev, NULL, remove_iter);
	pci_free_irq_vectors(dev);
	pci_disable_device(dev);
}

/**
 * pcie_port_probe_service - probe driver for given PCI Express port service
 * @dev: PCI Express port service device to probe against
 *
 * If PCI Express port service driver is registered with
 * pcie_port_service_register(), this function will be called by the driver core
 * whenever match is found between the driver and a port service device.
 */
static int pcie_port_probe_service(struct device *dev)
{
	struct pcie_device *pciedev;
	struct pcie_port_service_driver *driver;
	int status;

	if (!dev || !dev->driver)
		return -ENODEV;

	driver = to_service_driver(dev->driver);
	if (!driver || !driver->probe)
		return -ENODEV;

	pciedev = to_pcie_device(dev);
	status = driver->probe(pciedev);
	if (status)
		return status;

	get_device(dev);
	return 0;
}

/**
 * pcie_port_remove_service - detach driver from given PCI Express port service
 * @dev: PCI Express port service device to handle
 *
 * If PCI Express port service driver is registered with
 * pcie_port_service_register(), this function will be called by the driver core
 * when device_unregister() is called for the port service device associated
 * with the driver.
 */
static int pcie_port_remove_service(struct device *dev)
{
	struct pcie_device *pciedev;
	struct pcie_port_service_driver *driver;

	if (!dev || !dev->driver)
		return 0;

	pciedev = to_pcie_device(dev);
	driver = to_service_driver(dev->driver);
	if (driver && driver->remove) {
		driver->remove(pciedev);
		put_device(dev);
	}
	return 0;
}

void pcie_port_device_remove(struct pci_dev *dev)
{
	struct device *device;
	unsigned long device_addr;
	int interrupt_mode = PCIE_PORT_INTx_MODE;
	int status;

	do {
		status = device_for_each_child(&dev->dev, &device_addr, remove_iter);
		if (status) {
			device = (struct device*)device_addr;
			interrupt_mode = (to_pcie_device(device))->interrupt_mode;
			put_device(device);
			device_unregister(device);
		}
	} while (status);
	/* Switch to INTx by default if MSI enabled */
	if (interrupt_mode == PCIE_PORT_MSIX_MODE)
		pci_disable_msix(dev);
	else if (interrupt_mode == PCIE_PORT_MSI_MODE)
		pci_disable_msi(dev);
}

int pcie_port_bus_register(void)
{
	return bus_register(&pcie_port_bus_type);
}

void pcie_port_bus_unregister(void)
{
	bus_unregister(&pcie_port_bus_type);
}

int pcie_port_service_register(struct pcie_port_service_driver *new)
{
	new->driver.name = (char *)new->name;
/**
 * pcie_port_shutdown_service - shut down given PCI Express port service
 * @dev: PCI Express port service device to handle
 *
 * If PCI Express port service driver is registered with
 * pcie_port_service_register(), this function will be called by the driver core
 * when device_shutdown() is called for the port service device associated
 * with the driver.
 */
static void pcie_port_shutdown_service(struct device *dev) {}

/**
 * pcie_port_service_register - register PCI Express port service driver
 * @new: PCI Express port service driver to register
 */
int pcie_port_service_register(struct pcie_port_service_driver *new)
{
	if (pcie_ports_disabled)
		return -ENODEV;

	new->driver.name = new->name;
	new->driver.bus = &pcie_port_bus_type;
	new->driver.probe = pcie_port_probe_service;
	new->driver.remove = pcie_port_remove_service;
	new->driver.shutdown = pcie_port_shutdown_service;
	new->driver.suspend = pcie_port_suspend_service;
	new->driver.resume = pcie_port_resume_service;

	return driver_register(&new->driver);
}

void pcie_port_service_unregister(struct pcie_port_service_driver *new)
{
	driver_unregister(&new->driver);
}

EXPORT_SYMBOL(pcie_port_service_register);

	return driver_register(&new->driver);
}
EXPORT_SYMBOL(pcie_port_service_register);

/**
 * pcie_port_service_unregister - unregister PCI Express port service driver
 * @drv: PCI Express port service driver to unregister
 */
void pcie_port_service_unregister(struct pcie_port_service_driver *drv)
{
	driver_unregister(&drv->driver);
}
EXPORT_SYMBOL(pcie_port_service_unregister);
