#ifndef _POWERPC_PROM_H
#define _POWERPC_PROM_H
#ifdef __KERNEL__

/*
 * Definitions for talking to the Open Firmware PROM on
 * Power Macintosh computers.
 *
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 * Updates for PPC64 by Peter Bergner & David Engebretsen, IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/platform_device.h>
#include <asm/irq.h>
#include <asm/atomic.h>

#define OF_ROOT_NODE_ADDR_CELLS_DEFAULT	1
#define OF_ROOT_NODE_SIZE_CELLS_DEFAULT	1

#define of_compat_cmp(s1, s2, l)	strcasecmp((s1), (s2))
#define of_prop_cmp(s1, s2)		strcmp((s1), (s2))
#define of_node_cmp(s1, s2)		strcasecmp((s1), (s2))

/* Definitions used by the flattened device tree */
#define OF_DT_HEADER		0xd00dfeed	/* marker */
#include <asm/irq.h>
#include <linux/atomic.h>

/* These includes should be removed once implicit includes are cleaned up. */
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

#define OF_DT_BEGIN_NODE	0x1		/* Start of node, full name */
#define OF_DT_END_NODE		0x2		/* End node */
#define OF_DT_PROP		0x3		/* Property: name off, size,
						 * content */
#define OF_DT_NOP		0x4		/* nop */
#define OF_DT_END		0x9

#define OF_DT_VERSION		0x10

/*
 * This is what gets passed to the kernel by prom_init or kexec
 *
 * The dt struct contains the device tree structure, full pathes and
 * property contents. The dt strings contain a separate block with just
 * the strings for the property names, and is fully page aligned and
 * self contained in a page, so that it can be kept around by the kernel,
 * each property name appears only once in this page (cheap compression)
 *
 * the mem_rsvmap contains a map of reserved ranges of physical memory,
 * passing it here instead of in the device-tree itself greatly simplifies
 * the job of everybody. It's just a list of u64 pairs (base/size) that
 * ends when size is 0
 */
struct boot_param_header
{
	u32	magic;			/* magic word OF_DT_HEADER */
	u32	totalsize;		/* total size of DT block */
	u32	off_dt_struct;		/* offset to structure */
	u32	off_dt_strings;		/* offset to strings */
	u32	off_mem_rsvmap;		/* offset to memory reserve map */
	u32	version;		/* format version */
	u32	last_comp_version;	/* last compatible version */
	/* version 2 fields below */
	u32	boot_cpuid_phys;	/* Physical CPU id we're booting on */
	/* version 3 fields below */
	u32	dt_strings_size;	/* size of the DT strings block */
	/* version 17 fields below */
	u32	dt_struct_size;		/* size of the DT structure block */
};



typedef u32 phandle;
typedef u32 ihandle;

struct property {
	char	*name;
	int	length;
	void	*value;
	struct property *next;
};

struct device_node {
	const char *name;
	const char *type;
	phandle	node;
	phandle linux_phandle;
	char	*full_name;

	struct	property *properties;
	struct  property *deadprops; /* removed properties */
	struct	device_node *parent;
	struct	device_node *child;
	struct	device_node *sibling;
	struct	device_node *next;	/* next device of same type */
	struct	device_node *allnext;	/* next in list of all nodes */
	struct  proc_dir_entry *pde;	/* this node's proc directory */
	struct  kref kref;
	unsigned long _flags;
	void	*data;
};

extern struct device_node *of_chosen;

static inline int of_node_check_flag(struct device_node *n, unsigned long flag)
{
	return test_bit(flag, &n->_flags);
}

static inline void of_node_set_flag(struct device_node *n, unsigned long flag)
{
	set_bit(flag, &n->_flags);
}


#define HAVE_ARCH_DEVTREE_FIXUPS

static inline void set_node_proc_entry(struct device_node *dn, struct proc_dir_entry *de)
{
	dn->pde = de;
}


extern struct device_node *of_find_all_nodes(struct device_node *prev);
extern struct device_node *of_node_get(struct device_node *node);
extern void of_node_put(struct device_node *node);

/* For scanning the flat device-tree at boot time */
extern int __init of_scan_flat_dt(int (*it)(unsigned long node,
					    const char *uname, int depth,
					    void *data),
				  void *data);
extern void* __init of_get_flat_dt_prop(unsigned long node, const char *name,
					unsigned long *size);
extern int __init of_flat_dt_is_compatible(unsigned long node, const char *name);
extern unsigned long __init of_get_flat_dt_root(void);

/* For updating the device tree at runtime */
extern void of_attach_node(struct device_node *);
extern void of_detach_node(struct device_node *);

/* Other Prototypes */
extern void finish_device_tree(void);
extern void unflatten_device_tree(void);
extern void early_init_devtree(void *);
extern int machine_is_compatible(const char *compat);
extern void print_properties(struct device_node *node);
extern int prom_n_intr_cells(struct device_node* np);
extern void prom_get_irq_senses(unsigned char *senses, int off, int max);
extern int prom_add_property(struct device_node* np, struct property* prop);
extern int prom_remove_property(struct device_node *np, struct property *prop);
extern int prom_update_property(struct device_node *np,
				struct property *newprop,
				struct property *oldprop);

#ifdef CONFIG_PPC32
/*
 * PCI <-> OF matching functions
 * (XXX should these be here?)
 */
struct pci_bus;
struct pci_dev;
extern int pci_device_from_OF_node(struct device_node *node,
				   u8* bus, u8* devfn);
extern struct device_node* pci_busdev_to_OF_node(struct pci_bus *, int);
extern struct device_node* pci_device_to_OF_node(struct pci_dev *);
extern void pci_create_OF_bus_map(void);
#endif

extern struct resource *request_OF_resource(struct device_node* node,
				int index, const char* name_postfix);
extern int release_OF_resource(struct device_node* node, int index);


struct boot_param_header {
	__be32	magic;			/* magic word OF_DT_HEADER */
	__be32	totalsize;		/* total size of DT block */
	__be32	off_dt_struct;		/* offset to structure */
	__be32	off_dt_strings;		/* offset to strings */
	__be32	off_mem_rsvmap;		/* offset to memory reserve map */
	__be32	version;		/* format version */
	__be32	last_comp_version;	/* last compatible version */
	/* version 2 fields below */
	__be32	boot_cpuid_phys;	/* Physical CPU id we're booting on */
	/* version 3 fields below */
	__be32	dt_strings_size;	/* size of the DT strings block */
	/* version 17 fields below */
	__be32	dt_struct_size;		/* size of the DT structure block */
};

/*
 * OF address retreival & translation
 */


/* Helper to read a big number; size is in cells (not bytes) */
static inline u64 of_read_number(const u32 *cell, int size)
{
	u64 r = 0;
	while (size--)
		r = (r << 32) | *(cell++);
	return r;
}

/* Like of_read_number, but we want an unsigned long result */
#ifdef CONFIG_PPC32
static inline unsigned long of_read_ulong(const u32 *cell, int size)
{
	return cell[size-1];
}
#else
#define of_read_ulong(cell, size)	of_read_number(cell, size)
#endif

/* Translate an OF address block into a CPU physical address
 */
extern u64 of_translate_address(struct device_node *np, const u32 *addr);

/* Translate a DMA address from device space to CPU space */
extern u64 of_translate_dma_address(struct device_node *dev,
				    const u32 *in_addr);

/* Extract an address from a device, returns the region size and
 * the address space flags too. The PCI version uses a BAR number
 * instead of an absolute index
 */
extern const u32 *of_get_address(struct device_node *dev, int index,
			   u64 *size, unsigned int *flags);
#ifdef CONFIG_PCI
extern const u32 *of_get_pci_address(struct device_node *dev, int bar_no,
			       u64 *size, unsigned int *flags);
#else
static inline const u32 *of_get_pci_address(struct device_node *dev,
		int bar_no, u64 *size, unsigned int *flags)
{
	return NULL;
}
#endif /* CONFIG_PCI */

/* Get an address as a resource. Note that if your address is
 * a PIO address, the conversion will fail if the physical address
 * can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called to early
 * or it can't be matched to any host bridge IO space
 */
extern int of_address_to_resource(struct device_node *dev, int index,
				  struct resource *r);
#ifdef CONFIG_PCI
extern int of_pci_address_to_resource(struct device_node *dev, int bar,
				      struct resource *r);
#else
static inline int of_pci_address_to_resource(struct device_node *dev, int bar,
		struct resource *r)
{
	return -ENOSYS;
}
#endif /* CONFIG_PCI */

/* Parse the ibm,dma-window property of an OF node into the busno, phys and
 * size parameters.
 */
void of_parse_dma_window(struct device_node *dn, const void *dma_window_prop,
		unsigned long *busno, unsigned long *phys, unsigned long *size);

extern void kdump_move_device_tree(void);

/* CPU OF node matching */
struct device_node *of_get_cpu_node(int cpu, unsigned int *thread);

/* Get the MAC address */
extern const void *of_get_mac_address(struct device_node *np);

/*
 * OF interrupt mapping
 */

/* This structure is returned when an interrupt is mapped. The controller
 * field needs to be put() after use
 */

#define OF_MAX_IRQ_SPEC		 4 /* We handle specifiers of at most 4 cells */

struct of_irq {
	struct device_node *controller;	/* Interrupt controller node */
	u32 size;			/* Specifier size */
	u32 specifier[OF_MAX_IRQ_SPEC];	/* Specifier copy */
};

/**
 * of_irq_map_init - Initialize the irq remapper
 * @flags:	flags defining workarounds to enable
 *
 * Some machines have bugs in the device-tree which require certain workarounds
 * to be applied. Call this before any interrupt mapping attempts to enable
 * those workarounds.
 */
#define OF_IMAP_OLDWORLD_MAC	0x00000001
#define OF_IMAP_NO_PHANDLE	0x00000002

extern void of_irq_map_init(unsigned int flags);

/**
 * of_irq_map_raw - Low level interrupt tree parsing
 * @parent:	the device interrupt parent
 * @intspec:	interrupt specifier ("interrupts" property of the device)
 * @ointsize:   size of the passed in interrupt specifier
 * @addr:	address specifier (start of "reg" property of the device)
 * @out_irq:	structure of_irq filled by this function
 *
 * Returns 0 on success and a negative number on error
 *
 * This function is a low-level interrupt tree walking function. It
 * can be used to do a partial walk with synthetized reg and interrupts
 * properties, for example when resolving PCI interrupts when no device
 * node exist for the parent.
 *
 */

extern int of_irq_map_raw(struct device_node *parent, const u32 *intspec,
			  u32 ointsize, const u32 *addr,
			  struct of_irq *out_irq);


/**
 * of_irq_map_one - Resolve an interrupt for a device
 * @device:	the device whose interrupt is to be resolved
 * @index:     	index of the interrupt to resolve
 * @out_irq:	structure of_irq filled by this function
 *
 * This function resolves an interrupt, walking the tree, for a given
 * device-tree node. It's the high level pendant to of_irq_map_raw().
 * It also implements the workarounds for OldWolrd Macs.
 */
extern int of_irq_map_one(struct device_node *device, int index,
			  struct of_irq *out_irq);

/**
 * of_irq_map_pci - Resolve the interrupt for a PCI device
 * @pdev:	the device whose interrupt is to be resolved
 * @out_irq:	structure of_irq filled by this function
 *
 * This function resolves the PCI interrupt for a given PCI device. If a
 * device-node exists for a given pci_dev, it will use normal OF tree
 * walking. If not, it will implement standard swizzling and walk up the
 * PCI tree until an device-node is found, at which point it will finish
 * resolving using the OF tree walking.
 */
struct pci_dev;
extern int of_irq_map_pci(struct pci_dev *pdev, struct of_irq *out_irq);

extern int of_irq_to_resource(struct device_node *dev, int index,
			struct resource *r);

/**
 * of_iomap - Maps the memory mapped IO for a given device_node
 * @device:	the device whose io range will be mapped
 * @index:	index of the io range
 *
 * Returns a pointer to the mapped memory
 */
extern void __iomem *of_iomap(struct device_node *device, int index);

/*
 * NB:  This is here while we transition from using asm/prom.h
 * to linux/of.h
 */
#include <linux/of.h>
/* Parse the ibm,dma-window property of an OF node into the busno, phys and
 * size parameters.
 */
void of_parse_dma_window(struct device_node *dn, const __be32 *dma_window,
			 unsigned long *busno, unsigned long *phys,
			 unsigned long *size);

extern void of_instantiate_rtc(void);

extern int of_get_ibm_chip_id(struct device_node *np);

struct of_drc_info {
	char *drc_type;
	char *drc_name_prefix;
	u32 drc_index_start;
	u32 drc_name_suffix_start;
	u32 num_sequential_elems;
	u32 sequential_inc;
	u32 drc_power_domain;
	u32 last_drc_index;
};

extern int of_read_drc_info_cell(struct property **prop,
			const __be32 **curval, struct of_drc_info *data);


/*
 * There are two methods for telling firmware what our capabilities are.
 * Newer machines have an "ibm,client-architecture-support" method on the
 * root node.  For older machines, we have to call the "process-elf-header"
 * method in the /packages/elf-loader node, passing it a fake 32-bit
 * ELF header containing a couple of PT_NOTE sections that contain
 * structures that contain various information.
 */

/* New method - extensible architecture description vector. */

/* Option vector bits - generic bits in byte 1 */
#define OV_IGNORE		0x80	/* ignore this vector */
#define OV_CESSATION_POLICY	0x40	/* halt if unsupported option present*/

/* Option vector 1: processor architectures supported */
#define OV1_PPC_2_00		0x80	/* set if we support PowerPC 2.00 */
#define OV1_PPC_2_01		0x40	/* set if we support PowerPC 2.01 */
#define OV1_PPC_2_02		0x20	/* set if we support PowerPC 2.02 */
#define OV1_PPC_2_03		0x10	/* set if we support PowerPC 2.03 */
#define OV1_PPC_2_04		0x08	/* set if we support PowerPC 2.04 */
#define OV1_PPC_2_05		0x04	/* set if we support PowerPC 2.05 */
#define OV1_PPC_2_06		0x02	/* set if we support PowerPC 2.06 */
#define OV1_PPC_2_07		0x01	/* set if we support PowerPC 2.07 */

#define OV1_PPC_3_00		0x80	/* set if we support PowerPC 3.00 */

/* Option vector 2: Open Firmware options supported */
#define OV2_REAL_MODE		0x20	/* set if we want OF in real mode */

/* Option vector 3: processor options supported */
#define OV3_FP			0x80	/* floating point */
#define OV3_VMX			0x40	/* VMX/Altivec */
#define OV3_DFP			0x20	/* decimal FP */

/* Option vector 4: IBM PAPR implementation */
#define OV4_MIN_ENT_CAP		0x01	/* minimum VP entitled capacity */

/* Option vector 5: PAPR/OF options supported
 * These bits are also used in firmware_has_feature() to validate
 * the capabilities reported for vector 5 in the device tree so we
 * encode the vector index in the define and use the OV5_FEAT()
 * and OV5_INDX() macros to extract the desired information.
 */
#define OV5_FEAT(x)	((x) & 0xff)
#define OV5_INDX(x)	((x) >> 8)
#define OV5_LPAR		0x0280	/* logical partitioning supported */
#define OV5_SPLPAR		0x0240	/* shared-processor LPAR supported */
/* ibm,dynamic-reconfiguration-memory property supported */
#define OV5_DRCONF_MEMORY	0x0220
#define OV5_LARGE_PAGES		0x0210	/* large pages supported */
#define OV5_DONATE_DEDICATE_CPU	0x0202	/* donate dedicated CPU support */
#define OV5_MSI			0x0201	/* PCIe/MSI support */
#define OV5_CMO			0x0480	/* Cooperative Memory Overcommitment */
#define OV5_XCMO		0x0440	/* Page Coalescing */
#define OV5_TYPE1_AFFINITY	0x0580	/* Type 1 NUMA affinity */
#define OV5_PRRN		0x0540	/* Platform Resource Reassignment */
#define OV5_HP_EVT		0x0604	/* Hot Plug Event support */
#define OV5_RESIZE_HPT		0x0601	/* Hash Page Table resizing */
#define OV5_PFO_HW_RNG		0x1180	/* PFO Random Number Generator */
#define OV5_PFO_HW_842		0x1140	/* PFO Compression Accelerator */
#define OV5_PFO_HW_ENCR		0x1120	/* PFO Encryption Accelerator */
#define OV5_SUB_PROCESSORS	0x1501	/* 1,2,or 4 Sub-Processors supported */
#define OV5_DRMEM_V2		0x1680	/* ibm,dynamic-reconfiguration-v2 */
#define OV5_XIVE_SUPPORT	0x17C0	/* XIVE Exploitation Support Mask */
#define OV5_XIVE_LEGACY		0x1700	/* XIVE legacy mode Only */
#define OV5_XIVE_EXPLOIT	0x1740	/* XIVE exploitation mode Only */
#define OV5_XIVE_EITHER		0x1780	/* XIVE legacy or exploitation mode */
/* MMU Base Architecture */
#define OV5_MMU_SUPPORT		0x18C0	/* MMU Mode Support Mask */
#define OV5_MMU_HASH		0x1800	/* Hash MMU Only */
#define OV5_MMU_RADIX		0x1840	/* Radix MMU Only */
#define OV5_MMU_EITHER		0x1880	/* Hash or Radix Supported */
#define OV5_MMU_DYNAMIC		0x18C0	/* Hash or Radix Can Switch Later */
#define OV5_NMMU		0x1820	/* Nest MMU Available */
/* Hash Table Extensions */
#define OV5_HASH_SEG_TBL	0x1980	/* In Memory Segment Tables Available */
#define OV5_HASH_GTSE		0x1940	/* Guest Translation Shoot Down Avail */
/* Radix Table Extensions */
#define OV5_RADIX_GTSE		0x1A40	/* Guest Translation Shoot Down Avail */
#define OV5_DRC_INFO		0x1640	/* Redef Prop Structures: drc-info   */

/* Option Vector 6: IBM PAPR hints */
#define OV6_LINUX		0x02	/* Linux is our OS */

#endif /* __KERNEL__ */
#endif /* _POWERPC_PROM_H */
