/*
 * 
 * Common boot and setup code.
 *
 * Copyright (C) 2001 PPC64 Team, IBM Corp
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#undef DEBUG

#include <linux/module.h>
#define DEBUG

#include <linux/export.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/initrd.h>
#include <linux/seq_file.h>
#include <linux/ioport.h>
#include <linux/console.h>
#include <linux/utsname.h>
#include <linux/tty.h>
#include <linux/root_dev.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/unistd.h>
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <linux/bootmem.h>
#include <linux/pci.h>
#include <linux/lockdep.h>
#include <linux/lmb.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/nmi.h>

#include <asm/debugfs.h>
#include <asm/io.h>
#include <asm/kdump.h>
#include <asm/prom.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/smp.h>
#include <asm/elf.h>
#include <asm/machdep.h>
#include <asm/paca.h>
#include <asm/time.h>
#include <asm/cputable.h>
#include <asm/dt_cpu_ftrs.h>
#include <asm/sections.h>
#include <asm/btext.h>
#include <asm/nvram.h>
#include <asm/setup.h>
#include <asm/system.h>
#include <asm/rtas.h>
#include <asm/iommu.h>
#include <asm/serial.h>
#include <asm/cache.h>
#include <asm/page.h>
#include <asm/mmu.h>
#include <asm/firmware.h>
#include <asm/xmon.h>
#include <asm/udbg.h>
#include <asm/kexec.h>

#include "setup.h"
#include <asm/mmu_context.h>
#include <asm/code-patching.h>
#include <asm/livepatch.h>
#include <asm/opal.h>
#include <asm/cputhreads.h>
#include <asm/hw_irq.h>
#include <asm/feature-fixups.h>

#include "setup.h"

#ifdef DEBUG
#define DBG(fmt...) udbg_printf(fmt)
#else
#define DBG(fmt...)
#endif

int have_of = 1;
int boot_cpuid = 0;
int spinning_secondaries;
u64 ppc64_pft_size;

struct ppc64_caches ppc64_caches = {
	.l1d = {
		.block_size = 0x40,
		.log_block_size = 6,
	},
	.l1i = {
		.block_size = 0x40,
		.log_block_size = 6
	},
};
EXPORT_SYMBOL_GPL(ppc64_caches);

/*
 * These are used in binfmt_elf.c to put aux entries on the stack
 * for each elf executable being started.
 */
int dcache_bsize;
int icache_bsize;
int ucache_bsize;

#ifdef CONFIG_SMP

static int smt_enabled_cmdline;
#if defined(CONFIG_PPC_BOOK3E) && defined(CONFIG_SMP)
void __init setup_tlb_core_data(void)
{
	int cpu;

	BUILD_BUG_ON(offsetof(struct tlb_core_data, lock) != 0);

	for_each_possible_cpu(cpu) {
		int first = cpu_first_thread_sibling(cpu);

		/*
		 * If we boot via kdump on a non-primary thread,
		 * make sure we point at the thread that actually
		 * set up this TLB.
		 */
		if (cpu_first_thread_sibling(boot_cpuid) == first)
			first = boot_cpuid;

		paca_ptrs[cpu]->tcd_ptr = &paca_ptrs[first]->tcd;

		/*
		 * If we have threads, we need either tlbsrx.
		 * or e6500 tablewalk mode, or else TLB handlers
		 * will be racy and could produce duplicate entries.
		 * Should we panic instead?
		 */
		WARN_ONCE(smt_enabled_at_boot >= 2 &&
			  !mmu_has_feature(MMU_FTR_USE_TLBRSRV) &&
			  book3e_htw_mode != PPC_HTW_E6500,
			  "%s: unsupported MMU configuration\n", __func__);
	}
}
#endif

#ifdef CONFIG_SMP

static char *smt_enabled_cmdline;

/* Look for ibm,smt-enabled OF option */
void __init check_smt_enabled(void)
{
	struct device_node *dn;
	const char *smt_option;

	/* Allow the command line to overrule the OF option */
	if (smt_enabled_cmdline)
		return;

	dn = of_find_node_by_path("/options");

	if (dn) {
		smt_option = of_get_property(dn, "ibm,smt-enabled", NULL);

                if (smt_option) {
			if (!strcmp(smt_option, "on"))
				smt_enabled_at_boot = 1;
			else if (!strcmp(smt_option, "off"))
				smt_enabled_at_boot = 0;
                }
        }
	/* Default to enabling all threads */
	smt_enabled_at_boot = threads_per_core;

	/* Allow the command line to overrule the OF option */
	if (smt_enabled_cmdline) {
		if (!strcmp(smt_enabled_cmdline, "on"))
			smt_enabled_at_boot = threads_per_core;
		else if (!strcmp(smt_enabled_cmdline, "off"))
			smt_enabled_at_boot = 0;
		else {
			int smt;
			int rc;

			rc = kstrtoint(smt_enabled_cmdline, 10, &smt);
			if (!rc)
				smt_enabled_at_boot =
					min(threads_per_core, smt);
		}
	} else {
		dn = of_find_node_by_path("/options");
		if (dn) {
			smt_option = of_get_property(dn, "ibm,smt-enabled",
						     NULL);

			if (smt_option) {
				if (!strcmp(smt_option, "on"))
					smt_enabled_at_boot = threads_per_core;
				else if (!strcmp(smt_option, "off"))
					smt_enabled_at_boot = 0;
			}

			of_node_put(dn);
		}
	}
}

/* Look for smt-enabled= cmdline option */
static int __init early_smt_enabled(char *p)
{
	smt_enabled_cmdline = 1;

	if (!p)
		return 0;

	if (!strcmp(p, "on") || !strcmp(p, "1"))
		smt_enabled_at_boot = 1;
	else if (!strcmp(p, "off") || !strcmp(p, "0"))
		smt_enabled_at_boot = 0;

	smt_enabled_cmdline = p;
	return 0;
}
early_param("smt-enabled", early_smt_enabled);

#endif /* CONFIG_SMP */

/* Put the paca pointer into r13 and SPRG3 */
void __init setup_paca(int cpu)
{
	local_paca = &paca[cpu];
	mtspr(SPRN_SPRG3, local_paca);
/** Fix up paca fields required for the boot cpu */
static void __init fixup_boot_paca(void)
{
	/* The boot cpu is started */
	get_paca()->cpu_start = 1;
	/* Allow percpu accesses to work until we setup percpu data */
	get_paca()->data_offset = 0;
	/* Mark interrupts disabled in PACA */
	irq_soft_mask_set(IRQS_DISABLED);
}

static void __init configure_exceptions(void)
{
	/*
	 * Setup the trampolines from the lowmem exception vectors
	 * to the kdump kernel when not using a relocatable kernel.
	 */
	setup_kdump_trampoline();

	/* Under a PAPR hypervisor, we need hypercalls */
	if (firmware_has_feature(FW_FEATURE_SET_MODE)) {
		/* Enable AIL if possible */
		pseries_enable_reloc_on_exc();

		/*
		 * Tell the hypervisor that we want our exceptions to
		 * be taken in little endian mode.
		 *
		 * We don't call this for big endian as our calling convention
		 * makes us always enter in BE, and the call may fail under
		 * some circumstances with kdump.
		 */
#ifdef __LITTLE_ENDIAN__
		pseries_little_endian_exceptions();
#endif
	} else {
		/* Set endian mode using OPAL */
		if (firmware_has_feature(FW_FEATURE_OPAL))
			opal_configure_cores();

		/* AIL on native is done in cpu_ready_for_interrupts() */
	}
}

static void cpu_ready_for_interrupts(void)
{
	/*
	 * Enable AIL if supported, and we are in hypervisor mode. This
	 * is called once for every processor.
	 *
	 * If we are not in hypervisor mode the job is done once for
	 * the whole partition in configure_exceptions().
	 */
	if (cpu_has_feature(CPU_FTR_HVMODE) &&
	    cpu_has_feature(CPU_FTR_ARCH_207S)) {
		unsigned long lpcr = mfspr(SPRN_LPCR);
		mtspr(SPRN_LPCR, lpcr | LPCR_AIL_3);
	}

	/*
	 * Fixup HFSCR:TM based on CPU features. The bit is set by our
	 * early asm init because at that point we haven't updated our
	 * CPU features from firmware and device-tree. Here we have,
	 * so let's do it.
	 */
	if (cpu_has_feature(CPU_FTR_HVMODE) && !cpu_has_feature(CPU_FTR_TM_COMP))
		mtspr(SPRN_HFSCR, mfspr(SPRN_HFSCR) & ~HFSCR_TM);

	/* Set IR and DR in PACA MSR */
	get_paca()->kernel_msr = MSR_KERNEL;
}

unsigned long spr_default_dscr = 0;

void __init record_spr_defaults(void)
{
	if (early_cpu_has_feature(CPU_FTR_DSCR))
		spr_default_dscr = mfspr(SPRN_DSCR);
}

/*
 * Early initialization entry point. This is called by head.S
 * with MMU translation disabled. We rely on the "feature" of
 * the CPU that ignores the top 2 bits of the address in real
 * mode so we can access kernel globals normally provided we
 * only toy with things in the RMO region. From here, we do
 * some early parsing of the device-tree to setup out LMB
 * some early parsing of the device-tree to setup out MEMBLOCK
 * data structures, and allocate & initialize the hash table
 * and segment tables so we can start running with translation
 * enabled.
 *
 * It is this function which will call the probe() callback of
 * the various platform types and copy the matching one to the
 * global ppc_md structure. Your platform can eventually do
 * some very early initializations from the probe() routine, but
 * this is not recommended, be very careful as, for example, the
 * device-tree is not accessible via normal means at this point.
 */

void __init early_setup(unsigned long dt_ptr)
{
	/* -------- printk is _NOT_ safe to use here ! ------- */

	/* Fill in any unititialised pacas */
	initialise_pacas();
	static __initdata struct paca_struct boot_paca;

	/* -------- printk is _NOT_ safe to use here ! ------- */

	/* Try new device tree based feature discovery ... */
	if (!dt_cpu_ftrs_init(__va(dt_ptr)))
		/* Otherwise use the old style CPU table */
		identify_cpu(0, mfspr(SPRN_PVR));

	/* Assume we're on cpu 0 for now. Don't write to the paca yet! */
	setup_paca(0);
	initialise_paca(&boot_paca, 0);
	setup_paca(&boot_paca);
	fixup_boot_paca();

	/* -------- printk is now safe to use ------- */

	/* Enable early debugging if any specified (see udbg.h) */
	udbg_early_init();

 	DBG(" -> early_setup(), dt_ptr: 0x%lx\n", dt_ptr);

	/*
	 * Do early initialization using the flattened device
	 * tree, such as retrieving the physical memory map or
	 * calculating/retrieving the hash table size.
	 */
	early_init_devtree(__va(dt_ptr));

	/* Now we know the logical id of our boot cpu, setup the paca. */
	setup_paca(boot_cpuid);

	/* Fix up paca fields required for the boot cpu */
	get_paca()->cpu_start = 1;
	get_paca()->stab_real = __pa((u64)&initial_stab);
	get_paca()->stab_addr = (u64)&initial_stab;
	epapr_paravirt_early_init();

	/* Now we know the logical id of our boot cpu, setup the paca. */
	setup_paca(&paca[boot_cpuid]);
	if (boot_cpuid != 0) {
		/* Poison paca_ptrs[0] again if it's not the boot cpu */
		memset(&paca_ptrs[0], 0x88, sizeof(paca_ptrs[0]));
	}
	setup_paca(paca_ptrs[boot_cpuid]);
	fixup_boot_paca();

	/*
	 * Configure exception handlers. This include setting up trampolines
	 * if needed, setting exception endian mode, etc...
	 */
	configure_exceptions();

	/* Apply all the dynamic patching */
	apply_feature_fixups();
	setup_feature_keys();

	/*
	 * Initialize the MMU Hash table and create the linear mapping
	 * of memory. Has to be done before stab/slb initialization as
	 * this is currently where the page size encoding is obtained
	 */
	htab_initialize();

	/*
	 * Initialize stab / SLB management except on iSeries
	 */
	if (cpu_has_feature(CPU_FTR_SLB))
		slb_initialize();
	else if (!firmware_has_feature(FW_FEATURE_ISERIES))
		stab_initialize(get_paca()->stab_real);

	DBG(" <- early_setup()\n");
	/* Initialize the hash table or TLB handling */
	early_init_mmu();

	/*
	 * After firmware and early platform setup code has set things up,
	 * we note the SPR values for configurable control/performance
	 * registers, and use those as initial defaults.
	 */
	record_spr_defaults();

	/*
	 * At this point, we can let interrupts switch to virtual mode
	 * (the MMU has been setup), so adjust the MSR in the PACA to
	 * have IR and DR set and enable AIL if it exists
	 */
	cpu_ready_for_interrupts();

	/*
	 * We enable ftrace here, but since we only support DYNAMIC_FTRACE, it
	 * will only actually get enabled on the boot cpu much later once
	 * ftrace itself has been initialized.
	 */
	this_cpu_enable_ftrace();

	DBG(" <- early_setup()\n");

#ifdef CONFIG_PPC_EARLY_DEBUG_BOOTX
	/*
	 * This needs to be done *last* (after the above DBG() even)
	 *
	 * Right after we return from this function, we turn on the MMU
	 * which means the real-mode access trick that btext does will
	 * no longer work, it needs to switch to using a real MMU
	 * mapping. This call will ensure that it does
	 */
	btext_map();
#endif /* CONFIG_PPC_EARLY_DEBUG_BOOTX */
}

#ifdef CONFIG_SMP
void early_setup_secondary(void)
{
	struct paca_struct *lpaca = get_paca();

	/* Mark interrupts enabled in PACA */
	lpaca->soft_enabled = 0;

	/* Initialize hash table for that CPU */
	htab_initialize_secondary();

	/* Initialize STAB/SLB. We use a virtual address as it works
	 * in real mode on pSeries and we want a virutal address on
	 * iSeries anyway
	 */
	if (cpu_has_feature(CPU_FTR_SLB))
		slb_initialize();
	else
		stab_initialize(lpaca->stab_addr);
	/* Mark interrupts enabled in PACA */
	/* Mark interrupts disabled in PACA */
	irq_soft_mask_set(IRQS_DISABLED);

	/* Initialize the hash table or TLB handling */
	early_init_mmu_secondary();

	/*
	 * At this point, we can let interrupts switch to virtual mode
	 * (the MMU has been setup), so adjust the MSR in the PACA to
	 * have IR and DR set.
	 */
	cpu_ready_for_interrupts();
}

#endif /* CONFIG_SMP */

#if defined(CONFIG_SMP) || defined(CONFIG_KEXEC)
void smp_release_cpus(void)
{
	extern unsigned long __secondary_hold_spinloop;
	unsigned long *ptr;
void panic_smp_self_stop(void)
{
	hard_irq_disable();
	spin_begin();
	while (1)
		spin_cpu_relax();
}

#if defined(CONFIG_SMP) || defined(CONFIG_KEXEC_CORE)
static bool use_spinloop(void)
{
	if (IS_ENABLED(CONFIG_PPC_BOOK3S)) {
		/*
		 * See comments in head_64.S -- not all platforms insert
		 * secondaries at __secondary_hold and wait at the spin
		 * loop.
		 */
		if (firmware_has_feature(FW_FEATURE_OPAL))
			return false;
		return true;
	}

	/*
	 * When book3e boots from kexec, the ePAPR spin table does
	 * not get used.
	 */
	return of_property_read_bool(of_chosen, "linux,booted-from-kexec");
}

void smp_release_cpus(void)
{
	unsigned long *ptr;
	int i;

	if (!use_spinloop())
		return;

	DBG(" -> smp_release_cpus()\n");

	/* All secondary cpus are spinning on a common spinloop, release them
	 * all now so they can start to spin on their individual paca
	 * spinloops. For non SMP kernels, the secondary cpus never get out
	 * of the common spinloop.
	 * This is useless but harmless on iSeries, secondaries are already
	 * waiting on their paca spinloops. */

	ptr  = (unsigned long *)((unsigned long)&__secondary_hold_spinloop
			- PHYSICAL_START);
	*ptr = 1;
	mb();
	 */

	ptr  = (unsigned long *)((unsigned long)&__secondary_hold_spinloop
			- PHYSICAL_START);
	*ptr = ppc_function_entry(generic_secondary_smp_init);

	/* And wait a bit for them to catch up */
	for (i = 0; i < 100000; i++) {
		mb();
		HMT_low();
		if (spinning_secondaries == 0)
			break;
		udelay(1);
	}
	DBG("spinning_secondaries = %d\n", spinning_secondaries);

	DBG(" <- smp_release_cpus()\n");
}
#endif /* CONFIG_SMP || CONFIG_KEXEC_CORE */

/*
 * Initialize some remaining members of the ppc64_caches and systemcfg
 * structures
 * (at least until we get rid of them completely). This is mostly some
 * cache informations about the CPU that will be used by cache flush
 * routines and/or provided to userland
 */

static void init_cache_info(struct ppc_cache_info *info, u32 size, u32 lsize,
			    u32 bsize, u32 sets)
{
	info->size = size;
	info->sets = sets;
	info->line_size = lsize;
	info->block_size = bsize;
	info->log_block_size = __ilog2(bsize);
	if (bsize)
		info->blocks_per_page = PAGE_SIZE / bsize;
	else
		info->blocks_per_page = 0;

	if (sets == 0)
		info->assoc = 0xffff;
	else
		info->assoc = size / (sets * lsize);
}

static bool __init parse_cache_info(struct device_node *np,
				    bool icache,
				    struct ppc_cache_info *info)
{
	static const char *ipropnames[] __initdata = {
		"i-cache-size",
		"i-cache-sets",
		"i-cache-block-size",
		"i-cache-line-size",
	};
	static const char *dpropnames[] __initdata = {
		"d-cache-size",
		"d-cache-sets",
		"d-cache-block-size",
		"d-cache-line-size",
	};
	const char **propnames = icache ? ipropnames : dpropnames;
	const __be32 *sizep, *lsizep, *bsizep, *setsp;
	u32 size, lsize, bsize, sets;
	bool success = true;

	size = 0;
	sets = -1u;
	lsize = bsize = cur_cpu_spec->dcache_bsize;
	sizep = of_get_property(np, propnames[0], NULL);
	if (sizep != NULL)
		size = be32_to_cpu(*sizep);
	setsp = of_get_property(np, propnames[1], NULL);
	if (setsp != NULL)
		sets = be32_to_cpu(*setsp);
	bsizep = of_get_property(np, propnames[2], NULL);
	lsizep = of_get_property(np, propnames[3], NULL);
	if (bsizep == NULL)
		bsizep = lsizep;
	if (lsizep != NULL)
		lsize = be32_to_cpu(*lsizep);
	if (bsizep != NULL)
		bsize = be32_to_cpu(*bsizep);
	if (sizep == NULL || bsizep == NULL || lsizep == NULL)
		success = false;

	/*
	 * OF is weird .. it represents fully associative caches
	 * as "1 way" which doesn't make much sense and doesn't
	 * leave room for direct mapped. We'll assume that 0
	 * in OF means direct mapped for that reason.
	 */
	if (sets == 1)
		sets = 0;
	else if (sets == 0)
		sets = 1;

	init_cache_info(info, size, lsize, bsize, sets);

	return success;
}

void __init initialize_cache_info(void)
{
	struct device_node *cpu = NULL, *l2, *l3 = NULL;
	u32 pvr;

	DBG(" -> initialize_cache_info()\n");

	for (np = NULL; (np = of_find_node_by_type(np, "cpu"));) {
		num_cpus += 1;

		/* We're assuming *all* of the CPUs have the same
		 * d-cache and i-cache sizes... -Peter
		 */

		if ( num_cpus == 1 ) {
			const u32 *sizep, *lsizep;
	for_each_node_by_type(np, "cpu") {
		num_cpus += 1;
	/*
	 * All shipping POWER8 machines have a firmware bug that
	 * puts incorrect information in the device-tree. This will
	 * be (hopefully) fixed for future chips but for now hard
	 * code the values if we are running on one of these
	 */
	pvr = PVR_VER(mfspr(SPRN_PVR));
	if (pvr == PVR_POWER8 || pvr == PVR_POWER8E ||
	    pvr == PVR_POWER8NVL) {
						/* size    lsize   blk  sets */
		init_cache_info(&ppc64_caches.l1i, 0x8000,   128,  128, 32);
		init_cache_info(&ppc64_caches.l1d, 0x10000,  128,  128, 64);
		init_cache_info(&ppc64_caches.l2,  0x80000,  128,  0,   512);
		init_cache_info(&ppc64_caches.l3,  0x800000, 128,  0,   8192);
	} else
		cpu = of_find_node_by_type(NULL, "cpu");

	/*
	 * We're assuming *all* of the CPUs have the same
	 * d-cache and i-cache sizes... -Peter
	 */
	if (cpu) {
		if (!parse_cache_info(cpu, false, &ppc64_caches.l1d))
			DBG("Argh, can't find dcache properties !\n");

		if (!parse_cache_info(cpu, true, &ppc64_caches.l1i))
			DBG("Argh, can't find icache properties !\n");

		/*
		 * Try to find the L2 and L3 if any. Assume they are
		 * unified and use the D-side properties.
		 */
		if (num_cpus == 1) {
			const __be32 *sizep, *lsizep;
			u32 size, lsize;

			size = 0;
			lsize = cur_cpu_spec->dcache_bsize;
			sizep = of_get_property(np, "d-cache-size", NULL);
			if (sizep != NULL)
				size = *sizep;
			lsizep = of_get_property(np, "d-cache-block-size", NULL);
			/* fallback if block size missing */
			if (lsizep == NULL)
				lsizep = of_get_property(np, "d-cache-line-size", NULL);
			if (lsizep != NULL)
				lsize = *lsizep;
			if (sizep == 0 || lsizep == 0)
				size = be32_to_cpu(*sizep);
			lsizep = of_get_property(np, "d-cache-block-size",
						 NULL);
			/* fallback if block size missing */
			if (lsizep == NULL)
				lsizep = of_get_property(np,
							 "d-cache-line-size",
							 NULL);
			if (lsizep != NULL)
				lsize = be32_to_cpu(*lsizep);
			if (sizep == NULL || lsizep == NULL)
				DBG("Argh, can't find dcache properties ! "
				    "sizep: %p, lsizep: %p\n", sizep, lsizep);

			ppc64_caches.dsize = size;
			ppc64_caches.dline_size = lsize;
			ppc64_caches.log_dline_size = __ilog2(lsize);
			ppc64_caches.dlines_per_page = PAGE_SIZE / lsize;

			size = 0;
			lsize = cur_cpu_spec->icache_bsize;
			sizep = of_get_property(np, "i-cache-size", NULL);
			if (sizep != NULL)
				size = *sizep;
			lsizep = of_get_property(np, "i-cache-block-size", NULL);
			if (lsizep == NULL)
				lsizep = of_get_property(np, "i-cache-line-size", NULL);
			if (lsizep != NULL)
				lsize = *lsizep;
			if (sizep == 0 || lsizep == 0)
				size = be32_to_cpu(*sizep);
			lsizep = of_get_property(np, "i-cache-block-size",
						 NULL);
			if (lsizep == NULL)
				lsizep = of_get_property(np,
							 "i-cache-line-size",
							 NULL);
			if (lsizep != NULL)
				lsize = be32_to_cpu(*lsizep);
			if (sizep == NULL || lsizep == NULL)
				DBG("Argh, can't find icache properties ! "
				    "sizep: %p, lsizep: %p\n", sizep, lsizep);

			ppc64_caches.isize = size;
			ppc64_caches.iline_size = lsize;
			ppc64_caches.log_iline_size = __ilog2(lsize);
			ppc64_caches.ilines_per_page = PAGE_SIZE / lsize;
		l2 = of_find_next_cache_node(cpu);
		of_node_put(cpu);
		if (l2) {
			parse_cache_info(l2, false, &ppc64_caches.l2);
			l3 = of_find_next_cache_node(l2);
			of_node_put(l2);
		}
		if (l3) {
			parse_cache_info(l3, false, &ppc64_caches.l3);
			of_node_put(l3);
		}
	}

	/* For use by binfmt_elf */
	dcache_bsize = ppc64_caches.l1d.block_size;
	icache_bsize = ppc64_caches.l1i.block_size;

	cur_cpu_spec->dcache_bsize = dcache_bsize;
	cur_cpu_spec->icache_bsize = icache_bsize;

	DBG(" <- initialize_cache_info()\n");
}


/*
 * Do some initial setup of the system.  The parameters are those which 
 * were passed in from the bootloader.
 */
void __init setup_system(void)
{
	DBG(" -> setup_system()\n");

	/* Apply the CPUs-specific and firmware specific fixups to kernel
	 * text (nop out sections not relevant to this CPU or this firmware)
	 */
	do_feature_fixups(cur_cpu_spec->cpu_features,
			  &__start___ftr_fixup, &__stop___ftr_fixup);
	do_feature_fixups(cur_cpu_spec->mmu_features,
			  &__start___mmu_ftr_fixup, &__stop___mmu_ftr_fixup);
	do_feature_fixups(powerpc_firmware_features,
			  &__start___fw_ftr_fixup, &__stop___fw_ftr_fixup);
	do_lwsync_fixups(cur_cpu_spec->cpu_features,
			 &__start___lwsync_fixup, &__stop___lwsync_fixup);
	do_final_fixups();

	/*
	 * Unflatten the device-tree passed by prom_init or kexec
	 */
	unflatten_device_tree();

	/*
	 * Fill the ppc64_caches & systemcfg structures with informations
 	 * retrieved from the device-tree.
	 */
	initialize_cache_info();

	/*
	 * Initialize irq remapping subsystem
	 */
	irq_early_init();

#ifdef CONFIG_PPC_RTAS
	/*
	 * Initialize RTAS if available
	 */
	rtas_initialize();
#endif /* CONFIG_PPC_RTAS */

	/*
	 * Check if we have an initrd provided via the device-tree
	 */
	check_for_initrd();

	/*
	 * Do some platform specific early initializations, that includes
	 * setting up the hash table pointers. It also sets up some interrupt-mapping
	 * related options that will be used by finish_device_tree()
	 */
	if (ppc_md.init_early)
		ppc_md.init_early();

 	/*
	 * We can discover serial ports now since the above did setup the
	 * hash table management for us, thus ioremap works. We do that early
	 * so that further code can be debugged
	 */
	find_legacy_serial_ports();

	/*
	 * Register early console
	 */
	register_early_udbg_console();

	/*
	 * Initialize xmon
	 */
	xmon_setup();

	check_smt_enabled();
	smp_setup_cpu_maps();

#ifdef CONFIG_SMP
	smp_setup_cpu_maps();
	check_smt_enabled();
	setup_tlb_core_data();

	/*
	 * Freescale Book3e parts spin in a loop provided by firmware,
	 * so smp_release_cpus() does nothing for them
	 */
#if defined(CONFIG_SMP)
	/* Release secondary cpus out of their spinloops at 0x60 now that
	 * we can map physical -> logical CPU ids
	 */
	smp_release_cpus();
#endif

	printk("Starting Linux PPC64 %s\n", init_utsname()->version);

	printk("-----------------------------------------------------\n");
	printk("ppc64_pft_size                = 0x%lx\n", ppc64_pft_size);
	printk("physicalMemorySize            = 0x%lx\n", lmb_phys_mem_size());
	if (ppc64_caches.dline_size != 0x80)
		printk("ppc64_caches.dcache_line_size = 0x%x\n",
		       ppc64_caches.dline_size);
	if (ppc64_caches.iline_size != 0x80)
		printk("ppc64_caches.icache_line_size = 0x%x\n",
		       ppc64_caches.iline_size);
	if (htab_address)
		printk("htab_address                  = 0x%p\n", htab_address);
	printk("htab_hash_mask                = 0x%lx\n", htab_hash_mask);
#if PHYSICAL_START > 0
	printk("physical_start                = 0x%lx\n", PHYSICAL_START);
#endif
	printk("-----------------------------------------------------\n");
	pr_info("Starting Linux %s %s\n", init_utsname()->machine,
		 init_utsname()->version);

	pr_info("-----------------------------------------------------\n");
	pr_info("ppc64_pft_size    = 0x%llx\n", ppc64_pft_size);
	pr_info("phys_mem_size     = 0x%llx\n", memblock_phys_mem_size());

	if (ppc64_caches.dline_size != 0x80)
		pr_info("dcache_line_size  = 0x%x\n", ppc64_caches.dline_size);
	if (ppc64_caches.iline_size != 0x80)
		pr_info("icache_line_size  = 0x%x\n", ppc64_caches.iline_size);

	pr_info("cpu_features      = 0x%016lx\n", cur_cpu_spec->cpu_features);
	pr_info("  possible        = 0x%016lx\n", CPU_FTRS_POSSIBLE);
	pr_info("  always          = 0x%016lx\n", CPU_FTRS_ALWAYS);
	pr_info("cpu_user_features = 0x%08x 0x%08x\n", cur_cpu_spec->cpu_user_features,
		cur_cpu_spec->cpu_user_features2);
	pr_info("mmu_features      = 0x%08x\n", cur_cpu_spec->mmu_features);
	pr_info("firmware_features = 0x%016lx\n", powerpc_firmware_features);

#ifdef CONFIG_PPC_STD_MMU_64
	if (htab_address)
		pr_info("htab_address      = 0x%p\n", htab_address);

	pr_info("htab_hash_mask    = 0x%lx\n", htab_hash_mask);
#endif

	if (PHYSICAL_START > 0)
		pr_info("physical_start    = 0x%llx\n",
		       (unsigned long long)PHYSICAL_START);
	pr_info("-----------------------------------------------------\n");

	DBG(" <- setup_system()\n");
}

#ifdef CONFIG_IRQSTACKS
static void __init irqstack_early_init(void)
{
	unsigned int i;

	/*
	 * interrupt stacks must be under 256MB, we cannot afford to take
	 * SLB misses on them.
	 */
	for_each_possible_cpu(i) {
		softirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc_base(THREAD_SIZE,
					    THREAD_SIZE, 0x10000000));
		hardirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc_base(THREAD_SIZE,
					    THREAD_SIZE, 0x10000000));
	}
}
#else
#define irqstack_early_init()
/* This returns the limit below which memory accesses to the linear
 * mapping are guarnateed not to cause a TLB or SLB miss. This is
 * used to allocate interrupt or emergency stacks for which our
 * exception entry path doesn't deal with being interrupted.
/*
 * This returns the limit below which memory accesses to the linear
 * mapping are guarnateed not to cause an architectural exception (e.g.,
 * TLB or SLB miss fault).
 *
 * This is used to allocate PACAs and various interrupt stacks that
 * that are accessed early in interrupt handlers that must not cause
 * re-entrant interrupts.
 */
__init u64 ppc64_bolted_size(void)
{
#ifdef CONFIG_PPC_BOOK3E
	/* Freescale BookE bolts the entire linear mapping */
	/* XXX: BookE ppc64_rma_limit setup seems to disagree? */
	if (early_mmu_has_feature(MMU_FTR_TYPE_FSL_E))
		return linear_map_top;
	/* Other BookE, we assume the first GB is bolted */
	return 1ul << 30;
#else
	/* BookS radix, does not take faults on linear mapping */
	if (early_radix_enabled())
		return ULONG_MAX;

	/* BookS hash, the first segment is bolted */
	if (early_mmu_has_feature(MMU_FTR_1T_SEGMENT))
		return 1UL << SID_SHIFT_1T;
	return 1UL << SID_SHIFT;
#endif
}

static void *__init alloc_stack(unsigned long limit, int cpu)
{
	unsigned long pa;

	pa = memblock_alloc_base_nid(THREAD_SIZE, THREAD_SIZE, limit,
					early_cpu_to_node(cpu), MEMBLOCK_NONE);
	if (!pa) {
		pa = memblock_alloc_base(THREAD_SIZE, THREAD_SIZE, limit);
		if (!pa)
			panic("cannot allocate stacks");
	}

	return __va(pa);
}

void __init irqstack_early_init(void)
{
	u64 limit = ppc64_bolted_size();
	unsigned int i;

	/*
	 * Interrupt stacks must be in the first segment since we
	 * cannot afford to take SLB misses on them. They are not
	 * accessed in realmode.
	 */
	for_each_possible_cpu(i) {
		softirq_ctx[i] = alloc_stack(limit, i);
		hardirq_ctx[i] = alloc_stack(limit, i);
	}
}

#ifdef CONFIG_PPC_BOOK3E
void __init exc_lvl_early_init(void)
{
	unsigned int i;

	for_each_possible_cpu(i) {
		void *sp;

		sp = alloc_stack(ULONG_MAX, i);
		critirq_ctx[i] = sp;
		paca_ptrs[i]->crit_kstack = sp + THREAD_SIZE;

		sp = alloc_stack(ULONG_MAX, i);
		dbgirq_ctx[i] = sp;
		paca_ptrs[i]->dbg_kstack = sp + THREAD_SIZE;

		sp = alloc_stack(ULONG_MAX, i);
		mcheckirq_ctx[i] = sp;
		paca_ptrs[i]->mc_kstack = sp + THREAD_SIZE;
	}

	if (cpu_has_feature(CPU_FTR_DEBUG_LVL_EXC))
		patch_exception(0x040, exc_debug_debug_book3e);
}
#endif

/*
 * Emergency stacks are used for a range of things, from asynchronous
 * NMIs (system reset, machine check) to synchronous, process context.
 * We set preempt_count to zero, even though that isn't necessarily correct. To
 * get the right value we'd need to copy it from the previous thread_info, but
 * doing that might fault causing more problems.
 * TODO: what to do with accounting?
 */
static void emerg_stack_init_thread_info(struct thread_info *ti, int cpu)
{
	ti->task = NULL;
	ti->cpu = cpu;
	ti->preempt_count = 0;
	ti->local_flags = 0;
	ti->flags = 0;
	klp_init_thread_info(ti);
}

/*
 * Stack space used when we detect a bad kernel stack pointer, and
 * early in SMP boots before relocation is enabled.
 */
static void __init emergency_stack_init(void)
{
	unsigned long limit;
 * early in SMP boots before relocation is enabled. Exclusive emergency
 * stack for machine checks.
 */
void __init emergency_stack_init(void)
{
	u64 limit;
	unsigned int i;

	/*
	 * Emergency stacks must be under 256MB, we cannot afford to take
	 * SLB misses on them. The ABI also requires them to be 128-byte
	 * aligned.
	 *
	 * Since we use these as temporary stacks during secondary CPU
	 * bringup, machine check, system reset, and HMI, we need to get
	 * at them in real mode. This means they must also be within the RMO
	 * region.
	 *
	 * The IRQ stacks allocated elsewhere in this file are zeroed and
	 * initialized in kernel/irq.c. These are initialized here in order
	 * to have emergency stacks available as early as possible.
	 */
	limit = min(0x10000000UL, lmb.rmo_size);

	for_each_possible_cpu(i) {
		unsigned long sp;
		sp  = lmb_alloc_base(THREAD_SIZE, THREAD_SIZE, limit);
		sp += THREAD_SIZE;
		paca[i].emergency_sp = __va(sp);
	limit = min(safe_stack_limit(), ppc64_rma_size);
	limit = min(ppc64_bolted_size(), ppc64_rma_size);

	for_each_possible_cpu(i) {
		struct thread_info *ti;

		ti = alloc_stack(limit, i);
		memset(ti, 0, THREAD_SIZE);
		emerg_stack_init_thread_info(ti, i);
		paca_ptrs[i]->emergency_sp = (void *)ti + THREAD_SIZE;

#ifdef CONFIG_PPC_BOOK3S_64
		/* emergency stack for NMI exception handling. */
		ti = alloc_stack(limit, i);
		memset(ti, 0, THREAD_SIZE);
		emerg_stack_init_thread_info(ti, i);
		paca_ptrs[i]->nmi_emergency_sp = (void *)ti + THREAD_SIZE;

		/* emergency stack for machine check exception handling. */
		ti = alloc_stack(limit, i);
		memset(ti, 0, THREAD_SIZE);
		emerg_stack_init_thread_info(ti, i);
		paca_ptrs[i]->mc_emergency_sp = (void *)ti + THREAD_SIZE;
#endif
	}
}

/*
 * Called into from start_kernel, after lock_kernel has been called.
 * Initializes bootmem, which is unsed to manage page allocation until
 * mem_init is called.
 */
void __init setup_arch(char **cmdline_p)
{
	ppc64_boot_msg(0x12, "Setup Arch");

	*cmdline_p = cmd_line;
 * Called into from start_kernel this initializes memblock, which is used
 * to manage page allocation until mem_init is called.
 */
void __init setup_arch(char **cmdline_p)
{
	*cmdline_p = boot_command_line;

	/*
	 * Set cache line size based on type of cpu as a default.
	 * Systems with OF can look in the properties on the cpu node(s)
	 * for a possibly more accurate value.
	 */
	dcache_bsize = ppc64_caches.dline_size;
	icache_bsize = ppc64_caches.iline_size;

	/* reboot on panic */
	panic_timeout = 180;

	if (ppc_md.panic)
		setup_panic();

	init_mm.start_code = (unsigned long)_stext;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = klimit;
	
	irqstack_early_init();
	emergency_stack_init();

	stabs_alloc();

	/* set up the bootmem stuff with available memory */
	do_init_bootmem();
	sparse_init();
#ifdef CONFIG_PPC_64K_PAGES
	init_mm.context.pte_frag = NULL;
#endif
#ifdef CONFIG_SPAPR_TCE_IOMMU
	mm_iommu_init(&init_mm.context);
#endif
	irqstack_early_init();
	exc_lvl_early_init();
	emergency_stack_init();

	initmem_init();

#ifdef CONFIG_DUMMY_CONSOLE
	conswitchp = &dummy_con;
#endif

	if (ppc_md.setup_arch)
		ppc_md.setup_arch();

	paging_init();
	ppc64_boot_msg(0x15, "Setup Done");
}


/* ToDo: do something useful if ppc_md is not yet setup. */
#define PPC64_LINUX_FUNCTION 0x0f000000
#define PPC64_IPL_MESSAGE 0xc0000000
#define PPC64_TERM_MESSAGE 0xb0000000

static void ppc64_do_msg(unsigned int src, const char *msg)
{
	if (ppc_md.progress) {
		char buf[128];

		sprintf(buf, "%08X\n", src);
		ppc_md.progress(buf, 0);
		snprintf(buf, 128, "%s", msg);
		ppc_md.progress(buf, 0);
	}
}

/* Print a boot progress message. */
void ppc64_boot_msg(unsigned int src, const char *msg)
{
	ppc64_do_msg(PPC64_LINUX_FUNCTION|PPC64_IPL_MESSAGE|src, msg);
	printk("[boot]%04x %s\n", src, msg);
}

/* Print a termination message (print only -- does not stop the kernel) */
void ppc64_terminate_msg(unsigned int src, const char *msg)
{
	ppc64_do_msg(PPC64_LINUX_FUNCTION|PPC64_TERM_MESSAGE|src, msg);
	printk("[terminate]%04x %s\n", src, msg);
}

void cpu_die(void)
{
	if (ppc_md.cpu_die)
		ppc_md.cpu_die();
}

#ifdef CONFIG_SMP
void __init setup_per_cpu_areas(void)
{
	int i;
	unsigned long size;
	char *ptr;

	/* Copy section for each CPU (we discard the original) */
	size = ALIGN(__per_cpu_end - __per_cpu_start, PAGE_SIZE);
#ifdef CONFIG_MODULES
	if (size < PERCPU_ENOUGH_ROOM)
		size = PERCPU_ENOUGH_ROOM;
#endif

	for_each_possible_cpu(i) {
		ptr = alloc_bootmem_pages_node(NODE_DATA(cpu_to_node(i)), size);
		if (!ptr)
			panic("Cannot allocate cpu data for CPU %d\n", i);

		paca[i].data_offset = ptr - __per_cpu_start;
		memcpy(ptr, __per_cpu_start, __per_cpu_end - __per_cpu_start);

	/* Initialize the MMU context management stuff */
	mmu_context_init();

	/* Interrupt code needs to be 64K-aligned */
	if ((unsigned long)_stext & 0xffff)
		panic("Kernelbase not 64K-aligned (0x%lx)!\n",
		      (unsigned long)_stext);
}

#ifdef CONFIG_SMP
#define PCPU_DYN_SIZE		()

static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size, size_t align)
{
	return __alloc_bootmem_node(NODE_DATA(early_cpu_to_node(cpu)), size, align,
				    __pa(MAX_DMA_ADDRESS));
}

static void __init pcpu_fc_free(void *ptr, size_t size)
{
	free_bootmem(__pa(ptr), size);
}

static int pcpu_cpu_distance(unsigned int from, unsigned int to)
{
	if (early_cpu_to_node(from) == early_cpu_to_node(to))
		return LOCAL_DISTANCE;
	else
		return REMOTE_DISTANCE;
}

unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(__per_cpu_offset);

void __init setup_per_cpu_areas(void)
{
	const size_t dyn_size = PERCPU_MODULE_RESERVE + PERCPU_DYNAMIC_RESERVE;
	size_t atom_size;
	unsigned long delta;
	unsigned int cpu;
	int rc;

	/*
	 * Linear mapping is one of 4K, 1M and 16M.  For 4K, no need
	 * to group units.  For larger mappings, use 1M atom which
	 * should be large enough to contain a number of units.
	 */
	if (mmu_linear_psize == MMU_PAGE_4K)
		atom_size = PAGE_SIZE;
	else
		atom_size = 1 << 20;

	rc = pcpu_embed_first_chunk(0, dyn_size, atom_size, pcpu_cpu_distance,
				    pcpu_fc_alloc, pcpu_fc_free);
	if (rc < 0)
		panic("cannot initialize percpu area (err=%d)", rc);

	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu) {
                __per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
		paca_ptrs[cpu]->data_offset = __per_cpu_offset[cpu];
	}
}
#endif


#ifdef CONFIG_PPC_INDIRECT_IO
struct ppc_pci_io ppc_pci_io;
EXPORT_SYMBOL(ppc_pci_io);
#endif /* CONFIG_PPC_INDIRECT_IO */

#ifdef CONFIG_MEMORY_HOTPLUG_SPARSE
unsigned long memory_block_size_bytes(void)
{
	if (ppc_md.memory_block_size)
		return ppc_md.memory_block_size();

	return MIN_MEMORY_BLOCK_SIZE;
}
#endif

#if defined(CONFIG_PPC_INDIRECT_PIO) || defined(CONFIG_PPC_INDIRECT_MMIO)
struct ppc_pci_io ppc_pci_io;
EXPORT_SYMBOL(ppc_pci_io);
#endif

#ifdef CONFIG_HARDLOCKUP_DETECTOR_PERF
u64 hw_nmi_get_sample_period(int watchdog_thresh)
{
	return ppc_proc_freq * watchdog_thresh;
}
#endif

/*
 * The perf based hardlockup detector breaks PMU event based branches, so
 * disable it by default. Book3S has a soft-nmi hardlockup detector based
 * on the decrementer interrupt, so it does not suffer from this problem.
 *
 * It is likely to get false positives in VM guests, so disable it there
 * by default too.
 */
static int __init disable_hardlockup_detector(void)
{
#ifdef CONFIG_HARDLOCKUP_DETECTOR_PERF
	hardlockup_detector_disable();
#else
	if (firmware_has_feature(FW_FEATURE_LPAR))
		hardlockup_detector_disable();
#endif

	return 0;
}
early_initcall(disable_hardlockup_detector);

#ifdef CONFIG_PPC_BOOK3S_64
static enum l1d_flush_type enabled_flush_types;
static void *l1d_flush_fallback_area;
static bool no_rfi_flush;
bool rfi_flush;

static int __init handle_no_rfi_flush(char *p)
{
	pr_info("rfi-flush: disabled on command line.");
	no_rfi_flush = true;
	return 0;
}
early_param("no_rfi_flush", handle_no_rfi_flush);

/*
 * The RFI flush is not KPTI, but because users will see doco that says to use
 * nopti we hijack that option here to also disable the RFI flush.
 */
static int __init handle_no_pti(char *p)
{
	pr_info("rfi-flush: disabling due to 'nopti' on command line.\n");
	handle_no_rfi_flush(NULL);
	return 0;
}
early_param("nopti", handle_no_pti);

static void do_nothing(void *unused)
{
	/*
	 * We don't need to do the flush explicitly, just enter+exit kernel is
	 * sufficient, the RFI exit handlers will do the right thing.
	 */
}

void rfi_flush_enable(bool enable)
{
	if (enable) {
		do_rfi_flush_fixups(enabled_flush_types);
		on_each_cpu(do_nothing, NULL, 1);
	} else
		do_rfi_flush_fixups(L1D_FLUSH_NONE);

	rfi_flush = enable;
}

static void __ref init_fallback_flush(void)
{
	u64 l1d_size, limit;
	int cpu;

	/* Only allocate the fallback flush area once (at boot time). */
	if (l1d_flush_fallback_area)
		return;

	l1d_size = ppc64_caches.l1d.size;

	/*
	 * If there is no d-cache-size property in the device tree, l1d_size
	 * could be zero. That leads to the loop in the asm wrapping around to
	 * 2^64-1, and then walking off the end of the fallback area and
	 * eventually causing a page fault which is fatal. Just default to
	 * something vaguely sane.
	 */
	if (!l1d_size)
		l1d_size = (64 * 1024);

	limit = min(ppc64_bolted_size(), ppc64_rma_size);

	/*
	 * Align to L1d size, and size it at 2x L1d size, to catch possible
	 * hardware prefetch runoff. We don't have a recipe for load patterns to
	 * reliably avoid the prefetcher.
	 */
	l1d_flush_fallback_area = __va(memblock_alloc_base(l1d_size * 2, l1d_size, limit));
	memset(l1d_flush_fallback_area, 0, l1d_size * 2);

	for_each_possible_cpu(cpu) {
		struct paca_struct *paca = paca_ptrs[cpu];
		paca->rfi_flush_fallback_area = l1d_flush_fallback_area;
		paca->l1d_flush_size = l1d_size;
	}
}

void setup_rfi_flush(enum l1d_flush_type types, bool enable)
{
	if (types & L1D_FLUSH_FALLBACK) {
		pr_info("rfi-flush: fallback displacement flush available\n");
		init_fallback_flush();
	}

	if (types & L1D_FLUSH_ORI)
		pr_info("rfi-flush: ori type flush available\n");

	if (types & L1D_FLUSH_MTTRIG)
		pr_info("rfi-flush: mttrig type flush available\n");

	enabled_flush_types = types;

	if (!no_rfi_flush)
		rfi_flush_enable(enable);
}

#ifdef CONFIG_DEBUG_FS
static int rfi_flush_set(void *data, u64 val)
{
	bool enable;

	if (val == 1)
		enable = true;
	else if (val == 0)
		enable = false;
	else
		return -EINVAL;

	/* Only do anything if we're changing state */
	if (enable != rfi_flush)
		rfi_flush_enable(enable);

	return 0;
}

static int rfi_flush_get(void *data, u64 *val)
{
	*val = rfi_flush ? 1 : 0;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_rfi_flush, rfi_flush_get, rfi_flush_set, "%llu\n");

static __init int rfi_flush_debugfs_init(void)
{
	debugfs_create_file("rfi_flush", 0600, powerpc_debugfs_root, NULL, &fops_rfi_flush);
	return 0;
}
device_initcall(rfi_flush_debugfs_init);
#endif
#endif /* CONFIG_PPC_BOOK3S_64 */
