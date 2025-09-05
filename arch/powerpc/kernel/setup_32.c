/*
 * Common prep/pmac/chrp boot and setup code.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/initrd.h>
#include <linux/tty.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/root_dev.h>
#include <linux/cpu.h>
#include <linux/console.h>
#include <linux/lmb.h>
#include <linux/memblock.h>
#include <linux/export.h>

#include <asm/io.h>
#include <asm/prom.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/elf.h>
#include <asm/cputable.h>
#include <asm/bootx.h>
#include <asm/btext.h>
#include <asm/machdep.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/uaccess.h>
#include <asm/pmac_feature.h>
#include <asm/sections.h>
#include <asm/nvram.h>
#include <asm/xmon.h>
#include <asm/time.h>
#include <asm/serial.h>
#include <asm/udbg.h>

#include "setup.h"
#include <asm/mmu_context.h>
#include <asm/epapr_hcalls.h>
#include <asm/code-patching.h>
#include <asm/cpu_has_feature.h>
#include <asm/asm-prototypes.h>
#include <asm/kdump.h>
#include <asm/feature-fixups.h>

#include "setup.h"

#define DBG(fmt...)

extern void bootx_init(unsigned long r4, unsigned long phys);

int boot_cpuid;
EXPORT_SYMBOL_GPL(boot_cpuid);
int boot_cpuid_phys;
int boot_cpuid_phys;
EXPORT_SYMBOL_GPL(boot_cpuid_phys);

int smp_hw_index[NR_CPUS];
EXPORT_SYMBOL(smp_hw_index);

unsigned long ISA_DMA_THRESHOLD;
unsigned int DMA_MODE_READ;
unsigned int DMA_MODE_WRITE;

int have_of = 1;

#ifdef CONFIG_VGA_CONSOLE
unsigned long vgacon_remap_base;
EXPORT_SYMBOL(vgacon_remap_base);
#endif

/*
 * These are used in binfmt_elf.c to put aux entries on the stack
 * for each elf executable being started.
 */
int dcache_bsize;
int icache_bsize;
int ucache_bsize;
EXPORT_SYMBOL(ISA_DMA_THRESHOLD);
EXPORT_SYMBOL(DMA_MODE_READ);
EXPORT_SYMBOL(DMA_MODE_WRITE);

/*
 * We're called here very early in the boot.
 *
 * Note that the kernel may be running at an address which is different
 * from the address that it was linked at, so we must use RELOC/PTRRELOC
 * to access static data (including strings).  -- paulus
 */
notrace unsigned long __init early_init(unsigned long dt_ptr)
{
	unsigned long offset = reloc_offset();

	/* First zero the BSS -- use memset_io, some platforms don't have
	 * caches on yet */
	memset_io((void __iomem *)PTRRELOC(&__bss_start), 0,
			__bss_stop - __bss_start);

	/*
	 * Identify the CPU type and fix up code sections
	 * that depend on which cpu we have.
	 */
	identify_cpu(offset, mfspr(SPRN_PVR));

	apply_feature_fixups();

	return KERNELBASE + offset;
}


/*
 * This is run before start_kernel(), the kernel has been relocated
 * and we are running with enough of the MMU enabled to have our
 * proper kernel virtual addresses
 *
 * We do the initial parsing of the flat device-tree and prepares
 * for the MMU to be fully initialized.
 */
notrace void __init machine_init(unsigned long dt_ptr, unsigned long phys)
{
	/* Enable early debugging if any specified (see udbg.h) */
	udbg_early_init();

	/* Do some early initialization based on the flat device tree */
	early_init_devtree(__va(dt_ptr));

	probe_machine();

extern unsigned int memset_nocache_branch; /* Insn to be replaced by NOP */

notrace void __init machine_init(u64 dt_ptr)
{
	unsigned int *addr = (unsigned int *)((unsigned long)&patch__memset_nocache +
					       patch__memset_nocache);
	unsigned long insn;

	/* Configure static keys first, now that we're relocated. */
	setup_feature_keys();

	/* Enable early debugging if any specified (see udbg.h) */
	udbg_early_init();

	patch_instruction_site(&patch__memcpy_nocache, PPC_INST_NOP);

	insn = create_cond_branch(addr, branch_target(addr), 0x820000);
	patch_instruction(addr, insn);	/* replace b by bne cr0 */

	/* Do some early initialization based on the flat device tree */
	early_init_devtree(__va(dt_ptr));

	early_init_mmu();

	setup_kdump_trampoline();
}

#ifdef CONFIG_BOOKE_WDT
/* Checks wdt=x and wdt_period=xx command-line option */
notrace int __init early_parse_wdt(char *p)
{
	if (p && strncmp(p, "0", 1) != 0)
	       booke_wdt_enabled = 1;

	return 0;
}
early_param("wdt", early_parse_wdt);

int __init early_parse_wdt_period (char *p)
{
	if (p)
		booke_wdt_period = simple_strtoul(p, NULL, 0);

	return 0;
}
early_param("wdt_period", early_parse_wdt_period);
#endif	/* CONFIG_BOOKE_WDT */

/* Checks "l2cr=xxxx" command-line option */
static int __init ppc_setup_l2cr(char *str)
{
	if (cpu_has_feature(CPU_FTR_L2CR)) {
		unsigned long val = simple_strtoul(str, NULL, 0);
		printk(KERN_INFO "l2cr set to %lx\n", val);
		_set_L2CR(0);		/* force invalidate by disable cache */
		_set_L2CR(val);		/* and enable it */
	}
	return 1;
}
__setup("l2cr=", ppc_setup_l2cr);

/* Checks "l3cr=xxxx" command-line option */
static int __init ppc_setup_l3cr(char *str)
{
	if (cpu_has_feature(CPU_FTR_L3CR)) {
		unsigned long val = simple_strtoul(str, NULL, 0);
		printk(KERN_INFO "l3cr set to %lx\n", val);
		_set_L3CR(val);		/* and enable it */
	}
	return 1;
}
__setup("l3cr=", ppc_setup_l3cr);

#ifdef CONFIG_GENERIC_NVRAM

/* Generic nvram hooks used by drivers/char/gen_nvram.c */
unsigned char nvram_read_byte(int addr)
{
	if (ppc_md.nvram_read_val)
		return ppc_md.nvram_read_val(addr);
	return 0xff;
}
EXPORT_SYMBOL(nvram_read_byte);

void nvram_write_byte(unsigned char val, int addr)
{
	if (ppc_md.nvram_write_val)
		ppc_md.nvram_write_val(addr, val);
}
EXPORT_SYMBOL(nvram_write_byte);

ssize_t nvram_get_size(void)
{
	if (ppc_md.nvram_size)
		return ppc_md.nvram_size();
	return -1;
}
EXPORT_SYMBOL(nvram_get_size);

void nvram_sync(void)
{
	if (ppc_md.nvram_sync)
		ppc_md.nvram_sync();
}
EXPORT_SYMBOL(nvram_sync);

#endif /* CONFIG_NVRAM */

static DEFINE_PER_CPU(struct cpu, cpu_devices);

int __init ppc_init(void)
{
	int cpu;

int __init ppc_init(void)
static int __init ppc_init(void)
{
	/* clear the progress line */
	if (ppc_md.progress)
		ppc_md.progress("             ", 0xffff);

	/* register CPU devices */
	for_each_possible_cpu(cpu) {
		struct cpu *c = &per_cpu(cpu_devices, cpu);
		c->hotpluggable = 1;
		register_cpu(c, cpu);
	}

	/* call platform init */
	if (ppc_md.init != NULL) {
		ppc_md.init();
	}
	return 0;
}
arch_initcall(ppc_init);

#ifdef CONFIG_IRQSTACKS
static void __init irqstack_early_init(void)
void __init irqstack_early_init(void)
{
	unsigned int i;

	/* interrupt stacks must be in lowmem, we get that for free on ppc32
	 * as the lmb is limited to lowmem by LMB_REAL_LIMIT */
	for_each_possible_cpu(i) {
		softirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
		hardirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
	}
}
#else
#define irqstack_early_init()
#endif
	 * as the memblock is limited to lowmem by default */
	for_each_possible_cpu(i) {
		softirq_ctx[i] = (struct thread_info *)
			__va(memblock_alloc(THREAD_SIZE, THREAD_SIZE));
		hardirq_ctx[i] = (struct thread_info *)
			__va(memblock_alloc(THREAD_SIZE, THREAD_SIZE));
	}
}

#if defined(CONFIG_BOOKE) || defined(CONFIG_40x)
void __init exc_lvl_early_init(void)
{
	unsigned int i;

	/* interrupt stacks must be in lowmem, we get that for free on ppc32
	 * as the lmb is limited to lowmem by LMB_REAL_LIMIT */
	for_each_possible_cpu(i) {
		critirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
#ifdef CONFIG_BOOKE
		dbgirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
		mcheckirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
	unsigned int i, hw_cpu;

	/* interrupt stacks must be in lowmem, we get that for free on ppc32
	 * as the memblock is limited to lowmem by MEMBLOCK_REAL_LIMIT */
	for_each_possible_cpu(i) {
#ifdef CONFIG_SMP
		hw_cpu = get_hard_smp_processor_id(i);
#else
		hw_cpu = 0;
#endif

		critirq_ctx[hw_cpu] = (struct thread_info *)
			__va(memblock_alloc(THREAD_SIZE, THREAD_SIZE));
#ifdef CONFIG_BOOKE
		dbgirq_ctx[hw_cpu] = (struct thread_info *)
			__va(memblock_alloc(THREAD_SIZE, THREAD_SIZE));
		mcheckirq_ctx[hw_cpu] = (struct thread_info *)
			__va(memblock_alloc(THREAD_SIZE, THREAD_SIZE));
#endif
	}
}
#endif

void __init setup_power_save(void)
{
	*cmdline_p = cmd_line;
	*cmdline_p = boot_command_line;
#ifdef CONFIG_6xx
	if (cpu_has_feature(CPU_FTR_CAN_DOZE) ||
	    cpu_has_feature(CPU_FTR_CAN_NAP))
		ppc_md.power_save = ppc6xx_idle;
#endif

#ifdef CONFIG_E500
	if (cpu_has_feature(CPU_FTR_CAN_DOZE) ||
	    cpu_has_feature(CPU_FTR_CAN_NAP))
		ppc_md.power_save = e500_idle;
#endif
}

__init void initialize_cache_info(void)
{
	/*
	 * Set cache line size based on type of cpu as a default.
	 * Systems with OF can look in the properties on the cpu node(s)
	 * for a possibly more accurate value.
	 */
	dcache_bsize = cur_cpu_spec->dcache_bsize;
	icache_bsize = cur_cpu_spec->icache_bsize;
	ucache_bsize = 0;
	if (cpu_has_feature(CPU_FTR_UNIFIED_ID_CACHE))
		ucache_bsize = icache_bsize = dcache_bsize;

	/* reboot on panic */
	panic_timeout = 180;

	if (ppc_md.panic)
		setup_panic();

	init_mm.start_code = (unsigned long)_stext;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = klimit;

	exc_lvl_early_init();

	irqstack_early_init();

	/* set up the bootmem stuff with available memory */
	do_init_bootmem();
	if ( ppc_md.progress ) ppc_md.progress("setup_arch: bootmem", 0x3eab);
	initmem_init();
	if ( ppc_md.progress ) ppc_md.progress("setup_arch: initmem", 0x3eab);

#ifdef CONFIG_DUMMY_CONSOLE
	conswitchp = &dummy_con;
#endif

	if (ppc_md.setup_arch)
		ppc_md.setup_arch();
	if ( ppc_md.progress ) ppc_md.progress("arch: exit", 0x3eab);

	paging_init();

	/* Initialize the MMU context management stuff */
	mmu_context_init();
}
