/* SPDX-License-Identifier: GPL-2.0 */
/* ld script to make s390 Linux kernel
 * Written by Martin Schwidefsky (schwidefsky@de.ibm.com)
 */

#include <asm/page.h>
#include <asm-generic/vmlinux.lds.h>

#ifndef CONFIG_64BIT
OUTPUT_FORMAT("elf32-s390", "elf32-s390", "elf32-s390")
OUTPUT_ARCH(s390)
ENTRY(_start)
jiffies = jiffies_64 + 4;
#else
OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)
ENTRY(_start)
jiffies = jiffies_64;
#endif
#include <asm/thread_info.h>
#include <asm/page.h>

/*
 * Put .bss..swapper_pg_dir as the first thing in .bss. This will
 * make sure it has 16k alignment.
 */
#define BSS_FIRST_SECTIONS *(.bss..swapper_pg_dir)

/* Handle ro_after_init data on our own. */
#define RO_AFTER_INIT_DATA

#include <asm-generic/vmlinux.lds.h>

OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)
ENTRY(startup)
jiffies = jiffies_64;

PHDRS {
	text PT_LOAD FLAGS(5);	/* R_E */
	data PT_LOAD FLAGS(7);	/* RWE */
	note PT_NOTE FLAGS(0);	/* ___ */
}

SECTIONS
{
	. = 0x00000000;
	.text : {
	_text = .;		/* Text and read-only data */
		*(.text.head)
	TEXT_TEXT
		SCHED_TEXT
		LOCK_TEXT
		KPROBES_TEXT
		/* Text and read-only data */
		HEAD_TEXT
		/*
		 * E.g. perf doesn't like symbols starting at address zero,
		 * therefore skip the initial PSW and channel program located
		 * at address zero and let _text start at 0x200.
		 */
	_text = 0x200;
		TEXT_TEXT
		SCHED_TEXT
		CPUIDLE_TEXT
		LOCK_TEXT
		KPROBES_TEXT
		IRQENTRY_TEXT
		SOFTIRQENTRY_TEXT
		*(.fixup)
		*(.gnu.warning)
	} :text = 0x0700

	. = ALIGN(PAGE_SIZE);
	_etext = .;		/* End of text section */

	NOTES :text :note

	RODATA
	.dummy : { *(.dummy) } :data

	RO_DATA_SECTION(PAGE_SIZE)

#ifdef CONFIG_SHARED_KERNEL
	. = ALIGN(0x100000);	/* VM shared segments are 1MB aligned */
#endif

	. = ALIGN(PAGE_SIZE);
	_eshared = .;		/* End of shareable data */

	. = ALIGN(16);		/* Exception table */
	__ex_table : {
		__start___ex_table = .;
		*(__ex_table)
		__stop___ex_table = .;
	} :data

	.data : {		/* Data */
		DATA_DATA
		CONSTRUCTORS
	}

	. = ALIGN(PAGE_SIZE);
	.data_nosave : {
	__nosave_begin = .;
		*(.data.nosave)
	}
	. = ALIGN(PAGE_SIZE);
	__nosave_end = .;

	. = ALIGN(PAGE_SIZE);
	.data.page_aligned : {
		*(.data.idt)
	}

	. = ALIGN(0x100);
	.data.cacheline_aligned : {
		*(.data.cacheline_aligned)
	}

	. = ALIGN(0x100);
	.data.read_mostly : {
		*(.data.read_mostly)
	}
	_edata = .;		/* End of data section */

	. = ALIGN(2 * PAGE_SIZE);	/* init_task */
	.data.init_task : {
		*(.data.init_task)
	}

	/* will be freed after init */
	. = ALIGN(PAGE_SIZE);	/* Init code and data */
	__init_begin = .;
	.init.text : {
		_sinittext = .;
		INIT_TEXT
		_einittext = .;
	}
	_sdata = .;		/* Start of data section */

	. = ALIGN(PAGE_SIZE);
	__start_ro_after_init = .;
	.data..ro_after_init : {
		 *(.data..ro_after_init)
	}
	EXCEPTION_TABLE(16)
	. = ALIGN(PAGE_SIZE);
	__end_ro_after_init = .;

	RW_DATA_SECTION(0x100, PAGE_SIZE, THREAD_SIZE)

	_edata = .;		/* End of data section */

	/* will be freed after init */
	. = ALIGN(PAGE_SIZE);	/* Init code and data */
	__init_begin = .;

	. = ALIGN(PAGE_SIZE);
	.init.text : AT(ADDR(.init.text) - LOAD_OFFSET) {
		VMLINUX_SYMBOL(_sinittext) = . ;
		INIT_TEXT
		. = ALIGN(PAGE_SIZE);
		VMLINUX_SYMBOL(_einittext) = . ;
	}

	/*
	 * .exit.text is discarded at runtime, not link time,
	 * to deal with references from __bug_table
	*/
	.exit.text : {
		EXIT_TEXT
	}

	.init.data : {
		INIT_DATA
	}
	. = ALIGN(0x100);
	.init.setup : {
		__setup_start = .;
		*(.init.setup)
		__setup_end = .;
	}
	.initcall.init : {
		__initcall_start = .;
		INITCALLS
		__initcall_end = .;
	}

	.con_initcall.init : {
		__con_initcall_start = .;
		*(.con_initcall.init)
		__con_initcall_end = .;
	}
	SECURITY_INIT

#ifdef CONFIG_BLK_DEV_INITRD
	. = ALIGN(0x100);
	.init.ramfs : {
		__initramfs_start = .;
		*(.init.ramfs)
		. = ALIGN(2);
		__initramfs_end = .;
	}
#endif

	PERCPU(PAGE_SIZE)
	. = ALIGN(PAGE_SIZE);
	__init_end = .;		/* freed after init ends here */

	/* BSS */
	.bss : {
		__bss_start = .;
		*(.bss)
		. = ALIGN(2);
		__bss_stop = .;
	}

	_end = . ;

	/* Sections to be discarded */
	/DISCARD/ : {
		EXIT_DATA
		*(.exitcall.exit)
	}

	/* Debugging sections.	*/
	STABS_DEBUG
	DWARF_DEBUG
	.exit.data : {
		EXIT_DATA
	}

	/* early.c uses stsi, which requires page aligned data. */
	. = ALIGN(PAGE_SIZE);
	INIT_DATA_SECTION(0x100)

	PERCPU_SECTION(0x100)
	. = ALIGN(PAGE_SIZE);
	__init_end = .;		/* freed after init ends here */

	BSS_SECTION(PAGE_SIZE, 4 * PAGE_SIZE, PAGE_SIZE)

	_end = . ;

	/* Debugging sections.	*/
	STABS_DEBUG
	DWARF_DEBUG

	/* Sections to be discarded */
	DISCARDS
}
