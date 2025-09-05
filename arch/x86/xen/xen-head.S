/* SPDX-License-Identifier: GPL-2.0 */
/* Xen-specific pieces of head.S, intended to be included in the right
	place in head.S */

#ifdef CONFIG_XEN

#include <linux/elfnote.h>
#include <linux/init.h>

#include <asm/boot.h>
#include <asm/asm.h>
#include <asm/page.h>

#include <xen/interface/elfnote.h>
#include <asm/xen/interface.h>

#include <asm/msr.h>
#include <asm/page_types.h>
#include <asm/percpu.h>
#include <asm/unwind_hints.h>

#include <xen/interface/elfnote.h>
#include <xen/interface/features.h>
#include <xen/interface/xen.h>
#include <xen/interface/xen-mca.h>
#include <asm/xen/interface.h>

#ifdef CONFIG_XEN_PV
	__INIT
ENTRY(startup_xen)
	UNWIND_HINT_EMPTY
	cld

	/* Clear .bss */
	xor %eax,%eax
	mov $__bss_start, %_ASM_DI
	mov $__bss_stop, %_ASM_CX
	sub %_ASM_DI, %_ASM_CX
	shr $__ASM_SEL(2, 3), %_ASM_CX
	rep __ASM_SIZE(stos)

	mov %_ASM_SI, xen_start_info
	mov $init_thread_union+THREAD_SIZE, %_ASM_SP

#ifdef CONFIG_X86_64
	/* Set up %gs.
	 *
	 * The base of %gs always points to the bottom of the irqstack
	 * union.  If the stack protector canary is enabled, it is
	 * located at %gs:40.  Note that, on SMP, the boot cpu uses
	 * init data section till per cpu areas are set up.
	 */
	movl	$MSR_GS_BASE,%ecx
	movq	$INIT_PER_CPU_VAR(irq_stack_union),%rax
	cdq
	wrmsr
#endif

	jmp xen_start_kernel
END(startup_xen)
	__FINIT

.pushsection .text
	.align PAGE_SIZE_asm
ENTRY(hypercall_page)
	.skip PAGE_SIZE_asm
#ifdef CONFIG_XEN_PVH
/*
 * xen_pvh_early_cpu_init() - early PVH VCPU initialization
 * @cpu:   this cpu number (%rdi)
 * @entry: true if this is a secondary vcpu coming up on this entry
 *         point, false if this is the boot CPU being initialized for
 *         the first time (%rsi)
 *
 * Note: This is called as a function on the boot CPU, and is the entry point
 *       on the secondary CPU.
 */
ENTRY(xen_pvh_early_cpu_init)
	mov     %rsi, %r11

	/* Gather features to see if NX implemented. */
	mov     $0x80000001, %eax
	cpuid
	mov     %edx, %esi

	mov     $MSR_EFER, %ecx
	rdmsr
	bts     $_EFER_SCE, %eax

	bt      $20, %esi
	jnc     1f      	/* No NX, skip setting it */
	bts     $_EFER_NX, %eax
1:	wrmsr
#ifdef CONFIG_SMP
	cmp     $0, %r11b
	jne     cpu_bringup_and_idle
#endif

.pushsection .text
	.balign PAGE_SIZE
ENTRY(hypercall_page)
	.rept (PAGE_SIZE / 32)
		UNWIND_HINT_EMPTY
		.skip 32
	.endr

#define HYPERCALL(n) \
	.equ xen_hypercall_##n, hypercall_page + __HYPERVISOR_##n * 32; \
	.type xen_hypercall_##n, @function; .size xen_hypercall_##n, 32
#include <asm/xen-hypercalls.h>
#undef HYPERCALL
END(hypercall_page)
.popsection

	ELFNOTE(Xen, XEN_ELFNOTE_GUEST_OS,       .asciz "linux")
	ELFNOTE(Xen, XEN_ELFNOTE_GUEST_VERSION,  .asciz "2.6")
	ELFNOTE(Xen, XEN_ELFNOTE_XEN_VERSION,    .asciz "xen-3.0")
#ifdef CONFIG_X86_32
	ELFNOTE(Xen, XEN_ELFNOTE_VIRT_BASE,      _ASM_PTR __PAGE_OFFSET)
#else
	ELFNOTE(Xen, XEN_ELFNOTE_VIRT_BASE,      _ASM_PTR __START_KERNEL_map)
#endif
	ELFNOTE(Xen, XEN_ELFNOTE_ENTRY,          _ASM_PTR startup_xen)
	ELFNOTE(Xen, XEN_ELFNOTE_HYPERCALL_PAGE, _ASM_PTR hypercall_page)
	ELFNOTE(Xen, XEN_ELFNOTE_FEATURES,       .asciz "!writable_page_tables|pae_pgdir_above_4gb")
	/* Map the p2m table to a 512GB-aligned user address. */
	ELFNOTE(Xen, XEN_ELFNOTE_INIT_P2M,       .quad (PUD_SIZE * PTRS_PER_PUD))
#endif
#ifdef CONFIG_XEN_PV
	ELFNOTE(Xen, XEN_ELFNOTE_ENTRY,          _ASM_PTR startup_xen)
#endif
	ELFNOTE(Xen, XEN_ELFNOTE_HYPERCALL_PAGE, _ASM_PTR hypercall_page)
	ELFNOTE(Xen, XEN_ELFNOTE_FEATURES,
		.ascii "!writable_page_tables|pae_pgdir_above_4gb")
	ELFNOTE(Xen, XEN_ELFNOTE_SUPPORTED_FEATURES,
		.long (1 << XENFEAT_writable_page_tables) | (1 << XENFEAT_dom0))
	ELFNOTE(Xen, XEN_ELFNOTE_PAE_MODE,       .asciz "yes")
	ELFNOTE(Xen, XEN_ELFNOTE_LOADER,         .asciz "generic")
	ELFNOTE(Xen, XEN_ELFNOTE_L1_MFN_VALID,
		.quad _PAGE_PRESENT; .quad _PAGE_PRESENT)
	ELFNOTE(Xen, XEN_ELFNOTE_SUSPEND_CANCEL, .long 1)
	ELFNOTE(Xen, XEN_ELFNOTE_MOD_START_PFN,  .long 1)
	ELFNOTE(Xen, XEN_ELFNOTE_HV_START_LOW,   _ASM_PTR __HYPERVISOR_VIRT_START)
	ELFNOTE(Xen, XEN_ELFNOTE_PADDR_OFFSET,   _ASM_PTR 0)

#endif /*CONFIG_XEN */
