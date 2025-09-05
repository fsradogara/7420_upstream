/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_KVM_PARA_H
#define __LINUX_KVM_PARA_H

/*
 * This header file provides a method for making a hypercall to the host
 * Architectures should define:
 * - kvm_hypercall0, kvm_hypercall1...
 * - kvm_arch_para_features
 * - kvm_para_available
 */

/* Return values for hypercalls */
#define KVM_ENOSYS		1000
#define KVM_EFAULT		EFAULT
#define KVM_E2BIG		E2BIG

#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2

/*
 * hypercalls use architecture specific
 */
#include <asm/kvm_para.h>

#ifdef __KERNEL__
#ifdef CONFIG_KVM_GUEST
void __init kvm_guest_init(void);
#else
#define kvm_guest_init() do { } while (0)
#endif
#include <uapi/linux/kvm_para.h>


static inline bool kvm_para_has_feature(unsigned int feature)
{
	return !!(kvm_arch_para_features() & (1UL << feature));
}
#endif /* __KERNEL__ */
#endif /* __LINUX_KVM_PARA_H */


static inline bool kvm_para_has_hint(unsigned int feature)
{
	return !!(kvm_arch_para_hints() & (1UL << feature));
}
#endif /* __LINUX_KVM_PARA_H */
