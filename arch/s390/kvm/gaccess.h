/*
 * gaccess.h -  access guest memory
 *
 * Copyright IBM Corp. 2008
 * access guest memory
 *
 * Copyright IBM Corp. 2008, 2014
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (version 2 only)
 * as published by the Free Software Foundation.
 *
 *    Author(s): Carsten Otte <cotte@de.ibm.com>
 */

#ifndef __KVM_S390_GACCESS_H
#define __KVM_S390_GACCESS_H

#include <linux/compiler.h>
#include <linux/kvm_host.h>
#include <asm/uaccess.h>

static inline void __user *__guestaddr_to_user(struct kvm_vcpu *vcpu,
					       unsigned long guestaddr)
{
	unsigned long prefix  = vcpu->arch.sie_block->prefix;
	unsigned long origin  = vcpu->kvm->arch.guest_origin;
	unsigned long memsize = vcpu->kvm->arch.guest_memsize;

	if (guestaddr < 2 * PAGE_SIZE)
		guestaddr += prefix;
	else if ((guestaddr >= prefix) && (guestaddr < prefix + 2 * PAGE_SIZE))
		guestaddr -= prefix;

	if (guestaddr > memsize)
		return (void __user __force *) ERR_PTR(-EFAULT);

	guestaddr += origin;

	return (void __user *) guestaddr;
}

static inline int get_guest_u64(struct kvm_vcpu *vcpu, unsigned long guestaddr,
				u64 *result)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	BUG_ON(guestaddr & 7);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return get_user(*result, (unsigned long __user *) uptr);
}

static inline int get_guest_u32(struct kvm_vcpu *vcpu, unsigned long guestaddr,
				u32 *result)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	BUG_ON(guestaddr & 3);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return get_user(*result, (u32 __user *) uptr);
}

static inline int get_guest_u16(struct kvm_vcpu *vcpu, unsigned long guestaddr,
				u16 *result)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	BUG_ON(guestaddr & 1);

	if (IS_ERR(uptr))
		return PTR_ERR(uptr);

	return get_user(*result, (u16 __user *) uptr);
}

static inline int get_guest_u8(struct kvm_vcpu *vcpu, unsigned long guestaddr,
			       u8 *result)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return get_user(*result, (u8 __user *) uptr);
}

static inline int put_guest_u64(struct kvm_vcpu *vcpu, unsigned long guestaddr,
				u64 value)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	BUG_ON(guestaddr & 7);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return put_user(value, (u64 __user *) uptr);
}

static inline int put_guest_u32(struct kvm_vcpu *vcpu, unsigned long guestaddr,
				u32 value)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	BUG_ON(guestaddr & 3);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return put_user(value, (u32 __user *) uptr);
}

static inline int put_guest_u16(struct kvm_vcpu *vcpu, unsigned long guestaddr,
				u16 value)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	BUG_ON(guestaddr & 1);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return put_user(value, (u16 __user *) uptr);
}

static inline int put_guest_u8(struct kvm_vcpu *vcpu, unsigned long guestaddr,
			       u8 value)
{
	void __user *uptr = __guestaddr_to_user(vcpu, guestaddr);

	if (IS_ERR((void __force *) uptr))
		return PTR_ERR((void __force *) uptr);

	return put_user(value, (u8 __user *) uptr);
}


static inline int __copy_to_guest_slow(struct kvm_vcpu *vcpu,
				       unsigned long guestdest,
				       const void *from, unsigned long n)
{
	int rc;
	unsigned long i;
	const u8 *data = from;

	for (i = 0; i < n; i++) {
		rc = put_guest_u8(vcpu, guestdest++, *(data++));
		if (rc < 0)
			return rc;
	}
	return 0;
}

static inline int copy_to_guest(struct kvm_vcpu *vcpu, unsigned long guestdest,
				const void *from, unsigned long n)
{
	unsigned long prefix  = vcpu->arch.sie_block->prefix;
	unsigned long origin  = vcpu->kvm->arch.guest_origin;
	unsigned long memsize = vcpu->kvm->arch.guest_memsize;

	if ((guestdest < 2 * PAGE_SIZE) && (guestdest + n > 2 * PAGE_SIZE))
		goto slowpath;

	if ((guestdest < prefix) && (guestdest + n > prefix))
		goto slowpath;

	if ((guestdest < prefix + 2 * PAGE_SIZE)
	    && (guestdest + n > prefix + 2 * PAGE_SIZE))
		goto slowpath;

	if (guestdest < 2 * PAGE_SIZE)
		guestdest += prefix;
	else if ((guestdest >= prefix) && (guestdest < prefix + 2 * PAGE_SIZE))
		guestdest -= prefix;

	if (guestdest + n > memsize)
		return -EFAULT;

	if (guestdest + n < guestdest)
		return -EFAULT;

	guestdest += origin;

	return copy_to_user((void __user *) guestdest, from, n);
slowpath:
	return __copy_to_guest_slow(vcpu, guestdest, from, n);
}

static inline int __copy_from_guest_slow(struct kvm_vcpu *vcpu, void *to,
					 unsigned long guestsrc,
					 unsigned long n)
{
	int rc;
	unsigned long i;
	u8 *data = to;

	for (i = 0; i < n; i++) {
		rc = get_guest_u8(vcpu, guestsrc++, data++);
		if (rc < 0)
			return rc;
	}
	return 0;
}

static inline int copy_from_guest(struct kvm_vcpu *vcpu, void *to,
				  unsigned long guestsrc, unsigned long n)
{
	unsigned long prefix  = vcpu->arch.sie_block->prefix;
	unsigned long origin  = vcpu->kvm->arch.guest_origin;
	unsigned long memsize = vcpu->kvm->arch.guest_memsize;

	if ((guestsrc < 2 * PAGE_SIZE) && (guestsrc + n > 2 * PAGE_SIZE))
		goto slowpath;

	if ((guestsrc < prefix) && (guestsrc + n > prefix))
		goto slowpath;

	if ((guestsrc < prefix + 2 * PAGE_SIZE)
	    && (guestsrc + n > prefix + 2 * PAGE_SIZE))
		goto slowpath;

	if (guestsrc < 2 * PAGE_SIZE)
		guestsrc += prefix;
	else if ((guestsrc >= prefix) && (guestsrc < prefix + 2 * PAGE_SIZE))
		guestsrc -= prefix;

	if (guestsrc + n > memsize)
		return -EFAULT;

	if (guestsrc + n < guestsrc)
		return -EFAULT;

	guestsrc += origin;

	return copy_from_user(to, (void __user *) guestsrc, n);
slowpath:
	return __copy_from_guest_slow(vcpu, to, guestsrc, n);
}

static inline int copy_to_guest_absolute(struct kvm_vcpu *vcpu,
					 unsigned long guestdest,
					 const void *from, unsigned long n)
{
	unsigned long origin  = vcpu->kvm->arch.guest_origin;
	unsigned long memsize = vcpu->kvm->arch.guest_memsize;

	if (guestdest + n > memsize)
		return -EFAULT;

	if (guestdest + n < guestdest)
		return -EFAULT;

	guestdest += origin;

	return copy_to_user((void __user *) guestdest, from, n);
}

static inline int copy_from_guest_absolute(struct kvm_vcpu *vcpu, void *to,
					   unsigned long guestsrc,
					   unsigned long n)
{
	unsigned long origin  = vcpu->kvm->arch.guest_origin;
	unsigned long memsize = vcpu->kvm->arch.guest_memsize;

	if (guestsrc + n > memsize)
		return -EFAULT;

	if (guestsrc + n < guestsrc)
		return -EFAULT;

	guestsrc += origin;

	return copy_from_user(to, (void __user *) guestsrc, n);
}
#endif
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include "kvm-s390.h"

/**
 * kvm_s390_real_to_abs - convert guest real address to guest absolute address
 * @vcpu - guest virtual cpu
 * @gra - guest real address
 *
 * Returns the guest absolute address that corresponds to the passed guest real
 * address @gra of a virtual guest cpu by applying its prefix.
 */
static inline unsigned long kvm_s390_real_to_abs(struct kvm_vcpu *vcpu,
						 unsigned long gra)
{
	unsigned long prefix  = kvm_s390_get_prefix(vcpu);

	if (gra < 2 * PAGE_SIZE)
		gra += prefix;
	else if (gra >= prefix && gra < prefix + 2 * PAGE_SIZE)
		gra -= prefix;
	return gra;
}

/**
 * kvm_s390_logical_to_effective - convert guest logical to effective address
 * @vcpu: guest virtual cpu
 * @ga: guest logical address
 *
 * Convert a guest vcpu logical address to a guest vcpu effective address by
 * applying the rules of the vcpu's addressing mode defined by PSW bits 31
 * and 32 (extendended/basic addressing mode).
 *
 * Depending on the vcpu's addressing mode the upper 40 bits (24 bit addressing
 * mode), 33 bits (31 bit addressing mode) or no bits (64 bit addressing mode)
 * of @ga will be zeroed and the remaining bits will be returned.
 */
static inline unsigned long kvm_s390_logical_to_effective(struct kvm_vcpu *vcpu,
							  unsigned long ga)
{
	psw_t *psw = &vcpu->arch.sie_block->gpsw;

	if (psw_bits(*psw).eaba == PSW_BITS_AMODE_64BIT)
		return ga;
	if (psw_bits(*psw).eaba == PSW_BITS_AMODE_31BIT)
		return ga & ((1UL << 31) - 1);
	return ga & ((1UL << 24) - 1);
}

/*
 * put_guest_lc, read_guest_lc and write_guest_lc are guest access functions
 * which shall only be used to access the lowcore of a vcpu.
 * These functions should be used for e.g. interrupt handlers where no
 * guest memory access protection facilities, like key or low address
 * protection, are applicable.
 * At a later point guest vcpu lowcore access should happen via pinned
 * prefix pages, so that these pages can be accessed directly via the
 * kernel mapping. All of these *_lc functions can be removed then.
 */

/**
 * put_guest_lc - write a simple variable to a guest vcpu's lowcore
 * @vcpu: virtual cpu
 * @x: value to copy to guest
 * @gra: vcpu's destination guest real address
 *
 * Copies a simple value from kernel space to a guest vcpu's lowcore.
 * The size of the variable may be 1, 2, 4 or 8 bytes. The destination
 * must be located in the vcpu's lowcore. Otherwise the result is undefined.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * Note: an error indicates that either the kernel is out of memory or
 *	 the guest memory mapping is broken. In any case the best solution
 *	 would be to terminate the guest.
 *	 It is wrong to inject a guest exception.
 */
#define put_guest_lc(vcpu, x, gra)				\
({								\
	struct kvm_vcpu *__vcpu = (vcpu);			\
	__typeof__(*(gra)) __x = (x);				\
	unsigned long __gpa;					\
								\
	__gpa = (unsigned long)(gra);				\
	__gpa += kvm_s390_get_prefix(__vcpu);			\
	kvm_write_guest(__vcpu->kvm, __gpa, &__x, sizeof(__x));	\
})

/**
 * write_guest_lc - copy data from kernel space to guest vcpu's lowcore
 * @vcpu: virtual cpu
 * @gra: vcpu's source guest real address
 * @data: source address in kernel space
 * @len: number of bytes to copy
 *
 * Copy data from kernel space to guest vcpu's lowcore. The entire range must
 * be located within the vcpu's lowcore, otherwise the result is undefined.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * Note: an error indicates that either the kernel is out of memory or
 *	 the guest memory mapping is broken. In any case the best solution
 *	 would be to terminate the guest.
 *	 It is wrong to inject a guest exception.
 */
static inline __must_check
int write_guest_lc(struct kvm_vcpu *vcpu, unsigned long gra, void *data,
		   unsigned long len)
{
	unsigned long gpa = gra + kvm_s390_get_prefix(vcpu);

	return kvm_write_guest(vcpu->kvm, gpa, data, len);
}

/**
 * read_guest_lc - copy data from guest vcpu's lowcore to kernel space
 * @vcpu: virtual cpu
 * @gra: vcpu's source guest real address
 * @data: destination address in kernel space
 * @len: number of bytes to copy
 *
 * Copy data from guest vcpu's lowcore to kernel space. The entire range must
 * be located within the vcpu's lowcore, otherwise the result is undefined.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * Note: an error indicates that either the kernel is out of memory or
 *	 the guest memory mapping is broken. In any case the best solution
 *	 would be to terminate the guest.
 *	 It is wrong to inject a guest exception.
 */
static inline __must_check
int read_guest_lc(struct kvm_vcpu *vcpu, unsigned long gra, void *data,
		  unsigned long len)
{
	unsigned long gpa = gra + kvm_s390_get_prefix(vcpu);

	return kvm_read_guest(vcpu->kvm, gpa, data, len);
}

enum gacc_mode {
	GACC_FETCH,
	GACC_STORE,
	GACC_IFETCH,
};

int guest_translate_address(struct kvm_vcpu *vcpu, unsigned long gva,
			    u8 ar, unsigned long *gpa, enum gacc_mode mode);
int check_gva_range(struct kvm_vcpu *vcpu, unsigned long gva, u8 ar,
		    unsigned long length, enum gacc_mode mode);

int access_guest(struct kvm_vcpu *vcpu, unsigned long ga, u8 ar, void *data,
		 unsigned long len, enum gacc_mode mode);

int access_guest_real(struct kvm_vcpu *vcpu, unsigned long gra,
		      void *data, unsigned long len, enum gacc_mode mode);

/**
 * write_guest - copy data from kernel space to guest space
 * @vcpu: virtual cpu
 * @ga: guest address
 * @ar: access register
 * @data: source address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @data (kernel space) to @ga (guest address).
 * In order to copy data to guest space the PSW of the vcpu is inspected:
 * If DAT is off data will be copied to guest real or absolute memory.
 * If DAT is on data will be copied to the address space as specified by
 * the address space bits of the PSW:
 * Primary, secondary, home space or access register mode.
 * The addressing mode of the PSW is also inspected, so that address wrap
 * around is taken into account for 24-, 31- and 64-bit addressing mode,
 * if the to be copied data crosses page boundaries in guest address space.
 * In addition also low address and DAT protection are inspected before
 * copying any data (key protection is currently not implemented).
 *
 * This function modifies the 'struct kvm_s390_pgm_info pgm' member of @vcpu.
 * In case of an access exception (e.g. protection exception) pgm will contain
 * all data necessary so that a subsequent call to 'kvm_s390_inject_prog_vcpu()'
 * will inject a correct exception into the guest.
 * If no access exception happened, the contents of pgm are undefined when
 * this function returns.
 *
 * Returns:  - zero on success
 *	     - a negative value if e.g. the guest mapping is broken or in
 *	       case of out-of-memory. In this case the contents of pgm are
 *	       undefined. Also parts of @data may have been copied to guest
 *	       space.
 *	     - a positive value if an access exception happened. In this case
 *	       the returned value is the program interruption code and the
 *	       contents of pgm may be used to inject an exception into the
 *	       guest. No data has been copied to guest space.
 *
 * Note: in case an access exception is recognized no data has been copied to
 *	 guest space (this is also true, if the to be copied data would cross
 *	 one or more page boundaries in guest space).
 *	 Therefore this function may be used for nullifying and suppressing
 *	 instruction emulation.
 *	 It may also be used for terminating instructions, if it is undefined
 *	 if data has been changed in guest space in case of an exception.
 */
static inline __must_check
int write_guest(struct kvm_vcpu *vcpu, unsigned long ga, u8 ar, void *data,
		unsigned long len)
{
	return access_guest(vcpu, ga, ar, data, len, GACC_STORE);
}

/**
 * read_guest - copy data from guest space to kernel space
 * @vcpu: virtual cpu
 * @ga: guest address
 * @ar: access register
 * @data: destination address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @ga (guest address) to @data (kernel space).
 *
 * The behaviour of read_guest is identical to write_guest, except that
 * data will be copied from guest space to kernel space.
 */
static inline __must_check
int read_guest(struct kvm_vcpu *vcpu, unsigned long ga, u8 ar, void *data,
	       unsigned long len)
{
	return access_guest(vcpu, ga, ar, data, len, GACC_FETCH);
}

/**
 * read_guest_instr - copy instruction data from guest space to kernel space
 * @vcpu: virtual cpu
 * @ga: guest address
 * @data: destination address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from the given address (guest space) to @data (kernel
 * space).
 *
 * The behaviour of read_guest_instr is identical to read_guest, except that
 * instruction data will be read from primary space when in home-space or
 * address-space mode.
 */
static inline __must_check
int read_guest_instr(struct kvm_vcpu *vcpu, unsigned long ga, void *data,
		     unsigned long len)
{
	return access_guest(vcpu, ga, 0, data, len, GACC_IFETCH);
}

/**
 * write_guest_abs - copy data from kernel space to guest space absolute
 * @vcpu: virtual cpu
 * @gpa: guest physical (absolute) address
 * @data: source address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @data (kernel space) to @gpa (guest absolute address).
 * It is up to the caller to ensure that the entire guest memory range is
 * valid memory before calling this function.
 * Guest low address and key protection are not checked.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * If an error occurs data may have been copied partially to guest memory.
 */
static inline __must_check
int write_guest_abs(struct kvm_vcpu *vcpu, unsigned long gpa, void *data,
		    unsigned long len)
{
	return kvm_write_guest(vcpu->kvm, gpa, data, len);
}

/**
 * read_guest_abs - copy data from guest space absolute to kernel space
 * @vcpu: virtual cpu
 * @gpa: guest physical (absolute) address
 * @data: destination address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @gpa (guest absolute address) to @data (kernel space).
 * It is up to the caller to ensure that the entire guest memory range is
 * valid memory before calling this function.
 * Guest key protection is not checked.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * If an error occurs data may have been copied partially to kernel space.
 */
static inline __must_check
int read_guest_abs(struct kvm_vcpu *vcpu, unsigned long gpa, void *data,
		   unsigned long len)
{
	return kvm_read_guest(vcpu->kvm, gpa, data, len);
}

/**
 * write_guest_real - copy data from kernel space to guest space real
 * @vcpu: virtual cpu
 * @gra: guest real address
 * @data: source address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @data (kernel space) to @gra (guest real address).
 * It is up to the caller to ensure that the entire guest memory range is
 * valid memory before calling this function.
 * Guest low address and key protection are not checked.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * If an error occurs data may have been copied partially to guest memory.
 */
static inline __must_check
int write_guest_real(struct kvm_vcpu *vcpu, unsigned long gra, void *data,
		     unsigned long len)
{
	return access_guest_real(vcpu, gra, data, len, 1);
}

/**
 * read_guest_real - copy data from guest space real to kernel space
 * @vcpu: virtual cpu
 * @gra: guest real address
 * @data: destination address in kernel space
 * @len: number of bytes to copy
 *
 * Copy @len bytes from @gra (guest real address) to @data (kernel space).
 * It is up to the caller to ensure that the entire guest memory range is
 * valid memory before calling this function.
 * Guest key protection is not checked.
 *
 * Returns zero on success or -EFAULT on error.
 *
 * If an error occurs data may have been copied partially to kernel space.
 */
static inline __must_check
int read_guest_real(struct kvm_vcpu *vcpu, unsigned long gra, void *data,
		    unsigned long len)
{
	return access_guest_real(vcpu, gra, data, len, 0);
}

void ipte_lock(struct kvm_vcpu *vcpu);
void ipte_unlock(struct kvm_vcpu *vcpu);
int ipte_lock_held(struct kvm_vcpu *vcpu);
int kvm_s390_check_low_addr_prot_real(struct kvm_vcpu *vcpu, unsigned long gra);

int kvm_s390_shadow_fault(struct kvm_vcpu *vcpu, struct gmap *shadow,
			  unsigned long saddr);

#endif /* __KVM_S390_GACCESS_H */
