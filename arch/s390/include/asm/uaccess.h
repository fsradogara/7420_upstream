/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/asm-s390/uaccess.h
 *
 *  S390 version
 *    Copyright (C) 1999,2000 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *  S390 version
 *    Copyright IBM Corp. 1999, 2000
 *    Author(s): Hartmut Penner (hp@de.ibm.com),
 *               Martin Schwidefsky (schwidefsky@de.ibm.com)
 *
 *  Derived from "include/asm-i386/uaccess.h"
 */
#ifndef __S390_UACCESS_H
#define __S390_UACCESS_H

/*
 * User space memory access functions
 */
#include <asm/processor.h>
#include <asm/ctl_reg.h>
#include <asm/extable.h>
#include <asm/facility.h>

/*
 * The fs value determines whether argument validity checking should be
 * performed or not.  If get_fs() == USER_DS, checking is performed, with
 * get_fs() == KERNEL_DS, checking is bypassed.
 *
 * For historical reasons, these macros are grossly misnamed.
 */

#define KERNEL_DS	(0)
#define KERNEL_DS_SACF	(1)
#define USER_DS		(2)
#define USER_DS_SACF	(3)

#define get_ds()        (KERNEL_DS)
#define get_fs()        (current->thread.mm_segment)
#define segment_eq(a,b) (((a) & 2) == ((b) & 2))


static inline int __access_ok(const void __user *addr, unsigned long size)
{
	return 1;
}
#define access_ok(type,addr,size) __access_ok(addr,size)
static inline void set_fs(mm_segment_t fs)
{
	current->thread.mm_segment = fs;
	if (uaccess_kernel()) {
		set_cpu_flag(CIF_ASCE_SECONDARY);
		__ctl_load(S390_lowcore.kernel_asce, 7, 7);
	} else {
		clear_cpu_flag(CIF_ASCE_SECONDARY);
		__ctl_load(S390_lowcore.user_asce, 7, 7);
	}
}
void set_fs(mm_segment_t fs);

static inline int __range_ok(unsigned long addr, unsigned long size)
{
	return 1;
}

#define __access_ok(addr, size)				\
({							\
	__chk_user_ptr(addr);				\
	__range_ok((unsigned long)(addr), (size));	\
})

#define access_ok(type, addr, size) __access_ok(addr, size)

unsigned long __must_check
raw_copy_from_user(void *to, const void __user *from, unsigned long n);

struct exception_table_entry
{
        unsigned long insn, fixup;
};

struct uaccess_ops {
	size_t (*copy_from_user)(size_t, const void __user *, void *);
	size_t (*copy_from_user_small)(size_t, const void __user *, void *);
	size_t (*copy_to_user)(size_t, void __user *, const void *);
	size_t (*copy_to_user_small)(size_t, void __user *, const void *);
	size_t (*copy_in_user)(size_t, void __user *, const void __user *);
	size_t (*clear_user)(size_t, void __user *);
	size_t (*strnlen_user)(size_t, const char __user *);
	size_t (*strncpy_from_user)(size_t, const char __user *, char *);
	int (*futex_atomic_op)(int op, int __user *, int oparg, int *old);
	int (*futex_atomic_cmpxchg)(int __user *, int old, int new);
};

extern struct uaccess_ops uaccess;
extern struct uaccess_ops uaccess_std;
extern struct uaccess_ops uaccess_mvcos;
extern struct uaccess_ops uaccess_mvcos_switch;
extern struct uaccess_ops uaccess_pt;

static inline int __put_user_fn(size_t size, void __user *ptr, void *x)
{
	size = uaccess.copy_to_user_small(size, ptr, x);
	return size ? -EFAULT : size;
}

static inline int __get_user_fn(size_t size, const void __user *ptr, void *x)
{
	size = uaccess.copy_from_user_small(size, ptr, x);
	return size ? -EFAULT : size;
}

	int insn, fixup;
};
unsigned long __must_check
raw_copy_to_user(void __user *to, const void *from, unsigned long n);

#define INLINE_COPY_FROM_USER
#define INLINE_COPY_TO_USER

#ifdef CONFIG_HAVE_MARCH_Z10_FEATURES

#define __put_get_user_asm(to, from, size, spec)		\
({								\
	register unsigned long __reg0 asm("0") = spec;		\
	int __rc;						\
								\
	asm volatile(						\
		"0:	mvcos	%1,%3,%2\n"			\
		"1:	xr	%0,%0\n"			\
		"2:\n"						\
		".pushsection .fixup, \"ax\"\n"			\
		"3:	lhi	%0,%5\n"			\
		"	jg	2b\n"				\
		".popsection\n"					\
		EX_TABLE(0b,3b) EX_TABLE(1b,3b)			\
		: "=d" (__rc), "+Q" (*(to))			\
		: "d" (size), "Q" (*(from)),			\
		  "d" (__reg0), "K" (-EFAULT)			\
		: "cc");					\
	__rc;							\
})

static inline int __put_user_fn(void *x, void __user *ptr, unsigned long size)
{
	unsigned long spec = 0x010000UL;
	int rc;

	switch (size) {
	case 1:
		rc = __put_get_user_asm((unsigned char __user *)ptr,
					(unsigned char *)x,
					size, spec);
		break;
	case 2:
		rc = __put_get_user_asm((unsigned short __user *)ptr,
					(unsigned short *)x,
					size, spec);
		break;
	case 4:
		rc = __put_get_user_asm((unsigned int __user *)ptr,
					(unsigned int *)x,
					size, spec);
		break;
	case 8:
		rc = __put_get_user_asm((unsigned long __user *)ptr,
					(unsigned long *)x,
					size, spec);
		break;
	}
	return rc;
}

static inline int __get_user_fn(void *x, const void __user *ptr, unsigned long size)
{
	unsigned long spec = 0x01UL;
	int rc;

	switch (size) {
	case 1:
		rc = __put_get_user_asm((unsigned char *)x,
					(unsigned char __user *)ptr,
					size, spec);
		break;
	case 2:
		rc = __put_get_user_asm((unsigned short *)x,
					(unsigned short __user *)ptr,
					size, spec);
		break;
	case 4:
		rc = __put_get_user_asm((unsigned int *)x,
					(unsigned int __user *)ptr,
					size, spec);
		break;
	case 8:
		rc = __put_get_user_asm((unsigned long *)x,
					(unsigned long __user *)ptr,
					size, spec);
		break;
	}
	return rc;
}

#else /* CONFIG_HAVE_MARCH_Z10_FEATURES */

static inline int __put_user_fn(void *x, void __user *ptr, unsigned long size)
{
	size = raw_copy_to_user(ptr, x, size);
	return size ? -EFAULT : 0;
}

static inline int __get_user_fn(void *x, const void __user *ptr, unsigned long size)
{
	size = raw_copy_from_user(x, ptr, size);
	return size ? -EFAULT : 0;
}

#endif /* CONFIG_HAVE_MARCH_Z10_FEATURES */

/*
 * These are the main single-value transfer routines.  They automatically
 * use the right size if we just have the right pointer type.
 */
#define __put_user(x, ptr) \
({								\
	__typeof__(*(ptr)) __x = (x);				\
	int __pu_err = -EFAULT;					\
        __chk_user_ptr(ptr);                                    \
	switch (sizeof (*(ptr))) {				\
	case 1:							\
	case 2:							\
	case 4:							\
	case 8:							\
		__pu_err = __put_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		__pu_err = __put_user_fn(&__x, ptr,		\
					 sizeof(*(ptr)));	\
		break;						\
	default:						\
		__put_user_bad();				\
		break;						\
	 }							\
	__builtin_expect(__pu_err, 0);				\
})

#define put_user(x, ptr)					\
({								\
	might_sleep();						\
	might_fault();						\
	__put_user(x, ptr);					\
})


extern int __put_user_bad(void) __attribute__((noreturn));
int __put_user_bad(void) __attribute__((noreturn));

#define __get_user(x, ptr)					\
({								\
	int __gu_err = -EFAULT;					\
	__chk_user_ptr(ptr);					\
	switch (sizeof(*(ptr))) {				\
	case 1: {						\
		unsigned char __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		unsigned char __x = 0;				\
		__gu_err = __get_user_fn(&__x, ptr,		\
					 sizeof(*(ptr)));	\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	case 2: {						\
		unsigned short __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		unsigned short __x = 0;				\
		__gu_err = __get_user_fn(&__x, ptr,		\
					 sizeof(*(ptr)));	\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	case 4: {						\
		unsigned int __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		unsigned int __x = 0;				\
		__gu_err = __get_user_fn(&__x, ptr,		\
					 sizeof(*(ptr)));	\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	case 8: {						\
		unsigned long long __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		unsigned long long __x = 0;			\
		__gu_err = __get_user_fn(&__x, ptr,		\
					 sizeof(*(ptr)));	\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	default:						\
		__get_user_bad();				\
		break;						\
	}							\
	__builtin_expect(__gu_err, 0);				\
})

#define get_user(x, ptr)					\
({								\
	might_sleep();						\
	__get_user(x, ptr);					\
})

extern int __get_user_bad(void) __attribute__((noreturn));
	might_fault();						\
	__get_user(x, ptr);					\
})

int __get_user_bad(void) __attribute__((noreturn));

#define __put_user_unaligned __put_user
#define __get_user_unaligned __get_user

/**
 * __copy_to_user: - Copy a block of data into user space, with less checking.
 * @to:   Destination address, in user space.
 * @from: Source address, in kernel space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 *
 * Copy data from kernel space to user space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
static inline unsigned long __must_check
__copy_to_user(void __user *to, const void *from, unsigned long n)
{
	if (__builtin_constant_p(n) && (n <= 256))
		return uaccess.copy_to_user_small(n, to, from);
	else
		return uaccess.copy_to_user(n, to, from);
}

#define __copy_to_user_inatomic __copy_to_user
#define __copy_from_user_inatomic __copy_from_user

/**
 * copy_to_user: - Copy a block of data into user space.
 * @to:   Destination address, in user space.
 * @from: Source address, in kernel space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Copy data from kernel space to user space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
static inline unsigned long __must_check
copy_to_user(void __user *to, const void *from, unsigned long n)
{
	might_sleep();
	if (access_ok(VERIFY_WRITE, to, n))
		n = __copy_to_user(to, from, n);
	return n;
}

/**
 * __copy_from_user: - Copy a block of data from user space, with less checking.
 * @to:   Destination address, in kernel space.
 * @from: Source address, in user space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 *
 * Copy data from user space to kernel space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
static inline unsigned long __must_check
__copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (__builtin_constant_p(n) && (n <= 256))
		return uaccess.copy_from_user_small(n, from, to);
	else
		return uaccess.copy_from_user(n, from, to);
}
	might_fault();
	return __copy_to_user(to, from, n);
}

void copy_from_user_overflow(void)
#ifdef CONFIG_DEBUG_STRICT_USER_COPY_CHECKS
__compiletime_warning("copy_from_user() buffer size is not provably correct")
#endif
;

/**
 * copy_from_user: - Copy a block of data from user space.
 * @to:   Destination address, in kernel space.
 * @from: Source address, in user space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Copy data from user space to kernel space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
static inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	might_sleep();
	if (access_ok(VERIFY_READ, from, n))
		n = __copy_from_user(to, from, n);
	else
		memset(to, 0, n);
	return n;
}

static inline unsigned long __must_check
__copy_in_user(void __user *to, const void __user *from, unsigned long n)
{
	return uaccess.copy_in_user(n, to, from);
}
	unsigned int sz = __compiletime_object_size(to);

	might_fault();
	if (unlikely(sz != -1 && sz < n)) {
		copy_from_user_overflow();
		return n;
	}
	return __copy_from_user(to, from, n);
}

unsigned long __must_check
__copy_in_user(void __user *to, const void __user *from, unsigned long n);

static inline unsigned long __must_check
copy_in_user(void __user *to, const void __user *from, unsigned long n)
{
	might_sleep();
	if (__access_ok(from,n) && __access_ok(to,n))
		n = __copy_in_user(to, from, n);
	return n;
	might_fault();
	return __copy_in_user(to, from, n);
}
unsigned long __must_check
raw_copy_in_user(void __user *to, const void __user *from, unsigned long n);

/*
 * Copy a null terminated string from userspace.
 */
static inline long __must_check
strncpy_from_user(char *dst, const char __user *src, long count)
{
        long res = -EFAULT;
        might_sleep();
        if (access_ok(VERIFY_READ, src, 1))
		res = uaccess.strncpy_from_user(count, src, dst);
        return res;
}

static inline unsigned long
strnlen_user(const char __user * src, unsigned long n)
{
	might_sleep();
	return uaccess.strnlen_user(n, src);

long __strncpy_from_user(char *dst, const char __user *src, long count);

static inline long __must_check
strncpy_from_user(char *dst, const char __user *src, long count)
{
	might_fault();
	return __strncpy_from_user(dst, src, count);
}

unsigned long __must_check __strnlen_user(const char __user *src, unsigned long count);

static inline unsigned long strnlen_user(const char __user *src, unsigned long n)
{
	might_fault();
	return __strnlen_user(src, n);
}

/**
 * strlen_user: - Get the size of a string in user space.
 * @str: The string to measure.
 *
 * Context: User context only.  This function may sleep.
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * On exception, returns 0.
 *
 * If there is a limit on the length of a valid string, you may wish to
 * consider using strnlen_user() instead.
 */
#define strlen_user(str) strnlen_user(str, ~0UL)

/*
 * Zero Userspace
 */

static inline unsigned long __must_check
__clear_user(void __user *to, unsigned long n)
{
	return uaccess.clear_user(n, to);
}

static inline unsigned long __must_check
clear_user(void __user *to, unsigned long n)
{
	might_sleep();
	if (access_ok(VERIFY_WRITE, to, n))
		n = uaccess.clear_user(n, to);
	return n;
}
unsigned long __must_check __clear_user(void __user *to, unsigned long size);

static inline unsigned long __must_check clear_user(void __user *to, unsigned long n)
{
	might_fault();
	return __clear_user(to, n);
}

int copy_to_user_real(void __user *dest, void *src, unsigned long count);
void s390_kernel_write(void *dst, const void *src, size_t size);

#endif /* __S390_UACCESS_H */
