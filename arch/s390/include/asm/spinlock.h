/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/asm-s390/spinlock.h
 *
 *  S390 version
 *    Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *  S390 version
 *    Copyright IBM Corp. 1999
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com)
 *
 *  Derived from "include/asm-i386/spinlock.h"
 */

#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <linux/smp.h>
#include <asm/atomic_ops.h>
#include <asm/barrier.h>
#include <asm/processor.h>
#include <asm/alternative.h>

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 2)

static inline int
_raw_compare_and_swap(volatile unsigned int *lock,
		      unsigned int old, unsigned int new)
{
	asm volatile(
		"	cs	%0,%3,%1"
		: "=d" (old), "=Q" (*lock)
		: "0" (old), "d" (new), "Q" (*lock)
		: "cc", "memory" );
	return old;
}

#else /* __GNUC__ */

static inline int
_raw_compare_and_swap(volatile unsigned int *lock,
		      unsigned int old, unsigned int new)
{
	asm volatile(
		"	cs	%0,%3,0(%4)"
		: "=d" (old), "=m" (*lock)
		: "0" (old), "d" (new), "a" (lock), "m" (*lock)
		: "cc", "memory" );
	return old;
}

#endif /* __GNUC__ */

#define SPINLOCK_LOCKVAL (S390_lowcore.spinlock_lockval)

extern int spin_retry;

#ifndef CONFIG_SMP
static inline bool arch_vcpu_is_preempted(int cpu) { return false; }
#else
bool arch_vcpu_is_preempted(int cpu);
#endif

#define vcpu_is_preempted arch_vcpu_is_preempted

/*
 * Simple spin lock operations.  There are two variants, one clears IRQ's
 * on the local processor, one does not.
 *
 * We make no fairness assumptions. They have a cost.
 *
 * (the type definitions are in asm/spinlock_types.h)
 */

#define __raw_spin_is_locked(x) ((x)->owner_cpu != 0)
#define __raw_spin_unlock_wait(lock) \
	do { while (__raw_spin_is_locked(lock)) \
		 _raw_spin_relax(lock); } while (0)

extern void _raw_spin_lock_wait(raw_spinlock_t *);
extern void _raw_spin_lock_wait_flags(raw_spinlock_t *, unsigned long flags);
extern int _raw_spin_trylock_retry(raw_spinlock_t *);
extern void _raw_spin_relax(raw_spinlock_t *lock);

static inline void __raw_spin_lock(raw_spinlock_t *lp)
{
	int old;

	old = _raw_compare_and_swap(&lp->owner_cpu, 0, ~smp_processor_id());
	if (likely(old == 0))
		return;
	_raw_spin_lock_wait(lp);
}

static inline void __raw_spin_lock_flags(raw_spinlock_t *lp,
					 unsigned long flags)
{
	int old;

	old = _raw_compare_and_swap(&lp->owner_cpu, 0, ~smp_processor_id());
	if (likely(old == 0))
		return;
	_raw_spin_lock_wait_flags(lp, flags);
}

static inline int __raw_spin_trylock(raw_spinlock_t *lp)
{
	int old;

	old = _raw_compare_and_swap(&lp->owner_cpu, 0, ~smp_processor_id());
	if (likely(old == 0))
		return 1;
	return _raw_spin_trylock_retry(lp);
}

static inline void __raw_spin_unlock(raw_spinlock_t *lp)
{
	_raw_compare_and_swap(&lp->owner_cpu, lp->owner_cpu, 0);
}
		
void arch_lock_relax(unsigned int cpu);
void arch_lock_relax(int cpu);
void arch_spin_relax(arch_spinlock_t *lock);
#define arch_spin_relax	arch_spin_relax

void arch_spin_lock_wait(arch_spinlock_t *);
int arch_spin_trylock_retry(arch_spinlock_t *);
void arch_spin_lock_setup(int cpu);

static inline u32 arch_spin_lockval(int cpu)
{
	return cpu + 1;
}

static inline int arch_spin_value_unlocked(arch_spinlock_t lock)
{
	return lock.lock == 0;
}

static inline int arch_spin_is_locked(arch_spinlock_t *lp)
{
	return READ_ONCE(lp->lock) != 0;
}

static inline int arch_spin_trylock_once(arch_spinlock_t *lp)
{
	barrier();
	return likely(__atomic_cmpxchg_bool(&lp->lock, 0, SPINLOCK_LOCKVAL));
}

static inline void arch_spin_lock(arch_spinlock_t *lp)
{
	if (!arch_spin_trylock_once(lp))
		arch_spin_lock_wait(lp);
}

static inline void arch_spin_lock_flags(arch_spinlock_t *lp,
					unsigned long flags)
{
	if (!arch_spin_trylock_once(lp))
		arch_spin_lock_wait(lp);
}
#define arch_spin_lock_flags	arch_spin_lock_flags

static inline int arch_spin_trylock(arch_spinlock_t *lp)
{
	if (!arch_spin_trylock_once(lp))
		return arch_spin_trylock_retry(lp);
	return 1;
}

static inline void arch_spin_unlock(arch_spinlock_t *lp)
{
	typecheck(int, lp->lock);
	asm volatile(
		ALTERNATIVE("", ".long 0xb2fa0070", 49)	/* NIAI 7 */
		"	sth	%1,%0\n"
		: "=Q" (((unsigned short *) &lp->lock)[1])
		: "d" (0) : "cc", "memory");
}

/*
 * Read-write spinlocks, allowing multiple readers
 * but only one writer.
 *
 * NOTE! it is quite common to have readers in interrupts
 * but no interrupt writers. For those circumstances we
 * can "mix" irq-safe locks - any writer needs to get a
 * irq-safe write-lock, but readers can get non-irqsafe
 * read-locks.
 */

/**
 * read_can_lock - would read_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define __raw_read_can_lock(x) ((int)(x)->lock >= 0)
#define arch_read_can_lock(x) ((int)(x)->lock >= 0)

/**
 * write_can_lock - would write_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define __raw_write_can_lock(x) ((x)->lock == 0)

extern void _raw_read_lock_wait(raw_rwlock_t *lp);
extern int _raw_read_trylock_retry(raw_rwlock_t *lp);
extern void _raw_write_lock_wait(raw_rwlock_t *lp);
extern int _raw_write_trylock_retry(raw_rwlock_t *lp);

static inline void __raw_read_lock(raw_rwlock_t *rw)
{
	unsigned int old;
	old = rw->lock & 0x7fffffffU;
	if (_raw_compare_and_swap(&rw->lock, old, old + 1) != old)
		_raw_read_lock_wait(rw);
}

static inline void __raw_read_unlock(raw_rwlock_t *rw)
{
	unsigned int old, cmp;

	old = rw->lock;
	do {
		cmp = old;
		old = _raw_compare_and_swap(&rw->lock, old, old - 1);
	} while (cmp != old);
}

static inline void __raw_write_lock(raw_rwlock_t *rw)
{
	if (unlikely(_raw_compare_and_swap(&rw->lock, 0, 0x80000000) != 0))
		_raw_write_lock_wait(rw);
}

static inline void __raw_write_unlock(raw_rwlock_t *rw)
{
	_raw_compare_and_swap(&rw->lock, 0x80000000, 0);
}

static inline int __raw_read_trylock(raw_rwlock_t *rw)
{
	unsigned int old;
	old = rw->lock & 0x7fffffffU;
	if (likely(_raw_compare_and_swap(&rw->lock, old, old + 1) == old))
		return 1;
	return _raw_read_trylock_retry(rw);
}

static inline int __raw_write_trylock(raw_rwlock_t *rw)
{
	if (likely(_raw_compare_and_swap(&rw->lock, 0, 0x80000000) == 0))
		return 1;
	return _raw_write_trylock_retry(rw);
}

#define _raw_read_relax(lock)	cpu_relax()
#define _raw_write_relax(lock)	cpu_relax()
#define arch_write_can_lock(x) ((x)->lock == 0)

extern int _raw_read_trylock_retry(arch_rwlock_t *lp);
extern int _raw_write_trylock_retry(arch_rwlock_t *lp);

#define arch_read_lock_flags(lock, flags) arch_read_lock(lock)
#define arch_write_lock_flags(lock, flags) arch_write_lock(lock)

static inline int arch_read_trylock_once(arch_rwlock_t *rw)
{
	int old = ACCESS_ONCE(rw->lock);
	return likely(old >= 0 &&
		      __atomic_cmpxchg_bool(&rw->lock, old, old + 1));
}

static inline int arch_write_trylock_once(arch_rwlock_t *rw)
{
	int old = ACCESS_ONCE(rw->lock);
	return likely(old == 0 &&
		      __atomic_cmpxchg_bool(&rw->lock, 0, 0x80000000));
}

#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES

#define __RAW_OP_OR	"lao"
#define __RAW_OP_AND	"lan"
#define __RAW_OP_ADD	"laa"

#define __RAW_LOCK(ptr, op_val, op_string)		\
({							\
	int old_val;					\
							\
	typecheck(int *, ptr);				\
	asm volatile(					\
		op_string "	%0,%2,%1\n"		\
		"bcr	14,0\n"				\
		: "=d" (old_val), "+Q" (*ptr)		\
		: "d" (op_val)				\
		: "cc", "memory");			\
	old_val;					\
})

#define __RAW_UNLOCK(ptr, op_val, op_string)		\
({							\
	int old_val;					\
							\
	typecheck(int *, ptr);				\
	asm volatile(					\
		op_string "	%0,%2,%1\n"		\
		: "=d" (old_val), "+Q" (*ptr)		\
		: "d" (op_val)				\
		: "cc", "memory");			\
	old_val;					\
})

extern void _raw_read_lock_wait(arch_rwlock_t *lp);
extern void _raw_write_lock_wait(arch_rwlock_t *lp, int prev);
#define arch_read_relax(rw) barrier()
#define arch_write_relax(rw) barrier()

void arch_read_lock_wait(arch_rwlock_t *lp);
void arch_write_lock_wait(arch_rwlock_t *lp);

static inline void arch_read_lock(arch_rwlock_t *rw)
{
	int old;

	old = __atomic_add(1, &rw->cnts);
	if (old & 0xffff0000)
		arch_read_lock_wait(rw);
}

static inline void arch_read_unlock(arch_rwlock_t *rw)
{
	__atomic_add_const_barrier(-1, &rw->cnts);
}

static inline void arch_write_lock(arch_rwlock_t *rw)
{
	if (!__atomic_cmpxchg_bool(&rw->cnts, 0, 0x30000))
		arch_write_lock_wait(rw);
}

static inline void arch_write_unlock(arch_rwlock_t *rw)
{
	__atomic_add_barrier(-0x30000, &rw->cnts);
}


static inline int arch_read_trylock(arch_rwlock_t *rw)
{
	int old;

	old = READ_ONCE(rw->cnts);
	return (!(old & 0xffff0000) &&
		__atomic_cmpxchg_bool(&rw->cnts, old, old + 1));
}

static inline int arch_write_trylock(arch_rwlock_t *rw)
{
	int old;

	old = READ_ONCE(rw->cnts);
	return !old && __atomic_cmpxchg_bool(&rw->cnts, 0, 0x30000);
}

#endif /* __ASM_SPINLOCK_H */
