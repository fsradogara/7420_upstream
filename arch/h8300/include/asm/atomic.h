/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARCH_H8300_ATOMIC__
#define __ARCH_H8300_ATOMIC__

#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/cmpxchg.h>
#include <asm/irqflags.h>

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

typedef struct { int counter; } atomic_t;
#define ATOMIC_INIT(i)	{ (i) }

#define atomic_read(v)		((v)->counter)
#define atomic_set(v, i)	(((v)->counter) = i)

#include <asm/system.h>
#include <linux/kernel.h>

static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int ret,flags;
	local_irq_save(flags);
	ret = v->counter += i;
	local_irq_restore(flags);
	return ret;
}

#define atomic_add(i, v) atomic_add_return(i, v)
#define atomic_add_negative(a, v)	(atomic_add_return((a), (v)) < 0)

static __inline__ int atomic_sub_return(int i, atomic_t *v)
{
	int ret,flags;
	local_irq_save(flags);
	ret = v->counter -= i;
	local_irq_restore(flags);
	return ret;
}

#define atomic_sub(i, v) atomic_sub_return(i, v)
#define atomic_sub_and_test(i,v) (atomic_sub_return(i, v) == 0)

static __inline__ int atomic_inc_return(atomic_t *v)
{
	int ret,flags;
	local_irq_save(flags);
	v->counter++;
	ret = v->counter;
	local_irq_restore(flags);
	return ret;
}

#define atomic_inc(v) atomic_inc_return(v)

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)

static __inline__ int atomic_dec_return(atomic_t *v)
{
	int ret,flags;
	local_irq_save(flags);
	--v->counter;
	ret = v->counter;
	local_irq_restore(flags);
	return ret;
}

#define atomic_dec(v) atomic_dec_return(v)

static __inline__ int atomic_dec_and_test(atomic_t *v)
{
	int ret,flags;
	local_irq_save(flags);
	--v->counter;
	ret = v->counter;
	local_irq_restore(flags);
	return ret == 0;
}
#define ATOMIC_INIT(i)	{ (i) }

#define atomic_read(v)		READ_ONCE((v)->counter)
#define atomic_set(v, i)	WRITE_ONCE(((v)->counter), (i))

#define ATOMIC_OP_RETURN(op, c_op)				\
static inline int atomic_##op##_return(int i, atomic_t *v)	\
{								\
	h8300flags flags;					\
	int ret;						\
								\
	flags = arch_local_irq_save();				\
	ret = v->counter c_op i;				\
	arch_local_irq_restore(flags);				\
	return ret;						\
}

#define ATOMIC_FETCH_OP(op, c_op)				\
static inline int atomic_fetch_##op(int i, atomic_t *v)		\
{								\
	h8300flags flags;					\
	int ret;						\
								\
	flags = arch_local_irq_save();				\
	ret = v->counter;					\
	v->counter c_op i;					\
	arch_local_irq_restore(flags);				\
	return ret;						\
}

#define ATOMIC_OP(op, c_op)					\
static inline void atomic_##op(int i, atomic_t *v)		\
{								\
	h8300flags flags;					\
								\
	flags = arch_local_irq_save();				\
	v->counter c_op i;					\
	arch_local_irq_restore(flags);				\
}

ATOMIC_OP_RETURN(add, +=)
ATOMIC_OP_RETURN(sub, -=)

#define ATOMIC_OPS(op, c_op)					\
	ATOMIC_OP(op, c_op)					\
	ATOMIC_FETCH_OP(op, c_op)

ATOMIC_OPS(and, &=)
ATOMIC_OPS(or,  |=)
ATOMIC_OPS(xor, ^=)
ATOMIC_OPS(add, +=)
ATOMIC_OPS(sub, -=)

#undef ATOMIC_OPS
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	int ret;
	unsigned long flags;

	local_irq_save(flags);
	ret = v->counter;
	if (likely(ret == old))
		v->counter = new;
	local_irq_restore(flags);
	return ret;
}

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
	int ret;
	unsigned long flags;

	local_irq_save(flags);
	ret = v->counter;
	if (ret != u)
		v->counter += a;
	local_irq_restore(flags);
	return ret != u;
}
#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)

static __inline__ void atomic_clear_mask(unsigned long mask, unsigned long *v)
{
	__asm__ __volatile__("stc ccr,r1l\n\t"
	                     "orc #0x80,ccr\n\t"
	                     "mov.l %0,er0\n\t"
	                     "and.l %1,er0\n\t"
	                     "mov.l er0,%0\n\t"
	                     "ldc r1l,ccr" 
                             : "=m" (*v) : "g" (~(mask)) :"er0","er1");
}

static __inline__ void atomic_set_mask(unsigned long mask, unsigned long *v)
{
	__asm__ __volatile__("stc ccr,r1l\n\t"
	                     "orc #0x80,ccr\n\t"
	                     "mov.l %0,er0\n\t"
	                     "or.l %1,er0\n\t"
	                     "mov.l er0,%0\n\t"
	                     "ldc r1l,ccr" 
                             : "=m" (*v) : "g" (mask) :"er0","er1");
}

/* Atomic operations are already serializing */
#define smp_mb__before_atomic_dec()    barrier()
#define smp_mb__after_atomic_dec() barrier()
#define smp_mb__before_atomic_inc()    barrier()
#define smp_mb__after_atomic_inc() barrier()

#include <asm-generic/atomic.h>
	h8300flags flags;

	flags = arch_local_irq_save();
	ret = v->counter;
	if (likely(ret == old))
		v->counter = new;
	arch_local_irq_restore(flags);
	return ret;
}

static inline int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
	int ret;
	h8300flags flags;

	flags = arch_local_irq_save();
	ret = v->counter;
	if (ret != u)
		v->counter += a;
	arch_local_irq_restore(flags);
	return ret;
}
#define atomic_fetch_add_unless		atomic_fetch_add_unless

#endif /* __ARCH_H8300_ATOMIC __ */
