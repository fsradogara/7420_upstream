/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ALPHA_ATOMIC_H
#define _ALPHA_ATOMIC_H

#include <asm/barrier.h>
#include <asm/system.h>
#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc...
 *
 * But use these as seldom as possible since they are much slower
 * than regular operations.
 */

/*
 * To ensure dependency ordering is preserved for the _relaxed and
 * _release atomics, an smp_read_barrier_depends() is unconditionally
 * inserted into the _relaxed variants, which are used to build the
 * barriered versions. Avoid redundant back-to-back fences in the
 * _acquire and _fence versions.
 */
#define __atomic_acquire_fence()
#define __atomic_post_full_fence()

/*
 * Counter is volatile to make sure gcc doesn't try to be clever
 * and move things around on us. We need to use _exactly_ the address
 * the user gave us, not some alias that contains the same information.
 */
typedef struct { volatile int counter; } atomic_t;
typedef struct { volatile long counter; } atomic64_t;

#define ATOMIC_INIT(i)		( (atomic_t) { (i) } )
#define ATOMIC64_INIT(i)	( (atomic64_t) { (i) } )

#define atomic_read(v)		((v)->counter + 0)
#define atomic64_read(v)	((v)->counter + 0)

#define atomic_set(v,i)		((v)->counter = (i))
#define atomic64_set(v,i)	((v)->counter = (i))
#define ATOMIC_INIT(i)		{ (i) }
#define ATOMIC64_INIT(i)	{ (i) }

#define atomic_read(v)		READ_ONCE((v)->counter)
#define atomic64_read(v)	READ_ONCE((v)->counter)

#define atomic_set(v,i)		WRITE_ONCE((v)->counter, (i))
#define atomic64_set(v,i)	WRITE_ONCE((v)->counter, (i))

/*
 * To get proper branch prediction for the main line, we must branch
 * forward to code at the end of this object's .text section, then
 * branch back to restart the operation.
 */

static __inline__ void atomic_add(int i, atomic_t * v)
{
	unsigned long temp;
	__asm__ __volatile__(
	"1:	ldl_l %0,%1\n"
	"	addl %0,%2,%0\n"
	"	stl_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter)
	:"Ir" (i), "m" (v->counter));
}

static __inline__ void atomic64_add(long i, atomic64_t * v)
{
	unsigned long temp;
	__asm__ __volatile__(
	"1:	ldq_l %0,%1\n"
	"	addq %0,%2,%0\n"
	"	stq_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter)
	:"Ir" (i), "m" (v->counter));
}

static __inline__ void atomic_sub(int i, atomic_t * v)
{
	unsigned long temp;
	__asm__ __volatile__(
	"1:	ldl_l %0,%1\n"
	"	subl %0,%2,%0\n"
	"	stl_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter)
	:"Ir" (i), "m" (v->counter));
}

static __inline__ void atomic64_sub(long i, atomic64_t * v)
{
	unsigned long temp;
	__asm__ __volatile__(
	"1:	ldq_l %0,%1\n"
	"	subq %0,%2,%0\n"
	"	stq_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter)
	:"Ir" (i), "m" (v->counter));
}


/*
 * Same as above, but return the result value
 */
static inline int atomic_add_return(int i, atomic_t *v)
{
	long temp, result;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldl_l %0,%1\n"
	"	addl %0,%3,%2\n"
	"	addl %0,%3,%0\n"
	"	stl_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)
	:"Ir" (i), "m" (v->counter) : "memory");
	smp_mb();
	return result;
}

static __inline__ long atomic64_add_return(long i, atomic64_t * v)
{
	long temp, result;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldq_l %0,%1\n"
	"	addq %0,%3,%2\n"
	"	addq %0,%3,%0\n"
	"	stq_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)
	:"Ir" (i), "m" (v->counter) : "memory");
	smp_mb();
	return result;
}

static __inline__ long atomic_sub_return(int i, atomic_t * v)
{
	long temp, result;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldl_l %0,%1\n"
	"	subl %0,%3,%2\n"
	"	subl %0,%3,%0\n"
	"	stl_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)
	:"Ir" (i), "m" (v->counter) : "memory");
	smp_mb();
	return result;
}

static __inline__ long atomic64_sub_return(long i, atomic64_t * v)
{
	long temp, result;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldq_l %0,%1\n"
	"	subq %0,%3,%2\n"
	"	subq %0,%3,%0\n"
	"	stq_c %0,%1\n"
	"	beq %0,2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)
	:"Ir" (i), "m" (v->counter) : "memory");
	smp_mb();
	return result;
}
#define ATOMIC_OP(op, asm_op)						\
static __inline__ void atomic_##op(int i, atomic_t * v)			\
{									\
	unsigned long temp;						\
	__asm__ __volatile__(						\
	"1:	ldl_l %0,%1\n"						\
	"	" #asm_op " %0,%2,%0\n"					\
	"	stl_c %0,%1\n"						\
	"	beq %0,2f\n"						\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	:"=&r" (temp), "=m" (v->counter)				\
	:"Ir" (i), "m" (v->counter));					\
}									\

#define ATOMIC_OP_RETURN(op, asm_op)					\
static inline int atomic_##op##_return_relaxed(int i, atomic_t *v)	\
{									\
	long temp, result;						\
	__asm__ __volatile__(						\
	"1:	ldl_l %0,%1\n"						\
	"	" #asm_op " %0,%3,%2\n"					\
	"	" #asm_op " %0,%3,%0\n"					\
	"	stl_c %0,%1\n"						\
	"	beq %0,2f\n"						\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)		\
	:"Ir" (i), "m" (v->counter) : "memory");			\
	smp_read_barrier_depends();					\
	return result;							\
}

#define ATOMIC_FETCH_OP(op, asm_op)					\
static inline int atomic_fetch_##op##_relaxed(int i, atomic_t *v)	\
{									\
	long temp, result;						\
	__asm__ __volatile__(						\
	"1:	ldl_l %2,%1\n"						\
	"	" #asm_op " %2,%3,%0\n"					\
	"	stl_c %0,%1\n"						\
	"	beq %0,2f\n"						\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)		\
	:"Ir" (i), "m" (v->counter) : "memory");			\
	smp_read_barrier_depends();					\
	return result;							\
}

#define ATOMIC64_OP(op, asm_op)						\
static __inline__ void atomic64_##op(long i, atomic64_t * v)		\
{									\
	unsigned long temp;						\
	__asm__ __volatile__(						\
	"1:	ldq_l %0,%1\n"						\
	"	" #asm_op " %0,%2,%0\n"					\
	"	stq_c %0,%1\n"						\
	"	beq %0,2f\n"						\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	:"=&r" (temp), "=m" (v->counter)				\
	:"Ir" (i), "m" (v->counter));					\
}									\

#define ATOMIC64_OP_RETURN(op, asm_op)					\
static __inline__ long atomic64_##op##_return_relaxed(long i, atomic64_t * v)	\
{									\
	long temp, result;						\
	__asm__ __volatile__(						\
	"1:	ldq_l %0,%1\n"						\
	"	" #asm_op " %0,%3,%2\n"					\
	"	" #asm_op " %0,%3,%0\n"					\
	"	stq_c %0,%1\n"						\
	"	beq %0,2f\n"						\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)		\
	:"Ir" (i), "m" (v->counter) : "memory");			\
	smp_read_barrier_depends();					\
	return result;							\
}

#define ATOMIC64_FETCH_OP(op, asm_op)					\
static __inline__ long atomic64_fetch_##op##_relaxed(long i, atomic64_t * v)	\
{									\
	long temp, result;						\
	__asm__ __volatile__(						\
	"1:	ldq_l %2,%1\n"						\
	"	" #asm_op " %2,%3,%0\n"					\
	"	stq_c %0,%1\n"						\
	"	beq %0,2f\n"						\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	:"=&r" (temp), "=m" (v->counter), "=&r" (result)		\
	:"Ir" (i), "m" (v->counter) : "memory");			\
	smp_read_barrier_depends();					\
	return result;							\
}

#define ATOMIC_OPS(op)							\
	ATOMIC_OP(op, op##l)						\
	ATOMIC_OP_RETURN(op, op##l)					\
	ATOMIC_FETCH_OP(op, op##l)					\
	ATOMIC64_OP(op, op##q)						\
	ATOMIC64_OP_RETURN(op, op##q)					\
	ATOMIC64_FETCH_OP(op, op##q)

ATOMIC_OPS(add)
ATOMIC_OPS(sub)

#define atomic_add_return_relaxed	atomic_add_return_relaxed
#define atomic_sub_return_relaxed	atomic_sub_return_relaxed
#define atomic_fetch_add_relaxed	atomic_fetch_add_relaxed
#define atomic_fetch_sub_relaxed	atomic_fetch_sub_relaxed

#define atomic64_add_return_relaxed	atomic64_add_return_relaxed
#define atomic64_sub_return_relaxed	atomic64_sub_return_relaxed
#define atomic64_fetch_add_relaxed	atomic64_fetch_add_relaxed
#define atomic64_fetch_sub_relaxed	atomic64_fetch_sub_relaxed

#define atomic_andnot atomic_andnot
#define atomic64_andnot atomic64_andnot

#undef ATOMIC_OPS
#define ATOMIC_OPS(op, asm)						\
	ATOMIC_OP(op, asm)						\
	ATOMIC_FETCH_OP(op, asm)					\
	ATOMIC64_OP(op, asm)						\
	ATOMIC64_FETCH_OP(op, asm)

ATOMIC_OPS(and, and)
ATOMIC_OPS(andnot, bic)
ATOMIC_OPS(or, bis)
ATOMIC_OPS(xor, xor)

#define atomic_fetch_and_relaxed	atomic_fetch_and_relaxed
#define atomic_fetch_andnot_relaxed	atomic_fetch_andnot_relaxed
#define atomic_fetch_or_relaxed		atomic_fetch_or_relaxed
#define atomic_fetch_xor_relaxed	atomic_fetch_xor_relaxed

#define atomic64_fetch_and_relaxed	atomic64_fetch_and_relaxed
#define atomic64_fetch_andnot_relaxed	atomic64_fetch_andnot_relaxed
#define atomic64_fetch_or_relaxed	atomic64_fetch_or_relaxed
#define atomic64_fetch_xor_relaxed	atomic64_fetch_xor_relaxed

#undef ATOMIC_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

#define atomic64_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), old, new))
#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))

#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), old, new))
#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

/**
 * atomic_add_unless - add unless the number is a given value
 * __atomic_add_unless - add unless the number is a given value
 * atomic_fetch_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static __inline__ int atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}

#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)
 * Returns the old value of @v.
 */
static __inline__ int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
	int c, new, old;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldl_l	%[old],%[mem]\n"
	"	cmpeq	%[old],%[u],%[c]\n"
	"	addl	%[old],%[a],%[new]\n"
	"	bne	%[c],2f\n"
	"	stl_c	%[new],%[mem]\n"
	"	beq	%[new],3f\n"
	"2:\n"
	".subsection 2\n"
	"3:	br	1b\n"
	".previous"
	: [old] "=&r"(old), [new] "=&r"(new), [c] "=&r"(c)
	: [mem] "m"(*v), [a] "rI"(a), [u] "rI"((long)u)
	: "memory");
	smp_mb();
	return old;
}
#define atomic_fetch_add_unless atomic_fetch_add_unless

/**
 * atomic64_fetch_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static __inline__ int atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic64_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
 * Returns true iff @v was not @u.
 * Returns the old value of @v.
 */
static __inline__ long atomic64_fetch_add_unless(atomic64_t *v, long a, long u)
{
	long c, new, old;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldq_l	%[old],%[mem]\n"
	"	cmpeq	%[old],%[u],%[c]\n"
	"	addq	%[old],%[a],%[new]\n"
	"	bne	%[c],2f\n"
	"	stq_c	%[new],%[mem]\n"
	"	beq	%[new],3f\n"
	"2:\n"
	".subsection 2\n"
	"3:	br	1b\n"
	".previous"
	: [old] "=&r"(old), [new] "=&r"(new), [c] "=&r"(c)
	: [mem] "m"(*v), [a] "rI"(a), [u] "rI"(u)
	: "memory");
	smp_mb();
	return old;
}
#define atomic64_fetch_add_unless atomic64_fetch_add_unless

/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
static inline long atomic64_dec_if_positive(atomic64_t *v)
{
	long old, tmp;
	smp_mb();
	__asm__ __volatile__(
	"1:	ldq_l	%[old],%[mem]\n"
	"	subq	%[old],1,%[tmp]\n"
	"	ble	%[old],2f\n"
	"	stq_c	%[tmp],%[mem]\n"
	"	beq	%[tmp],3f\n"
	"2:\n"
	".subsection 2\n"
	"3:	br	1b\n"
	".previous"
	: [old] "=&r"(old), [tmp] "=&r"(tmp)
	: [mem] "m"(*v)
	: "memory");
	smp_mb();
	return old - 1;
}
#define atomic64_dec_if_positive atomic64_dec_if_positive

#define smp_mb__before_atomic_dec()	smp_mb()
#define smp_mb__after_atomic_dec()	smp_mb()
#define smp_mb__before_atomic_inc()	smp_mb()
#define smp_mb__after_atomic_inc()	smp_mb()

#include <asm-generic/atomic.h>
#endif /* _ALPHA_ATOMIC_H */
