/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright IBM Corp. 1999, 2016
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>,
 *	      Denis Joseph Barrow,
 *	      Arnd Bergmann,
 */

#ifndef __ARCH_S390_ATOMIC__
#define __ARCH_S390_ATOMIC__

#include <linux/compiler.h>

/*
 *  include/asm-s390/atomic.h
 *
 *  S390 version
 *    Copyright (C) 1999-2005 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com),
 *               Denis Joseph Barrow,
 *		 Arnd Bergmann (arndb@de.ibm.com)
 *
 *  Derived from "include/asm-i386/bitops.h"
 *    Copyright (C) 1992, Linus Torvalds
 *
 */

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 * S390 uses 'Compare And Swap' for atomicity in SMP enviroment
 */

typedef struct {
	int counter;
} __attribute__ ((aligned (4))) atomic_t;
#define ATOMIC_INIT(i)  { (i) }

#ifdef __KERNEL__

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 2)

#define __CS_LOOP(ptr, op_val, op_string) ({				\
	typeof(ptr->counter) old_val, new_val;				\
#include <linux/types.h>
#include <asm/atomic_ops.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

#define ATOMIC_INIT(i)  { (i) }

#define __ATOMIC_NO_BARRIER	"\n"

#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES

#define __ATOMIC_OR	"lao"
#define __ATOMIC_AND	"lan"
#define __ATOMIC_ADD	"laa"
#define __ATOMIC_XOR	"lax"
#define __ATOMIC_BARRIER "bcr	14,0\n"

#define __ATOMIC_LOOP(ptr, op_val, op_string, __barrier)		\
({									\
	int old_val;							\
									\
	typecheck(atomic_t *, ptr);					\
	asm volatile(							\
		op_string "	%0,%2,%1\n"				\
		__barrier						\
		: "=d" (old_val), "+Q" ((ptr)->counter)			\
		: "d" (op_val)						\
		: "cc", "memory");					\
	old_val;							\
})

#else /* CONFIG_HAVE_MARCH_Z196_FEATURES */

#define __ATOMIC_OR	"or"
#define __ATOMIC_AND	"nr"
#define __ATOMIC_ADD	"ar"
#define __ATOMIC_XOR	"xr"
#define __ATOMIC_BARRIER "\n"

#define __ATOMIC_LOOP(ptr, op_val, op_string, __barrier)		\
({									\
	int old_val, new_val;						\
									\
	typecheck(atomic_t *, ptr);					\
	asm volatile(							\
		"	l	%0,%2\n"				\
		"0:	lr	%1,%0\n"				\
		op_string "	%1,%3\n"				\
		"	cs	%0,%1,%2\n"				\
		"	jl	0b"					\
		: "=&d" (old_val), "=&d" (new_val),			\
		  "=Q" (((atomic_t *)(ptr))->counter)			\
		: "d" (op_val),	 "Q" (((atomic_t *)(ptr))->counter)	\
		: "cc", "memory");					\
	new_val;							\
})

#else /* __GNUC__ */

#define __CS_LOOP(ptr, op_val, op_string) ({				\
	typeof(ptr->counter) old_val, new_val;				\
	asm volatile(							\
		"	l	%0,0(%3)\n"				\
		"0:	lr	%1,%0\n"				\
		op_string "	%1,%4\n"				\
		"	cs	%0,%1,0(%3)\n"				\
		"	jl	0b"					\
		: "=&d" (old_val), "=&d" (new_val),			\
		  "=m" (((atomic_t *)(ptr))->counter)			\
		: "a" (ptr), "d" (op_val),				\
		  "m" (((atomic_t *)(ptr))->counter)			\
		: "cc", "memory");					\
	new_val;							\
})

#endif /* __GNUC__ */

static inline int atomic_read(const atomic_t *v)
{
	barrier();
	return v->counter;
		: "=&d" (old_val), "=&d" (new_val), "+Q" ((ptr)->counter)\
		: "d" (op_val)						\
		: "cc", "memory");					\
	old_val;							\
})

#endif /* CONFIG_HAVE_MARCH_Z196_FEATURES */

static inline int atomic_read(const atomic_t *v)
{
	int c;

	asm volatile(
		"	l	%0,%1\n"
		: "=d" (c) : "Q" (v->counter));
	return c;
}

static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
	barrier();
}

static __inline__ int atomic_add_return(int i, atomic_t * v)
{
	return __CS_LOOP(v, i, "ar");
}
#define atomic_add(_i, _v)		atomic_add_return(_i, _v)
#define atomic_add_negative(_i, _v)	(atomic_add_return(_i, _v) < 0)
#define atomic_inc(_v)			atomic_add_return(1, _v)
#define atomic_inc_return(_v)		atomic_add_return(1, _v)
#define atomic_inc_and_test(_v)		(atomic_add_return(1, _v) == 0)

static __inline__ int atomic_sub_return(int i, atomic_t * v)
{
	return __CS_LOOP(v, i, "sr");
}
#define atomic_sub(_i, _v)		atomic_sub_return(_i, _v)
#define atomic_sub_and_test(_i, _v)	(atomic_sub_return(_i, _v) == 0)
#define atomic_dec(_v)			atomic_sub_return(1, _v)
#define atomic_dec_return(_v)		atomic_sub_return(1, _v)
#define atomic_dec_and_test(_v)		(atomic_sub_return(1, _v) == 0)

static __inline__ void atomic_clear_mask(unsigned long mask, atomic_t * v)
{
	       __CS_LOOP(v, ~mask, "nr");
}

static __inline__ void atomic_set_mask(unsigned long mask, atomic_t * v)
{
	       __CS_LOOP(v, mask, "or");
}

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

static __inline__ int atomic_cmpxchg(atomic_t *v, int old, int new)
{
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 2)
	asm volatile(
		"	cs	%0,%2,%1"
		: "+d" (old), "=Q" (v->counter)
		: "d" (new), "Q" (v->counter)
		: "cc", "memory");
#else /* __GNUC__ */
	asm volatile(
		"	cs	%0,%3,0(%2)"
		: "+d" (old), "=m" (v->counter)
		: "a" (v), "d" (new), "m" (v->counter)
		: "cc", "memory");
#endif /* __GNUC__ */
	return old;
}

static __inline__ int atomic_add_unless(atomic_t *v, int a, int u)
	asm volatile(
		"	st	%1,%0\n"
		: "=Q" (v->counter) : "d" (i));
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	return __atomic_add_barrier(i, &v->counter) + i;
}

static inline int atomic_fetch_add(int i, atomic_t *v)
{
	return __atomic_add_barrier(i, &v->counter);
}

static inline void atomic_add(int i, atomic_t *v)
{
#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES
	if (__builtin_constant_p(i) && (i > -129) && (i < 128)) {
		__atomic_add_const(i, &v->counter);
		return;
	}
#endif
	__atomic_add(i, &v->counter);
}

#define atomic_add_negative(_i, _v)	(atomic_add_return(_i, _v) < 0)
#define atomic_inc(_v)			atomic_add(1, _v)
#define atomic_inc_return(_v)		atomic_add_return(1, _v)
#define atomic_inc_and_test(_v)		(atomic_add_return(1, _v) == 0)
#define atomic_sub(_i, _v)		atomic_add(-(int)(_i), _v)
#define atomic_sub_return(_i, _v)	atomic_add_return(-(int)(_i), _v)
#define atomic_fetch_sub(_i, _v)	atomic_fetch_add(-(int)(_i), _v)
#define atomic_sub_and_test(_i, _v)	(atomic_sub_return(_i, _v) == 0)
#define atomic_dec(_v)			atomic_sub(1, _v)
#define atomic_dec_return(_v)		atomic_sub_return(1, _v)
#define atomic_dec_and_test(_v)		(atomic_sub_return(1, _v) == 0)

#define ATOMIC_OPS(op)							\
static inline void atomic_##op(int i, atomic_t *v)			\
{									\
	__atomic_##op(i, &v->counter);					\
}									\
static inline int atomic_fetch_##op(int i, atomic_t *v)			\
{									\
	return __atomic_##op##_barrier(i, &v->counter);			\
}

ATOMIC_OPS(and)
ATOMIC_OPS(or)
ATOMIC_OPS(xor)

#undef ATOMIC_OPS

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return __atomic_cmpxchg(&v->counter, old, new);
}

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;
		old = atomic_cmpxchg(v, c, c + a);
		if (likely(old == c))
			break;
		c = old;
	}
	return c != u;
}

#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)

#undef __CS_LOOP

#ifdef __s390x__
typedef struct {
	long long counter;
} __attribute__ ((aligned (8))) atomic64_t;
#define ATOMIC64_INIT(i)  { (i) }

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 2)

#define __CSG_LOOP(ptr, op_val, op_string) ({				\
	typeof(ptr->counter) old_val, new_val;				\
	return c;
}

#define ATOMIC64_INIT(i)  { (i) }

#define __ATOMIC64_NO_BARRIER	"\n"

#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES

#define __ATOMIC64_OR	"laog"
#define __ATOMIC64_AND	"lang"
#define __ATOMIC64_ADD	"laag"
#define __ATOMIC64_XOR	"laxg"
#define __ATOMIC64_BARRIER "bcr	14,0\n"

#define __ATOMIC64_LOOP(ptr, op_val, op_string, __barrier)		\
({									\
	long long old_val;						\
									\
	typecheck(atomic64_t *, ptr);					\
	asm volatile(							\
		op_string "	%0,%2,%1\n"				\
		__barrier						\
		: "=d" (old_val), "+Q" ((ptr)->counter)			\
		: "d" (op_val)						\
		: "cc", "memory");					\
	old_val;							\
})

#else /* CONFIG_HAVE_MARCH_Z196_FEATURES */

#define __ATOMIC64_OR	"ogr"
#define __ATOMIC64_AND	"ngr"
#define __ATOMIC64_ADD	"agr"
#define __ATOMIC64_XOR	"xgr"
#define __ATOMIC64_BARRIER "\n"

#define __ATOMIC64_LOOP(ptr, op_val, op_string, __barrier)		\
({									\
	long long old_val, new_val;					\
									\
	typecheck(atomic64_t *, ptr);					\
	asm volatile(							\
		"	lg	%0,%2\n"				\
		"0:	lgr	%1,%0\n"				\
		op_string "	%1,%3\n"				\
		"	csg	%0,%1,%2\n"				\
		"	jl	0b"					\
		: "=&d" (old_val), "=&d" (new_val),			\
		  "=Q" (((atomic_t *)(ptr))->counter)			\
		: "d" (op_val),	"Q" (((atomic_t *)(ptr))->counter)	\
		: "cc", "memory" );					\
	new_val;							\
})

#else /* __GNUC__ */

#define __CSG_LOOP(ptr, op_val, op_string) ({				\
	typeof(ptr->counter) old_val, new_val;				\
	asm volatile(							\
		"	lg	%0,0(%3)\n"				\
		"0:	lgr	%1,%0\n"				\
		op_string "	%1,%4\n"				\
		"	csg	%0,%1,0(%3)\n"				\
		"	jl	0b"					\
		: "=&d" (old_val), "=&d" (new_val),			\
		  "=m" (((atomic_t *)(ptr))->counter)			\
		: "a" (ptr), "d" (op_val),				\
		  "m" (((atomic_t *)(ptr))->counter)			\
		: "cc", "memory" );					\
	new_val;							\
})

#endif /* __GNUC__ */

static inline long long atomic64_read(const atomic64_t *v)
{
	barrier();
	return v->counter;
		: "=&d" (old_val), "=&d" (new_val), "+Q" ((ptr)->counter)\
		: "d" (op_val)						\
		: "cc", "memory");					\
	old_val;							\
})

#endif /* CONFIG_HAVE_MARCH_Z196_FEATURES */

static inline long long atomic64_read(const atomic64_t *v)
static inline long atomic64_read(const atomic64_t *v)
{
	long c;

	asm volatile(
		"	lg	%0,%1\n"
		: "=d" (c) : "Q" (v->counter));
	return c;
}

static inline void atomic64_set(atomic64_t *v, long i)
{
	v->counter = i;
	barrier();
}

static __inline__ long long atomic64_add_return(long long i, atomic64_t * v)
{
	return __CSG_LOOP(v, i, "agr");
}
#define atomic64_add(_i, _v)		atomic64_add_return(_i, _v)
#define atomic64_add_negative(_i, _v)	(atomic64_add_return(_i, _v) < 0)
#define atomic64_inc(_v)		atomic64_add_return(1, _v)
#define atomic64_inc_return(_v)		atomic64_add_return(1, _v)
#define atomic64_inc_and_test(_v)	(atomic64_add_return(1, _v) == 0)

static __inline__ long long atomic64_sub_return(long long i, atomic64_t * v)
{
	return __CSG_LOOP(v, i, "sgr");
}
#define atomic64_sub(_i, _v)		atomic64_sub_return(_i, _v)
#define atomic64_sub_and_test(_i, _v)	(atomic64_sub_return(_i, _v) == 0)
#define atomic64_dec(_v)		atomic64_sub_return(1, _v)
#define atomic64_dec_return(_v)		atomic64_sub_return(1, _v)
#define atomic64_dec_and_test(_v)	(atomic64_sub_return(1, _v) == 0)

static __inline__ void atomic64_clear_mask(unsigned long mask, atomic64_t * v)
{
	       __CSG_LOOP(v, ~mask, "ngr");
}

static __inline__ void atomic64_set_mask(unsigned long mask, atomic64_t * v)
{
	       __CSG_LOOP(v, mask, "ogr");
	asm volatile(
		"	stg	%1,%0\n"
		: "=Q" (v->counter) : "d" (i));
}

static inline long atomic64_add_return(long i, atomic64_t *v)
{
	return __atomic64_add_barrier(i, &v->counter) + i;
}

static inline long atomic64_fetch_add(long i, atomic64_t *v)
{
	return __atomic64_add_barrier(i, &v->counter);
}

static inline void atomic64_add(long i, atomic64_t *v)
{
#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES
	if (__builtin_constant_p(i) && (i > -129) && (i < 128)) {
		__atomic64_add_const(i, &v->counter);
		return;
	}
#endif
	__atomic64_add(i, &v->counter);
}

#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))

static __inline__ long long atomic64_cmpxchg(atomic64_t *v,
					     long long old, long long new)
{
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 2)
	asm volatile(
		"	csg	%0,%2,%1"
		: "+d" (old), "=Q" (v->counter)
		: "d" (new), "Q" (v->counter)
		: "cc", "memory");
#else /* __GNUC__ */
	asm volatile(
		"	csg	%0,%3,0(%2)"
		: "+d" (old), "=m" (v->counter)
		: "a" (v), "d" (new), "m" (v->counter)
		: "cc", "memory");
#endif /* __GNUC__ */
	return old;
}

static __inline__ int atomic64_add_unless(atomic64_t *v,
					  long long a, long long u)
{
	long long c, old;
static inline long long atomic64_cmpxchg(atomic64_t *v,
					     long long old, long long new)
static inline long atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return __atomic64_cmpxchg(&v->counter, old, new);
}

#define ATOMIC64_OPS(op)						\
static inline void atomic64_##op(long i, atomic64_t *v)			\
{									\
	__atomic64_##op(i, &v->counter);				\
}									\
static inline long atomic64_fetch_##op(long i, atomic64_t *v)		\
{									\
	return __atomic64_##op##_barrier(i, &v->counter);		\
}

ATOMIC64_OPS(and)
ATOMIC64_OPS(or)
ATOMIC64_OPS(xor)

#undef ATOMIC64_OPS

static inline int atomic64_add_unless(atomic64_t *v, long i, long u)
{
	long c, old;

	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;
		old = atomic64_cmpxchg(v, c, c + a);
		old = atomic64_cmpxchg(v, c, c + i);
		if (likely(old == c))
			break;
		c = old;
	}
	return c != u;
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

#undef __CSG_LOOP
#endif

#define smp_mb__before_atomic_dec()	smp_mb()
#define smp_mb__after_atomic_dec()	smp_mb()
#define smp_mb__before_atomic_inc()	smp_mb()
#define smp_mb__after_atomic_inc()	smp_mb()

#include <asm-generic/atomic.h>
#endif /* __KERNEL__ */
static inline long long atomic64_dec_if_positive(atomic64_t *v)
static inline long atomic64_dec_if_positive(atomic64_t *v)
{
	long c, old, dec;

	c = atomic64_read(v);
	for (;;) {
		dec = c - 1;
		if (unlikely(dec < 0))
			break;
		old = atomic64_cmpxchg((v), c, dec);
		if (likely(old == c))
			break;
		c = old;
	}
	return dec;
}

#define atomic64_add_negative(_i, _v)	(atomic64_add_return(_i, _v) < 0)
#define atomic64_inc(_v)		atomic64_add(1, _v)
#define atomic64_inc_return(_v)		atomic64_add_return(1, _v)
#define atomic64_inc_and_test(_v)	(atomic64_add_return(1, _v) == 0)
#define atomic64_sub_return(_i, _v)	atomic64_add_return(-(long)(_i), _v)
#define atomic64_fetch_sub(_i, _v)	atomic64_fetch_add(-(long)(_i), _v)
#define atomic64_sub(_i, _v)		atomic64_add(-(long)(_i), _v)
#define atomic64_sub_and_test(_i, _v)	(atomic64_sub_return(_i, _v) == 0)
#define atomic64_dec(_v)		atomic64_sub(1, _v)
#define atomic64_dec_return(_v)		atomic64_sub_return(1, _v)
#define atomic64_dec_and_test(_v)	(atomic64_sub_return(1, _v) == 0)
#define atomic64_inc_not_zero(v)	atomic64_add_unless((v), 1, 0)

#endif /* __ARCH_S390_ATOMIC__  */
