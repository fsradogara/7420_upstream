/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SPINLOCK_TYPES_H
#define __ASM_SPINLOCK_TYPES_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

typedef struct {
	volatile unsigned int owner_cpu;
} __attribute__ ((aligned (4))) raw_spinlock_t;

#define __RAW_SPIN_LOCK_UNLOCKED	{ 0 }

typedef struct {
	volatile unsigned int lock;
} raw_rwlock_t;

#define __RAW_RW_LOCK_UNLOCKED		{ 0 }
	unsigned int lock;
	int lock;
} __attribute__ ((aligned (4))) arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { .lock = 0, }

typedef struct {
	int lock;
	int owner;
} arch_rwlock_t;

#define __ARCH_RW_LOCK_UNLOCKED		{ 0 }

#endif
