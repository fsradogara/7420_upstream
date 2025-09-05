/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SH_FUTEX_H
#define __ASM_SH_FUTEX_H

#ifdef __KERNEL__

#include <linux/futex.h>
#include <linux/uaccess.h>
#include <asm/errno.h>

#if !defined(CONFIG_SMP)
#include <asm/futex-irq.h>

static inline int futex_atomic_op_inuser(int encoded_op, int __user *uaddr)
static inline int futex_atomic_op_inuser(int encoded_op, u32 __user *uaddr)
{
	int op = (encoded_op >> 28) & 7;
	int cmp = (encoded_op >> 24) & 15;
	int oparg = (encoded_op << 8) >> 20;
	int cmparg = (encoded_op << 20) >> 20;
	int oldval = 0, ret;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28))
		oparg = 1 << oparg;

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(u32)))
		return -EFAULT;

	pagefault_disable();

	switch (op) {
	case FUTEX_OP_SET:
		ret = atomic_futex_op_xchg_set(oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_ADD:
		ret = atomic_futex_op_xchg_add(oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_OR:
		ret = atomic_futex_op_xchg_or(oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_ANDN:
		ret = atomic_futex_op_xchg_and(~oparg, uaddr, &oldval);
		break;
	case FUTEX_OP_XOR:
		ret = atomic_futex_op_xchg_xor(oparg, uaddr, &oldval);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	pagefault_enable();

	if (!ret) {
		switch (cmp) {
		case FUTEX_OP_CMP_EQ: ret = (oldval == cmparg); break;
		case FUTEX_OP_CMP_NE: ret = (oldval != cmparg); break;
		case FUTEX_OP_CMP_LT: ret = (oldval < cmparg); break;
		case FUTEX_OP_CMP_GE: ret = (oldval >= cmparg); break;
		case FUTEX_OP_CMP_LE: ret = (oldval <= cmparg); break;
		case FUTEX_OP_CMP_GT: ret = (oldval > cmparg); break;
		default: ret = -ENOSYS;
		}
	}

	return ret;
}
#elif defined(CONFIG_CPU_J2)
#include <asm/futex-cas.h>
#elif defined(CONFIG_CPU_SH4A)
#include <asm/futex-llsc.h>
#else
#error SMP not supported on this configuration.
#endif

static inline int
futex_atomic_cmpxchg_inatomic(int __user *uaddr, int oldval, int newval)
{
	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;

	return atomic_futex_op_cmpxchg_inatomic(uaddr, oldval, newval);
futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
			      u32 oldval, u32 newval)
{
	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(u32)))
		return -EFAULT;

	return atomic_futex_op_cmpxchg_inatomic(uval, uaddr, oldval, newval);
}

static inline int arch_futex_atomic_op_inuser(int op, u32 oparg, int *oval,
		u32 __user *uaddr)
{
	u32 oldval, newval, prev;
	int ret;

	pagefault_disable();

	do {
		if (op == FUTEX_OP_SET)
			ret = oldval = 0;
		else
			ret = get_user(oldval, uaddr);

		if (ret) break;

		switch (op) {
		case FUTEX_OP_SET:
			newval = oparg;
			break;
		case FUTEX_OP_ADD:
			newval = oldval + oparg;
			break;
		case FUTEX_OP_OR:
			newval = oldval | oparg;
			break;
		case FUTEX_OP_ANDN:
			newval = oldval & ~oparg;
			break;
		case FUTEX_OP_XOR:
			newval = oldval ^ oparg;
			break;
		default:
			ret = -ENOSYS;
			break;
		}

		if (ret) break;

		ret = futex_atomic_cmpxchg_inatomic(&prev, uaddr, oldval, newval);
	} while (!ret && prev != oldval);

	pagefault_enable();

	if (!ret)
		*oval = oldval;

	return ret;
}

#endif /* __KERNEL__ */
#endif /* __ASM_SH_FUTEX_H */
