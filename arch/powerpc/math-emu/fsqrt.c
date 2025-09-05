// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

#include "soft-fp.h"
#include "double.h"
#include <asm/sfp-machine.h>
#include <math-emu/soft-fp.h>
#include <math-emu/double.h>

int
fsqrt(void *frD, void *frB)
{
	FP_DECL_D(B);
	FP_DECL_D(R);
	int ret = 0;
	FP_DECL_EX;

#ifdef DEBUG
	printk("%s: %p %p %p %p\n", __func__, frD, frB);
#endif

	__FP_UNPACK_D(B, frB);
	FP_UNPACK_DP(B, frB);

#ifdef DEBUG
	printk("B: %ld %lu %lu %ld (%ld)\n", B_s, B_f1, B_f0, B_e, B_c);
#endif

	if (B_s && B_c != FP_CLS_ZERO)
		ret |= EFLAG_VXSQRT;
	if (B_c == FP_CLS_NAN)
		ret |= EFLAG_VXSNAN;
		FP_SET_EXCEPTION(EFLAG_VXSQRT);
	if (B_c == FP_CLS_NAN)
		FP_SET_EXCEPTION(EFLAG_VXSNAN);

	FP_SQRT_D(R, B);

#ifdef DEBUG
	printk("R: %ld %lu %lu %ld (%ld)\n", R_s, R_f1, R_f0, R_e, R_c);
#endif

	return (ret | __FP_PACK_D(frD, R));
	__FP_PACK_D(frD, R);

	return FP_CUR_EXCEPTIONS;
}
