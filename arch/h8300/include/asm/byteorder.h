#ifndef _H8300_BYTEORDER_H
#define _H8300_BYTEORDER_H

#include <asm/types.h>

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) || defined(__KERNEL__)
#  define __BYTEORDER_HAS_U64__
#  define __SWAB_64_THRU_32__
#endif

#include <linux/byteorder/big_endian.h>

#endif /* _H8300_BYTEORDER_H */
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __H8300_BYTEORDER_H__
#define __H8300_BYTEORDER_H__

#include <linux/byteorder/big_endian.h>

#endif
