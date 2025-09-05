/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CRC32C_H
#define _LINUX_CRC32C_H

#include <linux/types.h>

extern u32 crc32c_le(u32 crc, unsigned char const *address, size_t length);
extern u32 crc32c_be(u32 crc, unsigned char const *address, size_t length);

#define crc32c(seed, data, length)  crc32c_le(seed, (unsigned char const *)data, length)
extern u32 crc32c(u32 crc, const void *address, unsigned int length);
extern const char *crc32c_impl(void);

/* This macro exists for backwards-compatibility. */
#define crc32c_le crc32c

#endif	/* _LINUX_CRC32C_H */
