/* SPDX-License-Identifier: GPL-2.0 */
#ifdef CONFIG_SUPERH32
# include "checksum_32.h"
#else
# include "checksum_64.h"
# include <asm/checksum_32.h>
#else
# include <asm-generic/checksum.h>
#endif
