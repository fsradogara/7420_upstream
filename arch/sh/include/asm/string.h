/* SPDX-License-Identifier: GPL-2.0 */
#ifdef CONFIG_SUPERH32
# include "string_32.h"
#else
# include "string_64.h"
# include <asm/string_32.h>
#else
# include <asm/string_64.h>
#endif
