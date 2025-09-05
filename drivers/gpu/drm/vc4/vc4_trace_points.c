/*
 * Copyright (C) 2015 Broadcom
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "vc4_drv.h"

#define pcibios_assign_all_busses()	1

#define PCIBIOS_MIN_IO		0x00001000
#define PCIBIOS_MIN_MEM		0x01000000
#define PCIMEM_BASE		ORION5X_PCIE_MEM_PHYS_BASE


#ifndef __CHECKER__
#define CREATE_TRACE_POINTS
#include "vc4_trace.h"
#endif
