/*
 * Project Name MFC DRIVER
 * Copyright (c) Samsung Electronics 
 * All right reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/wait.h>

#include "MfcConfig.h"
#include "MfcMutex.h"
#include "MfcTypes.h"

extern wait_queue_head_t	WaitQueue_MFC;
static struct mutex	*hMutex = NULL;


BOOL MFC_Mutex_Create(void)
{
	hMutex = (struct mutex *)kmalloc(sizeof(struct mutex), GFP_KERNEL);
	if (hMutex == NULL)
		return FALSE;

	mutex_init(hMutex);

	return TRUE;
}

void MFC_Mutex_Delete(void)
{
	if (hMutex == NULL)
		return;

	mutex_destroy(hMutex);
}

BOOL MFC_Mutex_Lock(void)
{
	mutex_lock(hMutex);

	return TRUE;
}

BOOL MFC_Mutex_Release(void)
{
	mutex_unlock(hMutex);

	return TRUE;
}

