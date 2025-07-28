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

#include "s3c-mfc.h"
#include "MfcIntrNotification.h"
#include "MfcSfr.h"


extern wait_queue_head_t	WaitQueue_MFC;
static unsigned int  		gIntrType = 0;

int SendInterruptNotification(int intr_type)
{
	gIntrType = intr_type;
	wake_up_interruptible(&WaitQueue_MFC);
	
	return 0;
}

int WaitInterruptNotification(void)
{
	if(interruptible_sleep_on_timeout(&WaitQueue_MFC, 500) == 0)
	{
		MfcStreamEnd();
		return WAIT_INT_NOTI_TIMEOUT; 
	}
	
	return gIntrType;
}
