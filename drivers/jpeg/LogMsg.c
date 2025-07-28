/*
 * Project Name MFC DRIVER 
 * Copyright  2007 Samsung Electronics Co, Ltd. All Rights Reserved. 
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

#include <stdarg.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <asm/param.h>
#include <linux/delay.h>

#include "LogMsg.h"

//#define DEBUG

static const LOG_LEVEL log_level = LOG_ERROR;

static const char *modulename = "JPEG_DRV";

static const char *level_str[] = {"TRACE", "WARNING", "ERROR"};

void JPEG_LOG_MSG(LOG_LEVEL level, const char *func_name, const char *msg, ...)
{
	
	char buf[256];
	va_list argptr;

	#ifndef DEBUG
	if (level < log_level)
		return;
	#endif // DEBUG

	sprintf(buf, "[%s: %s] %s: ", modulename, level_str[level], func_name);

	va_start(argptr, msg);
	vsprintf(buf + strlen(buf), msg, argptr);

		printk(buf);
	
	va_end(argptr);
}

