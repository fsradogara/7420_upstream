/* SPDX-License-Identifier: GPL-2.0 */
#ifndef S390_CIO_IOASM_H
#define S390_CIO_IOASM_H

#include <asm/chpid.h>
#include <asm/schid.h>
#include <asm/crw.h>
#include "orb.h"
#include "cio.h"
#include "trace.h"

/*
 * Some S390 specific IO instructions
 */

static inline int stsch(struct subchannel_id schid,
			    volatile struct schib *addr)
{
	register struct subchannel_id reg1 asm ("1") = schid;
	int ccode;

	asm volatile(
		"	stsch	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode) : "d" (reg1), "a" (addr), "m" (*addr) : "cc");
	return ccode;
}

static inline int stsch_err(struct subchannel_id schid,
				volatile struct schib *addr)
static inline int stsch_err(struct subchannel_id schid, struct schib *addr)
{
	register struct subchannel_id reg1 asm ("1") = schid;
	int ccode = -EIO;

	asm volatile(
		"	stsch	0(%2)\n"
		"	stsch	0(%3)\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "+d" (ccode) : "d" (reg1), "a" (addr), "m" (*addr) : "cc");
	return ccode;
}

static inline int msch(struct subchannel_id schid,
			   volatile struct schib *addr)
		: "+d" (ccode), "=m" (*addr)
		: "d" (reg1), "a" (addr)
		: "cc");
	return ccode;
}

static inline int msch(struct subchannel_id schid, struct schib *addr)
{
	register struct subchannel_id reg1 asm ("1") = schid;
	int ccode;

	asm volatile(
		"	msch	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode) : "d" (reg1), "a" (addr), "m" (*addr) : "cc");
	return ccode;
}

static inline int msch_err(struct subchannel_id schid,
			       volatile struct schib *addr)
		: "=d" (ccode)
		: "d" (reg1), "a" (addr), "m" (*addr)
		: "cc");
	return ccode;
}

static inline int msch_err(struct subchannel_id schid, struct schib *addr)
{
	register struct subchannel_id reg1 asm ("1") = schid;
	int ccode = -EIO;

	asm volatile(
		"	msch	0(%2)\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b,1b)
		: "+d" (ccode) : "d" (reg1), "a" (addr), "m" (*addr) : "cc");
	return ccode;
}

static inline int tsch(struct subchannel_id schid,
			   volatile struct irb *addr)
		: "+d" (ccode)
		: "d" (reg1), "a" (addr), "m" (*addr)
		: "cc");
	return ccode;
}

static inline int tsch(struct subchannel_id schid, struct irb *addr)
{
	register struct subchannel_id reg1 asm ("1") = schid;
	int ccode;

	asm volatile(
		"	tsch	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode) : "d" (reg1), "a" (addr), "m" (*addr) : "cc");
	return ccode;
}

static inline int tpi( volatile struct tpi_info *addr)
		"	tsch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode), "=m" (*addr)
		: "d" (reg1), "a" (addr)
		: "cc");
	return ccode;
}

static inline int ssch(struct subchannel_id schid, union orb *addr)
{
	register struct subchannel_id reg1 asm("1") = schid;
	int ccode = -EIO;

	asm volatile(
		"	ssch	0(%2)\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+d" (ccode)
		: "d" (reg1), "a" (addr), "m" (*addr)
		: "cc", "memory");
	return ccode;
}

static inline int csch(struct subchannel_id schid)
{
	register struct subchannel_id reg1 asm("1") = schid;
	int ccode;

	asm volatile(
		"	csch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode)
		: "d" (reg1)
		: "cc");
	return ccode;
}

static inline int tpi(struct tpi_info *addr)
{
	int ccode;

	asm volatile(
		"	tpi	0(%1)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode) : "a" (addr), "m" (*addr) : "cc");
		"	tpi	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode), "=m" (*addr)
		: "a" (addr)
		: "cc");
	return ccode;
}

static inline int chsc(void *chsc_area)
{
	typedef struct { char _[4096]; } addr_type;
	int cc;

	asm volatile(
		"	.insn	rre,0xb25f0000,%2,0\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (cc), "=m" (*(addr_type *) chsc_area)
		: "d" (chsc_area), "m" (*(addr_type *) chsc_area)
		: "cc");
	return cc;
}

static inline int rchp(struct chp_id chpid)
{
	register struct chp_id reg1 asm ("1") = chpid;
	int ccode;

	asm volatile(
		"	lr	1,%1\n"
		"	rchp\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (ccode) : "d" (reg1) : "cc");
	return ccode;
}
int stsch(struct subchannel_id schid, struct schib *addr);
int msch(struct subchannel_id schid, struct schib *addr);
int tsch(struct subchannel_id schid, struct irb *addr);
int ssch(struct subchannel_id schid, union orb *addr);
int csch(struct subchannel_id schid);
int tpi(struct tpi_info *addr);
int chsc(void *chsc_area);
int rsch(struct subchannel_id schid);
int hsch(struct subchannel_id schid);
int xsch(struct subchannel_id schid);
int stcrw(struct crw *crw);

#endif
