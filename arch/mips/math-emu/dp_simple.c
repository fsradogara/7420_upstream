/* IEEE754 floating point arithmetic
 * double precision: common utilities
 */
/*
 * MIPS floating point support
 * Copyright (C) 1994-2000 Algorithmics Ltd.
 * http://www.algor.co.uk
 *
 * ########################################################################
 *
 *  This program is free software; you can distribute it and/or modify it
 *  under the terms of the GNU General Public License (Version 2) as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * ########################################################################
 */


#include "ieee754dp.h"

int ieee754dp_finite(ieee754dp x)
{
	return DPBEXP(x) != DP_EMAX + 1 + DP_EBIAS;
}

ieee754dp ieee754dp_copysign(ieee754dp x, ieee754dp y)
{
	CLEARCX;
	DPSIGN(x) = DPSIGN(y);
	return x;
}


ieee754dp ieee754dp_neg(ieee754dp x)
{
	COMPXDP;

	EXPLODEXDP;
	CLEARCX;
	FLUSHXDP;

	/*
	 * Invert the sign ALWAYS to prevent an endless recursion on
	 * pow() in libc.
	 */
	/* quick fix up */
	DPSIGN(x) ^= 1;

	if (xc == IEEE754_CLASS_SNAN) {
		ieee754dp y = ieee754dp_indef();
		SETCX(IEEE754_INVALID_OPERATION);
		DPSIGN(y) = DPSIGN(x);
		return ieee754dp_nanxcpt(y, "neg");
	}

	if (ieee754dp_isnan(x))	/* but not infinity */
		return ieee754dp_nanxcpt(x, "neg", x);
	return x;
}


ieee754dp ieee754dp_abs(ieee754dp x)
{
	COMPXDP;

	EXPLODEXDP;
	CLEARCX;
	FLUSHXDP;

	if (xc == IEEE754_CLASS_SNAN) {
		SETCX(IEEE754_INVALID_OPERATION);
		return ieee754dp_nanxcpt(ieee754dp_indef(), "neg");
	}

	if (ieee754dp_isnan(x))	/* but not infinity */
		return ieee754dp_nanxcpt(x, "abs", x);

	/* quick fix up */
	DPSIGN(x) = 0;
	return x;
 *  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.
 */

#include "ieee754dp.h"

union ieee754dp ieee754dp_neg(union ieee754dp x)
{
	union ieee754dp y;

	if (ieee754_csr.abs2008) {
		y = x;
		DPSIGN(y) = !DPSIGN(x);
	} else {
		unsigned int oldrm;

		oldrm = ieee754_csr.rm;
		ieee754_csr.rm = FPU_CSR_RD;
		y = ieee754dp_sub(ieee754dp_zero(0), x);
		ieee754_csr.rm = oldrm;
	}
	return y;
}

union ieee754dp ieee754dp_abs(union ieee754dp x)
{
	union ieee754dp y;

	if (ieee754_csr.abs2008) {
		y = x;
		DPSIGN(y) = 0;
	} else {
		unsigned int oldrm;

		oldrm = ieee754_csr.rm;
		ieee754_csr.rm = FPU_CSR_RD;
		if (DPSIGN(x))
			y = ieee754dp_sub(ieee754dp_zero(0), x);
		else
			y = ieee754dp_add(ieee754dp_zero(0), x);
		ieee754_csr.rm = oldrm;
	}
	return y;
}
