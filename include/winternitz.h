/*
 * Copyright (C) 2017 Geovandro Pereira
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H

#include "hash.h"

#define WINTERNITZ_OK 1
#define WINTERNITZ_ERROR 0


#define WINTERNITZ_SEC_LVL	128
#define WINTERNITZ_N 		256

#if WINTERNITZ_W > 8
#error maximum value for w is 8 due to chosen data type in this implementation
#endif

#define WINTERNITZ_l1 ((WINTERNITZ_N + WINTERNITZ_W - 1) / WINTERNITZ_W)
#if (WINTERNITZ_W == 2)
    #if WINTERNITZ_N == 128
		#define WINTERNITZ_l2 (4)
    #elif WINTERNITZ_N == 256
    	#define WINTERNITZ_l2 (5)
    #endif
#elif (WINTERNITZ_W == 4)
    #define WINTERNITZ_l2 (3) //l2=3 if l1 \in {32,64}
#elif (WINTERNITZ_W == 8)
    #define WINTERNITZ_l2 (2)
#endif
#define WINTERNITZ_CHECKSUM_SIZE (WINTERNITZ_l2)
#define WINTERNITZ_l (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)
#define WINTERNITZ_L (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)

//#define GET_CHUNK(x, startbit) ((x & (unsigned)( (unsigned)((1 << WINTERNITZ_W) - 1) << startbit)) >> startbit)
#define LEN_BYTES(bits) ((bits+7)/8)

#define WINTERNITZ_SIG_SIZE WINTERNITZ_L*LEN_BYTES(WINTERNITZ_N)

/**
 * Compute a Winternitz public key v = H_N(x_{0}^{2^w-1}, x_{1}^{2^w-1}, ..., x_{L-1}^{2^w-1}), with L = ceil(N/w) + ceil(lg((2^w-1)*(N/w))/w), N = 256.
 *
 * @param s         the private signing key.
 * @param X         the fixed N-bit string for key generation (from WOTS-PRF)
 * @param v         the resulting verification key 
 */
void winternitz_keygen(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char v[LEN_BYTES(WINTERNITZ_N)]);

/**
 * Sign the value under private key s, yielding (x_{0:0}, x_{0:1}, x_{0:2}, x_{0:3}, ..., x_{(N/8-1):0}, x_{(N/8-1):1}, x_{(N/8-1):2}, x_{(N/8-1):3})
 *
 * @param s		 the private signing key.
 * @param X              the fixed N-bit string for key generation (from WOTS-PRF)
 * @param hash
 * @param h		 buffer containing the message hash to be signed, computed outside as h = H(v,data)
 * @param sig
 */
void winternitz_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, unsigned char *sig);

/**
 * Verify a signature on hash H(v,data)
 *
 * @param v         The verification key, used here as the random nonce as well.
 * @param X         first component of the public key pk = (pk_0, pk_1, ..., pk_L)
 * @param h
 * @param sig       the signature
 * @param y         scratch (should match v at the end)
 */
unsigned char winternitz_verify(const unsigned char *v, unsigned char *X, unsigned char *h, const unsigned char *sig, unsigned char *y);


#endif // __WINTERNITZ_H
