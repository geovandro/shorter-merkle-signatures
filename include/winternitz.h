#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H

#include "hash.h"

#define WINTERNITZ_OK 1
#define WINTERNITZ_ERROR 0


#define WINTERNITZ_SEC_LVL	128
#define WINTERNITZ_W		2
#define WINTERNITZ_N 		128

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
#define LEN_BYTES(len_bits) ((len_bits+7)/8)

void winternitz_keygen(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], mmo_t *hash1, mmo_t *hash2, unsigned char v[LEN_BYTES(WINTERNITZ_N)]);
void winternitz_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], mmo_t *hash, unsigned char h[], unsigned char sig[]);
unsigned char winternitz_verify(const unsigned char v[], mmo_t *hash1, mmo_t *hash2, unsigned char h[], const unsigned char sig[], unsigned char x[]);


#endif // __WINTERNITZ_H
