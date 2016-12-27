#ifndef __HASH_H
#define __HASH_H

#include "aes_128.h"

typedef struct {
    unsigned char H[AES_128_KEY_SIZE]; // hash chaining state
    unsigned char M[AES_128_BLOCK_SIZE]; // message block
    unsigned int t; // remaining space on M, in unsigned chars
    unsigned int n; // total message length
} mmo_t;

void MMO_init(mmo_t *mmo);
void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m);
void MMO_final(mmo_t *mmo, unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash16(mmo_t *mmo, const unsigned char M[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash32(mmo_t *mmo, const unsigned char M1[AES_128_BLOCK_SIZE], const unsigned char M2[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);

//forward secure pseudo-random generator
//short fsprg_counter = 0;
//void fsprg(unsigned char seed[16], unsigned char out1[16], unsigned char out2[32]);
//void fsprg_restart();

void prg16(short input, const unsigned char seed[16], unsigned char output[16]);

#endif // __HASH_H
