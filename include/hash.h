/*
 * Copyright (C) 2015-2017 Geovandro Pereira, Cassius Puodzius, Paulo Barreto
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

#ifndef __HASH_H
#define __HASH_H

#include "aes_128.h"

#define HASH_BLOCKSIZE AES_128_BLOCK_SIZE

typedef struct {
    unsigned char H[AES_128_KEY_SIZE]; // hash chaining state
    unsigned char M[HASH_BLOCKSIZE]; // message block
    unsigned int t; // remaining space on M, in unsigned chars
    unsigned int n; // total message length
} mmo_t;

/**
 * Recommendation is that rp is unpredictable and r is at least 128 bits to provide minimal security
 *  
 * @param rp
 * @param r
 * @param rlen
 */
void rmx_salt(unsigned char *rp, const unsigned char *r, const unsigned int rlen);

/**
 * The randomization of the plain message as suggested in https://tools.ietf.org/html/draft-irtf-cfrg-rhash-01
 * 
 * @param randomizeddata     The sequence drp = rp || d1 XOR rp || ... dt XOR rp where di's are data blocks of length HASH_BLOCKSIZE and dt is possibly padded with zeros if needed
 * @param rp                 The salt rp is xored with each data block and that will be concatenated with the randomized data later
 * @param r
 * @param rlen
 * @param d                 The plain data to be signed
 * @param dlen              The amount of bytes in data
 */
void rmx(char *randomizeddata, unsigned char *rp, const unsigned char *r, const unsigned char rlen, const char *data, const unsigned long datalen);

void MMO_init(mmo_t *mmo);
void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m);
void MMO_final(mmo_t *mmo, unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash16(mmo_t *mmo, const unsigned char M[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash32(mmo_t *mmo, const unsigned char M1[AES_128_BLOCK_SIZE], const unsigned char M2[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);

/**
 * The randomized hashing (enhanced target collision resistance (eTCR) notion) described by Halevi and Krawczyk at CRYPTO'06
 * cf. for example https://tools.ietf.org/html/draft-irtf-cfrg-rhash-01 
 * With this technique the underlying hash function doesn't need to be collision resistant so that off-line collision attacks are avoided.
 * 
 * @param h         The hash of the randomized data (H(rp,d1 xor rp,d2 xor rp,...)
 * @param r         The application salt
 * @param rlen   
 * @param data      The original plain data d=(d1,d2,...)to be signed
 * @param datalen
 */
void etcr_hash(unsigned char *h, const unsigned char *r, const unsigned char rlen, const char *data, const unsigned short datalen);

void prg16(short input, const unsigned char seed[16], unsigned char output[16]);

#endif // __HASH_H
