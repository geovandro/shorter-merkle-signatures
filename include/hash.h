/*
 * Copyright (C) 2015-2016 Geovandro Pereira, Cassius Puodzius, Paulo Barreto
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
 * 
 * @param randomizeddata    The sequence dr = d1 xor r || d2 xor r || ... where di's are blocks of length HASH_BLOCKSIZE in data d
 * @param r                 The final salt r that is xored with each data block and that will be concatenated with the randomized data later
 * @param data              The plain data to be signed d
 * @param datalen           The amount of bytes in data
 */
void randomize_data(char *randomizeddata, unsigned char *r, const unsigned char *salt, const unsigned char saltlen, const char *data, const unsigned long datalen);

void MMO_init(mmo_t *mmo);
void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m);
void MMO_final(mmo_t *mmo, unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash16(mmo_t *mmo, const unsigned char M[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash32(mmo_t *mmo, const unsigned char M1[AES_128_BLOCK_SIZE], const unsigned char M2[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);

/**
 * The randomized hashing (enhanced target collision resistance (eTCR) notion) described by Halevi and Krawczyk at CRYPTO'06
 * With this technique the underlying hash function doesn't need to be collision resistant so that collision attacks are avoided.
 * 
 * @param h         The hash of the randomized data (H(r,d1 xor r,d2 xor r,...)
 * @param salt      The application salt
 * @param saltlen   
 * @param data      The original plain data d=(d1,d2,...)to be signed
 * @param datalen
 */
void etcr_hash(unsigned char *h, const unsigned char *salt, const unsigned char saltlen, const char *data, const unsigned long datalen);

void prg16(short input, const unsigned char seed[16], unsigned char output[16]);

#endif // __HASH_H
