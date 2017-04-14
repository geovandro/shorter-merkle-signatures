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

void prg16(short input, const unsigned char seed[16], unsigned char output[16]);

#endif // __HASH_H
