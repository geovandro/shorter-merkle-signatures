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

#include <stdint.h>
#include "aes_128.h"
#include "sph_sha2.h"

//#define HASH_BLOCKSIZE AES_128_BLOCK_SIZE
#define HASH_BLOCKSIZE 64 // SHA256 block size is 512 bits
#define HASH_OUTPUTSIZE 32 // SHA256 output size is 256 bits

typedef struct {
    unsigned char H[AES_128_KEY_SIZE]; // hash chaining state
    unsigned char M[HASH_BLOCKSIZE]; // message block
    unsigned int t; // remaining space on M, in unsigned chars
    unsigned int n; // total message length
} mmo_t;

void MMO_init(mmo_t *mmo);
void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m);
void MMO_final(mmo_t *mmo, unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash16(mmo_t *mmo, const unsigned char M[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);
void MMO_hash32(mmo_t *mmo, const unsigned char M1[AES_128_BLOCK_SIZE], const unsigned char M2[AES_128_BLOCK_SIZE], unsigned char tag[AES_128_BLOCK_SIZE]);
void hash32(const unsigned char *in, unsigned int inlen, unsigned char *out);

/**
 * The randomized hashing (enhanced target collision resistance (eTCR) notion) described by Halevi and Krawczyk at CRYPTO'06
 * cf. for example https://tools.ietf.org/html/draft-irtf-cfrg-rhash-01 
 * With this technique the underlying hash function doesn't need to be collision resistant so that off-line collision attacks are avoided.
 * 
 * @param r         The application salt
 * @param rlen   
 * @param data      The original plain data d=(d1,d2,...) to be signed
 * @param datalen
 * @param h         The hash of the randomized data (H(rp,d1 xor rp,d2 xor rp,...)
 */
void etcr_hash(const unsigned char *r, const unsigned char rlen, const char *data, const unsigned short datalen, unsigned char *h);

/**
 * HMAC, a provable PseudoRandom Function based on hash functions
 * returns hash(o_key_pad || hash(i_key_pad || message)) 
 * src: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 * @param key       The index for the function family member
 * @param keylen
 * @param message   The input for the PRF
 * @param msglen
 */
void hmac(const unsigned char *key, unsigned int keylen, const unsigned char *message, unsigned int msglen, unsigned char *output);

void prg(const unsigned char seed[32], uint64_t input, unsigned char output[32]);

/**
 * An implementation of the Pseudorandom function family suggested at section 2 of 
 * "Forward secure signatures on smart cards" by Hulsing, Busold and Buchmann
 * @param key
 * @param input      A fixed input produced once at WOTS+ key generation
 * @param output
 */
void prg32(const unsigned char key[32], const unsigned char input[32], unsigned char output[32]);

/**
 * Forward secure pseudorandom generator as suggested in 
 * "Forward secure signatures on smart cards" by Hulsing, Busold and Buchmann
 * @param seed
 * @param nextseed
 * @param rand
 */
void fsgen(const unsigned char seed[32], unsigned char nextseed[32], unsigned char rand[32]);


#endif // __HASH_H
