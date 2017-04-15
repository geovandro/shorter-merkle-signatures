/*
 * Copyright (C) 2015-2016 Geovandro Pereira, Cassius Puodzius
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

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "bench.h"
#include "mss.h"


#ifdef VERBOSE
#include "util.h"
#endif

#define BENCH_KEYGEN 10
#define BENCH_SIGNATURE ((unsigned long) 1 << MSS_HEIGHT)

struct mss_node nodes[2];
struct mss_state state_test;
struct mss_node currentLeaf_test;
struct mss_node authpath_test[MSS_HEIGHT];
mmo_t hash1, hash2;

unsigned char pkey_test[NODE_VALUE_SIZE];

unsigned char seed[LEN_BYTES(MSS_SEC_LVL)] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
unsigned char h1[LEN_BYTES(WINTERNITZ_N)], h2[LEN_BYTES(WINTERNITZ_N)];
unsigned char sig_test[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_N)];
unsigned char aux[LEN_BYTES(WINTERNITZ_N)];

void bench_mss_signature() {

    unsigned long i;
    unsigned char k;
    clock_t elapsed;

    char M[1 << MSS_HEIGHT][16];
    
    for (i = 0; i < ((unsigned long) 1 << MSS_HEIGHT); i++)
        for (k = 0; k < 16; k++)
            M[i][k] = (char) 2 * i + k;

    MMO_init(&hash1);
    MMO_init(&hash2);

    printf("Benchmarking MSS key gen ...\n");    
    
    elapsed = -clock();
    for (k = 0; k < BENCH_KEYGEN; k++)
        mss_keygen_core(&hash1, &hash2, seed, &nodes[0], &nodes[1], &state_test, pkey_test);
    elapsed += clock();
    printf("Elapsed time: %.1f ms\n\n", 1000 * (float) elapsed / CLOCKS_PER_SEC / BENCH_KEYGEN);

    printf("Benchmarking MSS sign ...\n");

    elapsed = -clock();
    for (i = 0; i < BENCH_SIGNATURE; i++)
        mss_sign_core(&state_test, seed, &currentLeaf_test, (const char *) M[i], strlen(M[i]), &hash1, &hash2, h1, i, &nodes[0], &nodes[1], sig_test, authpath_test);

    elapsed += clock();
    printf("Elapsed time: %.1f ms\n\n", 1000 * (float) elapsed / CLOCKS_PER_SEC / BENCH_SIGNATURE);

    printf("Benchmarking MSS verify ...\n");
    elapsed = -clock();
    for (i = 0; i < BENCH_SIGNATURE; i++)
        mss_verify_core(authpath_test, (const char *) M[1], strlen(M[1]), &hash1, &hash2, h1, i, sig_test, aux, &currentLeaf_test, pkey_test);

    elapsed += clock();
    printf("Elapsed time: %.1f ms\n\n", 1000 * (float) elapsed / CLOCKS_PER_SEC / BENCH_SIGNATURE);

}

void bench_hash() {

    clock_t elapsed;
    unsigned long k, hashbenchs = 10000;
    
    unsigned char data[hashbenchs][16];
    unsigned char digest[hashbenchs][16];

    for (k = 0; k < hashbenchs; k++) {
        for (int i = 0; i < 16; i++) {
            data[k][i] = 2*k + i;
        }
    }
    
    printf("Running %lu times each hash function operation.\n\n", hashbenchs);
    
    printf("Benchmarking underlying hash - init ...\n");
    
    elapsed = -clock();
    for (k = 0; k < hashbenchs; k++)
        MMO_init(&hash1);
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", (1000000 * (float) elapsed) / CLOCKS_PER_SEC / hashbenchs);
    
    printf("Benchmarking underlying hash - update...\n");
    elapsed = -clock();
    for (k = 0; k < hashbenchs; k++) {
        MMO_update(&hash1, data[k], 16);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / hashbenchs);

    printf("Benchmarking underlying hash - final...\n");
    elapsed = -clock();
    for (k = 0; k < hashbenchs; k++) {
        MMO_final(&hash1, digest[k]);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / hashbenchs);    
        
    printf("Benchmarking a fixed 16-byte input/ouput hash ...\n");
    elapsed = -clock();    
    for (k = 0; k < hashbenchs; k++) {
        MMO_hash16(&hash1, data[k], digest[k]);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / hashbenchs);    
    
    printf("Benchmarking a fixed 32-byte input, 16-byte output hash ...\n");
    elapsed = -clock();    
    for (k = 0; k < hashbenchs; k++) {
        MMO_hash32(&hash1, data[k], data[k], digest[k]);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / hashbenchs);    
    
}

void do_bench(enum BENCH operation) {

    switch (operation) {
        case BENCH_MSS:
            bench_mss_signature();
            break;
        case BENCH_HASH:
            bench_hash();
            break;
        default:
            break;
    }

}

int main() {
    
    printf("\nParameters:  WINTERNITZ_n=%u, Tree_Height=%u, Treehash_K=%u, WINTERNITZ_w=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);
    
    do_bench(BENCH_HASH);
    do_bench(BENCH_MSS);    
    
    return 0;
}

