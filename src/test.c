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

#include <stdio.h>
#include <string.h>
#include "test.h"
#include "mss.h"

#ifdef VERBOSE
#include "util.h"
#endif

#define HASH_LEN LEN_BYTES(WINTERNITZ_N)

struct mss_node nodes[2];
struct mss_state state_bench;
struct mss_node currentLeaf_bench;
struct mss_node authpath_bench[MSS_HEIGHT];
mmo_t hash1, hash2;

unsigned char pkey_test[NODE_VALUE_SIZE];

unsigned char seed[LEN_BYTES(WINTERNITZ_N)] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
unsigned char h1[HASH_LEN], h2[HASH_LEN];
unsigned char sig_bench[WINTERNITZ_L*HASH_LEN];
unsigned char aux[HASH_LEN];

unsigned short test_mss_signature() {

    unsigned char si[LEN_BYTES(WINTERNITZ_N)], ri[LEN_BYTES(WINTERNITZ_N)];
    unsigned short errors;
    uint64_t j;

    char M[16] = "--Hello, world!!";

    MMO_init(&hash1);

    // Compute Merkle Public Key and TreeHash state        
    mss_keygen_core(&hash1, &hash2, seed, &nodes[0], &nodes[1], &state_bench, pkey_test);

#if defined(VERBOSE) && defined(DEBUG)
    Display("Merkle Public Key", pkey_test, NODE_VALUE_SIZE);
    print_retain(&state_bench);
#endif 

    memcpy(si, seed, LEN_BYTES(WINTERNITZ_N));
    
    //Sign and verify for all j-th authentication paths
    errors = 0;
    for (j = 0; j < ((uint64_t) 1 << MSS_HEIGHT); j++) {

        #if defined(VERBOSE) && defined(DEBUG)
        printf("Testing MSS for leaf %llu ...", j);
        #endif
        fsgen(si, si, ri);
        mss_sign_core(&state_bench, si, ri, &currentLeaf_bench, M, strlen(M)-1, &hash1, h1, j, &nodes[0], &nodes[1], sig_bench, authpath_bench);

        #if defined(VERBOSE) && defined(DEBUG)
        Display("", sig_bench, 16);
         #endif

        if (mss_verify_core(authpath_bench, M, strlen(M)-1, h1, j, sig_bench, aux, &currentLeaf_bench, pkey_test) == MSS_OK) {
            #if defined(VERBOSE) && defined(DEBUG)
            printf(" [OK]\n");
            #endif
        } else {
            errors++;
            #if defined(VERBOSE) && defined(DEBUG)
            printf(" [ERROR]\n");
            #endif
        }
    }

    return errors;
}

int test_AES128() {
    int res;
    unsigned char cipher[AES_128_BLOCK_SIZE],
                  key[AES_128_BLOCK_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
                  plain[AES_128_BLOCK_SIZE] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    unsigned char expectedCipher[AES_128_BLOCK_SIZE] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                                                        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

    aes_128_encrypt(cipher, plain, key);

    res = memcmp(cipher, expectedCipher, AES_128_BLOCK_SIZE);

#ifdef VERBOSE
    if (res)
        Display("AES128 ciphertext", cipher, AES_128_BLOCK_SIZE);
#endif 

    return res;
}

unsigned short do_test(enum TEST operation) {
    uint64_t errors = 0;

    switch (operation) {
        case TEST_MSS_SIGN:
            errors = test_mss_signature();
#ifdef VERBOSE
            if (errors == 0) {
                printf("Shorter Merkle signature tests: PASSED\n");
                printf("All %u leaves tested.\n\n", (1 << MSS_HEIGHT));
            }
            else 
                printf("Merkle Signature tests: FAILED. #Errors: %llu \n\n", errors);
#endif
        break;
        case TEST_AES_ENC:
            errors = test_AES128();
#ifdef VERBOSE
            if (errors == 0)
                printf("AES128 tests: PASSED\n\n");
            else 
                printf("AES128 tests: FAILED\n\n");
#endif
            break;
        default:
            break;
    }

    return errors;
}


int main() {
    
    printf("\nParameters:  WINTERNITZ_n=%u, Tree_Height=%u, Treehash_K=%u, WINTERNITZ_w=%u \n\n", WINTERNITZ_N, MSS_HEIGHT, MSS_K, WINTERNITZ_W);
    
    //do_test(TEST_AES_ENC);
    do_test(TEST_MSS_SIGN);
    //do_test(TEST_MSS_SERIALIZATION);
    
    return 0;
}
