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
#include "test.h"
#include "mss.h"

#ifdef VERBOSE
#include "util.h"
#endif

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

unsigned short test_mss_signature() {

    unsigned short errors;
    unsigned long j;

    char M[16] = "--Hello, world!!";

    MMO_init(&hash1);
    MMO_init(&hash2);

    // Compute Merkle Public Key and TreeHash state        
    mss_keygen_core(&hash1, &hash2, seed, &nodes[0], &nodes[1], &state_test, pkey_test);

#if defined(VERBOSE) && defined(DEBUG)
    Display("Merkle Public Key", pkey_test, NODE_VALUE_SIZE);
    print_retain(&state_test);
#endif 

    //Sign and verify for all j-th authentication paths
    errors = 0;
    for (j = 0; j < ((unsigned long) 1 << MSS_HEIGHT); j++) {

#if defined(VERBOSE) && defined(DEBUG)
    printf("Testing MSS for leaf %ld ...", j);
#endif

    mss_sign_core(&state_test, seed, &currentLeaf_test, (const char *) M, strlen(M)-1, &hash1, &hash2, h1, j, &nodes[0], &nodes[1], sig_test, authpath_test);

#if defined(VERBOSE) && defined(DEBUG)
    Display("", sig_test, 16);
#endif

    if (mss_verify_core(authpath_test, (const char *) M, strlen(M)-1, &hash1, &hash2, h1, j, sig_test, aux, &currentLeaf_test, pkey_test) == MSS_OK) {

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

#ifdef SERIALIZATION

int test_mss_serialization() {
    unsigned short errors = 0;

    struct mss_node node_in, node_out;
    struct mss_state state_in, state_out;

    unsigned short index_in = 0, index_out;
    unsigned char skey_in[LEN_BYTES(MSS_SEC_LVL)], skey_out[LEN_BYTES(MSS_SEC_LVL)];

    unsigned char ots_in[MSS_OTS_SIZE], ots_out[MSS_OTS_SIZE];
    struct mss_node authpath_in[MSS_HEIGHT], authpath_out[MSS_HEIGHT];

    // MSS NODE
    printf("Testing MSS Node serialization/deserialization ...\n");
    unsigned char buffer_node[MSS_NODE_SIZE];

    serialize_mss_node(node_in, buffer_node);
    deserialize_mss_node(&node_out, buffer_node);

    if (memcmp(&node_in, &node_out, sizeof (node_in)) == 0) {
        printf(" [OK]\n");
    } else {
        errors++;
        printf(" [ERROR]\n");
    }

    // MSS STATE
    printf("Testing MSS State serialization/deserialization...");
    unsigned char buffer_state[MSS_STATE_SIZE];

    serialize_mss_state(state_in, index_in, buffer_state);
    deserialize_mss_state(&state_out, &index_out, buffer_state);

    if ((memcmp(&node_in, &node_out, sizeof (node_in)) == 0) && (index_in == index_out)) {
        printf(" [OK]\n");
    } else {
        errors++;
        printf(" [ERROR]\n");
    }

    // SKEY
    printf("Testing MSS skey serialization/deserialization...");
    unsigned char buffer_skey[MSS_SKEY_SIZE];

    serialize_mss_skey(state_in, index_in, skey_in, buffer_skey);
    deserialize_mss_skey(&state_out, &index_out, skey_out, buffer_skey);

    if ((memcmp(&skey_in, &skey_out, sizeof (skey_in)) == 0) && (memcmp(&state_in, &state_out, sizeof (state_in)) == 0) && (index_in == index_out)) {
        printf(" [OK]\n");
    } else {
        errors++;
        printf(" [ERROR]\n");
    }

    // SIGNATURE
    printf("Testing MSS Signature serialization/deserialization...");
    unsigned char buffer_signature[MSS_SIGNATURE_SIZE];

    serialize_mss_signature(ots_in, node_in, authpath_in, buffer_signature);
    deserialize_mss_signature(ots_out, &node_out, authpath_out, buffer_signature);

    if ((memcmp(&ots_in, &ots_out, sizeof (ots_in)) == 0) && (memcmp(&node_in, &node_out, sizeof (node_in)) == 0) && (memcmp(authpath_in, authpath_out, sizeof (authpath_in)) == 0)) {
        printf(" [OK]\n");
    } else {
        errors++;
        printf(" [ERROR]\n");
    }

    return errors;
}

#endif //test_mss_serialization

unsigned short do_test(enum TEST operation) {
    unsigned short errors = 0;

    switch (operation) {
        case TEST_MSS_SIGN:
            errors = test_mss_signature();
#ifdef VERBOSE
            if (errors == 0) {
                printf("Shorter Merkle signature tests: PASSED\n");
                printf("All %u leaves tested.\n\n", (1 << MSS_HEIGHT));
            }
            else 
                printf("Merkle Signature tests: FAILED. #Errors: %u \n\n", errors);
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
#ifdef SERIALIZATION
        case TEST_MSS_SERIALIZATION:
            errors = test_mss_serialization();
#ifdef VERBOSE
            if (errors == 0)
                printf("Merkle signature serialization tests: PASSED\n\n");
            else 
                printf("Merkle signature serialization tests: FAILED. #Errors: %u \n\n", errors);
#endif            
            break;
#endif
        default:
            break;
    }

    return errors;
}

//#ifdef SELF_TEST

int main() {
    
    printf("\nParameters:  WINTERNITZ_n=%u, Tree_Height=%u, Treehash_K=%u, WINTERNITZ_w=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);
    
    //do_test(TEST_AES_ENC);
    do_test(TEST_MSS_SIGN);
    //do_test(TEST_MSS_SERIALIZATION);
    
    return 0;
}

//#endif
