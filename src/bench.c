
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "bench.h"
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

unsigned char seed_test[LEN_BYTES(MSS_SEC_LVL)] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
unsigned char h1[LEN_BYTES(WINTERNITZ_N)], h2[LEN_BYTES(WINTERNITZ_N)];
unsigned char sig_test[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_N)];
unsigned char aux[LEN_BYTES(WINTERNITZ_N)];

void bench_mss_signature() {

    unsigned long i, benchs = ((unsigned long) 1 << MSS_HEIGHT);
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
    for (k = 0; k < 10; k++)
        mss_keygen_core(&hash1, &hash2, seed_test, &nodes[0], &nodes[1], &state_test, pkey_test);
    elapsed += clock();
    printf("Elapsed time: %.1f ms\n\n", 1000 * (float) elapsed / CLOCKS_PER_SEC / 10);

    printf("Benchmarking MSS sign ...\n");

    elapsed = -clock();
    for (i = 0; i < ((unsigned long) 1 << MSS_HEIGHT); i++)
        mss_sign_core(&state_test, seed_test, &currentLeaf_test, (const char *) M[i], strlen(M[i]), &hash1, &hash2, h1, i, &nodes[0], &nodes[1], sig_test, authpath_test, pkey_test);

    elapsed += clock();
    printf("Elapsed time: %.1f ms\n\n", 1000 * (float) elapsed / CLOCKS_PER_SEC / benchs);

    printf("Benchmarking MSS verify ...\n");
    elapsed = -clock();
    for (i = 0; i < ((unsigned long) 1 << MSS_HEIGHT); i++)
        mss_verify_core(authpath_test, (const char *) M[1], strlen(M[1]), &hash1, &hash2, h1, i, sig_test, aux, &currentLeaf_test, pkey_test);

    elapsed += clock();
    printf("Elapsed time: %.1f ms\n\n", 1000 * (float) elapsed / CLOCKS_PER_SEC / benchs);

}

void bench_hash() {

    clock_t elapsed;
    unsigned long k, benchs = 10000;
    
    unsigned char data[benchs][16];
    unsigned char digest[benchs][16];

    for (k = 0; k < benchs; k++) {
        for (int i = 0; i < 16; i++) {
            data[k][i] = 2*k + i;
        }
    }
    
    printf("Benchmarking hash init ...\n");
    
    elapsed = -clock();
    for (k = 0; k < benchs; k++)
        MMO_init(&hash1);
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", (1000000 * (float) elapsed) / CLOCKS_PER_SEC / benchs);
    
    printf("Benchmarking hash update...\n");
    elapsed = -clock();
    for (k = 0; k < benchs; k++) {
        MMO_update(&hash1, data[k], 16);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / benchs);

    printf("Benchmarking hash final...\n");
    elapsed = -clock();
    for (k = 0; k < benchs; k++) {
        MMO_final(&hash1, digest[k]);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / benchs);    
        
    printf("Benchmarking 16-byte input and ouput hash ...\n");
    elapsed = -clock();    
    for (k = 0; k < benchs; k++) {
        MMO_hash16(&hash1, data[k], digest[k]);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / benchs);    
    
    printf("Benchmarking 32-byte input 16-byte output hash ...\n");
    elapsed = -clock();    
    for (k = 0; k < benchs; k++) {
        MMO_hash32(&hash1, data[k], data[k], digest[k]);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / benchs);    
    
}

void do_bench(enum BENCH operation) {

    switch (operation) {
        case BENCH_MSS_SIGN:
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
    do_bench(BENCH_MSS_SIGN);    
    
    return 0;
}

