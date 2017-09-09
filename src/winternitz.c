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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <string.h>

#include "winternitz.h"

void winternitz_chaining(unsigned char sk[LEN_BYTES(WINTERNITZ_N)], unsigned char x[LEN_BYTES(WINTERNITZ_N)], unsigned int t, unsigned char output[LEN_BYTES(WINTERNITZ_N)]) {
    unsigned int i;
    
    if (t == 0) {
        memcpy(output, sk, LEN_BYTES(WINTERNITZ_N));
        return;
    }
    
    prg32(sk,x,output);             //output = F_{sk}(X)
    for (i = 1; i < t; i++)
        prg32(output,x,output);     //output = F_{output}(X)
    
}

void winternitz_keygen(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char x[LEN_BYTES(WINTERNITZ_N)], unsigned char v[LEN_BYTES(WINTERNITZ_N)]) {
    unsigned char i;
    sph_sha256_context ctx;
    
    sph_sha256_init(&ctx); // Context for the hash y = H(y_1 || ... || y_L)
    
    for (i = 0; i < WINTERNITZ_L; i++) {                        // chunk count, including checksum
        prg(s,i,v);                                             // v = sk_i = private block for i-th byte
        winternitz_chaining(v, x, (1 << WINTERNITZ_W)-1, v);    // v is the hash chain of its previous value = y_i = F_{sk_i}^{2^w-1}(X)
        sph_sha256(&ctx, v, LEN_BYTES(WINTERNITZ_N));
    }
    sph_sha256_close(&ctx, v);                                  // y = H(y_1 || ... || y_L)

}

#if WINTERNITZ_W == 2

void winternitz_2_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, unsigned char *sig) {
    unsigned char i, seed_i[LEN_BYTES(WINTERNITZ_N)];
    unsigned short checksum = 0;
    
    memcpy(seed_i, s, LEN_BYTES(WINTERNITZ_N));
    
    // data part:
    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // 0 part:
        fsgen(seed_i, seed_i, sig); // (seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) where sig = s_i = private block for i-th "0" chunk

        checksum += 3-(h[i] & 3);
        
        winternitz_chaining(sig, X, h[i] & 3, sig);
        
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk

        // 1 part:
        fsgen(seed_i, seed_i, sig); // (seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block for i-th "1" chunk             
       
        checksum += 3-((h[i]>> 2) & 3);
        
        winternitz_chaining(sig, X, (h[i]>> 2) & 3, sig);        

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk

        // 2 part:
        fsgen(seed_i, seed_i, sig); // (seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block for i-th "2" chunk            
        
        checksum += 3-((h[i]>> 4) & 3);
        
        winternitz_chaining(sig, X, (h[i]>> 4) & 3, sig); 

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk

        // 3 part:
        fsgen(seed_i, seed_i, sig); // (seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block for i-th "3" chunk 
        
        checksum += 3-((h[i]>> 6) & 3);
        
        winternitz_chaining(sig, X, (h[i]>> 6) & 3, sig); 

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk
    }

    // checksum part:
    for (i = 0; i < WINTERNITZ_l2; i++) { // checksum
        fsgen(seed_i, seed_i, sig); // (seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block for i-th checksum chunk         

        winternitz_chaining(sig, X, checksum & 3, sig); 

        checksum >>= 2;
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }
}
#endif // WINTERNITZ_W == 2


#if WINTERNITZ_W == 4

void winternitz_4_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, unsigned char *sig) {
    //Sign h = H(v, M) under private key s, yielding (x_{0:lo}, x_{0:hi}, ..., x_{(N/8-1):lo}, x_{(N/8-1):hi})
    unsigned char i, c, seed_i[LEN_BYTES(WINTERNITZ_N)];
    unsigned short checksum = 0;
    
    memcpy(seed_i, s, LEN_BYTES(WINTERNITZ_N));    
    
    // data part:
    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // lo part:
        fsgen(seed_i, seed_i, sig); //(seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block s_2i for i-th "lo" nybble         

        c = h[i] & 15; // lo nybble
        checksum += 15 - (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif

        winternitz_chaining(sig, X, c, sig);

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble

        // hi part:
        fsgen(seed_i, seed_i, sig); //(seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block for i-th "hi" nybble

        c = h[i] >> 4; // hi nybble
        checksum += 15 - (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif
        winternitz_chaining(sig, X, c, sig);

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        fsgen(seed_i, seed_i, sig); //(seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) sig holds the private block for i-th checksum nybble

        c = checksum & 15; // least significant nybble
        checksum >>= 4;

#ifdef DEBUG
        assert(c < 16);
#endif
        winternitz_chaining(sig, X, c, sig);

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }

}
#endif // WINTERNITZ_W = 4

#if WINTERNITZ_W == 8

void winternitz_8_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, unsigned char *sig) {
    //Sign h = H(v, M) under private key s, yielding (x_{0}, x_{1}, ..., x_{N/8-1})    
    unsigned char i, seed_i[LEN_BYTES(WINTERNITZ_N)];
    unsigned short c, checksum = 0;
    
    memcpy(seed_i, s, LEN_BYTES(WINTERNITZ_N));
    
    // data part:
    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // process 8-bit chunk
        
        fsgen(seed_i, seed_i, sig); //(seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) where sig = s_i = private block for i-th byte
        // sig holds the private block i-th byte               
        
        checksum += 255 - (unsigned char) h[i];

        winternitz_chaining(sig, X, h[i], sig); // sig holds the hash chain on s_i, sig = F_{s_i}^{h[i]}(X)

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        fsgen(seed_i, seed_i, sig); //(seed_{i+1}, sig) =  F_{seed_i}(0)||F_{seed_i}(1) where sig = s_i = private block for i-th byte
        // sig holds the private block for i-th checksum unsigned char

        c = checksum & 255; // least significant byte of the checksum
        checksum >>= 8;

#ifdef DEBUG
        assert(c < 256);
#endif

        winternitz_chaining(sig, X, c, sig); // sig holds the hash chain on s_i, sig = F_{s_i}^{h[i]}(X)

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next unsigned char
    }
    
}
#endif /* WINTERNITZ_W = 8*/

void winternitz_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, unsigned char *sig) {

#if WINTERNITZ_W == 2
    winternitz_2_sign(s, X, h, sig);
#elif WINTERNITZ_W == 4
    winternitz_4_sign(s, X, h, sig);
#elif WINTERNITZ_W == 8
    winternitz_8_sign(s, X, h, sig);
#endif
}

#if WINTERNITZ_W == 2

unsigned char winternitz_2_verify(const unsigned char *v, unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, const unsigned char *sig, unsigned char *y) {
    unsigned char i, c;
    unsigned short checksum = 0;
    sph_sha256_context ctx;

    sph_sha256_init(&ctx);

    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // 0 part:
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the current signature block
        c = 3 - ((h[i] >> 0) & 3); // chunk
        checksum += (unsigned short) c;
        
        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // 1 part:
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the current signature block
        c = 3 - ((h[i] >> 2) & 3); // chunk
        checksum += (unsigned short) c;
        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // 2 part:
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the current signature block
        c = 3 - ((h[i] >> 4) & 3); // chunk
        checksum += (unsigned short) c;
        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // 3 part:
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the current signature block
        c = 3 - ((h[i] >> 6) & 3); // chunk
        checksum += (unsigned short) c;
        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_l2; i++) { // checksum
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the current signature block
        c = 3 - (checksum & 3); // chunk
        checksum >>= 2;
        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value
        
        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    sph_sha256_close(&ctx, y);

    return (memcmp(y, v, LEN_BYTES(WINTERNITZ_N)) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif // WINTERNITZ_W == 2

#if WINTERNITZ_W == 4

unsigned char winternitz_4_verify(const unsigned char *v, unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, const unsigned char *sig, unsigned char *y) {
    unsigned char i, c;
    unsigned short checksum = 0;
    sph_sha256_context ctx;

    sph_sha256_init(&ctx);
    
    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // lo part:
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the i-th signature block
        c = 15 - (h[i] & 15); // lo nybble
        checksum += (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif

        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // hi part:
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // x is now the i-th signature block
        c = 15 - (h[i] >> 4); // hi nybble
        checksum += (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif

        winternitz_chaining(y, X, c, y); // y holds the hash of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the i-th signature block
        c = 15 - (checksum & 15); // least significant nybble
        checksum >>= 4;

#ifdef DEBUG
        assert(c < 16);
#endif

        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    sph_sha256_close(&ctx, y);

    return (memcmp(y, v, LEN_BYTES(WINTERNITZ_N)) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif /* WINTERNITZ_W = 4*/

#if WINTERNITZ_W == 8

unsigned char winternitz_8_verify(const unsigned char *v, unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, const unsigned char *sig, unsigned char *y) {
    unsigned char i;
    unsigned short c, checksum = 0;
    sph_sha256_context ctx;

    sph_sha256_init(&ctx);
    
    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // process a one-byte chunk
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N)); // y holds now the i-th signature block sigma_i
        c = 255 - (unsigned char) h[i];          // Compute the checksum component c = 2^w-1-m_i
        checksum += (unsigned char) c;           // Update the overall checksum with the current component CS = CS + 2^w-1-m_i

#ifdef DEBUG
        assert(c < 256);
#endif

        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        memcpy(y, sig, LEN_BYTES(WINTERNITZ_N));    // y holds now the i-th signature block
        c = 255 - (unsigned char) (checksum & 255); // process the least significant byte of the checksum
        checksum >>= 8;                             // go to the next checksum byte

#ifdef DEBUG
        assert(c < 256);
#endif

        winternitz_chaining(y, X, c, y); // y holds the hash chain of its previous value

        sph_sha256(&ctx, y, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    sph_sha256_close(&ctx, y);

    return (memcmp(y, v, LEN_BYTES(WINTERNITZ_N)) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
    
}
#endif // WINTERNITZ_W = 8

unsigned char winternitz_verify(const unsigned char *v, unsigned char X[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, const unsigned char *sig, unsigned char *x) {
#if WINTERNITZ_W == 2
    return winternitz_2_verify(v, X, h, sig, x);
#elif WINTERNITZ_W == 4
    return winternitz_4_verify(v, X, h, sig, x);
#elif WINTERNITZ_W == 8
    return winternitz_8_verify(v, X, h, sig, x);
#endif
    return WINTERNITZ_ERROR;
}

