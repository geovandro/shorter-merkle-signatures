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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <string.h>

#include "winternitz.h"

void winternitz_keygen(const unsigned char s[LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char v[LEN_BYTES(WINTERNITZ_N)]) {
    unsigned char i, j;
    sph_sha256_context ctx, y;
    
    sph_sha256_init(&y); // Context for the hash y = H(y1 || y2 || ... || yL)
        
    for (i = 0; i < WINTERNITZ_L; i++) { // chunk count, including checksum
        sph_sha256_init(&ctx);
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        sph_sha256(&ctx, &i, 1);        
        sph_sha256_close(&ctx, v); //v = s_i = H(s,i) = private block for i-th byte

        for (j = 0; j < (1 << WINTERNITZ_W) - 1; j++)
            hash32(v, LEN_BYTES(WINTERNITZ_N), v); // v is the hash of its previous value = y_i = H^{2^w-1}(s_i)
        
        sph_sha256(&y, v, LEN_BYTES(WINTERNITZ_N));
    }
    sph_sha256_close(&y, v);

}

#if WINTERNITZ_W == 2

void winternitz_2_sign(const unsigned char s[LEN_BYTES(WINTERNITZ_N)], unsigned char *h, unsigned char *sig) {
    unsigned char i, c;
    unsigned short checksum = 0;
    sph_sha256_context ctx;

    sph_sha256_init(&ctx);    
    
    // data part:
    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // 0 part:
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (i << 2) + 0;
        sph_sha256(&ctx, &c, 1); //H(s, 4i + 0) // 0 chunk index
        sph_sha256_close(&ctx, sig); //sig = s_i = H(s,4i+0) // sig holds the private block for i-th "0" chunk        

        checksum += 3;
        switch ((h[i]) & 3) { // 0 chunk
            case 3:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 2:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 1:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 0:
                ;
                // FALLTHROUGH
        }
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk

        // 1 part:
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (i << 2) + 1;
        sph_sha256(&ctx, &c, 1); //H(s, 4i + 1) // 1 chunk index
        sph_sha256_close(&ctx, sig); //sig = s_i = H(s,4i+1) // sig holds the private block for i-th "1" chunk             
       
        checksum += 3;
        switch ((h[i] >> 2) & 3) { // 1 chunk
            case 3:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 2:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 1:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 0:
                ;
                // FALLTHROUGH
        }
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk

        // 2 part:
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (i << 2) + 2;
        sph_sha256(&ctx, &c, 1); //H(s, 4i + 2) // 2 chunk index
        sph_sha256_close(&ctx, sig); //sig = s_i = H(s,4i+2) // sig holds the private block for i-th "2" chunk            
        
        checksum += 3;
        switch ((h[i] >> 4) & 3) { // 2 chunk
            case 3:
                checksum--; // FALLTHROUGH
            case 2:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 1:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 0:
                ;
                // FALLTHROUGH
        }
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk

        // 3 part:
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (i << 2) + 3;
        sph_sha256(&ctx, &c, 1); //H(s, 4i + 3) // 3 chunk index
        sph_sha256_close(&ctx, sig); //sig = s_i = H(s,4i+2) // sig holds the private block for i-th "3" chunk 
        
        checksum += 3;
        switch ((h[i] >> 6) & 3) { // 3 chunk
            case 3:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 2:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 1:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                checksum--; // FALLTHROUGH
            case 0:
                ;
                // FALLTHROUGH
        }
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next chunk
    }

    // checksum part:
    for (i = 0; i < WINTERNITZ_l2; i++) { // checksum
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (LEN_BYTES(WINTERNITZ_N) << 2) + i;
        sph_sha256(&ctx, &c, 1); //H(s, 4*(N/8) + i) // i-th chunk index
        sph_sha256_close(&ctx, sig); //sig = s_i = H(s,4*(N/8) + i) // sig holds the private block for i-th checksum chunk         

        switch (checksum & 3) { // 3 chunk
            case 3:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                // FALLTHROUGH
            case 2:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                // FALLTHROUGH
            case 1:
                hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value
                // FALLTHROUGH
            case 0:
                ;
                // FALLTHROUGH
        }
        checksum >>= 2;
        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }
}
#endif // WINTERNITZ_W == 2


#if WINTERNITZ_W == 4

void winternitz_4_sign(const unsigned char *s, unsigned char *h, unsigned char sig[/*(2*N/8+3)*N/8*/] /* 2(N/8)+3 (N/8)-unsigned char blocks */) {
    //Sign h = H(v, M) under private key s, yielding (x_{0:lo}, x_{0:hi}, ..., x_{(N/8-1):lo}, x_{(N/8-1):hi})
    unsigned char i, j, c;
    unsigned short checksum = 0;
    sph_sha256_context ctx;

    sph_sha256_init(&ctx);   
    
    // data part:
    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // lo part:
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (i << 1) + 0;
        sph_sha256(&ctx, &c, 1); //H(s, 2i + 0) // lo nybble tag
        sph_sha256_close(&ctx, sig); //sig holds the private block s_{2i} for i-th "lo" nybble         

        c = h[i] & 15; // lo nybble
        checksum += 15 - (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++)
            hash32(sig, LEN_BYTES(WINTERNITZ_N), sig);

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble

        // hi part:
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (i << 1) + 1; 
        sph_sha256(&ctx, &c, 1); // H(s, 2i + 1) // hi nybble tag
        sph_sha256_close(&ctx, sig); // sig holds the private block for i-th "hi" nybble

        c = h[i] >> 4; // hi nybble
        checksum += 15 - (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif
        for (j = 0; j < c; j++)
            hash32(sig, LEN_BYTES(WINTERNITZ_N), sig);

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = (LEN_BYTES(WINTERNITZ_N) << 1) + i; 
        sph_sha256(&ctx, &c, 1); // H(s, 2n + i) // lo nybble tag
        sph_sha256_close(&ctx, sig); // sig holds the private block for i-th checksum nybble

        c = checksum & 15; // least significant nybble
        checksum >>= 4;

#ifdef DEBUG
        assert(c < 16);
#endif
        for (j = 0; j < c; j++)
            hash32(sig, LEN_BYTES(WINTERNITZ_N), sig);

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }

}
#endif // WINTERNITZ_W = 4

#if WINTERNITZ_W == 8

void winternitz_8_sign(const unsigned char *s, unsigned char *h, unsigned char sig[/*(N/8+2)*N/8*/] /* N/8+2 N/8-unsigned char blocks */) {
    //Sign h = H(v, M) under private key s, yielding (x_{0}, x_{1}, ..., x_{N/8-1})    
    unsigned char i, j;
    unsigned short c, checksum = 0;
    sph_sha256_context ctx;

    sph_sha256_init(&ctx);      

    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) {
        // process 8-bit chunk
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = i;
        sph_sha256(&ctx, &c, 1); // H(s, i) // byte tag
        sph_sha256_close(&ctx, sig); // sig holds the private block i-th byte               
        
        checksum += 255 - (unsigned char) h[i];

#ifdef DEBUG
        assert(h[i] < 256);
#endif

        for (j = 0; j < (unsigned char) h[i]; j++)
            hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        sph_sha256(&ctx, s, LEN_BYTES(WINTERNITZ_SEC_LVL));
        c = LEN_BYTES(WINTERNITZ_N) + i;
        sph_sha256(&ctx, &c, 1); // H(s, N/8 + i) // byte tag
        sph_sha256_close(&ctx, sig); // sig holds the private block for i-th checksum unsigned char

        c = checksum & 255; // least significant unsigned char
        checksum >>= 8;

#ifdef DEBUG
        assert(c < 256);
#endif

        for (j = 0; j < (unsigned char) c; j++)
            hash32(sig, LEN_BYTES(WINTERNITZ_N), sig); // sig holds the hash of its previous value

        sig += LEN_BYTES(WINTERNITZ_N); // signature block for next unsigned char
    }
    
}
#endif /* WINTERNITZ_W = 8*/

void winternitz_sign(const unsigned char *s, unsigned char *h, unsigned char *sig) {

#if WINTERNITZ_W == 2
    winternitz_2_sign(s, h, sig);
#elif WINTERNITZ_W == 4
    winternitz_4_sign(s, h, sig);
#elif WINTERNITZ_W == 8
    winternitz_8_sign(s, h, sig);
#endif
}

#if WINTERNITZ_W == 2

unsigned char winternitz_2_verify(const unsigned char *v, unsigned char *h, const unsigned char *sig, unsigned char *x) {
    unsigned char i, j, c;
    unsigned short checksum = 0;
    sph_sha256_context y;

    sph_sha256_init(&y);

    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) { // NB: hash length is N=128 here, but was N=256 in the predecessor scheme
        // 0 part:
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the current signature block
        c = 3 - ((h[i] >> 0) & 3); // chunk
        checksum += (unsigned short) c;
        for (j = 0; j < c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // 1 part:
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the current signature block
        c = 3 - ((h[i] >> 2) & 3); // chunk
        checksum += (unsigned short) c;
        for (j = 0; j < c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // 2 part:
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the current signature block
        c = 3 - ((h[i] >> 4) & 3); // chunk
        checksum += (unsigned short) c;
        for (j = 0; j < c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // 3 part:
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the current signature block
        c = 3 - ((h[i] >> 6) & 3); // chunk
        checksum += (unsigned short) c;
        for (j = 0; j < c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));
        
        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_l2; i++) { // checksum
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the current signature block
        c = 3 - (checksum & 3); // chunk
        checksum >>= 2;
        for (j = 0; j < c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value
        
        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    sph_sha256_close(&y, x);

    return (memcmp(x, v, LEN_BYTES(WINTERNITZ_N)) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif // WINTERNITZ_W == 2

#if WINTERNITZ_W == 4

unsigned char winternitz_4_verify(const unsigned char *v, unsigned char h[/*N/8*/], const unsigned char *sig, unsigned char *x) {
    unsigned char i, j, c;
    unsigned short checksum = 0;
    sph_sha256_context y;

    sph_sha256_init(&y);
    
    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) { // NB: hash length is N=128 here, but was N=256 in the predecessor scheme
        // lo part:
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the i-th signature block
        c = 15 - (h[i] & 15); // lo nybble
        checksum += (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block

        // hi part:
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x is now the i-th signature block
        c = 15 - (h[i] >> 4); // hi nybble
        checksum += (unsigned short) c;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++)
             hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the i-th signature block
        c = 15 - (checksum & 15); // least significant nybble
        checksum >>= 4;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++)
             hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    sph_sha256_close(&y, x);

    return (memcmp(x, v, LEN_BYTES(WINTERNITZ_N)) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif /* WINTERNITZ_W = 4*/

#if WINTERNITZ_W == 8

unsigned char winternitz_8_verify(const unsigned char *v, unsigned char *h, const unsigned char sig[/*(N/8+2)*N/8*/] /* N/8+2 N/8-unsigned char blocks */, unsigned char *x) {
    unsigned char i, j;
    unsigned short c, checksum = 0;
    sph_sha256_context y;

    sph_sha256_init(&y);
    
    // data part:

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) { // NB: hash length is N here, but was 2*N in the predecessor scheme
        // process unsigned char
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the i-th signature block
        c = 255 - (unsigned char) h[i]; // unsigned char
        checksum += (unsigned char) c;

#ifdef DEBUG
        assert(c < 256);
#endif

        for (j = 0; j < (unsigned char) c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        memcpy(x, sig, LEN_BYTES(WINTERNITZ_N)); // x holds now the i-th signature block
        c = 255 - (unsigned char) (checksum & 255); // least significant unsigned char
        checksum >>= 8;

#ifdef DEBUG
        assert(c < 256);
#endif

        for (j = 0; j < (unsigned char) c; j++)
            hash32(x, LEN_BYTES(WINTERNITZ_N), x); // x holds the hash of its previous value

        sph_sha256(&y, x, LEN_BYTES(WINTERNITZ_N));

        sig += LEN_BYTES(WINTERNITZ_N); // next signature block
    }
    sph_sha256_close(&y, x);

    return (memcmp(x, v, LEN_BYTES(WINTERNITZ_N)) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
    
}
#endif // WINTERNITZ_W = 8

unsigned char winternitz_verify(const unsigned char *v, unsigned char *h, const unsigned char *sig, unsigned char *x) {
#if WINTERNITZ_W == 2
    return winternitz_2_verify(v, h, sig, x);
#elif WINTERNITZ_W == 4
    return winternitz_4_verify(v, h, sig, x);
#elif WINTERNITZ_W == 8
    return winternitz_8_verify(v, h, sig, x);
#endif
    return WINTERNITZ_ERROR;
}

/*
\begin{itemize}
\item \textsf{Gen}:
Choose $s \samples \{0 \dots 2^w-1\}^\ell$ uniformly at random,
compute the $\ell \cdot 2^h$ strings $s_i^{(j)} \gets H(s \mid\mid i \mid\mid j)$ and correspondingly the $\ell \cdot 2^h$ strings $v_i^{(j)} \gets H^{2^w-1}(s_i^{(j)})$,
compute  $v^{(j)} \gets H(v_0^{(j)} \mid\mid \dots \mid\mid v_{\ell-1}^{(j)})$,
compute the Merkle tree nodes $q_u = H(q_{2u} \mid\mid q_{2u+1})$ for $1 \leqslant u < 2^h$, and $q_{2^h + j} = H(v^{(j)})$ for $0 \leqslant i < \ell$, $0 \leqslant j < 2^h$.
The private key is $s$, and the public key is $Y := q_1$, each consisting of $\ell$ $w$-bit words\footnote{The BDS algorithm, if adopted, would compute some ancillary information to expedite signing as well.}. The $s_i^{(j)}$ and $v^{(j)}$ keys as well as the authentication path can be recomputed on demand during a signing operation.
%
\item \textsf{Sig}:
To sign the $j$-th message $M^{(j)}$, compute the message representative $m^{(j)} := (m_0^{(j)}, \dots, m_{\ell-1}^{(j)}) \gets G(Y, v^{(j)}, M^{(j)})$,
compute $s_i^{(j)} \gets H(s \mid\mid i \mid\mid j)$ and $S_i^{(j)} \gets H^{2^w - 1 - m_i}(s_i^{(j)})$ for $0 \leqslant i < \ell$,
compute $S^{(j)} \gets (S_0^{(j)}, \dots, S_{\ell-1}^{(j)})$ and the authentication path $Q^{(j)} := (q_{\lfloor j/2^u \rfloor \oplus 1} \mid u = 0, \dots, h-1)$,
and finally let the signature be the triple $(S^{(j)}, v^{(j)}, Q^{(j)})$.
%
\item \textsf{Ver}:
To verify a signature $(S^{(j)}, v^{(j)}, Q^{(j)})$ for the $j$-th message $M^{(j)}$,
compute the message representative $m^{(j)} := (m_0^{(j)}, \dots, m_{\ell-1}^{(j)}) \gets G(Y, v^{(j)}, M^{(j)})$,
compute $t_i^{(j)} = H^{m_i^{(j)}}(S_i^{(j)})$ for $0 \leqslant i < \ell$ and $t^{(j)} \gets H(t_0^{(j)} \mid\mid \dots \mid\mid t_{\ell-1}^{(j)})$.
Then compute the nodes from the $j$-th leaf to the root via $q_{2^h + j} = H(v^{(j)})$ and $q_i \gets H(q_{2i} \mid\mid q_{2i+1})$ for $1 \leqslant i < 2^h$,
taking the missing nodes from the authentication path $Q^{(j)}$. Accept iff $q_1 = Y$ and $v^{(j)} = t^{(j)}$.
\end{itemize}
 */

#if defined(WINTERNITZ_SELFTEST)

int main(int argc, char *argv[]) {

    unsigned char n = LEN_BYTES(WINTERNITZ_N);
    mmo_t hash1, hash2;
    unsigned char s[n]; // the n-unsigned char private signing key.
    unsigned char v[m]; // the corresponding n-unsigned char verification key.
    char M[16] = " --Hello, world!";
    unsigned char h[m]; // n-unsigned char message hash.
    unsigned char sig[WINTERNITZ_L * n];
    unsigned char x[n]; // scratch (should match v at the end)
    unsigned char ok;
    unsigned char i;
    clock_t elapsed;
    int test, tests = 1;

    printf("\n Winternitz(w = %d, sec = %d) \n\n", WINTERNITZ_W, WINTERNITZ_SEC_LVL);
    printf("l1 = %d, checksum = %d, L = %d \n\n", WINTERNITZ_l1, WINTERNITZ_CHECKSUM_SIZE, WINTERNITZ_L);
    //printf("mem occupation: %d unsigned chars.\n",
    //	sizeof(priv) + sizeof(hash) + sizeof(pubk) + sizeof(s) + sizeof(v) + sizeof(M) + sizeof(h) + sizeof(sig) + sizeof(x));
    printf("sig size: %u unsigned chars.\n\n", (unsigned int) sizeof (sig));

    for (i = 0; i < n; i++) {
        s[i] = 0xA0 ^ i; // sample private key, for debugging only
    }

    printf("======== GEN ========\n");
    elapsed = -clock();
    //display("priv", s, LEN_BYTES(WINTERNITZ_N));
    for (test = 0; test < tests; test++) {
        winternitz_keygen(s, n, &hash1, &hash2, v);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / tests);
    //display("pubk", v, LEN_BYTES(WINTERNITZ_N));

    printf("======== SIG ========\n");
    elapsed = -clock();
    for (test = 0; test < tests; test++) {
        winternitz_sign(s, &hash1, h, sig);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / tests);
    //display("wsig", sig, 2*LEN_BYTES(WINTERNITZ_N)*LEN_BYTES(WINTERNITZ_N));

    MMO_init(&hash);
    DM_init(&f);

    printf("======== VER ========\n");
    elapsed = -clock();
    for (test = 0; test < tests; test++) {
        ok = winternitz_verify(v, &hash1, &hash2, h, sig, x);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000 * (float) elapsed / CLOCKS_PER_SEC / tests);
    printf("**** verification ok? >>>> %s <<<<\n", ok ? "true" : "false");
    //display("verv", x, LEN_BYTES(WINTERNITZ_N));
    return 0;
}
#endif
