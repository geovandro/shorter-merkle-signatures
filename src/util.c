#include <stdio.h>
#include <stdlib.h>
#include "util.h"

/***************************************************************************************************/
/* Coding/Decoding																				   */
/***************************************************************************************************/

int base64encode(const void* data_buf, int data_size, char* result, int result_size) {
	const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const unsigned char *data = (const unsigned char *)data_buf;
	int result_index = 0;
	int x;
	unsigned int n = 0;
	int pad_count = data_size % 3;
	unsigned char n0, n1, n2, n3;
 
	/* increment over the length of the string, three characters at a time */
	for (x = 0; x < data_size; x += 3) {
		/* these three 8-bit (ASCII) characters become one 24-bit number */
		n = (unsigned long) data[x] << 16;
 
		if((x+1) < data_size)
			n += data[x+1] << 8;
 
		if((x+2) < data_size)
			n += data[x+2];
 
		/* this 24-bit number gets separated into four 6-bit numbers */
		n0 = (unsigned char)((unsigned long)n >> 18) & 63;
		n1 = (unsigned char)(n >> 12) & 63;
		n2 = (unsigned char)(n >> 6) & 63;
		n3 = (unsigned char)n & 63;
 
		/*
		 * if we have one byte available, then its encoding is spread
		 * out over two characters
		 */
		if(result_index >= result_size) return 1;	/* indicate failure: buffer too small */
		  result[result_index++] = base64chars[n0];
		if(result_index >= result_size) return 1;	/* indicate failure: buffer too small */
		  result[result_index++] = base64chars[n1];
 
		/*
		 * if we have only two bytes available, then their encoding is
		 * spread out over three chars
		 */
		if((x+1) < data_size) {
			if(result_index >= result_size) return 1;	/* indicate failure: buffer too small */
			result[result_index++] = base64chars[n2];
		}
 
		/*
		 * if we have all three bytes available, then their encoding is spread
		 * out over four characters
		 */
		if((x+2) < data_size) {
			if(result_index >= result_size) return 1;	/* indicate failure: buffer too small */
			result[result_index++] = base64chars[n3];
		}
	}  
 
	/*
	 * create and add padding that is required if we did not have a multiple of 3
	 * number of characters available
	 */
	if (pad_count > 0) { 
		for (; pad_count < 3; pad_count++) { 
			if(result_index >= result_size) return 1;	/* indicate failure: buffer too small */
			result[result_index++] = '=';
		} 
	}
	if(result_index >= result_size) return 1;	/* indicate failure: buffer too small */
		result[result_index] = 0;
   return 0;   /* indicate success */
}

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
    66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
    54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
};

int base64decode (char *in, int in_len, unsigned char *out, int *out_len) {
    char *end = in + in_len;
    int buf = 1, len = 0;

    while (in < end) {
        unsigned char c = d[(int)*in++];

        switch (c) {
        case WHITESPACE: continue;   /* skip whitespace */
        case INVALID:    return 1;   /* invalid input, return error */
        case EQUALS:                 /* pad character, end of data */
            in = end;
            continue;
        default:
            buf = buf << 6 | c;

            /* If the buffer is full, split it into bytes */
            if (buf & 0x1000000) {
                if ((len += 3) > *out_len) return 1; /* buffer overflow */
                *out++ = (unsigned long) buf >> 16;
                *out++ = buf >> 8;
                *out++ = buf;
                buf = 1;
            }
        }
    }

    if (buf & 0x40000) {
        if ((len += 2) > *out_len) return 1; /* buffer overflow */
        *out++ = buf >> 10;
        *out++ = buf >> 2;
    }
    else if (buf & 0x1000) {
        if (++len > *out_len) return 1; /* buffer overflow */
        *out++ = buf >> 4;
    }

    *out_len = len; /* modify to reflect the actual output size */
    return 0;
}

#undef WHITESPACE
#undef EQUALS
#undef INVALID

/***************************************************************************************************/
/* Debugging											   */
/***************************************************************************************************/

void Display(const char *tag, const unsigned char *u, unsigned short n) {
    unsigned short i;
    printf("%s:\n", tag);
    for (i = 0; i < n; i++) {
        printf("%02X", u[i]);
    }
    printf("\n\n");
}


/*unsigned char rand_dig_f(void) {
	return (unsigned char)rand();
}

short Rand(unsigned char *x, short bits, unsigned char rand_dig_f()) {
	short i, xd = (bits + 7)/8;
	for (i = 0; i < xd; i++) {
		x[i] = rand_dig_f();
	}
	i = (bits % WINTERNITZ_W);
	if (xd > 0 && i > 0) {
		x[xd - 1] &= (unsigned char)(1 << i) - 1;
	}
	while (xd > 0 && x[xd - 1] == 0) {
		xd--;
	}
	return xd;
}*/

/**
 * Returns -1, 0, or +1 if u < v, u = v, or u > v, respectively
 */
short Comp(const unsigned char *u, short ud, const unsigned char *v, short vd) {
	short i;
	//assert(ud >= 0);
	//assert(vd >= 0);
	if (ud < vd) {
		return -1;
	}
	if (ud > vd) {
		return +1;
	}
	// ud == vd
	for (i = ud - 1; i >= 0; i--) {
		if (u[i] < v[i]) {
			return -1;
		}
		if (u[i] > v[i]) {
			return +1;
		}
	}
	return 0;
}

void display_value(const char *tag, const unsigned char *u, unsigned short n) {
	unsigned short i;
	printf("{");
	for (i = 0; i < n; i++) {
		printf("0x%02x", u[i]);
		if(i < n-1)
			printf(",");
	}
	printf("},\n");
}

void start_seed(unsigned char seed[], short len) {
	unsigned short j;
	for (j = 0; j < len; j++) {
		seed[j] = 0xA0 ^ j; // sample seed, for debugging only
	}
}
