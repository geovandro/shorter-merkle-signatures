#ifndef _UTIL_H_
#define _UTIL_H_

//unsigned char rand_dig_f(void);

//short Rand(unsigned char *x, short bits, unsigned char rand_dig_f());
/*short Comp(const unsigned char *u, short ud, const unsigned char *v, short vd);
void start_seed(unsigned char seed[], short len);*/

#ifdef DEBUG

void Display(const char *tag, const unsigned char *u, unsigned short n);
void display_value(const char *tag, const unsigned char *u, unsigned short n);

/*void print_retain(const struct state_mt *state);*/
#endif

void Display(const char *tag, const unsigned char *u, unsigned short n);
int base64encode(const void* data_buf, int data_size, char* result, int result_size);
int base64decode (char *in, int in_len, unsigned char *out, int *out_len);

#endif // _UTIL_H_
