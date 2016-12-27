#ifndef __TI_AES_H_
#define __TI_AES_H_


void expandKey(unsigned char *expandedKey, unsigned char *key);
unsigned char galois_mul2(unsigned char value);
void aes_encr(unsigned char *state, unsigned char *expandedKey);
void ti_aes_encrypt(unsigned char *state, unsigned char *key);

#endif /* __TI_AES_H_ */
