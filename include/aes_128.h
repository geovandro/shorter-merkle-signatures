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

#ifndef __AES_128_H_
#define __AES_128_H_

#define AES_128_BLOCK_SIZE	16
#define AES_128_KEY_SIZE	16

void aes128_encrypt_keyexpanded(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE]);//, const unsigned char expandedKey[11*AES_128_KEY_SIZE]);
void aes_128_encrypt(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char key[AES_128_KEY_SIZE]);

#ifdef AES_ENC_DEC
    #ifdef AES_CBC_MODE

    void aes_128_decrypt(unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char key[AES_128_KEY_SIZE]);
    void aes_128_cbc_encrypt(const unsigned char key[AES_128_KEY_SIZE], const unsigned char iv[AES_128_BLOCK_SIZE], const char *plaintext, unsigned char *ciphertext, unsigned int *ciphertext_len);
    void aes_128_cbc_decrypt(const unsigned char key[AES_128_KEY_SIZE], const unsigned char iv[AES_128_BLOCK_SIZE], const unsigned char *ciphertext, unsigned int ciphertext_len, char *plaintext);

    #endif	//AES_CBC
#endif	//AES_DECRYPT

#endif /* __AES_128_H_ */
