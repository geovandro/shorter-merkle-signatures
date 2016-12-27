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
