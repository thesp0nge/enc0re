/* 
 * This file is part of the enc0re distribution
 * (https://github.com/thesp0nge/enc0re).
 * Copyright (C) 2019, Paolo Perego - paolo@armoredcode.com
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include "enc0re_utils.h"

char *word_to_string(char *buf) {
  char str[17];
  sprintf(str,"\\x%02x\\x%02x\\x%02x\\x%02x", (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2], (unsigned char)buf[3]);
  return strdup(str);
}

char *word_to_asm(char *buf) {
  char str[17];
  sprintf(str,"0x%02x%02x%02x%02x", (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2], (unsigned char)buf[3]);
  return strdup(str);
}

int print_word(char *buf) {
  return fprintf(stdout, "\\x%02x\\x%02x\\x%02x\\x%02x\n", 
      (unsigned char)buf[0],
      (unsigned char)buf[1],
      (unsigned char)buf[2],
      (unsigned char)buf[3]);
}

int read_word(char *buf, FILE *fp){
  int ret;

  bzero((void *)buf, 4);
  if ((ret = fread(buf, 4, sizeof(char), fp)) < 0 ){
    perror("fread()");
    return -1;
  }

  return ret;
}

int read_word_and_pad(char *buf, int count, FILE *fp){
  int ret;

  if (count >= 4) 
    return 0;

  buf[0]=0x90;
  buf[1]=0x90;
  buf[2]=0x90;
  buf[3]=0x90;
  buf[4]=0x00;

  if ((ret = fread(buf, count, sizeof(char), fp)) < 0 ){
    perror("fread()");
    return -1;
  }

  return ret;
}

void xor_word(char *dest, char *src, char *key) {
  for (int z=0; z<5; z++) 
    dest[z] = src[z] ^ key[z];

  return ;

}

