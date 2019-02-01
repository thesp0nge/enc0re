/*
 * enc0re.c - custom binary encoder just for fun and for OSCE preparation.
 * (c) 2019, Paolo Perego - paolo@armoredcode.com
 *
 * # Changelog
 * 
 * This is the enc0re tool changelog. enc0re is a simple tool I wrote to create
 * custom encoding schemes to avoid AV detection. This is just a fun program to
 * solve OSCE certification. If someone will find it useful, I will be glad of
 * it.
 *
 * ## [0.01] - 2019-02-01
 * ### Added
 * - plain XOR encoder
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

static char *word_to_string(char *buf) {
  char str[17];
  sprintf(str,"\\x%02x\\x%02x\\x%02x\\x%02x", (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2], (unsigned char)buf[3]);
  return strdup(str);
}

static char *word_to_asm(char *buf) {
  char str[17];
  sprintf(str,"0x%02x%02x%02x%02x", (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2], (unsigned char)buf[3]);
  return strdup(str);
}

static int print_word(char *buf) {
  return fprintf(stdout, "\\x%02x\\x%02x\\x%02x\\x%02x\n", 
      (unsigned char)buf[0],
      (unsigned char)buf[1],
      (unsigned char)buf[2],
      (unsigned char)buf[3]);
}

static int read_word(char *buf, FILE *fp){
  int ret;

  bzero((void *)buf, 4);
  if ((ret = fread(buf, 4, sizeof(char), fp)) < 0 ){
    perror("fread()");
    return -1;
  }

  return ret;
}

static int read_word_and_pad(char *buf, int count, FILE *fp){
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

static void xor_word(char *dest, char *src, char *key) {
  for (int z=0; z<5; z++) 
    dest[z] = src[z] ^ key[z];

  return ;

}


static int verbose_flag;

int main(int argc, char **argv) {
  char filename[256];
  char myname[256];
  FILE *fp;
  unsigned char buf[5];
  unsigned char enc[5];
  int offset=SEEK_SET, length=16, i, remaining, encoder;
  unsigned char key[5] = "\xde\xad\xbe\xef";

  unsigned char *original, *enc0ded;


  static struct option long_options[] =
        {
          {"verbose", no_argument,       &verbose_flag, 1},
          {"brief",   no_argument,       &verbose_flag, 0},
          {"encoder", required_argument, 0, 'e'},
          {"key",     required_argument, 0, 'k'},
          {"offset",  required_argument, 0, 'o'},
          {"length",  required_argument, 0, 'l'},
          {0, 0, 0, 0}
        };

  int c;
  while ((c = getopt_long(argc, argv, "e:k:o:l:", long_options, &optind)) != -1) {
    switch (c) {
      case 'o': 
        offset = atoi(optarg);
        break;

      case 'l': 
        length = atoi(optarg);
        break;

      case 'k':
        strncpy(key, optarg, 4);
        break;
      case 'e':
        encoder = atoi(optarg);
        break;
    }
  }

  strncpy(myname, basename(argv[0]), 255);

  if ( argv[optind] == NULL ) {
    fprintf(stderr, "%s: missing filename\n", myname);
    return -1;
  } else
    strncpy(filename, argv[optind], 255);

  fp = fopen(filename, "r");

  if (fp == NULL) {
    perror(filename);
    return -1;
  }

  printf("filename: %20s\n", filename);
  printf("encryption key: %5s\n", key); 
  printf("reading from byte: %d\n", offset);
  printf("bytes to be encrypted: %d\n", length);

  original  = calloc(length*4+1, sizeof(unsigned char));
  enc0ded   = calloc(length*4+1, sizeof(unsigned char));

  if (fseek(fp, offset, SEEK_SET) < 0) {
    perror("fseek()");
    return -1;
  }

  for (i =0; i<length / 4; i++) {
    read_word(buf, fp);
    xor_word(enc, buf, key);
    strcat(original, word_to_string(buf));
    strcat(enc0ded, word_to_string(enc));
  }
  remaining = length - (i * 4);
  if (remaining != 0) {
    read_word_and_pad(buf, remaining, fp);
    xor_word(enc, buf, key);
    strcat(original, word_to_string(buf));
    strcat(enc0ded, word_to_string(enc));
  }

  printf("Original: %50s (%ld)\n", original, strlen(original) / 4);
  printf("enc0ded : %50s (%ld)\n", enc0ded, strlen(enc0ded) /4);


  printf("Decoding asm stub\n------- 8< ---- 8< ---- 8< -------\n");
  printf("mov eax, startaddress\n");
  printf("mov ebx, %s\n", word_to_asm(key));
  printf("loop:\n");
  printf("xor dword ptr ds:[eax], ebx\n");
  printf("add eax, 4\n");
  printf("cmp eax, endaddress\n");
  printf("jle loop\n");
  printf("; asm instructions removed from program start\n");
  printf("; JMP program hijacked entrypoint\n");
  printf("------- 8< ---- 8< ---- 8< -------\n");
  fclose(fp);
}
