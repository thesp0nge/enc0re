#ifndef ENC0RE_UTILS
#define ENC0RE_UTILS
char *word_to_string(char *buf);
char *word_to_asm(char *buf);
int print_word(char *buf);
int read_word(char *buf, FILE *fp);
int read_word_and_pad(char *buf, int count, FILE *fp);
void xor_word(char *dest, char *src, char *key);
#endif
