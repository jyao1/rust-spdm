#ifndef _STRING_H_
#define _STRING_H_
#include <stddef.h>
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);

char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);

char *strstr(const char *, const char *);
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *vl, const void *vr, size_t n);
void *memmove(void *dest, const void *src, size_t n);
size_t strlen(const char *);
char *strchr(const char *, int);
#endif
