#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


typedef unsigned char Byte;

char *str_sub (const char *, int, int);

void strToBytes(const char *str, Byte *bytes_array);
void bytesToStr(Byte *bytes,int bytes_s,char *str);
int isHexInput(const char *input);
void asciiToHex(const char *s,char* s_hex);
void hexToAscii(const char *s_hex,char* s);

#endif // UTILS_H_INCLUDED
