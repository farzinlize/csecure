#ifndef _FUZZY_UTILITY_H
#define _FUZZY_UTILITY_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define INTEGER_BYTES 4

int read_integer(FILE * data);
char * read_string(FILE * data, int size);
char * read_str(FILE * data, int size);
void logit(const char * message, const char * logfile);
void put_integer(uint8_t * here, int n);
void deploy_integer(FILE * stream, int n);
int get_integer(uint8_t * here);
// char * concat_malloc(char * a, char * b);

#endif