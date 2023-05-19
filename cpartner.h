#ifndef _CPARTNER_H
#define _CPARTNER_H

#include"security.h"
#include"utility.h"
#include"global.h"
#include<stdio.h>
#include <stdlib.h>

#define OK 'O'
#define REDO 'R'
#define ERR 'E'

typedef struct bundle{
    int size;
    uint8_t * data;
} bundle;

#endif