#include"utility.h"

int read_integer(FILE * data){
    unsigned char byte = 0;
    int result;
    for(int i=INTEGER_BYTES-1;i>=0;i--){
        byte = fgetc(data);
        result = result + byte << i*8;
    }
    return result;
}


char * read_string(FILE * data, int size){
    char * result = (char *) calloc(size+1, sizeof(char));
    fread(result, sizeof(char), size, data);
    return result;
}


/* just like read_string but using fgetc instead of fread */
char * read_str(FILE * data, int size){
    char * result = (char *) malloc(size+1);
    for(int i=0;i<size;i++){
        result[i] = fgetc(data);
    }
    result[size] = '\0';
    return result;
}

void logit(const char * message, const char * logfile){
    time_t date = time(NULL);
    FILE * log = fopen(logfile, "a");
    fprintf(log, "[%.19s]%s\n", ctime(&date), message);
    fclose(log);
}

void put_integer(uint8_t * here, int n){
    here[0] = (n >> 24) & 0xFF;
    here[1] = (n >> 16) & 0xFF;
    here[2] = (n >> 8 ) & 0xFF;
    here[3] =  n        & 0xFF;
}

int get_integer(uint8_t * here){
    return (here[3]) + (here[2] << 8) + (here[1] << 16) + (here[0] << 24);
}

char * concat_malloc(char * a, char * b){
    int size_a = strlen(a), size_b = strlen(b);
    int size = size_a + size_b + 1;
    char * result = (char *) malloc(sizeof(char)*size);

    int i = 0, ax = 0, bx = 0;
    while(ax<size_a) result[i++] = a[ax++];
    while(bx<size_b) result[i++] = b[bx++];

    result[i] = '\0';
    return result;
}

#ifdef UTILITY_MAIN
int main(int argc, char * argv[]){
    char * a = concat_malloc(argv[1], argv[2]);
    printf("result is in here -> (%s) len=%ld\n", a, strlen(a));
    int b;
    if(((b=atoi(argv[3])) % 5) == 0) printf("a is %d and its devidable by 5\n", b);
    else printf("a is %d but its not devidable by 5 oh no\n", b);
}
#endif