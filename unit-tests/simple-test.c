#include"../includes/security.h"

#ifndef CMAKE_MAKE
#define LIBCS_SINGLE_SIZE 102400
#endif

char * random_bytes(size_t length){
    char * r = (char *)malloc(length);
    for(int i=0;i<length;i++)
        r[i] = (char) rand()%256;
    return r;
}

void random_bytes_nomem(char * where, size_t length){
    for(int i=0;i<length;i++)
        where[i] = (char) rand()%256;
}

int main(){
    keyring keys;
    size_t enc_count, dec_count, en2_count;
    char * simple = random_bytes(LIBCS_SINGLE_SIZE);
    char stack[LIBCS_SINGLE_SIZE];

    printf("stack and simple compare:\n- stack\n");
    fwrite(stack, 1, LIBCS_SINGLE_SIZE, stdout);
    printf("\n- simple\n");
    fwrite(simple, 1, LIBCS_SINGLE_SIZE, stdout);
    if(memcmp(simple, stack, LIBCS_SINGLE_SIZE)) printf("\nequal approved\n");

    generate_rsa_keys(&keys);
    setup_other_key(&keys, keys.me_public_key);
    printf("keys are generated\n");

    char * enc = encrypt_msg(keys, simple, LIBCS_SINGLE_SIZE, &enc_count);
    printf("encrypted --- enc_length=%ld\n", enc_count);
    char * en2 = encrypt_msg(keys, stack,  LIBCS_SINGLE_SIZE, &en2_count);
    printf("stacked ok --- en2_length=%ld\n", en2_count);
    
    char * dec = decrypt_msg(keys, enc, enc_count, &dec_count);
    printf("decrypted\ndec_length=%ld, approved->%s\n",
        dec_count, memcmp(simple, dec, LIBCS_SINGLE_SIZE)?"no":"yes"
    );
}