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

int main(){
    keyring keys;
    size_t enc_count, dec_count;
    char * simple = random_bytes(LIBCS_SINGLE_SIZE);

    generate_rsa_keys(&keys);
    setup_other_key(&keys, keys.me_public_key);
    printf("keys are generated\n");

    char * enc = encrypt_msg(keys, simple, LIBCS_SINGLE_SIZE, &enc_count);
    printf("encrypted --- enc_length=%ld\n", enc_count);
    char * dec = decrypt_msg(keys, enc, enc_count, &dec_count);
    printf("decrypted\ndec_length=%ld, approved->%s\n",
        dec_count, memcmp(simple, dec, LIBCS_SINGLE_SIZE)?"no":"yes"
    );
}