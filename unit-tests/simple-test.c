#include"../includes/security.h"

#define SINGLE_SIZE 102400

char * random_bytes(size_t length){
    char * r = (char *)malloc(length);
    for(int i=0;i<length;i++)
        r[i] = (char) rand()%256;
    return r;
}

int main(){
    keyring keys;
    size_t enc_count, dec_count;
    char * simple = random_bytes(SINGLE_SIZE);

    generate_rsa_keys(&keys);
    setup_other_key(&keys, keys.me_public_key);
    printf("keys are generated\n");

    char * enc = encrypt_msg(keys, simple, SINGLE_SIZE, &enc_count);
    printf("encrypted --- enc_length=%ld\n", enc_count);
    char * dec = decrypt_msg(keys, enc, enc_count, &dec_count);
    printf("decrypted\ndec_length=%ld, approved->%s\n",
        dec_count, memcmp(simple, dec, SINGLE_SIZE)?"no":"yes"
    );
}