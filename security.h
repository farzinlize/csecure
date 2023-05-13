#ifndef _SECURITY_H
#define _SECURITY_H

#include<gcrypt.h>
#include<stdio.h>

typedef struct keyring{
    gcry_sexp_t me_public_key;
    gcry_sexp_t me_private_key;
    gcry_sexp_t other_public_key;
} keyring;

keyring generate_rsa_keys();
void setup_other_key(keyring * keys, gcry_sexp_t rpk);
char * encrypt_msg(keyring keys, char * msg, size_t msg_length, size_t * enc_length);
char * decrypt_msg(keyring keys, char * encrypted_msg, size_t enc_length, size_t * msg_length);
char * lock_object(gcry_sexp_t the_object, char * passphrase, size_t pp_length, size_t * length);
gcry_sexp_t unlock_object(char * buffer, size_t length, char * passphrase, size_t pp_length);

#endif