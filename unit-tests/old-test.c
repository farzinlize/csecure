#include"../includes/security.h"

int main(){
    printf("[SECURITY][MAIN] test security module (gcrypt version=%s)\n",
        gcry_check_version(NULL));

    // ---> define variables
    char buffer[1000], *cipher_buffer;
    char * chunk;
    char * sample_message = "[sample message to test encryption]";
    char * sample_passphrase = "password";
    gcry_sexp_t publickey, privatekey, keyconfig, keypair, secret_data, 
        encrypted_data, decrypted_data, received_data, inside, insider,
        unlocked_key;
    gcry_mpi_t mpi_message, mpi_received, mpi_sent;
    gcry_cipher_hd_t cipher;
    gcry_error_t api_err;
    int err, l;
    keyring another;
    size_t length;

    #ifdef TEST
    unsigned char * hash_key;
    gcry_md_hd_t hash_machine;
    gcry_sexp_t testy;
    keyring testkeys;
    size_t testsize, testsize2;
    char *secret, *revealed;
    #endif

    // * * * * * * *  generate key pairs  * * * * * * * *
    // this process generate `publickey` and `privatekey` pair by using `keyconfig` 
    // as configuration and `keypair` for api call (gnu library)
    // `keypair` and `keyconfig` will be erased from memory after this part

    // configuring key `keyconfig`
    err = gcry_sexp_new(&keyconfig, "(genkey (rsa (nbits 4:4096)))", 0, 1);
    if(err){printf("[ERROR] cant make sexp object (err=%d)\n", err);return 1;}
    #ifdef CS_INSPECT
    inspect_sexp(keyconfig);
    #endif

    // api call generating `keypair`
    err = gcry_pk_genkey(&keypair, keyconfig);
    if(err){printf("[ERROR] cant make key pair (err=%d)\n", err);return 1;}

    publickey  = gcry_sexp_find_token(keypair, "public-key", 0);
    privatekey = gcry_sexp_find_token(keypair, "private-key", 0);
    printf("[MODULE] key pairs are generated successfully\n");

    #ifdef CS_INSPECT
    printf("[NAME] publickey -> \n");inspect_sexp(publickey);
    printf("[NAME] privatekey -> \n");inspect_sexp(privatekey);
    #endif

    generate_rsa_keys(&another);
    printf("[MODULE] another key ring is generated\n");

    #ifdef CS_INSPECT
    printf("[NAME] another publickey -> \n");inspect_sexp(another.me_public_key);
    printf("[NAME] another privatekey -> \n");inspect_sexp(another.me_private_key);
    #endif

    #ifdef TEST
    testkeys.me_private_key = privatekey;
    testkeys.me_public_key = publickey;
    testkeys.other_public_key = publickey;
    secret = encrypt_msg(testkeys, "salam", 5, &testsize);
    printf("[test] message=salam | encrypted in next line ->\n");
    // for(int i=0;i<testsize;i++) printf("%c", secret[i]);
    printf("\n[test] len=(%ld)\n", testsize);
    revealed = decrypt_msg(testkeys, secret, testsize, &testsize2);
    printf("[test] decrypted message next line ->\n");
    for(int i=0;i<testsize2;i++) printf("%c", revealed[i]);
    printf("\n[test] len=(%ld)\n", testsize2);
    // write_sexp_file("test.sexp", privatekey);
    // printf("[TEST] READ/WRITE testy -> \n");
    // testy = read_sexp_file("test.sexp");
    // dump_sexp2file("test.sexp", privatekey);
    // inspect_sexp(testy);
    #endif

    // free memory (end of this section)
    gcry_sexp_release(keypair);
    gcry_sexp_release(keyconfig);

    // * * * * * * *  encrypt key for communication  * * * * * * * *
    cipher_buffer = lock_object(publickey, sample_passphrase, strlen(sample_passphrase), &length);
    unlocked_key = unlock_object(cipher_buffer, length, sample_passphrase, strlen(sample_passphrase));
    printf("[MODULE] public key is locked and then unlocked with sample passphrase\n");

    #ifdef CS_INSPECT
    printf("[NAME] publickey (after lock and unlock) -> \n");inspect_sexp(unlocked_key);
    #endif

    #ifdef TEST
    // hash the passphrase to generate fixed size key 
    api_err = gcry_md_open(&hash_machine, GCRY_MD_SHA256, 0);
    gcry_md_write(hash_machine, sample_passphrase, strlen(sample_passphrase));
    hash_key = gcry_md_read(hash_machine, GCRY_MD_SHA256);
    printf("[MODULE] hash key is generated from sample pasphrase ->\n", hash_key);
    for(int i=0;i<32;i++){
        printf("%x", hash_key[i]);
    }printf(" (32-bytes-> %s)\n", hash_key[32]==0?"yes":"no");
    #endif

    // * * * * * * *  encrypt a message  * * * * * * * *
    // api_err = gcry_mpi_scan(&mpi_message, GCRYMPI_FMT_USG, sample_message, strlen(sample_message), NULL);
    // if(api_err){printf("[ERROR] cant make mpi from message (err=%u)\n", api_err);return 0;}

    api_err = gcry_sexp_build(&secret_data,
        NULL, 
        "(data (flags pkcs1) (value %b))", 
        strlen(sample_message), sample_message
    );
    if(api_err){printf("[ERROR] cant build sexp structure (err=%u)\n", api_err);return 1;}

    api_err = gcry_pk_encrypt(&encrypted_data, secret_data, publickey);
    if(api_err){printf("[ERROR] cant encrypt data.sexp (err=%u)\n", api_err);return 1;}
    printf("[MODULE] a sample message is encrypted (use inspect mode to see more detail)\n");

    #ifdef CS_INSPECT
    printf("[NAME] secret_data -> \n");inspect_sexp(secret_data);
    printf("[NAME] encrypted_data -> \n");inspect_sexp(encrypted_data);
    #endif

    // * * * * * * *  decrypt that message  * * * * * * * *

    // recived or extract mpi data from structure
    inside  = gcry_sexp_nth(encrypted_data, 1);
    insider = gcry_sexp_nth(inside, 1);gcry_sexp_release(inside);
    mpi_received = gcry_sexp_nth_mpi(insider, 1, GCRYMPI_FMT_STD);gcry_sexp_release(insider);
    api_err = gcry_mpi_aprint(GCRYMPI_FMT_STD, (unsigned char **) &chunk, &length, mpi_received);
    printf("[MODULE] size after encryption -> %ld\n", length);
    
    api_err = gcry_mpi_scan(&mpi_sent, GCRYMPI_FMT_STD, chunk, length, NULL);
    api_err = gcry_sexp_build(&received_data, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))", mpi_sent);
    if(api_err){
        printf("[ERROR] cant make sexp from received data (err_code=%u)\n", gcry_err_code(api_err));
        return 1;
    }
    api_err = gcry_pk_decrypt(&decrypted_data, received_data, privatekey);
    if(api_err){printf("[ERROR] cant decrypt data.sexp (err=%u)\n", api_err);return 1;}
    printf("[MODULE] encrypted message is decrypted successfully\n");

    #ifdef CS_INSPECT
    printf("[NAME] decrypted_data -> \n");inspect_sexp(decrypted_data);
    #endif

    return 0;
}