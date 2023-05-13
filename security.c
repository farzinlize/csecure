#include"security.h"

void write_sexp_file(const char * filename, gcry_sexp_t object){
    size_t length = gcry_sexp_sprint(object, 0, NULL, 0);
    char * buffer = (char *) malloc(length);
    size_t offset = gcry_sexp_sprint(object, 0, buffer, length);
    FILE * f = fopen(filename, "wb");
    fwrite(buffer, sizeof(char), length, f);
    fclose(f);
    free(buffer);
}

gcry_sexp_t read_sexp_file(const char * filename){
    gcry_sexp_t result;
    gcry_error_t err;
    char * buffer;
    FILE * f = fopen(filename, "rb");

    fseek(f, 0, SEEK_END);
    int length = ftell(f);
    fseek(f, 0, 0);
    buffer = (char *) malloc(length * sizeof(char));
    fread(buffer, sizeof(char), length, f);fclose(f);
    err = gcry_sexp_new(&result, buffer, length, 1);
    if(err) printf("[FILE] cant read sexp from file (code=%d)\n", gcry_err_code(err));
    return result;
}

gcry_sexp_t read_sexp_memory(char * buffer, int length){
    gcry_sexp_t result;
    gcry_error_t err = gcry_sexp_new(&result, buffer, length, 1);
    if(err) printf("[MEM] cant read sexp in memory (code=%d)\n", gcry_err_code(err));
    return result;
}

#ifdef INSPECT
void inspect_sexp(gcry_sexp_t object){
    size_t len;
    const char *data;
    int all_items = gcry_sexp_length(object);
    printf("[INSPECT] list length -> %d\n", all_items);
    for (int i=0;i<all_items;i++){
        data = gcry_sexp_nth_data(object, i, &len);
        if(len)printf("[ITEM] i=%d | %.*s (len=%d)\n", i, (int)len, data, (int)len);
        else{
            printf("[LIST] another list at i=%d ---\n", i);
            inspect_sexp(gcry_sexp_nth(object, i));
            printf("---end of inner list---\n");
        }
    }
}
#endif

void free_keyring(keyring * thering){
    gcry_sexp_release(thering->me_public_key);
    gcry_sexp_release(thering->me_private_key);
    gcry_sexp_release(thering->other_public_key);
}

/* Create new `keyring` with personal asymetric keys 
    in case of error a brief message will be printed and function will return
    unfinished `keyring` structure with NULL attributes */
keyring generate_rsa_keys(){
    gcry_sexp_t keyconfig, keypair;
    gcry_error_t api_err;
    keyring result = {NULL, NULL, NULL};
    
    // * * * * * * *  generate key pairs  * * * * * * * *
    // this process generate `publickey` and `privatekey` pair by using `keconfig` 
    // as configuration and `keypair` for api call (gnu library)
    // `keypair` and `keyconfig` will be erased from memory after this part

    // configuring key `keyconfig`
    api_err = gcry_sexp_new(&keyconfig, "(genkey (rsa (nbits 4:4096)))", 0, 1);
    if(api_err){
        printf("[KEYGEN][ERROR] cant make sexp object (err=%d)\n", gcry_err_code(api_err));
        return result;
    }

    // api call generating `keypair`
    api_err = gcry_pk_genkey(&keypair, keyconfig);
    if(api_err){
        printf("[KEYGEN][ERROR] cant make key pair (err=%d)\n", gcry_err_code(api_err));
        return result;
    }
    
    // free memory (end of this section)
    gcry_sexp_release(keypair);
    gcry_sexp_release(keyconfig);

    result.me_public_key = gcry_sexp_find_token(keypair, "public-key", 0);
    result.me_private_key = gcry_sexp_find_token(keypair, "private-key", 0);
    return result;
}

void setup_other_key(keyring * keys, gcry_sexp_t rpk){
    keys->other_public_key = rpk;
}

/* Decrypt a message with provided size using RSA methode 
    the length of decrypted message will be stored at `msg_lenth` variable */
char * decrypt_msg(keyring keys, char * encrypted_msg, size_t enc_length, size_t * msg_length){
    gcry_sexp_t recived_data, decrypted_data;
    gcry_error_t api_err;
    gcry_mpi_t mpi_encrypted;
    char * result;

    api_err = gcry_mpi_scan(&mpi_encrypted, GCRYMPI_FMT_STD, encrypted_msg, enc_length, NULL);

    api_err = gcry_sexp_build(&recived_data, NULL, "(enc-val (flags) (rsa (a %m)))", mpi_encrypted);
    if(api_err){
        printf("[ERROR] cant make sexp from recived data (err_code=%u)\n", gcry_err_code(api_err));
        return NULL;
    }
    api_err = gcry_pk_decrypt(&decrypted_data, recived_data, keys.me_private_key);
    if(api_err){printf("[ERROR] cant decrypt data.sexp (err=%u)\n", api_err);return 0;}
    result = gcry_sexp_nth_data(decrypted_data, 1, msg_length);
    return result;
}

/* Encrypt any binary or message with provided size `msg_length` using RSA
    a pointer to encrypted message will be returned on success and the length of
    result will be saved in `enc_length` variable */
char * encrypt_msg(keyring keys, char * msg, size_t msg_length, size_t * enc_length){
    gcry_sexp_t secret_data, encrypted_data, inside, insider;
    gcry_mpi_t mpi_message, mpi_encrypted;
    gcry_error_t api_err;
    char * result;

    api_err = gcry_mpi_scan(&mpi_message, GCRYMPI_FMT_STD, (const char *) msg, msg_length, NULL);
    if(api_err){printf("[ERROR] cant make mpi from message (err=%u)\n", api_err);return 0;}

    api_err = gcry_sexp_build(&secret_data, NULL, "(data (flags raw) (value %m))", mpi_message);
    if(api_err){printf("[ERROR] cant build sexp structure (err=%u)\n", api_err);return 0;}

    api_err = gcry_pk_encrypt(&encrypted_data, secret_data, keys.other_public_key);
    if(api_err){printf("[ERROR] cant encrypt data.sexp (err=%u)\n", api_err);return 0;}

    inside  = gcry_sexp_nth(encrypted_data, 1);
    insider = gcry_sexp_nth(inside, 1);gcry_sexp_release(inside);
    mpi_encrypted = gcry_sexp_nth_mpi(insider, 1, GCRYMPI_FMT_STD);gcry_sexp_release(insider);
    api_err = gcry_mpi_aprint(GCRYMPI_FMT_STD, &result, enc_length, mpi_encrypted);
    if(api_err){printf("[ERROR] cant encrypt data.sexp (err=%u)\n", api_err);return 0;}
    return result;
}

/* Encrypt a key or `gcry_sexp_t` object using symetric cipher using a password
    the shared key is a passphrase shared between peers with length of `pp_length` 
    length of the encrypted text will be placed at `length` variable
    WARNING -> `free(buffer)` you must call `free` on output of this function 
                to prevent memory leaks */
char * lock_object(gcry_sexp_t the_object, char * passphrase, size_t pp_length, size_t * length){
    gcry_error_t api_err;
    gcry_cipher_hd_t cipher;
    gcry_md_hd_t hash_machine;
    size_t data_len, offset, pad_len;
    unsigned char * hash_key;
    char * data_buffer;

    // hash the passphrase to generate fixed size key 
    api_err = gcry_md_open(&hash_machine, GCRY_MD_SHA256, 0);
    gcry_md_write(hash_machine, passphrase, pp_length);
    hash_key = gcry_md_read(hash_machine, GCRY_MD_SHA256);

    // encode key into binary and padding
    data_len = gcry_sexp_sprint(the_object, 0, NULL, 0);
    pad_len = 16 - (data_len%16);
    *length = data_len + pad_len;
    data_buffer = malloc(data_len + pad_len);
    offset = gcry_sexp_sprint(the_object, 0, data_buffer, data_len);
    for(int i=offset+1;i<data_len+pad_len;i++){data_buffer[i] = 0x0;}
        
    // enryption part
    api_err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
    api_err = gcry_cipher_setkey(cipher, hash_key, 32);
    api_err = gcry_cipher_encrypt(cipher, data_buffer, data_len+pad_len, NULL, 0);
    if(api_err)printf("[ERROR] can not encrypt message (code=%d)\n", gcry_err_code(api_err));

    // free memory 
    gcry_cipher_close(cipher);
    gcry_md_close(hash_machine);

    return data_buffer;
}

/* Decrypt a key or `gcry_sexp_t` object in `buffer` with symetric cipher using shared key
    the shared key is a passphrase shared between peers with length of `pp_length`
    buffer size is `length` */
gcry_sexp_t unlock_object(char * buffer, size_t length, char * passphrase, size_t pp_length){
    gcry_error_t api_err;
    gcry_cipher_hd_t cipher;
    gcry_md_hd_t hash_machine;
    unsigned char * hash_key;
    int i = length-1;

    // hash the passphrase to generate fixed size key 
    api_err = gcry_md_open(&hash_machine, GCRY_MD_SHA256, 0);
    gcry_md_write(hash_machine, passphrase, pp_length);
    hash_key = gcry_md_read(hash_machine, GCRY_MD_SHA256);

    // decyption
    api_err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
    api_err = gcry_cipher_setkey(cipher, hash_key, 32);
    api_err = gcry_cipher_decrypt(cipher, buffer, length, NULL, 0);

    // decode key data into struct
    return read_sexp_memory(buffer, length);
}

#ifdef SECURITY_MAIN
int main(){
    printf("[SECURITY][MAIN] test security module (gcrypt version=%s)\n", gcry_check_version(NULL));

    // ---> define variables
    char buffer[1000], *cipher_buffer;
    const char * sample_message = "[sample message to test encryption]";
    const char * sample_passphrase = "password";
    gcry_sexp_t publickey, privatekey, keyconfig, keypair, secret_data, encrypted_data, decrypted_data, recived_data, inside, insider, unlocked_key;
    gcry_mpi_t mpi_message, mpi_recived;
    gcry_cipher_hd_t cipher;
    gcry_error_t api_err;
    int err, l;
    size_t length;

    #ifdef TEST
    unsigned char * hash_key;
    gcry_md_hd_t hash_machine;
    gcry_sexp_t testy;
    keyring testkeys;
    size_t testsize, testsize2;
    #endif

    // * * * * * * *  generate key pairs  * * * * * * * *
    // this process generate `publickey` and `privatekey` pair by using `keconfig` 
    // as configuration and `keypair` for api call (gnu library)
    // `keypair` and `keyconfig` will be erased from memory after this part

    // configuring key `keyconfig`
    err = gcry_sexp_new(&keyconfig, "(genkey (rsa (nbits 4:4096)))", 0, 1);
    if(err){printf("[ERROR] cant make sexp object (err=%d)\n", err);return 0;}
    #ifdef INSPECT
    inspect_sexp(keyconfig);
    #endif

    // api call generating `keypair`
    err = gcry_pk_genkey(&keypair, keyconfig);
    if(err){printf("[ERROR] cant make key pair (err=%d)\n", err);return 0;}

    publickey  = gcry_sexp_find_token(keypair, "public-key", 0);
    privatekey = gcry_sexp_find_token(keypair, "private-key", 0);
    printf("[MODULE] key pairs are generated successfully\n");

    #ifdef INSPECT
    printf("[NAME] publickey -> \n");inspect_sexp(publickey);
    printf("[NAME] privatekey -> \n");inspect_sexp(privatekey);
    #endif

    #ifdef TEST
    testkeys.me_private_key = privatekey;
    testkeys.me_public_key = publickey;
    testkeys.other_public_key = publickey;
    char * secret = encrypt_msg("hi", testkeys, &testsize);
    printf("[test] message=hi | encrypted in next line ->\n%s\n", secret);
    printf("[test] len=(%ld)\n", testsize);
    printf("[test] decrypted message next line ->\n%s\n", decrypt_msg(testkeys, secret, testsize, &testsize2));
    printf("[test] len=(%ld)\n", testsize2);
    write_sexp_file("test.sexp", privatekey);
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

    #ifdef INSPECT
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
    api_err = gcry_mpi_scan(&mpi_message, GCRYMPI_FMT_USG, sample_message, strlen(sample_message), NULL);
    if(api_err){printf("[ERROR] cant make mpi from message (err=%u)\n", api_err);return 0;}

    api_err = gcry_sexp_build(&secret_data, NULL, "(data (flags raw) (value %m))", mpi_message);
    if(api_err){printf("[ERROR] cant build sexp structure (err=%u)\n", api_err);return 0;}

    api_err = gcry_pk_encrypt(&encrypted_data, secret_data, publickey);
    if(api_err){printf("[ERROR] cant encrypt data.sexp (err=%u)\n", api_err);return 0;}
    printf("[MODULE] a sample message is encrypted (use inspect mode to see more detail)\n");

    #ifdef INSPECT
    printf("[NAME] secret_data -> \n");inspect_sexp(secret_data);
    printf("[NAME] encrypted_data -> \n");inspect_sexp(encrypted_data);
    #endif

    // * * * * * * *  decrypt that message  * * * * * * * *

    // recived or extract mpi data from structure
    inside  = gcry_sexp_nth(encrypted_data, 1);
    insider = gcry_sexp_nth(inside, 1);gcry_sexp_release(inside);
    mpi_recived = gcry_sexp_nth_mpi(insider, 1, GCRYMPI_FMT_STD);gcry_sexp_release(insider);
    
    api_err = gcry_sexp_build(&recived_data, NULL, "(enc-val (flags) (rsa (a %m)))", mpi_recived);
    if(api_err){
        printf("[ERROR] cant make sexp from recived data (err_code=%u)\n", gcry_err_code(api_err));
        return 0;
    }
    api_err = gcry_pk_decrypt(&decrypted_data, recived_data, privatekey);
    if(api_err){printf("[ERROR] cant decrypt data.sexp (err=%u)\n", api_err);return 0;}
    printf("[MODULE] encrypted message is decrypted successflly\n");

    #ifdef INSPECT
    printf("[NAME] decrypted_data -> \n");inspect_sexp(decrypted_data);
    #endif

    return 0;
}
#endif