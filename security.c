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

void inspect_sexp_log(gcry_sexp_t object, FILE * stream){
    size_t len;
    const char *data;
    int all_items = gcry_sexp_length(object);
    fprintf(stream, "[INSPECT] list length -> %d\n", all_items);
    for (int i=0;i<all_items;i++){
        data = gcry_sexp_nth_data(object, i, &len);
        if(len)fprintf(stream, "[ITEM] i=%d | %.*s (len=%d)\n", i, (int)len, data, (int)len);
        else{
            fprintf(stream, "[LIST] another list at i=%d ---\n", i);
            inspect_sexp_log(gcry_sexp_nth(object, i), stream);
            fprintf(stream, "---end of inner list---\n");
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
void generate_rsa_keys(keyring * keys){
    gcry_sexp_t keyconfig, keypair;
    gcry_error_t api_err;
    keys->me_public_key = NULL;
    keys->me_private_key = NULL;
    
    // * * * * * * *  generate key pairs  * * * * * * * *
    // this process generate `publickey` and `privatekey` pair by using `keconfig` 
    // as configuration and `keypair` for api call (gnu library)
    // `keypair` and `keyconfig` will be erased from memory after this part

    // configuring key `keyconfig`
    api_err = gcry_sexp_new(&keyconfig, "(genkey (rsa (nbits 4:4096)))", 0, 1);
    if(api_err){
        printf("[KEYGEN][ERROR] cant make sexp object (err=%d)\n", gcry_err_code(api_err));
    }

    // api call generating `keypair`
    api_err = gcry_pk_genkey(&keypair, keyconfig);
    if(api_err){
        printf("[KEYGEN][ERROR] cant make key pair (err=%d)\n", gcry_err_code(api_err));
    }
    
    keys->me_public_key = gcry_sexp_find_token(keypair, "public-key", 0);
    keys->me_private_key = gcry_sexp_find_token(keypair, "private-key", 0);
    
    // free memory (end of this section)
    gcry_sexp_release(keypair);
    gcry_sexp_release(keyconfig);
}

void setup_other_key(keyring * keys, gcry_sexp_t rpk){
    keys->other_public_key = rpk;
}

/* Decrypt a message with provided size using RSA methode 
    the length of decrypted message will be stored at `msg_lenth` variable */
char * decrypt_msg(keyring keys, char * encrypted_msg, size_t enc_length, size_t * msg_length){
    int how_much_left, chunk_size, estimated_chunks, write_done, i;
    gcry_sexp_t recived_data, decrypted_data;
    gcry_error_t api_err;
    gcry_mpi_t mpi_encrypted;
    char * chunk, * whole;
    size_t dec_chunk_length, nscanned;

    write_done = 0;
    how_much_left = enc_length;
    whole = malloc(((enc_length+KEY_SIZE-1) / KEY_SIZE)*CHUNK_SIZE + 1);

    // chunk data into key size pieces
    while(how_much_left > 0){
        if(how_much_left > KEY_SIZE) chunk_size = KEY_SIZE;
        else                         chunk_size = how_much_left;

        // decryption and extract data
        api_err = gcry_mpi_scan(&mpi_encrypted, GCRYMPI_FMT_STD, &encrypted_msg[enc_length-how_much_left], chunk_size, &nscanned);
        api_err = gcry_sexp_build(&recived_data, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))", mpi_encrypted);
        api_err = gcry_pk_decrypt(&decrypted_data, recived_data, keys.me_private_key);
        chunk = (char *) gcry_sexp_nth_data(decrypted_data, 1, &dec_chunk_length);

        // write data chunks
        for(i=0;i<dec_chunk_length;i++) whole[write_done++] = chunk[i];
        how_much_left -= chunk_size;

        // free middle memory
        gcry_mpi_release(mpi_encrypted);
        gcry_sexp_release(recived_data);gcry_sexp_release(decrypted_data);
    }
    *msg_length = write_done;
    return whole;
}

/* Encrypt any binary or message with provided size `msg_length` using RSA
    a pointer to encrypted message will be returned on success and the length of
    result will be saved in `enc_length` variable */
char * encrypt_msg(keyring keys, char * msg, size_t msg_length, size_t * enc_length){
    gcry_sexp_t secret_data, encrypted_data, inside, insider;
    gcry_mpi_t mpi_encrypted;
    gcry_error_t api_err;
    size_t enc_chunk_length;
    char * whole, * chunk;
    int how_much_left, chunk_size, write_done, i;

    // initial values and reserve memory
    write_done = 0;
    how_much_left = msg_length;
    whole = malloc(((msg_length+CHUNK_SIZE-1) / CHUNK_SIZE)*KEY_SIZE + 1);

    // chunk the data into pieces a little smaller than KEY
    while(how_much_left > 0){
        if(how_much_left > CHUNK_SIZE) chunk_size = CHUNK_SIZE;
        else                           chunk_size = how_much_left;

        // encryption
        api_err = gcry_sexp_build(&secret_data, NULL, "(data (flags pkcs1) (value %b))", chunk_size, &msg[msg_length-how_much_left]);
        api_err = gcry_pk_encrypt(&encrypted_data, secret_data, keys.other_public_key);

        // extract binary
        inside  = gcry_sexp_nth(encrypted_data, 1);
        insider = gcry_sexp_nth(inside, 1);gcry_sexp_release(inside);
        mpi_encrypted = gcry_sexp_nth_mpi(insider, 1, GCRYMPI_FMT_STD);gcry_sexp_release(insider);
        api_err = gcry_mpi_aprint(GCRYMPI_FMT_STD, (unsigned char **) &chunk, &enc_chunk_length, mpi_encrypted);

        // write fixed sized chunks to reserved memory
        for(i=0;KEY_SIZE-enc_chunk_length-i!=0;i++) whole[write_done++]='\0';
        for(i=0;i<enc_chunk_length;i++) whole[write_done++] = chunk[i];
        how_much_left -= chunk_size;

        //free middle memories
        gcry_mpi_release(mpi_encrypted);
        gcry_sexp_release(secret_data); gcry_sexp_release(encrypted_data);
        free(chunk);
    }

    *enc_length = write_done;
    return whole;
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
#ifdef TEST
//test main
int main(int argc, char ** argv){
    int datasize = atoi(argv[1]);
    char * enc, * dec;
    keyring k;
    size_t r, r2;
    int errcount= 0;
    printf("[TEST] testing phase\n");
    FILE * f = fopen("cv.pdf", "rb");
    char * data = malloc(datasize);
    fread(data, sizeof(char), datasize, f);
    generate_rsa_keys(&k); k.other_public_key=k.me_public_key;

    enc = encrypt_msg(k, data, datasize, &r);
    printf("[TEST] enc size -> %ld\n", r);

    dec = decrypt_msg(k, enc, r, &r2);
    printf("[TEST] dec size -> %ld\n", r2);

    FILE * errfile = fopen("error.log", "w");
    printf("%c%c%c%c\t%c%c%c%c\n", data[0], data[1], data[2], data[3], dec[0], dec[1], dec[2], dec[3]);
    for(int i=0;i<datasize;i++) if(dec[i] != data[i]) fprintf(errfile, "err=%d|%c!=%c|i=%d|%s|%s\n", errcount++, data[i], dec[i], i, data[i]==dec[i+1]?"true":"false", dec[i]=='\0'?"zero":"not");
    printf("Error count = %d\n", errcount);
}
#else
//module main
int main(){
    printf("[SECURITY][MAIN] test security module (gcrypt version=%s)\n", gcry_check_version(NULL));

    // ---> define variables
    char buffer[1000], *cipher_buffer;
    char * chunk;
    const char * sample_message = "[sample message to test encryption]";
    const char * sample_passphrase = "password";
    gcry_sexp_t publickey, privatekey, keyconfig, keypair, secret_data, encrypted_data, decrypted_data, recived_data, inside, insider, unlocked_key;
    gcry_mpi_t mpi_message, mpi_recived, mpi_sent;
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

    generate_rsa_keys(&another);
    printf("[MODULE] another key ring is generated\n");

    #ifdef INSPECT
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
    // api_err = gcry_mpi_scan(&mpi_message, GCRYMPI_FMT_USG, sample_message, strlen(sample_message), NULL);
    // if(api_err){printf("[ERROR] cant make mpi from message (err=%u)\n", api_err);return 0;}

    api_err = gcry_sexp_build(&secret_data, NULL, "(data (flags pkcs1) (value %b))", strlen(sample_message), sample_message);
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
    api_err = gcry_mpi_aprint(GCRYMPI_FMT_STD, (unsigned char **) &chunk, &length, mpi_recived);
    printf("[MODULE] size after encryption -> %ld\n", length);
    
    api_err = gcry_mpi_scan(&mpi_sent, GCRYMPI_FMT_STD, chunk, length, NULL);
    api_err = gcry_sexp_build(&recived_data, NULL, "(enc-val (flags pkcs1) (rsa (a %m)))", mpi_sent);
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
#endif