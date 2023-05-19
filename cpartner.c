#include"cpartner.h"

bool initialized = false;
bool otherkey = false;
keyring mine;

void keygen_API(char * passphrase){
    if(!initialized) {putchar(OK);initialized=true;} else {putchar(REDO); free_keyring(&mine);}
    generate_rsa_keys(&mine);
    size_t length;
    char * locked_pkey = lock_object(mine.me_public_key, passphrase, strlen(passphrase), &length);
    deploy_integer(stdout, (int)length);
    fwrite(locked_pkey, length, sizeof(char), stdout);
}

void setkey_API(char * passphrase, bundle data){
    if   (!otherkey) {putchar(OK);otherkey=true;} 
    else {putchar(REDO);gcry_sexp_release(mine.other_public_key);}
    setup_other_key(&mine, unlock_object(data.data, data.size, passphrase, strlen(passphrase)));
}

void encrypt_API(bundle data){
    if(!initialized) {putchar(ERR); return;}
    putchar(OK);
    size_t length;
    char * result = encrypt_msg(mine, data.data, data.size, &length);
    deploy_integer(stdout, (int)length);
    fwrite(result, sizeof(char), length, stdout);
}

void decrypt_API(bundle data){
    if(!otherkey) {putchar(ERR); return;}
    putchar(OK);
    size_t length;
    char * result = decrypt_msg(mine, data.data, data.size, &length);
    deploy_integer(stdout, (int)length);
    fwrite(result, sizeof(char), length, stdout);
}

char * get_string(){
    int length = read_integer(stdin);
    return read_string(stdin, length);
}


bundle get_data(){
    bundle result;
    result.size = read_integer(stdin);
    result.data = malloc(result.size);
    fread(result.data, sizeof(uint8_t), result.size, stdin);
    return result;
}


int main(int argc, char ** argv){
    #ifdef TEST
    if(argc!=2) {putchar(ERR);return -1;}
    FILE * l = fopen(argv[1], "w");
    #endif

    char command = getchar();
    while(command != 'X'){
        switch (command){
            case 'G':keygen_API(get_string());break;
            case 'S':setkey_API(get_string(), get_data());break;
            case 'C':encrypt_API(get_data());break;
            case 'D':decrypt_API(get_data());break;
            default:putchar(ERR);return -1;
        }
        fflush(stdout);

        #ifdef TEST
        fprintf(l, "COMMAND - %c is processed and my keyring inspection is here:\n", command);
        fprintf(l, "my public key ->\n");
        inspect_sexp_log(mine.me_public_key, l);
        fprintf(l, "my private key ->\n");
        inspect_sexp_log(mine.me_private_key, l);
        fprintf(l, "other public key ->\n");
        inspect_sexp_log(mine.other_public_key, l);
        #endif

        command = getchar();
    }
    return 0;
}
