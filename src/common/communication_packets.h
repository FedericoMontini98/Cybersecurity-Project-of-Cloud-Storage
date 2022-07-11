#include <openssl/evp.h>
#include <iostream>
#include <stdlib.h>

using namespace std;

/***
 * THIS FILE CONTAINS THE STRUCTURE OF THE PACKETS WITH THEIR CODE
 * 
 ***/

# define BOOTSTRAP_LOGIN            1
# define BOOTSTRAP_UPLOAD           5
# define BOOTSTRAP_DOWNLOAD         10
# define FILE_UPLOAD                6


// sent in clear
struct bootstrap_login_pkt {
    int code;
    string username;
    EVP_PKEY* sts_key_param;
    EVP_PKEY* hmac_key_param;
};

struct bootstrap_upload {
    uint8_t code;
    string filename;
    bool response;      //True: upload allowed  False: upload not allowed
    uint32_t counter;
    uintmax_t size;
    
}

struct file_upload {
    uint8_t code;
    unsigned char* msg;
    bool response;      //True: upload allowed  False: upload not allowed
    uint32_t counter;
    
}

