#include <openssl/evp.h>
#include <iostream>
#include <stdlib.h>

using namespace std;

/***
 * THIS FILE CONTAINS THE STRUCTURE OF THE PACKETS WITH THEIR CODE
 * 
 ***/

# define BOOTSTRAP_LOGIN 1
// sent in clear
struct bootstrap_login_pkt {
    int code;
    string username;
    EVP_PKEY* sts_key_param;
    EVP_PKEY* hmac_key_param;
};

