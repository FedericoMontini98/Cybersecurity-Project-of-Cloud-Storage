#include <openssl/evp.h>
#include <iostream>
#include <cstring>
#include <openssl/err.h>
#include <openssl/hmac.h>

using namespace std;

int generate_SHA256_HMAC (unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen, 
unsigned char* key, uint32_t max_msg_size);