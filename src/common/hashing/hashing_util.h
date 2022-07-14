#include <openssl/evp.h>
#include <iostream>
#include <cstring>
#include <openssl/err.h>
#include <openssl/hmac.h>

using namespace std;

int generate_SHA256_MAC (unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen, uint32_t max_msg_size);
bool verify_SHA256_MAC(unsigned char* digest, unsigned char* received_digest);
int generate_SHA256_HMAC (unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen, unsigned char* key, uint32_t max_msg_size);
int hash_symmetric_key(unsigned char*& symmetric_key, unsigned char* symmetric_key_no_hashed);
int hash_hmac_key(unsigned char*& hmac_key, unsigned char* hmac_key_no_hashed);