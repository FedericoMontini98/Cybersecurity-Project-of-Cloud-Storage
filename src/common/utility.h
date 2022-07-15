
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/pem.h>

using namespace std;

EVP_PKEY* generate_dh_key();
void* serialize_evp_pkey (EVP_PKEY* _key, uint32_t& _key_length);
EVP_PKEY* deserialize_evp_pkey (const void* _key_buffer, const uint32_t _key_length);
unsigned char* sign_message(EVP_PKEY* prvkey, const unsigned char* msg, const size_t msg_len, unsigned int& signature_len);
int verify_signature(EVP_PKEY* pubkey, const unsigned char* signature, const size_t signature_len, const unsigned char* cleartext, const size_t cleartext_len);
