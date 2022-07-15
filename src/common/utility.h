
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

using namespace std;

/**
 *  Generate the client or the server part of the shared session key, i.e. g**a for the DH protocol
 * 
 * @return the genereted key on success or NULL in the other cases
 */
EVP_PKEY* generate_dh_key();

/**
 * This function derive a shared session key using the Diffie-Hellman exchange method
 * The shared session key obtained by the merge of the client and the server's keys is then 
 * hashed with SHA-256, this function could be used to create the asimmetric key for the AES or
 * the key for the HMAC
 * 
 * @param client_dh_key is the key genereted by the client
 * @param server_dh_key is the key genereted by the server
 * @return the session key on success or NULL in the other cases
 */
unsigned char* derive_share_secret(EVP_PKEY* client_dh_key, EVP_PKEY* server_dh_key);
void* serialize_evp_pkey (EVP_PKEY* _key, uint32_t& _key_length);
EVP_PKEY* deserialize_evp_pkey (const void* _key_buffer, const uint32_t _key_length);
void* serialize_certificate_X509(X509* cert, uint32_t& cert_length);
X509* deserialize_certificate_X509(const void* cert_buffer, const uint32_t cert_length);
unsigned char* sign_message(EVP_PKEY* prvkey, const unsigned char* msg, const size_t msg_len, unsigned int& signature_len);
int verify_signature(EVP_PKEY* pubkey, const unsigned char* signature, const size_t signature_len, const unsigned char* cleartext, const size_t cleartext_len);
