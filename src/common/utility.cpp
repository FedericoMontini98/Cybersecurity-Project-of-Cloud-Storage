#include "utility.h"

/**
 *  Generate the client or the server part of the shared session key, i.e. g**a for the DH protocol
 * 
 * @return the genereted key on success or NULL in the other cases
 */
 
# define DEBUG true

EVP_PKEY* generate_dh_key(){
	EVP_PKEY* dh_params = nullptr;
    EVP_PKEY_CTX* dh_gen_ctx = nullptr;
	EVP_PKEY* dh_key = nullptr;
    
    int ret;

    try{
        // Allocate p and g
        dh_params = EVP_PKEY_new();
        if (!dh_params){
            cerr << "ERR: fail to generate new dh params" << endl;
            throw 0;
        }

        // set default dh parameters for p and g
        DH* default_params = DH_get_2048_224();
        ret = EVP_PKEY_set1_DH(dh_params, default_params);
        
        // no longer need of this variable
        DH_free(default_params);

        if (ret != 1) {
            cerr << "ERR: failed to load default params" << endl;
            throw 1;
        }

        // g^a or g^b
        dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
		if (!dh_gen_ctx) {
            cerr << "ERR: failed to load define dh context" << endl;
            throw 2;
        }

        ret = EVP_PKEY_keygen_init(dh_gen_ctx);
		if (ret != 1) {
            cerr << "ERR: failed dh keygen init" << endl;
            throw 3;
        }

		ret = EVP_PKEY_keygen(dh_gen_ctx, &dh_key);
		if (ret != 1){ 
            cerr << "ERR: failed dh keygen" << endl;
            throw 4;
        }
    }
    catch (int error_code){

        if (error_code > 0){
            EVP_PKEY_free(dh_params);
        }
        
        if (error_code > 1) {
            EVP_PKEY_CTX_free(dh_gen_ctx);
        }

        return nullptr;
    }

    EVP_PKEY_CTX_free(dh_gen_ctx);
	EVP_PKEY_free(dh_params);

    return dh_key;
}


/**
 * This function derive a shared session key using the Diffie-Hellman exchange method
 * The shared session key obtained by the merge of the client and the server's keys is then 
 * hashed with SHA-256, this function could be used to create the asimmetric key for the AES or
 * the key for the HMAC
 * 
 * @param this_host_dh_key is the key genereted by the current host
 * @param other_host_dh_key is the key genereted by the others hosts
 * @return the session key on success or NULL in the other cases
 */
unsigned char* derive_shared_secret(EVP_PKEY* this_host_dh_key, EVP_PKEY* other_host_dh_key){

	int ret;
	unsigned char* key = nullptr;

	// Create a new context for deriving DH key
	EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(this_host_dh_key, nullptr);
	if (!key_ctx) {
		cerr << "ERR: failed to load define dh context of the current host" << endl;
		return nullptr;
	}

	unsigned char* shared_secret = nullptr;
	size_t secret_length = 0;

	// Derive the shared secret between the two hosts
	try {
		ret = EVP_PKEY_derive_init(key_ctx);
		if (ret != 1){
			throw 0;
		}
		ret = EVP_PKEY_derive_set_peer(key_ctx, other_host_dh_key);
		if (ret != 1){
			throw 0;
		}
		ret = EVP_PKEY_derive(key_ctx, nullptr, &secret_length);
		if (ret != 1){
			throw 0;
		} 
		shared_secret = (unsigned char*)malloc(secret_length);
		if (!shared_secret){
			throw 1;
		}
			
	} 
	catch (int e) {
		if (e == 1) {
			cerr << "[derive_session_key]: allocation for shared secret failed" << endl;
		}
		else {
			cerr << "[derive_session_key]: failed " <<endl;
			ERR_print_errors_fp(stderr);
		}

		EVP_PKEY_CTX_free(key_ctx);
		return nullptr;
	}

	ret = EVP_PKEY_derive(key_ctx, shared_secret, &secret_length);
	EVP_PKEY_CTX_free(key_ctx);
	if (ret != 1) { 
		memset(shared_secret, 0, secret_length);
		free(shared_secret);

		return nullptr;
	}

	return shared_secret;
}

// serialize key EVP_PKEY
void* serialize_evp_pkey (EVP_PKEY* _key, uint32_t& _key_length){
	int ret;
	long ret_long;

	BIO* bio = nullptr;
    // maybe char*
	void* key_buffer = nullptr;

	try {
		// Allocate an instance of the BIO structure for serialization
		bio = BIO_new(BIO_s_mem());
		if (!bio) {
			cerr << "BIO_new failed" << endl;
			throw 0;
		}

		// Serialize a key into PEM format and write it in the BIO
		ret = PEM_write_bio_PUBKEY(bio, _key);
		if (ret != 1) {
			cerr << "PEM_write_bio_PUBKEY failed and returned: " << ret << endl;
			throw 1;
		}

		// Set of the pointer key_buffer to the buffer of the memory bio and return its size
		ret_long = BIO_get_mem_data(bio, &key_buffer);
		if (ret_long <= 0) {
			cerr << "BIO_get_mem_data failed and returned: " << ret_long << endl;
			throw 1;
		}
		_key_length = (uint32_t)ret_long;
		
		// Allocate memory for the serialized key
		key_buffer = malloc(_key_length);
		if (!key_buffer) {
			cerr << "malloc of the buffer for serialized key failed" << endl;
			throw 1;
		}

		// Read data from bio and extract serialized key
		ret = BIO_read(bio, key_buffer, _key_length);
		if (ret < 1) {
			cerr << "BIO_read failed and returned: " << ret << endl;
			throw 2;
		}

	} 
    catch (int error_code) {
		if (error_code >= 2) {
            // free the allocated buffer for the key
			free(key_buffer);
		}
		if (error_code >= 1) {
            // free the allocated space for bio
			BIO_free(bio);
		}
		return nullptr;
	}

	BIO_free(bio);

	return key_buffer;
}

// deserialize key EVP_PKEY
EVP_PKEY* deserialize_evp_pkey (const void* _key_buffer, const uint32_t _key_length){
	int ret;
	BIO* bio;
	EVP_PKEY* key;

	try {
		// Allocate an instance of the BIO structure for serialization
		bio = BIO_new(BIO_s_mem());
		if (!bio) {
			cerr << "BIO_new failed" << endl;
			throw 0;
		}
		
		// Write serialized the key from the buffer in bio
		ret = BIO_write(bio, _key_buffer, _key_length);
		if (ret <= 0) {
			cerr << "BIO_write failed and returned: " << ret << endl;
			throw 1;
		}
		
		// Reads a key written in PEM format from the bio and deserialize it
		key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
		if (!key) {
			cerr << "PEM_read_bio_PUBKEY failed" << endl;
			throw 1;
		}
		
	} 
    catch (int e) {
        // free the allocated space for bio
		if (e >= 1) {
			BIO_free(bio);
		}
		return nullptr;
	}

	BIO_free(bio);

	return key;
}

// serialize certificate X509
void* serialize_certificate_X509(X509* cert, uint32_t& cert_length){
	int ret;
	long ret_long;

	BIO* bio = nullptr;
	void* cert_buffer = nullptr;

	try {
		// Allocate an instance of the BIO structure for serialization
		bio = BIO_new(BIO_s_mem());
		if (!bio) {
			cerr << "BIO_new failed" << endl;
			throw 0;
		}

		// Serialize certificate into PEM format and write it in the BIO
		ret = PEM_write_bio_X509(bio, cert);
		if (ret != 1) {
			cerr << "PEM_write_bio_X509 failed and returned: " << ret << endl;
			throw 1;
		}

		// Set of the pointer cert_buffer to the buffer of the memory bio and return its size
		ret_long = BIO_get_mem_data(bio, &cert_buffer);
		if (ret_long <= 0) {
			cerr << "BIO_get_mem_data failed and returned: " << ret_long << endl;
			throw 1;
		}
		cert_length = (uint32_t)ret_long;
		
		// Allocate memory for the serialized certificate
		cert_buffer = malloc(cert_length);
		if (!cert_buffer) {
			cerr << "malloc of the buffer for serialized cert failed" << endl;
			throw 1;
		}

		// Read data from bio and extract serialized certificate
		ret = BIO_read(bio, cert_buffer, cert_length);
		if (ret < 1) {
			cerr << "BIO_read failed and returned: " << ret << endl;
			throw 2;
		}

	} 
    catch (int error_code) {
		if (error_code >= 2) {
            // free the allocated buffer for the certificate
			free(cert_buffer);
		}
		if (error_code >= 1) {
            // free the allocated space for bio
			BIO_free(bio);
		}
		return nullptr;
	}

	BIO_free(bio);

	return cert_buffer;
}

// deserialize certificate X509
X509* deserialize_certificate_X509(const void* cert_buffer, const uint32_t cert_length){
	int ret;
	BIO* bio;
	X509* cert;

	try {
		// Allocate an instance of the BIO structure for serialization
		bio = BIO_new(BIO_s_mem());
		if (!bio) {
			cerr << "BIO_new failed" << endl;
			throw 0;
		}
		
		// Write serialized the key from the buffer in bio
		ret = BIO_write(bio, cert_buffer, cert_length);
		if (ret <= 0) {
			cerr << "BIO_write failed and returned: " << ret << endl;
			throw 1;
		}
		
		// Reads a certificate written in PEM format from the bio and deserialize it
		cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
		if (!cert) {
			cerr << "PEM_read_bio_X509 failed" << endl;
			throw 1;
		}
		
	} 
    catch (int error_code) {
        // free the allocated space for bio
		if (error_code >= 1) {
			BIO_free(bio);
		}
		return nullptr;
	}

	BIO_free(bio);

	return cert;
}

// sign a message using private key prvkey
// DO NOT HANDLE FREE
unsigned char* sign_message(EVP_PKEY* prvkey, const unsigned char* msg, const size_t msg_len, unsigned int& signature_len) {
	int ret;
	EVP_MD_CTX* ctx = nullptr;
	unsigned char* signature = nullptr;
	
	if (!prvkey){
		return nullptr;
	}
	
	try {
		
		ctx = EVP_MD_CTX_new();
		if (!ctx) {
			cerr << "error in defining new context for signature" << endl;
			throw 1;
		}

		ret = EVP_SignInit(ctx, EVP_sha256());
		if (ret != 1) {
			cerr << "sign init error" << endl;
			throw 2;
		}

		ret = EVP_SignUpdate(ctx, msg, msg_len);
		if (ret != 1) {
			cerr << "sign update error" << endl;
			throw 3;
		}

		signature_len = EVP_PKEY_size(prvkey);
		signature = (unsigned char*) malloc(signature_len);
		if (!signature) {
			cerr << "error in signature malloc" << endl;
			throw 4;
		}

		ret = EVP_SignFinal(ctx, signature, &signature_len, prvkey);
		if (ret != 1) {
			cerr << "sign final error" << endl;
			throw 5;
		}

	} catch (int error_code) {
		
		EVP_MD_CTX_free(ctx);
		
		if (error_code >= 4) {
			free(signature);
		}
		return nullptr;
	}
	
	// DEBUG, print signature 
    if (DEBUG) {
        cout << "signature_len: " << signature_len << endl;
        cout << "signature: ";
        for (int i = 0; i < 1; i++){
            std::cout << static_cast<unsigned int>(signature[0]) << std::flush;
        }
        cout << endl;
    }
	
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(prvkey);

	return signature;
}

// verify signature with pubkey
// DO NOT HANDLE FREE
int verify_signature(EVP_PKEY* pubkey, const unsigned char* signature, const size_t signature_len, const unsigned char* cleartext, const size_t cleartext_len){
	EVP_MD_CTX* ctx = nullptr;

	int ret;
	
	if (pubkey == nullptr){
		return -1;
	}
	
	// verify signature
	try {
		ctx = EVP_MD_CTX_new();
		if (!ctx) {
			cerr << "error in defining new context for signature" << endl;
			throw 1;
		}

		ret = EVP_VerifyInit(ctx, EVP_sha256());
		if (ret != 1) {
			cerr << "error in verify init for signature" << endl;
			throw 2;
		}

		ret = EVP_VerifyUpdate(ctx, cleartext, cleartext_len);
		if (ret != 1) {
			cerr << "error in verify update for signature" << endl;
			throw 3;
		}
		
		ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);

		if (ret != 1) {
			cerr << "error in verify final for signature" << endl;
			throw 4;
		}

	} catch (int error_code) {
		
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pubkey);

	return 0;
}

int validate_certificate(X509* CA_cert, X509_CRL* crl, X509* cert_to_verify) {
	int ret = 0;
	X509_STORE* store = nullptr;
	X509_STORE_CTX* ctx = nullptr;

	try {
		// allocate store
		store = X509_STORE_new();
		if (!store) {
			cerr << "failed to create a new store" << endl;
			throw 0;
		}
		// add CA_cert to store
		ret = X509_STORE_add_cert(store, CA_cert);
		if (ret != 1) {
			cerr << "failed to add ca certificate to store" << endl;
			throw 1;
		}
		// add crl to store
		ret = X509_STORE_add_crl(store, crl);
		if (ret != 1) {
			cerr << "failed to add crl to store" << endl;
			throw 1;
		}
		// set flags
		ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		if (ret != 1) {
			cerr << "failed to set flags to store" << endl;
			throw 1;
		}

		//check validity
		ctx = X509_STORE_CTX_new();
		if (!ctx) {
			cerr << "failed to create a new context for store" << endl;
			throw 2;
		}
		ret = X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL);
		if (ret != 1) {
			cerr << "failed to initialize store context" << endl;
			throw 2;
		}
		ret = X509_verify_cert(ctx);
		if (ret != 1) {
			cerr << "failed to verify certificate" << endl;
			cerr << ERR_error_string(ERR_get_error(), NULL) << endl;
			throw 2;
		}

	} catch (int e) {
		if (e >= 2) {
			X509_STORE_CTX_free(ctx);;
		}
		if (e >= 1) {
			X509_STORE_free(store);
		}
		return -1;
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return 0;
}

