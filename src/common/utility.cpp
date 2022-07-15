#include "utility.h"


// return dh_key if no error occurs, otherwise NULL
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
    catch (int e) {
		if (e >= 2) {
            // free the allocated buffer for the key
			free(key_buffer);
		}
		if (e >= 1) {
            // free the allocated space for bio
			BIO_free(bio);
		}
		return nullptr;
	}

	BIO_free(bio);

	return key_buffer;
}

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
		signature = (unsigned char*)malloc(signature_len);
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