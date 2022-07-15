#include "hashing_util.h"

// GENERATE SHA-256 MAC
int generate_SHA256_MAC (unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen, uint32_t max_msg_size){
	int ret;
    EVP_MD_CTX* ctx;

    if (msg_len == 0 || msg_len > max_msg_size) {
        cerr << "message length is not allowed" << endl;
        return -1;
    }

    try{
        digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
        if (!digest){
            cerr << "malloc of digest failed" << endl;
            throw 1;
        }

        ctx = EVP_MD_CTX_new();

        if (!ctx){
            cerr << "context definition failed" << endl;
            throw 2;
        }

        ret = EVP_DigestInit(ctx, EVP_sha256());;

        if (ret != 1) {
			cerr << "failed to initialize digest creation" << endl;
			ERR_print_errors_fp(stderr);
			throw 3;
		}

        ret = EVP_DigestUpdate(ctx, (unsigned char*)msg, msg_len); 

        if (ret != 1) {
            cerr << "failed to update digest " << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
        }

        ret = EVP_DigestFinal(ctx, digest, &digestlen);

        if (ret != 1) {
            cerr << "failed to finalize digest " << endl;
			ERR_print_errors_fp(stderr);
			throw 5;
        }

    }
    catch (int error_code){

        free(digest);
        
        if (error_code > 1){
            EVP_MD_CTX_free(ctx);
        }

        return -1;

    }
	
	EVP_MD_CTX_free(ctx);
    return 0;
}

// verify if 2 digest SHA-256 are the same
bool verify_SHA256_MAC(unsigned char* digest, unsigned char* received_digest){
	
	if(CRYPTO_memcmp(digest, received_digest, EVP_MD_size(EVP_sha256())) == 0){
		return true;
	}
	else{
		return false;
	}		

}

// GENERATE SHA-256 HMAC with a 256 bit key
int generate_SHA256_HMAC (unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen, 
unsigned char* key, uint32_t max_msg_size){
	int ret;
    HMAC_CTX* ctx;

    if (msg_len == 0 || msg_len > max_msg_size) {
        cerr << "message length is not allowed" << endl;
        return -1;
    }

    try{
        digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
        if (!digest){
            cerr << "malloc of digest failed" << endl;
            throw 1;
        }

        ctx = HMAC_CTX_new();;

        if (!ctx){
            cerr << "context definition failed" << endl;
            throw 2;
        }

        ret = HMAC_Init_ex(ctx, key, EVP_MD_size(EVP_sha256()), EVP_sha256(), NULL);

        if (ret != 1) {
			cerr << "failed to initialize digest creation" << endl;
			ERR_print_errors_fp(stderr);
			throw 3;
		}

        ret = HMAC_Update(ctx, (unsigned char*)msg, msg_len); 

        if (ret != 1) {
            cerr << "failed to update digest " << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
        }

        ret = HMAC_Final(ctx, digest, &digestlen);

        if (ret != 1) {
            cerr << "failed to finalize digest " << endl;
			ERR_print_errors_fp(stderr);
			throw 5;
        }

    }
    catch (int error_code){

        free(digest);
        
        if (error_code > 1){
            HMAC_CTX_free(ctx);
        }

        return -1;

    }
	
	HMAC_CTX_free(ctx);
    return 0;
}

int hash_symmetric_key(unsigned char*& symmetric_key, unsigned char* symmetric_key_no_hashed){
	unsigned char* hash;
	uint32_t len;
	int ret;
	
	ret = generate_SHA256_MAC(symmetric_key_no_hashed, 128, hash, len, 128);
	
	if (ret != 0){
		cerr << "failed to hash symmetric key" << endl;
		return ret;
	}
	
	symmetric_key = (unsigned char*) malloc(128);
	
	if (symmetric_key == nullptr){
		cerr << "failed to malloc symmetric key" << endl;
		return -1;
	}
	
	// take a portion of the mac
	memcpy(symmetric_key, hash, 128);
	
	return 0;
}

int hash_hmac_key(unsigned char*& hmac_key, unsigned char* hmac_key_no_hashed){
	unsigned char* hash;
	uint32_t len;
	int ret;
	
	ret = generate_SHA256_MAC(hmac_key_no_hashed, 128, hash, len, 128);
	
	if (ret != 0){
		cerr << "failed to hash symmetric key" << endl;
		return ret;
	}
	
	hmac_key = (unsigned char*) malloc(256);
	
	if (hmac_key == nullptr){
		cerr << "failed to malloc hmac key" << endl;
		return -1;
	}
	
	// take the total hash
	memcpy(hmac_key, hash, 256);
	
	return 0;
}