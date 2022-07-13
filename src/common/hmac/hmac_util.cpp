#include "hmac_util.h"

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