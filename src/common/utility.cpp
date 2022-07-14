#include "utility.h"

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