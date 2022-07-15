
#include <cstring>
#include "utility.h"

using namespace std;


// THIS FILE CONTAINS THE STRUCTURE OF THE PACKETS WITH THEIR CODE

// PACKET CODES
# define BOOTSTRAP_LOGIN            1
# define BOOTSTRAP_UPLOAD           5


/*
    Legenda tipi
    uint8_t = char/
    uint16_t = short/ unsigend short -- htons
    uint32_t = int/ unsigned int     -- htonl
*/

// SENT IN CLEAR
# define LOGIN_BOOTSTRAP 1

struct login_bootstrap_pkt {
    uint16_t code;
    uint16_t username_len;
    string username;
    uint32_t symmetric_key_param_len;
    uint32_t hmac_key_param_len;
    EVP_PKEY* symmetric_key_param;
    EVP_PKEY* hmac_key_param;  
    
    // function that return a void* serialized_pkt that contains the serialized packet 
    // ready to be sent on the network 
    void* serialize_message(int& len){
        uint8_t* serialized_pkt = nullptr;     // pointer to the serialized packet buffer to be returned
        void* key_buffer_symmetric = nullptr;     // pointer to the buffer with the serialized key for the sts parameter
        void* key_buffer_hmac = nullptr;    // pointer to the buffer with the serialized key for the hmac parameter
        int pointer_counter = 0;       // pointer for copy the field of the bootstrap packet into the buffer for the
                                            // serialized packet pointed by serialized_pkt

        // get of the pointer to the serialized sts parameter buffer
        key_buffer_symmetric = serialize_evp_pkey(symmetric_key_param, symmetric_key_param_len);

        if(key_buffer_symmetric == nullptr){
            return nullptr;
        }

        // get of the pointer to the serialized hmac parameter buffer
        key_buffer_hmac = serialize_evp_pkey(hmac_key_param, hmac_key_param_len);

        if(key_buffer_hmac == nullptr){
            return nullptr;
        }

        // get certified lengths and set username_len
        uint16_t certified_code = htons(code);
        username_len = username.length();
        uint16_t certified_username_len = htons(username_len);

        // total len of the serialized packet
        len = sizeof(certified_code) + sizeof(certified_username_len) + username_len + sizeof(symmetric_key_param_len) 
        + sizeof(hmac_key_param_len) + symmetric_key_param_len + hmac_key_param_len;

        // buffer allocation for the serialized packet
        serialized_pkt = (uint8_t*) malloc(len);

        if (!serialized_pkt){
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        // copy of all the field of the bootstrap packet into the serialized packet buffer

        // copy of the code
        memcpy(serialized_pkt, &certified_code, sizeof(certified_code));
        pointer_counter += sizeof(code);

        // copy username_len
        memcpy(serialized_pkt + pointer_counter, &certified_username_len, sizeof(certified_username_len));
        pointer_counter += sizeof(username_len);

        // copy of the username passing a null terminated sequence of characters
        uint8_t * username_certified = (uint8_t *) username.c_str();
        memcpy (serialized_pkt + pointer_counter, username_certified, username_len);
        pointer_counter += username_len;

        // copy of symmetric_key_param_len
        uint32_t certified_symmetric_len = htonl(symmetric_key_param_len);
        memcpy(serialized_pkt + pointer_counter, &certified_symmetric_len, sizeof(certified_symmetric_len));
        pointer_counter += sizeof(certified_symmetric_len);

        // copy of hmac_key_param_len
        uint32_t certified_hmac_len = htonl(hmac_key_param_len);
        memcpy(serialized_pkt + pointer_counter, &certified_hmac_len, sizeof(certified_hmac_len));
        pointer_counter += sizeof(certified_hmac_len);

        // copy of the symmetric_key_param buffer
        memcpy (serialized_pkt + pointer_counter, key_buffer_symmetric, symmetric_key_param_len);
        pointer_counter += symmetric_key_param_len;

        // copy of the hmac_key_param buffer
        memcpy (serialized_pkt + pointer_counter, key_buffer_hmac, hmac_key_param_len);

        return serialized_pkt;
    }

    // function that deserialize a pkt from the network and set
    // the field of the struct
    bool deserialize_message(uint8_t* serialized_pkt){
        int pointer_counter = 0;

        // copy of the code
        memcpy (&code, serialized_pkt, sizeof(code));
        code = ntohs(code);
        pointer_counter += sizeof(code);
		
		// pkt type mismatch
		if (code != LOGIN_BOOTSTRAP){
			return false;
		}

        // copy username_len
        memcpy(&username_len, serialized_pkt + pointer_counter, sizeof(username_len));
        username_len = ntohs(username_len);
        pointer_counter += sizeof(username_len);

        // copy of the username 
        username.assign((char *) serialized_pkt + pointer_counter, username_len);
        pointer_counter += username_len;

        // copy of symmetric_key_param_len
        memcpy(&symmetric_key_param_len, serialized_pkt + pointer_counter, sizeof(symmetric_key_param_len));
        symmetric_key_param_len = ntohl(symmetric_key_param_len);
        pointer_counter += sizeof(symmetric_key_param_len);

        // copy of hmac_key_param_len
        memcpy(&hmac_key_param_len, serialized_pkt + pointer_counter, sizeof(hmac_key_param_len));
        hmac_key_param_len = ntohl(hmac_key_param_len);
        pointer_counter += sizeof(hmac_key_param_len);

        // copy of the symmetric parameter
        symmetric_key_param = deserialize_evp_pkey(serialized_pkt + pointer_counter, symmetric_key_param_len);
        pointer_counter += symmetric_key_param_len;

        // copy of the hmac parameter
        hmac_key_param = deserialize_evp_pkey(serialized_pkt + pointer_counter, hmac_key_param_len);
		
		if (symmetric_key_param == nullptr || hmac_key_param == nullptr){
			return false;
		}

        /*
        BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
        EVP_PKEY_print_public(bp, symmetric_key_param, 1, NULL);
        BIO_free(bp);
        */
		
		return true;
    }
};

struct upload_filename_exist {
    int code;
    string filename;
    bool response;      //True: upload allowed  False: upload not allowed
    uint32_t counter;
    
};

# define LOGIN_REFUSE_CONNECTION 2

struct login_refuse_connection_pkt {
    uint16_t code;

    void serialize_message(){
        code = htons(code);
    }

    bool deserialize_message(){
        code= ntohs(code);
		
		if (code != LOGIN_REFUSE_CONNECTION){
			return false;
		}
    }
};

# define LOGIN_AUTHENTICATION 3

struct login_authentication_pkt {
	//CONSTANT
	int iv_cbc_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
	
	// clear fields
    uint16_t code;
	uint32_t cert_len = 0;
	uint32_t encrypted_signing_len;
	uint8_t* iv_cbc = nullptr;
	X509* cert = nullptr;
	
	// encrypted string
	uint8_t* encrypted_signing = nullptr;
	
	// Encrypted/Decrypted part
	uint32_t symmetric_key_param_len_server;
    uint32_t hmac_key_param_len_server;
	uint32_t symmetric_key_param_len_client;
    uint32_t hmac_key_param_len_client;
	
	EVP_PKEY* symmetric_key_param_server;
	EVP_PKEY* hmac_key_param_server;
	EVP_PKEY* symmetric_key_param_client;
	EVP_PKEY* hmac_key_param_client;
	
	
	// serialize the part to be encrypted/signed, this function must be called before serialized_message
	void* serialize_part_to_encrypt(int &len){
		uint8_t* serialized_pte;
        void* key_buffer_symmetric_server = nullptr;     
        void* key_buffer_hmac_server = nullptr;    
        void* key_buffer_symmetric_client = nullptr;    
        void* key_buffer_hmac_client = nullptr;    
		
        int pointer_counter = 0; 
		
		// evp serializations
		key_buffer_symmetric_server = serialize_evp_pkey(symmetric_key_param_server, symmetric_key_param_len_server);
		key_buffer_hmac_server = serialize_evp_pkey(hmac_key_param_server, hmac_key_param_len_server);
		key_buffer_symmetric_client = serialize_evp_pkey(symmetric_key_param_client, symmetric_key_param_len_client);
		key_buffer_hmac_client = serialize_evp_pkey(hmac_key_param_client, hmac_key_param_len_client);
		
		// total len of the encrypted part
        len = sizeof(symmetric_key_param_len_server) + sizeof(hmac_key_param_len_server) + sizeof(symmetric_key_param_len_client) + 
		sizeof(hmac_key_param_len_client) + symmetric_key_param_len_server + hmac_key_param_len_server + symmetric_key_param_len_client +
		hmac_key_param_len_client;

        // buffer allocation for the serialized packet
        serialized_pte = (uint8_t*) malloc(len);

        if (!serialized_pte){
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }
		
		// get certified lengths
        uint32_t certified_symmetric_key_param_len_server = htonl(symmetric_key_param_len_server);
        uint32_t certified_hmac_key_param_len_server = htonl(hmac_key_param_len_server);
		uint32_t certified_symmetric_key_param_len_client = htonl(symmetric_key_param_len_client);
        uint32_t certified_hmac_key_param_len_client = htonl(hmac_key_param_len_client);
		
		// lenght copies
        memcpy(serialized_pte, &certified_symmetric_key_param_len_server, sizeof(certified_symmetric_key_param_len_server));
        pointer_counter += sizeof(certified_symmetric_key_param_len_server);
		
		memcpy(serialized_pte + pointer_counter, &certified_hmac_key_param_len_server, sizeof(certified_hmac_key_param_len_server));
        pointer_counter += sizeof(certified_hmac_key_param_len_server);
		
		memcpy(serialized_pte + pointer_counter, &certified_symmetric_key_param_len_client, sizeof(certified_symmetric_key_param_len_client));
        pointer_counter += sizeof(certified_symmetric_key_param_len_client);
		
		memcpy(serialized_pte + pointer_counter, &certified_hmac_key_param_len_client, sizeof(certified_hmac_key_param_len_client));
        pointer_counter += sizeof(certified_hmac_key_param_len_client);
		
		// buffer copies
		memcpy(serialized_pte + pointer_counter, key_buffer_symmetric_server, symmetric_key_param_len_server);
        pointer_counter += symmetric_key_param_len_server;
		
		memcpy(serialized_pte + pointer_counter, key_buffer_hmac_server, hmac_key_param_len_server);
        pointer_counter += hmac_key_param_len_server;
		
		memcpy(serialized_pte + pointer_counter, key_buffer_symmetric_client, symmetric_key_param_len_client);
        pointer_counter += symmetric_key_param_len_client;
		
		memcpy(serialized_pte + pointer_counter, key_buffer_hmac_client, hmac_key_param_len_client);
        pointer_counter += hmac_key_param_len_client;
		
		return serialized_pte;
    }

	// serialize the message with the encrypted part
	void* serialize_message(int& len){
		uint8_t* serialized_pkt = nullptr;  
		void* cert_buffer = nullptr; 
		int pointer_counter = 0;
		
		if(encrypted_signing == nullptr || encrypted_signing_len== 0 || iv_cbc == nullptr || cert == nullptr || cert_len == 0){
			
			cerr << "missing fields for serialization" << endl;
			return nullptr;
		}
		
		//certified lenghts
		uint16_t certified_code = htons(code);
		uint32_t certified_encrypted_signing_len = htonl(encrypted_signing_len);
		
		// serialize the certificate
		cert_buffer = serialize_certificate_X509(cert, cert_len);
		uint32_t certified_cert_len = htonl(cert_len);
		
		len = sizeof(certified_code) + sizeof(certified_cert_len) + sizeof(certified_encrypted_signing_len) 
		+ iv_cbc_len + cert_len + encrypted_signing_len;
		
		// buffer allocation for the serialized packet
        serialized_pkt = (uint8_t*) malloc(len);

        if (!serialized_pkt){
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }
		
		// copy lengths
		memcpy(serialized_pkt, &certified_code, sizeof(certified_code));
		pointer_counter += sizeof(certified_code);
		memcpy(serialized_pkt + pointer_counter, &certified_cert_len, sizeof(certified_cert_len));
		pointer_counter += sizeof(certified_cert_len);
		memcpy(serialized_pkt + pointer_counter, &certified_encrypted_signing_len, sizeof(certified_encrypted_signing_len));
		pointer_counter += sizeof(encrypted_signing_len);
		
		// copy fields
		memcpy(serialized_pkt + pointer_counter, iv_cbc, iv_cbc_len);
		pointer_counter += iv_cbc_len;
		memcpy(serialized_pkt + pointer_counter, cert_buffer, cert_len);
		pointer_counter += cert_len;
		memcpy(serialized_pkt + pointer_counter, encrypted_signing, encrypted_signing_len);
		
		return serialized_pkt;
	}
	
	// deserialize the message with the encrypted parte, this function must be called before deserialize_encrypted_part
    bool deserialize_message(uint8_t* serialized_pkt){
		int pointer_counter = 0;

        // copy of the code
        memcpy (&code, serialized_pkt, sizeof(code));
        code = ntohs(code);
        pointer_counter += sizeof(code);
		
		// pkt type mismatch
		if (code != LOGIN_BOOTSTRAP){
			return false;
		}
		
		// copy cert_len
		memcpy (&cert_len, serialized_pkt + pointer_counter, sizeof(cert_len));
        cert_len = ntohl(cert_len);
        pointer_counter += sizeof(cert_len);
		
		// copy of encrypted_signing_len
		memcpy (&encrypted_signing_len, serialized_pkt + pointer_counter, sizeof(encrypted_signing_len));
        encrypted_signing_len = ntohl(encrypted_signing_len);
        pointer_counter += sizeof(encrypted_signing_len);
		
		// copy of iv_cbc
		memcpy (iv_cbc, serialized_pkt + pointer_counter, iv_cbc_len);
        pointer_counter += iv_cbc_len;
		
		// copy of certificate
		cert = deserialize_certificate_X509 (serialized_pkt + pointer_counter, cert_len);
		pointer_counter += cert_len;
		
		// copy of the encrypted part
		memcpy (encrypted_signing, serialized_pkt + pointer_counter, encrypted_signing_len);
		
		/*
        BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
        EVP_X509_print_public(bp, cert, 1, NULL);
        BIO_free(bp);
        */
    }
	
	bool deserialize_encrypted_part(uint8_t* plaintext){
		int pointer_counter = 0;
		
		// length copies
        memcpy(&symmetric_key_param_len_server, plaintext, sizeof(symmetric_key_param_len_server));
        pointer_counter += sizeof(symmetric_key_param_len_server);
		
		memcpy(&hmac_key_param_len_server, plaintext + pointer_counter, sizeof(hmac_key_param_len_server));
        pointer_counter += sizeof(hmac_key_param_len_server);
		
		memcpy(&symmetric_key_param_len_client, plaintext + pointer_counter, sizeof(symmetric_key_param_len_client));
        pointer_counter += sizeof(symmetric_key_param_len_client);
		
		memcpy(&hmac_key_param_len_client, plaintext + pointer_counter, sizeof(hmac_key_param_len_client));
        pointer_counter += sizeof(hmac_key_param_len_client);

		// key deserialization
		symmetric_key_param_server = deserialize_evp_pkey(plaintext + pointer_counter, symmetric_key_param_len_server);
		pointer_counter += symmetric_key_param_len_server;
		
		hmac_key_param_server = deserialize_evp_pkey(plaintext + pointer_counter, hmac_key_param_len_server);
		pointer_counter += hmac_key_param_len_server;
		
		symmetric_key_param_client = deserialize_evp_pkey(plaintext + pointer_counter, symmetric_key_param_len_client);
		pointer_counter += symmetric_key_param_len_client;
		
		hmac_key_param_client = deserialize_evp_pkey(plaintext + pointer_counter, hmac_key_param_len_client);
		pointer_counter += hmac_key_param_len_client;
		
		if (symmetric_key_param_server == nullptr || hmac_key_param_server == nullptr || symmetric_key_param_client == nullptr || hmac_key_param_client == nullptr){
			
			return false;
		}
		
		/*
        BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
        EVP_PKEY_print_public(bp, symmetric_key_param_server, 1, NULL);
        BIO_free(bp);
        */
		
		return true;

	}	
};

# define LOGIN_CLIENT_AUTHENTICATION 4
// sent in clear
struct login_client_authentication_pkt {
    uint16_t code;
	

    void serialize_message(){
        code = htons(code);
    }

    void deserialize_message(){
        code = ntohs(code);
    }
};


