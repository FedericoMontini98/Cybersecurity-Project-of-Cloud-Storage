
#include <cstring>
#include "utility.h"
#include "./hashing/hashing_util.h"


using namespace std;

// THIS FILE CONTAINS THE STRUCTURE OF THE PACKETS WITH THEIR CODE
# define IV_LENGTH 16
# define HMAC_LENGTH 256

// PACKET CODES
#define BOOTSTRAP_LOGIN 1

/*
    Legenda tipi
    uint8_t = char/
    uint16_t = short/ unsigend short -- htons
    uint32_t = int/ unsigned int     -- htonl
*/

/*********************************************************************************************************************************/

#define GENERIC_MESSAGE 0
struct generic_message{

    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    bool deserialize_message(uint8_t *serialized_pkt){
        int pointer_counter = 0;

        iv = (unsigned char*)malloc(IV_LENGTH);

        // copy of the iv
        memcpy(iv,serialized_pkt + pointer_counter,IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // copy of the ciphertext
        ciphertext.assign((char *)(serialized_pkt + pointer_counter), cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);

        // copy of the ciphertext
        memcpy(HMAC,serialized_pkt + pointer_counter,HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    int deserialize_code(uint8_t *serialized_decrypted_pkt){

        unsigned short code = -1;

        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";
        unsigned int pos;
        //Extract the code
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
        }

        return code;
    }

    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (sizeof(cipher_len) + cipher_len + IV_LENGTH + HMAC_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint32_t certif_ciph_len = htonl(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }
    
};

/*********************************************************************************************************************************/

// SENT IN CLEAR
#define LOGIN_BOOTSTRAP 1

struct login_bootstrap_pkt
{
    uint16_t code = LOGIN_BOOTSTRAP;
    uint16_t username_len;
    string username;
    uint32_t symmetric_key_param_len;
    uint32_t hmac_key_param_len;
    EVP_PKEY *symmetric_key_param;
    EVP_PKEY *hmac_key_param;

    // function that return a void* serialized_pkt that contains the serialized packet
    // ready to be sent on the network
    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;    // pointer to the serialized packet buffer to be returned
        void *key_buffer_symmetric = nullptr; // pointer to the buffer with the serialized key for the sts parameter
        void *key_buffer_hmac = nullptr;      // pointer to the buffer with the serialized key for the hmac parameter
        int pointer_counter = 0;              // pointer for copy the field of the bootstrap packet into the buffer for the
                                              // serialized packet pointed by serialized_pkt

        // get of the pointer to the serialized sts parameter buffer
        key_buffer_symmetric = serialize_evp_pkey(symmetric_key_param, symmetric_key_param_len);

        if (key_buffer_symmetric == nullptr)
        {
            return nullptr;
        }

        // get of the pointer to the serialized hmac parameter buffer
        key_buffer_hmac = serialize_evp_pkey(hmac_key_param, hmac_key_param_len);

        if (key_buffer_hmac == nullptr)
        {
            return nullptr;
        }

        // get certified lengths and set username_len
        uint16_t certified_code = htons(code);
        username_len = username.length();
        uint16_t certified_username_len = htons(username_len);

        // total len of the serialized packet
        len = sizeof(certified_code) + sizeof(certified_username_len) + username_len + sizeof(symmetric_key_param_len) + sizeof(hmac_key_param_len) + symmetric_key_param_len + hmac_key_param_len;

        // buffer allocation for the serialized packet
        serialized_pkt = (uint8_t *)malloc(len);

        if (!serialized_pkt)
        {
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
        uint8_t *username_certified = (uint8_t *)username.c_str();
        memcpy(serialized_pkt + pointer_counter, username_certified, username_len);
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
        memcpy(serialized_pkt + pointer_counter, key_buffer_symmetric, symmetric_key_param_len);
        pointer_counter += symmetric_key_param_len;

        // copy of the hmac_key_param buffer
        memcpy(serialized_pkt + pointer_counter, key_buffer_hmac, hmac_key_param_len);

        return serialized_pkt;
    }

    // function that deserialize a pkt from the network and set
    // the field of the struct
    bool deserialize_message(uint8_t *serialized_pkt)
    {
        int pointer_counter = 0;

        // copy of the code
        memcpy(&code, serialized_pkt, sizeof(code));
        code = ntohs(code);
        pointer_counter += sizeof(code);
		
		cout << code << endl;
		
		// pkt type mismatch
		if (code != LOGIN_BOOTSTRAP){
			cerr << "invalid code in login bootstrap" << endl;
			return false;
		}

        // copy username_len
        memcpy(&username_len, serialized_pkt + pointer_counter, sizeof(username_len));
        username_len = ntohs(username_len);
        pointer_counter += sizeof(username_len);

        // copy of the username
        username.assign((char *)serialized_pkt + pointer_counter, username_len);
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
		
		if (symmetric_key_param == nullptr){
			cerr << "error in deserialization of symmetric key param" << endl;
			return false;
		}

        // copy of the hmac parameter
        hmac_key_param = deserialize_evp_pkey(serialized_pkt + pointer_counter, hmac_key_param_len);
		
		if (hmac_key_param == nullptr){
			cerr << "error in deserialization of hmac key param" << endl;
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

/*********************************************************************************************************************************/

#define LOGIN_REFUSE_CONNECTION 2
// sent in clear
struct login_refuse_connection_pkt
{
    uint16_t code;

    void serialize_message()
    {
        code = htons(code);
    }

    void deserialize_message()
    {
        code = ntohs(code);
    }
};


/*********************************************************************************************************************************/

# define LOGIN_AUTHENTICATION 3

struct login_authentication_pkt {
	
	// clear fields
    uint16_t code = LOGIN_AUTHENTICATION;
	uint32_t cert_len = 0;
	uint32_t symmetric_key_param_server_clear_len; 
	uint32_t hmac_key_param_server_clear_len; 
	uint32_t encrypted_signing_len;
	uint8_t* iv_cbc = nullptr;
	X509* cert = nullptr;
	EVP_PKEY* symmetric_key_param_server_clear;
	EVP_PKEY* hmac_key_param_server_clear;
	
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
	
	
	// serialize the part to be signed and then encrypted, this function must be called before serialize_message
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
		void* key_buffer_symmetric_server_clear = nullptr;
		void* key_buffer_hmac_server_clear = nullptr;
		int pointer_counter = 0;
		
		if(encrypted_signing == nullptr || encrypted_signing_len == 0 || iv_cbc == nullptr || cert == nullptr){
			
			cerr << "missing fields for serialization" << endl;
			return nullptr;
		}
		
		//certified lenghts
		uint16_t certified_code = htons(code);
		uint32_t certified_encrypted_signing_len = htonl(encrypted_signing_len);
		
		// serialize the certificate
		cert_buffer = serialize_certificate_X509(cert, cert_len);
		uint32_t certified_cert_len = htonl(cert_len);
		
		// serialize the dh keys
		
		// symmetric
		key_buffer_symmetric_server_clear = serialize_evp_pkey(symmetric_key_param_server_clear, symmetric_key_param_server_clear_len);
		uint32_t certified_symmetric_key_server_clear_len = htonl(symmetric_key_param_server_clear_len);
		
		// hmac
		key_buffer_hmac_server_clear = serialize_evp_pkey(hmac_key_param_server_clear, hmac_key_param_server_clear_len);
		uint32_t certified_hmac_key_server_clear_len = htonl(hmac_key_param_server_clear_len);
		
		len = sizeof(certified_code) + sizeof(certified_cert_len) + sizeof(certified_symmetric_key_server_clear_len) + sizeof(certified_hmac_key_server_clear_len) 
		+ sizeof(certified_encrypted_signing_len) + IV_LENGTH + cert_len + symmetric_key_param_server_clear_len + hmac_key_param_server_clear_len + encrypted_signing_len;
		
		// buffer allocation for the serialized packet
        serialized_pkt = (uint8_t*) malloc(len);

        if (!serialized_pkt){
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }
		
		// copy code
		memcpy(serialized_pkt, &certified_code, sizeof(certified_code));
		pointer_counter += sizeof(certified_code);
		
		// copy lengths
		memcpy(serialized_pkt + pointer_counter, &certified_cert_len, sizeof(certified_cert_len));
		pointer_counter += sizeof(certified_cert_len);
		
		memcpy(serialized_pkt + pointer_counter, &certified_symmetric_key_server_clear_len, sizeof(certified_symmetric_key_server_clear_len));
		pointer_counter += sizeof(certified_symmetric_key_server_clear_len);
		
		memcpy(serialized_pkt + pointer_counter, &certified_hmac_key_server_clear_len, sizeof(certified_hmac_key_server_clear_len));
		pointer_counter += sizeof(certified_hmac_key_server_clear_len);
		
		memcpy(serialized_pkt + pointer_counter, &certified_encrypted_signing_len, sizeof(certified_encrypted_signing_len));
		pointer_counter += sizeof(encrypted_signing_len);

		// copy fields
		memcpy(serialized_pkt + pointer_counter, iv_cbc, IV_LENGTH);
		pointer_counter += IV_LENGTH;
		
		memcpy(serialized_pkt + pointer_counter, cert_buffer, cert_len);
		pointer_counter += cert_len;
		
		memcpy(serialized_pkt + pointer_counter, key_buffer_symmetric_server_clear, symmetric_key_param_server_clear_len);
		pointer_counter += symmetric_key_param_server_clear_len;
		
		memcpy(serialized_pkt + pointer_counter, key_buffer_hmac_server_clear, hmac_key_param_server_clear_len);
		pointer_counter += hmac_key_param_server_clear_len;
		
		memcpy(serialized_pkt + pointer_counter, encrypted_signing, encrypted_signing_len);
		
		return serialized_pkt;
	}
	
	// deserialize the message with the encrypted part, this function must be called before deserialize_encrypted_part
    bool deserialize_message(uint8_t* serialized_pkt){
		int pointer_counter = 0;

        // copy of the code
        memcpy (&code, serialized_pkt, sizeof(code));
        code = ntohs(code);
        pointer_counter += sizeof(code);
		
		// pkt type mismatch
		if (code != LOGIN_AUTHENTICATION){
			cerr << "invalid code in login bootstrap" << endl;
			return false;
		}
		// code, cert_len, dh_symm_key_len, dh_hmac_key_len, encrypted_signing_len, iv_cbc, cert_len, 
		// dh_symm_key, dh_hmac_key, encrypted_signing
		
		// copy cert_len
		memcpy (&cert_len, serialized_pkt + pointer_counter, sizeof(cert_len));
        cert_len = ntohl(cert_len);
        pointer_counter += sizeof(cert_len);
		
		// copy of dh keys in clear len
		memcpy (&symmetric_key_param_server_clear_len, serialized_pkt + pointer_counter, sizeof(symmetric_key_param_server_clear_len));
        symmetric_key_param_server_clear_len = ntohl(symmetric_key_param_server_clear_len);
        pointer_counter += sizeof(symmetric_key_param_server_clear_len);
		
		memcpy (&hmac_key_param_server_clear_len, serialized_pkt + pointer_counter, sizeof(hmac_key_param_server_clear_len));
        hmac_key_param_server_clear_len = ntohl(hmac_key_param_server_clear_len);
        pointer_counter += sizeof(hmac_key_param_server_clear_len);
		
		// copy of encrypted_signing_len
		memcpy (&encrypted_signing_len, serialized_pkt + pointer_counter, sizeof(encrypted_signing_len));
        encrypted_signing_len = ntohl(encrypted_signing_len);
        pointer_counter += sizeof(encrypted_signing_len);
		
		// copy of iv_cbc
		iv_cbc = serialized_pkt + pointer_counter;
        pointer_counter += IV_LENGTH;
		
		// copy of certificate
		cert = deserialize_certificate_X509 (serialized_pkt + pointer_counter, cert_len);
		pointer_counter += cert_len;
		
		// copy of dh keys
		
		// symmetric
		symmetric_key_param_server_clear = deserialize_evp_pkey(serialized_pkt + pointer_counter, symmetric_key_param_server_clear_len);
		pointer_counter += symmetric_key_param_server_clear_len;
		
		if (symmetric_key_param_server_clear == nullptr){
			cerr << "error in deserialization of symmetric key param" << endl;
			return false;
		}
		
		// hmac
		hmac_key_param_server_clear = deserialize_evp_pkey(serialized_pkt + pointer_counter, hmac_key_param_server_clear_len);
		pointer_counter += hmac_key_param_server_clear_len;
		
		if (hmac_key_param_server_clear == nullptr){
			cerr << "error in deserialization of hmac key param" << endl;
			return false;
		}
		
		// point to encrypted part
		encrypted_signing = (uint8_t*) malloc(encrypted_signing_len);
		memcpy(encrypted_signing, serialized_pkt + pointer_counter, encrypted_signing_len);
		
		return true;
		
		/*
        BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
        EVP_X509_print_public(bp, cert, 1, NULL);
        BIO_free(bp);
        */
    }
	
	// deserialize the decripted part 
	bool deserialize_encrypted_part(uint8_t* plaintext){
		int pointer_counter = 0;
		
		// length copies
        memcpy(&symmetric_key_param_len_server, plaintext, sizeof(symmetric_key_param_len_server));
		symmetric_key_param_len_server = ntohl(symmetric_key_param_len_server);
        pointer_counter += sizeof(symmetric_key_param_len_server);
		
		memcpy(&hmac_key_param_len_server, plaintext + pointer_counter, sizeof(hmac_key_param_len_server));
		hmac_key_param_len_server = ntohl(hmac_key_param_len_server);
        pointer_counter += sizeof(hmac_key_param_len_server);
		
		memcpy(&symmetric_key_param_len_client, plaintext + pointer_counter, sizeof(symmetric_key_param_len_client));
		symmetric_key_param_len_client = ntohl(symmetric_key_param_len_client);
        pointer_counter += sizeof(symmetric_key_param_len_client);
		
		memcpy(&hmac_key_param_len_client, plaintext + pointer_counter, sizeof(hmac_key_param_len_client));
		hmac_key_param_len_client = ntohl(hmac_key_param_len_client);
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

/*********************************************************************************************************************************/

#define BOOTSTRAP_UPLOAD 5
struct bootstrap_upload
{
    // Send through the net
    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    // Filled before serialization and after deserialization_decrypted
    uint16_t code;
    uint32_t filename_len;
    string filename;
    uint32_t response; // 1: upload allowed  0: upload not allowed
    uint32_t counter;
    uint32_t size;

    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (sizeof(cipher_len) + cipher_len + IV_LENGTH + HMAC_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint32_t certif_ciph_len = htonl(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }

    bool deserialize_message(uint8_t *serialized_pkt)
    {
        int pointer_counter = 0;

        iv = (unsigned char*)malloc(IV_LENGTH);

        // copy of the iv
        memcpy(iv,serialized_pkt + pointer_counter,IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // copy of the ciphertext
        ciphertext.assign((char *)(serialized_pkt + pointer_counter), cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);

        // copy of the ciphertext
        memcpy(HMAC,serialized_pkt + pointer_counter,HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    bool deserialize_plaintext(uint8_t *serialized_decrypted_pkt){

        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";
        unsigned int pos;
        //Extract the code
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
            if(code!=BOOTSTRAP_UPLOAD){
                return false;
            }
            s.erase(0, pos + delimiter.length());
        }
        //Extract the filename length
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            filename_len = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the filename
        pos = s.find(delimiter);
        if(pos!=string::npos){
            filename = s.substr(0, pos);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the counter
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            counter = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the size
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            filename_len = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        free(serialized_decrypted_pkt);
        return true;
    }

};

/*********************************************************************************************************************************/

#define FILE_UPLOAD 6
struct file_upload
{
    //In clear fields
    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    //Encrypted, set during deserialization of the plaintext
    uint8_t code;
    uint32_t counter;
    uint32_t msg_len;
    unsigned char *msg;

    void* serialize_message(int& len){
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (sizeof(cipher_len) + cipher_len + HMAC_LENGTH + IV_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint32_t certif_ciph_len = htonl(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }

    bool deserialize_message(uint8_t *serialized_pkt){
        int pointer_counter = 0;

        iv = (unsigned char*)malloc(IV_LENGTH);

        // copy of the iv
        memcpy(iv,serialized_pkt + pointer_counter,IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // copy of the ciphertext
        ciphertext.assign((char *)(serialized_pkt + pointer_counter), cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);

        // copy of the ciphertext
        memcpy(HMAC,serialized_pkt + pointer_counter,HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    bool deserialize_plaintext(uint8_t *serialized_decrypted_pkt){
        unsigned int pos;
        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";

        // Extract the CODE
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
            if(code!=FILE_UPLOAD){
                return false;
            }
            s.erase(0, pos + delimiter.length());
        }
        // Extract the counter
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            counter = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the msg_len
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            msg_len = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the msg
        pos = s.find(delimiter);
        if(pos!=string::npos){
            msg = (unsigned char*)s.substr(0, pos).c_str();
            s.erase(0, pos + delimiter.length());
        }

        free(serialized_decrypted_pkt);
        return true;
    }
};

/*********************************************************************************************************************************/

#define FILE_EOF_HS 7
struct end_upload{
    // Sent through the net
    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    //Set during decryption
    uint16_t code;
    string response;
    uint32_t counter;

    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (sizeof(cipher_len) + cipher_len + HMAC_LENGTH + IV_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint32_t certif_ciph_len = htonl(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;        

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }

    bool deserialize_message(uint8_t *serialized_pkt)
    {
        int pointer_counter = 0;

        iv = (unsigned char*)malloc(IV_LENGTH);

        // copy of the iv
        memcpy(iv,serialized_pkt + pointer_counter,IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // copy of the ciphertext
        ciphertext.assign((char *)(serialized_pkt + pointer_counter), cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);

        // copy of the ciphertext
        memcpy(HMAC,serialized_pkt + pointer_counter,HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    bool deserialize_plaintext(uint8_t *serialized_decrypted_pkt){
        unsigned int pos;
        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";

        // Extract the CODE
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
            if(code!=FILE_EOF_HS){
                return false;
            }
            s.erase(0, pos + delimiter.length());
        }
        // Extract the response
        pos = s.find(delimiter);
        if(pos!=string::npos){
            response = s.substr(0, pos);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the counter
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            counter = stoi(i);
            s.erase(0, pos + delimiter.length());
        }

        free(serialized_decrypted_pkt);
        return true;
    }

};

/*********************************************************************************************************************************/

#define BOOTSTRAP_DOWNLOAD 8
struct bootstrap_download
{
    // fields to send
    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    // ciphertext fields
    uint16_t code;
    uint16_t filename_len;
    string filename;
    uint32_t counter;

    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (strlen(ciphertext.c_str()) + IV_LENGTH + sizeof(cipher_len) + HMAC_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint16_t certif_ciph_len = htons(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }

    void deserialize_message(uint8_t *serialized_pkt)
    {
        int pointer_counter = 0;

        // copy of the code
        memcpy(&code, serialized_pkt, sizeof(code));
        code = ntohs(code);
        pointer_counter += sizeof(code);

        // copy filename_len
        memcpy(&filename_len, serialized_pkt + pointer_counter, sizeof(filename_len));
        filename_len = ntohs(filename_len);
        pointer_counter += sizeof(filename_len);

        // copy of the filename
        filename.assign((char *)(serialized_pkt + pointer_counter), filename_len);
        pointer_counter += filename_len;

        // copy of the counter
        memcpy(&counter, serialized_pkt + pointer_counter, sizeof(counter));
        counter = ntohl(counter);
        pointer_counter += sizeof(counter);

        free(serialized_pkt);
        return;
    }

    bool deserialize_plaintext(uint8_t *serialized_decrypted_pkt){

        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";
        unsigned int pos;
        //Extract the code
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
            if(code!=BOOTSTRAP_DOWNLOAD){
                return false;
            }
            s.erase(0, pos + delimiter.length());
        }
        //Extract the filename length
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            filename_len = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the filename
        pos = s.find(delimiter);
        if(pos!=string::npos){
            filename = s.substr(0, pos);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the counter
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            counter = stoi(i);
            s.erase(0, pos + delimiter.length());
        }

        free(serialized_decrypted_pkt);
        return true;
    }
};

/*********************************************************************************************************************************/

#define FILE_DOWNLOAD 9
struct file_download
{
    //In clear fields
    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    //Encrypted, set during deserialization of the plaintext
    uint8_t code;
    uint32_t counter;
    uint32_t msg_len;
    unsigned char *msg;

    void* serialize_message(int& len){
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (sizeof(cipher_len) + cipher_len + HMAC_LENGTH + IV_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint32_t certif_ciph_len = htonl(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;        

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }

    bool deserialize_message(uint8_t *serialized_pkt){
        int pointer_counter = 0;

        iv = (unsigned char*)malloc(IV_LENGTH);

        // copy of the iv
        memcpy(iv,serialized_pkt + pointer_counter,IV_LENGTH);
        pointer_counter += IV_LENGTH;

        // copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // copy of the ciphertext
        ciphertext.assign((char *)(serialized_pkt + pointer_counter), cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);

        // copy of the ciphertext
        memcpy(HMAC,serialized_pkt + pointer_counter,HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    bool deserialize_plaintext(uint8_t *serialized_decrypted_pkt){
        unsigned int pos;
        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";

        // Extract the CODE
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
            if(code!=FILE_DOWNLOAD){
                return false;
            }
            s.erase(0, pos + delimiter.length());
        }
        // Extract the counter
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            counter = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the msg_len
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            msg_len = stoi(i);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the msg
        pos = s.find(delimiter);
        if(pos!=string::npos){
            msg = (unsigned char*)s.substr(0, pos).c_str();
            s.erase(0, pos + delimiter.length());
        }

        free(serialized_decrypted_pkt);
        return true;
    }
};

/*********************************************************************************************************************************/

#define FILE_DL_HS 10
struct end_download{
    // Sent through the net
    unsigned char* iv;
    uint32_t cipher_len;
    string ciphertext;
    unsigned char* HMAC;

    //Set during decryption
    uint16_t code;
    string response;
    uint32_t counter;

    void *serialize_message(int &len)
    {
        uint8_t *serialized_pkt = nullptr;
        int pointer_counter = 0;

        len = (sizeof(cipher_len) + cipher_len + HMAC_LENGTH + IV_LENGTH);

        serialized_pkt = (uint8_t *)malloc(len);
        if (!serialized_pkt)
        {
            cerr << "serialized packet malloc failed" << endl;
            return nullptr;
        }

        uint32_t certif_ciph_len = htonl(cipher_len);

        // adding the iv
        uint8_t *cert_iv = (uint8_t *)iv;
        memcpy(serialized_pkt + pointer_counter, cert_iv, IV_LENGTH);
        pointer_counter += IV_LENGTH;        

        // adding the ciphertext length
        memcpy(serialized_pkt + pointer_counter, &certif_ciph_len, sizeof(certif_ciph_len));
        pointer_counter += sizeof(certif_ciph_len);

        // adding the ciphertext
        uint8_t *cert_ciph = (uint8_t *)ciphertext.c_str();
        memcpy(serialized_pkt + pointer_counter, cert_ciph, cipher_len);
        pointer_counter += cipher_len;

        // adding the hmac
        uint8_t *cert_hmac = (uint8_t *)HMAC;
        memcpy(serialized_pkt + pointer_counter, cert_hmac, HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        return serialized_pkt;
    }

    bool deserialize_message(uint8_t *serialized_pkt)
    {
        int pointer_counter = 0;

        iv = (unsigned char*)malloc(IV_LENGTH);

        // copy of the iv
        memcpy(iv,serialized_pkt + pointer_counter,IV_LENGTH);
        pointer_counter += IV_LENGTH;        

        // copy of the ciphertext length
        memcpy(&cipher_len, serialized_pkt + pointer_counter, sizeof(cipher_len));
        cipher_len = ntohl(cipher_len);
        pointer_counter += sizeof(cipher_len);

        // copy of the ciphertext
        ciphertext.assign((char *)(serialized_pkt + pointer_counter), cipher_len);
        pointer_counter += cipher_len;

        HMAC = (unsigned char *)malloc(HMAC_LENGTH);

        // copy of the ciphertext
        memcpy(HMAC,serialized_pkt + pointer_counter,HMAC_LENGTH);
        pointer_counter += HMAC_LENGTH;

        free(serialized_pkt);

        return true;
    }

    bool deserialize_plaintext(uint8_t *serialized_decrypted_pkt){
        unsigned int pos;
        string s = (char*)serialized_decrypted_pkt;
        string delimiter = "$";

        // Extract the CODE
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            code = stoi(i);
            if(code!=FILE_DL_HS){
                return false;
            }
            s.erase(0, pos + delimiter.length());
        }
        // Extract the response
        pos = s.find(delimiter);
        if(pos!=string::npos){
            response = s.substr(0, pos);
            s.erase(0, pos + delimiter.length());
        }
        // Extract the counter
        pos = s.find(delimiter);
        if(pos!=string::npos){
            string i = s.substr(0, pos);
            counter = stoi(i);
            s.erase(0, pos + delimiter.length());
        }

        free(serialized_decrypted_pkt);
        return true;
    }

};

/*********************************************************************************************************************************/
