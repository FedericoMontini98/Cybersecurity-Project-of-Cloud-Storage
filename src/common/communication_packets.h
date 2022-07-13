
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
    uint16_t code = LOGIN_BOOTSTRAP;
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
    void deserialize_message(uint8_t* serialized_pkt){
        int pointer_counter = 0;

        // copy of the code
        memcpy (&code, serialized_pkt, sizeof(code));
        code = ntohs(code);
        pointer_counter += sizeof(code);

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

        /*
        BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
        EVP_PKEY_print_public(bp, symmetric_key_param, 1, NULL);
        BIO_free(bp);
        */
    }
};

struct upload_filename_exist {
    int code;
    string filename;
    bool response;      //True: upload allowed  False: upload not allowed
    uint32_t counter;
    
};

# define LOGIN_REFUSE_CONNECTION 2
// sent in clear
struct login_refuse_connection_pkt {
    uint16_t code;

    void serialize_message(){
        code= htons(code);
    }

    void deserialize_message(){
        code= ntohs(code);
    }
};

# define LOGIN_SERVER_AUTHENTICATION 3
// sent in clear
struct login_server_authentication_pkt {
    uint16_t code;

    void serialize_message(){
        code = htons(code);
    }

    void deserialize_message(){
        code = ntohs(code);
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

