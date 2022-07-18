#include "server.h"
#include "./../common/hashing/hashing_util.h"
#include "./../common/utility.h"

Worker::Worker (Server* server, const int socket, const sockaddr_in addr){
    server = server;
    socket_fd = socket;
    client_addr = addr;
}

Worker::~Worker(){
    // if keys are nullptr frees do nothing
    EVP_PKEY_free(private_key);
    //free(symmetric_key); //for testing leave this comment when symmetric_key is a constant
    free(hmac_key);      
    free(iv);
}

// generate HMAC digest of a fragment (FILE_FRAGMENTS_SIZE)
int Worker::generate_HMAC(unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen){
	
	// hmac_util.cpp
	return generate_SHA256_HMAC(msg, msg_len, digest, digestlen, hmac_key, FILE_FRAGMENTS_SIZE);

}


// to test serialization
/*void debug_serialize_pkt(uint8_t* buffer){
    login_bootstrap_pkt pkt;
    pkt.deserialize_message((uint8_t*) buffer);
    exit(EXIT_FAILURE);
}*/

// send a message through socket 
bool Worker::send_message(void* msg, const uint32_t len){
    
    ssize_t ret;
    uint32_t certified_len = htonl(len);

    // send message length
    ret = send (socket_fd, &certified_len, sizeof(certified_len), 0);

    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0){
        cerr << "Error: message length not sent" << endl;
        return false;
    }
    
    // send message
    ret = send (socket_fd, msg, len, 0);

    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0){
        cerr << "Error: message not sent" << endl;
        return false;
    }

    return true;
}

// receive message from socket
int Worker::receive_message(unsigned char*& recv_buffer, uint32_t& len){ //EDIT: MAYBE ADD CHECK ON THE MAXIMUM LENGHT OF A FRAGMENT: 4096
    ssize_t ret;

    // receive message length
    ret = recv(socket_fd, &len, sizeof(uint32_t), 0);

    if (ret == 0){
        cerr << "ERR: client disconnected" << endl;
        return -2;
    }

    if (ret < 0 || (unsigned long)ret < sizeof(len)){
        cerr << "ERR: message length received is too short" << endl;
        return -1;
    }

    try{
        // allocate receive buffer
        len = ntohl(len);
        recv_buffer = (unsigned char*) malloc (len);

        if (DEBUG) {
            cout << "msg_len of received message is: " << len << endl;
        }


        if (!recv_buffer){
            cerr << "ERR: recv_buffer malloc fail" << endl;
            throw 1;
        }

        // receive message
        ret = recv(socket_fd, recv_buffer, len, 0);

        if (ret == 0){
            cerr << "ERR: client disconnected" << endl;
            throw 2;
        }

        if (ret < 0 || (unsigned long)ret < sizeof(len)){
            cerr << "ERR: message received is too short" << endl;
            throw 3;
        }
    }
    catch (int error_code){

        free(recv_buffer);

        if (error_code == 2){
            return -2;
        }
        else{
            return -1;
        }

    }

    return 0;
}

/**
 * @brief manage the receive and various general checks on the received packet
 *        MANAGE THE plaintxt destruction!
 * @return unsigned* the plaintext to deserialize inside the correct packet type
 */
unsigned char* Worker::receive_decrypt_and_verify_HMAC(){
    unsigned char* data;
    generic_message rcvd_pkt;
    uint32_t length_rec;
    
    //Receive the serialized data
    if(!receive_message(data, length_rec)){
        cerr << "ERR: some error in receiving MSG2 in upload" << endl;
		free(data);
		return nullptr;
    }

    if(!rcvd_pkt.deserialize_message(data)){
        cerr<<"Error during deserialization of the data"<<endl;
        return nullptr;
    }

    uint32_t MAC_len; 
    unsigned char*  MACStr = (unsigned char*)malloc(IV_LENGTH + rcvd_pkt.cipher_len);
    unsigned char* HMAC;
    MACStr = (unsigned char*)malloc(IV_LENGTH + rcvd_pkt.cipher_len);
    memcpy(MACStr,rcvd_pkt.iv, IV_LENGTH);
    memcpy(MACStr + 16,(void*)rcvd_pkt.ciphertext.c_str(),rcvd_pkt.cipher_len);

    //Generate the HMAC on the receiving side iv||ciphertext
    generate_HMAC(MACStr,IV_LENGTH + rcvd_pkt.cipher_len, HMAC,MAC_len);
    //Free
    free(MACStr);

    //HMAC Verification
    if(!verify_SHA256_MAC(HMAC,rcvd_pkt.HMAC)){
        cout<<"HMAC cant be verified, try again"<<endl;
        return nullptr;
    }

    unsigned char* plaintxt;
    int ptlen;

    //The IV get a free every time it gets generated again and at the end of execution during a class destruction
    this->iv = rcvd_pkt.iv;

    //Decrypt the ciphertext and obtain the plaintext
    if(cbc_decrypt_fragment((unsigned char* )rcvd_pkt.ciphertext.c_str(),rcvd_pkt.cipher_len,plaintxt,ptlen)!=0){
        cout<<"Error during encryption"<<endl;
        return nullptr;
    }

    free(HMAC);
    free(rcvd_pkt.HMAC);
    return plaintxt;
}

/**
 * @brief Encrypt the plaintext and fill a generic packet to send through the socket
 * 
 * @param buffer : plaintext to encrypt
 * @return true : the crypted msg has been sent successfully
 * @return false : error during packet preparation or during the send
 */
bool Worker::encrypt_generate_HMAC_and_send(string buffer){
	// Generic Packet
	generic_message pkt;

	unsigned char* ciphertext;
    int cipherlen;
	// Encryption
    if(cbc_encrypt_fragment((unsigned char*)buffer.c_str(), strlen(buffer.c_str()), ciphertext, cipherlen, true)!=0){
        cout<<"Error during encryption"<<endl;
        return false;
    }

	// Get the HMAC
    uint32_t MAC_len; 
    unsigned char*  MACStr = (unsigned char*)malloc(IV_LENGTH + cipherlen);
    unsigned char* HMAC;
    memcpy(MACStr,this->iv, IV_LENGTH);
    memcpy(MACStr + 16,ciphertext,cipherlen);

	//Initialization of the data to serialize
    pkt.ciphertext = (const char*)ciphertext;
    pkt.cipher_len = cipherlen;
    pkt.iv = this->iv;
    generate_HMAC(MACStr,IV_LENGTH + cipherlen, HMAC,MAC_len); 
    pkt.HMAC = HMAC;
    unsigned char* data;

    int data_length;
    data = (unsigned char*)pkt.serialize_message(data_length);

    //Send the first message
    if(!send_message((void *)data, data_length)){
        cout<<"Error during packet #1 forwarding"<<endl;
        free(MACStr);
        free(ciphertext);
		free(pkt.HMAC);
        return false;
    }

    free(MACStr);
    free(ciphertext);
    free(pkt.HMAC);
	return true;
}

int Worker::cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& ciphertext, int& cipherlen, bool _generate_iv){
	int outlen;
    int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    int ret;

    EVP_CIPHER_CTX* ctx;
	
	if (msg_len == 0 || msg_len > FILE_FRAGMENTS_SIZE) {
        cerr << "message length is not allowed" << endl;
        return -1;
    }
	
	try {
         // buffer for the ciphertext + padding
        ciphertext = (unsigned char*)malloc(msg_len + block_size);
		if (!ciphertext) {
			cerr << "malloc ciphertext failed" << endl;
			throw 1;
		}
		memset(ciphertext,0,msg_len + block_size);
        // context definition
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "context definition failed" << endl;
            throw 2;
        }
		
		// if variable is set then generate iv
		if (_generate_iv){
			//iv generation
			if (!generate_iv(EVP_aes_128_cbc())){
				cerr << "failed to generate iv" << endl;
				throw 3;
			} 
		}

        // init encryption
        ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), symmetric_key, iv);
		if (ret != 1) {
			cerr << "failed to initialize encryption" << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}

        outlen = 0;
        cipherlen = 0;

        // encrypt update on the message
        ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)msg, msg_len);

        if (ret != 1) {
                ERR_print_errors_fp(stderr);
                throw 5;
        }

        cipherlen += outlen;

        ret = EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);

		if (ret != 1) {
			ERR_print_errors_fp(stderr);
			throw 6;
		}

        // extra check on the cipherlen overflow
        if (cipherlen > numeric_limits<int>::max() - outlen) {
            cerr << "overflow error on cipherlen" << endl;
            throw 7;
        }

        cipherlen += outlen;

    }
    catch (int error_code) {

        free(ciphertext);

        if (error_code > 1){
            EVP_CIPHER_CTX_free(ctx);
        }

        if (error_code > 3){
            free(iv);
        }

        return -1;
    }

    return 0;
    
}

// function to decrypt fragments
// this function will set plaintext and plainlen arguments
int Worker::cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, int& plainlen){
	int outlen;
    int ret;

    EVP_CIPHER_CTX* ctx;
	
    if (cipherlen == 0 || cipherlen > FILE_FRAGMENTS_SIZE) {
        cerr << "ERR: input cipher len not allowed" << endl;
        return -1;
    }
	
	//error if iv is not set
    if (iv == nullptr){
        cerr << "ERR: missing iv for decryption" << endl;
        return -1;
    }

    try {
         // buffer for the plaintext
        plaintext = (unsigned char*)malloc(cipherlen);
		if (!plaintext) {
			cerr << "ERR: malloc plaintext failed" << endl;
			throw 1;
		}

        // context definition
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "ERR: context definition failed" << endl;
            throw 2;
        }

        // init encryption
        ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), symmetric_key, iv);
		if (ret != 1) {
			cerr << "ERR: failed to initialize decryption" << endl;
			ERR_print_errors_fp(stderr);
			throw 3;
		}

        outlen = 0;
        plainlen = 0;

        ret = EVP_DecryptUpdate(ctx, plaintext + outlen, &outlen, (unsigned char*)ciphertext+outlen, cipherlen);

        if (ret != 1) {
                cerr << "ERR: failed decrypt update" << endl;
                ERR_print_errors_fp(stderr);
                throw 4;
        }

        plainlen += outlen;

        ret = EVP_DecryptFinal(ctx, plaintext + outlen, &outlen);

		if (ret != 1) {
            cerr << "ERR: failed decrypt finalization" << endl;
			ERR_print_errors_fp(stderr);
			throw 5;
		}

        // extra check on the cipherlen overflow
        if (plainlen > numeric_limits<int>::max() - outlen) {
            cerr << "ERR: overflow error on plaintext length" << endl;
            throw 6;
        }

        plainlen += outlen;

    }
    catch (int error_code) {

        free(plaintext);

        if (error_code > 1){
            EVP_CIPHER_CTX_free(ctx);
        }

    }

    return 0;

}


bool Worker::load_private_server_key(){
	string dir = "./Server_key.pem";
    FILE* file = fopen(dir.c_str(), "r");

    if (!file){
        return false;
    }

    EVP_PKEY* privk = PEM_read_PrivateKey(file, NULL, NULL, NULL); //maybe "" as password?

    fclose(file);

    if (privk == NULL){
        return false;
    }

    private_key = privk;
    return true;
}

bool Worker::generate_iv (const EVP_CIPHER* cipher){
    int iv_len = EVP_CIPHER_iv_length(cipher);

    free(iv);
	iv = nullptr;
    iv = (unsigned char*) malloc(iv_len);

	if (!iv) {
		cerr << "ERR: failed to allocate iv" << endl;
        iv = nullptr;
		return false;
	}
	
	int ret = RAND_bytes(iv, iv_len);

	if (ret != 1) {
		ERR_print_errors_fp(stderr);

        // must free the iv
		free(iv);
        iv = nullptr;
		return false;
	}

    // DEBUG, print IV 
    if (DEBUG) {
        cout << "iv_len: " << iv_len << endl;
        cout << "iv: ";
        for (int i = 0; i < iv_len; i++){
            std::cout << static_cast<unsigned int>(iv[i]) << std::flush;
        }
        cout << endl;
    }

    return true;
}

// returns the generated key or null if an error occurs
EVP_PKEY* Worker::generate_sts_key_param(){
	
	// utility.cpp
	return generate_dh_key();
}



/**
 * this method checks that a user is registered in the 'application at the login
 * 
 * @param username of the user who is trying to login
 * 
 * @return true if the user is registered, and false otherwise 
 */
bool Worker::check_username(string username){
	
	ifstream file("users.txt");
    vector<string> users;
    string str;
    while (getline(file, str)) {
		int len = strlen(str.c_str()) - 1 ;
        str = str.substr(0,len);
        users.push_back(str);
    }

    for (string i: users){
        if(!username.compare(i)){
            return true;
        }
    }
	
    return false;
	
}

// send the server authentication packet
int Worker::send_login_server_authentication(login_authentication_pkt& pkt){
	unsigned char* part_to_encrypt;
	int pte_len;
	int final_pkt_len;
	unsigned int signature_len;
	unsigned char* signature;
	unsigned char* ciphertext;
	unsigned char* final_pkt;
	int cipherlen;
	int ret;
	
	// load server certificate
	pkt.cert = get_certificate();
	
	if (pkt.cert == nullptr){
		cerr << "cannot load certificate" << endl;
		return -1;
	}
	
	// serialize the part to encrypt
	part_to_encrypt = (unsigned char*) pkt.serialize_part_to_encrypt(pte_len);
	
	if (part_to_encrypt == nullptr){
		cerr << "error in serialize part to encrypt" << endl;
		return -1;
	}
	
	// sign it
	signature = sign_message(private_key, part_to_encrypt, pte_len, signature_len);
	if (signature == nullptr){
		cerr << "cannot generate valid signature" << endl;
		return -1;
	}

	// encrypt, also set the iv field
	ret = cbc_encrypt_fragment(signature, signature_len, ciphertext, cipherlen, true);
	if (ret != 0){
		cerr << "cannot generate valid ciphertext" << endl;
		return -1;
	}
	
	pkt.iv_cbc = iv;
	pkt.encrypted_signing = ciphertext;
	pkt.encrypted_signing_len = cipherlen;
	
	// final serialization
	final_pkt = (unsigned char*) pkt.serialize_message(final_pkt_len);
	
	if (!send_message(final_pkt, final_pkt_len)){
		cerr << "message cannot be sent" << endl;
		return -1;
	}
	
	return 0;
}

// init session with client, the worker act as slave
bool Worker::init_session(){
	int ret;
	login_bootstrap_pkt bootstrap_pkt;
	login_authentication_pkt server_auth_pkt;
	login_authentication_pkt client_auth_pkt;
	unsigned char* symmetric_key_no_hashed;
	unsigned char* hmac_key_no_hashed;
	unsigned char* plaintext;
	int plainlen;
	unsigned char* signed_text;
	int signed_text_len;
	EVP_PKEY* client_pubk;
	X509* ca_cert;
	X509_CRL* ca_crl;
	
	memset(&bootstrap_pkt, 0, sizeof(bootstrap_pkt));
	memset(&server_auth_pkt, 0, sizeof(server_auth_pkt));
	memset(&client_auth_pkt, 0, sizeof(client_auth_pkt));
	
	// receive buffer
	unsigned char* receive_buffer;
    uint32_t len;
	
	// receive bootstrap_pkt from client
	while (true){
		
		// receive message
		if (receive_message(receive_buffer, len) < 0){
			cerr << "ERR: some error in receiving login_bootstrap_pkt" << endl;
			free(receive_buffer);
			continue;
		}
		
		// deserialize bootstrap pkt
		if (!bootstrap_pkt.deserialize_message(receive_buffer)){
			cerr << "ERR: some error in deserialize login_bootstrap_pkt" << endl;
			free(receive_buffer);
			bootstrap_pkt.free_pointers();
			continue;
		}
		
		// check username 
		if (!check_username(bootstrap_pkt.username)){
			cerr << "ERR: username "+bootstrap_pkt.username+ " is not registered" << endl;
			free(receive_buffer);
			bootstrap_pkt.free_pointers();
			return false;
		}
		
		// check if key params are valid
		if (bootstrap_pkt.symmetric_key_param == nullptr || bootstrap_pkt.hmac_key_param == nullptr){
			cerr << "ERR: one of the key params is not valid" << endl;
			free(receive_buffer);
			bootstrap_pkt.free_pointers();
			continue;
		}
		
		// correct packet
		free(receive_buffer);
		break;
	}
	
	// generate dh keys
	server_auth_pkt.symmetric_key_param_server_clear = generate_sts_key_param();
	server_auth_pkt.symmetric_key_param_server = server_auth_pkt.symmetric_key_param_server_clear; // TO ENCRYPT
	
	if (server_auth_pkt.symmetric_key_param_server == nullptr){
		cerr << "ERR: failed to generate session keys parameters" << endl;
		return false;
	}
	
	EVP_PKEY_up_ref(server_auth_pkt.symmetric_key_param_server_clear);
	
	server_auth_pkt.hmac_key_param_server_clear = generate_sts_key_param();
	server_auth_pkt.hmac_key_param_server = server_auth_pkt.hmac_key_param_server_clear; // TO ENCRYPT
	
	if (server_auth_pkt.hmac_key_param_server == nullptr){
		cerr << "ERR: failed to generate session keys parameters" << endl;
		return false;
	}
	
	EVP_PKEY_up_ref(server_auth_pkt.hmac_key_param_server_clear);
	
	// set the params sent by client
	server_auth_pkt.symmetric_key_param_client = bootstrap_pkt.symmetric_key_param;
	EVP_PKEY_up_ref(bootstrap_pkt.symmetric_key_param);
	
	server_auth_pkt.hmac_key_param_client = bootstrap_pkt.hmac_key_param;
	EVP_PKEY_up_ref(bootstrap_pkt.hmac_key_param);
	
	// derive symmetric key and hmac key, hash them, take a portion of the hash for the 128 bit key
	symmetric_key_no_hashed = derive_shared_secret(server_auth_pkt.symmetric_key_param_server, bootstrap_pkt.symmetric_key_param);
	
	if (!symmetric_key_no_hashed){
		cerr << "failed to derive symmetric key" << endl;
		return false;
	}
	ret = hash_symmetric_key(symmetric_key, symmetric_key_no_hashed);
	
	if (ret != 0){
		cerr << "failed to hash symmetric key" << endl;
		return false;
	}
	
	hmac_key_no_hashed = derive_shared_secret(server_auth_pkt.hmac_key_param_server, bootstrap_pkt.hmac_key_param);
	
	if (!hmac_key_no_hashed){
		cerr << "failed to derive hmac key" << endl;
		return false;
	}
	ret = hash_hmac_key(hmac_key, hmac_key_no_hashed);
	
	if (ret != 0){
		cerr << "failed to hash hmac key" << endl;
		return false;
	}
	
	// clean no hashed keys
	secure_free(symmetric_key_no_hashed, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	secure_free(hmac_key_no_hashed, HMAC_KEY_SIZE);
	
	// encrypt and send login_server_authentication_pkt (also generate iv)
	if (send_login_server_authentication(server_auth_pkt) != 0){
		return false;
	}
	
	// receive client authentication pkt
	while (true){
		try{
			// receive message
			if (receive_message(receive_buffer, len) < 0){
				cerr << "ERR: some error in receiving login_server_authentication_pkt" << endl;
				throw 1;
			}
			
			// check if it is consistent with server_auth_pkt
			if (!client_auth_pkt.deserialize_message_no_clear_keys(receive_buffer)){
				cerr << "ERR: some error in deserialize client_auth_pkt" << endl;
				throw 2;
			}
			
			// decrypt the encrypted part using the derived symmetric key and the received iv
			free(iv);
			iv = (unsigned char*) malloc(iv_size);
			
			if(!iv){
				cerr << "failed malloc for iv in init_session" << endl;
				throw 3;
			}
			
			memcpy(iv, client_auth_pkt.iv_cbc, iv_size);

			ret = cbc_decrypt_fragment(client_auth_pkt.encrypted_signing, client_auth_pkt.encrypted_signing_len, plaintext, plainlen);
			
			if (ret != 0){
				cerr << "error in decrypting server authentication packet" << endl;
				throw 4;
			}
			
			// get CA certificate and its crl
			
			ca_cert = get_CA_certificate();
			
			if (ca_cert == nullptr){
				throw 5;
			}
			
			ca_crl = get_crl();
			
			if (ca_crl == nullptr){
				throw 6;
			}
			
			// validate client's certificate
			ret = validate_certificate(ca_cert, ca_crl, client_auth_pkt.cert);
			if (ret != 0){
				throw 7;
			}
			
			// extract client public key
			client_pubk = X509_get_pubkey(client_auth_pkt.cert);
			
			if (client_pubk == nullptr){
				cerr << "failed to extract client public key" << endl;
				throw 8;
			}
			
			// cleartext to verify signature: <lengths|server_serialized_params|client_serialized_params>
			// the signature is on the serialized version of the dh keys

			// re-serialize the dh keys and verify the signature
			
			// SET THE FIELDS RECEIVED ON BOOTSTRAP
			client_auth_pkt.symmetric_key_param_client = bootstrap_pkt.symmetric_key_param;
			EVP_PKEY_up_ref(bootstrap_pkt.symmetric_key_param);
			client_auth_pkt.symmetric_key_param_len_client = bootstrap_pkt.symmetric_key_param_len;
			
			client_auth_pkt.hmac_key_param_client = bootstrap_pkt.hmac_key_param;
			EVP_PKEY_up_ref(bootstrap_pkt.hmac_key_param);
			client_auth_pkt.hmac_key_param_len_client = bootstrap_pkt.hmac_key_param_len;
			
			// SET THE FIELDS THAT WE HAVE GENERATED BEFORE
			client_auth_pkt.symmetric_key_param_server = server_auth_pkt.symmetric_key_param_server_clear;
			EVP_PKEY_up_ref(server_auth_pkt.symmetric_key_param_server_clear);
			client_auth_pkt.symmetric_key_param_len_server = client_auth_pkt.symmetric_key_param_server_clear_len;
			
			client_auth_pkt.hmac_key_param_server = server_auth_pkt.hmac_key_param_server_clear;
			EVP_PKEY_up_ref(server_auth_pkt.hmac_key_param_server_clear);
			client_auth_pkt.hmac_key_param_len_server = server_auth_pkt.hmac_key_param_server_clear_len;
			
			// this will serialize as the client did
			unsigned char* to_copy = (unsigned char*) client_auth_pkt.serialize_part_to_encrypt(signed_text_len);
			signed_text = (unsigned char*) malloc(signed_text_len);
			
			if(!signed_text){
				cerr << "error in signed_text malloc" << endl;
				throw 9;
			}
			memcpy(signed_text, to_copy, signed_text_len);
			
			// verify the signature (freshness verification)
			ret = verify_signature(client_pubk, plaintext, plainlen, signed_text, signed_text_len);
			
			if (ret != 0){
				cerr << "error in signature verification" << endl;
				return false;
			}
			
			// frees
			free(signed_text);
			free(receive_buffer);
			X509_free(ca_cert);
			X509_CRL_free(ca_crl);
			EVP_PKEY_free(client_pubk);
			
		}catch (int error_code){
			
			if (error_code > 1) {free(receive_buffer);}
			if (error_code > 3) {free(iv); iv = nullptr;}
			if (error_code > 5) {X509_free(ca_cert);}
			if (error_code > 6) {X509_CRL_free(ca_crl);}
			if (error_code > 8) {EVP_PKEY_free(client_pubk);}
			if (error_code > 9) { free(signed_text); }
			
			// reset structures
			memset(&server_auth_pkt, 0, sizeof(server_auth_pkt));
			memset(&client_auth_pkt, 0, sizeof(client_auth_pkt));
		}
		
		break;
		
	}
	
	// user correctly authenticated
	logged_user = bootstrap_pkt.username;
	
	//free all 
	bootstrap_pkt.free_pointers();
	server_auth_pkt.free_pointers();
	client_auth_pkt.free_pointers();
	
	cout << "ok" << endl;
	
	return true;
}

// read server certificate, returns null on failure
X509* Worker::get_certificate() {
	
	FILE* file = nullptr;
	X509* cert = nullptr;

	try {
		file = fopen(filename_certificate.c_str(), "r");
		if (!file) {
			cerr << "cannot find server certificate" << endl;
			throw 0;
		}

		cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
		if (!cert) {
			cerr << "cannot read server certificate correctly" << endl;
			throw 1;
		}

	} catch (int e) {
		if (e >= 1) {
			fclose(file);
		}
		return nullptr;
	}

	fclose(file);
	return cert;
}

X509* Worker::get_CA_certificate (){
	// Open file which contains CA certificate
	FILE* file = fopen(filename_ca_certificate.c_str(), "r");
	if (!file) {
		cerr << "failed to open CA certificate file" << endl;
		return nullptr;
	}

	// Extract the certificate
	X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
	fclose(file);
	if (!cert) {
		cerr << "failed to read CA certificate file" << endl;
		return nullptr;
	}

	return cert;
}


X509_CRL* Worker::get_crl() {
	// Open the file which contains the CRL
	FILE* file = fopen(filename_ca_crl.c_str(), "r");
	if (!file) {
		cerr << "cannot open CA crl file" << endl;
		return nullptr;
	}

	// Extract the CRL
	X509_CRL* crl = PEM_read_X509_CRL(file, nullptr, nullptr, nullptr);
	fclose(file);
	if (!crl) {
		cerr << "cannot read pem file of CA crl file" << endl;
		return nullptr;
	}

	return crl;
}


void Worker::run (){
	unsigned char* recv_buffer;
	uint32_t len;
	
	// load private server key
	if (!load_private_server_key()){
		cerr << "load of private key failed" << endl;
		exit(EXIT_FAILURE);
	}
	
	// init session with client
	init_session();
    
    while(true){
		
		// wait for commands
        int ret = receive_message(recv_buffer, len);
		
		/* --ERROR HANDLES-- */

        // CLIENT DISCONNECTED
        if (ret == -2){
            exit(EXIT_FAILURE);
        }
		
		/* --ERROR HANDLES-- */
		
		// handle command
		handle_command(recv_buffer);

		// the content of the buffer is not needed anymore
		free(recv_buffer);
    }
}
