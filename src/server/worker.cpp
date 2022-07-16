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

int Worker::cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& iv, unsigned char*& ciphertext, 
int& cipherlen){
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

        // context definition
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "context definition failed" << endl;
            throw 2;
        }

        //iv generation
        if (!generate_iv(EVP_aes_128_cbc())){
            cerr << "failed to generate iv" << endl;
            throw 3;
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
int Worker::cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char* iv, unsigned char*& plaintext, int& plainlen){
	int outlen;
    int ret;

    EVP_CIPHER_CTX* ctx;
	
    if (cipherlen == 0 || cipherlen > FILE_FRAGMENTS_SIZE) {
        cerr << "ERR: input cipher len not allowed" << endl;
        return -1;
    }
	
	//error if iv is not set
    if (!iv){
        cerr << "ERR: missing iv for decryption" << endl;
        return -1;
    }

    try {
         // buffer for the plaintext
        plaintext = (unsigned char*)malloc(cipherlen+1);
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

        // make plaintext printable
        plaintext[plainlen] = '\0';

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
        for (int i = 0; i<iv_len; i++){
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

// read server certificate, returns null on failure
X509* Worker::get_certificate() {
	
	FILE* file = nullptr;
	X509* cert = nullptr;

	try {
		file = fopen(filename_certificate.c_str(), "r");
		if (!file) {
			cerr << "cannot find server cetificate" << endl;
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

bool Worker::check_username(string username){
	
	// IMPLEMENT
	
	return true;
}

// send the server authentication packet
int Worker::send_login_server_authentication(login_authentication_pkt& pkt){
	unsigned char* part_to_encrypt;
	int pte_len;
	int final_pkt_len;
	unsigned int signature_len;
	unsigned char* signature;
	unsigned char* iv;
	unsigned char* ciphertext;
	unsigned char* final_pkt;
	int cipherlen;
	int ret;
	
	pkt.code = LOGIN_AUTHENTICATION;
	
	// load server certificate
	pkt.cert = get_certificate();
	
	if (pkt.cert == nullptr){
		cerr << "cannot load certificate" << endl;
		return -1;
	}
	
	part_to_encrypt = (unsigned char*) pkt.serialize_part_to_encrypt(pte_len);
	
	cout << "regolare" << endl;
	
	if (part_to_encrypt == nullptr){
		cerr << "error in serialize part to encrypt" << endl;
		return -1;
	}
	
	// sign
	signature = sign_message(private_key, part_to_encrypt, pte_len, signature_len);
	if (signature == nullptr){
		cerr << "cannot generate valid signature" << endl;
		return -1;
	}
	
	cout << pte_len << endl;
	cout << "regolare2" << endl;
	cout << signature_len << endl;

	// encrypt, also set the iv field
	ret = cbc_encrypt_fragment(signature, signature_len, iv, ciphertext, cipherlen);
	if (ret != 0){
		cerr << "cannot generate valid ciphertext" << endl;
		return -1;
	}
	
	cout << "regolare3" << endl;
	pkt.iv_cbc = iv;
	pkt.encrypted_signing = ciphertext;
	pkt.encrypted_signing_len = cipherlen;
	
	/*cout << "fields" << endl;
	printf ("iv: %s \n", (char*) pkt.iv_cbc);
	printf("encryption: %s \n + %d", (char* ) pkt.encrypted_signing, pkt.encrypted_signing_len);*/
	cout << "cert:";
	BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
	X509_print_ex(bp, pkt.cert, 1, NULL);
	BIO_free(bp);
	cout << endl;
	
	
	final_pkt = (unsigned char*) pkt.serialize_message(final_pkt_len);
	
	cout << "regolare4" << endl;
	
	if (!send_message(final_pkt, final_pkt_len)){
		cerr << "message cannot be sent" << endl;
		return -1;
	}
	
	cout << "regolare5" << endl;
	
	return 0;
}

// init session with client, the worker act as slave
bool Worker::init_session(){
	unsigned char* receive_buffer;
    uint32_t len;
	login_bootstrap_pkt bootstrap_pkt;
	login_authentication_pkt server_auth_pkt;
	login_authentication_pkt client_auth_pkt;
	unsigned char* symmetric_key_no_hashed;
	unsigned char* hmac_key_no_hashed;
	int ret;
	
	memset(&bootstrap_pkt, 0, sizeof(bootstrap_pkt));
	memset(&server_auth_pkt, 0, sizeof(server_auth_pkt));
	memset(&client_auth_pkt, 0, sizeof(client_auth_pkt));
	
	// receive bootstrap_pkt
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
			continue;
		}
		
		// check username (WE NEED A READ THAT IS THREAD SAFE)
		if (!check_username(bootstrap_pkt.username)){
			cerr << "ERR: username "+bootstrap_pkt.username+ " is not registered" << endl;
			free(receive_buffer);
			continue;
		}
		
		// check if key params are valid
		if (bootstrap_pkt.symmetric_key_param == nullptr || bootstrap_pkt.hmac_key_param == nullptr){
			cerr << "ERR: one of the key params is not valid" << endl;
			free(receive_buffer);
			continue;
		}
		
		cout << "FIRST OK" << endl;
		
		// correct packet
		free(receive_buffer);
		break;
	}
	
	// generate dh keys
	server_auth_pkt.symmetric_key_param_server = generate_sts_key_param();
	
	if (server_auth_pkt.symmetric_key_param_server == nullptr){
		cerr << "ERR: failed to generate session keys parameters" << endl;
		return -1;
	}
	
	server_auth_pkt.hmac_key_param_server = generate_sts_key_param();
	
	if (server_auth_pkt.hmac_key_param_server == nullptr){
		cerr << "ERR: failed to generate session keys parameters" << endl;
		return -1;
	}
	
	// set the params sent by client
	server_auth_pkt.symmetric_key_param_client = bootstrap_pkt.symmetric_key_param;
	server_auth_pkt.hmac_key_param_client = bootstrap_pkt.hmac_key_param;

	
	// derive key using login_bootstrap_pkt.symmetric_key_param and hmac one
	
	// symmetric_key_no_hashed = // IMPLEMENT
	
	// hmac_key_no_hashed = // IMPLEMENT
	
	// hash the keys
	/*ret = hash_symmetric_key(symmetric_key, symmetric_key_no_hashed);
	
	if (ret != 0){
		return ret;
	}
	
	ret = hash_hmac_key(hmac_key, hmac_key_no_hashed);
	
	if (ret != 0){
		return ret;
	}*/
	
	// encrypt and send login_server_authentication_pkt (also generate iv)
	send_login_server_authentication(server_auth_pkt);
	
	// free dh params on the struct
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
