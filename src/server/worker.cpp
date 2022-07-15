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

// receive message from socket
// MAYBE DEFINE A RECV_BUFFER IN CLASS
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
			cerr << "[Thread " << this_thread::get_id() << "] get_server_certificate: "
			<< "cannot open file " << filename_certificate << endl;
			throw 0;
		}

		cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
		if (!cert) {
			cerr << "[Thread " << this_thread::get_id() << "] get_server_certificate: "
			<< "cannot read X509 certificate " << endl;
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
int Worker::send_login_server_authentication(login_authentication_pkt& pkt, login_bootstrap_pkt bootstrap_pkt){
	// initialize to 0 the pack
    memset(&pkt, 0, sizeof(pkt));
	
	pkt.code = LOGIN_AUTHENTICATION;
	
	// load server certificate
	pkt.cert = get_certificate();
	
	if (pkt.cert == nullptr){
		return -1;
	}
	
	// sign
	
	// encrypt, also set the iv field
	
}

// init session with client, the worker act as slave
bool Worker::init_session(){
	unsigned char* receive_buffer;
    uint32_t len;
	login_bootstrap_pkt bootstrap_pkt;
	login_authentication_pkt server_auth_pkt;
	unsigned char* symmetric_key_no_hashed;
	unsigned char* hmac_key_no_hashed;
	int ret;
	
	// receive bootstrap_pkt
	while (true){
		
		// receive message
		if (receive_message(receive_buffer, len) < 0){
			cerr << "ERR: some error in receiving login_bootstrap_pkt" << endl;
			free(receive_buffer);
			continue;
		}
		
		// check if it is consistent with server_auth_pkt
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
		
		// correct packet
		free(receive_buffer);
		break;
	}
	
	// generate dh keys
	server_auth_pkt.symmetric_key_param_server = generate_sts_key_param();
	
	if (server_auth_pkt.symmetric_key_param_server == nullptr){
		return -1;
	}
	
	server_auth_pkt.hmac_key_param_server = generate_sts_key_param();
	
	if (server_auth_pkt.hmac_key_param_server == nullptr){
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
	send_login_server_authentication(server_auth_pkt, bootstrap_pkt);
	
	// free dh params on the struct
}


void Worker::run (){
	unsigned char* recv_buffer;
	uint32_t len;
	
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
