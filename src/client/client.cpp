#include "./../common/errors.h"
#include <fstream>
#include <cstdint>
#include <vector>
#include "client.h"
#include "./../common/hashing/hashing_util.h"
#include "./../common/utility.h"
#include <sys/stat.h>
#include <sstream>
#include <math.h>

// CONSTRUCTOR
Client::Client(const uint16_t _port){
    port = _port;
}

// DESTRUCTOR
Client::~Client(){

    // if keys are nullptr frees do nothing
    EVP_PKEY_free(private_key);
    //free(symmetric_key); //for testing leave this comment when symmetric_key is a constant
    free(hmac_key);      
    free(iv);
}

// check if password is ok and extract the private key 
bool Client::extract_private_key(string _username, string password){
    string dir;

    if (username.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos)
    {
        std::cerr << "ERR: username check on whitelist fails"<<endl;
        return false;
    }

    // default dir for users
    dir = "./users/" + _username + "/" + _username + "_key.pem";
    FILE* file = fopen(dir.c_str(), "r");

    if (!file){
        return false;
    }

    EVP_PKEY* privk = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());

    fclose(file);

    if (privk == NULL){
        return false;
    }

    username = _username;
    private_key = privk;
    return true;
}

// send a message through socket
bool Client::send_message(void* msg, const uint32_t len){
    
    ssize_t ret;
    uint32_t certified_len = htonl(len);

    // send message length
    ret = send (session_socket, &certified_len, sizeof(certified_len), 0);

    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0){
        cerr << "Error: message length not sent" << endl;
        return false;
    }
    
    // send message
    ret = send (session_socket, msg, len, 0);

    // -1 error, if returns 0 no bytes are sent
    if (ret <= 0){
        cerr << "Error: message not sent" << endl;
        return false;
    }
	
    return true;
}

// receive a message from socket
// DO NOT HANDLE FREE
int Client::receive_message(unsigned char*& recv_buffer, uint32_t& len){ //EDIT: MAYBE ADD CHECK ON THE MAXIMUM LENGHT OF A FRAGMENT: 4096
    ssize_t ret;

    // receive message length
    ret = recv(session_socket, &len, sizeof(uint32_t), 0);

    if (ret == 0){
        cerr << "ERR: server disconnected" << endl;
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
        ret = recv(session_socket, recv_buffer, len, 0);

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

    if (DEBUG){
        recv_buffer[len] = '\0'; 
        printf("received message: %s\n", recv_buffer);
    }

    return 0;
}

/* DO NOT DELETE WILL BE USEFUL FOR FILES DOWNLOAD/UPLOAD
int Client::cbc_encrypt_msg (unsigned char* msg, int msg_len, unsigned char* iv, int iv_len, unsigned char*& ciphertext, 
int& cipherlen){
    int outlen;
    int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    int fragment_size;
    int number_of_fragments;
    int ret;

    EVP_CIPHER_CTX* ctx;

    if (msg_len == 0){
        return -1;
    }

    if (msg_len < block_size){
        fragment_size = msg_len;
        number_of_fragments = 1;
    }
    else{
        fragment_size = EVP_CIPHER_block_size(EVP_aes_128_cbc()); // fragments size equal to blocks size
        number_of_fragments = block_size / msg_len;
    }

    try{
        
        ciphertext = (unsigned char*)malloc(msg_len + block_size);
		if (!ciphertext) {
			cerr << "malloc ciphertext failed" << endl;
			throw MALLOC_FAIL;
		}

        // context definition
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "context definition failed";
            throw OPENSSL_FAIL;
        }

        // init encryption
        ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), session_key, iv);
		if (ret != 1) {
			cerr << "[Thread " << this_thread::get_id() << "] gcm_encrypt: "
			<< "EVP_EncryptInit returned " << ret << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}

        outlen = 0;
        cipherlen = 0;

        // Encrypt Updates
        for (int i = 0; i < number_of_fragments; i++){
            
            ret = EVP_EncryptUpdate(ctx, ciphertext + outlen, &outlen, (unsigned char*)msg+outlen, fragment_size);

            if (ret != 1){
                ERR_print_errors_fp(stderr);
                throw OPENSSL_FAIL;
            }

            // overflow check
            if ( cipherlen > numeric_limits<int>::max() - outlen){
                throw 4;
            }

            cipherlen = cipherlen == 0? outlen : cipherlen + outlen;
        }

        // Final update
        ret = EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);
		if (ret != 1) {
			ERR_print_errors_fp(stderr);
			throw 4;
		}
        // overflow check
		if ( cipherlen > numeric_limits<int>::max() - outlen ) {
			throw 4;
		}
		cipherlen += outlen;

    }
    catch (int err_code){

        if (error_code) {

        }
    }

    // buffer for the ciphertext + padding
    ciphertext = (unsigned char*)malloc(sizeof(msg) + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    // encryption
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), &session_key, NULL);
}*/

// generate a new iv for the specified cipher
// DO NOT HANDLE FREE
bool Client::generate_iv (const EVP_CIPHER* cipher){
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


// function to encrypt a fragment of a message, the maximum size of a fragment is set by the file fragments
// this function will set the iv, ciphertext and cipherlen arguments
// HANDLE FREE ONLY ON ERROR
int Client::cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& ciphertext, int& cipherlen, bool _generate_iv){
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
int Client::cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, int& plainlen){
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

/**
 * Function that send the specified file through chunks of specified max size
 * 
 * @param filename : name of the file to send
 * @param counter : current counter number
 * @return int : result of the operation
 */
int Client::send_encrypted_file (string filename, uint32_t& counter){
    unsigned char* buffer;
    // build a string that cointain the path of the file
    string path = FILE_PATH + this->username + "/Upload/" + filename;
    //open the file
    FILE* file = fopen(path.c_str(), "rb"); 
    // If !file the file cant be open or is not present inside the dir
    if (!file){
        return false;
    }
    struct stat buf;
    if (stat(path.c_str(),&buf)!=0){ //stat failed
        cout<<"Failed stat function: File doesn't exists in the Upload dir"<<endl;
        return 0;
    }

    //Calculate the number of chunks to send
    size_t num_chunk_to_send = ceil((float)buf.st_size/4096);
    if(DEBUG){
        cout << "Number of chunks: " << num_chunk_to_send << endl << endl;
    }

    buffer = (unsigned char*)malloc(FILE_FRAGMENTS_SIZE);
    if(!buffer){            
        cerr << "ERR: cannot allocate a buffer for the file fragment" << endl;
        return -1;
    }
    memset(buffer,0,FILE_FRAGMENTS_SIZE);
    int ret;
    //Start to send the chunks
    for(size_t i = 0; i < num_chunk_to_send; ++i){

        // read bytes from file, the pointer is automatically increased
        ret = fread(buffer, 1, FILE_FRAGMENTS_SIZE, file);
        if ( ferror(file) != 0 ){
            std::cerr << "ERR: file reading error occured" << endl;
            return -1;
        }
        //Declare a new packet & init its fields
        file_upload pkt;
        pkt.code = FILE_UPLOAD;
        pkt.counter = counter;
        pkt.msg_len = ret;
        pkt.msg = (unsigned char*)buffer;

        unsigned char* ciphertext;
        int cipherlen;

        string to_encrypt = to_string(pkt.code) + "$" + to_string(pkt.counter) + "$" + to_string(pkt.msg_len) + "$" + reinterpret_cast<char*>(pkt.msg);
        if(cbc_encrypt_fragment((unsigned char*)to_encrypt.c_str(), strlen(to_encrypt.c_str()) , ciphertext, cipherlen, true) != 0){
            cerr<<"Failed encryption during the file send"<<endl;
            return -1;
        }

        // Get the HMAC
        uint32_t MAC_len; 
        unsigned char*  MACStr = (unsigned char*)malloc(IV_LENGTH + cipherlen);
        unsigned char* HMAC;
        memcpy(MACStr,iv, IV_LENGTH);
        memcpy(MACStr + 16,ciphertext,cipherlen);

        pkt.ciphertext = (const char*)ciphertext;
        pkt.cipher_len = cipherlen;
        generate_HMAC(MACStr,IV_LENGTH + cipherlen, HMAC,MAC_len); 
        pkt.HMAC = HMAC;
        pkt.iv = this->iv;

        //Initialization of the data to serialize
        unsigned char* data;
        int data_length;

        data = (unsigned char*)pkt.serialize_message(data_length);

        //Send the first message
        if(!send_message((void *)data, data_length)){
            cout<<"Error during packet #1 forwarding"<<endl;
            free(MACStr);
            free(ciphertext);
            return -1;
        }


        free(MACStr);
        free(ciphertext);
        counter++;
        memset(buffer,0,FILE_FRAGMENTS_SIZE);
    }

    free(buffer);
    return 0;
}

// sent packet [username | sts_key_param | hmac_key_param]
//MISS CONTROLS AND FREES
int Client::send_login_bootstrap(login_bootstrap_pkt& pkt){
	unsigned char* send_buffer;
	int len;
	
    // initialize to 0 the pack
    memset(&pkt, 0, sizeof(pkt));
	
	// lens will be automatically set after sending
    pkt.code = LOGIN_BOOTSTRAP;
    pkt.username = username;
	
	// generate dh keys
    pkt.symmetric_key_param = generate_sts_key_param();
	
	if (pkt.symmetric_key_param == nullptr){
		cerr << "ERR: failed to generate session keys parameters" << endl;
        return false;
	}
	
    pkt.hmac_key_param = generate_sts_key_param();

    if (pkt.hmac_key_param == nullptr){
        cerr << "ERR: failed to generate session keys parameters" << endl;
        return false;
    }

	send_buffer = (unsigned char*) pkt.serialize_message(len);
	
	if (send_buffer == nullptr){
		cerr << "ERR: failed to serialize login bootstrap packet" << endl;
		return -1;
	}
	
    if (!send_message(send_buffer, len)){
        cerr << "ERR: failed to send login bootstrap packet" << endl;
        return -1;
    }

    // handle response

    // if all is ok save the 2 parameters on the class field

    return 0;
    
}

// generate HMAC digest of a fragment (FILE_FRAGMENTS_SIZE)
int Client::generate_HMAC(unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen){
	
	// hmac_util.cpp
	return generate_SHA256_HMAC(msg, msg_len, digest, digestlen, hmac_key, FILE_FRAGMENTS_SIZE);

}

// generate the sts key parameter, null if an error occurs
EVP_PKEY* Client::generate_sts_key_param(){
	
	// utility.cpp
	return generate_dh_key();
}


// initialize session socket
bool Client::init_socket(){
    // ipv4 + tcp
    session_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (session_socket < 0) {
		cerr << "Error: socket creation failed" << endl;
		return false;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
	server_addr.sin_port = htons(port);

	return true;
}

bool Client::init_session(){
    int ret;
	login_bootstrap_pkt bootstrap_pkt;
	login_authentication_pkt server_auth_pkt; 
	login_authentication_pkt client_auth_pkt;
	unsigned char* plaintext;
	int plainlen;
	
	// receive buffer
	unsigned char* receive_buffer;
    uint32_t len;
    
    // initialize socket
    if (!init_socket()){
        cerr << " Error: socket definition failed" << endl;
        return false;
    }

    // connect to server
    ret = connect(session_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		cerr << "Error: connection to server failed" << endl;
		return false;
	}
	
	cout << "Connection with server has been established correctly for socket id: " << session_socket << endl;

    // send login bootstrap packet
    if (send_login_bootstrap(bootstrap_pkt) < 0){
        cerr << "something goes wrong in sending login_bootstrap_pkt" << endl;
        return false;
    }
	
	// receive login_server_authentication_pkt
	while (true){
	
		// receive message
		if (receive_message(receive_buffer, len) < 0){
			cerr << "ERR: some error in receiving login_server_authentication_pkt" << endl;
			free(receive_buffer);
			continue;
		}
		
		// check if it is consistent with server_auth_pkt
		if (!server_auth_pkt.deserialize_message(receive_buffer)){
			cerr << "ERR: some error in deserialize server_auth_pkt" << endl;
			free(receive_buffer);
			continue;
		}
		
		// derive symmetric key using server_auth_pkt.symmetric_key_param_server_clear
		
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
		
		// decrypt the encrypted part using the derived symmetric key
		iv = server_auth_pkt.iv_cbc;
		// allocate
		cbc_decrypt_fragment(server_auth_pkt.encrypted_signing, server_auth_pkt.encrypted_signing_len, plaintext, plainlen);
		
		// extract the key from the server certificate
		
		// verify the signature
		
		// check freshness EVP_PKEY_parameters_eq()
		
		// correct packet
		free(receive_buffer);
		break;
	}
	
	// free dh parameters
	EVP_PKEY_free(bootstrap_pkt.symmetric_key_param);
	EVP_PKEY_free(bootstrap_pkt.hmac_key_param);

    return true;
}

/**
 * Check the existance of the file inside the upload directory
 * 
 * @param filename : file name to check
 * @param username : user that what to upload
 * @return uint32_t : 0 -> wrong >0 -> correct result
 */
uint32_t Client::file_exists(string filename, string username){
    string path = FILE_PATH + username + "/Upload/" + filename;
    struct stat buffer;
    if (stat(path.c_str(),&buffer)!=0){ //stat failed
        cout<<"Failed stat function: File doesn't exists in the Upload dir"<<endl;
        return 0;
    }
    if( buffer.st_size - 4294967296 > 0){   //4294967296 Bytes = 4GiB
        cout<< "File too big" << endl;
        return 0;
    }
    //The file exists and has a size which is less then 4Gib
    return buffer.st_size;
}

/**Check the existance of the file inside the download directory
 *  @filename : file of which we have to check the existance
 *  @username : needed to find the current user directory 
 */
uint32_t Client::file_exists_to_download(string filename, string username){
    string path = FILE_PATH + username + "/Download/" + filename;
    struct stat buffer;
    if (stat(path.c_str(),&buffer)!=0){ //stat failed
        return 0;
    }
    //The file exists and has a size which is less then 4Gib
    return -1;
}

/**
 * Help function that shows all the available commands to the user
 * 
 */
void Client::help(){
    cout<<"===================================== HELP ================================================="<<endl<<endl;
    cout<<"The available commands are the following:"<<endl<<endl;
    cout<<"help : \tthat shows all the available commands"<<endl<<endl;
    cout<<"download : \tSpecifies a file on the server machine. The server sends the requested file to the user. The filename of any downloaded file must be the filename used to store the file on the server. If this is not possible, the file is not downloaded."<<endl<<endl;
    cout<<"delete : \tSpecifies a file on the server machine. The server asks the user for confirmation. If the user confirms, the file is deleted from the server. "<<endl<<endl;
    cout<<"upload : \tSpecifies a filename on the client machine and sends it to the server. The server saves the uploaded file with the filename specified by the user. If this is not possible, the file is not uploaded. The max file size is 4GiB"<<endl<<endl;
    cout<<"list: \tThe client asks to the server the list of the filenames of the available files in his dedicated storage. The client prints to screen the list."<<endl<<endl;
    cout<<"rename : \tSpecifies a file on the server machine. Within the request, the clients sends the new filename. If the renaming operation is not possible, the filename is not changed."<<endl<<endl;
    cout<<"logout: \tThe client gracefully closes the connection with the server. "<<endl;
    cout<<"============================================================================================"<<endl<<endl; 
}

/**
 * Function that manage the upload command, takes as a parameter the name of the file that the user want to upload. The file must be located in a specific directory.
 * 
 * @param username: name of the file that the user wants to upload
 * @return int: exit param
 */
int Client::upload(string username){
    uint32_t counter = 0;
    cout<<"**********************************************"<<endl;
    cout<<"Which file do you want to upload on the cloud?"<<endl;
    cout<<"**********************************************"<<endl<<endl;
    string filename;
    cin>>filename;

    if (filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
        std::cerr << "ERR: command check on whitelist fails"<<endl;
        return -1;
    }

    //I need to be sure that no other file is in Download directory with the same name

    //filename is a string composed from whitelisted chars, so no path traversal allowed (see the cycle at 724)
    //We can proceed to check the existance of the file
    uint32_t size_file = file_exists(filename,username);
    if(size_file==0){
        cout<<"Error during upload"<<endl;
        cout<<"*******************"<<endl;
        return -1;
    }

    /******************************************************/
    /******* Phase 1: send iv + encrypt_msg + HMAC ********/

    //Phase needed to check if on the server is present another file with the same name of the one that the user want to upload
    //The server will send an ACK or NACK depending on its disponibility to recive the file

    //Packet initialization
    bootstrap_upload pkt;
    pkt.code = BOOTSTRAP_UPLOAD;
    pkt.filename = filename;
    pkt.filename_len = strlen(filename.c_str());
    pkt.response = 0;
    pkt.counter = counter;
    pkt.size = size_file;

    unsigned char* iv = (unsigned char*)malloc(IV_LENGTH);
    unsigned char* ciphertext;
    int cipherlen;

    // Prepare the plaintext to encrypt
    string buffer = to_string(pkt.code) + "$" + to_string(pkt.filename_len) + "$" + filename + "$" + to_string(pkt.response) + "$" + to_string(pkt.counter) + "$" + to_string(pkt.size);

    // Encryption
    if(cbc_encrypt_fragment((unsigned char*)buffer.c_str(), strlen(buffer.c_str()), ciphertext, cipherlen, true)!=0){
        cout<<"Error during encryption"<<endl;
        return -1;
    }

    // Get the HMAC
    uint32_t MAC_len; 
    unsigned char*  MACStr = (unsigned char*)malloc(IV_LENGTH + cipherlen);
    unsigned char* HMAC;
    memcpy(MACStr,iv, IV_LENGTH);
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
        return -1;
    }
    free(MACStr);
    free(ciphertext);
    counter++;
    
    /***************************************************************************************/
    // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 2 ******************** //

    uint32_t length_rec;

    if(!receive_message(data, length_rec)){
        cerr << "ERR: some error in receiving MSG2 in upload" << endl;
		free(data);
		return -2;
    }

    bootstrap_upload rcvd_pkt;
    if(!rcvd_pkt.deserialize_message(data)){
        cerr<<"Received the wrong packet!"<<endl;
        return -2;
    }

    this->iv = iv;

    MACStr = (unsigned char*)malloc(IV_LENGTH + rcvd_pkt.cipher_len);
    memcpy(MACStr,iv, IV_LENGTH);
    memcpy(MACStr + 16,(void*)rcvd_pkt.ciphertext.c_str(),rcvd_pkt.cipher_len);

    //Generate the HMAC on the receiving side iv||ciphertext
    generate_HMAC(MACStr,IV_LENGTH + rcvd_pkt.cipher_len, HMAC,MAC_len);
    //Free
    free(MACStr);

    //HMAC Verification
    if(!verify_SHA256_MAC(HMAC,rcvd_pkt.HMAC)){
        cout<<"HMAC cant be verified, try again"<<endl;
        return -2;
    }

    unsigned char* plaintxt;
    int ptlen;

    //Decrypt the ciphertext and obtain the plaintext
    if(cbc_decrypt_fragment((unsigned char* )rcvd_pkt.ciphertext.c_str(),rcvd_pkt.cipher_len,plaintxt,ptlen)!=0){
        cout<<"Error during encryption"<<endl;
        return -2;
    }

    //Parsing and pkt parameters setting, it also free 'plaintxt'
        if(!rcvd_pkt.deserialize_plaintext(plaintxt)){
        cerr<<"Received wrong message type!"<<endl;
        return -2;
    }

    if(DEBUG){
        cout<<"You received the following cripted message: "<<endl;
        cout<<"Code: "<<rcvd_pkt.code<<";\n filename_len:"<<rcvd_pkt.filename_len<<";\n filename:"<<rcvd_pkt.filename<<";\n counter:"<<rcvd_pkt.counter<<";\n size: "<<rcvd_pkt.size<<endl;
    }
    // Check on rcvd packets values
    if( rcvd_pkt.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<rcvd_pkt.counter<<" instead of: "<<counter<<endl;
        return -2;
    }
    // Check the response of the server
    if( rcvd_pkt.response != 1){
        cerr<<"There is already a file with the same name on the server! Rename or delete it before uploading a new one"<<endl;
        return -2;
    }
    free(ciphertext);
    counter++;
    // If the server response is '1' the server is now ready to obtain the file 

    /***************************************************************************************/
    // *************************** PHASE 2 SEND THE FILE: MSG 3 ************************** //

    if(!send_encrypted_file(filename, counter)){
        cerr<<"error during the upload of the file"<<endl;
        return -3;
    }

    /***************************************************************************************/
    // ******************************* SEND EOF NOTIF: MSG 4 ***************************** //

    end_upload pkt_end_1;
    pkt_end_1.code = FILE_EOF_HS;
    pkt_end_1.response = "END";
    pkt_end_1.counter = counter;

    // Prepare the plaintext to encrypt
    buffer =  to_string(pkt_end_1.code) + "$" + pkt_end_1.response + "$" + to_string(pkt_end_1.counter);

    // Encryption
    if(cbc_encrypt_fragment((unsigned char*)buffer.c_str(), strlen(buffer.c_str()), ciphertext, cipherlen, false)!=0){
        cout<<"Error during encryption of EOF Handshaking"<<endl;
        return -5;
    }

    // Get the HMAC
    MACStr = (unsigned char*)malloc(IV_LENGTH + cipherlen);
    memcpy(MACStr,iv, IV_LENGTH);
    memcpy(MACStr + 16,ciphertext,cipherlen);


    //Initialization of the data to serialize
    pkt_end_1.ciphertext = (const char*)ciphertext;
    pkt_end_1.cipher_len = cipherlen;
    generate_HMAC(MACStr,IV_LENGTH + cipherlen, HMAC, MAC_len);
    pkt_end_1.HMAC = HMAC;

    data = (unsigned char*)pkt_end_1.serialize_message(data_length);

    //Send the EOF message
    if(!send_message((void *)data, data_length)){
        cout<<"Error during packet #5 forwarding"<<endl;
        free(MACStr);
        free(ciphertext);
        return -1;
    }

    free(MACStr);
    free(ciphertext);
    counter++;

    /***************************************************************************************/
    // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 5 ******************** //

    if(!receive_message(data, length_rec)){
        cerr << "ERR: some error in receiving MSG2 in upload" << endl;
		free(data);
		return -6;
    }

    end_upload pkt_end_2;
    if(!pkt_end_2.deserialize_message(data)){
        cerr<<"Received the wrong packet!"<<endl;
        return -6;
    }

    MACStr = (unsigned char*)malloc(IV_LENGTH + pkt_end_2.cipher_len);
    memcpy(MACStr,iv, IV_LENGTH);
    memcpy(MACStr + 16,(void*)pkt_end_2.ciphertext.c_str(),pkt_end_2.cipher_len);

    //Generate the HMAC on the receiving side iv||ciphertext
    generate_HMAC(MACStr,IV_LENGTH + pkt_end_2.cipher_len, HMAC,MAC_len);
    //Free
    free(MACStr);

    //HMAC Verification
    if(!verify_SHA256_MAC(HMAC,pkt_end_2.HMAC)){
        cerr<<"Error: HMAC cant be verified"<<endl;
        return -6;
    }

    //Decrypt the ciphertext and obtain the plaintext
    if(cbc_decrypt_fragment((unsigned char* )pkt_end_2.ciphertext.c_str(),pkt_end_2.cipher_len, plaintxt,ptlen)!=0){
        cerr<<"Error during encryptionof packet #6"<<endl;
        return -6;
    }

    //Parsing and pkt parameters setting, it also free 'plaintxt'
    if(!pkt_end_2.deserialize_plaintext(plaintxt)){
        cerr<<"Received wrong message type!"<<endl;
        return -6;
    }

    if(DEBUG){
        cout<<"You received the following cripted message: "<<endl;
        cout<<"Code: "<<pkt_end_2.code<<";\n filename:"<<pkt_end_2.response<<";\n counter:"<<pkt_end_2.counter<<endl;
    }

    // Check on rcvd packets values
    if( pkt_end_2.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<pkt_end_2.counter<<" instead of: "<<counter<<endl;
        return -6;
    }
    // Check the response of the server
    if(!strcmp(pkt_end_2.response.c_str(),"OK")){
        cerr<<"There was a problem during the finalization of the upload!"<<endl;
        return -6;
    }

    cout<<"***************************************************************************************"<<endl;
    cout<<"************************ THE UPLOAD HAS BEEN SUCCESSFUL! ******************************"<<endl;

    return 0;
}

/**
 * Function that manage the downlaod command, takes as a parameter the name of the file that the user want to download.
 * 
 * @param username : username of the user that want to download the file
 * @return int : 0 => success, !=0 => failure
 */
int Client::download(string username){
    uint32_t counter = 0;

    cout<<"**************************************************"<<endl;
    cout<<"Which file do you want to download from the cloud?"<<endl;
    cout<<"**************************************************"<<endl<<endl;

    string filename;
    cin>>filename;

    if (filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
        std::cerr << "ERR: command check on whitelist fails"<<endl;
        return -1;
    }

    if(file_exists_to_download(filename, username)!=0){
        std::cerr << "ERR: file already inside download dir"<<endl;
        return -1;
    }
    //Check if on server side there is a file with the same name
    //Packet initialization
    bootstrap_download pkt;
    pkt.code = BOOTSTRAP_DOWNLOAD;
    pkt.filename = filename;
    pkt.counter = counter;

    //Data structure serialization
    int pkt_len;
    unsigned char* buffer = (unsigned char *)pkt.serialize_message(pkt_len);


    unsigned char* iv = this->iv; 
    unsigned char* ciphertext;
    int cipherlen;

    //Message encryption
    if(cbc_encrypt_fragment(buffer, pkt_len, ciphertext, cipherlen, true)!=0){
        cout<<"Error during encryption"<<endl;
        return -1;
    }
    //buffer is no longer needed
    free(buffer);

    //Send the iv
    send_message((void *)iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

    //send the cyphertext
    send_message((void*)ciphertext, cipherlen);
    
    //ciphertext no longer needed
    free(ciphertext);

    //Generation of the HMAC

    // ??

    //send_message((void*)hmac, /*hmacsize*/)

    //ret = receive_message()
    return 0;
}

// RUN
int Client::run(){
    try {

        // establish session and HMAC key
        if(!init_session()){
            cerr << "Session keys establishment failed" << endl;
            throw 1;
        }

        cout << "session keys has been established correctly " << endl;
    }
    catch (int error_code) {
        cout<<"Error during session initialization, exited with code: "<<error_code<<endl;
        return -1;
    }

    cout<<"======================================="<<endl;
	cout<<"=            CLIENT AVVIATO           ="<<endl;
	cout<<"======================================="<<endl<<endl<<endl;

    help();

    //vector that contains the command 
    vector <string> words{};

    while(true){
        string command;
        cout<<"-> Insert a command:"<<endl;
        cin>>command;


        if (command.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
            std::cerr << "ERR: command check on whitelist fails"<<endl;
            return -1;
        }

        //Check for command existance
        int state = -1;
        const char* command_chars = command.c_str();

        if(!strcmp(command_chars,"help")){
            state = 0;
            //cout<<"sei dentro help"<<endl;
        }
        if(!strcmp(command_chars,"upload")){
            state = 1;
            //cout<<"sei dentro upload"<<endl;
        }
        if(!strcmp(command_chars,"download")){
            state = 2;
            //cout<<"sei dentro download"<<endl;
        }
        if(!strcmp(command_chars,"list")){
            state = 3;
            //cout<<"sei dentro list"<<endl;
        }
        if(!strcmp(command_chars,"rename")){
            state = 4;
            //cout<<"sei dentro rename"<<endl;
        }
        if(!strcmp(command_chars,"delete")){
            state = 5;
            //cout<<"sei dentro delete"<<endl;
        }
        if(!strcmp(command_chars,"logout")){
            state = 6;
            //cout<<"sei dentro logout"<<endl;
        }

        switch(state){
            case 0:
                help();
                continue;
            
            case 1:
                upload(this->username);
                continue;

            case 2:
                download(this->username);
                continue;

            case 3:
                //list();
                continue;

            case 4:
                //rename(words[1],words[2]);
                continue;

            case 5:
                //delete(words[1]);
                continue;

            case 6:
                //logout();
                continue;

            case -1:
                cout<<"Wrong command, check and try again"<<endl;
                continue;

        }

        //Clean the command string once the state is chosen
        words.erase(words.begin(),words.end());
        //Clear the cin flag
        cin.clear();
    }
}

// TESTS

// TEST ENCRYPTION
/*void Client::run(){
    cout << "RUN" <<endl;

    unsigned char* prova = (unsigned char*)malloc(5);
    unsigned char* iv = nullptr;
    unsigned char* ct = nullptr;
    unsigned char* pt = nullptr;
    
    int plainlen;
    int cipherlen;
    memset((void*) prova, 'A', 5);
    if (cbc_encrypt_fragment(prova, 5, iv, ct, cipherlen) == 0){
        cout << "encryption OK" << endl;
    }

    cout << "cipherlen: " << cipherlen << endl;
    BIO_dump_fp(stdout, (const char *)ct, cipherlen);

    if (cbc_decrypt_fragment(ct, cipherlen, iv, pt, plainlen) == 0){
        cout << "decryption OK" << endl;
    }

    printf("%s\n", pt);
}*/

// TEST socket

/*void Client::run(){
    cout << "RUN" <<endl;

    // establish session and HMAC key
    if(!initialize_session()){
        cerr << "Session keys establishment failed" << endl;
        throw INITIALIZE_SESSION_FAIL;
    }

    unsigned char* send_buffer = (unsigned char*) malloc(5);
    memset(send_buffer, 'A', 5);
    send_message((void *)send_buffer, 5);

    recv (session_socket, send_buffer, 5, 0);
  
}*/
/*
int Client::run(){
    cout << "RUN" << endl;

    int ret;
    
    // initialize socket
    if (!init_socket()){
        cerr << " Error: socket definition failed" << endl;
        return false;
    }

    // connect to server
    ret = connect(session_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		cerr << "Error: connection to server failed" << endl;
		return false;
	}

    login_bootstrap_pkt pkt;
    int len;
    pkt.username = username;
    pkt.symmetric_key_param = generate_sts_key_param();
    pkt.hmac_key_param = generate_sts_key_param();
    
    void* send_buffer = pkt.serialize_message(len);
    
    send_message(send_buffer, len);
    return 0;
}

int Client::run(){
    upload("fedem");
}
*/
