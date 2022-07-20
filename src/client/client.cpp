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
	if (symmetric_key != nullptr) {secure_free(symmetric_key, symmetric_key_length);}
    if (hmac_key != nullptr) {secure_free(hmac_key, hmac_key_length);}      
    if (iv != nullptr) {free(iv);}
}

/**
 * @brief manage the receive and various general checks on the received packet
 *        MANAGE THE plaintxt destruction!
 * @return unsigned* the plaintext to deserialize inside the correct packet type
 */
unsigned char* Client::receive_decrypt_and_verify_HMAC(){
    unsigned char* data;
    generic_message rcvd_pkt;
    uint32_t length_rec;
    
    //Receive the serialized data
    int ret = receive_message(data, length_rec);
    if(ret!=0){
        cerr << "ERR: some error in receiving MSG, received error: " << ret<< endl;
		free(data);
        data = nullptr;
		return nullptr;
    }

    if(!rcvd_pkt.deserialize_message(data)){
        cerr<<"Error during deserialization of the data"<<endl;
        free(data);
        data = nullptr;
        return nullptr;
    }
    free(this->iv);
    this->iv = nullptr;
    this->iv = rcvd_pkt.iv;

    uint32_t MAC_len; 
    uint8_t*  MACStr;
    uint8_t* HMAC;
    MACStr = (uint8_t*)malloc(IV_LENGTH + rcvd_pkt.cipher_len);
    if(!MACStr){
        cerr<<"Error during malloc of MACStr"<<endl;
        return nullptr;
    }
    memset(MACStr, 0 , IV_LENGTH + rcvd_pkt.cipher_len);
    memcpy(MACStr,rcvd_pkt.iv, IV_LENGTH);
    memcpy(MACStr + 16,(void*)rcvd_pkt.ciphertext,rcvd_pkt.cipher_len);

    //Generate the HMAC on the receiving side iv||ciphertext
    generate_HMAC(MACStr,IV_LENGTH + rcvd_pkt.cipher_len, HMAC,MAC_len);

    //HMAC Verification
    if(!verify_SHA256_MAC(HMAC,rcvd_pkt.HMAC)){
        cout<<"HMAC cant be verified, try again"<<endl;
        free(MACStr);
        MACStr = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }

    unsigned char* plaintxt;
    int ptlen;

    //The IV get a free every time it gets generated again and at the end of execution during a class destruction
    this->iv = rcvd_pkt.iv;

    //Decrypt the ciphertext and obtain the plaintext
    if(cbc_decrypt_fragment((unsigned char* )rcvd_pkt.ciphertext,rcvd_pkt.cipher_len,plaintxt,ptlen)!=0){
        cout<<"Error during encryption"<<endl;
        free(MACStr);
        MACStr = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }
    free(MACStr);
    MACStr = nullptr;
    free(HMAC);
    HMAC = nullptr;
    free(rcvd_pkt.HMAC);
    rcvd_pkt.HMAC = nullptr;
    return plaintxt;
}

/**
 * @brief manage the receive and various general checks on the received packet fo files
 *        MANAGE THE plaintxt destruction!
 * @return unsigned* the plaintext to deserialize inside the correct packet type
 */
unsigned char* Client::receive_decrypt_and_verify_HMAC_for_files(){
    unsigned char* data;
    generic_message_file rcvd_pkt;
    uint32_t length_rec;
    
    //Receive the serialized data
    int ret = receive_message(data, length_rec);
    if(ret!=0){
        cerr << "ERR: some error in receiving MSG, received error: " << ret<< endl;
		free(data);
        data = nullptr;
		return nullptr;
    }

	//It also FREE data if reaches the end
    if(!rcvd_pkt.deserialize_message(data)){
        cerr<<"Error during deserialization of the data"<<endl;
        free(data);
        data = nullptr;
        return nullptr;
    }

	//Deallocate the iv
	if(this->iv != nullptr)
    	free(this->iv);
    this->iv = rcvd_pkt.iv;

    uint32_t MAC_len; 
    uint8_t*  MACStr;
    uint8_t* HMAC;

    MACStr = (unsigned char*)malloc(IV_LENGTH + rcvd_pkt.cipher_len);
    if(!MACStr){
        cerr<<"Error during malloc of MACStr"<<endl;
        return nullptr;
    }
	memset(MACStr, 0 ,IV_LENGTH + rcvd_pkt.cipher_len);
    memcpy(MACStr, this->iv , IV_LENGTH);
    memcpy(MACStr + IV_LENGTH,rcvd_pkt.ciphertext,rcvd_pkt.cipher_len);

    //Generate the HMAC on the receiving side iv||ciphertext
    generate_HMAC(MACStr,IV_LENGTH + rcvd_pkt.cipher_len, HMAC,MAC_len);

    //HMAC Verification
    if(!verify_SHA256_MAC(HMAC,rcvd_pkt.HMAC)){
        cout<<"HMAC cant be verified, try again"<<endl;
        free(MACStr);
        MACStr = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }

    unsigned char* plaintxt;
    int ptlen;

    //Decrypt the ciphertext and obtain the plaintext
    if(cbc_decrypt_fragment(rcvd_pkt.ciphertext,rcvd_pkt.cipher_len,plaintxt,ptlen)!=0){
        cout<<"Error during encryption"<<endl;
        free(MACStr);
        MACStr = nullptr;
        free(rcvd_pkt.HMAC);
        rcvd_pkt.HMAC = nullptr;
        return nullptr;
    }
    free(MACStr);
    MACStr = nullptr;
    free(HMAC);
    HMAC = nullptr;
    free(rcvd_pkt.HMAC);
    rcvd_pkt.HMAC = nullptr;
    return plaintxt;
}

/**
 * @brief Encrypt the plaintext and fill a generic packet to send through the socket
 * 
 * @param buffer : plaintext to encrypt
 * @return true : the crypted msg has been sent successfully
 * @return false : error during packet preparation or during the send
 */
bool Client::encrypt_generate_HMAC_and_send(string buffer){
	// Generic Packet
	generic_message pkt;

	unsigned char* ciphertext;
    int cipherlen;
	// Encryption
    if(cbc_encrypt_fragment((unsigned char*)buffer.c_str(), buffer.length(), ciphertext, cipherlen, true)!=0){
        cout<<"Error during encryption"<<endl;
        free(ciphertext);
        ciphertext = nullptr;
        return false;
    }

	// Get the HMAC
    uint32_t MAC_len; 
    unsigned char*  MACStr = (unsigned char*)malloc(IV_LENGTH + cipherlen);
    if(!MACStr){
        cerr<<"Error during malloc of MACStr"<<endl;
        free(ciphertext);
        return -1;
    }
    memset(MACStr,0,IV_LENGTH + cipherlen);
    unsigned char* HMAC;
    memcpy(MACStr,this->iv, IV_LENGTH);
    memcpy(MACStr + 16,ciphertext,cipherlen);

	//Initialization of the data to serialize
    pkt.ciphertext = (uint8_t*)ciphertext;
    pkt.cipher_len = cipherlen;
    pkt.iv = this->iv;
    generate_HMAC(MACStr,IV_LENGTH + cipherlen, HMAC,MAC_len); 
    pkt.HMAC = HMAC;

    unsigned char* data;
    int data_length;

    data = (unsigned char*)pkt.serialize_message(data_length);

    if(data == nullptr){
        free(MACStr);
        MACStr = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;

        cerr<<"Error during serialization"<<endl;
        return false;
    }

    //Send the first message
    if(!send_message((void *)data, data_length)){
        cout<<"Error during packet forwarding"<<endl;
        free(MACStr);
        MACStr = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;
        free(data);
        data = nullptr;
        return false;
    }
    free(MACStr);
    MACStr = nullptr;
    free(ciphertext);
    ciphertext = nullptr;
    free(pkt.HMAC);
    pkt.HMAC = nullptr;
    free(data);
    data = nullptr;
	return true;
}

/**
 * @brief Encrypt the plaintext and fill a generic packet to send through the socket REDEFINITION FOR FILE TRANSFER
 * 
 * @param buffer : plaintext to encrypt
 * @return true : the crypted msg has been sent successfully
 * @return false : error during packet preparation or during the send
 */
bool Client::encrypt_generate_HMAC_and_send(uint8_t* buffer, uint32_t msg_len){
	// Generic Packet
	generic_message_file pkt;
    if(DEBUG){
        cout<<"buffer len: "<<msg_len<<endl;
    }
	unsigned char* ciphertext;
    int cipherlen;
	// Encryption
    if(cbc_encrypt_fragment((unsigned char*)buffer, msg_len, ciphertext, cipherlen, true)!=0){
        cout<<"Error during encryption"<<endl;
        free(ciphertext);
        ciphertext = nullptr;
        return false;
    }

	// Get the HMAC
    uint32_t MAC_len; 
    uint8_t*  MACStr = (unsigned char*)malloc(IV_LENGTH + cipherlen);
    if(!MACStr){
        cerr<<"Error during malloc of MACStr"<<endl;
        free(ciphertext);
        return -1;
    }
    memset(MACStr,0,IV_LENGTH + cipherlen);
    unsigned char* HMAC;
    memcpy(MACStr,this->iv, IV_LENGTH);
    memcpy(MACStr + IV_LENGTH,ciphertext,cipherlen);

	//Initialization of the data to serialize
    pkt.ciphertext = ciphertext;
    pkt.cipher_len = cipherlen;
    pkt.iv = this->iv;
    generate_HMAC(MACStr,IV_LENGTH + cipherlen, HMAC,MAC_len); 
    pkt.HMAC = HMAC;

    unsigned char* data;
    int data_length;

    data = (unsigned char*)pkt.serialize_message(data_length);

    if(data == nullptr){
        free(MACStr);
        MACStr = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;

        cerr<<"Error during serialization"<<endl;
        return false;
    }

    //Send the first message
    if(!send_message((void *)data, data_length)){
        cout<<"Error during packet #1 forwarding"<<endl;
        free(MACStr);
        MACStr = nullptr;
        free(ciphertext);
        ciphertext = nullptr;
        free(pkt.HMAC);
        pkt.HMAC = nullptr;
        free(data);
        data = nullptr;
        return false;
    }

    free(MACStr);
    MACStr = nullptr;
    free(ciphertext);
    ciphertext = nullptr;
    free(pkt.HMAC);
    pkt.HMAC = nullptr;
    free(data);
    data = nullptr;
	return true;
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

    if (privk == nullptr){
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

    if(DEBUG)
        cout<<ret<<" bytes sent"<<endl;

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

    return 0;
}

// generate a new iv for the specified cipher
// DO NOT HANDLE FREE
bool Client::generate_iv (const EVP_CIPHER* cipher){
    int iv_len = EVP_CIPHER_iv_length(cipher);

    if (iv != nullptr){
        free(iv);
    }
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
	
	if (msg_len == 0 || msg_len > MAX_PKT_SIZE) {
        cerr << "message length is not allowed: " << msg_len << endl;
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
	
    if (cipherlen == 0 || cipherlen > MAX_PKT_SIZE) {
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

/**
 * Function that send the specified file through chunks of specified max size
 * 
 * @param filename : name of the file to send
 * @param counter : current counter number
 * @return int : result of the operation
 */
int Client::send_encrypted_file (string filename, uint32_t& counter){
    // build a string that cointain the path of the file
    string path = FILE_PATH + this->username + "/Upload/" + filename;
    //open the file
    FILE* file = fopen(path.c_str(), "rb"); 
    // If !file the file cant be open or is not present inside the dir
    if (!file){
        cerr<<"Error during file opening"<<endl;
        return -1;
    }
    struct stat buf;
    if (stat(path.c_str(),&buf)!=0){ //stat failed
        cout<<"Failed stat function: File doesn't exists in the Upload dir"<<endl;
        return -1;
    }

    //Calculate the number of chunks to send
    size_t num_chunk_to_send = ceil((float)buf.st_size/FILE_FRAGMENTS_SIZE);
    if(DEBUG){
        cout << "Number of chunks: " << num_chunk_to_send << endl << endl;
    }

    unsigned char* buffer = (unsigned char*)malloc(FILE_FRAGMENTS_SIZE);

    if(!buffer){            
        cerr << "ERR: cannot allocate a buffer for the file fragment" << endl;
        return -1;
    }

    memset(buffer,0,FILE_FRAGMENTS_SIZE);

    int ret;
    //Start to send the chunks
    for(size_t i = 0; i < num_chunk_to_send; ++i){
        long to_send;
        // read bytes from file, the pointer is automatically increased
        if(i+1 == num_chunk_to_send){
            to_send = buf.st_size - i*FILE_FRAGMENTS_SIZE;
        }
        else{
            to_send = FILE_FRAGMENTS_SIZE;
        }

        ret = fread(buffer,1, to_send, file);

        if(ret != to_send && DEBUG){
            cerr<<"Error: to send="<<to_send<<" and ret="<<ret<<endl;
        }

        if(DEBUG)
            cout<<"read: "<<ret<<" bytes"<<endl;

        if ( ferror(file) != 0 ){
            std::cerr << "ERR: file reading error occured" << endl;
            return -1;
        }

        //Declare a new packet & init its fields
        file_upload pkt;
        pkt.code = FILE_UPLOAD;
        pkt.counter = counter;
        pkt.msg_len = ret;
        pkt.msg = buffer;
        long size = sizeof(pkt.code) + sizeof(pkt.counter) + sizeof(pkt.msg_len) + ret;
        uint8_t* to_encrypt = (uint8_t*)malloc(size);
        if(to_encrypt == nullptr){
            cerr<<"Failed malloc of to_encrypt"<<endl;
            return -1;
        }

        memset(to_encrypt,0,size);
        
        uint32_t cnt = 0;
        pkt.code = htons(pkt.code);
        memcpy(to_encrypt,&pkt.code,sizeof(pkt.code));
        cnt += sizeof(pkt.code);

        pkt.counter = htonl(pkt.counter);
        memcpy(to_encrypt + cnt ,&pkt.counter,sizeof(pkt.counter));
        cnt += sizeof(pkt.counter);

        pkt.msg_len = htonl(pkt.msg_len);
        memcpy(to_encrypt + cnt ,&pkt.msg_len,sizeof(pkt.msg_len));
        cnt += sizeof(pkt.msg_len);

        memcpy(to_encrypt + cnt ,buffer,ret);

        //Send the fragment
        if(!encrypt_generate_HMAC_and_send(to_encrypt, size)){
            cerr<<"Error during encrypt_generate_HMAC_and_send of fragment n°"<<i+1<<endl;
            return -1;
        }
        counter++;
        free(to_encrypt);
        memset(buffer,0,FILE_FRAGMENTS_SIZE);
    }
    fclose(file);
    free(buffer);
    return 0;
}  

/**
 * @brief Manage the file upload
 * 
 * @param size size of the uploaded file
 * @param filename name of the uploaded file
 * @return true : receive successful
 * @return false : receive failed
 */
bool Client::encrypted_file_receive(uint32_t size, string filename, uint32_t& counter){
    string path = FILE_PATH + this->username + "/Download/" + filename;
    //number of file chunk expected
	unsigned int num_chunks = ceil((float) size/FILE_FRAGMENTS_SIZE);
    if(DEBUG)
	    cout << "Number of chunks: " << num_chunks << endl << endl;

	//opening file on disk
	ofstream file(path, std::ofstream::binary);
	if(file.fail()){
		cerr << "error opening the file\n";
        return false;
	}
    //Prepare the buffer
    unsigned char* buffer;
    buffer = (unsigned char*)malloc(FILE_FRAGMENTS_SIZE);
    if(!buffer){            
        cerr << "ERR: cannot allocate a buffer for the file fragment" << endl;
        return false;
    }
    memset(buffer,0,FILE_FRAGMENTS_SIZE);

	for(uint32_t i = 0; i < num_chunks; ++i){
        //Receive the message
        unsigned char* plaintxt;
        plaintxt = receive_decrypt_and_verify_HMAC_for_files();
        file_upload pkt;
    
        if(plaintxt == nullptr){
            cerr<<"Error during receive_decrypt_and_verify_HMAC n°"<<i+1<<endl;
            free(buffer);
            buffer = nullptr;
            return -2;
        }

        //Parsing and pkt parameters setting, it also free 'plaintxt'
        if(!pkt.deserialize_plaintext(plaintxt)){
            cerr<<"Received wrong message type!"<<endl;
            free(plaintxt);
            plaintxt = nullptr;
            free(buffer);
            buffer = nullptr;
            return -2;
        }

        // Check for a replay attack
        if(counter!= pkt.counter){
            cerr<<"Wrong counter value, received "<<pkt.counter<<" instead of "<<counter<<endl;
            free(plaintxt);
            plaintxt = nullptr;
            free(buffer);
            buffer = nullptr;
            return -2;
        }

		if(!file.write((const char*)pkt.msg, pkt.msg_len)){
            cerr<<"Error during file write"<<endl;
            return -2;
        }
        free(pkt.msg);
        pkt.msg = nullptr;
        memset(buffer,0,FILE_FRAGMENTS_SIZE);
        counter++;
    }
    free(buffer);
    buffer = nullptr;
    return true;
}

// sent packet [username | sts_key_param | hmac_key_param]
//MISS CONTROLS AND FREES
int Client::send_login_bootstrap(login_bootstrap_pkt& pkt){
	unsigned char* send_buffer;
	int len;
    unsigned char* to_copy;
	
	// lens will be automatically set after sending
    pkt.code = LOGIN_BOOTSTRAP;
    pkt.username = username;
	
	// generate dh keys
    pkt.symmetric_key_param = generate_sts_key_param();
	
	if (pkt.symmetric_key_param == nullptr){
		cerr << "ERR: failed to generate session keys parameters" << endl;
        return -1;
	}
	
    pkt.hmac_key_param = generate_sts_key_param();

    if (pkt.hmac_key_param == nullptr){
        cerr << "ERR: failed to generate session keys parameters" << endl;
        return -1;
    }

    // TO FREE
	to_copy = (unsigned char*) pkt.serialize_message(len);

    if (to_copy == nullptr){
		cerr << "ERR: failed to serialize login bootstrap packet" << endl;
		return -1;
	}

    // TO FREE
    send_buffer = (unsigned char*) malloc(len);

    if (!send_buffer){
        cerr << "malloc failed on send_buffer" << endl;
        return -1;
    }
	
	memcpy(send_buffer, to_copy, len);
	
    if (!send_message(send_buffer, len)){
        cerr << "ERR: failed to send login bootstrap packet" << endl;
        return -1;
    }

    secure_free(send_buffer, len);
    secure_free(to_copy, len);
	
    return 0;
    
}

// send the client authentication packet with no dh keys in cleartext
int Client::send_login_client_authentication(login_authentication_pkt& pkt){
	unsigned char* part_to_encrypt;
	int pte_len;
	int final_pkt_len;
	unsigned int signature_len;
	unsigned char* signature;
	unsigned char* ciphertext;
	unsigned char* final_pkt;
    unsigned char* to_copy;
	int cipherlen;
	int ret;
	
	//set the clear fields that must be null as ""
	
	// load client certificate
	pkt.cert = get_certificate();
	
	if (pkt.cert == nullptr){
		cerr << "cannot load certificate" << endl;
		return -1;
	}
	
	// serialize the part to encrypt, TO FREE
	to_copy = (unsigned char*) pkt.serialize_part_to_encrypt(pte_len);

    if (to_copy == nullptr){
		cerr << "error in serialize part to encrypt" << endl;
		return -1;
	}

    part_to_encrypt = (unsigned char*) malloc(pte_len);

    if(part_to_encrypt == nullptr){
        cerr << "failed malloc on part_to_encrypt" << endl;
        return -1;
    }

    memcpy(part_to_encrypt, to_copy, pte_len);
	
	// sign the document and free the private_key
	signature = sign_message(private_key, part_to_encrypt, pte_len, signature_len);
	if (signature == nullptr){
		cerr << "cannot generate valid signature" << endl;
		return -1;
	}

	// encrypt, also set the iv field, TO FREE ciphertext
	ret = cbc_encrypt_fragment(signature, signature_len, ciphertext, cipherlen, true);
	if (ret != 0){
		cerr << "cannot generate valid ciphertext" << endl;
		return -1;
	}
   
	pkt.iv_cbc = iv;
	pkt.encrypted_signing = ciphertext;
	pkt.encrypted_signing_len = cipherlen;
	
	// final serialization, this time there will be no dh keys in clear
    secure_free(to_copy, pte_len);
    secure_free(part_to_encrypt, pte_len);
    // TO FREE
	to_copy = (unsigned char*) pkt.serialize_message_no_clear_keys(final_pkt_len);
	final_pkt = (unsigned char*) malloc(final_pkt_len);
	
	if (!final_pkt){
		cerr << "malloc failed on final_pkt" << endl;
		return -1;
	}
	
	// copy
	memcpy(final_pkt, to_copy, final_pkt_len);
	
	if (!send_message(final_pkt, final_pkt_len)){
		cerr << "message cannot be sent" << endl;
		return -1;
	}

	free(ciphertext);
	free(iv);
    iv = nullptr;
    free(signature);
    secure_free(to_copy, final_pkt_len);
	secure_free(final_pkt, final_pkt_len); 
	
	return 0;
}

// generate HMAC digest of a fragment (FILE_FRAGMENTS_SIZE)
int Client::generate_HMAC(unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen){
	
	// hmac_util.cpp
	return generate_SHA256_HMAC(msg, msg_len, digest, digestlen, hmac_key, MAX_PKT_SIZE);

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

// initialize a session with the server
bool Client::init_session(){
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
	EVP_PKEY* server_pubk;
	X509* ca_cert; 
	X509_CRL* ca_crl; 
	
	// receive buffer
	unsigned char* receive_buffer; 
    uint32_t len;

    cout<<"INITIALIZE SESSION."<<endl<<endl;
    
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
    if (send_login_bootstrap(bootstrap_pkt) != 0){
		EVP_PKEY_free(bootstrap_pkt.symmetric_key_param);
        EVP_PKEY_free(bootstrap_pkt.hmac_key_param);
        cerr << "something goes wrong in sending login_bootstrap_pkt" << endl;
        return false;
    }

    cout<<"CONNECTED TO SERVER"<<endl;
    cout<<"WAIT FOR SERVER AUTHENTICATION..."<<endl<<endl;
	
	// receive login_server_authentication_pkt
	while (true){
	
		try{
			// receive message
			if (receive_message(receive_buffer, len) < 0){
				cerr << "ERR: some error in receiving login_server_authentication_pkt" << endl;
				throw 1;
			}
			
			// check if it is consistent with server_auth_pkt, the call already free the buffer
			if (!server_auth_pkt.deserialize_message(receive_buffer)){
				cerr << "ERR: some error in deserialize server_auth_pkt" << endl;
				throw 2;
            }
			
			// derive symmetric key and hmac key, hash them, take a portion of the hash for the 128 bit key
			symmetric_key_no_hashed = derive_shared_secret(bootstrap_pkt.symmetric_key_param, server_auth_pkt.symmetric_key_param_server_clear);
			
			if (!symmetric_key_no_hashed){
				cerr << "failed to derive symmetric key" << endl;
				throw 3;
				return false;
			}
			ret = hash_symmetric_key(symmetric_key, symmetric_key_no_hashed);
			
			if (ret != 0){
				cerr << "failed to hash symmetric key" << endl;
				throw 4;
				return false;
			}
			
			hmac_key_no_hashed = derive_shared_secret(bootstrap_pkt.hmac_key_param, server_auth_pkt.hmac_key_param_server_clear);
			
			if (!hmac_key_no_hashed){
				cerr << "failed to derive hmac key" << endl;
				throw 5;
				return false;
			}
			ret = hash_hmac_key(hmac_key, hmac_key_no_hashed);
			
			if (ret != 0){
				cerr << "failed to hash hmac key" << endl;
				throw 6;
				return false;
			}
			
			// clean no hashed keys
			secure_free(symmetric_key_no_hashed, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
			secure_free(hmac_key_no_hashed, HMAC_KEY_SIZE);
			
			// decrypt the encrypted part using the derived symmetric key and the received iv
            if (iv != nullptr){
			    free(iv);
            }
			iv = (unsigned char*) malloc(iv_size);
			
			if(!iv){
				cerr << "failed malloc for iv in init_session" << endl;
				throw 7;
			}
			
			memcpy(iv, server_auth_pkt.iv_cbc, iv_size);
            free(server_auth_pkt.iv_cbc);

			ret = cbc_decrypt_fragment(server_auth_pkt.encrypted_signing, server_auth_pkt.encrypted_signing_len, plaintext, plainlen);
			
			if (ret != 0){
				cerr << "error in decrypting server authentication packet" << endl;
				throw 8;
			}
			
			// get CA certificate and its crl
			
			ca_cert = get_CA_certificate();
			
			if (ca_cert == nullptr){
				throw 9;
			}
			
			ca_crl = get_crl();
			
			if (ca_crl == nullptr){
				throw 10;
			}
			
			// validate server's certificate
			ret = validate_certificate(ca_cert, ca_crl, server_auth_pkt.cert);
			if (ret != 0){
				throw 11;
			}
			
			// extract server public key
			server_pubk = X509_get_pubkey(server_auth_pkt.cert);
			
			if (server_pubk == nullptr){
				cerr << "failed to extract server public key" << endl;
				throw 12;
			}
			
			// cleartext to verify signature: <lengths|server_serialized_params|client_serialized_params>
			// the signature is on the serialized version of the dh keys

			// re-serialize the dh keys and verify the signature

			// SET RECEIVED FIELDS
			server_auth_pkt.symmetric_key_param_server = server_auth_pkt.symmetric_key_param_server_clear;
			server_auth_pkt.symmetric_key_param_len_server = server_auth_pkt.symmetric_key_param_server_clear_len;
			
			server_auth_pkt.hmac_key_param_server = server_auth_pkt.hmac_key_param_server_clear;
			server_auth_pkt.hmac_key_param_len_server = server_auth_pkt.hmac_key_param_server_clear_len;
			
			// SET THE FIELDS THAT WE HAVE GENERATED BEFORE
			server_auth_pkt.symmetric_key_param_client = bootstrap_pkt.symmetric_key_param;
			server_auth_pkt.symmetric_key_param_len_client = bootstrap_pkt.symmetric_key_param_len;
			
			server_auth_pkt.hmac_key_param_client = bootstrap_pkt.hmac_key_param;
			server_auth_pkt.hmac_key_param_len_client = bootstrap_pkt.hmac_key_param_len;
			
			// this will serialize as the server did
			unsigned char* to_copy = (unsigned char*) server_auth_pkt.serialize_part_to_encrypt(signed_text_len);
			signed_text = (unsigned char*) malloc(signed_text_len);
			
			if(!signed_text){
				cerr << "error in signed_text malloc" << endl;
				throw 13;
			}
			memcpy(signed_text, to_copy, signed_text_len);
			
			// verify the signature (freshness verification)
			ret = verify_signature(server_pubk, plaintext, plainlen, signed_text, signed_text_len);
			
			if (ret != 0){
				cerr << "error in signature verification" << endl;
				return false;
			}
			
			// frees
			free(signed_text);
            free(to_copy);
			secure_free(receive_buffer, len);
            secure_free(plaintext, plainlen);
			X509_free(ca_cert);
			X509_CRL_free(ca_crl);
			EVP_PKEY_free(server_pubk);
			
		}catch (int error_code){
			
			if (error_code > 1)  { free(receive_buffer); }
			if (error_code > 7)  { free(iv); iv = nullptr; }
            if (error_code > 8)  { free(plaintext); }
			if (error_code > 9)  { X509_free(ca_cert); }
			if (error_code > 10) { X509_CRL_free(ca_crl); }
			if (error_code > 12) { EVP_PKEY_free(server_pubk); }
			if (error_code > 13) { free(signed_text); }

            cout << "some error occurred in receiveing server_auth_pkt" << endl;
            continue;
		}

		cout<<"SERVER CORRECTLY AUTHENTICATED."<<endl<<endl;
		break;
	}

	
	
	// all is verified, time to send client authentication packet 
	client_auth_pkt.symmetric_key_param_server = server_auth_pkt.symmetric_key_param_server_clear;
	client_auth_pkt.symmetric_key_param_len_server = server_auth_pkt.symmetric_key_param_server_clear_len;
	
	client_auth_pkt.hmac_key_param_server = server_auth_pkt.hmac_key_param_server_clear;
	client_auth_pkt.hmac_key_param_len_server = server_auth_pkt.hmac_key_param_server_clear_len;
	
	client_auth_pkt.symmetric_key_param_client = bootstrap_pkt.symmetric_key_param;
	client_auth_pkt.symmetric_key_param_len_client = bootstrap_pkt.symmetric_key_param_len;
	
	client_auth_pkt.hmac_key_param_client = bootstrap_pkt.hmac_key_param;
	client_auth_pkt.hmac_key_param_len_client = bootstrap_pkt.hmac_key_param_len;
	
	if (send_login_client_authentication(client_auth_pkt) != 0){
		return false;
	}

    cout<<"CLIENT AUTHENTICATION CORRECTLY SENT."<<endl<<endl;

    // free dh keys
    EVP_PKEY_free(bootstrap_pkt.symmetric_key_param);
    EVP_PKEY_free(bootstrap_pkt.hmac_key_param);
    EVP_PKEY_free(server_auth_pkt.symmetric_key_param_server_clear);
    EVP_PKEY_free(server_auth_pkt.hmac_key_param_server_clear);


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
    cout<<"******************************************************************"<<endl;
    cout<<"                             HELP                                 "<<endl;
    cout<<"******************************************************************"<<endl<<endl;
    cout<<"The available commands are the following:"<<endl<<endl;
    cout<<"help : \tthat shows all the available commands"<<endl<<endl;
    cout<<"download : \tSpecifies a file on the server machine. The server sends the requested file to the user. The filename of any downloaded file must be the filename used to store the file on the server. If this is not possible, the file is not downloaded."<<endl<<endl;
    cout<<"delete : \tSpecifies a file on the server machine. The server asks the user for confirmation. If the user confirms, the file is deleted from the server. "<<endl<<endl;
    cout<<"upload : \tSpecifies a filename on the client machine and sends it to the server. The server saves the uploaded file with the filename specified by the user. If this is not possible, the file is not uploaded. The max file size is 4GiB"<<endl<<endl;
    cout<<"list: \tThe client asks to the server the list of the filenames of the available files in his dedicated storage. The client prints to screen the list."<<endl<<endl;
    cout<<"rename : \tSpecifies a file on the server machine. Within the request, the clients sends the new filename. If the renaming operation is not possible, the filename is not changed."<<endl<<endl;
    cout<<"logout: \tThe client gracefully closes the connection with the server. "<<endl;
    cout<<"******************************************************************"<<endl<<endl; 
}

/**
 * Function that manage the upload command, takes as a parameter the name of the file that the user want to upload. The file must be located in a specific directory.
 * 
 * @param username: name of the file that the user wants to upload
 * @return int: exit param
 */
int Client::upload(string username){
    try{
        uint32_t counter = 0;

        cout<<"******************************************************************"<<endl;
        cout<<"                               UPLOAD                             "<<endl;
        cout<<"******************************************************************"<<endl<<endl;
        cout<<"-------------------------------------------------------"<<endl;
        cout<<"Which file do you want to upload on the cloud?"<<endl;
        string filename;
        cin>>filename;
        cout<<endl;

        if (filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
            std::cerr << "ERR: command check on whitelist fails"<<endl;
            throw -1;
        }

        //I need to be sure that no other file is in Download directory with the same name

        //filename is a string composed from whitelisted chars, so no path traversal allowed (see the cycle at 724)
        //We can proceed to check the existance of the file
        uint32_t size_file = file_exists(filename,username);
        if(size_file==0){
            cout<<"Error during upload"<<endl;
            throw -1;
        }

        /****************************************************************************************/
        /******* Phase 1: send filename, file length and other initialization parameters ********/

        //Phase needed to check if on the server is present another file with the same name of the one that the user want to upload
        //The server will send an ACK or NACK depending on its disponibility to recive the file

        //Packet initialization
        bootstrap_upload pkt;
        pkt.code = BOOTSTRAP_UPLOAD;
        pkt.filename = filename;
        pkt.filename_len = filename.length();
        pkt.response = 0;
        pkt.counter = counter;
        pkt.size = size_file;

        // Prepare the plaintext to encrypt
        string buffer = to_string(pkt.code) + "$" + to_string(pkt.filename_len) + "$" + filename + "$" + to_string(pkt.response) + "$" + to_string(pkt.counter) + "$" + to_string(pkt.size) + "$";

        if(!encrypt_generate_HMAC_and_send(buffer)){
            cerr<<"Error during encryption and send of MSG#1 of Upload"<<endl;
            throw -1;
        }

        counter++;
        /***************************************************************************************/
        // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 2 ******************** //

        //Receive the message, check the HMAC validity and decrypt the ciphertext
        unsigned char* plaintxt = receive_decrypt_and_verify_HMAC();

        if(plaintxt == nullptr){
            cerr<<"Error during receive_decrypt_and_verify_HMAC of MSG#2"<<endl;
            return -1;   //SOMETHING WRONG DURING RECEIVE, SEND AN END OF OPERATION MESSAGE
        }

        // Expected packet type
        bootstrap_upload rcvd_pkt;

        //Parsing and pkt parameters setting, it also FREE(PLAINTXT)
        if(!rcvd_pkt.deserialize_plaintext(plaintxt)){
            cerr<<"Received wrong message type!"<<endl;
            return -1;    //RECEIVED WRONG TYPE MESSAGE => TYPE EXIT OP
        }

        if(DEBUG){
            cout<<"You received the following cripted message: "<<endl;
            cout<<"Code: "<<rcvd_pkt.code<<";\n filename_len:"<<rcvd_pkt.filename_len<<";\n filename:"<<rcvd_pkt.filename<<";\n counter:"<<rcvd_pkt.counter<<";\n size: "<<rcvd_pkt.size<<endl;
        }
        // Check on rcvd packets values
        if( rcvd_pkt.counter != counter ){
            cerr<<"Wrong counter value, we received: "<<rcvd_pkt.counter<<" instead of: "<<counter<<endl;
            throw 1;    //SOMETHING WRONG DURING RECEIVE, SEND AN END OF OPERATION MESSAGE
        }
        if(DEBUG){
            cout<<"Counter with good value"<<endl;
        }
        // Check the response of the server
        if( rcvd_pkt.response != 1){
            cerr<<"There is already a file with the same name on the server! Rename or delete it before uploading a new one"<<endl;
            return -2;      //OPERATION ENDED -> NEGATIVE RESPONSE FROM SERVER
        }
        if(DEBUG){
            cout<<"Affirmative response"<<endl;
        }
        counter++;
        // If the server response is '1' the server is now ready to obtain the file
        /***************************************************************************************/
        // *************************** PHASE 2 SEND THE FILE: MSG 3 ************************** //

        cout<<"HANDLE FILE TRANSFER PHASE"<<endl;

        if(send_encrypted_file(filename, counter) != 0){
            cerr<<"error during the upload of the file"<<endl;
            throw 1;  //SOMETHING WRONG DURING FILE EXCANGE, SEND AN END OF OPERATION MESSAGE
        }
        

        cout<<"FILE TRANSFER PHASE COMPLETED"<<endl<<endl;

        /***************************************************************************************/
        // ******************************* SEND EOF NOTIF: MSG 4 ***************************** //

        end_upload pkt_end_1;
        pkt_end_1.code = FILE_EOF_HS;
        pkt_end_1.response = "END";
        pkt_end_1.counter = counter;

        // Prepare the plaintext to encrypt
        buffer =  to_string(pkt_end_1.code) + "$" + pkt_end_1.response + "$" + to_string(pkt_end_1.counter) + "$";

        if(!encrypt_generate_HMAC_and_send(buffer)){
            cerr<<"Error during encryption and send of MSG#4 of Upload"<<endl;
            throw 1;    //FILE EXCHANGED BUT SOMETHING WRONG DURING EOF HS, SEND AN END OF OPERATION MESSAGE
        }
        counter++;
        /***************************************************************************************/
        // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 5 ******************** //
  
        plaintxt = receive_decrypt_and_verify_HMAC();

        if(plaintxt == nullptr){
            cerr<<"Error during receive_decrypt_and_verify_HMAC"<<endl;
            return -1;  //SOMETHING WRONG DURING EOF HS RECEIVE, SEND AN END OF OPERATION MESSAGE
        }

        end_upload pkt_end_2;

        //Parsing and pkt parameters setting, it also FREE(plaintxt)
        if(!pkt_end_2.deserialize_plaintext(plaintxt)){
            cerr<<"Received wrong message type!"<<endl;
            return -1;  //WRONG MESSAGE TYPE IS ERROR_PKT
        }

        if(DEBUG){
            cout<<"You received the following cripted message: "<<endl;
            cout<<"Code: "<<pkt_end_2.code<<";\n filename:"<<pkt_end_2.response<<";\n counter:"<<pkt_end_2.counter<<endl;
        }

        // Check on rcvd packets values
        if( pkt_end_2.counter != counter ){
            cerr<<"Wrong counter value, we received: "<<pkt_end_2.counter<<" instead of: "<<counter<<endl;
            throw 1;    //SOMETHING WRONG DURING RECEIVE, SEND AN END OF OPERATION MESSAGE
        }

        // Check the response of the server
        if(strcmp(pkt_end_2.response.c_str(),"OK") != 0){
            cerr<<"There was a problem during the finalization of the upload!"<<endl;
            return -1;
        }
    }
    catch(int errorCode){

        cout<<"THE UPLOAD HAS FAILED"<<endl;
        if(errorCode == -1){
            return -2;
        }
        if(errorCode == 10){
            return -3;
        }
        if(errorCode == 1){
            exit_op pkt_exit;
            pkt_exit.response = "FAILED";
            pkt_exit.code = EXIT_OP;

            string buffer = to_string(pkt_exit.code) + "$" + pkt_exit.response + "$";

            if(!encrypt_generate_HMAC_and_send(buffer)){
                cerr<<"Sending of err msg failed"<<endl;
                return -4;
            }
        }

    }
    
    cout<<"THE UPLOAD HAS BEEN SUCCESSFUL!"<<endl;

    return 0;
}

/**
 * Function that manage the downlaod command, takes as a parameter the name of the file that the user want to download.
 * 
 * @param username : username of the user that want to download the file
 * @return int : 0 => success, !=0 => failure
 */
int Client::download(string username){
    try{
        uint32_t counter = 0;

        cout<<"******************************************************************"<<endl;
        cout<<"                               DOWNLOAD                           "<<endl;
        cout<<"******************************************************************"<<endl<<endl;
        cout<<"-------------------------------------------------------"<<endl;
        cout<<"Which file do you want to download from the cloud?"<<endl;

        string filename;
        cin>>filename;
        cout<<endl;

        if (filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
            std::cerr << "ERR: command check on whitelist fails"<<endl;
            return -1;
        }

        if(file_exists_to_download(filename, username)!=0){
            std::cerr << "ERR: file already inside download dir"<<endl;
            return -1;
        }

        /****************************************************************************************/
        /************** Phase 1: send filename and other initialization parameters **************/

        //Check if on server side there is a file with the same name
        //Packet initialization
        bootstrap_download pkt;
        pkt.code = BOOTSTRAP_DOWNLOAD;
        pkt.filename_len = strlen(filename.c_str());
        pkt.filename = filename;
        pkt.counter = counter;
        pkt.size = 0;

        // Prepare the plaintext to encrypt
        string buffer = to_string(pkt.code) + "$" + to_string(pkt.filename_len) + "$" + filename + "$" + to_string(pkt.counter) + "$" + to_string(pkt.size) + "$";

        if(!encrypt_generate_HMAC_and_send(buffer)){
            cerr<<"Error during encryption and send of MSG#1 of Upload"<<endl;
            throw 1;
        }

        counter++;

        /****************************************************************************************/

        //Receive the message, check the HMAC validity and decrypt the ciphertext
        unsigned char* plaintxt = receive_decrypt_and_verify_HMAC();

        if(plaintxt == nullptr){
            cerr<<"Error during receive_decrypt_and_verify_HMAC"<<endl;
            return -2;
        }

        // Expected packet type
        bootstrap_download rcvd_pkt;

        //Parsing and pkt parameters setting, it also FREE(PLAINTXT)
        if(!rcvd_pkt.deserialize_plaintext(plaintxt)){
            cerr<<"Received wrong message type!"<<endl;
            return -1;
        }

        if(DEBUG){
            cout<<"You received the following cripted message: "<<endl;
            cout<<"Code: "<<rcvd_pkt.code<<";\n filename_len:"<<rcvd_pkt.filename_len<<";\n filename:"<<rcvd_pkt.filename<<";\n counter:"<<rcvd_pkt.counter<<";\n size: "<<rcvd_pkt.size<<endl;
        }
        // Check on rcvd packets values
        if( rcvd_pkt.counter != counter ){
            cerr<<"Wrong counter value, we received: "<<rcvd_pkt.counter<<" instead of: "<<counter<<endl;
            throw 1;
        }
        // Check the response of the server
        if( rcvd_pkt.size == 0){
            cerr<<"File not found on the server"<<endl;
            return -2;
        }
        
        counter++;
        // If the size is != 0 the server is now ready to send the file 

        /**************************************************************************************************/
        // ******************************* PHASE 2 RECEIVE THE FILE: MSG 3 ****************************** //

        cout<<"HANDLE FILE TRANSFER PHASE"<<endl;

        if(!encrypted_file_receive(rcvd_pkt.size, filename, counter)){
            cerr<<"Phase 2 failed: error during file upload"<<endl;
            return -3;
        }

        cout<<"FILE TRANSFER PHASE COMPLETED"<<endl<<endl;

        /**************************************************************************************************/
        // ********************************* PHASE 3 FILE EOF HS : MSG 4 ******************************** //

        end_download pkt_end_1;

        plaintxt = receive_decrypt_and_verify_HMAC();

        if(plaintxt == nullptr){
            cerr<<"Error during receive_decrypt_and_verify_HMAC for MSG#4"<<endl;
            return -4;
        }

        //Parsing and pkt parameters setting, it also free 'plaintxt'
        if(!pkt_end_1.deserialize_plaintext(plaintxt)){
            cerr<<"Received wrong message type!"<<endl;
            return -4;
        }

        if(DEBUG){
            cout<<"You received the following cripted message: "<<endl;
            cout<<"Code: "<<pkt_end_1.code<<";\n filename:"<<pkt_end_1.response<<";\n counter:"<<pkt_end_1.counter<<endl;
        }

        // Check on rcvd packets values
        if( pkt_end_1.counter != counter ){
            cerr<<"Wrong counter value, we received: "<<pkt_end_1.counter<<" instead of: "<<counter<<endl;
            throw 1;
        }
        // Check the response of the server
        if(strcmp(pkt_end_1.response.c_str(),"END") != 0){
            cerr<<"There was a problem during the finalization of the upload!"<<endl;
            throw 1;
        }

        counter++;

        /*******************************************************************************/
        /**************************** LAST MESSAGE *************************************/

        end_download pkt_end_2;
        pkt_end_2.code = FILE_DL_HS;
        pkt_end_2.response = "OK";
        pkt_end_2.counter = counter;

        // Prepare the plaintext to encrypt
        buffer =  to_string(pkt_end_2.code) + "$" + pkt_end_2.response + "$" + to_string(pkt_end_2.counter) + "$";

        if(!encrypt_generate_HMAC_and_send(buffer)){
            cerr<<"Error during encrypt_generate_HMAC_and_send of MSG#5"<<endl;
            return -5;
        }
    }
    catch(int errorCode){
        
        cout<<"THE DOWNLOAD HAS FAILED"<<endl;

        if(errorCode == 1){
            exit_op pkt_exit;
            pkt_exit.response = "FAILED";
            pkt_exit.code = EXIT_OP;

            string buffer = to_string(pkt_exit.code) + "$" + pkt_exit.response + "$";

            if(!encrypt_generate_HMAC_and_send(buffer)){
                cerr<<"Sending of err msg failed"<<endl;
                return -4;
            }
        }


    }

    cout<<"THE DOWNLOAD HAS BEEN SUCCESSFUL!"<<endl;

    return 0;
}

// delete, rename, list
int Client::simple_operation(int operation){
    uint32_t counter = 0;
    string filename;
    string renamed_filename;

    if ( operation == BOOTSTRAP_DELETE ){
        cout<<"******************************************************************"<<endl;
        cout<<"                               DELETE                             "<<endl;
        cout<<"******************************************************************"<<endl<<endl;
        cout<<"-------------------------------------------------------"<<endl;
        cout<<"Which file do you want to delete on the cloud?"<<endl;
        cin>>filename;
        cout<<endl;
    }
    else if ( operation == BOOTSTRAP_RENAME ){
        cout<<"******************************************************************"<<endl;
        cout<<"                               RENAME                             "<<endl;
        cout<<"******************************************************************"<<endl<<endl;
        cout<<"-------------------------------------------------------"<<endl;
        cout<<"Which file do you want to rename on the cloud?"<<endl;
        cin>>filename;
        cout<<endl;
        cout<<"Insert the new name for the file: "<< filename<<endl;
        cin>>renamed_filename;
        cout<<endl;
    }
    else if ( operation == BOOTSTRAP_LIST ){
        cout<<"******************************************************************"<<endl;
        cout<<"                              LIST                                "<<endl;
        cout<<"******************************************************************"<<endl<<endl;
        cout<<"-------------------------------------------------------"<<endl;
        filename = "--";
    }

    // patht traversal
    if (filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
        std::cerr << "ERR: command check on whitelist fails"<<endl;
        return -1;
    }

    // patht traversal
    if (renamed_filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos){
        std::cerr << "ERR: command check on whitelist fails"<<endl;
        return -1;
    }

    //Packet initialization
    bootstrap_simple_operation pkt;
    pkt.code = BOOTSTRAP_SIMPLE_OPERATION;
    pkt.simple_op_code = operation;
    pkt.filename = filename;
    pkt.filename_len = strlen(filename.c_str());
    pkt.renamed_filename = renamed_filename;
    pkt.response = 0;
    pkt.counter = counter;
    string buffer;

    // Prepare the plaintext to encrypt
    if (pkt.simple_op_code == BOOTSTRAP_LIST || pkt.simple_op_code == BOOTSTRAP_DELETE) {
        buffer = to_string(pkt.code) + "$" + to_string(pkt.simple_op_code) + "$" + to_string(pkt.filename_len) 
        + "$" + filename + "$" + to_string(pkt.response) + "$" + to_string(pkt.counter)+ "$";
    }
    else if (pkt.simple_op_code == BOOTSTRAP_RENAME){
        buffer = to_string(pkt.code) + "$" + to_string(pkt.simple_op_code) + "$" + to_string(pkt.filename_len) 
        + "$" + filename + "$" + renamed_filename + "$" + to_string(pkt.response) + "$" + to_string(pkt.counter)+ "$";
    }

    if(!encrypt_generate_HMAC_and_send(buffer)){
        cerr<<"Error during encryption and send of MSG#1 of Delete"<<endl;
        return -1;
    }

    counter++;

    /***************************************************************************************/
    // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 2 ******************** //

    //Receive the message, check the HMAC validity and decrypt the ciphertext
    unsigned char* plaintxt = receive_decrypt_and_verify_HMAC();

    if(plaintxt == nullptr){
        cerr<<"Error during receive_decrypt_and_verify_HMAC of MSG#2"<<endl;
        return -2;
    }

    // Expected packet type
    bootstrap_simple_operation rcvd_pkt;

    //Parsing and pkt parameters setting, it also FREE(PLAINTXT)
    if(!rcvd_pkt.deserialize_plaintext(plaintxt)){
        cerr<<"Received wrong message type!"<<endl;
        return -2;
    }

    if(DEBUG){
        cout<<"You received the following cripted message: "<<endl;
        cout<<"Code: "<<rcvd_pkt.code<<";\n simple_code_op:"<<rcvd_pkt.simple_op_code<<";\n filename_len:"<<rcvd_pkt.filename_len<<";\n filename:"<<rcvd_pkt.filename<<";\n counter:"<<rcvd_pkt.counter<<endl;
    }

    // Check on rcvd packets values
    if( rcvd_pkt.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<rcvd_pkt.counter<<" instead of: "<<counter<<endl;
        return -2;
    }

    if(DEBUG){
        cout<<"Counter with good value"<<endl;
    }

    // Check the response of the server
    if( rcvd_pkt.response != 1 && rcvd_pkt.response != 2){

        if (operation == BOOTSTRAP_DELETE || operation == BOOTSTRAP_RENAME)
            cerr << "Operation Failed, file not found" << endl;
        else if (operation == BOOTSTRAP_LIST)
            cerr << "rename failed" << endl;
        return -2;
    }
    
    if(DEBUG){
        cout<<"Affirmative response"<<endl;
    }

    // response_output available (eg. list), i print it on stdout
    if (rcvd_pkt.response == 2 && rcvd_pkt.simple_op_code == BOOTSTRAP_LIST){
        cout <<"LIST OUTPUT: " <<endl <<endl;
        if(rcvd_pkt.response_output.compare("") == 0){
            cout <<"Files not found on the cloud" <<endl;
        }
        else{   
            cout << rcvd_pkt.response_output <<  endl;
        }
    }

    cout<<"THE OPERATION HAS BEEN SUCCESSFUL!"<<endl;

    return 0;
}

int Client::logout(){
    uint32_t counter = 0;
    string filename;
    int ret = 0;

    //Packet initialization
    bootstrap_logout pkt;
    pkt.code = BOOTSTRAP_LOGOUT;
    pkt.response = 0;
    pkt.counter = counter;

    // Prepare the plaintext to encrypt
    string buffer = to_string(pkt.code) + "$" + to_string(pkt.response) + "$" + to_string(pkt.counter) + "$";

    cout<<"-------------------------------------------------------"<<endl;

    if(!encrypt_generate_HMAC_and_send(buffer)){
        cerr<<"Error during encryption and send of MSG#1 of Delete"<<endl;
        return -2;
    }

    counter++;

    /***************************************************************************************/
    // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 2 ******************** //

    //Receive the message, check the HMAC validity and decrypt the ciphertext
    unsigned char* plaintxt = receive_decrypt_and_verify_HMAC();

    if(plaintxt == nullptr){
        cerr<<"Error during receive_decrypt_and_verify_HMAC of MSG#2"<<endl;
        ret = -1;
    }

    // Expected packet type
    bootstrap_logout rcvd_pkt;

    //Parsing and pkt parameters setting, it also FREE(PLAINTXT)
    if(!rcvd_pkt.deserialize_plaintext(plaintxt)){
        cerr<<"Received wrong message type!"<<endl;
        ret = -1;
    }

    if(DEBUG){
        cout<<"You received the following cripted message: "<<endl;
        cout<<"Code: "<<rcvd_pkt.code<<";\n response:"<<rcvd_pkt.response<<";\n counter:"<<rcvd_pkt.counter<<endl;
    }

    // Check on rcvd packets values
    if( rcvd_pkt.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<rcvd_pkt.counter<<" instead of: "<<counter<<endl;
        ret = -1;
    }

    if(DEBUG){
        cout<<"Counter with good value"<<endl;
    }

    // Check the response of the server
    if( rcvd_pkt.response != 1){
        cerr << "Send wrong feedback, disconnect anyway" << endl;
        ret = -1;
    }
    
    if(DEBUG){
        cout<<"Affirmative response"<<endl;
    }

    //secure frees
    secure_free(symmetric_key, symmetric_key_length);
    symmetric_key = nullptr;
    secure_free(hmac_key, hmac_key_length);
    hmac_key = nullptr;

    cout << "KEYS FREED CORRECTLY"<< endl;

    return ret;
}

// retrieve user certificate
X509* Client::get_certificate() {
	
	FILE* file = nullptr;
	X509* cert = nullptr;
	string dir = "./users/" + username + "/" + username + "_cert.pem";

	try {
		file = fopen(dir.c_str(), "r");
		if (!file) {
			cerr << "cannot find user certificate" << endl;
			throw 0;
		}

		cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
		if (!cert) {
			cerr << "cannot read user certificate correctly" << endl;
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

// get ca certificate
X509* Client::get_CA_certificate (){
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

// get ca crl
X509_CRL* Client::get_crl() {
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

// RUN
int Client::run(){
    try {

        // establish session and HMAC key
        if(!init_session()){
            cerr << "Session keys establishment failed" << endl;
            throw 1;
        }

        cout << "session keys has been established correctly " << endl<< endl;
    }
    catch (int error_code) {
        cout<<"Error during session initialization, exited with code: "<<error_code<<endl;
        return -1;
    }

    cout<<"******************************************************************"<<endl;
	cout<<"                            CLIENT STARTED                        "<<endl;
	cout<<"******************************************************************"<<endl<<endl;

    help();

    //vector that contains the command 
    vector <string> words{};

    while(true){
        string command;
        cout<<"-> Insert a command:"<<endl;
        cin>>command;
        cout<<endl;

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
                cout<<"-------------------------------------------------------"<<endl<<endl;
                continue;

            case 2:
                download(this->username);
                cout<<"-------------------------------------------------------"<<endl<<endl;
                continue;

            case 3:
                simple_operation(BOOTSTRAP_LIST);
                cout<<"-------------------------------------------------------"<<endl<<endl;
                continue;

            case 4:
                simple_operation(BOOTSTRAP_RENAME);
                cout<<"-------------------------------------------------------"<<endl<<endl;
                continue;

            case 5:
                simple_operation(BOOTSTRAP_DELETE);
                cout<<"-------------------------------------------------------"<<endl<<endl;
                continue;

            case 6:
                logout();
                cout<<"-------------------------------------------------------"<<endl<<endl;
                cout<<"******************************************************************"<<endl;
                cout<<"                              LOGOUT                              "<<endl;
                cout<<"******************************************************************"<<endl<<endl;
                close(session_socket);
                return 0;

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

