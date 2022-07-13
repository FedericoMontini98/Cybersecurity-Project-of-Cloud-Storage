#include "./../common/errors.h"
#include <fstream>
#include <cstdint>
#include <vector>
#include "client.h"
#include "./../common/utility.h"
#include <sys/stat.h>
#include <sstream>


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

// send a message through socket and free msg
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
int Client::cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& iv, unsigned char*& ciphertext, 
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
int Client::cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char* iv, unsigned char*& plaintext, int& plainlen){
    int outlen;
    int ret;

    EVP_CIPHER_CTX* ctx;

    if (cipherlen == 0 || cipherlen > FILE_FRAGMENTS_SIZE) {
        cerr << "ERR: input cipher fragment exceeds the maximum size" << endl;
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

// encrypt using cbc_encrypt but for pieces of file
int Client::send_encrypted_file (string filename, unsigned char* iv, int iv_len, uint32_t& counter){
    unsigned char* buffer;

    // check filename on whitelist
    if (filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos)
    {
        std::cerr << "ERR: filename check on whitelist fails" << endl;
        return -1;
    }

    FILE* file = fopen(filename.c_str(), "rb"); 

    if (!file){
        return false;
    }

    int ret;

    // read while eof
    while ( !feof(file) ){
        buffer = (unsigned char*)malloc(FILE_FRAGMENTS_SIZE);

        if (!buffer) {
            std::cerr << "ERR: cannot allocate a buffer for the file fragment" << endl;
            return -1;
        }

        // read bytes from file, the pointer is automatically increased
        ret = fread(buffer, 1, FILE_FRAGMENTS_SIZE, file);

        if ( ferror(file) != 0 ){
            std::cerr << "ERR: file reading error occured" << endl;
            return -1;
        }

        unsigned char* ct;
        int len_ct;

        /*file_upload pkt;
        pkt.code = FILE_UPLOAD;
        pkt.msg = buffer;
        pkt.counter = counter;*/

        uint32_t cipherlen = strlen((char*)ct);

        //buffer = pkt.serialize_message();

        cbc_encrypt_fragment(buffer, ret, this->iv, ct, len_ct);

        if(!send_message((void*)ct, cipherlen)){
            cout<<"Error: send of a fragment failed"<<endl;
            return -1;
        }   

        //HMAC SEND TODO

        counter++;
        free(ct);
        free(buffer);
    }

    return 0;
}

// sent packet [username | sts_key_param | hmac_key_param]
//MISS CONTROLS AND FREES
int Client::send_login_boostrap(){
    login_bootstrap_pkt pkt;

    pkt.code = LOGIN_BOOTSTRAP;
    pkt.username = username;
    pkt.symmetric_key_param = generate_sts_key_param();
    pkt.hmac_key_param = generate_sts_key_param();

    if (!pkt.hmac_key_param || !pkt.symmetric_key_param){
        cerr << "ERR: failed to generate session keys parameters" << endl;
        return false;
    }

    if (!send_message(&pkt, sizeof(login_bootstrap_pkt))){
        cerr << "ERR: failed to send login bootstrap packet" << endl;
        return -1;
    }

    // handle response

    // if all is ok save the 2 parameters on the class field

    return 0;
    
}



// generate HMAC digest of a fragment (FILE_FRAGMENTS_SIZE)
int Client::generate_HMAC(EVP_MD* hmac_type, unsigned char* msg, int msg_len, unsigned char*& digest, unsigned*& digestlen){
    int ret;
    EVP_MD_CTX* ctx;

    if (msg_len == 0 || msg_len > FILE_FRAGMENTS_SIZE) {
        cerr << "message length is not allowed" << endl;
        return -1;
    }

    try{
        digest = (unsigned char*) malloc(EVP_MD_size(hmac_type));
        if (!digest){
            cerr << "malloc of digest failed" << endl;
            throw 1;
        }

        ctx = EVP_MD_CTX_new();

        if (!ctx){
            cerr << "context definition failed" << endl;
            throw 2;
        }

        ret = EVP_DigestInit(ctx, hmac_type);

        if (ret != 1) {
			cerr << "failed to initialize digest creation" << endl;
			ERR_print_errors_fp(stderr);
			throw 3;
		}

        ret = EVP_DigestUpdate(ctx, (unsigned char*)msg, sizeof(msg)); //try or put it in input function

        if (ret != 1) {
            cerr << "failed to update digest " << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
        }

        ret = EVP_DigestFinal(ctx, digest, digestlen);

        if (ret != 1) {
            cerr << "failed to finalize digest " << endl;
			ERR_print_errors_fp(stderr);
			throw 5;
        }

    }
    catch (int error_code){

        free(digest);
        
        if (error_code > 1){
            EVP_MD_CTX_free(ctx);
        }

        return -1;

    }

    return 0;
}

// generate the sts key parameter g**a (diffie-hellman) for the session key establishment
EVP_PKEY* Client::generate_sts_key_param(){
    EVP_PKEY* dh_params = nullptr;
    EVP_PKEY_CTX* dh_gen_ctx = nullptr;
    EVP_PKEY* dh_key = nullptr;
    int ret;

    try{
        // Allocate p and g
        dh_params = EVP_PKEY_new();
        if (!dh_params){
            cerr << "ERR: fail to generate new dh params" << endl;
            throw 0;
        }

        // set default dh parameters for p and g
        DH* default_params = DH_get_2048_224();
        ret = EVP_PKEY_set1_DH(dh_params, default_params);
        
        // no longer need of this variable
        DH_free(default_params);

        if (ret != 1) {
            cerr << "ERR: failed to load default params" << endl;
            throw 1;
        }

        // g^a or g^b
        dh_gen_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
		if (!dh_gen_ctx) {
            cerr << "ERR: failed to load define dh context" << endl;
            throw 2;
        }

        ret = EVP_PKEY_keygen_init(dh_gen_ctx);
		if (ret != 1) {
            cerr << "ERR: failed dh keygen init" << endl;
            throw 3;
        }

		ret = EVP_PKEY_keygen(dh_gen_ctx, &dh_key);
		if (ret != 1){ 
            cerr << "ERR: failed dh keygen" << endl;
            throw 4;
        }
    }
    catch (int error_code){

        if (error_code > 0){
            EVP_PKEY_free(dh_params);
        }
        
        if (error_code > 1) {
            EVP_PKEY_CTX_free(dh_gen_ctx);
        }

        return nullptr;
    }

    EVP_PKEY_CTX_free(dh_gen_ctx);
	EVP_PKEY_free(dh_params);

    return dh_key;

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

    // send login bootstrap packet
    if (send_login_boostrap() < 0){
        cerr << "something goes wrong in sending login bootstrap packet" << endl;
        return false;
    }

    unsigned char* receive_buffer;
    uint32_t len;
    // receive response
    if (receive_message(receive_buffer, len) < 0){
        cerr << "ERR: some error in receiving bootstrap login response occurred" << endl;
        return -1;
    }

    return true;
}

/**Check the existance of the file inside the upload directory
 *  @filename : file of which we have to check the existance
 *  @username : needed to find the current user directory 
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

/** Help function that shows all the available commands to the user
 */
void Client::help(){
    cout<<"===================================== HELP ================================================="<<endl<<endl;
    cout<<"The available commands are the following:"<<endl<<endl;
    cout<<"help: that shows all the available commands"<<endl<<endl;
    cout<<"download fileName: Specifies a file on the server machine. The server sends the requested file to the user. The filename of any downloaded file must be the filename used to store the file on the server. If this is not possible, the file is not downloaded."<<endl<<endl;
    cout<<"delete fileName: Specifies a file on the server machine. The server asks the user for confirmation. If the user confirms, the file is deleted from the server. "<<endl<<endl;
    cout<<"upload fileName: Specifies a filename on the client machine and sends it to the server. The server saves the uploaded file with the filename specified by the user. If this is not possible, the file is not uploaded. The max file size is 4GiB"<<endl<<endl;
    cout<<"list: The client asks to the server the list of the filenames of the available files in his dedicated storage. The client prints to screen the list."<<endl<<endl;
    cout<<"rename fileName newName: Specifies a file on the server machine. Within the request, the clients sends the new filename. If the renaming operation is not possible, the filename is not changed."<<endl<<endl;
    cout<<"logout: The client gracefully closes the connection with the server. "<<endl;
    cout<<"============================================================================================"<<endl<<endl; 
}

/**Function that manage the upload command, takes as a parameter the name of the file that the user want to upload. The file must be located in a specific directory.
 *  @filename : name of the file that the user wants to upload 
 *  @username : the username used to log in
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

    //Check if on server side there is a file with the same name
    //Packet initialization
    bootstrap_upload pkt;
    pkt.code = BOOTSTRAP_UPLOAD;
    pkt.filename = filename;
    pkt.response = 0;
    pkt.counter = counter;
    pkt.size = size_file;

    //Serialization of the data-structure
    int size_pkt;
    unsigned char* buffer = (unsigned char *)pkt.serialize_message(size_pkt);

    unsigned char* iv = this->iv;
    unsigned char* ciphertext;
    int cipherlen; 

    /******************************************************/
    /******* Phase 1: send iv + encrypt_msg + HMAC ********/

    //Message encryption
    if(cbc_encrypt_fragment(buffer, size_pkt, iv, ciphertext, cipherlen)!=0){
        cout<<"Error during encryption"<<endl;
        return -1;
    }
    
    //Send the iv
    if(!send_message((void *)iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()))){
        cout<<"Error during send #1"<<endl;
        return -1;
    }

    //send the cyphertext
    if(!send_message((void*)ciphertext, cipherlen)){
        cout<<"Error during send #2"<<endl;
        return -1;
    }

    //Generation of the HMAC
    //generate_HMAC()
    //send the HMAC
    //if(!send_message((void*)hmac, /*hmacsize*/)){
    //  cout<<"Error during send #3"<<endl;
    //  return;
    //}

    counter++;

    /******************************************************/
    /******** Phase 2: receive encrypt_msg + HMAC *********/
    uint32_t size;
    //receive the encrypted message
    if(receive_message(ciphertext,size)!=0){
        cout<<"Error during a receive"<<endl;
        return -1;
    }
    //Get the cyphertext received size
    int size_pt;
    uint64_t size_ct = strlen((char*)ciphertext);

    //Cyphertext decryption with session key
    if (cbc_decrypt_fragment(ciphertext,size_ct, iv, buffer, size_pt) != 0){
        cout << "Error during decryption" << endl;
        return -1;
    }

    //receive the encrypted message
    /*
    if(receive_message(&HMAC)!=0){
        cout<<"Error during the communication with the server"<<endl;
        return -1;
    }*/

    //TODO 
    //CHECK HMAC VALIDITY
    /*if(!check_HMAC(HMAC,cyphertext, iv, counter)){
        cout<<"received HMAC not valid"<<endl;
        return;
    }
    */

    //pkt.deserialize_message(buffer);    //TODO

    if(pkt.response == false){
        cout<<"A file with this name is already in the cloud, rename it locally and try again"<<endl;
        return -1;
    }

    counter++;

    /******************************************************/
    /************* Phase 3: send file chunks **************/

    if(send_encrypted_file (filename, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()),counter)!=0){
        cout << "Error during phase 3 of the upload" << endl;
        return -1;
    }

    /******************************************************/
    /*********** Phase 4: send completion msg *************/



    /******************************************************/
    /*********** Phase 5: send completion msg *************/
    
    //Free the allocated space
    free(ciphertext);
    free(buffer);
    free(this->iv);
    return 0;
}

/**Function that manage the downlaod command, takes as a parameter the name of the file that the user want to download.
 *  @filename : name of the file that the user wants to download 
 *  @username : the username used to log in
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
    if(cbc_encrypt_fragment(buffer, pkt_len, iv, ciphertext, cipherlen)!=0){
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
    free(iv)
    return 0;
}

// RUN
int Client::run(){
    cout << "RUN" <<endl;

    try {

        // establish session and HMAC key
        if(!init_session()){
            cerr << "Session keys establishment failed" << endl;
            throw 1;
        }

        cout << "session keys has been established correctly " << endl;
    }
    catch (int error_code) {

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
}*/


