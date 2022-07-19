#include "server.h"

int Worker::handle_command(unsigned char* received_mes) {

    unsigned char*  MACStr;
    uint32_t MAC_len; 
    unsigned char* HMAC;
    unsigned char* plaintxt;
    int ptlen;
    int code;

    generic_message first_pkt;
    cout<<"****************************************************"<<endl;
    cout<<"****************COMMAND HANDLER*********************"<<endl;
    cout<<"****************************************************"<<endl;
	try {
        
        if(!first_pkt.deserialize_message(received_mes)){
            cerr<<"Deserialize of the first packet failed!"<<endl;
            // va fatta la free del received?
            throw 0;
        }
        this->iv = first_pkt.iv;
        MACStr = (unsigned char*)malloc(IV_LENGTH + first_pkt.cipher_len);
        memcpy(MACStr, first_pkt.iv, IV_LENGTH);
        memcpy(MACStr + 16,(void*)first_pkt.ciphertext.c_str(),first_pkt.cipher_len);

        //Generate the HMAC on the receiving side iv||ciphertext
        generate_HMAC(MACStr,IV_LENGTH + first_pkt.cipher_len, HMAC,MAC_len);
        //Free
        free(MACStr);

        //HMAC Verification
        if(!verify_SHA256_MAC(HMAC,first_pkt.HMAC)){
            cerr<<"Error: HMAC cant be verified"<<endl;
            throw 1;
        }

        //Decrypt the ciphertext and obtain the plaintext
        if(cbc_decrypt_fragment((unsigned char* )first_pkt.ciphertext.c_str(),first_pkt.cipher_len, plaintxt,ptlen)!=0){
            cerr<<"Error during the decryption of the first packet"<<endl;
            throw 2;
        }

        code = first_pkt.deserialize_code(plaintxt);
        if(code == -1){
            cerr<<"error in identifying the code!"<<endl;
            throw 0;
        }


        /*********  FREE HOW TO HANDLE ********/
        switch(code) {
            /**************************************************************************************/
            case BOOTSTRAP_UPLOAD:
            {
                bootstrap_upload pkt_u;
                //Parsing and pkt parameters setting, it also free 'plaintxt'
                if(!pkt_u.deserialize_plaintext(plaintxt)){
                    cerr<<"Received wrong message type!"<<endl;
                    throw 0;
                }
                int ret = upload(pkt_u);
                return ret;
            }
            /**************************************************************************************/
            case BOOTSTRAP_DOWNLOAD:     
            {
                bootstrap_download pkt_d;
                //Parsing and pkt parameters setting, it also free 'plaintxt'
                if(!pkt_d.deserialize_plaintext(plaintxt)){
                    cerr<<"Received wrong message type!"<<endl;
                    throw 0;
                }
                int ret = download(pkt_d);
                return ret;
            }
            /**************************************************************************************/
            // delete, rename, list
            case BOOTSTRAP_SIMPLE_OPERATION:
            {
                bootstrap_simple_operation pkt_simple;
                //Parsing and pkt parameters setting, it also free 'plaintxt'
                if(!pkt_simple.deserialize_plaintext(plaintxt)){
                    cerr<<"Received wrong message type!"<<endl;
                    throw 0;
                }
                int ret = simple_operation(pkt_simple);
                return ret;
            }
            /**************************************************************************************/
            case BOOTSTRAP_LOGOUT:
            {
                return 0;
            }
            /**************************************************************************************/
        }

    }
    catch(int error_code){
		if (error_code > 0) {
            free(HMAC);
		}
		if (error_code > 1) {
            free(plaintxt);
		}
		return -1;
    }
    return 0;
}

/**
 * @brief Check the presence of the file inside the user dir
 * 
 * @param filename : name of the file to check the existance
 * @return true : the file doesnt exists
 * @return false : the file doesnt exists
 */
bool Worker::checkFileExistance(string filename){
    string path = FILE_PATH + this->logged_user + "/" + filename;
    struct stat buffer;
    if (stat(path.c_str(),&buffer)!=0){ //stat failed the file doesnt exists
        return false;
    }
    return true;
}

/**
 * @brief Function that check the existance of the file and return the file size
 * 
 * @param filename name of the file to download
 * @return size_t size of the file, 0 if is not present
 */
size_t Worker::checkFileExistanceAndGetSize(string filename){
    string path = FILE_PATH + this->logged_user + "/" + filename;
    struct stat buffer;
    if (stat(path.c_str(),&buffer)!=0){ //stat failed the file doesnt exists
        return 0;
    }
    return buffer.st_size;
}

/**
 * @brief Manage the file upload
 * 
 * @param size size of the uploaded file
 * @param filename name of the uploaded file
 * @return true : receive successful
 * @return false : receive failed
 */
bool Worker::encrypted_file_receive(uint32_t size, string filename, uint32_t& counter){
    string path = FILE_PATH + this->logged_user + "/" + filename;
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

/**
 * Function that send the specified file through chunks of specified max size
 * 
 * @param filename : name of the file to send
 * @param counter : current counter number
 * @return int : result of the operation => 0 = success
 */
int Worker::send_encrypted_file (string filename, uint32_t& counter){
    // build a string that cointain the path of the file
    string path = FILE_PATH + this->logged_user + "/" + filename;
    //open the file
    FILE* file = fopen(path.c_str(), "rb"); 
    // If !file the file cant be open or is not present inside the dir
    if (!file){
        cerr<<"Error during file opening"<<endl;
        return false;
    }
    struct stat buf;
    if (stat(path.c_str(),&buf)!=0){ //stat failed
        cout<<"Failed stat function: File doesn't exists in the Upload dir"<<endl;
        return 0;
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
 * @brief function that manage the upload request from the client
 * 
 * @param pkt packet received that contains the information needed to start the upload
 * @return int error code, if =0 its a success
 */
int Worker::upload(bootstrap_upload pkt){
    uint32_t counter = pkt.counter;
    if(DEBUG){
        cout<<"Received an upload packet with the following fields: "<<endl;
        cout<<"code: "<<pkt.code<<"\nfilename_len: "<<pkt.filename_len<<"\n filename: "<<pkt.filename<<"\n response: "<<pkt.response<<"\n counter: "<<counter<<"\n size: "<<pkt.size<<endl;
    }

    if (pkt.filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos)
    {
        cerr << "ERR: filename check on whitelist fails"<<endl;
        return -1;
    }

    /**********************************************************/
    /******* Phase 1: received iv + encrypt_msg + HMAC ********/
    cout<<"***********************************************"<<endl;
    counter = counter +1;
    bootstrap_upload response_pkt;

    //Check if there is a file with the same name inside the user dir
    if(checkFileExistance(pkt.filename)){
        cerr<<"File already inside the user dir, delete or rename before upload"<<endl;
        response_pkt.response = 0;  //Upload not possible 
    }
    else
        response_pkt.response = 1;
    //Fill the other fields
    response_pkt.code = BOOTSTRAP_UPLOAD;
    response_pkt.filename = string("--");
    response_pkt.filename_len = strlen(response_pkt.filename.c_str());
    response_pkt.counter = counter;
    response_pkt.size = 0;

    // Prepare the plaintext to encrypt
    string pt = to_string(response_pkt.code) + "$" + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.response) + "$" + to_string(response_pkt.counter) + "$" + to_string(response_pkt.size) + "$";

    //Send the MSG
    if(!encrypt_generate_HMAC_and_send(pt)){
        cerr<<"Error during MSG#2 send"<<endl;
        return -2;
    }

    if(response_pkt.response == 0){
        cout<<"Upload aborted due to a duplicated name"<<endl;
        cout<<"***********************************************"<<endl;
        return -1;
    }

    counter++;
    cout<<"***********************************************"<<endl;
    /**********************************************************/
    /*************** Phase 2: receive the file ****************/

    if(!encrypted_file_receive(pkt.size,pkt.filename, counter)){
        cerr<<"Phase 2 failed: error during file upload"<<endl;
        return -3;
    }
    cout<<"***********************************************"<<endl;
    /**********************************************************/
    /**************** Phase 3: EOF Handshake ******************/

    
    end_upload pkt_end_1;

    unsigned char* plaintxt = receive_decrypt_and_verify_HMAC();

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
        cout<<"Code: "<<pkt_end_1.code<<";\n response:"<<pkt_end_1.response<<";\n counter:"<<pkt_end_1.counter<<endl;
    }

    // Check on rcvd packets values
    if( pkt_end_1.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<pkt_end_1.counter<<" instead of: "<<counter<<endl;
        return -4;
    }
    // Check the response of the server
    if(strcmp(pkt_end_1.response.c_str(),"END") != 0){
        cerr<<"There was a problem during the finalization of the upload!"<<endl;
        return -4;
    }

    counter++;
    cout<<"***********************************************"<<endl;
    /*******************************************************************************/
    /**************************** LAST MESSAGE *************************************/

    end_upload pkt_end_2;
    pkt_end_2.code = FILE_EOF_HS;
    pkt_end_2.response = "OK";
    pkt_end_2.counter = counter;

    // Prepare the plaintext to encrypt
    pt =  to_string(pkt_end_2.code) + "$" + pkt_end_2.response + "$" + to_string(pkt_end_2.counter) + "$";

    if(!encrypt_generate_HMAC_and_send(pt)){
        cerr<<"Error during encrypt_generate_HMAC_and_send of MSG#5"<<endl;
        return -5;
    }

    cout<<"***************************************************************************************"<<endl;
    cout<<"************************ THE UPLOAD HAS BEEN SUCCESSFUL! ******************************"<<endl;


    return 0;
}

/**
 * @brief function that manage the download request from the client
 * 
 * @param pkt packet received that contains the information needed to start the download
 * @return int error code, if =0 its a success
 */
int Worker::download(bootstrap_download pkt){
    uint32_t counter = pkt.counter;
    if(DEBUG){
        cout<<"Received an upload packet with the following fields: "<<endl;
        cout<<"code: "<<pkt.code<<"\nfilename_len: "<<pkt.filename_len<<"\n filename: "<<pkt.filename<<"\n counter: "<<counter<<"\n size: "<<pkt.size<<endl;
    }

    if (pkt.filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos)
    {
        cerr << "ERR: filename check on whitelist fails"<<endl;
        return -1;
    }

    /**********************************************************/
    /******* Phase 1: received iv + encrypt_msg + HMAC ********/
    counter++;
    bootstrap_download response_pkt;

    //Check if there is a file with the same name inside the user dir
    response_pkt.size = checkFileExistanceAndGetSize(pkt.filename); // = 0 if the file doesnt exists
    //Fill the other fields
    response_pkt.code = BOOTSTRAP_DOWNLOAD;
    response_pkt.filename = string("--");
    response_pkt.filename_len = strlen(response_pkt.filename.c_str());
    response_pkt.counter = counter;

    // Prepare the plaintext to encrypt
    string buffer = to_string(response_pkt.code) + "$" + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.counter) + "$" + to_string(response_pkt.size);

    //Send the MSG
    if(!encrypt_generate_HMAC_and_send(buffer)){
        cerr<<"Error during MSG#2 send"<<endl;
        return -2;
    }
    counter++;

    /***************************************************************************************/
    /****************************** Phase 2: send the file *********************************/

    if(send_encrypted_file(pkt.filename,counter) != 0){
        cerr<<"Phase 2 failed: error during file send in Download"<<endl;
        return -3;
    }

    /***************************************************************************************/
    /************************** Phase 3: send the eof MSG #4 *******************************/

    end_download pkt_end_1;
    pkt_end_1.code = FILE_DL_HS;
    pkt_end_1.response = "END";
    pkt_end_1.counter = counter;

    // Prepare the plaintext to encrypt
    buffer =  to_string(pkt_end_1.code) + "$" + pkt_end_1.response + "$" + to_string(pkt_end_1.counter);

    if(!encrypt_generate_HMAC_and_send(buffer)){
        cerr<<"Error during encryption and send of MSG#4 of Upload"<<endl;
        return -4;
    }
    counter++;

    /***************************************************************************************/
    // ******************** RECEIVE THE ANSWER FROM THE SERVER: MSG 5 ******************** //
    unsigned char* plaintxt;
    plaintxt = receive_decrypt_and_verify_HMAC();

    if(plaintxt == nullptr){
        cerr<<"Error during receive_decrypt_and_verify_HMAC"<<endl;
        return -5;
    }

    end_download pkt_end_2;

    //Parsing and pkt parameters setting, it also FREE(plaintxt)
    if(!pkt_end_2.deserialize_plaintext(plaintxt)){
        cerr<<"Received wrong message type!"<<endl;
        return -5;
    }

    if(DEBUG){
        cout<<"You received the following cripted message: "<<endl;
        cout<<"Code: "<<pkt_end_2.code<<";\n response:"<<pkt_end_2.response<<";\n counter:"<<pkt_end_2.counter<<endl;
    }

    // Check on rcvd packets values
    if( pkt_end_2.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<pkt_end_2.counter<<" instead of: "<<counter<<endl;
        return -5;
    }

    // Check the response of the server
    if(strcmp(pkt_end_2.response.c_str(),"OK") != 0){
        cerr<<"There was a problem during the finalization of the download!"<<endl;
        return -5;
    }

    cout<<"***************************************************************************************"<<endl;
    cout<<"************************ THE DOWNLOAD HAS BEEN SUCCESSFUL! ******************************"<<endl;

    return 0;
}

// perform one of the operations between delete, list, and remove
int Worker::simple_operation( bootstrap_simple_operation pkt ){
    uint32_t counter = pkt.counter;
    bootstrap_simple_operation response_pkt;
    string pt;
    string dir = "./users/" + logged_user + "/" + pkt.filename;

    if(DEBUG){
        cout<<"Received an simple_operation packet with the following fields: "<<endl;
        cout<<"Code: "<<pkt.code<<";\n simple_code_op:"<<pkt.simple_op_code<<";\n filename_len:"<<pkt.filename_len<<";\n filename:"<<pkt.filename<<";\n counter:"<<pkt.counter<<endl;
    }

    counter = counter + 1;
    response_pkt.code = BOOTSTRAP_SIMPLE_OPERATION;
    response_pkt.simple_op_code = pkt.simple_op_code;
    response_pkt.filename_len = strlen(pkt.filename.c_str()); 
    response_pkt.filename = pkt.filename;
    response_pkt.response = 0;
    response_pkt.counter = counter;

    try {
        if (pkt.filename.find_first_not_of(FILENAME_WHITELIST_CHARS) != std::string::npos)
        {
            cerr << "ERR: filename check on whitelist fails"<<endl;
            throw 1;
        }

        /**********************************************************/
        /******* Phase 1: received iv + encrypt_msg + HMAC ********/
        cout<<"***********************************************"<<endl;

        // filename is -- in this case
        if (pkt.simple_op_code == BOOTSTRAP_LIST){
            // DO LIST

            // IMPLEMENT

            // FAIL
            response_pkt.response = 0;

            // SUCCESS (PUT DATA IN response_pkt.response_output)
            response_pkt.response = 2;
        }

        else if (pkt.simple_op_code == BOOTSTRAP_RENAME){
            // DO RENAME

            //Check if there is a file with the same name inside the user dir
            if(!checkFileExistance(pkt.filename.c_str())){
                cerr<<"File does not exist, delete failed"<<endl;
                response_pkt.response = 0;  // Delete not possible 
                throw 2;
            }
            // IMPLEMENT rename on dir

            //FAIL
            response_pkt.response = 0;

            // SUCCESS 
            response_pkt.response = 1;
        }

        else if (pkt.simple_op_code == BOOTSTRAP_DELETE){
            // DO DELETE

            //Check if there is a file with the same name inside the user dir
            if(!checkFileExistance(pkt.filename.c_str())){
                cerr<<"File does not exist, delete failed"<<endl;
                response_pkt.response = 0;  // Delete not possible 
                throw 2;
            }
            else{
                //try to remove the file
                if( remove( dir.c_str() ) != 0 ){
                    cerr << "Error in removing file, delete fails" << endl;
                    response_pkt.response = 0;
                    throw 2;
                }
                else{
                    cout << "DELETE SUCCESS on user: " + logged_user + " for file: " + pkt.filename << endl;
                    response_pkt.response = 1;
                }
            }
        }

        if (response_pkt.response == 0 || response_pkt.response == 1){
            // Prepare the plaintext to encrypt
            pt = to_string(response_pkt.code) + "$" + to_string(response_pkt.simple_op_code) + "$" 
            + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.response) 
            + "$" + to_string(response_pkt.counter);
        }
        else if (response_pkt.response == 2){
            // Prepare the plaintext to encrypt with response_output
            pt = to_string(response_pkt.code) + "$" + to_string(response_pkt.simple_op_code) + "$" 
            + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.response) 
            + "$" + to_string(response_pkt.counter) + "$" + response_pkt.response_output;
        }

        //Send the feedback message
        if(!encrypt_generate_HMAC_and_send(pt)){
            cerr<<"Error during MSG#2 send"<<endl;
            throw 2;
        }
    }
    catch(int error_code){

        if(DEBUG)
            cout << "counter is:" + counter << endl;

        // SEND FAILURE PACKET
        if (response_pkt.response == 0 || response_pkt.response == 1){
            // Prepare the plaintext to encrypt
            pt = to_string(response_pkt.code) + "$" + to_string(response_pkt.simple_op_code) + "$" 
            + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.response) 
            + "$" + to_string(response_pkt.counter);
        }
        else if (response_pkt.response == 2){
            // Prepare the plaintext to encrypt with response_output
            pt = to_string(response_pkt.code) + "$" + to_string(response_pkt.simple_op_code) + "$" 
            + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.response) 
            + "$" + to_string(response_pkt.counter) + "$" + response_pkt.response_output;
        }

        //Send the feedback message
        if(!encrypt_generate_HMAC_and_send(pt)){
            cerr<<"Error during MSG#2 send"<<endl;
        }

        if (error_code == 1){
            return -1;
        }
        else if (error_code == 2){
            return -2;
        }

    }
    
    return 0;
}



