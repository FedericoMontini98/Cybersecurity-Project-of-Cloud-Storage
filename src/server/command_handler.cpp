#include "server.h"

int Worker::handle_command(unsigned char* received_mes) {

    unsigned char*  MACStr;
    uint32_t MAC_len; 
    unsigned char* HMAC;
    unsigned char* plaintxt;
    int ptlen;
    unsigned short int code;

    received_message first_pkt;

	try {
        
        if(!first_pkt.deserialize_message(received_mes)){
            cerr<<"Deserialize of the first packet failed!"<<endl;
            // va fatta la free del received?
            throw 0;
        }

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
            case 1:
                // code block
                break;
            case 5:
                
                bootstrap_upload pkt;
                //Parsing and pkt parameters setting, it also free 'plaintxt'
                if(!pkt.deserialize_plaintext(plaintxt)){
                    cerr<<"Received wrong message type!"<<endl;
                    throw 0;
                }

                int ret = upload(pkt);
                break;
                // code block
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

}

/**
 * @brief Check the presence of the file inside the user dir
 * 
 * @param filename : name of the file to check the existance
 * @return true : the file doesnt exists
 * @return false : the file doesnt exists
 */
bool checkFileExistance(string filename){
    string path = FILE_PATH + this->logged_user + "/" + filename;
    if(DEBUG){
        cout<<"PATH: "<<path<<endl;
    }
    struct stat buffer;
    if (stat(path.c_str(),&buffer)!=0){ //stat failed the file doesnt exists
        return false;
    }
    return true;
}

/**
 * @brief Manage the file upload
 * 
 * @param size size of the uploaded file
 * @param filename name of the uploaded file
 * @return true : receive successful
 * @return false : receive failed
 */
bool Worker::encrypted_file_receive(uint32_t size, string filename, uint32_t counter){
    string path = FILE_PATH + this->logged_user + "/" + filename;
    //number of file chunk expected
	unsigned int num_chunks = ceil((float) size/FILE_FRAGMENTS_SIZE);
    if(DEBUG)
	    cout << "Number of chunks: " << num_chunks << endl << endl;

	//opening file on disk
	ofstream file(path, ios::out|ios::binary);
	if(!file.is_open()){
		cerr << "error opening the file\n";
	}
    //Prepare the buffer
    unsigned char* buffer;
    buffer = (unsigned char*)malloc(FILE_FRAGMENTS_SIZE);
    if(!buffer){            
        cerr << "ERR: cannot allocate a buffer for the file fragment" << endl;
        return false;
    }
    memset(buffer,0,FILE_FRAGMENTS_SIZE);
    unsigned char* data;
	for(uint32_t i = 0; i < num_chunks; ++i){
        //Receive the message
        uint32_t length_rec;
        if(!receive_message(data, length_rec)){
            cerr << "ERR: during the receive of fragment n°: "<< i << endl;
            free(data);
            return -2;
        }
        file_upload pkt;
        if(!pkt.deserialize_message(data)){
            cerr<<"Error during deserialization of packet n°: "<< i <<endl;
            return -2;
        }

        uint32_t MAC_len; 
        unsigned char*  MACStr = (unsigned char*)malloc(IV_LENGTH + pkt.cipher_len);
        unsigned char* HMAC;

        MACStr = (unsigned char*)malloc(IV_LENGTH + pkt.cipher_len);
        memcpy(MACStr,pkt.iv, IV_LENGTH);
        memcpy(MACStr + 16,(void*)pkt.ciphertext.c_str(),pkt.cipher_len);

        //Generate the HMAC on the receiving side iv||ciphertext
        generate_HMAC(MACStr,IV_LENGTH + pkt.cipher_len, HMAC,MAC_len);
        //Free
        free(MACStr);

        //HMAC Verification
        if(!verify_SHA256_MAC(HMAC,pkt.HMAC)){
            cout<<"HMAC cant be verified, try again"<<endl;
            return -2;
        }

        unsigned char* plaintxt;
        int ptlen;
        this->iv = pkt.iv;

        //Decrypt the ciphertext and obtain the plaintext
        if(cbc_decrypt_fragment((unsigned char* )pkt.ciphertext.c_str(),pkt.cipher_len,plaintxt,ptlen)!=0){
            cout<<"Error during encryption"<<endl;
            return -2;
        }

        //Parsing and pkt parameters setting, it also free 'plaintxt'
        if(!pkt.deserialize_plaintext(plaintxt)){
            cerr<<"Received wrong message type!"<<endl;
            return -2;
        }

        // Check for a replay attack
        if(counter!= pkt.counter){
            cerr<<"Wrong counter value, received "<<pkt.counter<<" instead of "<<counter<<endl;
            return -2;
        }

        cout<<"HMAC verified, counter with the right value and ciphertext deciphered correctly at iteration: "<<i<<endl;

        //copying chunk on disk
		file.seekp(i*FILE_FRAGMENTS_SIZE, ios::beg);
		int remaining = size - i*FILE_FRAGMENTS_SIZE;
		size_t byte_to_write = min(FILE_FRAGMENTS_SIZE, remaining);
		file.write((const char*)pkt.msg, byte_to_write);


        memset(buffer,0,FILE_FRAGMENTS_SIZE);
        free(data);
        free(pkt.iv);
        free(pkt.HMAC);
        free(HMAC);
        counter++;
    }

    return true;
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

    /**********************************************************/
    /******* Phase 1: received iv + encrypt_msg + HMAC ********/

    counter++;
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

    unsigned char* ciphertext;
    int cipherlen;

    // Prepare the plaintext to encrypt
    string buffer = to_string(response_pkt.code) + "$" + to_string(response_pkt.filename_len) + "$" + response_pkt.filename + "$" + to_string(response_pkt.response) + "$" + to_string(response_pkt.counter) + "$" + to_string(response_pkt.size);

    // Encryption
    if(cbc_encrypt_fragment((unsigned char*)buffer.c_str(), strlen(buffer.c_str()), ciphertext, cipherlen, true)!=0){
        cout<<"Error during encryption"<<endl;
        return -2;
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
        cout<<"Error during packet #2 forwarding"<<endl;
        free(MACStr);
        free(ciphertext);
        return -2;
    }
    free(MACStr);
    free(ciphertext);
    free(pkt.HMAC);
    free(pkt.iv);
    counter++;

    /**********************************************************/
    /*************** Phase 2: receive the file ****************/

    if(!encrypted_file_receive(pkt.size,pkt.filename, counter)){
        cerr<<"Phase 2 failed: error during file upload"<<endl;
        return -3;
    }

    /**********************************************************/
    /**************** Phase 3: EOF Handshake ******************/

    uint32_t length_rec;
    unsigned char* plaintxt;
    int ptlen;

    if(!receive_message(data, length_rec)){
        cerr << "ERR: some error in receiving MSG2 in upload" << endl;
		free(data);
		return -6;
    }

    end_upload pkt_end_1;
    if(!pkt_end_1.deserialize_message(data)){
        cerr<<"Received the wrong packet!"<<endl;
        return -6;
    }

    MACStr = (unsigned char*)malloc(IV_LENGTH + pkt_end_1.cipher_len);
    memcpy(MACStr,pkt_end_1.iv, IV_LENGTH);
    memcpy(MACStr + 16,(void*)pkt_end_1.ciphertext.c_str(),pkt_end_1.cipher_len);

    //Generate the HMAC on the receiving side iv||ciphertext
    generate_HMAC(MACStr,IV_LENGTH + pkt_end_1.cipher_len, HMAC,MAC_len);
    //Free
    free(MACStr);

    //HMAC Verification
    if(!verify_SHA256_MAC(HMAC,pkt_end_1.HMAC)){
        cerr<<"Error: HMAC cant be verified"<<endl;
        return -6;
    }

    //Decrypt the ciphertext and obtain the plaintext
    if(cbc_decrypt_fragment((unsigned char* )pkt_end_1.ciphertext.c_str(),pkt_end_1.cipher_len, plaintxt,ptlen)!=0){
        cerr<<"Error during encryptionof packet #6"<<endl;
        return -6;
    }

    //Parsing and pkt parameters setting, it also free 'plaintxt'
    if(!pkt_end_1.deserialize_plaintext(plaintxt)){
        cerr<<"Received wrong message type!"<<endl;
        return -6;
    }

    if(DEBUG){
        cout<<"You received the following cripted message: "<<endl;
        cout<<"Code: "<<pkt_end_1.code<<";\n filename:"<<pkt_end_1.response<<";\n counter:"<<pkt_end_1.counter<<endl;
    }

    // Check on rcvd packets values
    if( pkt_end_1.counter != counter ){
        cerr<<"Wrong counter value, we received: "<<pkt_end_1.counter<<" instead of: "<<counter<<endl;
        return -6;
    }
    // Check the response of the server
    if(!strcmp(pkt_end_1.response.c_str(),"END")){
        cerr<<"There was a problem during the finalization of the upload!"<<endl;
        return -6;
    }

    cout<<"Received EOF Message"<<endl;

    counter++;

    /*******************************************************************************/
    /**************************** LAST MESSAGE *************************************/

    end_upload pkt_end_2;
    pkt_end_2.code = FILE_EOF_HS;
    pkt_end_2.response = "OK";
    pkt_end_2.counter = counter;

    // Prepare the plaintext to encrypt
    buffer =  to_string(pkt_end_2.code) + "$" + pkt_end_2.response + "$" + to_string(pkt_end_2.counter);

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
    pkt_end_2.ciphertext = (const char*)ciphertext;
    pkt_end_2.cipher_len = cipherlen;
    generate_HMAC(MACStr,IV_LENGTH + cipherlen, HMAC, MAC_len);
    pkt_end_2.HMAC = HMAC;

    data = (unsigned char*)pkt_end_2.serialize_message(data_length);

    //Send the EOF message
    if(!send_message((void *)data, data_length)){
        cout<<"Error during packet #5 forwarding"<<endl;
        free(MACStr);
        free(ciphertext);
        return -1;
    }

    free(MACStr);
    free(ciphertext);

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

    return 0;
}



