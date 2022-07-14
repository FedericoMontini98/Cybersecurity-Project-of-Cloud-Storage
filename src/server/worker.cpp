#include "server.h"
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
void debug_serialize_pkt(uint8_t* buffer){
    login_bootstrap_pkt pkt;

    pkt.deserialize_message((uint8_t*) buffer);

    exit(EXIT_FAILURE);
}

// receive message from socket
// MAYBE DEFINE A RECV_BUFFER IN CLASS
int Worker::receive_message(){ //EDIT: MAYBE ADD CHECK ON THE MAXIMUM LENGHT OF A FRAGMENT: 4096
    ssize_t ret;
    uint32_t len; 
    unsigned char* recv_buffer;

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

    // handle command
    //handle_command(recv_buffer);

    // TEST SERIALIZATION
    debug_serialize_pkt(recv_buffer);

    // the content of the buffer is not needed anymore
    free(recv_buffer);

    return 0;
}


void Worker::run (){
    
    while(true){
        int ret = receive_message();

        // CLIENT DISCONNECTED
        if (ret == -2){
            exit(EXIT_FAILURE);
        }
    }
}
