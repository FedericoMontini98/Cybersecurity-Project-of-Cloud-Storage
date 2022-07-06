#include "server.h"

Worker::Worker (Server* server, const int socket, const sockaddr_in addr){
    server = server;
    socket_fd = socket;
    client_addr = addr;
}

Worker::~Worker(){
    free(session_key);
    EVP_PKEY_free(private_key);
}

// receive message from socket
// MISS free
int Worker::receive_message(){ //EDIT: MAYBE ADD CHECK ON THE MAXIMUM LENGHT OF A FRAGMENT: 4096
    ssize_t ret;
    uint32_t len; 
    unsigned char* recv_buffer;

    // receive message length
    ret = recv(socket_fd, &len, sizeof(uint32_t), 0);

    if (DEBUG) {
        cout << len << endl;
    }

    if (ret == 0){
        cerr << "ERR: client disconnected" << endl;
        return -2;
    }

    if (ret < 0 || (unsigned long)ret < sizeof(len)){
        cerr << "ERR: message length received is too short" << endl;
        return -1;
    }

    try{
        // convert len to host format
        len = ntohl(len);

        // allocate receive buffer
        
        if (!DEBUG) {
            recv_buffer = (unsigned char*) malloc (len);
        }
        else {
            // make the receive buffer printable adding '\0'
            recv_buffer = (unsigned char*) malloc (len+1);
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

    if (DEBUG){
        recv_buffer[len] = '\0'; 
        printf("%s\n", recv_buffer);
    }

    // handle command
    handle_command(recv_buffer);
    free(recv_buffer);

    return 0;
}

void Worker::run (){
    
    while(true){
        receive_message();
    }
}
