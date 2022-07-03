#include "server.h"

    Worker::Worker (Server* server, const int socket, const sockaddr_in addr){
        server = server;
        socket_fd = socket;
        client_addr = addr;
    }

    void run (){
        
        while(true){
            //do stuff
        }
    }
