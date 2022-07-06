#include "server.h"

// CONSTRUCTOR
Server::Server(const uint16_t port){
    // Configure server_addr
    memset(&server_addr, 0, sizeof(server_addr));

    // set for IPv4 addresses
    server_addr.sin_family = AF_INET; 

    // set port
	server_addr.sin_port = htons(port);

    // all available interfaces will be binded
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
}

// DESTRUCTOR
Server::~Server(){
    free(private_key);
}

// set the socket listener of the server
bool Server::set_listener(){

    // check if listener is already defined
    if (listener_socket != -1){
        return false;
    }

    // ipv4 + tcp
    listener_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (listener_socket == -1) {
        perror("ERR: socket definition failed");
        return false;
    }
    
    // bind and listen
    if (bind(listener_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        perror("ERR: socket bind failed");
        return false;
    }

    if (listen(listener_socket, BACKLOG_QUEUE_SIZE) == -1){
        perror("ERR: socket is not listening");
        return false;
    }

    // all function calls succeed
    return true;

}

int Server::wait_for_client_connections(sockaddr_in* client_addr){
    socklen_t addr_len = sizeof(client_addr);
  
    return accept(listener_socket, (sockaddr*)client_addr, &addr_len);
}