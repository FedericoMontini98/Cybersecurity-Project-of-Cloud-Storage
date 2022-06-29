#include "client.h"

// CONSTRUCTOR
Client::Client(const uint16_t port){
    // Configure client_addr
    memset(&client_addr, 0, sizeof(client_addr));

    // set for IPv4 addresses
    client_addr.sin_family = AF_INET; 

    // set port
	client_addr.sin_port = htons(port);

    // all available interfaces will be binded
	client_addr.sin_addr.s_addr = INADDR_ANY;
}

// 