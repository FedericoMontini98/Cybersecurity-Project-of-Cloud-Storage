#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <cstring>


class Client{
    int socket_fd = -1;
    sockaddr_in client_addr;
    int port;
    string username;

    public:
    Client(const uint16_t port);
    ~Client();
    void run();

};