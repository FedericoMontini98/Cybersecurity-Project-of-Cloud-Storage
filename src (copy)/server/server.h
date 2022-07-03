#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <cstring>

// MACROS

#define BACKLOG_QUEUE_SIZE  50

class Server {
    int listener_socket = -1;
    sockaddr_in server_addr;
    int port;

    public:

    Server(const uint16_t port);
    ~Server();

    bool set_listener();
    int wait_for_client_connections(sockaddr_in* client_addr);

};

class Worker {

    Server* server;
    int socket_fd;
    sockaddr_in client_addr;

    public:

    Worker(Server* server, const int socket, const sockaddr_in addr);
    ~Worker();

    void run();

};