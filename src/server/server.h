#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <openssl/ssl.h>
#include <communication_packets.h>

# define DEBUG true
# define BACKLOG_QUEUE_SIZE  10

class Server {
    int listener_socket = -1;
    sockaddr_in server_addr;
    int port;
    EVP_PKEY* private_key;

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
    unsigned char* session_key;
    EVP_PKEY* private_key; //contains a copy of private key of the server

    public:

    Worker(Server* server, const int socket, const sockaddr_in addr);
    ~Worker();
    int receive_message();
    int handle_command(unsigned char* cmd);

    void run();

};