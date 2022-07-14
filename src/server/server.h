#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <cstring>
#include <openssl/ssl.h>
#include "./../common/communication_packets.h"

# define DEBUG true
# define BACKLOG_QUEUE_SIZE  10

class Server {
    int listener_socket = -1;
    sockaddr_in server_addr;
    int port;
    EVP_PKEY* private_key = nullptr;

    public:

    Server(const uint16_t port);
    ~Server();

    bool set_listener();
    int wait_for_client_connections(sockaddr_in* client_addr);

};

// MAYBE ADD SEND AND RECV BUFFER
class Worker {
    Server* server;
    int socket_fd;
    sockaddr_in client_addr;

    /* must be freed */
    // when a new iv is generated this variable must be freed
    unsigned char* iv = nullptr;

    // keys
    /* must be freed */
    EVP_PKEY* private_key = nullptr; // contain a copy of the private_key of the server
    unsigned char* symmetric_key = (unsigned char*) "0123456789012345"; //EDIT set to nullptr
    unsigned char* hmac_key = nullptr;

    public:

    Worker(Server* server, const int socket, const sockaddr_in addr);
    ~Worker();
    int receive_message();
    int handle_command(unsigned char* cmd);
	bool check_username(string username);

    void run();

};