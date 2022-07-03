#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <cstring>
#include <openssl/pem.h>
using namespace std;

#define USERNAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-"

class Client{
    int socket_fd = -1;
    sockaddr_in client_addr;
    int port;
    string username;
    EVP_PKEY* private_key; /*must be freed*/

    public:
    Client(const uint16_t port);
    ~Client();
    void run();
    bool check_password(string username, string password);
};