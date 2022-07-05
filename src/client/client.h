#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
using namespace std;

#define USERNAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-"
#define FILENAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-."
#define FILE_FRAGMENTS_SIZE 4096

class Client{
    int session_socket = -1;
    int port;
    const string server_ip = "127.0.0.1";
    sockaddr_in server_addr;
    string username;
    EVP_PKEY* private_key; /*must be freed*/
    unsigned char* session_key = (unsigned char*) "0123456789012345";

    public:
    Client(const uint16_t _port);
    ~Client();
    void run();
    bool extract_private_key(string _username, string password);
    bool initialize_session();
    bool init_socket();
    bool send_message(void* msg, const uint32_t len);
    unsigned char* generate_iv (const EVP_CIPHER* cipher);
    int cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& iv, unsigned char*& ciphertext, int& cipherlen);
    int cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char* iv, unsigned char*& plaintext, int& plainlen);
    int send_encrypted_file (string filename, unsigned char* iv, int iv_len);
};