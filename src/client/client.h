#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <thread>
#include "./../common/communication_packets.h"


# define DEBUG true
# define MAX_USERNAME_LENGTH 30
# define MIN_USERNAME_LENGTH 3
# define MAX_FILENAME_LENGHT 30
# define USERNAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-"
# define FILENAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-."
# define FILE_FRAGMENTS_SIZE 4096
# define MAX_PKT_SIZE 4300
# define FILE_PATH "./users/"
# define FILE_MAX_SIZE 4294967296
# define IV_LENGTH 16
# define HMAC_KEY_SIZE 32

// MAYBE ADD SEND AND RECV BUFFER
class Client{
    int session_socket = -1;
    int port; // server port to connect
    const string server_ip = "127.0.0.1"; 
    sockaddr_in server_addr;
    string username;
	string filename_ca_certificate = "./Your Organisation CA_cert.pem";
	string filename_ca_crl = "./Your Organisation CA_crl.pem";

    /* must be freed */
    // when a new iv is generated this variable must be freed
    unsigned char* iv = nullptr;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

    // keys
    /* must be freed */
    EVP_PKEY* private_key = nullptr; 
	
	//EDIT set to nullptr
    unsigned char* symmetric_key = (unsigned char*) 
	"0123456789012345"; 
	
	//EDIT set to nullptr
    unsigned char* hmac_key = (unsigned char*)
	"01234567890123450123456789012345";

    public:
    Client(const uint16_t _port);
    ~Client();
    int run();
    bool extract_private_key(string _username, string password);
    bool init_session();
    bool init_socket();
    bool send_message(void* msg, const uint32_t len);
    int receive_message(unsigned char*& recv_buffer, uint32_t& len);
    bool generate_iv (const EVP_CIPHER* cipher);
    int generate_HMAC(unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen);
    int cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& ciphertext, int& cipherlen, bool _generate_iv);
    int cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, int& plainlen);
    int send_encrypted_file (string filename, uint32_t& counter);
    bool encrypted_file_receive(uint32_t size, string filename, uint32_t& counter);
    EVP_PKEY* generate_sts_key_param();
	X509* get_certificate();
	X509* get_CA_certificate();
	X509_CRL* get_crl();

    //Operational functions
    void help();
    int upload(string username);
    int download(string username);
    int simple_operation(int operation);

    //Utility functions
    uint32_t file_exists(string filename, string username);
    uint32_t file_exists_to_download(string filename, string username);

    // packets methods
    //Utility function
    unsigned char* receive_decrypt_and_verify_HMAC();
    unsigned char* receive_decrypt_and_verify_HMAC_for_files();
    bool encrypt_generate_HMAC_and_send(string buffer);
    bool encrypt_generate_HMAC_and_send(uint8_t* buffer, uint32_t msg_len);

    int send_login_bootstrap(login_bootstrap_pkt& pkt);
	int send_login_client_authentication(login_authentication_pkt& pkt);
};