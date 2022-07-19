#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <thread>
#include <fstream>
#include <cstring>
#include <string>
#include <openssl/ssl.h>
#include <vector>
#include <string.h>
#include "./../common/communication_packets.h"
#include <sys/stat.h>
#include <math.h>

# define DEBUG true
# define BACKLOG_QUEUE_SIZE  10
# define FILE_FRAGMENTS_SIZE 4096
# define HMAC_KEY_SIZE 32
# define MAX_PKT_SIZE 8300
# define FILE_PATH "./users/"
# define USERNAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-"
# define FILENAME_WHITELIST_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_-."

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
	string logged_user;
	string filename_certificate = "./Server_cert.pem";
	string filename_ca_certificate = "./Your Organisation CA_cert.pem";
	string filename_ca_crl = "./Your Organisation CA_crl.pem";

    /* must be freed */
    // when a new iv is generated this variable must be freed
    unsigned char* iv = nullptr;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

    // keys
    /* must be freed */
    EVP_PKEY* private_key = nullptr; // contain a copy of the private_key of the server
	
    /*//EDIT set to nullptr
    unsigned char* symmetric_key = (unsigned char*) 
	"0123456789012345"; 
	
	//EDIT set to nullptr
    unsigned char* hmac_key = (unsigned char*)
	"01234567890123450123456789012345";*/
	
	unsigned char* symmetric_key = nullptr;
	unsigned char* hmac_key = nullptr;

    public:

    Worker(Server* server, const int socket, const sockaddr_in addr);
    ~Worker();
    int generate_HMAC(unsigned char* msg, size_t msg_len, unsigned char*& digest, uint32_t& digestlen);
	bool send_message(void* msg, const uint32_t len);
    int receive_message(unsigned char*& recv_buffer, uint32_t& len);
	int cbc_encrypt_fragment (unsigned char* msg, int msg_len, unsigned char*& ciphertext, int& cipherlen, bool _generate_iv);
    int cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, int& plainlen);
    int handle_command(unsigned char* cmd);
	bool load_private_server_key();
	EVP_PKEY* generate_sts_key_param();
	bool check_username(string username);
	bool generate_iv (const EVP_CIPHER* cipher);
	bool init_session();
	int send_login_server_authentication(login_authentication_pkt& pkt);
	X509* get_certificate();
	X509* get_CA_certificate();
    bool encrypted_file_receive(uint32_t size, string filename, uint32_t& counter);
    int send_encrypted_file (string filename, uint32_t& counter);
	X509_CRL* get_crl();

    //Commands
    int upload(bootstrap_upload pkt);
    int download(bootstrap_download pkt);
    int simple_operation(bootstrap_simple_operation pkt); //rename, list, delete

    //Utility function
    unsigned char* receive_decrypt_and_verify_HMAC();
    unsigned char* receive_decrypt_and_verify_HMAC_for_files();
    bool encrypt_generate_HMAC_and_send(string buffer);
    bool checkFileExistance(string filename);
    size_t checkFileExistanceAndGetSize(string filename);

    void run();

};