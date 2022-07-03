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

// DESTRUCTOR
Client::~Client(){
    free(private_key);
}

// check if password is ok and extract the private key 
bool Client::check_password(string username, string password){
    string dir;

    if (username.find_first_not_of(USERNAME_WHITELIST_CHARS) != std::string::npos)
    {
        std::cerr << "ERR: username check on whitelist fails"<<endl;
        return false;
    }

    // default dir for users
    dir = "./users/" + username + "/" + username + "_key.pem";
    FILE* file = fopen(dir.c_str(), "r");

    if (!file){
        return false;
    }

    EVP_PKEY* privk = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());

    fclose(file);

    if (privk == NULL){
        return false;
    }

    private_key = privk;
    return true;
    
}

// RUN
void Client::run(){
    cout << "RUN" <<endl;
}