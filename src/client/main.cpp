#include "client.h"

int main(int argc, char** argv) {
    if (argc != 2) {    
		cerr << "ERR: no parameter port" << endl;
		exit(EXIT_FAILURE);
	}

    // port to string and to unsigned integer
    string port_str (argv[1]); 
	unsigned long port = stoul(port_str); 

	// Check uint16_t overflow
	if (port > numeric_limits<uint16_t>::max()) {
		cerr << "ERR: input port overflow" << endl;
		exit(EXIT_FAILURE);
	}

    // client definition
    Client client = Client(port);

    // ask username 
    cout<<"Insert your username"<<endl;
    string username;
    cin >> username;
    if (!cin){
        exit(EXIT_FAILURE);
    }
    
    //Check on the username length
    if (username.length() > 32 || username.length() <= 1){
        cerr << "Username bounds not respected: the username must have a number of character that stays between 2 and 32 char"<<endl;
        exit(EXIT_FAILURE);
    }

    cout<<"Insert your password"<<endl; 
    string password;
    cin >> password;
    if (!cin){
        exit(EXIT_FAILURE);
    }

    if (!client.check_password(username, password)){
        cout << "Username does not exists or password is wrong" <<endl;
        exit(EXIT_FAILURE);
    }

    // read input commands and sends it to the server
    client.run();

}