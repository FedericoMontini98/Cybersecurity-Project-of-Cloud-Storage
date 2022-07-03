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
    
    //Check on the username lenght
    if (username.lenght() > 32 || username.lenght() <= 1){
        cerr << "Username bounds not respected: the username must have a number of character that stays between 2 and 32 char"<<endl;
        exit(EXIT_FAILURE);
    }

    //whitelisted chars
    static char ok_chars[]="abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "1234567890_-.@";

    //Check for malicious chars using white-listing
    if(strspn(username, ok_chars) < username.lenght() ){
        cerr << "Your username include invalid chars, if you're trying to penetrate our system please stop"<<endl;
        exit(EXIT_FAILURE);
    }

    cout<<"Insert your password"<<endl; 
    string password;
    cin >> password;
    if (!cin){
        exit(EXIT_FAILURE);
    }

    if (!client.check_password(username, password)){
        cout << "wrong password" <<endl;
        exit(EXIT_FAILURE);
    }

    // read input commands and sends it to the server
    client.run();

}