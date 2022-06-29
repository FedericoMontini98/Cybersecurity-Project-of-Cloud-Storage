#include "client.h"
using namespace std;

int main(int argc, char** argv) {

    if (argc < 2) {
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

    // ask username and maybe check if exists?
    string username;
    cin >> username;
    if (!cin){
        exit(EXIT_FAILURE);
    }

    // ask password and see if is it correct
    //PEM_read_PrivateKey(prvkey_file, NULL, NULL, (void*)client_password.c_str()); //forse è meglio che la pass sia 
    //cancellata subito dalla memoria e non venga usata come campo

    Client client = Client(port);

    // read input commands and sends it to the server
    client.run();

}