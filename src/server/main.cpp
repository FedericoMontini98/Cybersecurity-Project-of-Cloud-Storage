#include "server.h"
using namespace std;

// start a new worker thread for handling the communication
void new_worker_thread(Server* server, const int socket, const sockaddr_in addr){
    Worker worker = Worker(server, socket, addr);
    worker.run();

    // finish run and close socket
    close(socket);
}

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

    // server definition
    Server server = Server(port);

    // set listener
    if (!server.set_listener()){
        exit(EXIT_FAILURE);
    }

    cout << "Success: listener set correctly" << endl;

    // client address structure
    sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));

    while (true){
        int new_socket = server.wait_for_client_connections(&client_addr);

        if (new_socket == -1){
            perror("ERR: new connection to client failed");
            continue;
        }

        // start a new thread to handle the communication, 
        thread worker_thread(new_worker_thread, &server, new_socket, client_addr);

        // detach from main thread
		worker_thread.detach();
    }
}