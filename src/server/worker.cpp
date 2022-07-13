#include "server.h"
#include "./../common/utility.h"

Worker::Worker (Server* server, const int socket, const sockaddr_in addr){
    server = server;
    socket_fd = socket;
    client_addr = addr;
}

Worker::~Worker(){
    // if keys are nullptr frees do nothing
    EVP_PKEY_free(private_key);
    //free(symmetric_key); //for testing leave this comment when symmetric_key is a constant
    free(hmac_key);      
    free(iv);
}

// to test serialization
/*void debug_serialize_pkt(uint8_t* buffer){
    login_bootstrap_pkt pkt;

    pkt.deserialize_message((uint8_t*) buffer);

    exit(EXIT_FAILURE);
}*/

// receive message from socket
// MAYBE DEFINE A RECV_BUFFER IN CLASS
int Worker::receive_message(unsigned char&* recv_buffer, uint32_t& len){ //EDIT: MAYBE ADD CHECK ON THE MAXIMUM LENGHT OF A FRAGMENT: 4096
    ssize_t ret;
    uint32_t len; 

    // receive message length
    ret = recv(socket_fd, &len, sizeof(uint32_t), 0);

    if (ret == 0){
        cerr << "ERR: client disconnected" << endl;
        return -2;
    }

    if (ret < 0 || (unsigned long)ret < sizeof(len)){
        cerr << "ERR: message length received is too short" << endl;
        return -1;
    }

    try{
        // allocate receive buffer
        len = ntohl(len);
        recv_buffer = (unsigned char*) malloc (len);

        if (DEBUG) {
            cout << "msg_len of received message is: " << len << endl;
        }


        if (!recv_buffer){
            cerr << "ERR: recv_buffer malloc fail" << endl;
            throw 1;
        }

        // receive message
        ret = recv(socket_fd, recv_buffer, len, 0);

        if (ret == 0){
            cerr << "ERR: client disconnected" << endl;
            throw 2;
        }

        if (ret < 0 || (unsigned long)ret < sizeof(len)){
            cerr << "ERR: message received is too short" << endl;
            throw 3;
        }
    }
    catch (int error_code){

        free(recv_buffer);

        if (error_code == 2){
            return -2;
        }
        else{
            return -1;
        }

    }

    return 0;
}

bool Worker::check_username(string username){
	
	// IMPLEMENT
	
	return true;
}

// init session with client, the worker act as slave
bool Worker::init_session(){
	login_bootstrap_pkt bootstrap_pkt;
	ogin_server_authentication_pkt server_auth_pkt;
	
	// receive bootstrap_pkt
	while (true)
	
		// receive message
		if (receive_message(receive_buffer, len) < 0){
			cerr << "ERR: some error in receiving login_bootstrap_pkt" << endl;
			free(receive_buffer);
			continue;
		}
		
		// check if it is consistent with server_auth_pkt
		if (!login_bootstrap_pkt.deserialize(receive_buffer)){
			cerr << "ERR: some error in deserialize login_bootstrap_pkt" << endl;
			free(receive_buffer);
			continue;
		}
		
		// check username (WE NEED A READ THAT IS THREAD SAFE)
		if (!check_username(login_bootstrap_pkt.username)){
			cerr << "ERR: username "+login_bootstrap_pkt.username+ " is not registered" << endl;
			free(receive_buffer);
			continue;
		}	
		
		// correct packet
		free(receive_buffer);
		break;
	}
	
	// generate the params (and then delete them), the freshness is get using dh params
	
	// derive key using login_bootstrap_pkt.symmetric_key_param and hmac one
	
	// hash the keys
	
	// generate iv
	
	// send login_server_authentication_pkt
	
}


void Worker::run (){
	
	init_session()
    
    while(true){
        int ret = receive_message();
		
		/* --ERROR HANDLES-- */

        // CLIENT DISCONNECTED
        if (ret == -2){
            exit(EXIT_FAILURE);
        }
		
		/* --ERROR HANDLES-- */
		
		// handle command
		handle_command(recv_buffer);

		// the content of the buffer is not needed anymore
		free(recv_buffer);
    }
}
