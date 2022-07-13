#include "server.h"

int Worker::handle_command(unsigned char* cmd) {
    const char* ptr;
    int code;

    // read the code
    std::copy(ptr, ptr+sizeof(int), reinterpret_cast<char*>(code));

    if (DEBUG) {
        cout << code << endl;
    }

}



