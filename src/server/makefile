CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++14 -Wno-unknown-pragmas #does not work without lssl 
CFLAGS = -c -Wall 

all: server.exe

server.exe: main.o server.o worker.o command_handler.o utility.o

	$(CC) main.o server.o worker.o command_handler.o utility.o $(LFLAGS) -o server.exe 

server.o: server.cpp

	$(CC) $(CFLAGS) server.cpp

worker.o: worker.cpp

	$(CC) $(CFLAGS) worker.cpp

command_handler.o: command_handler.cpp

	$(CC) $(CFLAGS) command_handler.cpp

utility.o: ./../common/utility.cpp

	$(CC) $(CFLAGS) ./../common/utility.cpp

main.o: main.cpp

	$(CC) $(CFLAGS) main.cpp

clean:
	rm *.o server.exe
