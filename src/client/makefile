CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++14 -Wno-unknown-pragmas #does not work without lssl 
CFLAGS = -c -Wall 

all: client.exe

client.exe: main.o client.o

	$(CC) main.o client.o $(LFLAGS) -o client.exe 
	#$(CC) $(LFLAGS) main.o client.o -o client.exe

client.o: client.cpp

	$(CC) $(CFLAGS) client.cpp

main.o: main.cpp

	$(CC) $(CFLAGS) main.cpp

clean:
	rm *.o client.exe
