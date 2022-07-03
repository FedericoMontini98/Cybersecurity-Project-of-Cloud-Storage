CC = g++
LFLAGS = -Wall -pthread -lcrypto -std=c++14 -Wno-unknown-pragmas 
CFLAGS = -c -Wall 

all: client.exe

client.exe: main.o client.o

	$(CC) main.o client.o $(LFLAGS) -o client.exe # or try $(CC) $(LFLAGS) main.o client.o -o client.exe

client.o: client.cpp

	$(CC) $(CFLAGS) client.cpp

main.o: main.cpp

	$(CC) $(CFLAGS) main.cpp

clean:
	rm *.o client
