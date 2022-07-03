CC = g++
LFLAGS = -pthread -lcrypto
CFLAGS = -wall -g

all: client

client: main.o client.o

	$(CC) $(CFLAGS) -o main.cpp client.cpp $(LFLAGS) -o client.exe

client.o: client.cpp

	$(CC) $(CFLAFS) client.cpp

main.o: main.cpp

	$(CC) $(CFLAFS) main.cpp

clean:
	rm *.o client
