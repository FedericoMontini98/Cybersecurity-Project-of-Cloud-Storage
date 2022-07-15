CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++14 -Wno-unknown-pragmas #does not work without lssl 
CFLAGS = -c -Wall 

all: client.exe

client.exe: main.o client.o utility.o hashing_util.o

	$(CC) main.o client.o utility.o hashing_util.o $(LFLAGS) -o client.exe 
	#$(CC) $(LFLAGS) main.o client.o -o client.exe

client.o: client.cpp

	$(CC) $(CFLAGS) client.cpp

utility.o: ./../common/utility.cpp 
	
	$(CC) $(CFLAGS) ./../common/utility.cpp

hashing_util.o: ./../common/hashing/hashing_util.cpp

	$(CC) $(CFLAGS) ./../common/hashing/hashing_util.cpp

main.o: main.cpp

	$(CC) $(CFLAGS) main.cpp

clean:
	rm *.o client.exe
