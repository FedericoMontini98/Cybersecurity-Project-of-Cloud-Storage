# Cybersecurity Project of a Cloud Storage

University project for the *Foundations of Cybersecurity* course (MSc Computer Engineering) by Fabrizio Lanzillo, Federico Montini e Niko Salamini.

Design of a Client-Server application that resembles a Cloud Storage.

Developed in C++14 with OpenSSL 1.1.1 Library for Linux systems and consists of 2 different programs:
- client.exe
- server.exe

We recommend the use of the commands inside the makefiles, for the correct compilation of the programs.
Both programs, client and server, need the server port number as an argument at execution time.

## Structure of the repository

```
Cybersecurity Project of Cloud Storage
|
├── docs
│   ├── Cloud Storage Project Documentation.pdf
│   ├── Project-guidelines-2022.pdf
│   └── Credentials.txt
|
└── src
    ├── client
    ├── common
    └── server     
```

# How to run
- Compile using the commands inside the makefiles.
- Run both client and server by specifying the port as a paramenter and remembering to have root privileges
