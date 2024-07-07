# echo-server
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Build simple TCP echo server

## Instructions
```
make
./echo-server 1234 -e -b
```

## Details
- It uses socket-related functions (socket, connect, send, recv, bind, listen, accept, etc.).
- echo-client (a.k.a. client) makes a TCP connection to echo-server (server).
- The client receives messages from the user and delivers them to the server.
- The server prints the received message to the screen and sends it to client verbatim if the "-e" (echo) option is given.
- The server sends the message to all connected clients if the "-b" (broadcast) option is given.
- When the client receives a message from the server, it prints it to the screen.
- The server must be able to handle multiple client connection requests and data processing (hint: thread).

## Additional
You should also upload the project file(Makefile) along with source code files.