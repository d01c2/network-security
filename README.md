# tcp-block
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Write a program that blocks websites by using TCP packet injection (including RST and FIN flags) in an out-of-path environment

## Instructions
```
make
./tcp-block wlan0 "Host: test.gilgil.net"
```

## Details
- Receive packets using the pcap library, which is a representative of out of path.
- If a pattern is detected in the TCP Data area of the received packet, a blocking packet is sent to both sides.
- Forward sends packets with RST flags (test using wget or a web browser on your own machine).
- Backward sends a packet with the FIN flag and TCP Data of "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n". The reverse packets you send to yourself should be sent using a raw socket, as pcap may not work on Linux.

## Additional
You should also upload the project file(Makefile) along with source code files.