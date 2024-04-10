# send-arp
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Write a program that poisons Sender's ARP cache table.

## Instructions
```
make
./send-arp wlan0 192.168.10.2 192.168.10.1
```

## Details
- Sender is also called as Victim.
- Target is primarily the Gateway.
- Configure the program to handle multiple pairs of (Sender, Target).
- Get Attacker's MAC address by interface.
- Get Sender's MAC address automatically by sending normal ARP request and analyzing the reply
- Send an ARP infection packet and poison ARP cache

## Additional
You should also upload the project file(Makefile) along with source code files.
