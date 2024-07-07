# arp-spoof
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Write a program that performs ARP Spoofing Attack.

## Instructions
```
make
./arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

## Details
- Implement code to relay spoofed IP packets sent from the sender when received by the attacker.
- Implement code to accurately identify the point at which the infection is recovered from the sender and re-infect it.
- Implement code to handle multiple (sender, target) flows.
- If possible, implement functionality to periodically send ARP infect packets.
- If possible, enable relay for jumbo frames (packets with larger sizes).
- The attacker, sender, and target must be physically separate machines.

## Additional
You should also upload the project file(Makefile) along with source code files.
