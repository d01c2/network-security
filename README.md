# pcap-test
`pcap-test` is the assignment repository for the `System Network Security` course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Write a program that captures packets and prints important information including:
- Ethernet Header - src mac / dst mac
- IP Header - src ip / dst ip
- TCP Header - src port / dst port
- Payload(Data) - hexadecimal value (MAX 20 bytes)

## Instructions
```
make
./pcap-test wlan0
```

## Details
- Print the information above only when TCP packets are captured.
- Use network library or define custom structures for packet header structure.

## Additional
You should also upload the project file(Makefile) along with source code files.