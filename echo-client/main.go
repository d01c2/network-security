package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

var reader = bufio.NewReader(os.Stdin)

func echo(conn net.Conn) {
	recv := make([]byte, 4096)
	for {
		n, err := conn.Read(recv)
		if err != nil {
			break
		}
		if n > 0 {
			fmt.Print(string(recv[:n]))
		}
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("syntax : echo-client <ip> <port>")
		fmt.Println("sample : echo-client 192.168.10.2 1234")
		panic("Invalid usage")
	}

	ip := os.Args[1]
	port := os.Args[2]

	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		panic("Failed to connect to server")
	}
	defer conn.Close()

	go echo(conn)

	for {
		msg, _ := reader.ReadString('\n')
		if _, err := conn.Write([]byte(msg)); err != nil {
			fmt.Println("Failed to send data to server")
			break
		}
	}
}
