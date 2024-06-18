package main

import (
	"fmt"
	"net"
	"os"
	"sync"
)

var clients = make(map[net.Conn]bool)
var mutex = &sync.Mutex{}

func checkOption() (bool, bool) {
	if len(os.Args) == 2 {
		return false, false
	} else if len(os.Args) == 3 && os.Args[2] == "-e" {
		return true, false
	} else if len(os.Args) == 4 && os.Args[2] == "-e" && os.Args[3] == "-b" {
		return true, true
	} else {
		fmt.Println("syntax : echo-server <port> [-e[-b]]")
		fmt.Println("sample : echo-server 1234 -e -b")
		panic("Invalid usage")
	}
}

func handler(conn net.Conn, isEcho bool, isBroadcast bool) {
	recv := make([]byte, 4096)
	for {
		n, err := conn.Read(recv)
		if err != nil {
			break
		}
		if n > 0 {
			fmt.Print(string(recv[:n]))
			if isEcho {
				if isBroadcast {
					conn.Write(recv[:n])
					broadcast(recv[:n], conn)
				} else {
					conn.Write(recv[:n])
				}
			}
		}
	}
	conn.Close()
	mutex.Lock()
	delete(clients, conn)
	mutex.Unlock()
}

func broadcast(message []byte, sender net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()
	for client := range clients {
		if client != sender {
			client.Write(message)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("syntax : echo-server <port> [-e[-b]]")
		fmt.Println("sample : echo-server 1234 -e -b")
		panic("Invalid usage")
	}

	port := os.Args[1]
	isEcho, isBroadcast := checkOption()

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic("Failed to listen")
	}
	defer ln.Close()
	fmt.Println("[+] Listening...")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Failed to accept")
			fmt.Println(err)
			continue
		}

		mutex.Lock()
		clients[conn] = true
		mutex.Unlock()
		go handler(conn, isEcho, isBroadcast)
	}
}
