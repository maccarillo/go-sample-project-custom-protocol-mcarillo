package main

import (
	"fmt"
	"net"
)

func main() {
	// Start listening on port 8080
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()
	fmt.Println("Server is listening on port 8080...")

	for {
		// Accept an incoming connection
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err.Error())
			return
		}
		fmt.Println("New connection established")

		// Handle the connection in a new goroutine (optional, for concurrency)
		go handleConnection(conn)
	}
}

// Function to handle the connection (optional implementation for further tasks)
func handleConnection(conn net.Conn) {
	defer conn.Close()
	// Implement handling logic here
}
