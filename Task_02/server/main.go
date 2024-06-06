package main

import (
	"bufio"
	//"crypto/sha256"
	"fmt"
	"net"
	"strings"
)

var (
	storedUsername     = "user1"
	storedPasswordHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd21b5bb2f7d24e869e" // SHA-256 hash of "password"
)

func authenticate(username, passwordHash string) bool {
	return username == storedUsername && passwordHash == storedPasswordHash
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Simple Authentication
	fmt.Println("Waiting for username...")
	username, _ := reader.ReadString('\n')
	fmt.Println("Waiting for password hash...")
	passwordHash, _ := reader.ReadString('\n')

	username = strings.TrimSpace(username)
	passwordHash = strings.TrimSpace(passwordHash)

	if !authenticate(username, passwordHash) {
		fmt.Println("Authentication failed for", username)
		conn.Write([]byte("Authentication failed\n"))
		return
	}

	fmt.Println("Authentication successful for", username)
	conn.Write([]byte("Authentication successful\n"))

}

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

		// Handle the connection
		go handleConnection(conn)
	}
}
