package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"strings"
)

var (
	storedUsername     = "user1"
	storedPasswordHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" // SHA-256 hash of "password"
)

func calculateCRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func validateChecksum(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	receivedChecksum := binary.BigEndian.Uint32(data[len(data)-4:])
	calculatedChecksum := calculateCRC32(data[:len(data)-4])
	return receivedChecksum == calculatedChecksum
}

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

	for {
		// Read message type
		messageType, err := reader.ReadByte()
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println("Connection closed by client")
				return
			}
			fmt.Println("Error reading message type:", err)
			return
		}

		if messageType == 0x01 {
			// Read the text length
			lengthBuf := make([]byte, 4)
			_, err := reader.Read(lengthBuf)
			if err != nil {
				fmt.Println("Error reading text length:", err)
				return
			}
			textLength := binary.BigEndian.Uint32(lengthBuf)

			// Read the message including the checksum
			message := make([]byte, textLength+4)
			_, err = reader.Read(message)
			if err != nil {
				fmt.Println("Error reading message:", err)
				return
			}

			//requirements checker
			fmt.Printf("Received message: %x, %s, %T\n", message, string(message[:textLength]), message[:textLength])

			//message, _ := reader.ReadBytes('\n')
			if validateChecksum(message) {
				fmt.Println("Received valid message:", string(message[:len(message)-4]))
				conn.Write([]byte("Message received successfully\n"))
			} else {
				fmt.Println("Received message:", string(message[:len(message)-4]))
				conn.Write([]byte("Message received is invalid\n"))
			}
		} else {
			fmt.Println("Unknown message type:", messageType)
			conn.Write([]byte("Unknown message type\n"))
		}
	}
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
