package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"strings"
)

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
}

func calculateCRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func appendChecksum(data []byte) []byte {
	checksum := calculateCRC32(data)
	checksumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBytes, checksum)
	return append(data, checksumBytes...)
}

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting:", err.Error())
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password) // Trim the password input
	passwordHash := hashPassword(password)

	//passwordHash checker
	//fmt.Println("Converted password hash:", passwordHash) // Print the hashed password for verification

	conn.Write([]byte(username + "\n"))
	conn.Write([]byte(passwordHash + "\n"))

	serverResponse, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("Server response:", serverResponse)

	if serverResponse != "Authentication successful\n" {
		return
	}

	// Sending a message with CRC checksum
	message := "Hello, Server"
	messageWithChecksum := appendChecksum([]byte(message + "\n"))
	messageLength := uint32(len(messageWithChecksum))
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, messageLength)
	conn.Write(lengthBuf)
	conn.Write(messageWithChecksum)

	//messageWithChecksum checker
	fmt.Println("CRC message:", messageWithChecksum)

	response, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("Server response:", response)
}
