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

func sendMessage(conn net.Conn, messageType byte, text string) {
	textBytes := []byte(text)
	textLength := uint32(len(textBytes))

	// Create message
	message := make([]byte, 1+4+len(textBytes)+4)
	message[0] = messageType
	binary.BigEndian.PutUint32(message[1:5], textLength)
	copy(message[5:], textBytes)

	// Append checksum
	messageWithChecksum := appendChecksum(message[:5+len(textBytes)])

	// Send the message
	conn.Write(messageWithChecksum)
}

func sendCommandMessage(conn net.Conn, command, parameter string) {
	commandBytes := []byte(command)
	commandLength := uint32(len(commandBytes))

	parameterBytes := []byte(parameter)
	parameterLength := uint32(len(parameterBytes))

	// Create message
	message := make([]byte, 1+4+len(commandBytes)+4+len(parameterBytes)+4)
	message[0] = 0x02
	binary.BigEndian.PutUint32(message[1:5], commandLength)
	copy(message[5:], commandBytes)
	binary.BigEndian.PutUint32(message[5+len(commandBytes):9+len(commandBytes)], parameterLength)
	copy(message[9+len(commandBytes):], parameterBytes)

	// Append checksum
	messageWithChecksum := appendChecksum(message[:9+len(commandBytes)+len(parameterBytes)])

	// Send the message
	conn.Write(messageWithChecksum)
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

	fmt.Println("Converted password hash:", passwordHash) // Print the hashed password for verification

	conn.Write([]byte(username + "\n"))
	conn.Write([]byte(passwordHash + "\n"))

	serverResponse, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("Server response:", serverResponse)

	if serverResponse != "Authentication successful\n" {
		return
	}

	for {
		fmt.Print("Enter message type (1 for text, 2 for command): ")
		messageType, _ := reader.ReadString('\n')
		messageType = strings.TrimSpace(messageType)

		switch messageType {
		case "1":
			fmt.Print("Enter text message: ")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			sendMessage(conn, 0x01, text)
		case "2":
			fmt.Print("Enter command: ")
			command, _ := reader.ReadString('\n')
			command = strings.TrimSpace(command)
			fmt.Print("Enter parameter: ")
			parameter, _ := reader.ReadString('\n')
			parameter = strings.TrimSpace(parameter)
			sendCommandMessage(conn, command, parameter)
		default:
			fmt.Println("Unknown message type")
		}

		response, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Println("Server response:", response)
	}
}
