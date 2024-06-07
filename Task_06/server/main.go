package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
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

		switch messageType {
		case 0x01:
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

			// Debug print statement
			fmt.Printf("Received message: %x, %s, %T\n", message, string(message[:textLength]), message[:textLength])

			if validateChecksum(message) {
				fmt.Println("Received valid text message:", string(message[:textLength]))
				conn.Write([]byte("Text message received successfully\n"))
			} else {
				fmt.Println("Received invalid text message checksum")
				conn.Write([]byte("Invalid text message checksum\n"))
			}

		case 0x02:
			// Read the command length
			commandLengthBuf := make([]byte, 4)
			_, err := reader.Read(commandLengthBuf)
			if err != nil {
				fmt.Println("Error reading command length:", err)
				return
			}
			commandLength := binary.BigEndian.Uint32(commandLengthBuf)

			// Read the command
			command := make([]byte, commandLength)
			_, err = reader.Read(command)
			if err != nil {
				fmt.Println("Error reading command:", err)
				return
			}

			// Read the parameter length
			parameterLengthBuf := make([]byte, 4)
			_, err = reader.Read(parameterLengthBuf)
			if err != nil {
				fmt.Println("Error reading parameter length:", err)
				return
			}
			parameterLength := binary.BigEndian.Uint32(parameterLengthBuf)

			// Read the parameter
			parameter := make([]byte, parameterLength)
			_, err = reader.Read(parameter)
			if err != nil {
				fmt.Println("Error reading parameter:", err)
				return
			}

			// Read the checksum
			checksumBuf := make([]byte, 4)
			_, err = reader.Read(checksumBuf)
			if err != nil {
				fmt.Println("Error reading checksum:", err)
				return
			}
			message := append(append(append(append([]byte{messageType}, commandLengthBuf...), command...), parameterLengthBuf...), parameter...)
			messageWithChecksum := append(message, checksumBuf...)

			// Debug print statement
			fmt.Printf("Received message: %x, %s, %s, %T\n", messageWithChecksum, string(command), string(parameter), messageWithChecksum)

			if validateChecksum(messageWithChecksum) {
				fmt.Printf("Received valid command message: Command: %s, Parameter: %s\n", string(command), string(parameter))
				conn.Write([]byte("Command message received successfully\n"))
			} else {
				fmt.Println("Received invalid command message checksum")
				conn.Write([]byte("Invalid command message checksum\n"))
			}

		case 0x03:
			// Read data field 1 (integer)
			dataField1Buf := make([]byte, 4)
			_, err := reader.Read(dataField1Buf)
			if err != nil {
				fmt.Println("Error reading data field 1:", err)
				return
			}
			dataField1 := binary.BigEndian.Uint32(dataField1Buf)

			// Read data field 2 (float)
			dataField2Buf := make([]byte, 8)
			_, err = reader.Read(dataField2Buf)
			if err != nil {
				fmt.Println("Error reading data field 2:", err)
				return
			}
			dataField2 := math.Float64frombits(binary.BigEndian.Uint64(dataField2Buf))

			// Read data field 3 length
			dataField3LengthBuf := make([]byte, 4)
			_, err = reader.Read(dataField3LengthBuf)
			if err != nil {
				fmt.Println("Error reading data field 3 length:", err)
				return
			}
			dataField3Length := binary.BigEndian.Uint32(dataField3LengthBuf)

			// Read data field 3 (string)
			dataField3 := make([]byte, dataField3Length)
			_, err = reader.Read(dataField3)
			if err != nil {
				fmt.Println("Error reading data field 3:", err)
				return
			}

			// Read the checksum
			checksumBuf := make([]byte, 4)
			_, err = reader.Read(checksumBuf)
			if err != nil {
				fmt.Println("Error reading checksum:", err)
				return
			}
			message := append(append(append(append(append([]byte{messageType}, dataField1Buf...), dataField2Buf...), dataField3LengthBuf...), dataField3...), checksumBuf...)

			// Debug print statement
			fmt.Printf("Received message: %x, %d, %f, %s, %T\n", message, dataField1, dataField2, string(dataField3), message)

			if validateChecksum(message) {
				fmt.Printf("Received valid data packet: Data Field 1: %d, Data Field 2: %f, Data Field 3: %s\n", dataField1, dataField2, string(dataField3))
				conn.Write([]byte("Data packet received successfully\n"))
			} else {
				fmt.Println("Received invalid data packet checksum")
				conn.Write([]byte("Invalid data packet checksum\n"))
			}

		default:
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
