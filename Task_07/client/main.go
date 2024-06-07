package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
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

func sendMessage(conn net.Conn, messageType byte, message string) {
	messageBytes := []byte(message)
	messageLength := uint32(len(messageBytes))

	buf := make([]byte, 1+4+len(messageBytes))
	buf[0] = messageType
	binary.BigEndian.PutUint32(buf[1:], messageLength)
	copy(buf[5:], messageBytes)

	bufWithChecksum := appendChecksum(buf)
	conn.Write(bufWithChecksum)
}

func sendCommandMessage(conn net.Conn, command string, parameter string) {
	commandBytes := []byte(command)
	commandLength := uint32(len(commandBytes))

	parameterBytes := []byte(parameter)
	parameterLength := uint32(len(parameterBytes))

	buf := make([]byte, 1+4+len(commandBytes)+4+len(parameterBytes))
	buf[0] = 0x02
	binary.BigEndian.PutUint32(buf[1:], commandLength)
	copy(buf[5:], commandBytes)
	binary.BigEndian.PutUint32(buf[5+len(commandBytes):], parameterLength)
	copy(buf[9+len(commandBytes):], parameterBytes)

	bufWithChecksum := appendChecksum(buf)
	conn.Write(bufWithChecksum)
}

func sendDataPacket(conn net.Conn, dataField1 uint32, dataField2 float64, dataField3 string) {
	dataField3Bytes := []byte(dataField3)
	dataField3Length := uint32(len(dataField3Bytes))

	buf := make([]byte, 1+4+8+4+len(dataField3Bytes))
	buf[0] = 0x03
	binary.BigEndian.PutUint32(buf[1:], dataField1)
	binary.BigEndian.PutUint64(buf[5:], math.Float64bits(dataField2))
	binary.BigEndian.PutUint32(buf[13:], dataField3Length)
	copy(buf[17:], dataField3Bytes)

	bufWithChecksum := appendChecksum(buf)
	conn.Write(bufWithChecksum)
}

func receiveAndParseMessages(conn net.Conn) {
	for {
		reader := bufio.NewReader(conn)

		messageType, err := reader.ReadByte()
		if err != nil {
			fmt.Println("Error reading message type:", err)
			return
		}

		switch messageType {
		case 0x01:
			lengthBuf := make([]byte, 4)
			_, err := reader.Read(lengthBuf)
			if err != nil {
				fmt.Println("Error reading text length:", err)
				return
			}
			textLength := binary.BigEndian.Uint32(lengthBuf)

			text := make([]byte, textLength)
			_, err = reader.Read(text)
			if err != nil {
				fmt.Println("Error reading text:", err)
				return
			}

			fmt.Println("Received text message:", string(text))

		case 0x02:
			commandLengthBuf := make([]byte, 4)
			_, err := reader.Read(commandLengthBuf)
			if err != nil {
				fmt.Println("Error reading command length:", err)
				return
			}
			commandLength := binary.BigEndian.Uint32(commandLengthBuf)

			command := make([]byte, commandLength)
			_, err = reader.Read(command)
			if err != nil {
				fmt.Println("Error reading command:", err)
				return
			}

			parameterLengthBuf := make([]byte, 4)
			_, err = reader.Read(parameterLengthBuf)
			if err != nil {
				fmt.Println("Error reading parameter length:", err)
				return
			}
			parameterLength := binary.BigEndian.Uint32(parameterLengthBuf)

			parameter := make([]byte, parameterLength)
			_, err = reader.Read(parameter)
			if err != nil {
				fmt.Println("Error reading parameter:", err)
				return
			}

			fmt.Printf("Received command message: Command: %s, Parameter: %s\n", string(command), string(parameter))

		case 0x03:
			dataField1Buf := make([]byte, 4)
			_, err := reader.Read(dataField1Buf)
			if err != nil {
				fmt.Println("Error reading data field 1:", err)
				return
			}
			dataField1 := binary.BigEndian.Uint32(dataField1Buf)

			dataField2Buf := make([]byte, 8)
			_, err = reader.Read(dataField2Buf)
			if err != nil {
				fmt.Println("Error reading data field 2:", err)
				return
			}
			dataField2 := math.Float64frombits(binary.BigEndian.Uint64(dataField2Buf))

			dataField3LengthBuf := make([]byte, 4)
			_, err = reader.Read(dataField3LengthBuf)
			if err != nil {
				fmt.Println("Error reading data field 3 length:", err)
				return
			}
			dataField3Length := binary.BigEndian.Uint32(dataField3LengthBuf)

			dataField3 := make([]byte, dataField3Length)
			_, err = reader.Read(dataField3)
			if err != nil {
				fmt.Println("Error reading data field 3:", err)
				return
			}

			fmt.Printf("Received data packet: Data Field 1: %d, Data Field 2: %f, Data Field 3: %s\n", dataField1, dataField2, string(dataField3))

		default:
			fmt.Println("Unknown message type:", messageType)
		}
	}
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
	password = strings.TrimSpace(password)
	hashedPassword := hashPassword(password)
	fmt.Println("Hashed password:", hashedPassword)

	conn.Write([]byte(username + "\n"))
	conn.Write([]byte(hashedPassword + "\n"))

	authResponse, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println(authResponse)

	if strings.TrimSpace(authResponse) != "Authentication successful" {
		fmt.Println("Authentication failed, exiting.")
		return
	}

	go receiveAndParseMessages(conn)

	for {
		fmt.Println("Choose message type (1=Text, 2=Command, 3=Data Packet): ")
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
		case "3":
			var dataField1 uint32
			var dataField2 float64
			var dataField3 string

			fmt.Print("Enter data field 1 (integer): ")
			fmt.Scanf("%d\n", &dataField1)
			fmt.Print("Enter data field 2 (float): ")
			fmt.Scanf("%f\n", &dataField2)
			fmt.Print("Enter data field 3 (string): ")
			dataField3, _ = reader.ReadString('\n')
			dataField3 = strings.TrimSpace(dataField3)
			sendDataPacket(conn, dataField1, dataField2, dataField3)
		default:
			fmt.Println("Unknown message type")
		}
	}
}
