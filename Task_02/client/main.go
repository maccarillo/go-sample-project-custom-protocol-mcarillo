package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"
)

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
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

	//fmt.Println("Converted password hash:", passwordHash) // Print the hashed password for verification

	conn.Write([]byte(username + "\n"))
	conn.Write([]byte(passwordHash + "\n"))

	serverResponse, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("Server response:", serverResponse)

	if serverResponse != "Authentication successful\n" {
		return
	}

}
