package main

import (
	"fmt"
	"net"
)

func main() {

	addr := "localhost:12345"

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Error dialing %s\n", addr)
		return
	}
	defer conn.Close()

	buffer := make([]byte, 2048)
	msg := "Mensaje"
	conn.Write([]byte("Message"))
	fmt.Printf("Msg sent: %s\n", msg)

	if _, err := conn.Read(buffer); err != nil {
		fmt.Println("Error reading to buffer")
		return
	}
	fmt.Println(string(buffer))
}
