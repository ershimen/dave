package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
)

func main2() {

	var node_type string

	flag.StringVar(&node_type, "t", "client", "Especifica si es servidor o cliente (default)")
	flag.Usage = func() {
		fmt.Println("Uso:")
		fmt.Println("[-t] client|server (default: client)")
	}

	flag.Parse()

	if node_type == "server" {
		l, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			fmt.Println("Error en listen")
			os.Exit(1)
		}
		defer l.Close()
		fmt.Println("listening on port", l.Addr().(*net.TCPAddr).Port)
		for {
			c, err := l.Accept()
			if err != nil {
				fmt.Println("Error en accept")
				os.Exit(1)
			}
			go resolve_petition(c)
		}
	} else {
		fmt.Print("puerto: ")
		reader := bufio.NewReader(os.Stdin)
		input, _, err := reader.ReadLine()
		if err != nil {
			fmt.Println("error leyendo entrada")
			os.Exit(1)
		}

		fmt.Printf("dialing: \"%s\"\n", input)
		c, err := net.Dial("tcp", "localhost:"+string(input))
		if err != nil {
			fmt.Println("error conectando con el servidor")
			os.Exit(1)
		}
		defer c.Close()
		buff := make([]byte, 1024)
		for {
			fmt.Print("> ")
			input, _, err := reader.ReadLine()
			if err != nil {
				fmt.Println("error leyendo entrada")
				os.Exit(1)
			}
			if string(input) == "STOP" {
				c.Write([]byte("STOP"))
				break
			}
			c.Write(input)
			_, err = c.Read(buff)
			fmt.Print("\t-> ")
			fmt.Println(string(buff))
		}
	}

}

func resolve_petition(c net.Conn) {
	defer fmt.Println("Instance stopped")
	defer c.Close()
	defer fmt.Println("Stopping instance...")
	for {
		buff := make([]byte, 1024)
		_, err := c.Read(buff)
		if err != nil {
			fmt.Println("La conexión se ha cerrado")
			break
		}
		if string(buff[:4]) == "STOP" {
			break
		}
		for i := range buff {
			if buff[i] == 0 {
				break
			}
			buff[i] += 1
		}
		fmt.Printf("response: \"%s\"\n", string(buff))
		c.Write(buff)
	}
}
