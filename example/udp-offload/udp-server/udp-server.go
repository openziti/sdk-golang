package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	addr := ":10001"
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("Listening on %s\n", addr)

	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Println("Error reading:", err)
			continue
		}

		fmt.Printf("%s sent: %s\n", remoteAddr, string(buf[:n-1]))

		_, err = conn.WriteTo([]byte("udp server echo: "), remoteAddr)
		if err != nil {
			fmt.Println("Error writing:", err)
		}
		_, err = conn.WriteTo(buf[:n], remoteAddr)
		if err != nil {
			fmt.Println("Error writing:", err)
		}
	}
}
