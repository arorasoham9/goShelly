package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port")
		return
	}

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		log.Fatalf("SSL Key Error: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", arguments[1], &config)
	if err != nil {
		log.Fatalf("Client Dial Error: %s", err)
	}
	defer conn.Close()
	log.Println("Client Connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)


	reader := bufio.NewReader(conn)
	
	for {
		text, _ := reader.ReadString('\n')
		fmt.Printf(strings.Split(strings.TrimSpace(string(text)), "\n")[0] + "\n")
		if strings.TrimSpace(string(text)) == "stop" || strings.TrimSpace(string(text)) == "exit" {
			fmt.Println("Disconnected from Server")
			return
		}
	}
}
