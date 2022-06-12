package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"crypto/tls"
    "crypto/x509"
	"log"
)

func Dial(CONNECT string, config tls.Config) net.Conn {
	c, err := tls.Dial("tcp", CONNECT, &config)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return c
}

func execCommand(command string, length int32){

}

// func loadCertificate(config ) {
// 	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
//     if err != nil {
//         log.Fatalf("server: loadkeys: %s", err)
//     }
//     config := tls.Config{Certificates: []tls.Certificate{cert}}
//     config.Rand = rand.Reader
// }

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port")
		return
	}
	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	CONNECT := arguments[1]
	c := Dial(CONNECT, config)
	if c == nil {
		os.Exit(1)
	}

	fmt.Println("Connected to server: ",strings.Split(c.RemoteAddr().String(), ":")[0]) 
	reader := bufio.NewReader(c)
	for {
		text, _ := reader.ReadString('\n')
		fmt.Printf(strings.Split(strings.TrimSpace(string(text)), "\n")[0] + "\n")
		if strings.TrimSpace(string(text)) == "STOP" || strings.TrimSpace(string(text)) == "exit" {
			fmt.Println("Disconnected from Server")
			return
		}
	}
}
