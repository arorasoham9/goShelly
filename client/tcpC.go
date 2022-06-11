package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	// "crypto/tls"
    // "crypto/x509"
)

func Dial(CONNECT string) net.Conn {
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return c
}
func execCommand(command string, length int32){

}

func loadCertificate(config ) {
	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}}
    config.Rand = rand.Reader
}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port")
		return
	}
	CONNECT := arguments[1]
	c := Dial(CONNECT)
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
