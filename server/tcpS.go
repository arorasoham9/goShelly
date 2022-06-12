package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	"crypto/tls"
	"log"
)

func handleErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}


func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide port number")
		return
	}

	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}}

	reader := bufio.NewReader(os.Stdin)
	PORT := ":" + arguments[1]
	for {
		fmt.Print("Listening for incoming connections...\n")
		l, err := tls.Listen("tcp", PORT, &config)
		handleErr(err)
		defer l.Close()

		c, err := l.Accept()
		handleErr(err)
		fmt.Println("Connected to Client: ", strings.Split(c.RemoteAddr().String(), ":")[0])
		// reader := bufio.NewReader(os.Stdin)
		for {
			
			text, _ := reader.ReadString('\n')
			fmt.Fprintf(c, text+"\n")
			if strings.TrimSpace(string(text)) == "Stop" || strings.TrimSpace(string(text)) == "exit" {
				fmt.Println("Disconnecting Client: ", strings.Split(c.RemoteAddr().String(), ":")[0])
				l.Close()
				break
			}
		}
		time.Sleep(time.Second * 5)

	}

}
