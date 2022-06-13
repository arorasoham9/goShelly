package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {

	arguments := os.Args

	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:" + arguments[1]
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("Server Listen: %s", err)
	}

	log.Print("Server listening on port: ", arguments[1])
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Client accept error: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("Client accepted: %s", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("ok=true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
				fmt.Println("looping")
			}
		}
		go handleClient(conn, listener)
	}
}

func handleClient(conn net.Conn, l net.Listener) {
	defer conn.Close()
	reader := bufio.NewReader(os.Stdin)

	for {
		text, err := reader.ReadString('\n')
		if err != nil {
			if err != nil {
				log.Printf("Stdin read error: %s", err)
			}
			break
		}
		fmt.Fprintf(conn, text+"\n")
		if strings.TrimSpace(string(text)) == "Stop" || strings.TrimSpace(string(text)) == "exit" {
			fmt.Println("Disconnecting Client: ", strings.Split(conn.RemoteAddr().String(), ":")[0])
			l.Close()
			break
		}
	}

	// buf := make([]byte, 512)
	// for {
	//     log.Print("server: conn: waiting")
	//     n, err := conn.Read(buf)

	//     log.Printf("server: conn: echo %q\n", string(buf[:n]))
	//     n, err = conn.Write(buf[:n])

	//     n, err = conn.Write(buf[:n])
	//     log.Printf("server: conn: wrote %d bytes", n)

	//     if err != nil {
	//         log.Printf("server: write: %s", err)
	//         break
	//     }
	// }
	// log.Println("server: conn: closed")

}
