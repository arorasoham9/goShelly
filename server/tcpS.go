package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func uploadFile(conn *tls.Conn, path string) {
	// open file to upload
	fi, err := os.Open(path)
	handleError(err)
	defer fi.Close()
	// upload
	_, err = io.Copy(conn, fi)
	handleError(err)
}

func downloadFile(conn *tls.Conn, path string) {
	// create new file to hold response
	fo, err := os.Create(path)
	handleError(err)
	defer fo.Close()

	handleError(err)
	defer conn.Close()

	_, err = io.Copy(fo, conn)
	handleError(err)
}

func main() {

	arguments := os.Args
	if len(arguments) != 2 {
		fmt.Println("Missing Host Port number. Exiting...")
		os.Exit(1)
	}

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
	for {
		log.Print("Server listening on port: ", arguments[1])

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
		fmt.Print("returning f call\n")
	}
}
func genCert(email string) string {
	cmd, err := exec.Command("/bin/sh", "../certGen.sh", email).Output()
	if err != nil {
		fmt.Printf("Error generating SSL Certificate: %s", err)
	}
	outstr := string(cmd)
	return outstr
}

func handleClient(conn net.Conn, l net.Listener) {
	log.Println("Handling Client.")
	defer conn.Close()
	reader := bufio.NewReader(os.Stdin)

	for {

		text, err := reader.ReadString('\n')
		if err != nil {
			if err != nil {
				log.Printf("Stdin read error: %s", err)
			}
			l.Close()
			conn.Close()
			return
		}

		fmt.Fprintf(conn, text+"\n")

		if strings.TrimSpace(string(text)) == "stop" || strings.TrimSpace(string(text)) == "exit" {
			fmt.Println("Disconnecting Client: ", strings.Split(conn.RemoteAddr().String(), ":")[0])
			conn.Close()
			return
		}
	}
}
