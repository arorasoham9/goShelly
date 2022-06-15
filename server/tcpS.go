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
	if len(arguments) < 2 {
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
			}
		}
		
		go handleClient(conn, listener)
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

func readString(reader *bufio.Reader) (string, error){
	text, err := reader.ReadString('\n')
	if err != nil {
		if err != nil {
			log.Printf("Stdin read error: %s", err)
		}
		l.Close()
		conn.Close()
		os.Exit(1)
		return nil, err
	}
	return text, nil
}

func handleClient(conn net.Conn, l net.Listener) {
	log.Println("Handling Client.")
	defer conn.Close()
	reader := bufio.NewReader(os.Stdin)

	for {

	
		text, _ = readString(reader)
		fmt.Fprintf(conn, text)
		cmdCheck := true
		for next := true; next; cmdCheck {
			
		}
		cmd := strings.TrimSpace(string(text))

		checkCommand(cmd, conn *tls.Conn, reader)
	}
}
func checkCommmand(cmd, conn *tls.Conn, reader *bufio.Reader) bool {
	
	
	cmd, _ = readString(reader)
	switch(strings.ToLower(cmd)){
	case "bash":
		//goroutine here? ig
		break
	case "exit", "close","stop":
			fmt.Println("Disconnecting Client: ", strings.Split(conn.RemoteAddr().String(), ":")[0])
			conn.Close()

		break
	

	case "help", "h":
		break
	case "":
		break
	default:
		fmt.Fprintf(conn, "%s is not the name of a valid command. Run 'help' or 'h' to learn about all possible commands.",cmd)
		return false
		break
	}
	return true
}

func appendStrBuild(prompt strings.Builder, append []string) string{
	for i := 0;i < len(append);i++ {
		prompt.append(append[i])
	}
}


func printHelp(){
	var prompt strings.Builder
	prompt.Write("Welcome to GoShelly help\n
				  List of commands:
				  1) 'bash'- Run bash shell\n
				  2) 'exit or 'close' or 'stop' - Terminate GoShelly Session\n
				  3) 'help' or 'h' - Get this prompt\n")
	return prompt
}

func beginBash(conn *tls.Conn) {




}