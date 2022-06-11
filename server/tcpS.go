package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	
	
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

	PORT := ":" + arguments[1]
	for {
		fmt.Print("Listening for incoming connections...\n")
		l, err := net.Listen("tcp", PORT)
		handleErr(err)
		defer l.Close()

		c, err := l.Accept()
		handleErr(err)
		fmt.Print("Connected to Client.\n")
		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("$ ")
			text, _ := reader.ReadString('\n')
			fmt.Fprintf(c, text+"\n")
			if strings.TrimSpace(string(text)) == "Stop" || strings.TrimSpace(string(text)) == "exit" {
				fmt.Println("Disconnecting Client.")
				l.Close()
				break
			}
		}
		time.Sleep(time.Second * 5)

	}

}
