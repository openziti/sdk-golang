package main

import (
	"bufio"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"io"
	"os"
)

var log = pfxlog.Logger()

func main() {
	serviceName := "udp.relay.example"

	zitiCfg, err := ziti.NewConfigFromFile(os.Args[1])
	if err != nil {
		log.Fatalf("failed to load ziti configuration file: %v", err)
	}
	zitiCfg.ConfigTypes = []string{
		"ziti-tunneler-client.v1",
	}

	ctx, err := ziti.NewContext(zitiCfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	foundSvc, ok := ctx.GetService(serviceName)
	if !ok {
		fmt.Println("error when retrieving all the services for the provided config")
		os.Exit(1)
	}
	log.Infof("found service named: %s", *foundSvc.Name)

	svc, err := ctx.Dial(serviceName) //dial the service using the given name
	if err != nil {
		fmt.Println(fmt.Sprintf("error when dialing service name %s. %v", serviceName, err))
		os.Exit(1)
	}

	go ReadFromZiti(svc)
	log.Infof("Connected to %s successfully.", serviceName)
	log.Info("You may now type a line to be sent to the server (press enter to send)")
	log.Info("The line will be sent to the reflect server and returned")
	ReadFromConsole(svc)
}

func ReadFromConsole(writer io.Writer) {
	conWrite := bufio.NewWriter(writer)
	reader := bufio.NewReader(os.Stdin)
	for {
		text, err := reader.ReadString('\n') //read a line from input
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		bytesRead, err := conWrite.WriteString(text)
		_ = conWrite.Flush()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			fmt.Println("wrote", bytesRead, "bytes")
		}
		fmt.Print("Sent     :", text)
	}
}

func ReadFromZiti(reader io.Reader) {
	conRead := bufio.NewReader(reader)
	for {
		read, err := conRead.ReadString('\n')
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			fmt.Print("Received: ", read)
		}
	}
}
