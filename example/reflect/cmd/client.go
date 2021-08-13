package cmd

import (
	"bufio"
	"fmt"
	"github.com/qrkourier/sdk-golang/ziti"
	"github.com/qrkourier/sdk-golang/ziti/config"
	"os"
)

type ServiceConfig struct {
	Protocol string
	Hostname string
	Port     int
}

func Client(zitiCfg *config.Config, serviceName string) {
	ctx := ziti.NewContextWithConfig(zitiCfg) //get a ziti context using a file

	foundSvc, ok := ctx.GetService(serviceName)
	if !ok {
		panic("error when retrieving all the services for the provided config")
	}
	log.Infof("found service named: %s", serviceName)

	clientConfig := &ServiceConfig{}
	found, err := foundSvc.GetConfigOfType("ziti-tunneler-client.v1", clientConfig)
	if err != nil {
		panic(fmt.Sprintf("error when getting configs for service named %s. %v", serviceName, err))
	}
	if !found {
		log.Warn("no config of type ziti-tunneler-client.v1 was found")
	}

	svc, err := ctx.Dial(serviceName) //dial the service using the given name
	if err != nil {
		panic(fmt.Sprintf("error when dialing service name %s. %v", serviceName, err))
	}
	log.Infof("Connected to %s successfully.", serviceName)
	log.Info("You may now type a line to be sent to the server (press enter to send)")
	log.Info("The line will be sent to the reflect server and returned")

	reader := bufio.NewReader(os.Stdin) //setup a reader for reading input from the commandline

	conRead := bufio.NewReader(svc)
	conWrite := bufio.NewWriter(svc)

	for {
		text, err := reader.ReadString('\n') //read a line from intput
		if err != nil {
			fmt.Println(err)
		}
		bytesRead, err := conWrite.WriteString(text)
		_ = conWrite.Flush()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("wrote", bytesRead, "bytes")
		}
		fmt.Print("Sent    :", text)
		read, err := conRead.ReadString('\n')
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Received:", read)
		}
	}
}
