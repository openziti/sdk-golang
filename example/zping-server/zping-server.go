/*
	Copyright 2019 NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
)

func handlePing(conn net.Conn) {
	for {
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			_ = conn.Close()
			return
		}
		msg := buf[:n]
		if _, err := conn.Write(msg); err != nil {
			logrus.WithError(err).Error("failed to write. closing connection")
			_ = conn.Close()
		}
	}
}

func main() {

	logger := pfxlog.Logger()

	servicePtr := flag.String("s", "ziti-ping", "Name of Service")
	configPtr := flag.String("c", "device.json", "Name of config file")

	flag.Parse()
	var service string
	if len(*servicePtr) > 0 {
		service = *servicePtr
	} else {
		service = "ziti-ping"
	}

	options := ziti.ListenOptions{
		ConnectTimeout:        5 * time.Minute,
		MaxConnections:        3,
		BindUsingEdgeIdentity: true,
	}
	logger.Infof("binding service %v\n", service)
	var listener edge.Listener
	var err error
	if len(*configPtr) > 0 {
		file := *configPtr
		configFile, err := config.NewFromFile(file)
		if err != nil {
			logrus.WithError(err).Error("Error loading config file")
			os.Exit(1)
		}
		context := ziti.NewContextWithConfig(configFile)
		identity, _ := context.GetCurrentIdentity()
		fmt.Printf("\n%+v now serving\n\n", identity.Name)
		listener, err = context.ListenWithOptions(service, &options)
		if err != nil {
			logrus.WithError(err).Error("Error Binding Service")
			os.Exit(1)
		}
	} else {
		listener, err = ziti.NewContext().ListenWithOptions(service, &options)
		if err != nil {
			logrus.WithError(err).Error("Error Binding Service")
			os.Exit(1)
		}
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.WithError(err).Error("Problem accepting connection")
		}
		logger.Infof("new connection")
		fmt.Println()
		go handlePing(conn)
	}
}
