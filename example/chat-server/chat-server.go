/*
	Copyright 2019 NetFoundry Inc.

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
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/sirupsen/logrus"
	"net"
	"os"
	"time"
)

type chatServer struct {
	clients map[string]net.Conn
	eventC  chan event
}

func (server *chatServer) run() {
	for event := range server.eventC {
		event.handle(server)
	}
}

func (server *chatServer) handleChat(conn net.Conn) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		return
	}
	name := string(buf[:n])
	server.eventC <- &clientConnectedEvent{
		name: name,
		conn: conn,
	}

	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			_ = conn.Close()
			server.eventC <- &clientDisconnectEvent{name: name}
			return
		}
		msg := string(buf[:n])
		server.eventC <- &msgEvent{
			source: name,
			msg:    msg,
		}
	}
}

type event interface {
	handle(server *chatServer)
}

type clientConnectedEvent struct {
	name string
	conn net.Conn
}

func (event *clientConnectedEvent) handle(server *chatServer) {
	pfxlog.Logger().Infof("client '%v' connected\n", event.name)
	server.clients[event.name] = event.conn
}

type clientDisconnectEvent struct {
	name string
}

func (event *clientDisconnectEvent) handle(server *chatServer) {
	pfxlog.Logger().Infof("client '%v' disconnected\n", event.name)
	delete(server.clients, event.name)
}

type msgEvent struct {
	source string
	msg    string
}

func (event *msgEvent) handle(server *chatServer) {
	msg := []byte(fmt.Sprintf("%v: %v", event.source, event.msg))
	pfxlog.Logger().Debug(string(msg))
	for name, conn := range server.clients {
		if name != event.source {
			if _, err := conn.Write(msg); err != nil {
				pfxlog.Logger().Errorf("failed to write to %v (%v). closing connection", name, err)
				delete(server.clients, name)
				_ = conn.Close()
			}
		}
	}
}

func main() {
	if os.Getenv("DEBUG") == "true" {
		pfxlog.GlobalInit(logrus.DebugLevel, pfxlog.DefaultOptions())
		pfxlog.Logger().Debugf("debug enabled")
	}

	logger := pfxlog.Logger()

	service := "chat"
	if len(os.Args) > 1 {
		service = os.Args[1]
	}

	options := ziti.ListenOptions{
		ConnectTimeout: 5 * time.Minute,
		MaxConnections: 3,
	}
	logger.Infof("binding service %v\n", service)
	listener, err := ziti.NewContext().ListenWithOptions(service, &options)
	if err != nil {
		logrus.Errorf("Error binding service %+v", err)
		panic(err)
	}

	server := &chatServer{
		clients: map[string]net.Conn{},
		eventC:  make(chan event, 10),
	}
	go server.run()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("server error, exiting: %+v\n", err)
			panic(err)
		}
		logger.Infof("new connection")
		go server.handleChat(conn)
	}
}
