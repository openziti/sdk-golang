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
	"bufio"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"net"
	"os"
	"strings"
	"time"
)

type callApp struct {
	context     ziti.Context
	service     string
	listener    edge.Listener
	eventC      chan event
	pending     net.Conn
	current     net.Conn
	currentName string
}

type event interface {
	handle(*callApp)
}

type connectEvent struct {
	conn net.Conn
}

func (event *connectEvent) handle(app *callApp) {
	fmt.Printf("\n")
	if app.pending != nil {
		fmt.Printf("New incoming connection, dropping existing unanswered connection request\n")
		_ = app.pending.Close()
	}
	connInfo := "from " + event.conn.RemoteAddr().String()
	if edgeConn, ok := event.conn.(edge.Conn); ok {
		appData := edgeConn.GetAppData()
		connInfo += " with appData '" + string(appData) + "'"
	}
	fmt.Printf("Incoming connection %v. Type /accept to accept the connection\n> ", connInfo)
	app.pending = event.conn
}

func (app *callApp) waitForCalls() {
	for {
		conn, err := app.listener.Accept()
		if err != nil {
			panic(err)
		}
		app.eventC <- &connectEvent{conn: conn}
	}
}

type userInputEvent struct {
	input string
}

func (event *userInputEvent) handle(app *callApp) {
	if event.input == "/quit" {
		fmt.Printf("quitting\n")
		os.Exit(0)
		return
	}

	if event.input == "/accept" {
		if app.current != nil {
			app.disconnectCurrent()
		}

		if app.pending != nil {
			app.current = app.pending
			app.currentName = app.current.RemoteAddr().String()
			if app.currentName == "" {
				app.currentName = "Anonymous"
			}
			go app.connectionIO()
			app.pending = nil
			fmt.Printf("call accepted and in progress...\n> ")
		} else {
			fmt.Printf("no current incoming call, nothing to accept\n> ")
		}
		return
	}

	if event.input == "/bye" {
		app.disconnectCurrent()
		return
	}

	if strings.HasPrefix(event.input, "/call") {
		identity := strings.TrimPrefix(event.input, "/call")
		identity = strings.TrimSpace(identity)
		if app.current != nil {
			fmt.Printf("closing open connection before dialing %v...\n", identity)
			app.disconnectCurrent()
		}
		fmt.Printf("calling %v...", identity)
		dialOptions := &ziti.DialOptions{
			Identity:       identity,
			ConnectTimeout: 1 * time.Minute,
			AppData:        []byte("hi there"),
		}
		conn, err := app.context.DialWithOptions(app.service, dialOptions)
		if err != nil {
			fmt.Printf("dial error (%v), unable to connect to %v\n> ", err, identity)
		} else {
			fmt.Printf("connected to %v\n> ", identity)
			app.current = conn
			app.currentName = identity
			go app.connectionIO()
		}
		return
	}

	if app.current != nil {
		if _, err := app.current.Write([]byte(event.input + "\n")); err != nil {
			fmt.Printf("write error, closing connection %v\n> ", err)
			_ = app.current.Close()
		}
	} else {
		fmt.Printf("not connected, input ignore\n> ")
	}
}

type remoteDataEvent struct {
	input string
}

func (event *remoteDataEvent) handle(app *callApp) {
	fmt.Printf("\n%v: %v\n> ", app.currentName, event.input)
}

func (app *callApp) run() {
	logger := pfxlog.Logger()
	options := ziti.ListenOptions{
		ConnectTimeout:        5 * time.Minute,
		MaxConnections:        3,
		BindUsingEdgeIdentity: true,
	}
	logger.Infof("registering to service %v\n", app.service)
	app.context = ziti.NewContext()
	var err error
	app.listener, err = app.context.ListenWithOptions(app.service, &options)
	if err != nil {
		logrus.Errorf("Error binding service %+v", err)
		panic(err)
	}

	go app.waitForCalls()
	go app.consoleIO()

	for event := range app.eventC {
		event.handle(app)
	}
}

func (app *callApp) consoleIO() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		app.eventC <- &userInputEvent{input: strings.TrimSpace(line)}
	}
}

func (app *callApp) disconnectCurrent() {
	if app.current != nil {
		if err := app.current.Close(); err != nil {
			fmt.Printf("error while closing connection %v\n", err)
		}
		app.current = nil
		app.currentName = "Anonymous"
		fmt.Printf("disconnected...\n> ")
	} else {
		fmt.Printf("no active call, nothing to disconnect\n> ")
	}
}

func (app *callApp) connectionIO() {
	reader := bufio.NewReader(app.current)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("err (%v)\n> ", err)
			return
		}
		app.eventC <- &remoteDataEvent{input: line}
	}
}

func newCallApp(service string) *callApp {
	return &callApp{
		service: service,
		eventC:  make(chan event),
	}
}

func main() {
	if os.Getenv("DEBUG") == "true" {
		pfxlog.Global(logrus.DebugLevel)
		pfxlog.Logger().Debugf("debug enabled")
	}

	service := "call"
	if len(os.Args) > 1 {
		service = os.Args[1]
	}

	app := newCallApp(service)
	app.run()
}
