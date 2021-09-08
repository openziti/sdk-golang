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
	"errors"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
	"time"
)

type callApp struct {
	context     ziti.Context
	service     string
	identity    string
	listener    edge.Listener
	eventC      chan event
	pending     edge.Conn
	current     edge.Conn
	currentName string
}

type event interface {
	handle(*callApp)
}

type connectEvent struct {
	conn edge.Conn
}

func (event *connectEvent) handle(app *callApp) {
	fmt.Printf("\n")
	if app.pending != nil {
		fmt.Printf("New incoming connection, dropping existing unanswered connection request\n")
		_ = app.pending.Close()
	}
	connInfo := "from " + event.conn.SourceIdentifier()
	if edgeConn, ok := event.conn.(edge.Conn); ok {
		appData := edgeConn.GetAppData()
		connInfo += " with appData '" + string(appData) + "'"
	}
	fmt.Printf("Incoming connection %v. Type /accept to accept the connection\n", connInfo)
	fmt.Printf("%v > ", app.identity)
	app.pending = event.conn
}

func (app *callApp) waitForCalls() {
	for {
		conn, err := app.listener.Accept()
		if err != nil {
			panic(err)
		}
		app.eventC <- &connectEvent{conn: conn.(edge.Conn)}
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
			app.currentName = app.current.SourceIdentifier()
			if app.currentName == "" {
				app.currentName = "Anonymous"
			}
			go app.connectionIO()
			app.pending = nil
			fmt.Printf("\ncall accepted and in progress...\n%v > ", app.identity)
		} else {
			fmt.Printf("no current incoming call, nothing to accept\n%v > ", app.identity)
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
		fmt.Printf("calling %v...\n", identity)
		dialOptions := &ziti.DialOptions{
			Identity:       identity,
			ConnectTimeout: 1 * time.Minute,
			AppData:        []byte("hi there"),
		}
		conn, err := app.context.DialWithOptions(app.service, dialOptions)
		if err != nil {
			fmt.Printf("dial error (%v), unable to connect to %v\n", err, identity)
			fmt.Printf("%v > ", app.identity)
		} else {
			fmt.Printf("connected to %v\n", identity)
			fmt.Printf("%v > ", app.identity)
			app.current = conn
			app.currentName = identity
			go app.connectionIO()
		}
		return
	}

	if app.current != nil {
		if _, err := app.current.Write([]byte(event.input + "\n")); err != nil {
			fmt.Printf("write error, closing connection %v\n", err)
			fmt.Printf("%v > ", app.identity)
			_ = app.current.Close()
		}
	} else {
		fmt.Printf("not connected, input ignore\n")
		fmt.Printf("%v > ", app.identity)
	}
}

type remoteDataEvent struct {
	input string
}

func (event *remoteDataEvent) handle(app *callApp) {
	fmt.Printf("\n%v: %v", app.currentName, event.input)
	fmt.Printf("%v > ", app.identity)
}

type disconnectEvent struct{}

func (event *disconnectEvent) handle(app *callApp) {
	app.current = nil
	app.currentName = ""
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

	identity, err := app.context.GetCurrentIdentity()
	if err != nil {
		panic(err)
	}
	app.identity = identity.Name

	go app.waitForCalls()
	go app.consoleIO()

	for event := range app.eventC {
		event.handle(app)
	}
}

func (app *callApp) consoleIO() {
	// wait briefly to allow connections to be established to edge router(s)
	// so output doesn't get overlapped. Could use SessionListener API to wait for connections,
	// but want to keep example code simpler
	time.Sleep(250 * time.Millisecond)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%v > ", app.identity)
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("\ngoodbye")
				os.Exit(0)
			}
			panic(err)
		}
		line = strings.TrimSpace(line)

		if line == "/list" {
			l, _, err := app.context.GetServiceTerminators(app.service, 0, 100)
			if err != nil {
				fmt.Printf("error listing call identities %v\n", err)
			} else {
				for idx, l := range l {
					fmt.Printf("%v: %v\n", idx+1, l.Identity)
				}
			}
		} else {
			app.eventC <- &userInputEvent{input: line}
		}
	}
}

func (app *callApp) disconnectCurrent() {
	if app.current != nil {
		if err := app.current.Close(); err != nil {
			fmt.Printf("error while closing connection %v\n", err)
		}
		app.current = nil
		app.currentName = "Anonymous"
		fmt.Printf("disconnected...\n")
		fmt.Printf("%v > ", app.identity)
	} else {
		fmt.Printf("no active call, nothing to disconnect\n")
		fmt.Printf("%v > ", app.identity)
	}
}

func (app *callApp) connectionIO() {
	reader := bufio.NewReader(app.current)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("err (%v)\n", err)
			fmt.Printf("%v > ", app.identity)
			app.eventC <- &disconnectEvent{}
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
		pfxlog.GlobalInit(logrus.DebugLevel, pfxlog.DefaultOptions())
		pfxlog.Logger().Debugf("debug enabled")
	}

	service := "call"
	if len(os.Args) > 1 {
		service = os.Args[1]
	}

	app := newCallApp(service)
	app.run()
}
