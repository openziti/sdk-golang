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
	"bufio"
	"errors"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	app := newCallApp()

	cmd := &cobra.Command{
		Use:     "chat-p2p",
		Example: "chat-p2p -i user1.json",
		Short:   "An example P2P chat app demonstrating addressable terminators ",
		Args:    cobra.ExactArgs(0),
		Run:     app.run,
	}

	cmd.AddCommand(newSetupCmd())

	// allow interspersing positional args and flags
	cmd.Flags().SetInterspersed(true)
	cmd.Flags().BoolVarP(&app.cfg.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().StringVar(&app.cfg.logFormatter, "log-formatter", "pfxlog", "Specify log formatter [json|pfxlog|text]")
	cmd.Flags().StringVarP(&app.cfg.configFile, "identity", "i", "", "Specify the Ziti identity to use. If not specified the Ziti listener won't be started")
	cmd.Flags().StringVarP(&app.cfg.service, "service", "s", "chat-p2p", "Specify the service to use")
	cmd.Flags().SetInterspersed(true)

	_ = cmd.Execute()
}

func newCallApp() *chatPeerToPeer {
	return &chatPeerToPeer{
		eventC: make(chan event),
	}
}

type chatConfig struct {
	configFile string
	service    string

	verbose      bool
	logFormatter string
}

type chatPeerToPeer struct {
	cfg         chatConfig
	context     ziti.Context
	identity    string
	listener    edge.Listener
	eventC      chan event
	pending     edge.Conn
	current     edge.Conn
	currentName string
}

type event interface {
	handle(*chatPeerToPeer)
}

type connectEvent struct {
	conn edge.Conn
}

func (event *connectEvent) handle(app *chatPeerToPeer) {
	fmt.Printf("\n")
	if app.pending != nil {
		fmt.Printf("New incoming connection, dropping existing unanswered connection request\n")
		_ = app.pending.Close()
	}
	connInfo := "from " + event.conn.SourceIdentifier()
	appData := event.conn.GetAppData()
	connInfo += " with appData '" + string(appData) + "'"
	fmt.Printf("Incoming connection %v. Type /accept to accept the connection or /decline to decline it\n", connInfo)
	fmt.Printf("%v > ", app.identity)
	app.pending = event.conn
}

func (self *chatPeerToPeer) waitForCalls() {
	for {
		conn, err := self.listener.Accept()
		if err != nil {
			panic(err)
		}
		self.eventC <- &connectEvent{conn: conn.(edge.Conn)}
	}
}

type userInputEvent struct {
	input string
}

func (event *userInputEvent) handle(app *chatPeerToPeer) {
	if strings.HasPrefix(event.input, "/connect") {
		identity := strings.TrimPrefix(event.input, "/connect")
		identity = strings.TrimSpace(identity)
		if app.current != nil {
			fmt.Printf("closing open connection before dialing %v...\n", identity)
			app.disconnectCurrent()
		}
		fmt.Printf("connecting to %v...\n", identity)
		dialOptions := &ziti.DialOptions{
			Identity:       identity,
			ConnectTimeout: 1 * time.Minute,
			AppData:        []byte("hi there"),
		}
		conn, err := app.context.DialWithOptions(app.cfg.service, dialOptions)
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
	}
}

type remoteDataEvent struct {
	input string
}

func (event *remoteDataEvent) handle(app *chatPeerToPeer) {
	fmt.Printf("\n%v: %v", app.currentName, event.input)
	fmt.Printf("%v > ", app.identity)
}

type disconnectEvent struct{}

func (event *disconnectEvent) handle(app *chatPeerToPeer) {
	app.current = nil
	app.currentName = ""
}

func (self *chatPeerToPeer) run(*cobra.Command, []string) {
	self.initLogging()

	logger := pfxlog.Logger()
	if self.cfg.configFile == "" {
		var err error
		self.context, err = ziti.NewContext()

		if err != nil {
			panic(err)
		}
	} else {
		cfg, err := config.NewFromFile(self.cfg.configFile)
		if err != nil {
			panic(err)
		}
		self.context, err = ziti.NewContextWithConfig(cfg)

		if err != nil {
			panic(err)
		}
	}

	logger.Infof("registering to service %v\n", self.cfg.service)

	options := ziti.ListenOptions{
		ConnectTimeout:        5 * time.Minute,
		MaxConnections:        3,
		BindUsingEdgeIdentity: true,
	}
	listener, err := self.context.ListenWithOptions(self.cfg.service, &options)
	if err != nil {
		logrus.WithError(err).Fatalf("Error binding service")
	}
	self.listener = listener

	identity, err := self.context.GetCurrentIdentity()
	if err != nil {
		panic(err)
	}
	self.identity = *identity.Name

	go self.waitForCalls()
	go self.consoleIO()

	for event := range self.eventC {
		event.handle(self)
	}
}

func (self *chatPeerToPeer) outputHelp() {
	fmt.Println("\nCommands:")
	fmt.Println("/connect <identity> | Tries to make a connection to the given identity")
	fmt.Println("/accept             | Accepts an incoming chat connection")
	fmt.Println("/decline            | Declines an incoming chat connection")
	fmt.Println("/bye                | Disconnects the current chat connection")
	fmt.Println("/list               | Lists currently connected identities")
	fmt.Println("/help               | Should this help output")
	fmt.Printf("/quit               | Exit the application. You may also use Ctrl-D\n\n")
}

func (self *chatPeerToPeer) consoleIO() {
	self.outputHelp()

	// wait briefly to allow connections to be established to edge router(s)
	// so output doesn't get overlapped. Could use SessionListener API to wait for connections,
	// but want to keep example code simpler
	time.Sleep(250 * time.Millisecond)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%v > ", self.identity)
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("\ngoodbye")
				os.Exit(0)
			}
			panic(err)
		}
		line = strings.TrimSpace(line)

		if line == "/quit" {
			fmt.Println("quitting")
			os.Exit(0)
		}

		if line == "/accept" {
			if self.current != nil {
				self.disconnectCurrent()
			}

			if self.pending != nil {
				self.current = self.pending
				self.currentName = self.current.SourceIdentifier()
				if self.currentName == "" {
					self.currentName = "Anonymous"
				}
				go self.connectionIO()
				self.pending = nil
				fmt.Println("\nconnection accepted and chat now in progress...")
			} else {
				fmt.Println("\nno current incoming connection, nothing to accept")
			}
			continue
		}

		if line == "/decline" {
			if self.pending != nil {
				_ = self.pending.Close()
			} else {
				fmt.Println("\nno current incoming connection, nothing to decline")
			}
		}

		if line == "/list" {
			l, _, err := self.context.GetServiceTerminators(self.cfg.service, 0, 100)
			if err != nil {
				fmt.Printf("error listing available chat identities %v\n", err)
			} else {
				for idx, l := range l {
					fmt.Printf("%v: %v\n", idx+1, l.Identity)
				}
			}
			continue
		}

		if line == "/help" {
			self.outputHelp()
			continue
		}

		if line == "/bye" {
			self.disconnectCurrent()
			continue
		}

		self.eventC <- &userInputEvent{input: line}
	}
}

func (self *chatPeerToPeer) disconnectCurrent() {
	if self.current != nil {
		if err := self.current.Close(); err != nil {
			fmt.Printf("error while closing connection %v\n", err)
		}
		self.current = nil
		self.currentName = "Anonymous"
		fmt.Printf("disconnected...\n")
		fmt.Printf("%v > ", self.identity)
	} else {
		fmt.Printf("no active connection, nothing to disconnect\n")
		fmt.Printf("%v > ", self.identity)
	}
}

func (self *chatPeerToPeer) connectionIO() {
	reader := bufio.NewReader(self.current)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("err (%v)\n", err)
			fmt.Printf("%v > ", self.identity)
			self.eventC <- &disconnectEvent{}
			return
		}
		self.eventC <- &remoteDataEvent{input: line}
	}
}

func (self *chatPeerToPeer) initLogging() {
	logLevel := logrus.InfoLevel
	if self.cfg.verbose {
		logLevel = logrus.DebugLevel
	}

	options := pfxlog.DefaultOptions().SetTrimPrefix("github.com/openziti/").NoColor()
	pfxlog.GlobalInit(logLevel, options)

	switch self.cfg.logFormatter {
	case "pfxlog":
		pfxlog.SetFormatter(pfxlog.NewFormatter(pfxlog.DefaultOptions().SetTrimPrefix("github.com/openziti/").StartingToday()))
	case "json":
		pfxlog.SetFormatter(&logrus.JSONFormatter{TimestampFormat: "2006-01-02T15:04:05.000Z"})
	case "text":
		pfxlog.SetFormatter(&logrus.TextFormatter{})
	default:
		// let logrus do its own thing
	}
}
