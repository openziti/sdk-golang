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
	"encoding/json"
	"flag"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"html"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func processEnrollment(jwtpath, outpath string) error {
	var keyAlg config.KeyAlgVar = "RSA"
	var keyPath, certPath, idname, caOverride string

	if strings.TrimSpace(outpath) == "" {
		out, outErr := outPathFromJwt(jwtpath)
		if outErr != nil {
			return fmt.Errorf("could not set the output path: %s", outErr)
		}
		outpath = out
	}

	if jwtpath != "" {
		if _, err := os.Stat(jwtpath); os.IsNotExist(err) {
			return fmt.Errorf("the provided jwt file does not exist: %s", jwtpath)
		}
	}

	if caOverride != "" {
		if _, err := os.Stat(caOverride); os.IsNotExist(err) {
			return fmt.Errorf("the provided ca file does not exist: %s", caOverride)
		}
	}

	if strings.TrimSpace(outpath) == strings.TrimSpace(jwtpath) {
		return fmt.Errorf("the output path must not be the same as the jwt path")
	}

	tokenStr, _ := ioutil.ReadFile(jwtpath)

	pfxlog.Logger().Debugf("jwt to parse: %s", tokenStr)
	tkn, _, err := enroll.ParseToken(string(tokenStr))

	if err != nil {
		return fmt.Errorf("failed to parse JWT: %s", err.Error())
	}

	flags := enroll.EnrollmentFlags{
		CertFile:      certPath,
		KeyFile:       keyPath,
		KeyAlg:        keyAlg,
		Token:         tkn,
		IDName:        idname,
		AdditionalCAs: caOverride,
	}

	conf, err := enroll.Enroll(flags)
	if err != nil {
		return fmt.Errorf("failed to enroll: %v", err)
	}

	output, err := os.Create(outpath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s': %s", outpath, err.Error())
	}
	defer func() { _ = output.Close() }()

	enc := json.NewEncoder(output)
	enc.SetEscapeHTML(false)
	encErr := enc.Encode(&conf)

	if encErr == nil {
		pfxlog.Logger().Infof("enrolled successfully. identity file written to: %s", outpath)
		return nil
	} else {
		return fmt.Errorf("enrollment successful but the identity file was not able to be written to: %s [%s]", outpath, encErr)
	}
}

func outPathFromJwt(jwt string) (string, error) {
	outFlag := "out"
	if strings.HasSuffix(jwt, ".jwt") {
		return jwt[:len(jwt)-len(".jwt")] + ".json", nil
	} else if strings.HasSuffix(jwt, ".json") {
		//ugh - so that makes things a bit uglier but ok fine. we'll return an error in this situation
		return "", errors.Errorf("unexpected configuration. cannot infer '%s' flag if the jwt file "+
			"ends in .json. rename jwt file or provide the '%s' flag", outFlag, outFlag)
	} else {
		//doesn't end with .jwt - so just slap a .json on the end and call it a day
		return jwt + ".json", nil
	}
}

type ping_session struct {
	roundtrip []float64
	psent     int
	prec      int
	identity  string
	avgrt     float64
	maxrt     float64
	minrt     float64
	stddv     float64
}

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

func RandomPingData(n int) string {
	var set = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	slice := make([]rune, n)
	for i := range slice {
		slice[i] = set[rand.Intn(len(set))]
	}
	return string(slice)
}

func (psession *ping_session) getStddev() {
	var sum float64
	var sqavg float64
	for index, elem := range psession.roundtrip {
		sum += math.Pow(elem-psession.avgrt, 2)
		if index == len(psession.roundtrip)-1 {
			sqavg = sum / float64(len(psession.roundtrip))
		}
	}
	psession.stddv = math.Sqrt(sqavg)
}
func (psession *ping_session) getMinMaxAvg() {
	var sum float64
	var avg float64
	var max float64
	var min float64
	for index, elem := range psession.roundtrip {
		sum += elem
		if index == 0 {
			min = elem
			max = elem
		}
		if elem < min {
			min = elem
		}
		if elem > max {
			max = elem
		}
		if index == len(psession.roundtrip)-1 {
			avg = sum / float64(len(psession.roundtrip))
		}

	}
	psession.avgrt = avg
	psession.maxrt = max
	psession.minrt = min
}

func (psession *ping_session) finish() {
	fmt.Printf("\n--- %+v ping statistics ---", psession.identity)
	fmt.Printf("\n%+v packets transmitted and %+v packets recieved, %.2f%+v packet loss\n", psession.psent, psession.prec, (1.0-(float32(psession.prec)/float32(psession.psent)))*100.00, html.EscapeString("%"))
	psession.getMinMaxAvg()
	psession.getStddev()
	fmt.Printf("round-trip min/max/avg/stddev %.3f/%.3f/%.3f/%.3f ms\n\n ", psession.minrt, psession.maxrt, psession.avgrt, psession.stddv)
}

func main() {
	var context ziti.Context
	var service string
	var identity string
	var seq string
	var finite bool

	servicePtr := flag.String("s", "ziti-ping", "Name of Service")
	configPtr := flag.String("c", "", "Name of config file")
	identityPtr := flag.String("i", "", "Name of remote identity")
	lengthPtr := flag.Int("l", 100, "Length of data to send")
	timeoutPtr := flag.Int("t", 2, "delay in seconds between ping attempts")
	countPtr := flag.Int("n", 0, "number of pings to send, default is 0 for continuous")
	modePtr := flag.String("mode", "client", " 'client','server' or 'enroll")
	jwtPtr := flag.String("j", "", " 'path of jwt file'")
	jsonPtr := flag.String("o", "", " '(optional:enroll path/name of output identity file)'")

	flag.Parse()

	if len(*servicePtr) > 0 {
		service = *servicePtr
	} else {
		service = "ziti-ping"
	}

	if *countPtr > 0 {
		finite = true
	} else {
		finite = false
	}

	if (*modePtr != "client") && (*modePtr != "server") && (*modePtr != "enroll") {
		fmt.Fprintf(os.Stderr, "-mode must be either client(default), server or enroll\n")
		os.Exit(2)
	}

	if *modePtr == "enroll" {
		if len(*jwtPtr) > 0 {
			err := processEnrollment(*jwtPtr, *jsonPtr)
			if err != nil {
				logrus.WithError(err).Error("Error enrolling")
				os.Exit(1)
			}
			os.Exit(0)
		} else {
			fmt.Fprintf(os.Stderr, "If mode is 'enroll' then must specify -j <jwt file path>\n")
			os.Exit(2)
		}
	}

	if *modePtr == "client" {
		if len(*identityPtr) == 0 {
			fmt.Fprintf(os.Stderr, "missing required argument/flag -i\n")
			os.Exit(2)
		} else {
			identity = *identityPtr
		}
	}
	if (*lengthPtr <= 0) || (*lengthPtr > 1500) {
		fmt.Fprintf(os.Stderr, "-l needs to be integer in range 1-1500\n")
		os.Exit(2)
	}
	//create struct to hold ping session data
	psession := &ping_session{
		roundtrip: []float64{},
		psent:     1,
		prec:      0,
		identity:  identity,
		avgrt:     0.0,
		maxrt:     0.0,
		minrt:     0.0,
		stddv:     0.0,
	}

	if *modePtr == "server" {
		logger := pfxlog.Logger()
		options := ziti.ListenOptions{
			ConnectTimeout:        10 * time.Second,
			MaxConnections:        3,
			BindUsingEdgeIdentity: true,
		}
		logger.Infof("binding service %v\n", service)
		var listener edge.Listener
		if len(*configPtr) > 0 {
			file := *configPtr
			configFile, err := config.NewFromFile(file)
			if err != nil {
				logrus.WithError(err).Error("Error loading config file")
				os.Exit(1)
			}
			context := ziti.NewContextWithConfig(configFile)
			identity, err := context.GetCurrentIdentity()
			if err != nil {
				logrus.WithError(err).Error("Error resolving local Identity")
				os.Exit(1)
			}
			fmt.Printf("\n%+v now serving\n\n", identity.Name)
			listener, err = context.ListenWithOptions(service, &options)
			if err != nil {
				logrus.WithError(err).Error("Error Binding Service")
				os.Exit(1)
			}
		} else {
			context := ziti.NewContext()
			identity, err := context.GetCurrentIdentity()
			if err != nil {
				logrus.WithError(err).Error("Error resolving local Identity")
				os.Exit(1)
			}
			fmt.Printf("\n%+v now serving\n\n", identity.Name)
			listener, err = context.ListenWithOptions(service, &options)
			if err != nil {
				logrus.WithError(err).Error("Error Binding Service")
				os.Exit(1)
			}
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.WithError(err).Error("Problem accepting connection, sleeping for 5 Seconds")
				time.Sleep(time.Duration(5) * time.Second)
			}
			logger.Infof("new connection")
			fmt.Println()
			go handlePing(conn)
		}
	} else {
		if len(*configPtr) > 0 {
			file := *configPtr
			configFile, err := config.NewFromFile(file)
			if err != nil {
				logrus.WithError(err).Error("Error loading config file")
				os.Exit(1)
			}
			context = ziti.NewContextWithConfig(configFile)
		} else {
			context = ziti.NewContext()
		}
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			psession.finish()
			os.Exit(1)
		}()
		dialOptions := &ziti.DialOptions{
			Identity:       identity,
			ConnectTimeout: 1 * time.Minute,
			//AppData:        []byte("hi there"),
		}
		//dial ziti service with options specified in dialOptions
		conn, err := context.DialWithOptions(service, dialOptions)
		if err != nil {
			logrus.WithError(err).Error("Error dialing service")
			os.Exit(1)
		}
		fmt.Printf("\nSending %+v byte pings to %+v:\n\n", *lengthPtr, identity)
		for {
			//Generate a random payload of length -l
			stringData := RandomPingData(*lengthPtr - (len(strconv.Itoa(psession.psent)) + 1))
			pingData := strconv.Itoa(psession.psent) + ":" + stringData
			//Get timestamp at ping send
			start := time.Now()
			//send ping message into ziti connection
			input := []byte(pingData)
			if _, err := conn.Write(input); err != nil {
				panic(err)
			}
			buf := make([]byte, 1500)
			//read ping response from ziti connection
			n, err := conn.Read(buf)
			if err != nil {
				_ = conn.Close()
				return
			}
			recData := string(buf[:n])
			recBytes := len(buf[:n])
			//get timestamp at receipt of response from hosting identity
			duration := time.Since(start)
			ms, _ := strconv.ParseFloat(duration.String()[0:len(duration.String())-2], 64)
			psession.roundtrip = append(psession.roundtrip, ms)
			seq = strings.Split(recData, ":")[0]
			if recData == pingData {
				//increments valid responses received
				fmt.Printf("%+v bytes from %+v: ziti_seq=%+v time=%.3fms\n", recBytes, psession.identity, seq, ms)
				psession.prec, _ = strconv.Atoi(seq)
			}
			time.Sleep(time.Duration(*timeoutPtr) * time.Second)
			if finite && (psession.psent == *countPtr) {
				psession.finish()
				break
			}
			psession.psent++
		}
	}
}
