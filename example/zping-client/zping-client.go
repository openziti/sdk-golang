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
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/sirupsen/logrus"
	"html"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var context ziti.Context
	var service string
	var identity string
	var seq string
	var finite bool

	servicePtr := flag.String("s", "ziti-ping", "Name of Service")
	configPtr := flag.String("c", "device.json", "Name of config file")
	identityPtr := flag.String("i", "", "Name of remote identity")
	lengthPtr := flag.Int("l", 100, "Length of data to send")
	timeoutPtr := flag.Int("t", 2, "delay in seconds between ping attempts")
	countPtr := flag.Int("n", 0, "number of pings to send, default is 0 for continuous")

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
	if len(*identityPtr) == 0 {
		fmt.Fprintf(os.Stderr, "missing required argument/flag -i\n")
		os.Exit(2)
	} else {
		identity = *identityPtr
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
	go func() {
		<-c
		psession.finish()
		os.Exit(1)
	}()
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
