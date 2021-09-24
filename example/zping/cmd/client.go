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
package cmd

import (
	"fmt"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
	fmt.Printf("round-trip min/max/avg/stddev %.3f/%.3f/%.3f/%.3f ms\n", psession.minrt, psession.maxrt, psession.avgrt, psession.stddv)
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

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "zping client command",
	Long: `This command runs zping in client mode which generates ziti probe
messages which are sent to a specified ziti endpoint running zping 
in server mode`,
	Run: func(cmd *cobra.Command, args []string) {
		sflag, _ := cmd.Flags().GetString("service")
		cflag, _ := cmd.Flags().GetString("config")
		iflag, _ := cmd.Flags().GetString("identity")
		lflag, err := cmd.Flags().GetInt("length")
		if (err != nil) || (lflag <= 0) || (lflag > 1500) {
			fmt.Fprintf(os.Stderr, "-l,--length needs to be an integer in range 1-1500\n")
			os.Exit(2)
		}

		tflag, err := cmd.Flags().GetInt("time-out")
		if (err != nil) || (tflag < 0) || (tflag > 65535) {
			fmt.Fprintf(os.Stderr, "-t, --time-out needs to be an integer in range 0-65535\n")
			os.Exit(2)
		}

		nflag, err := cmd.Flags().GetInt("number")
		if (err != nil) || (nflag < 0) || (nflag > 65535) {
			fmt.Fprintf(os.Stderr, "-n, --number needs to be an integer in range 0-65535\n")
			os.Exit(2)
		}

		var context ziti.Context
		var service string
		var identity string
		var seq string
		var finite bool

		if nflag > 0 {
			finite = true
		} else {
			finite = false
		}

		if len(sflag) > 0 {
			service = sflag
		} else {
			service = "ziti-ping"
		}

		if len(iflag) == 0 {
			fmt.Fprintf(os.Stderr, "missing required argument/flag -i\n")
			os.Exit(2)
		} else {
			identity = iflag
		}

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
		if len(cflag) > 0 {
			file := cflag
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
		fmt.Printf("\nSending %+v byte pings to %+v:\n\n", lflag, identity)
		for {
			//Generate a random payload of length -l
			stringData := RandomPingData(lflag - (len(strconv.Itoa(psession.psent)) + 1))
			pingData := strconv.Itoa(psession.psent) + ":" + stringData
			//Get timestamp at ping send
			start := time.Now()
			//send ping message into ziti connection
			input := []byte(pingData)
			if _, err := conn.Write(input); err != nil {
				logrus.WithError(err).Error("Error Writing to Server")
				_ = conn.Close()
				psession.finish()
				os.Exit(1)
			}
			buf := make([]byte, 1500)
			//read ping response from ziti connection
			n, err := conn.Read(buf)
			if err != nil {
				logrus.WithError(err).Error("Error Reading from Server")
				_ = conn.Close()
				psession.finish()
				os.Exit(1)
			}
			recData := string(buf[:n])
			recBytes := len(buf[:n])
			//get timestamp at receipt of response from hosting identity
			ms := time.Since(start).Seconds() * 1000
			psession.roundtrip = append(psession.roundtrip, ms)
			seq = strings.Split(recData, ":")[0]
			if recData == pingData {
				//increments valid responses received
				fmt.Printf("%+v bytes from %+v: ziti_seq=%+v time=%.3fms\n", recBytes, psession.identity, seq, ms)
				psession.prec, _ = strconv.Atoi(seq)
			}
			time.Sleep(time.Duration(tflag) * time.Second)
			if finite && (psession.psent == nflag) {
				psession.finish()
				break
			}
			psession.psent++
		}
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)
	clientCmd.Flags().StringP("service", "s", "ziti-ping", "Name of Service")
	clientCmd.Flags().StringP("config", "c", "", "Name of config file")
	clientCmd.Flags().StringP("identity", "i", "", "Name of remote identity")
	clientCmd.Flags().IntP("length", "l", 100, "Length of data to send")
	clientCmd.Flags().IntP("time-out", "t", 2, "delay in seconds between ping attempts")
	clientCmd.Flags().IntP("number", "n", 0, "number of pings to send, default is 0 for continuous")
}
