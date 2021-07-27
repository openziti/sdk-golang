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
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
)

func RandomPingData(n int) string {
	var set = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	slice := make([]rune, n)
	for i := range slice {
		slice[i] = set[rand.Intn(len(set))]
	}
	return string(slice)
}

func main() {

	var context ziti.Context
	var service string
	var identity string
	servicePtr := flag.String("s", "ziti-ping", "Name of Service")
	configPtr := flag.String("c", "device.json", "Name of config file")
	identityPtr := flag.String("i", "", "Name of remote identity")
	lengthPtr := flag.Int("l", 100, "Length of data to send")
	timeoutPtr := flag.Int("t", 2, "delay in seconds between ping attempts")

	flag.Parse()

	if len(*servicePtr) > 0 {
		service = *servicePtr
	} else {
		service = "ziti-ping"
	}

	if len(*configPtr) > 0 {
		//file := os.Args[1]
		file := *configPtr
		//fmt.Println(file)
		configFile, _ := config.NewFromFile(file)
		//fmt.Println(configFile)
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

	dialOptions := &ziti.DialOptions{
		Identity:       identity,
		ConnectTimeout: 1 * time.Minute,
		//AppData:        []byte("hi there"),
	}
	conn, err := context.DialWithOptions(service, dialOptions)
	//conn, err := context.Dial(service)
	if err != nil {
		fmt.Printf("failed to dial service %v, err: %+v\n", service, err)
		panic(err)
	}
	var count int = 1
	for {
		stringData := RandomPingData(*lengthPtr - (len(strconv.Itoa(count))+1))
		pingData := strconv.Itoa(count) + ":" + stringData
		//fmt.Println(pingData)
		start := time.Now()
		input := []byte(pingData)
		//fmt.Println("sent", len(input))
		if _, err := conn.Write(input); err != nil {
			panic(err)
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			_ = conn.Close()
			return
		}
		recData := string(buf[:n])
		recBytes := len(buf[:n])
		//fmt.Println(rec)
		duration := time.Since(start)
        //fmt.Println(recData)
		seq := strings.Split(recData,":")[0]
		if recData == pingData {
			fmt.Printf("%+v bytes from %+v: ziti_seq=%+v time=%+v\n", recBytes, identity,seq, duration)
		}
		count++
		time.Sleep(time.Duration(*timeoutPtr) * time.Second)
	}
}
