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
	"os"
	"time"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
)

func main() {

	var context ziti.Context
	var service string
	var identity string
	servicePtr := flag.String("s", "ziti-ping", "Name of Service")
	configPtr := flag.String("c", "device.json", "Name of config file")
	identityPtr := flag.String("i", "", "Name of remote identity")

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

	func() {
		for {
			start := time.Now()
			input := []byte("pingdata")
			//fmt.Println("sent", len(input))
			if _, err := conn.Write(input); err != nil {
				panic(err)
			}
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				_ = conn.Close()
				return
			}
			//rec := string(buf[:n])
			recBytes := len(buf[:n])
			//fmt.Println(rec)
			duration := time.Since(start)
			fmt.Printf("%+v bytes from %+v: time=%+v\n", recBytes, identity, duration)

			time.Sleep(time.Duration(2) * time.Second)
		}
	}()
}
