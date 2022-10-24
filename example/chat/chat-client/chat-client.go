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
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Insufficient arguments provided\n\nUsage: ./chat-client <username> <identityFile> <optional_serviceName>\n\n")
		return
	}
	name := os.Args[1]

	// Get identity config
	cfg, err := config.NewFromFile(os.Args[2])
	if err != nil {
		panic(err)
	}

	// Get service name (defaults to "chat")
	serviceName := "chat"
	if len(os.Args) > 3 {
		serviceName = os.Args[3]
	}

	context := ziti.NewContextWithConfig(cfg)
	conn, err := context.Dial(serviceName)
	if err != nil {
		fmt.Printf("failed to dial service %v, err: %+v\n", serviceName, err)
		panic(err)
	}

	if _, err := conn.Write([]byte(name)); err != nil {
		panic(err)
	}

	go func() {
		written, err := io.Copy(conn, os.Stdin)
		fmt.Printf("finished writing (stdin => conn) %v. err? %v\n", written, err)
	}()

	written, err := io.Copy(os.Stdout, conn)
	fmt.Printf("finished writing (conn => stdout) %v. err? %v\n", written, err)
}
