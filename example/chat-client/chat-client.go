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
	"fmt"
	"github.com/openziti/sdk-golang/ziti"
	"io"
	"os"
)

func main() {
	service := "chat"
	if len(os.Args) < 2 {
		fmt.Println("must specify username on command line")
		return
	}
	name := os.Args[1]
	context := ziti.NewContext()
	conn, err := context.Dial(service)
	if err != nil {
		fmt.Printf("failed to dial service %v, err: %+v\n", service, err)
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
