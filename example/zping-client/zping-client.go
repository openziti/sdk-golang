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

func getStddev(roundtrip []float64, avg float64)(float64){
	var sum float64
	var sqavg float64
	for index, elem := range roundtrip{
		sum += math.Pow(elem-avg,2)
		if index == len(roundtrip)-1{
			sqavg = sum/float64(len(roundtrip))
		}
	}
    return math.Sqrt(sqavg)
}
func getMinMaxAvg(roundtrip []float64)(float64,float64,float64){
	var sum float64
	var avg float64
	var max float64
	var min float64
	for index, elem := range roundtrip{
		sum += elem
		if index == 0 {
			min = elem
			max = elem
		}
		if elem < min{
			min = elem
		}
		if elem > max {
			max = elem
		}
		if index == len(roundtrip)-1{
			avg = sum/float64(len(roundtrip))
		}

	}
	return min,max,avg
}

func finish(roundtrip []float64, count int, seq int,identity string){
	rec :=seq
	fmt.Printf("\n--- %+v ping statistics ---", identity)
	fmt.Printf("\n%+v packets transmitted and %+v packets recieved, %.2f%+v packet loss\n", count, rec, (1.0-(float32(rec)/float32(count)))*100.00, html.EscapeString("%"))
	min,max,avg := getMinMaxAvg(roundtrip)
	stddev := getStddev(roundtrip,avg)
	fmt.Printf("round-trip min/max/avg/stddev %.3f/%.3f/%.3f/%.3f ms\n\n ", min, max,avg,stddev)
}

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var context ziti.Context
	var service string
	var identity string
	var seq string
	var roundtrip []float64
	var finite bool
	var seq_counter int = 0
	servicePtr := flag.String("s", "ziti-ping", "Name of Service")
	configPtr := flag.String("c", "device.json", "Name of config file")
	identityPtr := flag.String("i", "", "Name of remote identity")
	lengthPtr := flag.Int("l", 100, "Length of data to send")
	timeoutPtr := flag.Int("t", 2, "delay in seconds between ping attempts")
	countPtr := flag.Int("n", 0, "number of pings to send 0 for continuous")


	flag.Parse()

	if len(*servicePtr) > 0 {
		service = *servicePtr
	} else {
		service = "ziti-ping"
	}

	if *countPtr > 0{
		finite = true
	}else{
		finite = false
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
	fmt.Printf("\nSending %+v byte pings to %+v:\n\n",*lengthPtr,identity)
	go func(){
		<-c
		finish(roundtrip,count,seq_counter,identity)
		os.Exit(1)
	}()
	for {
		//Generate a random payload of length -l
		stringData := RandomPingData(*lengthPtr - (len(strconv.Itoa(count))+1))
		pingData := strconv.Itoa(count) + ":" + stringData
		//Get timestamp at ping send
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
		//get timestamp at receipt of response from hosting identity
		duration := time.Since(start)
		ms, _ := strconv.ParseFloat(duration.String()[0:len(duration.String())-2],64)
		roundtrip = append(roundtrip,ms)
		seq = strings.Split(recData,":")[0]
		if recData == pingData {
			seq_counter ++
			fmt.Printf("%+v bytes from %+v: ziti_seq=%+v time=%.3fms\n", recBytes, identity,seq, ms)
		}
		time.Sleep(time.Duration(*timeoutPtr) * time.Second)
		count++
		if finite && (count > *countPtr){
			finish(roundtrip,count-1,seq_counter,identity)
			break
		}
	}

}
