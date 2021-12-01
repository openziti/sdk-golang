package main

import (
	"fmt"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	http.HandleFunc("/hello", hello)
	http.HandleFunc("/add", add)
	if err := http.Serve(createZitiListener(), nil); err != nil {
		panic(err)
	}
}

func hello(w http.ResponseWriter, req *http.Request) {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "zitified hello from %s", host)
}

func add(w http.ResponseWriter, req *http.Request) {
	a, _ := strconv.Atoi(req.URL.Query().Get("a"))
	b, _ := strconv.Atoi(req.URL.Query().Get("b"))
	c := a + b
	fmt.Fprintf(w, "zitified a+b=%d+%d=%d", a, b, c)
}

func createZitiListener() net.Listener {
	cfg, err := config.NewFromFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	options := ziti.ListenOptions{
		ConnectTimeout: 5 * time.Minute,
	}
	listener, err := ziti.NewContextWithConfig(cfg).ListenWithOptions(os.Args[2], &options)
	if err != nil {
		fmt.Printf("Error binding service %+v\n", err)
		panic(err)
	}
	return listener
}
