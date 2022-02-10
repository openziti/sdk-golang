package main

import (
	"context"
	"fmt"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	target := os.Args[2]
	helloUrl := fmt.Sprintf("http://%s/hello", target)
	httpClient := createZitifiedHttpClient(os.Args[1])
	resp, e := httpClient.Get(helloUrl)
	if e != nil {
		panic(e)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Hello response:", string(body))

	a := 1
	b := 2
	addUrl := fmt.Sprintf("http://%s/add?a=%d&b=%d", target, a, b)
	resp, _ = httpClient.Get(addUrl)
	if e != nil {
		panic(e)
	}
	body, _ = ioutil.ReadAll(resp.Body)
	fmt.Println("Add Result:", string(body))
}

var zitiContext ziti.Context

func Dial(_ context.Context, _ string, addr string) (net.Conn, error) {
	service := strings.Split(addr, ":")[0] // will always get passed host:port
	return zitiContext.Dial(service)
}
func createZitifiedHttpClient(idFile string) http.Client {
	cfg, err := config.NewFromFile(idFile)
	if err != nil {
		panic(err)
	}
	zitiContext = ziti.NewContextWithConfig(cfg)
	zitiTransport := http.DefaultTransport.(*http.Transport).Clone() // copy default transport
	zitiTransport.DialContext = Dial                                 //zitiDialContext.Dial
	return http.Client{Transport: zitiTransport}
}
