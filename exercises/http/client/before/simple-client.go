package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	target := "localhost:8090"
	helloUrl := fmt.Sprintf("http://%s/hello", target)
	httpClient := http.Client{}
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