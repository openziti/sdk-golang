package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
)

func main() {
	http.HandleFunc("/hello", hello)
	http.HandleFunc("/add", add)
	if err := http.ListenAndServe(":8090", nil); err != nil {
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
	fmt.Fprintf(w, "a+b=%d+%d=%d", a, b, c)
}
