package main

import (
	"crypto/tls"
	"net/http"

	"github.com/SlyMarbo/spdy"
)

func handle(err error) {
	if err != nil {
		panic(err)
	}
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Testing, testing, 1, 2, 3."))
}

func main() {
	http.HandleFunc("/", serveHTTP)
	handle(spdy.ConnectAndServe("http://localhost:8080/", &tls.Config{InsecureSkipVerify: true}, nil))
}
