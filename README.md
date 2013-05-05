spdy
====

My implementation of SPDY/v3 (work in progress)

Adding SPDY support to an existing server shouldn't take much work.

Example use:
```go
package main

import (
	"github.com/SlyMarbo/spdy"
	"net/http"
)

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, HTTP!"))
}

func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	w.Write([]byte("Hello, SPDY!"))
}

func main() {
	
	// Register handlers.
	http.HandleFunc("/", ServeHTTP)
	spdy.HandleFunc("/", ServeSPDY)

	// SPDY connections require TLS.
	err := spdy.ListenAndServeTLS("localhost:443", "cert.pem", "key.pem")
	if err != nil {
		// handle error.
	}
}
```
