spdy
====

My implementation of SPDY/v3 (work in progress)

Adding SPDY support to an existing server shouldn't take much work.

Example use:
```go
package main

import (
	"fmt"
	"github.com/SlyMarbo/spdy"
	"net/http"
)

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s over HTTP!", r.RequestURI)
}

func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	fmt.Fprintf(w, "Hello, %s over SPDY!", r.RequestURI)
}

func main() {
	// SPDY requires an explicit http.Server.
	server := new(http.Server)
	server.Addr = "localhost:443"
	
	http.HandleFunc("/", ServeHTTP)
	spdy.HandleFunc("/", ServeSPDY)
	
	// Add SPDY handling to the server.
	spdy.AddSPDY(server)

	// SPDY connections require TLS.
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		// handle error.
	}
}
```
