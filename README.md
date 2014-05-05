spdy
====

A full-featured SPDY library for the Go language (still under very active development).
 
Note that this implementation currently supports SPDY drafts 2 and 3, and support for SPDY/4, and HTTP/2.0 is upcoming.

The GoDoc documentation for this package can be found at http://godoc.org/github.com/SlyMarbo/spdy.

Servers
-------

Adding SPDY support to an existing Go server requires minimal work.

Modifying a simple example server like the following:
```go
package main

import (
	"net/http"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	// Remember not to add any headers after calling
	// w.WriteHeader().
	
	w.Write([]byte("Hello, HTTP!"))
}

func main() {
	
	// Register handler.
	http.HandleFunc("/", Serve)

	err := http.ListenAndServeTLS("localhost:443", "cert.pem", "key.pem", nil)
	if err != nil {
		// handle error.
	}
}
```

Simply requires the following changes:
```go
package main

import (
	"github.com/SlyMarbo/spdy" // Import SPDY.
	"net/http"
)

// This handler will now serve HTTP, HTTPS, and SPDY requests.
func Serve(w http.ResponseWriter, r *http.Request) {
	// Remember not to add any headers after calling
	// w.WriteHeader().

	w.Write([]byte("Hello, HTTP!"))
}

func main() {
	
	http.HandleFunc("/", Serve)

	// Use spdy's ListenAndServe.
	err := spdy.ListenAndServeTLS("localhost:443", "cert.pem", "key.pem", nil)
	if err != nil {
		// handle error.
	}
}
```

A very simple file server for both SPDY and HTTPS:
```go
package main

import (
	"github.com/SlyMarbo/spdy"
	"net/http"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	if spdy.UsingSPDY(w) {
		// Using SPDY.
	} else {
		// Using HTTP(S).
	}
	http.ServeFile(w, r, "." + r.RequestURI)
}

func main() {
	
	// Register handler.
	http.HandleFunc("/", Serve)

	err := spdy.ListenAndServeTLS("localhost:443", "cert.pem", "key.pem", nil)
	if err != nil {
		// handle error.
	}
}
```



The following examples use features specific to SPDY.

Just the handler is shown.

Use SPDY's pinging features to test the connection:
```go
package main

import (
	"github.com/SlyMarbo/spdy"
	"net/http"
	"time"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	// Ping returns a channel which will send an empty struct.
	ping, err := spdy.PingClient(w)
	if err != nil {
		// Not using SPDY.
	}
	
	select {
	case response := <- ping:
		if response != nil {
			// Connection is fine.
		} else {
			// Something went wrong.
		}
		
	case <-time.After(timeout):
		// Ping took too long.
		
	}
	
	// ...
}
```



Sending a server push:
```go
package main

import (
	"github.com/SlyMarbo/spdy"
	"net/http"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	// Push returns a separate http.ResponseWriter and an error.
	path := r.URL.Scheme + "://" + r.URL.Host + "/example.js"
	push, err := spdy.Push(path)
	if err != nil {
		// Not using SPDY.
	}
	http.ServeFile(push, r, "./content/example.js")

	// Note that a PushStream must be finished manually once
	// all writing has finished.
	push.Finish()
	
	// ...
}
```

Clients
-------

The client API is even easier to use. Simply import the spdy package to add SPDY support.
Here's a simple example that will fetch the requested page over HTTP, HTTPS, or SPDY, as necessary.
```go
package main

import (
	"fmt"
	_ "github.com/SlyMarbo/spdy" // Simply import SPDY.
	"io/ioutil"
	"net/http"
)

func main() {
	res, err := http.Get("https://example.com/") // http.Get (and .Post etc) can now use SPDY.
	if err != nil {
		// handle the error.
	}
	
	bytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		// handle the error.
	}
	res.Body.Close()
	
	fmt.Printf("Received: %s\n", bytes)
}
```


To add SPDY support to your own client, just use the spdy package's Transport.
```go
package main

import (
	"github.com/SlyMarbo/spdy" // Import SPDY.
	"net/http"
)

func main() {
	client := new(http.Client)
	client.Transport = new(spdy.Transport) // This client now supports HTTP, HTTPS, and SPDY.
	
	// ...
}
```
