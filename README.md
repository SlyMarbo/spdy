spdy
====

A full-featured SPDY library for the Go language (still under very active development).

So far, servers and clients are ready, but the client API is not completely stable.
 
Note that this implementation currently supports SPDY drafts 2 and 3.

Servers
-------

Adding SPDY support to an existing Go server doesn't take much work.

Modifying a simple example server like the following:
```go
package main

import (
	"net/http"
)

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, HTTP!"))
}

func main() {
	
	// Register handler.
	http.HandleFunc("/", ServeHTTP)

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
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, HTTP!"))
}

func main() {
	
	// Register handler.
	http.HandleFunc("/", ServeHTTP)

	// Use spdy's ListenAndServe.
	err := spdy.ListenAndServeTLS("localhost:443", "cert.pem", "key.pem", nil)
	if err != nil {
		// handle error.
	}
}
```

SPDY now supports reuse of HTTP handlers, as demonstrated above. Although this allows you to use just one set of
handlers, it means there is no way to use the SPDY-specific capabilities provided by `spdy.ResponseWriter`, such as
server pushes, or to know which protocol is being used.

Making full use of the SPDY protocol simple requires adding an extra handler:
```go
package main

import (
	"github.com/SlyMarbo/spdy"
	"net/http"
)

// This now only serves HTTP/HTTPS requests.
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, HTTP!"))
}

// Add a SPDY handler.
func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	w.Write([]byte("Hello, SPDY!"))
}

func main() {
	
	// Register handlers.
	http.HandleFunc("/", ServeHTTP)
	spdy.HandleFunc("/", ServeSPDY)

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

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "." + r.RequestURI)
}

func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	spdy.ServeFile(w, r, "." + r.RequestURI)
}

func main() {
	
	// Register handlers.
	http.HandleFunc("/", ServeHTTP)
	spdy.HandleFunc("/", ServeSPDY)

	err := spdy.ListenAndServeTLS("localhost:443", "cert.pem", "key.pem", nil)
	if err != nil {
		// handle error.
	}
}
```



The following examples use features specific to SPDY.

Just the SPDY handler is shown.

Use SPDY's pinging features to test the connection:
```go
package main

import (
	"github.com/SlyMarbo/spdy"
	"time"
)

func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	// Ping returns a channel which will send a bool.
	ping := w.Ping()
	
	select {
	case success := <- ping:
		if success {
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

import "github.com/SlyMarbo/spdy"

func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	
	// Push a whole file automatically.
	spdy.PushFile(w, r, otherFile)
	
	// or
	
	// Push returns a PushWriter (similar to a ResponseWriter) and an error.
	push, err := w.Push()
	if err != nil {
		// Handle the error.
	}
	push.Write([]byte("Some stuff."))   // Push data manually.
	
	// ...
}
```



Sending SPDY settings:
```go
package main

import "github.com/SlyMarbo/spdy"

func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
	
	setting := new(spdy.Setting)
	setting.Flags = spdy.FLAG_SETTINGS_PERSIST_VALUE
	setting.ID = spdy.SETTINGS_MAX_CONCURRENT_STREAMS
	setting.Value = 500
	
	w.WriteSettings(setting)
	
	// ...
}
```

Clients
-------

The basic client API seems to work well in general, but gets a redirect loop when requesting https://twitter.com/, so
I'm not happy with it. Since I can't see Twitter's servers' SPDY logs, I don't know what's wrong yet, but I'm working
hard at it.

Here's a simple example that will fetch the requested page over HTTP, HTTPS, or SPDY, as necessary.
```go
package main

import (
	"fmt"
	"github.com/SlyMarbo/spdy"
	"io/ioutil"
)

func main() {
	res, err := spdy.Get("https://example.com/")
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
