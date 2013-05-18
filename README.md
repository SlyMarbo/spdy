spdy
====

My implementation of SPDY/v3 (work in progress).

So far, servers are ready, but the client API is experimental.
 
Note that this implementation supports SPDY/3, but not SPDY/2.

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
	"github.com/SlyMarbo/spdy"
	"net/http"
)

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

The basic client API seems to work ok with this package's servers, but gets error responses when
requesting https://www.google.co.uk/, so I'm not happy with it. Since I can't see Google's servers'
SPDY error logs, I don't know what's wrong yet, but I'm working hard at it.

The existing client API is small, but will (in due course) mirror the net/http API.

Here's a simple example that will fetch the requested page over HTTP, HTTPS, or SPDY, as necessary.
```go
package main

import (
	"bytes"
	"fmt"
	"github.com/SlyMarbo/spdy"
	"io"
)

func main() {
	res, err := spdy.Get("https://example.com/")
	if err != nil {
		// handle the error.
	}
	
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, res.Body)
	if err != nil {
		// handle the error.
	}
	
	res.Body.Close()
	
	fmt.Printf("Received: %s\n", buf.String())
}
```
