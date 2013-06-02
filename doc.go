/*
Package spdy is a full-featured SPDY library for the Go language (still under very active development).

Note that this implementation currently supports SPDY drafts 2 and 3, and support for SPDY/4, and HTTP/2.0 is upcoming.

-------------------------------

		Servers

Adding SPDY support to an existing Go server requires minimal work.

Modifying a simple example server like the following:

		package main

		import (
			"net/http"
		)

		func Serve(w http.ResponseWriter, r *http.Request) {
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

Simply requires the following changes:

		package main

		import (
			"github.com/SlyMarbo/spdy" // Import SPDY.
			"net/http"
		)

		// This handler will now serve HTTP, HTTPS, and SPDY requests.
		func Serve(w http.ResponseWriter, r *http.Request) {
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


A very simple file server for both SPDY and HTTPS:

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


The following examples use features specific to SPDY.

Just the handler is shown.

Use SPDY's pinging features to test the connection:

		package main

		import (
			"github.com/SlyMarbo/spdy"
			"net/http"
			"time"
		)

		func Serve(w http.ResponseWriter, r *http.Request) {
			// Ping returns a channel which will send a bool.
			ping, err := spdy.PingClient(w)
			if err != nil {
				// Not using SPDY.
			}

			select {
			case _, ok := <- ping:
				if ok {
					// Connection is fine.
				} else {
					// Something went wrong.
				}

			case <-time.After(timeout):
				// Ping took too long.

			}

			// ...
		}


Sending a server push:

		package main

		import (
			"github.com/SlyMarbo/spdy"
			"net/http"
		)

		func Serve(w http.ResponseWriter, r *http.Request) {
			// Push returns a separate http.ResponseWriter and an error.
			push, err := spdy.Push("/example.js")
			if err != nil {
				// Not using SPDY.
			}
			http.ServeFile(push, r, "./content/example.js")

			// ...
		}

-------------------------------

		Clients

The basic client API seems to work well in general, but gets a redirect loop when requesting https://twitter.com/, so
I'm not happy with it. Since I can't see Twitter's servers' SPDY logs, I don't know what's wrong yet, but I'm working
hard at it.

Here's a simple example that will fetch the requested page over HTTP, HTTPS, or SPDY, as necessary.

		package main

		import (
			"fmt"
			"github.com/SlyMarbo/spdy" // Simply import SPDY.
			"io/ioutil"
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

*/
package spdy
