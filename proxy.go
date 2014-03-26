package spdy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ConnectAndServe is used to perform connection
// reversal where the client (who is normally
// behind a NAT of some kind) connects to a server
// on the internet. The connection is then reversed
// so that the 'server' sends requests to the 'client'.
//
// This works very similarly to ListenAndServeTLS,
// except that addr and config are used to connect
// to the client. If srv is nil, a new http.Server
// is used, with http.DefaultServeMux as the handler.
func ConnectAndServe(addr string, config *tls.Config, srv *http.Server) error {
	if config == nil {
		config = new(tls.Config)
	}
	if srv == nil {
		srv = &http.Server{Handler: http.DefaultServeMux}
	}
	AddSPDY(srv)

	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	var conn net.Conn

	conn, err = tls.Dial("tcp", u.Host, config)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		return err
	}

	client := httputil.NewClientConn(conn, nil)
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		log.Printf("Proxy responded with status code %d\n", res.StatusCode)
		return ErrConnectFail
	}

	conn, _ = client.Hijack()

	server, err := NewServerConn(conn, srv, 3.1)
	if err != nil {
		return err
	}

	return server.Run()
}

type ProxyConnHandler interface {
	ProxyConnHandle(Conn)
}

type ProxyConnHandlerFunc func(Conn)

func (p ProxyConnHandlerFunc) ProxyConnHandle(c Conn) {
	p(c)
}

type proxyHandler struct {
	ProxyConnHandler
}

func (p proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body.Close()

	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Println("Failed to hijack connection in ProxyConnections.", err)
		return
	}

	defer conn.Close()

	if _, ok := conn.(*tls.Conn); !ok {
		log.Println("Recieved a non-TLS connection in ProxyConnections.")
		return
	}

	// Send the connection accepted response.
	res := new(http.Response)
	res.Status = "200 Connection Established"
	res.StatusCode = http.StatusOK
	res.Proto = "HTTP/1.1"
	res.ProtoMajor = 1
	res.ProtoMinor = 1
	if err = res.Write(conn); err != nil {
		log.Println("Failed to send connection established message in ProxyConnections.", err)
		return
	}

	client, err := NewClientConn(conn, nil, 3.1)
	if err != nil {
		log.Println("Error creating SPDY connection in ProxyConnections.", err)
		return
	}

	go client.Run()

	// Call user code.
	p.ProxyConnHandle(client)

	client.Close()
}

// ProxyConnections is used with ConnectAndServe in connection-
// reversing proxies. This returns an http.Handler which will call
// handler each time a client connects. The call is treated as
// an event loop and the connection may be terminated if the call
// returns. The returned Handler should then be used in a normal
// HTTP server, like the following:
//
//   package main
//
//   import (
//     "net/http"
//
//     "github.com/SlyMarbo/spdy"
//   )
//
//   func handleProxy(conn spdy.Conn) {
//     // make requests...
//   }
//
//   func main() {
//     http.HandleFunc("/", spdy.ProxyConnHandlerFunc(handleProxy))
//     http.ListenAndServeTLS(":80", "cert.pem", "key.pem", nil)
//   }
//
// Use Conn.Request to make requests to the client and Conn.Conn
// to access the underlying connection for further details like
// the client's address.
func ProxyConnections(handler ProxyConnHandler) http.Handler {
	return proxyHandler{handler}
}
