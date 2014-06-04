// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/SlyMarbo/spdy/common"
	"github.com/SlyMarbo/spdy/spdy2"
	"github.com/SlyMarbo/spdy/spdy3"
)

// NewServerConn is used to create a SPDY connection, using the given
// net.Conn for the underlying connection, and the given http.Server to
// configure the request serving.
func NewServerConn(conn net.Conn, server *http.Server, version float64) (common.Conn, error) {
	if conn == nil {
		return nil, errors.New("Error: Connection initialised with nil net.conn.")
	}
	if server == nil {
		return nil, errors.New("Error: Connection initialised with nil server.")
	}

	switch version {
	case 3:
		return spdy3.NewConn(conn, server, 0), nil

	case 3.1:
		return spdy3.NewConn(conn, server, 1), nil

	case 2:
		return spdy2.NewConn(conn, server), nil

	default:
		return nil, errors.New("Error: Unsupported SPDY version.")
	}
}

// ListenAndServeTLS listens on the TCP network address addr
// and then calls Serve with handler to handle requests on
// incoming connections.  Handler is typically nil, in which
// case the DefaultServeMux is used. Additionally, files
// containing a certificate and matching private key for the
// server must be provided. If the certificate is signed by
// a certificate authority, the certFile should be the
// concatenation of the server's certificate followed by the
// CA's certificate.
//
// A trivial example server is:
//
//      import (
//              "github.com/SlyMarbo/spdy"
//              "log"
//              "net/http"
//      )
//
//      func httpHandler(w http.ResponseWriter, req *http.Request) {
//              w.Header().Set("Content-Type", "text/plain")
//              w.Write([]byte("This is an example server.\n"))
//      }
//
//      func main() {
//              http.HandleFunc("/", httpHandler)
//              log.Printf("About to listen on 10443. Go to https://127.0.0.1:10443/")
//              err := spdy.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil)
//              if err != nil {
//                      log.Fatal(err)
//              }
//      }
//
// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	npnStrings := npn()
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			NextProtos: npnStrings,
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	for _, str := range npnStrings {
		switch str {
		case "spdy/2":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 2)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
				conn = nil
				runtime.GC()
			}
		case "spdy/3":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 3)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
				conn = nil
				runtime.GC()
			}
		case "spdy/3.1":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 3.1)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
				conn = nil
				runtime.GC()
			}
		}
	}

	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServeTLS listens on the TCP network address addr
// and then calls Serve with handler to handle requests on
// incoming connections.  Handler is typically nil, in which
// case the DefaultServeMux is used. Additionally, files
// containing a certificate and matching private key for the
// server must be provided. If the certificate is signed by
// a certificate authority, the certFile should be the
// concatenation of the server's certificate followed by the
// CA's certificate.
//
// IMPORTANT NOTE: Unlike spdy.ListenAndServeTLS, this function
// will ONLY serve SPDY. HTTPS requests are refused.
//
// A trivial example server is:
//
//      import (
//              "github.com/SlyMarbo/spdy"
//              "log"
//              "net/http"
//      )
//
//      func httpHandler(w http.ResponseWriter, req *http.Request) {
//              w.Header().Set("Content-Type", "text/plain")
//              w.Write([]byte("This is an example server.\n"))
//      }
//
//      func main() {
//              http.HandleFunc("/", httpHandler)
//              log.Printf("About to listen on 10443. Go to https://127.0.0.1:10443/")
//              err := spdy.ListenAndServeSPDY(":10443", "cert.pem", "key.pem", nil)
//              if err != nil {
//                      log.Fatal(err)
//              }
//      }
//
// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
func ListenAndServeSPDY(addr string, certFile string, keyFile string, handler http.Handler) error {
	npnStrings := npn()
	if addr == "" {
		addr = ":https"
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			NextProtos:   npnStrings,
			Certificates: make([]tls.Certificate, 1),
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	for _, str := range npnStrings {
		switch str {
		case "spdy/2":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 2)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
				conn = nil
				runtime.GC()
			}
		case "spdy/3":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 3)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
				conn = nil
				runtime.GC()
			}
		case "spdy/3.1":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 3.1)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
				conn = nil
				runtime.GC()
			}
		}
	}

	var err error
	server.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	conn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(conn, server.TLSConfig)
	defer tlsListener.Close()

	// Main loop
	var tempDelay time.Duration
	for {
		rw, e := tlsListener.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		go serveSPDY(rw, server)
	}
}

// ListenAndServeSPDYNoNPN creates a server that listens exclusively
// for SPDY and (unlike the rest of the package) will not support
// HTTPS.
func ListenAndServeSPDYNoNPN(addr string, certFile string, keyFile string, handler http.Handler, version float64) error {
	if addr == "" {
		addr = ":https"
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: make([]tls.Certificate, 1),
		},
	}

	var err error
	server.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	conn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(conn, server.TLSConfig)
	defer tlsListener.Close()

	// Main loop
	var tempDelay time.Duration
	for {
		rw, e := tlsListener.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		go serveSPDYNoNPN(rw, server, version)
	}
}

func serveSPDY(conn net.Conn, srv *http.Server) {
	defer func() {
		if v := recover(); v != nil {
			const size = 4096
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic serving %v: %v\n%s", conn.RemoteAddr(), v, buf)
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok { // Only allow TLS connections.
		return
	}

	if d := srv.ReadTimeout; d != 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := srv.WriteTimeout; d != 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	tlsState := new(tls.ConnectionState)
	*tlsState = tlsConn.ConnectionState()
	proto := tlsState.NegotiatedProtocol
	if fn := srv.TLSNextProto[proto]; fn != nil {
		fn(srv, tlsConn, nil)
	}
	return
}

func serveSPDYNoNPN(conn net.Conn, srv *http.Server, version float64) {
	defer func() {
		if v := recover(); v != nil {
			const size = 4096
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic serving %v: %v\n%s", conn.RemoteAddr(), v, buf)
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok { // Only allow TLS connections.
		return
	}

	if d := srv.ReadTimeout; d != 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := srv.WriteTimeout; d != 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	serverConn, err := NewServerConn(tlsConn, srv, version)
	if err != nil {
		log.Println(err)
		return
	}
	serverConn.Run()
	serverConn = nil
	runtime.GC()

	return
}
