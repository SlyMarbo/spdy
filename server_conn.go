package spdy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
)

func NewServerConn(conn net.Conn, server *http.Server, version uint16) (spdyConn Conn, err error) {
	if conn == nil {
		return nil, errors.New("Error: Connection initialised with nil net.conn.")
	}
	if server == nil {
		return nil, errors.New("Error: Connection initialised with nil server.")
	}

	switch version {
	case 3:
		out := new(connV3)
		out.remoteAddr = conn.RemoteAddr().String()
		out.server = server
		out.conn = conn
		out.buf = bufio.NewReader(conn)
		if tlsConn, ok := conn.(*tls.Conn); ok {
			out.tlsState = new(tls.ConnectionState)
			*out.tlsState = tlsConn.ConnectionState()
		}
		out.streams = make(map[StreamID]Stream)
		out.output = [8]chan Frame{}
		out.output[0] = make(chan Frame)
		out.output[1] = make(chan Frame)
		out.output[2] = make(chan Frame)
		out.output[3] = make(chan Frame)
		out.output[4] = make(chan Frame)
		out.output[5] = make(chan Frame)
		out.output[6] = make(chan Frame)
		out.output[7] = make(chan Frame)
		out.pings = make(map[uint32]chan<- Ping)
		out.nextPingID = 2
		out.compressor = NewCompressor(3)
		out.decompressor = NewDecompressor(3)
		out.receivedSettings = make(Settings)
		out.lastPushStreamID = 0
		out.lastRequestStreamID = 0
		out.oddity = 0
		out.initialWindowSize = DEFAULT_INITIAL_WINDOW_SIZE
		out.requestStreamLimit = newStreamLimit(DEFAULT_STREAM_LIMIT)
		out.pushStreamLimit = newStreamLimit(NO_STREAM_LIMIT)
		out.vectorIndex = 8
		out.certificates = make(map[uint16][]*x509.Certificate, 8)
		if out.tlsState != nil && out.tlsState.PeerCertificates != nil {
			out.certificates[1] = out.tlsState.PeerCertificates
		}
		out.stop = make(chan struct{})
		out.init = func() {
			// Initialise the connection by sending the connection settings.
			settings := new(settingsFrameV3)
			settings.Flags = FLAG_SETTINGS_PERSIST_VALUE
			settings.Settings = defaultSPDYServerSettings(3, DEFAULT_STREAM_LIMIT)
			out.output[0] <- settings
		}

		return out, nil

	default:
		return nil, errors.New("Error: Unsupported SPDY version.")
	}
}

// AddSPDY adds SPDY support to srv, and must be called before srv begins serving.
func AddSPDY(srv *http.Server) {
	npnStrings := npn()
	if len(npnStrings) <= 1 {
		return
	}
	if srv.TLSConfig == nil {
		srv.TLSConfig = new(tls.Config)
	}
	if srv.TLSConfig.NextProtos == nil {
		srv.TLSConfig.NextProtos = npnStrings
	} else {
		// Collect compatible alternative protocols.
		others := make([]string, 0, len(srv.TLSConfig.NextProtos))
		for _, other := range srv.TLSConfig.NextProtos {
			if !strings.Contains(other, "spdy/") && !strings.Contains(other, "http/") {
				others = append(others, other)
			}
		}

		// Start with spdy.
		srv.TLSConfig.NextProtos = make([]string, 0, len(others)+len(npnStrings))
		srv.TLSConfig.NextProtos = append(srv.TLSConfig.NextProtos, npnStrings[:len(npnStrings)-1]...)

		// Add the others.
		srv.TLSConfig.NextProtos = append(srv.TLSConfig.NextProtos, others...)
		srv.TLSConfig.NextProtos = append(srv.TLSConfig.NextProtos, "http/1.1")
	}
	if srv.TLSNextProto == nil {
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	for _, str := range npnStrings {
		switch str {
		case "spdy/2":
			srv.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 2)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
			}
		case "spdy/3":
			srv.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 3)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
			}
		}
	}
}

// ErrNotSPDY indicates that a SPDY-specific feature was attempted
// with a ResponseWriter using a non-SPDY connection.
var ErrNotSPDY = errors.New("Error: Not a SPDY connection.")

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
			}
		case "spdy/3":
			server.TLSNextProto[str] = func(s *http.Server, tlsConn *tls.Conn, handler http.Handler) {
				conn, err := NewServerConn(tlsConn, s, 3)
				if err != nil {
					log.Println(err)
					return
				}
				conn.Run()
			}
		}
	}

	return server.ListenAndServeTLS(certFile, keyFile)
}

// Push is used to send server pushes with SPDY servers.
// Push takes a ResponseWriter and the url of the resource
// being pushed, and returns a ResponseWriter to which the
// push should be written.
//
// If the underlying connection is using HTTP, and not SPDY,
// Push will return the ErrNotSPDY error.
//
// A simple example of pushing a file is:
//
//      import (
//              "github.com/SlyMarbo/spdy"
//              "log"
//              "net/http"
//      )
//
//      func httpHandler(w http.ResponseWriter, req *http.Request) {
//              push, err := spdy.Push(w, "/javascript.js")
//              if err != nil {
//                      // HTTP connection.
//              } else {
//                      http.ServeFile(push, req, "./javascript.js")
//              }
//              
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
func Push(w http.ResponseWriter, url string) (http.ResponseWriter, error) {
	if stream, ok := w.(Stream); !ok {
		return nil, ErrNotSPDY
	} else {
		return stream.Conn().Push(url, stream)
	}
}

// SPDYversion returns the SPDY version being used in the underlying
// connection used by the given http.ResponseWriter. This is 0 for
// connections not using SPDY.
func SPDYversion(w http.ResponseWriter) uint16 {
	if stream, ok := w.(Stream); ok {
		switch stream.Conn().(type) {
		case *connV3:
			return 3

		default:
			return 0
		}
	}
	return 0
}

// UsingSPDY indicates whether a given ResponseWriter is using SPDY.
func UsingSPDY(w http.ResponseWriter) bool {
	_, ok := w.(Stream)
	return ok
}
