package spdy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A Transport is an HTTP/SPDY http.RoundTripper.
type Transport struct {
	m sync.Mutex

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// Dial specifies the dial function for creating TCP
	// connections.
	// If Dial is nil, net.Dial is used.
	Dial func(network, addr string) (net.Conn, error) // TODO: use

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// DisableKeepAlives, if true, prevents re-use of TCP connections
	// between different HTTP requests.
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) to keep per-host.  If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	spdyConns map[string]Conn          // SPDY connections mapped to host:port.
	tcpConns  map[string]chan net.Conn // Non-SPDY connections mapped to host:port.
	connLimit map[string]chan struct{} // Used to enforce the TCP conn limit.

	// Priority is used to determine the request priority of SPDY
	// requests. If nil, spdy.DefaultPriority is used.
	Priority func(*url.URL) Priority

	// Receiver is used to receive the server's response. If left
	// nil, the default Receiver will parse and create a normal
	// Response.
	Receiver Receiver

	// PushReceiver is used to receive server pushes. If left nil,
	// pushes will be refused. The provided Request will be that
	// sent with the server push. See Receiver for more detail on
	// its methods.
	PushReceiver Receiver
}

// dial makes the connection to an endpoint.
func (t *Transport) dial(u *url.URL) (net.Conn, error) {

	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{
			NextProtos: npn(),
		}
	} else if t.TLSClientConfig.NextProtos == nil {
		t.TLSClientConfig.NextProtos = npn()
	}

	// Wait for a connection slot to become available.
	<-t.connLimit[u.Host]

	switch u.Scheme {
	case "http":
		return net.Dial("tcp", u.Host)
	case "https":
		return tls.Dial("tcp", u.Host, t.TLSClientConfig)
	default:
		return nil, errors.New(fmt.Sprintf("Error: URL has invalid scheme %q.", u.Scheme))
	}
}

// doHTTP is used to process an HTTP(S) request, using the TCP connection pool.
func (t *Transport) doHTTP(conn net.Conn, req *http.Request) (*http.Response, error) {
	debug.Printf("Requesting %q over HTTP.\n", req.URL.String())

	// Create the HTTP ClientConn, which handles the
	// HTTP details.
	httpConn := httputil.NewClientConn(conn, nil)
	res, err := httpConn.Do(req)
	if err != nil {
		return nil, err
	}

	if !res.Close {
		t.tcpConns[req.URL.Host] <- conn
	} else {
		// This connection is closing, so another can be used.
		t.connLimit[req.URL.Host] <- struct{}{}
		err = httpConn.Close()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// RoundTrip handles the actual request; ensuring a connection is
// made, determining which protocol to use, and performing the
// request.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL

	// Make sure the URL host contains the port.
	if !strings.Contains(u.Host, ":") {
		switch u.Scheme {
		case "http":
			u.Host += ":80"

		case "https":
			u.Host += ":443"
		}
	}

	t.m.Lock()

	// Initialise structures if necessary.
	if t.spdyConns == nil {
		t.spdyConns = make(map[string]Conn)
	}
	if t.tcpConns == nil {
		t.tcpConns = make(map[string]chan net.Conn)
	}
	if t.connLimit == nil {
		t.connLimit = make(map[string]chan struct{})
	}
	if t.MaxIdleConnsPerHost == 0 {
		t.MaxIdleConnsPerHost = http.DefaultMaxIdleConnsPerHost
	}
	if _, ok := t.connLimit[u.Host]; !ok {
		limitChan := make(chan struct{}, t.MaxIdleConnsPerHost)
		t.connLimit[u.Host] = limitChan
		for i := 0; i < t.MaxIdleConnsPerHost; i++ {
			limitChan <- struct{}{}
		}
	}

	// Check the non-SPDY connection pool.
	if connChan, ok := t.tcpConns[u.Host]; ok {
		select {
		case tcpConn := <-connChan:
			t.m.Unlock()
			// Use a connection from the pool.
			return t.doHTTP(tcpConn, req)
		default:
		}
	} else {
		t.tcpConns[u.Host] = make(chan net.Conn, t.MaxIdleConnsPerHost)
	}

	// Check the SPDY connection pool.
	conn, ok := t.spdyConns[u.Host]
	if !ok || u.Scheme == "http" {
		tcpConn, err := t.dial(req.URL)
		if err != nil {
			t.m.Unlock()
			return nil, err
		}

		// Handle HTTPS/SPDY requests.
		if tlsConn, ok := tcpConn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()

			// Complete handshake if necessary.
			if !state.HandshakeComplete {
				err = tlsConn.Handshake()
				if err != nil {
					t.m.Unlock()
					return nil, err
				}
			}

			// Verify hostname, unless requested not to.
			if !t.TLSClientConfig.InsecureSkipVerify {
				err = tlsConn.VerifyHostname(req.URL.Host)
				if err != nil {
					t.m.Unlock()
					return nil, err
				}
			}

			// If a protocol could not be negotiated, assume HTTPS.
			if !state.NegotiatedProtocolIsMutual {
				t.m.Unlock()
				return t.doHTTP(tcpConn, req)
			}

			// Scan the list of supported NPN strings.
			supported := false
			for _, proto := range npn() {
				if state.NegotiatedProtocol == proto {
					supported = true
					break
				}
			}

			// Ensure the negotiated protocol is supported.
			if !supported {
				msg := fmt.Sprintf("Error: Unsupported negotiated protocol %q.", state.NegotiatedProtocol)
				t.m.Unlock()
				return nil, errors.New(msg)
			}

			// Handle the protocol.
			switch state.NegotiatedProtocol {
			case "http/1.1", "":
				t.m.Unlock()
				return t.doHTTP(tcpConn, req)

			case "spdy/3":
				newConn, err := NewClientConn(tlsConn, t.PushReceiver, 3)
				if err != nil {
					return nil, err
				}
				go newConn.Run()
				t.spdyConns[u.Host] = newConn
				conn = newConn

			case "spdy/2":
				newConn, err := NewClientConn(tlsConn, t.PushReceiver, 2)
				if err != nil {
					return nil, err
				}
				go newConn.Run()
				t.spdyConns[u.Host] = newConn
				conn = newConn
			}
		} else {
			// Handle HTTP requests.
			t.m.Unlock()
			return t.doHTTP(tcpConn, req)
		}
	}
	t.m.Unlock()

	// The connection has now been established.

	debug.Printf("Requesting %q over SPDY.\n", u.String())

	// Prepare the response.
	res := new(response)
	res.Request = req
	res.Data = new(bytes.Buffer)
	res.Receiver = t.Receiver

	// Determine the request priority.
	priority := Priority(0)
	if t.Priority != nil {
		priority = t.Priority(req.URL)
	} else {
		priority = DefaultPriority(req.URL)
	}

	// Send the request.
	stream, err := conn.Request(req, res, priority)
	if err != nil {
		return nil, err
	}

	// Let the request run its course.
	stream.Run()

	return res.Response(), nil
}

// response is used in handling responses; storing
// the data as it's received, and producing an
// http.Response once complete.
//
// response may be given a Receiver to enable live
// handling of the response data. This is provided
// by setting spdy.Transport.Receiver.
type response struct {
	StatusCode int
	Header     http.Header
	Data       *bytes.Buffer
	Request    *http.Request
	Receiver   Receiver
}

func (r *response) ReceiveData(req *http.Request, data []byte, finished bool) {
	r.Data.Write(data)
	if r.Receiver != nil {
		r.Receiver.ReceiveData(req, data, finished)
	}
}

var statusRegex = regexp.MustCompile(`\A\s*(?P<code>\d+)`)

func (r *response) ReceiveHeader(req *http.Request, header http.Header) {
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	updateHeader(r.Header, header)
	if status := r.Header.Get(":status"); status != "" && statusRegex.MatchString(status) {
		if matches := statusRegex.FindAllStringSubmatch(status, -1); matches != nil {
			s, err := strconv.Atoi(matches[0][1])
			if err == nil {
				r.StatusCode = s
			}
		}
	}
	if r.Receiver != nil {
		r.Receiver.ReceiveHeader(req, header)
	}
}

func (r *response) ReceiveRequest(req *http.Request) bool {
	if r.Receiver != nil {
		return r.Receiver.ReceiveRequest(req)
	}
	return false
}

func (r *response) Response() *http.Response {
	if r.Data == nil {
		r.Data = new(bytes.Buffer)
	}
	out := new(http.Response)
	out.Status = fmt.Sprintf("%d %s", r.StatusCode, http.StatusText(r.StatusCode))
	out.StatusCode = r.StatusCode
	out.Proto = "HTTP/1.1"
	out.ProtoMajor = 1
	out.ProtoMinor = 1
	out.Header = r.Header
	out.Body = &readCloser{r.Data}
	out.ContentLength = int64(r.Data.Len())
	out.TransferEncoding = nil
	out.Close = true
	out.Trailer = make(http.Header)
	out.Request = r.Request
	return out
}
