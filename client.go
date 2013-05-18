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
	"strings"
	"sync"
	"time"
)

// Objects implementing the Receiver interface can be
// registered to a specific request on the Client.
//
// Receive is passed the original request, the raw data
// to receive and a bool indicating whether this is the
// final batch of data. If the bool is set to true, the
// data may be empty, but should not be nil.
type Receiver interface {
	ReceiveData(*Request, []byte, bool)
	ReceiveHeaders(*Request, Header)
	ReceiveStatus(*Request, int)
}

type Client struct {
	sync.RWMutex
	ReadTimeout        time.Duration // max duration before timing out read on the request
	WriteTimeout       time.Duration // max duration before timing out write on the response
	TLSConfig          *tls.Config   // optional TLS config, used by ListenAndServeTLS
	GlobalSettings     []*Setting    // SPDY settings to be sent to all servers automatically.
	MaxTcpConnsPerHost int           // Maximum concurrent TCP connections per host.

	spdyConns map[string]Connection // SPDY connections mapped to host:port.

	// Jar specifies the cookie jar.
	// If Jar is nil, cookies are not sent in requests and ignored
	// in responses.
	Jar http.CookieJar
}

// DefaultClient is the default Client and is used by Get, Head, and Post.
var DefaultClient = &Client{}

// dial makes the connection to an endpoint.
func (c *Client) dial(u *url.URL) (net.Conn, error) {
	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{
			NextProtos: []string{"http/1.1", "spdy/3"},
		}
	} else if c.TLSConfig.NextProtos == nil {
		c.TLSConfig.NextProtos = []string{"http/1.1", "spdy/3"}
	}

	switch u.Scheme {
	case "http":
		return net.Dial("tcp", u.Host)
	case "https":
		return tls.Dial("tcp", u.Host, c.TLSConfig)
	default:
		return nil, errors.New(fmt.Sprintf("Error: URL has invalid scheme %q.", u.Scheme))
	}
}

func (c *Client) doHTTP(conn net.Conn, req *Request) (*Response, error) {
	httpConn := httputil.NewClientConn(conn, nil)
	httpReq := spdyToHttpRequest(req)
	httpRes, err := httpConn.Do(httpReq)
	if err != nil {
		return nil, err
	}

	return httpToSpdyResponse(httpRes, req), nil
}

func (c *Client) do(req *Request) (*Response, error) {
	u := req.URL
	if !strings.Contains(u.Host, ":") {
		switch u.Scheme {
		case "http":
			u.Host += ":80"
		case "https":
			u.Host += ":443"
		default:
			return nil, errors.New(fmt.Sprintf("Error: URL has invalid scheme %q.", u.Scheme))
		}
	}

	c.Lock()
	if c.spdyConns == nil {
		c.spdyConns = make(map[string]Connection)
	}
	conn, ok := c.spdyConns[u.Host]
	if !ok {
		tcpConn, err := c.dial(req.URL)
		if err != nil {
			c.Unlock()
			return nil, err
		}

		// Handle HTTPS/SPDY requests.
		if tlsConn, ok := tcpConn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()

			// Complete handshake if necessary.
			if !state.HandshakeComplete {
				err = tlsConn.Handshake()
				if err != nil {
					c.Unlock()
					return nil, err
				}
			}

			// Verify hostname, unless requested not to.
			if !c.TLSConfig.InsecureSkipVerify {
				err = tlsConn.VerifyHostname(req.URL.Host)
				if err != nil {
					c.Unlock()
					return nil, err
				}
			}

			// If a protocol could not be negotiated, assume HTTPS.
			if !state.NegotiatedProtocolIsMutual {
				c.Unlock()
				return c.doHTTP(tcpConn, req)
			}

			switch state.NegotiatedProtocol {
			case "http/1.1", "":
				c.Unlock()
				return c.doHTTP(tcpConn, req)

			case "spdy/3":
				newConn := newClientConn(tlsConn)
				newConn.client = c
				newConn.version = 3
				go newConn.run()
				c.spdyConns[u.Host] = newConn
				conn = newConn
				c.Unlock()

			case "spdy/2":
				fmt.Println("Warning: Negotiated SPDY/2.")
				newConn := newClientConn(tlsConn)
				newConn.client = c
				newConn.version = 2
				go newConn.run()
				c.spdyConns[u.Host] = newConn
				conn = newConn
				c.Unlock()

			default:
				msg := fmt.Sprintf("Error: Unknonwn negotiated protocol %q.", state.NegotiatedProtocol)
				c.Unlock()
				return nil, errors.New(msg)
			}
		} else {
			// TODO: add connection handling.
			// Handle HTTP requests.
			c.Unlock()
			return c.doHTTP(tcpConn, req)
		}
	}

	// The connection has now been established.

	// Prepare the response.
	res := new(response)
	res.SPDYProto = int(conn.Version())
	res.Request = req
	res.Data = new(bytes.Buffer)

	// Send the request.
	stream, err := conn.Request(req, res)
	if err != nil {
		return nil, err
	}

	// Let the request run its course.
	stream.Run()

	return res.Response(), nil
}

// Do sends a SPDY request and returns a SPDY response,
// following policiy (e.g. redirects, cookies, auth) as
// configured on the client.
//
// Note that Do can also perform HTTP requests, in case
// the server does not support SPDY. Which protocol was
// used can be determined by checking the value set for
// Response.SentOverSpdy.
func (c *Client) Do(req *Request) (*Response, error) {
	return c.do(req)
}

// Get issues a GET to the specified URL. If the response
// is one of the following redirect codes, Get follows the
// redirect after calling the Client's CheckRedirect
// function.
//
//		301 (Moved Permanently)
//		302 (Found)
// 		303 (See Other)
//		307 (Temporary Redirect)
//
// And error is returned if the Client's CheckRedirect
// function fails or if there was an HTTP protocol error.
// A non-2xx response doesn't cause an error.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
func (c *Client) Get(url string) (*Response, error) {
	req, err := NewRequest("GET", url, nil, 3)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func Get(url string) (*Response, error) {
	return DefaultClient.Get(url)
}
