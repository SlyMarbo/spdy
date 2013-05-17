package spdy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type Client struct {
	ReadTimeout    time.Duration // maximum duration before timing out read of the request
	WriteTimeout   time.Duration // maximum duration before timing out write of the response
	TLSConfig      *tls.Config   // optional TLS config, used by ListenAndServeTLS
	GlobalSettings []*Setting    // SPDY settings to be sent to all clients automatically.

	httpClientConn     *httputil.ClientConn // backup for servers that don't support SPDY.
	MaxTcpConnsPerHost int                  // Maximum concurrent TCP connections per host.

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

// Do sends a SPDY request and returns a SPDY response,
// following policiy (e.g. redirects, cookies, auth) as
// configured on the client.
//
// Note that Do can also perform HTTP requests, in case
// the server does not support SPDY. Which protocol was
// used can be determined by checking the value set for
// Response.SentOverSpdy.
func (c *Client) Do(req *Request) (*Response, error) {
	conn, err := c.dial(req.URL)
	if err != nil {
		return nil, err
	}

	// Handle HTTPS/SPDY requests.
	// if tlsConn, ok := conn.(*tls.Conn); ok {
// 
// 	}

	// TODO: add connection handling.
	// Handle HTTP requests.
	httpConn := httputil.NewClientConn(conn, nil)
	httpReq := spdyToHttpRequest(req)
	httpRes, err := httpConn.Do(httpReq)
	if err != nil {
		return nil, err
	}

	return httpToSpdyResponse(httpRes, req), nil
}
