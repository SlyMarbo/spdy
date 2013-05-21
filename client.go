package spdy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
// ReceiveData is passed the original request, the data
// to receive and a bool indicating whether this is the
// final batch of data. If the bool is set to true, the
// data may be empty, but should not be nil.
//
// ReceiveHeaders is passed the request and any sent
// text headers. This may be called multiple times.
//
// ReceiveRequest is used when server pushes are sent.
// The returned bool should inticate whether to accept
// the push. The provided Request will be that sent by
// the server with the push.
type Receiver interface {
	ReceiveData(request *Request, data []byte, final bool)
	ReceiveHeaders(request *Request, header Header)
	ReceiveRequest(request *Request) bool
}

// A Client is an HTTP/SPDY client. Its zero value (DefaultClient) is
// a usable client.
//
// The Client has an internal state (cached TCP and SPDY connections),
// so Clients should be reused instead of created as needed. Clients
// are safe for concurrent use by multiple goroutines.
//
// A Client is higher-level than a RoundTripper (such as Transport)
// and additionally handles HTTP and SPDY details such as cookies and
// redirects.
type Client struct {
	sync.RWMutex
	ReadTimeout    time.Duration // max duration before timing out read on the request
	WriteTimeout   time.Duration // max duration before timing out write on the response
	TLSConfig      *tls.Config   // optional TLS config, used by ListenAndServeTLS
	GlobalSettings []*Setting    // SPDY settings to be sent to all servers automatically.

	// Maximum concurrent non-SPDY connections per host.
	// Changes to MaxTcpConnsPerHost are ignored after
	// the client has made any requests.
	MaxTcpConnsPerHost int

	spdyConns map[string]Connection    // SPDY connections mapped to host:port.
	tcpConns  map[string]chan net.Conn // Non-SPDY connections mapped to host:port.
	connLimit map[string]chan struct{} // Used to enforce the TCP conn limit.

	// CheckRedirect specifies the policy for handling redirects.
	// If CheckRedirect is not nil, the client calls it before
	// following an HTTP redirect. The arguments req and via are
	// the upcoming request and the requests made already, oldest
	// first. If CheckRedirect returns an error, the Client's Get
	// method returns both the previous Response and
	// CheckRedirect's error (wrapped in a url.Error) instead of
	// issuing the Request req.
	//
	// If CheckRedirect is nil, the Client uses its default policy,
	// which is to stop after 10 consecutive requests.
	CheckRedirect func(req *Request, via []*Request) error

	// Jar specifies the cookie jar.
	// If Jar is nil, cookies are not sent in requests and ignored
	// in responses.
	Jar http.CookieJar

	// MaxConcurrentStreams sets the maximum number of concurrent
	// streams streams that the library will allow servers to
	// create. The default value is 1000, and the limit can be
	// disabled by setting it to 0.
	MaxConcurrentStreams uint32

	// PushReceiver is used to receive server pushes. If left nil,
	// pushes will be refused. The provided Request will be that
	// sent with the server push. See Receiver for more detail on
	// its methods.
	PushReceiver Receiver
}

// DefaultClient is the default Client and is used by Get, Head, and Post.
var DefaultClient = &Client{}

// dial makes the connection to an endpoint.
func (c *Client) dial(u *url.URL) (net.Conn, error) {

	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{
			NextProtos: NpnStrings(),
		}
	} else if c.TLSConfig.NextProtos == nil {
		c.TLSConfig.NextProtos = NpnStrings()
	}

	// Wait for a connection slot to become available.
	<-c.connLimit[u.Host]

	switch u.Scheme {
	case "http":
		return net.Dial("tcp", u.Host)
	case "https":
		return tls.Dial("tcp", u.Host, c.TLSConfig)
	default:
		return nil, errors.New(fmt.Sprintf("Error: URL has invalid scheme %q.", u.Scheme))
	}
}

// doHTTP is used to process an HTTP(S) request, using the TCP connection pool.
func (c *Client) doHTTP(conn net.Conn, req *Request) (*Response, error) {
	debug.Printf("Requesting %q over HTTP.\n", req.URL.String())

	// Create the HTTP ClientConn, which handles the
	// HTTP details.
	httpConn := httputil.NewClientConn(conn, nil)
	httpReq := spdyToHttpRequest(req)
	httpRes, err := httpConn.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if !httpRes.Close {
		c.tcpConns[req.URL.Host] <- conn
	} else {
		// This connection is closing, so another can be used.
		c.connLimit[req.URL.Host] <- struct{}{}
		err = httpConn.Close()
		if err != nil {
			return nil, err
		}
	}

	return httpToSpdyResponse(httpRes, req), nil
}

// do handles the actual request; ensuring a connection is
// made, determining which protocol to use, and performing
// the request.
func (c *Client) do(req *Request) (*Response, error) {
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

	c.Lock()

	// Initialise structures if necessary.
	if c.spdyConns == nil {
		c.spdyConns = make(map[string]Connection)
	}
	if c.tcpConns == nil {
		c.tcpConns = make(map[string]chan net.Conn)
	}
	if c.connLimit == nil {
		c.connLimit = make(map[string]chan struct{})
	}
	if c.MaxTcpConnsPerHost == 0 {
		c.MaxTcpConnsPerHost = 6
	}
	if _, ok := c.connLimit[u.Host]; !ok {
		limitChan := make(chan struct{}, c.MaxTcpConnsPerHost)
		c.connLimit[u.Host] = limitChan
		for i := 0; i < c.MaxTcpConnsPerHost; i++ {
			limitChan <- struct{}{}
		}
	}

	// Check the non-SPDY connection pool.
	if connChan, ok := c.tcpConns[u.Host]; ok {
		select {
		case tcpConn := <-connChan:
			c.Unlock()
			// Use a connection from the pool.
			return c.doHTTP(tcpConn, req)
		default:
		}
	} else {
		c.tcpConns[u.Host] = make(chan net.Conn, c.MaxTcpConnsPerHost)
	}

	// Check the SPDY connection pool.
	conn, ok := c.spdyConns[u.Host]
	if !ok || u.Scheme == "http" {
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

			// Scan the list of supported NPN strings.
			supported := false
			for _, proto := range NpnStrings() {
				if state.NegotiatedProtocol == proto {
					supported = true
					break
				}
			}

			if !supported {
				msg := fmt.Sprintf("Error: Unsupported negotiated protocol %q.", state.NegotiatedProtocol)
				c.Unlock()
				return nil, errors.New(msg)
			}

			switch state.NegotiatedProtocol {
			case "http/1.1", "":
				c.Unlock()
				return c.doHTTP(tcpConn, req)

			case "spdy/3":
				newConn := newClientConn(tlsConn)
				newConn.client = c
				newConn.version = 3
				newConn.pushReceiver = c.PushReceiver
				go newConn.run()
				c.spdyConns[u.Host] = newConn
				conn = newConn
				c.Unlock()

			case "spdy/2":
				newConn := newClientConn(tlsConn)
				newConn.client = c
				newConn.version = 2
				newConn.pushReceiver = c.PushReceiver
				go newConn.run()
				c.spdyConns[u.Host] = newConn
				conn = newConn
				c.Unlock()
			}
		} else {
			// Handle HTTP requests.
			c.Unlock()
			return c.doHTTP(tcpConn, req)
		}
	}

	// The connection has now been established.

	debug.Printf("Requesting %q over SPDY.\n", u.String())

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

// doFollowingRedirects follows redirects while using c.do to actually process each request.
func (c *Client) doFollowingRedirects(ireq *Request, shouldRedirect func(int) bool) (res *Response, err error) {
	var base *url.URL
	redirectChecker := c.CheckRedirect
	if redirectChecker == nil {
		redirectChecker = defaultCheckRedirect
	}
	var via []*Request

	if ireq.URL == nil {
		return nil, errors.New("spdy: nil Request.URL")
	}

	req := ireq
	urlStr := "" // next relative or absolute URL to fetch (after first request)
	redirectFailed := false
	for redirect := 0; ; redirect++ {
		if redirect != 0 {
			req = new(Request)
			req.Method = ireq.Method
			if ireq.Method == "POST" || ireq.Method == "PUT" {
				req.Method = "GET"
			}
			req.Header = make(Header)
			req.URL, err = base.Parse(urlStr)
			if err != nil {
				break
			}
			u := req.URL
			if !strings.Contains(u.Host, ":") {
				switch u.Scheme {
				case "http":
					u.Host += ":80"
				case "https":
					u.Host += ":443"
				}
			}
			if len(via) > 0 {
				// Add the Referer header.
				lastReq := via[len(via)-1]
				if lastReq.URL.Scheme != "https" {
					req.Header.Set("Referer", lastReq.URL.String())
				}

				err = redirectChecker(req, via)
				if err != nil {
					redirectFailed = true
					break
				}
			}
		}

		urlStr = req.URL.String()
		if res, err = c.do(req); err != nil {
			break
		}

		if shouldRedirect(res.StatusCode) {
			res.Body.Close()
			if urlStr = res.Header.Get("Location"); urlStr == "" {
				err = errors.New(fmt.Sprintf("%d response missing Location header", res.StatusCode))
				break
			}
			base = req.URL
			via = append(via, req)
			continue
		}
		return res, err
	}

	method := ireq.Method
	urlErr := &url.Error{
		Op:  method[0:1] + strings.ToLower(method[1:]),
		URL: urlStr,
		Err: err,
	}

	if redirectFailed {
		// Special case for Go 1 compatibility: return both the response
		// and an error if the CheckRedirect function failed.
		// See http://golang.org/issue/3795
		return res, urlErr
	}

	if res != nil {
		res.Body.Close()
	}
	return nil, urlErr
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
	if req.Method == "GET" || req.Method == "HEAD" {
		return c.doFollowingRedirects(req, shouldRedirectGet)
	}
	if req.Method == "POST" || req.Method == "PUT" {
		return c.doFollowingRedirects(req, shouldRedirectPost)
	}
	return c.do(req)
}

// True if the specified HTTP status code is one for
// which the Get utility should automatically redirect.
func shouldRedirectGet(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound,
		http.StatusSeeOther, http.StatusTemporaryRedirect:
		return true
	}
	return false
}

// True if the specified HTTP status code is one for which the Post utility should
// automatically redirect.
func shouldRedirectPost(statusCode int) bool {
	switch statusCode {
	case http.StatusFound, http.StatusSeeOther:
		return true
	}
	return false
}

// defaultCheckRedirect simply accepts redirects until 10 have
// occurred, or a loop is detected.
func defaultCheckRedirect(req *Request, via []*Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	str := req.URL.String()
	for _, viareq := range via {
		if str == viareq.URL.String() {
			return errors.New("encountered redirect loop")
		}
	}
	return nil
}

// Get issues a GET to the specified URL.  If the response is one of the following
// redirect codes, Get follows the redirect, up to a maximum of 10 redirects:
//
//    301 (Moved Permanently)
//    302 (Found)
//    303 (See Other)
//    307 (Temporary Redirect)
//
// An error is returned if there were too many redirects or if there
// was an HTTP protocol error. A non-2xx response doesn't cause an
// error.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// Get is a wrapper around DefaultClient.Get.
func Get(url string) (*Response, error) {
	return DefaultClient.Get(url)
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
	req, err := NewRequest("GET", url, nil, DefaultPriority(url))
	if err != nil {
		return nil, err
	}
	return c.doFollowingRedirects(req, shouldRedirectGet)
}

// Post issues a POST to the specified URL.
//
// Caller should close resp.Body when done reading from it.
//
// Post is a wrapper around DefaultClient.Post
func Post(url string, bodyType string, body io.Reader) (*Response, error) {
	return DefaultClient.Post(url, bodyType, body)
}

// Post issues a POST to the specified URL.
//
// Caller should close resp.Body when done reading from it.
func (c *Client) Post(url string, bodyType string, body io.Reader) (*Response, error) {
	req, err := NewRequest("POST", url, body, DefaultPriority(url))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	return c.doFollowingRedirects(req, shouldRedirectPost)
}

// PostForm issues a POST to the specified URL, with data's keys and
// values URL-encoded as the request body.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// PostForm is a wrapper around DefaultClient.PostForm
func PostForm(url string, data url.Values) (*Response, error) {
	return DefaultClient.PostForm(url, data)
}

// PostForm issues a POST to the specified URL,
// with data's keys and values urlencoded as the request body.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
func (c *Client) PostForm(url string, data url.Values) (resp *Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Head issues a HEAD to the specified URL.  If the response is one of the
// following redirect codes, Head follows the redirect after calling the
// Client's CheckRedirect function.
//
//    301 (Moved Permanently)
//    302 (Found)
//    303 (See Other)
//    307 (Temporary Redirect)
//
// Head is a wrapper around DefaultClient.Head
func Head(url string) (resp *Response, err error) {
	return DefaultClient.Head(url)
}

// Head issues a HEAD to the specified URL.  If the response is one of the
// following redirect codes, Head follows the redirect after calling the
// Client's CheckRedirect function.
//
//    301 (Moved Permanently)
//    302 (Found)
//    303 (See Other)
//    307 (Temporary Redirect)
func (c *Client) Head(url string) (resp *Response, err error) {
	req, err := NewRequest("HEAD", url, nil, DefaultPriority(url))
	if err != nil {
		return nil, err
	}
	return c.doFollowingRedirects(req, shouldRedirectGet)
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }
