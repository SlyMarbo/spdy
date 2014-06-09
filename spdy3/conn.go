// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy3

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SlyMarbo/spdy/common"
	"github.com/SlyMarbo/spdy/spdy3/frames"
	"github.com/SlyMarbo/spdy/spdy3/streams"
	"github.com/SlyMarbo/spin"
)

// Conn is a spdy.Conn implementing SPDY/3. This is used in both
// servers and clients, and is created with either NewServerConn,
// or NewClientConn.
type Conn struct {
	PushReceiver common.Receiver // Receiver to call for server Pushes.
	Subversion   int             // SPDY 3 subversion (eg 0 for SPDY/3, 1 for SPDY/3.1).

	remoteAddr              string
	server                  *http.Server                          // nil if client connection.
	conn                    net.Conn                              // underlying network (TLS) connection.
	connLock                spin.Lock                             // protects the interface value of the above conn.
	buf                     *bufio.Reader                         // buffered reader on conn.
	tlsState                *tls.ConnectionState                  // underlying TLS connection state.
	streams                 map[common.StreamID]common.Stream     // map of active streams.
	streamsLock             spin.Lock                             // protects streams.
	output                  [8]chan common.Frame                  // one output channel per priority level.
	pings                   map[uint32]chan<- common.Ping         // response channel for pings.
	pingsLock               spin.Lock                             // protects pings.
	nextPingID              uint32                                // next outbound ping ID.
	nextPingIDLock          spin.Lock                             // protects nextPingID.
	compressor              common.Compressor                     // outbound compression state.
	decompressor            common.Decompressor                   // inbound decompression state.
	receivedSettings        common.Settings                       // settings sent by client.
	lastPushStreamID        common.StreamID                       // last push stream ID. (even)
	lastPushStreamIDLock    spin.Lock                             // protects lastPushStreamID.
	lastRequestStreamID     common.StreamID                       // last request stream ID. (odd)
	lastRequestStreamIDLock spin.Lock                             // protects lastRequestStreamID.
	streamCreation          sync.Mutex                            // ensures new streams are sent in order.
	oddity                  common.StreamID                       // whether locally-sent streams are odd or even.
	initialWindowSize       uint32                                // initial transport window.
	initialWindowSizeLock   spin.Lock                             // lock for initialWindowSize
	goawayReceived          bool                                  // goaway has been received.
	goawaySent              bool                                  // goaway has been sent.
	goawayLock              spin.Lock                             // protects goawayReceived and goawaySent.
	numBenignErrors         int                                   // number of non-serious errors encountered.
	requestStreamLimit      *common.StreamLimit                   // Limit on streams started by the client.
	pushStreamLimit         *common.StreamLimit                   // Limit on streams started by the server.
	vectorIndex             uint16                                // current limit on the credential vector size.
	certificates            map[uint16][]*x509.Certificate        // certificates received in CREDENTIAL frames and TLS handshake.
	pushRequests            map[common.StreamID]*http.Request     // map of requests sent in server pushes.
	stop                    chan bool                             // this channel is closed when the connection closes.
	sending                 chan struct{}                         // this channel is used to ensure pending frames are sent.
	sendingLock             spin.Lock                             // protects changes to sending's value.
	init                    func()                                // this function is called before the connection begins.
	readTimeout             time.Duration                         // optional timeout for network reads.
	writeTimeout            time.Duration                         // optional timeout for network writes.
	timeoutLock             spin.Lock                             // protects readTimeout and writeTimeout.
	flowControl             common.FlowControl                    // flow control module.
	flowControlLock         spin.Lock                             // protects flowControl.
	pushedResources         map[common.Stream]map[string]struct{} // used to prevent duplicate headers being pushed.
	shutdownOnce            sync.Once                             // used to ensure clean shutdown.

	// SPDY/3.1
	dataBuffer                []*frames.DATA // used to store frames witheld for flow control.
	connectionWindowSize      int64
	initialWindowSizeThere    uint32
	connectionWindowSizeThere int64
}

// NewConn produces an initialised spdy3 connection.
func NewConn(conn net.Conn, server *http.Server, subversion int) *Conn {
	out := new(Conn)

	// Common ground.
	out.remoteAddr = conn.RemoteAddr().String()
	out.server = server
	out.conn = conn
	out.buf = bufio.NewReader(conn)
	if tlsConn, ok := conn.(*tls.Conn); ok {
		out.tlsState = new(tls.ConnectionState)
		*out.tlsState = tlsConn.ConnectionState()
	}
	out.streams = make(map[common.StreamID]common.Stream)
	out.output[0] = make(chan common.Frame)
	out.output[1] = make(chan common.Frame)
	out.output[2] = make(chan common.Frame)
	out.output[3] = make(chan common.Frame)
	out.output[4] = make(chan common.Frame)
	out.output[5] = make(chan common.Frame)
	out.output[6] = make(chan common.Frame)
	out.output[7] = make(chan common.Frame)
	out.pings = make(map[uint32]chan<- common.Ping)
	out.compressor = common.NewCompressor(3)
	out.decompressor = common.NewDecompressor(3)
	out.receivedSettings = make(common.Settings)
	out.lastPushStreamID = 0
	out.lastRequestStreamID = 0
	out.stop = make(chan bool)
	out.Subversion = subversion

	// Server/client specific.
	if server != nil { // servers
		out.nextPingID = 2
		out.oddity = 0
		out.initialWindowSize = common.DEFAULT_INITIAL_WINDOW_SIZE
		out.requestStreamLimit = common.NewStreamLimit(common.DEFAULT_STREAM_LIMIT)
		out.pushStreamLimit = common.NewStreamLimit(common.NO_STREAM_LIMIT)
		out.vectorIndex = 8
		out.init = func() {
			// Initialise the connection by sending the connection settings.
			settings := new(frames.SETTINGS)
			settings.Settings = defaultServerSettings(common.DEFAULT_STREAM_LIMIT)
			out.output[0] <- settings
		}
		if d := server.ReadTimeout; d != 0 {
			out.SetReadTimeout(d)
		}
		if d := server.WriteTimeout; d != 0 {
			out.SetWriteTimeout(d)
		}
		out.flowControl = streams.DefaultFlowControl(common.DEFAULT_INITIAL_WINDOW_SIZE)
		out.pushedResources = make(map[common.Stream]map[string]struct{})

		if subversion == 0 {
			out.certificates = make(map[uint16][]*x509.Certificate, 8)
			if out.tlsState != nil && out.tlsState.PeerCertificates != nil {
				out.certificates[1] = out.tlsState.PeerCertificates
			}
		} else if subversion == 1 {
			out.connectionWindowSize = common.DEFAULT_INITIAL_WINDOW_SIZE
		}

	} else { // clients
		out.nextPingID = 1
		out.oddity = 1
		out.initialWindowSize = common.DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
		out.requestStreamLimit = common.NewStreamLimit(common.NO_STREAM_LIMIT)
		out.pushStreamLimit = common.NewStreamLimit(common.DEFAULT_STREAM_LIMIT)
		out.pushRequests = make(map[common.StreamID]*http.Request)
		out.init = func() {
			// Initialise the connection by sending the connection settings.
			settings := new(frames.SETTINGS)
			settings.Settings = defaultClientSettings(common.DEFAULT_STREAM_LIMIT)
			out.output[0] <- settings
		}
		out.flowControl = streams.DefaultFlowControl(common.DEFAULT_INITIAL_CLIENT_WINDOW_SIZE)

		if subversion == 1 {
			out.connectionWindowSize = common.DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
		}
	}

	if subversion == 1 {
		out.initialWindowSizeThere = out.flowControl.InitialWindowSize()
		out.connectionWindowSizeThere = int64(out.initialWindowSizeThere)
	}
	return out
}

// Request is used to make a client request.
func (c *Conn) Request(request *http.Request, receiver common.Receiver, priority common.Priority) (common.Stream, error) {
	c.goawayLock.Lock()
	goaway := c.goawayReceived || c.goawaySent
	c.goawayLock.Unlock()
	if goaway {
		return nil, common.ErrGoaway
	}

	if c.server != nil {
		return nil, errors.New("Error: Only clients can send requests.")
	}

	// Check stream limit would allow the new stream.
	if !c.requestStreamLimit.Add() {
		return nil, errors.New("Error: Max concurrent streams limit exceeded.")
	}

	if !priority.Valid(3) {
		return nil, errors.New("Error: Priority must be in the range 0 - 7.")
	}

	url := request.URL
	if url == nil || url.Scheme == "" || url.Host == "" {
		return nil, errors.New("Error: Incomplete path provided to resource.")
	}

	// Prepare the SYN_STREAM.
	path := url.Path
	if url.RawQuery != "" {
		path += "?" + url.RawQuery
	}
	if url.Fragment != "" {
		path += "#" + url.Fragment
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	syn := new(frames.SYN_STREAM)
	syn.Priority = priority
	syn.Header = request.Header
	syn.Header.Set(":method", request.Method)
	syn.Header.Set(":path", path)
	syn.Header.Set(":version", "HTTP/1.1")
	syn.Header.Set(":host", url.Host)
	syn.Header.Set(":scheme", url.Scheme)

	// Prepare the request body, if any.
	body := make([]*frames.DATA, 0, 1)
	if request.Body != nil {
		buf := make([]byte, 32*1024)
		n, err := request.Body.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		total := n
		for n > 0 {
			data := new(frames.DATA)
			data.Data = make([]byte, n)
			copy(data.Data, buf[:n])
			body = append(body, data)
			n, err = request.Body.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			total += n
		}

		// Half-close the stream.
		if len(body) == 0 {
			syn.Flags = common.FLAG_FIN
		} else {
			syn.Header.Set("Content-Length", fmt.Sprint(total))
			body[len(body)-1].Flags = common.FLAG_FIN
		}
		request.Body.Close()
	} else {
		syn.Flags = common.FLAG_FIN
	}

	// Send.
	c.streamCreation.Lock()
	defer c.streamCreation.Unlock()

	c.lastRequestStreamIDLock.Lock()
	if c.lastRequestStreamID == 0 {
		c.lastRequestStreamID = 1
	} else {
		c.lastRequestStreamID += 2
	}
	syn.StreamID = c.lastRequestStreamID
	c.lastRequestStreamIDLock.Unlock()
	if syn.StreamID > common.MAX_STREAM_ID {
		return nil, errors.New("Error: All client streams exhausted.")
	}
	c.output[0] <- syn
	for _, frame := range body {
		frame.StreamID = syn.StreamID
		c.output[0] <- frame
	}

	// Create the request stream.
	out := streams.NewRequestStream(c, syn.StreamID, c.output[0], c.stop)
	out.Request = request
	out.Receiver = receiver
	out.AddFlowControl(c.flowControl)
	c.streamsLock.Lock()
	c.streams[syn.StreamID] = out // Store in the connection map.
	c.streamsLock.Unlock()

	return out, nil
}

func (c *Conn) RequestResponse(request *http.Request, receiver common.Receiver, priority common.Priority) (*http.Response, error) {
	res := new(common.Response)
	res.Request = request
	res.Data = new(bytes.Buffer)
	res.Receiver = receiver

	// Send the request.
	stream, err := c.Request(request, res, priority)
	if err != nil {
		return nil, err
	}

	// Let the request run its course.
	stream.Run()

	return res.Response(), nil
}

func (c *Conn) Run() error {
	go c.send()        // Start the send loop.
	if c.init != nil { // Must be after sending is enabled.
		c.init() // Prepare any initialisation frames.
	}
	go c.readFrames() // Start the main loop.
	<-c.stop          // Run until the connection ends.
	return nil
}

// closed indicates whether the connection has
// been closed.
func (c *Conn) closed() bool {
	select {
	case <-c.stop:
		return true
	default:
		return false
	}
}

// newStream is used to create a new serverStream from a SYN_STREAM frame.
func (c *Conn) newStream(frame *frames.SYN_STREAM) *streams.ResponseStream {
	header := frame.Header
	rawUrl := header.Get(":scheme") + "://" + header.Get(":host") + header.Get(":path")

	url, err := url.Parse(rawUrl)
	if c.check(err != nil, "Received SYN_STREAM with invalid request URL (%v)", err) {
		return nil
	}

	vers := header.Get(":version")
	major, minor, ok := http.ParseHTTPVersion(vers)
	if c.check(!ok, "Invalid HTTP version: "+vers) {
		return nil
	}

	method := header.Get(":method")

	// Build this into a request to present to the Handler.
	request := &http.Request{
		Method:     method,
		URL:        url,
		Proto:      vers,
		ProtoMajor: major,
		ProtoMinor: minor,
		RemoteAddr: c.remoteAddr,
		Header:     header,
		Host:       url.Host,
		RequestURI: url.RequestURI(),
		TLS:        c.tlsState,
	}

	output := c.output[frame.Priority]
	c.streamCreation.Lock()
	out := streams.NewResponseStream(c, frame, output, c.server.Handler, request, c.stop)
	c.streamCreation.Unlock()
	c.flowControlLock.Lock()
	f := c.flowControl
	c.flowControlLock.Unlock()
	out.AddFlowControl(f)

	return out
}
