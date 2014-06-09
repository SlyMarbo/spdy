// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy2

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/SlyMarbo/spdy/common"
	"github.com/SlyMarbo/spdy/spdy2/frames"
	"github.com/SlyMarbo/spdy/spdy2/streams"
	"github.com/SlyMarbo/spin"
)

// Conn is a spdy.Conn implementing SPDY/2. This is used in both
// servers and clients, and is created with either NewServerConn,
// or NewClientConn.
type Conn struct {
	PushReceiver common.Receiver // Receiver to call for server Pushes.

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
	goawayLock              spin.Lock                             // protects goawaySent and goawayReceived.
	numBenignErrors         int                                   // number of non-serious errors encountered.
	requestStreamLimit      *common.StreamLimit                   // Limit on streams started by the client.
	pushStreamLimit         *common.StreamLimit                   // Limit on streams started by the server.
	pushRequests            map[common.StreamID]*http.Request     // map of requests sent in server pushes.
	stop                    chan bool                             // this channel is closed when the connection closes.
	sending                 chan struct{}                         // this channel is used to ensure pending frames are sent.
	sendingLock             spin.Lock                             // protects changes to sending's value.
	init                    func()                                // this function is called before the connection begins.
	readTimeout             time.Duration                         // optional timeout for network reads.
	writeTimeout            time.Duration                         // optional timeout for network writes.
	timeoutLock             spin.Lock                             // protects changes to readTimeout and writeTimeout.
	pushedResources         map[common.Stream]map[string]struct{} // used to prevent duplicate headers being pushed.
	shutdownOnce            sync.Once                             // used to ensure clean shutdown.
}

// NewConn produces an initialised spdy3 connection.
func NewConn(conn net.Conn, server *http.Server) *Conn {
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
	out.compressor = common.NewCompressor(2)
	out.decompressor = common.NewDecompressor(2)
	out.receivedSettings = make(common.Settings)
	out.lastPushStreamID = 0
	out.lastRequestStreamID = 0
	out.stop = make(chan bool)

	// Server/client specific.
	if server != nil { // servers
		out.nextPingID = 2
		out.oddity = 0
		out.initialWindowSize = common.DEFAULT_INITIAL_WINDOW_SIZE
		out.requestStreamLimit = common.NewStreamLimit(common.DEFAULT_STREAM_LIMIT)
		out.pushStreamLimit = common.NewStreamLimit(common.NO_STREAM_LIMIT)
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
		out.pushedResources = make(map[common.Stream]map[string]struct{})

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
	}
	return out
}

func (c *Conn) Run() error {
	// Start the send loop.
	go c.send()

	// Prepare any initialisation frames.
	if c.init != nil {
		c.init()
	}

	// Start the main loop.
	go c.readFrames()

	// Run until the connection ends.
	<-c.stop

	return nil
}

func (c *Conn) SetFlowControl(common.FlowControl) error {
	return common.ErrNoFlowControl
}

// closed indicates whether the connection has
// been closed.
func (c *Conn) closed() bool {
	select {
	case _ = <-c.stop:
		return true
	default:
		return false
	}
}

// newStream is used to create a new serverStream from a SYN_STREAM frame.
func (c *Conn) newStream(frame *frames.SYN_STREAM, priority common.Priority) *streams.ResponseStream {
	header := frame.Header
	rawUrl := header.Get("scheme") + "://" + header.Get("host") + header.Get("url")

	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Println("Error: Received SYN_STREAM with invalid request URL: ", err)
		return nil
	}

	vers := header.Get("version")
	major, minor, ok := http.ParseHTTPVersion(vers)
	if !ok {
		log.Println("Error: Invalid HTTP version: " + vers)
		return nil
	}

	method := header.Get("method")

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

	c.streamCreation.Lock()
	out := streams.NewResponseStream(c, frame, c.output[priority], c.server.Handler, request, c.stop)
	c.streamCreation.Unlock()

	return out
}

// readFrames is the main processing loop, where frames
// are read from the connection and processed individually.
// Returning from readFrames begins the cleanup and exit
// process for this connection.
func (c *Conn) readFrames() {
	// Ensure no panics happen.
	defer func() {
		if v := recover(); v != nil {
			if !c.closed() {
				log.Println("Encountered receive error:", v)
			}
		}
	}()

	for {

		// This is the mechanism for handling too many benign errors.
		// By default MaxBenignErrors is 0, which ignores errors.
		if c.numBenignErrors > common.MaxBenignErrors && common.MaxBenignErrors > 0 {
			log.Println("Warning: Too many invalid stream IDs received. Ending connection.")
			c.protocolError(0)
			return
		}

		// ReadFrame takes care of the frame parsing for us.
		c.refreshReadTimeout()
		frame, err := frames.ReadFrame(c.buf)
		if err != nil {
			c.handleReadWriteError(err)
			return
		}

		// Print frame type.
		debug.Printf("Receiving %s:\n", frame.Name())

		// Decompress the frame's headers, if there are any.
		err = frame.Decompress(c.decompressor)
		if err != nil {
			log.Printf("Error in decompression: %v (%T).\n", err, frame)
			c.protocolError(0)
			return
		}

		// Print frame once the content's been decompressed.
		debug.Println(frame)

		// This is the main frame handling.
		if c.processFrame(frame) {
			return
		}
	}
}

// send is run in a separate goroutine. It's used
// to ensure clear interleaving of frames and to
// provide assurances of priority and structure.
func (c *Conn) send() {
	// Catch any panics.
	defer func() {
		if v := recover(); v != nil {
			if !c.closed() {
				log.Println("Encountered send error:", v)
			}
		}
	}()

	// Enter the processing loop.
	i := 1
	for {

		// Once per 5 frames, pick randomly.
		var frame common.Frame
		if i == 0 { // Ignore priority.
			frame = c.selectFrameToSend(false)
		} else { // Normal selection.
			frame = c.selectFrameToSend(true)
		}

		i++
		if i >= 5 {
			i = 0
		}

		if frame == nil {
			c.Close()
			return
		}

		// Compress any name/value header blocks.
		err := frame.Compress(c.compressor)
		if err != nil {
			log.Printf("Error in compression: %v (%T).\n", err, frame)
			return
		}

		debug.Printf("Sending %s:\n", frame.Name())
		debug.Println(frame)

		// Leave the specifics of writing to the
		// connection up to the frame.
		c.refreshWriteTimeout()
		_, err = frame.WriteTo(c.conn)
		if err != nil {
			c.handleReadWriteError(err)
			return
		}
	}
}

// selectFrameToSend follows the specification's guidance
// on frame priority, sending frames with higher priority
// (a smaller number) first. If the given boolean is false,
// this priority is temporarily ignored, which can be used
// when high load is ignoring low-priority frames.
func (c *Conn) selectFrameToSend(prioritise bool) (frame common.Frame) {
	if c.closed() {
		return nil
	}

	// Try in priority order first.
	if prioritise {
		for i := 0; i < 8; i++ {
			select {
			case frame = <-c.output[i]:
				return frame
			default:
			}
		}

		// No frames are immediately pending, so if the
		// connection is being closed, cease sending
		// safely.
		c.sendingLock.Lock()
		if c.sending != nil {
			close(c.sending)
			c.sendingLock.Unlock()
			runtime.Goexit()
		}
		c.sendingLock.Unlock()
	}

	// Wait for any frame.
	select {
	case frame = <-c.output[0]:
		return frame
	case frame = <-c.output[1]:
		return frame
	case frame = <-c.output[2]:
		return frame
	case frame = <-c.output[2]:
		return frame
	case frame = <-c.output[4]:
		return frame
	case frame = <-c.output[5]:
		return frame
	case frame = <-c.output[6]:
		return frame
	case frame = <-c.output[7]:
		return frame
	case _ = <-c.stop:
		return nil
	}
}
