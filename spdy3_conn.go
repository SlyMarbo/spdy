// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"
)

// connV3 is a spdy.Conn implementing SPDY/3. This is used in both
// servers and clients, and is created with either NewServerConn,
// or NewClientConn.
type connV3 struct {
	sync.Mutex
	remoteAddr          string
	server              *http.Server
	conn                net.Conn
	buf                 *bufio.Reader
	tlsState            *tls.ConnectionState
	streams             map[StreamID]Stream            // map of active streams.
	output              [8]chan Frame                  // one output channel per priority level.
	pings               map[uint32]chan<- Ping         // response channel for pings.
	nextPingID          uint32                         // next outbound ping ID.
	compressor          Compressor                     // outbound compression state.
	decompressor        Decompressor                   // inbound decompression state.
	receivedSettings    Settings                       // settings sent by client.
	lastPushStreamID    StreamID                       // last push stream ID. (even)
	lastRequestStreamID StreamID                       // last request stream ID. (odd)
	oddity              StreamID                       // whether locally-sent streams are odd or even.
	initialWindowSize   uint32                         // initial transport window.
	goawayReceived      bool                           // goaway has been received.
	goawaySent          bool                           // goaway has been sent.
	numBenignErrors     int                            // number of non-serious errors encountered.
	requestStreamLimit  *streamLimit                   // Limit on streams started by the client.
	pushStreamLimit     *streamLimit                   // Limit on streams started by the server.
	vectorIndex         uint16                         // current limit on the credential vector size.
	certificates        map[uint16][]*x509.Certificate // certificates received in CREDENTIAL frames and TLS handshake.
	pushRequests        map[StreamID]*http.Request     // map of requests sent in server pushes.
	pushReceiver        Receiver                       // Receiver to call for server Pushes.
	stop                chan struct{}                  // this channel is closed when the connection closes.
	sending             chan struct{}                  // this channel is used to ensure pending frames are sent.
	init                func()                         // this function is called before the connection begins.
	readTimeout         time.Duration
	writeTimeout        time.Duration
}

// Close ends the connection, cleaning up relevant resources.
// Close can be called multiple times safely.
func (conn *connV3) Close() (err error) {
	conn.Lock()
	defer conn.Unlock()

	if conn.closed() {
		return nil
	}

	// Inform the other endpoint that the connection is closing.
	if !conn.goawaySent && conn.sending == nil {
		goaway := new(goawayFrameV3)
		if conn.server != nil {
			goaway.LastGoodStreamID = conn.lastRequestStreamID
		} else {
			goaway.LastGoodStreamID = conn.lastPushStreamID
		}
		conn.output[0] <- goaway
		conn.goawaySent = true
	}

	// Ensure any pending frames are sent.
	if conn.sending == nil {
		conn.sending = make(chan struct{})
		<-conn.sending
	}

	select {
	case _, ok := <-conn.stop:
		if ok {
			close(conn.stop)
		}
	default:
		close(conn.stop)
	}

	if conn.conn != nil {
		conn.conn.Close()
		conn.conn = nil
	}

	for _, stream := range conn.streams {
		err = stream.Close()
		if err != nil {
			debug.Println(err)
		}
	}
	conn.streams = nil

	if conn.compressor != nil {
		conn.compressor.Close()
		conn.compressor = nil
	}
	conn.decompressor = nil

	for _, stream := range conn.output {
		select {
		case _, ok := <-stream:
			if ok {
				close(stream)
			}
		default:
			close(stream)
		}
	}

	return nil
}

// InitialWindowSize gives the most recently-received value for
// the INITIAL_WINDOW_SIZE setting.
func (conn *connV3) InitialWindowSize() (uint32, error) {
	return conn.initialWindowSize, nil
}

// Ping is used by spdy.PingServer and spdy.PingClient to send
// SPDY PINGs.
func (conn *connV3) Ping() (<-chan Ping, error) {
	conn.Lock()
	defer conn.Unlock()

	if conn.closed() {
		return nil, errors.New("Error: Conn has been closed.")
	}

	ping := new(pingFrameV3)
	pid := conn.nextPingID
	if pid+2 < pid {
		if pid&1 == 0 {
			conn.nextPingID = 2
		} else {
			conn.nextPingID = 1
		}
	} else {
		conn.nextPingID += 2
	}
	ping.PingID = pid
	conn.output[0] <- ping
	c := make(chan Ping, 1)
	conn.pings[pid] = c

	return c, nil
}

// Push is used to issue a server push to the client. Note that this cannot be performed
// by clients.
func (conn *connV3) Push(resource string, origin Stream) (PushStream, error) {
	if conn.goawayReceived || conn.goawaySent {
		return nil, ErrGoaway
	}

	if conn.server == nil {
		return nil, errors.New("Error: Only servers can send pushes.")
	}

	// Check stream limit would allow the new stream.
	if !conn.pushStreamLimit.Add() {
		return nil, errors.New("Error: Max concurrent streams limit exceeded.")
	}

	// Parse and check URL.
	url, err := url.Parse(resource)
	if err != nil {
		return nil, err
	}
	if url.Scheme == "" || url.Host == "" || url.Path == "" {
		return nil, errors.New("Error: Incomplete path provided to resource.")
	}

	// Prepare the SYN_STREAM.
	push := new(synStreamFrameV3)
	push.Flags = FLAG_UNIDIRECTIONAL
	push.AssocStreamID = origin.StreamID()
	push.Priority = 7
	push.Header = make(http.Header)
	push.Header.Set(":scheme", url.Scheme)
	push.Header.Set(":host", url.Host)
	push.Header.Set(":path", url.Path)
	push.Header.Set(":version", "HTTP/1.1")
	push.Header.Set(":status", "200 OK")

	// Send.
	conn.Lock()
	defer conn.Unlock()

	conn.lastPushStreamID += 2
	if conn.lastPushStreamID > MAX_STREAM_ID {
		return nil, errors.New("Error: All server streams exhausted.")
	}
	newID := conn.lastPushStreamID
	push.StreamID = newID
	conn.output[0] <- push

	// Create the pushStream.
	out := new(pushStreamV3)
	out.conn = conn
	out.streamID = newID
	out.origin = origin
	out.state = new(StreamState)
	out.output = conn.output[7]
	out.header = make(http.Header)
	out.stop = conn.stop
	out.AddFlowControl()

	// Store in the connection map.
	conn.streams[newID] = out

	return out, nil
}

// Request is used to make a client request.
func (conn *connV3) Request(request *http.Request, receiver Receiver, priority Priority) (Stream, error) {
	if conn.goawayReceived || conn.goawaySent {
		return nil, ErrGoaway
	}

	if conn.server != nil {
		return nil, errors.New("Error: Only clients can send requests.")
	}

	// Check stream limit would allow the new stream.
	if !conn.requestStreamLimit.Add() {
		return nil, errors.New("Error: Max concurrent streams limit exceeded.")
	}

	if !priority.Valid(3) {
		return nil, errors.New("Error: Priority must be in the range 0 - 7.")
	}

	url := request.URL
	if url == nil || url.Scheme == "" || url.Host == "" || url.Path == "" {
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
	syn := new(synStreamFrameV3)
	syn.Priority = priority
	syn.Header = request.Header
	syn.Header.Set(":method", request.Method)
	syn.Header.Set(":path", path)
	syn.Header.Set(":version", "HTTP/1.1")
	syn.Header.Set(":host", url.Host)
	syn.Header.Set(":scheme", url.Scheme)

	// Prepare the request body, if any.
	body := make([]*dataFrameV3, 0, 1)
	if request.Body != nil {
		buf := make([]byte, 32*1024)
		n, err := request.Body.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		total := n
		for n > 0 {
			data := new(dataFrameV3)
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
			syn.Flags = FLAG_FIN
		} else {
			syn.Header.Set("Content-Length", fmt.Sprint(total))
			body[len(body)-1].Flags = FLAG_FIN
		}
		request.Body.Close()
	} else {
		syn.Flags = FLAG_FIN
	}

	// Send.
	conn.Lock()
	defer conn.Unlock()

	if conn.lastRequestStreamID == 0 {
		conn.lastRequestStreamID = 1
	} else {
		conn.lastRequestStreamID += 2
	}
	if conn.lastRequestStreamID > MAX_STREAM_ID {
		return nil, errors.New("Error: All client streams exhausted.")
	}
	syn.StreamID = conn.lastRequestStreamID
	conn.output[0] <- syn
	for _, frame := range body {
		frame.StreamID = syn.StreamID
		conn.output[0] <- frame
	}

	// Create the request stream.
	out := new(clientStreamV3)
	out.conn = conn
	out.streamID = syn.StreamID
	out.state = new(StreamState)
	out.state.CloseHere()
	out.output = conn.output[0]
	out.request = request
	out.receiver = receiver
	out.header = make(http.Header)
	out.stop = conn.stop
	out.finished = make(chan struct{})
	out.AddFlowControl()

	// Store in the connection map.
	conn.streams[syn.StreamID] = out

	return out, nil
}

func (conn *connV3) Run() error {
	// Start the send loop.
	go conn.send()

	// Prepare any initialisation frames.
	if conn.init != nil {
		conn.init()
	}

	// Ensure no panics happen.
	defer func() {
		if v := recover(); v != nil {
			if !conn.closed() {
				log.Println("Encountered error in connection:", v)
			}
		}
	}()

	// Start the main loop.
	go conn.readFrames()

	// Run until the connection ends.
	<-conn.stop

	return nil
}

func (c *connV3) SetTimeout(d time.Duration) {
	c.Lock()
	c.readTimeout = d
	c.writeTimeout = d
	c.Unlock()
}

func (c *connV3) SetReadTimeout(d time.Duration) {
	c.Lock()
	c.readTimeout = d
	c.Unlock()
}

func (c *connV3) SetWriteTimeout(d time.Duration) {
	c.Lock()
	c.writeTimeout = d
	c.Unlock()
}

// closed indicates whether the connection has
// been closed.
func (conn *connV3) closed() bool {
	select {
	case _ = <-conn.stop:
		return true
	default:
		return false
	}
}

// handleClientData performs the processing of DATA frames sent by the client.
func (conn *connV3) handleClientData(frame *dataFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	if conn.server == nil {
		log.Println("Error: Requests can only be received by the server.")
		conn.numBenignErrors++
		return
	}

	// Handle request data.
	if sid&1 == 0 {
		log.Printf("Error: Received DATA with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream ID is valid.
	if !sid.Valid() {
		log.Printf("Error: Received DATA with Stream ID %d, which exceeds the limit.\n", sid)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedThere() {
		if ok {
			debug.Printf("Warning: Received DATA with Stream ID %d, which is closed.\n", sid)
		} else {
			debug.Printf("Error: Received DATA with Stream ID %d, which is unopened.\n", sid)
			conn.numBenignErrors++
		}
		return
	}

	// Stream ID is fine.

	// Send data to stream.
	stream.ReceiveFrame(frame)
}

// handleHeaders performs the processing of HEADERS frames.
func (conn *connV3) handleHeaders(frame *headersFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	// Handle push headers.
	if sid&1 == 0 && conn.server == nil {
		// Ignore refused push headers.
		if req := conn.pushRequests[sid]; req != nil && conn.pushReceiver != nil {
			conn.pushReceiver.ReceiveHeader(req, frame.Header)
		}
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedThere() {
		if ok {
			debug.Printf("Warning: Received HEADERS with Stream ID %d, which is closed.\n", sid)
		} else {
			debug.Printf("Error: Received HEADERS with Stream ID %d, which is unopened.\n", sid)
			conn.numBenignErrors++
		}
		return
	}

	// Stream ID is fine.

	// Send headers to stream.
	stream.ReceiveFrame(frame)
}

// handlePush performs the processing of SYN_STREAM frames forming a server push.
func (conn *connV3) handlePush(frame *synStreamFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	// Check stream creation is allowed.
	if conn.goawayReceived || conn.goawaySent || conn.closed() {
		return
	}

	sid := frame.StreamID

	// Push.
	if conn.server != nil {
		log.Println("Error: Only clients can receive server pushes.")
		return
	}

	// Check Stream ID is even.
	if sid&1 != 0 {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be even.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is the right number.
	lsid := conn.lastPushStreamID
	if sid <= lsid {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be greater than %d.\n", sid, lsid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is not out of bounds.
	if !sid.Valid() {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which exceeds the limit.\n", sid)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Stream ID is fine.

	// Check stream limit would allow the new stream.
	if !conn.pushStreamLimit.Add() {
		rst := new(rstStreamFrameV3)
		rst.StreamID = sid
		rst.Status = RST_STREAM_REFUSED_STREAM
		conn.output[0] <- rst
		return
	}

	if !frame.Priority.Valid(3) {
		log.Printf("Error: Received SYN_STREAM with invalid priority %d.\n", frame.Priority)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Parse the request.
	header := frame.Header
	rawUrl := header.Get(":scheme") + "://" + header.Get(":host") + header.Get(":path")
	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Println("Error: Received SYN_STREAM with invalid request URL: ", err)
		return
	}

	vers := header.Get(":version")
	major, minor, ok := http.ParseHTTPVersion(vers)
	if !ok {
		log.Println("Error: Invalid HTTP version: " + vers)
		return
	}

	method := header.Get(":method")

	request := &http.Request{
		Method:     method,
		URL:        url,
		Proto:      vers,
		ProtoMajor: major,
		ProtoMinor: minor,
		RemoteAddr: conn.remoteAddr,
		Header:     header,
		Host:       url.Host,
		RequestURI: url.Path,
		TLS:        conn.tlsState,
	}

	// Check whether the receiver wants this resource.
	if conn.pushReceiver != nil && !conn.pushReceiver.ReceiveRequest(request) {
		rst := new(rstStreamFrameV3)
		rst.StreamID = sid
		rst.Status = RST_STREAM_REFUSED_STREAM
		conn.output[0] <- rst
		return
	}

	// Create and start new stream.
	if conn.pushReceiver != nil {
		conn.pushReceiver.ReceiveHeader(request, frame.Header)
		conn.pushRequests[sid] = request
		conn.lastPushStreamID = sid
	}
}

// handleRequest performs the processing of SYN_STREAM request frames.
func (conn *connV3) handleRequest(frame *synStreamFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	// Check stream creation is allowed.
	if conn.goawayReceived || conn.goawaySent || conn.closed() {
		return
	}

	sid := frame.StreamID

	if conn.server == nil {
		log.Println("Error: Only servers can receive requests.")
		return
	}

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is the right number.
	lsid := conn.lastRequestStreamID
	if sid <= lsid && lsid != 0 {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be greater than %d.\n", sid, lsid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is not out of bounds.
	if !sid.Valid() {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which exceeds the limit.\n", sid)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Stream ID is fine.

	// Check stream limit would allow the new stream.
	if !conn.requestStreamLimit.Add() {
		rst := new(rstStreamFrameV3)
		rst.StreamID = sid
		rst.Status = RST_STREAM_REFUSED_STREAM
		conn.output[0] <- rst
		return
	}

	// Check request priority.
	if !frame.Priority.Valid(3) {
		log.Printf("Error: Received SYN_STREAM with invalid priority %d.\n", frame.Priority)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Create and start new stream.
	nextStream := conn.newStream(frame, conn.output[frame.Priority])
	// Make sure an error didn't occur when making the stream.
	if nextStream == nil {
		return
	}

	// Determine which handler to use.
	nextStream.handler = conn.server.Handler
	if nextStream.handler == nil {
		nextStream.handler = http.DefaultServeMux
	}

	// Set and prepare.
	conn.streams[sid] = nextStream
	conn.lastRequestStreamID = sid

	// Start the stream.
	go nextStream.Run()
}

// handleRstStream performs the processing of RST_STREAM frames.
func (conn *connV3) handleRstStream(frame *rstStreamFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	// Determine the status code and react accordingly.
	switch frame.Status {
	case RST_STREAM_INVALID_STREAM:
		log.Printf("Error: Received INVALID_STREAM for stream ID %d.\n", sid)
		if stream, ok := conn.streams[sid]; ok {
			stream.Close()
		}
		conn.numBenignErrors++

	case RST_STREAM_REFUSED_STREAM:
		if stream, ok := conn.streams[sid]; ok {
			stream.Close()
		}

	case RST_STREAM_CANCEL:
		// Allow cancelling of pushes.
		stream, ok := conn.streams[sid]
		if !ok {
			return
		}
		_, ok = stream.(*pushStreamV3)
		if sid&1 == conn.oddity && !ok {
			log.Println("Error: Cannot cancel locally-sent streams.")
			conn.numBenignErrors++
			return
		}
		stream.Close()

	case RST_STREAM_FLOW_CONTROL_ERROR:
		conn.numBenignErrors++

	case RST_STREAM_STREAM_IN_USE:
		log.Printf("Error: Received STREAM_IN_USE for stream ID %d.\n", sid)
		conn.numBenignErrors++

	case RST_STREAM_STREAM_ALREADY_CLOSED:
		log.Printf("Error: Received STREAM_ALREADY_CLOSED for stream ID %d.\n", sid)
		if stream, ok := conn.streams[sid]; ok {
			stream.Close()
		}
		conn.numBenignErrors++

	case RST_STREAM_INVALID_CREDENTIALS:
		log.Printf("Error: Received INVALID_CREDENTIALS for stream ID %d.\n", sid)
		conn.numBenignErrors++

	default:
		log.Printf("Error: Received unknown RST_STREAM status code %d.\n", frame.Status)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
	}
}

// handleServerData performs the processing of DATA frames sent by the server.
func (conn *connV3) handleServerData(frame *dataFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	// Handle push data.
	if sid&1 == 0 {
		// Ignore refused push data.
		if req := conn.pushRequests[sid]; req != nil && conn.pushReceiver != nil {
			conn.pushReceiver.ReceiveData(req, frame.Data, frame.Flags.FIN())
		}
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedThere() {
		if ok {
			debug.Printf("Warning: Received DATA with Stream ID %d, which is closed.\n", sid)
		} else {
			debug.Printf("Error: Received DATA with Stream ID %d, which is unopened.\n", sid)
			conn.numBenignErrors++
		}
		return
	}

	// Stream ID is fine.

	// Send data to stream.
	stream.ReceiveFrame(frame)
}

// handleSynReply performs the processing of SYN_REPLY frames.
func (conn *connV3) handleSynReply(frame *synReplyFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	if conn.server != nil {
		log.Println("Error: Only clients can receive SYN_REPLY frames.")
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received SYN_REPLY with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	if !sid.Valid() {
		log.Printf("Error: Received SYN_REPLY with Stream ID %d, which exceeds the limit.\n", sid)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State() == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received SYN_REPLY with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send headers to stream.
	stream.ReceiveFrame(frame)
}

// handleWindowUpdate performs the processing of WINDOW_UPDATE frames.
func (conn *connV3) handleWindowUpdate(frame *windowUpdateFrameV3) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	if !sid.Valid() {
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which exceeds the limit.\n", sid)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedHere() {
		debug.Printf("Warning: Received WINDOW_UPDATE with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Check delta window size is valid.
	delta := frame.DeltaWindowSize
	if delta > MAX_DELTA_WINDOW_SIZE || delta < 1 {
		log.Printf("Error: Received WINDOW_UPDATE with invalid delta window size %d.\n", delta)
		conn.Unlock()
		conn.protocolError(sid)
		conn.Lock()
		return
	}

	// Send update to stream.
	stream.ReceiveFrame(frame)
}

// newStream is used to create a new serverStream from a SYN_STREAM frame.
func (conn *connV3) newStream(frame *synStreamFrameV3, output chan<- Frame) *serverStreamV3 {
	stream := new(serverStreamV3)
	stream.conn = conn
	stream.streamID = frame.StreamID
	stream.state = new(StreamState)
	stream.output = output
	stream.header = make(http.Header)
	stream.unidirectional = frame.Flags.UNIDIRECTIONAL()
	stream.stop = conn.stop

	if frame.Flags.FIN() {
		stream.state.CloseThere()
	}

	header := frame.Header
	rawUrl := header.Get(":scheme") + "://" + header.Get(":host") + header.Get(":path")

	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Println("Error: Received SYN_STREAM with invalid request URL: ", err)
		return nil
	}

	vers := header.Get(":version")
	major, minor, ok := http.ParseHTTPVersion(vers)
	if !ok {
		log.Println("Error: Invalid HTTP version: " + vers)
		return nil
	}

	method := header.Get(":method")

	// Build this into a request to present to the Handler.
	stream.request = &http.Request{
		Method:     method,
		URL:        url,
		Proto:      vers,
		ProtoMajor: major,
		ProtoMinor: minor,
		RemoteAddr: conn.remoteAddr,
		Header:     header,
		Host:       url.Host,
		RequestURI: url.Path,
		TLS:        conn.tlsState,
	}

	stream.AddFlowControl()

	return stream
}

// protocolError informs the other endpoint that a protocol error has
// occurred, stops all running streams, and ends the connection.
func (conn *connV3) protocolError(streamID StreamID) {
	reply := new(rstStreamFrameV3)
	reply.StreamID = streamID
	reply.Status = RST_STREAM_PROTOCOL_ERROR
	conn.output[0] <- reply
	if !conn.goawaySent {
		goaway := new(goawayFrameV3)
		if conn.server != nil {
			goaway.LastGoodStreamID = conn.lastRequestStreamID
		} else {
			goaway.LastGoodStreamID = conn.lastPushStreamID
		}
		goaway.Status = GOAWAY_PROTOCOL_ERROR
		conn.output[0] <- goaway
		conn.goawaySent = true
	}

	conn.Close()
}

// readFrames is the main processing loop, where frames
// are read from the connection and processed individually.
// Returning from readFrames begins the cleanup and exit
// process for this connection.
func (conn *connV3) readFrames() {
	// Main loop.
Loop:
	for {

		// This is the mechanism for handling too many benign errors.
		// Default MaxBenignErrors is 10.
		if conn.numBenignErrors > MaxBenignErrors && MaxBenignErrors > 0 {
			log.Println("Warning: Too many invalid stream IDs received. Ending connection.")
			conn.protocolError(0)
			return
		}

		// ReadFrame takes care of the frame parsing for us.
		conn.refreshReadTimeout()
		frame, err := readFrameV3(conn.buf)
		if err != nil {
			if _, ok := err.(*net.OpError); ok || err == io.EOF {
				// Client has closed the TCP connection.
				debug.Println("Note: Endpoint has disconnected.")

				// Make sure conn.Close succeeds and sending stops.
				if conn.sending == nil {
					conn.sending = make(chan struct{})
				}

				// Run conn.Close in a separate goroutine to ensure
				// that conn.Run returns.
				go conn.Close()
				return
			}

			log.Printf("Error: Encountered read error: %q (%T)\n", err.Error(), err)
			// Make sure conn.Close succeeds and sending stops.
			if conn.sending == nil {
				conn.sending = make(chan struct{})
			}

			// Run conn.Close in a separate goroutine to ensure
			// that conn.Run returns.
			go conn.Close()
			return
		}

		// Print frame type.
		debug.Printf("Receiving %s:\n", frame.Name())

		// Decompress the frame's headers, if there are any.
		err = frame.Decompress(conn.decompressor)
		if err != nil {
			log.Println("Error in decompression: ", err)
			conn.protocolError(0)
			return
		}

		// Print frame once the content's been decompressed.
		debug.Println(frame)

		// This is the main frame handling section.
		switch frame := frame.(type) {

		case *synStreamFrameV3:
			if conn.server == nil {
				conn.handlePush(frame)
			} else {
				conn.handleRequest(frame)
			}

		case *synReplyFrameV3:
			conn.handleSynReply(frame)

		case *rstStreamFrameV3:
			if statusCodeIsFatal(frame.Status) {
				code := statusCodeText[frame.Status]
				log.Printf("Warning: Received %s on stream %d. Closing connection.\n", code, frame.StreamID)
				conn.Close()
				return
			}
			conn.handleRstStream(frame)

		case *settingsFrameV3:
			for _, setting := range frame.Settings {
				conn.receivedSettings[setting.ID] = setting
				switch setting.ID {
				case SETTINGS_INITIAL_WINDOW_SIZE:
					debug.Printf("Initial window size is %d.\n", setting.Value)
					conn.initialWindowSize = setting.Value

				case SETTINGS_MAX_CONCURRENT_STREAMS:
					if conn.server == nil {
						conn.requestStreamLimit.SetLimit(setting.Value)
					} else {
						conn.pushStreamLimit.SetLimit(setting.Value)
					}
				}
			}

		case *pingFrameV3:
			// Check whether Ping ID is a response.
			if frame.PingID&1 == conn.nextPingID&1 {
				if conn.pings[frame.PingID] == nil {
					log.Printf("Warning: Ignored PING with Ping ID %d, which hasn't been requested.\n",
						frame.PingID)
					conn.numBenignErrors++
					continue Loop
				}
				conn.pings[frame.PingID] <- Ping{}
				close(conn.pings[frame.PingID])
				delete(conn.pings, frame.PingID)
			} else {
				debug.Println("Received PING. Replying...")
				conn.output[0] <- frame
			}

		case *goawayFrameV3:
			lastProcessed := frame.LastGoodStreamID
			for streamID, stream := range conn.streams {
				if streamID&1 == conn.oddity && streamID > lastProcessed {
					// Stream is locally-sent and has not been processed.
					// TODO: Inform the server that the push has not been successful.
					stream.Close()
				}
			}
			conn.goawayReceived = true

		case *headersFrameV3:
			conn.handleHeaders(frame)

		case *windowUpdateFrameV3:
			conn.handleWindowUpdate(frame)

		case *credentialFrameV3:
			if conn.server == nil {
				log.Println("Ignored unexpected CREDENTIAL.")
				continue Loop
			}
			if frame.Slot >= conn.vectorIndex {
				setting := new(settingsFrameV3)
				setting.Settings = Settings{
					SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE: &Setting{
						ID:    SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE,
						Value: uint32(frame.Slot + 4),
					},
				}
				conn.output[0] <- setting
				conn.vectorIndex += 4
			}
			conn.certificates[frame.Slot] = frame.Certificates

		case *dataFrameV3:
			if conn.server == nil {
				conn.handleServerData(frame)
			} else {
				conn.handleClientData(frame)
			}

		default:
			log.Println(fmt.Sprintf("Ignored unexpected frame type %T", frame))
		}
	}
}

// send is run in a separate goroutine. It's used
// to ensure clear interleaving of frames and to
// provide assurances of priority and structure.
func (conn *connV3) send() {
	// Catch any panics.
	defer func() {
		if v := recover(); v != nil {
			if !conn.closed() {
				log.Println("Encountered send error:", v)
			}
		}
	}()

	// Enter the processing loop.
	i := 1
	for {

		// Once per 5 frames, pick randomly.
		var frame Frame
		if i == 0 { // Ignore priority.
			frame = conn.selectFrameToSend(false)
		} else { // Normal selection.
			frame = conn.selectFrameToSend(true)
		}

		i++
		if i >= 5 {
			i = 0
		}

		if frame == nil {
			conn.Close()
			return
		}

		// Compress any name/value header blocks.
		err := frame.Compress(conn.compressor)
		if err != nil {
			log.Printf("Error in compression: %v (%T).\n", err, frame)
			return
		}

		debug.Printf("Sending %s:\n", frame.Name())
		debug.Println(frame)

		// Leave the specifics of writing to the
		// connection up to the frame.
		conn.refreshWriteTimeout()
		_, err = frame.WriteTo(conn.conn)
		if err != nil {
			if _, ok := err.(*net.OpError); ok || err == io.EOF || err == ErrConnNil {
				// Server has closed the TCP connection.
				debug.Println("Note: Endpoint has disconnected.")
				// Make sure conn.Close succeeds and sending stops.
				if conn.sending == nil {
					conn.sending = make(chan struct{})
				}
				conn.Close()
				return
			}

			// Unexpected error which prevented a write.
			log.Printf("Error: Encountered write error: %q\n", err.Error())
			// Make sure conn.Close succeeds and sending stops.
			if conn.sending == nil {
				conn.sending = make(chan struct{})
			}
			conn.Close()
			return
		}
	}
}

// selectFrameToSend follows the specification's guidance
// on frame priority, sending frames with higher priority
// (a smaller number) first. If the given boolean is false,
// this priority is temporarily ignored, which can be used
// when high load is ignoring low-priority frames.
func (conn *connV3) selectFrameToSend(prioritise bool) (frame Frame) {
	if conn.closed() {
		return nil
	}

	// Try in priority order first.
	if prioritise {
		for i := 0; i < 8; i++ {
			select {
			case frame = <-conn.output[i]:
				return frame
			default:
			}
		}

		// No frames are immediately pending, so if the
		// connection is being closed, cease sending
		// safely.
		if conn.sending != nil {
			close(conn.sending)
			runtime.Goexit()
		}
	}

	// Wait for any frame.
	select {
	case frame = <-conn.output[0]:
		return frame
	case frame = <-conn.output[1]:
		return frame
	case frame = <-conn.output[2]:
		return frame
	case frame = <-conn.output[3]:
		return frame
	case frame = <-conn.output[4]:
		return frame
	case frame = <-conn.output[5]:
		return frame
	case frame = <-conn.output[6]:
		return frame
	case frame = <-conn.output[7]:
		return frame
	case _ = <-conn.stop:
		return nil
	}
}

// Add timeouts if requested by the server.
func (conn *connV3) refreshTimeouts() {
	if d := conn.readTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := conn.writeTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetWriteDeadline(time.Now().Add(d))
	}
}

// Add timeouts if requested by the server.
func (conn *connV3) refreshReadTimeout() {
	if d := conn.readTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
}

// Add timeouts if requested by the server.
func (conn *connV3) refreshWriteTimeout() {
	if d := conn.writeTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetWriteDeadline(time.Now().Add(d))
	}
}
