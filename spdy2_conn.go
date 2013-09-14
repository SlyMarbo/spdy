package spdy

import (
	"bufio"
	"crypto/tls"
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

// connV2 is a spdy.Conn implementing SPDY/2. This is used in both
// servers and clients, and is created with either NewServerConn,
// or NewClientConn.
type connV2 struct {
	sync.Mutex
	remoteAddr          string
	server              *http.Server
	conn                net.Conn
	buf                 *bufio.Reader
	tlsState            *tls.ConnectionState
	streams             map[StreamID]Stream        // map of active streams.
	output              [8]chan Frame              // one output channel per priority level.
	pings               map[uint32]chan<- Ping     // response channel for pings.
	nextPingID          uint32                     // next outbound ping ID.
	compressor          Compressor                 // outbound compression state.
	decompressor        Decompressor               // inbound decompression state.
	receivedSettings    Settings                   // settings sent by client.
	lastPushStreamID    StreamID                   // last push stream ID. (even)
	lastRequestStreamID StreamID                   // last request stream ID. (odd)
	oddity              StreamID                   // whether locally-sent streams are odd or even.
	initialWindowSize   uint32                     // initial transport window.
	goaway              bool                       // goaway has been sent/received.
	numBenignErrors     int                        // number of non-serious errors encountered.
	requestStreamLimit  *streamLimit               // Limit on streams started by the client.
	pushStreamLimit     *streamLimit               // Limit on streams started by the server.
	pushRequests        map[StreamID]*http.Request // map of requests sent in server pushes.
	pushReceiver        Receiver                   // Receiver to call for server Pushes.
	stop                chan struct{}              // this channel is closed when the connection closes.
	sending             chan struct{}              // this channel is used to ensure pending frames are sent.
	init                func()                     // this function is called before the connection begins.
	readTimeout         time.Duration
	writeTimeout        time.Duration
}

// Close ends the connection, cleaning up relevant resources.
// Close can be called multiple times safely.
func (conn *connV2) Close() (err error) {
	conn.Lock()
	defer conn.Unlock()

	if conn.closed() {
		return nil
	}

	// Inform the other endpoint that the connection is closing.
	goaway := new(goawayFrameV2)
	if conn.server != nil {
		goaway.LastGoodStreamID = conn.lastRequestStreamID
	} else {
		goaway.LastGoodStreamID = conn.lastPushStreamID
	}
	conn.output[0] <- goaway

	// Ensure any pending frames are sent.
	if conn.sending == nil {
		conn.sending = make(chan struct{})
		<-conn.sending
	}

	select {
	case _ = <-conn.stop:
	default:
		close(conn.stop)
	}

	err = conn.conn.Close()
	if err != nil {
		return err
	}
	conn.conn = nil

	for _, stream := range conn.streams {
		err = stream.Close()
		if err != nil {
			return err
		}
	}
	conn.streams = nil

	err = conn.compressor.Close()
	if err != nil {
		return err
	}
	conn.compressor = nil
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
func (conn *connV2) InitialWindowSize() (uint32, error) {
	return conn.initialWindowSize, nil
}

// Ping is used by spdy.PingServer and spdy.PingClient to send
// SPDY PINGs.
func (conn *connV2) Ping() (<-chan Ping, error) {
	conn.Lock()
	defer conn.Unlock()

	if conn.closed() {
		return nil, errors.New("Error: Conn has been closed.")
	}

	ping := new(pingFrameV2)
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
func (conn *connV2) Push(resource string, origin Stream) (http.ResponseWriter, error) {
	if conn.goaway {
		return nil, errors.New("Error: GOAWAY received, so push could not be sent.")
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
	push := new(synStreamFrameV2)
	push.Flags = FLAG_UNIDIRECTIONAL
	push.AssocStreamID = origin.StreamID()
	push.Priority = 3
	push.Header = make(http.Header)
	push.Header.Set("scheme", url.Scheme)
	push.Header.Set("host", url.Host)
	push.Header.Set("url", url.Path)
	push.Header.Set("version", "HTTP/1.1")
	push.Header.Set(":status", "200 OK")

	// Send.
	conn.Lock()
	conn.lastPushStreamID += 2
	if conn.lastPushStreamID > MAX_STREAM_ID {
		conn.Unlock()
		return nil, errors.New("Error: All server streams exhausted.")
	}
	newID := conn.lastPushStreamID
	push.StreamID = newID
	conn.output[0] <- push
	conn.Unlock()

	// Create the pushStream.
	out := new(pushStreamV2)
	out.conn = conn
	out.streamID = newID
	out.origin = origin
	out.state = new(StreamState)
	out.output = conn.output[3]
	out.header = make(http.Header)
	out.stop = conn.stop

	// Store in the connection map.
	conn.streams[newID] = out

	return out, nil
}

// Request is used to make a client request.
func (conn *connV2) Request(request *http.Request, receiver Receiver, priority Priority) (Stream, error) {
	if conn.goaway {
		return nil, ErrGoaway
	}

	if conn.server != nil {
		return nil, errors.New("Error: Only clients can send requests.")
	}

	// Check stream limit would allow the new stream.
	if !conn.requestStreamLimit.Add() {
		return nil, errors.New("Error: Max concurrent streams limit exceeded.")
	}

	if !priority.Valid(2) {
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
	syn := new(synStreamFrameV2)
	syn.Priority = priority
	syn.Header = request.Header
	syn.Header.Set("method", request.Method)
	syn.Header.Set("url", path)
	syn.Header.Set("version", "HTTP/1.1")
	syn.Header.Set("host", url.Host)
	syn.Header.Set("scheme", url.Scheme)

	// Prepare the request body, if any.
	body := make([]*dataFrameV2, 0, 1)
	if request.Body != nil {
		buf := make([]byte, 32*1024)
		n, err := request.Body.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		total := n
		for n > 0 {
			data := new(dataFrameV2)
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
	if conn.lastRequestStreamID == 0 {
		conn.lastRequestStreamID = 1
	} else {
		conn.lastRequestStreamID += 2
	}
	if conn.lastRequestStreamID > MAX_STREAM_ID {
		conn.Unlock()
		return nil, errors.New("Error: All client streams exhausted.")
	}
	syn.StreamID = conn.lastRequestStreamID
	conn.output[0] <- syn
	for _, frame := range body {
		frame.StreamID = syn.StreamID
		conn.output[0] <- frame
	}
	conn.Unlock()

	// // Create the request stream.
	out := new(clientStreamV2)
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

	// Store in the connection map.
	conn.streams[syn.StreamID] = out

	return out, nil
}

func (conn *connV2) Run() error {
	// Start the send loop.
	go conn.send()

	// Prepare any initialisation frames.
	if conn.init != nil {
		conn.init()
	}

	// Enter the main loop.
	conn.readFrames()

	// Cleanup before the connection closes.
	return conn.Close()
}

func (c *connV2) SetTimeout(d time.Duration) {
	c.Lock()
	c.readTimeout = d
	c.writeTimeout = d
	c.Unlock()
}

func (c *connV2) SetReadTimeout(d time.Duration) {
	c.Lock()
	c.readTimeout = d
	c.Unlock()
}

func (c *connV2) SetWriteTimeout(d time.Duration) {
	c.Lock()
	c.writeTimeout = d
	c.Unlock()
}

// closed indicates whether the connection has
// been closed.
func (conn *connV2) closed() bool {
	select {
	case _ = <-conn.stop:
		return true
	default:
		return false
	}
}

// handleClientData performs the processing of DATA frames sent by the client.
func (conn *connV2) handleClientData(frame *dataFrameV2) {
	conn.Lock()
	defer conn.Unlock()

	sid := frame.StreamID

	if conn.server == nil {
		log.Println("Error: Requests can only be received by the server.")
		conn.numBenignErrors++
		return
	}

	// Handle push data.
	if sid&1 == 0 {
		log.Printf("Error: Received DATA with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream ID is valid.
	if !sid.Valid() {
		log.Printf("Error: Received DATA with Stream ID %d, which exceeds the limit.\n", sid)
		conn.protocolError(sid)
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received DATA with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send data to stream.
	stream.ReceiveFrame(frame)
}

// handleHeaders performs the processing of HEADERS frames.
func (conn *connV2) handleHeaders(frame *headersFrameV2) {
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
		log.Printf("Error: Received HEADERS with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send headers to stream.
	stream.ReceiveFrame(frame)
}

// handlePush performs the processing of SYN_STREAM frames forming a server push.
func (conn *connV2) handlePush(frame *synStreamFrameV2) {
	conn.Lock()
	defer conn.Unlock()

	// Check stream creation is allowed.
	if conn.goaway || conn.closed() {
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
		conn.protocolError(sid)
		return
	}

	// Stream ID is fine.

	// Check stream limit would allow the new stream.
	if !conn.pushStreamLimit.Add() {
		rst := new(rstStreamFrameV2)
		rst.StreamID = sid
		rst.Status = RST_STREAM_REFUSED_STREAM
		conn.output[0] <- rst
		return
	}

	if !frame.Priority.Valid(2) {
		log.Printf("Error: Received SYN_STREAM with invalid priority %d.\n", frame.Priority)
		conn.protocolError(sid)
		return
	}

	// Parse the request.
	header := frame.Header
	rawUrl := header.Get("scheme") + "://" + header.Get("host") + header.Get("url")
	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Println("Error: Received SYN_STREAM with invalid request URL: ", err)
		return
	}

	vers := header.Get("version")
	major, minor, ok := http.ParseHTTPVersion(vers)
	if !ok {
		log.Println("Error: Invalid HTTP version: " + vers)
		return
	}

	method := header.Get("method")

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
		rst := new(rstStreamFrameV2)
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
func (conn *connV2) handleRequest(frame *synStreamFrameV2) {
	conn.Lock()
	defer conn.Unlock()

	// Check stream creation is allowed.
	if conn.goaway || conn.closed() {
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
		conn.protocolError(sid)
		return
	}

	// Stream ID is fine.

	// Check stream limit would allow the new stream.
	if !conn.requestStreamLimit.Add() {
		rst := new(rstStreamFrameV2)
		rst.StreamID = sid
		rst.Status = RST_STREAM_REFUSED_STREAM
		conn.output[0] <- rst
		return
	}

	// Check request priority.
	if !frame.Priority.Valid(2) {
		log.Printf("Error: Received SYN_STREAM with invalid priority %d.\n", frame.Priority)
		conn.protocolError(sid)
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
func (conn *connV2) handleRstStream(frame *rstStreamFrameV2) {
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
		if sid&1 == conn.oddity {
			log.Println("Error: Cannot cancel locally-sent streams.")
			conn.numBenignErrors++
			return
		}
		if stream, ok := conn.streams[sid]; ok {
			stream.Close()
		}

	case RST_STREAM_FLOW_CONTROL_ERROR:
		log.Printf("Error: Received FLOW_CONTROL_ERROR for stream ID %d.\n", sid)
		conn.numBenignErrors++
		return

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
		conn.protocolError(sid)
	}
}

// handleServerData performs the processing of DATA frames sent by the server.
func (conn *connV2) handleServerData(frame *dataFrameV2) {
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
		log.Printf("Error: Received DATA with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send data to stream.
	stream.ReceiveFrame(frame)
}

// handleSynReply performs the processing of SYN_REPLY frames.
func (conn *connV2) handleSynReply(frame *synReplyFrameV2) {
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
		conn.protocolError(sid)
		return
	}

	// Check stream is open.
	if stream, ok := conn.streams[sid]; !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received SYN_REPLY with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send headers to stream.
	conn.streams[sid].ReceiveFrame(frame)
}

// newStream is used to create a new serverStream from a SYN_STREAM frame.
func (conn *connV2) newStream(frame *synStreamFrameV2, output chan<- Frame) *serverStreamV2 {
	stream := new(serverStreamV2)
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

	return stream
}

// protocolError informs the other endpoint that a protocol error has
// occurred, stops all running streams, and ends the connection.
func (conn *connV2) protocolError(streamID StreamID) {
	reply := new(rstStreamFrameV2)
	reply.StreamID = streamID
	reply.Status = RST_STREAM_PROTOCOL_ERROR
	conn.output[0] <- reply

	conn.Close()
}

// readFrames is the main processing loop, where frames
// are read from the connection and processed individually.
// Returning from readFrames begins the cleanup and exit
// process for this connection.
func (conn *connV2) readFrames() {
	// Main loop.
Loop:
	for {

		// This is the mechanism for handling too many benign errors.
		// Default MaxBenignErrors is 10.
		if conn.numBenignErrors > MaxBenignErrors {
			log.Println("Error: Too many invalid stream IDs received. Ending connection.")
			conn.protocolError(0)
		}

		// ReadFrame takes care of the frame parsing for us.
		conn.refreshReadTimeout()
		frame, err := readFrameV2(conn.buf)
		if err != nil {
			if err == io.EOF {
				// Client has closed the TCP connection.
				debug.Println("Note: Endpoint has disconnected.")

				// Make sure conn.Close succeeds and sending stops.
				if conn.sending == nil {
					conn.sending = make(chan struct{})
				}

				conn.Close()
				return
			}

			log.Printf("Error: Encountered read error: %q\n", err.Error())
			conn.Close()
			return
		}

		// Print frame type.
		debug.Printf("Receiving %s:\n", frame.Name())

		// Decompress the frame's headers, if there are any.
		err = frame.Decompress(conn.decompressor)
		if err != nil {
			log.Printf("Error in decompression: %v (%T).\n", err, frame)
			conn.protocolError(0)
		}

		// Print frame once the content's been decompressed.
		debug.Println(frame)

		// This is the main frame handling section.
		switch frame := frame.(type) {

		case *synStreamFrameV2:
			if conn.server == nil {
				conn.handlePush(frame)
			} else {
				conn.handleRequest(frame)
			}

		case *synReplyFrameV2:
			conn.handleSynReply(frame)

		case *rstStreamFrameV2:
			if statusCodeIsFatal(frame.Status) {
				code := statusCodeText[frame.Status]
				log.Printf("Warning: Received %s on stream %d. Closing connection.\n", code, frame.StreamID)
				conn.Close()
				return
			}
			conn.handleRstStream(frame)

		case *settingsFrameV2:
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

		case *noopFrameV2:
			// Ignore.

		case *pingFrameV2:
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

		case *goawayFrameV2:
			lastProcessed := frame.LastGoodStreamID
			for streamID, stream := range conn.streams {
				if streamID&1 == conn.oddity && streamID > lastProcessed {
					// Stream is locally-sent and has not been processed.
					// TODO: Inform the server that the push has not been successful.
					stream.Close()
				}
			}
			conn.goaway = true

		case *headersFrameV2:
			conn.handleHeaders(frame)

		case *windowUpdateFrameV2:
			// Ignore.

		case *dataFrameV2:
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
func (conn *connV2) send() {
	// Enter the processing loop.
	for {
		frame := conn.selectFrameToSend()

		if frame == nil {
			conn.Close()
			return
		}

		// Compress any name/value header blocks.
		err := frame.Compress(conn.compressor)
		if err != nil {
			log.Println(err)
			continue
		}

		debug.Printf("Sending %s:\n", frame.Name())
		debug.Println(frame)

		// Leave the specifics of writing to the
		// connection up to the frame.
		conn.refreshWriteTimeout()
		_, err = frame.WriteTo(conn.conn)
		if err != nil {
			if err == io.EOF || err == ErrConnNil {
				// Server has closed the TCP connection.
				debug.Println("Note: Endpoint has disconnected.")
				conn.Close()
				return
			}

			// Unexpected error which prevented a write.
			log.Printf("Error: Encountered write error: %q\n", err.Error())
			conn.Close()
			return
		}
	}
}

// selectFrameToSend follows the specification's guidance
// on frame priority, sending frames with higher priority
// (a smaller number) first.
func (conn *connV2) selectFrameToSend() (frame Frame) {
	if conn.closed() {
		return nil
	}

	// Try in priority order first.
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

	// Wait for any frame.
	select {
	case frame = <-conn.output[0]:
		return frame
	case frame = <-conn.output[1]:
		return frame
	case frame = <-conn.output[2]:
		return frame
	case frame = <-conn.output[2]:
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
func (conn *connV2) refreshTimeouts() {
	if d := conn.readTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := conn.writeTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetWriteDeadline(time.Now().Add(d))
	}
}

// Add timeouts if requested by the server.
func (conn *connV2) refreshReadTimeout() {
	if d := conn.readTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
}

// Add timeouts if requested by the server.
func (conn *connV2) refreshWriteTimeout() {
	if d := conn.writeTimeout; d != 0 && conn.conn != nil {
		conn.conn.SetWriteDeadline(time.Now().Add(d))
	}
}
