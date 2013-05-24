package spdy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"
)

// serverConnection represents a SPDY session at the server
// end. This performs the overall connection management and
// co-ordination between streams.
type serverConnection struct {
	sync.RWMutex
	remoteAddr         string
	server             *Server
	conn               *tls.Conn
	buf                *bufio.Reader // buffered reader for the connection.
	tlsState           *tls.ConnectionState
	streams            map[uint32]Stream
	dataPriority       [8]chan Frame          // one output channel per priority level.
	pings              map[uint32]chan<- bool // response channel for pings.
	pingID             uint32                 // next outbound ping ID.
	compressor         *Compressor            // outbound compression state.
	decompressor       *Decompressor          // inbound decompression state.
	receivedSettings   map[uint32]*Setting    // settings sent by client.
	nextServerStreamID uint32                 // next outbound stream ID. (even)
	nextClientStreamID uint32                 // next inbound stream ID. (odd)
	initialWindowSize  uint32                 // initial transport window.
	goaway             bool                   // goaway has been sent/received.
	version            uint16                 // SPDY version.
	numBenignErrors    int                    // number of non-serious errors encountered.
	done               *sync.WaitGroup        // WaitGroup for active streams.
	clientStreamLimit  *streamLimit           // Limit on streams openable by the client.
	serverStreamLimit  *streamLimit           // Limit on streams openable by the server.
	vectorIndex        uint16                 // current limit on the credential vector size.
	certificates       map[uint16][]*x509.Certificate
}

// readFrames is the main processing loop, where frames
// are read from the connection and processed individually.
// Returning from readFrames begins the cleanup and exit
// process for this connection.
func (conn *serverConnection) readFrames() {

	// Add timeouts if requested by the server.
	conn.refreshTimeouts()

	// Main loop.
	for {

		// This is the mechanism for handling too many benign errors.
		// Default MaxBenignErrors is 10.
		if conn.numBenignErrors > MaxBenignErrors {
			log.Println("Error: Too many invalid stream IDs received. Ending connection.")
			conn.protocolError(0)
		}

		// ReadFrame takes care of the frame parsing for us.
		frame, err := ReadFrame(conn.buf)
		conn.refreshTimeouts()
		if err != nil {
			if err == io.EOF {
				// Client has closed the TCP connection.
				debug.Println("Note: Client has disconnected.")
				return
			}

			log.Printf("Error: Server encountered read error: %q\n", err.Error())
			return
		}

		// Decompress the frame's headers, if there are any.
		err = frame.DecodeHeaders(conn.decompressor)
		if err != nil {
			log.Println("Error in decompression: ", err)
			conn.protocolError(frame.StreamID())
		}

		debug.Println("Received Frame:")
		debug.Println(frame)

		// Make sure the received frame uses an appropriate
		// SPDY version.
		if !conn.validFrameVersion(frame) {
			reply := new(RstStreamFrame)
			reply.version = DEFAULT_SPDY_VERSION
			reply.streamID = frame.StreamID()
			reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
			conn.WriteFrame(reply)
			continue
		}

	FrameHandling:
		// This is the main frame handling section.
		switch frame := frame.(type) {

		case *SynStreamFrame:
			conn.handleSynStream(frame)

		case *SynReplyFrame:
			conn.handleSynReply(frame)

		case *RstStreamFrame:
			if statusCodeIsFatal(int(frame.StatusCode)) {
				code := statusCodeText[int(frame.StatusCode)]
				log.Printf("Warning: Received %s on stream %d. Closing connection.\n", code, frame.StreamID())
				return
			}
			conn.handleRstStream(frame)

		case *SettingsFrame:
			for _, setting := range frame.Settings {
				conn.receivedSettings[setting.ID] = setting
				switch setting.ID {
				case SETTINGS_INITIAL_WINDOW_SIZE:
					if conn.version > 2 {
						debug.Printf("Initial window size is %d.\n", setting.Value)
						conn.initialWindowSize = setting.Value
					} else {
						msg := "Warning: Received INITIAL_WINDOW_SIZE setting on SPDY/%d, which has no flow control.\n"
						log.Printf(msg, conn.version)
					}

				case SETTINGS_MAX_CONCURRENT_STREAMS:
					conn.serverStreamLimit.SetLimit(setting.Value)
				}
			}

		case *NoopFrame:

		case *PingFrame:
			// Check whether Ping ID is server-sent.
			if frame.PingID&1 == 0 {
				if conn.pings[frame.PingID] == nil {
					log.Printf("Warning: Ignored PING with Ping ID %d, which hasn't been requested.\n",
						frame.PingID)
					conn.numBenignErrors++
					break FrameHandling
				}
				conn.pings[frame.PingID] <- true
				close(conn.pings[frame.PingID])
				delete(conn.pings, frame.PingID)
			} else {
				debug.Println("Received PING. Replying...")
				conn.WriteFrame(frame)
			}

		case *GoawayFrame:
			lastProcessed := frame.LastGoodStreamID
			for streamID, stream := range conn.streams {
				if streamID&1 == 0 && streamID > lastProcessed {
					// Stream is server-sent and has not been processed.
					stream.Cancel()
				}
			}
			conn.goaway = true

		case *HeadersFrame:
			conn.handleHeaders(frame)

		case *WindowUpdateFrame:
			conn.handleWindowUpdate(frame)

		case *CredentialFrame:
			if frame.Slot >= conn.vectorIndex {
				setting := new(SettingsFrame)
				setting.version = conn.version
				setting.Settings = []*Setting{
					&Setting{
						ID:    SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE,
						Value: uint32(frame.Slot + 4),
					},
				}
				conn.WriteFrame(setting)
				conn.vectorIndex += 4
			}
			conn.certificates[frame.Slot] = frame.Certificates

		case *DataFrame:
			conn.handleData(frame)

		default:
			log.Println(fmt.Sprintf("unexpected frame type %T", frame))
		}
	}
}

// send is run in a separate goroutine. It's used
// to ensure clear interleaving of frames and to
// provide assurances of priority and structure.
func (conn *serverConnection) send() {

	// Initialise the connection by sending the connection settings.
	settings := new(SettingsFrame)
	settings.version = conn.version
	settings.Settings = defaultSPDYServerSettings(conn.version, conn.clientStreamLimit.Limit())

	// Add any global settings set by the server.
	if conn.server.GlobalSettings != nil {
		settings.Settings = append(settings.Settings, conn.server.GlobalSettings...)
	}

	frame := Frame(settings)

	// Enter the normal processing loop.
	for {

		// Compress any name/value header blocks.
		err := frame.EncodeHeaders(conn.compressor)
		if err != nil {
			log.Println(err)
			continue
		}

		debug.Println("Sending Frame:")
		debug.Println(frame)

		// Leave the specifics of writing to the
		// connection up to the frame.
		err = frame.WriteTo(conn.conn)
		conn.refreshTimeouts()
		if err != nil {
			if err == io.EOF {
				// Server has closed the TCP connection.
				debug.Println("Note: Server has disconnected.")
				return
			}

			// Unexpected error which prevented a write.
			return
		}

		// Select the next frame to send.
		frame = conn.selectFrameToSend()
	}
}

// selectFrameToSend follows the specification's guidance
// on frame priority, sending frames with higher priority
// (a smaller number) first.
func (conn *serverConnection) selectFrameToSend() (frame Frame) {
	// Try in priority order first.
	for i := 0; i < 8; i++ {
		select {
		case frame = <-conn.dataPriority[i]:
			return frame
		default:
		}
	}

	// Wait for any frame.
	select {
	case frame = <-conn.dataPriority[0]:
		return frame
	case frame = <-conn.dataPriority[1]:
		return frame
	case frame = <-conn.dataPriority[2]:
		return frame
	case frame = <-conn.dataPriority[3]:
		return frame
	case frame = <-conn.dataPriority[4]:
		return frame
	case frame = <-conn.dataPriority[5]:
		return frame
	case frame = <-conn.dataPriority[6]:
		return frame
	case frame = <-conn.dataPriority[7]:
		return frame
	}
}

// newStream is used to create a new serverStream from a SYN_STREAM frame.
func (conn *serverConnection) newStream(frame *SynStreamFrame, output chan<- Frame) *serverStream {
	stream := new(serverStream)
	stream.conn = conn
	stream.streamID = frame.streamID
	stream.state = new(StreamState)
	stream.output = output
	stream.headers = make(http.Header)
	stream.unidirectional = frame.Flags&FLAG_UNIDIRECTIONAL != 0
	stream.version = conn.version
	stream.done = make(chan struct{}, 1)

	if frame.Flags&FLAG_FIN != 0 {
		stream.state.CloseThere()
	}

	headers := frame.Headers
	var rawUrl string
	switch frame.version {
	case 3:
		rawUrl = headers.Get(":scheme") + "://" + headers.Get(":host") + headers.Get(":path")
	case 2:
		rawUrl = headers.Get("scheme") + "://" + headers.Get("host") + headers.Get("url")
	}
	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Println("Error: Received SYN_STREAM with invalid request URL: ", err)
		return nil
	}

	var vers string
	switch frame.version {
	case 3:
		vers = headers.Get(":version")
	case 2:
		vers = headers.Get("version")
	}
	major, minor, ok := http.ParseHTTPVersion(vers)
	if !ok {
		log.Println("Error: Invalid HTTP version: " + vers)
		return nil
	}

	var method string
	switch frame.version {
	case 3:
		method = headers.Get(":method")
	case 2:
		method = headers.Get("method")
	}

	// Build this into a request to present to the Handler.
	stream.request = &http.Request{
		Method:     method,
		URL:        url,
		Proto:      vers,
		ProtoMajor: major,
		ProtoMinor: minor,
		RemoteAddr: conn.remoteAddr,
		Header:     headers,
		Host:       url.Host,
		RequestURI: url.Path,
		TLS:        conn.tlsState,
	}

	return stream
}

func (conn *serverConnection) InitialWindowSize() uint32 {
	return conn.initialWindowSize
}

// Ping is used to send a SPDY ping to the client.
// A channel is returned immediately, and 'true'
// sent when the ping reply is received. If there
// is a fault in the connection, the channel is
// closed.
func (conn *serverConnection) Ping() <-chan bool {
	ping := new(PingFrame)
	ping.version = conn.version

	conn.Lock()

	pid := conn.pingID
	conn.pingID += 2
	ping.PingID = pid
	conn.dataPriority[0] <- ping

	conn.Unlock()

	c := make(chan bool, 1)
	conn.pings[pid] = c

	return c
}

// Push is used to create a server push. A SYN_STREAM is created and sent,
// opening the stream. Push then creates and initialises a PushWriter and
// returns it.
//
// According to the specification, the establishment of the push is very
// high-priority, to mitigate the race condition of the client receiving
// enough information to request the resource being pushed before the
// push SYN_STREAM arrives. However, the actual push data is fairly low
// priority, since it's probably being sent at the same time as the data
// for a resource which may result in further requests. As a result of
// these two factors, the SYN_STREAM is sent at priority 0 (max), but its
// data is sent at priority 7 (min).
func (conn *serverConnection) Push(resource string, origin Stream) (PushWriter, error) {
	if conn.goaway {
		return nil, errors.New("Error: GOAWAY received, so push could not be sent.")
	}

	// Check stream limit would allow the new stream.
	if !conn.clientStreamLimit.Add() {
		return nil, errors.New("Error: Max concurrent streams limit exceeded.")
	}

	// Prepare the SYN_STREAM.
	push := new(SynStreamFrame)
	push.version = conn.version
	push.Flags = FLAG_UNIDIRECTIONAL
	push.AssocStreamID = origin.StreamID()
	push.Priority = 0
	url, err := url.Parse(resource)
	if err != nil {
		return nil, err
	}
	if url.Scheme == "" || url.Host == "" || url.Path == "" {
		return nil, errors.New("Error: Incomplete path provided to resource.")
	}

	headers := make(http.Header)
	switch conn.version {
	case 3:
		headers.Set(":scheme", url.Scheme)
		headers.Set(":host", url.Host)
		headers.Set(":path", url.Path)
		headers.Set(":version", "HTTP/1.1")
		headers.Set(":status", "200 OK")
	case 2:
		headers.Set("scheme", url.Scheme)
		headers.Set("host", url.Host)
		headers.Set("url", url.Path)
		headers.Set("version", "HTTP/1.1")
		headers.Set("status", "200 OK")
	}
	push.Headers = headers

	// Send.
	conn.Lock()
	conn.nextServerStreamID += 2
	newID := conn.nextServerStreamID
	push.streamID = newID
	conn.WriteFrame(push)
	conn.Unlock()

	// Create the pushStream.
	out := new(pushStream)
	out.conn = conn
	out.streamID = newID
	out.origin = origin
	out.state = new(StreamState)
	out.output = conn.dataPriority[7]
	out.headers = make(http.Header)
	out.stop = false
	out.version = conn.version
	out.AddFlowControl()

	// Store in the connection map.
	conn.streams[newID] = out

	return out, nil
}

// Request is a method stub required to satisfy the Connection
// interface. It must not be used by servers.
func (conn *serverConnection) Request(req *http.Request, res Receiver, priority int) (Stream, error) {
	return nil, errors.New("Error: Servers cannot make requests.")
}

func (conn *serverConnection) Version() uint16 {
	return conn.version
}

// Internally-sent frames have high priority.
func (conn *serverConnection) WriteFrame(frame Frame) {
	conn.dataPriority[0] <- frame
}

// validFrameVersion checks that a frame has the same SPDY
// version number as the rest of the connection. This library
// does not support the mixing of different versions within a
// connection, even if the library supports all versions being
// used.
func (conn *serverConnection) validFrameVersion(frame Frame) bool {

	// DATA frames have no version, so they
	// are always valid.
	if _, ok := frame.(*DataFrame); ok {
		return true
	}

	notSupported := "Error: Received frame with SPDY version %d, which is not supported.\n"
	different := "Error: Received frame with SPDY version %d on connection with version %d.\n"

	// Check the version.
	v := frame.Version()
	if v != conn.version {
		if !SupportedVersion(v) {
			log.Printf(notSupported, v)
		} else {
			log.Printf(different, v, conn.version)
		}
		return false
	}
	return true
}

// handleSynStream performs the processing of SYN_STREAM frames.
func (conn *serverConnection) handleSynStream(frame *SynStreamFrame) {
	conn.Lock()
	defer conn.Unlock()

	// Check stream creation is allowed.
	if conn.goaway {
		return
	}

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is the right number.
	nsid := conn.nextClientStreamID
	if sid != nsid && sid != 1 && conn.nextClientStreamID != 0 {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be %d.\n", sid, nsid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is not out of bounds.
	if sid > MAX_STREAM_ID {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which exceeds the limit.\n", sid)
		conn.protocolError(sid)
	}

	// Stream ID is fine.

	// Check stream limit would allow the new stream.
	if !conn.clientStreamLimit.Add() {
		rst := new(RstStreamFrame)
		rst.version = conn.version
		rst.streamID = sid
		rst.StatusCode = RST_STREAM_REFUSED_STREAM
		conn.WriteFrame(rst)
		return
	}

	// Create and start new stream.
	nextStream := conn.newStream(frame, conn.dataPriority[frame.Priority])
	if nextStream == nil { // Make sure an error didn't occur when making the stream.
		return
	}

	// Determine which handler to use.
	nextStream.handler = conn.server.Handler
	if nextStream.handler == nil {
		nextStream.handler = DefaultServeMux
	}
	nextStream.httpHandler = conn.server.httpHandler
	if nextStream.httpHandler == nil {
		nextStream.httpHandler = http.DefaultServeMux
	}

	// Set and prepare.
	conn.streams[sid] = nextStream
	conn.nextClientStreamID = sid + 2

	// Start the stream.
	go nextStream.Run()
}

// handleSynReply performs the processing of SYN_REPLY frames.
func (conn *serverConnection) handleSynReply(frame *SynReplyFrame) {
	conn.RLock()
	defer conn.RUnlock()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received HEADERS with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received SYN_REPLY with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send headers to stream.
	stream.ReceiveFrame(frame)

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		stream.State().CloseThere()
	}
}

// handleRstStream performs the processing of RST_STREAM frames.
func (conn *serverConnection) handleRstStream(frame *RstStreamFrame) {
	conn.RLock()
	defer conn.RUnlock()

	sid := frame.streamID

	// Determine the status code and react accordingly.
	switch frame.StatusCode {
	case RST_STREAM_INVALID_STREAM:
		log.Printf("Error: Received INVALID_STREAM for stream %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_REFUSED_STREAM:
		conn.closeStream(sid)
		return

	case RST_STREAM_CANCEL:
		if sid&1 == 0 {
			log.Printf("Error: Received RST_STREAM with Stream %d, which should be odd.\n", sid)
			conn.numBenignErrors++
			return
		}
		conn.closeStream(sid)
		return

	case RST_STREAM_FLOW_CONTROL_ERROR:
		log.Printf("Error: Received FLOW_CONTROL_ERROR for stream %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_STREAM_IN_USE:
		log.Printf("Error: Received STREAM_IN_USE for stream %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_STREAM_ALREADY_CLOSED:
		log.Printf("Error: Received STREAM_ALREADY_CLOSED for stream %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_INVALID_CREDENTIALS:
		log.Printf("Error: Received INVALID_CREDENTIALS for stream %d.\n", sid)
		conn.numBenignErrors++
		return

	default:
		log.Printf("Error: Received unknown RST_STREAM status code %d.\n", frame.StatusCode)
		conn.protocolError(sid)
	}
}

// handleDataFrame performs the processing of DATA frames.
func (conn *serverConnection) handleData(frame *DataFrame) {
	conn.RLock()
	defer conn.RUnlock()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received DATA with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
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

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		stream.State().CloseThere()
		stream.Stop()
	}
}

// handleHeaders performs the processing of HEADERS frames.
func (conn *serverConnection) handleHeaders(frame *HeadersFrame) {
	conn.RLock()
	defer conn.RUnlock()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received HEADERS with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
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

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		stream.State().CloseThere()
		stream.Stop()
	}
}

// handleWindowUpdate performs the processing of WINDOW_UPDATE frames.
func (conn *serverConnection) handleWindowUpdate(frame *WindowUpdateFrame) {
	conn.RLock()
	defer conn.RUnlock()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream is open.
	stream, ok := conn.streams[sid]
	if !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Check delta window size is valid.
	delta := frame.DeltaWindowSize
	if delta > MAX_DELTA_WINDOW_SIZE || delta < 0 {
		log.Printf("Error: Received WINDOW_UPDATE with invalid delta window size %d.\n", delta)
		conn.protocolError(sid)
	}

	// Ignore empty deltas.
	if delta == 0 {
		return
	}

	// Send update to stream.
	stream.ReceiveFrame(frame)
}

// Add timeouts if requested by the server.
// TODO: this could be improved.
func (conn *serverConnection) refreshTimeouts() {
	if d := conn.server.ReadTimeout; d != 0 {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := conn.server.WriteTimeout; d != 0 {
		conn.conn.SetWriteDeadline(time.Now().Add(d))
	}
}

// closeStream closes the provided stream safely.
func (conn *serverConnection) closeStream(streamID uint32) {
	if streamID == 0 {
		log.Println("Error: Tried to close stream 0.")
		return
	}

	conn.streams[streamID].Stop()
	conn.streams[streamID].State().Close()
	delete(conn.streams, streamID)
}

// PROTOCOL_ERROR informs the client that a protocol error has
// occurred, stops all running streams, and ends the connection.
func (conn *serverConnection) protocolError(streamID uint32) {
	reply := new(RstStreamFrame)
	reply.version = conn.version
	reply.streamID = streamID
	reply.StatusCode = RST_STREAM_PROTOCOL_ERROR
	conn.WriteFrame(reply)

	// Leave time for the message to be sent and received.
	time.Sleep(100 * time.Millisecond)
	conn.cleanup()
	runtime.Goexit()
}

// cleanup is used to end any running streams and
// aid garbage collection before the connection
// is closed.
func (conn *serverConnection) cleanup() {
	for _, stream := range conn.streams {
		stream.Stop()
	}
	conn.streams = nil
}

// serve prepares and executes the frame reading
// loop of the connection. At this point, any
// global settings set by the server are sent to
// the new client.
func (conn *serverConnection) serve() {
	defer func() {
		if err := recover(); err != nil {
			const size = 4096
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("spdy: panic serving %v: %v\n%s", conn.remoteAddr, err, buf)
		}
	}()

	// Initialise max concurrent streams limit.
	if conn.server.maxConcurrentStreams != 0 {
		conn.clientStreamLimit.SetLimit(conn.server.maxConcurrentStreams)
	} else {
		conn.clientStreamLimit.SetLimit(DEFAULT_MAX_CONCURRENT_STREAMS)
	}

	// Create the header (de)compression states.
	conn.compressor = NewCompressor(conn.version)
	conn.decompressor = NewDecompressor(conn.version)

	// Start the send loop.
	go conn.send()

	// Enter the main loop.
	conn.readFrames()

	// Cleanup before the connection closes.
	conn.cleanup()
}

// newConn is used to create and initialise a server connection.
func newConn(tlsConn *tls.Conn) *serverConnection {
	conn := new(serverConnection)
	conn.remoteAddr = tlsConn.RemoteAddr().String()
	conn.conn = tlsConn
	conn.buf = bufio.NewReader(tlsConn)
	conn.tlsState = new(tls.ConnectionState)
	*conn.tlsState = tlsConn.ConnectionState()
	conn.initialWindowSize = DEFAULT_INITIAL_WINDOW_SIZE
	conn.streams = make(map[uint32]Stream)
	conn.receivedSettings = make(map[uint32]*Setting)
	conn.dataPriority = [8]chan Frame{}
	conn.dataPriority[0] = make(chan Frame)
	conn.dataPriority[1] = make(chan Frame)
	conn.dataPriority[2] = make(chan Frame)
	conn.dataPriority[3] = make(chan Frame)
	conn.dataPriority[4] = make(chan Frame)
	conn.dataPriority[5] = make(chan Frame)
	conn.dataPriority[6] = make(chan Frame)
	conn.dataPriority[7] = make(chan Frame)
	conn.pings = make(map[uint32]chan<- bool)
	conn.done = new(sync.WaitGroup)
	conn.clientStreamLimit = new(streamLimit)
	conn.serverStreamLimit = new(streamLimit)
	conn.serverStreamLimit.SetLimit(NO_STREAM_LIMIT)
	conn.vectorIndex = 8
	conn.certificates = make(map[uint16][]*x509.Certificate, 8)
	if conn.tlsState != nil && conn.tlsState.PeerCertificates != nil {
		conn.certificates[1] = conn.tlsState.PeerCertificates
	}

	return conn
}
