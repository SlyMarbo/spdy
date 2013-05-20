package spdy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
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
	streamInputs       map[uint32]chan<- Frame
	dataPriority       [8]chan Frame
	pings              map[uint32]chan<- bool
	pingID             uint32
	compressor         *Compressor
	decompressor       *Decompressor
	receivedSettings   map[uint32]*Setting
	nextServerStreamID uint32          // even
	nextClientStreamID uint32          // odd
	initialWindowSize  uint32          // transport window
	goaway             bool            // goaway has been sent/received.
	version            uint16          // SPDY version.
	numBenignErrors    int             // number of non-serious errors encountered.
	done               *sync.WaitGroup // WaitGroup for active streams.
	activeStreams      uint32
	maxActiveStreams   uint32
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
			conn.PROTOCOL_ERROR(0)
		}

		// ReadFrame takes care of the frame parsing for us.
		frame, err := ReadFrame(conn.buf)
		conn.refreshTimeouts()
		if err != nil {
			if err == io.EOF {
				// Client has closed the TCP connection.
				log.Println("Warning: Client has disconnected.")
				return
			}

			log.Printf("Error: Server encountered read error: %q\n", err.Error())
			return
		}

		// Decompress the frame's headers, if there are any.
		err = frame.ReadHeaders(conn.decompressor)
		if err != nil {
			log.Println("Error in decompression: ", err)
			conn.PROTOCOL_ERROR(frame.StreamID())
		}

		if DebugMode {
			fmt.Println("Received Frame:")
			fmt.Println(frame)
		}

		// Make sure the received frame uses an appropriate
		// SPDY version.
		if !conn.validFrameVersion(frame) {
			reply := new(RstStreamFrame)
			reply.version = SPDY_VERSION
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
			if StatusCodeIsFatal(int(frame.StatusCode)) {
				code := StatusCodeText(int(frame.StatusCode))
				log.Printf("Warning: Received %s on stream %d. Closing stream.\n", code, frame.StreamID())
				return
			}
			conn.handleRstStream(frame)

		case *SettingsFrame:
			for _, setting := range frame.Settings {
				conn.receivedSettings[setting.ID] = setting
				switch setting.ID {
				case SETTINGS_INITIAL_WINDOW_SIZE:
					if conn.version > 2 {
						if DebugMode {
							log.Printf("Initial window size is %d.\n", setting.Value)
						}
						conn.initialWindowSize = setting.Value
					} else {
						msg := "Warning: Received INITIAL_WINDOW_SIZE setting on SPDY/%d, which has no flow control.\n"
						log.Printf(msg, conn.version)
					}

				case SETTINGS_MAX_CONCURRENT_STREAMS:
					conn.maxActiveStreams = setting.Value
					// TODO: enforce. (Issue #7)
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
				if DebugMode {
					log.Println("Received PING. Replying...")
				}
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
			conn.handleHeadersFrame(frame)

		case *WindowUpdateFrame:
			conn.handleWindowUpdateFrame(frame)

		/*** [UNIMPLEMENTED] ***/
		case *CredentialFrame:
			log.Println("Got CREDENTIAL: [UNIMPLEMENTED]")

		case *DataFrame:
			conn.handleDataFrame(frame)

		default:
			log.Println(fmt.Sprintf("unexpected frame type %T", frame))
		}
	}
}

// send is run in a separate goroutine. It's used
// to ensure clear interleaving of frames and to
// provide assurances of priority and structure.
func (conn *serverConnection) send() {
	for {
		frame := conn.selectFrameToSend()

		// Compress any name/value header blocks.
		err := frame.WriteHeaders(conn.compressor)
		if err != nil {
			log.Println(err)
			continue
		}

		if DebugMode {
			log.Println("Sending Frame:")
			log.Println(frame)
		}

		// Leave the specifics of writing to the
		// connection up to the frame.
		err = frame.WriteTo(conn.conn)
		conn.refreshTimeouts()
		if err != nil {
			if err == io.EOF {
				// Server has closed the TCP connection.
				log.Println("Warning: Server has disconnected.")
				return
			}

			panic(err)
		}
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

// newStream is used to create a new responseStream from a SYN_STREAM frame.
func (conn *serverConnection) newStream(frame *SynStreamFrame, input <-chan Frame, output chan<- Frame) *responseStream {
	stream := new(responseStream)
	stream.conn = conn
	stream.streamID = frame.streamID
	stream.state = new(StreamState)
	stream.input = input
	stream.output = output
	stream.certificates = make([]Certificate, 1)
	stream.headers = make(Header)
	stream.unidirectional = frame.Flags&FLAG_UNIDIRECTIONAL != 0
	stream.version = conn.version

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
		log.Println("Error: Invalid HTTP version: " + headers.Get(":version"))
		return nil
	}

	var method string
	switch frame.version {
	case 3:
		method = headers.Get(":method")
	case 2:
		method = headers.Get("method")
	}

	stream.request = &Request{
		Method:     method,
		URL:        url,
		Proto:      vers,
		ProtoMajor: major,
		ProtoMinor: minor,
		Priority:   int(frame.Priority),
		RemoteAddr: conn.remoteAddr,
		Header:     headers,
		Host:       url.Host,
		RequestURI: url.Path,
		TLS:        conn.tlsState,
	}

	return stream
}

// Internally-sent frames have high priority.
func (conn *serverConnection) WriteFrame(frame Frame) {
	conn.dataPriority[0] <- frame
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

	headers := make(Header)
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
	out.headers = make(Header)
	out.stop = false
	out.version = conn.version
	out.AddFlowControl()

	// Store in the connection map.
	conn.streams[newID] = out

	return out, nil
}

// Request is a method stub required to satisfy the Connection
// interface. It must not be used by servers.
func (conn *serverConnection) Request(_ *Request, _ Receiver) (Stream, error) {
	return nil, errors.New("Error: Servers cannot make requests.")
}

func (conn *serverConnection) Version() uint16 {
	return conn.version
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

	// Check the version.
	if frame.Version() != conn.version {
		log.Printf("Error: Received frame with SPDY version %d on connection with version %d.\n",
			frame.Version(), conn.version)
		if frame.Version() > SPDY_VERSION {
			log.Printf("Error: Received frame with SPDY version %d, which is not supported.\n",
				frame.Version())
		}
		return false
	}
	return true
}

// handleSynStream performs the processing of SYN_STREAM frames.
func (conn *serverConnection) handleSynStream(frame *SynStreamFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

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
	nsid := conn.nextClientStreamID + 2
	if sid != nsid && sid != 1 && conn.nextClientStreamID != 0 {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be %d.\n", sid, nsid)
		conn.numBenignErrors++
		return
	}

	// Check Stream ID is not out of bounds.
	if sid > MAX_STREAM_ID {
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which exceeds the limit.\n", sid)
		conn.PROTOCOL_ERROR(sid)
	}

	// Stream ID is fine.

	// Create and start new stream.
	conn.RUnlock()
	conn.Lock()
	input := make(chan Frame)
	nextStream := conn.newStream(frame, input, conn.dataPriority[frame.Priority])
	if nextStream == nil {
		conn.Unlock()
		conn.RLock()
		return
	}
	nextStream.handler = conn.server.Handler
	if nextStream.handler == nil {
		nextStream.handler = DefaultServeMux
	}
	nextStream.httpHandler = conn.server.httpHandler
	if nextStream.httpHandler == nil {
		nextStream.httpHandler = http.DefaultServeMux
	}
	conn.streamInputs[sid] = input
	conn.streams[sid] = nextStream
	conn.Unlock()
	conn.RLock()

	go nextStream.Run()

	return
}

// handleSynReply performs the processing of SYN_REPLY frames.
func (conn *serverConnection) handleSynReply(frame *SynReplyFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received HEADERS with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
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
	conn.streamInputs[sid] <- frame

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		conn.streams[sid].State().CloseThere()
	}
}

// handleRstStream performs the processing of RST_STREAM frames.
func (conn *serverConnection) handleRstStream(frame *RstStreamFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	sid := frame.streamID

	switch frame.StatusCode {
	case RST_STREAM_INVALID_STREAM:
		log.Printf("Error: Received INVALID_STREAM for stream ID %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_REFUSED_STREAM:
		conn.closeStream(sid)
		return

	case RST_STREAM_CANCEL:
		if sid&1 == 0 {
			log.Printf("Error: Received RST_STREAM with Stream ID %d, which should be odd.\n", sid)
			conn.numBenignErrors++
			return
		}
		conn.closeStream(sid)
		return

	case RST_STREAM_FLOW_CONTROL_ERROR:
		log.Printf("Error: Received FLOW_CONTROL_ERROR for stream ID %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_STREAM_IN_USE:
		log.Printf("Error: Received STREAM_IN_USE for stream ID %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_STREAM_ALREADY_CLOSED:
		log.Printf("Error: Received STREAM_ALREADY_CLOSED for stream ID %d.\n", sid)
		conn.numBenignErrors++
		return

	case RST_STREAM_INVALID_CREDENTIALS:
		log.Printf("Error: Received INVALID_CREDENTIALS for stream ID %d.\n", sid)
		conn.numBenignErrors++
		return

	default:
		log.Printf("Error: Received unknown RST_STREAM status code %d.\n", frame.StatusCode)
		conn.PROTOCOL_ERROR(sid)
	}
}

// handleDataFrame performs the processing of DATA frames.
func (conn *serverConnection) handleDataFrame(frame *DataFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received DATA with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream is open.
	if stream, ok := conn.streams[sid]; !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received DATA with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send data to stream.
	conn.streamInputs[sid] <- frame

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		conn.streams[sid].State().CloseThere()
	}
}

// handleHeadersFrame performs the processing of HEADERS frames.
func (conn *serverConnection) handleHeadersFrame(frame *HeadersFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received HEADERS with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream is open.
	if stream, ok := conn.streams[sid]; !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received HEADERS with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Send headers to stream.
	conn.streamInputs[sid] <- frame

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		conn.streams[sid].State().CloseThere()
	}
}

// handleWindowUpdateFrame performs the processing of WINDOW_UPDATE frames.
func (conn *serverConnection) handleWindowUpdateFrame(frame *WindowUpdateFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	sid := frame.streamID

	// Check Stream ID is odd.
	if sid&1 == 0 {
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which should be odd.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Check stream is open.
	if stream, ok := conn.streams[sid]; !ok || stream == nil || stream.State().ClosedThere() {
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which is closed or unopened.\n", sid)
		conn.numBenignErrors++
		return
	}

	// Stream ID is fine.

	// Check delta window size is valid.
	delta := frame.DeltaWindowSize
	if delta > MAX_DELTA_WINDOW_SIZE || delta < 0 {
		log.Printf("Error: Received WINDOW_UPDATE with invalid delta window size %d.\n", delta)
		conn.PROTOCOL_ERROR(sid)
	}

	// Ignore empty deltas.
	if delta == 0 {
		return
	}

	// Send update to stream.
	conn.streamInputs[sid] <- frame
}

// Add timeouts if requested by the server.
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
	close(conn.streamInputs[streamID])
	delete(conn.streams, streamID)
}

// PROTOCOL_ERROR informs the client that a protocol error has
// occurred, stops all running streams, and ends the connection.
func (conn *serverConnection) PROTOCOL_ERROR(streamID uint32) {
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
	for streamID, c := range conn.streamInputs {
		close(c)
		conn.streams[streamID].Stop()
	}
	conn.streamInputs = nil
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

	// Start the send loop.
	go conn.send()

	// Send any global settings.
	if conn.server.GlobalSettings != nil {
		settings := new(SettingsFrame)
		settings.version = conn.version
		settings.Settings = conn.server.GlobalSettings
		conn.dataPriority[3] <- settings
	}

	// Enter the main loop.
	conn.readFrames()

	// Cleanup before the connection closes.
	conn.cleanup()
}

// acceptDefaultSPDYv2 is used in starting a SPDY/2 connection from
// an HTTP server supporting NPN.
func acceptDefaultSPDYv2(srv *http.Server, tlsConn *tls.Conn, _ http.Handler) {
	server := new(Server)
	server.TLSConfig = srv.TLSConfig
	acceptSPDYv2(server, tlsConn, nil)
}

// acceptSPDYv2 is used in starting a SPDY/2 connection from an HTTP
// server supporting NPN. This is called manually from within a
// closure which stores the SPDY server.
func acceptSPDYv2(server *Server, tlsConn *tls.Conn, _ http.Handler) {
	conn := newConn(tlsConn)
	conn.server = server
	conn.version = 2

	conn.serve()
}

// acceptDefaultSPDYv3 is used in starting a SPDY/3 connection from
// an HTTP server supporting NPN.
func acceptDefaultSPDYv3(srv *http.Server, tlsConn *tls.Conn, _ http.Handler) {
	server := new(Server)
	server.TLSConfig = srv.TLSConfig
	acceptSPDYv3(server, tlsConn, nil)
}

// acceptSPDYv3 is used in starting a SPDY/3 connection from an HTTP
// server supporting NPN. This is called manually from within a
// closure which stores the SPDY server.
func acceptSPDYv3(server *Server, tlsConn *tls.Conn, _ http.Handler) {
	conn := newConn(tlsConn)
	conn.server = server
	conn.version = 3

	conn.serve()
}

// newConn is used to create and initialise a server connection.
func newConn(tlsConn *tls.Conn) *serverConnection {
	conn := new(serverConnection)
	conn.remoteAddr = tlsConn.RemoteAddr().String()
	conn.conn = tlsConn
	conn.buf = bufio.NewReader(tlsConn)
	conn.tlsState = new(tls.ConnectionState)
	*conn.tlsState = tlsConn.ConnectionState()
	conn.compressor = new(Compressor)
	conn.decompressor = new(Decompressor)
	conn.initialWindowSize = DEFAULT_INITIAL_WINDOW_SIZE
	conn.streams = make(map[uint32]Stream)
	conn.streamInputs = make(map[uint32]chan<- Frame)
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

	return conn
}
