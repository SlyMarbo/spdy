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
// co-ordination between 
type serverConnection struct {
	sync.RWMutex
	remoteAddr          string
	server              *Server
	conn                *tls.Conn
	buf                 *bufio.Reader // buffered reader for the connection.
	tlsState            *tls.ConnectionState
	streams             map[uint32]*responseStream
	streamInputs        map[uint32]chan<- Frame
	streamOutputs       [8]chan Frame
	pings               map[uint32]chan<- bool
	pingID              uint32
	compressor          *Compressor
	decompressor        *Decompressor
	receivedSettings    []*Setting
	nextServerStreamID  uint32 // even
	nextClientStreamID  uint32 // odd
	initialWindowSize   uint32 // transport window
	goaway              bool // goaway has been sent/received.
	version             int // SPDY version.
	numInvalidStreamIDs int // number of invalid Stream IDs received.
	done                *sync.WaitGroup // WaitGroup for active streams.
}

func (conn *serverConnection) readFrames() {
	if d := conn.server.ReadTimeout; d != 0 {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := conn.server.WriteTimeout; d != 0 {
		defer func() {
			conn.conn.SetWriteDeadline(time.Now().Add(d))
		}()
	}

	for {
		if conn.numInvalidStreamIDs > MaxInvalidStreamIDs {
			log.Println("Error: Too many invalid stream IDs received. Ending connection.")
			conn.PROTOCOL_ERROR(0)
		}

		frame, err := ReadFrame(conn.buf)
		if err != nil {
			if err == io.EOF {
				// Client has closed the TCP connection.
				return
			}

			// TODO: handle error
			panic(err)
		}
		err = frame.ReadHeaders(conn.decompressor)
		if err != nil {
			panic(err)
		}

		if DebugMode {
			fmt.Println("Received Frame:")
			fmt.Println(frame)
		}

	FrameHandling:
		switch frame := frame.(type) {

		/*** COMPLETE! ***/
		case *SynStreamFrame:
			conn.handleSynStream(frame)

		case *SynReplyFrame:
			panic("Got SYN_REPLY: [UNIMPLEMENTED]")

		case *RstStreamFrame:
			switch frame.StatusCode {
			case RST_STREAM_PROTOCOL_ERROR: fallthrough
			case RST_STREAM_INTERNAL_ERROR: fallthrough
			case RST_STREAM_FRAME_TOO_LARGE: fallthrough
			case RST_STREAM_UNSUPPORTED_VERSION:
				
				code := StatusCodeText(int(frame.StatusCode))
				log.Printf("Warning: Received %s on stream %d. Closing stream.\n", code, frame.StreamID)
				return
			}
			conn.handleRstStream(frame)

		/*** COMPLETE! ***/
		case *SettingsFrame:
			if conn.receivedSettings == nil {
				conn.receivedSettings = frame.Settings
			} else {
				for _, new := range frame.Settings {
					for i, old := range conn.receivedSettings {
						if new.ID == old.ID {
							conn.receivedSettings[i] = new
						}
					}
					conn.receivedSettings = append(conn.receivedSettings, new)
				}
			}
			for _, setting := range frame.Settings {
				if setting.ID == SETTINGS_INITIAL_WINDOW_SIZE && conn.version > 2 {
					log.Printf("Initial window size is %d.\n", setting.Value)
					conn.initialWindowSize = setting.Value
				}
			}

		/*** COMPLETE! ***/
		case *PingFrame:
			// Check Ping ID is odd.
			if frame.PingID&1 == 0 {
				if conn.pings[frame.PingID] == nil {
					log.Printf("Warning: Ignored PING with Ping ID %d, which hasn't been requested.\n",
						frame.PingID)
					break FrameHandling
				}
				conn.pings[frame.PingID] <- true
				close(conn.pings[frame.PingID])
				delete(conn.pings, frame.PingID)
			} else {
				// TODO: Print to the log in DebugMode only.
				log.Println("Received PING. Replying...")
				conn.WriteFrame(frame)
			}

		case *GoawayFrame:
			// Check version.
			if frame.Version() != uint16(conn.version) {
				log.Printf("Warning: Received frame with SPDY version %d on connection with version %d.\n",
					frame.Version(), conn.version)
				if frame.Version() > SPDY_VERSION {
					log.Printf("Error: Received frame with SPDY version %d, which is not supported.\n",
						frame.Version)
				}
				reply := new(RstStreamFrame)
				reply.version = SPDY_VERSION
				reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
				conn.WriteFrame(reply)
				break FrameHandling
			}

			// TODO: inform push streams that they haven't been processed if
			// the last good stream ID is less than their ID.

			conn.Lock()
			conn.goaway = true
			conn.Unlock()

		/*** COMPLETE! ***/
		case *HeadersFrame:
			conn.handleHeadersFrame(frame)

		/*** COMPLETE! ***/
		case *WindowUpdateFrame:
			conn.handleWindowUpdateFrame(frame)

		case *CredentialFrame:
			panic("Got CREDENTIAL: [UNIMPLEMENTED]")

		/*** COMPLETE! ***/
		case *DataFrame:
			conn.handleDataFrame(frame)

		default:
			panic(fmt.Sprintf("unexpected frame type %T", frame))
		}
	}
}

func (conn *serverConnection) send() {
	for {
		frame := conn.selectFrameToSend()
		err := frame.WriteHeaders(conn.compressor)
		if err != nil {
			panic(err)
		}
		err = frame.WriteTo(conn.conn)
		if err != nil {
			panic(err)
		}
	}
}

func (conn *serverConnection) selectFrameToSend() (frame Frame) {
	// Try in priority order first.
	for i := 0; i < 8; i++ {
		select {
		case frame = <-conn.streamOutputs[i]:
			return frame
		default:
		}
	}

	// Wait for any frame.
	select {
	case frame = <-conn.streamOutputs[0]:
		return frame
	case frame = <-conn.streamOutputs[1]:
		return frame
	case frame = <-conn.streamOutputs[2]:
		return frame
	case frame = <-conn.streamOutputs[3]:
		return frame
	case frame = <-conn.streamOutputs[4]:
		return frame
	case frame = <-conn.streamOutputs[5]:
		return frame
	case frame = <-conn.streamOutputs[6]:
		return frame
	case frame = <-conn.streamOutputs[7]:
		return frame
	}

	panic("Unreachable")
}

func (conn *serverConnection) newStream(frame *SynStreamFrame, input <-chan Frame, output chan<- Frame) *responseStream {
	stream := new(responseStream)
	stream.conn = conn
	stream.streamID = frame.StreamID
	stream.state = new(StreamState)
	if frame.Flags&FLAG_FIN != 0 {
		stream.state.CloseThere()
	}
	stream.input = input
	stream.output = output
	stream.handler = DefaultServeMux
	stream.certificates = make([]Certificate, 1)
	stream.headers = make(Header)
	stream.settings = make([]*Setting, 1)
	stream.unidirectional = frame.Flags&FLAG_UNIDIRECTIONAL != 0
	stream.version = conn.version

	headers := frame.Headers
	rawUrl := headers.Get(":scheme") + "://" + headers.Get(":host") + headers.Get(":path")
	url, err := url.Parse(rawUrl)
	if err != nil {
		panic(err)
	}
	major, minor, ok := http.ParseHTTPVersion(headers.Get(":version"))
	if !ok {
		panic("Invalid HTTP version: " + headers.Get(":version"))
	}
	stream.request = &Request{
		Method:     headers.Get(":method"),
		URL:        url,
		Proto:      headers.Get(":version"),
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
	conn.streamOutputs[0] <- frame
}

func (conn *serverConnection) Ping() <-chan bool {
	conn.Lock()
	defer conn.Unlock()

	conn.pingID += 2
	ping := new(PingFrame)
	ping.version = uint16(conn.version)
	ping.PingID = conn.pingID
	conn.streamOutputs[0] <- ping
	c := make(chan bool, 1)
	conn.pings[conn.pingID] = c
	return c
}

func (conn *serverConnection) Push(resource string, origin Stream) (PushWriter, error) {
	conn.Lock()
	defer conn.Unlock()
	conn.nextServerStreamID += 2
	newID := conn.nextServerStreamID

	// Send the SYN_STREAM.
	push := new(SynStreamFrame)
	push.version = uint16(conn.version)
	push.Flags = FLAG_UNIDIRECTIONAL
	push.StreamID = newID
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
	headers.Set(":scheme", url.Scheme)
	headers.Set(":host", url.Host)
	headers.Set(":path", url.Path)
	headers.Set(":version", "HTTP/1.1")
	headers.Set(":status", "200 OK")
	push.Headers = headers
	conn.WriteFrame(push)

	// Create the pushStream.
	out := new(pushStream)
	out.conn = conn
	out.streamID = newID
	out.origin = origin
	out.state = new(StreamState)
	out.output = conn.streamOutputs[7] // The SYN_STREAM is priority 0, but its data is less urgent.
	out.headers = make(Header)
	out.stop = false
	out.version = conn.version
	out.AddFlowControl()

	return out, nil
}

func (conn *serverConnection) checkFrameVersion(frame Frame) bool {
	if frame.Version() != uint16(conn.version) {

		// This is currently strict; only one version allowed per connection.
		log.Printf("Error: Received frame with SPDY version %d on connection with version %d.\n",
			frame.Version(), conn.version)
		if frame.Version() > SPDY_VERSION {
			log.Printf("Error: Received frame with SPDY version %d, which is not supported.\n",
				frame.Version())
		}
		return true
	}
	return false
}

func (conn *serverConnection) handleSynStream(frame *SynStreamFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	// Check stream creation is allowed.
	if conn.goaway {
		return
	}

	if conn.checkFrameVersion(frame) {
		reply := new(RstStreamFrame)
		reply.version = SPDY_VERSION
		reply.StreamID = frame.StreamID
		reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
		conn.WriteFrame(reply)
		return
	}

	// Check Stream ID is odd.
	if frame.StreamID&1 == 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be odd.\n",
			frame.StreamID)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Check Stream ID is the right number.
	if frame.StreamID != conn.nextClientStreamID+2 && frame.StreamID != 1 &&
		conn.nextClientStreamID != 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be %d.\n",
			frame.StreamID, conn.nextClientStreamID+2)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Check Stream ID is not too large.
	if frame.StreamID > MAX_STREAM_ID {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received SYN_STREAM with Stream ID %d, which is too large.\n",
			frame.StreamID)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Stream ID is fine.

	// Create and start new stream.
	conn.RUnlock()
	conn.Lock()
	input := make(chan Frame)
	conn.streamInputs[frame.StreamID] = input
	conn.streams[frame.StreamID] = conn.newStream(frame, input, conn.streamOutputs[frame.Priority])
	conn.Unlock()
	conn.RLock()

	go conn.streams[frame.StreamID].run()
	conn.done.Add(1)

	return
}

func (conn *serverConnection) handleRstStream(frame *RstStreamFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	if conn.checkFrameVersion(frame) {
		reply := new(RstStreamFrame)
		reply.version = SPDY_VERSION
		reply.StreamID = frame.StreamID
		reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
		conn.WriteFrame(reply)
		return
	}
	
	streamID := frame.StreamID
	
	switch frame.StatusCode {
	case RST_STREAM_INVALID_STREAM:
		log.Printf("Error: Received INVALID_STREAM for stream ID %d.\n", streamID)
		conn.numInvalidStreamIDs++
		return
		
	case RST_STREAM_REFUSED_STREAM:
		conn.closeStream(streamID)
		return
		
	case RST_STREAM_CANCEL:
		if streamID&1 == 0 {
			log.Printf("Error: Received RST_STREAM with Stream ID %d, which should be odd.\n", streamID)
			conn.PROTOCOL_ERROR(streamID)
		}
		conn.closeStream(streamID)
		return
		
	case RST_STREAM_FLOW_CONTROL_ERROR:
		log.Printf("Error: Received FLOW_CONTROL_ERROR for stream ID %d.\n", streamID)
		conn.numInvalidStreamIDs++
		return
		
	case RST_STREAM_STREAM_IN_USE:
		log.Printf("Error: Received STREAM_IN_USE for stream ID %d.\n", streamID)
		conn.numInvalidStreamIDs++
		return
		
	case RST_STREAM_STREAM_ALREADY_CLOSED:
		log.Printf("Error: Received STREAM_ALREADY_CLOSED for stream ID %d.\n", streamID)
		conn.numInvalidStreamIDs++
		return
		
	case RST_STREAM_INVALID_CREDENTIALS:
		log.Printf("Error: Received INVALID_CREDENTIALS for stream ID %d.\n", streamID)
		conn.numInvalidStreamIDs++
		return
		
	default:
		log.Printf("Error: Received unknown RST_STREAM status code %d.\n", frame.StatusCode)
		conn.PROTOCOL_ERROR(streamID)
	}
}

func (conn *serverConnection) handleDataFrame(frame *DataFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	// Check Stream ID is odd.
	if frame.StreamID&1 == 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received DATA with Stream ID %d, which should be odd.\n",
			frame.StreamID)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Check stream is open.
	if frame.StreamID != conn.nextClientStreamID+2 && frame.StreamID != 1 &&
		conn.nextClientStreamID != 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received DATA with Stream ID %d, which should be %d.\n",
			frame.StreamID, conn.nextClientStreamID+2)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Stream ID is fine.

	// Send data to stream.
	conn.streamInputs[frame.StreamID] <- frame

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		conn.streams[frame.StreamID].state.CloseThere()
	}
}

func (conn *serverConnection) handleHeadersFrame(frame *HeadersFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	if conn.checkFrameVersion(frame) {
		reply := new(RstStreamFrame)
		reply.version = SPDY_VERSION
		reply.StreamID = frame.StreamID
		reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
		conn.WriteFrame(reply)
		return
	}

	// Check Stream ID is odd.
	if frame.StreamID&1 == 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received HEADERS with Stream ID %d, which should be odd.\n",
			frame.StreamID)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Check stream is open.
	if frame.StreamID != conn.nextClientStreamID+2 && frame.StreamID != 1 &&
		conn.nextClientStreamID != 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received HEADERS with Stream ID %d, which should be %d.\n",
			frame.StreamID, conn.nextClientStreamID+2)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Stream ID is fine.

	// Send data to stream.
	conn.streamInputs[frame.StreamID] <- frame

	// Handle flags.
	if frame.Flags&FLAG_FIN != 0 {
		conn.streams[frame.StreamID].state.CloseThere()
	}
}

func (conn *serverConnection) handleWindowUpdateFrame(frame *WindowUpdateFrame) {
	conn.RLock()
	defer func() { conn.RUnlock() }()

	if conn.checkFrameVersion(frame) {
		reply := new(RstStreamFrame)
		reply.version = SPDY_VERSION
		reply.StreamID = frame.StreamID
		reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
		conn.WriteFrame(reply)
		return
	}

	// Check Stream ID is odd.
	if frame.StreamID&1 == 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which should be odd.\n",
			frame.StreamID)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Check stream is open.
	if frame.StreamID != conn.nextClientStreamID+2 && frame.StreamID != 1 &&
		conn.nextClientStreamID != 0 {
		conn.numInvalidStreamIDs++
		log.Printf("Error: Received WINDOW_UPDATE with Stream ID %d, which should be %d.\n",
			frame.StreamID, conn.nextClientStreamID+2)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Stream ID is fine.

	// Check delta window size is valid.
	if frame.DeltaWindowSize > MAX_DELTA_WINDOW_SIZE || frame.DeltaWindowSize < 1 {
		log.Printf("Error: Received WINDOW_UPDATE with invalid delta window size %d.\n",
			frame.DeltaWindowSize)
		conn.PROTOCOL_ERROR(frame.StreamID)
	}

	// Send data to stream.
	conn.streamInputs[frame.StreamID] <- frame
}

func (conn *serverConnection) closeStream(streamID uint32) {
	if streamID == 0 {
		log.Println("Error: Tried to close stream 0.")
		return
	}
	
	conn.streams[streamID].stop = true
	conn.streams[streamID].state.Close()
	close(conn.streamInputs[streamID])
	delete(conn.streams, streamID)
}

func (conn *serverConnection) PROTOCOL_ERROR(streamID uint32) {
	reply := new(RstStreamFrame)
	reply.version = uint16(conn.version)
	reply.StreamID = streamID
	reply.StatusCode = RST_STREAM_PROTOCOL_ERROR
	conn.WriteFrame(reply)
	time.Sleep(100 * time.Millisecond)
	conn.cleanup()
	runtime.Goexit()
}

func (conn *serverConnection) cleanup() {
	for streamID, c := range conn.streamInputs {
		close(c)
		conn.streams[streamID].stop = true
	}
	conn.streamInputs = nil
	conn.streams = nil
}

func (conn *serverConnection) serve() {
	defer func() {
		if err := recover(); err != nil {
			const size = 4096
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("spdy: panic serving %v: %v\n%s", conn.remoteAddr, err, buf)
		}
	}()

	go func() { conn.send() }()
	if conn.server.GlobalSettings != nil {
		settings := new(SettingsFrame)
		settings.version = uint16(conn.version)
		settings.Settings = conn.server.GlobalSettings
		conn.streamOutputs[3] <- settings
	}
	conn.readFrames()
	conn.cleanup()
}

func acceptDefaultSPDYv2(srv *http.Server, tlsConn *tls.Conn, _ http.Handler) {
	server := new(Server)
	server.TLSConfig = srv.TLSConfig
	acceptSPDYv2(server, tlsConn, nil)
}

func acceptSPDYv2(server *Server, tlsConn *tls.Conn, _ http.Handler) {
	conn := newConn(tlsConn)
	conn.server = server
	conn.version = 2

	conn.serve()
}

func acceptDefaultSPDYv3(srv *http.Server, tlsConn *tls.Conn, _ http.Handler) {
	server := new(Server)
	server.TLSConfig = srv.TLSConfig
	acceptSPDYv3(server, tlsConn, nil)
}

func acceptSPDYv3(server *Server, tlsConn *tls.Conn, _ http.Handler) {
	conn := newConn(tlsConn)
	conn.server = server
	conn.version = 3

	conn.serve()
}

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
	conn.streams = make(map[uint32]*responseStream)
	conn.streamInputs = make(map[uint32]chan<- Frame)
	conn.streamOutputs = [8]chan Frame{}
	conn.streamOutputs[0] = make(chan Frame)
	conn.streamOutputs[1] = make(chan Frame)
	conn.streamOutputs[2] = make(chan Frame)
	conn.streamOutputs[3] = make(chan Frame)
	conn.streamOutputs[4] = make(chan Frame)
	conn.streamOutputs[5] = make(chan Frame)
	conn.streamOutputs[6] = make(chan Frame)
	conn.streamOutputs[7] = make(chan Frame)
	conn.pings = make(map[uint32]chan<- bool)
	conn.done = new(sync.WaitGroup)

	return conn
}
