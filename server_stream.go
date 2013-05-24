package spdy

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
)

// serverStream is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type serverStream struct {
	sync.RWMutex
	conn           *serverConnection
	streamID       uint32
	flow           *flowControl
	requestBody    *bytes.Buffer
	state          *StreamState
	output         chan<- Frame
	request        *http.Request
	handler        Handler
	httpHandler    http.Handler
	headers        http.Header
	unidirectional bool
	responseCode   int
	stop           bool
	wroteHeader    bool
	version        uint16
	done           chan struct{}
}

func (s *serverStream) Cancel() {
	panic("Error: Client-sent stream cancelled. Use Stop() instead.")
}

func (s *serverStream) ClientCertificates(index uint16) []*x509.Certificate {
	return s.conn.certificates[index]
}

func (s *serverStream) Connection() Connection {
	return s.conn
}

func (s *serverStream) Header() http.Header {
	return s.headers
}

func (s *serverStream) Ping() <-chan bool {
	return s.conn.Ping()
}

func (s *serverStream) Push(resource string) (PushWriter, error) {
	return s.conn.Push(resource, s)
}

func (s *serverStream) ReceiveFrame(frame Frame) {
	s.Lock()
	defer s.Unlock()

	s.receiveFrame(frame)
}

func (s *serverStream) Settings() []*Setting {
	out := make([]*Setting, 0, len(s.conn.receivedSettings))
	for _, val := range s.conn.receivedSettings {
		out = append(out, val)
	}
	return out
}

func (s *serverStream) State() *StreamState {
	return s.state
}

func (s *serverStream) Stop() {
	s.stop = true
	s.done <- struct{}{}
}

func (s *serverStream) StreamID() uint32 {
	return s.streamID
}

// Write is the main method with which data is sent.
func (s *serverStream) Write(inputData []byte) (int, error) {
	if s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	if s.stop {
		return 0, ErrCancelled
	}

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

	// Default to 200 response.
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}

	// Send any new headers.
	s.WriteHeaders()

	// Chunk the response if necessary.
	// Data is sent to the flow control to
	// ensure that the protocol is followed.
	written := 0
	for len(data) > MAX_DATA_SIZE {
		n, err := s.flow.Write(data[:MAX_DATA_SIZE])
		if err != nil {
			return written, err
		}
		written += n
		data = data[MAX_DATA_SIZE:]
	}

	n, err := s.flow.Write(data)
	written += n

	return written, err
}

// WriteHeader is used to set the HTTP status code.
func (s *serverStream) WriteHeader(code int) {
	if s.wroteHeader {
		log.Println("spdy: Error: Multiple calls to ResponseWriter.WriteHeader.")
		return
	}

	s.wroteHeader = true
	s.responseCode = code

	switch s.version {
	case 3:
		s.headers.Set(":status", strconv.Itoa(code))
		s.headers.Set(":version", "HTTP/1.1")
	case 2:
		s.headers.Set("status", strconv.Itoa(code))
		s.headers.Set("version", "HTTP/1.1")
	}

	// Create the response SYN_REPLY.
	synReply := new(SynReplyFrame)
	synReply.version = s.version
	synReply.streamID = s.streamID
	synReply.Headers = cloneHeaders(s.headers)

	// Clear the headers that have been sent.
	for name := range synReply.Headers {
		s.headers.Del(name)
	}

	// These responses have no body, so close the stream now.
	if code == 204 || code == 304 || code/100 == 1 {
		synReply.Flags = FLAG_FIN
		s.state.CloseHere()
	}

	s.output <- synReply
}

// WriteHeaders is used to flush HTTP headers.
func (s *serverStream) WriteHeaders() {
	if len(s.headers) == 0 {
		return
	}

	// Create the HEADERS frame.
	headers := new(HeadersFrame)
	headers.version = s.version
	headers.streamID = s.streamID
	headers.Headers = cloneHeaders(s.headers)

	// Clear the headers that have been sent.
	for name := range headers.Headers {
		s.headers.Del(name)
	}

	s.output <- headers
}

func (s *serverStream) WriteSettings(settings ...*Setting) {
	if settings == nil {
		return
	}

	// Create the SETTINGS frame.
	frame := new(SettingsFrame)
	frame.version = s.version
	frame.Settings = settings
	s.output <- frame
}

func (s *serverStream) Version() uint16 {
	return s.version
}

// receiveFrame is used to process an inbound frame.
func (s *serverStream) receiveFrame(frame Frame) {
	if frame == nil {
		panic("Nil frame received in receiveFrame.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *DataFrame:
		s.requestBody.Write(frame.Data)
		if frame.Flags&FLAG_FIN == 0 {
			s.flow.Receive(frame.Data)
		}

	case *SynReplyFrame:
		updateHeaders(s.headers, frame.Headers)

	case *HeadersFrame:
		updateHeaders(s.headers, frame.Headers)

	case *WindowUpdateFrame:
		err := s.flow.UpdateWindow(frame.DeltaWindowSize)
		if err != nil {
			reply := new(RstStreamFrame)
			reply.version = s.version
			reply.streamID = s.streamID
			reply.StatusCode = RST_STREAM_FLOW_CONTROL_ERROR
			s.output <- reply
			return
		}

	default:
		panic(fmt.Sprintf("Received unknown frame of type %T.", frame))
	}
}

// Wait blocks until a frame is received
// or the input channel is closed. If a
// frame is received, it is processed.
func (s *serverStream) Wait() {
	<-s.done
}

// run is the main control path of
// the stream. It is prepared, the
// registered handler is called,
// and then the stream is cleaned
// up and closed.
func (s *serverStream) Run() {
	s.conn.done.Add(1)

	// Make sure Request is prepared.
	s.AddFlowControl()
	s.requestBody = new(bytes.Buffer)
	s.request.Body = &readCloserBuffer{s.requestBody}

	/***************
	 *** HANDLER ***
	 ***************/
	mux, ok := s.handler.(*ServeMux)
	if s.handler == nil || (ok && mux.Nil()) {
		s.httpHandler.ServeHTTP(s, s.request)
	} else {
		s.handler.ServeSPDY(s, s.request)
	}

	// Make sure any queued data has been sent.
	if s.flow.Paused() && s.state.OpenThere() {
		s.Wait()
		s.flow.Flush()
	}
	if s.flow.Paused() {
		log.Printf("Error: Stream %d has been closed with data still buffered.\n", s.streamID)
	}

	// Close the stream with a SYN_REPLY if
	// none has been sent, or an empty DATA
	// frame, if a SYN_REPLY has been sent
	// already.
	// If the stream is already closed at
	// this end, then nothing happens.
	if s.state.OpenHere() && !s.wroteHeader {
		switch s.version {
		case 3:
			s.headers.Set(":status", "200")
			s.headers.Set(":version", "HTTP/1.1")
		case 2:
			s.headers.Set("status", "200")
			s.headers.Set("version", "HTTP/1.1")
		}

		// Create the response SYN_REPLY.
		synReply := new(SynReplyFrame)
		synReply.version = s.version
		synReply.Flags = FLAG_FIN
		synReply.streamID = s.streamID
		synReply.Headers = s.headers

		s.output <- synReply
	} else if s.state.OpenHere() {
		// Create the DATA.
		data := new(DataFrame)
		data.streamID = s.streamID
		data.Flags = FLAG_FIN
		data.Data = []byte{}

		s.output <- data
	}

	// Clean up state.
	s.state.CloseHere()
	s.conn.done.Done()
}

// readCloserBuffer is a helper structure
// to allow a bytes buffer to satisfy the
// io.ReadCloser interface.
type readCloserBuffer struct {
	*bytes.Buffer
}

func (r *readCloserBuffer) Close() error {
	return nil
}
