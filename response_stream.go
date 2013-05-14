package spdy

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
)

// responseStream is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type responseStream struct {
	sync.RWMutex
	conn           *serverConnection
	streamID       uint32
	flow           *flowControl
	requestBody    *bytes.Buffer
	state          *StreamState
	input          <-chan Frame
	output         chan<- Frame
	request        *Request
	handler        *ServeMux
	certificates   []Certificate
	headers        Header
	settings       []*Setting
	unidirectional bool
	responseCode   int
	stop           bool
	wroteHeader    bool
	version        int
}

func (s *responseStream) Connection() Connection {
	return s.conn
}

func (s *responseStream) Header() Header {
	return s.headers
}

func (s *responseStream) Ping() <-chan bool {
	return s.conn.Ping()
}

func (s *responseStream) Push(resource string) (PushWriter, error) {
	return s.conn.Push(resource, s)
}

func (s *responseStream) Settings() []*Setting {
	out := make([]*Setting, 0, len(s.conn.receivedSettings))
	for _, val := range s.conn.receivedSettings {
		out = append(out, val)
	}
	return out
}

func (s *responseStream) State() *StreamState {
	return s.state
}

func (s *responseStream) Stop() {
	s.stop = true
}

func (s *responseStream) StreamID() uint32 {
	return s.streamID
}

// Write is the main method with which data is sent.
func (s *responseStream) Write(inputData []byte) (int, error) {
	if s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	// Check any frames received since last call.
	s.processInput()
	if s.stop {
		return 0, ErrCancelled
	}

	// Send any new headers.
	s.WriteHeaders()

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

	// Default to 200 response.
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}

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
func (s *responseStream) WriteHeader(code int) {
	if s.wroteHeader {
		log.Println("spdy: Error: Multiple calls to ResponseWriter.WriteHeader.")
		return
	}

	s.wroteHeader = true
	s.responseCode = code

	s.headers.Set(":status", fmt.Sprint(code))
	s.headers.Set(":version", "HTTP/1.1")

	synReply := new(SynReplyFrame)
	synReply.version = uint16(s.version)
	synReply.streamID = s.streamID
	synReply.Headers = s.headers.clone()

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
func (s *responseStream) WriteHeaders() {
	if len(s.headers) == 0 {
		return
	}

	headers := new(HeadersFrame)
	headers.version = uint16(s.version)
	headers.streamID = s.streamID
	headers.Headers = s.headers.clone()

	// Clear the headers that have been sent.
	for name := range headers.Headers {
		s.headers.Del(name)
	}

	s.output <- headers
}

func (s *responseStream) WriteSettings(settings ...*Setting) {
	if settings == nil {
		return
	}

	frame := new(SettingsFrame)
	frame.version = uint16(s.version)
	frame.Settings = settings
	s.output <- frame
}

func (s *responseStream) Version() uint16 {
	return uint16(s.version)
}

// receiveFrame is used to process an inbound frame.
func (s *responseStream) receiveFrame(frame Frame) {
	if frame == nil {
		panic("Nil frame received in receiveFrame.")
	}

	switch frame := frame.(type) {
	case *DataFrame:
		s.requestBody.Write(frame.Data)

	case *HeadersFrame:
		s.headers.Update(frame.Headers)

	case *WindowUpdateFrame:
		err := s.flow.UpdateWindow(frame.DeltaWindowSize)
		if err != nil {
			reply := new(RstStreamFrame)
			reply.version = uint16(s.version)
			reply.streamID = s.streamID
			reply.StatusCode = RST_STREAM_FLOW_CONTROL_ERROR
			s.output <- reply
			return
		}

	default:
		panic(fmt.Sprintf("Received unknown frame of type %T.", frame))
	}
}

// wait blocks until a frame is received
// or the input channel is closed. If a
// frame is received, it is processed.
func (s *responseStream) wait() {
	frame := <-s.input
	if frame == nil {
		return
	}
	s.receiveFrame(frame)
}

// processInput processes any frames currently
// queued in the input channel, but does not
// wait once the channel has been cleared.
func (s *responseStream) processInput() {
	var frame Frame
	var ok bool

	for {
		select {
		case frame, ok = <-s.input:
			if !ok {
				return
			}
			s.receiveFrame(frame)

		default:
			return
		}
	}
}

// run is the main control path of
// the stream. It is prepared, the
// registered handler is called,
// and then the stream is cleaned
// up and closed.
func (s *responseStream) run() {

	// Make sure Request is prepared.
	s.AddFlowControl()
	s.requestBody = new(bytes.Buffer)
	s.processInput()
	s.request.Body = &readCloserBuffer{s.requestBody}

	/***************
	 *** HANDLER ***
	 ***************/
	s.handler.ServeSPDY(s, s.request)

	// Make sure any queued data has been sent.
	for s.flow.Paused() {
		s.wait()
		s.flow.Flush()
	}

	// Close the stream with a SYN_REPLY if
	// none has been sent, or an empty DATA
	// frame, if a SYN_REPLY has been sent
	// already.
	// If the stream is already closed at
	// this end, then nothing happens.
	if s.state.OpenHere() && !s.wroteHeader {
		s.headers.Set(":status", "200")
		s.headers.Set(":version", "HTTP/1.1")

		synReply := new(SynReplyFrame)
		synReply.version = uint16(s.version)
		synReply.Flags = FLAG_FIN
		synReply.streamID = s.streamID
		synReply.Headers = s.headers

		s.output <- synReply
	} else if s.state.OpenHere() {
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

type readCloserBuffer struct {
	*bytes.Buffer
}

func (_ *readCloserBuffer) Close() error {
	return nil
}
