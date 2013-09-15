package spdy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// serverStreamV2 is a structure that implements the
// Stream interface. This is used for responding to
// client requests.
type serverStreamV2 struct {
	sync.Mutex
	conn           Conn
	streamID       StreamID
	requestBody    *bytes.Buffer
	state          *StreamState
	output         chan<- Frame
	request        *http.Request
	handler        http.Handler
	header         http.Header
	unidirectional bool
	responseCode   int
	stop           chan struct{}
	wroteHeader    bool
}

/***********************
 * http.ResponseWriter *
 ***********************/

func (s *serverStreamV2) Header() http.Header {
	return s.header
}

// Write is the main method with which data is sent.
func (s *serverStreamV2) Write(inputData []byte) (int, error) {
	if s.unidirectional {
		return 0, errors.New("Error: Stream is unidirectional.")
	}

	if s.closed() || s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

	// Default to 200 response.
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}

	// Send any new headers.
	s.writeHeader()

	// Chunk the response if necessary.
	written := 0
	for len(data) > MAX_DATA_SIZE {
		dataFrame := new(dataFrameV2)
		dataFrame.StreamID = s.streamID
		dataFrame.Data = data[:MAX_DATA_SIZE]
		s.output <- dataFrame

		written += MAX_DATA_SIZE
	}

	n := len(data)
	if n == 0 {
		return written, nil
	}

	dataFrame := new(dataFrameV2)
	dataFrame.StreamID = s.streamID
	dataFrame.Data = data
	s.output <- dataFrame

	return written + n, nil
}

// WriteHeader is used to set the HTTP status code.
func (s *serverStreamV2) WriteHeader(code int) {
	if s.unidirectional {
		log.Println("Error: Stream is unidirectional.")
		return
	}

	if s.wroteHeader {
		log.Println("Error: Multiple calls to ResponseWriter.WriteHeader.")
		return
	}

	s.wroteHeader = true
	s.responseCode = code
	s.header.Set("status", strconv.Itoa(code))
	s.header.Set("version", "HTTP/1.1")

	// Create the response SYN_REPLY.
	synReply := new(synReplyFrameV2)
	synReply.StreamID = s.streamID
	synReply.Header = cloneHeader(s.header)

	// Clear the headers that have been sent.
	for name := range synReply.Header {
		s.header.Del(name)
	}

	// These responses have no body, so close the stream now.
	if code == 204 || code == 304 || code/100 == 1 {
		synReply.Flags = FLAG_FIN
		s.state.CloseHere()
	}

	s.output <- synReply
}

/*****************
 * io.ReadCloser *
 *****************/

func (s *serverStreamV2) Close() error {
	s.Lock()
	defer s.Unlock()
	s.writeHeader()
	if s.state != nil {
		s.state.Close()
	}
	if s.requestBody != nil {
		s.requestBody.Reset()
		s.requestBody = nil
	}
	s.output = nil
	s.request = nil
	s.handler = nil
	s.header = nil
	s.stop = nil
	return nil
}

func (s *serverStreamV2) Read(out []byte) (int, error) {
	n, err := s.requestBody.Read(out)
	if err == io.EOF && s.state.OpenThere() {
		return n, nil
	}
	return n, err
}

/**********
 * Stream *
 **********/

func (s *serverStreamV2) Conn() Conn {
	return s.conn
}

func (s *serverStreamV2) ReceiveFrame(frame Frame) error {
	s.Lock()
	defer s.Unlock()

	if frame == nil {
		return errors.New("Error: Nil frame received.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *dataFrameV2:
		s.requestBody.Write(frame.Data)
		if frame.Flags.FIN() {
			s.state.CloseThere()
		}

	case *synReplyFrameV2:
		updateHeader(s.header, frame.Header)
		if frame.Flags.FIN() {
			s.state.CloseThere()
		}

	case *headersFrameV2:
		updateHeader(s.header, frame.Header)

	case *windowUpdateFrameV2:
		// Ignore.

	default:
		return errors.New(fmt.Sprintf("Received unknown frame of type %T.", frame))
	}

	return nil
}

// run is the main control path of
// the stream. It is prepared, the
// registered handler is called,
// and then the stream is cleaned
// up and closed.
func (s *serverStreamV2) Run() error {
	// Make sure Request is prepared.
	s.requestBody = new(bytes.Buffer)
	s.request.Body = &readCloser{s.requestBody}

	/***************
	 *** HANDLER ***
	 ***************/
	s.handler.ServeHTTP(s, s.request)

	// Close the stream with a SYN_REPLY if
	// none has been sent, or an empty DATA
	// frame, if a SYN_REPLY has been sent
	// already.
	// If the stream is already closed at
	// this end, then nothing happens.
	if !s.unidirectional {
		if s.state.OpenHere() && !s.wroteHeader {
			s.header.Set("status", "200")
			s.header.Set("version", "HTTP/1.1")

			// Create the response SYN_REPLY.
			synReply := new(synReplyFrameV2)
			synReply.Flags = FLAG_FIN
			synReply.StreamID = s.streamID
			synReply.Header = s.header

			s.output <- synReply
		} else if s.state.OpenHere() {
			// Create the DATA.
			data := new(dataFrameV2)
			data.StreamID = s.streamID
			data.Flags = FLAG_FIN
			data.Data = []byte{}

			s.output <- data
		}
	}

	// Clean up state.
	s.state.CloseHere()
	return nil
}

func (s *serverStreamV2) State() *StreamState {
	return s.state
}

func (s *serverStreamV2) StreamID() StreamID {
	return s.streamID
}

func (s *serverStreamV2) closed() bool {
	if s.conn == nil || s.state == nil || s.handler == nil {
		return true
	}
	select {
	case _ = <-s.stop:
		return true
	default:
		return false
	}
}

// writeHeader is used to flush HTTP headers.
func (s *serverStreamV2) writeHeader() {
	if len(s.header) == 0 || s.unidirectional {
		return
	}

	// Create the HEADERS frame.
	header := new(headersFrameV2)
	header.StreamID = s.streamID
	header.Header = cloneHeader(s.header)

	// Clear the headers that have been sent.
	for name := range header.Header {
		s.header.Del(name)
	}

	s.output <- header
}
