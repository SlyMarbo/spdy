package spdy

import (
	"errors"
	"fmt"
	"sync"
)

// requestStream is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type requestStream struct {
	sync.RWMutex
	conn         *clientConnection
	streamID     uint32
	flow         *flowControl
	state        *StreamState
	input        <-chan Frame
	output       chan<- Frame
	request      *Request
	receiver     Receiver
	headers      Header
	responseCode int
	stop         bool
	version      uint16
}

func (s *requestStream) Cancel() {
	s.Lock()
	s.stop = true
	rst := new(RstStreamFrame)
	rst.streamID = s.streamID
	rst.version = uint16(s.version)
	rst.StatusCode = RST_STREAM_CANCEL
	s.output <- rst
	s.Unlock()
}

func (s *requestStream) Connection() Connection {
	return s.conn
}

func (s *requestStream) Header() Header {
	return s.headers
}

func (s *requestStream) Ping() <-chan bool {
	return s.conn.Ping()
}

func (_ *requestStream) Push(_ string) (PushWriter, error) {
	panic("Error: Request stream cannot push.")
}

func (s *requestStream) Settings() []*Setting {
	out := make([]*Setting, 0, len(s.conn.receivedSettings))
	for _, val := range s.conn.receivedSettings {
		out = append(out, val)
	}
	return out
}

func (s *requestStream) State() *StreamState {
	return s.state
}

func (s *requestStream) Stop() {
	s.stop = true
}

func (s *requestStream) StreamID() uint32 {
	return s.streamID
}

// Write is one method with which request data is sent.
func (s *requestStream) Write(inputData []byte) (int, error) {
	if s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	// Check any frames received since last call.
	s.processInput()
	if s.stop {
		return 0, ErrCancelled
	}

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

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
func (_ *requestStream) WriteHeader(_ int) {
	panic("Error: Cannot write status code on request.")
}

// WriteHeaders is used to flush HTTP headers.
func (s *requestStream) WriteHeaders() {
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

func (s *requestStream) WriteSettings(settings ...*Setting) {
	if settings == nil {
		return
	}

	frame := new(SettingsFrame)
	frame.version = uint16(s.version)
	frame.Settings = settings
	s.output <- frame
}

func (s *requestStream) Version() uint16 {
	return uint16(s.version)
}

// receiveFrame is used to process an inbound frame.
func (s *requestStream) receiveFrame(frame Frame) {
	if frame == nil {
		panic("Nil frame received in receiveFrame.")
	}

	switch frame := frame.(type) {
	case *DataFrame:

		// Extract the data.
		data := frame.Data
		if data == nil {
			data = []byte{}
		}

		// Check whether this is the last frame.
		finish := frame.Flags&FLAG_FIN != 0

		// Give to the client.
		s.receiver.ReceiveData(s.request, data, finish)
		if !finish {
			s.flow.Receive(frame.Data)
		}

	case *SynReplyFrame:
		s.receiver.ReceiveHeaders(s.request, frame.Headers)

	case *HeadersFrame:
		s.receiver.ReceiveHeaders(s.request, frame.Headers)

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
func (s *requestStream) wait() {
	frame := <-s.input
	if frame == nil {
		return
	}
	s.receiveFrame(frame)
}

// processInput processes any frames currently
// queued in the input channel, but does not
// wait once the channel has been cleared, or
// if it is empty immediately.
func (s *requestStream) processInput() {
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
// the stream. Data is recieved,
// processed, and then the stream
// is cleaned up and closed.
func (s *requestStream) Run() {
	s.conn.done.Add(1)

	// Make sure Request is prepared.
	s.AddFlowControl()

	// Make sure any queued data has been sent.
	for s.flow.Paused() {
		s.wait()
		s.flow.Flush()
	}

	// Receive and process inbound frames.
	for frame := range s.input {
		s.receiveFrame(frame)
	}

	// Clean up state.
	s.state.CloseHere()
	s.conn.done.Done()
}
