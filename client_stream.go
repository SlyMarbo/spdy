package spdy

import (
	"errors"
	"fmt"
	"sync"
)

// clientStream is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type clientStream struct {
	sync.RWMutex
	conn         *clientConnection
	streamID     uint32
	flow         *flowControl
	state        *StreamState
	output       chan<- Frame
	request      *Request
	receiver     Receiver
	headers      Header
	responseCode int
	stop         bool
	version      uint16
	done         chan struct{}
}

// Cancel is used to cancel a mid-air
// request.
func (s *clientStream) Cancel() {
	s.Lock()
	s.Stop()
	if s.state.OpenHere() {
		rst := new(RstStreamFrame)
		rst.streamID = s.streamID
		rst.version = uint16(s.version)
		rst.StatusCode = RST_STREAM_CANCEL
		s.output <- rst
	}
	s.state.CloseHere()
	s.Unlock()
}

func (s *clientStream) Connection() Connection {
	return s.conn
}

func (s *clientStream) Header() Header {
	return s.headers
}

func (s *clientStream) Ping() <-chan bool {
	return s.conn.Ping()
}

func (s *clientStream) Push(string) (PushWriter, error) {
	panic("Error: Request stream cannot push.")
}

func (s *clientStream) ReceiveFrame(frame Frame) {
	s.Lock()
	s.receiveFrame(frame)
	s.Unlock()
}

func (s *clientStream) Settings() []*Setting {
	out := make([]*Setting, 0, len(s.conn.receivedSettings))
	for _, val := range s.conn.receivedSettings {
		out = append(out, val)
	}
	return out
}

func (s *clientStream) State() *StreamState {
	return s.state
}

func (s *clientStream) Stop() {
	s.stop = true
	s.done <- struct{}{}
}

func (s *clientStream) StreamID() uint32 {
	return s.streamID
}

// Write is one method with which request data is sent.
func (s *clientStream) Write(inputData []byte) (int, error) {
	if s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

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
func (s *clientStream) WriteHeader(int) {
	panic("Error: Cannot write status code on request.")
}

// WriteHeaders is used to flush HTTP headers.
func (s *clientStream) WriteHeaders() {
	if len(s.headers) == 0 {
		return
	}

	// Create the HEADERS frame.
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

func (s *clientStream) WriteSettings(settings ...*Setting) {
	if settings == nil {
		return
	}

	// Create the SETTINGS frame.
	frame := new(SettingsFrame)
	frame.version = uint16(s.version)
	frame.Settings = settings
	s.output <- frame
}

func (s *clientStream) Version() uint16 {
	return uint16(s.version)
}

// receiveFrame is used to process an inbound frame.
func (s *clientStream) receiveFrame(frame Frame) {
	if frame == nil {
		panic("Nil frame received in receiveFrame.")
	}

	// Process the frame depending on its type.
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

// Wait blocks until a frame is received
// or the input channel is closed. If a
// frame is received, it is processed.
func (s *clientStream) Wait() {
	<-s.done
}

// run is the main control path of
// the stream. Data is recieved,
// processed, and then the stream
// is cleaned up and closed.
func (s *clientStream) Run() {
	s.conn.done.Add(1)

	// Make sure Request is prepared.
	s.AddFlowControl()

	// Receive and process inbound frames.
	s.Wait()

	// Make sure any queued data has been sent.
	if s.flow.Paused() {
		log.Printf("Error: Stream %d has been closed with data still buffered.\n", s.streamID)
	}

	// Clean up state.
	s.state.CloseHere()
	s.conn.done.Done()
}
