// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// clientStreamV3 is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type clientStreamV3 struct {
	sync.Mutex
	recvMutex    sync.Mutex
	conn         Conn
	streamID     StreamID
	flow         *flowControl
	state        *StreamState
	output       chan<- Frame
	request      *http.Request
	receiver     Receiver
	header       http.Header
	responseCode int
	stop         <-chan struct{}
	finished     chan struct{}
}

/***********************
 * http.ResponseWriter *
 ***********************/

func (s *clientStreamV3) Header() http.Header {
	return s.header
}

// Write is one method with which request data is sent.
func (s *clientStreamV3) Write(inputData []byte) (int, error) {
	if s.closed() || s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

	// Send any new headers.
	s.writeHeader()

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

	if len(data) > 0 {
		n, err := s.flow.Write(data)
		written += n
		if err != nil {
			return written, err
		}
	}

	return written, nil
}

// WriteHeader is used to set the HTTP status code.
func (s *clientStreamV3) WriteHeader(int) {
	s.writeHeader()
}

/*****************
 * io.ReadCloser *
 *****************/

// Close is used to stop the stream safely.
func (s *clientStreamV3) Close() error {
	s.Lock()
	defer s.Unlock()
	s.writeHeader()
	if s.state != nil {
		if s.state.OpenThere() {
			// Send the RST_STREAM.
			rst := new(rstStreamFrameV3)
			rst.StreamID = s.streamID
			rst.Status = RST_STREAM_CANCEL
			s.output <- rst
		}
		s.state.Close()
	}
	if s.flow != nil {
		s.flow.Close()
	}
	select {
	case <-s.finished:
	default:
		close(s.finished)
	}
	s.output = nil
	s.request = nil
	s.receiver = nil
	s.header = nil
	s.stop = nil
	return nil
}

func (s *clientStreamV3) Read(out []byte) (int, error) {
	// TODO
	return 0, nil
}

/**********
 * Stream *
 **********/

func (s *clientStreamV3) Conn() Conn {
	return s.conn
}

func (s *clientStreamV3) ReceiveFrame(frame Frame) error {
	s.recvMutex.Lock()
	defer s.recvMutex.Unlock()

	if frame == nil {
		return errors.New("Nil frame received.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *dataFrameV3:

		// Extract the data.
		data := frame.Data
		if data == nil {
			data = []byte{}
		}

		// Give to the client.
		s.receiver.ReceiveData(s.request, data, frame.Flags.FIN())
		s.flow.Receive(frame.Data)

		if frame.Flags.FIN() {
			s.state.CloseThere()
			close(s.finished)
		}

	case *synReplyFrameV3:
		s.receiver.ReceiveHeader(s.request, frame.Header)

		if frame.Flags.FIN() {
			s.state.CloseThere()
			close(s.finished)
		}

	case *headersFrameV3:
		s.receiver.ReceiveHeader(s.request, frame.Header)

		if frame.Flags.FIN() {
			s.state.CloseThere()
			close(s.finished)
		}

	case *windowUpdateFrameV3:
		err := s.flow.UpdateWindow(frame.DeltaWindowSize)
		if err != nil {
			reply := new(rstStreamFrameV3)
			reply.StreamID = s.streamID
			reply.Status = RST_STREAM_FLOW_CONTROL_ERROR
			s.output <- reply
		}

	default:
		return errors.New(fmt.Sprintf("Received unknown frame of type %T.", frame))
	}

	return nil
}

// run is the main control path of
// the stream. Data is recieved,
// processed, and then the stream
// is cleaned up and closed.
func (s *clientStreamV3) Run() error {
	// Make sure Request is prepared.
	s.AddFlowControl()

	// Receive and process inbound frames.
	<-s.finished

	// Make sure any queued data has been sent.
	if s.flow.Paused() {
		return errors.New(fmt.Sprintf("Error: Stream %d has been closed with data still buffered.\n", s.streamID))
	}

	// Clean up state.
	s.state.CloseHere()
	return nil
}

func (s *clientStreamV3) State() *StreamState {
	return s.state
}

func (s *clientStreamV3) StreamID() StreamID {
	return s.streamID
}

func (s *clientStreamV3) closed() bool {
	if s.conn == nil || s.state == nil || s.receiver == nil {
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
func (s *clientStreamV3) writeHeader() {
	if len(s.header) == 0 {
		return
	}

	// Create the HEADERS frame.
	header := new(headersFrameV3)
	header.StreamID = s.streamID
	header.Header = cloneHeader(s.header)

	// Clear the headers that have been sent.
	for name := range header.Header {
		s.header.Del(name)
	}

	s.output <- header
}
