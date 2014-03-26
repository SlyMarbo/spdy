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

// clientStreamV2 is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type clientStreamV2 struct {
	sync.Mutex
	recvMutex    sync.Mutex
	conn         Conn
	streamID     StreamID
	state        *StreamState
	output       chan<- Frame
	request      *http.Request
	receiver     Receiver
	header       http.Header
	responseCode int
	stop         <-chan bool
	finished     chan struct{}
}

/***********************
 * http.ResponseWriter *
 ***********************/

func (s *clientStreamV2) Header() http.Header {
	return s.header
}

// Write is one method with which request data is sent.
func (s *clientStreamV2) Write(inputData []byte) (int, error) {
	if s.closed() || s.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

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
func (s *clientStreamV2) WriteHeader(int) {
	s.writeHeader()
}

/*****************
 * io.ReadCloser *
 *****************/

// Close is used to cancel a mid-air
// request.
func (s *clientStreamV2) Close() error {
	s.Lock()
	defer s.Unlock()
	s.writeHeader()
	if s.state != nil {
		if s.state.OpenThere() {
			// Send the RST_STREAM.
			rst := new(rstStreamFrameV2)
			rst.StreamID = s.streamID
			rst.Status = RST_STREAM_CANCEL
			s.output <- rst
		}
		s.state.Close()
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

func (s *clientStreamV2) Read(out []byte) (int, error) {
	log.Println("clientStream.Read() is unimplemented. " +
		"To get the response from a client directly (and not via the Response), " +
		"provide a Receiver to clientConn.Request().")
	return 0, nil
}

/**********
 * Stream *
 **********/

func (s *clientStreamV2) Conn() Conn {
	return s.conn
}

func (s *clientStreamV2) ReceiveFrame(frame Frame) error {
	s.recvMutex.Lock()
	defer s.recvMutex.Unlock()

	if frame == nil {
		return errors.New("Nil frame received.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *dataFrameV2:

		// Extract the data.
		data := frame.Data
		if data == nil {
			data = []byte{}
		}

		// Give to the client.
		s.receiver.ReceiveData(s.request, data, frame.Flags.FIN())

		if frame.Flags.FIN() {
			s.state.CloseThere()
			close(s.finished)
		}

	case *synReplyFrameV2:
		s.receiver.ReceiveHeader(s.request, frame.Header)

		if frame.Flags.FIN() {
			s.state.CloseThere()
			close(s.finished)
		}

	case *headersFrameV2:
		s.receiver.ReceiveHeader(s.request, frame.Header)

	case *windowUpdateFrameV2:
		// Ignore.

	default:
		return errors.New(fmt.Sprintf("Received unknown frame of type %T.", frame))
	}

	return nil
}

func (s *clientStreamV2) CloseNotify() <-chan bool {
	return s.stop
}

// run is the main control path of
// the stream. Data is recieved,
// processed, and then the stream
// is cleaned up and closed.
func (s *clientStreamV2) Run() error {
	// Receive and process inbound frames.
	<-s.finished

	// Clean up state.
	s.state.CloseHere()
	return nil
}

func (s *clientStreamV2) State() *StreamState {
	return s.state
}

func (s *clientStreamV2) StreamID() StreamID {
	return s.streamID
}

func (s *clientStreamV2) closed() bool {
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
func (s *clientStreamV2) writeHeader() {
	if len(s.header) == 0 {
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
