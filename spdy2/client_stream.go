// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy2

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/SlyMarbo/spdy/common"
	"github.com/SlyMarbo/spdy/spdy2/frames"
)

// ClientStream is a structure that implements
// the Stream and ResponseWriter interfaces. This
// is used for responding to client requests.
type ClientStream struct {
	sync.Mutex
	recvMutex    sync.Mutex
	shutdownOnce sync.Once
	conn         common.Conn
	streamID     common.StreamID
	state        *common.StreamState
	output       chan<- common.Frame
	request      *http.Request
	receiver     common.Receiver
	header       http.Header
	headerChan   chan func()
	responseCode int
	stop         <-chan bool
	finished     chan struct{}
}

/***********************
 * http.ResponseWriter *
 ***********************/

func (s *ClientStream) Header() http.Header {
	return s.header
}

// Write is one method with which request data is sent.
func (s *ClientStream) Write(inputData []byte) (int, error) {
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
	for len(data) > common.MAX_DATA_SIZE {
		dataFrame := new(frames.DataFrame)
		dataFrame.StreamID = s.streamID
		dataFrame.Data = data[:common.MAX_DATA_SIZE]
		s.output <- dataFrame

		written += common.MAX_DATA_SIZE
	}

	n := len(data)
	if n == 0 {
		return written, nil
	}

	dataFrame := new(frames.DataFrame)
	dataFrame.StreamID = s.streamID
	dataFrame.Data = data
	s.output <- dataFrame

	return written + n, nil
}

// WriteHeader is used to set the HTTP status code.
func (s *ClientStream) WriteHeader(int) {
	s.writeHeader()
}

/*****************
 * io.ReadCloser *
 *****************/

// Close is used to cancel a mid-air
// request.
func (s *ClientStream) Close() error {
	s.shutdownOnce.Do(s.shutdown)
	return nil
}

func (s *ClientStream) shutdown() {
	s.writeHeader()
	if s.state != nil {
		if s.state.OpenThere() {
			// Send the RST_STREAM.
			rst := new(frames.RstStreamFrame)
			rst.StreamID = s.streamID
			rst.Status = common.RST_STREAM_CANCEL
			s.output <- rst
		}
		s.state.Close()
	}
	select {
	case <-s.finished:
	default:
		close(s.finished)
	}
	select {
	case <-s.headerChan:
	default:
		close(s.headerChan)
	}
	s.output = nil
	s.request = nil
	s.receiver = nil
	s.header = nil
	s.stop = nil
}

func (s *ClientStream) Read(out []byte) (int, error) {
	log.Println("ClientStream.Read() is unimplemented. " +
		"To get the response from a client directly (and not via the Response), " +
		"provide a Receiver to clientConn.Request().")
	return 0, nil
}

/**********
 * Stream *
 **********/

func (s *ClientStream) Conn() common.Conn {
	return s.conn
}

func (s *ClientStream) ReceiveFrame(frame common.Frame) error {
	s.recvMutex.Lock()
	defer s.recvMutex.Unlock()

	if frame == nil {
		return errors.New("Nil frame received.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *frames.DataFrame:

		// Extract the data.
		data := frame.Data
		if data == nil {
			data = []byte{}
		}

		// Give to the client.
		s.headerChan <- func() {
			s.receiver.ReceiveData(s.request, data, frame.Flags.FIN())

			if frame.Flags.FIN() {
				s.state.CloseThere()
				close(s.finished)
			}
		}

	case *frames.SynReplyFrame:
		s.headerChan <- func() {
			s.receiver.ReceiveHeader(s.request, frame.Header)

			if frame.Flags.FIN() {
				s.state.CloseThere()
				close(s.finished)
			}
		}

	case *frames.HeadersFrame:
		s.headerChan <- func() {
			s.receiver.ReceiveHeader(s.request, frame.Header)

			if frame.Flags.FIN() {
				s.state.CloseThere()
				close(s.finished)
			}
		}

	case *frames.WindowUpdateFrame:
		// Ignore.

	default:
		return errors.New(fmt.Sprintf("Received unknown frame of type %T.", frame))
	}

	return nil
}

func (s *ClientStream) CloseNotify() <-chan bool {
	return s.stop
}

// run is the main control path of
// the stream. Data is recieved,
// processed, and then the stream
// is cleaned up and closed.
func (s *ClientStream) Run() error {
	// Receive and process inbound frames.
	<-s.finished

	// Clean up state.
	s.state.CloseHere()
	return nil
}

func (s *ClientStream) State() *common.StreamState {
	return s.state
}

func (s *ClientStream) StreamID() common.StreamID {
	return s.streamID
}

func (s *ClientStream) closed() bool {
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
func (s *ClientStream) writeHeader() {
	if len(s.header) == 0 {
		return
	}

	// Create the HEADERS frame.
	header := new(frames.HeadersFrame)
	header.StreamID = s.streamID
	header.Header = common.CloneHeader(s.header)

	// Clear the headers that have been sent.
	for name := range header.Header {
		s.header.Del(name)
	}

	s.output <- header
}

func (s *ClientStream) processFrames() {
	for f := range s.headerChan {
		f()
	}
}
