// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// pushStreamV2 is a structure that implements the
// Stream and PushWriter interfaces. this is used
// for performing server pushes.
type pushStreamV2 struct {
	sync.Mutex
	conn     Conn
	streamID StreamID
	origin   Stream
	state    *StreamState
	output   chan<- Frame
	header   http.Header
	stop     <-chan struct{}
}

/***********************
 * http.ResponseWriter *
 ***********************/

func (p *pushStreamV2) Header() http.Header {
	return p.header
}

// Write is used for sending data in the push.
func (p *pushStreamV2) Write(inputData []byte) (int, error) {
	if p.closed() || p.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	state := p.origin.State()
	if p.origin == nil || state.ClosedHere() {
		return 0, errors.New("Error: Origin stream is closed.")
	}

	p.writeHeader()

	// Copy the data locally to avoid any pointer issues.
	data := make([]byte, len(inputData))
	copy(data, inputData)

	// Chunk the response if necessary.
	written := 0
	for len(data) > MAX_DATA_SIZE {
		dataFrame := new(dataFrameV2)
		dataFrame.StreamID = p.streamID
		dataFrame.Data = data[:MAX_DATA_SIZE]
		p.output <- dataFrame

		written += MAX_DATA_SIZE
	}

	n := len(data)
	if n == 0 {
		return written, nil
	}

	dataFrame := new(dataFrameV2)
	dataFrame.StreamID = p.streamID
	dataFrame.Data = data
	p.output <- dataFrame

	return written + n, nil
}

// WriteHeader is provided to satisfy the Stream
// interface, but has no effect.
// TODO: add handling for certain status codes like 304.
func (p *pushStreamV2) WriteHeader(int) {
	p.writeHeader()
	return
}

/*****************
 * io.ReadCloser *
 *****************/

func (p *pushStreamV2) Close() error {
	p.Lock()
	defer p.Unlock()
	p.writeHeader()
	if p.state != nil {
		p.state.Close()
	}
	p.origin = nil
	p.output = nil
	p.header = nil
	p.stop = nil
	return nil
}

func (p *pushStreamV2) Read(out []byte) (int, error) {
	return 0, io.EOF
}

/**********
 * Stream *
 **********/

func (p *pushStreamV2) Conn() Conn {
	return p.conn
}

func (p *pushStreamV2) ReceiveFrame(frame Frame) error {
	p.Lock()
	defer p.Unlock()

	if frame == nil {
		return errors.New("Error: Nil frame received.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *windowUpdateFrameV2:
		// Ignore.

	default:
		return errors.New(fmt.Sprintf("Received unexpected frame of type %T.", frame))
	}

	return nil
}

func (p *pushStreamV2) Run() error {
	return nil
}

func (p *pushStreamV2) State() *StreamState {
	return p.state
}

func (p *pushStreamV2) StreamID() StreamID {
	return p.streamID
}

func (p *pushStreamV2) closed() bool {
	if p.conn == nil || p.state == nil {
		return true
	}
	select {
	case _ = <-p.stop:
		return true
	default:
		return false
	}
}

// writeHeader is used to send HTTP headers to
// the client.
func (p *pushStreamV2) writeHeader() {
	if len(p.header) == 0 || p.closed() {
		return
	}

	header := new(headersFrameV2)
	header.StreamID = p.streamID
	header.Header = cloneHeader(p.header)
	for name := range header.Header {
		p.header.Del(name)
	}
	p.output <- header
}
