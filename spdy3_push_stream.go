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

// pushStreamV3 is a structure that implements the
// Stream and PushWriter interfaces. this is used
// for performing server pushes.
type pushStreamV3 struct {
	sync.Mutex
	conn     Conn
	streamID StreamID
	flow     *flowControl
	origin   Stream
	state    *StreamState
	output   chan<- Frame
	header   http.Header
	stop     <-chan struct{}
}

/***********************
 * http.ResponseWriter *
 ***********************/

func (p *pushStreamV3) Header() http.Header {
	return p.header
}

// Write is used for sending data in the push.
func (p *pushStreamV3) Write(inputData []byte) (int, error) {
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
	// Data is sent to the flow control to
	// ensure that the protocol is followed.
	written := 0
	for len(data) > MAX_DATA_SIZE {
		n, err := p.flow.Write(data[:MAX_DATA_SIZE])
		if err != nil {
			return written, err
		}
		written += n
		data = data[MAX_DATA_SIZE:]
	}

	n, err := p.flow.Write(data)
	written += n

	return written, err
}

// WriteHeader is provided to satisfy the Stream
// interface, but has no effect.
func (p *pushStreamV3) WriteHeader(int) {
	p.writeHeader()
	return
}

/*****************
 * io.ReadCloser *
 *****************/

func (p *pushStreamV3) Close() error {
	p.Lock()
	defer p.Unlock()
	p.writeHeader()
	if p.state != nil {
		p.state.Close()
	}
	if p.flow != nil {
		p.flow.Close()
	}
	p.origin = nil
	p.output = nil
	p.header = nil
	p.stop = nil
	return nil
}

func (p *pushStreamV3) Read(out []byte) (int, error) {
	return 0, io.EOF
}

/**********
 * Stream *
 **********/

func (p *pushStreamV3) Conn() Conn {
	return p.conn
}

func (p *pushStreamV3) ReceiveFrame(frame Frame) error {
	p.Lock()
	defer p.Unlock()

	if frame == nil {
		return errors.New("Error: Nil frame received.")
	}

	// Process the frame depending on its type.
	switch frame := frame.(type) {
	case *windowUpdateFrameV3:
		err := p.flow.UpdateWindow(frame.DeltaWindowSize)
		if err != nil {
			reply := new(rstStreamFrameV3)
			reply.StreamID = p.streamID
			reply.Status = RST_STREAM_FLOW_CONTROL_ERROR
			p.output <- reply
			return err
		}

	default:
		return errors.New(fmt.Sprintf("Received unexpected frame of type %T.", frame))
	}

	return nil
}

func (p *pushStreamV3) Run() error {
	return nil
}

func (p *pushStreamV3) State() *StreamState {
	return p.state
}

func (p *pushStreamV3) StreamID() StreamID {
	return p.streamID
}

/**************
 * PushStream *
 **************/

func (p *pushStreamV3) Finish() {
	p.writeHeader()
	end := new(dataFrameV3)
	end.Data = []byte{}
	end.Flags = FLAG_FIN
	p.output <- end
}

/**********
 * Others *
 **********/

func (p *pushStreamV3) closed() bool {
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
func (p *pushStreamV3) writeHeader() {
	if len(p.header) == 0 || p.closed() {
		return
	}

	header := new(headersFrameV3)
	header.StreamID = p.streamID
	header.Header = make(http.Header)

	for name, values := range p.header {
		for _, value := range values {
			header.Header.Add(name, value)
		}
		p.header.Del(name)
	}

	if len(header.Header) == 0 {
		return
	}

	p.output <- header
}
