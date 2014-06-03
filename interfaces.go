// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/SlyMarbo/spdy/spdyutils"
)

/**************
 * Interfaces *
 **************/

// Connection represents a SPDY connection. The connection should
// be started with a call to Run, which will return once the
// connection has been terminated. The connection can be ended
// early by using Close.
type Conn interface {
	http.CloseNotifier
	io.Closer
	Conn() net.Conn
	InitialWindowSize() (uint32, error)
	Ping() (<-chan Ping, error)
	Push(url string, origin Stream) (PushStream, error)
	Request(request *http.Request, receiver Receiver, priority Priority) (Stream, error)
	RequestResponse(request *http.Request, receiver Receiver, priority Priority) (*http.Response, error)
	Run() error
	SetFlowControl(FlowControl) error
	SetTimeout(time.Duration)
	SetReadTimeout(time.Duration)
	SetWriteTimeout(time.Duration)
}

// Stream contains a single SPDY stream.
type Stream interface {
	http.CloseNotifier
	http.ResponseWriter
	io.ReadCloser
	Conn() Conn
	ReceiveFrame(Frame) error
	Run() error
	State() *spdyutils.StreamState
	StreamID() StreamID
}

// PushStream contains a single SPDY push stream.
type PushStream interface {
	Stream

	// Fin is used to close the
	// push stream once writing
	// has finished.
	Finish()
}

// Frame represents a single SPDY frame.
type Frame interface {
	fmt.Stringer
	io.ReaderFrom
	io.WriterTo
	Compress(Compressor) error
	Decompress(Decompressor) error
	Name() string
}

// Compressor is used to compress the text header of a SPDY frame.
type Compressor interface {
	io.Closer
	Compress(http.Header) ([]byte, error)
}

// Decompressor is used to decompress the text header of a SPDY frame.
type Decompressor interface {
	Decompress([]byte) (http.Header, error)
}

// Objects implementing the Receiver interface can be
// registered to receive requests on the Client.
//
// ReceiveData is passed the original request, the data
// to receive and a bool indicating whether this is the
// final batch of data. If the bool is set to true, the
// data may be empty, but should not be nil.
//
// ReceiveHeaders is passed the request and any sent
// text headers. This may be called multiple times.
// Note that these headers may contain the status code
// of the response, under the ":status" header. If the
// Receiver is being used to proxy a request, and the
// headers presented to ReceiveHeader are copied to
// another ResponseWriter, take care to call its
// WriteHeader method after copying all headers, since
// this may flush headers received so far.
//
// ReceiveRequest is used when server pushes are sent.
// The returned bool should inticate whether to accept
// the push. The provided Request will be that sent by
// the server with the push.
type Receiver interface {
	ReceiveData(request *http.Request, data []byte, final bool)
	ReceiveHeader(request *http.Request, header http.Header)
	ReceiveRequest(request *http.Request) bool
}
