package spdy

import (
	"errors"
	"log"
	"sync"
)

// pushStream is a structure that implements the
// Stream and PushWriter interfaces. this is used
// for performing server pushes.
type pushStream struct {
	sync.RWMutex
	conn        *serverConnection
	streamID    uint32
	flow        *flowControl
	origin      Stream
	state       *StreamState
	output      chan<- Frame
	headers     Header
	headersSent bool
	stop        bool
	cancelled   bool
	version     uint16
}

func (p *pushStream) Cancel() {
	p.Lock()
	p.cancelled = true
	rst := new(RstStreamFrame)
	rst.streamID = p.streamID
	rst.version = p.version
	rst.StatusCode = RST_STREAM_CANCEL
	p.output <- rst
	p.Unlock()
}

func (p *pushStream) Connection() Connection {
	return p.conn
}

// Close is used to complete a server push. This
// closes the underlying stream and signals to
// the recipient that the push is complete. The
// equivalent action in a ResponseWriter is to
// return from the handler. Any calls to Write
// after calling Close will have no effect.
func (p *pushStream) Close() {
	p.stop = true

	stop := new(DataFrame)
	stop.streamID = p.streamID
	stop.Flags = FLAG_FIN
	stop.Data = []byte{}

	p.output <- stop

	p.state.CloseHere()
}

func (p *pushStream) Header() Header {
	return p.headers
}

func (p *pushStream) State() *StreamState {
	return p.state
}

func (p *pushStream) Stop() {
	p.stop = true
}

func (p *pushStream) StreamID() uint32 {
	return p.streamID
}

// Write is used for sending data in the push.
func (p *pushStream) Write(inputData []byte) (int, error) {
	if p.cancelled {
		return 0, errors.New("Error: Client sent GOAWAY without processing server push.")
	}

	if p.state.ClosedHere() {
		return 0, errors.New("Error: Stream already closed.")
	}

	state := p.origin.State()
	if p.origin == nil || state.ClosedHere() {
		return 0, errors.New("Error: Origin stream is closed.")
	}

	if p.stop {
		return 0, ErrCancelled
	}

	p.WriteHeaders()

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
func (p *pushStream) WriteHeader(int) {
	log.Println("Warning: PushWriter.WriteHeader has no effect.")
	p.WriteHeaders()
	return
}

// WriteHeaders is used to send HTTP headers to
// the client.
func (p *pushStream) WriteHeaders() {
	if len(p.headers) == 0 {
		return
	}

	headers := new(HeadersFrame)
	headers.version = p.version
	headers.streamID = p.streamID
	headers.Headers = p.headers.clone()
	for name := range headers.Headers {
		p.headers.Del(name)
	}
	p.output <- headers
}

func (p *pushStream) Version() uint16 {
	return p.version
}

func (p *pushStream) Run() {
	panic("Error: Push cannot run.")
}
