package spdy

import (
	"errors"
)

type pushStream struct {
	conn        *serverConnection
	streamID    uint32
	flow        *flowControl
	origin      Stream
	state       *StreamState
	output      chan<- Frame
	headers     Header
	headersSent bool
	stop        bool
	version     int
}

func (p *pushStream) Connection() Connection {
	return p.conn
}

func (p *pushStream) Close() {
	p.stop = true

	stop := new(DataFrame)
	stop.StreamID = p.streamID
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

func (p *pushStream) StreamID() uint32 {
	return p.streamID
}

func (p *pushStream) Write(inputData []byte) (int, error) {
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

	// Dereference the pointer.
	data := make([]byte, len(inputData))
	copy(data, inputData)

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

func (p *pushStream) WriteHeader(_ int) {
	p.WriteHeaders()
	return
}

func (p *pushStream) WriteHeaders() {
	if len(p.headers) == 0 {
		return
	}

	headers := new(HeadersFrame)
	headers.version = uint16(p.version)
	headers.StreamID = p.streamID
	headers.Headers = p.headers.clone()
	for name := range headers.Headers {
		p.headers.Del(name)
	}
	p.output <- headers
}

func (p *pushStream) Version() uint16 {
	return uint16(p.version)
}
