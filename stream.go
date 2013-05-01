package spdy

import (
// "crypto/tls"
//   "net"
//   "sync"
)

type stream struct {
  conn           *connection
  streamID       uint32
  state          StreamState
  priority       uint8
	request        *Request
  certificates   []Certificate
  headers        *Headers
  settings       []*Setting
  unidirectional bool
}

func newStream(frame *SynStreamFrame) *stream {
	newStream := new(stream)
	newStream.conn = conn
	newStream.streamID = frame.StreamID
	newStream.state = STATE_OPEN
	newStream.priority = frame.Priority
	newStream.request = new(Request)
	newStream.certificates = make([]Certificate, 1)
	newStream.headers = frame.Headers
	newStream.settings = make([]*Setting, 1)
	newStream.unidirectional = frame.Flags & FLAG_UNIDIRECTIONAL != 0
	
	return newStream
}

func (s *stream) run() {
	
}
