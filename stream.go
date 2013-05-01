package spdy

import (
  // "crypto/tls"
  //   "net"
  "sync"
)

type stream struct {
  sync.RWMutex
  conn           *connection
  streamID       uint32
  state          StreamState
  priority       uint8
  input          <-chan []byte
	output         chan<- Frame
  request        *Request
  certificates   []Certificate
  headers        Header
  settings       []*Setting
  unidirectional bool
	version        int
}

func (s *stream) run() {
	
}
