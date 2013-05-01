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
  input          <-chan []byte
  request        *Request
  certificates   []Certificate
  headers        *Headers
  settings       []*Setting
  unidirectional bool
}

func (s *stream) run() {

}
