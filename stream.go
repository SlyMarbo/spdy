package spdy

import (
  // "crypto/tls"
  //   "net"
  "log"
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
  handler        *ServeMux
  certificates   []Certificate
  headers        Header
  settings       []*Setting
  unidirectional bool
  version        int
}

func (s *stream) Header() Header {
  return s.headers
}

func (s *stream) Ping() <-chan bool {
  return make(chan bool)
}

func (s *stream) Push() (PushWriter, error) {
  return nil, nil
}

func (s *stream) Write(data []byte) (int, error) {
  log.Println("Wrote data", data)
  return len(data), nil
}

func (s *stream) WriteHeader(code int) {
  log.Println("Wrote code", code)
}

func (s *stream) run() {
  s.handler.ServeSPDY(s, s.request)
}
