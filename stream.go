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
  certificates   [][]byte
  headers        *Headers
  settings       []*Setting
  credentials    []Certificate
  unidirectional bool
}
