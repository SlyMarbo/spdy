package spdy

import (
  // "crypto/tls"
//   "net"
//   "sync"
)

type stream struct {
  conn         *connection
  streamID     uint32
  state        StreamState
  priority     uint8
  certificates [][]byte
  headers      *Headers
  settings     []*Setting
  credentials  []Certificate
}

type StreamState uint8

const (
  CLOSED StreamState = iota
  HALF_CLOSED_HERE
  HALF_CLOSED_THERE
  OPEN
)

const MAX_PRIORITY = 7
