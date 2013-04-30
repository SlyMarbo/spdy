package spdy

import (
  "crypto/tls"
  "net"
  "sync"
)

type connection struct {
  remoteAddr         string // network address of remote side
  conn               net.Conn
  tlsState           *tls.ConnectionState
  mutex              sync.Mutex
  streams            map[uint32]*stream
  buffer             [][]byte
  queue              [][]byte
  nextServerStreamID uint32 // even
  nextClientStreamID uint32 // odd
  goaway             bool
}

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
