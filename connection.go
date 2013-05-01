package spdy

import (
  "crypto/tls"
	"log"
	"net/http"
	"runtime"
  "sync"
	"time"
)

type connection struct {
	sync.Mutex
  remoteAddr         string // network address of remote side
	server             *http.Server
  conn               *tls.Conn
  tlsState           *tls.ConnectionState
	tlsConfig          *tls.Config
  streams            map[uint32]*stream
  buffer             []Frame
  queue              []Frame
  nextServerStreamID uint32 // even
  nextClientStreamID uint32 // odd
  goaway             bool
	version            int
}

func (conn *connection) readRequests() {
	if d := conn.server.ReadTimeout; d != 0 {
		conn.conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := conn.server.WriteTimeout; d != 0 {
		defer func() {
			conn.conn.SetWriteDeadline(time.Now().Add(d))
		}()
	}
	
	
}

func (conn *connection) serve() {
	defer func() {
		if err := recover(); err != nil {
			const size = 4096
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("spdy: panic serving %v: %v\n%s", conn.remoteAddr, err, buf)
		}
	}()
	
	conn.readRequests()
}

func acceptSPDYVersion2(server *http.Server, tlsConn *tls.Conn, _ http.Handler) {
	conn := new(connection)
	conn.remoteAddr = tlsConn.RemoteAddr().String()
	conn.conn = tlsConn
	conn.server = server
	*conn.tlsState = tlsConn.ConnectionState()
	conn.tlsConfig = server.TLSConfig
	conn.streams = make(map[uint32]*stream)
	conn.buffer = make([]Frame, 0, 10)
	conn.queue = make([]Frame, 0, 10)
	conn.version = 2
	
	conn.serve()
}

func acceptSPDYVersion3(server *http.Server, tlsConn *tls.Conn, _ http.Handler) {
	conn := new(connection)
	conn.remoteAddr = tlsConn.RemoteAddr().String()
	conn.conn = tlsConn
	conn.server = server
	*conn.tlsState = tlsConn.ConnectionState()
	conn.tlsConfig = server.TLSConfig
	conn.streams = make(map[uint32]*stream)
	conn.buffer = make([]Frame, 0, 10)
	conn.queue = make([]Frame, 0, 10)
	conn.version = 3
	
	conn.serve()
}
