package spdy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
)

func NewServerConn(conn net.Conn, server *http.Server, version uint16) (spdyConn Conn, err error) {
	if conn == nil {
		return nil, errors.New("Error: Connection initialised with nil net.conn.")
	}
	if server == nil {
		return nil, errors.New("Error: Connection initialised with nil server.")
	}

	switch version {
	case 3:
		out := new(connV3)
		out.remoteAddr = conn.RemoteAddr().String()
		out.server = server
		out.client = nil
		out.conn = conn
		out.buf = bufio.NewReader(conn)
		if tlsConn, ok := conn.(*tls.Conn); ok {
			out.tlsState = new(tls.ConnectionState)
			*out.tlsState = tlsConn.ConnectionState()
		}
		out.streams = make(map[StreamID]Stream)
		out.output = [8]chan Frame{}
		out.output[0] = make(chan Frame)
		out.output[1] = make(chan Frame)
		out.output[2] = make(chan Frame)
		out.output[3] = make(chan Frame)
		out.output[4] = make(chan Frame)
		out.output[5] = make(chan Frame)
		out.output[6] = make(chan Frame)
		out.output[7] = make(chan Frame)
		out.pings = make(map[uint32]chan<- Ping)
		out.nextPingID = 2
		out.compressor = NewCompressor(3)
		out.decompressor = NewDecompressor(3)
		out.receivedSettings = make(Settings)
		out.lastPushStreamID = 0
		out.lastRequestStreamID = 0
		out.oddity = 0
		out.initialWindowSize = DEFAULT_INITIAL_WINDOW_SIZE
		out.requestStreamLimit = newStreamLimit(DEFAULT_STREAM_LIMIT)
		out.pushStreamLimit = newStreamLimit(NO_STREAM_LIMIT)
		out.vectorIndex = 8
		out.certificates = make(map[uint16][]*x509.Certificate, 8)
		if out.tlsState != nil && out.tlsState.PeerCertificates != nil {
			out.certificates[1] = out.tlsState.PeerCertificates
		}
		out.stop = make(chan struct{})
		out.init = func() {
			// Initialise the connection by sending the connection settings.
			settings := new(settingsFrameV3)
			settings.Flags = FLAG_SETTINGS_PERSIST_VALUE
			settings.Settings = defaultSPDYServerSettings(3, DEFAULT_STREAM_LIMIT)
			out.output[0] <- settings
		}

		return out, nil

	default:
		return nil, errors.New("Error: Unrecognised SPDY version.")
	}
}
