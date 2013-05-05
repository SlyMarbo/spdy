package spdy

import (
  "bufio"
  "crypto/tls"
  "fmt"
  "log"
  "net/http"
  "net/url"
  "runtime"
  "sync"
  "time"
)

type connection struct {
  sync.RWMutex
  remoteAddr          string // network address of remote side
  server              *Server
  conn                *tls.Conn
  buf                 *bufio.Reader
  tlsState            *tls.ConnectionState
  tlsConfig           *tls.Config
  streams             map[uint32]*stream
  streamInputs        map[uint32]chan<- []byte
  streamOutputs       [8]chan Frame
  compressor          *Compressor
  decompressor        *Decompressor
  receivedSettings    []*Setting
  nextServerStreamID  uint32 // even
  nextClientStreamID  uint32 // odd
  goaway              bool
  version             int
  numInvalidStreamIDs int
}

func (conn *connection) send() {
  for {
    frame := conn.selectFrameToSend()
    err := frame.WriteHeaders(conn.compressor)
    if err != nil {
      panic(err)
    }
    err = frame.WriteTo(conn.conn)
    if err != nil {
      panic(err)
    }
  }
}

func (conn *connection) selectFrameToSend() (frame Frame) {
  // Try in priority order first.
  for i := 0; i < 8; i++ {
    select {
    case frame = <-conn.streamOutputs[i]:
      return frame
    default:
    }
  }

  // Wait for any frame.
  select {
  case frame = <-conn.streamOutputs[0]:
    return frame
  case frame = <-conn.streamOutputs[1]:
    return frame
  case frame = <-conn.streamOutputs[2]:
    return frame
  case frame = <-conn.streamOutputs[3]:
    return frame
  case frame = <-conn.streamOutputs[4]:
    return frame
  case frame = <-conn.streamOutputs[5]:
    return frame
  case frame = <-conn.streamOutputs[6]:
    return frame
  case frame = <-conn.streamOutputs[7]:
    return frame
  }

  panic("Unreachable")
}

func (conn *connection) newStream(frame *SynStreamFrame, input <-chan []byte,
  output chan<- Frame) *stream {

  stream := new(stream)
  stream.conn = conn
  stream.streamID = frame.StreamID
  stream.state = STATE_OPEN
  if frame.Flags&FLAG_FIN != 0 {
    stream.state = STATE_HALF_CLOSED_THERE
  }
  stream.priority = frame.Priority
  stream.input = input
  stream.output = output
  stream.handler = DefaultServeMux
  stream.certificates = make([]Certificate, 1)
  stream.headers = make(Header)
  stream.settings = make([]*Setting, 1)
  stream.unidirectional = frame.Flags&FLAG_UNIDIRECTIONAL != 0
  stream.version = conn.version
  stream.contentLength = -1

  headers := frame.Headers
  rawUrl := headers.Get(":scheme") + "://" + headers.Get(":host") + headers.Get(":path")
  url, err := url.Parse(rawUrl)
  if err != nil {
    panic(err)
  }
  major, minor, ok := http.ParseHTTPVersion(headers.Get(":version"))
  if !ok {
    panic("Invalid HTTP version: " + headers.Get(":version"))
  }
  stream.request = &Request{
    Method:     headers.Get(":method"),
    URL:        url,
    Proto:      headers.Get(":version"),
    ProtoMajor: major,
    ProtoMinor: minor,
    Header:     headers,
    Host:       url.Host,
    RequestURI: url.Path,
    TLS:        conn.tlsState,
  }

  return stream
}

func (conn *connection) WriteFrame(frame Frame) error {
  return nil
}

func (conn *connection) handleSynStream(frame *SynStreamFrame) {
  conn.RLock()
  defer func() { conn.RUnlock() }()

  // Check stream creation is allowed.
  if conn.goaway {
    return
  }

  // Check version.
  if frame.Version != uint16(conn.version) {

    // This is currently strict; only one version allowed per connection.
    log.Printf("Error: Received frame with SPDY version %d on connection with version %d.\n",
      frame.Version, conn.version)
    if frame.Version > SPDY_VERSION {
      log.Printf("Error: Received frame with SPDY version %d, which is not supported.\n",
        frame.Version)
    }
    reply := new(RstStreamFrame)
    reply.Version = SPDY_VERSION
    reply.StreamID = frame.StreamID
    reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
    conn.WriteFrame(reply)
    return
  }

  protocolError := func() {
    reply := new(RstStreamFrame)
    reply.Version = SPDY_VERSION
    reply.StreamID = frame.StreamID
    reply.StatusCode = RST_STREAM_PROTOCOL_ERROR
    conn.WriteFrame(reply)
  }

  // Check Stream ID is odd.
  if frame.StreamID&1 == 0 {
    log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be odd.\n",
      frame.StreamID)
    protocolError()
    return
  }

  // Check Stream ID is the right number.
  if frame.StreamID != conn.nextClientStreamID+2 && frame.StreamID != 1 &&
    conn.nextClientStreamID != 0 {
    log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be %d.\n",
      frame.StreamID, conn.nextClientStreamID+2)
    protocolError()
    return
  }

  // Check Stream ID is not too large.
  if frame.StreamID > MAX_STREAM_ID {
    log.Printf("Error: Received SYN_STREAM with Stream ID %d, which is too large.\n",
      frame.StreamID)
    protocolError()
    return
  }

  // Stream ID is fine.

  // Create and start new stream.
  conn.RUnlock()
  conn.Lock()
  input := make(chan []byte)
  conn.streamInputs[frame.StreamID] = input
  if frame.Flags&FLAG_FIN != 0 {
    close(input)
  }
  conn.streams[frame.StreamID] = conn.newStream(frame, input, conn.streamOutputs[frame.Priority])
  conn.Unlock()
  conn.RLock()

  go func() { conn.streams[frame.StreamID].run() }()

  return
}

func (conn *connection) handleDataFrame(frame *DataFrame) {
  conn.RLock()
  defer func() { conn.RUnlock() }()

  // Check Stream ID is odd.
  if frame.StreamID&1 == 0 {
    log.Printf("Error: Received DATA with Stream ID %d, which should be odd.\n",
      frame.StreamID)
    reply := new(RstStreamFrame)
    reply.Version = SPDY_VERSION
    reply.StreamID = frame.StreamID
    reply.StatusCode = RST_STREAM_PROTOCOL_ERROR
    conn.WriteFrame(reply)
    return
  }

  // Check stream is open.
  if frame.StreamID != conn.nextClientStreamID+2 && frame.StreamID != 1 &&
    conn.nextClientStreamID != 0 {
    log.Printf("Error: Received SYN_STREAM with Stream ID %d, which should be %d.\n",
      frame.StreamID, conn.nextClientStreamID+2)
    reply := new(RstStreamFrame)
    reply.Version = SPDY_VERSION
    reply.StreamID = frame.StreamID
    reply.StatusCode = RST_STREAM_PROTOCOL_ERROR
    conn.WriteFrame(reply)
    return
  }

  // Stream ID is fine.

  // Send data to stream.
  conn.streamInputs[frame.StreamID] <- frame.Data

  // Handle flags.
  if frame.Flags&FLAG_FIN != 0 {
    stream := conn.streams[frame.StreamID]
    stream.Lock()
    stream.state = STATE_HALF_CLOSED_THERE
    close(conn.streamInputs[frame.StreamID])
    stream.Unlock()
  }

  return
}

func (conn *connection) readFrames() {
  if d := conn.server.ReadTimeout; d != 0 {
    conn.conn.SetReadDeadline(time.Now().Add(d))
  }
  if d := conn.server.WriteTimeout; d != 0 {
    defer func() {
      conn.conn.SetWriteDeadline(time.Now().Add(d))
    }()
  }

  for {
    frame, err := ReadFrame(conn.buf)
    if err != nil {
      // TODO: handle error
      panic(err)
    }
    err = frame.ReadHeaders(conn.decompressor)
    if err != nil {
      panic(err)
    }

    if DebugMode {
      fmt.Println("Received Frame:")
      fmt.Println(frame)
    }

  FrameHandling:
    switch frame := frame.(type) {
    default:
      panic(fmt.Sprintf("unexpected frame type %T", frame))

    /*** COMPLETE! ***/
    case *SynStreamFrame:
      conn.handleSynStream(frame)

    case *SynReplyFrame:
      log.Println("Got SYN_REPLY")

    case *RstStreamFrame:
      log.Printf("Received RST_STREAM on stream %d with status %q.\n", frame.StreamID,
        StatusCodeText(int(frame.StatusCode)))

      /*** COMPLETE! ***/
    case *SettingsFrame:
      if conn.receivedSettings == nil {
        conn.receivedSettings = frame.Settings
      } else {
        conn.receivedSettings = append(conn.receivedSettings, frame.Settings...)
      }
      // TODO: Sort out duplication and updating.
      // TODO: Perhaps add some handling by the server here?

    /*** COMPLETE! ***/
    case *PingFrame:
      // Check Ping ID is odd.
      if frame.PingID&1 == 0 {
        log.Printf("Error: Received PING with Stream ID %d, which should be odd.\n", frame.PingID)
        reply := new(RstStreamFrame)
        reply.Version = SPDY_VERSION
        reply.StatusCode = RST_STREAM_PROTOCOL_ERROR
        conn.WriteFrame(reply)
        break FrameHandling
      }
      log.Println("Received PING. Replying...")
      conn.WriteFrame(frame)

    case *GoawayFrame:
      // Check version.
      if frame.Version != uint16(conn.version) {
        log.Printf("Warning: Received frame with SPDY version %d on connection with version %d.\n",
          frame.Version, conn.version)
        if frame.Version > SPDY_VERSION {
          log.Printf("Error: Received frame with SPDY version %d, which is not supported.\n",
            frame.Version)
          reply := new(RstStreamFrame)
          reply.Version = SPDY_VERSION
          reply.StatusCode = RST_STREAM_UNSUPPORTED_VERSION
          conn.WriteFrame(reply)
          break FrameHandling
        }
      }

      // TODO: inform push streams that they haven't been processed if
      // the last good stream ID is less than their ID.

      conn.Lock()
      conn.goaway = true
      conn.Unlock()

    case *HeadersFrame:
      log.Println("Got HEADERS")

    case *WindowUpdateFrame:
      log.Println("Got WINDOW_UPDATE")

    case *CredentialFrame:
      log.Println("Got CREDENTIAL")

      /*** COMPLETE! ***/
    case *DataFrame:
      conn.handleDataFrame(frame)
    }
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

  go func() { conn.send() }()
  if conn.server.GlobalSettings != nil {
    settings := new(SettingsFrame)
    settings.Version = uint16(conn.version)
    settings.Settings = conn.server.GlobalSettings
    conn.streamOutputs[3] <- settings
  }
  conn.readFrames()
}

func acceptDefaultSPDYv2(srv *http.Server, tlsConn *tls.Conn, _ http.Handler) {
  server := new(Server)
  server.TLSConfig = srv.TLSConfig
  acceptSPDYv2(server, tlsConn, nil)
}

func acceptSPDYv2(server *Server, tlsConn *tls.Conn, _ http.Handler) {
  conn := newConn(tlsConn)
  conn.server = server
  conn.tlsConfig = server.TLSConfig
  conn.version = 2

  conn.serve()
}

func acceptDefaultSPDYv3(srv *http.Server, tlsConn *tls.Conn, _ http.Handler) {
  server := new(Server)
  server.TLSConfig = srv.TLSConfig
  acceptSPDYv3(server, tlsConn, nil)
}

func acceptSPDYv3(server *Server, tlsConn *tls.Conn, _ http.Handler) {
  conn := newConn(tlsConn)
  conn.server = server
  conn.tlsConfig = server.TLSConfig
  conn.version = 3

  conn.serve()
}

func newConn(tlsConn *tls.Conn) *connection {
  conn := new(connection)
  conn.remoteAddr = tlsConn.RemoteAddr().String()
  conn.conn = tlsConn
  conn.buf = bufio.NewReader(tlsConn)
  conn.tlsState = new(tls.ConnectionState)
  *conn.tlsState = tlsConn.ConnectionState()
  conn.compressor = new(Compressor)
  conn.decompressor = new(Decompressor)
  conn.streams = make(map[uint32]*stream)
  conn.streamInputs = make(map[uint32]chan<- []byte)
  conn.streamOutputs = [8]chan Frame{}
  conn.streamOutputs[0] = make(chan Frame)
  conn.streamOutputs[1] = make(chan Frame)
  conn.streamOutputs[2] = make(chan Frame)
  conn.streamOutputs[3] = make(chan Frame)
  conn.streamOutputs[4] = make(chan Frame)
  conn.streamOutputs[5] = make(chan Frame)
  conn.streamOutputs[6] = make(chan Frame)
  conn.streamOutputs[7] = make(chan Frame)

  return conn
}
