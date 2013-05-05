package spdy

import (
  "bytes"
  "fmt"
  "log"
  "net/http"
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
  responseSent   bool
  responseCode   int
  wroteHeader    bool
  contentLength  int64
  written        int64
  version        int
  stop           bool
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

func (s *stream) Settings() []*Setting {
  return s.conn.receivedSettings
}

func (s *stream) Write(data []byte) (int, error) {
  if s.stop {
    return 0, ErrCancelled
  }

  if !s.wroteHeader {
    s.WriteHeader(http.StatusOK)
  }

  if len(data) == 0 {
    return 0, nil
  }

  s.written += int64(len(data)) // ignoring errors, for errorKludge
  if s.contentLength != -1 && s.written > s.contentLength {
    return 0, ErrContentLength
  }

  dataFrame := new(DataFrame)
  dataFrame.StreamID = s.streamID
  dataFrame.Data = data

  s.output <- dataFrame
  if DebugMode {
    fmt.Printf("Debug: Wrote %d bytes of data from stream %d.\n", len(data), s.streamID)
  }

  return len(data), nil
}

func (s *stream) WriteHeader(code int) {
  if s.wroteHeader {
    log.Println("spdy: Error: Multiple calls to ResponseWriter.WriteHeader.")
    return
  }

  s.wroteHeader = true
  s.responseCode = code

  s.headers.Set(":status", fmt.Sprint(code))
  s.headers.Set(":version", "HTTP/1.1")

  synReply := new(SynReplyFrame)
  synReply.Version = uint16(s.version)
  synReply.StreamID = s.streamID
  synReply.Headers = s.headers

  s.output <- synReply
}

func (s *stream) WriteSettings(settings ...*Setting) {
  if settings == nil {
    return
  }

  frame := new(SettingsFrame)
  frame.Version = uint16(s.version)
  frame.Settings = settings
  s.output <- frame
}

type readCloserBuffer struct {
  *bytes.Buffer
}

func (_ *readCloserBuffer) Close() error {
  return nil
}

func (s *stream) run() {

  // Make sure Request is prepared.
  body := new(bytes.Buffer)
  for data := range s.input {
    body.Write(data)
  }
  s.request.Body = &readCloserBuffer{body}

  s.handler.ServeSPDY(s, s.request)

  if !s.wroteHeader {
    s.headers.Set(":status", "200")
    s.headers.Set(":version", "HTTP/1.1")

    synReply := new(SynReplyFrame)
    synReply.Version = uint16(s.version)
    synReply.Flags = FLAG_FIN
    synReply.StreamID = s.streamID
    synReply.Headers = s.headers

    s.output <- synReply
  } else {
    data := new(DataFrame)
    data.StreamID = s.streamID
    data.Flags = FLAG_FIN
    data.Data = []byte{}

    s.output <- data
  }
}
