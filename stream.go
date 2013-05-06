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
  conn              *connection
  streamID          uint32
  flow              *flowControl
  requestBody       *bytes.Buffer
  state             StreamState
  input             <-chan Frame
  output            chan<- Frame
  request           *Request
  handler           *ServeMux
  certificates      []Certificate
  headers           Header
  settings          []*Setting
  unidirectional    bool
  responseSent      bool
  responseCode      int
  stop              bool
  initialWindowSize uint32
  transferWindow    int64
  queuedData        *queue
  wroteHeader       bool
  version           int
}

func (s *stream) Header() Header {
  return s.headers
}

func (s *stream) Ping() <-chan bool {
  return s.conn.Ping()
}

func (s *stream) Push() (PushWriter, error) {
  return nil, nil
}

func (s *stream) Settings() []*Setting {
  return s.conn.receivedSettings
}

func (s *stream) Write(data []byte) (int, error) {
  s.processInput()
  if s.stop {
    return 0, ErrCancelled
  }

  if !s.wroteHeader {
    s.WriteHeader(http.StatusOK)
  }

  return s.flow.Write(data)
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
  synReply.version = uint16(s.version)
  synReply.StreamID = s.streamID
  synReply.Headers = s.headers

  s.output <- synReply
}

func (s *stream) WriteSettings(settings ...*Setting) {
  if settings == nil {
    return
  }

  frame := new(SettingsFrame)
  frame.version = uint16(s.version)
  frame.Settings = settings
  s.output <- frame
}

func (s *stream) receiveFrame(frame Frame) {
  if frame == nil {
    panic("Nil frame received in receiveFrame.")
  }

  switch frame := frame.(type) {
  case *DataFrame:
    s.requestBody.Write(frame.Data)

  case *HeadersFrame:
    s.headers.Update(frame.Headers)

  case *WindowUpdateFrame:
    err := s.flow.UpdateWindow(frame.DeltaWindowSize)
    if err != nil {
      reply := new(RstStreamFrame)
      reply.version = uint16(s.version)
      reply.StreamID = s.streamID
      reply.StatusCode = RST_STREAM_FLOW_CONTROL_ERROR
      s.output <- reply
      return
    }

  default:
    panic(fmt.Sprintf("Received unknown frame of type %T.", frame))
  }
}

func (s *stream) wait() {
  frame := <-s.input
  if frame == nil {
    return
  }
  s.receiveFrame(frame)
}

func (s *stream) processInput() {
  var frame Frame
  var ok bool

  for {
    select {
    case frame, ok = <-s.input:
      if !ok {
        return
      }
      s.receiveFrame(frame)

    default:
      return
    }
  }
}

func (s *stream) run() {

  // Make sure Request is prepared.
  s.AddFlowControl()
  s.requestBody = new(bytes.Buffer)
  s.processInput()
  s.request.Body = &readCloserBuffer{s.requestBody}

  /***************
   *** HANDLER ***
   ***************/
  s.handler.ServeSPDY(s, s.request)

  // Make sure any queued data has been sent.
  for s.flow.Paused() {
    s.wait()
    s.flow.Flush()
  }

  if !s.wroteHeader {
    s.headers.Set(":status", "200")
    s.headers.Set(":version", "HTTP/1.1")

    synReply := new(SynReplyFrame)
    synReply.version = uint16(s.version)
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

  s.conn.done.Done()
}

type queue struct {
  data []byte
}

func (q *queue) Push(data []byte) {
  if q.data == nil {
    q.data = data
  } else {
    q.data = append(q.data, data...)
  }
}

func (q *queue) Pop(n int) []byte {
  if n < 0 {
    return nil
  }

  if n < len(q.data) {
    out := q.data[:n]
    q.data = q.data[n:]
    return out
  }

  out := q.data
  q.data = nil
  return out
}

func (q *queue) Empty() bool {
  if q.data == nil {
    return true
  }
  return len(q.data) == 0
}

type readCloserBuffer struct {
  *bytes.Buffer
}

func (_ *readCloserBuffer) Close() error {
  return nil
}
