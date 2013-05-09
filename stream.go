package spdy

import (
  "bytes"
	"errors"
  "fmt"
  "log"
  "net/http"
  "sync"
)

type stream struct {
  sync.RWMutex
  conn           *connection
  streamID       uint32
  flow           *flowControl
  requestBody    *bytes.Buffer
  state          StreamState
  input          <-chan Frame
  output         chan<- Frame
  request        *Request
  handler        *ServeMux
  certificates   []Certificate
  headers        Header
  settings       []*Setting
  unidirectional bool
  responseSent   bool
  responseCode   int
  stop           bool
  wroteHeader    bool
  version        int
}

func (s *stream) Header() Header {
  return s.headers
}

func (s *stream) Ping() <-chan bool {
  return s.conn.Ping()
}

func (s *stream) Push(resource string) (PushWriter, error) {
	newID, err := s.conn.Push(resource, s.streamID)
	if err != nil {
		return nil, err
	}
	
	
	
  return nil, nil
}

func (s *stream) Settings() []*Setting {
  return s.conn.receivedSettings
}

func (s *stream) Write(inputData []byte) (int, error) {
  if s.state == STATE_CLOSED || s.state == STATE_HALF_CLOSED_HERE {
    return 0, errors.New("Error: Stream already closed.")
  }

  s.processInput()
  if s.stop {
    return 0, ErrCancelled
  }

  // Dereference the pointer.
  data := make([]byte, len(inputData))
  copy(data, inputData)

  if !s.wroteHeader {
    s.WriteHeader(http.StatusOK)
  }

  written := 0
  for len(data) > MAX_DATA_SIZE {
    n, err := s.flow.Write(data[:MAX_DATA_SIZE])
    if err != nil {
      return written, err
    }
    written += n
    data = data[MAX_DATA_SIZE:]
  }

  n, err := s.flow.Write(data)
  written += n

  return written, err
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

  // These responses have no body, so close the stream now.
  if code == 204 || code == 304 || code/100 == 1 {
    synReply.Flags = FLAG_FIN
    if s.state == STATE_HALF_CLOSED_THERE {
      s.state = STATE_CLOSED
    } else if s.state == STATE_OPEN {
      s.state = STATE_HALF_CLOSED_HERE
    }
  }

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
  } else if s.state == STATE_OPEN {
    data := new(DataFrame)
    data.StreamID = s.streamID
    data.Flags = FLAG_FIN
    data.Data = []byte{}

    s.output <- data
  }

  // Clean up state.
  if s.state == STATE_HALF_CLOSED_THERE {
    s.state = STATE_CLOSED
  } else if s.state == STATE_OPEN {
    s.state = STATE_HALF_CLOSED_HERE
  }
  s.conn.done.Done()
}

type readCloserBuffer struct {
  *bytes.Buffer
}

func (_ *readCloserBuffer) Close() error {
  return nil
}
