package spdy

import (
  "errors"
)

type pushStream struct {
  conn     *serverConnection
  streamID uint32
  flow     *flowControl
  origin   *responseStream
  state    StreamState
  output   chan<- Frame
  headers  Header
  stop     bool
  version  int
}

func (p *pushStream) Header() Header {
  return p.headers
}

func (p *pushStream) Write(inputData []byte) (int, error) {
  if p.state == STATE_CLOSED || p.state == STATE_HALF_CLOSED_HERE {
    return 0, errors.New("Error: Stream already closed.")
  }

  if p.stop {
    return 0, ErrCancelled
  }

  // Dereference the pointer.
  data := make([]byte, len(inputData))
  copy(data, inputData)

  written := 0
  for len(data) > MAX_DATA_SIZE {
    n, err := p.flow.Write(data[:MAX_DATA_SIZE])
    if err != nil {
      return written, err
    }
    written += n
    data = data[MAX_DATA_SIZE:]
  }

  n, err := p.flow.Write(data)
  written += n

  return written, err
}
