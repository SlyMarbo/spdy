package spdy

import (
	"errors"
	"fmt"
)

// flowControl is used by Streams to ensure that
// they abide by SPDY's flow control rules. For
// versions of SPDY before 3, this has no effect.
type flowControl struct {
	stream              Stream
	streamID            uint32
	output              chan<- Frame
	active              bool
	initialWindow       uint32
	transferWindow      int64
	sent                uint32
	buffer              [][]byte
	constrained         bool
	initialWindowThere  uint32
	transferWindowThere int64
}

// AddFlowControl initialises flow control for
// the Stream. If the Stream is running at an
// older SPDY version than SPDY/3, the flow
// control has no effect. Multiple calls to
// AddFlowControl are safe.
func (s *responseStream) AddFlowControl() {
	if s.flow != nil {
		return
	}

	flow := new(flowControl)
	initialWindow := s.conn.initialWindowSize
	flow.streamID = s.streamID
	flow.output = s.output
	if s.version == 3 {
		flow.active = true
		flow.buffer = make([][]byte, 0, 10)
		flow.initialWindow = initialWindow
		flow.transferWindow = int64(initialWindow)
		flow.stream = s
		flow.initialWindowThere = DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
		flow.transferWindowThere = DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
	}
	s.flow = flow
}

// AddFlowControl initialises flow control for
// the Stream. If the Stream is running at an
// older SPDY version than SPDY/3, the flow
// control has no effect. Multiple calls to
// AddFlowControl are safe.
func (p *pushStream) AddFlowControl() {
	if p.flow != nil {
		return
	}

	flow := new(flowControl)
	initialWindow := p.conn.initialWindowSize
	flow.streamID = p.streamID
	flow.output = p.output
	if p.version == 3 {
		flow.active = true
		flow.buffer = make([][]byte, 0, 10)
		flow.initialWindow = initialWindow
		flow.transferWindow = int64(initialWindow)
		flow.stream = p
		flow.initialWindowThere = DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
		flow.transferWindowThere = DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
	}
	p.flow = flow
}

// AddFlowControl initialises flow control for
// the Stream. If the Stream is running at an
// older SPDY version than SPDY/3, the flow
// control has no effect. Multiple calls to
// AddFlowControl are safe.
func (r *requestStream) AddFlowControl() {
	if r.flow != nil {
		return
	}

	flow := new(flowControl)
	initialWindow := r.conn.initialWindowSize
	flow.streamID = r.streamID
	flow.output = r.output
	if r.version == 3 {
		flow.active = true
		flow.buffer = make([][]byte, 0, 10)
		flow.initialWindow = initialWindow
		flow.transferWindow = int64(initialWindow)
		flow.stream = r
		flow.initialWindowThere = DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
		flow.transferWindowThere = DEFAULT_INITIAL_CLIENT_WINDOW_SIZE
	}
	r.flow = flow
}

// Active indicates whether flow control
// is currently in effect. By default,
// this is true for SPDY version 3 and
// above, and false for version 1 or 2.
func (f *flowControl) Active() bool {
	return f.active
}

// Activate can be used to manually
// activate flow control. This is
// not recommended.
func (f *flowControl) Activate() {
	f.active = true
}

// Deactivate can be used to manually
// deactivate flow control. This is
// not recommended.
func (f *flowControl) Deactivate() {
	f.active = false
}

// CheckInitialWindow is used to handle the race
// condition where the flow control is initialised
// before the server has received any updates to
// the initial tranfer window sent by the client.
//
// The transfer window is updated retroactively,
// if necessary.
func (f *flowControl) CheckInitialWindow() {
	if !f.active {
		return
	}

	newWindow := f.stream.Connection().InitialWindowSize()

	if f.initialWindow != newWindow {
		if f.initialWindow > newWindow {
			f.transferWindow = int64(newWindow - f.sent)
		} else if f.initialWindow < newWindow {
			f.transferWindow += int64(newWindow - f.initialWindow)
		}
		if f.transferWindow <= 0 {
			f.constrained = true
		}
		f.initialWindow = newWindow
	}
}

// Receive is called when data is received from
// the other endpoint. This ensures that they
// conform to the transfer window, regrows the
// window, and sends errors if necessary.
func (f *flowControl) Receive(data []byte) {
	if !f.active {
		return
	}

	// The transfer window shouldn't already be negative.
	if f.transferWindowThere < 0 {
		rst := new(RstStreamFrame)
		rst.version = f.stream.Version()
		rst.streamID = f.streamID
		rst.StatusCode = RST_STREAM_FLOW_CONTROL_ERROR
		f.output <- rst
		return
	}

	// Update the window.
	f.transferWindowThere -= int64(len(data))

	// Regrow the window if it's half-empty.
	if f.transferWindowThere <= int64(f.initialWindowThere/2) {
		grow := new(WindowUpdateFrame)
		grow.version = f.stream.Version()
		grow.streamID = f.streamID
		grow.DeltaWindowSize = uint32(int64(f.initialWindowThere) - f.transferWindowThere)
		f.output <- grow
	}
}

// UpdateWindow is called when an UPDATE_WINDOW frame is received,
// and performs the growing of the transfer window.
func (f *flowControl) UpdateWindow(deltaWindowSize uint32) error {
	if int64(deltaWindowSize)+f.transferWindow > MAX_TRANSFER_WINDOW_SIZE {
		return errors.New("Error: WINDOW_UPDATE delta window size overflows transfer window size.")
	}

	// Grow window and flush queue.
	fmt.Printf("Flow: Growing window in stream %d by %d bytes.\n", f.streamID, deltaWindowSize)
	f.transferWindow += int64(deltaWindowSize)

	f.Flush()
	return nil
}

// Write is used to send data to the connection. This
// takes care of the windowing. Although data may be
// buffered, rather than actually sent, this is not
// visible to the caller.
func (f *flowControl) Write(data []byte) (int, error) {
	l := len(data)
	if l == 0 {
		return 0, nil
	}

	// Transfer window processing.
	if f.active {
		f.CheckInitialWindow()
		if f.active && f.constrained {
			f.Flush()
		}
		var window uint32
		if f.transferWindow < 0 {
			window = 0
		} else {
			window = uint32(f.transferWindow)
		}

		if uint32(len(data)) > window {
			f.buffer = append(f.buffer, data[window:])
			data = data[:window]
			f.sent += window
			f.transferWindow -= int64(window)
			f.constrained = true
			fmt.Printf("Stream %d is now constrained.\n", f.streamID)
		}
	}

	if len(data) == 0 {
		return l, nil
	}

	dataFrame := new(DataFrame)
	dataFrame.streamID = f.streamID
	dataFrame.Data = data

	f.output <- dataFrame
	return l, nil
}

// Flush is used to send buffered data to
// the connection, if the transfer window
// will allow. Flush does not guarantee
// that any or all buffered data will be
// sent with a single flush.
func (f *flowControl) Flush() {
	f.CheckInitialWindow()
	if !f.active || !f.constrained || f.transferWindow == 0 {
		return
	}

	out := make([]byte, 0, f.transferWindow)
	left := f.transferWindow
	for i := 0; i < len(f.buffer); i++ {
		if l := int64(len(f.buffer[i])); l <= left {
			out = append(out, f.buffer[i]...)
			left -= l
			f.buffer = f.buffer[1:]
		} else {
			out = append(out, f.buffer[i][:left]...)
			f.buffer[i] = f.buffer[i][left:]
			left = 0
		}

		if left == 0 {
			break
		}
	}

	f.transferWindow -= int64(len(out))

	if f.transferWindow > 0 {
		f.constrained = false
		fmt.Printf("Stream %d is no longer constrained.\n", f.streamID)
	}

	dataFrame := new(DataFrame)
	dataFrame.streamID = f.streamID
	dataFrame.Data = out

	f.output <- dataFrame
}

// Paused indicates whether there is data buffered.
// A Stream should not be closed until after the
// last data has been sent and then Paused returns
// false.
func (f *flowControl) Paused() bool {
	f.CheckInitialWindow()
	return f.active && f.constrained
}
