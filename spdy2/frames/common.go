package frames

import (
	"bufio"
	"errors"

	"github.com/SlyMarbo/spdy/common"
)

// ReadFrame reads and parses a frame from reader.
func ReadFrame(reader *bufio.Reader) (frame common.Frame, err error) {
	start, err := reader.Peek(4)
	if err != nil {
		return nil, err
	}

	if start[0] != 128 {
		frame = new(DataFrame)
		_, err = frame.ReadFrom(reader)
		return frame, err
	}

	switch common.BytesToUint16(start[2:4]) {
	case SYN_STREAM:
		frame = new(SynStreamFrame)
	case SYN_REPLY:
		frame = new(SynReplyFrame)
	case RST_STREAM:
		frame = new(RstStreamFrame)
	case SETTINGS:
		frame = new(SettingsFrame)
	case NOOP:
		frame = new(NoopFrame)
	case PING:
		frame = new(PingFrame)
	case GOAWAY:
		frame = new(GoawayFrame)
	case HEADERS:
		frame = new(HeadersFrame)
	case WINDOW_UPDATE:
		frame = new(WindowUpdateFrame)

	default:
		return nil, errors.New("Error Failed to parse frame type.")
	}

	_, err = frame.ReadFrom(reader)
	return frame, err
}

// controlFrameCommonProcessing performs checks identical between
// all control frames. This includes the control bit, the version
// number, the type byte (which is checked against the byte
// provided), and the flags (which are checked against the bitwise
// OR of valid flags provided).
func controlFrameCommonProcessing(data []byte, frameType uint16, flags byte) error {
	// Check it's a control frame.
	if data[0] != 128 {
		return common.IncorrectFrame(DATA_FRAME, int(frameType), 2)
	}

	// Check version.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return common.UnsupportedVersion(version)
	}

	// Check its type.
	realType := common.BytesToUint16(data[2:])
	if realType != frameType {
		return common.IncorrectFrame(int(realType), int(frameType), 2)
	}

	// Check the flags.
	if data[4] & ^flags != 0 {
		return common.InvalidField("flags", int(data[4]), int(flags))
	}

	return nil
}

// Frame types in SPDY/2
const (
	SYN_STREAM    = 1
	SYN_REPLY     = 2
	RST_STREAM    = 3
	SETTINGS      = 4
	NOOP          = 5
	PING          = 6
	GOAWAY        = 7
	HEADERS       = 8
	WINDOW_UPDATE = 9
	CONTROL_FRAME = -1
	DATA_FRAME    = -2
)

// frameNames provides the name for a particular SPDY/2
// frame type.
var frameNames = map[int]string{
	SYN_STREAM:    "SYN_STREAM",
	SYN_REPLY:     "SYN_REPLY",
	RST_STREAM:    "RST_STREAM",
	SETTINGS:      "SETTINGS",
	NOOP:          "NOOP",
	PING:          "PING",
	GOAWAY:        "GOAWAY",
	HEADERS:       "HEADERS",
	WINDOW_UPDATE: "WINDOW_UPDATE",
	CONTROL_FRAME: "CONTROL_FRAME",
	DATA_FRAME:    "DATA_FRAME",
}
