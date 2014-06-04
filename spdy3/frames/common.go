package frames

import (
	"bufio"
	"errors"
	"fmt"

	"github.com/SlyMarbo/spdy/common"
)

// ReadFrame reads and parses a frame from reader.
func ReadFrame(reader *bufio.Reader, subversion int) (frame common.Frame, err error) {
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
		switch subversion {
		case 0:
			frame = new(SynStreamFrame)
		case 1:
			frame = new(SynStreamFrameV3_1)
		default:
			return nil, fmt.Errorf("Error: Given subversion %d is unrecognised.", subversion)
		}
	case SYN_REPLY:
		frame = new(SynReplyFrame)
	case RST_STREAM:
		frame = new(RstStreamFrame)
	case SETTINGS:
		frame = new(SettingsFrame)
	case PING:
		frame = new(PingFrame)
	case GOAWAY:
		frame = new(GoawayFrame)
	case HEADERS:
		frame = new(HeadersFrame)
	case WINDOW_UPDATE:
		frame = &WindowUpdateFrame{subversion: subversion}
	case CREDENTIAL:
		frame = new(CredentialFrame)

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
		return common.IncorrectFrame(DATA_FRAME, int(frameType), 3)
	}

	// Check version.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return common.UnsupportedVersion(version)
	}

	// Check its type.
	realType := common.BytesToUint16(data[2:])
	if realType != frameType {
		return common.IncorrectFrame(int(realType), int(frameType), 3)
	}

	// Check the flags.
	if data[4] & ^flags != 0 {
		return common.InvalidField("flags", int(data[4]), int(flags))
	}

	return nil
}

// Frame types in SPDY/3
const (
	SYN_STREAM    = 1
	SYN_REPLY     = 2
	RST_STREAM    = 3
	SETTINGS      = 4
	PING          = 6
	GOAWAY        = 7
	HEADERS       = 8
	WINDOW_UPDATE = 9
	CREDENTIAL    = 10
	CONTROL_FRAME = -1
	DATA_FRAME    = -2
)

// frameNames provides the name for a particular SPDY/3
// frame type.
var frameNames = map[int]string{
	SYN_STREAM:    "SYN_STREAM",
	SYN_REPLY:     "SYN_REPLY",
	RST_STREAM:    "RST_STREAM",
	SETTINGS:      "SETTINGS",
	PING:          "PING",
	GOAWAY:        "GOAWAY",
	HEADERS:       "HEADERS",
	WINDOW_UPDATE: "WINDOW_UPDATE",
	CREDENTIAL:    "CREDENTIAL",
	CONTROL_FRAME: "CONTROL_FRAME",
	DATA_FRAME:    "DATA_FRAME",
}
