package spdy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
)

/**************
 * Interfaces *
 **************/

// Connection represents a SPDY connection. The connection should
// be started with a call to Run, which will return once the
// connection has been terminated. The connection can be ended
// early by using Close.
type Conn interface {
	io.Closer
	InitialWindowSize() (uint32, error)
	Ping() (<-chan Ping, error)
	Push(url string, origin Stream) (http.ResponseWriter, error)
	Request(request *http.Request, receiver Receiver, priority Priority) (Stream, error)
	Run() error
}

// Stream contains a single SPDY stream.
type Stream interface {
	http.ResponseWriter
	io.ReadCloser
	Conn() Conn
	ReceiveFrame(Frame) error
	Run() error
	State() *StreamState
	StreamID() StreamID
}

// Frame represents a single SPDY frame.
type Frame interface {
	fmt.Stringer
	io.ReaderFrom
	io.WriterTo
	Compress(Compressor) error
	Decompress(Decompressor) error
	StreamID() StreamID
}

// Compressor is used to compress the text header of a SPDY frame.
type Compressor interface {
	io.Closer
	Compress(http.Header) ([]byte, error)
}

// Decompressor is used to decompress the text header of a SPDY frame.
type Decompressor interface {
	Decompress([]byte) (http.Header, error)
}

// Objects implementing the Receiver interface can be
// registered to receive requests on the Client.
//
// ReceiveData is passed the original request, the data
// to receive and a bool indicating whether this is the
// final batch of data. If the bool is set to true, the
// data may be empty, but should not be nil.
//
// ReceiveHeaders is passed the request and any sent
// text headers. This may be called multiple times.
//
// ReceiveRequest is used when server pushes are sent.
// The returned bool should inticate whether to accept
// the push. The provided Request will be that sent by
// the server with the push.
type Receiver interface {
	ReceiveData(request *http.Request, data []byte, final bool)
	ReceiveHeader(request *http.Request, header http.Header)
	ReceiveRequest(request *http.Request) bool
}

/********
 * Ping *
 ********/

// Ping is used in indicating the response from a ping request.
type Ping struct{}

/************
 * StreamID *
 ************/

// StreamID is the unique identifier for a single SPDY stream.
type StreamID uint32

func (s StreamID) b1() byte {
	return byte(s >> 24)
}

func (s StreamID) b2() byte {
	return byte(s >> 16)
}

func (s StreamID) b3() byte {
	return byte(s >> 8)
}

func (s StreamID) b4() byte {
	return byte(s)
}

// Client indicates whether the ID should belong to a client-sent stream.
func (s StreamID) Client() bool {
	return s != 0 && s&1 != 0
}

// Server indicates whether the ID should belong to a server-sent stream.
func (s StreamID) Server() bool {
	return s != 0 && s&1 == 0
}

// Valid indicates whether the ID is in the range of legal values (including 0).
func (s StreamID) Valid() bool {
	return s <= MAX_STREAM_ID
}

// Zero indicates whether the ID is zero.
func (s StreamID) Zero() bool {
	return s == 0
}

/*********
 * Flags *
 *********/

// Flags represent a frame's Flags.
type Flags byte

// CLEAR_SETTINGS indicates whether the CLEAR_SETTINGS
// flag is set.
func (f Flags) CLEAR_SETTINGS() bool {
	return f&FLAG_SETTINGS_CLEAR_SETTINGS != 0
}

// FIN indicates whether the FIN flag is set.
func (f Flags) FIN() bool {
	return f&FLAG_FIN != 0
}

// PERSIST_VALUE indicates whether the PERSIST_VALUE
// flag is set.
func (f Flags) PERSIST_VALUE() bool {
	return f&FLAG_SETTINGS_PERSIST_VALUE != 0
}

// PERSISTED indicates whether the PERSISTED flag is
// set.
func (f Flags) PERSISTED() bool {
	return f&FLAG_SETTINGS_PERSISTED != 0
}

// UNIDIRECTIONAL indicates whether the UNIDIRECTIONAL
// flag is set.
func (f Flags) UNIDIRECTIONAL() bool {
	return f&FLAG_UNIDIRECTIONAL != 0
}

/************
 * Priority *
 ************/

// Priority represents a stream's priority.
type Priority byte

// Byte returns the priority in binary form, adjusted
// for the given SPDY version.
func (p Priority) Byte(version uint16) byte {
	switch version {
	case 3:
		return byte((p & 7) << 5)
	case 2:
		return byte((p & 3) << 6)
	default:
		return 0
	}
}

// Valid indicates whether the priority is in the valid
// range for the given SPDY version.
func (p Priority) Valid(version uint16) bool {
	switch version {
	case 3:
		return p <= 7
	case 2:
		return p <= 3
	default:
		return false
	}
}

/**************
 * StatusCode *
 **************/

// StatusCode represents a status code sent in
// certain SPDY frames, such as RST_STREAM and
// GOAWAY.
type StatusCode uint32

func (r StatusCode) b1() byte {
	return byte(r >> 24)
}

func (r StatusCode) b2() byte {
	return byte(r >> 16)
}

func (r StatusCode) b3() byte {
	return byte(r >> 8)
}

func (r StatusCode) b4() byte {
	return byte(r)
}

// String gives the StatusCode in text form.
func (r StatusCode) String() string {
	return statusCodeText[r]
}

/************
 * Settings *
 ************/

// Setting represents a single setting as sent
// in a SPDY SETTINGS frame.
type Setting struct {
	Flags Flags
	ID    uint32
	Value uint32
}

// String gives the textual representation of a Setting.
func (s *Setting) String() string {
	id := settingText[s.ID] + ":"
	Flags := ""
	if s.Flags.PERSIST_VALUE() {
		Flags += " FLAG_SETTINGS_PERSIST_VALUE"
	}
	if s.Flags.PERSISTED() {
		Flags += " FLAG_SETTINGS_PERSISTED"
	}
	if Flags == "" {
		Flags = "[NONE]"
	} else {
		Flags = Flags[1:]
	}

	return fmt.Sprintf("%-31s %-10d %s", id, s.Value, Flags)
}

// Settings represents a series of settings, stored in a map
// by setting ID. This ensures that duplicate settings are
// not sent, since the new value will replace the old.
type Settings map[uint32]*Setting

// Settings returns a slice of Setting, sorted into order by
// ID, as in the SPDY specification.
func (s Settings) Settings() []*Setting {
	if len(s) == 0 {
		return []*Setting{}
	}

	ids := make([]int, 0, len(s))
	for id := range s {
		ids = append(ids, int(id))
	}

	sort.Sort(sort.IntSlice(ids))

	out := make([]*Setting, len(s))

	for i, id := range ids {
		out[i] = s[uint32(id)]
	}

	return out
}

/***************
 * StreamState *
 ***************/

// StreamState is used to store and query the stream's state. The active methods
// do not directly affect the stream's state, but it will use that information
// to effect the changes.
type StreamState struct {
	sync.RWMutex
	s uint8
}

// Check whether the stream is open.
func (s *StreamState) Open() bool {
	s.RLock()
	defer s.RUnlock()
	return s.s == stateOpen
}

// Check whether the stream is closed.
func (s *StreamState) Closed() bool {
	s.RLock()
	defer s.RUnlock()
	return s.s == stateClosed
}

// Check whether the stream is half-closed at the other endpoint.
func (s *StreamState) ClosedThere() bool {
	s.RLock()
	defer s.RUnlock()
	return s.s == stateClosed || s.s == stateHalfClosedThere
}

// Check whether the stream is open at the other endpoint.
func (s *StreamState) OpenThere() bool {
	return !s.ClosedThere()
}

// Check whether the stream is half-closed at the other endpoint.
func (s *StreamState) ClosedHere() bool {
	s.RLock()
	defer s.RUnlock()
	return s.s == stateClosed || s.s == stateHalfClosedHere
}

// Check whether the stream is open locally.
func (s *StreamState) OpenHere() bool {
	return !s.ClosedHere()
}

// Closes the stream.
func (s *StreamState) Close() {
	s.Lock()
	s.s = stateClosed
	s.Unlock()
}

// Half-close the stream locally.
func (s *StreamState) CloseHere() {
	s.Lock()
	if s.s == stateOpen {
		s.s = stateHalfClosedHere
	} else if s.s == stateHalfClosedThere {
		s.s = stateClosed
	}
	s.Unlock()
}

// Half-close the stream at the other endpoint.
func (s *StreamState) CloseThere() {
	s.Lock()
	if s.s == stateOpen {
		s.s = stateHalfClosedThere
	} else if s.s == stateHalfClosedHere {
		s.s = stateClosed
	}
	s.Unlock()
}

/********************
 * Helper Functions *
 ********************/

// cloneHeader returns a duplicate of the provided Header.
func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// updateHeader adds and new name/value pairs and replaces
// those already existing in the older header.
func updateHeader(older, newer http.Header) {
	for name, values := range newer {
		for i, value := range values {
			if i == 0 {
				older.Set(name, value)
			} else {
				older.Add(name, value)
			}
		}
	}
}

// frameNamesV3 provides the name for a particular SPDY/3
// frame type.
var frameNamesV3 = map[int]string{
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

// frameNamesV2 provides the name for a particular SPDY/2
// frame type.
var frameNamesV2 = map[int]string{
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

func bytesToUint16(b []byte) uint16 {
	return (uint16(b[0]) << 8) + uint16(b[1])
}

func bytesToUint24(b []byte) uint32 {
	return (uint32(b[0]) << 16) + (uint32(b[1]) << 8) + uint32(b[2])
}

func bytesToUint24Reverse(b []byte) uint32 {
	return (uint32(b[2]) << 16) + (uint32(b[1]) << 8) + uint32(b[0])
}

func bytesToUint32(b []byte) uint32 {
	return (uint32(b[0]) << 24) + (uint32(b[1]) << 16) + (uint32(b[2]) << 8) + uint32(b[3])
}

// read is used to ensure that the given number of bytes
// are read if possible, even if multiple calls to Read
// are required.
func read(r io.Reader, i int) ([]byte, error) {
	out := make([]byte, i)
	in := out[:]
	for i > 0 {
		if n, err := r.Read(in); err != nil {
			return nil, err
		} else {
			in = in[n:]
			i -= n
		}
	}
	return out, nil
}

// write is used to ensure that the given data is written
// if possible, even if multiple calls to Write are
// required.
func write(w io.Writer, data []byte) error {
	i := len(data)
	for i > 0 {
		if n, err := w.Write(data); err != nil {
			return err
		} else {
			data = data[n:]
			i -= n
		}
	}
	return nil
}

// readCloser is a helper structure to allow
// an io.Reader to satisfy the io.ReadCloser
// interface.
type readCloser struct {
	io.Reader
}

func (r *readCloser) Close() error {
	return nil
}

/**********
 * Errors *
 **********/

type incorrectFrame struct {
	got, expected, version int
}

func (i *incorrectFrame) Error() string {
	if i.version == 3 {
		return fmt.Sprintf("Error: Frame %s tried to parse data for a %s.", frameNamesV3[i.expected], frameNamesV3[i.got])
	}
	return fmt.Sprintf("Error: Frame %s tried to parse data for a %s.", frameNamesV2[i.expected], frameNamesV2[i.got])
}

type unsupportedVersion uint16

func (u unsupportedVersion) Error() string {
	return fmt.Sprintf("Error: Unsupported SPDY version: %d.\n", u)
}

type incorrectDataLength struct {
	got, expected int
}

func (i *incorrectDataLength) Error() string {
	return fmt.Sprintf("Error: Incorrect amount of data for frame: got %d bytes, expected %d.", i.got, i.expected)
}

var frameTooLarge = errors.New("Error: Frame too large.")

type invalidField struct {
	field         string
	got, expected int
}

func (i *invalidField) Error() string {
	return fmt.Sprintf("Error: Field %q recieved invalid data %d, expecting %d.", i.field, i.got, i.expected)
}

var streamIDTooLarge = errors.New("Error: Stream ID is too large.")
