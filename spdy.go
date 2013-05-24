package spdy

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// Connection represents a SPDY
// session. This co-ordinates
// and manages SPDY Streams.
type Connection interface {
	InitialWindowSize() uint32
	Ping() <-chan bool
	Push(string, Stream) (PushWriter, error)
	Request(*http.Request, Receiver, int) (Stream, error)
	WriteFrame(Frame)
	Version() uint16
}

// Stream represents a SPDY
// stream.
type Stream interface {
	AddFlowControl()
	Cancel()
	Connection() Connection
	Header() http.Header
	ReceiveFrame(Frame)
	Run()
	State() *StreamState
	Stop()
	StreamID() uint32
	Write([]byte) (int, error)
	WriteHeader(int)
	WriteHeaders()
	Wait()
	Version() uint16
}

// Frame represents a SPDY frame.
type Frame interface {
	Bytes() ([]byte, error)
	DecodeHeaders(*Decompressor) error
	EncodeHeaders(*Compressor) error
	Parse(*bufio.Reader) error
	StreamID() uint32
	String() string
	WriteTo(io.Writer) error
	Version() uint16
}

// ReadRequest reads and parses a frame from reader.
func ReadFrame(reader *bufio.Reader) (frame Frame, err error) {
	start, err := reader.Peek(4)
	if err != nil {
		return nil, err
	}

	if start[0]&0x80 == 0 {
		frame = new(DataFrame)
		err = frame.Parse(reader)
		return
	}

	switch bytesToUint16(start[2:4]) {
	case SYN_STREAM:
		frame = new(SynStreamFrame)
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
		frame = new(WindowUpdateFrame)
	case CREDENTIAL:
		frame = new(CredentialFrame)

	default:
		return nil, errors.New("Error Failed to parse frame type.")
	}

	err = frame.Parse(reader)
	return frame, err
}

/******************
 *** SYN_STREAM ***
 ******************/
type SynStreamFrame struct {
	version        uint16
	Flags          byte
	streamID       uint32
	AssocStreamID  uint32
	Priority       byte
	Slot           byte
	Headers        http.Header
	rawHeaders     []byte
	headersWritten bool
	headersDecoded bool
}

func (frame *SynStreamFrame) Bytes() ([]byte, error) {
	if !frame.headersWritten {
		return nil, errors.New("spdy: Error: Headers not written.")
	}

	headers := frame.rawHeaders
	length := 10 + len(headers)
	out := make([]byte, 18, 8+length)

	out[0] = 0x80 | byte(frame.version>>8)         // Control bit and Version
	out[1] = byte(frame.version)                   // Version
	out[2] = 0                                     // Type
	out[3] = 1                                     // Type
	out[4] = frame.Flags                           // Flags
	out[5] = byte(length >> 16)                    // Length
	out[6] = byte(length >> 8)                     // Length
	out[7] = byte(length)                          // Length
	out[8] = byte(frame.streamID>>24) & 0x7f       // Stream ID
	out[9] = byte(frame.streamID >> 16)            // Stream ID
	out[10] = byte(frame.streamID >> 8)            // Stream ID
	out[11] = byte(frame.streamID)                 // Stream ID
	out[12] = byte(frame.AssocStreamID>>24) & 0x7f // Associated Stream ID
	out[13] = byte(frame.AssocStreamID >> 16)      // Associated Stream ID
	out[14] = byte(frame.AssocStreamID >> 8)       // Associated Stream ID
	out[15] = byte(frame.AssocStreamID)            // Associated Stream ID

	switch frame.version {
	case 3:
		out[16] = ((frame.Priority & 0x7) << 5) // Priority and unused
		out[17] = frame.Slot                    // Slot
	case 2:
		out[16] = ((frame.Priority & 0x3) << 6) // Priority and unused
		out[17] = 0                             // Unused
	}

	out = append(out, headers...) // Name/Value Header Block

	return out, nil
}

func (frame *SynStreamFrame) DecodeHeaders(decom *Decompressor) error {
	if frame.headersDecoded {
		return nil
	}

	headers, err := decodeHeaders(frame.rawHeaders, decom, frame.version)
	if err != nil {
		return err
	}
	frame.Headers = headers
	frame.headersDecoded = true
	return nil
}

func (frame *SynStreamFrame) EncodeHeaders(com *Compressor) error {
	data, err := encodeHeaders(frame.Headers, com, frame.version)
	if err != nil {
		return err
	}
	frame.rawHeaders = data
	frame.headersWritten = true
	return nil
}

func (frame *SynStreamFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, SYN_STREAM}
	}

	// Check it's a SYN_STREAM.
	if bytesToUint16(start[2:4]) != SYN_STREAM {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), SYN_STREAM}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if version == 3 && length < 10 {
		return &IncorrectDataLength{length, 10}
	} else if version == 2 && length < 12 {
		return &IncorrectDataLength{length, 12}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check unused space.
	if (data[8]>>7) != 0 || (data[12]>>7) != 0 {
		return &InvalidField{"Unused", 1, 0}
	} else if (data[16] & 0x1f) != 0 {
		return &InvalidField{"Unused", int(data[16] & 0x1f), 0}
	} else if version == 2 && data[17] != 0 {
		return &InvalidField{"Unused", int(data[17]), 0}
	}

	frame.version = version
	frame.Flags = data[4]
	frame.streamID = bytesToUint31(data[8:12])
	frame.AssocStreamID = bytesToUint31(data[12:16])
	if version == 3 {
		frame.Priority = data[16] >> 5
		frame.Slot = data[17]
	} else if version == 2 {
		frame.Priority = data[16] >> 6
	}

	frame.rawHeaders = data[18:]

	return nil
}

func (frame *SynStreamFrame) StreamID() uint32 {
	return frame.streamID
}

func (frame *SynStreamFrame) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.Flags&FLAG_FIN != 0 {
		flags += "FLAG_FIN "
	}
	if frame.Flags&FLAG_UNIDIRECTIONAL != 0 {
		flags += "FLAG_UNIDIRECTIONAL "
	}
	if flags == "" {
		flags = "[NONE]"
	}

	buf.WriteString("SYN_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Associated Stream ID: %d\n\t", frame.AssocStreamID))
	buf.WriteString(fmt.Sprintf("Priority:             %d\n\t", frame.Priority))
	if frame.version > 2 {
		buf.WriteString(fmt.Sprintf("Slot:                 %d\n\t", frame.Slot))
	}
	buf.WriteString(fmt.Sprintf("Headers:              %v\n}\n", frame.Headers))

	return buf.String()
}

func (frame *SynStreamFrame) Version() uint16 {
	return frame.version
}

func (frame *SynStreamFrame) WriteTo(writer io.Writer) error {
	if !frame.headersWritten {
		return errors.New("spdy: Error: Headers not written.")
	}

	headers := frame.rawHeaders
	length := 10 + len(headers)
	out := make([]byte, 18)

	out[0] = 0x80 | byte(frame.version>>8)         // Control bit and Version
	out[1] = byte(frame.version)                   // Version
	out[2] = 0                                     // Type
	out[3] = 1                                     // Type
	out[4] = frame.Flags                           // Flags
	out[5] = byte(length >> 16)                    // Length
	out[6] = byte(length >> 8)                     // Length
	out[7] = byte(length)                          // Length
	out[8] = byte(frame.streamID>>24) & 0x7f       // Stream ID
	out[9] = byte(frame.streamID >> 16)            // Stream ID
	out[10] = byte(frame.streamID >> 8)            // Stream ID
	out[11] = byte(frame.streamID)                 // Stream ID
	out[12] = byte(frame.AssocStreamID>>24) & 0x7f // Associated Stream ID
	out[13] = byte(frame.AssocStreamID >> 16)      // Associated Stream ID
	out[14] = byte(frame.AssocStreamID >> 8)       // Associated Stream ID
	out[15] = byte(frame.AssocStreamID)            // Associated Stream ID

	switch frame.version {
	case 3:
		out[16] = ((frame.Priority & 0x7) << 5) // Priority and unused
		out[17] = frame.Slot                    // Slot
	case 2:
		out[16] = ((frame.Priority & 0x3) << 6) // Priority and unused
		out[17] = 0                             // Unused
	}

	_, err := writer.Write(out)
	if err != nil {
		return err
	}

	_, err = writer.Write(headers)
	return err
}

/*****************
 *** SYN_REPLY ***
 *****************/
type SynReplyFrame struct {
	version        uint16
	Flags          byte
	streamID       uint32
	Headers        http.Header
	rawHeaders     []byte
	headersWritten bool
	headersDecoded bool
}

func (frame *SynReplyFrame) Bytes() ([]byte, error) {
	if !frame.headersWritten {
		return nil, errors.New("spdy: Error: Headers not written.")
	}

	headers := frame.rawHeaders
	length := 4 + len(headers)
	start := 12
	if frame.version == 2 {
		length += 2
		start += 2
	}
	out := make([]byte, start, 8+length)

	out[0] = 0x80 | byte(frame.version>>8)   // Control bit and Version
	out[1] = byte(frame.version)             // Version
	out[2] = 0                               // Type
	out[3] = 2                               // Type
	out[4] = frame.Flags                     // Flags
	out[5] = byte(length >> 16)              // Length
	out[6] = byte(length >> 8)               // Length
	out[7] = byte(length)                    // Length
	out[8] = byte(frame.streamID>>24) & 0x7f // Stream ID
	out[9] = byte(frame.streamID >> 16)      // Stream ID
	out[10] = byte(frame.streamID >> 8)      // Stream ID
	out[11] = byte(frame.streamID)           // Stream ID

	out = append(out, headers...) // Name/Value Header Block

	return out, nil
}

func (frame *SynReplyFrame) DecodeHeaders(decom *Decompressor) error {
	if frame.headersDecoded {
		return nil
	}

	headers, err := decodeHeaders(frame.rawHeaders, decom, frame.version)
	if err != nil {
		return err
	}
	frame.Headers = headers
	frame.headersDecoded = true
	return nil
}

func (frame *SynReplyFrame) EncodeHeaders(com *Compressor) error {
	data, err := encodeHeaders(frame.Headers, com, frame.version)
	if err != nil {
		return err
	}
	frame.rawHeaders = data
	frame.headersWritten = true
	return nil
}

func (frame *SynReplyFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, SYN_REPLY}
	}

	// Check it's a SYN_REPLY.
	if bytesToUint16(start[2:4]) != SYN_REPLY {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), SYN_REPLY}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if version == 3 && length < 4 {
		return &IncorrectDataLength{length, 4}
	} else if version == 2 && length < 8 {
		return &IncorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return &InvalidField{"Unused", 1, 0}
	} else if version == 2 && data[12] != 0 {
		return &InvalidField{"Unused", int(data[12]), 0}
	} else if version == 2 && data[13] != 0 {
		return &InvalidField{"Unused", int(data[13]), 0}
	}

	frame.version = version
	frame.Flags = data[4]
	frame.streamID = bytesToUint31(data[8:12])

	offset := 12
	if version == 2 {
		offset += 2
	}

	frame.rawHeaders = data[offset:]

	return nil
}

func (frame *SynReplyFrame) StreamID() uint32 {
	return frame.streamID
}

func (frame *SynReplyFrame) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.Flags&FLAG_FIN != 0 {
		flags += "FLAG_FIN "
	}
	if flags == "" {
		flags = "[NONE]"
	}

	buf.WriteString("SYN_REPLY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Headers:              %v\n}\n", frame.Headers))

	return buf.String()
}

func (frame *SynReplyFrame) Version() uint16 {
	return frame.version
}

func (frame *SynReplyFrame) WriteTo(writer io.Writer) error {
	if !frame.headersWritten {
		return errors.New("spdy: Error: Headers not written.")
	}

	headers := frame.rawHeaders
	length := 4 + len(headers)
	start := 12
	if frame.version == 2 {
		length += 2
		start += 2
	}
	out := make([]byte, start)

	out[0] = 0x80 | byte(frame.version>>8)   // Control bit and Version
	out[1] = byte(frame.version)             // Version
	out[2] = 0                               // Type
	out[3] = 2                               // Type
	out[4] = frame.Flags                     // Flags
	out[5] = byte(length >> 16)              // Length
	out[6] = byte(length >> 8)               // Length
	out[7] = byte(length)                    // Length
	out[8] = byte(frame.streamID>>24) & 0x7f // Stream ID
	out[9] = byte(frame.streamID >> 16)      // Stream ID
	out[10] = byte(frame.streamID >> 8)      // Stream ID
	out[11] = byte(frame.streamID)           // Stream ID

	_, err := writer.Write(out)
	if err != nil {
		return err
	}

	_, err = writer.Write(headers)
	return err
}

/******************
 *** RST_STREAM ***
 ******************/
type RstStreamFrame struct {
	version    uint16
	streamID   uint32
	StatusCode uint32
}

func (frame *RstStreamFrame) Bytes() ([]byte, error) {
	out := make([]byte, 16)

	out[0] = 0x80 | byte(frame.version>>8)   // Control bit and Version
	out[1] = byte(frame.version)             // Version
	out[2] = 0                               // Type
	out[3] = 3                               // Type
	out[4] = 0                               // Flag
	out[5] = 0                               // Length
	out[6] = 0                               // Length
	out[7] = 8                               // Length
	out[8] = byte(frame.streamID>>24) & 0x7f // Stream ID
	out[9] = byte(frame.streamID >> 16)      // Stream ID
	out[10] = byte(frame.streamID >> 8)      // Stream ID
	out[11] = byte(frame.streamID)           // Stream ID
	out[12] = byte(frame.StatusCode >> 24)   // Status code
	out[13] = byte(frame.StatusCode >> 16)   // Status code
	out[14] = byte(frame.StatusCode >> 8)    // Status code
	out[15] = byte(frame.StatusCode)         // Status code

	return out, nil
}

func (frame *RstStreamFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *RstStreamFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *RstStreamFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, RST_STREAM}
	}

	// Check it's a RST_STREAM.
	if bytesToUint16(start[2:4]) != RST_STREAM {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), RST_STREAM}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if length != 8 {
		return &IncorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return &InvalidField{"Unused", 1, 0}
	}

	frame.version = version
	frame.streamID = bytesToUint31(data[8:12])
	frame.StatusCode = bytesToUint32(data[12:16])

	return nil
}

func (frame *RstStreamFrame) StreamID() uint32 {
	return frame.streamID
}

func (frame *RstStreamFrame) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("RST_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Status code:          %d\n}\n", frame.StatusCode))

	return buf.String()
}

func (frame *RstStreamFrame) Version() uint16 {
	return frame.version
}

func (frame *RstStreamFrame) WriteTo(writer io.Writer) error {
	bytes, err := frame.Bytes()
	if err != nil {
		return err
	}
	_, err = writer.Write(bytes)
	return err
}

/****************
 *** SETTINGS ***
 ****************/
type SettingsFrame struct {
	version  uint16
	Flags    byte
	Settings []*Setting
}

func (frame *SettingsFrame) Add(flags byte, id, value uint32) {
	for _, setting := range frame.Settings {
		if setting.ID == id {
			setting.Flags = flags
			setting.Value = value
			return
		}
	}
	frame.Settings = append(frame.Settings, &Setting{flags, id, value})
	return
}

func (frame *SettingsFrame) Bytes() ([]byte, error) {
	numSettings := uint32(len(frame.Settings))
	length := 4 + (8 * numSettings)
	out := make([]byte, 8+length)

	out[0] = 0x80 | byte(frame.version>>8) // Control bit and Version
	out[1] = byte(frame.version)           // Version
	out[2] = 0                             // Type
	out[3] = 4                             // Type
	out[4] = frame.Flags                   // Flags
	out[5] = byte(length >> 16)            // Length
	out[6] = byte(length >> 8)             // Length
	out[7] = byte(length)                  // Length
	out[8] = byte(numSettings >> 24)       // Number of Entries
	out[9] = byte(numSettings >> 16)       // Number of Entries
	out[10] = byte(numSettings >> 8)       // Number of Entries
	out[11] = byte(numSettings)            // Number of Entries

	offset := 12
	sort.Sort(settingsSorter(frame.Settings))
	var lastID uint32
	for _, setting := range frame.Settings {
		if setting.ID == lastID {
			return nil, errors.New("Error: Duplicate settings IDs found.")
		}
		lastID = setting.ID
		bytes := setting.Bytes(frame.version)
		for i, b := range bytes {
			out[offset+i] = b
		}

		offset += 8
	}

	return out, nil
}

func (frame *SettingsFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *SettingsFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *SettingsFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, SETTINGS}
	}

	// Check it's a SETTINGS.
	if bytesToUint16(start[2:4]) != SETTINGS {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), SETTINGS}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if length < 8 {
		return &IncorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check size.
	numSettings := int(bytesToUint32(data[8:12]))
	if length < 4+(8*numSettings) {
		return &IncorrectDataLength{length, 4 + (8 * numSettings)}
	}

	// Check control bit.
	if data[0]&0x80 == 0 {
		return &InvalidField{"Control bit", 0, 1}
	}

	// Check type.
	if data[2] != 0 || data[3] != 4 {
		return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 4}
	}

	frame.version = version
	frame.Flags = data[4]
	frame.Settings = make([]*Setting, numSettings)
	offset := 12
	for i := 0; i < numSettings; i++ {
		switch version {
		case 3:
			frame.Settings[i] = &Setting{
				Flags: data[offset],
				ID:    bytesToUint24(data[offset+1 : offset+4]),
				Value: bytesToUint32(data[offset+4 : offset+8]),
			}
		case 2:
			frame.Settings[i] = &Setting{
				Flags: data[offset+4],
				ID:    bytesToUint24Reverse(data[offset+0 : offset+3]),
				Value: bytesToUint32(data[offset+4 : offset+8]),
			}
		}

		offset += 8
	}

	return nil
}

func (frame *SettingsFrame) StreamID() uint32 {
	return 0
}

func (frame *SettingsFrame) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.Flags&FLAG_SETTINGS_CLEAR_SETTINGS != 0 {
		flags += "FLAG_SETTINGS_CLEAR_SETTINGS "
	}
	if flags == "" {
		flags = "[NONE]"
	}

	buf.WriteString("SETTINGS {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Settings:"))
	for _, setting := range frame.Settings {
		buf.WriteString("\n\t\t" + setting.String())
	}
	buf.WriteString(fmt.Sprintln("}"))

	return buf.String()
}

func (frame *SettingsFrame) Version() uint16 {
	return frame.version
}

func (frame *SettingsFrame) WriteTo(writer io.Writer) error {
	bytes, err := frame.Bytes()
	if err != nil {
		return err
	}
	_, err = writer.Write(bytes)
	return err
}

type settingsSorter []*Setting

func (s settingsSorter) Len() int {
	return len(s)
}

func (s settingsSorter) Less(i, j int) bool {
	return s[i].ID < s[j].ID
}

func (s settingsSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type Setting struct {
	Flags byte
	ID    uint32
	Value uint32
}

func (s *Setting) Bytes(version uint16) []byte {
	out := make([]byte, 8)

	switch version {
	case 3:
		out[0] = s.Flags
		out[1] = byte(s.ID >> 16)
		out[2] = byte(s.ID >> 8)
		out[3] = byte(s.ID)
	case 2:
		out[0] = byte(s.ID)
		out[1] = byte(s.ID >> 8)
		out[2] = byte(s.ID >> 16)
		out[3] = s.Flags
	}

	out[4] = byte(s.Value >> 24)
	out[5] = byte(s.Value >> 16)
	out[6] = byte(s.Value >> 8)
	out[7] = byte(s.Value)

	return out
}

func (frame *Setting) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("SETTING {\n\t\t\t")
	buf.WriteString(fmt.Sprintf("Flags:         %d\n\t\t\t", frame.Flags))
	buf.WriteString(fmt.Sprintf("ID:            %d\n\t\t\t", frame.ID))
	buf.WriteString(fmt.Sprintf("Value:         %d\n\t\t}\n", frame.Value))

	return buf.String()
}

/************
 *** NOOP ***
 ************/
type NoopFrame struct{}

func (frame *NoopFrame) Bytes() ([]byte, error) {
	out := make([]byte, 8)

	out[0] = 0x80 // Control bit and Version
	out[1] = 2    // Version
	out[2] = 0    // Type
	out[3] = 5    // Type
	out[4] = 0    // Flags
	out[5] = 0    // Length
	out[6] = 0    // Length
	out[7] = 0    // Length

	return out, nil
}

func (frame *NoopFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *NoopFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *NoopFrame) Parse(reader *bufio.Reader) error {
	// Read in data.
	data := make([]byte, 8)
	remaining := 8
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check it's a control frame.
	if data[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, NOOP}
	}

	// Check it's a NOOP.
	if bytesToUint16(data[2:4]) != NOOP {
		return &IncorrectFrame{int(bytesToUint16(data[2:4])), NOOP}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 || !SupportedVersion(2) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 0 {
		return &IncorrectDataLength{length, 0}
	}

	return nil
}

func (frame *NoopFrame) StreamID() uint32 {
	return 0
}

func (frame *NoopFrame) String() string {
	return "NOOP {\n\tVersion: 2\n}\n"
}

func (frame *NoopFrame) Version() uint16 {
	return 2
}

func (frame *NoopFrame) WriteTo(writer io.Writer) error {
	return nil
}

/************
 *** PING ***
 ************/
type PingFrame struct {
	version uint16
	PingID  uint32
}

func (frame *PingFrame) Bytes() ([]byte, error) {
	out := make([]byte, 12)

	out[0] = 0x80 | byte(frame.version>>8) // Control bit and Version
	out[1] = byte(frame.version)           // Version
	out[2] = 0                             // Type
	out[3] = 6                             // Type
	out[4] = 0                             // Flags
	out[5] = 0                             // Length
	out[6] = 0                             // Length
	out[7] = 4                             // Length
	out[8] = byte(frame.PingID >> 24)      // Ping ID
	out[9] = byte(frame.PingID >> 16)      // Ping ID
	out[10] = byte(frame.PingID >> 8)      // Ping ID
	out[11] = byte(frame.PingID)           // Ping ID

	return out, nil
}

func (frame *PingFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *PingFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *PingFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, PING}
	}

	// Check it's a PING.
	if bytesToUint16(start[2:4]) != PING {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), PING}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if length != 4 {
		return &IncorrectDataLength{length, 4}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check flags.
	if (data[4]) != 0 {
		return &InvalidField{"Flags", int(data[4]), 0}
	}

	frame.version = version
	frame.PingID = bytesToUint32(data[8:12])

	return nil
}

func (frame *PingFrame) StreamID() uint32 {
	return 0
}

func (frame *PingFrame) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("PING {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Ping ID:              %d\n}\n", frame.PingID))

	return buf.String()
}

func (frame *PingFrame) Version() uint16 {
	return frame.version
}

func (frame *PingFrame) WriteTo(writer io.Writer) error {
	bytes, err := frame.Bytes()
	if err != nil {
		return err
	}
	_, err = writer.Write(bytes)
	return err
}

/**************
 *** GOAWAY ***
 **************/
type GoawayFrame struct {
	version          uint16
	LastGoodStreamID uint32
	StatusCode       uint32
}

func (frame *GoawayFrame) Bytes() ([]byte, error) {
	size := 12
	if frame.version > 2 {
		size += 4
	}
	out := make([]byte, size)

	out[0] = 0x80 | byte(frame.version>>8)           // Control bit and Version
	out[1] = byte(frame.version)                     // Version
	out[2] = 0                                       // Type
	out[3] = 7                                       // Type
	out[4] = 0                                       // Flags
	out[5] = 0                                       // Length
	out[6] = 0                                       // Length
	out[7] = 8                                       // Length
	out[8] = byte(frame.LastGoodStreamID>>24) & 0x7f // Last Good Stream ID
	out[9] = byte(frame.LastGoodStreamID >> 16)      // Last Good Stream ID
	out[10] = byte(frame.LastGoodStreamID >> 8)      // Last Good Stream ID
	out[11] = byte(frame.LastGoodStreamID)           // Last Good Stream ID

	if frame.version > 2 {
		out[12] = byte(frame.StatusCode >> 24) // Status Code
		out[13] = byte(frame.StatusCode >> 16) // Status Code
		out[14] = byte(frame.StatusCode >> 8)  // Status Code
		out[15] = byte(frame.StatusCode)       // Status Code
	}

	return out, nil
}

func (frame *GoawayFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *GoawayFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *GoawayFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, GOAWAY}
	}

	// Check it's a GOAWAY.
	if bytesToUint16(start[2:4]) != GOAWAY {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), GOAWAY}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if version == 3 && length != 8 {
		return &IncorrectDataLength{length, 8}
	} else if version == 2 && length != 4 {
		return &IncorrectDataLength{length, 4}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return &InvalidField{"Unused", 1, 0}
	}

	// Check flags.
	if (data[4]) != 0 {
		return &InvalidField{"Flags", int(data[4]), 0}
	}

	frame.version = version
	frame.LastGoodStreamID = bytesToUint31(data[8:12])
	if version > 2 {
		frame.StatusCode = bytesToUint32(data[12:16])
	}

	return nil
}

func (frame *GoawayFrame) StreamID() uint32 {
	return 0
}

func (frame *GoawayFrame) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("GOAWAY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Last good stream ID:  %d\n\t", frame.LastGoodStreamID))

	if frame.version > 2 {
		buf.WriteString(fmt.Sprintf("Status code:          %d\n}\n", frame.StatusCode))
	}

	return buf.String()
}

func (frame *GoawayFrame) Version() uint16 {
	return frame.version
}

func (frame *GoawayFrame) WriteTo(writer io.Writer) error {
	bytes, err := frame.Bytes()
	if err != nil {
		return err
	}
	_, err = writer.Write(bytes)
	return err
}

/***************
 *** HEADERS ***
 ***************/
type HeadersFrame struct {
	version        uint16
	Flags          byte
	streamID       uint32
	Headers        http.Header
	rawHeaders     []byte
	headersWritten bool
	headersDecoded bool
}

func (frame *HeadersFrame) Bytes() ([]byte, error) {
	if !frame.headersWritten {
		return nil, errors.New("spdy: Error: Headers not written.")
	}

	headers := frame.rawHeaders
	length := 4 + len(headers)
	start := 12
	if frame.version == 2 {
		length += 2
		start += 2
	}
	out := make([]byte, start, 8+length)

	out[0] = 0x80 | byte(frame.version>>8)   // Control bit and Version
	out[1] = byte(frame.version)             // Version
	out[2] = 0                               // Type
	out[3] = 8                               // Type
	out[4] = frame.Flags                     // Flags
	out[5] = byte(length >> 16)              // Length
	out[6] = byte(length >> 8)               // Length
	out[7] = byte(length)                    // Length
	out[8] = byte(frame.streamID>>24) & 0x7f // Stream ID
	out[9] = byte(frame.streamID >> 16)      // Stream ID
	out[10] = byte(frame.streamID >> 8)      // Stream ID
	out[11] = byte(frame.streamID)           // Stream ID
	out = append(out, headers...)            // Name/Value Header Block

	return out, nil
}

func (frame *HeadersFrame) DecodeHeaders(decom *Decompressor) error {
	if frame.headersDecoded {
		return nil
	}

	headers, err := decodeHeaders(frame.rawHeaders, decom, frame.version)
	if err != nil {
		return err
	}
	frame.Headers = headers
	frame.headersDecoded = true
	return nil
}

func (frame *HeadersFrame) EncodeHeaders(com *Compressor) error {
	data, err := encodeHeaders(frame.Headers, com, frame.version)
	if err != nil {
		return err
	}
	frame.rawHeaders = data
	frame.headersWritten = true
	return nil
}

func (frame *HeadersFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, HEADERS}
	}

	// Check it's a HEADERS.
	if bytesToUint16(start[2:4]) != HEADERS {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), HEADERS}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if version == 3 && length < 4 {
		return &IncorrectDataLength{length, 4}
	} else if version == 2 && length < 8 {
		return &IncorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return &InvalidField{"Unused", 1, 0}
	} else if version == 2 && data[12] != 0 {
		return &InvalidField{"Unused", int(data[12]), 0}
	} else if version == 2 && data[13] != 0 {
		return &InvalidField{"Unused", int(data[13]), 0}
	}

	frame.version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	frame.Flags = data[4]
	frame.streamID = bytesToUint31(data[8:12])

	offset := 12
	if version == 2 {
		offset += 2
	}
	frame.rawHeaders = data[offset:]

	return nil
}

func (frame *HeadersFrame) StreamID() uint32 {
	return frame.streamID
}

func (frame *HeadersFrame) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.Flags&FLAG_FIN != 0 {
		flags += "FLAG_FIN "
	}
	if flags == "" {
		flags = "[NONE]"
	}

	buf.WriteString("HEADERS {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Headers:              %v\n}\n", frame.Headers))

	return buf.String()
}

func (frame *HeadersFrame) Version() uint16 {
	return frame.version
}

func (frame *HeadersFrame) WriteTo(writer io.Writer) error {
	if !frame.headersWritten {
		return errors.New("spdy: Error: Headers not written.")
	}

	headers := frame.rawHeaders
	length := 4 + len(headers)
	start := 12
	if frame.version == 2 {
		length += 2
		start += 2
	}
	out := make([]byte, start)

	out[0] = 0x80 | byte(frame.version>>8)   // Control bit and Version
	out[1] = byte(frame.version)             // Version
	out[2] = 0                               // Type
	out[3] = 8                               // Type
	out[4] = frame.Flags                     // Flags
	out[5] = byte(length >> 16)              // Length
	out[6] = byte(length >> 8)               // Length
	out[7] = byte(length)                    // Length
	out[8] = byte(frame.streamID>>24) & 0x7f // Stream ID
	out[9] = byte(frame.streamID >> 16)      // Stream ID
	out[10] = byte(frame.streamID >> 8)      // Stream ID
	out[11] = byte(frame.streamID)           // Stream ID

	_, err := writer.Write(out)
	if err != nil {
		return err
	}

	_, err = writer.Write(headers)
	return err
}

/*********************
 *** WINDOW_UPDATE ***
 *********************/
type WindowUpdateFrame struct {
	version         uint16
	streamID        uint32
	DeltaWindowSize uint32
}

func (frame *WindowUpdateFrame) Bytes() ([]byte, error) {
	out := make([]byte, 12)

	out[0] = 0x80 | byte(frame.version>>8)           // Control bit and Version
	out[1] = byte(frame.version)                     // Version
	out[2] = 0                                       // Type
	out[3] = 8                                       // Type
	out[4] = 0                                       // Flags
	out[5] = 0                                       // Length
	out[6] = 0                                       // Length
	out[7] = 8                                       // Length
	out[8] = byte(frame.streamID>>24) & 0x7f         // Stream ID
	out[9] = byte(frame.streamID >> 16)              // Stream ID
	out[10] = byte(frame.streamID >> 8)              // Stream ID
	out[11] = byte(frame.streamID)                   // Stream ID
	out[12] = byte(frame.DeltaWindowSize>>24) & 0x7f // Delta Window Size
	out[13] = byte(frame.DeltaWindowSize >> 16)      // Delta Window Size
	out[14] = byte(frame.DeltaWindowSize >> 8)       // Delta Window Size
	out[15] = byte(frame.DeltaWindowSize)            // Delta Window Size

	return out, nil
}

func (frame *WindowUpdateFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *WindowUpdateFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *WindowUpdateFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, WINDOW_UPDATE}
	}

	// Check it's a WINDOW_UPDATE.
	if bytesToUint16(start[2:4]) != WINDOW_UPDATE {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), WINDOW_UPDATE}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if length != 8 {
		return &IncorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check unused space.
	if (data[8]>>7)|(data[12]>>7) != 0 {
		return &InvalidField{"Unused", 1, 0}
	}

	// Ignored in SPDY/2.
	if version == 2 {
		return nil
	}

	frame.version = version
	frame.streamID = bytesToUint31(data[8:12])
	frame.DeltaWindowSize = bytesToUint32(data[12:16]) & 0x7f

	return nil
}

func (frame *WindowUpdateFrame) StreamID() uint32 {
	return frame.streamID
}

func (frame *WindowUpdateFrame) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("WINDOW_UPDATE {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Delta window size:    %d\n}\n", frame.DeltaWindowSize))

	return buf.String()
}

func (frame *WindowUpdateFrame) Version() uint16 {
	return frame.version
}

func (frame *WindowUpdateFrame) WriteTo(writer io.Writer) error {
	if frame.version == 2 {
		return nil
	}

	bytes, err := frame.Bytes()
	if err != nil {
		return err
	}
	_, err = writer.Write(bytes)
	return err
}

/******************
 *** CREDENTIAL ***
 ******************/
type CredentialFrame struct {
	version      uint16
	Slot         uint16
	Proof        []byte
	Certificates []*x509.Certificate
}

func (frame *CredentialFrame) Bytes() ([]byte, error) {

	proofLength := len(frame.Proof)
	certsLength := 0
	for _, cert := range frame.Certificates {
		certsLength += len(cert.Raw)
	}

	length := 6 + proofLength + certsLength
	out := make([]byte, 14, 8+length)

	out[0] = 0x80 | byte(frame.version>>8) // Control bit and Version
	out[1] = byte(frame.version)           // Version
	out[2] = 0                             // Type
	out[3] = 10                            // Type
	out[4] = 0                             // Flags
	out[5] = byte(length >> 16)            // Length
	out[6] = byte(length >> 8)             // Length
	out[7] = byte(length)                  // Length
	out[8] = byte(frame.Slot >> 8)         // Slot
	out[9] = byte(frame.Slot)              // Slot
	out[10] = byte(proofLength >> 24)      // Proof Length
	out[11] = byte(proofLength >> 16)      // Proof Length
	out[12] = byte(proofLength >> 8)       // Proof Length
	out[13] = byte(proofLength)            // Proof Length
	out = append(out, frame.Proof...)      // Proof
	for _, cert := range frame.Certificates {
		out = append(out, cert.Raw...) // Certificates
	}

	return out, nil
}

func (frame *CredentialFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *CredentialFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *CredentialFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a control frame.
	if start[0]&0x80 == 0 {
		return &IncorrectFrame{DATA_FRAME, CREDENTIAL}
	}

	// Check it's a CREDENTIAL.
	if bytesToUint16(start[2:4]) != CREDENTIAL {
		return &IncorrectFrame{int(bytesToUint16(start[2:4])), CREDENTIAL}
	}

	// Check version and adapt accordingly.
	version := (uint16(start[0]&0x7f) << 8) + uint16(start[1])
	if !SupportedVersion(version) || version < 3 {
		return UnsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if length < 6 {
		return &IncorrectDataLength{length, 6}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	// Check flags.
	if (data[4]) != 0 {
		return &InvalidField{"Flags", int(data[4]), 0}
	}

	frame.version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	frame.Slot = bytesToUint16(data[8:10])

	proofLen := int(bytesToUint32(data[10:14]))
	if proofLen > 0 {
		frame.Proof = data[14 : 14+proofLen]
	} else {
		frame.Proof = []byte{}
	}

	numCerts := 0
	for offset := 14 + proofLen; offset < length; {
		offset += int(bytesToUint32(data[offset:offset+4])) + 4
		numCerts++
	}

	frame.Certificates = make([]*x509.Certificate, numCerts)
	for i, offset := 0, 14+proofLen; offset < length; i++ {
		length := int(bytesToUint32(data[offset : offset+4]))
		rawCert := data[offset+4 : offset+4+length]
		frame.Certificates[i], err = x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}
		offset += length + 4
	}

	return nil
}

func (frame *CredentialFrame) StreamID() uint32 {
	return 0
}

func (frame *CredentialFrame) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("CREDENTIAL {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              %d\n\t", frame.version))
	buf.WriteString(fmt.Sprintf("Slot:                 %d\n\t", frame.Slot))
	buf.WriteString(fmt.Sprintf("Proof:                %v\n\t", frame.Proof))
	buf.WriteString(fmt.Sprintf("Certificates:         %v\n}\n", frame.Certificates))

	return buf.String()
}

func (frame *CredentialFrame) Version() uint16 {
	return frame.version
}

func (frame *CredentialFrame) WriteTo(writer io.Writer) error {
	proofLength := len(frame.Proof)
	certsLength := 0
	for _, cert := range frame.Certificates {
		certsLength += len(cert.Raw)
	}

	length := 6 + proofLength + certsLength
	out := make([]byte, 14, 8+length)

	out[0] = 0x80 | byte(frame.version>>8) // Control bit and Version
	out[1] = byte(frame.version)           // Version
	out[2] = 0                             // Type
	out[3] = 10                            // Type
	out[4] = 0                             // Flags
	out[5] = byte(length >> 16)            // Length
	out[6] = byte(length >> 8)             // Length
	out[7] = byte(length)                  // Length
	out[8] = byte(frame.Slot >> 8)         // Slot
	out[9] = byte(frame.Slot)              // Slot
	out[10] = byte(proofLength >> 24)      // Proof Length
	out[11] = byte(proofLength >> 16)      // Proof Length
	out[12] = byte(proofLength >> 8)       // Proof Length
	out[13] = byte(proofLength)            // Proof Length

	_, err := writer.Write(out)
	if err != nil {
		return err
	}

	_, err = writer.Write(frame.Proof)
	if err != nil {
		return err
	}

	for _, cert := range frame.Certificates {
		_, err = writer.Write(cert.Raw)
		if err != nil {
			return err
		}
	}

	return nil
}

/************
 *** DATA ***
 ************/
type DataFrame struct {
	streamID uint32
	Flags    byte
	Data     []byte
}

func (frame *DataFrame) Bytes() ([]byte, error) {
	length := len(frame.Data)
	out := make([]byte, 8, 8+length)

	out[0] = byte(frame.streamID>>24) & 0x7f // Control bit and Stream ID
	out[1] = byte(frame.streamID >> 16)      // Stream ID
	out[2] = byte(frame.streamID >> 8)       // Stream ID
	out[3] = byte(frame.streamID)            // Stream ID
	out[4] = frame.Flags                     // Flags
	out[5] = byte(length >> 16)              // Length
	out[6] = byte(length >> 8)               // Length
	out[7] = byte(length)                    // Length
	out = append(out, frame.Data...)         // Data

	return out, nil
}

func (frame *DataFrame) DecodeHeaders(decomp *Decompressor) error {
	return nil
}

func (frame *DataFrame) EncodeHeaders(comp *Compressor) error {
	return nil
}

func (frame *DataFrame) Parse(reader *bufio.Reader) error {
	start, err := reader.Peek(8)
	if err != nil {
		return err
	}

	// Check it's a data frame.
	if start[0]&0x80 == 1 {
		return &IncorrectFrame{CONTROL_FRAME, DATA_FRAME}
	}

	// Get and check length.
	length := int(bytesToUint24(start[5:8]))
	if length < 1 && start[4] == 0 {
		return &IncorrectDataLength{length, 1}
	} else if length > MAX_FRAME_SIZE-8 {
		return FrameTooLarge
	}

	// Read in data.
	data := make([]byte, 8+length)
	remaining := 8 + length
	in := data[:]
	for remaining > 0 {
		if n, err := reader.Read(in); err != nil {
			return err
		} else {
			in = in[n:]
			remaining -= n
		}
	}

	frame.streamID = bytesToUint31(data[0:4])
	frame.Flags = data[4]
	if length > 0 {
		frame.Data = data[8:]
	} else {
		frame.Data = []byte{}
	}

	return nil
}

func (frame *DataFrame) StreamID() uint32 {
	return frame.streamID
}

func (frame *DataFrame) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.Flags&FLAG_FIN != 0 {
		flags += "FLAG_FIN "
	}
	if flags == "" {
		flags = "[NONE]"
	}

	buf.WriteString("DATA {\n\t")
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Length:               %d\n\t", len(frame.Data)))
	buf.WriteString(fmt.Sprintf("Data:                 %v\n}\n", frame.Data))

	return buf.String()
}

func (frame *DataFrame) Version() uint16 {
	return 0
}

func (frame *DataFrame) WriteTo(writer io.Writer) error {
	length := len(frame.Data)
	if length > MAX_DATA_SIZE {
		return errors.New("Error: Data size too large.")
	}
	if length == 0 && frame.Flags&FLAG_FIN == 0 {
		return errors.New("Error: Data is empty.")
	}

	out := make([]byte, 8)

	out[0] = byte(frame.streamID>>24) & 0x7f // Control bit and Stream ID
	out[1] = byte(frame.streamID >> 16)      // Stream ID
	out[2] = byte(frame.streamID >> 8)       // Stream ID
	out[3] = byte(frame.streamID)            // Stream ID
	out[4] = frame.Flags                     // Flags
	out[5] = byte(length >> 16)              // Length
	out[6] = byte(length >> 8)               // Length
	out[7] = byte(length)                    // Length

	_, err := writer.Write(out)
	if err != nil {
		return err
	}

	_, err = writer.Write(frame.Data)
	return err
}

func decodeHeaders(data []byte, dec *Decompressor, version uint16) (http.Header, error) {
	return dec.Decompress(data)
}

func encodeHeaders(h http.Header, enc *Compressor, version uint16) ([]byte, error) {
	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Connection")
	h.Del("Transfer-Encoding")

	length := 4
	num := len(h)
	lens := make(map[string]int)
	for name, values := range h {
		length += len(name) + 8
		lens[name] = len(values) - 1
		for _, value := range values {
			length += len(value)
			lens[name] += len(value)
		}
	}

	out := make([]byte, length)
	switch version {
	case 3:
		out[0] = byte(num >> 24)
		out[1] = byte(num >> 16)
		out[2] = byte(num >> 8)
		out[3] = byte(num)
	case 2:
		out[0] = byte(num >> 8)
		out[1] = byte(num)
	}

	offset := 4
	if version == 2 {
		offset = 2
	}
	for name, values := range h {
		nLen := len(name)
		switch version {
		case 3:
			out[offset+0] = byte(nLen >> 24)
			out[offset+1] = byte(nLen >> 16)
			out[offset+2] = byte(nLen >> 8)
			out[offset+3] = byte(nLen)
			offset += 4
		case 2:
			out[offset+0] = byte(nLen >> 8)
			out[offset+1] = byte(nLen)
			offset += 2
		}

		for i, b := range []byte(strings.ToLower(name)) {
			out[offset+i] = b
		}

		offset += nLen

		vLen := lens[name]
		switch version {
		case 3:
			out[offset+0] = byte(vLen >> 24)
			out[offset+1] = byte(vLen >> 16)
			out[offset+2] = byte(vLen >> 8)
			out[offset+3] = byte(vLen)
			offset += 4
		case 2:
			out[offset+0] = byte(vLen >> 8)
			out[offset+1] = byte(vLen)
			offset += 2
		}

		for n, value := range values {
			for i, b := range []byte(value) {
				out[offset+i] = b
			}
			offset += len(value)
			if n < len(values)-1 {
				out[offset] = '\x00'
				offset += 1
			}
		}
	}

	return enc.Compress(out)
}

func cloneHeaders(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func updateHeaders(older, newer http.Header) {
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

/*** HELPER FUNCTIONS ***/

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

func FrameName(frameType int) string {
	return frameNames[frameType]
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

func bytesToUint31(b []byte) uint32 {
	return (uint32(b[0]&0x7f) << 24) + (uint32(b[1]) << 16) + (uint32(b[2]) << 8) + uint32(b[3])
}

/*** ERRORS ***/
type IncorrectFrame struct {
	got, expected int
}

func (i *IncorrectFrame) Error() string {
	return fmt.Sprintf("Error: Frame %s tried to parse data for a %s.", FrameName(i.expected), FrameName(i.got))
}

type UnsupportedVersion uint16

func (u UnsupportedVersion) Error() string {
	return fmt.Sprintf("Error: Unsupported SPDY version: %d.\n", u)
}

type IncorrectDataLength struct {
	got, expected int
}

func (i *IncorrectDataLength) Error() string {
	return fmt.Sprintf("Error: Incorrect amount of data for frame: got %d bytes, expected %d.", i.got, i.expected)
}

var FrameTooLarge = errors.New("Error: Frame too large.")

type InvalidField struct {
	field         string
	got, expected int
}

func (i *InvalidField) Error() string {
	return fmt.Sprintf("Error: Field %q recieved invalid data %d, expecting %d.", i.field, i.got, i.expected)
}
