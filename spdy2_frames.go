package spdy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
)

// ReadFrame reads and parses a frame from reader.
func readFrameV2(reader *bufio.Reader) (frame Frame, err error) {
	start, err := reader.Peek(4)
	if err != nil {
		return nil, err
	}

	if start[0] != 128 {
		frame = new(dataFrameV2)
		_, err = frame.ReadFrom(reader)
		return frame, err
	}

	switch bytesToUint16(start[2:4]) {
	case SYN_STREAM:
		frame = new(synStreamFrameV2)
	case SYN_REPLY:
		frame = new(synReplyFrameV2)
	case RST_STREAM:
		frame = new(rstStreamFrameV2)
	case SETTINGS:
		frame = new(settingsFrameV2)
	case NOOP:
		frame = new(noopFrameV2)
	case PING:
		frame = new(pingFrameV2)
	case GOAWAY:
		frame = new(goawayFrameV2)
	case HEADERS:
		frame = new(headersFrameV2)

	default:
		return nil, errors.New("Error Failed to parse frame type.")
	}

	_, err = frame.ReadFrom(reader)
	return frame, err
}

/******************
 *** SYN_STREAM ***
 ******************/
type synStreamFrameV2 struct {
	flags         Flags
	streamID      StreamID
	AssocStreamID StreamID
	Priority      Priority
	Header        http.Header
	rawHeader     []byte
}

func (frame *synStreamFrameV2) Compress(com Compressor) error {
	if frame.rawHeader != nil {
		return nil
	}

	data, err := com.Compress(frame.Header)
	if err != nil {
		return err
	}

	frame.rawHeader = data
	return nil
}

func (frame *synStreamFrameV2) Decompress(decom Decompressor) error {
	if frame.Header != nil {
		return nil
	}

	header, err := decom.Decompress(frame.rawHeader)
	if err != nil {
		return err
	}

	frame.Header = header
	frame.rawHeader = nil
	return nil
}

func (frame *synStreamFrameV2) Flags() Flags {
	return frame.flags
}

func (frame *synStreamFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 18)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 18, &incorrectFrame{DATA_FRAME, SYN_STREAM, 2}
	}

	// Check it's a SYN_STREAM.
	if bytesToUint16(data[2:4]) != SYN_STREAM {
		return 18, &incorrectFrame{int(bytesToUint16(data[2:4])), SYN_STREAM, 2}
	}

	// Check version.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 18, unsupportedVersion(version)
	}

	// Check unused space.
	if (data[8]>>7) != 0 || (data[12]>>7) != 0 {
		return 18, &invalidField{"Unused", 1, 0}
	} else if (data[16] & 0x1f) != 0 {
		return 18, &invalidField{"Unused", int(data[16] & 0x1f), 0}
	} else if data[17] != 0 {
		return 18, &invalidField{"Unused", int(data[17]), 0}
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 12 {
		return 18, &incorrectDataLength{length, 12}
	} else if length > MAX_FRAME_SIZE-18 {
		return 18, frameTooLarge
	}

	// Read in data.
	header, err := read(reader, length-10)
	if err != nil {
		return 18, err
	}

	frame.flags = Flags(data[4])
	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.AssocStreamID = StreamID(bytesToUint32(data[12:16]))
	frame.Priority = Priority(data[16] >> 5)
	frame.rawHeader = header

	if !frame.streamID.Valid() {
		return 18, streamIDTooLarge
	}
	if !frame.AssocStreamID.Valid() {
		return 18, streamIDTooLarge
	}

	return int64(length + 8), nil
}

func (frame *synStreamFrameV2) StreamID() StreamID {
	return frame.streamID
}

func (frame *synStreamFrameV2) String() string {
	buf := new(bytes.Buffer)
	flags := ""
	if frame.flags.FIN() {
		flags += " FLAG_FIN"
	}
	if frame.flags.UNIDIRECTIONAL() {
		flags += " FLAG_UNIDIRECTIONAL"
	}
	if flags == "" {
		flags = "[NONE]"
	} else {
		flags = flags[1:]
	}

	buf.WriteString("SYN_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Associated Stream ID: %d\n\t", frame.AssocStreamID))
	buf.WriteString(fmt.Sprintf("Priority:             %d\n\t", frame.Priority))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *synStreamFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader != nil {
		return 0, errors.New("Error: Headers not written.")
	}
	if !frame.streamID.Valid() {
		return 0, streamIDTooLarge
	}
	if !frame.AssocStreamID.Valid() {
		return 0, streamIDTooLarge
	}

	header := frame.rawHeader
	length := 10 + len(header)
	out := make([]byte, 18)

	out[0] = 128                       // Control bit and Version
	out[1] = 3                         // Version
	out[2] = 0                         // Type
	out[3] = 1                         // Type
	out[4] = byte(frame.flags)         // Flags
	out[5] = byte(length >> 16)        // Length
	out[6] = byte(length >> 8)         // Length
	out[7] = byte(length)              // Length
	out[8] = frame.streamID.b1()       // Stream ID
	out[9] = frame.streamID.b2()       // Stream ID
	out[10] = frame.streamID.b3()      // Stream ID
	out[11] = frame.streamID.b4()      // Stream ID
	out[12] = frame.AssocStreamID.b1() // Associated Stream ID
	out[13] = frame.AssocStreamID.b2() // Associated Stream ID
	out[14] = frame.AssocStreamID.b3() // Associated Stream ID
	out[15] = frame.AssocStreamID.b4() // Associated Stream ID
	out[16] = frame.Priority.Byte(2)   // Priority and Unused
	out[17] = 0                        // Unused

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, header)
	if err != nil {
		return 18, err
	}

	return int64(len(header) + 18), nil
}

/*****************
 *** SYN_REPLY ***
 *****************/
type synReplyFrameV2 struct {
	flags     Flags
	streamID  StreamID
	Header    http.Header
	rawHeader []byte
}

func (frame *synReplyFrameV2) Compress(com Compressor) error {
	if frame.rawHeader != nil {
		return nil
	}

	data, err := com.Compress(frame.Header)
	if err != nil {
		return err
	}

	frame.rawHeader = data
	return nil
}

func (frame *synReplyFrameV2) Decompress(decom Decompressor) error {
	if frame.Header != nil {
		return nil
	}

	header, err := decom.Decompress(frame.rawHeader)
	if err != nil {
		return err
	}

	frame.Header = header
	frame.rawHeader = nil
	return nil
}

func (frame *synReplyFrameV2) Flags() Flags {
	return frame.flags
}

func (frame *synReplyFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 14)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAME, SYN_REPLY, 2}
	}

	// Check it's a SYN_REPLY.
	if bytesToUint16(data[2:4]) != SYN_REPLY {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), SYN_REPLY, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 12, unsupportedVersion(version)
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 12, &invalidField{"Unused", 1, 0}
	} else if data[12] != 0 {
		return 12, &invalidField{"Unused", int(data[12]), 0}
	} else if data[13] != 0 {
		return 12, &invalidField{"Unused", int(data[13]), 0}
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 8 {
		return 12, &incorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return 12, frameTooLarge
	}

	// Read in data.
	header, err := read(reader, length-4)
	if err != nil {
		return 12, err
	}

	frame.flags = Flags(data[4])
	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.rawHeader = header

	return int64(length + 8), nil
}

func (frame *synReplyFrameV2) StreamID() StreamID {
	return frame.streamID
}

func (frame *synReplyFrameV2) String() string {
	buf := new(bytes.Buffer)
	flags := ""
	if frame.flags.FIN() {
		flags += " FLAG_FIN"
	}
	if flags == "" {
		flags = "[NONE]"
	} else {
		flags = flags[1:]
	}

	buf.WriteString("SYN_REPLY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *synReplyFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Header not written.")
	}
	if !frame.streamID.Valid() {
		return 0, streamIDTooLarge
	}

	header := frame.rawHeader
	length := 6 + len(header)
	out := make([]byte, 14)

	out[0] = 128                  // Control bit and Version
	out[1] = 3                    // Version
	out[2] = 0                    // Type
	out[3] = 2                    // Type
	out[4] = byte(frame.flags)    // Flags
	out[5] = byte(length >> 16)   // Length
	out[6] = byte(length >> 8)    // Length
	out[7] = byte(length)         // Length
	out[8] = frame.streamID.b1()  // Stream ID
	out[9] = frame.streamID.b2()  // Stream ID
	out[10] = frame.streamID.b3() // Stream ID
	out[11] = frame.streamID.b4() // Stream ID

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, header)
	if err != nil {
		return 14, err
	}

	return int64(len(header) + 12), nil
}

/******************
 *** RST_STREAM ***
 ******************/
type rstStreamFrameV2 struct {
	streamID StreamID
	Status   StatusCode
}

func (frame *rstStreamFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *rstStreamFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *rstStreamFrameV2) Flags() Flags {
	return 0
}

func (frame *rstStreamFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 16, &incorrectFrame{DATA_FRAME, RST_STREAM, 2}
	}

	// Check it's a RST_STREAM.
	if bytesToUint16(data[2:4]) != RST_STREAM {
		return 16, &incorrectFrame{int(bytesToUint16(data[2:4])), RST_STREAM, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 16, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 8 {
		return 16, &incorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return 16, frameTooLarge
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 16, &invalidField{"Unused", 1, 0}
	}

	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.Status = StatusCode(bytesToUint32(data[12:16]))

	if !frame.streamID.Valid() {
		return 16, streamIDTooLarge
	}

	return 16, nil
}

func (frame *rstStreamFrameV2) StreamID() StreamID {
	return frame.streamID
}

func (frame *rstStreamFrameV2) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("RST_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Status code:          %s\n}\n", frame.Status))

	return buf.String()
}

func (frame *rstStreamFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if !frame.streamID.Valid() {
		return 0, streamIDTooLarge
	}

	out := make([]byte, 16)

	out[0] = 128                  // Control bit and Version
	out[1] = 3                    // Version
	out[2] = 0                    // Type
	out[3] = 3                    // Type
	out[4] = 0                    // Flags
	out[5] = 0                    // Length
	out[6] = 0                    // Length
	out[7] = 8                    // Length
	out[8] = frame.streamID.b1()  // Stream ID
	out[9] = frame.streamID.b2()  // Stream ID
	out[10] = frame.streamID.b3() // Stream ID
	out[11] = frame.streamID.b4() // Stream ID
	out[12] = frame.Status.b1()   // Status
	out[13] = frame.Status.b2()   // Status
	out[14] = frame.Status.b3()   // Status
	out[15] = frame.Status.b4()   // Status

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	return 16, nil
}

/****************
 *** SETTINGS ***
 ****************/
type settingsFrameV2 struct {
	flags    Flags
	Settings Settings
}

func (frame *settingsFrameV2) Add(flags Flags, id uint32, value uint32) {
	frame.Settings[id] = &Setting{flags, id, value}
}

func (frame *settingsFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *settingsFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *settingsFrameV2) Flags() Flags {
	return frame.flags
}

func (frame *settingsFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAME, SETTINGS, 2}
	}

	// Check it's a SETTINGS.
	if bytesToUint16(data[2:4]) != SETTINGS {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), SETTINGS, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 12, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 4 {
		return 12, &incorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return 12, frameTooLarge
	}

	// Check size.
	numSettings := int(bytesToUint32(data[8:12]))
	if length != 4+(8*numSettings) {
		return 12, &incorrectDataLength{length, 4 + (8 * numSettings)}
	}

	// Read in data.
	settings, err := read(reader, 8*numSettings)
	if err != nil {
		return 12, err
	}

	frame.flags = Flags(data[4])
	frame.Settings = make(Settings)
	for i := 0; i < numSettings; i++ {
		j := i * 8
		setting := decodeSettingV2(settings[j:])
		if setting == nil {
			return int64(length), errors.New("Error: Failed to parse settings.")
		}
		frame.Settings[setting.ID] = setting
	}

	return int64(length), nil
}

func (frame *settingsFrameV2) StreamID() StreamID {
	return 0
}

func (frame *settingsFrameV2) String() string {
	buf := new(bytes.Buffer)
	flags := ""
	if frame.flags.CLEAR_SETTINGS() {
		flags += " FLAG_SETTINGS_CLEAR_SETTINGS"
	}
	if flags == "" {
		flags = "[NONE]"
	} else {
		flags = flags[1:]
	}

	buf.WriteString("SETTINGS {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", frame.flags))
	buf.WriteString(fmt.Sprintf("Settings:\n"))
	settings := frame.Settings.Settings()
	for _, setting := range settings {
		buf.WriteString("\t\t" + setting.String())
	}
	buf.WriteString("}\n")

	return buf.String()
}

func (frame *settingsFrameV2) WriteTo(writer io.Writer) (int64, error) {
	settings := encodeSettingsV2(frame.Settings)
	numSettings := uint32(len(frame.Settings))
	length := 4 + len(settings)
	out := make([]byte, 12)

	out[0] = 128                     // Control bit and Version
	out[1] = 3                       // Version
	out[2] = 0                       // Type
	out[3] = 4                       // Type
	out[4] = byte(frame.flags)       // Flags
	out[5] = byte(length >> 16)      // Length
	out[6] = byte(length >> 8)       // Length
	out[7] = byte(length)            // Length
	out[8] = byte(numSettings >> 24) // Number of Entries
	out[9] = byte(numSettings >> 16) // Number of Entries
	out[10] = byte(numSettings >> 8) // Number of Entries
	out[11] = byte(numSettings)      // Number of Entries

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, settings)
	if err != nil {
		return 12, err
	}

	return int64(length + 8), nil
}

func decodeSettingV2(data []byte) *Setting {
	if len(data) < 8 {
		return nil
	}

	setting := new(Setting)
	setting.ID = bytesToUint24(data[0:]) // Might need to reverse this.
	setting.Flags = Flags(data[3])
	setting.Value = bytesToUint32(data[4:])

	return setting
}

func encodeSettingsV2(s Settings) []byte {
	if len(s) == 0 {
		return []byte{}
	}

	ids := make([]int, 0, len(s))
	for id := range s {
		ids = append(ids, int(id))
	}

	sort.Sort(sort.IntSlice(ids))

	out := make([]byte, 8*len(s))

	offset := 0
	for _, id := range ids {
		setting := s[uint32(id)]
		out[offset] = byte(setting.ID >> 16)  // Might need to reverse this.
		out[offset+1] = byte(setting.ID >> 8) // Might need to reverse this.
		out[offset+2] = byte(setting.ID)      // Might need to reverse this.
		out[offset+3] = byte(setting.Flags)
		out[offset+4] = byte(setting.Value >> 24)
		out[offset+5] = byte(setting.Value >> 16)
		out[offset+6] = byte(setting.Value >> 8)
		out[offset+7] = byte(setting.Value)
		offset += 8
	}

	return out
}

/************
 *** NOOP ***
 ************/
type noopFrameV2 struct{}

func (frame *noopFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *noopFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *noopFrameV2) Flags() Flags {
	return 0
}

func (frame *noopFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 8)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 8, &incorrectFrame{DATA_FRAME, NOOP, 2}
	}

	// Check it's a PING.
	if bytesToUint16(data[2:4]) != PING {
		return 8, &incorrectFrame{int(bytesToUint16(data[2:4])), NOOP, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 8, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 0 {
		return 8, &incorrectDataLength{length, 0}
	}

	// Check flags.
	if (data[4]) != 0 {
		return 8, &invalidField{"Flags", int(data[4]), 0}
	}

	return 8, nil
}

func (frame *noopFrameV2) StreamID() StreamID {
	return 0
}

func (frame *noopFrameV2) String() string {
	return "NOOP {\n\tVersion:              2\n}\n"
}

func (frame *noopFrameV2) WriteTo(writer io.Writer) (int64, error) {
	return 0, nil
}

/************
 *** PING ***
 ************/
type pingFrameV2 struct {
	PingID uint32
}

func (frame *pingFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *pingFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *pingFrameV2) Flags() Flags {
	return 0
}

func (frame *pingFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAME, PING, 2}
	}

	// Check it's a PING.
	if bytesToUint16(data[2:4]) != PING {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), PING, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 12, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 4 {
		return 12, &incorrectDataLength{length, 4}
	}

	// Check flags.
	if (data[4]) != 0 {
		return 12, &invalidField{"Flags", int(data[4]), 0}
	}

	frame.PingID = bytesToUint32(data[8:12])

	return 12, nil
}

func (frame *pingFrameV2) StreamID() StreamID {
	return 0
}

func (frame *pingFrameV2) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("PING {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Ping ID:              %d\n}\n", frame.PingID))

	return buf.String()
}

func (frame *pingFrameV2) WriteTo(writer io.Writer) (int64, error) {
	out := make([]byte, 12)

	out[0] = 128                      // Control bit and Version
	out[1] = 3                        // Version
	out[2] = 0                        // Type
	out[3] = 6                        // Type
	out[4] = 0                        // Flags
	out[5] = 0                        // Length
	out[6] = 0                        // Length
	out[7] = 4                        // Length
	out[8] = byte(frame.PingID >> 24) // Ping ID
	out[9] = byte(frame.PingID >> 16) // Ping ID
	out[10] = byte(frame.PingID >> 8) // Ping ID
	out[11] = byte(frame.PingID)      // Ping ID

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	return 12, nil
}

/**************
 *** GOAWAY ***
 **************/
type goawayFrameV2 struct {
	LastGoodStreamID StreamID
}

func (frame *goawayFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *goawayFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *goawayFrameV2) Flags() Flags {
	return 0
}

func (frame *goawayFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAME, GOAWAY, 2}
	}

	// Check it's a GOAWAY.
	if bytesToUint16(data[2:4]) != GOAWAY {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), GOAWAY, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 12, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 4 {
		return 12, &incorrectDataLength{length, 4}
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 12, &invalidField{"Unused", 1, 0}
	}

	// Check flags.
	if (data[4]) != 0 {
		return 12, &invalidField{"Flags", int(data[4]), 0}
	}

	frame.LastGoodStreamID = StreamID(bytesToUint32(data[8:12]))

	if !frame.LastGoodStreamID.Valid() {
		return 12, streamIDTooLarge
	}

	return 12, nil
}

func (frame *goawayFrameV2) StreamID() StreamID {
	return 0
}

func (frame *goawayFrameV2) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("GOAWAY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Last good stream ID:  %d\n}\n", frame.LastGoodStreamID))

	return buf.String()
}

func (frame *goawayFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if !frame.LastGoodStreamID.Valid() {
		return 0, streamIDTooLarge
	}

	out := make([]byte, 12)

	out[0] = 128                          // Control bit and Version
	out[1] = 3                            // Version
	out[2] = 0                            // Type
	out[3] = 7                            // Type
	out[4] = 0                            // Flags
	out[5] = 0                            // Length
	out[6] = 0                            // Length
	out[7] = 8                            // Length
	out[8] = frame.LastGoodStreamID.b1()  // Last Good Stream ID
	out[9] = frame.LastGoodStreamID.b2()  // Last Good Stream ID
	out[10] = frame.LastGoodStreamID.b3() // Last Good Stream ID
	out[11] = frame.LastGoodStreamID.b4() // Last Good Stream ID

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	return 12, nil
}

/***************
 *** HEADERS ***
 ***************/
type headersFrameV2 struct {
	flags     Flags
	streamID  StreamID
	Header    http.Header
	rawHeader []byte
}

func (frame *headersFrameV2) Compress(com Compressor) error {
	if frame.rawHeader != nil {
		return nil
	}

	data, err := com.Compress(frame.Header)
	if err != nil {
		return err
	}

	frame.rawHeader = data
	return nil
}

func (frame *headersFrameV2) Decompress(decom Decompressor) error {
	if frame.Header != nil {
		return nil
	}

	header, err := decom.Decompress(frame.rawHeader)
	if err != nil {
		return err
	}

	frame.Header = header
	frame.rawHeader = nil
	return nil
}

func (frame *headersFrameV2) Flags() Flags {
	return frame.flags
}

func (frame *headersFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 14)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 14, &incorrectFrame{DATA_FRAME, HEADERS, 2}
	}

	// Check it's a HEADERS.
	if bytesToUint16(data[2:4]) != HEADERS {
		return 14, &incorrectFrame{int(bytesToUint16(data[2:4])), HEADERS, 2}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return 14, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 6 {
		return 14, &incorrectDataLength{length, 6}
	} else if length > MAX_FRAME_SIZE-8 {
		return 14, frameTooLarge
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 14, &invalidField{"Unused", 1, 0}
	}

	// Read in data.
	header, err := read(reader, length-6)
	if err != nil {
		return 14, err
	}

	frame.flags = Flags(data[4])
	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.rawHeader = header

	if !frame.streamID.Valid() {
		return int64(length + 8), streamIDTooLarge
	}

	return int64(length + 8), nil
}

func (frame *headersFrameV2) StreamID() StreamID {
	return frame.streamID
}

func (frame *headersFrameV2) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.flags.FIN() {
		flags += " FLAG_FIN"
	}
	if flags == "" {
		flags = "[NONE]"
	} else {
		flags = flags[1:]
	}

	buf.WriteString("HEADERS {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *headersFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Headers not written.")
	}
	if !frame.streamID.Valid() {
		return 0, streamIDTooLarge
	}

	header := frame.rawHeader
	length := 4 + len(header)
	out := make([]byte, 14)

	out[0] = 128                  // Control bit and Version
	out[1] = 3                    // Version
	out[2] = 0                    // Type
	out[3] = 8                    // Type
	out[4] = byte(frame.flags)    // Flags
	out[5] = byte(length >> 16)   // Length
	out[6] = byte(length >> 8)    // Length
	out[7] = byte(length)         // Length
	out[8] = frame.streamID.b1()  // Stream ID
	out[9] = frame.streamID.b2()  // Stream ID
	out[10] = frame.streamID.b3() // Stream ID
	out[11] = frame.streamID.b4() // Stream ID

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, header)
	if err != nil {
		return 14, err
	}

	return int64(length + 8), nil
}

/************
 *** DATA ***
 ************/
type dataFrameV2 struct {
	streamID StreamID
	flags    Flags
	Data     []byte
}

func (frame *dataFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *dataFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *dataFrameV2) Flags() Flags {
	return 0
}

func (frame *dataFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 8)
	if err != nil {
		return 0, err
	}

	// Check it's a data frame.
	if data[0]&0x80 == 1 {
		return 8, &incorrectFrame{CONTROL_FRAME, DATA_FRAME, 2}
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length == 0 && data[4] == 0 {
		return 8, &incorrectDataLength{length, 1}
	} else if length > MAX_FRAME_SIZE-8 {
		return 8, frameTooLarge
	}

	// Read in data.
	if length != 0 {
		frame.Data, err = read(reader, length)
		if err != nil {
			return 8, err
		}
	}

	frame.streamID = StreamID(bytesToUint32(data[0:4]))
	frame.flags = Flags(data[4])
	if frame.Data == nil {
		frame.Data = []byte{}
	}

	return int64(length + 8), nil
}

func (frame *dataFrameV2) StreamID() StreamID {
	return frame.streamID
}

func (frame *dataFrameV2) String() string {
	buf := new(bytes.Buffer)

	flags := ""
	if frame.flags.FIN() {
		flags += " FLAG_FIN"
	}
	if flags == "" {
		flags = "[NONE]"
	} else {
		flags = flags[1:]
	}

	buf.WriteString("DATA {\n\t")
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Length:               %d\n\t", len(frame.Data)))
	buf.WriteString(fmt.Sprintf("Data:                 %v\n}\n", frame.Data))

	return buf.String()
}

func (frame *dataFrameV2) WriteTo(writer io.Writer) (int64, error) {
	length := len(frame.Data)
	if length > MAX_DATA_SIZE {
		return 0, errors.New("Error: Data size too large.")
	}
	if length == 0 && !frame.flags.FIN() {
		return 0, errors.New("Error: Data is empty.")
	}

	out := make([]byte, 8)

	out[0] = frame.streamID.b1() // Control bit and Stream ID
	out[1] = frame.streamID.b2() // Stream ID
	out[2] = frame.streamID.b3() // Stream ID
	out[3] = frame.streamID.b4() // Stream ID
	out[4] = byte(frame.flags)   // Flags
	out[5] = byte(length >> 16)  // Length
	out[6] = byte(length >> 8)   // Length
	out[7] = byte(length)        // Length

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, frame.Data)
	if err != nil {
		return 8, err
	}

	return int64(length + 8), nil
}
