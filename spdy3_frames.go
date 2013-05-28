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
)

// ReadFrame reads and parses a frame from reader.
func readFrameV3(reader *bufio.Reader) (frame Frame, err error) {
	start, err := reader.Peek(4)
	if err != nil {
		return nil, err
	}

	if start[0] != 128 {
		frame = new(dataFrameV3)
		_, err = frame.ReadFrom(reader)
		return frame, err
	}

	switch bytesToUint16(start[2:4]) {
	case SYN_STREAMv3:
		frame = new(synStreamFrameV3)
	case SYN_REPLYv3:
		frame = new(synReplyFrameV3)
	case RST_STREAMv3:
		frame = new(rstStreamFrameV3)
	case SETTINGSv3:
		frame = new(settingsFrameV3)
	case PINGv3:
		frame = new(pingFrameV3)
	case GOAWAYv3:
		frame = new(goawayFrameV3)
	case HEADERSv3:
		frame = new(headersFrameV3)
	case WINDOW_UPDATEv3:
		frame = new(windowUpdateFrameV3)
	case CREDENTIALv3:
		frame = new(credentialFrameV3)

	default:
		return nil, errors.New("Error Failed to parse frame type.")
	}

	_, err = frame.ReadFrom(reader)
	return frame, err
}

/******************
 *** SYN_STREAM ***
 ******************/
type synStreamFrameV3 struct {
	Flags         Flags
	streamID      StreamID
	AssocStreamID StreamID
	Priority      Priority
	Slot          byte
	Header        http.Header
	rawHeader     []byte
}

func (frame *synStreamFrameV3) Compress(com Compressor) error {
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

func (frame *synStreamFrameV3) Decompress(decom Decompressor) error {
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

func (frame *synStreamFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 18)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 18, &incorrectFrame{DATA_FRAMEv3, SYN_STREAMv3, 3}
	}

	// Check it's a SYN_STREAM.
	if bytesToUint16(data[2:4]) != SYN_STREAMv3 {
		return 18, &incorrectFrame{int(bytesToUint16(data[2:4])), SYN_STREAMv3, 3}
	}

	// Check version.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 18, unsupportedVersion(version)
	}

	// Check unused space.
	if (data[8]>>7) != 0 || (data[12]>>7) != 0 {
		return 18, &invalidField{"Unused", 1, 0}
	} else if (data[16] & 0x1f) != 0 {
		return 18, &invalidField{"Unused", int(data[16] & 0x1f), 0}
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 10 {
		return 18, &incorrectDataLength{length, 10}
	} else if length > MAX_FRAME_SIZE-18 {
		return 18, frameTooLarge
	}

	// Read in data.
	header, err := read(reader, length-10)
	if err != nil {
		return 18, err
	}

	frame.Flags = Flags(data[4])
	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.AssocStreamID = StreamID(bytesToUint32(data[12:16]))
	frame.Priority = Priority(data[16] >> 5)
	frame.Slot = data[17]
	frame.rawHeader = header

	if !frame.streamID.Valid() {
		return 18, streamIDTooLarge
	}
	if !frame.AssocStreamID.Valid() {
		return 18, streamIDTooLarge
	}

	return int64(length + 8), nil
}

func (frame *synStreamFrameV3) StreamID() StreamID {
	return frame.streamID
}

func (frame *synStreamFrameV3) String() string {
	buf := new(bytes.Buffer)
	Flags := ""
	if frame.Flags.FIN() {
		Flags += " FLAG_FIN"
	}
	if frame.Flags.UNIDIRECTIONAL() {
		Flags += " FLAG_UNIDIRECTIONAL"
	}
	if Flags == "" {
		Flags = "[NONE]"
	} else {
		Flags = Flags[1:]
	}

	buf.WriteString("SYN_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Associated Stream ID: %d\n\t", frame.AssocStreamID))
	buf.WriteString(fmt.Sprintf("Priority:             %d\n\t", frame.Priority))
	buf.WriteString(fmt.Sprintf("Slot:                 %d\n\t", frame.Slot))
	buf.WriteString(fmt.Sprintf("Header:               %#v\n}\n", frame.Header))

	return buf.String()
}

func (frame *synStreamFrameV3) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
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
	out[4] = byte(frame.Flags)         // Flags
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
	out[16] = frame.Priority.Byte(3)   // Priority and unused
	out[17] = frame.Slot               // Slot

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
type synReplyFrameV3 struct {
	Flags     Flags
	streamID  StreamID
	Header    http.Header
	rawHeader []byte
}

func (frame *synReplyFrameV3) Compress(com Compressor) error {
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

func (frame *synReplyFrameV3) Decompress(decom Decompressor) error {
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

func (frame *synReplyFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAMEv3, SYN_REPLYv3, 3}
	}

	// Check it's a SYN_REPLY.
	if bytesToUint16(data[2:4]) != SYN_REPLYv3 {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), SYN_REPLYv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 12, unsupportedVersion(version)
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 12, &invalidField{"Unused", 1, 0}
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 4 {
		return 12, &incorrectDataLength{length, 4}
	} else if length > MAX_FRAME_SIZE-8 {
		return 12, frameTooLarge
	}

	// Read in data.
	header, err := read(reader, length-4)
	if err != nil {
		return 12, err
	}

	frame.Flags = Flags(data[4])
	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.rawHeader = header

	return int64(length + 8), nil
}

func (frame *synReplyFrameV3) StreamID() StreamID {
	return frame.streamID
}

func (frame *synReplyFrameV3) String() string {
	buf := new(bytes.Buffer)
	Flags := ""
	if frame.Flags.FIN() {
		Flags += " FLAG_FIN"
	}
	if Flags == "" {
		Flags = "[NONE]"
	} else {
		Flags = Flags[1:]
	}

	buf.WriteString("SYN_REPLY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Header:               %#v\n}\n", frame.Header))

	return buf.String()
}

func (frame *synReplyFrameV3) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Header not written.")
	}
	if !frame.streamID.Valid() {
		return 0, streamIDTooLarge
	}

	header := frame.rawHeader
	length := 4 + len(header)
	out := make([]byte, 12)

	out[0] = 128                  // Control bit and Version
	out[1] = 3                    // Version
	out[2] = 0                    // Type
	out[3] = 2                    // Type
	out[4] = byte(frame.Flags)    // Flags
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
		return 12, err
	}

	return int64(len(header) + 12), nil
}

/******************
 *** RST_STREAM ***
 ******************/
type rstStreamFrameV3 struct {
	streamID StreamID
	Status   StatusCode
}

func (frame *rstStreamFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *rstStreamFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *rstStreamFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 16, &incorrectFrame{DATA_FRAMEv3, RST_STREAMv3, 3}
	}

	// Check it's a RST_STREAM.
	if bytesToUint16(data[2:4]) != RST_STREAMv3 {
		return 16, &incorrectFrame{int(bytesToUint16(data[2:4])), RST_STREAMv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
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

func (frame *rstStreamFrameV3) StreamID() StreamID {
	return frame.streamID
}

func (frame *rstStreamFrameV3) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("RST_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Status code:          %s\n}\n", frame.Status))

	return buf.String()
}

func (frame *rstStreamFrameV3) WriteTo(writer io.Writer) (int64, error) {
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
type settingsFrameV3 struct {
	Flags    Flags
	Settings Settings
}

func (frame *settingsFrameV3) Add(Flags Flags, id uint32, value uint32) {
	frame.Settings[id] = &Setting{Flags, id, value}
}

func (frame *settingsFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *settingsFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *settingsFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAMEv3, SETTINGSv3, 3}
	}

	// Check it's a SETTINGS.
	if bytesToUint16(data[2:4]) != SETTINGSv3 {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), SETTINGSv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
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

	frame.Flags = Flags(data[4])
	frame.Settings = make(Settings)
	for i := 0; i < numSettings; i++ {
		j := i * 8
		setting := decodeSettingV3(settings[j:])
		if setting == nil {
			return int64(length), errors.New("Error: Failed to parse settings.")
		}
		frame.Settings[setting.ID] = setting
	}

	return int64(length), nil
}

func (frame *settingsFrameV3) StreamID() StreamID {
	return 0
}

func (frame *settingsFrameV3) String() string {
	buf := new(bytes.Buffer)
	Flags := ""
	if frame.Flags.CLEAR_SETTINGS() {
		Flags += " FLAG_SETTINGS_CLEAR_SETTINGS"
	}
	if Flags == "" {
		Flags = "[NONE]"
	} else {
		Flags = Flags[1:]
	}

	buf.WriteString("SETTINGS {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Settings:\n"))
	settings := frame.Settings.Settings()
	for _, setting := range settings {
		buf.WriteString("\t\t" + setting.String() + "\n")
	}
	buf.WriteString("\n")

	return buf.String()
}

func (frame *settingsFrameV3) WriteTo(writer io.Writer) (int64, error) {
	settings := encodeSettingsV3(frame.Settings)
	numSettings := uint32(len(frame.Settings))
	length := 4 + len(settings)
	out := make([]byte, 12)

	out[0] = 128                     // Control bit and Version
	out[1] = 3                       // Version
	out[2] = 0                       // Type
	out[3] = 4                       // Type
	out[4] = byte(frame.Flags)       // Flags
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

func decodeSettingV3(data []byte) *Setting {
	if len(data) < 8 {
		return nil
	}

	setting := new(Setting)
	setting.Flags = Flags(data[0])
	setting.ID = bytesToUint24(data[1:])
	setting.Value = bytesToUint32(data[4:])

	return setting
}

func encodeSettingsV3(s Settings) []byte {
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
		out[offset] = byte(setting.Flags)
		out[offset+1] = byte(setting.ID >> 16)
		out[offset+2] = byte(setting.ID >> 8)
		out[offset+3] = byte(setting.ID)
		out[offset+4] = byte(setting.Value >> 24)
		out[offset+5] = byte(setting.Value >> 16)
		out[offset+6] = byte(setting.Value >> 8)
		out[offset+7] = byte(setting.Value)
		offset += 8
	}

	return out
}

/************
 *** PING ***
 ************/
type pingFrameV3 struct {
	PingID uint32
}

func (frame *pingFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *pingFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *pingFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAMEv3, PINGv3, 3}
	}

	// Check it's a PING.
	if bytesToUint16(data[2:4]) != PINGv3 {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), PINGv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 12, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 4 {
		return 12, &incorrectDataLength{length, 4}
	}

	// Check Flags.
	if (data[4]) != 0 {
		return 12, &invalidField{"Flags", int(data[4]), 0}
	}

	frame.PingID = bytesToUint32(data[8:12])

	return 12, nil
}

func (frame *pingFrameV3) StreamID() StreamID {
	return 0
}

func (frame *pingFrameV3) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("PING {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Ping ID:              %d\n}\n", frame.PingID))

	return buf.String()
}

func (frame *pingFrameV3) WriteTo(writer io.Writer) (int64, error) {
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
type goawayFrameV3 struct {
	LastGoodStreamID StreamID
	Status           StatusCode
}

func (frame *goawayFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *goawayFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *goawayFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 16, &incorrectFrame{DATA_FRAMEv3, GOAWAYv3, 3}
	}

	// Check it's a GOAWAY.
	if bytesToUint16(data[2:4]) != GOAWAYv3 {
		return 16, &incorrectFrame{int(bytesToUint16(data[2:4])), GOAWAYv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 16, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 8 {
		return 16, &incorrectDataLength{length, 8}
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 16, &invalidField{"Unused", 1, 0}
	}

	// Check Flags.
	if (data[4]) != 0 {
		return 16, &invalidField{"Flags", int(data[4]), 0}
	}

	frame.LastGoodStreamID = StreamID(bytesToUint32(data[8:12]))
	frame.Status = StatusCode(bytesToUint32(data[12:16]))

	if !frame.LastGoodStreamID.Valid() {
		return 16, streamIDTooLarge
	}

	return 16, nil
}

func (frame *goawayFrameV3) StreamID() StreamID {
	return 0
}

func (frame *goawayFrameV3) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("GOAWAY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Last good stream ID:  %d\n\t", frame.LastGoodStreamID))
	buf.WriteString(fmt.Sprintf("Status code:          %s (%d)\n}\n", frame.Status, frame.Status))

	return buf.String()
}

func (frame *goawayFrameV3) WriteTo(writer io.Writer) (int64, error) {
	if !frame.LastGoodStreamID.Valid() {
		return 0, streamIDTooLarge
	}

	out := make([]byte, 16)

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
	out[12] = byte(frame.Status >> 24)    // Status Code
	out[13] = byte(frame.Status >> 16)    // Status Code
	out[14] = byte(frame.Status >> 8)     // Status Code
	out[15] = byte(frame.Status)          // Status Code

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	return 16, nil
}

/***************
 *** HEADERS ***
 ***************/
type headersFrameV3 struct {
	Flags     Flags
	streamID  StreamID
	Header    http.Header
	rawHeader []byte
}

func (frame *headersFrameV3) Compress(com Compressor) error {
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

func (frame *headersFrameV3) Decompress(decom Decompressor) error {
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

func (frame *headersFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 12, &incorrectFrame{DATA_FRAMEv3, HEADERSv3, 3}
	}

	// Check it's a HEADERS.
	if bytesToUint16(data[2:4]) != HEADERSv3 {
		return 12, &incorrectFrame{int(bytesToUint16(data[2:4])), HEADERSv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 12, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 4 {
		return 12, &incorrectDataLength{length, 4}
	} else if length > MAX_FRAME_SIZE-8 {
		return 12, frameTooLarge
	}

	// Check unused space.
	if (data[8] >> 7) != 0 {
		return 12, &invalidField{"Unused", 1, 0}
	}

	// Read in data.
	header, err := read(reader, length-4)
	if err != nil {
		return 12, err
	}

	frame.Flags = Flags(data[4])
	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.rawHeader = header

	if !frame.streamID.Valid() {
		return 18, streamIDTooLarge
	}

	return 18, nil
}

func (frame *headersFrameV3) StreamID() StreamID {
	return frame.streamID
}

func (frame *headersFrameV3) String() string {
	buf := new(bytes.Buffer)

	Flags := ""
	if frame.Flags.FIN() {
		Flags += " FLAG_FIN"
	}
	if Flags == "" {
		Flags = "[NONE]"
	} else {
		Flags = Flags[1:]
	}

	buf.WriteString("HEADERS {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Header:               %#v\n}\n", frame.Header))

	return buf.String()
}

func (frame *headersFrameV3) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Headers not written.")
	}
	if !frame.streamID.Valid() {
		return 0, streamIDTooLarge
	}

	header := frame.rawHeader
	length := 4 + len(header)
	out := make([]byte, 12)

	out[0] = 128                  // Control bit and Version
	out[1] = 3                    // Version
	out[2] = 0                    // Type
	out[3] = 8                    // Type
	out[4] = byte(frame.Flags)    // Flags
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
		return 12, err
	}

	return int64(length + 8), nil
}

/*********************
 *** WINDOW_UPDATE ***
 *********************/
type windowUpdateFrameV3 struct {
	streamID        StreamID
	DeltaWindowSize uint32
}

func (frame *windowUpdateFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *windowUpdateFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *windowUpdateFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 16, &incorrectFrame{DATA_FRAMEv3, WINDOW_UPDATEv3, 3}
	}

	// Check it's a WINDOW_UPDATE.
	if bytesToUint16(data[2:4]) != WINDOW_UPDATEv3 {
		return 16, &incorrectFrame{int(bytesToUint16(data[2:4])), WINDOW_UPDATEv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 16, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 8 {
		return 16, &incorrectDataLength{length, 8}
	}

	// Check unused space.
	if (data[8]>>7)|(data[12]>>7) != 0 {
		return 16, &invalidField{"Unused", 1, 0}
	}

	frame.streamID = StreamID(bytesToUint32(data[8:12]))
	frame.DeltaWindowSize = bytesToUint32(data[12:16])

	if !frame.streamID.Valid() {
		return 16, streamIDTooLarge
	}
	if frame.DeltaWindowSize > MAX_DELTA_WINDOW_SIZE {
		return 16, errors.New("Error: Delta Window Size too large.")
	}

	return 16, nil
}

func (frame *windowUpdateFrameV3) StreamID() StreamID {
	return frame.streamID
}

func (frame *windowUpdateFrameV3) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("WINDOW_UPDATE {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Delta window size:    %d\n}\n", frame.DeltaWindowSize))

	return buf.String()
}

func (frame *windowUpdateFrameV3) WriteTo(writer io.Writer) (int64, error) {
	out := make([]byte, 12)

	out[0] = 128                                     // Control bit and Version
	out[1] = 3                                       // Version
	out[2] = 0                                       // Type
	out[3] = 8                                       // Type
	out[4] = 0                                       // Flags
	out[5] = 0                                       // Length
	out[6] = 0                                       // Length
	out[7] = 8                                       // Length
	out[8] = frame.streamID.b1()                     // Stream ID
	out[9] = frame.streamID.b2()                     // Stream ID
	out[10] = frame.streamID.b3()                    // Stream ID
	out[11] = frame.streamID.b4()                    // Stream ID
	out[12] = byte(frame.DeltaWindowSize>>24) & 0x7f // Delta Window Size
	out[13] = byte(frame.DeltaWindowSize >> 16)      // Delta Window Size
	out[14] = byte(frame.DeltaWindowSize >> 8)       // Delta Window Size
	out[15] = byte(frame.DeltaWindowSize)            // Delta Window Size

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	return 16, nil
}

/******************
 *** CREDENTIAL ***
 ******************/
type credentialFrameV3 struct {
	Slot         uint16
	Proof        []byte
	Certificates []*x509.Certificate
}

func (frame *credentialFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *credentialFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *credentialFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 18)
	if err != nil {
		return 0, err
	}

	// Check it's a control frame.
	if data[0] != 128 {
		return 18, &incorrectFrame{DATA_FRAMEv3, CREDENTIALv3, 3}
	}

	// Check it's a CREDENTIAL.
	if bytesToUint16(data[2:4]) != CREDENTIALv3 {
		return 18, &incorrectFrame{int(bytesToUint16(data[2:4])), CREDENTIALv3, 3}
	}

	// Check version and adapt accordingly.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 3 {
		return 18, unsupportedVersion(version)
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 6 {
		return 18, &incorrectDataLength{length, 6}
	} else if length > MAX_FRAME_SIZE-8 {
		return 18, frameTooLarge
	}

	// Check Flags.
	if (data[4]) != 0 {
		return 18, &invalidField{"Flags", int(data[4]), 0}
	}

	// Read in data.
	certs, err := read(reader, length-10)
	if err != nil {
		return 18, err
	}

	frame.Slot = bytesToUint16(data[8:10])
	proofLen := int(bytesToUint32(data[10:14]))
	if proofLen > 0 {
		frame.Proof = data[14 : 14+proofLen]
	} else {
		frame.Proof = []byte{}
	}

	numCerts := 0
	for offset := 0; offset < length-10; {
		offset += int(bytesToUint32(certs[offset:offset+4])) + 4
		numCerts++
	}

	frame.Certificates = make([]*x509.Certificate, numCerts)
	for i, offset := 0, 0; offset < length-10; i++ {
		length := int(bytesToUint32(certs[offset : offset+4]))
		rawCert := certs[offset+4 : offset+4+length]
		frame.Certificates[i], err = x509.ParseCertificate(rawCert)
		if err != nil {
			return int64(length + 8), err
		}
		offset += length + 4
	}

	return int64(length + 8), nil
}

func (frame *credentialFrameV3) StreamID() StreamID {
	return 0
}

func (frame *credentialFrameV3) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("CREDENTIAL {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Slot:                 %d\n\t", frame.Slot))
	buf.WriteString(fmt.Sprintf("Proof:                %v\n\t", frame.Proof))
	buf.WriteString(fmt.Sprintf("Certificates:         %v\n}\n", frame.Certificates))

	return buf.String()
}

func (frame *credentialFrameV3) WriteTo(writer io.Writer) (int64, error) {
	proofLength := len(frame.Proof)
	certsLength := 0
	for _, cert := range frame.Certificates {
		certsLength += len(cert.Raw)
	}

	length := 6 + proofLength + certsLength
	out := make([]byte, 14)

	out[0] = 128                      // Control bit and Version
	out[1] = 3                        // Version
	out[2] = 0                        // Type
	out[3] = 10                       // Type
	out[4] = 0                        // Flags
	out[5] = byte(length >> 16)       // Length
	out[6] = byte(length >> 8)        // Length
	out[7] = byte(length)             // Length
	out[8] = byte(frame.Slot >> 8)    // Slot
	out[9] = byte(frame.Slot)         // Slot
	out[10] = byte(proofLength >> 24) // Proof Length
	out[11] = byte(proofLength >> 16) // Proof Length
	out[12] = byte(proofLength >> 8)  // Proof Length
	out[13] = byte(proofLength)       // Proof Length

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	if len(frame.Proof) > 0 {
		err = write(writer, frame.Proof)
		if err != nil {
			return 14, err
		}
	}

	written := int64(14 + len(frame.Proof))
	for _, cert := range frame.Certificates {
		err = write(writer, cert.Raw)
		if err != nil {
			return written, err
		}
		written += int64(len(cert.Raw))
	}

	return written, nil
}

/************
 *** DATA ***
 ************/
type dataFrameV3 struct {
	streamID StreamID
	Flags    Flags
	Data     []byte
}

func (frame *dataFrameV3) Compress(comp Compressor) error {
	return nil
}

func (frame *dataFrameV3) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *dataFrameV3) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 8)
	if err != nil {
		return 0, err
	}

	// Check it's a data frame.
	if data[0]&0x80 == 1 {
		return 8, &incorrectFrame{CONTROL_FRAMEv3, DATA_FRAMEv3, 3}
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
	frame.Flags = Flags(data[4])
	if frame.Data == nil {
		frame.Data = []byte{}
	}

	return int64(length + 8), nil
}

func (frame *dataFrameV3) StreamID() StreamID {
	return frame.streamID
}

func (frame *dataFrameV3) String() string {
	buf := new(bytes.Buffer)

	Flags := ""
	if frame.Flags.FIN() {
		Flags += " FLAG_FIN"
	}
	if Flags == "" {
		Flags = "[NONE]"
	} else {
		Flags = Flags[1:]
	}

	buf.WriteString("DATA {\n\t")
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.streamID))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Length:               %d\n\t", len(frame.Data)))
	buf.WriteString(fmt.Sprintf("Data:                 %v\n}\n", frame.Data))

	return buf.String()
}

func (frame *dataFrameV3) WriteTo(writer io.Writer) (int64, error) {
	length := len(frame.Data)
	if length > MAX_DATA_SIZE {
		return 0, errors.New("Error: Data size too large.")
	}
	if length == 0 && !frame.Flags.FIN() {
		return 0, errors.New("Error: Data is empty.")
	}

	out := make([]byte, 8)

	out[0] = frame.streamID.b1() // Control bit and Stream ID
	out[1] = frame.streamID.b2() // Stream ID
	out[2] = frame.streamID.b3() // Stream ID
	out[3] = frame.streamID.b4() // Stream ID
	out[4] = byte(frame.Flags)   // Flags
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
