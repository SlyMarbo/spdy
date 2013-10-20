// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	case SYN_STREAMv2:
		frame = new(synStreamFrameV2)
	case SYN_REPLYv2:
		frame = new(synReplyFrameV2)
	case RST_STREAMv2:
		frame = new(rstStreamFrameV2)
	case SETTINGSv2:
		frame = new(settingsFrameV2)
	case NOOPv2:
		frame = new(noopFrameV2)
	case PINGv2:
		frame = new(pingFrameV2)
	case GOAWAYv2:
		frame = new(goawayFrameV2)
	case HEADERSv2:
		frame = new(headersFrameV2)
	case WINDOW_UPDATEv2:
		frame = new(windowUpdateFrameV2)

	default:
		return nil, errors.New("Error Failed to parse frame type.")
	}

	_, err = frame.ReadFrom(reader)
	return frame, err
}

// controlFrameCommonProcessingV2 performs checks identical between
// all control frames. This includes the control bit, the version
// number, the type byte (which is checked against the byte
// provided), and the flags (which are checked against the bitwise
// OR of valid flags provided).
func controlFrameCommonProcessingV2(data []byte, frameType uint16, flags byte) error {
	// Check it's a control frame.
	if data[0] != 128 {
		return &incorrectFrame{DATA_FRAMEv3, int(frameType), 2}
	}

	// Check version.
	version := (uint16(data[0]&0x7f) << 8) + uint16(data[1])
	if version != 2 {
		return unsupportedVersion(version)
	}

	// Check its type.
	realType := bytesToUint16(data[2:])
	if realType != frameType {
		return &incorrectFrame{int(realType), int(frameType), 2}
	}

	// Check the flags.
	if data[4] & ^flags != 0 {
		return &invalidField{"flags", int(data[4]), int(flags)}
	}

	return nil
}

/******************
 *** SYN_STREAM ***
 ******************/
type synStreamFrameV2 struct {
	Flags         Flags
	StreamID      StreamID
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

func (frame *synStreamFrameV2) Name() string {
	return "SYN_STREAM"
}

func (frame *synStreamFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 18)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], SYN_STREAMv2, FLAG_FIN|FLAG_UNIDIRECTIONAL)
	if err != nil {
		return 18, err
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

	frame.Flags = Flags(data[4])
	frame.StreamID = StreamID(bytesToUint32(data[8:12]))
	frame.AssocStreamID = StreamID(bytesToUint32(data[12:16]))
	frame.Priority = Priority(data[16] >> 6)
	frame.rawHeader = header

	if !frame.StreamID.Valid() {
		return 18, streamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 18, streamIdIsZero
	}
	if !frame.AssocStreamID.Valid() {
		return 18, streamIdTooLarge
	}

	return int64(length + 8), nil
}

func (frame *synStreamFrameV2) String() string {
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
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Associated Stream ID: %d\n\t", frame.AssocStreamID))
	buf.WriteString(fmt.Sprintf("Priority:             %d\n\t", frame.Priority))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *synStreamFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Headers not written.")
	}
	if !frame.StreamID.Valid() {
		return 0, streamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 0, streamIdIsZero
	}
	if !frame.AssocStreamID.Valid() {
		return 0, streamIdTooLarge
	}

	header := frame.rawHeader
	length := 10 + len(header)
	out := make([]byte, 18)

	out[0] = 128                       // Control bit and Version
	out[1] = 2                         // Version
	out[2] = 0                         // Type
	out[3] = 1                         // Type
	out[4] = byte(frame.Flags)         // Flags
	out[5] = byte(length >> 16)        // Length
	out[6] = byte(length >> 8)         // Length
	out[7] = byte(length)              // Length
	out[8] = frame.StreamID.b1()       // Stream ID
	out[9] = frame.StreamID.b2()       // Stream ID
	out[10] = frame.StreamID.b3()      // Stream ID
	out[11] = frame.StreamID.b4()      // Stream ID
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
	Flags     Flags
	StreamID  StreamID
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

func (frame *synReplyFrameV2) Name() string {
	return "SYN_REPLY"
}

func (frame *synReplyFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 14)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], SYN_REPLYv2, FLAG_FIN)
	if err != nil {
		return 14, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 8 {
		return 14, &incorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return 14, frameTooLarge
	}

	// Read in data.
	header, err := read(reader, length-6)
	if err != nil {
		return 14, err
	}

	frame.Flags = Flags(data[4])
	frame.StreamID = StreamID(bytesToUint32(data[8:12]))
	frame.rawHeader = header

	return int64(length + 8), nil
}

func (frame *synReplyFrameV2) String() string {
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
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *synReplyFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Header not written.")
	}
	if !frame.StreamID.Valid() {
		return 0, streamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 0, streamIdIsZero
	}

	header := frame.rawHeader
	length := 6 + len(header)
	out := make([]byte, 14)

	out[0] = 128                  // Control bit and Version
	out[1] = 2                    // Version
	out[2] = 0                    // Type
	out[3] = 2                    // Type
	out[4] = byte(frame.Flags)    // Flags
	out[5] = byte(length >> 16)   // Length
	out[6] = byte(length >> 8)    // Length
	out[7] = byte(length)         // Length
	out[8] = frame.StreamID.b1()  // Stream ID
	out[9] = frame.StreamID.b2()  // Stream ID
	out[10] = frame.StreamID.b3() // Stream ID
	out[11] = frame.StreamID.b4() // Stream ID
	out[12] = 0                   // Unused
	out[13] = 0                   // Unused

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, header)
	if err != nil {
		return 14, err
	}

	return int64(len(header) + 14), nil
}

/******************
 *** RST_STREAM ***
 ******************/
type rstStreamFrameV2 struct {
	StreamID StreamID
	Status   StatusCode
}

func (frame *rstStreamFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *rstStreamFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *rstStreamFrameV2) Name() string {
	return "RST_STREAM"
}

func (frame *rstStreamFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], RST_STREAMv2, 0)
	if err != nil {
		return 16, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 8 {
		return 16, &incorrectDataLength{length, 8}
	} else if length > MAX_FRAME_SIZE-8 {
		return 16, frameTooLarge
	}

	frame.StreamID = StreamID(bytesToUint32(data[8:12]))
	frame.Status = StatusCode(bytesToUint32(data[12:16]))

	if !frame.StreamID.Valid() {
		return 16, streamIdTooLarge
	}

	return 16, nil
}

func (frame *rstStreamFrameV2) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("RST_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Status code:          %s\n}\n", frame.Status))

	return buf.String()
}

func (frame *rstStreamFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if !frame.StreamID.Valid() {
		return 0, streamIdTooLarge
	}

	out := make([]byte, 16)

	out[0] = 128                  // Control bit and Version
	out[1] = 2                    // Version
	out[2] = 0                    // Type
	out[3] = 2                    // Type
	out[4] = 0                    // Flags
	out[5] = 0                    // Length
	out[6] = 0                    // Length
	out[7] = 8                    // Length
	out[8] = frame.StreamID.b1()  // Stream ID
	out[9] = frame.StreamID.b2()  // Stream ID
	out[10] = frame.StreamID.b3() // Stream ID
	out[11] = frame.StreamID.b4() // Stream ID
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
	Flags    Flags
	Settings Settings
}

func (frame *settingsFrameV2) Add(Flags Flags, id uint32, value uint32) {
	frame.Settings[id] = &Setting{Flags, id, value}
}

func (frame *settingsFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *settingsFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *settingsFrameV2) Name() string {
	return "SETTINGS"
}

func (frame *settingsFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], SETTINGSv2, FLAG_SETTINGS_CLEAR_SETTINGS)
	if err != nil {
		return 12, err
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
		setting := decodeSettingV2(settings[j:])
		if setting == nil {
			return int64(length), errors.New("Error: Failed to parse settings.")
		}
		frame.Settings[setting.ID] = setting
	}

	return int64(length), nil
}

func (frame *settingsFrameV2) String() string {
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
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Settings:\n"))
	settings := frame.Settings.Settings()
	for _, setting := range settings {
		buf.WriteString("\t\t" + setting.String() + "\n")
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
	out[1] = 2                       // Version
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

func decodeSettingV2(data []byte) *Setting {
	if len(data) < 8 {
		return nil
	}

	setting := new(Setting)
	setting.ID = bytesToUint24Reverse(data[0:]) // Might need to reverse this.
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
		out[offset] = byte(setting.ID)         // Might need to reverse this.
		out[offset+1] = byte(setting.ID >> 8)  // Might need to reverse this.
		out[offset+2] = byte(setting.ID >> 16) // Might need to reverse this.
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

func (frame *noopFrameV2) Name() string {
	return "NOOP"
}

func (frame *noopFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 8)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], NOOPv2, 0)
	if err != nil {
		return 8, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 0 {
		return 8, &incorrectDataLength{length, 0}
	}

	return 8, nil
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

func (frame *pingFrameV2) Name() string {
	return "PING"
}

func (frame *pingFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], PINGv2, 0)
	if err != nil {
		return 12, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 4 {
		return 12, &incorrectDataLength{length, 4}
	}

	frame.PingID = bytesToUint32(data[8:12])

	return 12, nil
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
	out[1] = 2                        // Version
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

func (frame *goawayFrameV2) Name() string {
	return "GOAWAY"
}

func (frame *goawayFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 12)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], GOAWAYv2, 0)
	if err != nil {
		return 12, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 4 {
		return 12, &incorrectDataLength{length, 4}
	}

	frame.LastGoodStreamID = StreamID(bytesToUint32(data[8:12]))

	if !frame.LastGoodStreamID.Valid() {
		return 12, streamIdTooLarge
	}

	return 12, nil
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
		return 0, streamIdTooLarge
	}

	out := make([]byte, 12)

	out[0] = 128                          // Control bit and Version
	out[1] = 2                            // Version
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
	Flags     Flags
	StreamID  StreamID
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

func (frame *headersFrameV2) Name() string {
	return "HEADERS"
}

func (frame *headersFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], HEADERSv2, FLAG_FIN)
	if err != nil {
		return 16, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length < 6 {
		return 16, &incorrectDataLength{length, 6}
	} else if length > MAX_FRAME_SIZE-8 {
		return 16, frameTooLarge
	}

	// Read in data.
	header, err := read(reader, length-8)
	if err != nil {
		return 16, err
	}

	frame.Flags = Flags(data[4])
	frame.StreamID = StreamID(bytesToUint32(data[8:12]))
	frame.rawHeader = header

	if !frame.StreamID.Valid() {
		return int64(length + 8), streamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return int64(length + 8), streamIdIsZero
	}

	return int64(length + 8), nil
}

func (frame *headersFrameV2) String() string {
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
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *headersFrameV2) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Headers not written.")
	}
	if !frame.StreamID.Valid() {
		return 0, streamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 0, streamIdIsZero
	}

	header := frame.rawHeader
	length := 4 + len(header)
	out := make([]byte, 16)

	out[0] = 128                  // Control bit and Version
	out[1] = 2                    // Version
	out[2] = 0                    // Type
	out[3] = 8                    // Type
	out[4] = byte(frame.Flags)    // Flags
	out[5] = byte(length >> 16)   // Length
	out[6] = byte(length >> 8)    // Length
	out[7] = byte(length)         // Length
	out[8] = frame.StreamID.b1()  // Stream ID
	out[9] = frame.StreamID.b2()  // Stream ID
	out[10] = frame.StreamID.b3() // Stream ID
	out[11] = frame.StreamID.b4() // Stream ID

	err := write(writer, out)
	if err != nil {
		return 0, err
	}

	err = write(writer, header)
	if err != nil {
		return 16, err
	}

	return int64(length + 8), nil
}

/*********************
 *** WINDOW_UPDATE ***
 *********************/
type windowUpdateFrameV2 struct {
	StreamID        StreamID
	DeltaWindowSize uint32
}

func (frame *windowUpdateFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *windowUpdateFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *windowUpdateFrameV2) Name() string {
	return "WINDOW_UPDATE"
}

func (frame *windowUpdateFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessingV2(data[:4], WINDOW_UPDATEv2, 0)
	if err != nil {
		return 16, err
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length != 8 {
		return 16, &incorrectDataLength{length, 8}
	}

	frame.StreamID = StreamID(bytesToUint32(data[8:12]))
	frame.DeltaWindowSize = bytesToUint32(data[12:16])

	if !frame.StreamID.Valid() {
		return 16, streamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 16, streamIdIsZero
	}
	if frame.DeltaWindowSize > MAX_DELTA_WINDOW_SIZE {
		return 16, errors.New("Error: Delta Window Size too large.")
	}

	return 16, nil
}

func (frame *windowUpdateFrameV2) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("WINDOW_UPDATE {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Delta window size:    %d\n}\n", frame.DeltaWindowSize))

	return buf.String()
}

func (frame *windowUpdateFrameV2) WriteTo(writer io.Writer) (int64, error) {
	return 0, nil
}

/************
 *** DATA ***
 ************/
type dataFrameV2 struct {
	StreamID StreamID
	Flags    Flags
	Data     []byte
}

func (frame *dataFrameV2) Compress(comp Compressor) error {
	return nil
}

func (frame *dataFrameV2) Decompress(decomp Decompressor) error {
	return nil
}

func (frame *dataFrameV2) Name() string {
	return "DATA"
}

func (frame *dataFrameV2) ReadFrom(reader io.Reader) (int64, error) {
	data, err := read(reader, 8)
	if err != nil {
		return 0, err
	}

	// Check it's a data frame.
	if data[0]&0x80 == 1 {
		return 8, &incorrectFrame{CONTROL_FRAMEv2, DATA_FRAMEv2, 2}
	}

	// Check flags.
	if data[4] & ^byte(FLAG_FIN) != 0 {
		return 8, &invalidField{"flags", int(data[4]), FLAG_FIN}
	}

	// Get and check length.
	length := int(bytesToUint24(data[5:8]))
	if length > MAX_FRAME_SIZE-8 {
		return 8, frameTooLarge
	}

	// Read in data.
	if length != 0 {
		frame.Data, err = read(reader, length)
		if err != nil {
			return 8, err
		}
	}

	frame.StreamID = StreamID(bytesToUint32(data[0:4]))
	frame.Flags = Flags(data[4])
	if frame.Data == nil {
		frame.Data = []byte{}
	}

	return int64(length + 8), nil
}

func (frame *dataFrameV2) String() string {
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
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", Flags))
	buf.WriteString(fmt.Sprintf("Length:               %d\n\t", len(frame.Data)))
	if VerboseLogging || len(frame.Data) <= 21 {
		buf.WriteString(fmt.Sprintf("Data:                 [% x]\n}\n", frame.Data))
	} else {
		buf.WriteString(fmt.Sprintf("Data:                 [% x ... % x]\n}\n", frame.Data[:9],
			frame.Data[len(frame.Data)-9:]))
	}

	return buf.String()
}

func (frame *dataFrameV2) WriteTo(writer io.Writer) (int64, error) {
	length := len(frame.Data)
	if length > MAX_DATA_SIZE {
		return 0, errors.New("Error: Data size too large.")
	}
	if length == 0 && !frame.Flags.FIN() {
		return 0, errors.New("Error: Data is empty.")
	}

	out := make([]byte, 8)

	out[0] = frame.StreamID.b1() // Control bit and Stream ID
	out[1] = frame.StreamID.b2() // Stream ID
	out[2] = frame.StreamID.b3() // Stream ID
	out[3] = frame.StreamID.b4() // Stream ID
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
