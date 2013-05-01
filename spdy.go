package spdy

import (
  "bufio"
  "fmt"
  "io"
)

const (
  CONTROL_FRAME = 0
  DATA_FRAME    = -1
  SYN_STREAM    = 1
  SYN_REPLY     = 2
  RST_STREAM    = 3
  SETTINGS      = 4
  PING          = 6
  GOAWAY        = 7
  HEADERS       = 8
  WINDOW_UPDATE = 9
  CREDENTIAL    = 10
)

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
  return fmt.Sprintf("Error: Frame %s tried to parse data for a %s.", FrameName(i.expected),
    FrameName(i.got))
}

type IncorrectDataLength struct {
  got, expected int
}

func (i *IncorrectDataLength) Error() string {
  return fmt.Sprintf("Error: Incorrect amount of data for frame: got %d bytes, expected %d.", i.got,
    i.expected)
}

type FrameTooLarge struct{}

func (_ FrameTooLarge) Error() string {
  return "Error: Frame too large."
}

type InvalidField struct {
  field         string
  got, expected int
}

func (i *InvalidField) Error() string {
  return fmt.Sprintf("Error: Field %q recieved invalid data %d, expecting %d.", i.field, i.got,
    i.expected)
}

/*** FRAMES ***/
type Frame interface {
  Bytes() ([]byte, error)
  Parse(bufio.Reader) error
  WriteTo(io.Writer) error
}

func ReadFrame(reader bufio.Reader) (Frame, error) {

  panic("Unreachable")
}

/******************
 *** SYN_STREAM ***
 ******************/
type SynStreamFrame struct {
  Version       uint16
  Flags         byte
  StreamID      uint32
  AssocStreamID uint32
  Priority      byte
  Slot          byte
  Headers       *Headers
}

func (frame *SynStreamFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length < 10 {
    return &IncorrectDataLength{length, 10}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check unused space.
  if (data[8]>>7) != 0 || (data[12]>>7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  } else if (data[16] & 0x1f) != 0 {
    return &InvalidField{"Unused", int(data[16] & 0x1f), 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.Flags = data[4]
  frame.StreamID = bytesToUint31(data[8:12])
  frame.AssocStreamID = bytesToUint31(data[12:16])
  frame.Priority = data[16] >> 5
  frame.Slot = data[17]

  headers := new(Headers)
  err = headers.Parse(data[18:])
  if err != nil {
    return err
  }
  frame.Headers = headers

  return nil
}

func (frame *SynStreamFrame) Bytes() ([]byte, error) {

  headers, err := frame.Headers.Compressed()
  if err != nil {
    return nil, err
  }

  length := 10 + len(headers)
  out := make([]byte, 18, 8+length)

  out[0] = 0x80 | byte(frame.Version>>8)         // Control bit and Version
  out[1] = byte(frame.Version)                   // Version
  out[2] = 0                                     // Type
  out[3] = 1                                     // Type
  out[4] = frame.Flags                           // Flags
  out[5] = byte(length >> 16)                    // Length
  out[6] = byte(length >> 8)                     // Length
  out[7] = byte(length)                          // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f       // Stream ID
  out[9] = byte(frame.StreamID >> 16)            // Stream ID
  out[10] = byte(frame.StreamID >> 8)            // Stream ID
  out[11] = byte(frame.StreamID)                 // Stream ID
  out[12] = byte(frame.AssocStreamID>>24) & 0x7f // Associated Stream ID
  out[13] = byte(frame.AssocStreamID >> 16)      // Associated Stream ID
  out[14] = byte(frame.AssocStreamID >> 8)       // Associated Stream ID
  out[15] = byte(frame.AssocStreamID)            // Associated Stream ID
  out[16] = ((frame.Priority & 0x7) << 5)        // Priority and unused
  out[17] = frame.Slot                           // Slot
  out = append(out, headers...)                  // Name/Value Header Block

  return out, nil
}

func (frame *SynStreamFrame) WriteTo(writer io.Writer) error {
  headers, err := frame.Headers.Compressed()
  if err != nil {
    return err
  }

  length := 10 + len(headers)
  out := make([]byte, 18)

  out[0] = 0x80 | byte(frame.Version>>8)         // Control bit and Version
  out[1] = byte(frame.Version)                   // Version
  out[2] = 0                                     // Type
  out[3] = 1                                     // Type
  out[4] = frame.Flags                           // Flags
  out[5] = byte(length >> 16)                    // Length
  out[6] = byte(length >> 8)                     // Length
  out[7] = byte(length)                          // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f       // Stream ID
  out[9] = byte(frame.StreamID >> 16)            // Stream ID
  out[10] = byte(frame.StreamID >> 8)            // Stream ID
  out[11] = byte(frame.StreamID)                 // Stream ID
  out[12] = byte(frame.AssocStreamID>>24) & 0x7f // Associated Stream ID
  out[13] = byte(frame.AssocStreamID >> 16)      // Associated Stream ID
  out[14] = byte(frame.AssocStreamID >> 8)       // Associated Stream ID
  out[15] = byte(frame.AssocStreamID)            // Associated Stream ID
  out[16] = ((frame.Priority & 0x7) << 5)        // Priority and unused
  out[17] = frame.Slot                           // Slot

  _, err = writer.Write(out)
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
  Version  uint16
  Flags    byte
  StreamID uint32
  Headers  *Headers
}

func (frame *SynReplyFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length < 4 {
    return &IncorrectDataLength{length, 4}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.Flags = data[4]
  frame.StreamID = bytesToUint31(data[8:12])

  headers := new(Headers)
  err = headers.Parse(data[12:])
  if err != nil {
    return err
  }
  frame.Headers = headers

  return nil
}

func (frame *SynReplyFrame) Bytes() ([]byte, error) {

  headers, err := frame.Headers.Compressed()
  if err != nil {
    return nil, err
  }

  length := 4 + len(headers)
  out := make([]byte, 12, 8+length)

  out[0] = 0x80 | byte(frame.Version>>8)   // Control bit and Version
  out[1] = byte(frame.Version)             // Version
  out[2] = 0                               // Type
  out[3] = 2                               // Type
  out[4] = frame.Flags                     // Flags
  out[5] = byte(length >> 16)              // Length
  out[6] = byte(length >> 8)               // Length
  out[7] = byte(length)                    // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f // Stream ID
  out[9] = byte(frame.StreamID >> 16)      // Stream ID
  out[10] = byte(frame.StreamID >> 8)      // Stream ID
  out[11] = byte(frame.StreamID)           // Stream ID
  out = append(out, headers...)            // Name/Value Header Block

  return out, nil
}

func (frame *SynReplyFrame) WriteTo(writer io.Writer) error {

  headers, err := frame.Headers.Compressed()
  if err != nil {
    return err
  }

  length := 4 + len(headers)
  out := make([]byte, 12)

  out[0] = 0x80 | byte(frame.Version>>8)   // Control bit and Version
  out[1] = byte(frame.Version)             // Version
  out[2] = 0                               // Type
  out[3] = 2                               // Type
  out[4] = frame.Flags                     // Flags
  out[5] = byte(length >> 16)              // Length
  out[6] = byte(length >> 8)               // Length
  out[7] = byte(length)                    // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f // Stream ID
  out[9] = byte(frame.StreamID >> 16)      // Stream ID
  out[10] = byte(frame.StreamID >> 8)      // Stream ID
  out[11] = byte(frame.StreamID)           // Stream ID

  _, err = writer.Write(out)
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
  Version    uint16
  Flags      byte
  StreamID   uint32
  StatusCode uint32
}

func (frame *RstStreamFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length != 8 {
    return &IncorrectDataLength{length, 8}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.Flags = data[4]
  frame.StreamID = bytesToUint31(data[8:12])
  frame.StatusCode = bytesToUint32(data[12:16])

  return nil
}

func (frame *RstStreamFrame) Bytes() ([]byte, error) {
  out := make([]byte, 8)

  out[0] = 0x80 | byte(frame.Version>>8)   // Control bit and Version
  out[1] = byte(frame.Version)             // Version
  out[2] = 0                               // Type
  out[3] = 3                               // Type
  out[4] = frame.Flags                     // Flag
  out[5] = 0                               // Length
  out[6] = 0                               // Length
  out[7] = 8                               // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f // Stream ID
  out[9] = byte(frame.StreamID >> 16)      // Stream ID
  out[10] = byte(frame.StreamID >> 8)      // Stream ID
  out[11] = byte(frame.StreamID)           // Stream ID
  out[12] = byte(frame.StatusCode >> 24)   // Status code
  out[13] = byte(frame.StatusCode >> 16)   // Status code
  out[14] = byte(frame.StatusCode >> 8)    // Status code
  out[15] = byte(frame.StatusCode)         // Status code

  return out, nil
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
  Version  uint16
  Flags    byte
  Settings []*Setting
}

func (frame *SettingsFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length < 8 {
    return &IncorrectDataLength{length, 8}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
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

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.Flags = data[4]
  frame.Settings = make([]*Setting, numSettings)
  offset := 12
  for i := 0; i < numSettings; i++ {
    frame.Settings[i] = &Setting{
      Flags: data[offset],
      ID:    bytesToUint24(data[offset+1 : offset+4]),
      Value: bytesToUint32(data[offset+4 : offset+8]),
    }

    offset += 8
  }

  return nil
}

func (frame *SettingsFrame) Bytes() ([]byte, error) {
  numSettings := uint32(len(frame.Settings))
  length := 4 + (8 * numSettings)
  out := make([]byte, 12, 8+length)

  out[0] = 0x80 | byte(frame.Version>>8) // Control bit and Version
  out[1] = byte(frame.Version)           // Version
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
  for _, setting := range frame.Settings {
    bytes := setting.Bytes()
    for i, b := range bytes {
      out[offset+i] = b
    }
    offset += 8
  }

  return out, nil
}

func (frame *SettingsFrame) WriteTo(writer io.Writer) error {
  bytes, err := frame.Bytes()
  if err != nil {
    return err
  }
  _, err = writer.Write(bytes)
  return err
}

func (frame *SettingsFrame) Add(flags byte, id, value uint32) error {
  // TODO: Check for a matching setting.
  frame.Settings = append(frame.Settings, &Setting{flags, id, value})
  return nil
}

type Setting struct {
  Flags byte
  ID    uint32
  Value uint32
}

func (s *Setting) Bytes() []byte {
  out := make([]byte, 8)

  out[0] = s.Flags
  out[1] = byte(s.ID >> 16)
  out[2] = byte(s.ID >> 8)
  out[3] = byte(s.ID)
  out[4] = byte(s.Value >> 24)
  out[5] = byte(s.Value >> 16)
  out[6] = byte(s.Value >> 8)
  out[7] = byte(s.Value)

  return out
}

/************
 *** PING ***
 ************/
type PingFrame struct {
  Version uint16
  PingID  uint32
}

func (frame *PingFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length != 4 {
    return &IncorrectDataLength{length, 4}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check flags.
  if (data[4]) != 0 {
    return &InvalidField{"Flags", int(data[4]), 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.PingID = bytesToUint32(data[8:12])

  return nil
}

func (frame *PingFrame) Bytes() ([]byte, error) {
  out := make([]byte, 12)

  out[0] = 0x80 | byte(frame.Version>>8) // Control bit and Version
  out[1] = byte(frame.Version)           // Version
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
  Version          uint16
  LastGoodStreamID uint32
  StatusCode       uint32
}

func (frame *GoawayFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length != 8 {
    return &IncorrectDataLength{length, 8}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  // Check flags.
  if (data[4]) != 0 {
    return &InvalidField{"Flags", int(data[4]), 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.LastGoodStreamID = bytesToUint31(data[8:12])
  frame.StatusCode = bytesToUint32(data[12:16])

  return nil
}

func (frame *GoawayFrame) Bytes() ([]byte, error) {
  out := make([]byte, 16)

  out[0] = 0x80 | byte(frame.Version>>8)           // Control bit and Version
  out[1] = byte(frame.Version)                     // Version
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
  out[12] = byte(frame.StatusCode >> 24)           // Status Code
  out[13] = byte(frame.StatusCode >> 16)           // Status Code
  out[14] = byte(frame.StatusCode >> 8)            // Status Code
  out[15] = byte(frame.StatusCode)                 // Status Code

  return out, nil
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
  Version  uint16
  Flags    byte
  StreamID uint32
  Headers  *Headers
}

func (frame *HeadersFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length < 4 {
    return &IncorrectDataLength{length, 4}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.Flags = data[4]
  frame.StreamID = bytesToUint31(data[8:12])

  headers := new(Headers)
  err = headers.Parse(data[12:])
  if err != nil {
    return err
  }
  frame.Headers = headers

  return nil
}

func (frame *HeadersFrame) Bytes() ([]byte, error) {
  headers, err := frame.Headers.Compressed()
  if err != nil {
    return nil, err
  }

  length := 4 + len(headers)
  out := make([]byte, 12, 8+length)

  out[0] = 0x80 | byte(frame.Version>>8)   // Control bit and Version
  out[1] = byte(frame.Version)             // Version
  out[2] = 0                               // Type
  out[3] = 8                               // Type
  out[4] = frame.Flags                     // Flags
  out[5] = byte(length >> 16)              // Length
  out[6] = byte(length >> 8)               // Length
  out[7] = byte(length)                    // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f // Stream ID
  out[9] = byte(frame.StreamID >> 16)      // Stream ID
  out[10] = byte(frame.StreamID >> 8)      // Stream ID
  out[11] = byte(frame.StreamID)           // Stream ID
  out = append(out, headers...)            // Name/Value Header Block

  return out, nil
}

func (frame *HeadersFrame) WriteTo(writer io.Writer) error {
  headers, err := frame.Headers.Compressed()
  if err != nil {
    return err
  }

  length := 4 + len(headers)
  out := make([]byte, 12)

  out[0] = 0x80 | byte(frame.Version>>8)   // Control bit and Version
  out[1] = byte(frame.Version)             // Version
  out[2] = 0                               // Type
  out[3] = 1                               // Type
  out[4] = frame.Flags                     // Flags
  out[5] = byte(length >> 16)              // Length
  out[6] = byte(length >> 8)               // Length
  out[7] = byte(length)                    // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f // Stream ID
  out[9] = byte(frame.StreamID >> 16)      // Stream ID
  out[10] = byte(frame.StreamID >> 8)      // Stream ID
  out[11] = byte(frame.StreamID)           // Stream ID

  _, err = writer.Write(out)
  if err != nil {
    return err
  }

  _, err = writer.Write(headers)
  return err
}

type header struct {
  name, value string
}

type Headers struct {
  headers []*header
}

func (h *Headers) Parse(data []byte) error {
  return nil
}

func (h *Headers) Compressed() ([]byte, error) {
  // TODO: implement (needs compression)
  return nil, nil
}

/*********************
 *** WINDOW_UPDATE ***
 *********************/
type WindowUpdateFrame struct {
  Version         uint16
  StreamID        uint32
  DeltaWindowSize uint32
}

func (frame *WindowUpdateFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length != 8 {
    return &IncorrectDataLength{length, 8}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check unused space.
  if (data[8]>>7)|(data[12]>>7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
  frame.StreamID = bytesToUint31(data[8:12])
  frame.DeltaWindowSize = bytesToUint32(data[12:16]) & 0x7f

  return nil
}

func (frame *WindowUpdateFrame) Bytes() ([]byte, error) {
  out := make([]byte, 12)

  out[0] = 0x80 | byte(frame.Version>>8)           // Control bit and Version
  out[1] = byte(frame.Version)                     // Version
  out[2] = 0                                       // Type
  out[3] = 8                                       // Type
  out[4] = 0                                       // Flags
  out[5] = 0                                       // Length
  out[6] = 0                                       // Length
  out[7] = 8                                       // Length
  out[8] = byte(frame.StreamID>>24) & 0x7f         // Stream ID
  out[9] = byte(frame.StreamID >> 16)              // Stream ID
  out[10] = byte(frame.StreamID >> 8)              // Stream ID
  out[11] = byte(frame.StreamID)                   // Stream ID
  out[12] = byte(frame.DeltaWindowSize>>24) & 0x7f // Delta Window Size
  out[13] = byte(frame.DeltaWindowSize >> 16)      // Delta Window Size
  out[14] = byte(frame.DeltaWindowSize >> 8)       // Delta Window Size
  out[15] = byte(frame.DeltaWindowSize)            // Delta Window Size

  return out, nil
}

func (frame *WindowUpdateFrame) WriteTo(writer io.Writer) error {
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
  Version      uint16
  Slot         uint16
  Proof        []byte
  Certificates []Certificate
}

func (frame *CredentialFrame) Parse(reader bufio.Reader) error {
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

  // Get and check length.
  length := int(bytesToUint24(start[5:8]))
  if length < 6 {
    return &IncorrectDataLength{length, 6}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  // Check flags.
  if (data[4]) != 0 {
    return &InvalidField{"Flags", int(data[4]), 0}
  }

  frame.Version = (uint16(data[0]&0x7f) << 8) + uint16(data[1])
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

  frame.Certificates = make([]Certificate, numCerts)
  for i, offset := 0, 14+proofLen; offset < length; i++ {
    length := int(bytesToUint32(data[offset : offset+4]))
    frame.Certificates[i] = data[offset+4 : offset+4+length]
    offset += length + 4
  }

  return nil
}

func (frame *CredentialFrame) Bytes() ([]byte, error) {

  proofLength := len(frame.Proof)
  certsLength := 0
  for _, cert := range frame.Certificates {
    certsLength += len(cert)
  }

  length := 6 + proofLength + certsLength
  out := make([]byte, 14, 8+length)

  out[0] = 0x80 | byte(frame.Version>>8) // Control bit and Version
  out[1] = byte(frame.Version)           // Version
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
    out = append(out, cert...) // Certificates
  }

  return out, nil
}

func (frame *CredentialFrame) WriteTo(writer io.Writer) error {
  proofLength := len(frame.Proof)
  certsLength := 0
  for _, cert := range frame.Certificates {
    certsLength += len(cert)
  }

  length := 6 + proofLength + certsLength
  out := make([]byte, 14, 8+length)

  out[0] = 0x80 | byte(frame.Version>>8) // Control bit and Version
  out[1] = byte(frame.Version)           // Version
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
    _, err = writer.Write(cert)
    if err != nil {
      return err
    }
  }

  return nil
}

type Certificate []byte

/************
 *** DATA ***
 ************/
type DataFrame struct {
  StreamID uint32
  Flags    byte
  Data     []byte
}

func (frame *DataFrame) Parse(reader bufio.Reader) error {
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
  if length < 1 {
    return &IncorrectDataLength{length, 1}
  } else if length > MAX_FRAME_SIZE-8 {
    return FrameTooLarge{}
  }

  // Read in data.
  data := make([]byte, 8+length)
  if _, err := reader.Read(data); err != nil {
    return err
  }

  frame.StreamID = bytesToUint31(data[0:4])
  frame.Flags = data[4]
  length = int(bytesToUint16(data[2:4]))
  frame.Data = data[8 : 8+length]

  return nil
}

func (frame *DataFrame) Bytes() []byte {
  length := len(frame.Data)
  out := make([]byte, 8, 8+length)

  out[0] = byte(frame.StreamID>>24) & 0x7f // Control bit and Stream ID
  out[1] = byte(frame.StreamID >> 16)      // Stream ID
  out[2] = byte(frame.StreamID >> 8)       // Stream ID
  out[3] = byte(frame.StreamID)            // Stream ID
  out[4] = frame.Flags                     // Flags
  out[5] = byte(length >> 16)              // Length
  out[6] = byte(length >> 8)               // Length
  out[7] = byte(length)                    // Length
  out = append(out, frame.Data...)         // Data

  return out
}

func (frame *DataFrame) WriteTo(writer io.Writer) error {
  length := len(frame.Data)
  out := make([]byte, 8)

  out[0] = byte(frame.StreamID>>24) & 0x7f // Control bit and Stream ID
  out[1] = byte(frame.StreamID >> 16)      // Stream ID
  out[2] = byte(frame.StreamID >> 8)       // Stream ID
  out[3] = byte(frame.StreamID)            // Stream ID
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
