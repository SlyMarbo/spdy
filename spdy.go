package spdy

import (
  //"encoding/hex"
  "fmt"
)

const (
  SYN_STREAM = iota
  SYN_REPLY
  RST_STREAM
  SETTINGS
  PING
  GOAWAY
  HEADERS
  WINDOW_UPDATE
  CREDENTIAL
)

func bytesToUint24(b []byte) uint32 {
  return (uint32(b[0]) << 16) + (uint32(b[1]) << 8) + uint32(b[2])
}

func bytesToUint32(b []byte) uint32 {
  return (uint32(b[0]) << 24) + (uint32(b[1]) << 16) + (uint32(b[2]) << 8) + uint32(b[3])
}

/*** ERRORS ***/
type InsufficientData struct {
  got, expected int
}

func (i *InsufficientData) Error() string {
  return fmt.Sprintf("Error: Insufficient data for frame: got %d bytes, expected %d.", i.got,
    i.expected)
}

type InvalidField struct {
  field         string
  got, expected int
}

func (i *InvalidField) Error() string {
  return fmt.Sprintf("Error: Field %q recieved invalid data %d, expecting %d.", i.field, i.got,
    i.expected)
}

type Frame interface {
  Bytes() []byte
  Parse([]byte) error
}

func Parse(data []byte) (int, error) {
  if data[0]&0x80 != 0 {
    // Control frame.

    // TODO

  } else {
    // Data frame.

  }

  panic("Unreachable")
}

/******************
 *** SYN_STREAM ***
 ******************/
type SYN_STREAM_FRAME struct {
  ControlBit    byte
  Version       uint16
  Type          uint16
  Flags         byte
  Length        uint32
  StreamID      uint32
  AssocStreamID uint32
  Priority      byte
  Slot          byte
  Headers       []*HEADERS_BLOCK
}

func (s *SYN_STREAM_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 22 {
    return &InsufficientData{size, 22}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 1 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 1}
  }

  // Check unused space.
  if (data[8]>>7) != 0 || (data[12]>>7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  } else if (data[16] & 0x1f) != 0 {
    return &InvalidField{"Unused", int(data[16] & 0x1f), 0}
  }

  s.ControlBit = 1
  s.Version = (uint16(data[0]) << 8) + uint16(data[1])
  s.Type = 1
  s.Flags = data[4]
  s.Length = bytesToUint24(data[5:8])
  s.StreamID = bytesToUint32(data[8:12])
  s.AssocStreamID = bytesToUint32(data[12:16])
  s.Priority = data[16] >> 5
  s.Slot = data[17]
  s.Headers = make([]*HEADERS_BLOCK, 0, bytesToUint32(data[18:22]))
  offset := 22
  if cap(s.Headers) != 0 {
    for offset < size {

      header := &HEADERS_BLOCK{}
      if offset+4 > size {
        return &InsufficientData{size, offset + 4}
      }
      length := (int(data[offset]) << 24) + (int(data[offset+1]) << 16) +
        (int(data[offset+2]) << 8) + int(data[offset+3])
      if offset+4+length > size {
        return &InsufficientData{size, offset + 4 + length}
      }
      header.Name = string(data[offset+4 : offset+4+length])
      offset += 4 + length

      if offset+4 > size {
        return &InsufficientData{size, offset + 4}
      }
      length = (int(data[offset]) << 24) + (int(data[offset+1]) << 16) +
        (int(data[offset+2]) << 8) + int(data[offset+3])
      if offset+4+length > size {
        return &InsufficientData{size, offset + 4 + length}
      }
      header.Value = string(data[offset+4 : offset+4+length])
      offset += 4 + length

      s.Headers = append(s.Headers, header)
    }
  }

  return nil
}

func (s *SYN_STREAM_FRAME) Bytes() []byte {
  size := 22
  num := uint32(0)
  for _, h := range s.Headers {
    num++
    size += 8 + len(h.Name) + len(h.Value)
  }
  out := make([]byte, size)

  out[0] = 0x80 | byte(s.Version>>8)
  out[1] = byte(s.Version)
  out[2] = 0
  out[3] = 1
  out[4] = s.Flags
  out[5] = byte(s.Length >> 16)
  out[6] = byte(s.Length >> 8)
  out[7] = byte(s.Length)
  out[8] = byte(s.StreamID>>24) & 0x7f
  out[9] = byte(s.StreamID >> 16)
  out[10] = byte(s.StreamID >> 8)
  out[11] = byte(s.StreamID)
  out[12] = byte(s.AssocStreamID>>24) & 0x7f
  out[13] = byte(s.AssocStreamID >> 16)
  out[14] = byte(s.AssocStreamID >> 8)
  out[15] = byte(s.AssocStreamID)
  out[16] = ((s.Priority & 0x7) << 5)
  out[17] = s.Slot
  out[18] = byte(num >> 24)
  out[19] = byte(num >> 16)
  out[20] = byte(num >> 8)
  out[21] = byte(num)

  offset := 22
  for _, h := range s.Headers {
    bs := h.Bytes()
    var j int
    for i, b := range bs {
      out[offset+i] = b
      j = offset + i
    }
    offset = j + 1
  }

  return out
}

/*****************
 *** SYN_REPLY ***
 *****************/
type SYN_REPLY_FRAME struct {
  ControlBit byte
  Version    uint16
  Type       uint16
  Flags      byte
  Length     uint32
  StreamID   uint32
  Headers    []*HEADERS_BLOCK
}

func (s *SYN_REPLY_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 16 {
    return &InsufficientData{size, 16}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 2 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 2}
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  s.ControlBit = 1
  s.Version = (uint16(data[0]) << 8) + uint16(data[1])
  s.Type = 2
  s.Flags = data[4]
  s.Length = bytesToUint24(data[5:8])
  s.StreamID = bytesToUint32(data[8:12])
  s.Headers = make([]*HEADERS_BLOCK, 0, bytesToUint32(data[12:16]))
  offset := 16
  if cap(s.Headers) != 0 {
    for offset < size {

      header := &HEADERS_BLOCK{}
      if offset+4 > size {
        return &InsufficientData{size, offset + 4}
      }
      length := (int(data[offset]) << 24) + (int(data[offset+1]) << 16) +
        (int(data[offset+2]) << 8) + int(data[offset+3])
      if offset+4+length > size {
        return &InsufficientData{size, offset + 4 + length}
      }
      header.Name = string(data[offset+4 : offset+4+length])
      offset += 4 + length

      if offset+4 > size {
        return &InsufficientData{size, offset + 4}
      }
      length = (int(data[offset]) << 24) + (int(data[offset+1]) << 16) +
        (int(data[offset+2]) << 8) + int(data[offset+3])
      if offset+4+length > size {
        return &InsufficientData{size, offset + 4 + length}
      }
      header.Value = string(data[offset+4 : offset+4+length])
      offset += 4 + length

      s.Headers = append(s.Headers, header)
    }
  }

  return nil
}

func (s *SYN_REPLY_FRAME) Bytes() []byte {
  size := 16
  num := uint32(0)
  for _, h := range s.Headers {
    num++
    size += 8 + len(h.Name) + len(h.Value)
  }
  out := make([]byte, size)

  out[0] = 0x80 | byte(s.Version>>8)
  out[1] = byte(s.Version)
  out[2] = 0
  out[3] = 2
  out[4] = s.Flags
  out[5] = byte(s.Length >> 16)
  out[6] = byte(s.Length >> 8)
  out[7] = byte(s.Length)
  out[8] = byte(s.StreamID>>24) & 0x7f
  out[9] = byte(s.StreamID >> 16)
  out[10] = byte(s.StreamID >> 8)
  out[11] = byte(s.StreamID)
  out[12] = byte(num >> 24)
  out[13] = byte(num >> 16)
  out[14] = byte(num >> 8)
  out[15] = byte(num)

  offset := 16
  for _, h := range s.Headers {
    bs := h.Bytes()
    var j int
    for i, b := range bs {
      out[offset+i] = b
      j = offset + i
    }
    offset = j + 1
  }

  return out
}

/******************
 *** RST_STREAM ***
 ******************/
type RST_STREAM_FRAME struct {
  ControlBit byte
  Version    uint16
  Type       uint16
  Flags      byte
  Length     uint32
  StreamID   uint32
  StatusCode uint32
}

func (s *RST_STREAM_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 16 {
    return &InsufficientData{size, 16}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 3 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 3}
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  // Check length.
  if bytesToUint24(data[5:8]) != uint32(8) {
    return &InvalidField{"Length", int(bytesToUint24(data[5:8])), 8}
  }

  s.ControlBit = 1
  s.Version = (uint16(data[0]) << 8) + uint16(data[1])
  s.Type = 3
  s.Flags = data[4]
  s.Length = 8
  s.StreamID = bytesToUint32(data[8:12])
  s.StatusCode = bytesToUint32(data[12:16])

  return nil
}

func (s *RST_STREAM_FRAME) Bytes() []byte {
  size := 16
  out := make([]byte, size)

  out[0] = 0x80 | byte(s.Version>>8)
  out[1] = byte(s.Version)
  out[2] = 0
  out[3] = 3
  out[4] = s.Flags
  out[5] = 0
  out[6] = 0
  out[7] = 8
  out[8] = byte(s.StreamID>>24) & 0x7f
  out[9] = byte(s.StreamID >> 16)
  out[10] = byte(s.StreamID >> 8)
  out[11] = byte(s.StreamID)
  out[12] = byte(s.StatusCode >> 24)
  out[13] = byte(s.StatusCode >> 16)
  out[14] = byte(s.StatusCode >> 8)
  out[15] = byte(s.StatusCode)

  return out
}

/****************
 *** SETTINGS ***
 ****************/
type SETTINGS_ENTRY struct {
  Flags byte
  ID    uint32
  Value uint32
}

func (s *SETTINGS_ENTRY) Bytes() []byte {
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

type SETTINGS_FRAME struct {
  ControlBit byte
  Version    uint16
  Type       uint16
  Flags      byte
  Length     uint32
  Entries    []*SETTINGS_ENTRY
}

func (s *SETTINGS_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 12 {
    return &InsufficientData{size, 12}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  } else if uint32(size) < (uint32(12) + (uint32(8) * bytesToUint32(data[8:12]))) {
    return &InsufficientData{size, 12 + (8 * int(bytesToUint32(data[8:12])))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 4 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 4}
  }

  s.ControlBit = 1
  s.Version = (uint16(data[0]) << 8) + uint16(data[1])
  s.Type = 4
  s.Flags = data[4]
  s.Length = bytesToUint24(data[5:8])
  s.Entries = make([]*SETTINGS_ENTRY, 0, bytesToUint32(data[8:12]))
  offset := 12
  if cap(s.Entries) != 0 {
    for offset < size {

      s.Entries = append(s.Entries, &SETTINGS_ENTRY{
        Flags: data[offset],
        ID:    bytesToUint24(data[offset+1 : offset+4]),
        Value: bytesToUint32(data[offset+4 : offset+8]),
      })
    }
  }

  return nil
}

func (s *SETTINGS_FRAME) Bytes() []byte {
  num := uint32(len(s.Entries))
  size := 12 + (8 * num)
  out := make([]byte, size)

  out[0] = 0x80 | byte(s.Version>>8)
  out[1] = byte(s.Version)
  out[2] = 0
  out[3] = 4
  out[4] = s.Flags
  out[5] = byte(s.Length >> 16)
  out[6] = byte(s.Length >> 8)
  out[7] = byte(s.Length)
  out[8] = byte(num >> 24)
  out[9] = byte(num >> 16)
  out[10] = byte(num >> 8)
  out[11] = byte(num)

  offset := 16
  for _, e := range s.Entries {
    bs := e.Bytes()
    var j int
    for i, b := range bs {
      out[offset+i] = b
      j = offset + i
    }
    offset = j + 1
  }

  return out
}

/************
 *** PING ***
 ************/
type PING_FRAME struct {
  ControlBit byte
  Version    uint16
  Type       uint16
  Flags      byte
  Length     uint32
  PingID     uint32
}

func (s *PING_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 12 {
    return &InsufficientData{size, 12}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 6 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 6}
  }

  // Check flags.
  if (data[4]) != 0 {
    return &InvalidField{"Flags", int(data[4]), 0}
  }

  // Check length.
  if bytesToUint24(data[5:8]) != uint32(4) {
    return &InvalidField{"Length", int(bytesToUint24(data[5:8])), 4}
  }

  s.ControlBit = 1
  s.Version = (uint16(data[0]) << 8) + uint16(data[1])
  s.Type = 6
  s.Flags = 0
  s.Length = 4
  s.PingID = bytesToUint32(data[8:12])

  return nil
}

func (s *PING_FRAME) Bytes() []byte {
  size := 12
  out := make([]byte, size)

  out[0] = 0x80 | byte(s.Version>>8)
  out[1] = byte(s.Version)
  out[2] = 0
  out[3] = 6
  out[4] = 0
  out[5] = 0
  out[6] = 0
  out[7] = 4
  out[8] = byte(s.PingID >> 24)
  out[9] = byte(s.PingID >> 16)
  out[10] = byte(s.PingID >> 8)
  out[11] = byte(s.PingID)

  return out
}

/**************
 *** GOAWAY ***
 **************/
type GOAWAY_FRAME struct {
  ControlBit       byte
  Version          uint16
  Type             uint16
  Flags            byte
  Length           uint32
  LastGoodStreamID uint32
  StatusCode       uint32
}

func (s *GOAWAY_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 16 {
    return &InsufficientData{size, 16}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 7 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 7}
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  // Check flags.
  if (data[4]) != 0 {
    return &InvalidField{"Flags", int(data[4]), 0}
  }

  // Check length.
  if bytesToUint24(data[5:8]) != uint32(8) {
    return &InvalidField{"Length", int(bytesToUint24(data[5:8])), 8}
  }

  s.ControlBit = 1
  s.Version = (uint16(data[0]) << 8) + uint16(data[1])
  s.Type = 7
  s.Flags = 0
  s.Length = 8
  s.LastGoodStreamID = bytesToUint32(data[8:12])
  s.StatusCode = bytesToUint32(data[12:16])

  return nil
}

func (s *GOAWAY_FRAME) Bytes() []byte {
  size := 16
  out := make([]byte, size)

  out[0] = 0x80 | byte(s.Version>>8)
  out[1] = byte(s.Version)
  out[2] = 0
  out[3] = 7
  out[4] = 0
  out[5] = 0
  out[6] = 0
  out[7] = 8
  out[8] = byte(s.LastGoodStreamID>>24) & 0x7f
  out[9] = byte(s.LastGoodStreamID >> 16)
  out[10] = byte(s.LastGoodStreamID >> 8)
  out[11] = byte(s.LastGoodStreamID)
  out[12] = byte(s.StatusCode >> 24)
  out[13] = byte(s.StatusCode >> 16)
  out[14] = byte(s.StatusCode >> 8)
  out[15] = byte(s.StatusCode)

  return out
}

type Headers struct {
}

/********************
 *** HEADER_BLOCK ***
 ********************/
type HEADERS_BLOCK struct {
  Name, Value string
}

func (h *HEADERS_BLOCK) Parse(data []byte) error {
  return nil
}

func (h *HEADERS_BLOCK) Bytes() []byte {
  out := make([]byte, 8+len(h.Name)+len(h.Value))
  l := len(h.Name)
  out[0] = byte(l >> 24)
  out[1] = byte(l >> 16)
  out[2] = byte(l >> 8)
  out[3] = byte(l)
  var j int
  for i, b := range []byte(h.Name) {
    out[4+i] = b
    j = 5 + i
  }

  l = len(h.Value)
  out[0+j] = byte(l >> 24)
  out[1+j] = byte(l >> 16)
  out[2+j] = byte(l >> 8)
  out[3+j] = byte(l)
  for i, b := range []byte(h.Value) {
    out[4+j+i] = b
  }

  return out
}

type HEADERS_FRAME struct {
  ControlBit byte
  Version    uint16
  Type       uint16
  Flags      byte
  Length     uint32
  StreamID   uint32
  Headers    []*HEADERS_BLOCK
}

func (h *HEADERS_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 16 {
    return &InsufficientData{size, 16}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 8 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 8}
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  h.ControlBit = 1
  h.Version = (uint16(data[0]) << 8) + uint16(data[1])
  h.Type = 8
  h.Flags = data[4]
  h.Length = bytesToUint24(data[5:8])
  h.StreamID = bytesToUint32(data[8:12])
  h.Headers = make([]*HEADERS_BLOCK, bytesToUint32(data[12:16]))
	
	// TODO: add headers parsing.

  return nil
}

func (h *HEADERS_FRAME) Bytes() []byte {
  size := 12
  num := uint32(0)
  for _, he := range h.Headers {
    num++
    size += 8 + len(he.Name) + len(he.Value)
  }
  out := make([]byte, size)

  out[0] = 0x80 | byte(h.Version>>8)
  out[1] = byte(h.Version)
  out[2] = 0
  out[3] = 8
  out[4] = h.Flags
  out[5] = byte(h.Length >> 16)
  out[6] = byte(h.Length >> 8)
  out[7] = byte(h.Length)
  out[8] = byte(h.StreamID>>24) & 0x7f
  out[9] = byte(h.StreamID >> 16)
  out[10] = byte(h.StreamID >> 8)
  out[11] = byte(h.StreamID)

  offset := 12
  for _, he := range h.Headers {
    bs := he.Bytes()
    var j int
    for i, b := range bs {
      out[offset+i] = b
      j = offset + i
    }
    offset = j + 1
  }

  return out
}

type WINDOW_UPDATE_FRAME struct {
  ControlBit      byte
  Version         uint16
  Type            uint16
  Flags           byte
  Length          uint32
  StreamID        uint32
  DeltaWindowSize uint32
}

func (w *WINDOW_UPDATE_FRAME) Parse(data []byte) error {
  // Check size.
  size := len(data)
  if size < 22 {
    return &InsufficientData{size, 22}
  } else if uint32(size) < (uint32(8) + bytesToUint24(data[5:8])) {
    return &InsufficientData{size, 8 + int(bytesToUint24(data[5:8]))}
  }

  // Check control bit.
  if data[0]&0x80 == 0 {
    return &InvalidField{"Control bit", 0, 1}
  }

  // Check type.
  if data[2] != 0 || data[3] != 8 {
    return &InvalidField{"Type", (int(data[2]) << 8) + int(data[3]), 8}
  }

  // Check unused space.
  if (data[8] >> 7) != 0 {
    return &InvalidField{"Unused", 1, 0}
  }

  w.ControlBit = 1
  w.Version = (uint16(data[0]) << 8) + uint16(data[1])
  w.Type = 8
  w.Flags = data[4]
  w.Length = bytesToUint24(data[5:8])
  w.StreamID = bytesToUint32(data[8:12])
  w.DeltaWindowSize = bytesToUint32(data[12:16]) & 0x7f

  return nil
}

func (w *WINDOW_UPDATE_FRAME) Bytes() []byte {
  size := 12
  out := make([]byte, size)

  out[0] = 0x80 | byte(w.Version>>8)
  out[1] = byte(w.Version)
  out[2] = 0
  out[3] = 8
  out[4] = w.Flags
  out[5] = byte(w.Length >> 16)
  out[6] = byte(w.Length >> 8)
  out[7] = byte(w.Length)
  out[8] = byte(w.StreamID>>24) & 0x7f
  out[9] = byte(w.StreamID >> 16)
  out[10] = byte(w.StreamID >> 8)
  out[11] = byte(w.StreamID)
  out[12] = byte(w.DeltaWindowSize>>24) & 0x7f
  out[13] = byte(w.DeltaWindowSize >> 16)
  out[14] = byte(w.DeltaWindowSize >> 8)
  out[15] = byte(w.DeltaWindowSize)

  return out
}

type CREDENTIAL_FRAME struct {
}

type CERTIFICATE struct {
}
