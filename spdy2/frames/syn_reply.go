// Copyright 2014 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package frames

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/SlyMarbo/spdy/common"
)

type SYN_REPLY struct {
	Flags     common.Flags
	StreamID  common.StreamID
	Header    http.Header
	rawHeader []byte
}

func (frame *SYN_REPLY) Compress(com common.Compressor) error {
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

func (frame *SYN_REPLY) Decompress(decom common.Decompressor) error {
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

func (frame *SYN_REPLY) Name() string {
	return "SYN_REPLY"
}

func (frame *SYN_REPLY) ReadFrom(reader io.Reader) (int64, error) {
	data, err := common.ReadExactly(reader, 14)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], _SYN_REPLY, common.FLAG_FIN)
	if err != nil {
		return 14, err
	}

	// Get and check length.
	length := int(common.BytesToUint24(data[5:8]))
	if length < 8 {
		return 14, common.IncorrectDataLength(length, 8)
	} else if length > common.MAX_FRAME_SIZE-8 {
		return 14, common.FrameTooLarge
	}

	// Read in data.
	header, err := common.ReadExactly(reader, length-6)
	if err != nil {
		return 14, err
	}

	frame.Flags = common.Flags(data[4])
	frame.StreamID = common.StreamID(common.BytesToUint32(data[8:12]))
	frame.rawHeader = header

	return int64(length + 8), nil
}

func (frame *SYN_REPLY) String() string {
	buf := new(bytes.Buffer)
	flags := ""
	if frame.Flags.FIN() {
		flags += " common.FLAG_FIN"
	}
	if flags == "" {
		flags = "[NONE]"
	} else {
		flags = flags[1:]
	}

	buf.WriteString("SYN_REPLY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Flags:                %s\n\t", flags))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Header:               %v\n}\n", frame.Header))

	return buf.String()
}

func (frame *SYN_REPLY) WriteTo(writer io.Writer) (int64, error) {
	if frame.rawHeader == nil {
		return 0, errors.New("Error: Header not written.")
	}
	if !frame.StreamID.Valid() {
		return 0, common.StreamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 0, common.StreamIdIsZero
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
	out[8] = frame.StreamID.B1()  // Stream ID
	out[9] = frame.StreamID.B2()  // Stream ID
	out[10] = frame.StreamID.B3() // Stream ID
	out[11] = frame.StreamID.B4() // Stream ID
	out[12] = 0                   // Unused
	out[13] = 0                   // Unused

	err := common.WriteExactly(writer, out)
	if err != nil {
		return 0, err
	}

	err = common.WriteExactly(writer, header)
	if err != nil {
		return 14, err
	}

	return int64(len(header) + 14), nil
}
