// Copyright 2014 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package frames

import (
	"bytes"
	"fmt"
	"io"

	"github.com/SlyMarbo/spdy/common"
)

type GOAWAY struct {
	LastGoodStreamID common.StreamID
	Status           common.StatusCode
}

func (frame *GOAWAY) Compress(comp common.Compressor) error {
	return nil
}

func (frame *GOAWAY) Decompress(decomp common.Decompressor) error {
	return nil
}

func (frame *GOAWAY) Name() string {
	return "GOAWAY"
}

func (frame *GOAWAY) ReadFrom(reader io.Reader) (int64, error) {
	data, err := common.ReadExactly(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], _GOAWAY, 0)
	if err != nil {
		return 16, err
	}

	// Get and check length.
	length := int(common.BytesToUint24(data[5:8]))
	if length != 8 {
		return 16, common.IncorrectDataLength(length, 8)
	}

	frame.LastGoodStreamID = common.StreamID(common.BytesToUint32(data[8:12]))
	frame.Status = common.StatusCode(common.BytesToUint32(data[12:16]))

	if !frame.LastGoodStreamID.Valid() {
		return 16, common.StreamIdTooLarge
	}

	return 16, nil
}

func (frame *GOAWAY) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("GOAWAY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Last good stream ID:  %d\n\t", frame.LastGoodStreamID))
	buf.WriteString(fmt.Sprintf("Status code:          %s (%d)\n}\n", frame.Status, frame.Status))

	return buf.String()
}

func (frame *GOAWAY) WriteTo(writer io.Writer) (int64, error) {
	if !frame.LastGoodStreamID.Valid() {
		return 0, common.StreamIdTooLarge
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
	out[8] = frame.LastGoodStreamID.B1()  // Last Good Stream ID
	out[9] = frame.LastGoodStreamID.B2()  // Last Good Stream ID
	out[10] = frame.LastGoodStreamID.B3() // Last Good Stream ID
	out[11] = frame.LastGoodStreamID.B4() // Last Good Stream ID
	out[12] = byte(frame.Status >> 24)    // Status Code
	out[13] = byte(frame.Status >> 16)    // Status Code
	out[14] = byte(frame.Status >> 8)     // Status Code
	out[15] = byte(frame.Status)          // Status Code

	err := common.WriteExactly(writer, out)
	if err != nil {
		return 0, err
	}

	return 16, nil
}
