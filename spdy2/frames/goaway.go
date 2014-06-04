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
	data, err := common.ReadExactly(reader, 12)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], _GOAWAY, 0)
	if err != nil {
		return 12, err
	}

	// Get and check length.
	length := int(common.BytesToUint24(data[5:8]))
	if length != 4 {
		return 12, common.IncorrectDataLength(length, 4)
	}

	frame.LastGoodStreamID = common.StreamID(common.BytesToUint32(data[8:12]))

	if !frame.LastGoodStreamID.Valid() {
		return 12, common.StreamIdTooLarge
	}

	return 12, nil
}

func (frame *GOAWAY) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("GOAWAY {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Last good stream ID:  %d\n}\n", frame.LastGoodStreamID))

	return buf.String()
}

func (frame *GOAWAY) WriteTo(writer io.Writer) (int64, error) {
	if !frame.LastGoodStreamID.Valid() {
		return 0, common.StreamIdTooLarge
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
	out[8] = frame.LastGoodStreamID.B1()  // Last Good Stream ID
	out[9] = frame.LastGoodStreamID.B2()  // Last Good Stream ID
	out[10] = frame.LastGoodStreamID.B3() // Last Good Stream ID
	out[11] = frame.LastGoodStreamID.B4() // Last Good Stream ID

	err := common.WriteExactly(writer, out)
	if err != nil {
		return 0, err
	}

	return 12, nil
}
