package frames

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/SlyMarbo/spdy/common"
)

type WindowUpdateFrame struct {
	StreamID        common.StreamID
	DeltaWindowSize uint32
}

func (frame *WindowUpdateFrame) Compress(comp common.Compressor) error {
	return nil
}

func (frame *WindowUpdateFrame) Decompress(decomp common.Decompressor) error {
	return nil
}

func (frame *WindowUpdateFrame) Name() string {
	return "WINDOW_UPDATE"
}

func (frame *WindowUpdateFrame) ReadFrom(reader io.Reader) (int64, error) {
	data, err := common.ReadExactly(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], WINDOW_UPDATE, 0)
	if err != nil {
		return 16, err
	}

	// Get and check length.
	length := int(common.BytesToUint24(data[5:8]))
	if length != 8 {
		return 16, common.IncorrectDataLength(length, 8)
	}

	frame.StreamID = common.StreamID(common.BytesToUint32(data[8:12]))
	frame.DeltaWindowSize = common.BytesToUint32(data[12:16])

	if !frame.StreamID.Valid() {
		return 16, common.StreamIdTooLarge
	}
	if frame.StreamID.Zero() {
		return 16, common.StreamIdIsZero
	}
	if frame.DeltaWindowSize > common.MAX_DELTA_WINDOW_SIZE {
		return 16, errors.New("Error: Delta Window Size too large.")
	}

	return 16, nil
}

func (frame *WindowUpdateFrame) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("WINDOW_UPDATE {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Delta window size:    %d\n}\n", frame.DeltaWindowSize))

	return buf.String()
}

func (frame *WindowUpdateFrame) WriteTo(writer io.Writer) (int64, error) {
	return 0, nil
}
