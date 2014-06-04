package frames

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/SlyMarbo/spdy/common"
)

type WINDOW_UPDATE struct {
	StreamID        common.StreamID
	DeltaWindowSize uint32
}

func (frame *WINDOW_UPDATE) Compress(comp common.Compressor) error {
	return nil
}

func (frame *WINDOW_UPDATE) Decompress(decomp common.Decompressor) error {
	return nil
}

func (frame *WINDOW_UPDATE) Name() string {
	return "WINDOW_UPDATE"
}

func (frame *WINDOW_UPDATE) ReadFrom(reader io.Reader) (int64, error) {
	data, err := common.ReadExactly(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], _WINDOW_UPDATE, 0)
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

func (frame *WINDOW_UPDATE) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("WINDOW_UPDATE {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              2\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Delta window size:    %d\n}\n", frame.DeltaWindowSize))

	return buf.String()
}

func (frame *WINDOW_UPDATE) WriteTo(writer io.Writer) (int64, error) {
	return 0, nil
}
