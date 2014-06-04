package frames

import (
	"bytes"
	"fmt"
	"io"

	"github.com/SlyMarbo/spdy/common"
)

type RST_STREAM struct {
	StreamID common.StreamID
	Status   common.StatusCode
}

func (frame *RST_STREAM) Compress(comp common.Compressor) error {
	return nil
}

func (frame *RST_STREAM) Decompress(decomp common.Decompressor) error {
	return nil
}

func (frame *RST_STREAM) Name() string {
	return "RST_STREAM"
}

func (frame *RST_STREAM) ReadFrom(reader io.Reader) (int64, error) {
	data, err := common.ReadExactly(reader, 16)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], _RST_STREAM, 0)
	if err != nil {
		return 16, err
	}

	// Get and check length.
	length := int(common.BytesToUint24(data[5:8]))
	if length != 8 {
		return 16, common.IncorrectDataLength(length, 8)
	} else if length > common.MAX_FRAME_SIZE-8 {
		return 16, common.FrameTooLarge
	}

	frame.StreamID = common.StreamID(common.BytesToUint32(data[8:12]))
	frame.Status = common.StatusCode(common.BytesToUint32(data[12:16]))

	if !frame.StreamID.Valid() {
		return 16, common.StreamIdTooLarge
	}

	return 16, nil
}

func (frame *RST_STREAM) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("RST_STREAM {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Stream ID:            %d\n\t", frame.StreamID))
	buf.WriteString(fmt.Sprintf("Status code:          %s\n}\n", frame.Status))

	return buf.String()
}

func (frame *RST_STREAM) WriteTo(writer io.Writer) (int64, error) {
	if !frame.StreamID.Valid() {
		return 0, common.StreamIdTooLarge
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
	out[8] = frame.StreamID.B1()  // Stream ID
	out[9] = frame.StreamID.B2()  // Stream ID
	out[10] = frame.StreamID.B3() // Stream ID
	out[11] = frame.StreamID.B4() // Stream ID
	out[12] = frame.Status.B1()   // Status
	out[13] = frame.Status.B2()   // Status
	out[14] = frame.Status.B3()   // Status
	out[15] = frame.Status.B4()   // Status

	err := common.WriteExactly(writer, out)
	if err != nil {
		return 0, err
	}

	return 16, nil
}
