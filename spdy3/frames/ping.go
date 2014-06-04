package frames

import (
	"bytes"
	"fmt"
	"io"

	"github.com/SlyMarbo/spdy/common"
)

type PING struct {
	PingID uint32
}

func (frame *PING) Compress(comp common.Compressor) error {
	return nil
}

func (frame *PING) Decompress(decomp common.Decompressor) error {
	return nil
}

func (frame *PING) Name() string {
	return "PING"
}

func (frame *PING) ReadFrom(reader io.Reader) (int64, error) {
	data, err := common.ReadExactly(reader, 12)
	if err != nil {
		return 0, err
	}

	err = controlFrameCommonProcessing(data[:5], _PING, 0)
	if err != nil {
		return 12, err
	}

	// Get and check length.
	length := int(common.BytesToUint24(data[5:8]))
	if length != 4 {
		return 12, common.IncorrectDataLength(length, 4)
	}

	frame.PingID = common.BytesToUint32(data[8:12])

	return 12, nil
}

func (frame *PING) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("PING {\n\t")
	buf.WriteString(fmt.Sprintf("Version:              3\n\t"))
	buf.WriteString(fmt.Sprintf("Ping ID:              %d\n}\n", frame.PingID))

	return buf.String()
}

func (frame *PING) WriteTo(writer io.Writer) (int64, error) {
	out := make([]byte, 12)

	out[0] = 128                      // Control bit and Version
	out[1] = 3                        // Version
	out[2] = 0                        // Type
	out[3] = 6                        // Type
	out[4] = 0                        // common.Flags
	out[5] = 0                        // Length
	out[6] = 0                        // Length
	out[7] = 4                        // Length
	out[8] = byte(frame.PingID >> 24) // Ping ID
	out[9] = byte(frame.PingID >> 16) // Ping ID
	out[10] = byte(frame.PingID >> 8) // Ping ID
	out[11] = byte(frame.PingID)      // Ping ID

	err := common.WriteExactly(writer, out)
	if err != nil {
		return 0, err
	}

	return 12, nil
}
