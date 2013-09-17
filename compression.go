package spdy

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

var versionError = errors.New("Version not supported.")

// Decompressor is used to decompress name/value header blocks.
// Decompressors retain their state, so a single Decompressor
// should be used for each direction of a particular connection.
type decompressor struct {
	m       sync.Mutex
	in      *bytes.Buffer
	out     io.ReadCloser
	version uint16
}

// NewDecompressor is used to create a new decompressor.
// It takes the SPDY version to use.
func NewDecompressor(version uint16) Decompressor {
	out := new(decompressor)
	out.version = version
	return out
}

// Decompress uses zlib decompression to decompress the provided
// data, according to the SPDY specification of the given version.
func (d *decompressor) Decompress(data []byte) (headers http.Header, err error) {
	d.m.Lock()
	defer d.m.Unlock()

	if d.in == nil {
		d.in = bytes.NewBuffer(data)
	} else {
		d.in.Reset()
		d.in.Write(data)
	}

	// Initialise the decompressor with the appropriate
	// dictionary, depending on SPDY version.
	if d.out == nil {
		switch d.version {
		case 2:
			d.out, err = zlib.NewReaderDict(d.in, HeaderDictionaryV2)
		case 3:
			d.out, err = zlib.NewReaderDict(d.in, HeaderDictionaryV3)
		default:
			err = versionError
		}

		if err != nil {
			return nil, err
		}
	}

	var chunk []byte
	var dechunk func([]byte) int

	// SPDY/2 uses 16-bit fixed fields, where SPDY/3 uses 32-bit fields.
	switch d.version {
	case 2:
		chunk = make([]byte, 2)
		dechunk = func(b []byte) int {
			return int(bytesToUint16(b))
		}
	case 3:
		chunk = make([]byte, 4)
		dechunk = func(b []byte) int {
			return int(bytesToUint32(b))
		}
	default:
		return nil, versionError
	}

	// Read in the number of name/value pairs.
	if _, err = d.out.Read(chunk); err != nil {
		return nil, err
	}
	numNameValuePairs := dechunk(chunk)

	headers = make(http.Header)
	length := 0
	bounds := MAX_FRAME_SIZE - 12 // Maximum frame size minus maximum non-headers data (SYN_STREAM)
	for i := 0; i < numNameValuePairs; i++ {
		var nameLength, valueLength int

		// Get the name.
		if _, err = d.out.Read(chunk); err != nil {
			return nil, err
		}
		nameLength = dechunk(chunk)

		if nameLength > bounds {
			debug.Printf("Error: Maximum header length is %d. Received name length %d.\n", bounds, nameLength)
			return nil, errors.New("Error: Incorrect header name length.")
		}
		bounds -= nameLength

		name := make([]byte, nameLength)
		if _, err = d.out.Read(name); err != nil {
			return nil, err
		}

		// Get the value.
		if _, err = d.out.Read(chunk); err != nil {
			return nil, err
		}
		valueLength = dechunk(chunk)

		if valueLength > bounds {
			debug.Printf("Error: Maximum remaining header length is %d. Received values length %d.\n",
				bounds, valueLength)
			return nil, errors.New("Error: Incorrect header values length.")
		}
		bounds -= valueLength

		values := make([]byte, valueLength)
		if _, err = d.out.Read(values); err != nil {
			return nil, err
		}

		// Count name and ': '.
		length += nameLength + 2

		// Split the value on null boundaries.
		for _, value := range bytes.Split(values, []byte{'\x00'}) {
			headers.Add(string(name), string(value))
			length += len(value) + 2 // count value and ', ' or '\n\r'.
		}
	}

	return headers, nil
}

// Compressor is used to compress name/value header blocks.
// Compressors retain their state, so a single Compressor
// should be used for each direction of a particular
// connection.
type compressor struct {
	m       sync.Mutex
	buf     *bytes.Buffer
	w       *zlib.Writer
	version uint16
}

// NewCompressor is used to create a new compressor.
// It takes the SPDY version to use.
func NewCompressor(version uint16) Compressor {
	out := new(compressor)
	out.version = version
	return out
}

// Compress uses zlib compression to compress the provided
// data, according to the SPDY specification of the given version.
func (c *compressor) Compress(h http.Header) ([]byte, error) {
	c.m.Lock()
	defer c.m.Unlock()

	var err error
	if c.buf == nil {
		c.buf = new(bytes.Buffer)

		if c.w == nil {
			switch c.version {
			case 2:
				c.w, err = zlib.NewWriterLevelDict(c.buf, zlib.BestCompression, HeaderDictionaryV2)
			case 3:
				c.w, err = zlib.NewWriterLevelDict(c.buf, zlib.BestCompression, HeaderDictionaryV3)
			default:
				err = versionError
			}
		}

		if err != nil {
			return nil, err
		}
	} else {
		c.buf.Reset()
	}

	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Connection")
	h.Del("Transfer-Encoding")

	length := 4 // The 4-byte number of name/value pairs.
	num := len(h)
	lens := make(map[string]int)
	for name, values := range h {
		if _, ok := lens[name]; ok {
			return nil, errors.New("Error: Duplicate header name discovered.")
		}

		lens[name] = len(values) - 1 // +1 for each null separator, (fence post)
		if len(values) == 0 {
			lens[name] = 0 // No separator.
		}

		for _, value := range values {
			lens[name] += len(value)
		}
		length += len(name) + lens[name] + 8 // +4 for len(name), +4 for len(values).
	}

	out := make([]byte, length)
	var offset int
	switch c.version {
	case 3:
		out[0] = byte(num >> 24)
		out[1] = byte(num >> 16)
		out[2] = byte(num >> 8)
		out[3] = byte(num)
		offset = 4
	case 2:
		out[0] = byte(num >> 8)
		out[1] = byte(num)
		offset = 2
	}

	for name, values := range h {
		nLen := len(name)
		switch c.version {
		case 3:
			out[offset+0] = byte(nLen >> 24)
			out[offset+1] = byte(nLen >> 16)
			out[offset+2] = byte(nLen >> 8)
			out[offset+3] = byte(nLen)
			offset += 4
		case 2:
			out[offset+0] = byte(nLen >> 8)
			out[offset+1] = byte(nLen)
			offset += 2
		}

		for i, b := range []byte(strings.ToLower(name)) {
			out[offset+i] = b
		}

		offset += nLen

		vLen := lens[name]
		switch c.version {
		case 3:
			out[offset+0] = byte(vLen >> 24)
			out[offset+1] = byte(vLen >> 16)
			out[offset+2] = byte(vLen >> 8)
			out[offset+3] = byte(vLen)
			offset += 4
		case 2:
			out[offset+0] = byte(vLen >> 8)
			out[offset+1] = byte(vLen)
			offset += 2
		}

		for n, value := range values {
			for i, b := range []byte(value) {
				out[offset+i] = b
			}
			offset += len(value)
			if n < len(values)-1 {
				out[offset] = '\x00'
				offset++
			}
		}
	}

	_, err = c.w.Write(out)
	if err != nil {
		return nil, err
	}

	c.w.Flush()
	return c.buf.Bytes(), nil
}

func (c *compressor) Close() error {
	if c.w == nil {
		return nil
	}
	err := c.w.Close()
	if err != nil {
		return err
	}
	c.w = nil
	return nil
}
