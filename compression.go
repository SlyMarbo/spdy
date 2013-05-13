package spdy

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"sync"
)

var versionError = errors.New("spdy: Version not supported.")

// Decompressor is used to decompress name/value header blocks.
// Decompressors retain their state, so a single Decompressor
// should be used for each direction of a particular connection.
type Decompressor struct {
	m   sync.Mutex
	in  *bytes.Buffer
	out io.ReadCloser
}

// Decompress uses zlib decompression to decompress the provided
// data, according to the SPDY specification of the given version.
func (d *Decompressor) Decompress(version int, data []byte) (headers Header, err error) {
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
		switch version {
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
	switch version {
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
		panic(err)
		return nil, err
	}
	numNameValuePairs := dechunk(chunk)

	headers = make(Header)
	length := 0
	for i := 0; i < numNameValuePairs; i++ {
		var nameLength, valueLength int

		// Get the name.
		if _, err = d.out.Read(chunk); err != nil {
			return nil, err
		}
		nameLength = dechunk(chunk)

		// TODO: bounds check the name length.

		name := make([]byte, nameLength)
		if _, err = d.out.Read(name); err != nil {
			panic(err)
			return nil, err
		}

		// Get the value.
		if _, err = d.out.Read(chunk); err != nil {
			panic(err)
			return nil, err
		}
		valueLength = dechunk(chunk)

		// TODO: bounds check the value length.

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

	if DebugMode {
		fmt.Printf("Headers decompressed from %d bytes to %d.\n", len(data), length)
	}

	return headers, nil
}

// Compressor is used to compress name/value header blocks.
// Compressors retain their state, so a single Compressor
// should be used for each direction of a particular
// connection.
type Compressor struct {
	m   sync.Mutex
	buf *bytes.Buffer
	w   *zlib.Writer
}

// Compress uses zlib compression to compress the provided
// data, according to the SPDY specification of the given version.
func (c *Compressor) Compress(version int, data []byte) ([]byte, error) {
	c.m.Lock()
	defer c.m.Unlock()

	var err error
	if c.buf == nil {
		c.buf = new(bytes.Buffer)

		switch version {
		case 2:
			c.w, err = zlib.NewWriterLevelDict(c.buf, zlib.BestCompression, HeaderDictionaryV2)
		case 3:
			c.w, err = zlib.NewWriterLevelDict(c.buf, zlib.BestCompression, HeaderDictionaryV3)
		default:
			err = versionError
		}

		if err != nil {
			return nil, err
		}
	} else {
		c.buf.Reset()
	}

	_, err = c.w.Write(data)
	if err != nil {
		return nil, err
	}

	c.w.Flush()
	return c.buf.Bytes(), nil
}
