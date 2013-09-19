// Copyright 2013 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	sync.Mutex
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
	d.Lock()
	defer d.Unlock()

	// Make sure the buffer is ready.
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

	var size int
	var bytesToInt func([]byte) int

	// SPDY/2 uses 16-bit fixed fields, where SPDY/3 uses 32-bit fields.
	switch d.version {
	case 2:
		size = 2
		bytesToInt = func(b []byte) int {
			return int(bytesToUint16(b))
		}
	case 3:
		size = 4
		bytesToInt = func(b []byte) int {
			return int(bytesToUint32(b))
		}
	default:
		return nil, versionError
	}

	// Read in the number of name/value pairs.
	pairs, err := read(d.out, size)
	if err != nil {
		return nil, err
	}
	numNameValuePairs := bytesToInt(pairs)

	headers = make(http.Header)
	bounds := MAX_FRAME_SIZE - 12 // Maximum frame size minus maximum non-headers data (SYN_STREAM)
	for i := 0; i < numNameValuePairs; i++ {
		var nameLength, valueLength int

		// Get the name's length.
		length, err := read(d.out, size)
		if err != nil {
			return nil, err
		}
		nameLength = bytesToInt(length)
		bounds -= size

		if nameLength > bounds {
			debug.Printf("Error: Maximum header length is %d. Received name length %d.\n", bounds, nameLength)
			return nil, errors.New("Error: Incorrect header name length.")
		}
		bounds -= nameLength

		// Get the name.
		name, err := read(d.out, nameLength)
		if err != nil {
			return nil, err
		}

		// Get the value's length.
		length, err = read(d.out, size)
		if err != nil {
			return nil, err
		}
		valueLength = bytesToInt(length)
		bounds -= size

		if valueLength > bounds {
			debug.Printf("Error: Maximum header length is %d. Received values length %d.\n", bounds, valueLength)
			return nil, errors.New("Error: Incorrect header values length.")
		}
		bounds -= valueLength

		// Get the values.
		values, err := read(d.out, valueLength)
		if err != nil {
			return nil, err
		}

		// Split the value on null boundaries.
		for _, value := range bytes.Split(values, []byte{'\x00'}) {
			headers.Add(string(name), string(value))
		}
	}

	return headers, nil
}

// Compressor is used to compress name/value header blocks.
// Compressors retain their state, so a single Compressor
// should be used for each direction of a particular
// connection.
type compressor struct {
	sync.Mutex
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
	c.Lock()
	defer c.Unlock()

	// Ensure the buffer is prepared.
	if c.buf == nil {
		c.buf = new(bytes.Buffer)
	} else {
		c.buf.Reset()
	}

	// Same for the compressor.
	if c.w == nil {
		var err error
		switch c.version {
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
	}

	var size int // Size of length values.
	switch c.version {
	case 2:
		size = 2
	case 3:
		size = 4
	default:
		return nil, versionError
	}

	// Remove invalid headers.
	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Connection")
	h.Del("Transfer-Encoding")

	length := size                   // The 4-byte or 2-byte number of name/value pairs.
	pairs := make(map[string]string) // Used to store the validated, joined headers.
	for name, values := range h {
		// Ignore invalid names.
		if _, ok := pairs[name]; ok { // We've already seen this name.
			return nil, errors.New("Error: Duplicate header name discovered.")
		}
		if name == "" { // Ignore empty names.
			continue
		}

		// Multiple values are separated by a single null byte.
		pairs[name] = strings.Join(values, "\x00")

		// +size for len(name), +size for len(values).
		length += len(name) + size + len(pairs[name]) + size
	}

	// Uncompressed data.
	out := make([]byte, length)

	// Current offset into out.
	var offset uint32

	// Write the number of name/value pairs.
	num := uint32(len(pairs))
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

	// For each name/value pair...
	for name, value := range pairs {

		// The length of the name.
		nLen := uint32(len(name))
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

		// The name itself.
		copy(out[offset:], []byte(strings.ToLower(name)))
		offset += nLen

		// The length of the value.
		vLen := uint32(len(value))
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

		// The value itself.
		copy(out[offset:], []byte(value))
		offset += vLen
	}

	// Compress.
	err := write(c.w, out)
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
