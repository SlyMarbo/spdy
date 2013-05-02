package spdy

import (
  "bytes"
  "compress/zlib"
  "errors"
  "io"
)

var versionError = errors.New("spdy: Version not supported.")

type decompressor struct {
  in  *bytes.Buffer
  out io.ReadCloser
}

func (d *decompressor) Decompress(version int, data []byte) (headers Header, err error) {
  if d.in == nil {
    d.in = bytes.NewBuffer(data)
  } else {
    d.in.Reset()
    d.in.Write(data)
  }

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

  if _, err = d.out.Read(chunk); err != nil {
    panic(err)
    return nil, err
  }
  numKeys := dechunk(chunk)

  headers = make(Header)
  for i := 0; i < numKeys; i++ {
    var keyLen, valLen int

    // Get the key.
    if _, err = d.out.Read(chunk); err != nil {
      return nil, err
    }
    keyLen = dechunk(chunk)

    // TODO: bounds check the key length.

    key := make([]byte, keyLen)
    if _, err = d.out.Read(key); err != nil {
      panic(err)
      return nil, err
    }

    // Get the value.
    if _, err = d.out.Read(chunk); err != nil {
      panic(err)
      return nil, err
    }
    valLen = dechunk(chunk)

    // TODO: bounds check the value length.

    value := make([]byte, valLen)
    if _, err = d.out.Read(value); err != nil {
      return nil, err
    }

    // Split the value on null boundaries.
    for _, val := range bytes.Split(value, []byte{'\x00'}) {
      headers.Add(string(key), string(val))
    }
  }

  return headers, nil
}

type compressor struct {
  buf *bytes.Buffer
  w   *zlib.Writer
}

func (c *compressor) Compress(version int, data []byte) ([]byte, error) {
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
