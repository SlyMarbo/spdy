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

type Decompressor struct {
  m   sync.Mutex
  in  *bytes.Buffer
  out io.ReadCloser
}

func (d *Decompressor) Decompress(version int, data []byte) (headers Header, err error) {
  d.m.Lock()
  defer d.m.Unlock()

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
  length := 0
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

    // Count name and ': '.
    length += keyLen + 2

    // Split the value on null boundaries.
    for _, val := range bytes.Split(value, []byte{'\x00'}) {
      headers.Add(string(key), string(val))
      length += len(val) + 2 // count value and ', ' or '\n\r'.
    }
  }

  if DebugMode {
    fmt.Printf("Headers decompressed from %d bytes to %d.\n", len(data), length)
  }

  return headers, nil
}

type Compressor struct {
  m   sync.Mutex
  buf *bytes.Buffer
  w   *zlib.Writer
}

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
