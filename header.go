package spdy

import (
  "bytes"
  "fmt"
  "io"
  "net/textproto"
  "sort"
  "strings"
  "time"
)

// A Header represents the key-value pairs in an HTTP header.
type Header map[string][]string

func (h Header) String() string {
  buf := new(bytes.Buffer)
  buf.WriteString(fmt.Sprintf("Headers {\n\t\t\t"))
  for name, values := range h {
    buf.WriteString(fmt.Sprintf("%-16s", name))
    l := len(values) - 1
    for i, value := range values {
      buf.WriteString(fmt.Sprintf("%s\n\t\t\t", value))
      if i < l {
        for j := 0; j < 16; j++ {
          buf.WriteString(" ")
        }
      }
    }
  }
  buf.WriteString(fmt.Sprintf("\n\t\t}\n"))
  return buf.String()
}

func (h Header) Parse(data []byte, dec *Decompressor) error {
  header, err := dec.Decompress(3, data)
  if err != nil {
    return err
  }

  for name, values := range header {
    for _, value := range values {
      h.Add(name, value)
    }
  }
  return nil
}

func (h Header) Bytes() []byte {
  h.Del("Connection")
  h.Del("Keep-Alive")
  h.Del("Proxy-Connection")
  h.Del("Transfer-Encoding")

  length := 4
  num := len(h)
  lens := make(map[string]int)
  for name, values := range h {
    length += len(name) + 8
    lens[name] = len(values) - 1
    for _, value := range values {
      length += len(value)
      lens[name] += len(value)
    }
  }

  out := make([]byte, length)
  out[0] = byte(num >> 24)
  out[1] = byte(num >> 16)
  out[2] = byte(num >> 8)
  out[3] = byte(num)

  offset := 4
  for name, values := range h {
    nLen := len(name)
    out[offset+0] = byte(nLen >> 24)
    out[offset+1] = byte(nLen >> 16)
    out[offset+2] = byte(nLen >> 8)
    out[offset+3] = byte(nLen)

    for i, b := range []byte(strings.ToLower(name)) {
      out[offset+4+i] = b
    }

    offset += (4 + nLen)

    vLen := lens[name]
    out[offset+0] = byte(vLen >> 24)
    out[offset+1] = byte(vLen >> 16)
    out[offset+2] = byte(vLen >> 8)
    out[offset+3] = byte(vLen)

    offset += 4

    for n, value := range values {
      for i, b := range []byte(value) {
        out[offset+i] = b
      }
      offset += len(value)
      if n < len(values)-1 {
        out[offset] = '\x00'
        offset += 1
      }
    }
  }

  return out
}

func (h Header) Compressed(com *Compressor) ([]byte, error) {
  return com.Compress(3, h.Bytes())
}

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
func (h Header) Add(key, value string) {
  textproto.MIMEHeader(h).Add(key, value)
}

// Set sets the header entries associated with key to
// the single element value.  It replaces any existing
// values associated with key.
func (h Header) Set(key, value string) {
  textproto.MIMEHeader(h).Set(key, value)
}

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, access the map directly
// with CanonicalHeaderKey.
func (h Header) Get(key string) string {
  return textproto.MIMEHeader(h).Get(key)
}

// get is like Get, but key must already be in CanonicalHeaderKey form.
func (h Header) get(key string) string {
  if v := h[key]; len(v) > 0 {
    return v[0]
  }
  return ""
}

// Del deletes the values associated with key.
func (h Header) Del(key string) {
  textproto.MIMEHeader(h).Del(key)
}

// Write writes a header in wire format.
func (h Header) Write(w io.Writer) error {
  return h.WriteSubset(w, nil)
}

func (h Header) clone() Header {
  h2 := make(Header, len(h))
  for k, vv := range h {
    vv2 := make([]string, len(vv))
    copy(vv2, vv)
    h2[k] = vv2
  }
  return h2
}

var timeFormats = []string{
  TimeFormat,
  time.RFC850,
  time.ANSIC,
}

// ParseTime parses a time header (such as the Date: header),
// trying each of the three formats allowed by HTTP/1.1:
// TimeFormat, time.RFC850, and time.ANSIC.
func ParseTime(text string) (t time.Time, err error) {
  for _, layout := range timeFormats {
    t, err = time.Parse(layout, text)
    if err == nil {
      return
    }
  }
  return
}

var headerNewlineToSpace = strings.NewReplacer("\n", " ", "\r", " ")

type writeStringer interface {
  WriteString(string) (int, error)
}

// stringWriter implements WriteString on a Writer.
type stringWriter struct {
  w io.Writer
}

func (w stringWriter) WriteString(s string) (n int, err error) {
  return w.w.Write([]byte(s))
}

type keyValues struct {
  key    string
  values []string
}

// A headerSorter implements sort.Interface by sorting a []keyValues
// by key. It's used as a pointer, so it can fit in a sort.Interface
// interface value without allocation.
type headerSorter struct {
  kvs []keyValues
}

func (s *headerSorter) Len() int           { return len(s.kvs) }
func (s *headerSorter) Swap(i, j int)      { s.kvs[i], s.kvs[j] = s.kvs[j], s.kvs[i] }
func (s *headerSorter) Less(i, j int) bool { return s.kvs[i].key < s.kvs[j].key }

// TODO: convert this to a sync.Cache (issue 4720)
var headerSorterCache = make(chan *headerSorter, 8)

// sortedKeyValues returns h's keys sorted in the returned kvs
// slice. The headerSorter used to sort is also returned, for possible
// return to headerSorterCache.
func (h Header) sortedKeyValues(exclude map[string]bool) (kvs []keyValues, hs *headerSorter) {
  select {
  case hs = <-headerSorterCache:
  default:
    hs = new(headerSorter)
  }
  if cap(hs.kvs) < len(h) {
    hs.kvs = make([]keyValues, 0, len(h))
  }
  kvs = hs.kvs[:0]
  for k, vv := range h {
    if !exclude[k] {
      kvs = append(kvs, keyValues{k, vv})
    }
  }
  hs.kvs = kvs
  sort.Sort(hs)
  return kvs, hs
}

// WriteSubset writes a header in wire format.
// If exclude is not nil, keys where exclude[key] == true are not written.
func (h Header) WriteSubset(w io.Writer, exclude map[string]bool) error {
  ws, ok := w.(writeStringer)
  if !ok {
    ws = stringWriter{w}
  }
  kvs, sorter := h.sortedKeyValues(exclude)
  for _, kv := range kvs {
    for _, v := range kv.values {
      v = headerNewlineToSpace.Replace(v)
      v = textproto.TrimString(v)
      for _, s := range []string{kv.key, ": ", v, "\r\n"} {
        if _, err := ws.WriteString(s); err != nil {
          return err
        }
      }
    }
  }
  select {
  case headerSorterCache <- sorter:
  default:
  }
  return nil
}

// CanonicalHeaderKey returns the canonical format of the
// header key s.  The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase.  For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }

// hasToken returns whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
func hasToken(v, token string) bool {
  if len(token) > len(v) || token == "" {
    return false
  }
  if v == token {
    return true
  }
  for sp := 0; sp <= len(v)-len(token); sp++ {
    // Check that first character is good.
    // The token is ASCII, so checking only a single byte
    // is sufficient.  We skip this potential starting
    // position if both the first byte and its potential
    // ASCII uppercase equivalent (b|0x20) don't match.
    // False positives ('^' => '~') are caught by EqualFold.
    if b := v[sp]; b != token[0] && b|0x20 != token[0] {
      continue
    }
    // Check that start pos is on a valid token boundary.
    if sp > 0 && !isTokenBoundary(v[sp-1]) {
      continue
    }
    // Check that end pos is on a valid token boundary.
    if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
      continue
    }
    if strings.EqualFold(v[sp:sp+len(token)], token) {
      return true
    }
  }
  return false
}

func isTokenBoundary(b byte) bool {
  return b == ' ' || b == ',' || b == '\t'
}
