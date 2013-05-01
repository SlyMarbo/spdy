package spdy

import (
	"errors"
	"io"
	"net/url"
)

// Response represents the response from an HTTP request.
//
type Response struct {
  Status     string // e.g. "200 OK"
  StatusCode int    // e.g. 200
  Proto      string // e.g. "HTTP/1.0"
  ProtoMajor int    // e.g. 1
  ProtoMinor int    // e.g. 0

  // Header maps header keys to values.  If the response had multiple
  // headers with the same key, they will be concatenated, with comma
  // delimiters.  (Section 4.2 of RFC 2616 requires that multiple headers
  // be semantically equivalent to a comma-delimited sequence.) Values
  // duplicated by other fields in this struct (e.g., ContentLength) are
  // omitted from Header.
  //
  // Keys in the map are canonicalized (see CanonicalHeaderKey).
  Header Header

  // Body represents the response body.
  //
  // The http Client and Transport guarantee that Body is always
  // non-nil, even on responses without a body or responses with
  // a zero-lengthed body.
  //
  // The Body is automatically dechunked if the server replied
  // with a "chunked" Transfer-Encoding.
  Body io.ReadCloser

  // ContentLength records the length of the associated content.  The
  // value -1 indicates that the length is unknown.  Unless Request.Method
  // is "HEAD", values >= 0 indicate that the given number of bytes may
  // be read from Body.
  ContentLength int64

  // Trailer maps trailer keys to values, in the same
  // format as the header.
  Trailer Header

  // The Request that was sent to obtain this Response.
  // Request's Body is nil (having already been consumed).
  // This is only populated for Client requests.
  Request *Request
}

// Cookies parses and returns the cookies set in the Set-Cookie headers.
func (r *Response) Cookies() []*Cookie {
  return readSetCookies(r.Header)
}

var ErrNoLocation = errors.New("spdy: no Location header in response")

// Location returns the URL of the response's "Location" header,
// if present.  Relative redirects are resolved relative to
// the Response's Request.  ErrNoLocation is returned if no
// Location header is present.
func (r *Response) Location() (*url.URL, error) {
  lv := r.Header.Get("Location")
  if lv == "" {
    return nil, ErrNoLocation
  }
  if r.Request != nil && r.Request.URL != nil {
    return r.Request.URL.Parse(lv)
  }
  return url.Parse(lv)
}

// ProtoAtLeast returns whether the HTTP protocol used
// in the response is at least major.minor.
func (r *Response) ProtoAtLeast(major, minor int) bool {
  return r.ProtoMajor > major ||
    r.ProtoMajor == major && r.ProtoMinor >= minor
}
