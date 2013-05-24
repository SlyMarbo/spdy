package spdy

import (
	"io"
	"net/http"
	"net/url"
	"time"
)

// _httpResponseWriter is just a wrapper used
// to allow a spdy.PushWriter to fulfil the
// http.ResponseWriter interface.
type _httpPushWriter struct {
	PushWriter
}

func (h *_httpPushWriter) WriteHeader(int) {
	h.WriteHeaders()
}

// ServeContent replies to the request using the content in the
// provided ReadSeeker.  The main benefit of ServeContent over io.Copy
// is that it handles Range requests properly, sets the MIME type, and
// handles If-Modified-Since requests.
//
// If the response's Content-Type header is not set, ServeContent
// first tries to deduce the type from name's file extension and,
// if that fails, falls back to reading the first block of the content
// and passing it to DetectContentType.
// The name is otherwise unused; in particular it can be empty and is
// never sent in the response.
//
// If modtime is not the zero time, ServeContent includes it in a
// Last-Modified header in the response.  If the request includes an
// If-Modified-Since header, ServeContent uses modtime to decide
// whether the content needs to be sent at all.
//
// The content's Seek method must work: ServeContent uses
// a seek to the end of the content to determine its size.
//
// If the caller has set w's ETag header, ServeContent uses it to
// handle requests using If-Range and If-None-Match.
//
// Note that *os.File implements the io.ReadSeeker interface.
func ServeContent(w ResponseWriter, r *http.Request, name string, modtime time.Time, content io.ReadSeeker) {
	http.ServeContent(w, r, name, modtime, content)
}

// ServeFile replies to the request with the contents of
// the named file or directory.
func ServeFile(w ResponseWriter, r *http.Request, name string) {
	http.ServeFile(w, r, name)
}

// PushFile uses a server push to send the contents of
// the named file or directory directly to the client.
//
//		func ServeSPDY(w spdy.ResponseWriter, r *spdy.Request) {
//			
//			spdy.PushFile(w, r, "/", "./index.html")
//			
//      // ...
//		}
func PushFile(wrt ResponseWriter, r *http.Request, name, path string) error {
	url := new(url.URL)
	*url = *r.URL
	url.Path = name

	push, err := wrt.Push(url.String())
	if err != nil {
		return err
	}
	w := &_httpPushWriter{push}
	http.ServeFile(w, r, path)
	push.Close()
	return nil
}
