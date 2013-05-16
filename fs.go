package spdy

import (
	"net/http"
	"net/url"
)

// _httpResponseWriter is just a wrapper used
// to allow a spdy.ResponseWriter to fulfil
// the http.ResponseWriter interface.
type _httpResponseWriter struct {
	ResponseWriter
}

func (h *_httpResponseWriter) Header() http.Header {
	return http.Header(h.ResponseWriter.Header())
}

// _httpResponseWriter is just a wrapper used
// to allow a spdy.PushWriter to fulfil the
// http.ResponseWriter interface.
type _httpPushWriter struct {
	PushWriter
}

func (h *_httpPushWriter) Header() http.Header {
	return http.Header(h.PushWriter.Header())
}

func (h *_httpPushWriter) WriteHeader(_ int) {
	h.WriteHeaders()
}

// ServeFile replies to the request with the contents of
// the named file or directory.
func ServeFile(wrt ResponseWriter, req *Request, name string) {
	r := spdyRequestToHttpRequest(req)
	w := &_httpResponseWriter{wrt}
	http.ServeFile(w, r, name)
}

// PushFile uses a server push to send the contents of
// the named file or directory directly to the client.
func PushFile(wrt ResponseWriter, req *Request, name, path string) error {
	url := new(url.URL)
	*url = *req.URL
	url.Path = name

	push, err := wrt.Push(url.String())
	if err != nil {
		return err
	}
	r := spdyRequestToHttpRequest(req)
	w := &_httpPushWriter{push}
	http.ServeFile(w, r, path)
	push.Close()
	return nil
}

func NotFound(w ResponseWriter, r *Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 page not found"))
}
