package spdy

import (
	"net/http"
	"net/url"
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
