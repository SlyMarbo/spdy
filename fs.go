package spdy

import (
	"net/http"
)

type httpResponseWriter struct {
	ResponseWriter
}

func (h *httpResponseWriter) Header() http.Header {
	return http.Header(h.ResponseWriter.Header())
}

func ServeFile(wrt ResponseWriter, req *Request, name string) {
	r := spdyRequestToHttpRequest(req)
	w := &httpResponseWriter{wrt}
	http.ServeFile(w, r, name)
}
