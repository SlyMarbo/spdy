package spdy

import (
  "net/http"
  "net/url"
)

type _httpResponseWriter struct {
  ResponseWriter
}

func (h *_httpResponseWriter) Header() http.Header {
  return http.Header(h.ResponseWriter.Header())
}

type _httpPushWriter struct {
  PushWriter
}

func (h *_httpPushWriter) Header() http.Header {
  return http.Header(h.PushWriter.Header())
}

func (_ *_httpPushWriter) WriteHeader(_ int) {
  return
}

func ServeFile(wrt ResponseWriter, req *Request, name string) {
  r := spdyRequestToHttpRequest(req)
  w := &_httpResponseWriter{wrt}
  http.ServeFile(w, r, name)
}

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
