package spdy

import (
  "crypto/tls"
  "errors"
  "fmt"
  "net/http"
  "net/url"
  "path"
  "strings"
  "sync"
)

// AddSPDY adjusts the given server too support SPDY/v3.
//
// TODO: Add spdy/2 support.
func AddSPDY(server *http.Server) {
  if server.TLSNextProto == nil {
    server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
  }
  //server.TLSNextProto["spdy/2"] = acceptSPDYVersion2
  server.TLSNextProto["spdy/3"] = acceptSPDYVersion3

  if server.TLSConfig == nil {
    server.TLSConfig = new(tls.Config)
  }
  if server.TLSConfig.NextProtos == nil {
    server.TLSConfig.NextProtos = []string{
      "spdy/3",
      //"spdy/2",
    }
  } else {
    server.TLSConfig.NextProtos = append(server.TLSConfig.NextProtos, []string{
      "spdy/3",
      //"spdy/2",
    }...)
  }
}

type Handler interface {
  ServeSPDY(ResponseWriter, *Request)
}

type ResponseWriter interface {
  // Header returns the header map that will be sent by WriteHeader.
  // Changing the header after a call to WriteHeader (or Write) has
  // no effect.
  Header() Header

  // Ping immediately returns a channel on which a single boolean will
  // sent when the ping completes, which can be used as some measure of
  // the network's current performance. The boolean will be false if
  // the ping failed for any reason, and true otherwise.
  Ping() <-chan bool

  // Push returns a PushWriter which can be used immediately to send
  // server pushes.
  Push() (PushWriter, error)

  // Write writes the data to the connection as part of an HTTP/SPDY
  // reply. If WriteHeader has not yet been called, Write calls
  // WriteHeader(http.StatusOK) before writing the data. If the Header
  // does not contain a Content-Type line, Write adds a Content-Type
  // set to the result of passing the initial 512 bytes of written
  // data to DetectContentType.
  Write([]byte) (int, error)

  // WriteHeader sends an HTTP/SPDY response header with status code.
  // If WriteHeader is not called explicitly, the first call to Write
  // will Trigger an implicit WriteHeader(http.StatusOK). Thus
  // explicit calls to WriteHeader are mainly used to send error codes.
  WriteHeader(int)
}

type PushWriter interface {
  // Header returns the header map that will be sent with the push.
  // Changing the header after a call to Write has no effect.
  Header() Header

  // Ping immediately returns a channel on which a single boolean will
  // sent when the ping completes, which can be used as some measure of
  // the network's current performance. The boolean will be false if
  // the ping failed for any reason, and true otherwise.
  Ping() <-chan bool

  // Write writes the data to the connection as part of a SPDY server
  // push. If the Header does not contain a Content-Type line, Write
  // adds a Content-Type set to the result of passing the initial 512
  // bytes of written data to DetectContentType.
  Write([]byte) (int, error)
}

// The HandlerFunc type is an adapter to allow the use of ordinary
// functions as SPDY handlers. If f is a function with the appropriate
// signature, HandlerFunc(f) is a Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeSPDY calls f(w, r).
func (f HandlerFunc) ServeSPDY(w ResponseWriter, r *Request) {
  f(w, r)
}

// Helper handlers.

// Error replies to the request with the specified error message and
// HTTP code.
func Error(w ResponseWriter, error string, code int) {
  w.Header().Set("Content-Type", "text/plain; charset=utf-8")
  w.WriteHeader(code)
  fmt.Fprintln(w, error)
}

// NotFound replies to the request with an HTTP 404 not found error.
func NotFound(w ResponseWriter, _ *Request) {
  Error(w, "404 page not found", http.StatusNotFound)
}

// NotFoundHandler returns a simple request handler that replies to
// each request with a ''404 page not found'' reply.
func NotFoundHandler() Handler {
  return HandlerFunc(NotFound)
}

// StripPrefix returns a handler that serves SPDY requests by removing
// the given prefix from the request URL's Path and invoking the
// handler h. StripPrefix handles a request for a path that doesn't
// begin with prefix by replying with an HTTP 404 not found error.
func StripPrefix(prefix string, h Handler) Handler {
  if prefix == "" {
    return h
  }
  return HandlerFunc(func(w ResponseWriter, r *Request) {
    if p := strings.TrimPrefix(r.URL.Path, prefix); len(p) < len(r.URL.Path) {
      r.URL.Path = p
      h.ServeSPDY(w, r)
    } else {
      NotFound(w, r)
    }
  })
}

// Redirect replies to the request with a redirect to url,
// which may be a path relative to the request path.
func Redirect(w ResponseWriter, r *Request, urlStr string, code int) {
  if u, err := url.Parse(urlStr); err == nil {
    // If url was relative, make absolute by
    // combining with request path.
    // The browser would probably do this for us,
    // but doing it ourselves is more reliable.

    // NOTE(rsc): RFC 2616 says that the Location
    // line must be an absolute URI, like
    // "http://www.google.com/redirect/",
    // not a path like "/redirect/".
    // Unfortunately, we don't know what to
    // put in the host name section to get the
    // client to connect to us again, so we can't
    // know the right absolute URI to send back.
    // Because of this problem, no one pays attention
    // to the RFC; they all send back just a new path.
    // So do we.
    oldpath := r.URL.Path
    if oldpath == "" { // should not happen, but avoid a crash if it does
      oldpath = "/"
    }
    if u.Scheme == "" {
      // no leading http://server
      if urlStr == "" || urlStr[0] != '/' {
        // make relative path absolute
        olddir, _ := path.Split(oldpath)
        urlStr = olddir + urlStr
      }

      var query string
      if i := strings.Index(urlStr, "?"); i != -1 {
        urlStr, query = urlStr[:i], urlStr[i:]
      }

      // clean up but preserve trailing slash
      trailing := strings.HasSuffix(urlStr, "/")
      urlStr = path.Clean(urlStr)
      if trailing && !strings.HasSuffix(urlStr, "/") {
        urlStr += "/"
      }
      urlStr += query
    }
  }

  w.Header().Set("Location", urlStr)
  w.WriteHeader(code)

  // RFC2616 recommends that a short note "SHOULD" be included in the
  // response because older user agents may not understand 301/307.
  // Shouldn't send the response for POST or HEAD; that leaves GET.
  if r.Method == "GET" {
    note := "<a href=\"" + htmlEscape(urlStr) + "\">" + http.StatusText(code) + "</a>.\n"
    fmt.Fprintln(w, note)
  }
}

var htmlReplacer = strings.NewReplacer(
  "&", "&amp;",
  "<", "&lt;",
  ">", "&gt;",
  // "&#34;" is shorter than "&quot;".
  `"`, "&#34;",
  // "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
  "'", "&#39;",
)

func htmlEscape(s string) string {
  return htmlReplacer.Replace(s)
}

// Redirect to a fixed URL.
type redirectHandler struct {
  url  string
  code int
}

func (rh *redirectHandler) ServeSPDY(w ResponseWriter, r *Request) {
  Redirect(w, r, rh.url, rh.code)
}

// RedirectHandler returns a request handler that redirects each
// request it receives to the given URL, using the given status
// code.
func RedirectHandler(url string, code int) Handler {
  return &redirectHandler{url, code}
}

// ServeMux is a SPDY request multiplexer. It matches the URL of each
// incoming request against a list of registered patterns and calls
// the handler for the pattern that most closely matches the URL.
//
// Patterns name fixed, rooted paths, like "/favicon.ico", or rooted
// subtrees, like "/images/" (note the trailing slash). Longer patterns
// take precedence over shorter ones, so that if there are handlers
// registered for both "/images/" and "/images/thumbnails/", the latter
// handler will be called for paths beginning "/images/thumbnails/" and
// the former will receive requests for any other paths in the
// "/images/" subtree.
//
// Patterns may optionally begin with a host name, restricting matches
// to URLs on that host only. Host-specific paterns take precedence
// over general patterns, so that a handler might register for the two
// patterns "/codesearch" and "codesearch.google.com/" without also
// taking over requests for "https://www.google.com".
//
// ServeMux also takes care of sanitising the URL request path,
// redirecting any request containing . or .. elements to an
// equivalent .- and ..-free URL.
type ServeMux struct {
  sync.RWMutex
  m     map[string]muxEntry
  hosts bool // whether any patterns contain hostnames.
}

type muxEntry struct {
  explicit bool
  h        Handler
  pattern  string
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
  return &ServeMux{m: make(map[string]muxEntry)}
}

// DefaultServeMux is the default ServeMux used by Serve and ServeFunc.
var DefaultServeMux = NewServeMux()

// Does path match pattern?
func pathMatch(pattern, path string) bool {
  n := len(pattern)
  if n == 0 {
    // Should not happen.
    return false
  }
  if pattern[n-1] != '/' {
    return pattern == path
  }
  return len(path) >= n && path[:n] == pattern
}

// Return the canonical path for p, eliminating . and .. elements.
func cleanPath(p string) string {
  if p == "" {
    return "/"
  }
  if p[0] != '/' {
    p = "/" + p
  }
  np := path.Clean(p)
  // path.Clean removes trailing slash except for root;
  // put the trailing slash back if necessary.
  if p[len(p)-1] == '/' && np != "/" {
    np += "/"
  }
  return np
}

// Find a handler on a handler map given a path string.
// The most-specific (longest) pattern wins.
func (mux *ServeMux) match(path string) (h Handler, pattern string) {
  var n = 0
  for k, v := range mux.m {
    if !pathMatch(k, path) {
      continue
    }
    if h == nil || len(k) > n {
      n = len(k)
      h = v.h
      pattern = v.pattern
    }
  }
  return
}

// Handler returns the handler to use for the given request,
// consulting r.Method, r.Host, and r.URL.Path. It always
// returns a non-nil handler. If the path is not in its
// canonical form, the handler will be an internally-
// generated handler that redirects to the canonical path.
//
// Handler also returns the registered pattern that matches
// the request or, in the case of internally-generated
// redirects, the pattern that will match after following
// the redirect.
//
// If there is no registered handler that applies to the
// request, Handler returns a ''page not found'' handler
// and an empty pattern.
func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string) {
  if r.Method != "CONNECT" {
    if p := cleanPath(r.URL.Path); p != r.URL.Path {
      _, pattern = mux.handler(r.Host, p)
      return RedirectHandler(p, http.StatusMovedPermanently), pattern
    }
  }

  return mux.handler(r.Host, r.URL.Path)
}

// handler is the main implementation of Handler.
// The path is known to be in canonical form, except for
// CONNECT methods.
func (mux *ServeMux) handler(host, path string) (h Handler, pattern string) {
  mux.RLock()
  defer mux.RUnlock()

  // Host-specific pattern takes precedence over generic ones.
  if mux.hosts {
    h, pattern = mux.match(host + path)
  }
  if h == nil {
    h, pattern = mux.match(path)
  }
  if h == nil {
    h, pattern = NotFoundHandler(), ""
  }
  return
}

// ServeSPDY dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (mux *ServeMux) ServeSPDY(w ResponseWriter, r *Request) {
  if r.RequestURI == "*" {
    w.Header().Set("Connection", "close")
    w.WriteHeader(http.StatusBadRequest)
    return
  }
  h, _ := mux.Handler(r)
  h.ServeSPDY(w, r)
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
  mux.Lock()
  defer mux.Unlock()

  if pattern == "" {
    panic("spdy: invalid pattern " + pattern)
  }
  if handler == nil {
    panic("spdy: nil handler")
  }
  if mux.m[pattern].explicit {
    panic("spdy: multiple registrations for " + pattern)
  }

  mux.m[pattern] = muxEntry{
    explicit: true,
    h:        handler,
    pattern:  pattern,
  }

  if pattern[0] != '/' {
    mux.hosts = true
  }

  // Helpful behaviour:
  // If attern is /tree/, insert an implicit permanent redirect
  // for /tree. It can be overriden by an explicit registration.
  n := len(pattern)
  if n > 0 && pattern[n-1] == '/' && !mux.m[pattern[:n-1]].explicit {
    // If pattern contains a host name, strip it and use remaining
    // path for redirect.
    path := pattern
    if pattern[0] != '/' {
      // In pattern, at least the last character is a '/', so
      // strings.Index can't be -1.
      path = pattern[strings.Index(pattern, "/"):]
    }
    mux.m[pattern[:n-1]] = muxEntry{
      h:       RedirectHandler(path, http.StatusMovedPermanently),
      pattern: pattern,
    }
  }
}

// HandleFunc registers the handler function for the given pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
  mux.Handle(pattern, HandlerFunc(handler))
}

func Handle(pattern string, handler Handler) {
  DefaultServeMux.Handle(pattern, handler)
}

func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
  DefaultServeMux.HandleFunc(pattern, handler)
}

func ListenAndServeTLS(addr string, certFile string, keyFile string) error {
  server := &http.Server{
    Addr: addr,
    TLSConfig: &tls.Config{
      NextProtos: []string{
        "spdy/3",
        //"spdy/2",
      },
    },
    TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
      //"spdy/2": acceptSPDYVersion2,
      "spdy/3": acceptSPDYVersion3,
    },
  }

  return server.ListenAndServeTLS(certFile, keyFile)
}

// Errors introduced by the HTTP server.
var (
  ErrWriteAfterFlush = errors.New("Conn.Write called after Flush")
  ErrBodyNotAllowed  = errors.New("spdy: request method or response status code does not allow body")
  ErrHijacked        = errors.New("Conn has been hijacked")
  ErrContentLength   = errors.New("Conn.Write wrote more than the declared Content-Length")
  ErrCancelled       = errors.New("spdy: Stream has been cancelled.")
)
