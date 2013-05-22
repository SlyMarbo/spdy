package spdy

import (
	"net/http"
)

// SetCookie adds a Set-Cookie header to the provided ResponseWriter's headers.
func SetCookie(w ResponseWriter, cookie *http.Cookie) {
	w.Header().Add("Set-Cookie", cookie.String())
}
