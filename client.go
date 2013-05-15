package spdy

import (
	"crypto/tls"
	"time"
)

type Client struct {
	ReadTimeout    time.Duration // maximum duration before timing out read of the request
	WriteTimeout   time.Duration // maximum duration before timing out write of the response
	TLSConfig      *tls.Config   // optional TLS config, used by ListenAndServeTLS
	GlobalSettings []*Setting    // SPDY settings to be sent to all clients automatically.
}
