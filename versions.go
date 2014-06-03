package spdy

import (
	"errors"
	"sort"
)

// Version factors.
var supportedVersions = map[float64]struct{}{
	2:   struct{}{},
	3:   struct{}{},
	3.1: struct{}{},
}

const minVersion = 2
const maxVersion = 3.1

// SupportedVersions will return a slice of supported SPDY versions.
// The returned versions are sorted into order of most recent first.
func SupportedVersions() []float64 {
	s := make([]float64, 0, len(supportedVersions))
	for v, _ := range supportedVersions {
		s = append(s, v)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(s)))
	return s
}

var npnStrings = map[float64]string{
	2:   "spdy/2",
	3:   "spdy/3",
	3.1: "spdy/3.1",
}

// npn returns the NPN version strings for the SPDY versions
// currently enabled, plus HTTP/1.1.
func npn() []string {
	v := SupportedVersions()
	s := make([]string, 0, len(v)+1)
	for _, v := range v {
		if str := npnStrings[float64(v)]; str != "" {
			s = append(s, str)
		}
	}
	s = append(s, "http/1.1")
	return s
}

// SupportedVersion determines if the provided SPDY version is
// supported by this instance of the library. This can be modified
// with EnableSpdyVersion and DisableSpdyVersion.
func SupportedVersion(v float64) bool {
	_, s := supportedVersions[v]
	return s
}

// EnableSpdyVersion can re-enable support for versions of SPDY
// that have been disabled by DisableSpdyVersion.
func EnableSpdyVersion(v float64) error {
	if v == 0 {
		return errors.New("Error: version 0 is invalid.")
	}
	if v < minVersion {
		return errors.New("Error: SPDY version too old.")
	}
	if v > maxVersion {
		return errors.New("Error: SPDY version too new.")
	}
	supportedVersions[v] = struct{}{}
	return nil
}

// DisableSpdyVersion can be used to disable support for the
// given SPDY version. This process can be undone by using
// EnableSpdyVersion.
func DisableSpdyVersion(v float64) error {
	if v == 0 {
		return errors.New("Error: version 0 is invalid.")
	}
	if v < minVersion {
		return errors.New("Error: SPDY version too old.")
	}
	if v > maxVersion {
		return errors.New("Error: SPDY version too new.")
	}
	delete(supportedVersions, v)
	return nil
}

// defaultSPDYServerSettings are used in initialising the connection.
// It takes the SPDY version and max concurrent streams.
func defaultSPDYServerSettings(v float64, m uint32) Settings {
	switch v {
	case 3:
		return Settings{
			SETTINGS_INITIAL_WINDOW_SIZE: &Setting{
				Flags: FLAG_SETTINGS_PERSIST_VALUE,
				ID:    SETTINGS_INITIAL_WINDOW_SIZE,
				Value: DEFAULT_INITIAL_WINDOW_SIZE,
			},
			SETTINGS_MAX_CONCURRENT_STREAMS: &Setting{
				Flags: FLAG_SETTINGS_PERSIST_VALUE,
				ID:    SETTINGS_MAX_CONCURRENT_STREAMS,
				Value: m,
			},
		}
	case 2:
		return Settings{
			SETTINGS_MAX_CONCURRENT_STREAMS: &Setting{
				Flags: FLAG_SETTINGS_PERSIST_VALUE,
				ID:    SETTINGS_MAX_CONCURRENT_STREAMS,
				Value: m,
			},
		}
	}
	return nil
}

// defaultSPDYClientSettings are used in initialising the connection.
// It takes the SPDY version and max concurrent streams.
func defaultSPDYClientSettings(v float64, m uint32) Settings {
	switch v {
	case 3:
		return Settings{
			SETTINGS_INITIAL_WINDOW_SIZE: &Setting{
				ID:    SETTINGS_INITIAL_WINDOW_SIZE,
				Value: DEFAULT_INITIAL_CLIENT_WINDOW_SIZE,
			},
			SETTINGS_MAX_CONCURRENT_STREAMS: &Setting{
				ID:    SETTINGS_MAX_CONCURRENT_STREAMS,
				Value: m,
			},
		}
	case 2:
		return Settings{
			SETTINGS_MAX_CONCURRENT_STREAMS: &Setting{
				ID:    SETTINGS_MAX_CONCURRENT_STREAMS,
				Value: m,
			},
		}
	}
	return nil
}

// frameNamesV4 provides the name for a particular SPDY/3
// / HTTP/2.0 frame type.
var frameNamesV4 = map[int]string{
	DATAv4:             "DATA",
	HEADERS_PRIORITYv4: "HEADERS+PRIORITY",
	RST_STREAMv4:       "RST_STREAM",
	SETTINGSv4:         "SETTINGS",
	PUSH_PROMISEv4:     "PUSH_PROMISE",
	PINGv4:             "PING",
	GOAWAYv4:           "GOAWAY",
	HEADERSv4:          "HEADERS",
	WINDOW_UPDATEv4:    "WINDOW_UPDATE",
	CREDENTIALv4:       "CREDENTIAL",
}

// frameNamesV3 provides the name for a particular SPDY/3
// frame type.
var frameNamesV3 = map[int]string{
	SYN_STREAMv3:    "SYN_STREAM",
	SYN_REPLYv3:     "SYN_REPLY",
	RST_STREAMv3:    "RST_STREAM",
	SETTINGSv3:      "SETTINGS",
	PINGv3:          "PING",
	GOAWAYv3:        "GOAWAY",
	HEADERSv3:       "HEADERS",
	WINDOW_UPDATEv3: "WINDOW_UPDATE",
	CREDENTIALv3:    "CREDENTIAL",
	CONTROL_FRAMEv3: "CONTROL_FRAME",
	DATA_FRAMEv3:    "DATA_FRAME",
}

// frameNamesV2 provides the name for a particular SPDY/2
// frame type.
var frameNamesV2 = map[int]string{
	SYN_STREAMv2:    "SYN_STREAM",
	SYN_REPLYv2:     "SYN_REPLY",
	RST_STREAMv2:    "RST_STREAM",
	SETTINGSv2:      "SETTINGS",
	NOOPv2:          "NOOP",
	PINGv2:          "PING",
	GOAWAYv2:        "GOAWAY",
	HEADERSv2:       "HEADERS",
	WINDOW_UPDATEv2: "WINDOW_UPDATE",
	CONTROL_FRAMEv2: "CONTROL_FRAME",
	DATA_FRAMEv2:    "DATA_FRAME",
}
