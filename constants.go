package spdy

const SPDY_VERSION = 3

// Control types
const (
  CONTROL_FRAME = -1
  DATA_FRAME    = -2
)

// Frame types
const (
  SYN_STREAM    = 1
  SYN_REPLY     = 2
  RST_STREAM    = 3
  SETTINGS      = 4
  PING          = 6
  GOAWAY        = 7
  HEADERS       = 8
  WINDOW_UPDATE = 9
  CREDENTIAL    = 10
)

// Flags
const (
  FLAG_FIN                     = 1
  FLAG_UNIDIRECTIONAL          = 2
  FLAG_SETTINGS_CLEAR_SETTINGS = 1
  FLAG_SETTINGS_PERSIST_VALUE  = 1
  FLAG_SETTINGS_PERSISTED      = 2
)

// RST_STREAM status codes
const (
  RST_STREAM_PROTOCOL_ERROR        = 1
  RST_STREAM_INVALID_STREAM        = 2
  RST_STREAM_REFUSED_STREAM        = 3
  RST_STREAM_UNSUPPORTED_VERSION   = 4
  RST_STREAM_CANCEL                = 5
  RST_STREAM_INTERNAL_ERROR        = 6
  RST_STREAM_FLOW_CONTROL_ERROR    = 7
  RST_STREAM_STREAM_IN_USE         = 8
  RST_STREAM_STREAM_ALREADY_CLOSED = 9
  RST_STREAM_INVALID_CREDENTIALS   = 10
  RST_STREAM_FRAME_TOO_LARGE       = 11
)

// Settings IDs
const (
  SETTINGS_UPLOAD_BANDWIDTH               = 1
  SETTINGS_DOWNLOAD_BANDWIDTH             = 2
  SETTINGS_ROUND_TRIP_TIME                = 3
  SETTINGS_MAX_CONCURRENT_STREAMS         = 4
  SETTINGS_CURRENT_CWND                   = 5
  SETTINGS_DOWNLOAD_RETRANS_RATE          = 6
  SETTINGS_INITIAL_WINDOW_SIZE            = 7
  SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE = 8
)

// Stream state
type StreamState uint8
const (
  STATE_CLOSED StreamState = iota
  STATE_HALF_CLOSED_HERE
  STATE_HALF_CLOSED_THERE
  STATE_OPEN
)

// Stream priority values.
const (
	MAX_PRIORITY = 0
	MIN_PRIORITY = 7
)

// HTTP time format.
const TimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

// Maximum frame size (2 ** 24 -1).
const MAX_FRAME_SIZE = 0xffffff

// Maximum stream ID (2 ** 31 -1).
const MAX_STREAM_ID = 0x7fffffff
