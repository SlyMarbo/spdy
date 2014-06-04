package common

import (
	"io"
	"io/ioutil"
	logging "log"
	"os"
)

var log = logging.New(os.Stderr, "(spdy) ", logging.LstdFlags|logging.Lshortfile)
var debug = logging.New(ioutil.Discard, "(spdy debug) ", logging.LstdFlags)
var VerboseLogging = false

func GetLogger() *logging.Logger {
	return log
}

func GetDebugLogger() *logging.Logger {
	return debug
}

// SetLogger sets the package's error logger.
func SetLogger(l *logging.Logger) {
	log = l
}

// SetLogOutput sets the output for the package's error logger.
func SetLogOutput(w io.Writer) {
	log = logging.New(w, "(spdy) ", logging.LstdFlags|logging.Lshortfile)
}

// SetDebugLogger sets the package's debug info logger.
func SetDebugLogger(l *logging.Logger) {
	debug = l
}

// SetDebugOutput sets the output for the package's debug info logger.
func SetDebugOutput(w io.Writer) {
	debug = logging.New(w, "(spdy debug) ", logging.LstdFlags)
}

// EnableDebugOutput sets the output for the package's debug info logger to os.Stdout.
func EnableDebugOutput() {
	SetDebugOutput(os.Stdout)
}
