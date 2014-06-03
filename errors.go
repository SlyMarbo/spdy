package spdy

import (
	"errors"
	"fmt"
)

// MaxBenignErrors is the maximum number of minor errors each
// connection will allow without ending the session.
//
// By default, MaxBenignErrors is set to 0, disabling checks
// and allowing minor errors to go unchecked, although they
// will still be reported to the debug logger. If it is
// important that no errors go unchecked, such as when testing
// another implementation, set MaxBenignErrors to 1 or higher.
var MaxBenignErrors = 0

var (
	ErrGoaway         = errors.New("Error: GOAWAY received.")
	ErrConnNil        = errors.New("Error: Connection is nil.")
	ErrNoFlowControl  = errors.New("Error: This connection does not use flow control.")
	ErrConnectFail    = errors.New("Error: Failed to connect.")
	ErrInvalidVersion = errors.New("Error: Invalid SPDY version.")
)

type incorrectFrame struct {
	got, expected, version int
}

func (i *incorrectFrame) Error() string {
	if i.version == 3 {
		return fmt.Sprintf("Error: Frame %s tried to parse data for a %s.", frameNamesV3[i.expected], frameNamesV3[i.got])
	}
	return fmt.Sprintf("Error: Frame %s tried to parse data for a %s.", frameNamesV2[i.expected], frameNamesV2[i.got])
}

type unsupportedVersion uint16

func (u unsupportedVersion) Error() string {
	return fmt.Sprintf("Error: Unsupported SPDY version: %d.\n", u)
}

type incorrectDataLength struct {
	got, expected int
}

func (i *incorrectDataLength) Error() string {
	return fmt.Sprintf("Error: Incorrect amount of data for frame: got %d bytes, expected %d.", i.got, i.expected)
}

var frameTooLarge = errors.New("Error: Frame too large.")

type invalidField struct {
	field         string
	got, expected int
}

func (i *invalidField) Error() string {
	return fmt.Sprintf("Error: Field %q recieved invalid data %d, expecting %d.", i.field, i.got, i.expected)
}

var streamIdTooLarge = errors.New("Error: Stream ID is too large.")

var streamIdIsZero = errors.New("Error: Stream ID is zero.")
