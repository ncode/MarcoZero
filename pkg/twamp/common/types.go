package common

import (
	"errors"
	"fmt"
	"time"
)

// TWAMP protocol constants
const (
	// Mode values
	ModeUnauthenticated = 1
	ModeAuthenticated   = 2
	ModeEncrypted       = 4

	// Accept values from RFC 4656 Section 3.3
	AcceptOK                  = 0
	AcceptFailure             = 1
	AcceptInternalError       = 2
	AcceptNotSupported        = 3
	AcceptPermanentResLimited = 4
	AcceptTempResLimited      = 5

	// Command numbers
	CmdRequestTWSession = 5
	CmdStartSessions    = 2
	CmdStopSessions     = 3

	// Default timeouts
	DefaultSERVWAIT = 900 * time.Second
	DefaultREFWAIT  = 900 * time.Second
	DefaultTimeout  = 3 * time.Second
)

// AcceptCodeToString converts an Accept code to a human-readable string
func AcceptCodeToString(code uint8) string {
	switch code {
	case AcceptOK:
		return "OK"
	case AcceptFailure:
		return "Failure, reason unspecified"
	case AcceptInternalError:
		return "Internal error"
	case AcceptNotSupported:
		return "Some aspect of request is not supported"
	case AcceptPermanentResLimited:
		return "Cannot perform request due to permanent resource limitations"
	case AcceptTempResLimited:
		return "Cannot perform request due to temporary resource limitations"
	default:
		return fmt.Sprintf("Unknown accept code: %d", code)
	}
}

// ErrInvalidMessageLength is returned when a message is too short
var ErrInvalidMessageLength = errors.New("invalid message length")

// Mode represents TWAMP test modes
type Mode uint32

// ModeToString function to convert mode to string
func ModeToString(mode Mode) string {
	switch mode {
	case ModeUnauthenticated:
		return "unauthenticated"
	case ModeAuthenticated:
		return "authenticated"
	case ModeEncrypted:
		return "encrypted"
	default:
		return "unknown"
	}
}

// ErrorEstimate represents the TWAMP error estimate field
type ErrorEstimate struct {
	Multiplier uint8
	Scale      uint8
	S          bool // Sync bit
}

// ToUint16 converts ErrorEstimate to its uint16 wire representation
func (ee ErrorEstimate) ToUint16() uint16 {
	val := uint16(ee.Multiplier)
	val |= uint16(ee.Scale) << 8
	if ee.S {
		val |= 1 << 15 // Set the S bit (high bit of first byte)
	}
	return val
}

// FromUint16 parses a uint16 into an ErrorEstimate
func (ee *ErrorEstimate) FromUint16(val uint16) {
	ee.S = (val & 0x8000) != 0        // Extract S bit
	ee.Scale = uint8(val>>8) & 0x3F   // Extract Scale (6 bits)
	ee.Multiplier = uint8(val & 0xFF) // Extract Multiplier
}

// SessionID represents a TWAMP session identifier (16 octets)
type SessionID [16]byte

// TWAMPError represents an error in the TWAMP protocol
type TWAMPError struct {
	AcceptCode uint8
	Message    string
}

// Error implements the error interface
func (e *TWAMPError) Error() string {
	return fmt.Sprintf("TWAMP error (%s): %s",
		AcceptCodeToString(e.AcceptCode),
		e.Message)
}

// NewTWAMPError creates a new TWAMP error
func NewTWAMPError(code uint8, msg string) *TWAMPError {
	return &TWAMPError{
		AcceptCode: code,
		Message:    msg,
	}
}
