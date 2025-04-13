// pkg/twamp/common/timestamp.go
package common

import (
	"encoding/binary"
	"time"
)

// NTP constants
const (
	// NTPEpochOffset NTP epoch starts on Jan 1, 1900, while Unix time starts on Jan 1, 1970
	// This is the offset in seconds between the two epochs
	NTPEpochOffset = 2208988800

	// NanoToFrac is the multiplier to convert nanoseconds to NTP fractional part
	// 2^32 / 10^9
	NanoToFrac = float64(1<<32) / 1e9

	// FracToNano is the multiplier to convert NTP fractional part to nanoseconds
	// 10^9 / 2^32
	FracToNano = 1e9 / float64(1<<32)
)

// TWAMPTimestamp represents the 64-bit NTP-style timestamp used in TWAMP
type TWAMPTimestamp struct {
	Seconds  uint32 // Seconds since NTP epoch (January 1, 1900)
	Fraction uint32 // Fractional part of second (1/2^32 seconds)
}

// FromTime creates a TWAMPTimestamp from a Go time.Time
// with precise handling of nanoseconds
func FromTime(t time.Time) TWAMPTimestamp {
	// Get the Unix time and convert to NTP epoch
	secs := uint32(t.Unix() + NTPEpochOffset)

	// Convert nanoseconds to NTP fraction with high precision
	// We multiply by 2^32 then divide by 10^9 to get the correct scale
	nanos := t.Nanosecond()
	frac := uint32(float64(nanos) * NanoToFrac)

	return TWAMPTimestamp{
		Seconds:  secs,
		Fraction: frac,
	}
}

// ToTime converts a TWAMPTimestamp to a Go time.Time
// with precise handling of fractional parts
func (ts TWAMPTimestamp) ToTime() time.Time {
	// Convert from NTP epoch to Unix epoch
	secs := int64(ts.Seconds) - NTPEpochOffset

	// Convert fractional part to nanoseconds
	// We multiply by 10^9 then divide by 2^32 to get nanoseconds
	nanos := int64(float64(ts.Fraction) * FracToNano)

	return time.Unix(secs, nanos)
}

// Marshal converts a TWAMPTimestamp to network bytes
func (ts TWAMPTimestamp) Marshal(b []byte) {
	binary.BigEndian.PutUint32(b[0:], ts.Seconds)
	binary.BigEndian.PutUint32(b[4:], ts.Fraction)
}

// Unmarshal parses network bytes into a TWAMPTimestamp
func (ts *TWAMPTimestamp) Unmarshal(b []byte) {
	ts.Seconds = binary.BigEndian.Uint32(b[0:])
	ts.Fraction = binary.BigEndian.Uint32(b[4:])
}

// Now returns the current time as a TWAMPTimestamp
func Now() TWAMPTimestamp {
	return FromTime(time.Now())
}

// MonotonicNow returns the current time from monotonic clock as a TWAMPTimestamp
// This is crucial for accurate RTT measurements that avoid issues with system time jumps
func MonotonicNow() (TWAMPTimestamp, time.Time) {
	// In Go, time.Now() includes a monotonic clock reading
	// When doing t2.Sub(t1), Go uses the monotonic reading if both have it
	now := time.Now()
	return FromTime(now), now
}

// DurationBetween calculates the duration between two TWAMPTimestamps
func DurationBetween(start, end TWAMPTimestamp) time.Duration {
	// Calculate seconds difference
	secDiff := int64(end.Seconds) - int64(start.Seconds)

	// Calculate fraction difference, handling underflow
	var fracDiff int64
	if end.Fraction >= start.Fraction {
		fracDiff = int64(end.Fraction) - int64(start.Fraction)
	} else {
		fracDiff = int64(end.Fraction) + (1 << 32) - int64(start.Fraction)
		secDiff-- // Borrow one second
	}

	// Convert the fraction difference to nanoseconds
	nanoDiff := int64(float64(fracDiff) * FracToNano)

	// Combine seconds and nanoseconds to get the total duration
	return time.Duration(secDiff)*time.Second + time.Duration(nanoDiff)*time.Nanosecond
}

// Add adds a duration to a TWAMPTimestamp
func (ts TWAMPTimestamp) Add(d time.Duration) TWAMPTimestamp {
	// Convert duration to seconds and nanoseconds
	secs := d / time.Second
	nanos := d % time.Second

	// Convert nanoseconds to NTP fraction
	fracToAdd := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)

	// Add fraction parts
	// Use uint64 to avoid overflow in intermediate calculation
	newFracU64 := uint64(ts.Fraction) + uint64(fracToAdd)

	// Handle overflow in fraction
	carry := uint32(0)
	if newFracU64 >= (1 << 32) {
		carry = 1
		newFracU64 -= 1 << 32
	}

	// Convert back to uint32 after handling overflow
	newFrac := uint32(newFracU64)

	// Add seconds and any carry from fraction
	newSecs := ts.Seconds + uint32(secs) + carry

	return TWAMPTimestamp{
		Seconds:  newSecs,
		Fraction: newFrac,
	}
}

// Sub subtracts a duration from a TWAMPTimestamp
func (ts TWAMPTimestamp) Sub(d time.Duration) TWAMPTimestamp {
	// Convert duration to seconds and nanoseconds
	secs := d / time.Second
	nanos := d % time.Second

	// Convert nanoseconds to NTP fraction
	fracToSub := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)

	// Subtract fraction parts, handling underflow
	borrow := uint32(0)
	var newFrac uint32

	if fracToSub > ts.Fraction {
		// Handle underflow correctly
		borrow = 1
		// Use uint64 for intermediate calculation to avoid overflow
		newFrac = uint32(uint64(ts.Fraction) + (1 << 32) - uint64(fracToSub))
	} else {
		newFrac = ts.Fraction - fracToSub
	}

	// Subtract seconds and any borrow from fraction
	newSecs := ts.Seconds - uint32(secs) - borrow

	return TWAMPTimestamp{
		Seconds:  newSecs,
		Fraction: newFrac,
	}
}

// Equal checks if two TWAMPTimestamps are equal
func (ts TWAMPTimestamp) Equal(other TWAMPTimestamp) bool {
	return ts.Seconds == other.Seconds && ts.Fraction == other.Fraction
}

// Before checks if this timestamp is before another
func (ts TWAMPTimestamp) Before(other TWAMPTimestamp) bool {
	if ts.Seconds < other.Seconds {
		return true
	}
	if ts.Seconds > other.Seconds {
		return false
	}
	return ts.Fraction < other.Fraction
}

// After checks if this timestamp is after another
func (ts TWAMPTimestamp) After(other TWAMPTimestamp) bool {
	if ts.Seconds > other.Seconds {
		return true
	}
	if ts.Seconds < other.Seconds {
		return false
	}
	return ts.Fraction > other.Fraction
}
