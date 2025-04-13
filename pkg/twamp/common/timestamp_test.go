// pkg/twamp/common/timestamp_test.go
package common

import (
	"math"
	"testing"
	"time"
)

func TestTimestampConversion(t *testing.T) {
	// Test conversion to and from NTP timestamp
	now := time.Now()
	ts := FromTime(now)
	converted := ts.ToTime()

	// Since we convert through different representations,
	// we may lose some sub-nanosecond precision.
	// Allow a small tolerance of 1 microsecond
	tolerance := time.Microsecond

	diff := now.Sub(converted)
	if diff < -tolerance || diff > tolerance {
		t.Errorf("Time conversion error too large: %v", diff)
	}
}

func TestTimestampMath(t *testing.T) {
	// Test addition and subtraction
	baseTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	ts := FromTime(baseTime)

	// Add 1 second
	added := ts.Add(time.Second)
	expected := FromTime(baseTime.Add(time.Second))

	if !added.Equal(expected) {
		t.Errorf("Timestamp addition error: got %v, expected %v", added, expected)
	}

	// Subtract 1 second
	subtracted := ts.Sub(time.Second)
	expected = FromTime(baseTime.Add(-time.Second))

	if !subtracted.Equal(expected) {
		t.Errorf("Timestamp subtraction error: got %v, expected %v", subtracted, expected)
	}

	// Test spanning second boundaries
	ts = TWAMPTimestamp{Seconds: 1000, Fraction: 0x80000000} // Half second

	// Add 0.75 seconds (crosses second boundary)
	added = ts.Add(750 * time.Millisecond)
	if added.Seconds != 1001 || added.Fraction != 0x40000000 {
		t.Errorf("Timestamp addition across boundary failed: got %v, expected {1001, 0x40000000}", added)
	}

	// Subtract 0.75 seconds (crosses second boundary)
	subtracted = ts.Sub(750 * time.Millisecond)
	if subtracted.Seconds != 999 || subtracted.Fraction != 0xC0000000 {
		t.Errorf("Timestamp subtraction across boundary failed: got %v, expected {999, 0xC0000000}", subtracted)
	}
}

func TestDurationBetween(t *testing.T) {
	// Test duration calculation
	start := TWAMPTimestamp{Seconds: 1000, Fraction: 0x40000000} // Quarter second
	end := TWAMPTimestamp{Seconds: 1002, Fraction: 0x80000000}   // Half second

	// Expected: 2.25 seconds
	expected := 2*time.Second + 250*time.Millisecond

	duration := DurationBetween(start, end)

	// Allow a small tolerance due to floating point conversion
	tolerance := time.Microsecond

	if duration < expected-tolerance || duration > expected+tolerance {
		t.Errorf("Duration calculation error: got %v, expected %v", duration, expected)
	}

	// Test with fraction underflow
	start = TWAMPTimestamp{Seconds: 1000, Fraction: 0x80000000} // Half second
	end = TWAMPTimestamp{Seconds: 1001, Fraction: 0x40000000}   // Quarter second

	// Expected: 0.75 seconds
	expected = 750 * time.Millisecond

	duration = DurationBetween(start, end)

	if duration < expected-tolerance || duration > expected+tolerance {
		t.Errorf("Duration calculation with underflow error: got %v, expected %v", duration, expected)
	}
}

func TestNTPEpoch(t *testing.T) {
	// Test NTP epoch handling
	// January 1, 1900, 00:00:00 UTC is the NTP epoch
	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := FromTime(ntpEpoch)

	if ts.Seconds != 0 || ts.Fraction != 0 {
		t.Errorf("NTP epoch conversion error: got %v, expected {0, 0}", ts)
	}

	// January 1, 1970, 00:00:00 UTC is the Unix epoch
	unixEpoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	ts = FromTime(unixEpoch)

	if ts.Seconds != NTPEpochOffset || ts.Fraction != 0 {
		t.Errorf("Unix epoch conversion error: got %v, expected {%d, 0}", ts, NTPEpochOffset)
	}
}

func TestHighPrecision(t *testing.T) {
	// Test case with nanosecond precision
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 123456789, time.UTC)
	ts := FromTime(originalTime)
	recoveredTime := ts.ToTime()

	// Allow a small margin of error due to floating point conversions
	// The error should be less than 1 nanosecond
	tolerance := time.Nanosecond

	diff := originalTime.Sub(recoveredTime)
	if diff < -tolerance || diff > tolerance {
		t.Errorf("High precision time conversion error: %v", diff)
	}

	// Test the limits of precision with very small values
	oneNano := time.Date(2023, 1, 1, 0, 0, 0, 1, time.UTC)
	ts = FromTime(oneNano)

	// The NTP fraction for 1ns should be approximately 2^32 / 10^9
	expectedFraction := uint32(math.Round(float64(1) * NanoToFrac))
	if math.Abs(float64(ts.Fraction)-float64(expectedFraction)) > 1.0 {
		t.Errorf("1ns precision error: got fraction %d, expected ~%d",
			ts.Fraction, expectedFraction)
	}
}
