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

// helper to compare two timestamps exactly in tests
func equalTS(a, b TWAMPTimestamp) bool {
	return a.Seconds == b.Seconds && a.Fraction == b.Fraction
}

// TestAddOverflowCarry verifies that Add() correctly carries when the fractional
// sum exceeds 2^32 – i.e. one full second.
func TestAddOverflowCarry(t *testing.T) {
	start := TWAMPTimestamp{Seconds: 123, Fraction: (1 << 32) - 16} // 0xfffffff0
	dur := 50 * time.Nanosecond                                     // gives ~214 frac units

	got := start.Add(dur)

	// Manually compute the expected result using the same rules as Add().
	secs := start.Seconds
	nanos := dur % time.Second
	fracToAdd := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)
	newFracU64 := uint64(start.Fraction) + uint64(fracToAdd)
	carry := uint32(0)
	if newFracU64 >= (1 << 32) {
		carry = 1
		newFracU64 -= 1 << 32
	}
	want := TWAMPTimestamp{Seconds: secs + carry, Fraction: uint32(newFracU64)}

	if !equalTS(got, want) {
		t.Fatalf("Add overflow: want %+v, got %+v", want, got)
	}
}

// TestSubUnderflowBorrow verifies that Sub() borrows correctly when the
// fractional part underflows.
func TestSubUnderflowBorrow(t *testing.T) {
	start := TWAMPTimestamp{Seconds: 123, Fraction: 10}
	dur := time.Microsecond // ~4 294 frac units

	got := start.Sub(dur)

	// Expected – borrow one full second
	nanos := dur % time.Second
	fracToSub := uint32(float64(nanos.Nanoseconds()) * NanoToFrac)
	var newFrac uint32
	borrow := uint32(0)
	if fracToSub > start.Fraction {
		borrow = 1
		newFrac = uint32(uint64(start.Fraction) + (1 << 32) - uint64(fracToSub))
	} else {
		newFrac = start.Fraction - fracToSub
	}
	want := TWAMPTimestamp{Seconds: start.Seconds - borrow, Fraction: newFrac}

	if !equalTS(got, want) {
		t.Fatalf("Sub underflow: want %+v, got %+v", want, got)
	}
}

// TestDurationBetween covers both the regular case and the underflow branch.
func TestDurationBetween(t *testing.T) {
	start := TWAMPTimestamp{Seconds: 100, Fraction: (1 << 32) - 100}
	end := TWAMPTimestamp{Seconds: 101, Fraction: 50}

	got := DurationBetween(start, end)
	want := end.ToTime().Sub(start.ToTime())

	// Accept ±1 ns tolerance due to float rounding.
	diff := got - want
	if diff > time.Nanosecond || diff < -time.Nanosecond {
		t.Fatalf("DurationBetween mismatch: want %v, got %v", want, got)
	}
}

// TestComparisonHelpers exercises Equal/Before/After for seconds and fraction.
func TestComparisonHelpers(t *testing.T) {
	a := TWAMPTimestamp{Seconds: 10, Fraction: 100}
	b := TWAMPTimestamp{Seconds: 10, Fraction: 200}
	c := TWAMPTimestamp{Seconds: 11, Fraction: 0}

	if !a.Before(b) || b.Before(a) {
		t.Fatalf("Before failed for same second different fraction")
	}
	if !b.After(a) || a.After(b) {
		t.Fatalf("After failed for same second different fraction")
	}
	if !b.Before(c) || !a.Before(c) {
		t.Fatalf("Before failed across seconds")
	}
	if !c.After(b) {
		t.Fatalf("After failed across seconds")
	}
	if !a.Equal(a) || a.Equal(b) {
		t.Fatalf("Equal logic incorrect")
	}
}

// TestRoundTripTime ensures FromTime and ToTime are inverses to nanosecond
// precision (the original time’s monotonic component is lost, so we compare
// only the wall‑clock UnixNano).
func TestRoundTripTime(t *testing.T) {
	now := time.Now().Truncate(time.Nanosecond) // strip monotonic for fairness
	ts := FromTime(now)
	back := ts.ToTime()

	// Allow ±1 ns tolerance because of float64 conversions.
	delta := math.Abs(float64(back.UnixNano() - now.UnixNano()))
	if delta > 1 {
		t.Fatalf("Round‑trip exceeded tolerance: %dns", int64(delta))
	}
}
