package messages

import "testing"

func TestPaddingHelpers(t *testing.T) {
	if got := GenerateZeroPadding(0); len(got) != 0 {
		t.Fatalf("zero padding size 0 should be empty")
	}
	if got := GenerateZeroPadding(4); len(got) != 4 || got[0] != 0 || got[3] != 0 {
		t.Fatalf("zero padding not zero‑filled or wrong size")
	}
	randPad, err := GenerateRandomPadding(8)
	if err != nil || len(randPad) != 8 {
		t.Fatalf("random padding failure: %v len=%d", err, len(randPad))
	}
	allZero := true
	for _, b := range randPad {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("random padding appears to be all zeros – very unlikely, investigate")
	}
}
