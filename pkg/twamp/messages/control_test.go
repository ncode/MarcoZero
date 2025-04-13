package messages

import (
	"bytes"
	"testing"
)

func TestServerGreetingMarshaling(t *testing.T) {
	// Create a sample greeting
	greeting := ServerGreeting{
		Modes:     0x00000007, // All three modes supported
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	// Marshal
	data, err := greeting.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal into a new struct
	var parsedGreeting ServerGreeting
	err = parsedGreeting.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if greeting.Modes != parsedGreeting.Modes {
		t.Errorf("Modes mismatch: got %d, want %d", parsedGreeting.Modes, greeting.Modes)
	}

	if !bytes.Equal(greeting.Challenge[:], parsedGreeting.Challenge[:]) {
		t.Errorf("Challenge mismatch")
	}

	if !bytes.Equal(greeting.Salt[:], parsedGreeting.Salt[:]) {
		t.Errorf("Salt mismatch")
	}

	if greeting.Count != parsedGreeting.Count {
		t.Errorf("Count mismatch: got %d, want %d", parsedGreeting.Count, greeting.Count)
	}
}

func TestSetupResponseMarshaling(t *testing.T) {
	// Create a sample response
	response := SetupResponse{
		Mode:     0x00000001, // Unauthenticated mode
		KeyID:    [80]byte{}, // Empty in unauthenticated mode
		Token:    [64]byte{}, // Empty in unauthenticated mode
		ClientIV: [16]byte{}, // Empty in unauthenticated mode
	}

	// Marshal
	data, err := response.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal into a new struct
	var parsedResponse SetupResponse
	err = parsedResponse.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if response.Mode != parsedResponse.Mode {
		t.Errorf("Mode mismatch: got %d, want %d", parsedResponse.Mode, response.Mode)
	}
}
