package messages

import (
	"crypto/rand"
)

// GenerateRandomPadding creates cryptographically secure random padding
func GenerateRandomPadding(size int) ([]byte, error) {
	if size <= 0 {
		return []byte{}, nil
	}

	padding := make([]byte, size)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, err
	}

	return padding, nil
}

// GenerateZeroPadding creates padding filled with zeros
func GenerateZeroPadding(size int) []byte {
	if size <= 0 {
		return []byte{}
	}

	return make([]byte, size)
}
