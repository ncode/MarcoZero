package crypto

import (
	"bytes"
	"testing"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
)

func TestDeriveKey(t *testing.T) {
	// Test vector
	secret := "test-password"
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	count := uint32(1024)

	aesKey, hmacKey, err := DeriveKey(secret, salt, count)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	// Verify key lengths
	if len(aesKey) != 16 {
		t.Errorf("AES key length incorrect: got %d, want 16", len(aesKey))
	}

	if len(hmacKey) != 32 {
		t.Errorf("HMAC key length incorrect: got %d, want 32", len(hmacKey))
	}

	// Verify keys are deterministic (same input produces same output)
	aesKey2, hmacKey2, err := DeriveKey(secret, salt, count)
	if err != nil {
		t.Fatalf("Failed to derive keys second time: %v", err)
	}

	if !bytes.Equal(aesKey, aesKey2) {
		t.Errorf("AES key not deterministic")
	}

	if !bytes.Equal(hmacKey, hmacKey2) {
		t.Errorf("HMAC key not deterministic")
	}
}

func TestTokenEncryptionDecryption(t *testing.T) {
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	aesKey := []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	hmacKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hmacKey[i] = byte(i)
	}

	// Create token
	token, err := CreateToken(challenge, aesKey, hmacKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Decrypt token
	contents, err := DecryptToken(token, challenge)
	if err != nil {
		t.Fatalf("Failed to decrypt token: %v", err)
	}

	// Verify token contents
	if !bytes.Equal(contents.Challenge, challenge) {
		t.Errorf("Challenge mismatch in decrypted token")
	}

	if !bytes.Equal(contents.AESKey, aesKey) {
		t.Errorf("AES key mismatch in decrypted token")
	}

	if !bytes.Equal(contents.HMACKey, hmacKey) {
		t.Errorf("HMAC key mismatch in decrypted token")
	}
}

func TestDeriveTestSessionKeys(t *testing.T) {
	controlAESKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	controlHMACKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		controlHMACKey[i] = byte(i)
	}

	var sid common.SessionID
	for i := 0; i < 16; i++ {
		sid[i] = byte(16 - i)
	}

	// Derive test session keys
	testAESKey, testHMACKey, err := DeriveTestSessionKeys(controlAESKey, controlHMACKey, sid)
	if err != nil {
		t.Fatalf("Failed to derive test session keys: %v", err)
	}

	// Verify key lengths
	if len(testAESKey) != 16 {
		t.Errorf("Test AES key length incorrect: got %d, want 16", len(testAESKey))
	}

	if len(testHMACKey) != 32 {
		t.Errorf("Test HMAC key length incorrect: got %d, want 32", len(testHMACKey))
	}

	// Verify keys are deterministic
	testAESKey2, testHMACKey2, err := DeriveTestSessionKeys(controlAESKey, controlHMACKey, sid)
	if err != nil {
		t.Fatalf("Failed to derive test session keys second time: %v", err)
	}

	if !bytes.Equal(testAESKey, testAESKey2) {
		t.Errorf("Test AES key not deterministic")
	}

	if !bytes.Equal(testHMACKey, testHMACKey2) {
		t.Errorf("Test HMAC key not deterministic")
	}

	// Verify test keys differ from control keys
	if bytes.Equal(testAESKey, controlAESKey) {
		t.Errorf("Test AES key should be different from control AES key")
	}

	if bytes.Equal(testHMACKey, controlHMACKey) {
		t.Errorf("Test HMAC key should be different from control HMAC key")
	}
}

func TestHMAC(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}

	message := []byte("This is a test message for HMAC calculation")

	// Calculate HMAC
	hmac1, err := CalculateHMAC(key, message)
	if err != nil {
		t.Fatalf("Failed to calculate HMAC: %v", err)
	}

	// Verify length
	if len(hmac1) != 16 {
		t.Errorf("HMAC length incorrect: got %d, want 16", len(hmac1))
	}

	// Verify HMAC is deterministic
	hmac2, err := CalculateHMAC(key, message)
	if err != nil {
		t.Fatalf("Failed to calculate HMAC second time: %v", err)
	}

	if !bytes.Equal(hmac1, hmac2) {
		t.Errorf("HMAC calculation not deterministic")
	}

	// Verify HMAC validation
	valid, err := VerifyHMAC(key, message, hmac1)
	if err != nil {
		t.Fatalf("HMAC verification failed: %v", err)
	}

	if !valid {
		t.Errorf("HMAC verification should succeed for correct HMAC")
	}

	// Modify message and verify HMAC fails
	modifiedMessage := append([]byte{}, message...)
	modifiedMessage[0] ^= 1 // Flip a bit

	valid, err = VerifyHMAC(key, modifiedMessage, hmac1)
	if err != nil {
		t.Fatalf("HMAC verification failed: %v", err)
	}

	if valid {
		t.Errorf("HMAC verification should fail for modified message")
	}
}

func TestBlockEncryptionDecryption(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	plaintext := []byte("This is a test message for block encryption")

	// Encrypt
	ciphertext, err := EncryptBlocks(key, iv, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptBlocks(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decryption worked
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original: got %q, want %q", decrypted, plaintext)
	}

	// Modify ciphertext and verify decryption fails or produces different result
	modifiedCiphertext := append([]byte{}, ciphertext...)
	modifiedCiphertext[0] ^= 1 // Flip a bit

	modifiedDecrypted, err := DecryptBlocks(key, iv, modifiedCiphertext)
	if err != nil {
		// It's okay if it errors due to padding issues
		return
	}

	// If it didn't error, the result should be different
	if bytes.Equal(plaintext, modifiedDecrypted) {
		t.Errorf("Decryption of modified ciphertext should not match original plaintext")
	}
}
