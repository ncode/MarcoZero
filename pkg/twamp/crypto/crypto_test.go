package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"golang.org/x/crypto/pbkdf2"
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

// TestDeriveTestSessionKeys validates key lengths and deterministic output.
func TestDeriveTestSessionKeys(t *testing.T) {
	controlAES := make([]byte, 16)
	controlHMAC := make([]byte, 32)
	rand.Read(controlAES)
	rand.Read(controlHMAC)
	var sid common.SessionID
	rand.Read(sid[:])

	testAES, testHMAC, err := DeriveTestSessionKeys(controlAES, controlHMAC, sid)
	if err != nil {
		t.Fatalf("DeriveTestSessionKeys: %v", err)
	}
	if len(testAES) != 16 || len(testHMAC) != 32 {
		t.Fatalf("derived key lengths wrong")
	}
	// Same inputs should yield same outputs (deterministic)
	testAES2, testHMAC2, _ := DeriveTestSessionKeys(controlAES, controlHMAC, sid)
	if !bytes.Equal(testAES, testAES2) || !bytes.Equal(testHMAC, testHMAC2) {
		t.Fatalf("DeriveTestSessionKeys not deterministic")
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

// TestDeriveKeyRoundTrip checks DeriveKey returns expected lengths and matches
// an independent PBKDF2 call when count > 0. Also ensures count == 0 still
// returns 48 bytes without error (RFC allows it).
func TestDeriveKeyRoundTrip(t *testing.T) {
	secret := "s3cr3t!"
	salt := make([]byte, 16)
	rand.Read(salt)

	aesKey, hmacKey, err := DeriveKey(secret, salt, 100)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	ref := pbkdf2.Key([]byte(secret), salt, 100, 48, sha1.New)
	if !bytes.Equal(aesKey, ref[:16]) || !bytes.Equal(hmacKey, ref[16:]) {
		t.Fatalf("DeriveKey output mismatch with reference implementation")
	}
	// count = 0 still OK, just different output
	if a2, h2, err := DeriveKey(secret, salt, 0); err != nil || len(a2) != 16 || len(h2) != 32 {
		t.Fatalf("DeriveKey count=0 unexpected error or sizes: %v", err)
	}
	// wrong salt length
	if _, _, err := DeriveKey(secret, salt[:15], 1); err != ErrInvalidSaltLen {
		t.Fatalf("DeriveKey wrong salt len should error, got %v", err)
	}
}

// TestHMACVerify exercises both success and failure paths of VerifyHMAC.
func TestHMACVerify(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	msg := []byte("hello twamp")
	mac, err := CalculateHMAC(key, msg)
	if err != nil {
		t.Fatalf("CalculateHMAC: %v", err)
	}
	ok, _ := VerifyHMAC(key, msg, mac)
	if !ok {
		t.Fatalf("VerifyHMAC should succeed on valid digest")
	}

	mac[0] ^= 0xFF // corrupt
	ok, _ = VerifyHMAC(key, msg, mac)
	if ok {
		t.Fatalf("VerifyHMAC should fail on corrupted digest")
	}
}

// TestEncryptDecryptBlocks round‑trips an arbitrary payload through AES‑CBC.
func TestEncryptDecryptBlocks(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)
	payload := []byte("Twenty‑three bytes of data")

	ct, err := EncryptBlocks(key, iv, payload)
	if err != nil {
		t.Fatalf("EncryptBlocks: %v", err)
	}
	pt, err := DecryptBlocks(key, iv, ct)
	if err != nil {
		t.Fatalf("DecryptBlocks: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("decrypt output mismatch")
	}
	// invalid key size
	if _, err := EncryptBlocks(key[:15], iv, payload); err != ErrInvalidKeyLength {
		t.Fatalf("expected ErrInvalidKeyLength, got %v", err)
	}
}

// TestEncryptDecryptTWAMPPacket covers both authenticated and encrypted modes.
func TestEncryptDecryptTWAMPPacket(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	// Need at least 96 bytes for encrypted mode
	packet := make([]byte, 96)
	rand.Read(packet)

	for _, auth := range []bool{true, false} {
		enc, err := EncryptTWAMPTestPacket(key, iv, packet, auth)
		if err != nil {
			t.Fatalf("EncryptTWAMPTestPacket auth=%v: %v", auth, err)
		}
		dec, err := DecryptTWAMPTestPacket(key, iv, enc, auth)
		if err != nil {
			t.Fatalf("DecryptTWAMPTestPacket auth=%v: %v", auth, err)
		}
		if !bytes.Equal(dec, packet) {
			t.Fatalf("round‑trip mismatch auth=%v", auth)
		}
	}
}

// TestTokenCreateDecrypt round‑trips CreateToken / DecryptToken and hits error
// paths for invalid lengths.
func TestTokenCreateDecrypt(t *testing.T) {
	challenge := make([]byte, 16)
	aesKey := make([]byte, 16)
	hmacKey := make([]byte, 32)
	rand.Read(challenge)
	rand.Read(aesKey)
	rand.Read(hmacKey)

	token, err := CreateToken(challenge, aesKey, hmacKey)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	contents, err := DecryptToken(token, challenge)
	if err != nil {
		t.Fatalf("DecryptToken: %v", err)
	}
	if !bytes.Equal(contents.Challenge, challenge) || !bytes.Equal(contents.AESKey, aesKey) || !bytes.Equal(contents.HMACKey, hmacKey) {
		t.Fatalf("token round‑trip mismatch")
	}
	// Error: wrong challenge length
	if _, err := CreateToken(challenge[:15], aesKey, hmacKey); err == nil {
		t.Fatalf("expected error on short challenge")
	}
	if _, err := DecryptToken(token, challenge[:15]); err == nil {
		t.Fatalf("expected error on decrypt with short challenge")
	}
}
