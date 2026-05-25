// Package denygo implements the deny.sh deniable encryption algorithm.
//
// Algorithm-compatible with the TypeScript and Python reference implementations.
// Ciphertext produced by any SDK can be decrypted by any other.
//
// Algorithm:
//
// ENCRYPT:
//  1. Derive AES-256 key from password1 + password2 via Argon2id
//  2. Prepend 4-byte LE plaintext length to plaintext (inside encrypted zone)
//  3. XOR (length + plaintext) with control data
//  4. AES-256-CTR encrypt the result
//  5. Prepend: salt (32 bytes) + IV (16 bytes) as unencrypted header
//
// DECRYPT:
//  1. Extract salt + IV from header
//  2. Re-derive AES-256 key from passwords + salt
//  3. AES-256-CTR decrypt payload
//  4. XOR with control data
//  5. Read 4-byte length prefix, trim plaintext to that length
//
// DENIABLE DECRYPTION:
//
//	Given ciphertext + passwords + desired fake plaintext:
//	1. AES decrypt to get intermediate (= length+plaintext XOR controlData)
//	2. Construct fake payload = 4-byte-length(fake) + fake plaintext + random padding
//	3. New control data = intermediate XOR fake payload
//	4. Now decrypting with new control file produces the fake plaintext
package denygo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Constants matching the TypeScript/Python reference implementations.
const (
	SaltLength   = 32
	IVLength     = 16
	KeyLength    = 32                    // AES-256
	HeaderLength = SaltLength + IVLength // 48 bytes
	LengthPrefix = 4                     // 4-byte LE length prefix

	argon2TimeCost    uint32 = 3
	argon2MemoryCost  uint32 = 65536 // KiB
	argon2Parallelism uint8  = 1
)

// DeriveKey derives an AES-256 key from two passwords and a salt using Argon2id.
// Combines both passwords via SHA-256 hashing to avoid length ambiguities.
func DeriveKey(password1, password2 string, salt []byte) []byte {
	h1 := sha256.Sum256([]byte(password1))
	h2 := sha256.Sum256([]byte(password2))

	combined := make([]byte, 64)
	copy(combined[:32], h1[:])
	copy(combined[32:], h2[:])

	return argon2.IDKey(combined, salt, argon2TimeCost, argon2MemoryCost, argon2Parallelism, KeyLength)
}

// GenerateControlData generates cryptographically secure random control data.
func GenerateControlData(size int) []byte {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return data
}

// xorBytes XORs two byte slices and returns a new slice of length min(len(a), len(b)).
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// buildPayload prepends a 4-byte little-endian length prefix to data.
func buildPayload(data []byte) []byte {
	payload := make([]byte, LengthPrefix+len(data))
	binary.LittleEndian.PutUint32(payload[:LengthPrefix], uint32(len(data)))
	copy(payload[LengthPrefix:], data)
	return payload
}

// extractPayload reads the 4-byte LE length prefix and returns the trimmed plaintext.
func extractPayload(payload []byte) ([]byte, error) {
	if len(payload) < LengthPrefix {
		return nil, errors.New("payload too short")
	}
	length := binary.LittleEndian.Uint32(payload[:LengthPrefix])
	if int(length) > len(payload)-LengthPrefix {
		// Length exceeds available data - likely wrong password or control file.
		// Return everything after the prefix (matches TS/Python behaviour).
		return payload[LengthPrefix:], nil
	}
	return payload[LengthPrefix : LengthPrefix+int(length)], nil
}

// aesCTR applies AES-256-CTR encryption/decryption (symmetric operation).
func aesCTR(key, iv, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	stream := cipher.NewCTR(block, iv)
	dst := make([]byte, len(src))
	stream.XORKeyStream(dst, src)
	return dst, nil
}

// Encrypt encrypts plaintext using dual passwords and control data.
//
// If controlData is nil, random control data is generated automatically.
// Returns (ciphertext, controlData, error).
// Ciphertext format: salt(32) + iv(16) + AES-256-CTR(payload XOR controlData).
func Encrypt(plaintext []byte, password1, password2 string, controlData []byte) ([]byte, []byte, error) {
	// Build inner payload with length prefix
	payload := buildPayload(plaintext)

	// Generate control data if not provided
	if controlData == nil {
		controlData = GenerateControlData(len(payload))
	}

	if len(controlData) < len(payload) {
		return nil, nil, fmt.Errorf(
			"control data (%d bytes) must be >= plaintext + 4 bytes (%d bytes)",
			len(controlData), len(payload),
		)
	}

	// Generate random salt and IV
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, fmt.Errorf("generating salt: %w", err)
	}
	iv := make([]byte, IVLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("generating iv: %w", err)
	}

	// Derive key
	key := DeriveKey(password1, password2, salt)

	// XOR payload with control data (the deniability layer)
	controlSlice := controlData[:len(payload)]
	xored := xorBytes(payload, controlSlice)

	// AES-256-CTR encrypt
	encrypted, err := aesCTR(key, iv, xored)
	if err != nil {
		return nil, nil, err
	}

	// Pack: salt || iv || encrypted
	result := make([]byte, HeaderLength+len(encrypted))
	copy(result[:SaltLength], salt)
	copy(result[SaltLength:HeaderLength], iv)
	copy(result[HeaderLength:], encrypted)

	return result, controlData, nil
}

// Decrypt decrypts ciphertext using dual passwords and the control data.
func Decrypt(ciphertext []byte, password1, password2 string, controlData []byte) ([]byte, error) {
	if len(ciphertext) < HeaderLength {
		return nil, errors.New("ciphertext too short - missing header")
	}

	// Extract header
	salt := ciphertext[:SaltLength]
	iv := ciphertext[SaltLength:HeaderLength]
	encryptedData := ciphertext[HeaderLength:]

	// Derive key
	key := DeriveKey(password1, password2, salt)

	// AES-256-CTR decrypt
	decrypted, err := aesCTR(key, iv, encryptedData)
	if err != nil {
		return nil, err
	}

	// XOR with control data to recover payload
	if len(controlData) < len(decrypted) {
		return nil, errors.New("control data shorter than decrypted payload")
	}
	controlSlice := controlData[:len(decrypted)]
	payload := xorBytes(decrypted, controlSlice)

	// Extract plaintext from payload
	plaintext, err := extractPayload(payload)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateDeniableControl generates new control data that makes existing ciphertext
// decrypt to a completely different plaintext.
//
// Given:
//   - Original ciphertext (encrypted with password1 + password2 + originalControlData)
//   - The same passwords
//   - A desired fake plaintext
//
// Returns new control data such that Decrypt(ciphertext, pw1, pw2, newControl) = desiredPlaintext.
func GenerateDeniableControl(ciphertext []byte, password1, password2 string, desiredPlaintext []byte) ([]byte, error) {
	if len(ciphertext) < HeaderLength {
		return nil, errors.New("ciphertext too short - missing header")
	}

	// Extract header
	salt := ciphertext[:SaltLength]
	iv := ciphertext[SaltLength:HeaderLength]
	encryptedData := ciphertext[HeaderLength:]

	// Build fake payload with length prefix
	fakePayload := buildPayload(desiredPlaintext)

	if len(fakePayload) > len(encryptedData) {
		return nil, fmt.Errorf(
			"desired plaintext (%d bytes) is too long for this ciphertext",
			len(desiredPlaintext),
		)
	}

	// Derive key
	key := DeriveKey(password1, password2, salt)

	// AES decrypt to get intermediate
	intermediate, err := aesCTR(key, iv, encryptedData)
	if err != nil {
		return nil, err
	}

	// Pad fake payload to match intermediate length with random bytes
	var paddedFake []byte
	if len(fakePayload) < len(intermediate) {
		paddedFake = make([]byte, len(intermediate))
		copy(paddedFake, fakePayload)
		if _, err := io.ReadFull(rand.Reader, paddedFake[len(fakePayload):]); err != nil {
			return nil, fmt.Errorf("generating padding: %w", err)
		}
	} else {
		paddedFake = fakePayload
	}

	// New control data = intermediate XOR fakePayload
	newControlData := xorBytes(intermediate, paddedFake)

	return newControlData, nil
}
