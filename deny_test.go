package denygo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

var (
	pw1 = "agent0018765432!unconditional"
	pw2 = "unconditional1234567Bagent001"
)

// --- Basic encrypt/decrypt ---

func TestEncryptDecryptRoundtrip(t *testing.T) {
	message := []byte("Meet Me At 2pm Tomorrow")
	controlData := GenerateControlData(len(message) + 4)

	ciphertext, ctrl, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Errorf("roundtrip failed: got %q, want %q", plaintext, message)
	}
}

func TestEncryptDecryptEmptyMessage(t *testing.T) {
	message := []byte{}
	controlData := GenerateControlData(4)

	ciphertext, ctrl, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(plaintext) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(plaintext))
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	message := make([]byte, 100*1024) // 100KB
	for i := range message {
		message[i] = byte(i % 256)
	}
	controlData := GenerateControlData(len(message) + 4)

	ciphertext, ctrl, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Error("large data roundtrip failed")
	}
}

func TestDifferentCiphertextEachTime(t *testing.T) {
	message := []byte("Same message")
	controlData := GenerateControlData(len(message) + 4)

	c1, _, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(c1, c2) {
		t.Error("two encryptions should produce different ciphertext (random salt+IV)")
	}
}

func TestWrongPasswordProducesGarbage(t *testing.T) {
	message := []byte("Secret")
	controlData := GenerateControlData(len(message) + 4)

	ciphertext, _, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(ciphertext, "wrong", pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(plaintext, message) {
		t.Error("wrong password should not produce correct plaintext")
	}
}

func TestWrongControlDataProducesGarbage(t *testing.T) {
	message := []byte("Secret")
	controlData := GenerateControlData(len(message) + 4)
	wrongControl := GenerateControlData(len(message) + 4)

	ciphertext, _, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, wrongControl)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(plaintext, message) {
		t.Error("wrong control data should not produce correct plaintext")
	}
}

func TestControlDataTooShort(t *testing.T) {
	message := []byte("Hello world")
	shortControl := GenerateControlData(3)

	_, _, err := Encrypt(message, pw1, pw2, shortControl)
	if err == nil {
		t.Error("expected error for short control data")
	}
}

func TestAutoGenerateControlData(t *testing.T) {
	message := []byte("Auto control generation")

	ciphertext, ctrl, err := Encrypt(message, pw1, pw2, nil)
	if err != nil {
		t.Fatalf("Encrypt with nil controlData failed: %v", err)
	}

	if ctrl == nil || len(ctrl) == 0 {
		t.Fatal("expected auto-generated control data")
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Errorf("auto control roundtrip failed: got %q, want %q", plaintext, message)
	}
}

func TestUnicodeMessage(t *testing.T) {
	message := []byte("Привет мир 🌍 こんにちは")
	controlData := GenerateControlData(len(message) + 4)

	ciphertext, ctrl, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Errorf("unicode roundtrip failed: got %q, want %q", plaintext, message)
	}
}

func TestCiphertextTooShort(t *testing.T) {
	_, err := Decrypt([]byte{1, 2, 3}, pw1, pw2, []byte{0})
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

// --- Deniable encryption ---

func TestDeniableControlGeneration(t *testing.T) {
	realMessage := []byte("Meet Me At 2pm Tomorrow")
	fakeMessage := []byte("Kill KyK In One Month")
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, ctrl, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	// Verify real decryption
	realDecrypted, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(realDecrypted, realMessage) {
		t.Fatalf("real decryption failed: got %q", realDecrypted)
	}

	// Generate deniable control
	fakeControl, err := GenerateDeniableControl(ciphertext, pw1, pw2, fakeMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with fake control
	fakeDecrypted, err := Decrypt(ciphertext, pw1, pw2, fakeControl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fakeDecrypted, fakeMessage) {
		t.Errorf("deniable decryption failed: got %q, want %q", fakeDecrypted, fakeMessage)
	}
}

func TestDeniableShorterFakeMessage(t *testing.T) {
	realMessage := []byte("This is a long secret message with details")
	fakeMessage := []byte("Nothing here")
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, _, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	fakeControl, err := GenerateDeniableControl(ciphertext, pw1, pw2, fakeMessage)
	if err != nil {
		t.Fatal(err)
	}

	fakeDecrypted, err := Decrypt(ciphertext, pw1, pw2, fakeControl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fakeDecrypted, fakeMessage) {
		t.Errorf("short fake decryption failed: got %q, want %q", fakeDecrypted, fakeMessage)
	}
}

func TestDeniableEmptyFakeMessage(t *testing.T) {
	realMessage := []byte("Real secret")
	fakeMessage := []byte{}
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, _, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	fakeControl, err := GenerateDeniableControl(ciphertext, pw1, pw2, fakeMessage)
	if err != nil {
		t.Fatal(err)
	}

	fakeDecrypted, err := Decrypt(ciphertext, pw1, pw2, fakeControl)
	if err != nil {
		t.Fatal(err)
	}

	if len(fakeDecrypted) != 0 {
		t.Errorf("expected empty fake plaintext, got %d bytes", len(fakeDecrypted))
	}
}

func TestDeniableSameLengthMessages(t *testing.T) {
	realMessage := []byte("AAAA")
	fakeMessage := []byte("BBBB")
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, _, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	fakeControl, err := GenerateDeniableControl(ciphertext, pw1, pw2, fakeMessage)
	if err != nil {
		t.Fatal(err)
	}

	fakeDecrypted, err := Decrypt(ciphertext, pw1, pw2, fakeControl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fakeDecrypted, fakeMessage) {
		t.Errorf("same-length fake decryption failed: got %q, want %q", fakeDecrypted, fakeMessage)
	}
}

func TestDeniableMultipleFakeMessages(t *testing.T) {
	realMessage := []byte("The real secret")
	fake1 := []byte("Fake message 1")
	fake2 := []byte("Fake message 2")
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, _, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	ctrl1, err := GenerateDeniableControl(ciphertext, pw1, pw2, fake1)
	if err != nil {
		t.Fatal(err)
	}
	ctrl2, err := GenerateDeniableControl(ciphertext, pw1, pw2, fake2)
	if err != nil {
		t.Fatal(err)
	}

	dec1, err := Decrypt(ciphertext, pw1, pw2, ctrl1)
	if err != nil {
		t.Fatal(err)
	}
	dec2, err := Decrypt(ciphertext, pw1, pw2, ctrl2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dec1, fake1) {
		t.Errorf("fake1 decryption failed: got %q, want %q", dec1, fake1)
	}
	if !bytes.Equal(dec2, fake2) {
		t.Errorf("fake2 decryption failed: got %q, want %q", dec2, fake2)
	}
	if bytes.Equal(ctrl1, ctrl2) {
		t.Error("control data for different fakes should differ")
	}
}

func TestDeniableUnicodeFakeMessage(t *testing.T) {
	realMessage := []byte("Secret plans that are quite long for testing")
	fakeMessage := []byte("日本語テスト")
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, _, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	fakeControl, err := GenerateDeniableControl(ciphertext, pw1, pw2, fakeMessage)
	if err != nil {
		t.Fatal(err)
	}

	fakeDecrypted, err := Decrypt(ciphertext, pw1, pw2, fakeControl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fakeDecrypted, fakeMessage) {
		t.Errorf("unicode fake decryption failed: got %q, want %q", fakeDecrypted, fakeMessage)
	}
}

func TestDeniableFakeTooLong(t *testing.T) {
	realMessage := []byte("Short")
	controlData := GenerateControlData(len(realMessage) + 4)

	ciphertext, _, err := Encrypt(realMessage, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	tooLong := make([]byte, 1000)
	_, err = GenerateDeniableControl(ciphertext, pw1, pw2, tooLong)
	if err == nil {
		t.Error("expected error for fake message too long")
	}
}

// --- Key derivation ---

func TestDeriveKeyConsistent(t *testing.T) {
	salt := make([]byte, 32)
	k1 := DeriveKey("pass1", "pass2", salt)
	k2 := DeriveKey("pass1", "pass2", salt)
	if !bytes.Equal(k1, k2) {
		t.Error("same inputs should produce same key")
	}
}

func TestDeriveKeyDifferentPasswords(t *testing.T) {
	salt := make([]byte, 32)
	k1 := DeriveKey("pass1", "pass2", salt)
	k2 := DeriveKey("pass1", "pass3", salt)
	if bytes.Equal(k1, k2) {
		t.Error("different passwords should produce different keys")
	}
}

func TestDeriveKeyDifferentSalts(t *testing.T) {
	salt1 := make([]byte, 32)
	salt2 := bytes.Repeat([]byte{1}, 32)
	k1 := DeriveKey("pass1", "pass2", salt1)
	k2 := DeriveKey("pass1", "pass2", salt2)
	if bytes.Equal(k1, k2) {
		t.Error("different salts should produce different keys")
	}
}

func TestDeriveKeyPasswordOrderMatters(t *testing.T) {
	salt := make([]byte, 32)
	k1 := DeriveKey("alpha", "beta", salt)
	k2 := DeriveKey("beta", "alpha", salt)
	if bytes.Equal(k1, k2) {
		t.Error("password order should matter")
	}
}

// --- Cross-implementation Known Answer Tests ---
//
// These vectors are byte-identical across the four reference SDKs
// (TypeScript, Python, Rust, Go) and gate cross-SDK ciphertext
// interoperability. A regression in Argon2id parameters (t=3, m=64MiB,
// p=1, variant=Argon2id, version=0x13), SHA-256 pre-hashing, or
// AES-CTR composition will fail one of these tests before publishing.
// Whitepaper §8 references these exact values.

func TestDeriveKeyKAT1(t *testing.T) {
	// DeriveKey('password1', 'password2', salt=0xAA*32) full 32-byte output.
	salt := bytes.Repeat([]byte{0xAA}, 32)
	key := DeriveKey("password1", "password2", salt)
	want := "854e7acffd85eae6d45ed07e84237fddc887928270f591a41b36d57e675181d8"
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("KAT1 deriveKey: got %s, want %s", got, want)
	}
}

func TestDeriveKeyKAT2(t *testing.T) {
	// DeriveKey('test-pw1', 'test-pw2', salt=0x01*32) full 32-byte output.
	salt := bytes.Repeat([]byte{0x01}, 32)
	key := DeriveKey("test-pw1", "test-pw2", salt)
	want := "d99364f250367785bff7a962331254b18138d2249c969e27b0f75060070fa3f6"
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("KAT2 deriveKey: got %s, want %s", got, want)
	}
}

func TestFullCiphertextKAT(t *testing.T) {
	// Inputs match Python tests/test_core.py:test_full_encrypt_decrypt_kat,
	// TypeScript src/test/core.test.ts "KAT 3: full ciphertext", and
	// Rust tests/integration_test.rs:kat_full_ciphertext_byte_exact.
	pw1Local := "test-pw1"
	pw2Local := "test-pw2"
	fixedSalt := bytes.Repeat([]byte{0x01}, 32)
	fixedIV := bytes.Repeat([]byte{0x02}, 16)
	message := []byte("Hello, World!") // 13 bytes
	controlData := bytes.Repeat([]byte{0x03}, len(message)+4) // 17 bytes

	// 1. Derive key (must match KAT 2).
	key := DeriveKey(pw1Local, pw2Local, fixedSalt)
	if got := hex.EncodeToString(key); got != "d99364f250367785bff7a962331254b18138d2249c969e27b0f75060070fa3f6" {
		t.Fatalf("derived key mismatch: %s", got)
	}

	// 2. Build payload: LE32 length || plaintext.
	payload := make([]byte, len(message)+4)
	binary.LittleEndian.PutUint32(payload[:4], uint32(len(message)))
	copy(payload[4:], message)
	if got := hex.EncodeToString(payload); got != "0d00000048656c6c6f2c20576f726c6421" {
		t.Fatalf("payload mismatch: %s", got)
	}

	// 3. XOR with control data.
	xored := make([]byte, len(payload))
	for i := range payload {
		xored[i] = payload[i] ^ controlData[i]
	}
	if got := hex.EncodeToString(xored); got != "0e0303034b666f6f6c2f23546c716f6722" {
		t.Fatalf("xored mismatch: %s", got)
	}

	// 4. AES-256-CTR encrypt with fixed IV.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	stream := cipher.NewCTR(block, fixedIV)
	encrypted := make([]byte, len(xored))
	stream.XORKeyStream(encrypted, xored)
	if got := hex.EncodeToString(encrypted); got != "7c5cd13699e85f6bcde6dad013d48047ca" {
		t.Fatalf("encrypted mismatch: %s", got)
	}

	// 5. Full wire-format ciphertext = salt(32) || iv(16) || encrypted(17).
	fullCT := append(append(append([]byte{}, fixedSalt...), fixedIV...), encrypted...)
	wantFull := "0101010101010101010101010101010101010101010101010101010101010101" +
		"02020202020202020202020202020202" +
		"7c5cd13699e85f6bcde6dad013d48047ca"
	if got := hex.EncodeToString(fullCT); got != wantFull {
		t.Fatalf("full ciphertext mismatch:\n got %s\nwant %s", got, wantFull)
	}
}

// --- Header format ---

func TestCiphertextHeaderFormat(t *testing.T) {
	message := []byte("Test header format")
	controlData := GenerateControlData(len(message) + 4)

	ciphertext, _, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	// Header should be 48 bytes (32 salt + 16 iv) + encrypted payload
	expectedLen := HeaderLength + len(message) + LengthPrefix
	if len(ciphertext) != expectedLen {
		t.Errorf("ciphertext length: got %d, want %d", len(ciphertext), expectedLen)
	}
}

// --- Short plaintext lengths ---

func TestSingleByteMessage(t *testing.T) {
	message := []byte{0x42}
	controlData := GenerateControlData(len(message) + 4)

	ciphertext, ctrl, err := Encrypt(message, pw1, pw2, controlData)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(ciphertext, pw1, pw2, ctrl)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Errorf("single byte roundtrip failed: got %v, want %v", plaintext, message)
	}
}

// --- Argon2id parameter pinning ---
//
// If any of these constants ever drifts (e.g. a future refactor changes
// m=65536 to m=131072), a DeriveKey call with known inputs will produce
// DIFFERENT output from the locked KAT vectors above. This test asserts
// the PARAMETERS THEMSELVES rather than the resulting hex so that the
// failure message names the bad constant directly.
func TestArgon2idParametersAreLocked(t *testing.T) {
	// These are the locked v2.0.0 cross-SDK parameters.
	const (
		lockedTime        uint32 = 3
		lockedMemory      uint32 = 65536
		lockedParallelism uint8  = 1
		lockedKeyLen      uint32 = 32
	)

	pw1Hash := sha256.Sum256([]byte("password1"))
	pw2Hash := sha256.Sum256([]byte("password2"))
	combined := append(pw1Hash[:], pw2Hash[:]...)
	salt := bytes.Repeat([]byte{0xAA}, 32)

	key := argon2.IDKey(combined, salt, lockedTime, lockedMemory, lockedParallelism, lockedKeyLen)

	want := "854e7acffd85eae6d45ed07e84237fddc887928270f591a41b36d57e675181d8"
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("Argon2id parameter pinning failed; one of t=%d m=%d p=%d len=%d has drifted.\n got %s\nwant %s",
			lockedTime, lockedMemory, lockedParallelism, lockedKeyLen, got, want)
	}
}

// TestDecryptShortControlData is a regression test for the Go panic when
// controlData is shorter than the decrypted payload. Other SDKs return a
// clean error; Go must match.
func TestDecryptShortControlData(t *testing.T) {
	msg := []byte("test message for short ctrl regression")
	ctrl := GenerateControlData(len(msg) + 4)
	ct, _, err := Encrypt(msg, "pw1", "pw2", ctrl)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	shortCtrl := []byte{0x01, 0x02} // much shorter than payload
	_, err = Decrypt(ct, "pw1", "pw2", shortCtrl)
	if err == nil {
		t.Fatal("expected error on short control data, got none (panic risk)")
	}
}
