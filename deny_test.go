package denygo

import (
	"bytes"
	"encoding/hex"
	"testing"
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

// --- Cross-compatibility KAT vectors (from TypeScript tests) ---

func TestDeriveKeyKAT1(t *testing.T) {
	// DeriveKey('password1', 'password2', salt=0xAA*32) -> hex starts with 73dd642b
	salt := bytes.Repeat([]byte{0xAA}, 32)
	key := DeriveKey("password1", "password2", salt)
	hexKey := hex.EncodeToString(key)
	if hexKey[:8] != "73dd642b" {
		t.Errorf("KAT1 failed: got prefix %s, want 73dd642b (full: %s)", hexKey[:8], hexKey)
	}
}

func TestDeriveKeyKAT2(t *testing.T) {
	// DeriveKey('test-pw1', 'test-pw2', salt=0x01*32) -> hex starts with ed672cc0
	salt := bytes.Repeat([]byte{0x01}, 32)
	key := DeriveKey("test-pw1", "test-pw2", salt)
	hexKey := hex.EncodeToString(key)
	if hexKey[:8] != "ed672cc0" {
		t.Errorf("KAT2 failed: got prefix %s, want ed672cc0 (full: %s)", hexKey[:8], hexKey)
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
