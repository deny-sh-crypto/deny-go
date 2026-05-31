package denygo

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	honeyDomain = "deny-sh/honey/v1"

	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alnumUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	base64URL   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	hexAlphabet = "0123456789abcdef"
	base58Alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var defaultHoneyLengths = map[string]int{
	"stripe-test-key":      32,
	"stripe-live-key":      107,
	"github-pat-classic":   40,
	"github-pat-fine":      93,
	"openai-key":           51,
	"anthropic-key":        108,
	"aws-access-key":       20,
	"bip39-phrase":         200,
	"ethereum-private-key": 64,
	"bitcoin-wif":          51,
	"solana-private-key":   88,
}

var honeyV1Types = map[string]struct{}{
	"stripe-test-key":      {},
	"stripe-live-key":      {},
	"github-pat-classic":   {},
	"github-pat-fine":      {},
	"openai-key":           {},
	"anthropic-key":        {},
	"aws-access-key":       {},
	"bip39-phrase":         {},
	"ethereum-private-key": {},
	"bitcoin-wif":          {},
	"solana-private-key":   {},
}

// EncryptHoneyResult is the high-level Honey Mode encrypt output.
type EncryptHoneyResult struct {
	Ciphertext []byte
	RealCtrl   []byte
	Band       int
	HoneyType  string
}

// DecryptHoneyResult is the high-level Honey Mode decrypt output.
type DecryptHoneyResult struct {
	Value  string
	Branch string
}

// IsHoneyEligible returns whether a type can be Honey Mode backed.
func IsHoneyEligible(typ string) bool {
	return typ != "generic" && typ != "freeform-secret"
}

// DeriveHoneySeed derives the deterministic Honey Mode seed.
func DeriveHoneySeed(decryptBytes, salt []byte, typeTag string) [32]byte {
	h := sha256.New()
	h.Write([]byte(honeyDomain))
	h.Write([]byte{0})
	h.Write(decryptBytes)
	h.Write([]byte{0})
	h.Write(salt)
	h.Write([]byte{0})
	h.Write([]byte(typeTag))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SeededByteSource is the Honey Mode SHA-256 counter DRBG.
type SeededByteSource struct {
	seed    [32]byte
	counter uint32
	buffer  [32]byte
	bufPos  int
	bufLen  int
}

// NewSeededByteSource constructs a deterministic byte source from a 32-byte seed.
func NewSeededByteSource(seed [32]byte) *SeededByteSource {
	return &SeededByteSource{seed: seed, bufPos: 32}
}

func (s *SeededByteSource) refill() {
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], s.counter)
	h := sha256.New()
	h.Write(s.seed[:])
	h.Write(ctr[:])
	copy(s.buffer[:], h.Sum(nil))
	s.bufPos = 0
	s.bufLen = 32
	s.counter++
}

// Bytes returns the next n bytes from the continuous keystream.
func (s *SeededByteSource) Bytes(n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	out := make([]byte, n)
	written := 0
	for written < n {
		if s.bufPos >= s.bufLen {
			s.refill()
		}
		take := n - written
		if remaining := s.bufLen - s.bufPos; take > remaining {
			take = remaining
		}
		copy(out[written:written+take], s.buffer[s.bufPos:s.bufPos+take])
		s.bufPos += take
		written += take
	}
	return out
}

func sourcedInt(src *SeededByteSource, max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	limit := (uint64(0x100000000) / uint64(max)) * uint64(max)
	for attempt := 0; attempt < 128; attempt++ {
		v := binary.LittleEndian.Uint32(src.Bytes(4))
		if uint64(v) < limit {
			return int(v % uint32(max)), nil
		}
	}
	return 0, errors.New("sourcedInt: rejection sampling exceeded bound")
}

func honeyChars(src *SeededByteSource, alphabet string, n int) (string, error) {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		idx, err := sourcedInt(src, len(alphabet))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[idx])
	}
	return b.String(), nil
}

func boundedLen(realLen, prefixLen, minBody int, fixedBody *int) (int, error) {
	if fixedBody != nil {
		if prefixLen+*fixedBody > realLen {
			return 0, errors.New("generated decoy exceeds real value length")
		}
		return *fixedBody, nil
	}
	bodyLen := realLen - prefixLen
	if bodyLen < minBody {
		bodyLen = minBody
	}
	if prefixLen+bodyLen > realLen {
		return 0, errors.New("generated decoy exceeds real value length")
	}
	return bodyLen, nil
}

func honeyToken(src *SeededByteSource, prefix string, realLen int, alphabet string, minBody int, fixedBody *int) (string, error) {
	n, err := boundedLen(realLen, len(prefix), minBody, fixedBody)
	if err != nil {
		return "", err
	}
	body, err := honeyChars(src, alphabet, n)
	if err != nil {
		return "", err
	}
	return prefix + body, nil
}

func fixedInt(v int) *int {
	return &v
}

func dummyRealForHoneyType(typ string, lenHint int) string {
	if typ == "bip39-phrase" {
		return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	}
	return strings.Repeat("x", lenHint)
}

func defaultLengthForHoneyType(typ string) (int, error) {
	n, ok := defaultHoneyLengths[typ]
	if !ok {
		return 0, fmt.Errorf("unsupported honey type (post-v1)")
	}
	return n, nil
}

func bip39FromEntropy(entropy []byte, wordCount int) (string, error) {
	entBits := len(entropy) * 8
	csBits := entBits / 32
	if (entBits+csBits)/11 != wordCount {
		return "", fmt.Errorf("entropy length %d does not match %d words", len(entropy), wordCount)
	}
	hash := sha256.Sum256(entropy)
	totalBits := entBits + csBits
	words := make([]string, wordCount)
	for i := 0; i < wordCount; i++ {
		idx := 0
		for j := 0; j < 11; j++ {
			bitPos := i*11 + j
			var bit byte
			if bitPos < entBits {
				bit = (entropy[bitPos/8] >> uint(7-(bitPos%8))) & 1
			} else if bitPos < totalBits {
				hp := bitPos - entBits
				bit = (hash[hp/8] >> uint(7-(hp%8))) & 1
			}
			idx = (idx << 1) | int(bit)
		}
		words[i] = bip39Words[idx]
	}
	return strings.Join(words, " "), nil
}

func randomWords(src *SeededByteSource, count, budget int) (string, error) {
	switch count {
	case 12, 15, 18, 21, 24:
	default:
		return "", errors.New("unsupported honey type (post-v1)")
	}
	entBytes := (count*11 - (count*11)/33) / 8
	for attempt := 0; attempt < 64; attempt++ {
		phrase, err := bip39FromEntropy(src.Bytes(entBytes), count)
		if err != nil {
			return "", err
		}
		if len(phrase) <= budget {
			return phrase, nil
		}
	}
	return "", errors.New("generated decoy exceeds real value length")
}

func base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	digits := []int{0}
	for _, byt := range data {
		carry := int(byt)
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}
	var out strings.Builder
	for _, byt := range data {
		if byt != 0 {
			break
		}
		out.WriteByte('1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out.WriteByte(base58Alpha[digits[i]])
	}
	return out.String()
}

func base58CheckEncode(payload []byte) string {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	full := make([]byte, len(payload)+4)
	copy(full, payload)
	copy(full[len(payload):], second[:4])
	return base58Encode(full)
}

func randomBitcoinWif(src *SeededByteSource, realLen int) (string, error) {
	if realLen < 51 {
		return "", errors.New("generated decoy exceeds real value length")
	}
	compressed := realLen >= 52
	payloadLen := 33
	if compressed {
		payloadLen = 34
	}
	payload := make([]byte, payloadLen)
	payload[0] = 0x80
	copy(payload[1:33], src.Bytes(32))
	if compressed {
		payload[33] = 0x01
	}
	wif := base58CheckEncode(payload)
	if len(wif) <= realLen {
		return wif, nil
	}
	for i := 0; i < 16; i++ {
		copy(payload[1:33], src.Bytes(32))
		retry := base58CheckEncode(payload)
		if len(retry) <= realLen {
			return retry, nil
		}
	}
	return "", errors.New("generated decoy exceeds real value length")
}

func generateLocalHoneyDecoy(src *SeededByteSource, dummyReal, typ string) (string, error) {
	realLen := len(dummyReal)
	switch typ {
	case "stripe-test-key":
		return honeyToken(src, "sk_test_", realLen, alnum, 24, nil)
	case "stripe-live-key":
		return honeyToken(src, "sk_live_", realLen, alnum, 24, nil)
	case "github-pat-classic":
		return honeyToken(src, "ghp_", realLen, alnum, 36, fixedInt(36))
	case "github-pat-fine":
		return honeyToken(src, "github_pat_", realLen, alnum+"_", 60, nil)
	case "openai-key":
		prefix := "sk-"
		if strings.HasPrefix(dummyReal, "sk-proj-") {
			prefix = "sk-proj-"
		}
		return honeyToken(src, prefix, realLen, base64URL, 40, nil)
	case "anthropic-key":
		prefix := "sk-ant-"
		if strings.HasPrefix(dummyReal, "sk-ant-api03-") {
			prefix = "sk-ant-api03-"
		}
		return honeyToken(src, prefix, realLen, base64URL, 80, nil)
	case "aws-access-key":
		prefix := "AKIA"
		if strings.HasPrefix(dummyReal, "ASIA") {
			prefix = "ASIA"
		}
		bodyLen, err := boundedLen(realLen, 4, 16, fixedInt(16))
		if err != nil {
			return "", err
		}
		body, err := honeyChars(src, alnumUpper, bodyLen)
		if err != nil {
			return "", err
		}
		return prefix + body, nil
	case "bip39-phrase":
		words := strings.Fields(dummyReal)
		return randomWords(src, len(words), realLen)
	case "ethereum-private-key":
		if strings.HasPrefix(dummyReal, "0x") {
			return honeyToken(src, "0x", realLen, hexAlphabet, 64, fixedInt(64))
		}
		bodyLen, err := boundedLen(realLen, 0, 64, fixedInt(64))
		if err != nil {
			return "", err
		}
		return honeyChars(src, hexAlphabet, bodyLen)
	case "bitcoin-wif":
		return randomBitcoinWif(src, realLen)
	case "solana-private-key":
		if realLen < 87 {
			return "", errors.New("generated decoy exceeds real value length")
		}
		for i := 0; i < 16; i++ {
			enc := base58Encode(src.Bytes(64))
			if len(enc) >= 87 && len(enc) <= realLen {
				return enc, nil
			}
		}
		return "", errors.New("generated decoy exceeds real value length")
	default:
		return "", fmt.Errorf("unsupported honey type (post-v1)")
	}
}

// GenerateHoneyDecoy deterministically generates a Honey Mode decoy for v1 types.
func GenerateHoneyDecoy(typ string, decryptBytes, salt []byte, realLengthHint int) (string, error) {
	if !IsHoneyEligible(typ) {
		return "", fmt.Errorf("unsupported honey type (post-v1)")
	}
	if _, ok := honeyV1Types[typ]; !ok {
		return "", fmt.Errorf("unsupported honey type (post-v1)")
	}
	lenHint := realLengthHint
	if lenHint < 0 {
		var err error
		lenHint, err = defaultLengthForHoneyType(typ)
		if err != nil {
			return "", err
		}
	}
	dummyReal := dummyRealForHoneyType(typ, lenHint)
	seed := DeriveHoneySeed(decryptBytes, salt, typ)
	return generateLocalHoneyDecoy(NewSeededByteSource(seed), dummyReal, typ)
}

// EncryptHoney encrypts a single structured secret with Honey Mode enabled.
func EncryptHoney(secret, password1, password2, honeyType string) (EncryptHoneyResult, error) {
	if !IsHoneyEligible(honeyType) {
		return EncryptHoneyResult{}, fmt.Errorf(
			"Honey Mode is not supported for unstructured type %q. Use classic Encrypt for generic / freeform secrets.",
			honeyType,
		)
	}

	rawPayload := buildPayload([]byte(secret))
	band := BucketedPayloadLength(len(rawPayload))
	controlData := GenerateControlData(band)

	payload := make([]byte, band)
	copy(payload, rawPayload)
	if band > len(rawPayload) {
		if _, err := io.ReadFull(rand.Reader, payload[len(rawPayload):]); err != nil {
			return EncryptHoneyResult{}, fmt.Errorf("generating padding: %w", err)
		}
	}

	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return EncryptHoneyResult{}, fmt.Errorf("generating salt: %w", err)
	}
	iv := make([]byte, IVLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return EncryptHoneyResult{}, fmt.Errorf("generating iv: %w", err)
	}

	key := DeriveKey(password1, password2, salt)
	xored := xorBytes(payload, controlData[:len(payload)])
	encrypted, err := aesCTR(key, iv, xored)
	if err != nil {
		return EncryptHoneyResult{}, err
	}

	ciphertext := make([]byte, HeaderLength+len(encrypted))
	copy(ciphertext[:SaltLength], salt)
	copy(ciphertext[SaltLength:HeaderLength], iv)
	copy(ciphertext[HeaderLength:], encrypted)

	return EncryptHoneyResult{
		Ciphertext: ciphertext,
		RealCtrl:   controlData,
		Band:       band,
		HoneyType:  honeyType,
	}, nil
}

// DecryptHoney returns the real plaintext for well-formed frames, or a deterministic typed honey fake.
func DecryptHoney(ciphertext, controlData []byte, password1, password2, honeyType string, band int) (DecryptHoneyResult, error) {
	if !IsHoneyEligible(honeyType) {
		return DecryptHoneyResult{}, fmt.Errorf("Honey Mode is not supported for unstructured type %q", honeyType)
	}

	recovered, err := decryptToPayload(ciphertext, password1, password2, controlData, band)
	if err != nil {
		return DecryptHoneyResult{}, err
	}
	if recovered.wellFormed {
		return DecryptHoneyResult{Value: string(recovered.plaintext), Branch: "real"}, nil
	}

	fake, err := GenerateHoneyDecoy(honeyType, recovered.payload, recovered.salt, -1)
	if err != nil {
		return DecryptHoneyResult{}, err
	}
	return DecryptHoneyResult{Value: fake, Branch: "honey"}, nil
}

// IsWellFormedFrame validates the 4-byte LE length frame, optionally against a band.
func IsWellFormedFrame(payload []byte, expectedBand int) bool {
	if len(payload) < LengthPrefix {
		return false
	}
	length := binary.LittleEndian.Uint32(payload[:LengthPrefix])
	if uint64(length) > uint64(len(payload)-LengthPrefix) {
		return false
	}
	if expectedBand >= 0 {
		if expectedBand < LengthPrefix {
			return false
		}
		if uint64(length) > uint64(expectedBand-LengthPrefix) {
			return false
		}
	}
	return true
}
