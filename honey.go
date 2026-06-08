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
	niFirst     = "ABCEGHJKLMNOPRSTWXYZ"
	niSecond    = "ABCEGHJKLMNPRSTWXYZ"
)

var defaultHoneyLengths = map[string]int{
	"stripe-test-key":      32,
	"stripe-live-key":      107,
	"github-pat-classic":   40,
	"github-pat-fine":      93,
	"openai-key":           51,
	"anthropic-key":        108,
	"resend-key":           36,
	"aws-access-key":       20,
	"bip39-phrase":         200,
	"jwt-token":            300,
	"iban":                 22,
	"credit-card":          16,
	"private-key-pem":      1700,
	"postgres-uri":         80,
	"mongodb-uri":          90,
	"slack-bot-token":      57,
	"slack-user-token":     65,
	"discord-bot-token":    72,
	"digitalocean-pat":     71,
	"twilio-auth-token":    34,
	"sendgrid-key":         69,
	"huggingface-token":    40,
	"npm-publish-token":    40,
	"pypi-token":           156,
	"gitlab-pat":           26,
	"mailgun-api-key":      36,
	"linear-api-key":       51,
	"notion-token":         50,
	"shopify-token":        38,
	"square-token":         64,
	"cloudflare-api-token": 40,
	"ethereum-private-key": 64,
	"bitcoin-wif":          51,
	"solana-private-key":   88,
	"uk-nhs-number":        10,
	"us-ssn":               11,
	"uk-ni-number":         9,
	"phone-e164":           15,
	"generic":              32,
	"freeform-secret":      32,
}

var honeyV1Types = map[string]struct{}{
	"stripe-test-key":      {},
	"stripe-live-key":      {},
	"github-pat-classic":   {},
	"github-pat-fine":      {},
	"openai-key":           {},
	"anthropic-key":        {},
	"resend-key":           {},
	"aws-access-key":       {},
	"bip39-phrase":         {},
	"jwt-token":            {},
	"iban":                 {},
	"credit-card":          {},
	"private-key-pem":      {},
	"postgres-uri":         {},
	"mongodb-uri":          {},
	"slack-bot-token":      {},
	"slack-user-token":     {},
	"discord-bot-token":    {},
	"digitalocean-pat":     {},
	"twilio-auth-token":    {},
	"sendgrid-key":         {},
	"huggingface-token":    {},
	"npm-publish-token":    {},
	"pypi-token":           {},
	"gitlab-pat":           {},
	"mailgun-api-key":      {},
	"linear-api-key":       {},
	"notion-token":         {},
	"shopify-token":        {},
	"square-token":         {},
	"cloudflare-api-token": {},
	"ethereum-private-key": {},
	"bitcoin-wif":          {},
	"solana-private-key":   {},
	"uk-nhs-number":        {},
	"us-ssn":               {},
	"uk-ni-number":         {},
	"phone-e164":           {},
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
//
// Excludes the unstructured fallback types (generic / freeform-secret) and the
// post-v1 structured types whose cross-SDK byte parity is not yet proven
// (jwt/uri generators build JSON / multi-branch connection strings).
// HONEY-MODE-SPEC marks the post-v1 set "stub to throw" until a byte-exact port
// lands. Must match the TS HONEY_INELIGIBLE set exactly.
func IsHoneyEligible(typ string) bool {
	switch typ {
	case "generic", "freeform-secret", "jwt-token", "postgres-uri", "mongodb-uri":
		return false
	default:
		return true
	}
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

func honeyDigits(src *SeededByteSource, n int) (string, error) {
	return honeyChars(src, "0123456789", n)
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func dummyRealForHoneyType(typ string, lenHint int) string {
	switch typ {
	case "bip39-phrase":
		return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	case "jwt-token":
		bodyLen := maxInt(1, lenHint-len("e30.."))
		first := maxInt(1, bodyLen/2)
		return "e30." + strings.Repeat("x", first) + "." + strings.Repeat("x", bodyLen-first)
	case "credit-card":
		return strings.Repeat("4", lenHint)
	case "iban":
		return "GB" + strings.Repeat("0", maxInt(0, lenHint-2))
	case "postgres-uri":
		return "postgres://" + strings.Repeat("x", maxInt(0, lenHint-len("postgres://")))
	case "mongodb-uri":
		return "mongodb://" + strings.Repeat("x", maxInt(0, lenHint-len("mongodb://")))
	case "phone-e164":
		return "+" + strings.Repeat("1", maxInt(0, lenHint-1))
	default:
		return strings.Repeat("x", lenHint)
	}
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
	// The decoy must fit `budget` (== the real phrase's char length). Naive
	// `<= budget` rejection biases decoys SHORTER than the real value, which a
	// length/transition-rate classifier exploits. Prefer a phrase whose length
	// EXACTLY equals the budget so the decoy length distribution matches the
	// real distribution. Mirrors the TS reference (256 attempts, prefer-exact).
	bestFit := ""
	for attempt := 0; attempt < 256; attempt++ {
		phrase, err := bip39FromEntropy(src.Bytes(entBytes), count)
		if err != nil {
			return "", err
		}
		if len(phrase) == budget {
			return phrase, nil
		}
		if len(phrase) <= budget && len(phrase) > len(bestFit) {
			bestFit = phrase
		}
	}
	if bestFit != "" {
		return bestFit, nil
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

func segment(src *SeededByteSource, n int, alphabet string) (string, error) {
	return honeyChars(src, alphabet, maxInt(1, n))
}

func splitLengths(real string, parts int) []int {
	segs := strings.Split(real, ".")
	if len(segs) == parts {
		out := make([]int, parts)
		for i, s := range segs {
			out[i] = maxInt(1, len(s))
		}
		return out
	}
	base := maxInt(1, len(real)/parts)
	out := make([]int, parts)
	for i := 0; i < parts; i++ {
		if i == parts-1 {
			out[i] = maxInt(1, len(real)-base*(parts-1))
		} else {
			out[i] = base
		}
	}
	return out
}

func randomJwt(src *SeededByteSource, real string) (string, error) {
	lengths := splitLengths(real, 3)
	lengths[0] = maxInt(lengths[0], len("e30"))
	headerPadLen := maxInt(0, lengths[0]-len("e30"))
	headerPad := ""
	var err error
	if headerPadLen > 0 {
		headerPad, err = segment(src, headerPadLen, base64URL)
		if err != nil {
			return "", err
		}
	}
	mid, err := segment(src, lengths[1], base64URL)
	if err != nil {
		return "", err
	}
	last, err := segment(src, lengths[2], base64URL)
	if err != nil {
		return "", err
	}
	out := "e30" + headerPad + "." + mid + "." + last
	if len(out) > len(real) {
		return "", errors.New("generated decoy exceeds real value length")
	}
	return out, nil
}

func ibanCheckDigits(countryCode, bban string) string {
	rearranged := strings.ToUpper(bban) + strings.ToUpper(countryCode) + "00"
	remainder := 0
	for i := 0; i < len(rearranged); i++ {
		ch := rearranged[i]
		if ch >= '0' && ch <= '9' {
			remainder = (remainder*10 + int(ch-'0')) % 97
		} else if ch >= 'A' && ch <= 'Z' {
			v := int(ch - 55)
			remainder = (remainder*10 + v/10) % 97
			remainder = (remainder*10 + v%10) % 97
		}
	}
	check := 98 - remainder
	if check < 10 {
		return fmt.Sprintf("0%d", check)
	}
	return fmt.Sprintf("%d", check)
}

func randomIban(src *SeededByteSource, real string) (string, error) {
	clean := strings.ToUpper(strings.Join(strings.Fields(real), ""))
	if len(clean) < 15 {
		return "", errors.New("real IBAN value too short (minimum 15 chars)")
	}
	cc := "GB"
	if len(clean) >= 2 && clean[0] >= 'A' && clean[0] <= 'Z' && clean[1] >= 'A' && clean[1] <= 'Z' {
		cc = clean[:2]
	}
	bban, err := honeyChars(src, alnumUpper, len(clean)-4)
	if err != nil {
		return "", err
	}
	return cc + ibanCheckDigits(cc, bban) + bban, nil
}

func luhnCheckDigit(bodyDigits string) int {
	sum := 0
	alternate := true
	for i := len(bodyDigits) - 1; i >= 0; i-- {
		d := int(bodyDigits[i] - '0')
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}
	return (10 - (sum % 10)) % 10
}

func randomCreditCard(src *SeededByteSource, real string) (string, error) {
	layout := []byte(real)
	var digitPositions []int
	for i, ch := range layout {
		if ch >= '0' && ch <= '9' {
			digitPositions = append(digitPositions, i)
		}
	}
	if len(digitPositions) < 2 {
		for _, pos := range digitPositions {
			n, err := sourcedInt(src, 10)
			if err != nil {
				return "", err
			}
			layout[pos] = byte('0' + n)
		}
		return string(layout), nil
	}
	for k := 0; k < len(digitPositions)-1; k++ {
		n, err := sourcedInt(src, 10)
		if err != nil {
			return "", err
		}
		layout[digitPositions[k]] = byte('0' + n)
	}
	var body strings.Builder
	for _, pos := range digitPositions[:len(digitPositions)-1] {
		body.WriteByte(layout[pos])
	}
	layout[digitPositions[len(digitPositions)-1]] = byte('0' + luhnCheckDigit(body.String()))
	return string(layout), nil
}

func randomPrivateKeyPem(src *SeededByteSource, real string) (string, error) {
	begin := "-----BEGIN PRIVATE KEY-----\n"
	end := "\n-----END PRIVATE KEY-----"
	budget := len(real) - len(begin) - len(end)
	if budget < 1 {
		return "", errors.New("generated decoy exceeds real value length")
	}
	body, err := honeyChars(src, base64URL, budget)
	if err != nil {
		return "", err
	}
	return begin + body + end, nil
}

func uriScheme(real, fallbackScheme string) string {
	colon := strings.Index(real, "://")
	if colon <= 0 {
		return fallbackScheme
	}
	for i := 0; i < colon; i++ {
		ch := real[i]
		if i == 0 {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
				return fallbackScheme
			}
			continue
		}
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '.' || ch == '-') {
			return fallbackScheme
		}
	}
	return real[:colon+3]
}

func randomURI(src *SeededByteSource, real, fallbackScheme string) (string, error) {
	scheme := uriScheme(real, fallbackScheme)
	hostBody, err := honeyChars(src, "abcdefghijklmnopqrstuvwxyz", 8)
	if err != nil {
		return "", err
	}
	userBody, err := honeyChars(src, alnum, 5)
	if err != nil {
		return "", err
	}
	passBody, err := honeyChars(src, alnum, 8)
	if err != nil {
		return "", err
	}
	pathBody, err := honeyChars(src, "abcdefghijklmnopqrstuvwxyz", 6)
	if err != nil {
		return "", err
	}
	host := hostBody + ".example.test"
	out := scheme + "u" + userBody + ":" + "p" + passBody + "@" + host + "/" + pathBody
	if len(out) > len(real) {
		out = scheme + host
	}
	if len(out) > len(real) {
		return "", errors.New("generated decoy exceeds real value length")
	}
	return out, nil
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
	case "resend-key":
		return honeyToken(src, "re_", realLen, alnum+"_", 20, nil)
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
	case "jwt-token":
		return randomJwt(src, dummyReal)
	case "iban":
		return randomIban(src, dummyReal)
	case "credit-card":
		return randomCreditCard(src, dummyReal)
	case "private-key-pem":
		return randomPrivateKeyPem(src, dummyReal)
	case "postgres-uri":
		return randomURI(src, dummyReal, "postgres://")
	case "mongodb-uri":
		return randomURI(src, dummyReal, "mongodb://")
	case "slack-bot-token":
		bodyLen, err := boundedLen(realLen, len("xoxb-")+11+1+11+1, 24, nil)
		if err != nil {
			return "", err
		}
		a, err := honeyDigits(src, 11)
		if err != nil {
			return "", err
		}
		b, err := honeyDigits(src, 11)
		if err != nil {
			return "", err
		}
		c, err := honeyChars(src, alnum, bodyLen)
		if err != nil {
			return "", err
		}
		return "xoxb-" + a + "-" + b + "-" + c, nil
	case "slack-user-token":
		bodyLen, err := boundedLen(realLen, len("xoxp-")+11+1+11+1+11+1, 24, nil)
		if err != nil {
			return "", err
		}
		a, err := honeyDigits(src, 11)
		if err != nil {
			return "", err
		}
		b, err := honeyDigits(src, 11)
		if err != nil {
			return "", err
		}
		c, err := honeyDigits(src, 11)
		if err != nil {
			return "", err
		}
		d, err := honeyChars(src, alnum, bodyLen)
		if err != nil {
			return "", err
		}
		return "xoxp-" + a + "-" + b + "-" + c + "-" + d, nil
	case "discord-bot-token":
		lengths := splitLengths(dummyReal, 3)
		lengths[0] = maxInt(23, minInt(28, lengths[0]))
		lengths[1] = maxInt(6, minInt(7, lengths[1]))
		lengths[2] = maxInt(27, minInt(38, realLen-lengths[0]-lengths[1]-2))
		a, err := segment(src, lengths[0], base64URL)
		if err != nil {
			return "", err
		}
		b, err := segment(src, lengths[1], base64URL)
		if err != nil {
			return "", err
		}
		c, err := segment(src, lengths[2], base64URL)
		if err != nil {
			return "", err
		}
		out := a + "." + b + "." + c
		if len(out) > realLen {
			return "", errors.New("generated decoy exceeds real value length")
		}
		return out, nil
	case "digitalocean-pat":
		return honeyToken(src, "dop_v1_", realLen, hexAlphabet, 64, fixedInt(64))
	case "twilio-auth-token":
		return honeyToken(src, "SK", realLen, hexAlphabet, 32, fixedInt(32))
	case "sendgrid-key":
		if realLen < 69 {
			return "", errors.New("generated decoy exceeds real value length")
		}
		a, err := segment(src, 22, base64URL)
		if err != nil {
			return "", err
		}
		b, err := segment(src, 43, base64URL)
		if err != nil {
			return "", err
		}
		return "SG." + a + "." + b, nil
	case "huggingface-token":
		return honeyToken(src, "hf_", realLen, alnum, minInt(30, maxInt(1, realLen-3)), nil)
	case "npm-publish-token":
		return honeyToken(src, "npm_", realLen, alnum, 36, fixedInt(36))
	case "pypi-token":
		return honeyToken(src, "pypi-AgE", realLen, base64URL, 80, nil)
	case "gitlab-pat":
		return honeyToken(src, "glpat-", realLen, base64URL, 20, fixedInt(20))
	case "mailgun-api-key":
		return honeyToken(src, "key-", realLen, hexAlphabet, 32, fixedInt(32))
	case "linear-api-key":
		return honeyToken(src, "lin_api_", realLen, alnum, 40, fixedInt(40))
	case "notion-token":
		prefix := "secret_"
		if strings.HasPrefix(dummyReal, "ntn_") {
			prefix = "ntn_"
		}
		return honeyToken(src, prefix, realLen, alnum, minInt(43, maxInt(1, realLen-len(prefix))), nil)
	case "shopify-token":
		return honeyToken(src, "shpat_", realLen, hexAlphabet, 32, fixedInt(32))
	case "square-token":
		if strings.HasPrefix(dummyReal, "sq0atp-") {
			return honeyToken(src, "sq0atp-", realLen, base64URL, 22, fixedInt(22))
		}
		return honeyToken(src, "EAAA", realLen, base64URL, 60, nil)
	case "cloudflare-api-token":
		return honeyChars(src, base64URL, realLen)
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
	case "uk-nhs-number":
		return honeyDigits(src, len(strings.Join(strings.Fields(dummyReal), "")))
	case "us-ssn":
		a, err := sourcedInt(src, 799)
		if err != nil {
			return "", err
		}
		b, err := sourcedInt(src, 90)
		if err != nil {
			return "", err
		}
		c, err := sourcedInt(src, 9000)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d-%d-%d", 100+a, 10+b, 1000+c), nil
	case "uk-ni-number":
		a, err := sourcedInt(src, len(niFirst))
		if err != nil {
			return "", err
		}
		b, err := sourcedInt(src, len(niSecond))
		if err != nil {
			return "", err
		}
		nums, err := honeyDigits(src, 6)
		if err != nil {
			return "", err
		}
		c, err := sourcedInt(src, 4)
		if err != nil {
			return "", err
		}
		return string(niFirst[a]) + string(niSecond[b]) + nums + string("ABCD"[c]), nil
	case "phone-e164":
		noPlus := strings.TrimPrefix(dummyReal, "+")
		n := maxInt(8, minInt(15, len(noPlus)))
		first, err := sourcedInt(src, 9)
		if err != nil {
			return "", err
		}
		rest, err := honeyDigits(src, n-1)
		if err != nil {
			return "", err
		}
		out := fmt.Sprintf("+%d%s", 1+first, rest)
		if len(out) > realLen {
			return "", errors.New("generated decoy exceeds real value length")
		}
		return out, nil
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
