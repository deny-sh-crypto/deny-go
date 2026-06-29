package denygo

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	base64Std   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	azureSecret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
	hexAlphabet = "0123456789abcdef"
	base58Alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	niFirst     = "ABCEGHJKLMNOPRSTWXYZ"
	niSecond    = "ABCEGHJKLMNPRSTWXYZ"
	mbiAlpha    = "ACDEFGHJKMNPQRTUVWXY"
	mbiAlnum    = "ACDEFGHJKMNPQRTUVWXY0123456789"
	vinChars    = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
)

var itinGroups = []string{
	"50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
	"60", "61", "62", "63", "64", "65", "70", "71", "72", "73",
	"74", "75", "76", "77", "78", "79", "80", "81", "82", "83",
	"84", "85", "86", "87", "88", "90", "91", "92", "94", "95",
	"96", "97", "98", "99",
}

var countryCodes = []string{"US", "GB", "DE", "FR", "ES", "IT", "AT", "NL", "SE", "IE", "IN"}

var mrzCountryCodes = []string{"USA", "GBR", "DEU", "FRA", "ESP", "ITA", "AUT", "NLD", "SWE", "IRL", "IND"}

var emailLocals = []string{"alex", "admin", "billing", "ops", "support", "nora", "sam"}

var emailDomains = []string{"acme", "northstar", "ledger", "fieldops", "exampleco"}

var emailTLDs = []string{"com", "net", "io", "co"}

var einPrefixes = []string{
	"01", "02", "03", "04", "05", "06", "10", "11", "12", "13", "14", "15", "16",
	"20", "21", "22", "23", "24", "25", "26", "27", "30", "31", "32", "33", "34",
	"35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47",
	"48", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61",
	"62", "63", "64", "65", "66", "67", "68", "71", "72", "73", "74", "75", "76",
	"77", "80", "81", "82", "83", "84", "85", "86", "87", "88", "90", "91", "92",
	"93", "94", "95", "98", "99",
}

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
	"gcp-api-key":          39,
	"azure-client-secret":  40,
	"azure-storage-key":    88,
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
	"us-npi":               10,
	"us-dea-number":        9,
	"us-medicare-mbi":      11,
	"us-ndc":               13,
	"lei":                  20,
	"isin":                 12,
	"cusip":                9,
	"us-ein":               10,
	"duns":                 9,
	"us-routing-number":    9,
	"us-bank-account":      12,
	"bic-swift":            11,
	"us-itin":              11,
	"passport-mrz":         89,
	"us-passport":          9,
	"uscis-number":         9,
	"aadhaar":              12,
	"eidas-id":             15,
	"email-address":        22,
	"ipv4-address":         15,
	"ipv6-address":         39,
	"mac-address":          17,
	"imei":                 15,
	"vin":                  17,
	"uuid":                 36,
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
	"gcp-api-key":          {},
	"azure-client-secret":  {},
	"azure-storage-key":    {},
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
	"us-npi":               {},
	"us-dea-number":        {},
	"us-medicare-mbi":      {},
	"us-ndc":               {},
	"lei":                  {},
	"isin":                 {},
	"cusip":                {},
	"us-ein":               {},
	"duns":                 {},
	"us-routing-number":    {},
	"us-bank-account":      {},
	"bic-swift":            {},
	"us-itin":              {},
	"passport-mrz":         {},
	"us-passport":          {},
	"uscis-number":         {},
	"aadhaar":              {},
	"eidas-id":             {},
	"email-address":        {},
	"ipv4-address":         {},
	"ipv6-address":         {},
	"mac-address":          {},
	"imei":                 {},
	"vin":                  {},
	"uuid":                 {},
	"phone-e164":           {},
}

// EncryptHoneyResult is the high-level Honey Mode encrypt output.
type EncryptHoneyResult struct {
	Ciphertext []byte
	RealCtrl   []byte
	Band       int
	HoneyType  string
}

// DecryptHoneyResult is the high-level Honey Mode decrypt output (PUBLIC).
//
// It deliberately exposes ONLY Value. The real-vs-honey branch is a perfect
// distinguisher and MUST NOT be surfaced to SDK consumers: a caller who logged
// or returned it would hand an attacker exactly the oracle Honey Mode exists to
// deny. The branch is available only via the internal decryptHoneyWithBranch
// helper used by tests.
type DecryptHoneyResult struct {
	Value string
}

// decryptHoneyInternalResult carries branch telemetry. NOT exported; tests only.
type decryptHoneyInternalResult struct {
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
	case "generic", "freeform-secret", "jwt-token", "postgres-uri", "mongodb-uri", "gcp-service-account-key":
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
	case "lei":
		return strings.Repeat("0", maxInt(20, lenHint))
	case "isin":
		return "US" + strings.Repeat("0", maxInt(10, lenHint-2))
	case "cusip":
		return strings.Repeat("0", maxInt(9, lenHint))
	case "us-ein":
		return "12-0000000"
	case "duns":
		return strings.Repeat("0", maxInt(9, lenHint))
	case "us-routing-number":
		return strings.Repeat("0", maxInt(9, lenHint))
	case "us-bank-account":
		return strings.Repeat("0", maxInt(8, lenHint))
	case "bic-swift":
		return "DEMOUS00XXX"
	case "us-itin":
		return "900-70-0000"
	case "passport-mrz":
		return padEnd("P<UTOERIKSSON<<ANNA<MARIA", 44, '<') + "\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"
	case "us-passport":
		return "A12345678"
	case "uscis-number":
		return "123456789"
	case "aadhaar":
		return "234567890124"
	case "eidas-id":
		return "ES/AT/02635542Y"
	case "email-address":
		return "alex@exampleco.com"
	case "ipv4-address":
		return "192.168.100.200"
	case "ipv6-address":
		return "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	case "mac-address":
		return "02:00:5e:10:00:00"
	case "imei":
		return "490154203237518"
	case "vin":
		return "1HGCM82633A004352"
	case "uuid":
		return "550e8400-e29b-41d4-a716-446655440000"
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

// ed25519PKCS8Prefix is the fixed PKCS#8 DER prefix for an Ed25519 private key
// (see TS reference ED25519_PKCS8_PREFIX_HEX). Any 32 bytes appended form a
// structurally valid PKCS#8 Ed25519 key that openssl/Node parse, so the decoy
// is no longer distinguishable from a real PEM by DER-validity (review #5).
var ed25519PKCS8Prefix = []byte{
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
}

func randomPrivateKeyPem(src *SeededByteSource, _ string) (string, error) {
	der := make([]byte, 0, 48)
	der = append(der, ed25519PKCS8Prefix...)
	der = append(der, src.Bytes(32)...)
	body := base64.StdEncoding.EncodeToString(der) // 48 bytes -> 64 chars, no padding
	return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----", nil
}

// nhsCheckDigit returns the NHS mod-11 check digit for a 9-digit body, or -1
// when the checksum resolves to 10 (an invalid NHS number), matching the TS
// nhsCheckDigit.
func nhsCheckDigit(body9 string) int {
	if len(body9) != 9 {
		return -1
	}
	sum := 0
	for i := 0; i < 9; i++ {
		c := body9[i]
		if c < '0' || c > '9' {
			return -1
		}
		sum += int(c-'0') * (10 - i)
	}
	check := 11 - (sum % 11)
	if check == 11 {
		check = 0
	}
	if check == 10 {
		return -1
	}
	return check
}

func deaCheckDigit(body6 string) int {
	d := make([]int, len(body6))
	for i := range body6 {
		d[i] = int(body6[i] - '0')
	}
	return (d[0] + d[2] + d[4] + 2*(d[1]+d[3]+d[5])) % 10
}

func alphaNumToNumeric(value string) string {
	var out strings.Builder
	for _, ch := range strings.ToUpper(value) {
		switch {
		case ch >= '0' && ch <= '9':
			out.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			out.WriteString(fmt.Sprintf("%d", ch-55))
		}
	}
	return out.String()
}

func mod97Numeric(numeric string) int {
	remainder := 0
	for i := 0; i < len(numeric); i++ {
		remainder = (remainder*10 + int(numeric[i]-'0')) % 97
	}
	return remainder
}

func leiCheckDigits(body18 string) string {
	check := 98 - mod97Numeric(alphaNumToNumeric(strings.ToUpper(body18)+"00"))
	return fmt.Sprintf("%02d", check)
}

func isinCheckDigit(body11 string) int {
	return luhnCheckDigit(alphaNumToNumeric(body11))
}

func cusipCharValue(ch byte) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'A' && ch <= 'Z':
		return int(ch - 55)
	case ch == '*':
		return 36
	case ch == '@':
		return 37
	case ch == '#':
		return 38
	default:
		return 0
	}
}

func cusipCheckDigit(body8 string) int {
	body := strings.ToUpper(body8)
	sum := 0
	for i := 0; i < len(body); i++ {
		weighted := cusipCharValue(body[i])
		if i%2 == 1 {
			weighted *= 2
		}
		sum += weighted/10 + weighted%10
	}
	return (10 - (sum % 10)) % 10
}

func abaRoutingCheckDigit(body8 string) int {
	weights := []int{3, 7, 1, 3, 7, 1, 3, 7}
	sum := 0
	for i := 0; i < len(body8); i++ {
		sum += int(body8[i]-'0') * weights[i]
	}
	return (10 - (sum % 10)) % 10
}

func mrzCharValue(ch byte) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'A' && ch <= 'Z':
		return int(ch - 55)
	default:
		return 0
	}
}

func mrzCheckDigit(field string) int {
	weights := []int{7, 3, 1}
	sum := 0
	for i := 0; i < len(field); i++ {
		sum += mrzCharValue(field[i]) * weights[i%3]
	}
	return sum % 10
}

var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

var verhoeffInv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

func verhoeffCheckDigit(body string) int {
	c := 0
	for i := 0; i < len(body); i++ {
		digit := int(body[len(body)-1-i] - '0')
		c = verhoeffD[c][verhoeffP[(i+1)%8][digit]]
	}
	return verhoeffInv[c]
}

func vinTranslit(ch byte) int {
	switch ch {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return int(ch - '0')
	case 'A', 'J':
		return 1
	case 'B', 'K', 'S':
		return 2
	case 'C', 'L', 'T':
		return 3
	case 'D', 'M', 'U':
		return 4
	case 'E', 'N', 'V':
		return 5
	case 'F', 'W':
		return 6
	case 'G', 'P', 'X':
		return 7
	case 'H', 'Y':
		return 8
	case 'R', 'Z':
		return 9
	default:
		return 0
	}
}

func vinCheckDigit(vin17 string) byte {
	weights := []int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < len(vin17); i++ {
		sum += vinTranslit(vin17[i]) * weights[i]
	}
	rem := sum % 11
	if rem == 10 {
		return 'X'
	}
	return byte('0' + rem)
}

func padEnd(value string, length int, fill byte) string {
	if len(value) >= length {
		return value[:length]
	}
	return value + strings.Repeat(string(fill), length-len(value))
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

func randomPassportMRZ(src *SeededByteSource, realLen int) (string, error) {
	if _, err := boundedLen(realLen, 0, 89, fixedInt(89)); err != nil {
		return "", err
	}
	issuerIdx, err := sourcedInt(src, len(mrzCountryCodes))
	if err != nil {
		return "", err
	}
	issuer := mrzCountryCodes[issuerIdx]
	first, err := honeyChars(src, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 7)
	if err != nil {
		return "", err
	}
	last, err := honeyChars(src, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6)
	if err != nil {
		return "", err
	}
	line1 := padEnd("P<"+issuer+first+"<<"+last, 44, '<')
	passportNumber, err := honeyChars(src, alnumUpper, 9)
	if err != nil {
		return "", err
	}
	year, err := sourcedInt(src, 50)
	if err != nil {
		return "", err
	}
	month, err := sourcedInt(src, 12)
	if err != nil {
		return "", err
	}
	day, err := sourcedInt(src, 28)
	if err != nil {
		return "", err
	}
	birth := fmt.Sprintf("%d%02d%02d", 40+year, 1+month, 1+day)
	sexIdx, err := sourcedInt(src, 3)
	if err != nil {
		return "", err
	}
	sex := "MF<"[sexIdx]
	expYear, err := sourcedInt(src, 20)
	if err != nil {
		return "", err
	}
	expMonth, err := sourcedInt(src, 12)
	if err != nil {
		return "", err
	}
	expDay, err := sourcedInt(src, 28)
	if err != nil {
		return "", err
	}
	expiry := fmt.Sprintf("%d%02d%02d", 26+expYear, 1+expMonth, 1+expDay)
	personal, err := honeyChars(src, alnumUpper+"<", 14)
	if err != nil {
		return "", err
	}
	docCheck := mrzCheckDigit(passportNumber)
	birthCheck := mrzCheckDigit(birth)
	expiryCheck := mrzCheckDigit(expiry)
	personalCheck := mrzCheckDigit(personal)
	composite := fmt.Sprintf("%s%d%s%d%s%d%s%d", passportNumber, docCheck, birth, birthCheck, expiry, expiryCheck, personal, personalCheck)
	line2 := fmt.Sprintf("%s%d%s%s%d%c%s%d%s%d%d", passportNumber, docCheck, issuer, birth, birthCheck, sex, expiry, expiryCheck, personal, personalCheck, mrzCheckDigit(composite))
	return line1 + "\n" + line2, nil
}

func randomEmailAddress(src *SeededByteSource, realLen int) (string, error) {
	locals := make([]string, 0, len(emailLocals))
	for _, local := range emailLocals {
		if len(local)+1+2+1+2 <= realLen {
			locals = append(locals, local)
		}
	}
	local := "a"
	if len(locals) > 0 {
		idx, err := sourcedInt(src, len(locals))
		if err != nil {
			return "", err
		}
		local = locals[idx]
	}
	domains := make([]string, 0, len(emailDomains))
	for _, domain := range emailDomains {
		if len(local)+1+len(domain)+1+2 <= realLen {
			domains = append(domains, domain)
		}
	}
	domain := "b"
	if len(domains) > 0 {
		idx, err := sourcedInt(src, len(domains))
		if err != nil {
			return "", err
		}
		domain = domains[idx]
	}
	tlds := make([]string, 0, len(emailTLDs))
	for _, tld := range emailTLDs {
		if len(local)+1+len(domain)+1+len(tld) <= realLen {
			tlds = append(tlds, tld)
		}
	}
	if len(tlds) == 0 {
		return "", errors.New("generated decoy exceeds real value length")
	}
	idx, err := sourcedInt(src, len(tlds))
	if err != nil {
		return "", err
	}
	return local + "@" + domain + "." + tlds[idx], nil
}

func randomIPv6Address(src *SeededByteSource, realLen int) (string, error) {
	if _, err := boundedLen(realLen, 0, 39, fixedInt(39)); err != nil {
		return "", err
	}
	parts := make([]string, 8)
	for i := range parts {
		part, err := honeyChars(src, hexAlphabet, 4)
		if err != nil {
			return "", err
		}
		parts[i] = part
	}
	return strings.Join(parts, ":"), nil
}

func randomMacAddress(src *SeededByteSource, realLen int) (string, error) {
	if _, err := boundedLen(realLen, 0, 17, fixedInt(17)); err != nil {
		return "", err
	}
	octets := src.Bytes(6)
	octets[0] = (octets[0] | 0x02) & 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]), nil
}

func randomVIN(src *SeededByteSource, realLen int) (string, error) {
	if _, err := boundedLen(realLen, 0, 17, fixedInt(17)); err != nil {
		return "", err
	}
	vin := make([]byte, 17)
	for i := range vin {
		idx, err := sourcedInt(src, len(vinChars))
		if err != nil {
			return "", err
		}
		vin[i] = vinChars[idx]
	}
	vin[8] = '0'
	vin[8] = vinCheckDigit(string(vin))
	return string(vin), nil
}

func randomUUIDV4(src *SeededByteSource, realLen int) (string, error) {
	if _, err := boundedLen(realLen, 0, 36, fixedInt(36)); err != nil {
		return "", err
	}
	raw := src.Bytes(16)
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexValue := fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
	return hexValue[:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:], nil
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
	case "gcp-api-key":
		return honeyToken(src, "AIza", realLen, base64URL, 35, fixedInt(35))
	case "azure-client-secret":
		if realLen < 34 {
			return "", errors.New("generated decoy exceeds real value length")
		}
		csLen := realLen
		if csLen > 44 {
			csLen = 44
		}
		head, err := honeyChars(src, alnum, 4)
		if err != nil {
			return "", err
		}
		tail, err := honeyChars(src, azureSecret, csLen-5)
		if err != nil {
			return "", err
		}
		return head + "~" + tail, nil
	case "azure-storage-key":
		if realLen < 88 {
			return "", errors.New("generated decoy exceeds real value length")
		}
		body, err := honeyChars(src, base64Std, 86)
		if err != nil {
			return "", err
		}
		return body + "==", nil
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
		// Emit a 9-digit body plus its mod-11 check digit so the honey/decoy NHS
		// number passes the same checksum a real one does (review #7). Redraw
		// deterministically from the same stream on the rare mod-11 == 10 case.
		for i := 0; i < 64; i++ {
			body, err := honeyDigits(src, 9)
			if err != nil {
				return "", err
			}
			if check := nhsCheckDigit(body); check >= 0 {
				return fmt.Sprintf("%s%d", body, check), nil
			}
		}
		return "", errors.New("could not generate valid NHS check digit")
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
	case "us-npi":
		body, err := honeyDigits(src, 9)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s%d", body, luhnCheckDigit("80840"+body)), nil
	case "us-dea-number":
		prefix, err := honeyChars(src, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2)
		if err != nil {
			return "", err
		}
		body, err := honeyDigits(src, 6)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s%s%d", prefix, body, deaCheckDigit(body)), nil
	case "us-medicare-mbi":
		first, err := sourcedInt(src, 9)
		if err != nil {
			return "", err
		}
		a, err := honeyChars(src, mbiAlpha, 1)
		if err != nil {
			return "", err
		}
		b, err := honeyChars(src, mbiAlnum, 1)
		if err != nil {
			return "", err
		}
		c, err := honeyDigits(src, 1)
		if err != nil {
			return "", err
		}
		d, err := honeyChars(src, mbiAlpha, 1)
		if err != nil {
			return "", err
		}
		e, err := honeyChars(src, mbiAlnum, 1)
		if err != nil {
			return "", err
		}
		f, err := honeyDigits(src, 1)
		if err != nil {
			return "", err
		}
		g, err := honeyChars(src, mbiAlpha, 2)
		if err != nil {
			return "", err
		}
		h, err := honeyDigits(src, 2)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d%s%s%s%s%s%s%s%s", 1+first, a, b, c, d, e, f, g, h), nil
	case "us-ndc":
		a, err := honeyDigits(src, 5)
		if err != nil {
			return "", err
		}
		b, err := honeyDigits(src, 4)
		if err != nil {
			return "", err
		}
		c, err := honeyDigits(src, 2)
		if err != nil {
			return "", err
		}
		return a + "-" + b + "-" + c, nil
	case "lei":
		if _, err := boundedLen(realLen, 0, 20, fixedInt(20)); err != nil {
			return "", err
		}
		body, err := honeyChars(src, alnumUpper, 18)
		if err != nil {
			return "", err
		}
		return body + leiCheckDigits(body), nil
	case "isin":
		if _, err := boundedLen(realLen, 0, 12, fixedInt(12)); err != nil {
			return "", err
		}
		country, err := honeyChars(src, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2)
		if err != nil {
			return "", err
		}
		rest, err := honeyChars(src, alnumUpper, 9)
		if err != nil {
			return "", err
		}
		body := country + rest
		return fmt.Sprintf("%s%d", body, isinCheckDigit(body)), nil
	case "cusip":
		if _, err := boundedLen(realLen, 0, 9, fixedInt(9)); err != nil {
			return "", err
		}
		body, err := honeyChars(src, alnumUpper+"*@#", 8)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s%d", body, cusipCheckDigit(body)), nil
	case "us-ein":
		if _, err := boundedLen(realLen, 0, 10, fixedInt(10)); err != nil {
			return "", err
		}
		idx, err := sourcedInt(src, len(einPrefixes))
		if err != nil {
			return "", err
		}
		body, err := honeyDigits(src, 7)
		if err != nil {
			return "", err
		}
		return einPrefixes[idx] + "-" + body, nil
	case "duns":
		if _, err := boundedLen(realLen, 0, 9, fixedInt(9)); err != nil {
			return "", err
		}
		return honeyDigits(src, 9)
	case "us-routing-number":
		if _, err := boundedLen(realLen, 0, 9, fixedInt(9)); err != nil {
			return "", err
		}
		body, err := honeyDigits(src, 8)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s%d", body, abaRoutingCheckDigit(body)), nil
	case "us-bank-account":
		n := maxInt(8, minInt(12, realLen))
		if _, err := boundedLen(realLen, 0, 8, fixedInt(n)); err != nil {
			return "", err
		}
		return honeyDigits(src, n)
	case "bic-swift":
		if _, err := boundedLen(realLen, 0, 11, fixedInt(11)); err != nil {
			return "", err
		}
		a, err := honeyChars(src, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4)
		if err != nil {
			return "", err
		}
		b, err := honeyChars(src, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2)
		if err != nil {
			return "", err
		}
		c, err := honeyChars(src, alnumUpper, 2)
		if err != nil {
			return "", err
		}
		d, err := honeyChars(src, alnumUpper, 3)
		if err != nil {
			return "", err
		}
		return a + b + c + d, nil
	case "us-itin":
		if _, err := boundedLen(realLen, 0, 11, fixedInt(11)); err != nil {
			return "", err
		}
		prefix, err := honeyDigits(src, 2)
		if err != nil {
			return "", err
		}
		idx, err := sourcedInt(src, len(itinGroups))
		if err != nil {
			return "", err
		}
		tail, err := honeyDigits(src, 4)
		if err != nil {
			return "", err
		}
		return "9" + prefix + "-" + itinGroups[idx] + "-" + tail, nil
	case "passport-mrz":
		return randomPassportMRZ(src, realLen)
	case "us-passport":
		if _, err := boundedLen(realLen, 0, 9, fixedInt(9)); err != nil {
			return "", err
		}
		return honeyChars(src, alnumUpper, 9)
	case "uscis-number":
		if _, err := boundedLen(realLen, 0, 9, fixedInt(9)); err != nil {
			return "", err
		}
		return honeyDigits(src, 9)
	case "aadhaar":
		if _, err := boundedLen(realLen, 0, 12, fixedInt(12)); err != nil {
			return "", err
		}
		first, err := sourcedInt(src, 8)
		if err != nil {
			return "", err
		}
		rest, err := honeyDigits(src, 10)
		if err != nil {
			return "", err
		}
		body := fmt.Sprintf("%d%s", 2+first, rest)
		return fmt.Sprintf("%s%d", body, verhoeffCheckDigit(body)), nil
	case "eidas-id":
		bodyLen := maxInt(1, minInt(20, realLen-6))
		if _, err := boundedLen(realLen, 6, 1, fixedInt(bodyLen)); err != nil {
			return "", err
		}
		c1, err := sourcedInt(src, len(countryCodes))
		if err != nil {
			return "", err
		}
		c2, err := sourcedInt(src, len(countryCodes))
		if err != nil {
			return "", err
		}
		body, err := honeyChars(src, alnumUpper, bodyLen)
		if err != nil {
			return "", err
		}
		return countryCodes[c1] + "/" + countryCodes[c2] + "/" + body, nil
	case "email-address":
		return randomEmailAddress(src, realLen)
	case "ipv4-address":
		a, err := sourcedInt(src, 256)
		if err != nil {
			return "", err
		}
		b, err := sourcedInt(src, 256)
		if err != nil {
			return "", err
		}
		c, err := sourcedInt(src, 256)
		if err != nil {
			return "", err
		}
		d, err := sourcedInt(src, 256)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d), nil
	case "ipv6-address":
		return randomIPv6Address(src, realLen)
	case "mac-address":
		return randomMacAddress(src, realLen)
	case "imei":
		if _, err := boundedLen(realLen, 0, 15, fixedInt(15)); err != nil {
			return "", err
		}
		first, err := sourcedInt(src, 6)
		if err != nil {
			return "", err
		}
		rest, err := honeyDigits(src, 13)
		if err != nil {
			return "", err
		}
		body := fmt.Sprintf("%d%s", 3+first, rest)
		return fmt.Sprintf("%s%d", body, luhnCheckDigit(body)), nil
	case "vin":
		return randomVIN(src, realLen)
	case "uuid":
		return randomUUIDV4(src, realLen)
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
	res, err := decryptHoneyWithBranch(ciphertext, controlData, password1, password2, honeyType, band)
	if err != nil {
		return DecryptHoneyResult{}, err
	}
	return DecryptHoneyResult{Value: res.Value}, nil
}

// decryptHoneyWithBranch is the internal honey decrypt that retains branch
// telemetry. NOT exported from the package surface; tests/telemetry only.
func decryptHoneyWithBranch(ciphertext, controlData []byte, password1, password2, honeyType string, band int) (decryptHoneyInternalResult, error) {
	if !IsHoneyEligible(honeyType) {
		return decryptHoneyInternalResult{}, fmt.Errorf("Honey Mode is not supported for unstructured type %q", honeyType)
	}

	recovered, err := decryptToPayload(ciphertext, password1, password2, controlData, band)
	if err != nil {
		return decryptHoneyInternalResult{}, err
	}
	if recovered.wellFormed {
		return decryptHoneyInternalResult{Value: string(recovered.plaintext), Branch: "real"}, nil
	}

	// Length-oracle fix: band-match the honey fake to the real ciphertext band via
	// realLengthHint, derived identically to the TS reference. Canonical length that
	// already lands in this band keeps KAT output byte-identical (-1 == no hint path
	// equivalent); otherwise size to the band.
	realLengthHint := -1
	if defaultHint, err := defaultLengthForHoneyType(honeyType); err == nil {
		if BucketedPayloadLength(defaultHint+LengthPrefix) == len(recovered.payload) {
			realLengthHint = defaultHint
		} else {
			realLengthHint = len(recovered.payload) - LengthPrefix
			if realLengthHint < 0 {
				realLengthHint = 0
			}
		}
	}
	fake, err := GenerateHoneyDecoy(honeyType, recovered.payload, recovered.salt, realLengthHint)
	if err != nil {
		return decryptHoneyInternalResult{}, err
	}
	return decryptHoneyInternalResult{Value: fake, Branch: "honey"}, nil
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
