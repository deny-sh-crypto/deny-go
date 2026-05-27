# deny-go

Go SDK for [deny.sh](https://deny.sh), the deniability infrastructure. Same ciphertext, two passwords, two completely different plaintexts. When the bytes leak, what leaks is the decoy.

Part of the **Encrypt pillar**: Apache 2.0, zero copyleft, free for any use. Algorithm-compatible with the [TypeScript](https://www.npmjs.com/package/deny-sh), [Rust](https://crates.io/crates/deny-sh), and [Python](https://pypi.org/project/deny-sh/) SDKs. Ciphertext produced by any SDK can be decrypted by any other.

## Install

```bash
go get github.com/deny-sh-crypto/deny-go/v2
```

Requires Go 1.23+.

## Usage

```go
package main

import (
	"fmt"
	denysh "github.com/deny-sh-crypto/deny-go/v2"
)

func main() {
	// Encrypt (control data auto-generated when nil)
	ct, ctrl, _ := denysh.Encrypt([]byte("seed phrase"), "pw1", "pw2", nil)

	// Decrypt with real control data → real message
	msg, _ := denysh.Decrypt(ct, "pw1", "pw2", ctrl)
	fmt.Println(string(msg)) // "seed phrase"

	// Generate deniable control data → same ciphertext decrypts to decoy
	fakeCtrl, _ := denysh.GenerateDeniableControl(ct, "pw1", "pw2", []byte("decoy seed"))
	decoy, _ := denysh.Decrypt(ct, "pw1", "pw2", fakeCtrl)
	fmt.Println(string(decoy)) // "decoy seed"
}
```

### Multiple decoys from one ciphertext

There is no per-ciphertext cap on the number of decoys. Derive a fresh control file for each cover story, sized to fit within the original real plaintext envelope:

```go
// Encrypt a 64-byte real seed phrase so decoys have room
real := []byte("abandon ability able about above absent absorb abstract absurd ab")
ct, ctrl, _ := denysh.Encrypt(real, "pw1", "pw2", nil)

stories := [][]byte{
	[]byte("meeting moved to wednesday"),
	[]byte("taxi receipts october 2026"),
	[]byte("vegetable risotto recipe"),
}

for _, story := range stories {
	cover, _ := denysh.GenerateDeniableControl(ct, "pw1", "pw2", story)
	recovered, _ := denysh.Decrypt(ct, "pw1", "pw2", cover)
	if !bytes.Equal(recovered, story) {
		panic("decoy mismatch")
	}
}

// And the original real plaintext is still recoverable with the real control file
original, _ := denysh.Decrypt(ct, "pw1", "pw2", ctrl)
_ = original
```

The practical upper bound on plaintext length per decoy is the inner-payload envelope: ciphertext length minus 48-byte header minus 4-byte length prefix. Pad the real plaintext to your largest expected cover-story length at encrypt time so every decoy fits.

## API

### `Encrypt(plaintext []byte, password1, password2 string, controlData []byte) (ciphertext, control []byte, err error)`

Encrypts plaintext using dual passwords and a control file. If `controlData` is `nil`, random control data is generated automatically.

### `Decrypt(ciphertext []byte, password1, password2 string, controlData []byte) (plaintext []byte, err error)`

Decrypts ciphertext using dual passwords and the control data.

### `GenerateDeniableControl(ciphertext []byte, password1, password2 string, desiredPlaintext []byte) (controlData []byte, err error)`

Generates new control data that makes existing ciphertext decrypt to a different plaintext.

### `GenerateControlData(size int) []byte`

Generates cryptographically secure random control data.

### `DeriveKey(password1, password2 string, salt []byte) []byte`

Derives an AES-256 key from two passwords and a salt using Argon2id (t=3, m=65536 KiB, p=1).

## Algorithm

- **KDF**: Argon2id (t=3, m=65536 KiB, p=1, keylen=32) on `SHA-256(pw1) || SHA-256(pw2)`
- **Cipher**: AES-256-CTR
- **Deniability**: XOR with control data, 4-byte LE length prefix inside encrypted zone
- **Format**: `salt(32) + iv(16) + AES-CTR(payload ⊕ control_data)`

Cross-compatible: ciphertext from any SDK (TypeScript, Python, Rust, Go) can be decrypted by any other. Full wire format and KAT vectors: [deny.sh/sdks](https://deny.sh/sdks).

## Threat model

deny.sh defends against **passive ciphertext leak**: an adversary gets the encrypted artefact (lost laptop, cloud breach, prompt-injected agent) and tries to read it. The construction guarantees that whatever the adversary decrypts is indistinguishable from any other decryption.

It is **not** designed to resist an adaptive adversary who can compel you to perform multiple decryptions, demand additional passwords iteratively, or run forensic side-channel analysis on the host hardware. Full threat model: [deny.sh/threat-model](https://deny.sh/threat-model). Cryptographic argument: [deny.sh/whitepaper](https://deny.sh/whitepaper) §5.

The primitive is intentionally unauthenticated. Wrong passwords return garbage, not an error. If you need decryption to fail loudly on wrong inputs, add a caller-side integrity check (magic bytes + SHA-256 fingerprint) on the plaintext.

## Tests

```bash
go test -v ./...
```

26 tests covering roundtrips, deniability, KAT vectors, unicode, edge cases.

## License

Apache License 2.0. See [LICENSE](LICENSE). Free for commercial and proprietary use. See [deny.sh/licensing](https://deny.sh/licensing).

## Reporting vulnerabilities

Found a bug in the crypto or the SDK? Email security@deny.sh (PGP fingerprint and disclosure policy at [deny.sh/disclosure](https://deny.sh/disclosure)). Please give us a reasonable window before public disclosure.
