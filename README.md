# deny-go

Go SDK for [deny.sh](https://deny.sh) — deniable encryption that lies for you.

Algorithm-compatible with the [TypeScript](https://www.npmjs.com/package/deny-sh) and [Python](https://pypi.org/project/deny-sh/) SDKs. Ciphertext produced by any SDK can be decrypted by any other.

## Install

```bash
go get github.com/deny-sh-crypto/deny-go
```

Requires Go 1.21+.

## Usage

```go
package main

import (
	"fmt"
	denysh "github.com/deny-sh-crypto/deny-go"
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

Derives an AES-256 key from two passwords and a salt using scrypt (N=16384, r=8, p=1).

## Algorithm

- **KDF**: scrypt (N=16384, r=8, p=1, keylen=32) on `SHA-256(pw1) || SHA-256(pw2)`
- **Cipher**: AES-256-CTR
- **Deniability**: XOR with control data, 4-byte LE length prefix inside encrypted zone
- **Format**: `salt(32) + iv(16) + AES-CTR(payload ⊕ control_data)`

## Tests

```bash
go test -v ./...
```

25 tests covering roundtrips, deniability, KAT vectors, unicode, edge cases.

## License

Apache License 2.0. See [LICENSE](LICENSE). Free for commercial and proprietary use. See [deny.sh/licensing](https://deny.sh/licensing).
