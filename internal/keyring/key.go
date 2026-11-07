package keyring

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/stubbedev/lys-secrets/internal/lockedmem"
)

const keyLen = chacha20poly1305.KeySize

// KDF is the Argon2id cost a collection's key is derived with.
type KDF struct {
	Time    uint32
	MemKiB  uint32
	Threads uint8
}

// Stretch turns a password into key material. It is slow on purpose, so it runs
// outside whatever lock a caller of this package holds; Argon2id is what every
// real key uses.
type Stretch func(password, salt []byte, kdf KDF) []byte

// Argon2id is the Stretch of every real key.
func Argon2id(password, salt []byte, kdf KDF) []byte {
	return argon2.IDKey(password, salt, kdf.Time, kdf.MemKiB, kdf.Threads, keyLen)
}

// DefaultKDF is RFC 9106's second recommended option: 3 passes over
// 64 MiB.
var DefaultKDF = KDF{Time: 3, MemKiB: 64 * 1024, Threads: 4}

// key is a collection key in locked memory, off the Go heap.
type key struct{ mem *lockedmem.Buf }

// deriveKey stretches password with salt under kdf. Stretching hands back a
// heap slice; it is copied into the key's locked memory and zeroed.
func deriveKey(password, salt []byte, kdf KDF, stretch Stretch) (*key, error) {
	derived := stretch(password, salt, kdf)
	defer clear(derived)
	mem, err := lockedmem.Copy(derived)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return &key{mem: mem}, nil
}

func (k *key) bytes() []byte { return k.mem.Bytes() }

func (k *key) destroy() {
	if k == nil {
		return
	}
	k.mem.Destroy()
}

func (k *key) aead() cipher.AEAD {
	a, err := chacha20poly1305.NewX(k.bytes())
	if err != nil {
		panic(fmt.Sprintf("keyring: a %d-byte key is rejected: %v", keyLen, err))
	}
	return a
}

// seal encrypts plaintext under k with a fresh nonce, bound to ad: the
// nonce, then the ciphertext and tag.
func (k *key) seal(plaintext, ad []byte) []byte {
	a := k.aead()
	out := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(out); err != nil {
		panic(fmt.Sprintf("keyring: no randomness for a nonce: %v", err))
	}
	return a.Seal(out, out, plaintext, ad)
}

// errOpen is a seal that does not open under the key: the wrong
// password, or tampered data.
var errOpen = errors.New("authentication failed")

func (k *key) open(sealed, ad []byte) ([]byte, error) {
	a := k.aead()
	if len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, fmt.Errorf("sealed data of %d bytes is shorter than its nonce and tag", len(sealed))
	}
	plain, err := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], ad)
	if err != nil {
		return nil, errOpen
	}
	return plain, nil
}
