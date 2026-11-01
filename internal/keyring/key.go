package keyring

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)

const keyLen = chacha20poly1305.KeySize

// KDF is the Argon2id cost a collection's key is derived with.
type KDF struct {
	Time    uint32
	MemKiB  uint32
	Threads uint8
}

// DefaultKDF is RFC 9106's second recommended option: 3 passes over
// 64 MiB.
var DefaultKDF = KDF{Time: 3, MemKiB: 64 * 1024, Threads: 4}

// key is a collection key in its own anonymous mapping: off the Go heap,
// so the collector never copies it, locked against swap where the
// RLIMIT_MEMLOCK allows, excluded from core dumps, and zeroed on destroy.
type key struct{ page []byte }

// swapGuard locks key pages against swap and says once when it cannot:
// every key after the first fails for the same reason.
type swapGuard struct {
	mlock  func([]byte) error
	limit  func() (uint64, error)
	logf   func(format string, args ...any)
	warned sync.Once
}

var keyPages = swapGuard{mlock: unix.Mlock, limit: memlockLimit, logf: log.Printf}

func memlockLimit() (uint64, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return 0, fmt.Errorf("read RLIMIT_MEMLOCK: %w", err)
	}
	return lim.Cur, nil
}

func (g *swapGuard) pin(page []byte) {
	err := g.mlock(page)
	if err == nil {
		return
	}
	g.warned.Do(func() {
		limit := "unknown"
		if n, limErr := g.limit(); limErr == nil {
			limit = strconv.FormatUint(n, 10) + " bytes"
		}
		g.logf("keyring: collection keys may reach swap: mlock of a %d-byte key page failed: %v (RLIMIT_MEMLOCK %s; raise LimitMEMLOCK= for the unit, or use encrypted or no swap)", len(page), err, limit)
	})
}

func newKey() (*key, error) {
	page, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("keyring: map key memory: %w", err)
	}
	keyPages.pin(page)
	_ = unix.Madvise(page, unix.MADV_DONTDUMP)
	return &key{page: page}, nil
}

// deriveKey stretches password with salt under kdf. Argon2 hands back a
// heap slice; it is copied into the key's page and zeroed.
func deriveKey(password, salt []byte, kdf KDF) (*key, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	derived := argon2.IDKey(password, salt, kdf.Time, kdf.MemKiB, kdf.Threads, keyLen)
	copy(k.bytes(), derived)
	clear(derived)
	return k, nil
}

func (k *key) bytes() []byte { return k.page[:keyLen] }

func (k *key) destroy() {
	if k == nil || k.page == nil {
		return
	}
	clear(k.page)
	_ = unix.Munlock(k.page)
	_ = unix.Munmap(k.page)
	k.page = nil
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
