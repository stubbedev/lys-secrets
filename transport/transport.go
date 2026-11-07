// Package transport is the Secret Service's secret transports, the
// encryption both ends of a session agree on: plain, and the DH session
// over the 1024-bit MODP group with HKDF-SHA256 and AES-128-CBC.
package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// The algorithms OpenSession negotiates.
const (
	AlgPlain = "plain"
	AlgDH    = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

// Prime is the 1024-bit MODP group of RFC 2409 §6.2 (Oakley group 2),
// generator Generator, the group the spec names for its DH transport.
var Prime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF", 16)

// Generator is the group's generator.
var Generator = big.NewInt(2)

// PrimeLen is the prime's length in bytes, the shared secret's padded
// encoding.
const PrimeLen = 128

// Transport encrypts a secret for the other end and decrypts what it
// sends. Plain is the identity.
type Transport interface {
	Encode(secret []byte) (params, value []byte, err error)
	Decode(params, value []byte) ([]byte, error)
}

// Plain is the plain session.
type Plain struct{}

// Encode implements Transport.
func (Plain) Encode(secret []byte) ([]byte, []byte, error) {
	return []byte{}, bytes.Clone(secret), nil
}

// Decode implements Transport.
func (Plain) Decode(params, value []byte) ([]byte, error) {
	if len(params) != 0 {
		return nil, fmt.Errorf("a plain session's secret has %d bytes of parameters, want none", len(params))
	}
	return bytes.Clone(value), nil
}

// AES is the DH session: AES-128-CBC with PKCS#7 padding under the
// HKDF-SHA256 of the shared secret, a fresh IV per secret as its
// parameters.
type AES struct{ key []byte }

// NewAES derives the session from the shared secret padded to PrimeLen,
// with HKDF-SHA256, no salt and no info.
func NewAES(shared []byte) (AES, error) {
	key, err := hkdf.Key(sha256.New, shared, nil, "", aes.BlockSize)
	if err != nil {
		return AES{}, fmt.Errorf("HKDF: %w", err)
	}
	return AES{key: key}, nil
}

// Encode implements Transport.
func (a AES) Encode(secret []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("IV: %w", err)
	}
	pad := aes.BlockSize - len(secret)%aes.BlockSize
	buf := make([]byte, len(secret)+pad)
	copy(buf, secret)
	for i := len(secret); i < len(buf); i++ {
		buf[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	return iv, buf, nil
}

// Decode implements Transport.
func (a AES) Decode(params, value []byte) ([]byte, error) {
	if len(params) != aes.BlockSize {
		return nil, fmt.Errorf("the secret's IV is %d bytes, want %d", len(params), aes.BlockSize)
	}
	if len(value) == 0 || len(value)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("the secret's ciphertext is %d bytes, not a whole number of blocks", len(value))
	}
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	buf := bytes.Clone(value)
	cipher.NewCBCDecrypter(block, params).CryptBlocks(buf, buf)
	pad := int(buf[len(buf)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(buf) {
		clear(buf)
		return nil, errors.New("the secret's padding is invalid")
	}
	for _, b := range buf[len(buf)-pad:] {
		if int(b) != pad {
			clear(buf)
			return nil, errors.New("the secret's padding is invalid")
		}
	}
	return buf[:len(buf)-pad], nil
}
