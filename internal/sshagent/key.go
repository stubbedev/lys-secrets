package sshagent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"

	"github.com/stubbedev/lys-secrets/internal/lockedmem"
)

// privateKey is a decrypted private key in locked memory. An Ed25519 key
// signs straight from there; an RSA or ECDSA key is kept as PKCS #8 and
// parsed onto the Go heap for each signature, since the standard library
// signs only with keys of its own.
type privateKey struct {
	mem     *lockedmem.Buf
	ed25519 bool
}

// lockKey moves a parsed private key into locked memory and clears what of
// the parsed key it can reach.
func lockKey(raw any) (*privateKey, error) {
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		return lockKey(*k)
	case ed25519.PrivateKey:
		defer clear(k)
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("an Ed25519 key of %d bytes", len(k))
		}
		mem, err := lockedmem.Copy(k)
		if err != nil {
			return nil, err
		}
		return &privateKey{mem: mem, ed25519: true}, nil
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		defer wipe(k)
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("encode the key: %w", err)
		}
		defer clear(der)
		mem, err := lockedmem.Copy(der)
		if err != nil {
			return nil, err
		}
		return &privateKey{mem: mem}, nil
	default:
		return nil, fmt.Errorf("keys of type %T are not supported", raw)
	}
}

// sign signs data with the key; algorithm "" is the key's own.
func (k *privateKey) sign(data []byte, algorithm string) (*ssh.Signature, error) {
	if k.mem.Destroyed() {
		return nil, errors.New("the key was dropped")
	}
	if k.ed25519 {
		sig, err := signEd25519(k.mem.Bytes(), data)
		if err != nil {
			return nil, err
		}
		return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: sig}, nil
	}
	raw, err := x509.ParsePKCS8PrivateKey(k.mem.Bytes())
	if err != nil {
		return nil, fmt.Errorf("read the key: %w", err)
	}
	defer wipe(raw)
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("a signer for the key: %w", err)
	}
	if algorithm == "" {
		return signer.Sign(nil, data)
	}
	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("the key cannot sign with %s", algorithm)
	}
	return as.SignWithAlgorithm(nil, data, algorithm)
}

// signEd25519 is RFC 8032's Ed25519 signature of message under key, a seed
// and public key in locked memory. Every secret it derives stays in locked
// memory or on the stack: crypto/ed25519 would keep an expanded copy of the
// key on the heap, in a cache keyed by the key's address.
func signEd25519(key, message []byte) ([]byte, error) {
	seed, public := key[:ed25519.SeedSize], key[ed25519.SeedSize:]
	h := sha512.Sum512(seed)
	defer clear(h[:])
	var s, r, k, sum edwards25519.Scalar
	defer func() { s, r, sum = edwards25519.Scalar{}, edwards25519.Scalar{}, edwards25519.Scalar{} }()
	if _, err := s.SetBytesWithClamping(h[:32]); err != nil {
		return nil, fmt.Errorf("the Ed25519 scalar: %w", err)
	}
	nonceInput, err := lockedmem.New(32 + len(message))
	if err != nil {
		return nil, err
	}
	defer nonceInput.Destroy()
	copy(nonceInput.Bytes(), h[32:])
	copy(nonceInput.Bytes()[32:], message)
	nonce := sha512.Sum512(nonceInput.Bytes())
	defer clear(nonce[:])
	if _, err := r.SetUniformBytes(nonce[:]); err != nil {
		return nil, fmt.Errorf("the Ed25519 nonce: %w", err)
	}
	var commitment edwards25519.Point
	commitment.ScalarBaseMult(&r)
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig, commitment.Bytes())
	challenge := sha512.New()
	challenge.Write(sig[:32])
	challenge.Write(public)
	challenge.Write(message)
	if _, err := k.SetUniformBytes(challenge.Sum(make([]byte, 0, sha512.Size))); err != nil {
		return nil, fmt.Errorf("the Ed25519 challenge: %w", err)
	}
	sum.MultiplyAdd(&k, &s, &r)
	copy(sig[32:], sum.Bytes())
	return sig, nil
}

func (k *privateKey) destroy() {
	if k != nil {
		k.mem.Destroy()
	}
}

// wipe zeroes the private numbers of an RSA or ECDSA key the standard
// library parsed, which is as far as its copies can be reached.
func wipe(raw any) {
	zero := func(n *big.Int) {
		if n != nil {
			clear(n.Bits())
		}
	}
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		zero(k.D)
		for _, p := range k.Primes {
			zero(p)
		}
		zero(k.Precomputed.Dp)
		zero(k.Precomputed.Dq)
		zero(k.Precomputed.Qinv)
	case *ecdsa.PrivateKey:
		zero(k.D) //nolint:staticcheck // D is the only handle on the scalar this key was parsed into
	case ed25519.PrivateKey:
		clear(k)
	}
}
