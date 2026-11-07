package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/stubbedev/lys-secrets/transport"
)

// maxDHTries bounds the private keys negotiateDH draws; each is
// rejected with probability 1/256.
const maxDHTries = 64

// negotiateDH answers a client's public key: the server's public key to
// send back, and the session's transport. The shared secret is stretched
// with HKDF-SHA256 (no salt, no info) to an AES-128 key.
//
// Clients disagree on the secret's encoding: libsecret built on libgcrypt,
// gnome-keyring and python-secretstorage pad it to the prime's length,
// libsecret built on GnuTLS drops its leading zero bytes. The private key
// is drawn until the secret has no leading zero byte, where the two
// encodings are the same bytes, so every client derives this key.
func negotiateDH(peer []byte, random io.Reader) (public []byte, t transport.Transport, err error) {
	y := new(big.Int).SetBytes(peer)
	pMinus1 := new(big.Int).Sub(transport.Prime, big.NewInt(1))
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pMinus1) >= 0 {
		return nil, nil, errors.New("the client's DH public key is out of range")
	}
	var priv, k *big.Int
	for range maxDHTries {
		if priv, err = rand.Int(random, pMinus1); err != nil {
			return nil, nil, fmt.Errorf("DH private key: %w", err)
		}
		priv.Add(priv, big.NewInt(1))
		k = new(big.Int).Exp(y, priv, transport.Prime)
		if k.BitLen() > 8*(transport.PrimeLen-1) {
			break
		}
		k = nil
	}
	if k == nil {
		return nil, nil, fmt.Errorf("no DH private key in %d draws gives a full-length secret", maxDHTries)
	}
	public = new(big.Int).Exp(transport.Generator, priv, transport.Prime).Bytes()
	shared := k.FillBytes(make([]byte, transport.PrimeLen))
	defer clear(shared)
	session, err := transport.NewAES(shared)
	if err != nil {
		return nil, nil, err
	}
	return public, session, nil
}
