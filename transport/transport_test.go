package transport

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestAnAESSessionRoundTripsAndRefusesBadPadding(t *testing.T) {
	a, err := NewAES(bytes.Repeat([]byte{7}, PrimeLen))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"", "x", "exactly sixteen!", "a longer secret than one block"} {
		params, value, err := a.Encode([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.Decode(params, value)
		if err != nil || string(got) != secret {
			t.Fatalf("%q: %q %v", secret, got, err)
		}
	}
	if _, err := a.Decode(make([]byte, aes.BlockSize), make([]byte, aes.BlockSize)); err == nil {
		t.Fatal("a zero block decoded")
	}
	if _, err := (Plain{}).Decode([]byte{1}, []byte("x")); err == nil {
		t.Fatal("a plain secret with parameters decoded")
	}
}

func FuzzAESDecode(f *testing.F) {
	a := AES{key: make([]byte, aes.BlockSize)}
	f.Add(make([]byte, 16), make([]byte, 32))
	f.Fuzz(func(t *testing.T, params, value []byte) {
		_, _ = a.Decode(params, value)
	})
}
