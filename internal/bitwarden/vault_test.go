package bitwarden

import (
	"bytes"
	"crypto/aes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/stubbedev/lys-secrets/vault"
)

func seal(t *testing.T, key SymmetricKey, plain []byte) string {
	t.Helper()
	e, err := key.encryptIV(plain, bytes.Repeat([]byte{7}, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	return e.String()
}

func testKey(fill byte) SymmetricKey {
	k, _ := symmetricKeyFrom(bytes.Repeat([]byte{fill}, 64))
	return k
}

// Items open under the user key, an organization's key, or their own
// item key; deleted items are left out; favorites sort first, then by
// name; folder names resolve.
func TestDecryptVault(t *testing.T) {
	user, org, item := testKey(1), testKey(2), testKey(3)
	kr := &Keyring{User: user, Orgs: map[string]SymmetricKey{"o1": org}}
	s := func(k SymmetricKey, v string) string { return seal(t, k, []byte(v)) }
	deleted := "2026-01-01"
	sync := SyncResponse{
		Folders: []SyncFolder{{ID: "f1", Name: s(user, "Work")}},
		Ciphers: []SyncCipher{
			{ID: "c1", Type: vault.ItemLogin, FolderID: "f1", Name: s(user, "zeta mail"), Login: &SyncLogin{Username: s(user, "ada"), Password: s(user, "hunter2"), Totp: s(user, "JBSWY3DPEHPK3PXP"), Uris: []struct{ URI string }{{URI: s(user, "https://mail.example.com")}}}},
			{ID: "c2", Type: vault.ItemLogin, OrganizationID: "o1", Favorite: true, Name: s(org, "Shared VPN"), Login: &SyncLogin{Password: s(org, "s3cret")}},
			{ID: "c3", Type: vault.ItemSecureNote, Key: s(user, string(bytes.Repeat([]byte{3}, 64))), Name: s(item, "alpha note"), Notes: s(item, "body")},
			{ID: "c4", Type: vault.ItemLogin, DeletedDate: &deleted, Name: s(user, "gone")},
			{ID: "c5", Type: vault.ItemCard, Name: s(user, "Visa"), Card: &SyncCard{Number: s(user, "4111111111111111"), Code: s(user, "123")}, Fields: []SyncField{{Name: s(user, "pin"), Value: s(user, "0000"), Type: 1}}},
		},
	}
	v := DecryptVault(kr, sync)
	var names []string
	for _, it := range v.Items {
		names = append(names, it.Name)
		if it.Undecryptable {
			t.Errorf("%s is undecryptable", it.Name)
		}
	}
	if want := []string{"Shared VPN", "alpha note", "Visa", "zeta mail"}; !slices.Equal(names, want) {
		t.Errorf("items = %v, want %v (favorite first, then by name, trash left out)", names, want)
	}
	mail := v.Items[3]
	if mail.Username != "ada" || mail.Password != "hunter2" || mail.TOTP != "JBSWY3DPEHPK3PXP" || mail.Folder != "Work" || len(mail.URIs) != 1 {
		t.Errorf("login = %+v", mail)
	}
	if v.Items[1].Notes != "body" {
		t.Errorf("item-key note = %+v", v.Items[1])
	}
	if card := v.Items[2]; card.Card.Number != "4111111111111111" || card.Card.Code != "123" || len(card.Fields) != 1 || !card.Fields[0].Hidden || card.Fields[0].Value != "0000" {
		t.Errorf("card = %+v", card)
	}
	v.Wipe()
	if len(v.Items) != 0 || len(v.Folders) != 0 {
		t.Error("Wipe kept plaintext")
	}
}

// A field under the wrong key, or an item of an organization whose key
// is missing, marks the item undecryptable and keeps the rest of the
// sync.
func TestUndecryptableItems(t *testing.T) {
	user, other := testKey(1), testKey(9)
	kr := &Keyring{User: user, Orgs: map[string]SymmetricKey{}}
	v := DecryptVault(kr, SyncResponse{Ciphers: []SyncCipher{
		{ID: "ok", Type: vault.ItemLogin, Name: seal(t, user, []byte("fine")), Login: &SyncLogin{Password: seal(t, other, []byte("x"))}},
		{ID: "orphan", Type: vault.ItemLogin, OrganizationID: "missing", Name: seal(t, user, []byte("n"))},
		{ID: "garbled", Type: vault.ItemLogin, Name: "9.what"},
	}})
	if len(v.Items) != 3 {
		t.Fatalf("items = %d, want all three kept", len(v.Items))
	}
	for _, it := range v.Items {
		if !it.Undecryptable {
			t.Errorf("%s decrypted", it.ID)
		}
	}
	for _, it := range v.Items {
		if it.ID == "ok" && (it.Name != "fine" || it.Password != "") {
			t.Errorf("partly decryptable item = %+v", it)
		}
	}
}

func TestNetworkLogin(t *testing.T) {
	home := Item{ID: "1", Type: vault.ItemLogin, Folder: "Networks", Name: "Home Wi-Fi", Password: "hunter22"}
	items := []Item{
		home,
		{ID: "2", Type: vault.ItemLogin, Folder: "Personal", Name: "Office"},
		{ID: "3", Type: vault.ItemSecureNote, Folder: "Networks", Name: "Office"},
		{ID: "4", Type: vault.ItemLogin, Folder: "Networks", Name: "Twice"},
		{ID: "5", Type: vault.ItemLogin, Folder: "Networks", Name: "Twice"},
		{ID: "6", Type: vault.ItemLogin, Folder: "Networks", Name: "Guarded", Reprompt: true},
		{ID: "7", Type: vault.ItemLogin, Folder: "Networks", Name: "Broken", Undecryptable: true},
	}
	if got, ok := networkLogin(items, "Networks", "Home Wi-Fi"); !ok || got.ID != "1" {
		t.Errorf("the one login named like the connection: %+v %v", got, ok)
	}
	for _, name := range []string{"home wi-fi", "Office", "Twice", "Guarded", "Broken", "Absent"} {
		if got, ok := networkLogin(items, "Networks", name); ok {
			t.Errorf("%q answered with %+v: not the one exact, unprotected login in the folder", name, got)
		}
	}
	if _, ok := networkLogin(items, "Personal", "Home Wi-Fi"); ok {
		t.Error("a login outside the folder answered")
	}
}

func TestURIChecksumMatchesBitwarden(t *testing.T) {
	if got := uriChecksum("https://test.com"); got != "OWk2vQvwYD1nhLZdA+ltrpBWbDa2JmHyjUEWxRZSS8w=" {
		t.Errorf("checksum = %s", got)
	}
	if got := uriChecksum("https://example.com"); got != "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=" {
		t.Errorf("checksum = %s", got)
	}
}

func TestEncryptLoginRoundTrip(t *testing.T) {
	user := testKey(1)
	kr := &Keyring{User: user}
	l := vault.NewLogin{Folder: "Networks", Name: "Home", Username: "ann", Password: "hunter22", URIs: []string{"nm://home", "https://router.lan"}}
	req, err := encryptLogin(user, "f1", l)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"Home", "ann", "hunter22", "nm://home"} {
		if strings.Contains(string(raw), plain) {
			t.Errorf("the request carries %q in the clear: %s", plain, raw)
		}
	}
	var wire SyncCipher
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire.ID = "c1"
	it := decryptCipher(kr, wire, map[string]string{"f1": "Networks"})
	if it.Undecryptable || it.Type != vault.ItemLogin || it.Name != "Home" || it.Folder != "Networks" || it.Username != "ann" || it.Password != "hunter22" || !slices.Equal(it.URIs, l.URIs) {
		t.Errorf("decrypted = %+v", it)
	}
	var uris struct {
		Login struct{ URIs []uriRequest }
	}
	if err := json.Unmarshal(raw, &uris); err != nil {
		t.Fatal(err)
	}
	for i, u := range uris.Login.URIs {
		if sum, err := user.DecryptString(u.URIChecksum); err != nil || sum != uriChecksum(l.URIs[i]) {
			t.Errorf("URI %d checksum = %q, %v", i, sum, err)
		}
	}
	bare, err := encryptLogin(user, "", vault.NewLogin{Name: "Bare"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(bare)
	if strings.Contains(string(raw), "folderId") || strings.Contains(string(raw), "username") || strings.Contains(string(raw), "password") {
		t.Errorf("empty values went out: %s", raw)
	}
}

func TestEncryptedLengthsMatchTheContractsLimits(t *testing.T) {
	for _, c := range []struct {
		limit, fits int
	}{{1000, 687}, {5000, 3695}, {10000, 7439}} {
		for n, want := range map[int]bool{c.fits: true, c.fits + 1: false} {
			s, err := testKey(1).EncryptString(strings.Repeat("x", n))
			if err != nil {
				t.Fatal(err)
			}
			if got := len(s) <= c.limit; got != want {
				t.Errorf("%d bytes encrypt to %d characters; within %d = %v, want %v", n, len(s), c.limit, got, want)
			}
		}
	}
	long := vault.NewLogin{Name: strings.Repeat("n", 687), Username: strings.Repeat("u", 687), Password: strings.Repeat("p", 3695), URIs: []string{strings.Repeat("u", 7439)}}
	if err := long.Validate(); err != nil {
		t.Errorf("the longest login is refused: %v", err)
	}
}

func TestFindLoginMatching(t *testing.T) {
	items := []Item{
		{ID: "a", Type: vault.ItemLogin, Name: "Home", Folder: "Networks"},
		{ID: "b", Type: vault.ItemLogin, Name: "Home"},
		{ID: "c", Type: vault.ItemCard, Name: "Mail", Folder: "Networks"},
		{ID: "d", Type: vault.ItemLogin, Name: "home", Folder: "Networks"},
	}
	if it, ok, err := findLogin(items, "Home", vault.InFolder("Networks")); err != nil || !ok || it.ID != "a" {
		t.Errorf("scoped = %+v %v %v", it, ok, err)
	}
	if it, ok, err := findLogin(items, "Home", vault.InFolder("")); err != nil || !ok || it.ID != "b" {
		t.Errorf("no folder = %+v %v %v", it, ok, err)
	}
	if _, ok, err := findLogin(items, "Home", vault.AnyFolder()); !errors.Is(err, vault.ErrAmbiguous) || ok {
		t.Errorf("two matches = %v %v", ok, err)
	}
	if _, ok, err := findLogin(items, "Mail", vault.AnyFolder()); err != nil || ok {
		t.Errorf("a card = %v %v", ok, err)
	}
}

func TestVaultPutAndFolderID(t *testing.T) {
	v := Vault{Folders: map[string]string{"f1": "Work", "f2": "Dup", "f3": "Dup"}}
	v.put(Item{ID: "z", Name: "zeta"})
	v.put(Item{ID: "a", Name: "alpha"})
	v.put(Item{ID: "z", Name: "Zulu"})
	if len(v.Items) != 2 || v.Items[0].ID != "a" || v.Items[1].Name != "Zulu" {
		t.Errorf("items = %+v", v.Items)
	}
	if it, ok := v.Item("z"); !ok || it.Name != "Zulu" {
		t.Errorf("by id = %+v %v", it, ok)
	}
	for name, want := range map[string]error{"": nil, "Work": nil, "Dup": vault.ErrAmbiguous, "None": vault.ErrNoSuchFolder} {
		if _, err := v.folderID(name); !errors.Is(err, want) {
			t.Errorf("folder %q = %v, want %v", name, err, want)
		}
	}
}
