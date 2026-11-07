package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stubbedev/lys-secrets/vault"
)

type memKeychain struct {
	mu    sync.Mutex
	items map[string][]byte
	fail  error
	reads int
}

func newKeychain() *memKeychain { return &memKeychain{items: map[string][]byte{}} }

func keychainKey(attrs map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(attrs)) {
		b.WriteString(k + "=" + attrs[k] + "\x00")
	}
	return b.String()
}

func (k *memKeychain) Lookup(_ context.Context, attrs map[string]string) ([]byte, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return nil, false, k.fail
	}
	k.reads++
	v, ok := k.items[keychainKey(attrs)]
	return slices.Clone(v), ok, nil
}

func (k *memKeychain) Store(_ context.Context, _ string, attrs map[string]string, value []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return k.fail
	}
	k.items[keychainKey(attrs)] = slices.Clone(value)
	return nil
}

func (k *memKeychain) Delete(_ context.Context, attrs map[string]string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return k.fail
	}
	delete(k.items, keychainKey(attrs))
	return nil
}

func (k *memKeychain) only(t *testing.T) credential {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	values := slices.Collect(maps.Values(k.items))
	if len(values) != 1 {
		t.Fatalf("the keyring holds %d sessions, want 1", len(values))
	}
	c, err := parseCredential(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (k *memKeychain) empty() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.items) == 0
}

type home struct {
	dir  string
	keys *memKeychain
}

func newHome(t *testing.T) home { return home{dir: t.TempDir(), keys: newKeychain()} }

const (
	testAPIKeyID     = "user.api"
	testAPIKeySecret = "api-secret"
)

func apiKeyLogin(a *account) vault.APIKeyRequest {
	return vault.APIKeyRequest{Server: a.server(), Email: "test@bitwarden.com", Password: "asdfasdfasdf", ClientID: testAPIKeyID, Secret: testAPIKeySecret}
}

func (a *account) grantsSince(n int) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.grants[n:])
}

func (a *account) grantCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.grants)
}

func requireNoSecretOnDisk(t *testing.T, h home, secrets ...string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.dir, sessionFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(raw), s) {
			t.Errorf("the session file holds %q: %s", s, raw)
		}
	}
}

func TestARestartAsksOnlyForTheMasterPassword(t *testing.T) {
	a := newAccount(t)
	a.needTOTP = true
	h := newHome(t)
	s := openService(t, h)
	req := login(a)
	req.TwoFactor = &vault.TwoFactor{Provider: vault.TwoFactorAuthenticator, Code: "123456"}
	if err := s.Login(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	requireNoSecretOnDisk(t, h, a.refresh)

	before := a.grantCount()
	restarted := openService(t, h)
	if st := restarted.Status(); st.State != vault.StateLocked || st.Email != "test@bitwarden.com" {
		t.Fatalf("after a restart the status is %+v, want locked for the account", st)
	}
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); err != nil || restarted.Status().State != vault.StateUnlocked {
		t.Fatalf("unlock with the master password alone = %v, status %+v", err, restarted.Status())
	}
	if got := a.grantsSince(before); !slices.Equal(got, []string{"refresh_token"}) {
		t.Errorf("the unlock after a restart sent the grants %v, want the refresh alone", got)
	}
	if got := h.keys.only(t).RefreshToken; got != a.refresh {
		t.Errorf("the keyring keeps %q, want the rotated %q", got, a.refresh)
	}
	requireNoSecretOnDisk(t, h, a.refresh)
}

func TestAnAPIKeySessionSurvivesARestart(t *testing.T) {
	a := newAccount(t)
	h := newHome(t)
	s := openService(t, h)
	if err := s.LoginAPIKey(context.Background(), apiKeyLogin(a)); err != nil {
		t.Fatal(err)
	}
	if got := h.keys.only(t); got != (credential{ClientSecret: testAPIKeySecret}) {
		t.Errorf("the keyring keeps %+v, want the API key secret alone", got)
	}
	requireNoSecretOnDisk(t, h, testAPIKeySecret)

	before := a.grantCount()
	restarted := openService(t, h)
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); err != nil || restarted.Status().State != vault.StateUnlocked {
		t.Fatalf("unlock with the master password alone = %v, status %+v", err, restarted.Status())
	}
	if got := a.grantsSince(before); !slices.Equal(got, []string{"client_credentials"}) {
		t.Errorf("the unlock after a restart sent the grants %v, want the API key login alone", got)
	}
}

func TestARefusedAPIKeyLogsOut(t *testing.T) {
	a := newAccount(t)
	h := newHome(t)
	if err := openService(t, h).LoginAPIKey(context.Background(), apiKeyLogin(a)); err != nil {
		t.Fatal(err)
	}
	h.keys.mu.Lock()
	for k := range h.keys.items {
		h.keys.items[k] = []byte(`{"client_secret":"rotated-away"}`)
	}
	h.keys.mu.Unlock()
	restarted := openService(t, h)
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); !errors.Is(err, vault.ErrLoginRequired) {
		t.Errorf("unlock with a refused API key = %v, want ErrLoginRequired", err)
	}
	requireLoggedOut(t, restarted, h)
}

func TestAnUnreachableKeyringLeavesTheVaultLocked(t *testing.T) {
	a := newAccount(t)
	h := newHome(t)
	if err := openService(t, h).Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	down := errors.New("no Secret Service")
	h.keys.mu.Lock()
	h.keys.fail = down
	h.keys.mu.Unlock()
	restarted := openService(t, h)
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); !errors.Is(err, down) || errors.Is(err, vault.ErrLoginRequired) {
		t.Errorf("unlock without a keyring = %v, want its error and no logout", err)
	}
	if st := restarted.Status(); st.State != vault.StateLocked || st.Email != "test@bitwarden.com" {
		t.Errorf("status %+v, want still locked for the account", st)
	}
	h.keys.mu.Lock()
	h.keys.fail = nil
	h.keys.mu.Unlock()
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); err != nil {
		t.Errorf("unlock once the keyring answers = %v", err)
	}
}

func TestASessionTheKeyringDoesNotKeepLogsOut(t *testing.T) {
	a := newAccount(t)
	h := newHome(t)
	if err := openService(t, h).Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	h.keys.mu.Lock()
	clear(h.keys.items)
	h.keys.mu.Unlock()
	restarted := openService(t, h)
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); !errors.Is(err, vault.ErrLoginRequired) {
		t.Errorf("unlock = %v, want ErrLoginRequired", err)
	}
	requireLoggedOut(t, restarted, h)
}

func TestALoginTheKeyringCannotKeepDoesNotOpen(t *testing.T) {
	a := newAccount(t)
	h := newHome(t)
	h.keys.fail = errors.New("no Secret Service")
	s := openService(t, h)
	if err := s.Login(context.Background(), login(a)); !errors.Is(err, h.keys.fail) {
		t.Errorf("login = %v, want the keyring's error", err)
	}
	if st := s.Status(); st.State != vault.StateLoggedOut || !closed(s) {
		t.Errorf("status %+v, want logged out and closed", st)
	}
	if _, err := os.Stat(filepath.Join(h.dir, sessionFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the session file: %v, want none", err)
	}
}

func TestOpenDropsARefreshTokenAnOlderVersionSavedOnDisk(t *testing.T) {
	a := newAccount(t)
	h := newHome(t)
	saved := fmt.Sprintf(`{"Server":%q,"Email":"test@bitwarden.com","RefreshToken":"rt-plaintext","ClientID":"desktop"}`, a.server().String())
	if err := os.WriteFile(filepath.Join(h.dir, sessionFile), []byte(saved), privateFileMode); err != nil {
		t.Fatal(err)
	}
	s := openService(t, h)
	if st := s.Status(); st.State != vault.StateLocked || st.Email != "test@bitwarden.com" {
		t.Errorf("status %+v, want locked for the account", st)
	}
	requireNoSecretOnDisk(t, h, "rt-plaintext")
}
