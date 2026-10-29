package bitwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stubbedev/lys-secrets/vault"
)

// account serves the test@bitwarden.com account: prelogin, the token
// grants (checking the password hash, a second factor when asked, the
// refresh token), and a sync with one organization item.
type account struct {
	t          *testing.T
	mu         sync.Mutex
	srv        *httptest.Server
	wantHash   string
	needTOTP   bool
	refresh    string
	rejectRefr bool
	grants     []string
	itemName   string
}

func newAccount(t *testing.T) *account {
	t.Helper()
	a := &account{t: t, refresh: "rt-1", itemName: testOrgName}
	mk, err := deriveMasterKey("asdfasdfasdf", "test@bitwarden.com", Kdf{Type: KdfPBKDF2, Iterations: 600000})
	if err != nil {
		t.Fatal(err)
	}
	a.wantHash, _ = mk.serverHash("asdfasdfasdf")
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/accounts/prelogin/password", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"KdfSettings": map[string]any{"KdfType": 0, "Iterations": 600000}, "Salt": "test@bitwarden.com"})
	})
	mux.HandleFunc("/identity/connect/token", a.token)
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at-") {
			writeJSON(w, 401, map[string]any{"message": "unauthorized"})
			return
		}
		a.mu.Lock()
		name := a.itemName
		a.mu.Unlock()
		writeJSON(w, 200, map[string]any{
			"profile": map[string]any{
				"email": "test@bitwarden.com", "key": testUserKey, "privateKey": testPrivateKey,
				"organizations": []any{map[string]any{"id": testOrgID, "key": testOrgKey}},
			},
			"ciphers": []any{map[string]any{"id": "c1", "type": 2, "organizationId": testOrgID, "name": name}},
		})
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *account) server() vault.Server {
	s, err := vault.ParseServer(a.srv.URL)
	if err != nil {
		a.t.Fatal(err)
	}
	return s
}

func (a *account) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Error(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f := r.PostForm
	a.grants = append(a.grants, f.Get("grant_type"))
	switch f.Get("grant_type") {
	case "password":
		if f.Get("password") != a.wantHash {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "ErrorModel": map[string]any{"Message": "Username or password is incorrect."}})
			return
		}
		if a.needTOTP && f.Get("twoFactorToken") != "123456" {
			writeJSON(w, 400, map[string]any{"TwoFactorProviders2": map[string]any{"0": nil}})
			return
		}
	case "refresh_token":
		if a.rejectRefr || f.Get("refresh_token") != a.refresh {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
	}
	a.refresh += "+"
	writeJSON(w, 200, map[string]any{"access_token": "at-" + a.refresh, "refresh_token": a.refresh, "expires_in": 3600, "token_type": "Bearer"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// counted is a Service that counts its change announcements.
type counted struct {
	*Service
	changes int
}

// openService opens the service in dir, failing the test when it cannot.
func openService(t *testing.T, dir string) *counted {
	t.Helper()
	c := &counted{}
	s, err := Open(dir, "lys-secrets", func() { c.changes++ })
	if err != nil {
		t.Fatal(err)
	}
	c.Service = s
	return c
}

// listed is the open vault's listing, failing the test when it is not
// open.
func listed(t *testing.T, s *counted) []vault.Item {
	t.Helper()
	items, err := s.Items()
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// closed reports whether the vault refuses to list, as a vault that is
// not open does.
func closed(s *counted) bool {
	items, err := s.Items()
	return errors.Is(err, vault.ErrLocked) && items == nil
}

// opened logs in to a's account and replaces the vault's items with
// items, keeping the account's keys and master password.
func opened(t *testing.T, a *account, items ...Item) *counted {
	t.Helper()
	s := openService(t, t.TempDir())
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.vault = Vault{Items: items, byID: map[string]int{}}
	for i, it := range items {
		s.vault.byID[it.ID] = i
	}
	s.mu.Unlock()
	return s
}

func login(a *account) vault.LoginRequest {
	return vault.LoginRequest{Server: a.server(), Email: "test@bitwarden.com", Password: "asdfasdfasdf"}
}

// A fresh directory starts logged out with a private device id that
// survives a reopen.
func TestOpenRegistersADevice(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "lys-secrets", func() {})
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.State != vault.StateLoggedOut {
		t.Errorf("state = %v", st.State)
	}
	info, err := os.Stat(filepath.Join(dir, deviceFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("device file %v, %v", info, err)
	}
	again, err := Open(dir, "lys-secrets", func() {})
	if err != nil || again.device.ID != s.device.ID || len(s.device.ID) != 36 {
		t.Errorf("device id %q then %q", s.device.ID, again.device.ID)
	}
}

// A login opens the vault and saves only the session: server, email,
// refresh token, client id; never the password, a key or an item.
func TestLoginOpensTheVault(t *testing.T) {
	a := newAccount(t)
	dir := t.TempDir()
	s := openService(t, dir)
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.State != vault.StateUnlocked || st.Items != 1 || st.Err != nil || st.Email != "test@bitwarden.com" {
		t.Errorf("status = %+v", st)
	}
	if items := listed(t, s); len(items) != 1 || items[0].Name != "Default collection" {
		t.Errorf("items = %+v", items)
	}
	raw, err := os.ReadFile(filepath.Join(dir, sessionFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"asdfasdfasdf", "Default collection", testUserKey[:20], "at-"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the session file holds %q", secret)
		}
	}
	if !strings.Contains(string(raw), a.refresh) {
		t.Errorf("the session file lacks the refresh token: %s", raw)
	}
	if info, _ := os.Stat(filepath.Join(dir, sessionFile)); info.Mode().Perm() != 0o600 {
		t.Errorf("session file mode %v", info.Mode().Perm())
	}
}

// A wrong password is refused by the server and opens nothing; a second
// factor comes back as vault.TwoFactorRequiredError and the retry with the
// code opens the vault.
func TestLoginFailuresAndSecondFactor(t *testing.T) {
	a := newAccount(t)
	s := openService(t, t.TempDir())
	bad := login(a)
	bad.Password = "nope"
	if err := s.Login(context.Background(), bad); !errors.Is(err, vault.ErrInvalidCredentials) || s.Status().State != vault.StateLoggedOut || s.Status().Err == nil {
		t.Errorf("wrong password = %v, status %+v", err, s.Status())
	}
	a.needTOTP = true
	var tf *vault.TwoFactorRequiredError
	if err := s.Login(context.Background(), login(a)); !errors.As(err, &tf) || tf.Providers[0] != vault.TwoFactorAuthenticator {
		t.Fatalf("no code = %v", err)
	}
	req := login(a)
	req.TwoFactor = &vault.TwoFactor{Provider: vault.TwoFactorAuthenticator, Code: "123456"}
	if err := s.Login(context.Background(), req); err != nil || s.Status().State != vault.StateUnlocked || s.Status().Err != nil {
		t.Errorf("with the code = %v, status %+v", err, s.Status())
	}
}

// Lock wipes the keys and items and keeps the session; a restarted
// shell starts locked; unlocking refreshes the token (saving the
// rotated one), and a wrong master password leaves it locked.
func TestLockAndUnlock(t *testing.T) {
	a := newAccount(t)
	dir := t.TempDir()
	s := openService(t, dir)
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	kr := s.kr
	s.Lock()
	if s.Status().State != vault.StateLocked || !closed(s) || s.kr != nil || len(kr.Orgs) != 0 {
		t.Errorf("after Lock: status %+v, keyring %v", s.Status(), s.kr)
	}
	restarted := openService(t, dir)
	if restarted.Status().State != vault.StateLocked {
		t.Fatalf("restart = %+v", restarted.Status())
	}
	if err := restarted.Unlock(context.Background(), "wrong"); !errors.Is(err, vault.ErrWrongPassword) || restarted.Status().State != vault.StateLocked {
		t.Errorf("wrong password = %v, status %+v", err, restarted.Status())
	}
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); err != nil || restarted.Status().State != vault.StateUnlocked {
		t.Fatalf("unlock = %v, status %+v", err, restarted.Status())
	}
	sess, _ := loadSession(filepath.Join(dir, sessionFile))
	if sess.RefreshToken != a.refresh {
		t.Errorf("saved refresh token %q, want the rotated %q", sess.RefreshToken, a.refresh)
	}
}

// A revoked refresh token logs out: the session file goes and the error
// says to log in again.
func TestRevokedRefreshLogsOut(t *testing.T) {
	a := newAccount(t)
	dir := t.TempDir()
	s := openService(t, dir)
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	a.rejectRefr = true
	if err := s.Unlock(context.Background(), "asdfasdfasdf"); !errors.Is(err, vault.ErrLoginRequired) {
		t.Errorf("unlock = %v", err)
	}
	if s.Status().State != vault.StateLoggedOut {
		t.Errorf("state = %v", s.Status().State)
	}
	if _, err := os.Stat(filepath.Join(dir, sessionFile)); !os.IsNotExist(err) {
		t.Errorf("session file survived: %v", err)
	}
}

// Sync picks up a change while unlocked, refreshing an expired access
// token first; while locked it is an error.
func TestServiceSync(t *testing.T) {
	a := newAccount(t)
	s := openService(t, t.TempDir())
	clock := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	kr := s.kr
	a.mu.Lock()
	a.itemName = seal(t, kr.Orgs[testOrgID], []byte("Renamed"))
	a.mu.Unlock()
	clock = clock.Add(2 * time.Hour)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if items := listed(t, s); len(items) != 1 || items[0].Name != "Renamed" {
		t.Errorf("after sync = %+v", items)
	}
	if last := a.grants[len(a.grants)-1]; last != "refresh_token" {
		t.Errorf("an expired token was not refreshed: grants %v", a.grants)
	}
	s.Lock()
	if err := s.Sync(context.Background()); err == nil {
		t.Error("a locked vault synced")
	}
}

// Logout forgets the session.
func TestLogout(t *testing.T) {
	a := newAccount(t)
	dir := t.TempDir()
	s := openService(t, dir)
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(); err != nil {
		t.Fatal(err)
	}
	if s.Status().State != vault.StateLoggedOut || !closed(s) {
		t.Errorf("status %+v", s.Status())
	}
	if again := openService(t, dir); again.Status().State != vault.StateLoggedOut {
		t.Error("a reopened service still has the session")
	}
}

// An open vault locks once it has gone unused for the idle time, and a
// use restarts the clock; a locked vault has nothing to lock.
func TestLockIdle(t *testing.T) {
	a := newAccount(t)
	s := openService(t, t.TempDir())
	clock := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Minute)
	s.touch()
	clock = clock.Add(14 * time.Minute)
	if s.lockIdle(15*time.Minute) || s.Status().State != vault.StateUnlocked {
		t.Fatalf("locked 14 minutes after a touch: %+v", s.Status())
	}
	changes := s.changes
	clock = clock.Add(time.Minute)
	if !s.lockIdle(15*time.Minute) || s.Status().State != vault.StateLocked || !closed(s) {
		t.Fatalf("still open 15 minutes after a touch: %+v", s.Status())
	}
	if s.changes == changes {
		t.Error("an idle lock did not announce itself")
	}
	if s.lockIdle(0) {
		t.Error("a locked vault locked again")
	}
}

// The reprompt accepts the master password of the open account and
// refuses another; a locked vault verifies nothing.
func TestVerifyPassword(t *testing.T) {
	a := newAccount(t)
	s := openService(t, t.TempDir())
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyPassword("asdfasdfasdf"); err != nil {
		t.Errorf("the master password = %v", err)
	}
	if err := s.verifyPassword("asdfasdfasdg"); !errors.Is(err, vault.ErrWrongPassword) {
		t.Errorf("a wrong password = %v", err)
	}
	s.Lock()
	if err := s.verifyPassword("asdfasdfasdf"); err == nil {
		t.Error("a locked vault verified a password")
	}
}

// A field comes out of the open vault by item and field: a login's
// username and password, an identity's own username, a verification
// code with its expiry. A field the item does not give out, an unknown
// item and a locked vault are the contract's errors.
func TestField(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a,
		Item{ID: "mail", Type: vault.ItemLogin, Name: "Mail", Username: "ada", Password: "hunter2", TOTP: "JBSWY3DPEHPK3PXP"},
		Item{ID: "me", Type: vault.ItemIdentity, Name: "Me", Username: "login-name", Identity: Identity{Username: "ada.l", Email: "ada@example.com"}},
	)
	at := time.Unix(1_700_000_020, 0)
	s.now = func() time.Time { return at }
	for _, c := range []struct {
		id   string
		f    vault.Field
		want string
	}{
		{"mail", vault.FieldUsername, "ada"},
		{"mail", vault.FieldPassword, "hunter2"},
		{"me", vault.FieldUsername, "ada.l"},
		{"me", vault.FieldEmail, "ada@example.com"},
	} {
		if v, err := s.Field(c.id, c.f, ""); err != nil || v.Text != c.want || !v.Expires.IsZero() {
			t.Errorf("%s field %d = %+v, %v; want %q without expiry", c.id, c.f, v, err, c.want)
		}
	}
	totp, _ := ParseTOTP("JBSWY3DPEHPK3PXP")
	code, _ := totp.Code(at)
	if v, err := s.Field("mail", vault.FieldTOTP, ""); err != nil || v.Text != code || !v.Expires.Equal(at.Add(20*time.Second)) {
		t.Errorf("code = %+v, %v; want %s until %v", v, err, code, at.Add(20*time.Second))
	}
	if _, err := s.Field("mail", vault.FieldCardNumber, ""); !errors.Is(err, vault.ErrNoSuchField) {
		t.Errorf("a card number of a login = %v", err)
	}
	if _, err := s.Field("absent", vault.FieldPassword, ""); !errors.Is(err, vault.ErrNoSuchItem) {
		t.Errorf("an unknown item = %v", err)
	}
	s.Lock()
	if _, err := s.Field("mail", vault.FieldPassword, ""); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("a locked vault = %v", err)
	}
}

// An item behind the reprompt gives out its secrets only with the
// master password, and its username without; a copy restarts the idle
// clock.
func TestFieldReprompt(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a, Item{ID: "bank", Type: vault.ItemLogin, Name: "Bank", Username: "ada", Password: "s3cret", Reprompt: true})
	clock := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	if _, err := s.Field("bank", vault.FieldPassword, ""); !errors.Is(err, vault.ErrRepromptRequired) {
		t.Errorf("no master password = %v", err)
	}
	if _, err := s.Field("bank", vault.FieldPassword, "asdfasdfasdg"); !errors.Is(err, vault.ErrWrongPassword) {
		t.Errorf("a wrong master password = %v", err)
	}
	if v, err := s.Field("bank", vault.FieldUsername, ""); err != nil || v.Text != "ada" {
		t.Errorf("the username = %+v, %v", v, err)
	}
	clock = clock.Add(20 * time.Minute)
	if v, err := s.Field("bank", vault.FieldPassword, "asdfasdfasdf"); err != nil || v.Text != "s3cret" {
		t.Errorf("with the master password = %+v, %v", v, err)
	}
	clock = clock.Add(14 * time.Minute)
	if s.lockIdle(15 * time.Minute) {
		t.Error("the vault locked 14 minutes after a copy")
	}
}

// A listing shows what an item gives out, its primary field first, and
// no secret.
func TestItemsList(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a,
		Item{ID: "mail", Type: vault.ItemLogin, Name: "Mail", Username: "ada", Password: "hunter2", TOTP: "JBSWY3DPEHPK3PXP", URIs: []string{"https://mail.example.com"}},
		Item{ID: "visa", Type: vault.ItemCard, Name: "Visa", Card: Card{Brand: "Visa", Number: "4111", Code: "123"}},
		Item{ID: "note", Type: vault.ItemSecureNote, Name: "Note"},
	)
	items := listed(t, s)
	want := [][]vault.Field{
		{vault.FieldPassword, vault.FieldUsername, vault.FieldTOTP},
		{vault.FieldCardNumber, vault.FieldCardCode},
		nil,
	}
	for i, it := range items {
		if !slices.Equal(it.Fields, want[i]) {
			t.Errorf("%s offers %v, want %v", it.Name, it.Fields, want[i])
		}
	}
	if items[0].Username != "ada" || items[0].URIs[0] != "https://mail.example.com" || items[1].CardBrand != "Visa" {
		t.Errorf("listing = %+v", items)
	}
	if listedText := fmt.Sprintf("%+v", items); strings.Contains(listedText, "hunter2") || strings.Contains(listedText, "4111") || strings.Contains(listedText, "JBSW") {
		t.Errorf("the listing carries a secret: %s", listedText)
	}
}

// The network login comes from the configured folder of the open
// vault, its custom fields by name; an empty folder or a locked vault
// answers nothing.
func TestServiceNetworkLogin(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a, Item{
		ID: "home", Type: vault.ItemLogin, Folder: "Networks", Name: "Home", Username: "ann", Password: "hunter22",
		Fields: []Field{{Name: "pin", Value: "1234", Hidden: true}},
	})
	l, ok := s.NetworkLogin("Networks", "Home")
	if !ok || l.Username != "ann" || l.Password != "hunter22" || l.Fields["pin"] != "1234" {
		t.Fatalf("login = %+v %v", l, ok)
	}
	if _, ok := s.NetworkLogin("", "Home"); ok {
		t.Error("an empty folder answered")
	}
	s.Lock()
	if _, ok := s.NetworkLogin("Networks", "Home"); ok {
		t.Error("a locked vault answered")
	}
}
