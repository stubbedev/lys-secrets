package bitwarden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	posted     []map[string]any
	postStatus int
	sends      []map[string]any
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
	mux.HandleFunc("POST /api/ciphers", a.createCipher)
	mux.HandleFunc("POST /api/sends", a.createSend)
	mux.HandleFunc("DELETE /api/sends/{id}", a.deleteSend)
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
			"sends":   a.sends,
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

func (a *account) createCipher(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at-") {
		writeJSON(w, 401, map[string]any{"message": "unauthorized"})
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.t.Error(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.postStatus != 0 {
		writeJSON(w, a.postStatus, map[string]any{"message": "The field Name is invalid."})
		return
	}
	a.posted = append(a.posted, body)
	body["id"] = fmt.Sprintf("new-%d", len(a.posted))
	writeJSON(w, 200, body)
}

func (a *account) createSend(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.t.Error(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.postStatus != 0 {
		writeJSON(w, a.postStatus, map[string]any{"message": "You cannot have a Send with a deletion date that far into the future."})
		return
	}
	body["id"] = fmt.Sprintf("s%d", len(a.sends)+1)
	body["accessId"] = fmt.Sprintf("acc-%d", len(a.sends)+1)
	body["accessCount"] = 0
	a.sends = append(a.sends, body)
	writeJSON(w, 200, body)
}

func (a *account) deleteSend(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, sd := range a.sends {
		if sd["id"] == r.PathValue("id") {
			a.sends = slices.Delete(a.sends, i, i+1)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	writeJSON(w, 404, map[string]any{"message": "Resource not found."})
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

func TestCreateLogin(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a, Item{ID: "old", Type: vault.ItemLogin, Folder: "Networks", Name: "Office"})
	s.mu.Lock()
	s.vault.Folders = map[string]string{"f1": "Networks"}
	s.mu.Unlock()
	changes := s.changes
	l := vault.NewLogin{Folder: "Networks", Name: "Home", Username: "ann", Password: "hunter22", URIs: []string{"nm://home"}}
	id, err := s.CreateLogin(context.Background(), l)
	if err != nil || id != "new-1" {
		t.Fatalf("CreateLogin = %q, %v", id, err)
	}
	if s.changes == changes || s.Status().Items != 2 {
		t.Errorf("no change announced: %d changes, status %+v", s.changes-changes, s.Status())
	}
	it, ok, err := s.FindLogin("Home", vault.InFolder("Networks"))
	if err != nil || !ok || it.ID != "new-1" || it.Username != "ann" || !slices.Equal(it.URIs, l.URIs) {
		t.Errorf("found = %+v %v %v", it, ok, err)
	}
	if v, err := s.Field("new-1", vault.FieldPassword, ""); err != nil || v.Text != "hunter22" {
		t.Errorf("password = %+v, %v", v, err)
	}
	a.mu.Lock()
	posted := a.posted[0]
	a.mu.Unlock()
	kr, err := Unlock(UnlockInput{Password: "asdfasdfasdf", Email: "test@bitwarden.com", Kdf: Kdf{Type: KdfPBKDF2, Iterations: 600000}, UserKey: testUserKey})
	if err != nil {
		t.Fatal(err)
	}
	name, err := kr.User.DecryptString(posted["name"].(string))
	if err != nil || name != "Home" || posted["folderId"] != "f1" || posted["type"] != float64(1) {
		t.Errorf("posted %v: name %q, %v", posted, name, err)
	}
	pw, err := kr.User.DecryptString(posted["login"].(map[string]any)["password"].(string))
	if err != nil || pw != "hunter22" {
		t.Errorf("posted password opens to %q, %v", pw, err)
	}
}

func TestCreateLoginRefusals(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a, Item{ID: "old", Type: vault.ItemLogin, Folder: "Networks", Name: "Home"})
	s.mu.Lock()
	s.vault.Folders = map[string]string{"f1": "Networks", "f2": "Twice", "f3": "Twice"}
	s.mu.Unlock()
	ctx := context.Background()
	for _, c := range []struct {
		l    vault.NewLogin
		want error
	}{
		{vault.NewLogin{Folder: "Networks", Name: "Home", Password: "hunter22"}, vault.ErrItemExists},
		{vault.NewLogin{Folder: "Absent", Name: "New", Password: "hunter22"}, vault.ErrNoSuchFolder},
		{vault.NewLogin{Folder: "Twice", Name: "New", Password: "hunter22"}, vault.ErrAmbiguous},
		{vault.NewLogin{Name: " ", Password: "hunter22"}, vault.ErrInvalidInput},
	} {
		if _, err := s.CreateLogin(ctx, c.l); !errors.Is(err, c.want) || strings.Contains(err.Error(), "hunter22") {
			t.Errorf("%+v = %v, want %v", c.l, err, c.want)
		}
	}
	a.mu.Lock()
	a.postStatus = 400
	a.mu.Unlock()
	var se *vault.ServerError
	if _, err := s.CreateLogin(ctx, vault.NewLogin{Name: "New", Password: "hunter22"}); !errors.As(err, &se) || se.Status != 400 {
		t.Errorf("a refusing server = %v", err)
	}
	a.mu.Lock()
	posted := len(a.posted)
	a.mu.Unlock()
	if posted != 0 || len(listed(t, s)) != 1 {
		t.Errorf("a refused login reached the server or the vault: %d posted, %+v", posted, listed(t, s))
	}
	s.Lock()
	if _, err := s.CreateLogin(ctx, vault.NewLogin{Name: "New"}); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("a locked vault = %v", err)
	}
	if _, _, err := s.FindLogin("Home", vault.AnyFolder()); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("find in a locked vault = %v", err)
	}
}

func TestSendsLifecycle(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	ctx := context.Background()
	if sends, err := s.Sends(); err != nil || len(sends) != 0 {
		t.Fatalf("sends = %+v, %v", sends, err)
	}
	deletion := clock.Add(7 * 24 * time.Hour).Truncate(time.Second)
	changes := s.changes
	created, err := s.CreateTextSend(ctx, vault.NewTextSend{Name: "Wifi", Text: "hunter22", Deletion: deletion, MaxAccessCount: 2, Password: "pw"})
	if err != nil || created.ID != "s1" {
		t.Fatalf("created = %+v, %v", created, err)
	}
	prefix := a.srv.URL + "/#/send/acc-1/"
	if !strings.HasPrefix(created.URL, prefix) {
		t.Fatalf("URL = %s, want under %s", created.URL, prefix)
	}
	material, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(created.URL, prefix))
	if err != nil || len(material) != sendKeyLen {
		t.Fatalf("URL key = %v, %v", material, err)
	}
	a.mu.Lock()
	posted := a.sends[0]
	a.mu.Unlock()
	key, err := deriveSendKey(material)
	if err != nil {
		t.Fatal(err)
	}
	if text, err := key.DecryptString(posted["text"].(map[string]any)["text"].(string)); err != nil || text != "hunter22" {
		t.Errorf("the recipient's view of the text = %q, %v", text, err)
	}
	if h, _ := sendPasswordHash("pw", material); posted["password"] != h {
		t.Errorf("password hash = %v, want %s", posted["password"], h)
	}
	sends, err := s.Sends()
	if err != nil || len(sends) != 1 || sends[0].Name != "Wifi" || !sends[0].HasPassword || sends[0].MaxAccessCount != 2 || !sends[0].Deletion.Equal(deletion) || s.changes == changes {
		t.Errorf("sends = %+v, %v, %d changes", sends, err, s.changes-changes)
	}
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if sends, _ := s.Sends(); len(sends) != 1 || sends[0].Name != "Wifi" || sends[0].Undecryptable {
		t.Errorf("synced sends = %+v", sends)
	}
	if err := s.DeleteSend(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if sends, _ := s.Sends(); len(sends) != 0 {
		t.Errorf("sends after delete = %+v", sends)
	}
	if err := s.DeleteSend(ctx, created.ID); !errors.Is(err, vault.ErrNoSuchSend) {
		t.Errorf("delete twice = %v", err)
	}
}

func TestSendRefusals(t *testing.T) {
	a := newAccount(t)
	s := opened(t, a)
	ctx := context.Background()
	deletion := time.Now().Add(24 * time.Hour)
	if _, err := s.CreateTextSend(ctx, vault.NewTextSend{Name: "Wifi", Text: "hunter22", Deletion: time.Now()}); !errors.Is(err, vault.ErrInvalidInput) || strings.Contains(err.Error(), "hunter22") {
		t.Errorf("an expired Send = %v", err)
	}
	a.mu.Lock()
	a.postStatus = 400
	a.mu.Unlock()
	var se *vault.ServerError
	if _, err := s.CreateTextSend(ctx, vault.NewTextSend{Name: "Wifi", Text: "hunter22", Deletion: deletion}); !errors.As(err, &se) || se.Status != 400 || strings.Contains(err.Error(), "hunter22") {
		t.Errorf("a refusing server = %v", err)
	}
	if sends, _ := s.Sends(); len(sends) != 0 {
		t.Errorf("a refused Send was listed: %+v", sends)
	}
	s.Lock()
	if _, err := s.Sends(); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("list locked = %v", err)
	}
	if _, err := s.CreateTextSend(ctx, vault.NewTextSend{Name: "Wifi", Text: "t", Deletion: deletion}); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("create locked = %v", err)
	}
	if err := s.DeleteSend(ctx, "s1"); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("delete locked = %v", err)
	}
}

func TestASessionForAPlainHTTPServerStartsLoggedOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sessionFile)
	saved := `{"Server":"http://vault.example.com","Email":"ada@example.com","RefreshToken":"rt","ClientID":"desktop"}`
	if err := os.WriteFile(path, []byte(saved), privateFileMode); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, "test", func() {})
	if err != nil {
		t.Fatalf("Open = %v, want a vault that starts", err)
	}
	st := s.Status()
	if st.State != vault.StateLoggedOut || !errors.Is(st.Err, vault.ErrInsecureServer) {
		t.Errorf("status = %+v, want logged out with ErrInsecureServer", st)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the session file: %v, want it gone", err)
	}
	if s.session() != nil {
		t.Error("the refused session is still held")
	}
}
