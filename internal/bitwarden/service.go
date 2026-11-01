package bitwarden

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/stubbedev/lys-lib/atomicfile"

	"github.com/stubbedev/lys-secrets/vault"
)

// session is what survives a restart: the server, the account, the
// refresh token and the client id it was issued to. No key material and
// no vault data; the KDF comes from a fresh prelogin at every unlock.
type session struct {
	Server       vault.Server
	Email        string
	RefreshToken string
	ClientID     string
}

const (
	sessionFile     = "session.json"
	deviceFile      = "device-id"
	privateFileMode = 0o600
	privateDirMode  = 0o700
	refreshMargin   = time.Minute
)

// Service owns the vault: the session, the keys while unlocked, and the
// decrypted items. Operations run one at a time; no lock is held across
// a network call except the operation lock that serializes them.
type Service struct {
	dir       string
	now       func() time.Time
	newClient func(vault.Server, Device) *Client
	device    Device

	op sync.Mutex

	mu        sync.Mutex
	sess      *session
	access    string
	accessExp time.Time
	kr        *Keyring
	vault     Vault
	gate      passwordGate
	lastUse   time.Time
	status    vault.Status
	// changed runs after every status or vault change, outside the
	// locks.
	changed func()
}

// Open loads the session in dir (created 0700), registering a device id
// on first use: an account there starts locked, none logged out.
// changed runs after every status or vault change.
func Open(dir, deviceName string, changed func()) (*Service, error) {
	if err := os.MkdirAll(dir, privateDirMode); err != nil {
		return nil, fmt.Errorf("bitwarden: state directory %s: %w", dir, err)
	}
	id, err := deviceID(filepath.Join(dir, deviceFile))
	if err != nil {
		return nil, err
	}
	s := &Service{dir: dir, now: time.Now, newClient: NewClient, device: Device{ID: id, Name: deviceName}, changed: changed}
	sess, err := loadSession(filepath.Join(dir, sessionFile))
	if errors.Is(err, vault.ErrInsecureServer) {
		return s.forgetInsecureSession(err)
	}
	if err != nil {
		return nil, err
	}
	if sess != nil {
		s.sess = sess
		s.status = vault.Status{State: vault.StateLocked, Email: sess.Email}
	}
	return s, nil
}

// forgetInsecureSession drops a session saved for a server that is now
// refused: its refresh token will not be sent there again, and a vault
// that cannot start must not take the Secret Service down with it. The
// account starts logged out, with err as its status.
func (s *Service) forgetInsecureSession(err error) (*Service, error) {
	log.Printf("bitwarden: logged out: %v", err)
	if rmErr := os.Remove(filepath.Join(s.dir, sessionFile)); rmErr != nil {
		return nil, fmt.Errorf("bitwarden: remove the session of a refused server: %w", rmErr)
	}
	s.status = vault.Status{State: vault.StateLoggedOut, Err: err}
	return s, nil
}

// deviceID reads the device id at path, minting and saving a random
// UUID the first time.
func deviceID(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the client's own state file
	if err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("bitwarden: device id %s: %w", path, err)
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", fmt.Errorf("bitwarden: device id: %w", err)
	}
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	if err := atomicfile.WriteFile(path, []byte(id+"\n"), privateFileMode); err != nil {
		return "", fmt.Errorf("bitwarden: save the device id: %w", err)
	}
	return id, nil
}

func loadSession(path string) (*session, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the client's own state file
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bitwarden: session %s: %w", path, err)
	}
	var s session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("bitwarden: session %s: %w", path, err)
	}
	return &s, nil
}

func (s *Service) saveSession(sess *session) error {
	b, err := json.Marshal(sess) //nolint:gosec // the refresh token is the session; it is written 0600 and is all that persists
	if err != nil {
		return fmt.Errorf("bitwarden: session: %w", err)
	}
	if err := atomicfile.WriteFile(filepath.Join(s.dir, sessionFile), b, privateFileMode); err != nil {
		return fmt.Errorf("bitwarden: save the session: %w", err)
	}
	return nil
}

// Status is the latest status.
func (s *Service) Status() vault.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// session is the current session.
func (s *Service) session() *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}

// Items lists the open vault, favorites first then by name.
func (s *Service) Items() ([]vault.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr == nil {
		return nil, vault.ErrLocked
	}
	out := make([]vault.Item, len(s.vault.Items))
	for i, it := range s.vault.Items {
		out[i] = it.summary()
	}
	return out, nil
}

// Field is item id's field f, a verification code the one current now.
// A secret of an item behind the master password reprompt needs the
// master password; otherwise password is ignored. It counts as use.
func (s *Service) Field(id string, f vault.Field, password string) (vault.Value, error) {
	s.mu.Lock()
	it, ok := s.vault.Item(id)
	open := s.kr != nil
	s.mu.Unlock()
	switch {
	case !open:
		return vault.Value{}, vault.ErrLocked
	case !ok:
		return vault.Value{}, fmt.Errorf("%w: %s", vault.ErrNoSuchItem, id)
	}
	if it.Reprompt && f.Secret() {
		if password == "" {
			return vault.Value{}, fmt.Errorf("%w: %s", vault.ErrRepromptRequired, it.Name)
		}
		if err := s.verifyPassword(password); err != nil {
			return vault.Value{}, err
		}
	}
	v, err := it.value(f, s.now())
	if err != nil {
		return vault.Value{}, err
	}
	s.touch()
	return v, nil
}

// NetworkLogin is the login answering the network connection named
// name from folder (networkLogin); none from an empty folder or a
// vault that is not open.
func (s *Service) NetworkLogin(folder, name string) (vault.NetworkLogin, bool) {
	if folder == "" {
		return vault.NetworkLogin{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr == nil {
		return vault.NetworkLogin{}, false
	}
	it, ok := networkLogin(s.vault.Items, folder, name)
	if !ok {
		return vault.NetworkLogin{}, false
	}
	fields := make(map[string]string, len(it.Fields))
	for _, f := range it.Fields {
		fields[f.Name] = f.Value
	}
	return vault.NetworkLogin{Username: it.Username, Password: it.Password, Fields: fields}, true
}

// update applies f under the data lock and announces the change.
func (s *Service) update(f func()) {
	s.mu.Lock()
	f()
	s.mu.Unlock()
	s.changed()
}

// fail records err as the last error and returns it.
func (s *Service) fail(err error) error {
	s.update(func() { s.status.Err = err; s.status.Syncing = false })
	return err
}

// Login logs in with the master password and opens the vault. A second
// factor or a new device's code comes back as TwoFactorRequiredError or
// ErrNewDeviceVerification: ask for it and call Login again with it.
func (s *Service) Login(ctx context.Context, req vault.LoginRequest) error {
	s.op.Lock()
	defer s.op.Unlock()
	c := s.newClient(req.Server, s.device)
	pre, err := c.Prelogin(ctx, req.Email)
	if err != nil {
		return s.fail(err)
	}
	mk, err := deriveMasterKey(req.Password, pre.Salt, pre.Kdf)
	if err != nil {
		return s.fail(err)
	}
	defer mk.wipe()
	hash, err := mk.serverHash(req.Password)
	if err != nil {
		return s.fail(err)
	}
	tok, err := c.PasswordLogin(ctx, req.Email, hash, req.TwoFactor, req.NewDeviceOTP, s.now())
	if err != nil {
		return s.fail(err)
	}
	return s.open(ctx, c, &session{Server: req.Server, Email: req.Email, RefreshToken: tok.RefreshToken, ClientID: clientID}, tok, pre, mk)
}

// SendLoginEmail asks the server to email the second-factor code for a
// login that needs it.
func (s *Service) SendLoginEmail(ctx context.Context, req vault.LoginRequest) error {
	s.op.Lock()
	defer s.op.Unlock()
	c := s.newClient(req.Server, s.device)
	pre, err := c.Prelogin(ctx, req.Email)
	if err != nil {
		return s.fail(err)
	}
	mk, err := deriveMasterKey(req.Password, pre.Salt, pre.Kdf)
	if err != nil {
		return s.fail(err)
	}
	defer mk.wipe()
	hash, err := mk.serverHash(req.Password)
	if err != nil {
		return s.fail(err)
	}
	if err := c.SendLoginEmail(ctx, req.Email, hash); err != nil {
		return s.fail(err)
	}
	return nil
}

// LoginAPIKey logs in with the personal API key and opens the vault
// with the master password. The server issues no refresh token for it:
// once the access token expires, a locked vault needs the key again.
func (s *Service) LoginAPIKey(ctx context.Context, req vault.APIKeyRequest) error {
	s.op.Lock()
	defer s.op.Unlock()
	c := s.newClient(req.Server, s.device)
	tok, err := c.APIKeyLogin(ctx, req.ClientID, req.Secret, s.now())
	if err != nil {
		return s.fail(err)
	}
	pre, err := c.Prelogin(ctx, req.Email)
	if err != nil {
		return s.fail(err)
	}
	mk, err := deriveMasterKey(req.Password, pre.Salt, pre.Kdf)
	if err != nil {
		return s.fail(err)
	}
	defer mk.wipe()
	return s.open(ctx, c, &session{Server: req.Server, Email: req.Email, RefreshToken: tok.RefreshToken, ClientID: req.ClientID}, tok, pre, mk)
}

// Unlock opens a locked vault with the master password: a fresh token,
// a sync, the keys. A wrong password leaves it locked; a session that
// can no longer refresh logs out with vault.ErrLoginRequired.
func (s *Service) Unlock(ctx context.Context, password string) error {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	sess := s.sess
	s.mu.Unlock()
	if sess == nil {
		return s.fail(vault.ErrLoginRequired)
	}
	c := s.newClient(sess.Server, s.device)
	tok, err := s.freshToken(ctx, c, sess)
	if err != nil {
		return s.fail(err)
	}
	if sess = s.session(); sess == nil {
		return s.fail(vault.ErrLoginRequired)
	}
	pre, err := c.Prelogin(ctx, sess.Email)
	if err != nil {
		return s.fail(err)
	}
	mk, err := deriveMasterKey(password, pre.Salt, pre.Kdf)
	if err != nil {
		return s.fail(err)
	}
	defer mk.wipe()
	return s.open(ctx, c, sess, tok, pre, mk)
}

// open syncs under tok, opens the keys with the master key, and makes
// the vault current; the session is saved only once the vault opened.
func (s *Service) open(ctx context.Context, c *Client, sess *session, tok Token, pre Prelogin, mk *masterKey) error {
	s.update(func() { s.status.Syncing = true })
	sync, err := c.Sync(ctx, tok.AccessToken)
	if err != nil {
		return s.fail(err)
	}
	kr, err := unlockWith(mk, sync.Profile.Key, sync.Profile.PrivateKey, orgKeys(sync.Profile))
	if err != nil {
		return s.fail(err)
	}
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	if err := s.saveSession(sess); err != nil {
		kr.Wipe()
		return s.fail(err)
	}
	v := DecryptVault(kr, sync)
	now := s.now()
	s.update(func() {
		s.wipeLocked()
		s.sess, s.kr, s.vault = sess, kr, v
		s.gate = passwordGate{kdf: pre.Kdf, salt: pre.Salt, userKey: sync.Profile.Key}
		s.lastUse = now
		s.access, s.accessExp = tok.AccessToken, tok.Expires
		s.status = vault.Status{State: vault.StateUnlocked, Email: sess.Email, LastSync: now, Items: len(v.Items)}
	})
	return nil
}

func orgKeys(p SyncProfile) map[string]string {
	m := make(map[string]string, len(p.Organizations))
	for _, o := range p.Organizations {
		if o.Key != "" {
			m[o.ID] = o.Key
		}
	}
	return m
}

// freshToken is the held access token while it lasts, else a refreshed
// one; a revoked refresh token, or none (an API key login), logs out.
func (s *Service) freshToken(ctx context.Context, c *Client, sess *session) (Token, error) {
	s.mu.Lock()
	access, exp := s.access, s.accessExp
	s.mu.Unlock()
	if access != "" && s.now().Add(refreshMargin).Before(exp) {
		return Token{AccessToken: access, Expires: exp}, nil
	}
	if sess.RefreshToken == "" {
		return Token{}, errors.Join(vault.ErrLoginRequired, s.logout())
	}
	tok, err := c.Refresh(ctx, sess.RefreshToken, sess.ClientID, s.now())
	if errors.Is(err, vault.ErrInvalidCredentials) {
		return Token{}, errors.Join(fmt.Errorf("%w: %w", vault.ErrLoginRequired, err), s.logout())
	}
	if err != nil {
		return Token{}, err
	}
	// The server rotates the refresh token: the new one is the only
	// one that works from here, whatever happens to this operation.
	next := *sess
	next.RefreshToken = tok.RefreshToken
	if next != *sess {
		if err := s.saveSession(&next); err != nil {
			return Token{}, err
		}
	}
	s.mu.Lock()
	if s.sess == sess {
		s.sess = &next
	}
	s.access, s.accessExp = tok.AccessToken, tok.Expires
	s.mu.Unlock()
	return tok, nil
}

// Sync refetches the open vault: new and changed items, organization
// memberships, folder names.
func (s *Service) Sync(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.keyring() == nil {
		return s.fail(fmt.Errorf("bitwarden: sync: %w", vault.ErrLocked))
	}
	s.update(func() { s.status.Syncing = true })
	a, err := s.authorize(ctx)
	if err != nil {
		return s.fail(fmt.Errorf("bitwarden: sync: %w", err))
	}
	c, sess, kr, tok := a.client, a.sess, a.kr, a.tok
	sync, err := c.Sync(ctx, tok.AccessToken)
	if err != nil {
		return s.fail(err)
	}
	s.mu.Lock()
	if s.kr != kr {
		// Locked or logged out while the sync ran: drop the answer.
		s.mu.Unlock()
		return nil
	}
	err = kr.SetOrgKeys(orgKeys(sync.Profile))
	s.mu.Unlock()
	if err != nil {
		return s.fail(err)
	}
	v := DecryptVault(kr, sync)
	now := s.now()
	s.update(func() {
		if s.kr != kr {
			return
		}
		s.vault.Wipe()
		s.sess, s.vault = sess, v
		s.gate.userKey = sync.Profile.Key
		s.access, s.accessExp = tok.AccessToken, tok.Expires
		s.status = vault.Status{State: vault.StateUnlocked, Email: sess.Email, LastSync: now, Items: len(v.Items)}
	})
	return nil
}

func (s *Service) keyring() *Keyring {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kr
}

type authorized struct {
	client *Client
	sess   *session
	kr     *Keyring
	tok    Token
}

func (s *Service) authorize(ctx context.Context) (authorized, error) {
	s.mu.Lock()
	sess, kr := s.sess, s.kr
	s.mu.Unlock()
	if kr == nil {
		return authorized{}, vault.ErrLocked
	}
	c := s.newClient(sess.Server, s.device)
	tok, err := s.freshToken(ctx, c, sess)
	if err != nil {
		return authorized{}, err
	}
	if sess = s.session(); sess == nil {
		return authorized{}, vault.ErrLoginRequired
	}
	return authorized{client: c, sess: sess, kr: kr, tok: tok}, nil
}

func (s *Service) FindLogin(name string, scope vault.FolderScope) (vault.Item, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr == nil {
		return vault.Item{}, false, vault.ErrLocked
	}
	it, ok, err := findLogin(s.vault.Items, name, scope)
	if !ok || err != nil {
		return vault.Item{}, false, err
	}
	return it.summary(), true, nil
}

func (s *Service) CreateLogin(ctx context.Context, l vault.NewLogin) (vault.ItemID, error) {
	if err := l.Validate(); err != nil {
		return "", fmt.Errorf("bitwarden: create a login: %w", err)
	}
	s.op.Lock()
	defer s.op.Unlock()
	a, err := s.authorize(ctx)
	if err != nil {
		return "", fmt.Errorf("bitwarden: create a login: %w", err)
	}
	req, err := sealLocked(s, a.kr, func() (cipherRequest, error) {
		folderID, err := s.vault.folderID(l.Folder)
		if err != nil {
			return cipherRequest{}, err
		}
		if len(logins(s.vault.Items, l.Name, vault.InFolder(l.Folder))) > 0 {
			return cipherRequest{}, fmt.Errorf("%w: %q in %q", vault.ErrItemExists, l.Name, l.Folder)
		}
		return encryptLogin(a.kr.User, folderID, l)
	})
	if err != nil {
		return "", fmt.Errorf("bitwarden: create a login: %w", err)
	}
	created, err := a.client.CreateCipher(ctx, a.tok.AccessToken, req)
	if err != nil {
		return "", err
	}
	s.update(func() {
		if s.kr != a.kr {
			return
		}
		s.vault.put(decryptCipher(a.kr, created, s.vault.Folders))
		s.status.Items = len(s.vault.Items)
	})
	return vault.ItemID(created.ID), nil
}

func (s *Service) Sends() ([]vault.Send, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr == nil {
		return nil, vault.ErrLocked
	}
	return slices.Clone(s.vault.Sends), nil
}

func (s *Service) CreateTextSend(ctx context.Context, n vault.NewTextSend) (vault.CreatedSend, error) {
	if err := n.Validate(s.now()); err != nil {
		return vault.CreatedSend{}, fmt.Errorf("bitwarden: create a Send: %w", err)
	}
	s.op.Lock()
	defer s.op.Unlock()
	a, err := s.authorize(ctx)
	if err != nil {
		return vault.CreatedSend{}, fmt.Errorf("bitwarden: create a Send: %w", err)
	}
	material := make([]byte, sendKeyLen)
	if _, err := rand.Read(material); err != nil {
		return vault.CreatedSend{}, fmt.Errorf("bitwarden: create a Send: %w", err)
	}
	defer wipe(material)
	req, err := sealLocked(s, a.kr, func() (sendRequest, error) { return encryptTextSend(a.kr.User, material, n) })
	if err != nil {
		return vault.CreatedSend{}, fmt.Errorf("bitwarden: create a Send: %w", err)
	}
	created, err := a.client.CreateSend(ctx, a.tok.AccessToken, req)
	if err != nil {
		return vault.CreatedSend{}, err
	}
	link, err := a.client.sendURL(created.AccessID, material)
	if err != nil {
		return vault.CreatedSend{}, err
	}
	s.update(func() {
		if s.kr != a.kr {
			return
		}
		s.vault.Sends = append(slices.DeleteFunc(s.vault.Sends, func(x vault.Send) bool { return x.ID == vault.SendID(created.ID) }), decryptSend(a.kr.User, created))
		sortSends(s.vault.Sends)
	})
	return vault.CreatedSend{ID: vault.SendID(created.ID), URL: link}, nil
}

func (s *Service) DeleteSend(ctx context.Context, id vault.SendID) error {
	s.op.Lock()
	defer s.op.Unlock()
	a, err := s.authorize(ctx)
	if err != nil {
		return fmt.Errorf("bitwarden: delete a Send: %w", err)
	}
	if err := a.client.DeleteSend(ctx, a.tok.AccessToken, id); err != nil {
		if se, ok := errors.AsType[*APIError](err); ok && se.Status == http.StatusNotFound {
			return fmt.Errorf("%w: %s", vault.ErrNoSuchSend, id)
		}
		return err
	}
	s.update(func() {
		if s.kr == a.kr {
			s.vault.Sends = slices.DeleteFunc(s.vault.Sends, func(x vault.Send) bool { return x.ID == id })
		}
	})
	return nil
}

func sealLocked[T any](s *Service, kr *Keyring, seal func() (T, error)) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr != kr {
		var zero T
		return zero, vault.ErrLocked
	}
	return seal()
}

// Lock wipes the keys and the plaintext; the session stays for Unlock.
func (s *Service) Lock() { s.update(s.lockLocked) }

// lockLocked is Lock under mu.
func (s *Service) lockLocked() {
	s.wipeLocked()
	if s.sess != nil {
		s.status = vault.Status{State: vault.StateLocked, Email: s.sess.Email}
	}
}

// touch marks the open vault used now, restarting lockIdle's clock.
func (s *Service) touch() {
	s.mu.Lock()
	s.lastUse = s.now()
	s.mu.Unlock()
}

// lockIdle locks an open vault unused for idle or longer: since it
// opened, or since the last touch. It reports whether it locked.
func (s *Service) lockIdle(idle time.Duration) bool {
	s.mu.Lock()
	stale := s.kr != nil && !s.now().Before(s.lastUse.Add(idle))
	if stale {
		s.lockLocked()
	}
	s.mu.Unlock()
	if stale {
		s.changed()
	}
	return stale
}

// passwordGate is what verifyPassword checks a master password against:
// the account's KDF and salt and the user key as the server wraps it
// under the master key. None of it is secret.
type passwordGate struct {
	kdf           Kdf
	salt, userKey string
}

// verifyPassword checks the master password against the open vault's
// account, as the master password reprompt does before a protected
// item's secrets: vault.ErrWrongPassword when it does not open the user
// key. It derives the key, so it is as slow as an unlock.
func (s *Service) verifyPassword(password string) error {
	s.mu.Lock()
	gate, open := s.gate, s.kr != nil
	s.mu.Unlock()
	if !open {
		return fmt.Errorf("bitwarden: verify the master password: %w", vault.ErrLocked)
	}
	mk, err := deriveMasterKey(password, gate.salt, gate.kdf)
	if err != nil {
		return err
	}
	defer mk.wipe()
	key, err := unwrapUserKey(mk, gate.userKey)
	if err != nil {
		return err
	}
	key.Wipe()
	return nil
}

// Logout locks and forgets the session.
func (s *Service) Logout() error { return s.logout() }

func (s *Service) logout() error {
	s.update(func() {
		s.wipeLocked()
		s.sess = nil
		s.status = vault.Status{State: vault.StateLoggedOut}
	})
	err := os.Remove(filepath.Join(s.dir, sessionFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("bitwarden: remove the session: %w", err)
	}
	return nil
}

// wipeLocked drops the keys, the plaintext and the access token; the
// caller holds mu.
func (s *Service) wipeLocked() {
	if s.kr != nil {
		s.kr.Wipe()
		s.kr = nil
	}
	s.vault.Wipe()
	s.gate = passwordGate{}
	s.access, s.accessExp = "", time.Time{}
}
