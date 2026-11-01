// Package vault is the dev.stubbe.lys.Vault1 contract: lys-secrets'
// Bitwarden vault on the session bus, so the one process that holds the
// vault's keys serves every surface that shows or uses it (lys-shell's
// bar module, dropdown and launcher mode, its NetworkManager secret
// agent). It holds the types both sides speak, the errors a call
// fails with, the Host a vault implements, the Daemon serving one and
// the Client calling it.
//
// Secret values leave the vault one field at a time (Client.Field),
// only to a caller running as the vault's own user, and an item behind
// Bitwarden's master password reprompt gives up its secrets only with
// the master password.
package vault

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// D-Bus identity.
const (
	ServiceName = "dev.stubbe.lys.Vault1"
	ServicePath = dbus.ObjectPath("/dev/stubbe/lys/Vault")
	iface       = "dev.stubbe.lys.Vault1"
)

// State is where the vault stands.
type State uint32

// The vault states: no account, an account whose keys are not in
// memory, and an open vault.
const (
	StateLoggedOut State = iota
	StateLocked
	StateUnlocked
)

func (s State) valid() bool { return s <= StateUnlocked }

// Status is the vault at a glance: the state, the account, whether a
// sync runs, when the last one landed (zero for none), how many items
// the open vault holds, and the last operation's error (nil once one
// succeeds).
type Status struct {
	State    State
	Email    string
	Syncing  bool
	LastSync time.Time
	Items    int
	Err      error
}

// ItemType is an item's kind, as Bitwarden numbers it.
type ItemType uint32

// The item types.
const (
	ItemLogin      ItemType = 1
	ItemSecureNote ItemType = 2
	ItemCard       ItemType = 3
	ItemIdentity   ItemType = 4
	ItemSSHKey     ItemType = 5
)

func (t ItemType) valid() bool { return t >= ItemLogin && t <= ItemSSHKey }

// Field is one value an item gives out: a login's or identity's
// username, a login's password and verification code, a card's number
// and code, an identity's email, a secure note's text.
type Field uint32

// The fields.
const (
	FieldUsername Field = iota
	FieldPassword
	FieldTOTP
	FieldCardNumber
	FieldCardCode
	FieldEmail
	FieldNotes
)

func (f Field) valid() bool { return f <= FieldNotes }

// Secret reports whether the field is a secret: behind the item's
// master password reprompt, and for a client to mark as such where it
// puts it (a clipboard). A username and an email are not.
func (f Field) Secret() bool {
	switch f {
	case FieldUsername, FieldEmail:
		return false
	}
	return true
}

// Item is what a listing shows of a vault item, no secret among it:
// its names, the login's username and URIs, the card's brand, and the
// fields it gives out, its primary one first. Undecryptable marks an
// item any of whose fields did not open; Reprompt one behind the master
// password reprompt.
type Item struct {
	ID            string
	Type          ItemType
	Name          string
	Folder        string
	Organization  string
	Favorite      bool
	Reprompt      bool
	Undecryptable bool
	Username      string
	URIs          []string
	CardBrand     string
	Fields        []Field
}

// Match reports whether the item matches every word of query, in its
// name, username, URIs or folder, ignoring case.
func (it Item) Match(query string) bool {
	hay := strings.ToLower(strings.Join(append([]string{it.Name, it.Username, it.Folder}, it.URIs...), "\n"))
	for w := range strings.FieldsSeq(strings.ToLower(query)) {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

func (it Item) check() error {
	if !it.Type.valid() {
		return fmt.Errorf("item %s has type %d", it.ID, it.Type)
	}
	for _, f := range it.Fields {
		if !f.valid() {
			return fmt.Errorf("item %s offers field %d", it.ID, f)
		}
	}
	return nil
}

// Value is one field's value; Expires is when a verification code
// stops being valid, zero for a value that does not expire.
type Value struct {
	Text    string
	Expires time.Time
}

// NetworkLogin is the login answering a network connection's secrets:
// its username and password, and its custom fields by name.
type NetworkLogin struct {
	Username, Password string
	Fields             map[string]string
}

// Server is where an account lives: an official cloud by its name, or
// a self-hosted server (or Vaultwarden) by its base URL, https unless
// it is on this machine. The zero Server is none.
type Server struct{ s string }

// The official clouds, by the names ParseServer takes.
const (
	CloudUS = "bitwarden.com"
	CloudEU = "bitwarden.eu"
)

// ParseServer reads a server setting: CloudUS, CloudEU, or an http(s)
// base URL without a query or fragment. A URL CheckTransport refuses is
// an error matching ErrInsecureServer.
func ParseServer(s string) (Server, error) {
	if s == CloudUS || s == CloudEU {
		return Server{s}, nil
	}
	u, err := url.Parse(strings.TrimRight(s, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return Server{}, fmt.Errorf("vault: server %q is neither %s, %s nor an http(s) base URL", s, CloudUS, CloudEU)
	}
	if err := CheckTransport(u); err != nil {
		return Server{}, err
	}
	return Server{u.String()}, nil
}

// CheckTransport refuses a URL that would carry the password hash and
// the tokens unencrypted off this machine: http to anything but loopback.
func CheckTransport(u *url.URL) error {
	if u.Scheme != "http" || isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%w: %s; use https://, as http:// is only for a server on this machine", ErrInsecureServer, u.Redacted())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// String is the cloud's name or the base URL.
func (s Server) String() string { return s.s }

// MarshalText implements encoding.TextMarshaler.
func (s Server) MarshalText() ([]byte, error) { return []byte(s.s), nil }

// UnmarshalText implements encoding.TextUnmarshaler, refusing what
// ParseServer refuses.
func (s *Server) UnmarshalText(b []byte) error {
	parsed, err := ParseServer(string(b))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// TwoFactorProvider is a second factor, as Bitwarden numbers it.
type TwoFactorProvider uint32

// The providers a login completes; the server may list others (Duo,
// WebAuthn, YubiKey) that the API key login gets around.
const (
	TwoFactorAuthenticator TwoFactorProvider = 0
	TwoFactorEmail         TwoFactorProvider = 1
)

// TwoFactor is a second factor answering a TwoFactorRequiredError.
type TwoFactor struct {
	Provider TwoFactorProvider
	Code     string
}

// LoginRequest is a password login: the server, the account, the
// master password, and the second factor or new device code when a
// previous attempt asked for one.
type LoginRequest struct {
	Server       Server
	Email        string
	Password     string
	TwoFactor    *TwoFactor
	NewDeviceOTP string
}

// APIKeyRequest is a login with the account's personal API key; the
// master password still opens the keys.
type APIKeyRequest struct {
	Server           Server
	Email            string
	ClientID, Secret string
	Password         string
}

type ItemID string

type FolderScope struct {
	folder string
	scoped bool
}

func AnyFolder() FolderScope { return FolderScope{} }

func InFolder(name string) FolderScope { return FolderScope{folder: name, scoped: true} }

func (s FolderScope) Folder() (string, bool) { return s.folder, s.scoped }

func (s FolderScope) Contains(folder string) bool { return !s.scoped || s.folder == folder }

type NewLogin struct {
	Folder   string
	Name     string
	Username string
	Password string
	URIs     []string
}

const (
	maxEncryptedName     = 1000
	maxEncryptedUsername = 1000
	maxEncryptedPassword = 5000
	maxEncryptedURI      = 10000
)

func (l NewLogin) Validate() error {
	if err := validName("name", l.Name, maxEncryptedName); err != nil {
		return err
	}
	if !utf8.ValidString(l.Folder) {
		return fmt.Errorf("%w: the folder is not UTF-8", ErrInvalidInput)
	}
	if err := fitsEncrypted("username", l.Username, maxEncryptedUsername); err != nil {
		return err
	}
	if err := fitsEncrypted("password", l.Password, maxEncryptedPassword); err != nil {
		return err
	}
	for i, u := range l.URIs {
		if err := validName(fmt.Sprintf("URI %d", i), u, maxEncryptedURI); err != nil {
			return err
		}
	}
	return nil
}

func validName(what, s string, limit int) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%w: the %s is empty", ErrInvalidInput, what)
	}
	return fitsEncrypted(what, s, limit)
}

func fitsEncrypted(what, s string, limit int) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: the %s is not UTF-8", ErrInvalidInput, what)
	}
	if encryptedLen(len(s)) > limit {
		return fmt.Errorf("%w: the %s of %d bytes encrypts past Bitwarden's limit of %d characters", ErrInvalidInput, what, len(s), limit)
	}
	return nil
}

func encryptedLen(n int) int {
	b64 := base64.StdEncoding.EncodedLen
	return len("2.") + b64(aes.BlockSize) + 1 + b64((n/aes.BlockSize+1)*aes.BlockSize) + 1 + b64(sha256.Size)
}
