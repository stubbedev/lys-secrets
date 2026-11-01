package vault

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// Host is a vault the Daemon serves. Each call blocks until done; a
// failing one returns the contract's errors.
type Host interface {
	// Status is the vault at a glance.
	Status() Status
	// Items lists the open vault, favorites first then by name;
	// ErrLocked while it is not open.
	Items() ([]Item, error)
	// Field is item id's field f, a verification code as of now. A
	// secret of an item behind the reprompt needs the master password
	// (ErrRepromptRequired without, ErrWrongPassword for another);
	// otherwise password is ignored. It counts as use of the vault.
	Field(id string, f Field, password string) (Value, error)
	// Login logs in with the master password and opens the vault.
	Login(ctx context.Context, r LoginRequest) error
	// SendLoginEmail asks the server to email a login's second-factor
	// code.
	SendLoginEmail(ctx context.Context, r LoginRequest) error
	// LoginAPIKey logs in with the personal API key and opens the vault
	// with the master password.
	LoginAPIKey(ctx context.Context, r APIKeyRequest) error
	// Unlock opens a locked vault with the master password.
	Unlock(ctx context.Context, password string) error
	// Lock wipes the keys and the plaintext; the session stays.
	Lock()
	// Logout locks, forgets the session here, and asks the server to
	// revoke it. The session is gone here whatever the server does. A
	// server with no way to revoke it is ErrRevocationUnsupported, and an
	// attempt that failed is ErrSessionNotRevoked.
	Logout(ctx context.Context) error
	// Sync refetches the open vault.
	Sync(ctx context.Context) error
	// NetworkLogin is the login answering the network connection named
	// name from folder; false when there is none or the vault is not
	// open.
	NetworkLogin(folder, name string) (NetworkLogin, bool)
	CreateLogin(ctx context.Context, l NewLogin) (ItemID, error)
	FindLogin(name string, scope FolderScope) (Item, bool, error)
	Sends() ([]Send, error)
	CreateTextSend(ctx context.Context, s NewTextSend) (CreatedSend, error)
	DeleteSend(ctx context.Context, id SendID) error
}

// wireStatus is a Status on the bus: LastSync in Unix seconds (0 for
// none), the error as its name ("" for none) and body.
type wireStatus struct {
	State    uint32         `dbus:"state"`
	Email    string         `dbus:"email"`
	Syncing  bool           `dbus:"syncing"`
	LastSync int64          `dbus:"last_sync"`
	Items    uint32         `dbus:"items"`
	ErrName  string         `dbus:"error"`
	ErrBody  []dbus.Variant `dbus:"error_body"`
}

// wireError is an error on the bus, its name ("" for none) and body.
type wireError struct {
	Name string         `dbus:"error"`
	Body []dbus.Variant `dbus:"error_body"`
}

func toWireError(err error) wireError {
	if err == nil {
		return wireError{Body: []dbus.Variant{}}
	}
	e := encodeError(err)
	body := make([]dbus.Variant, len(e.Body))
	for i, v := range e.Body {
		body[i] = dbus.MakeVariant(v)
	}
	return wireError{Name: e.Name, Body: body}
}

func fromWireError(w wireError) error {
	if w.Name == "" {
		return nil
	}
	body := make([]any, len(w.Body))
	for i, v := range w.Body {
		body[i] = v.Value()
	}
	return decodeError(dbus.Error{Name: w.Name, Body: body})
}

func toWire(s Status) wireStatus {
	last := int64(0)
	if !s.LastSync.IsZero() {
		last = s.LastSync.Unix()
	}
	e := toWireError(s.Err)
	return wireStatus{
		State: uint32(s.State), Email: s.Email, Syncing: s.Syncing, LastSync: last,
		Items: uint32(max(s.Items, 0)), ErrName: e.Name, ErrBody: e.Body, //nolint:gosec // clamped to 0..MaxInt, a count of items
	}
}

func fromWire(w wireStatus) (Status, error) {
	st := State(w.State)
	if !st.valid() {
		return Status{}, fmt.Errorf("vault: status carries state %d", w.State)
	}
	s := Status{State: st, Email: w.Email, Syncing: w.Syncing, Items: int(w.Items), Err: fromWireError(wireError{w.ErrName, w.ErrBody})}
	if w.LastSync != 0 {
		s.LastSync = time.Unix(w.LastSync, 0)
	}
	return s, nil
}

// wireLogin is a LoginRequest on the bus: the server as its setting,
// HasTwoFactor saying whether Provider and Code are one.
type wireLogin struct {
	Server, Email, Password string
	HasTwoFactor            bool
	Provider                uint32
	Code, NewDeviceOTP      string
}

func toWireLogin(r LoginRequest) wireLogin {
	w := wireLogin{Server: r.Server.String(), Email: r.Email, Password: r.Password, NewDeviceOTP: r.NewDeviceOTP}
	if r.TwoFactor != nil {
		w.HasTwoFactor, w.Provider, w.Code = true, uint32(r.TwoFactor.Provider), r.TwoFactor.Code
	}
	return w
}

func (w wireLogin) parse() (LoginRequest, error) {
	server, err := ParseServer(w.Server)
	if err != nil {
		return LoginRequest{}, err
	}
	r := LoginRequest{Server: server, Email: w.Email, Password: w.Password, NewDeviceOTP: w.NewDeviceOTP}
	if w.HasTwoFactor {
		r.TwoFactor = &TwoFactor{Provider: TwoFactorProvider(w.Provider), Code: w.Code}
	}
	return r, nil
}

// wireAPIKey is an APIKeyRequest on the bus.
type wireAPIKey struct {
	Server, Email, ClientID, Secret, Password string
}

func (w wireAPIKey) parse() (APIKeyRequest, error) {
	server, err := ParseServer(w.Server)
	if err != nil {
		return APIKeyRequest{}, err
	}
	return APIKeyRequest{Server: server, Email: w.Email, ClientID: w.ClientID, Secret: w.Secret, Password: w.Password}, nil
}

// The signals: the status after every change of it or of the items,
// and a periodic sync failing.
var (
	changed    = dbusx.NewSignal[wireStatus](iface, "Changed")
	syncFailed = dbusx.NewSignal[wireError](iface, "SyncFailed")
)

// peerTimeout bounds asking the bus who a caller is.
const peerTimeout = 5 * time.Second

// Daemon serves a Host as dev.stubbe.lys.Vault1 to callers running as
// this process's user.
type Daemon struct {
	host Host
	life context.Context
	uid  uint32
	conn *dbus.Conn
}

// NewDaemon wraps host for export; life bounds the operations callers
// start.
func NewDaemon(life context.Context, host Host) *Daemon {
	return &Daemon{host: host, life: life, uid: uint32(os.Getuid())} //nolint:gosec // a uid fits 32 bits
}

// Export serves the interface under its name on conn; the returned
// release drops the name. A name another process owns is
// dbusx.ErrNameTaken, and leaves nothing exported.
func (d *Daemon) Export(conn *dbus.Conn) (func(), error) {
	d.conn = conn
	return dbusx.Serve(conn, dbusx.Service{
		Name: ServiceName, Path: ServicePath, Interface: iface,
		Methods: methods{d}, Signals: []dbusx.SignalDecl{changed, syncFailed},
	})
}

// Changed signals the host's status, after a change of it or of the
// vault's items.
func (d *Daemon) Changed() error {
	return changed.Emit(d.conn, ServicePath, toWire(d.host.Status()))
}

// SyncFailed signals a periodic sync failing with err.
func (d *Daemon) SyncFailed(err error) error {
	return syncFailed.Emit(d.conn, ServicePath, toWireError(err))
}

// methods are the interface's methods. Each first checks that the
// caller runs as the vault's user.
type methods struct{ d *Daemon }

func (m methods) allow(sender dbus.Sender) *dbus.Error {
	ctx, cancel := context.WithTimeout(m.d.life, peerTimeout)
	defer cancel()
	var uid uint32
	if err := m.d.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
		return dbusx.Failed(fmt.Sprintf("vault: the uid of caller %s: %v", sender, err))
	}
	if uid != m.d.uid {
		return encodeError(fmt.Errorf("%w: caller %s runs as uid %d", ErrAccessDenied, sender, uid))
	}
	return nil
}

func (m methods) run(sender dbus.Sender, op func() error) *dbus.Error {
	if derr := m.allow(sender); derr != nil {
		return derr
	}
	if err := op(); err != nil {
		return encodeError(err)
	}
	return nil
}

// Status is the vault at a glance.
func (m methods) Status(sender dbus.Sender) (wireStatus, *dbus.Error) {
	if derr := m.allow(sender); derr != nil {
		return wireStatus{}, derr
	}
	return toWire(m.d.host.Status()), nil
}

// Items lists the open vault.
func (m methods) Items(sender dbus.Sender) ([]Item, *dbus.Error) {
	var items []Item
	derr := m.run(sender, func() (err error) {
		items, err = m.d.host.Items()
		return err
	})
	if items == nil {
		items = []Item{}
	}
	return items, derr
}

// Field is one field's value and when it expires (Unix seconds, 0 for
// never).
func (m methods) Field(sender dbus.Sender, id string, field uint32, password string) (string, int64, *dbus.Error) {
	f := Field(field)
	if !f.valid() {
		return "", 0, dbusx.InvalidArgs(fmt.Sprintf("Field: no field %d", field))
	}
	var v Value
	derr := m.run(sender, func() (err error) {
		v, err = m.d.host.Field(id, f, password)
		return err
	})
	if derr != nil || v.Expires.IsZero() {
		return v.Text, 0, derr
	}
	return v.Text, v.Expires.Unix(), nil
}

// Login logs in with the master password.
func (m methods) Login(sender dbus.Sender, w wireLogin) *dbus.Error {
	r, err := w.parse()
	if err != nil {
		return dbusx.InvalidArgs("Login: " + err.Error())
	}
	return m.run(sender, func() error { return m.d.host.Login(m.d.life, r) })
}

// SendLoginEmail asks for a login's emailed code.
func (m methods) SendLoginEmail(sender dbus.Sender, w wireLogin) *dbus.Error {
	r, err := w.parse()
	if err != nil {
		return dbusx.InvalidArgs("SendLoginEmail: " + err.Error())
	}
	return m.run(sender, func() error { return m.d.host.SendLoginEmail(m.d.life, r) })
}

// LoginAPIKey logs in with the personal API key.
func (m methods) LoginAPIKey(sender dbus.Sender, w wireAPIKey) *dbus.Error {
	r, err := w.parse()
	if err != nil {
		return dbusx.InvalidArgs("LoginAPIKey: " + err.Error())
	}
	return m.run(sender, func() error { return m.d.host.LoginAPIKey(m.d.life, r) })
}

// Unlock opens the vault with the master password.
func (m methods) Unlock(sender dbus.Sender, password string) *dbus.Error {
	return m.run(sender, func() error { return m.d.host.Unlock(m.d.life, password) })
}

// Lock locks the vault.
func (m methods) Lock(sender dbus.Sender) *dbus.Error {
	return m.run(sender, func() error {
		m.d.host.Lock()
		return nil
	})
}

// Logout forgets the session here and asks the server to revoke it.
func (m methods) Logout(sender dbus.Sender) *dbus.Error {
	return m.run(sender, func() error { return m.d.host.Logout(m.d.life) })
}

// Sync refetches the open vault.
func (m methods) Sync(sender dbus.Sender) *dbus.Error {
	return m.run(sender, func() error { return m.d.host.Sync(m.d.life) })
}

// NetworkLogin is the login for a network connection: whether there is
// one, its username, password and custom fields.
func (m methods) NetworkLogin(sender dbus.Sender, folder, name string) (bool, string, string, map[string]string, *dbus.Error) {
	if derr := m.allow(sender); derr != nil {
		return false, "", "", map[string]string{}, derr
	}
	l, ok := m.d.host.NetworkLogin(folder, name)
	if l.Fields == nil {
		l.Fields = map[string]string{}
	}
	return ok, l.Username, l.Password, l.Fields, nil
}

func (m methods) CreateLogin(sender dbus.Sender, folder, name, username, password string, uris []string) (string, *dbus.Error) {
	l := NewLogin{Folder: folder, Name: name, Username: username, Password: password, URIs: uris}
	var id ItemID
	derr := m.run(sender, func() (err error) {
		if err := l.Validate(); err != nil {
			return fmt.Errorf("CreateLogin: %w", err)
		}
		id, err = m.d.host.CreateLogin(m.d.life, l)
		return err
	})
	return string(id), derr
}

func (m methods) FindLogin(sender dbus.Sender, name string, scoped bool, folder string) (bool, Item, *dbus.Error) {
	scope := AnyFolder()
	if scoped {
		scope = InFolder(folder)
	}
	var (
		it    Item
		found bool
	)
	derr := m.run(sender, func() (err error) {
		if err := validName("name", name, maxEncryptedName); err != nil {
			return fmt.Errorf("FindLogin: %w", err)
		}
		it, found, err = m.d.host.FindLogin(name, scope)
		return err
	})
	if derr != nil || !found {
		return false, Item{Fields: []Field{}, URIs: []string{}}, derr
	}
	return true, it, nil
}

func (m methods) Sends(sender dbus.Sender) ([]wireSend, *dbus.Error) {
	var sends []Send
	derr := m.run(sender, func() (err error) {
		sends, err = m.d.host.Sends()
		return err
	})
	out := make([]wireSend, len(sends))
	for i, s := range sends {
		out[i] = toWireSend(s)
	}
	return out, derr
}

func (m methods) CreateTextSend(sender dbus.Sender, name, text string, deletion int64, maxAccessCount uint32, password string) (string, string, *dbus.Error) {
	s := NewTextSend{Name: name, Text: text, Deletion: time.Unix(deletion, 0), MaxAccessCount: maxAccessCount, Password: password}
	var created CreatedSend
	derr := m.run(sender, func() error {
		if err := s.Validate(time.Now()); err != nil {
			return fmt.Errorf("CreateTextSend: %w", err)
		}
		var err error
		created, err = m.d.host.CreateTextSend(m.d.life, s)
		return err
	})
	return string(created.ID), created.URL, derr
}

func (m methods) DeleteSend(sender dbus.Sender, id string) *dbus.Error {
	return m.run(sender, func() error {
		if err := SendID(id).validate(); err != nil {
			return fmt.Errorf("DeleteSend: %w", err)
		}
		return m.d.host.DeleteSend(m.d.life, SendID(id))
	})
}
