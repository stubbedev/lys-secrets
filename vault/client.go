package vault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// Client calls the vault. A login or an unlock derives the master key
// and talks to the server, so the calls are bounded only by ctx.
type Client struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

// NewClient addresses the vault over conn.
func NewClient(conn *dbus.Conn) *Client {
	return &Client{conn: conn, obj: conn.Object(ServiceName, ServicePath)}
}

func (c *Client) call(ctx context.Context, method string, args ...any) *dbus.Call {
	return c.obj.CallWithContext(ctx, iface+"."+method, 0, args...)
}

func (c *Client) do(ctx context.Context, method string, args ...any) error {
	return decodeError(c.call(ctx, method, args...).Err)
}

// Status is the vault at a glance.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var w wireStatus
	if err := c.call(ctx, "Status").Store(&w); err != nil {
		return Status{}, decodeError(err)
	}
	return fromWire(w)
}

// Items lists the open vault, favorites first then by name; ErrLocked
// while it is not open.
func (c *Client) Items(ctx context.Context) ([]Item, error) {
	var items []Item
	if err := c.call(ctx, "Items").Store(&items); err != nil {
		return nil, decodeError(err)
	}
	for _, it := range items {
		if err := it.check(); err != nil {
			return nil, fmt.Errorf("vault: Items: %w", err)
		}
	}
	return items, nil
}

// Field is item id's field f. A secret of an item behind the reprompt
// needs the master password as password; otherwise it is ignored.
func (c *Client) Field(ctx context.Context, id string, f Field, password string) (Value, error) {
	var (
		text    string
		expires int64
	)
	if err := c.call(ctx, "Field", id, uint32(f), password).Store(&text, &expires); err != nil {
		return Value{}, decodeError(err)
	}
	v := Value{Text: text}
	if expires != 0 {
		v.Expires = time.Unix(expires, 0)
	}
	return v, nil
}

// Login logs in with the master password and opens the vault. A second
// factor or a new device's code comes back as TwoFactorRequiredError or
// ErrNewDeviceVerification: ask for it and call Login again with it.
func (c *Client) Login(ctx context.Context, r LoginRequest) error {
	return c.do(ctx, "Login", toWireLogin(r))
}

// SendLoginEmail asks the server to email a login's second-factor
// code.
func (c *Client) SendLoginEmail(ctx context.Context, r LoginRequest) error {
	return c.do(ctx, "SendLoginEmail", toWireLogin(r))
}

// LoginAPIKey logs in with the personal API key and opens the vault
// with the master password.
func (c *Client) LoginAPIKey(ctx context.Context, r APIKeyRequest) error {
	return c.do(ctx, "LoginAPIKey", wireAPIKey{Server: r.Server.String(), Email: r.Email, ClientID: r.ClientID, Secret: r.Secret, Password: r.Password})
}

// Unlock opens a locked vault with the master password.
func (c *Client) Unlock(ctx context.Context, password string) error {
	return c.do(ctx, "Unlock", password)
}

// Lock wipes the vault's keys and plaintext.
func (c *Client) Lock(ctx context.Context) error { return c.do(ctx, "Lock") }

// Logout locks and forgets the session.
func (c *Client) Logout(ctx context.Context) error { return c.do(ctx, "Logout") }

// Sync refetches the open vault.
func (c *Client) Sync(ctx context.Context) error { return c.do(ctx, "Sync") }

// NetworkLogin is the login in folder answering the network connection
// named name; false when there is none or the vault is not open.
func (c *Client) NetworkLogin(ctx context.Context, folder, name string) (NetworkLogin, bool, error) {
	var (
		found bool
		l     NetworkLogin
	)
	if err := c.call(ctx, "NetworkLogin", folder, name).Store(&found, &l.Username, &l.Password, &l.Fields); err != nil {
		return NetworkLogin{}, false, decodeError(err)
	}
	if !found {
		return NetworkLogin{}, false, nil
	}
	return l, true, nil
}

// Watcher is what Watch reports.
type Watcher struct {
	// Changed is the status after a change of it or of the items, and
	// the vault's status whenever the vault (re)appears on the bus.
	Changed func(Status)
	// SyncFailed is a periodic sync failing.
	SyncFailed func(error)
}

// Watch reports the vault's signals to w, each on the watch's
// goroutine, until ctx ends. Only the signals of the vault's current
// owner count; a malformed one is logged and skipped.
func (c *Client) Watch(ctx context.Context, w Watcher) error {
	match := []dbus.MatchOption{dbus.WithMatchSender(ServiceName), dbus.WithMatchObjectPath(ServicePath), dbus.WithMatchInterface(iface)}
	if err := c.conn.AddMatchSignalContext(ctx, match...); err != nil {
		return fmt.Errorf("vault: watch %s: %w", ServiceName, err)
	}
	signals := make(chan *dbus.Signal, 16)
	c.conn.Signal(signals)
	appeared := make(chan struct{}, 1)
	if err := dbusx.WatchOwner(ctx, c.conn, ServiceName, func() {
		select {
		case appeared <- struct{}{}:
		default:
		}
	}); err != nil {
		c.conn.RemoveSignal(signals)
		_ = c.conn.RemoveMatchSignal(match...)
		return fmt.Errorf("vault: watch %s: %w", ServiceName, err)
	}
	owner, _ := dbusx.NameOwner(ctx, c.conn, ServiceName)
	go func() {
		defer func() {
			c.conn.RemoveSignal(signals)
			_ = c.conn.RemoveMatchSignal(match...)
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-appeared:
				owner, _ = dbusx.NameOwner(ctx, c.conn, ServiceName)
				st, err := c.Status(ctx)
				if err != nil {
					log.Printf("vault: the status of the vault that appeared: %v", err)
					continue
				}
				w.Changed(st)
			case sig := <-signals:
				if sig.Sender == owner && sig.Path == ServicePath {
					dispatch(sig, w)
				}
			}
		}
	}()
	return nil
}

func dispatch(sig *dbus.Signal, w Watcher) {
	switch sig.Name {
	case changed.Name():
		raw, err := changed.Decode(sig)
		if err != nil {
			log.Printf("vault: skip a malformed signal: %v", err)
			return
		}
		st, err := fromWire(raw)
		if err != nil {
			log.Printf("vault: skip a malformed signal: %v", err)
			return
		}
		w.Changed(st)
	case syncFailed.Name():
		raw, err := syncFailed.Decode(sig)
		if err != nil {
			log.Printf("vault: skip a malformed signal: %v", err)
			return
		}
		err = fromWireError(raw)
		if err == nil {
			log.Printf("vault: skip a %s signal without an error", sig.Name)
			return
		}
		w.SyncFailed(err)
	}
}
