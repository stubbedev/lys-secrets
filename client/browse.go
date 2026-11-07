package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/transport"
)

const (
	ifaceProperties = "org.freedesktop.DBus.Properties"
	errIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
)

// OpenEncrypted starts a DH session, so secrets cross the bus encrypted
// under a key only this client and the provider hold.
func OpenEncrypted(ctx context.Context, conn *dbus.Conn) (*Client, error) {
	pMinus1 := new(big.Int).Sub(transport.Prime, big.NewInt(1))
	priv, err := rand.Int(rand.Reader, pMinus1)
	if err != nil {
		return nil, fmt.Errorf("secrets: DH private key: %w", err)
	}
	priv.Add(priv, big.NewInt(1))
	public := new(big.Int).Exp(transport.Generator, priv, transport.Prime).Bytes()
	c := &Client{conn: conn, svc: conn.Object(busName, servicePath)}
	var out dbus.Variant
	if err := c.svc.CallWithContext(ctx, ifaceService+".OpenSession", 0, transport.AlgDH, dbus.MakeVariant(public)).Store(&out, &c.session); err != nil {
		return nil, fmt.Errorf("secrets: open an encrypted session with %s: %w", busName, err)
	}
	peer, ok := out.Value().([]byte)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("secrets: the provider answered the DH session with %s, not its public key", out.Signature())
	}
	shared := new(big.Int).Exp(new(big.Int).SetBytes(peer), priv, transport.Prime).FillBytes(make([]byte, transport.PrimeLen))
	defer clear(shared)
	if c.tr, err = transport.NewAES(shared); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Collection is one collection and whether it is locked.
type Collection struct {
	Path   dbus.ObjectPath
	Label  string
	Locked bool
}

// Item is one item as the provider describes it, its secret aside.
type Item struct {
	Path              dbus.ObjectPath
	Label             string
	Attributes        map[string]string
	Created, Modified uint64
	Locked            bool
}

// Collections is every collection the provider serves.
func (c *Client) Collections(ctx context.Context) ([]Collection, error) {
	v, err := c.svc.GetProperty(ifaceService + ".Collections")
	if err != nil {
		return nil, fmt.Errorf("secrets: list the collections: %w", err)
	}
	paths, _ := v.Value().([]dbus.ObjectPath)
	props, err := c.getAll(ctx, paths, ifaceCollection)
	if err != nil {
		return nil, err
	}
	out := make([]Collection, len(paths))
	for i, p := range paths {
		label, _ := props[i]["Label"].Value().(string)
		locked, _ := props[i]["Locked"].Value().(bool)
		out[i] = Collection{Path: p, Label: label, Locked: locked}
	}
	return out, nil
}

// Search is every item of coll, locked or not.
func (c *Client) Search(ctx context.Context, coll dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	var out []dbus.ObjectPath
	if err := c.conn.Object(busName, coll).CallWithContext(ctx, ifaceCollection+".SearchItems", 0, map[string]string{}).Store(&out); err != nil {
		return nil, fmt.Errorf("secrets: search %s: %w", coll, err)
	}
	return out, nil
}

// Describe is the items' labels, attributes, times and lock state, their
// GetAll calls sent together and collected after.
func (c *Client) Describe(ctx context.Context, items []dbus.ObjectPath) ([]Item, error) {
	props, err := c.getAll(ctx, items, ifaceItem)
	if err != nil {
		return nil, err
	}
	out := make([]Item, len(items))
	for i, p := range items {
		it := Item{Path: p}
		it.Label, _ = props[i]["Label"].Value().(string)
		it.Attributes, _ = props[i]["Attributes"].Value().(map[string]string)
		it.Created, _ = props[i]["Created"].Value().(uint64)
		it.Modified, _ = props[i]["Modified"].Value().(uint64)
		it.Locked, _ = props[i]["Locked"].Value().(bool)
		out[i] = it
	}
	return out, nil
}

func (c *Client) getAll(ctx context.Context, paths []dbus.ObjectPath, iface string) ([]map[string]dbus.Variant, error) {
	calls := make([]*dbus.Call, len(paths))
	for i, p := range paths {
		calls[i] = c.conn.Object(busName, p).GoWithContext(ctx, ifaceProperties+".GetAll", 0, make(chan *dbus.Call, 1), iface)
	}
	out := make([]map[string]dbus.Variant, len(paths))
	for i, call := range calls {
		<-call.Done
		if err := call.Store(&out[i]); err != nil {
			return nil, fmt.Errorf("secrets: describe %s: %w", paths[i], err)
		}
	}
	return out, nil
}

// Secret is the item's secret, its collection unlocked through the
// provider's prompt when needed. The caller owns the returned bytes and
// should clear them when done.
func (c *Client) Secret(ctx context.Context, item dbus.ObjectPath) ([]byte, error) {
	var s secret
	err := c.conn.Object(busName, item).CallWithContext(ctx, ifaceItem+".GetSecret", 0, c.session).Store(&s)
	var derr dbus.Error
	if errors.As(err, &derr) && derr.Name == errIsLocked {
		if err := c.Unlock(ctx, []dbus.ObjectPath{item}); err != nil {
			return nil, err
		}
		err = c.conn.Object(busName, item).CallWithContext(ctx, ifaceItem+".GetSecret", 0, c.session).Store(&s)
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: read %s: %w", item, err)
	}
	value, err := c.tr.Decode(s.Parameters, s.Value)
	clear(s.Value)
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt %s: %w", item, err)
	}
	return value, nil
}

// SetSecret replaces the item's secret.
func (c *Client) SetSecret(ctx context.Context, item dbus.ObjectPath, value []byte, contentType string) error {
	params, enc, err := c.tr.Encode(value)
	if err != nil {
		return fmt.Errorf("secrets: encrypt for %s: %w", item, err)
	}
	if err := c.conn.Object(busName, item).CallWithContext(ctx, ifaceItem+".SetSecret", 0, secret{Session: c.session, Parameters: params, Value: enc, ContentType: contentType}).Err; err != nil {
		return fmt.Errorf("secrets: replace the secret of %s: %w", item, err)
	}
	return nil
}

// SetLabel renames the item.
func (c *Client) SetLabel(ctx context.Context, item dbus.ObjectPath, label string) error {
	if err := c.conn.Object(busName, item).CallWithContext(ctx, ifaceProperties+".Set", 0, ifaceItem, "Label", dbus.MakeVariant(label)).Err; err != nil {
		return fmt.Errorf("secrets: rename %s: %w", item, err)
	}
	return nil
}

// Unlock unlocks objects (collections or items) through the provider's
// prompt when it needs one.
func (c *Client) Unlock(ctx context.Context, objects []dbus.ObjectPath) error {
	return c.withPrompt(ctx, "unlock", ".Unlock", objects)
}

// Lock locks objects.
func (c *Client) Lock(ctx context.Context, objects []dbus.ObjectPath) error {
	return c.withPrompt(ctx, "lock", ".Lock", objects)
}

func (c *Client) withPrompt(ctx context.Context, what, method string, objects []dbus.ObjectPath) error {
	var done []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := c.svc.CallWithContext(ctx, ifaceService+method, 0, objects).Store(&done, &prompt); err != nil {
		return fmt.Errorf("secrets: %s %v: %w", what, objects, err)
	}
	if prompt == noPath {
		return nil
	}
	if _, err := c.prompt(ctx, prompt); err != nil {
		return fmt.Errorf("secrets: %s %v: %w", what, objects, err)
	}
	return nil
}

// ChangeLock asks the provider for a new password for coll through its
// prompt (lys-secrets' extension of the service).
func (c *Client) ChangeLock(ctx context.Context, coll dbus.ObjectPath) error {
	var prompt dbus.ObjectPath
	if err := c.svc.CallWithContext(ctx, ifaceService+".ChangeLock", 0, coll).Store(&prompt); err != nil {
		return fmt.Errorf("secrets: change the password of %s: %w", coll, err)
	}
	if prompt == noPath {
		return nil
	}
	if _, err := c.prompt(ctx, prompt); err != nil {
		return fmt.Errorf("secrets: change the password of %s: %w", coll, err)
	}
	return nil
}

// DeleteItem deletes the item, through a prompt when the provider asks.
func (c *Client) DeleteItem(ctx context.Context, item dbus.ObjectPath) error {
	var prompt dbus.ObjectPath
	if err := c.conn.Object(busName, item).CallWithContext(ctx, ifaceItem+".Delete", 0).Store(&prompt); err != nil {
		return fmt.Errorf("secrets: delete %s: %w", item, err)
	}
	if prompt == noPath {
		return nil
	}
	if _, err := c.prompt(ctx, prompt); err != nil {
		return fmt.Errorf("secrets: delete %s: %w", item, err)
	}
	return nil
}

// WatchItems calls changed on every item created, changed or deleted in
// coll, until stop.
func (c *Client) WatchItems(coll dbus.ObjectPath, changed func()) (stop func(), err error) {
	match := []dbus.MatchOption{dbus.WithMatchObjectPath(coll), dbus.WithMatchInterface(ifaceCollection)}
	if err := c.conn.AddMatchSignal(match...); err != nil {
		return nil, fmt.Errorf("secrets: follow %s: %w", coll, err)
	}
	ch := make(chan *dbus.Signal, 16)
	c.conn.Signal(ch)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range ch {
			if sig.Path == coll && strings.HasPrefix(sig.Name, ifaceCollection+".Item") {
				changed()
			}
		}
	}()
	return func() {
		c.conn.RemoveSignal(ch)
		_ = c.conn.RemoveMatchSignal(match...)
		close(ch)
		<-done
	}, nil
}
