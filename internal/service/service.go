// Package service serves the freedesktop Secret Service API
// (org.freedesktop.secrets) over keyring collections stored encrypted in
// a directory: sessions with plain and DH transport, collections and
// items with their properties and signals, aliases, and prompts that ask
// the user through a Prompter.
//
// Every client on the user's bus may read an unlocked collection, as
// with gnome-keyring; sandboxed apps reach their secrets through the
// portal instead, which identifies them.
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/control"
	"github.com/stubbedev/lys-secrets/internal/keyring"
)

// D-Bus names of the API.
const (
	BusName         = "org.freedesktop.secrets"
	rootPath        = dbus.ObjectPath("/org/freedesktop/secrets")
	collectionBase  = "/org/freedesktop/secrets/collection/"
	aliasBase       = "/org/freedesktop/secrets/aliases/"
	sessionBase     = "/org/freedesktop/secrets/session/"
	promptBase      = "/org/freedesktop/secrets/prompt/"
	noPrompt        = dbus.ObjectPath("/")
	ifaceService    = "org.freedesktop.Secret.Service"
	ifaceCollection = "org.freedesktop.Secret.Collection"
	ifaceItem       = "org.freedesktop.Secret.Item"
	ifaceSession    = "org.freedesktop.Secret.Session"
	ifacePrompt     = "org.freedesktop.Secret.Prompt"
	propItemLabel   = "org.freedesktop.Secret.Item.Label"
	propItemAttrs   = "org.freedesktop.Secret.Item.Attributes"
	propCollLabel   = "org.freedesktop.Secret.Collection.Label"
	errIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
	errNoSession    = "org.freedesktop.Secret.Error.NoSession"
	errNoSuchObject = "org.freedesktop.Secret.Error.NoSuchObject"
	errNotSupported = "org.freedesktop.DBus.Error.NotSupported"
)

// LoginID is the collection the login password unlocks; the default
// alias points at it unless set otherwise.
const LoginID = "login"

// Secret is the API's Secret struct, (oayays).
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Prompter asks the user for passwords. ok is false when they dismissed
// the prompt; ctx ends when the client dismisses it.
type Prompter interface {
	// Password asks for an existing collection's password; retry says
	// the previous attempt was wrong.
	Password(ctx context.Context, collection string, retry bool) (password []byte, ok bool, err error)
	// NewPassword asks for a new password for a collection, typed twice.
	NewPassword(ctx context.Context, collection string) (password []byte, ok bool, err error)
	// MasterPassword asks for the Bitwarden vault's master password;
	// retry says the previous attempt was wrong.
	MasterPassword(ctx context.Context, retry bool) (password []byte, ok bool, err error)
}

// Config is what Start needs.
type Config struct {
	// Dir holds the collection files.
	Dir      string
	KDF      keyring.KDF
	Prompter Prompter
	Now      func() time.Time
	// Vault, when set, is shown as the read-only VaultID collection.
	Vault Vault
}

// Service is a running Secret Service.
type Service struct {
	conn *dbus.Conn
	cfg  Config
	disk disk

	mu       sync.Mutex
	colls    map[string]*collection
	aliases  map[string]string
	aliasOff map[string]func()
	sessions map[dbus.ObjectPath]*session
	prompts  map[dbus.ObjectPath]func()
	nextID   uint64
	closed   bool
	// stops undo, in reverse, what Start set up beyond the collections,
	// aliases, vault, sessions and prompts: the root object, the
	// missing-collection subtrees, the owner watch and the bus name.
	stops []func()
	// vault is the vault collection, nil without a Config.Vault.
	vault *vaultColl
}

type collection struct {
	id    string
	kr    *keyring.Collection
	off   func()
	items map[uint32]func()
}

// unexport takes the collection and its items off the connection.
func (c *collection) unexport() {
	for id, off := range c.items {
		off()
		delete(c.items, id)
	}
	if c.off != nil {
		c.off()
		c.off = nil
	}
}

type session struct {
	owner string
	t     transport
	off   func()
}

// Start loads the collections in cfg.Dir, exports them on conn and takes
// the bus name. A name another provider holds is dbusx.ErrNameTaken:
// the service never queues for it or replaces the owner. A failed Start
// leaves nothing exported or watched on conn.
func Start(conn *dbus.Conn, cfg Config) (*Service, error) {
	s := &Service{
		conn: conn, cfg: cfg, disk: disk{dir: cfg.Dir},
		colls: map[string]*collection{}, aliasOff: map[string]func(){},
		sessions: map[dbus.ObjectPath]*session{}, prompts: map[dbus.ObjectPath]func(){},
	}
	var err error
	if s.aliases, err = s.disk.loadAliases(); err != nil {
		return nil, err
	}
	ids, err := s.disk.ids()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		data, err := s.disk.load(id)
		if err != nil {
			return nil, err
		}
		kr, err := keyring.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("collection %s: %w", id, err)
		}
		s.colls[id] = &collection{id: id, kr: kr, items: map[uint32]func(){}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.serveLocked(); err != nil {
		s.withdrawLocked()
		return nil, err
	}
	return s, nil
}

// serveLocked exports the service, its collections, aliases and vault,
// watches for clients leaving and takes the bus name last.
func (s *Service) serveLocked() error {
	off, err := dbusx.Export(s.conn, rootPath, dbusx.Interface{
		Name: ifaceService, Methods: serviceMethods{s},
		Properties: dbusx.Getters{"Collections": s.collectionPathsLocked},
	})
	if err != nil {
		return err
	}
	s.stops = append(s.stops, off)
	for _, base := range []string{aliasBase, collectionBase} {
		path := dbus.ObjectPath(strings.TrimSuffix(base, "/"))
		if err := s.conn.ExportSubtree(missingCollection{}, path, ifaceCollection); err != nil {
			return fmt.Errorf("export the missing-collection fallback: %w", err)
		}
		s.stops = append(s.stops, func() { _ = s.conn.Export(nil, path, ifaceCollection) })
	}
	for _, c := range s.colls {
		if err := s.exportCollectionLocked(c); err != nil {
			return err
		}
	}
	for alias := range s.aliases {
		if err := s.exportAliasLocked(alias); err != nil {
			return err
		}
	}
	if s.cfg.Vault != nil {
		if err := s.startVaultLocked(s.cfg.Vault); err != nil {
			return fmt.Errorf("the vault collection: %w", err)
		}
	}
	if err := s.watchOwners(); err != nil {
		return err
	}
	release, err := dbusx.Own(s.conn, BusName)
	if err != nil {
		return err
	}
	s.stops = append(s.stops, release)
	return nil
}

// withdrawLocked gives up the bus name, stops the owner watch and
// unexports every object the service put on its connection.
func (s *Service) withdrawLocked() {
	for _, stop := range slices.Backward(s.stops) {
		stop()
	}
	s.stops = nil
	for _, c := range s.colls {
		c.unexport()
	}
	for alias, off := range s.aliasOff {
		off()
		delete(s.aliasOff, alias)
	}
	if vc := s.vault; vc != nil {
		for p, off := range vc.items {
			off()
			delete(vc.items, p)
		}
		vc.off()
	}
	for path := range s.sessions {
		s.closeSessionLocked(path)
	}
	for path, off := range s.prompts {
		off()
		delete(s.prompts, path)
	}
}

// Close destroys every collection's key, gives up the bus name and
// unexports everything Start exported. Every change is on disk already,
// so nothing is sealed on the way out.
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, c := range s.colls {
		c.kr.Destroy()
	}
	s.withdrawLocked()
}

func (s *Service) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// UnlockLogin unlocks the login collection with the password the user
// logged in or unlocked the session with, creating it with that password
// on first use and pointing the default alias at it when none is set. A
// wrong password matches both control.ErrWrongPassword and
// keyring.ErrWrongPassword, and leaves it locked.
func (s *Service) UnlockLogin(password []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.colls[LoginID]; ok {
		err := c.kr.Unlock(password)
		if errors.Is(err, keyring.ErrWrongPassword) {
			return fmt.Errorf("%w: %w", control.ErrWrongPassword, err)
		}
		if err != nil {
			return err
		}
		s.emitLocked(rootPath, ifaceService+".CollectionChanged", collectionPath(LoginID))
		return nil
	}
	kr, err := keyring.New("Login", password, s.cfg.KDF, s.now())
	if err != nil {
		return err
	}
	if err := s.addCollectionLocked(LoginID, kr); err != nil {
		return err
	}
	if _, ok := s.aliases["default"]; !ok {
		return s.setAliasLocked("default", LoginID)
	}
	return nil
}

// Lock locks every collection, the vault's too.
func (s *Service) Lock() {
	s.mu.Lock()
	for _, c := range s.colls {
		s.lockCollectionLocked(c)
	}
	vc := s.vault
	s.mu.Unlock()
	if vc != nil {
		vc.v.Lock()
	}
}

func collectionPath(id string) dbus.ObjectPath { return dbus.ObjectPath(collectionBase + id) }

func itemPath(cid string, iid uint32) dbus.ObjectPath {
	return dbus.ObjectPath(collectionBase + cid + "/" + strconv.FormatUint(uint64(iid), 10))
}

// resolve maps a collection, alias or item path to its collection and
// item (0 for the collection itself).
func (s *Service) resolveLocked(p dbus.ObjectPath) (*collection, uint32, bool) {
	str := string(p)
	if alias, ok := strings.CutPrefix(str, aliasBase); ok {
		c, ok := s.colls[s.aliases[alias]]
		return c, 0, ok
	}
	rest, ok := strings.CutPrefix(str, collectionBase)
	if !ok {
		return nil, 0, false
	}
	cid, item, hasItem := strings.Cut(rest, "/")
	c, ok := s.colls[cid]
	if !ok {
		return nil, 0, false
	}
	if !hasItem {
		return c, 0, true
	}
	n, err := strconv.ParseUint(item, 10, 32)
	if err != nil || n == 0 {
		return nil, 0, false
	}
	if _, err := c.kr.Item(uint32(n)); err != nil {
		return nil, 0, false
	}
	return c, uint32(n), true
}

func (s *Service) collectionPathsLocked() any {
	out := make([]dbus.ObjectPath, 0, len(s.colls)+1)
	for _, id := range slices.Sorted(maps.Keys(s.colls)) {
		out = append(out, collectionPath(id))
	}
	if s.vault != nil {
		out = append(out, collectionPath(VaultID))
		slices.Sort(out)
	}
	return out
}

// The property getters run under the D-Bus dispatch; they take the lock
// themselves.
func (s *Service) locked(fn func() any) func() any {
	return func() any {
		s.mu.Lock()
		defer s.mu.Unlock()
		return fn()
	}
}

func (s *Service) emitLocked(path dbus.ObjectPath, name string, args ...any) {
	if err := s.conn.Emit(path, name, args...); err != nil {
		log.Printf("secrets: emit %s: %v", name, err)
	}
}

func (s *Service) saveLocked(c *collection) error {
	data, err := c.kr.Marshal()
	if err != nil {
		return err
	}
	if err := s.disk.save(c.id, data); err != nil {
		return fmt.Errorf("save collection %s: %w", c.id, err)
	}
	return nil
}

func (s *Service) addCollectionLocked(id string, kr *keyring.Collection) error {
	c := &collection{id: id, kr: kr, items: map[uint32]func(){}}
	if err := s.saveLocked(c); err != nil {
		return err
	}
	s.colls[id] = c
	if err := s.exportCollectionLocked(c); err != nil {
		return err
	}
	s.emitLocked(rootPath, ifaceService+".CollectionCreated", collectionPath(id))
	return nil
}

func (s *Service) collectionIface(c *collection) dbusx.Interface {
	return dbusx.Interface{
		Name: ifaceCollection, Methods: collectionMethods{s, c.id},
		Properties: dbusx.Getters{
			"Items": s.locked(func() any {
				out := []dbus.ObjectPath{}
				for _, id := range c.kr.IDs() {
					out = append(out, itemPath(c.id, id))
				}
				return out
			}),
			"Label":    s.locked(func() any { return c.kr.Label() }),
			"Locked":   s.locked(func() any { return c.kr.Locked() }),
			"Created":  s.locked(func() any { return unixSeconds(c.kr.Created()) }),
			"Modified": s.locked(func() any { return unixSeconds(c.kr.Modified()) }),
		},
		Setters: dbusx.Setters{"Label": func(v dbus.Variant) *dbus.Error {
			label, ok := v.Value().(string)
			if !ok {
				return dbusx.InvalidArgs("Label is a string")
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := c.kr.SetLabel(label, s.now()); err != nil {
				return lockedErr(err)
			}
			if err := s.saveLocked(c); err != nil {
				return dbusx.Failed(err.Error())
			}
			s.emitLocked(rootPath, ifaceService+".CollectionChanged", collectionPath(c.id))
			return nil
		}},
	}
}

func (s *Service) exportCollectionLocked(c *collection) error {
	off, err := dbusx.Export(s.conn, collectionPath(c.id), s.collectionIface(c))
	if err != nil {
		return fmt.Errorf("export collection %s: %w", c.id, err)
	}
	c.off = off
	for _, id := range c.kr.IDs() {
		if err := s.exportItemLocked(c, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) exportAliasLocked(alias string) error {
	if off := s.aliasOff[alias]; off != nil {
		off()
		delete(s.aliasOff, alias)
	}
	c, ok := s.colls[s.aliases[alias]]
	if !ok {
		return nil
	}
	off, err := dbusx.Export(s.conn, dbus.ObjectPath(aliasBase+alias), s.collectionIface(c))
	if err != nil {
		return fmt.Errorf("export alias %s: %w", alias, err)
	}
	s.aliasOff[alias] = off
	return nil
}

func (s *Service) setAliasLocked(alias, id string) error {
	if id == "" {
		delete(s.aliases, alias)
	} else {
		s.aliases[alias] = id
	}
	if err := s.disk.saveAliases(s.aliases); err != nil {
		return err
	}
	return s.exportAliasLocked(alias)
}

func (s *Service) exportItemLocked(c *collection, id uint32) error {
	item := func(read func(keyring.Item) any) func() any {
		return s.locked(func() any {
			it, _ := c.kr.Item(id)
			return read(it)
		})
	}
	off, err := dbusx.Export(s.conn, itemPath(c.id, id), dbusx.Interface{
		Name: ifaceItem, Methods: itemMethods{s, c.id, id},
		Properties: dbusx.Getters{
			"Locked": s.locked(func() any { return c.kr.Locked() }),
			"Label":  item(func(it keyring.Item) any { return it.Label }),
			"Attributes": item(func(it keyring.Item) any {
				if it.Attributes == nil {
					return map[string]string{}
				}
				return it.Attributes
			}),
			"Created":  item(func(it keyring.Item) any { return unixSeconds(it.Created) }),
			"Modified": item(func(it keyring.Item) any { return unixSeconds(it.Modified) }),
		},
		Setters: dbusx.Setters{
			"Label": s.itemSetter(c, id, func(v dbus.Variant) (func() error, *dbus.Error) {
				label, ok := v.Value().(string)
				if !ok {
					return nil, dbusx.InvalidArgs("Label is a string")
				}
				return func() error { return c.kr.SetItemLabel(id, label, s.now()) }, nil
			}),
			"Attributes": s.itemSetter(c, id, func(v dbus.Variant) (func() error, *dbus.Error) {
				attrs, ok := v.Value().(map[string]string)
				if !ok {
					return nil, dbusx.InvalidArgs("Attributes is a{ss}")
				}
				return func() error { return c.kr.SetItemAttributes(id, attrs, s.now()) }, nil
			}),
		},
	})
	if err != nil {
		return fmt.Errorf("export item %s/%d: %w", c.id, id, err)
	}
	c.items[id] = off
	return nil
}

func (s *Service) itemSetter(c *collection, id uint32, decode func(dbus.Variant) (func() error, *dbus.Error)) func(dbus.Variant) *dbus.Error {
	return func(v dbus.Variant) *dbus.Error {
		apply, derr := decode(v)
		if derr != nil {
			return derr
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := apply(); err != nil {
			return lockedErr(err)
		}
		if err := s.saveLocked(c); err != nil {
			return dbusx.Failed(err.Error())
		}
		s.emitLocked(collectionPath(c.id), ifaceCollection+".ItemChanged", itemPath(c.id, id))
		return nil
	}
}

func (s *Service) lockCollectionLocked(c *collection) {
	if c.kr.Locked() {
		return
	}
	if err := c.kr.Lock(); err != nil {
		log.Printf("secrets: lock collection %s: its key is destroyed, but it opens again only after a restart: %v", c.id, err)
	}
	s.emitLocked(rootPath, ifaceService+".CollectionChanged", collectionPath(c.id))
}

// watchOwners closes a client's sessions when it leaves the bus, until
// the stop it adds to s.stops runs.
func (s *Service) watchOwners() error {
	match := []dbus.MatchOption{
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
	}
	if err := s.conn.AddMatchSignal(match...); err != nil {
		return fmt.Errorf("watch bus clients: %w", err)
	}
	signals := make(chan *dbus.Signal, 64)
	done := make(chan struct{})
	s.conn.Signal(signals)
	s.stops = append(s.stops, func() {
		s.conn.RemoveSignal(signals)
		_ = s.conn.RemoveMatchSignal(match...)
		close(done)
	})
	go s.closeSessionsOfLeavers(signals, done)
	return nil
}

func (s *Service) closeSessionsOfLeavers(signals <-chan *dbus.Signal, done <-chan struct{}) {
	for {
		var sig *dbus.Signal
		select {
		case <-done:
			return
		case got, ok := <-signals:
			if !ok {
				return
			}
			sig = got
		}
		if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
			continue
		}
		name, _ := sig.Body[0].(string)
		newOwner, _ := sig.Body[2].(string)
		if newOwner != "" || !strings.HasPrefix(name, ":") {
			continue
		}
		s.mu.Lock()
		for path, sess := range s.sessions {
			if sess.owner == name {
				s.closeSessionLocked(path)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Service) closeSessionLocked(path dbus.ObjectPath) {
	sess, ok := s.sessions[path]
	if !ok {
		return
	}
	delete(s.sessions, path)
	sess.off()
}

func (s *Service) newPathLocked(base string) dbus.ObjectPath {
	s.nextID++
	return dbus.ObjectPath(base + strconv.FormatUint(s.nextID, 10))
}

func (s *Service) sessionLocked(path dbus.ObjectPath, sender dbus.Sender) (*session, *dbus.Error) {
	sess, ok := s.sessions[path]
	if !ok || sess.owner != string(sender) {
		return nil, dbus.NewError(errNoSession, []any{"no session " + string(path)})
	}
	return sess, nil
}

// secretLocked is item id's secret, encoded for sess.
func (s *Service) secretLocked(c *collection, id uint32, sessPath dbus.ObjectPath, sess *session) (Secret, *dbus.Error) {
	value, err := c.kr.Secret(id)
	if err != nil {
		return Secret{}, lockedErr(err)
	}
	defer clear(value)
	it, _ := c.kr.Item(id)
	params, enc, err := sess.t.encode(value)
	if err != nil {
		return Secret{}, dbusx.Failed("encode the secret: " + err.Error())
	}
	contentType := it.ContentType
	if contentType == "" {
		contentType = "text/plain"
	}
	return Secret{Session: sessPath, Parameters: params, Value: enc, ContentType: contentType}, nil
}

func lockedErr(err error) *dbus.Error {
	switch {
	case errors.Is(err, keyring.ErrLocked):
		return dbus.NewError(errIsLocked, []any{"the collection is locked"})
	case errors.Is(err, keyring.ErrNoItem):
		return dbus.NewError(errNoSuchObject, []any{"no such item"})
	}
	return dbusx.Failed(err.Error())
}

func noSuchObject(p dbus.ObjectPath) *dbus.Error {
	return dbus.NewError(errNoSuchObject, []any{"no such object " + string(p)})
}

func unixSeconds(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(max(t.Unix(), 0))
}
