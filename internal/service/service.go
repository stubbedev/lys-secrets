// Package service serves the freedesktop Secret Service API
// (org.freedesktop.secrets) over keyring collections stored encrypted in
// a directory: sessions with plain and DH transport, collections and
// items with their properties and signals, aliases, and prompts that ask
// the user through a Prompter.
//
// Every client on the user's bus may read an unlocked collection, as
// with gnome-keyring, unless reads are confirmed: then a program reading
// an item it does not own sees it locked, and its Unlock prompt asks the
// user. Sandboxed apps reach their secrets through the portal instead,
// which identifies them.
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

	"github.com/stubbedev/lys-lib/atomicfile"
	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/control"
	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/secretbus"
	"github.com/stubbedev/lys-secrets/transport"
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

// idleCheckEvery bounds how late Config.LockAfter acts after a suspend,
// which timers do not count and the wall clock does.
const idleCheckEvery = 30 * time.Second

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
	// ConfirmRead asks whether a program may read an item it does not own.
	ConfirmRead(ctx context.Context, r ReadRequest) (Access, error)
	// PreviousLoginPassword asks for the login password from before it
	// changed, to move the login collection to the new one; ok is false
	// when the user keeps the old password apart. retry says the previous
	// attempt was wrong.
	PreviousLoginPassword(ctx context.Context, retry bool) (password []byte, ok bool, err error)
}

// Config is what Start needs.
type Config struct {
	// Dir holds the collection files.
	Dir string
	KDF keyring.KDF
	// Stretch derives keys from passwords, off the service's lock.
	Stretch  keyring.Stretch
	Prompter Prompter
	Now      func() time.Time
	// Vault, when set, locks with LockService, and shows as a collection
	// if it says so.
	Vault Vault
	// LockAfter locks a collection once no secret was read from it and
	// nothing in it changed for this long; 0 never does.
	LockAfter time.Duration
	// ConfirmForeignReads asks the user before a program reads an item it
	// does not own.
	ConfirmForeignReads bool
	// Locked, when set, runs each time a collection locks, with its id, under
	// the service's lock: it must not call back into the Service.
	Locked func(id string)
}

// Service is a running Secret Service.
type Service struct {
	conn *dbus.Conn
	cfg  Config
	disk disk
	// signals sends what the service emits, off its lock.
	signals *signalQueue

	// loginMu keeps two logins from creating the login collection at once,
	// and a re-key from racing either.
	loginMu sync.Mutex
	// rekey is the question a login password that does not open the login
	// collection raises.
	rekey rekeyOffer
	// aliasWriter is held across a change of the alias table, its write and its
	// commit, so the table a reader sees is always the one on disk.
	aliasWriter sync.Mutex

	mu    sync.Mutex
	colls map[string]*collection
	// reserved are ids of collections being written for the first time.
	reserved map[string]struct{}
	aliases  map[string]string
	aliasOff map[string]func()
	sessions map[dbus.ObjectPath]*session
	prompts  map[dbus.ObjectPath]func()
	// clients names the program behind each bus connection.
	peers *peers
	// grants are the items each connection was allowed to read once, by
	// unique name, kept until it leaves or the collection locks.
	grants map[string]map[itemRef]struct{}
	nextID uint64
	closed bool
	// stops undo, in reverse, what Start set up beyond the collections,
	// aliases, vault, sessions and prompts: the root object, the
	// missing-collection subtrees, the watch of clients leaving and the
	// bus name.
	stops []func()
	// leavers is the watch of clients leaving the bus, nil until Start
	// has set it up.
	leavers *dbusx.Watch
	// vault is the vault collection, nil unless Config.Vault shows as one.
	vault *vaultColl
	// idle is the pending check of Config.LockAfter, nil with no collection
	// unlocked.
	idle *time.Timer
}

type collection struct {
	id string
	// writer is held across whatever changes the collection's file, from the
	// change through its write to its commit: writes are in order, two unlocks do
	// not each pay for the KDF, and a delete waits for a change in flight.
	writer sync.Mutex
	kr     *keyring.Collection
	off    func()
	items  map[uint32]func()
	// lastUse is when a secret was last read or anything changed, in wall
	// clock time, kept only under Config.LockAfter.
	lastUse time.Time
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
	t     transport.Transport
	off   func()
}

// Start loads the collections in cfg.Dir, exports them on conn and takes
// the bus name. A name another provider holds is dbusx.ErrNameTaken:
// the service never queues for it or replaces the owner. A failed Start
// leaves nothing exported or watched on conn.
func Start(conn *dbus.Conn, cfg Config) (*Service, error) {
	if cfg.Stretch == nil {
		return nil, errors.New("start the secret service: no Stretch to derive keys with")
	}
	s := &Service{
		conn: conn, cfg: cfg, disk: disk{dir: cfg.Dir, write: atomicfile.WriteFile},
		colls: map[string]*collection{}, reserved: map[string]struct{}{}, aliasOff: map[string]func(){},
		sessions: map[dbus.ObjectPath]*session{}, prompts: map[dbus.ObjectPath]func(){},
		peers: newPeers(conn), grants: map[string]map[itemRef]struct{}{},
		signals: newSignalQueue(),
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
	err = s.serveLocked()
	if err != nil {
		s.withdrawLocked()
	}
	s.mu.Unlock()
	if err != nil {
		return nil, errors.Join(err, s.stopWatchingLeavers())
	}
	return s, nil
}

// serveLocked exports the service, its collections, aliases and vault,
// watches for clients leaving and takes the bus name last.
func (s *Service) serveLocked() error {
	off, err := dbusx.Export(s.conn, rootPath, dbusx.Interface{
		Name: secretbus.ServiceInterface, Methods: serviceMethods{s},
		Properties: dbusx.Getters{"Collections": s.collectionPathsLocked},
		Signals:    []dbusx.SignalDecl{secretbus.CollectionCreated, secretbus.CollectionDeleted, secretbus.CollectionChanged},
	})
	if err != nil {
		return err
	}
	s.stops = append(s.stops, off)
	for _, base := range []string{aliasBase, collectionBase} {
		path := dbus.ObjectPath(strings.TrimSuffix(base, "/"))
		if err := s.conn.ExportSubtree(missingCollection{}, path, secretbus.CollectionInterface); err != nil {
			return fmt.Errorf("export the missing-collection fallback: %w", err)
		}
		s.stops = append(s.stops, func() { _ = s.conn.Export(nil, path, secretbus.CollectionInterface) })
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
	if s.cfg.Vault != nil && s.cfg.Vault.Shown() {
		if err := s.startVaultLocked(s.cfg.Vault); err != nil {
			return fmt.Errorf("the vault collection: %w", err)
		}
	}
	if err := s.watchLeavers(); err != nil {
		return err
	}
	release, err := dbusx.Own(s.conn, BusName)
	if err != nil {
		return err
	}
	s.stops = append(s.stops, release)
	return nil
}

// withdrawLocked gives up the bus name, cancels the watch of clients
// leaving and unexports every object the service put on its connection.
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
	if s.closed {
		s.mu.Unlock()
		return
	}
	defer s.signals.drain(time.After(signalDrainWait))
	defer func() {
		if err := s.stopWatchingLeavers(); err != nil {
			log.Printf("secrets: %v", err)
		}
	}()
	defer s.mu.Unlock()
	s.closed = true
	s.dropRekey()
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
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
// keyring.ErrWrongPassword, and leaves it locked: the login password
// changed, so the user is asked once for the previous one, to move the
// collection to this one.
func (s *Service) UnlockLogin(password []byte) error {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.mu.Lock()
	c, ok := s.colls[LoginID]
	_, aliased := s.aliases["default"]
	s.mu.Unlock()
	if ok {
		err := s.unlock(c, password)
		switch {
		case errors.Is(err, keyring.ErrWrongPassword):
			s.offerRekey(password)
			return fmt.Errorf("%w: %w", control.ErrWrongPassword, err)
		case err == nil:
			s.dropRekey()
		}
		return err
	}
	kr, err := keyring.New("Login", password, s.cfg.KDF, s.cfg.Stretch, s.now())
	if err != nil {
		return err
	}
	if _, err := s.addCollection(func(func(string) bool) string { return LoginID }, kr); err != nil {
		return err
	}
	if !aliased {
		return s.setAlias("default", LoginID)
	}
	return nil
}

// unlock unlocks c and announces it, rewriting a file of the first format so it
// can tell a wrong password from a changed file from now on. A failed rewrite
// costs only that, so it does not fail the unlock. The lock is free while the
// key is derived, which is what makes it take as long as it does, and while the
// file is written; a second unlock of c waits for the first and pays nothing if
// that one worked.
func (s *Service) unlock(c *collection, password []byte) error {
	c.writer.Lock()
	defer c.writer.Unlock()
	s.mu.Lock()
	if s.colls[c.id] != c {
		s.mu.Unlock()
		return fmt.Errorf("unlock collection %s: %w", c.id, keyring.ErrChanged)
	}
	if !c.kr.Locked() {
		s.mu.Unlock()
		return nil
	}
	legacy := c.kr.Legacy()
	opening, err := c.kr.BeginUnlock()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.finishUnlock(c, password, opening, legacy)
}

func (s *Service) finishUnlock(c *collection, password []byte, opening *keyring.Opening, legacy bool) error {
	opened, err := opening.Open(password, s.cfg.Stretch)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		opened.Discard()
		return keyring.ErrChanged
	}
	if err := c.kr.FinishUnlock(opened); err != nil {
		s.mu.Unlock()
		return err
	}
	var rewrite []byte
	if legacy {
		if rewrite, err = c.kr.Marshal(); err != nil {
			log.Printf("secrets: rewrite collection %s in the current format: %v", c.id, err)
		}
	}
	s.usedLocked(c)
	s.mu.Unlock()
	if rewrite != nil {
		if err := s.saveCollection(c.id, rewrite); err != nil {
			log.Printf("secrets: rewrite collection %s in the current format: %v", c.id, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	emit(s, secretbus.CollectionChanged, rootPath, secretbus.CollectionEvent{Collection: collectionPath(c.id)})
	return nil
}

// usedLocked restarts c's idle clock and makes sure a check is pending.
func (s *Service) usedLocked(c *collection) {
	if s.cfg.LockAfter == 0 {
		return
	}
	c.lastUse = s.now().Round(0)
	s.armIdleLocked()
}

// armIdleLocked schedules the next idle check when one is due and none is
// pending, leaving nothing to wake up for with every collection locked.
func (s *Service) armIdleLocked() {
	if s.idle != nil || s.closed {
		return
	}
	if wait, ok := s.nextIdleCheckLocked(s.now().Round(0)); ok {
		s.idle = time.AfterFunc(wait, s.lockIdle)
	}
}

// nextIdleCheckLocked is how long until the unlocked collection closest to
// its idle time gets there, capped at idleCheckEvery; false with none
// unlocked.
func (s *Service) nextIdleCheckLocked(now time.Time) (time.Duration, bool) {
	wait, unlocked := idleCheckEvery, false
	for _, c := range s.colls {
		if !c.kr.Locked() {
			unlocked = true
			wait = min(wait, max(c.lastUse.Add(s.cfg.LockAfter).Sub(now), 0))
		}
	}
	return wait, unlocked
}

// lockIdle locks the collections past their idle time and schedules the
// next check.
func (s *Service) lockIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idle = nil
	if s.closed {
		return
	}
	now := s.now().Round(0)
	for _, c := range s.colls {
		if !c.kr.Locked() && !now.Before(c.lastUse.Add(s.cfg.LockAfter)) {
			s.lockCollectionLocked(c)
		}
	}
	s.armIdleLocked()
}

// LockCollections locks every collection, leaving the vault as it is.
func (s *Service) LockCollections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.colls {
		s.lockCollectionLocked(c)
	}
}

// Lock locks every collection and the vault, whether or not the vault
// shows as a collection.
func (s *Service) Lock() {
	s.LockCollections()
	if s.cfg.Vault != nil {
		s.cfg.Vault.Lock()
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

func (s *Service) saveCollection(id string, data []byte) error {
	if err := s.disk.save(id, data); err != nil {
		return fmt.Errorf("save collection %s: %w", id, err)
	}
	return nil
}

// errGone is a change to a collection deleted or closed before it could apply.
var errGone = errors.New("the collection is gone")

// change applies a change to a copy of c under the lock and makes that durable
// with the lock free, so a slow disk holds nobody else up, while every reader goes
// on seeing c as it is on disk. Only then does the copy become c and is the change
// announced, so nobody reads a change a crash could still undo, and a reply built on
// the result promises what it always promised. A collection locked during the
// write is left locked, as it is now on disk.
func (s *Service) change(c *collection, apply func(kr *keyring.Collection) error, announce func() error) error {
	c.writer.Lock()
	defer c.writer.Unlock()
	s.mu.Lock()
	if s.closed || s.colls[c.id] != c {
		s.mu.Unlock()
		return fmt.Errorf("change collection %s: %w", c.id, errGone)
	}
	if c.kr.Locked() {
		s.mu.Unlock()
		return keyring.ErrLocked
	}
	base := c.kr
	next := base.Clone()
	if err := apply(next); err != nil {
		s.mu.Unlock()
		base.Discard(next)
		return err
	}
	data, err := next.Marshal()
	s.mu.Unlock()
	if err == nil {
		err = s.saveCollection(c.id, data)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		base.Discard(next)
		return err
	}
	if s.closed {
		base.Discard(next)
		return nil
	}
	if base.Locked() {
		base.Discard(next)
		next.Destroy()
		locked, perr := keyring.Parse(data)
		if perr != nil {
			return fmt.Errorf("collection %s, locked while its change was written: %w", c.id, perr)
		}
		c.kr = locked
	} else {
		base.Commit(next)
		c.kr = next
	}
	s.usedLocked(c)
	return announce()
}

func nothingToAnnounce() error { return nil }

// addCollection writes a new collection under an id pick chooses and only then
// shows it. The id is reserved meanwhile.
func (s *Service) addCollection(pick func(taken func(string) bool) string, kr *keyring.Collection) (string, error) {
	s.mu.Lock()
	taken := func(id string) bool {
		_, ok := s.colls[id]
		_, writing := s.reserved[id]
		return ok || writing
	}
	id := pick(taken)
	if taken(id) {
		s.mu.Unlock()
		return "", fmt.Errorf("add collection %s: it is being created already", id)
	}
	s.reserved[id] = struct{}{}
	c := &collection{id: id, kr: kr, items: map[uint32]func(){}}
	data, err := kr.Marshal()
	s.mu.Unlock()
	if err == nil {
		err = s.saveCollection(id, data)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.reserved, id)
	if err != nil {
		return "", err
	}
	s.colls[id] = c
	s.usedLocked(c)
	if err := s.exportCollectionLocked(c); err != nil {
		return "", err
	}
	emit(s, secretbus.CollectionCreated, rootPath, secretbus.CollectionEvent{Collection: collectionPath(id)})
	return id, nil
}

var collectionSignals = []dbusx.SignalDecl{secretbus.ItemCreated, secretbus.ItemDeleted, secretbus.ItemChanged}

func (s *Service) collectionIface(c *collection) dbusx.Interface {
	return dbusx.Interface{
		Name: secretbus.CollectionInterface, Methods: collectionMethods{s, c.id},
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
		Signals: collectionSignals,
		Setters: dbusx.Setters{"Label": func(v dbus.Variant) *dbus.Error {
			label, ok := v.Value().(string)
			if !ok {
				return dbusx.InvalidArgs("Label is a string")
			}
			err := s.change(c, func(kr *keyring.Collection) error { return kr.SetLabel(label, s.now()) }, func() error {
				emit(s, secretbus.CollectionChanged, rootPath, secretbus.CollectionEvent{Collection: collectionPath(c.id)})
				return nil
			})
			if err != nil {
				return lockedErr(err)
			}
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

// setAlias points alias at id, or removes it with "".
func (s *Service) setAlias(alias, id string) error {
	return s.changeAliases([]string{alias}, func(aliases map[string]string) {
		if id == "" {
			delete(aliases, alias)
		} else {
			aliases[alias] = id
		}
	})
}

// changeAliases applies a change to a copy of the alias table, makes that durable
// with the lock free, then makes it the table and exports the aliases it names:
// nobody reads an alias a crash could still undo.
func (s *Service) changeAliases(names []string, apply func(aliases map[string]string)) error {
	s.aliasWriter.Lock()
	defer s.aliasWriter.Unlock()
	s.mu.Lock()
	next := maps.Clone(s.aliases)
	s.mu.Unlock()
	apply(next)
	data, err := encodeAliases(next)
	if err != nil {
		return err
	}
	if err := s.disk.saveAliases(data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.aliases = next
	var errs []error
	for _, alias := range names {
		errs = append(errs, s.exportAliasLocked(alias))
	}
	return errors.Join(errs...)
}

func (s *Service) exportItemLocked(c *collection, id uint32) error {
	item := func(read func(keyring.Item) any) func() any {
		return s.locked(func() any {
			it, _ := c.kr.Item(id)
			return read(it)
		})
	}
	off, err := dbusx.Export(s.conn, itemPath(c.id, id), dbusx.Interface{
		Name: secretbus.ItemInterface, Methods: itemMethods{s, c.id, id},
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
			"Label": s.itemSetter(c, id, func(v dbus.Variant) (func(*keyring.Collection) error, *dbus.Error) {
				label, ok := v.Value().(string)
				if !ok {
					return nil, dbusx.InvalidArgs("Label is a string")
				}
				return func(kr *keyring.Collection) error { return kr.SetItemLabel(id, label, s.now()) }, nil
			}),
			"Attributes": s.itemSetter(c, id, func(v dbus.Variant) (func(*keyring.Collection) error, *dbus.Error) {
				attrs, ok := v.Value().(map[string]string)
				if !ok {
					return nil, dbusx.InvalidArgs("Attributes is a{ss}")
				}
				return func(kr *keyring.Collection) error { return kr.SetItemAttributes(id, attrs, s.now()) }, nil
			}),
		},
	})
	if err != nil {
		return fmt.Errorf("export item %s/%d: %w", c.id, id, err)
	}
	c.items[id] = off
	return nil
}

func (s *Service) itemSetter(c *collection, id uint32, decode func(dbus.Variant) (func(*keyring.Collection) error, *dbus.Error)) func(dbus.Variant) *dbus.Error {
	return func(v dbus.Variant) *dbus.Error {
		apply, derr := decode(v)
		if derr != nil {
			return derr
		}
		err := s.change(c, apply, func() error {
			emit(s, secretbus.ItemChanged, collectionPath(c.id), secretbus.ItemEvent{Item: itemPath(c.id, id)})
			return nil
		})
		if err != nil {
			return lockedErr(err)
		}
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
	s.dropGrantsLocked(c.id)
	if s.cfg.Locked != nil {
		s.cfg.Locked(c.id)
	}
	emit(s, secretbus.CollectionChanged, rootPath, secretbus.CollectionEvent{Collection: collectionPath(c.id)})
}

const (
	messageBus = "org.freedesktop.DBus"
	busPath    = dbus.ObjectPath("/org/freedesktop/DBus")
)

type ownerChange struct {
	Name     string `dbus:"name"`
	OldOwner string `dbus:"old_owner"`
	NewOwner string `dbus:"new_owner"`
}

var nameOwnerChanged = dbusx.NewSignal[ownerChange](messageBus, "NameOwnerChanged")

// watchLeavers closes a client's sessions when it leaves the bus. The
// stop it adds to s.stops only cancels the watch, since its handler
// takes s.mu, which the stops run under; stopWatchingLeavers, called
// without s.mu, waits for it to end.
func (s *Service) watchLeavers() error {
	watching, cancel := context.WithCancel(context.Background())
	w, err := dbusx.WatchSignals(watching, s.conn, dbusx.FromBus(),
		func(err error) { log.Printf("secrets: watch bus clients: %v", err) },
		dbusx.On(nameOwnerChanged, busPath, s.closeSessionsOfLeaver))
	if err != nil {
		cancel()
		return fmt.Errorf("watch bus clients: %w", err)
	}
	s.leavers = w
	s.stops = append(s.stops, cancel)
	return nil
}

// stopWatchingLeavers waits for the watch of clients leaving, cancelled
// by withdrawLocked, to end. The caller does not hold s.mu.
func (s *Service) stopWatchingLeavers() error {
	if s.leavers == nil {
		return nil
	}
	if err := s.leavers.Stop(); err != nil && !errors.Is(err, dbusx.ErrDisconnected) {
		return fmt.Errorf("stop watching bus clients: %w", err)
	}
	return nil
}

// closeSessionsOfLeaver closes the sessions of a connection that left
// the bus, and forgets what it was allowed and who it was.
func (s *Service) closeSessionsOfLeaver(change ownerChange, _ dbus.Sequence) error {
	if change.NewOwner != "" || !strings.HasPrefix(change.Name, ":") {
		return nil
	}
	s.peers.forget(change.Name)
	s.mu.Lock()
	defer s.mu.Unlock()
	for path, sess := range s.sessions {
		if sess.owner == change.Name {
			s.closeSessionLocked(path)
		}
	}
	delete(s.grants, change.Name)
	return nil
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
	s.usedLocked(c)
	it, _ := c.kr.Item(id)
	params, enc, err := sess.t.Encode(value)
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
