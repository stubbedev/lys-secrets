package service

import (
	"context"
	"encoding/hex"
	"errors"
	"log"
	"maps"
	"slices"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/vault"
)

// VaultID is the collection the Bitwarden vault shows as: the logins of
// one vault folder, read-only, locked while the vault is.
const VaultID = "bitwarden"

// vaultSchema is the xdg:schema of the vault collection's items.
const vaultSchema = "dev.stubbe.lys.Bitwarden.Login"

// VaultLogin is one login the vault collection shows.
type VaultLogin struct {
	ID, Name, Username, URI, Folder string
}

// attributes are the item's lookup attributes: its schema, its vault id
// and name, and the username, URI and folder it has.
func (l VaultLogin) attributes() map[string]string {
	a := map[string]string{"xdg:schema": vaultSchema, "bitwarden:id": l.ID, "name": l.Name}
	for k, v := range map[string]string{"username": l.Username, "uri": l.URI, "folder": l.Folder} {
		if v != "" {
			a[k] = v
		}
	}
	return a
}

// Vault is the Bitwarden vault behind the vault collection.
type Vault interface {
	// Logins are the logins the collection shows; open is false while
	// the vault is not open.
	Logins() (logins []VaultLogin, open bool)
	// Password is login id's password.
	Password(id string) ([]byte, error)
	// Unlock opens the vault with the master password; a wrong one
	// matches vault.ErrWrongPassword.
	Unlock(ctx context.Context, password string) error
	// Lock locks the vault.
	Lock()
}

// vaultColl is the vault collection as exported: whether the vault is
// open, its logins by item path, each item's unexport and the
// collection's own.
type vaultColl struct {
	v      Vault
	open   bool
	logins map[dbus.ObjectPath]VaultLogin
	items  map[dbus.ObjectPath]func()
	off    func()
}

func vaultItemPath(id string) dbus.ObjectPath {
	return collectionPath(VaultID) + "/" + dbus.ObjectPath(hex.EncodeToString([]byte(id)))
}

// isVaultPathLocked reports whether p is the vault collection or one of
// its items.
func (s *Service) isVaultPathLocked(p dbus.ObjectPath) bool {
	if s.vault == nil {
		return false
	}
	_, item := s.vault.logins[p]
	return item || p == collectionPath(VaultID)
}

// startVaultLocked exports the vault collection and its items.
func (s *Service) startVaultLocked(v Vault) error {
	if _, clash := s.colls[VaultID]; clash {
		return errors.New("a keyring collection named " + VaultID + " stands where the vault collection goes; rename " + s.disk.path(VaultID))
	}
	vc := &vaultColl{v: v, logins: map[dbus.ObjectPath]VaultLogin{}, items: map[dbus.ObjectPath]func(){}}
	off, err := dbusx.Export(s.conn, collectionPath(VaultID), dbusx.Interface{
		Name: ifaceCollection, Methods: vaultCollectionMethods{s},
		Properties: dbusx.Getters{
			"Items":    s.locked(func() any { return slices.Sorted(maps.Keys(s.vault.logins)) }),
			"Label":    func() any { return "Bitwarden" },
			"Locked":   s.locked(func() any { return !s.vault.open }),
			"Created":  func() any { return uint64(0) },
			"Modified": func() any { return uint64(0) },
		},
	})
	if err != nil {
		return err
	}
	vc.off = off
	s.vault = vc
	s.syncVaultLocked()
	return nil
}

// VaultChanged follows a change of the vault: the collection's lock
// state and items, with their signals.
func (s *Service) VaultChanged() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != nil && !s.closed {
		s.syncVaultLocked()
	}
}

func (s *Service) syncVaultLocked() {
	vc := s.vault
	logins, open := vc.v.Logins()
	current := make(map[dbus.ObjectPath]VaultLogin, len(logins))
	for _, l := range logins {
		current[vaultItemPath(l.ID)] = l
	}
	changed := open != vc.open
	vc.open = open
	for _, p := range slices.Sorted(maps.Keys(vc.logins)) {
		if _, ok := current[p]; ok {
			continue
		}
		vc.items[p]()
		delete(vc.items, p)
		delete(vc.logins, p)
		s.emitLocked(collectionPath(VaultID), ifaceCollection+".ItemDeleted", p)
		changed = true
	}
	for _, p := range slices.Sorted(maps.Keys(current)) {
		l := current[p]
		old, had := vc.logins[p]
		vc.logins[p] = l
		switch {
		case !had:
			if err := s.exportVaultItemLocked(p); err != nil {
				log.Printf("secrets: %v", err)
				delete(vc.logins, p)
				continue
			}
			s.emitLocked(collectionPath(VaultID), ifaceCollection+".ItemCreated", p)
			changed = true
		case old != l:
			s.emitLocked(collectionPath(VaultID), ifaceCollection+".ItemChanged", p)
			changed = true
		}
	}
	if changed {
		s.emitLocked(rootPath, ifaceService+".CollectionChanged", collectionPath(VaultID))
	}
}

func (s *Service) exportVaultItemLocked(p dbus.ObjectPath) error {
	login := func(read func(VaultLogin) any) func() any {
		return s.locked(func() any { return read(s.vault.logins[p]) })
	}
	off, err := dbusx.Export(s.conn, p, dbusx.Interface{
		Name: ifaceItem, Methods: vaultItemMethods{s, p},
		Properties: dbusx.Getters{
			"Locked":     s.locked(func() any { return !s.vault.open }),
			"Label":      login(func(l VaultLogin) any { return l.Name }),
			"Attributes": login(func(l VaultLogin) any { return l.attributes() }),
			"Created":    func() any { return uint64(0) },
			"Modified":   func() any { return uint64(0) },
		},
	})
	if err != nil {
		return err
	}
	s.vault.items[p] = off
	return nil
}

// searchVaultLocked is the open vault's items holding attrs.
func (s *Service) searchVaultLocked(attrs map[string]string) []dbus.ObjectPath {
	out := []dbus.ObjectPath{}
	if s.vault == nil || !s.vault.open {
		return out
	}
	for _, p := range slices.Sorted(maps.Keys(s.vault.logins)) {
		have := s.vault.logins[p].attributes()
		if matches(have, attrs) {
			out = append(out, p)
		}
	}
	return out
}

func matches(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// vaultSecretLocked is vault item p's password, encoded for sess.
func (s *Service) vaultSecretLocked(p dbus.ObjectPath, sessPath dbus.ObjectPath, sess *session) (Secret, *dbus.Error) {
	l, ok := s.vault.logins[p]
	if !ok {
		return Secret{}, noSuchObject(p)
	}
	if !s.vault.open {
		return Secret{}, dbus.NewError(errIsLocked, []any{"the vault is locked"})
	}
	value, err := s.vault.v.Password(l.ID)
	if err != nil {
		return Secret{}, dbusx.Failed(err.Error())
	}
	defer clear(value)
	params, enc, err := sess.t.encode(value)
	if err != nil {
		return Secret{}, dbusx.Failed("encode the secret: " + err.Error())
	}
	return Secret{Session: sessPath, Parameters: params, Value: enc, ContentType: "text/plain"}, nil
}

// promptVaultUnlock asks for the master password until the vault opens
// or the user gives up.
func (s *Service) promptVaultUnlock(ctx context.Context) bool {
	retry := false
	for {
		s.mu.Lock()
		open := s.vault.open
		s.mu.Unlock()
		if open {
			return true
		}
		password, ok, err := s.cfg.Prompter.MasterPassword(ctx, retry)
		if err != nil || !ok {
			logPromptErr("unlock the vault", err)
			return false
		}
		err = s.vault.v.Unlock(ctx, string(password))
		clear(password)
		switch {
		case err == nil:
			s.VaultChanged()
			return true
		case errors.Is(err, vault.ErrWrongPassword):
			retry = true
		default:
			log.Printf("secrets: unlock the vault: %v", err)
			return false
		}
	}
}

var errReadOnly = dbus.NewError(errNotSupported, []any{"the Bitwarden vault collection is read-only"})

// vaultCollectionMethods is org.freedesktop.Secret.Collection for the
// vault collection, which is read-only.
type vaultCollectionMethods struct{ s *Service }

// Delete refuses: the vault is not the Secret Service's to delete.
func (vaultCollectionMethods) Delete() (dbus.ObjectPath, *dbus.Error) { return "", errReadOnly }

// SearchItems is the open vault's items holding attrs.
func (m vaultCollectionMethods) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	return m.s.searchVaultLocked(attrs), nil
}

// CreateItem refuses: the vault collection is read-only.
func (vaultCollectionMethods) CreateItem(dbus.Sender, map[string]dbus.Variant, Secret, bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return "", "", errReadOnly
}

// vaultItemMethods is org.freedesktop.Secret.Item for a vault item.
type vaultItemMethods struct {
	s    *Service
	path dbus.ObjectPath
}

// Delete refuses: the vault collection is read-only.
func (vaultItemMethods) Delete() (dbus.ObjectPath, *dbus.Error) { return "", errReadOnly }

// GetSecret is the login's password, encoded for the caller's session.
func (m vaultItemMethods) GetSecret(sender dbus.Sender, sessPath dbus.ObjectPath) (Secret, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, derr := s.sessionLocked(sessPath, sender)
	if derr != nil {
		return Secret{}, derr
	}
	return s.vaultSecretLocked(m.path, sessPath, sess)
}

// SetSecret refuses: the vault collection is read-only.
func (vaultItemMethods) SetSecret(dbus.Sender, Secret) *dbus.Error { return errReadOnly }
