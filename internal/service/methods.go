package service

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"maps"
	"slices"
	"sync"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/secretbus"
	"github.com/stubbedev/lys-secrets/transport"
)

// serviceMethods is org.freedesktop.Secret.Service.
type serviceMethods struct{ s *Service }

// OpenSession negotiates the transport for the caller's secrets.
func (m serviceMethods) OpenSession(sender dbus.Sender, algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	var t transport.Transport
	output := dbus.MakeVariant("")
	switch algorithm {
	case transport.AlgPlain:
		t = transport.Plain{}
	case transport.AlgDH:
		peer, ok := input.Value().([]byte)
		if !ok {
			return dbus.Variant{}, "", dbusx.InvalidArgs("the DH input is the client's public key, ay")
		}
		public, dh, err := negotiateDH(peer, rand.Reader)
		if err != nil {
			return dbus.Variant{}, "", dbusx.InvalidArgs(err.Error())
		}
		t, output = dh, dbus.MakeVariant(public)
	default:
		return dbus.Variant{}, "", dbus.NewError(errNotSupported, []any{"unsupported transport algorithm " + algorithm})
	}
	s := m.s
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.newPathLocked(sessionBase)
	off, err := dbusx.Export(s.conn, path, dbusx.Interface{Name: secretbus.SessionInterface, Methods: sessionMethods{s, path}})
	if err != nil {
		return dbus.Variant{}, "", dbusx.Failed(err.Error())
	}
	s.sessions[path] = &session{owner: string(sender), t: t, off: off}
	return output, path, nil
}

// CreateCollection makes a collection after asking for its password; an
// alias already pointing at a collection returns that one at once.
func (m serviceMethods) CreateCollection(props map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s := m.s
	if alias != "" && !validID(alias) {
		return "", "", dbusx.InvalidArgs("invalid alias " + alias)
	}
	label := ""
	if v, ok := props[propCollLabel]; ok {
		if label, ok = v.Value().(string); !ok {
			return "", "", dbusx.InvalidArgs(propCollLabel + " is a string")
		}
	}
	s.mu.Lock()
	if id, ok := s.aliases[alias]; ok && alias != "" {
		if _, exists := s.colls[id]; exists {
			s.mu.Unlock()
			return collectionPath(id), noPrompt, nil
		}
	}
	s.mu.Unlock()
	if label == "" {
		label = alias
	}
	prompt, derr := s.newPrompt(func(ctx context.Context) (bool, dbus.Variant) {
		password, ok, err := s.cfg.Prompter.NewPassword(ctx, label)
		if err != nil || !ok {
			logPromptErr("create collection", err)
			return true, dbus.MakeVariant(noPrompt)
		}
		defer clear(password)
		kr, err := keyring.New(label, password, s.cfg.KDF, s.cfg.Stretch, s.now())
		if err != nil {
			log.Printf("secrets: create collection %q: %v", label, err)
			return true, dbus.MakeVariant(noPrompt)
		}
		id, err := s.addCollection(func(taken func(string) bool) string { return idFor(label, taken) }, kr)
		if err != nil {
			log.Printf("secrets: create collection %q: %v", label, err)
			return true, dbus.MakeVariant(noPrompt)
		}
		if alias != "" {
			if err := s.setAlias(alias, id); err != nil {
				log.Printf("secrets: alias %s: %v", alias, err)
			}
		}
		return false, dbus.MakeVariant(collectionPath(id))
	})
	if derr != nil {
		return "", "", derr
	}
	return noPrompt, prompt, nil
}

// SearchItems is every item matching attrs, unlocked and locked apart. When
// reads are confirmed, an item the caller may not read without asking is
// locked to it.
func (m serviceMethods) SearchItems(sender dbus.Sender, attrs map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	s := m.s
	cl, confirm := s.reader(sender)
	s.mu.Lock()
	defer s.mu.Unlock()
	unlocked, locked := []dbus.ObjectPath{}, []dbus.ObjectPath{}
	for _, id := range slices.Sorted(maps.Keys(s.colls)) {
		c := s.colls[id]
		for _, iid := range c.kr.Search(attrs) {
			if c.kr.Locked() || confirm && !s.mayReadLocked(sender, cl, c, iid) {
				locked = append(locked, itemPath(id, iid))
			} else {
				unlocked = append(unlocked, itemPath(id, iid))
			}
		}
	}
	unlocked = append(unlocked, s.searchVaultLocked(attrs)...)
	return unlocked, locked, nil
}

// Unlock returns what is unlocked already and a prompt for the rest: the
// passwords of locked collections, then, when reads are confirmed, the
// user's leave for each item the caller does not own.
func (m serviceMethods) Unlock(sender dbus.Sender, objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s := m.s
	cl, confirm := s.reader(sender)
	s.mu.Lock()
	unlocked := []dbus.ObjectPath{}
	pending := map[string][]dbus.ObjectPath{}
	var pendingVault, pendingReads []dbus.ObjectPath
	for _, p := range objects {
		if s.isVaultPathLocked(p) {
			if s.vault.open {
				unlocked = append(unlocked, p)
			} else {
				pendingVault = append(pendingVault, p)
			}
			continue
		}
		c, iid, ok := s.resolveLocked(p)
		switch {
		case !ok:
		case c.kr.Locked():
			pending[c.id] = append(pending[c.id], p)
		case confirm && iid != 0 && !s.mayReadLocked(sender, cl, c, iid):
			pendingReads = append(pendingReads, p)
		default:
			unlocked = append(unlocked, p)
		}
	}
	s.mu.Unlock()
	if len(pending) == 0 && len(pendingVault) == 0 && len(pendingReads) == 0 {
		return unlocked, noPrompt, nil
	}
	prompt, derr := s.newPrompt(func(ctx context.Context) (bool, dbus.Variant) {
		done := []dbus.ObjectPath{}
		reads := pendingReads
		for _, id := range slices.Sorted(maps.Keys(pending)) {
			if !s.promptUnlock(ctx, id) {
				return true, dbus.MakeVariant(done)
			}
			if confirm {
				reads = append(reads, pending[id]...)
			} else {
				done = append(done, pending[id]...)
			}
		}
		if len(pendingVault) > 0 {
			if !s.promptVaultUnlock(ctx) {
				return true, dbus.MakeVariant(done)
			}
			done = append(done, pendingVault...)
		}
		for _, p := range reads {
			s.mu.Lock()
			c, iid, ok := s.resolveLocked(p)
			s.mu.Unlock()
			if ok && iid != 0 && !s.confirmRead(ctx, sender, cl, itemRef{c.id, iid}) {
				return true, dbus.MakeVariant(done)
			}
			done = append(done, p)
		}
		return false, dbus.MakeVariant(done)
	})
	if derr != nil {
		return nil, "", derr
	}
	return unlocked, prompt, nil
}

// promptUnlock asks for collection id's password until it unlocks or the
// user gives up.
func (s *Service) promptUnlock(ctx context.Context, id string) bool {
	retry := false
	for {
		s.mu.Lock()
		c, ok := s.colls[id]
		done := ok && !c.kr.Locked()
		s.mu.Unlock()
		if !ok {
			return false
		}
		if done {
			return true
		}
		password, ok, err := s.cfg.Prompter.Password(ctx, id, retry)
		if err != nil || !ok {
			logPromptErr("unlock "+id, err)
			return false
		}
		err = s.unlock(c, password)
		clear(password)
		switch {
		case err == nil:
			return true
		case errors.Is(err, keyring.ErrWrongPassword):
			retry = true
		default:
			log.Printf("secrets: unlock %s: %v", id, err)
			return false
		}
	}
}

// Lock locks the collections of objects, the vault's too.
func (m serviceMethods) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	locked := []dbus.ObjectPath{}
	lockVault := false
	for _, p := range objects {
		if s.isVaultPathLocked(p) {
			lockVault = true
			locked = append(locked, p)
			continue
		}
		if c, _, ok := s.resolveLocked(p); ok {
			s.lockCollectionLocked(c)
			locked = append(locked, p)
		}
	}
	s.mu.Unlock()
	if lockVault {
		s.cfg.Vault.Lock()
	}
	return locked, noPrompt, nil
}

// LockService locks every collection and the vault.
func (m serviceMethods) LockService() *dbus.Error {
	m.s.Lock()
	return nil
}

// ChangeLock asks for a new password for an unlocked collection.
func (m serviceMethods) ChangeLock(collection dbus.ObjectPath) (dbus.ObjectPath, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	c, item, ok := s.resolveLocked(collection)
	s.mu.Unlock()
	if !ok || item != 0 {
		return "", noSuchObject(collection)
	}
	return s.newPrompt(func(ctx context.Context) (bool, dbus.Variant) {
		if !s.promptUnlock(ctx, c.id) {
			return true, dbus.MakeVariant("")
		}
		password, ok, err := s.cfg.Prompter.NewPassword(ctx, c.id)
		if err != nil || !ok {
			logPromptErr("change the password of "+c.id, err)
			return true, dbus.MakeVariant("")
		}
		defer clear(password)
		rekey, err := keyring.NewRekey(password, s.cfg.KDF, s.cfg.Stretch)
		if err != nil {
			log.Printf("secrets: change the password of %s: %v", c.id, err)
			return true, dbus.MakeVariant("")
		}
		if err := s.changeKey(c, rekey); err != nil {
			log.Printf("secrets: change the password of %s: %v", c.id, err)
			return true, dbus.MakeVariant("")
		}
		return false, dbus.MakeVariant("")
	})
}

// GetSecrets returns the secrets of the unlocked items among items; when
// reads are confirmed, only of those the caller may read without asking, and
// the caller owns those nobody owned before.
func (m serviceMethods) GetSecrets(sender dbus.Sender, items []dbus.ObjectPath, sessPath dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	s := m.s
	cl, confirm := s.reader(sender)
	out, claims, derr := s.getSecrets(sender, cl, confirm, items, sessPath)
	s.claim(cl, claims)
	return out, derr
}

func (s *Service) getSecrets(sender dbus.Sender, cl peer, confirm bool, items []dbus.ObjectPath, sessPath dbus.ObjectPath) (map[dbus.ObjectPath]Secret, []itemRef, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, derr := s.sessionLocked(sessPath, sender)
	if derr != nil {
		return nil, nil, derr
	}
	out := map[dbus.ObjectPath]Secret{}
	var read []itemRef
	for _, p := range items {
		if s.isVaultPathLocked(p) && p != collectionPath(VaultID) {
			if !s.vault.open {
				continue
			}
			secret, derr := s.vaultSecretLocked(p, sessPath, sess)
			if derr != nil {
				return nil, nil, derr
			}
			out[p] = secret
			continue
		}
		c, id, ok := s.resolveLocked(p)
		if !ok || id == 0 || c.kr.Locked() || confirm && !s.mayReadLocked(sender, cl, c, id) {
			continue
		}
		secret, derr := s.secretLocked(c, id, sessPath, sess)
		if derr != nil {
			return nil, nil, derr
		}
		out[p] = secret
		read = append(read, itemRef{c.id, id})
	}
	if !confirm {
		return out, nil, nil
	}
	return out, s.claimsLocked(cl, read), nil
}

// ReadAlias is the collection an alias names, "/" for none.
func (m serviceMethods) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.aliases[name]; ok {
		if _, exists := s.colls[id]; exists {
			return collectionPath(id), nil
		}
	}
	return noPrompt, nil
}

// SetAlias points an alias at a collection, or removes it with "/". The
// collection it points at and the one it would point at must be unlocked,
// since a locked collection cannot be changed; otherwise it is IsLocked and
// the client must unlock first.
func (m serviceMethods) SetAlias(name string, collection dbus.ObjectPath) *dbus.Error {
	s := m.s
	if !validID(name) {
		return dbusx.InvalidArgs("invalid alias " + name)
	}
	s.mu.Lock()
	if current, ok := s.colls[s.aliases[name]]; ok && current.kr.Locked() {
		s.mu.Unlock()
		return lockedErr(keyring.ErrLocked)
	}
	id := ""
	if collection != noPrompt {
		c, item, ok := s.resolveLocked(collection)
		if !ok || item != 0 {
			s.mu.Unlock()
			return noSuchObject(collection)
		}
		if c.kr.Locked() {
			s.mu.Unlock()
			return lockedErr(keyring.ErrLocked)
		}
		id = c.id
	}
	s.mu.Unlock()
	if err := s.setAlias(name, id); err != nil {
		return dbusx.Failed(err.Error())
	}
	return nil
}

// collectionMethods is org.freedesktop.Secret.Collection.
type collectionMethods struct {
	s  *Service
	id string
}

func (m collectionMethods) collection() (*collection, *dbus.Error) {
	c, ok := m.s.colls[m.id]
	if !ok {
		return nil, noSuchObject(collectionPath(m.id))
	}
	return c, nil
}

// Delete removes an unlocked collection and its file; a locked one is
// IsLocked and stays as it is, since the client must unlock it first.
func (m collectionMethods) Delete() (dbus.ObjectPath, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	c, derr := m.collection()
	if derr != nil {
		s.mu.Unlock()
		return "", derr
	}
	if c.kr.Locked() {
		s.mu.Unlock()
		return "", lockedErr(keyring.ErrLocked)
	}
	s.mu.Unlock()
	c.writer.Lock()
	defer c.writer.Unlock()
	if err := s.disk.remove(c.id); err != nil {
		return "", dbusx.Failed(err.Error())
	}
	s.mu.Lock()
	if s.colls[c.id] != c {
		s.mu.Unlock()
		return noPrompt, nil
	}
	c.kr.Destroy()
	c.unexport()
	delete(s.colls, c.id)
	var aliases []string
	for alias, id := range s.aliases {
		if id == c.id {
			aliases = append(aliases, alias)
		}
	}
	s.mu.Unlock()
	if len(aliases) > 0 {
		err := s.changeAliases(aliases, func(table map[string]string) {
			for _, alias := range aliases {
				delete(table, alias)
			}
		})
		if err != nil {
			log.Printf("secrets: drop aliases %v: %v", aliases, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	emit(s, secretbus.CollectionDeleted, rootPath, secretbus.CollectionEvent{Collection: collectionPath(c.id)})
	return noPrompt, nil
}

// SearchItems is the collection's items matching attrs.
func (m collectionMethods) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	defer s.mu.Unlock()
	c, derr := m.collection()
	if derr != nil {
		return nil, derr
	}
	out := []dbus.ObjectPath{}
	for _, id := range c.kr.Search(attrs) {
		out = append(out, itemPath(c.id, id))
	}
	return out, nil
}

// CreateItem stores a secret; a locked collection is unlocked through a
// prompt first, whose result is the item.
func (m collectionMethods) CreateItem(sender dbus.Sender, props map[string]dbus.Variant, secret Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s := m.s
	owner := s.peers.identify(string(sender)).program
	label, attrs := "", map[string]string{}
	if v, ok := props[propItemLabel]; ok {
		if label, ok = v.Value().(string); !ok {
			return "", "", dbusx.InvalidArgs(propItemLabel + " is a string")
		}
	}
	if v, ok := props[propItemAttrs]; ok {
		if attrs, ok = v.Value().(map[string]string); !ok {
			return "", "", dbusx.InvalidArgs(propItemAttrs + " is a{ss}")
		}
	}
	s.mu.Lock()
	c, derr := m.collection()
	if derr != nil {
		s.mu.Unlock()
		return "", "", derr
	}
	sess, derr := s.sessionLocked(secret.Session, sender)
	if derr != nil {
		s.mu.Unlock()
		return "", "", derr
	}
	value, err := sess.t.Decode(secret.Parameters, secret.Value)
	if err != nil {
		s.mu.Unlock()
		return "", "", dbusx.InvalidArgs("decode the secret: " + err.Error())
	}
	create := func() (dbus.ObjectPath, *dbus.Error) {
		defer clear(value)
		path, err := s.createItem(c, label, attrs, value, secret.ContentType, owner, replace)
		if err != nil {
			return "", lockedErr(err)
		}
		return path, nil
	}
	locked := c.kr.Locked()
	s.mu.Unlock()
	if !locked {
		path, derr := create()
		return path, noPrompt, derr
	}
	prompt, derr := s.newPrompt(func(ctx context.Context) (bool, dbus.Variant) {
		if !s.promptUnlock(ctx, c.id) {
			clear(value)
			return true, dbus.MakeVariant(noPrompt)
		}
		path, derr := create()
		if derr != nil {
			log.Printf("secrets: create an item in %s: %v", c.id, derr)
			return true, dbus.MakeVariant(noPrompt)
		}
		return false, dbus.MakeVariant(path)
	})
	if derr != nil {
		clear(value)
		return "", "", derr
	}
	return noPrompt, prompt, nil
}

// createItem stores a secret in the unlocked c and announces the item.
func (s *Service) createItem(c *collection, label string, attrs map[string]string, value []byte, contentType string, owner keyring.Owner, replace bool) (dbus.ObjectPath, error) {
	var id uint32
	var created bool
	err := s.change(c, func(kr *keyring.Collection) error {
		var err error
		id, created, err = kr.CreateItem(label, attrs, value, contentType, owner, replace, s.now())
		return err
	}, func() error {
		path := itemPath(c.id, id)
		if !created {
			emit(s, secretbus.ItemChanged, collectionPath(c.id), secretbus.ItemEvent{Item: path})
			return nil
		}
		if err := s.exportItemLocked(c, id); err != nil {
			return err
		}
		emit(s, secretbus.ItemCreated, collectionPath(c.id), secretbus.ItemEvent{Item: path})
		return nil
	})
	if err != nil {
		return "", err
	}
	return itemPath(c.id, id), nil
}

// itemMethods is org.freedesktop.Secret.Item.
type itemMethods struct {
	s   *Service
	cid string
	id  uint32
}

// Delete removes the item.
func (m itemMethods) Delete() (dbus.ObjectPath, *dbus.Error) {
	s := m.s
	s.mu.Lock()
	c, ok := s.colls[m.cid]
	s.mu.Unlock()
	if !ok {
		return "", noSuchObject(itemPath(m.cid, m.id))
	}
	err := s.change(c, func(kr *keyring.Collection) error { return kr.DeleteItem(m.id, s.now()) }, func() error {
		if off := c.items[m.id]; off != nil {
			off()
			delete(c.items, m.id)
		}
		emit(s, secretbus.ItemDeleted, collectionPath(c.id), secretbus.ItemEvent{Item: itemPath(c.id, m.id)})
		return nil
	})
	if err != nil {
		return "", lockedErr(err)
	}
	return noPrompt, nil
}

// GetSecret returns the secret, encoded for the caller's session. When reads
// are confirmed, an item the caller may not read without asking is locked to
// it, and the caller owns one nobody owned before.
func (m itemMethods) GetSecret(sender dbus.Sender, sessPath dbus.ObjectPath) (Secret, *dbus.Error) {
	s := m.s
	cl, confirm := s.reader(sender)
	secrets, claims, derr := s.getSecrets(sender, cl, confirm, []dbus.ObjectPath{itemPath(m.cid, m.id)}, sessPath)
	s.claim(cl, claims)
	if derr != nil {
		return Secret{}, derr
	}
	secret, ok := secrets[itemPath(m.cid, m.id)]
	if ok {
		return secret, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.colls[m.cid]
	if !ok {
		return Secret{}, noSuchObject(itemPath(m.cid, m.id))
	}
	if _, err := c.kr.Item(m.id); err != nil {
		return Secret{}, lockedErr(err)
	}
	return Secret{}, lockedErr(keyring.ErrLocked)
}

// SetSecret replaces the secret.
func (m itemMethods) SetSecret(sender dbus.Sender, secret Secret) *dbus.Error {
	s := m.s
	owner := s.peers.identify(string(sender)).program
	s.mu.Lock()
	sess, derr := s.sessionLocked(secret.Session, sender)
	if derr != nil {
		s.mu.Unlock()
		return derr
	}
	c, ok := s.colls[m.cid]
	if !ok {
		s.mu.Unlock()
		return noSuchObject(itemPath(m.cid, m.id))
	}
	value, err := sess.t.Decode(secret.Parameters, secret.Value)
	s.mu.Unlock()
	if err != nil {
		return dbusx.InvalidArgs("decode the secret: " + err.Error())
	}
	defer clear(value)
	err = s.change(c, func(kr *keyring.Collection) error {
		return kr.SetSecret(m.id, value, secret.ContentType, owner, s.now())
	}, func() error {
		emit(s, secretbus.ItemChanged, collectionPath(c.id), secretbus.ItemEvent{Item: itemPath(c.id, m.id)})
		return nil
	})
	if err != nil {
		return lockedErr(err)
	}
	return nil
}

// sessionMethods is org.freedesktop.Secret.Session.
type sessionMethods struct {
	s    *Service
	path dbus.ObjectPath
}

// Close ends the session.
func (m sessionMethods) Close(sender dbus.Sender) *dbus.Error {
	s := m.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, derr := s.sessionLocked(m.path, sender); derr != nil {
		return derr
	}
	s.closeSessionLocked(m.path)
	return nil
}

// prompt is org.freedesktop.Secret.Prompt: run starts on Prompt and
// reports Completed once; Dismiss cancels it.
type prompt struct {
	s    *Service
	path dbus.ObjectPath
	run  func(ctx context.Context) (dismissed bool, result dbus.Variant)

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	off     func()
}

func (s *Service) newPrompt(run func(ctx context.Context) (bool, dbus.Variant)) (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &prompt{s: s, path: s.newPathLocked(promptBase), run: run}
	off, err := dbusx.Export(s.conn, p.path, dbusx.Interface{Name: secretbus.PromptInterface, Methods: promptMethods{p}, Signals: []dbusx.SignalDecl{secretbus.PromptCompleted}})
	if err != nil {
		return "", dbusx.Failed(err.Error())
	}
	p.off = off
	s.prompts[p.path] = off
	return p.path, nil
}

type promptMethods struct{ p *prompt }

// Prompt shows the prompt; the answer arrives as Completed.
func (m promptMethods) Prompt(string) *dbus.Error {
	p := m.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return dbusx.Failed("the prompt was already shown")
	}
	p.started = true
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go func() {
		dismissed, result := p.run(ctx)
		if ctx.Err() != nil {
			dismissed = true
		}
		cancel()
		p.complete(dismissed, result)
	}()
	return nil
}

// Dismiss withdraws the prompt.
func (m promptMethods) Dismiss() *dbus.Error {
	p := m.p
	p.mu.Lock()
	started, cancel := p.started, p.cancel
	p.mu.Unlock()
	if started {
		cancel()
		return nil
	}
	p.complete(true, dbus.MakeVariant(""))
	return nil
}

func (p *prompt) complete(dismissed bool, result dbus.Variant) {
	emit(p.s, secretbus.PromptCompleted, p.path, secretbus.Completion{Dismissed: dismissed, Result: result})
	p.s.mu.Lock()
	delete(p.s.prompts, p.path)
	p.s.mu.Unlock()
	p.off()
}

func logPromptErr(what string, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("secrets: %s: the prompt failed: %v", what, err)
	}
}

// missingCollection answers for collection and alias paths that name
// nothing: NoSuchObject, which tells libsecret to create the default
// collection rather than fail.
type missingCollection struct{}

func (missingCollection) Delete(msg dbus.Message) (dbus.ObjectPath, *dbus.Error) {
	return "", noSuchObject(msgPath(msg))
}

func (missingCollection) SearchItems(msg dbus.Message, _ map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	return nil, noSuchObject(msgPath(msg))
}

func (missingCollection) CreateItem(msg dbus.Message, _ map[string]dbus.Variant, _ Secret, _ bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return "", "", noSuchObject(msgPath(msg))
}

func msgPath(msg dbus.Message) dbus.ObjectPath {
	p, _ := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	return p
}
