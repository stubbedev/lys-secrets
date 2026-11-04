// Package keyring is the Secret Service's storage core: a collection of
// items whose labels, attributes and secrets are encrypted at rest under
// a key derived from the collection's password.
//
// On disk a collection is one file:
//
//	magic     8 bytes  "LYSKR\x00\x00\x02"
//	kdf       u32 time, u32 memory KiB, u8 threads (Argon2id)
//	salt      16 bytes
//	check     40 bytes, XChaCha20-Poly1305 nonce and tag over nothing,
//	          under the key: it opens exactly when the password is right
//	items     u32 count, then per item: u32 id, u32 n, n × 32-byte
//	          SHA-256 of u32 len(name) ‖ name ‖ value, one per attribute
//	body      XChaCha20-Poly1305 nonce, ciphertext and tag of the
//	          JSON body, with everything above as associated data
//
// The attribute hashes let a locked collection answer a search with the
// matching items, so a client knows to ask for an unlock, as
// gnome-keyring's format does; everything else is in the body. While
// unlocked, each item's secret stays sealed in memory under the key and
// opens only for the call that asks for it.
//
// The check tells a wrong password from a changed file: when it opens and
// the body does not, the file was changed. It offers nothing the body does
// not, since whoever holds the file can already test a password against
// the body at the same Argon2id cost. A changed KDF, salt or check derives
// or finds no key, so it still looks like a wrong password.
//
// The first format, "LYSKR\x00\x00\x01", has no check, so there a body
// that fails to open is always ErrWrongPassword. It is read as it stands
// and written as the current format once unlocked.
package keyring

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	magic       = [8]byte{'L', 'Y', 'S', 'K', 'R', 0, 0, 2}
	legacyMagic = [8]byte{'L', 'Y', 'S', 'K', 'R', 0, 0, 1}
)

const (
	saltLen     = 16
	keyCheckLen = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
)

// keyCheckAD is what the check binds to; a body's associated data starts
// with the magic and an item's with "item", so no seal opens as another.
var keyCheckAD = []byte("key check")

// Errors a caller tells apart.
var (
	// ErrWrongPassword is a password that finds no key. A changed KDF,
	// salt or check, or any change to a file of the first format, is
	// indistinguishable from it.
	ErrWrongPassword = errors.New("keyring: wrong password")
	// ErrTampered is a file changed after it was written: the password is
	// right and the contents no longer authenticate under it.
	ErrTampered = errors.New("keyring: the password is right but the file was changed: its contents do not authenticate")
	ErrLocked   = errors.New("keyring: the collection is locked")
	ErrNoItem   = errors.New("keyring: no such item")
)

type attrHash [sha256.Size]byte

func hashAttr(name, value string) attrHash {
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(name)))) //nolint:gosec // attribute names stay far below 4 GiB
	h.Write([]byte(name))
	h.Write([]byte(value))
	return attrHash(h.Sum(nil))
}

// Item is one stored secret's metadata; the secret itself is read with
// Collection.Secret.
type Item struct {
	ID          uint32
	Label       string
	Attributes  map[string]string
	ContentType string
	Created     time.Time
	Modified    time.Time
}

type entry struct {
	Item
	hashes []attrHash
	// sealed is the secret under the collection key, nil while locked.
	sealed []byte
}

// Collection is one keyring. It is not safe for concurrent use.
type Collection struct {
	kdf     KDF
	salt    []byte
	label   string
	created time.Time
	mod     time.Time
	entries map[uint32]*entry
	nextID  uint32
	// key is nil while locked; body is the sealed body of a parsed
	// collection that has not been unlocked yet.
	key  *key
	body []byte
	// check is nil only for a parsed file of the first format, until it
	// unlocks.
	check []byte
}

// New creates an unlocked collection whose key derives from password.
func New(label string, password []byte, kdf KDF, stretch Stretch, now time.Time) (*Collection, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keyring: salt: %w", err)
	}
	k, err := deriveKey(password, salt, kdf, stretch)
	if err != nil {
		return nil, err
	}
	return &Collection{
		kdf: kdf, salt: salt, label: label, created: now.UTC(), mod: now.UTC(),
		entries: map[uint32]*entry{}, nextID: 1, key: k, check: k.seal(nil, keyCheckAD),
	}, nil
}

// Parse reads a collection file. The result is locked: its items are
// known by id and attribute hashes only, until Unlock.
func Parse(data []byte) (*Collection, error) {
	r := reader{b: data}
	version := r.take(len(magic))
	current := bytes.Equal(version, magic[:])
	if !current && !bytes.Equal(version, legacyMagic[:]) {
		return nil, errors.New("keyring: not a lys-secrets collection (bad magic)")
	}
	c := &Collection{entries: map[uint32]*entry{}, nextID: 1}
	c.kdf.Time, c.kdf.MemKiB = r.u32(), r.u32()
	if t := r.take(1); t != nil {
		c.kdf.Threads = t[0]
	}
	c.salt = bytes.Clone(r.take(saltLen))
	if current {
		c.check = bytes.Clone(r.take(keyCheckLen))
	}
	n := r.u32()
	for range n {
		if r.err != nil {
			break
		}
		id, nh := r.u32(), r.u32()
		if uint64(nh)*sha256.Size > uint64(len(r.b)) {
			r.err = fmt.Errorf("item %d claims %d attribute hashes past the end", id, nh)
			break
		}
		e := &entry{ID: id, hashes: make([]attrHash, nh)}
		for i := range e.hashes {
			copy(e.hashes[i][:], r.take(sha256.Size))
		}
		if _, dup := c.entries[id]; dup {
			r.err = fmt.Errorf("item %d appears twice", id)
			break
		}
		c.entries[id] = e
		c.nextID = max(c.nextID, id+1)
	}
	if r.err != nil {
		return nil, fmt.Errorf("keyring: truncated or corrupt header: %w", r.err)
	}
	if c.kdf.Time == 0 || c.kdf.MemKiB == 0 || c.kdf.Threads == 0 {
		return nil, fmt.Errorf("keyring: invalid KDF parameters %+v", c.kdf)
	}
	c.body = bytes.Clone(r.b)
	return c, nil
}

// header is the file's cleartext part, the body's associated data.
func (c *Collection) header() []byte {
	var b bytes.Buffer
	if c.check == nil {
		b.Write(legacyMagic[:])
	} else {
		b.Write(magic[:])
	}
	b.Write(binary.BigEndian.AppendUint32(nil, c.kdf.Time))
	b.Write(binary.BigEndian.AppendUint32(nil, c.kdf.MemKiB))
	b.WriteByte(c.kdf.Threads)
	b.Write(c.salt)
	b.Write(c.check)
	ids := slices.Sorted(maps.Keys(c.entries))
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(ids)))) //nolint:gosec // item counts stay far below 2^32
	for _, id := range ids {
		e := c.entries[id]
		b.Write(binary.BigEndian.AppendUint32(nil, id))
		b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(e.hashes)))) //nolint:gosec // attribute counts stay far below 2^32
		for _, h := range e.hashes {
			b.Write(h[:])
		}
	}
	return b.Bytes()
}

type bodyJSON struct {
	Label    string     `json:"label"`
	Created  int64      `json:"created"`
	Modified int64      `json:"modified"`
	Items    []itemJSON `json:"items"`
}

type itemJSON struct {
	ID          uint32            `json:"id"`
	Label       string            `json:"label"`
	Attributes  map[string]string `json:"attributes"`
	ContentType string            `json:"content_type"`
	Secret      []byte            `json:"secret"`
	Created     int64             `json:"created"`
	Modified    int64             `json:"modified"`
}

// Opening is what unlocking a locked collection needs of it, taken under the
// lock that guards the collection and used outside it, since deriving the key
// takes as long as the KDF makes it.
type Opening struct {
	salt   []byte
	kdf    KDF
	check  []byte
	body   []byte
	header []byte
}

// BeginUnlock starts unlocking a locked collection.
func (c *Collection) BeginUnlock() (*Opening, error) {
	if c.body == nil {
		return nil, errors.New("keyring: the collection was destroyed or failed to lock, so it opens only from its file")
	}
	return &Opening{salt: c.salt, kdf: c.kdf, check: c.check, body: c.body, header: c.header()}, nil
}

// Opened is a collection's unlocked state, its secrets sealed again under the
// key, waiting for FinishUnlock. Whoever gives up on one calls Discard.
type Opened struct {
	key     *key
	from    []byte
	label   string
	created int64
	mod     int64
	items   []openedItem
}

type openedItem struct {
	Item
	sealed []byte
}

// Open derives the key from password and opens the body. A wrong password is
// ErrWrongPassword and a changed file ErrTampered. No plain secret outlives it,
// whatever happens.
func (o *Opening) Open(password []byte, stretch Stretch) (*Opened, error) {
	k, err := deriveKey(password, o.salt, o.kdf, stretch)
	if err != nil {
		return nil, err
	}
	opened, err := o.read(k)
	if err != nil {
		k.destroy()
		return nil, err
	}
	return opened, nil
}

func (o *Opening) read(k *key) (*Opened, error) {
	if o.check != nil {
		if _, err := k.open(o.check, keyCheckAD); err != nil {
			return nil, ErrWrongPassword
		}
	}
	plain, err := k.open(o.body, o.header)
	if err != nil {
		switch {
		case o.check != nil:
			return nil, fmt.Errorf("%w: %w", ErrTampered, err)
		case errors.Is(err, errOpen):
			return nil, ErrWrongPassword
		}
		return nil, fmt.Errorf("keyring: corrupt body: %w", err)
	}
	defer clear(plain)
	var body bodyJSON
	if err := json.Unmarshal(plain, &body); err != nil {
		return nil, fmt.Errorf("keyring: corrupt body: %w", err)
	}
	items := make([]openedItem, len(body.Items))
	for i, it := range body.Items {
		items[i] = openedItem{
			ID: it.ID, Label: it.Label, Attributes: it.Attributes, ContentType: it.ContentType,
			Created: time.Unix(it.Created, 0).UTC(), Modified: time.Unix(it.Modified, 0).UTC(),
			sealed: k.seal(it.Secret, itemAD(it.ID)),
		}
		clear(it.Secret)
		if items[i].Attributes == nil {
			items[i].Attributes = map[string]string{}
		}
	}
	return &Opened{key: k, from: o.body, label: body.Label, created: body.Created, mod: body.Modified, items: items}, nil
}

// Discard destroys the key of an Opened nothing will use.
func (o *Opened) Discard() {
	o.key.destroy()
}

// ErrChanged is an unlock finishing on a collection that is no longer what it
// began on.
var ErrChanged = errors.New("keyring: the collection changed while it was unlocking")

// FinishUnlock makes the collection unlocked with what Open found, under the
// lock that guards it. A collection already unlocked stays as it is, and one
// changed since BeginUnlock is ErrChanged; either way o is used up. A body that
// opens but does not match the header is corruption.
func (c *Collection) FinishUnlock(o *Opened) error {
	if c.key != nil {
		o.Discard()
		return nil
	}
	if c.body == nil || !bytes.Equal(c.body, o.from) {
		o.Discard()
		return ErrChanged
	}
	if err := c.adopt(o); err != nil {
		o.Discard()
		return err
	}
	c.body = nil
	return nil
}

func (c *Collection) adopt(o *Opened) error {
	if len(o.items) != len(c.entries) {
		return fmt.Errorf("keyring: corrupt body: %d items, the header lists %d", len(o.items), len(c.entries))
	}
	for _, it := range o.items {
		if _, ok := c.entries[it.ID]; !ok {
			return fmt.Errorf("keyring: corrupt body: item %d is not in the header", it.ID)
		}
	}
	for _, it := range o.items {
		e := c.entries[it.ID]
		e.Item, e.sealed = it.Item, it.sealed
	}
	c.label, c.created, c.mod = o.label, time.Unix(o.created, 0).UTC(), time.Unix(o.mod, 0).UTC()
	c.key = o.key
	if c.check == nil {
		c.check = o.key.seal(nil, keyCheckAD)
	}
	return nil
}

// Lock seals the collection's current state into its body and destroys
// the key: what remains in memory is the header a locked file shows. The
// key is destroyed whatever happens: state that fails to seal is an
// error, and the collection stays locked with no body, so it opens again
// only from its file, by a new Parse.
func (c *Collection) Lock() error {
	if c.key == nil {
		return nil
	}
	body, err := c.sealBody()
	c.body = body
	c.forget()
	return err
}

// Destroy drops the key and the unlocked state without sealing anything,
// for a collection that is not used again. It cannot fail.
func (c *Collection) Destroy() {
	c.body = nil
	c.forget()
}

// forget destroys the key and everything only it could read.
func (c *Collection) forget() {
	for _, e := range c.entries {
		e.Item = Item{ID: e.ID}
		e.sealed = nil
	}
	c.label, c.created, c.mod = "", time.Time{}, time.Time{}
	c.key.destroy()
	c.key = nil
}

// Locked reports whether the key is gone.
func (c *Collection) Locked() bool { return c.key == nil }

// Legacy reports a parsed file of the first format, not unlocked yet.
func (c *Collection) Legacy() bool { return c.check == nil }

// sealBody encrypts the unlocked state under the key.
func (c *Collection) sealBody() ([]byte, error) {
	body := bodyJSON{Label: c.label, Created: c.created.Unix(), Modified: c.mod.Unix(), Items: []itemJSON{}}
	defer func() {
		for _, it := range body.Items {
			clear(it.Secret)
		}
	}()
	for _, id := range slices.Sorted(maps.Keys(c.entries)) {
		e := c.entries[id]
		secret, err := c.key.open(e.sealed, itemAD(id))
		if err != nil {
			return nil, fmt.Errorf("keyring: item %d's secret does not open: %w", id, err)
		}
		body.Items = append(body.Items, itemJSON{
			ID: id, Label: e.Label, Attributes: e.Attributes, ContentType: e.ContentType, Secret: secret,
			Created: e.Created.Unix(), Modified: e.Modified.Unix(),
		})
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("keyring: encode the body: %w", err)
	}
	defer clear(plain)
	return c.key.seal(plain, c.header()), nil
}

// Marshal is the collection file. A locked collection writes the body it
// was parsed or locked with; one left without a body has no file to give.
func (c *Collection) Marshal() ([]byte, error) {
	body := c.body
	if c.key != nil {
		var err error
		if body, err = c.sealBody(); err != nil {
			return nil, err
		}
	} else if body == nil {
		return nil, errors.New("keyring: the collection was destroyed or failed to lock, so it has no body to write")
	}
	return append(c.header(), body...), nil
}

// Rekey is a new key for a collection, derived outside the lock that guards it.
// Whoever gives up on one calls Discard.
type Rekey struct {
	key  *key
	salt []byte
	kdf  KDF
}

// NewRekey derives a new key from password with a fresh salt.
func NewRekey(password []byte, kdf KDF, stretch Stretch) (*Rekey, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keyring: salt: %w", err)
	}
	k, err := deriveKey(password, salt, kdf, stretch)
	if err != nil {
		return nil, err
	}
	return &Rekey{key: k, salt: salt, kdf: kdf}, nil
}

// Discard destroys a new key nothing will use.
func (r *Rekey) Discard() {
	r.key.destroy()
}

// ChangeKey moves an unlocked collection to the new key; r is used up.
func (c *Collection) ChangeKey(r *Rekey) error {
	if c.key == nil {
		r.Discard()
		return ErrLocked
	}
	sealed := make(map[uint32][]byte, len(c.entries))
	for id, e := range c.entries {
		secret, err := c.key.open(e.sealed, itemAD(id))
		if err != nil {
			r.Discard()
			return fmt.Errorf("keyring: item %d's secret does not open: %w", id, err)
		}
		sealed[id] = r.key.seal(secret, itemAD(id))
		clear(secret)
	}
	for id, e := range c.entries {
		e.sealed = sealed[id]
	}
	c.key.destroy()
	c.key, c.salt, c.kdf, c.check = r.key, r.salt, r.kdf, r.key.seal(nil, keyCheckAD)
	return nil
}

// Label is the collection's label, "" while locked.
func (c *Collection) Label() string { return c.label }

// SetLabel renames an unlocked collection.
func (c *Collection) SetLabel(label string, now time.Time) error {
	if c.key == nil {
		return ErrLocked
	}
	c.label, c.mod = label, now.UTC()
	return nil
}

// Created is when the collection was made, zero while locked.
func (c *Collection) Created() time.Time { return c.created }

// Modified is when it last changed, zero while locked.
func (c *Collection) Modified() time.Time { return c.mod }

// IDs is every item's id, ascending.
func (c *Collection) IDs() []uint32 { return slices.Sorted(maps.Keys(c.entries)) }

// Search is the items holding every attribute in attrs, ascending; it
// answers while locked too, from the hashes.
func (c *Collection) Search(attrs map[string]string) []uint32 {
	want := make([]attrHash, 0, len(attrs))
	for name, value := range attrs {
		want = append(want, hashAttr(name, value))
	}
	var out []uint32
	for id, e := range c.entries {
		if !slices.ContainsFunc(want, func(h attrHash) bool { return !slices.Contains(e.hashes, h) }) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// Item is an item's metadata; locked, only its ID is known.
func (c *Collection) Item(id uint32) (Item, error) {
	e, ok := c.entries[id]
	if !ok {
		return Item{}, ErrNoItem
	}
	it := e.Item
	it.Attributes = maps.Clone(e.Attributes)
	return it, nil
}

// Secret opens an item's secret. The caller clears it after use.
func (c *Collection) Secret(id uint32) ([]byte, error) {
	if c.key == nil {
		return nil, ErrLocked
	}
	e, ok := c.entries[id]
	if !ok {
		return nil, ErrNoItem
	}
	secret, err := c.key.open(e.sealed, itemAD(id))
	if err != nil {
		return nil, fmt.Errorf("keyring: item %d's secret does not open: %w", id, err)
	}
	return secret, nil
}

// CreateItem stores a secret. With replace, an item with exactly the
// same attributes is updated in place instead; created reports which.
func (c *Collection) CreateItem(label string, attrs map[string]string, secret []byte, contentType string, replace bool, now time.Time) (id uint32, created bool, err error) {
	if c.key == nil {
		return 0, false, ErrLocked
	}
	now = now.UTC()
	if replace {
		for _, cand := range c.Search(attrs) {
			if e := c.entries[cand]; maps.Equal(e.Attributes, attrs) {
				e.Label, e.ContentType, e.Modified = label, contentType, now
				e.sealed = c.key.seal(secret, itemAD(cand))
				c.mod = now
				return cand, false, nil
			}
		}
	}
	id = c.nextID
	c.nextID++
	e := &entry{ID: id, Created: now, Modified: now}
	c.entries[id] = e
	e.Label, e.ContentType = label, contentType
	c.setAttributes(e, attrs)
	e.sealed = c.key.seal(secret, itemAD(id))
	c.mod = now
	return id, true, nil
}

// SetSecret replaces an item's secret.
func (c *Collection) SetSecret(id uint32, secret []byte, contentType string, now time.Time) error {
	e, err := c.unlocked(id)
	if err != nil {
		return err
	}
	e.sealed, e.ContentType, e.Modified = c.key.seal(secret, itemAD(id)), contentType, now.UTC()
	c.mod = e.Modified
	return nil
}

// SetItemLabel renames an item.
func (c *Collection) SetItemLabel(id uint32, label string, now time.Time) error {
	e, err := c.unlocked(id)
	if err != nil {
		return err
	}
	e.Label, e.Modified = label, now.UTC()
	c.mod = e.Modified
	return nil
}

// SetItemAttributes replaces an item's attributes.
func (c *Collection) SetItemAttributes(id uint32, attrs map[string]string, now time.Time) error {
	e, err := c.unlocked(id)
	if err != nil {
		return err
	}
	c.setAttributes(e, attrs)
	e.Modified = now.UTC()
	c.mod = e.Modified
	return nil
}

// DeleteItem removes an item.
func (c *Collection) DeleteItem(id uint32, now time.Time) error {
	if _, err := c.unlocked(id); err != nil {
		return err
	}
	delete(c.entries, id)
	c.mod = now.UTC()
	return nil
}

func (c *Collection) unlocked(id uint32) (*entry, error) {
	if c.key == nil {
		return nil, ErrLocked
	}
	e, ok := c.entries[id]
	if !ok {
		return nil, ErrNoItem
	}
	return e, nil
}

func (c *Collection) setAttributes(e *entry, attrs map[string]string) {
	e.Attributes = maps.Clone(attrs)
	if e.Attributes == nil {
		e.Attributes = map[string]string{}
	}
	e.hashes = e.hashes[:0]
	for _, name := range slices.Sorted(maps.Keys(e.Attributes)) {
		e.hashes = append(e.hashes, hashAttr(name, e.Attributes[name]))
	}
}

// itemAD binds a sealed secret to its item, so secrets cannot be swapped
// between items.
func itemAD(id uint32) []byte { return binary.BigEndian.AppendUint32([]byte("item"), id) }

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.err = fmt.Errorf("want %d more bytes, have %d", n, len(r.b))
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
