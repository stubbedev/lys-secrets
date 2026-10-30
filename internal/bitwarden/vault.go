package bitwarden

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/stubbedev/lys-secrets/vault"
)

// SyncResponse is /sync's answer, the encrypted account.
type SyncResponse struct {
	Profile     SyncProfile
	Folders     []SyncFolder
	Collections []SyncCollection
	Ciphers     []SyncCipher
}

// SyncProfile carries the wrapped keys: the user key under the master
// key, the private key under the user key, each organization's key
// under the private key.
type SyncProfile struct {
	Email         string
	Key           string
	PrivateKey    string
	Organizations []SyncOrganization
}

// SyncOrganization is a membership: the organization and its wrapped
// key.
type SyncOrganization struct {
	ID, Name, Key string
}

// SyncFolder is a folder, its name encrypted under the user key.
type SyncFolder struct {
	ID, Name string
}

// SyncCollection is an organization collection, its name encrypted
// under the organization key.
type SyncCollection struct {
	ID, OrganizationID, Name string
}

// SyncCipher is one encrypted vault item.
type SyncCipher struct {
	ID             string
	OrganizationID string
	FolderID       string
	Type           vault.ItemType
	Name           string
	Notes          string
	Favorite       bool
	Key            string
	Reprompt       int
	DeletedDate    *string
	Login          *SyncLogin
	Card           *SyncCard
	Identity       *SyncIdentity
	Fields         []SyncField
}

// SyncLogin is a login's encrypted fields.
type SyncLogin struct {
	Username, Password, Totp string
	Uris                     []struct{ URI string }
}

// SyncCard is a card's encrypted fields.
type SyncCard struct {
	CardholderName, Brand, Number, ExpMonth, ExpYear, Code string
}

// SyncIdentity is an identity's encrypted fields this client shows.
type SyncIdentity struct {
	Title, FirstName, MiddleName, LastName, Email, Phone, Username, Company string
}

// SyncField is a custom field; its type says whether the value is
// hidden (1) or plain (0, 2 boolean, 3 linked).
type SyncField struct {
	Name, Value string
	Type        int
}

const hiddenFieldType = 1

// Item is a decrypted vault item. Undecryptable marks one any of whose
// fields failed to open (a key it was not shared with, an EncString
// type this client does not speak); the rest still shows.
type Item struct {
	ID            string
	Type          vault.ItemType
	Name          string
	Notes         string
	Folder        string
	Organization  string
	Favorite      bool
	Reprompt      bool
	Username      string
	Password      string
	TOTP          string
	URIs          []string
	Card          Card
	Identity      Identity
	Fields        []Field
	Undecryptable bool
}

// Card is a decrypted card.
type Card struct {
	Cardholder, Brand, Number, ExpMonth, ExpYear, Code string
}

// Identity is a decrypted identity's shown fields.
type Identity struct {
	Title, First, Middle, Last, Email, Phone, Username, Company string
}

// Field is a decrypted custom field.
type Field struct {
	Name, Value string
	Hidden      bool
}

// Vault is the decrypted account: its items, favorites first then by
// name, and folder names by id. Deleted items (the trash) are left out.
type Vault struct {
	Items   []Item
	Folders map[string]string
	// byID indexes Items by item id.
	byID map[string]int
}

// Wipe drops the plaintext; the vault is empty after.
func (v *Vault) Wipe() {
	clear(v.Items)
	v.Items = nil
	clear(v.Folders)
	clear(v.byID)
}

// Item is the item with id, false when the vault has none.
func (v *Vault) Item(id string) (Item, bool) {
	i, ok := v.byID[id]
	if !ok {
		return Item{}, false
	}
	return v.Items[i], true
}

// DecryptVault opens a sync under the keyring. A field that does not
// open marks its item Undecryptable rather than failing the sync.
func DecryptVault(kr *Keyring, s SyncResponse) Vault {
	v := Vault{Folders: make(map[string]string, len(s.Folders))}
	for _, f := range s.Folders {
		name, ok := open(kr.User, f.Name)
		if !ok {
			name = f.ID
		}
		v.Folders[f.ID] = name
	}
	for _, c := range s.Ciphers {
		if c.DeletedDate != nil {
			continue
		}
		v.Items = append(v.Items, decryptCipher(kr, c, v.Folders))
	}
	v.index()
	return v
}

func (v *Vault) index() {
	slices.SortStableFunc(v.Items, func(a, b Item) int {
		if a.Favorite != b.Favorite {
			if a.Favorite {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	v.byID = make(map[string]int, len(v.Items))
	for i, it := range v.Items {
		v.byID[it.ID] = i
	}
}

func (v *Vault) put(it Item) {
	if i, ok := v.byID[it.ID]; ok {
		v.Items[i] = it
	} else {
		v.Items = append(v.Items, it)
	}
	v.index()
}

func (v *Vault) folderID(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	var ids []string
	for id, n := range v.Folders {
		if n == name {
			ids = append(ids, id)
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("%w: %q", vault.ErrNoSuchFolder, name)
	case 1:
		return ids[0], nil
	default:
		return "", fmt.Errorf("%w: %d folders are named %q", vault.ErrAmbiguous, len(ids), name)
	}
}

func logins(items []Item, name string, scope vault.FolderScope) []Item {
	var out []Item
	for _, it := range items {
		if it.Type == vault.ItemLogin && it.Name == name && scope.Contains(it.Folder) {
			out = append(out, it)
		}
	}
	return out
}

// decryptCipher opens one item under its organization's key or the
// user key, and under its own item key when it has one.
func decryptCipher(kr *Keyring, c SyncCipher, folders map[string]string) Item {
	it := Item{ID: c.ID, Type: c.Type, Favorite: c.Favorite, Reprompt: c.Reprompt != 0, Folder: folders[c.FolderID], Organization: c.OrganizationID}
	key := kr.User
	if c.OrganizationID != "" {
		org, ok := kr.Orgs[c.OrganizationID]
		if !ok {
			it.Name, it.Undecryptable = c.ID, true
			return it
		}
		key = org
	}
	if c.Key != "" {
		e, err := ParseEncString(c.Key)
		if err != nil {
			it.Name, it.Undecryptable = c.ID, true
			return it
		}
		raw, err := key.Decrypt(e)
		if err != nil {
			it.Name, it.Undecryptable = c.ID, true
			return it
		}
		itemKey, err := symmetricKeyFrom(raw)
		wipe(raw)
		if err != nil {
			it.Name, it.Undecryptable = c.ID, true
			return it
		}
		defer itemKey.Wipe()
		key = itemKey
	}
	field := func(s string) string {
		if s == "" {
			return ""
		}
		v, ok := open(key, s)
		if !ok {
			it.Undecryptable = true
		}
		return v
	}
	it.Name = field(c.Name)
	if it.Name == "" {
		it.Name = c.ID
	}
	it.Notes = field(c.Notes)
	if l := c.Login; l != nil {
		it.Username, it.Password, it.TOTP = field(l.Username), field(l.Password), field(l.Totp)
		for _, u := range l.Uris {
			if s := field(u.URI); s != "" {
				it.URIs = append(it.URIs, s)
			}
		}
	}
	if cd := c.Card; cd != nil {
		it.Card = Card{Cardholder: field(cd.CardholderName), Brand: field(cd.Brand), Number: field(cd.Number), ExpMonth: field(cd.ExpMonth), ExpYear: field(cd.ExpYear), Code: field(cd.Code)}
	}
	if id := c.Identity; id != nil {
		it.Identity = Identity{Title: field(id.Title), First: field(id.FirstName), Middle: field(id.MiddleName), Last: field(id.LastName), Email: field(id.Email), Phone: field(id.Phone), Username: field(id.Username), Company: field(id.Company)}
	}
	for _, f := range c.Fields {
		it.Fields = append(it.Fields, Field{Name: field(f.Name), Value: field(f.Value), Hidden: f.Type == hiddenFieldType})
	}
	return it
}

// open decrypts one EncString field, false when it does not open.
func open(key SymmetricKey, s string) (string, bool) {
	v, err := key.DecryptString(s)
	return v, err == nil
}

// summary is what a listing shows of the item.
func (it Item) summary() vault.Item {
	return vault.Item{
		ID: it.ID, Type: it.Type, Name: it.Name, Folder: it.Folder, Organization: it.Organization,
		Favorite: it.Favorite, Reprompt: it.Reprompt, Undecryptable: it.Undecryptable,
		Username: it.Username, URIs: slices.Clone(it.URIs), CardBrand: it.Card.Brand, Fields: it.fields(),
	}
}

// fields is what the item gives out, its primary field first: a
// login's password, username and verification code, a card's number
// and code, an identity's email and username, a note's text. Empty
// fields are left out.
func (it Item) fields() []vault.Field {
	var fs []vault.Field
	add := func(f vault.Field, v string) {
		if v != "" {
			fs = append(fs, f)
		}
	}
	switch it.Type {
	case vault.ItemLogin:
		add(vault.FieldPassword, it.Password)
		add(vault.FieldUsername, it.Username)
		add(vault.FieldTOTP, it.TOTP)
	case vault.ItemCard:
		add(vault.FieldCardNumber, it.Card.Number)
		add(vault.FieldCardCode, it.Card.Code)
	case vault.ItemIdentity:
		add(vault.FieldEmail, it.Identity.Email)
		add(vault.FieldUsername, it.Identity.Username)
	case vault.ItemSecureNote:
		add(vault.FieldNotes, it.Notes)
	}
	return fs
}

// value is field f's value, a verification code the one current at
// now; ErrNoSuchField for a field the item does not give out.
func (it Item) value(f vault.Field, now time.Time) (vault.Value, error) {
	if !slices.Contains(it.fields(), f) {
		return vault.Value{}, fmt.Errorf("%w: item %s, field %d", vault.ErrNoSuchField, it.ID, f)
	}
	switch f {
	case vault.FieldUsername:
		if it.Type == vault.ItemIdentity {
			return vault.Value{Text: it.Identity.Username}, nil
		}
		return vault.Value{Text: it.Username}, nil
	case vault.FieldPassword:
		return vault.Value{Text: it.Password}, nil
	case vault.FieldTOTP:
		t, err := ParseTOTP(it.TOTP)
		if err != nil {
			return vault.Value{}, fmt.Errorf("bitwarden: item %s's verification code: %w", it.ID, err)
		}
		code, remaining := t.Code(now)
		return vault.Value{Text: code, Expires: now.Add(remaining)}, nil
	case vault.FieldCardNumber:
		return vault.Value{Text: it.Card.Number}, nil
	case vault.FieldCardCode:
		return vault.Value{Text: it.Card.Code}, nil
	case vault.FieldEmail:
		return vault.Value{Text: it.Identity.Email}, nil
	}
	return vault.Value{Text: it.Notes}, nil
}

// networkLogin is the login stored for the network connection named
// name: the one login item in folder with that exact name. None, two of
// them, or one protected by the master-password reprompt or not fully
// decrypted is no answer: a network secret is sent without asking, so
// it must be unambiguous and unprotected.
func networkLogin(items []Item, folder, name string) (Item, bool) {
	found := logins(items, name, vault.InFolder(folder))
	if len(found) != 1 || found[0].Reprompt || found[0].Undecryptable {
		return Item{}, false
	}
	return found[0], true
}

func findLogin(items []Item, name string, scope vault.FolderScope) (Item, bool, error) {
	found := logins(items, name, scope)
	switch len(found) {
	case 0:
		return Item{}, false, nil
	case 1:
		return found[0], true, nil
	default:
		return Item{}, false, fmt.Errorf("%w: %d logins are named %q", vault.ErrAmbiguous, len(found), name)
	}
}

type cipherRequest struct {
	Type     vault.ItemType `json:"type"`
	FolderID string         `json:"folderId,omitempty"`
	Name     string         `json:"name"`
	Favorite bool           `json:"favorite"`
	Reprompt int            `json:"reprompt"`
	Login    *loginRequest  `json:"login,omitempty"`
}

type loginRequest struct {
	Username string       `json:"username,omitempty"`
	Password string       `json:"password,omitempty"`
	URIs     []uriRequest `json:"uris"`
}

type uriRequest struct {
	URI         string `json:"uri"`
	URIChecksum string `json:"uriChecksum"`
}

func encryptLogin(key SymmetricKey, folderID string, l vault.NewLogin) (cipherRequest, error) {
	seal := func(what, s string) (string, error) {
		if s == "" {
			return "", nil
		}
		e, err := key.EncryptString(s)
		if err != nil {
			return "", fmt.Errorf("bitwarden: encrypt the %s: %w", what, err)
		}
		return e, nil
	}
	name, errN := seal("name", l.Name)
	username, errU := seal("username", l.Username)
	password, errP := seal("password", l.Password)
	if err := errors.Join(errN, errU, errP); err != nil {
		return cipherRequest{}, err
	}
	uris := make([]uriRequest, len(l.URIs))
	for i, u := range l.URIs {
		uri, err := seal("URI", u)
		if err != nil {
			return cipherRequest{}, err
		}
		checksum, err := seal("URI checksum", uriChecksum(u))
		if err != nil {
			return cipherRequest{}, err
		}
		uris[i] = uriRequest{URI: uri, URIChecksum: checksum}
	}
	return cipherRequest{
		Type: vault.ItemLogin, FolderID: folderID, Name: name,
		Login: &loginRequest{Username: username, Password: password, URIs: uris},
	}, nil
}

func uriChecksum(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return base64.StdEncoding.EncodeToString(sum[:])
}
