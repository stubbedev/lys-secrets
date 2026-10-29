package bitwarden

import (
	"fmt"

	"github.com/stubbedev/lys-secrets/vault"
)

// FolderLogin is a login the Secret Service shows: its id, name,
// username, first URI and folder.
type FolderLogin struct {
	ID, Name, Username, URI, Folder string
}

// shareable reports whether it may leave the vault unasked, as a
// Secret Service item: a login in folder with a password, fully
// decrypted, and not behind the master password reprompt.
func (it Item) shareable(folder string) bool {
	return it.Type == vault.ItemLogin && it.Folder == folder && it.Password != "" && !it.Reprompt && !it.Undecryptable
}

// FolderLogins is the open vault's shareable logins in folder, in vault
// order; open is false (and the list empty) while the vault is not
// open.
func (s *Service) FolderLogins(folder string) (logins []FolderLogin, open bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr == nil {
		return nil, false
	}
	for _, it := range s.vault.Items {
		if !it.shareable(folder) {
			continue
		}
		l := FolderLogin{ID: it.ID, Name: it.Name, Username: it.Username, Folder: it.Folder}
		if len(it.URIs) > 0 {
			l.URI = it.URIs[0]
		}
		logins = append(logins, l)
	}
	return logins, true
}

// FolderPassword is the password of login id, one of FolderLogins'
// for folder. It counts as use.
func (s *Service) FolderPassword(folder, id string) ([]byte, error) {
	s.mu.Lock()
	it, ok := s.vault.Item(id)
	open := s.kr != nil
	s.mu.Unlock()
	switch {
	case !open:
		return nil, vault.ErrLocked
	case !ok || !it.shareable(folder):
		return nil, fmt.Errorf("%w: %s in folder %q", vault.ErrNoSuchItem, id, folder)
	}
	s.touch()
	return []byte(it.Password), nil
}
