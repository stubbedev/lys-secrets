package service

import (
	"errors"
	"fmt"
	"os"

	"github.com/stubbedev/lys-secrets/internal/keyring"
)

// errNoLogin is a login secret asked for before the login collection exists.
var errNoLogin = errors.New("there is no login collection yet")

// LoginSecret is the secret of the first item of the login collection holding
// attrs, for lys-secrets' own use; found is false with none. A locked login
// collection is keyring.ErrLocked: it is not unlocked for this. The caller
// clears the secret.
func (s *Service) LoginSecret(attrs map[string]string) (secret []byte, found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.colls[LoginID]
	if !ok {
		return nil, false, errNoLogin
	}
	if c.kr.Locked() {
		return nil, false, fmt.Errorf("read a login secret: %w", keyring.ErrLocked)
	}
	ids := c.kr.Search(attrs)
	if len(ids) == 0 {
		return nil, false, nil
	}
	secret, err = c.kr.Secret(ids[0])
	if err != nil {
		return nil, false, err
	}
	s.usedLocked(c)
	return secret, true, nil
}

// StoreLoginSecret stores secret under attrs in the unlocked login collection,
// replacing an item with the same attributes, owned by lys-secrets itself.
func (s *Service) StoreLoginSecret(label string, attrs map[string]string, secret []byte) error {
	s.mu.Lock()
	c, ok := s.colls[LoginID]
	s.mu.Unlock()
	if !ok {
		return errNoLogin
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("name lys-secrets as the owner: %w", err)
	}
	if _, err := s.createItem(c, label, attrs, secret, "text/plain", keyring.Owner(self), true); err != nil {
		return fmt.Errorf("store a login secret: %w", err)
	}
	return nil
}
