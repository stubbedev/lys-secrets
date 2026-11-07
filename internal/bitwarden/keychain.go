package bitwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/stubbedev/lys-secrets/vault"
)

type Keychain interface {
	Lookup(ctx context.Context, attrs map[string]string) (value []byte, found bool, err error)
	Store(ctx context.Context, label string, attrs map[string]string, value []byte) error
	Delete(ctx context.Context, attrs map[string]string) error
}

const keychainSchema = "dev.stubbe.lys.Vault.Session"

type credential struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

var errBadCredential = errors.New("bitwarden: the session in the keyring is unusable")

func parseCredential(b []byte) (credential, error) {
	var c credential
	if err := json.Unmarshal(b, &c); err != nil {
		return credential{}, fmt.Errorf("%w: %w", errBadCredential, err)
	}
	if c.RefreshToken == "" && c.ClientSecret == "" {
		return credential{}, fmt.Errorf("%w: it holds neither a refresh token nor an API key", errBadCredential)
	}
	return c, nil
}

func keychainAttrs(sess *session) map[string]string {
	return map[string]string{"xdg:schema": keychainSchema, "server": sess.Server.String(), "email": sess.Email}
}

func (s *Service) keep(ctx context.Context, sess *session, cred credential) error {
	b, err := json.Marshal(cred) //nolint:gosec // the credential goes to the keyring, encrypted at rest
	if err != nil {
		return fmt.Errorf("bitwarden: credential: %w", err)
	}
	if err := s.keychain.Store(ctx, "Bitwarden session for "+sess.Email, keychainAttrs(sess), b); err != nil {
		return fmt.Errorf("bitwarden: keep the session in the keyring: %w", err)
	}
	return nil
}

func (s *Service) heldCredential(ctx context.Context, sess *session) (cred credential, found bool, err error) {
	s.mu.Lock()
	held := s.cred
	s.mu.Unlock()
	if held != nil {
		return *held, true, nil
	}
	b, found, err := s.keychain.Lookup(ctx, keychainAttrs(sess))
	if err != nil {
		return credential{}, false, fmt.Errorf("bitwarden: read the session from the keyring: %w", err)
	}
	if !found {
		return credential{}, false, nil
	}
	cred, err = parseCredential(b)
	if err != nil {
		return credential{}, false, err
	}
	s.mu.Lock()
	if s.sess == sess {
		s.cred = &cred
	}
	s.mu.Unlock()
	return cred, true, nil
}

func (s *Service) credential(ctx context.Context, sess *session) (credential, error) {
	cred, found, err := s.heldCredential(ctx, sess)
	switch {
	case err != nil && !errors.Is(err, errBadCredential):
		return credential{}, err
	case err != nil:
		return credential{}, errors.Join(fmt.Errorf("%w: %w", vault.ErrLoginRequired, err), s.logout(ctx))
	case !found:
		return credential{}, errors.Join(fmt.Errorf("%w: the keyring keeps no session for %s", vault.ErrLoginRequired, sess.Email), s.logout(ctx))
	}
	return cred, nil
}
