package bitwarden

import (
	"context"
	"errors"
	"testing"

	"github.com/stubbedev/lys-lib/dbustest"

	"github.com/stubbedev/lys-secrets/client"
	"github.com/stubbedev/lys-secrets/secretstest"
	"github.com/stubbedev/lys-secrets/vault"
)

func TestTheSessionOutlivesARestartInTheSecretService(t *testing.T) {
	a := newAccount(t)
	bus := dbustest.Start(t)
	conn := bus.Conn(t)
	srv := secretstest.Start(t, conn, "login-pw")
	dir := t.TempDir()
	open := func() *Service {
		t.Helper()
		s, err := Open(dir, "lys-secrets", client.NewKeychain(conn), func() {})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if err := open().Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{"xdg:schema": keychainSchema, "server": a.server().String(), "email": "test@bitwarden.com"}
	kept, found, err := client.NewKeychain(bus.Conn(t)).Lookup(context.Background(), attrs)
	if err != nil || !found {
		t.Fatalf("the Secret Service keeps no session: %v, %v", found, err)
	}
	if cred, err := parseCredential(kept); err != nil || cred.RefreshToken != a.refresh {
		t.Errorf("the Secret Service keeps %q, %v; want the refresh token %s", kept, err, a.refresh)
	}

	srv.Lock()
	srv.Answer("")
	restarted := open()
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); !errors.Is(err, client.ErrDismissed) || restarted.Status().State != vault.StateLocked {
		t.Errorf("unlock with the keyring prompt dismissed = %v, status %+v; want ErrDismissed and still locked", err, restarted.Status())
	}
	srv.Answer("login-pw")
	if err := restarted.Unlock(context.Background(), "asdfasdfasdf"); err != nil || restarted.Status().State != vault.StateUnlocked {
		t.Fatalf("unlock after the keyring opened = %v, status %+v", err, restarted.Status())
	}

	if err := restarted.Logout(context.Background()); err != nil && !errors.Is(err, vault.ErrRevocationUnsupported) {
		t.Fatal(err)
	}
	if _, found, err := client.NewKeychain(bus.Conn(t)).Lookup(context.Background(), attrs); err != nil || found {
		t.Errorf("after the logout the Secret Service still keeps the session: %v, %v", found, err)
	}
}
