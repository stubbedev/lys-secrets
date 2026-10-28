package secretstest_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stubbedev/lys-lib/dbustest"

	"github.com/stubbedev/lys-secrets/client"
	"github.com/stubbedev/lys-secrets/secretstest"
)

func TestServesTheUnlockedLoginCollectionAndScriptsItsPrompts(t *testing.T) {
	bus := dbustest.Start(t)
	srv := secretstest.Start(t, bus.Conn(t), "pw")
	c, err := client.Open(t.Context(), bus.Conn(t))
	if err != nil {
		t.Fatalf("open a session: %v", err)
	}
	defer c.Close()
	attrs := map[string]string{"app": "a"}
	if err := c.Store(t.Context(), "x", attrs, []byte("v")); err != nil {
		t.Fatalf("store in the unlocked login collection: %v", err)
	}

	srv.Lock()
	srv.Answer("")
	if _, _, err := c.Lookup(t.Context(), attrs); !errors.Is(err, client.ErrDismissed) {
		t.Errorf("lookup with the unlock prompt dismissed = %v, want ErrDismissed", err)
	}
	if _, _, err := c.Lookup(t.Context(), attrs); !errors.Is(err, client.ErrDismissed) {
		t.Errorf("lookup with no answer scripted = %v, want ErrDismissed", err)
	}
	srv.Answer("wrong", "pw")
	if v, found, err := c.Lookup(t.Context(), attrs); err != nil || !found || !bytes.Equal(v, []byte("v")) {
		t.Errorf("lookup after a wrong then the right password = %q %v %v", v, found, err)
	}
}
