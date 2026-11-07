package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
	"golang.org/x/sys/unix"

	"github.com/stubbedev/lys-secrets/client"
	"github.com/stubbedev/lys-secrets/internal/pinentry"
	"github.com/stubbedev/lys-secrets/internal/prompt"
)

// cacheTimeout bounds each round trip to the Secret Service for a cached
// passphrase.
const cacheTimeout = 10 * time.Second

// runPinentry is lys-secrets pinentry: gpg-agent's pinentry on standard input
// and output, asking through the session's dialog host and caching in its
// Secret Service. Without a session bus every dialog is GPG_ERR_NO_PIN_ENTRY.
func runPinentry() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("make the process undumpable: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lys-secrets pinentry: no session bus, so no dialog: %v\n", err)
		return pinentry.Serve(ctx, os.Stdin, os.Stdout, noDialogHost{}, nil)
	}
	defer func() { _ = conn.Close() }()
	return pinentry.Serve(ctx, os.Stdin, os.Stdout, prompt.New(conn), secretCache{conn: conn})
}

// noDialogHost is the UI of a pinentry with no session bus.
type noDialogHost struct{}

func (noDialogHost) GetPin(context.Context, pinentry.Request) ([]byte, bool, bool, error) {
	return nil, false, false, pinentry.ErrNoDialogHost
}

func (noDialogHost) Confirm(context.Context, pinentry.Request, bool) (bool, error) {
	return false, pinentry.ErrNoDialogHost
}

// secretCache keeps GnuPG passphrases in the Secret Service as
// pinentry-gnome3 does, remembering them in the login collection.
type secretCache struct{ conn *dbus.Conn }

func passphraseAttrs(keyinfo string) map[string]string {
	return map[string]string{"xdg:schema": pinentry.Schema, "keygrip": keyinfo}
}

func (c secretCache) session(ctx context.Context, do func(context.Context, *client.Client) error) error {
	ctx, cancel := context.WithTimeout(ctx, cacheTimeout)
	defer cancel()
	cl, err := client.Open(ctx, c.conn)
	if err != nil {
		return err
	}
	defer cl.Close()
	return do(ctx, cl)
}

func (c secretCache) Lookup(ctx context.Context, keyinfo string) (pin []byte, found bool, err error) {
	err = c.session(ctx, func(ctx context.Context, cl *client.Client) error {
		pin, found, err = cl.Find(ctx, passphraseAttrs(keyinfo))
		return err
	})
	return pin, found, err
}

func (c secretCache) Store(ctx context.Context, keyinfo string, pin []byte) error {
	attrs := passphraseAttrs(keyinfo)
	attrs["stored-by"] = "GnuPG Pinentry"
	return c.session(ctx, func(ctx context.Context, cl *client.Client) error {
		return cl.StoreLogin(ctx, "GnuPG: "+keyinfo, attrs, pin)
	})
}

func (c secretCache) Clear(ctx context.Context, keyinfo string) error {
	return c.session(ctx, func(ctx context.Context, cl *client.Client) error {
		return cl.Delete(ctx, passphraseAttrs(keyinfo))
	})
}
