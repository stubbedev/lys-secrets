// Package prompt asks the user for lys-secrets' passwords through the
// shell's dialog host (dev.stubbe.lys.PortalDialogs1), so the prompts
// look like every other lys dialog and lys-secrets draws no UI itself.
package prompt

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/stubbedev/lys-lib/portaldialogs"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/service"
)

// Dialogs is a service.Prompter over the shell's dialogs.
type Dialogs struct {
	client *portaldialogs.Client
	seq    atomic.Uint64
}

// New prompts through the dialog host on conn.
func New(conn *dbus.Conn) *Dialogs { return &Dialogs{client: portaldialogs.NewClient(conn)} }

// caller is a new prompt's caller, taken down with ctx.
func (d *Dialogs) caller(ctx context.Context) (portaldialogs.Caller, func()) {
	caller := portaldialogs.Caller{Handle: fmt.Sprintf("/dev/stubbe/lys/secrets/prompt/%d", d.seq.Add(1))}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			dismiss, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = d.client.Dismiss(dismiss, caller.Handle)
		case <-done:
		}
	}()
	return caller, func() { close(done) }
}

func (d *Dialogs) ask(ctx context.Context, r portaldialogs.PasswordRequest) ([]byte, bool, error) {
	caller, done := d.caller(ctx)
	defer done()
	ok, password, _, err := d.client.Password(ctx, caller, r)
	if err != nil {
		return nil, false, fmt.Errorf("ask through %s: %w", portaldialogs.ServiceName, err)
	}
	if !ok {
		return nil, false, nil
	}
	return []byte(password), true, nil
}

// Password asks for an existing collection's password.
func (d *Dialogs) Password(ctx context.Context, collection string, retry bool) ([]byte, bool, error) {
	return d.ask(ctx, portaldialogs.PasswordRequest{
		Title: "Unlock keyring",
		Body:  fmt.Sprintf("An application wants to use the “%s” keyring, which is locked.", collection),
		Retry: retry,
	})
}

// NewPassword asks for a new collection's password, twice.
func (d *Dialogs) NewPassword(ctx context.Context, collection string) ([]byte, bool, error) {
	return d.ask(ctx, portaldialogs.PasswordRequest{
		Title:   "New keyring password",
		Body:    fmt.Sprintf("Choose a password for the “%s” keyring. It encrypts the secrets stored in it.", collection),
		Confirm: true,
	})
}

// MasterPassword asks for the Bitwarden vault's master password.
func (d *Dialogs) MasterPassword(ctx context.Context, retry bool) ([]byte, bool, error) {
	return d.ask(ctx, portaldialogs.PasswordRequest{
		Title: "Unlock Bitwarden",
		Body:  "An application wants a password from your Bitwarden vault, which is locked. Enter your master password.",
		Retry: retry,
	})
}

// PreviousLoginPassword asks for the login password from before it changed.
func (d *Dialogs) PreviousLoginPassword(ctx context.Context, retry bool) ([]byte, bool, error) {
	return d.ask(ctx, portaldialogs.PasswordRequest{
		Title:       "Your login password changed",
		Body:        "Enter your previous password to update the login keyring. To keep the keyring on its old password, apart from your login, keep the old password; it then asks for that password when an application needs it.",
		Retry:       retry,
		AcceptLabel: "Update",
		CancelLabel: "Keep the old password",
	})
}

// alwaysChoice is ConfirmRead's choice to make the program an owner.
const alwaysChoice = "always"

// ConfirmRead asks whether a program may read an item it does not own.
func (d *Dialogs) ConfirmRead(ctx context.Context, r service.ReadRequest) (service.Access, error) {
	caller, done := d.caller(ctx)
	defer done()
	who, details := "A program that could not be identified", fmt.Sprintf("Process %d", r.PID)
	var choices []portaldialogs.Choice
	if r.Program != "" {
		who = programName(r.Program)
		details = "Program: " + string(r.Program)
		choices = []portaldialogs.Choice{{ID: alwaysChoice, Label: "Always allow " + who + " to read it", Options: []portaldialogs.Option{}}}
	}
	stored := make([]string, len(r.Owners))
	for i, o := range r.Owners {
		stored[i] = string(o)
	}
	granted, picked, err := d.client.Access(ctx, caller, portaldialogs.AccessRequest{
		Title:      "Allow access to a secret?",
		Subtitle:   fmt.Sprintf("%s wants to read “%s” from the “%s” keyring.", who, r.Item, r.Collection),
		Body:       details + "\nStored by: " + strings.Join(stored, ", "),
		GrantLabel: "Allow",
		DenyLabel:  "Deny",
		Icon:       "dialog-password",
		Choices:    choices,
	})
	if err != nil {
		return service.Denied, fmt.Errorf("ask through %s: %w", portaldialogs.ServiceName, err)
	}
	if !granted {
		return service.Denied, nil
	}
	if slices.Contains(picked, portaldialogs.Selection{ID: alwaysChoice, Value: "true"}) {
		return service.AllowedAlways, nil
	}
	return service.AllowedOnce, nil
}

// programName is how the dialog names a program: a Flatpak app by its id,
// anything else by its executable's name.
func programName(p keyring.Owner) string {
	if app, ok := strings.CutPrefix(string(p), "flatpak:"); ok {
		return app
	}
	return filepath.Base(string(p))
}
