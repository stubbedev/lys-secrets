// Package prompt asks the user for lys-secrets' passwords through the
// shell's dialog host (dev.stubbe.lys.PortalDialogs1), so the prompts
// look like every other lys dialog and lys-secrets draws no UI itself.
package prompt

import (
	"cmp"
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
	"github.com/stubbedev/lys-secrets/internal/pinentry"
	"github.com/stubbedev/lys-secrets/internal/service"
	"github.com/stubbedev/lys-secrets/internal/sshagent"
)

// Dialogs is a service.Prompter, an sshagent.Prompter and a pinentry.UI over
// the shell's dialogs.
type Dialogs struct {
	conn   *dbus.Conn
	client *portaldialogs.Client
	seq    atomic.Uint64
}

// New prompts through the dialog host on conn.
func New(conn *dbus.Conn) *Dialogs {
	return &Dialogs{conn: conn, client: portaldialogs.NewClient(conn)}
}

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
	password, _, ok, err := d.askChoosing(ctx, r)
	return password, ok, err
}

// askChoosing asks for a password and the request's choices.
func (d *Dialogs) askChoosing(ctx context.Context, r portaldialogs.PasswordRequest) ([]byte, []portaldialogs.Selection, bool, error) {
	caller, done := d.caller(ctx)
	defer done()
	ok, password, picked, err := d.client.Password(ctx, caller, r)
	if err != nil {
		return nil, nil, false, fmt.Errorf("ask through %s: %w", portaldialogs.ServiceName, err)
	}
	if !ok {
		return nil, nil, false, nil
	}
	return []byte(password), picked, true, nil
}

// rememberChoice is the checkbox that keeps a passphrase in the login
// collection.
var rememberChoice = portaldialogs.Choice{ID: "remember", Label: "Remember in the login keyring", Options: []portaldialogs.Option{}, Initial: "true"}

// remembered reports whether the user left rememberChoice ticked.
func remembered(picked []portaldialogs.Selection) bool {
	return slices.Contains(picked, portaldialogs.Selection{ID: rememberChoice.ID, Value: "true"})
}

// KeyPassphrase asks for an SSH key's passphrase, and whether to remember it.
func (d *Dialogs) KeyPassphrase(ctx context.Context, k sshagent.Key, retry bool) ([]byte, bool, bool, error) {
	name := cmp.Or(k.Comment, k.Path)
	passphrase, picked, ok, err := d.askChoosing(ctx, portaldialogs.PasswordRequest{
		Title:       "Unlock SSH key",
		Body:        fmt.Sprintf("Enter the passphrase of the SSH key “%s” (%s) to sign with it.", name, k.Fingerprint),
		Retry:       retry,
		AcceptLabel: "Unlock",
		Choices:     []portaldialogs.Choice{rememberChoice},
	})
	return passphrase, remembered(picked), ok, err
}

// ConfirmUse asks whether an SSH key added with ssh-add -c may sign.
func (d *Dialogs) ConfirmUse(ctx context.Context, k sshagent.Key) (bool, error) {
	caller, done := d.caller(ctx)
	defer done()
	granted, _, err := d.client.Access(ctx, caller, portaldialogs.AccessRequest{
		Title:      "Use SSH key?",
		Subtitle:   fmt.Sprintf("A program wants to sign with the SSH key “%s”.", cmp.Or(k.Comment, k.Fingerprint)),
		Body:       "Fingerprint: " + k.Fingerprint,
		GrantLabel: "Allow",
		DenyLabel:  "Deny",
		Icon:       "dialog-password",
	})
	if err != nil {
		return false, fmt.Errorf("ask through %s: %w", portaldialogs.ServiceName, err)
	}
	return granted, nil
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

// hostTimeout bounds asking the bus whether a dialog host is there.
const hostTimeout = time.Second

// present is pinentry.ErrNoDialogHost unless a dialog host owns its name.
// It asks the bus who owns the name rather than calling it, which could wait
// on a host D-Bus would try to start.
func (d *Dialogs) present(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, hostTimeout)
	defer cancel()
	var has bool
	if err := d.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, portaldialogs.ServiceName).Store(&has); err != nil {
		return fmt.Errorf("%w: ask the bus for %s: %w", pinentry.ErrNoDialogHost, portaldialogs.ServiceName, err)
	}
	if !has {
		return pinentry.ErrNoDialogHost
	}
	return nil
}

// GetPin asks for a GnuPG passphrase as gpg-agent set the dialog up.
func (d *Dialogs) GetPin(ctx context.Context, r pinentry.Request) ([]byte, bool, bool, error) {
	if err := d.present(ctx); err != nil {
		return nil, false, false, err
	}
	req := portaldialogs.PasswordRequest{
		Title:       cmp.Or(r.Title, "GnuPG passphrase"),
		Body:        strings.Join(nonEmpty(r.Error, r.Description), "\n\n"),
		Confirm:     r.Repeat,
		Retry:       r.Error != "",
		AcceptLabel: mnemonicFree(r.OK),
		CancelLabel: mnemonicFree(r.Cancel),
	}
	if r.Remember {
		req.Choices = []portaldialogs.Choice{rememberChoice}
	}
	pin, picked, ok, err := d.askChoosing(ctx, req)
	return pin, remembered(picked), ok, err
}

// Confirm asks gpg-agent's question; a message only has its OK.
func (d *Dialogs) Confirm(ctx context.Context, r pinentry.Request, oneButton bool) (bool, error) {
	if err := d.present(ctx); err != nil {
		return false, err
	}
	caller, done := d.caller(ctx)
	defer done()
	deny := cmp.Or(mnemonicFree(r.Cancel), "Cancel")
	if oneButton {
		deny = "Close"
	}
	granted, _, err := d.client.Access(ctx, caller, portaldialogs.AccessRequest{
		Title:      cmp.Or(r.Title, "GnuPG"),
		Body:       strings.Join(nonEmpty(r.Error, r.Description), "\n\n"),
		GrantLabel: cmp.Or(mnemonicFree(r.OK), "OK"),
		DenyLabel:  deny,
		Icon:       "dialog-password",
	})
	if err != nil {
		return false, fmt.Errorf("ask through %s: %w", portaldialogs.ServiceName, err)
	}
	return granted, nil
}

func nonEmpty(parts ...string) []string {
	out := parts[:0:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// mnemonicFree drops GnuPG's mnemonic underscores from a label: "_OK" is
// "OK", and "__" an underscore.
func mnemonicFree(label string) string {
	var b strings.Builder
	for i := 0; i < len(label); i++ {
		if label[i] == '_' {
			if i+1 < len(label) && label[i+1] == '_' {
				b.WriteByte('_')
				i++
			}
			continue
		}
		b.WriteByte(label[i])
	}
	return b.String()
}
