package prompt

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	"github.com/stubbedev/lys-lib/portaldialogs"

	"github.com/stubbedev/lys-secrets/internal/dialogtest"
	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/pinentry"
	"github.com/stubbedev/lys-secrets/internal/service"
	"github.com/stubbedev/lys-secrets/internal/sshagent"
)

func TestOverlappingPromptsGetTheirOwnHandles(t *testing.T) {
	d := New(dbustest.Session(t).Conn(t))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, ok, err := d.Password(ctx, "login", false); err == nil || ok {
				t.Errorf("asked with no dialog host on the bus: ok %v, err %v", ok, err)
			}
		})
	}
	wg.Wait()
	if got := d.seq.Load(); got != 16 {
		t.Errorf("%d prompts numbered, want 16", got)
	}
}

func TestConfirmReadNamesTheProgramAndReadsTheAnswer(t *testing.T) {
	bus := dbustest.Session(t)
	answers := []struct {
		granted bool
		picked  []portaldialogs.Selection
	}{
		{false, nil},
		{true, []portaldialogs.Selection{{ID: "always", Value: "false"}}},
		{true, []portaldialogs.Selection{{ID: "always", Value: "true"}}},
		{true, nil},
	}
	host := &dialogtest.Host{}
	host.Access = func(portaldialogs.AccessRequest) (bool, []portaldialogs.Selection) {
		_, asked := host.Asked()
		a := answers[len(asked)-1]
		return a.granted, a.picked
	}
	dialogtest.Serve(t, bus.Conn(t), host)
	d := New(bus.Conn(t))
	r := service.ReadRequest{Program: "/usr/bin/secret-tool", PID: 42, Item: "Token", Collection: "Login", Owners: []keyring.Owner{"/usr/bin/git"}}
	for _, want := range []service.Access{service.Denied, service.AllowedOnce, service.AllowedAlways} {
		if got, err := d.ConfirmRead(t.Context(), r); err != nil || got != want {
			t.Errorf("ConfirmRead = %v, %v, want %v", got, err, want)
		}
	}
	_, asked := host.Asked()
	shown := asked[0]
	if !strings.Contains(shown.Subtitle, "secret-tool wants to read “Token” from the “Login” keyring") || !strings.Contains(shown.Body, "/usr/bin/secret-tool") || !strings.Contains(shown.Body, "/usr/bin/git") || len(shown.Choices) != 1 {
		t.Errorf("the dialog showed %+v", shown)
	}
	if got, err := d.ConfirmRead(t.Context(), service.ReadRequest{PID: 42, Item: "Token", Collection: "Login"}); err != nil || got != service.AllowedOnce {
		t.Errorf("an unidentified program's ConfirmRead = %v, %v", got, err)
	}
	_, asked = host.Asked()
	if last := asked[len(asked)-1]; len(last.Choices) != 0 || !strings.Contains(last.Body, "Process 42") {
		t.Errorf("an unidentified program's dialog showed %+v", last)
	}
}

func TestKeyPassphraseOffersToRememberIt(t *testing.T) {
	bus := dbustest.Session(t)
	host := &dialogtest.Host{Password: func(r portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection) {
		return true, "phrase", []portaldialogs.Selection{{ID: r.Choices[0].ID, Value: r.Choices[0].Initial}}
	}}
	dialogtest.Serve(t, bus.Conn(t), host)
	d := New(bus.Conn(t))
	k := sshagent.Key{Path: "/home/u/.ssh/id_ed25519", Fingerprint: "SHA256:abc", Comment: "u@host"}
	passphrase, remember, ok, err := d.KeyPassphrase(t.Context(), k, true)
	if err != nil || !ok || !remember || string(passphrase) != "phrase" {
		t.Fatalf("KeyPassphrase = %q, %v, %v, %v", passphrase, remember, ok, err)
	}
	asked, _ := host.Asked()
	r := asked[0]
	if !r.Retry || !strings.Contains(r.Body, "u@host") || !strings.Contains(r.Body, "SHA256:abc") || len(r.Choices) != 1 || r.Choices[0].Label != "Remember in the login keyring" || r.Choices[0].Initial != "true" {
		t.Errorf("the dialog showed %+v", r)
	}
}

func TestGetPinShowsGpgAgentsDialog(t *testing.T) {
	bus := dbustest.Session(t)
	d := New(bus.Conn(t))
	if _, _, _, err := d.GetPin(t.Context(), pinentry.Request{}); !errors.Is(err, pinentry.ErrNoDialogHost) {
		t.Fatalf("GetPin with no dialog host = %v, want ErrNoDialogHost", err)
	}
	host := &dialogtest.Host{Password: func(r portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection) {
		return true, "pin", []portaldialogs.Selection{{ID: "remember", Value: "false"}}
	}}
	dialogtest.Serve(t, bus.Conn(t), host)
	pin, remember, ok, err := d.GetPin(t.Context(), pinentry.Request{
		Description: "Unlock the key", Error: "Bad Passphrase (try 2 of 3)", OK: "_OK", Cancel: "_Cancel", Repeat: true, Remember: true,
	})
	if err != nil || !ok || remember || string(pin) != "pin" {
		t.Fatalf("GetPin = %q, %v, %v, %v", pin, remember, ok, err)
	}
	asked, _ := host.Asked()
	r := asked[0]
	if r.Body != "Bad Passphrase (try 2 of 3)\n\nUnlock the key" || !r.Retry || !r.Confirm || r.AcceptLabel != "OK" || r.CancelLabel != "Cancel" || len(r.Choices) != 1 {
		t.Errorf("the dialog showed %+v", r)
	}
	if got := mnemonicFree("Save in __password manager_"); got != "Save in _password manager" {
		t.Errorf("mnemonicFree = %q", got)
	}
}
