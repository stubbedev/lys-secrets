package client

import (
	"context"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/secretbus"
)

const fakePromptPath = dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")

// impersonatedPrompt is a provider's prompt that, shown, has an
// impostor complete it first, with a descriptor as its result, and then
// completes it itself.
type impersonatedPrompt struct {
	provider, impostor *dbus.Conn
	fd                 dbus.UnixFD
	failed             chan error
}

func (p *impersonatedPrompt) Prompt(string) *dbus.Error {
	go func() {
		p.failed <- p.complete()
	}()
	return nil
}

func (p *impersonatedPrompt) complete() error {
	if err := secretbus.PromptCompleted.Emit(p.impostor, fakePromptPath, secretbus.Completion{Result: dbus.MakeVariant(p.fd)}); err != nil {
		return err
	}
	if err := p.impostor.BusObject().Call("org.freedesktop.DBus.GetId", 0).Err; err != nil {
		return err
	}
	return secretbus.PromptCompleted.Emit(p.provider, fakePromptPath, secretbus.Completion{Result: dbus.MakeVariant("the provider's")})
}

func TestAPromptIsCompletedOnlyByTheProvider(t *testing.T) {
	bus := dbustest.Start(t)
	pipe := dbustest.NewPipe(t)
	p := &impersonatedPrompt{provider: bus.Conn(t), impostor: bus.Conn(t), fd: pipe.Write, failed: make(chan error, 1)}
	if err := p.provider.Export(p, fakePromptPath, secretbus.PromptInterface); err != nil {
		t.Fatal(err)
	}
	if reply, err := p.provider.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request %s: %v %v", busName, reply, err)
	}
	c := &Client{conn: bus.Conn(t)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := c.prompt(ctx, fakePromptPath)
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	if got, ok := result.Value().(string); !ok || got != "the provider's" {
		t.Errorf("prompt completed with %v, want the provider's result, not the impostor's", result)
	}
	if err := <-p.failed; err != nil {
		t.Fatalf("complete the prompt: %v", err)
	}
	pipe.RequireEveryCopyClosed(t)
}
