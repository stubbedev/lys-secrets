// Package secretstest serves lys-secrets' Secret Service on a test's
// own bus, so a consumer (lys-shell's Secret portal) is checked against
// the real service instead of a fake. The collections live in the
// test's temporary directory under a fast KDF, and the user's answers
// to its password prompts are scripted.
package secretstest

import (
	"context"
	"sync"
	"testing"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/service"
)

// Server is a Secret Service serving org.freedesktop.secrets on a
// test's bus until the test ends.
type Server struct {
	svc     *service.Service
	prompts *prompts
}

// Start serves the Secret Service on conn with its login collection
// created and unlocked with password. It fails the test when the name
// is taken or the collection cannot be created.
func Start(t testing.TB, conn *dbus.Conn, password string) *Server {
	t.Helper()
	p := &prompts{}
	svc, err := service.Start(conn, service.Config{
		Dir: t.TempDir(), KDF: keyring.KDF{Time: 1, MemKiB: 64, Threads: 1}, Prompter: p,
	})
	if err != nil {
		t.Fatalf("secretstest: start the Secret Service: %v", err)
	}
	t.Cleanup(svc.Close)
	if err := svc.UnlockLogin([]byte(password)); err != nil {
		t.Fatalf("secretstest: unlock the login collection: %v", err)
	}
	return &Server{svc: svc, prompts: p}
}

// Lock locks every collection, as the user locking the session does.
func (s *Server) Lock() { s.svc.Lock() }

// Answer scripts the user's answers to the next password prompts, in
// order: a password, or "" to dismiss the prompt. A prompt with no
// answer left is dismissed.
func (s *Server) Answer(answers ...string) {
	s.prompts.mu.Lock()
	defer s.prompts.mu.Unlock()
	s.prompts.answers = append(s.prompts.answers, answers...)
}

type prompts struct {
	mu      sync.Mutex
	answers []string
}

func (p *prompts) next() ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.answers) == 0 {
		return nil, false, nil
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return []byte(a), a != "", nil
}

func (p *prompts) Password(context.Context, string, bool) ([]byte, bool, error) {
	return p.next()
}

func (p *prompts) NewPassword(context.Context, string) ([]byte, bool, error) { return p.next() }

func (p *prompts) MasterPassword(context.Context, bool) ([]byte, bool, error) { return p.next() }
