package service

import (
	"slices"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/keyring"
)

const testInterface = "org.example.Test"

// The watch of clients leaving reads every signal the service's
// connection is sent, and closes the descriptors of those it drops.
func TestTheDescriptorsOfSignalsTheLeaverWatchDropsAreClosed(t *testing.T) {
	f := newFixture(t)
	rule := []dbus.MatchOption{dbus.WithMatchInterface(testInterface)}
	if err := f.svc.conn.AddMatchSignal(rule...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.svc.conn.RemoveMatchSignal(rule...) })
	pipe := dbustest.NewPipe(t)
	client := f.bus.Conn(t)
	sess := openSession(t, client)
	if err := client.Emit("/", testInterface+".Hand", pipe.Write); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.svc.mu.Lock()
		_, open := f.svc.sessions[sess]
		f.svc.mu.Unlock()
		if !open {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session outlived its client")
		}
		time.Sleep(20 * time.Millisecond)
	}
	pipe.RequireEveryCopyClosed(t)
}

// Close and a failed Start leave the connection's match rules as they
// were.
func TestTheLeaverWatchLeavesNoMatchRule(t *testing.T) {
	bus := dbustest.Session(t)
	conn := bus.Conn(t)
	before := dbustest.MatchRules(t, conn)
	svc, err := Start(conn, Config{Dir: t.TempDir(), KDF: testKDF, Stretch: keyring.Argon2id, Prompter: &fakePrompter{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := dbustest.MatchRules(t, conn); slices.Equal(got, before) {
		t.Fatalf("match rules while serving = %q, want the leaver watch's added", got)
	}
	svc.Close()
	if got := dbustest.MatchRules(t, conn); !slices.Equal(got, before) {
		t.Errorf("match rules after Close = %q, want %q", got, before)
	}
	other := bus.Conn(t)
	if _, err := other.RequestName(BusName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(conn, Config{Dir: t.TempDir(), KDF: testKDF, Stretch: keyring.Argon2id, Prompter: &fakePrompter{}}); err == nil {
		t.Fatal("Start beside another provider succeeded")
	}
	if got := dbustest.MatchRules(t, conn); !slices.Equal(got, before) {
		t.Errorf("match rules after a failed Start = %q, want %q", got, before)
	}
}
