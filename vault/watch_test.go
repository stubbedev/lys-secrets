package vault

import (
	"context"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

func awaitStatus(t *testing.T, statuses <-chan Status, what string) Status {
	t.Helper()
	select {
	case s := <-statuses:
		return s
	case <-time.After(5 * time.Second):
		t.Fatalf("no Changed for %s", what)
	}
	return Status{}
}

// A watch begun before the vault is on the bus hears it appear, and
// keeps following it across a restart.
func TestWatchFollowsTheVaultAcrossARestart(t *testing.T) {
	bus := testBus{t, dbustest.Start(t).Address}
	statuses := make(chan Status, 4)
	if err := NewClient(bus.conn()).Watch(ctx(t), Watcher{Changed: func(s Status) { statuses <- s }, SyncFailed: func(err error) { t.Errorf("sync failed: %v", err) }}); err != nil {
		t.Fatal(err)
	}
	first := NewDaemon(context.Background(), &fakeHost{status: Status{State: StateLocked, Email: "ada@example.com"}})
	release, err := first.Export(bus.conn())
	if err != nil {
		t.Fatal(err)
	}
	if s := awaitStatus(t, statuses, "the vault appearing"); s.State != StateLocked || s.Email != "ada@example.com" {
		t.Errorf("the vault appeared as %+v, want the first daemon's status", s)
	}
	release()
	second := NewDaemon(context.Background(), &fakeHost{status: Status{State: StateLoggedOut}})
	releaseSecond, err := second.Export(bus.conn())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(releaseSecond)
	if s := awaitStatus(t, statuses, "the vault restarting"); s.State != StateLoggedOut {
		t.Errorf("the restarted vault appeared as %+v, want the second daemon's status", s)
	}
	if err := second.Changed(); err != nil {
		t.Fatal(err)
	}
	if s := awaitStatus(t, statuses, "the restarted vault's Changed"); s.State != StateLoggedOut {
		t.Errorf("the restarted vault's Changed = %+v, want its status", s)
	}
}

// A Changed from anyone but the vault is dropped, with the descriptor
// it carries closed.
func TestWatchClosesTheDescriptorsOfAnImpostorsSignal(t *testing.T) {
	host := &fakeHost{status: Status{State: StateLocked, Email: "ada@example.com"}}
	d, c, conn, bus := serveOn(t, host)
	statuses := make(chan Status, 4)
	if err := c.Watch(ctx(t), Watcher{Changed: func(s Status) { statuses <- s }, SyncFailed: func(err error) { t.Errorf("sync failed: %v", err) }}); err != nil {
		t.Fatal(err)
	}
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(iface)); err != nil {
		t.Fatal(err)
	}
	pipe := dbustest.NewPipe(t)
	impostor := bus.conn()
	if err := impostor.Emit(ServicePath, changed.Name(), toWire(Status{State: StateUnlocked}), pipe.Write); err != nil {
		t.Fatal(err)
	}
	if err := impostor.BusObject().Call("org.freedesktop.DBus.GetId", 0).Err; err != nil {
		t.Fatal(err)
	}
	if err := d.Changed(); err != nil {
		t.Fatal(err)
	}
	if s := awaitStatus(t, statuses, "the daemon's Changed"); s.State != StateLocked {
		t.Errorf("changed = %+v, want the daemon's, not the impostor's", s)
	}
	pipe.RequireEveryCopyClosed(t)
}
