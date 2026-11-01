package screenlock

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

const fakeSession = dbus.ObjectPath("/org/freedesktop/login1/session/_31")

type fakeManager struct{ err *dbus.Error }

func (m fakeManager) GetSession(name string) (dbus.ObjectPath, *dbus.Error) {
	if m.err != nil {
		return "", m.err
	}
	if name != autoSession {
		return "", dbus.NewError("org.freedesktop.login1.NoSuchSession", []any{name})
	}
	return fakeSession, nil
}

func logind(t *testing.T, conn *dbus.Conn, m fakeManager) {
	t.Helper()
	if err := conn.Export(m, managerPath, managerIf); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName(service, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("own %s on the private bus: %v, %v", service, reply, err)
	}
}

func TestWatchFollowsTheSessionLocking(t *testing.T) {
	bus := dbustest.Start(t)
	owner := bus.Conn(t)
	logind(t, owner, fakeManager{})
	locked := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	watcher := bus.Conn(t)
	go func() { done <- Watch(ctx, watcher, func() { locked <- struct{}{} }) }()

	hint := func(path dbus.ObjectPath, iface string, value any) {
		t.Helper()
		changed := map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(value)}
		if err := owner.Emit(path, propsIf+".PropertiesChanged", iface, changed, []string{}); err != nil {
			t.Fatal(err)
		}
	}
	lockSignal := func() {
		t.Helper()
		if err := owner.Emit(fakeSession, sessionIf+".Lock"); err != nil {
			t.Fatal(err)
		}
	}
	reported := func(what string) {
		t.Helper()
		select {
		case <-locked:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s was not reported", what)
		}
	}

	subscribed := time.After(5 * time.Second)
	for len(locked) == 0 {
		select {
		case <-time.After(20 * time.Millisecond):
			lockSignal()
		case <-subscribed:
			t.Fatal("Lock was not reported")
		}
	}
	time.Sleep(100 * time.Millisecond)
	for len(locked) > 0 {
		<-locked
	}

	hint(fakeSession, sessionIf, true)
	reported("LockedHint turning true")

	hint(fakeSession, sessionIf, false)
	hint(fakeSession, "org.example.Other", true)
	hint("/org/freedesktop/login1/session/_99", sessionIf, true)
	if err := owner.Emit("/org/freedesktop/login1/session/_99", sessionIf+".Lock"); err != nil {
		t.Fatal(err)
	}
	if err := owner.Emit(fakeSession, sessionIf+".Unlock"); err != nil {
		t.Fatal(err)
	}
	lockSignal()
	reported("the Lock after the other events")
	if len(locked) != 0 {
		t.Errorf("%d events other than a lock of this session were reported", len(locked))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Watch after ctx ended = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not end with its context")
	}
}

func TestWatchWithoutASessionSaysSo(t *testing.T) {
	bus := dbustest.Start(t)
	logind(t, bus.Conn(t), fakeManager{err: dbus.NewError("org.freedesktop.login1.NoSuchSession", []any{"no session"})})
	err := Watch(t.Context(), bus.Conn(t), func() {})
	if err == nil || !strings.Contains(err.Error(), "GetSession") {
		t.Errorf("Watch = %v, want the GetSession failure", err)
	}
}

func TestWatchWithoutLogindSaysSo(t *testing.T) {
	bus := dbustest.Start(t)
	err := Watch(t.Context(), bus.Conn(t), func() {})
	if _, ok := errors.AsType[dbus.Error](err); !ok {
		t.Errorf("Watch = %v, want the bus error", err)
	}
}
