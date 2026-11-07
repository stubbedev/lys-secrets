package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/client"
	"github.com/stubbedev/lys-secrets/internal/keyring"
)

func confirmingFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{bus: dbustest.Session(t), dir: t.TempDir(), prompter: &fakePrompter{}, confirm: true}
	f.start(t)
	return f
}

// otherProgram is a process that is not the test, for a connection to pass as.
func otherProgram(t *testing.T) uint32 {
	t.Helper()
	cmd := exec.Command(requireTool(t, "sleep"), "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return uint32(cmd.Process.Pid)
}

// passAs makes the service see conn as process pid.
func (f *fixture) passAs(conn *dbus.Conn, pid uint32) {
	real := f.svc.peers.credentials
	name := conn.Names()[0]
	f.svc.peers.credentials = func(ctx context.Context, sender string) (map[string]dbus.Variant, error) {
		if sender == name {
			return map[string]dbus.Variant{"ProcessID": dbus.MakeVariant(pid)}, nil
		}
		return real(ctx, sender)
	}
}

func store(t *testing.T, conn *dbus.Conn, label, value string, attrs map[string]string) {
	t.Helper()
	c, err := client.Open(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Store(context.Background(), label, attrs, []byte(value)); err != nil {
		t.Fatal(err)
	}
}

func lookup(t *testing.T, conn *dbus.Conn, attrs map[string]string) (string, error) {
	t.Helper()
	c, err := client.Open(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v, found, err := c.Lookup(ctx, attrs)
	if err == nil && !found {
		err = errors.New("not found")
	}
	return string(v), err
}

func TestAForeignReadAsksAndTheAnswerHolds(t *testing.T) {
	tool := requireTool(t, "secret-tool")
	f := confirmingFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	creator := f.bus.Conn(t)
	attrs := map[string]string{"service": "git", "user": "me"}
	store(t, creator, "Token", "s3cret", attrs)
	if got, err := lookup(t, creator, attrs); err != nil || got != "s3cret" {
		t.Fatalf("the creator's own read = %q, %v", got, err)
	}
	if got := f.prompter.log(); len(got) != 0 {
		t.Fatalf("the creator's read asked %v", got)
	}

	f.prompter.script("")
	if got, err := run(t, "", tool, "lookup", "service", "git"); err == nil || got != "" {
		t.Errorf("a denied lookup = %q, %v", got, err)
	}
	if len(f.prompter.readRequests()) != 1 {
		t.Fatalf("a foreign lookup asked %d times", len(f.prompter.readRequests()))
	}
	exe, _ := os.Executable()
	r := f.prompter.readRequests()[0]
	if !strings.Contains(filepath.Base(string(r.Program)), "secret-tool") || r.Item != "Token" || r.Collection != "Login" || len(r.Owners) != 1 || string(r.Owners[0]) != exe {
		t.Errorf("the dialog showed %+v", r)
	}

	f.prompter.script("always")
	if got, err := run(t, "", tool, "lookup", "service", "git"); err != nil || got != "s3cret" {
		t.Fatalf("an always-allowed lookup = %q, %v", got, err)
	}
	f.svc.Close()
	f.start(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.prompter.script()
	if got, err := run(t, "", tool, "lookup", "service", "git"); err != nil || got != "s3cret" {
		t.Errorf("after a restart the always-allowed lookup = %q, %v", got, err)
	}
	if got := f.prompter.log(); len(got) != 0 {
		t.Errorf("after a restart the always-allowed lookup asked %v", got)
	}
}

func TestADeniedReadDismissesThePromptAndReturnsNoSecret(t *testing.T) {
	f := confirmingFixture(t)
	foreign := f.bus.Conn(t)
	f.passAs(foreign, otherProgram(t))
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{"service": "mail"}
	store(t, f.bus.Conn(t), "Mail", "m41l", attrs)

	root := foreign.Object(BusName, rootPath)
	var unlocked, locked []dbus.ObjectPath
	if err := root.Call(ifaceService+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil || len(unlocked) != 0 || len(locked) != 1 {
		t.Fatalf("a foreign search = %v, %v, %v; want the item locked to it", unlocked, locked, err)
	}
	var session dbus.ObjectPath
	var out dbus.Variant
	if err := root.Call(ifaceService+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &session); err != nil {
		t.Fatal(err)
	}
	var secrets map[dbus.ObjectPath]Secret
	if err := root.Call(ifaceService+".GetSecrets", 0, locked, session).Store(&secrets); err != nil || len(secrets) != 0 {
		t.Errorf("a foreign GetSecrets before the dialog = %v, %v", secrets, err)
	}
	var secret Secret
	err := foreign.Object(BusName, locked[0]).Call(ifaceItem+".GetSecret", 0, session).Store(&secret)
	var de dbus.Error
	if !errors.As(err, &de) || de.Name != errIsLocked {
		t.Errorf("a foreign GetSecret before the dialog = %v, want IsLocked", err)
	}
	var done []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := root.Call(ifaceService+".Unlock", 0, locked).Store(&done, &prompt); err != nil || len(done) != 0 || prompt == noPrompt {
		t.Fatalf("a foreign Unlock = %v, %q, %v; want a prompt", done, prompt, err)
	}
	if dismissed := f.showPrompt(t, foreign, prompt, ""); !dismissed {
		t.Error("a denied read completed the prompt undismissed")
	}
	if err := root.Call(ifaceService+".GetSecrets", 0, locked, session).Store(&secrets); err != nil || len(secrets) != 0 {
		t.Errorf("a foreign GetSecrets after Deny = %v, %v", secrets, err)
	}

	if err := root.Call(ifaceService+".Unlock", 0, locked).Store(&done, &prompt); err != nil || prompt == noPrompt {
		t.Fatalf("a foreign Unlock = %v, %q, %v; want a prompt", done, prompt, err)
	}
	if dismissed := f.showPrompt(t, foreign, prompt, "allow"); dismissed {
		t.Fatal("an allowed read dismissed the prompt")
	}
	if err := root.Call(ifaceService+".GetSecrets", 0, locked, session).Store(&secrets); err != nil || string(secrets[locked[0]].Value) != "m41l" {
		t.Errorf("a foreign GetSecrets after Allow = %v, %v", secrets, err)
	}
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := root.Call(ifaceService+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil || len(locked) != 1 {
		t.Errorf("after a lock the once-allowed item searches as %v, %v, %v; want it locked again", unlocked, locked, err)
	}
}

func TestAnItemWithNoOwnerBelongsToItsFirstReader(t *testing.T) {
	f := confirmingFixture(t)
	first, second := f.bus.Conn(t), f.bus.Conn(t)
	f.passAs(second, otherProgram(t))
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	f.svc.mu.Unlock()
	attrs := map[string]string{"old": "item"}
	var id uint32
	err := f.svc.change(c, func(kr *keyring.Collection) error {
		var err error
		id, _, err = kr.CreateItem("Old", attrs, []byte("0ld"), "text/plain", "", false, time.Now())
		return err
	}, nothingToAnnounce)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := lookup(t, first, attrs); err != nil || got != "0ld" {
		t.Fatalf("the first reader's lookup = %q, %v", got, err)
	}
	exe, _ := os.Executable()
	f.svc.mu.Lock()
	it, _ := c.kr.Item(id)
	f.svc.mu.Unlock()
	if len(it.Owners) != 1 || string(it.Owners[0]) != exe {
		t.Errorf("after the first read the owners are %v, want the test", it.Owners)
	}
	if got := f.prompter.log(); len(got) != 0 {
		t.Errorf("the first reader was asked %v", got)
	}
	f.prompter.script("")
	if got, err := lookup(t, second, attrs); err == nil {
		t.Errorf("the second program read %q unasked", got)
	}
	if len(f.prompter.readRequests()) != 1 {
		t.Errorf("the second program was asked %d times", len(f.prompter.readRequests()))
	}
}

func TestAnUnidentifiedProgramIsOnlyEverAllowedOnce(t *testing.T) {
	f := confirmingFixture(t)
	unknown := f.bus.Conn(t)
	real := f.svc.peers.credentials
	name := unknown.Names()[0]
	f.svc.peers.credentials = func(ctx context.Context, sender string) (map[string]dbus.Variant, error) {
		if sender == name {
			return map[string]dbus.Variant{"ProcessID": dbus.MakeVariant(uint32(1 << 30))}, nil
		}
		return real(ctx, sender)
	}
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{"service": "x"}
	store(t, f.bus.Conn(t), "X", "x", attrs)
	f.prompter.script("always")
	if got, err := lookup(t, unknown, attrs); err != nil || got != "x" {
		t.Fatalf("an allowed unidentified read = %q, %v", got, err)
	}
	if r := f.prompter.readRequests()[0]; r.Program != "" || r.PID != 1<<30 {
		t.Errorf("the dialog showed %+v, want no program and the pid", r)
	}
	f.svc.mu.Lock()
	ids := f.svc.colls[LoginID].kr.Search(attrs)
	it, _ := f.svc.colls[LoginID].kr.Item(ids[0])
	f.svc.mu.Unlock()
	if len(it.Owners) != 1 {
		t.Errorf("an unidentified program became an owner: %v", it.Owners)
	}
}

func TestWithoutConfirmationAReadAsksTheBusNothing(t *testing.T) {
	f := newFixture(t)
	var calls atomic.Int32
	real := f.svc.peers.credentials
	f.svc.peers.credentials = func(ctx context.Context, sender string) (map[string]dbus.Variant, error) {
		calls.Add(1)
		return real(ctx, sender)
	}
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{"service": "y"}
	store(t, f.bus.Conn(t), "Y", "y", attrs)
	calls.Store(0)
	reader := f.bus.Conn(t)
	if got, err := lookup(t, reader, attrs); err != nil || got != "y" {
		t.Fatalf("lookup = %q, %v", got, err)
	}
	root := reader.Object(BusName, rootPath)
	var unlocked, locked []dbus.ObjectPath
	if err := root.Call(ifaceService+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		t.Fatal(err)
	}
	var session dbus.ObjectPath
	var out dbus.Variant
	if err := root.Call(ifaceService+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &session); err != nil {
		t.Fatal(err)
	}
	var secret Secret
	if err := reader.Object(BusName, unlocked[0]).Call(ifaceItem+".GetSecret", 0, session).Store(&secret); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("reads without confirmation asked the bus who the reader is %d times", got)
	}
}

func TestAFlatpakAppIsItsAppID(t *testing.T) {
	info := "[Instance]\nname=org.not.This\n\n[Application]\nname=org.gnome.Fractal\nruntime=runtime/org.gnome.Platform\n"
	if app, err := flatpakApp([]byte(info)); err != nil || app != "org.gnome.Fractal" {
		t.Errorf("flatpakApp = %q, %v", app, err)
	}
	if app, err := flatpakApp([]byte("[Instance]\nname=org.not.This\n")); err == nil {
		t.Errorf("an info naming no application = %q", app)
	}
	self, err := programOf(uint32(os.Getpid()))
	exe, _ := os.Executable()
	if err != nil || string(self) != exe {
		t.Errorf("programOf(the test) = %q, %v, want %q", self, err, exe)
	}
}
