package service

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/secretbus"
	"github.com/stubbedev/lys-secrets/vault"
)

// fakeVault is the Bitwarden vault behind the vault collection: its
// logins and passwords, opened by "master", announcing its changes as
// lys-secrets' main does.
type fakeVault struct {
	hidden    bool
	mu        sync.Mutex
	open      bool
	logins    []VaultLogin
	passwords map[string]string
	changed   func()
	reads     []string
}

func (v *fakeVault) Shown() bool { return !v.hidden }

func (v *fakeVault) Logins() ([]VaultLogin, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.open {
		return nil, false
	}
	return slices.Clone(v.logins), true
}

func (v *fakeVault) Password(id string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reads = append(v.reads, id)
	if !v.open {
		return nil, vault.ErrLocked
	}
	return []byte(v.passwords[id]), nil
}

func (v *fakeVault) Unlock(_ context.Context, password string) error {
	if password != "master" {
		return fmt.Errorf("bitwarden: %w", vault.ErrWrongPassword)
	}
	v.set(func() { v.open = true })
	return nil
}

func (v *fakeVault) Lock() { v.set(func() { v.open = false }) }

func (v *fakeVault) set(fn func()) {
	v.mu.Lock()
	fn()
	v.mu.Unlock()
	v.changed()
}

func vaultFixture(t *testing.T) (*fixture, *fakeVault) {
	t.Helper()
	v := &fakeVault{
		logins: []VaultLogin{
			{ID: "0b6c9e1a-0000-4000-8000-000000000001", Name: "Mail", Username: "ada", URI: "https://mail.example.com", Folder: "Desktop"},
			{ID: "0b6c9e1a-0000-4000-8000-000000000002", Name: "Chat", Folder: "Desktop"},
		},
		passwords: map[string]string{"0b6c9e1a-0000-4000-8000-000000000001": "mail-pw", "0b6c9e1a-0000-4000-8000-000000000002": "chat-pw"},
	}
	f := &fixture{bus: dbustest.Session(t), dir: t.TempDir(), prompter: &fakePrompter{}}
	svc, err := Start(f.bus.Conn(t), Config{Dir: f.dir, KDF: testKDF, Stretch: keyring.Argon2id, Prompter: f.prompter, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	f.svc = svc
	v.changed = svc.VaultChanged
	return f, v
}

func (f *fixture) prop(t *testing.T, path dbus.ObjectPath, name string) any {
	t.Helper()
	v, err := f.bus.Conn(t).Object(BusName, path).GetProperty(name)
	if err != nil {
		t.Fatalf("%s %s: %v", path, name, err)
	}
	return v.Value()
}

// A locked vault is a locked collection without items; secret-tool's
// lookup unlocks it through the master password prompt, asking again
// after a wrong one, and then finds the login by its attributes.
func TestVaultCollectionUnlocksThroughThePrompt(t *testing.T) {
	tool := requireTool(t, "secret-tool")
	f, v := vaultFixture(t)
	coll := collectionPath(VaultID)
	if paths, _ := f.prop(t, rootPath, secretbus.ServiceInterface+".Collections").([]dbus.ObjectPath); !slices.Contains(paths, coll) {
		t.Fatalf("collections %v lack the vault", paths)
	}
	if locked, _ := f.prop(t, coll, secretbus.CollectionInterface+".Locked").(bool); !locked {
		t.Error("a locked vault's collection is unlocked")
	}
	if items, _ := f.prop(t, coll, secretbus.CollectionInterface+".Items").([]dbus.ObjectPath); len(items) != 0 {
		t.Errorf("a locked vault lists %v", items)
	}
	if got, _ := run(t, "", tool, "lookup", "username", "ada"); got != "" {
		t.Fatalf("a locked vault answered %q", got)
	}

	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := f.bus.Conn(t).Object(BusName, rootPath).Call(secretbus.ServiceInterface+".Unlock", 0, []dbus.ObjectPath{coll}).Store(&unlocked, &prompt); err != nil || prompt == noPrompt {
		t.Fatalf("Unlock = %v, %v, %v", unlocked, prompt, err)
	}
	f.prompter.script("wrong", "master")
	completed := watchCompleted(t, f, prompt)
	if err := f.bus.Conn(t).Object(BusName, prompt).Call(secretbus.PromptInterface+".Prompt", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	if dismissed, result := completed(); dismissed || !slices.Contains(result, coll) {
		t.Fatalf("Completed = %v, %v", dismissed, result)
	}
	if got := strings.Join(f.prompter.log(), ","); got != "master,master retry" {
		t.Errorf("prompts = %s", got)
	}
	got, err := run(t, "", tool, "lookup", "username", "ada", "xdg:schema", vaultSchema)
	if err != nil || got != "mail-pw" {
		t.Fatalf("lookup = %q, %v", got, err)
	}
	items, _ := f.prop(t, coll, secretbus.CollectionInterface+".Items").([]dbus.ObjectPath)
	if len(items) != 2 {
		t.Fatalf("items %v", items)
	}
	attrs, _ := f.prop(t, vaultItemPath(v.logins[0].ID), secretbus.ItemInterface+".Attributes").(map[string]string)
	want := map[string]string{"xdg:schema": vaultSchema, "bitwarden:id": v.logins[0].ID, "name": "Mail", "username": "ada", "uri": "https://mail.example.com", "folder": "Desktop"}
	if fmt.Sprint(attrs) != fmt.Sprint(want) {
		t.Errorf("attributes = %v, want %v", attrs, want)
	}
	if label, _ := f.prop(t, vaultItemPath(v.logins[1].ID), secretbus.ItemInterface+".Label").(string); label != "Chat" {
		t.Errorf("label = %q", label)
	}
}

// Dismissing the master password prompt leaves the vault locked.
func TestVaultCollectionDismissedStaysLocked(t *testing.T) {
	f, v := vaultFixture(t)
	f.prompter.script("")
	ctx := context.Background()
	if f.svc.promptVaultUnlock(ctx) {
		t.Fatal("a dismissed prompt unlocked the vault")
	}
	if _, open := v.Logins(); open {
		t.Error("the vault opened")
	}
}

// The collection is read-only: no item is created, deleted or
// rewritten, and the vault's password stays as it was. Locking the
// collection locks the vault and takes its items away.
func TestVaultCollectionIsReadOnlyAndLocks(t *testing.T) {
	f, v := vaultFixture(t)
	v.set(func() { v.open = true })
	conn := f.bus.Conn(t)
	sess := openSession(t, conn)
	item := vaultItemPath(v.logins[0].ID)
	secret := plainSecret(sess, "new")
	props := itemProps("x")
	for name, err := range map[string]error{
		"CreateItem": conn.Object(BusName, collectionPath(VaultID)).Call(secretbus.CollectionInterface+".CreateItem", 0, props, secret, false).Err,
		"Delete":     conn.Object(BusName, collectionPath(VaultID)).Call(secretbus.CollectionInterface+".Delete", 0).Err,
		"item":       conn.Object(BusName, item).Call(secretbus.ItemInterface+".Delete", 0).Err,
		"SetSecret":  conn.Object(BusName, item).Call(secretbus.ItemInterface+".SetSecret", 0, secret).Err,
		"Label":      conn.Object(BusName, item).SetProperty(propItemLabel, dbus.MakeVariant("y")),
	} {
		if err == nil {
			t.Errorf("%s on the vault collection succeeded", name)
		}
	}
	var got Secret
	if err := conn.Object(BusName, item).Call(secretbus.ItemInterface+".GetSecret", 0, sess).Store(&got); err != nil || string(got.Value) != "mail-pw" {
		t.Fatalf("GetSecret = %q, %v", got.Value, err)
	}
	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := conn.Object(BusName, rootPath).Call(secretbus.ServiceInterface+".Lock", 0, []dbus.ObjectPath{collectionPath(VaultID)}).Store(&locked, &prompt); err != nil {
		t.Fatal(err)
	}
	if _, open := v.Logins(); open {
		t.Error("locking the collection left the vault open")
	}
	if items, _ := f.prop(t, collectionPath(VaultID), secretbus.CollectionInterface+".Items").([]dbus.ObjectPath); len(items) != 0 {
		t.Errorf("a locked vault still lists %v", items)
	}
	got = Secret{}
	if err := conn.Object(BusName, item).Call(secretbus.ItemInterface+".GetSecret", 0, sess).Store(&got); err == nil || len(got.Value) != 0 {
		t.Errorf("GetSecret after locking = %q, %v", got.Value, err)
	}
}

// A keyring collection where the vault collection goes is refused at
// start, never shadowed.
func TestVaultCollectionRefusesAClash(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	if err := f.svc.disk.save(VaultID, mustMarshal(t, c)); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Unlock()
	f.svc.Close()
	_, err := Start(f.bus.Conn(t), Config{Dir: f.dir, KDF: testKDF, Stretch: keyring.Argon2id, Prompter: f.prompter, Vault: &fakeVault{changed: func() {}}})
	if err == nil || !strings.Contains(err.Error(), VaultID) {
		t.Errorf("Start = %v, want the clash", err)
	}
}

// watchCompleted watches prompt's Completed and returns the wait for
// it: whether it was dismissed, and the paths it carries.
func watchCompleted(t *testing.T, f *fixture, prompt dbus.ObjectPath) func() (bool, []dbus.ObjectPath) {
	t.Helper()
	completed := make(chan secretbus.Completion, 1)
	w, err := dbusx.WatchSignals(t.Context(), f.bus.Conn(t), dbusx.FromOwner(BusName), func(err error) { t.Errorf("watch %s: %v", prompt, err) },
		dbusx.On(secretbus.PromptCompleted, prompt, func(c secretbus.Completion, _ dbus.Sequence) error {
			completed <- c
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Stop() })
	return func() (bool, []dbus.ObjectPath) {
		t.Helper()
		select {
		case c := <-completed:
			paths, _ := c.Result.Value().([]dbus.ObjectPath)
			return c.Dismissed, paths
		case <-time.After(10 * time.Second):
			t.Fatal("the prompt never completed")
		}
		return false, nil
	}
}

func mustMarshal(t *testing.T, c *collection) []byte {
	t.Helper()
	data, err := c.kr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVaultSearchMatchesTheExportedAttributes(t *testing.T) {
	mail := VaultLogin{ID: "m", Name: "Mail", Username: "ada", URI: "https://mail.example.com", Folder: "Desktop"}
	chat := VaultLogin{ID: "c", Name: "Chat", Folder: "Desktop"}
	s := &Service{vault: &vaultColl{open: true, logins: map[dbus.ObjectPath]VaultLogin{
		vaultItemPath(mail.ID): mail, vaultItemPath(chat.ID): chat,
	}}}
	both := []dbus.ObjectPath{vaultItemPath(chat.ID), vaultItemPath(mail.ID)}
	slices.Sort(both)
	cases := []struct {
		query map[string]string
		want  []dbus.ObjectPath
	}{
		{mail.attributes(), []dbus.ObjectPath{vaultItemPath(mail.ID)}},
		{chat.attributes(), []dbus.ObjectPath{vaultItemPath(chat.ID)}},
		{map[string]string{"folder": "Desktop", "xdg:schema": vaultSchema}, both},
		{map[string]string{"username": ""}, []dbus.ObjectPath{vaultItemPath(chat.ID)}},
		{map[string]string{"server": "mail.example.com"}, []dbus.ObjectPath{}},
		{nil, both},
	}
	for _, tc := range cases {
		if got := s.searchVaultLocked(tc.query); !slices.Equal(got, tc.want) {
			t.Errorf("search %v = %v, want %v", tc.query, got, tc.want)
		}
	}
}

func TestLockServiceLocksAVaultNotShownAsACollection(t *testing.T) {
	v := &fakeVault{hidden: true, open: true, changed: func() {}}
	bus := dbustest.Session(t)
	svc, err := Start(bus.Conn(t), Config{Dir: t.TempDir(), KDF: testKDF, Stretch: keyring.Argon2id, Prompter: &fakePrompter{}, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	if svc.vault != nil {
		t.Fatal("a hidden vault shows as a collection")
	}
	conn := bus.Conn(t)
	var cols dbus.Variant
	if err := conn.Object(BusName, rootPath).Call("org.freedesktop.DBus.Properties.Get", 0, secretbus.ServiceInterface, "Collections").Store(&cols); err != nil {
		t.Fatal(err)
	}
	if got := cols.Value().([]dbus.ObjectPath); slices.Contains(got, collectionPath(VaultID)) {
		t.Errorf("Collections = %v shows the hidden vault", got)
	}
	if err := conn.Object(BusName, rootPath).Call(secretbus.ServiceInterface+".LockService", 0).Err; err != nil {
		t.Fatal(err)
	}
	if _, open := v.Logins(); open {
		t.Error("LockService left the hidden vault open")
	}
}
