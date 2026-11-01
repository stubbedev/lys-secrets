package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

const loginPassword = "login-pw"

var defaultAliasPath = dbus.ObjectPath(aliasBase + "default")

var lockStates = []struct {
	name    string
	restart bool
}{{"locked", false}, {"restarted", true}}

var deletePaths = []struct {
	name string
	path dbus.ObjectPath
}{{"collection path", collectionPath(LoginID)}, {"default alias", defaultAliasPath}}

func openSession(t *testing.T, conn *dbus.Conn) dbus.ObjectPath {
	t.Helper()
	var out dbus.Variant
	var sess dbus.ObjectPath
	if err := conn.Object(BusName, rootPath).Call(ifaceService+".OpenSession", 0, algPlain, dbus.MakeVariant("")).Store(&out, &sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func plainSecret(sess dbus.ObjectPath, value string) Secret {
	return Secret{Session: sess, Parameters: []byte{}, Value: []byte(value), ContentType: "text/plain"}
}

func itemProps(label string) map[string]dbus.Variant {
	return map[string]dbus.Variant{propItemLabel: dbus.MakeVariant(label), propItemAttrs: dbus.MakeVariant(map[string]string{"k": "v"})}
}

func requireDBusError(t *testing.T, what string, err error, name string) {
	t.Helper()
	var de dbus.Error
	if !errors.As(err, &de) || de.Name != name {
		t.Errorf("%s = %v, want %s", what, err, name)
	}
}

func (f *fixture) loginFile(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, LoginID+collectionExt))
	if err != nil {
		t.Fatalf("the login collection's file: %v", err)
	}
	return data
}

func readDefaultAlias(t *testing.T, conn *dbus.Conn) dbus.ObjectPath {
	t.Helper()
	var got dbus.ObjectPath
	if err := conn.Object(BusName, rootPath).Call(ifaceService+".ReadAlias", 0, "default").Store(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func (f *fixture) showPrompt(t *testing.T, conn *dbus.Conn, prompt dbus.ObjectPath, answer string) (dismissed bool) {
	t.Helper()
	f.prompter.script(answer)
	completed := watchCompleted(t, f, prompt)
	if err := conn.Object(BusName, prompt).Call(ifacePrompt+".Prompt", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	dismissed, _ = completed()
	return dismissed
}

func (f *fixture) unlockThroughPrompt(t *testing.T, conn *dbus.Conn, path dbus.ObjectPath, answer string) (dismissed bool) {
	t.Helper()
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := conn.Object(BusName, rootPath).Call(ifaceService+".Unlock", 0, []dbus.ObjectPath{path}).Store(&unlocked, &prompt); err != nil || prompt == noPrompt {
		t.Fatalf("Unlock(%s) = %v, %q, %v; want a prompt", path, unlocked, prompt, err)
	}
	return f.showPrompt(t, conn, prompt, answer)
}

func lockedLogin(t *testing.T, restart bool) (f *fixture, conn *dbus.Conn, item dbus.ObjectPath) {
	t.Helper()
	f = newFixture(t)
	if err := f.svc.UnlockLogin([]byte(loginPassword)); err != nil {
		t.Fatal(err)
	}
	conn = f.bus.Conn(t)
	var prompt dbus.ObjectPath
	if err := conn.Object(BusName, defaultAliasPath).Call(ifaceCollection+".CreateItem", 0, itemProps("a"), plainSecret(openSession(t, conn), "kept"), false).Store(&item, &prompt); err != nil {
		t.Fatal(err)
	}
	f.svc.Lock()
	if restart {
		f.svc.Close()
		f.start(t)
	}
	return f, conn, item
}

func TestDeletingALockedCollectionIsRefused(t *testing.T) {
	for _, state := range lockStates {
		for _, target := range deletePaths {
			t.Run(state.name+"/"+target.name, func(t *testing.T) {
				f, conn, item := lockedLogin(t, state.restart)
				before := f.loginFile(t)

				err := conn.Object(BusName, target.path).Call(ifaceCollection+".Delete", 0).Err
				requireDBusError(t, "Delete", err, errIsLocked)

				if !bytes.Equal(f.loginFile(t), before) {
					t.Error("a refused Delete changed the file")
				}
				if paths, _ := f.prop(t, rootPath, ifaceService+".Collections").([]dbus.ObjectPath); !slices.Contains(paths, collectionPath(LoginID)) {
					t.Errorf("Collections = %v, want the login collection kept", paths)
				}
				if got := readDefaultAlias(t, conn); got != collectionPath(LoginID) {
					t.Errorf("ReadAlias(default) = %q, want it kept", got)
				}
				if asked := f.prompter.log(); len(asked) != 0 {
					t.Errorf("a refused Delete prompted: %v", asked)
				}
				if err := f.svc.UnlockLogin([]byte(loginPassword)); err != nil {
					t.Fatal(err)
				}
				var secret Secret
				if err := conn.Object(BusName, item).Call(ifaceItem+".GetSecret", 0, openSession(t, conn)).Store(&secret); err != nil || string(secret.Value) != "kept" {
					t.Errorf("GetSecret after the refusal = %q, %v", secret.Value, err)
				}
			})
		}
	}
}

func TestACollectionDeletesOnlyOnceUnlockedThroughThePrompt(t *testing.T) {
	for _, target := range deletePaths {
		t.Run(target.name, func(t *testing.T) {
			f, conn, _ := lockedLogin(t, false)
			obj := conn.Object(BusName, target.path)

			if !f.unlockThroughPrompt(t, conn, target.path, "") {
				t.Fatal("the unlock prompt completed although dismissed")
			}
			requireDBusError(t, "Delete after a dismissed unlock", obj.Call(ifaceCollection+".Delete", 0).Err, errIsLocked)

			if f.unlockThroughPrompt(t, conn, target.path, loginPassword) {
				t.Fatal("the unlock prompt was dismissed")
			}
			var prompt dbus.ObjectPath
			if err := obj.Call(ifaceCollection+".Delete", 0).Store(&prompt); err != nil || prompt != noPrompt {
				t.Fatalf("Delete of an unlocked collection = %q, %v", prompt, err)
			}
			if _, err := os.Stat(filepath.Join(f.dir, LoginID+collectionExt)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the file after Delete: %v, want it gone", err)
			}
			if got := readDefaultAlias(t, conn); got != noPrompt {
				t.Errorf("ReadAlias(default) = %q, want it gone with the collection", got)
			}
			requireDBusError(t, "Delete again", obj.Call(ifaceCollection+".Delete", 0).Err, errNoSuchObject)
		})
	}
}

func TestALockedCollectionRefusesEveryChange(t *testing.T) {
	for _, state := range lockStates {
		t.Run(state.name, func(t *testing.T) {
			f, conn, item := lockedLogin(t, state.restart)
			before := f.loginFile(t)
			sess := openSession(t, conn)
			itemObj := conn.Object(BusName, item)
			for _, change := range []struct {
				name string
				err  error
			}{
				{"Item.Delete", itemObj.Call(ifaceItem+".Delete", 0).Err},
				{"Item.SetSecret", itemObj.Call(ifaceItem+".SetSecret", 0, plainSecret(sess, "changed")).Err},
				{"Item.Label", itemObj.SetProperty(propItemLabel, dbus.MakeVariant("changed"))},
				{"Item.Attributes", itemObj.SetProperty(propItemAttrs, dbus.MakeVariant(map[string]string{"k": "changed"}))},
				{"Collection.Label", conn.Object(BusName, collectionPath(LoginID)).SetProperty(propCollLabel, dbus.MakeVariant("changed"))},
				{"alias Collection.Label", conn.Object(BusName, defaultAliasPath).SetProperty(propCollLabel, dbus.MakeVariant("changed"))},
			} {
				requireDBusError(t, change.name, change.err, errIsLocked)
			}

			var created, prompt dbus.ObjectPath
			if err := conn.Object(BusName, defaultAliasPath).Call(ifaceCollection+".CreateItem", 0, itemProps("changed"), plainSecret(sess, "changed"), true).Store(&created, &prompt); err != nil || prompt == noPrompt {
				t.Fatalf("CreateItem = %q, %q, %v; want a prompt", created, prompt, err)
			}
			if !f.showPrompt(t, conn, prompt, "") {
				t.Error("CreateItem's dismissed prompt completed")
			}

			if err := conn.Object(BusName, rootPath).Call(ifaceService+".ChangeLock", 0, collectionPath(LoginID)).Store(&prompt); err != nil {
				t.Fatalf("ChangeLock = %v", err)
			}
			if !f.showPrompt(t, conn, prompt, "") {
				t.Error("ChangeLock's dismissed prompt completed")
			}

			if !bytes.Equal(f.loginFile(t), before) {
				t.Error("a refused change altered the file")
			}
			if locked, _ := f.prop(t, collectionPath(LoginID), ifaceCollection+".Locked").(bool); !locked {
				t.Error("a refused change unlocked the collection")
			}
		})
	}
}

func TestDeletingACollectionDestroysItsKey(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.UnlockLogin([]byte(loginPassword)); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	kr := f.svc.colls[LoginID].kr
	f.svc.mu.Unlock()
	conn := f.bus.Conn(t)
	if err := conn.Object(BusName, collectionPath(LoginID)).Call(ifaceCollection+".Delete", 0).Err; err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	defer f.svc.mu.Unlock()
	if !kr.Locked() {
		t.Error("the deleted collection's key is still in memory")
	}
}
