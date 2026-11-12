package client_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"

	"github.com/stubbedev/lys-secrets/client"
	"github.com/stubbedev/lys-secrets/internal/secretbus"
	"github.com/stubbedev/lys-secrets/secretstest"
)

func browseRig(t *testing.T) (*client.Client, *secretstest.Server) {
	t.Helper()
	bus := dbustest.Start(t)
	srv := secretstest.Start(t, bus.Conn(t), "login-pw")
	ctx := context.Background()
	c, err := client.OpenEncrypted(ctx, bus.Conn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if err := c.StoreLogin(ctx, "GitHub token", map[string]string{"xdg:schema": "org.example.Token", "service": "github"}, []byte("ghp_secret")); err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestALockedCollectionListsItsItemsAndARevealPromptsOnce(t *testing.T) {
	c, srv := browseRig(t)
	ctx := context.Background()
	srv.Lock()
	colls, err := c.Collections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(colls, func(x client.Collection) bool { return x.Path == client.LoginCollection })
	if i < 0 || !colls[i].Locked {
		t.Fatalf("collections %+v, want a locked login", colls)
	}
	items, err := c.Search(ctx, client.LoginCollection)
	if err != nil || len(items) != 1 {
		t.Fatalf("%v %v", items, err)
	}
	described, err := c.Describe(ctx, items)
	if err != nil || !described[0].Locked {
		t.Fatalf("%+v %v", described, err)
	}
	if srv.Asked() != 0 {
		t.Fatal("listing a locked collection prompted")
	}
	srv.Answer("login-pw")
	secret, err := c.Secret(ctx, items[0])
	if err != nil || string(secret) != "ghp_secret" {
		t.Fatalf("%q %v", secret, err)
	}
	if srv.Asked() != 1 {
		t.Fatalf("the reveal prompted %d times, want once", srv.Asked())
	}
}

func TestDeletingAnItemIsAnnouncedAndChangeLockRekeys(t *testing.T) {
	c, srv := browseRig(t)
	ctx := context.Background()
	changed := make(chan struct{}, 4)
	w, err := c.WatchItems(t.Context(), client.LoginCollection, func() { changed <- struct{}{} }, func(err error) { t.Errorf("the watch failed: %v", err) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Stop(); err != nil {
			t.Errorf("stop watching the items: %v", err)
		}
	}()
	items, _ := c.Search(ctx, client.LoginCollection)
	if err := c.DeleteItem(ctx, items[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(10 * time.Second):
		t.Fatal("no ItemDeleted")
	}
	if left, _ := c.Search(ctx, client.LoginCollection); len(left) != 0 {
		t.Fatalf("%v left", left)
	}
	file := filepath.Join(srv.Dir(), "login.keyring")
	before, err := os.ReadFile(file)
	if err != nil {
		entries, _ := os.ReadDir(srv.Dir())
		t.Fatalf("%v; the directory holds %v", err, entries)
	}
	asked := srv.Asked()
	srv.Answer("new-pw")
	if err := c.ChangeLock(ctx, client.LoginCollection); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if srv.Asked() != asked+1 || bytes.Equal(before[:64], after[:64]) {
		t.Fatalf("asked %d more times, header changed %v", srv.Asked()-asked, !bytes.Equal(before[:64], after[:64]))
	}
}

// Only the provider announces a change of items: an ItemCreated from
// anyone else is dropped, with the descriptor it carries closed.
func TestWatchItemsClosesTheDescriptorsOfAnImpostorsAnnouncement(t *testing.T) {
	bus := dbustest.Start(t)
	secretstest.Start(t, bus.Conn(t), "login-pw")
	ctx := context.Background()
	c, err := client.OpenEncrypted(ctx, bus.Conn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	changed := make(chan struct{}, 4)
	w, err := c.WatchItems(t.Context(), client.LoginCollection, func() { changed <- struct{}{} }, func(err error) { t.Errorf("the watch failed: %v", err) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Stop() })
	pipe := dbustest.NewPipe(t)
	impostor := bus.Conn(t)
	if err := impostor.Emit(client.LoginCollection, secretbus.ItemCreated.Name(), client.LoginCollection+"/9", pipe.Write); err != nil {
		t.Fatal(err)
	}
	if err := impostor.BusObject().Call("org.freedesktop.DBus.GetId", 0).Err; err != nil {
		t.Fatal(err)
	}
	if err := c.StoreLogin(ctx, "Mail", map[string]string{"service": "mail"}, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(10 * time.Second):
		t.Fatal("the provider's ItemCreated behind the impostor's was not announced")
	}
	pipe.RequireEveryCopyClosed(t)
}

func TestAnUnlockedItemIsDescribed(t *testing.T) {
	c, _ := browseRig(t)
	ctx := context.Background()
	items, _ := c.Search(ctx, client.LoginCollection)
	described, err := c.Describe(ctx, items)
	if err != nil || described[0].Label != "GitHub token" || described[0].Attributes["service"] != "github" || described[0].Locked || described[0].Created == 0 {
		t.Fatalf("%+v %v", described, err)
	}
	if err := c.SetLabel(ctx, items[0], "GitHub"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSecret(ctx, items[0], []byte("ghp_new"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	got, err := c.Secret(ctx, items[0])
	if again, _ := c.Describe(ctx, items); err != nil || string(got) != "ghp_new" || again[0].Label != "GitHub" {
		t.Fatalf("%q %v %+v", got, err, again)
	}
}
