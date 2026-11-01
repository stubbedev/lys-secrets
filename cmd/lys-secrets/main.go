// Command lys-secrets serves the freedesktop Secret Service
// (org.freedesktop.secrets) for a lys desktop: libsecret, Chromium and
// Electron apps, git's credential helper and the portal's Secret backend
// keep their secrets in collections encrypted at rest under
// $XDG_DATA_HOME/lys-secrets. It also holds the user's Bitwarden vault
// (dev.stubbe.lys.Vault1), its session under
// $XDG_STATE_HOME/lys-secrets/bitwarden. It is a small process of its
// own, apart from the shell, so the code holding unlocked keys is only
// this.
//
//	lys-secrets [--unlock-fd N] [--collection-lock-after D] [--collection-lock-on-screen-lock]
//	            [--vault-lock-after D] [--vault-sync-interval D] [--vault-collection-folder NAME]
//
// The login collection unlocks with the password the user logs in or
// unlocks the session with: the login screen writes it to an inherited
// descriptor (--unlock-fd), the lock screen sends it over the control
// socket at $XDG_RUNTIME_DIR/lys-secrets/control. When another provider
// already owns org.freedesktop.secrets, lys-secrets logs who and serves
// the vault alone; when another lys-secrets serves the vault, it exits.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
	"github.com/stubbedev/lys-lib/xdg"
	"golang.org/x/sys/unix"

	"github.com/stubbedev/lys-secrets/control"
	"github.com/stubbedev/lys-secrets/internal/bitwarden"
	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/prompt"
	"github.com/stubbedev/lys-secrets/internal/screenlock"
	"github.com/stubbedev/lys-secrets/internal/service"
	"github.com/stubbedev/lys-secrets/vault"
)

// vaultDevice is the name the Bitwarden account's device list shows.
const vaultDevice = "lys-secrets"

// options are the command line's settings.
type options struct {
	unlockFD            int
	vault               bitwarden.Policy
	vaultFolder         string
	collectionLockAfter time.Duration
	lockOnScreenLock    bool
}

func main() {
	var o options
	flag.IntVar(&o.unlockFD, "unlock-fd", -1, "read the login password from this inherited descriptor and unlock the login collection with it")
	flag.DurationVar(&o.collectionLockAfter, "collection-lock-after", 0, "lock a collection after no secret was read from it and nothing in it changed for this long; 0 keeps it open until locked")
	flag.BoolVar(&o.lockOnScreenLock, "collection-lock-on-screen-lock", false, "lock every collection when logind says the session locked")
	flag.DurationVar(&o.vault.LockAfter, "vault-lock-after", 15*time.Minute, "lock the Bitwarden vault after it went unused this long; 0 keeps it open until locked")
	flag.DurationVar(&o.vault.SyncInterval, "vault-sync-interval", 30*time.Minute, "sync the open Bitwarden vault this often; 0 syncs only on unlock and when asked")
	flag.StringVar(&o.vaultFolder, "vault-collection-folder", "", "show the logins of this Bitwarden folder as the Secret Service's \"bitwarden\" collection; empty shows none")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "lys-secrets: unexpected argument %q\n", flag.Arg(0))
		os.Exit(2)
	}
	if o.vault.LockAfter < 0 || o.vault.SyncInterval < 0 || o.collectionLockAfter < 0 {
		fmt.Fprintf(os.Stderr, "lys-secrets: --collection-lock-after %v, --vault-lock-after %v and --vault-sync-interval %v must not be negative\n", o.collectionLockAfter, o.vault.LockAfter, o.vault.SyncInterval)
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "lys-secrets:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	// Neither a core dump nor a same-user ptrace may read unlocked keys.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("make the process undumpable: %w", err)
	}
	var password []byte
	if o.unlockFD >= 0 {
		f := os.NewFile(uintptr(o.unlockFD), "unlock-fd")
		if f == nil {
			return fmt.Errorf("--unlock-fd %d is not a descriptor", o.unlockFD)
		}
		var err error
		password, err = control.ReadPassword(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		defer clear(password)
	}
	data, ok := xdg.OS.DataHome()
	if !ok {
		return errors.New("neither XDG_DATA_HOME nor HOME is set")
	}
	state, ok := xdg.OS.StateDir("lys-secrets")
	if !ok {
		return errors.New("neither XDG_STATE_HOME nor HOME is set")
	}
	sock, err := control.SocketPath(xdg.OS)
	if err != nil {
		return err
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("connect to the session bus: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var secrets atomic.Pointer[service.Service]
	bw, release, err := serveVault(ctx, conn, filepath.Join(state, "bitwarden"), o.vault, func() {
		if svc := secrets.Load(); svc != nil {
			svc.VaultChanged()
		}
	})
	if errors.Is(err, dbusx.ErrNameTaken) {
		var owner string
		_ = conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, vault.ServiceName).Store(&owner)
		log.Printf("lys-secrets: %s is already served by %s; staying off", vault.ServiceName, owner)
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	defer bw.Lock()

	svc, err := service.Start(conn, service.Config{
		Dir: filepath.Join(data, "lys-secrets"), KDF: keyring.DefaultKDF, Prompter: prompt.New(conn),
		Vault:     vaultCollection{bw: bw, folder: o.vaultFolder},
		LockAfter: o.collectionLockAfter,
	})
	if errors.Is(err, dbusx.ErrNameTaken) {
		var owner string
		_ = conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, service.BusName).Store(&owner)
		log.Printf("lys-secrets: %s is already served by %s; serving %s alone", service.BusName, owner, vault.ServiceName)
		<-ctx.Done()
		return nil
	}
	if err != nil {
		return err
	}
	defer svc.Close()
	secrets.Store(svc)

	if password != nil {
		if err := svc.UnlockLogin(password); err != nil {
			log.Printf("lys-secrets: the login password does not unlock the login collection: %v", err)
		}
		clear(password)
	}

	if o.lockOnScreenLock {
		go lockOnScreenLock(ctx, svc)
	}

	ln, err := control.Listen(sock)
	if err != nil {
		return err
	}
	log.Printf("lys-secrets: serving %s and %s, unlock socket %s", service.BusName, vault.ServiceName, sock)
	control.Serve(ctx, ln, svc)
	return nil
}

// lockOnScreenLock locks svc's collections each time the session locks,
// until ctx ends. Not being able to watch does not stop the service, whose
// secrets every app needs, and the log says what it means.
func lockOnScreenLock(ctx context.Context, svc *service.Service) {
	conn, err := dbus.ConnectSystemBus()
	if err == nil {
		defer func() { _ = conn.Close() }()
		err = screenlock.Watch(ctx, conn, func() {
			svc.LockCollections()
			log.Print("lys-secrets: the session locked, so every collection did")
		})
	}
	if err != nil {
		log.Printf("lys-secrets: collections will NOT lock with the screen, despite --collection-lock-on-screen-lock: %v", err)
	}
}

// serveVault opens the Bitwarden vault whose session lives in dir and
// serves it under its name on conn, keeping it under policy until ctx
// ends; changed runs after each change of it. release drops the name.
func serveVault(ctx context.Context, conn *dbus.Conn, dir string, policy bitwarden.Policy, changed func()) (*bitwarden.Service, func(), error) {
	var d *vault.Daemon
	bw, err := bitwarden.Open(dir, vaultDevice, func() {
		if err := d.Changed(); err != nil {
			log.Printf("lys-secrets: %v", err)
		}
		changed()
	})
	if err != nil {
		return nil, nil, err
	}
	d = vault.NewDaemon(ctx, bw)
	release, err := d.Export(conn)
	if err != nil {
		return nil, nil, err
	}
	go bw.Keep(ctx, policy, func(err error) {
		if err := d.SyncFailed(err); err != nil {
			log.Printf("lys-secrets: %v", err)
		}
	})
	return bw, release, nil
}

// vaultCollection is the vault as the Secret Service sees it: the
// shareable logins of one folder, shown when a folder is set.
type vaultCollection struct {
	bw     *bitwarden.Service
	folder string
}

func (c vaultCollection) Shown() bool { return c.folder != "" }

func (c vaultCollection) Logins() ([]service.VaultLogin, bool) {
	logins, open := c.bw.FolderLogins(c.folder)
	out := make([]service.VaultLogin, len(logins))
	for i, l := range logins {
		out[i] = service.VaultLogin(l)
	}
	return out, open
}

func (c vaultCollection) Password(id string) ([]byte, error) {
	return c.bw.FolderPassword(c.folder, id)
}

func (c vaultCollection) Unlock(ctx context.Context, password string) error {
	return c.bw.Unlock(ctx, password)
}

func (c vaultCollection) Lock() { c.bw.Lock() }
