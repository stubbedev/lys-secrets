package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	"github.com/stubbedev/lys-lib/sockdir"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
	"github.com/stubbedev/lys-lib/xdg"

	"github.com/stubbedev/lys-secrets/control"
	"github.com/stubbedev/lys-secrets/internal/service"
	"github.com/stubbedev/lys-secrets/vault"
)

// TestMain lets the test binary be lys-secrets: the tests re-exec it
// with LYS_SECRETS_TEST_MAIN set.
func TestMain(m *testing.M) {
	if os.Getenv("LYS_SECRETS_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type daemon struct {
	cmd  *exec.Cmd
	logs chan string
}

// start runs lys-secrets on the test's private session bus, the login
// password on an inherited pipe when given.
func start(t *testing.T, password string, args ...string) *daemon {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "LYS_SECRETS_TEST_MAIN=1")
	if password != "" {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, password+"\n")
		_ = w.Close()
		cmd.ExtraFiles = []*os.File{r}
		cmd.Args = append(cmd.Args, "--unlock-fd", "3")
		t.Cleanup(func() { _ = r.Close() })
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	d := &daemon{cmd: cmd, logs: make(chan string, 64)}
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			d.logs <- sc.Text()
		}
		close(d.logs)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return d
}

// waitLog waits for a log line containing want.
func (d *daemon) waitLog(t *testing.T, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case line, ok := <-d.logs:
			if !ok {
				t.Fatalf("lys-secrets exited before logging %q", want)
			}
			if strings.Contains(line, want) {
				return
			}
		case <-deadline:
			t.Fatalf("lys-secrets never logged %q", want)
		}
	}
}

func setup(t *testing.T) {
	t.Helper()
	dbustest.Session(t)
	t.Setenv("XDG_RUNTIME_DIR", sockdir.Dir(t))
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
}

func secretTool(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	tool, err := exec.LookPath("secret-tool")
	if err != nil {
		t.Skip("secret-tool is not installed (the nix dev shell carries it)")
	}
	cmd := exec.Command(tool, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	return string(out), err
}

func TestLoginPasswordUnlocksAndTheLockScreenRelocks(t *testing.T) {
	setup(t)
	d := start(t, "login-pw")
	d.waitLog(t, "serving org.freedesktop.secrets")
	if _, err := secretTool(t, "v1", "store", "--label=x", "app", "a"); err != nil {
		t.Fatalf("store after --unlock-fd: %v", err)
	}
	if got, err := secretTool(t, "", "lookup", "app", "a"); err != nil || got != "v1" {
		t.Fatalf("lookup = %q, %v", got, err)
	}
	files, _ := filepath.Glob(filepath.Join(os.Getenv("XDG_DATA_HOME"), "lys-secrets", "*.keyring"))
	if len(files) != 1 || filepath.Base(files[0]) != "login.keyring" {
		t.Errorf("collection files = %v", files)
	}

	// A restart starts locked; the control socket unlocks it with the
	// password the lock screen verified, and refuses a wrong one.
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	if err := d.cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM exit: %v", err)
	}
	d = start(t, "")
	d.waitLog(t, "serving org.freedesktop.secrets")
	sock, err := control.SocketPath(xdg.OS)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Unlock(sock, []byte("wrong")); !errors.Is(err, control.ErrWrongPassword) {
		t.Fatalf("wrong password over the socket = %v", err)
	}
	if err := control.Unlock(sock, []byte("login-pw")); err != nil {
		t.Fatalf("unlock over the socket: %v", err)
	}
	if got, err := secretTool(t, "", "lookup", "app", "a"); err != nil || got != "v1" {
		t.Errorf("lookup after the socket unlock = %q, %v", got, err)
	}
}

func TestAWrongLoginPasswordLeavesItLocked(t *testing.T) {
	setup(t)
	d := start(t, "right")
	d.waitLog(t, "serving")
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	_ = d.cmd.Wait()
	d = start(t, "wrong")
	d.waitLog(t, "does not unlock the login collection")
	d.waitLog(t, "serving")
	if got, _ := secretTool(t, "", "lookup", "app", "a"); got != "" {
		t.Errorf("lookup = %q while locked", got)
	}
}

// Another Secret Service provider (gnome-keyring) keeps its name, and
// lys-secrets still serves the vault, logged out on a fresh state
// directory.
func TestAnotherSecretServiceLeavesTheVault(t *testing.T) {
	setup(t)
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if reply, err := conn.RequestName("org.freedesktop.secrets", dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("take the Secret Service name: %v, %v", reply, err)
	}
	d := start(t, "")
	d.waitLog(t, "serving "+vault.ServiceName+" alone")
	st, err := vault.NewClient(conn).Status(context.Background())
	if err != nil || st.State != vault.StateLoggedOut {
		t.Errorf("vault status = %+v, %v", st, err)
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	if err := d.cmd.Wait(); err != nil {
		t.Errorf("SIGTERM exit: %v", err)
	}
}

// The vault shows as a Secret Service collection only when a folder is
// named for it.
func TestTheVaultCollectionIsOptIn(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{{nil, false}, {[]string{"--vault-collection-folder", "Desktop"}, true}} {
		t.Run(strconv.FormatBool(c.want), func(t *testing.T) {
			setup(t)
			d := start(t, "", c.args...)
			d.waitLog(t, "serving org.freedesktop.secrets")
			conn, err := dbus.ConnectSessionBus()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			v, err := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets").GetProperty("org.freedesktop.Secret.Service.Collections")
			if err != nil {
				t.Fatal(err)
			}
			paths, _ := v.Value().([]dbus.ObjectPath)
			if got := slices.Contains(paths, "/org/freedesktop/secrets/collection/bitwarden"); got != c.want {
				t.Errorf("collections %v: vault listed %v, want %v", paths, got, c.want)
			}
		})
	}
}

// A negative vault policy is a usage error.
func TestANegativeVaultPolicyIsRefused(t *testing.T) {
	setup(t)
	for _, arg := range []string{"--vault-lock-after=-1m", "--vault-sync-interval=-1s"} {
		cmd := exec.Command(os.Args[0], arg)
		cmd.Env = append(os.Environ(), "LYS_SECRETS_TEST_MAIN=1")
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "must not be negative") {
			t.Errorf("%s: %v, %s", arg, err, out)
		}
	}
}

func TestAnotherProviderKeepsTheName(t *testing.T) {
	setup(t)
	first := start(t, "pw")
	first.waitLog(t, "serving")
	second := start(t, "")
	second.waitLog(t, "is already served by")
	if err := second.cmd.Wait(); err != nil {
		t.Errorf("the second instance exit = %v, want a clean exit", err)
	}
	if first.cmd.ProcessState != nil {
		t.Error("the first instance died")
	}
}

type fakeLogind struct{}

func (fakeLogind) GetSession(string) (dbus.ObjectPath, *dbus.Error) {
	return "/org/freedesktop/login1/session/_1", nil
}

func loginLocked(t *testing.T) bool {
	t.Helper()
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	v, err := conn.Object(service.BusName, "/org/freedesktop/secrets/collection/login").GetProperty("org.freedesktop.Secret.Collection.Locked")
	if err != nil {
		t.Fatal(err)
	}
	locked, ok := v.Value().(bool)
	if !ok {
		t.Fatalf("Locked is %v", v)
	}
	return locked
}

func TestCollectionsLockWithTheScreen(t *testing.T) {
	setup(t)
	system := dbustest.Start(t)
	system.UseAsSystemBus(t)
	owner := system.Conn(t)
	if err := owner.Export(fakeLogind{}, "/org/freedesktop/login1", "org.freedesktop.login1.Manager"); err != nil {
		t.Fatal(err)
	}
	if reply, err := owner.RequestName("org.freedesktop.login1", dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("own logind's name on the private bus: %v, %v", reply, err)
	}

	d := start(t, "login-pw", "--collection-lock-on-screen-lock")
	d.waitLog(t, "serving org.freedesktop.secrets")
	if loginLocked(t) {
		t.Fatal("locked before the screen did")
	}
	deadline := time.Now().Add(10 * time.Second)
	for !loginLocked(t) {
		if time.Now().After(deadline) {
			t.Fatal("the collection did not lock with the screen")
		}
		if err := owner.Emit("/org/freedesktop/login1/session/_1", "org.freedesktop.login1.Session.Lock"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	sock, err := control.SocketPath(xdg.OS)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Unlock(sock, []byte("login-pw")); err != nil {
		t.Errorf("the unlocking lock screen's password = %v", err)
	}
	if loginLocked(t) {
		t.Error("the lock screen's password did not reopen the collection")
	}
}

func TestWithoutLogindTheServiceKeepsServingAndSaysSo(t *testing.T) {
	setup(t)
	system := dbustest.Start(t)
	system.UseAsSystemBus(t)
	d := start(t, "", "--collection-lock-on-screen-lock")
	d.waitLog(t, "NOT lock with the screen")
	sock, err := control.SocketPath(xdg.OS)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := control.Unlock(sock, []byte("login-pw"))
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service does not answer: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestANegativeCollectionLockAfterIsRefused(t *testing.T) {
	setup(t)
	cmd := exec.Command(os.Args[0], "--collection-lock-after=-1s")
	cmd.Env = append(os.Environ(), "LYS_SECRETS_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "--collection-lock-after") {
		t.Errorf("exit %v, output %q", err, out)
	}
}

// The usage line in the package comment names every flag.
func TestTheUsageLineNamesEveryFlag(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	doc, _, found := strings.Cut(string(src), "package main")
	if !found {
		t.Fatal("main.go has no package clause")
	}
	flags := regexp.MustCompile(`flag\.\w+\(&[\w.]+, "([a-z-]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(flags) == 0 {
		t.Fatal("found no flags in main.go")
	}
	for _, m := range flags {
		if !strings.Contains(doc, "[--"+m[1]) {
			t.Errorf("the usage line omits --%s", m[1])
		}
	}
}
