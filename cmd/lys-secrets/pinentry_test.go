package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/portaldialogs"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/dialogtest"
)

// runPinentryCmd runs lys-secrets pinentry on the test's bus with stdin, until it
// exits or ctx ends.
func runPinentryCmd(ctx context.Context, t *testing.T, stdin io.Reader) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "pinentry")
	cmd.Env = append(os.Environ(), "LYS_SECRETS_TEST_MAIN=1")
	cmd.Stdin = stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func TestWithoutADialogHostThePinentryEndsAtOnce(t *testing.T) {
	setup(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := io.WriteString(w, "SETDESC Unlock%0Athe key\nGETPIN\n"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runPinentryCmd(ctx, t, r)
	_ = r.Close()
	if ctx.Err() != nil {
		t.Fatalf("the pinentry was still waiting after 2 seconds: %q", out)
	}
	if err != nil || !strings.Contains(out, "\nERR 83886165 ") {
		t.Errorf("without a dialog host the pinentry answered %q, %v; want GPG_ERR_NO_PIN_ENTRY", out, err)
	}
}

func TestAPassphrasePinentryGnome3StoredIsFound(t *testing.T) {
	setup(t)
	d := start(t, "pw")
	d.waitLog(t, "serving org.freedesktop.secrets")
	if _, err := secretTool(t, "from-gnome3", "store", "--label=GnuPG: n/ABCDEF", "xdg:schema", "org.gnupg.Passphrase", "stored-by", "GnuPG Pinentry", "keygrip", "n/ABCDEF"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := runPinentryCmd(ctx, t, strings.NewReader("OPTION allow-external-password-cache\nSETKEYINFO n/ABCDEF\nGETPIN\nBYE\n"))
	if err != nil || !strings.Contains(out, "\nS PASSWORD_FROM_CACHE\nD from-gnome3\nOK\n") {
		t.Errorf("the pinentry answered %q, %v; want the stored passphrase", out, err)
	}
}

// gnupg is a GnuPG home whose agent asks lys-secrets pinentry, holding one
// signing key under the passphrase hunter2.
func gnupg(t *testing.T) (gpg func(args ...string) (string, error), kill func()) {
	t.Helper()
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed (the nix dev shell carries it)")
	}
	gpgconf, err := exec.LookPath("gpgconf")
	if err != nil {
		t.Skip("gpgconf is not installed (the nix dev shell carries it)")
	}
	home := t.TempDir()
	wrapper := filepath.Join(home, "pinentry")
	script := "#!/bin/sh\nexec env LYS_SECRETS_TEST_MAIN=1 DBUS_SESSION_BUS_ADDRESS='" + os.Getenv("DBUS_SESSION_BUS_ADDRESS") + "' '" + os.Args[0] + "' pinentry \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "gpg-agent.conf"), []byte("pinentry-program "+wrapper+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GNUPGHOME="+home)
	run := func(bin string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	kill = func() { _, _ = run(gpgconf, "--kill", "gpg-agent") }
	t.Cleanup(kill)
	if out, err := run(gpgBin, "--batch", "--pinentry-mode", "loopback", "--passphrase", "hunter2", "--quick-gen-key", "Test <t@example.org>", "ed25519", "sign", "never"); err != nil {
		t.Fatalf("generate a key: %v\n%s", err, out)
	}
	kill()
	if err := os.WriteFile(filepath.Join(home, "in.txt"), []byte("signed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return func(args ...string) (string, error) {
		return run(gpgBin, append([]string{"--no-tty", "--yes"}, args...)...)
	}, kill
}

// gpg --sign asks for the key's passphrase through the lys dialog; once the
// user chose to remember it, the next signature after the agent restarted
// needs no dialog while the login collection is open.
func TestGpgSignsThroughTheLysDialogAndRemembers(t *testing.T) {
	setup(t)
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var dialogs atomic.Int32
	host := &dialogtest.Host{Password: func(r portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection) {
		dialogs.Add(1)
		var picked []portaldialogs.Selection
		for _, c := range r.Choices {
			picked = append(picked, portaldialogs.Selection{ID: c.ID, Value: "true"})
		}
		return true, "hunter2", picked
	}}
	dialogtest.Serve(t, conn, host)
	d := start(t, "pw")
	d.waitLog(t, "serving org.freedesktop.secrets")
	gpg, kill := gnupg(t)
	sign := func() {
		t.Helper()
		if out, err := gpg("--output", filepath.Join(t.TempDir(), "out.sig"), "--sign", filepath.Join(gnupgHome(t, gpg), "in.txt")); err != nil {
			t.Fatalf("gpg --sign: %v\n%s", err, out)
		}
	}
	sign()
	asked, _ := host.Asked()
	if len(asked) != 1 || len(asked[0].Choices) != 1 || !strings.Contains(asked[0].Body, "Test <t@example.org>") {
		t.Fatalf("the first signature asked %+v, want one dialog offering to remember", asked)
	}
	if out, err := secretTool(t, "", "search", "xdg:schema", "org.gnupg.Passphrase"); err != nil || !strings.Contains(out, "label = GnuPG: n/") || !strings.Contains(out, "secret = hunter2") {
		t.Fatalf("the remembered passphrase: %q, %v", out, err)
	}
	kill()
	sign()
	if got := dialogs.Load(); got != 1 {
		t.Errorf("after the agent restarted the signature asked %d dialogs in all, want the first one only", got)
	}
}

// gnupgHome is the GnuPG home gpg runs in.
func gnupgHome(t *testing.T, gpg func(args ...string) (string, error)) string {
	t.Helper()
	out, err := gpg("--version")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(out, "\n") {
		if home, ok := strings.CutPrefix(line, "Home: "); ok {
			return strings.TrimSpace(home)
		}
	}
	t.Fatalf("gpg --version names no home:\n%s", out)
	return ""
}

// pinentry-lys, a link to the binary, is the pinentry with no argument, as a
// pinentry-program line names it.
func TestTheBinaryNamedPinentryLysIsThePinentry(t *testing.T) {
	setup(t)
	link := filepath.Join(t.TempDir(), "pinentry-lys")
	if err := os.Symlink(os.Args[0], link); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, link)
	cmd.Env = append(os.Environ(), "LYS_SECRETS_TEST_MAIN=1")
	cmd.Stdin = strings.NewReader("GETINFO flavor\nBYE\n")
	out, err := cmd.Output()
	if err != nil || !strings.HasPrefix(string(out), "OK Pleased to meet you") || !strings.Contains(string(out), "\nD lys\nOK\nOK closing connection\n") {
		t.Errorf("pinentry-lys answered %q, %v", out, err)
	}
}
