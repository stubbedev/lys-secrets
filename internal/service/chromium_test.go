package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
)

// Chromium keeps its cookie encryption key in the Secret Service: the
// first run creates "Chromium Safe Storage", a second run reads it back
// and decrypts the cookie the first one stored.
func TestChromiumKeepsItsSafeStorageKey(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		t.Run(map[bool]string{false: "every reader", true: "reads confirmed"}[confirm], func(t *testing.T) {
			chromiumKeepsItsKey(t, confirm)
		})
	}
}

// chromiumKeepsItsKey runs Chromium twice; with reads confirmed, secret-tool,
// another program, is allowed once each time it looks.
func chromiumKeepsItsKey(t *testing.T, confirm bool) {
	chromium := requireTool(t, "chromium")
	tool := requireTool(t, "secret-tool")
	f := &fixture{bus: dbustest.Session(t), dir: t.TempDir(), prompter: &fakePrompter{}, confirm: confirm}
	f.start(t)
	if confirm {
		f.prompter.script("allow", "allow")
	}
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "kept", Value: "across-runs", MaxAge: 3600})
			_, _ = fmt.Fprint(w, "<html><body>set</body></html>")
			return
		}
		_, _ = fmt.Fprintf(w, "<html><body>cookie=%s</body></html>", r.Header.Get("Cookie"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	profile, home := t.TempDir(), t.TempDir()
	browse := func(path string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chromium, "--headless=new", "--no-sandbox", "--disable-gpu",
			"--password-store=gnome-libsecret", "--user-data-dir="+profile, "--dump-dom", "http://"+ln.Addr().String()+path)
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("chromium %s: %v", path, err)
		}
		return string(out)
	}
	keys := func() string {
		t.Helper()
		args := []string{"search", "--all", "application", "chromium"}
		if confirm {
			args = append(args, "--unlock")
		}
		out, err := run(t, "", tool, args...)
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		return out
	}

	browse("/set")
	first := keys()
	if strings.Count(first, "label = Chromium Safe Storage") != 1 || confirm && !strings.Contains(first, "secret = ") {
		t.Fatalf("after the first run the keyring holds:\n%s", first)
	}
	if got := browse("/read"); !strings.Contains(got, "cookie=kept=across-runs") {
		t.Errorf("the second run did not decrypt the stored cookie: %s", got)
	}
	if second := keys(); second != first {
		t.Errorf("the second run changed the key:\n%s\nwas:\n%s", second, first)
	}
	if want := map[bool]int{false: 0, true: 2}[confirm]; len(f.prompter.log()) != want {
		t.Errorf("asked %v, want %d reads confirmed", f.prompter.log(), want)
	}
}
