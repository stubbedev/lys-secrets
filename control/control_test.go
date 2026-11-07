package control

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stubbedev/lys-lib/sockdir"
	"github.com/stubbedev/lys-lib/xdg"
)

type fakeLogin struct {
	mu   sync.Mutex
	want string
	got  []string
	err  error
}

func (f *fakeLogin) UnlockLogin(password []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, string(password))
	if f.err != nil {
		return f.err
	}
	if string(password) != f.want {
		return ErrWrongPassword
	}
	return nil
}

func (f *fakeLogin) RekeyLogin(old, next []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, string(old)+">"+string(next))
	if f.err != nil {
		return f.err
	}
	if string(old) != f.want && string(next) != f.want {
		return ErrWrongPassword
	}
	f.want = string(next)
	return nil
}

func serve(t *testing.T, u Login) string {
	t.Helper()
	path := filepath.Join(sockdir.Dir(t), "lys-secrets", "control")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Serve(ctx, ln, u); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

func TestUnlockOverTheSocket(t *testing.T) {
	u := &fakeLogin{want: "right"}
	path := serve(t, u)
	if err := Unlock(path, []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password = %v", err)
	}
	if err := Unlock(path, []byte("right")); err != nil {
		t.Errorf("right password = %v", err)
	}
	if strings.Join(u.got, ",") != "wrong,right" {
		t.Errorf("the server saw %v", u.got)
	}
	u.err = errors.New("disk full")
	if err := Unlock(path, []byte("right")); err == nil || errors.Is(err, ErrWrongPassword) {
		t.Errorf("a failing unlock = %v, want a generic failure", err)
	}
}

func TestRekeyOverTheSocket(t *testing.T) {
	u := &fakeLogin{want: "old"}
	path := serve(t, u)
	if err := Rekey(path, []byte("typo"), []byte("new")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("a wrong old password = %v", err)
	}
	if err := Rekey(path, []byte("old"), []byte("new")); err != nil {
		t.Errorf("the right old password = %v", err)
	}
	if err := Unlock(path, []byte("new")); err != nil {
		t.Errorf("the new password after the re-key = %v", err)
	}
	if strings.Join(u.got, ",") != "typo>new,old>new,new" {
		t.Errorf("the server saw %v", u.got)
	}
	if err := Rekey(path, []byte("old"), nil); err == nil {
		t.Error("an empty new password was sent")
	}
}

func TestUnlockWithoutAServer(t *testing.T) {
	path := filepath.Join(sockdir.Dir(t), "absent")
	if err := Unlock(path, []byte("x")); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Unlock = %v, want ErrNotRunning", err)
	}
	if err := Unlock(path, nil); err == nil || errors.Is(err, ErrNotRunning) {
		t.Errorf("empty password = %v, want a refusal before dialing", err)
	}
}

func TestServerRefusesMalformedRequests(t *testing.T) {
	u := &fakeLogin{want: "x"}
	path := serve(t, u)
	for _, msg := range [][]byte{
		{},
		{9},
		binary.BigEndian.AppendUint32([]byte{byte(requestUnlock)}, 0),
		binary.BigEndian.AppendUint32([]byte{byte(requestUnlock)}, maxPassword+1),
		append(binary.BigEndian.AppendUint32([]byte{byte(requestUnlock)}, 10), "short"...),
		append(binary.BigEndian.AppendUint32([]byte{byte(requestRekey)}, 1), 'x'),
		binary.BigEndian.AppendUint32(append(binary.BigEndian.AppendUint32([]byte{byte(requestRekey)}, 1), 'x'), 0),
	} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write(msg)
		_ = conn.(*net.UnixConn).CloseWrite()
		status := make([]byte, 1)
		n, _ := conn.Read(status)
		_ = conn.Close()
		if n != 1 || status[0] != statusFailed {
			t.Errorf("%x: status %v", msg, status[:n])
		}
	}
	if len(u.got) != 0 {
		t.Errorf("a malformed request reached the login collection: %v", u.got)
	}
}

func TestReadPassword(t *testing.T) {
	for in, want := range map[string]string{"pw\n": "pw", "pw": "pw", "a b\n": "a b"} {
		got, err := ReadPassword(strings.NewReader(in))
		if err != nil || string(got) != want {
			t.Errorf("%q = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "\n", strings.Repeat("x", maxPassword+1)} {
		if _, err := ReadPassword(strings.NewReader(bad)); err == nil {
			t.Errorf("%d bytes accepted", len(bad))
		}
	}
}

func TestSocketPath(t *testing.T) {
	runtimeDir := func(dir string) xdg.Env {
		return func(key string) string {
			if key == "XDG_RUNTIME_DIR" {
				return dir
			}
			return ""
		}
	}
	if got, err := SocketPath(runtimeDir("/run/user/1000")); err != nil || got != "/run/user/1000/lys-secrets/control" {
		t.Errorf("SocketPath = %q, %v", got, err)
	}
	for _, bad := range []string{"", "run/user/1000"} {
		if got, err := SocketPath(runtimeDir(bad)); err == nil {
			t.Errorf("XDG_RUNTIME_DIR=%q: SocketPath = %q, want an error", bad, got)
		}
	}
}
