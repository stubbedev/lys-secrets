package usersock

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/sockdir"
)

func serve(t *testing.T, l *Listener, handled *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.Serve(ctx, "test", func(conn *net.UnixConn) {
			handled.Add(1)
			_, _ = conn.Write([]byte{1})
		})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

func answer(t *testing.T, path string) []byte {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestTheUsersOwnProcessIsServed(t *testing.T) {
	path := filepath.Join(sockdir.Dir(t), "d", "sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	var handled atomic.Int32
	serve(t, l, &handled)
	if got := answer(t, path); len(got) != 1 || handled.Load() != 1 {
		t.Errorf("answered %v after %d handled", got, handled.Load())
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the socket's directory is %v, %v", info.Mode(), err)
	}
}

func TestAnotherUidIsRefusedUnheard(t *testing.T) {
	path := filepath.Join(sockdir.Dir(t), "sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	l.uid = os.Getuid() + 1
	var handled atomic.Int32
	serve(t, l, &handled)
	if got := answer(t, path); len(got) != 0 || handled.Load() != 0 {
		t.Errorf("another uid got %v after %d handled", got, handled.Load())
	}
}

func TestListenRefusesALiveServerAndReplacesAStaleSocket(t *testing.T) {
	path := filepath.Join(sockdir.Dir(t), "sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	var handled atomic.Int32
	serve(t, l, &handled)
	if _, err := Listen(path); err == nil {
		t.Error("a second server took a live socket")
	}
	stale := filepath.Join(sockdir.Dir(t), "stale")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close()
	l2, err := Listen(stale)
	if err != nil {
		t.Fatalf("a stale socket blocked Listen: %v", err)
	}
	_ = l2.Close()
}
