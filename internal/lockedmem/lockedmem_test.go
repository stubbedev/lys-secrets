package lockedmem

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAFailedMlockIsLoggedOnceWithItsContext(t *testing.T) {
	var logged []string
	g := swapGuard{
		mlock: func([]byte) error { return unix.ENOMEM },
		limit: func() (uint64, error) { return 65536, nil },
		logf:  func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	page := make([]byte, 4096)
	g.pin(page)
	g.pin(page)
	if len(logged) != 1 {
		t.Fatalf("logged %q, want one line", logged)
	}
	for _, want := range []string{"swap", "4096-byte page", unix.ENOMEM.Error(), "RLIMIT_MEMLOCK 65536 bytes", "LimitMEMLOCK="} {
		if !strings.Contains(logged[0], want) {
			t.Errorf("%q does not say %q", logged[0], want)
		}
	}
}

func TestAFailedMlockStillLogsWithoutTheLimit(t *testing.T) {
	var logged []string
	g := swapGuard{
		mlock: func([]byte) error { return unix.EPERM },
		limit: func() (uint64, error) { return 0, errors.New("no limit") },
		logf:  func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	g.pin(make([]byte, 4096))
	if len(logged) != 1 || !strings.Contains(logged[0], "RLIMIT_MEMLOCK unknown") {
		t.Errorf("logged %q", logged)
	}
}

func TestASuccessfulMlockLogsNothing(t *testing.T) {
	g := swapGuard{
		mlock: func([]byte) error { return nil },
		limit: func() (uint64, error) { return 0, nil },
		logf:  func(string, ...any) { t.Error("logged after a successful mlock") },
	}
	g.pin(make([]byte, 4096))
}

func TestABufHoldsItsBytesUntilDestroyed(t *testing.T) {
	b, err := Copy([]byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Bytes()) != "hunter2" || len(b.Bytes()) != 7 || cap(b.Bytes()) != 7 {
		t.Fatalf("Bytes = %q (cap %d)", b.Bytes(), cap(b.Bytes()))
	}
	if !b.Holds(b.Bytes()) || !b.Holds(b.Bytes()[2:4]) {
		t.Error("the buffer does not hold its own bytes")
	}
	if b.Holds([]byte("hunter2")) || b.Holds(nil) {
		t.Error("the buffer holds a heap slice")
	}
	view := b.Bytes()[:1]
	b.Destroy()
	if !b.Destroyed() || b.Bytes() != nil || b.Holds(view) {
		t.Error("a destroyed buffer still holds memory")
	}
	b.Destroy()
	if _, err := New(0); err == nil {
		t.Error("a zero-length buffer was mapped")
	}
}

func TestDestroyZeroesBeforeUnmapping(t *testing.T) {
	b, err := Copy([]byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	var seen []byte
	unmap = func(page []byte) error {
		seen = append(seen, page...)
		return unix.Munmap(page)
	}
	t.Cleanup(func() { unmap = unix.Munmap })
	b.Destroy()
	if len(seen) == 0 || bytes.ContainsFunc(seen, func(r rune) bool { return r != 0 }) {
		t.Errorf("the page held %q as it was unmapped", bytes.TrimRight(seen, "\x00"))
	}
}
