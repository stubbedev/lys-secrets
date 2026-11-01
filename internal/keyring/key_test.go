package keyring

import (
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
	for _, want := range []string{"swap", "4096-byte", unix.ENOMEM.Error(), "RLIMIT_MEMLOCK 65536 bytes", "LimitMEMLOCK="} {
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
