// Package fdtest checks that a descriptor a test sends over D-Bus is
// closed by everyone it reaches: a pipe whose read end hangs up only
// once no copy of its write end is open anywhere in the process.
package fdtest

import (
	"errors"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/intconv"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
	"golang.org/x/sys/unix"
)

const hangupBound = 5 * time.Second

// Pipe is a pipe whose write end, Write, the test sends.
type Pipe struct {
	read   int
	Write  dbus.UnixFD
	closed bool
}

// New opens a pipe, closed at cleanup.
func New(t testing.TB) *Pipe {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("fdtest: open a pipe: %v", err)
	}
	p := &Pipe{read: fds[0], Write: intconv.Must[dbus.UnixFD](fds[1])}
	t.Cleanup(func() {
		if !p.closed {
			_ = unix.Close(int(p.Write))
		}
		_ = unix.Close(p.read)
	})
	return p
}

// RequireEveryCopyClosed closes the test's write end and fails the test
// unless every copy of it the bus handed out is closed as well.
func (p *Pipe) RequireEveryCopyClosed(t testing.TB) {
	t.Helper()
	p.closed = true
	if err := unix.Close(int(p.Write)); err != nil {
		t.Fatalf("fdtest: close the write end %d: %v", p.Write, err)
	}
	fds := []unix.PollFd{{Fd: intconv.Must[int32](p.read), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, int(hangupBound.Milliseconds()))
	for errors.Is(err, unix.EINTR) {
		n, err = unix.Poll(fds, int(hangupBound.Milliseconds()))
	}
	if err != nil || n != 1 || fds[0].Revents&unix.POLLHUP == 0 {
		t.Fatalf("a copy of descriptor %d the bus carried is still open %v later: poll = %d, %v, events %#x", p.Write, hangupBound, n, err, fds[0].Revents)
	}
}
