// Package usersock serves a unix socket only the user's own processes may
// use: it lives in a 0700 directory, and a peer whose SO_PEERCRED uid is
// another is refused before it is heard.
package usersock

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/stubbedev/lys-lib/peercred"
)

// Listener accepts the user's own connections on a socket.
type Listener struct {
	ln  *net.UnixListener
	uid int
}

// Listen binds the socket at path in a 0700 directory, replacing a stale
// socket a dead server left, and refusing one a live server holds.
func Listen(path string) (*Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs its search bit; 0700 keeps it the user's alone
		return nil, fmt.Errorf("restrict %s: %w", dir, err)
	}
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("another server holds %s", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("remove the stale %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	return &Listener{ln: ln, uid: os.Getuid()}, nil
}

// Close stops listening and removes the socket.
func (l *Listener) Close() error { return l.ln.Close() }

// Serve hands each connection of the user's own processes to handle, in a
// goroutine of its own that closes it afterwards, until ctx ends; name says
// whose socket it is in the log.
func (l *Listener) Serve(ctx context.Context, name string, handle func(*net.UnixConn)) {
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	for {
		conn, err := l.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("%s: accept: %v", name, err)
			}
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			if err := l.own(conn); err != nil {
				log.Printf("%s: refused a connection: %v", name, err)
				return
			}
			handle(conn)
		}()
	}
}

func (l *Listener) own(conn *net.UnixConn) error {
	uid, err := peercred.UID(conn)
	if err != nil {
		return err
	}
	if int(uid) != l.uid {
		return fmt.Errorf("peer uid %d is not this user's %d", uid, l.uid)
	}
	return nil
}
