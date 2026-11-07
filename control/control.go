// Package control is lys-secrets' login channel: a unix socket in the
// user's runtime directory through which lys-login's login and lock
// screens hand over the password they just verified, so the login
// collection unlocks with it, and through which a password change moves
// the login collection from the old password to the new. No password
// crosses D-Bus. Only processes of the same user may connect, checked
// with SO_PEERCRED.
//
// Wire format: the client sends one request byte, then each of the
// request's passwords as a big-endian u32 length and the bytes (unlock:
// the password; rekey: the old password, then the new); the server
// answers one status byte.
package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/stubbedev/lys-lib/xdg"

	"github.com/stubbedev/lys-secrets/internal/usersock"
)

type request byte

const (
	requestUnlock request = iota + 1
	requestRekey
)

const (
	statusOK byte = iota
	statusWrongPassword
	statusFailed
)

// maxPassword bounds what a client may send.
const maxPassword = 4096

const timeout = 10 * time.Second

// Errors a client tells apart. ErrWrongPassword is also what a [Login]
// returns, or wraps, for a password that does not open the login
// collection.
var (
	ErrNotRunning    = errors.New("lys-secrets is not running")
	ErrWrongPassword = errors.New("lys-secrets: the password does not unlock the login collection")
)

// SocketPath is $XDG_RUNTIME_DIR/lys-secrets/control as env resolves
// it, so a process may find the socket of a session other than its own;
// an error when XDG_RUNTIME_DIR holds no absolute path, since there is
// no other place the user's session agrees on.
func SocketPath(env xdg.Env) (string, error) {
	return usersock.Path(env, "control")
}

// Login is the login collection as the socket serves it; a password that
// does not open it is an error matching ErrWrongPassword.
type Login interface {
	// UnlockLogin unlocks it with the login password.
	UnlockLogin(password []byte) error
	// RekeyLogin moves it from the login password old to next.
	RekeyLogin(old, next []byte) error
}

// Listen binds the socket at path in a 0700 directory, replacing a stale
// socket a dead server left.
func Listen(path string) (*usersock.Listener, error) {
	ln, err := usersock.Listen(path)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	return ln, nil
}

// Serve answers requests on ln until ctx ends.
func Serve(ctx context.Context, ln *usersock.Listener, l Login) {
	ln.Serve(ctx, "control", func(conn *net.UnixConn) { handle(conn, l) })
}

func handle(conn *net.UnixConn, l Login) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	err := answer(conn, l)
	status := statusOK
	switch {
	case errors.Is(err, ErrWrongPassword):
		status = statusWrongPassword
		log.Printf("control: %v", err)
	case err != nil:
		status = statusFailed
		log.Printf("control: %v", err)
	}
	_, _ = conn.Write([]byte{status})
}

func answer(r io.Reader, l Login) error {
	var req [1]byte
	if _, err := io.ReadFull(r, req[:]); err != nil {
		return fmt.Errorf("read the request: %w", err)
	}
	switch request(req[0]) {
	case requestUnlock:
		password, err := readPassword(r)
		if err != nil {
			return err
		}
		defer clear(password)
		if err := l.UnlockLogin(password); err != nil {
			return fmt.Errorf("unlock the login collection: %w", err)
		}
		return nil
	case requestRekey:
		old, err := readPassword(r)
		if err != nil {
			return err
		}
		defer clear(old)
		next, err := readPassword(r)
		if err != nil {
			return err
		}
		defer clear(next)
		if err := l.RekeyLogin(old, next); err != nil {
			return fmt.Errorf("move the login collection to the new password: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown request %d", req[0])
	}
}

func readPassword(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, fmt.Errorf("read the password length: %w", err)
	}
	if n == 0 || n > maxPassword {
		return nil, fmt.Errorf("a password of %d bytes is outside 1-%d", n, maxPassword)
	}
	password := make([]byte, n)
	if _, err := io.ReadFull(r, password); err != nil {
		clear(password)
		return nil, fmt.Errorf("read the password: %w", err)
	}
	return password, nil
}

// ReadPassword reads a password whatever started the process wrote to an
// inherited descriptor (--unlock-fd): the whole stream, without a trailing
// newline.
func ReadPassword(r io.Reader) ([]byte, error) {
	password, err := io.ReadAll(io.LimitReader(r, maxPassword+1))
	if err != nil {
		clear(password)
		return nil, fmt.Errorf("read the login password: %w", err)
	}
	if len(password) > maxPassword {
		clear(password)
		return nil, fmt.Errorf("the login password is longer than %d bytes", maxPassword)
	}
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
	}
	if len(password) == 0 {
		return nil, errors.New("the login password is empty")
	}
	return password, nil
}

// Unlock hands password to the lys-secrets serving path. No server is
// ErrNotRunning; a password that does not open the login collection is
// ErrWrongPassword.
func Unlock(path string, password []byte) error {
	return send(path, requestUnlock, password)
}

// Rekey asks the lys-secrets serving path to move the login collection
// from the password old to next, as a password change does. No server is
// ErrNotRunning; an old password that does not open the login collection,
// which next does not open either, is ErrWrongPassword.
func Rekey(path string, old, next []byte) error {
	return send(path, requestRekey, old, next)
}

func send(path string, req request, passwords ...[]byte) error {
	size := 1
	for _, p := range passwords {
		if len(p) == 0 || len(p) > maxPassword {
			return fmt.Errorf("control: a password of %d bytes is outside 1-%d", len(p), maxPassword)
		}
		size += 4 + len(p)
	}
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return ErrNotRunning
		}
		return fmt.Errorf("control: connect to %s: %w", path, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	msg := append(make([]byte, 0, size), byte(req))
	for _, p := range passwords {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(p))) //nolint:gosec // bounded by maxPassword above
		msg = append(msg, p...)
	}
	defer clear(msg)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("control: send the request: %w", err)
	}
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		return fmt.Errorf("control: read the answer: %w", err)
	}
	switch status[0] {
	case statusOK:
		return nil
	case statusWrongPassword:
		return ErrWrongPassword
	default:
		return errors.New("control: lys-secrets could not do it (see its log)")
	}
}
