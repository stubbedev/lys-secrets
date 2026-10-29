package vault

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// The errors a call fails with. A Client returns them wrapped with the
// vault's own message, so errors.Is tells them apart.
var (
	ErrWrongPassword         = errors.New("vault: wrong master password")
	ErrInvalidCredentials    = errors.New("vault: invalid credentials")
	ErrLoginRequired         = errors.New("vault: login required")
	ErrNewDeviceVerification = errors.New("vault: new device verification required")
	ErrLocked                = errors.New("vault: the vault is not open")
	ErrNoSuchItem            = errors.New("vault: no such item")
	ErrNoSuchField           = errors.New("vault: the item has no such field")
	ErrRepromptRequired      = errors.New("vault: the item asks for the master password")
	ErrUnreachable           = errors.New("vault: the server is unreachable")
	ErrAccessDenied          = errors.New("vault: only the vault's own user may use it")
)

// TwoFactorRequiredError asks for a second factor: the providers the
// account has.
type TwoFactorRequiredError struct{ Providers []TwoFactorProvider }

func (e *TwoFactorRequiredError) Error() string {
	return fmt.Sprintf("vault: two-factor authentication required (providers %v)", e.Providers)
}

// ServerError is a server answer the vault does not handle: its HTTP
// status and the server's message.
type ServerError struct {
	Status  int
	Message string
}

func (e *ServerError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("vault: the server answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("vault: the server answered HTTP %d: %s", e.Status, e.Message)
}

// Retryable reports a rate limit or a server-side failure, worth trying
// again later; a client error is not.
func (e *ServerError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= http.StatusInternalServerError
}

const (
	errPrefix            = iface + ".Error."
	errTwoFactorRequired = errPrefix + "TwoFactorRequired"
	errServer            = errPrefix + "Server"
)

// sentinels names each sentinel error on the bus.
var sentinels = []struct {
	name string
	err  error
}{
	{errPrefix + "WrongPassword", ErrWrongPassword},
	{errPrefix + "InvalidCredentials", ErrInvalidCredentials},
	{errPrefix + "LoginRequired", ErrLoginRequired},
	{errPrefix + "NewDeviceVerification", ErrNewDeviceVerification},
	{errPrefix + "Locked", ErrLocked},
	{errPrefix + "NoSuchItem", ErrNoSuchItem},
	{errPrefix + "NoSuchField", ErrNoSuchField},
	{errPrefix + "RepromptRequired", ErrRepromptRequired},
	{errPrefix + "Unreachable", ErrUnreachable},
	{errPrefix + "AccessDenied", ErrAccessDenied},
}

// encodeError is err as the bus carries it: a contract error under its
// name, its message first in the body; anything else Failed.
func encodeError(err error) *dbus.Error {
	if tf, ok := errors.AsType[*TwoFactorRequiredError](err); ok {
		providers := make([]uint32, len(tf.Providers))
		for i, p := range tf.Providers {
			providers[i] = uint32(p)
		}
		return dbus.NewError(errTwoFactorRequired, []any{err.Error(), providers})
	}
	if se, ok := errors.AsType[*ServerError](err); ok {
		return dbus.NewError(errServer, []any{err.Error(), uint32(max(se.Status, 0)), se.Message}) //nolint:gosec // clamped to 0..MaxInt, an HTTP status
	}
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return dbus.NewError(s.name, []any{err.Error()})
		}
	}
	return dbusx.Failed(err.Error())
}

// remoteError is a contract error as the vault reported it: its
// message, matching the sentinel.
type remoteError struct {
	msg string
	is  error
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.is }

// decodeError reads a call's failure back into the contract's errors;
// an error name the contract does not define is an error saying so,
// and a failure off the bus (no vault running) is returned as it is.
func decodeError(err error) error {
	var de dbus.Error
	if !errors.As(err, &de) || !strings.HasPrefix(de.Name, errPrefix) {
		return err
	}
	msg := de.Name
	if len(de.Body) > 0 {
		if s, ok := de.Body[0].(string); ok {
			msg = s
		}
	}
	switch de.Name {
	case errTwoFactorRequired:
		tf := &TwoFactorRequiredError{}
		if len(de.Body) > 1 {
			raw, ok := de.Body[1].([]uint32)
			if !ok {
				return fmt.Errorf("vault: %s carries providers of type %T", de.Name, de.Body[1])
			}
			for _, p := range raw {
				tf.Providers = append(tf.Providers, TwoFactorProvider(p))
			}
		}
		return tf
	case errServer:
		if len(de.Body) != 3 {
			return fmt.Errorf("vault: %s carries %d values, want 3: %s", de.Name, len(de.Body), msg)
		}
		status, ok1 := de.Body[1].(uint32)
		message, ok2 := de.Body[2].(string)
		if !ok1 || !ok2 {
			return fmt.Errorf("vault: %s carries (%T, %T), want (u, s): %s", de.Name, de.Body[1], de.Body[2], msg)
		}
		return &ServerError{Status: int(status), Message: message}
	}
	for _, s := range sentinels {
		if s.name == de.Name {
			return &remoteError{msg: msg, is: s.err}
		}
	}
	return fmt.Errorf("vault: unknown error %s: %s", de.Name, msg)
}
