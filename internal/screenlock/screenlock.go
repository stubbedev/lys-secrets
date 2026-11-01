// Package screenlock tells when the user's logind session locks: a Lock
// signal, sent for `loginctl lock-session` and the like, or LockedHint
// turning true, which a screen locker such as lys-login's sets itself.
package screenlock

import (
	"context"
	"errors"
	"fmt"
	"time"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

const (
	service     = "org.freedesktop.login1"
	managerPath = dbus.ObjectPath("/org/freedesktop/login1")
	managerIf   = "org.freedesktop.login1.Manager"
	sessionIf   = "org.freedesktop.login1.Session"
	propsIf     = "org.freedesktop.DBus.Properties"
	// autoSession is the caller's session, or for a user unit, which is
	// in none, the user's display session.
	autoSession = "auto"
	callTimeout = 10 * time.Second
)

// Watch runs locked each time the session locks, until ctx ends. It
// returns an error when it cannot watch, or the bus goes away; locked runs
// on Watch's goroutine.
func Watch(ctx context.Context, conn *dbus.Conn, locked func()) error {
	path, err := session(ctx, conn)
	if err != nil {
		return err
	}
	opts := []dbus.MatchOption{dbus.WithMatchObjectPath(path), dbus.WithMatchSender(service)}
	if err := conn.AddMatchSignal(opts...); err != nil {
		return fmt.Errorf("screenlock: watch session %s: %w", path, err)
	}
	defer func() { _ = conn.RemoveMatchSignal(opts...) }()
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)
	for {
		select {
		case <-ctx.Done():
			return nil
		case sig, ok := <-signals:
			if !ok {
				return errors.New("screenlock: the system bus went away")
			}
			if sig.Path == path && isLock(sig) {
				locked()
			}
		}
	}
}

// session is the real object path of the session: logind emits its
// signals from that one, not from the /session/auto alias.
func session(ctx context.Context, conn *dbus.Conn) (dbus.ObjectPath, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var path dbus.ObjectPath
	if err := conn.Object(service, managerPath).CallWithContext(ctx, managerIf+".GetSession", 0, autoSession).Store(&path); err != nil {
		return "", fmt.Errorf("screenlock: find the session with logind's GetSession(%q): %w", autoSession, err)
	}
	return path, nil
}

func isLock(sig *dbus.Signal) bool {
	switch sig.Name {
	case sessionIf + ".Lock":
		return true
	case propsIf + ".PropertiesChanged":
		if len(sig.Body) < 2 || sig.Body[0] != sessionIf {
			return false
		}
		changed, ok := sig.Body[1].(map[string]dbus.Variant)
		if !ok {
			return false
		}
		hint, ok := changed["LockedHint"]
		if !ok {
			return false
		}
		locked, ok := hint.Value().(bool)
		return ok && locked
	}
	return false
}
