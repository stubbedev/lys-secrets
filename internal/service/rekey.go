package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/stubbedev/lys-secrets/control"
	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/lockedmem"
)

// rekeyOffer is the question a login password that does not open the login
// collection raises: the account's password changed, so the user is asked once
// for the previous one to move the collection to the new. The new password waits
// in locked memory while the dialog is up, and is destroyed when it closes.
type rekeyOffer struct {
	mu sync.Mutex
	// next is the newest login password, nil when none waits.
	next *lockedmem.Buf
	// cancel takes the dialog down, nil while none is up.
	cancel context.CancelFunc
}

// offer remembers password as the new login password and shows the dialog unless
// it is up already, in which case the newer password replaces the one it waited
// with.
func (s *Service) offerRekey(password []byte) {
	next, err := lockedmem.Copy(password)
	if err != nil {
		log.Printf("secrets: keep the new login password for the re-key dialog: %v", err)
		return
	}
	o := &s.rekey
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next.Destroy()
	o.next = next
	if o.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	go s.askRekey(ctx)
}

// dropRekey takes down the dialog and destroys the password it waited with.
func (s *Service) dropRekey() {
	o := &s.rekey
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next.Destroy()
	o.next = nil
	if o.cancel != nil {
		o.cancel()
	}
}

// take hands the waiting new password to whoever re-keys with it.
func (o *rekeyOffer) take() *lockedmem.Buf {
	o.mu.Lock()
	defer o.mu.Unlock()
	next := o.next
	o.next = nil
	return next
}

// giveBack returns a password take handed out, unless a newer one came meanwhile.
func (o *rekeyOffer) giveBack(next *lockedmem.Buf) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.next != nil || next == nil {
		next.Destroy()
		return
	}
	o.next = next
}

// close ends the dialog's run, destroying what it waited with.
func (o *rekeyOffer) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next.Destroy()
	o.next = nil
	o.cancel()
	o.cancel = nil
}

// askRekey asks for the previous login password until it opens the login
// collection, which then moves to the new one, or the user keeps the old
// password apart.
func (s *Service) askRekey(ctx context.Context) {
	defer s.rekey.close()
	retry := false
	for {
		old, ok, err := s.cfg.Prompter.PreviousLoginPassword(ctx, retry)
		if err != nil || !ok {
			logPromptErr("re-key the login collection", err)
			return
		}
		next := s.rekey.take()
		if next == nil {
			clear(old)
			return
		}
		err = s.RekeyLogin(old, next.Bytes())
		clear(old)
		switch {
		case err == nil:
			next.Destroy()
			log.Printf("secrets: the login collection moved to the new login password")
			return
		case errors.Is(err, control.ErrWrongPassword):
			s.rekey.giveBack(next)
			retry = true
		default:
			next.Destroy()
			log.Printf("secrets: re-key the login collection: %v", err)
			return
		}
	}
}

// RekeyLogin moves the login collection from the password old to next, as a
// password change does, unlocking it on the way. A collection next opens already
// is left as it is, so running it twice is safe, and with no login collection
// there is nothing to move. An old password that opens nothing matches both
// control.ErrWrongPassword and keyring.ErrWrongPassword.
func (s *Service) RekeyLogin(old, next []byte) error {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.mu.Lock()
	c, ok := s.colls[LoginID]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	err := s.verify(c, old)
	if errors.Is(err, keyring.ErrWrongPassword) {
		if s.verify(c, next) == nil {
			return nil
		}
		return fmt.Errorf("%w: %w", control.ErrWrongPassword, err)
	}
	if err != nil {
		return err
	}
	rekey, err := keyring.NewRekey(next, s.cfg.KDF, s.cfg.Stretch)
	if err != nil {
		return err
	}
	return s.changeKey(c, rekey)
}

// verify tests password against c, unlocking c with it when it is locked.
func (s *Service) verify(c *collection, password []byte) error {
	s.mu.Lock()
	v, err := c.kr.Verifier()
	s.mu.Unlock()
	if errors.Is(err, keyring.ErrLocked) {
		return s.unlock(c, password)
	}
	if err != nil {
		return err
	}
	return v.Verify(password, s.cfg.Stretch)
}

// changeKey moves c to the key r holds, through the same durable write as every
// change; r is used up whatever happens.
func (s *Service) changeKey(c *collection, r *keyring.Rekey) error {
	applied := false
	err := s.change(c, func(kr *keyring.Collection) error {
		applied = true
		return kr.ChangeKey(r)
	}, nothingToAnnounce)
	if !applied {
		r.Discard()
	}
	return err
}
