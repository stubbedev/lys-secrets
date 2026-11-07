package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/atomicfile"

	"github.com/stubbedev/lys-secrets/control"
	"github.com/stubbedev/lys-secrets/internal/keyring"
)

// loginWithItem is a locked login collection on the password "old", holding one
// item whose secret is "s3cret".
func loginWithItem(t *testing.T) (*fixture, uint32) {
	t.Helper()
	f := newFixture(t)
	if err := f.svc.UnlockLogin([]byte("old")); err != nil {
		t.Fatal(err)
	}
	var id uint32
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	f.svc.mu.Unlock()
	err := f.svc.change(c, func(kr *keyring.Collection) error {
		var err error
		id, _, err = kr.CreateItem("token", map[string]string{"service": "git"}, []byte("s3cret"), "text/plain", false, time.Now())
		return err
	}, nothingToAnnounce)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.LockCollections()
	return f, id
}

func (f *fixture) loginSecret(t *testing.T, id uint32) string {
	t.Helper()
	f.svc.mu.Lock()
	defer f.svc.mu.Unlock()
	secret, err := f.svc.colls[LoginID].kr.Secret(id)
	if err != nil {
		t.Fatalf("the login collection's item: %v", err)
	}
	return string(secret)
}

// rekeyDialogClosed waits until no re-key dialog is up.
func (f *fixture) rekeyDialogClosed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.svc.rekey.mu.Lock()
		up := f.svc.rekey.cancel != nil
		f.svc.rekey.mu.Unlock()
		if !up {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the re-key dialog is still up; asked %v", f.prompter.log())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAChangedLoginPasswordAsksOnceForThePreviousOne(t *testing.T) {
	f, id := loginWithItem(t)
	f.prompter.script("typo", "old")
	if err := f.svc.UnlockLogin([]byte("new")); !errors.Is(err, control.ErrWrongPassword) {
		t.Fatalf("the new password before the re-key = %v", err)
	}
	f.rekeyDialogClosed(t)
	if got, want := f.prompter.log(), []string{"previous login", "previous login retry"}; !slices.Equal(got, want) {
		t.Errorf("asked %v, want %v", got, want)
	}
	if f.loginLocked() || f.loginSecret(t, id) != "s3cret" {
		t.Fatal("the re-key left the login collection locked or lost its item")
	}

	f.prompter.script()
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("new")); err != nil {
		t.Fatalf("the new password after the re-key = %v", err)
	}
	if got := f.prompter.log(); len(got) != 0 {
		t.Errorf("an unlock after the re-key asked %v", got)
	}
	f.svc.Close()
	f.start(t)
	if err := f.svc.UnlockLogin([]byte("new")); err != nil || f.loginSecret(t, id) != "s3cret" {
		t.Errorf("after a restart the new password = %v", err)
	}
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("old")); !errors.Is(err, keyring.ErrWrongPassword) {
		t.Errorf("the old password after the re-key = %v", err)
	}
}

func TestKeepingTheOldPasswordLeavesTheFileAsItWas(t *testing.T) {
	f, _ := loginWithItem(t)
	before := f.loginFile(t)
	f.prompter.script("")
	if err := f.svc.UnlockLogin([]byte("new")); !errors.Is(err, control.ErrWrongPassword) {
		t.Fatalf("the new password = %v", err)
	}
	f.rekeyDialogClosed(t)
	if got := f.prompter.log(); !slices.Equal(got, []string{"previous login"}) {
		t.Errorf("asked %v", got)
	}
	if !bytes.Equal(f.loginFile(t), before) {
		t.Error("keeping the old password changed the file")
	}
	if !f.loginLocked() {
		t.Error("keeping the old password unlocked the collection")
	}
	if err := f.svc.UnlockLogin([]byte("old")); err != nil {
		t.Errorf("the old password after keeping it = %v", err)
	}
}

// heldPrompter holds the previous-password dialog open until the test answers it.
type heldPrompter struct {
	*fakePrompter
	shown   chan struct{}
	answers chan string
}

func (h *heldPrompter) PreviousLoginPassword(ctx context.Context, _ bool) ([]byte, bool, error) {
	h.shown <- struct{}{}
	select {
	case a := <-h.answers:
		return []byte(a), a != "", nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

func TestTheWaitingNewPasswordIsDestroyedWhicheverButtonIsPressed(t *testing.T) {
	for _, answer := range []string{"", "old"} {
		f, _ := loginWithItem(t)
		h := &heldPrompter{fakePrompter: f.prompter, shown: make(chan struct{}, 1), answers: make(chan string)}
		f.svc.cfg.Prompter = h
		if err := f.svc.UnlockLogin([]byte("new")); !errors.Is(err, control.ErrWrongPassword) {
			t.Fatalf("the new password = %v", err)
		}
		select {
		case <-h.shown:
		case <-time.After(10 * time.Second):
			t.Fatal("the dialog never showed")
		}
		f.svc.rekey.mu.Lock()
		waiting := f.svc.rekey.next
		f.svc.rekey.mu.Unlock()
		if string(waiting.Bytes()) != "new" {
			t.Fatalf("the dialog waits with %q", waiting.Bytes())
		}
		h.answers <- answer
		f.rekeyDialogClosed(t)
		if !waiting.Destroyed() {
			t.Errorf("answer %q: the new password outlived the dialog", answer)
		}
		if locked := f.loginLocked(); locked != (answer == "") {
			t.Errorf("answer %q: locked %v", answer, locked)
		}
	}
}

func TestASecondWrongLoginPasswordReplacesTheOneTheDialogWaitsWith(t *testing.T) {
	f, id := loginWithItem(t)
	h := &heldPrompter{fakePrompter: f.prompter, shown: make(chan struct{}, 2), answers: make(chan string)}
	f.svc.cfg.Prompter = h
	_ = f.svc.UnlockLogin([]byte("first"))
	<-h.shown
	_ = f.svc.UnlockLogin([]byte("second"))
	h.answers <- "old"
	f.rekeyDialogClosed(t)
	if len(h.shown) != 0 {
		t.Error("a second wrong password showed a second dialog")
	}
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("second")); err != nil || f.loginSecret(t, id) != "s3cret" {
		t.Errorf("the newest login password after the re-key = %v", err)
	}
}

func TestRekeyLoginNeedsNoDialogAndIsSafeTwice(t *testing.T) {
	f, id := loginWithItem(t)
	if err := f.svc.RekeyLogin([]byte("typo"), []byte("new")); !errors.Is(err, control.ErrWrongPassword) {
		t.Errorf("a wrong old password = %v", err)
	}
	if !f.loginLocked() {
		t.Error("a wrong old password unlocked it")
	}
	for range 2 {
		if err := f.svc.RekeyLogin([]byte("old"), []byte("new")); err != nil {
			t.Fatalf("RekeyLogin = %v", err)
		}
	}
	if err := f.svc.RekeyLogin([]byte("new"), []byte("newer")); err != nil {
		t.Fatalf("RekeyLogin of an unlocked collection = %v", err)
	}
	if got := f.prompter.log(); len(got) != 0 {
		t.Errorf("RekeyLogin asked %v", got)
	}
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("newer")); err != nil || f.loginSecret(t, id) != "s3cret" {
		t.Errorf("the newest password = %v", err)
	}
}

func TestACrashDuringARekeyLeavesTheOldFileOrTheNew(t *testing.T) {
	f, id := loginWithItem(t)
	before := f.loginFile(t)
	f.svc.disk.write = func(path string, data []byte, perm os.FileMode) error {
		return atomicfile.Write(path, perm, func(w io.Writer) error {
			if _, err := w.Write(data[:len(data)/2]); err != nil {
				return err
			}
			return errors.New("the power went out")
		})
	}
	if err := f.svc.RekeyLogin([]byte("old"), []byte("new")); err == nil {
		t.Fatal("a re-key whose write failed succeeded")
	}
	if !bytes.Equal(f.loginFile(t), before) {
		t.Fatal("a failed re-key write changed the file")
	}
	f.svc.disk.write = atomicfile.WriteFile
	f.svc.Close()
	f.start(t)
	if err := f.svc.UnlockLogin([]byte("old")); err != nil || f.loginSecret(t, id) != "s3cret" {
		t.Fatalf("the old password after a failed re-key = %v", err)
	}
	if err := f.svc.RekeyLogin([]byte("old"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	after := f.loginFile(t)
	if err := opens(after, "new"); err != nil {
		t.Errorf("the re-keyed file does not open with the new password: %v", err)
	}
	if err := opens(after, "old"); !errors.Is(err, keyring.ErrWrongPassword) {
		t.Errorf("the re-keyed file with the old password = %v", err)
	}
	for _, torn := range [][]byte{after[:len(after)/2], before[:len(before)/2]} {
		if opens(torn, "new") == nil || opens(torn, "old") == nil {
			t.Error("a torn file opened")
		}
	}
}

// opens reports whether a collection file opens with password.
func opens(data []byte, password string) error {
	kr, err := keyring.Parse(data)
	if err != nil {
		return err
	}
	o, err := kr.BeginUnlock()
	if err != nil {
		return err
	}
	opened, err := o.Open([]byte(password), keyring.Argon2id)
	if err != nil {
		return err
	}
	opened.Discard()
	return nil
}

func TestTheRekeyDialogIsTakenDownWhenTheLoginPasswordOpensIt(t *testing.T) {
	f, _ := loginWithItem(t)
	h := &heldPrompter{fakePrompter: f.prompter, shown: make(chan struct{}, 1), answers: make(chan string)}
	f.svc.cfg.Prompter = h
	_ = f.svc.UnlockLogin([]byte("new"))
	<-h.shown
	f.svc.rekey.mu.Lock()
	waiting := f.svc.rekey.next
	f.svc.rekey.mu.Unlock()
	if err := f.svc.UnlockLogin([]byte("old")); err != nil {
		t.Fatal(err)
	}
	f.rekeyDialogClosed(t)
	if !waiting.Destroyed() {
		t.Error("the waiting password outlived the dialog")
	}
}
