// Package sshagent is lys-secrets' SSH agent: it serves the agent protocol
// for the keys in ~/.ssh that have a .pub beside them and for those added
// with ssh-add. An encrypted key's passphrase is asked through the
// desktop's dialog on its first signature, and may be remembered in the
// login collection, so that signing needs no prompt while it is unlocked.
// Decrypted keys live in locked memory and are dropped when the login
// collection locks.
package sshagent

import (
	"bytes"
	"cmp"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/stubbedev/lys-secrets/internal/lockedmem"
	"github.com/stubbedev/lys-secrets/internal/usersock"
)

// Schema is the xdg:schema of a remembered passphrase's item in the login
// collection; its other attributes are the key's fingerprint and path.
const Schema = "dev.stubbe.lys.SshKey"

// askTimeout bounds how long a signature waits for the user at a dialog.
const askTimeout = 5 * time.Minute

// Key is a key as the dialogs name it.
type Key struct {
	// Path is the private key's file, "" for a key added with ssh-add.
	Path        string
	Fingerprint string
	Comment     string
}

// Prompter asks the user about keys.
type Prompter interface {
	// KeyPassphrase asks for an encrypted key's passphrase and whether to
	// remember it; ok is false when they dismissed the dialog. retry says
	// the previous attempt was wrong.
	KeyPassphrase(ctx context.Context, k Key, retry bool) (passphrase []byte, remember, ok bool, err error)
	// ConfirmUse asks whether a key added with ssh-add -c may sign.
	ConfirmUse(ctx context.Context, k Key) (bool, error)
}

// Passphrases keeps remembered passphrases in the login collection. A locked
// login collection is an error.
type Passphrases interface {
	Lookup(attrs map[string]string) (passphrase []byte, found bool, err error)
	Remember(label string, attrs map[string]string, passphrase []byte) error
}

// Agent is the agent's keys.
type Agent struct {
	dir         string
	prompter    Prompter
	passphrases Passphrases

	mu    sync.Mutex
	added []*addedKey
	// held are the decrypted keys of ~/.ssh, by path.
	held map[string]*privateKey
	// unlocking keeps two signatures from asking for one key's passphrase
	// at once, by path.
	unlocking map[string]*sync.Mutex
	// lock is the passphrase ssh-add -x locked the agent with, nil while
	// unlocked.
	lock *lockedmem.Buf
}

type addedKey struct {
	public  ssh.PublicKey
	key     *privateKey
	comment string
	confirm bool
	expiry  *time.Timer
}

// New is an agent for the keys in dir (~/.ssh), asking prompter and
// remembering passphrases in passphrases.
func New(dir string, prompter Prompter, passphrases Passphrases) *Agent {
	return &Agent{dir: dir, prompter: prompter, passphrases: passphrases, held: map[string]*privateKey{}, unlocking: map[string]*sync.Mutex{}}
}

// Serve answers agent requests on ln until ctx ends.
func (a *Agent) Serve(ctx context.Context, ln *usersock.Listener) {
	ln.Serve(ctx, "ssh-agent", func(conn *net.UnixConn) {
		if err := agent.ServeAgent(a, conn); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			log.Printf("ssh-agent: %v", err)
		}
	})
}

// Forget drops every decrypted key of ~/.ssh, as the login collection
// locking does; the next signature asks again or reads the remembered
// passphrase.
func (a *Agent) Forget() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for path, k := range a.held {
		k.destroy()
		delete(a.held, path)
	}
}

// Close drops every key.
func (a *Agent) Close() {
	a.Forget()
	_ = a.RemoveAll()
}

// fileKey is a key of ~/.ssh: a private key with its .pub beside it.
type fileKey struct {
	path    string
	public  ssh.PublicKey
	comment string
}

// fileKeys are the keys of ~/.ssh, by name.
func (a *Agent) fileKeys() ([]fileKey, error) {
	entries, err := os.ReadDir(a.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", a.dir, err)
	}
	var out []fileKey
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "id_") || strings.HasSuffix(name, ".pub") || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(a.dir, name)
		data, err := os.ReadFile(path + ".pub") //nolint:gosec // a file the agent listed in ~/.ssh
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s.pub: %w", path, err)
		}
		public, comment, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			log.Printf("ssh-agent: %s.pub is not a public key: %v", path, err)
			continue
		}
		out = append(out, fileKey{path: path, public: public, comment: comment})
	}
	return out, nil
}

// List is the keys of ~/.ssh, then those added with ssh-add; none while the
// agent is locked.
func (a *Agent) List() ([]*agent.Key, error) {
	files, err := a.fileKeys()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lock != nil {
		return []*agent.Key{}, nil
	}
	out := make([]*agent.Key, 0, len(files)+len(a.added))
	for _, f := range files {
		out = append(out, &agent.Key{Format: f.public.Type(), Blob: f.public.Marshal(), Comment: cmp.Or(f.comment, f.path)})
	}
	for _, k := range a.added {
		out = append(out, &agent.Key{Format: k.public.Type(), Blob: k.public.Marshal(), Comment: k.comment})
	}
	return out, nil
}

// Sign signs data with key.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with key, an RSA key with the SHA-2 algorithm
// flags ask for.
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	algorithm := ""
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algorithm = ssh.KeyAlgoRSASHA512
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algorithm = ssh.KeyAlgoRSASHA256
	}
	want := key.Marshal()
	a.mu.Lock()
	if a.lock != nil {
		a.mu.Unlock()
		return nil, errors.New("the agent is locked")
	}
	for _, k := range a.added {
		if !bytes.Equal(k.public.Marshal(), want) {
			continue
		}
		confirm, info := k.confirm, Key{Fingerprint: ssh.FingerprintSHA256(k.public), Comment: k.comment}
		a.mu.Unlock()
		if confirm && !a.confirmUse(info) {
			return nil, errors.New("the user refused the key's use")
		}
		return a.signAdded(want, data, algorithm)
	}
	a.mu.Unlock()
	files, err := a.fileKeys()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if bytes.Equal(f.public.Marshal(), want) {
			return a.signFile(f, data, algorithm)
		}
	}
	return nil, errors.New("no such key")
}

func (a *Agent) confirmUse(k Key) bool {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	ok, err := a.prompter.ConfirmUse(ctx, k)
	if err != nil {
		log.Printf("ssh-agent: confirm the use of %s: %v", k.Fingerprint, err)
	}
	return ok
}

func (a *Agent) signAdded(want, data []byte, algorithm string) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range a.added {
		if bytes.Equal(k.public.Marshal(), want) {
			return k.key.sign(data, algorithm)
		}
	}
	return nil, errors.New("the key was removed")
}

// signFile signs with a key of ~/.ssh, decrypting it first unless it is
// held already.
func (a *Agent) signFile(f fileKey, data []byte, algorithm string) (*ssh.Signature, error) {
	a.mu.Lock()
	gate, ok := a.unlocking[f.path]
	if !ok {
		gate = &sync.Mutex{}
		a.unlocking[f.path] = gate
	}
	a.mu.Unlock()
	gate.Lock()
	defer gate.Unlock()
	if sig, ok, err := a.signHeld(f.path, data, algorithm); ok {
		return sig, err
	}
	k, err := a.decrypt(f)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.held[f.path].destroy()
	a.held[f.path] = k
	return k.sign(data, algorithm)
}

func (a *Agent) signHeld(path string, data []byte, algorithm string) (*ssh.Signature, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k, ok := a.held[path]
	if !ok {
		return nil, false, nil
	}
	sig, err := k.sign(data, algorithm)
	return sig, true, err
}

// decrypt reads a key of ~/.ssh: as it stands when it is not encrypted,
// else with its remembered passphrase, else with one the user types.
func (a *Agent) decrypt(f fileKey) (*privateKey, error) {
	pem, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.path, err)
	}
	defer clear(pem)
	raw, err := ssh.ParseRawPrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return lockKey(raw)
	case !errors.As(err, &missing):
		return nil, fmt.Errorf("read %s: %w", f.path, err)
	}
	info := Key{Path: f.path, Fingerprint: ssh.FingerprintSHA256(f.public), Comment: f.comment}
	attrs := map[string]string{"xdg:schema": Schema, "fingerprint": info.Fingerprint, "path": f.path}
	remembered, found, err := a.passphrases.Lookup(attrs)
	switch {
	case err != nil:
		log.Printf("ssh-agent: look up the remembered passphrase of %s: %v", f.path, err)
	case found:
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(pem, remembered)
		clear(remembered)
		if err == nil {
			return lockKey(raw)
		}
		log.Printf("ssh-agent: the remembered passphrase of %s does not open it: %v", f.path, err)
	}
	return a.ask(pem, info, attrs)
}

// ask asks for a key's passphrase until it opens the key, remembering it
// when the user says so.
func (a *Agent) ask(pem []byte, info Key, attrs map[string]string) (*privateKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	retry := false
	for {
		passphrase, remember, ok, err := a.prompter.KeyPassphrase(ctx, info, retry)
		if err != nil {
			return nil, fmt.Errorf("ask for the passphrase of %s: %w", info.Path, err)
		}
		if !ok {
			return nil, fmt.Errorf("the passphrase of %s was not given", info.Path)
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(pem, passphrase)
		if errors.Is(err, x509.IncorrectPasswordError) {
			clear(passphrase)
			retry = true
			continue
		}
		if err != nil {
			clear(passphrase)
			return nil, fmt.Errorf("read %s: %w", info.Path, err)
		}
		if remember {
			if err := a.passphrases.Remember("SSH key "+cmp.Or(info.Comment, info.Path), attrs, passphrase); err != nil {
				log.Printf("ssh-agent: remember the passphrase of %s: %v", info.Path, err)
			}
		}
		clear(passphrase)
		return lockKey(raw)
	}
}

// Add holds a key ssh-add sent, in memory only.
func (a *Agent) Add(key agent.AddedKey) error {
	if len(key.ConstraintExtensions) > 0 {
		return fmt.Errorf("constraint %s is not supported", key.ConstraintExtensions[0].ExtensionName)
	}
	public, err := publicOf(key)
	if err != nil {
		return err
	}
	k, err := lockKey(key.PrivateKey)
	if err != nil {
		return err
	}
	added := &addedKey{public: public, key: k, comment: key.Comment, confirm: key.ConfirmBeforeUse}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lock != nil {
		k.destroy()
		return errors.New("the agent is locked")
	}
	a.removeLocked(public.Marshal())
	if key.LifetimeSecs > 0 {
		added.expiry = time.AfterFunc(time.Duration(key.LifetimeSecs)*time.Second, func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.dropLocked(added)
		})
	}
	a.added = append(a.added, added)
	return nil
}

func publicOf(key agent.AddedKey) (ssh.PublicKey, error) {
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("the key's public half: %w", err)
	}
	if key.Certificate == nil {
		return signer.PublicKey(), nil
	}
	if !bytes.Equal(key.Certificate.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errors.New("the certificate is not the key's")
	}
	return key.Certificate, nil
}

// Remove drops an added key; a key of ~/.ssh stays listed, its decrypted
// copy dropped.
func (a *Agent) Remove(key ssh.PublicKey) error {
	want := key.Marshal()
	files, err := a.fileKeys()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lock != nil {
		return errors.New("the agent is locked")
	}
	found := a.removeLocked(want)
	for _, f := range files {
		if bytes.Equal(f.public.Marshal(), want) {
			a.held[f.path].destroy()
			delete(a.held, f.path)
			found = true
		}
	}
	if !found {
		return errors.New("no such key")
	}
	return nil
}

func (a *Agent) removeLocked(want []byte) bool {
	found := false
	for _, k := range slices.Clone(a.added) {
		if bytes.Equal(k.public.Marshal(), want) {
			a.dropLocked(k)
			found = true
		}
	}
	return found
}

func (a *Agent) dropLocked(k *addedKey) {
	i := slices.Index(a.added, k)
	if i < 0 {
		return
	}
	a.added = slices.Delete(a.added, i, i+1)
	if k.expiry != nil {
		k.expiry.Stop()
	}
	k.key.destroy()
}

// RemoveAll drops every added key and every decrypted key of ~/.ssh.
func (a *Agent) RemoveAll() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range slices.Clone(a.added) {
		a.dropLocked(k)
	}
	for path, k := range a.held {
		k.destroy()
		delete(a.held, path)
	}
	return nil
}

// Lock locks the agent with passphrase, as ssh-add -x does.
func (a *Agent) Lock(passphrase []byte) error {
	mem, err := lockedmem.Copy(passphrase)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lock != nil {
		mem.Destroy()
		return errors.New("the agent is locked already")
	}
	a.lock = mem
	return nil
}

// Unlock undoes Lock given the same passphrase.
func (a *Agent) Unlock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lock == nil {
		return errors.New("the agent is not locked")
	}
	if subtle.ConstantTimeCompare(a.lock.Bytes(), passphrase) != 1 {
		return errors.New("wrong passphrase")
	}
	a.lock.Destroy()
	a.lock = nil
	return nil
}

// Signers is not offered: the agent signs only over its socket.
func (a *Agent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("the agent hands out no signers")
}

// Extension answers no extension.
func (a *Agent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
