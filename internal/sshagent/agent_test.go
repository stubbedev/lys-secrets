package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	"github.com/stubbedev/lys-lib/sockdir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/stubbedev/lys-secrets/internal/keyring"
	"github.com/stubbedev/lys-secrets/internal/service"
	"github.com/stubbedev/lys-secrets/internal/usersock"
)

// fakePrompter answers passphrase dialogs with passphrase, remembering it
// when remember is set, and confirms uses with confirm.
type fakePrompter struct {
	mu         sync.Mutex
	passphrase string
	remember   bool
	confirm    bool
	asked      []string
}

func (f *fakePrompter) KeyPassphrase(_ context.Context, k Key, retry bool) ([]byte, bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, fmt.Sprintf("passphrase %s retry=%v", filepath.Base(k.Path), retry))
	if f.passphrase == "" {
		return nil, false, false, nil
	}
	return []byte(f.passphrase), f.remember, true, nil
}

func (f *fakePrompter) ConfirmUse(_ context.Context, k Key) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "use "+k.Comment)
	return f.confirm, nil
}

func (f *fakePrompter) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// countingPassphrases counts the lookups of the passphrases it wraps.
type countingPassphrases struct {
	Passphrases
	lookups atomic.Int32
}

func (c *countingPassphrases) Lookup(attrs map[string]string) ([]byte, bool, error) {
	c.lookups.Add(1)
	return c.Passphrases.Lookup(attrs)
}

type noPassphrases struct{}

func (noPassphrases) Lookup(map[string]string) ([]byte, bool, error) {
	return nil, false, errors.New("no login collection")
}

func (noPassphrases) Remember(string, map[string]string, []byte) error {
	return errors.New("no login collection")
}

// writeKey writes a new Ed25519 key as dir/id_ed25519 and its .pub, under
// passphrase unless that is "".
func writeKey(t *testing.T, dir, passphrase string) (ssh.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test@key")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test@key", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)), " test@key\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	return public, path
}

func serve(t *testing.T, a *Agent) string {
	t.Helper()
	path := filepath.Join(sockdir.Dir(t), "ssh")
	ln, err := usersock.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done; a.Close() })
	return path
}

func requireTool(t *testing.T, bin string) string {
	t.Helper()
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("%s is not installed (the nix dev shell carries it)", bin)
	}
	return path
}

func runTool(t *testing.T, env []string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sshd is a test SSH server on loopback that lets in only allowed, and runs
// every command as a success.
func sshd(t *testing.T, allowed ssh.PublicKey) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("not this key")
	}}
	config.AddHostKey(host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(c, config)
		}
	}()
	return ln.Addr().String()
}

func serveSSH(c net.Conn, config *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range requests {
				_ = r.Reply(r.Type == "exec", nil)
				if r.Type == "exec" {
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					_ = ch.Close()
				}
			}
		}()
	}
}

func TestSshAddListsAKeyOfDotSSHAndSshLogsInWithIt(t *testing.T) {
	sshAdd, sshBin := requireTool(t, "ssh-add"), requireTool(t, "ssh")
	home := t.TempDir()
	public, _ := writeKey(t, filepath.Join(home, ".ssh"), "")
	a := New(filepath.Join(home, ".ssh"), &fakePrompter{}, noPassphrases{})
	sock := serve(t, a)
	env := []string{"SSH_AUTH_SOCK=" + sock, "HOME=" + home}
	out, err := runTool(t, env, sshAdd, "-l")
	if err != nil || !strings.Contains(out, ssh.FingerprintSHA256(public)) || !strings.Contains(out, "test@key") {
		t.Fatalf("ssh-add -l = %q, %v", out, err)
	}
	addr := sshd(t, public)
	host, port, _ := net.SplitHostPort(addr)
	out, err = runTool(t, env, sshBin, "-F", "/dev/null", "-o", "IdentityAgent="+sock, "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "PasswordAuthentication=no",
		"-p", port, "tester@"+host, "true")
	if err != nil {
		t.Fatalf("ssh through the agent: %v\n%s", err, out)
	}
}

// loginService is a Secret Service on a test bus whose login collection opens
// with "pw", locking the agent's keys with it.
func loginService(t *testing.T, bus *dbustest.Bus, dir string, a *atomic.Pointer[Agent]) *service.Service {
	t.Helper()
	svc, err := service.Start(bus.Conn(t), service.Config{
		Dir: dir, KDF: keyring.KDF{Time: 1, MemKiB: 64, Threads: 1}, Stretch: keyring.Argon2id, Prompter: nil,
		Locked: func(id string) {
			if agent := a.Load(); agent != nil && id == service.LoginID {
				agent.Forget()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	if err := svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	return svc
}

type servicePassphrases struct{ svc *service.Service }

func (p servicePassphrases) Lookup(attrs map[string]string) ([]byte, bool, error) {
	return p.svc.LoginSecret(attrs)
}

func (p servicePassphrases) Remember(label string, attrs map[string]string, passphrase []byte) error {
	return p.svc.StoreLoginSecret(label, attrs, passphrase)
}

func TestAnEncryptedKeyAsksOnceAndIsRememberedInTheLoginCollection(t *testing.T) {
	bus, dir, home := dbustest.Session(t), t.TempDir(), t.TempDir()
	public, path := writeKey(t, filepath.Join(home, ".ssh"), "open sesame")
	var current atomic.Pointer[Agent]
	svc := loginService(t, bus, dir, &current)
	prompter := &fakePrompter{passphrase: "open sesame", remember: true}
	a := New(filepath.Join(home, ".ssh"), prompter, servicePassphrases{svc})
	current.Store(a)
	for range 2 {
		sig, err := a.Sign(public, []byte("data"))
		if err != nil {
			t.Fatal(err)
		}
		if err := public.Verify([]byte("data"), sig); err != nil {
			t.Fatalf("the signature does not verify: %v", err)
		}
	}
	if got := prompter.log(); len(got) != 1 || got[0] != "passphrase id_ed25519 retry=false" {
		t.Fatalf("two signatures asked %v, want one passphrase", got)
	}
	attrs := map[string]string{"xdg:schema": Schema, "fingerprint": ssh.FingerprintSHA256(public), "path": path}
	if got, found, err := svc.LoginSecret(attrs); err != nil || !found || string(got) != "open sesame" {
		t.Fatalf("the remembered passphrase = %q, %v, %v", got, found, err)
	}

	svc.Close()
	current.Store(nil)
	a.Close()
	svc = loginService(t, bus, dir, &current)
	counting := &countingPassphrases{Passphrases: servicePassphrases{svc}}
	prompter = &fakePrompter{}
	a = New(filepath.Join(home, ".ssh"), prompter, counting)
	current.Store(a)
	if _, err := a.Sign(public, []byte("data")); err != nil {
		t.Fatalf("after a restart and a login unlock: %v", err)
	}
	if got := prompter.log(); len(got) != 0 || counting.lookups.Load() != 1 {
		t.Fatalf("after a restart the signature asked %v after %d lookups", got, counting.lookups.Load())
	}
	a.mu.Lock()
	held := a.held[path]
	a.mu.Unlock()

	svc.LockCollections()
	if !held.mem.Destroyed() {
		t.Error("locking the login collection left the decrypted key")
	}
	if err := svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(public, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if got := counting.lookups.Load(); got != 2 || len(prompter.log()) != 0 {
		t.Errorf("after the lock the signature made %d lookups and asked %v, want it to re-read the passphrase", got, prompter.log())
	}
}

func TestAWrongPassphraseAsksAgainAndALockedLoginStillAsks(t *testing.T) {
	home := t.TempDir()
	public, _ := writeKey(t, filepath.Join(home, ".ssh"), "right")
	prompts := []string{"wrong", "right"}
	prompter := &scriptedPrompter{answers: prompts}
	a := New(filepath.Join(home, ".ssh"), prompter, noPassphrases{})
	defer a.Close()
	if _, err := a.Sign(public, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := prompter.retries; len(got) != 2 || got[0] || !got[1] {
		t.Errorf("retries %v, want the second dialog to say the first was wrong", got)
	}
	a.Forget()
	if _, err := a.Sign(public, []byte("x")); err == nil {
		t.Error("a dismissed dialog signed")
	}
}

type scriptedPrompter struct {
	answers []string
	retries []bool
}

func (s *scriptedPrompter) KeyPassphrase(_ context.Context, _ Key, retry bool) ([]byte, bool, bool, error) {
	s.retries = append(s.retries, retry)
	if len(s.answers) == 0 {
		return nil, false, false, nil
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return []byte(a), false, true, nil
}

func (s *scriptedPrompter) ConfirmUse(context.Context, Key) (bool, error) { return false, nil }

func TestADecryptedKeyLivesOffTheHeap(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := priv.Public().(ed25519.PublicKey)
	parsed := ed25519.PrivateKey(bytes.Clone(priv))
	k, err := lockKey(&parsed)
	if err != nil {
		t.Fatal(err)
	}
	defer k.destroy()
	if !bytes.Equal(parsed, make([]byte, len(parsed))) {
		t.Error("the parsed key was left on the heap")
	}
	if !k.ed25519 || !k.mem.Holds(k.mem.Bytes()) || !bytes.Equal(k.mem.Bytes(), priv) {
		t.Fatal("the key is not in locked memory")
	}
	sig, err := k.sign([]byte("data"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, []byte("data"), sig.Blob) {
		t.Error("the signature from locked memory does not verify")
	}
	message := bytes.Repeat([]byte("m"), 200)
	if got, want := mustSignEd25519(t, k.mem.Bytes(), message), ed25519.Sign(priv, message); !bytes.Equal(got, want) {
		t.Errorf("the signature differs from crypto/ed25519's:\n%x\n%x", got, want)
	}
	allocs := testing.AllocsPerRun(20, func() { _, _ = signEd25519(k.mem.Bytes(), message) })
	if allocs > 2 {
		t.Errorf("a signature allocates %v times on the heap, want only the signature and its challenge hash", allocs)
	}
	k.destroy()
	if _, err := k.sign([]byte("data"), ""); err == nil {
		t.Error("a destroyed key signed")
	}
}

func mustSignEd25519(t *testing.T, key, message []byte) []byte {
	t.Helper()
	sig, err := signEd25519(key, message)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestAddedKeysConfirmExpireAndLock(t *testing.T) {
	prompter := &fakePrompter{}
	a := New(t.TempDir(), prompter, noPassphrases{})
	conn, err := net.Dial("unix", serve(t, a))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := agent.NewClient(conn)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.Add(agent.AddedKey{PrivateKey: priv, Comment: "added", ConfirmBeforeUse: true}); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	if _, err := c.Sign(signer.PublicKey(), []byte("x")); err == nil {
		t.Error("a refused use signed")
	}
	prompter.mu.Lock()
	prompter.confirm = true
	prompter.mu.Unlock()
	if _, err := c.Sign(signer.PublicKey(), []byte("x")); err != nil {
		t.Errorf("a confirmed use: %v", err)
	}
	if got := prompter.log(); len(got) != 2 || got[0] != "use added" {
		t.Errorf("asked %v", got)
	}

	if err := c.Lock([]byte("pass")); err != nil {
		t.Fatal(err)
	}
	if keys, err := c.List(); err != nil || len(keys) != 0 {
		t.Errorf("a locked agent lists %v, %v", keys, err)
	}
	if err := c.Unlock([]byte("nope")); err == nil {
		t.Error("a wrong passphrase unlocked the agent")
	}
	if err := c.Unlock([]byte("pass")); err != nil {
		t.Fatal(err)
	}
	if keys, err := c.List(); err != nil || len(keys) != 1 {
		t.Errorf("an unlocked agent lists %v, %v", keys, err)
	}

	if err := c.Add(agent.AddedKey{PrivateKey: priv, Comment: "brief", LifetimeSecs: 1}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		keys, err := c.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a key with a one-second lifetime is still listed: %v", keys)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := c.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if keys, _ := c.List(); len(keys) != 0 {
		t.Errorf("RemoveAll left %v", keys)
	}
}
