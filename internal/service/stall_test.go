package service

import (
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/atomicfile"
	"github.com/stubbedev/lys-lib/dbustest"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"

	"github.com/stubbedev/lys-secrets/internal/keyring"
)

// gate is a slow step a test decides the end of: the KDF, or a disk's fsync.
type gate struct {
	entered chan struct{}
	release chan struct{}
}

func newGate() *gate {
	return &gate{entered: make(chan struct{}, 64), release: make(chan struct{})}
}

func (g *gate) pass() {
	g.entered <- struct{}{}
	<-g.release
}

func (g *gate) reached(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never started", what)
	}
}

func finished[T any](t *testing.T, what string, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		buf := make([]byte, 1<<16)
		t.Fatalf("%s did not finish while the slow step was pending:\n%s", what, buf[:runtime.Stack(buf, true)])
		panic("unreachable")
	}
}

type stallFixture struct {
	*fixture
	kdf          *gate
	underLock    atomic.Int32
	stretches    atomic.Int32
	blockStretch atomic.Bool
}

func newStallFixture(t *testing.T) *stallFixture {
	t.Helper()
	f := &stallFixture{fixture: &fixture{bus: dbustest.Session(t), dir: t.TempDir(), prompter: &fakePrompter{}}, kdf: newGate()}
	stretch := func(password, salt []byte, kdf keyring.KDF) []byte {
		f.stretches.Add(1)
		if f.svc != nil && !f.svc.mu.TryLock() {
			f.underLock.Add(1)
		} else if f.svc != nil {
			f.svc.mu.Unlock()
		}
		if f.blockStretch.Load() {
			f.kdf.pass()
		}
		return keyring.Argon2id(password, salt, kdf)
	}
	svc, err := Start(f.bus.Conn(t), Config{Dir: f.dir, KDF: testKDF, Stretch: stretch, Prompter: f.prompter})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	f.svc = svc
	return f
}

func (f *stallFixture) search(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_, _, _ = serviceMethods{f.svc}.SearchItems(map[string]string{"a": "b"})
		close(done)
	}()
	finished(t, "SearchItems", done)
}

func TestTheKDFRunsWithoutTheLock(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.LockCollections()
	f.stretches.Store(0)
	f.blockStretch.Store(true)
	unlocked := make(chan error, 1)
	go func() { unlocked <- f.svc.UnlockLogin([]byte("pw")) }()
	f.kdf.reached(t, "the unlock's KDF")
	f.search(t)
	close(f.kdf.release)
	if err := finished(t, "the unlock", unlocked); err != nil {
		t.Fatal(err)
	}
	if got := f.underLock.Load(); got != 0 {
		t.Errorf("%d KDF calls with the lock held", got)
	}
	if got := f.stretches.Load(); got != 1 {
		t.Errorf("%d KDF calls for one unlock", got)
	}
	f.svc.mu.Lock()
	locked := f.svc.colls[LoginID].kr.Locked()
	f.svc.mu.Unlock()
	if locked {
		t.Error("the collection stayed locked after a right password")
	}
}

func TestChangeLockAndFirstLoginRunTheKDFWithoutTheLock(t *testing.T) {
	f := newStallFixture(t)
	f.blockStretch.Store(true)
	first := make(chan error, 1)
	go func() { first <- f.svc.UnlockLogin([]byte("pw")) }()
	f.kdf.reached(t, "the first login's KDF")
	f.search(t)
	f.kdf.release <- struct{}{}
	if err := finished(t, "the first login", first); err != nil {
		t.Fatal(err)
	}
	f.prompter.script("new")
	path, derr := serviceMethods{f.svc}.ChangeLock(collectionPath(LoginID))
	if derr != nil {
		t.Fatal(derr)
	}
	conn := f.bus.Conn(t)
	if err := conn.Object(BusName, path).Call(ifacePrompt+".Prompt", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	f.kdf.reached(t, "the new password's KDF")
	f.search(t)
	close(f.kdf.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.svc.mu.Lock()
		pending := len(f.svc.prompts)
		f.svc.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the prompt did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	if got := f.underLock.Load(); got != 0 {
		t.Errorf("%d KDF calls with the lock held", got)
	}
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("new")); err != nil {
		t.Errorf("the new password after ChangeLock: %v", err)
	}
}

func TestAWrongPasswordDuringTheKDFLeavesItLockedAndSecretsSealed(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.LockCollections()
	if err := f.svc.UnlockLogin([]byte("wrong")); err == nil {
		t.Fatal("a wrong password unlocked")
	}
	f.svc.mu.Lock()
	locked := f.svc.colls[LoginID].kr.Locked()
	f.svc.mu.Unlock()
	if !locked {
		t.Error("a wrong password left it unlocked")
	}
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Errorf("the right password after a wrong one: %v", err)
	}
}

func TestAConcurrentUnlockPaysForOneKDF(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	f.svc.mu.Unlock()
	f.svc.LockCollections()
	f.stretches.Store(0)
	f.blockStretch.Store(true)
	results := make(chan error, 3)
	for range 3 {
		go func() { results <- f.svc.unlock(c, []byte("pw")) }()
	}
	f.kdf.reached(t, "the first unlock's KDF")
	f.search(t)
	close(f.kdf.release)
	for range 3 {
		if err := finished(t, "an unlock", results); err != nil {
			t.Error(err)
		}
	}
	if got := f.stretches.Load(); got != 1 {
		t.Errorf("%d KDF calls for three unlocks at once", got)
	}
}

// slowDisk replaces the service's writes with ones that wait for a gate.
func slowDisk(s *Service) (*gate, *atomic.Int32) {
	g := newGate()
	var writes atomic.Int32
	s.disk.write = func(path string, data []byte, perm os.FileMode) error {
		writes.Add(1)
		g.pass()
		return atomicfile.WriteFile(path, data, perm)
	}
	return g, &writes
}

func TestAReadCompletesWhileASaveIsPendingAndTheReplyWaitsForTheDisk(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	f.svc.mu.Unlock()
	disk, writes := slowDisk(f.svc)
	saved := make(chan error, 1)
	go func() {
		saved <- f.svc.change(c, func() error {
			_, _, err := c.kr.CreateItem("label", map[string]string{"a": "b"}, []byte("secret"), "text/plain", false, f.svc.now())
			return err
		}, nothingToAnnounce)
	}()
	disk.reached(t, "the save")
	f.search(t)
	select {
	case err := <-saved:
		t.Fatalf("the change returned %v before its data reached the disk", err)
	default:
	}
	data, err := os.ReadFile(f.svc.disk.path(LoginID))
	if err != nil {
		t.Fatal(err)
	}
	before, err := keyring.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(before.IDs()); got != 0 {
		t.Fatalf("%d items on disk before the write", got)
	}
	close(disk.release)
	if err := finished(t, "the save", saved); err != nil {
		t.Fatal(err)
	}
	if got := writes.Load(); got != 1 {
		t.Errorf("%d writes for one change", got)
	}
	data, err = os.ReadFile(f.svc.disk.path(LoginID))
	if err != nil {
		t.Fatal(err)
	}
	after, err := keyring.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(after.IDs()); got != 1 {
		t.Errorf("%d items on disk when the change returned, want the new one", got)
	}
	if strings.Contains(string(data), "secret") {
		t.Error("the secret reached the disk in the clear")
	}
}

func TestSavesReachTheDiskInOrderAndAnOlderOneNeverOverwritesANewer(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	f.svc.mu.Unlock()
	f.svc.mu.Lock()
	older, err := f.svc.sealLocked(c)
	if err != nil {
		f.svc.mu.Unlock()
		t.Fatal(err)
	}
	if _, _, err := c.kr.CreateItem("label", map[string]string{"a": "b"}, []byte("s"), "text/plain", false, f.svc.now()); err != nil {
		f.svc.mu.Unlock()
		t.Fatal(err)
	}
	newer, err := f.svc.sealLocked(c)
	f.svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := newer.write(); err != nil {
		t.Fatal(err)
	}
	if err := older.write(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.svc.disk.path(LoginID))
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := keyring.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(onDisk.IDs()); got != 1 {
		t.Errorf("%d items on disk: the older state overwrote the newer", got)
	}
}

func TestAnAliasSaveHoldsNoLock(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	disk, _ := slowDisk(f.svc)
	done := make(chan *dbus.Error, 1)
	go func() { done <- serviceMethods{f.svc}.SetAlias("other", collectionPath(LoginID)) }()
	disk.reached(t, "the alias save")
	f.search(t)
	close(disk.release)
	if err := finished(t, "the alias", done); err != nil {
		t.Fatal(err)
	}
	aliases, err := f.svc.disk.loadAliases()
	if err != nil {
		t.Fatal(err)
	}
	if aliases["other"] != LoginID {
		t.Errorf("aliases on disk: %v", aliases)
	}
}

func TestADeletedCollectionStaysDeletedPastASaveInFlight(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	save, err := f.svc.sealLocked(c)
	f.svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, derr := (collectionMethods{f.svc, LoginID}).Delete(); derr != nil {
		t.Fatal(derr)
	}
	if err := save.write(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.svc.disk.path(LoginID)); !os.IsNotExist(err) {
		t.Errorf("the file of a deleted collection: %v", err)
	}
}

func TestABlockedBusHoldsNoRead(t *testing.T) {
	f := newStallFixture(t)
	if err := f.svc.UnlockLogin([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	f.svc.mu.Lock()
	c := f.svc.colls[LoginID]
	f.svc.mu.Unlock()
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var mu sync.Mutex
	var sent []string
	queue := newSignalQueue(func(_ dbus.ObjectPath, name string, _ ...any) error {
		mu.Lock()
		sent = append(sent, name)
		mu.Unlock()
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	f.svc.mu.Lock()
	f.svc.signals = queue
	f.svc.mu.Unlock()
	for i, name := range []string{"first", "second", "third"} {
		err := f.svc.change(c, func() error {
			return c.kr.SetLabel(name, f.svc.now())
		}, func() error {
			f.svc.emitLocked(rootPath, name, i)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	finishedSearch := make(chan struct{})
	go func() {
		f.search(t)
		close(finishedSearch)
	}()
	finished(t, "the read during a blocked Emit", finishedSearch)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signal was never sent")
	}
	close(release)
	queue.drain(time.After(5 * time.Second))
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(sent, []string{"first", "second", "third"}) {
		t.Errorf("signals sent as %v, want them in order", sent)
	}
}

func TestSignalsPastTheBoundAreDroppedAndTheQueueIsBounded(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	queue := newSignalQueue(func(dbus.ObjectPath, string, ...any) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	queue.post(rootPath, "first")
	<-entered
	for range 4 * maxPendingSignals {
		queue.post(rootPath, "flood")
	}
	queue.mu.Lock()
	pending, dropped := len(queue.pending), queue.dropped
	queue.mu.Unlock()
	if pending != maxPendingSignals || dropped == 0 {
		t.Errorf("%d signals queued and %d dropped, want the bound of %d and the rest dropped", pending, dropped, maxPendingSignals)
	}
	close(release)
	queue.drain(time.After(5 * time.Second))
}

func TestAClosingServiceDoesNotWaitOnABlockedBus(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	queue := newSignalQueue(func(dbus.ObjectPath, string, ...any) error {
		<-release
		return nil
	})
	queue.post(rootPath, "stuck")
	timeout := make(chan time.Time)
	close(timeout)
	queue.drain(timeout)
}
