package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
	"golang.org/x/sys/unix"

	"github.com/stubbedev/lys-secrets/internal/keyring"
)

// credentialsTimeout bounds asking the bus who a client is.
const credentialsTimeout = 5 * time.Second

// Access is the user's answer to a program reading an item it does not own.
type Access int

// The answers to ConfirmRead.
const (
	Denied Access = iota
	AllowedOnce
	AllowedAlways
)

// ReadRequest is what ConfirmRead shows: the program asking, the item and
// who owns it.
type ReadRequest struct {
	// Program is who asks, "" for a program that could not be identified,
	// which can only be allowed once.
	Program keyring.Owner
	PID     uint32
	// Item and Collection are the item's and its collection's labels.
	Item, Collection string
	Owners           []keyring.Owner
}

// client is who a bus connection is: the program it runs, "" when that
// could not be told, and its process.
type peer struct {
	program keyring.Owner
	pid     uint32
}

// itemRef names one item of one collection.
type itemRef struct {
	collection string
	id         uint32
}

// clients identifies bus connections by the program behind them, once per
// connection: a unique name is never reused on a bus.
type peers struct {
	credentials func(ctx context.Context, sender string) (map[string]dbus.Variant, error)

	mu    sync.Mutex
	known map[string]peer
}

func newPeers(conn *dbus.Conn) *peers {
	return &peers{
		known: map[string]peer{},
		credentials: func(ctx context.Context, sender string) (map[string]dbus.Variant, error) {
			var creds map[string]dbus.Variant
			err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionCredentials", 0, sender).Store(&creds)
			return creds, err
		},
	}
}

// identify is who sender is. A sender whose process cannot be named is a
// client with no program, logged once.
func (c *peers) identify(sender string) peer {
	c.mu.Lock()
	cl, ok := c.known[sender]
	c.mu.Unlock()
	if ok {
		return cl
	}
	cl, err := c.lookUp(sender)
	if err != nil {
		log.Printf("secrets: identify the program behind %s: %v", sender, err)
	}
	c.mu.Lock()
	c.known[sender] = cl
	c.mu.Unlock()
	return cl
}

func (c *peers) forget(sender string) {
	c.mu.Lock()
	delete(c.known, sender)
	c.mu.Unlock()
}

func (c *peers) lookUp(sender string) (peer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), credentialsTimeout)
	defer cancel()
	creds, err := c.credentials(ctx, sender)
	if err != nil {
		return peer{}, fmt.Errorf("ask the bus for its credentials: %w", err)
	}
	pid, ok := creds["ProcessID"].Value().(uint32)
	if !ok {
		return peer{}, errors.New("the bus names no process")
	}
	pidfd := -1
	if fd, ok := creds["ProcessFD"].Value().(dbus.UnixFD); ok {
		pidfd = int(fd)
		defer func() { _ = unix.Close(pidfd) }()
	}
	program, err := programOf(pid)
	if err != nil {
		return peer{pid: pid}, err
	}
	if pidfd >= 0 {
		if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
			return peer{pid: pid}, fmt.Errorf("process %d ended while it was named, so its pid may name another: %w", pid, err)
		}
	}
	return peer{program: program, pid: pid}, nil
}

// programOf is the program process pid runs: a Flatpak app by its app id,
// anything else by its executable.
func programOf(pid uint32) (keyring.Owner, error) {
	proc := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
	info, err := os.ReadFile(filepath.Join(proc, "root", ".flatpak-info")) //nolint:gosec // a path under /proc built from a pid
	switch {
	case err == nil:
		app, err := flatpakApp(info)
		if err != nil {
			return "", fmt.Errorf("process %d: %w", pid, err)
		}
		return keyring.Owner("flatpak:" + app), nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("process %d: %w", pid, err)
	}
	exe, err := os.Readlink(filepath.Join(proc, "exe"))
	if err != nil {
		return "", fmt.Errorf("process %d: %w", pid, err)
	}
	return keyring.Owner(exe), nil
}

// flatpakApp is the app id a .flatpak-info names in its [Application]
// group.
func flatpakApp(info []byte) (string, error) {
	group := ""
	sc := bufio.NewScanner(bytes.NewReader(info))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			group = line[1 : len(line)-1]
			continue
		}
		if name, ok := strings.CutPrefix(line, "name="); ok && group == "Application" && name != "" {
			return name, nil
		}
	}
	return "", errors.New(".flatpak-info names no application")
}

// reader is who sender is when reads are confirmed; otherwise it asks the
// bus nothing and is false.
func (s *Service) reader(sender dbus.Sender) (peer, bool) {
	if !s.cfg.ConfirmForeignReads {
		return peer{}, false
	}
	return s.peers.identify(string(sender)), true
}

// mayReadLocked reports whether cl may read item id of the unlocked c
// without asking: it owns the item, the user allowed this connection, or
// nobody owns it yet.
func (s *Service) mayReadLocked(sender dbus.Sender, cl peer, c *collection, id uint32) bool {
	it, err := c.kr.Item(id)
	if err != nil {
		return false
	}
	if len(it.Owners) == 0 || cl.program != "" && it.Owned(cl.program) {
		return true
	}
	_, granted := s.grants[string(sender)][itemRef{c.id, id}]
	return granted
}

// claimsLocked are the items among read that nobody owned, which cl now owns
// as their first reader.
func (s *Service) claimsLocked(cl peer, read []itemRef) []itemRef {
	if cl.program == "" {
		return nil
	}
	var out []itemRef
	for _, ref := range read {
		if it, err := s.colls[ref.collection].kr.Item(ref.id); err == nil && len(it.Owners) == 0 {
			out = append(out, ref)
		}
	}
	return out
}

// claim makes cl the owner of each of refs, as its first reader.
func (s *Service) claim(cl peer, refs []itemRef) {
	for _, ref := range refs {
		if err := s.addOwner(ref, cl.program); err != nil {
			log.Printf("secrets: make %s the owner of item %s/%d: %v", cl.program, ref.collection, ref.id, err)
			continue
		}
		log.Printf("secrets: item %s/%d had no owner, so %s, its first reader, owns it now", ref.collection, ref.id, cl.program)
	}
}

func (s *Service) addOwner(ref itemRef, owner keyring.Owner) error {
	s.mu.Lock()
	c, ok := s.colls[ref.collection]
	s.mu.Unlock()
	if !ok {
		return errGone
	}
	return s.change(c, func(kr *keyring.Collection) error { return kr.AddOwner(ref.id, owner) }, nothingToAnnounce)
}

// confirmRead asks the user whether cl, behind sender, may read ref, and
// remembers a yes: for the connection, or as an owner of the item.
func (s *Service) confirmRead(ctx context.Context, sender dbus.Sender, cl peer, ref itemRef) bool {
	s.mu.Lock()
	c, ok := s.colls[ref.collection]
	if !ok || c.kr.Locked() {
		s.mu.Unlock()
		return false
	}
	if s.mayReadLocked(sender, cl, c, ref.id) {
		s.mu.Unlock()
		return true
	}
	it, _ := c.kr.Item(ref.id)
	req := ReadRequest{Program: cl.program, PID: cl.pid, Item: it.Label, Collection: c.kr.Label(), Owners: it.Owners}
	s.mu.Unlock()
	answer, err := s.cfg.Prompter.ConfirmRead(ctx, req)
	if err != nil {
		logPromptErr("confirm a read of "+string(itemPath(ref.collection, ref.id)), err)
		return false
	}
	switch {
	case answer == AllowedAlways && cl.program != "":
		if err := s.addOwner(ref, cl.program); err != nil {
			log.Printf("secrets: always allow %s to read item %s/%d: %v", cl.program, ref.collection, ref.id, err)
			return false
		}
		return true
	case answer == AllowedOnce || answer == AllowedAlways:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.grants[string(sender)] == nil {
			s.grants[string(sender)] = map[itemRef]struct{}{}
		}
		s.grants[string(sender)][ref] = struct{}{}
		return true
	}
	return false
}

// dropGrantsLocked forgets every read the user allowed once of collection id.
func (s *Service) dropGrantsLocked(id string) {
	for sender, refs := range s.grants {
		for ref := range refs {
			if ref.collection == id {
				delete(refs, ref)
			}
		}
		if len(refs) == 0 {
			delete(s.grants, sender)
		}
	}
}
