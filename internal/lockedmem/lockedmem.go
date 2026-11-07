// Package lockedmem holds secrets outside the Go heap: each Buf is an
// anonymous mapping of its own, so the collector never copies it, locked
// against swap where RLIMIT_MEMLOCK allows, excluded from core dumps, and
// zeroed before it is unmapped.
package lockedmem

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// Buf is n bytes of locked memory. The zero Buf, and a destroyed one, hold
// nothing.
type Buf struct {
	page []byte
	n    int
}

// swapGuard locks pages against swap and says once when it cannot: every
// page after the first fails for the same reason.
type swapGuard struct {
	mlock  func([]byte) error
	limit  func() (uint64, error)
	logf   func(format string, args ...any)
	warned sync.Once
}

var (
	pages = swapGuard{mlock: unix.Mlock, limit: memlockLimit, logf: log.Printf}
	unmap = unix.Munmap
)

func memlockLimit() (uint64, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return 0, fmt.Errorf("read RLIMIT_MEMLOCK: %w", err)
	}
	return lim.Cur, nil
}

func (g *swapGuard) pin(page []byte) {
	err := g.mlock(page)
	if err == nil {
		return
	}
	g.warned.Do(func() {
		limit := "unknown"
		if n, limErr := g.limit(); limErr == nil {
			limit = strconv.FormatUint(n, 10) + " bytes"
		}
		g.logf("lockedmem: secrets may reach swap: mlock of a %d-byte page failed: %v (RLIMIT_MEMLOCK %s; raise LimitMEMLOCK= for the unit, or use encrypted or no swap)", len(page), err, limit)
	})
}

// New maps n zeroed bytes of locked memory.
func New(n int) (*Buf, error) {
	if n <= 0 {
		return nil, fmt.Errorf("lockedmem: a buffer of %d bytes", n)
	}
	size := (n + os.Getpagesize() - 1) / os.Getpagesize() * os.Getpagesize()
	page, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("lockedmem: map %d bytes: %w", size, err)
	}
	pages.pin(page)
	_ = unix.Madvise(page, unix.MADV_DONTDUMP)
	return &Buf{page: page, n: n}, nil
}

// Copy is a new Buf holding a copy of src.
func Copy(src []byte) (*Buf, error) {
	b, err := New(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.Bytes(), src)
	return b, nil
}

// Bytes is the buffer's memory, nil once destroyed. It must not be kept
// past Destroy.
func (b *Buf) Bytes() []byte {
	if b == nil || b.page == nil {
		return nil
	}
	return b.page[:b.n:b.n]
}

// Destroyed reports whether the buffer holds nothing any more.
func (b *Buf) Destroyed() bool { return b == nil || b.page == nil }

// Destroy zeroes and unmaps the buffer. It is safe to call more than once.
func (b *Buf) Destroy() {
	if b == nil || b.page == nil {
		return
	}
	clear(b.page)
	_ = unix.Munlock(b.page)
	_ = unmap(b.page)
	b.page = nil
	b.n = 0
}
