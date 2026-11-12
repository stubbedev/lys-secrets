package service

import (
	"log"
	"sync"
	"time"

	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

const (
	// maxPendingSignals bounds what waits for a bus that stopped taking anything.
	maxPendingSignals = 1024
	signalDrainWait   = 2 * time.Second
)

// signalQueue sends signals in the order they were raised on one goroutine,
// because a write to a stalled bus blocks, and it must not do so with the service's
// lock held. Past its bound it drops signals and says so: they say something
// changed, and whoever missed one can read the state again.
type signalQueue struct {
	mu      sync.Mutex
	pending []func() error
	dropped int
	closed  bool

	wake chan struct{}
	done chan struct{}
}

func newSignalQueue() *signalQueue {
	q := &signalQueue{wake: make(chan struct{}, 1), done: make(chan struct{})}
	go q.run()
	return q
}

func (q *signalQueue) post(emit func() error) {
	q.mu.Lock()
	if q.closed || len(q.pending) >= maxPendingSignals {
		q.dropped++
		q.mu.Unlock()
		return
	}
	q.pending = append(q.pending, emit)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *signalQueue) run() {
	defer close(q.done)
	for {
		q.mu.Lock()
		pending, dropped, closed := q.pending, q.dropped, q.closed
		q.pending, q.dropped = nil, 0
		q.mu.Unlock()
		if dropped > 0 {
			log.Printf("secrets: the bus stopped taking signals, so %d were dropped", dropped)
		}
		for _, emit := range pending {
			if err := emit(); err != nil {
				log.Printf("secrets: %v", err)
			}
		}
		if len(pending) > 0 {
			continue
		}
		if closed {
			return
		}
		<-q.wake
	}
}

// drain sends what is queued and ends the queue, giving up when timeout fires.
func (q *signalQueue) drain(timeout <-chan time.Time) {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	select {
	case <-q.done:
	case <-timeout:
		log.Printf("secrets: the bus stopped taking signals, so the service closes without them")
	}
}

func emit[T any](s *Service, sig dbusx.Signal[T], path dbus.ObjectPath, v T) {
	s.signals.post(func() error { return sig.Emit(s.conn, path, v) })
}
