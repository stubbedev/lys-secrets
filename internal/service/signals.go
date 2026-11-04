package service

import (
	"log"
	"sync"
	"time"

	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

const (
	// maxPendingSignals bounds what waits for a bus that stopped taking anything.
	maxPendingSignals = 1024
	signalDrainWait   = 2 * time.Second
)

type signal struct {
	path dbus.ObjectPath
	name string
	args []any
}

// signalQueue sends signals in the order they were raised on one goroutine,
// because a write to a stalled bus blocks, and it must not do so with the service's
// lock held. Past its bound it drops signals and says so: they say something
// changed, and whoever missed one can read the state again.
type signalQueue struct {
	emit func(path dbus.ObjectPath, name string, args ...any) error

	mu      sync.Mutex
	pending []signal
	dropped int
	closed  bool

	wake chan struct{}
	done chan struct{}
}

func newSignalQueue(emit func(dbus.ObjectPath, string, ...any) error) *signalQueue {
	q := &signalQueue{emit: emit, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go q.run()
	return q
}

func (q *signalQueue) post(path dbus.ObjectPath, name string, args ...any) {
	q.mu.Lock()
	if q.closed || len(q.pending) >= maxPendingSignals {
		q.dropped++
		q.mu.Unlock()
		return
	}
	q.pending = append(q.pending, signal{path, name, args})
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
		for _, s := range pending {
			if err := q.emit(s.path, s.name, s.args...); err != nil {
				log.Printf("secrets: emit %s: %v", s.name, err)
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
