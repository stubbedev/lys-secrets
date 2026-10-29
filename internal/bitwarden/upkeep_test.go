package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stubbedev/lys-secrets/vault"
)

var upkeepNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// The periodic sync is due an interval after the last sync or the last
// attempt, whichever is later, and only for an open vault that is not
// already syncing.
func TestSyncDue(t *testing.T) {
	open := vault.Status{State: vault.StateUnlocked, LastSync: upkeepNow.Add(-30 * time.Minute)}
	if !syncDue(open, 30*time.Minute, time.Time{}, upkeepNow) {
		t.Error("an open vault synced 30 minutes ago is not due a 30 minute sync")
	}
	for name, c := range map[string]struct {
		st          vault.Status
		every       time.Duration
		lastAttempt time.Time
	}{
		"interval 0":     {open, 0, time.Time{}},
		"too soon":       {open, 31 * time.Minute, time.Time{}},
		"locked":         {vault.Status{State: vault.StateLocked}, 30 * time.Minute, time.Time{}},
		"syncing":        {vault.Status{State: vault.StateUnlocked, Syncing: true}, 30 * time.Minute, time.Time{}},
		"failed lately":  {open, 30 * time.Minute, upkeepNow.Add(-time.Minute)},
		"never unlocked": {vault.Status{}, 30 * time.Minute, time.Time{}},
	} {
		if syncDue(c.st, c.every, c.lastAttempt, upkeepNow) {
			t.Errorf("%s: sync due", name)
		}
	}
}

// The upkeep syncs a due vault and remembers the attempt, then locks it
// once unused for LockAfter; LockAfter 0 never locks.
func TestUpkeepRun(t *testing.T) {
	a := newAccount(t)
	s := openService(t, t.TempDir())
	clock := upkeepNow
	s.now = func() time.Time { return clock }
	if err := s.Login(context.Background(), login(a)); err != nil {
		t.Fatal(err)
	}
	u := upkeep{s: s.Service, policy: Policy{SyncInterval: 30 * time.Minute}, failed: func(err error) { t.Errorf("reported %v", err) }}
	clock = clock.Add(30 * time.Minute)
	u.run(context.Background(), clock)
	if !u.lastAttempt.Equal(clock) || !s.Status().LastSync.Equal(clock) {
		t.Errorf("due upkeep: attempt %v, last sync %v", u.lastAttempt, s.Status().LastSync)
	}
	syncs := len(a.grants)
	clock = clock.Add(time.Hour)
	u.policy = Policy{}
	u.run(context.Background(), clock)
	if s.Status().State != vault.StateUnlocked || len(a.grants) != syncs {
		t.Errorf("a policy of zeros locked or synced: %+v, grants %v", s.Status(), a.grants)
	}
	u.policy.LockAfter = 15 * time.Minute
	u.run(context.Background(), clock)
	if s.Status().State != vault.StateLocked {
		t.Errorf("an hour unused under a 15 minute lock: %+v", s.Status())
	}
}

// A failing periodic sync is reported once per run of failures, and
// again only after a success; a forced logout always is.
func TestUpkeepReport(t *testing.T) {
	var reported []error
	u := upkeep{failed: func(err error) { reported = append(reported, err) }}
	u.report(errors.New("connection refused"))
	u.report(errors.New("connection refused"))
	if len(reported) != 1 {
		t.Fatalf("two failures reported %v", reported)
	}
	u.report(nil)
	if len(reported) != 1 {
		t.Errorf("a success reported: %v", reported)
	}
	u.report(errors.New("again"))
	if len(reported) != 2 {
		t.Errorf("a failure after a success was not reported: %v", reported)
	}
	logout := fmt.Errorf("refresh: %w", vault.ErrLoginRequired)
	u.report(logout)
	u.report(logout)
	if len(reported) != 4 || !errors.Is(reported[3], vault.ErrLoginRequired) {
		t.Errorf("forced logouts = %v", reported)
	}
}
