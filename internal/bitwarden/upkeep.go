package bitwarden

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/stubbedev/lys-secrets/vault"
)

// Policy is how the open vault is kept: locked once unused for
// LockAfter (0 never), synced every SyncInterval (0 only on unlock and
// when asked).
type Policy struct {
	LockAfter, SyncInterval time.Duration
}

// upkeepTick is how often Keep checks the idle lock and the sync
// interval.
const upkeepTick = 30 * time.Second

// Keep upholds p until ctx ends. A periodic sync that fails is
// reported to failed once per run of failures, and every time it logs
// the account out.
func (s *Service) Keep(ctx context.Context, p Policy, failed func(error)) {
	t := time.NewTicker(upkeepTick)
	defer t.Stop()
	u := upkeep{s: s, policy: p, failed: failed}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.run(ctx, s.now())
		}
	}
}

// upkeep is Keep's state: when it last tried to sync, and whether the
// periodic syncs keep failing.
type upkeep struct {
	s           *Service
	policy      Policy
	failed      func(error)
	lastAttempt time.Time
	failing     bool
}

// run locks the vault once unused for LockAfter and syncs it every
// SyncInterval, counted from the last sync or the last attempt, so a
// server that is down is retried once an interval, not every tick.
func (u *upkeep) run(ctx context.Context, now time.Time) {
	if u.policy.LockAfter > 0 {
		u.s.lockIdle(u.policy.LockAfter)
	}
	if !syncDue(u.s.Status(), u.policy.SyncInterval, u.lastAttempt, now) {
		return
	}
	u.lastAttempt = now
	u.report(u.s.Sync(ctx))
}

// report passes on the first failure of a run of periodic syncs and a
// forced logout.
func (u *upkeep) report(err error) {
	switch {
	case err == nil:
		u.failing = false
		return
	case errors.Is(err, vault.ErrLoginRequired):
		u.failing = false
	case u.failing:
		log.Printf("bitwarden: periodic sync: %v", err)
		return
	default:
		u.failing = true
	}
	log.Printf("bitwarden: periodic sync: %v", err)
	u.failed(err)
}

// syncDue reports whether an open vault is due its periodic sync.
func syncDue(st vault.Status, every time.Duration, lastAttempt, now time.Time) bool {
	if every == 0 || st.State != vault.StateUnlocked || st.Syncing {
		return false
	}
	last := st.LastSync
	if lastAttempt.After(last) {
		last = lastAttempt
	}
	return !now.Before(last.Add(every))
}
