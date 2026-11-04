package prompt

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
)

func TestOverlappingPromptsGetTheirOwnHandles(t *testing.T) {
	d := New(dbustest.Session(t).Conn(t))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, ok, err := d.Password(ctx, "login", false); err == nil || ok {
				t.Errorf("asked with no dialog host on the bus: ok %v, err %v", ok, err)
			}
		})
	}
	wg.Wait()
	if got := d.seq.Load(); got != 16 {
		t.Errorf("%d prompts numbered, want 16", got)
	}
}
