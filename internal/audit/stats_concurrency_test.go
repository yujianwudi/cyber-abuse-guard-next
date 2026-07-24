package audit

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type statsGateProbeContext struct {
	context.Context
	reached chan struct{}
	once    sync.Once
}

func (c *statsGateProbeContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.reached) })
	return c.Context.Done()
}

func TestStatsConcurrencyGateLeavesWriterCapacity(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "stats-concurrency.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := cap(store.statsSlots); got != statsConcurrentLimit {
		t.Fatalf("statistics concurrency capacity=%d, want %d", got, statsConcurrentLimit)
	}

	// Model the one admitted Stats request with both its gate token and the
	// read-only transaction/connection it owns. Every additional request must
	// wait at the gate instead of consuming the other three pooled connections.
	if err := store.acquireStatsSlot(context.Background()); err != nil {
		t.Fatal(err)
	}
	gateHeld := true
	defer func() {
		if gateHeld {
			store.releaseStatsSlot()
		}
	}()
	activeTx, err := store.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	activeTxOpen := true
	defer func() {
		if activeTxOpen {
			_ = activeTx.Rollback()
		}
	}()
	var seed int
	if err := activeTx.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&seed); err != nil {
		t.Fatal(err)
	}

	const waiters = 4
	type waiter struct {
		cancel  context.CancelFunc
		done    chan error
		reached chan struct{}
	}
	waiting := make([]waiter, 0, waiters)
	for index := 0; index < waiters; index++ {
		base, cancel := context.WithCancel(context.Background())
		probe := &statsGateProbeContext{Context: base, reached: make(chan struct{})}
		done := make(chan error, 1)
		waiting = append(waiting, waiter{cancel: cancel, done: done, reached: probe.reached})
		go func(ctx context.Context, result chan<- error) {
			_, err := store.Stats(ctx)
			result <- err
		}(probe, done)
	}
	for index := range waiting {
		select {
		case <-waiting[index].reached:
		case <-time.After(5 * time.Second):
			t.Fatalf("statistics waiter %d did not reach the concurrency gate", index)
		}
	}
	if inUse := store.db.Stats().InUse; inUse != 1 {
		t.Fatalf("pooled connections in use with one active snapshot and four waiters=%d, want 1", inUse)
	}

	prepared, err := prepareEvent(testEvent("stats-writer-capacity", time.Now().UTC()), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- store.writeWork(store.db, workItem{event: &prepared})
	}()
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("writer failed while statistics waiters were queued: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer was starved by queued statistics requests")
	}

	for index := range waiting {
		waiting[index].cancel()
	}
	for index := range waiting {
		select {
		case err := <-waiting[index].done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("statistics waiter %d error=%v, want context cancellation", index, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("statistics waiter %d did not cancel", index)
		}
	}
	if err := activeTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	activeTxOpen = false
	store.releaseStatsSlot()
	gateHeld = false

	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 1 {
		t.Fatalf("statistics after releasing gate reported %d events, want 1", stats.Events)
	}
}
