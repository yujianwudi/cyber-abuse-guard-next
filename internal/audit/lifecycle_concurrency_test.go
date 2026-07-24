package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConcurrentFlushStatusRecordAndClose(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "audit.db"),
		QueueSize: 64,
		Now:       fixedMigrationTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 32; index++ {
		_ = store.Enqueue(Event{
			ID:         fmt.Sprintf("lifecycle-%03d", index),
			Timestamp:  fixedMigrationTime(),
			Action:     "audit",
			Mode:       "audit",
			Classifier: "lifecycle-test",
		})
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 50; iteration++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				err := store.Flush(ctx)
				cancel()
				if err != nil && !errors.Is(err, ErrClosed) && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("Flush() error = %v", err)
					return
				}
				_ = store.Status()
				_ = store.Record(Event{
					ID:         fmt.Sprintf("concurrent-%02d-%03d", worker, iteration),
					Timestamp:  fixedMigrationTime(),
					Action:     "audit",
					Mode:       "audit",
					Classifier: "lifecycle-test",
				})
			}
		}(worker)
	}
	for closer := 0; closer < 4; closer++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = store.CloseContext(ctx)
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("audit lifecycle operations did not finish")
	}
	if store.Record(Event{ID: "after-close", Timestamp: fixedMigrationTime(), Action: "audit", Mode: "audit", Classifier: "test"}) {
		t.Fatal("audit Record succeeded after concurrent close")
	}
}
