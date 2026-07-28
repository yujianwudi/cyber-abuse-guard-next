package plugin

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard/internal/subject"
)

const (
	subjectPersistenceDebounce = 5 * time.Second
	subjectPersistenceInterval = time.Minute
	subjectPersistenceTimeout  = 5 * time.Second
)

type subjectPersistenceRuntime struct {
	enabled bool
	keyID   string

	dirty chan struct{}
	stop  chan struct{}
	done  chan struct{}

	started         atomic.Bool
	stopOnce        sync.Once
	degraded        atomic.Bool
	writesBlocked   atomic.Bool
	lastErr         atomic.Pointer[string]
	restored        atomic.Uint64
	droppedExpired  atomic.Uint64
	droppedCapacity atomic.Uint64
	saved           atomic.Uint64
	failed          atomic.Uint64
}

type subjectPersistenceStatus struct {
	Enabled         bool   `json:"enabled"`
	Started         bool   `json:"started"`
	Healthy         bool   `json:"healthy"`
	Degraded        bool   `json:"degraded"`
	Restored        uint64 `json:"restored_subjects"`
	DroppedExpired  uint64 `json:"dropped_expired"`
	DroppedCapacity uint64 `json:"dropped_capacity"`
	SuccessfulSaves uint64 `json:"successful_saves"`
	FailedSaves     uint64 `json:"failed_saves"`
	LastError       string `json:"last_error,omitempty"`
	WritesBlocked   bool   `json:"writes_blocked"`
}

func newSubjectPersistenceRuntime(keyID string) *subjectPersistenceRuntime {
	return &subjectPersistenceRuntime{
		enabled: true,
		keyID:   keyID,
		dirty:   make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (runtime *subjectPersistenceRuntime) status() subjectPersistenceStatus {
	if runtime == nil || !runtime.enabled {
		return subjectPersistenceStatus{}
	}
	lastError := ""
	if value := runtime.lastErr.Load(); value != nil {
		lastError = *value
	}
	degraded := runtime.degraded.Load()
	return subjectPersistenceStatus{
		Enabled:         true,
		Started:         runtime.started.Load(),
		Healthy:         !degraded,
		Degraded:        degraded,
		Restored:        runtime.restored.Load(),
		DroppedExpired:  runtime.droppedExpired.Load(),
		DroppedCapacity: runtime.droppedCapacity.Load(),
		SuccessfulSaves: runtime.saved.Load(),
		FailedSaves:     runtime.failed.Load(),
		LastError:       lastError,
		WritesBlocked:   runtime.writesBlocked.Load(),
	}
}

func (runtime *subjectPersistenceRuntime) setError(err error) {
	if runtime == nil {
		return
	}
	if err == nil {
		runtime.degraded.Store(false)
		runtime.lastErr.Store(nil)
		return
	}
	message := err.Error()
	runtime.degraded.Store(true)
	runtime.lastErr.Store(&message)
}

func (state *runtimeState) restoreSubjectPersistence(p *Plugin) {
	if state == nil || state.persistence == nil {
		return
	}
	if state.audit == nil {
		state.persistence.writesBlocked.Store(true)
		state.persistence.setError(errors.New("subject persistence database is unavailable"))
		p.logSubjectPersistenceError("subject_persistence_restore_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), subjectPersistenceTimeout)
	defer cancel()
	snapshot, found, err := state.audit.LoadSubjectSnapshot(ctx, state.persistence.keyID)
	if err != nil {
		// A failed restore leaves the on-disk state untrusted. Never replace the
		// evidence with a fresh in-memory snapshot during a later dirty,
		// periodic, reconfigure, or shutdown save. Recovery requires an operator
		// to repair or explicitly delete the damaged snapshot and restart.
		state.persistence.writesBlocked.Store(true)
		state.persistence.setError(err)
		code := "subject_persistence_restore_failed"
		if errors.Is(err, subject.ErrPersistenceKeyMismatch) {
			code = "subject_persistence_hmac_mismatch"
		}
		p.logSubjectPersistenceError(code)
		return
	}
	if !found {
		state.persistence.setError(nil)
		return
	}
	restored, err := state.subject.RestorePersistent(snapshot, state.persistence.keyID)
	if err != nil {
		state.persistence.writesBlocked.Store(true)
		state.persistence.setError(err)
		p.logSubjectPersistenceError("subject_persistence_restore_rejected")
		return
	}
	state.persistence.restored.Store(uint64(restored.Loaded))
	state.persistence.droppedExpired.Store(uint64(restored.DroppedExpired))
	state.persistence.droppedCapacity.Store(uint64(restored.DroppedCapacity))
	state.persistence.setError(nil)
}

func (p *Plugin) logSubjectPersistenceError(code string) {
	if p == nil {
		return
	}
	now := time.Now().UnixNano()
	for {
		previous := p.lastPersistenceNotice.Load()
		if previous != 0 && time.Duration(now-previous) < time.Minute {
			return
		}
		if p.lastPersistenceNotice.CompareAndSwap(previous, now) {
			break
		}
	}
	p.log("error", "cyber-abuse-guard subject persistence is degraded; in-memory enforcement remains active", map[string]any{
		"plugin": ID,
		"code":   code,
	})
}

func (state *runtimeState) startSubjectPersistence(p *Plugin) {
	if state == nil || state.persistence == nil || !state.persistence.started.CompareAndSwap(false, true) {
		return
	}
	go state.runSubjectPersistence(p)
}

func (state *runtimeState) markSubjectPersistenceDirty() {
	if state == nil || state.persistence == nil {
		return
	}
	select {
	case state.persistence.dirty <- struct{}{}:
	default:
	}
}

func (state *runtimeState) runSubjectPersistence(p *Plugin) {
	runtime := state.persistence
	defer close(runtime.done)
	periodic := time.NewTicker(subjectPersistenceInterval)
	defer periodic.Stop()
	debounce := time.NewTimer(subjectPersistenceDebounce)
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()
	var debounceC <-chan time.Time
	dirty := false

	for {
		select {
		case <-runtime.dirty:
			if !dirty {
				dirty = true
				debounce.Reset(subjectPersistenceDebounce)
				debounceC = debounce.C
			}
		case <-debounceC:
			state.saveSubjectPersistence(p)
			dirty = false
			debounceC = nil
		case <-periodic.C:
			if dirty {
				if debounceC != nil && !debounce.Stop() {
					select {
					case <-debounce.C:
					default:
					}
				}
				state.saveSubjectPersistence(p)
				dirty = false
				debounceC = nil
			}
		case <-runtime.stop:
			if debounceC != nil && !debounce.Stop() {
				select {
				case <-debounce.C:
				default:
				}
			}
			// Always save at a clean lifecycle boundary so unblocks and decay
			// cleanup are not lost even if a dirty notification was coalesced.
			state.saveSubjectPersistence(p)
			return
		}
	}
}

func (state *runtimeState) saveSubjectPersistence(p *Plugin) {
	if state == nil || state.persistence == nil || state.subject == nil || state.audit == nil {
		return
	}
	// Any rejected or unreadable restore makes the stored state untrusted.
	// Preserve that snapshot for operator review instead of silently replacing
	// it during shutdown or the periodic save cycle.
	if state.persistence.writesBlocked.Load() {
		return
	}
	snapshot, err := state.subject.ExportPersistent(state.persistence.keyID)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), subjectPersistenceTimeout)
		err = state.audit.SaveSubjectSnapshot(ctx, snapshot)
		cancel()
	}
	if err != nil {
		state.persistence.failed.Add(1)
		state.persistence.setError(err)
		p.logSubjectPersistenceError("subject_persistence_save_failed")
		return
	}
	state.persistence.saved.Add(1)
	state.persistence.setError(nil)
}

func (state *runtimeState) stopSubjectPersistence() {
	if state == nil || state.persistence == nil || !state.persistence.started.Load() {
		return
	}
	state.persistence.stopOnce.Do(func() { close(state.persistence.stop) })
	select {
	case <-state.persistence.done:
	case <-time.After(subjectPersistenceTimeout + time.Second):
		state.persistence.failed.Add(1)
		state.persistence.setError(errors.New("subject persistence shutdown timed out"))
	}
}
