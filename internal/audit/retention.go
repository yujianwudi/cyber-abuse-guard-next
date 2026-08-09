package audit

import (
	"context"
	"database/sql"
	"fmt"
	"math"
)

const (
	capacityDeleteBatchSize   int64 = 256
	maxCapacityCleanupBatches       = 64
)

// Cleanup applies logical retention, bounds live database pages by deleting
// oldest sensitive captures before ordinary events, checkpoints WAL, and asks
// SQLite to reclaim free pages. A logical TTL cannot guarantee physical-media
// irrecoverability; audit databases additionally enable secure_delete because
// captures can remain from an earlier configuration where the feature was on.
// Failures are reported to the caller but never affect classification.
func (s *Store) Cleanup(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	return s.cleanup(ctx)
}

func (s *Store) cleanup(ctx context.Context) error {
	if s.db == nil {
		return ErrUnavailable
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	return s.cleanupLocked(ctx)
}

func (s *Store) cleanupLocked(ctx context.Context) error {
	if err := s.checkStorageAccess(); err != nil {
		return err
	}
	cutoff := s.cfg.Now().UTC().Add(-s.cfg.Retention).UnixNano()
	result, err := s.db.ExecContext(ctx, "DELETE FROM audit_events WHERE timestamp_ns < ?", cutoff)
	if err != nil {
		return fmt.Errorf("audit: retention cleanup: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr == nil && count > 0 {
		s.cleaned.Add(uint64(count))
	}
	if !s.cfg.RawCapture.Enabled {
		// Disabling capture is privacy-destructive by design. Retrying the purge
		// here makes a transient hot-reconfigure WAL/lock conflict self-healing.
		if _, err := s.purgeRawCapturesLocked(ctx); err != nil {
			return err
		}
	} else {
		rawCutoff := s.cfg.Now().UTC().Add(-s.cfg.RawCapture.TTL).UnixNano()
		rawResult, err := s.db.ExecContext(ctx, "DELETE FROM raw_request_captures WHERE timestamp_ns < ?", rawCutoff)
		if err != nil {
			return fmt.Errorf("audit: raw capture TTL cleanup: %w", err)
		}
		if count, countErr := rawResult.RowsAffected(); countErr == nil && count > 0 {
			s.cleaned.Add(uint64(count))
		}
	}

	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		return fmt.Errorf("audit: WAL checkpoint: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		return fmt.Errorf("audit: incremental vacuum: %w", err)
	}
	if err := secureSQLiteFiles(s.cfg.Path, !s.cfg.RequirePersistentStorage); err != nil {
		return err
	}
	return s.enforceCapacityMaintenanceLocked(ctx)
}

// enforceCapacity is the runtime hard-cap gate. The writer invokes it after
// every bounded batch, while startup and explicit maintenance use the same
// path. Cleanup is itself bounded so a very large inherited database cannot
// monopolize the writer indefinitely; an unrecoverable excess latches the
// admission gate until a later maintenance pass proves the store is back under
// the configured limit.
func (s *Store) enforceCapacity(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	s.maintenanceMu.Lock()
	err := s.enforceCapacityMaintenanceLocked(ctx)
	s.maintenanceMu.Unlock()
	if err != nil {
		s.report(err)
	}
	return err
}

func (s *Store) enforceCapacityMaintenanceLocked(ctx context.Context) error {
	s.capacityMu.Lock()
	err := s.enforceCapacityLocked(ctx)
	s.capacityMu.Unlock()
	return err
}

// remeasureCapacity refreshes and latches the hard-cap state without deleting
// any rows. It is used after committed maintenance where automatic eviction of
// unrelated audit evidence would violate the operation's scope.
func (s *Store) remeasureCapacity(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	s.maintenanceMu.Lock()
	err := s.remeasureCapacityMaintenanceLocked(ctx)
	s.maintenanceMu.Unlock()
	if err != nil {
		s.report(err)
	}
	return err
}

func (s *Store) remeasureCapacityMaintenanceLocked(ctx context.Context) error {
	s.capacityMu.Lock()
	used, err := s.liveDatabaseBytes(ctx)
	if err != nil {
		err = s.capacityFailure(ErrCapacityCheckFailed, false)
	} else {
		s.setCapacityMeasurement(used)
		if used > s.cfg.MaxBytes {
			err = s.capacityFailure(ErrCapacityExceeded, true)
		} else {
			s.clearCapacityFailure()
		}
	}
	s.capacityMu.Unlock()
	return err
}

func (s *Store) enforceCapacityLocked(ctx context.Context) error {
	used, err := s.liveDatabaseBytes(ctx)
	if err != nil {
		return s.capacityFailure(ErrCapacityCheckFailed, false)
	}
	s.setCapacityMeasurement(used)
	if used <= s.cfg.MaxBytes {
		s.clearCapacityFailure()
		return nil
	}

	s.capacityCleanupRuns.Add(1)
	deletedTotal := uint64(0)
	for batch := 0; batch < maxCapacityCleanupBatches && used > s.cfg.MaxBytes; batch++ {
		deleted, deleteErr := s.deleteOldestCapacityRows(ctx, "raw_request_captures")
		if deleteErr != nil {
			return s.capacityFailure(ErrCapacityCleanupFailed, false)
		}
		if deleted == 0 {
			deleted, deleteErr = s.deleteOldestCapacityRows(ctx, "audit_events")
			if deleteErr != nil {
				return s.capacityFailure(ErrCapacityCleanupFailed, false)
			}
		}
		if deleted == 0 {
			break
		}
		deletedTotal += uint64(deleted)
		s.cleaned.Add(uint64(deleted))
		s.capacityCleanupDeleted.Add(uint64(deleted))

		used, err = s.liveDatabaseBytes(ctx)
		if err != nil {
			return s.capacityFailure(ErrCapacityCheckFailed, false)
		}
		s.setCapacityMeasurement(used)
	}

	if deletedTotal != 0 {
		if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
			return s.capacityFailure(ErrCapacityCleanupFailed, false)
		}
		if _, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
			return s.capacityFailure(ErrCapacityCleanupFailed, false)
		}
	}

	used, err = s.liveDatabaseBytes(ctx)
	if err != nil {
		return s.capacityFailure(ErrCapacityCheckFailed, false)
	}
	s.setCapacityMeasurement(used)
	if used > s.cfg.MaxBytes {
		return s.capacityFailure(ErrCapacityExceeded, true)
	}
	s.clearCapacityFailure()
	return nil
}

func (s *Store) deleteOldestCapacityRows(ctx context.Context, table string) (int64, error) {
	var statement string
	switch table {
	case "raw_request_captures":
		statement = `DELETE FROM raw_request_captures WHERE id IN (
			SELECT id FROM raw_request_captures ORDER BY timestamp_ns ASC, id ASC LIMIT ?
		)`
	case "audit_events":
		statement = `DELETE FROM audit_events WHERE id IN (
			SELECT id FROM audit_events ORDER BY timestamp_ns ASC, id ASC LIMIT ?
		)`
	default:
		return 0, ErrCapacityCleanupFailed
	}
	result, err := s.db.ExecContext(ctx, statement, capacityDeleteBatchSize)
	if err != nil {
		return 0, ErrCapacityCleanupFailed
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, ErrCapacityCleanupFailed
	}
	return deleted, nil
}

func (s *Store) setCapacityMeasurement(used int64) {
	s.currentLiveBytes.Store(used)
	s.capacityMeasured.Store(true)
}

func (s *Store) capacityFailure(kind error, measurementAvailable bool) error {
	if !measurementAvailable {
		s.capacityMeasured.Store(false)
	}
	s.overLimit.Store(true)
	s.degraded.Store(true)
	s.lastErr.Store(kind.Error())
	return kind
}

func (s *Store) clearCapacityFailure() {
	s.overLimit.Store(false)
	lastError, _ := s.lastErr.Load().(string)
	if lastError == ErrCapacityExceeded.Error() ||
		lastError == ErrCapacityCheckFailed.Error() ||
		lastError == ErrCapacityCleanupFailed.Error() {
		s.degraded.Store(false)
		s.lastErr.Store("")
	}
}

func (s *Store) liveDatabaseBytes(ctx context.Context) (int64, error) {
	return liveDatabaseBytesFrom(ctx, s.db)
}

type sqliteQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func liveDatabaseBytesFrom(ctx context.Context, queryer sqliteQueryRower) (int64, error) {
	pageCount, err := pragmaInt64(ctx, queryer, "PRAGMA page_count")
	if err != nil {
		return 0, err
	}
	freePages, err := pragmaInt64(ctx, queryer, "PRAGMA freelist_count")
	if err != nil {
		return 0, err
	}
	pageSize, err := pragmaInt64(ctx, queryer, "PRAGMA page_size")
	if err != nil {
		return 0, err
	}
	livePages := pageCount - freePages
	if livePages < 0 {
		return 0, ErrCapacityCheckFailed
	}
	if pageSize <= 0 || livePages > math.MaxInt64/pageSize {
		return 0, ErrCapacityCheckFailed
	}
	return livePages * pageSize, nil
}

func pragmaInt64(ctx context.Context, queryer sqliteQueryRower, statement string) (int64, error) {
	var value int64
	if err := queryer.QueryRowContext(ctx, statement).Scan(&value); err != nil {
		return 0, ErrCapacityCheckFailed
	}
	if value < 0 {
		return 0, ErrCapacityCheckFailed
	}
	return value, nil
}
