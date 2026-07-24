package audit

import (
	"context"
	"fmt"
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
		if _, err := s.purgeRawCaptures(ctx); err != nil {
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

	for {
		used, err := s.liveDatabaseBytes(ctx)
		if err != nil {
			return err
		}
		if used <= s.cfg.MaxBytes {
			break
		}
		var rawCount int64
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM raw_request_captures").Scan(&rawCount); err != nil {
			return fmt.Errorf("audit: count raw captures for size cleanup: %w", err)
		}
		if rawCount > 0 {
			batch := rawCount / 10
			if batch < 1 {
				batch = 1
			}
			result, err := s.db.ExecContext(ctx, `DELETE FROM raw_request_captures WHERE id IN (
            SELECT id FROM raw_request_captures ORDER BY timestamp_ns ASC, id ASC LIMIT ?
        )`, batch)
			if err != nil {
				return fmt.Errorf("audit: raw capture maximum-size cleanup: %w", err)
			}
			deleted, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("audit: count raw capture maximum-size cleanup: %w", err)
			}
			if deleted > 0 {
				s.cleaned.Add(uint64(deleted))
				continue
			}
		}
		var count int64
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
			return fmt.Errorf("audit: count events for size cleanup: %w", err)
		}
		if count == 0 {
			break // the fixed schema itself can be larger than a tiny configured cap
		}
		batch := count / 10
		if batch < 1 {
			batch = 1
		}
		result, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN (
            SELECT id FROM audit_events ORDER BY timestamp_ns ASC, id ASC LIMIT ?
        )`, batch)
		if err != nil {
			return fmt.Errorf("audit: maximum-size cleanup: %w", err)
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("audit: count maximum-size cleanup: %w", err)
		}
		if deleted <= 0 {
			break
		}
		s.cleaned.Add(uint64(deleted))
	}

	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		return fmt.Errorf("audit: WAL checkpoint: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		return fmt.Errorf("audit: incremental vacuum: %w", err)
	}
	if err := secureSQLiteFiles(s.cfg.Path); err != nil {
		return err
	}
	return nil
}

func (s *Store) liveDatabaseBytes(ctx context.Context) (int64, error) {
	pageCount, err := pragmaInt64(ctx, s, "PRAGMA page_count")
	if err != nil {
		return 0, err
	}
	freePages, err := pragmaInt64(ctx, s, "PRAGMA freelist_count")
	if err != nil {
		return 0, err
	}
	pageSize, err := pragmaInt64(ctx, s, "PRAGMA page_size")
	if err != nil {
		return 0, err
	}
	livePages := pageCount - freePages
	if livePages < 0 {
		livePages = 0
	}
	return livePages * pageSize, nil
}

func pragmaInt64(ctx context.Context, s *Store, statement string) (int64, error) {
	var value int64
	if err := s.db.QueryRowContext(ctx, statement).Scan(&value); err != nil {
		return 0, fmt.Errorf("audit: %s: %w", statement, err)
	}
	return value, nil
}
