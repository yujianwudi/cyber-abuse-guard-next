package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard/internal/subject"
)

const (
	maxPersistedSubjectRows = 10_000
	maxPersistedStateJSON   = 1 << 20
)

// SaveSubjectSnapshot atomically replaces the optional persisted subject
// state. Its typed input cannot contain a plaintext credential.
func (s *Store) SaveSubjectSnapshot(ctx context.Context, snapshot subject.PersistentSnapshot) error {
	db, err := s.availableDB()
	if err != nil {
		return err
	}
	if snapshot.Version != subject.PersistenceVersion || !validPersistenceDigest(snapshot.HMACKeyID, "sha256:") || snapshot.SavedAt.IsZero() {
		return errors.New("audit: invalid subject persistence metadata")
	}
	if len(snapshot.Subjects) > maxPersistedSubjectRows {
		return fmt.Errorf("audit: subject persistence rows exceed %d", maxPersistedSubjectRows)
	}
	seen := make(map[string]struct{}, len(snapshot.Subjects))
	for _, persisted := range snapshot.Subjects {
		if !validPersistenceDigest(persisted.SubjectHash, "hmac-sha256:") {
			return errors.New("audit: subject persistence contains an invalid subject hash")
		}
		if _, duplicate := seen[persisted.SubjectHash]; duplicate {
			return errors.New("audit: subject persistence contains a duplicate subject hash")
		}
		seen[persisted.SubjectHash] = struct{}{}
		seenRequests := make(map[string]struct{}, len(persisted.Hits))
		for _, persistedHit := range persisted.Hits {
			if persistedHit.RequestHash == "" {
				continue
			}
			if !validPersistenceDigest(persistedHit.RequestHash, "sha256:") {
				return errors.New("audit: subject persistence contains an invalid request hash")
			}
			if _, duplicate := seenRequests[persistedHit.RequestHash]; duplicate {
				return errors.New("audit: subject persistence contains a duplicate request hash")
			}
			seenRequests[persistedHit.RequestHash] = struct{}{}
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin subject persistence update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM subject_state`); err != nil {
		return fmt.Errorf("audit: clear prior subject state: %w", err)
	}
	updatedAt := s.cfg.Now().UTC().UnixNano()
	if _, err := tx.ExecContext(ctx, `INSERT INTO subject_state_meta(singleton, persistence_version, hmac_key_id, saved_at_ns, updated_at_ns)
VALUES(1, ?, ?, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET persistence_version=excluded.persistence_version,
hmac_key_id=excluded.hmac_key_id, saved_at_ns=excluded.saved_at_ns, updated_at_ns=excluded.updated_at_ns`,
		snapshot.Version, snapshot.HMACKeyID, snapshot.SavedAt.UTC().UnixNano(), updatedAt); err != nil {
		return fmt.Errorf("audit: store subject persistence metadata: %w", err)
	}
	statement, err := tx.PrepareContext(ctx, `INSERT INTO subject_state(subject_hash, state_json, updated_at_ns) VALUES(?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("audit: prepare subject persistence write: %w", err)
	}
	defer statement.Close()
	for _, persisted := range snapshot.Subjects {
		encoded, err := json.Marshal(persisted)
		if err != nil {
			return fmt.Errorf("audit: encode subject persistence row: %w", err)
		}
		if len(encoded) > maxPersistedStateJSON {
			return fmt.Errorf("audit: encoded subject persistence row exceeds %d bytes", maxPersistedStateJSON)
		}
		if _, err := statement.ExecContext(ctx, persisted.SubjectHash, string(encoded), updatedAt); err != nil {
			return fmt.Errorf("audit: store subject persistence row: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit subject persistence update: %w", err)
	}
	return nil
}

// LoadSubjectSnapshot returns false when persistence has never been written.
// A key mismatch is explicit so callers cannot silently correlate hashes made
// with different HMAC keys.
func (s *Store) LoadSubjectSnapshot(ctx context.Context, expectedHMACKeyID string) (subject.PersistentSnapshot, bool, error) {
	db, err := s.availableDB()
	if err != nil {
		return subject.PersistentSnapshot{}, false, err
	}
	var version int
	var keyID string
	var savedAtNS int64
	err = db.QueryRowContext(ctx, `SELECT persistence_version, hmac_key_id, saved_at_ns FROM subject_state_meta WHERE singleton = 1`).Scan(&version, &keyID, &savedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return subject.PersistentSnapshot{}, false, nil
	}
	if err != nil {
		return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: load subject persistence metadata: %w", err)
	}
	if keyID != expectedHMACKeyID {
		return subject.PersistentSnapshot{}, false, subject.ErrPersistenceKeyMismatch
	}
	snapshot := subject.PersistentSnapshot{
		Version:   version,
		HMACKeyID: keyID,
		SavedAt:   time.Unix(0, savedAtNS).UTC(),
	}
	rows, err := db.QueryContext(ctx, `SELECT subject_hash, state_json FROM subject_state ORDER BY subject_hash`)
	if err != nil {
		return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: query subject persistence rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		if len(snapshot.Subjects) >= maxPersistedSubjectRows {
			return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: subject persistence rows exceed %d", maxPersistedSubjectRows)
		}
		var rowHash, raw string
		if err := rows.Scan(&rowHash, &raw); err != nil {
			return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: scan subject persistence row: %w", err)
		}
		if len(raw) > maxPersistedStateJSON {
			return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: encoded subject persistence row exceeds %d bytes", maxPersistedStateJSON)
		}
		var persisted subject.PersistentSubject
		decoder := json.NewDecoder(bytes.NewBufferString(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&persisted); err != nil {
			return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: decode subject persistence row: %w", err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return subject.PersistentSnapshot{}, false, err
		}
		if !validPersistenceDigest(persisted.SubjectHash, "hmac-sha256:") || persisted.SubjectHash != rowHash {
			return subject.PersistentSnapshot{}, false, errors.New("audit: subject persistence row hash is invalid or inconsistent")
		}
		snapshot.Subjects = append(snapshot.Subjects, persisted)
	}
	if err := rows.Err(); err != nil {
		return subject.PersistentSnapshot{}, false, fmt.Errorf("audit: iterate subject persistence rows: %w", err)
	}
	return snapshot, true, nil
}

func (s *Store) DeleteSubjectSnapshot(ctx context.Context) error {
	db, err := s.availableDB()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM subject_state`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM subject_state_meta`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) availableDB() (*sql.DB, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	s.sendMu.RLock()
	closed := s.closed
	s.sendMu.RUnlock()
	if closed {
		return nil, ErrClosed
	}
	return s.db, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("audit: decode trailing subject persistence data: %w", err)
	}
	return errors.New("audit: subject persistence row contains multiple JSON values")
}

func validPersistenceDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}
