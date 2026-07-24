package subject

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	PersistenceVersion      = 1
	maxPersistedSubjects    = 10_000
	maxPersistedHitScore    = 1_000_000_000
	maxPersistenceClockSkew = 5 * time.Minute
)

var (
	ErrPersistenceKeyMismatch = errors.New("subject: persisted state belongs to a different HMAC key")
	ErrInvalidPersistence     = errors.New("subject: invalid persisted state")
)

// PersistentSnapshot contains only already-HMACed subjects and bounded risk
// metadata. It deliberately cannot contain a plaintext API key or credential.
type PersistentSnapshot struct {
	Version   int                 `json:"version"`
	HMACKeyID string              `json:"hmac_key_id"`
	SavedAt   time.Time           `json:"saved_at"`
	Subjects  []PersistentSubject `json:"subjects"`
}

type PersistentSubject struct {
	SubjectHash   string          `json:"subject_hash"`
	Hits          []PersistentHit `json:"hits,omitempty"`
	CooldownUntil time.Time       `json:"cooldown_until,omitempty"`
	ManualBlocked bool            `json:"manual_blocked,omitempty"`
}

type PersistentHit struct {
	At          time.Time `json:"at"`
	Score       float64   `json:"score"`
	RequestHash string    `json:"request_hash,omitempty"`
}

type RestoreResult struct {
	Loaded          int `json:"loaded"`
	DroppedExpired  int `json:"dropped_expired"`
	DroppedCapacity int `json:"dropped_capacity"`
}

type restoreCandidate struct {
	subjectHash  string
	current      *entry
	lastActivity time.Time
}

// ExportPersistent returns a deterministic, secret-free snapshot. Expired
// state is removed before export so a restart cannot resurrect stale risk.
func (c *Controller) ExportPersistent(hmacKeyID string) (PersistentSnapshot, error) {
	if c == nil {
		return PersistentSnapshot{}, errors.New("subject: controller is unavailable")
	}
	if !validDigest(hmacKeyID, "sha256:") {
		return PersistentSnapshot{}, fmt.Errorf("%w: invalid HMAC key identifier", ErrInvalidPersistence)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now().UTC()
	snapshot := PersistentSnapshot{Version: PersistenceVersion, HMACKeyID: hmacKeyID, SavedAt: now}
	if !c.cfg.Enabled {
		return snapshot, nil
	}
	if len(c.entries) > maxPersistedSubjects {
		return PersistentSnapshot{}, fmt.Errorf("%w: %d subjects exceed persistence limit %d", ErrInvalidPersistence, len(c.entries), maxPersistedSubjects)
	}
	for subjectHash, current := range c.entries {
		c.prune(current, now)
		if inactive(current, now) {
			c.removeEntryLocked(subjectHash, current)
			continue
		}
		persisted := PersistentSubject{
			SubjectHash:   subjectHash,
			CooldownUntil: current.cooldownUntil,
			ManualBlocked: current.manualBlocked,
			Hits:          make([]PersistentHit, 0, len(current.hits)),
		}
		for _, item := range current.hits {
			persisted.Hits = append(persisted.Hits, PersistentHit{
				At:          item.at,
				Score:       item.score,
				RequestHash: item.requestHash,
			})
		}
		snapshot.Subjects = append(snapshot.Subjects, persisted)
	}
	sort.Slice(snapshot.Subjects, func(i, j int) bool {
		return snapshot.Subjects[i].SubjectHash < snapshot.Subjects[j].SubjectHash
	})
	return snapshot, nil
}

// RestorePersistent validates a complete snapshot before atomically replacing
// in-memory state. Old hits are discarded and remaining scores continue to
// decay from their original timestamps.
func (c *Controller) RestorePersistent(snapshot PersistentSnapshot, expectedHMACKeyID string) (RestoreResult, error) {
	if c == nil {
		return RestoreResult{}, errors.New("subject: controller is unavailable")
	}
	if !validDigest(expectedHMACKeyID, "sha256:") || !validDigest(snapshot.HMACKeyID, "sha256:") {
		return RestoreResult{}, fmt.Errorf("%w: invalid HMAC key identifier", ErrInvalidPersistence)
	}
	if snapshot.HMACKeyID != expectedHMACKeyID {
		return RestoreResult{}, ErrPersistenceKeyMismatch
	}
	if snapshot.Version != PersistenceVersion {
		return RestoreResult{}, fmt.Errorf("%w: unsupported persistence version %d", ErrInvalidPersistence, snapshot.Version)
	}
	if snapshot.SavedAt.IsZero() {
		return RestoreResult{}, fmt.Errorf("%w: missing save timestamp", ErrInvalidPersistence)
	}
	if len(snapshot.Subjects) > maxPersistedSubjects {
		return RestoreResult{}, fmt.Errorf("%w: %d subjects exceed persistence limit %d", ErrInvalidPersistence, len(snapshot.Subjects), maxPersistedSubjects)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled {
		return RestoreResult{}, fmt.Errorf("%w: controller is disabled", ErrInvalidPersistence)
	}
	now := c.cfg.Now().UTC()
	if snapshot.SavedAt.After(now.Add(maxPersistenceClockSkew)) {
		return RestoreResult{}, fmt.Errorf("%w: save timestamp is in the future", ErrInvalidPersistence)
	}
	seen := make(map[string]struct{}, len(snapshot.Subjects))
	manual := make([]restoreCandidate, 0)
	nonManual := make([]restoreCandidate, 0)
	result := RestoreResult{}

	for _, persisted := range snapshot.Subjects {
		if !validSubjectHash(persisted.SubjectHash) {
			return RestoreResult{}, fmt.Errorf("%w: invalid subject hash", ErrInvalidPersistence)
		}
		if _, duplicate := seen[persisted.SubjectHash]; duplicate {
			return RestoreResult{}, fmt.Errorf("%w: duplicate subject hash", ErrInvalidPersistence)
		}
		seen[persisted.SubjectHash] = struct{}{}
		if len(persisted.Hits) > maxHitsPerSubject {
			return RestoreResult{}, fmt.Errorf("%w: subject hit count exceeds %d", ErrInvalidPersistence, maxHitsPerSubject)
		}
		current := &entry{manualBlocked: persisted.ManualBlocked}
		lastActivity := time.Time{}
		seenRequests := make(map[string]struct{}, len(persisted.Hits))
		for _, persistedHit := range persisted.Hits {
			at := persistedHit.At.UTC()
			if at.IsZero() || at.After(now.Add(maxPersistenceClockSkew)) {
				return RestoreResult{}, fmt.Errorf("%w: invalid hit timestamp", ErrInvalidPersistence)
			}
			if at.After(now) {
				// Small wall-clock skew is tolerated, but it must never increase a
				// restored score or leave future-dated history in memory.
				at = now
			}
			if persistedHit.Score <= 0 || persistedHit.Score > maxPersistedHitScore || math.IsNaN(persistedHit.Score) || math.IsInf(persistedHit.Score, 0) {
				return RestoreResult{}, fmt.Errorf("%w: invalid hit score", ErrInvalidPersistence)
			}
			if persistedHit.RequestHash != "" {
				if !validDigest(persistedHit.RequestHash, "sha256:") {
					return RestoreResult{}, fmt.Errorf("%w: invalid persisted request hash", ErrInvalidPersistence)
				}
				if _, duplicate := seenRequests[persistedHit.RequestHash]; duplicate {
					return RestoreResult{}, fmt.Errorf("%w: duplicate persisted request hash", ErrInvalidPersistence)
				}
				seenRequests[persistedHit.RequestHash] = struct{}{}
			}
			if now.Sub(at) >= c.cfg.Window {
				continue
			}
			current.hits = append(current.hits, hit{at: at, score: persistedHit.Score, requestHash: persistedHit.RequestHash})
			if at.After(lastActivity) {
				lastActivity = at
			}
		}
		sort.Slice(current.hits, func(i, j int) bool {
			return current.hits[i].at.Before(current.hits[j].at)
		})
		if persisted.CooldownUntil.After(now) {
			current.cooldownUntil = persisted.CooldownUntil.UTC()
			maximumCooldown := now.Add(c.cfg.Cooldown)
			if current.cooldownUntil.After(maximumCooldown) {
				current.cooldownUntil = maximumCooldown
			}
			if current.cooldownUntil.After(lastActivity) {
				lastActivity = current.cooldownUntil
			}
		}
		if inactive(current, now) {
			result.DroppedExpired++
			continue
		}
		candidate := restoreCandidate{subjectHash: persisted.SubjectHash, current: current, lastActivity: lastActivity}
		if current.manualBlocked {
			manual = append(manual, candidate)
		} else {
			nonManual = append(nonManual, candidate)
		}
	}
	if len(manual) > c.cfg.MaxSubjects {
		return RestoreResult{}, fmt.Errorf("%w: %d manual blocks exceed capacity %d", ErrInvalidPersistence, len(manual), c.cfg.MaxSubjects)
	}
	sort.Slice(nonManual, func(i, j int) bool {
		if nonManual[i].lastActivity.Equal(nonManual[j].lastActivity) {
			return nonManual[i].subjectHash > nonManual[j].subjectHash
		}
		return nonManual[i].lastActivity.After(nonManual[j].lastActivity)
	})
	available := c.cfg.MaxSubjects - len(manual)
	if len(nonManual) > available {
		result.DroppedCapacity = len(nonManual) - available
		nonManual = nonManual[:available]
	}
	sort.Slice(nonManual, func(i, j int) bool {
		if nonManual[i].lastActivity.Equal(nonManual[j].lastActivity) {
			return nonManual[i].subjectHash < nonManual[j].subjectHash
		}
		return nonManual[i].lastActivity.Before(nonManual[j].lastActivity)
	})

	entries := make(map[string]*entry, len(manual)+len(nonManual))
	for _, candidate := range manual {
		entries[candidate.subjectHash] = candidate.current
	}
	for _, candidate := range nonManual {
		entries[candidate.subjectHash] = candidate.current
	}
	c.entries = entries
	c.evictable.Init()
	for _, candidate := range nonManual {
		candidate.current.element = c.evictable.PushBack(candidate.subjectHash)
	}
	c.manualSubjects = len(manual)
	result.Loaded = len(entries)
	return result, nil
}
