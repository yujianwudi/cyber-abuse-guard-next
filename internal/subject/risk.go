package subject

import (
	"container/list"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// Reason is a stable, coarse risk-control outcome. It contains no classifier
// evidence or request content.
type Reason string

const (
	ReasonSafe        Reason = "safe"
	ReasonRisk        Reason = "risk_recorded"
	ReasonCooldown    Reason = "cooldown"
	ReasonManualBlock Reason = "manual_block"
	ReasonDisabled    Reason = "disabled"
	ReasonInvalidHash Reason = "invalid_subject_hash"
	ReasonCapacity    Reason = "subject_capacity"
)

// Config controls rolling in-memory subject risk.
type Config struct {
	Enabled          bool
	Window           time.Duration
	AuditThreshold   int
	CooldownScore    float64
	ManualBlockScore float64
	Cooldown         time.Duration
	RepeatMultiplier float64
	MaxMultiplier    float64
	MaxSubjects      int
	Now              func() time.Time
}

// Stats is a constant-time, management-safe capacity snapshot. Counters are
// cumulative for the life of the Controller, including across Reconfigure.
type Stats struct {
	Enabled          bool   `json:"enabled"`
	Subjects         int    `json:"subjects"`
	MaxSubjects      int    `json:"max_subjects"`
	ManualBlocked    int    `json:"manual_blocked"`
	Evicted          uint64 `json:"evicted"`
	RejectedCapacity uint64 `json:"rejected_capacity"`
}

// Decision describes the result for the current request. A new receipt can add
// risk only at or above AuditThreshold; a duplicate returns the disposition of
// its existing receipt even if a later policy raises that threshold.
type Decision struct {
	SubjectHash   string    `json:"subject_hash"`
	Blocked       bool      `json:"blocked"`
	Reason        Reason    `json:"reason"`
	Duplicate     bool      `json:"duplicate,omitempty"`
	Score         float64   `json:"score"`
	AddedScore    float64   `json:"added_score"`
	Multiplier    float64   `json:"multiplier"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	ManualBlocked bool      `json:"manual_blocked"`
	RepeatCount   int       `json:"repeat_count"`
}

// Observation separates a classifier result from permission to persist it in
// rolling subject risk. Callers may set Accumulate=false to check an existing
// cooldown or manual block without allocating a subject, adding a hit or
// idempotency receipt, or advancing the repeat multiplier.
type Observation struct {
	RiskScore  int
	Accumulate bool
}

// State is a secret-free management snapshot for one already-HMACed subject.
type State struct {
	SubjectHash   string    `json:"subject_hash"`
	Score         float64   `json:"score"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	ManualBlocked bool      `json:"manual_blocked"`
	HitCount      int       `json:"hit_count"`
}

type hit struct {
	at          time.Time
	score       float64
	requestHash string
}

type entry struct {
	hits          []hit
	cooldownUntil time.Time
	manualBlocked bool
	element       *list.Element
}

// Controller owns concurrent in-memory risk state.
type Controller struct {
	mu               sync.Mutex
	cfg              Config
	entries          map[string]*entry
	evictable        list.List
	manualSubjects   int
	evicted          uint64
	rejectedCapacity uint64
}

const (
	maxHitsPerSubject = 1024
	maintenanceBatch  = 16
	// DefaultMaxSubjects bounds pre-authentication header cardinality when an
	// operator does not choose an explicit limit.
	DefaultMaxSubjects = 10_000
)

// NewController validates risk-control thresholds before creating state. A
// disabled controller accepts zero-valued thresholds and always allows.
func NewController(cfg Config) (*Controller, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Controller{cfg: normalized, entries: make(map[string]*entry)}, nil
}

// Reconfigure atomically updates control parameters. Existing entries are
// preserved for enabled-to-enabled updates. Shrinking capacity evicts only the
// oldest non-manual entries; a limit below the protected manual-block count is
// rejected without partially changing either configuration or state. Disabling
// clears process-local subject state.
func (c *Controller) Reconfigure(cfg Config) error {
	if c == nil {
		return errors.New("subject: controller is unavailable")
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !normalized.Enabled {
		c.cfg = normalized
		clear(c.entries)
		c.evictable.Init()
		c.manualSubjects = 0
		return nil
	}
	if c.manualSubjects > normalized.MaxSubjects {
		return fmt.Errorf("subject: max subjects %d is below %d protected manual blocks", normalized.MaxSubjects, c.manualSubjects)
	}

	c.cfg = normalized
	now := c.cfg.Now().UTC()
	c.cleanupOldestLocked(now, maintenanceBatch)
	for len(c.entries) > c.cfg.MaxSubjects {
		if !c.evictOldestLocked() {
			return errors.New("subject: capacity shrink could not preserve protected manual blocks")
		}
	}
	return nil
}

// Evaluate records and evaluates one classifier score. Scores below the audit
// threshold are always safe, including while a subject is cooling down or
// manually blocked; this prevents ordinary traffic from being permanently
// denied after a false positive.
func (c *Controller) Evaluate(subjectHash string, riskScore int) Decision {
	return c.Observe(subjectHash, Observation{RiskScore: riskScore, Accumulate: true})
}

// EvaluateRequest records and evaluates one classifier score while making the
// request accounting idempotent for the life of the corresponding rolling
// risk hit. requestHash must be a domain-separated SHA-256 request digest.
// Duplicate callbacks return the current subject disposition without adding a
// second hit or advancing the repeat multiplier.
func (c *Controller) EvaluateRequest(subjectHash, requestHash string, riskScore int) Decision {
	return c.ObserveRequest(subjectHash, requestHash, Observation{RiskScore: riskScore, Accumulate: true})
}

// Observe evaluates an explicit subject-risk observation without an
// idempotency receipt. Accumulate=false is a read-only disposition lookup.
func (c *Controller) Observe(subjectHash string, observation Observation) Decision {
	return c.observe(subjectHash, "", observation)
}

// ObserveRequest evaluates an explicit subject-risk observation. requestHash
// is validated and retained only when Accumulate=true; an ineligible
// observation cannot create a receipt that suppresses a later eligible event.
func (c *Controller) ObserveRequest(subjectHash, requestHash string, observation Observation) Decision {
	if observation.Accumulate && !validDigest(requestHash, "sha256:") {
		return Decision{Reason: ReasonInvalidHash}
	}
	return c.observe(subjectHash, requestHash, observation)
}

func (c *Controller) observe(subjectHash, requestHash string, observation Observation) Decision {
	if c == nil {
		return Decision{SubjectHash: subjectHash, Reason: ReasonDisabled}
	}
	if !validSubjectHash(subjectHash) {
		return Decision{Reason: ReasonInvalidHash}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled {
		return Decision{SubjectHash: subjectHash, Reason: ReasonDisabled}
	}
	now := c.cfg.Now().UTC()
	if !observation.Accumulate {
		return c.nonAccumulatingDecisionLocked(subjectHash, observation.RiskScore, now)
	}
	c.cleanupOldestLocked(now, maintenanceBatch)

	current := c.entries[subjectHash]
	if current != nil {
		c.prune(current, now)
	}
	if requestHash != "" && current != nil {
		for _, recorded := range current.hits {
			if recorded.requestHash == requestHash {
				decision := c.decision(subjectHash, current, now)
				decision.Duplicate = true
				switch {
				case current.manualBlocked:
					decision.Blocked = true
					decision.Reason = ReasonManualBlock
				case now.Before(current.cooldownUntil):
					decision.Blocked = true
					decision.Reason = ReasonCooldown
				default:
					decision.Reason = ReasonRisk
				}
				return decision
			}
		}
	}
	if observation.RiskScore < c.cfg.AuditThreshold {
		if current == nil {
			return Decision{SubjectHash: subjectHash, Reason: ReasonSafe}
		}
		decision := c.decision(subjectHash, current, now)
		decision.Reason = ReasonSafe
		decision.Blocked = false
		if inactive(current, now) {
			c.removeEntryLocked(subjectHash, current)
		}
		return decision
	}

	if current == nil {
		if len(c.entries) >= c.cfg.MaxSubjects && !c.evictOldestLocked() {
			c.rejectedCapacity++
			return Decision{SubjectHash: subjectHash, Blocked: true, Reason: ReasonCapacity}
		}
		current = &entry{}
		c.entries[subjectHash] = current
		current.element = c.evictable.PushBack(subjectHash)
	}
	repeatCount := len(current.hits) + 1
	multiplier := math.Pow(c.cfg.RepeatMultiplier, float64(repeatCount-1))
	if multiplier > c.cfg.MaxMultiplier {
		multiplier = c.cfg.MaxMultiplier
	}
	added := float64(observation.RiskScore) * multiplier
	if requestHash != "" && len(current.hits) >= maxHitsPerSubject {
		// Keep every idempotency receipt that is still inside the risk window.
		// If the bounded history is full, fail closed for a new risky hash rather
		// than evicting a receipt and allowing an old retry to add risk again.
		decision := c.decision(subjectHash, current, now)
		decision.Blocked = true
		decision.Reason = ReasonCapacity
		return decision
	}
	if len(current.hits) >= maxHitsPerSubject {
		// Conservatively combine the two oldest hits at the later timestamp.
		// This bounds adversarial memory use and can only decay more slowly than
		// the exact representation near the oldest hit's expiry.
		current.hits[1].score += current.hits[0].score
		copy(current.hits, current.hits[1:])
		current.hits = current.hits[:len(current.hits)-1]
	}
	current.hits = append(current.hits, hit{at: now, score: added, requestHash: requestHash})
	if current.element != nil {
		c.evictable.MoveToBack(current.element)
	}
	score := c.score(current, now)

	reason := ReasonRisk
	blocked := false
	if current.manualBlocked || score >= c.cfg.ManualBlockScore {
		if !current.manualBlocked {
			current.manualBlocked = true
			c.manualSubjects++
			if current.element != nil {
				c.evictable.Remove(current.element)
				current.element = nil
			}
		}
		blocked = true
		reason = ReasonManualBlock
	} else if now.Before(current.cooldownUntil) || score >= c.cfg.CooldownScore {
		blocked = true
		reason = ReasonCooldown
		if !now.Before(current.cooldownUntil) {
			current.cooldownUntil = now.Add(c.cfg.Cooldown)
		}
	}

	return Decision{
		SubjectHash:   subjectHash,
		Blocked:       blocked,
		Reason:        reason,
		Score:         score,
		AddedScore:    added,
		Multiplier:    multiplier,
		CooldownUntil: current.cooldownUntil,
		ManualBlocked: current.manualBlocked,
		RepeatCount:   repeatCount,
	}
}

// nonAccumulatingDecisionLocked performs bounded expiry maintenance but never
// allocates state or adds a hit, receipt, or multiplier. Scores below the audit
// threshold retain the Controller's clean-request contract and remain safe
// even when an existing cooldown or manual block is reported in the metadata.
func (c *Controller) nonAccumulatingDecisionLocked(subjectHash string, riskScore int, now time.Time) Decision {
	c.cleanupOldestLocked(now, maintenanceBatch)
	current := c.entries[subjectHash]
	if current == nil {
		return Decision{SubjectHash: subjectHash, Reason: ReasonSafe}
	}
	c.prune(current, now)
	if inactive(current, now) {
		c.removeEntryLocked(subjectHash, current)
		return Decision{SubjectHash: subjectHash, Reason: ReasonSafe}
	}
	decision := c.decision(subjectHash, current, now)
	if riskScore < c.cfg.AuditThreshold {
		decision.Reason = ReasonSafe
		decision.Blocked = false
		return decision
	}
	switch {
	case current.manualBlocked:
		decision.Blocked = true
		decision.Reason = ReasonManualBlock
	case now.Before(current.cooldownUntil):
		decision.Blocked = true
		decision.Reason = ReasonCooldown
	default:
		decision.Reason = ReasonSafe
	}
	return decision
}

// Snapshot returns a decayed snapshot and removes expired inactive state.
func (c *Controller) Snapshot(subjectHash string) (State, bool) {
	if c == nil || !validSubjectHash(subjectHash) {
		return State{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled {
		return State{}, false
	}
	now := c.cfg.Now().UTC()
	c.cleanupOldestLocked(now, maintenanceBatch)
	current, ok := c.entries[subjectHash]
	if !ok {
		return State{}, false
	}
	c.prune(current, now)
	if inactive(current, now) {
		c.removeEntryLocked(subjectHash, current)
		return State{}, false
	}
	return c.state(subjectHash, current, now), true
}

// Unblock clears manual, cooldown, and rolling history so the next risky event
// starts from a clean state.
func (c *Controller) Unblock(subjectHash string) bool {
	if c == nil || !validSubjectHash(subjectHash) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[subjectHash]; !ok {
		return false
	}
	c.removeEntryLocked(subjectHash, c.entries[subjectHash])
	return true
}

// Count returns the number of currently allocated subject entries.
func (c *Controller) Count() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Enabled {
		c.cleanupOldestLocked(c.cfg.Now().UTC(), maintenanceBatch)
	}
	return len(c.entries)
}

// Stats returns a bounded-maintenance capacity snapshot without scanning the
// complete subject map.
func (c *Controller) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Enabled {
		c.cleanupOldestLocked(c.cfg.Now().UTC(), maintenanceBatch)
	}
	return Stats{
		Enabled:          c.cfg.Enabled,
		Subjects:         len(c.entries),
		MaxSubjects:      c.cfg.MaxSubjects,
		ManualBlocked:    c.manualSubjects,
		Evicted:          c.evicted,
		RejectedCapacity: c.rejectedCapacity,
	}
}

// cleanupOldestLocked performs at most budget inspections. Non-manual entries
// are kept in least-recent-risk order. A fixed prefix is inspected because an
// older entry can still be active due to cooldown while a later entry has
// expired. Manual blocks never enter this list.
func (c *Controller) cleanupOldestLocked(now time.Time, budget int) {
	for inspected, candidate := 0, c.evictable.Front(); inspected < budget && candidate != nil; inspected++ {
		next := candidate.Next()
		subjectHash, ok := candidate.Value.(string)
		if !ok {
			c.evictable.Remove(candidate)
			candidate = next
			continue
		}
		current, ok := c.entries[subjectHash]
		if !ok || current.element != candidate || current.manualBlocked {
			c.evictable.Remove(candidate)
			if ok && current.element == candidate {
				current.element = nil
			}
			candidate = next
			continue
		}
		c.prune(current, now)
		if inactive(current, now) {
			c.removeEntryLocked(subjectHash, current)
		}
		candidate = next
	}
}

// evictOldestLocked evicts exactly one non-manual subject, if available.
func (c *Controller) evictOldestLocked() bool {
	for {
		front := c.evictable.Front()
		if front == nil {
			return false
		}
		subjectHash, ok := front.Value.(string)
		if !ok {
			c.evictable.Remove(front)
			continue
		}
		current, ok := c.entries[subjectHash]
		if !ok || current.element != front || current.manualBlocked {
			c.evictable.Remove(front)
			if ok && current.element == front {
				current.element = nil
			}
			continue
		}
		c.removeEntryLocked(subjectHash, current)
		c.evicted++
		return true
	}
}

func (c *Controller) removeEntryLocked(subjectHash string, current *entry) {
	if current == nil {
		return
	}
	if current.element != nil {
		c.evictable.Remove(current.element)
		current.element = nil
	}
	if current.manualBlocked {
		c.manualSubjects--
		if c.manualSubjects < 0 {
			c.manualSubjects = 0
		}
	}
	delete(c.entries, subjectHash)
}

func (c *Controller) decision(subjectHash string, current *entry, now time.Time) Decision {
	return Decision{
		SubjectHash:   subjectHash,
		Score:         c.score(current, now),
		CooldownUntil: current.cooldownUntil,
		ManualBlocked: current.manualBlocked,
		RepeatCount:   len(current.hits),
	}
}

func (c *Controller) state(subjectHash string, current *entry, now time.Time) State {
	return State{
		SubjectHash:   subjectHash,
		Score:         c.score(current, now),
		CooldownUntil: current.cooldownUntil,
		ManualBlocked: current.manualBlocked,
		HitCount:      len(current.hits),
	}
}

func (c *Controller) prune(current *entry, now time.Time) {
	kept := current.hits[:0]
	for _, item := range current.hits {
		if age := now.Sub(item.at); age < c.cfg.Window {
			kept = append(kept, item)
		}
	}
	current.hits = kept
	if !current.cooldownUntil.IsZero() && !now.Before(current.cooldownUntil) {
		current.cooldownUntil = time.Time{}
	}
}

func (c *Controller) score(current *entry, now time.Time) float64 {
	total := 0.0
	window := float64(c.cfg.Window)
	for _, item := range current.hits {
		age := now.Sub(item.at)
		if age < 0 {
			age = 0
		}
		factor := 1 - float64(age)/window
		if factor > 0 {
			total += item.score * factor
		}
	}
	return total
}

func inactive(current *entry, now time.Time) bool {
	return len(current.hits) == 0 && !current.manualBlocked && !now.Before(current.cooldownUntil)
}

func validateConfig(cfg Config) error {
	if cfg.Window <= 0 {
		return errors.New("subject: risk window must be positive")
	}
	if cfg.AuditThreshold <= 0 {
		return errors.New("subject: audit threshold must be positive")
	}
	if !finitePositive(cfg.CooldownScore) {
		return errors.New("subject: cooldown score must be positive and finite")
	}
	if !finitePositive(cfg.ManualBlockScore) || cfg.ManualBlockScore <= cfg.CooldownScore {
		return errors.New("subject: manual block score must be finite and greater than cooldown score")
	}
	if cfg.Cooldown <= 0 {
		return errors.New("subject: cooldown duration must be positive")
	}
	if math.IsNaN(cfg.RepeatMultiplier) || math.IsInf(cfg.RepeatMultiplier, 0) || cfg.RepeatMultiplier < 1 {
		return errors.New("subject: repeat multiplier must be finite and at least 1")
	}
	if math.IsNaN(cfg.MaxMultiplier) || math.IsInf(cfg.MaxMultiplier, 0) || cfg.MaxMultiplier < cfg.RepeatMultiplier {
		return fmt.Errorf("subject: maximum multiplier must be finite and at least %.3g", cfg.RepeatMultiplier)
	}
	if cfg.MaxSubjects < 1 {
		return errors.New("subject: maximum subjects must be positive")
	}
	return nil
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxSubjects == 0 {
		cfg.MaxSubjects = DefaultMaxSubjects
	}
	if cfg.MaxSubjects < 0 {
		return Config{}, errors.New("subject: maximum subjects must not be negative")
	}
	if cfg.Enabled {
		if err := validateConfig(cfg); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func finitePositive(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validSubjectHash(value string) bool {
	return validDigest(value, "hmac-sha256:")
}
