// Package audit stores a fixed, privacy-minimal security event schema. Request
// bodies, prompts, headers, and plaintext credentials are not representable by
// Event and therefore cannot accidentally be handed to the store.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	explanationpkg "github.com/yujianwudi/cyber-abuse-guard/internal/explanation"
)

const (
	requestHashDomain = "cyber-abuse-guard/audit/request/v1\x00"
	modelHashDomain   = "cyber-abuse-guard/audit/model/v1\x00"
	modelHashPrefix   = "sha256-model-v1:"

	// SourceFormatUnknown is the only value retained for caller-supplied source
	// formats outside the fixed CPA provider enum.
	SourceFormatUnknown          = "unknown"
	SourceFormatCodexAlphaSearch = "codex-alpha-search"
)

// Event is the complete persistent audit schema. Keep this type deliberately
// boring: adding request text, arbitrary metadata, or headers would violate the
// package's privacy boundary.
type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Mode        string    `json:"mode"`
	Category    string    `json:"category,omitempty"`
	RiskScore   int       `json:"risk_score"`
	RuleIDs     []string  `json:"rule_ids,omitempty"`
	RequestHash string    `json:"request_hash,omitempty"`
	SubjectHash string    `json:"subject_hash,omitempty"`
	// Model is either empty or a domain-separated SHA-256 digest. The caller-
	// controlled model name is never retained in a prepared audit event.
	Model            string `json:"model,omitempty"`
	SourceFormat     string `json:"source_format,omitempty"`
	Stream           bool   `json:"stream"`
	TextBytesScanned int    `json:"text_bytes_scanned"`
	Classifier       string `json:"classifier,omitempty"`
	Decision         string `json:"decision"`
	Coverage         string `json:"coverage"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	Scanner          string `json:"scanner"`
	LatencyUS        int64  `json:"latency_us"`
	// DecisionExplanation is a bounded, identifier-only explanation of the
	// winning decision. It deliberately has no text, span, offset, arbitrary
	// metadata, or map field capable of carrying request fragments.
	DecisionExplanation *DecisionExplanation `json:"decision_explanation,omitempty"`
}

// ScoreComponent is one bounded scoring dimension. Dimension and EvidenceIDs
// are stable implementation identifiers, never matched text or request spans.
type ScoreComponent struct {
	Dimension   string   `json:"dimension"`
	Points      int      `json:"points"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// DecisionExplanation is the privacy-safe persisted explanation contract used
// by audit and protected management surfaces. Keep it closed and scalar: do not
// add prompt text, matched fragments, arbitrary metadata, field paths, offsets,
// or provider payloads.
type DecisionExplanation struct {
	WinningRuleID           string           `json:"winning_rule_id,omitempty"`
	WinningCategory         string           `json:"winning_category,omitempty"`
	ScoreBreakdown          []ScoreComponent `json:"score_breakdown,omitempty"`
	CorePredicateComplete   bool             `json:"core_predicate_complete"`
	EvidenceDimensionMask   uint64           `json:"evidence_dimension_mask"`
	EvidenceOccurrenceCount int              `json:"evidence_occurrence_count"`
	EvidenceSegmentCount    int              `json:"evidence_segment_count"`
	WinningRole             string           `json:"winning_role,omitempty"`
	WinningProvenance       string           `json:"winning_provenance,omitempty"`
	CurrentTurnEvidence     bool             `json:"current_turn_evidence"`
	CrossSegmentComposition string           `json:"cross_segment_composition,omitempty"`
	ReferentLinkUsed        bool             `json:"referent_link_used"`
	QuotedOrInertSuppressed bool             `json:"quoted_or_inert_suppressed"`
	ContextAdjustment       int              `json:"context_adjustment"`
	HardFloorApplied        bool             `json:"hard_floor_applied"`
	HardFloorReason         string           `json:"hard_floor_reason,omitempty"`
}

// HashRequest produces the one-way request correlation value accepted by an
// Event. Callers should discard the request bytes after classification.
func HashRequest(request []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(requestHashDomain))
	_, _ = hash.Write(request)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// HashModel returns the deterministic, domain-separated correlation value used
// for caller-controlled requested model names. It deliberately uses a distinct
// domain and output prefix from HashRequest so equal inputs cannot be correlated
// across the two audit fields.
func HashModel(model string) string {
	if model == "" {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(modelHashDomain))
	_, _ = hash.Write([]byte(model))
	return modelHashPrefix + hex.EncodeToString(hash.Sum(nil))
}

// CanonicalSourceFormat converts CPA provider names to the fixed values that
// may cross the audit privacy boundary. The Anthropic alias maps to CPA's
// canonical "claude" value; all other inputs collapse to "unknown".
func CanonicalSourceFormat(sourceFormat string) string {
	switch strings.ToLower(strings.TrimSpace(sourceFormat)) {
	case "openai":
		return "openai"
	case "openai-response":
		return "openai-response"
	case "interactions":
		return "interactions"
	case SourceFormatCodexAlphaSearch:
		return SourceFormatCodexAlphaSearch
	case "openai-image":
		return "openai-image"
	case "openai-video":
		return "openai-video"
	case "claude", "anthropic":
		return "claude"
	case "gemini":
		return "gemini"
	default:
		return SourceFormatUnknown
	}
}

func prepareEvent(event Event, now time.Time) (Event, error) {
	if event.ID == "" {
		id, err := randomID()
		if err != nil {
			return Event{}, err
		}
		event.ID = id
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = now.UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	event.RuleIDs = append([]string(nil), event.RuleIDs...)
	event.DecisionExplanation = cloneDecisionExplanation(event.DecisionExplanation)
	event.Model = privacySafeModel(event.Model)
	event.SourceFormat = privacySafeSourceFormat(event.SourceFormat)
	// Source compatibility for pre-Round6 callers and migration tests. New
	// routing code always supplies explicit fixed values.
	if event.Decision == "" {
		event.Decision = "legacy_unspecified"
	}
	if event.Coverage == "" {
		event.Coverage = "legacy_unknown"
	}
	if event.Scanner == "" {
		event.Scanner = "legacy"
	}
	if err := validateEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func validateEvent(event Event) error {
	if err := validateField("id", event.ID, 128, false); err != nil {
		return err
	}
	if event.Timestamp.Year() < 1970 || event.Timestamp.Year() > 9999 {
		return errors.New("audit: invalid event timestamp")
	}
	if !oneOf(event.Action, "allow", "observe", "audit", "block", "cooldown") {
		return fmt.Errorf("audit: invalid action %q", event.Action)
	}
	if !oneOf(event.Mode, "off", "observe", "audit", "balanced", "strict") {
		return fmt.Errorf("audit: invalid mode %q", event.Mode)
	}
	for name, field := range map[string]struct {
		value string
		limit int
	}{
		"category":          {event.Category, 128},
		"classifier":        {event.Classifier, 64},
		"decision":          {event.Decision, 96},
		"coverage":          {event.Coverage, 32},
		"incomplete_reason": {event.IncompleteReason, 64},
		"scanner":           {event.Scanner, 64},
	} {
		if err := validateField(name, field.value, field.limit, true); err != nil {
			return err
		}
	}
	if !validDecision(event.Decision) {
		return fmt.Errorf("audit: invalid decision %q", event.Decision)
	}
	if !oneOf(event.Coverage, "complete", "incomplete", "legacy_unknown") {
		return fmt.Errorf("audit: invalid coverage %q", event.Coverage)
	}
	if !validIncompleteReason(event.IncompleteReason) {
		return fmt.Errorf("audit: invalid incomplete_reason %q", event.IncompleteReason)
	}
	switch event.Coverage {
	case "complete":
		if event.IncompleteReason != "" {
			return errors.New("audit: complete coverage must not include incomplete_reason")
		}
	case "incomplete":
		if event.IncompleteReason == "" {
			return errors.New("audit: incomplete coverage requires incomplete_reason")
		}
	}
	if !oneOf(event.Scanner, "legacy", "streaming-scanner-v1") {
		return fmt.Errorf("audit: invalid scanner %q", event.Scanner)
	}
	if event.Model != "" && !validDigest(event.Model, modelHashPrefix) {
		return errors.New("audit: model is not a domain-separated SHA-256 correlation value")
	}
	if event.SourceFormat != "" && !oneOf(event.SourceFormat, "openai", "openai-response", "interactions", SourceFormatCodexAlphaSearch, "openai-image", "openai-video", "claude", "gemini", SourceFormatUnknown) {
		return errors.New("audit: source_format is not a canonical provider value")
	}
	if event.RiskScore < 0 || event.RiskScore > 1_000_000 {
		return errors.New("audit: risk score is outside the supported range")
	}
	if event.TextBytesScanned < 0 || event.TextBytesScanned > 1<<30 {
		return errors.New("audit: text_bytes_scanned is outside the supported range")
	}
	if event.LatencyUS < 0 {
		return errors.New("audit: latency_us must not be negative")
	}
	if err := validateDecisionExplanation(event.DecisionExplanation); err != nil {
		return err
	}
	if err := validateDecisionExplanationEventConsistency(event); err != nil {
		return err
	}
	if len(event.RuleIDs) > 128 {
		return errors.New("audit: too many rule IDs")
	}
	for _, ruleID := range event.RuleIDs {
		if err := validateField("rule_id", ruleID, 128, false); err != nil {
			return err
		}
	}
	if event.RequestHash != "" && !validDigest(event.RequestHash, "sha256:") {
		return errors.New("audit: request_hash is not a SHA-256 correlation value")
	}
	if event.SubjectHash != "" && !validDigest(event.SubjectHash, "hmac-sha256:") {
		return errors.New("audit: subject_hash is not an HMAC-SHA256 correlation value")
	}
	return nil
}

// validateDecisionExplanationEventConsistency binds the structured
// explanation to the audit row it explains. Both write admission and SQLite
// reads use this check so a corrupt or externally modified row cannot present
// a category, winning rule, score, or context adjustment that contradicts the
// persisted top-level decision.
func validateDecisionExplanationEventConsistency(event Event) error {
	if event.DecisionExplanation == nil {
		return nil
	}
	var finalScore *int
	var contextAdjustment *int
	for index := range event.DecisionExplanation.ScoreBreakdown {
		component := &event.DecisionExplanation.ScoreBreakdown[index]
		switch component.Dimension {
		case "final_score":
			finalScore = &component.Points
		case "context_adjustment":
			contextAdjustment = &component.Points
		}
	}
	if finalScore == nil {
		return errors.New("audit: decision explanation requires final_score")
	}
	if *finalScore != event.RiskScore {
		return errors.New("audit: decision explanation final_score does not match risk_score")
	}
	if contextAdjustment == nil {
		return errors.New("audit: decision explanation requires context_adjustment")
	}
	if *contextAdjustment != event.DecisionExplanation.ContextAdjustment {
		return errors.New("audit: decision explanation context_adjustment is inconsistent")
	}
	if event.Category != "" {
		if event.DecisionExplanation.WinningCategory == "" {
			return errors.New("audit: decision explanation requires winning_category when category is logged")
		}
		if event.Category != event.DecisionExplanation.WinningCategory {
			return errors.New("audit: decision explanation winning_category does not match category")
		}
	} else if event.DecisionExplanation.WinningCategory != "" {
		return errors.New("audit: decision explanation winning_category bypasses category logging policy")
	}
	if len(event.RuleIDs) != 0 {
		if event.DecisionExplanation.WinningRuleID == "" {
			return errors.New("audit: decision explanation requires winning_rule_id when rule_ids are logged")
		}
		if countExact(event.RuleIDs, event.DecisionExplanation.WinningRuleID) != 1 {
			return errors.New("audit: decision explanation winning_rule_id must occur exactly once in rule_ids")
		}
	} else if event.DecisionExplanation.WinningRuleID != "" {
		return errors.New("audit: decision explanation winning_rule_id bypasses rule_ids logging policy")
	}
	return nil
}

func countExact(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

func cloneDecisionExplanation(source *DecisionExplanation) *DecisionExplanation {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.ScoreBreakdown = make([]ScoreComponent, len(source.ScoreBreakdown))
	for index, component := range source.ScoreBreakdown {
		cloned.ScoreBreakdown[index] = component
		cloned.ScoreBreakdown[index].EvidenceIDs = append([]string(nil), component.EvidenceIDs...)
	}
	return &cloned
}

func validateDecisionExplanation(explanation *DecisionExplanation) error {
	if explanation == nil {
		return nil
	}
	for name, value := range map[string]string{
		"winning_rule_id":   explanation.WinningRuleID,
		"winning_category":  explanation.WinningCategory,
		"hard_floor_reason": explanation.HardFloorReason,
	} {
		if value != "" && !validStableCode(value, 128) {
			return fmt.Errorf("audit: decision explanation %s is not a stable identifier", name)
		}
	}
	if explanation.WinningRole != "" && !oneOf(explanation.WinningRole,
		"unknown", "user", "system", "assistant", "tool") {
		return errors.New("audit: decision explanation winning_role is unsupported")
	}
	if explanation.WinningProvenance != "" && !oneOf(explanation.WinningProvenance,
		"unknown", "content", "tool_payload") {
		return errors.New("audit: decision explanation winning_provenance is unsupported")
	}
	if explanation.CrossSegmentComposition != "" && !oneOf(explanation.CrossSegmentComposition,
		"none", "bounded_same_scope", "explicit_referent") {
		return errors.New("audit: decision explanation cross_segment_composition is unsupported")
	}
	if explanation.EvidenceOccurrenceCount < 0 || explanation.EvidenceOccurrenceCount > 1_000_000 {
		return errors.New("audit: decision explanation evidence_occurrence_count is outside the supported range")
	}
	if explanation.EvidenceSegmentCount < 0 || explanation.EvidenceSegmentCount > 1_000_000 {
		return errors.New("audit: decision explanation evidence_segment_count is outside the supported range")
	}
	if explanation.ContextAdjustment < -1_000_000 || explanation.ContextAdjustment > 1_000_000 {
		return errors.New("audit: decision explanation context_adjustment is outside the supported range")
	}
	if len(explanation.ScoreBreakdown) > 32 {
		return errors.New("audit: decision explanation has too many score components")
	}
	seenDimensions := make(map[string]struct{}, len(explanation.ScoreBreakdown))
	seenEvidenceDimensions := make(map[string]string)
	for _, component := range explanation.ScoreBreakdown {
		if !oneOf(component.Dimension,
			"core_predicate_score", "qualifier_score", "scope_coherence_score",
			"ownership_score", "active_directive_score", "context_adjustment",
			"contradiction_adjustment", "final_score") {
			return errors.New("audit: decision explanation score dimension is unsupported")
		}
		if _, duplicate := seenDimensions[component.Dimension]; duplicate {
			return fmt.Errorf("audit: decision explanation score dimension %q is duplicated", component.Dimension)
		}
		seenDimensions[component.Dimension] = struct{}{}
		if component.Points < -1_000_000 || component.Points > 1_000_000 {
			return errors.New("audit: decision explanation score component is outside the supported range")
		}
		if len(component.EvidenceIDs) > 128 {
			return errors.New("audit: decision explanation score component has too many evidence IDs")
		}
		seenEvidence := make(map[string]struct{}, len(component.EvidenceIDs))
		for _, evidenceID := range component.EvidenceIDs {
			if !validStableCode(evidenceID, 128) {
				return errors.New("audit: decision explanation evidence ID is not a stable identifier")
			}
			if _, duplicate := seenEvidence[evidenceID]; duplicate {
				return fmt.Errorf("audit: decision explanation evidence ID %q is duplicated within one dimension", evidenceID)
			}
			seenEvidence[evidenceID] = struct{}{}
			if previousDimension, duplicate := seenEvidenceDimensions[evidenceID]; duplicate {
				return fmt.Errorf(
					"audit: decision explanation evidence ID %q is assigned to both %q and %q",
					evidenceID, previousDimension, component.Dimension,
				)
			}
			seenEvidenceDimensions[evidenceID] = component.Dimension
		}
	}
	if explanation.HardFloorApplied {
		if explanation.HardFloorReason == "" {
			return errors.New("audit: applied hard floor requires a stable reason")
		}
		if !explanationpkg.IsKnownAppliedHardFloorReason(explanationpkg.HardFloorReason(explanation.HardFloorReason)) {
			return errors.New("audit: applied hard floor reason is unsupported")
		}
	}
	if !explanation.HardFloorApplied && explanation.HardFloorReason != "" {
		return errors.New("audit: hard floor reason requires hard_floor_applied")
	}
	encoded, err := json.Marshal(explanation)
	if err != nil {
		return fmt.Errorf("audit: encode decision explanation: %w", err)
	}
	if len(encoded) > 32768 {
		return errors.New("audit: decision explanation exceeds 32768 bytes")
	}
	return nil
}

func validStableCode(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func validDecision(value string) bool {
	return oneOf(value,
		"legacy_unspecified",
		"allow_clean",
		"observe_malicious_text", "audit_malicious_text", "block_malicious_text",
		"observe_suspicious_text", "audit_suspicious_text",
		"observe_incomplete_inspection", "audit_incomplete_inspection",
		"allow_due_to_incomplete_inspection", "block_due_to_incomplete_inspection",
		"allow_incomplete_inspection_off", "block_verified_hard_policy_under_incomplete_inspection",
		"observe_opaque_media", "audit_opaque_media", "allow_with_opaque_media_audit", "block_opaque_media",
		"audit_subject_risk", "block_subject_risk",
		"block_unknown_source_format", "cooldown_subject_risk")
}

func validIncompleteReason(value string) bool {
	return oneOf(value, "", "parse_error", "scan_limit", "rpc_body_limit", "json_depth_limit",
		"text_part_limit", "role_attribution", "classification_chunk_limit", "total_text_limit", "multipart_limit",
		"multipart_schema", "tool_schema", "deferred_text_limit", "unsupported_content_type",
		"incomplete_inspection")
}

// privacySafeModel is also used when reading legacy databases so management
// and export surfaces never echo historical plaintext model values.
func privacySafeModel(model string) string {
	if model == "" || validDigest(model, modelHashPrefix) {
		return model
	}
	return HashModel(model)
}

func privacySafeSourceFormat(sourceFormat string) string {
	if sourceFormat == "" {
		return ""
	}
	return CanonicalSourceFormat(sourceFormat)
}

func validateField(name, value string, limit int, emptyOK bool) error {
	if value == "" {
		if emptyOK {
			return nil
		}
		return fmt.Errorf("audit: %s must not be empty", name)
	}
	if len(value) > limit {
		return fmt.Errorf("audit: %s exceeds %d bytes", name, limit)
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return fmt.Errorf("audit: %s contains an unsafe character", name)
		}
	}
	return nil
}

func validDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("audit: generate event ID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
