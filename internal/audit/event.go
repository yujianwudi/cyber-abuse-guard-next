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

	explanationpkg "github.com/yujianwudi/cyber-abuse-guard-next/internal/explanation"
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

const (
	decisionKindLegacyUnspecified          = "legacy_unspecified"
	decisionKindAllowClean                 = "allow_clean"
	decisionKindAuditIneligibleRisk        = "audit_ineligible_risk"
	decisionKindAuditEligibleMaliciousText = "audit_eligible_malicious_text"
	decisionKindBlockMaliciousText         = "block_malicious_text"
	decisionKindBlockIncomplete            = "block_incomplete_inspection"
	decisionKindBlockOpaqueMedia           = "block_opaque_media"
	decisionKindBlockSubjectRisk           = "block_subject_risk"
	decisionKindAuditCSAMText              = "audit_csam_text"
	decisionKindBlockCSAMText              = "block_csam_text"
)

const (
	// DecisionExplanationSchemaNone is used when an event deliberately has no
	// structured explanation (for example, a clean allow or a migrated legacy
	// row that never carried one).
	DecisionExplanationSchemaNone = "none"
	// DecisionExplanationSchemaV1 identifies the read-only Round 8 flat
	// explanation contract. New writes never emit v1, but schema-v6 readers must
	// continue to decode rows migrated from schema v5.
	DecisionExplanationSchemaV1 = "decision-explanation-v1"
	// DecisionExplanationSchemaV2 is the Round 9 closed discriminated union.
	DecisionExplanationSchemaV2 = "decision-explanation-v2"

	decisionExplanationKindMalicious  = "malicious"
	decisionExplanationKindIncomplete = "incomplete"
	decisionExplanationKindOpaque     = "opaque_media"
	decisionExplanationKindSubject    = "subject_risk"
	decisionExplanationKindCSAMText   = "csam_text"

	opaqueMediaExplanationReason = "opaque_media_present"
)

const (
	eligibilityReasonIncompleteInspection = "incomplete_inspection"
	eligibilityReasonUntrustedOwnership   = "untrusted_ownership"
	eligibilityReasonNoCurrentDirective   = "no_current_directive"
	eligibilityReasonQuotedOrAnalytical   = "quoted_or_analytical"
	eligibilityReasonDefensivePurpose     = "defensive_purpose"
	eligibilityReasonAuthorizedOwned      = "authorized_owned_operation"
	eligibilityReasonAmbiguousCore        = "ambiguous_core"
	eligibilityReasonCrossScope           = "cross_scope_composition"
	eligibilityReasonOperationalAbsent    = "operational_core_absent"
	eligibilityReasonExplicitMalice       = "eligible_explicit_malice"
)

// EnforcementScope is the closed, content-free reason an eligible malicious
// candidate may be enforced at the request boundary. It records classifier
// provenance without persisting request text, provider paths, or offsets.
type EnforcementScope string

const (
	EnforcementScopeNone               EnforcementScope = ""
	EnforcementScopeCurrentUser        EnforcementScope = "current_user"
	EnforcementScopeRequestLocalSystem EnforcementScope = "request_local_system"
	EnforcementScopeRequestLocalTool   EnforcementScope = "request_local_tool"
)

// ExplanationRelationType is the closed, content-free relation that joined a
// winning carrier to the actor whose current directive made it enforceable.
type ExplanationRelationType string

const (
	ExplanationRelationNone                     ExplanationRelationType = ""
	ExplanationRelationHistoricalToolActivation ExplanationRelationType = "historical_tool_activation"
)

// ExplanationEnforcementOwner identifies the trusted actor supplying the
// execution act. It never changes the role or evidence ownership of the carrier.
type ExplanationEnforcementOwner string

const (
	ExplanationEnforcementOwnerNone               ExplanationEnforcementOwner = ""
	ExplanationEnforcementOwnerCurrentTrustedUser ExplanationEnforcementOwner = "current_trusted_user"
)

const (
	eligibilityFlagIncompleteInspection uint64 = 1 << iota
	eligibilityFlagUntrustedOwnership
	eligibilityFlagNoCurrentDirective
	eligibilityFlagQuotedOrAnalytical
	eligibilityFlagDefensivePurpose
	eligibilityFlagAuthorizedOwned
	eligibilityFlagAmbiguousCore
	eligibilityFlagCrossScope
	eligibilityFlagOperationalAbsent
	eligibilityFlagExplicitMalice
)

const knownEligibilityReasonFlags = eligibilityFlagIncompleteInspection |
	eligibilityFlagUntrustedOwnership |
	eligibilityFlagNoCurrentDirective |
	eligibilityFlagQuotedOrAnalytical |
	eligibilityFlagDefensivePurpose |
	eligibilityFlagAuthorizedOwned |
	eligibilityFlagAmbiguousCore |
	eligibilityFlagCrossScope |
	eligibilityFlagOperationalAbsent |
	eligibilityFlagExplicitMalice

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
	Model             string `json:"model,omitempty"`
	SourceFormat      string `json:"source_format,omitempty"`
	Stream            bool   `json:"stream"`
	TextBytesScanned  int    `json:"text_bytes_scanned"`
	Classifier        string `json:"classifier,omitempty"`
	Decision          string `json:"decision"`
	DecisionKind      string `json:"decision_kind"`
	ExplanationSchema string `json:"explanation_schema"`
	Coverage          string `json:"coverage"`
	IncompleteReason  string `json:"incomplete_reason,omitempty"`
	Scanner           string `json:"scanner"`
	LatencyUS         int64  `json:"latency_us"`
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
	// Kind discriminates the v2 closed union. Malicious candidate explanations
	// use the existing bounded score/eligibility fields below. The other three
	// variants use only their fixed branch field and are forbidden from carrying
	// a classifier category, rule, score breakdown, or eligibility state.
	Kind                       string                      `json:"kind,omitempty"`
	IncompleteInspectionReason string                      `json:"incomplete_inspection_reason,omitempty"`
	OpaqueMediaReason          string                      `json:"opaque_media_reason,omitempty"`
	SubjectRiskAction          string                      `json:"subject_risk_action,omitempty"`
	WinningRuleID              string                      `json:"winning_rule_id,omitempty"`
	WinningCategory            string                      `json:"winning_category,omitempty"`
	ScoreBreakdown             []ScoreComponent            `json:"score_breakdown,omitempty"`
	CorePredicateComplete      bool                        `json:"core_predicate_complete"`
	EvidenceDimensionMask      uint64                      `json:"evidence_dimension_mask"`
	EvidenceOccurrenceCount    int                         `json:"evidence_occurrence_count"`
	EvidenceSegmentCount       int                         `json:"evidence_segment_count"`
	WinningRole                string                      `json:"winning_role,omitempty"`
	WinningProvenance          string                      `json:"winning_provenance,omitempty"`
	CurrentTurnEvidence        bool                        `json:"current_turn_evidence"`
	CrossSegmentComposition    string                      `json:"cross_segment_composition,omitempty"`
	ReferentLinkUsed           bool                        `json:"referent_link_used"`
	RelationType               ExplanationRelationType     `json:"relation_type,omitempty"`
	EnforcementOwner           ExplanationEnforcementOwner `json:"enforcement_owner,omitempty"`
	QuotedOrInertSuppressed    bool                        `json:"quoted_or_inert_suppressed"`
	ContextAdjustment          int                         `json:"context_adjustment"`
	HardFloorApplied           bool                        `json:"hard_floor_applied"`
	HardFloorReason            string                      `json:"hard_floor_reason,omitempty"`
	BlockEligible              bool                        `json:"block_eligible"`
	PrimaryEligibilityReason   string                      `json:"primary_eligibility_reason,omitempty"`
	EligibilityReasonFlags     uint64                      `json:"eligibility_reason_flags"`
	InspectionComplete         bool                        `json:"inspection_complete"`
	EvidenceOwnedByCurrentUser bool                        `json:"evidence_owned_by_current_user"`
	EnforcementScope           EnforcementScope            `json:"enforcement_scope,omitempty"`
	CurrentExecutionActProven  bool                        `json:"current_execution_act_proven"`
	HarmfulCoreComplete        bool                        `json:"harmful_core_complete"`
	OperationallyActionable    bool                        `json:"operationally_actionable"`
	AuthorizationClaimState    string                      `json:"authorization_claim_state,omitempty"`
	ExplicitVictimOrNonconsent bool                        `json:"explicit_victim_or_nonconsent"`
	CovertAcquisition          bool                        `json:"covert_acquisition"`
	ExfiltrationOrTakeover     bool                        `json:"exfiltration_or_takeover"`
	MaliciousPersistence       bool                        `json:"malicious_persistence"`
	DestructiveOutcome         bool                        `json:"destructive_outcome"`
	SecurityControlEvasion     bool                        `json:"security_control_evasion"`
	DefensiveScopeConflict     bool                        `json:"defensive_scope_conflict"`
	QuotedOrAnalyticalScope    bool                        `json:"quoted_or_analytical_scope"`
	CrossScopeComposition      bool                        `json:"cross_scope_composition"`
	ReferentProofComplete      bool                        `json:"referent_proof_complete"`
	EvidenceAmbiguous          bool                        `json:"evidence_ambiguous"`
}

// MarshalJSON preserves the exact Round 8 wire contract for read-only v1
// values while emitting every required boolean for the Round 9 v2 union. This
// is primarily useful for management clients and corruption tests that
// re-encode a value after reading it; durable writes still use the explicit
// explanation_schema-aware encoder.
func (explanation DecisionExplanation) MarshalJSON() ([]byte, error) {
	if explanation.Kind == "" && explanation.IncompleteInspectionReason == "" &&
		explanation.OpaqueMediaReason == "" && explanation.SubjectRiskAction == "" &&
		!hasEligibilityContract(&explanation) {
		legacy := legacyDecisionExplanationFromCurrent(&explanation)
		return json.Marshal(legacy)
	}
	type wire DecisionExplanation
	return json.Marshal(wire(explanation))
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
	if event.DecisionKind == "" {
		// Source compatibility for callers compiled before Round 9. Only the
		// current plugin router supplies an explicit canonical kind; omitted kinds
		// remain visibly legacy instead of being upgraded from score/disposition
		// text without candidate eligibility evidence.
		event.DecisionKind = decisionKindLegacyUnspecified
	}
	if err := normalizeNewDecisionExplanation(&event); err != nil {
		return Event{}, err
	}
	if err := validateNewDecisionExplanationRelation(event.DecisionExplanation); err != nil {
		return Event{}, err
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

// validateNewDecisionExplanationRelation keeps canonical writes on the current
// closed contract while decode paths remain able to read relation-free v2 rows
// produced by the pre-RT10 historical-tool implementation.
func validateNewDecisionExplanationRelation(explanation *DecisionExplanation) error {
	if explanation != nil && explanation.EnforcementScope == EnforcementScopeRequestLocalTool &&
		explanation.CurrentTurnEvidence &&
		(explanation.RelationType != ExplanationRelationHistoricalToolActivation ||
			explanation.EnforcementOwner != ExplanationEnforcementOwnerCurrentTrustedUser) {
		return errors.New("audit: new historical-tool activation explanation requires relation_type and enforcement_owner")
	}
	return nil
}

func normalizeNewDecisionExplanation(event *Event) error {
	if event == nil {
		return errors.New("audit: event is nil")
	}
	if event.DecisionExplanation != nil {
		if event.DecisionKind == decisionKindLegacyUnspecified &&
			event.DecisionExplanation.Kind == "" && !hasEligibilityContract(event.DecisionExplanation) {
			if event.ExplanationSchema == "" {
				event.ExplanationSchema = DecisionExplanationSchemaV1
			}
			if event.ExplanationSchema != DecisionExplanationSchemaV1 {
				return errors.New("audit: legacy decision explanation requires the v1 schema identity")
			}
			return nil
		}
		if event.ExplanationSchema == DecisionExplanationSchemaV1 {
			return errors.New("audit: decision-explanation-v1 is read-only for canonical Round9 decisions")
		}
		if event.DecisionExplanation.Kind == "" {
			event.DecisionExplanation.Kind = decisionExplanationKindMalicious
		}
		if event.ExplanationSchema == "" {
			event.ExplanationSchema = DecisionExplanationSchemaV2
		}
		return nil
	}

	switch event.DecisionKind {
	case decisionKindBlockIncomplete:
		event.DecisionExplanation = &DecisionExplanation{
			Kind:                       decisionExplanationKindIncomplete,
			IncompleteInspectionReason: event.IncompleteReason,
		}
		event.ExplanationSchema = DecisionExplanationSchemaV2
	case decisionKindBlockOpaqueMedia:
		event.DecisionExplanation = &DecisionExplanation{
			Kind:              decisionExplanationKindOpaque,
			OpaqueMediaReason: opaqueMediaExplanationReason,
		}
		event.ExplanationSchema = DecisionExplanationSchemaV2
	case decisionKindBlockSubjectRisk:
		event.DecisionExplanation = &DecisionExplanation{
			Kind:              decisionExplanationKindSubject,
			SubjectRiskAction: event.Action,
		}
		event.ExplanationSchema = DecisionExplanationSchemaV2
	case decisionKindAuditCSAMText, decisionKindBlockCSAMText:
		event.DecisionExplanation = &DecisionExplanation{Kind: decisionExplanationKindCSAMText}
		event.ExplanationSchema = DecisionExplanationSchemaV2
	default:
		if event.ExplanationSchema == "" {
			event.ExplanationSchema = DecisionExplanationSchemaNone
		}
	}
	return nil
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
		"category":           {event.Category, 128},
		"classifier":         {event.Classifier, 64},
		"decision":           {event.Decision, 96},
		"decision_kind":      {event.DecisionKind, 64},
		"explanation_schema": {event.ExplanationSchema, 64},
		"coverage":           {event.Coverage, 32},
		"incomplete_reason":  {event.IncompleteReason, 64},
		"scanner":            {event.Scanner, 64},
	} {
		if err := validateField(name, field.value, field.limit, true); err != nil {
			return err
		}
	}
	if !validDecision(event.Decision) {
		return fmt.Errorf("audit: invalid decision %q", event.Decision)
	}
	if !validDecisionKind(event.DecisionKind) {
		return fmt.Errorf("audit: invalid decision_kind %q", event.DecisionKind)
	}
	if !validDecisionExplanationSchema(effectiveDecisionExplanationSchema(event)) {
		return fmt.Errorf("audit: invalid explanation_schema %q", event.ExplanationSchema)
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
	if err := validateDecisionExplanationForSchema(event.DecisionExplanation, effectiveDecisionExplanationSchema(event)); err != nil {
		return err
	}
	if err := validateDecisionExplanationEventConsistency(event); err != nil {
		return err
	}
	if err := validateDecisionKindEventConsistency(event); err != nil {
		return err
	}
	if len(event.RuleIDs) > 128 {
		return errors.New("audit: too many rule IDs")
	}
	for _, ruleID := range event.RuleIDs {
		if !validStableCode(ruleID, 128) {
			return fmt.Errorf("audit: invalid stable rule_id %q", ruleID)
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

func effectiveDecisionExplanationSchema(event Event) string {
	if event.ExplanationSchema != "" {
		return event.ExplanationSchema
	}
	if event.DecisionExplanation == nil {
		return DecisionExplanationSchemaNone
	}
	if event.DecisionExplanation.Kind != "" || hasEligibilityContract(event.DecisionExplanation) {
		return DecisionExplanationSchemaV2
	}
	return DecisionExplanationSchemaV1
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
	if !isMaliciousDecisionExplanation(event.DecisionExplanation) {
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

// validateDecisionKindEventConsistency prevents transport-level safety blocks
// from masquerading as malicious-text classifier wins. Legacy rows remain
// readable under the explicit legacy_unspecified identity introduced by the v6
// migration.
func validateDecisionKindEventConsistency(event Event) error {
	explanationSchema := effectiveDecisionExplanationSchema(event)
	if err := validateDecisionKindExplanationSchema(event.DecisionKind, event.Decision, explanationSchema); err != nil {
		return err
	}
	switch event.DecisionKind {
	case decisionKindLegacyUnspecified:
		return nil
	case decisionKindAllowClean:
		if !oneOf(event.Action, "allow", "observe", "audit") || event.Decision != "allow_clean" {
			return errors.New("audit: allow_clean decision_kind requires the clean allow disposition")
		}
		if event.Coverage != "complete" || event.IncompleteReason != "" {
			return errors.New("audit: allow_clean decision_kind requires complete inspection")
		}
		if event.RiskScore != 0 || event.Category != "" || len(event.RuleIDs) != 0 {
			return errors.New("audit: allow_clean decision_kind must not carry classifier risk identifiers")
		}
		if event.DecisionExplanation != nil || explanationSchema != DecisionExplanationSchemaNone {
			return errors.New("audit: allow_clean decision_kind must not carry a decision explanation")
		}
		return nil
	case decisionKindAuditIneligibleRisk:
		return validateAuditIneligibleRiskEvent(event, explanationSchema)
	case decisionKindAuditEligibleMaliciousText:
		if !oneOf(event.Action, "observe", "audit") || !oneOf(event.Decision,
			"observe_malicious_text", "audit_malicious_text",
			"observe_suspicious_text", "audit_suspicious_text") {
			return errors.New("audit: audit_eligible_malicious_text decision_kind requires a non-blocking classifier disposition")
		}
		if event.Coverage != "complete" {
			return errors.New("audit: audit_eligible_malicious_text decision_kind requires complete inspection")
		}
		explanation := event.DecisionExplanation
		if explanationSchema != DecisionExplanationSchemaV2 || explanation == nil ||
			explanation.Kind != decisionExplanationKindMalicious || !hasEligibilityContract(explanation) ||
			!explanation.BlockEligible || explanation.PrimaryEligibilityReason != eligibilityReasonExplicitMalice {
			return errors.New("audit: audit_eligible_malicious_text decision_kind requires an eligible malicious explanation")
		}
		if event.Category == "" || explanation.WinningCategory == "" ||
			len(event.RuleIDs) == 0 || explanation.WinningRuleID == "" {
			return errors.New("audit: audit_eligible_malicious_text decision_kind requires a winning category and rule")
		}
		return nil
	case decisionKindBlockMaliciousText:
		if event.Action != "block" || event.Decision != "block_malicious_text" {
			return errors.New("audit: block_malicious_text decision_kind requires the malicious-text block disposition")
		}
		if event.Coverage != "complete" {
			return errors.New("audit: block_malicious_text decision_kind requires complete inspection")
		}
		explanation := event.DecisionExplanation
		if explanationSchema != DecisionExplanationSchemaV2 || explanation == nil ||
			explanation.Kind != decisionExplanationKindMalicious || !hasEligibilityContract(explanation) {
			return errors.New("audit: block_malicious_text decision_kind requires an eligibility explanation")
		}
		if !explanation.BlockEligible || explanation.PrimaryEligibilityReason != eligibilityReasonExplicitMalice {
			return errors.New("audit: block_malicious_text decision_kind requires an eligible malicious explanation")
		}
		if event.Category == "" || explanation.WinningCategory == "" {
			return errors.New("audit: block_malicious_text decision_kind requires a winning category")
		}
		if len(event.RuleIDs) == 0 || explanation.WinningRuleID == "" {
			return errors.New("audit: block_malicious_text decision_kind requires a winning rule")
		}
		return nil
	case decisionKindBlockIncomplete:
		if event.Action != "block" || !oneOf(event.Decision,
			"block_due_to_incomplete_inspection", "block_unknown_source_format") {
			return errors.New("audit: block_incomplete_inspection decision_kind requires the incomplete-inspection block disposition")
		}
		if event.Coverage != "incomplete" || event.IncompleteReason == "" {
			return errors.New("audit: block_incomplete_inspection decision_kind requires incomplete coverage")
		}
		if event.Category != "" && event.Category != event.IncompleteReason {
			return errors.New("audit: block_incomplete_inspection category must identify the incomplete reason")
		}
		return validateNonMaliciousBlockIdentifiers(event, decisionExplanationKindIncomplete)
	case decisionKindBlockOpaqueMedia:
		if event.Action != "block" || event.Decision != "block_opaque_media" {
			return errors.New("audit: block_opaque_media decision_kind requires the opaque-media block disposition")
		}
		if event.Category != "" && event.Category != "opaque_media" {
			return errors.New("audit: block_opaque_media category must use the opaque-media taxonomy")
		}
		return validateNonMaliciousBlockIdentifiers(event, decisionExplanationKindOpaque)
	case decisionKindBlockSubjectRisk:
		if !oneOf(event.Action, "block", "cooldown") || !oneOf(event.Decision, "block_subject_risk", "cooldown_subject_risk") {
			return errors.New("audit: block_subject_risk decision_kind requires the subject-risk block disposition")
		}
		if event.Category != "" && event.Category != "subject_risk" {
			return errors.New("audit: block_subject_risk category must use the subject-risk taxonomy")
		}
		return validateNonMaliciousBlockIdentifiers(event, decisionExplanationKindSubject)
	case decisionKindAuditCSAMText:
		if !oneOf(event.Action, "observe", "audit") ||
			!oneOf(event.Decision, "observe_csam_text", "audit_csam_text") {
			return errors.New("audit: audit_csam_text decision_kind requires a non-blocking CSAM-text disposition")
		}
		return validateCSAMTextEvent(event, explanationSchema, false)
	case decisionKindBlockCSAMText:
		if event.Action != "block" || event.Decision != "block_csam_text" {
			return errors.New("audit: block_csam_text decision_kind requires the CSAM-text block disposition")
		}
		return validateCSAMTextEvent(event, explanationSchema, true)
	default:
		return fmt.Errorf("audit: unsupported decision_kind %q", event.DecisionKind)
	}
}

// validateDecisionKindExplanationSchema is the shared compatibility contract
// for audit events and their separately persisted raw-capture metadata. Keeping
// it centralized prevents a raw-capture row from claiming a current decision
// kind while carrying a legacy or absent explanation schema.
func validateDecisionKindExplanationSchema(decisionKind, decision, explanationSchema string) error {
	switch decisionKind {
	case decisionKindLegacyUnspecified:
		if explanationSchema == DecisionExplanationSchemaV2 {
			return errors.New("audit: legacy_unspecified decision_kind must not carry a v2 explanation")
		}
		return nil
	case decisionKindAllowClean:
		if explanationSchema != DecisionExplanationSchemaNone {
			return errors.New("audit: allow_clean decision_kind requires explanation_schema none")
		}
		return nil
	case decisionKindAuditIneligibleRisk:
		switch decision {
		case "observe_ineligible_risk", "observe_suspicious_text",
			"audit_ineligible_risk", "audit_suspicious_text":
			if explanationSchema != DecisionExplanationSchemaV2 {
				return fmt.Errorf("audit: %s decision requires explanation_schema %s", decision, DecisionExplanationSchemaV2)
			}
			return nil
		case "observe_incomplete_inspection", "audit_incomplete_inspection",
			"allow_due_to_incomplete_inspection", "allow_incomplete_inspection_off",
			"observe_opaque_media", "audit_opaque_media", "allow_with_opaque_media_audit",
			"audit_subject_risk":
			if explanationSchema != DecisionExplanationSchemaNone {
				return fmt.Errorf("audit: %s decision requires explanation_schema none", decision)
			}
			return nil
		default:
			return errors.New("audit: audit_ineligible_risk decision_kind has an unsupported disposition")
		}
	case decisionKindAuditEligibleMaliciousText,
		decisionKindBlockMaliciousText,
		decisionKindBlockIncomplete,
		decisionKindBlockOpaqueMedia,
		decisionKindBlockSubjectRisk,
		decisionKindAuditCSAMText,
		decisionKindBlockCSAMText:
		if explanationSchema != DecisionExplanationSchemaV2 {
			return fmt.Errorf("audit: %s decision_kind requires explanation_schema %s", decisionKind, DecisionExplanationSchemaV2)
		}
		return nil
	default:
		return fmt.Errorf("audit: unsupported decision_kind %q", decisionKind)
	}
}

func validateCSAMTextEvent(event Event, explanationSchema string, blocking bool) error {
	if event.Coverage != "complete" || event.IncompleteReason != "" {
		return errors.New("audit: CSAM-text disposition requires complete inspection")
	}
	if event.Category != "csam_malicious" || len(event.RuleIDs) != 1 ||
		!validCSAMTextRuleID(event.RuleIDs[0]) ||
		event.Classifier != "csam-text-v1" {
		return errors.New("audit: CSAM-text disposition requires a registered classifier category and rule")
	}
	if event.RiskScore != 0 {
		return errors.New("audit: CSAM-text disposition must not borrow the cyber-abuse score")
	}
	explanation := event.DecisionExplanation
	if explanationSchema != DecisionExplanationSchemaV2 || explanation == nil ||
		explanation.Kind != decisionExplanationKindCSAMText {
		return errors.New("audit: CSAM-text disposition requires the CSAM-text explanation branch")
	}
	if err := validateIndependentDecisionExplanation(explanation); err != nil {
		return err
	}
	if blocking != (event.DecisionKind == decisionKindBlockCSAMText) {
		return errors.New("audit: CSAM-text disposition blocking identity drifted")
	}
	return nil
}

func validCSAMTextRuleID(ruleID string) bool {
	return oneOf(ruleID,
		"CSAM-TXT-PRODUCTION-001",
		"CSAM-TXT-SOLICITATION-001",
		"CSAM-TXT-EXCHANGE-001",
		"CSAM-TXT-DISSEMINATION-001",
		"CSAM-TXT-GROOMING-001",
	)
}

func validateAuditIneligibleRiskEvent(event Event, explanationSchema string) error {
	classifierDisposition := false
	switch event.Decision {
	case "observe_ineligible_risk", "observe_suspicious_text":
		classifierDisposition = true
		if event.Action != "observe" {
			return errors.New("audit: observe ineligible-risk disposition requires observe action")
		}
	case "audit_ineligible_risk", "audit_suspicious_text":
		classifierDisposition = true
		if event.Action != "audit" {
			return errors.New("audit: audit ineligible-risk disposition requires audit action")
		}
	case "observe_incomplete_inspection":
		if event.Action != "observe" {
			return errors.New("audit: observed incomplete inspection requires observe action")
		}
		return validateNonBlockingTransportAudit(event, "incomplete")
	case "audit_incomplete_inspection", "allow_due_to_incomplete_inspection", "allow_incomplete_inspection_off":
		if event.Action != "audit" && event.Action != "allow" {
			return errors.New("audit: allowed incomplete inspection requires audit or allow action")
		}
		return validateNonBlockingTransportAudit(event, "incomplete")
	case "observe_opaque_media":
		if event.Action != "observe" {
			return errors.New("audit: observed opaque media requires observe action")
		}
		return validateNonBlockingTransportAudit(event, "opaque_media")
	case "audit_opaque_media", "allow_with_opaque_media_audit":
		if event.Action != "audit" {
			return errors.New("audit: audited opaque media requires audit action")
		}
		return validateNonBlockingTransportAudit(event, "opaque_media")
	case "audit_subject_risk":
		if event.Action != "audit" {
			return errors.New("audit: audited subject risk requires audit action")
		}
		return validateNonBlockingTransportAudit(event, "subject_risk")
	default:
		return errors.New("audit: audit_ineligible_risk decision_kind has an unsupported disposition")
	}

	if !classifierDisposition || event.Coverage != "complete" || event.IncompleteReason != "" {
		return errors.New("audit: classifier ineligible-risk disposition requires complete inspection")
	}
	explanation := event.DecisionExplanation
	if explanationSchema != DecisionExplanationSchemaV2 || explanation == nil ||
		explanation.Kind != decisionExplanationKindMalicious || !hasEligibilityContract(explanation) || explanation.BlockEligible {
		return errors.New("audit: classifier ineligible-risk disposition requires an ineligible malicious v2 explanation")
	}
	return nil
}

func validateNonBlockingTransportAudit(event Event, transportKind string) error {
	if event.DecisionExplanation != nil || effectiveDecisionExplanationSchema(event) != DecisionExplanationSchemaNone {
		return errors.New("audit: non-blocking transport disposition must not carry a classifier explanation")
	}
	if len(event.RuleIDs) != 0 {
		return errors.New("audit: non-blocking transport disposition must not carry classifier rule IDs")
	}
	switch transportKind {
	case "incomplete":
		if event.Coverage != "incomplete" || event.IncompleteReason == "" {
			return errors.New("audit: incomplete transport disposition requires incomplete coverage")
		}
		if event.Category != "" && event.Category != event.IncompleteReason {
			return errors.New("audit: incomplete transport category must identify the incomplete reason")
		}
	case "opaque_media", "subject_risk":
		if event.Coverage != "complete" || event.IncompleteReason != "" {
			return errors.New("audit: non-incomplete transport disposition requires complete inspection")
		}
		if event.Category != "" && event.Category != transportKind {
			return errors.New("audit: transport category does not match its decision kind")
		}
	default:
		return errors.New("audit: unsupported non-blocking transport disposition")
	}
	return nil
}

func validateNonMaliciousBlockIdentifiers(event Event, expectedKind string) error {
	if len(event.RuleIDs) != 0 {
		return errors.New("audit: non-malicious block decision_kind must not carry classifier rule IDs")
	}
	if effectiveDecisionExplanationSchema(event) != DecisionExplanationSchemaV2 || event.DecisionExplanation == nil ||
		event.DecisionExplanation.Kind != expectedKind {
		return errors.New("audit: non-malicious block decision_kind requires its independent v2 explanation")
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
	if len(source.ScoreBreakdown) == 0 {
		cloned.ScoreBreakdown = nil
		return &cloned
	}
	cloned.ScoreBreakdown = make([]ScoreComponent, len(source.ScoreBreakdown))
	for index, component := range source.ScoreBreakdown {
		cloned.ScoreBreakdown[index] = component
		cloned.ScoreBreakdown[index].EvidenceIDs = append([]string(nil), component.EvidenceIDs...)
	}
	return &cloned
}

func normalizeDecisionExplanationCollections(explanation *DecisionExplanation) {
	if explanation == nil {
		return
	}
	if len(explanation.ScoreBreakdown) == 0 {
		explanation.ScoreBreakdown = nil
		return
	}
	for index := range explanation.ScoreBreakdown {
		if len(explanation.ScoreBreakdown[index].EvidenceIDs) == 0 {
			explanation.ScoreBreakdown[index].EvidenceIDs = nil
		}
	}
}

func validateDecisionExplanation(explanation *DecisionExplanation) error {
	if explanation == nil {
		return nil
	}
	if explanation.Kind != "" && explanation.Kind != decisionExplanationKindMalicious {
		return validateIndependentDecisionExplanation(explanation)
	}
	if explanation.IncompleteInspectionReason != "" || explanation.OpaqueMediaReason != "" ||
		explanation.SubjectRiskAction != "" {
		return errors.New("audit: malicious explanation contains another union branch")
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
	if explanation.RelationType != ExplanationRelationNone &&
		explanation.RelationType != ExplanationRelationHistoricalToolActivation {
		return errors.New("audit: decision explanation relation_type is unsupported")
	}
	if explanation.EnforcementOwner != ExplanationEnforcementOwnerNone &&
		explanation.EnforcementOwner != ExplanationEnforcementOwnerCurrentTrustedUser {
		return errors.New("audit: decision explanation enforcement_owner is unsupported")
	}
	if (explanation.RelationType == ExplanationRelationNone) !=
		(explanation.EnforcementOwner == ExplanationEnforcementOwnerNone) {
		return errors.New("audit: decision explanation relation_type and enforcement_owner must be present together")
	}
	if err := validateEligibilityExplanation(explanation); err != nil {
		return err
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

func validateDecisionExplanationForSchema(explanation *DecisionExplanation, schema string) error {
	switch schema {
	case DecisionExplanationSchemaNone:
		if explanation != nil {
			return errors.New("audit: explanation_schema none must not carry a decision explanation")
		}
		return nil
	case DecisionExplanationSchemaV1:
		if explanation == nil {
			return errors.New("audit: decision-explanation-v1 requires an explanation")
		}
		if explanation.Kind != "" || explanation.IncompleteInspectionReason != "" ||
			explanation.OpaqueMediaReason != "" || explanation.SubjectRiskAction != "" ||
			hasEligibilityContract(explanation) {
			return errors.New("audit: decision-explanation-v1 contains Round9 fields")
		}
		return validateDecisionExplanation(explanation)
	case DecisionExplanationSchemaV2:
		if explanation == nil || explanation.Kind == "" {
			return errors.New("audit: decision-explanation-v2 requires a discriminated explanation")
		}
		return validateDecisionExplanation(explanation)
	default:
		return fmt.Errorf("audit: unsupported explanation schema %q", schema)
	}
}

func validateIndependentDecisionExplanation(explanation *DecisionExplanation) error {
	if hasMaliciousExplanationPayload(explanation) {
		return errors.New("audit: independent decision explanation must not carry malicious classifier metadata")
	}
	switch explanation.Kind {
	case decisionExplanationKindIncomplete:
		if explanation.IncompleteInspectionReason == "" ||
			!validIncompleteReason(explanation.IncompleteInspectionReason) {
			return errors.New("audit: incomplete explanation requires a supported incomplete reason")
		}
		if explanation.OpaqueMediaReason != "" || explanation.SubjectRiskAction != "" {
			return errors.New("audit: incomplete explanation contains another union branch")
		}
	case decisionExplanationKindOpaque:
		if explanation.OpaqueMediaReason != opaqueMediaExplanationReason {
			return errors.New("audit: opaque-media explanation requires the fixed reason")
		}
		if explanation.IncompleteInspectionReason != "" || explanation.SubjectRiskAction != "" {
			return errors.New("audit: opaque-media explanation contains another union branch")
		}
	case decisionExplanationKindSubject:
		if !oneOf(explanation.SubjectRiskAction, "block", "cooldown") {
			return errors.New("audit: subject-risk explanation requires block or cooldown action")
		}
		if explanation.IncompleteInspectionReason != "" || explanation.OpaqueMediaReason != "" {
			return errors.New("audit: subject-risk explanation contains another union branch")
		}
	case decisionExplanationKindCSAMText:
		if explanation.IncompleteInspectionReason != "" || explanation.OpaqueMediaReason != "" ||
			explanation.SubjectRiskAction != "" {
			return errors.New("audit: CSAM-text explanation contains another union branch")
		}
	default:
		return errors.New("audit: decision explanation kind is unsupported")
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

func hasMaliciousExplanationPayload(explanation *DecisionExplanation) bool {
	if explanation == nil {
		return false
	}
	return explanation.WinningRuleID != "" || explanation.WinningCategory != "" ||
		len(explanation.ScoreBreakdown) != 0 || explanation.CorePredicateComplete ||
		explanation.EvidenceDimensionMask != 0 || explanation.EvidenceOccurrenceCount != 0 ||
		explanation.EvidenceSegmentCount != 0 || explanation.WinningRole != "" ||
		explanation.WinningProvenance != "" || explanation.CurrentTurnEvidence ||
		explanation.CrossSegmentComposition != "" || explanation.ReferentLinkUsed ||
		explanation.RelationType != ExplanationRelationNone ||
		explanation.EnforcementOwner != ExplanationEnforcementOwnerNone ||
		explanation.QuotedOrInertSuppressed || explanation.ContextAdjustment != 0 ||
		explanation.HardFloorApplied || explanation.HardFloorReason != "" ||
		hasEligibilityContract(explanation)
}

func isMaliciousDecisionExplanation(explanation *DecisionExplanation) bool {
	return explanation != nil && (explanation.Kind == "" || explanation.Kind == decisionExplanationKindMalicious)
}

func hasEligibilityContract(explanation *DecisionExplanation) bool {
	if explanation == nil {
		return false
	}
	return explanation.BlockEligible ||
		explanation.PrimaryEligibilityReason != "" ||
		explanation.EligibilityReasonFlags != 0 ||
		explanation.InspectionComplete ||
		explanation.EvidenceOwnedByCurrentUser ||
		explanation.EnforcementScope != EnforcementScopeNone ||
		explanation.RelationType != ExplanationRelationNone ||
		explanation.EnforcementOwner != ExplanationEnforcementOwnerNone ||
		explanation.CurrentExecutionActProven ||
		explanation.HarmfulCoreComplete ||
		explanation.OperationallyActionable ||
		explanation.AuthorizationClaimState != "" ||
		explanation.ExplicitVictimOrNonconsent ||
		explanation.CovertAcquisition ||
		explanation.ExfiltrationOrTakeover ||
		explanation.MaliciousPersistence ||
		explanation.DestructiveOutcome ||
		explanation.SecurityControlEvasion ||
		explanation.DefensiveScopeConflict ||
		explanation.QuotedOrAnalyticalScope ||
		explanation.CrossScopeComposition ||
		explanation.ReferentProofComplete ||
		explanation.EvidenceAmbiguous
}

func validateEligibilityExplanation(explanation *DecisionExplanation) error {
	if !hasEligibilityContract(explanation) {
		return nil
	}
	if err := validateEnforcementScopeContract(explanation); err != nil {
		return err
	}
	if !validEligibilityReason(explanation.PrimaryEligibilityReason) {
		return errors.New("audit: decision explanation primary_eligibility_reason is unsupported")
	}
	if !oneOf(explanation.AuthorizationClaimState, "absent", "consistent", "conflicting", "unverifiable") {
		return errors.New("audit: decision explanation authorization_claim_state is unsupported")
	}
	if explanation.EligibilityReasonFlags&^knownEligibilityReasonFlags != 0 {
		return errors.New("audit: decision explanation eligibility_reason_flags contains unknown bits")
	}
	primaryFlag := eligibilityReasonFlag(explanation.PrimaryEligibilityReason)
	if primaryFlag == 0 || explanation.EligibilityReasonFlags&primaryFlag == 0 {
		return errors.New("audit: decision explanation primary eligibility reason is missing from eligibility_reason_flags")
	}

	eligibleConditions := explanation.InspectionComplete &&
		auditRequestBlockAuthorityProven(explanation) &&
		explanation.CurrentExecutionActProven &&
		explanation.HarmfulCoreComplete &&
		explanation.OperationallyActionable &&
		!explanation.DefensiveScopeConflict &&
		!explanation.QuotedOrAnalyticalScope &&
		!explanation.CrossScopeComposition &&
		explanation.ReferentProofComplete &&
		!explanation.EvidenceAmbiguous
	expectedFlags := expectedEligibilityReasonFlags(explanation)
	if explanation.EligibilityReasonFlags != expectedFlags {
		return errors.New("audit: decision explanation eligibility_reason_flags contradict the persisted evidence state")
	}

	if explanation.BlockEligible {
		if explanation.PrimaryEligibilityReason != eligibilityReasonExplicitMalice ||
			explanation.EligibilityReasonFlags != eligibilityFlagExplicitMalice {
			return errors.New("audit: eligible decision explanation must use only eligible_explicit_malice")
		}
		if !eligibleConditions {
			return errors.New("audit: eligible decision explanation contradicts its eligibility evidence")
		}
		return nil
	}

	if explanation.PrimaryEligibilityReason == eligibilityReasonExplicitMalice ||
		explanation.EligibilityReasonFlags&eligibilityFlagExplicitMalice != 0 {
		return errors.New("audit: ineligible decision explanation must not claim explicit-malice eligibility")
	}
	if explanation.HardFloorApplied || explanation.HardFloorReason != "" {
		return errors.New("audit: ineligible decision explanation must not apply a hard floor")
	}
	if eligibleConditions {
		return errors.New("audit: ineligible decision explanation satisfies every eligibility condition")
	}

	consistent := false
	switch explanation.PrimaryEligibilityReason {
	case eligibilityReasonIncompleteInspection:
		consistent = !explanation.InspectionComplete
	case eligibilityReasonUntrustedOwnership:
		consistent = !auditRequestBlockAuthorityProven(explanation)
	case eligibilityReasonNoCurrentDirective:
		consistent = !explanation.CurrentExecutionActProven
	case eligibilityReasonQuotedOrAnalytical:
		consistent = explanation.QuotedOrAnalyticalScope
	case eligibilityReasonDefensivePurpose:
		consistent = explanation.DefensiveScopeConflict
	case eligibilityReasonAuthorizedOwned:
		consistent = explanation.AuthorizationClaimState == "consistent" && !explanation.HarmfulCoreComplete
	case eligibilityReasonAmbiguousCore:
		consistent = explanation.EvidenceAmbiguous || !explanation.HarmfulCoreComplete
	case eligibilityReasonCrossScope:
		consistent = explanation.CrossScopeComposition || !explanation.ReferentProofComplete
	case eligibilityReasonOperationalAbsent:
		consistent = !explanation.OperationallyActionable
	}
	if !consistent {
		return errors.New("audit: decision explanation primary eligibility reason contradicts its evidence")
	}
	return nil
}

func expectedEligibilityReasonFlags(explanation *DecisionExplanation) uint64 {
	if explanation == nil {
		return 0
	}
	flags := uint64(0)
	add := func(condition bool, flag uint64) {
		if condition {
			flags |= flag
		}
	}
	add(!explanation.InspectionComplete, eligibilityFlagIncompleteInspection)
	add(!auditRequestBlockAuthorityProven(explanation), eligibilityFlagUntrustedOwnership)
	add(!explanation.CurrentExecutionActProven, eligibilityFlagNoCurrentDirective)
	add(explanation.QuotedOrAnalyticalScope, eligibilityFlagQuotedOrAnalytical)
	add(explanation.DefensiveScopeConflict, eligibilityFlagDefensivePurpose)
	add(explanation.AuthorizationClaimState == "consistent" && !explanation.HarmfulCoreComplete, eligibilityFlagAuthorizedOwned)
	add(explanation.EvidenceAmbiguous || !explanation.HarmfulCoreComplete, eligibilityFlagAmbiguousCore)
	add(explanation.CrossScopeComposition || !explanation.ReferentProofComplete, eligibilityFlagCrossScope)
	add(!explanation.OperationallyActionable, eligibilityFlagOperationalAbsent)
	if explanation.BlockEligible {
		flags |= eligibilityFlagExplicitMalice
	}
	return flags
}

// validateEnforcementScopeContract checks the exact persisted projection of the
// occurrence proof already enforced by the plugin. Current-user winners must be
// current user content. Request-local system winners must be non-user system
// content; CurrentTurnEvidence is deliberately false so provider-native
// top-level Responses instructions retain their valid -1 segment sentinel.
// Request-local tool winners keep non-user tool provenance. A terminal result
// has no current-turn evidence; a uniquely associated historical result may set
// CurrentTurnEvidence only when an exact current-user referent/execution proof
// is persisted with it.
//
// Empty scope is retained for non-eligible v2 history and for eligible legacy
// current-user rows written before enforcement_scope existed. That legacy path
// requires the exact current user-content authority tuple and can never admit a
// non-user system/tool winner. V1 explanations do not carry an eligibility
// contract at all. New eligible malicious-text events persist a positive scope.
func validateEnforcementScopeContract(explanation *DecisionExplanation) error {
	if explanation == nil {
		return errors.New("audit: decision explanation enforcement_scope requires an explanation")
	}
	hasActivationRelation := explanation.RelationType != ExplanationRelationNone ||
		explanation.EnforcementOwner != ExplanationEnforcementOwnerNone
	switch explanation.EnforcementScope {
	case EnforcementScopeNone:
		if hasActivationRelation {
			return errors.New("audit: historical-tool activation relation requires request_local_tool enforcement_scope")
		}
		if explanation.BlockEligible && !currentUserAuthorityTupleProven(explanation) {
			return errors.New("audit: eligible decision explanation requires enforcement_scope or legacy current-user authority")
		}
		return nil
	case EnforcementScopeCurrentUser:
		if hasActivationRelation {
			return errors.New("audit: current_user enforcement_scope cannot carry a historical-tool activation relation")
		}
		if !currentUserAuthorityTupleProven(explanation) {
			return errors.New("audit: current_user enforcement_scope requires current user-content provenance")
		}
	case EnforcementScopeRequestLocalSystem:
		if hasActivationRelation {
			return errors.New("audit: request_local_system enforcement_scope cannot carry a historical-tool activation relation")
		}
		if explanation.EvidenceOwnedByCurrentUser || explanation.WinningRole != "system" ||
			explanation.WinningProvenance != "content" || explanation.CurrentTurnEvidence {
			return errors.New("audit: request_local_system enforcement_scope requires non-user system-content provenance")
		}
	case EnforcementScopeRequestLocalTool:
		if explanation.EvidenceOwnedByCurrentUser || explanation.WinningRole != "tool" ||
			explanation.WinningProvenance != "content" {
			return errors.New("audit: request_local_tool enforcement_scope requires non-user tool-result provenance")
		}
		if explanation.CurrentTurnEvidence {
			if !explanation.BlockEligible || !explanation.ReferentLinkUsed || !explanation.ReferentProofComplete ||
				!explanation.CurrentExecutionActProven || explanation.CrossSegmentComposition != "explicit_referent" ||
				explanation.EvidenceSegmentCount < 2 {
				return errors.New("audit: activated request_local_tool enforcement_scope requires a complete current-user referent proof")
			}
		} else if explanation.ReferentLinkUsed || explanation.CrossSegmentComposition == "explicit_referent" ||
			hasActivationRelation {
			return errors.New("audit: terminal request_local_tool enforcement_scope cannot carry activation fields")
		}
	default:
		return errors.New("audit: decision explanation enforcement_scope is unsupported")
	}
	return nil
}

// currentUserAuthorityTupleProven is the narrow legacy compatibility proof for
// eligible decision-explanation-v2 rows written before enforcement_scope was
// added. Keep all four checks together: an empty scope must never manufacture
// authority for a non-user system/tool record. Explicit current_user scopes use
// the same tuple so the two acceptance paths cannot drift.
func currentUserAuthorityTupleProven(explanation *DecisionExplanation) bool {
	return explanation != nil &&
		explanation.EvidenceOwnedByCurrentUser &&
		explanation.WinningRole == "user" &&
		explanation.WinningProvenance == "content" &&
		explanation.CurrentTurnEvidence
}

// auditRequestBlockAuthorityProven is evaluated only after the exact persisted
// scope/provenance combination above has been validated. It therefore never
// infers authority from BlockEligible, avoiding a circular acceptance path.
func auditRequestBlockAuthorityProven(explanation *DecisionExplanation) bool {
	if explanation == nil {
		return false
	}
	switch explanation.EnforcementScope {
	case EnforcementScopeNone, EnforcementScopeCurrentUser:
		return currentUserAuthorityTupleProven(explanation)
	case EnforcementScopeRequestLocalSystem, EnforcementScopeRequestLocalTool:
		return !explanation.EvidenceOwnedByCurrentUser
	default:
		return false
	}
}

func validEligibilityReason(value string) bool {
	return oneOf(value,
		eligibilityReasonIncompleteInspection,
		eligibilityReasonUntrustedOwnership,
		eligibilityReasonNoCurrentDirective,
		eligibilityReasonQuotedOrAnalytical,
		eligibilityReasonDefensivePurpose,
		eligibilityReasonAuthorizedOwned,
		eligibilityReasonAmbiguousCore,
		eligibilityReasonCrossScope,
		eligibilityReasonOperationalAbsent,
		eligibilityReasonExplicitMalice,
	)
}

func eligibilityReasonFlag(value string) uint64 {
	switch value {
	case eligibilityReasonIncompleteInspection:
		return eligibilityFlagIncompleteInspection
	case eligibilityReasonUntrustedOwnership:
		return eligibilityFlagUntrustedOwnership
	case eligibilityReasonNoCurrentDirective:
		return eligibilityFlagNoCurrentDirective
	case eligibilityReasonQuotedOrAnalytical:
		return eligibilityFlagQuotedOrAnalytical
	case eligibilityReasonDefensivePurpose:
		return eligibilityFlagDefensivePurpose
	case eligibilityReasonAuthorizedOwned:
		return eligibilityFlagAuthorizedOwned
	case eligibilityReasonAmbiguousCore:
		return eligibilityFlagAmbiguousCore
	case eligibilityReasonCrossScope:
		return eligibilityFlagCrossScope
	case eligibilityReasonOperationalAbsent:
		return eligibilityFlagOperationalAbsent
	case eligibilityReasonExplicitMalice:
		return eligibilityFlagExplicitMalice
	default:
		return 0
	}
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
		"observe_ineligible_risk", "audit_ineligible_risk",
		"observe_malicious_text", "audit_malicious_text", "block_malicious_text",
		"observe_suspicious_text", "audit_suspicious_text",
		"observe_incomplete_inspection", "audit_incomplete_inspection",
		"allow_due_to_incomplete_inspection", "block_due_to_incomplete_inspection",
		"allow_incomplete_inspection_off",
		"observe_opaque_media", "audit_opaque_media", "allow_with_opaque_media_audit", "block_opaque_media",
		"audit_subject_risk", "block_subject_risk",
		"observe_csam_text", "audit_csam_text", "block_csam_text",
		"block_unknown_source_format", "cooldown_subject_risk")
}

func decisionKindForDisposition(disposition string) string {
	switch disposition {
	case "allow_clean":
		return decisionKindAllowClean
	case "block_malicious_text":
		return decisionKindBlockMaliciousText
	case "observe_malicious_text", "audit_malicious_text":
		return decisionKindAuditEligibleMaliciousText
	case "block_due_to_incomplete_inspection", "block_unknown_source_format":
		return decisionKindBlockIncomplete
	case "block_opaque_media":
		return decisionKindBlockOpaqueMedia
	case "block_subject_risk", "cooldown_subject_risk":
		return decisionKindBlockSubjectRisk
	case "observe_csam_text", "audit_csam_text":
		return decisionKindAuditCSAMText
	case "block_csam_text":
		return decisionKindBlockCSAMText
	case "legacy_unspecified":
		return decisionKindLegacyUnspecified
	default:
		if validDecision(disposition) {
			return decisionKindAuditIneligibleRisk
		}
		return decisionKindLegacyUnspecified
	}
}

func validDecisionKind(value string) bool {
	return oneOf(value,
		decisionKindLegacyUnspecified,
		decisionKindAllowClean,
		decisionKindAuditIneligibleRisk,
		decisionKindAuditEligibleMaliciousText,
		decisionKindBlockMaliciousText,
		decisionKindBlockIncomplete,
		decisionKindBlockOpaqueMedia,
		decisionKindBlockSubjectRisk,
		decisionKindAuditCSAMText,
		decisionKindBlockCSAMText,
	)
}

func validDecisionExplanationSchema(value string) bool {
	return oneOf(value,
		DecisionExplanationSchemaNone,
		DecisionExplanationSchemaV1,
		DecisionExplanationSchemaV2,
	)
}

func validIncompleteReason(value string) bool {
	return oneOf(value, "", "parse_error", "scan_limit", "rpc_body_limit", "json_depth_limit",
		"text_part_limit", "role_attribution", "classification_chunk_limit", "total_text_limit", "multipart_limit",
		"multipart_schema", "tool_schema", "deferred_text_limit", "unsupported_content_type",
		"classifier_proof_budget", "incomplete_inspection", "unknown_source_format")
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
