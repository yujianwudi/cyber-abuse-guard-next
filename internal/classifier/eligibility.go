package classifier

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

// AuthorizationClaimState records only what the request text proves about an
// authorization claim. It never asserts real-world ownership of a browser,
// host, account, service, or other target.
type AuthorizationClaimState string

const (
	AuthorizationAbsent       AuthorizationClaimState = "absent"
	AuthorizationConsistent   AuthorizationClaimState = "consistent"
	AuthorizationConflicting  AuthorizationClaimState = "conflicting"
	AuthorizationUnverifiable AuthorizationClaimState = "unverifiable"
)

// DispositionGate is the closed, content-free reason why one candidate may or
// may not enter malicious-text scoring and hard-floor enforcement.
type DispositionGate string

const (
	GateIncompleteInspection     DispositionGate = "incomplete_inspection"
	GateUntrustedOwnership       DispositionGate = "untrusted_ownership"
	GateNoCurrentDirective       DispositionGate = "no_current_directive"
	GateQuotedOrAnalytical       DispositionGate = "quoted_or_analytical"
	GateDefensivePurpose         DispositionGate = "defensive_purpose"
	GateAuthorizedOwnedOperation DispositionGate = "authorized_owned_operation"
	GateAmbiguousCore            DispositionGate = "ambiguous_core"
	GateCrossScopeComposition    DispositionGate = "cross_scope_composition"
	GateOperationalCoreAbsent    DispositionGate = "operational_core_absent"
	GateEligibleExplicitMalice   DispositionGate = "eligible_explicit_malice"
)

const (
	EligibilityReasonIncompleteInspection uint64 = 1 << iota
	EligibilityReasonUntrustedOwnership
	EligibilityReasonNoCurrentDirective
	EligibilityReasonQuotedOrAnalytical
	EligibilityReasonDefensivePurpose
	EligibilityReasonAuthorizedOwnedOperation
	EligibilityReasonAmbiguousCore
	EligibilityReasonCrossScopeComposition
	EligibilityReasonOperationalCoreAbsent
	EligibilityReasonExplicitMalice
)

const eligibilityKnownReasonFlags = EligibilityReasonIncompleteInspection |
	EligibilityReasonUntrustedOwnership |
	EligibilityReasonNoCurrentDirective |
	EligibilityReasonQuotedOrAnalytical |
	EligibilityReasonDefensivePurpose |
	EligibilityReasonAuthorizedOwnedOperation |
	EligibilityReasonAmbiguousCore |
	EligibilityReasonCrossScopeComposition |
	EligibilityReasonOperationalCoreAbsent |
	EligibilityReasonExplicitMalice

// EnforcementScope records why a complete malicious candidate may be enforced
// at the request boundary. It is deliberately independent from user ownership:
// request-local system instructions and terminal tool results can contain an
// active prompt-injection directive, but they must never be attributed to the
// authenticated user or enter cross-request subject state.
type EnforcementScope string

const (
	EnforcementScopeNone               EnforcementScope = ""
	EnforcementScopeCurrentUser        EnforcementScope = "current_user"
	EnforcementScopeRequestLocalSystem EnforcementScope = "request_local_system"
	EnforcementScopeRequestLocalTool   EnforcementScope = "request_local_tool"
)

// CandidateBlockEligibility is bound to one category/clause/scope/referent
// candidate. Score and hard-floor code may consume it, but may never create or
// upgrade it. The fields contain no matched request text.
type CandidateBlockEligibility struct {
	InspectionComplete         bool                    `json:"inspection_complete"`
	EvidenceOwnedByCurrentUser bool                    `json:"evidence_owned_by_current_user"`
	EnforcementScope           EnforcementScope        `json:"enforcement_scope,omitempty"`
	CurrentExecutionActProven  bool                    `json:"current_execution_act_proven"`
	HarmfulCoreComplete        bool                    `json:"harmful_core_complete"`
	OperationallyActionable    bool                    `json:"operationally_actionable"`
	AuthorizationClaim         AuthorizationClaimState `json:"authorization_claim_state"`
	ExplicitVictimOrNonConsent bool                    `json:"explicit_victim_or_nonconsent"`
	CovertAcquisition          bool                    `json:"covert_acquisition"`
	ExfiltrationOrTakeover     bool                    `json:"exfiltration_or_takeover"`
	MaliciousPersistence       bool                    `json:"malicious_persistence"`
	DestructiveOutcome         bool                    `json:"destructive_outcome"`
	SecurityControlEvasion     bool                    `json:"security_control_evasion"`
	DefensiveScopeConflict     bool                    `json:"defensive_scope_conflict"`
	QuotedOrAnalyticalScope    bool                    `json:"quoted_or_analytical_scope"`
	CrossScopeComposition      bool                    `json:"cross_scope_composition"`
	ReferentProofComplete      bool                    `json:"referent_proof_complete"`
	EvidenceAmbiguous          bool                    `json:"evidence_ambiguous"`
	Eligible                   bool                    `json:"block_eligible"`
	PrimaryReason              DispositionGate         `json:"primary_eligibility_reason"`
	ReasonFlags                uint64                  `json:"eligibility_reason_flags"`
}

// RequestBlockAuthorityProven is the closed request-level authority predicate.
// The current-user scope remains ownership-bound. Non-user scopes are assigned
// only by the role-aware classifier after structural provider provenance has
// been proved; callers cannot manufacture a blocking result because the private
// candidate identity and occurrence contract are still required downstream.
func (eligibility CandidateBlockEligibility) RequestBlockAuthorityProven() bool {
	switch eligibility.EnforcementScope {
	case EnforcementScopeCurrentUser:
		return eligibility.EvidenceOwnedByCurrentUser
	case EnforcementScopeRequestLocalSystem, EnforcementScopeRequestLocalTool:
		return !eligibility.EvidenceOwnedByCurrentUser
	default:
		return false
	}
}

type candidateBlockIdentity struct {
	category          rules.Category
	clauseIDs         []int
	ownershipScopeIDs []uint64
	referentLinked    bool
	referentChain     candidateReferentChainIdentity
	occurrences       []EvidenceOccurrence
}

// candidateReferentChainIdentity is the bounded, content-free identity of one
// proven carrier -> current speech-act anchor relationship. Field/scope/turn
// coordinates are sufficient to distinguish two otherwise equal candidates;
// no request text, offsets beyond the winning evidence, or arbitrary metadata
// is retained.
type candidateReferentChainIdentity struct {
	set                     bool
	proofComplete           bool
	carrierScopeID          uint64
	carrierFirstFieldID     int
	carrierLastFieldID      int
	carrierOccurrenceCount  int
	anchorConversationIndex int
	anchorTurnIndex         int
	anchorScopeID           uint64
	anchorFieldID           int
}

const directCandidateSyntheticScopeID uint64 = ^uint64(0)

// classificationCandidate is deliberately package-level so every ordinary,
// semantic, composition, role, referent, and streaming producer can carry the
// same candidate-bound eligibility contract before winner selection.
type classificationCandidate struct {
	score                       int
	category                    rules.Category
	ruleID                      string
	ruleIDs                     []string
	evidence                    []Evidence
	occurrences                 []EvidenceOccurrence
	explanation                 DecisionExplanation
	identity                    candidateBlockIdentity
	eligibility                 CandidateBlockEligibility
	ordinaryMaterializationSlot uint8
}

type candidateTypedMaliciousAxes struct {
	explicitVictim bool
	covert         bool
	exfiltration   bool
	persistence    bool
	destructive    bool
	evasion        bool
}

const explicitMaliciousRelationRulePrefix = "R9-EXPLICIT-"
const maxExplicitQuotedActivationClauses = 8

const (
	explicitMaliciousRelationProofWindowOverlapBytes = 2 * maxRuleIntentLookbackBytes
	explicitMaliciousRelationProofWindowGuardBytes   = maxRuleIntentLookbackBytes
)

type explicitMaliciousRelationProofState uint8

const (
	explicitMaliciousRelationNotMatched explicitMaliciousRelationProofState = iota
	explicitMaliciousRelationMatched
	explicitMaliciousRelationProofBudgetExceeded
)

var candidateExplicitMaliciousRelationActions = []string{
	"apply", "steal", "steals", "stealing", "read", "capture", "divert", "sabotage", "use the", "extract", "interrupt",
	"execute", "exploit", "evade", "deploy", "disable", "suppress", "install", "push", "send to", "sends", "sending",
	"deliver", "replace", "act on", "insert", "obey", "trigger", "overload", "release", "carry out", "run", "turn", "treat",
	"compromise", "launch", "abuse", "collect", "copy", "export", "retain", "impersonate", "solicit",
	"harvest", "gather", "gathers", "gathering", "flood", "encrypt", "append", "activate", "weaponize", "exfiltrate", "hijack", "take over",
	"encrypts", "encrypting", "lock", "locks", "locking", "delete", "deletes", "deleting", "wipe", "wipes", "wiping", "destroy", "destroys", "destroying",
	"move", "remove", "force", "compel", "make", "keep", "hold", "discard", "reveal", "override", "ignore", "conceal",
	"silence", "silences", "silencing", "mute", "mutes", "muting", "unhook", "unhooks", "unhooking",
	"tamper", "tampers", "tampering", "tamper with", "tampers with", "tampering with",
	"stop", "stops", "stopping", "stopped", "suspend", "suspends", "suspending", "suspended",
	"erase", "erases", "erasing", "erased", "clear", "clears", "clearing", "cleared",
	"turn off", "turns off", "turning off", "shut down", "shuts down", "shutting down",
	"blind", "blinds", "blinding", "neutralize", "neutralizes", "neutralizing",
	"forward", "forwards", "forwarding", "forwarded", "route", "routes", "routing", "routed",
	"relay", "relays", "relaying", "relayed", "intercept", "intercepts", "intercepting", "intercepted",
	"利用", "隐藏", "躲开", "避开", "操纵", "关闭", "绕过", "规避", "禁用", "压制", "混淆",
	"write", "writes", "writing", "build", "builds", "building", "create", "creates", "creating", "develop", "develops", "developing", "generate",
	"利用", "取得", "进入", "攻击", "侵入", "绕过", "查看", "接管", "复制", "获取", "收集", "截取", "外传",
	"传出", "导出", "禁用", "隐藏", "规避", "压制", "投放", "安装", "推送", "发送", "冒充", "伪装", "诱导",
	"骗取", "植入", "应用", "执行", "泄露", "加密", "锁住", "启动", "灌入", "拖垮", "耗尽", "触发", "造成",
	"阻止", "保留", "改成", "包装成", "嵌入", "投向", "实施", "操纵", "关闭", "带走", "采集", "维持",
	"迫使", "驱使", "忽略", "交出", "接收", "读取", "改作", "索款", "吐出", "骗走",
	"编写", "构建", "创建", "开发", "生成", "制作",
}

var candidateExplicitMaliciousRelationActionPatterns = compileCompactRuleIntentPatterns(
	candidateExplicitMaliciousRelationActions,
)

var candidateExplicitQuotedActivationIntents = []string{
	"apply", "execute", "follow", "obey", "carry out", "act on", "install", "deploy", "activate", "run", "implement", "use",
	"应用", "执行", "遵循", "服从", "照做", "安装", "部署", "激活", "运行", "实施", "采用",
}

var candidateExplicitQuotedActivationIntentPatterns = compileCompactRuleIntentPatterns(
	candidateExplicitQuotedActivationIntents,
)

var candidateRansomwareEncryptionIntents = []string{
	"encrypt", "encrypts", "encrypting",
	"加密", "锁住", "锁定",
}

var candidateRansomwareEncryptionIntentPatterns = compileCompactRuleIntentPatterns(
	candidateRansomwareEncryptionIntents,
)

var candidateRansomwareExtortionIntents = []string{
	"hold", "holds", "holding", "lock", "locks", "locking", "deny", "denies", "denying",
	"demand", "demands", "demanding", "delete", "deletes", "deleting", "remove", "removes", "removing",
	"扣押", "锁住", "锁定", "拒绝", "索款", "索要", "删除", "移除",
}

var candidateRansomwareExtortionIntentPatterns = compileCompactRuleIntentPatterns(
	candidateRansomwareExtortionIntents,
)

var candidateDestructiveDataEncryptLockIntents = []string{
	"encrypt", "encrypts", "encrypting",
	"lock", "locks", "locking",
}

var candidateDestructiveDataEncryptLockIntentPatterns = compileCompactRuleIntentPatterns(
	candidateDestructiveDataEncryptLockIntents,
)

var candidateDestructiveDataDeleteWipeIntents = []string{
	"delete", "deletes", "deleting",
	"wipe", "wipes", "wiping",
	"destroy", "destroys", "destroying",
}

var candidateDestructiveDataDeleteWipeIntentPatterns = compileCompactRuleIntentPatterns(
	candidateDestructiveDataDeleteWipeIntents,
)

var candidateDestructiveDataTargets = []string{
	"file", "files", "document", "documents", "record", "records", "data",
	"database", "databases", "drive", "drives", "volume", "volumes",
	"backup", "backups", "restore point", "restore points", "filesystem", "filesystems",
}

var candidateDestructiveDataDefensiveTargets = []string{
	"dummy file", "dummy files", "test file", "test files", "fixture", "fixtures",
	"sample file", "sample files", "temporary file", "temporary files", "cache", "caches",
	"lab file", "lab files", "quarantined file", "quarantined files",
}

type candidateDestructiveDataRelation struct {
	encryptOrLock bool
	deleteOrWipe  bool
}

func candidateDestructiveDataControlledScope(text string) bool {
	controlled := containsAnyLiteral(text,
		"isolated lab", "offline lab", "authorized lab", "approved lab", "test fixture", "test fixtures",
		"dummy file", "dummy files", "synthetic file", "synthetic files", "quarantined sample", "quarantined files",
		"incident response", "forensic analysis", "malware analysis", "backup recovery", "disaster recovery",
	)
	if !controlled {
		return false
	}
	return !containsAnyLiteral(text,
		"real victim", "real victims", "non-consenting", "nonconsenting", "without consent",
		"without authorization", "without permission", "unauthorized", "production user", "production users",
		"hold hostage", "held hostage", "demand payment", "attacker-controlled",
	)
}

func candidateDestructiveDataHostileScope(text string) bool {
	return candidateExplicitMaliciousHostileScope(text) || containsAnyLiteral(text,
		"employee files", "production user files", "operational records", "business files", "business records",
		"company files on victim systems", "owner access", "lock owners out", "lock the owner out",
	)
}

func candidateDestructiveDataClauseRelation(text string) candidateDestructiveDataRelation {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" || candidateDestructiveDataControlledScope(text) ||
		candidateFirstBoundedLiteralIndex(text, candidateDestructiveDataTargets) < 0 ||
		!candidateDestructiveDataHostileScope(text) {
		return candidateDestructiveDataRelation{}
	}
	encryptTargets := candidateActionTargets(
		text,
		candidateDestructiveDataEncryptLockIntents,
		candidateDestructiveDataDefensiveTargets,
		candidateDestructiveDataTargets,
	)
	deleteTargets := candidateActionTargets(
		text,
		candidateDestructiveDataDeleteWipeIntents,
		candidateDestructiveDataDefensiveTargets,
		candidateDestructiveDataTargets,
	)
	return candidateDestructiveDataRelation{
		encryptOrLock: encryptTargets.harmful && containsUnnegatedRuleIntentPrepared(
			text,
			candidateDestructiveDataEncryptLockIntents,
			candidateDestructiveDataEncryptLockIntentPatterns,
		),
		deleteOrWipe: deleteTargets.harmful && containsUnnegatedRuleIntentPrepared(
			text,
			candidateDestructiveDataDeleteWipeIntents,
			candidateDestructiveDataDeleteWipeIntentPatterns,
		),
	}
}

// candidateClauseLocalDestructiveDataRelation never borrows an action, data
// target, or hostile owner from a different physical record. The caller may
// pass a larger candidate window, but each complete destructive relation must
// still be proved inside one directive clause.
func candidateClauseLocalDestructiveDataRelation(text string) candidateDestructiveDataRelation {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" ||
		!containsAnyLiteral(text, "encrypt", "lock", "delete", "wipe", "destroy") ||
		candidateFirstBoundedLiteralIndex(text, candidateDestructiveDataTargets) < 0 {
		return candidateDestructiveDataRelation{}
	}
	var relation candidateDestructiveDataRelation
	walkDirectiveClauses([]rune(text), func(clause []rune) bool {
		clauseRelation := candidateDestructiveDataClauseRelation(string(clause))
		relation.encryptOrLock = relation.encryptOrLock || clauseRelation.encryptOrLock
		relation.deleteOrWipe = relation.deleteOrWipe || clauseRelation.deleteOrWipe
		return !relation.encryptOrLock || !relation.deleteOrWipe
	})
	return relation
}

// explicitMaliciousRelationCandidate materializes one bounded, category-local
// candidate only after the current clause proves an active malicious relation.
// It is intentionally independent from the legacy rule vocabulary: eligibility
// must not disappear merely because an otherwise unambiguous request uses a
// different verb for the same victim/action/outcome relation.  Conversely, the
// detector below is conjunctive and never admits a bare risk noun, a defensive
// deliverable, a quoted review, or an authorized first-party workflow.
func explicitMaliciousRelationCandidate(
	text string,
	authorizationText string,
	context ContextFlags,
	inspectionComplete bool,
	existingEligibleCategoryMasks ...uint16,
) (classificationCandidate, bool) {
	return explicitMaliciousRelationCandidatePrepared(
		text,
		authorizationText,
		nil,
		context,
		inspectionComplete,
		existingEligibleCategoryMasks...,
	)
}

func explicitMaliciousRelationCandidatePrepared(
	text string,
	authorizationText string,
	authorizationPhishingProof *candidatePhishingRelationProof,
	context ContextFlags,
	inspectionComplete bool,
	existingEligibleCategoryMasks ...uint16,
) (classificationCandidate, bool) {
	normalizedText := strings.ToLower(strings.TrimSpace(text))
	normalizedAuthorizationText := strings.ToLower(strings.TrimSpace(authorizationText))

	var localCandidatePhishingProof candidatePhishingRelationProof
	candidatePhishingProof := authorizationPhishingProof
	if candidatePhishingProof == nil || candidatePhishingProof.text != normalizedText {
		localCandidatePhishingProof = newCandidatePhishingRelationProof(normalizedText)
		candidatePhishingProof = &localCandidatePhishingProof
	}
	var localAuthorizationPhishingProof candidatePhishingRelationProof
	if authorizationPhishingProof == nil || authorizationPhishingProof.text != normalizedAuthorizationText {
		if candidatePhishingProof.text == normalizedAuthorizationText {
			authorizationPhishingProof = candidatePhishingProof
		} else {
			localAuthorizationPhishingProof = newCandidatePhishingRelationProof(normalizedAuthorizationText)
			authorizationPhishingProof = &localAuthorizationPhishingProof
		}
	}

	category, ok := candidateExplicitMaliciousRelationCategoryPrepared(normalizedText, candidatePhishingProof)
	if !ok {
		return classificationCandidate{}, false
	}
	if category == rules.CategoryPhishing {
		candidateRealCredentialRelation := candidatePhishingRealCredentialInteractionRelationPrepared(
			normalizedText, candidatePhishingProof,
		)
		realCredentialRelation := candidatePhishingRealCredentialInteractionRelationPrepared(
			normalizedAuthorizationText, authorizationPhishingProof,
		)
		authorizationDetectionArtifact := candidatePhishingDetectionArtifactScopePrepared(
			normalizedAuthorizationText, authorizationPhishingProof,
		)
		if authorizationDetectionArtifact &&
			candidatePhishingReferencedNonExecutionScope(normalizedAuthorizationText) &&
			!realCredentialRelation {
			_, authorizationIndependentExecution := candidatePhishingIndependentMaliciousExecutionTailPrepared(
				normalizedAuthorizationText, authorizationPhishingProof,
			)
			if !authorizationIndependentExecution {
				return classificationCandidate{}, false
			}
		}
		if candidatePhishingSyntheticSimulationScopePrepared(
			normalizedAuthorizationText, authorizationPhishingProof,
		) && !candidateRealCredentialRelation {
			return classificationCandidate{}, false
		}
		if authorizationDetectionArtifact &&
			candidatePhishingDetectionArtifactScopePrepared(normalizedText, candidatePhishingProof) &&
			!candidateRealCredentialRelation {
			return classificationCandidate{}, false
		}
	}

	ruleID := explicitMaliciousRelationRuleID(category)
	activeDirective := true
	if category == rules.CategoryPhishing {
		// The typed phishing relation deliberately recognizes past and passive
		// incident language so it can preserve taxonomy and evidence. That lexical
		// relation is not itself proof of a current execution speech act.
		activeDirective = candidatePhishingCurrentCredentialInteractionSpeechActPrepared(
			normalizedText, candidatePhishingProof,
		)
	}
	quotedActivation := candidateExplicitQuotedActivation(normalizedText)
	independentTail, independentExecution := candidatePhishingIndependentMaliciousExecutionTailPrepared(
		normalizedText, candidatePhishingProof,
	)
	quotedOrAnalytical := candidateQuotedOrAnalyticalScopePrepared(normalizedText, candidatePhishingProof) &&
		!quotedActivation && !independentExecution
	// The request-wide matcher context is only a discovery hint; it does not
	// prove that a defensive/remediation token owns this physical candidate.
	// In particular, hostile requests commonly name the control they intend to
	// disable (EDR, incident response, logging) or the legitimate workflow they
	// intend to abuse (rotation, recovery).  Treating those ambient flags as a
	// candidate-local owner discarded an otherwise complete typed relation and
	// recreated the request-global gate that Round 9 is designed to remove.
	//
	// Quoted/analytical owners and concrete safety deliverables are proved from
	// normalizedText below. The clause walker separately suppresses a whole
	// analytical carrier unless it contains an independent malicious execution
	// clause, so no request-level safety label is needed here.
	defensiveConflict := candidateExplicitRelationDefensiveConflictPrepared(
		category, normalizedText, candidatePhishingProof,
	)
	if independentExecution {
		defensiveConflict = candidateExplicitRelationDefensiveConflict(category, independentTail)
	}
	if quotedActivation {
		defensiveConflict = false
	}
	// This detector is a vocabulary-seam fallback for an otherwise explicit,
	// active malicious relation. Quoted/analytical owners and concrete defensive
	// deliverables are not such a relation: the ordinary classifier may retain
	// them as audit evidence, but the typed fallback must not manufacture a
	// score-100 candidate from the dangerous words inside the artifact.
	if quotedOrAnalytical || defensiveConflict {
		return classificationCandidate{}, false
	}
	typedAxes := candidateExplicitRelationTypedAxes(category, normalizedText)
	eligibility := assessCandidateBlockEligibility(candidateEligibilityInput{
		category:                    category,
		ruleID:                      ruleID,
		text:                        text,
		authorizationText:           authorizationText,
		coreComplete:                true,
		activeDirective:             activeDirective,
		currentExecutionProven:      activeDirective,
		operational:                 activeDirective,
		ownershipProven:             true,
		inspectionComplete:          inspectionComplete,
		referentProofComplete:       true,
		typedExplicitMalice:         true,
		quotedOrAnalytical:          quotedOrAnalytical,
		defensiveConflict:           defensiveConflict,
		typedExplicitVictim:         typedAxes.explicitVictim,
		typedCovertAcquisition:      typedAxes.covert,
		typedExfiltration:           typedAxes.exfiltration,
		typedMaliciousPersistence:   typedAxes.persistence,
		typedDestructiveOutcome:     typedAxes.destructive,
		typedSecurityControlEvasion: typedAxes.evasion,
		context:                     context,
	})
	const score = 100
	var existingEligibleCategoryMask uint16
	if len(existingEligibleCategoryMasks) != 0 {
		existingEligibleCategoryMask = existingEligibleCategoryMasks[0]
	}
	if priority := categoryPriority(category); priority >= 0 && priority < 16 &&
		existingEligibleCategoryMask&(uint16(1)<<uint(priority)) != 0 {
		// appendExplicitMaliciousRelationFallback only needs category, score, and
		// eligibility when an established eligible candidate already owns this
		// category. Defer synthetic evidence/identity allocation unless the typed
		// fallback must become a standalone candidate.
		return classificationCandidate{
			score: score, category: category, ruleID: ruleID, eligibility: eligibility,
		}, true
	}
	evidence := []Evidence{
		{ID: ruleID + ":harm", Kind: "harm"},
		{ID: ruleID + ":object", Kind: "object"},
		{ID: ruleID + ":action", Kind: "action"},
		{ID: ruleID + ":target", Kind: "target"},
	}
	// Every typed axis that can make this synthetic fallback block-eligible must
	// have its own occurrence. Without a physical occurrence the overflow
	// selector can prefer a longer, apparently richer axis set even though the
	// extra behavior was never bound to a clause in that candidate window.
	if typedAxes.persistence {
		evidence = append(evidence, Evidence{ID: ruleID + ":outcome", Kind: "outcome"})
	}
	if typedAxes.exfiltration {
		evidence = append(evidence, Evidence{ID: ruleID + ":destination", Kind: "destination"})
	}
	if typedAxes.destructive {
		evidence = append(evidence, Evidence{ID: ruleID + ":impact", Kind: "impact"})
	}
	if typedAxes.evasion {
		evidence = append(evidence, Evidence{ID: ruleID + ":evasion", Kind: "evasion"})
	}
	occurrences := syntheticEvidenceOccurrences(evidence, ruleID)
	explanation := DecisionExplanation{
		WinningRuleID:           ruleID,
		WinningCategory:         string(category),
		CorePredicateComplete:   true,
		EvidenceDimensionMask:   occurrenceDimensionMask(occurrences),
		EvidenceOccurrenceCount: len(occurrences),
		EvidenceSegmentCount:    1,
		ScoreBreakdown: ScoreBreakdown{
			CorePredicateScore: 70,
			QualifierScore:     30,
			FinalScore:         score,
		},
	}
	applyEligibilityToExplanation(&explanation, eligibility)
	return classificationCandidate{
		score:       score,
		category:    category,
		ruleID:      ruleID,
		evidence:    evidence,
		occurrences: occurrences,
		explanation: explanation,
		identity:    directCandidateIdentityFor(category, occurrences, false),
		eligibility: eligibility,
	}, true
}

// explicitMaliciousRelationClauseCandidates runs the vocabulary-seam fallback
// on one bounded directive clause at a time.  The fallback must never combine
// an action from one sentence with a target, object, or outcome from another:
// doing so would manufacture a request-global malicious core without a
// candidate/clause identity.  Every returned occurrence is therefore bound to
// the one clause that proved the complete typed relation.
func (c *Classifier) explicitMaliciousRelationClauseCandidates(
	text []rune,
	context ContextFlags,
	inspectionComplete bool,
	existingEligibleCategoryMasks ...uint16,
) []classificationCandidate {
	var existingEligibleCategoryMask uint16
	if len(existingEligibleCategoryMasks) != 0 {
		existingEligibleCategoryMask = existingEligibleCategoryMasks[0]
	}
	return c.explicitMaliciousRelationClauseCandidatesPrepared(
		text, context, inspectionComplete, nil, existingEligibleCategoryMask, nil,
	)
}

func (c *Classifier) explicitMaliciousRelationClauseCandidatesPrepared(
	text []rune,
	context ContextFlags,
	inspectionComplete bool,
	sharedPhishingProof *candidatePhishingRelationProof,
	existingEligibleCategoryMask uint16,
	proofBudgetExceeded *bool,
) []classificationCandidate {
	if c == nil || len(text) == 0 || len(text) > maxClassifierNormalizedRunes {
		// Production inputs are capped by normalizePartsInto before this fallback
		// runs. Keep the same absolute bound for direct/internal callers so whole-
		// field ownership checks can never materialize more than the classifier's
		// reviewed normalized field budget.
		return nil
	}
	clauseCount := 0
	clauseOverflow := false
	c.walkDirectiveClausesWithBoundaryRange(text, func(clause []rune, _, _ int, _ directiveBoundaryKind) bool {
		clauseCount++
		if clauseCount > maxAnalyzedDirectiveClauses {
			clauseOverflow = true
			return false
		}
		return true
	})
	if clauseOverflow && !c.explicitMaliciousRelationOverflowMayContainCandidate(text) {
		return nil
	}
	// Resolve whole-field ownership before selecting any physical clause. The
	// overflow path used to return from a four-clause tail before these gates,
	// which both lost front/middle malicious relations and let an overflowed
	// quoted or analytical carrier bypass its owner proof entirely. The hard
	// normalized-rune guard above bounds this one whole-field view absolutely;
	// the clause scanner below still retains only four physical clauses.
	rawWholeText := strings.ToLower(string(text))
	wholeText := strings.TrimSpace(rawWholeText)
	wholeQuotedActivation := candidateExplicitQuotedActivation(wholeText)
	if candidateExplicitRelationAmbiguousQuoteStructure(wholeText) {
		return nil
	}
	if candidateUnclosedFencedCarrier(wholeText) {
		return nil
	}
	var quotedSpans [maxAnalyzedDirectiveClauses]explicitRelationRuneSpan
	quotedSpanCount := 0
	if candidateExplicitRelationHasStructuredQuoteSyntax(wholeText) {
		spans, complete := metaOverrideQuotedSpansWithLimit(rawWholeText, len(quotedSpans))
		if !complete {
			return nil
		}
		previousByte := 0
		previousRune := 0
		for _, span := range spans {
			startRune := previousRune + utf8.RuneCountInString(rawWholeText[previousByte:span.start])
			endRune := startRune + utf8.RuneCountInString(rawWholeText[span.start:span.end])
			quotedSpans[quotedSpanCount] = explicitRelationRuneSpan{start: startRune, end: endRune}
			quotedSpanCount++
			previousByte = span.end
			previousRune = endRune
		}
	}
	fieldQuotedSpans := quotedSpans[:quotedSpanCount]
	var localWholePhishingProof candidatePhishingRelationProof
	wholePhishingProof := sharedPhishingProof
	if wholePhishingProof == nil || wholePhishingProof.text != wholeText {
		localWholePhishingProof = newCandidatePhishingRelationProof(wholeText)
		wholePhishingProof = &localWholePhishingProof
	}
	independentPhishingClause := false
	independentPhishingClauseChecked := false
	hasIndependentPhishingClause := func() bool {
		if !independentPhishingClauseChecked {
			independentPhishingClause = candidateFieldHasIndependentPhishingRealCredentialClause(text)
			independentPhishingClauseChecked = true
		}
		return independentPhishingClause
	}
	independentExplicitClause := false
	independentExplicitClauseChecked := false
	hasIndependentExplicitClause := func() bool {
		if !independentExplicitClauseChecked {
			independentExplicitClause = c.candidateFieldHasIndependentExplicitMaliciousClause(text, fieldQuotedSpans)
			independentExplicitClauseChecked = true
		}
		return independentExplicitClause
	}
	if carrier, tailState := candidateInertLabeledCarrierExecutionTailProof(wholeText); carrier {
		// The exact first-line log/console/terminal label owns the complete
		// remainder of this field unless a later transition explicitly reactivates
		// that carrier. An oversized possible transition remains owned here while
		// its neutral proof-budget state is propagated to the request result.
		// Reactivation across parser-proven adjacent
		// fields still follows the profiled referent path; ordinary payload lines
		// must never materialize an eligible explicit candidate.
		if tailState == explicitMaliciousRelationProofBudgetExceeded && proofBudgetExceeded != nil {
			*proofBudgetExceeded = true
		}
		if tailState != explicitMaliciousRelationMatched {
			return nil
		}
	}
	wholeAnalyticalOwner := !wholeQuotedActivation &&
		(candidateQuotedOrAnalyticalScopePrepared(wholeText, wholePhishingProof) ||
			candidateTransformativeAnalyticalScope(wholeText))
	wholeDefensiveOwner := !wholeQuotedActivation && candidateExplicitRelationWholeFieldDefensiveOwner(wholeText)
	wholePhishingSimulation := candidatePhishingSyntheticSimulationScopePrepared(
		wholeText, wholePhishingProof,
	)

	_, wholeIndependentExecution := candidatePhishingIndependentMaliciousExecutionTailPrepared(
		wholeText, wholePhishingProof,
	)
	if len(wholeText) > maxCompactIntentProofBytes {
		if (wholeAnalyticalOwner || wholePhishingSimulation) &&
			!wholeIndependentExecution &&
			!hasIndependentPhishingClause() &&
			!hasIndependentExplicitClause() {
			return nil
		}
	} else if wholeAnalyticalOwner && !wholeIndependentExecution &&
		!hasIndependentPhishingClause() &&
		!hasIndependentExplicitClause() {
		return nil
	}
	preferredCategory, wholeRelationState := candidateExplicitMaliciousRelationCategoryProof(
		wholeText, wholePhishingProof,
	)
	wholeRelationComplete := wholeRelationState == explicitMaliciousRelationMatched
	if wholeRelationState == explicitMaliciousRelationProofBudgetExceeded {
		if proofBudgetExceeded != nil {
			*proofBudgetExceeded = true
		}
	}
	if clauseOverflow {
		return c.explicitMaliciousRelationOverflowCandidates(
			text,
			context,
			inspectionComplete,
			existingEligibleCategoryMask,
			wholeAnalyticalOwner || wholeDefensiveOwner || wholePhishingSimulation,
			wholeQuotedActivation,
			wholePhishingSimulation,
			fieldQuotedSpans,
		)
	}
	if wholeRelationComplete && !wholeQuotedActivation &&
		candidateExplicitRelationDefensiveConflictPrepared(preferredCategory, wholeText, wholePhishingProof) &&
		!wholeIndependentExecution &&
		!hasIndependentPhishingClause() &&
		!hasIndependentExplicitClause() {
		// Preserve a candidate-local defensive/analytical owner before the clause
		// walker discards it. Strong same-scope hostile execution is handled by the
		// conflict helper and still reaches the per-clause assessment below.
		return nil
	}
	candidates := make([]classificationCandidate, 0, 8)
	if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(
		wholeText, wholePhishingProof,
	); independent {
		if candidate, ok := explicitMaliciousRelationCandidatePrepared(
			wholeText, wholeText, wholePhishingProof, context, inspectionComplete, existingEligibleCategoryMask,
		); ok {
			var clauseTexts [maxExplicitQuotedActivationClauses]string
			var clauseIDs [maxExplicitQuotedActivationClauses]int
			clauseCount := 0
			clauseOverflow := false
			c.walkDirectiveClausesWithBoundaryRange(text, func(clause []rune, _, _ int, _ directiveBoundaryKind) bool {
				clauseText := strings.TrimSpace(string(clause))
				if clauseText == "" {
					return true
				}
				if clauseCount == len(clauseTexts) {
					clauseOverflow = true
					return false
				}
				clauseTexts[clauseCount] = clauseText
				clauseIDs[clauseCount] = clauseCount
				clauseCount++
				return true
			})
			if !clauseOverflow && clauseCount != 0 {
				bound := bindExplicitRelationCandidateToAdjacentClauses(
					&candidate, clauseTexts[:clauseCount], clauseIDs[:clauseCount],
				)
				if !bound {
					last := clauseCount - 1
					for index := range candidate.occurrences {
						selected := last
						if candidate.occurrences[index].Dimension == "object" {
							for clauseIndex := 0; clauseIndex < clauseCount; clauseIndex++ {
								if candidateExplicitRelationObjectOwnedBy(candidate.category, strings.ToLower(clauseTexts[clauseIndex])) {
									selected = clauseIndex
									break
								}
							}
						}
						candidate.occurrences[index].ClauseID = clauseIDs[selected]
						candidate.occurrences[index].SentenceID = clauseIDs[selected]
						candidate.occurrences[index].Start = 0
						candidate.occurrences[index].End = len([]rune(clauseTexts[selected]))
					}
					candidate.identity = directCandidateIdentityFor(candidate.category, candidate.occurrences, false)
					candidate.explanation.EvidenceOccurrenceCount = len(candidate.occurrences)
					bound = candidateIdentityBlockingProofComplete(candidate.identity)
				}
				if bound {
					candidates = append(candidates, candidate)
				}
			}
		}
	}
	if wholeRelationComplete && wholeQuotedActivation {
		spans, quoteComplete := metaOverrideQuotedSpans(wholeText)
		candidate, ok := explicitMaliciousRelationCandidatePrepared(
			wholeText, wholeText, wholePhishingProof, context, inspectionComplete, existingEligibleCategoryMask,
		)
		if quoteComplete && len(spans) != 0 && ok && candidate.category == preferredCategory {
			var clauseTexts [maxExplicitQuotedActivationClauses]string
			var clauseIDs [maxExplicitQuotedActivationClauses]int
			activationClauseCount := 0
			activationClauseOverflow := false
			c.walkDirectiveClausesWithBoundaryRange(text, func(clause []rune, _, _ int, _ directiveBoundaryKind) bool {
				clauseText := strings.TrimSpace(string(clause))
				if clauseText == "" {
					return true
				}
				if activationClauseCount == len(clauseTexts) {
					activationClauseOverflow = true
					return false
				}
				clauseTexts[activationClauseCount] = clauseText
				clauseIDs[activationClauseCount] = activationClauseCount
				activationClauseCount++
				return true
			})
			if !activationClauseOverflow && activationClauseCount >= 1 {
				bound := bindExplicitRelationCandidateToAdjacentClauses(
					&candidate,
					clauseTexts[:activationClauseCount],
					clauseIDs[:activationClauseCount],
				)
				if !bound && quotedSpanCount != 0 {
					// A quote-aware clause walker may retain the carrier and its
					// external activation as one physical clause. The completed
					// single-carrier activation proof above then supplies the local
					// ownership edge without borrowing from another record.
					for index := range candidate.occurrences {
						candidate.occurrences[index].ClauseID = 0
						candidate.occurrences[index].SentenceID = 0
						candidate.occurrences[index].Start = 0
						candidate.occurrences[index].End = len(text)
					}
					candidate.identity = directCandidateIdentityFor(candidate.category, candidate.occurrences, false)
					candidate.explanation.EvidenceOccurrenceCount = len(candidate.occurrences)
					bound = true
				}
				if bound {
					candidates = append(candidates, candidate)
				}
			}
		}
	}
	type linkedPhysicalClause struct {
		text             string
		clauseID         int
		start            int
		end              int
		explicitComplete bool
	}
	previousClause := linkedPhysicalClause{clauseID: -1}
	secondPreviousClause := linkedPhysicalClause{clauseID: -1}
	previousBoundary := directiveBoundaryStrong
	preferredCategoryEstablished := false
	advancePrevious := func(current linkedPhysicalClause, boundary directiveBoundaryKind) {
		secondPreviousClause = previousClause
		previousClause = current
		previousBoundary = boundary
	}
	clauseID := 0
	c.walkDirectiveClausesWithBoundaryRange(text, func(clause []rune, start, end int, boundary directiveBoundaryKind) bool {
		currentClauseID := clauseID
		clauseID++
		clauseText := string(clause)
		currentPhysical := linkedPhysicalClause{
			text: clauseText, clauseID: currentClauseID, start: start, end: end,
		}
		if !wholeQuotedActivation && explicitRelationWindowIntersectsQuotes(
			[]explicitRelationPhysicalClause{{runes: clause, start: start, end: end}}, fieldQuotedSpans,
		) {
			previousClause = linkedPhysicalClause{clauseID: -1}
			secondPreviousClause = linkedPhysicalClause{clauseID: -1}
			previousBoundary = directiveBoundaryStrong
			return true
		}
		currentCandidate, currentComplete := explicitMaliciousRelationCandidatePrepared(
			clauseText, wholeText, wholePhishingProof, context, inspectionComplete, existingEligibleCategoryMask,
		)
		currentPhysical.explicitComplete = currentComplete
		if wholeRelationComplete && currentComplete && currentCandidate.category == preferredCategory {
			preferredCategoryEstablished = true
		}
		linkedPhishing := previousClause.clauseID >= 0 && candidateLinkedPhishingSoftPair(
			previousClause.text, clauseText, wholeText, boundary,
		)
		if linkedPhishing {
			joined := strings.TrimSpace(previousClause.text + "\n" + clauseText)
			candidate, linked := explicitMaliciousRelationCandidatePrepared(
				joined, wholeText, wholePhishingProof, context, inspectionComplete, existingEligibleCategoryMask,
			)
			if linked && candidate.category == rules.CategoryPhishing &&
				(!wholeRelationComplete || candidate.category == preferredCategory) {
				var clauseTexts = [2]string{previousClause.text, clauseText}
				var clauseIDs = [2]int{previousClause.clauseID, currentClauseID}
				if bindExplicitRelationCandidateToAdjacentClauses(
					&candidate, clauseTexts[:], clauseIDs[:],
				) {
					candidates = append(candidates, candidate)
					if wholeRelationComplete && candidate.category == preferredCategory {
						preferredCategoryEstablished = true
					}
				}
			}
		}
		if previousClause.clauseID >= 0 && !linkedPhishing &&
			(!wholeRelationComplete || !preferredCategoryEstablished) &&
			(!previousClause.explicitComplete || !currentComplete) &&
			(boundary == directiveBoundarySoft || boundary == directiveBoundaryContinuation) {
			joined := strings.TrimSpace(previousClause.text + "\n" + clauseText)
			candidate, linked := explicitMaliciousRelationCandidatePrepared(
				joined, wholeText, wholePhishingProof, context, inspectionComplete, existingEligibleCategoryMask,
			)
			if linked && (!wholeRelationComplete || candidate.category == preferredCategory) {
				var clauseTexts = [2]string{previousClause.text, clauseText}
				var clauseIDs = [2]int{previousClause.clauseID, currentClauseID}
				if bindExplicitRelationCandidateToAdjacentClauses(
					&candidate,
					clauseTexts[:],
					clauseIDs[:],
				) {
					candidates = append(candidates, candidate)
				}
				if wholeRelationComplete && candidate.category == preferredCategory {
					preferredCategoryEstablished = true
				}
			}
		}
		if secondPreviousClause.clauseID >= 0 &&
			(!wholeRelationComplete || !preferredCategoryEstablished) &&
			(!secondPreviousClause.explicitComplete || !previousClause.explicitComplete || !currentComplete) &&
			(previousBoundary == directiveBoundarySoft || previousBoundary == directiveBoundaryContinuation) &&
			(boundary == directiveBoundarySoft || boundary == directiveBoundaryContinuation) {
			joined := strings.TrimSpace(secondPreviousClause.text + "\n" + previousClause.text + "\n" + clauseText)
			candidate, linked := explicitMaliciousRelationCandidatePrepared(
				joined, wholeText, wholePhishingProof, context, inspectionComplete, existingEligibleCategoryMask,
			)
			if linked && (!wholeRelationComplete || candidate.category == preferredCategory) {
				var clauseTexts = [3]string{secondPreviousClause.text, previousClause.text, clauseText}
				var clauseIDs = [3]int{secondPreviousClause.clauseID, previousClause.clauseID, currentClauseID}
				if bindExplicitRelationCandidateToAdjacentClauses(
					&candidate,
					clauseTexts[:],
					clauseIDs[:],
				) {
					candidates = append(candidates, candidate)
				}
				if wholeRelationComplete && candidate.category == preferredCategory {
					preferredCategoryEstablished = true
				}
			}
		}
		candidate, ok := currentCandidate, currentComplete
		if !ok {
			advancePrevious(currentPhysical, boundary)
			return true
		}
		if wholeRelationComplete && candidate.category != preferredCategory &&
			boundary != directiveBoundaryStrong {
			// Preserve the established whole-sentence taxonomy when a generic
			// consequence clause also forms a lower-level relation. For example,
			// a phishing deployment followed by "collect passwords" remains
			// phishing; the credential suffix must not steal the winner solely
			// because synthetic fallback candidates score 100.
			advancePrevious(currentPhysical, boundary)
			return true
		}
		for index := range candidate.occurrences {
			candidate.occurrences[index].ClauseID = currentClauseID
			candidate.occurrences[index].SentenceID = currentClauseID
			candidate.occurrences[index].Start = 0
			candidate.occurrences[index].End = len(clause)
		}
		candidate.identity = directCandidateIdentityFor(candidate.category, candidate.occurrences, false)
		candidate.explanation.EvidenceOccurrenceCount = len(candidate.occurrences)
		candidates = append(candidates, candidate)
		advancePrevious(currentPhysical, boundary)
		return true
	})
	return bestExplicitMaliciousRelationCandidates(candidates)
}

type explicitRelationRuneSpan struct {
	start int
	end   int
}

type explicitRelationClausePotential uint8

const (
	explicitRelationPotentialAction explicitRelationClausePotential = 1 << iota
)

type explicitRelationPhysicalClause struct {
	runes                        []rune
	clauseID                     int
	start                        int
	end                          int
	boundaryBefore               directiveBoundaryKind
	potential                    explicitRelationClausePotential
	potentialSet                 bool
	clearlyNonExecutable         bool
	requiresIndependentSpeechAct bool
}

type explicitRelationCandidateChoice struct {
	candidate   classificationCandidate
	clauseCount int
	spanRunes   int
	firstClause int
	lastClause  int
	softChainID int
	set         bool
}

type explicitRelationCandidateAlternates struct {
	leftmost  [8]explicitRelationCandidateChoice
	rightmost [8]explicitRelationCandidateChoice
	used      uint16
}

func (alternates *explicitRelationCandidateAlternates) reset() {
	if alternates == nil || alternates.used == 0 {
		return
	}
	for priority := range alternates.leftmost {
		if alternates.used&(uint16(1)<<uint(priority)) == 0 {
			continue
		}
		alternates.leftmost[priority] = explicitRelationCandidateChoice{}
		alternates.rightmost[priority] = explicitRelationCandidateChoice{}
	}
	alternates.used = 0
}

func candidateExplicitRelationWholeFieldDefensiveOwner(text string) bool {
	return candidateExplicitRelationLocalDefensiveOwner(text) || containsDetectionArtifact(text) ||
		isSafetyDeliverableClause(text) || hasAnyPrefix(text,
		"incident report", "historical incident report", "post-incident report", "forensic report",
	)
}

func candidateExplicitRelationClauseEstablishesOwner(clause []rune) bool {
	text := strings.ToLower(strings.TrimSpace(string(clause)))
	return text != "" && (candidateQuotedOrAnalyticalScope(text) ||
		candidateTransformativeAnalyticalScope(text) ||
		candidateExplicitRelationWholeFieldDefensiveOwner(text))
}

var candidateExplicitRelationCoarseNegationTerms = []string{
	"do not ", "never ", "don't ", "must not ", "must never ", "should not ", "should never ",
	"shall not ", "will not ", "cannot ", "can't ", "not to ",
	"forbid", "prohibit", "refuse to ",
}

var candidateExplicitRelationCoarseReversalTerms = []string{
	" but ", " however ", " instead ", " actually ", " anyway", "do it anyway",
	"do not fail", "don't fail", "must not fail", "mustn't fail", "not fail",
	"do not avoid", "don't avoid", "not avoid", "do not prevent", "not prevent",
	"do not refrain", "not refrain", "do not stop before", "not stop before",
	"will not refuse", "won't refuse", "not refuse", "same operation",
}

const explicitRelationASCIILetterCount = int('z'-'a') + 1

type explicitRelationASCIITrigramBuckets [explicitRelationASCIILetterCount][explicitRelationASCIILetterCount][explicitRelationASCIILetterCount][]string

type explicitRelationCoarseTermBuckets struct {
	// Most operational verbs start with three ASCII letters. Keep those terms in
	// a direct trigram table so long ordinary clauses do not retry every verb that
	// happens to share their first letter. The first-rune buckets retain short or
	// non-word prefixes, while non-ASCII terms keep their existing rune map.
	asciiTrigrams *explicitRelationASCIITrigramBuckets
	asciiFallback [utf8.RuneSelf][]string
	asciiShort    [utf8.RuneSelf][]string
	other         map[rune][]string
}

func explicitRelationASCIILetterIndex(value byte) (int, bool) {
	if value >= 'A' && value <= 'Z' {
		value += 'a' - 'A'
	}
	if value < 'a' || value > 'z' {
		return 0, false
	}
	return int(value - 'a'), true
}

func explicitRelationASCIITrigram(value string) (int, int, int, bool) {
	if len(value) < 3 {
		return 0, 0, 0, false
	}
	first, firstOK := explicitRelationASCIILetterIndex(value[0])
	second, secondOK := explicitRelationASCIILetterIndex(value[1])
	third, thirdOK := explicitRelationASCIILetterIndex(value[2])
	return first, second, third, firstOK && secondOK && thirdOK
}

func compileExplicitRelationCoarseTermBuckets(valueSets ...[]string) explicitRelationCoarseTermBuckets {
	var buckets explicitRelationCoarseTermBuckets
	for _, values := range valueSets {
		for _, value := range values {
			if value == "" {
				continue
			}
			if first, second, third, ok := explicitRelationASCIITrigram(value); ok {
				if buckets.asciiTrigrams == nil {
					buckets.asciiTrigrams = new(explicitRelationASCIITrigramBuckets)
				}
				buckets.asciiTrigrams[first][second][third] = append(
					buckets.asciiTrigrams[first][second][third], value,
				)
				continue
			}
			first, _ := utf8.DecodeRuneInString(value)
			if first >= 'A' && first <= 'Z' {
				first += 'a' - 'A'
			}
			if first >= 0 && first < utf8.RuneSelf {
				index := int(first)
				if utf8.RuneCountInString(value) < 3 {
					buckets.asciiShort[index] = append(buckets.asciiShort[index], value)
				} else {
					buckets.asciiFallback[index] = append(buckets.asciiFallback[index], value)
				}
				continue
			}
			if buckets.other == nil {
				buckets.other = make(map[rune][]string)
			}
			buckets.other[first] = append(buckets.other[first], value)
		}
	}
	return buckets
}

var candidateExplicitRelationActionTermBuckets = compileExplicitRelationCoarseTermBuckets(
	candidateExplicitMaliciousRelationActions,
)

var candidateExplicitRelationPotentialActionTermBuckets = compileExplicitRelationCoarseTermBuckets(
	candidateExplicitMaliciousRelationActions,
	candidatePhishingCredentialInteractionIntents,
)

var candidateExplicitRelationReversalTermBuckets = compileExplicitRelationCoarseTermBuckets(
	candidateExplicitRelationCoarseReversalTerms,
)

func runeSliceContainsFoldASCII(text []rune, value string) bool {
	if len(text) == 0 || value == "" {
		return false
	}
	for start := range text {
		if runeSliceMatchesFoldASCIIAt(text, start, value) {
			return true
		}
	}
	return false
}

func runeSliceMatchesFoldASCIIAt(text []rune, start int, value string) bool {
	index := start
	for _, expected := range value {
		if index >= len(text) {
			return false
		}
		current := text[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		if expected >= 'A' && expected <= 'Z' {
			expected += 'a' - 'A'
		}
		if current != expected {
			return false
		}
		index++
	}
	return true
}

func runeSliceContainsAnyFoldASCIIBucketed(
	text []rune,
	buckets *explicitRelationCoarseTermBuckets,
) bool {
	if len(text) == 0 || buckets == nil {
		return false
	}
	for start, current := range text {
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		var values []string
		if current >= 0 && current < utf8.RuneSelf {
			for _, value := range buckets.asciiShort[int(current)] {
				if runeSliceMatchesFoldASCIIAt(text, start, value) {
					return true
				}
			}
			if buckets.asciiTrigrams != nil && start+2 < len(text) {
				first, firstOK := explicitRelationASCIILetterIndex(byte(current))
				secondRune := text[start+1]
				thirdRune := text[start+2]
				if secondRune >= 0 && secondRune < utf8.RuneSelf && thirdRune >= 0 && thirdRune < utf8.RuneSelf {
					second, secondOK := explicitRelationASCIILetterIndex(byte(secondRune))
					third, thirdOK := explicitRelationASCIILetterIndex(byte(thirdRune))
					if firstOK && secondOK && thirdOK {
						values = buckets.asciiTrigrams[first][second][third]
					} else {
						values = buckets.asciiFallback[int(current)]
					}
				} else {
					values = buckets.asciiFallback[int(current)]
				}
			} else {
				values = buckets.asciiFallback[int(current)]
			}
		} else if buckets.other != nil {
			values = buckets.other[current]
		}
		for _, value := range values {
			if runeSliceMatchesFoldASCIIAt(text, start, value) {
				return true
			}
		}
	}
	return false
}

func candidateExplicitRelationClausePotentialRunes(clause []rune) explicitRelationClausePotential {
	if runeSliceContainsAnyFoldASCIIBucketed(clause, &candidateExplicitRelationPotentialActionTermBuckets) {
		return explicitRelationPotentialAction
	}
	return 0
}

func candidateExplicitRelationClausePreflightRunes(
	clause []rune,
	compactScratch *compactRuleIntentClauseScratch,
) (explicitRelationClausePotential, bool) {
	potential := candidateExplicitRelationClausePotentialRunes(clause)
	// A clause with no physical action occurrence cannot independently execute
	// this relation. Mark it non-executable without running the substantially
	// richer negation/permission proof; if a neighboring clause owns the action,
	// that action clause still decides whether the combined span is active.
	clearlyNonExecutable := potential&explicitRelationPotentialAction == 0 ||
		candidateExplicitRelationClauseClearlyNonExecutableRunes(clause, compactScratch)
	return potential, clearlyNonExecutable
}

func explicitRelationTrimLeadingDirectiveRunes(clause []rune) []rune {
	for len(clause) != 0 {
		switch clause[0] {
		case ' ', '\t', '\r', '\n', '-', '*', '#', '>', ',', ':':
			clause = clause[1:]
		default:
			return clause
		}
	}
	return clause
}

func explicitRelationTrimTrailingDirectiveRunes(clause []rune) []rune {
	for len(clause) != 0 {
		switch clause[len(clause)-1] {
		case ' ', '\t', '\r', '\n':
			clause = clause[:len(clause)-1]
		default:
			return clause
		}
	}
	return clause
}

func runeSliceIndexFoldASCII(text []rune, value string) int {
	if len(text) == 0 || value == "" {
		return -1
	}
	for start := range text {
		if runeSliceMatchesFoldASCIIAt(text, start, value) {
			return start
		}
	}
	return -1
}

func candidateExplicitRelationClauseStartsWithProhibitionRunes(clause []rune) bool {
	clause = explicitRelationTrimLeadingDirectiveRunes(clause)
	for _, prefix := range candidateExplicitRelationCoarseNegationTerms {
		if runeSliceMatchesFoldASCIIAt(clause, 0, prefix) {
			return true
		}
	}
	return false
}

func candidateExplicitRelationNumberedClosedGrammarRunes(
	clause []rune,
	prefix, suffix string,
) bool {
	clause = explicitRelationTrimTrailingDirectiveRunes(explicitRelationTrimLeadingDirectiveRunes(clause))
	if !runeSliceMatchesFoldASCIIAt(clause, 0, prefix) {
		return false
	}
	index := len(prefix)
	digitStart := index
	for index < len(clause) && clause[index] >= '0' && clause[index] <= '9' {
		index++
	}
	if index == digitStart || index+len(suffix) != len(clause) {
		return false
	}
	return runeSliceMatchesFoldASCIIAt(clause, index, suffix)
}

func candidateExplicitRelationClauseHasUnsafeProhibitionContinuationRunes(clause []rune) bool {
	for _, value := range []string{
		" but ", " however ", " instead ", " actually ", " anyway", " then ",
		" while ", " whereas ", " although ", " except ", " unless ", ",", ":",
	} {
		if runeSliceContainsFoldASCII(clause, value) {
			return true
		}
	}
	return false
}

func candidateExplicitRelationSimpleProhibitionRunes(clause []rune) bool {
	clause = explicitRelationTrimLeadingDirectiveRunes(clause)
	if !candidateExplicitRelationClauseStartsWithProhibitionRunes(clause) ||
		runeSliceContainsAnyFoldASCIIBucketed(clause, &candidateExplicitRelationReversalTermBuckets) ||
		candidateExplicitRelationClauseHasUnsafeProhibitionContinuationRunes(clause) {
		return false
	}
	andIndex := runeSliceIndexFoldASCII(clause, " and ")
	if andIndex < 0 {
		return true
	}
	if !runeSliceMatchesFoldASCIIAt(clause, andIndex, " and now ") {
		return false
	}
	suffix := explicitRelationTrimLeadingDirectiveRunes(clause[andIndex+len(" and now "):])
	return candidateExplicitRelationClauseStartsWithProhibitionRunes(suffix) &&
		runeSliceIndexFoldASCII(suffix, " and ") < 0 &&
		!candidateExplicitRelationClauseHasUnsafeProhibitionContinuationRunes(suffix)
}

func candidateExplicitRelationClauseClearlySuppressedRunes(clause []rune) bool {
	if len(clause) == 0 {
		return true
	}
	if candidateExplicitRelationNumberedClosedGrammarRunes(
		clause,
		"policy item ",
		" requires us to never deploy ransomware across production endpoints",
	) || candidateExplicitRelationNumberedClosedGrammarRunes(
		clause,
		"build customer records for approved migration batch ",
		"",
	) {
		return true
	}
	if candidateExplicitRelationSimpleProhibitionRunes(clause) {
		return true
	}
	return false
}

// candidateExplicitRelationClauseClearlyNonExecutableRunes extends the cheap
// prohibition proof with the existing permission-only grammar. The latter is
// important for overflow fields such as repeated "not forbidden to ..."
// statements: they express permission, not a current execution act, and must
// not force the expensive whole-window relation classifier for every clause.
// Reuse one caller-owned compact scratch across the field so this exact proof
// remains bounded without retaining prompt-derived state after classification.
func candidateExplicitRelationClauseClearlyNonExecutableRunes(
	clause []rune,
	compactScratch *compactRuleIntentClauseScratch,
) bool {
	if candidateExplicitRelationClauseClearlySuppressedRunes(clause) {
		return true
	}
	if len(clause) == 0 || len(clause) > maxCompactIntentProofBytes {
		return false
	}
	hasPermissionMarker := false
	for _, marker := range []string{"forbid", "prohibit", "禁止", "严禁", "拒绝"} {
		if runeSliceContainsFoldASCII(clause, marker) {
			hasPermissionMarker = true
			break
		}
	}
	if !hasPermissionMarker {
		return false
	}
	return candidatePermissionDominatedClauseWithScratch(string(clause), compactScratch)
}

// candidatePermissionDominatedClauseWithScratch proves permission locally.
// A later independent action may coexist in the same physical sentence, but
// it remains dominated only when its own bounded suffix is non-malicious. This
// prevents a broad verb such as create/release from borrowing the permission
// prefix's hostile object, while preserving a genuinely hostile continuation.
func candidatePermissionDominatedClauseWithScratch(
	clause string,
	compactScratch *compactRuleIntentClauseScratch,
) bool {
	proof := candidateRuleIntentClauseProofPreparedWithScratch(
		clause,
		candidatePermissionScopedIntents,
		candidatePermissionScopedIntentPatterns,
		compactScratch,
	)
	if proof.overflow || !proof.found {
		return false
	}
	if proof.permissionOnly {
		return true
	}
	for _, boundary := range []string{
		" and independently ", " but independently ", " and separately ",
		" and then ", ", then ", "; then ",
	} {
		index := strings.LastIndex(clause, boundary)
		if index < 0 {
			continue
		}
		prefix := strings.TrimSpace(clause[:index])
		tail := strings.TrimSpace(clause[index+len(boundary):])
		prefixProof := candidateRuleIntentClauseProofPreparedWithScratch(
			prefix, candidatePermissionScopedIntents, candidatePermissionScopedIntentPatterns, compactScratch,
		)
		tailProof := candidateRuleIntentClauseProofPreparedWithScratch(
			tail, candidatePermissionScopedIntents, candidatePermissionScopedIntentPatterns, compactScratch,
		)
		if prefixProof.permissionOnly && !prefixProof.overflow && tailProof.active && !tailProof.overflow &&
			candidateCurrentExecutionTail(tail) && !candidateTailHasHarmfulObject(tail) {
			return true
		}
	}
	return false
}

func (c *Classifier) explicitMaliciousRelationOverflowMayContainCandidate(text []rune) bool {
	if c == nil || len(text) == 0 {
		return false
	}
	// A suppression-dominated field is cheapest to reject clause by clause,
	// while ordinary prose without any operational action is cheapest to reject
	// with one action-only pass. Sample only the bounded window size to choose
	// between those equivalent preflights; either path still scans every clause
	// before admitting a relation and stores no field-sized state.
	sampledClauses := 0
	allSampledClausesClearlySuppressed := true
	c.walkDirectiveClausesWithBoundaryRange(text, func(
		clause []rune,
		_, _ int,
		_ directiveBoundaryKind,
	) bool {
		sampledClauses++
		if !candidateExplicitRelationClauseClearlySuppressedRunes(clause) {
			allSampledClausesClearlySuppressed = false
			return false
		}
		return sampledClauses < maxSemanticDirectiveSpan
	})
	if sampledClauses == 0 {
		return false
	}
	if !allSampledClausesClearlySuppressed &&
		!runeSliceContainsAnyFoldASCIIBucketed(text, &candidateExplicitRelationActionTermBuckets) {
		return false
	}
	var window [maxSemanticDirectiveSpan]explicitRelationPhysicalClause
	var compactScratch compactRuleIntentClauseScratch
	windowCount := 0
	found := false
	c.walkDirectiveClausesWithBoundaryRange(text, func(
		clause []rune,
		_, _ int,
		boundary directiveBoundaryKind,
	) bool {
		if boundary == directiveBoundaryStrong {
			windowCount = 0
		}
		if windowCount == len(window) {
			copy(window[:], window[1:])
			windowCount--
		}
		potential, clearlyNonExecutable := candidateExplicitRelationClausePreflightRunes(clause, &compactScratch)
		window[windowCount] = explicitRelationPhysicalClause{
			runes:                clause,
			boundaryBefore:       boundary,
			potential:            potential,
			potentialSet:         true,
			clearlyNonExecutable: clearlyNonExecutable,
		}
		windowCount++
		for count := 1; count <= windowCount; count++ {
			first := windowCount - count
			if count > 1 {
				boundaryBefore := window[first+1].boundaryBefore
				if boundaryBefore != directiveBoundarySoft && boundaryBefore != directiveBoundaryContinuation {
					break
				}
			}
			spanRunes := count - 1
			allClearlyNonExecutable := true
			for index := first; index < windowCount; index++ {
				spanRunes += len(window[index].runes)
				allClearlyNonExecutable = allClearlyNonExecutable && window[index].clearlyNonExecutable
			}
			if allClearlyNonExecutable || spanRunes > maxCompactIntentProofBytes {
				continue
			}
			var potential explicitRelationClausePotential
			for index := first; index < windowCount; index++ {
				if !window[index].potentialSet {
					window[index].potential = candidateExplicitRelationClausePotentialRunes(window[index].runes)
					window[index].potentialSet = true
				}
				potential |= window[index].potential
			}
			if potential&explicitRelationPotentialAction != 0 {
				windowText, ok := explicitRelationWindowText(window[first:windowCount])
				if !ok {
					continue
				}
				if _, complete := candidateExplicitMaliciousRelationCategory(windowText); complete {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func explicitRelationWindowIntersectsQuotes(
	clauses []explicitRelationPhysicalClause,
	quotedSpans []explicitRelationRuneSpan,
) bool {
	if len(quotedSpans) == 0 || len(clauses) == 0 {
		return false
	}
	windowStart := clauses[0].start
	windowEnd := clauses[len(clauses)-1].end
	for _, quotedSpan := range quotedSpans {
		if quotedSpan.start >= windowEnd {
			return false
		}
		if windowStart < quotedSpan.end && windowEnd > quotedSpan.start {
			return true
		}
	}
	return false
}

func explicitRelationWindowText(clauses []explicitRelationPhysicalClause) (string, bool) {
	if len(clauses) == 0 {
		return "", false
	}
	totalRunes := len(clauses) - 1
	for _, clause := range clauses {
		totalRunes += len(clause.runes)
		if totalRunes > maxCompactIntentProofBytes {
			return "", false
		}
	}
	if len(clauses) == 1 {
		text := strings.TrimSpace(string(clauses[0].runes))
		return text, text != "" && len(text) <= maxCompactIntentProofBytes
	}
	var builder strings.Builder
	builder.Grow(totalRunes)
	for index, clause := range clauses {
		if index != 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(string(clause.runes))
	}
	text := strings.TrimSpace(builder.String())
	return text, text != "" && len(text) <= maxCompactIntentProofBytes
}

func candidateExplicitRelationIndependentSpeechAct(text string) bool {
	text = strings.TrimLeft(strings.TrimSpace(text), "-*#>,:\t")
	return startsWithRuleIntent(text, candidateExplicitMaliciousRelationActions) ||
		startsWithRuleIntent(text, candidatePhishingCredentialInteractionIntents) ||
		hasOperationalDeliverableFraming(text)
}

func (c *Classifier) candidateFieldHasIndependentExplicitMaliciousClause(
	text []rune,
	quotedSpans []explicitRelationRuneSpan,
) bool {
	if c == nil || len(text) == 0 {
		return false
	}
	found := false
	var compactScratch compactRuleIntentClauseScratch
	transformativeOwnerOwnsNextClause := false
	c.walkDirectiveClausesWithBoundaryRange(text, func(
		clause []rune,
		start, end int,
		boundary directiveBoundaryKind,
	) bool {
		clauseText := strings.ToLower(strings.TrimSpace(string(clause)))
		ownedByTransformativeOwner := transformativeOwnerOwnsNextClause
		transformativeOwnerOwnsNextClause = clauseText != "" &&
			candidateTransformativeAnalyticalScope(clauseText)
		if ownedByTransformativeOwner {
			// A bounded transformative owner such as "rewrite the dangerous
			// request as a compliant refusal:" owns exactly the immediately
			// following payload clause, even when a colon produced a strong
			// physical boundary. A later execution clause is still independent.
			return true
		}
		if boundary != directiveBoundaryNone && boundary != directiveBoundaryStrong {
			return true
		}
		if explicitRelationWindowIntersectsQuotes(
			[]explicitRelationPhysicalClause{{runes: clause, start: start, end: end}}, quotedSpans,
		) || candidateExplicitRelationClauseClearlyNonExecutableRunes(clause, &compactScratch) ||
			candidateExplicitRelationSimpleProhibitionRunes(clause) {
			return true
		}
		if clauseText == "" || !candidateExplicitRelationIndependentSpeechAct(clauseText) ||
			candidateInertLabeledCarrier(clauseText) || candidateQuotedOrAnalyticalScope(clauseText) ||
			candidateTransformativeAnalyticalScope(clauseText) ||
			candidateExplicitRelationWholeFieldDefensiveOwner(clauseText) ||
			candidatePermissionOnlyScope(clauseText) || candidatePhishingDetectionArtifactScope(clauseText) {
			return true
		}
		_, found = candidateExplicitMaliciousRelationCategory(clauseText)
		return !found
	})
	return found
}

func bindExplicitRelationCandidateToPhysicalClauses(
	candidate *classificationCandidate,
	clauses []explicitRelationPhysicalClause,
) bool {
	if candidate == nil || len(clauses) == 0 {
		return false
	}
	var clauseTexts [maxSemanticDirectiveSpan]string
	var clauseIDs [maxSemanticDirectiveSpan]int
	for index, clause := range clauses {
		clauseTexts[index] = string(clause.runes)
		clauseIDs[index] = clause.clauseID
	}
	return bindExplicitRelationCandidateToAdjacentClauses(
		candidate, clauseTexts[:len(clauses)], clauseIDs[:len(clauses)],
	)
}

func explicitRelationCandidateChoiceBetter(
	candidate classificationCandidate,
	clauseCount, spanRunes, firstClause, lastClause, softChainID int,
	current explicitRelationCandidateChoice,
) bool {
	if !current.set {
		return true
	}
	if candidate.eligibility.Eligible != current.candidate.eligibility.Eligible {
		return candidate.eligibility.Eligible
	}
	candidateAxes := explicitRelationCandidateAxisMask(candidate)
	currentAxes := explicitRelationCandidateAxisMask(current.candidate)
	candidateActionRoot, candidateActionRootOK := explicitRelationCandidateActionRootClause(candidate)
	currentActionRoot, currentActionRootOK := explicitRelationCandidateActionRootClause(current.candidate)
	if candidate.eligibility.Eligible && current.candidate.eligibility.Eligible &&
		softChainID == current.softChainID && candidateActionRootOK && currentActionRootOK &&
		candidateActionRoot == currentActionRoot && explicitRelationClauseRangesOverlap(
		firstClause, lastClause, current.firstClause, current.lastClause,
	) && candidateAxes != currentAxes {
		// A longer bounded window may complete additional behavior axes owned by
		// the same physical speech act (for example persistence + evasion +
		// outbound C2). It may replace the minimal span only when its proof is a
		// strict semantic superset. Equal-cardinality and otherwise incomparable
		// axis sets retain the deterministic minimal-span tie-breakers below.
		candidateStrictSuperset := candidateAxes&currentAxes == currentAxes
		currentStrictSuperset := candidateAxes&currentAxes == candidateAxes
		if candidateStrictSuperset {
			return true
		}
		if currentStrictSuperset {
			return false
		}
	}
	if clauseCount != current.clauseCount {
		return clauseCount < current.clauseCount
	}
	if spanRunes != current.spanRunes {
		return spanRunes < current.spanRunes
	}
	return firstClause < current.firstClause
}

func explicitRelationCandidateActionRootClause(candidate classificationCandidate) (int, bool) {
	root := -1
	for _, occurrence := range candidate.occurrences {
		if occurrence.Dimension != "action" {
			continue
		}
		if occurrence.ClauseID < 0 || root >= 0 && root != occurrence.ClauseID {
			return -1, false
		}
		root = occurrence.ClauseID
	}
	return root, root >= 0
}

type explicitRelationAxisMask uint8

const (
	explicitRelationAxisVictim explicitRelationAxisMask = 1 << iota
	explicitRelationAxisCovert
	explicitRelationAxisExfiltration
	explicitRelationAxisPersistence
	explicitRelationAxisDestructive
	explicitRelationAxisEvasion
)

func explicitRelationCandidateAxisMask(candidate classificationCandidate) explicitRelationAxisMask {
	var mask explicitRelationAxisMask
	for _, axis := range [...]struct {
		present bool
		mask    explicitRelationAxisMask
	}{
		{candidate.eligibility.ExplicitVictimOrNonConsent, explicitRelationAxisVictim},
		{candidate.eligibility.CovertAcquisition, explicitRelationAxisCovert},
		{candidate.eligibility.ExfiltrationOrTakeover, explicitRelationAxisExfiltration},
		{candidate.eligibility.MaliciousPersistence, explicitRelationAxisPersistence},
		{candidate.eligibility.DestructiveOutcome, explicitRelationAxisDestructive},
		{candidate.eligibility.SecurityControlEvasion, explicitRelationAxisEvasion},
	} {
		if axis.present {
			mask |= axis.mask
		}
	}
	return mask
}

func explicitRelationClauseRangesOverlap(first, last, otherFirst, otherLast int) bool {
	if first < 0 || otherFirst < 0 || last < first || otherLast < otherFirst {
		return false
	}
	return first <= otherLast && otherFirst <= last
}

func considerExplicitRelationCandidateChoice(
	choices *[8]explicitRelationCandidateChoice,
	candidate classificationCandidate,
	clauseCount, spanRunes, firstClause, lastClause, softChainID int,
) {
	priority := categoryPriority(candidate.category)
	if priority < 0 || priority >= len(choices) {
		return
	}
	current := choices[priority]
	if !explicitRelationCandidateChoiceBetter(
		candidate, clauseCount, spanRunes, firstClause, lastClause, softChainID, current,
	) {
		return
	}
	choices[priority] = explicitRelationCandidateChoice{
		candidate: candidate, clauseCount: clauseCount, spanRunes: spanRunes,
		firstClause: firstClause, lastClause: lastClause, softChainID: softChainID,
		set: true,
	}
}

func recordExplicitRelationCandidateChoice(
	choices *[8]explicitRelationCandidateChoice,
	alternates *explicitRelationCandidateAlternates,
	candidate classificationCandidate,
	clauseCount, spanRunes, firstClause, lastClause, softChainID int,
) {
	considerExplicitRelationCandidateChoice(
		choices, candidate, clauseCount, spanRunes, firstClause, lastClause, softChainID,
	)
	if alternates == nil {
		return
	}
	priority := categoryPriority(candidate.category)
	if priority < 0 || priority >= len(alternates.leftmost) {
		return
	}
	alternates.used |= uint16(1) << uint(priority)
	choice := explicitRelationCandidateChoice{
		candidate: candidate, clauseCount: clauseCount, spanRunes: spanRunes,
		firstClause: firstClause, lastClause: lastClause, softChainID: softChainID,
		set: true,
	}
	leftmost := alternates.leftmost[priority]
	if !leftmost.set || lastClause < leftmost.lastClause ||
		lastClause == leftmost.lastClause && explicitRelationCandidateChoiceBetter(
			candidate, clauseCount, spanRunes, firstClause, lastClause, softChainID, leftmost,
		) {
		alternates.leftmost[priority] = choice
	}
	rightmost := alternates.rightmost[priority]
	if !rightmost.set || firstClause > rightmost.firstClause ||
		firstClause == rightmost.firstClause && explicitRelationCandidateChoiceBetter(
			candidate, clauseCount, spanRunes, firstClause, lastClause, softChainID, rightmost,
		) {
		alternates.rightmost[priority] = choice
	}
}

func explicitRelationChoiceDominatedBy(
	primary, secondary explicitRelationCandidateChoice,
) bool {
	if !primary.set || !secondary.set ||
		!primary.candidate.eligibility.Eligible || !secondary.candidate.eligibility.Eligible ||
		secondary.softChainID != primary.softChainID {
		return false
	}
	if explicitRelationClauseRangesOverlap(
		primary.firstClause, primary.lastClause, secondary.firstClause, secondary.lastClause,
	) {
		return true
	}
	// A distinctive deployment core may be completed in one physical clause
	// while its generic consequence occupies the immediately adjacent comma or
	// continuation clause. Treat that direct continuation as the same bounded
	// speech act; a one-clause gap or strong-chain boundary remains independent.
	return primary.lastClause+1 == secondary.firstClause ||
		secondary.lastClause+1 == primary.firstClause
}

func suppressExplicitRelationChoiceInSoftChain(
	choices *[8]explicitRelationCandidateChoice,
	alternates *explicitRelationCandidateAlternates,
	primary explicitRelationCandidateChoice,
	secondaryCategory rules.Category,
) {
	priority := categoryPriority(secondaryCategory)
	if choices == nil || priority < 0 || priority >= len(choices) || !primary.set {
		return
	}
	secondary := choices[priority]
	if !explicitRelationChoiceDominatedBy(primary, secondary) {
		return
	}
	var replacement explicitRelationCandidateChoice
	if alternates != nil {
		for _, alternate := range [...]explicitRelationCandidateChoice{
			// Any interval disjoint from the primary lies wholly to its left or
			// right. Retaining the minimum-end and maximum-start choices therefore
			// guarantees one bounded fallback whenever an independent candidate
			// exists, without growing state with the length of a soft chain.
			alternates.leftmost[priority], alternates.rightmost[priority],
		} {
			if !alternate.set || explicitRelationChoiceDominatedBy(primary, alternate) {
				continue
			}
			if explicitRelationCandidateChoiceBetter(
				alternate.candidate,
				alternate.clauseCount,
				alternate.spanRunes,
				alternate.firstClause,
				alternate.lastClause,
				alternate.softChainID,
				replacement,
			) {
				replacement = alternate
			}
		}
	}
	choices[priority] = replacement
}

func suppressSecondaryExplicitRelationsInSoftChain(
	choices *[8]explicitRelationCandidateChoice,
	alternates *explicitRelationCandidateAlternates,
) {
	if choices == nil {
		return
	}
	ransomwarePriority := categoryPriority(rules.CategoryRansomware)
	if ransomwarePriority >= 0 && ransomwarePriority < len(choices) && choices[ransomwarePriority].set {
		primary := choices[ransomwarePriority]
		// Evasion and generic malware are common secondary axes of one bounded
		// ransomware execution core. Keeping them as independent score-100 typed
		// fallbacks can outrank the established ransomware rule solely because an
		// explicit rule ID wins a tie. Suppress only eligible proofs whose physical
		// clause ranges overlap this ransomware core.
		suppressExplicitRelationChoiceInSoftChain(choices, alternates, primary, rules.CategoryEvasion)
		suppressExplicitRelationChoiceInSoftChain(choices, alternates, primary, rules.CategoryMalware)
	}
	phishingPriority := categoryPriority(rules.CategoryPhishing)
	if phishingPriority >= 0 && phishingPriority < len(choices) && choices[phishingPriority].set {
		primary := choices[phishingPriority]
		// Credential collection and outbound delivery can be consequences of the
		// same phishing speech act. Preserve the distinctive deceptive-delivery
		// taxonomy without suppressing an independent theft or export record that
		// merely shares the same long soft chain.
		suppressExplicitRelationChoiceInSoftChain(choices, alternates, primary, rules.CategoryCredentialTheft)
		suppressExplicitRelationChoiceInSoftChain(choices, alternates, primary, rules.CategoryExfiltration)
	}
}

func mergeExplicitRelationCandidateChoices(
	destination *[8]explicitRelationCandidateChoice,
	source *[8]explicitRelationCandidateChoice,
	alternates *explicitRelationCandidateAlternates,
) {
	if destination == nil || source == nil {
		return
	}
	suppressSecondaryExplicitRelationsInSoftChain(source, alternates)
	for _, choice := range source {
		if !choice.set {
			continue
		}
		considerExplicitRelationCandidateChoice(
			destination,
			choice.candidate,
			choice.clauseCount,
			choice.spanRunes,
			choice.firstClause,
			choice.lastClause,
			choice.softChainID,
		)
	}
}

func explicitRelationCandidatesFromChoices(choices [8]explicitRelationCandidateChoice) []classificationCandidate {
	candidates := make([]classificationCandidate, 0, len(choices))
	for _, category := range classifierCategoryOrder {
		priority := categoryPriority(category)
		if priority < 0 || priority >= len(choices) || !choices[priority].set {
			continue
		}
		candidates = append(candidates, choices[priority].candidate)
	}
	return candidates
}

func bestExplicitMaliciousRelationCandidates(candidates []classificationCandidate) []classificationCandidate {
	if len(candidates) <= 1 {
		return candidates
	}
	var choices [8]explicitRelationCandidateChoice
	for _, candidate := range candidates {
		clauseCount := len(candidate.identity.clauseIDs)
		spanRunes := 0
		firstClause := int(^uint(0) >> 1)
		lastClause := -1
		if clauseCount == 0 {
			clauseCount = maxSemanticDirectiveSpan + 1
		}
		for _, occurrence := range candidate.occurrences {
			if occurrence.End > occurrence.Start {
				spanRunes += occurrence.End - occurrence.Start
			}
			if occurrence.ClauseID >= 0 && occurrence.ClauseID < firstClause {
				firstClause = occurrence.ClauseID
			}
			if occurrence.ClauseID > lastClause {
				lastClause = occurrence.ClauseID
			}
		}
		considerExplicitRelationCandidateChoice(
			&choices, candidate, clauseCount, spanRunes, firstClause, lastClause, -1,
		)
	}
	return explicitRelationCandidatesFromChoices(choices)
}

func (c *Classifier) explicitMaliciousRelationOverflowCandidates(
	text []rune,
	context ContextFlags,
	inspectionComplete bool,
	existingEligibleCategoryMask uint16,
	hasWholeFieldOwner bool,
	wholeQuotedActivation bool,
	wholePhishingSimulation bool,
	quotedSpans []explicitRelationRuneSpan,
) []classificationCandidate {
	var choices [8]explicitRelationCandidateChoice
	var softChainChoices [8]explicitRelationCandidateChoice
	var softChainAlternates explicitRelationCandidateAlternates
	var window [maxSemanticDirectiveSpan]explicitRelationPhysicalClause
	var compactScratch compactRuleIntentClauseScratch
	windowCount := 0
	clauseID := 0
	softChainID := 0
	ownerSeen := false
	flushSoftChain := func() {
		mergeExplicitRelationCandidateChoices(&choices, &softChainChoices, &softChainAlternates)
		softChainChoices = [8]explicitRelationCandidateChoice{}
		softChainAlternates.reset()
	}
	c.walkDirectiveClausesWithBoundaryRange(text, func(
		clause []rune,
		start, end int,
		boundary directiveBoundaryKind,
	) bool {
		currentClauseID := clauseID
		clauseID++
		if boundary == directiveBoundaryStrong {
			flushSoftChain()
			softChainID++
			windowCount = 0
		}
		if windowCount == len(window) {
			copy(window[:], window[1:])
			windowCount--
		}
		potential, clearlyNonExecutable := candidateExplicitRelationClausePreflightRunes(clause, &compactScratch)
		window[windowCount] = explicitRelationPhysicalClause{
			runes: clause, clauseID: currentClauseID, start: start, end: end,
			boundaryBefore:               boundary,
			potential:                    potential,
			potentialSet:                 true,
			clearlyNonExecutable:         clearlyNonExecutable,
			requiresIndependentSpeechAct: hasWholeFieldOwner && ownerSeen,
		}
		windowCount++

		for count := 1; count <= windowCount; count++ {
			first := windowCount - count
			if count > 1 {
				boundaryBefore := window[first+1].boundaryBefore
				if boundaryBefore != directiveBoundarySoft && boundaryBefore != directiveBoundaryContinuation {
					break
				}
			}
			physical := window[first:windowCount]
			if physical[0].requiresIndependentSpeechAct &&
				(physical[0].boundaryBefore == directiveBoundarySoft ||
					physical[0].boundaryBefore == directiveBoundaryContinuation) {
				// A soft continuation belongs to the preceding analytical/defensive
				// owner. It cannot become an independent malicious speech act merely
				// because the fragment itself starts with an action verb.
				continue
			}
			spanRunes := count - 1
			allClearlyNonExecutable := true
			for _, candidateClause := range physical {
				spanRunes += len(candidateClause.runes)
				allClearlyNonExecutable = allClearlyNonExecutable && candidateClause.clearlyNonExecutable
			}
			if allClearlyNonExecutable || spanRunes > maxCompactIntentProofBytes ||
				!wholeQuotedActivation && explicitRelationWindowIntersectsQuotes(physical, quotedSpans) {
				continue
			}
			var potential explicitRelationClausePotential
			for index := first; index < windowCount; index++ {
				if !window[index].potentialSet {
					window[index].potential = candidateExplicitRelationClausePotentialRunes(window[index].runes)
					window[index].potentialSet = true
				}
				potential |= window[index].potential
			}
			if potential&explicitRelationPotentialAction == 0 {
				continue
			}
			windowText, ok := explicitRelationWindowText(physical)
			if !ok || physical[0].requiresIndependentSpeechAct &&
				!candidateExplicitRelationIndependentSpeechAct(windowText) {
				continue
			}
			candidate, complete := explicitMaliciousRelationCandidate(
				windowText, windowText, context, inspectionComplete, existingEligibleCategoryMask,
			)
			if !complete || wholePhishingSimulation && candidate.category == rules.CategoryPhishing {
				continue
			}
			if !bindExplicitRelationCandidateToPhysicalClauses(&candidate, physical) {
				continue
			}
			recordExplicitRelationCandidateChoice(
				&softChainChoices,
				&softChainAlternates,
				candidate,
				count,
				spanRunes,
				physical[0].clauseID,
				physical[len(physical)-1].clauseID,
				softChainID,
			)
		}
		if hasWholeFieldOwner && candidateExplicitRelationClauseEstablishesOwner(clause) {
			ownerSeen = true
		}
		return true
	})
	flushSoftChain()
	return explicitRelationCandidatesFromChoices(choices)
}

func bindExplicitRelationCandidateToAdjacentClauses(
	candidate *classificationCandidate,
	clauseTexts []string,
	clauseIDs []int,
) bool {
	if candidate == nil || len(clauseTexts) == 0 || len(clauseTexts) != len(clauseIDs) {
		return false
	}
	for index := range clauseTexts {
		clauseTexts[index] = strings.ToLower(strings.TrimSpace(clauseTexts[index]))
	}
	var selectedClauses [8]int
	if len(candidate.occurrences) > len(selectedClauses) {
		return false
	}
	for index := range candidate.occurrences {
		dimension := candidate.occurrences[index].Dimension
		selected := -1
		for clauseIndex, clauseText := range clauseTexts {
			if candidateExplicitRelationDimensionOwnedBy(candidate.category, dimension, clauseText) {
				selected = clauseIndex
				break
			}
		}
		if selected < 0 {
			if candidateExplicitRelationDimensionRequiresPhysicalOwner(*candidate, dimension) {
				return false
			}
			selected = 0
			if dimension == "harm" || dimension == "target" || dimension == "destination" ||
				dimension == "outcome" || dimension == "impact" || dimension == "evasion" {
				selected = len(clauseTexts) - 1
			}
		}
		selectedClauses[index] = selected
	}
	for index := range candidate.occurrences {
		selected := selectedClauses[index]
		candidate.occurrences[index].ClauseID = clauseIDs[selected]
		candidate.occurrences[index].SentenceID = clauseIDs[selected]
		candidate.occurrences[index].Start = 0
		candidate.occurrences[index].End = len([]rune(clauseTexts[selected]))
	}
	candidate.identity = directCandidateIdentityFor(candidate.category, candidate.occurrences, false)
	candidate.explanation.EvidenceOccurrenceCount = len(candidate.occurrences)
	return true
}

func candidateExplicitRelationDimensionRequiresPhysicalOwner(
	candidate classificationCandidate,
	dimension string,
) bool {
	switch dimension {
	case "harm", "object", "action", "target":
		return true
	case "destination":
		return candidate.eligibility.ExfiltrationOrTakeover
	case "outcome":
		return candidate.eligibility.MaliciousPersistence
	case "impact":
		return candidate.eligibility.DestructiveOutcome
	case "evasion":
		return candidate.eligibility.SecurityControlEvasion
	default:
		return false
	}
}

func candidateExplicitRelationDimensionOwnedBy(category rules.Category, dimension, text string) bool {
	if text == "" {
		return false
	}
	switch dimension {
	case "action":
		return candidateExplicitMaliciousRelationAction(text) ||
			category == rules.CategoryPhishing && candidatePhishingCredentialInteractionAction(text)
	case "harm":
		return candidateExplicitMaliciousHostileScope(text) || candidateCovertAcquisition(text) ||
			candidateDestructiveOutcome(category, text) || candidateSecurityControlEvasion(category, text) ||
			category == rules.CategoryPhishing && candidatePhishingCredentialCollectionClause(text) ||
			category == rules.CategoryEvasion &&
				(candidateSecurityControlEvasionMaliciousPurpose(text) || candidatePromptInjectionHarmScope(text))
	case "target":
		return candidateExplicitMaliciousHostileScope(text) || candidateCovertAcquisition(text) ||
			candidateExplicitRelationObjectOwnedBy(category, text)
	case "destination":
		return candidateExplicitExfiltrationOutbound(text) || candidateExfiltrationOrTakeover(text)
	case "outcome":
		return candidateMaliciousPersistence(category, text)
	case "impact":
		return candidateDestructiveOutcome(category, text) ||
			(category == rules.CategoryRansomware || category == rules.CategoryDisruption) &&
				candidateExplicitRelationObjectOwnedBy(category, text)
	case "evasion":
		return candidateSecurityControlEvasionMechanism(text) || containsAnyLiteral(text,
			"override", "ignore", "discard", "reveal", "disclose", "expose", "bypass", "unrestricted mode",
			"active instructions", "injected instruction", "injection language", "prompt injection",
			"无视", "忽略", "泄露", "覆盖", "注入", "植入指令", "越权指令", "不受限制模式",
		)
	case "object":
		return candidateExplicitRelationObjectOwnedBy(category, text)
	}
	return false
}

func candidateExplicitRelationObjectOwnedBy(category rules.Category, text string) bool {
	switch category {
	case rules.CategoryCredentialTheft:
		return candidateExplicitCredentialMaterial(text)
	case rules.CategoryPhishing:
		return candidatePhishingDeceptionSurface(text) || candidateExplicitCredentialMaterial(text)
	case rules.CategoryMalware:
		return containsAnyLiteral(text, candidateExplicitMalwareObjectTerms...)
	case rules.CategoryRansomware:
		return candidateDirectRansomwareExecution(text) || candidateDestructiveOutcome(category, text) ||
			containsAnyLiteral(text, "ransomware", "ransom", "hostage", "勒索", "赎金")
	case rules.CategoryExploitation:
		return containsAnyLiteral(text,
			"exploit", "flaw", "weakness", "vulnerability", "failure path", "crash", "injection", "overflow", "boundary error",
			"缺陷", "漏洞", "弱点", "崩溃", "注入", "溢出", "校验缺口",
		)
	case rules.CategoryDisruption:
		return candidateDestructiveOutcome(category, text) || containsAnyLiteral(text,
			"service", "cluster", "gateway", "queue", "capacity", "connection pool", "request storm", "denial of service", "ddos",
			"服务", "集群", "网关", "队列", "容量", "拒绝服务",
		)
	case rules.CategoryExfiltration:
		return candidateExplicitExfiltrationObject(text)
	case rules.CategoryEvasion:
		return containsAnyLiteral(text,
			"model", "assistant", "prompt", "system instruction", "protected context", "tool result", "instruction file",
			"security control", "security telemetry", "defensive telemetry", "monitoring", "detection", "sandbox", "endpoint defense",
			"endpoint protection", "endpoint-protection", "endpoint analytics", "scheduled-task analytics", "intrusion alert",
			"edr", "siem", "antivirus", "audit", "ioc", "yara", "sigma", "signature scanner", "signature scanners",
			"模型", "助手", "系统指令", "受保护上下文", "安全控制", "安全遥测", "防御遥测", "监控", "检测", "沙箱", "防护", "防护记录", "安全记录",
		)
	}
	return false
}

func explicitMaliciousRelationRuleID(category rules.Category) string {
	switch category {
	case rules.CategoryCredentialTheft:
		return explicitMaliciousRelationRulePrefix + "CREDENTIAL"
	case rules.CategoryPhishing:
		return explicitMaliciousRelationRulePrefix + "PHISHING"
	case rules.CategoryMalware:
		return explicitMaliciousRelationRulePrefix + "MALWARE"
	case rules.CategoryRansomware:
		return explicitMaliciousRelationRulePrefix + "RANSOMWARE"
	case rules.CategoryExploitation:
		return explicitMaliciousRelationRulePrefix + "EXPLOITATION"
	case rules.CategoryDisruption:
		return explicitMaliciousRelationRulePrefix + "DISRUPTION"
	case rules.CategoryExfiltration:
		return explicitMaliciousRelationRulePrefix + "EXFILTRATION"
	case rules.CategoryEvasion:
		return explicitMaliciousRelationRulePrefix + "EVASION"
	default:
		return explicitMaliciousRelationRulePrefix + "UNKNOWN"
	}
}

func candidateExplicitMaliciousRelationCategory(raw string) (rules.Category, bool) {
	return candidateExplicitMaliciousRelationCategoryPrepared(raw, nil)
}

func candidateExplicitMaliciousRelationCategoryPrepared(
	raw string,
	phishingProof *candidatePhishingRelationProof,
) (rules.Category, bool) {
	category, state := candidateExplicitMaliciousRelationCategoryProof(raw, phishingProof)
	return category, state == explicitMaliciousRelationMatched
}

func candidateExplicitMaliciousRelationCategoryProof(
	raw string,
	phishingProof *candidatePhishingRelationProof,
) (rules.Category, explicitMaliciousRelationProofState) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", explicitMaliciousRelationNotMatched
	}
	if len(text) > maxCompactIntentProofBytes {
		// The request-wide phishing cache may be mid-population when the explicit
		// fallback is reached. Use an independent proof object for this tri-state
		// preflight so a partially cached recursive owner check cannot turn a safe
		// detection artifact into a synthetic budget overflow.
		if candidateExplicitMaliciousRelationOversizedPotential(strings.ToLower(text), nil) {
			return "", explicitMaliciousRelationProofBudgetExceeded
		}
		return "", explicitMaliciousRelationNotMatched
	}
	return candidateExplicitMaliciousRelationCategoryProofWithinBudget(text, phishingProof)
}

func candidateExplicitMaliciousRelationCategoryProofWithinBudget(
	raw string,
	phishingProof *candidatePhishingRelationProof,
) (rules.Category, explicitMaliciousRelationProofState) {
	text := strings.TrimSpace(raw)
	if text == "" || len(text) > maxCompactIntentProofBytes {
		return "", explicitMaliciousRelationNotMatched
	}
	if candidateExplicitRelationClauseBudgetExceeded(text) {
		// The clause-overflow caller has its own bounded rolling-window proof and
		// deliberately treats this whole-field view as unavailable, not as a
		// field-wide overflow. Keep direct callers source-compatible while the
		// enclosing scanner completes the proof clause by clause.
		return "", explicitMaliciousRelationNotMatched
	}
	if tail, ok := candidatePermissionIndependentMaliciousTail(strings.ToLower(text)); ok {
		text = tail
	}
	text = strings.ToLower(text)
	if candidateExplicitRelationAmbiguousQuoteStructure(text) ||
		candidateExplicitRelationQuotedPayloadOwnsOnlyAction(text) {
		return "", explicitMaliciousRelationNotMatched
	}
	if candidateExplicitRelationSimpleProhibitionRunes([]rune(text)) {
		return "", explicitMaliciousRelationNotMatched
	}
	quotedActivation := candidateExplicitQuotedActivation(text)
	_, independentExecution := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, phishingProof)
	if candidatePermissionOnlyScope(text) || candidateUnclosedFencedCarrier(text) {
		return "", explicitMaliciousRelationNotMatched
	}
	if !quotedActivation && !independentExecution {
		analyticalOwner := candidateInertLabeledCarrier(text) ||
			candidateTransformativeAnalyticalScope(text) ||
			candidateQuotedOrAnalyticalScopePrepared(text, phishingProof)
		if analyticalOwner && !candidatePhishingRealCredentialInteractionRelationPrepared(text, phishingProof) {
			return "", explicitMaliciousRelationNotMatched
		}
	}
	// Curly and modifier apostrophes are common possessive spelling variants,
	// not independent quote carriers, in targets such as users' browsers. Keep
	// the original text for the quote/analytical ownership checks above, then use
	// a narrow possessive-equivalent view for the typed relation axes below.
	relationText := possessiveApostropheEquivalent(text)
	if !candidateExplicitRelationAnyAction(relationText) {
		return "", explicitMaliciousRelationNotMatched
	}
	hostile := candidateExplicitMaliciousHostileScope(relationText)

	// Order is semantic, not severity based.  Categories with a distinctive
	// delivery/object relation are resolved before generic data movement or
	// service impact so their secondary consequences cannot steal the winner.
	if candidateExplicitPromptInjectionRelation(relationText, hostile) {
		return rules.CategoryEvasion, explicitMaliciousRelationMatched
	}
	if candidateExplicitRansomwareRelation(relationText, hostile) {
		return rules.CategoryRansomware, explicitMaliciousRelationMatched
	}
	// A deceptive pretext must not relabel direct acquisition from an existing
	// browser/credential store as phishing. Phishing owns credentials entered or
	// submitted through the deceptive surface; reading an already-saved secret
	// remains credential theft even when the attacker impersonates support.
	if candidateStoredCredentialAcquisitionRelation(relationText) &&
		candidateExplicitCredentialRelation(relationText, hostile) {
		return rules.CategoryCredentialTheft, explicitMaliciousRelationMatched
	}
	if candidateExplicitPhishingRelationPrepared(relationText, hostile, phishingProof) {
		return rules.CategoryPhishing, explicitMaliciousRelationMatched
	}
	if candidateExplicitDefenseEvasionRelation(relationText, hostile) {
		return rules.CategoryEvasion, explicitMaliciousRelationMatched
	}
	if candidateExplicitMalwareRelation(relationText, hostile) {
		return rules.CategoryMalware, explicitMaliciousRelationMatched
	}
	if candidateExplicitCredentialRelation(relationText, hostile) {
		return rules.CategoryCredentialTheft, explicitMaliciousRelationMatched
	}
	if candidateExplicitExploitationRelation(relationText, hostile) {
		return rules.CategoryExploitation, explicitMaliciousRelationMatched
	}
	if candidateExplicitDisruptionRelation(relationText, hostile) {
		return rules.CategoryDisruption, explicitMaliciousRelationMatched
	}
	if candidateExplicitExfiltrationRelation(relationText, hostile) {
		return rules.CategoryExfiltration, explicitMaliciousRelationMatched
	}
	return "", explicitMaliciousRelationNotMatched
}

// candidateExplicitMaliciousRelationOversizedPotential searches a long field
// only through UTF-8-safe, fixed-overlap windows that are each no larger than
// the reviewed category proof budget. A matched window is a bounded positive
// witness, not a blocking candidate: field-wide negation, ownership, and
// occurrence identity remain unresolved, so the caller reports proof-budget
// exhaustion unless an independent complete candidate already qualifies.
func candidateExplicitMaliciousRelationOversizedPotential(
	text string,
	_ *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	textRunes := []rune(text)
	if text == "" || candidateExplicitRelationAmbiguousQuoteStructure(text) ||
		candidateExplicitRelationQuotedPayloadOwnsOnlyAction(text) ||
		candidateExplicitRelationSimpleProhibitionRunes(textRunes) ||
		candidatePermissionOnlyScope(text) || candidateUnclosedFencedCarrier(text) {
		return false
	}
	if !candidateExplicitMaliciousRelationRunesHavePotentialAction(text, textRunes) {
		return false
	}

	wholePhishingProof := newCandidatePhishingRelationProof(text)
	quotedActivation := candidateExplicitQuotedActivation(text)
	_, independentExecution := candidatePhishingIndependentMaliciousExecutionTailPrepared(
		text, &wholePhishingProof,
	)
	if !quotedActivation && !independentExecution {
		analyticalOwner := candidateInertLabeledCarrier(text) ||
			candidateTransformativeAnalyticalScope(text) ||
			candidateQuotedOrAnalyticalScopePrepared(text, &wholePhishingProof)
		simulationOwner := candidatePhishingSyntheticSimulationScopePrepared(text, &wholePhishingProof)
		if analyticalOwner || simulationOwner {
			return false
		}
	}

	found := false
	walkDirectiveStrongScopeRunes(textRunes, func(scopeRunes []rune) bool {
		if !candidateExplicitMaliciousRelationScopeRunesMayContainAction(scopeRunes) {
			return true
		}
		scope := strings.TrimSpace(string(scopeRunes))
		if scope == "" {
			return true
		}
		if candidateExplicitMaliciousRelationOversizedScopeWindowPotential(scope) ||
			len(scope) > maxCompactIntentProofBytes &&
				candidateExplicitMaliciousRelationOversizedCrossWindowScopePotential(scope) {
			found = true
			return false
		}
		return true
	})
	return found
}

// candidateExplicitMaliciousRelationOversizedScopeWindowPotential applies the
// bounded positive-witness scan to exactly one strong directive scope. Raw
// byte windows must never bridge a sentence/strong boundary: otherwise an
// ordinary action such as "install the payroll update" can borrow a risk noun
// from the next descriptive sentence and turn a benign long field incomplete.
func candidateExplicitMaliciousRelationOversizedScopeWindowPotential(text string) bool {
	start := 0
	for start < len(text) {
		end := start + maxCompactIntentProofBytes
		if end >= len(text) {
			end = len(text)
		} else {
			for end > start && !utf8.RuneStart(text[end]) {
				end--
			}
		}
		if end <= start {
			return false
		}

		windowText := strings.TrimSpace(text[start:end])
		if windowText != "" &&
			candidateExplicitMaliciousRelationWindowHasPotentialAction(windowText) {
			windowPhishingProof := newCandidatePhishingRelationProof(windowText)
			category, state := candidateExplicitMaliciousRelationCategoryProofWithinBudget(
				windowText, &windowPhishingProof,
			)
			if state == explicitMaliciousRelationMatched &&
				!candidateExplicitRelationDefensiveConflictPrepared(
					category, windowText, &windowPhishingProof,
				) {
				return true
			}
		}
		if end == len(text) {
			break
		}

		next := end - explicitMaliciousRelationProofWindowOverlapBytes
		if next <= start {
			next = end
		}
		for next < len(text) && !utf8.RuneStart(text[next]) {
			next++
		}
		if next <= start {
			return false
		}
		start = next
	}
	return false
}

func candidateExplicitMaliciousRelationOversizedCrossWindowPotential(text string) bool {
	found := false
	walkDirectiveStrongScopes(text, func(scope string) bool {
		if len(scope) <= maxCompactIntentProofBytes {
			return true
		}
		if candidateExplicitMaliciousRelationOversizedCrossWindowScopePotential(scope) {
			found = true
			return false
		}
		return true
	})
	return found
}

// candidateExplicitMaliciousRelationOversizedCrossWindowScopePotential is
// deliberately confined to one strong directive scope. A distant action in an
// earlier sentence must not combine with a later risk noun merely because the
// whole field exceeds the compact proof window. Soft/continuation clauses stay
// in the same scope so a genuinely connected relation that straddles an
// internal window remains fail-closed.
func candidateExplicitMaliciousRelationOversizedCrossWindowScopePotential(text string) bool {
	seenAction := false
	seenRisk := false
	start := 0
	for start < len(text) {
		end := start + maxCompactIntentProofBytes
		if end >= len(text) {
			break
		}
		for end > start && !utf8.RuneStart(text[end]) {
			end--
		}
		if end <= start {
			return false
		}

		next := end - explicitMaliciousRelationProofWindowOverlapBytes
		if next <= start {
			next = end
		}
		for next < len(text) && !utf8.RuneStart(text[next]) {
			next++
		}
		if next <= start {
			return false
		}

		// [start,next) is the portion owned only by the current window. Any
		// relation between that cumulative prefix and bytes after end cannot fit
		// in either adjacent proof window; the overlap itself is deliberately
		// excluded because the next full window already assessed it.
		leftExclusive := text[start:next]
		seenAction = seenAction || candidateExplicitMaliciousRelationWindowHasPotentialAction(leftExclusive)
		seenRisk = seenRisk || candidateExplicitMaliciousRelationOversizedRiskSignal(leftExclusive)

		nextEnd := next + maxCompactIntentProofBytes
		if nextEnd >= len(text) {
			nextEnd = len(text)
		} else {
			for nextEnd > next && !utf8.RuneStart(text[nextEnd]) {
				nextEnd--
			}
		}
		if end < nextEnd {
			rightExclusive := text[end:nextEnd]
			if seenAction && candidateExplicitMaliciousRelationOversizedRiskSignal(rightExclusive) ||
				seenRisk && candidateExplicitMaliciousRelationWindowHasPotentialAction(rightExclusive) {
				return true
			}
		}
		start = next
	}
	return false
}

func walkDirectiveStrongScopes(text string, visit func(string) bool) {
	walkDirectiveStrongScopeRunes([]rune(text), func(scope []rune) bool {
		return visit(string(scope))
	})
}

func walkDirectiveStrongScopeRunes(runes []rune, visit func([]rune) bool) {
	scopeStart := -1
	scopeEnd := -1
	keepGoing := true
	flush := func() bool {
		if scopeStart < 0 || scopeEnd <= scopeStart {
			return true
		}
		return visit(runes[scopeStart:scopeEnd])
	}
	walkDirectiveClausesWithBoundaryRangeIntentStarts(
		runes,
		nil,
		func(_ []rune, start, end int, boundaryBefore directiveBoundaryKind) bool {
			if scopeStart < 0 {
				scopeStart = start
			}
			if boundaryBefore == directiveBoundaryStrong && scopeEnd > scopeStart {
				if !flush() {
					keepGoing = false
					return false
				}
				scopeStart = start
			}
			scopeEnd = end
			return true
		},
	)
	if keepGoing {
		flush()
	}
}

func candidateExplicitMaliciousRelationOversizedRiskSignal(text string) bool {
	if text == "" {
		return false
	}
	if candidateExplicitMaliciousHostileScope(text) {
		return true
	}
	if candidatePhishingDeceptionSurface(text) && candidateExplicitCredentialMaterial(text) {
		return true
	}
	if containsAnyLiteral(text,
		"ransomware", "ransom", "hostage", "victim files", "business files", "production user files",
		"勒索软件", "勒索程序", "勒索载荷", "勒索", "赎金", "受害文件",
	) {
		return true
	}
	if containsAnyLiteral(text,
		"protected context", "protected instruction", "restricted instruction", "production model", "target model",
		"受保护上下文", "受保护指令", "受限指令", "生产模型", "目标模型", "安全边界",
	) {
		return true
	}
	if containsAnyLiteral(text,
		"hide the intrusion", "conceal the intrusion", "intrusion remains undetected", "intrusion stays undetected",
		"malicious", "unauthorized access", "covert access", "credential theft", "persistent access", "ongoing attack",
		"隐藏入侵", "入侵不被发现", "恶意", "未授权访问", "秘密访问", "凭证窃取", "持续访问",
	) && containsAnyLiteral(text,
		"edr", "antivirus", "endpoint defense", "endpoint protection", "security control", "security telemetry",
		"security monitoring", "detection", "sandbox", "siem", "安全控制", "安全遥测", "安全监控", "检测", "防护", "杀毒", "沙箱",
	) {
		return true
	}
	return containsAnyLiteral(text,
		"malicious traffic", "prevent the owner", "prevent operators", "cannot recover", "users remain locked out",
		"恶意流量", "不让运维", "阻止自动迁移", "阻止恢复", "所有者无法恢复",
	) && containsAnyLiteral(text,
		"overload", "flood", "exhaust", "destructive load", "request storm", "connection storm",
		"outage", "denial of service", "ddos", "耗尽", "洪泛", "拖垮", "停摆", "服务不可用", "业务中断", "拒绝服务",
	)
}

func candidateExplicitMaliciousRelationWindowHasPotentialAction(text string) bool {
	return containsRuleIntentPrepared(
		text,
		candidateExplicitMaliciousRelationActions,
		candidateExplicitMaliciousRelationActionPatterns,
	) || containsRuleIntentPrepared(
		text,
		candidatePhishingCredentialInteractionIntents,
		candidatePhishingCredentialInteractionIntentPatterns,
	)
}

func candidateExplicitMaliciousRelationRunesHavePotentialAction(text string, runes []rune) bool {
	if runeSliceContainsAnyFoldASCIIBucketed(
		runes, &candidateExplicitRelationPotentialActionTermBuckets,
	) {
		return true
	}
	// The bucketed literal preflight deliberately ignores compact/obfuscated
	// spellings. Preserve those candidates through the reviewed compact matcher;
	// its first-rune preflight keeps homogeneous oversized carriers allocation-free.
	return candidateExplicitMaliciousRelationWindowHasPotentialAction(text)
}

func candidateExplicitMaliciousRelationScopeRunesMayContainAction(runes []rune) bool {
	if runeSliceContainsAnyFoldASCIIBucketed(
		runes, &candidateExplicitRelationPotentialActionTermBuckets,
	) {
		return true
	}
	return compactRuleIntentRunesMayContainPatternStart(
		runes, candidateExplicitMaliciousRelationActionPatterns,
	) || compactRuleIntentRunesMayContainPatternStart(
		runes, candidatePhishingCredentialInteractionIntentPatterns,
	)
}

func compactRuleIntentRunesMayContainPatternStart(
	runes []rune,
	patterns compactRuleIntentPatterns,
) bool {
	if len(runes) == 0 || len(patterns.values) == 0 {
		return false
	}
	for _, r := range runes {
		if r < utf8.RuneSelf {
			if patterns.asciiFirst[r] {
				return true
			}
			continue
		}
		if patterns.hasNonASCIIFirst && len(patterns.byFirst[r]) != 0 {
			return true
		}
	}
	return false
}

// candidateExplicitRelationTypedAxes preserves the category-local proof that
// caused the R9 explicit-relation fallback to materialize. Re-running only the
// narrower legacy helpers here used to create a split-brain result: the typed
// relation scored 100, while every public malicious axis remained false and
// the eligibility state machine downgraded the same candidate to ambiguous.
// Each mapping below is justified by the corresponding conjunctive relation
// predicate; no bare noun or global risk-word score can reach this function.
func candidateExplicitRelationTypedAxes(category rules.Category, text string) candidateTypedMaliciousAxes {
	axes := candidateTypedMaliciousAxes{
		explicitVictim: hasExplicitHarmConflict(text) || candidateExplicitVictimOrNonConsent(text),
		covert:         candidateCovertAcquisition(text),
		exfiltration:   candidateExfiltrationOrTakeover(text),
		persistence:    candidateMaliciousPersistence(category, text),
		destructive:    candidateDestructiveOutcome(category, text),
		evasion:        candidateSecurityControlEvasion(category, text),
	}
	switch category {
	case rules.CategoryCredentialTheft, rules.CategoryExploitation:
		if !axes.explicitVictim && !axes.covert && !axes.exfiltration {
			// These category predicates already require an active hostile-use or
			// unauthorized-outcome relation. Preserve that typed target proof even
			// when the wording is category-specific (for example, restricted data or
			// privileged account impersonation) rather than a generic victim phrase.
			axes.explicitVictim = true
		}
	case rules.CategoryPhishing:
		// An active deceptive authentication surface that solicits real secrets is
		// a covert-acquisition relation even when it omits the word "secretly".
		axes.covert = true
	case rules.CategoryMalware:
		if !axes.explicitVictim && !axes.covert && !axes.exfiltration && !axes.persistence {
			axes.explicitVictim = true
		}
	case rules.CategoryRansomware, rules.CategoryDisruption:
		axes.destructive = true
	case rules.CategoryExfiltration:
		axes.exfiltration = true
	case rules.CategoryEvasion:
		axes.evasion = true
	}
	return axes
}

func candidateExplicitMaliciousRelationAction(text string) bool {
	return containsUnnegatedRuleIntentPrepared(
		text,
		candidateExplicitMaliciousRelationActions,
		candidateExplicitMaliciousRelationActionPatterns,
	)
}

func candidateExplicitRelationAnyAction(text string) bool {
	return candidateExplicitMaliciousRelationAction(text) ||
		candidatePhishingCredentialInteractionAction(text)
}

func candidateExplicitRelationClauseBudgetExceeded(text string) bool {
	clauses := 1
	for _, value := range text {
		switch value {
		case ';', '\n', '.', '!', '?', '；', '。', '！', '？':
			clauses++
			if clauses > maxAnalyzedDirectiveClauses {
				return true
			}
		}
	}
	return false
}

func candidateExplicitRelationMayContainDirectiveNegation(text string) bool {
	return containsAnyLiteral(text,
		"do not ", "don't ", "must not ", "must never ", "should not ", "should never ",
		"need not ", "ought not ", "shall not ", "would not ", "could not ", "may not ",
		"will not ", "cannot ", "can't ", "never ", "not to ", "forbid", "prohibit", "refus",
		"不要", "不得", "禁止", "严禁", "切勿", "不应", "不可", "拒绝",
	)
}

func candidateExplicitRelationHasStructuredQuoteSyntax(text string) bool {
	// strings.ContainsAny must decode every rune when its search set contains
	// non-ASCII quote marks. Oversized ASCII carriers are common and otherwise
	// pay that full Unicode scan every time an ownership helper asks the same
	// question. Exact substring searches preserve the accepted syntax while
	// using the runtime's byte-search fast path for absent delimiters.
	return strings.IndexByte(text, '"') >= 0 || strings.IndexByte(text, '`') >= 0 ||
		strings.Contains(text, "“") || strings.Contains(text, "”") ||
		strings.Contains(text, "「") || strings.Contains(text, "」") ||
		strings.Contains(text, "『") || strings.Contains(text, "』") ||
		strings.Contains(text, "<sample>") || strings.Contains(text, "</sample>") ||
		strings.Contains(text, "[sample]") || strings.Contains(text, "[/sample]")
}

func candidateExplicitRelationAmbiguousQuoteStructure(text string) bool {
	if !candidateExplicitRelationHasStructuredQuoteSyntax(text) {
		return false
	}
	// Closing-only CJK fragments are otherwise invisible to the span parser and
	// commonly arise when one quoted carrier is split across request fields.
	if strings.Contains(text, "”") && !strings.Contains(text, "“") ||
		strings.Contains(text, "」") && !strings.Contains(text, "「") ||
		strings.Contains(text, "』") && !strings.Contains(text, "『") ||
		strings.Contains(text, "</sample>") && !strings.Contains(text, "<sample>") ||
		strings.Contains(text, "[/sample]") && !strings.Contains(text, "[sample]") {
		return true
	}
	_, complete := metaOverrideQuotedSpansWithLimit(text, maxAnalyzedDirectiveClauses)
	return !complete
}

func candidateExplicitRelationQuotedPayloadOwnsOnlyAction(text string) bool {
	if !candidateExplicitRelationHasStructuredQuoteSyntax(text) ||
		candidateExplicitRelationAmbiguousQuoteStructure(text) {
		return false
	}
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete || len(spans) != 1 {
		return false
	}
	quoted := spans[0]
	if quoted.start < 0 || quoted.end <= quoted.start || quoted.end > len(text) {
		return true
	}
	outside := strings.TrimSpace(text[:quoted.start] + " " + text[quoted.end:])
	return !candidateExplicitMaliciousRelationAction(outside) &&
		!candidateExplicitQuotedActivation(text)
}

func candidateExplicitQuotedActivation(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" || !candidateExplicitMaliciousRelationAction(text) ||
		!candidateExplicitRelationHasStructuredQuoteSyntax(text) {
		return false
	}
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete || len(spans) != 1 {
		return false
	}
	quoted := spans[0]
	if quoted.start < 0 || quoted.end <= quoted.start || quoted.end > len(text) {
		return false
	}
	// Activation must be the current user's speech act outside the carrier. An
	// occurrence of "apply this quoted..." inside the quoted sample is inert and
	// cannot reactivate itself.
	outside := strings.TrimSpace(text[:quoted.start] + " " + text[quoted.end:])
	// The activation speech act must govern the quote itself. Merely containing
	// an execution verb inside a quoted incident or an explicit "do not execute"
	// boundary is analytical ownership, not referent activation.
	referent := containsAnyLiteral(outside,
		"this quoted", "the quoted", "quoted request", "quoted instruction", "quoted sample", "quoted passage", "quoted carrier",
		"this quotation", "the quotation", "the quote", "this quote",
		"这段引用", "以下引用", "上述引用", "引用内容", "这段引文", "以下引文", "上述引文",
	)
	if !referent {
		suffix := strings.TrimSpace(text[quoted.end:])
		referent = containsAnyLiteral(suffix,
			"apply it", "execute it", "follow it", "obey it", "carry it out",
			"install it", "deploy it", "activate it", "run it", "implement it", "use it",
		)
	}
	return referent && containsUnnegatedRuleIntentPrepared(
		outside,
		candidateExplicitQuotedActivationIntents,
		candidateExplicitQuotedActivationIntentPatterns,
	)
}

func candidateExplicitMaliciousHostileScope(text string) bool {
	return hasExplicitHarmConflict(text) || candidateExplicitVictimOrNonConsent(text) ||
		candidateCovertAcquisition(text) || candidateExfiltrationOrTakeover(text) || containsAnyLiteral(text,
		"non-consenting", "nonconsenting", "unauthorized", "without authorization", "without approval",
		"without permission", "without consent", "without their knowledge", "another person's", "third-party",
		"victim", "stolen", "illicit access", "attacker-controlled", "server i control", "host i control",
		"outside the company",
		"owner cannot", "owners cannot", "private use", "take over", "retain control",
		"未经授权", "未经批准", "未经许可", "未经同意", "不知情", "第三方", "受害", "攻击者控制",
		"我控制", "供我私用", "绕过审批", "绕过批准", "用户不知情", "所有者不察觉", "接管", "窃取",
	)
}

func candidateExplicitPromptInjectionRelation(text string, hostile bool) bool {
	model := containsAnyLiteral(text,
		"model", "assistant", "prompt", "system instruction", "governing instruction", "protected context",
		"tool result", "tool schema", "instruction file", "model_instructions_file", "模型", "助手", "系统规则",
		"系统指令", "受保护上下文", "工具 schema", "工具输入", "指令文件",
	)
	control := containsAnyLiteral(text, candidateSecurityControlEvasionTargetTerms...) || containsAnyLiteral(text,
		"override", "ignore", "discard", "bypass", "reveal", "disclose", "expose", "conceal", "suppress refusal",
		"unrestricted mode", "reject", "deny", "injected instruction", "injection language", "prompt injection", "active instructions",
		"fake instruction", "high-priority command", "injected behavior", "无视", "忽略", "泄露", "覆盖", "绕过", "注入", "植入指令",
		"越权指令", "伪指令", "高优先级命令", "压制拒绝", "不受限制模式",
	)
	activation := containsAnyLiteral(text,
		"apply", "execute", "obey", "inject", "append", "insert", "activate", "deploy", "deliver", "send to", "treat", "turn", "use them", "use the",
		"force", "compel", "make", "run this quoted", "应用", "执行", "服从", "注入", "追加", "植入", "嵌入", "激活", "投放", "发送", "投向",
		"交给", "诱导", "迫使", "驱使",
	)
	// Use word boundaries for the two generic adjectives. A raw substring check
	// makes "unrestricted mode" satisfy the hostile-target proof through its
	// embedded "restricted" suffix, turning a standalone META wrapper into a
	// synthetic cyber-abuse base behavior on clause-overflow inputs.
	harm := hostile || candidatePromptInjectionHarmScope(text)
	return model && control && activation && harm
}

// candidatePromptInjectionHarmScope is the dimension-local harm half of an
// already complete prompt-injection relation. It may bind a protected-context
// consequence to its physical clause, but cannot create a category candidate
// without the separate model, control, and activation axes above.
func candidatePromptInjectionHarmScope(text string) bool {
	return candidateExplicitMaliciousHostileScope(text) || candidateExplicitQuotedActivation(text) ||
		candidateCovertAcquisition(text) || candidateExfiltrationOrTakeover(text) ||
		containsAnyLiteral(text,
			"protected context", "protected instruction", "protected instructions",
			"restricted context", "restricted instruction", "restricted instructions",
			"safety policy", "safeguard", "production model", "production assistant",
			"active model", "live assistant", "target model", "target assistant",
			"受保护上下文", "受保护指令", "受限上下文", "受限指令", "真实模型", "目标模型",
			"生产模型", "第三方模型", "私密配置", "隐藏配置", "安全边界",
		)
}

func candidateExplicitRansomwareRelation(text string, hostile bool) bool {
	// A named ransomware deployment is intrinsically an active malicious core;
	// it must not borrow an unrelated export/copy verb from the surrounding
	// request. Conversely, the adjective "encrypted" in an approved backup vault
	// is not an active ransomware encryption act.
	if candidateDirectRansomwareExecution(text) {
		return true
	}
	destructiveData := candidateClauseLocalDestructiveDataRelation(text)
	if destructiveData.encryptOrLock {
		return true
	}
	namedCore := containsAnyLiteral(text,
		"ransomware", "ransom", "hostage", "勒索软件", "勒索程序", "勒索载荷", "勒索", "赎金",
	)
	namedExtortionAction := namedCore && containsUnnegatedRuleIntentPrepared(
		text,
		candidateRansomwareExtortionIntents,
		candidateRansomwareExtortionIntentPatterns,
	) && containsAnyLiteral(text,
		"files", "systems", "records", "documents", "backups", "restore points", "access", "payment", "victim",
		"文件", "系统", "记录", "文档", "备份", "还原点", "访问", "付款", "受害",
	)
	activeEncryption := containsUnnegatedRuleIntentPrepared(
		text,
		candidateRansomwareEncryptionIntents,
		candidateRansomwareEncryptionIntentPatterns,
	) || containsAnyLiteral(text,
		"trigger encryption", "triggers encryption", "triggering encryption", "initiate encryption", "initiates encryption",
		"start encryption", "starts encryption", "launch encryption", "cause encryption", "causes encryption",
		"触发加密", "启动加密", "发起加密", "造成加密",
	)
	victimEncryption := activeEncryption && containsAnyLiteral(text,
		"victim files", "victim's files", "victims files", "victims' files", "victims’ files",
		"victim documents", "victim's documents", "business systems", "business files",
		"employee files", "production user files", "operational records", "real files", "company files", "owner access",
		"受害者文件", "受害者文档", "业务系统", "业务文件", "员工文件", "生产用户文件", "业务记录", "真实资料", "关键资料", "所有者访问",
	)
	namedExtortionOutcome := containsAnyLiteral(text,
		"demand payment", "demands payment", "hold files hostage", "holds files hostage",
		"hold records hostage", "holds records hostage", "recovery remains under attacker control",
	)
	return namedExtortionAction && (hostile || namedExtortionOutcome) ||
		victimEncryption
}

func candidatePhishingDeceptionSurface(text string) bool {
	if containsAnyLiteral(text,
		"phishing", "fake login", "fake oauth", "fake support", "fake portal", "cloned login", "credential form",
		"spoofed", "deceptive", "impersonate", "仿冒登录", "冒充", "伪装", "包装成", "假登录", "钓鱼", "诱导", "骗取",
	) {
		return true
	}
	// Counterfeit/lookalike is a deception axis only when it modifies an
	// authentication surface. A counterfeit artifact, brand mockup, or training
	// example by itself is not phishing evidence.
	authSurface := containsAnyLiteral(text,
		"sign-in", "sign in", "login", "log-in", "authentication", "verification", "approval page", "oauth", "account portal", "portal", "support notice",
		"登录", "认证", "验证", "审批页", "授权页", "通知", "入口",
	)
	return authSurface && containsAnyLiteral(text,
		"counterfeit", "lookalike", "look-alike", "imitation", "fake", "cloned", "spoofed", "deceptive", "impersonat",
		"仿冒", "假", "伪装", "包装成", "冒充", "诱导",
	)
}

type candidatePhishingRelationProof struct {
	text string

	realCredentialRelationKnown bool
	realCredentialRelation      bool
	syntheticSimulationKnown    bool
	syntheticSimulation         bool
	explicitRelationKnown       [2]bool
	explicitRelation            [2]bool
	currentSpeechActKnown       bool
	currentSpeechAct            bool
	independentTailKnown        bool
	independentTail             string
	independentExecution        bool
	quotedOrAnalyticalKnown     bool
	quotedOrAnalytical          bool
	detectionArtifactKnown      bool
	detectionArtifact           bool
	passiveIncidentKnown        bool
	passiveIncident             bool
	credentialLifecycleKnown    bool
	credentialLifecycle         bool
	currentExecutionActKnown    bool
	currentExecutionAct         bool
}

func newCandidatePhishingRelationProof(text string) candidatePhishingRelationProof {
	return candidatePhishingRelationProof{text: text}
}

func candidatePhishingIndependentMaliciousExecutionTailPrepared(
	text string,
	proof *candidatePhishingRelationProof,
) (string, bool) {
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.independentTailKnown {
		return proof.independentTail, proof.independentExecution
	}
	tail, independent := independentMaliciousExecutionTail(text)
	if proofMatches {
		proof.independentTailKnown = true
		proof.independentTail = tail
		proof.independentExecution = independent
	}
	return tail, independent
}

func candidateExplicitPhishingRelation(text string, hostile bool) bool {
	return candidateExplicitPhishingRelationPrepared(text, hostile, nil)
}

func candidateExplicitPhishingRelationPrepared(
	text string,
	hostile bool,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	proofMatches := proof != nil && proof.text == text
	proofIndex := 0
	if hostile {
		proofIndex = 1
	}
	if proofMatches && proof.explicitRelationKnown[proofIndex] {
		return proof.explicitRelation[proofIndex]
	}
	result := candidateExplicitPhishingRelationUncached(text, hostile, proof)
	if proofMatches {
		proof.explicitRelationKnown[proofIndex] = true
		proof.explicitRelation[proofIndex] = result
	}
	return result
}

func candidateExplicitPhishingRelationUncached(
	text string,
	hostile bool,
	proof *candidatePhishingRelationProof,
) bool {
	realCredentialRelation := candidatePhishingRealCredentialInteractionRelationPrepared(text, proof)
	if !realCredentialRelation && candidatePhishingDetectionArtifactScopePrepared(text, proof) {
		if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); !independent {
			return false
		}
	}
	if !realCredentialRelation &&
		(candidatePhishingSyntheticSimulationScopePrepared(text, proof) || candidatePhishingSyntheticTelemetryScope(text)) {
		return false
	}
	if !realCredentialRelation && candidatePhishingCredentialSecurityArtifact(text) {
		return false
	}
	deception := candidatePhishingDeceptionSurface(text)
	secret := candidateExplicitCredentialMaterial(text) || containsAnyLiteral(text,
		"sign-in", "account access", "account credentials", "staff credentials", "employee credentials", "session", "stolen account", "login information",
		"access rights", "access entitlement", "登录信息", "账号密码", "账户访问权", "访问权", "有效会话", "凭据", "用户输入",
	)
	delivery := containsAnyLiteral(text,
		"send", "deliver", "push", "replace", "solicit", "harvest", "collect", "capture", "receive", "prompt", "induce",
		"发给", "发送", "投放", "替换", "收集", "接收", "骗取", "诱导", "交出", "转给",
	)
	// A deceptive authentication surface that actively solicits credentials is
	// itself the phishing harm relation; a generic real-target noun is not needed
	// to manufacture non-consent for unrelated credential workflows.
	return realCredentialRelation || deception && secret && delivery && (hostile || containsAnyLiteral(
		text, "phishing", "fake login", "cloned login", "deceptive", "spoofed", "impersonate", "钓鱼", "仿冒登录", "假登录", "伪装", "冒充", "诱导",
	))
}

// candidatePhishingCredentialSecurityArtifact distinguishes credentials that
// are the subject of an alert/finding from credentials that the request asks a
// deceptive surface to collect.  Without this distinction, a defensive request
// such as "scan a cloned login page and collect password-leak alerts" can be
// misread as collecting the passwords themselves.  The proof is deliberately
// conjunctive and local: it requires both a credential-exposure artifact and a
// defensive inspection/remediation act in the same bounded relation window.
var candidateCredentialSecurityArtifactTerms = []string{
	"credential leak alert", "credential leakage alert", "credential exposure alert", "credential compromise alert",
	"password leak alert", "password leakage alert", "password exposure alert", "leaked-password alert",
	"credential leak finding", "credential exposure finding", "password leak finding", "password exposure finding",
	"凭据泄露告警", "凭据暴露告警", "凭据泄漏告警", "密码泄露告警", "密码暴露告警", "密码泄漏告警",
	"凭据泄露发现", "凭据暴露发现", "密码泄露发现", "密码暴露发现",
}

func candidatePhishingCredentialSecurityArtifact(text string) bool {
	credentialArtifact := containsAnyLiteral(text, candidateCredentialSecurityArtifactTerms...)
	if !credentialArtifact {
		return false
	}
	return containsAnyLiteral(text,
		"scan", "detect", "inspect", "review", "analyze", "analyse", "monitor", "alert", "finding", "remediation", "mitigation",
		"read", "open", "view", "retrieve", "recover", "triage", "investigate", "archive",
		"扫描", "检测", "检查", "审查", "分析", "监控", "告警", "发现", "修复", "缓解",
		"读取", "查看", "打开", "检索", "恢复", "分诊", "调查", "归档",
	)
}

var candidateExplicitMalwareOperationalIntents = []string{
	"deploy", "deploys", "deploying", "deployed",
	"install", "installs", "installing", "installed",
	"execute", "executes", "executing", "executed",
	"launch", "launches", "launching", "launched",
	"activate", "activates", "activating", "activated",
	"persist", "persists", "persisting", "persisted",
	"push", "pushes", "pushing", "pushed",
	"turn", "turns", "turning", "turned",
	"collect", "collects", "collecting", "collected",
	"extract", "extracts", "extracting", "extracted",
	"manipulate", "manipulates", "manipulating", "manipulated",
	"maintain", "maintains", "maintaining", "maintained",
	"hide", "hides", "hiding", "hidden",
	"部署", "安装", "执行", "投放", "激活", "控制", "推送", "操纵", "采集", "收集", "维持", "隐藏",
}

var candidateExplicitMalwareOperationalPatterns = compileCompactRuleIntentPatterns(
	candidateExplicitMalwareOperationalIntents,
)

var candidateExplicitMalwareCreationIntents = []string{
	"write", "writes", "writing", "written",
	"build", "builds", "building", "built",
	"create", "creates", "creating", "created",
	"develop", "develops", "developing", "developed",
	"generate", "generates", "generating", "generated",
	"编写", "构建", "创建", "开发", "生成", "制作",
}

var candidateExplicitMalwareCreationPatterns = compileCompactRuleIntentPatterns(
	candidateExplicitMalwareCreationIntents,
)

var candidateExplicitMalwareDetectionArtifactTerms = []string{
	"detector", "scanner", "detection rule", "detection signature", "detection guidance",
	"behavioral detector", "behavioural detector", "malware detector", "malware scanner",
	"persistence agent detector", "persistence-agent detector", "persistence agent scanner", "persistence-agent scanner",
	"c2 agent detector", "c2 agent scanner", "command-and-control agent detector", "command-and-control agent scanner",
	"检测器", "扫描器", "检测规则", "检测签名", "检测指南",
}

var candidateExplicitMalwareObjectTerms = []string{
	"malware", "trojan", "backdoor", "implant", "keylogger", "keystroke logger", "spyware",
	"remote-control agent", "remote control agent", "management agent",
	"remote support agent", "support agent", "management client", "monitoring helper", "control program", "control software", "remote foothold",
	"persistence agent", "remote access agent", "c2 agent", "command-and-control agent", "command and control agent",
	"恶意软件", "木马", "后门", "植入程序", "远程支持 agent", "支持 agent", "管理客户端", "监控 helper", "控制程序", "控制软件", "远程控制",
}

var candidateExplicitMalwareActionTargetTerms = append(
	append([]string{}, candidateExplicitMalwareObjectTerms...),
	"that agent", "this agent", "the agent", "agent", "unauthorized access", "persistent access", "hidden session",
	"victim device", "victim machine", "victim workstation",
	"该 agent", "这个 agent", "持久访问", "未授权访问", "隐藏会话", "受害设备", "受害机器", "受害工作站",
)

type candidateActionTargetProof struct {
	active    bool
	defensive bool
	harmful   bool
	unknown   bool
}

func candidateFirstBoundedLiteralIndex(text string, terms []string) int {
	best := -1
	for _, term := range terms {
		if term == "" || len(term) > len(text) {
			continue
		}
		for offset := 0; offset <= len(text)-len(term); {
			index := strings.Index(text[offset:], term)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(term)
			leftOK := !isASCIIStringLocal(term) || index == 0 || !isASCIIWordByte(text[index-1])
			rightOK := !isASCIIStringLocal(term) || end == len(text) || !isASCIIWordByte(text[end])
			if leftOK && rightOK && (best < 0 || index < best) {
				best = index
			}
			offset = index + 1
		}
	}
	return best
}

func candidateLastBoundedLiteralIndex(text string, terms []string) int {
	best := -1
	for _, term := range terms {
		if term == "" || len(term) > len(text) {
			continue
		}
		for offset := 0; offset <= len(text)-len(term); {
			index := strings.Index(text[offset:], term)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(term)
			leftOK := !isASCIIStringLocal(term) || index == 0 || !isASCIIWordByte(text[index-1])
			rightOK := !isASCIIStringLocal(term) || end == len(text) || !isASCIIWordByte(text[end])
			if leftOK && rightOK && index > best {
				best = index
			}
			offset = index + 1
		}
	}
	return best
}

// candidateActionTargets binds each literal, unnegated action to the first
// recognized artifact that follows it. This prevents a detector requested for
// a malicious sample from donating its creation/deployment verb to the sample,
// while a later independent "deploy/create that agent" remains hostile.
func candidateActionTargets(
	text string,
	intents []string,
	defensiveTargets []string,
	harmfulTargets []string,
) candidateActionTargetProof {
	proof := candidateActionTargetProof{}
	if text == "" {
		return proof
	}
	mayContainNegation := stringMayContainNegation(text)
	if !candidateHasUnnegatedBoundedLiteralPrepared(text, intents, mayContainNegation) {
		return proof
	}
	proof.active = true

	// Precompute the first target kind at or after every byte offset once. The
	// previous implementation rescanned every defensive and harmful target over
	// the complete suffix for every repeated action occurrence. A 16 KiB
	// "ask ask ... employees for passwords" clause therefore became
	// O(action_matches * bytes). The reviewed term sets are fixed; marking their
	// bounded starts and folding the nearest target backwards makes each action
	// lookup O(1), while preserving the existing defensive-wins-on-equal-offset
	// contract.
	const (
		candidateTargetDefensive byte = 1 << iota
		candidateTargetHarmful
	)
	nextTargetKind := make([]byte, len(text)+1)
	candidateMarkBoundedLiteralStarts(text, defensiveTargets, candidateTargetDefensive, nextTargetKind)
	candidateMarkBoundedLiteralStarts(text, harmfulTargets, candidateTargetHarmful, nextTargetKind)
	nearest := byte(0)
	for index := len(text) - 1; index >= 0; index-- {
		if kinds := nextTargetKind[index]; kinds != 0 {
			if kinds&candidateTargetDefensive != 0 {
				nearest = candidateTargetDefensive
			} else {
				nearest = candidateTargetHarmful
			}
		}
		nextTargetKind[index] = nearest
	}

	candidateVisitBoundedLiteralOccurrences(text, intents, func(index, end int) bool {
		kind := nextTargetKind[end]
		if kind == candidateTargetDefensive && proof.defensive ||
			kind == candidateTargetHarmful && proof.harmful ||
			kind == 0 && proof.unknown {
			// The proof records only whether each target kind has at least one
			// active action. Once that fact is established, later occurrences
			// pointing at the same kind cannot change the result and need no
			// repeated bounded negation lookback.
			return true
		}
		if mayContainNegation {
			_, negated := ruleIntentOccurrenceNegation(text, index)
			if negated {
				return true
			}
		}
		switch kind {
		case candidateTargetDefensive:
			proof.defensive = true
		case candidateTargetHarmful:
			proof.harmful = true
		default:
			proof.unknown = true
		}
		return !proof.defensive || !proof.harmful || !proof.unknown
	})
	return proof
}

func candidateHasUnnegatedBoundedLiteral(text string, terms []string) bool {
	return candidateHasUnnegatedBoundedLiteralPrepared(text, terms, stringMayContainNegation(text))
}

func candidateHasUnnegatedBoundedLiteralPrepared(text string, terms []string, mayContainNegation bool) bool {
	found := false
	candidateVisitBoundedLiteralOccurrences(text, terms, func(index, _ int) bool {
		if mayContainNegation {
			_, negated := ruleIntentOccurrenceNegation(text, index)
			if negated {
				return true
			}
		}
		found = true
		return false
	})
	return found
}

func candidateMarkBoundedLiteralStarts(text string, terms []string, kind byte, starts []byte) {
	if kind == 0 || len(starts) < len(text)+1 {
		return
	}
	candidateVisitBoundedLiteralOccurrences(text, terms, func(index, _ int) bool {
		starts[index] |= kind
		return true
	})
}

func candidateVisitBoundedLiteralOccurrences(
	text string,
	terms []string,
	visit func(index, end int) bool,
) {
	if text == "" || visit == nil {
		return
	}
	for _, term := range terms {
		if term == "" || len(term) > len(text) {
			continue
		}
		for offset := 0; offset <= len(text)-len(term); {
			index := strings.Index(text[offset:], term)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(term)
			leftOK := !isASCIIStringLocal(term) || index == 0 || !isASCIIWordByte(text[index-1])
			rightOK := !isASCIIStringLocal(term) || end == len(text) || !isASCIIWordByte(text[end])
			if leftOK && rightOK && !visit(index, end) {
				return
			}
			offset = index + 1
		}
	}
}

func candidateExplicitMalwareControlAction(text string) bool {
	return containsAnyLiteral(text,
		"take control", "takes control", "taking control", "took control",
		"gain control", "gains control", "gaining control", "gained control",
		"control the victim", "control a victim", "control victim", "control victims",
		"unauthorized control", "hidden control", "remote manipulation",
		"接管", "未授权控制", "未经批准的控制", "隐藏控制", "远程操纵",
	)
}

func candidateExplicitMalwareRelation(text string, hostile bool) bool {
	object := containsAnyLiteral(text, candidateExplicitMalwareObjectTerms...)
	operationalIntentAction := containsUnnegatedRuleIntentPrepared(
		text, candidateExplicitMalwareOperationalIntents, candidateExplicitMalwareOperationalPatterns,
	)
	controlAction := candidateExplicitMalwareControlAction(text)
	creationAction := containsUnnegatedRuleIntentPrepared(
		text, candidateExplicitMalwareCreationIntents, candidateExplicitMalwareCreationPatterns,
	)
	creationTargets := candidateActionTargets(
		text,
		candidateExplicitMalwareCreationIntents,
		candidateExplicitMalwareDetectionArtifactTerms,
		candidateExplicitMalwareActionTargetTerms,
	)
	if creationTargets.active && creationTargets.defensive {
		if !creationTargets.harmful && !creationTargets.unknown {
			creationAction = false
		}
		operationalTargets := candidateActionTargets(
			text,
			candidateExplicitMalwareOperationalIntents,
			candidateExplicitMalwareDetectionArtifactTerms,
			candidateExplicitMalwareActionTargetTerms,
		)
		if operationalTargets.active && operationalTargets.defensive && !operationalTargets.harmful && !operationalTargets.unknown {
			operationalIntentAction = false
		}
	}
	// A proved takeover/control relation is independent of an earlier request to
	// create or deploy a defensive detector. Suppressing the detector's verb must
	// never erase a later explicit malicious control act.
	action := operationalIntentAction || controlAction || creationAction
	maliciousOperation := candidateMaliciousPersistence(rules.CategoryMalware, text) || candidateCovertAcquisition(text) ||
		candidateExfiltrationOrTakeover(text) || containsAnyLiteral(text,
		"malicious", "victim device", "victim machine", "unauthorized control", "hidden control", "hidden session",
		"remote manipulation", "private file", "private files", "persistent access", "attacker's remote foothold",
		"恶意", "受害设备", "受害机器", "未授权控制", "未经批准的控制软件", "隐藏控制", "隐藏会话",
		"远程操纵", "秘密采集", "私密文件", "持续控制", "维持远程控制", "持久访问")
	return object && action && hostile && maliciousOperation
}

var candidateExplicitCredentialMaterialTerms = []string{
	"password", "passwords", "credential", "credentials", "access token", "access tokens", "api key", "api keys", "service key", "service keys", "secret material", "vault secret", "vault secrets",
	"session token", "account session", "saved passwords", "browser cookie", "browser cookies", "sign-ins", "login information", "account access",
	"密码", "凭据", "访问令牌", "api key", "服务账户密钥", "密钥", "有效会话", "可用会话", "会话", "登录信息", "账号密码",
}

func candidateExplicitCredentialMaterial(text string) bool {
	return containsAnyLiteral(text, candidateExplicitCredentialMaterialTerms...)
}

var candidateExplicitCredentialActionIntents = []string{
	"steal", "read", "capture", "divert", "copy", "retain", "collect", "harvest", "gather", "gathers", "gathering", "export", "extract", "dump",
	"intercept", "hijack", "take over", "impersonate", "sabotage", "obtain", "recover",
	"窃取", "查看", "读取", "复制", "截取", "获取", "取得", "收集", "导出", "保留", "接管", "冒用",
}

var candidateExplicitCredentialActionPatterns = compileCompactRuleIntentPatterns(
	candidateExplicitCredentialActionIntents,
)

func candidateExplicitCredentialRelation(text string, hostile bool) bool {
	if !candidateExplicitCredentialMaterial(text) {
		return false
	}
	artifactTargets := candidateActionTargets(
		text,
		candidateExplicitCredentialActionIntents,
		candidateCredentialSecurityArtifactTerms,
		candidateExplicitCredentialMaterialTerms,
	)
	if candidatePhishingCredentialSecurityArtifact(text) && artifactTargets.active && artifactTargets.defensive &&
		!artifactTargets.harmful && !artifactTargets.unknown {
		return false
	}
	if containsAnyLiteral(text, "authentication events", "identity and session information", "认证事件", "身份和会话信息") &&
		containsAnyLiteral(text, "export", "exfiltrat", "send outside", "外传", "传出", "导出") {
		return false
	}
	// Keep the fallback relation boundary-aware. A raw substring search made
	// ordinary words such as "wholesale" satisfy the theft verb "steal" once
	// a victim and cookie noun appeared elsewhere in the same candidate.
	action := containsRuleIntentPrepared(
		text, candidateExplicitCredentialActionIntents, candidateExplicitCredentialActionPatterns,
	) && containsUnnegatedRuleIntentPrepared(
		text, candidateExplicitCredentialActionIntents, candidateExplicitCredentialActionPatterns,
	)
	// A later affirmative theft verb that reverses a same-candidate prohibition
	// is an explicit hostile relation. A lone theft verb remains ambiguous under
	// Round 9 and cannot manufacture victim scope from the secret noun alone.
	reactivatedTheft := candidateRuleIntentReactivated(
		text, credentialStrongTheftIntents, credentialStrongTheftIntentPatterns,
	)
	intrinsicTakeover := containsAnyLiteral(text,
		"hijack", "take over", "account takeover", "impersonate", "owners are locked out", "owner is locked out",
		"continue to work", "continues to work", "continue access", "continues access",
		"接管", "冒用", "所有者无法", "继续访问", "继续有效",
	)
	hostileUse := hostile || reactivatedTheft || intrinsicTakeover || credentialSensitiveTargetAcquisition(text) || candidateCovertAcquisition(text) ||
		candidateExfiltrationOrTakeover(text) || containsAnyLiteral(text,
		"unauthorized sign-in", "account takeover", "stolen credential", "protected system", "restricted data",
		"未授权登录", "账户接管", "窃取凭据", "受保护系统", "受限数据",
	)
	return action && hostileUse
}

func candidateStoredCredentialAcquisitionRelation(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" || !containsAnyLiteral(text,
		"saved password", "saved passwords", "stored password", "stored passwords",
		"browser password", "browser passwords", "browser credential", "browser credentials",
		"credential store", "password vault",
		"保存的密码", "已保存密码", "存储的密码", "浏览器密码", "浏览器凭据", "凭据库", "密码库",
	) {
		return false
	}
	return containsUnnegatedRuleIntentPrepared(
		text,
		candidateExplicitCredentialActionIntents,
		candidateExplicitCredentialActionPatterns,
	)
}

func candidateExplicitExploitationRelation(text string, hostile bool) bool {
	flaw := containsAnyLiteral(text,
		"exploit", "flaw", "weakness", "vulnerability", "failure path", "crash", "injection", "overflow", "boundary error",
		"缺陷", "漏洞", "弱点", "崩溃", "注入", "溢出", "非法回退", "校验缺口",
	)
	action := containsAnyLiteral(text,
		"exploit", "weaponize", "compromise", "launch", "abuse", "use the", "enter", "seize",
		"利用", "武器化", "攻击", "侵入", "进入", "取得", "拿", "借漏洞",
	)
	outcome := containsAnyLiteral(text,
		"unauthorized control", "unauthorized access", "seize", "take over", "restricted account", "production host",
		"victim host", "crash", "interrupt", "administrative area", "admin area", "internal network", "runtime environment",
		"live service", "production system", "protected order", "backend data", "service privileges",
		"后台访问", "后台数据", "控制权", "受限账户", "管理区域", "内部网络", "运行环境", "生产主机", "生产系统", "受害主机", "受保护订单",
	)
	// Some explicit intrusion requests name the compromise operation and the
	// unauthorized network/host takeover without repeating a vulnerability noun.
	// Keep that relation in exploitation when the target is a concrete system and
	// the hostile outcome is control/access, rather than letting a secondary data
	// export consequence steal the taxonomy.
	intrusionAction := containsASCIIWord(text, "compromise") || containsASCIIWord(text, "intrude") ||
		containsAnyLiteral(text,
			"breach the", "breach a", "breach an", "break into", "seize control", "take control",
			"攻入", "攻破", "取得控制",
		)
	systemTarget := containsAnyLiteral(text,
		"network", "host", "server", "system", "service", "environment", "endpoint", "account",
		"网络", "主机", "服务器", "系统", "服务", "环境", "终端", "账户",
	)
	unauthorizedOutcome := containsAnyLiteral(text,
		"unauthorized control", "unauthorized access", "retain unauthorized control", "unrelated network", "victim host", "restricted account",
		"未经授权的控制", "未授权控制", "未授权访问", "保持控制", "受害主机", "受限账户",
	)
	return (flaw && action && outcome && hostile) ||
		(intrusionAction && systemTarget && unauthorizedOutcome && hostile)
}

var candidateSecurityControlEvasionTargetTerms = []string{
	"endpoint telemetry", "endpoint event collection", "event collection", "event collector", "event collectors",
	"security telemetry", "security event collection", "event logging", "telemetry collection",
	"endpoint sensor", "endpoint sensors", "security sensor", "security sensors", "security agent", "security agents",
	"endpoint agent", "endpoint agents", "edr agent", "edr agents", "telemetry agent", "telemetry agents",
	"siem agent", "siem agents", "ids agent", "ids agents", "ips agent", "ips agents", "forensic artifacts",
	"端点遥测", "端点事件收集", "事件收集", "端点传感器", "安全传感器", "安全代理",
	"安全监控", "安全遥测", "安全控制", "安全告警", "防护", "防护记录", "安全记录", "检测", "沙箱",
}

var candidateSecurityControlActiveEvasionIntents = []string{
	"bypass", "bypasses", "bypassing", "evade", "evades", "evading",
	"disable", "disables", "disabling", "suppress", "suppresses", "suppressing",
	"hide", "hides", "hiding", "conceal", "conceals", "concealing",
	"avoid detection", "prevent detection", "obfuscate", "obfuscates", "obfuscating",
	"stop", "stops", "stopping", "stopped", "suspend", "suspends", "suspending", "suspended",
	"erase", "erases", "erasing", "erased", "delete", "deletes", "deleting", "deleted",
	"clear", "clears", "clearing", "cleared", "shut down", "shuts down", "shutting down",
	"blind", "blinds", "blinding",
	"silence", "silences", "silencing", "mute", "mutes", "muting",
	"unhook", "unhooks", "unhooking", "tamper", "tampers", "tampering",
	"tamper with", "tampers with", "tampering with", "turn off", "turns off", "turning off",
	"neutralize", "neutralizes", "neutralizing",
	"绕过", "规避", "躲开", "躲避检测", "避开", "禁用", "关闭", "隐藏", "压制", "混淆", "不再触发",
}

var candidateSecurityControlActiveEvasionIntentPatterns = compileCompactRuleIntentPatterns(
	candidateSecurityControlActiveEvasionIntents,
)

// candidateSecurityControlDetectionReferenceScope recognizes a concrete
// defensive rule whose subject is an attempted evasion, rather than a request
// to perform that evasion. The proof is deliberately conjunctive and bounded:
// a named detection artifact, a reviewed alert/detection purpose, and an
// explicit attempt-reference must all be present, and a later independent
// execution clause defeats the owner. Generic words such as "detection" or
// "alert" therefore cannot suppress an otherwise hostile control action.
func candidateSecurityControlDetectionReferenceScope(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" || hasIndependentMaliciousExecutionClause(text) {
		return false
	}
	artifact := containsAnyLiteral(text,
		"detection rule", "detection rules", "detection signature", "detection signatures",
		"alert rule", "alert rules", "analytic rule", "analytic rules",
		"soc rule", "soc rules", "soc detection rule", "soc detection rules",
	)
	if !artifact {
		return false
	}
	detectionPurpose := containsAnyLiteral(text,
		"should alert", "must alert", "alert when", "alerts when", "alert on", "alerts on",
		"alert defenders", "alerts defenders", "detect attempts", "detects attempts",
		"flag attempts", "flags attempts", "identify attempts", "identifies attempts",
	)
	referencedAttempt := containsAnyLiteral(text,
		"attempts to", "attempted to", "tries to", "tried to", "for attempts to", "on attempts to",
	)
	return detectionPurpose && referencedAttempt &&
		!candidateSecurityControlDetectionReferenceHostileImplementation(text)
}

// candidateSecurityControlDetectionReferenceHostileImplementation prevents a
// defensive rule owner from washing out a concrete implementation embedded in
// the same physical sentence. The suffix grammar is intentionally narrow: a
// reviewed implementation introducer must own an active control-evasion action,
// its control target, and a hostile purpose. Mere detector descriptions and
// referenced malware behavior therefore remain defensive.
func candidateSecurityControlDetectionReferenceHostileImplementation(text string) bool {
	for _, boundary := range []string{
		" using a routine that ", " using the routine that ",
		" using a script that ", " using the script that ",
		" using code that ", " using the code that ",
		" using a program that ", " using the program that ",
		" using software that ", " using the software that ",
		" using a tool that ", " using the tool that ",
		" using an implementation that ", " using the implementation that ",
		" with a routine that ", " with the routine that ",
		" with a script that ", " with the script that ",
		" with code that ", " with the code that ",
		" via a routine that ", " via the routine that ",
		" via a script that ", " via the script that ",
		" via code that ", " via the code that ",
	} {
		index := strings.LastIndex(text, boundary)
		if index < 0 {
			continue
		}
		tail := strings.TrimSpace(text[index+len(boundary):])
		if tail == "" || candidatePassiveIncidentReportOrDocumentationScope(tail) ||
			candidatePermissionOnlyScope(tail) {
			continue
		}
		control := containsAnyLiteral(tail, candidateSecurityControlEvasionTargetTerms...) ||
			containsAnyLiteral(tail,
				"edr", "antivirus", "endpoint defense", "endpoint protection", "security control",
				"security telemetry", "security monitoring", "monitoring", "detection", "sandbox", "siem",
				"安全控制", "安全遥测", "安全监控", "检测", "防护", "杀毒", "沙箱",
			)
		active := containsUnnegatedRuleIntentPrepared(
			tail,
			candidateSecurityControlActiveEvasionIntents,
			candidateSecurityControlActiveEvasionIntentPatterns,
		)
		if control && active && candidateSecurityControlEvasionMaliciousPurpose(tail) &&
			candidateCurrentExecutionAct(tail) {
			return true
		}
	}
	return false
}

func candidateSecurityControlActiveEvasion(text string) bool {
	if (isSafeDetectionArtifactClause(text) || candidateSecurityControlDetectionReferenceScope(text)) &&
		!hasIndependentMaliciousExecutionClause(text) {
		return false
	}
	if containsUnnegatedRuleIntentPrepared(
		text,
		candidateSecurityControlActiveEvasionIntents,
		candidateSecurityControlActiveEvasionIntentPatterns,
	) {
		return true
	}
	// Outcome wording remains active only when this same candidate also owns an
	// affirmative execution action. A bare historical state is not an action.
	return candidateExplicitMaliciousRelationAction(text) && containsAnyLiteral(text,
		"evasion", "undetected", "stays undetected", "stay undetected", "cannot detect", "cannot identify",
		"miss the intrusion", "miss the malicious", "misses the intrusion", "misses the malicious",
		"no longer trigger", "stops triggering", "不被发现", "不再触发",
	)
}

func candidateExplicitDefenseEvasionRelation(text string, hostile bool) bool {
	control := containsAnyLiteral(text, candidateSecurityControlEvasionTargetTerms...) || containsAnyLiteral(text,
		"endpoint defense", "defense evasion", "detection evasion", "endpoint protection", "endpoint-protection", "monitoring", "intrusion alert",
		"security control", "security telemetry", "audit", "yara", "sigma", "siem", "ioc", "detection", "sandbox",
		"signature scanner", "signature scanners", "edr", "antivirus", "defensive telemetry", "defensive service",
		"endpoint analytics", "scheduled-task analytics", "threat-indicator", "indicator ingestion", "alerting pipeline",
		"安全监控", "检测", "安全控制", "安全告警", "防护", "防护记录", "安全记录", "防御遥测", "告警处置", "阻断", "沙箱",
	)
	evasionState := containsAnyLiteral(text,
		"evade", "evasion", "disable", "suppress", "hide", "conceal", "bypass", "avoid detection", "undetected",
		"cannot detect", "cannot identify", "miss the intrusion", "miss the malicious", "misses the intrusion", "misses the malicious",
		"no longer trigger", "stops triggering", "prevent detection", "躲开", "避开", "规避", "禁用", "关闭", "隐藏", "绕过", "压制", "不被发现", "不再触发",
	)
	evasion := candidateSecurityControlActiveEvasion(text) ||
		!containsDetectionArtifact(text) && !candidateSecurityControlDetectionReferenceScope(text) &&
			evasionState && candidateExplicitMaliciousRelationAction(text)
	maliciousPurpose := hostile || containsAnyLiteral(text,
		"hide the intrusion", "hide an intrusion", "conceal the intrusion", "conceal an intrusion", "keep the intrusion hidden",
		"intrusion remains undetected", "intrusion stays undetected", "malware", "malicious", "unauthorized access", "unauthorized control", "covert access", "credential theft", "theft", "exfiltrat",
		"persistent access", "continuing access", "ongoing access", "ongoing attack", "恶意", "未授权访问", "入侵", "入侵活动", "持续访问", "凭据窃取", "外传",
	)
	// A request whose actual core is exporting records remains exfiltration even
	// when it also asks to conceal that transfer from an IDS/SOC.
	dataExportPrimary := candidateExplicitExfiltrationObject(text) && candidateExplicitExfiltrationOutbound(text)
	primaryEvasion := hasAnyPrefix(text,
		"evade ", "disable ", "suppress ", "hide ", "conceal ", "bypass ", "avoid detection ",
		"stop ", "suspend ", "erase ", "delete ", "clear ", "silence ", "mute ", "unhook ",
		"tamper ", "turn off ", "shut down ", "blind ", "neutralize ",
		"规避", "禁用", "关闭", "隐藏", "绕过", "压制",
	)
	return control && evasion && maliciousPurpose && (!dataExportPrimary || primaryEvasion)
}

func candidateExplicitDisruptionRelation(text string, hostile bool) bool {
	destructiveData := candidateClauseLocalDestructiveDataRelation(text)
	if destructiveData.deleteOrWipe && !destructiveData.encryptOrLock {
		// Destructive deletion/wiping without an encryption or extortion core is
		// disruption, not ransomware. The ransomware branch is evaluated first and
		// still owns a combined encryption+backup-destruction speech act.
		return true
	}
	mechanism := containsAnyLiteral(text,
		"overload", "flood", "exhaust", "destructive load", "destructive request load", "request storm", "connection storm", "capacity",
		"offline", "unavailable", "outage", "stop responding", "denial of service", "ddos", "processing stops", "cannot recover",
		"耗尽", "洪泛", "拖垮", "停摆", "服务不可用", "业务中断", "离线", "破坏性负载", "停止响应", "拒绝服务",
	)
	action := containsAnyLiteral(text,
		"overload", "release", "exhaust", "exhausting", "flood", "trigger", "disrupt", "keep exhausting", "carry out",
		"持续耗尽", "触发", "拖垮", "灌入", "洪泛", "中断", "造成", "阻止",
	)
	hostileImpact := hostile || containsAnyLiteral(text,
		"malicious traffic", "prevent the owner", "prevent operators", "cannot recover", "users remain locked out",
		"恶意流量", "不让运维", "阻止自动迁移", "阻止恢复", "所有者无法恢复",
	)
	return mechanism && action && hostileImpact
}

func candidateExplicitExfiltrationObject(text string) bool {
	return containsAnyLiteral(text,
		"record", "records", "confidential data", "confidential case data", "private data", "protected data", "evidence", "identity data", "identity records",
		"network telemetry", "private file", "private files", "billing data", "customer data", "customer records", "customer files",
		"network traffic", "traffic records", "business content", "secret material", "login data", "session information", "authentication events", "access history",
		"记录", "机密数据", "私密数据", "受保护数据", "受保护记录", "证据", "证据文件", "身份数据", "身份记录", "身份和会话信息",
		"网络遥测", "网络流量", "私密文件", "客户数据", "客户资料", "员工身份记录", "登录数据", "认证事件", "访问历史", "业务内容",
	)
}

func candidateExplicitExfiltrationOutbound(text string) bool {
	return containsAnyLiteral(text,
		"exfiltrat", "export", "send to", "copy", "remove", "steal", "outside", "external server", "off-site",
		"private use", "unauthorized recipient", "ongoing export", "continuing export", "move them outside", "send that confidential data",
		"外传", "传出", "导出", "带走", "发送到", "发送给", "传到", "复制到", "转给我", "供我私用", "外部服务器", "我控制的位置",
	)
}

func candidateExplicitExfiltrationRelation(text string, hostile bool) bool {
	return candidateExplicitExfiltrationObject(text) && candidateExplicitExfiltrationOutbound(text) && hostile
}

type candidateEligibilityInput struct {
	category       rules.Category
	ruleID         string
	text           string
	supportingText string
	phishingProof  *candidatePhishingRelationProof
	// authorizationText is a bounded request-local view used only to retain an
	// authorization claim that prefixes the winning clause. It must never
	// contribute harm, target, operational, or other malicious-core evidence.
	authorizationText           string
	coreComplete                bool
	activeDirective             bool
	currentExecutionProven      bool
	operational                 bool
	ownershipProven             bool
	inspectionComplete          bool
	quotedOrAnalytical          bool
	defensiveConflict           bool
	crossScope                  bool
	referentLinked              bool
	referentProofComplete       bool
	evidenceAmbiguous           bool
	typedExplicitMalice         bool
	typedExplicitVictim         bool
	typedCovertAcquisition      bool
	typedExfiltration           bool
	typedMaliciousPersistence   bool
	typedDestructiveOutcome     bool
	typedSecurityControlEvasion bool
	context                     ContextFlags
}

func candidateIdentityFor(
	category rules.Category,
	occurrences []EvidenceOccurrence,
	referent bool,
	ownershipScopeIDs ...uint64,
) candidateBlockIdentity {
	identity := candidateBlockIdentity{
		category: category, referentLinked: referent,
		occurrences: append([]EvidenceOccurrence(nil), occurrences...),
	}
	seenClauses := make(map[int]struct{}, len(occurrences))
	for _, occurrence := range occurrences {
		clauseID := occurrence.ClauseID
		if clauseID < 0 {
			// Synthetic semantic/meta evidence deliberately has no text offset. Its
			// profiled field is still a stable bounded clause carrier, represented by
			// a negative internal key that cannot collide with physical clause IDs.
			// Before role annotation, all such evidence belongs to the one bounded
			// roleless synthetic clause; annotation later replaces that key with the
			// exact profiled field identity.
			clauseID = -2
			if occurrence.FieldID >= 0 {
				clauseID -= occurrence.FieldID
			}
		}
		if _, duplicate := seenClauses[clauseID]; duplicate {
			continue
		}
		seenClauses[clauseID] = struct{}{}
		identity.clauseIDs = append(identity.clauseIDs, clauseID)
	}
	sort.Ints(identity.clauseIDs)
	seenScopes := make(map[uint64]struct{}, len(ownershipScopeIDs))
	for _, scopeID := range ownershipScopeIDs {
		if scopeID == 0 {
			continue
		}
		if _, duplicate := seenScopes[scopeID]; duplicate {
			continue
		}
		seenScopes[scopeID] = struct{}{}
		identity.ownershipScopeIDs = append(identity.ownershipScopeIDs, scopeID)
	}
	sort.Slice(identity.ownershipScopeIDs, func(left, right int) bool {
		return identity.ownershipScopeIDs[left] < identity.ownershipScopeIDs[right]
	})
	return identity
}

// directCandidateIdentityFor gives the internal role-free matcher a stable
// synthetic ownership scope. Public roleless callers are still narrowed to an
// untrusted actor by ClassifyWithPolicy; trusted profiled callers replace this
// scope with extractor-proven metadata in annotateProfiledResult.
func directCandidateIdentityFor(
	category rules.Category,
	occurrences []EvidenceOccurrence,
	referent bool,
) candidateBlockIdentity {
	return candidateIdentityFor(category, occurrences, referent, directCandidateSyntheticScopeID)
}

func candidateIdentityBlockingProofComplete(identity candidateBlockIdentity) bool {
	if identity.category == "" || len(identity.ownershipScopeIDs) != 1 || len(identity.clauseIDs) == 0 ||
		len(identity.occurrences) == 0 {
		return false
	}
	if identity.referentLinked {
		chain := identity.referentChain
		if !chain.set || !chain.proofComplete || chain.carrierScopeID == 0 ||
			chain.anchorScopeID == 0 || chain.carrierOccurrenceCount == 0 {
			return false
		}
	}
	for _, occurrence := range identity.occurrences {
		if occurrence.EvidenceID == "" || occurrence.Dimension == "" {
			return false
		}
	}
	return true
}

// CandidateIdentityBlockingProofComplete reports whether this Result still
// carries the classifier-private, candidate-bound proof that produced its
// public evidence.  Callers can verify the proof, but cannot construct or
// mutate it because candidateIdentity remains private to this package.
//
// The exact occurrence comparison is intentional: a copied Result whose
// public category or evidence was rewritten after classification must not be
// accepted as an eligible malicious winner by the plugin boundary.
func (result Result) CandidateIdentityBlockingProofComplete() bool {
	identity := result.candidateIdentity
	if result.Category == "" || identity.category != result.Category ||
		!candidateIdentityBlockingProofComplete(identity) ||
		len(identity.occurrences) != len(result.EvidenceOccurrences) {
		return false
	}
	for index := range identity.occurrences {
		if identity.occurrences[index] != result.EvidenceOccurrences[index] {
			return false
		}
	}
	return true
}

func bindResultCandidateReferentAnchor(
	result *Result,
	anchor profiledSegmentRef,
	proofComplete bool,
	mode Mode,
	thresholds Thresholds,
) {
	if result == nil {
		return
	}
	identity := result.candidateIdentity
	identity.referentLinked = true
	chain := candidateReferentChainIdentity{
		proofComplete:           proofComplete,
		anchorConversationIndex: anchor.segment.ConversationIndex,
		anchorTurnIndex:         anchor.segment.TurnIndex,
		anchorScopeID:           anchor.segment.ScopeID,
		anchorFieldID:           anchor.index,
	}
	if len(identity.ownershipScopeIDs) == 1 && len(identity.occurrences) != 0 {
		chain.set = true
		chain.carrierScopeID = identity.ownershipScopeIDs[0]
		chain.carrierFirstFieldID = identity.occurrences[0].FieldID
		chain.carrierLastFieldID = identity.occurrences[0].FieldID
		chain.carrierOccurrenceCount = len(identity.occurrences)
		for _, occurrence := range identity.occurrences[1:] {
			if occurrence.FieldID < chain.carrierFirstFieldID {
				chain.carrierFirstFieldID = occurrence.FieldID
			}
			if occurrence.FieldID > chain.carrierLastFieldID {
				chain.carrierLastFieldID = occurrence.FieldID
			}
		}
	}
	identity.referentChain = chain
	bindResultCandidateIdentity(result, identity, mode, thresholds)
}

func bindResultCandidateIdentity(
	result *Result,
	identity candidateBlockIdentity,
	mode Mode,
	thresholds Thresholds,
) {
	if result == nil {
		return
	}
	result.candidateIdentity = identity
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	if len(identity.ownershipScopeIDs) > 1 {
		eligibility.CrossScopeComposition = true
	}
	if identity.category == "" || identity.category != result.Category ||
		!candidateIdentityBlockingProofComplete(identity) {
		eligibility.EvidenceAmbiguous = true
	}
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if !eligibility.Eligible {
		removeIneligibleHardFloor(result)
	}
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

func candidatePassiveIncidentReportOrDocumentationScope(text string) bool {
	return candidatePassiveIncidentReportOrDocumentationScopePrepared(text, nil)
}

func candidatePassiveIncidentReportOrDocumentationScopePrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.passiveIncidentKnown {
		return proof.passiveIncident
	}
	result := candidatePassiveIncidentReportOrDocumentationScopeUncached(text, proof)
	if proofMatches {
		proof.passiveIncidentKnown = true
		proof.passiveIncident = result
	}
	return result
}

func candidatePassiveIncidentReportOrDocumentationScopeUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); independent {
		return false
	}
	owner := hasAnyPrefix(text,
		"incident report", "the incident report", "historical incident report", "post-incident report",
		"forensic report", "the forensic report", "soc report", "the soc report",
		"documentation ", "the documentation ", "incident timeline", "the incident timeline",
		"during the incident", "during yesterday's incident", "during yesterday’s incident",
	)
	commissionedHistoricalDocumentation := hasAnyPrefix(text,
		"write documentation ", "draft documentation ", "prepare documentation ",
		"create documentation ", "produce documentation ",
	) && containsAnyLiteral(text,
		"during the incident", "during yesterday's incident", "after the incident",
		"from the incident", "post-incident", "historical incident",
	)
	if !owner && !commissionedHistoricalDocumentation {
		return false
	}
	return containsAnyLiteral(text,
		" states ", " stated ", " documents ", " documented ", " explains ", " explained ", " explaining ",
		" records ", " recorded ", " observed ", " showed ", " reported ", " noted ",
		" requested ", " asked ", " required ", " submitted ", " received ",
		" turned off ", " silenced ", " muted ", " unhooked ", " tampered ",
	) || strings.Contains(text, ":")
}

func assessCandidateBlockEligibility(input candidateEligibilityInput) CandidateBlockEligibility {
	metaControlCandidate := input.ruleID == metaOverrideRuleID
	if metaControlCandidate {
		// assessMetaOverride has already proved the bounded control-plane
		// composition that makes this a defense-evasion core. Re-scanning an
		// attacker-sized prompt for every ordinary category predicate is both
		// semantically redundant and a linear-times-many hot path. Keep the META
		// eligibility proof typed and content-free here.
		return finalizeCandidateBlockEligibility(CandidateBlockEligibility{
			InspectionComplete:         input.inspectionComplete,
			EvidenceOwnedByCurrentUser: input.ownershipProven,
			CurrentExecutionActProven:  input.activeDirective && !input.quotedOrAnalytical && !input.defensiveConflict,
			HarmfulCoreComplete:        input.coreComplete,
			OperationallyActionable:    input.operational,
			AuthorizationClaim:         AuthorizationAbsent,
			SecurityControlEvasion:     input.coreComplete,
			DefensiveScopeConflict:     input.defensiveConflict,
			QuotedOrAnalyticalScope:    input.quotedOrAnalytical,
			CrossScopeComposition:      input.crossScope,
			ReferentProofComplete:      !input.referentLinked || input.referentProofComplete,
			EvidenceAmbiguous:          input.evidenceAmbiguous || !input.coreComplete,
		})
	}
	text := strings.ToLower(strings.TrimSpace(input.text))
	supportingText := strings.ToLower(strings.TrimSpace(input.supportingText))
	authorizationText := strings.ToLower(strings.TrimSpace(input.authorizationText))
	phishingProof := input.phishingProof
	var localPhishingProof candidatePhishingRelationProof
	if phishingProof == nil || phishingProof.text != text {
		localPhishingProof = newCandidatePhishingRelationProof(text)
		phishingProof = &localPhishingProof
	}
	semanticTypedCore := strings.HasPrefix(input.ruleID, "SEMANTIC-") && input.coreComplete
	permissionOnly := candidatePermissionOnlyScope(text) ||
		candidatePermissionDominatesCategory(text, input.category) ||
		authorizationText != "" && candidatePermissionDominatesCategory(authorizationText, input.category)
	quotedOrAnalytical := input.quotedOrAnalytical ||
		candidatePassiveIncidentReportOrDocumentationScopePrepared(text, phishingProof) ||
		supportingText != "" && candidatePassiveIncidentReportOrDocumentationScope(supportingText)
	defensiveConflict := input.defensiveConflict
	if !input.typedExplicitMalice {
		quotedOrAnalytical = quotedOrAnalytical || candidateQuotedOrAnalyticalScopePrepared(text, phishingProof) ||
			supportingText != "" && candidateQuotedOrAnalyticalScope(supportingText)
		defensiveConflict = defensiveConflict || candidateDefensiveScopeConflictPrepared(
			input.category, text, input.context, phishingProof,
		) ||
			supportingText != "" && candidateDefensiveScopeConflict(input.category, supportingText, input.context)
	}
	credentialReactivation := input.category == rules.CategoryCredentialTheft &&
		candidateRuleIntentReactivated(text, credentialStrongTheftIntents, credentialStrongTheftIntentPatterns)
	explicitVictim := input.typedExplicitVictim || credentialReactivation || hasExplicitHarmConflict(text) || candidateExplicitVictimOrNonConsent(text) ||
		input.category == rules.CategoryCredentialTheft && credentialSensitiveTargetAcquisition(text) ||
		supportingText != "" && (hasExplicitHarmConflict(supportingText) ||
			candidateExplicitVictimOrNonConsent(supportingText) ||
			input.category == rules.CategoryCredentialTheft && credentialSensitiveTargetAcquisition(supportingText))
	covert := input.typedCovertAcquisition || candidateCovertAcquisition(text) ||
		supportingText != "" && candidateCovertAcquisition(supportingText)
	exfiltration := input.typedExfiltration || candidateExfiltrationOrTakeover(text) ||
		supportingText != "" && candidateExfiltrationOrTakeover(supportingText)
	persistence := input.typedMaliciousPersistence || candidateMaliciousPersistence(input.category, text) ||
		supportingText != "" && candidateMaliciousPersistence(input.category, supportingText)
	destructive := input.typedDestructiveOutcome || candidateDestructiveOutcome(input.category, text) ||
		supportingText != "" && candidateDestructiveOutcome(input.category, supportingText)
	evasionReactivation := input.category == rules.CategoryEvasion && candidateSecurityControlTarget(text) &&
		candidateRuleIntentReactivated(text, candidateSecurityControlReactivationIntents, candidateSecurityControlReactivationIntentPatterns)
	exfiltrationCopy := input.category == rules.CategoryExfiltration &&
		candidateExplicitExfiltrationCopyAction(text, explicitVictim, exfiltration)
	compactCredentialTheft := input.category == rules.CategoryCredentialTheft && candidateCredentialTheftAction(text)
	evasion := input.typedSecurityControlEvasion || candidateSecurityControlEvasion(input.category, text) || evasionReactivation ||
		supportingText != "" && candidateSecurityControlEvasion(input.category, supportingText)
	authorization := candidateAuthorizationClaim(text, explicitVictim, covert, exfiltration)
	if supportingText != "" {
		authorization = mergeCandidateAuthorizationClaims(
			authorization,
			candidateAuthorizationClaim(supportingText, explicitVictim, covert, exfiltration),
		)
	}
	if authorizationText != "" {
		authorization = mergeCandidateAuthorizationClaims(
			authorization,
			candidateAuthorizationClaim(authorizationText, explicitVictim, covert, exfiltration),
		)
	}
	positiveMalice := candidateCategoryHasExplicitMalice(
		input.category, input.ruleID, text, explicitVictim, covert, exfiltration,
		persistence, destructive, evasion, credentialReactivation, evasionReactivation,
	)
	if !positiveMalice && supportingText != "" {
		positiveMalice = candidateCategoryHasExplicitMalice(
			input.category, input.ruleID, supportingText, explicitVictim, covert, exfiltration,
			persistence, destructive, evasion, false, false,
		)
	}
	// A semantic profile reaches coreComplete only after its category-specific,
	// same-window predicate has proved the required typed dimensions. Preserve
	// that proof here instead of requiring the ordinary literal matcher to find
	// a second, redundant theft/malware/evasion phrase in the same text.
	positiveMalice = positiveMalice || semanticTypedCore || input.typedExplicitMalice
	authorizationConflictCore := positiveMalice || input.typedExplicitMalice ||
		(input.coreComplete && input.activeDirective && input.operational &&
			!quotedOrAnalytical && !defensiveConflict &&
			!candidateCredentialLifecyclePrepared(text, phishingProof))
	if authorizationConflictCore && (candidateAuthorizationClaimPresent(text) ||
		candidateAuthorizationClaimPresent(supportingText) ||
		candidateAuthorizationClaimPresent(authorizationText)) {
		// A generic authorization/lab assertion cannot wash a separately proven,
		// clause-local malicious core. Preserve the claim as conflicting without
		// letting the wider authorization-only view supply any malicious axis.
		authorization = AuthorizationConflicting
	}
	if permissionOnly {
		// A statement that an action is permitted (for example, "not forbidden
		// to steal") is not itself an execution speech act. It may remain
		// auditable, but it cannot create an eligible malicious-text winner.
		positiveMalice = false
	}
	currentExecution := !quotedOrAnalytical && !defensiveConflict &&
		!permissionOnly && (input.currentExecutionProven || input.activeDirective &&
		(semanticTypedCore && input.operational ||
			(candidateCurrentExecutionActPrepared(text, phishingProof) || compactCredentialTheft || exfiltrationCopy ||
				credentialReactivation || evasionReactivation)))
	operational := !permissionOnly && (input.operational || candidateOperationallyActionablePrepared(
		input.category, text, phishingProof,
	) ||
		compactCredentialTheft || exfiltrationCopy || credentialReactivation || evasionReactivation)
	harmfulCore := input.coreComplete && positiveMalice
	referentComplete := !input.referentLinked || input.referentProofComplete
	ambiguous := input.evidenceAmbiguous || (!positiveMalice && input.coreComplete) || permissionOnly

	eligibility := CandidateBlockEligibility{
		InspectionComplete:         input.inspectionComplete,
		EvidenceOwnedByCurrentUser: input.ownershipProven,
		CurrentExecutionActProven:  currentExecution,
		HarmfulCoreComplete:        harmfulCore,
		OperationallyActionable:    operational,
		AuthorizationClaim:         authorization,
		ExplicitVictimOrNonConsent: explicitVictim,
		CovertAcquisition:          covert,
		ExfiltrationOrTakeover:     exfiltration,
		MaliciousPersistence:       persistence,
		DestructiveOutcome:         destructive,
		SecurityControlEvasion:     evasion,
		DefensiveScopeConflict:     defensiveConflict,
		QuotedOrAnalyticalScope:    quotedOrAnalytical,
		CrossScopeComposition:      input.crossScope,
		ReferentProofComplete:      referentComplete,
		EvidenceAmbiguous:          ambiguous,
	}
	return finalizeCandidateBlockEligibility(eligibility)
}

var candidatePhishingCredentialSolicitationIntents = []string{
	"ask", "asks", "asking", "asked",
	"request", "requests", "requesting", "requested",
	"require", "requires", "requiring", "required",
	"tell", "tells", "telling", "told",
	"prompt", "prompts", "prompting", "prompted",
	"induce", "induces", "inducing", "induced",
	"solicit", "solicits", "soliciting", "solicited",
	"询问", "要求", "请求", "提示", "诱导", "让", "叫",
}

var candidatePhishingCredentialEntryIntents = []string{
	"enter", "enters", "entering", "entered",
	"type", "types", "typing", "typed",
	"submit", "submits", "submitting", "submitted",
	"provide", "provides", "providing", "provided",
	"give", "gives", "giving", "gave", "hand over", "hands over", "handing over", "handed over",
	"input", "inputs", "inputting", "fill in", "fills in", "filling in", "filled in",
	"输入", "键入", "提交", "提供", "交出", "填写",
}

var candidatePhishingCredentialCollectionIntents = []string{
	"collect", "collects", "collecting", "collected",
	"capture", "captures", "capturing", "captured",
	"harvest", "harvests", "harvesting", "harvested",
	"record", "records", "recording", "recorded",
	"gather", "gathers", "gathering", "gathered",
	"store", "stores", "storing", "stored",
	"save", "saves", "saving", "saved",
	"receive", "receives", "receiving", "received",
	"retain", "retains", "retaining", "retained",
	"forward", "forwards", "forwarding", "forwarded",
	"route", "routes", "routing", "routed",
	"relay", "relays", "relaying", "relayed",
	"intercept", "intercepts", "intercepting", "intercepted",
	"steal", "steals", "stealing", "stolen",
	"收集", "采集", "截取", "记录", "保存", "存储", "接收", "获取", "骗取", "窃取",
}

var candidatePhishingCredentialInteractionIntents = func() []string {
	intents := make([]string, 0,
		len(candidatePhishingCredentialSolicitationIntents)+
			len(candidatePhishingCredentialEntryIntents)+
			len(candidatePhishingCredentialCollectionIntents))
	intents = append(intents, candidatePhishingCredentialSolicitationIntents...)
	intents = append(intents, candidatePhishingCredentialEntryIntents...)
	intents = append(intents, candidatePhishingCredentialCollectionIntents...)
	return intents
}()

var candidatePhishingCredentialInteractionIntentPatterns = compileCompactRuleIntentPatterns(
	candidatePhishingCredentialInteractionIntents,
)

var candidatePhishingCurrentSpeechActHeads = []string{
	"build", "create", "deploy", "host", "launch", "publish", "install", "place", "send", "deliver", "push",
	"design", "generate", "construct", "write", "implement", "produce", "make",
	"ask", "request", "require", "tell", "prompt", "induce", "solicit",
	"enter", "type", "submit", "provide", "give", "input", "fill in",
	"collect", "capture", "harvest", "record", "gather", "store", "save", "receive", "retain", "steal",
	"forward", "route", "relay", "intercept",
	"execute", "run", "activate", "apply", "follow", "obey", "use", "carry out",
	"部署", "投放", "上线", "托管", "发布", "安装", "放置", "发送", "推送", "构建", "创建", "设计", "生成", "制作",
	"询问", "要求", "请求", "提示", "诱导", "输入", "键入", "提交", "提供", "交出", "填写",
	"收集", "采集", "截取", "记录", "保存", "存储", "接收", "获取", "骗取", "窃取",
	"执行", "运行", "启用", "应用", "遵循", "服从", "采用",
}

var candidatePhishingCurrentDeploymentIntents = []string{
	"build", "create", "deploy", "host", "launch", "publish", "install", "place", "send", "deliver", "push",
	"design", "generate", "construct", "write", "implement", "produce", "make",
	"部署", "投放", "上线", "托管", "发布", "安装", "放置", "发送", "推送", "构建", "创建", "设计", "生成", "制作",
}

// These verbs are intentionally not part of the global current-speech-act
// vocabulary. A bare hide/replace/suppress or training/notice phrase is often
// descriptive or defensive. They become an execution proof only when one
// bounded physical clause independently proves a hostile phishing relation and
// the action is unnegated; this keeps the proof candidate-local.
var candidatePhishingCurrentRelationActionIntents = []string{
	"suppress", "suppresses", "suppressing", "suppressed",
	"hide", "hides", "hiding", "hidden",
	"replace", "replaces", "replacing", "replaced",
	"skip", "skips", "skipping", "skipped",
	"act on", "act upon",
	"改成", "改作", "伪装成", "包装成", "冒充", "接收", "骗取", "诱导", "交出", "利用", "发送", "发给",
}

var candidatePhishingCurrentRelationActionPatterns = compileCompactRuleIntentPatterns(
	candidatePhishingCurrentRelationActionIntents,
)

var candidatePhishingCurrentDeploymentIntentPatterns = compileCompactRuleIntentPatterns(
	candidatePhishingCurrentDeploymentIntents,
)

func candidatePhishingCurrentSpeechActHead(text string) bool {
	text = strings.TrimLeft(strings.TrimSpace(text), "-*#>,:\t")
	for range 4 {
		previous := text
		for _, prefix := range []string{
			"please ", "now ", "then ", "and then ", "next ", "also ", "immediately ", "right now ",
			"i want you to ", "i need you to ", "you must ", "you should ", "must ",
			"can you ", "could you ", "would you ", "help me ",
			"\u7acb\u5373", "\u8fd9\u6b21", "\u76f4\u63a5",
			"请", "现在", "然后", "接着", "我需要你", "帮我",
		} {
			if strings.HasPrefix(text, prefix) {
				text = strings.TrimSpace(text[len(prefix):])
				break
			}
		}
		if text == previous {
			break
		}
	}
	if startsWithRuleIntent(text, candidatePhishingCurrentSpeechActHeads) {
		return true
	}
	// Imperatives can carry a short discourse preface before the action. Inspect
	// only the first bounded clause continuation; the caller has already proved
	// the complete phishing relation, so this is not a global keyword allowlist.
	for _, boundary := range []string{",", "，", ":", "：", ";", "；"} {
		index := strings.Index(text, boundary)
		if index < 0 || index+len(boundary) >= len(text) || index > 192 {
			continue
		}
		tail := strings.TrimLeft(strings.TrimSpace(text[index+len(boundary):]), "-*#>,:\t")
		for range 3 {
			previous := tail
			for _, prefix := range []string{"please ", "now ", "then ", "immediately ", "right now ", "\u7acb\u5373", "\u73b0\u5728"} {
				if strings.HasPrefix(tail, prefix) {
					tail = strings.TrimSpace(tail[len(prefix):])
					break
				}
			}
			if tail == previous {
				break
			}
		}
		if startsWithRuleIntent(tail, candidatePhishingCurrentSpeechActHeads) {
			return true
		}
	}
	return false
}

func candidatePhishingCurrentRelationActionPrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	// Quoted activation is already a complete current-user speech-act proof;
	// the enclosing caller has already proved the phishing relation for this
	// candidate. Do not ask the quoted payload to independently re-prove it: the
	// payload is intentionally inert and the activation is the local authority.
	if candidateExplicitQuotedActivation(text) {
		return true
	}
	if !candidatePhishingDeceptionSurface(text) {
		return false
	}

	found := false
	walkDirectiveClauses([]rune(text), func(clause []rune) bool {
		clauseText := strings.ToLower(strings.TrimSpace(string(clause)))
		if clauseText == "" || candidateExplicitRelationSimpleProhibitionRunes(clause) ||
			candidatePassiveIncidentReportOrDocumentationScope(clauseText) ||
			candidateQuotedOrAnalyticalScope(clauseText) ||
			candidateTransformativeAnalyticalScope(clauseText) ||
			candidatePermissionOnlyScope(clauseText) {
			return true
		}
		if !containsUnnegatedRuleIntentPrepared(
			clauseText,
			candidatePhishingCurrentRelationActionIntents,
			candidatePhishingCurrentRelationActionPatterns,
		) || !candidatePhishingDeceptionSurface(clauseText) {
			return true
		}
		// Re-prove the relation inside this exact clause. The whole request may
		// contain a hostile noun elsewhere; it must not lend authority here. Let
		// the typed phishing relation prove its own intrinsically hostile form
		// (for example, inducing real users to surrender account access) instead
		// of requiring an unrelated generic non-consent marker in the clause.
		clauseProof := newCandidatePhishingRelationProof(clauseText)
		if !candidateExplicitPhishingRelationPrepared(
			clauseText, candidateExplicitMaliciousHostileScope(clauseText), &clauseProof,
		) {
			return true
		}
		found = true
		return false
	})
	return found
}

func candidatePhishingCurrentCredentialInteractionSpeechAct(text string) bool {
	return candidatePhishingCurrentCredentialInteractionSpeechActPrepared(text, nil)
}

func candidatePhishingCurrentCredentialInteractionSpeechActPrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.currentSpeechActKnown {
		return proof.currentSpeechAct
	}
	result := candidatePhishingCurrentCredentialInteractionSpeechActUncached(text, proof)
	if proofMatches {
		proof.currentSpeechActKnown = true
		proof.currentSpeechAct = result
	}
	return result
}

func candidatePhishingCurrentCredentialInteractionSpeechActUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if tail, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); independent &&
		candidateExplicitPhishingRelation(
			tail, candidateExplicitMaliciousHostileScope(tail),
		) &&
		candidatePhishingCurrentSpeechActHead(tail) {
		return true
	}
	if !candidateExplicitPhishingRelationPrepared(
		text, candidateExplicitMaliciousHostileScope(text), proof,
	) {
		return false
	}
	quotedActivation := candidateExplicitQuotedActivation(text)
	if candidatePassiveIncidentReportOrDocumentationScopePrepared(text, proof) ||
		candidatePhishingDetectionArtifactScopePrepared(text, proof) ||
		candidateQuotedOrAnalyticalScopePrepared(text, proof) && !quotedActivation ||
		candidateTransformativeAnalyticalScope(text) ||
		candidateExplicitRelationWholeFieldDefensiveOwner(text) ||
		candidatePermissionOnlyScope(text) ||
		candidateExplicitRelationSimpleProhibitionRunes([]rune(text)) {
		return false
	}
	return candidatePhishingCurrentSpeechActHead(text) ||
		candidatePhishingCurrentRelationActionPrepared(text, proof) ||
		containsUnnegatedRuleIntentPrepared(
			text,
			candidatePhishingCurrentDeploymentIntents,
			candidatePhishingCurrentDeploymentIntentPatterns,
		)
}

var candidatePhishingSyntheticSecretTerms = []string{
	"synthetic credentials", "synthetic credential", "synthetic passwords", "synthetic password",
	"synthetic training_token values", "synthetic training_token value", "synthetic training tokens", "synthetic training token",
	"dummy credentials", "dummy credential", "dummy passwords", "dummy password",
	"test credentials", "test credential", "test passwords", "test password",
	"fictional credentials", "fictional credential", "fictional passwords", "fictional password",
	"合成凭据", "合成密码", "虚构凭据", "虚构密码", "测试凭据", "测试密码",
}

var candidatePhishingSyntheticTargetTerms = []string{
	"synthetic users", "synthetic user", "dummy users", "dummy user",
	"test users", "test user", "fictional users", "fictional user",
	"test personas", "test persona", "lab personas", "lab persona",
	"合成用户", "测试用户", "虚构用户", "测试角色", "实验室角色",
}

var candidatePhishingCredentialNonSecretTerms = []string{
	"password managers", "password manager", "password policies", "password policy",
	"password hygiene", "password strength", "password reset", "password resets", "passwordless",
	"credential policy", "credential policies", "credential guidance", "credential documentation",
	"密码管理器", "密码策略", "密码卫生", "密码强度", "密码重置", "无密码登录", "凭据策略", "凭据文档",
}

var candidatePhishingDetectionArtifactTerms = []string{
	"detector", "detection rule", "detection signature", "scanner", "classifier", "alert rule", "analytic rule",
	"detection guidance", "remediation guidance", "incident report", "forensic report",
	"检测器", "检测规则", "检测签名", "扫描器", "分类器", "告警规则", "分析规则", "检测指南", "修复指南", "事件报告", "取证报告",
}

var candidatePhishingDeceptiveSurfaceTargetTerms = []string{
	"phishing page", "phishing site", "fake login", "fake oauth", "fake support", "fake portal",
	"cloned login", "credential form", "spoofed sign-in", "spoofed login", "deceptive login", "lookalike login",
	"钓鱼页面", "钓鱼站点", "假登录", "仿冒登录", "假授权页", "假支持页面", "仿冒入口", "凭据表单",
}

var candidatePhishingCredentialDefensiveTargetTerms = func() []string {
	terms := make([]string, 0,
		len(candidatePhishingSyntheticSecretTerms)+
			len(candidatePhishingSyntheticTelemetryTerms)+
			len(candidateCredentialSecurityArtifactTerms)+
			len(candidatePhishingCredentialNonSecretTerms))
	terms = append(terms, candidatePhishingSyntheticSecretTerms...)
	terms = append(terms, candidatePhishingSyntheticTelemetryTerms...)
	terms = append(terms, candidateCredentialSecurityArtifactTerms...)
	terms = append(terms, candidatePhishingCredentialNonSecretTerms...)
	return terms
}()

var candidatePhishingRealPersonTargetTerms = []string{
	"real user", "real users", "end user", "end users", "user", "users",
	"real employee", "real employees", "employee", "employees", "staff member", "staff members", "staff",
	"real customer", "real customers", "customer", "customers",
	"victim", "victims", "account holder", "account holders", "people", "person",
	"真实用户", "用户", "真实员工", "员工", "职员", "真实客户", "客户", "受害者", "账户所有者",
}

var candidatePhishingExplicitHumanCredentialTerms = []string{
	"real password", "real passwords", "actual password", "actual passwords", "live password", "live passwords",
	"real credential", "real credentials", "actual credential", "actual credentials", "live credential", "live credentials",
	"their password", "their passwords", "their credential", "their credentials", "their session token", "their session tokens",
	"their browser cookie", "their browser cookies", "users' passwords", "employees' passwords",
	"entered password", "entered passwords", "typed password", "typed passwords",
	"submitted password", "submitted passwords", "provided credential", "provided credentials",
	"saved password", "saved passwords", "staff credentials", "employee credentials", "user credentials",
	"真实密码", "实际密码", "真实凭据", "实际凭据", "输入的密码", "键入的密码", "提交的密码", "提供的凭据", "保存的密码",
}

var candidatePhishingCredentialHarmfulTargetTerms = append(
	[]string{
		"session tokens", "account sessions", "vault secrets", "service keys", "secret materials",
		"会话令牌", "账户会话", "保险库密钥", "服务密钥", "秘密材料",
	},
	candidateExplicitCredentialMaterialTerms...,
)

var candidatePhishingDeploymentIntents = []string{
	"deploy", "deploys", "deploying", "host", "hosts", "hosting", "launch", "launches", "launching",
	"publish", "publishes", "publishing", "install", "installs", "installing", "place", "places", "placing",
	"send", "sends", "sending", "deliver", "delivers", "delivering", "push", "pushes", "pushing",
	"build", "builds", "building", "create", "creates", "creating", "design", "designs", "designing",
	"generate", "generates", "generating", "construct", "constructs", "constructing",
	"部署", "投放", "上线", "托管", "发布", "安装", "放置", "发送", "推送", "构建", "创建", "设计", "生成", "制作",
}

var candidatePhishingDeploymentIntentPatterns = compileCompactRuleIntentPatterns(
	candidatePhishingDeploymentIntents,
)

func candidatePhishingCredentialInteractionAction(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	return text != "" && containsUnnegatedRuleIntentPrepared(
		text,
		candidatePhishingCredentialInteractionIntents,
		candidatePhishingCredentialInteractionIntentPatterns,
	)
}

func candidatePhishingCredentialActionCanReachSurface(text string) bool {
	surfaceIndex := candidateFirstBoundedLiteralIndex(text, candidatePhishingDeceptiveSurfaceTargetTerms)
	if surfaceIndex < 0 {
		return true
	}
	mayContainNegation := stringMayContainNegation(text)
	// Precompute the two suffix facts needed by every action occurrence. The
	// former implementation rescanned every harmful term and the entire suffix
	// for each repeated intent, making a 16 KiB "ask ask ..." field quadratic.
	// The reviewed term sets are fixed, so these are constant-count linear scans;
	// the loop below then performs only O(1) bounded work per matched intent.
	lastHarmfulTarget := candidateLastBoundedLiteralIndex(text, candidatePhishingCredentialHarmfulTargetTerms)
	if lastHarmfulTarget < 0 {
		return false
	}
	lastBoundaryBeforeSurface := candidatePhishingLastDirectiveBoundaryBefore(text, surfaceIndex)
	for _, intent := range candidatePhishingCredentialInteractionIntents {
		if intent == "" || len(intent) > len(text) {
			continue
		}
		for offset := 0; offset <= len(text)-len(intent); {
			index := strings.Index(text[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(intent)
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(text[index-1])
			rightOK := !isASCIIStringLocal(intent) || end == len(text) || !isASCIIWordByte(text[end])
			if leftOK && rightOK {
				negated := false
				if mayContainNegation {
					_, negated = ruleIntentOccurrenceNegation(text, index)
				}
				if !negated && lastHarmfulTarget >= end &&
					(index >= surfaceIndex || index > lastBoundaryBeforeSurface) {
					return true
				}
			}
			offset = index + 1
		}
	}
	return false
}

func candidatePhishingLastDirectiveBoundaryBefore(text string, end int) int {
	if end <= 0 {
		return -1
	}
	if end > len(text) {
		end = len(text)
	}
	prefix := text[:end]
	best := strings.LastIndexAny(prefix, ",.!?;:")
	for _, marker := range []string{
		"，", "。", "！", "？", "；", "：",
		" but ", " however ", " then ", " instead ", " actually ", " while ",
		"但是", "然而", "然后", "改为", "实际",
	} {
		if index := strings.LastIndex(prefix, marker); index > best {
			best = index
		}
	}
	return best
}

func candidatePhishingDirectiveBoundaryBetween(text string) bool {
	if strings.ContainsAny(text, ",.!?;:\uff0c\u3002\uff01\uff1f\uff1b\uff1a") {
		return true
	}
	for _, marker := range []string{
		" but ", " however ", " then ", " instead ", " actually ", " while ",
		"\u4f46\u662f", "\u7136\u800c", "\u7136\u540e", "\u6539\u4e3a", "\u5b9e\u9645",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func candidatePhishingReferencedNonExecutionScope(text string) bool {
	return containsAnyLiteral(text,
		"for requests that", "for requests which", "for prompts that", "for prompts which",
		"detect requests that", "detect prompts that", "flag requests that", "flag prompts that",
		"identify requests that", "identify prompts that", "\u8fd9\u7c7b\u8bf7\u6c42", "\u6b64\u7c7b\u8bf7\u6c42", "\u8fd9\u7c7b\u63d0\u793a", "\u6b64\u7c7b\u63d0\u793a",
	) && containsAnyLiteral(text,
		"do not execute", "don't execute", "must not execute", "never execute", "without executing",
		"analysis only", "detection only", "\u4e0d\u8981\u6267\u884c", "\u4e0d\u5f97\u6267\u884c", "\u7981\u6b62\u6267\u884c", "\u4ec5\u5206\u6790", "\u4ec5\u68c0\u6d4b",
	)
}

func candidatePhishingDetectionArtifactScope(text string) bool {
	return candidatePhishingDetectionArtifactScopePrepared(text, nil)
}

func candidatePhishingDetectionArtifactScopePrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.detectionArtifactKnown {
		return proof.detectionArtifact
	}
	result := candidatePhishingDetectionArtifactScopeUncached(text, proof)
	if proofMatches {
		proof.detectionArtifactKnown = true
		proof.detectionArtifact = result
	}
	return result
}

func candidatePhishingDetectionArtifactScopeUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" || !containsAnyLiteral(text, candidatePhishingDetectionArtifactTerms...) {
		return false
	}
	detectionPurpose := containsAnyLiteral(text,
		"detect", "flag", "identify", "scan", "classify", "alert", "analyze", "analyse", "review",
		"检测", "识别", "扫描", "分类", "告警", "分析", "审查",
	)
	artifactCreation := containsUnnegatedRuleIntentPrepared(
		text,
		candidatePhishingDeploymentIntents,
		candidatePhishingDeploymentIntentPatterns,
	)
	if !detectionPurpose && !artifactCreation {
		return false
	}
	_, independentExecution := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof)
	if candidatePhishingReferencedNonExecutionScope(text) && !independentExecution {
		return true
	}
	if !independentExecution && containsAnyLiteral(text,
		"fake login detector", "fake login page detector", "fake login pages detector",
		"cloned login detector", "phishing page detector", "deceptive login detector",
		"spoofed sign-in detector", "spoofed login detector",
		"仿冒登录检测器", "假登录检测器", "钓鱼页面检测器", "欺骗登录检测器",
	) {
		return true
	}
	targets := candidateActionTargets(
		text,
		candidatePhishingDeploymentIntents,
		candidatePhishingDetectionArtifactTerms,
		candidatePhishingDeceptiveSurfaceTargetTerms,
	)
	return targets.active && targets.defensive && !targets.harmful && !targets.unknown
}

func candidateMaskPhishingLiteralTerms(text string, terms []string) string {
	var masked []byte
	for _, term := range terms {
		if term == "" || len(term) > len(text) {
			continue
		}
		for offset := 0; offset <= len(text)-len(term); {
			index := strings.Index(text[offset:], term)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(term)
			leftOK := !isASCIIStringLocal(term) || index == 0 || !isASCIIWordByte(text[index-1])
			rightOK := !isASCIIStringLocal(term) || end == len(text) || !isASCIIWordByte(text[end])
			if leftOK && rightOK {
				if masked == nil {
					masked = []byte(text)
				}
				for position := index; position < end; position++ {
					masked[position] = ' '
				}
			}
			offset = index + 1
		}
	}
	if masked == nil {
		return text
	}
	return string(masked)
}

func candidatePhishingCredentialMaterialAfterExclusions(text string) bool {
	if !candidateExplicitCredentialMaterial(text) {
		return false
	}
	if !containsAnyLiteral(text, candidatePhishingCredentialDefensiveTargetTerms...) {
		return true
	}
	text = candidateMaskPhishingLiteralTerms(text, candidatePhishingCredentialDefensiveTargetTerms)
	return candidateExplicitCredentialMaterial(text)
}

func candidatePhishingCredentialCollectionPhysicalClause(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	proofText := candidateMaskPhishingLiteralTerms(text, candidatePhishingCredentialDefensiveTargetTerms)
	if !candidateExplicitCredentialMaterial(proofText) {
		return false
	}
	targets := candidateActionTargets(
		proofText,
		candidatePhishingCredentialInteractionIntents,
		nil,
		candidatePhishingCredentialHarmfulTargetTerms,
	)
	return targets.active && targets.harmful
}

func candidatePhishingCredentialCollectionClause(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" || !candidatePhishingCredentialMaterialAfterExclusions(text) {
		return false
	}
	found := false
	walkDirectiveClauses([]rune(text), func(clause []rune) bool {
		clauseText := strings.TrimSpace(string(clause))
		if clauseText == "" || candidateExplicitRelationSimpleProhibitionRunes(clause) {
			return true
		}
		found = candidatePhishingCredentialCollectionPhysicalClause(clauseText)
		return !found
	})
	return found
}

func candidatePhishingRealCredentialTarget(text string) bool {
	targetText := candidateMaskPhishingLiteralTerms(text, candidatePhishingSyntheticTargetTerms)
	realPersonTarget := candidateFirstBoundedLiteralIndex(targetText, candidatePhishingRealPersonTargetTerms) >= 0
	explicitHumanCredential := candidateFirstBoundedLiteralIndex(text, candidatePhishingExplicitHumanCredentialTerms) >= 0
	return realPersonTarget || explicitHumanCredential
}

// candidatePhishingRealCredentialInteractionRelation proves a compact,
// candidate-local relation between a deceptive authentication surface and an
// unnegated request for human credentials. Synthetic secrets, synthetic users,
// training telemetry, credential-alert artifacts, and password-policy topics
// are removed only from this proof view; they cannot suppress a second, real
// credential relation elsewhere in the same bounded candidate.
func candidatePhishingRealCredentialInteractionRelation(text string) bool {
	return candidatePhishingRealCredentialInteractionRelationPrepared(text, nil)
}

func candidatePhishingRealCredentialInteractionRelationPrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.realCredentialRelationKnown {
		return proof.realCredentialRelation
	}
	result := candidatePhishingRealCredentialInteractionRelationUncached(text, proof)
	if proofMatches {
		proof.realCredentialRelationKnown = true
		proof.realCredentialRelation = result
	}
	return result
}

func candidatePhishingRealCredentialInteractionRelationUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	// A complete detection/analysis request owns the quoted hostile relation in
	// its subject. Only a later, independently executable malicious clause may
	// reactivate that relation. Checking this boundary before the credential
	// proof also avoids turning the detector's quoted target into a real request.
	if candidatePhishingDetectionArtifactScopePrepared(text, proof) &&
		candidatePhishingReferencedNonExecutionScope(text) {
		if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); !independent {
			return false
		}
	}
	// Keep the expensive clause-local proof off unrelated candidate windows.
	// These are necessary whole-window signals only; the walker below still has
	// to bind the deception surface, real person, secret, and action locally.
	if !candidatePhishingDeceptionSurface(text) ||
		!candidatePhishingCredentialActionCanReachSurface(text) ||
		!candidatePhishingCredentialMaterialAfterExclusions(text) ||
		!candidatePhishingRealCredentialTarget(text) {
		return false
	}
	found := false
	pendingDeceptiveSurface := false
	walkDirectiveClausesWithBoundary([]rune(text), func(clause []rune, boundary directiveBoundaryKind) bool {
		if boundary == directiveBoundaryStrong {
			pendingDeceptiveSurface = false
		}
		clauseText := strings.ToLower(strings.TrimSpace(string(clause)))
		if clauseText == "" || candidateExplicitRelationSimpleProhibitionRunes(clause) ||
			candidateQuotedOrAnalyticalScope(clauseText) ||
			candidateTransformativeAnalyticalScope(clauseText) ||
			candidatePermissionOnlyScope(clauseText) {
			pendingDeceptiveSurface = false
			return true
		}

		deceptionSurface := candidatePhishingDeceptionSurface(clauseText)
		detectionArtifact := candidatePhishingDetectionArtifactScope(clauseText)
		credentialRelation := candidatePhishingCredentialCollectionPhysicalClause(clauseText) &&
			candidatePhishingRealCredentialTarget(clauseText)
		if !detectionArtifact && credentialRelation && (deceptionSurface || pendingDeceptiveSurface) {
			found = true
			return false
		}

		if candidateExplicitRelationWholeFieldDefensiveOwner(clauseText) && !detectionArtifact {
			pendingDeceptiveSurface = false
			return true
		}
		pendingDeceptiveSurface = deceptionSurface &&
			(detectionArtifact || containsUnnegatedRuleIntentPrepared(
				clauseText,
				candidatePhishingDeploymentIntents,
				candidatePhishingDeploymentIntentPatterns,
			))
		return true
	})
	return found
}

// candidateFieldHasIndependentPhishingRealCredentialClause prevents an
// unrelated analytical prefix or suffix from owning an operational phishing
// clause in the middle of the same bounded field. Each physical clause must
// independently prove the full local relation; quoted, analytical, defensive,
// synthetic, and prohibited clauses remain inert.
func candidateFieldHasIndependentPhishingRealCredentialClause(text []rune) bool {
	found := false
	walkDirectiveClauses(text, func(clause []rune) bool {
		clauseText := strings.TrimSpace(string(clause))
		if clauseText == "" || candidateExplicitRelationSimpleProhibitionRunes(clause) {
			return true
		}
		found = candidatePhishingRealCredentialInteractionRelation(clauseText)
		return !found
	})
	return found
}

func candidatePhishingSyntheticSimulationScope(text string) bool {
	return candidatePhishingSyntheticSimulationScopePrepared(text, nil)
}

func candidatePhishingSyntheticSimulationScopePrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.syntheticSimulationKnown {
		return proof.syntheticSimulation
	}
	result := candidatePhishingSyntheticSimulationScopeUncached(text, proof)
	if proofMatches {
		proof.syntheticSimulationKnown = true
		proof.syntheticSimulation = result
	}
	return result
}

func candidatePhishingSyntheticSimulationScopeUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	controlled := containsAnyLiteral(text,
		"isolated lab", "offline lab", "test tenant", "phishing simulation", "awareness exercise", "training exercise",
		"隔离实验室", "离线实验室", "测试租户", "钓鱼演练", "安全演练", "意识培训", "培训练习",
	)
	syntheticSecrets := containsAnyLiteral(text, candidatePhishingSyntheticSecretTerms...)
	defensivePurpose := containsAnyLiteral(text,
		"alert validation", "validate alerts", "detector validation", "detection validation", "training",
		"验证告警", "告警验证", "检测验证", "培训",
	)
	if !controlled || !syntheticSecrets || !defensivePurpose {
		return false
	}
	if candidatePhishingRealCredentialInteractionRelationPrepared(text, proof) || hasExplicitHarmConflict(text) ||
		candidateExplicitVictimOrNonConsent(text) || candidateCovertAcquisition(text) ||
		candidateExfiltrationOrTakeover(text) {
		return false
	}
	realTarget := containsAnyLiteral(text,
		"real user", "real users", "real employee", "real employees", "real customer", "real customers",
		"真实用户", "真实员工", "真实客户",
	)
	realTargetExplicitlyExcluded := containsAnyLiteral(text,
		"does not connect to real users", "doesn't connect to real users", "do not connect to real users",
		"not connected to real users", "without connecting to real users", "does not contact real users",
		"doesn't contact real users", "do not contact real users", "without contacting real users",
		"not delivered to real users", "not sent to real users", "not exposed to real users",
		"不连接真实用户", "不接触真实用户", "不面向真实用户", "不发送给真实用户", "不投放给真实用户",
		"不会连接真实用户", "不会接触真实用户", "不会面向真实用户",
	)
	if realTarget && !realTargetExplicitlyExcluded {
		return false
	}
	return controlled && syntheticSecrets && defensivePurpose
}

// candidateLinkedPhishingSoftPair proves one narrow, candidate-local relation
// across two adjacent soft/continuation clauses. It never joins strong or
// contrast boundaries and never uses a request-global risk-word bag.
func candidateLinkedPhishingSoftPair(previous, current, ownerText string, boundary directiveBoundaryKind) bool {
	if boundary != directiveBoundarySoft && boundary != directiveBoundaryContinuation {
		return false
	}
	previous = strings.ToLower(strings.TrimSpace(previous))
	current = strings.ToLower(strings.TrimSpace(current))
	ownerText = strings.ToLower(strings.TrimSpace(ownerText))
	joined := strings.TrimSpace(previous + "\n" + current)
	if previous == "" || current == "" || candidateQuotedOrAnalyticalScope(ownerText) ||
		candidateTransformativeAnalyticalScope(ownerText) || containsDetectionArtifact(ownerText) ||
		candidatePhishingDetectionArtifactScope(ownerText) || isSafetyDeliverableClause(ownerText) ||
		candidateCredentialLifecycle(joined) ||
		candidatePermissionOnlyScope(joined) || candidatePhishingSyntheticSimulationScope(ownerText) {
		return false
	}
	// The delivery clause may explicitly deploy a deceptive authentication
	// surface or directly send it to the target. A passive training-page
	// description cannot become a delivery proof merely because it names
	// employees.
	deployment := candidatePhishingDeceptionSurface(previous) &&
		containsUnnegatedRuleIntentPrepared(
			previous,
			candidatePhishingDeploymentIntents,
			candidatePhishingDeploymentIntentPatterns,
		)
	realTarget := containsAnyLiteral(joined,
		"real user", "real users", "real employee", "real employees", "real customer", "real customers",
		"victim user", "victim users", "victim employee", "victim employees",
		"employee", "employees", "staff member", "staff members", "account holder", "account holders",
		"真实用户", "真实员工", "真实客户", "受害用户", "受害员工", "员工", "账户所有者",
	)
	collection := candidatePhishingCredentialCollectionClause(current) && realTarget &&
		!candidatePhishingSyntheticTelemetryScope(joined)
	return deployment && collection
}

// candidatePhishingSyntheticTelemetryScope keeps awareness telemetry distinct
// from credential values. It is deliberately narrow: an explicit password,
// token, cookie, or credential value defeats this exemption even when the
// request labels the collection as training.
var candidatePhishingSyntheticTelemetryTerms = []string{
	"password-entry events", "password-entry event", "password entry events", "password entry event",
	"login-attempt events", "login-attempt event", "form-submission events", "form-submission event",
	"click-through events", "click-through event", "密码输入事件", "登录尝试事件", "表单提交事件", "点击事件",
}

func candidatePhishingSyntheticTelemetryScope(text string) bool {
	telemetry := containsAnyLiteral(text, candidatePhishingSyntheticTelemetryTerms...)
	defensivePurpose := containsAnyLiteral(text,
		"training report", "awareness report", "simulation report", "aggregate metric", "aggregate metrics",
		"training analytics", "awareness analytics", "training telemetry", "awareness telemetry",
		"培训报告", "意识培训报告", "演练报告", "汇总指标", "培训分析", "演练遥测",
	)
	actualSecret := containsAnyLiteral(text,
		"session token", "session tokens", "session cookie", "session cookies",
		"entered password", "entered passwords", "submitted password", "submitted passwords",
		"password value", "password values", "credential value", "credential values",
		"raw password", "raw passwords", "actual password", "actual passwords", "real password", "real passwords",
		"会话令牌", "会话 cookie", "输入的密码", "提交的密码", "密码值", "凭证值", "原始密码", "真实密码",
	)
	hostileTransfer := containsAnyLiteral(text,
		"attacker-controlled", "outside the company", "export the events", "export these events", "exfiltrate the events",
		"send the events to", "upload the events to", "攻击者控制", "公司外部", "导出这些事件", "外传这些事件", "发送事件到", "上传事件到",
	)
	if telemetry && defensivePurpose && !actualSecret {
		// Remove only the recognized event names before checking for an
		// independent credential-collection relation. This preserves the benign
		// "record password-entry events" form while preventing the same training
		// phrase from hiding a later "collect their passwords" instruction.
		withoutTelemetry := text
		for _, term := range candidatePhishingSyntheticTelemetryTerms {
			withoutTelemetry = strings.ReplaceAll(withoutTelemetry, term, "")
		}
		actualSecret = candidatePhishingCredentialCollectionClause(withoutTelemetry)
	}
	return telemetry && defensivePurpose && !actualSecret && !hostileTransfer
}

func mergeCandidateAuthorizationClaims(
	left AuthorizationClaimState,
	right AuthorizationClaimState,
) AuthorizationClaimState {
	if left == AuthorizationConflicting || right == AuthorizationConflicting {
		return AuthorizationConflicting
	}
	if left == AuthorizationUnverifiable || right == AuthorizationUnverifiable {
		return AuthorizationUnverifiable
	}
	if left == AuthorizationConsistent || right == AuthorizationConsistent {
		return AuthorizationConsistent
	}
	return AuthorizationAbsent
}

// retainCandidateAuthorizationConflict preserves a bounded request-local
// authorization prefix when a profiled natural-language pre-pass classifies
// only an independently executable malicious tail. The wider text may supply
// the claim state, but it can never supply a harm axis or repair eligibility;
// those proofs must already belong to the retained tail candidate.
func retainCandidateAuthorizationConflict(result *Result, authorizationText string) {
	if result == nil || result.BlockEligibility == nil {
		return
	}
	text := strings.ToLower(strings.TrimSpace(authorizationText))
	if !candidateAuthorizationClaimPresent(text) {
		return
	}
	eligibility := *result.BlockEligibility
	if !eligibility.HarmfulCoreComplete || !candidateEligibilityHasPositiveMaliceAxis(eligibility) {
		return
	}
	eligibility.AuthorizationClaim = AuthorizationConflicting
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

// finalizeCandidateBlockEligibility is the single state-machine transition
// used both when a clause-local candidate is first built and when a role-aware
// caller binds that candidate to the actual request actor. Callers may narrow
// evidence ownership or inspection completeness, but score and hard-floor code
// can never make an ineligible candidate eligible.
func finalizeCandidateBlockEligibility(eligibility CandidateBlockEligibility) CandidateBlockEligibility {
	if eligibility.AuthorizationClaim == "" {
		eligibility.AuthorizationClaim = AuthorizationAbsent
	}
	// Direct classifier producers start from current-user semantics. Role-aware
	// binding may later replace that scope with a request-local non-user scope or
	// clear it entirely. Never let a non-user scope masquerade as user ownership.
	if eligibility.EvidenceOwnedByCurrentUser {
		eligibility.EnforcementScope = EnforcementScopeCurrentUser
	} else if eligibility.EnforcementScope == EnforcementScopeCurrentUser {
		eligibility.EnforcementScope = EnforcementScopeNone
	}
	switch eligibility.EnforcementScope {
	case EnforcementScopeNone, EnforcementScopeCurrentUser,
		EnforcementScopeRequestLocalSystem, EnforcementScopeRequestLocalTool:
	default:
		eligibility.EnforcementScope = EnforcementScopeNone
		eligibility.EvidenceAmbiguous = true
	}
	// Round 9's block gate is a positive-proof gate. A complete score/core is
	// insufficient unless the same bounded candidate proves at least one typed
	// malicious axis. This prevents generic provider composition (for example,
	// building ordinary production records) from becoming blockable merely
	// because semantic or composed evidence reached a high score.
	if !candidateEligibilityHasPositiveMaliceAxis(eligibility) {
		eligibility.HarmfulCoreComplete = false
		eligibility.EvidenceAmbiguous = true
	}
	eligibility.Eligible = false
	eligibility.PrimaryReason = ""
	eligibility.ReasonFlags = 0

	addReason := func(condition bool, flag uint64) {
		if condition {
			eligibility.ReasonFlags |= flag
		}
	}
	addReason(!eligibility.InspectionComplete, EligibilityReasonIncompleteInspection)
	addReason(!eligibility.RequestBlockAuthorityProven(), EligibilityReasonUntrustedOwnership)
	addReason(!eligibility.CurrentExecutionActProven, EligibilityReasonNoCurrentDirective)
	addReason(eligibility.QuotedOrAnalyticalScope, EligibilityReasonQuotedOrAnalytical)
	addReason(eligibility.DefensiveScopeConflict, EligibilityReasonDefensivePurpose)
	addReason(eligibility.AuthorizationClaim == AuthorizationConsistent && !eligibility.HarmfulCoreComplete, EligibilityReasonAuthorizedOwnedOperation)
	addReason(eligibility.EvidenceAmbiguous || !eligibility.HarmfulCoreComplete, EligibilityReasonAmbiguousCore)
	addReason(eligibility.CrossScopeComposition || !eligibility.ReferentProofComplete, EligibilityReasonCrossScopeComposition)
	addReason(!eligibility.OperationallyActionable, EligibilityReasonOperationalCoreAbsent)

	eligibility.Eligible = eligibility.InspectionComplete &&
		eligibility.RequestBlockAuthorityProven() &&
		eligibility.CurrentExecutionActProven &&
		eligibility.HarmfulCoreComplete &&
		eligibility.OperationallyActionable &&
		!eligibility.DefensiveScopeConflict &&
		!eligibility.QuotedOrAnalyticalScope &&
		!eligibility.CrossScopeComposition &&
		eligibility.ReferentProofComplete &&
		!eligibility.EvidenceAmbiguous
	if eligibility.Eligible {
		eligibility.PrimaryReason = GateEligibleExplicitMalice
		eligibility.ReasonFlags |= EligibilityReasonExplicitMalice
		return eligibility
	}

	switch {
	case !eligibility.InspectionComplete:
		eligibility.PrimaryReason = GateIncompleteInspection
	case !eligibility.RequestBlockAuthorityProven():
		eligibility.PrimaryReason = GateUntrustedOwnership
	case eligibility.QuotedOrAnalyticalScope:
		eligibility.PrimaryReason = GateQuotedOrAnalytical
	case eligibility.DefensiveScopeConflict:
		eligibility.PrimaryReason = GateDefensivePurpose
	case eligibility.AuthorizationClaim == AuthorizationConsistent && !eligibility.HarmfulCoreComplete:
		eligibility.PrimaryReason = GateAuthorizedOwnedOperation
	case eligibility.CrossScopeComposition || !eligibility.ReferentProofComplete:
		eligibility.PrimaryReason = GateCrossScopeComposition
	case !eligibility.CurrentExecutionActProven:
		eligibility.PrimaryReason = GateNoCurrentDirective
	case !eligibility.OperationallyActionable:
		eligibility.PrimaryReason = GateOperationalCoreAbsent
	default:
		eligibility.PrimaryReason = GateAmbiguousCore
	}
	return eligibility
}

func candidateEligibilityHasPositiveMaliceAxis(eligibility CandidateBlockEligibility) bool {
	return eligibility.ExplicitVictimOrNonConsent ||
		eligibility.CovertAcquisition ||
		eligibility.ExfiltrationOrTakeover ||
		eligibility.MaliciousPersistence ||
		eligibility.DestructiveOutcome ||
		eligibility.SecurityControlEvasion
}

func candidateActionFor(mode Mode, score int, thresholds Thresholds, eligibility CandidateBlockEligibility) Action {
	thresholds = validThresholdsOrDefault(thresholds)
	if eligibility.Eligible {
		return actionFor(mode, score, thresholds)
	}
	if score < thresholds.Audit || mode == ModeOff {
		return ActionAllow
	}
	switch mode {
	case ModeObserve:
		return ActionObserve
	case ModeAudit, ModeBalanced, ModeStrict:
		return ActionAudit
	default:
		return ActionAllow
	}
}

func enforceResultCandidateEligibility(result *Result, mode Mode, thresholds Thresholds) {
	if result != nil && resultIsNeutralClassifierIncomplete(*result) {
		// A bounded classifier-window overflow is deliberately category-free. Do
		// not let the generic score/behavior fallback manufacture a synthetic
		// eligibility object for this neutral terminal result.
		result.Action = ActionAllow
		result.BlockEligibility = nil
		result.DecisionExplanation = nil
		return
	}
	if result == nil || (result.Score == 0 && len(result.RuleIDs) == 0 && result.Behavior == nil) {
		return
	}
	if result.BlockEligibility == nil {
		fallback := CandidateBlockEligibility{
			InspectionComplete:    result.Coverage.State == "" || result.Coverage.State == CoverageComplete,
			ReferentProofComplete: true,
			EvidenceAmbiguous:     true,
			PrimaryReason:         GateAmbiguousCore,
			ReasonFlags:           EligibilityReasonAmbiguousCore,
		}
		result.BlockEligibility = &fallback
	}
	eligibility := *result.BlockEligibility
	if result.Truncated || result.Coverage.State != "" && result.Coverage.State != CoverageComplete {
		eligibility.InspectionComplete = false
	}
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if !eligibility.Eligible {
		removeIneligibleHardFloor(result)
	}
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

func classifierIncompleteCoverageReason(reason CoverageReason) bool {
	return reason == CoverageReasonClassifierWindow ||
		reason == CoverageReasonClassifierProofBudget
}

func resultIsNeutralClassifierIncomplete(result Result) bool {
	return result.Truncated && result.FindingConfidence == FindingNone &&
		result.Coverage.State == CoverageUnavailable &&
		classifierIncompleteCoverageReason(result.Coverage.Reason) &&
		result.Score == 0 && result.Category == "" && len(result.RuleIDs) == 0
}

// bindResultCandidateActor narrows a clause-local candidate to the proven
// actor boundary. Intrinsic ownership/coherence is preserved with && so a role
// label can never repair a candidate that already failed its local scope proof.
func bindResultCandidateActor(result *Result, actorOwned bool, mode Mode, thresholds Thresholds) {
	if result == nil {
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	eligibility.EvidenceOwnedByCurrentUser = eligibility.EvidenceOwnedByCurrentUser && actorOwned
	if eligibility.EvidenceOwnedByCurrentUser {
		eligibility.EnforcementScope = EnforcementScopeCurrentUser
	} else {
		eligibility.EnforcementScope = EnforcementScopeNone
	}
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if !eligibility.Eligible {
		removeIneligibleHardFloor(result)
	}
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

// bindResultCandidateEnforcementScope admits a structurally proven request-local
// non-user carrier without rewriting its ownership. It is intentionally separate
// from bindResultCandidateActor so system/tool blocks cannot poison subject state.
func bindResultCandidateEnforcementScope(
	result *Result,
	scope EnforcementScope,
	mode Mode,
	thresholds Thresholds,
) {
	if result == nil {
		return
	}
	if scope != EnforcementScopeRequestLocalSystem && scope != EnforcementScopeRequestLocalTool {
		bindResultCandidateActor(result, false, mode, thresholds)
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	eligibility.EvidenceOwnedByCurrentUser = false
	eligibility.EnforcementScope = scope
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if !eligibility.Eligible {
		removeIneligibleHardFloor(result)
	}
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

func markResultCandidateInactive(result *Result, mode Mode, thresholds Thresholds) {
	if result == nil {
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	eligibility.CurrentExecutionActProven = false
	eligibility.QuotedOrAnalyticalScope = true
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	removeIneligibleHardFloor(result)
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

// markResultCandidateCrossScopeAmbiguous narrows a result whose bounded
// window no longer proves one complete logical candidate. Streaming META
// windows use synthetic occurrences, so actor binding must never turn a
// reconstructed partial window into an eligible current-user directive.
func markResultCandidateCrossScopeAmbiguous(result *Result, mode Mode, thresholds Thresholds) {
	if result == nil {
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	eligibility.CrossScopeComposition = true
	eligibility.EvidenceAmbiguous = true
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	removeIneligibleHardFloor(result)
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

// markResultCandidateEvidenceAmbiguous narrows a candidate when the risk match
// is real but its bounded physical occurrence proof is incomplete. Unlike the
// cross-scope helper, this does not claim that two actors or fields were joined;
// it records only that the candidate cannot enter the blocking gate.
func markResultCandidateEvidenceAmbiguous(result *Result, mode Mode, thresholds Thresholds) {
	if result == nil {
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	eligibility.EvidenceAmbiguous = true
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	removeIneligibleHardFloor(result)
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

func markResultReferentActivated(
	result *Result,
	anchorOwned bool,
	proofComplete bool,
	mode Mode,
	thresholds Thresholds,
) {
	scope := EnforcementScopeNone
	if anchorOwned && proofComplete {
		scope = EnforcementScopeCurrentUser
	}
	markResultReferentActivatedWithScope(
		result, anchorOwned && proofComplete, scope,
		anchorOwned && proofComplete, proofComplete, mode, thresholds,
	)
}

// markResultRequestLocalReferentActivated records an exact same-request
// non-user activation without ever transiently claiming current-user
// ownership. The caller must still bind the carrier identity and exact anchor;
// this helper changes only the referent relationship and request authority.
func markResultRequestLocalReferentActivated(
	result *Result,
	scope EnforcementScope,
	proofComplete bool,
	mode Mode,
	thresholds Thresholds,
) {
	if scope != EnforcementScopeRequestLocalSystem && scope != EnforcementScopeRequestLocalTool {
		scope = EnforcementScopeNone
		proofComplete = false
	}
	markResultReferentActivatedWithScope(
		result, false, scope, proofComplete, proofComplete, mode, thresholds,
	)
}

func markResultReferentActivatedWithScope(
	result *Result,
	evidenceOwnedByCurrentUser bool,
	scope EnforcementScope,
	executionProven bool,
	proofComplete bool,
	mode Mode,
	thresholds Thresholds,
) {
	if result == nil {
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	eligibility.EvidenceOwnedByCurrentUser = evidenceOwnedByCurrentUser
	eligibility.EnforcementScope = scope
	eligibility.CurrentExecutionActProven = executionProven
	eligibility.ReferentProofComplete = proofComplete
	if proofComplete {
		// The carrier may be inert, quoted, defensive, or historical on its own.
		// A separately proven current-user speech act changes only that referent
		// relationship; the harmful-core and operational predicates still come
		// from the carrier and remain independently required below.
		eligibility.CrossScopeComposition = false
		eligibility.QuotedOrAnalyticalScope = false
		eligibility.DefensiveScopeConflict = false
		if harmfulCore, operational := resultReferentSemanticCarrierProof(*result, eligibility); harmfulCore {
			eligibility.HarmfulCoreComplete = true
			eligibility.OperationallyActionable = eligibility.OperationallyActionable || operational
			if operational {
				eligibility.EvidenceAmbiguous = false
			}
		}
	} else {
		eligibility.EvidenceAmbiguous = true
	}
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if !eligibility.Eligible {
		removeIneligibleHardFloor(result)
	}
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		result.DecisionExplanation.ReferentLinkUsed = proofComplete
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

// markResultDirectCarrierActivated records the execution proof supplied by a
// current trusted-user natural-language owner for one adjacent code or
// configuration carrier. The roleless classifier intentionally cannot infer
// that ownership before profiled refs are bound, so direct-carrier callers must
// apply this proof only after annotateProfiledResult has established one exact
// same-scope candidate identity.
func markResultDirectCarrierActivated(
	result *Result,
	ownerOwned bool,
	proofComplete bool,
	mode Mode,
	thresholds Thresholds,
) {
	if result == nil {
		return
	}
	enforceResultCandidateEligibility(result, mode, thresholds)
	if result.BlockEligibility == nil {
		return
	}
	eligibility := *result.BlockEligibility
	activated := ownerOwned && proofComplete
	eligibility.EvidenceOwnedByCurrentUser = activated
	eligibility.CurrentExecutionActProven = activated
	eligibility.OperationallyActionable = eligibility.OperationallyActionable ||
		activated && eligibility.HarmfulCoreComplete
	eligibility.ReferentProofComplete = proofComplete
	if proofComplete {
		eligibility.CrossScopeComposition = false
		eligibility.QuotedOrAnalyticalScope = false
		eligibility.DefensiveScopeConflict = false
	}
	eligibility = finalizeCandidateBlockEligibility(eligibility)
	result.BlockEligibility = &eligibility
	if !eligibility.Eligible {
		removeIneligibleHardFloor(result)
	}
	result.Action = candidateActionFor(mode, result.Score, thresholds, eligibility)
	if result.DecisionExplanation != nil {
		applyEligibilityToExplanation(result.DecisionExplanation, eligibility)
	}
}

// resultReferentSemanticCarrierProof consumes only the closed, content-free
// semantic winner explanation. It lets a current execution speech act
// reactivate a carrier whose complete semantic core already proved a harmful
// outcome and multiple risk axes, without treating an ordinary descriptive
// remote-management fixture as malicious. The explicit malice axis remains a
// separate prerequisite and is never created by the referent phrase itself.
func resultReferentSemanticCarrierProof(
	result Result,
	eligibility CandidateBlockEligibility,
) (harmfulCore bool, operational bool) {
	explanation := result.DecisionExplanation
	if explanation == nil || !explanation.CorePredicateComplete || result.Category == "" ||
		explanation.WinningCategory != string(result.Category) ||
		!strings.HasPrefix(explanation.WinningRuleID, "SEMANTIC-") {
		return false, false
	}
	explicitMalice := eligibility.ExplicitVictimOrNonConsent || eligibility.CovertAcquisition ||
		eligibility.ExfiltrationOrTakeover || eligibility.MaliciousPersistence ||
		eligibility.DestructiveOutcome || eligibility.SecurityControlEvasion
	if !explicitMalice {
		return false, false
	}
	dimensions := semanticDimensionsFromMask(explanation.EvidenceDimensionMask)
	if !dimensions.object || !(dimensions.harm || dimensions.action || dimensions.outcome) {
		return false, false
	}
	riskAxes := 0
	for _, matched := range [...]bool{
		dimensions.target, dimensions.destination, dimensions.evasion,
		dimensions.scale, dimensions.sequence, dimensions.impact,
	} {
		if matched {
			riskAxes++
		}
	}
	if riskAxes < 2 {
		return false, false
	}
	// The current trusted-user referent anchor supplies the execution speech act.
	// Once the inert carrier itself proves a complete semantic behavior with two
	// independent risk axes, that relationship is operationally actionable even
	// when the quoted carrier was phrased as a noun clause rather than an
	// imperative. This does not make the carrier blockable on its own.
	return true, true
}

func removeIneligibleHardFloor(result *Result) {
	if result == nil || result.DecisionExplanation == nil {
		return
	}
	explanation := result.DecisionExplanation
	if explanation.HardFloorApplied {
		breakdown := explanation.ScoreBreakdown
		preFloor := breakdown.CorePredicateScore + breakdown.QualifierScore +
			breakdown.ScopeCoherenceScore + breakdown.OwnershipScore +
			breakdown.ActiveDirectiveScore + breakdown.ContextAdjustment +
			breakdown.ContradictionAdjustment
		preFloor = clampScore(preFloor)
		if preFloor < result.Score {
			result.Score = preFloor
		}
	}
	explanation.HardFloorApplied = false
	explanation.HardFloorReason = hardFloorReasonNone
	explanation.ScoreBreakdown.FinalScore = result.Score
}

func resultHasEligibleBlockingCandidate(result Result, thresholds Thresholds) bool {
	thresholds = validThresholdsOrDefault(thresholds)
	return !result.Truncated &&
		(result.Coverage.State == "" || result.Coverage.State == CoverageComplete) &&
		result.BlockEligibility != nil && result.BlockEligibility.Eligible &&
		result.Score >= thresholds.BalancedBlock
}

func resultIsEligibleBlockAction(result Result) bool {
	return result.Action == ActionBlock && !result.Truncated &&
		(result.Coverage.State == "" || result.Coverage.State == CoverageComplete) &&
		result.BlockEligibility != nil && result.BlockEligibility.Eligible
}

func resultHasEligibleMaliciousWinner(result Result, thresholds Thresholds) bool {
	if !resultHasEligibleBlockingCandidate(result, thresholds) || result.Category == "" ||
		len(result.RuleIDs) == 0 || result.DecisionExplanation == nil {
		return false
	}
	explanation := result.DecisionExplanation
	return explanation.BlockEligible && explanation.WinningRuleID != "" &&
		candidateEligibilityHasPositiveMaliceAxis(*result.BlockEligibility) &&
		resultContainsRuleID(result, explanation.WinningRuleID) &&
		explanation.WinningCategory == string(result.Category) &&
		explanationEligibilityMatches(explanation, *result.BlockEligibility)
}

func explanationEligibilityMatches(explanation *DecisionExplanation, eligibility CandidateBlockEligibility) bool {
	if explanation == nil {
		return false
	}
	return explanation.BlockEligible == eligibility.Eligible &&
		explanation.PrimaryEligibilityReason == eligibility.PrimaryReason &&
		explanation.EligibilityReasonFlags == eligibility.ReasonFlags&eligibilityKnownReasonFlags &&
		explanation.InspectionComplete == eligibility.InspectionComplete &&
		explanation.EvidenceOwnedByCurrentUser == eligibility.EvidenceOwnedByCurrentUser &&
		explanation.EnforcementScope == eligibility.EnforcementScope &&
		explanation.CurrentExecutionActProven == eligibility.CurrentExecutionActProven &&
		explanation.HarmfulCoreComplete == eligibility.HarmfulCoreComplete &&
		explanation.OperationallyActionable == eligibility.OperationallyActionable &&
		explanation.AuthorizationClaimState == eligibility.AuthorizationClaim &&
		explanation.ExplicitVictimOrNonConsent == eligibility.ExplicitVictimOrNonConsent &&
		explanation.CovertAcquisition == eligibility.CovertAcquisition &&
		explanation.ExfiltrationOrTakeover == eligibility.ExfiltrationOrTakeover &&
		explanation.MaliciousPersistence == eligibility.MaliciousPersistence &&
		explanation.DestructiveOutcome == eligibility.DestructiveOutcome &&
		explanation.SecurityControlEvasion == eligibility.SecurityControlEvasion &&
		explanation.DefensiveScopeConflict == eligibility.DefensiveScopeConflict &&
		explanation.QuotedOrAnalyticalScope == eligibility.QuotedOrAnalyticalScope &&
		explanation.CrossScopeComposition == eligibility.CrossScopeComposition &&
		explanation.ReferentProofComplete == eligibility.ReferentProofComplete &&
		explanation.EvidenceAmbiguous == eligibility.EvidenceAmbiguous
}

func applyEligibilityToExplanation(explanation *DecisionExplanation, eligibility CandidateBlockEligibility) {
	if explanation == nil {
		return
	}
	explanation.BlockEligible = eligibility.Eligible
	explanation.PrimaryEligibilityReason = eligibility.PrimaryReason
	explanation.EligibilityReasonFlags = eligibility.ReasonFlags & eligibilityKnownReasonFlags
	explanation.InspectionComplete = eligibility.InspectionComplete
	explanation.EvidenceOwnedByCurrentUser = eligibility.EvidenceOwnedByCurrentUser
	explanation.EnforcementScope = eligibility.EnforcementScope
	explanation.CurrentExecutionActProven = eligibility.CurrentExecutionActProven
	explanation.HarmfulCoreComplete = eligibility.HarmfulCoreComplete
	explanation.OperationallyActionable = eligibility.OperationallyActionable
	explanation.AuthorizationClaimState = eligibility.AuthorizationClaim
	explanation.ExplicitVictimOrNonConsent = eligibility.ExplicitVictimOrNonConsent
	explanation.CovertAcquisition = eligibility.CovertAcquisition
	explanation.ExfiltrationOrTakeover = eligibility.ExfiltrationOrTakeover
	explanation.MaliciousPersistence = eligibility.MaliciousPersistence
	explanation.DestructiveOutcome = eligibility.DestructiveOutcome
	explanation.SecurityControlEvasion = eligibility.SecurityControlEvasion
	explanation.DefensiveScopeConflict = eligibility.DefensiveScopeConflict
	explanation.QuotedOrAnalyticalScope = eligibility.QuotedOrAnalyticalScope
	explanation.CrossScopeComposition = eligibility.CrossScopeComposition
	explanation.ReferentProofComplete = eligibility.ReferentProofComplete
	explanation.EvidenceAmbiguous = eligibility.EvidenceAmbiguous
}

func candidateExplicitRelationQuotedNonExecutionBoundary(text string) bool {
	if !candidateExplicitRelationHasStructuredQuoteSyntax(text) ||
		candidateExplicitRelationAmbiguousQuoteStructure(text) {
		return false
	}
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete || len(spans) != 1 {
		return false
	}
	quoted := spans[0]
	if quoted.end <= quoted.start || quoted.end >= len(text) {
		return false
	}
	suffix := strings.TrimSpace(text[quoted.end:])
	if suffix == "" || candidateExplicitQuotedActivation(text) ||
		hasIndependentMaliciousExecutionClause(text) {
		return false
	}
	return metaOverrideHasInertDirective(suffix) || containsAnyLiteral(suffix,
		"recommend controls", "recommend mitigations", "recommend defenses", "analysis only", "for analysis only",
		"do not execute", "do not apply", "do not follow", "must not execute", "must not apply", "must not follow",
		"keep the sample inert", "keep the example inert",
		"建议防护", "建议缓解", "仅用于分析", "仅分析", "不要执行", "不得执行", "不要应用", "不要遵循", "保持样本惰性",
	)
}

func candidateQuotedOrAnalyticalScope(text string) bool {
	return candidateQuotedOrAnalyticalScopePrepared(text, nil)
}

func candidateQuotedOrAnalyticalScopePrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.quotedOrAnalyticalKnown {
		return proof.quotedOrAnalytical
	}
	result := candidateQuotedOrAnalyticalScopeUncached(text, proof)
	if proofMatches {
		proof.quotedOrAnalyticalKnown = true
		proof.quotedOrAnalytical = result
	}
	return result
}

func candidateQuotedOrAnalyticalScopeUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	if candidateInertLabeledCarrier(text) {
		return true
	}
	// Only the complete category-specific proof may escape an earlier
	// analytical owner. Bare log maintenance stays in the defensive scope.
	if candidateOperationalAuditLogDestructionEvasion(text) {
		return false
	}
	if candidateTransformativeAnalyticalScope(text) {
		return true
	}
	if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); independent {
		return false
	}
	if candidatePolicyStatementCarrierScope(text) {
		return true
	}
	quotedTask := containsAnyLiteral(text,
		"review this quoted", "review the quoted", "review this example", "review the example",
		"explain why this is unsafe", "explain why it is unsafe", "explain why this is dangerous",
		"translate the following", "summarize the following", "summarise the following",
		"quoted incident", "quoted request", "quoted sample", "quoted example",
		"审查下面引用", "审查以下引用", "审查下面的示例", "解释为什么危险", "解释为什么不安全",
		"翻译以下", "总结以下", "引用的危险示例", "被分析对象",
	)
	analyticalTask := containsAnyLiteral(text,
		"analyze this incident", "analyse this incident", "analyze the incident log", "analyse the incident log",
		"summarize detection gaps", "summarise detection gaps", "explain the detection gaps",
		"static analysis", "forensic analysis", "incident log", "security analysis",
		"分析这段事件日志", "分析事件日志", "总结检测缺口", "静态分析", "离线取证", "安全分析",
	) && containsAnyLiteral(text,
		"analyze", "analyse", "review", "explain", "summarize", "summarise", "detect", "mitigation",
		"分析", "审查", "解释", "总结", "检测", "修复", "缓解", "取证",
	)
	analyticalOwner := hasAnyPrefix(text,
		"analyze ", "analyse ", "review ", "explain ", "summarize ", "summarise ", "translate ",
		"分析", "审查", "解释", "总结", "翻译",
	) && !containsAnyLiteral(text,
		"working code", "complete code", "ready-to-run", "source code", "give commands", "provide commands",
		"write code", "build a tool", "implement it", "execute it", "deploy it", "operational steps",
		"可运行代码", "完整代码", "现成脚本", "提供命令", "编写代码", "构建工具", "执行它", "部署它", "操作步骤",
	)
	curationVerb := hasAnyPrefix(text, "catalog ", "list ", "organize ", "organise ") ||
		containsAnyLiteral(text, "整理", "汇总", "归纳")
	curationTask := curationVerb && containsAnyLiteral(text,
		"signals", "indicators", "symptoms", "warning signs", "patterns",
		"信号", "指标", "迹象", "征兆", "模式",
	) && !containsAnyLiteral(text,
		"working code", "ready-to-run", "execute it", "deploy it", "operational steps",
		"可运行代码", "执行它", "部署它", "操作步骤",
	)
	nonExecutionBoundary := containsAnyLiteral(text,
		"do not execute", "do not provide execution steps", "do not provide operational steps", "do not implement",
		"analysis only", "mitigations only", "safe synthetic", "synthetic test strings",
		"不要执行", "不提供执行步骤", "不要提供执行步骤", "只总结", "仅分析", "仅用于检测", "合成测试字符串",
	)
	return quotedTask || analyticalTask || analyticalOwner || curationTask ||
		candidateExplicitRelationQuotedNonExecutionBoundary(text) ||
		nonExecutionBoundary &&
			containsAnyLiteral(text, "analyze", "review", "explain", "detect", "rule", "分析", "审查", "解释", "检测", "规则")
}

// candidatePolicyStatementCarrierScope recognizes a narrow natural-language
// documentation owner for policy text that follows "stating/saying".  The
// independent-tail guard in candidateQuotedOrAnalyticalScope runs first, so a
// later "Then append/deploy ..." instruction is not laundered by the policy
// prefix.  This helper only identifies the owner relation; it does not treat a
// bare occurrence of the word "policy" as a safe allow token.
func candidatePolicyStatementCarrierScope(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	policyOwner := hasAnyPrefix(text,
		"write a safety policy ", "write the safety policy ", "draft a safety policy ", "draft the safety policy ",
		"create a safety policy ", "create the safety policy ", "prepare a safety policy ", "prepare the safety policy ",
		"write a security policy ", "write the security policy ", "draft a security policy ", "draft the security policy ",
		"create a security policy ", "create the security policy ", "prepare a security policy ", "prepare the security policy ",
		"编写安全策略", "起草安全策略", "制定安全策略", "编写安全政策", "起草安全政策", "制定安全政策",
		"编写安全规范", "起草安全规范", "制定安全规范",
	)
	if !policyOwner {
		return false
	}
	return containsAnyLiteral(text,
		" policy stating ", " policy stating that ", " policy saying ", " policy saying that ",
		" policy that states ", " policy which states ", " policy to state ",
		"策略写明", "策略规定", "策略说明", "政策写明", "政策规定", "政策说明",
		"规范写明", "规范规定", "规范说明",
	)
}

// candidateInertLabeledCarrier recognizes a whole field whose first non-empty
// line explicitly labels the remainder as recorded log/console/terminal
// output. The label owns every ordinary payload line in that field. A parser-
// proven adjacent segment or field may still reactivate the carrier through the
// established referent paths. Within the same field, only an explicit later
// transition with either a payload referent and affirmative execution act or an
// independently complete hostile directive can revoke that ownership; a
// newline by itself is never such a boundary.
func candidateInertLabeledCarrier(text string) bool {
	carrier, tailState := candidateInertLabeledCarrierExecutionTailProof(text)
	// A proof-budget overflow is still owned by the exact carrier. Callers that
	// produce a disposition inspect the tri-state helper and return a neutral
	// incomplete result; ownership-only callers must not expose the recorded
	// payload as a fresh malicious candidate while that proof is unresolved.
	return carrier && tailState != explicitMaliciousRelationMatched
}

func candidateInertLabeledCarrierExecutionTailProof(
	text string,
) (bool, explicitMaliciousRelationProofState) {
	payload, ok := candidateInertLabeledCarrierPayload(text)
	if !ok {
		return false, explicitMaliciousRelationNotMatched
	}
	return true, candidateInertLabeledCarrierExecutionTailProofFromPayload(payload)
}

func candidateInertLabeledCarrierPayload(text string) (string, bool) {
	text = strings.TrimSpace(strings.ToLower(text))
	if !candidateInertLabeledCarrierSyntax(text) {
		return "", false
	}
	lineEnd, boundaryWidth := candidateInertLabeledCarrierBoundary(text)
	if lineEnd < 0 {
		return "", false
	}
	payload := strings.TrimSpace(text[lineEnd+boundaryWidth:])
	return payload, payload != ""
}

const maxInertLabeledCarrierExecutionTailBytes = 512
const maxInertLabeledCarrierExecutionHeadBytes = 128

// candidateInertLabeledCarrierHasExecutionTail admits only a narrow same-field
// reactivation. A later physical line must explicitly transition out of the
// recorded carrier and either refer to that carrier with an affirmative
// execution act, or independently prove a complete malicious directive inside
// one strong scope. Scanning all later lines prevents an attacker from hiding
// the directive behind a final benign status line. This keeps ordinary payload
// lines, summaries, and direct prohibitions inert while preventing an exact
// label from laundering either a referential or self-contained hostile tail.
func candidateInertLabeledCarrierExecutionTailProofFromPayload(
	payload string,
) explicitMaliciousRelationProofState {
	carrierSeen := false
	proofBudgetExceeded := false
	hasNewline := strings.IndexByte(payload, '\n') >= 0
	hasHardBoundary := strings.Contains(payload, compactHardBoundaryText)
	lineStart := 0
	for lineStart <= len(payload) {
		lineEnd, width := candidateInertLabeledCarrierNextBoundary(
			payload, lineStart, hasNewline, hasHardBoundary,
		)
		if lineEnd < 0 {
			lineEnd = len(payload)
			width = 0
		}
		line := strings.TrimSpace(payload[lineStart:lineEnd])
		if line != "" {
			if carrierSeen {
				body, ok := candidateInertLabeledCarrierExecutionTailBody(line)
				if ok {
					if candidateInertLabeledCarrierTailReferencesPayload(body) {
						if hasAffirmativeQuotedReviewContinuation(body) {
							return explicitMaliciousRelationMatched
						}
					}
					switch candidateInertLabeledCarrierIndependentMaliciousTailProof(body) {
					case explicitMaliciousRelationMatched:
						return explicitMaliciousRelationMatched
					case explicitMaliciousRelationProofBudgetExceeded:
						proofBudgetExceeded = true
					}
				}
			}
			carrierSeen = true
		}
		if width == 0 {
			break
		}
		lineStart = lineEnd + width
	}
	if proofBudgetExceeded {
		return explicitMaliciousRelationProofBudgetExceeded
	}
	return explicitMaliciousRelationNotMatched
}

func candidateInertLabeledCarrierIndependentMaliciousTailProof(
	text string,
) explicitMaliciousRelationProofState {
	state := explicitMaliciousRelationNotMatched
	walkDirectiveStrongScopes(text, func(scope string) bool {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return true
		}
		executionScope := scope
		if !candidateCurrentExecutionTail(executionScope) {
			var ok bool
			executionScope, ok = independentMaliciousExecutionTail(scope)
			if !ok {
				executionScope, ok = candidateInertLabeledCarrierCoordinatedExecutionTail(scope)
			}
			if !ok {
				return true
			}
		}
		proof := newCandidatePhishingRelationProof(executionScope)
		category, proofState := candidateExplicitMaliciousRelationCategoryProof(
			executionScope, &proof,
		)
		if proofState == explicitMaliciousRelationProofBudgetExceeded {
			state = explicitMaliciousRelationProofBudgetExceeded
			return true
		}
		if proofState == explicitMaliciousRelationMatched &&
			!candidateExplicitRelationDefensiveConflictPrepared(category, executionScope, &proof) &&
			!isLegitimateCategoryWorkflow(category, executionScope) &&
			!hasAffirmativeSafetyPurpose(executionScope) {
			state = explicitMaliciousRelationMatched
			return false
		}
		return true
	})
	return state
}

func candidateInertLabeledCarrierCoordinatedExecutionTail(text string) (string, bool) {
	const connector = " and "
	for searchAt := 0; searchAt < len(text); {
		index := strings.Index(text[searchAt:], connector)
		if index < 0 {
			break
		}
		index += searchAt
		tail := strings.TrimLeftFunc(text[index+len(connector):], unicode.IsSpace)
		head := tail
		if len(head) > maxInertLabeledCarrierExecutionHeadBytes {
			head = validUTF8Prefix(head, maxInertLabeledCarrierExecutionHeadBytes)
		}
		if candidateCurrentExecutionTail(head) {
			// The full suffix is proved exactly once by the caller. Keeping this
			// admission check prefix-bounded avoids rescanning every remaining
			// connector suffix on long log/status floods.
			return tail, true
		}
		searchAt = index + len(connector)
	}
	return "", false
}

func candidateInertLabeledCarrierNextBoundary(
	text string,
	start int,
	hasNewline bool,
	hasHardBoundary bool,
) (index, width int) {
	if hasNewline && !hasHardBoundary {
		if relative := strings.IndexByte(text[start:], '\n'); relative >= 0 {
			return start + relative, 1
		}
		return -1, 0
	}
	if hasHardBoundary && !hasNewline {
		if relative := strings.Index(text[start:], compactHardBoundaryText); relative >= 0 {
			return start + relative, len(compactHardBoundaryText)
		}
		return -1, 0
	}
	nextNewline := strings.IndexByte(text[start:], '\n')
	nextHardBoundary := strings.Index(text[start:], compactHardBoundaryText)
	if nextNewline < 0 && nextHardBoundary < 0 {
		return -1, 0
	}
	if nextHardBoundary < 0 || nextNewline >= 0 && nextNewline < nextHardBoundary {
		return start + nextNewline, 1
	}
	return start + nextHardBoundary, len(compactHardBoundaryText)
}

func candidateInertLabeledCarrierExecutionTailBody(tail string) (string, bool) {
	// candidateInertLabeledCarrierPayload already supplies a lowercase view.
	// Avoid allocating another lowercase copy for every physical log line.
	tail = strings.TrimSpace(tail)
	for _, transition := range []string{"now", "then"} {
		if !strings.HasPrefix(tail, transition) || len(tail) == len(transition) {
			continue
		}
		remainder := tail[len(transition):]
		first, _ := utf8.DecodeRuneInString(remainder)
		if !unicode.IsSpace(first) && !strings.ContainsRune(",:;-\u2014\u2013", first) {
			continue
		}
		body := strings.TrimLeftFunc(remainder, func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune(",:;-\u2014\u2013", r)
		})
		body = strings.TrimSpace(body)
		return body, body != ""
	}
	return "", false
}

func candidateInertLabeledCarrierTailReferencesPayload(text string) bool {
	if containsAnyLiteral(text,
		"the quoted request", "quoted request", "the request above", "the above request",
		"the previous request", "the preceding request", "that request", "this request",
		"the quoted instruction", "quoted instruction", "the instructions above", "the above instructions",
		"the previous instructions", "the preceding instructions", "those instructions", "these instructions",
		"the quoted payload", "quoted payload", "the payload above", "the above payload",
		"the previous payload", "the preceding payload", "the payload", "that payload", "this payload",
		"the quoted output", "quoted output", "the output above", "the above output",
		"the previous output", "the preceding output", "the output", "that output", "this output",
		"上述请求", "前述请求", "前面的请求", "上面的请求", "该请求", "这个请求",
		"上述指令", "前述指令", "前面的指令", "上面的指令", "这些指令", "该指令",
		"上述载荷", "前述载荷", "前面的载荷", "上面的载荷", "该载荷", "这个载荷",
	) {
		return true
	}
	return containsASCIIWord(text, "it") || containsASCIIWord(text, "that")
}

func candidateInertLabeledCarrierBoundary(text string) (index, width int) {
	lineEnd := strings.IndexByte(text, '\n')
	boundaryWidth := 1
	if hardBoundary := strings.Index(text, compactHardBoundaryText); hardBoundary >= 0 &&
		(lineEnd < 0 || hardBoundary < lineEnd) {
		// The internal hard-boundary sentinel survives string conversion, so
		// callers must advance by its full UTF-8 width.
		lineEnd = hardBoundary
		boundaryWidth = len(compactHardBoundaryText)
	}
	if lineEnd < 0 {
		return -1, 0
	}
	return lineEnd, boundaryWidth
}

func candidateInertLabeledCarrierSyntax(text string) bool {
	text = strings.TrimSpace(strings.ToLower(text))
	if text == "" {
		return false
	}
	lineEnd, boundaryWidth := candidateInertLabeledCarrierBoundary(text)
	if lineEnd < 0 {
		return false
	}
	label := strings.TrimSpace(strings.TrimSuffix(text[:lineEnd], "\r"))
	if label == "log output" || label == "console output" || label == "terminal output" {
		return false
	}
	switch label {
	case "log output:", "console output:",
		"terminal output:", "terminal output", "日志输出：", "日志输出",
		"控制台输出：", "控制台输出", "终端输出：", "终端输出":
		return strings.TrimSpace(text[lineEnd+boundaryWidth:]) != ""
	default:
		return false
	}
}

// candidateUnclosedFencedCarrier detects only a first-line CommonMark-style
// opening fence that has no matching closing line.  Such a field has an
// incomplete content-kind proof: Balanced must fail open and Strict may use
// the separate incomplete-inspection disposition, never a malicious taxonomy.
func candidateUnclosedFencedCarrier(text string) bool {
	text = strings.TrimSpace(text)
	firstLineEnd := strings.IndexByte(text, '\n')
	if firstLineEnd < 0 {
		return false
	}
	marker, count, ok := profiledFenceMarkerLine(strings.TrimSuffix(text[:firstLineEnd], "\r"))
	if !ok {
		return false
	}
	for lineStart := firstLineEnd + 1; lineStart <= len(text); {
		lineEnd := len(text)
		if relativeEnd := strings.IndexByte(text[lineStart:], '\n'); relativeEnd >= 0 {
			lineEnd = lineStart + relativeEnd
		}
		line := text[lineStart:lineEnd]
		if profiledClosingFenceLine(strings.TrimSuffix(line, "\r"), marker, count) {
			return false
		}
		if lineEnd == len(text) {
			break
		}
		lineStart = lineEnd + 1
	}
	return true
}

// candidateTransformativeAnalyticalScope recognizes requests whose active
// speech act transforms a dangerous quoted/report payload into a bounded safe
// artifact.  The dangerous payload remains evidence for audit, but it is not
// the requested execution.  This is deliberately outcome-typed rather than a
// bare "rewrite" allow word: operational/code deliverables and independent
// execution tails still fail the guard above and remain active candidates.
func candidateTransformativeAnalyticalScope(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	transform := containsAnyLiteral(text,
		"rewrite", "rephrase", "convert", "turn the following", "turn this", "edit the following", "edit this report",
		"改写", "重写", "转换为", "转成", "整理成", "编辑这份报告", "报告改写",
	)
	if !transform {
		return false
	}
	safeOutcome := containsAnyLiteral(text,
		"compliant refusal", "policy-compliant refusal", "safe refusal", "refusal response", "refusal reply",
		"board-facing summary", "board level summary", "board-level summary", "executive summary", "leadership summary",
		"non-operational summary", "defensive summary", "incident summary", "risk summary", "mitigation summary",
		"合规拒绝", "安全拒绝", "拒绝回复", "拒绝答复", "面向董事会", "董事会摘要", "高管摘要", "管理层摘要",
		"非操作性摘要", "防御性摘要", "事件摘要", "风险摘要", "修复摘要",
	)
	if !safeOutcome {
		return false
	}
	if containsAnyLiteral(text,
		"then execute", "then deploy", "then run", "and execute it", "and deploy it", "also execute", "also deploy",
		"after that execute", "after that deploy", "but execute", "but deploy",
		"然后执行", "然后部署", "随后执行", "随后部署", "另外执行", "另外部署", "同时执行", "同时部署", "但要执行", "但要部署",
	) {
		return false
	}
	// A request for an executable artifact is not made analytical merely by
	// also naming a safe audience or format.
	return !containsAnyLiteral(text,
		"working code", "complete code", "ready-to-run", "ready to run", "source code", "give commands", "provide commands",
		"write code", "build a tool", "implement it", "execute it", "deploy it", "operational steps", "step-by-step commands",
		"可运行代码", "完整代码", "现成脚本", "源代码", "提供命令", "编写代码", "构建工具", "执行它", "部署它", "操作步骤", "逐步命令",
	)
}

func candidateDefensiveScopeConflict(category rules.Category, text string, context ContextFlags) bool {
	return candidateDefensiveScopeConflictPrepared(category, text, context, nil)
}

func candidateDefensiveScopeConflictPrepared(
	category rules.Category,
	text string,
	context ContextFlags,
	phishingProof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, phishingProof); independent {
		return false
	}
	if candidateQuotedOrAnalyticalScopePrepared(text, phishingProof) {
		return true
	}
	// Concrete safety artifacts own their dangerous examples even when those
	// examples contain strong vocabulary. A bare "defensive"/"remediation"
	// label, however, cannot launder a same-candidate explicit hostile action.
	if containsDetectionArtifact(text) || isSafetyDeliverableClause(text) {
		if candidateExplicitHostileExecution(category, text) {
			return false
		}
		return true
	}
	localDefensiveOwner := isLegitimateCategoryWorkflow(category, text) ||
		candidateCredentialLifecyclePrepared(text, phishingProof) || hasAffirmativeSafetyPurpose(text)
	contextDefensiveOwner := context.Defensive || context.Remediation || context.StaticAnalysis ||
		context.IncidentResponse || context.HighLevel
	if !localDefensiveOwner && !contextDefensiveOwner {
		// A hostile-execution proof matters here only as a contradiction to an
		// otherwise established defensive owner. Running the category-specific
		// proof on every ordinary malicious candidate repeated the complete
		// phishing relation and clause walk without changing this false result.
		return false
	}
	if candidateExplicitHostileExecution(category, text) {
		return false
	}
	return true
}

// candidateExplicitRelationDefensiveConflict is deliberately narrower than
// candidateDefensiveScopeConflict. Reaching this helper means a conjunctive,
// category-specific hostile relation has already been proved in the same
// bounded text. Ambient workflow words such as rotation, recovery, logging, or
// EDR therefore cannot own and suppress the candidate. Only a local analytical
// carrier or a concrete safety deliverable can do so; an independent malicious
// execution clause remains eligible for its own assessment.
func candidateExplicitRelationDefensiveConflict(category rules.Category, text string) bool {
	return candidateExplicitRelationDefensiveConflictPrepared(category, text, nil)
}

func candidateExplicitRelationDefensiveConflictPrepared(
	category rules.Category,
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); independent {
		return false
	}
	if category == rules.CategoryEvasion &&
		(candidateTelemetryRestorationWorkflow(text) || candidatePassiveTelemetryFailureReport(text)) {
		return true
	}
	if candidateQuotedOrAnalyticalScopePrepared(text, proof) && !candidateExplicitQuotedActivation(text) {
		return true
	}
	if containsDetectionArtifact(text) || isSafetyDeliverableClause(text) {
		if candidateExplicitHostileExecution(category, text) {
			return false
		}
		return true
	}
	if candidateExplicitRelationLocalDefensiveOwner(text) {
		// A concrete current-clause owner is stronger than ambient request context,
		// but it is not a universal allow word. Same-scope victim/non-consent,
		// takeover, malicious persistence, destructive impact, or control-evasion
		// execution still defeats the owner through the category-local predicate.
		return !candidateExplicitHostileExecution(category, text)
	}
	// Local workflow/safety language remains a real owner when the relation has
	// no explicit victim, non-consent, covert acquisition, exfiltration, or other
	// hostile scope. Conversely, those positive hostile axes prevent words such
	// as "rotation" or "incident response" from laundering the same clause.
	return !candidateExplicitMaliciousHostileScope(text) &&
		(isLegitimateCategoryWorkflow(category, text) || candidateCredentialLifecyclePrepared(text, proof) ||
			hasAffirmativeSafetyPurpose(text))
}

func candidateExplicitRelationLocalDefensiveOwner(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	return hasAnyPrefix(text,
		"for defensive ", "for defense ", "for static analysis ", "for defensive static analysis ",
		"for incident response ", "for forensic analysis ", "for malware analysis ", "for security analysis ",
		"用于防御", "用于防护", "用于静态分析", "用于事件响应", "用于应急响应", "用于取证分析", "用于安全分析",
		"为防御", "为防护", "为静态分析", "为事件响应", "为应急响应", "为取证分析", "为安全分析",
	)
}

var candidateRansomwareExecutionIntents = []string{
	"deploy", "deploys", "deploying", "deployed",
	"execute", "executes", "executing", "executed",
	"launch", "launches", "launching", "launched",
	"install", "installs", "installing", "installed",
	"spread", "spreads", "spreading",
	"部署", "执行", "投放", "安装", "传播",
}

var candidateRansomwareExecutionIntentPatterns = compileCompactRuleIntentPatterns(
	candidateRansomwareExecutionIntents,
)

func candidateDirectRansomwareExecution(text string) bool {
	if !containsAnyLiteral(text, "ransomware", "勒索软件", "勒索程序", "勒索载荷") {
		return false
	}
	if len(text) > maxCompactIntentProofBytes {
		found := false
		walkDirectiveStrongScopes(text, func(scope string) bool {
			scope = strings.TrimSpace(scope)
			if scope == "" || len(scope) > maxCompactIntentProofBytes ||
				!containsAnyLiteral(scope, "ransomware", "勒索软件", "勒索程序", "勒索载荷") {
				return true
			}
			if containsUnnegatedRuleIntentPrepared(
				scope,
				candidateRansomwareExecutionIntents,
				candidateRansomwareExecutionIntentPatterns,
			) {
				found = true
				return false
			}
			return true
		})
		return found
	}
	return containsUnnegatedRuleIntentPrepared(
		text,
		candidateRansomwareExecutionIntents,
		candidateRansomwareExecutionIntentPatterns,
	)
}

func candidateExplicitHostileExecution(category rules.Category, text string) bool {
	if category == rules.CategoryRansomware {
		destructiveData := candidateClauseLocalDestructiveDataRelation(text)
		if destructiveData.encryptOrLock || destructiveData.deleteOrWipe {
			return true
		}
	}
	if category == rules.CategoryPhishing &&
		!candidatePhishingDetectionArtifactScope(text) &&
		candidateExplicitPhishingRelation(text, false) {
		return true
	}
	if text == "" || !candidateCurrentExecutionAct(text) {
		return false
	}
	switch category {
	case rules.CategoryCredentialTheft:
		return candidateCredentialMetadataConflictCore(text) ||
			credentialSensitiveTargetAcquisition(text) ||
			candidateCredentialHostileTargetScope(text) &&
				(candidateCredentialTheftAction(text) || credentialActiveHostileAccessAction(text) ||
					candidateCredentialVictimAcquisitionAction(text))
	case rules.CategoryPhishing:
		return candidateExplicitPhishingRelation(text, false) ||
			containsAnyLiteral(text, "phishing", "fake login", "cloned login", "credential form", "钓鱼", "假登录", "仿冒登录") &&
				(candidateExplicitVictimOrNonConsent(text) || candidateCovertAcquisition(text) || candidateExfiltrationOrTakeover(text))
	case rules.CategoryRansomware:
		return candidateDirectRansomwareExecution(text) ||
			candidateDestructiveOutcome(category, text) && candidateExplicitVictimOrNonConsent(text)
	case rules.CategoryMalware:
		return candidateMaliciousPersistence(category, text) ||
			candidateExplicitMalwareRelation(text, candidateExplicitMaliciousHostileScope(text))
	case rules.CategoryEvasion:
		return candidateSecurityControlEvasion(category, text)
	case rules.CategoryDisruption:
		return candidateDestructiveOutcome(category, text) &&
			(candidateExplicitVictimOrNonConsent(text) || explicitHostileDisruptionTarget(text))
	default:
		return hasExplicitHarmConflict(text) &&
			(candidateCovertAcquisition(text) || candidateExfiltrationOrTakeover(text) ||
				candidateDestructiveOutcome(category, text))
	}
}

func candidateCredentialHostileTargetScope(text string) bool {
	return candidateExplicitVictimOrNonConsent(text) || candidateCovertAcquisition(text) ||
		candidateExfiltrationOrTakeover(text) || containsAnyLiteral(text,
		"user browser", "users' browser", "users’ browser", "employee's browser", "employees' browser",
	)
}

func candidateCredentialLifecycle(text string) bool {
	return candidateCredentialLifecyclePrepared(text, nil)
}

func candidateCredentialLifecyclePrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.credentialLifecycleKnown {
		return proof.credentialLifecycle
	}
	result := candidateCredentialLifecycleUncached(text)
	if proofMatches {
		proof.credentialLifecycleKnown = true
		proof.credentialLifecycle = result
	}
	return result
}

func candidateCredentialLifecycleUncached(text string) bool {
	purpose := containsAnyLiteral(text,
		"migration", "migrate", "import", "approved export", "backup", "recovery", "restore", "rotation", "rotate",
		"expiry", "expiration", "password manager", "secrets manager", "enterprise password manager", "oauth callback",
		"token exchange", "documented oauth", "company-managed browser", "company managed browser", "service account",
		"迁移", "导入", "批准导出", "备份", "恢复", "轮换", "过期", "密码管理器", "企业密码管理器",
		"公司管理的浏览器", "自有账户", "服务账号", "oauth 回调", "令牌交换",
	)
	if !purpose {
		return false
	}
	control := containsAnyLiteral(text,
		"approved", "company-managed", "company managed", "enterprise", "organization-owned", "company-owned",
		"our ", "my own", "user confirmation", "after user confirmation", "documented flow", "consent",
		"批准", "公司管理", "企业", "组织自有", "公司自有", "我们的", "自有", "用户确认", "明确确认", "同意",
	)
	if !control {
		return false
	}
	return !credentialMetadataHostileConflict(text) && !hasExplicitHarmConflict(text) &&
		!candidateCovertAcquisition(text) && !candidateExfiltrationOrTakeover(text)
}

func candidateAuthorizationClaim(text string, explicitVictim, covert, exfiltration bool) AuthorizationClaimState {
	claimed := candidateAuthorizationClaimPresent(text)
	if explicitVictim || hasExplicitHarmConflict(text) {
		if claimed {
			return AuthorizationConflicting
		}
		return AuthorizationAbsent
	}
	if !claimed {
		return AuthorizationAbsent
	}
	if covert || exfiltration {
		return AuthorizationConflicting
	}
	if candidateCredentialLifecycle(text) || containsAnyLiteral(text,
		"allowlist", "rate limit", "test window", "isolated lab", "owned service", "approved process",
		"白名单", "速率上限", "测试窗口", "隔离实验室", "自有服务", "批准流程",
	) {
		return AuthorizationConsistent
	}
	return AuthorizationUnverifiable
}

func candidateAuthorizationClaimPresent(text string) bool {
	return text != "" && containsAnyLiteral(text,
		"authorized", "authorised", "with permission", "we own", "we manage", "our ", "my own", "company-managed",
		"ctf", "lab", "for testing", "approved", "user confirmation", "consent",
		"已授权", "已获授权", "有授权", "授权测试", "经批准", "我们拥有", "我们管理", "我们的", "自有", "ctf", "实验室", "用于测试", "用户确认", "同意",
	)
}

func candidateExplicitVictimOrNonConsent(text string) bool {
	ownerConsentBypass := containsAnyLiteral(text,
		"bypass", "skip", "without", "prevent", "绕过", "跳过", "未经", "不经", "不要", "别做",
	) && containsAnyLiteral(text,
		"owner consent", "owner approval", "owner permission", "user consent", "user confirmation",
		"data owner", "system owner", "service owner", "file owner", "asset owner", "custodian", "two-person review",
		"所有者同意", "所有者批准", "所有者许可", "所有者审批", "用户同意", "用户确认", "数据所有者",
		"系统所有者", "服务所有者", "文件所有者", "资产所有者", "保管人", "双人复核", "审批", "批准", "许可", "确认",
	)
	return ownerConsentBypass || containsAnyLiteral(text,
		"other users", "another user", "someone else's", "third-party", "third party", "victim", "without consent",
		"without permission", "bypass consent", "without their knowledge", "without the user's knowledge",
		"another tenant", "compromised user", "compromised profile", "non-consenting", "nonconsenting",
		"another company", "another business", "another organization", "another organisation", "another person",
		"unrelated network", "unauthorized", "without authorization", "without approval", "without notice",
		"owners are locked out", "owner is locked out", "owners cannot", "owner cannot",
		"production user file",
		"stolen credential", "stolen credentials", "stolen password", "stolen passwords", "stolen session token", "stolen session tokens",
		"其他用户", "另一用户", "他人", "第三方", "受害者", "未经同意", "未经许可", "未经授权", "未经批准", "绕过同意",
		"不知情", "不属于我们", "非我方", "所有者看不到", "所有者不察觉", "用户不知情", "保管人不知情",
	)
}

func candidateCovertAcquisition(text string) bool {
	boundedStealth := lastASCIIPhraseIndex(text, "without prompting") >= 0 ||
		lastASCIIPhraseIndex(text, "without notice") >= 0 ||
		lastASCIIPhraseIndex(text, "without their knowledge") >= 0 ||
		lastASCIIPhraseIndex(text, "without the user's knowledge") >= 0
	return boundedStealth || containsAnyLiteral(text,
		"covert", "covertly", "silently collect", "silently read", "hidden harvester", "hidden collector",
		"stays covert", "stay covert", "hidden across hosts", "hidden across multiple hosts",
		"silently", "secretly", "hidden control", "hidden session", "concealed collection", "concealed access",
		"hide the collection", "hides the collection", "hiding the collection", "undetected collection", "secretly collect", "secretly collects",
		"without alerting", "without notifying", "no owner notification", "owner cannot see", "owner cannot detect",
		"隐蔽获取", "隐蔽收集", "静默收集", "静默读取", "隐藏收集", "隐藏会话", "隐藏控制", "隐蔽控制",
		"不提示用户", "不通知用户", "不触发通知", "秘密收集", "秘密采集", "秘密复制", "悄悄发送", "悄悄嵌入",
		"所有者看不到", "所有者不察觉", "不让保管人收到提示", "不告知用途", "不提醒用户",
	)
}

func candidateExfiltrationOrTakeover(text string) bool {
	return containsAnyLiteral(text,
		"exfiltrat", "send to an external server", "forward to an external server", "attacker-controlled",
		"account takeover", "take over the account", "hijack the session", "hijack session token", "hijack access token",
		"steal the session", "server i control", "host i control", "uploads them to my host", "sends them off site",
		"outside the company", "outside the investigation", "outside the case", "unauthorized recipient", "private use",
		"retain unauthorized access", "retain control", "preserve illicit access", "preserve access", "keep illicit access",
		"impersonate those accounts", "impersonate the account", "continue unauthorized access",
		"外传", "传出", "传到我控制", "发送给未经授权", "转给我", "供我私用", "攻击者控制", "我控制的位置",
		"回传到外部", "账号接管", "账户接管", "接管账号", "冒用账号", "劫持会话", "窃取会话", "我控制的服务器",
		"继续访问", "维持访问", "保留访问", "冒用这些账户",
	)
}

func candidateMaliciousPersistence(category rules.Category, text string) bool {
	if category != rules.CategoryMalware && !containsAnyLiteral(text, "malware", "backdoor", "implant", "木马", "后门", "恶意软件") {
		return false
	}
	persistence := containsAnyLiteral(text,
		"persist", "persistence", "automatic startup", "startup persistence", "survive reboot", "reconnect", "connect back",
		"survives reboot",
		"phone home", "phones home", "call back", "calls back", "command server", "c2", "backdoor", "implant",
		"持久化", "自启动", "重启后继续", "回连", "命令服务器", "后门", "植入程序",
	)
	remoteControlPersistence := containsAnyLiteral(text, "accept commands", "receive commands", "execute commands") &&
		containsAnyLiteral(text, "operator server", "off-site controller", "remote controller", "controller after each reboot") &&
		containsAnyLiteral(text, "after each reboot", "survive reboot", "survives reboot", "persistent")
	persistence = persistence || remoteControlPersistence
	hostile := hasExplicitHarmConflict(text) || candidateCovertAcquisition(text) || candidateExfiltrationOrTakeover(text) ||
		containsAnyLiteral(text, "malware", "malicious payload", "trojan", "c2 beacon", "command-and-control beacon", "command and control beacon", "恶意软件", "恶意载荷", "木马")
	return persistence && hostile
}

func candidateDestructiveOutcome(category rules.Category, text string) bool {
	destructiveData := candidateClauseLocalDestructiveDataRelation(text)
	if destructiveData.encryptOrLock || destructiveData.deleteOrWipe {
		return true
	}
	if category == rules.CategoryDisruption {
		return containsAnyLiteral(text,
			"knock offline", "take offline", "make unavailable", "make the service unavailable", "make service unavailable", "render unavailable", "stop responding", "customers cannot access",
			"users cannot access", "exhaust", "overwhelm", "flood", "ddos", "denial-of-service",
			"connection-pool storm", "connection pool storm", "request storm", "processing stops", "cannot recover", "remain locked out",
			"使其离线", "服务不可用", "停止响应", "用户无法访问", "耗尽", "压垮", "拖垮", "洪泛", "停摆", "业务中断", "拒绝服务",
		)
	}
	if category == rules.CategoryRansomware {
		// A clause-local, unnegated deployment of a named ransomware payload is
		// itself a destructive outcome proof. Keep this narrower than the old
		// bare "ransom" substring shortcut: true prohibitions remain inert, while
		// negation-reversal bait such as "do not refrain from deploying
		// ransomware" retains the positive malicious axis required by the
		// Round 9 eligibility finalizer.
		if candidateDirectRansomwareExecution(text) {
			return true
		}
		return containsAnyLiteral(text,
			"encrypt victim files", "encrypts victim files", "encrypt real victim files", "encrypts real victim files",
			"encrypt employee files", "encrypts employee files", "encrypt their files", "encrypts their files",
			"encrypt company files on victim systems", "encrypts company files on victim systems",
			"encrypt production user files", "encrypts production user files",
			"demand payment", "demands payment", "hold operational records hostage", "operations stop", "recovery remains under attacker control",
			"加密受害者文件", "加密员工文件", "加密真实用户文件", "锁住业务文件", "加密关键资料", "加密真实资料",
			"删除备份", "删除还原点", "索要付款", "索款", "赎金威胁", "勒索",
		)
	}
	return containsAnyLiteral(text,
		"destroy data", "wipe data", "delete evidence", "cause an outage", "disrupt production",
		"破坏数据", "擦除数据", "删除证据", "造成中断", "中断生产",
	)
}

var candidateAuditLogDestructionIntents = []string{
	"clear", "clears", "clearing",
	"delete", "deletes", "deleting",
	"erase", "erases", "erasing",
	"destroy", "destroys", "destroying",
	"purge", "purges", "purging",
	"清除", "清空", "删除", "擦除", "销毁",
}

var candidateAuditLogDestructionIntentPatterns = compileCompactRuleIntentPatterns(
	candidateAuditLogDestructionIntents,
)

// candidateOperationalAuditLogDestructionEvasion proves the narrow log-
// destruction core used by EVADE-003. A log-maintenance verb is not enough:
// the same bounded execution scope must contain a security/audit-log object,
// an explicit post-intrusion concealment purpose, and an operational artifact.
// Keeping these axes conjunctive prevents ordinary rotation, retention-policy
// cleanup, fixture cleanup, and incident-response restoration from acquiring
// malicious-text block eligibility.
func candidateOperationalAuditLogDestructionEvasion(text string) bool {
	text = strings.TrimSpace(text)
	// This predicate is consulted by several generic eligibility paths. Keep the
	// overwhelmingly common non-log request allocation-free and avoid invoking
	// the clause walker until every coarse axis is present.
	if text == "" ||
		!containsAnyLiteral(text,
			"audit log", "audit-log", "security log", "security-log", "system log", "system-log", "forensic log", "forensic-log",
			"审计日志", "安全日志", "系统日志", "取证日志",
		) ||
		!containsAnyLiteral(text,
			"working code", "ready-to-run", "ready to run", "commands", "script", "utility", "program",
			"可直接运行", "可运行代码", "命令", "脚本", "工具", "完整程序",
		) ||
		!containsAnyLiteral(text,
			"after intrusion", "after an intrusion", "after the intrusion",
			"hide intrusion", "hide an intrusion", "hide the intrusion", "cover up the intrusion",
			"destroy evidence", "erase traces", "cover tracks", "avoid detection", "harder to spot",
			"入侵后", "掩盖入侵", "销毁证据", "擦除痕迹", "躲避检测", "避免告警",
		) {
		return false
	}
	text = strings.ToLower(text)
	if !containsAnyLiteral(text, candidateAuditLogDestructionIntents...) {
		return false
	}
	matched := false
	overflow := false
	clauseCount := 0
	walkDirectiveClauses([]rune(text), func(clause []rune) bool {
		clauseCount++
		if clauseCount > maxAnalyzedDirectiveClauses {
			overflow = true
			return false
		}
		if candidateOperationalAuditLogDestructionClause(string(clause)) {
			matched = true
			return false
		}
		return true
	})
	return matched && !overflow
}

func candidateOperationalAuditLogDestructionClause(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if !candidateAuditLogDestructionSpeechAct(text) ||
		!containsAnyLiteral(text,
			"audit log", "audit-log", "security log", "security-log", "system log", "system-log", "forensic log", "forensic-log",
			"审计日志", "安全日志", "系统日志", "取证日志",
		) ||
		!candidateAuditLogDestructionMaliciousPurpose(text) ||
		!containsAnyLiteral(text,
			"working code", "ready-to-run", "ready to run", "commands", "script", "utility", "program",
			"可直接运行", "可运行代码", "命令", "脚本", "工具", "完整程序",
		) {
		return false
	}
	proof := candidateRuleIntentClauseProofPrepared(
		text, candidateAuditLogDestructionIntents, candidateAuditLogDestructionIntentPatterns,
	)
	return !proof.overflow && proof.active
}

func candidateAuditLogDestructionSpeechAct(text string) bool {
	text = strings.TrimSpace(text)
	if startsWithRuleIntent(text, candidateAuditLogDestructionIntents) {
		return true
	}
	if !hasOperationalDeliverableFraming(text) {
		return false
	}
	return containsAnyLiteral(text,
		"code to clear", "code to delete", "code to erase", "code to destroy", "code to purge",
		"script to clear", "script to delete", "script to erase", "script to destroy", "script to purge",
		"commands to clear", "commands to delete", "commands to erase", "commands to destroy", "commands to purge",
		"utility to clear", "utility to delete", "utility to erase", "utility to destroy", "utility to purge",
		"program to clear", "program to delete", "program to erase", "program to destroy", "program to purge",
		"tool to clear", "tool to delete", "tool to erase", "tool to destroy", "tool to purge",
		"code that clears", "code that deletes", "code that erases", "code that destroys", "code that purges",
		"script that clears", "script that deletes", "script that erases", "script that destroys", "script that purges",
		"用于清除", "用于清空", "用于删除", "用于擦除", "用于销毁", "来清除", "来清空", "来删除", "来擦除", "来销毁",
	)
}

func candidateAuditLogDestructionMaliciousPurpose(text string) bool {
	if containsAnyLiteral(text,
		"hide intrusion", "hide an intrusion", "hide the intrusion", "cover up the intrusion",
		"destroy evidence", "erase traces", "cover tracks", "avoid detection", "harder to spot",
		"掩盖入侵", "销毁证据", "擦除痕迹", "躲避检测", "避免告警",
	) {
		return true
	}
	if candidateAuditLogDefensiveWorkflowScope(text) {
		return false
	}
	return containsAnyLiteral(text,
		"after intrusion", "after an intrusion", "after the intrusion", "入侵后",
	)
}

func candidateAuditLogDefensiveWorkflowScope(text string) bool {
	if hasExplicitHarmConflict(text) {
		return false
	}
	if containsDetectionArtifact(text) || isSafetyDeliverableClause(text) || hasAffirmativeSafetyPurpose(text) {
		return true
	}
	fixture := containsAnyLiteral(text,
		"synthetic audit log", "synthetic security log", "synthetic system log", "synthetic forensic log",
		"audit-log fixture", "security-log fixture", "log fixture", "test fixture",
		"合成审计日志", "合成安全日志", "日志测试夹具", "测试日志夹具",
	)
	testScope := containsAnyLiteral(text,
		"parser test", "unit test", "test assertion", "test assertions", "after assertions",
		"intrusion simulation", "intrusion-simulation", "simulation assertion", "test harness",
		"解析器测试", "单元测试", "测试断言", "入侵模拟", "测试框架",
	)
	if fixture && testScope {
		return true
	}
	return containsAnyLiteral(text,
		"retention policy", "approved retention", "expired logs", "log rotation", "rotate audit logs",
		"immutable copies", "immutable backups", "restore deleted logs", "restore audit logs",
		"incident response", "forensic recovery", "evidence preservation", "preserve evidence",
		"留存策略", "批准的留存", "过期日志", "日志轮换", "不可变副本", "不可变备份",
		"恢复审计日志", "事件响应", "取证恢复", "证据保全", "保留证据",
	)
}

func candidateSecurityControlEvasion(category rules.Category, text string) bool {
	if category != rules.CategoryEvasion && !containsAnyLiteral(text, "bypass edr", "evade detection", "绕过 edr", "规避检测") {
		return false
	}
	if candidateSecurityControlDetectionReferenceScope(text) {
		return false
	}
	if candidateOperationalAuditLogDestructionEvasion(text) {
		return true
	}
	if !candidateSecurityControlEvasionMechanism(text) {
		return false
	}
	return candidateSecurityControlEvasionMaliciousPurpose(text)
}

// candidateSecurityControlEvasionMaliciousPurpose is kept separate from the
// control/evasion mechanism so adjacent physical clauses can own distinct
// dimensions without borrowing request-global evidence.
func candidateSecurityControlEvasionMaliciousPurpose(text string) bool {
	return containsAnyLiteral(text,
		"malware", "malicious payload", "implant", "backdoor", "hide the intrusion", "hide an intrusion", "conceal the intrusion", "conceal an intrusion",
		"malicious intrusion", "keep the intrusion hidden", "intrusion remains hidden", "intrusion stays hidden",
		"intrusion remains undetected", "intrusion stays undetected", "credential theft", "exfiltrat",
		"unauthorized access", "unauthorized control", "covert access", "persistent access", "continuing access", "ongoing access", "theft",
		"恶意软件", "恶意载荷", "植入程序", "后门", "入侵", "凭证窃取", "外传", "未授权访问", "未授权控制", "秘密访问", "持续访问", "窃取",
	) || hasExplicitHarmConflict(text)
}

var candidateSecurityControlBlindIntents = []string{"致盲"}

var candidateSecurityControlBlindIntentPatterns = compileCompactRuleIntentPatterns(
	candidateSecurityControlBlindIntents,
)

// candidateSecurityControlEvasionMechanism is the dimension-local half of the
// full evasion axis. A bounded multi-clause candidate may own the malicious
// purpose in one physical clause and the control+evasion mechanism in the next;
// the binder must still locate the mechanism without inventing either half.
func candidateSecurityControlEvasionMechanism(text string) bool {
	if candidateSecurityControlDetectionReferenceScope(text) {
		return false
	}
	if candidateOperationalAuditLogDestructionEvasion(text) {
		return true
	}
	control := containsAnyLiteral(text, candidateSecurityControlEvasionTargetTerms...) || containsAnyLiteral(text,
		"edr", "antivirus", "endpoint defense", "endpoint protection", "endpoint-protection", "endpoint analytics", "scheduled-task analytics",
		"audit forwarding", "intrusion alert", "security control", "security telemetry", "security monitoring", "monitoring", "detection", "sandbox", "siem", "ioc",
		"protection record", "protection records", "security record", "security records", "signature scanner", "signature scanners",
		"安全控制", "安全遥测", "安全监控", "检测", "防护", "防护记录", "安全记录", "杀毒", "沙箱",
	)
	evasionState := containsAnyLiteral(text,
		"bypass", "evade", "avoid detection", "disable", "suppress", "conceal", "undetected", "stays undetected", "stay undetected",
		"cannot detect", "cannot identify", "hide", "hidden", "miss it", "obfuscate", "no longer trigger", "stops triggering", "prevent detection",
		"绕过", "规避", "躲避检测", "躲开", "避开", "禁用", "关闭", "隐藏", "压制", "不被检测", "不再触发", "混淆",
	)
	evasion := candidateSecurityControlActiveEvasion(text) ||
		!containsDetectionArtifact(text) && !candidateSecurityControlDetectionReferenceScope(text) &&
			evasionState && candidateExplicitMaliciousRelationAction(text) ||
		candidateSecurityControlBlindMechanism(text)
	return control && evasion
}

func candidateSecurityControlBlindMechanism(text string) bool {
	if !strings.Contains(text, "致盲") {
		return false
	}
	blind := candidateRuleIntentClauseProofPrepared(
		text, candidateSecurityControlBlindIntents, candidateSecurityControlBlindIntentPatterns,
	)
	if blind.overflow || !blind.active {
		return false
	}
	execution := candidateRuleIntentClauseProofPrepared(
		text, candidatePermissionScopedIntents, candidatePermissionScopedIntentPatterns,
	)
	return !execution.overflow && (!execution.found || !execution.allNegated)
}

func candidateCategoryHasExplicitMalice(
	category rules.Category,
	ruleID string,
	text string,
	explicitVictim, covert, exfiltration, persistence, destructive, evasion bool,
	credentialReactivation, evasionReactivation bool,
) bool {
	switch category {
	case rules.CategoryCredentialTheft:
		return credentialMetadataHostileConflict(text) || credentialSensitiveTargetAcquisition(text) ||
			(candidateCredentialTheftAction(text) || credentialActiveHostileAccessAction(text) ||
				candidateCredentialVictimAcquisitionAction(text)) &&
				(explicitVictim || covert || exfiltration || credentialExplicitHostileScope(text) ||
					credentialReactivation && credentialActiveSecretMaterial(text))
	case rules.CategoryEvasion:
		return evasion || evasionReactivation
	case rules.CategoryMalware:
		return persistence || containsAnyLiteral(text,
			"deploy malware", "install malware", "execute malware", "launch the malicious payload", "deploy the backdoor",
			"部署恶意软件", "安装恶意软件", "执行恶意软件", "投放恶意载荷", "部署后门",
		)
	case rules.CategoryDisruption:
		return destructive && (explicitVictim || explicitHostileDisruptionTarget(text) || containsAnyLiteral(text,
			"competitor", "third-party service", "production users", "real customers", "竞争对手", "第三方服务", "生产用户", "真实客户",
		))
	case rules.CategoryPhishing:
		return candidatePhishingDeceptionSurface(text) &&
			(explicitVictim || covert || exfiltration)
	case rules.CategoryRansomware:
		directExecution := containsAnyLiteral(text, "deploy", "execute", "spread", "encrypt", "部署", "执行", "传播", "加密")
		construction := explicitVictim && containsAnyLiteral(text, "ransomware", "勒索软件", "勒索载荷") &&
			containsAnyLiteral(text,
				"write", "build", "create", "develop", "produce", "generate", "ready-to-run", "ready to run", "working",
				"编写", "构建", "创建", "开发", "生成", "可运行", "现成",
			)
		return candidateDirectRansomwareExecution(text) || destructive && (directExecution || construction)
	case rules.CategoryExfiltration:
		// A same-candidate covert acquisition request against an explicit victim is
		// already a complete hostile collection core even when the requester omits
		// the eventual receiver. Current execution and operational actionability are
		// still independent eligibility gates, so defensive descriptions and inert
		// references cannot become blockable through this predicate alone.
		return (exfiltration || covert) && (explicitVictim || hasExplicitHarmConflict(text))
	case rules.CategoryExploitation:
		return containsAnyLiteral(text, "exploit", "weaponize", "gain unauthorized access", "利用漏洞", "武器化", "未授权访问") &&
			(explicitVictim || hasExplicitHarmConflict(text) || containsAnyLiteral(text, "real target", "production target", "真实目标", "生产目标"))
	default:
		if ruleID == metaOverrideRuleID {
			return containsAnyLiteral(text,
				"append these instructions", "replace model_instructions_file", "persist this override", "ignore system instructions",
				"把这些指令追加", "替换模型指令文件", "持续生效", "忽略系统指令",
			) && !candidateQuotedOrAnalyticalScope(text)
		}
		return explicitVictim && (covert || exfiltration || destructive || evasion)
	}
}

// adjacentNegationReversalExplicitMalice consumes the already-proven active
// intent relation from the previous field and asks only whether the joined,
// same-scope candidate has a category-specific hostile object or outcome. It
// deliberately does not equate a security-control noun with malice: "disable
// EDR on employee endpoints" remains auditable unless malware/evasion purpose
// is independently present.
func adjacentNegationReversalExplicitMalice(category rules.Category, text string) bool {
	explicitVictim := hasExplicitHarmConflict(text) || candidateExplicitVictimOrNonConsent(text)
	covert := candidateCovertAcquisition(text)
	exfiltration := candidateExfiltrationOrTakeover(text)
	switch category {
	case rules.CategoryCredentialTheft:
		return credentialActiveSecretMaterial(text) &&
			(explicitVictim || covert || exfiltration || credentialExplicitHostileScope(text))
	case rules.CategoryRansomware:
		return containsAnyLiteral(text, "ransomware", "勒索软件", "勒索程序", "勒索载荷") ||
			candidateDestructiveOutcome(category, text) && explicitVictim
	case rules.CategoryPhishing:
		return candidatePhishingDeceptionSurface(text) &&
			(explicitVictim || covert || exfiltration)
	case rules.CategoryMalware:
		return candidateMaliciousPersistence(category, text) ||
			containsAnyLiteral(text, "malware", "keylogger", "backdoor", "implant", "trojan", "恶意软件", "键盘记录器", "后门", "植入程序") &&
				(explicitVictim || covert || exfiltration)
	case rules.CategoryEvasion:
		return candidateSecurityControlEvasion(category, text)
	case rules.CategoryDisruption:
		return candidateDestructiveOutcome(category, text) &&
			(explicitVictim || explicitHostileDisruptionTarget(text))
	case rules.CategoryExfiltration:
		return (explicitVictim || hasExplicitHarmConflict(text)) && (covert || exfiltration)
	case rules.CategoryExploitation:
		return containsAnyLiteral(text, "exploit", "weaponize", "gain unauthorized access", "利用漏洞", "武器化", "未授权访问") &&
			(explicitVictim || containsAnyLiteral(text, "real target", "production target", "真实目标", "生产目标"))
	default:
		return false
	}
}

// candidateCredentialMetadataConflictCore preserves the existing typed proof
// for a deceptive metadata-only wrapper without turning every terse theft verb
// into explicit malice. The hostile relation must already be proven by the
// credential matcher, and the same clause must also carry the metadata/test
// fixture cover story (or the established required-secret double negation).
func candidateCredentialMetadataConflictCore(text string) bool {
	if !credentialMetadataHostileConflict(text) {
		return false
	}
	return credentialRequiredSecretAccess(text) || containsAnyLiteral(text,
		"credential metadata", "credentials metadata", "metadata only", "inventory metadata",
		"internal inventory", "test fixture", "secret values", "without reading secret",
	)
}

// candidateCredentialTheftAction admits a compact, clearly active theft verb
// only when the same candidate also contains active secret material. The
// hostile victim/destination requirement remains in the category predicate,
// so a compact verb alone cannot make an ordinary credential workflow eligible.
func candidateCredentialTheftAction(text string) bool {
	if explicitCredentialTheftAction(text) {
		return true
	}
	return credentialActiveSecretMaterial(text) && containsUnnegatedRuleIntentPrepared(
		text,
		credentialExplicitTheftIntents,
		credentialExplicitTheftIntentPatterns,
	)
}

var candidateExfiltrationCopyIntents = []string{
	"copy", "copies", "copying", "copied",
	"transfer", "transfers", "transferring", "transferred",
}

var candidateExfiltrationCopyIntentPatterns = compileCompactRuleIntentPatterns(candidateExfiltrationCopyIntents)

// candidateExplicitExfiltrationCopyAction is deliberately conjunctive. "Copy"
// remains a normal business verb unless the same candidate proves both a real
// victim/non-consent scope and an attacker/external exfiltration destination.
func candidateExplicitExfiltrationCopyAction(text string, explicitVictim, exfiltration bool) bool {
	if !explicitVictim || !exfiltration || candidatePermissionOnlyScope(text) {
		return false
	}
	return containsUnnegatedRuleIntentPrepared(
		text,
		candidateExfiltrationCopyIntents,
		candidateExfiltrationCopyIntentPatterns,
	)
}

var candidateSecurityControlReactivationIntents = []string{
	"disable", "disables", "disabling", "disabled",
	"bypass", "bypasses", "bypassing", "bypassed",
	"evade", "evades", "evading", "evaded",
	"禁用", "绕过", "规避",
}

var candidateSecurityControlReactivationIntentPatterns = compileCompactRuleIntentPatterns(
	candidateSecurityControlReactivationIntents,
)

func candidateSecurityControlTarget(text string) bool {
	return containsAnyLiteral(text,
		"edr", "antivirus", "security control", "security telemetry", "detection", "sandbox", "siem",
		"安全控制", "安全遥测", "检测", "杀毒", "沙箱",
	)
}

var candidatePermissionScopedIntents = []string{
	"create", "creates", "creating", "created",
	"release", "releases", "releasing", "released",
	"deploy", "deploys", "deploying", "deployed",
	"steal", "steals", "stealing", "stole", "stolen",
	"disable", "disables", "disabling", "disabled",
	"copy", "copies", "copying", "copied",
	"execute", "executes", "executing", "executed",
	"install", "installs", "installing", "installed",
	"spread", "spreads", "spreading",
	"dump", "dumps", "dumping", "dumped",
	"harvest", "harvests", "harvesting", "harvested",
	"exfiltrate", "exfiltrates", "exfiltrating", "exfiltrated",
	"创建", "制作", "发布", "释放",
	"部署", "窃取", "盗取", "禁用", "复制", "执行", "安装", "传播", "转储", "收集", "外传",
}

var candidatePermissionScopedIntentPatterns = compileCompactRuleIntentPatterns(candidatePermissionScopedIntents)

type candidateRuleIntentOccurrence struct {
	start  int
	end    int
	intent string
}

type candidateRuleIntentClauseProof struct {
	found          bool
	active         bool
	allNegated     bool
	permissionOnly bool
	reactivated    bool
	overflow       bool
}

// candidateRuleIntentClauseProofPrepared provides the bounded state that the
// eligibility gate needs without changing the historical low-level
// fail-active matcher contract. In particular it distinguishes a proven later
// active occurrence from a permission-only negated prohibition and from proof
// overflow.
func candidateRuleIntentClauseProofPrepared(
	clause string,
	intents []string,
	patterns compactRuleIntentPatterns,
) candidateRuleIntentClauseProof {
	compactScratch := acquireCompactRuleIntentClauseScratch()
	proof := candidateRuleIntentClauseProofPreparedWithScratch(clause, intents, patterns, compactScratch)
	releaseCompactRuleIntentClauseScratch(compactScratch)
	return proof
}

func candidateRuleIntentClauseProofPreparedWithScratch(
	clause string,
	intents []string,
	patterns compactRuleIntentPatterns,
	compactScratch *compactRuleIntentClauseScratch,
) candidateRuleIntentClauseProof {
	clause = normalizeNegationSyntax(strings.ToLower(strings.TrimSpace(clause)))
	if clause == "" {
		return candidateRuleIntentClauseProof{}
	}
	if len(clause) > maxCompactIntentProofBytes {
		return candidateRuleIntentClauseProof{overflow: true}
	}

	var occurrences [maxRuleIntentOccurrences]candidateRuleIntentOccurrence
	var literalSpans [maxRuleIntentOccurrences]ruleIntentLiteralSpan
	occurrenceCount := 0
	for _, intent := range intents {
		if intent == "" || len(intent) > len(clause) {
			continue
		}
		for offset := 0; offset <= len(clause)-len(intent); {
			index := strings.Index(clause[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(intent)
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(clause[index-1])
			rightOK := !isASCIIStringLocal(intent) || end == len(clause) || !isASCIIWordByte(clause[end])
			if leftOK && rightOK {
				duplicate := false
				for proofIndex := 0; proofIndex < occurrenceCount; proofIndex++ {
					if occurrences[proofIndex].start == index && occurrences[proofIndex].end == end {
						duplicate = true
						break
					}
				}
				if !duplicate {
					if occurrenceCount == len(occurrences) {
						return candidateRuleIntentClauseProof{overflow: true}
					}
					occurrences[occurrenceCount] = candidateRuleIntentOccurrence{start: index, end: end, intent: intent}
					literalSpans[occurrenceCount] = ruleIntentLiteralSpan{start: index, end: end}
					occurrenceCount++
				}
			}
			offset = index + 1
		}
	}

	if occurrenceCount > 1 {
		sort.Slice(occurrences[:occurrenceCount], func(left, right int) bool {
			if occurrences[left].start != occurrences[right].start {
				return occurrences[left].start < occurrences[right].start
			}
			return occurrences[left].end > occurrences[right].end
		})
		sort.Slice(literalSpans[:occurrenceCount], func(left, right int) bool {
			if literalSpans[left].start != literalSpans[right].start {
				return literalSpans[left].start < literalSpans[right].start
			}
			return literalSpans[left].end > literalSpans[right].end
		})
	}

	proof := candidateRuleIntentClauseProof{found: occurrenceCount != 0}
	sawNegated := false
	sawPermissionOnly := false
	for occurrenceIndex := 0; occurrenceIndex < occurrenceCount; occurrenceIndex++ {
		occurrence := occurrences[occurrenceIndex]
		foundNegation, negated := ruleIntentOccurrenceNegation(clause, occurrence.start)
		if foundNegation && !negated && coordinatedRuleIntentNegation(
			clause, occurrence.start, occurrence.intent, intents,
		) {
			negated = true
		}
		if ruleIntentOccurrencePermissionOnly(clause, occurrence.start) {
			sawPermissionOnly = true
			continue
		}
		if foundNegation && negated {
			sawNegated = true
			continue
		}
		proof.active = true
		if sawNegated {
			proof.reactivated = true
		}
	}

	if compactScratch == nil {
		compactScratch = new(compactRuleIntentClauseScratch)
	}
	compactScratch.reset()
	if compactRuleIntentOutsideLiteralSpansPrepared(
		clause, patterns, literalSpans[:occurrenceCount], compactScratch,
	) {
		proof.found = true
		proof.active = true
		if sawNegated {
			proof.reactivated = true
		}
	}
	proof.allNegated = proof.found && sawNegated && !proof.active && !sawPermissionOnly
	proof.permissionOnly = proof.found && sawPermissionOnly && !proof.active && !sawNegated
	return proof
}

// candidateRuleIntentReactivated proves only a local same-family reversal: a
// negated occurrence followed by an explicit active occurrence in the same or
// immediately adjacent directive clause. A lone active verb, a lone permission
// statement, and any bounded-proof overflow all return false.
func candidateRuleIntentReactivated(text string, intents []string, patterns compactRuleIntentPatterns) bool {
	if text == "" || len(text) > maxCompactIntentProofBytes {
		return false
	}
	if !stringMayContainNegation(text) {
		// Reactivation requires a preceding negated occurrence by definition.
		// Avoid constructing compact clause-position tables for the overwhelmingly
		// common affirmative request, especially when several candidate categories
		// reuse the same bounded text.
		return false
	}
	textRunes := []rune(text)
	previousAllNegated := false
	clauseCount := 0
	reactivated := false
	walkDirectiveClauses(textRunes, func(clause []rune) bool {
		clauseCount++
		if clauseCount > maxAnalyzedDirectiveClauses {
			return false
		}
		proof := candidateRuleIntentClauseProofPrepared(string(clause), intents, patterns)
		if proof.overflow {
			return false
		}
		if proof.reactivated || previousAllNegated && proof.active {
			reactivated = true
			return false
		}
		previousAllNegated = proof.allNegated
		return true
	})
	return reactivated
}

// candidatePermissionOnlyScope recognizes a complete sequence of permission
// statements without treating "permission" as authorization or as an active
// execution request. It intentionally scans all clauses so a repeated
// permission-only flood remains non-blocking; each clause proof is fixed-size
// and any ambiguous/overflowing clause fails this credit.
func candidatePermissionOnlyScope(text string) bool {
	if text == "" || !containsAnyLiteral(text,
		"forbid", "forbidden", "prohibit", "prohibited", "禁止", "严禁", "拒绝",
	) {
		return false
	}
	foundPermission := false
	permissionOnly := true
	walkDirectiveClauses([]rune(text), func(clause []rune) bool {
		clauseText := string(clause)
		proof := candidateRuleIntentClauseProofPrepared(
			clauseText, candidatePermissionScopedIntents, candidatePermissionScopedIntentPatterns,
		)
		if !proof.found {
			return true
		}
		if proof.overflow || !candidatePermissionDominatedClauseWithScratch(clauseText, nil) {
			permissionOnly = false
			return false
		}
		foundPermission = true
		return true
	})
	return foundPermission && permissionOnly
}

// candidatePermissionDominatesCategory keeps permission ownership local to
// the candidate being assessed. In a mixed physical sentence the independent
// suffix may be malicious, but it cannot reactivate a different category from
// the permission prefix (for example permitted credential theft followed by
// independent malware creation).
func candidatePermissionDominatesCategory(text string, category rules.Category) bool {
	if text == "" || category == "" {
		return false
	}
	tail, ok := candidatePermissionIndependentMaliciousTail(text)
	if !ok {
		return false
	}
	tailCategory, complete := candidateExplicitMaliciousRelationCategory(tail)
	return complete && tailCategory != category
}

func candidatePermissionIndependentMaliciousTail(text string) (string, bool) {
	for _, boundary := range []string{
		" and independently ", " but independently ", " and separately ",
		" and then ", ", then ", "; then ",
	} {
		index := strings.LastIndex(text, boundary)
		if index < 0 {
			continue
		}
		prefix := strings.TrimSpace(text[:index])
		tail := strings.TrimSpace(text[index+len(boundary):])
		prefixProof := candidateRuleIntentClauseProofPrepared(
			prefix, candidatePermissionScopedIntents, candidatePermissionScopedIntentPatterns,
		)
		if !prefixProof.overflow && prefixProof.permissionOnly &&
			candidateCurrentExecutionTail(tail) && candidateTailHasHarmfulObject(tail) {
			return tail, true
		}
	}
	return "", false
}

func ruleIntentOccurrencePermissionOnly(clause string, intentIndex int) bool {
	if intentIndex <= 0 || intentIndex > len(clause) {
		return false
	}
	prefixStart := 0
	if intentIndex > maxRuleIntentLookbackBytes {
		prefixStart = intentIndex - maxRuleIntentLookbackBytes
		for prefixStart < intentIndex && clause[prefixStart]&0xc0 == 0x80 {
			prefixStart++
		}
	}
	prefix := strings.TrimSpace(clause[prefixStart:intentIndex])
	closest := -1
	closestMarker := ""
	for _, marker := range []string{
		"forbidden to", "prohibited from", "forbids", "forbid", "prohibits", "prohibit",
		"严禁", "禁止", "拒绝",
	} {
		var index int
		if isASCIIStringLocal(marker) {
			index = lastASCIIPhraseIndex(prefix, marker)
		} else {
			index = strings.LastIndex(prefix, marker)
		}
		if index >= 0 && (index > closest || index == closest && len(marker) > len(closestMarker)) {
			closest = index
			closestMarker = marker
		}
	}
	if closest < 0 || !prohibitionMarkerIsNegated(prefix[:closest], closestMarker) {
		return false
	}
	between := strings.TrimSpace(prefix[closest+len(closestMarker):])
	return between == "" || prohibitionNegationBridge(between)
}

var candidateCredentialVictimAcquisitionIntents = []string{
	"obtain", "obtains", "obtaining",
	"recover", "recovers", "recovering",
	"take", "takes", "taking",
	"export", "exports", "exporting", "exported",
}

var candidateCredentialVictimAcquisitionIntentPatterns = compileCompactRuleIntentPatterns(
	candidateCredentialVictimAcquisitionIntents,
)

// candidateCredentialVictimAcquisitionAction covers verbs that are legitimate
// in first-party credential lifecycles but become an explicit acquisition act
// when the same candidate also proves victim/non-consent, covert collection, or
// takeover scope. The hostile-scope requirement is applied by the category
// predicate above; this helper deliberately proves only the active secret
// acquisition relation and cannot make an ordinary OAuth/recovery request
// eligible by itself.
func candidateCredentialVictimAcquisitionAction(text string) bool {
	if !credentialActiveSecretMaterial(text) {
		return false
	}
	return containsUnnegatedRuleIntentPrepared(
		text,
		candidateCredentialVictimAcquisitionIntents,
		candidateCredentialVictimAcquisitionIntentPatterns,
	) || containsAnyLiteral(text, "获取", "取得", "拿取", "恢复")
}

func candidateCurrentExecutionAct(text string) bool {
	return candidateCurrentExecutionActPrepared(text, nil)
}

func candidateCurrentExecutionActPrepared(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	proofMatches := proof != nil && proof.text == text
	if proofMatches && proof.currentExecutionActKnown {
		return proof.currentExecutionAct
	}
	result := candidateCurrentExecutionActUncached(text, proof)
	if proofMatches {
		proof.currentExecutionActKnown = true
		proof.currentExecutionAct = result
	}
	return result
}

func candidateCurrentExecutionActUncached(
	text string,
	proof *candidatePhishingRelationProof,
) bool {
	if text == "" {
		return false
	}
	if _, independent := candidatePhishingIndependentMaliciousExecutionTailPrepared(text, proof); independent {
		return true
	}
	if candidateOperationalAuditLogDestructionEvasion(text) {
		return true
	}
	if candidateQuotedOrAnalyticalScopePrepared(text, proof) ||
		candidateCredentialLifecyclePrepared(text, proof) {
		return false
	}
	return containsAnyLiteral(text,
		"create", "build", "write", "implement", "provide", "produce", "design", "generate", "obtain", "recover", "take", "transfer", "export", "deploy", "execute", "install", "launch", "run", "place", "steal", "dump", "harvest",
		"capture", "collect", "gather", "extract", "send", "exfiltrate", "bypass", "evade", "disable", "flood", "overload", "take over",
		"stop", "suspend", "erase", "delete", "clear", "silence", "mute", "unhook", "tamper", "turn off", "shut down", "blind", "neutralize",
		"forward", "route", "relay", "intercept",
		"encrypt", "制作", "创建", "编写", "实现", "导出", "部署", "执行", "安装", "运行", "放置", "窃取", "转储", "收集", "提取", "外传", "回传", "加密",
		"绕过", "规避", "禁用", "洪泛", "压垮", "接管",
	)
}

func candidateOperationallyActionable(category rules.Category, text string) bool {
	return candidateOperationallyActionablePrepared(category, text, nil)
}

func candidateOperationallyActionablePrepared(
	category rules.Category,
	text string,
	phishingProof *candidatePhishingRelationProof,
) bool {
	if category == rules.CategoryPhishing {
		return candidatePhishingCurrentCredentialInteractionSpeechActPrepared(text, phishingProof)
	}
	if category == rules.CategoryEvasion && candidateSecurityControlDetectionReferenceScope(text) {
		return false
	}
	if !candidateCurrentExecutionActPrepared(text, phishingProof) {
		return false
	}
	if containsAnyLiteral(text,
		"code", "source", "source code", "software", "script", "tool", "utility", "commands", "payload", "deploy", "execute", "install", "launch", "run",
		"working", "ready-to-run", "plan", "steps", "workflow", "at scale", "automated", "real target", "production",
		"代码", "脚本", "工具", "程序", "命令", "载荷", "部署", "执行", "安装", "运行", "可运行", "计划", "步骤", "流程", "自动化", "真实目标", "生产",
	) {
		return true
	}
	switch category {
	case rules.CategoryCredentialTheft:
		return explicitCredentialStrongTheftAction(text) || credentialActiveHostileAccessAction(text) ||
			candidateCredentialVictimAcquisitionAction(text) ||
			credentialMetadataHostileConflict(text) ||
			candidateExplicitVictimOrNonConsent(text) && credentialActiveSecretMaterial(text) &&
				containsAnyLiteral(text, "export", "read", "copy", "导出", "读取", "复制")
	case rules.CategoryRansomware:
		return candidateDestructiveOutcome(category, text) && containsAnyLiteral(text, "encrypt", "delete", "wipe", "加密", "删除", "擦除")
	case rules.CategoryMalware:
		return candidateMaliciousPersistence(category, text)
	case rules.CategoryEvasion:
		return candidateSecurityControlEvasion(category, text)
	case rules.CategoryExfiltration:
		explicitVictim := hasExplicitHarmConflict(text) || candidateExplicitVictimOrNonConsent(text)
		exfiltration := candidateExfiltrationOrTakeover(text) || candidateExplicitExfiltrationOutbound(text)
		return candidateExplicitExfiltrationObject(text) && exfiltration &&
			(explicitVictim || candidateCovertAcquisition(text) || containsAnyLiteral(text,
				"unauthorized recipient", "outside the investigation", "outside the company", "private use",
				"未经授权的接收方", "我控制的位置", "供我私用", "调查范围之外",
			)) && containsAnyLiteral(text,
			"copy", "steal", "export", "extract", "send", "remove", "exfiltrat",
			"复制", "窃取", "导出", "提取", "发送", "带走", "外传", "传出",
		)
	default:
		return false
	}
}

func hasIndependentMaliciousExecutionClause(text string) bool {
	_, ok := independentMaliciousExecutionTail(text)
	return ok
}

var independentExecutionASCIITransitionBoundaries = [...]string{
	"; then ", ", then ", ". then ", " but then ", ", but then ", " but also ",
	" and then ", ", and then ", " additionally ", ", additionally ", " now ",
	". separately, ", "; separately, ", ", separately, ", " separately, ",
}

var independentExecutionASCIISentenceBoundaries = [...]string{". ", "! ", "? "}

var independentExecutionASCIITransitionFirst = compileASCIIBoundaryFirstIndexes(
	independentExecutionASCIITransitionBoundaries[:],
)

var independentExecutionASCIISentenceFirst = compileASCIIBoundaryFirstIndexes(
	independentExecutionASCIISentenceBoundaries[:],
)

func compileASCIIBoundaryFirstIndexes(boundaries []string) [256][]uint8 {
	var byFirst [256][]uint8
	for index, boundary := range boundaries {
		if boundary == "" || index > int(^uint8(0)) {
			continue
		}
		byFirst[boundary[0]] = append(byFirst[boundary[0]], uint8(index))
	}
	return byFirst
}

func lastASCIIBoundaryIndexes(
	text string,
	boundaries []string,
	byFirst *[256][]uint8,
	last []int,
) {
	for index := range last {
		last[index] = -1
	}
	for start := 0; start < len(text); start++ {
		for _, encodedIndex := range byFirst[text[start]] {
			index := int(encodedIndex)
			boundary := boundaries[index]
			if len(boundary) <= len(text)-start && text[start:start+len(boundary)] == boundary {
				last[index] = start
			}
		}
	}
}

func independentMaliciousExecutionTailASCII(text string) (string, bool) {
	var transitionLast [len(independentExecutionASCIITransitionBoundaries)]int
	lastASCIIBoundaryIndexes(
		text,
		independentExecutionASCIITransitionBoundaries[:],
		&independentExecutionASCIITransitionFirst,
		transitionLast[:],
	)
	for index, boundary := range independentExecutionASCIITransitionBoundaries {
		if transitionLast[index] < 0 {
			continue
		}
		tail := strings.TrimSpace(text[transitionLast[index]+len(boundary):])
		if candidateCurrentExecutionTail(tail) && candidateTailHasHarmfulObject(tail) {
			return tail, true
		}
	}

	var sentenceLast [len(independentExecutionASCIISentenceBoundaries)]int
	lastASCIIBoundaryIndexes(
		text,
		independentExecutionASCIISentenceBoundaries[:],
		&independentExecutionASCIISentenceFirst,
		sentenceLast[:],
	)
	for index, boundary := range independentExecutionASCIISentenceBoundaries {
		if sentenceLast[index] < 0 {
			continue
		}
		tail := strings.TrimSpace(text[sentenceLast[index]+len(boundary):])
		if candidateCurrentExecutionTail(tail) && candidateTailHasHarmfulObject(tail) {
			return tail, true
		}
	}
	return "", false
}

// independentMaliciousExecutionTail returns only a bounded, independently
// executable hostile tail. Callers that need a separate candidate can classify
// this text without inheriting the analytical or defensive scope that precedes
// the boundary. The boolean helper above intentionally remains the common
// eligibility predicate so both paths share exactly the same admission rule.
func independentMaliciousExecutionTail(text string) (string, bool) {
	if strings.IndexAny(text, ".,;!?") < 0 &&
		!containsAnyLiteral(text,
			" then ", " but also ", " additionally ", " now ", " separately, ", " separately ",
		) {
		if isASCIIStringLocal(text) || !containsAnyLiteral(text,
			"；然后", "。然后", "但是随后", "但同时", "另外", "现在", "。", "！", "？",
		) {
			return "", false
		}
	}
	if isASCIIStringLocal(text) {
		return independentMaliciousExecutionTailASCII(text)
	}
	for _, boundary := range []string{
		"; then ", ", then ", ". then ", " but then ", ", but then ", " but also ",
		" and then ", ", and then ", " additionally ", ", additionally ", " now ",
		". separately, ", "; separately, ", ", separately, ", " separately, ",
		"；然后", "。然后", "但是随后", "但同时", "另外", "现在",
	} {
		index := strings.LastIndex(text, boundary)
		if index < 0 {
			continue
		}
		tail := strings.TrimSpace(text[index+len(boundary):])
		if candidateCurrentExecutionTail(tail) && candidateTailHasHarmfulObject(tail) {
			return tail, true
		}
	}
	// A closed analytical/review sentence does not own a later standalone
	// imperative merely because the author omitted an explicit "then" marker.
	// Admit ordinary sentence boundaries only when the tail independently proves
	// both a direct execution head and a harmful object. Descriptive incident text
	// therefore remains inert, while "... mitigation only. Steal ..." is not
	// washed out by the earlier safety scope.
	for _, boundary := range []string{". ", "。", "! ", "！", "? ", "？"} {
		index := strings.LastIndex(text, boundary)
		if index < 0 {
			continue
		}
		tail := strings.TrimSpace(text[index+len(boundary):])
		if candidateCurrentExecutionTail(tail) && candidateTailHasHarmfulObject(tail) {
			return tail, true
		}
	}
	return "", false
}

func candidateCurrentExecutionTail(text string) bool {
	return hasAnyPrefix(strings.TrimSpace(text),
		"create ", "build ", "write ", "implement ", "ask ", "request ", "require ", "tell ", "enter ", "type ", "submit ", "provide ", "produce ", "design ", "generate ", "obtain ", "recover ", "take ", "transfer ", "copy ", "deploy ", "execute ", "install ", "launch ", "run ",
		"steal ", "dump ", "harvest ", "capture ", "collect ", "save ", "extract ", "bypass ", "disable ", "flood ", "release ", "activate ",
		"stop ", "suspend ", "erase ", "delete ", "clear ", "silence ", "mute ", "unhook ",
		"tamper ", "turn off ", "shut down ", "blind ", "neutralize ",
		"forward ", "route ", "relay ", "intercept ",
		"制作", "创建", "编写", "实现", "部署", "执行", "安装", "运行", "窃取", "转储", "收集", "提取", "绕过", "禁用", "洪泛",
	)
}

func candidateTailHasHarmfulObject(text string) bool {
	return hasExplicitHarmConflict(text) || containsAnyLiteral(text,
		"credential", "password", "session token", "cookie", "malware", "backdoor", "victim", "edr", "security control",
		"endpoint telemetry", "security telemetry", "event collection", "security event collection", "event logging",
		"telemetry collection", "endpoint sensor", "security agent", "telemetry agent", "forensic artifacts",
		"third-party", "competitor", "production users", "phishing", "ransomware", "external server",
		"covert persistence", "unauthorized", "destructive", "request load", "victim service",
		"凭证", "密码", "会话令牌", "cookie", "恶意软件", "后门", "受害者", "安全控制", "第三方", "竞争对手", "生产用户", "钓鱼", "勒索软件", "外部服务器",
	)
}
