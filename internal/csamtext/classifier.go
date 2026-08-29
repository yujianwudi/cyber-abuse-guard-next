// Package csamtext provides a deliberately small, local classifier for
// synthetic CSAM-related text intent signals.  It is independent from the
// cyber-abuse ruleset: the package has no I/O, network, model, media, or
// persistence path and never returns matched text.
package csamtext

import (
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"golang.org/x/text/unicode/norm"
)

// Bounds are intentionally conservative.  They are part of the package
// contract so callers can account for an incomplete result without retaining a
// prompt-sized copy.
const (
	MaxSegments   = 64
	MaxTotalBytes = 64 << 10
	MaxScopeBytes = 32 << 10
)

type Mode string

const (
	ModeOff      Mode = "off"
	ModeObserve  Mode = "observe"
	ModeAudit    Mode = "audit"
	ModeBalanced Mode = "balanced"
	ModeStrict   Mode = "strict"
)

type Action string

const (
	ActionAllow   Action = "allow"
	ActionObserve Action = "observe"
	ActionAudit   Action = "audit"
	ActionBlock   Action = "block"
)

type Category string

const CategoryCSAMMalicious Category = "csam_malicious"

type Intent string

const (
	IntentNone          Intent = ""
	IntentProduction    Intent = "production"
	IntentSolicitation  Intent = "solicitation"
	IntentExchange      Intent = "exchange"
	IntentDissemination Intent = "dissemination"
	IntentGrooming      Intent = "grooming"
)

type Confidence string

const (
	ConfidenceNone   Confidence = "none"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type Coverage string

const (
	CoverageComplete        Coverage = "complete"
	CoverageBudgetExhausted Coverage = "budget_exhausted"
)

type Reason string

const (
	ReasonNone           Reason = ""
	ReasonEligible       Reason = "eligible"
	ReasonInsufficient   Reason = "insufficient_evidence"
	ReasonNormalPurpose  Reason = "normal_purpose"
	ReasonNegated        Reason = "negated_request"
	ReasonNotCurrentUser Reason = "not_current_trusted_user"
	ReasonUnknownRole    Reason = "unknown_role_or_provenance"
	ReasonIncomplete     Reason = "incomplete_inspection"
	ReasonScopeConflict  Reason = "scope_conflict"
)

// Input is a transient model-visible text segment. Text is read synchronously
// and is never copied into Result or classifier state. Empty/unknown role or
// provenance is intentionally untrusted.
type Input struct {
	Role        string
	Provenance  string
	TrustedUser bool
	CurrentTurn bool
	ScopeID     uint64
	Incomplete  bool
	Text        string
}

const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
	RoleUnknown   = "unknown"

	ProvenanceContent     = "content"
	ProvenanceToolPayload = "tool_payload"
)

// Result is a fixed, privacy-safe projection. It contains no prompt bytes,
// offsets, matched spans, URLs, hashes of request content, or dynamic labels.
type Result struct {
	Detected    bool       `json:"detected"`
	Eligible    bool       `json:"eligible"`
	Category    Category   `json:"category,omitempty"`
	RuleID      string     `json:"rule_id,omitempty"`
	Intent      Intent     `json:"intent,omitempty"`
	Confidence  Confidence `json:"confidence"`
	Action      Action     `json:"action"`
	Coverage    Coverage   `json:"coverage"`
	Reason      Reason     `json:"reason,omitempty"`
	policyProof policyFindingProof
	// privacySensitive is a content-free, request-local taint. It records that
	// the joint action/object/harm candidate gate fired before normal-purpose or
	// negation exclusions. It is deliberately private and never identifies the
	// matched text, position, or exclusion reason.
	privacySensitive bool
}

// PrivacySensitiveCandidate reports whether classifier-visible text crossed
// the conservative pre-exclusion CSAM candidate gate. The bit contains no
// request text and is intended only to prevent raw request capture.
func (result Result) PrivacySensitiveCandidate() bool { return result.privacySensitive }

// policyFindingProof binds a classifier-produced positive to its complete
// content-free public projection. It remains private so a caller cannot make a
// hand-built or JSON-decoded Result policy-capable, and it contains no request
// text, offsets, hashes, or other input-derived values.
type policyFindingProof struct {
	set        bool
	detected   bool
	eligible   bool
	category   Category
	ruleID     string
	intent     Intent
	confidence Confidence
	action     Action
	coverage   Coverage
	reason     Reason
}

// PolicyFindingProofComplete reports whether this positive still carries the
// classifier-private proof for its exact public fields. Callers may verify the
// proof but cannot construct it. Copying and rewriting any public policy field,
// or recreating a Result from JSON, invalidates the proof.
func (result Result) PolicyFindingProofComplete() bool {
	proof := result.policyProof
	return proof.set &&
		proof.detected == result.Detected &&
		proof.eligible == result.Eligible &&
		proof.category == result.Category &&
		proof.ruleID == result.RuleID &&
		proof.intent == result.Intent &&
		proof.confidence == result.Confidence &&
		proof.action == result.Action &&
		proof.coverage == result.Coverage &&
		proof.reason == result.Reason
}

func bindPolicyFindingProof(result *Result) {
	if result == nil {
		return
	}
	result.policyProof = policyFindingProof{
		set:        true,
		detected:   result.Detected,
		eligible:   result.Eligible,
		category:   result.Category,
		ruleID:     result.RuleID,
		intent:     result.Intent,
		confidence: result.Confidence,
		action:     result.Action,
		coverage:   result.Coverage,
		reason:     result.Reason,
	}
}

type intentSpec struct {
	intent            Intent
	ruleID            string
	markers           []string
	normalizedMarkers []string
}

// Classifier is immutable after construction and safe for concurrent use.
type Classifier struct {
	specs                        []intentSpec
	objectMarkers                []string
	harmMarkers                  []string
	normalSignalGroups           [][]string
	protectiveTargets            []string
	referenceMarkers             []string
	negations                    []string
	continuations                []string
	normalizedObjectMarkers      []string
	normalizedHarmMarkers        []string
	normalizedObjectHarmMarkers  []string
	normalizedNormalSignalGroups [][]string
	normalizedProtectiveTargets  []string
	normalizedReferenceMarkers   []string
	normalizedNegations          []string
	normalizedContinuations      []string
}

// CandidateSignals is a fixed, content-free projection of the conservative
// lexical gate used before semantic exclusions. It supports streaming privacy
// and coverage accounting without retaining prompt text.
type CandidateSignals struct {
	Action bool
	Object bool
	Harm   bool
}

func (signals CandidateSignals) Complete() bool {
	return signals.Action && signals.Object && signals.Harm
}

func (signals CandidateSignals) Merge(other CandidateSignals) CandidateSignals {
	return CandidateSignals{
		Action: signals.Action || other.Action,
		Object: signals.Object || other.Object,
		Harm:   signals.Harm || other.Harm,
	}
}

// ScanCandidateSignals scans one transient chunk and returns only the three
// low-cardinality candidate dimensions. Callers may combine them by scope.
func (c *Classifier) ScanCandidateSignals(text string) CandidateSignals {
	if c == nil || text == "" {
		return CandidateSignals{}
	}
	normalized := normalize(text)
	action := false
	for _, spec := range c.specs {
		action = action || hasAnyPrepared(normalized, spec.normalizedMarkers)
	}
	return CandidateSignals{
		Action: action,
		Object: hasAnyPrepared(normalized, c.normalizedObjectMarkers),
		Harm:   hasAnyPrepared(normalized, c.normalizedHarmMarkers),
	}
}

var (
	defaultOnce sync.Once
	defaultInst *Classifier
)

// New returns an immutable classifier. Each invocation returns a fresh value;
// callers may share it freely between goroutines.
func New() *Classifier {
	c := &Classifier{
		specs: []intentSpec{
			{IntentProduction, "CSAM-TXT-PRODUCTION-001", []string{
				"create", "creates", "creating", "generate", "generates", "generating", "produce", "produces", "producing", "make", "makes", "making", "synthesize", "synthesizes", "synthesizing", "制作", "生成", "合成",
			}, nil},
			{IntentSolicitation, "CSAM-TXT-SOLICITATION-001", []string{
				"request", "requests", "requested", "requesting", "solicit", "solicits", "solicited", "soliciting", "seek", "seeks", "sought", "seeking", "ask for", "asked for", "asking for", "索取", "请求", "寻找", "求取",
			}, nil},
			{IntentExchange, "CSAM-TXT-EXCHANGE-001", []string{
				"trade", "trades", "traded", "trading", "exchange", "exchanges", "exchanged", "exchanging", "swap", "swaps", "swapped", "swapping", "barter", "barters", "bartered", "bartering", "交易", "交换", "互换",
			}, nil},
			{IntentDissemination, "CSAM-TXT-DISSEMINATION-001", []string{
				"distribute", "distributes", "distributed", "distributing", "share", "shares", "shared", "sharing", "spread", "spreads", "spreading", "publish", "publishes", "published", "publishing", "circulate", "circulates", "circulated", "circulating", "传播", "散布", "分享", "发布",
			}, nil},
			{IntentGrooming, "CSAM-TXT-GROOMING-001", []string{
				"groom", "grooms", "groomed", "grooming", "entice", "entices", "enticed", "enticing", "coerce", "coerces", "coerced", "coercing", "pressure", "pressures", "pressured", "pressuring", "诱骗", "胁迫", "诱导", "拉拢",
			}, nil},
		},
		objectMarkers: []string{
			"minor", "minors", "youth", "underage", "child", "children", "未成年人", "未成年", "儿童", "青少年",
		},
		harmMarkers: []string{
			"sexual", "intimate", "prohibited", "illegal", "exploitative", "色情", "性内容", "违法", "不当内容",
		},
		normalSignalGroups: [][]string{
			{"news", "journalism", "newsroom", "article", "新闻"},
			{"report", "reporting", "hotline", "举报", "报道", "保留证据"},
			{"legal", "lawful", "compliance", "law", "laws", "法律", "合规"},
			{"research", "研究"},
			{"detect", "detecting", "detection", "analyze", "analysis", "classifier", "false positive", "检测", "识别", "文本意图"},
			{"prevention", "prevent", "safety", "safety guide", "safety research", "security", "security research", "安全", "预防"},
			{"parent", "parental", "guardian", "家长", "监护"},
			{"protect", "protecting", "protection", "保护"},
			{"support", "victim support", "支持", "求助"},
			{"survivor", "survivors", "victim", "victims", "受害者"},
			{"resource", "resources", "guide", "checklist", "options", "confidential", "资源", "指南"},
			{"takedown", "delete", "deletion", "remove", "removal", "删除", "下架", "清除"},
			{"platform", "notice", "services", "duties", "平台", "义务"},
		},
		// These are deliberately noun phrases or remedial operations that can
		// be the direct target of an otherwise risky-looking verb. A generic
		// word such as "safety" is not enough to neutralize a harmful request.
		protectiveTargets: []string{
			"news report", "news article", "report", "legal report", "compliance report", "reporting guide", "hotline guide", "platform notice", "compliance checklist", "safety checklist",
			"victim support", "support resource", "survivor support", "guardian checklist",
			"parental safety guide", "safety guide", "protection checklist", "prevention resource",
			"deletion", "deletion guide", "removal", "removal checklist", "takedown notice",
			"新闻报道", "举报指南", "合规清单", "受害者支持", "支持资源", "家长安全指南",
			"监护人清单", "删除", "下架", "清除",
		},
		// Reference markers make a nearby intent verb an object of detection,
		// quotation, or analysis rather than an instruction to perform it.
		referenceMarkers: []string{
			"detect", "detects", "detected", "detecting", "detection", "quoted", "quote", "says", "said",
			"reported that", "mentions", "analysis of", "检测", "识别", "引用", "提及",
		},
		negations: []string{"do not", "don't", "never", "not", "禁止", "不要", "勿", "严禁", "反对"},
		// These words start a new coordinated instruction/object. They prevent
		// a negation, quotation, or protective direct object from silently
		// extending over a later harmful directive in the same sentence.
		continuations: []string{
			"and", "then", "but", "however", "instead", "plus", "also", "along with", "as well as",
			"然后", "但是", "不过", "改为", "另外", "以及", "并且", "同时",
		},
	}
	c.prepareMarkers()
	return c
}

// prepareMarkers compiles the fixed vocabulary once at construction time. The
// request path operates on already-normalized marker slices so classification
// does not repeatedly allocate while normalizing the same static policy words.
func (c *Classifier) prepareMarkers() {
	if c == nil {
		return
	}
	for index := range c.specs {
		c.specs[index].normalizedMarkers = normalizeMarkerList(c.specs[index].markers)
	}
	c.normalizedObjectMarkers = normalizeMarkerList(c.objectMarkers)
	c.normalizedHarmMarkers = normalizeMarkerList(c.harmMarkers)
	c.normalizedObjectHarmMarkers = append(append([]string(nil), c.normalizedObjectMarkers...), c.normalizedHarmMarkers...)
	c.normalizedNormalSignalGroups = normalizeMarkerGroups(c.normalSignalGroups)
	c.normalizedProtectiveTargets = normalizeMarkerList(c.protectiveTargets)
	c.normalizedReferenceMarkers = normalizeMarkerList(c.referenceMarkers)
	c.normalizedNegations = normalizeMarkerList(c.negations)
	c.normalizedContinuations = normalizeMarkerList(c.continuations)
}

func normalizeMarkerList(markers []string) []string {
	prepared := make([]string, 0, len(markers))
	for _, marker := range markers {
		if marker = normalize(marker); marker != "" {
			prepared = append(prepared, marker)
		}
	}
	return prepared
}

func normalizeMarkerGroups(groups [][]string) [][]string {
	prepared := make([][]string, len(groups))
	for index, group := range groups {
		prepared[index] = normalizeMarkerList(group)
	}
	return prepared
}

func defaultClassifier() *Classifier {
	defaultOnce.Do(func() { defaultInst = New() })
	return defaultInst
}

// Classify applies the default immutable classifier to one request.
func Classify(inputs []Input, mode Mode) Result {
	return defaultClassifier().Classify(inputs, mode)
}

// ClassifyExtractSegments adapts the repository's transient extract.Segment
// values without exposing that package in Result. The adapter performs no I/O.
func ClassifyExtractSegments(segments []extract.Segment, mode Mode) Result {
	return defaultClassifier().ClassifyExtractSegments(segments, mode)
}

func (c *Classifier) ClassifyExtractSegments(segments []extract.Segment, mode Mode) Result {
	inputs := make([]Input, 0, len(segments))
	for _, segment := range segments {
		role := string(segment.Role)
		provenance := ""
		switch segment.Provenance {
		case extract.ProvenanceContent:
			provenance = ProvenanceContent
		case extract.ProvenanceToolPayload:
			provenance = ProvenanceToolPayload
		}
		inputs = append(inputs, Input{
			Role:        role,
			Provenance:  provenance,
			TrustedUser: segment.UserAttribution == extract.UserAttributionTrusted,
			CurrentTurn: segment.IsCurrentTurn,
			ScopeID:     segment.ScopeID,
			Text:        segment.Text,
		})
	}
	return c.Classify(inputs, mode)
}

// Classify evaluates bounded, same-scope text. A positive result needs one
// intent marker, one protected-object marker, and one harm marker. Normal-use
// framing and negated/prohibitory requests are explicit exclusions. Only
// structurally scoped, trusted current-user content is inspected; all other
// carriers are ignored without reading or accounting their text.
func (c *Classifier) Classify(inputs []Input, mode Mode) Result {
	result := Result{Action: ActionAllow, Coverage: CoverageComplete, Confidence: ConfidenceNone}
	if mode == ModeOff || c == nil {
		return result
	}
	eligibleInputs := make([]Input, 0, minInt(len(inputs), MaxSegments))
	totalBytes := 0
	scopeBytes := make(map[uint64]int)
	for _, input := range inputs {
		if !enforcementEligible(input) {
			continue
		}
		if input.Incomplete {
			return c.incompleteResult()
		}
		if len(eligibleInputs) >= MaxSegments {
			return c.incompleteResult()
		}
		if len(input.Text) > MaxScopeBytes || totalBytes > MaxTotalBytes-len(input.Text) {
			return c.incompleteResult()
		}
		scopeBytes[input.ScopeID] += len(input.Text)
		if scopeBytes[input.ScopeID] > MaxScopeBytes {
			return c.incompleteResult()
		}
		totalBytes += len(input.Text)
		if !utf8.ValidString(input.Text) {
			return c.incompleteResult()
		}
		eligibleInputs = append(eligibleInputs, input)
	}
	if len(eligibleInputs) == 0 {
		return result
	}

	groups := groupInputs(eligibleInputs)
	var best Result
	privacySensitive := false
	for _, group := range groups {
		candidate := c.classifyGroup(group.text)
		privacySensitive = privacySensitive || candidate.privacySensitive
		if better(candidate, best) {
			best = candidate
		}
	}
	if best.Detected && best.Eligible && best.Coverage == CoverageComplete {
		best.privacySensitive = privacySensitive
		best.Action = actionFor(mode, best.Eligible)
		bindPolicyFindingProof(&best)
		return best
	}
	result.privacySensitive = privacySensitive
	return result
}

func enforcementEligible(input Input) bool {
	return input.TrustedUser && input.CurrentTurn && input.ScopeID != 0 &&
		strings.EqualFold(strings.TrimSpace(input.Role), RoleUser) &&
		strings.EqualFold(strings.TrimSpace(input.Provenance), ProvenanceContent)
}

type inputGroup struct {
	text  string
	scope uint64
}

func groupInputs(inputs []Input) []inputGroup {
	groups := make([]inputGroup, 0, len(inputs))
	byScope := make(map[uint64]int, len(inputs))
	for _, input := range inputs {
		if index, ok := byScope[input.ScopeID]; ok {
			groups[index].text += " " + input.Text
			continue
		}
		byScope[input.ScopeID] = len(groups)
		groups = append(groups, inputGroup{text: input.Text, scope: input.ScopeID})
	}
	return groups
}

func (c *Classifier) classifyGroup(raw string) Result {
	text := normalize(raw)
	if text == "" {
		return Result{Coverage: CoverageComplete, Confidence: ConfidenceNone, Action: ActionAllow}
	}
	normalExempt := false
	negatedExempt := false
	privacySensitive := false
	for _, spec := range c.specs {
		if !hasAnyPrepared(text, spec.normalizedMarkers) ||
			!hasAnyPrepared(text, c.normalizedObjectMarkers) ||
			!hasAnyPrepared(text, c.normalizedHarmMarkers) {
			continue
		}
		privacySensitive = true
		if !hasScopedActionEvidence(
			text, spec.normalizedMarkers, c.normalizedObjectMarkers, c.normalizedHarmMarkers,
		) {
			continue
		}
		if normalPurposePrepared(text, spec.normalizedMarkers, c) {
			normalExempt = true
			continue
		}
		if allActionOccurrencesExcludedPrepared(text, spec.normalizedMarkers, c.normalizedNegations,
			c.normalizedReferenceMarkers, c.normalizedContinuations, c.normalizedObjectMarkers,
			c.normalizedHarmMarkers, c.normalizedObjectHarmMarkers) {
			negatedExempt = true
			continue
		}
		result := Result{
			Detected: true, Eligible: true, Category: CategoryCSAMMalicious,
			RuleID: spec.ruleID, Intent: spec.intent, Confidence: ConfidenceMedium,
			Coverage: CoverageComplete, Reason: ReasonEligible,
		}
		result.privacySensitive = true
		result.Confidence = ConfidenceHigh
		return result
	}
	if normalExempt {
		return Result{Coverage: CoverageComplete, Confidence: ConfidenceNone, Action: ActionAllow, Reason: ReasonNormalPurpose, privacySensitive: privacySensitive}
	}
	if negatedExempt {
		return Result{Coverage: CoverageComplete, Confidence: ConfidenceNone, Action: ActionAllow, Reason: ReasonNegated, privacySensitive: privacySensitive}
	}
	return Result{Coverage: CoverageComplete, Confidence: ConfidenceNone, Action: ActionAllow, Reason: ReasonInsufficient, privacySensitive: privacySensitive}
}

func (c *Classifier) incompleteResult() Result {
	return Result{
		Action: ActionAllow, Coverage: CoverageBudgetExhausted,
		Confidence: ConfidenceNone, Reason: ReasonIncomplete,
	}
}

func actionFor(mode Mode, eligible bool) Action {
	if !eligible {
		switch mode {
		case ModeObserve:
			return ActionObserve
		case ModeAudit:
			return ActionAudit
		default:
			return ActionAllow
		}
	}
	switch mode {
	case ModeObserve:
		return ActionObserve
	case ModeAudit:
		return ActionAudit
	case ModeBalanced, ModeStrict:
		return ActionBlock
	default:
		return ActionAllow
	}
}

func better(candidate, current Result) bool {
	if !candidate.Detected {
		return false
	}
	if !current.Detected {
		return true
	}
	if candidate.Eligible != current.Eligible {
		return candidate.Eligible
	}
	return candidate.RuleID < current.RuleID
}

func normalize(value string) string {
	value = strings.ToLower(norm.NFKC.String(value))
	var b strings.Builder
	lastSpace := true
	for _, r := range value {
		if unicode.Is(unicode.Cf, r) || r == '\u200b' || r == '\u200c' || r == '\u200d' {
			// Format controls are not content, but removing one outright can join
			// otherwise distinct words (for example, "create<ZWSP>prohibited").
			// Preserve a safe word boundary without letting it carry clause-local
			// negation or reference context across structural separators.
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastSpace = false
			continue
		}
		if isClauseBoundary(r) {
			// Keep a non-word clause separator so local negation/reference
			// evidence cannot leak across a sentence or semicolon. It remains
			// whitespace to strings.Fields and markerIndex.
			b.WriteByte('\n')
			lastSpace = true
			continue
		}
		if !lastSpace {
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

func isClauseBoundary(r rune) bool {
	switch r {
	case '\n', '\r', '\u2028', '\u2029', '.', '!', '?', ';', ':', '\u3002', '\uff01', '\uff1f', '\uff1b', '\uff1a':
		return true
	default:
		return false
	}
}

func hasAny(text string, markers []string) bool {
	for _, marker := range markers {
		marker = normalize(marker)
		if marker != "" && markerIndex(text, marker, 0) >= 0 {
			return true
		}
	}
	return false
}

func hasAnyPrepared(text string, markers []string) bool {
	for _, marker := range markers {
		if marker != "" && markerIndex(text, marker, 0) >= 0 {
			return true
		}
	}
	return false
}

func normalPurpose(text string, actions []string, c *Classifier) bool {
	return normalPurposePrepared(text, normalizeMarkerList(actions), c)
}

func normalPurposePrepared(text string, actions []string, c *Classifier) bool {
	// A normal-use exclusion needs corroboration from two independent semantic
	// groups. Repeating synonyms from one group cannot manufacture confidence.
	if normalSignalCountPrepared(text, c.normalizedNormalSignalGroups) < 2 {
		return false
	}
	// Direct requests to perform the harmful action always win over surrounding
	// benign vocabulary. The only exclusions are individually negated or plainly
	// referenced actions, plus commands whose direct object is itself protective.
	return !hasUnexcludedActionPrepared(text, actions, c.normalizedNegations, c.normalizedReferenceMarkers,
		c.normalizedProtectiveTargets, c.normalizedContinuations, c.normalizedObjectMarkers,
		c.normalizedHarmMarkers, c.normalizedObjectHarmMarkers)
}

func normalSignalCount(text string, groups [][]string) int {
	return normalSignalCountPrepared(text, normalizeMarkerGroups(groups))
}

func normalSignalCountPrepared(text string, groups [][]string) int {
	count := 0
	for _, group := range groups {
		if hasAnyPrepared(text, group) {
			count++
		}
	}
	return count
}

func allActionOccurrencesExcluded(text string, actions, negations, references, continuations, objectMarkers, harmMarkers []string) bool {
	found, unexcluded := actionOccurrenceState(text, normalizeMarkerList(actions), normalizeMarkerList(negations), normalizeMarkerList(references), nil, normalizeMarkerList(continuations), normalizeMarkerList(objectMarkers), normalizeMarkerList(harmMarkers), nil)
	return found && !unexcluded
}

func hasUnexcludedAction(text string, actions, negations, references, protectiveTargets, continuations, objectMarkers, harmMarkers []string) bool {
	return hasUnexcludedActionPrepared(text, normalizeMarkerList(actions), normalizeMarkerList(negations), normalizeMarkerList(references), normalizeMarkerList(protectiveTargets), normalizeMarkerList(continuations), normalizeMarkerList(objectMarkers), normalizeMarkerList(harmMarkers), nil)
}

func allActionOccurrencesExcludedPrepared(text string, actions, negations, references, continuations, objectMarkers, harmMarkers, objectHarmMarkers []string) bool {
	found, unexcluded := actionOccurrenceState(text, actions, negations, references, nil, continuations, objectMarkers, harmMarkers, objectHarmMarkers)
	return found && !unexcluded
}

func hasUnexcludedActionPrepared(text string, actions, negations, references, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers []string) bool {
	_, unexcluded := actionOccurrenceState(text, actions, negations, references, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers)
	return unexcluded
}

func actionOccurrenceState(text string, actions, negations, references, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers []string) (bool, bool) {
	found := false
	for _, action := range actions {
		start := 0
		for {
			index := markerIndex(text, action, start)
			if index < 0 {
				break
			}
			// The conservative privacy gate deliberately composes action,
			// protected-object, and harm signals across the whole bounded scope.
			// Enforcement is narrower: an action occurrence must bind those
			// signals inside its own clause. Otherwise unrelated instructions in
			// a long defensive quotation could combine with a distant protective
			// sentence into a false malicious intent. Preserve the explicit
			// anaphoric continuation case (for example, a later "create it")
			// only when the immediately preceding clause contains the complete
			// object/harm pair.
			if !occurrenceHasScopedEvidence(
				text, index, index+len(action), objectMarkers, harmMarkers,
			) {
				start = index + len(action)
				if start >= len(text) {
					break
				}
				continue
			}
			found = true
			if !occurrenceExcluded(text, index, index+len(action), negations, references, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers) {
				return true, true
			}
			start = index + len(action)
			if start >= len(text) {
				break
			}
		}
	}
	return found, false
}

func hasScopedActionEvidence(text string, actions, objectMarkers, harmMarkers []string) bool {
	for _, action := range actions {
		for start := 0; ; {
			index := markerIndex(text, action, start)
			if index < 0 {
				break
			}
			end := index + len(action)
			if occurrenceHasScopedEvidence(text, index, end, objectMarkers, harmMarkers) {
				return true
			}
			start = end
			if start >= len(text) {
				break
			}
		}
	}
	return false
}

func occurrenceHasScopedEvidence(text string, start, end int, objectMarkers, harmMarkers []string) bool {
	clauseStart := strings.LastIndexByte(text[:start], '\n') + 1
	clauseEnd := len(text)
	if relative := strings.IndexByte(text[end:], '\n'); relative >= 0 {
		clauseEnd = end + relative
	}
	clause := text[clauseStart:clauseEnd]
	if hasAnyPrepared(clause, objectMarkers) && hasAnyPrepared(clause, harmMarkers) {
		return true
	}
	// A standalone action heading followed immediately by its object clause
	// is one syntactic unit after normalization (for example, "Exchange:"
	// followed by the bounded object). Do not generalize this to an arbitrary
	// action sentence: only the action marker itself may occupy the heading.
	relativeStart := start - clauseStart
	relativeEnd := end - clauseStart
	headingRemainder := strings.TrimSpace(clause[:relativeStart] + " " + clause[relativeEnd:])
	if headingRemainder == "" && clauseEnd < len(text) {
		nextClause := currentClauseSuffix(text[clauseEnd+1:])
		if hasAnyPrepared(nextClause, objectMarkers) && hasAnyPrepared(nextClause, harmMarkers) {
			return true
		}
	}

	// A short direct-object referent may carry an immediately preceding
	// prohibited object into a new instruction. This keeps structural
	// separators and negation from creating a "create it" bypass without
	// allowing arbitrary distant clauses to compose evidence.
	suffixWords := strings.Fields(currentClauseSuffix(text[end:]))
	if len(suffixWords) == 0 || len(suffixWords) > 4 || !isScopedObjectReferent(suffixWords) || clauseStart == 0 {
		return false
	}
	previous := strings.TrimSpace(text[:clauseStart-1])
	if previous == "" {
		return false
	}
	previousClause := currentClausePrefix(previous)
	return hasAnyPrepared(previousClause, objectMarkers) &&
		hasAnyPrepared(previousClause, harmMarkers)
}

func isScopedObjectReferent(words []string) bool {
	if len(words) == 0 {
		return false
	}
	prefixLength := 0
	for _, referent := range [][]string{
		{"the", "same"}, {"that", "material"}, {"this", "material"}, {"that", "content"},
		{"this", "content"}, {"same", "material"}, {"same", "content"},
		{"it"}, {"them"}, {"that"}, {"this"}, {"它"}, {"它们"}, {"该内容"}, {"这些内容"}, {"同一内容"},
	} {
		if len(words) >= len(referent) && strings.Join(words[:len(referent)], " ") == strings.Join(referent, " ") {
			prefixLength = len(referent)
			break
		}
	}
	if prefixLength == 0 {
		return false
	}
	for _, modifier := range words[prefixLength:] {
		switch modifier {
		case "now", "again", "immediately", "directly", "please", "现在", "再次", "立即", "直接":
		default:
			return false
		}
	}
	return true
}

func occurrenceExcluded(text string, start, end int, negations, references, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers []string) bool {
	prefixText := currentClausePrefix(text[:start])
	prefixWords := strings.Fields(prefixText)
	prefix := strings.Join(prefixWords[maxInt(0, len(prefixWords)-4):], " ")
	if scopedPrefixMarker(prefix, negations, continuations, true) ||
		scopedPrefixMarker(prefix, references, continuations, true) {
		return true
	}
	// Protective targets must immediately follow the action. This permits
	// "create a victim support resource" but not "for safety, create [harm]".
	suffixWords := strings.Fields(currentClauseSuffix(text[end:]))
	suffix := strings.Join(suffixWords[:minInt(8, len(suffixWords))], " ")
	return hasProtectiveTargetBeforeHarmPrepared(suffix, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers)
}

func currentClausePrefix(text string) string {
	if index := strings.LastIndexByte(text, '\n'); index >= 0 {
		return text[index+1:]
	}
	return text
}

func currentClauseSuffix(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return text[:index]
	}
	return text
}

func scopedPrefixMarker(prefix string, markers, continuations []string, resetOnContinuation bool) bool {
	if resetOnContinuation {
		if cut := lastMarkerEndPrepared(prefix, continuations); cut >= 0 {
			prefix = prefix[cut:]
		}
	}
	return hasAnyPrepared(prefix, markers)
}

func lastMarkerEnd(text string, markers []string) int {
	return lastMarkerEndPrepared(text, normalizeMarkerList(markers))
}

func lastMarkerEndPrepared(text string, markers []string) int {
	last := -1
	for _, marker := range markers {
		start := 0
		for {
			index := markerIndex(text, marker, start)
			if index < 0 {
				break
			}
			last = maxInt(last, index+len(marker))
			start = index + len(marker)
			if start >= len(text) {
				break
			}
		}
	}
	return last
}

func hasProtectiveTargetBeforeHarm(suffix string, protectiveTargets, continuations, objectMarkers, harmMarkers []string) bool {
	return hasProtectiveTargetBeforeHarmPrepared(suffix, normalizeMarkerList(protectiveTargets), normalizeMarkerList(continuations), normalizeMarkerList(objectMarkers), normalizeMarkerList(harmMarkers), nil)
}

func hasProtectiveTargetBeforeHarmPrepared(suffix string, protectiveTargets, continuations, objectMarkers, harmMarkers, objectHarmMarkers []string) bool {
	if !hasAnyPrepared(suffix, protectiveTargets) {
		return false
	}
	firstHarm := -1
	markers := objectHarmMarkers
	if len(markers) == 0 {
		markers = append(append([]string(nil), objectMarkers...), harmMarkers...)
	}
	for _, marker := range markers {
		if index := markerIndex(suffix, marker, 0); index >= 0 && (firstHarm < 0 || index < firstHarm) {
			firstHarm = index
		}
	}
	for _, marker := range protectiveTargets {
		index := markerIndex(suffix, marker, 0)
		if index >= 0 && (firstHarm < 0 || index < firstHarm) {
			between := ""
			if firstHarm >= 0 {
				between = suffix[index+len(marker) : firstHarm]
			}
			if !hasAnyPrepared(between, continuations) {
				return true
			}
		}
	}
	return false
}

func markerIndex(text, marker string, start int) int {
	if marker == "" || start < 0 || start > len(text) {
		return -1
	}
	boundaryRequired := true
	for _, r := range marker {
		if r > unicode.MaxASCII {
			boundaryRequired = false
			break
		}
	}
	for offset := start; offset <= len(text)-len(marker); {
		relative := strings.Index(text[offset:], marker)
		if relative < 0 {
			return -1
		}
		index := offset + relative
		if !boundaryRequired || asciiMarkerBoundary(text, index, index+len(marker)) {
			return index
		}
		offset = index + 1
	}
	return -1
}

func asciiMarkerBoundary(text string, start, end int) bool {
	left := start == 0 || !asciiWordByte(text[start-1])
	right := end == len(text) || !asciiWordByte(text[end])
	return left && right
}

func asciiWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_'
}

func knownRole(role string) bool {
	switch role {
	case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		return true
	default:
		return false
	}
}

func knownProvenance(provenance string) bool {
	return provenance == ProvenanceContent || provenance == ProvenanceToolPayload
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
