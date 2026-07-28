// Package classifier implements a deterministic, local abuse classifier. It
// performs no I/O and returns only stable identifiers and aggregate flags.
package classifier

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const (
	AuditThreshold                = 35
	BalancedThreshold             = 60
	HardThreshold                 = 80
	maxAdjacentNegationCandidates = 8
	maxAdjacentNegationRunes      = 64 << 10
	maxCompactIntentProofBytes    = 16 << 10
	maxRuleIntentOccurrences      = 64
	maxRuleIntentLookbackBytes    = 512
	maxNegationReversalCandidates = 64
	maxNegationReversalTailBytes  = 512
	maxInertReviewPriorParts      = 8
	maxInertReviewPriorBytes      = 32 << 10
)

// Mode controls how a score becomes an action. The hard threshold is a global
// safety ceiling for every enabled classifier mode; host integrations may
// still preserve a non-enforcing observe/audit transport policy explicitly.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeObserve  Mode = "observe"
	ModeAudit    Mode = "audit"
	ModeBalanced Mode = "balanced"
	ModeStrict   Mode = "strict"
)

// Action is the policy disposition derived from a score and mode.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionObserve Action = "observe"
	ActionAudit   Action = "audit"
	ActionBlock   Action = "block"
)

// Thresholds are configurable policy thresholds. A zero value selects the
// documented defaults.
type Thresholds struct {
	Audit         int
	BalancedBlock int
	HardBlock     int
}

// ContextPolicy controls which matched safety contexts may reduce risk. A
// disabled field still allows the context to be reported, but it has no effect
// on scoring. Keeping this type independent from internal/config avoids a
// package cycle at the plugin boundary.
type ContextPolicy struct {
	Defensive        bool
	Remediation      bool
	CTF              bool
	Lab              bool
	Authorized       bool
	StaticAnalysis   bool
	IncidentResponse bool
	HighLevel        bool
}

// HardBlockPolicy controls the categories for which an authorization claim is
// not a score-reducing exception.
type HardBlockPolicy struct {
	CredentialTheft      bool
	PhishingDeployment   bool
	RansomwareDeployment bool
	DataExfiltration     bool
}

// Policy contains the configurable context and authorization behavior used by
// ClassifyWithPolicy. It is a value type and is safe to reuse concurrently.
type Policy struct {
	Allow                     ContextPolicy
	HardBlockEvenIfAuthorized HardBlockPolicy
}

// DefaultThresholds returns the production defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{Audit: AuditThreshold, BalancedBlock: BalancedThreshold, HardBlock: HardThreshold}
}

// DefaultPolicy returns the balanced task-book policy.
func DefaultPolicy() Policy {
	return Policy{
		Allow: ContextPolicy{
			Defensive:        true,
			Remediation:      true,
			CTF:              true,
			Lab:              true,
			Authorized:       true,
			StaticAnalysis:   true,
			IncidentResponse: true,
			HighLevel:        true,
		},
		HardBlockEvenIfAuthorized: HardBlockPolicy{
			CredentialTheft:      true,
			PhishingDeployment:   true,
			RansomwareDeployment: true,
			DataExfiltration:     true,
		},
	}
}

// ContextFlags contains no matched text and is safe to include in minimal
// audit metadata.
type ContextFlags struct {
	Defensive        bool `json:"defensive"`
	Remediation      bool `json:"remediation"`
	CTFOrLab         bool `json:"ctf_or_lab"`
	Authorized       bool `json:"authorized"`
	StaticAnalysis   bool `json:"static_analysis"`
	IncidentResponse bool `json:"incident_response"`
	HighLevel        bool `json:"high_level"`
}

// Evidence contains stable rule-local evidence identifiers only.
type Evidence struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// FindingOrigin is a closed, privacy-safe attribution for the winning
// classifier finding. It never contains role text, field names, request
// fragments, or provider-specific identifiers.
type FindingOrigin string

const (
	FindingOriginNone               FindingOrigin = ""
	FindingOriginUserContent        FindingOrigin = "user_content"
	FindingOriginNonUserOrUntrusted FindingOrigin = "non_user_or_untrusted"
)

// Result intentionally has no field capable of carrying prompt fragments.
type Result struct {
	PolicyVersion       string               `json:"policy_version"`
	PolicySHA256        string               `json:"policy_sha256"`
	RuleSetVersion      string               `json:"ruleset_version"`
	Score               int                  `json:"score"`
	Category            rules.Category       `json:"category,omitempty"`
	Action              Action               `json:"action"`
	RuleIDs             []string             `json:"rule_ids,omitempty"`
	Context             ContextFlags         `json:"context"`
	Evidence            []Evidence           `json:"evidence,omitempty"`
	EvidenceOccurrences []EvidenceOccurrence `json:"evidence_occurrences,omitempty"`
	DecisionExplanation *DecisionExplanation `json:"decision_explanation,omitempty"`
	Behavior            *BehaviorGraph       `json:"behavior,omitempty"`
	FindingOrigin       FindingOrigin        `json:"finding_origin,omitempty"`
	Coverage            Coverage             `json:"coverage,omitempty,omitzero"`
	FindingConfidence   FindingConfidence    `json:"finding_confidence,omitempty"`
	Truncated           bool                 `json:"truncated,omitempty"`
}

// classificationSignalFacts is the privacy-safe, bounded semantic summary
// captured from one classifier part. It contains no prompt bytes and reuses the
// exact signals and negation analysis already produced by classifyWithPolicy.
// Streaming callers merge these facts inside one logical field or across a
// consecutive unknown-role, content-provenance sequence whose long field
// cannot retain exact text; role and provenance boundaries are never merged.
type classificationSignalFacts struct {
	signals                  []bool
	unnegatedRuleIntents     []bool
	matchedSemanticIntents   []bool
	unnegatedSemanticIntents []bool
	semanticAgencies         []bool
	semanticCoreEvidence     []uint8
	harmConflict             bool
}

type compiledRule struct {
	id                     string
	category               rules.Category
	baseScore              int
	hardFloor              int
	authorizationProtected bool
	intent                 int
	object                 int
	operational            int
	target                 int
	evasion                int
	scale                  int
	independentOperational int
	independentTarget      int
	independentEvasion     int
	independentScale       int
	intentStarts           []string
	intentPatterns         compactRuleIntentPatterns
}

type compiledContexts map[rules.ContextKind]int

type ruleIntentStartBuckets struct {
	ascii [26][]string
	other map[rune][][]rune
}

var classifierCategoryOrder = []rules.Category{
	rules.CategoryCredentialTheft,
	rules.CategoryPhishing,
	rules.CategoryMalware,
	rules.CategoryRansomware,
	rules.CategoryExploitation,
	rules.CategoryDisruption,
	rules.CategoryExfiltration,
	rules.CategoryEvasion,
}

// Classifier is immutable after construction and safe for concurrent use.
type Classifier struct {
	version                string
	rules                  []compiledRule
	contexts               compiledContexts
	standardMatcher        *literalMatcher
	compactMatcher         *literalMatcher
	categoryRules          map[rules.Category][]int
	signalCount            int
	implementationRequest  int
	implementationStarts   []string
	implementationPatterns compactRuleIntentPatterns
	outcomeRequest         int
	metaOverride           compiledMetaOverrideSignals
	semanticProfiles       []compiledSemanticProfile
	directiveIntentStarts  ruleIntentStartBuckets
}

// New validates and precompiles a private matcher snapshot.
func New(set *rules.RuleSet) (*Classifier, error) {
	if err := rules.Validate(set); err != nil {
		return nil, fmt.Errorf("compile classifier: %w", err)
	}
	c := &Classifier{
		version:       set.Version,
		rules:         make([]compiledRule, 0, len(set.Rules)),
		contexts:      make(compiledContexts, len(set.Contexts)),
		categoryRules: make(map[rules.Category][]int, len(classifierCategoryOrder)),
	}
	standardBuilder := newMatcherBuilder()
	compactBuilder := newMatcherBuilder()
	nextSignal := 0
	compileGroup := func(terms rules.Terms, label string) (int, error) {
		signalID := nextSignal
		nextSignal++
		if err := addTerms(standardBuilder, compactBuilder, terms, signalID); err != nil {
			return 0, fmt.Errorf("compile classifier %s: %w", label, err)
		}
		return signalID, nil
	}
	compileOptionalGroup := func(terms rules.Terms, label string) (int, error) {
		if len(terms.ZH) == 0 && len(terms.EN) == 0 {
			return -1, nil
		}
		return compileGroup(terms, label)
	}
	for _, source := range set.Rules {
		compiled := compiledRule{
			id:                     source.ID,
			category:               source.Category,
			baseScore:              source.BaseScore,
			hardFloor:              source.HardFloor,
			authorizationProtected: source.AuthorizationProtected,
			intentStarts:           normalizedTermValues(source.Intent),
		}
		compiled.intentPatterns = compileCompactRuleIntentPatterns(compiled.intentStarts)
		groups := []struct {
			source rules.Terms
			target *int
			name   string
		}{
			{source.Intent, &compiled.intent, "intent"},
			{source.Object, &compiled.object, "object"},
			{source.Operational, &compiled.operational, "operational"},
			{source.Target, &compiled.target, "target"},
			{source.Evasion, &compiled.evasion, "evasion"},
			{source.Scale, &compiled.scale, "scale"},
		}
		for _, group := range groups {
			signalID, err := compileGroup(group.source, "rule "+source.ID+" "+group.name)
			if err != nil {
				return nil, err
			}
			*group.target = signalID
		}
		independentGroups := []struct {
			source rules.Terms
			target *int
			name   string
		}{
			{source.Operational, &compiled.independentOperational, "independent operational"},
			{source.Target, &compiled.independentTarget, "independent target"},
			{source.Evasion, &compiled.independentEvasion, "independent evasion"},
			{source.Scale, &compiled.independentScale, "independent scale"},
		}
		coveredGroups := []rules.Terms{source.Intent, source.Object}
		for _, group := range independentGroups {
			terms := independentQualifierTerms(group.source, coveredGroups...)
			signalID, err := compileOptionalGroup(terms, "rule "+source.ID+" "+group.name)
			if err != nil {
				return nil, err
			}
			*group.target = signalID
			coveredGroups = append(coveredGroups, group.source)
		}
		c.rules = append(c.rules, compiled)
		c.categoryRules[compiled.category] = append(c.categoryRules[compiled.category], len(c.rules)-1)
	}
	c.directiveIntentStarts = compileRuleIntentStarts(c.rules)
	contextOrder := []rules.ContextKind{
		rules.ContextDefensive,
		rules.ContextRemediation,
		rules.ContextCTF,
		rules.ContextLab,
		rules.ContextAuthorized,
		rules.ContextStaticAnalysis,
		rules.ContextIncidentResponse,
		rules.ContextHighLevel,
	}
	for _, kind := range contextOrder {
		terms := set.Contexts[kind]
		signalID, err := compileGroup(terms, "context "+string(kind))
		if err != nil {
			return nil, err
		}
		c.contexts[kind] = signalID
	}
	implementationTerms := rules.Terms{
		ZH: []string{"现在给出代码", "现在写代码", "把它实现出来", "继续给完整步骤", "给我代码", "实现上述内容", "实现上面的方案", "按上面方案开始写", "按上述方案开始写", "给出源码", "展示源码", "开始实现", "用 python", "用 powershell", "用 bash", "用 go", "加入错误处理", "逐步给出命令", "把命令列出来", "给出实际步骤", "给出执行流程", "给出可操作方案", "制定执行计划", "制定投放计划", "具体怎么做", "实施步骤"},
		EN: []string{"now give working code", "now write the code", "give me the code", "implement it", "implement the above", "implement the plan above", "now provide steps", "turn that into code", "now give code", "show me the source", "show the source", "provide the source", "start implementing", "write the implementation", "use python", "in python", "use powershell", "in powershell", "use bash", "in bash", "use go", "in go", "include error handling", "show the commands", "step by step", "practical steps", "actionable steps", "practical workflow", "operational workflow", "execution plan", "deployment plan", "rollout plan", "implementation plan", "lay out how to"},
	}
	implementationSignal, err := compileGroup(implementationTerms, "implementation request")
	if err != nil {
		return nil, err
	}
	c.implementationRequest = implementationSignal
	c.implementationStarts = normalizedTermValues(implementationTerms)
	c.implementationPatterns = compileCompactRuleIntentPatterns(c.implementationStarts)
	outcomeTerms := rules.Terms{
		ZH: []string{"最终结果", "最终要", "最终应", "最终状态", "最终需要", "目标结果", "目标是", "成功标准", "完成后", "交付后", "结果应", "结果要", "期望结果", "预期结果", "所需终态", "要求的终态"},
		EN: []string{"desired outcome", "desired result", "required outcome", "required result", "specific outcome", "target outcome", "end result", "end state", "end-state", "required end state", "final outcome", "final state", "success means", "success is", "success criteria", "at completion", "when finished", "by the end", "once complete", "once finished"},
	}
	outcomeSignal, err := compileGroup(outcomeTerms, "outcome request")
	if err != nil {
		return nil, err
	}
	c.outcomeRequest = outcomeSignal
	metaTargets := []*int{
		&c.metaOverride.hierarchy,
		&c.metaOverride.refusalSuppression,
		&c.metaOverride.unrestrictedMode,
		&c.metaOverride.directCompletion,
		&c.metaOverride.scopeLaundering,
		&c.metaOverride.outputControl,
		&c.metaOverride.secretDisclosure,
		&c.metaOverride.negativeAuthorization,
		&c.metaOverride.benchmarkCoercion,
		&c.metaOverride.persistentInjection,
		&c.metaOverride.personaTakeover,
		&c.metaOverride.agenticEscalation,
	}
	for index, terms := range metaOverrideTermGroups() {
		signalID, compileErr := compileGroup(terms, fmt.Sprintf("meta override family %d", index+1))
		if compileErr != nil {
			return nil, compileErr
		}
		*metaTargets[index] = signalID
	}
	for _, category := range classifierCategoryOrder {
		profile, ok := set.Semantics[category]
		if !ok {
			continue
		}
		compiled := compiledSemanticProfile{
			index:        uint8(len(c.semanticProfiles)),
			category:     category,
			intentStarts: append(normalizedTermValues(profile.Harm), normalizedTermValues(profile.Action)...),
		}
		categorySources := make([]rules.Rule, 0, len(c.categoryRules[category]))
		for _, ruleIndex := range c.categoryRules[category] {
			compiled.intentStarts = append(compiled.intentStarts, c.rules[ruleIndex].intentStarts...)
			categorySources = append(categorySources, set.Rules[ruleIndex])
		}
		compiled.intentStarts = uniqueSorted(compiled.intentStarts)
		compiled.intentPatterns = compileCompactRuleIntentPatterns(compiled.intentStarts)
		evidenceTerms := buildSemanticEvidenceTerms(profile, categorySources, implementationTerms, outcomeTerms)
		compiled.evidence = make([]compiledSemanticEvidence, len(evidenceTerms))
		for index, evidenceTerm := range evidenceTerms {
			signalID, compileErr := compileGroup(evidenceTerm.terms, "semantic "+string(category)+" evidence")
			if compileErr != nil {
				return nil, compileErr
			}
			compiled.evidence[index] = compiledSemanticEvidence{
				id: uint16(index), signalID: signalID, dimensionMask: evidenceTerm.dimensionMask,
			}
		}
		linkLongerSemanticEvidence(&compiled, evidenceTerms)
		intentDimensionMask := uint16(1)<<semanticHarm | uint16(1)<<semanticAction
		for _, evidence := range compiled.evidence {
			if evidence.dimensionMask&intentDimensionMask != 0 {
				compiled.intentSignals = append(compiled.intentSignals, evidence.signalID)
			}
		}
		for dimension, kind := range semanticDimensionKinds {
			compiled.result[dimension] = Evidence{ID: compiled.id() + ":" + kind, Kind: kind}
		}
		c.semanticProfiles = append(c.semanticProfiles, compiled)
	}
	c.standardMatcher = standardBuilder.build()
	c.compactMatcher = compactBuilder.build()
	c.signalCount = nextSignal
	return c, nil
}

func compileRuleIntentStarts(compiledRules []compiledRule) ruleIntentStartBuckets {
	var buckets ruleIntentStartBuckets
	otherValues := make(map[rune][]string)
	for _, rule := range compiledRules {
		for _, intent := range rule.intentStarts {
			intent = strings.TrimSpace(intent)
			if intent == "" {
				continue
			}
			if isASCIIStringLocal(intent) {
				first := intent[0]
				if first >= 'A' && first <= 'Z' {
					first += 'a' - 'A'
				}
				if first >= 'a' && first <= 'z' {
					bucket := first - 'a'
					buckets.ascii[bucket] = append(buckets.ascii[bucket], intent)
					continue
				}
			}
			intentRunes := []rune(intent)
			if len(intentRunes) == 0 {
				continue
			}
			first := intentRunes[0]
			if first >= 'A' && first <= 'Z' {
				first += 'a' - 'A'
			}
			otherValues[first] = append(otherValues[first], intent)
		}
	}
	for bucket := range buckets.ascii {
		buckets.ascii[bucket] = uniqueSorted(buckets.ascii[bucket])
		sort.Slice(buckets.ascii[bucket], func(left, right int) bool {
			if len(buckets.ascii[bucket][left]) != len(buckets.ascii[bucket][right]) {
				return len(buckets.ascii[bucket][left]) > len(buckets.ascii[bucket][right])
			}
			return buckets.ascii[bucket][left] < buckets.ascii[bucket][right]
		})
	}
	if len(otherValues) != 0 {
		buckets.other = make(map[rune][][]rune, len(otherValues))
	}
	for first, values := range otherValues {
		values = uniqueSorted(values)
		sort.Slice(values, func(left, right int) bool {
			if len(values[left]) != len(values[right]) {
				return len(values[left]) > len(values[right])
			}
			return values[left] < values[right]
		})
		compiled := make([][]rune, len(values))
		for index, value := range values {
			compiled[index] = []rune(value)
		}
		buckets.other[first] = compiled
	}
	return buckets
}

// Analyze scores parts under the balanced policy defaults.
func (c *Classifier) Analyze(parts []string) Result {
	return c.Classify(parts, ModeBalanced, DefaultThresholds())
}

// Classify scores parts and derives an action for the selected mode.
func (c *Classifier) Classify(parts []string, mode Mode, thresholds Thresholds) Result {
	return c.ClassifyWithPolicy(parts, mode, thresholds, DefaultPolicy())
}

// ClassifyWithPolicy scores parts with explicit configurable context and
// authorization behavior. Callers should start from DefaultPolicy and override
// only fields exposed by their validated configuration. This roleless entry
// point is conservatively attributed as non-user/untrusted; role-aware callers
// may upgrade only a proven user-content winner.
func (c *Classifier) ClassifyWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy) Result {
	return withFindingOrigin(
		c.classifyWithPolicy(parts, mode, thresholds, policy, false),
		FindingOriginNonUserOrUntrusted,
	)
}

// classifyWithPolicy keeps role provenance out of the public API while
// allowing a provider-native structured tool payload to retain one whole-part
// semantic window. Ordinary user text never receives that exception.
func (c *Classifier) classifyWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy, structuredToolPayload bool) Result {
	return c.classifyWithPolicyCaptured(parts, mode, thresholds, policy, structuredToolPayload, nil)
}

func (c *Classifier) classifyWithPolicyCaptured(parts []string, mode Mode, thresholds Thresholds, policy Policy, structuredToolPayload bool, capture *classificationSignalFacts) Result {
	if c == nil {
		return Result{PolicyVersion: ClassifierPolicyVersion, PolicySHA256: ClassifierPolicySHA256, Action: ActionAllow}
	}
	if mode == ModeOff {
		return Result{
			PolicyVersion: ClassifierPolicyVersion, PolicySHA256: ClassifierPolicySHA256,
			RuleSetVersion: c.version, Action: ActionAllow,
		}
	}
	thresholds = validThresholdsOrDefault(thresholds)
	signals := make([]bool, c.signalCount)
	var previousSignals, currentSignals, scratchSignals []bool
	var previousRunes, currentRunes, scratchRunes []rune
	var previousRunesUsed, currentRunesUsed, scratchRunesUsed int
	defer func() {
		putNormalizedRuneBuffer(previousRunes, previousRunesUsed)
		putNormalizedRuneBuffer(currentRunes, currentRunesUsed)
		putNormalizedRuneBuffer(scratchRunes, scratchRunesUsed)
	}()
	var normalizerScratch normalizationScratch
	var compactScratch []bool
	// Family bits accumulate across the current explicitly linked meta chain so
	// a long chain cannot evict its first unique signal. Only the raw text window
	// is capped at eight parts; the signal set itself is bounded by signalCount.
	metaTailSignals := make([]bool, c.signalCount)
	metaTailParts := make([]string, 0, 8)
	metaTailActive := false
	metaTailLastPart := ""
	metaTailWindowComplete := true
	pendingMetaPrefix := ""
	pendingMetaPrefixSignals := make([]bool, c.signalCount)
	bestMeta := metaOverrideAssessment{}
	bestAdjacentReversal := Result{}
	hasAdjacentReversal := false
	bestReactivatedQuotedReferent := Result{}
	hasReactivatedQuotedReferent := false
	adjacentReversalCandidates := 0
	adjacentReversalTerminal := false
	inertQuotedSafetyReview := false
	quotedOrInertSuppressed := false
	var currentDirectives analyzedDirectives
	directivesReady := false
	finishResult := func(result Result) Result {
		if directivesReady && currentDirectives.occurrenceBudgetExhausted {
			result.Truncated = true
		}
		best := result
		if !inertQuotedSafetyReview && hasAdjacentReversal && roleResultBetter(bestAdjacentReversal, best) {
			best = bestAdjacentReversal
		}
		if !inertQuotedSafetyReview && hasReactivatedQuotedReferent && roleResultBetter(bestReactivatedQuotedReferent, best) {
			best = bestReactivatedQuotedReferent
		}
		best.Truncated = best.Truncated || result.Truncated
		ensureResultDecisionExplanation(&best)
		if quotedOrInertSuppressed {
			markQuotedOrInertSuppressed(&best)
		}
		return best
	}
	partCount := 0
	currentPartIndex := -1
	previousRawPart := ""
	remainingBytes := maxClassifierInputBytes
	truncated := false
	resetMetaTail := func() {
		clear(metaTailSignals)
		metaTailParts = metaTailParts[:0]
		metaTailActive = false
		metaTailLastPart = ""
		metaTailWindowComplete = true
	}
	mergeMetaTailSignals := func(source []bool) {
		for signalID, matched := range source {
			if matched {
				metaTailSignals[signalID] = true
			}
		}
	}
	clearPendingMetaPrefix := func() {
		pendingMetaPrefix = ""
		clear(pendingMetaPrefixSignals)
	}
	appendMetaTailPart := func(partText string) {
		if len(metaTailParts) == cap(metaTailParts) {
			copy(metaTailParts, metaTailParts[1:])
			metaTailParts = metaTailParts[:len(metaTailParts)-1]
			metaTailWindowComplete = false
		}
		metaTailParts = append(metaTailParts, partText)
		metaTailLastPart = partText
	}
	finalizeMetaTail := func() {
		if !metaTailActive {
			return
		}
		metaTailText := ""
		if len(metaTailParts) == 1 {
			metaTailText = metaTailParts[0]
		} else if len(metaTailParts) > 1 {
			metaTailText = strings.Join(metaTailParts, "\n")
		}
		metaContext := c.matchContextsWithPolicy(metaTailSignals, policy.Allow)
		assessment := c.assessMetaOverride(
			[][]bool{metaTailSignals}, metaTailText, metaContext,
			metaTailWindowComplete && !truncated,
		)
		if (assessment.controlPlaneBlock && !bestMeta.controlPlaneBlock) ||
			(assessment.controlPlaneBlock == bestMeta.controlPlaneBlock &&
				(assessment.score > bestMeta.score ||
					(assessment.score == bestMeta.score && len(assessment.evidence) > len(bestMeta.evidence)))) {
			bestMeta = assessment
		}
		resetMetaTail()
	}
	for partIndex, part := range parts {
		if partIndex >= maxClassifierParts || remainingBytes <= 0 {
			truncated = true
			break
		}
		consumedBytes := len(part)
		if consumedBytes > remainingBytes {
			consumedBytes = remainingBytes
			part = validUTF8Prefix(part, consumedBytes)
			truncated = true
		}
		remainingBytes -= consumedBytes
		reusedPreviousPart := partCount > 0 && part == previousRawPart && len(currentRunes) != 0
		if scratchRunes == nil {
			scratchRunes = takeNormalizedRuneBuffer()
		}
		var views normalizedViews
		if reusedPreviousPart {
			if cap(scratchRunes) < len(currentRunes) {
				scratchRunes = make([]rune, len(currentRunes))
			} else {
				scratchRunes = scratchRunes[:len(currentRunes)]
			}
			copy(scratchRunes, currentRunes)
			views = normalizedViews{standardRunes: scratchRunes, storageUsed: len(scratchRunes)}
		} else {
			views = normalizePartsInto([]string{part}, scratchRunes, &normalizerScratch)
		}
		bufferUsed := views.storageUsed
		if scratchRunesUsed > bufferUsed {
			bufferUsed = scratchRunesUsed
		}
		truncated = truncated || views.truncated
		if len(views.standardRunes) == 0 {
			scratchRunes = views.standardRunes
			scratchRunesUsed = bufferUsed
			continue
		}
		if scratchSignals == nil {
			scratchSignals = make([]bool, c.signalCount)
		} else if !reusedPreviousPart {
			clear(scratchSignals)
		}
		if reusedPreviousPart {
			copy(scratchSignals, currentSignals)
		} else {
			if compactScratch == nil && c.compactMatcher != nil {
				compactScratch = make([]bool, c.compactMatcher.maxPatternLength)
			}
			c.standardMatcher.match(views.standardRunes, scratchSignals)
			c.compactMatcher.matchCompactWithScratch(views.standardRunes, scratchSignals, compactScratch)
		}
		if partCount > 0 && !adjacentReversalTerminal {
			corePotential := adjacentRuleCorePotential(c.rules, currentSignals, scratchSignals)
			if corePotential && runesMayContainNegation(currentRunes) {
				if len(currentRunes)+1+len(views.standardRunes) > maxAdjacentNegationRunes {
					candidate, _ := c.adjacentNegationOverflowResultForSignals(currentSignals, scratchSignals, mode, thresholds, structuredToolPayload)
					adjacentReversalCandidates++
					adjacentReversalTerminal = true
					// This caps an internal proof reconstruction after a concrete
					// intent/object core is already known. It is not input truncation:
					// marking it as such would let balanced routing discard the hard block.
					if !hasAdjacentReversal || roleResultBetter(candidate, bestAdjacentReversal) {
						bestAdjacentReversal = candidate
						hasAdjacentReversal = true
					}
				} else if rule, reconstruct := c.adjacentNegationNeedsReconstruction(currentRunes, currentSignals, scratchSignals); reconstruct {
					adjacentReversalCandidates++
					var candidate Result
					if adjacentReversalCandidates > maxAdjacentNegationCandidates {
						var found bool
						candidate, found = c.adjacentNegationOverflowResultForSignals(currentSignals, scratchSignals, mode, thresholds, structuredToolPayload)
						if !found {
							candidate = c.adjacentNegationOverflowResult(rule, mode, thresholds, structuredToolPayload)
						}
						adjacentReversalTerminal = true
						// Candidate-budget exhaustion has the same fail-active semantics as
						// the rune cap above and must not masquerade as incomplete inspection.
					} else {
						// adjacentNegationNeedsReconstruction has already proved that the
						// most recent intent-bearing clause is an active negation reversal,
						// while the next part supplies the matching harmful object. Re-running
						// ordinary directive admission over the joined text can reinterpret
						// the reversal as a plain prohibition and discard that proof. Preserve
						// the bounded proof as the fail-active candidate directly.
						candidate = c.adjacentNegationOverflowResult(rule, mode, thresholds, structuredToolPayload)
						adjacentReversalTerminal = true
					}
					if !hasAdjacentReversal || roleResultBetter(candidate, bestAdjacentReversal) {
						bestAdjacentReversal = candidate
						hasAdjacentReversal = true
					}
				}
			}
		}
		currentHasMeta := c.hasMetaOverrideSignal(scratchSignals)
		if currentHasMeta {
			partText := string(views.standardRunes)
			pendingLinked := false
			if !metaTailActive && pendingMetaPrefix != "" {
				metaTailActive = true
				mergeMetaTailSignals(pendingMetaPrefixSignals)
				appendMetaTailPart(pendingMetaPrefix)
				pendingLinked = true
			}
			clearPendingMetaPrefix()
			linked := pendingLinked
			if metaTailActive && !linked {
				linked = metaOverridePartsLinked(metaTailLastPart, partText)
				if !linked {
					linked = metaOverrideQuoteBoundaryOpen(strings.Join(metaTailParts, "\n"))
				}
			}
			if !linked {
				finalizeMetaTail()
			}
			metaTailActive = true
			mergeMetaTailSignals(scratchSignals)
			appendMetaTailPart(partText)
		} else {
			partText := ""
			if metaTailActive {
				partText = string(views.standardRunes)
				signalsLinked := metaOverridePartsLinked(metaTailLastPart, partText)
				if !signalsLinked {
					signalsLinked = metaOverrideQuoteBoundaryOpen(strings.Join(metaTailParts, "\n"))
				}
				if signalsLinked {
					mergeMetaTailSignals(scratchSignals)
				}
				// Keep the complete bounded tail, including unknown clauses. The
				// structural decision requires the last effective directive to be
				// explicitly inert; silently dropping an unrecognized final segment
				// would let terse imperatives such as "Deploy." sanitize a quoted
				// persistent override. The eight-part cap prevents connector floods.
				if len(metaTailParts) < cap(metaTailParts) {
					appendMetaTailPart(partText)
				} else {
					metaTailWindowComplete = false
					finalizeMetaTail()
				}
			}
			if !metaTailActive {
				if partText == "" && metaOverrideMayContainQuotedPrefix(part) {
					partText = string(views.standardRunes)
				}
				if metaOverridePotentialQuotedPrefix(partText) {
					pendingMetaPrefix = partText
					copy(pendingMetaPrefixSignals, scratchSignals)
				} else {
					clearPendingMetaPrefix()
				}
			}
		}
		for signalID, matched := range scratchSignals {
			if matched {
				signals[signalID] = true
			}
		}
		previousRawPart = part
		previousSignals, currentSignals, scratchSignals = currentSignals, scratchSignals, previousSignals
		previousRunes, currentRunes, scratchRunes = currentRunes, views.standardRunes, previousRunes
		previousRunesUsed, currentRunesUsed, scratchRunesUsed = currentRunesUsed, bufferUsed, previousRunesUsed
		currentPartIndex = partIndex
		partCount++
	}
	finalizeMetaTail()
	currentText := string(currentRunes)
	previousQuotedReferent := ""
	previousInertQuotedSafetyReview := false
	if partCount > 1 && !truncated {
		previousQuotedReferent, previousInertQuotedSafetyReview =
			c.inertQuotedSafetyReviewReferent(string(previousRunes))
	}
	quotedReviewImplementationFollowUp := previousInertQuotedSafetyReview &&
		c.hasAffirmativeQuotedReviewFollowUp(currentText)
	if quotedReviewImplementationFollowUp {
		bestReactivatedQuotedReferent = c.classifyWithPolicy(
			[]string{previousQuotedReferent}, mode, thresholds, policy, structuredToolPayload,
		)
		hasReactivatedQuotedReferent = true
	}
	inertQuotedSafetyReview = !truncated && c.isInertQuotedSafetyReview(currentText) &&
		c.priorPartsAllowInertQuotedSafetyReview(parts, currentPartIndex, mode, thresholds, policy)
	quotedOrInertSuppressed = inertQuotedSafetyReview ||
		(previousInertQuotedSafetyReview && !quotedReviewImplementationFollowUp)
	if capture != nil {
		capture.harmConflict = false
		if cap(capture.signals) < c.signalCount {
			capture.signals = make([]bool, c.signalCount)
		} else {
			capture.signals = capture.signals[:c.signalCount]
			clear(capture.signals)
		}
		if cap(capture.unnegatedRuleIntents) < len(c.rules) {
			capture.unnegatedRuleIntents = make([]bool, len(c.rules))
		} else {
			capture.unnegatedRuleIntents = capture.unnegatedRuleIntents[:len(c.rules)]
			clear(capture.unnegatedRuleIntents)
		}
		for _, destination := range []*[]bool{
			&capture.matchedSemanticIntents,
			&capture.unnegatedSemanticIntents,
			&capture.semanticAgencies,
		} {
			if cap(*destination) < len(c.semanticProfiles) {
				*destination = make([]bool, len(c.semanticProfiles))
			} else {
				*destination = (*destination)[:len(c.semanticProfiles)]
				clear(*destination)
			}
		}
		if cap(capture.semanticCoreEvidence) < len(c.semanticProfiles) {
			capture.semanticCoreEvidence = make([]uint8, len(c.semanticProfiles))
		} else {
			capture.semanticCoreEvidence = capture.semanticCoreEvidence[:len(c.semanticProfiles)]
			clear(capture.semanticCoreEvidence)
		}
		if partCount > 0 {
			copy(capture.signals, currentSignals)
			capture.harmConflict = hasExplicitHarmConflict(currentText)
			needsIntentAnalysis := false
			for _, rule := range c.rules {
				if currentSignals[rule.intent] {
					needsIntentAnalysis = true
					break
				}
			}
			if needsIntentAnalysis {
				currentDirectives = c.analyzeDirectives(currentRunes, policy)
				directivesReady = true
			}
			for ruleIndex, rule := range c.rules {
				if currentSignals[rule.intent] && !currentDirectives.ruleIntentIsOnlyNegated(ruleIndex, rule) {
					capture.unnegatedRuleIntents[ruleIndex] = true
				}
			}
			for profileIndex, profile := range c.semanticProfiles {
				dimensions := c.semanticDimensions(profile, [][]bool{currentSignals})
				capture.semanticAgencies[profileIndex] = dimensions.harm || dimensions.action || dimensions.outcome
				capture.semanticCoreEvidence[profileIndex] = round8SemanticCoreEvidenceBits(profile.category, currentText)
				if (dimensions.harm || dimensions.action) && containsRuleIntent(currentText, profile.intentStarts) {
					capture.matchedSemanticIntents[profileIndex] = true
					if len(currentText) > maxCompactIntentProofBytes || containsUnnegatedRuleIntentPrepared(currentText, profile.intentStarts, profile.intentPatterns) {
						capture.unnegatedSemanticIntents[profileIndex] = true
					}
				}
			}
		}
	}
	currentContext := ContextFlags{}
	if partCount > 0 {
		currentContext = c.matchContextsWithPolicy(currentSignals, policy.Allow)
	}
	context := currentContext
	carriedCTFOrLab := false
	carriedAuthorized := false
	if partCount > 1 {
		prior := c.matchContextsWithPolicy(previousSignals, policy.Allow)
		carriedCTFOrLab = prior.CTFOrLab
		carriedAuthorized = prior.Authorized
		context.CTFOrLab = context.CTFOrLab || prior.CTFOrLab
		context.Authorized = context.Authorized || prior.Authorized
	}
	result := Result{
		PolicyVersion:  ClassifierPolicyVersion,
		PolicySHA256:   ClassifierPolicySHA256,
		RuleSetVersion: c.version,
		Action:         ActionAllow,
		Context:        context,
		Truncated:      truncated,
	}
	if partCount == 0 {
		result.Action = actionFor(mode, 0, thresholds)
		return result
	}

	type candidate struct {
		score       int
		category    rules.Category
		ruleID      string
		ruleIDs     []string
		evidence    []Evidence
		occurrences []EvidenceOccurrence
		explanation DecisionExplanation
	}
	candidates := make([]candidate, 0, 8)
	var categoryHasCandidate [8]bool
	previousFollowUpEligible := partCount > 1 && !previousInertQuotedSafetyReview && followUpEligible(previousRunes)
	var previousDirectives analyzedDirectives
	previousDirectivesReady := false
	previousHarmConflict := false
	previousHarmConflictReady := false
	for ruleIndex, rule := range c.rules {
		if inertQuotedSafetyReview {
			break
		}
		targetedRound8Rule := isRound8TargetedRule(rule.id)
		intent := signals[rule.intent]
		object := signals[rule.object]
		current := currentSignals
		if (current[rule.intent] || current[rule.object]) && !directivesReady {
			currentDirectives = c.analyzeDirectives(currentRunes, policy)
			directivesReady = true
		}
		directiveMatch := ruleDirectiveMatch{}
		if targetedRound8Rule && directivesReady {
			directiveMatch = c.bestRuleDirectiveMatch(ruleIndex, rule, currentDirectives)
		} else if !targetedRound8Rule {
			// Round 8 physical occurrence ownership is intentionally limited to
			// the five broad-vocabulary production-FP rules. Mature narrow rules
			// retain their established whole-field signal path, including a later
			// unnegated intent after an earlier prohibition. Applying the physical
			// window winner to every rule both lost that recall and multiplied the
			// hot-path occurrence work by the full ruleset size.
			mask := ruleDimensionMaskForSignalSet(rule, current)
			core := current[rule.intent] && current[rule.object] &&
				directivesReady && !c.ruleCoreIsOnlyNegated(currentDirectives, ruleIndex, rule) &&
				!isLegitimateCategoryWorkflow(rule.category, currentText)
			directiveMatch = ruleDirectiveMatch{
				found:                 mask != 0,
				coreComplete:          core,
				corePredicateComplete: core,
				activeDirective:       core,
				scopeCoherent:         true,
				dimensionMask:         mask,
				text:                  currentText,
				clauseCount:           1,
			}
		}
		objectQualifiedFallback := isCredentialObjectQualifiedFallback(rule, current) &&
			directiveMatch.has(ruleDimensionObject) && !isLegitimateCategoryWorkflow(rule.category, directiveMatch.text)
		disruptionServiceObjectFallback := rule.id == "DISRUPT-001" && directiveMatch.coreComplete
		if (!intent || !object) && !(directiveMatch.coreComplete && directiveMatch.derivedIntent) &&
			!objectQualifiedFallback && !disruptionServiceObjectFallback {
			continue
		}
		currentCore := directiveMatch.coreComplete
		if currentCore {
			currentCore = directiveMatch.activeDirective
		}
		priorStrongCore := false
		var priorCoreSignals []bool
		if partCount > 1 {
			prior := previousSignals
			if previousFollowUpEligible && prior[rule.intent] && prior[rule.object] && (rule.baseScore >= BalancedThreshold || prior[rule.target] || prior[rule.evasion] || prior[rule.scale]) {
				if !previousDirectivesReady {
					previousDirectives = c.analyzeDirectives(previousRunes, policy)
					previousDirectivesReady = true
				}
				priorMatch := c.bestRuleDirectiveMatch(ruleIndex, rule, previousDirectives)
				priorEligible := priorMatch.coreComplete && priorMatch.activeDirective && priorMatch.scopeCoherent
				if isRound8TargetedRule(rule.id) {
					priorEligible = priorMatch.hardFloorEligible
				}
				if priorEligible {
					priorStrongCore = true
					priorCoreSignals = prior
				}
			}
		}
		implementationFollowUp := current[c.implementationRequest] && priorStrongCore
		if !currentCore && !implementationFollowUp && !objectQualifiedFallback {
			continue
		}
		if isRound8TargetedRule(rule.id) && !directiveMatch.corePredicateComplete && !implementationFollowUp {
			// Round 8 rules must not leak a named audit finding from a partial
			// generic-vocabulary core. Their complete hostile relationship is the
			// admission predicate, not merely a balanced-score cap.
			continue
		}
		coreCoLocated := directiveMatch.scopeCoherent && directiveMatch.coreComplete
		score := rule.baseScore
		evidence := []Evidence{{ID: rule.id + ":object", Kind: "object"}}
		if objectQualifiedFallback {
			// Credential artifacts combined with operational, real-target, and
			// evasion evidence form four independent signals even when an
			// unfamiliar theft verb is used. A missing intent still receives a
			// conservative penalty and a bare credential keyword never blocks.
			score -= 25
		} else {
			evidence = append(evidence, Evidence{ID: rule.id + ":intent", Kind: "intent"})
		}
		if !objectQualifiedFallback && !coreCoLocated {
			score -= 20
		}
		corePredicateScore := score
		qualifiers := 0
		// A same-turn request for code, commands, an execution plan, or a
		// practical workflow is operational evidence too. Previously this signal
		// was used only for a later follow-up, which let explicit abuse phrased as
		// "give me a plan to ..." remain below the balanced threshold.
		operational := directiveMatch.has(ruleDimensionOperational) || current[c.implementationRequest] || implementationFollowUp
		target := directiveMatch.has(ruleDimensionTarget)
		evasion := directiveMatch.has(ruleDimensionEvasion)
		scale := directiveMatch.has(ruleDimensionScale)
		if implementationFollowUp && priorCoreSignals != nil {
			target = target || signalMatched(priorCoreSignals, rule.independentTarget)
			evasion = evasion || signalMatched(priorCoreSignals, rule.independentEvasion)
			scale = scale || signalMatched(priorCoreSignals, rule.independentScale)
		}
		if operational {
			score += 20
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":operational", Kind: "operational"})
		}
		if target {
			score += 18
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":target", Kind: "target"})
		}
		if evasion {
			score += 16
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":evasion", Kind: "evasion"})
		}
		if scale {
			score += 16
			qualifiers++
			evidence = append(evidence, Evidence{ID: rule.id + ":scale", Kind: "scale"})
		}
		if qualifiers >= 2 {
			score += 5
		}
		strongQualifiers := 0
		if targetedRound8Rule {
			strongQualifiers = strongRuleQualifierCount(rule.id, directiveMatch)
		}
		hardFloorEligible := qualifiers > 0
		hardFloorReason := hardFloorReasonNone
		balancedEligible := true
		if targetedRound8Rule {
			// The five production false-positive rules use unusually broad
			// development vocabulary and therefore require the stronger Round 8
			// ownership/core predicate. Other mature rules keep their existing
			// curated one-qualifier floor so the established malicious matrix does
			// not lose recall merely because its rule vocabulary is already narrow.
			// A prior Round 8 core reaches priorStrongCore only after ownership,
			// active-scope, and hard-floor admission have all succeeded. One fresh
			// implementation qualifier is therefore enough for an explicit adjacent
			// follow-up; requiring two new qualifiers discarded the already-owned
			// target/theft relationship from the prior directive.
			directMatchEligible := directiveMatch.hardFloorEligible
			followUpEligible := implementationFollowUp && qualifiers >= 1
			hardFloorEligible = directMatchEligible || followUpEligible
			balancedEligible = round8RuleBalancedEligible(rule.id, directiveMatch, strongQualifiers) ||
				followUpEligible
			switch {
			case directMatchEligible:
				hardFloorReason = directiveMatch.hardFloorReason
			case followUpEligible:
				hardFloorReason = hardFloorReasonImplementationFollowUpToOwnedPriorCore
			}
		} else if hardFloorEligible {
			hardFloorReason = hardFloorReasonCompleteCoreWithIndependentQualifier
		}
		hardFloorApplied := false
		if hardFloorEligible && rule.hardFloor > score {
			score = rule.hardFloor
			hardFloorApplied = true
		}
		if !balancedEligible && score >= thresholds.BalancedBlock {
			score = thresholds.BalancedBlock - 1
		}
		effectiveContext := context
		priorTargetConflict := implementationFollowUp && priorCoreSignals != nil && signalMatched(priorCoreSignals, rule.target)
		if current[rule.target] || priorTargetConflict {
			if carriedCTFOrLab && !currentContext.CTFOrLab {
				effectiveContext.CTFOrLab = false
			}
			if carriedAuthorized && !currentContext.Authorized {
				effectiveContext.Authorized = false
			}
		}
		priorHarmConflict := false
		if implementationFollowUp {
			if !previousHarmConflictReady {
				previousHarmConflict = hasExplicitHarmConflict(string(previousRunes))
				previousHarmConflictReady = true
			}
			priorHarmConflict = previousHarmConflict
		}
		if hasExplicitHarmConflict(currentText) || priorHarmConflict {
			effectiveContext.Authorized = false
			effectiveContext.CTFOrLab = false
		}
		authorizationProtected := rule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(rule.category)
		contradictoryDirective := false
		if context != (ContextFlags{}) {
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes, policy)
				directivesReady = true
			}
			contradictoryDirective = c.hasRuleContradictoryDirective(currentDirectives, ruleIndex, ruleIndex, rule, policy.Allow)
		}
		if contradictoryDirective {
			// Scoped authorization and named lab boundaries are affirmative scope
			// signals, not generic safety labels. Preserve them for categories where
			// authorization is an accepted exception; protected categories still
			// ignore these deductions below.
			effectiveContext = ContextFlags{
				CTFOrLab:   effectiveContext.CTFOrLab,
				Authorized: effectiveContext.Authorized,
			}
		}
		if implementationFollowUp && !(currentContext.Defensive && currentContext.StaticAnalysis) {
			effectiveContext = ContextFlags{
				CTFOrLab:   effectiveContext.CTFOrLab,
				Authorized: effectiveContext.Authorized,
			}
		}
		scoreBeforeContext := score
		baselineContextScore := applyContextDeductions(scoreBeforeContext, context, authorizationProtected)
		score = applyContextDeductions(scoreBeforeContext, effectiveContext, authorizationProtected)
		contextAdjustment := baselineContextScore - scoreBeforeContext
		contradictionAdjustment := score - baselineContextScore
		strongOperationalAbuse := operational && (target || evasion || scale)
		genuineSafetyContext := effectiveContext.Defensive || effectiveContext.Remediation || effectiveContext.StaticAnalysis || effectiveContext.IncidentResponse || effectiveContext.HighLevel
		protectedOperationalAbuse := authorizationProtected && operational && !genuineSafetyContext
		unmitigatedOperationalAbuse := strongOperationalAbuse && effectiveContext == (ContextFlags{})
		if hardFloorEligible && rule.hardFloor > score && (unmitigatedOperationalAbuse || protectedOperationalAbuse) {
			score = rule.hardFloor
			hardFloorApplied = true
		}
		if !balancedEligible && score >= thresholds.BalancedBlock {
			score = thresholds.BalancedBlock - 1
		}
		explanation := DecisionExplanation{
			WinningRuleID:         rule.id,
			WinningCategory:       string(rule.category),
			CorePredicateComplete: directiveMatch.corePredicateComplete || implementationFollowUp,
			EvidenceDimensionMask: directiveMatch.dimensionMask,
			EvidenceSegmentCount:  1,
			CurrentTurnEvidence:   false,
			ContextAdjustment:     contextAdjustment,
			HardFloorApplied:      hardFloorApplied,
			ScoreBreakdown: ScoreBreakdown{
				CorePredicateScore:      corePredicateScore,
				QualifierScore:          qualifierScoreForRuleMatch(operational, target, evasion, scale, qualifiers),
				ScopeCoherenceScore:     0,
				OwnershipScore:          0,
				ActiveDirectiveScore:    0,
				ContextAdjustment:       contextAdjustment,
				ContradictionAdjustment: contradictionAdjustment,
				FinalScore:              score,
			},
		}
		if hardFloorApplied {
			explanation.HardFloorReason = hardFloorReason
		}
		var occurrences []EvidenceOccurrence
		if targetedRound8Rule {
			occurrences = evidenceOccurrencesForMatch(rule.id, directiveMatch)
		}
		explanation.EvidenceOccurrenceCount = len(occurrences)
		candidates = append(candidates, candidate{
			score: score, category: rule.category, ruleID: rule.id, evidence: evidence,
			occurrences: occurrences, explanation: explanation,
		})
		categoryHasCandidate[categoryPriority(rule.category)] = true
	}

	// A requested end state can describe clear abuse without using a familiar
	// action verb. Compose this semantic intent only inside one category and
	// require a harmful object plus two independent qualifier dimensions. This
	// lets related rules contribute complementary target/destination/scale
	// vocabulary while retaining the same multi-evidence floor as ordinary
	// rule candidates.
	if !inertQuotedSafetyReview && signalMatched(currentSignals, c.outcomeRequest) && !hasAffirmativeSafetyPurpose(currentText) {
		for _, category := range classifierCategoryOrder {
			if categoryHasCandidate[categoryPriority(category)] || isLegitimateCategoryWorkflow(category, currentText) {
				continue
			}
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes, policy)
				directivesReady = true
			}
			if c.categoryMatchedIntentsAreOnlyNegated(category, currentSignals, currentDirectives) {
				continue
			}
			providers := c.categoryOutcomeProviders(category, currentSignals)
			if providers.object < 0 || providers.qualifierCount() < 2 {
				continue
			}
			objectRule := c.rules[providers.object]
			if isRound8TargetedRule(objectRule.id) && !round8ComposedRuleCorePredicate(
				objectRule.id, currentText, providers.hasOperational,
				providers.target >= 0, providers.evasion >= 0, providers.scale >= 0,
			) {
				continue
			}
			score := 45
			corePredicateScore := score
			evidence := []Evidence{
				{ID: objectRule.id + ":object", Kind: "object"},
				{ID: objectRule.id + ":outcome", Kind: "intent"},
			}
			ruleIDs := []string{objectRule.id}
			appendQualifier := func(provider int, present bool, points int, kind string) {
				if !present {
					return
				}
				score += points
				qualifierRule := objectRule
				if provider >= 0 {
					qualifierRule = c.rules[provider]
					ruleIDs = append(ruleIDs, qualifierRule.id)
				}
				evidence = append(evidence, Evidence{ID: qualifierRule.id + ":" + kind, Kind: kind})
			}
			appendQualifier(providers.operational, providers.hasOperational, 20, "operational")
			appendQualifier(providers.target, providers.target >= 0, 18, "target")
			appendQualifier(providers.evasion, providers.evasion >= 0, 16, "evasion")
			appendQualifier(providers.scale, providers.scale >= 0, 16, "scale")
			if providers.qualifierCount() >= 2 {
				score += 5
			}
			qualifierScore := score - corePredicateScore

			effectiveContext := context
			if hasExplicitHarmConflict(currentText) {
				effectiveContext.Authorized = false
				effectiveContext.CTFOrLab = false
			}
			authorizationProtected := objectRule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(category)
			scoreBeforeContext := score
			score = applyContextDeductions(score, effectiveContext, authorizationProtected)
			contextAdjustment := score - scoreBeforeContext
			genuineSafetyContext := effectiveContext.Defensive || effectiveContext.Remediation || effectiveContext.StaticAnalysis || effectiveContext.IncidentResponse || effectiveContext.HighLevel
			hardFloorApplied := false
			if authorizationProtected && !genuineSafetyContext && score < HardThreshold {
				score = HardThreshold
				hardFloorApplied = true
			}
			score = clampScore(score)
			occurrences := syntheticEvidenceOccurrences(evidence, objectRule.id)
			explanation := DecisionExplanation{
				WinningRuleID:           objectRule.id,
				WinningCategory:         string(category),
				CorePredicateComplete:   true,
				EvidenceDimensionMask:   occurrenceDimensionMask(occurrences),
				EvidenceOccurrenceCount: len(occurrences),
				EvidenceSegmentCount:    1,
				ContextAdjustment:       contextAdjustment,
				HardFloorApplied:        hardFloorApplied,
				ScoreBreakdown: ScoreBreakdown{
					CorePredicateScore: corePredicateScore,
					QualifierScore:     qualifierScore,
					ContextAdjustment:  contextAdjustment,
					FinalScore:         score,
				},
			}
			if hardFloorApplied {
				explanation.HardFloorReason = hardFloorReasonOutcomeCompleteCoreWithTwoQualifiers
			}
			candidates = append(candidates, candidate{
				score:       score,
				category:    category,
				ruleIDs:     uniqueSorted(ruleIDs),
				evidence:    evidence,
				occurrences: occurrences,
				explanation: explanation,
			})
			categoryHasCandidate[categoryPriority(category)] = true
		}
	}

	// Category-level semantic profiles compose grammar-independent evidence
	// dimensions inside a bounded related window. They complement, rather than
	// weaken, rule-local intent/object candidates: an object, an agency/outcome
	// signal, a target or destination, and an additional consequence dimension
	// are all mandatory, and negative/legitimate workflow scope still wins.
	if !inertQuotedSafetyReview && len(c.semanticProfiles) != 0 {
		semanticSignals := [][]bool{currentSignals}
		previousText := ""
		partsLinked := false
		if partCount > 1 {
			previousText = string(previousRunes)
			partsLinked = semanticPartsLinked(previousText, currentText)
			if partsLinked {
				semanticSignals = append(semanticSignals, previousSignals)
			}
		}
		var semanticPotentialProfiles uint64
		semanticPotentialOverflow := false
		for profileIndex, profile := range c.semanticProfiles {
			if !semanticProfilePotential(profile, semanticSignals) {
				continue
			}
			if profileIndex < 64 {
				semanticPotentialProfiles |= uint64(1) << profileIndex
			} else {
				semanticPotentialOverflow = true
			}
		}
		if semanticPotentialProfiles != 0 || semanticPotentialOverflow {
			if !directivesReady {
				currentDirectives = c.analyzeDirectives(currentRunes, policy)
				directivesReady = true
			}
			windows := semanticDirectiveWindows(currentDirectives)
			if len(windows) == 0 || (structuredToolPayload && structuredSemanticFragment(currentText)) {
				windows = append(windows, semanticSignalWindow{signals: [][]bool{currentSignals}, text: currentText})
			}
			if partsLinked {
				windows = append(windows, semanticSignalWindow{
					signals: [][]bool{previousSignals, currentSignals},
					text:    strings.TrimSpace(previousText + "\n" + currentText),
				})
			}
			for profileIndex, profile := range c.semanticProfiles {
				if profileIndex < 64 && semanticPotentialProfiles&(uint64(1)<<profileIndex) == 0 {
					continue
				}
				if profileIndex >= 64 && !semanticProfilePotential(profile, semanticSignals) {
					continue
				}
				bestSemantic := semanticAssessment{}
				if profileIndex < len(currentDirectives.overflowSemantic) {
					bestSemantic = currentDirectives.overflowSemantic[profileIndex]
				}
				for windowIndex := range windows {
					prepareSemanticSignalWindowCategory(&windows[windowIndex], profile.category)
					assessment := c.assessSemanticWindow(profile, windows[windowIndex], policy)
					if semanticAssessmentBetter(assessment, bestSemantic) {
						bestSemantic = assessment
					}
				}
				bestSemantic = constrainSemanticAssessment(bestSemantic, thresholds)
				if bestSemantic.score < AuditThreshold {
					continue
				}
				candidates = append(candidates, candidate{
					score:       bestSemantic.score,
					category:    profile.category,
					ruleID:      profile.id(),
					evidence:    bestSemantic.evidence,
					explanation: bestSemantic.explanation,
				})
			}
		}
	}

	// Compose a core only within one category and one current directive clause,
	// and only when no ordinary rule candidate exists for that category. Both
	// the intent and object provider must carry an additional qualifier, and the
	// pair must jointly include operational evidence plus two of
	// target/evasion/scale. This closes vocabulary seams between related rules
	// without turning a loose bag of security words, separate clauses, or
	// evidence from different categories into a core.
	for _, category := range classifierCategoryOrder {
		if inertQuotedSafetyReview {
			break
		}
		categoryAlreadyHasCandidate := categoryHasCandidate[categoryPriority(category)]
		ruleIndexes := c.categoryRules[category]
		if len(ruleIndexes) < 2 {
			continue
		}
		hasQualifiedIntent := false
		hasQualifiedObject := false
		for _, ruleIndex := range ruleIndexes {
			rule := c.rules[ruleIndex]
			hasQualifiedIntent = hasQualifiedIntent || (currentSignals[rule.intent] && ruleHasMatchedQualifier(rule, currentSignals))
			hasQualifiedObject = hasQualifiedObject || (currentSignals[rule.object] && ruleHasMatchedQualifier(rule, currentSignals))
		}
		if !hasQualifiedIntent || !hasQualifiedObject {
			continue
		}
		legitimateCategoryWorkflow := isLegitimateCategoryWorkflow(category, currentText)
		if !directivesReady {
			currentDirectives = c.analyzeDirectives(currentRunes, policy)
			directivesReady = true
		}

		composition := categoryCompositionMatch{}
		considerComposition := func(match categoryCompositionMatch) {
			if preferCategoryCompositionMatch(match, composition) {
				composition = match
			}
		}
		for _, clause := range currentDirectives.clauses {
			if match, ok := c.matchCategoryCompositionClause(ruleIndexes, clause, policy); ok {
				considerComposition(match)
				if composition.localScore == 100 && composition.contradictory {
					break
				}
			}
		}
		if currentDirectives.overflow {
			priority := categoryPriority(category)
			considerComposition(currentDirectives.overflowCategoryComposition[priority])
			considerComposition(currentDirectives.overflowCategoryContradictoryComposition[priority])
		}
		if !composition.found {
			continue
		}
		intentProvider := composition.intent
		objectProvider := composition.object
		operationalProvider := composition.operational
		targetProvider := composition.target
		evasionProvider := composition.evasion
		scaleProvider := composition.scale
		intentRule := c.rules[intentProvider]
		objectRule := c.rules[objectProvider]
		for _, coreRuleID := range []string{intentRule.id, objectRule.id} {
			if !isRound8TargetedRule(coreRuleID) {
				continue
			}
			if !round8ComposedRuleCorePredicate(
				coreRuleID, currentText, operationalProvider >= 0,
				targetProvider >= 0, evasionProvider >= 0, scaleProvider >= 0,
			) {
				intentProvider = -1
				break
			}
		}
		if intentProvider < 0 {
			continue
		}
		score := 45
		corePredicateScore := score
		qualifiers := 0
		evidence := []Evidence{
			{ID: intentRule.id + ":intent", Kind: "intent"},
			{ID: objectRule.id + ":object", Kind: "object"},
		}
		appendQualifier := func(provider int, points int, kind string) {
			if provider < 0 {
				return
			}
			score += points
			qualifiers++
			evidence = append(evidence, Evidence{ID: c.rules[provider].id + ":" + kind, Kind: kind})
		}
		appendQualifier(operationalProvider, 20, "operational")
		appendQualifier(targetProvider, 18, "target")
		appendQualifier(evasionProvider, 16, "evasion")
		appendQualifier(scaleProvider, 16, "scale")
		if qualifiers >= 2 {
			score += 5
		}
		qualifierScore := score - corePredicateScore
		score = clampScore(score)

		effectiveContext := context
		if targetProvider >= 0 {
			if carriedCTFOrLab && !currentContext.CTFOrLab {
				effectiveContext.CTFOrLab = false
			}
			if carriedAuthorized && !currentContext.Authorized {
				effectiveContext.Authorized = false
			}
		}
		if hasExplicitHarmConflict(currentText) {
			effectiveContext.Authorized = false
			effectiveContext.CTFOrLab = false
		}
		composedRule := compiledRule{
			category:               category,
			authorizationProtected: intentRule.authorizationProtected || objectRule.authorizationProtected,
			intent:                 intentRule.intent,
			object:                 objectRule.object,
			operational:            c.rules[operationalProvider].operational,
			intentStarts:           intentRule.intentStarts,
		}
		overflowPairContradiction := currentDirectives.overflow && directiveProviderPairMatched(
			currentDirectives.overflowPairContradictions, len(c.rules), intentProvider, objectProvider,
		)
		locallyBlockingComposition := actionFor(mode, composition.localScore, thresholds) == ActionBlock
		compositionContradiction := composition.contradictory || overflowPairContradiction ||
			c.hasRuleContradictoryDirective(currentDirectives, -1, intentProvider, composedRule, policy.Allow)
		// A low-scoring ordinary candidate must not suppress a different-provider
		// composition whose active clause contradicts the matched safety context.
		// The local score still contains those context deductions; the final score
		// below intentionally removes them only after the contradiction proof. If
		// we return here first, a harmless same-category head can launder an active
		// composed tail merely by setting categoryHasCandidate.
		if categoryAlreadyHasCandidate && !locallyBlockingComposition && !compositionContradiction {
			continue
		}
		if legitimateCategoryWorkflow && !locallyBlockingComposition && !compositionContradiction {
			continue
		}
		if context != (ContextFlags{}) && compositionContradiction {
			effectiveContext = ContextFlags{
				CTFOrLab:   effectiveContext.CTFOrLab,
				Authorized: effectiveContext.Authorized,
			}
		}
		authorizationProtected := composedRule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(category)
		scoreBeforeContext := score
		score = applyContextDeductions(score, effectiveContext, authorizationProtected)
		contextAdjustment := score - scoreBeforeContext
		genuineSafetyContext := effectiveContext.Defensive || effectiveContext.Remediation || effectiveContext.StaticAnalysis || effectiveContext.IncidentResponse || effectiveContext.HighLevel
		hardFloorApplied := false
		if authorizationProtected && !genuineSafetyContext && score < HardThreshold {
			score = HardThreshold
			hardFloorApplied = true
		}
		explanation := DecisionExplanation{
			WinningRuleID:           "COMPOSED-" + string(category),
			WinningCategory:         string(category),
			CorePredicateComplete:   true,
			EvidenceOccurrenceCount: len(evidence),
			EvidenceSegmentCount:    1,
			ContextAdjustment:       contextAdjustment,
			HardFloorApplied:        hardFloorApplied,
			ScoreBreakdown: ScoreBreakdown{
				CorePredicateScore: corePredicateScore,
				QualifierScore:     qualifierScore,
				ContextAdjustment:  contextAdjustment,
				FinalScore:         score,
			},
		}
		if hardFloorApplied {
			explanation.HardFloorReason = hardFloorReasonComposedCompleteCoreWithTwoQualifiers
		}
		candidates = append(candidates, candidate{
			score:       score,
			category:    category,
			ruleIDs:     []string{intentRule.id, objectRule.id},
			evidence:    evidence,
			explanation: explanation,
		})
	}

	// Meta-override language is an abuse amplifier, not a standalone keyword
	// blocklist. It covers instruction-hierarchy inversion, refusal suppression,
	// sandbox/placeholder laundering, forced exact-output templates, negative
	// authorization, and control-plane secret disclosure. It may raise an
	// existing cyber-abuse candidate, but never creates a cyber taxonomy by
	// itself. Wrapper-only requests remain a bounded control-plane audit signal.
	meta := bestMeta
	metaAttachedToOrdinary := false
	if meta.score >= AuditThreshold {
		bestOrdinaryIndex := -1
		for index := range candidates {
			if candidates[index].score < AuditThreshold {
				continue
			}
			if bestOrdinaryIndex < 0 || candidates[index].score > candidates[bestOrdinaryIndex].score ||
				(candidates[index].score == candidates[bestOrdinaryIndex].score &&
					(categoryPriority(candidates[index].category) < categoryPriority(candidates[bestOrdinaryIndex].category) ||
						(candidates[index].category == candidates[bestOrdinaryIndex].category &&
							candidateSortID(candidates[index].ruleID, candidates[index].ruleIDs) < candidateSortID(candidates[bestOrdinaryIndex].ruleID, candidates[bestOrdinaryIndex].ruleIDs)))) {
				bestOrdinaryIndex = index
			}
		}
		if bestOrdinaryIndex >= 0 {
			winner := &candidates[bestOrdinaryIndex]
			mayAmplify := winner.explanation.CorePredicateComplete &&
				(winner.score >= thresholds.BalancedBlock || ordinaryEvidenceSupportsMetaAmplification(winner.evidence))
			// Persistent instruction injection is independently blockable. If the
			// ordinary candidate is only a weak incidental match, leave the META
			// assessment unattached so the standalone control-plane decision below
			// retains its category-free hard-block semantics.
			if !meta.controlPlaneBlock || mayAmplify {
				metaAttachedToOrdinary = true
				if mayAmplify && winner.score < meta.score {
					winner.score = meta.score
				}
				if winner.ruleID != "" {
					winner.ruleIDs = append(winner.ruleIDs, winner.ruleID)
					winner.ruleID = ""
				}
				winner.ruleIDs = append(winner.ruleIDs, metaOverrideRuleID)
				winner.evidence = append(winner.evidence, meta.evidence...)
			}
		}
	}
	// A control-plane decision must not disappear merely because unrelated
	// defensive text created a below-audit taxonomy candidate. If there is no
	// auditable base behavior to own the decision, preserve the standalone,
	// category-free audit or persistent control-plane block.
	if len(candidates) == 0 || (meta.score >= AuditThreshold && !metaAttachedToOrdinary) {
		if meta.score >= AuditThreshold {
			if meta.controlPlaneBlock {
				result.Score = meta.score
				if result.Score < thresholds.HardBlock {
					result.Score = thresholds.HardBlock
				}
				hardFloorApplied := result.Score > meta.score
				result.DecisionExplanation = &DecisionExplanation{
					WinningRuleID:         metaOverrideRuleID,
					CorePredicateComplete: true,
					EvidenceSegmentCount:  1,
					HardFloorApplied:      hardFloorApplied,
					ScoreBreakdown: ScoreBreakdown{
						CorePredicateScore: result.Score,
						FinalScore:         result.Score,
					},
				}
				if hardFloorApplied {
					result.DecisionExplanation.HardFloorReason = hardFloorReasonPersistentControlPlaneBlockThreshold
				}
			} else {
				result.Score = metaControlAuditScore(meta.score, thresholds)
			}
			result.RuleIDs = []string{metaOverrideRuleID}
			result.Evidence = append(result.Evidence, meta.evidence...)
			result.Evidence = append(result.Evidence, contextEvidence(context)...)
			result.Evidence = uniqueSortedEvidence(result.Evidence)
			if meta.controlPlaneBlock {
				result.Action = actionFor(mode, result.Score, thresholds)
			} else {
				result.Action = actionForMetaControl(mode, result.Score, thresholds)
			}
			carrier := "text"
			if structuredToolPayload {
				carrier = "structured_tool_payload"
			}
			attachBehaviorGraph(&result, "parts", carrier)
			return finishResult(result)
		}
		result.Action = actionFor(mode, 0, thresholds)
		result.Evidence = contextEvidence(context)
		carrier := "text"
		if structuredToolPayload {
			carrier = "structured_tool_payload"
		}
		attachBehaviorGraph(&result, "parts", carrier)
		return finishResult(result)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].category != candidates[j].category {
			return categoryPriority(candidates[i].category) < categoryPriority(candidates[j].category)
		}
		leftSpecificity := round8CandidateSpecificity(candidates[i].ruleID, candidates[i].ruleIDs)
		rightSpecificity := round8CandidateSpecificity(candidates[j].ruleID, candidates[j].ruleIDs)
		if leftSpecificity != rightSpecificity {
			return leftSpecificity > rightSpecificity
		}
		return candidateSortID(candidates[i].ruleID, candidates[i].ruleIDs) < candidateSortID(candidates[j].ruleID, candidates[j].ruleIDs)
	})
	best := candidates[0]
	result.Score = clampScore(best.score)
	result.Category = best.category
	result.EvidenceOccurrences = append(result.EvidenceOccurrences, best.occurrences...)
	if best.explanation.WinningRuleID != "" || best.explanation.WinningCategory != "" {
		explanation := best.explanation
		explanation.ScoreBreakdown.FinalScore = result.Score
		result.DecisionExplanation = &explanation
		if explanation.WinningRuleID != "" {
			// The winning identifier is part of the persisted decision contract,
			// including synthetic COMPOSED-/SEMANTIC- winners. Keep it in RuleIDs
			// so classifier -> plugin -> audit validation cannot reject the event.
			result.RuleIDs = append(result.RuleIDs, explanation.WinningRuleID)
		}
	}
	result.RuleIDs = appendCandidateRuleIDs(result.RuleIDs, best.ruleID, best.ruleIDs)
	result.Evidence = append(result.Evidence, best.evidence...)
	for _, other := range candidates[1:] {
		if other.category != best.category || other.score != best.score {
			continue
		}
		result.RuleIDs = appendCandidateRuleIDs(result.RuleIDs, other.ruleID, other.ruleIDs)
		result.Evidence = append(result.Evidence, other.evidence...)
	}
	result.Evidence = append(result.Evidence, contextEvidence(context)...)
	result.RuleIDs = uniqueSorted(result.RuleIDs)
	result.Evidence = uniqueSortedEvidence(result.Evidence)
	result.Action = actionFor(mode, result.Score, thresholds)
	carrier := "text"
	if structuredToolPayload {
		carrier = "structured_tool_payload"
	}
	attachBehaviorGraph(&result, "parts", carrier)
	return finishResult(result)
}

func markQuotedOrInertSuppressed(result *Result) {
	if result == nil {
		return
	}
	if result.DecisionExplanation == nil {
		result.DecisionExplanation = &DecisionExplanation{
			ScoreBreakdown: ScoreBreakdown{FinalScore: result.Score},
		}
	}
	result.DecisionExplanation.QuotedOrInertSuppressed = true
}

func round8CandidateSpecificity(ruleID string, ruleIDs []string) int {
	if isRound8TargetedRule(ruleID) {
		return 2
	}
	for _, candidate := range ruleIDs {
		if isRound8TargetedRule(candidate) {
			return 2
		}
	}
	if strings.HasPrefix(ruleID, "SEMANTIC-") {
		return 0
	}
	return 1
}

func adjacentRuleCorePotential(rules []compiledRule, previous, current []bool) bool {
	if len(previous) == 0 || len(current) == 0 {
		return false
	}
	for _, rule := range rules {
		if previous[rule.intent] && current[rule.object] {
			return true
		}
	}
	return false
}

var coarseNegationRunes = [][]rune{
	[]rune("not"), []rune("never"), []rune("without"), []rune("forbid"), []rune("prohibit"),
	[]rune("refus"), []rune("cannot"), []rune("can't"), []rune("don't"),
	[]rune("n't"), []rune("n’t"), []rune("n‘t"),
	[]rune("严禁"), []rune("禁止"), []rune("不得"), []rune("不要"), []rune("不能"), []rune("不会"), []rune("拒绝"), []rune("不"),
}

var coarseNegationRunesByInitial, coarseNegationRunesByInitialNonASCII = func() ([128][][]rune, map[rune][][]rune) {
	var ascii [128][][]rune
	nonASCII := make(map[rune][][]rune)
	for _, marker := range coarseNegationRunes {
		if len(marker) == 0 {
			continue
		}
		if marker[0] < 128 {
			ascii[marker[0]] = append(ascii[marker[0]], marker)
		} else {
			nonASCII[marker[0]] = append(nonASCII[marker[0]], marker)
		}
	}
	return ascii, nonASCII
}()

var compactNegationMatcher = func() *literalMatcher {
	builder := newMatcherBuilder()
	for _, pattern := range []string{
		"donot", "mustnot", "shouldnot", "neednot", "oughtnot", "shallnot", "wouldnot", "couldnot", "maynot", "willnot",
		"cannot", "never", "without", "forbid", "prohibit", "refuse",
		"严禁", "禁止", "不得", "不要", "不能", "不会", "拒绝",
	} {
		builder.add(pattern, isASCIIStringLocal(pattern), 0)
	}
	return builder.build()
}()

func runesMayContainNegation(text []rune) bool {
	for start, initial := range text {
		var markers [][]rune
		if initial < 128 {
			markers = coarseNegationRunesByInitial[initial]
		} else {
			markers = coarseNegationRunesByInitialNonASCII[initial]
		}
		for _, marker := range markers {
			if start+len(marker) > len(text) {
				continue
			}
			matched := true
			for offset := range marker {
				if text[start+offset] != marker[offset] {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return runesMayContainCompactNegation(text)
}

func runesMayContainCompactNegation(text []rune) bool {
	var signals [1]bool
	var beforeRing [32]bool
	compactNegationMatcher.matchCompactWithScratch(text, signals[:], beforeRing[:])
	return signals[0]
}

func (c *Classifier) adjacentNegationNeedsReconstruction(previousRunes []rune, previous, current []bool) (compiledRule, bool) {
	if len(previous) == 0 || len(current) == 0 {
		return compiledRule{}, false
	}
	analysis := c.analyzeDirectives(previousRunes, DefaultPolicy())
	for _, rule := range c.rules {
		if !previous[rule.intent] || !current[rule.object] {
			continue
		}
		if analysis.overflow {
			return rule, true
		}
		laterActiveContinuation := false
		for index := len(analysis.clauses) - 1; index >= 0; index-- {
			clause := analysis.clauses[index]
			if !clause.signals.matched(rule.intent) {
				laterActiveContinuation = laterActiveContinuation || continuesPriorRiskDirective(clause.text)
				continue
			}
			found, negates := clauseRuleIntentNegation(clause.text, rule.intentStarts)
			if laterActiveContinuation {
				return rule, true
			}
			if found && !negates {
				if descriptiveNegationClause(clause.text) {
					break
				}
				if adjacentClauseReactivatesNegatedIntent(previousRunes, analysis, index, rule) {
					return rule, true
				}
				// This helper exists only to preserve an intent-owning negation
				// reversal across an adjacent part boundary. A negation in an
				// unrelated earlier clause must not turn a later affirmative OAuth,
				// credential-management, or other ordinary workflow into a hard
				// block merely because the next part supplies a matching noun.
				if runesMayContainNegation(clause.runes) {
					return rule, true
				}
				break
			}
			if !found && startsWithRuleIntent(clause.text, rule.intentStarts) {
				if runesMayContainNegation(clause.runes) {
					return rule, true
				}
				break
			}
			if !found && runesMayContainNegation(clause.runes) {
				// The matcher proved that this clause owns the intent, but literal
				// position analysis cannot bind a compact-only spelling such as
				// "d e p l o y" to its negation or reversal. Reconstruct the joined
				// request and fail closed instead of treating the missing literal
				// offset as proof of a benign prohibition.
				return rule, true
			}
			// The most recent clause that owns this intent controls the adjacent
			// object. A direct prohibition must not be washed out by an older
			// reversal, and an unnegated explanatory mention is not enough to join
			// otherwise independent parts.
			break
		}
	}
	return compiledRule{}, false
}

func adjacentClauseReactivatesNegatedIntent(previousRunes []rune, analysis analyzedDirectives, index int, rule compiledRule) bool {
	if index <= 0 || index >= len(analysis.clauses) {
		return false
	}
	if !adjacentReversalConnectorBefore(previousRunes, analysis.clauses[index].runes) {
		return false
	}
	for priorIndex := index - 1; priorIndex >= 0; priorIndex-- {
		prior := analysis.clauses[priorIndex]
		if !prior.signals.matched(rule.intent) {
			continue
		}
		found, negates := clauseRuleIntentNegation(prior.text, rule.intentStarts)
		if found && negates {
			return true
		}
		return runesMayContainNegation(prior.runes) && hasExplanatoryFraming(prior.text)
	}
	return false
}

func adjacentReversalConnectorBefore(text, clause []rune) bool {
	if len(clause) == 0 || len(clause) > len(text) {
		return false
	}
	clauseStart := -1
	for start := len(text) - len(clause); start >= 0; start-- {
		matched := true
		for offset := range clause {
			if text[start+offset] != clause[offset] {
				matched = false
				break
			}
		}
		if matched {
			clauseStart = start
			break
		}
	}
	if clauseStart <= 0 {
		return false
	}
	end := clauseStart
	for end > 0 && unicode.IsSpace(text[end-1]) {
		end--
	}
	start := end
	for start > 0 {
		r := text[start-1]
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			start--
			continue
		}
		break
	}
	word := text[start:end]
	return runeSliceEqualFoldASCII(word, "but") ||
		runeSliceEqualFoldASCII(word, "however") ||
		runeSliceEqualFoldASCII(word, "instead") ||
		runeSliceEqualFoldASCII(word, "yet")
}

func descriptiveNegationClause(clause string) bool {
	clause = strings.ToLower(strings.TrimSpace(clause))
	if !hasExplanatoryFraming(clause) {
		return false
	}
	return containsAnyLiteral(clause,
		"why attackers", "how attackers", "attackers ", "why an attacker", "how an attacker", "an attacker ",
		"why the malware", "how the malware", "the malware ", "why the sample", "how the sample", "the sample ",
		"为何攻击者", "攻击者为何", "攻击者如何", "恶意软件为何", "恶意软件如何", "样本为何", "样本如何",
	)
}

func (c *Classifier) adjacentNegationOverflowResult(rule compiledRule, mode Mode, thresholds Thresholds, structuredToolPayload bool) Result {
	score := thresholds.HardBlock
	if score < HardThreshold {
		score = HardThreshold
	}
	result := Result{
		PolicyVersion:  ClassifierPolicyVersion,
		PolicySHA256:   ClassifierPolicySHA256,
		RuleSetVersion: c.version,
		Score:          clampScore(score),
		Category:       rule.category,
		Action:         actionFor(mode, score, thresholds),
		RuleIDs:        []string{rule.id},
		Evidence: []Evidence{
			{ID: rule.id + ":intent", Kind: "intent"},
			{ID: rule.id + ":object", Kind: "object"},
		},
	}
	carrier := "text"
	if structuredToolPayload {
		carrier = "structured_tool_payload"
	}
	attachBehaviorGraph(&result, "parts", carrier)
	return result
}

func (c *Classifier) adjacentNegationOverflowResultForSignals(previous, current []bool, mode Mode, thresholds Thresholds, structuredToolPayload bool) (Result, bool) {
	var best Result
	found := false
	for _, rule := range c.rules {
		if !signalMatched(previous, rule.intent) || !signalMatched(current, rule.object) {
			continue
		}
		candidate := c.adjacentNegationOverflowResult(rule, mode, thresholds, structuredToolPayload)
		if !found || roleResultBetter(candidate, best) {
			best = candidate
		}
		found = true
	}
	if !found {
		return Result{}, false
	}
	ruleIDs := make([]string, 0, 4)
	evidence := make([]Evidence, 0, 8)
	for _, rule := range c.rules {
		if !signalMatched(previous, rule.intent) || !signalMatched(current, rule.object) || rule.category != best.Category {
			continue
		}
		candidate := c.adjacentNegationOverflowResult(rule, mode, thresholds, structuredToolPayload)
		if candidate.Score != best.Score {
			continue
		}
		ruleIDs = append(ruleIDs, candidate.RuleIDs...)
		evidence = append(evidence, candidate.Evidence...)
	}
	best.RuleIDs = uniqueSorted(ruleIDs)
	best.Evidence = uniqueSortedEvidence(evidence)
	return best, true
}

func ruleHasMatchedQualifier(rule compiledRule, signals []bool) bool {
	return signalMatched(signals, rule.independentOperational) ||
		signalMatched(signals, rule.independentTarget) ||
		signalMatched(signals, rule.independentEvasion) ||
		signalMatched(signals, rule.independentScale)
}

func ruleHasMatchedDirectiveQualifier(rule compiledRule, signals directiveSignalSet) bool {
	return signals.matched(rule.independentOperational) ||
		signals.matched(rule.independentTarget) ||
		signals.matched(rule.independentEvasion) ||
		signals.matched(rule.independentScale)
}

func ruleHasMatchedAnalyzedDirectiveQualifier(rule compiledRule, sparse directiveSignalSet, dense []bool) bool {
	if dense != nil {
		return ruleHasMatchedQualifier(rule, dense)
	}
	return ruleHasMatchedDirectiveQualifier(rule, sparse)
}

func (c *Classifier) matchCategoryCompositionClause(
	ruleIndexes []int,
	clause analyzedDirectiveClause,
	policy Policy,
) (categoryCompositionMatch, bool) {
	return c.matchCategoryCompositionClauseWithDense(ruleIndexes, clause, nil, policy)
}

func (c *Classifier) matchCategoryCompositionClauseWithDense(
	ruleIndexes []int,
	clause analyzedDirectiveClause,
	denseSignals []bool,
	policy Policy,
) (categoryCompositionMatch, bool) {
	return c.bestCategoryCompositionClauseMatch(ruleIndexes, clause, denseSignals, policy)
}

func (c *Classifier) bestCategoryCompositionClauseMatch(
	ruleIndexes []int,
	clause analyzedDirectiveClause,
	denseSignals []bool,
	policy Policy,
) (categoryCompositionMatch, bool) {
	clauseSignals := clause.signals
	hasQualifiedIntent := false
	hasQualifiedObject := false
	hasOperational := false
	hasTarget := false
	hasEvasion := false
	hasScale := false
	for _, ruleIndex := range ruleIndexes {
		rule := c.rules[ruleIndex]
		hasQualifiedIntent = hasQualifiedIntent || (analyzedDirectiveSignalMatched(clauseSignals, denseSignals, rule.intent) && ruleHasMatchedAnalyzedDirectiveQualifier(rule, clauseSignals, denseSignals))
		hasQualifiedObject = hasQualifiedObject || (analyzedDirectiveSignalMatched(clauseSignals, denseSignals, rule.object) && ruleHasMatchedAnalyzedDirectiveQualifier(rule, clauseSignals, denseSignals))
		hasOperational = hasOperational || analyzedDirectiveSignalMatched(clauseSignals, denseSignals, rule.independentOperational)
		hasTarget = hasTarget || analyzedDirectiveSignalMatched(clauseSignals, denseSignals, rule.independentTarget)
		hasEvasion = hasEvasion || analyzedDirectiveSignalMatched(clauseSignals, denseSignals, rule.independentEvasion)
		hasScale = hasScale || analyzedDirectiveSignalMatched(clauseSignals, denseSignals, rule.independentScale)
	}
	riskAxes := 0
	for _, matched := range [...]bool{hasTarget, hasEvasion, hasScale} {
		if matched {
			riskAxes++
		}
	}
	if !hasQualifiedIntent || !hasQualifiedObject || !hasOperational || riskAxes < 2 {
		return categoryCompositionMatch{}, false
	}
	best := categoryCompositionMatch{}
	for _, intentIndex := range ruleIndexes {
		if clause.negatedRuleIntents.matched(intentIndex) {
			continue
		}
		for _, objectIndex := range ruleIndexes {
			match, ok := c.categoryCompositionPairMatch(intentIndex, objectIndex, clauseSignals, denseSignals)
			if !ok {
				continue
			}
			match.localScore = c.categoryCompositionLocalScore(match, clause, denseSignals, policy)
			if c.categoryCompositionMatchContradictsContext(match, clause, denseSignals, policy.Allow) {
				match.contradictory = true
			}
			if preferCategoryCompositionMatch(match, best) {
				best = match
			}
			if best.localScore == 100 && best.contradictory {
				return best, true
			}
		}
	}
	return best, best.found
}

func preferCategoryCompositionMatch(candidate, current categoryCompositionMatch) bool {
	if !candidate.found {
		return false
	}
	if !current.found || candidate.localScore != current.localScore {
		return !current.found || candidate.localScore > current.localScore
	}
	return candidate.localScore >= HardThreshold && candidate.contradictory && !current.contradictory
}

func (c *Classifier) categoryCompositionPairMatch(
	intentIndex int,
	objectIndex int,
	sparseSignals directiveSignalSet,
	denseSignals []bool,
) (categoryCompositionMatch, bool) {
	if intentIndex == objectIndex {
		return categoryCompositionMatch{}, false
	}
	intentRule := c.rules[intentIndex]
	objectRule := c.rules[objectIndex]
	if !analyzedDirectiveSignalMatched(sparseSignals, denseSignals, intentRule.intent) ||
		!ruleHasMatchedAnalyzedDirectiveQualifier(intentRule, sparseSignals, denseSignals) ||
		!analyzedDirectiveSignalMatched(sparseSignals, denseSignals, objectRule.object) ||
		!ruleHasMatchedAnalyzedDirectiveQualifier(objectRule, sparseSignals, denseSignals) {
		return categoryCompositionMatch{}, false
	}
	operational := firstPairAnalyzedDirectiveSignalProvider(sparseSignals, denseSignals, intentIndex, objectIndex, intentRule.independentOperational, objectRule.independentOperational)
	target := firstPairAnalyzedDirectiveSignalProvider(sparseSignals, denseSignals, intentIndex, objectIndex, intentRule.independentTarget, objectRule.independentTarget)
	evasion := firstPairAnalyzedDirectiveSignalProvider(sparseSignals, denseSignals, intentIndex, objectIndex, intentRule.independentEvasion, objectRule.independentEvasion)
	scale := firstPairAnalyzedDirectiveSignalProvider(sparseSignals, denseSignals, intentIndex, objectIndex, intentRule.independentScale, objectRule.independentScale)
	riskQualifiers := 0
	for _, provider := range [...]int{target, evasion, scale} {
		if provider >= 0 {
			riskQualifiers++
		}
	}
	if operational < 0 || riskQualifiers < 2 {
		return categoryCompositionMatch{}, false
	}
	return categoryCompositionMatch{
		found: true, intent: intentIndex, object: objectIndex,
		operational: operational, target: target, evasion: evasion, scale: scale,
	}, true
}

func (c *Classifier) categoryCompositionMatchContradictsContext(
	match categoryCompositionMatch,
	clause analyzedDirectiveClause,
	denseSignals []bool,
	allow ContextPolicy,
) bool {
	if !match.found {
		return false
	}
	intentRule := c.rules[match.intent]
	objectRule := c.rules[match.object]
	composedRule := compiledRule{
		category:     intentRule.category,
		intent:       intentRule.intent,
		object:       objectRule.object,
		intentStarts: intentRule.intentStarts,
	}
	for _, operationalProvider := range [...]int{match.intent, match.object} {
		composedRule.operational = c.rules[operationalProvider].operational
		if c.activeDirectiveClauseContradictsContextWithDense(clause, denseSignals, composedRule, allow) {
			return true
		}
	}
	return false
}

func (c *Classifier) categoryCompositionLocalScore(
	match categoryCompositionMatch,
	clause analyzedDirectiveClause,
	denseSignals []bool,
	policy Policy,
) int {
	if !match.found {
		return 0
	}
	intentRule := c.rules[match.intent]
	if isLegitimateCategoryWorkflow(intentRule.category, clause.text) {
		return 0
	}
	score := 45
	qualifiers := 0
	for _, qualifier := range [...]struct {
		provider int
		points   int
	}{
		{match.operational, 20},
		{match.target, 18},
		{match.evasion, 16},
		{match.scale, 16},
	} {
		if qualifier.provider < 0 {
			continue
		}
		score += qualifier.points
		qualifiers++
	}
	if qualifiers >= 2 {
		score += 5
	}
	context := c.matchDirectiveContextsWithPolicy(clause.signals, policy.Allow)
	if denseSignals != nil {
		context = c.matchContextsWithPolicy(denseSignals, policy.Allow)
	}
	if hasExplicitHarmConflict(clause.text) {
		context.Authorized = false
		context.CTFOrLab = false
	}
	objectRule := c.rules[match.object]
	authorizationProtected := (intentRule.authorizationProtected || objectRule.authorizationProtected) &&
		policy.HardBlockEvenIfAuthorized.protects(intentRule.category)
	score = applyContextDeductions(clampScore(score), context, authorizationProtected)
	genuineSafetyContext := context.Defensive || context.Remediation || context.StaticAnalysis || context.IncidentResponse || context.HighLevel
	if authorizationProtected && !genuineSafetyContext && score < HardThreshold {
		score = HardThreshold
	}
	return clampScore(score)
}

func (c *Classifier) updateCategoryDirectivePairContradictions(
	category rules.Category,
	ruleIndexes []int,
	clause analyzedDirectiveClause,
	denseSignals []bool,
	allow ContextPolicy,
	destination []uint64,
) {
	if isLegitimateCategoryWorkflow(category, clause.text) {
		return
	}
	for _, intentIndex := range ruleIndexes {
		intentRule := c.rules[intentIndex]
		if !analyzedDirectiveSignalMatched(clause.signals, denseSignals, intentRule.intent) || clause.negatedRuleIntents.matched(intentIndex) {
			continue
		}
		for _, objectIndex := range ruleIndexes {
			if objectIndex == intentIndex {
				continue
			}
			objectRule := c.rules[objectIndex]
			if !analyzedDirectiveSignalMatched(clause.signals, denseSignals, objectRule.object) {
				continue
			}
			composedRule := compiledRule{
				category:     category,
				intent:       intentRule.intent,
				object:       objectRule.object,
				intentStarts: intentRule.intentStarts,
			}
			for _, operationalProvider := range [...]int{intentIndex, objectIndex} {
				composedRule.operational = c.rules[operationalProvider].operational
				if c.activeDirectiveClauseContradictsContextWithDense(clause, denseSignals, composedRule, allow) {
					markDirectiveProviderPair(destination, len(c.rules), intentIndex, objectIndex)
					break
				}
			}
		}
	}
}

func firstPairSignalProvider(signals []bool, first, second, firstSignal, secondSignal int) int {
	if signalMatched(signals, firstSignal) {
		return first
	}
	if signalMatched(signals, secondSignal) {
		return second
	}
	return -1
}

func firstPairDirectiveSignalProvider(signals directiveSignalSet, first, second, firstSignal, secondSignal int) int {
	if signals.matched(firstSignal) {
		return first
	}
	if signals.matched(secondSignal) {
		return second
	}
	return -1
}

func firstPairAnalyzedDirectiveSignalProvider(
	sparse directiveSignalSet,
	dense []bool,
	first, second, firstSignal, secondSignal int,
) int {
	if analyzedDirectiveSignalMatched(sparse, dense, firstSignal) {
		return first
	}
	if analyzedDirectiveSignalMatched(sparse, dense, secondSignal) {
		return second
	}
	return -1
}

func signalMatched(signals []bool, signalID int) bool {
	return signalID >= 0 && signalID < len(signals) && signals[signalID]
}

func candidateSortID(ruleID string, ruleIDs []string) string {
	if ruleID != "" {
		return ruleID
	}
	if len(ruleIDs) == 0 {
		return ""
	}
	return ruleIDs[0]
}

func appendCandidateRuleIDs(destination []string, ruleID string, ruleIDs []string) []string {
	if ruleID != "" {
		return append(destination, ruleID)
	}
	return append(destination, ruleIDs...)
}

// syntheticEvidenceOccurrences turns already-scored, content-free evidence
// into bounded occurrence records. It is deliberately used only after the
// active-directive and core predicates have succeeded, so these synthetic
// records can explain a decision but can never satisfy ownership gates.
func syntheticEvidenceOccurrences(evidence []Evidence, fallbackRuleID string) []EvidenceOccurrence {
	counts := make(map[string]int, len(evidence))
	occurrences := make([]EvidenceOccurrence, 0, len(evidence))
	for _, item := range evidence {
		if item.Kind == "" || item.Kind == "context" {
			continue
		}
		ruleID := evidenceRuleID(item.ID, fallbackRuleID)
		key := ruleID + "\x00" + item.Kind
		counts[key]++
		occurrences = append(occurrences, EvidenceOccurrence{
			EvidenceID:     fmt.Sprintf("%s:%s:signal-%d", ruleID, item.Kind, counts[key]),
			RuleID:         ruleID,
			Dimension:      item.Kind,
			SegmentID:      -1,
			FieldID:        -1,
			ClauseID:       -1,
			SentenceID:     -1,
			Start:          -1,
			End:            -1,
			Polarity:       PolarityAffirmative,
			DirectiveOwner: DirectiveOwnerUnknown,
			TermStrength:   TermStrengthStrong,
		})
	}
	return occurrences
}

// ordinaryEvidenceSupportsMetaAmplification requires a concrete delivery or
// execution signal plus an independent risk axis. META language may annotate a
// weaker ordinary finding, but a lone object/core or a single qualifier must
// not promote an audit-only candidate into a balanced or hard block.
func ordinaryEvidenceSupportsMetaAmplification(evidence []Evidence) bool {
	operational := false
	riskAxis := false
	for _, item := range evidence {
		switch item.Kind {
		case "operational", "action":
			// Semantic profiles call the operational/delivery dimension "action".
			operational = true
		case "target", "evasion", "scale":
			riskAxis = true
		}
	}
	return operational && riskAxis
}

func isCredentialObjectQualifiedFallback(rule compiledRule, signals []bool) bool {
	return len(signals) > 0 && rule.category == rules.CategoryCredentialTheft &&
		!signals[rule.intent] && signals[rule.object] &&
		signalMatched(signals, rule.independentOperational) &&
		signalMatched(signals, rule.independentTarget) &&
		signalMatched(signals, rule.independentEvasion)
}

type streamingRiskAssessment struct {
	ordinaryScore          int
	hasOrdinary            bool
	qualifiedOrdinaryScore int
	hasQualifiedOrdinary   bool
	meta                   metaOverrideAssessment
}

func (assessment *streamingRiskAssessment) considerOrdinary(score int, qualified bool) {
	if assessment == nil {
		return
	}
	score = clampScore(score)
	if !assessment.hasOrdinary || score > assessment.ordinaryScore {
		assessment.ordinaryScore = score
		assessment.hasOrdinary = true
	}
	if qualified && (!assessment.hasQualifiedOrdinary || score > assessment.qualifiedOrdinaryScore) {
		assessment.qualifiedOrdinaryScore = score
		assessment.hasQualifiedOrdinary = true
	}
}

// blocks mirrors the classifier's two different action paths. Wrapper-only
// meta-control evidence remains audit-only even in strict mode; only an
// independently established ordinary behavior may be amplified by that score.
// A persistent control-plane finding retains its existing hard-block path.
func (assessment streamingRiskAssessment) blocks(mode Mode, thresholds Thresholds) bool {
	thresholds = validThresholdsOrDefault(thresholds)
	if assessment.hasOrdinary {
		if actionFor(mode, clampScore(assessment.ordinaryScore), thresholds) == ActionBlock {
			return true
		}
	}
	if assessment.meta.score >= AuditThreshold {
		amplifiableScore := 0
		hasAmplifiableOrdinary := false
		if assessment.hasOrdinary && assessment.ordinaryScore >= thresholds.BalancedBlock {
			amplifiableScore = assessment.ordinaryScore
			hasAmplifiableOrdinary = true
		}
		if assessment.hasQualifiedOrdinary && assessment.qualifiedOrdinaryScore >= AuditThreshold &&
			(!hasAmplifiableOrdinary || assessment.qualifiedOrdinaryScore > amplifiableScore) {
			amplifiableScore = assessment.qualifiedOrdinaryScore
			hasAmplifiableOrdinary = true
		}
		if hasAmplifiableOrdinary {
			score := amplifiableScore
			if assessment.meta.score > score {
				score = assessment.meta.score
			}
			if actionFor(mode, clampScore(score), thresholds) == ActionBlock {
				return true
			}
		}
	}
	if assessment.meta.score < AuditThreshold {
		return false
	}
	if assessment.meta.controlPlaneBlock {
		score := assessment.meta.score
		if score < thresholds.HardBlock {
			score = thresholds.HardBlock
		}
		return actionFor(mode, clampScore(score), thresholds) == ActionBlock
	}
	return actionForMetaControl(mode, metaControlAuditScore(assessment.meta.score, thresholds), thresholds) == ActionBlock
}

// streamingRiskPotential computes a positive-evidence upper bound using the
// classifier's compiled signal IDs and existing composition helpers. It does
// not manufacture a classification: streaming uses it only to notice when the
// union of multiple windows can become actionable while no individual window
// contained equivalent evidence. Context deductions and benign-workflow credit
// are intentionally omitted, making uncertainty fail closed rather than
// allowing a cross-window semantic composition to masquerade as complete.
func (c *Classifier) streamingRiskPotential(facts classificationSignalFacts, policy Policy, thresholds Thresholds) streamingRiskAssessment {
	assessment := streamingRiskAssessment{}
	if c == nil || len(facts.signals) != c.signalCount {
		return assessment
	}
	thresholds = validThresholdsOrDefault(thresholds)
	signals := facts.signals
	for ruleIndex, rule := range c.rules {
		core := signals[rule.intent] && signals[rule.object] &&
			ruleIndex < len(facts.unnegatedRuleIntents) && facts.unnegatedRuleIntents[ruleIndex]
		fallback := isCredentialObjectQualifiedFallback(rule, signals)
		if !core && !fallback {
			continue
		}
		score := rule.baseScore
		if fallback {
			score -= 25
		}
		qualifiers := 0
		operational := signalMatched(signals, rule.independentOperational) || signalMatched(signals, c.implementationRequest)
		if operational {
			score += 20
			qualifiers++
		}
		// An explicit victim/third-party/unauthorized conflict is target-quality
		// evidence for the conservative cross-window upper bound. It is never used
		// to manufacture a complete finding; streaming only turns an otherwise
		// actionable union into classifier-window incompleteness.
		if signalMatched(signals, rule.independentTarget) || facts.harmConflict {
			score += 18
			qualifiers++
		}
		if signalMatched(signals, rule.independentEvasion) {
			score += 16
			qualifiers++
		}
		if signalMatched(signals, rule.independentScale) {
			score += 16
			qualifiers++
		}
		if qualifiers >= 2 {
			score += 5
		}
		// This is a conservative upper bound used only after exact streaming
		// reconstruction is unavailable. One concrete qualifier may therefore
		// preserve the historical hard-floor potential without admitting an
		// actual Round 8 finding; complete requests still pass through the owned
		// active-directive predicate above.
		if qualifiers > 0 && rule.hardFloor > score {
			score = rule.hardFloor
		}
		if qualifiers == 0 && score >= BalancedThreshold {
			score = BalancedThreshold - 1
		}
		assessment.considerOrdinary(score, operational && qualifiers >= 2)
	}

	if signalMatched(signals, c.outcomeRequest) {
		for _, category := range classifierCategoryOrder {
			if c.streamingCategoryIntentsOnlyNegated(category, facts) {
				continue
			}
			providers := c.categoryOutcomeProviders(category, signals)
			if providers.object < 0 || providers.qualifierCount() < 2 {
				continue
			}
			score := 45
			if providers.hasOperational {
				score += 20
			}
			if providers.target >= 0 {
				score += 18
			}
			if providers.evasion >= 0 {
				score += 16
			}
			if providers.scale >= 0 {
				score += 16
			}
			if providers.qualifierCount() >= 2 {
				score += 5
			}
			objectRule := c.rules[providers.object]
			if objectRule.authorizationProtected && policy.HardBlockEvenIfAuthorized.protects(category) && score < HardThreshold {
				score = HardThreshold
			}
			assessment.considerOrdinary(score, providers.hasOperational &&
				(providers.target >= 0 || providers.evasion >= 0 || providers.scale >= 0))
		}
	}

	semanticPolicy := policy
	semanticPolicy.Allow = ContextPolicy{}
	for profileIndex, profile := range c.semanticProfiles {
		if profileIndex >= len(facts.semanticAgencies) || !facts.semanticAgencies[profileIndex] {
			continue
		}
		if profileIndex < len(facts.matchedSemanticIntents) && facts.matchedSemanticIntents[profileIndex] &&
			(profileIndex >= len(facts.unnegatedSemanticIntents) || !facts.unnegatedSemanticIntents[profileIndex]) {
			continue
		}
		coreEvidence := uint8(0)
		if profileIndex < len(facts.semanticCoreEvidence) {
			coreEvidence = facts.semanticCoreEvidence[profileIndex]
		}
		semanticAssessment := c.assessSemanticWindow(profile, semanticSignalWindow{
			signals: [][]bool{signals},
			text:    "\ue000", coreEvidence: coreEvidence, coreEvidenceKnown: true,
		}, semanticPolicy)
		semanticAssessment = constrainSemanticAssessment(semanticAssessment, thresholds)
		if semanticAssessment.score > 0 {
			assessment.considerOrdinary(
				semanticAssessment.score,
				semanticAssessment.corePredicateComplete && ordinaryEvidenceSupportsMetaAmplification(semanticAssessment.evidence),
			)
		}
	}
	assessment.meta = c.assessMetaOverride([][]bool{signals}, "\ue000", ContextFlags{}, false)

	for _, category := range classifierCategoryOrder {
		ruleIndexes := c.categoryRules[category]
		for _, intentIndex := range ruleIndexes {
			intentRule := c.rules[intentIndex]
			if intentIndex >= len(facts.unnegatedRuleIntents) || !facts.unnegatedRuleIntents[intentIndex] ||
				!signals[intentRule.intent] || !ruleHasMatchedQualifier(intentRule, signals) {
				continue
			}
			for _, objectIndex := range ruleIndexes {
				if objectIndex == intentIndex {
					continue
				}
				objectRule := c.rules[objectIndex]
				if !signals[objectRule.object] || !ruleHasMatchedQualifier(objectRule, signals) {
					continue
				}
				operational := firstPairSignalProvider(signals, intentIndex, objectIndex, intentRule.independentOperational, objectRule.independentOperational)
				target := firstPairSignalProvider(signals, intentIndex, objectIndex, intentRule.independentTarget, objectRule.independentTarget)
				evasion := firstPairSignalProvider(signals, intentIndex, objectIndex, intentRule.independentEvasion, objectRule.independentEvasion)
				scale := firstPairSignalProvider(signals, intentIndex, objectIndex, intentRule.independentScale, objectRule.independentScale)
				riskQualifiers := 0
				for _, provider := range []int{target, evasion, scale} {
					if provider >= 0 {
						riskQualifiers++
					}
				}
				if operational < 0 || riskQualifiers < 2 {
					continue
				}
				score := 45 + 20
				qualifiers := 1
				if target >= 0 {
					score += 18
					qualifiers++
				}
				if evasion >= 0 {
					score += 16
					qualifiers++
				}
				if scale >= 0 {
					score += 16
					qualifiers++
				}
				if qualifiers >= 2 {
					score += 5
				}
				assessment.considerOrdinary(score, true)
			}
		}
	}
	return assessment
}

// streamingImplementationFollowUpPotential mirrors the established
// previous-user-core plus current implementation-request path without retaining
// either logical field. It is used only when at least one field is too long for
// the exact bounded role summary; context deductions are omitted so unresolved
// cross-field composition fails closed.
func (c *Classifier) streamingImplementationFollowUpPotential(
	previous, current classificationSignalFacts,
	referentialExecution bool,
) streamingRiskAssessment {
	assessment := streamingRiskAssessment{}
	if c == nil || len(previous.signals) != c.signalCount || len(current.signals) != c.signalCount ||
		(!referentialExecution && !signalMatched(current.signals, c.implementationRequest)) {
		return assessment
	}
	for _, rule := range c.rules {
		priorStrongCore := previous.signals[rule.intent] && previous.signals[rule.object] &&
			(rule.baseScore >= BalancedThreshold || signalMatched(previous.signals, rule.target) ||
				signalMatched(previous.signals, rule.evasion) || signalMatched(previous.signals, rule.scale) ||
				previous.harmConflict)
		if !priorStrongCore {
			continue
		}
		score := rule.baseScore + 20
		qualifiers := 1
		if signalMatched(current.signals, rule.independentTarget) || signalMatched(previous.signals, rule.independentTarget) ||
			current.harmConflict || previous.harmConflict {
			score += 18
			qualifiers++
		}
		if signalMatched(current.signals, rule.independentEvasion) || signalMatched(previous.signals, rule.independentEvasion) {
			score += 16
			qualifiers++
		}
		if signalMatched(current.signals, rule.independentScale) || signalMatched(previous.signals, rule.independentScale) {
			score += 16
			qualifiers++
		}
		if qualifiers >= 2 {
			score += 5
		}
		if qualifiers >= 2 && rule.hardFloor > score {
			score = rule.hardFloor
		}
		if qualifiers < 2 && score >= BalancedThreshold {
			score = BalancedThreshold - 1
		}
		assessment.considerOrdinary(score, qualifiers >= 2)
	}
	return assessment
}

func (c *Classifier) streamingCategoryIntentsOnlyNegated(category rules.Category, facts classificationSignalFacts) bool {
	found := false
	for _, ruleIndex := range c.categoryRules[category] {
		rule := c.rules[ruleIndex]
		if !signalMatched(facts.signals, rule.intent) {
			continue
		}
		found = true
		if ruleIndex < len(facts.unnegatedRuleIntents) && facts.unnegatedRuleIntents[ruleIndex] {
			return false
		}
	}
	return found
}

// mergeStreamingRiskIngredients records only positive classifier ingredients.
// Context, safety, and meta-wrapper signals are intentionally excluded: they
// cannot by themselves make a cyber-abuse candidate actionable.
func (c *Classifier) mergeStreamingRiskIngredients(destination, source []bool) bool {
	if c == nil || len(destination) != c.signalCount || len(source) != c.signalCount {
		return false
	}
	added := false
	mark := func(signalID int) {
		if signalID < 0 || signalID >= len(source) || !source[signalID] || destination[signalID] {
			return
		}
		destination[signalID] = true
		added = true
	}
	for _, rule := range c.rules {
		mark(rule.intent)
		mark(rule.object)
		mark(rule.independentOperational)
		mark(rule.independentTarget)
		mark(rule.independentEvasion)
		mark(rule.independentScale)
	}
	mark(c.implementationRequest)
	mark(c.outcomeRequest)
	for _, profile := range c.semanticProfiles {
		for _, evidence := range profile.evidence {
			mark(evidence.signalID)
		}
	}
	return added
}

type outcomeProviders struct {
	object         int
	operational    int
	target         int
	evasion        int
	scale          int
	hasOperational bool
}

func (providers outcomeProviders) qualifierCount() int {
	count := 0
	if providers.hasOperational {
		count++
	}
	if providers.target >= 0 {
		count++
	}
	if providers.evasion >= 0 {
		count++
	}
	if providers.scale >= 0 {
		count++
	}
	return count
}

func (c *Classifier) categoryOutcomeProviders(category rules.Category, signals []bool) outcomeProviders {
	providers := outcomeProviders{object: -1, operational: -1, target: -1, evasion: -1, scale: -1}
	providers.hasOperational = signalMatched(signals, c.implementationRequest)
	for _, ruleIndex := range c.categoryRules[category] {
		rule := c.rules[ruleIndex]
		if providers.object < 0 && signalMatched(signals, rule.object) {
			providers.object = ruleIndex
		}
		if providers.operational < 0 && signalMatched(signals, rule.independentOperational) {
			providers.operational = ruleIndex
			providers.hasOperational = true
		}
		if providers.target < 0 && signalMatched(signals, rule.independentTarget) {
			providers.target = ruleIndex
		}
		if providers.evasion < 0 && signalMatched(signals, rule.independentEvasion) {
			providers.evasion = ruleIndex
		}
		if providers.scale < 0 && signalMatched(signals, rule.independentScale) {
			providers.scale = ruleIndex
		}
	}
	return providers
}

func (c *Classifier) categoryMatchedIntentsAreOnlyNegated(category rules.Category, signals []bool, analysis analyzedDirectives) bool {
	found := false
	for _, ruleIndex := range c.categoryRules[category] {
		rule := c.rules[ruleIndex]
		if !signalMatched(signals, rule.intent) {
			continue
		}
		found = true
		if !analysis.ruleIntentIsOnlyNegated(ruleIndex, rule) {
			return false
		}
	}
	return found
}

// hasExplicitHarmConflict identifies target scope that contradicts a generic
// authorization or lab claim. Ownership language may mitigate a genuinely
// scoped assessment, but it cannot authorize harm to a victim or third party.
func hasExplicitHarmConflict(text string) bool {
	return containsAnyLiteral(text,
		"victim", "third-party", "third party", "someone else's", "other people's",
		"without consent", "without permission", "i have no permission", "we have no permission", "i do not have permission",
		"we do not have permission", "i have no authorization", "we have no authorization", "no written authorization", "unauthorized", "named company",
		"do not own", "don't own", "not ours", "not mine", "target is not mine", "target site is not mine", "server is not mine",
		"not an authorized red-team exercise", "compromised host", "compromised machine", "compromised workstation",
		"competitor", "real customer", "real user", "real account",
		"attacker-controlled", "server i control", "personal storage account", "personal cloud", "my receiver",
		"受害者", "受害主机", "第三方", "他人", "未经同意", "未经许可", "未授权", "没有授权", "没有书面授权", "没有权限",
		"指定公司", "竞争对手", "真实客户", "真实用户", "真实账号", "攻击者控制",
		"不属于我们", "不属于我", "目标不属于我", "目标站点不属于我", "服务器不是我的", "不是授权红队演练",
		"非自有", "已失陷主机", "个人云盘", "私人网盘", "个人存储账号",
	)
}

// isInertQuotedSafetyReview recognizes one deliberately narrow user request:
// explain or review a single closed quotation, explicitly characterize it as
// unsafe, and end with an exact non-execution boundary. The quoted bytes retain
// their matcher signals so a later implementation follow-up can reactivate the
// underlying category, but they do not create a current-turn cyber-abuse
// candidate. Ambiguous quotations and any unquoted directive fail closed.
func (c *Classifier) isInertQuotedSafetyReview(text string) bool {
	_, ok := c.inertQuotedSafetyReviewReferent(text)
	return ok
}

func (c *Classifier) inertQuotedSafetyReviewReferent(text string) (string, bool) {
	if text == "" || !strings.Contains(text, "quoted ") || !strings.ContainsAny(text, "\"'`") {
		return "", false
	}
	if !strings.Contains(text, "quoted request") && !strings.Contains(text, "quoted prompt") {
		return "", false
	}

	spans, complete := metaOverrideQuotedSpans(text)
	if !complete || len(spans) != 1 {
		return "", false
	}
	quoted := spans[0]
	if quoted.start <= 0 || quoted.end <= quoted.start+2 || quoted.end >= len(text) {
		return "", false
	}

	prefix := strings.TrimSpace(text[:quoted.start])
	suffix := strings.TrimSpace(text[quoted.end:])
	if !inertQuotedSafetyReviewPrefix(prefix) {
		return "", false
	}
	clauses, overflow := metaOverrideDirectiveClausesBounded(suffix)
	if overflow || len(clauses) != 2 ||
		!inertQuotedSafetyAssessment(clauses[0].text) ||
		!inertQuotedNonExecutionBoundary(clauses[1].text) {
		return "", false
	}

	// The rare structural path may spend one bounded matcher pass proving that
	// the material before the quote contains no independent cyber-abuse,
	// implementation, or control-plane directive. The common route exits above
	// without allocating.
	prefixRunes := []rune(prefix)
	prefixSignals := make([]bool, c.signalCount)
	c.standardMatcher.match(prefixRunes, prefixSignals)
	if c.compactMatcher != nil {
		compactScratch := make([]bool, c.compactMatcher.maxPatternLength)
		c.compactMatcher.matchCompactWithScratch(prefixRunes, prefixSignals, compactScratch)
	}
	if prefixSignals[c.implementationRequest] || c.hasMetaOverrideSignal(prefixSignals) || hasNegationReversalFraming(prefix) {
		return "", false
	}
	for _, rule := range c.rules {
		if prefixSignals[rule.intent] || prefixSignals[rule.object] {
			return "", false
		}
	}
	referent, ok := quotedSafetyReviewSpanContent(text, quoted)
	if !ok {
		return "", false
	}
	return referent, true
}

func quotedSafetyReviewSpanContent(text string, span metaOverrideQuotedSpan) (string, bool) {
	if span.start < 0 || span.end > len(text) || span.start >= span.end {
		return "", false
	}
	quoted := text[span.start:span.end]
	var content string
	switch {
	case strings.HasPrefix(quoted, "```") && strings.HasSuffix(quoted, "```") && len(quoted) > 6:
		content = quoted[3 : len(quoted)-3]
	case strings.HasPrefix(quoted, "<sample>") && strings.HasSuffix(quoted, "</sample>"):
		content = quoted[len("<sample>") : len(quoted)-len("</sample>")]
	case strings.HasPrefix(quoted, "[sample]") && strings.HasSuffix(quoted, "[/sample]"):
		content = quoted[len("[sample]") : len(quoted)-len("[/sample]")]
	default:
		_, openingSize := utf8.DecodeRuneInString(quoted)
		_, closingSize := utf8.DecodeLastRuneInString(quoted)
		if openingSize <= 0 || closingSize <= 0 || openingSize+closingSize >= len(quoted) {
			return "", false
		}
		content = quoted[openingSize : len(quoted)-closingSize]
	}
	content = strings.TrimSpace(content)
	return content, content != ""
}

// isRawInertQuotedSafetyReview applies the exact structural proof to one raw
// complete field. It is used only on the rare adjacent-user reconstruction path
// after a quote delimiter has already passed the cheap gate. The temporary
// normalized copy is scrubbed before its backing buffer is pooled.
func (c *Classifier) isRawInertQuotedSafetyReview(text string) bool {
	_, ok := c.rawInertQuotedSafetyReviewReferent(text)
	return ok
}

func (c *Classifier) rawInertQuotedSafetyReviewReferent(text string) (string, bool) {
	if text == "" || !strings.ContainsAny(text, "\"'`") {
		return "", false
	}
	var scratch normalizationScratch
	views := normalizePartsInto([]string{text}, nil, &scratch)
	defer putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
	if views.truncated {
		return "", false
	}
	return c.inertQuotedSafetyReviewReferent(string(views.standardRunes))
}

func (c *Classifier) hasAffirmativeImplementationRequest(text string) bool {
	if c == nil || text == "" || len(c.implementationStarts) == 0 {
		return false
	}
	return containsUnnegatedRuleIntentPrepared(text, c.implementationStarts, c.implementationPatterns)
}

// hasAffirmativeQuotedReviewContinuation recognizes short, referential
// execution turns whose abuse object exists only in the preceding inert quoted
// review. It deliberately excludes bare pronouns and explanatory continuations
// so "why is that harmful?" remains safe, while "execute it" cannot discard the
// retained quoted category. A direct prohibition remains inert unless the same
// turn explicitly reverses it.
var quotedReviewSpecificContinuationIntents = []string{
	"execute it", "execute that", "execute the above", "execute the request", "execute the quoted request", "execute quoted request",
	"follow it", "follow that", "follow the above", "follow the request", "follow the quoted request", "follow quoted request",
	"obey it", "obey that", "obey the request", "obey the quoted request", "obey quoted request",
	"carry it out", "carry that out", "carry out the above", "carry out the request", "carry out the quoted request", "carry out quoted request",
	"apply it", "apply that", "apply the above", "apply the request", "apply the quoted request", "apply quoted request",
	"implement it", "implement that", "implement the above", "implement the request", "implement the quoted request", "implement quoted request",
	"do it", "do so", "do likewise", "do the same", "do that", "proceed with it", "proceed with that",
	"continue with the quoted request", "continue with the above operation",
	"run it", "run that", "run the quoted request", "run quoted request",
	"deploy it", "deploy that", "deploy the quoted request", "deploy quoted request",
	"build it", "build that", "build the quoted request", "build quoted request",
	"执行它", "执行该内容", "执行上述", "执行上面的请求", "执行前面的请求", "执行前述请求",
	"照做", "按上述执行", "按前述方案部署", "继续执行", "实施它", "实施上述",
	"应用它", "应用上述", "实现它", "实现上述", "运行它", "运行上述", "部署它", "部署上述",
}

var quotedReviewTerseContinuationIntents = []string{"proceed", "go ahead", "继续照做"}

var quotedReviewSpecificContinuationPatterns = compileCompactRuleIntentPatterns(quotedReviewSpecificContinuationIntents)
var quotedReviewTerseContinuationPatterns = compileCompactRuleIntentPatterns(quotedReviewTerseContinuationIntents)

type quotedReviewContinuationDisposition uint8

const (
	quotedReviewContinuationNone quotedReviewContinuationDisposition = iota
	quotedReviewContinuationInert
	quotedReviewContinuationCancelled
	quotedReviewContinuationActive
)

type quotedReviewContinuationDecision struct {
	disposition quotedReviewContinuationDisposition
	intent      string
	alternative bool
}

func hasAffirmativeQuotedReviewContinuation(text string) bool {
	return quotedReviewHasAffirmativeFollowUp(text, nil, compactRuleIntentPatterns{})
}

func (c *Classifier) hasAffirmativeQuotedReviewFollowUp(text string) bool {
	if c == nil || strings.TrimSpace(text) == "" || c.isInertQuotedSafetyReview(text) {
		return false
	}
	return quotedReviewHasAffirmativeFollowUp(text, c.implementationStarts, c.implementationPatterns)
}

// hasRawAffirmativeQuotedReviewFollowUp applies the unified referential
// speech-act parser to one complete raw field. The second return value proves a
// recognized inert use, while the third states whether normalization was
// complete. Streaming callers may therefore distinguish a proven explanation
// or prohibition from an unrecognized phrase that still needs conservative
// signal-based follow-up handling.
func (c *Classifier) hasRawAffirmativeQuotedReviewFollowUp(text string) (bool, bool, bool) {
	if c == nil || strings.TrimSpace(text) == "" {
		return false, false, true
	}
	var scratch normalizationScratch
	views := normalizePartsInto([]string{text}, nil, &scratch)
	defer putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
	if views.truncated {
		return false, false, false
	}
	disposition := quotedReviewFollowUpDisposition(
		string(views.standardRunes), c.implementationStarts, c.implementationPatterns,
	)
	return disposition == quotedReviewContinuationActive,
		disposition == quotedReviewContinuationInert || disposition == quotedReviewContinuationCancelled,
		true
}

func quotedReviewHasAffirmativeFollowUp(
	text string,
	explicitIntents []string,
	explicitPatterns compactRuleIntentPatterns,
) bool {
	return quotedReviewFollowUpDisposition(text, explicitIntents, explicitPatterns) ==
		quotedReviewContinuationActive
}

func quotedReviewFollowUpDisposition(
	text string,
	explicitIntents []string,
	explicitPatterns compactRuleIntentPatterns,
) quotedReviewContinuationDisposition {
	if strings.TrimSpace(text) == "" {
		return quotedReviewContinuationNone
	}
	allIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(explicitIntents))
	allIntents = append(allIntents, quotedReviewSpecificContinuationIntents...)
	allIntents = append(allIntents, quotedReviewTerseContinuationIntents...)
	allIntents = append(allIntents, explicitIntents...)
	clauses := make([]string, 0, 4)
	overflow := false
	walkDirectiveClauses([]rune(text), func(clauseRunes []rune) bool {
		if len(clauses) >= 32 {
			overflow = true
			return false
		}
		if clause := strings.TrimSpace(string(clauseRunes)); clause != "" {
			clauses = append(clauses, clause)
		}
		return true
	})
	if overflow {
		// The exact quoted-review path is optional safety credit. Fail active only
		// when the oversized continuation contains a real active speech act;
		// repeated analytical mentions and prohibitions remain inert.
		if quotedReviewOverflowTextHasActive(text, explicitIntents, allIntents) {
			return quotedReviewContinuationActive
		}
		return quotedReviewContinuationInert
	}
	sawInert := false
	sawCancellation := false
	cancellations := make([]quotedReviewContinuationDecision, 0, 4)
	for index := len(clauses) - 1; index >= 0; index-- {
		next := ""
		if index+1 < len(clauses) {
			next = clauses[index+1]
		}
		decisions, clauseInert, occurrenceOverflow := quotedReviewContinuationClauseDecisions(
			clauses[index], next, explicitIntents, explicitPatterns, allIntents,
		)
		if occurrenceOverflow {
			if quotedReviewOverflowClauseHasActive(clauses[index], next, explicitIntents, allIntents) {
				return quotedReviewContinuationActive
			}
			sawInert = true
			continue
		}
		sawInert = sawInert || clauseInert
		for _, decision := range decisions {
			if decision.disposition == quotedReviewContinuationCancelled &&
				!decision.alternative && index > 0 &&
				quotedReviewStandaloneAlternativeClause(clauses[index-1]) {
				decision.alternative = true
			}
			switch decision.disposition {
			case quotedReviewContinuationActive:
				cancelled := false
				for _, cancellation := range cancellations {
					if quotedReviewContinuationIntentsEquivalent(decision.intent, cancellation.intent) {
						cancelled = true
						break
					}
				}
				if !cancelled {
					return quotedReviewContinuationActive
				}
			case quotedReviewContinuationCancelled:
				sawCancellation = true
				if !decision.alternative {
					cancellations = append(cancellations, decision)
				}
			case quotedReviewContinuationInert:
				sawInert = true
			}
		}
	}
	if sawCancellation {
		return quotedReviewContinuationCancelled
	}
	if sawInert {
		return quotedReviewContinuationInert
	}
	return quotedReviewContinuationNone
}

func quotedReviewContinuationClauseDecisions(
	clause, next string,
	explicitIntents []string,
	explicitPatterns compactRuleIntentPatterns,
	allIntents []string,
) ([]quotedReviewContinuationDecision, bool, bool) {
	_ = explicitPatterns
	occurrences, occurrenceOverflow := quotedReviewContinuationOccurrences(clause, explicitIntents)
	if occurrenceOverflow {
		return nil, false, true
	}
	if len(occurrences) == 0 {
		return nil, false, false
	}
	sawInert := false
	decisions := make([]quotedReviewContinuationDecision, 0, len(occurrences))
	for index := len(occurrences) - 1; index >= 0; index-- {
		occurrence := occurrences[index]
		decision := quotedReviewEvaluateContinuationOccurrence(
			clause, next, occurrence, explicitIntents, allIntents,
		)
		switch decision.disposition {
		case quotedReviewContinuationActive, quotedReviewContinuationCancelled:
			decisions = append(decisions, decision)
		case quotedReviewContinuationInert:
			sawInert = true
		}
	}
	return decisions, sawInert, false
}

func quotedReviewEvaluateContinuationOccurrence(
	clause, next string,
	occurrence quotedReviewContinuationOccurrence,
	explicitIntents, allIntents []string,
) quotedReviewContinuationDecision {
	decision := quotedReviewContinuationDecision{intent: occurrence.intent}
	segment, localIndex := quotedReviewContinuationOccurrenceSegment(clause, occurrence)
	if localIndex < 0 || localIndex > len(segment) {
		return decision
	}
	if quotedReviewContinuationIsAnalytical(segment, next, localIndex) ||
		quotedReviewContinuationIsSafetyOnly(segment, explicitIntents) {
		decision.disposition = quotedReviewContinuationInert
		return decision
	}
	if !quotedReviewOccurrenceHasDirectiveHead(segment, localIndex, occurrence.intent) {
		return decision
	}
	negativeAuthorization := quotedReviewNegativeAuthorizationHead(segment, localIndex)
	directNegative := quotedReviewDirectNegativeHead(segment, localIndex)
	if negativeAuthorization {
		decision.disposition = quotedReviewContinuationCancelled
		decision.alternative = quotedReviewOccurrenceUsesAlternative(clause, occurrence) ||
			quotedReviewClauseStartsWithAlternative(segment)
		return decision
	}
	if quotedReviewAffirmativeReversalHead(segment, localIndex) {
		decision.disposition = quotedReviewContinuationActive
		return decision
	}
	if directNegative {
		decision.disposition = quotedReviewContinuationCancelled
		decision.alternative = quotedReviewOccurrenceUsesAlternative(clause, occurrence) ||
			quotedReviewClauseStartsWithAlternative(segment)
		return decision
	}
	found, negated := ruleIntentOccurrenceNegation(clause, occurrence.index)
	coordinatedNegation := found && coordinatedRuleIntentNegation(
		clause, occurrence.index, occurrence.intent, allIntents,
	)
	if found && !negated && coordinatedNegation {
		negated = true
	}
	if found && negated {
		decision.disposition = quotedReviewContinuationCancelled
		decision.alternative = !coordinatedNegation &&
			(quotedReviewOccurrenceUsesAlternative(clause, occurrence) ||
				quotedReviewClauseStartsWithAlternative(segment))
		return decision
	}
	decision.disposition = quotedReviewContinuationActive
	return decision
}

func quotedReviewOverflowTextHasActive(text string, explicitIntents, allIntents []string) bool {
	active := false
	walkDirectiveClauses([]rune(text), func(clauseRunes []rune) bool {
		clause := strings.TrimSpace(string(clauseRunes))
		if clause == "" {
			return true
		}
		if quotedReviewOverflowClauseHasActive(clause, "", explicitIntents, allIntents) {
			active = true
			return false
		}
		return true
	})
	return active
}

func quotedReviewOverflowClauseHasActive(
	clause, next string,
	explicitIntents, allIntents []string,
) bool {
	for _, intents := range [][]string{
		quotedReviewSpecificContinuationIntents,
		quotedReviewTerseContinuationIntents,
		explicitIntents,
	} {
		for _, intent := range intents {
			if intent == "" {
				continue
			}
			for offset := 0; offset <= len(clause)-len(intent); {
				relative := strings.Index(clause[offset:], intent)
				if relative < 0 {
					break
				}
				intentIndex := offset + relative
				intentEnd := intentIndex + len(intent)
				leftOK := !isASCIIStringLocal(intent) || intentIndex == 0 || !isASCIIWordByte(clause[intentIndex-1])
				rightOK := !isASCIIStringLocal(intent) || intentEnd == len(clause) || !isASCIIWordByte(clause[intentEnd])
				if leftOK && rightOK {
					decision := quotedReviewEvaluateContinuationOccurrence(
						clause,
						next,
						quotedReviewContinuationOccurrence{index: intentIndex, end: intentEnd, intent: intent},
						explicitIntents,
						allIntents,
					)
					if decision.disposition == quotedReviewContinuationActive {
						return true
					}
				}
				offset = intentIndex + 1
			}
		}
	}
	return false
}

func quotedReviewContinuationIntentsEquivalent(first, second string) bool {
	firstFamily := quotedReviewContinuationIntentFamily(first)
	secondFamily := quotedReviewContinuationIntentFamily(second)
	if firstFamily == "referential" || secondFamily == "referential" {
		return true
	}
	return firstFamily != "" && firstFamily == secondFamily
}

func quotedReviewContinuationIntentFamily(intent string) string {
	intent = strings.TrimSpace(intent)
	switch {
	case hasAnyPrefix(intent, "execute", "run", "执行", "按上述执行", "运行"):
		return "execute"
	case hasAnyPrefix(intent, "carry"):
		return "carry"
	case hasAnyPrefix(intent, "follow", "obey"):
		return "follow"
	case hasAnyPrefix(intent, "apply", "应用"):
		return "apply"
	case hasAnyPrefix(intent, "implement", "实现", "实施"):
		return "implement"
	case hasAnyPrefix(intent, "deploy", "部署"):
		return "deploy"
	case hasAnyPrefix(intent, "build"):
		return "build"
	case hasAnyPrefix(intent, "proceed", "go ahead"):
		return "proceed"
	case hasAnyPrefix(intent, "do it", "do so", "do likewise", "do the same", "do that", "照做", "继续照做"):
		return "referential"
	default:
		return intent
	}
}

func quotedReviewOccurrenceUsesAlternative(clause string, occurrence quotedReviewContinuationOccurrence) bool {
	if quotedReviewClauseStartsWithAlternative(clause) {
		return true
	}
	prefix := clause[:occurrence.index]
	for _, connector := range quotedReviewContinuationConnectors {
		if !strings.Contains(prefix, connector) {
			continue
		}
		switch strings.TrimSpace(connector) {
		case "or", "nor", "或", "或者", "否则", "要么":
			return true
		}
	}
	return false
}

func quotedReviewClauseStartsWithAlternative(clause string) bool {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#>,\t")
	return hasAnyPrefix(clause,
		"or else ", "alternatively ", "otherwise ", "if not ", "or ",
		"或者", "否则", "要么", "或",
	)
}

func quotedReviewStandaloneAlternativeClause(clause string) bool {
	clause = strings.Trim(strings.TrimSpace(clause), "-*#>,:;\t")
	return clause == "or" || clause == "alternatively" || clause == "otherwise" ||
		clause == "or else" || clause == "if not" ||
		clause == "或者" || clause == "否则" || clause == "要么" || clause == "或"
}

type quotedReviewContinuationOccurrence struct {
	index  int
	end    int
	intent string
}

func quotedReviewContinuationOccurrences(
	clause string,
	explicitIntents []string,
) ([]quotedReviewContinuationOccurrence, bool) {
	const maxOccurrences = 32
	groups := [][]string{
		quotedReviewSpecificContinuationIntents,
		quotedReviewTerseContinuationIntents,
		explicitIntents,
	}
	occurrences := make([]quotedReviewContinuationOccurrence, 0, 4)
	for _, intents := range groups {
		for _, intent := range intents {
			if intent == "" {
				continue
			}
			for offset := 0; offset <= len(clause)-len(intent); {
				relative := strings.Index(clause[offset:], intent)
				if relative < 0 {
					break
				}
				intentIndex := offset + relative
				intentEnd := intentIndex + len(intent)
				leftOK := !isASCIIStringLocal(intent) || intentIndex == 0 || !isASCIIWordByte(clause[intentIndex-1])
				rightOK := !isASCIIStringLocal(intent) || intentEnd == len(clause) || !isASCIIWordByte(clause[intentEnd])
				if leftOK && rightOK {
					duplicate := false
					for _, existing := range occurrences {
						if existing.index == intentIndex && existing.end == intentEnd {
							duplicate = true
							break
						}
					}
					if !duplicate {
						if len(occurrences) >= maxOccurrences {
							return occurrences, true
						}
						occurrences = append(occurrences, quotedReviewContinuationOccurrence{
							index:  intentIndex,
							end:    intentEnd,
							intent: intent,
						})
					}
				}
				offset = intentIndex + 1
			}
		}
	}
	for index := 1; index < len(occurrences); index++ {
		current := occurrences[index]
		position := index
		for position > 0 && (occurrences[position-1].index > current.index ||
			occurrences[position-1].index == current.index && occurrences[position-1].end > current.end) {
			occurrences[position] = occurrences[position-1]
			position--
		}
		occurrences[position] = current
	}
	return occurrences, false
}

var quotedReviewContinuationConnectors = []string{
	" and ", " or ", " nor ", " but ", " then ", " however ",
	" 或者 ", "或者", " 否则 ", "否则", " 要么 ", "要么",
	" 并且 ", " 以及 ", " 然后 ", " 但是 ", " 或者 ", "且", "并", "然后", "但是", "或",
}

func quotedReviewContinuationOccurrenceSegment(
	clause string,
	occurrence quotedReviewContinuationOccurrence,
) (string, int) {
	start := 0
	end := len(clause)
	for _, connector := range quotedReviewContinuationConnectors {
		if index := strings.LastIndex(clause[:occurrence.index], connector); index >= 0 {
			candidate := index + len(connector)
			if candidate > start {
				start = candidate
			}
		}
		if occurrence.end <= len(clause) {
			if relative := strings.Index(clause[occurrence.end:], connector); relative >= 0 {
				candidate := occurrence.end + relative
				if candidate < end {
					end = candidate
				}
			}
		}
	}
	segment := strings.TrimSpace(clause[start:end])
	trimmedPrefix := strings.TrimSpace(clause[start:occurrence.index])
	localIndex := len(trimmedPrefix)
	if trimmedPrefix != "" {
		localIndex++
	}
	if intentIndex := strings.Index(segment, occurrence.intent); intentIndex >= 0 {
		localIndex = intentIndex
	}
	return segment, localIndex
}

func quotedReviewOccurrenceHasDirectiveHead(segment string, intentIndex int, intent string) bool {
	if intentIndex < 0 || intentIndex > len(segment) {
		return false
	}
	if quotedReviewStartsWithExactIntent(strings.TrimSpace(segment), intent) {
		return true
	}
	trimmed := quotedReviewTrimDirectiveGovernors(segment)
	if quotedReviewStartsWithExactIntent(trimmed, intent) {
		return true
	}
	return quotedReviewConditionalDirective(segment, []string{intent})
}

func quotedReviewStartsWithExactIntent(clause, intent string) bool {
	if !strings.HasPrefix(clause, intent) {
		return false
	}
	return !isASCIIStringLocal(intent) || len(clause) == len(intent) || !isASCIIWordByte(clause[len(intent)])
}

func quotedReviewNegativeAuthorizationHead(segment string, intentIndex int) bool {
	if intentIndex <= 0 || intentIndex > len(segment) {
		return false
	}
	prefix := quotedReviewTrimNeutralDirectivePrefix(segment[:intentIndex])
	return hasAnyPrefix(prefix,
		"i do not authorize you to", "i don't authorize you to",
		"we do not authorize you to", "we don't authorize you to",
		"you are not authorized to", "you aren't authorized to",
		"我不授权你", "我们不授权你", "你未获授权", "你没有被授权",
	)
}

func quotedReviewAffirmativeReversalHead(segment string, intentIndex int) bool {
	if intentIndex <= 0 || intentIndex > len(segment) {
		return false
	}
	prefix := quotedReviewTrimNeutralDirectivePrefix(segment[:intentIndex])
	return hasAnyPrefix(prefix,
		"do not not", "don't not", "cannot not", "can't not",
		"do not fail to", "don't fail to", "never fail to",
		"do not refuse to", "don't refuse to", "never refuse to",
		"do not forget to", "don't forget to", "never forget to",
		"do not hesitate to", "don't hesitate to", "never hesitate to",
		"不要不", "不得不", "不能不", "不要忘记", "不得忘记",
	)
}

func quotedReviewDirectNegativeHead(segment string, intentIndex int) bool {
	if intentIndex <= 0 || intentIndex > len(segment) {
		return false
	}
	prefix := quotedReviewTrimNeutralDirectivePrefix(segment[:intentIndex])
	return hasAnyPrefix(prefix,
		"do not", "don't", "never", "must not", "should not", "cannot", "can't",
		"will not", "won't", "would not", "wouldn't", "could not", "couldn't", "may not",
		"let's not", "let us not",
		"you should not", "you must not", "you may not", "you cannot", "you can't",
		"we should not", "we must not", "we may not", "we cannot", "we can't",
		"请你不要", "你不应该", "你不应", "你不得", "你不能", "你不可以",
		"不要", "不得", "禁止", "严禁", "不能", "不应", "不可", "别",
	)
}

func quotedReviewTrimNeutralDirectivePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	for pass := 0; pass < 4; pass++ {
		before := prefix
		for _, neutral := range []string{
			"please ", "kindly ", "now ", "then ", "actually ", "instead ",
			"yes ", "sure ", "ok ", "okay ", "just ", "simply ",
			"nevertheless ", "nonetheless ", "even so ", "that said ",
			"all the same ", "regardless ", "in any case ",
			"请你", "请", "现在", "然后", "好的", "好", "是的",
		} {
			if prefix == strings.TrimSpace(neutral) {
				prefix = ""
				break
			}
			if strings.HasPrefix(prefix, neutral) {
				prefix = strings.TrimSpace(prefix[len(neutral):])
				break
			}
		}
		if prefix == before {
			break
		}
	}
	return prefix
}

func quotedReviewContinuationIntentIsActive(
	clause string,
	intents []string,
	patterns compactRuleIntentPatterns,
) bool {
	if !quotedReviewContinuationHasDirectiveHead(clause, intents) {
		return false
	}
	if metaOverrideHasDoubleNegatedInertDirective(clause) {
		return true
	}
	return containsUnnegatedRuleIntentPrepared(
		clause,
		intents,
		patterns,
	)
}

func quotedReviewContinuationExplicitlyNegates(
	clause string,
	intents []string,
	patterns compactRuleIntentPatterns,
) bool {
	if metaOverrideHasDoubleNegatedInertDirective(clause) {
		return false
	}
	var scratch ruleIntentNegationScratch
	scratch.reset(clause)
	found, negates := clauseRuleIntentNegationPrepared(&scratch, intents, patterns)
	return found && negates
}

func quotedReviewContinuationIsAnalytical(clause, next string, intentIndex int) bool {
	if intentIndex < 0 || intentIndex > len(clause) {
		return false
	}
	prefix := strings.TrimSpace(clause[:intentIndex])
	for {
		before := prefix
		for _, polite := range []string{
			"please ", "kindly ", "tell me ", "can you ", "could you ", "would you ", "will you ",
			"请问", "请解释", "可以解释", "告诉我", "请",
		} {
			if strings.HasPrefix(prefix, polite) {
				prefix = strings.TrimSpace(prefix[len(polite):])
				break
			}
		}
		if prefix == before {
			break
		}
	}
	if hasAnyPrefix(prefix,
		"what would happen if", "what happens if", "what if",
		"what does", "what do", "what did", "what is the meaning of",
		"explain what would happen if", "explain what happens if",
		"describe what would happen if", "describe what happens if",
		"analyze what would happen if", "analyze what happens if",
		"what are the consequences if", "what are the risks if",
		"explain the consequences if", "explain the risks if",
		"analyze the consequences if", "analyze the risks if",
		"should i", "should we", "can i", "can we", "could i", "could we",
		"may i", "may we", "would i", "would we", "whether i should", "whether we should",
		"explain whether i should", "explain whether we should",
		"analyze whether i should", "analyze whether we should",
		"should you", "are you authorized to", "why not",
		"did i", "did you", "did we", "did they", "have i", "have you", "have we", "have they",
		"why did", "when did", "where did", "who asked", "who told",
		"is it safe to", "is it unsafe to", "is it harmful to",
		"why is it harmful to", "why is it unsafe to",
		"would it be harmful to", "would it be unsafe to",
		"是否应该", "我是否应该", "我应该", "我能", "我可以", "我们应该", "我们能", "我们可以",
		"你是否应该", "你应该吗", "这样做是否安全", "这样做是否有害",
	) {
		return true
	}
	if quotedReviewConditionalDecisionQuestion(prefix) {
		return true
	}
	if hasAnyPrefix(prefix,
		"if i ", "if we ", "if someone ", "if they ", "when i ", "when we ",
		"assuming i ", "assuming we ", "suppose i ", "suppose we ",
		"如果我", "如果我们", "假如我", "假如我们", "倘若我", "倘若我们",
	) && (containsAnyLiteral(clause[intentIndex:],
		"what would happen", "what happens", "what are the consequences", "what are the risks",
		"会发生什么", "有什么后果", "后果是什么", "风险是什么",
	) || quotedReviewConsequenceQuestion(next)) {
		return true
	}
	return containsAnyLiteral(clause,
		"会发生什么", "有什么后果", "后果是什么", "风险是什么", "是否安全", "是否有害",
		"是什么意思", "安全吗", "有害吗", "危险吗",
	)
}

func quotedReviewConditionalDecisionQuestion(prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	for _, condition := range []string{
		"if approved", "if ready", "if authorized", "if checks pass",
		"if you can", "if you are ready", "once approved", "when approved", "after approval",
		"如果获批", "如果通过检查", "如果准备好了", "获批后", "通过检查后",
	} {
		if !strings.HasPrefix(prefix, condition) {
			continue
		}
		rest := strings.TrimSpace(prefix[len(condition):])
		if hasAnyPrefix(rest,
			"should i", "should we", "can i", "can we", "could i", "could we",
			"may i", "may we", "would it", "is it safe to", "is it harmful to",
			"我应该", "我能", "我可以", "我们应该", "我们能", "我们可以", "是否应该",
		) {
			return true
		}
	}
	return false
}

func quotedReviewConsequenceQuestion(clause string) bool {
	clause = strings.TrimSpace(clause)
	return hasAnyPrefix(clause,
		"what would happen", "what happens", "what are the consequences", "what are the risks",
		"会发生什么", "有什么后果", "后果是什么", "风险是什么",
	)
}

func quotedReviewContinuationIsSafetyOnly(clause string, explicitIntents []string) bool {
	safetyFraming := hasExplanatoryFraming(clause) || isSafetyDeliverableClause(clause) ||
		hasAffirmativeSafetyPurpose(clause) || quotedReviewSafetyContinuation(clause)
	if !safetyFraming || quotedReviewOperationalExplanationGovernor(clause) {
		return false
	}
	return !explanatoryFramingTurnsOperational(clause, quotedReviewSpecificContinuationIntents) &&
		!explanatoryFramingTurnsOperational(clause, quotedReviewTerseContinuationIntents) &&
		!explanatoryFramingTurnsOperational(clause, explicitIntents)
}

func quotedReviewSafetyContinuation(clause string) bool {
	return containsAnyLiteral(clause,
		"safety explanation", "safety analysis", "safety review", "risk explanation", "risk analysis",
		"harm explanation", "harm analysis", "defensive explanation", "defensive analysis",
		"安全解释", "安全分析", "安全审查", "风险解释", "风险分析", "危害解释", "危害分析", "防御解释", "防御分析",
	)
}

func quotedReviewOperationalExplanationGovernor(clause string) bool {
	clause = quotedReviewTrimIntroductoryGovernors(clause)
	return hasAnyPrefix(clause,
		"explain step by step how to ", "explain in detail how to ", "explain how to ",
		"show me step by step how to ", "show me how to ",
		"tell me the exact steps to ", "tell me detailed steps to ", "tell me how to ",
		"describe step by step how to ", "describe how to ",
		"provide step-by-step instructions to ", "provide step by step instructions to ",
		"give me detailed steps to ", "give me the exact steps to ",
		"walk me through how to ", "teach me how to ",
		"how do i ", "how can i ", "how would you ",
		"解释如何", "说明如何", "告诉我如何", "演示如何",
	)
}

func quotedReviewTrimIntroductoryGovernors(clause string) string {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#>,，:： \t")
	for pass := 0; pass < 6; pass++ {
		before := clause
		for _, prefix := range []string{
			"please ", "kindly ", "now ", "then ", "actually ", "instead ",
			"yes ", "sure ", "ok ", "okay ", "just ", "simply ", "really ",
			"quickly ", "quietly ", "carefully ", "promptly ",
			"directly ", "immediately ", "still ", "anyway ",
			"nevertheless ", "nonetheless ", "even so ", "that said ",
			"all the same ", "regardless ", "in any case ",
			"or else ", "alternatively ", "otherwise ", "if not ", "or ", "either ",
			"can you ", "could you ", "would you ", "will you ",
			"或者", "否则", "要么", "或",
			"请问你能不能", "请问你能", "请问你可以", "请你", "请",
			"现在", "然后", "好的", "好", "是的", "直接", "立即", "马上", "仍然", "你能", "你可以", "就",
		} {
			if strings.HasPrefix(clause, prefix) {
				clause = strings.TrimLeft(strings.TrimSpace(clause[len(prefix):]), ",，:：- ")
				break
			}
		}
		if clause == before {
			break
		}
	}
	return clause
}

func quotedReviewContinuationHasDirectiveHead(clause string, intents []string) bool {
	if len(intents) == 0 {
		return false
	}
	candidates := []string{clause}
	for _, connector := range []string{
		" and ", " or ", " nor ", " but ", " then ", " however ",
		" 并且 ", " 以及 ", " 然后 ", " 但是 ", " 或者 ", "且", "并", "然后", "但是", "或",
	} {
		if index := strings.LastIndex(clause, connector); index >= 0 {
			candidates = append(candidates, clause[index+len(connector):])
		}
	}
	for _, candidate := range candidates {
		candidate = strings.TrimLeft(strings.TrimSpace(candidate), "-*#>,，:： \t")
		if quotedReviewStartsWithIntent(candidate, intents) ||
			quotedReviewConditionalDirective(candidate, intents) {
			return true
		}
		candidate = quotedReviewTrimDirectiveGovernors(candidate)
		if quotedReviewStartsWithIntent(candidate, intents) ||
			quotedReviewConditionalDirective(candidate, intents) {
			return true
		}
	}
	return metaOverrideHasDoubleNegatedInertDirective(clause) &&
		earliestRuleIntentIndex(clause, intents) >= 0
}

func quotedReviewTrimDirectiveGovernors(clause string) string {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#>,，:： \t")
	for pass := 0; pass < 6; pass++ {
		before := clause
		for _, prefix := range []string{
			"or else ", "alternatively ", "otherwise ", "if not ", "or ", "either ",
			"nevertheless ", "nonetheless ", "even so ", "that said ",
			"all the same ", "regardless ", "in any case ",
			"also ", "ultimately ", "finally ", "eventually ", "subsequently ", "afterwards ", "again ",
			"或者", "否则", "要么", "或",
			"也", "还是", "仍然", "最终", "随后", "接着", "再",
			"i do not authorize you to ", "i don't authorize you to ",
			"we do not authorize you to ", "we don't authorize you to ",
			"you are not authorized to ", "you aren't authorized to ",
			"do not fail to ", "don't fail to ", "never fail to ",
			"do not refuse to ", "don't refuse to ", "never refuse to ",
			"do not forget to ", "don't forget to ", "never forget to ",
			"do not hesitate to ", "don't hesitate to ", "never hesitate to ",
			"do not not ", "don't not ", "cannot not ", "can't not ",
			"let's not ", "let us not ",
			"you should not ", "you must not ", "you may not ", "you cannot ", "you can't ",
			"we should not ", "we must not ", "we may not ", "we cannot ", "we can't ",
			"do not ", "don't ", "never ", "must not ", "should not ", "cannot ", "can't ",
			"will not ", "won't ", "would not ", "wouldn't ", "could not ", "couldn't ", "may not ",
			"i authorize you to ", "we authorize you to ", "i permit you to ", "we permit you to ", "you are authorized to ",
			"you have permission to ", "feel free to ",
			"your task is to ", "be sure to ", "make sure you ", "make sure to ",
			"you should ", "you must ", "you shall ", "you ought to ", "you may ", "you can ", "you need to ",
			"we should ", "we must ", "we may ", "we can ", "we need to ",
			"the assistant should ", "the assistant must ", "the assistant shall ", "the assistant ought to ",
			"the model should ", "the model must ", "the model shall ", "the model ought to ",
			"assistant should ", "assistant must ", "assistant shall ",
			"model should ", "model must ", "model shall ",
			"please ", "kindly ", "now ", "then ", "actually ", "instead ",
			"yes ", "sure ", "ok ", "okay ", "just ", "simply ", "really ",
			"quickly ", "quietly ", "carefully ", "promptly ",
			"directly ", "immediately ", "still ", "anyway ", "let's ", "let us ",
			"can you ", "could you ", "would you ", "will you ",
			"i need you to ", "i want you to ", "go ahead and ",
			"explain step by step how to ", "explain in detail how to ", "explain how to ",
			"show me step by step how to ", "show me how to ",
			"tell me the exact steps to ", "tell me detailed steps to ", "tell me how to ",
			"provide step-by-step instructions to ", "provide step by step instructions to ",
			"give me detailed steps to ", "give me the exact steps to ",
			"describe step by step how to ", "describe how to ",
			"walk me through how to ", "teach me how to ",
			"how do i ", "how can i ", "how would you ",
			"我不授权你", "我们不授权你", "你未获授权", "你没有被授权",
			"请你不要", "你不应该", "你不应", "你不得", "你不能", "你不可以",
			"不要不", "不得不", "不能不", "不要", "不得", "禁止", "严禁", "不能", "不应", "不可", "别",
			"我授权你", "我们授权你", "请问你能不能", "请问你能", "请问你可以", "请帮我", "麻烦你", "请你",
			"你应该", "你必须", "你可以", "你能", "务必", "请",
			"现在", "然后", "好的", "好", "是的", "直接", "立即", "马上", "仍然", "就",
			"解释如何", "说明如何", "告诉我如何", "演示如何",
		} {
			if strings.HasPrefix(clause, prefix) {
				clause = strings.TrimLeft(strings.TrimSpace(clause[len(prefix):]), ",，:：- ")
				break
			}
		}
		if clause == before {
			break
		}
	}
	return clause
}

func quotedReviewStartsWithIntent(clause string, intents []string) bool {
	for _, intent := range intents {
		if !strings.HasPrefix(clause, intent) {
			continue
		}
		if !isASCIIStringLocal(intent) || len(clause) == len(intent) || !isASCIIWordByte(clause[len(intent)]) {
			return true
		}
	}
	return false
}

func quotedReviewConditionalDirective(clause string, intents []string) bool {
	intentIndex := earliestRuleIntentIndex(clause, intents)
	if intentIndex <= 0 {
		return false
	}
	prefix := strings.TrimSpace(clause[:intentIndex])
	prefix = strings.TrimRight(prefix, ",，:：")
	for _, condition := range []string{
		"if approved", "if ready", "if authorized", "if checks pass",
		"if you can", "if you are ready", "once approved", "when approved", "after approval",
		"如果获批", "如果通过检查", "如果准备好了", "获批后", "通过检查后",
	} {
		if prefix == condition || strings.HasPrefix(prefix, condition+" ") {
			return true
		}
	}
	return false
}

// priorPartsAllowInertQuotedSafetyReview prevents a safe-looking final review
// from hiding an earlier actionable request in the same multipart/untrusted
// classification. This path runs only after the current part has satisfied the
// narrow quote structure. Earlier reviews that independently satisfy the same
// proof are blanked from this secondary scan: they are already inert, must not
// recursively re-enter this proof, and must not lend quoted signals to another
// part. Within the small optional-proof budget, every other earlier byte remains
// subject to the conservative roleless adapter. Larger histories receive no
// credit instead of triggering a second large streaming scan.
func (c *Classifier) priorPartsAllowInertQuotedSafetyReview(parts []string, currentPartIndex int, mode Mode, thresholds Thresholds, policy Policy) bool {
	if currentPartIndex <= 0 {
		return true
	}
	if currentPartIndex > maxInertReviewPriorParts {
		return false
	}
	priorParts := parts[:currentPartIndex]
	priorBytes := 0
	for _, part := range priorParts {
		if len(part) > maxInertReviewPriorBytes-priorBytes {
			return false
		}
		priorBytes += len(part)
	}
	scannedPriorParts := make([]string, len(priorParts))
	for index, part := range priorParts {
		var scratch normalizationScratch
		views := normalizePartsInto([]string{part}, takeNormalizedRuneBuffer(), &scratch)
		if views.truncated {
			putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
			return false
		}
		inert := c.isInertQuotedSafetyReview(string(views.standardRunes))
		putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
		if !inert {
			scannedPriorParts[index] = part
		}
	}

	// Reuse the conservative roleless adapter: it independently scans earlier
	// parts and their adjacent combinations, so appended benign history cannot
	// erase a prior block/audit finding. Provider-native tool privileges are not
	// carried into this optional safety-credit proof.
	priorResult := c.ClassifyUntrustedPartsWithPolicy(scannedPriorParts, mode, thresholds, policy)
	if priorResult.Truncated ||
		(priorResult.Coverage.State != "" && priorResult.Coverage.State != CoverageComplete) {
		return false
	}
	return priorResult.Action == ActionAllow && priorResult.Score < thresholds.Audit
}

func inertQuotedSafetyReviewPrefix(prefix string) bool {
	prefix = strings.Join(strings.Fields(prefix), " ")
	for _, allowed := range []string{
		"explain why the quoted request", "explain why this quoted request",
		"analyze why the quoted request", "analyze why this quoted request",
		"analyse why the quoted request", "analyse why this quoted request",
		"review why the quoted request", "review why this quoted request",
		"explain why the quoted prompt", "explain why this quoted prompt",
		"analyze why the quoted prompt", "analyze why this quoted prompt",
		"analyse why the quoted prompt", "analyse why this quoted prompt",
		"review why the quoted prompt", "review why this quoted prompt",
	} {
		if prefix == allowed || prefix == "for a defensive review, "+allowed {
			return true
		}
	}
	return false
}

func inertQuotedSafetyAssessment(clause string) bool {
	switch strings.Join(strings.Fields(clause), " ") {
	case "is harmful", "is unsafe", "is dangerous", "is abusive", "is malicious",
		"should be refused", "should be declined", "must be refused":
		return true
	default:
		return false
	}
}

func inertQuotedNonExecutionBoundary(clause string) bool {
	clause = strings.Join(strings.Fields(normalizeNegationSyntax(clause)), " ")
	switch clause {
	case "do not provide code or operational steps",
		"do not provide code",
		"do not provide operational steps",
		"do not implement it",
		"do not implement the request",
		"do not implement the quoted request",
		"do not execute it",
		"do not execute the request",
		"do not execute the quoted request",
		"do not follow it",
		"do not follow the request",
		"do not follow the quoted request",
		"do not apply it",
		"do not apply the request",
		"do not apply the quoted request",
		"keep the example inert",
		"keep the quoted request inert",
		"keep the quoted prompt inert":
		return true
	default:
		return false
	}
}

// isLegitimateCategoryWorkflow recognizes a narrow set of ordinary identity
// and encryption workflows that necessarily share verbs and objects with
// abuse. It is deliberately category-scoped and hostile markers always win,
// so generic safety labels cannot wash out a victim-targeted directive.
func isLegitimateCategoryWorkflow(category rules.Category, text string) bool {
	if hasExplicitHarmConflict(text) {
		return false
	}
	if category == rules.CategoryCredentialTheft &&
		containsAnyLiteral(text, "offline forensics", "memory image", "forensic image", "离线取证", "内存镜像", "取证镜像") &&
		containsAnyLiteral(text, "do not extract real passwords", "without extracting real passwords", "不提取真实密码", "不导出真实密码") &&
		!containsAnyLiteral(text,
			"victim", "someone else's", "other people's", "steal", "siphon", "exfiltrate", "bypass", "undetected",
			" but ", " instead ", " however ", " then ", " actually ", "do not refuse", "ignore the policy",
			"受害者", "他人", "窃取", "盗取", "外传", "回传", "绕过", "但是", "然后", "改为", "实际",
		) {
		return true
	}
	switch category {
	case rules.CategoryCredentialTheft, rules.CategoryPhishing:
		if credentialApprovedStoreWorkflow(text) {
			return true
		}
		if !containsAnyLiteral(text,
			"oauth response", "oauth callback", "token exchange response",
			"our login form", "our sign-in form", "our login page", "our sign-in page",
			"our login portal", "our sign-in portal", "our sso", "our authentication server",
			"users can log in", "users can sign in", "customers can log in", "customers can sign in",
			"normal authentication endpoint", "authenticate the user", "authenticate them",
			"credential migration", "credential rotation", "password manager export",
			"secrets manager", "account recovery",
			"我们的登录表单", "我们的登录页面", "我们的登录门户", "我们的认证服务器",
			"用户可以登录", "客户可以登录", "正常认证接口",
			"认证用户", "凭证轮换", "凭证迁移", "密码管理器导出", "密钥管理器", "账号恢复",
		) {
			return false
		}
		if credentialMetadataHostileConflict(text) {
			return false
		}
		return !containsAnyLiteral(text,
			"victim", "someone else's", "other people's", "without consent", "unauthorized",
			"steal", "credential stealer", "phishing", "fake login", "cloned login",
			"real brand", "lookalike", "external server", "collection server", "webhook",
			"bypass", "undetected", "silently",
			"受害者", "他人", "未经同意", "未授权", "窃取", "钓鱼", "假登录", "仿冒登录",
			"真实品牌", "外部服务器", "回传服务器", "绕过", "静默",
		)
	case rules.CategoryRansomware:
		if containsAnyLiteral(text, "fictional game", "game prop", "fictional story", "虚构游戏", "游戏道具", "虚构故事") &&
			containsAnyLiteral(text, "ransom note", "extortion note", "勒索信", "勒索便笺") &&
			!containsAnyLiteral(text,
				"deploy", "execute", "encrypt files", "delete backups", "remove restore", "demand payment",
				"部署", "执行", "加密文件", "删除备份", "删除还原点", "索要付款") {
			return true
		}
		// Recovery exercises often need to name a contained extortion sample.
		// Treat the workflow as legitimate only when the text independently
		// states both a recovery purpose and a non-execution/rollback control;
		// victim or third-party scope has already been rejected above.
		if hasAffirmativeSafetyPurpose(text) &&
			containsAnyLiteral(text,
				"recovery drill", "restoration exercise", "restoration sequence", "synthetic documents", "lab workstations",
				"恢复演练", "还原演练", "合成文档", "实验室工作站") &&
			containsAnyLiteral(text,
				"without running", "without executing", "preserves rollback", "preserve rollback", "immutable backups",
				"不运行", "不执行", "保留回滚", "不可变备份") {
			return true
		}
		if !containsAnyLiteral(text,
			"secure backup", "off-site backup", "offsite backup", "backup encryption",
			"encryption at rest", "disk encryption", "full-disk encryption", "protect files",
			"protect data", "data protection", "key management", "our files", "my files",
			"test fixture", "backup archive",
			"安全备份", "异地备份", "备份加密", "静态加密", "磁盘加密", "全盘加密",
			"保护文件", "保护数据", "数据保护", "密钥管理", "我们的文件", "我的文件", "测试样本",
		) {
			return false
		}
		return !containsAnyLiteral(text,
			"victim", "ransom", "extortion", "demand payment", "pay to restore", "bitcoin",
			"delete backups", "remove restore", "disable recovery", "spread", "propagate",
			"employee files", "production files", "target network", "undetected",
			"受害者", "勒索", "索要付款", "支付赎金", "比特币", "删除备份", "删除还原点",
			"关闭恢复", "传播", "员工文件", "生产文件", "目标网络", "静默",
		)
	case rules.CategoryExfiltration:
		// An investigation can quote a prohibited transfer while describing an
		// abnormal-export finding, trace preservation, and containment. Require
		// all four defensive facets so a generic safety label cannot suppress an
		// otherwise operational transfer request.
		if containsAnyLiteral(text,
			"abnormal export", "suspicious export", "unauthorized export", "异常导出", "可疑导出", "未授权导出") &&
			containsAnyLiteral(text,
				"correlate logs", "retain logs", "audit logs", "access logs", "关联日志", "访问日志", "审计日志", "保留日志") &&
			containsAnyLiteral(text,
				"block egress", "disable egress", "cut off egress", "封禁外送", "阻断外送", "切断外送") &&
			containsAnyLiteral(text,
				"do not execute", "must not execute", "without executing", "不得执行", "不要执行", "禁止执行") {
			return true
		}
		if !containsAnyLiteral(text,
			"approved backup", "backup policy", "disaster recovery", "recovery vault",
			"backup team", "working copy",
			"organization-owned", "company-owned", "approved migration", "data migration",
			"ediscovery", "external counsel", "legal hold", "retention archive", "authorized export",
			"批准的备份", "备份策略", "灾难恢复", "恢复保管库", "备份团队", "工作副本", "组织自有", "公司自有",
			"批准迁移", "数据迁移", "电子取证", "外部律师", "法律保全", "留存归档", "授权导出",
		) {
			return false
		}
		return !containsAnyLiteral(text,
			"attacker-controlled", "server i control", "personal storage", "personal cloud", "private drive",
			"covert", "without raising an alert", "avoid alert", "undetected", "compromised host", "victim",
			"攻击者控制", "我的服务器", "个人存储", "个人云盘", "私人网盘", "隐蔽", "避开告警", "受害",
		)
	case rules.CategoryDisruption:
		// Authorized load/capacity work is legitimate only when ownership and a
		// concrete safety ceiling are both explicit. Hostile target/outcome terms
		// are rejected by hasExplicitHarmConflict above before this exception.
		return containsAnyLiteral(text,
			"approved", "authorized", "our own", "our service", "our public api", "owned service",
			"批准", "授权", "自有服务", "我方服务", "我方接口",
		) && containsAnyLiteral(text,
			"load test", "capacity test", "capacity planning", "automated traffic", "rate limit",
			"压测", "容量测试", "容量规划", "自动化流量", "限流",
		) && containsAnyLiteral(text,
			"capped", "below", "test ceiling", "approved window", "stop at", "within the limit",
			"封顶", "低于", "测试上限", "批准窗口", "达到上限即停止", "限制以内",
		)
	default:
		return false
	}
}

func containsAnyLiteral(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, value) {
			return true
		}
	}
	return false
}

func categoryPriority(category rules.Category) int {
	switch category {
	case rules.CategoryPhishing:
		return 0
	case rules.CategoryCredentialTheft:
		return 1
	case rules.CategoryRansomware:
		return 2
	case rules.CategoryExfiltration:
		return 3
	case rules.CategoryEvasion:
		return 4
	case rules.CategoryExploitation:
		return 5
	case rules.CategoryDisruption:
		return 6
	case rules.CategoryMalware:
		return 7
	default:
		return 8
	}
}

const maxAnalyzedDirectiveClauses = 64

const inlineDirectiveRuleWords = 4

type directiveRuleIndexSet struct {
	inline   [inlineDirectiveRuleWords]uint64
	overflow []uint32
}

func (set *directiveRuleIndexSet) add(ruleIndex int) {
	if ruleIndex < 0 {
		return
	}
	word := ruleIndex / 64
	if word < len(set.inline) {
		set.inline[word] |= uint64(1) << uint(ruleIndex%64)
		return
	}
	set.overflow = append(set.overflow, uint32(ruleIndex))
}

func (set directiveRuleIndexSet) matched(ruleIndex int) bool {
	if ruleIndex < 0 {
		return false
	}
	word := ruleIndex / 64
	if word < len(set.inline) {
		return set.inline[word]&(uint64(1)<<uint(ruleIndex%64)) != 0
	}
	for _, candidate := range set.overflow {
		if int(candidate) == ruleIndex {
			return true
		}
		if int(candidate) > ruleIndex {
			break
		}
	}
	return false
}

type analyzedDirectiveClause struct {
	runes                      []rune
	text                       string
	signals                    directiveSignalSet
	occurrences                []signalOccurrence
	negatedRuleIntents         directiveRuleIndexSet
	semanticIntentsPresent     uint16
	semanticIntentsOnlyNegated uint16
	boundaryBefore             directiveBoundaryKind
}

type directiveClauseProofCacheEntry struct {
	text                       string
	negatedRuleIntents         directiveRuleIndexSet
	semanticIntentsPresent     uint16
	semanticIntentsOnlyNegated uint16
}

func directiveRunesEqualString(runes []rune, text string) bool {
	index := 0
	for _, r := range text {
		if index >= len(runes) || runes[index] != r {
			return false
		}
		index++
	}
	return index == len(runes)
}

type directiveSignalSet []uint32

func (signals directiveSignalSet) matched(signalID int) bool {
	if signalID < 0 || uint64(signalID) > uint64(^uint32(0)) {
		return false
	}
	target := uint32(signalID)
	left, right := 0, len(signals)
	for left < right {
		middle := left + (right-left)/2
		if signals[middle] < target {
			left = middle + 1
		} else {
			right = middle
		}
	}
	return left < len(signals) && signals[left] == target
}

func analyzedDirectiveSignalMatched(sparse directiveSignalSet, dense []bool, signalID int) bool {
	if dense != nil {
		return signalMatched(dense, signalID)
	}
	return sparse.matched(signalID)
}

func encodeDirectiveSignals(destination directiveSignalSet, signals []bool) directiveSignalSet {
	destination = destination[:0]
	for signalID, matched := range signals {
		if matched {
			destination = append(destination, uint32(signalID))
		}
	}
	return destination
}

func directiveRunesEqual(left, right []rune) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type analyzedDirectiveRuleState struct {
	foundIntent     bool
	unnegatedIntent bool
	foundCore       bool
	unnegatedCore   bool
	contradictory   bool
}

type categoryCompositionMatch struct {
	found                               bool
	contradictory                       bool
	localScore                          int
	intent, object                      int
	operational, target, evasion, scale int
}

type analyzedDirectives struct {
	clauses                                  []analyzedDirectiveClause
	overflowTail                             []analyzedDirectiveClause
	overflowRuleStates                       []analyzedDirectiveRuleState
	overflowPairContradictions               []uint64
	overflowCategoryComposition              [8]categoryCompositionMatch
	overflowCategoryContradictoryComposition [8]categoryCompositionMatch
	overflowSemantic                         []semanticAssessment
	overflow                                 bool
	occurrenceBudgetExhausted                bool
	semanticWindows                          []semanticSignalWindow
}

func directiveProviderPairIndex(ruleCount, intentProvider, objectProvider int) (int, bool) {
	if ruleCount <= 0 || intentProvider < 0 || intentProvider >= ruleCount || objectProvider < 0 || objectProvider >= ruleCount {
		return 0, false
	}
	return intentProvider*ruleCount + objectProvider, true
}

func markDirectiveProviderPair(destination []uint64, ruleCount, intentProvider, objectProvider int) {
	pairIndex, ok := directiveProviderPairIndex(ruleCount, intentProvider, objectProvider)
	if !ok || pairIndex/64 >= len(destination) {
		return
	}
	destination[pairIndex/64] |= uint64(1) << uint(pairIndex%64)
}

func directiveProviderPairMatched(source []uint64, ruleCount, intentProvider, objectProvider int) bool {
	pairIndex, ok := directiveProviderPairIndex(ruleCount, intentProvider, objectProvider)
	if !ok || pairIndex/64 >= len(source) {
		return false
	}
	return source[pairIndex/64]&(uint64(1)<<uint(pairIndex%64)) != 0
}

// analyzeDirectives scans the current part once and shares the result across
// all candidate rules. The previous implementation reran both literal
// automata for every candidate, making adversarial candidate-rich input scale
// with rules times input size.
func (c *Classifier) analyzeDirectives(text []rune, policy Policy) analyzedDirectives {
	clauseCapacityHint := c.directiveClauseCapacityHint(text)
	analysis := analyzedDirectives{clauses: make([]analyzedDirectiveClause, 0, clauseCapacityHint)}
	normalizedText := string(text)
	byteCursorRune := 0
	byteCursor := 0
	byteOffsetForRune := func(target int) int {
		for byteCursorRune < target {
			width := utf8.RuneLen(text[byteCursorRune])
			if width < 0 {
				// string([]rune) replaces invalid scalar values (including the
				// internal compactHardBoundary sentinel) with U+FFFD. Keep the
				// rune-to-byte cursor aligned with normalizedText's real encoding.
				width = utf8.RuneLen(utf8.RuneError)
			}
			byteCursor += width
			byteCursorRune++
		}
		return byteCursor
	}
	clauseSignals := make([]bool, c.signalCount)
	clauseSignalIDs := make(directiveSignalSet, 0, 16)
	compactScratch := make([]bool, c.compactMatcher.maxPatternLength)
	compactStartScratch := make([]int, c.compactMatcher.maxPatternLength)
	clauseOccurrences := make([]signalOccurrence, 0, 32)
	clauseOccurrencesPublished := false
	var retainedOccurrenceStorage []signalOccurrence
	var retainedOccurrenceOverflowStorage []signalOccurrence
	var retainedSignalStorage directiveSignalSet
	clauseSignalIDsPublished := false
	nextClauseID := 0
	var negationScratch ruleIntentNegationScratch
	var proofCache [4]directiveClauseProofCacheEntry
	proofCacheNext := 0
	retainNextContext := false
	strongBoundarySinceRetained := false
	var overflowSignalBuffers [maxSemanticDirectiveSpan]directiveSignalSet
	var overflowOccurrenceBuffers [maxSemanticDirectiveSpan][]signalOccurrence
	var overflowSemanticSignalStorage [maxSemanticDirectiveSpan]directiveSignalSet
	overflowBufferIndex := 0

	prepareOverflow := func() {
		if analysis.overflow {
			return
		}
		analysis.overflow = true
		analysis.overflowRuleStates = make([]analyzedDirectiveRuleState, len(c.rules))
		pairCount := len(c.rules) * len(c.rules)
		analysis.overflowPairContradictions = make([]uint64, (pairCount+63)/64)
		previousText := ""
		for _, clause := range analysis.clauses {
			if clause.text == previousText {
				continue
			}
			c.updateAnalyzedDirectiveRuleStates(analysis.overflowRuleStates, clause, nil, policy.Allow)
			previousText = clause.text
		}
		analysis.overflowSemantic = make([]semanticAssessment, len(c.semanticProfiles))
		start := len(analysis.clauses) - (maxSemanticDirectiveSpan - 1)
		if start < 0 {
			start = 0
		}
		analysis.overflowTail = make([]analyzedDirectiveClause, 0, maxSemanticDirectiveSpan)
		analysis.overflowTail = append(analysis.overflowTail, analysis.clauses[start:]...)
	}

	recordOverflowClause := func(clause analyzedDirectiveClause, denseSignals []bool) {
		prepareOverflow()
		duplicate := false
		if len(analysis.overflowTail) != 0 {
			previous := analysis.overflowTail[len(analysis.overflowTail)-1]
			duplicate = previous.boundaryBefore == clause.boundaryBefore && previous.text == clause.text
		}
		if !duplicate {
			c.updateAnalyzedDirectiveRuleStates(analysis.overflowRuleStates, clause, denseSignals, policy.Allow)
			for _, category := range classifierCategoryOrder {
				priority := categoryPriority(category)
				summary := &analysis.overflowCategoryComposition[priority]
				contradictorySummary := &analysis.overflowCategoryContradictoryComposition[priority]
				c.updateCategoryDirectivePairContradictions(
					category, c.categoryRules[category], clause, denseSignals, policy.Allow, analysis.overflowPairContradictions,
				)
				if match, ok := c.matchCategoryCompositionClauseWithDense(c.categoryRules[category], clause, denseSignals, policy); ok {
					if match.contradictory {
						markDirectiveProviderPair(
							analysis.overflowPairContradictions, len(c.rules), match.intent, match.object,
						)
					}
					if preferCategoryCompositionMatch(match, *summary) {
						*summary = match
					}
					if match.contradictory && preferCategoryCompositionMatch(match, *contradictorySummary) {
						*contradictorySummary = match
					}
				}
			}
		}

		// Keep only the exact semantic suffix. The reusable signal ring bounds
		// overflow memory independently of clause count while preserving every
		// window (maximum span four) that ends in the newly scanned clause.
		if len(analysis.overflowTail) == maxSemanticDirectiveSpan {
			copy(analysis.overflowTail, analysis.overflowTail[1:])
			analysis.overflowTail = analysis.overflowTail[:maxSemanticDirectiveSpan-1]
		}
		signalBuffer := overflowSignalBuffers[overflowBufferIndex]
		if cap(signalBuffer) < len(clause.signals) {
			signalBuffer = make(directiveSignalSet, len(clause.signals))
		} else {
			signalBuffer = signalBuffer[:len(clause.signals)]
		}
		overflowSignalBuffers[overflowBufferIndex] = signalBuffer
		copy(signalBuffer, clause.signals)
		clause.signals = signalBuffer
		occurrenceBuffer := overflowOccurrenceBuffers[overflowBufferIndex]
		if cap(occurrenceBuffer) < len(clause.occurrences) {
			occurrenceBuffer = make([]signalOccurrence, len(clause.occurrences))
		} else {
			occurrenceBuffer = occurrenceBuffer[:len(clause.occurrences)]
		}
		overflowOccurrenceBuffers[overflowBufferIndex] = occurrenceBuffer
		copy(occurrenceBuffer, clause.occurrences)
		clause.occurrences = occurrenceBuffer
		overflowBufferIndex = (overflowBufferIndex + 1) % len(overflowSignalBuffers)
		analysis.overflowTail = append(analysis.overflowTail, clause)
		if duplicate {
			return
		}

		c.updateOverflowSemanticAssessments(
			analysis.overflowSemantic, analysis.overflowTail, denseSignals, policy, &overflowSemanticSignalStorage,
		)
	}

	c.walkDirectiveClausesWithBoundaryRange(text, func(clause []rune, clauseStart, clauseEnd int, boundaryBefore directiveBoundaryKind) bool {
		clear(clauseSignals)
		if clauseOccurrencesPublished {
			clauseOccurrences = make([]signalOccurrence, 0, 32)
			clauseOccurrencesPublished = false
		} else {
			clauseOccurrences = clauseOccurrences[:0]
		}
		if clauseSignalIDsPublished {
			clauseSignalIDs = make(directiveSignalSet, 0, 16)
			clauseSignalIDsPublished = false
		}
		var standardOverflow, compactOverflow bool
		clauseOccurrences, standardOverflow = c.standardMatcher.matchWithOccurrences(
			clause, clauseSignals, clauseOccurrences, maxEvidenceOccurrencesPerClause,
		)
		clauseOccurrences, compactOverflow = c.compactMatcher.matchCompactOccurrencesWithScratch(
			clause, clauseSignals, compactScratch, compactStartScratch,
			clauseOccurrences, maxEvidenceOccurrencesPerClause,
		)
		analysis.occurrenceBudgetExhausted = analysis.occurrenceBudgetExhausted || standardOverflow || compactOverflow
		sortSignalOccurrencesByPhysicalLocation(clauseOccurrences)
		hasSignal := false
		for _, matched := range clauseSignals {
			if matched {
				hasSignal = true
				break
			}
		}
		// Signal-free catalog/filler clauses do not consume the bounded
		// directive budget. Retain one immediate follower after a signal-bearing
		// clause so pronoun-only continuations such as "do it" still participate
		// in negation and semantic-link analysis.
		if !hasSignal && !retainNextContext {
			strongBoundarySinceRetained = strongBoundarySinceRetained || boundaryBefore == directiveBoundaryStrong
			return true
		}
		if strongBoundarySinceRetained && len(analysis.clauses) != 0 {
			// Never compose semantics across discarded inert clauses merely because
			// the compact representation made the retained clauses adjacent.
			boundaryBefore = directiveBoundaryStrong
		}
		for index := range clauseOccurrences {
			clauseOccurrences[index].clauseID = int32(nextClauseID)
		}
		analyzedClause := analyzedDirectiveClause{
			runes: clause, boundaryBefore: boundaryBefore,
			occurrences: clauseOccurrences,
		}
		nextClauseID++
		var previousClause *analyzedDirectiveClause
		if analysis.overflow && len(analysis.overflowTail) != 0 {
			previousClause = &analysis.overflowTail[len(analysis.overflowTail)-1]
		} else if len(analysis.clauses) != 0 {
			previousClause = &analysis.clauses[len(analysis.clauses)-1]
		}
		if previousClause != nil && directiveRunesEqual(previousClause.runes, clause) {
			analyzedClause.text = previousClause.text
			analyzedClause.signals = previousClause.signals
			analyzedClause.negatedRuleIntents = previousClause.negatedRuleIntents
			analyzedClause.semanticIntentsPresent = previousClause.semanticIntentsPresent
			analyzedClause.semanticIntentsOnlyNegated = previousClause.semanticIntentsOnlyNegated
		} else {
			clauseSignalIDs = encodeDirectiveSignals(clauseSignalIDs, clauseSignals)
			analyzedClause.signals = clauseSignalIDs
			cacheHit := false
			for _, cached := range proofCache {
				if cached.text == "" || !directiveRunesEqualString(clause, cached.text) {
					continue
				}
				analyzedClause.text = cached.text
				analyzedClause.negatedRuleIntents = cached.negatedRuleIntents
				analyzedClause.semanticIntentsPresent = cached.semanticIntentsPresent
				analyzedClause.semanticIntentsOnlyNegated = cached.semanticIntentsOnlyNegated
				cacheHit = true
				break
			}
			if !cacheHit {
				startByte := byteOffsetForRune(clauseStart)
				endByte := byteOffsetForRune(clauseEnd)
				analyzedClause.text = normalizedText[startByte:endByte]
				c.populateDirectiveClauseNegations(&analyzedClause, clauseSignals, &negationScratch)
				proofCache[proofCacheNext] = directiveClauseProofCacheEntry{
					text:                       analyzedClause.text,
					negatedRuleIntents:         analyzedClause.negatedRuleIntents,
					semanticIntentsPresent:     analyzedClause.semanticIntentsPresent,
					semanticIntentsOnlyNegated: analyzedClause.semanticIntentsOnlyNegated,
				}
				proofCacheNext = (proofCacheNext + 1) % len(proofCache)
			}
		}
		if len(analysis.clauses) < maxAnalyzedDirectiveClauses {
			publishShortScratch := len(analysis.clauses) == 0 && clauseCapacityHint <= 2
			if publishShortScratch {
				// Most one-clause inputs receive a capacity hint of two because the
				// terminal punctuation is itself a boundary. Let the first retained
				// clause own the already-built scratch buffers; allocate replacements
				// only if a real second clause arrives. This avoids two hot-path copies
				// without changing the bounded arena used for long directive lists.
				clauseOccurrencesPublished = len(analyzedClause.occurrences) != 0
			} else if len(analyzedClause.occurrences) != 0 {
				if retainedOccurrenceStorage == nil {
					// Clauses from one directive family normally have nearly identical
					// occurrence counts. Reserve the bounded retained-clause arena from
					// the first signal-bearing clause, with a small allowance for an
					// alternating neighbour. Never grow this arena after slices have
					// been published into analysis.clauses: growing would keep every old
					// backing array alive and turn a 64-clause proof into quadratic-like
					// allocation pressure.
					perClause := len(analyzedClause.occurrences) + 4
					if perClause > maxEvidenceOccurrencesPerClause {
						perClause = maxEvidenceOccurrencesPerClause
					}
					remainingClauses := cap(analysis.clauses) - len(analysis.clauses)
					retainedOccurrenceStorage = make([]signalOccurrence, 0, perClause*remainingClauses)
				}
				if available := cap(retainedOccurrenceStorage) - len(retainedOccurrenceStorage); available >= len(analyzedClause.occurrences) {
					occurrenceStart := len(retainedOccurrenceStorage)
					retainedOccurrenceStorage = append(retainedOccurrenceStorage, analyzedClause.occurrences...)
					analyzedClause.occurrences = retainedOccurrenceStorage[occurrenceStart:]
				} else {
					// A later candidate-rich clause may exceed the initial family hint.
					// Use one secondary arena for the remaining clauses rather than
					// relocating the published primary arena or allocating each clause
					// separately. Extreme third-shape outliers still receive exact
					// storage, keeping both arenas bounded by the retained clause limit.
					if retainedOccurrenceOverflowStorage == nil {
						perClause := len(analyzedClause.occurrences) + 4
						if perClause > maxEvidenceOccurrencesPerClause {
							perClause = maxEvidenceOccurrencesPerClause
						}
						remainingClauses := cap(analysis.clauses) - len(analysis.clauses)
						retainedOccurrenceOverflowStorage = make([]signalOccurrence, 0, perClause*remainingClauses)
					}
					if available := cap(retainedOccurrenceOverflowStorage) - len(retainedOccurrenceOverflowStorage); available >= len(analyzedClause.occurrences) {
						occurrenceStart := len(retainedOccurrenceOverflowStorage)
						retainedOccurrenceOverflowStorage = append(retainedOccurrenceOverflowStorage, analyzedClause.occurrences...)
						analyzedClause.occurrences = retainedOccurrenceOverflowStorage[occurrenceStart:]
					} else {
						analyzedClause.occurrences = append([]signalOccurrence(nil), analyzedClause.occurrences...)
					}
				}
			}
			if previousClause == nil || analyzedClause.text != previousClause.text {
				if publishShortScratch {
					clauseSignalIDsPublished = len(analyzedClause.signals) != 0
				} else {
					if retainedSignalStorage != nil &&
						cap(retainedSignalStorage)-len(retainedSignalStorage) < len(analyzedClause.signals) {
						// The first retained shape stays in its naturally small backing
						// array. Only a later distinct shape that would grow that published
						// array opens the bounded secondary arena. This avoids paying the
						// full retained-clause reservation for repeated identical clauses,
						// while preventing alternating shapes from retaining one superseded
						// allocation per clause.
						perClause := len(analyzedClause.signals) + 4
						if perClause > c.signalCount {
							perClause = c.signalCount
						}
						remainingClauses := cap(analysis.clauses) - len(analysis.clauses)
						retainedSignalStorage = make(directiveSignalSet, 0, perClause*remainingClauses)
					}
					signalStart := len(retainedSignalStorage)
					retainedSignalStorage = append(retainedSignalStorage, analyzedClause.signals...)
					analyzedClause.signals = retainedSignalStorage[signalStart:]
				}
			}
			analysis.clauses = append(analysis.clauses, analyzedClause)
		} else {
			analyzedClause.signals = clauseSignalIDs
			recordOverflowClause(analyzedClause, clauseSignals)
		}
		retainNextContext = hasSignal
		strongBoundarySinceRetained = false
		return true
	})
	analysis.semanticWindows = semanticDirectiveWindows(analysis)
	return analysis
}

func (c *Classifier) directiveClauseCapacityHint(text []rune) int {
	count := 1
	start := 0
	for index := 0; index < len(text) && count < maxAnalyzedDirectiveClauses; index++ {
		width, _ := directiveBoundaryAt(text, index)
		if width == 0 {
			width, _ = conditionalAndNowDirectiveBoundaryAt(text, start, index, &c.directiveIntentStarts)
		}
		if width == 0 {
			continue
		}
		count++
		start = index + width
		index += width - 1
	}
	return count
}

func (c *Classifier) populateDirectiveClauseNegations(
	clause *analyzedDirectiveClause,
	denseSignals []bool,
	scratch *ruleIntentNegationScratch,
) {
	scratch.reset(clause.text)
	for ruleIndex, rule := range c.rules {
		if !analyzedDirectiveSignalMatched(clause.signals, denseSignals, rule.intent) {
			continue
		}
		_, negated := clauseRuleIntentNegationPrepared(scratch, rule.intentStarts, rule.intentPatterns)
		if negated {
			clause.negatedRuleIntents.add(ruleIndex)
		}
	}
	for profileIndex, profile := range c.semanticProfiles {
		if profileIndex >= 16 {
			break
		}
		intentMatched := false
		for _, signalID := range profile.intentSignals {
			if analyzedDirectiveSignalMatched(clause.signals, denseSignals, signalID) {
				intentMatched = true
				break
			}
		}
		if !intentMatched {
			continue
		}
		profileBit := uint16(1) << uint(profileIndex)
		clause.semanticIntentsPresent |= profileBit
		found, negated := clauseRuleIntentNegationPrepared(scratch, profile.intentStarts, profile.intentPatterns)
		if found && negated {
			clause.semanticIntentsOnlyNegated |= profileBit
		}
	}
}

func (c *Classifier) updateAnalyzedDirectiveRuleStates(
	states []analyzedDirectiveRuleState,
	clause analyzedDirectiveClause,
	denseSignals []bool,
	allow ContextPolicy,
) {
	for ruleIndex, rule := range c.rules {
		state := &states[ruleIndex]
		hasIntent := analyzedDirectiveSignalMatched(clause.signals, denseSignals, rule.intent)
		if !hasIntent {
			continue
		}
		state.foundIntent = true
		intentNegated := clause.negatedRuleIntents.matched(ruleIndex)
		if !intentNegated {
			state.unnegatedIntent = true
		}
		hasObject := analyzedDirectiveSignalMatched(clause.signals, denseSignals, rule.object)
		if !hasObject {
			if state.foundCore && !intentNegated && continuesPriorRiskDirective(clause.text) {
				state.unnegatedCore = true
			}
			continue
		}
		if !intentNegated && !state.contradictory && c.activeDirectiveClauseContradictsContextWithDense(clause, denseSignals, rule, allow) {
			state.contradictory = true
		}
		state.foundCore = true
		if len(clause.text) > maxCompactIntentProofBytes ||
			(!intentNegated && !c.coordinatedCoreNegated(clause, rule)) {
			state.unnegatedCore = true
		}
	}
}

func (c *Classifier) ruleCoreIsOnlyNegated(analysis analyzedDirectives, ruleIndex int, rule compiledRule) bool {
	if analysis.overflow && ruleIndex >= 0 && ruleIndex < len(analysis.overflowRuleStates) {
		state := analysis.overflowRuleStates[ruleIndex]
		return state.foundCore && !state.unnegatedCore
	}
	foundCore := false
	foundUnnegatedCore := false
	for _, clause := range analysis.clauses {
		signals := clause.signals
		if !signals.matched(rule.intent) || !signals.matched(rule.object) {
			if foundCore && signals.matched(rule.intent) && !clause.negatedRuleIntents.matched(ruleIndex) &&
				continuesPriorRiskDirective(clause.text) {
				foundUnnegatedCore = true
				break
			}
			continue
		}
		if len(clause.text) > maxCompactIntentProofBytes {
			// Negation-only suppression is optional defensive credit. Avoid
			// rescanning an oversized candidate-rich clause for every rule and
			// retain the matched abuse core when the proof budget is exceeded.
			return false
		}
		foundCore = true
		if !clause.negatedRuleIntents.matched(ruleIndex) && !c.coordinatedCoreNegated(clause, rule) {
			foundUnnegatedCore = true
			break
		}
	}
	return foundCore && !foundUnnegatedCore
}

func (c *Classifier) coordinatedCoreNegated(clause analyzedDirectiveClause, rule compiledRule) bool {
	intentIndex := earliestRuleIntentIndex(clause.text, rule.intentStarts)
	if intentIndex <= 0 {
		return false
	}
	prefix := strings.TrimSpace(clause.text[:intentIndex])
	conjunction := ""
	for _, marker := range []string{
		" as well as", " and", " nor", " or",
		"并且", "以及", "和", "与", "及", "并", "且", "或",
	} {
		if strings.HasSuffix(prefix, marker) && len(marker) > len(conjunction) {
			conjunction = marker
		}
	}
	if conjunction == "" {
		return false
	}
	earlier := strings.TrimSpace(prefix[:len(prefix)-len(conjunction)])
	if earlier == "" || !containsAnyLiteral(earlier,
		"never", "do not", "don't", "must not", "should not", "cannot", "can't", "without", "forbid", "prohibit", "refuse to",
		"严禁", "禁止", "不得", "不要", "不能", "拒绝", "不",
	) {
		return false
	}
	earlierRunes := []rune(earlier)
	signals := make([]bool, c.signalCount)
	c.standardMatcher.match(earlierRunes, signals)
	compactScratch := make([]bool, c.compactMatcher.maxPatternLength)
	c.compactMatcher.matchCompactWithScratch(earlierRunes, signals, compactScratch)
	for _, priorRule := range c.rules {
		if !signals[priorRule.intent] || !signals[priorRule.object] {
			continue
		}
		if priorRule.category != rule.category && crossCategoryCoordinatedNegationAmbiguous(earlier) {
			continue
		}
		if clauseNegatesRuleIntent(earlier, priorRule.intentStarts) {
			return true
		}
	}
	if hasAnyPrefix(earlier,
		"never ", "do not ", "don't ", "must not ", "should not ", "forbid ", "forbids ", "prohibit ", "prohibits ",
		"严禁", "禁止", "不得", "不要", "不能",
	) {
		sameCategoryObject := false
		for _, priorRule := range c.rules {
			if priorRule.category == rule.category && signals[priorRule.object] {
				sameCategoryObject = true
				break
			}
		}
		if sameCategoryObject && containsAnyLiteral(earlier,
			"render unreadable", "make inaccessible", "unreadable", "inaccessible", "encrypted",
			"不可读", "无法读取", "无法访问", "被加密",
		) {
			return true
		}
		for _, profile := range c.semanticProfiles {
			if profile.category != rule.category {
				continue
			}
			dimensions := c.semanticDimensions(profile, [][]bool{signals})
			if dimensions.object && (dimensions.harm || dimensions.action || dimensions.outcome) {
				return true
			}
		}
	}
	return false
}

func crossCategoryCoordinatedNegationAmbiguous(text string) bool {
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete || len(spans) != 0 {
		return true
	}
	text = strings.ToLower(strings.TrimSpace(text))
	if crossCategoryDirectProhibition(text) {
		return false
	}
	trimmed := metaOverrideTrimDirectiveGovernor(text)
	return !crossCategoryDirectProhibition(trimmed)
}

func crossCategoryDirectProhibition(text string) bool {
	return hasAnyPrefix(strings.TrimSpace(text),
		"not ", "never ", "do not ", "don't ", "must not ", "must never ", "should not ", "should never ",
		"cannot ", "can't ", "will not ", "would not ", "could not ", "may not ", "need not ", "ought not ", "shall not ",
		"forbid ", "forbids ", "forbidden ", "prohibit ", "prohibits ", "refuse to ",
		"严禁", "禁止", "不得", "不要", "不能", "不会", "不应", "不可", "拒绝",
	)
}

// continuesPriorRiskDirective is deliberately narrower than a bare second
// intent verb. A prohibition such as "never deploy ransomware; provide a
// recovery checklist" must not lend its object to the safe deliverable. The
// object is carried only when the later clause explicitly refers back to it or
// asks for a concrete implementation artifact.
func continuesPriorRiskDirective(clause string) bool {
	clause = strings.TrimSpace(clause)
	if isSafetyDeliverableClause(clause) || hasExplanatoryFraming(clause) || hasAffirmativeSafetyPurpose(clause) {
		return false
	}
	return containsAnyLiteral(clause,
		" it", " that", " them", " the above", " above request", " same payload", " same tool", " same operation", " same action",
		"do the same", "apply it", "implement it", "implement the above", "carry it out", "execute it",
		"working code", "complete code", "source code", "ready-to-run", "ready to run",
		"commands", "script", "payload", "executable", "implementation",
		"它", "该内容", "上述", "上面", "同一载荷", "同一工具", "同一操作", "照做", "执行它", "应用它", "实现上述", "完整代码", "可运行代码",
		"源码", "命令", "脚本", "载荷", "可执行文件", "实现出来",
	)
}

func hasAffirmativeSafetyPurpose(text string) bool {
	if containsAnyLiteral(text,
		"no ransomware remains", "ransomware is absent", "ransomware-free", "prevent ransomware infection", "block ransomware execution",
		"no malware remains", "malware is absent", "malware-free", "prevent malware infection", "block malware execution",
		"no backdoor remains", "remove the backdoor", "eradicate the backdoor",
		"不再存在勒索软件", "无勒索软件感染", "防止勒索软件感染", "阻止勒索软件执行",
		"不再存在恶意软件", "无恶意软件感染", "防止恶意软件感染", "阻止恶意软件执行",
		"不再存在后门", "移除后门", "清除后门",
	) {
		return true
	}
	if containsAnyLiteral(text, "detection rule", "alert rule", "检测规则", "告警规则") &&
		containsAnyLiteral(text, "alert when", "alerts when", "detect when", "detects when", "当出现时告警", "当检测到") {
		return true
	}
	if containsAnyLiteral(text, "verify", "verifies", "verified", "validate", "validates", "validated", "test", "tests", "testing", "验证", "校验", "测试") &&
		containsAnyLiteral(text, "recovery", "restoration", "restore", "backup", "fix", "patch", "恢复", "还原", "备份", "修复", "补丁") {
		return true
	}
	return containsAnyLiteral(text,
		"verify recovery", "verify restoration", "verify backups", "restore collection", "restore telemetry",
		"restore from", "recover files", "protect files", "prevent abuse", "investigate the outage",
		"investigate why", "apply the patch", "test the patch", "validate the fix",
		"验证恢复", "验证备份", "恢复采集", "恢复遥测", "从备份恢复", "恢复文件", "保护文件",
		"防止滥用", "调查故障", "调查停止原因", "应用补丁", "验证修复",
	)
}

func (analysis analyzedDirectives) ruleIntentIsOnlyNegated(ruleIndex int, rule compiledRule) bool {
	if analysis.overflow && ruleIndex >= 0 && ruleIndex < len(analysis.overflowRuleStates) {
		state := analysis.overflowRuleStates[ruleIndex]
		return state.foundIntent && !state.unnegatedIntent
	}
	foundIntent := false
	for _, clause := range analysis.clauses {
		if !clause.signals.matched(rule.intent) {
			continue
		}
		foundIntent = true
		if !clause.negatedRuleIntents.matched(ruleIndex) {
			return false
		}
	}
	return foundIntent
}

func clauseNegatesRuleIntent(clause string, intents []string) bool {
	found, negates := clauseRuleIntentNegation(clause, intents)
	return found && negates
}

type ruleIntentLiteralSpan struct {
	start int
	end   int
}

func clauseRuleIntentNegation(clause string, intents []string) (found, negates bool) {
	var scratch ruleIntentNegationScratch
	scratch.reset(clause)
	return clauseRuleIntentNegationPrepared(&scratch, intents, compileCompactRuleIntentPatterns(intents))
}

type ruleIntentNegationScratch struct {
	clause               string
	literalSpans         [maxRuleIntentOccurrences]ruleIntentLiteralSpan
	occurrenceProofs     [maxRuleIntentOccurrences]ruleIntentOccurrenceProof
	occurrenceProofCount int
	compact              compactRuleIntentClauseScratch
}

type ruleIntentOccurrenceProof struct {
	index   int
	found   bool
	negated bool
}

func (scratch *ruleIntentNegationScratch) reset(clause string) {
	scratch.clause = normalizeNegationSyntax(clause)
	scratch.occurrenceProofCount = 0
	scratch.compact.reset()
}

func (scratch *ruleIntentNegationScratch) occurrenceNegation(intentIndex int) (found, negated bool) {
	for proofIndex := 0; proofIndex < scratch.occurrenceProofCount; proofIndex++ {
		proof := scratch.occurrenceProofs[proofIndex]
		if proof.index == intentIndex {
			return proof.found, proof.negated
		}
	}
	found, negated = ruleIntentOccurrenceNegation(scratch.clause, intentIndex)
	if scratch.occurrenceProofCount < len(scratch.occurrenceProofs) {
		scratch.occurrenceProofs[scratch.occurrenceProofCount] = ruleIntentOccurrenceProof{
			index: intentIndex, found: found, negated: negated,
		}
		scratch.occurrenceProofCount++
	}
	return found, negated
}

func clauseRuleIntentNegationPrepared(
	scratch *ruleIntentNegationScratch,
	intents []string,
	patterns compactRuleIntentPatterns,
) (found, negates bool) {
	clause := scratch.clause
	occurrences := 0
	literalSpanCount := 0
	for _, intent := range intents {
		if intent == "" {
			continue
		}
		for offset := 0; offset <= len(clause)-len(intent); {
			index := strings.Index(clause[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(clause[index-1])
			right := index + len(intent)
			rightOK := !isASCIIStringLocal(intent) || right == len(clause) || !isASCIIWordByte(clause[right])
			if leftOK && rightOK {
				occurrences++
				if occurrences > maxRuleIntentOccurrences {
					// Proving that every occurrence is prohibited is optional
					// defensive credit. Bound adversarial repetition and retain the
					// matched intent when that proof becomes ambiguous.
					return true, false
				}
				scratch.literalSpans[literalSpanCount] = ruleIntentLiteralSpan{start: index, end: right}
				literalSpanCount++
				occurrenceFound, occurrenceNegates := scratch.occurrenceNegation(index)
				if occurrenceFound && !occurrenceNegates &&
					coordinatedRuleIntentNegation(clause, index, intent, intents) {
					occurrenceNegates = true
				}
				found = true
				if !occurrenceFound || !occurrenceNegates {
					return true, false
				}
			}
			offset = index + 1
		}
	}
	if found && compactRuleIntentOutsideLiteralSpansPrepared(clause, patterns, scratch.literalSpans[:literalSpanCount], &scratch.compact) {
		// Literal negation cannot authorize a second compact-only occurrence in
		// the same clause (for example "do not deploy ... and d.e.p.l.o.y").
		// Compact matches that are wholly contained by a recognized family
		// literal remain explained, including overlapping forms such as deploy
		// inside deploying. Any unmatched or excessive compact evidence fails
		// closed as an active occurrence.
		return true, false
	}
	return found, found
}

type compactRuleIntentPattern struct {
	runes []rune
	ascii bool
}

type compactRuleIntentPatterns struct {
	values  []compactRuleIntentPattern
	byFirst map[rune][]int
}

func compileCompactRuleIntentPatterns(intents []string) compactRuleIntentPatterns {
	patterns := compactRuleIntentPatterns{
		values:  make([]compactRuleIntentPattern, 0, len(intents)),
		byFirst: make(map[rune][]int),
	}
	seen := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		compact := compactString([]rune(intent))
		compactRunes := []rune(compact)
		if len(compactRunes) < 2 {
			continue
		}
		if _, exists := seen[compact]; exists {
			continue
		}
		seen[compact] = struct{}{}
		patternIndex := len(patterns.values)
		patterns.values = append(patterns.values, compactRuleIntentPattern{
			runes: compactRunes,
			ascii: isASCIIStringLocal(compact),
		})
		patterns.byFirst[compactRunes[0]] = append(patterns.byFirst[compactRunes[0]], patternIndex)
	}
	return patterns
}

type compactRuleIntentSegment struct {
	start int
	end   int
}

type compactRuleIntentClauseScratch struct {
	prepared       bool
	runes          []rune
	byteStarts     []int
	compactRunes   []rune
	originalStarts []int
	originalEnds   []int
	wordStarts     []bool
	wordEnds       []bool
	segments       []compactRuleIntentSegment
}

func (scratch *compactRuleIntentClauseScratch) reset() {
	scratch.prepared = false
}

func (scratch *compactRuleIntentClauseScratch) prepare(clause string) {
	if scratch.prepared {
		return
	}
	scratch.runes = scratch.runes[:0]
	scratch.byteStarts = scratch.byteStarts[:0]
	for byteIndex, r := range clause {
		scratch.runes = append(scratch.runes, r)
		scratch.byteStarts = append(scratch.byteStarts, byteIndex)
	}
	scratch.compactRunes = scratch.compactRunes[:0]
	scratch.originalStarts = scratch.originalStarts[:0]
	scratch.originalEnds = scratch.originalEnds[:0]
	scratch.wordStarts = scratch.wordStarts[:0]
	scratch.wordEnds = scratch.wordEnds[:0]
	scratch.segments = scratch.segments[:0]
	segmentStart := 0
	flushSegment := func() {
		if segmentStart < len(scratch.compactRunes) {
			scratch.segments = append(scratch.segments, compactRuleIntentSegment{start: segmentStart, end: len(scratch.compactRunes)})
		}
		segmentStart = len(scratch.compactRunes)
	}
	for index, r := range scratch.runes {
		if isHardCompactSeparator(scratch.runes, index) {
			flushSegment()
			continue
		}
		if !isCompactRune(r) {
			continue
		}
		byteEnd := len(clause)
		if index+1 < len(scratch.byteStarts) {
			byteEnd = scratch.byteStarts[index+1]
		}
		scratch.compactRunes = append(scratch.compactRunes, r)
		scratch.originalStarts = append(scratch.originalStarts, scratch.byteStarts[index])
		scratch.originalEnds = append(scratch.originalEnds, byteEnd)
		scratch.wordStarts = append(scratch.wordStarts, index == 0 || !isASCIILetterOrDigit(scratch.runes[index-1]))
		scratch.wordEnds = append(scratch.wordEnds, index+1 == len(scratch.runes) || !isASCIILetterOrDigit(scratch.runes[index+1]))
	}
	flushSegment()
	scratch.prepared = true
}

func compactRuleIntentOutsideLiteralSpans(clause string, intents []string, literalSpans []ruleIntentLiteralSpan) bool {
	var scratch compactRuleIntentClauseScratch
	return compactRuleIntentOutsideLiteralSpansPrepared(clause, compileCompactRuleIntentPatterns(intents), literalSpans, &scratch)
}

func compactRuleIntentOutsideLiteralSpansPrepared(
	clause string,
	patterns compactRuleIntentPatterns,
	literalSpans []ruleIntentLiteralSpan,
	scratch *compactRuleIntentClauseScratch,
) bool {
	if len(clause) > maxCompactIntentProofBytes {
		// Mapping compact occurrences back to literal byte spans is optional
		// defensive credit. Bound that proof before allocating clause-sized
		// position tables or rescanning the same candidate-rich clause for every
		// rule. Oversized clauses retain the matched intent (fail active).
		return true
	}
	if len(patterns.values) == 0 {
		return false
	}
	scratch.prepare(clause)
	compactOccurrences := 0
	for _, segment := range scratch.segments {
		for start := segment.start; start < segment.end; start++ {
			for _, patternIndex := range patterns.byFirst[scratch.compactRunes[start]] {
				pattern := patterns.values[patternIndex]
				if start+len(pattern.runes) > segment.end {
					continue
				}
				matched := true
				for offset := range pattern.runes {
					if scratch.compactRunes[start+offset] != pattern.runes[offset] {
						matched = false
						break
					}
				}
				if !matched {
					continue
				}
				end := start + len(pattern.runes) - 1
				if pattern.ascii && (!scratch.wordStarts[start] || !scratch.wordEnds[end]) {
					continue
				}
				compactOccurrences++
				if compactOccurrences > maxRuleIntentOccurrences {
					return true
				}
				originalStart := scratch.originalStarts[start]
				originalEnd := scratch.originalEnds[end]
				covered := false
				for _, span := range literalSpans {
					if span.start <= originalStart && originalEnd <= span.end {
						covered = true
						break
					}
				}
				if !covered {
					return true
				}
			}
		}
	}
	return false
}

// coordinatedRuleIntentNegation extends a valid prohibition over a bounded
// coordination of distinct actions, for example "do not build or deploy" or
// "forbids disabling EDR and deleting audit logs". Repeating the same action
// does not inherit the earlier negation: that conservative distinction keeps
// "do not deploy ... and deploy ..." from becoming an allow bypass.
func coordinatedRuleIntentNegation(clause string, currentIndex int, currentIntent string, intents []string) bool {
	if currentIndex <= 0 || currentIndex > len(clause) {
		return false
	}
	prefix := strings.TrimSpace(clause[:currentIndex])
	connector := ""
	for _, candidate := range []string{
		" as well as", " and", " nor", " or",
		"并且", "以及", "和", "与", "及", "并", "且", "或",
	} {
		if strings.HasSuffix(prefix, candidate) && len(candidate) > len(connector) {
			connector = candidate
		}
	}
	if connector == "" {
		return false
	}
	earlier := strings.TrimSpace(prefix[:len(prefix)-len(connector)])
	// This is a local grammar bridge, not a second unbounded clause scan. Long
	// coordinations remain fail-closed and are handled by the ordinary result.
	if len(earlier) > 512 {
		return false
	}
	priorIndex, priorIntent := latestRuleIntentOccurrence(earlier, intents)
	if priorIndex < 0 || sameRuleIntentFamily(priorIntent, currentIntent) {
		return false
	}
	priorEnd := priorIndex + len(priorIntent)
	if priorEnd > len(earlier) || strings.ContainsAny(earlier[priorEnd:], ",;:.!?，；：。！？") {
		return false
	}
	found, negated := ruleIntentOccurrenceNegation(earlier, priorIndex)
	return found && negated
}

func latestRuleIntentOccurrence(text string, intents []string) (latest int, matched string) {
	latest = -1
	for _, intent := range intents {
		if intent == "" {
			continue
		}
		for offset := 0; offset <= len(text)-len(intent); {
			index := strings.Index(text[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(text[index-1])
			right := index + len(intent)
			rightOK := !isASCIIStringLocal(intent) || right == len(text) || !isASCIIWordByte(text[right])
			if leftOK && rightOK && (index > latest || (index == latest && len(intent) > len(matched))) {
				latest = index
				matched = intent
			}
			offset = index + 1
		}
	}
	return latest, matched
}

func sameRuleIntentFamily(first, second string) bool {
	first = strings.ToLower(strings.TrimSpace(first))
	second = strings.ToLower(strings.TrimSpace(second))
	if first == second {
		return true
	}
	if !isASCIIStringLocal(first) || !isASCIIStringLocal(second) {
		return false
	}
	firstForms, firstCount := ruleIntentInflectionForms(first)
	secondForms, secondCount := ruleIntentInflectionForms(second)
	for firstIndex := 0; firstIndex < firstCount; firstIndex++ {
		for secondIndex := 0; secondIndex < secondCount; secondIndex++ {
			if firstForms[firstIndex] == secondForms[secondIndex] {
				return true
			}
		}
	}
	return false
}

func ruleIntentInflectionForms(intent string) ([4]string, int) {
	forms := [4]string{intent}
	count := 1
	add := func(candidate string) {
		if len(candidate) < 2 {
			return
		}
		for index := 0; index < count; index++ {
			if forms[index] == candidate {
				return
			}
		}
		if count < len(forms) {
			forms[count] = candidate
			count++
		}
	}
	// English verbs ending in consonant+y replace y with i before -es/-ed.
	// Preserve the y-stem so repeated forms such as copy/copies/copied are
	// treated as one action family and cannot inherit defensive credit from an
	// earlier occurrence through the coordination grammar.
	for _, suffix := range []string{"ies", "ied"} {
		if strings.HasSuffix(intent, suffix) && len(intent) > len(suffix)+1 {
			add(strings.TrimSuffix(intent, suffix) + "y")
			break
		}
	}
	for _, suffix := range []string{"ing", "ed", "es", "s"} {
		if !strings.HasSuffix(intent, suffix) || len(intent) <= len(suffix)+1 {
			continue
		}
		stem := strings.TrimSuffix(intent, suffix)
		add(stem)
		add(stem + "e")
		if len(stem) >= 2 && stem[len(stem)-1] == stem[len(stem)-2] {
			add(stem[:len(stem)-1])
		}
		break
	}
	return forms, count
}

func ruleIntentOccurrenceNegation(clause string, intentIndex int) (found, negates bool) {
	if intentIndex < 0 || intentIndex > len(clause) {
		return false, false
	}
	prefixStart := 0
	if intentIndex > maxRuleIntentLookbackBytes {
		prefixStart = intentIndex - maxRuleIntentLookbackBytes
		for prefixStart < intentIndex && clause[prefixStart]&0xc0 == 0x80 {
			prefixStart++
		}
		// Do not manufacture an English negator by cutting into the middle
		// of an ASCII word at the bounded-window edge.
		if prefixStart > 0 && prefixStart < intentIndex &&
			isASCIIWordByte(clause[prefixStart-1]) && isASCIIWordByte(clause[prefixStart]) {
			for prefixStart < intentIndex && isASCIIWordByte(clause[prefixStart]) {
				prefixStart++
			}
		}
	}
	prefix := strings.TrimSpace(clause[prefixStart:intentIndex])
	closest := -1
	closestEnd := -1
	closestMarker := ""
	for _, marker := range []string{
		"must never", "must not", "should never", "should not", "need not", "ought not", "shall not", "would not", "could not", "may not",
		"do not", "cannot", "will not", "never", "not to", "without", "forbids", "forbid", "forbidden to", "prohibits", "prohibit", "prohibited from", "refuse to",
		"严禁", "禁止", "不得", "不要", "不需要", "无需", "不能", "不会", "拒绝", "不",
	} {
		index := strings.LastIndex(prefix, marker)
		if isASCIIStringLocal(marker) {
			index = lastASCIIPhraseIndex(prefix, marker)
		}
		if marker == "不" && index >= 0 && !isBareChineseNegationBridge(strings.TrimSpace(prefix[index+len(marker):])) {
			continue
		}
		if index >= 0 && (index > closest || (index == closest && len(marker) > len(closestMarker))) {
			closest = index
			closestEnd = index + len(marker)
			closestMarker = marker
		}
	}
	if closest < 0 {
		return false, false
	}
	if prohibitionMarkerIsNegated(prefix[:closest], closestMarker) {
		return true, false
	}
	for _, override := range []string{"ignore", "disregard", "override", "忽略", "无视"} {
		if strings.Contains(prefix[:closest], override) {
			return true, false
		}
	}
	between := strings.TrimSpace(prefix[closestEnd:])
	if negationScopeInterrupted(between) {
		return true, false
	}
	if directNegationBridge(between) || safeIndirectNegationBridge(between) {
		return true, true
	}
	// Fail closed for an unrecognized intermediate predicate. Only a direct,
	// bounded negator-to-intent bridge can suppress a matched abuse action.
	return true, false
}

func prohibitionMarkerIsNegated(before, marker string) bool {
	switch marker {
	case "forbids", "forbid", "forbidden to", "prohibits", "prohibit", "prohibited from", "refuse to", "严禁", "禁止", "拒绝":
	default:
		return false
	}
	const maxLookbackBytes = 192
	truncated := len(before) > maxLookbackBytes
	if len(before) > maxLookbackBytes {
		start := len(before) - maxLookbackBytes
		for start < len(before) && before[start]&0xc0 == 0x80 {
			start++
		}
		before = before[start:]
	}
	before = strings.ToLower(strings.TrimSpace(before))
	for _, negator := range []string{
		"must never", "must not", "should never", "should not", "need not", "ought not", "shall not", "would not", "could not", "may not",
		"do not", "will not", "cannot", "never", "not to",
		"不得", "不要", "不能", "不会", "不",
	} {
		if strings.HasSuffix(before, negator) {
			return true
		}
	}
	cueEnd := -1
	for _, cue := range []string{
		"no longer", "nobody is", "nobody was", "no one is", "no one was", "none are", "none were", "not",
	} {
		if index := lastASCIIPhraseIndex(before, cue); index >= 0 && index+len(cue) > cueEnd {
			cueEnd = index + len(cue)
		}
	}
	for _, cue := range []string{"并不是", "并非", "不是", "不再", "没有被", "没有", "从未被", "无人被", "并未", "未被"} {
		if index := strings.LastIndex(before, cue); index >= 0 && index+len(cue) > cueEnd {
			cueEnd = index + len(cue)
		}
	}
	if cueEnd < 0 {
		// Once the left context is truncated, absence of a local cue cannot
		// prove that the prohibition marker is affirmative. Keep the intent
		// active instead of granting an attacker defensive credit.
		return truncated
	}
	bridge := strings.TrimSpace(before[cueEnd:])
	if strings.ContainsAny(bridge, ".!?;:\n\r。！？；：\ufffd") ||
		containsAnyLiteral(bridge, " but ", " however ", " instead ", " rather ", " although ", " except ", "但是", "然而", "而是", "不过", "除非") {
		return false
	}
	// A negated prohibition is recognized only through the same bounded,
	// fixed modifier grammar used for direct intent negation. Unknown
	// predicates such as "surprised that policy" describe a real prohibition
	// and must not be inverted into an active request.
	return prohibitionNegationBridge(bridge)
}

func prohibitionNegationBridge(bridge string) bool {
	bridge = strings.TrimSpace(bridge)
	if bridge == "" {
		return true
	}
	// The caller bounds this bridge to a short fixed window. Consume the full
	// known Chinese modifier grammar so a seventeenth valid modifier cannot
	// turn a negated prohibition back into defensive credit.
	for {
		matched := false
		for _, modifier := range []string{
			"在任何情况下", "无论如何", "永远", "绝对", "当前", "目前", "现在", "明确", "明文", "法律上", "正式", "技术上", "严格", "再次", "仍然", "立即", "直接", "再",
		} {
			if strings.HasPrefix(bridge, modifier) {
				bridge = strings.TrimSpace(bridge[len(modifier):])
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	if bridge == "" {
		return true
	}
	fields := strings.Fields(strings.ToLower(bridge))
	if len(fields) == 0 {
		return false
	}
	modifierEnd := 0
	for modifierEnd < len(fields) && directNegationModifier(fields[modifierEnd]) {
		modifierEnd++
	}
	if len(fields)-modifierEnd == 2 && fields[modifierEnd+1] == "to" {
		switch fields[modifierEnd] {
		case "allowed", "permitted", "authorized", "required", "supposed", "able":
			return true
		}
	}
	for _, field := range fields {
		if !directNegationModifier(field) {
			return false
		}
	}
	return true
}

func lastASCIIPhraseIndex(text, phrase string) int {
	for searchEnd := len(text); searchEnd >= len(phrase); {
		index := strings.LastIndex(text[:searchEnd], phrase)
		if index < 0 {
			return -1
		}
		beforeOK := index == 0 || !isASCIIWordByte(text[index-1])
		end := index + len(phrase)
		afterOK := end == len(text) || !isASCIIWordByte(text[end])
		if beforeOK && afterOK {
			return index
		}
		searchEnd = index
	}
	return -1
}

func directNegationBridge(between string) bool {
	between = strings.TrimSpace(between)
	if between == "" {
		return true
	}
	if strings.ContainsAny(between, ",，;；:：—–") {
		return false
	}
	for stripped := 0; stripped < 6; stripped++ {
		matched := false
		for _, modifier := range []string{
			"在任何情况下", "无论如何", "永远", "绝对", "再次", "仍然", "立即", "马上", "立刻", "主动", "故意", "轻易", "再",
		} {
			if strings.HasPrefix(between, modifier) {
				between = strings.TrimSpace(between[len(modifier):])
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	if between == "" {
		return true
	}
	fields := strings.Fields(strings.ToLower(between))
	if len(fields) == 0 || len(fields) > 8 {
		return false
	}
	for _, field := range fields {
		if !directNegationModifier(field) {
			return false
		}
	}
	return true
}

func directNegationModifier(word string) bool {
	switch strings.Trim(word, "'\"") {
	case "ever", "again", "still", "currently", "now", "immediately", "directly", "actively", "intentionally", "knowingly",
		"explicitly", "legally", "formally", "technically", "categorically", "unequivocally",
		"deliberately", "accidentally", "inadvertently", "routinely", "prematurely", "under", "any", "all", "circumstances",
		"in", "way", "by", "law", "this", "policy", "as", "matter", "of",
		"for", "a", "one", "reason", "at":
		return true
	default:
		return false
	}
}

func safeIndirectNegationBridge(between string) bool {
	between = strings.ToLower(strings.TrimSpace(between))
	if between == "" || len(between) > 192 || strings.ContainsAny(between, ",，;；:：—–") ||
		containsAnyLiteral(between, " but ", " however ", " then ", " and then ", "但是", "然而", "然后") {
		return false
	}
	for _, refusalBridge := range []string{
		"help", "help to", "help with", "assist", "assist to", "assist with", "assist in",
		"provide help to", "provide assistance to", "帮助", "协助",
		"discuss how attackers", "discuss how an attacker", "explain how to", "explain how attackers", "explain how an attacker",
		"analyze how attackers", "analyze how an attacker", "describe how to", "describe how attackers", "describe how an attacker",
	} {
		if between == refusalBridge {
			return true
		}
	}
	prefixOK := hasAnyPrefix(between,
		"treat ", "treating ", "be treated ", "use ", "using ", "be used ",
		"interpret ", "interpreting ", "be interpreted ", "consider ", "considering ", "be considered ",
	)
	if !prefixOK {
		return false
	}
	for _, suffix := range []string{
		" as authorization to", " as permission to", " as approval to", " as a reason to",
	} {
		if strings.HasSuffix(between, suffix) {
			return true
		}
	}
	return false
}

// parseNegationReversalGovernor recognizes only the first bounded governor in
// the negator's local scope. It deliberately does not search the whole bridge:
// in "do not treat a failed test as authorization to deploy", "failed" is
// evidence about the test, not a governor that reverses "do not". actionIndex
// points at the first token after the governor bridge; when it equals the field
// count, the risky action begins immediately after the caller's bridge.
func parseNegationReversalGovernor(text string) (actionIndex, fieldCount int, ok bool) {
	text = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(text)))
	for stripped := 0; stripped < 2; stripped++ {
		matched := false
		for _, modifier := range []string{"再", "再次", "仍然", "轻易"} {
			if strings.HasPrefix(text, modifier) {
				text = strings.TrimSpace(text[len(modifier):])
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	for _, governor := range []string{
		"拒绝", "犹豫", "避免", "未能", "忘记", "疏忽", "停止", "克制",
	} {
		if strings.HasPrefix(text, governor) {
			rest := strings.TrimSpace(text[len(governor):])
			for stripped := 0; stripped < 4; stripped++ {
				matched := false
				for _, modifier := range []string{
					"在任何情况下", "无论如何", "再次", "仍然", "立即", "马上", "立刻", "片刻", "短暂", "轻易", "再",
				} {
					if strings.HasPrefix(rest, modifier) {
						rest = strings.TrimSpace(rest[len(modifier):])
						matched = true
						break
					}
				}
				if !matched {
					break
				}
			}
			if rest == "" {
				return 1, 1, true
			}
			return 1, 2, true
		}
	}

	fields := strings.Fields(text)
	fieldCount = len(fields)
	if fieldCount == 0 {
		return 0, 0, false
	}
	governorIndex := 0
	for governorIndex < fieldCount && governorIndex < 4 && negationReversalModifier(fields[governorIndex]) {
		governorIndex++
	}
	if governorIndex >= fieldCount {
		return 0, fieldCount, false
	}

	governor := fields[governorIndex]
	switch governor {
	case "avoid", "stop":
		actionIndex = governorIndex + 1
		for actionIndex < fieldCount && actionIndex <= governorIndex+5 && negationReversalModifier(fields[actionIndex]) {
			actionIndex++
		}
		if actionIndex < fieldCount && (fields[actionIndex] == "before" || fields[actionIndex] == "from") {
			actionIndex++
		}
		return actionIndex, fieldCount, true
	case "refuse", "hesitate", "decline", "fail", "forget", "neglect", "refrain":
		connector := "to"
		if governor == "refrain" {
			connector = "from"
		}
		for index := governorIndex + 1; index < fieldCount && index <= governorIndex+6; index++ {
			if fields[index] == connector || (governor == "hesitate" && fields[index] == "before") {
				return index + 1, fieldCount, true
			}
			if !negationReversalModifier(fields[index]) {
				return 0, fieldCount, false
			}
		}
	}
	return 0, fieldCount, false
}

var negationGovernorSeparators = strings.NewReplacer(
	"-", " ", "‐", " ", "‑", " ", "‒", " ",
)

var negationQuoteNormalizer = strings.NewReplacer("’", "'", "‘", "'")

var negationContractionNormalizer = strings.NewReplacer(
	"mustn't", "must not", "shouldn't", "should not", "won't", "will not", "needn't", "need not",
	"oughtn't", "ought not", "shan't", "shall not", "wouldn't", "would not", "couldn't", "could not",
	"don't", "do not", "can't", "cannot", "isn't", "is not", "aren't", "are not",
	"wasn't", "was not", "weren't", "were not", "doesn't", "does not", "didn't", "did not",
	"hasn't", "has not", "haven't", "have not", "hadn't", "had not",
)

func normalizeNegationSyntax(text string) string {
	if !strings.ContainsAny(text, "'’‘-‐‑‒") {
		return text
	}
	text = negationQuoteNormalizer.Replace(text)
	text = negationContractionNormalizer.Replace(text)
	return negationGovernorSeparators.Replace(text)
}

func negationReversalModifier(word string) bool {
	switch strings.Trim(word, "'\"") {
	case "ever", "again", "even", "briefly", "momentarily", "accidentally", "inadvertently",
		"possibly", "temporarily", "prematurely", "needlessly", "unnecessarily", "simply", "just", "merely",
		"under", "any", "all", "circumstances", "for", "a", "one", "reason", "moment":
		return true
	default:
		return false
	}
}

func hasNegationReversalFraming(text string) bool {
	text = normalizeNegationSyntax(text)
	candidates := 0
	for _, negator := range []string{
		"must never ", "must not ", "should never ", "should not ", "need not ", "ought not ", "shall not ",
		"would not ", "could not ", "may not ", "will not ", "cannot ", "do not ", "never ", "not to ",
		"严禁", "禁止", "不得", "不要", "不能", "不会",
	} {
		searchFrom := 0
		for searchFrom < len(text) {
			index := strings.Index(text[searchFrom:], negator)
			if index < 0 {
				break
			}
			index += searchFrom
			candidates++
			if candidates > maxNegationReversalCandidates {
				// Reversal framing removes defensive credit. Excessive repeated
				// candidates are ambiguous and therefore fail active.
				return true
			}
			after := text[index+len(negator):]
			truncated := false
			if len(after) > maxNegationReversalTailBytes {
				after = validUTF8Prefix(after, maxNegationReversalTailBytes)
				truncated = true
			}
			if _, _, ok := parseNegationReversalGovernor(after); ok {
				return true
			}
			if truncated && !hasStrongDirectiveBoundary([]rune(after)) {
				// Reversal analysis removes defensive credit. If the bounded tail
				// ends inside one unbroken clause, the governor may sit just beyond
				// the window; retain the active interpretation instead of treating
				// truncation as proof of an ordinary prohibition.
				return true
			}
			searchFrom = index + len(negator)
		}
	}
	return false
}

func hasStrongDirectiveBoundary(text []rune) bool {
	for index := 0; index < len(text); index++ {
		width, kind := directiveBoundaryAt(text, index)
		if width == 0 {
			continue
		}
		if kind == directiveBoundaryStrong {
			return true
		}
		index += width - 1
	}
	return false
}

func isBareChineseNegationBridge(value string) bool {
	switch value {
	case "", "再", "会", "要", "得", "可", "能", "应", "应该", "允许", "需要", "准", "打算", "计划", "会再", "要再", "应该再":
		return true
	default:
		return false
	}
}

// negationScopeInterrupted recognizes a second coordinated directive between a
// prohibition and the risky intent. In "do not add comments and deploy
// ransomware", the prohibition applies to adding comments; carrying it across
// the conjunction would let an unrelated harmless clause suppress the abuse.
func negationScopeInterrupted(between string) bool {
	between = strings.TrimSpace(between)
	for _, marker := range []string{" and ", " then ", "并且", "然后"} {
		if index := strings.LastIndex(between, marker); index > 0 {
			return true
		}
	}
	for _, suffix := range []string{" and", " then", "并", "并且", "然后"} {
		if strings.HasSuffix(between, suffix) && strings.TrimSpace(strings.TrimSuffix(between, suffix)) != "" {
			return true
		}
	}
	return false
}

func earliestRuleIntentIndex(text string, intents []string) int {
	earliest := -1
	for _, intent := range intents {
		for offset := 0; offset <= len(text)-len(intent); {
			index := strings.Index(text[offset:], intent)
			if index < 0 {
				break
			}
			index += offset
			leftOK := !isASCIIStringLocal(intent) || index == 0 || !isASCIIWordByte(text[index-1])
			right := index + len(intent)
			rightOK := !isASCIIStringLocal(intent) || right == len(text) || !isASCIIWordByte(text[right])
			if leftOK && rightOK && (earliest < 0 || index < earliest) {
				earliest = index
			}
			offset = index + 1
		}
	}
	return earliest
}

func (c *Classifier) hasRuleContradictoryDirective(
	analysis analyzedDirectives,
	stateRuleIndex int,
	intentProvider int,
	rule compiledRule,
	allow ContextPolicy,
) bool {
	if analysis.overflow && stateRuleIndex >= 0 && stateRuleIndex < len(analysis.overflowRuleStates) {
		return analysis.overflowRuleStates[stateRuleIndex].contradictory
	}
	for _, clause := range analysis.clauses {
		if c.directiveClauseContradictsContext(clause, intentProvider, rule, allow) {
			return true
		}
	}
	if analysis.overflow {
		for _, clause := range analysis.overflowTail {
			if c.directiveClauseContradictsContext(clause, intentProvider, rule, allow) {
				return true
			}
		}
	}
	return false
}

func (c *Classifier) directiveClauseContradictsContext(
	clause analyzedDirectiveClause,
	intentProvider int,
	rule compiledRule,
	allow ContextPolicy,
) bool {
	signals := clause.signals
	if !signals.matched(rule.intent) || !signals.matched(rule.object) {
		return false
	}
	clauseText := clause.text
	if (intentProvider >= 0 && clause.negatedRuleIntents.matched(intentProvider)) ||
		(intentProvider < 0 && clauseNegatesRuleIntent(clauseText, rule.intentStarts)) {
		return false
	}
	return c.activeDirectiveClauseContradictsContext(clause, rule, allow)
}

func (c *Classifier) activeDirectiveClauseContradictsContext(clause analyzedDirectiveClause, rule compiledRule, allow ContextPolicy) bool {
	return c.activeDirectiveClauseContradictsContextWithDense(clause, nil, rule, allow)
}

func (c *Classifier) activeDirectiveClauseContradictsContextWithDense(
	clause analyzedDirectiveClause,
	denseSignals []bool,
	rule compiledRule,
	allow ContextPolicy,
) bool {
	signals := clause.signals
	clauseText := clause.text
	if isLegitimateCategoryWorkflow(rule.category, clauseText) {
		return false
	}
	clauseContext := c.matchDirectiveContextsWithPolicy(signals, allow)
	if denseSignals != nil {
		clauseContext = c.matchContextsWithPolicy(denseSignals, allow)
	}
	if isSafetyDeliverableClause(clauseText) {
		return c.safetyMarkerHasPriorRuleCore(clauseText, rule) || safetyDeliverableTurnsOperational(clauseText, rule.intentStarts)
	}
	if containsDetectionArtifact(clauseText) {
		return !isSafeDetectionArtifactClause(clauseText) || explanatoryFramingTurnsOperational(clauseText, rule.intentStarts)
	}
	if clauseContext.Remediation && isScopedRetentionMaintenance(clauseText) {
		return false
	}
	if analyzedDirectiveSignalMatched(signals, denseSignals, rule.operational) && hasOperationalDeliverableFraming(clauseText) {
		return true
	}
	if startsWithRuleIntent(clauseText, rule.intentStarts) {
		return !isSafeDetectionArtifactClause(clauseText)
	}
	if hasExplanatoryFraming(clauseText) {
		return explanatoryFramingTurnsOperational(clauseText, rule.intentStarts)
	}
	return clauseContext == (ContextFlags{})
}

func hasOperationalDeliverableFraming(clause string) bool {
	clause = strings.TrimSpace(clause)
	for {
		before := clause
		for _, prefix := range []string{
			"please ", "now ", "then ", "actually ", "instead ", "kindly ", "go ahead and ",
			"could you ", "can you ", "i need you to ", "i want you to ",
			"for incident response ", "for remediation ", "for defensive analysis ", "for static analysis ",
			"请", "现在", "然后", "改为", "用于事件响应", "用于修复", "用于防御分析", "用于静态分析",
		} {
			if strings.HasPrefix(clause, prefix) {
				clause = strings.TrimSpace(clause[len(prefix):])
				break
			}
		}
		if clause == before {
			break
		}
	}
	for _, prefix := range []string{
		"give ", "provide ", "write ", "build ", "create ", "make ", "generate ", "show ", "produce ", "implement ", "develop ", "return ", "supply ",
		"给出", "提供", "编写", "写出", "制作", "创建", "生成", "展示", "实现", "开发",
	} {
		if strings.HasPrefix(clause, prefix) {
			return true
		}
	}
	return false
}

func isScopedRetentionMaintenance(clause string) bool {
	if hasExplicitHarmConflict(clause) {
		return false
	}
	scope := false
	for _, marker := range []string{
		"maintenance", "retention policy", "retention procedure", "expired logs", "old logs", "decommissioned", "end-of-life",
		"维护", "保留策略", "留存策略", "过期日志", "旧日志", "退役",
	} {
		if strings.Contains(clause, marker) {
			scope = true
			break
		}
	}
	if !scope {
		return false
	}
	for _, abusive := range []string{
		"after intrusion", "hide the intrusion", "avoid detection", "destroy evidence", "erase traces", "before the payload", "undetected",
		"入侵后", "掩盖入侵", "躲避检测", "销毁证据", "擦除痕迹", "避免告警",
	} {
		if strings.Contains(clause, abusive) {
			return false
		}
	}
	return true
}

var safetyDeliverableMarkers = []string{
	"recovery checklist", "remediation plan", "mitigation plan", "patch guidance", "restore from backups",
	"detection rule", "security checklist", "incident response plan", "malware protection", "ransomware insurance",
	"malware prevention", "insurance options", "ransomware awareness", "ransomware-awareness", "phishing simulation", "campaign simulation", "phishing campaign tabletop exercise", "awareness training",
	"employee quiz", "tabletop exercise", "mock phishing", "recognizing suspicious", "reporting suspicious",
	"恢复清单", "修复方案", "缓解方案", "补丁指南", "检测规则", "安全清单", "应急响应方案", "员工测验", "桌面演练", "模拟钓鱼",
}

func isSafetyDeliverableClause(clause string) bool {
	for _, marker := range safetyDeliverableMarkers {
		if strings.Contains(clause, marker) {
			return true
		}
	}
	return false
}

func (c *Classifier) safetyMarkerHasPriorRuleCore(clause string, rule compiledRule) bool {
	earliest := -1
	for _, marker := range safetyDeliverableMarkers {
		index := strings.Index(clause, marker)
		if index >= 0 && (earliest < 0 || index < earliest) {
			earliest = index
		}
	}
	if earliest < 0 {
		return false
	}
	runes := []rune(clause[:earliest])
	signals := make([]bool, c.signalCount)
	c.standardMatcher.match(runes, signals)
	c.compactMatcher.matchCompact(runes, signals)
	return signals[rule.intent] && signals[rule.object]
}

func safetyDeliverableTurnsOperational(clause string, intents []string) bool {
	for _, marker := range safetyDeliverableMarkers {
		if index := strings.Index(clause, marker); index >= 0 {
			tail := clause[index+len(marker):]
			// Detection artifacts necessarily describe the behavior they match.
			// "alert when an implant silences telemetry" is a defensive condition,
			// not an instruction to silence telemetry. A coordinated second action
			// ("detect and then disable EDR") is still operational and is caught by
			// explanatoryFramingTurnsOperational.
			if hasDetectionConditionFraming(tail) && !explanatoryFramingTurnsOperational(tail, intents) {
				return false
			}
			return containsRuleIntent(tail, intents)
		}
	}
	return false
}

func hasDetectionConditionFraming(text string) bool {
	return containsAnyLiteral(text,
		"alert when", "alert if", "detect when", "detect if", "match when", "match if",
		"flag when", "flag if", "trigger when", "trigger if", "identify attempts to",
		"attempts to", "attempt to", "behavior that", "behaviour that",
		"当出现时告警", "当检测到", "用于检测", "检测以下行为", "识别尝试", "尝试执行",
	)
}

func explanatoryFramingTurnsOperational(clause string, intents []string) bool {
	for _, marker := range []string{" and ", " while ", " but ", " then ", " instead ", " actually ", " with ", " by ", " using ", " via ", " through ", " including ", "并且", "但是", "然后", "改为", "通过", "使用", "包含"} {
		if index := strings.Index(clause, marker); index >= 0 && containsUnnegatedRuleIntent(clause[index+len(marker):], intents) {
			return true
		}
	}
	return false
}

func containsUnnegatedRuleIntent(text string, intents []string) bool {
	return containsUnnegatedRuleIntentPrepared(text, intents, compileCompactRuleIntentPatterns(intents))
}

func containsUnnegatedRuleIntentPrepared(text string, intents []string, patterns compactRuleIntentPatterns) bool {
	if len(text) > maxCompactIntentProofBytes {
		// An exhaustive per-occurrence negation proof over an oversized window
		// is intentionally unavailable; fail active and bound repeated scans.
		return true
	}
	foundLiteral := false
	clauseCount := 0
	overflow := false
	unnegated := false
	var negationScratch ruleIntentNegationScratch
	walkDirectiveClauses([]rune(text), func(clause []rune) bool {
		clauseCount++
		if clauseCount > maxAnalyzedDirectiveClauses {
			overflow = true
			return false
		}
		clauseText := string(clause)
		negationScratch.reset(clauseText)
		found, negated := clauseRuleIntentNegationPrepared(&negationScratch, intents, patterns)
		if !found {
			if containsRuleIntent(clauseText, intents) {
				// A compact-only occurrence in this clause is active unless its
				// own bounded literal analysis proves otherwise. An earlier clause's
				// negated literal must not suppress it through the global fallback.
				unnegated = true
				return false
			}
			return true
		}
		foundLiteral = true
		if !negated {
			unnegated = true
			return false
		}
		return true
	})
	if overflow || unnegated {
		return true
	}
	// Compact-only matches cannot be tied to a literal occurrence and retain
	// the historical fail-closed behavior. Literal matches suppress semantic
	// intent only when every bounded directive clause proves them negated.
	return !foundLiteral && containsRuleIntent(text, intents)
}

func containsRuleIntent(text string, intents []string) bool {
	text = strings.TrimSpace(text)
	for _, intent := range intents {
		if isASCIIStringLocal(intent) {
			if containsASCIIWord(text, intent) {
				return true
			}
		} else if strings.Contains(text, intent) {
			return true
		}
	}
	compactText := compactString([]rune(text))
	for _, intent := range intents {
		compactIntent := compactString([]rune(intent))
		if len(compactIntent) >= 2 && strings.Contains(compactText, compactIntent) {
			return true
		}
	}
	return false
}

func isASCIIStringLocal(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func normalizedTermValues(terms rules.Terms) []string {
	values := make([]string, 0, len(terms.ZH)+len(terms.EN))
	source := append(append([]string(nil), terms.ZH...), terms.EN...)
	for _, value := range source {
		normalized := string(normalizeParts([]string{value}).standardRunes)
		if normalized != "" {
			values = append(values, normalized)
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values
}

// independentQualifierTerms removes qualifier literals that overlap a core or
// an earlier qualifier literal. The original signals remain available for
// scope and contradiction checks, while only independent text can add score.
func independentQualifierTerms(terms rules.Terms, coveredGroups ...rules.Terms) rules.Terms {
	covered := make([]string, 0)
	for _, group := range coveredGroups {
		covered = append(covered, normalizedTermValues(group)...)
	}
	filter := func(values []string) []string {
		result := make([]string, 0, len(values))
		for _, value := range values {
			normalized := string(normalizeParts([]string{value}).standardRunes)
			if normalized == "" || termOverlapsAny(normalized, covered) {
				continue
			}
			result = append(result, value)
		}
		return result
	}
	return rules.Terms{ZH: filter(terms.ZH), EN: filter(terms.EN)}
}

func termOverlapsAny(value string, covered []string) bool {
	valueASCII := isASCIIStringLocal(value)
	for _, other := range covered {
		if valueASCII && isASCIIStringLocal(other) {
			if containsASCIIWord(value, other) || containsASCIIWord(other, value) {
				return true
			}
			continue
		}
		if strings.Contains(value, other) || strings.Contains(other, value) {
			return true
		}
	}
	return false
}

func startsWithRuleIntent(clause string, intents []string) bool {
	clause = strings.TrimSpace(clause)
	for {
		before := clause
		for _, prefix := range []string{
			"please ", "now ", "then ", "actually ", "instead ", "kindly ", "go ahead and ",
			"could you ", "can you ", "i need you to ", "i want you to ",
			"for incident response ", "for remediation ", "for defensive analysis ",
			"for static analysis ", "for a high-level analysis ", "for high-level analysis ",
			"as part of remediation ", "in an incident response exercise ",
			"请", "现在", "然后", "改为", "用于事件响应", "用于修复", "用于防御分析", "用于静态分析", "用于高层次分析",
		} {
			if strings.HasPrefix(clause, prefix) {
				clause = strings.TrimSpace(clause[len(prefix):])
				break
			}
		}
		if clause == before {
			break
		}
	}
	for _, intent := range intents {
		if !strings.HasPrefix(clause, intent) {
			continue
		}
		if len(clause) == len(intent) || !isASCIIWordByte(clause[len(intent)]) {
			return true
		}
	}
	compactClause := compactString([]rune(clause))
	for _, intent := range intents {
		compactIntent := compactString([]rune(intent))
		if len(compactIntent) >= 2 && strings.HasPrefix(compactClause, compactIntent) {
			return true
		}
	}
	return false
}

func isSafeDetectionArtifactClause(clause string) bool {
	if !containsDetectionArtifact(clause) {
		return false
	}
	detectionSemantics := false
	for _, marker := range []string{"detect", "alert", "signature", "indicator", "analytic", "outline", "match", "检测", "告警", "签名", "指标", "分析规则", "匹配"} {
		if strings.Contains(clause, marker) {
			detectionSemantics = true
			break
		}
	}
	if !detectionSemantics {
		return false
	}
	clause = strings.TrimSpace(clause)
	for _, prefix := range []string{
		"write a ", "write ", "create a ", "create ", "build a ", "build ", "generate a ", "generate ", "draft a ", "draft ", "produce a ", "produce ",
		"编写", "创建", "制作", "生成", "起草",
	} {
		if strings.HasPrefix(clause, prefix) {
			return true
		}
	}
	return false
}

func containsDetectionArtifact(clause string) bool {
	for _, marker := range []string{
		"yara rule", "yara signature", "sigma rule", "sigma analytic", "suricata rule", "suricata signature", "suricata alert", "snort rule", "snort signature", "snort detection outline", "ioc extraction", "indicators of compromise",
		"yara 规则", "sigma 规则", "suricata 规则", "snort 规则", "ioc 提取", "入侵指标",
	} {
		if strings.Contains(clause, marker) {
			return true
		}
	}
	return false
}

var directiveMarkers = [][]rune{
	[]rune(" but "), []rune(" however "), []rune(" then "), []rune(" instead "), []rune(" actually "), []rune(" while "),
	[]rune("但是"), []rune("然而"), []rune("然后"), []rune("改为"), []rune("实际"),
}

type directiveBoundaryKind uint8

const (
	directiveBoundaryNone directiveBoundaryKind = iota
	directiveBoundarySoft
	directiveBoundaryContinuation
	directiveBoundaryStrong
)

func walkDirectiveClauses(text []rune, visit func([]rune) bool) {
	walkDirectiveClausesWithBoundary(text, func(clause []rune, _ directiveBoundaryKind) bool {
		return visit(clause)
	})
}

func walkDirectiveClausesWithBoundary(text []rune, visit func([]rune, directiveBoundaryKind) bool) {
	walkDirectiveClausesWithBoundaryIntentStarts(text, nil, visit)
}

func (c *Classifier) walkDirectiveClausesWithBoundary(text []rune, visit func([]rune, directiveBoundaryKind) bool) {
	walkDirectiveClausesWithBoundaryIntentStarts(text, &c.directiveIntentStarts, visit)
}

func (c *Classifier) walkDirectiveClausesWithBoundaryRange(
	text []rune,
	visit func([]rune, int, int, directiveBoundaryKind) bool,
) {
	walkDirectiveClausesWithBoundaryRangeIntentStarts(text, &c.directiveIntentStarts, visit)
}

func walkDirectiveClausesWithBoundaryIntentStarts(
	text []rune,
	intentStarts *ruleIntentStartBuckets,
	visit func([]rune, directiveBoundaryKind) bool,
) {
	walkDirectiveClausesWithBoundaryRangeIntentStarts(
		text, intentStarts,
		func(clause []rune, _, _ int, boundaryBefore directiveBoundaryKind) bool {
			return visit(clause, boundaryBefore)
		},
	)
}

func walkDirectiveClausesWithBoundaryRangeIntentStarts(
	text []rune,
	intentStarts *ruleIntentStartBuckets,
	visit func([]rune, int, int, directiveBoundaryKind) bool,
) {
	start := 0
	boundaryBefore := directiveBoundaryNone
	for index := 0; index < len(text); index++ {
		width, boundaryKind := directiveBoundaryAt(text, index)
		if width == 0 {
			width, boundaryKind = conditionalAndNowDirectiveBoundaryAt(text, start, index, intentStarts)
		}
		if width == 0 {
			continue
		}
		clauseStart, clauseEnd := trimRuneSpaceRange(text, start, index)
		if clauseStart < clauseEnd {
			if !visit(text[clauseStart:clauseEnd], clauseStart, clauseEnd, boundaryBefore) {
				return
			}
		}
		boundaryBefore = boundaryKind
		start = index + width
		index += width - 1
	}
	clauseStart, clauseEnd := trimRuneSpaceRange(text, start, len(text))
	if clauseStart < clauseEnd {
		visit(text[clauseStart:clauseEnd], clauseStart, clauseEnd, boundaryBefore)
	}
}

func trimRuneSpaceRange(text []rune, start, end int) (int, int) {
	for start < end && unicode.IsSpace(text[start]) {
		start++
	}
	for end > start && unicode.IsSpace(text[end-1]) {
		end--
	}
	return start, end
}

var conditionalAndNowDirectiveMarker = []rune(" and now ")

func conditionalAndNowDirectiveBoundaryAt(
	text []rune,
	start int,
	index int,
	intentStarts *ruleIntentStartBuckets,
) (int, directiveBoundaryKind) {
	marker := conditionalAndNowDirectiveMarker
	if index < start || len(text)-index < len(marker) {
		return 0, directiveBoundaryNone
	}
	for offset, expected := range marker {
		if text[index+offset] != expected {
			return 0, directiveBoundaryNone
		}
	}
	prefix := trimRuneSpaces(text[start:index])
	if len(prefix) == 0 {
		return 0, directiveBoundaryNone
	}
	if directivePrefixHasExplanatoryGovernor(prefix) &&
		!directiveSuffixStartsOperationalDeliverable(text[index+len(marker):], intentStarts) {
		return 0, directiveBoundaryNone
	}
	return len(marker), directiveBoundaryStrong
}

func directivePrefixHasExplanatoryGovernor(prefix []rune) bool {
	const maxGovernorPrefixRunes = 256
	if len(prefix) > maxGovernorPrefixRunes {
		prefix = prefix[:maxGovernorPrefixRunes]
	}
	wordStart := -1
	for index := 0; index <= len(prefix); index++ {
		isLetter := index < len(prefix) && ((prefix[index] >= 'a' && prefix[index] <= 'z') || (prefix[index] >= 'A' && prefix[index] <= 'Z'))
		if isLetter {
			if wordStart < 0 {
				wordStart = index
			}
			continue
		}
		if wordStart < 0 {
			continue
		}
		word := prefix[wordStart:index]
		for _, governor := range [...]string{"explain", "compare", "describe", "discuss", "analyze", "review", "summarize"} {
			if runeSliceEqualFoldASCII(word, governor) {
				return true
			}
		}
		wordStart = -1
	}
	return false
}

func directiveSuffixStartsOperationalDeliverable(
	suffix []rune,
	intentStarts *ruleIntentStartBuckets,
) bool {
	const maxSuffixPrefixRunes = 256
	if len(suffix) > maxSuffixPrefixRunes {
		suffix = suffix[:maxSuffixPrefixRunes]
	}
	suffix = trimLeadingRuneSpaces(suffix)
	for stripped := 0; stripped < 4; stripped++ {
		matched := false
		for _, prefix := range [...]string{
			"please ", "kindly ", "go ahead and ", "could you ", "can you ",
			"i need you to ", "i want you to ", "you should ", "you must ",
			"we need to ", "let us ", "let's ", "your task is to ",
			"then ", "actually ", "instead ",
		} {
			if !runeSliceHasPrefixFoldASCII(suffix, prefix) {
				continue
			}
			suffix = trimLeadingRuneSpaces(suffix[len(prefix):])
			matched = true
			break
		}
		if !matched {
			break
		}
	}
	for _, prefix := range [...]string{
		"give ", "provide ", "write ", "build ", "create ", "make ", "generate ",
		"show ", "produce ", "implement ", "develop ", "return ", "supply ",
		"deploy ", "execute ", "run ", "launch ",
	} {
		if runeSliceHasPrefixFoldASCII(suffix, prefix) {
			return true
		}
	}
	return directiveSuffixStartsRuleIntent(suffix, intentStarts) ||
		directiveSuffixContainsModalRuleIntent(suffix, intentStarts)
}

// directiveSuffixContainsModalRuleIntent recognizes a bounded grammatical
// lead-in before an otherwise direct rule intent. Enumerating whole phrases
// such as "you should" is not sufficient: equivalent forms like "it is
// necessary to" or "we are expected to" would keep an approved-workflow marker
// and the active tail in one clause. The restricted token grammar deliberately
// rejects explanatory verbs, arbitrary prose, and more than twelve words, so
// ordinary discussion is not split merely because it mentions a rule intent
// later in the sentence.
func directiveSuffixContainsModalRuleIntent(suffix []rune, intentStarts *ruleIntentStartBuckets) bool {
	if intentStarts == nil {
		return false
	}
	const maxModalLeadInRunes = 96
	if len(suffix) > maxModalLeadInRunes {
		suffix = suffix[:maxModalLeadInRunes]
	}
	for index := 1; index < len(suffix); index++ {
		if unicode.IsSpace(suffix[index]) {
			continue
		}
		if isASCIIWordRune(suffix[index]) && isASCIIWordRune(suffix[index-1]) {
			continue
		}
		candidate := trimLeadingRuneSpaces(suffix[index:])
		if len(candidate) == 0 || !directiveSuffixStartsRuleIntent(candidate, intentStarts) {
			continue
		}
		if directiveModalLeadIn(string(suffix[:index])) {
			return true
		}
	}
	return false
}

func directiveModalLeadIn(prefix string) bool {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return false
	}
	for _, marker := range []string{"需要", "应该", "應該", "必须", "必須", "有必要", "务必", "務必", "应当", "應當"} {
		if !strings.Contains(prefix, marker) {
			continue
		}
		if containsAnyLiteral(prefix,
			"解释", "解釋", "分析", "比较", "比較", "审查", "審查", "总结", "總結", "说明", "說明", "讨论", "討論", "为什么", "為什麼", "如何",
		) {
			return false
		}
		return true
	}

	words := strings.Fields(prefix)
	if len(words) == 0 || len(words) > 12 {
		return false
	}
	seenModal := false
	seenAuxiliary := false
	seenInfinitive := false
	for _, word := range words {
		word = strings.Trim(word, "'\"")
		switch word {
		case "i", "we", "you", "it", "they", "one", "us", "them",
			"our", "your", "their", "the", "a", "an", "this", "that",
			"team", "operator", "operators", "system", "service", "user", "users",
			"now", "also", "actually", "still", "then", "next", "really", "simply",
			"go", "ahead", "and", "for":
			// Restricted neutral scaffolding around a modal construction.
		case "am", "is", "are", "was", "were", "be", "been", "being",
			"have", "has", "had", "do", "does", "did":
			seenAuxiliary = true
		case "should", "must", "need", "needs", "needed", "ought", "shall",
			"will", "would", "can", "could", "may", "might",
			"necessary", "required", "expected", "supposed", "important", "essential",
			"going", "meant", "asked", "instructed", "tasked", "ready":
			seenModal = true
		case "to":
			seenInfinitive = true
		default:
			return false
		}
	}
	return seenModal || (seenAuxiliary && seenInfinitive)
}

func directiveSuffixStartsRuleIntent(suffix []rune, intentStarts *ruleIntentStartBuckets) bool {
	if intentStarts == nil || len(suffix) == 0 {
		return false
	}
	first := suffix[0]
	if first >= 'A' && first <= 'Z' {
		first += 'a' - 'A'
	}
	if first >= 'a' && first <= 'z' {
		for _, intent := range intentStarts.ascii[first-'a'] {
			if contextualRuleIntentNeedsObject(intent) {
				continue
			}
			if !runeSliceHasPrefixFoldASCII(suffix, intent) {
				continue
			}
			if len(suffix) == len(intent) || !isASCIIWordRune(suffix[len(intent)]) {
				return true
			}
		}
	}
	for _, intent := range intentStarts.other[first] {
		if !runeSliceHasPrefixFoldASCIIValue(suffix, intent) {
			continue
		}
		if len(suffix) == len(intent) || !isASCIIWordRune(suffix[len(intent)]) {
			return true
		}
	}
	return false
}

func contextualRuleIntentNeedsObject(intent string) bool {
	switch intent {
	case "use", "turn", "convert", "leverage", "transform":
		return true
	default:
		return false
	}
}

func runeSliceHasPrefixFoldASCIIValue(value, expected []rune) bool {
	if len(value) < len(expected) {
		return false
	}
	for index, expectedRune := range expected {
		current := value[index]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		if expectedRune >= 'A' && expectedRune <= 'Z' {
			expectedRune += 'a' - 'A'
		}
		if current != expectedRune {
			return false
		}
	}
	return true
}

func trimLeadingRuneSpaces(value []rune) []rune {
	for len(value) > 0 && unicode.IsSpace(value[0]) {
		value = value[1:]
	}
	return value
}

func runeSliceHasPrefixFoldASCII(value []rune, expected string) bool {
	return len(value) >= len(expected) && runeSliceEqualFoldASCII(value[:len(expected)], expected)
}

func runeSliceEqualFoldASCII(value []rune, expected string) bool {
	if len(value) != len(expected) {
		return false
	}
	for index, current := range value {
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		if current != rune(expected[index]) {
			return false
		}
	}
	return true
}

func directiveBoundaryWidth(text []rune, index int) int {
	width, _ := directiveBoundaryAt(text, index)
	return width
}

func directiveBoundaryAt(text []rune, index int) (int, directiveBoundaryKind) {
	r := text[index]
	if r == compactHardBoundary {
		return 1, directiveBoundaryStrong
	}
	switch r {
	case ',', '，':
		if !singleRuneTokensAround(text, index) {
			return 1, directiveBoundarySoft
		}
	case '.':
		// A tightly embedded ASCII dot is a common CJK word-obfuscation
		// character (for example, 登.录.页 or 密.码), not a sentence boundary.
		// Keep ordinary English periods and any whitespace-separated dot as
		// strong boundaries so unrelated directives cannot be joined.
		if compactCJKDot(text, index) {
			return 0, directiveBoundaryNone
		}
		if !singleRuneTokensAround(text, index) {
			return 1, directiveBoundaryStrong
		}
	case '!', '?', ';', ':', '。', '！', '？', '；', '：':
		if !singleRuneTokensAround(text, index) {
			return 1, directiveBoundaryStrong
		}
	}
	for markerIndex, marker := range directiveMarkers {
		if len(text)-index < len(marker) {
			continue
		}
		matched := true
		for offset := range marker {
			if text[index+offset] != marker[offset] {
				matched = false
				break
			}
		}
		if matched {
			kind := directiveBoundarySoft
			// Contrast and replacement markers introduce a new directive. Sequence
			// and overlap markers remain a soft continuation boundary.
			if markerIndex == 0 || markerIndex == 1 || markerIndex == 3 || markerIndex == 4 ||
				markerIndex == 6 || markerIndex == 7 || markerIndex == 9 || markerIndex == 10 {
				kind = directiveBoundaryStrong
			} else {
				kind = directiveBoundaryContinuation
			}
			return len(marker), kind
		}
	}
	return 0, directiveBoundaryNone
}

func compactCJKDot(text []rune, index int) bool {
	if index <= 0 || index+1 >= len(text) {
		return false
	}
	left, right := text[index-1], text[index+1]
	if !isCompactRune(left) || !isCompactRune(right) {
		return false
	}
	// Do not reinterpret an ordinary ASCII word or sentence such as
	// "login.page". At least one adjacent letter must be non-ASCII; both sides
	// still have to touch the dot directly, which excludes spaced punctuation.
	return left > unicode.MaxASCII || right > unicode.MaxASCII
}

func lastDirectiveClause(text []rune) []rune {
	start := 0
	var last []rune
	for index := 0; index < len(text); index++ {
		if width := directiveBoundaryWidth(text, index); width > 0 {
			if clause := trimRuneSpaces(text[start:index]); len(clause) > 0 {
				last = clause
			}
			start = index + width
			index += width - 1
		}
	}
	if clause := trimRuneSpaces(text[start:]); len(clause) > 0 {
		return clause
	}
	return last
}

func trimRuneSpaces(value []rune) []rune {
	for len(value) > 0 && unicode.IsSpace(value[0]) {
		value = value[1:]
	}
	for len(value) > 0 && unicode.IsSpace(value[len(value)-1]) {
		value = value[:len(value)-1]
	}
	return value
}

func hasExplanatoryFraming(clause string) bool {
	for _, framing := range []string{
		"explain", "analyze", "analysis", "overview", "detect", "prevent",
		"mitigation", "remediation", "how attackers", "how an attacker", "why attackers",
		"risk of", "risks of", "warning signs", "draft a system policy", "draft a safety policy",
		"found", "discovered", "was disabled", "after detecting",
		"解释", "分析", "概述", "检测", "防止", "修复", "缓解", "攻击者如何", "为何攻击者", "风险", "发现", "被关闭",
	} {
		if strings.Contains(clause, framing) {
			return true
		}
	}
	return false
}

func followUpEligible(text []rune) bool {
	whole := string(text)
	lastClause := string(lastDirectiveClause(text))
	if lastClause == "" {
		return false
	}
	if hasNegationReversalFraming(lastClause) {
		return true
	}
	for _, reinforcing := range []string{
		"do not refuse", "don't refuse", "must not refuse", "never hesitate", "do not hesitate", "don't hesitate",
		"不要拒绝", "不得拒绝", "不要犹豫", "不得犹豫",
	} {
		if strings.Contains(lastClause, reinforcing) {
			return true
		}
	}
	if hasNegatedSafetyFraming(lastClause) {
		return false
	}
	policyFraming := false
	for _, phrase := range []string{"system policy", "safety policy", "content policy", "系统策略", "安全策略", "内容策略"} {
		policyFraming = policyFraming || strings.Contains(whole, phrase)
	}
	if policyFraming {
		for _, override := range []string{"ignore the", "is irrelevant", "irrelevant", "disregard", "忽略", "无关"} {
			if strings.Contains(whole, override) {
				return true
			}
		}
		return false
	}
	return true
}

func hasNegatedSafetyFraming(text string) bool {
	text = normalizeNegationSyntax(text)
	for _, phrase := range []string{
		"never ", "do not ", "must not ", "should not ", "need not ", "ought not ", "shall not ",
		"would not ", "could not ", "may not ", "cannot ", "will not ", "refuse to ", "prohibited", "forbidden",
		"不要", "不得", "不能", "不会", "拒绝", "禁止", "严禁",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func containsASCIIWord(text, term string) bool {
	for offset := 0; offset <= len(text)-len(term); {
		index := strings.Index(text[offset:], term)
		if index < 0 {
			return false
		}
		index += offset
		leftOK := index == 0 || !isASCIIWordByte(text[index-1])
		right := index + len(term)
		rightOK := right == len(text) || !isASCIIWordByte(text[right])
		if leftOK && rightOK {
			return true
		}
		offset = index + 1
	}
	return false
}

func isASCIIWordByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_'
}

func (c *Classifier) matchContexts(signals []bool) ContextFlags {
	return ContextFlags{
		Defensive:        signals[c.contexts[rules.ContextDefensive]],
		Remediation:      signals[c.contexts[rules.ContextRemediation]],
		CTFOrLab:         signals[c.contexts[rules.ContextCTF]] || signals[c.contexts[rules.ContextLab]],
		Authorized:       signals[c.contexts[rules.ContextAuthorized]],
		StaticAnalysis:   signals[c.contexts[rules.ContextStaticAnalysis]],
		IncidentResponse: signals[c.contexts[rules.ContextIncidentResponse]],
		HighLevel:        signals[c.contexts[rules.ContextHighLevel]],
	}
}

func (c *Classifier) matchContextsWithPolicy(signals []bool, policy ContextPolicy) ContextFlags {
	context := c.matchContexts(signals)
	return ContextFlags{
		Defensive:        context.Defensive && policy.Defensive,
		Remediation:      context.Remediation && policy.Remediation,
		CTFOrLab:         (signals[c.contexts[rules.ContextCTF]] && policy.CTF) || (signals[c.contexts[rules.ContextLab]] && policy.Lab),
		Authorized:       context.Authorized && policy.Authorized,
		StaticAnalysis:   context.StaticAnalysis && policy.StaticAnalysis,
		IncidentResponse: context.IncidentResponse && policy.IncidentResponse,
		HighLevel:        context.HighLevel && policy.HighLevel,
	}
}

func (c *Classifier) matchDirectiveContextsWithPolicy(signals directiveSignalSet, policy ContextPolicy) ContextFlags {
	return ContextFlags{
		Defensive:        signals.matched(c.contexts[rules.ContextDefensive]) && policy.Defensive,
		Remediation:      signals.matched(c.contexts[rules.ContextRemediation]) && policy.Remediation,
		CTFOrLab:         (signals.matched(c.contexts[rules.ContextCTF]) && policy.CTF) || (signals.matched(c.contexts[rules.ContextLab]) && policy.Lab),
		Authorized:       signals.matched(c.contexts[rules.ContextAuthorized]) && policy.Authorized,
		StaticAnalysis:   signals.matched(c.contexts[rules.ContextStaticAnalysis]) && policy.StaticAnalysis,
		IncidentResponse: signals.matched(c.contexts[rules.ContextIncidentResponse]) && policy.IncidentResponse,
		HighLevel:        signals.matched(c.contexts[rules.ContextHighLevel]) && policy.HighLevel,
	}
}

func (policy HardBlockPolicy) protects(category rules.Category) bool {
	switch category {
	case rules.CategoryCredentialTheft:
		return policy.CredentialTheft
	case rules.CategoryPhishing:
		return policy.PhishingDeployment
	case rules.CategoryRansomware:
		return policy.RansomwareDeployment
	case rules.CategoryExfiltration:
		return policy.DataExfiltration
	default:
		return false
	}
}

func applyContextDeductions(score int, context ContextFlags, authorizationProtected bool) int {
	if context.Defensive {
		score -= 22
	}
	if context.Remediation {
		score -= 28
	}
	if context.CTFOrLab && !(authorizationProtected && context.Authorized) {
		score -= 28
	}
	if context.Authorized && !authorizationProtected {
		score -= 22
	}
	if context.StaticAnalysis {
		score -= 28
	}
	if context.IncidentResponse {
		score -= 30
	}
	if context.HighLevel {
		score -= 25
	}
	return clampScore(score)
}

func contextEvidence(context ContextFlags) []Evidence {
	evidence := make([]Evidence, 0, 7)
	appendIf := func(condition bool, id string) {
		if condition {
			evidence = append(evidence, Evidence{ID: id, Kind: "context"})
		}
	}
	appendIf(context.Defensive, "CTX:defensive")
	appendIf(context.Remediation, "CTX:remediation")
	appendIf(context.CTFOrLab, "CTX:ctf_lab")
	appendIf(context.Authorized, "CTX:authorized")
	appendIf(context.StaticAnalysis, "CTX:static_analysis")
	appendIf(context.IncidentResponse, "CTX:incident_response")
	appendIf(context.HighLevel, "CTX:high_level")
	return evidence
}

func actionFor(mode Mode, score int, thresholds Thresholds) Action {
	if mode != ModeOff && score >= thresholds.HardBlock {
		return ActionBlock
	}
	switch mode {
	case ModeObserve:
		if score >= thresholds.Audit {
			return ActionObserve
		}
		return ActionAllow
	case ModeAudit:
		if score >= thresholds.Audit {
			return ActionAudit
		}
		return ActionAllow
	case ModeStrict:
		if score >= thresholds.Audit {
			return ActionBlock
		}
		return ActionAllow
	case ModeBalanced:
		if score >= thresholds.BalancedBlock {
			return ActionBlock
		}
		if score >= thresholds.Audit {
			return ActionAudit
		}
		return ActionAllow
	default:
		return ActionAllow
	}
}

func validThresholdsOrDefault(thresholds Thresholds) Thresholds {
	if thresholds == (Thresholds{}) {
		return DefaultThresholds()
	}
	if thresholds.Audit < 0 || thresholds.BalancedBlock < thresholds.Audit || thresholds.HardBlock < thresholds.BalancedBlock || thresholds.HardBlock > 100 {
		return DefaultThresholds()
	}
	return thresholds
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func uniqueSortedEvidence(values []Evidence) []Evidence {
	sort.Slice(values, func(i, j int) bool {
		if values[i].ID != values[j].ID {
			return values[i].ID < values[j].ID
		}
		return values[i].Kind < values[j].Kind
	})
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
