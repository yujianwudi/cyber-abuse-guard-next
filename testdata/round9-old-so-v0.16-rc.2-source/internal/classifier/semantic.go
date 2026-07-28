package classifier

import (
	"math/bits"
	"sort"
	"strings"

	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const maxSemanticDirectiveSpan = 4

type semanticDimension uint8

const (
	semanticHarm semanticDimension = iota
	semanticObject
	semanticAction
	semanticOutcome
	semanticTarget
	semanticDestination
	semanticEvasion
	semanticScale
	semanticSequence
	semanticImpact
	semanticDimensionCount
)

var semanticDimensionKinds = [semanticDimensionCount]string{
	"harm", "object", "action", "outcome", "target",
	"destination", "evasion", "scale", "sequence", "impact",
}

type compiledSemanticEvidence struct {
	id             uint16
	signalID       int
	dimensionMask  uint16
	longerEvidence []uint16
}

type compiledSemanticProfile struct {
	index          uint8
	category       rules.Category
	evidence       []compiledSemanticEvidence
	result         [semanticDimensionCount]Evidence
	intentStarts   []string
	intentPatterns compactRuleIntentPatterns
	intentSignals  []int
}

func (profile compiledSemanticProfile) id() string {
	return "SEMANTIC-" + string(profile.category)
}

type semanticSignalWindow struct {
	signals           [][]bool
	directiveSignals  []directiveSignalSet
	clauses           []analyzedDirectiveClause
	occurrences       []signalOccurrence
	clauseCount       int
	text              string
	coreEvidence      uint8
	coreEvidenceKnown bool
	prepared          bool
	harmConflict      bool
	affirmativeSafety bool
	legitimateMask    uint16
	legitimateKnown   uint16
}

type semanticAssessment struct {
	score                 int
	evidence              []Evidence
	explanation           DecisionExplanation
	corePredicateComplete bool
}

type semanticDimensions struct {
	harm, object, action, outcome       bool
	target, destination, evasion, scale bool
	sequence, impact                    bool
}

func (dimensions semanticDimensions) mask() uint16 {
	var mask uint16
	for dimension, matched := range [...]bool{
		dimensions.harm, dimensions.object, dimensions.action, dimensions.outcome,
		dimensions.target, dimensions.destination, dimensions.evasion, dimensions.scale,
		dimensions.sequence, dimensions.impact,
	} {
		if matched {
			mask |= uint16(1) << semanticDimension(dimension)
		}
	}
	return mask
}

func semanticDimensionsFromMask(mask uint16) semanticDimensions {
	matched := func(dimension semanticDimension) bool { return mask&(uint16(1)<<dimension) != 0 }
	return semanticDimensions{
		harm: matched(semanticHarm), object: matched(semanticObject),
		action: matched(semanticAction), outcome: matched(semanticOutcome),
		target: matched(semanticTarget), destination: matched(semanticDestination),
		evasion: matched(semanticEvasion), scale: matched(semanticScale),
		sequence: matched(semanticSequence), impact: matched(semanticImpact),
	}
}

type semanticEvidenceTerm struct {
	normalized    string
	terms         rules.Terms
	dimensionMask uint16
}

func buildSemanticEvidenceTerms(profile rules.SemanticProfile, categoryRules []rules.Rule, implementation, outcome rules.Terms) []semanticEvidenceTerm {
	groups := [semanticDimensionCount]rules.Terms{
		semanticHarm: profile.Harm, semanticObject: profile.Object,
		semanticAction: profile.Action, semanticOutcome: profile.Outcome,
		semanticTarget: profile.Target, semanticDestination: profile.Destination,
		semanticEvasion: profile.Evasion, semanticScale: profile.Scale,
		semanticSequence: profile.Sequence, semanticImpact: profile.Impact,
	}
	appendTerms := func(target *rules.Terms, source rules.Terms) {
		target.ZH = append(target.ZH, source.ZH...)
		target.EN = append(target.EN, source.EN...)
	}
	appendTerms(&groups[semanticAction], implementation)
	appendTerms(&groups[semanticOutcome], outcome)
	for _, rule := range categoryRules {
		appendTerms(&groups[semanticHarm], rule.Intent)
		appendTerms(&groups[semanticObject], rule.Object)
		appendTerms(&groups[semanticAction], rule.Operational)
		appendTerms(&groups[semanticTarget], rule.Target)
		appendTerms(&groups[semanticEvasion], rule.Evasion)
		appendTerms(&groups[semanticScale], rule.Scale)
	}

	byPhrase := make(map[string]int)
	compiled := make([]semanticEvidenceTerm, 0, 96)
	add := func(value string, dimension semanticDimension, chinese bool) {
		normalized := string(normalizeParts([]string{value}).standardRunes)
		if normalized == "" {
			return
		}
		if index, ok := byPhrase[normalized]; ok {
			compiled[index].dimensionMask |= uint16(1) << dimension
			return
		}
		term := semanticEvidenceTerm{normalized: normalized, dimensionMask: uint16(1) << dimension}
		if chinese {
			term.terms.ZH = []string{value}
		} else {
			term.terms.EN = []string{value}
		}
		byPhrase[normalized] = len(compiled)
		compiled = append(compiled, term)
	}
	for dimension, group := range groups {
		for _, value := range group.ZH {
			add(value, semanticDimension(dimension), true)
		}
		for _, value := range group.EN {
			add(value, semanticDimension(dimension), false)
		}
	}
	sort.Slice(compiled, func(left, right int) bool { return compiled[left].normalized < compiled[right].normalized })
	return compiled
}

func linkLongerSemanticEvidence(profile *compiledSemanticProfile, terms []semanticEvidenceTerm) {
	for shorter := range terms {
		for longer := range terms {
			if shorter == longer || len(terms[longer].normalized) <= len(terms[shorter].normalized) {
				continue
			}
			if semanticPhraseContains(terms[longer].normalized, terms[shorter].normalized) {
				profile.evidence[shorter].longerEvidence = append(profile.evidence[shorter].longerEvidence, uint16(longer))
				// The longer occurrence owns the shared phrase ID, but it may be
				// assigned to any one of the dimensions represented by that phrase.
				// This preserves useful ontology meaning without counting the same
				// textual occurrence twice.
				profile.evidence[longer].dimensionMask |= profile.evidence[shorter].dimensionMask
			}
		}
	}
}

func semanticPhraseContains(longer, shorter string) bool {
	if isASCIIStringLocal(shorter) && isASCIIStringLocal(longer) {
		return containsASCIIWord(longer, shorter)
	}
	return strings.Contains(longer, shorter)
}

func semanticDimensionsPotential(dimensions semanticDimensions) bool {
	if !dimensions.object || !(dimensions.harm || dimensions.action || dimensions.outcome) {
		return false
	}
	riskAxes := 0
	evidence := 0
	for _, matched := range []bool{
		dimensions.harm, dimensions.object, dimensions.action, dimensions.outcome,
		dimensions.target, dimensions.destination, dimensions.evasion, dimensions.scale,
		dimensions.sequence, dimensions.impact,
	} {
		if matched {
			evidence++
		}
	}
	for _, matched := range []bool{
		dimensions.action, dimensions.target, dimensions.destination, dimensions.evasion,
		dimensions.scale, dimensions.sequence, dimensions.impact,
	} {
		if matched {
			riskAxes++
		}
	}
	return evidence >= 4 && riskAxes >= 2
}

// semanticProfilePotential is a cheap conservative gate for the exact
// one-occurrence/one-dimension assignment. It may return true when one phrase
// owns several possible dimensions, but it must never return false when the
// exact matcher could produce a qualifying profile. This keeps irrelevant
// profiles out of the 1,024-state assignment on the ordinary short-request
// path without changing a classification decision.
func semanticProfilePotential(profile compiledSemanticProfile, windows [][]bool) bool {
	var mask uint16
	for _, evidence := range profile.evidence {
		for _, signals := range windows {
			if signalMatched(signals, evidence.signalID) {
				mask |= evidence.dimensionMask
				break
			}
		}
	}
	return semanticDimensionsPotential(semanticDimensionsFromMask(mask))
}

func semanticDirectiveWindows(analysis analyzedDirectives) []semanticSignalWindow {
	if analysis.semanticWindows != nil {
		return analysis.semanticWindows
	}
	windows := make([]semanticSignalWindow, 0, (len(analysis.clauses)+len(analysis.overflowTail))*2)
	windows = appendSemanticDirectiveWindows(windows, analysis.clauses)
	if analysis.overflow {
		// The retained head and exact four-clause suffix are separate evidence
		// regions. Never invent a link across omitted overflow clauses.
		windows = appendSemanticDirectiveWindows(windows, analysis.overflowTail)
	}
	return windows
}

func appendSemanticDirectiveWindows(windows []semanticSignalWindow, clauses []analyzedDirectiveClause) []semanticSignalWindow {
	for start := range clauses {
		text := ""
		for end := start; end < len(clauses) && end < start+maxSemanticDirectiveSpan; end++ {
			clause := clauses[end]
			if end > start && !semanticClausesLinked(clauses[end-1].text, clause.text, clause.boundaryBefore) {
				break
			}
			if text == "" {
				text = clause.text
			} else {
				text += "\n" + clause.text
			}
			window := semanticSignalWindow{
				clauses:     clauses[start : end+1],
				clauseCount: end - start + 1,
				text:        text,
			}
			prepareSemanticSignalWindow(&window)
			windows = append(windows, window)
		}
	}
	return windows
}

func semanticDirectiveSuffixWindows(clauses []analyzedDirectiveClause) []semanticSignalWindow {
	if len(clauses) == 0 {
		return nil
	}
	last := len(clauses) - 1
	windows := make([]semanticSignalWindow, 0, len(clauses))
	for start := range clauses {
		text := ""
		linked := true
		for end := start; end <= last; end++ {
			clause := clauses[end]
			if end > start && !semanticClausesLinked(clauses[end-1].text, clause.text, clause.boundaryBefore) {
				linked = false
				break
			}
			if text == "" {
				text = clause.text
			} else {
				text += "\n" + clause.text
			}
		}
		if linked {
			window := semanticSignalWindow{
				clauses:     clauses[start:],
				clauseCount: len(clauses) - start,
				text:        text,
			}
			prepareSemanticSignalWindow(&window)
			windows = append(windows, window)
		}
	}
	return windows
}

func (c *Classifier) updateOverflowSemanticAssessments(
	destination []semanticAssessment,
	clauses []analyzedDirectiveClause,
	denseLastSignals []bool,
	policy Policy,
	signalStorage *[maxSemanticDirectiveSpan]directiveSignalSet,
) {
	if len(clauses) == 0 || len(destination) == 0 || signalStorage == nil {
		return
	}
	last := len(clauses) - 1
	for start := range clauses {
		signals := signalStorage[:0]
		linked := true
		for end := start; end <= last; end++ {
			if end > start && !semanticClausesLinked(clauses[end-1].text, clauses[end].text, clauses[end].boundaryBefore) {
				linked = false
				break
			}
			signals = append(signals, clauses[end].signals)
		}
		if !linked {
			continue
		}
		windowClauses := clauses[start:]
		if len(windowClauses) == 1 && semanticDirectiveClauseOnlyNegated(windowClauses[0]) {
			continue
		}
		window := semanticSignalWindow{
			directiveSignals: signals, clauses: windowClauses, clauseCount: len(windowClauses),
		}
		textReady := false
		for profileIndex, profile := range c.semanticProfiles {
			if profileIndex >= len(destination) || semanticDirectiveProfileOnlyNegated(windowClauses, profileIndex) {
				continue
			}
			dimensions := c.semanticDirectiveDimensionsWithDenseLast(profile, signals, denseLastSignals)
			if !semanticDimensionsPotential(dimensions) {
				continue
			}
			if !textReady {
				window.text = joinAnalyzedDirectiveClauseText(windowClauses)
				prepareSemanticSignalWindow(&window)
				textReady = true
			}
			prepareSemanticSignalWindowCategory(&window, profile.category)
			assessment := c.assessSemanticWindowWithDimensions(profile, window, dimensions, policy)
			if semanticAssessmentBetter(assessment, destination[profileIndex]) {
				destination[profileIndex] = assessment
			}
		}
	}
}

func semanticDirectiveClauseOnlyNegated(clause analyzedDirectiveClause) bool {
	return clause.semanticIntentsPresent != 0 &&
		clause.semanticIntentsPresent == clause.semanticIntentsOnlyNegated &&
		semanticNegatedBoundary(clause.text)
}

func semanticDirectiveProfileOnlyNegated(clauses []analyzedDirectiveClause, profileIndex int) bool {
	if profileIndex < 0 || profileIndex >= 16 {
		return false
	}
	profileBit := uint16(1) << uint(profileIndex)
	present := false
	for _, clause := range clauses {
		if clause.semanticIntentsPresent&profileBit == 0 {
			continue
		}
		present = true
		if clause.semanticIntentsOnlyNegated&profileBit == 0 {
			return false
		}
	}
	return present
}

func joinAnalyzedDirectiveClauseText(clauses []analyzedDirectiveClause) string {
	size := max(0, len(clauses)-1)
	for _, clause := range clauses {
		size += len(clause.text)
	}
	var text strings.Builder
	text.Grow(size)
	for index, clause := range clauses {
		if index != 0 {
			text.WriteByte('\n')
		}
		text.WriteString(clause.text)
	}
	return text.String()
}

func semanticClausesLinked(previous, current string, boundary directiveBoundaryKind) bool {
	previous = strings.ToLower(strings.TrimSpace(previous))
	current = strings.ToLower(strings.TrimSpace(current))
	if semanticTopicBreak(previous) || semanticTopicBreak(current) || semanticNegatedBoundary(current) {
		return false
	}
	if boundary == directiveBoundaryStrong {
		// Strong punctuation normally prevents composition. A narrow affirmative
		// referent ("actually steal them", "execute the above") is the explicit
		// exception required by the active-directive model: it reactivates the
		// immediately preceding object without allowing unrelated sentences to
		// donate dimensions.
		return semanticExplicitReferentReactivation(current)
	}
	if boundary == directiveBoundaryNone {
		return false
	}
	if boundary == directiveBoundaryContinuation {
		return true
	}
	if hasAnyPrefix(current,
		"and ", "or ", "then ", "next ", "while ", "with ", "including ", "followed by ",
		"并", "且", "然后", "接着", "随后", "同时", "以及", "包括", "再分批", "再外传",
	) || containsAnyLiteral(current,
		" it ", " them ", " those ", " these ", " the same ", " the traffic", " those sessions", " their backups",
		"它", "其", "这些", "上述", "该对象", "该流量", "这些会话", "其备份",
	) {
		return true
	}
	if semanticParallelPassive(previous, current) || semanticElidedPassive(previous, current) ||
		(hasAnyPrefix(previous, "success means ", "success is ", "成功标准", "成功是") || containsAnyLiteral(previous, " success means ", " success is ")) {
		return true
	}
	// A comma-delimited imperative or nominalized list is an explicit local
	// composition. Finite subject clauses are not joined merely because they are
	// adjacent, which prevents unrelated sentences from donating remote axes.
	if semanticFiniteClause(current) {
		return false
	}
	return semanticContinuationFragment(current)
}

func semanticExplicitReferentReactivation(text string) bool {
	if semanticNegatedBoundary(text) || hasExplanatoryFraming(text) || hasAffirmativeSafetyPurpose(text) {
		return false
	}
	activeDirective := semanticContinuationFragment(text) || hasAnyPrefix(text,
		"actually ", "instead ", "nevertheless ", "nonetheless ", "even so ",
		"execute ", "implement ", "apply ", "carry ", "do ",
		"实际", "改为", "执行", "实现", "应用", "照做",
	)
	return activeDirective && containsAnyLiteral(text,
		" it", " them", " that", " those", " the above", " above request", " same ",
		"它", "它们", "上述", "上面", "该内容", "同一",
	)
}

func semanticFiniteClause(text string) bool {
	return hasAnyPrefix(text, "i ", "we ", "you ", "he ", "she ", "they ", "the ", "a ", "an ", "this ", "that ", "weather ", "today ", "我", "我们", "你", "他", "她", "他们", "今天", "天气") ||
		containsAnyLiteral(text, " is ", " are ", " was ", " were ", " should ", " would ", " could ", " will ", " can ")
}

func semanticContinuationFragment(text string) bool {
	if text == "" {
		return false
	}
	return hasAnyPrefix(text,
		"avoid ", "bypass ", "copy ", "defeat ", "delete ", "destroy ", "disable ", "disguise ", "eliminate ",
		"accept ", "alter ", "capture ", "deploy ", "erase ", "escalate ", "exhaust ", "extract ", "extend ", "fill ", "flood ", "gain ", "harvest ", "have ", "hide ", "keep ", "label ", "leave ", "make ", "mute ", "obfuscate ", "obtain ", "overload ", "place ", "prevent ", "provide ", "remove ", "run ", "steal ",
		"retain ", "rewrite ", "route ", "send ", "stage ", "suppress ", "weaken ",
		"alert suppression", "attribution prevention", "authentication bypass", "audit cleanup", "capacity exhaustion",
		"covert ", "credential misuse", "destruction ", "evidence destruction", "failover prevention", "lateral access",
		"central monitoring", "dependency amplification", "privilege escalation", "security-control ", "staged ", "traffic disguise",
		"把", "从", "用", "对", "向", "将", "借", "停掉", "填入", "压缩", "拿下", "留下", "只在", "避开", "绕过", "删除", "删掉", "清除", "清掉", "拖垮", "压垮", "淹没", "洪泛", "隐藏", "静默", "开机常驻", "自动回连", "改写", "收集", "提取", "上传", "发送", "发动", "发起", "持续", "让真实", "再要求", "分批", "随后", "之后", "批量", "外送", "抑制", "阻止",
	)
}

func semanticParallelPassive(previous, current string) bool {
	previousPassive := containsAnyLiteral(previous, " is to be ", " are to be ", " is to become ", " are to become ")
	currentPassive := containsAnyLiteral(current, " is to be ", " are to be ", " is to become ", " are to become ")
	return previousPassive && currentPassive
}

func semanticElidedPassive(previous, current string) bool {
	if !containsAnyLiteral(previous, " is to be ", " are to be ", " is to become ", " are to become ") {
		return false
	}
	return containsAnyLiteral(current,
		" records rewritten", " activity labeled", " export split", " clues erased",
		" nodes dragged", " jobs disturbed", " backups erased", " access returned",
	)
}

func semanticNegatedBoundary(text string) bool {
	text = strings.TrimSpace(text)
	for {
		matched := false
		for _, prefix := range []string{"and ", "or ", "then ", "next ", "并且", "以及", "然后", "接着"} {
			if strings.HasPrefix(text, prefix) {
				text = strings.TrimSpace(text[len(prefix):])
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	return hasAnyPrefix(text,
		"do not ", "don't ", "never ", "must not ", "should not ",
		"不得", "不要", "严禁", "禁止", "无需", "不需要", "无须",
	)
}

func semanticTopicBreak(text string) bool {
	for _, marker := range []string{
		"separately", "respectively", "unrelated", "in another request", "on a different topic", "on another topic", "change topic", "switch topic", "by contrast",
		"另一个请求", "另一个话题", "与此无关", "分别", "另行", "换题", "换个话题", "切换话题",
	} {
		if text == marker || strings.HasPrefix(text, marker+" ") || (!isASCIIStringLocal(marker) && strings.HasPrefix(text, marker)) {
			return true
		}
	}
	return false
}

func structuredSemanticFragment(text string) bool {
	text = strings.TrimSpace(text)
	if strings.Count(text, "--") >= 3 {
		return true
	}
	if len(text) < 2 || !((text[0] == '{' && text[len(text)-1] == '}') || (text[0] == '[' && text[len(text)-1] == ']')) {
		return false
	}
	return strings.Count(text, "\":") >= 3
}

func semanticPartsLinked(previous, current string) bool {
	previous = strings.ToLower(strings.TrimSpace(previous))
	current = strings.ToLower(strings.TrimSpace(current))
	if semanticTopicBreak(previous) || semanticTopicBreak(current) {
		return false
	}
	bound := containsAnyLiteral(previous,
		"combine these", "treat this as", "these details", "one operation", "one rollout", "one deployment",
		"the asset is", "the artifact is", "the component is", "affected assets", "the mechanism is",
		"合并这些", "视为同一", "同一操作", "同一投放", "同一部署", "该资产是", "该组件是", "受影响资产", "该机制是",
	)
	continuationPrefix := ""
	for _, prefix := range []string{"then ", "next ", "continue ", "now ", "接着", "接下来", "然后", "继续", "现在"} {
		if strings.HasPrefix(current, prefix) {
			continuationPrefix = prefix
			break
		}
	}
	if !bound || continuationPrefix == "" || semanticNegatedBoundary(current) {
		return false
	}
	remainder := strings.TrimSpace(current[len(continuationPrefix):])
	return semanticContinuationFragment(remainder) || containsAnyLiteral(remainder,
		"execution sequence", "operating sequence", "operational sequence", "implementation sequence",
		"execution plan", "implementation plan", "deployment plan", "rollout plan", "practical workflow",
		"provide the sequence", "give the sequence", "provide a sequence", "give a sequence",
		"执行顺序", "执行步骤", "实施步骤", "操作顺序", "部署计划", "投放计划", "可操作方案",
	)
}

func (c *Classifier) assessSemanticWindow(profile compiledSemanticProfile, window semanticSignalWindow, policy Policy) semanticAssessment {
	prepareSemanticSignalWindow(&window)
	prepareSemanticSignalWindowCategory(&window, profile.category)
	if semanticWindowExcluded(profile, window) {
		return semanticAssessment{}
	}
	dimensions := c.semanticWindowDimensions(profile, window)
	return c.assessEligibleSemanticWindow(profile, window, dimensions, policy)
}

func (c *Classifier) assessSemanticWindowWithDimensions(
	profile compiledSemanticProfile,
	window semanticSignalWindow,
	dimensions semanticDimensions,
	policy Policy,
) semanticAssessment {
	prepareSemanticSignalWindow(&window)
	prepareSemanticSignalWindowCategory(&window, profile.category)
	if semanticWindowExcluded(profile, window) {
		return semanticAssessment{}
	}
	return c.assessEligibleSemanticWindow(profile, window, dimensions, policy)
}

func semanticWindowExcluded(profile compiledSemanticProfile, window semanticSignalWindow) bool {
	return strings.TrimSpace(window.text) == "" ||
		descriptiveDocumentationWindow(window.text) ||
		window.legitimateMask&(uint16(1)<<categoryPriority(profile.category)) != 0 ||
		window.affirmativeSafety
}

func descriptiveDocumentationWindow(text string) bool {
	text = strings.TrimSpace(text)
	if !hasAnyPrefix(text,
		"documentation notes that ", "documentation states that ",
		"the documentation notes that ", "the documentation states that ",
		"a report notes that ", "the report notes that ", "the report states that ",
		"文档指出", "文档说明", "报告指出", "报告说明",
	) {
		return false
	}
	return !containsAnyLiteral(text,
		" now ", " then ", " please ", "provide ", "write ", "create ", "build ",
		"implement ", "execute ", "deploy ", "run ", "carry it out", "do it",
		"现在", "然后", "请", "提供", "编写", "创建", "构建", "实现", "执行", "部署", "运行", "照做",
	)
}

func prepareSemanticSignalWindow(window *semanticSignalWindow) {
	if window == nil || window.prepared {
		return
	}
	window.prepared = true
	text := strings.TrimSpace(window.text)
	if text == "" {
		return
	}
	window.harmConflict = hasExplicitHarmConflict(text)
	window.affirmativeSafety = hasAffirmativeSafetyPurpose(text) && !window.harmConflict
}

// prepareSemanticSignalWindowCategory defers the comparatively expensive
// legitimate-workflow proof until a rule or semantic profile from that
// category can actually use the window. Candidate-rich inputs contain many
// local windows, but only a small subset are relevant to any one category;
// eagerly running all category predicates for every window multiplied both
// CPU and compact-intent scratch allocations.
func prepareSemanticSignalWindowCategory(window *semanticSignalWindow, category rules.Category) {
	if window == nil {
		return
	}
	prepareSemanticSignalWindow(window)
	bit := uint16(1) << categoryPriority(category)
	if window.legitimateKnown&bit != 0 {
		return
	}
	window.legitimateKnown |= bit
	if isLegitimateCategoryWorkflow(category, strings.TrimSpace(window.text)) {
		window.legitimateMask |= bit
	}
}

func (c *Classifier) assessEligibleSemanticWindow(
	profile compiledSemanticProfile,
	window semanticSignalWindow,
	dimensions semanticDimensions,
	policy Policy,
) semanticAssessment {
	if !dimensions.object || !(dimensions.harm || dimensions.action || dimensions.outcome) {
		return semanticAssessment{}
	}
	riskAxes := 0
	for _, matched := range []bool{dimensions.action, dimensions.target, dimensions.destination, dimensions.evasion, dimensions.scale, dimensions.sequence, dimensions.impact} {
		if matched {
			riskAxes++
		}
	}
	if riskAxes < 2 {
		return semanticAssessment{}
	}
	if semanticWindowIntentOnlyNegated(profile, window) {
		return semanticAssessment{}
	}
	corePredicateComplete := round8SemanticCorePredicate(profile.category, window.text, dimensions)
	if window.coreEvidenceKnown {
		corePredicateComplete = round8SemanticCorePredicateFromEvidence(
			profile.category, dimensions, window.coreEvidence,
		)
	}

	dimensionList := [...]struct {
		dimension semanticDimension
		matched   bool
		points    int
	}{
		{semanticHarm, dimensions.harm, 10}, {semanticObject, dimensions.object, 12},
		{semanticAction, dimensions.action, 9}, {semanticOutcome, dimensions.outcome, 9},
		{semanticTarget, dimensions.target, 8}, {semanticDestination, dimensions.destination, 8},
		{semanticEvasion, dimensions.evasion, 7}, {semanticScale, dimensions.scale, 6},
		{semanticSequence, dimensions.sequence, 6}, {semanticImpact, dimensions.impact, 9},
	}
	// Four independently owned dimensions are the semantic acceptance floor.
	// Base 27 makes the weakest valid object + agency + two-risk-axis set reach
	// balanced without requiring a fifth phrase from the same sentence.
	score := 27
	evidence := make([]Evidence, 0, len(dimensionList))
	for _, dimension := range dimensionList {
		if !dimension.matched {
			continue
		}
		score += dimension.points
		evidence = append(evidence, profile.result[dimension.dimension])
	}
	if len(evidence) < 4 {
		return semanticAssessment{}
	}

	corePredicateScore := 27
	for _, dimension := range dimensionList[:4] {
		if dimension.matched {
			corePredicateScore += dimension.points
		}
	}
	qualifierScore := score - corePredicateScore
	context := c.semanticWindowContexts(window, policy.Allow)
	if hasExplicitHarmConflict(window.text) {
		context.Authorized = false
		context.CTFOrLab = false
	}
	authorizationProtected := policy.HardBlockEvenIfAuthorized.protects(profile.category)
	scoreBeforeContext := score
	score = applyContextDeductions(score, context, authorizationProtected)
	contextAdjustment := score - scoreBeforeContext
	genuineSafetyContext := context.Defensive || context.Remediation || context.StaticAnalysis || context.IncidentResponse || context.HighLevel
	hardFloorApplied := false
	if corePredicateComplete && authorizationProtected && !genuineSafetyContext && score < HardThreshold {
		score = HardThreshold
		hardFloorApplied = true
	}
	score = clampScore(score)
	explanation := DecisionExplanation{
		WinningRuleID:           profile.id(),
		WinningCategory:         string(profile.category),
		CorePredicateComplete:   corePredicateComplete,
		EvidenceDimensionMask:   dimensions.mask(),
		EvidenceOccurrenceCount: len(evidence),
		EvidenceSegmentCount:    semanticWindowSegmentCount(window),
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
		explanation.HardFloorReason = hardFloorReasonSemanticCompleteCoreWithTwoRiskAxes
	}
	return semanticAssessment{
		score: score, evidence: evidence, explanation: explanation,
		corePredicateComplete: corePredicateComplete,
	}
}

func semanticAssessmentBetter(candidate, current semanticAssessment) bool {
	if candidate.corePredicateComplete != current.corePredicateComplete {
		return candidate.corePredicateComplete
	}
	return candidate.score > current.score
}

func constrainSemanticAssessment(assessment semanticAssessment, thresholds Thresholds) semanticAssessment {
	thresholds = validThresholdsOrDefault(thresholds)
	if assessment.corePredicateComplete || assessment.score < thresholds.BalancedBlock {
		return assessment
	}
	assessment.score = thresholds.BalancedBlock - 1
	if assessment.score < 0 {
		assessment.score = 0
	}
	assessment.explanation.CorePredicateComplete = false
	assessment.explanation.HardFloorApplied = false
	assessment.explanation.HardFloorReason = ""
	assessment.explanation.ScoreBreakdown.FinalScore = assessment.score
	return assessment
}

func semanticWindowIntentOnlyNegated(profile compiledSemanticProfile, window semanticSignalWindow) bool {
	if len(window.clauses) != 0 {
		return semanticDirectiveProfileOnlyNegated(window.clauses, int(profile.index))
	}
	return semanticIntentOnlyNegatedPrepared(window.text, profile.intentStarts, profile.intentPatterns)
}

func semanticWindowSegmentCount(window semanticSignalWindow) int {
	count := window.clauseCount
	if len(window.signals) > count {
		count = len(window.signals)
	}
	if count == 0 && (len(window.directiveSignals) != 0 || len(window.occurrences) != 0 || window.text != "") {
		count = 1
	}
	return count
}

func (c *Classifier) semanticDimensions(profile compiledSemanticProfile, windows [][]bool) semanticDimensions {
	matched := func(signalID int) bool {
		for _, signals := range windows {
			if signalMatched(signals, signalID) {
				return true
			}
		}
		return false
	}
	return c.semanticDimensionsByMatch(profile, matched)
}

func (c *Classifier) semanticDirectiveDimensions(profile compiledSemanticProfile, windows []directiveSignalSet) semanticDimensions {
	matched := func(signalID int) bool {
		for _, signals := range windows {
			if signals.matched(signalID) {
				return true
			}
		}
		return false
	}
	return c.semanticDimensionsByMatch(profile, matched)
}

func (c *Classifier) semanticDirectiveDimensionsWithDenseLast(
	profile compiledSemanticProfile,
	windows []directiveSignalSet,
	denseLastSignals []bool,
) semanticDimensions {
	matched := func(signalID int) bool {
		last := len(windows) - 1
		for index, signals := range windows {
			if index == last && denseLastSignals != nil {
				if signalMatched(denseLastSignals, signalID) {
					return true
				}
				continue
			}
			if signals.matched(signalID) {
				return true
			}
		}
		return false
	}
	return c.semanticDimensionsByMatch(profile, matched)
}

func (c *Classifier) semanticWindowDimensions(profile compiledSemanticProfile, window semanticSignalWindow) semanticDimensions {
	matched := func(signalID int) bool {
		for _, signals := range window.signals {
			if signalMatched(signals, signalID) {
				return true
			}
		}
		for _, signals := range window.directiveSignals {
			if signals.matched(signalID) {
				return true
			}
		}
		for _, clause := range window.clauses {
			if clause.signals.matched(signalID) {
				return true
			}
		}
		return false
	}
	return c.semanticDimensionsByMatch(profile, matched)
}

func (c *Classifier) semanticDimensionsByMatch(profile compiledSemanticProfile, matched func(int) bool) semanticDimensions {
	var reachable [1 << semanticDimensionCount]bool
	reachable[0] = true
	for _, evidence := range profile.evidence {
		if !matched(evidence.signalID) {
			continue
		}
		shadowed := false
		for _, longer := range evidence.longerEvidence {
			if matched(profile.evidence[longer].signalID) {
				shadowed = true
				break
			}
		}
		if shadowed {
			continue
		}
		for state := len(reachable) - 1; state >= 0; state-- {
			if !reachable[state] {
				continue
			}
			for choices := evidence.dimensionMask; choices != 0; choices &= choices - 1 {
				dimension := choices & -choices
				reachable[state|int(dimension)] = true
			}
		}
	}
	bestMask := uint16(0)
	bestUtility := -1
	for state, ok := range reachable {
		if !ok {
			continue
		}
		mask := uint16(state)
		utility := bits.OnesCount16(mask) * 100
		if mask&(uint16(1)<<semanticObject) != 0 {
			utility += 20
		}
		if mask&((uint16(1)<<semanticHarm)|(uint16(1)<<semanticAction)|(uint16(1)<<semanticOutcome)) != 0 {
			utility += 10
		}
		riskMask := mask & ((uint16(1) << semanticAction) | (uint16(1) << semanticTarget) |
			(uint16(1) << semanticDestination) | (uint16(1) << semanticEvasion) |
			(uint16(1) << semanticScale) | (uint16(1) << semanticSequence) | (uint16(1) << semanticImpact))
		utility += bits.OnesCount16(riskMask) * 2
		if utility > bestUtility {
			bestUtility = utility
			bestMask = mask
		}
	}
	return semanticDimensionsFromMask(bestMask)
}

func (c *Classifier) semanticWindowContexts(window semanticSignalWindow, policy ContextPolicy) ContextFlags {
	matched := func(signalID int) bool {
		for _, signals := range window.signals {
			if signalMatched(signals, signalID) {
				return true
			}
		}
		for _, signals := range window.directiveSignals {
			if signals.matched(signalID) {
				return true
			}
		}
		for _, clause := range window.clauses {
			if clause.signals.matched(signalID) {
				return true
			}
		}
		return false
	}
	return ContextFlags{
		Defensive:        matched(c.contexts[rules.ContextDefensive]) && policy.Defensive,
		Remediation:      matched(c.contexts[rules.ContextRemediation]) && policy.Remediation,
		CTFOrLab:         (matched(c.contexts[rules.ContextCTF]) && policy.CTF) || (matched(c.contexts[rules.ContextLab]) && policy.Lab),
		Authorized:       matched(c.contexts[rules.ContextAuthorized]) && policy.Authorized,
		StaticAnalysis:   matched(c.contexts[rules.ContextStaticAnalysis]) && policy.StaticAnalysis,
		IncidentResponse: matched(c.contexts[rules.ContextIncidentResponse]) && policy.IncidentResponse,
		HighLevel:        matched(c.contexts[rules.ContextHighLevel]) && policy.HighLevel,
	}
}

func semanticIntentOnlyNegated(text string, intents []string) bool {
	return semanticIntentOnlyNegatedPrepared(text, intents, compileCompactRuleIntentPatterns(intents))
}

func semanticIntentOnlyNegatedPrepared(text string, intents []string, patterns compactRuleIntentPatterns) bool {
	if len(text) > maxCompactIntentProofBytes {
		// Semantic suppression is optional defensive credit. Oversized windows
		// retain the matched semantic intent instead of paying rules x input
		// rescans to prove that every occurrence is negated.
		return false
	}
	if !containsRuleIntent(text, intents) {
		return false
	}
	return !containsUnnegatedRuleIntentPrepared(text, intents, patterns)
}
