package classifier

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxMetaOverrideQuotedSpans           = 16
	maxMetaOverrideSplitAssociationBytes = 512
	maxMetaOverrideDirectiveClauses      = 128
	maxMetaOverrideDirectiveBoundaries   = 1024
)

type metaOverrideQuotedSpan struct {
	start int
	end   int
}

var metaOverrideAnalysisTopics = []string{
	"prompt injection", "jailbreak attempt", "jailbreak sample", "instruction override", "instruction-hierarchy attack",
	"system prompt leakage", "quoted prompt", "red-team transcript", "untrusted instruction", "hostile instruction",
	"提示注入", "越狱尝试", "越狱样本", "指令覆盖", "指令层级攻击", "系统提示泄露", "引用提示词", "红队转录",
	"不可信指令", "敌意指令",
}

var metaOverrideAnalysisPurposes = []string{
	"analyze", "analyse", "review", "detect", "prevent", "mitigate", "summarize", "classify", "flag", "write a detector",
	"recommend controls", "explain why", "analysis only", "static analysis", "security review",
	"分析", "审查", "检测", "防止", "缓解", "总结", "分类", "标记", "编写检测器", "建议防护", "解释为什么", "仅用于分析", "静态分析",
}

var metaOverrideDirectiveActions = []string{
	"apply", "follow", "obey", "execute", "comply", "use", "install", "activate", "enable", "deploy", "persist",
	"load", "append", "replace", "override", "configure", "implement", "adopt", "run", "carry out", "operationalize",
	"应用", "遵循", "服从", "执行", "照做", "采用", "使用", "安装", "激活", "启用", "部署", "持久化", "加载",
	"追加", "替换", "覆盖", "配置", "落地", "实施", "运行", "生效",
}

type metaOverridePassiveActionForm struct {
	form   string
	action string
}

var metaOverridePassiveActionForms = []metaOverridePassiveActionForm{
	{form: "applied", action: "apply"},
	{form: "followed", action: "follow"},
	{form: "obeyed", action: "obey"},
	{form: "executed", action: "execute"},
	{form: "complied", action: "comply"},
	{form: "used", action: "use"},
	{form: "installed", action: "install"},
	{form: "activated", action: "activate"},
	{form: "enabled", action: "enable"},
	{form: "deployed", action: "deploy"},
	{form: "persisted", action: "persist"},
	{form: "loaded", action: "load"},
	{form: "appended", action: "append"},
	{form: "replaced", action: "replace"},
	{form: "overridden", action: "override"},
	{form: "configured", action: "configure"},
	{form: "implemented", action: "implement"},
	{form: "adopted", action: "adopt"},
	{form: "carried out", action: "carry out"},
	{form: "operationalized", action: "operationalize"},
}

var metaOverrideDirectiveObjects = []string{
	"the sample", "this sample", "the samples", "these samples", "quoted sample", "quoted samples", "the example", "this example", "the examples", "these examples", "the prompt", "this prompt", "the prompts", "these prompts",
	"the instruction", "the instructions", "these instruction", "these instructions", "following instruction", "following instructions", "the configuration", "this configuration", "the configurations", "these configurations", "following configuration", "following configurations",
	"the template", "this template", "the templates", "these templates", "the override", "this override", "the overrides", "these overrides", "the mode", "the modes", "these modes", "model_instructions_file", "agents.md",
	"unrestricted mode", "system instruction", "system instructions", "developer instruction", "developer instructions", "instruction hierarchy", "instruction hierarchies",
	" it", "it ", " them", "them ", "the above", "the following",
	"样本", "示例", "提示词", "提示", "指令", "配置", "模板", "覆盖", "模式", "上述", "以下", "这些", "它",
	"无限制模式", "系统指令", "开发者指令", "指令层级",
}

var metaOverrideContinuationCues = []string{
	"then", "now", "next", "afterwards", "afterward", "subsequently", "finally", "later", "once complete", "once done",
	"go ahead", "still", "anyway", "from there", "following that",
	"然后", "现在", "接下来", "随后", "之后", "接着", "最后", "完成后", "仍然", "照样", "再",
}

var metaOverrideActiveTailModifiers = []string{
	"actually ", "in fact ", "really ", "quietly ", "directly ", "immediately ", "explicitly ", "simply ", "just ", "please ",
	"实际上", "其实", "仍然", "照样", "直接", "立即", "明确", "现在", "请",
}

var metaOverrideDirectiveGovernors = []string{
	"i need you to ", "i want you to ", "you are required to ", "you need to ", "you should ", "you must ",
	"can you ", "could you ", "would you ", "kindly ", "without delay, ", "without delay ", "must ", "should ",
	"我需要你", "我要你", "麻烦你", "麻烦", "请你", "你应该", "你必须", "需要你", "请", "必须", "务必", "要求",
}

var metaOverrideNegations = []string{
	"do not", "don't", "must not", "must never", "should not", "should never", "cannot", "can't", "will not", "would not", "could not", "may not", "need not", "ought not", "shall not", "never", "prohibit", "prohibits", "prohibiting", "forbid", "forbids", "forbidding", "keep disabled",
	"不要", "不得", "禁止", "严禁", "切勿", "不应", "不可", "保持禁用",
}

var metaOverrideReversalCues = []string{
	" but ", " instead", " rather", " however", " except", "—", "–",
	"但是", "但要", "而是", "改为", "反而", "不过", "却", "而执行", "而遵循",
}

type metaOverrideLiteralGroups [256][]string

var (
	metaOverrideDirectiveActionsByInitial = metaOverrideGroupLiteralsByInitial(metaOverrideDirectiveActions)
	metaOverrideDirectiveObjectsByInitial = metaOverrideGroupLiteralsByInitial(metaOverrideDirectiveObjects)
)

func metaOverrideDefensiveStructure(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete {
		return false
	}
	if len(spans) == 0 {
		if span, ok := metaOverrideImplicitSampleSpan(text); ok {
			spans = append(spans, span)
		}
	}
	// Defensive deduction is intentionally single-sample. Additional unbound
	// quoted spans are ambiguous: text inside them cannot supply the inert
	// directive, and a trailing quoted imperative must not be masked. Fail closed
	// instead of guessing which quote the user intended as the analysis object.
	if len(spans) > 1 {
		return false
	}
	primary, hasPrimary := metaOverridePrimarySignalSpan(text, spans)
	maskedSpans := []metaOverrideQuotedSpan(nil)
	if hasPrimary {
		maskedSpans = []metaOverrideQuotedSpan{primary}
	}
	if metaOverrideConfigurationSafetyStructure(text, maskedSpans) {
		return true
	}
	if !hasPrimary {
		return false
	}

	// Only the single signal-bearing sample span is inert.
	outside := metaOverrideMaskQuotedSpans(text, maskedSpans)
	if !containsAnyLiteral(outside, metaOverrideAnalysisTopics...) ||
		!containsAnyLiteral(outside, metaOverrideAnalysisPurposes...) ||
		metaOverrideHasDoubleNegatedInertDirective(outside) ||
		!metaOverrideHasInertDirective(outside) ||
		metaOverrideHasActiveDirective(outside) {
		return false
	}
	last := metaOverrideLastDirectiveClause(outside)
	return last != "" && metaOverrideClauseIsInert(last)
}

func metaOverrideImplicitSampleSpan(text string) (metaOverrideQuotedSpan, bool) {
	for _, marker := range []string{
		"quoted prompt injection sample:", "prompt injection sample:", "quoted jailbreak sample:", "jailbreak sample:",
		"引用的提示注入样本:", "提示注入样本:", "引用的越狱样本:", "越狱样本:",
		"引用的提示注入样本：", "提示注入样本：", "引用的越狱样本：", "越狱样本：",
	} {
		markerIndex := strings.Index(text, marker)
		if markerIndex < 0 {
			continue
		}
		start := markerIndex + len(marker)
		for start < len(text) {
			r, size := utf8.DecodeRuneInString(text[start:])
			if !unicode.IsSpace(r) {
				break
			}
			start += size
		}
		end := len(text)
		for index := start; index < len(text); {
			r, size := utf8.DecodeRuneInString(text[index:])
			switch r {
			case '.', '!', '?', ';', '。', '！', '？', '；':
				end = index
				index = len(text)
				continue
			default:
				index += size
			}
		}
		if start < end && lastMetaOverrideLiteralIndex(text[start:end]) >= 0 {
			return metaOverrideQuotedSpan{start: start, end: end}, true
		}
	}
	return metaOverrideQuotedSpan{}, false
}

func metaOverrideConfigurationSafetyStructure(text string, spans []metaOverrideQuotedSpan) bool {
	outside := metaOverrideMaskQuotedSpans(text, spans)
	safetyPurpose := containsAnyLiteral(outside,
		"write a safety policy", "write a security policy", "document a policy", "policy that prohibits",
		"configuration hardening guidance", "configuration hardening", "review why administrators must never",
		"编写安全策略", "编写安全政策", "记录禁止", "配置加固", "审查管理员为何不得",
	)
	if !safetyPurpose || metaOverrideHasDoubleNegatedInertDirective(outside) || !metaOverrideHasNegatedMetaAction(outside) {
		return false
	}
	if metaOverrideHasActiveDirective(outside) {
		return false
	}
	last := metaOverrideLastDirectiveClause(outside)
	if last == "" {
		return false
	}
	return metaOverrideClauseIsSafetyPolicy(last) || metaOverrideHasInertDirective(last)
}

func metaOverrideQuotedSpans(text string) ([]metaOverrideQuotedSpan, bool) {
	spans := make([]metaOverrideQuotedSpan, 0, 4)
	for index := 0; index < len(text); {
		if len(spans) >= maxMetaOverrideQuotedSpans {
			return spans, false
		}
		if strings.HasPrefix(text[index:], "```") {
			closeAt := strings.Index(text[index+3:], "```")
			if closeAt < 0 {
				return spans, false
			}
			end := index + 3 + closeAt + 3
			spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
			index = end
			continue
		}
		if strings.HasPrefix(text[index:], "<sample>") {
			closeAt := strings.Index(text[index+len("<sample>"):], "</sample>")
			if closeAt < 0 {
				return spans, false
			}
			end := index + len("<sample>") + closeAt + len("</sample>")
			spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
			index = end
			continue
		}
		if strings.HasPrefix(text[index:], "[sample]") {
			closeAt := strings.Index(text[index+len("[sample]"):], "[/sample]")
			if closeAt < 0 {
				return spans, false
			}
			end := index + len("[sample]") + closeAt + len("[/sample]")
			spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
			index = end
			continue
		}

		r, size := utf8.DecodeRuneInString(text[index:])
		closeDelimiter := ""
		switch r {
		case '"':
			closeDelimiter = "\""
		case '“':
			closeDelimiter = "”"
		case '「':
			closeDelimiter = "」"
		case '『':
			closeDelimiter = "』"
		case '`':
			closeDelimiter = "`"
		case '\'':
			if metaOverrideSingleQuoteOpens(text, index, size) {
				closeDelimiter = "'"
			}
		case '‘':
			closeDelimiter = "’"
		}
		if closeDelimiter == "" {
			index += size
			continue
		}
		closeAt := metaOverrideFindClosingDelimiter(text, index+size, closeDelimiter)
		if closeAt < 0 {
			if r == '\'' {
				index += size
				continue
			}
			return spans, false
		}
		end := closeAt + len(closeDelimiter)
		spans = append(spans, metaOverrideQuotedSpan{start: index, end: end})
		index = end
	}
	return spans, true
}

func metaOverrideSingleQuoteOpens(text string, index, size int) bool {
	if index > 0 {
		previous, _ := utf8.DecodeLastRuneInString(text[:index])
		if unicode.IsLetter(previous) || unicode.IsDigit(previous) {
			return false
		}
	}
	if index+size >= len(text) {
		return false
	}
	next, _ := utf8.DecodeRuneInString(text[index+size:])
	return !unicode.IsSpace(next)
}

func metaOverrideFindClosingDelimiter(text string, start int, delimiter string) int {
	for offset := start; offset < len(text); {
		found := strings.Index(text[offset:], delimiter)
		if found < 0 {
			return -1
		}
		index := offset + found
		if !metaOverrideEscapedAt(text, index) {
			if delimiter != "'" || metaOverrideSingleQuoteCloses(text, index) {
				return index
			}
		}
		offset = index + len(delimiter)
	}
	return -1
}

func metaOverrideSingleQuoteCloses(text string, index int) bool {
	if index+1 >= len(text) {
		return true
	}
	next, _ := utf8.DecodeRuneInString(text[index+1:])
	return unicode.IsSpace(next) || unicode.IsPunct(next) || unicode.IsSymbol(next)
}

func metaOverrideEscapedAt(text string, index int) bool {
	backslashes := 0
	for index > 0 && text[index-1] == '\\' {
		backslashes++
		index--
	}
	return backslashes%2 == 1
}

func metaOverridePrimarySignalSpan(text string, spans []metaOverrideQuotedSpan) (metaOverrideQuotedSpan, bool) {
	var primary metaOverrideQuotedSpan
	found := false
	for _, span := range spans {
		if span.start < 0 || span.end > len(text) || span.start >= span.end {
			continue
		}
		if lastMetaOverrideLiteralIndex(text[span.start:span.end]) >= 0 {
			if found {
				return metaOverrideQuotedSpan{}, false
			}
			primary = span
			found = true
		}
	}
	return primary, found
}

func metaOverrideMaskQuotedSpans(text string, spans []metaOverrideQuotedSpan) string {
	if len(spans) == 0 {
		return text
	}
	masked := []byte(text)
	for _, span := range spans {
		start := span.start
		end := span.end
		if start < 0 {
			start = 0
		}
		if end > len(masked) {
			end = len(masked)
		}
		for index := start; index < end; index++ {
			masked[index] = ' '
		}
	}
	return string(masked)
}

func metaOverrideHasDoubleNegatedInertDirective(text string) bool {
	if metaOverrideHasPassiveDoubleNegation(text) {
		return true
	}
	return containsAnyLiteral(text,
		"do not not execute", "do not not follow", "don't not execute", "don't not follow", "not not execute", "not not follow",
		"do not avoid executing", "do not avoid following", "do not refrain from executing", "do not refrain from following",
		"must not avoid executing", "must not avoid following", "cannot not execute", "can't not execute",
		"do not fail to execute", "do not fail to follow", "don't fail to execute", "don't fail to follow",
		"never fail to execute", "never fail to follow", "do not stop before executing", "do not stop before following",
		"不要不执行", "不要不遵循", "不得不执行", "不能不执行", "不要避免执行", "不要避免遵循", "不应避免执行",
		"不要忘记执行", "不得忘记执行", "不要停止执行", "不要只分析",
	)
}

func metaOverrideHasInertDirective(text string) bool {
	if metaOverrideHasDoubleNegatedInertDirective(text) {
		return false
	}
	if containsAnyLiteral(text,
		"keep the example inert", "keep this example inert", "keep the sample inert", "treat the example as inert",
		"treat the sample as inert", "analysis only and not execution", "for analysis only", "without operationalizing",
		"without following it", "without following the sample", "without executing it", "without executing the sample",
		"保持样本惰性", "保持示例惰性", "仅用于分析且不执行", "仅分析不执行", "不要落地执行",
	) {
		return !metaOverrideHasActiveReversal(text)
	}
	return metaOverrideHasScopedNegatedDirective(text)
}

func metaOverrideHasNegatedMetaAction(text string) bool {
	return metaOverrideHasScopedNegatedDirective(text) &&
		containsAnyLiteral(text,
			"model_instructions_file", "agents.md", "system instruction", "unrestricted mode", "prompt", "configuration", "template", "override",
			"模型指令文件", "系统指令", "无限制模式", "提示词", "配置", "模板", "覆盖",
		)
}

func metaOverrideHasActiveDirective(text string) bool {
	clauses, overflow := metaOverrideDirectiveClausesBounded(text)
	if overflow {
		// Structural analysis grants optional defensive credit. A request that
		// exceeds the fixed clause or separator budget is ambiguous, so retain the
		// active wrapper interpretation instead of materializing attacker-sized
		// clause slices or treating the uninspected suffix as inert.
		return true
	}
	if metaOverrideAdjacentClausesHaveActiveDirective(clauses) {
		return true
	}
	for _, part := range clauses {
		clause := part.text
		if clause == "" {
			continue
		}
		if metaOverrideClauseHasActiveContinuation(clause) {
			return true
		}
		if metaOverrideHasActiveReversal(clause) {
			return true
		}
		safetyPolicy := metaOverrideClauseIsSafetyPolicy(clause)
		if !safetyPolicy && metaOverrideClauseHasCommaActiveTail(clause) {
			return true
		}
		if safetyPolicy {
			if metaOverrideSafetyPolicyHasActiveDirective(clause) {
				return true
			}
			continue
		}
		if metaOverrideContainsAction(clause) && metaOverrideContainsDirectiveTarget(clause) &&
			metaOverrideAssociatedDirectiveIsActive(clause) {
			return true
		}
		if metaOverrideHasInertDirective(clause) {
			continue
		}
		trimmed := metaOverrideTrimDirectiveGovernor(clause)
		if metaOverrideStartsWithAction(trimmed) && metaOverrideContainsDirectiveTarget(trimmed) {
			return true
		}
		if containsAnyLiteral(clause, "please ", "must ", "should ", "go ahead ", "i need you to ", "i want you to ", "请", "必须", "务必", "要求") &&
			metaOverrideContainsAction(clause) && metaOverrideContainsDirectiveTarget(clause) {
			return true
		}
	}
	return false
}

type metaOverrideDirectiveClause struct {
	text           string
	boundaryBefore rune
}

func metaOverrideAdjacentClausesHaveActiveDirective(clauses []metaOverrideDirectiveClause) bool {
	for index := 0; index < len(clauses)-1; index++ {
		window := strings.TrimSpace(clauses[index].text)
		hasAction := metaOverrideContainsAction(window)
		hasTarget := metaOverrideContainsDirectiveTarget(window)
		if !hasAction && !hasTarget {
			continue
		}
		if hasAction && hasTarget && metaOverrideAssociatedDirectiveIsActive(window) {
			return true
		}
		for next := index + 1; next < len(clauses); next++ {
			if !metaOverrideSplitAssociationBoundary(clauses[next].boundaryBefore) {
				break
			}
			nextClause := strings.TrimSpace(clauses[next].text)
			if len(window)+1+len(nextClause) > maxMetaOverrideSplitAssociationBytes {
				// A directive action or object followed only by colon/newline
				// continuations remains unresolved when an attacker expands the
				// bridge. Bound work and fail closed instead of restoring credit.
				return true
			}
			window = strings.TrimSpace(window + " " + nextClause)
			hasAction = metaOverrideContainsAction(window)
			hasTarget = metaOverrideContainsDirectiveTarget(window)
			if hasAction && hasTarget && metaOverrideAssociatedDirectiveIsActive(window) {
				return true
			}
		}
	}
	return false
}

func metaOverrideAssociatedDirectiveIsActive(window string) bool {
	window = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(window)))
	if !metaOverrideContainsAction(window) || !metaOverrideContainsDirectiveTarget(window) {
		return false
	}
	if metaOverrideHasDoubleNegatedInertDirective(window) || metaOverrideHasActiveReversal(window) || hasNegationReversalFraming(window) {
		return true
	}
	occurrences, overflow := metaOverrideActionOccurrenceList(window)
	if overflow {
		return true
	}
	for _, occurrence := range occurrences {
		found, negated := ruleIntentOccurrenceNegation(window, occurrence.index)
		if found && !negated && coordinatedRuleIntentNegation(window, occurrence.index, occurrence.action, metaOverrideDirectiveActions) {
			negated = true
		}
		if found && negated {
			continue
		}
		if !metaOverrideActionOccurrenceIsDescriptive(window, occurrence.index) {
			return true
		}
	}
	return false
}

type metaOverrideActionOccurrence struct {
	index  int
	action string
}

func metaOverrideSafetyPolicyHasActiveDirective(clause string) bool {
	clause = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(clause)))
	if !metaOverrideContainsAction(clause) || !metaOverrideContainsDirectiveTarget(clause) {
		return false
	}
	if metaOverrideHasDoubleNegatedInertDirective(clause) || metaOverrideHasActiveReversal(clause) || hasNegationReversalFraming(clause) {
		return true
	}
	occurrences, overflow := metaOverrideActionOccurrenceList(clause)
	if overflow {
		return true
	}
	previousEnd := 0
	previousAction := ""
	previousNegated := false
	for _, occurrence := range occurrences {
		found, negated := ruleIntentOccurrenceNegation(clause, occurrence.index)
		if found && !negated && coordinatedRuleIntentNegation(clause, occurrence.index, occurrence.action, metaOverrideDirectiveActions) {
			negated = true
		}
		if (!found || !negated) && previousNegated &&
			!sameRuleIntentFamily(previousAction, occurrence.action) &&
			metaOverridePolicyListBridge(clause[previousEnd:occurrence.index]) {
			negated = true
		}
		if !negated {
			if metaOverrideActionOccurrenceIsDescriptive(clause, occurrence.index) {
				previousNegated = false
				continue
			}
			return true
		}
		previousEnd = occurrence.index + len(occurrence.action)
		previousAction = occurrence.action
		previousNegated = true
	}
	return false
}

func metaOverrideActionOccurrenceList(text string) ([]metaOverrideActionOccurrence, bool) {
	occurrences := make([]metaOverrideActionOccurrence, 0, 8)
	for _, action := range metaOverrideDirectiveActions {
		for searchAt := 0; searchAt <= len(text)-len(action); {
			relative := metaOverrideIndexToken(text[searchAt:], action)
			if relative < 0 {
				break
			}
			index := searchAt + relative
			if len(occurrences) >= maxRuleIntentOccurrences {
				return nil, true
			}
			occurrences = append(occurrences, metaOverrideActionOccurrence{index: index, action: action})
			searchAt = index + len(action)
		}
	}
	if metaOverrideMayContainPassiveAction(text) {
		for _, passive := range metaOverridePassiveActionForms {
			for searchAt := 0; searchAt <= len(text)-len(passive.form); {
				relative := metaOverrideIndexToken(text[searchAt:], passive.form)
				if relative < 0 {
					break
				}
				index := searchAt + relative
				if metaOverridePassiveActionIsDirective(text, index) {
					if len(occurrences) >= maxRuleIntentOccurrences {
						return nil, true
					}
					occurrences = append(occurrences, metaOverrideActionOccurrence{index: index, action: passive.action})
				}
				searchAt = index + len(passive.form)
			}
		}
	}
	for index := 1; index < len(occurrences); index++ {
		current := occurrences[index]
		position := index
		for position > 0 && occurrences[position-1].index > current.index {
			occurrences[position] = occurrences[position-1]
			position--
		}
		occurrences[position] = current
	}
	return occurrences, false
}

func metaOverridePassiveActionIsDirective(text string, actionIndex int) bool {
	prefix, truncated := metaOverridePassivePrefix(text, actionIndex)
	if prefix == "" {
		return false
	}
	if metaOverridePassiveGovernorHasDoubleNegation(prefix) {
		candidate := metaOverridePassiveDirectiveTail(prefix)
		return metaOverridePassiveBridgeHasTarget(candidate) ||
			metaOverridePassiveSubjectIsOmitted(metaOverridePassiveSubjectBridge(candidate)) ||
			(truncated && !metaOverridePassivePrefixHasBoundary(prefix))
	}
	if metaOverridePassiveGovernorIsNegated(prefix) {
		return false
	}
	for _, governor := range []string{
		"must be", "should be", "shall be", "will be", "needs to be", "need to be",
		"has to be", "have to be", "is to be", "are to be", "required to be",
		"must remain", "should remain", "shall remain", "will remain", "needs to remain", "need to remain",
		"has to remain", "have to remain", "is to remain", "are to remain", "required to remain",
		"must stay", "should stay", "shall stay", "will stay", "needs to stay", "need to stay",
		"has to stay", "have to stay", "is to stay", "are to stay", "required to stay",
	} {
		if strings.HasSuffix(prefix, governor) {
			return true
		}
	}

	candidate := metaOverridePassiveDirectiveTail(prefix)
	if strings.HasPrefix(candidate, "keep ") {
		if metaOverridePassiveBridgeHasTarget(candidate[len("keep "):]) {
			return true
		}
	}
	if strings.HasPrefix(candidate, "ensure ") {
		bridge := strings.TrimSpace(candidate[len("ensure "):])
		bridge = strings.TrimPrefix(bridge, "that ")
		for _, copula := range []string{" remains", " remain", " stays", " stay", " is", " are"} {
			if strings.HasSuffix(bridge, copula) &&
				metaOverridePassiveBridgeHasTarget(strings.TrimSpace(bridge[:len(bridge)-len(copula)])) {
				return true
			}
		}
	}
	if metaOverridePassiveBridgeHasTarget(candidate) {
		// A passive form associated with a directive target but outside the
		// fixed positive/negative grammar is unresolved. Do not let an unknown
		// governor restore defensive credit.
		return true
	}
	// Passive evidence after an unbroken truncated prefix is ambiguous: the
	// governor or directive target may sit just outside the bounded association
	// window. Defensive credit is optional, so retain the active classification
	// instead of treating truncation as proof that the participle is descriptive.
	return truncated && !metaOverridePassivePrefixHasBoundary(prefix)
}

func metaOverridePassiveGovernorIsNegated(prefix string) bool {
	if _, ok := metaOverridePassiveNegatedModalGovernorStart(prefix); ok {
		return true
	}
	candidate := metaOverridePassiveDirectiveTail(prefix)
	for _, governor := range []string{
		"do not keep ", "don't keep ", "never keep ", "must not keep ", "should not keep ",
		"do not ensure ", "don't ensure ", "never ensure ", "must not ensure ", "should not ensure ",
	} {
		if strings.HasPrefix(candidate, governor) {
			return true
		}
	}
	return false
}

func metaOverridePassiveNegatedModalGovernorStart(prefix string) (int, bool) {
	best := -1
	for _, governor := range []string{
		"is not", "are not",
		"not be", "never be",
		"must not be", "must never be", "should not be", "should never be", "shall not be", "will not be",
		"would not be", "could not be", "may not be", "need not be", "does not need to be", "do not need to be",
		"is not to be", "are not to be", "is not required to be", "are not required to be", "not required to be",
		"not remain", "never remain",
		"must not remain", "must never remain", "should not remain", "should never remain", "shall not remain", "will not remain",
		"would not remain", "could not remain", "may not remain", "need not remain", "does not need to remain", "do not need to remain",
		"is not to remain", "are not to remain", "is not required to remain", "are not required to remain", "not required to remain",
		"not stay", "never stay",
		"must not stay", "must never stay", "should not stay", "should never stay", "shall not stay", "will not stay",
		"would not stay", "could not stay", "may not stay", "need not stay", "does not need to stay", "do not need to stay",
		"is not to stay", "are not to stay", "is not required to stay", "are not required to stay", "not required to stay",
	} {
		if strings.HasSuffix(prefix, governor) {
			start := len(prefix) - len(governor)
			if best < 0 || start < best {
				best = start
			}
		}
	}
	return best, best >= 0
}

func metaOverridePassiveGovernorHasDoubleNegation(prefix string) bool {
	candidate := metaOverridePassiveSubjectBridge(metaOverridePassiveDirectiveTail(prefix))
	candidate = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(candidate)))
	if candidate == "" {
		return false
	}
	if hasNegationReversalFraming(candidate) {
		return true
	}
	negations := 0
	for _, marker := range []string{"not", "never", "cannot"} {
		for searchAt := 0; searchAt <= len(candidate)-len(marker); {
			relative := metaOverrideIndexToken(candidate[searchAt:], marker)
			if relative < 0 {
				break
			}
			negations++
			if negations >= 2 {
				return true
			}
			searchAt += relative + len(marker)
		}
	}
	return false
}

func metaOverrideHasPassiveDoubleNegation(text string) bool {
	if !metaOverrideMayContainPassiveAction(text) {
		return false
	}
	occurrences, overflow := metaOverridePassiveOccurrenceList(text)
	if overflow {
		return true
	}
	previousBoundNegated := false
	previousEnd := 0
	for _, occurrence := range occurrences {
		prefix, truncated := metaOverridePassivePrefix(text, occurrence.index)
		candidate := metaOverridePassiveDirectiveTail(prefix)
		doubleNegated := metaOverridePassiveGovernorHasDoubleNegation(prefix)
		directlyAssociated := metaOverridePassiveBridgeHasTarget(candidate)
		inherited := previousBoundNegated && previousEnd <= occurrence.index &&
			metaOverridePassiveOmittedCoordinationBridge(text[previousEnd:occurrence.index], true)
		ambiguous := truncated && !metaOverridePassivePrefixHasBoundary(prefix)
		if doubleNegated && (directlyAssociated || inherited || ambiguous) {
			return true
		}
		previousBoundNegated = metaOverridePassiveActionIsNegatedDirective(text, occurrence.index)
		previousEnd = occurrence.index + len(occurrence.form)
	}
	return false
}

func metaOverridePassivePrefix(text string, actionIndex int) (string, bool) {
	if actionIndex <= 0 || actionIndex > len(text) {
		return "", false
	}
	start := 0
	truncated := false
	if actionIndex > maxMetaOverrideSplitAssociationBytes {
		start = actionIndex - maxMetaOverrideSplitAssociationBytes
		for start < actionIndex && text[start]&0xc0 == 0x80 {
			start++
		}
		truncated = true
	}
	prefix := strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(text[start:actionIndex])))
	return prefix, truncated
}

func metaOverridePassiveActionIsNegatedDirective(text string, actionIndex int) bool {
	prefix, _ := metaOverridePassivePrefix(text, actionIndex)
	if prefix == "" || metaOverridePassiveGovernorHasDoubleNegation(prefix) || !metaOverridePassiveGovernorIsNegated(prefix) {
		return false
	}
	return metaOverridePassiveNegatedSubjectHasTarget(prefix)
}

func metaOverridePassiveNegatedSubjectHasTarget(prefix string) bool {
	candidate := metaOverridePassiveDirectiveTail(prefix)
	if candidate == "" || metaOverrideHasActiveReversal(candidate) {
		return false
	}
	for _, governor := range []string{
		"do not keep ", "don't keep ", "never keep ", "must not keep ", "should not keep ",
	} {
		if strings.HasPrefix(candidate, governor) {
			return metaOverridePassiveSubjectEndsWithTarget(candidate[len(governor):])
		}
	}
	for _, governor := range []string{
		"do not ensure ", "don't ensure ", "never ensure ", "must not ensure ", "should not ensure ",
	} {
		if !strings.HasPrefix(candidate, governor) {
			continue
		}
		subject := strings.TrimSpace(candidate[len(governor):])
		for _, copula := range []string{" remains", " remain", " stays", " stay", " is", " are"} {
			if strings.HasSuffix(subject, copula) {
				subject = strings.TrimSpace(subject[:len(subject)-len(copula)])
				break
			}
		}
		return metaOverridePassiveSubjectEndsWithTarget(subject)
	}
	governorStart, ok := metaOverridePassiveNegatedModalGovernorStart(candidate)
	if !ok {
		return false
	}
	subject := strings.TrimSpace(candidate[:governorStart])
	for _, prefix := range []string{"ensure that ", "ensure "} {
		if strings.HasPrefix(subject, prefix) {
			subject = strings.TrimSpace(subject[len(prefix):])
			break
		}
	}
	return metaOverridePassiveSubjectEndsWithTarget(subject)
}

func metaOverridePassiveSubjectEndsWithTarget(subject string) bool {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.ContainsAny(subject, ",.!?;:\n\r，。！？；：\ufffd") {
		return false
	}
	for _, target := range metaOverrideDirectiveObjects {
		target = strings.TrimSpace(target)
		if target == "" || !strings.HasSuffix(subject, target) {
			continue
		}
		start := len(subject) - len(target)
		if start == 0 || !metaOverrideASCIIWordByte(subject[start-1]) || !metaOverrideASCIIWordByte(target[0]) {
			return true
		}
	}
	return false
}

type metaOverridePassiveOccurrence struct {
	index int
	form  string
}

func metaOverridePassiveOccurrenceList(text string) ([]metaOverridePassiveOccurrence, bool) {
	occurrences := make([]metaOverridePassiveOccurrence, 0, 8)
	for _, passive := range metaOverridePassiveActionForms {
		for searchAt := 0; searchAt <= len(text)-len(passive.form); {
			relative := metaOverrideIndexToken(text[searchAt:], passive.form)
			if relative < 0 {
				break
			}
			index := searchAt + relative
			if len(occurrences) >= maxRuleIntentOccurrences {
				return nil, true
			}
			occurrences = append(occurrences, metaOverridePassiveOccurrence{index: index, form: passive.form})
			searchAt = index + len(passive.form)
		}
	}
	for index := 1; index < len(occurrences); index++ {
		current := occurrences[index]
		position := index
		for position > 0 && occurrences[position-1].index > current.index {
			occurrences[position] = occurrences[position-1]
			position--
		}
		occurrences[position] = current
	}
	return occurrences, false
}

func metaOverridePassiveOmittedCoordinationBridge(bridge string, wantDoubleNegation bool) bool {
	governor, ok := metaOverridePassiveOmittedCoordinationGovernor(bridge)
	if !ok {
		return false
	}
	if wantDoubleNegation {
		return metaOverridePassiveGovernorHasDoubleNegation(governor)
	}
	return metaOverridePassiveGovernorIsNegated(governor) && !metaOverridePassiveGovernorHasDoubleNegation(governor)
}

func metaOverridePassiveOmittedCoordinationGovernor(bridge string) (string, bool) {
	bridge = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(bridge)))
	connector := ""
	for _, candidate := range []string{"as well as ", "and ", "but ", "or ", "并且", "以及", "和", "与", "或"} {
		if strings.HasPrefix(bridge, candidate) && len(candidate) > len(connector) {
			connector = candidate
		}
	}
	if connector == "" {
		return "", false
	}
	governor := strings.TrimSpace(bridge[len(connector):])
	if !metaOverridePassiveSubjectIsOmitted(governor) {
		return "", false
	}
	return governor, true
}

func metaOverrideHasNegatedPassiveDirective(text string) bool {
	if !metaOverrideMayContainPassiveAction(text) {
		return false
	}
	occurrences, overflow := metaOverridePassiveOccurrenceList(text)
	if overflow {
		return false
	}
	foundNegated := false
	previousBoundNegated := false
	previousEnd := 0
	for _, occurrence := range occurrences {
		prefix, truncated := metaOverridePassivePrefix(text, occurrence.index)
		candidate := metaOverridePassiveDirectiveTail(prefix)
		directNegated := metaOverridePassiveActionIsNegatedDirective(text, occurrence.index)
		inheritedNegated := previousBoundNegated && previousEnd <= occurrence.index &&
			metaOverridePassiveOmittedCoordinationBridge(text[previousEnd:occurrence.index], false)
		if directNegated || inheritedNegated {
			foundNegated = true
			previousBoundNegated = true
			previousEnd = occurrence.index + len(occurrence.form)
			continue
		}
		associated := metaOverridePassiveBridgeHasTarget(candidate)
		ambiguous := truncated && !metaOverridePassivePrefixHasBoundary(prefix)
		omittedGovernor, omittedAfterBound := metaOverridePassiveOmittedCoordinationGovernor(text[previousEnd:occurrence.index])
		omittedAfterBound = previousBoundNegated && previousEnd <= occurrence.index && omittedAfterBound
		if omittedAfterBound && !metaOverridePassiveGovernorIsNegated(omittedGovernor) &&
			!metaOverridePassiveGovernorHasDoubleNegation(omittedGovernor) {
			// A prior prohibition cannot authorize a coordinated bare positive
			// passive continuation ("must not be applied and be followed").
			// Defensive credit is optional, so unresolved positive coordination
			// fails active even inside descriptive safety-policy framing.
			return false
		}
		if associated || ambiguous || omittedAfterBound {
			if !metaOverrideActionOccurrenceIsDescriptive(text, occurrence.index) {
				return false
			}
		}
		previousBoundNegated = false
		previousEnd = occurrence.index + len(occurrence.form)
	}
	return foundNegated
}

func metaOverridePassiveDirectiveTail(prefix string) string {
	boundaryEnd := 0
	for index, r := range prefix {
		if metaOverrideDirectiveBoundary(r) || r == ',' || r == '，' {
			_, width := utf8.DecodeRuneInString(prefix[index:])
			boundaryEnd = index + width
		}
	}
	return metaOverrideTrimDirectiveGovernor(strings.TrimSpace(prefix[boundaryEnd:]))
}

func metaOverridePassivePrefixHasBoundary(prefix string) bool {
	for _, r := range prefix {
		if metaOverrideDirectiveBoundary(r) || r == ',' || r == '，' {
			return true
		}
	}
	return false
}

func metaOverridePassiveBridgeHasTarget(bridge string) bool {
	bridge = strings.TrimSpace(bridge)
	if bridge == "" || strings.ContainsAny(bridge, ",.!?;:\n\r，。！？；：\ufffd") ||
		containsAnyLiteral(bridge, metaOverrideReversalCues...) {
		return false
	}
	subjectBridge := metaOverridePassiveSubjectBridge(bridge)
	return subjectBridge != "" && metaOverrideContainsDirectiveTarget(subjectBridge)
}

func metaOverridePassiveSubjectBridge(bridge string) string {
	start, _ := metaOverridePassiveSubjectBridgeInfo(bridge)
	return strings.TrimSpace(bridge[start:])
}

func metaOverridePassiveSubjectBridgeStart(bridge string) int {
	start, _ := metaOverridePassiveSubjectBridgeInfo(bridge)
	return start
}

func metaOverridePassiveSubjectBridgeInfo(bridge string) (int, string) {
	lastConnectorEnd := 0
	lastConnector := ""
	for _, connector := range []string{
		" as well as ", " while ", " whereas ", " although ", " because ", " however ", " but ",
		" and ", " or ", " that ", " when ", " where ", " if ", " then ",
		" 并且 ", " 以及 ", " 和 ", " 与 ", " 或 ", " 但是 ", " 然而 ", " 当 ", " 如果 ",
	} {
		if index := strings.LastIndex(bridge, connector); index >= 0 && index+len(connector) > lastConnectorEnd {
			lastConnectorEnd = index + len(connector)
			lastConnector = connector
		}
	}
	return lastConnectorEnd, lastConnector
}

func metaOverridePassiveSubjectIsOmitted(subject string) bool {
	subject = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(subject)))
	if subject == "be" || subject == "remain" || subject == "stay" {
		return true
	}
	return hasAnyPrefix(subject,
		"be ", "remain ", "stay ",
		"must ", "should ", "shall ", "will ", "would ", "could ", "may ",
		"need ", "needs ", "has ", "have ", "is ", "are ", "required ",
		"do ", "never ", "not ", "keep ", "ensure ",
	)
}

func metaOverridePassiveOmittedSubjectUsesPriorTarget(bridge string) bool {
	start, connector := metaOverridePassiveSubjectBridgeInfo(bridge)
	if start <= 0 || start >= len(bridge) {
		return false
	}
	switch connector {
	case " as well as ", " and ", " or ", " 并且 ", " 以及 ", " 和 ", " 与 ", " 或 ":
	default:
		return false
	}
	return metaOverrideContainsDirectiveTarget(bridge[:start]) &&
		metaOverridePassiveSubjectIsOmitted(bridge[start:])
}

func metaOverrideMayContainPassiveAction(text string) bool {
	return strings.Contains(text, "ed") || strings.Contains(text, "overridden")
}

func metaOverridePolicyListBridge(bridge string) bool {
	bridge = strings.ToLower(strings.TrimSpace(bridge))
	if bridge == "" || strings.ContainsAny(bridge, ".!?;:\n\r。！？；：\ufffd") ||
		containsAnyLiteral(bridge, " but ", " however ", " instead ", " rather ", " although ", " except ", "但是", "然而", "而是", "不过", "除非") {
		return false
	}
	for _, connector := range []string{
		" as well as", " and", " nor", " or", ",", "，",
		"并且", "以及", "和", "与", "及", "并", "且", "或",
	} {
		if strings.HasSuffix(bridge, connector) {
			return true
		}
	}
	return false
}

func metaOverrideActionOccurrenceIsDescriptive(window string, actionIndex int) bool {
	if actionIndex <= 0 || actionIndex > len(window) {
		return false
	}
	start := 0
	truncated := false
	if actionIndex > maxMetaOverrideSplitAssociationBytes {
		start = actionIndex - maxMetaOverrideSplitAssociationBytes
		for start < actionIndex && window[start]&0xc0 == 0x80 {
			start++
		}
		truncated = true
	}
	prefix := window[start:actionIndex]
	boundaryEnd := 0
	for index, r := range prefix {
		switch r {
		case '.', '!', '?', ';', ':', ',', '\n', '\r', '。', '！', '？', '；', '：', '，', '\ufffd':
			_, width := utf8.DecodeRuneInString(prefix[index:])
			boundaryEnd = index + width
		}
	}
	if truncated && boundaryEnd == 0 {
		return false
	}
	prefix = strings.TrimSpace(prefix[boundaryEnd:])
	return hasExplanatoryFraming(prefix) && containsAnyLiteral(prefix,
		"why attackers", "how attackers", "attackers ", "why an attacker", "how an attacker", "an attacker ",
		"why the malware", "how the malware", "the malware ", "why the sample", "how the sample", "the sample ",
		"为何攻击者", "攻击者为何", "攻击者如何", "恶意软件为何", "恶意软件如何", "样本为何", "样本如何",
	)
}

func metaOverrideHasScopedNegatedDirective(text string) bool {
	if metaOverrideHasNegatedPassiveDirective(text) {
		return true
	}
	for _, negation := range metaOverrideNegations {
		searchAt := 0
		for searchAt < len(text) {
			index := metaOverrideIndexToken(text[searchAt:], negation)
			if index < 0 {
				break
			}
			index += searchAt
			tail := text[index+len(negation):]
			if len(tail) > 192 {
				tail = validUTF8Prefix(tail, 192)
			}
			if boundary := metaOverrideFirstDirectiveBoundary(tail); boundary >= 0 {
				tail = tail[:boundary]
			}
			if !metaOverrideHasActiveReversal(tail) &&
				metaOverrideNegationDirectlyControlsAction(negation, tail) &&
				metaOverrideContainsDirectiveTarget(tail) {
				return true
			}
			searchAt = index + len(negation)
		}
	}
	return false
}

func metaOverrideNegationDirectlyControlsAction(negation, tail string) bool {
	tail = strings.TrimLeft(strings.TrimSpace(tail), ",，:：-—– ")
	if tail == "" {
		return false
	}
	for _, prefix := range []string{"ever ", "directly ", "immediately ", "explicitly ", "再", "直接", "立即", "擅自"} {
		if strings.HasPrefix(tail, prefix) {
			tail = strings.TrimSpace(tail[len(prefix):])
			break
		}
	}
	if metaOverrideStartsWithAction(tail) {
		return true
	}
	if strings.HasPrefix(negation, "prohibit") || strings.HasPrefix(negation, "forbid") {
		for _, prefix := range []string{"appending", "replacing", "overriding", "installing", "enabling", "deploying", "applying", "executing", "following"} {
			if strings.HasPrefix(tail, prefix) {
				return true
			}
		}
	}
	if containsAnyLiteral(negation, "不要", "不得", "禁止", "严禁", "切勿", "不应", "不可") {
		for _, marker := range []string{"把", "将"} {
			if !strings.HasPrefix(tail, marker) {
				continue
			}
			actionIndex := metaOverrideFirstActionIndex(tail)
			if actionIndex > 0 && actionIndex <= 48 {
				return true
			}
		}
	}
	return false
}

func metaOverrideFirstActionIndex(text string) int {
	first := -1
	for _, action := range metaOverrideDirectiveActions {
		if index := metaOverrideIndexToken(text, action); index >= 0 && (first < 0 || index < first) {
			first = index
		}
	}
	return first
}

func metaOverrideFirstDirectiveBoundary(text string) int {
	for index, r := range text {
		switch r {
		case '.', '!', '?', ';', ':', '\n', '\r', '。', '！', '？', '；', '：':
			return index
		}
	}
	return -1
}

func metaOverrideHasActiveReversal(text string) bool {
	lastAction := metaOverrideLastActionIndex(text)
	lastTarget := metaOverrideLastDirectiveTargetIndex(text)
	searchEnd := min(lastAction, lastTarget)
	if searchEnd <= 0 {
		return false
	}
	for _, cue := range metaOverrideReversalCues {
		// The last action and object summarize every possible suffix. A cue
		// can only activate a tail when it ends before both signals.
		if strings.Index(text[:searchEnd], cue) >= 0 {
			return true
		}
	}
	return false
}

func metaOverrideClauseHasCommaActiveTail(clause string) bool {
	clause = strings.TrimSpace(clause)
	lastTarget := metaOverrideLastDirectiveTargetIndex(clause)
	if lastTarget < 0 {
		return false
	}
	for searchAt := 0; searchAt < len(clause); {
		relative := strings.IndexAny(clause[searchAt:], ",，")
		if relative < 0 {
			break
		}
		commaIndex := searchAt + relative
		_, commaSize := utf8.DecodeRuneInString(clause[commaIndex:])
		tailStart := commaIndex + commaSize
		tail := metaOverrideTrimDirectiveCue(clause[tailStart:])
		trimmedStart := len(clause) - len(tail)
		if metaOverrideStartsWithAction(tail) && lastTarget >= trimmedStart {
			return true
		}
		// All commas and directive punctuation skipped by the cue trimmer
		// resolve to the same tail. Jump over that run so each input byte is
		// examined only a bounded number of times.
		if trimmedStart > tailStart {
			searchAt = trimmedStart
		} else {
			searchAt = tailStart
		}
	}
	return false
}

func metaOverrideClauseHasActiveContinuation(clause string) bool {
	lastAction := metaOverrideLastActionIndex(clause)
	lastTarget := metaOverrideLastDirectiveTargetIndex(clause)
	searchEnd := min(lastAction, lastTarget)
	if searchEnd <= 0 {
		return false
	}
	for _, cue := range metaOverrideContinuationCues {
		if metaOverrideIndexToken(clause[:searchEnd], cue) >= 0 {
			return true
		}
	}
	return false
}

func metaOverrideLastActionIndex(text string) int {
	last := metaOverrideLastTokenIndex(text, &metaOverrideDirectiveActionsByInitial)
	if metaOverrideMayContainPassiveAction(text) {
		for _, passive := range metaOverridePassiveActionForms {
			for searchAt := 0; searchAt <= len(text)-len(passive.form); {
				relative := metaOverrideIndexToken(text[searchAt:], passive.form)
				if relative < 0 {
					break
				}
				index := searchAt + relative
				if metaOverridePassiveActionIsDirective(text, index) && index > last {
					last = index
				}
				searchAt = index + len(passive.form)
			}
		}
	}
	return last
}

func metaOverrideLastDirectiveTargetIndex(text string) int {
	return metaOverrideLastLiteralIndex(text, &metaOverrideDirectiveObjectsByInitial)
}

func metaOverrideClauseIsInert(clause string) bool {
	if clause == "" || metaOverrideHasDoubleNegatedInertDirective(clause) || metaOverrideHasActiveDirective(clause) {
		return false
	}
	return metaOverrideHasInertDirective(clause) ||
		(containsAnyLiteral(clause, metaOverrideAnalysisPurposes...) &&
			(containsAnyLiteral(clause, metaOverrideAnalysisTopics...) || metaOverrideContainsDirectiveObject(clause) ||
				containsAnyLiteral(clause, "controls", "safeguards", "unsafe", "risk", "防护", "风险", "不安全")))
}

func metaOverrideClauseIsSafetyPolicy(clause string) bool {
	return containsAnyLiteral(clause,
		"safety policy", "security policy", "policy that prohibits", "configuration hardening", "administrators must never",
		"安全策略", "安全政策", "记录禁止", "配置加固", "管理员不得",
	) && metaOverrideHasNegatedMetaAction(clause)
}

func metaOverrideDirectiveClauses(text string) []string {
	parts := metaOverrideDirectiveClausesWithBoundaries(text)
	clauses := make([]string, 0, len(parts))
	for _, part := range parts {
		clauses = append(clauses, part.text)
	}
	return clauses
}

func metaOverrideDirectiveClausesWithBoundaries(text string) []metaOverrideDirectiveClause {
	clauses, _ := metaOverrideDirectiveClausesBounded(text)
	return clauses
}

func metaOverrideDirectiveClausesBounded(text string) ([]metaOverrideDirectiveClause, bool) {
	clauses := make([]metaOverrideDirectiveClause, 0, 4)
	start := 0
	boundaryBefore := rune(0)
	boundaries := 0
	for index, r := range text {
		if !metaOverrideDirectiveBoundary(r) {
			continue
		}
		boundaries++
		if boundaries > maxMetaOverrideDirectiveBoundaries {
			return clauses, true
		}
		if clause := strings.TrimSpace(text[start:index]); clause != "" {
			if len(clauses) >= maxMetaOverrideDirectiveClauses {
				return clauses, true
			}
			clauses = append(clauses, metaOverrideDirectiveClause{text: clause, boundaryBefore: boundaryBefore})
			boundaryBefore = r
		} else if boundaryBefore == 0 || !metaOverrideSplitAssociationBoundary(r) {
			// Consecutive separators describe one boundary before the next
			// non-empty clause. Preserve any stronger sentence boundary so a
			// following newline cannot turn ".\n" or ";\n" into an allowed
			// split-association bridge. Colon/newline-only runs remain linked.
			boundaryBefore = r
		}
		_, width := utf8.DecodeRuneInString(text[index:])
		start = index + width
	}
	if clause := strings.TrimSpace(text[start:]); clause != "" {
		if len(clauses) >= maxMetaOverrideDirectiveClauses {
			return clauses, true
		}
		clauses = append(clauses, metaOverrideDirectiveClause{text: clause, boundaryBefore: boundaryBefore})
	}
	return clauses, false
}

func metaOverrideDirectiveBoundary(r rune) bool {
	switch r {
	case '.', '!', '?', ';', ':', '\n', '\r', utf8.RuneError, '。', '！', '？', '；', '：':
		return true
	default:
		return false
	}
}

func metaOverrideSplitAssociationBoundary(r rune) bool {
	switch r {
	case ':', '\n', '\r', utf8.RuneError, '：':
		return true
	default:
		return false
	}
}

func metaOverrideLastDirectiveClause(text string) string {
	last := ""
	start := 0
	boundaries := 0
	for index, r := range text {
		if !metaOverrideDirectiveBoundary(r) {
			continue
		}
		boundaries++
		if boundaries > maxMetaOverrideDirectiveBoundaries {
			return ""
		}
		if clause := strings.TrimSpace(text[start:index]); clause != "" {
			last = clause
		}
		_, width := utf8.DecodeRuneInString(text[index:])
		start = index + width
	}
	if clause := strings.TrimSpace(text[start:]); clause != "" {
		last = clause
	}
	return last
}

func metaOverrideTrimDirectiveCue(text string) string {
	text = strings.TrimLeft(strings.TrimSpace(text), "-*#>,， \"'`“”‘’「」『』")
	for pass := 0; pass < 4; pass++ {
		trimmed := text
		for _, cue := range metaOverrideContinuationCues {
			if strings.HasPrefix(trimmed, cue) {
				trimmed = strings.TrimLeft(strings.TrimSpace(trimmed[len(cue):]), ",，:：- ")
				break
			}
		}
		if trimmed == text {
			for _, modifier := range metaOverrideActiveTailModifiers {
				if strings.HasPrefix(trimmed, modifier) {
					trimmed = strings.TrimLeft(strings.TrimSpace(trimmed[len(modifier):]), ",，:：- ")
					break
				}
			}
		}
		if trimmed == text {
			break
		}
		text = trimmed
	}
	return text
}

func metaOverrideTrimDirectiveGovernor(text string) string {
	text = metaOverrideTrimDirectiveCue(text)
	for pass := 0; pass < 2; pass++ {
		trimmed := text
		for _, governor := range metaOverrideDirectiveGovernors {
			if strings.HasPrefix(trimmed, governor) {
				trimmed = strings.TrimLeft(strings.TrimSpace(trimmed[len(governor):]), ",，:：- ")
				break
			}
		}
		if trimmed == text {
			break
		}
		text = metaOverrideTrimDirectiveCue(trimmed)
	}
	return text
}

func metaOverrideContainsAction(text string) bool {
	for _, action := range metaOverrideDirectiveActions {
		if metaOverrideIndexToken(text, action) >= 0 {
			return true
		}
	}
	if metaOverrideMayContainPassiveAction(text) {
		for _, passive := range metaOverridePassiveActionForms {
			for searchAt := 0; searchAt <= len(text)-len(passive.form); {
				relative := metaOverrideIndexToken(text[searchAt:], passive.form)
				if relative < 0 {
					break
				}
				index := searchAt + relative
				if metaOverridePassiveActionIsDirective(text, index) {
					return true
				}
				searchAt = index + len(passive.form)
			}
		}
	}
	return false
}

func metaOverrideStartsWithAction(text string) bool {
	for _, action := range metaOverrideDirectiveActions {
		if strings.HasPrefix(text, action) {
			end := len(action)
			if end == len(text) || !metaOverrideASCIIWordByte(text[end]) || !metaOverrideASCIIWordByte(action[0]) {
				return true
			}
		}
	}
	return false
}

func metaOverrideContainsDirectiveObject(text string) bool {
	return containsAnyLiteral(text, metaOverrideDirectiveObjects...)
}

func metaOverrideContainsDirectiveTarget(text string) bool {
	return metaOverrideContainsDirectiveObject(text)
}

func metaOverrideIndexToken(text, token string) int {
	searchAt := 0
	for searchAt <= len(text)-len(token) {
		found := strings.Index(text[searchAt:], token)
		if found < 0 {
			return -1
		}
		index := searchAt + found
		beforeOK := index == 0 || !metaOverrideASCIIWordByte(text[index-1]) || !metaOverrideASCIIWordByte(token[0])
		end := index + len(token)
		afterOK := end == len(text) || !metaOverrideASCIIWordByte(text[end]) || !metaOverrideASCIIWordByte(token[len(token)-1])
		if beforeOK && afterOK {
			return index
		}
		searchAt = index + 1
	}
	return -1
}

func metaOverrideGroupLiteralsByInitial(values []string) metaOverrideLiteralGroups {
	var grouped metaOverrideLiteralGroups
	for _, value := range values {
		if value == "" {
			continue
		}
		grouped[value[0]] = append(grouped[value[0]], value)
	}
	return grouped
}

func metaOverrideLastTokenIndex(text string, grouped *metaOverrideLiteralGroups) int {
	for index := len(text) - 1; index >= 0; index-- {
		for _, token := range grouped[text[index]] {
			end := index + len(token)
			if end > len(text) || text[index:end] != token {
				continue
			}
			beforeOK := index == 0 || !metaOverrideASCIIWordByte(text[index-1]) || !metaOverrideASCIIWordByte(token[0])
			afterOK := end == len(text) || !metaOverrideASCIIWordByte(text[end]) || !metaOverrideASCIIWordByte(token[len(token)-1])
			if beforeOK && afterOK {
				return index
			}
		}
	}
	return -1
}

func metaOverrideLastLiteralIndex(text string, grouped *metaOverrideLiteralGroups) int {
	for index := len(text) - 1; index >= 0; index-- {
		for _, literal := range grouped[text[index]] {
			end := index + len(literal)
			if end <= len(text) && text[index:end] == literal {
				return index
			}
		}
	}
	return -1
}

func metaOverrideASCIIWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func metaOverrideQuoteBoundaryOpen(text string) bool {
	_, complete := metaOverrideQuotedSpans(strings.ToLower(text))
	return !complete
}

func metaOverrideMayContainQuotedPrefix(text string) bool {
	return strings.ContainsAny(text, "\"'`“‘「『<[：:")
}

func metaOverridePotentialQuotedPrefix(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	return text != "" &&
		containsAnyLiteral(text, metaOverrideAnalysisTopics...) &&
		containsAnyLiteral(text, metaOverrideAnalysisPurposes...) &&
		(metaOverrideQuoteBoundaryOpen(text) || metaOverrideEndsWithSampleMarker(text))
}

func metaOverrideEndsWithSampleMarker(text string) bool {
	for _, marker := range []string{
		"prompt injection sample:", "jailbreak sample:", "提示注入样本:", "越狱样本:", "提示注入样本：", "越狱样本：",
	} {
		if strings.HasSuffix(text, marker) {
			return true
		}
	}
	return false
}
