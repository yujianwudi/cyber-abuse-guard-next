package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	errPlanBudget            = errors.New("extract: streaming plan budget exhausted")
	errClassificationLimited = errors.New("extract: classification chunk budget exhausted")
)

const (
	maxShadowKeyBytes     = 128
	maxShadowValueBytes   = 256
	shadowUnknownKey      = "_"
	shadowUnknownValue    = "_"
	spanMarkerPrefix      = "~c"
	spanMarkerSuffix      = "~"
	derivedFieldIDFlag    = uint64(1) << 63
	encodingSampleBytes   = 64 << 10
	base64ProbeBlock      = 4 << 10
	base64ProbeDecoded    = base64ProbeBlock / 4 * 3
	minDenseEncodings     = 16
	minEncodingDensity    = 10
	minEncodedTextRun     = 32
	minEncodedTextDensity = 90
)

type plannedText struct {
	id                uint64
	rawStart          int
	rawEnd            int
	owned             string
	role              Role
	provenance        SegmentProvenance
	userAttribution   UserAttribution
	encryptedContent  bool
	skip              bool
	scalarCarrier     bool
	messageOwner      uint64
	conversationIndex int
	turnIndex         int
	isCurrentTurn     bool
	scopeID           uint64
	contentKind       ContentKind
	fieldPathHash     string
	roleEligible      bool
	semanticOrdinal   int
	fallbackText      bool
	exactKey          string
}

type planContext struct {
	role                Role
	provenance          SegmentProvenance
	userAttribution     UserAttribution
	historyTrusted      bool
	directUserInput     bool
	messageOwner        uint64
	conversationIndex   int
	scopeID             uint64
	contentKind         ContentKind
	fieldPath           string
	independentScope    bool
	independentItems    bool
	roleEligible        bool
	roleContent         bool
	roleTextValue       bool
	historyArray        bool
	messageObject       bool
	directMessageMember bool
	atRoot              bool
	fallbackText        bool
	unknownRoot         bool
	metadata            bool
	exactKey            string
}

type valueSummary struct {
	text    string
	isText  bool
	bounded bool
}

type shadowPlanner struct {
	body        []byte
	limits      Limits
	source      SourceProfile
	position    int
	shadow      []byte
	spans       []plannedText
	tokens      int
	nodes       int
	reason      IncompleteReason
	nextOwner   uint64
	roleAware   bool
	missingRole bool
	unsafeRole  bool
	trustRoles  bool
}

// ScanProfiledRequest performs complete envelope validation, builds a bounded
// structural span plan, and replays only model-visible text through sink.
func ScanProfiledRequest(body []byte, headers http.Header, profile RequestProfile, limits Limits, sink ChunkSink) (Result, error) {
	initial := contextNone
	if profile.Source == SourceProfileInteractions || profile.Source == SourceProfileCodexAlphaSearch {
		initial = contextText
	}
	return scanRequest(body, headers, profile, limits, initial, sink)
}

// ScanUntrustedRequest is the streaming entry point for an unknown provider
// schema. Every non-metadata string that is not proven opaque media is treated
// as untrusted user text.
func ScanUntrustedRequest(body []byte, headers http.Header, limits Limits, sink ChunkSink) (Result, error) {
	return scanRequest(body, headers, RequestProfile{Source: SourceProfileUnknown}, limits, contextText, sink)
}

// ScanRequest uses the conservative unknown source profile.
func ScanRequest(body []byte, headers http.Header, limits Limits, sink ChunkSink) (Result, error) {
	return ScanUntrustedRequest(body, headers, limits, sink)
}

func scanRequest(body []byte, headers http.Header, profile RequestProfile, limits Limits, initial contextKind, sink ChunkSink) (Result, error) {
	normalized, err := limits.normalized()
	if err != nil {
		return Result{}, err
	}
	result := newRequestResult(body, normalized)
	if sink == nil {
		sink = discardChunkSink{}
	}
	if len(body) > normalized.MaxRawBytes {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteRawBodyLimit)
		result.finish()
		sink.Abort()
		return result, nil
	}
	if unsupportedContentEncoding(headers) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedContentEncoding)
		result.finish()
		sink.Abort()
		return result, nil
	}

	contentTypes := headerValues(headers, "Content-Type")
	if len(contentTypes) > 1 {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}
	if len(contentTypes) == 0 || strings.TrimSpace(contentTypes[0]) == "" {
		if obviousJSON(body) {
			return scanRequestJSON(body, normalized, initial, initial == contextNone, profile.Source, sink)
		}
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}

	mediaType, params, parseErr := parseRequestMediaType(contentTypes[0])
	if parseErr != nil {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}
	switch {
	case isJSONMediaType(mediaType):
		if !supportedJSONCharset(params) {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteUnsupportedMediaType)
			result.finish()
			sink.Abort()
			return result, nil
		}
		return scanRequestJSON(body, normalized, initial, initial == contextNone, profile.Source, sink)
	case mediaType == "multipart/form-data":
		if profile.Source != SourceProfileUnknown && obviousJSON(body) {
			return scanTransformedMultipartJSON(body, profile, normalized, sink)
		}
		boundary, ok := params["boundary"]
		if !ok || boundary == "" {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteMultipartParseError)
			result.finish()
			sink.Abort()
			return result, nil
		}
		if len(boundary) > normalized.MaxMultipartBoundaryBytes {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteMultipartBoundaryLimit)
			result.finish()
			sink.Abort()
			return result, nil
		}
		return scanMultipartRequest(body, boundary, profile, normalized, sink)
	default:
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		sink.Abort()
		return result, nil
	}
}

func parseRequestMediaType(value string) (string, map[string]string, error) {
	// Kept in a small helper so stream_scan.go does not duplicate request.go's
	// dispatch semantics at each call site.
	mediaType, params, err := mime.ParseMediaType(value)
	return strings.ToLower(strings.TrimSpace(mediaType)), params, err
}

func scanRequestJSON(body []byte, limits Limits, initial contextKind, trustRoles bool, source SourceProfile, sink ChunkSink) (Result, error) {
	result := newRequestResult(body, limits)
	if !obviousJSON(body) || !utf8.Valid(body) || !json.Valid(body) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.finish()
		sink.Abort()
		return result, nil
	}
	result.Envelope = EnvelopeComplete

	planner := shadowPlanner{
		body:       body,
		limits:     limits,
		source:     source,
		shadow:     make([]byte, 0, minInt(len(body), 64<<10)),
		spans:      make([]plannedText, 0, minInt(limits.MaxTextParts, 64)),
		trustRoles: trustRoles,
	}
	root := planContext{
		role:              RoleUser,
		provenance:        ProvenanceContent,
		userAttribution:   UserAttributionUntrusted,
		conversationIndex: -1,
		contentKind:       ContentKindUnknown,
		fieldPath:         rootFieldPath,
		atRoot:            true,
	}
	if _, err := planner.parseValue(root, "", 0); err != nil {
		if !errors.Is(err, errPlanBudget) {
			result.Envelope = EnvelopeIncomplete
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteParseError)
			result.ParseError = ErrInvalidJSON.Error()
		} else {
			result.TextCoverage = TextCoverageExhausted
			result.addIncomplete(planner.reason)
		}
		result.finish()
		sink.Abort()
		return result, nil
	}
	planner.skipWhitespace()
	if planner.position != len(body) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.finish()
		sink.Abort()
		return result, nil
	}

	shadowLimits := limits
	shadowLimits.MaxScanBytes = HardMaxScanBytes
	shadowLimits.MaxRawBytes = HardMaxRawBytes
	shadowLimits.MaxTextPartBytes = HardMaxTextPartBytes
	shadowResult := extractRequestJSON(planner.shadow, shadowLimits, initial, false)
	result.OpaqueMedia = shadowResult.OpaqueMedia
	result.OpaqueMediaKinds = append(result.OpaqueMediaKinds, shadowResult.OpaqueMediaKinds...)
	if !shadowResult.IsComplete() {
		for _, reason := range shadowResult.IncompleteReasons {
			result.addIncomplete(reason)
		}
		result.TextCoverage = coverageForReasons(result.IncompleteReasons)
		result.finish()
		sink.Abort()
		return result, nil
	}

	result.RoleAware = planner.roleAware && !planner.missingRole && !planner.unsafeRole
	if planner.unsafeRole {
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteRoleAttribution)
		result.finish()
		sink.Abort()
		return result, nil
	}
	if !result.RoleAware {
		for index := range planner.spans {
			planner.spans[index].role = RoleUnknown
			planner.spans[index].userAttribution = UserAttributionUntrusted
		}
	}
	selected, owned := planner.selected(shadowResult.Parts)
	if !result.RoleAware {
		for index := range owned {
			owned[index].role = RoleUnknown
			owned[index].userAttribution = UserAttributionUntrusted
		}
	}
	finalizeConversationMetadata(selected)
	result.LogicalTextParts = len(selected) + len(owned)
	if result.LogicalTextParts > limits.MaxTextParts {
		result.TextCoverage = TextCoverageExhausted
		result.addIncomplete(IncompleteTextPartLimit)
		result.finish()
		sink.Abort()
		return result, nil
	}

	stream := streamEmitter{limits: limits, sink: sink, result: &result}
	for _, span := range selected {
		if err := stream.emitSpan(body[span.rawStart:span.rawEnd], span); err != nil {
			return Result{}, err
		}
		if stream.aborted {
			result.finish()
			return result, nil
		}
	}
	for index := range owned {
		owned[index].id = uint64(len(planner.spans) + index + 1)
		if err := stream.emitOwned(owned[index]); err != nil {
			return Result{}, err
		}
		if stream.aborted {
			result.finish()
			return result, nil
		}
	}
	result.TextCoverage = TextCoverageComplete
	result.finish()
	return result, nil
}

func coverageForReasons(reasons []IncompleteReason) TextCoverage {
	for _, reason := range reasons {
		switch reason {
		case IncompleteParseError, IncompleteMultipartParseError,
			IncompleteMultipartUnknownField, IncompleteMultipartTextFieldTypeMismatch,
			IncompleteToolSchema, IncompleteRoleAttribution, IncompleteUnsupportedMediaType,
			IncompleteUnsupportedContentEncoding, IncompleteRawBodyLimit,
			IncompleteRPCBodyLimit:
			return TextCoverageUnavailable
		}
	}
	return TextCoverageExhausted
}

func (p *shadowPlanner) parseValue(ctx planContext, key string, depth int) (valueSummary, error) {
	p.skipWhitespace()
	if p.position >= len(p.body) {
		return valueSummary{}, errors.New("unexpected end of JSON")
	}
	if err := p.bump(true); err != nil {
		return valueSummary{}, err
	}
	if ctx.independentScope {
		p.nextOwner++
		ctx.scopeID = p.nextOwner
		ctx.independentScope = false
	}
	if ctx.unknownRoot && (p.body[p.position] == '{' || p.body[p.position] == '[') {
		ctx.fallbackText = true
		ctx.unknownRoot = false
	}
	if ctx.roleTextValue && p.body[p.position] != '"' {
		// A closed content-block text field proves the enclosing role only for a
		// direct JSON string. Container and scalar mismatches remain inspectable,
		// but descendants must not regain role eligibility through nested text or
		// content keys.
		ctx.roleTextValue = false
		ctx.roleEligible = false
		ctx.roleContent = false
		ctx.role = RoleUser
		ctx.userAttribution = UserAttributionUntrusted
	}
	switch p.body[p.position] {
	case '{':
		return p.parseObject(ctx, depth+1)
	case '[':
		return p.parseArray(ctx, depth+1)
	case '"':
		start, end, err := p.takeString()
		if err != nil {
			return valueSummary{}, err
		}
		return p.appendStringValue(ctx, key, start, end), nil
	case 't':
		p.position += len("true")
		p.shadow = append(p.shadow, "true"...)
	case 'f':
		p.position += len("false")
		p.shadow = append(p.shadow, "false"...)
	case 'n':
		p.position += len("null")
		p.shadow = append(p.shadow, "null"...)
	default:
		p.takeNumber()
		p.shadow = append(p.shadow, '0')
	}
	return valueSummary{}, nil
}

func (p *shadowPlanner) parseObject(ctx planContext, depth int) (valueSummary, error) {
	if ctx.directUserInput {
		ctx.directUserInput = false
		ctx.userAttribution = UserAttributionUntrusted
	}
	if depth > p.limits.MaxJSONDepth {
		return valueSummary{}, p.exhaust(IncompleteJSONDepthLimit)
	}
	p.position++
	p.shadow = append(p.shadow, '{')
	messageOwner := uint64(0)
	spanStart := len(p.spans)
	if ctx.messageObject {
		p.nextOwner++
		messageOwner = p.nextOwner
		ctx.messageOwner = messageOwner
		ctx.scopeID = messageOwner
	}
	roleValue := ""
	roleSeen := false
	roleAmbiguous := false
	messageTypeValue := ""
	messageTypeSeen := false
	messageTypeAmbiguous := false
	blockTypeValue := ""
	blockTypeSeen := false
	blockTypeAmbiguous := false
	blockWrapperType := ""
	blockWrapperAmbiguous := false
	blockHasToolPayloadKey := false
	seenClosedKeys := make(map[string]struct{}, 8)
	blockTextKeys := make([]string, 0, 2)
	first := true
	for {
		p.skipWhitespace()
		if p.position < len(p.body) && p.body[p.position] == '}' {
			p.position++
			p.shadow = append(p.shadow, '}')
			if err := p.bumpTokenOnly(); err != nil {
				return valueSummary{}, err
			}
			break
		}
		if !first {
			if p.body[p.position] != ',' {
				return valueSummary{}, errors.New("object comma missing")
			}
			p.position++
			p.shadow = append(p.shadow, ',')
			p.skipWhitespace()
		}
		first = false
		if err := p.bumpTokenOnly(); err != nil {
			return valueSummary{}, err
		}
		keyStart, keyEnd, err := p.takeString()
		if err != nil {
			return valueSummary{}, err
		}
		keyValue, bounded := decodeShortJSONString(p.body[keyStart:keyEnd], maxShadowKeyBytes)
		if !bounded {
			keyValue = shadowUnknownKey
		}
		canonical := canonicalKey(keyValue)
		if identity, exact, closed := closedSchemaObjectKey(p.source, ctx, keyValue, canonical); closed {
			if !exact {
				p.unsafeRole = true
			}
			if _, duplicate := seenClosedKeys[identity]; duplicate {
				p.unsafeRole = true
			}
			seenClosedKeys[identity] = struct{}{}
		}
		p.shadow = strconv.AppendQuote(p.shadow, compactShadowKey(canonical))
		p.skipWhitespace()
		if p.position >= len(p.body) || p.body[p.position] != ':' {
			return valueSummary{}, errors.New("object colon missing")
		}
		p.position++
		p.shadow = append(p.shadow, ':')
		rootMember := depth == 1
		child := derivePlanContext(ctx, canonical, keyValue, rootMember, p.source)
		if rootMember && child.scopeID == 0 {
			p.nextOwner++
			child.scopeID = p.nextOwner
		}
		summary, err := p.parseValue(child, canonical, depth)
		if err != nil {
			return valueSummary{}, err
		}
		if ctx.messageObject && canonical == "role" {
			if roleSeen {
				p.unsafeRole = true
				roleAmbiguous = true
			}
			roleSeen = true
			if !summary.isText {
				p.unsafeRole = true
				roleAmbiguous = true
			} else {
				roleValue = summary.text
			}
		}
		if ctx.messageObject && canonical == "type" {
			if messageTypeSeen {
				messageTypeAmbiguous = true
			}
			messageTypeSeen = true
			if !summary.isText || !summary.bounded {
				messageTypeAmbiguous = true
			} else {
				messageTypeValue = summary.text
				messageType := canonicalKey(messageTypeValue)
				if p.source == SourceProfileOpenAIResponse && isReservedResponseItemType(messageType) &&
					!isExactResponseItemType(messageTypeValue) {
					p.unsafeRole = true
				}
			}
		}
		if ctx.roleContent && canonical == "type" {
			if blockTypeSeen {
				blockTypeAmbiguous = true
			}
			blockTypeSeen = true
			if !summary.isText || !summary.bounded {
				blockTypeAmbiguous = true
			} else {
				blockTypeValue = summary.text
			}
		}
		if ctx.roleContent && isRoleContentCarrierCanonical(canonical) {
			blockTextKeys = append(blockTextKeys, keyValue)
		}
		if ctx.roleContent && (isToolArgumentCanonical(canonical) || canonical == "input" ||
			isToolWrapperKeyCanonical(canonical)) {
			blockHasToolPayloadKey = true
		}
		if ctx.roleContent && (canonical == "functioncall" || canonical == "functionresponse") {
			if blockWrapperType != "" && blockWrapperType != canonical {
				blockWrapperAmbiguous = true
			}
			blockWrapperType = canonical
		}
	}
	if ctx.roleContent {
		effectiveBlockType := ""
		if blockTypeAmbiguous || blockWrapperAmbiguous {
			effectiveBlockType = "unknown"
		} else if blockTypeSeen {
			effectiveBlockType = canonicalKey(blockTypeValue)
			if isReservedRoleContentBlockType(effectiveBlockType) && !isExactRoleContentBlockType(blockTypeValue) {
				p.unsafeRole = true
			}
		}
		if blockWrapperType != "" && effectiveBlockType != "unknown" {
			if effectiveBlockType != "" && effectiveBlockType != blockWrapperType {
				effectiveBlockType = "unknown"
			} else {
				effectiveBlockType = blockWrapperType
			}
		}
		if blockHasToolPayloadKey && (effectiveBlockType == "" || isRoleTextBlockType(effectiveBlockType)) {
			// A natural-language block cannot simultaneously carry executable tool
			// input while proving authenticated-user authorship. Keep every string
			// visible, but demote the hybrid block to the untrusted path.
			effectiveBlockType = "unknown"
		}
		switch effectiveBlockType {
		case "tooluse", "functioncall", "customtoolcall":
			for index := spanStart; index < len(p.spans); index++ {
				if p.spans[index].messageOwner != ctx.messageOwner {
					continue
				}
				p.spans[index].role = RoleAssistant
				p.spans[index].provenance = ProvenanceToolPayload
				p.spans[index].contentKind = ContentKindToolCallArguments
				p.spans[index].userAttribution = UserAttributionUntrusted
				p.spans[index].roleEligible = false
			}
		case "toolresult", "functionresponse", "functioncalloutput", "customtoolcalloutput":
			for index := spanStart; index < len(p.spans); index++ {
				if p.spans[index].messageOwner != ctx.messageOwner {
					continue
				}
				p.spans[index].role = RoleTool
				p.spans[index].provenance = ProvenanceContent
				p.spans[index].contentKind = ContentKindToolResult
				p.spans[index].userAttribution = UserAttributionUntrusted
				p.spans[index].roleEligible = false
			}
		case "", "text", "inputtext", "outputtext", "refusal":
			// Known natural-language blocks retain the enclosing proven role.
			// Direct content/parts array items receive a provisional per-item scope
			// so executable calls cannot compose across siblings. Once an item is
			// proven to be ordinary text, fold it back into the enclosing message
			// scope so multipart natural-language directives retain their contract.
			for index := spanStart; index < len(p.spans); index++ {
				if p.spans[index].messageOwner == ctx.messageOwner {
					p.spans[index].scopeID = ctx.messageOwner
				}
			}
			for _, key := range blockTextKeys {
				if !roleContentTextFieldAllowed(p.source, effectiveBlockType, key) {
					p.unsafeRole = true
				}
			}
		default:
			for index := spanStart; index < len(p.spans); index++ {
				if p.spans[index].messageOwner != ctx.messageOwner {
					continue
				}
				p.spans[index].role = RoleUser
				p.spans[index].provenance = ProvenanceContent
				p.spans[index].contentKind = ContentKindUnknown
				p.spans[index].userAttribution = UserAttributionUntrusted
				p.spans[index].roleEligible = false
			}
		}
	}
	if messageOwner != 0 {
		typeDerivedRole := RoleUnknown
		typeDerivedProvenance := ProvenanceContent
		typeDerivedKnown := false
		typeDerivedRoleCompatible := false
		if !messageTypeAmbiguous && messageTypeSeen && ctx.historyTrusted && p.source == SourceProfileOpenAIResponse {
			if role, provenance, ok := rolelessResponseItemRole(messageTypeValue); ok {
				typeDerivedRole = role
				typeDerivedProvenance = provenance
				typeDerivedKnown = true
				typeDerivedRoleCompatible = !roleSeen ||
					(messageTypeValue == "additional_tools" && roleValue == "developer")
			}
		}
		if typeDerivedKnown && !typeDerivedRoleCompatible {
			// Responses call/output/reasoning/additional-tools items have a
			// closed type-derived role. CPA v7.2.95 Codex Responses Lite is the
			// sole reviewed exception: additional_tools carries the exact sibling
			// role "developer". Every other explicit role remains ambiguous and
			// must never promote runtime/tool text to trusted user content.
			p.unsafeRole = true
			roleAmbiguous = true
		}
		hasMessageSpan := false
		for index := spanStart; index < len(p.spans); index++ {
			if p.spans[index].messageOwner == messageOwner {
				hasMessageSpan = true
				break
			}
		}
		if typeDerivedKnown && typeDerivedRoleCompatible {
			messageType := canonicalKey(messageTypeValue)
			contentKind := responseItemContentKind(messageTypeValue)
			for index := spanStart; index < len(p.spans); index++ {
				if p.spans[index].messageOwner != messageOwner {
					continue
				}
				if messageType == "reasoning" && p.spans[index].encryptedContent {
					p.spans[index].skip = true
					p.spans[index].roleEligible = false
					p.spans[index].userAttribution = UserAttributionUntrusted
					continue
				}
				p.spans[index].role = typeDerivedRole
				p.spans[index].provenance = typeDerivedProvenance
				p.spans[index].contentKind = contentKind
				p.spans[index].userAttribution = UserAttributionUntrusted
				p.spans[index].roleEligible = false
			}
			p.roleAware = true
		}
		if !roleSeen && hasMessageSpan && !typeDerivedKnown {
			p.missingRole = true
		}
		if !typeDerivedKnown {
			role, ok := normalizedMessageRole(p.source, roleValue)
			trustedUserRolePath := ctx.historyTrusted
			if p.source == SourceProfileOpenAIResponse && messageTypeSeen {
				// CPA v7.2.95 treats only an omitted/empty type or the exact
				// "message" discriminator as a role-bearing Responses message.
				// Unknown and non-string item types are still scanned, but their
				// caller-controlled role must not prove authenticated-user origin.
				trustedUserRolePath = !messageTypeAmbiguous &&
					(messageTypeValue == "" || messageTypeValue == "message")
			}
			if roleSeen && !ok {
				p.unsafeRole = true
				roleAmbiguous = true
			}
			if !roleSeen || roleAmbiguous {
				role = RoleUser
			}
			if ok && !roleAmbiguous {
				p.roleAware = true
			}
			for index := spanStart; index < len(p.spans); index++ {
				if p.spans[index].messageOwner == messageOwner && p.spans[index].roleEligible {
					p.spans[index].role = role
					p.spans[index].userAttribution = UserAttributionUntrusted
					if trustedUserRolePath && role == RoleUser && p.spans[index].provenance == ProvenanceContent {
						p.spans[index].userAttribution = UserAttributionTrusted
					}
					if role == RoleTool && p.spans[index].provenance == ProvenanceContent {
						p.spans[index].contentKind = ContentKindToolResult
					}
				}
			}
		}
	}
	return valueSummary{}, nil
}

func (p *shadowPlanner) parseArray(ctx planContext, depth int) (valueSummary, error) {
	if ctx.directUserInput {
		ctx.directUserInput = false
		ctx.userAttribution = UserAttributionUntrusted
	}
	if depth > p.limits.MaxJSONDepth {
		return valueSummary{}, p.exhaust(IncompleteJSONDepthLimit)
	}
	p.position++
	p.shadow = append(p.shadow, '[')
	first := true
	itemIndex := 0
	for {
		p.skipWhitespace()
		if p.position < len(p.body) && p.body[p.position] == ']' {
			p.position++
			p.shadow = append(p.shadow, ']')
			if err := p.bumpTokenOnly(); err != nil {
				return valueSummary{}, err
			}
			break
		}
		if !first {
			if p.body[p.position] != ',' {
				return valueSummary{}, errors.New("array comma missing")
			}
			p.position++
			p.shadow = append(p.shadow, ',')
		}
		first = false
		child := ctx
		child.atRoot = false
		child.fieldPath = appendArrayFieldPath(ctx.fieldPath, itemIndex)
		child.independentScope = false
		child.independentItems = false
		// messageObject proves only a direct element of the provider history
		// array. Never carry that proof through a nested array.
		child.historyArray = false
		child.messageObject = false
		child.roleTextValue = false
		if ctx.historyArray && ctx.historyTrusted && p.trustRoles {
			child.messageObject = true
			child.conversationIndex = itemIndex
			child.contentKind = ContentKindNaturalLanguageDirective
			child.scopeID = 0
		} else if ctx.atRoot {
			p.nextOwner++
			child.scopeID = p.nextOwner
		} else if ctx.independentItems || ctx.roleContent && ctx.directMessageMember {
			p.nextOwner++
			child.scopeID = p.nextOwner
		}
		if ctx.roleContent {
			child.directMessageMember = false
			child.roleEligible = false
			child.userAttribution = UserAttributionUntrusted
			if !ctx.directMessageMember {
				// Only the direct message content array may contain provider
				// content-block objects. Scalars in that array, and every value
				// below a nested array/text-field array, remain inspectable but
				// cannot inherit the enclosing user role.
				child.roleContent = false
			}
		}
		if _, err := p.parseValue(child, "", depth); err != nil {
			return valueSummary{}, err
		}
		itemIndex++
	}
	return valueSummary{}, nil
}

func derivePlanContext(parent planContext, key, exactKey string, rootMember bool, source SourceProfile) planContext {
	child := parent
	child.atRoot = false
	child.historyArray = false
	child.messageObject = false
	child.roleTextValue = false
	child.directMessageMember = parent.messageObject
	child.directUserInput = false
	child.exactKey = exactKey
	child.fieldPath = appendObjectFieldPath(parent.fieldPath, exactKey)
	child.independentScope = false
	child.independentItems = false
	if parent.metadata {
		return child
	}
	if isProviderMetadataContainerCanonical(key) && parent.provenance != ProvenanceToolPayload {
		child.messageOwner = 0
		child.roleEligible = false
		child.fallbackText = false
		child.unknownRoot = false
		child.metadata = true
		child.contentKind = ContentKindUnknown
		return child
	}
	if rootMember && trustedHistoryEnvelope(source, exactKey) {
		child.historyArray = true
		child.historyTrusted = true
		child.messageOwner = 0
		child.roleEligible = false
		child.roleContent = false
		child.userAttribution = UserAttributionUntrusted
		child.contentKind = ContentKindNaturalLanguageDirective
		if source == SourceProfileOpenAIResponse && exactKey == "input" {
			child.directUserInput = true
			child.userAttribution = UserAttributionTrusted
			child.conversationIndex = 0
		}
		return child
	}
	if rootMember && trustedSystemEnvelope(source, exactKey) {
		child.role = RoleSystem
		child.roleEligible = true
		child.roleContent = false
		child.userAttribution = UserAttributionUntrusted
		child.contentKind = ContentKindNaturalLanguageDirective
		return child
	}
	if rootMember && isProviderToolDefinitionContainerCanonical(key) {
		child.role = RoleSystem
		child.provenance = ProvenanceContent
		child.contentKind = ContentKindToolSchema
		child.roleEligible = true
		child.roleContent = false
		child.userAttribution = UserAttributionUntrusted
		return child
	}
	if parent.contentKind == ContentKindToolSchema {
		// A schema may itself contain fields named input, arguments, content, or
		// examples. Those names do not turn declarations into runtime calls.
		child.role = RoleSystem
		child.provenance = ProvenanceContent
		child.userAttribution = UserAttributionUntrusted
		child.contentKind = ContentKindToolSchema
		return child
	}
	if parent.messageOwner != 0 {
		if parent.roleContent {
			switch {
			case isExactRoleContentTextField(exactKey):
				child.roleEligible = true
				child.roleContent = true
				child.roleTextValue = true
			case isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key):
				child.roleEligible = true
				child.roleContent = false
				child.provenance = ProvenanceToolPayload
				child.contentKind = ContentKindToolCallArguments
				child.userAttribution = UserAttributionUntrusted
			case isMetadataKeyCanonical(key):
				child.roleEligible = false
				child.roleContent = false
				child.fallbackText = false
			default:
				child.roleEligible = false
				child.roleContent = false
				child.role = RoleUser
				child.userAttribution = UserAttributionUntrusted
				child.contentKind = ContentKindUnknown
			}
			return child
		}
		switch {
		case parent.messageObject && exactMessageToolCallArrayKey(source, exactKey):
			child.roleEligible = true
			child.roleContent = false
			child.provenance = ProvenanceToolPayload
			child.contentKind = ContentKindToolCallArguments
			child.userAttribution = UserAttributionUntrusted
			child.independentItems = true
		case parent.messageObject && exactMessageToolCallValueKey(source, exactKey):
			child.roleEligible = true
			child.roleContent = false
			child.provenance = ProvenanceToolPayload
			child.contentKind = ContentKindToolCallArguments
			child.userAttribution = UserAttributionUntrusted
			child.independentScope = true
		case parent.messageObject && exactMessageContentKey(source, exactKey):
			child.roleEligible = true
			child.roleContent = true
		case parent.provenance == ProvenanceToolPayload && exactMessageContentKey(source, exactKey):
			// Nested content labels inside a proven tool transaction may retain the
			// enclosing assistant/tool role, but tool provenance keeps them
			// categorically ineligible for authenticated-user attribution.
			child.roleEligible = true
			child.roleContent = false
			child.userAttribution = UserAttributionUntrusted
		case isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key):
			child.roleEligible = true
			child.roleContent = false
			child.provenance = ProvenanceToolPayload
			child.contentKind = ContentKindToolCallArguments
			child.userAttribution = UserAttributionUntrusted
		case isMetadataKeyCanonical(key):
			child.roleEligible = false
			child.roleContent = false
		default:
			child.roleEligible = false
			child.roleContent = false
			child.role = RoleUser
			child.userAttribution = UserAttributionUntrusted
			child.contentKind = ContentKindUnknown
		}
		return child
	}
	if isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key) {
		child.provenance = ProvenanceToolPayload
		child.contentKind = ContentKindToolCallArguments
	}
	if rootMember && !isKnownRootPlanKey(key) {
		child.unknownRoot = true
		child.contentKind = ContentKindUnknown
	}
	return child
}

func exactMessageToolCallArrayKey(source SourceProfile, key string) bool {
	return (source == SourceProfileOpenAI || source == SourceProfileOpenAIResponse) && key == "tool_calls"
}

func exactMessageToolCallValueKey(source SourceProfile, key string) bool {
	if source != SourceProfileOpenAI && source != SourceProfileOpenAIResponse {
		return false
	}
	return key == "function_call" || key == "tool_call"
}

func trustedHistoryEnvelope(source SourceProfile, key string) bool {
	switch source {
	case SourceProfileOpenAI:
		return key == "messages"
	case SourceProfileOpenAIResponse:
		return key == "input"
	case SourceProfileClaude:
		return key == "messages"
	case SourceProfileGemini:
		return key == "contents"
	default:
		return false
	}
}

func trustedSystemEnvelope(source SourceProfile, key string) bool {
	switch source {
	case SourceProfileOpenAIResponse:
		return key == "instructions"
	case SourceProfileClaude:
		return key == "system"
	case SourceProfileGemini:
		return key == "systemInstruction"
	default:
		return false
	}
}

func isRoleContentTextKeyCanonical(key string) bool {
	switch key {
	case "content", "inputtext", "outputtext", "parts", "refusal", "text":
		return true
	default:
		return false
	}
}

func isRoleContentCarrierCanonical(key string) bool {
	switch key {
	case "content", "inputtext", "outputtext", "parts", "refusal", "text":
		return true
	default:
		return false
	}
}

func exactMessageContentKey(source SourceProfile, key string) bool {
	switch source {
	case SourceProfileOpenAI, SourceProfileOpenAIResponse, SourceProfileClaude:
		return key == "content"
	case SourceProfileGemini:
		return key == "parts"
	default:
		return false
	}
}

func isExactRoleContentTextField(key string) bool {
	return key == "text" || key == "refusal"
}

func roleContentTextFieldAllowed(source SourceProfile, blockType, key string) bool {
	switch blockType {
	case "text", "inputtext", "outputtext":
		return key == "text"
	case "refusal":
		return key == "refusal"
	case "":
		// Gemini parts are untyped {"text": ...} objects. Retain the same
		// conservative compatibility for other known providers, but never accept
		// content/parts/input_text aliases inside the block.
		return key == "text"
	default:
		return false
	}
}

func closedSchemaObjectKey(source SourceProfile, ctx planContext, rawKey, canonical string) (identity string, exact, closed bool) {
	if ctx.atRoot {
		for _, expected := range []string{
			trustedHistoryKey(source), trustedSystemKey(source),
		} {
			if expected != "" && canonical == canonicalKey(expected) {
				return canonical, rawKey == expected, true
			}
		}
		return "", false, false
	}
	if ctx.messageObject {
		switch canonical {
		case "role", "type":
			return canonical, rawKey == canonical, true
		case "content", "parts", "refusal", "text", "inputtext", "outputtext":
			expected := ""
			if exactMessageContentKey(source, rawKey) {
				expected = rawKey
			}
			return "message_text:" + canonical, expected != "", true
		}
	}
	if ctx.roleContent {
		switch canonical {
		case "type":
			return canonical, rawKey == "type", true
		case "content", "parts", "refusal", "text":
			return "block_text:" + canonical, rawKey == canonical, true
		case "inputtext":
			return "block_text:" + canonical, rawKey == "input_text", true
		case "outputtext":
			return "block_text:" + canonical, rawKey == "output_text", true
		}
	}
	return "", false, false
}

func trustedHistoryKey(source SourceProfile) string {
	switch source {
	case SourceProfileOpenAI:
		return "messages"
	case SourceProfileOpenAIResponse:
		return "input"
	case SourceProfileClaude:
		return "messages"
	case SourceProfileGemini:
		return "contents"
	default:
		return ""
	}
}

func trustedSystemKey(source SourceProfile) string {
	switch source {
	case SourceProfileOpenAIResponse:
		return "instructions"
	case SourceProfileClaude:
		return "system"
	case SourceProfileGemini:
		return "systemInstruction"
	default:
		return ""
	}
}

func isKnownRootPlanKey(key string) bool {
	return isTextKeyCanonical(key) || isTextContainerCanonical(key) ||
		isProviderMetadataContainerCanonical(key) || isProviderToolDefinitionContainerCanonical(key) ||
		isMediaContainerKeyCanonical(key) || isMetadataKeyCanonical(key) ||
		isToolWrapperKeyCanonical(key) || isToolArgumentCanonical(key)
}

func normalizedMessageRole(source SourceProfile, value string) (Role, bool) {
	switch value {
	case "user":
		return RoleUser, true
	case "system", "developer":
		if source == SourceProfileGemini {
			return RoleUser, false
		}
		return RoleSystem, true
	case "assistant":
		if source == SourceProfileGemini {
			return RoleUser, false
		}
		return RoleAssistant, true
	case "model":
		if source != SourceProfileGemini {
			return RoleUser, false
		}
		return RoleAssistant, true
	case "tool", "function":
		if source == SourceProfileGemini {
			return RoleUser, false
		}
		return RoleTool, true
	default:
		return RoleUser, false
	}
}

func rolelessResponseItemRole(value string) (Role, SegmentProvenance, bool) {
	switch value {
	case "additional_tools":
		// CPA v7.2.95 accepts Codex Desktop tool definitions in an input item
		// instead of the top-level tools field. The entire item is model-visible
		// authority supplied by the client/runtime, never current user content.
		return RoleSystem, ProvenanceContent, true
	case "function_call", "custom_tool_call":
		return RoleAssistant, ProvenanceToolPayload, true
	case "function_call_output", "custom_tool_call_output":
		return RoleTool, ProvenanceContent, true
	case "reasoning":
		return RoleAssistant, ProvenanceContent, true
	default:
		return RoleUnknown, ProvenanceContent, false
	}
}

func responseItemContentKind(value string) ContentKind {
	switch value {
	case "additional_tools":
		return ContentKindToolSchema
	case "function_call", "custom_tool_call":
		return ContentKindToolCallArguments
	case "function_call_output", "custom_tool_call_output":
		return ContentKindToolResult
	case "reasoning":
		return ContentKindUnknown
	default:
		return ContentKindNaturalLanguageDirective
	}
}

func isReservedResponseItemType(value string) bool {
	switch value {
	case "message", "additionaltools", "functioncall", "functioncalloutput", "customtoolcall", "customtoolcalloutput", "reasoning":
		return true
	default:
		return false
	}
}

func isExactResponseItemType(value string) bool {
	switch value {
	case "message", "additional_tools", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output", "reasoning":
		return true
	default:
		return false
	}
}

func isReservedRoleContentBlockType(value string) bool {
	switch value {
	case "text", "inputtext", "outputtext", "refusal", "tooluse", "toolresult",
		"functioncall", "functionresponse", "functioncalloutput", "customtoolcall", "customtoolcalloutput":
		return true
	default:
		return false
	}
}

func isExactRoleContentBlockType(value string) bool {
	switch value {
	case "text", "input_text", "output_text", "refusal", "tool_use", "tool_result",
		"function_call", "function_response", "function_call_output", "custom_tool_call", "custom_tool_call_output":
		return true
	default:
		return false
	}
}

func (p *shadowPlanner) appendStringValue(ctx planContext, key string, start, end int) valueSummary {
	raw := p.body[start:end]
	if ctx.directUserInput {
		p.roleAware = true
	}
	value, bounded := decodeShortJSONString(raw, maxShadowValueBytes)
	if ctx.metadata {
		p.shadow = append(p.shadow, '"', '"')
		return valueSummary{}
	}
	if shouldPreserveSemanticString(key) {
		p.shadow = strconv.AppendQuote(p.shadow, compactShadowSemanticValue(p.source, key, value, bounded))
		return valueSummary{text: value, isText: true, bounded: bounded}
	}
	if bounded && strings.TrimSpace(value) == "" {
		p.shadow = append(p.shadow, '"', '"')
		return valueSummary{text: value, isText: true, bounded: true}
	}
	id := uint64(len(p.spans) + 1)
	fallbackText := ctx.fallbackText && fallbackPlanTextKey(key)
	scalarCarrier := isScalarMediaCarrierKeyCanonical(key)
	encryptedContent := p.source == SourceProfileOpenAIResponse && ctx.messageOwner != 0 &&
		ctx.directMessageMember && key == "encryptedcontent" && ctx.exactKey == "encrypted_content"
	if representative, ok := opaqueScalarCarrierRepresentative(key, value, bounded, raw, id); ok {
		p.shadow = strconv.AppendQuote(p.shadow, representative)
		p.spans = append(p.spans, plannedText{
			id:                id,
			rawStart:          start,
			rawEnd:            end,
			role:              defaultRole(ctx.role),
			provenance:        ctx.provenance,
			userAttribution:   ctx.userAttribution,
			encryptedContent:  encryptedContent,
			scalarCarrier:     scalarCarrier,
			messageOwner:      ctx.messageOwner,
			conversationIndex: ctx.conversationIndex,
			turnIndex:         -1,
			scopeID:           ctx.scopeID,
			contentKind:       ctx.contentKind,
			fieldPathHash:     structuralFieldPathHash(p.source, ctx.fieldPath),
			roleEligible:      ctx.roleEligible,
			semanticOrdinal:   len(p.spans),
			fallbackText:      fallbackText,
			exactKey:          ctx.exactKey,
		})
		return valueSummary{text: representative, isText: true, bounded: bounded}
	}
	marker := spanMarker(id)
	p.shadow = strconv.AppendQuote(p.shadow, marker)
	p.spans = append(p.spans, plannedText{
		id:                id,
		rawStart:          start,
		rawEnd:            end,
		role:              defaultRole(ctx.role),
		provenance:        ctx.provenance,
		userAttribution:   ctx.userAttribution,
		encryptedContent:  encryptedContent,
		scalarCarrier:     scalarCarrier,
		messageOwner:      ctx.messageOwner,
		conversationIndex: ctx.conversationIndex,
		turnIndex:         -1,
		scopeID:           ctx.scopeID,
		contentKind:       ctx.contentKind,
		fieldPathHash:     structuralFieldPathHash(p.source, ctx.fieldPath),
		roleEligible:      ctx.roleEligible,
		semanticOrdinal:   len(p.spans),
		fallbackText:      fallbackText,
		exactKey:          ctx.exactKey,
	})
	return valueSummary{text: marker, isText: true, bounded: true}
}

func fallbackPlanTextKey(key string) bool {
	return !isMetadataKeyCanonical(key) && !isProviderMetadataContainerCanonical(key) &&
		!isMediaMetadataKeyCanonical(key) && !isMediaContainerKeyCanonical(key) &&
		!isScalarMediaCarrierKeyCanonical(key) && !isOpaquePayloadKeyCanonical(key)
}

func opaqueScalarCarrierRepresentative(key, value string, bounded bool, raw []byte, id uint64) (string, bool) {
	if !isScalarMediaCarrierKeyCanonical(key) {
		return "", false
	}
	candidate := value
	if !bounded {
		candidate = rawJSONStringPrefix(raw, 256)
	}
	trimmed := strings.ToLower(strings.TrimSpace(candidate))
	marker := spanMarker(id)
	switch {
	case strings.HasPrefix(trimmed, "data:image/"):
		return "data:image/png;base64," + marker, true
	case strings.HasPrefix(trimmed, "data:audio/"):
		return "data:audio/wav;base64," + marker, true
	case strings.HasPrefix(trimmed, "data:video/"):
		return "data:video/mp4;base64," + marker, true
	case strings.HasPrefix(trimmed, "data:application/pdf"):
		return "data:application/pdf;base64," + marker, true
	case strings.HasPrefix(trimmed, "https://"):
		return "https://opaque.invalid/" + marker, true
	case strings.HasPrefix(trimmed, "http://"):
		return "http://opaque.invalid/" + marker, true
	default:
		return "", false
	}
}

func defaultRole(role Role) Role {
	if role == "" {
		return RoleUser
	}
	return role
}

func shouldPreserveSemanticString(key string) bool {
	switch key {
	case "role", "type", "mimetype", "mediatype", toolControlSchemaKey:
		return true
	default:
		return false
	}
}

// compactShadowKey keeps only field identities that can change the legacy
// transactional media/tool/schema walk. Arbitrary caller-controlled property
// names collapse to one fixed unknown key. The planner already retains the
// original raw span and canonical context needed for fallback text, so copying
// long or unique keys into the shadow document adds memory without semantics.
func compactShadowKey(key string) string {
	if key == "" {
		return shadowUnknownKey
	}
	if isKnownRootPlanKey(key) || isMediaMetadataKeyCanonical(key) ||
		isScalarMediaCarrierKeyCanonical(key) || isOpaquePayloadKeyCanonical(key) ||
		isDeferredPayloadKeyCanonical(key) || key == toolControlSchemaKey {
		return key
	}
	if _, ok := toolControlBitForKey(key); ok {
		return key
	}
	if _, ok := toolAllowedTextForKey(key); ok {
		return key
	}
	return shadowUnknownKey
}

// compactShadowSemanticValue preserves only the closed semantic classes used
// by media and approved tool-control transactions. Role attribution uses the
// separately returned bounded valueSummary and never depends on this shadow
// representative.
func compactShadowSemanticValue(source SourceProfile, key, value string, bounded bool) string {
	if !bounded {
		return shadowUnknownValue
	}
	switch key {
	case "role":
		if role, ok := normalizedMessageRole(source, value); ok {
			return string(role)
		}
	case "type":
		if marked, kind := marksMediaContext(key, value); marked {
			return shadowMediaType(kind)
		}
	case "mimetype", "mediatype":
		if kind := mediaContextForMIME(value); kind != mediaContextNone {
			return shadowMediaMIME(kind)
		}
	case toolControlSchemaKey:
		trimmed := strings.ToLower(strings.TrimSpace(value))
		switch {
		case trimmed == toolControlSchemaV1:
			return toolControlSchemaV1
		case strings.HasPrefix(trimmed, toolControlSchemaReserved):
			return toolControlSchemaReserved + "unsupported"
		}
	}
	return shadowUnknownValue
}

func shadowMediaType(kind mediaContextKind) string {
	switch kind {
	case mediaContextImage:
		return "image"
	case mediaContextAudio:
		return "audio"
	case mediaContextVideo:
		return "video"
	case mediaContextDocument:
		return "file"
	case mediaContextOther:
		return "inline_data"
	default:
		return shadowUnknownValue
	}
}

func shadowMediaMIME(kind mediaContextKind) string {
	switch kind {
	case mediaContextImage:
		return "image/png"
	case mediaContextAudio:
		return "audio/wav"
	case mediaContextVideo:
		return "video/mp4"
	case mediaContextDocument:
		return "application/pdf"
	default:
		return shadowUnknownValue
	}
}

func decodeShortJSONString(raw []byte, limit int) (string, bool) {
	if len(raw) > limit+2 {
		return "", false
	}
	value, err := strconv.Unquote(string(raw))
	if err != nil || len(value) > limit {
		return "", false
	}
	return value, true
}

func rawJSONStringPrefix(raw []byte, limit int) string {
	if len(raw) < 2 || raw[0] != '"' {
		return ""
	}
	content := raw[1 : len(raw)-1]
	if slash := bytes.IndexByte(content, '\\'); slash >= 0 && slash < limit {
		content = content[:slash]
	}
	if len(content) > limit {
		content = content[:limit]
	}
	return string(content)
}

func (p *shadowPlanner) takeString() (int, int, error) {
	if p.position >= len(p.body) || p.body[p.position] != '"' {
		return 0, 0, errors.New("JSON string expected")
	}
	start := p.position
	p.position++
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case '\\':
			p.position += 2
		case '"':
			p.position++
			return start, p.position, nil
		default:
			p.position++
		}
	}
	return 0, 0, errors.New("unterminated JSON string")
}

func (p *shadowPlanner) takeNumber() {
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case ',', '}', ']', ' ', '\t', '\r', '\n':
			return
		default:
			p.position++
		}
	}
}

func (p *shadowPlanner) skipWhitespace() {
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case ' ', '\t', '\r', '\n':
			p.position++
		default:
			return
		}
	}
}

func (p *shadowPlanner) bump(node bool) error {
	p.tokens++
	if p.tokens > p.limits.MaxJSONTokens {
		return p.exhaust(IncompleteJSONTokenLimit)
	}
	if node {
		p.nodes++
		if p.nodes > p.limits.MaxJSONNodes {
			return p.exhaust(IncompleteJSONNodeLimit)
		}
	}
	return nil
}

func (p *shadowPlanner) bumpTokenOnly() error { return p.bump(false) }

func (p *shadowPlanner) exhaust(reason IncompleteReason) error {
	if p.reason == "" {
		p.reason = reason
	}
	return errPlanBudget
}

func spanMarker(id uint64) string {
	return spanMarkerPrefix + strconv.FormatUint(id, 36) + spanMarkerSuffix
}

func markerID(value string) (uint64, bool) {
	if !strings.HasPrefix(value, spanMarkerPrefix) || !strings.HasSuffix(value, spanMarkerSuffix) {
		return 0, false
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(value, spanMarkerPrefix), spanMarkerSuffix)
	if encoded == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(encoded, 36, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

func (p *shadowPlanner) selected(parts []string) ([]plannedText, []plannedText) {
	byID := make(map[uint64]plannedText, len(p.spans))
	for _, span := range p.spans {
		byID[span.id] = span
	}
	selected := make([]plannedText, 0, len(parts))
	seen := make(map[uint64]struct{}, len(parts))
	owned := make([]plannedText, 0, 8)
	for _, part := range parts {
		if id, ok := markerID(part); ok {
			if span, exists := byID[id]; exists {
				if span.skip {
					seen[id] = struct{}{}
					continue
				}
				selected = append(selected, span)
				seen[id] = struct{}{}
			}
			continue
		}
		if id, ok := embeddedMarkerID(part); ok {
			if span, exists := byID[id]; exists {
				if span.skip {
					seen[id] = struct{}{}
					continue
				}
				selected = append(selected, span)
				seen[id] = struct{}{}
			}
			continue
		}
		if strings.TrimSpace(part) != "" {
			p.nextOwner++
			ordinal := len(owned)
			owned = append(owned, plannedText{
				owned: part, role: RoleUser, provenance: ProvenanceToolPayload,
				userAttribution:   UserAttributionUntrusted,
				conversationIndex: -1, turnIndex: -1, scopeID: p.nextOwner,
				contentKind: ContentKindToolCallArguments,
				fieldPathHash: structuralFieldPathHash(
					p.source, appendArrayFieldPath("$synthetic", ordinal),
				),
			})
		}
	}
	for _, span := range p.spans {
		if span.skip || !span.fallbackText {
			continue
		}
		if _, exists := seen[span.id]; exists {
			continue
		}
		selected = append(selected, span)
		seen[span.id] = struct{}{}
	}
	contentIndexes := make([]int, 0, len(selected))
	contentSpans := make([]plannedText, 0, len(selected))
	for index, span := range selected {
		if span.provenance == ProvenanceToolPayload {
			continue
		}
		contentIndexes = append(contentIndexes, index)
		contentSpans = append(contentSpans, span)
	}
	sort.SliceStable(contentSpans, func(left, right int) bool {
		return contentSpans[left].semanticOrdinal < contentSpans[right].semanticOrdinal
	})
	for index, selectedIndex := range contentIndexes {
		selected[selectedIndex] = contentSpans[index]
	}
	return selected, owned
}

func finalizeConversationMetadata(spans []plannedText) {
	type scopeState struct {
		scopeID           uint64
		conversationIndex int
		trustedUser       bool
		turnIndex         int
	}

	byScope := make(map[uint64]*scopeState, len(spans))
	ordered := make([]*scopeState, 0, len(spans))
	for index := range spans {
		span := &spans[index]
		span.turnIndex = -1
		span.isCurrentTurn = false
		if span.scopeID == 0 || span.conversationIndex < 0 {
			continue
		}
		state := byScope[span.scopeID]
		if state == nil {
			state = &scopeState{
				scopeID: span.scopeID, conversationIndex: span.conversationIndex, turnIndex: -1,
			}
			byScope[span.scopeID] = state
			ordered = append(ordered, state)
		}
		if span.role == RoleUser && span.userAttribution == UserAttributionTrusted &&
			span.contentKind != ContentKindToolCallArguments && span.contentKind != ContentKindToolResult &&
			span.contentKind != ContentKindToolSchema {
			state.trustedUser = true
		}
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].conversationIndex == ordered[right].conversationIndex {
			return ordered[left].scopeID < ordered[right].scopeID
		}
		return ordered[left].conversationIndex < ordered[right].conversationIndex
	})
	turnIndex := -1
	currentScope := uint64(0)
	for _, state := range ordered {
		if state.trustedUser {
			turnIndex++
			currentScope = state.scopeID
		}
		state.turnIndex = turnIndex
	}
	for index := range spans {
		state := byScope[spans[index].scopeID]
		if state == nil {
			continue
		}
		spans[index].turnIndex = state.turnIndex
		spans[index].isCurrentTurn = currentScope != 0 && spans[index].scopeID == currentScope
	}
}

func embeddedMarkerID(value string) (uint64, bool) {
	start := strings.Index(value, spanMarkerPrefix)
	if start < 0 {
		return 0, false
	}
	suffixStart := start + len(spanMarkerPrefix)
	suffixOffset := strings.Index(value[suffixStart:], spanMarkerSuffix)
	if suffixOffset < 0 {
		return 0, false
	}
	end := suffixStart + suffixOffset + len(spanMarkerSuffix)
	return markerID(value[start:end])
}

type streamEmitter struct {
	limits                Limits
	sink                  ChunkSink
	result                *Result
	textLimit             int
	textLimitReason       IncompleteReason
	textLimitCoverage     TextCoverage
	binaryFailureReason   IncompleteReason
	binaryFailureCoverage TextCoverage
	decodeFailureReason   IncompleteReason
	decodeFailureCoverage TextCoverage
	aborted               bool
}

func (s *streamEmitter) emitOwned(span plannedText) error {
	return s.emitDecoded([]byte(span.owned), span)
}

func (s *streamEmitter) emitSpan(raw []byte, span plannedText) error {
	chunkSize := minInt(s.limits.MaxTextPartBytes, s.limits.MaxTextWindowBytes)
	measurement, err := measureJSONString(
		raw, chunkSize, shouldSegmentFencedCode(span), s.limits.MaxClassificationChunks,
	)
	if err != nil {
		return s.operational(err)
	}
	if measurement.binary {
		reason := s.binaryFailureReason
		if reason == "" {
			reason = IncompleteTextPartByteLimit
		}
		coverage := s.binaryFailureCoverage
		if coverage == "" {
			coverage = TextCoverageUnavailable
		}
		s.abort(reason, coverage)
		return nil
	}
	if !measurement.nonSpace {
		return nil
	}
	variants, decodeIncomplete := measurement.decoder.finish(span.scalarCarrier)
	if decodeIncomplete {
		reason := s.decodeFailureReason
		if reason == "" {
			reason = IncompleteTextPartByteLimit
		}
		coverage := s.decodeFailureCoverage
		if coverage == "" {
			coverage = TextCoverageUnavailable
		}
		s.abort(reason, coverage)
		return nil
	}
	pieces := measurement.contentPieces
	segmented := len(pieces) != 0
	if !segmented {
		pieces = []contentKindPiece{{
			start: 0,
			end:   measurement.length,
			kind:  span.contentKind,
		}}
	}
	chunks := (measurement.length + chunkSize - 1) / chunkSize
	if segmented {
		if measurement.chunkBoundaryOverflow {
			s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
			return nil
		}
		chunks = exactContentPieceChunkCount(measurement.chunkEnds, pieces)
	}
	if !s.canAddTextBytes(measurement.length) {
		return nil
	}
	if s.result.TextBytesScanned > s.limits.MaxTotalTextBytes-measurement.length {
		s.abort(IncompleteTotalTextLimit, TextCoverageExhausted)
		return nil
	}
	if s.result.ClassificationChunks > s.limits.MaxClassificationChunks-chunks {
		s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
		return nil
	}
	emitted := 0
	decodedOffset := 0
	pieceIndex := 0
	err = decodeJSONStringChunks(raw, chunkSize, func(chunk []byte, final bool) error {
		if len(chunk) == 0 && !final {
			return nil
		}
		for len(chunk) != 0 {
			if pieceIndex >= len(pieces) {
				return errors.New("decoded content exceeded content-kind plan")
			}
			piece := pieces[pieceIndex]
			if decodedOffset < piece.start || decodedOffset >= piece.end {
				return errors.New("decoded content diverged from content-kind plan")
			}
			partLength := minInt(len(chunk), piece.end-decodedOffset)
			part := chunk[:partLength:partLength]
			if !s.canAddClassificationChunk() {
				return errClassificationLimited
			}
			fieldID := span.id
			if segmented {
				fieldID = contentPieceFieldID(span.id, pieceIndex)
			}
			if err := s.sink.AddSegment(SegmentChunk{
				Role:              defaultRole(span.role),
				Provenance:        span.provenance,
				UserAttribution:   span.userAttribution,
				ConversationIndex: span.conversationIndex,
				TurnIndex:         span.turnIndex,
				IsCurrentTurn:     span.isCurrentTurn,
				ScopeID:           span.scopeID,
				ContentKind:       piece.kind,
				FieldPathHash:     span.fieldPathHash,
				FieldID:           fieldID,
				Start:             decodedOffset == piece.start,
				End:               decodedOffset+partLength == piece.end,
				Text:              part,
			}); err != nil {
				return err
			}
			decodedOffset += partLength
			emitted += partLength
			s.result.ClassificationChunks++
			if partLength > s.result.PeakTextBytesRetained {
				s.result.PeakTextBytesRetained = partLength
			}
			chunk = chunk[partLength:]
			if decodedOffset == piece.end {
				pieceIndex++
			}
		}
		return nil
	})
	if errors.Is(err, errClassificationLimited) {
		return nil
	}
	if err != nil {
		return s.operational(err)
	}
	if decodedOffset != measurement.length || pieceIndex != len(pieces) {
		return s.operational(errors.New("decoded content did not complete content-kind plan"))
	}
	s.result.TextBytesScanned += emitted
	for index, variant := range variants {
		derived := span
		derived.id = derivedFieldID(span.id, index)
		derived.owned = variant
		if err := s.emitOwned(derived); err != nil {
			return err
		}
		if s.aborted {
			return nil
		}
	}
	return nil
}

func (s *streamEmitter) emitDecoded(value []byte, span plannedText) error {
	if strings.TrimSpace(string(value)) == "" {
		return nil
	}
	chunkSize := minInt(s.limits.MaxTextPartBytes, s.limits.MaxTextWindowBytes)
	chunks := (len(value) + chunkSize - 1) / chunkSize
	if !s.canAddTextBytes(len(value)) {
		return nil
	}
	if s.result.TextBytesScanned > s.limits.MaxTotalTextBytes-len(value) {
		s.abort(IncompleteTotalTextLimit, TextCoverageExhausted)
		return nil
	}
	if s.result.ClassificationChunks > s.limits.MaxClassificationChunks-chunks {
		s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
		return nil
	}
	for offset := 0; offset < len(value); {
		end := minInt(len(value), offset+chunkSize)
		for end < len(value) && !utf8.RuneStart(value[end]) {
			end--
		}
		if end == offset {
			end = minInt(len(value), offset+chunkSize)
		}
		chunk := value[offset:end]
		if !s.canAddClassificationChunk() {
			return nil
		}
		if err := s.sink.AddSegment(SegmentChunk{
			Role:              defaultRole(span.role),
			Provenance:        span.provenance,
			UserAttribution:   span.userAttribution,
			ConversationIndex: span.conversationIndex,
			TurnIndex:         span.turnIndex,
			IsCurrentTurn:     span.isCurrentTurn,
			ScopeID:           span.scopeID,
			ContentKind:       span.contentKind,
			FieldPathHash:     span.fieldPathHash,
			FieldID:           span.id,
			Start:             offset == 0,
			End:               end == len(value),
			Text:              chunk,
		}); err != nil {
			return s.operational(err)
		}
		s.result.ClassificationChunks++
		s.result.TextBytesScanned += len(chunk)
		if len(chunk) > s.result.PeakTextBytesRetained {
			s.result.PeakTextBytesRetained = len(chunk)
		}
		offset = end
	}
	return nil
}

func (s *streamEmitter) canAddTextBytes(count int) bool {
	if s.textLimit <= 0 || s.result.TextBytesScanned <= s.textLimit-count {
		return true
	}
	reason := s.textLimitReason
	if reason == "" {
		reason = IncompleteTotalTextLimit
	}
	coverage := s.textLimitCoverage
	if coverage == "" {
		coverage = TextCoverageExhausted
	}
	s.abort(reason, coverage)
	return false
}

func (s *streamEmitter) canAddClassificationChunk() bool {
	if s.aborted {
		return false
	}
	if s.result.ClassificationChunks >= s.limits.MaxClassificationChunks {
		s.abort(IncompleteClassificationChunkLimit, TextCoverageExhausted)
		return false
	}
	return true
}

func (s *streamEmitter) abort(reason IncompleteReason, coverage TextCoverage) {
	if s.aborted {
		return
	}
	s.aborted = true
	s.result.TextCoverage = coverage
	s.result.addIncomplete(reason)
	s.sink.Abort()
}

func (s *streamEmitter) operational(err error) error {
	if !s.aborted {
		s.aborted = true
		s.sink.Abort()
	}
	return fmt.Errorf("extract: chunk sink: %w", err)
}

type jsonStringMeasurement struct {
	length                int
	nonSpace              bool
	binary                bool
	decoder               boundedStreamingDecoder
	contentPieces         []contentKindPiece
	chunkEnds             []int
	chunkBoundaryOverflow bool
}

func measureJSONString(raw []byte, chunkSize int, segmentFencedCode bool, maxChunks int) (measurement jsonStringMeasurement, err error) {
	measurement.decoder = newBoundedStreamingDecoder(len(raw))
	measurement.chunkEnds = make([]int, 0, minInt(maxChunks, 16))
	var planner *fencedCodePlanner
	if segmentFencedCode {
		planner = newFencedCodePlanner(maxChunks)
	}
	err = decodeJSONStringChunks(raw, chunkSize, func(chunk []byte, _ bool) error {
		measurement.length += len(chunk)
		if len(chunk) != 0 {
			if len(measurement.chunkEnds) < maxChunks {
				measurement.chunkEnds = append(measurement.chunkEnds, measurement.length)
			} else {
				measurement.chunkBoundaryOverflow = true
			}
		}
		measurement.decoder.add(chunk)
		if planner != nil {
			planner.add(chunk)
		}
		for len(chunk) > 0 {
			r, size := utf8.DecodeRune(chunk)
			if r == utf8.RuneError && size == 1 {
				return errors.New("invalid decoded UTF-8")
			}
			if !unicode.IsSpace(r) {
				measurement.nonSpace = true
			}
			if (r >= 0 && r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
				measurement.binary = true
			}
			chunk = chunk[size:]
		}
		return nil
	})
	if err == nil && planner != nil {
		measurement.contentPieces = planner.finish()
	}
	return
}

func exactContentPieceChunkCount(chunkEnds []int, pieces []contentKindPiece) int {
	count := len(chunkEnds)
	for index := 0; index+1 < len(pieces); index++ {
		boundary := pieces[index].end
		position := sort.SearchInts(chunkEnds, boundary)
		if position >= len(chunkEnds) || chunkEnds[position] != boundary {
			count++
		}
	}
	return count
}

type boundedStreamingDecoder struct {
	value   []byte
	tooLong bool
	probe   streamingEncodingProbe
}

func newBoundedStreamingDecoder(sourceBytes int) boundedStreamingDecoder {
	valueCapacity := minInt(sourceBytes, maxDecodeSourceBytes)
	sampleCapacity := minInt(sourceBytes, encodingSampleBytes)
	return boundedStreamingDecoder{
		value: make([]byte, 0, valueCapacity),
		probe: streamingEncodingProbe{sample: make([]byte, 0, sampleCapacity)},
	}
}

func (d *boundedStreamingDecoder) add(value []byte) {
	if d == nil || len(value) == 0 {
		return
	}
	d.probe.add(value)
	if d.tooLong {
		return
	}
	if len(d.value) > maxDecodeSourceBytes-len(value) {
		d.tooLong = true
		clear(d.value)
		d.value = nil
		return
	}
	d.value = append(d.value, value...)
}

func (d *boundedStreamingDecoder) finish(failClosedBareEncoding bool) (variants []string, incomplete bool) {
	if d == nil {
		return nil, false
	}
	if d.tooLong {
		if failClosedBareEncoding && d.probe.strongBareEncodingCandidate() {
			return nil, true
		}
		return nil, d.probe.potentiallyEncoded()
	}
	variants, encoded, decodeIncomplete := decodeStreamingBoundedText(string(d.value), failClosedBareEncoding)
	return variants, encoded && decodeIncomplete
}

type streamingEncodingProbe struct {
	sample                  []byte
	initialized             bool
	base64Possible          bool
	base64Padding           bool
	base64PaddingN          int
	base64Standard          bool
	base64URL               bool
	base64CompactBytes      int
	base64Horizontal        bool
	base64HorizontalGap     bool
	base64HorizontalInvalid bool
	base64TokenBytes        int
	base64Block             [base64ProbeBlock]byte
	base64BlockN            int
	base64DecodeFailed      bool
	base64MalformedStrong   bool
	base64DecodedText       streamingTextSignal
	percentState            uint8
	validPercent            bool
	entityActive            bool
	entityLength            int
	validEntity             bool
	entity                  [32]byte
	base64Distinct          int
	base64Alphabet          [256]bool
	base64StrongSig         bool
	totalBytes              int
	percentCount            int
	entityCount             int
	entityBytes             int
}

func (p *streamingEncodingProbe) add(value []byte) {
	if p == nil {
		return
	}
	if !p.initialized {
		p.initialized = true
		p.base64Possible = true
	}
	p.totalBytes += len(value)
	if len(p.sample) < encodingSampleBytes {
		count := minInt(len(value), encodingSampleBytes-len(p.sample))
		p.sample = append(p.sample, value[:count]...)
	}
	for _, character := range value {
		p.observePercent(character)
		p.observeEntity(character)
		p.observeBase64(character)
	}
}

func (p *streamingEncodingProbe) observeBase64(character byte) {
	if !p.base64Possible {
		return
	}
	alphabetCharacter := false
	switch {
	case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		if p.base64Padding {
			p.invalidateBase64Candidate()
			return
		}
		alphabetCharacter = true
	case character == '+' || character == '/':
		if p.base64Padding || p.base64URL {
			p.invalidateBase64Candidate()
			return
		}
		p.base64Standard = true
		p.base64StrongSig = true
		alphabetCharacter = true
	case character == '-' || character == '_':
		if p.base64Padding || p.base64Standard {
			p.invalidateBase64Candidate()
			return
		}
		p.base64URL = true
		p.base64StrongSig = true
		alphabetCharacter = true
	case character == '=':
		if p.base64PaddingN >= 2 {
			p.invalidateBase64Candidate()
			return
		}
		p.base64Padding = true
		p.base64PaddingN++
		p.base64StrongSig = true
	case character == '\r' || character == '\n':
		p.base64StrongSig = true
		return
	case character == ' ' || character == '\t':
		p.base64Horizontal = true
		p.base64HorizontalGap = true
		return
	default:
		p.invalidateBase64Candidate()
		return
	}

	if p.base64HorizontalGap {
		if p.base64TokenBytes > 0 && p.base64TokenBytes%4 != 0 {
			p.base64HorizontalInvalid = true
		}
		p.base64TokenBytes = 0
		p.base64HorizontalGap = false
	}
	p.base64TokenBytes++
	p.base64CompactBytes++
	if alphabetCharacter && !p.base64Alphabet[character] {
		p.base64Alphabet[character] = true
		p.base64Distinct++
	}
	p.base64Block[p.base64BlockN] = character
	p.base64BlockN++
	if p.base64BlockN == len(p.base64Block) {
		p.decodeBase64Block()
	}
}

func (p *streamingEncodingProbe) decodeBase64Block() {
	if !decodeBase64ProbeBlock(p.base64Block[:p.base64BlockN], p.base64URL, false, &p.base64DecodedText) {
		p.latchStrongMalformedBase64()
		p.base64DecodeFailed = true
		p.base64Possible = false
		return
	}
	p.base64BlockN = 0
}

func (p *streamingEncodingProbe) invalidateBase64Candidate() {
	if p == nil || !p.base64Possible {
		return
	}
	p.latchStrongMalformedBase64()
	p.base64Possible = false
}

func (p *streamingEncodingProbe) latchStrongMalformedBase64() {
	if p == nil || p.base64MalformedStrong || p.base64DecodeFailed ||
		p.base64CompactBytes < minBase64SourceBytes ||
		p.base64Horizontal && !p.base64Padding && p.base64HorizontalInvalid {
		return
	}
	if p.base64DecodedText.textual() {
		p.base64MalformedStrong = true
		return
	}
	if !p.base64StrongSig && p.base64Distinct < 16 {
		return
	}
	complete, printable := p.completeBase64Candidate()
	if complete && printable {
		p.base64MalformedStrong = true
		return
	}
	if !complete && p.printableMalformedBase64Prefix() {
		p.base64MalformedStrong = true
	}
}

func (p *streamingEncodingProbe) printableMalformedBase64Prefix() bool {
	if p == nil || p.base64BlockN <= 1 {
		return false
	}
	maxTrim := minInt(3, p.base64BlockN-1)
	for trim := 1; trim <= maxTrim; trim++ {
		candidate := p.base64Block[:p.base64BlockN-trim]
		if len(candidate)%4 == 0 {
			textSignal := p.base64DecodedText
			if decodeBase64ProbeBlock(candidate, p.base64URL, false, &textSignal) && textSignal.textual() {
				return true
			}
		}
		if len(candidate)%4 != 1 {
			textSignal := p.base64DecodedText
			if decodeBase64ProbeBlock(candidate, p.base64URL, true, &textSignal) && textSignal.textual() {
				return true
			}
		}
	}
	return false
}

func (p *streamingEncodingProbe) observePercent(character byte) {
	switch p.percentState {
	case 1:
		if isHexByte(character) {
			p.percentState = 2
			return
		}
		p.percentState = 0
	case 2:
		if isHexByte(character) {
			p.validPercent = true
			p.percentCount++
			p.percentState = 0
			return
		}
		p.percentState = 0
	}
	if character == '%' {
		p.percentState = 1
	}
}

func (p *streamingEncodingProbe) observeEntity(character byte) {
	if character == '&' {
		p.entityActive = true
		p.entityLength = 1
		p.entity[0] = '&'
		return
	}
	if !p.entityActive {
		return
	}
	if character == ';' {
		if p.entityLength < len(p.entity) {
			p.entity[p.entityLength] = ';'
			p.entityLength++
			candidate := string(p.entity[:p.entityLength])
			if html.UnescapeString(candidate) != candidate {
				p.validEntity = true
				p.entityCount++
				p.entityBytes += p.entityLength
			}
		}
		p.entityActive = false
		p.entityLength = 0
		return
	}
	allowed := character == '#' || character == 'x' || character == 'X' ||
		character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
	if !allowed || p.entityLength >= len(p.entity)-1 {
		p.entityActive = false
		p.entityLength = 0
		return
	}
	p.entity[p.entityLength] = character
	p.entityLength++
}

func (p *streamingEncodingProbe) potentiallyEncoded() bool {
	if p == nil {
		return false
	}
	sample := strings.TrimSpace(string(p.sample))
	if isData, textual := streamingDataURLKind(sample); isData {
		return textual
	}
	if p.validPercent && denseEncodingSignal(p.percentCount, p.percentCount*3, p.totalBytes) ||
		p.validEntity && denseEncodingSignal(p.entityCount, p.entityBytes, p.totalBytes) {
		return true
	}
	if p.base64MalformedStrong {
		return true
	}
	if !p.base64Possible {
		return false
	}
	complete, printable := p.completeBase64Candidate()
	if !complete {
		p.latchStrongMalformedBase64()
		if p.base64MalformedStrong {
			return true
		}
	}
	if complete && printable {
		return true
	}
	if !p.base64StrongSig && p.base64Distinct < 16 {
		return false
	}
	return complete && printableBase64Sample(sample)
}

func (p *streamingEncodingProbe) strongBareEncodingCandidate() bool {
	if p == nil || p.base64CompactBytes < minBase64SourceBytes ||
		p.base64Horizontal && !p.base64Padding && p.base64HorizontalInvalid {
		return false
	}
	if p.base64MalformedStrong {
		return true
	}
	if p.base64DecodeFailed {
		return p.base64Horizontal || p.base64StrongSig || p.base64Distinct >= 16
	}
	if !p.base64Possible {
		return false
	}
	return p.base64Horizontal || p.base64StrongSig || p.base64Distinct >= 16
}

func (p *streamingEncodingProbe) completeBase64Candidate() (bool, bool) {
	if p.base64DecodeFailed || p.base64CompactBytes < minBase64SourceBytes ||
		p.base64Horizontal && !p.base64Padding && p.base64HorizontalInvalid {
		return false, false
	}
	textSignal := p.base64DecodedText
	if p.base64BlockN == 0 {
		return true, textSignal.textual()
	}
	raw := !p.base64Padding
	if raw && p.base64BlockN%4 == 1 || !raw && p.base64BlockN%4 != 0 {
		return false, false
	}
	if !decodeBase64ProbeBlock(p.base64Block[:p.base64BlockN], p.base64URL, raw, &textSignal) {
		return false, false
	}
	return true, textSignal.textual()
}

func decodeBase64ProbeBlock(value []byte, urlAlphabet, raw bool, textSignal *streamingTextSignal) bool {
	encoding := base64.StdEncoding
	if raw {
		encoding = base64.RawStdEncoding
	}
	if urlAlphabet {
		encoding = base64.URLEncoding
		if raw {
			encoding = base64.RawURLEncoding
		}
	}
	var decoded [base64ProbeDecoded]byte
	n, err := encoding.Decode(decoded[:], value)
	if err != nil {
		return false
	}
	textSignal.add(decoded[:n])
	return true
}

type streamingTextSignal struct {
	pending         [utf8.UTFMax]byte
	pendingN        int
	runBytes        int
	decodedBytes    int
	printableBytes  int
	meaningfulBytes int
	meaningful      bool
	found           bool
}

func (p *streamingTextSignal) add(value []byte) {
	if p == nil || p.found {
		return
	}
	p.decodedBytes += len(value)
	for _, character := range value {
		p.pending[p.pendingN] = character
		p.pendingN++
		for p.pendingN > 0 && utf8.FullRune(p.pending[:p.pendingN]) {
			r, size := utf8.DecodeRune(p.pending[:p.pendingN])
			if r == utf8.RuneError && size == 1 {
				p.resetRun()
			} else {
				p.observeRune(r, size)
			}
			copy(p.pending[:], p.pending[size:p.pendingN])
			p.pendingN -= size
		}
	}
}

func (p *streamingTextSignal) observeRune(r rune, size int) {
	if r != '\n' && r != '\r' && r != '\t' && (unicode.IsControl(r) || !unicode.IsPrint(r)) {
		p.resetRun()
		return
	}
	p.printableBytes += size
	p.runBytes += size
	if unicode.IsLetter(r) || unicode.IsNumber(r) {
		p.meaningful = true
		p.meaningfulBytes += size
	}
	if p.runBytes >= minEncodedTextRun && p.meaningful {
		p.found = true
	}
}

func (p streamingTextSignal) textual() bool {
	if p.found {
		return true
	}
	return p.decodedBytes >= minEncodedTextRun &&
		p.meaningfulBytes >= minEncodedTextRun &&
		p.printableBytes*100 >= p.decodedBytes*minEncodedTextDensity
}

func (p *streamingTextSignal) resetRun() {
	p.runBytes = 0
	p.meaningful = false
}

func denseEncodingSignal(count, encodedBytes, totalBytes int) bool {
	return count >= minDenseEncodings && totalBytes > 0 && encodedBytes*100 >= totalBytes*minEncodingDensity
}

func printableBase64Sample(value string) bool {
	value = strings.TrimSpace(value)
	if compact, ok := horizontalBase64Candidate(value); ok {
		value = compact
	}
	compact, _, valid := compactBase64(value)
	if !valid {
		return false
	}
	if remainder := len(compact) % 4; remainder != 0 {
		compact = compact[:len(compact)-remainder]
	}
	if len(compact) < minBase64SourceBytes {
		return false
	}
	decoded, found := decodeBase64Bytes(compact, minBase64SourceBytes)
	return found && isInspectableText(decoded)
}

func decodeStreamingBoundedText(value string, failClosedBareEncoding bool) ([]string, bool, bool) {
	if isData, textual := streamingDataURLKind(value); isData && !textual {
		// A media-looking prefix in an ordinary, unproven text field remains
		// classifier-visible. Only a structurally proven media transaction may
		// remove the source span from the shadow plan. Ambiguous scalar carriers
		// still fail closed when an unknown or malformed data envelope also has a
		// strong incomplete encoding signal; known media data URLs retain the
		// established inspectable fallback.
		if _, knownMedia := opaqueDataURLKind(value); knownMedia || !failClosedBareEncoding {
			return nil, false, false
		}
	}
	variants, encoded, incomplete := decodeBoundedText(value)
	if encoded && incomplete && len(variants) == 0 && !failClosedBareEncoding && !hasExplicitTextEncodingEnvelope(value) {
		// Bare identifiers may be syntactically compatible with Base64 while
		// decoding only to binary. Ordinary text fields scan the original bytes and
		// do not turn such identifiers into request incompleteness. Ambiguous scalar
		// media carriers retain the legacy fail-closed contract because their value
		// may otherwise cross a provider media boundary without inspection.
		return nil, false, false
	}
	return variants, encoded, incomplete
}

func hasExplicitTextEncodingEnvelope(value string) bool {
	trimmed := strings.TrimSpace(value)
	if isData, textual := streamingDataURLKind(trimmed); isData {
		return textual
	}
	return strings.Contains(trimmed, "%") || strings.Contains(trimmed, "&") && strings.Contains(trimmed, ";")
}

func streamingDataURLKind(value string) (isData bool, textual bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < len("data:") || !strings.EqualFold(trimmed[:len("data:")], "data:") {
		return false, false
	}
	header := trimmed[len("data:"):]
	if comma := strings.IndexByte(header, ','); comma >= 0 {
		header = header[:comma]
	}
	mediaType := header
	if semicolon := strings.IndexByte(mediaType, ';'); semicolon >= 0 {
		mediaType = mediaType[:semicolon]
	}
	return true, isTextualDataMIME(mediaType)
}

func derivedFieldID(parent uint64, ordinal int) uint64 {
	return derivedFieldIDFlag | parent<<8 | uint64(ordinal+1)
}

func decodeJSONStringChunks(raw []byte, chunkSize int, emit func([]byte, bool) error) error {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return errors.New("invalid JSON string span")
	}
	if chunkSize <= 0 {
		return errors.New("invalid JSON string chunk size")
	}
	content := raw[1 : len(raw)-1]
	if bytes.IndexByte(content, '\\') < 0 {
		if !utf8.Valid(content) {
			return errors.New("invalid UTF-8 in JSON string")
		}
		if len(content) == 0 {
			return emit(nil, true)
		}
		for offset := 0; offset < len(content); {
			end := minInt(len(content), offset+chunkSize)
			for end < len(content) && !utf8.RuneStart(content[end]) {
				end--
			}
			if end == offset {
				_, size := utf8.DecodeRune(content[offset:])
				end = offset + size
			}
			chunk := content[offset:end:end]
			if err := emit(chunk, end == len(content)); err != nil {
				return err
			}
			offset = end
		}
		return nil
	}
	capacity := chunkSize
	if len(content) < capacity {
		capacity = len(content)
	}
	buffer := make([]byte, 0, capacity)
	flush := func(final bool) error {
		if len(buffer) == 0 && !final {
			return nil
		}
		if err := emit(buffer, final); err != nil {
			return err
		}
		buffer = buffer[:0]
		return nil
	}
	for index := 0; index < len(content); {
		var decoded [utf8.UTFMax]byte
		decodedBytes := decoded[:0]
		if content[index] != '\\' {
			r, size := utf8.DecodeRune(content[index:])
			if r == utf8.RuneError && size == 1 {
				return errors.New("invalid UTF-8 in JSON string")
			}
			decodedBytes = append(decodedBytes, content[index:index+size]...)
			index += size
		} else {
			index++
			if index >= len(content) {
				return errors.New("unterminated JSON escape")
			}
			switch content[index] {
			case '"', '\\', '/':
				decodedBytes = append(decodedBytes, content[index])
				index++
			case 'b':
				decodedBytes = append(decodedBytes, '\b')
				index++
			case 'f':
				decodedBytes = append(decodedBytes, '\f')
				index++
			case 'n':
				decodedBytes = append(decodedBytes, '\n')
				index++
			case 'r':
				decodedBytes = append(decodedBytes, '\r')
				index++
			case 't':
				decodedBytes = append(decodedBytes, '\t')
				index++
			case 'u':
				first, next, ok := decodeHexRune(content, index+1)
				if !ok {
					return errors.New("invalid unicode escape")
				}
				index = next
				r := rune(first)
				if utf16.IsSurrogate(r) {
					if r >= 0xd800 && r <= 0xdbff && index+6 <= len(content) && content[index] == '\\' && content[index+1] == 'u' {
						second, after, secondOK := decodeHexRune(content, index+2)
						if secondOK && second >= 0xdc00 && second <= 0xdfff {
							r = utf16.DecodeRune(r, rune(second))
							index = after
						} else {
							r = utf8.RuneError
						}
					} else {
						r = utf8.RuneError
					}
				}
				var encoded [utf8.UTFMax]byte
				size := utf8.EncodeRune(encoded[:], r)
				decodedBytes = append(decodedBytes, encoded[:size]...)
			default:
				return errors.New("invalid JSON escape")
			}
		}
		if len(buffer) > 0 && len(buffer)+len(decodedBytes) > chunkSize {
			if err := flush(false); err != nil {
				return err
			}
		}
		buffer = append(buffer, decodedBytes...)
		if len(buffer) == chunkSize {
			if err := flush(index == len(content)); err != nil {
				return err
			}
		}
	}
	if len(buffer) > 0 || len(content) == 0 {
		return flush(true)
	}
	return nil
}

func decodeHexRune(value []byte, start int) (uint16, int, bool) {
	if start+4 > len(value) {
		return 0, start, false
	}
	var result uint16
	for index := start; index < start+4; index++ {
		result <<= 4
		switch c := value[index]; {
		case c >= '0' && c <= '9':
			result |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			result |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			result |= uint16(c-'A') + 10
		default:
			return 0, start, false
		}
	}
	return result, start + 4, true
}

type discardChunkSink struct{}

func (discardChunkSink) AddSegment(SegmentChunk) error { return nil }
func (discardChunkSink) Abort()                        {}
