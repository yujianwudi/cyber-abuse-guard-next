package extract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Role is a normalized provider conversation role. Unknown role values never
// enter a role-aware result; the extractor falls back to legacy Parts instead.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
	// RoleUnknown is an internal streaming marker for a complete request whose
	// schema does not prove role attribution. Classifiers must treat it as
	// untrusted all-parts input rather than silently upgrading it to RoleUser.
	RoleUnknown Role = "unknown"
)

// SegmentProvenance distinguishes natural conversation content from arguments
// that a provider-native tool call would execute. Content is the zero value so
// existing callers that construct role-aware segments remain source compatible.
type SegmentProvenance uint8

const (
	ProvenanceContent SegmentProvenance = iota
	ProvenanceToolPayload
)

// UserAttribution records whether a closed, provider-aware schema path proved
// that natural-language content was authored by the authenticated user. The
// zero value is deliberately untrusted: unknown top-level fields, future
// message siblings, roleless items, tool output, and callers that construct a
// Segment without an explicit proof must never be upgraded implicitly.
type UserAttribution uint8

const (
	UserAttributionUntrusted UserAttribution = iota
	UserAttributionTrusted
)

// ContentKind is a closed, structural classification of model-visible text.
// It does not decide whether the text is safe; it preserves the boundary that
// downstream classifiers need in order to avoid composing unrelated evidence.
// Unknown is the zero value so callers using older keyed Segment literals stay
// conservative until they opt in to the richer metadata.
type ContentKind uint8

const (
	ContentKindUnknown ContentKind = iota
	ContentKindNaturalLanguageDirective
	ContentKindQuotedText
	ContentKindCodeBlock
	ContentKindLogOutput
	ContentKindToolSchema
	ContentKindToolCallArguments
	ContentKindToolResult
	ContentKindConfiguration
	ContentKindDocumentation
	ContentKindSecurityAnalysis
)

func (kind ContentKind) String() string {
	switch kind {
	case ContentKindNaturalLanguageDirective:
		return "natural_language_directive"
	case ContentKindQuotedText:
		return "quoted_text"
	case ContentKindCodeBlock:
		return "code_block"
	case ContentKindLogOutput:
		return "log_output"
	case ContentKindToolSchema:
		return "tool_schema"
	case ContentKindToolCallArguments:
		return "tool_call_arguments"
	case ContentKindToolResult:
		return "tool_result"
	case ContentKindConfiguration:
		return "configuration"
	case ContentKindDocumentation:
		return "documentation"
	case ContentKindSecurityAnalysis:
		return "security_analysis"
	default:
		return "unknown"
	}
}

type roleContentValueShape uint8

const (
	roleContentRoot roleContentValueShape = iota
	roleContentArrayItem
	roleContentTextField
)

// Segment is transient request text plus its normalized role and provenance.
// Neither the extractor nor classifier stores segments after the current route
// call.
type Segment struct {
	Role            Role
	Provenance      SegmentProvenance
	UserAttribution UserAttribution
	// ConversationIndex is the zero-based provider history item. TurnIndex is
	// the zero-based trusted-user turn and is inherited by following assistant
	// and tool items until the next trusted user item. Values are -1 when the
	// text is outside a recognized conversation history.
	ConversationIndex int
	TurnIndex         int
	IsCurrentTurn     bool
	// ScopeID is a request-local directive ownership boundary. FieldPathHash is
	// a one-way, content-free digest of the structural JSON/multipart field path.
	ScopeID       uint64
	ContentKind   ContentKind
	FieldPathHash string
	Text          string
}

// newLegacySegment is used by the pre-profiled role extractor. Its role and
// provenance remain useful, but it has no provider-history coordinates. Keep
// both indexes at the documented sentinel so a caller that later mixes these
// segments with profiled output cannot accidentally present them as turn 0.
func newLegacySegment(role Role, provenance SegmentProvenance, attribution UserAttribution, text string) Segment {
	return Segment{
		Role:              role,
		Provenance:        provenance,
		UserAttribution:   attribution,
		ConversationIndex: -1,
		TurnIndex:         -1,
		Text:              text,
	}
}

const (
	maxRoleSegments     = 64
	maxRoleSegmentBytes = 32 << 10
)

type segmentRing struct {
	items     []Segment
	start     int
	truncated bool
}

func (r *segmentRing) add(segment Segment) {
	if strings.TrimSpace(segment.Text) == "" {
		return
	}
	if len(r.items) < maxRoleSegments {
		r.items = append(r.items, segment)
		return
	}
	r.truncated = true
	r.items[r.start] = segment
	r.start = (r.start + 1) % len(r.items)
}

func (r *segmentRing) ordered() []Segment {
	if len(r.items) == 0 {
		return nil
	}
	result := make([]Segment, len(r.items))
	for index := range result {
		result[index] = r.items[(r.start+index)%len(r.items)]
	}
	return result
}

// extractRoleSegments recognizes only standard role-bearing request envelopes.
// It intentionally fails back to Parts on malformed, ambiguous, or unknown
// shapes so role labels can never make an untrusted protocol less strict.
func extractRoleSegments(body []byte, limits Limits) ([]Segment, bool, bool) {
	var historyKey string
	seenRoot := make(map[string]struct{}, 4)
	segments := segmentRing{items: make([]Segment, 0, maxRoleSegments)}
	truncated := false
	ambiguous := false
	unsafeRole := false

	err := walkRawObject(body, func(key string, raw json.RawMessage) error {
		standardKey := standardRoleKey(key)
		if standardKey == "" && isStandardRoleCanonical(canonicalKey(key)) {
			ambiguous = true
			return nil
		}
		if standardKey != "" {
			identity := canonicalKey(standardKey)
			if _, duplicate := seenRoot[identity]; duplicate {
				ambiguous = true
				return nil
			}
			seenRoot[identity] = struct{}{}
		}
		switch standardKey {
		case "messages", "contents":
			if historyKey != "" || !rawStartsWith(raw, '[') {
				ambiguous = true
				return nil
			}
			historyKey = standardKey
			historyTruncated, historyAmbiguous, historyUnsafeRole, err := addRoleHistorySegments(&segments, raw, historyKey, limits)
			if err != nil {
				return err
			}
			truncated = truncated || historyTruncated
			ambiguous = ambiguous || historyAmbiguous
			unsafeRole = unsafeRole || historyUnsafeRole
		case "input":
			// OpenAI Responses arrays carry the same top-level role shape as
			// messages. Scalar or otherwise unstructured input uses legacy mode.
			if !rawStartsWith(raw, '[') {
				return nil
			}
			if historyKey != "" {
				ambiguous = true
				return nil
			}
			historyKey = standardKey
			historyTruncated, historyAmbiguous, historyUnsafeRole, err := addRoleHistorySegments(&segments, raw, historyKey, limits)
			if err != nil {
				return err
			}
			truncated = truncated || historyTruncated
			ambiguous = ambiguous || historyAmbiguous
			unsafeRole = unsafeRole || historyUnsafeRole
		case "system", "instructions", "systeminstruction":
			partTruncated, err := addRoleSegment(&segments, raw, RoleSystem, ProvenanceContent, limits, contextText)
			if err != nil {
				return err
			}
			truncated = truncated || partTruncated
		default:
			if canonical := canonicalKey(key); isProviderToolDefinitionContainerCanonical(canonical) {
				// Provider tool declarations are system-level context, not user
				// intent and not executable invocation arguments. Retain their
				// semantic descriptions as content so a malicious definition is not
				// silently discarded, while actual calls are split per message below.
				partTruncated, err := addRoleSegment(&segments, raw, RoleSystem, ProvenanceContent, limits, contextTool)
				if err != nil {
					return err
				}
				truncated = truncated || partTruncated
				return nil
			}
			canonical := canonicalKey(key)
			if isMetadataKeyCanonical(canonical) || isProviderMetadataContainerCanonical(canonical) {
				return nil
			}
			// Preserve role isolation for the recognized history while treating
			// every semantic string under an unknown top-level field as untrusted
			// user content. A forged/future envelope therefore cannot hide text,
			// and harmless metadata cannot collapse the whole request into a
			// provenance-less fallback.
			parts, partTruncated, err := extractRawParts(raw, limits, contextText)
			if err != nil {
				return err
			}
			for _, part := range parts {
				segments.add(newLegacySegment(RoleUser, ProvenanceContent, UserAttributionUntrusted, part))
			}
			truncated = truncated || partTruncated
		}
		return nil
	})
	if err != nil || ambiguous {
		return nil, false, unsafeRole
	}
	if historyKey == "" {
		return nil, false, false
	}

	return segments.ordered(), true, truncated || segments.truncated
}

func addRoleHistorySegments(segments *segmentRing, history json.RawMessage, historyKey string, limits Limits) (bool, bool, bool, error) {
	truncated := false
	ambiguous := false
	unsafeRole := false
	err := walkRawArray(history, func(raw json.RawMessage) error {
		if !rawStartsWith(raw, '{') {
			ambiguous = true
			return nil
		}
		role, present, ok, err := messageRole(raw, historyKey)
		if err != nil {
			unsafeRole = true
			ambiguous = true
			return nil
		}
		if !ok && !present {
			recognized, itemTruncated, err := addRolelessProviderItem(segments, raw, historyKey, limits)
			if err != nil {
				return err
			}
			if recognized {
				truncated = truncated || itemTruncated
				return nil
			}
		}
		if !ok {
			// Role-less Gemini content and OpenAI Responses items are valid
			// provider shapes. They use the conservative legacy fallback. An
			// explicit but unsupported role is different: it is attacker-
			// controlled provenance and enforcing modes must fail closed.
			unsafeRole = present
			ambiguous = true
			return nil
		}
		messageTruncated, messageAmbiguous, err := addRoleMessageSegments(segments, raw, role, historyKey, limits)
		if err != nil {
			return err
		}
		if messageAmbiguous {
			ambiguous = true
			return nil
		}
		truncated = truncated || messageTruncated
		return nil
	})
	return truncated, ambiguous, unsafeRole, err
}

// addRoleMessageSegments separates rendered message content from executable
// tool-call arguments. Provider wrapper metadata (function names, call IDs,
// types) is deliberately excluded, while argument values remain inspectable.
func addRoleMessageSegments(segments *segmentRing, raw json.RawMessage, role Role, historyKey string, limits Limits) (bool, bool, error) {
	truncated := false
	ambiguous := false
	seenFields := make(map[string]struct{}, 4)
	userAttribution, typeAmbiguous, err := roleMessageUserAttribution(raw, role, historyKey)
	if err != nil {
		return false, false, err
	}
	if typeAmbiguous {
		return false, true, nil
	}

	err = walkRawObject(raw, func(key string, value json.RawMessage) error {
		canonical := canonicalKey(key)
		expectedContent := "content"
		if historyKey == "contents" {
			expectedContent = "parts"
		}
		switch {
		case key == "role":
			return nil
		case historyKey == "input" && key == "type":
			// Responses item type is a closed transport discriminator, not
			// model-visible message text. roleMessageUserAttribution already
			// validated duplicates, aliases, and the exact trusted message types.
			return nil
		case key == expectedContent:
			if _, seen := seenFields[canonical]; seen {
				ambiguous = true
				return nil
			}
			seenFields[canonical] = struct{}{}
			valueTruncated, valueAmbiguous, err := addRoleContentSegments(
				segments, value, role, userAttribution, limits,
			)
			truncated = truncated || valueTruncated
			ambiguous = ambiguous || valueAmbiguous
			return err
		case isExactLegacyToolWrapperKey(key):
			valueTruncated, err := addRoleSegment(segments, value, role, ProvenanceToolPayload, limits, contextTool)
			truncated = truncated || valueTruncated
			return err
		default:
			if canonical == "role" || isRoleContentCarrierCanonical(canonical) {
				ambiguous = true
				return nil
			}
			// Keep the known message content under its proven role, but treat text
			// below an unknown sibling field as a separate untrusted user segment.
			// This is conservative without allowing harmless metadata to erase role
			// isolation for assistant/system refusals and policies.
			if isProviderMetadataContainerCanonical(canonical) {
				return nil
			}
			parts, valueTruncated, err := extractRawParts(value, limits, contextText)
			if err != nil {
				return err
			}
			for _, part := range parts {
				segments.add(newLegacySegment(RoleUser, ProvenanceContent, UserAttributionUntrusted, part))
			}
			truncated = truncated || valueTruncated
			return nil
		}
	})
	return truncated, ambiguous, err
}

func roleMessageUserAttribution(raw json.RawMessage, role Role, historyKey string) (UserAttribution, bool, error) {
	if role != RoleUser {
		return UserAttributionUntrusted, false, nil
	}
	if historyKey != "input" {
		return UserAttributionTrusted, false, nil
	}

	typeSeen := false
	typeAlias := false
	typeValue := ""
	typeIsString := false
	err := walkRawObject(raw, func(key string, value json.RawMessage) error {
		if canonicalKey(key) != "type" {
			return nil
		}
		if key != "type" {
			typeAlias = true
			return nil
		}
		if typeSeen {
			return errors.New("duplicate response item type")
		}
		typeSeen = true
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) > 0 && trimmed[0] == '"' {
			if err := json.Unmarshal(value, &typeValue); err != nil {
				return err
			}
			typeIsString = true
		}
		return nil
	})
	if err != nil || typeAlias {
		return UserAttributionUntrusted, true, err
	}
	if !typeSeen || typeIsString && (typeValue == "" || typeValue == "message") {
		return UserAttributionTrusted, false, nil
	}
	if typeIsString {
		canonical := canonicalKey(typeValue)
		if isReservedResponseItemType(canonical) && !isExactResponseItemType(typeValue) {
			return UserAttributionUntrusted, true, nil
		}
		if _, _, known := rolelessResponseItemRole(typeValue); known {
			return UserAttributionUntrusted, true, nil
		}
	}
	return UserAttributionUntrusted, false, nil
}

// addRoleContentSegments keeps adjacent natural-language blocks from one
// provider message together. This preserves refusal/policy context when a
// provider splits rendered text into multiple blocks, while tool payload blocks
// remain separately identifiable and executable arguments are never merged
// into the surrounding prose.
func addRoleContentSegments(
	segments *segmentRing,
	raw json.RawMessage,
	role Role,
	userAttribution UserAttribution,
	limits Limits,
) (bool, bool, error) {
	local := segmentRing{items: make([]Segment, 0, 4)}
	truncated, ambiguous, err := addRoleContentValue(
		&local, raw, role, userAttribution, limits, roleContentRoot,
	)
	if err != nil || ambiguous {
		return truncated || local.truncated, ambiguous, err
	}

	type pendingContent struct {
		role            Role
		provenance      SegmentProvenance
		userAttribution UserAttribution
		rawParts        []string
	}
	var pending *pendingContent
	flush := func() {
		if pending != nil {
			rawJoined, joinTruncated := joinRoleParts(pending.rawParts)
			truncated = truncated || joinTruncated
			analysisParts := make([]string, 0, 1+len(pending.rawParts)*2)
			seen := make(map[string]struct{}, 1+len(pending.rawParts)*2)
			appendUnique := func(value string) {
				if strings.TrimSpace(value) == "" {
					return
				}
				if _, exists := seen[value]; exists {
					return
				}
				seen[value] = struct{}{}
				analysisParts = append(analysisParts, value)
			}
			appendDecoded := func(value string) {
				if _, opaque := opaqueDataURLKind(value); opaque {
					return
				}
				decoded, encoded, incomplete := decodeBoundedText(value)
				if encoded && incomplete {
					truncated = true
				}
				for _, variant := range decoded {
					appendUnique(variant)
				}
			}
			appendUnique(rawJoined)
			for _, rawPart := range pending.rawParts {
				appendDecoded(rawPart)
			}
			// Decode the pristine joined source after the per-block views. This
			// closes both sub-threshold splits and independently decodable chunks;
			// decoded fragments never contaminate the reassembly candidate.
			appendDecoded(rawJoined)
			text, textTruncated := joinRoleParts(analysisParts)
			truncated = truncated || textTruncated
			segments.add(newLegacySegment(
				pending.role, pending.provenance, pending.userAttribution, text,
			))
			pending = nil
		}
	}
	for _, segment := range local.ordered() {
		if segment.Provenance != ProvenanceContent {
			flush()
			segments.add(segment)
			continue
		}
		if pending == nil {
			pending = &pendingContent{
				role: segment.Role, provenance: segment.Provenance,
				userAttribution: segment.UserAttribution, rawParts: []string{segment.Text},
			}
			continue
		}
		if pending.role != segment.Role || pending.provenance != segment.Provenance ||
			pending.userAttribution != segment.UserAttribution {
			flush()
			pending = &pendingContent{
				role: segment.Role, provenance: segment.Provenance,
				userAttribution: segment.UserAttribution, rawParts: []string{segment.Text},
			}
			continue
		}
		pending.rawParts = append(pending.rawParts, segment.Text)
	}
	flush()
	return truncated || local.truncated, false, nil
}

func addRoleContentValue(
	segments *segmentRing,
	raw json.RawMessage,
	role Role,
	userAttribution UserAttribution,
	limits Limits,
	shape roleContentValueShape,
) (bool, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false, false, nil
	}
	switch trimmed[0] {
	case '"':
		if shape == roleContentArrayItem {
			truncated, err := addRawRoleContentSegmentAttributed(
				segments, raw, RoleUser, UserAttributionUntrusted, limits,
			)
			return truncated, false, err
		}
		truncated, err := addRawRoleContentSegmentAttributed(
			segments, raw, role, userAttribution, limits,
		)
		return truncated, false, err
	case '{':
		if shape == roleContentTextField {
			truncated, err := addRawRoleContentSegmentAttributed(
				segments, raw, RoleUser, UserAttributionUntrusted, limits,
			)
			return truncated, false, err
		}
		return addRoleContentBlock(segments, raw, role, userAttribution, limits)
	case '[':
		if shape != roleContentRoot {
			truncated, err := addRawRoleContentSegmentAttributed(
				segments, raw, RoleUser, UserAttributionUntrusted, limits,
			)
			return truncated, false, err
		}
		truncated := false
		ambiguous := false
		err := walkRawArray(raw, func(item json.RawMessage) error {
			itemTruncated, itemAmbiguous, err := addRoleContentValue(
				segments, item, role, userAttribution, limits, roleContentArrayItem,
			)
			truncated = truncated || itemTruncated
			ambiguous = ambiguous || itemAmbiguous
			return err
		})
		return truncated, ambiguous, err
	default:
		return false, true, nil
	}
}

func addRoleContentBlock(
	segments *segmentRing,
	raw json.RawMessage,
	role Role,
	userAttribution UserAttribution,
	limits Limits,
) (bool, bool, error) {
	blockType, hasToolPayloadKey, err := roleContentBlockShape(raw)
	if err != nil {
		return false, true, err
	}
	switch blockType {
	case "tooluse", "functioncall", "customtoolcall":
		truncated, err := addRoleSegment(segments, raw, role, ProvenanceToolPayload, limits, contextTool)
		return truncated, false, err
	case "toolresult", "functionresponse", "functioncalloutput", "customtoolcalloutput":
		truncated, err := addRawRoleContentSegment(segments, raw, RoleTool, limits)
		return truncated, false, err
	}
	if hasToolPayloadKey || blockType != "" && !isRoleTextBlockType(blockType) {
		truncated, err := addRawRoleContentSegmentAttributed(
			segments, raw, RoleUser, UserAttributionUntrusted, limits,
		)
		return truncated, false, err
	}
	return addRoleContentObjectFields(segments, raw, role, userAttribution, blockType, limits)
}

func addRawRoleContentSegment(segments *segmentRing, raw json.RawMessage, role Role, limits Limits) (bool, error) {
	attribution := UserAttributionUntrusted
	if role == RoleUser {
		attribution = UserAttributionTrusted
	}
	return addRawRoleContentSegmentAttributed(segments, raw, role, attribution, limits)
}

func addRawRoleContentSegmentAttributed(
	segments *segmentRing,
	raw json.RawMessage,
	role Role,
	attribution UserAttribution,
	limits Limits,
) (bool, error) {
	parts, partTruncated, err := extractRawPartsWithoutDecode(raw, limits, contextText)
	if err != nil {
		return false, err
	}
	text, joinTruncated := joinRoleParts(parts)
	segments.add(newLegacySegment(role, ProvenanceContent, attribution, text))
	return partTruncated || joinTruncated, nil
}

func addRoleContentObjectFields(
	segments *segmentRing,
	raw json.RawMessage,
	role Role,
	userAttribution UserAttribution,
	blockType string,
	limits Limits,
) (bool, bool, error) {
	truncated := false
	ambiguous := false
	seen := make(map[string]struct{}, 4)
	err := walkRawObject(raw, func(key string, value json.RawMessage) error {
		canonical := canonicalKey(key)
		if canonical == "type" {
			if key != "type" {
				ambiguous = true
			}
			return nil
		}
		if isMetadataKeyCanonical(canonical) || isProviderMetadataContainerCanonical(canonical) {
			return nil
		}
		if isRoleContentTextKeyCanonical(canonical) {
			if !roleContentTextFieldAllowed(SourceProfileUnknown, blockType, key) {
				ambiguous = true
				return nil
			}
			if _, duplicate := seen[canonical]; duplicate {
				ambiguous = true
				return nil
			}
			seen[canonical] = struct{}{}
			valueTruncated, valueAmbiguous, err := addRoleContentValue(
				segments, value, role, userAttribution, limits, roleContentTextField,
			)
			truncated = truncated || valueTruncated
			ambiguous = ambiguous || valueAmbiguous
			return err
		}

		parts, valueTruncated, err := extractRawParts(value, limits, contextText)
		if err != nil {
			return err
		}
		for _, part := range parts {
			segments.add(newLegacySegment(
				RoleUser, ProvenanceContent, UserAttributionUntrusted, part,
			))
		}
		truncated = truncated || valueTruncated
		return nil
	})
	return truncated, ambiguous, err
}

func isRoleTextBlockType(blockType string) bool {
	switch blockType {
	case "text", "inputtext", "outputtext", "refusal":
		return true
	default:
		return false
	}
}

func roleContentBlockShape(raw json.RawMessage) (string, bool, error) {
	blockType := ""
	typeSeen := false
	wrapperType := ""
	hasToolPayloadKey := false
	err := walkRawObject(raw, func(key string, value json.RawMessage) error {
		canonical := canonicalKey(key)
		if isToolArgumentCanonical(canonical) || canonical == "input" ||
			isToolWrapperKeyCanonical(canonical) {
			hasToolPayloadKey = true
		}
		if canonical == "functioncall" || canonical == "functionresponse" {
			if !isExactLegacyContentToolWrapperKey(key) {
				return errors.New("non-exact content block tool wrapper")
			}
			if wrapperType != "" {
				return errors.New("duplicate content block tool wrapper")
			}
			trimmed := bytes.TrimSpace(value)
			if len(trimmed) == 0 || trimmed[0] != '{' {
				return errors.New("content block functionCall must be an object")
			}
			wrapperType = canonical
			hasToolPayloadKey = true
		}
		if canonical != "type" {
			return nil
		}
		if key != "type" {
			return errors.New("non-exact content block type")
		}
		if typeSeen {
			return errors.New("duplicate content block type")
		}
		typeSeen = true
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) == 0 || trimmed[0] != '"' {
			if bytes.Equal(trimmed, []byte("null")) {
				// JSON null is accepted by encoding/json when unmarshalling into a
				// string, but it is not an omitted or empty block discriminator.
				blockType = "unknown"
				return nil
			}
			return errors.New("content block type must be a string")
		}
		var valueString string
		if err := json.Unmarshal(value, &valueString); err != nil {
			return err
		}
		blockType = canonicalKey(valueString)
		if isReservedRoleContentBlockType(blockType) && !isExactRoleContentBlockType(valueString) {
			return errors.New("non-exact content block type value")
		}
		return nil
	})
	if err != nil {
		return "", hasToolPayloadKey, err
	}
	if wrapperType != "" {
		if blockType != "" && blockType != wrapperType {
			return "", hasToolPayloadKey, errors.New("conflicting content block type and tool wrapper")
		}
		blockType = wrapperType
	}
	return blockType, hasToolPayloadKey, err
}

func addRoleSegment(segments *segmentRing, raw json.RawMessage, role Role, provenance SegmentProvenance, limits Limits, initial contextKind) (bool, error) {
	parts, partTruncated, err := extractRawParts(raw, limits, initial)
	if err != nil {
		return false, err
	}
	if provenance == ProvenanceToolPayload || role == RoleTool {
		rawParts, rawTruncated, rawErr := extractRawPartsWithoutDecode(raw, limits, initial)
		if rawErr != nil {
			return false, rawErr
		}
		text, analysisTruncated := joinRolePartsWithPristineDecode(parts, rawParts)
		segments.add(newLegacySegment(role, provenance, UserAttributionUntrusted, text))
		return partTruncated || rawTruncated || analysisTruncated, nil
	}
	text, joinTruncated := joinRoleParts(parts)
	segments.add(newLegacySegment(role, provenance, UserAttributionUntrusted, text))
	return partTruncated || joinTruncated, nil
}

func joinRolePartsWithPristineDecode(parts, rawParts []string) (string, bool) {
	rawJoined, truncated := joinRoleParts(rawParts)
	analysisParts := make([]string, 0, len(parts)+3)
	seen := make(map[string]struct{}, len(parts)+3)
	appendUnique := func(value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		analysisParts = append(analysisParts, value)
	}
	appendUnique(rawJoined)
	if _, opaque := opaqueDataURLKind(rawJoined); !opaque {
		decoded, encoded, incomplete := decodeBoundedText(rawJoined)
		if encoded && incomplete {
			truncated = true
		}
		for _, variant := range decoded {
			appendUnique(variant)
		}
	}
	for _, part := range parts {
		appendUnique(part)
	}
	text, joinTruncated := joinRoleParts(analysisParts)
	return text, truncated || joinTruncated
}

// addRolelessProviderItem recognizes only provider-native typed items whose
// provenance is intrinsic to the envelope. Other missing-role shapes retain
// the conservative legacy fallback.
func addRolelessProviderItem(segments *segmentRing, raw json.RawMessage, envelope string, limits Limits) (bool, bool, error) {
	if envelope != "input" {
		return false, false, nil
	}
	blockType, _, err := roleContentBlockShape(raw)
	if err != nil {
		return false, false, err
	}
	switch blockType {
	case "functioncall", "customtoolcall":
		truncated, err := addRoleSegment(segments, raw, RoleAssistant, ProvenanceToolPayload, limits, contextTool)
		return true, truncated, err
	case "functioncalloutput", "customtoolcalloutput":
		truncated, err := addRoleSegment(segments, raw, RoleTool, ProvenanceContent, limits, contextText)
		return true, truncated, err
	default:
		return false, false, nil
	}
}

func messageRole(raw json.RawMessage, envelope string) (Role, bool, bool, error) {
	seen := false
	alias := false
	value := ""
	err := walkRawObject(raw, func(key string, rawValue json.RawMessage) error {
		if key != "role" {
			if canonicalKey(key) == "role" {
				alias = true
			}
			return nil
		}
		if seen {
			return errors.New("duplicate message role")
		}
		seen = true
		return json.Unmarshal(rawValue, &value)
	})
	if err != nil || alias || !seen {
		return "", seen, false, err
	}
	switch value {
	case "user":
		return RoleUser, true, true, nil
	case "system", "developer":
		return RoleSystem, true, true, nil
	case "assistant":
		return RoleAssistant, true, true, nil
	case "model":
		if envelope == "contents" {
			return RoleAssistant, true, true, nil
		}
	case "tool", "function":
		return RoleTool, true, true, nil
	}
	return "", true, false, nil
}

func standardRoleKey(key string) string {
	switch key {
	case "messages":
		return "messages"
	case "contents":
		return "contents"
	case "input":
		return "input"
	case "system":
		return "system"
	case "instructions":
		return "instructions"
	case "system_instruction", "systemInstruction":
		return "systeminstruction"
	default:
		return ""
	}
}

func isStandardRoleCanonical(key string) bool {
	switch key {
	case "messages", "contents", "input", "system", "instructions", "systeminstruction":
		return true
	default:
		return false
	}
}

func isExactLegacyToolWrapperKey(key string) bool {
	switch key {
	case "tool_calls", "tool_call", "function_call", "tool_use", "functionCall":
		return true
	default:
		return false
	}
}

func isExactLegacyContentToolWrapperKey(key string) bool {
	switch key {
	case "functionCall", "functionResponse", "function_call", "function_response":
		return true
	default:
		return false
	}
}

func extractRawParts(raw []byte, limits Limits, initial contextKind) ([]string, bool, error) {
	result := Result{Parts: make([]string, 0, minInt(4, limits.MaxTextParts))}
	x := extractor{limits: limits, result: &result}
	if err := x.walkJSON(raw, initial, 0, false); err != nil {
		return nil, false, err
	}
	return result.Parts, result.Truncated, nil
}

func extractRawPartsWithoutDecode(raw []byte, limits Limits, initial contextKind) ([]string, bool, error) {
	result := Result{Parts: make([]string, 0, minInt(4, limits.MaxTextParts))}
	x := extractor{limits: limits, result: &result, skipDecode: true}
	if err := x.walkJSON(raw, initial, 0, false); err != nil {
		return nil, false, err
	}
	return result.Parts, result.Truncated, nil
}

func joinRoleParts(parts []string) (string, bool) {
	if len(parts) == 0 {
		return "", false
	}
	if len(parts) == 1 && len(parts[0]) <= maxRoleSegmentBytes {
		return parts[0], false
	}
	var builder strings.Builder
	builder.Grow(minInt(maxRoleSegmentBytes, totalPartBytes(parts)))
	truncated := false
	for _, part := range parts {
		if part == "" {
			continue
		}
		if builder.Len() > 0 {
			if builder.Len() == maxRoleSegmentBytes {
				truncated = true
				break
			}
			builder.WriteByte('\n')
		}
		remaining := maxRoleSegmentBytes - builder.Len()
		if len(part) > remaining {
			part = utf8Prefix(part, remaining)
			truncated = true
		}
		builder.WriteString(part)
		if truncated {
			break
		}
	}
	return builder.String(), truncated
}

func totalPartBytes(parts []string) int {
	total := 0
	for _, part := range parts {
		if total >= maxRoleSegmentBytes-len(part)-1 {
			return maxRoleSegmentBytes
		}
		total += len(part) + 1
	}
	return total
}

func utf8Prefix(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

func rawStartsWith(raw []byte, want byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == want
}

func walkRawObject(data []byte, visit func(string, json.RawMessage) error) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('{') {
		return errors.New("role envelope is not an object")
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("role envelope key is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if err := visit(key, raw); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("role envelope has invalid closing delimiter")
	}
	return requireJSONEOF(decoder)
}

func walkRawArray(data []byte, visit func(json.RawMessage) error) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('[') {
		return errors.New("role history is not an array")
	}
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if err := visit(raw); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(']') {
		return errors.New("role history has invalid closing delimiter")
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("role JSON contains trailing values")
		}
		return err
	}
	return nil
}
