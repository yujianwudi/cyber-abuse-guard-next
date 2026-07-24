// Package extract performs bounded, format-tolerant extraction of text from
// supported LLM JSON request bodies. It deliberately has no dependency on the
// CPA plugin package so it can be fuzzed and reused independently.
package extract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMaxScanBytes               = 262144
	DefaultMaxRawBytes                = 16 << 20
	DefaultMaxTextWindowBytes         = DefaultMaxScanBytes
	DefaultMaxTotalTextBytes          = 8 << 20
	DefaultMaxJSONDepth               = 32
	DefaultMaxJSONTokens              = 65536
	DefaultMaxJSONNodes               = 32768
	DefaultMaxTextParts               = 512
	DefaultMaxTextPartBytes           = 16 << 10
	DefaultMaxClassificationChunks    = 2048
	ClassificationOverlapReserveBytes = 4 << 10

	DefaultMaxMultipartBoundaryBytes = 70
	DefaultMaxMultipartParts         = 1024
	DefaultMaxMultipartHeaders       = 32
	DefaultMaxMultipartHeaderBytes   = 16 << 10
	DefaultMaxMultipartTextFields    = 512
	DefaultMaxMultipartTextBytes     = DefaultMaxScanBytes
	DefaultMaxMultipartTextPartBytes = 16 << 10

	HardMaxScanBytes            = 4 << 20
	HardMaxRawBytes             = 64 << 20
	MinTextWindowBytes          = 16 << 10
	HardMaxTextWindowBytes      = 1 << 20
	HardMaxTotalTextBytes       = 8 << 20
	HardMaxClassificationChunks = 16384
	HardMaxJSONDepth            = 128
	HardMaxJSONTokens           = 1 << 20
	HardMaxJSONNodes            = 1 << 20
	HardMaxTextParts            = 4096
	HardMaxTextPartBytes        = 1 << 20

	HardMaxMultipartBoundaryBytes = 256
	HardMaxMultipartParts         = 4096
	HardMaxMultipartHeaders       = 256
	HardMaxMultipartHeaderBytes   = 1 << 20
	HardMaxMultipartTextFields    = 4096
	HardMaxMultipartTextBytes     = HardMaxScanBytes
	HardMaxMultipartTextPartBytes = 1 << 20

	// Keeping parts modest prevents a single prompt from forcing large
	// downstream classifier allocations. This is an implementation bound, not
	// a separately configurable policy knob.
	maxTextPartBytes = 16 << 10

	// Ambiguous payload strings are retained only until their containing object
	// can prove whether they are media. These bounds are deliberately internal:
	// widening them through configuration would make a JSON member-order fix an
	// attacker-controlled memory knob. Effective byte limits are additionally
	// capped by MaxTextPartBytes and MaxScanBytes.
	maxDeferredCandidateBytes     = 64 << 10
	maxDeferredCandidatesPerFrame = 64
	maxDeferredCandidatesTotal    = 128
	maxDeferredRetainedBytes      = 256 << 10
)

var (
	ErrInvalidJSON   = errors.New("extract: invalid JSON")
	ErrInvalidLimits = errors.New("extract: invalid limits")
)

// Limits bounds both raw input processing and semantic traversal. A zero field
// uses its secure task-book default; negative or excessively large values are
// rejected. In streaming extraction, MaxTextPartBytes and
// MaxMultipartTextPartBytes bound each retained/emitted chunk rather than the
// cumulative length of one logical field. MaxTotalTextBytes and
// MaxMultipartTextBytes are the cumulative coverage bounds. The distinction is
// what lets long prompts remain fully inspectable without retaining them as one
// attacker-sized allocation.
type Limits struct {
	MaxScanBytes            int
	MaxRawBytes             int
	MaxTextWindowBytes      int
	MaxTotalTextBytes       int
	MaxClassificationChunks int
	MaxJSONDepth            int
	MaxJSONTokens           int
	MaxJSONNodes            int
	MaxTextParts            int
	MaxTextPartBytes        int

	MaxMultipartBoundaryBytes int
	MaxMultipartParts         int
	MaxMultipartHeaders       int
	MaxMultipartHeaderBytes   int
	MaxMultipartTextFields    int
	MaxMultipartTextBytes     int
	MaxMultipartTextPartBytes int
}

// Result contains only extracted text and bounded-processing metadata.
// ParseError is intentionally a message rather than the source body so callers
// can audit failures without retaining prompts.
type Result struct {
	Parts                 []string
	Segments              []Segment
	RoleAware             bool
	Completeness          Completeness
	Envelope              EnvelopeCompleteness
	TextCoverage          TextCoverage
	IncompleteReasons     []IncompleteReason
	TextBytesScanned      int
	RawBytesObserved      int64
	LogicalTextParts      int
	ClassificationChunks  int
	PeakTextBytesRetained int

	// BytesScanned and Truncated are retained for source compatibility. New
	// request-level callers must use TextBytesScanned, RawBytesObserved, and
	// IncompleteReasons because BytesScanned historically counted raw JSON.
	BytesScanned int
	Truncated    bool
	// OpaqueMedia reports media that was deliberately not fetched or decoded.
	// It is separate from Truncated so routing policy can audit or allow
	// legitimate multimodal requests without weakening fail-closed handling for
	// genuinely incomplete text inspection.
	OpaqueMedia      bool
	OpaqueMediaKinds []OpaqueMediaKind
	ParseError       string
}

// OpaqueMediaKind is a content-free, bounded classification of media that was
// deliberately not fetched or decoded. It is safe for counters and health
// telemetry because it cannot contain a URL, filename, MIME parameter, or
// request fragment.
type OpaqueMediaKind string

const (
	OpaqueMediaHTTPSImageURL OpaqueMediaKind = "https_image_url"
	OpaqueMediaDataURL       OpaqueMediaKind = "data_url"
	OpaqueMediaBase64Image   OpaqueMediaKind = "base64_image"
	OpaqueMediaAudio         OpaqueMediaKind = "audio"
	OpaqueMediaVideo         OpaqueMediaKind = "video"
	OpaqueMediaDocument      OpaqueMediaKind = "document_attachment"
	OpaqueMediaRemoteURL     OpaqueMediaKind = "remote_media_url"
	OpaqueMediaOther         OpaqueMediaKind = "other"
)

// ExtractText extracts text from OpenAI Chat/Responses, Anthropic Messages,
// Gemini, and common nested tool-call shapes. Invalid JSON returns
// ErrInvalidJSON and also populates Result.ParseError. MaxScanBytes is retained
// only as the compatibility alias for the streaming text window; it never cuts
// the raw JSON body.
func ExtractText(body []byte, limits Limits) (Result, error) {
	return extractText(body, limits, contextNone, true)
}

// ExtractUntrustedText performs a conservative bounded walk for an unknown
// provider shape. Every non-metadata string is treated as user-controlled
// text, including values nested below field names the current provider-aware
// extractor does not recognize. Role attribution is deliberately disabled:
// an unknown schema cannot safely prove that a field is a trusted system or
// assistant message.
func ExtractUntrustedText(body []byte, limits Limits) (Result, error) {
	return extractText(body, limits, contextText, false)
}

func extractText(body []byte, limits Limits, initial contextKind, roleIndex bool) (Result, error) {
	limits, err := limits.normalized()
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Parts:            make([]string, 0, minInt(8, limits.MaxTextParts)),
		Completeness:     CompletenessComplete,
		Envelope:         EnvelopeComplete,
		TextCoverage:     TextCoverageComplete,
		RawBytesObserved: int64(minInt(len(body), limits.MaxRawBytes)),
		BytesScanned:     len(body),
	}
	x := extractor{limits: limits, result: &result}
	if err := x.walkJSON(body, initial, 0, false); err != nil {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.finish()
		return result, ErrInvalidJSON
	}
	if roleIndex && result.IsComplete() {
		segments, roleAware, roleTruncated := extractRoleSegments(body, limits)
		if roleTruncated {
			result.addIncomplete(IncompleteTextPartLimit)
		}
		if roleAware {
			result.Segments = segments
			result.RoleAware = true
		}
	}
	result.TextBytesScanned = totalPartBytesUnbounded(result.Parts)
	if !result.IsComplete() {
		result.TextCoverage = coverageForReasons(result.IncompleteReasons)
	}
	result.finish()
	return result, nil
}

func (l Limits) normalized() (Limits, error) {
	if l.MaxScanBytes == 0 {
		l.MaxScanBytes = DefaultMaxScanBytes
	}
	if l.MaxRawBytes == 0 {
		l.MaxRawBytes = DefaultMaxRawBytes
	}
	if l.MaxTextWindowBytes == 0 {
		l.MaxTextWindowBytes = l.MaxScanBytes
		if l.MaxTextWindowBytes < MinTextWindowBytes {
			l.MaxTextWindowBytes = MinTextWindowBytes
		}
		if l.MaxTextWindowBytes > HardMaxTextWindowBytes {
			l.MaxTextWindowBytes = HardMaxTextWindowBytes
		}
	}
	if l.MaxTextWindowBytes < MinTextWindowBytes || l.MaxTextWindowBytes > HardMaxTextWindowBytes {
		return Limits{}, fmt.Errorf("%w: MaxTextWindowBytes must be between %d and %d", ErrInvalidLimits, MinTextWindowBytes, HardMaxTextWindowBytes)
	}
	if l.MaxTotalTextBytes == 0 {
		l.MaxTotalTextBytes = DefaultMaxTotalTextBytes
	}
	if l.MaxJSONDepth == 0 {
		l.MaxJSONDepth = DefaultMaxJSONDepth
	}
	if l.MaxJSONTokens == 0 {
		l.MaxJSONTokens = DefaultMaxJSONTokens
	}
	if l.MaxJSONNodes == 0 {
		l.MaxJSONNodes = DefaultMaxJSONNodes
	}
	if l.MaxTextParts == 0 {
		l.MaxTextParts = DefaultMaxTextParts
	}
	if l.MaxClassificationChunks == 0 {
		stride := l.MaxTextWindowBytes - ClassificationOverlapReserveBytes
		minimum := 2*l.MaxTextParts + (l.MaxTotalTextBytes+stride-1)/stride + 1
		l.MaxClassificationChunks = maxInt(DefaultMaxClassificationChunks, minimum)
	}
	if l.MaxTextPartBytes == 0 {
		l.MaxTextPartBytes = DefaultMaxTextPartBytes
	}
	if l.MaxMultipartBoundaryBytes == 0 {
		l.MaxMultipartBoundaryBytes = DefaultMaxMultipartBoundaryBytes
	}
	if l.MaxMultipartParts == 0 {
		l.MaxMultipartParts = DefaultMaxMultipartParts
	}
	if l.MaxMultipartHeaders == 0 {
		l.MaxMultipartHeaders = DefaultMaxMultipartHeaders
	}
	if l.MaxMultipartHeaderBytes == 0 {
		l.MaxMultipartHeaderBytes = DefaultMaxMultipartHeaderBytes
	}
	if l.MaxMultipartTextFields == 0 {
		l.MaxMultipartTextFields = DefaultMaxMultipartTextFields
	}
	if l.MaxMultipartTextBytes == 0 {
		l.MaxMultipartTextBytes = DefaultMaxMultipartTextBytes
	}
	if l.MaxMultipartTextPartBytes == 0 {
		l.MaxMultipartTextPartBytes = DefaultMaxMultipartTextPartBytes
	}
	if l.MaxScanBytes < 1 || l.MaxScanBytes > HardMaxScanBytes {
		return Limits{}, fmt.Errorf("%w: MaxScanBytes must be between 1 and %d", ErrInvalidLimits, HardMaxScanBytes)
	}
	if l.MaxRawBytes < 1 || l.MaxRawBytes > HardMaxRawBytes {
		return Limits{}, fmt.Errorf("%w: MaxRawBytes must be between 1 and %d", ErrInvalidLimits, HardMaxRawBytes)
	}
	if l.MaxTotalTextBytes < 1 || l.MaxTotalTextBytes > HardMaxTotalTextBytes {
		return Limits{}, fmt.Errorf("%w: MaxTotalTextBytes must be between 1 and %d", ErrInvalidLimits, HardMaxTotalTextBytes)
	}
	if l.MaxTotalTextBytes < l.MaxTextWindowBytes {
		return Limits{}, fmt.Errorf("%w: MaxTotalTextBytes must be at least MaxTextWindowBytes", ErrInvalidLimits)
	}
	if l.MaxClassificationChunks < 1 || l.MaxClassificationChunks > HardMaxClassificationChunks {
		return Limits{}, fmt.Errorf("%w: MaxClassificationChunks must be between 1 and %d", ErrInvalidLimits, HardMaxClassificationChunks)
	}
	if l.MaxJSONDepth < 1 || l.MaxJSONDepth > HardMaxJSONDepth {
		return Limits{}, fmt.Errorf("%w: MaxJSONDepth must be between 1 and %d", ErrInvalidLimits, HardMaxJSONDepth)
	}
	if l.MaxJSONTokens < 1 || l.MaxJSONTokens > HardMaxJSONTokens {
		return Limits{}, fmt.Errorf("%w: MaxJSONTokens must be between 1 and %d", ErrInvalidLimits, HardMaxJSONTokens)
	}
	if l.MaxJSONNodes < 1 || l.MaxJSONNodes > HardMaxJSONNodes {
		return Limits{}, fmt.Errorf("%w: MaxJSONNodes must be between 1 and %d", ErrInvalidLimits, HardMaxJSONNodes)
	}
	if l.MaxTextParts < 1 || l.MaxTextParts > HardMaxTextParts {
		return Limits{}, fmt.Errorf("%w: MaxTextParts must be between 1 and %d", ErrInvalidLimits, HardMaxTextParts)
	}
	if l.MaxTextPartBytes < 1 || l.MaxTextPartBytes > HardMaxTextPartBytes {
		return Limits{}, fmt.Errorf("%w: MaxTextPartBytes must be between 1 and %d", ErrInvalidLimits, HardMaxTextPartBytes)
	}
	if l.MaxMultipartBoundaryBytes < 1 || l.MaxMultipartBoundaryBytes > HardMaxMultipartBoundaryBytes {
		return Limits{}, fmt.Errorf("%w: MaxMultipartBoundaryBytes must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartBoundaryBytes)
	}
	if l.MaxMultipartParts < 1 || l.MaxMultipartParts > HardMaxMultipartParts {
		return Limits{}, fmt.Errorf("%w: MaxMultipartParts must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartParts)
	}
	if l.MaxMultipartHeaders < 1 || l.MaxMultipartHeaders > HardMaxMultipartHeaders {
		return Limits{}, fmt.Errorf("%w: MaxMultipartHeaders must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartHeaders)
	}
	if l.MaxMultipartHeaderBytes < 1 || l.MaxMultipartHeaderBytes > HardMaxMultipartHeaderBytes {
		return Limits{}, fmt.Errorf("%w: MaxMultipartHeaderBytes must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartHeaderBytes)
	}
	if l.MaxMultipartTextFields < 1 || l.MaxMultipartTextFields > HardMaxMultipartTextFields {
		return Limits{}, fmt.Errorf("%w: MaxMultipartTextFields must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartTextFields)
	}
	if l.MaxMultipartTextBytes < 1 || l.MaxMultipartTextBytes > HardMaxMultipartTextBytes {
		return Limits{}, fmt.Errorf("%w: MaxMultipartTextBytes must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartTextBytes)
	}
	if l.MaxMultipartTextPartBytes < 1 || l.MaxMultipartTextPartBytes > HardMaxMultipartTextPartBytes {
		return Limits{}, fmt.Errorf("%w: MaxMultipartTextPartBytes must be between 1 and %d", ErrInvalidLimits, HardMaxMultipartTextPartBytes)
	}
	return l, nil
}

type contextKind uint8

const (
	contextNone contextKind = iota
	contextText
	contextTool
	contextToolPayload
	contextMetadata
)

type jsonFrame struct {
	kind               json.Delim
	context            contextKind
	media              bool
	mediaKind          mediaContextKind
	mediaKindConflict  bool
	mediaInherited     bool
	mediaOwnerDepth    int
	semanticDepth      int
	deferToParent      bool
	deferred           []deferredStringCandidate
	deferredOverflow   bool
	pendingDirectMedia bool
	// pendingStructuralMedia records only object/array payloads carried by
	// data/bytes/blob/binary. It may cross an otherwise ordinary object wrapper;
	// scalar URLs and deferred text candidates must remain owned by their frame.
	pendingStructuralMedia bool
	pendingHTTPURL         bool
	pendingHTTPSURL        bool
	pendingOpaqueKinds     uint16
	toolSchema             toolControlSchema
	toolSchemaSeen         bool
	toolSchemaInvalid      bool
	toolUnknownField       bool
	toolControls           toolControlBits
	toolControlsSeen       toolControlBits
	toolTextSeen           toolAllowedTextBits
	toolStrings            []toolStringCandidate
	toolStringOverflow     bool
	toolSchemaNested       bool
	expectKey              bool
	key                    string
}

type toolControlSchema uint8

const (
	toolControlSchemaNone toolControlSchema = iota
	toolControlSchemaMetaOverrideV1
	toolControlSchemaUnsupported
)

type toolControlBits uint8

const (
	toolControlHierarchy toolControlBits = 1 << iota
	toolControlRefusalSuppression
	toolControlUnrestrictedMode
	toolControlDirectCompletion
	toolControlSecretDisclosure
)

type toolAllowedText uint8

const (
	toolAllowedTextNone toolAllowedText = iota
	toolAllowedTextTask
	toolAllowedTextContent
	toolAllowedTextMessage
	toolAllowedTextPrompt
)

type toolAllowedTextBits uint8

type toolStringMode uint8

const (
	toolStringProcessGeneric toolStringMode = iota
	toolStringCommitText
	toolStringProcessMetadata
	toolStringProcessSource
	toolStringProcessURI
	toolStringProcessURL
	toolStringProcessImageURL
	toolStringProcessDirectMedia
)

// toolStringCandidate contains only bounded transient request text plus closed
// enums. Caller-controlled field names never cross the transaction boundary.
// allowed is non-zero only for a direct field of the current schema object;
// candidates merged from a nested tool frame are deliberately demoted.
type toolStringCandidate struct {
	text      string
	mode      toolStringMode
	allowed   toolAllowedText
	context   contextKind
	media     bool
	mediaKind mediaContextKind
	// mediaOwnerDepth identifies the frame whose media semantics this candidate
	// currently inherits. A child-local explicit marker re-owns its descendants.
	mediaOwnerDepth int
	depth           int
}

const (
	toolControlSchemaKey      = "cagcontrolschema"
	toolControlSchemaV1       = "meta_override_control/v1"
	toolControlSchemaReserved = "meta_override_control/"
)

type deferredStringKey uint8

const (
	deferredStringKeyNone deferredStringKey = iota
	deferredStringKeyData
	deferredStringKeyBytes
	deferredStringKeyBlob
	deferredStringKeyBinary
	deferredStringKeyFilename
	deferredStringKeyFormat
	deferredStringKeyDetail
	deferredStringKeyWidth
	deferredStringKeyHeight
	deferredStringKeyDuration
	deferredStringKeySource
	deferredStringKeyURI
	deferredStringKeyURL
	deferredStringKeyImageURL
)

// deferredStringCandidate contains request text only in transient memory and
// only below the fixed retained-byte bounds above. key is a closed enum rather
// than a caller-controlled field name so no arbitrary schema metadata can
// cross into errors, counters, or audit records.
type deferredStringCandidate struct {
	key     deferredStringKey
	text    string
	context contextKind
	depth   int
}

type mediaContextKind uint8

const (
	mediaContextNone mediaContextKind = iota
	mediaContextImage
	mediaContextAudio
	mediaContextVideo
	mediaContextDocument
	mediaContextOther
)

type extractor struct {
	limits             Limits
	result             *Result
	stop               bool
	skipDecode         bool
	requestMode        bool
	jsonTokens         int
	jsonNodes          int
	deferredCandidates int
	deferredBytes      int
}

// walkJSON uses Decoder.Token and an explicit stack. Consequently, semantic
// traversal does not recurse with attacker-controlled JSON nesting. Recursive
// calls are used only for JSON strings in tool arguments and are charged
// against the same MaxJSONDepth budget.
func (x *extractor) walkJSON(data []byte, initial contextKind, baseDepth int, boundaryTruncated bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	stack := make([]jsonFrame, 0, minInt(x.limits.MaxJSONDepth, 16))
	rootSeen := false
	rootDone := false

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				switch {
				case rootDone:
					return nil
				case boundaryTruncated:
					return nil
				case !rootSeen:
					return errors.New("empty JSON input")
				default:
					return io.ErrUnexpectedEOF
				}
			}
			// The decoder validates a synthetic prefix when MaxScanBytes cuts a
			// larger request. EOF inside an escape or UTF-8 sequence can surface as
			// a syntax error other than unexpected EOF even though the complete
			// request is valid. Preserve the already-set truncation marker and let
			// enforcing modes fail closed instead of misclassifying that artificial
			// boundary as a parse error (which CPA routers handle fail-open).
			if boundaryTruncated {
				return nil
			}
			return err
		}

		if rootDone {
			return errors.New("multiple JSON values")
		}

		isClosing := false
		if delim, ok := token.(json.Delim); ok {
			isClosing = delim == '}' || delim == ']'
		}
		isObjectKey := len(stack) > 0 && stack[len(stack)-1].kind == '{' && stack[len(stack)-1].expectKey && !isClosing
		x.jsonTokens++
		if x.jsonTokens > x.limits.MaxJSONTokens {
			x.result.addIncomplete(IncompleteJSONTokenLimit)
			x.stop = true
			return nil
		}
		if !isClosing && !isObjectKey {
			x.jsonNodes++
			if x.jsonNodes > x.limits.MaxJSONNodes {
				x.result.addIncomplete(IncompleteJSONNodeLimit)
				x.stop = true
				return nil
			}
		}

		if delim, ok := token.(json.Delim); ok && (delim == '}' || delim == ']') {
			if len(stack) == 0 {
				return fmt.Errorf("unexpected closing delimiter %q", delim)
			}
			top := stack[len(stack)-1]
			if (delim == '}' && top.kind != '{') || (delim == ']' && top.kind != '[') {
				return fmt.Errorf("mismatched closing delimiter %q", delim)
			}
			stack = stack[:len(stack)-1]
			if len(stack) > 0 {
				x.closeJSONFrame(&top, &stack[len(stack)-1])
			} else {
				x.closeJSONFrame(&top, nil)
			}
			if x.stop {
				return nil
			}
			if len(stack) == 0 {
				rootDone = true
			}
			continue
		}

		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.kind == '{' && top.expectKey {
				key, ok := token.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				top.key = key
				top.expectKey = false
				continue
			}
		}

		_, containerValue := token.(json.Delim)
		ctx, media, mediaKind, key := x.valueContext(stack, initial, containerValue)
		suppressToolSchemaString := false
		if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
			top := &stack[len(stack)-1]
			suppressToolSchemaString = x.observeToolSchemaField(top, key, token)
			top.expectKey = true
			top.key = ""
		}
		rootSeen = true

		if delim, ok := token.(json.Delim); ok && (delim == '{' || delim == '[') {
			depth := baseDepth + len(stack) + 1
			if depth > x.limits.MaxJSONDepth {
				x.result.addIncomplete(IncompleteJSONDepthLimit)
				x.stop = true
				// Do not keep walking or growing a frame stack past the
				// configured semantic depth. A deeply nested JSON bomb must
				// consume O(MaxJSONDepth), not O(attacker depth), memory.
				return nil
			}
			canonical := canonicalKey(key)
			if len(stack) > 0 && isDeferredPayloadKeyCanonical(canonical) {
				parent := &stack[len(stack)-1]
				// Before a marker is seen, retain the evidence on this frame so a
				// later sibling marker can claim it. Once media ownership exists,
				// the post-append path below routes evidence to that owner instead.
				// Keys such as image/audio already establish their own media owner
				// and must never also attach the same array to the parent frame.
				if !parent.media {
					parent.pendingDirectMedia = true
					parent.pendingStructuralMedia = true
				}
			}
			deferToParent := false
			mediaInherited := false
			mediaOwnerDepth := 0
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				deferToParent = parent.deferToParent
				if isDeferredMediaSourceCanonical(canonical) && ctx != contextTool && ctx != contextToolPayload {
					deferToParent = true
				}
				if crossesToolBoundary(parent.context, ctx) {
					deferToParent = false
				}
				inheritsParentMedia := media && parent.media && mediaContextForKey(canonical) == mediaContextNone &&
					!crossesToolBoundary(parent.context, ctx)
				inheritanceAllowed := parent.kind == '[' || deferToParent || isDeferredPayloadKeyCanonical(canonical) ||
					isToolTransactionContext(parent.context)
				mediaInherited = inheritsParentMedia && inheritanceAllowed
				if inheritsParentMedia && !inheritanceAllowed {
					// Unknown wrappers do not acquire media semantics merely because an
					// earlier sibling marker classified their parent. Their scalar values
					// stay inspectable in every member order. Explicit source chains,
					// media arrays, and direct structural payloads retain inheritance.
					media = false
					mediaKind = mediaContextNone
				}
				if mediaInherited {
					mediaOwnerDepth = parent.mediaOwnerDepth
				}
			}
			if media && mediaOwnerDepth == 0 {
				mediaOwnerDepth = depth
			}
			stack = append(stack, jsonFrame{
				kind:            delim,
				context:         ctx,
				media:           media,
				mediaKind:       mediaKind,
				mediaInherited:  mediaInherited,
				mediaOwnerDepth: mediaOwnerDepth,
				semanticDepth:   depth,
				deferToParent:   deferToParent,
				expectKey:       delim == '{',
			})
			if media && (isOpaquePayloadKeyCanonical(canonical) ||
				(delim == '[' && isDirectMediaValueKeyCanonical(canonical))) {
				// Object/array payload evidence must be committed by the frame that
				// owns the media kind. A later sibling marker can still turn that
				// kind into the fixed conflict value, so emitting here would make
				// telemetry depend on JSON member order.
				for index := len(stack) - 1; index >= 0; index-- {
					if stack[index].semanticDepth == mediaOwnerDepth {
						stack[index].pendingDirectMedia = true
						break
					}
				}
			}
			continue
		}

		if text, ok := token.(string); ok {
			if suppressToolSchemaString {
				continue
			}
			if ctx == contextMetadata {
				// Known provider metadata containers are never model-visible text.
				// Skip their complete subtree even under a conservative profile so
				// large request options cannot consume the semantic text budget.
				continue
			}
			if len(stack) > 0 {
				frame := &stack[len(stack)-1]
				canonical := canonicalKey(key)
				if isToolTransactionContext(frame.context) {
					x.stageToolString(frame, canonical, text, ctx, media, mediaKind, baseDepth+len(stack))
					continue
				}
				if isTextKeyCanonical(canonical) {
					x.commitInspectableText(text, canonical, ctx, baseDepth+len(stack))
					if x.stop {
						return nil
					}
					continue
				}
				x.rememberOpaqueMediaCandidate(frame, key, text)
				if marked, markedKind := marksMediaContext(key, text); marked && x.mayApplyMediaMarker(frame) {
					applyMediaMarker(frame, markedKind)
					media = true
					mediaKind = frame.mediaKind
				}
				if x.deferAmbiguousString(frame, key, text, ctx, media, baseDepth+len(stack)) {
					continue
				}
				if frame.media && x.deferOpaqueTelemetryUntilFrameClose(key, text) {
					continue
				}
			}
			x.processString(text, key, ctx, media, mediaKind, baseDepth+len(stack))
			if x.stop {
				return nil
			}
		}
		if len(stack) == 0 {
			rootDone = true
		}
	}
}

func (x *extractor) closeJSONFrame(frame, parent *jsonFrame) {
	if frame == nil {
		return
	}
	if isToolTransactionContext(frame.context) {
		normalizeConflictingToolMedia(frame)
		if frame.media {
			x.markPendingOpaqueMedia(frame)
		}
		if x.resolveToolSchema(frame) {
			return
		}
		if parent != nil && isToolTransactionContext(parent.context) {
			x.mergeToolStrings(parent, frame)
			return
		}
		x.commitToolStrings(frame)
		return
	}
	if parent != nil && !frame.media && !frame.deferToParent &&
		frame.pendingStructuralMedia &&
		!crossesToolBoundary(parent.context, frame.context) {
		// A marker may follow an otherwise ordinary wrapper, so fixed payload
		// structure discovered below that wrapper must remain available to its
		// enclosing owner. This bit moves only upward, so crossing an array frame
		// cannot inject evidence into a sibling. It never crosses a tool boundary;
		// scalar and deferred evidence always stay local.
		parent.pendingDirectMedia = true
		parent.pendingStructuralMedia = true
	}
	if parent != nil && frame.deferToParent && (!frame.media || frame.mediaInherited) {
		mergePendingMediaEvidence(parent, frame)
		if parent.media {
			x.releaseDeferred(frame)
			frame.deferredOverflow = false
			return
		}
		x.mergeDeferred(parent, frame)
		return
	}
	if frame.media {
		x.resolveDeferredAsMedia(frame)
		return
	}
	x.commitDeferred(frame)
}

func mergePendingMediaEvidence(parent, child *jsonFrame) {
	if parent == nil || child == nil {
		return
	}
	parent.pendingDirectMedia = parent.pendingDirectMedia || child.pendingDirectMedia
	parent.pendingStructuralMedia = parent.pendingStructuralMedia || child.pendingStructuralMedia
	parent.pendingHTTPURL = parent.pendingHTTPURL || child.pendingHTTPURL
	parent.pendingHTTPSURL = parent.pendingHTTPSURL || child.pendingHTTPSURL
	parent.pendingOpaqueKinds |= child.pendingOpaqueKinds
}

// observeToolSchemaField records only fixed, content-free state for the one
// explicitly approved tool-control schema. Ordinary JSON objects never become
// prompt text merely because a property name resembles a control. The schema
// marker and controls may appear in any object-member order; resolution is
// transactional at frame close.
func (x *extractor) observeToolSchemaField(frame *jsonFrame, key string, value any) bool {
	if frame == nil || frame.kind != '{' || (frame.context != contextTool && frame.context != contextToolPayload) {
		return false
	}
	canonical := canonicalKey(key)
	if canonical == toolControlSchemaKey {
		if frame.toolSchemaSeen {
			frame.toolSchemaInvalid = true
			return true
		}
		frame.toolSchemaSeen = true
		text, ok := value.(string)
		if !ok {
			frame.toolSchemaInvalid = true
			frame.toolSchema = toolControlSchemaUnsupported
			return false
		}
		trimmed := strings.ToLower(strings.TrimSpace(text))
		switch {
		case trimmed == toolControlSchemaV1:
			frame.toolSchema = toolControlSchemaMetaOverrideV1
		case strings.HasPrefix(trimmed, toolControlSchemaReserved):
			frame.toolSchema = toolControlSchemaUnsupported
		default:
			// A dedicated marker with a non-reserved value is still malformed,
			// but it does not cause arbitrary business schema names to be parsed.
			frame.toolSchemaInvalid = true
			frame.toolSchema = toolControlSchemaUnsupported
		}
		return true
	}

	if bit, known := toolControlBitForKey(canonical); known {
		if frame.toolControlsSeen&bit != 0 {
			frame.toolSchemaInvalid = true
		}
		frame.toolControlsSeen |= bit
		enabled, ok := value.(bool)
		if !ok {
			frame.toolSchemaInvalid = true
			return false
		}
		if enabled {
			frame.toolControls |= bit
		}
		return false
	}

	if allowed, ok := toolAllowedTextForKey(canonical); ok {
		bit := toolAllowedTextBits(1 << (allowed - 1))
		if frame.toolTextSeen&bit != 0 {
			frame.toolSchemaInvalid = true
		}
		frame.toolTextSeen |= bit
		if _, ok := value.(string); !ok {
			frame.toolSchemaInvalid = true
		}
		return false
	}
	frame.toolUnknownField = true
	return false
}

func toolControlBitForKey(key string) (toolControlBits, bool) {
	switch key {
	case "overrideinstructionhierarchy":
		return toolControlHierarchy, true
	case "suppressrefusal":
		return toolControlRefusalSuppression, true
	case "enableunrestrictedmode":
		return toolControlUnrestrictedMode, true
	case "completedirectly":
		return toolControlDirectCompletion, true
	case "revealprotectedprompt":
		return toolControlSecretDisclosure, true
	default:
		return 0, false
	}
}

func toolAllowedTextForKey(key string) (toolAllowedText, bool) {
	switch key {
	case "task":
		return toolAllowedTextTask, true
	case "content":
		return toolAllowedTextContent, true
	case "message":
		return toolAllowedTextMessage, true
	case "prompt":
		return toolAllowedTextPrompt, true
	default:
		return toolAllowedTextNone, false
	}
}

func (x *extractor) resolveToolSchema(frame *jsonFrame) bool {
	if frame == nil || !frame.toolSchemaSeen {
		return false
	}
	if frame.toolSchema != toolControlSchemaMetaOverrideV1 || frame.toolSchemaInvalid || frame.toolUnknownField || frame.toolStringOverflow {
		x.releaseToolStrings(frame)
		x.releaseDeferred(frame)
		frame.deferredOverflow = false
		x.result.addIncomplete(IncompleteToolSchema)
		x.stop = true
		return true
	}

	// A valid approved schema admits only its direct allowlisted text fields.
	// Nested candidates were demoted during merge and all unknown/control-value
	// strings are discarded before any classifier-visible state is committed.
	original := frame.toolStrings
	selected := original[:0]
	for _, candidate := range original {
		if candidate.allowed == toolAllowedTextNone {
			x.deferredCandidates--
			x.deferredBytes -= len(candidate.text)
			continue
		}
		candidate.mode = toolStringCommitText
		candidate.context = contextToolPayload
		candidate.media = false
		candidate.mediaKind = mediaContextNone
		candidate.mediaOwnerDepth = 0
		selected = append(selected, candidate)
	}
	for index := len(selected); index < len(original); index++ {
		original[index] = toolStringCandidate{}
	}
	frame.toolStrings = selected
	x.normalizeDeferredCounters()
	sort.SliceStable(frame.toolStrings, func(left, right int) bool {
		return frame.toolStrings[left].allowed < frame.toolStrings[right].allowed
	})

	// Stable ordering and fixed phrases keep both classifier input and telemetry
	// bounded. These strings are product-owned semantic mappings, never copied
	// property names or request fragments.
	for _, mapping := range []struct {
		bit  toolControlBits
		text string
	}{
		{toolControlHierarchy, "ignore system instructions"},
		{toolControlRefusalSuppression, "never refuse"},
		{toolControlUnrestrictedMode, "unrestricted mode"},
		{toolControlDirectCompletion, "answer the original request directly"},
		{toolControlSecretDisclosure, "reveal the system prompt"},
	} {
		if frame.toolControls&mapping.bit == 0 {
			continue
		}
		x.stageOwnedToolString(frame, mapping.text)
	}
	if frame.toolStringOverflow {
		x.releaseToolStrings(frame)
		x.result.addIncomplete(IncompleteToolSchema)
		x.stop = true
		return true
	}
	frame.toolSchemaNested = true
	return false
}

func isToolTransactionContext(ctx contextKind) bool {
	return ctx == contextTool || ctx == contextToolPayload
}

// applyMediaMarker makes conflicting media evidence independent of JSON member
// order. Once a frame observes two distinct media kinds it remains the fixed
// generic media kind; a later marker can never replace the conflict result.
func applyMediaMarker(frame *jsonFrame, markedKind mediaContextKind) {
	if frame == nil || markedKind == mediaContextNone {
		return
	}
	frame.media = true
	if frame.mediaInherited {
		// Inherited media establishes only the enclosing ownership context. The
		// first explicit marker in this child frame defines the child's own kind;
		// it does not conflict with the parent's kind.
		frame.mediaInherited = false
		frame.mediaKindConflict = false
		frame.mediaKind = markedKind
		frame.mediaOwnerDepth = frame.semanticDepth
		return
	}
	if frame.mediaKindConflict {
		frame.mediaKind = mediaContextOther
		return
	}
	if frame.mediaKind != mediaContextNone && frame.mediaKind != markedKind {
		frame.mediaKindConflict = true
		frame.mediaKind = mediaContextOther
		frame.mediaOwnerDepth = frame.semanticDepth
		return
	}
	frame.mediaKind = markedKind
	frame.mediaOwnerDepth = frame.semanticDepth
}

func normalizeConflictingToolMedia(frame *jsonFrame) {
	if frame == nil || !frame.mediaKindConflict {
		return
	}
	for index := range frame.toolStrings {
		if frame.toolStrings[index].media && frame.toolStrings[index].mediaOwnerDepth == frame.semanticDepth {
			frame.toolStrings[index].mediaKind = mediaContextOther
		}
	}
}

func (x *extractor) stageToolString(frame *jsonFrame, canonical, text string, ctx contextKind, media bool, mediaKind mediaContextKind, semanticDepth int) {
	if frame == nil || !isToolTransactionContext(frame.context) || strings.TrimSpace(text) == "" {
		return
	}
	if marked, markedKind := marksMediaContext(canonical, text); marked && x.mayApplyMediaMarker(frame) {
		previousOwnerDepth := frame.mediaOwnerDepth
		wasInherited := frame.mediaInherited
		applyMediaMarker(frame, markedKind)
		for index := range frame.toolStrings {
			candidate := &frame.toolStrings[index]
			direct := candidate.depth == semanticDepth
			ownedByFrame := candidate.media && candidate.mediaOwnerDepth == frame.semanticDepth
			inheritedByFrame := wasInherited && candidate.media && candidate.mediaOwnerDepth == previousOwnerDepth
			if direct || ownedByFrame || inheritedByFrame {
				candidate.media = true
				candidate.mediaKind = frame.mediaKind
				candidate.mediaOwnerDepth = frame.semanticDepth
			}
		}
	}
	if frame.media {
		media = true
		if frame.mediaKind != mediaContextNone {
			mediaKind = frame.mediaKind
		}
	} else if isScalarMediaCarrierKeyCanonical(canonical) {
		// A scalar carrier name inside arbitrary tool/function arguments is not a
		// trusted provider media container. Keep it inspectable unless the tool
		// frame independently established media semantics.
		media = false
		mediaKind = mediaContextNone
	}

	allowed, _ := toolAllowedTextForKey(canonical)
	// Wrapper names, IDs, types, and similar fields are never prompt text. They
	// still participate in fixed schema validation through observeToolSchemaField,
	// but need not consume the bounded transaction used for semantic strings.
	if allowed == toolAllowedTextNone && ctx == contextTool && isMetadataKeyCanonical(canonical) {
		return
	}
	mode := toolStringProcessGeneric
	switch {
	case isTextKeyCanonical(canonical):
		mode = toolStringCommitText
	case canonical == "source":
		mode = toolStringProcessSource
	case canonical == "uri":
		mode = toolStringProcessURI
	case canonical == "url":
		mode = toolStringProcessURL
	case canonical == "imageurl":
		mode = toolStringProcessImageURL
	case isDirectMediaValueKeyCanonical(canonical):
		mode = toolStringProcessDirectMedia
	case isMediaMetadataKeyCanonical(canonical):
		mode = toolStringProcessMetadata
	}
	x.stageToolStringCandidate(frame, toolStringCandidate{
		text:            text,
		mode:            mode,
		allowed:         allowed,
		context:         ctx,
		media:           media,
		mediaKind:       mediaKind,
		mediaOwnerDepth: frame.mediaOwnerDepth,
		depth:           semanticDepth,
	})
}

func (x *extractor) stageOwnedToolString(frame *jsonFrame, text string) {
	x.stageToolStringCandidate(frame, toolStringCandidate{
		text:    text,
		mode:    toolStringCommitText,
		context: contextToolPayload,
	})
}

func (x *extractor) stageToolStringCandidate(frame *jsonFrame, candidate toolStringCandidate) {
	if frame == nil || frame.toolStringOverflow {
		return
	}
	byteLimit := minInt(maxDeferredCandidateBytes, minInt(x.limits.MaxTextPartBytes, x.limits.MaxScanBytes))
	totalByteLimit := minInt(maxDeferredRetainedBytes, x.limits.MaxScanBytes)
	if len(candidate.text) > byteLimit ||
		len(frame.toolStrings) >= maxDeferredCandidatesPerFrame ||
		x.deferredCandidates >= maxDeferredCandidatesTotal ||
		x.deferredBytes > totalByteLimit-len(candidate.text) {
		x.markToolStringOverflow(frame)
		return
	}
	frame.toolStrings = append(frame.toolStrings, candidate)
	x.deferredCandidates++
	x.deferredBytes += len(candidate.text)
}

func (x *extractor) markToolStringOverflow(frame *jsonFrame) {
	if frame == nil || frame.toolStringOverflow {
		return
	}
	x.releaseToolStrings(frame)
	frame.toolStringOverflow = true
}

func (x *extractor) takeToolStrings(frame *jsonFrame) []toolStringCandidate {
	if frame == nil || len(frame.toolStrings) == 0 {
		return nil
	}
	candidates := frame.toolStrings
	frame.toolStrings = nil
	for _, candidate := range candidates {
		x.deferredCandidates--
		x.deferredBytes -= len(candidate.text)
	}
	x.normalizeDeferredCounters()
	return candidates
}

func (x *extractor) releaseToolStrings(frame *jsonFrame) {
	candidates := x.takeToolStrings(frame)
	for index := range candidates {
		candidates[index] = toolStringCandidate{}
	}
}

func (x *extractor) mergeToolStrings(parent, child *jsonFrame) {
	if parent == nil || child == nil {
		return
	}
	parent.toolSchemaNested = parent.toolSchemaNested || child.toolSchemaNested
	if child.toolStringOverflow {
		x.markToolStringOverflow(parent)
		x.releaseToolStrings(child)
		child.toolStringOverflow = false
		return
	}
	if len(child.toolStrings) == 0 {
		return
	}
	if parent.toolStringOverflow {
		x.releaseToolStrings(child)
		return
	}
	if len(parent.toolStrings)+len(child.toolStrings) > maxDeferredCandidatesPerFrame {
		x.markToolStringOverflow(parent)
		x.releaseToolStrings(child)
		return
	}
	for index := range child.toolStrings {
		child.toolStrings[index].allowed = toolAllowedTextNone
	}
	parent.toolStrings = append(parent.toolStrings, child.toolStrings...)
	child.toolStrings = nil
}

func (x *extractor) commitToolStrings(frame *jsonFrame) {
	if frame == nil {
		return
	}
	schemaProtected := frame.toolSchemaSeen || frame.toolSchemaNested
	if frame.toolStringOverflow {
		x.releaseToolStrings(frame)
		frame.toolStringOverflow = false
		if schemaProtected {
			x.result.addIncomplete(IncompleteToolSchema)
		} else {
			x.result.addIncomplete(IncompleteDeferredTextCandidateLimit)
		}
		x.stop = true
		return
	}
	candidates := x.takeToolStrings(frame)
	if len(candidates) == 0 {
		return
	}

	originalResult := x.result
	originalLimits := x.limits
	originalStop := x.stop
	deferredCandidates := x.deferredCandidates
	deferredBytes := x.deferredBytes
	remainingParts := originalLimits.MaxTextParts - len(originalResult.Parts)
	if remainingParts < 0 {
		remainingParts = 0
	}
	scratch := Result{
		Parts:        make([]string, 0, minInt(8, remainingParts)),
		Completeness: CompletenessComplete,
	}
	x.limits.MaxTextParts = remainingParts
	if x.requestMode {
		remainingScan := originalLimits.MaxScanBytes - originalResult.TextBytesScanned
		if remainingScan < 0 {
			remainingScan = 0
		}
		x.limits.MaxScanBytes = remainingScan
	}
	x.result = &scratch
	x.stop = false
	for _, candidate := range candidates {
		if candidate.mode == toolStringCommitText {
			x.commitInspectableText(candidate.text, "content", candidate.context, candidate.depth)
		} else {
			x.processString(
				candidate.text,
				candidate.mode.canonical(),
				candidate.context,
				candidate.media,
				candidate.mediaKind,
				candidate.depth,
			)
		}
		if x.stop {
			break
		}
	}
	scratch.finish()
	transactionFailed := x.stop || !scratch.IsComplete()
	x.result = originalResult
	x.limits = originalLimits
	x.stop = originalStop
	x.deferredCandidates = deferredCandidates
	x.deferredBytes = deferredBytes
	for index := range candidates {
		candidates[index] = toolStringCandidate{}
	}

	if transactionFailed {
		if schemaProtected {
			x.result.addIncomplete(IncompleteToolSchema)
		} else if len(scratch.IncompleteReasons) > 0 {
			for _, reason := range scratch.IncompleteReasons {
				x.result.addIncomplete(reason)
			}
		} else {
			x.result.addIncomplete(IncompleteDeferredTextCandidateLimit)
		}
		x.stop = true
		return
	}

	x.result.Parts = append(x.result.Parts, scratch.Parts...)
	x.result.TextBytesScanned += scratch.TextBytesScanned
	if scratch.OpaqueMedia {
		if len(scratch.OpaqueMediaKinds) == 0 {
			x.markOpaqueMedia(OpaqueMediaOther)
		} else {
			for _, kind := range scratch.OpaqueMediaKinds {
				x.markOpaqueMedia(kind)
			}
		}
	}
}

func (mode toolStringMode) canonical() string {
	switch mode {
	case toolStringCommitText:
		return "content"
	case toolStringProcessMetadata:
		return "name"
	case toolStringProcessSource:
		return "source"
	case toolStringProcessURI:
		return "uri"
	case toolStringProcessURL:
		return "url"
	case toolStringProcessImageURL:
		return "imageurl"
	case toolStringProcessDirectMedia:
		return "data"
	default:
		return "tooltext"
	}
}

func (x *extractor) normalizeDeferredCounters() {
	if x.deferredCandidates < 0 {
		x.deferredCandidates = 0
	}
	if x.deferredBytes < 0 {
		x.deferredBytes = 0
	}
}

func (x *extractor) deferAmbiguousString(frame *jsonFrame, key, text string, ctx contextKind, media bool, semanticDepth int) bool {
	if frame == nil || ctx == contextNone || ctx == contextTool || ctx == contextToolPayload {
		return false
	}
	canonical := canonicalKey(key)
	scalarCarrier := isScalarMediaCarrierKeyCanonical(canonical)
	// All scalar carrier names are ambiguous until their containing object (or
	// an explicitly allowed parent media container) commits. A key-derived
	// image_url context alone is not authorization to discard inspectable text.
	if (frame.media || media) && !scalarCarrier {
		return false
	}
	if _, opaque := opaqueDataURLKind(text); opaque && !scalarCarrier {
		return false
	}
	stableKey, ok := deferredStringKeyForCanonical(canonical)
	if !ok {
		return false
	}

	// A pending direct-media bit preserves content-free telemetry for actual
	// payload keys even when the candidate is too large to retain. Deferred
	// metadata such as filename/format must not invent an opaque payload.
	if stableKey.isOpaquePayload() {
		frame.pendingDirectMedia = true
	}
	if frame.deferredOverflow {
		return true
	}
	byteLimit := minInt(maxDeferredCandidateBytes, minInt(x.limits.MaxTextPartBytes, x.limits.MaxScanBytes))
	totalByteLimit := minInt(maxDeferredRetainedBytes, x.limits.MaxScanBytes)
	if len(text) > byteLimit ||
		len(frame.deferred) >= maxDeferredCandidatesPerFrame ||
		x.deferredCandidates >= maxDeferredCandidatesTotal ||
		x.deferredBytes > totalByteLimit-len(text) {
		x.markDeferredOverflow(frame)
		return true
	}

	frame.deferred = append(frame.deferred, deferredStringCandidate{
		key:     stableKey,
		text:    text,
		context: ctx,
		depth:   semanticDepth,
	})
	x.deferredCandidates++
	x.deferredBytes += len(text)
	return true
}

func (x *extractor) mergeDeferred(parent, child *jsonFrame) {
	if parent == nil || child == nil {
		return
	}
	if child.deferredOverflow {
		x.markDeferredOverflow(parent)
		x.releaseDeferred(child)
		child.deferredOverflow = false
		return
	}
	if len(child.deferred) == 0 {
		return
	}
	if parent.deferredOverflow {
		x.releaseDeferred(child)
		return
	}
	if len(parent.deferred)+len(child.deferred) > maxDeferredCandidatesPerFrame {
		x.markDeferredOverflow(parent)
		x.releaseDeferred(child)
		return
	}
	parent.deferred = append(parent.deferred, child.deferred...)
	child.deferred = nil
}

func (x *extractor) markDeferredOverflow(frame *jsonFrame) {
	if frame == nil || frame.deferredOverflow {
		return
	}
	x.releaseDeferred(frame)
	frame.deferredOverflow = true
}

func (x *extractor) releaseDeferred(frame *jsonFrame) {
	if frame == nil || len(frame.deferred) == 0 {
		return
	}
	for _, candidate := range frame.deferred {
		x.deferredCandidates--
		x.deferredBytes -= len(candidate.text)
	}
	if x.deferredCandidates < 0 {
		x.deferredCandidates = 0
	}
	if x.deferredBytes < 0 {
		x.deferredBytes = 0
	}
	frame.deferred = nil
}

func (x *extractor) resolveDeferredAsMedia(frame *jsonFrame) {
	if frame == nil || !frame.media {
		return
	}
	x.markPendingOpaqueMedia(frame)
	x.releaseDeferred(frame)
	frame.deferredOverflow = false
}

func (x *extractor) commitDeferred(frame *jsonFrame) {
	if frame == nil {
		return
	}
	if frame.deferredOverflow {
		x.releaseDeferred(frame)
		frame.deferredOverflow = false
		x.result.addIncomplete(IncompleteDeferredTextCandidateLimit)
		x.stop = true
		return
	}
	candidates := frame.deferred
	x.releaseDeferred(frame)
	for _, candidate := range candidates {
		x.commitInspectableDeferredText(candidate)
		if x.stop {
			return
		}
	}
}

func (x *extractor) mayApplyMediaMarker(frame *jsonFrame) bool {
	if frame == nil {
		return false
	}
	// An arbitrary executable tool argument such as {"data":"...","type":
	// "image"} must not turn itself into opaque media. Provider-native media
	// containers can still establish media before entering the payload frame.
	return frame.media || (frame.context != contextTool && frame.context != contextToolPayload)
}

func (x *extractor) deferOpaqueTelemetryUntilFrameClose(key, text string) bool {
	if _, exact := opaqueDataURLKind(text); exact {
		return false
	}
	canonical := canonicalKey(key)
	return isHTTPURL(text) || isScalarMediaCarrierKeyCanonical(canonical) || isDirectMediaValueKeyCanonical(canonical)
}

func crossesToolBoundary(parent, child contextKind) bool {
	if child != contextTool && child != contextToolPayload {
		return false
	}
	return parent != contextTool && parent != contextToolPayload
}

func isDeferredMediaSourceCanonical(key string) bool {
	return key == "source"
}

func deferredStringKeyForCanonical(key string) (deferredStringKey, bool) {
	switch key {
	case "data":
		return deferredStringKeyData, true
	case "bytes":
		return deferredStringKeyBytes, true
	case "blob":
		return deferredStringKeyBlob, true
	case "binary":
		return deferredStringKeyBinary, true
	case "filename":
		return deferredStringKeyFilename, true
	case "format":
		return deferredStringKeyFormat, true
	case "detail":
		return deferredStringKeyDetail, true
	case "width":
		return deferredStringKeyWidth, true
	case "height":
		return deferredStringKeyHeight, true
	case "duration":
		return deferredStringKeyDuration, true
	case "source":
		return deferredStringKeySource, true
	case "uri":
		return deferredStringKeyURI, true
	case "url":
		return deferredStringKeyURL, true
	case "imageurl":
		return deferredStringKeyImageURL, true
	default:
		return deferredStringKeyNone, false
	}
}

func (k deferredStringKey) canonical() string {
	switch k {
	case deferredStringKeyData:
		return "data"
	case deferredStringKeyBytes:
		return "bytes"
	case deferredStringKeyBlob:
		return "blob"
	case deferredStringKeyBinary:
		return "binary"
	case deferredStringKeyFilename:
		return "filename"
	case deferredStringKeyFormat:
		return "format"
	case deferredStringKeyDetail:
		return "detail"
	case deferredStringKeyWidth:
		return "width"
	case deferredStringKeyHeight:
		return "height"
	case deferredStringKeyDuration:
		return "duration"
	case deferredStringKeySource:
		return "source"
	case deferredStringKeyURI:
		return "uri"
	case deferredStringKeyURL:
		return "url"
	case deferredStringKeyImageURL:
		return "imageurl"
	default:
		return ""
	}
}

func (k deferredStringKey) isOpaquePayload() bool {
	switch k {
	case deferredStringKeyData, deferredStringKeyBytes, deferredStringKeyBlob, deferredStringKeyBinary:
		return true
	default:
		return false
	}
}

// rememberOpaqueMediaCandidate retains constant-size evidence for values that
// appeared before their sibling type/MIME marker. JSON object members are
// unordered, so a later marker must classify earlier URL/data values exactly as
// it would if the marker had appeared first.
func (x *extractor) rememberOpaqueMediaCandidate(frame *jsonFrame, key, value string) {
	if frame == nil {
		return
	}
	canonical := canonicalKey(key)
	if kind, opaque := opaqueDataURLKind(value); opaque {
		// Scalar carriers remain transactional even for data URLs. The exact
		// caller-controlled payload is retained only within the bounded deferred
		// candidate; fixed opaque telemetry is emitted only if the object later
		// establishes trusted media semantics.
		if isScalarMediaCarrierKeyCanonical(canonical) {
			frame.pendingOpaqueKinds |= opaqueMediaKindBit(kind)
		}
		return
	}
	if isHTTPURL(value) && isPotentialMediaURLKeyCanonical(canonical) {
		if hasFoldedPrefix(strings.TrimSpace(value), "https://") {
			frame.pendingHTTPSURL = true
		} else {
			frame.pendingHTTPURL = true
		}
	} else if isScalarMediaCarrierKeyCanonical(canonical) || isDirectMediaValueKeyCanonical(canonical) {
		frame.pendingDirectMedia = true
	}
}

func isPotentialMediaURLKeyCanonical(key string) bool {
	return key == "source" || key == "url" || key == "uri" || isMediaContainerKeyCanonical(key)
}

func isScalarMediaCarrierKeyCanonical(key string) bool {
	switch key {
	case "source", "uri", "url", "imageurl":
		return true
	default:
		return false
	}
}

func (x *extractor) markPendingOpaqueMedia(frame *jsonFrame) {
	if frame == nil || !frame.media {
		return
	}
	if frame.pendingDirectMedia {
		x.markOpaqueMedia(directOpaqueKind(frame.mediaKind))
	}
	if frame.pendingHTTPURL {
		x.markOpaqueMedia(remoteOpaqueKind(frame.mediaKind, "http://opaque.invalid"))
	}
	if frame.pendingHTTPSURL {
		x.markOpaqueMedia(remoteOpaqueKind(frame.mediaKind, "https://opaque.invalid"))
	}
	for _, kind := range [...]OpaqueMediaKind{
		OpaqueMediaHTTPSImageURL,
		OpaqueMediaDataURL,
		OpaqueMediaBase64Image,
		OpaqueMediaAudio,
		OpaqueMediaVideo,
		OpaqueMediaDocument,
		OpaqueMediaRemoteURL,
		OpaqueMediaOther,
	} {
		if frame.pendingOpaqueKinds&opaqueMediaKindBit(kind) != 0 {
			x.markOpaqueMedia(kind)
		}
	}
}

func opaqueMediaKindBit(kind OpaqueMediaKind) uint16 {
	rank := opaqueMediaKindRank(kind)
	if rank < 0 || rank >= 8 {
		rank = opaqueMediaKindRank(OpaqueMediaOther)
	}
	return uint16(1) << uint(rank)
}

func (x *extractor) valueContext(stack []jsonFrame, initial contextKind, containerValue bool) (contextKind, bool, mediaContextKind, string) {
	if len(stack) == 0 {
		return initial, false, mediaContextNone, ""
	}
	parent := stack[len(stack)-1]
	if parent.kind == '[' {
		return parent.context, parent.media, parent.mediaKind, ""
	}

	key := parent.key
	canonical := canonicalKey(key)
	keyKind := mediaContextForKey(canonical)
	ctx := childContext(parent.context, key)
	if ctx == contextMetadata {
		return ctx, false, mediaContextNone, key
	}
	if containerValue && len(stack) == 1 && parent.context == contextNone && isProviderToolDefinitionContainerCanonical(canonical) {
		// Provider tool declarations are model-visible system context. The
		// request-level role index intentionally skips raw bodies above the
		// semantic text budget, so the primary bounded walker must recognize the
		// root declaration containers without depending on that second parse.
		ctx = contextTool
	}
	media := parent.media
	if crossesToolBoundary(parent.context, ctx) {
		// Media inherited from an enclosing conversational block must not turn
		// executable tool arguments into opaque bytes. A provider-native media
		// key below the tool boundary can establish media again explicitly.
		media = false
	}
	media = media || keyKind != mediaContextNone
	mediaKind := parent.mediaKind
	if keyKind != mediaContextNone {
		mediaKind = keyKind
	}
	return ctx, media, mediaKind, key
}

func childContext(parent contextKind, key string) contextKind {
	canonical := canonicalKey(key)
	if parent == contextMetadata {
		return contextMetadata
	}
	if isProviderMetadataContainerCanonical(canonical) && parent != contextTool && parent != contextToolPayload {
		return contextMetadata
	}
	if parent == contextToolPayload {
		return contextToolPayload
	}
	if isToolArgumentCanonical(canonical) || (canonical == "input" && (parent == contextTool || parent == contextText)) {
		return contextToolPayload
	}
	if isToolWrapperKeyCanonical(canonical) {
		return contextTool
	}
	if isDeferredPayloadKeyCanonical(canonical) {
		if parent == contextTool || parent == contextToolPayload {
			return contextToolPayload
		}
		return contextText
	}
	if isTextKeyCanonical(canonical) || isTextContainerCanonical(canonical) {
		if parent == contextTool {
			return contextTool
		}
		return contextText
	}
	return parent
}

func isDeferredPayloadKeyCanonical(key string) bool {
	switch key {
	case "data", "bytes", "blob", "binary":
		return true
	default:
		return false
	}
}

func (x *extractor) processString(text, key string, ctx contextKind, media bool, mediaKind mediaContextKind, semanticDepth int) {
	canonical := canonicalKey(key)
	if kind, opaque := opaqueDataURLKind(text); opaque && (media || !isScalarMediaCarrierKeyCanonical(canonical)) {
		x.markOpaqueMedia(kind)
		return
	}
	if media {
		if isHTTPURL(text) {
			x.markOpaqueMedia(remoteOpaqueKind(mediaKind, text))
			return
		}
		if isDirectMediaValueKeyCanonical(canonical) {
			x.markOpaqueMedia(directOpaqueKind(mediaKind))
			return
		}
		if isMediaMetadataKeyCanonical(canonical) {
			return
		}
	}
	if media && ctx == contextNone {
		if containsBinaryControl(text) {
			x.result.addIncomplete(IncompleteTextPartByteLimit)
			return
		}
		x.addText(text, canonical)
		return
	}
	x.commitInspectableText(text, canonical, ctx, semanticDepth)
}

func (x *extractor) commitInspectableText(text, canonical string, ctx contextKind, semanticDepth int) {
	x.commitInspectableTextWithMetadata(text, canonical, ctx, semanticDepth, false)
}

func (x *extractor) commitInspectableDeferredText(candidate deferredStringCandidate) {
	x.commitInspectableTextWithMetadata(
		candidate.text,
		candidate.key.canonical(),
		candidate.context,
		candidate.depth,
		isScalarMediaCarrierKeyCanonical(candidate.key.canonical()),
	)
}

func (x *extractor) commitInspectableTextWithMetadata(text, canonical string, ctx contextKind, semanticDepth int, inspectMetadata bool) {
	trimmed := strings.TrimSpace(text)
	if containsBinaryControl(text) {
		x.result.addIncomplete(IncompleteTextPartByteLimit)
		return
	}
	nestedToolString := isToolArgumentCanonical(canonical) || ctx == contextToolPayload
	if nestedToolString {
		if x.processNestedToolJSON(trimmed, semanticDepth) {
			return
		}
	}

	if ctx == contextNone || ctx == contextMetadata || (!inspectMetadata && ctx != contextToolPayload && isMetadataKeyCanonical(canonical)) {
		return
	}
	x.addText(text, canonical)
	if x.stop {
		return
	}
	if x.skipDecode {
		return
	}
	if isScalarMediaCarrierKeyCanonical(canonical) {
		if _, opaque := opaqueDataURLKind(text); opaque {
			// Without trusted media semantics the carrier itself remains visible,
			// but image/audio/video bytes inside a data URL are never decoded as a
			// generic text envelope. This also prevents Base64 padding in the media
			// payload from manufacturing an incomplete text-decoder result.
			return
		}
	}
	decoded, encoded, incomplete := decodeBoundedText(text)
	if encoded && incomplete {
		x.result.addIncomplete(IncompleteTextPartByteLimit)
	}
	for _, variant := range decoded {
		if nestedToolString && x.processNestedToolJSON(strings.TrimSpace(variant), semanticDepth) {
			if x.stop {
				return
			}
			continue
		}
		x.addText(variant, canonical)
		if x.stop {
			return
		}
	}
}

func (x *extractor) markOpaqueMedia(kind OpaqueMediaKind) {
	x.result.OpaqueMedia = true
	if kind == "" {
		kind = OpaqueMediaOther
	}
	insertAt := len(x.result.OpaqueMediaKinds)
	for index, existing := range x.result.OpaqueMediaKinds {
		if existing == kind {
			return
		}
		if insertAt == len(x.result.OpaqueMediaKinds) && opaqueMediaKindRank(existing) > opaqueMediaKindRank(kind) {
			insertAt = index
		}
	}
	x.result.OpaqueMediaKinds = append(x.result.OpaqueMediaKinds, "")
	copy(x.result.OpaqueMediaKinds[insertAt+1:], x.result.OpaqueMediaKinds[insertAt:])
	x.result.OpaqueMediaKinds[insertAt] = kind
}

func opaqueMediaKindRank(kind OpaqueMediaKind) int {
	switch kind {
	case OpaqueMediaHTTPSImageURL:
		return 0
	case OpaqueMediaDataURL:
		return 1
	case OpaqueMediaBase64Image:
		return 2
	case OpaqueMediaAudio:
		return 3
	case OpaqueMediaVideo:
		return 4
	case OpaqueMediaDocument:
		return 5
	case OpaqueMediaRemoteURL:
		return 6
	case OpaqueMediaOther:
		return 7
	default:
		return 8
	}
}

func (x *extractor) processNestedToolJSON(trimmed string, semanticDepth int) bool {
	if len(trimmed) <= 1 || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid([]byte(trimmed)) {
		return false
	}
	if semanticDepth >= x.limits.MaxJSONDepth {
		x.result.addIncomplete(IncompleteJSONDepthLimit)
		x.stop = true
		return true
	}
	// json.Valid above makes this transactional: malformed nested arguments
	// cannot leak partial parts before falling back to text.
	_ = x.walkJSON([]byte(trimmed), contextToolPayload, semanticDepth, false)
	return true
}

func (x *extractor) addText(text, key string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	if x.requestMode {
		x.addRequestText(text)
		return
	}
	for len(text) > maxTextPartBytes {
		if len(x.result.Parts) >= x.limits.MaxTextParts {
			x.result.addIncomplete(IncompleteTextPartLimit)
			x.stop = true
			return
		}
		cut := maxTextPartBytes
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		if cut == 0 {
			cut = maxTextPartBytes
		}
		x.result.Parts = append(x.result.Parts, text[:cut])
		text = text[cut:]
	}
	if text == "" {
		return
	}
	if len(x.result.Parts) >= x.limits.MaxTextParts {
		x.result.addIncomplete(IncompleteTextPartLimit)
		x.stop = true
		return
	}
	x.result.Parts = append(x.result.Parts, text)
}

func (x *extractor) addRequestText(text string) {
	if len(x.result.Parts) >= x.limits.MaxTextParts {
		x.result.addIncomplete(IncompleteTextPartLimit)
		x.stop = true
		return
	}

	allowedBytes := len(text)
	partLimited := allowedBytes > x.limits.MaxTextPartBytes
	if partLimited {
		allowedBytes = x.limits.MaxTextPartBytes
	}
	remaining := x.limits.MaxScanBytes - x.result.TextBytesScanned
	scanLimited := allowedBytes > remaining || (remaining <= 0 && len(text) > 0)
	if allowedBytes > remaining {
		allowedBytes = remaining
	}
	if allowedBytes < 0 {
		allowedBytes = 0
	}
	allowedText := utf8Prefix(text, allowedBytes)
	if allowedText != "" {
		x.result.Parts = append(x.result.Parts, allowedText)
		x.result.TextBytesScanned += len(allowedText)
	}
	if partLimited {
		x.result.addIncomplete(IncompleteTextPartByteLimit)
	}
	if scanLimited || len(allowedText) < len(text) && !partLimited {
		x.result.addIncomplete(IncompleteScanByteLimit)
	}
	if partLimited || scanLimited || len(allowedText) < len(text) {
		x.stop = true
	}
}

func canonicalKey(key string) string {
	if key == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch r {
		case '_', '-', ' ':
			continue
		default:
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isTextKeyCanonical(key string) bool {
	switch key {
	case "content", "text", "input", "inputtext", "outputtext", "system", "instructions", "systeminstruction", "prompt", "negativeprompt", "message", "caption", "query":
		return true
	default:
		return false
	}
}

func isTextContainerCanonical(key string) bool {
	switch key {
	case "messages", "contents", "parts":
		return true
	default:
		return false
	}
}

func isToolWrapperKeyCanonical(key string) bool {
	switch key {
	case "toolcalls", "toolcall", "tooluse", "function", "functioncall":
		return true
	default:
		return false
	}
}

func isProviderToolDefinitionContainerCanonical(key string) bool {
	switch key {
	case "tools", "functions":
		return true
	default:
		return false
	}
}

func isToolArgumentCanonical(key string) bool {
	switch key {
	case "arguments", "args", "parameters":
		return true
	default:
		return false
	}
}

func isMetadataKeyCanonical(key string) bool {
	switch key {
	case "role", "type", "name", "id", "model", "status", "index", "mimetype", "mediatype", "encoding", "url", "callid", "toolcallid", "finishreason":
		return true
	default:
		return false
	}
}

func isProviderMetadataContainerCanonical(key string) bool {
	switch key {
	case "metadata", "options", "requestoptions", "generationconfig", "safetysettings":
		return true
	default:
		return false
	}
}

func isMediaContainerKeyCanonical(key string) bool {
	return mediaContextForKey(key) != mediaContextNone
}

func mediaContextForKey(key string) mediaContextKind {
	switch key {
	case "image", "images", "mask", "imageurl", "imagedata", "inputimage", "outputimage":
		return mediaContextImage
	case "audio", "audiourl", "inputaudio", "inlineaudio":
		return mediaContextAudio
	case "video", "videourl", "inputvideo", "outputvideo":
		return mediaContextVideo
	case "file", "fileid", "fileurl", "fileuri", "filedata", "inputfile", "outputfile", "document", "documenturl", "attachment":
		return mediaContextDocument
	case "inlinedata":
		return mediaContextOther
	default:
		return mediaContextNone
	}
}

func isOpaquePayloadKeyCanonical(key string) bool {
	switch key {
	case "data", "bytes", "blob", "binary", "imagedata", "filedata":
		return true
	default:
		return false
	}
}

func isDirectMediaValueKeyCanonical(key string) bool {
	return isMediaContainerKeyCanonical(key) || isOpaquePayloadKeyCanonical(key)
}

func isMediaMetadataKeyCanonical(key string) bool {
	if isMetadataKeyCanonical(key) {
		return true
	}
	switch key {
	case "detail", "width", "height", "duration", "filename", "format":
		return true
	default:
		return false
	}
}

func marksMediaContext(key, value string) (bool, mediaContextKind) {
	canonical := canonicalKey(key)
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch canonical {
	case "type":
		switch canonicalKey(trimmed) {
		case "image", "imageurl", "inputimage", "outputimage":
			return true, mediaContextImage
		case "audio", "inputaudio", "inlineaudio":
			return true, mediaContextAudio
		case "video", "inputvideo", "outputvideo":
			return true, mediaContextVideo
		case "file", "inputfile", "outputfile", "document", "attachment":
			return true, mediaContextDocument
		case "inlinedata":
			return true, mediaContextOther
		}
	case "mimetype", "mediatype":
		kind := mediaContextForMIME(trimmed)
		return kind != mediaContextNone, kind
	}
	return false, mediaContextNone
}

func isOpaqueMediaMIME(value string) bool {
	return mediaContextForMIME(value) != mediaContextNone
}

func mediaContextForMIME(value string) mediaContextKind {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "image/"):
		return mediaContextImage
	case strings.HasPrefix(value, "audio/"):
		return mediaContextAudio
	case strings.HasPrefix(value, "video/"):
		return mediaContextVideo
	case value == "application/pdf", value == "application/octet-stream",
		value == "application/msword", strings.HasPrefix(value, "application/vnd.openxmlformats-officedocument"):
		return mediaContextDocument
	default:
		return mediaContextNone
	}
}

func opaqueDataURLKind(value string) (OpaqueMediaKind, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < len("data:") || !strings.EqualFold(trimmed[:len("data:")], "data:") {
		return "", false
	}
	comma := strings.IndexByte(trimmed, ',')
	if comma < 0 {
		return OpaqueMediaDataURL, true
	}
	header := strings.ToLower(trimmed[len("data:"):comma])
	mimeType := header
	if semicolon := strings.IndexByte(mimeType, ';'); semicolon >= 0 {
		mimeType = mimeType[:semicolon]
	}
	contextKind := mediaContextForMIME(mimeType)
	if contextKind == mediaContextNone {
		return "", false
	}
	if contextKind == mediaContextImage && strings.Contains(header, ";base64") {
		return OpaqueMediaBase64Image, true
	}
	switch contextKind {
	case mediaContextAudio:
		return OpaqueMediaAudio, true
	case mediaContextVideo:
		return OpaqueMediaVideo, true
	case mediaContextDocument:
		return OpaqueMediaDocument, true
	default:
		return OpaqueMediaDataURL, true
	}
}

func remoteOpaqueKind(kind mediaContextKind, value string) OpaqueMediaKind {
	switch kind {
	case mediaContextImage:
		if hasFoldedPrefix(strings.TrimSpace(value), "https://") {
			return OpaqueMediaHTTPSImageURL
		}
		return OpaqueMediaRemoteURL
	case mediaContextAudio:
		return OpaqueMediaAudio
	case mediaContextVideo:
		return OpaqueMediaVideo
	case mediaContextDocument:
		return OpaqueMediaDocument
	default:
		return OpaqueMediaRemoteURL
	}
}

func directOpaqueKind(kind mediaContextKind) OpaqueMediaKind {
	switch kind {
	case mediaContextImage:
		return OpaqueMediaBase64Image
	case mediaContextAudio:
		return OpaqueMediaAudio
	case mediaContextVideo:
		return OpaqueMediaVideo
	case mediaContextDocument:
		return OpaqueMediaDocument
	default:
		return OpaqueMediaOther
	}
}

func isHTTPURL(value string) bool {
	value = strings.TrimSpace(value)
	return hasFoldedPrefix(value, "https://") || hasFoldedPrefix(value, "http://")
}

func hasFoldedPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func containsBinaryControl(value string) bool {
	for _, r := range value {
		if (r >= 0 && r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func totalPartBytesUnbounded(parts []string) int {
	total := 0
	for _, part := range parts {
		if len(part) > int(^uint(0)>>1)-total {
			return int(^uint(0) >> 1)
		}
		total += len(part)
	}
	return total
}
