package extract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"strings"
	"unicode/utf8"
)

type transformedMultipartJSONPlanner struct {
	body           []byte
	limits         Limits
	profile        SourceProfile
	position       int
	tokens         int
	nodes          int
	partCount      int
	textFieldCount int
	spans          []plannedText
	result         *Result
}

// scanTransformedMultipartJSON handles the CPA image path where the host has
// already converted ingress multipart fields into a complete JSON execution
// object but retained the original multipart Content-Type. The top-level
// SourceProfile allowlist remains authoritative; only approved text fields are
// replayed through the bounded streaming sink. Unlike the legacy collector,
// this path never retains a whole long prompt and never treats MaxScanBytes or
// MaxMultipartTextPartBytes as total-coverage limits.
func scanTransformedMultipartJSON(body []byte, profile RequestProfile, limits Limits, sink ChunkSink) (Result, error) {
	result := newRequestResult(body, limits)
	if sink == nil {
		sink = discardChunkSink{}
	}
	if !obviousJSON(body) || !utf8.Valid(body) || !json.Valid(body) {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(IncompleteMultipartParseError)
		result.finish()
		sink.Abort()
		return result, nil
	}
	result.Envelope = EnvelopeComplete

	planner := transformedMultipartJSONPlanner{
		body:    body,
		limits:  limits,
		profile: profile.Source,
		spans:   make([]plannedText, 0, minInt(limits.MaxTextParts, 8)),
		result:  &result,
	}
	if reason := planner.plan(); reason != "" {
		result.addIncomplete(reason)
		if reason == IncompleteMultipartParseError {
			result.Envelope = EnvelopeIncomplete
		}
	}
	result.LogicalTextParts = planner.textFieldCount
	if len(result.IncompleteReasons) != 0 {
		result.TextCoverage = coverageForReasons(result.IncompleteReasons)
		result.finish()
		sink.Abort()
		return result, nil
	}

	emitter := streamEmitter{
		limits:                limits,
		sink:                  sink,
		result:                &result,
		textLimit:             limits.MaxMultipartTextBytes,
		textLimitReason:       IncompleteMultipartTextLimit,
		textLimitCoverage:     TextCoverageExhausted,
		binaryFailureReason:   IncompleteMultipartParseError,
		binaryFailureCoverage: TextCoverageUnavailable,
		decodeFailureReason:   IncompleteMultipartTextLimit,
		decodeFailureCoverage: TextCoverageExhausted,
	}
	for _, span := range planner.spans {
		if err := emitter.emitSpan(body[span.rawStart:span.rawEnd], span); err != nil {
			return Result{}, err
		}
		if emitter.aborted {
			result.BytesScanned = result.TextBytesScanned
			result.finish()
			return result, nil
		}
	}
	result.TextCoverage = TextCoverageComplete
	result.BytesScanned = result.TextBytesScanned
	result.finish()
	return result, nil
}

func (p *transformedMultipartJSONPlanner) plan() IncompleteReason {
	p.skipWhitespace()
	if reason := p.bump(true); reason != "" {
		return reason
	}
	if p.position >= len(p.body) || p.body[p.position] != '{' {
		return IncompleteMultipartUnknownField
	}
	if p.limits.MaxJSONDepth < 1 {
		return IncompleteJSONDepthLimit
	}
	p.position++
	first := true
	for {
		p.skipWhitespace()
		if p.position >= len(p.body) {
			return IncompleteMultipartParseError
		}
		if p.body[p.position] == '}' {
			p.position++
			if reason := p.bump(false); reason != "" {
				return reason
			}
			break
		}
		if !first {
			if p.body[p.position] != ',' {
				return IncompleteMultipartParseError
			}
			p.position++
			p.skipWhitespace()
		}
		first = false
		if reason := p.bump(false); reason != "" {
			return reason
		}
		keyStart, keyEnd, ok := p.takeString()
		if !ok {
			return IncompleteMultipartParseError
		}
		key, bounded := decodeShortJSONString(p.body[keyStart:keyEnd], maxShadowKeyBytes)
		if !bounded {
			key = ""
		}
		p.skipWhitespace()
		if p.position >= len(p.body) || p.body[p.position] != ':' {
			return IncompleteMultipartParseError
		}
		p.position++
		p.partCount++
		if p.partCount > p.limits.MaxMultipartParts {
			return IncompleteMultipartPartLimit
		}

		switch classifyMultipartField(p.profile, key) {
		case multipartFieldText:
			p.textFieldCount++
			if p.textFieldCount > p.limits.MaxMultipartTextFields {
				return IncompleteMultipartTextLimit
			}
			if p.textFieldCount > p.limits.MaxTextParts {
				return IncompleteTextPartLimit
			}
			p.skipWhitespace()
			if reason := p.bump(true); reason != "" {
				return reason
			}
			if p.position >= len(p.body) {
				return IncompleteMultipartParseError
			}
			if p.body[p.position] != '"' {
				p.result.addIncomplete(IncompleteMultipartTextFieldTypeMismatch)
				if reason := p.skipValueBody(1); reason != "" {
					return reason
				}
				continue
			}
			start, end, ok := p.takeString()
			if !ok {
				return IncompleteMultipartParseError
			}
			p.spans = append(p.spans, plannedText{
				id:                uint64(p.textFieldCount),
				rawStart:          start,
				rawEnd:            end,
				role:              RoleUser,
				provenance:        ProvenanceContent,
				userAttribution:   UserAttributionTrusted,
				conversationIndex: p.textFieldCount - 1,
				turnIndex:         0,
				isCurrentTurn:     true,
				scopeID:           uint64(p.textFieldCount),
				contentKind:       ContentKindNaturalLanguageDirective,
				fieldPathHash: structuralFieldPathHash(
					p.profile, multipartFieldPath(p.profile, key, p.textFieldCount-1),
				),
			})
		case multipartFieldMetadata:
			if reason := p.skipValue(1); reason != "" {
				return reason
			}
		case multipartFieldFile:
			p.result.OpaqueMedia = true
			markMultipartOpaque(p.result, key, "")
			if reason := p.skipValue(1); reason != "" {
				return reason
			}
		default:
			p.result.addIncomplete(IncompleteMultipartUnknownField)
			if reason := p.skipValue(1); reason != "" {
				return reason
			}
		}
	}
	p.skipWhitespace()
	if p.position != len(p.body) {
		return IncompleteMultipartParseError
	}
	return ""
}

func (p *transformedMultipartJSONPlanner) skipValue(depth int) IncompleteReason {
	p.skipWhitespace()
	if reason := p.bump(true); reason != "" {
		return reason
	}
	return p.skipValueBody(depth)
}

func (p *transformedMultipartJSONPlanner) skipValueBody(depth int) IncompleteReason {
	if p.position >= len(p.body) {
		return IncompleteMultipartParseError
	}
	switch p.body[p.position] {
	case '"':
		if _, _, ok := p.takeString(); !ok {
			return IncompleteMultipartParseError
		}
		return ""
	case '{':
		if depth+1 > p.limits.MaxJSONDepth {
			return IncompleteJSONDepthLimit
		}
		p.position++
		first := true
		for {
			p.skipWhitespace()
			if p.position >= len(p.body) {
				return IncompleteMultipartParseError
			}
			if p.body[p.position] == '}' {
				p.position++
				return p.bump(false)
			}
			if !first {
				if p.body[p.position] != ',' {
					return IncompleteMultipartParseError
				}
				p.position++
				p.skipWhitespace()
			}
			first = false
			if reason := p.bump(false); reason != "" {
				return reason
			}
			if _, _, ok := p.takeString(); !ok {
				return IncompleteMultipartParseError
			}
			p.skipWhitespace()
			if p.position >= len(p.body) || p.body[p.position] != ':' {
				return IncompleteMultipartParseError
			}
			p.position++
			if reason := p.skipValue(depth + 1); reason != "" {
				return reason
			}
		}
	case '[':
		if depth+1 > p.limits.MaxJSONDepth {
			return IncompleteJSONDepthLimit
		}
		p.position++
		first := true
		for {
			p.skipWhitespace()
			if p.position >= len(p.body) {
				return IncompleteMultipartParseError
			}
			if p.body[p.position] == ']' {
				p.position++
				return p.bump(false)
			}
			if !first {
				if p.body[p.position] != ',' {
					return IncompleteMultipartParseError
				}
				p.position++
			}
			first = false
			if reason := p.skipValue(depth + 1); reason != "" {
				return reason
			}
		}
	case 't':
		p.position += len("true")
	case 'f':
		p.position += len("false")
	case 'n':
		p.position += len("null")
	default:
		start := p.position
		for p.position < len(p.body) {
			switch p.body[p.position] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				if p.position == start {
					return IncompleteMultipartParseError
				}
				return ""
			default:
				p.position++
			}
		}
		if p.position == start {
			return IncompleteMultipartParseError
		}
	}
	if p.position > len(p.body) {
		return IncompleteMultipartParseError
	}
	return ""
}

func (p *transformedMultipartJSONPlanner) takeString() (int, int, bool) {
	if p.position >= len(p.body) || p.body[p.position] != '"' {
		return 0, 0, false
	}
	start := p.position
	p.position++
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case '\\':
			p.position += 2
		case '"':
			p.position++
			return start, p.position, true
		default:
			p.position++
		}
	}
	return 0, 0, false
}

func (p *transformedMultipartJSONPlanner) skipWhitespace() {
	for p.position < len(p.body) {
		switch p.body[p.position] {
		case ' ', '\t', '\r', '\n':
			p.position++
		default:
			return
		}
	}
}

func (p *transformedMultipartJSONPlanner) bump(node bool) IncompleteReason {
	p.tokens++
	if p.tokens > p.limits.MaxJSONTokens {
		return IncompleteJSONTokenLimit
	}
	if node {
		p.nodes++
		if p.nodes > p.limits.MaxJSONNodes {
			return IncompleteJSONNodeLimit
		}
	}
	return ""
}

func scanMultipartRequest(body []byte, boundary string, profile RequestProfile, limits Limits, sink ChunkSink) (Result, error) {
	result := newRequestResult(body, limits)
	if reason := preflightMultipart(body, boundary, limits); reason != "" {
		result.Envelope = EnvelopeIncomplete
		result.TextCoverage = TextCoverageUnavailable
		result.addIncomplete(reason)
		result.finish()
		sink.Abort()
		return result, nil
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	discardBuffer := make([]byte, multipartDiscardBufferBytes)
	partCount := 0
	textFieldCount := 0
	aborted := false
	abort := func(coverage TextCoverage, reason IncompleteReason) {
		result.addIncomplete(reason)
		if result.TextCoverage == "" || result.TextCoverage == TextCoverageComplete {
			result.TextCoverage = coverage
		}
		if !aborted {
			aborted = true
			sink.Abort()
		}
		// Multipart schema and framing are transactional. Once any later part
		// invalidates the request, no order-dependent prefix metrics may look like
		// committed classifier coverage.
		result.TextBytesScanned = 0
		result.ClassificationChunks = 0
		result.PeakTextBytesRetained = 0
	}

	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			if partCount == 0 {
				result.Envelope = EnvelopeIncomplete
				abort(TextCoverageUnavailable, IncompleteMultipartParseError)
			} else {
				result.Envelope = EnvelopeComplete
			}
			break
		}
		if err != nil {
			result.Envelope = EnvelopeIncomplete
			abort(TextCoverageUnavailable, IncompleteMultipartParseError)
			break
		}
		partCount++
		if partCount > limits.MaxMultipartParts {
			result.Envelope = EnvelopeIncomplete
			abort(TextCoverageExhausted, IncompleteMultipartPartLimit)
			_ = part.Close()
			break
		}
		if !multipartHeadersWithinLimits(part.Header, limits) {
			result.Envelope = EnvelopeIncomplete
			abort(TextCoverageExhausted, IncompleteMultipartHeaderLimit)
			_ = part.Close()
			break
		}

		disposition, params, ok := parsePartDisposition(part.Header)
		if !ok {
			result.Envelope = EnvelopeIncomplete
			abort(TextCoverageUnavailable, IncompleteMultipartParseError)
			_ = part.Close()
			break
		}
		name, hasName := params["name"]
		_, hasFilename := params["filename"]
		if !hasName && disposition != "attachment" {
			result.Envelope = EnvelopeIncomplete
			abort(TextCoverageUnavailable, IncompleteMultipartParseError)
			_ = part.Close()
			break
		}

		fieldClass := classifyMultipartField(profile.Source, name)
		partMediaType, mediaTypeOK := parsePartMediaType(part.Header)
		if fieldClass == multipartFieldUnknown {
			abort(TextCoverageUnavailable, IncompleteMultipartUnknownField)
			if mediaTypeOK && hasMultipartFileEvidence(disposition, hasFilename, partMediaType) {
				result.OpaqueMedia = true
				markMultipartOpaque(&result, name, partMediaType)
			}
			if _, copyErr := io.CopyBuffer(io.Discard, part, discardBuffer); copyErr != nil {
				result.Envelope = EnvelopeIncomplete
				abort(TextCoverageUnavailable, IncompleteMultipartParseError)
				_ = part.Close()
				break
			}
			_ = part.Close()
			continue
		}
		if !mediaTypeOK {
			result.Envelope = EnvelopeIncomplete
			abort(TextCoverageUnavailable, IncompleteMultipartParseError)
			_ = part.Close()
			break
		}
		fileEvidence := hasMultipartFileEvidence(disposition, hasFilename, partMediaType)
		textTypeMismatch := fieldClass == multipartFieldText && partMediaType != "" && !strings.HasPrefix(partMediaType, "text/")
		if fieldClass == multipartFieldText && (fileEvidence || textTypeMismatch) {
			result.OpaqueMedia = true
			markMultipartOpaque(&result, name, partMediaType)
			abort(TextCoverageUnavailable, IncompleteMultipartTextFieldTypeMismatch)
			if _, copyErr := io.CopyBuffer(io.Discard, part, discardBuffer); copyErr != nil {
				result.Envelope = EnvelopeIncomplete
				abort(TextCoverageUnavailable, IncompleteMultipartParseError)
				_ = part.Close()
				break
			}
			_ = part.Close()
			continue
		}
		if fileEvidence || fieldClass == multipartFieldFile {
			result.OpaqueMedia = true
			markMultipartOpaque(&result, name, partMediaType)
			if _, copyErr := io.CopyBuffer(io.Discard, part, discardBuffer); copyErr != nil {
				result.Envelope = EnvelopeIncomplete
				abort(TextCoverageUnavailable, IncompleteMultipartParseError)
				_ = part.Close()
				break
			}
			_ = part.Close()
			continue
		}
		if fieldClass == multipartFieldMetadata || aborted {
			if _, copyErr := io.CopyBuffer(io.Discard, part, discardBuffer); copyErr != nil {
				result.Envelope = EnvelopeIncomplete
				abort(TextCoverageUnavailable, IncompleteMultipartParseError)
				_ = part.Close()
				break
			}
			_ = part.Close()
			continue
		}

		textFieldCount++
		if textFieldCount > limits.MaxMultipartTextFields {
			abort(TextCoverageExhausted, IncompleteMultipartTextLimit)
			_, _ = io.CopyBuffer(io.Discard, part, discardBuffer)
			_ = part.Close()
			continue
		}
		if textFieldCount > limits.MaxTextParts {
			abort(TextCoverageExhausted, IncompleteTextPartLimit)
			_, _ = io.CopyBuffer(io.Discard, part, discardBuffer)
			_ = part.Close()
			continue
		}
		fieldID := uint64(textFieldCount)
		completed, streamErr := streamMultipartTextField(
			part, fieldID, name, profile.Source, limits, sink, &result,
		)
		_ = part.Close()
		if streamErr != nil {
			if !aborted {
				aborted = true
				sink.Abort()
			}
			return Result{}, streamErr
		}
		if !completed {
			if result.TextCoverage == "" {
				result.TextCoverage = TextCoverageExhausted
			}
			if !aborted {
				aborted = true
				sink.Abort()
			}
		}
	}

	result.LogicalTextParts = textFieldCount
	result.BytesScanned = result.TextBytesScanned
	if len(result.IncompleteReasons) == 0 {
		result.TextCoverage = TextCoverageComplete
	}
	result.finish()
	return result, nil
}

func streamMultipartTextField(
	part *multipart.Part,
	fieldID uint64,
	fieldName string,
	source SourceProfile,
	limits Limits,
	sink ChunkSink,
	result *Result,
) (bool, error) {
	// The legacy *PartBytes names are retained for API compatibility, but the
	// streaming path uses them as bounded chunk sizes. Cumulative text coverage
	// is enforced below by MaxTotalTextBytes and MaxMultipartTextBytes.
	chunkSize := minInt(limits.MaxMultipartTextPartBytes, minInt(limits.MaxTextPartBytes, limits.MaxTextWindowBytes))
	reader := bufio.NewReaderSize(part, chunkSize)
	chunk := make([]byte, 0, chunkSize)
	decoder := newBoundedStreamingDecoder(chunkSize)
	conversationIndex := int(fieldID - 1)
	fieldPathHash := structuralFieldPathHash(
		source, multipartFieldPath(source, fieldName, conversationIndex),
	)
	started := false
	emit := func(final bool) (bool, error) {
		if len(chunk) == 0 {
			if final && started {
				if err := sink.AddSegment(SegmentChunk{
					Role:              RoleUser,
					Provenance:        ProvenanceContent,
					UserAttribution:   UserAttributionTrusted,
					ConversationIndex: conversationIndex,
					TurnIndex:         0,
					IsCurrentTurn:     true,
					ScopeID:           fieldID,
					ContentKind:       ContentKindNaturalLanguageDirective,
					FieldPathHash:     fieldPathHash,
					FieldID:           fieldID,
					End:               true,
				}); err != nil {
					return false, fmtChunkSinkError(err)
				}
			}
			return true, nil
		}
		if result.ClassificationChunks >= limits.MaxClassificationChunks {
			result.TextCoverage = TextCoverageExhausted
			result.addIncomplete(IncompleteClassificationChunkLimit)
			return false, nil
		}
		if err := sink.AddSegment(SegmentChunk{
			Role:              RoleUser,
			Provenance:        ProvenanceContent,
			UserAttribution:   UserAttributionTrusted,
			ConversationIndex: conversationIndex,
			TurnIndex:         0,
			IsCurrentTurn:     true,
			ScopeID:           fieldID,
			ContentKind:       ContentKindNaturalLanguageDirective,
			FieldPathHash:     fieldPathHash,
			FieldID:           fieldID,
			Start:             !started,
			End:               final,
			Text:              chunk,
		}); err != nil {
			return false, fmtChunkSinkError(err)
		}
		started = true
		result.ClassificationChunks++
		result.TextBytesScanned += len(chunk)
		if len(chunk) > result.PeakTextBytesRetained {
			result.PeakTextBytesRetained = len(chunk)
		}
		chunk = chunk[:0]
		return true, nil
	}
	for {
		r, size, err := reader.ReadRune()
		if errors.Is(err, io.EOF) {
			variants, decodeIncomplete := decoder.finish(false)
			if decodeIncomplete {
				result.TextCoverage = TextCoverageUnavailable
				result.addIncomplete(IncompleteTextPartByteLimit)
				return false, nil
			}
			if len(chunk) == 0 && !started {
				return true, nil
			}
			ok, emitErr := emit(true)
			if emitErr != nil || !ok {
				return ok, emitErr
			}
			emitter := streamEmitter{
				limits: limits, sink: sink, result: result,
				textLimit: limits.MaxMultipartTextBytes, textLimitReason: IncompleteMultipartTextLimit,
				textLimitCoverage: TextCoverageExhausted,
			}
			for index, variant := range variants {
				if err := emitter.emitOwned(plannedText{
					id:                derivedFieldID(fieldID, index),
					owned:             variant,
					role:              RoleUser,
					provenance:        ProvenanceContent,
					userAttribution:   UserAttributionTrusted,
					conversationIndex: conversationIndex,
					turnIndex:         0,
					isCurrentTurn:     true,
					scopeID:           fieldID,
					contentKind:       ContentKindNaturalLanguageDirective,
					fieldPathHash:     fieldPathHash,
				}); err != nil {
					return false, err
				}
				if emitter.aborted {
					return false, nil
				}
			}
			return true, nil
		}
		if err != nil || r == utf8.RuneError && size == 1 {
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteMultipartParseError)
			return false, nil
		}
		if (r >= 0 && r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
			result.TextCoverage = TextCoverageUnavailable
			result.addIncomplete(IncompleteMultipartParseError)
			return false, nil
		}
		var encoded [utf8.UTFMax]byte
		encodedSize := utf8.EncodeRune(encoded[:], r)
		if result.TextBytesScanned+len(chunk) > limits.MaxTotalTextBytes-encodedSize {
			result.TextCoverage = TextCoverageExhausted
			result.addIncomplete(IncompleteTotalTextLimit)
			return false, nil
		}
		if result.TextBytesScanned+len(chunk) > limits.MaxMultipartTextBytes-encodedSize {
			result.TextCoverage = TextCoverageExhausted
			result.addIncomplete(IncompleteMultipartTextLimit)
			return false, nil
		}
		if len(chunk) > 0 && len(chunk)+encodedSize > chunkSize {
			ok, emitErr := emit(false)
			if emitErr != nil || !ok {
				return ok, emitErr
			}
		}
		decoder.add(encoded[:encodedSize])
		chunk = append(chunk, encoded[:encodedSize]...)
	}
}

func fmtChunkSinkError(err error) error {
	return errors.New("extract: chunk sink: " + err.Error())
}
