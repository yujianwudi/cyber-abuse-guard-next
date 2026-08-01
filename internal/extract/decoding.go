package extract

import (
	"encoding/base64"
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxDecodeLayers        = 2
	maxDecodeSourceBytes   = 128 << 10
	maxDecodedVariantBytes = 64 << 10
	// Two complete source-bounded decode layers, including UTF-8-safe overlap
	// fragments. Nested layers that would exceed this aggregate budget remain
	// fail-closed.
	maxDecodedTotalBytes = 288 << 10
	maxDecodedVariants   = 8
	minBase64SourceBytes = 16
)

type decodeNode struct {
	text  string
	depth int
}

type decodeStep struct {
	text string
}

// decodedTextView retains the source interval that produced a derived
// classifier view. Whole-field transformations cover the complete source;
// sparse local windows keep their exact parent interval so the stream emitter
// can preserve fenced/content metadata from that parent piece.
type decodedTextView struct {
	text        string
	sourceStart int
	sourceEnd   int
}

type decodedVariantBudget struct {
	count int
	bytes int
}

func (budget *decodedVariantBudget) admit(size int) bool {
	if budget == nil || size <= 0 || size > maxDecodedVariantBytes ||
		budget.count >= maxDecodedVariants || budget.bytes > maxDecodedTotalBytes-size {
		return false
	}
	budget.count++
	budget.bytes += size
	return true
}

// decodeBoundedText recognizes a deliberately small, non-recursive encoding
// set: textual data URLs, URL percent escapes, HTML entities, and Base64 text.
// It performs no decompression, archive parsing, or network access. The
// original string is retained by the caller and each unique decoded view is
// bounded by both layer and byte limits.
func decodeBoundedText(value string) (variants []string, encoded bool, incomplete bool) {
	views, encoded, incomplete := decodeBoundedTextViews(value)
	variants = make([]string, len(views))
	for index, view := range views {
		variants[index] = view.text
	}
	return variants, encoded, incomplete
}

func decodeBoundedTextViews(value string) (views []decodedTextView, encoded bool, incomplete bool) {
	if len(value) > maxDecodeSourceBytes {
		potentiallyEncoded := looksPotentiallyEncodedOversized(value)
		return nil, potentiallyEncoded, potentiallyEncoded
	}
	if windows, sparse := sparseEncodedWindows(value); sparse {
		if len(windows) == 1 && windows[0].start == 0 && windows[0].end == len(value) ||
			sparseSourceMayBecomeWholeEnvelope(value) {
			return decodeBoundedTextExactViews(value)
		}
		return decodeSparseEncodedWindowViews(value, windows)
	}
	return decodeBoundedTextExactViews(value)
}

func decodeBoundedTextExactViews(value string) ([]decodedTextView, bool, bool) {
	variants, encoded, incomplete := decodeBoundedTextExact(value)
	if incomplete {
		// Percent-encoded control bytes have two bounded text interpretations:
		// separator preservation and control deletion. Recover both even in a
		// short field, but only when the canonical traversal proves that no
		// malformed token or additional codec layer remains.
		if recovered, ok := decodeSparseMixedWindow(value); ok {
			variants = recovered
			encoded = true
			incomplete = false
		}
	}
	return wholeSourceDecodedTextViews(value, variants), encoded, incomplete
}

func wholeSourceDecodedTextViews(value string, variants []string) []decodedTextView {
	views := make([]decodedTextView, len(variants))
	for index, variant := range variants {
		views[index] = decodedTextView{text: variant, sourceEnd: len(value)}
	}
	return views
}

func decodeBoundedTextExact(value string) (variants []string, encoded bool, incomplete bool) {
	queue := []decodeNode{{text: value}}
	seen := map[string]struct{}{value: {}}
	emitted := make(map[string]struct{}, maxDecodedVariants)
	var budget decodedVariantBudget
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		steps, recognized, limited := decodeOneLayer(node.text)
		encoded = encoded || recognized
		incomplete = incomplete || limited
		if node.depth >= maxDecodeLayers {
			if len(steps) > 0 {
				incomplete = true
			}
			continue
		}
		for _, step := range steps {
			if step.text == "" || step.text == node.text {
				continue
			}
			if _, exists := seen[step.text]; exists {
				continue
			}
			fragments := splitDecodedView(step.text)
			candidateBudget := budget
			newFragments := make([]string, 0, len(fragments))
			candidateSeen := make(map[string]struct{}, len(fragments))
			admitted := true
			for _, fragment := range fragments {
				if _, exists := emitted[fragment]; exists {
					continue
				}
				if _, exists := candidateSeen[fragment]; exists {
					continue
				}
				if !candidateBudget.admit(len(fragment)) {
					admitted = false
					break
				}
				candidateSeen[fragment] = struct{}{}
				newFragments = append(newFragments, fragment)
			}
			if !admitted {
				incomplete = true
				continue
			}
			budget = candidateBudget
			seen[step.text] = struct{}{}
			for _, fragment := range newFragments {
				emitted[fragment] = struct{}{}
				variants = append(variants, fragment)
			}
			// Recursion uses the complete source-bounded transformation, not an
			// emitted 64 KiB fragment. Otherwise a sparse percent/entity change at
			// the front of a large Base64 or data-URL envelope could hide a later
			// decoded payload outside the local fragment.
			queue = append(queue, decodeNode{text: step.text, depth: node.depth + 1})
		}
	}
	return variants, encoded, incomplete
}

type decodedWindowSpan struct {
	start int
	end   int
}

// sparseEncodedWindows isolates a small number of percent/entity clusters
// from a much larger ordinary source field. Scanning the raw field remains the
// primary view. The derived views need only retain bounded context around each
// reversible token; decoding an entire source file would otherwise combine
// unrelated format strings, entities, and placeholders into artificial nested
// layers and exhaust the eight-view proof budget.
func sparseEncodedWindows(value string) ([]decodedWindowSpan, bool) {
	trimmed := strings.TrimSpace(value)
	if len(value) == 0 || len(trimmed) >= len("data:") && strings.EqualFold(trimmed[:len("data:")], "data:") {
		return nil, false
	}

	windows := make([]decodedWindowSpan, 0, maxDecodedVariants+1)
	tokenCount := 0
	encodedBytes := 0
	recordToken := func(tokenStart, tokenEnd int) bool {
		tokenCount++
		encodedBytes += tokenEnd - tokenStart
		start := tokenStart - ClassificationOverlapReserveBytes
		if start < 0 {
			start = 0
		}
		for start > 0 && !utf8.RuneStart(value[start]) {
			start++
		}
		end := minInt(len(value), tokenEnd+ClassificationOverlapReserveBytes)
		for end < len(value) && !utf8.RuneStart(value[end]) {
			end--
		}
		if len(windows) != 0 && start <= windows[len(windows)-1].end {
			if end > windows[len(windows)-1].end {
				windows[len(windows)-1].end = end
			}
		} else if len(windows) < maxDecodedVariants+1 {
			windows = append(windows, decodedWindowSpan{start: start, end: end})
		}
		return denseEncodingSignal(tokenCount, encodedBytes, len(value))
	}
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '%':
			if end, ok := percentPlaceholderEnd(value, index); ok {
				index = end - 1
				continue
			}
			if index+2 < len(value) && isHexByte(value[index+1]) && isHexByte(value[index+2]) {
				if recordToken(index, index+3) {
					return nil, false
				}
				index += 2
			}
		case '&':
			endLimit := minInt(len(value), index+32)
			for end := index + 2; end < endLimit; end++ {
				if value[end] != ';' {
					continue
				}
				candidate := value[index : end+1]
				if html.UnescapeString(candidate) != candidate {
					if recordToken(index, end+1) {
						return nil, false
					}
					index = end
				}
				break
			}
		}
	}
	if tokenCount == 0 {
		return nil, false
	}
	return windows, true
}

// sparseSourceMayBecomeWholeEnvelope detects the case where one local
// percent/entity substitution makes the entire source a Base64 or textual
// data-URL envelope. Such a transformation cannot be proved from a 4 KiB local
// window because the decoded payload may end near the opposite source edge.
func sparseSourceMayBecomeWholeEnvelope(value string) bool {
	current := value
	for depth := 0; depth < maxDecodeLayers; depth++ {
		next, changed, ok := decodeSparseCanonicalLayerBounded(
			current, false, false, maxDecodeSourceBytes,
		)
		if !ok || !changed {
			return false
		}
		current = next
		trimmed := strings.TrimSpace(current)
		if len(trimmed) >= len("data:") && strings.EqualFold(trimmed[:len("data:")], "data:") {
			return true
		}
		if _, found, _ := decodeBase64Text(current, minBase64SourceBytes); found ||
			looksLikeMalformedBase64(current) {
			return true
		}
	}
	return false
}

func decodeSparseEncodedWindows(value string, windows []decodedWindowSpan) (variants []string, encoded bool, incomplete bool) {
	views, encoded, incomplete := decodeSparseEncodedWindowViews(value, windows)
	variants = make([]string, len(views))
	for index, view := range views {
		variants[index] = view.text
	}
	return variants, encoded, incomplete
}

func decodeSparseEncodedWindowViews(value string, windows []decodedWindowSpan) (views []decodedTextView, encoded bool, incomplete bool) {
	if sparseWindowsNeedWholeSource(windows) {
		variants, encoded, incomplete := decodeSparseWholeSource(value)
		return wholeSourceDecodedTextViews(value, variants), encoded, incomplete
	}
	var budget decodedVariantBudget
	for _, window := range windows {
		if window.start < 0 || window.end <= window.start || window.end > len(value) {
			return views, encoded, true
		}
		windowText := value[window.start:window.end]
		windowVariants, windowEncoded, windowIncomplete := decodeBoundedTextExact(windowText)
		if windowIncomplete {
			if recovered, ok := decodeSparseMixedWindow(windowText); ok {
				windowVariants = recovered
				windowEncoded = true
				windowIncomplete = false
			}
		}
		if windowIncomplete && len(windowVariants) == 0 {
			// Local token windows are an optimization, not a distinct coverage
			// contract. If one window cannot be proven complete, normalize the
			// complete source once so interactions between binary test vectors,
			// nested escapes, and neighbouring windows remain classifier-visible.
			variants, fallbackEncoded, fallbackIncomplete := decodeSparseWholeSource(value)
			return wholeSourceDecodedTextViews(value, variants),
				encoded || windowEncoded || fallbackEncoded,
				incomplete || windowIncomplete || fallbackIncomplete
		}
		encoded = encoded || windowEncoded
		incomplete = incomplete || windowIncomplete
		// Content kind is assigned later from this source interval. Deduplicate only
		// interpretations of this window: identical text from another interval must
		// remain independently classifier-visible and consume the global budget.
		distinctWindowVariants := make([]string, 0, len(windowVariants))
		windowSeen := make(map[string]struct{}, len(windowVariants))
		for _, variant := range windowVariants {
			if _, exists := windowSeen[variant]; exists {
				continue
			}
			windowSeen[variant] = struct{}{}
			distinctWindowVariants = append(distinctWindowVariants, variant)
		}
		for _, variant := range distinctWindowVariants {
			if !budget.admit(len(variant)) {
				// Every reversible interpretation is security-relevant. If a distinct
				// view cannot be charged, retaining a traversal-order subset is not a
				// complete inspection proof.
				incomplete = true
				continue
			}
			views = append(views, decodedTextView{
				text: variant, sourceStart: window.start, sourceEnd: window.end,
			})
		}
	}
	return views, encoded, incomplete
}

func sparseWindowsNeedWholeSource(windows []decodedWindowSpan) bool {
	if len(windows) > maxDecodedVariants {
		return true
	}
	for _, window := range windows {
		if window.end-window.start > maxDecodedVariantBytes {
			return true
		}
	}
	return false
}

// decodeSparseWholeSource handles a large ordinary source/document window whose
// sparse token contexts coalesced beyond one emitted-view bound. The source is
// still capped at 128 KiB. Canonical transformations run over that complete
// source so UTF-8 and percent tokens are not cut at fragment edges; only the
// resulting classifier views are split and charged to the aggregate budget.
func decodeSparseWholeSource(value string) (variants []string, encoded bool, incomplete bool) {
	if len(value) == 0 || len(value) > maxDecodeSourceBytes {
		return nil, looksPotentiallyEncoded(value), looksPotentiallyEncoded(value)
	}
	validPercent, _, _ := percentEscapeCounts(value)
	entityChanged := strings.Contains(value, "&") && strings.Contains(value, ";") &&
		html.UnescapeString(value) != value
	if validPercent == 0 && !entityChanged ||
		hasMalformedPercentEscapeInEncodedToken(value) ||
		hasUnclosedPercentPlaceholderCollision(value) {
		return nil, validPercent > 0 || entityChanged, true
	}
	if _, found, _ := decodeBase64Text(value, minBase64SourceBytes); found ||
		looksLikeMalformedBase64(value) {
		return nil, true, true
	}

	seen := make(map[string]struct{}, maxDecodedVariants)
	var budget decodedVariantBudget
	appendView := func(view string) bool {
		for _, fragment := range splitDecodedView(view) {
			if _, exists := seen[fragment]; exists {
				continue
			}
			if !budget.admit(len(fragment)) {
				return false
			}
			seen[fragment] = struct{}{}
			variants = append(variants, fragment)
		}
		return true
	}

	// The raw source is always emitted separately, so it already preserves a
	// literal '+'. The derived inspection view may conservatively normalize '+'
	// to a separator when percent escapes are present. This avoids duplicating a
	// source-sized view while retaining both interpretations for classification.
	modes := []bool{validPercent > 0 && strings.Contains(value, "+")}
	for _, plusAsSpace := range modes {
		current := value
		for depth := 0; depth < maxDecodeLayers; depth++ {
			next, changed, ok := decodeSparseCanonicalLayerBounded(
				current, plusAsSpace, false, maxDecodeSourceBytes,
			)
			if !ok {
				return variants, true, true
			}
			if !changed {
				break
			}
			encoded = true
			current = next
			if !appendView(current) {
				return variants, true, true
			}
		}
		if _, changed, ok := decodeSparseCanonicalLayerBounded(
			current, plusAsSpace, false, maxDecodeSourceBytes,
		); !ok || changed || decodedTraversalHasFurtherLayer(current) {
			return variants, true, true
		}
	}
	return variants, encoded, false
}

// decodeSparseMixedWindow is a narrow recovery for ordinary source/document
// windows that contain a few reversible text tokens alongside binary percent
// test vectors such as %00. The caller retains the raw source. In the derived
// inspection view, encoded non-text bytes become separators so they cannot hide
// or concatenate surrounding text, while every printable percent/entity
// transformation remains classifier-visible. Explicit envelopes, malformed
// encoded tokens, and Base64-shaped windows retain the normal fail-closed path.
func decodeSparseMixedWindow(value string) ([]string, bool) {
	validPercent, _, _ := percentEscapeCounts(value)
	entityChanged := strings.Contains(value, "&") && strings.Contains(value, ";") &&
		html.UnescapeString(value) != value
	if validPercent == 0 && !entityChanged ||
		hasStrongMalformedPercentTripletOutsidePlaceholders(value) ||
		hasMalformedPercentEscapeInEncodedToken(value) ||
		hasUnclosedPercentPlaceholderCollision(value) {
		return nil, false
	}
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= len("data:") && strings.EqualFold(trimmed[:len("data:")], "data:") {
		return nil, false
	}
	if _, found, _ := decodeBase64Text(value, minBase64SourceBytes); found ||
		looksLikeMalformedBase64(value) {
		return nil, false
	}

	seen := map[string]struct{}{value: {}}
	variants := make([]string, 0, maxDecodedVariants)
	type canonicalMode struct {
		plusAsSpace bool
		dropControl bool
	}
	modes := []canonicalMode{
		{plusAsSpace: false, dropControl: false},
		{plusAsSpace: false, dropControl: true},
	}
	if validPercent > 0 && strings.Contains(value, "+") {
		modes = append(modes,
			canonicalMode{plusAsSpace: true, dropControl: false},
			canonicalMode{plusAsSpace: true, dropControl: true},
		)
	}
	for _, mode := range modes {
		current := value
		for depth := 0; depth < maxDecodeLayers; depth++ {
			next, changed, ok := decodeSparseCanonicalLayer(current, mode.plusAsSpace, mode.dropControl)
			if !ok {
				return variants, false
			}
			if !changed {
				break
			}
			current = next
			if _, exists := seen[current]; exists {
				continue
			}
			if len(variants) >= maxDecodedVariants {
				return variants, false
			}
			seen[current] = struct{}{}
			variants = append(variants, current)
		}
		if _, changed, ok := decodeSparseCanonicalLayer(current, mode.plusAsSpace, mode.dropControl); !ok || changed ||
			decodedTraversalHasFurtherLayer(current) {
			return variants, false
		}
	}
	return variants, len(variants) != 0
}

// decodeSparseInvalidUTF8Window is a narrow recovery used only for one local
// window inside a large, multi-window source document. The raw source remains a
// separate classifier view. A percent-decoded byte sequence that is not valid
// UTF-8 is represented as a separator instead of being silently discarded or
// replaced with RuneError; this keeps surrounding text visible under the two
// language-relevant interpretations without declaring short/dense envelopes
// complete.
func decodeSparseInvalidUTF8Window(value string) ([]string, bool) {
	if value == "" || len(value) > maxDecodedVariantBytes ||
		sourceHasUninspectableControl(value) ||
		hasMalformedPercentEscapeInEncodedToken(value) ||
		hasUnclosedPercentPlaceholderCollision(value) {
		return nil, false
	}
	if _, found, _ := decodeBase64Text(value, minBase64SourceBytes); found ||
		looksLikeMalformedBase64(value) {
		return nil, false
	}

	seen := map[string]struct{}{value: {}}
	variants := make([]string, 0, 2*maxDecodeLayers)
	sawInvalidUTF8 := false
	for _, dropControl := range []bool{false, true} {
		current := value
		modeSawInvalidUTF8 := false
		for depth := 0; depth < maxDecodeLayers; depth++ {
			validPercent, _, _ := percentEscapeCounts(current)
			entityChanged := strings.Contains(current, "&") && strings.Contains(current, ";") &&
				html.UnescapeString(current) != current
			if validPercent == 0 && !entityChanged {
				break
			}

			next := current
			changed := false
			if validPercent > 0 {
				decoded, ok := decodePercentEscapesBounded(current, false)
				if !ok {
					return nil, false
				}
				if decoded != current {
					if !utf8.ValidString(decoded) {
						var sanitizedOK bool
						decoded, sanitizedOK = sanitizeInvalidUTF8DecodedView(decoded, dropControl)
						if !sanitizedOK {
							return nil, false
						}
						modeSawInvalidUTF8 = true
					}
					next = decoded
					changed = true
				}
			}
			// A percent and an HTML transformation are separate codec layers even
			// when both happen to be present in the same source window.
			if !changed {
				if decoded := html.UnescapeString(next); decoded != next {
					next = decoded
					changed = true
				}
			}
			if !changed {
				break
			}
			if !isInspectableDecodedText([]byte(next)) {
				return nil, false
			}
			current = next
			if _, exists := seen[current]; !exists {
				seen[current] = struct{}{}
				variants = append(variants, current)
			}
		}

		validPercent, _, _ := percentEscapeCounts(current)
		if validPercent > 0 {
			decoded, ok := decodePercentEscapesBounded(current, false)
			if !ok || decoded != current {
				return nil, false
			}
		}
		if decoded := html.UnescapeString(current); decoded != current ||
			decodedTraversalHasFurtherLayer(current) {
			return nil, false
		}
		sawInvalidUTF8 = sawInvalidUTF8 || modeSawInvalidUTF8
	}
	return variants, sawInvalidUTF8 && len(variants) != 0
}

func sanitizeInvalidUTF8DecodedView(value string, dropControl bool) (string, bool) {
	if value == "" || utf8.ValidString(value) {
		return value, false
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastSeparator := false
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			if !dropControl && !lastSeparator {
				builder.WriteByte(' ')
			}
			lastSeparator = !dropControl
			index++
			continue
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			builder.WriteRune(r)
			lastSeparator = false
		case unicode.IsControl(r) || !unicode.IsPrint(r):
			if !dropControl && !lastSeparator {
				builder.WriteByte(' ')
			}
			lastSeparator = !dropControl
		default:
			builder.WriteRune(r)
			lastSeparator = false
		}
		index += size
	}
	result := builder.String()
	return result, isInspectableDecodedText([]byte(result))
}

func decodeSparseCanonicalLayer(value string, plusAsSpace, dropControl bool) (string, bool, bool) {
	return decodeSparseCanonicalLayerBounded(value, plusAsSpace, dropControl, maxDecodedVariantBytes)
}

func decodeSparseCanonicalLayerBounded(value string, plusAsSpace, dropControl bool, maxBytes int) (string, bool, bool) {
	current := value
	validPercent, _, _ := percentEscapeCounts(current)
	if validPercent > 0 {
		decoded, ok := decodePercentEscapesForInspectionMode(current, plusAsSpace, dropControl)
		if !ok {
			return "", false, false
		}
		if decoded != current {
			current = decoded
			if len(current) > maxBytes || !isInspectableDecodedText([]byte(current)) {
				return "", false, false
			}
			return current, true, true
		}
	}
	if decoded := html.UnescapeString(current); decoded != current {
		if !isInspectableDecodedText([]byte(decoded)) {
			return "", false, false
		}
		current = decoded
		if len(current) > maxBytes {
			return "", false, false
		}
		return current, true, true
	}
	return current, false, true
}

// decodePercentEscapesForInspection produces a text-only canonical view. The
// raw source remains a separate classifier view, so percent-encoded control
// runes can become separators here. Invalid UTF-8 remains fail-closed: a
// permissive downstream decoder may assign printable semantics (for example an
// overlong path separator) that a RuneError replacement cannot safely cover.
func decodePercentEscapesForInspection(value string, plusAsSpace bool) (string, bool) {
	return decodePercentEscapesForInspectionMode(value, plusAsSpace, false)
}

func decodePercentEscapesForInspectionMode(value string, plusAsSpace, dropControl bool) (string, bool) {
	if !utf8.ValidString(value) || sourceHasUninspectableControl(value) {
		return "", false
	}
	decoded, ok := decodePercentEscapesBounded(value, plusAsSpace)
	if !ok || decoded == value {
		return "", false
	}
	if !utf8.ValidString(decoded) {
		return "", false
	}
	if isInspectableDecodedText([]byte(decoded)) {
		return decoded, true
	}

	var builder strings.Builder
	builder.Grow(len(decoded))
	for index := 0; index < len(decoded); {
		r, size := utf8.DecodeRuneInString(decoded[index:])
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			builder.WriteRune(r)
		case unicode.IsControl(r) || !unicode.IsPrint(r):
			if !dropControl {
				builder.WriteByte(' ')
			}
		default:
			builder.WriteRune(r)
		}
		index += size
	}
	result := builder.String()
	return result, result != decoded && isInspectableDecodedText([]byte(result))
}

func decodedTraversalHasFurtherLayer(value string) bool {
	steps, _, limited := decodeOneLayer(value)
	return limited || len(steps) != 0
}

func sourceHasUninspectableControl(value string) bool {
	for _, r := range value {
		if r != '\n' && r != '\r' && r != '\t' && unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func decodeOneLayer(value string) ([]decodeStep, bool, bool) {
	steps := make([]decodeStep, 0, 3)
	recognized := false
	incomplete := false
	hasPercent := strings.Contains(value, "%")
	validPercentEscapes, invalidPercentEscapes := 0, 0
	closedPercentPlaceholder := false
	if hasPercent {
		validPercentEscapes, invalidPercentEscapes, closedPercentPlaceholder = percentEscapeCounts(value)
	}
	malformedPercentToken := hasPercent && hasMalformedPercentEscapeInEncodedToken(value)
	unclosedPercentCollision := strings.Contains(value, "%%") && hasUnclosedPercentPlaceholderCollision(value)
	appendText := func(decoded string, ok bool) bool {
		if !ok || decoded == value || !isInspectableDecodedText([]byte(decoded)) {
			return false
		}
		steps = append(steps, decodeStep{text: decoded})
		return true
	}

	if decoded, found, ok := decodeTextDataURL(value); found {
		recognized = true
		incomplete = incomplete ||
			invalidPercentEscapes > 0 && hasMalformedPercentEscapeOutsidePlaceholders(value) ||
			malformedPercentToken || unclosedPercentCollision
		if !ok {
			incomplete = true
		} else {
			appendText(decoded, true)
		}
		// A data URL is one encoding envelope. Do not reinterpret its header as
		// an unrelated Base64 or HTML candidate.
		return steps, recognized, incomplete
	}

	if hasPercent {
		recognized = recognized || closedPercentPlaceholder
		if validPercentEscapes > 0 {
			recognized = true
			incomplete = incomplete || malformedPercentToken || unclosedPercentCollision
			decoded, ok := decodePercentEscapesBounded(value, false)
			if !ok {
				incomplete = true
			} else if decoded != value {
				if isInspectableDecodedText([]byte(decoded)) {
					appendText(decoded, true)
				} else if percentDecodedViewMustFailClosed(validPercentEscapes) {
					incomplete = true
				}
			}

			// QueryEscape represents spaces as '+'. Generate this second bounded
			// view only when a percent escape is already present, so ordinary plus
			// signs are never rewritten speculatively.
			if strings.Contains(value, "+") {
				decoded, ok = decodePercentEscapesBounded(value, true)
				if !ok {
					incomplete = true
				} else if decoded != value {
					if isInspectableDecodedText([]byte(decoded)) {
						appendText(decoded, true)
					} else if percentDecodedViewMustFailClosed(validPercentEscapes) {
						incomplete = true
					}
				}
			}
		}
	}
	if strings.Contains(value, "&") && strings.Contains(value, ";") {
		if decoded := html.UnescapeString(value); decoded != value {
			recognized = true
			incomplete = !appendText(decoded, true) || incomplete
		}
	}
	if decoded, found, ok := decodeBase64Text(value, minBase64SourceBytes); found {
		recognized = true
		if !ok {
			incomplete = true
		} else {
			appendText(decoded, true)
		}
	} else if decoded, ok := recoverMalformedBase64Prefix(value, minBase64SourceBytes); ok {
		// Some permissive decoders stop at valid padding and ignore trailing
		// alphabet characters. Scan the recoverable prefix, but mark the envelope
		// incomplete so enforcing modes fail closed on the discarded suffix. If a
		// prior reversible step already produced a complete source-sized node,
		// defer that decision to the transformed node; it may repair the apparent
		// envelope and will otherwise reproduce the same malformed signal.
		recognized = true
		incomplete = incomplete || len(steps) == 0
		appendText(decoded, true)
	} else if looksLikeMalformedBase64(value) && len(steps) == 0 {
		// Strong, token-shaped Base64 with malformed terminal padding is an
		// incomplete inspection, not an ordinary identifier. Textual data URLs
		// are handled above and return before this branch.
		recognized = true
		incomplete = true
	}
	return steps, recognized, incomplete
}

// hasUnclosedPercentPlaceholderCollision retains the existing fail-closed
// contract for an unterminated double-percent identifier whose second opening
// percent exposes a printable %HH escape. A closed collision is different: the
// original placeholder interpretation and the reversible decoded view are both
// bounded and scanned, so it remains complete.
func hasUnclosedPercentPlaceholderCollision(value string) bool {
	for start := 0; start < len(value); start++ {
		if value[start] != '%' || !hasPercentPlaceholderCollisionPrefix(value, start) {
			continue
		}
		if _, _, ok := percentPlaceholderSpan(value, start); ok {
			continue
		}

		bodyStart := start + 2
		bodyEnd := minInt(len(value), bodyStart+maxPercentPlaceholderBodyBytes)
		identifierMarker := false
		for index := bodyStart + 2; index < bodyEnd; index++ {
			if index+1 < len(value) && value[index] == '%' && value[index+1] == '%' {
				identifierMarker = false
				break
			}
			allowed, marker := percentPlaceholderBodyByte(value[index])
			if !allowed {
				break
			}
			identifierMarker = identifierMarker || marker
		}
		if identifierMarker {
			return true
		}
	}
	return false
}

func percentEscapeCounts(value string) (valid, invalid int, closedPlaceholder bool) {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if end, ok := percentPlaceholderEnd(value, index); ok {
			closedPlaceholder = true
			index = end - 1
			continue
		}
		if index+2 < len(value) && isHexByte(value[index+1]) && isHexByte(value[index+2]) {
			valid++
			index += 2
			continue
		}
		invalid++
	}
	return valid, invalid, closedPlaceholder
}

// hasMalformedPercentEscapeOutsidePlaceholders keeps malformed textual data
// URLs fail-closed without treating Windows/template placeholders such as
// %USER% and %DB_HOST% as broken URI escapes. Closed collision forms are also
// safe here because the source and reversible decoded view are both scanned.
func hasMalformedPercentEscapeOutsidePlaceholders(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if end, _, ok := percentPlaceholderSpan(value, index); ok {
			index = end - 1
			continue
		}
		if index+2 >= len(value) || !isHexByte(value[index+1]) || !isHexByte(value[index+2]) {
			return true
		}
		index += 2
	}
	return false
}

// hasStrongMalformedPercentTripletOutsidePlaceholders catches unambiguous
// percent-escape shapes such as %ZZ without classifying modulo expressions,
// printf syntax, or closed environment/template placeholders as URI data.
func hasStrongMalformedPercentTripletOutsidePlaceholders(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if end, ok := percentPlaceholderEnd(value, index); ok {
			index = end - 1
			continue
		}
		if index+2 < len(value) &&
			isASCIIAlphaNumeric(value[index+1]) && isASCIIAlphaNumeric(value[index+2]) &&
			(!isHexByte(value[index+1]) || !isHexByte(value[index+2])) {
			return true
		}
	}
	return false
}

// hasMalformedPercentEscapeInEncodedToken distinguishes an interrupted
// percent-encoded token from unrelated percent syntax elsewhere in the same
// string. Encoded separators end the token, so a trailing placeholder or
// modulo expression does not poison an otherwise valid decoded view. The
// malformed triplet remains verbatim in that view; this signal only marks the
// inspection incomplete so enforcing callers fail closed.
func hasMalformedPercentEscapeInEncodedToken(value string) bool {
	tokenHasValidEscape := false
	tokenHasMalformedEscape := false
	finishToken := func() bool {
		malformed := tokenHasValidEscape && tokenHasMalformedEscape
		tokenHasValidEscape = false
		tokenHasMalformedEscape = false
		return malformed
	}

	for index := 0; index < len(value); {
		if value[index] == '%' {
			if end, ok := percentPlaceholderEnd(value, index); ok {
				if finishToken() {
					return true
				}
				index = end
				continue
			}
			if index+2 < len(value) && isHexByte(value[index+1]) && isHexByte(value[index+2]) {
				decoded := hexByteValue(value[index+1])<<4 | hexByteValue(value[index+2])
				if isPercentTokenByte(decoded) {
					tokenHasValidEscape = true
				} else if finishToken() {
					return true
				}
				index += 3
				continue
			}
			if index+2 < len(value) && isASCIIAlphaNumeric(value[index+1]) && isASCIIAlphaNumeric(value[index+2]) {
				tokenHasMalformedEscape = true
				index += 3
				continue
			}
			if finishToken() {
				return true
			}
			index++
			continue
		}
		if isPercentTokenByte(value[index]) {
			index++
			continue
		}
		if finishToken() {
			return true
		}
		index++
	}
	return finishToken()
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isPercentTokenByte(value byte) bool {
	return isASCIIAlphaNumeric(value) || value == '_' || value == '-' || value == '.' || value == '~' || value >= utf8.RuneSelf
}

func percentDecodedViewMustFailClosed(validEscapes int) bool {
	// Any recognized percent envelope that cannot produce inspectable text is an
	// incomplete inspection. Ordinary placeholders are excluded before decoding
	// by percentPlaceholderEnd, so malformed trailing escapes cannot be used to
	// discard an otherwise meaningful decoded malicious prefix.
	return validEscapes > 0
}

func isHexByte(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
}

// decodePercentEscapesBounded decodes every valid %HH triplet while copying
// malformed or ordinary percent signs verbatim. Decoding is lossless with
// respect to unrecognized input and never constructs an intermediate beyond
// the source-byte budget. Callers divide a larger result into independently
// bounded classifier views before admitting it to the decode traversal.
func decodePercentEscapesBounded(value string, plusAsSpace bool) (string, bool) {
	var builder strings.Builder
	changed := false
	startChangedView := func(prefixBytes int) bool {
		// The first transformation contributes one output byte, so a prefix that
		// already fills the budget cannot produce a bounded derived view.
		if prefixBytes >= maxDecodeSourceBytes {
			return false
		}
		builder.Grow(minInt(len(value), maxDecodeSourceBytes))
		builder.WriteString(value[:prefixBytes])
		changed = true
		return true
	}
	for index := 0; index < len(value); index++ {
		if changed && builder.Len() >= maxDecodeSourceBytes {
			return "", false
		}
		if value[index] == '%' {
			if end, ok := percentPlaceholderEnd(value, index); ok {
				if changed && builder.Len()+end-index > maxDecodeSourceBytes {
					return "", false
				}
				if changed {
					builder.WriteString(value[index:end])
				}
				index = end - 1
				continue
			}
			if index+2 < len(value) && isHexByte(value[index+1]) && isHexByte(value[index+2]) {
				if !changed && !startChangedView(index) {
					return "", false
				}
				builder.WriteByte(hexByteValue(value[index+1])<<4 | hexByteValue(value[index+2]))
				index += 2
				continue
			}
		}
		if plusAsSpace && value[index] == '+' {
			if !changed && !startChangedView(index) {
				return "", false
			}
			builder.WriteByte(' ')
			continue
		}
		if changed {
			builder.WriteByte(value[index])
		}
	}
	if !changed {
		// Unchanged placeholder/percent syntax is already present in the source
		// view. Reuse it without charging the derived-view output budget.
		return value, true
	}
	return builder.String(), true
}

const maxPercentPlaceholderBodyBytes = 128

// percentPlaceholderEnd recognizes bounded single- and double-percent
// identifier placeholders such as %DB_HOST% and %%ABCD%%. A body must contain
// an identifier marker, so repeated numeric percent envelopes cannot suppress
// decoding. Printable escape-leading collisions such as %%62uild%% are
// deliberately excluded: the caller preserves the source and also emits the
// reversible decoded view.
func percentPlaceholderEnd(value string, start int) (int, bool) {
	end, body, ok := percentPlaceholderSpan(value, start)
	if !ok || percentPlaceholderCollisionBody(body) {
		return 0, false
	}
	return end, true
}

func percentPlaceholderSpan(value string, start int) (int, string, bool) {
	if start < 0 || start >= len(value) || value[start] != '%' {
		return 0, "", false
	}
	delimiterBytes := 1
	if start+1 < len(value) && value[start+1] == '%' {
		delimiterBytes = 2
	}
	bodyStart := start + delimiterBytes
	searchEnd := minInt(len(value), bodyStart+maxPercentPlaceholderBodyBytes+delimiterBytes)
	identifierMarker := false
	for index := bodyStart; index < searchEnd; index++ {
		if value[index] == '%' {
			if delimiterBytes == 2 && (index+1 >= searchEnd || value[index+1] != '%') {
				return 0, "", false
			}
			if index == bodyStart || !identifierMarker {
				return 0, "", false
			}
			if delimiterBytes == 1 && index+2 < len(value) &&
				isASCIIAlphaNumeric(value[index+1]) && isASCIIAlphaNumeric(value[index+2]) {
				// The apparent closer is also the opening of another percent
				// token. Keep the conservative encoded-token interpretation.
				return 0, "", false
			}
			return index + delimiterBytes, value[bodyStart:index], true
		}
		allowed, marker := percentPlaceholderBodyByte(value[index])
		if !allowed {
			return 0, "", false
		}
		identifierMarker = identifierMarker || marker
	}
	return 0, "", false
}

func percentPlaceholderBodyByte(value byte) (allowed, marker bool) {
	switch {
	case value >= '0' && value <= '9':
		return true, false
	case value >= 'A' && value <= 'Z', value >= 'a' && value <= 'z':
		return true, true
	case value == '_' || value == '-' || value == '.':
		return true, true
	default:
		return false, false
	}
}

func percentPlaceholderCollisionBody(body string) bool {
	if len(body) < 2 || !isHexByte(body[0]) || !isHexByte(body[1]) {
		return false
	}
	decoded := hexByteValue(body[0])<<4 | hexByteValue(body[1])
	return decoded >= 0x20 && decoded <= 0x7e
}

func hasPercentPlaceholderCollisionPrefix(value string, start int) bool {
	if start < 0 || start+4 > len(value) || value[start] != '%' || value[start+1] != '%' {
		return false
	}
	return percentPlaceholderCollisionBody(value[start+2 : start+4])
}

func hexByteValue(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		return value - 'A' + 10
	}
}

func looksLikeMalformedBase64(value string) bool {
	trimmed := strings.TrimSpace(value)
	if compact, ok := horizontalBase64Candidate(trimmed); ok {
		trimmed = compact
	} else if strings.ContainsAny(trimmed, " \t") {
		return false
	}
	if len(trimmed) < minBase64SourceBytes || strings.Contains(trimmed, "://") {
		return false
	}
	// Terminal '=' is the explicit padding signal. Restrict it to the final
	// four bytes so ordinary key=value text and URLs do not become truncation
	// failures merely because they contain an equals sign.
	padding := strings.IndexByte(trimmed, '=')
	if padding < 0 {
		if !strings.ContainsAny(trimmed, "\r\n") {
			return false
		}
	} else if padding < len(trimmed)-4 {
		return false
	}
	base64ish := 0
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		switch {
		case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z',
			character >= '0' && character <= '9', strings.ContainsRune("+/=_-\r\n", rune(character)):
			base64ish++
		}
	}
	return base64ish*100 >= len(trimmed)*95
}

func decodeTextDataURL(value string) (decoded string, found bool, ok bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < len("data:,") || !strings.EqualFold(trimmed[:len("data:")], "data:") {
		return "", false, false
	}
	comma := strings.IndexByte(trimmed, ',')
	if comma < 0 {
		return "", true, false
	}
	header := strings.ToLower(trimmed[len("data:"):comma])
	mediaType := header
	if semicolon := strings.IndexByte(mediaType, ';'); semicolon >= 0 {
		mediaType = mediaType[:semicolon]
	}
	if !isTextualDataMIME(mediaType) {
		return "", false, false
	}
	payload := trimmed[comma+1:]
	if len(payload) > maxDecodeSourceBytes {
		return "", true, false
	}
	if strings.Contains(header, ";base64") {
		decodedBytes, valid := decodeBase64Bytes(payload, 1)
		if !valid || !isInspectableDecodedText(decodedBytes) {
			return "", true, false
		}
		return string(decodedBytes), true, true
	}
	decoded, ok = decodePercentEscapesBounded(payload, false)
	if !ok || !isInspectableDecodedText([]byte(decoded)) {
		return "", true, false
	}
	return decoded, true, true
}

func isTextualDataMIME(mediaType string) bool {
	mediaType = strings.TrimSpace(strings.ToLower(mediaType))
	return mediaType == "" || strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" || mediaType == "application/xml" ||
		strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
}

func decodeBase64Text(value string, minimum int) (string, bool, bool) {
	decoded, found := decodeBase64Bytes(value, minimum)
	if !found {
		if compact, ok := horizontalBase64Candidate(value); ok {
			decoded, found = decodeBase64Bytes(compact, minimum)
		}
	}
	if !found {
		return "", false, false
	}
	if !isInspectableDecodedText(decoded) {
		// Bare alphanumeric identifiers are syntactically compatible with raw
		// Base64. Treat them as opaque only when the source carries an explicit
		// encoding signal; otherwise preserving the original is safer than
		// turning routine IDs into scan-limit failures.
		return "", hasStrongBase64Signal(value), false
	}
	return string(decoded), true, true
}

func recoverMalformedBase64Prefix(value string, minimum int) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if compact, ok := horizontalBase64Candidate(trimmed); ok {
		trimmed = compact
	}
	if len(trimmed) < minimum || strings.Contains(trimmed, "://") {
		return "", false
	}
	padding := strings.IndexByte(trimmed, '=')
	if padding < 0 {
		return "", false
	}
	end := padding + 1
	if end < len(trimmed) && trimmed[end] == '=' {
		end++
	}
	for ; end > padding; end-- {
		if end >= len(trimmed) {
			continue
		}
		if !malformedBase64Suffix(trimmed[end:]) {
			continue
		}
		decoded, found := decodeBase64Bytes(trimmed[:end], minimum)
		if found && isInspectableText(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func malformedBase64Suffix(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+' || r == '/' || r == '-' || r == '_' || r == '=' || r == '\r' || r == '\n':
		default:
			return false
		}
	}
	return true
}

func stripHorizontalBase64Whitespace(value string) (string, bool) {
	if !strings.ContainsAny(value, " \t") {
		return value, false
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		if r != ' ' && r != '\t' {
			builder.WriteRune(r)
		}
	}
	return builder.String(), true
}

func horizontalBase64Candidate(value string) (string, bool) {
	compact, changed := stripHorizontalBase64Whitespace(value)
	if !changed || len(compact) < minBase64SourceBytes {
		return value, false
	}
	for _, r := range value {
		switch {
		case r == ' ' || r == '\t' || r == '\r' || r == '\n',
			r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+' || r == '/' || r == '-' || r == '_' || r == '=':
		default:
			return value, false
		}
	}
	if strings.HasSuffix(strings.TrimSpace(compact), "=") {
		return compact, true
	}
	chunks := strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(chunks) < 2 {
		return value, false
	}
	for index, chunk := range chunks {
		chunk = strings.ReplaceAll(strings.ReplaceAll(chunk, "\r", ""), "\n", "")
		if chunk == "" || (index < len(chunks)-1 && len(chunk)%4 != 0) {
			return value, false
		}
	}
	return compact, true
}

func hasStrongBase64Signal(value string) bool {
	if strings.ContainsAny(value, "=+/_\r\n") {
		return true
	}
	compact, _, valid := compactBase64(value)
	if !valid || len(compact) < 64 {
		return false
	}
	var alphabet [256]bool
	distinct := 0
	for index := 0; index < len(compact); index++ {
		value := compact[index]
		if !alphabet[value] {
			alphabet[value] = true
			distinct++
		}
	}
	return distinct >= 16
}

func decodeBase64Bytes(value string, minimum int) ([]byte, bool) {
	compact, urlAlphabet, valid := compactBase64(value)
	if !valid || len(compact) < minimum || len(compact)%4 == 1 {
		return nil, false
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding}
	if urlAlphabet {
		encodings = []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding}
	}
	for _, encoding := range encodings {
		decoded := make([]byte, encoding.DecodedLen(len(compact)))
		n, err := encoding.Decode(decoded, []byte(compact))
		if err == nil {
			return decoded[:n], true
		}
	}
	return nil, false
}

func compactBase64(value string) (string, bool, bool) {
	var builder strings.Builder
	builder.Grow(len(value))
	urlAlphabet := false
	padding := false
	for _, r := range value {
		switch {
		case r == '\r' || r == '\n':
			continue
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
			if padding {
				return "", false, false
			}
			builder.WriteRune(r)
		case r == '-' || r == '_':
			if padding {
				return "", false, false
			}
			urlAlphabet = true
			builder.WriteRune(r)
		case r == '=':
			padding = true
			builder.WriteRune(r)
		default:
			return "", false, false
		}
	}
	compact := builder.String()
	if strings.Count(compact, "=") > 2 || (strings.ContainsAny(compact, "-_") && strings.ContainsAny(compact, "+/")) {
		return "", false, false
	}
	return compact, urlAlphabet, true
}

func isInspectableText(value []byte) bool {
	if len(value) == 0 || len(value) > maxDecodedVariantBytes || !utf8.Valid(value) {
		return false
	}
	return isInspectableDecodedText(value)
}

// isInspectableDecodedText validates a complete, source-bounded decoded
// stream before it is divided into independently budgeted classifier views.
// Individual emitted views remain capped by maxDecodedVariantBytes.
func isInspectableDecodedText(value []byte) bool {
	if len(value) == 0 || len(value) > maxDecodeSourceBytes || !utf8.Valid(value) {
		return false
	}
	printable := 0
	meaningful := false
	for _, r := range string(value) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			printable++
		case unicode.IsControl(r):
			return false
		case unicode.IsPrint(r):
			printable++
			meaningful = meaningful || unicode.IsLetter(r) || unicode.IsNumber(r)
		}
	}
	return printable > 0 && meaningful
}

// splitDecodedView keeps every derived field within maxDecodedVariantBytes
// without requiring a source-sized field to be admitted as one variant. The
// overlap prevents an encoded token at a fragment boundary from disappearing
// between classifier views. The outer traversal still enforces
// maxDecodedVariants and maxDecodeLayers.
func splitDecodedView(value string) []string {
	if len(value) <= maxDecodedVariantBytes {
		return []string{value}
	}
	overlap := minInt(ClassificationOverlapReserveBytes, maxDecodedVariantBytes/2)
	stride := maxDecodedVariantBytes - overlap
	fragments := make([]string, 0, (len(value)+stride-1)/stride)
	for start := 0; start < len(value); {
		for start > 0 && !utf8.RuneStart(value[start]) {
			start++
		}
		end := minInt(len(value), start+maxDecodedVariantBytes)
		for end < len(value) && !utf8.RuneStart(value[end]) {
			end--
		}
		if end <= start {
			break
		}
		fragments = append(fragments, value[start:end])
		if end == len(value) {
			break
		}
		start += stride
	}
	return fragments
}

func looksPotentiallyEncoded(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= len("data:") && strings.EqualFold(trimmed[:len("data:")], "data:") ||
		strings.Contains(trimmed, "%") ||
		(strings.Contains(trimmed, "&") && strings.Contains(trimmed, ";")) {
		return true
	}
	candidate := trimmed
	horizontal := false
	if compact, ok := horizontalBase64Candidate(trimmed); ok {
		candidate = compact
		horizontal = true
	}
	_, _, valid := compactBase64(candidate)
	return valid && len(candidate) >= minBase64SourceBytes && (horizontal || hasStrongBase64Signal(candidate))
}

// looksPotentiallyEncodedOversized performs only a no-copy envelope probe.
// Oversized values are never decoded, so building a compact Base64 clone merely
// to decide the fail-closed bit would make peak memory proportional to an input
// that is already outside the decode budget.
func looksPotentiallyEncodedOversized(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= len("data:") && strings.EqualFold(trimmed[:len("data:")], "data:") ||
		strings.Contains(trimmed, "%") ||
		(strings.Contains(trimmed, "&") && strings.Contains(trimmed, ";")) {
		return true
	}
	var alphabet [256]bool
	count := 0
	distinct := 0
	padding := 0
	standardAlphabet := false
	urlAlphabet := false
	strongSignal := false
	horizontal := false
	horizontalChunks := 0
	chunkBytes := 0
	previousChunkBytes := 0
	boundaryPending := false
	for index := 0; index < len(trimmed); index++ {
		value := trimmed[index]
		if boundaryPending && value != ' ' && value != '\t' && value != '\r' && value != '\n' {
			if previousChunkBytes%4 != 0 {
				return false
			}
			boundaryPending = false
		}
		switch {
		case value == ' ' || value == '\t':
			horizontal = true
			if chunkBytes != 0 {
				horizontalChunks++
				boundaryPending = true
				previousChunkBytes = chunkBytes
				chunkBytes = 0
			}
			continue
		case value == '\r' || value == '\n':
			strongSignal = strongSignal || value == '\r' || value == '\n'
			continue
		case value >= 'A' && value <= 'Z', value >= 'a' && value <= 'z',
			value >= '0' && value <= '9':
			if padding != 0 {
				return false
			}
		case value == '+' || value == '/':
			if padding != 0 {
				return false
			}
			standardAlphabet = true
			strongSignal = true
		case value == '-' || value == '_':
			if padding != 0 {
				return false
			}
			urlAlphabet = true
			strongSignal = true
		case value == '=':
			padding++
			strongSignal = true
			if padding > 2 {
				return false
			}
		default:
			return false
		}
		count++
		chunkBytes++
		if !alphabet[value] {
			alphabet[value] = true
			distinct++
		}
	}
	if standardAlphabet && urlAlphabet || count < minBase64SourceBytes {
		return false
	}
	if chunkBytes != 0 {
		horizontalChunks++
	}
	return horizontal && horizontalChunks >= 2 || strongSignal || count >= 64 && distinct >= 16
}
