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
	maxDecodedVariants     = 8
	minBase64SourceBytes   = 16
)

type decodeNode struct {
	text  string
	depth int
}

type decodeStep struct {
	text string
}

// decodeBoundedText recognizes a deliberately small, non-recursive encoding
// set: textual data URLs, URL percent escapes, HTML entities, and Base64 text.
// It performs no decompression, archive parsing, or network access. The
// original string is retained by the caller and each unique decoded view is
// bounded by both layer and byte limits.
func decodeBoundedText(value string) (variants []string, encoded bool, incomplete bool) {
	if len(value) > maxDecodeSourceBytes {
		potentiallyEncoded := looksPotentiallyEncoded(value)
		return nil, potentiallyEncoded, potentiallyEncoded
	}
	queue := []decodeNode{{text: value}}
	seen := map[string]struct{}{value: {}}
	totalBytes := 0
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
			if len(step.text) > maxDecodedVariantBytes || totalBytes > maxDecodedVariantBytes-len(step.text) || len(variants) >= maxDecodedVariants {
				incomplete = true
				continue
			}
			seen[step.text] = struct{}{}
			variants = append(variants, step.text)
			totalBytes += len(step.text)
			queue = append(queue, decodeNode{text: step.text, depth: node.depth + 1})
		}
	}
	return variants, encoded, incomplete
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
		if !ok || decoded == value || !isInspectableText([]byte(decoded)) {
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
				if isInspectableText([]byte(decoded)) {
					steps = append(steps, decodeStep{text: decoded})
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
					if isInspectableText([]byte(decoded)) {
						steps = append(steps, decodeStep{text: decoded})
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
		// incomplete so enforcing modes fail closed on the discarded suffix.
		recognized = true
		incomplete = true
		appendText(decoded, true)
	} else if looksLikeMalformedBase64(value) {
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
// respect to unrecognized input and never constructs a view beyond the
// per-variant inspection budget.
func decodePercentEscapesBounded(value string, plusAsSpace bool) (string, bool) {
	var builder strings.Builder
	changed := false
	startChangedView := func(prefixBytes int) bool {
		// The first transformation contributes one output byte, so a prefix that
		// already fills the budget cannot produce a bounded derived view.
		if prefixBytes >= maxDecodedVariantBytes {
			return false
		}
		builder.Grow(minInt(len(value), maxDecodedVariantBytes))
		builder.WriteString(value[:prefixBytes])
		changed = true
		return true
	}
	for index := 0; index < len(value); index++ {
		if changed && builder.Len() >= maxDecodedVariantBytes {
			return "", false
		}
		if value[index] == '%' {
			if end, ok := percentPlaceholderEnd(value, index); ok {
				if changed && builder.Len()+end-index > maxDecodedVariantBytes {
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
		if !valid || !isInspectableText(decodedBytes) {
			return "", true, false
		}
		return string(decodedBytes), true, true
	}
	decoded, ok = decodePercentEscapesBounded(payload, false)
	if !ok || !isInspectableText([]byte(decoded)) {
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
	if !isInspectableText(decoded) {
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

func looksPotentiallyEncoded(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(trimmed), "data:") || strings.Contains(trimmed, "%") ||
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
