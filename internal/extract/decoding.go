package extract

import (
	"encoding/base64"
	"html"
	"net/url"
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
	appendText := func(decoded string, ok bool) bool {
		if !ok || decoded == value || !isInspectableText([]byte(decoded)) {
			return false
		}
		steps = append(steps, decodeStep{text: decoded})
		return true
	}

	if decoded, found, ok := decodeTextDataURL(value); found {
		recognized = true
		if !ok {
			incomplete = true
		} else {
			appendText(decoded, true)
		}
		// A data URL is one encoding envelope. Do not reinterpret its header as
		// an unrelated Base64 or HTML candidate.
		return steps, recognized, incomplete
	}

	if strings.Contains(value, "%") {
		validEscapes, invalidEscapes := percentEscapeSignals(value)
		if validEscapes {
			recognized = true
			// net/url rejects the whole string when even one percent escape is
			// malformed. Remember that partial encoding signal before attempting
			// either decoder so a valid escaped prefix followed by "%ZZ" cannot
			// silently fall back to scanning only the encoded source.
			incomplete = incomplete || invalidEscapes
		}
		if decoded, err := url.PathUnescape(value); err == nil && decoded != value {
			recognized = true
			incomplete = !appendText(decoded, true) || incomplete
		} else if err != nil && validEscapes {
			incomplete = true
		}
		// QueryEscape represents spaces as '+'. Generate this second bounded
		// view only when a percent escape is already present, so ordinary plus
		// signs are never rewritten speculatively.
		if decoded, err := url.QueryUnescape(value); err == nil && decoded != value {
			recognized = true
			incomplete = !appendText(decoded, true) || incomplete
		} else if err != nil && validEscapes {
			incomplete = true
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

func percentEscapeSignals(value string) (valid, invalid bool) {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if index+2 < len(value) && isHexByte(value[index+1]) && isHexByte(value[index+2]) {
			valid = true
			index += 2
			continue
		}
		invalid = true
	}
	return valid, invalid
}

func isHexByte(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
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
	decoded, err := url.PathUnescape(payload)
	if err != nil || !isInspectableText([]byte(decoded)) {
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
