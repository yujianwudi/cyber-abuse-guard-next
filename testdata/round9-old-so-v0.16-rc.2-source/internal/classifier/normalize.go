package classifier

import (
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// This mirrors extract.HardMaxScanBytes without importing the extractor.
	maxClassifierInputBytes           = 4 << 20
	maxClassifierNormalizedRunes      = 1 << 20
	maxClassifierParts                = 4096
	compactHardBoundary          rune = -1 // impossible in decoded UTF-8 input
)

type normalizedViews struct {
	standardRunes []rune
	truncated     bool
	storageUsed   int
}

type normalizationScratch struct {
	iterator norm.Iter
}

// normalizedRunePool amortizes the bounded 4 MiB rune backing array used by
// extreme inputs. Buffers are scrubbed through storageUsed before reuse so no
// prompt-derived runes survive a classification call.
var normalizedRunePool sync.Pool

func takeNormalizedRuneBuffer() []rune {
	value := normalizedRunePool.Get()
	if value == nil {
		return nil
	}
	return value.([]rune)[:0]
}

func putNormalizedRuneBuffer(buffer []rune, storageUsed int) {
	if cap(buffer) == 0 || cap(buffer) > maxClassifierNormalizedRunes {
		return
	}
	if storageUsed > cap(buffer) {
		storageUsed = cap(buffer)
	}
	scrubNormalizedRuneBuffer(buffer, storageUsed)
	normalizedRunePool.Put(buffer[:0])
}

func scrubNormalizedRuneBuffer(buffer []rune, storageUsed int) {
	if storageUsed > cap(buffer) {
		storageUsed = cap(buffer)
	}
	if storageUsed > 0 {
		clear(buffer[:storageUsed])
	}
}

func normalizeParts(parts []string) normalizedViews {
	var scratch normalizationScratch
	return normalizePartsInto(parts, nil, &scratch)
}

// normalizePartsInto is normalizeParts with caller-owned rune storage. The
// classifier rotates a small number of buffers while processing multipart
// requests, avoiding one proportional allocation per part.
func normalizePartsInto(parts []string, destination []rune, scratch *normalizationScratch) normalizedViews {
	estimated := 0
	for _, part := range parts {
		if len(part) >= maxClassifierNormalizedRunes-estimated {
			estimated = maxClassifierNormalizedRunes
			break
		}
		estimated += len(part)
	}
	var runes []rune
	if cap(destination) >= estimated {
		runes = destination[:0]
	} else {
		runes = make([]rune, 0, estimated)
	}
	remainingBytes := maxClassifierInputBytes
	truncated := false
	for partIndex, part := range parts {
		if partIndex >= maxClassifierParts || remainingBytes <= 0 || len(runes) >= maxClassifierNormalizedRunes {
			truncated = true
			break
		}
		if partIndex > 0 {
			runes = appendBoundary(runes)
		}
		consumedBytes := len(part)
		if consumedBytes > remainingBytes {
			consumedBytes = remainingBytes
			part = validUTF8Prefix(part, consumedBytes)
			truncated = true
		} else {
			part = validUTF8Prefix(part, len(part))
		}
		remainingBytes -= consumedBytes

		scratch.iterator.InitString(norm.NFKC, part)
		for !scratch.iterator.Done() && len(runes) < maxClassifierNormalizedRunes {
			segment := scratch.iterator.Next()
			for len(segment) > 0 && len(runes) < maxClassifierNormalizedRunes {
				r, size := utf8.DecodeRune(segment)
				segment = segment[size:]
				if unicode.In(r, unicode.Cf) || isExplicitZeroWidth(r) {
					continue
				}
				r = unicode.ToLower(r)
				if replacement, ok := commonHomoglyphReplacement(r); ok {
					r = replacement
				}
				runes = append(runes, r)
			}
		}
		if !scratch.iterator.Done() {
			truncated = true
			break
		}
	}

	return finishNormalizedViews(runes, truncated)
}

// normalizeBytesInto is the single-part byte equivalent used by the streaming
// overlap carry. It avoids copying every consumed window into a temporary
// string before NFKC iteration. Streaming callers have already established a
// valid UTF-8 and normalization boundary; an invalid byte slice is therefore
// reported as truncated instead of being repaired silently.
func normalizeBytesInto(value []byte, destination []rune, scratch *normalizationScratch) normalizedViews {
	estimated := len(value)
	if estimated > maxClassifierNormalizedRunes {
		estimated = maxClassifierNormalizedRunes
	}
	var runes []rune
	if cap(destination) >= estimated {
		runes = destination[:0]
	} else {
		runes = make([]rune, 0, estimated)
	}
	truncated := false
	if len(value) > maxClassifierInputBytes {
		value = value[:maxClassifierInputBytes]
		for attempts := 0; len(value) > 0 && attempts < utf8.UTFMax && !utf8.Valid(value); attempts++ {
			value = value[:len(value)-1]
		}
		truncated = true
	}
	if !utf8.Valid(value) {
		return normalizedViews{standardRunes: runes, truncated: true}
	}

	scratch.iterator.Init(norm.NFKC, value)
	for !scratch.iterator.Done() && len(runes) < maxClassifierNormalizedRunes {
		segment := scratch.iterator.Next()
		for len(segment) > 0 && len(runes) < maxClassifierNormalizedRunes {
			r, size := utf8.DecodeRune(segment)
			segment = segment[size:]
			if unicode.In(r, unicode.Cf) || isExplicitZeroWidth(r) {
				continue
			}
			r = unicode.ToLower(r)
			if replacement, ok := commonHomoglyphReplacement(r); ok {
				r = replacement
			}
			runes = append(runes, r)
		}
	}
	if !scratch.iterator.Done() {
		truncated = true
	}
	return finishNormalizedViews(runes, truncated)
}

func finishNormalizedViews(runes []rune, truncated bool) normalizedViews {
	for i, r := range runes {
		if r == '!' && ((i > 0 && unicode.IsSpace(runes[i-1])) || (i+1 < len(runes) && unicode.IsSpace(runes[i+1]))) {
			continue
		}
		if replacement, ok := leetReplacement(r); ok {
			left := letterNear(runes, i, -1) || isolatedLetterNear(runes, i, -1)
			right := letterNear(runes, i, 1) || isolatedLetterNear(runes, i, 1)
			if left && right {
				runes[i] = replacement
			}
		}
	}

	storageUsed := len(runes)
	standard := runes[:0]
	lastSpace := true
	for _, r := range runes {
		if isLineBoundary(r) || r == compactHardBoundary {
			standard = appendBoundary(standard)
			lastSpace = true
			continue
		}
		if unicode.IsSpace(r) {
			if !lastSpace {
				standard = append(standard, ' ')
				lastSpace = true
			}
			continue
		}
		standard = append(standard, r)
		lastSpace = false
	}
	for len(standard) > 0 && standard[len(standard)-1] == ' ' {
		standard = standard[:len(standard)-1]
	}
	return normalizedViews{standardRunes: standard, truncated: truncated, storageUsed: storageUsed}
}

func appendBoundary(runes []rune) []rune {
	for len(runes) > 0 && runes[len(runes)-1] == ' ' {
		runes = runes[:len(runes)-1]
	}
	if len(runes) == 0 || runes[len(runes)-1] != compactHardBoundary {
		runes = append(runes, compactHardBoundary)
	}
	return runes
}

func isLineBoundary(r rune) bool {
	switch r {
	case '\n', '\r', '\u0085', '\u2028', '\u2029':
		return true
	default:
		return false
	}
}

func isCompactRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isASCIILetterOrDigit(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func compactString(runes []rune) string {
	var compact strings.Builder
	compact.Grow(len(runes))
	for _, r := range runes {
		if isCompactRune(r) {
			compact.WriteRune(r)
		}
	}
	return compact.String()
}

func validUTF8Prefix(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) > limit {
		value = value[:limit]
	}
	if utf8.ValidString(value) {
		return value
	}
	return strings.ToValidUTF8(value, "\ufffd")
}

func isExplicitZeroWidth(r rune) bool {
	switch r {
	case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad':
		return true
	default:
		return false
	}
}

// commonHomoglyphReplacement covers the small set of Cyrillic and Greek
// letters most often substituted into otherwise-Latin security terms. It is
// intentionally not a general transliterator: unmapped script text remains
// untouched, limiting false matches in legitimate non-English prose.
func commonHomoglyphReplacement(r rune) (rune, bool) {
	switch r {
	case '\u0430', '\u03b1': // Cyrillic a, Greek alpha
		return 'a', true
	case '\u0432': // Cyrillic ve commonly used as a visual b
		return 'b', true
	case '\u0441', '\u03f2': // Cyrillic es, lunate sigma
		return 'c', true
	case '\u0501': // Cyrillic komi de
		return 'd', true
	case '\u0435', '\u03b5': // Cyrillic ie, Greek epsilon
		return 'e', true
	case '\u04bb': // Cyrillic shha
		return 'h', true
	case '\u0456', '\u03b9', '\u0131': // Cyrillic i, Greek iota, dotless i
		return 'i', true
	case '\u0458': // Cyrillic je
		return 'j', true
	case '\u03ba', '\u043a': // Greek kappa, Cyrillic ka
		return 'k', true
	case '\u04cf': // Cyrillic palochka
		return 'l', true
	case '\u043c': // Cyrillic em
		return 'm', true
	case '\u03bd': // Greek nu
		return 'v', true
	case '\u043e', '\u03bf': // Cyrillic o, Greek omicron
		return 'o', true
	case '\u0440', '\u03c1': // Cyrillic er, Greek rho
		return 'p', true
	case '\u0455': // Cyrillic dze
		return 's', true
	case '\u0442', '\u03c4': // Cyrillic te, Greek tau
		return 't', true
	case '\u0445', '\u03c7': // Cyrillic ha, Greek chi
		return 'x', true
	case '\u0443': // Cyrillic u
		return 'y', true
	default:
		return 0, false
	}
}

func leetReplacement(r rune) (rune, bool) {
	switch r {
	case '0':
		return 'o', true
	case '1', '!':
		return 'i', true
	case '3':
		return 'e', true
	case '4', '@':
		return 'a', true
	case '5', '$':
		return 's', true
	case '7':
		return 't', true
	default:
		return 0, false
	}
}

func letterNear(runes []rune, index, direction int) bool {
	for steps, i := 0, index+direction; i >= 0 && i < len(runes) && steps < 12; steps, i = steps+1, i+direction {
		r := runes[i]
		if unicode.IsSpace(r) || r == compactHardBoundary {
			return false
		}
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// isolatedLetterNear recognizes bounded single-rune obfuscation spans such as
// "c 0 0 k" without treating digits between ordinary multi-letter words as
// leet substitutions. The fixed lookaround cap keeps normalization linear.
func isolatedLetterNear(runes []rune, index, direction int) bool {
	for steps, i := 0, index+direction; i >= 0 && i < len(runes) && steps < 12; steps, i = steps+1, i+direction {
		r := runes[i]
		if unicode.IsSpace(r) || (!isCompactRune(r) && r != compactHardBoundary) {
			continue
		}
		if !unicode.IsLetter(r) {
			continue
		}
		farSide := i + direction
		return farSide < 0 || farSide >= len(runes) || !isCompactRune(runes[farSide])
	}
	return false
}
