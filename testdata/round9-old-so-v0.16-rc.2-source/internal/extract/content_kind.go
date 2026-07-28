package extract

import (
	"bytes"
	"strings"
)

const (
	maxContentFenceLineBytes = 512
	contentPieceFieldIDFlag  = uint64(1) << 62
	contentPieceOrdinalBits  = 16
)

type contentKindPiece struct {
	start int
	end   int
	kind  ContentKind
}

type contentByteRange struct {
	start int
	end   int
	kind  ContentKind
}

// fencedCodePlanner recognizes only closed CommonMark-style fenced code
// blocks. It retains at most one short candidate delimiter line plus bounded
// byte ranges; code bodies are never buffered. An unclosed, overlong, or
// over-budget construct remains natural-language content, which is the
// conservative classification fallback.
type fencedCodePlanner struct {
	maxRanges int
	ranges    []contentByteRange
	overflow  bool

	total        int
	lineStart    int
	line         []byte
	lineOverflow bool
	lineNonSpace bool

	inFence          bool
	fenceMarker      byte
	fenceMarkerCount int
	fenceStart       int
	fenceKind        ContentKind

	gapStart        int
	outsideNonSpace bool
}

func newFencedCodePlanner(maxRanges int) *fencedCodePlanner {
	if maxRanges < 1 {
		maxRanges = 1
	}
	return &fencedCodePlanner{
		maxRanges: maxRanges,
		ranges:    make([]contentByteRange, 0, minInt(maxRanges, 8)),
		line:      make([]byte, 0, maxContentFenceLineBytes),
	}
}

func (p *fencedCodePlanner) add(chunk []byte) {
	for _, value := range chunk {
		p.total++
		if len(p.line) < maxContentFenceLineBytes {
			p.line = append(p.line, value)
		} else {
			p.lineOverflow = true
		}
		if !asciiFenceWhitespace(value) {
			p.lineNonSpace = true
		}
		if value == '\n' {
			p.finishLine(p.total)
			p.lineStart = p.total
			p.line = p.line[:0]
			p.lineOverflow = false
			p.lineNonSpace = false
		}
	}
}

func (p *fencedCodePlanner) finish() []contentKindPiece {
	if len(p.line) != 0 || p.lineOverflow {
		p.finishLine(p.total)
	}
	if p.overflow || len(p.ranges) == 0 {
		return nil
	}
	if !p.inFence && !p.outsideNonSpace {
		p.ranges[len(p.ranges)-1].end = p.total
	}

	pieces := make([]contentKindPiece, 0, len(p.ranges)*2+1)
	cursor := 0
	for _, fenced := range p.ranges {
		if cursor < fenced.start {
			pieces = append(pieces, contentKindPiece{
				start: cursor,
				end:   fenced.start,
				kind:  ContentKindNaturalLanguageDirective,
			})
		}
		if fenced.start < fenced.end {
			pieces = append(pieces, contentKindPiece{
				start: fenced.start,
				end:   fenced.end,
				kind:  fenced.kind,
			})
		}
		cursor = fenced.end
	}
	if cursor < p.total {
		pieces = append(pieces, contentKindPiece{
			start: cursor,
			end:   p.total,
			kind:  ContentKindNaturalLanguageDirective,
		})
	}
	return pieces
}

func (p *fencedCodePlanner) finishLine(lineEnd int) {
	if p.lineOverflow {
		if !p.inFence && p.lineNonSpace {
			p.outsideNonSpace = true
		}
		return
	}
	line := trimFenceLineEnding(p.line)
	if !p.inFence {
		marker, count, kind, ok := openingFence(line)
		if !ok {
			if p.lineNonSpace {
				p.outsideNonSpace = true
			}
			return
		}
		p.inFence = true
		p.fenceMarker = marker
		p.fenceMarkerCount = count
		p.fenceKind = kind
		p.fenceStart = p.lineStart
		if !p.outsideNonSpace {
			p.fenceStart = p.gapStart
		}
		return
	}
	if !closingFence(line, p.fenceMarker, p.fenceMarkerCount) {
		return
	}
	p.appendRange(p.fenceStart, lineEnd, p.fenceKind)
	p.inFence = false
	p.fenceMarker = 0
	p.fenceMarkerCount = 0
	p.fenceStart = 0
	p.fenceKind = ContentKindUnknown
	p.gapStart = lineEnd
	p.outsideNonSpace = false
}

func (p *fencedCodePlanner) appendRange(start, end int, kind ContentKind) {
	if start >= end || p.overflow {
		return
	}
	if len(p.ranges) != 0 && start <= p.ranges[len(p.ranges)-1].end &&
		kind == p.ranges[len(p.ranges)-1].kind {
		if end > p.ranges[len(p.ranges)-1].end {
			p.ranges[len(p.ranges)-1].end = end
		}
		return
	}
	if len(p.ranges) >= p.maxRanges {
		p.overflow = true
		p.ranges = nil
		return
	}
	p.ranges = append(p.ranges, contentByteRange{start: start, end: end, kind: kind})
}

func openingFence(line []byte) (byte, int, ContentKind, bool) {
	index := leadingFenceSpaces(line)
	if index < 0 || index >= len(line) || line[index] != '`' && line[index] != '~' {
		return 0, 0, ContentKindUnknown, false
	}
	marker := line[index]
	end := index
	for end < len(line) && line[end] == marker {
		end++
	}
	count := end - index
	if count < 3 {
		return 0, 0, ContentKindUnknown, false
	}
	// CommonMark does not permit a backtick in the info string of a backtick
	// fence. Enforcing that rule also rejects one-line pseudo-fences such as
	// ```dangerous text``` instead of silently downgrading them.
	if marker == '`' && bytes.IndexByte(line[end:], '`') >= 0 {
		return 0, 0, ContentKindUnknown, false
	}
	return marker, count, fencedContentKind(line[end:]), true
}

func fencedContentKind(info []byte) ContentKind {
	fields := strings.Fields(strings.ToLower(string(info)))
	if len(fields) == 0 {
		return ContentKindCodeBlock
	}
	language := strings.Trim(fields[0], "{}.,;:")
	switch language {
	case "log", "logs", "console", "terminal", "stdout", "stderr":
		return ContentKindLogOutput
	case "json", "yaml", "yml", "toml", "ini", "conf", "config", "cfg", "properties", "env":
		return ContentKindConfiguration
	case "md", "markdown":
		return ContentKindDocumentation
	default:
		return ContentKindCodeBlock
	}
}

func closingFence(line []byte, marker byte, minimum int) bool {
	index := leadingFenceSpaces(line)
	if index < 0 || index >= len(line) || line[index] != marker {
		return false
	}
	end := index
	for end < len(line) && line[end] == marker {
		end++
	}
	if end-index < minimum {
		return false
	}
	for ; end < len(line); end++ {
		if line[end] != ' ' && line[end] != '\t' {
			return false
		}
	}
	return true
}

func leadingFenceSpaces(line []byte) int {
	index := 0
	for index < len(line) && line[index] == ' ' && index < 4 {
		index++
	}
	if index > 3 {
		return -1
	}
	return index
}

func trimFenceLineEnding(line []byte) []byte {
	if len(line) != 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) != 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line
}

func asciiFenceWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func shouldSegmentFencedCode(span plannedText) bool {
	// Syntax is independent of provider authority. Preserve fenced boundaries
	// for every ordinary content span; role, turn, and attribution remain
	// unchanged so the classifier can apply their separate policy semantics.
	return span.provenance == ProvenanceContent &&
		span.contentKind == ContentKindNaturalLanguageDirective
}

func contentPieceFieldID(parent uint64, ordinal int) uint64 {
	return contentPieceFieldIDFlag | parent<<contentPieceOrdinalBits | uint64(ordinal+1)
}
