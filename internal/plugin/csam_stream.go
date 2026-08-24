package plugin

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/csamtext"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

// csamTextStreamSink is a bounded side-car for the production extractor sink.
// The existing rules classifier remains the enforcement authority for its own
// taxonomy; this sink only projects the explicitly attributed current user
// content into the independent synthetic CSAM text classifier. It never keeps
// unknown-role, historical, assistant/tool, or tool-payload text.
type csamTextStreamSink struct {
	downstream extract.ChunkSink
	classifier *csamtext.Classifier
	mode       csamtext.Mode

	inputs               []csamtext.Input
	scopeBytes           map[uint64]int
	totalBytes           int
	structuralIncomplete bool
	budgetExceeded       bool
	aborted              bool
	finished             bool
	active               bool
	activeID             uint64
	activeScope          uint64
	activeRole           extract.Role
	activeProv           extract.SegmentProvenance
	activeAttr           extract.UserAttribution
	activeTurn           bool
	activeKeep           bool
	activeText           strings.Builder
	activeCandidateTail  string
	candidateByScope     map[uint64]csamtext.CandidateSignals
	sensitiveCandidate   bool
	result               csamtext.Result
	privacyTaint         bool
}

func newCSAMTextStreamSink(downstream extract.ChunkSink, mode csamtext.Mode) *csamTextStreamSink {
	return &csamTextStreamSink{
		downstream:       downstream,
		classifier:       csamtext.New(),
		mode:             mode,
		scopeBytes:       make(map[uint64]int),
		candidateByScope: make(map[uint64]csamtext.CandidateSignals),
	}
}

func (s *csamTextStreamSink) AddSegment(chunk extract.SegmentChunk) error {
	if s == nil || s.aborted {
		return errors.New("csam text sink is aborted")
	}
	if s.finished {
		return errors.New("csam text sink is finished")
	}
	if s.downstream == nil {
		return errors.New("csam text sink has no downstream")
	}
	// Forward first. The canonical classifier sink owns stream ordering and
	// remains the source of truth for extractor backpressure/errors.
	if err := s.downstream.AddSegment(chunk); err != nil {
		s.Abort()
		return err
	}

	// The side-car has no structural authority over excluded carriers. Do not
	// retain or validate their framing: an unknown/system/assistant/tool,
	// historical, untrusted, or unscoped field is inert even when its own
	// chunks are malformed. If an excluded chunk interrupts an eligible field,
	// the eligible field is incomplete and remains diagnostic-only.
	if !csamTextEligibleChunk(chunk) {
		if s.active {
			s.structuralIncomplete = true
			s.resetActive()
		}
		return nil
	}

	if chunk.Start {
		if s.active {
			s.structuralIncomplete = true
			s.resetActive()
		}
		s.active = true
		s.activeID = chunk.FieldID
		s.activeScope = chunk.ScopeID
		s.activeRole = chunk.Role
		s.activeProv = chunk.Provenance
		s.activeAttr = chunk.UserAttribution
		s.activeTurn = chunk.IsCurrentTurn
		s.activeKeep = true
		s.activeText.Reset()
	} else if !s.active || s.activeID != chunk.FieldID ||
		s.activeRole != chunk.Role || s.activeProv != chunk.Provenance ||
		s.activeAttr != chunk.UserAttribution || s.activeTurn != chunk.IsCurrentTurn ||
		s.activeScope != chunk.ScopeID {
		s.structuralIncomplete = true
		s.resetActive()
		// The canonical downstream sink has already received this chunk. Keep the
		// side-car failure content-free and let Finish return an incomplete result;
		// malformed side-car ordering must not turn a legal extractor request into
		// an operational route error.
		return nil
	}

	if len(chunk.Text) != 0 {
		probe := s.activeCandidateTail + string(chunk.Text)
		signals := s.candidateByScope[s.activeScope].Merge(s.classifier.ScanCandidateSignals(probe))
		s.candidateByScope[s.activeScope] = signals
		s.sensitiveCandidate = s.sensitiveCandidate || signals.Complete()
		s.activeCandidateTail = candidateOverlapTail(probe)
	}

	if s.activeKeep && len(chunk.Text) != 0 {
		// The side-car has a smaller, explicit privacy budget than the general
		// extractor. Once exceeded, discard the field and keep only the fixed
		// incomplete bit; do not retain a prefix that could be mistaken for a
		// complete finding.
		if len(chunk.Text) > csamtext.MaxScopeBytes-s.activeText.Len() {
			s.budgetExceeded = true
			s.activeKeep = false
			s.activeText.Reset()
		} else {
			s.activeText.Write(chunk.Text)
		}
	}
	if !chunk.End {
		return nil
	}

	if s.activeKeep {
		text := s.activeText.String()
		if text != "" {
			if !utf8.ValidString(text) || s.activeScope == 0 {
				s.structuralIncomplete = true
			} else if s.totalBytes > csamtext.MaxTotalBytes-len(text) ||
				s.scopeBytes[s.activeScope] > csamtext.MaxScopeBytes-len(text) ||
				len(s.inputs) >= csamtext.MaxSegments {
				s.budgetExceeded = true
			} else {
				s.inputs = append(s.inputs, csamtext.Input{
					Role:        csamtext.RoleUser,
					Provenance:  csamtext.ProvenanceContent,
					TrustedUser: true,
					CurrentTurn: true,
					ScopeID:     s.activeScope,
					Text:        text,
				})
				s.totalBytes += len(text)
				s.scopeBytes[s.activeScope] += len(text)
			}
		}
	}
	s.resetActive()
	return nil
}

func (s *csamTextStreamSink) Abort() {
	if s == nil {
		return
	}
	if s.finished {
		return
	}
	s.aborted = true
	s.structuralIncomplete = true
	s.resetActive()
	s.inputs = nil
	s.scopeBytes = nil
	if s.downstream != nil {
		s.downstream.Abort()
	}
}

func (s *csamTextStreamSink) resetActive() {
	if s == nil {
		return
	}
	s.active = false
	s.activeID = 0
	s.activeScope = 0
	s.activeRole = ""
	s.activeProv = 0
	s.activeAttr = 0
	s.activeTurn = false
	s.activeKeep = false
	s.activeText.Reset()
	s.activeCandidateTail = ""
}

func (s *csamTextStreamSink) Finish() csamtext.Result {
	if s == nil {
		return csamtext.Result{Action: csamtext.ActionAllow, Coverage: csamtext.CoverageComplete}
	}
	if s.finished {
		return s.result
	}
	s.finished = true
	if s.aborted || s.active {
		s.structuralIncomplete = true
	}
	policyIncomplete := s.structuralIncomplete || s.budgetExceeded && s.sensitiveCandidate
	if policyIncomplete {
		// This is a private side-car diagnostic, not extractor coverage. Preserve
		// that distinction by passing a fully attributed sentinel: the classifier
		// will report bounded coverage exhaustion but can never produce a category
		// or enforcement action from it.
		s.result = csamtext.Classify([]csamtext.Input{{
			Role:        csamtext.RoleUser,
			Provenance:  csamtext.ProvenanceContent,
			TrustedUser: true,
			CurrentTurn: true,
			ScopeID:     1,
			Incomplete:  true,
		}}, s.mode)
	} else if len(s.inputs) == 0 {
		s.result = csamtext.Result{Action: csamtext.ActionAllow, Coverage: csamtext.CoverageComplete}
	} else {
		s.result = s.classifier.Classify(s.inputs, s.mode)
	}
	// The privacy boundary is intentionally more conservative than enforcement:
	// a pre-exclusion candidate or any side-car coverage loss permanently taints
	// this request without retaining text, offsets, hashes, or labels.
	s.privacyTaint = s.privacyTaint || s.structuralIncomplete || s.budgetExceeded ||
		s.sensitiveCandidate || s.result.PrivacySensitiveCandidate()
	// Do not retain the bounded input projection beyond this synchronous route.
	s.inputs = nil
	s.scopeBytes = nil
	s.candidateByScope = nil
	s.activeCandidateTail = ""
	s.activeText.Reset()
	return s.result
}

const csamCandidateOverlapBytes = 128

func candidateOverlapTail(text string) string {
	if len(text) <= csamCandidateOverlapBytes {
		return text
	}
	start := len(text) - csamCandidateOverlapBytes
	for start < len(text) && !utf8.RuneStart(text[start]) {
		start++
	}
	return strings.Clone(text[start:])
}

// PrivacyTainted reports the irreversible, content-free request privacy bit.
// Finish should be called first so complete candidate results are included.
func (s *csamTextStreamSink) PrivacyTainted() bool {
	return s != nil && s.privacyTaint
}

func csamTextEligibleChunk(chunk extract.SegmentChunk) bool {
	return chunk.Role == extract.RoleUser &&
		chunk.Provenance == extract.ProvenanceContent &&
		chunk.UserAttribution == extract.UserAttributionTrusted &&
		chunk.IsCurrentTurn && chunk.ScopeID != 0
}

func csamTextMode(mode string) csamtext.Mode {
	switch mode {
	case "observe":
		return csamtext.ModeObserve
	case "audit":
		return csamtext.ModeAudit
	case "balanced":
		return csamtext.ModeBalanced
	case "strict":
		return csamtext.ModeStrict
	default:
		return csamtext.ModeOff
	}
}

func csamTextIncomplete(result csamtext.Result) bool {
	return result.Coverage == csamtext.CoverageBudgetExhausted
}
