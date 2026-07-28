package extract

import (
	"errors"
	"strings"
)

// SegmentChunk is a bounded, transient slice of one logical model-visible
// text unit. Chunks for a FieldID are delivered serially and never interleave
// with another field. Start and End describe real logical field boundaries,
// not classifier window boundaries.
type SegmentChunk struct {
	Role              Role
	Provenance        SegmentProvenance
	UserAttribution   UserAttribution
	ConversationIndex int
	TurnIndex         int
	IsCurrentTurn     bool
	ScopeID           uint64
	ContentKind       ContentKind
	FieldPathHash     string
	FieldID           uint64
	Start             bool
	End               bool
	Text              []byte
}

// ChunkSink consumes request text synchronously. AddSegment must not retain
// chunk.Text after the call returns. Abort invalidates all provisional findings
// for the current request; the extractor performs no further sink calls after
// Abort.
type ChunkSink interface {
	AddSegment(SegmentChunk) error
	Abort()
}

type collectingChunkSink struct {
	aborted                 bool
	active                  bool
	activeField             uint64
	activeRole              Role
	activeProv              SegmentProvenance
	activeAttr              UserAttribution
	activeConversationIndex int
	activeTurnIndex         int
	activeCurrentTurn       bool
	activeScopeID           uint64
	activeContentKind       ContentKind
	activeFieldPathHash     string
	activeText              strings.Builder
	parts                   []string
	segments                []Segment
}

func (s *collectingChunkSink) AddSegment(chunk SegmentChunk) error {
	if s.aborted {
		return errors.New("collector received a chunk after abort")
	}
	if chunk.Start {
		if s.active {
			return errors.New("collector received interleaved fields")
		}
		s.active = true
		s.activeField = chunk.FieldID
		s.activeRole = defaultRole(chunk.Role)
		s.activeProv = chunk.Provenance
		s.activeAttr = chunk.UserAttribution
		s.activeConversationIndex = chunk.ConversationIndex
		s.activeTurnIndex = chunk.TurnIndex
		s.activeCurrentTurn = chunk.IsCurrentTurn
		s.activeScopeID = chunk.ScopeID
		s.activeContentKind = chunk.ContentKind
		s.activeFieldPathHash = chunk.FieldPathHash
		s.activeText.Reset()
	} else if !s.active || s.activeField != chunk.FieldID ||
		s.activeRole != defaultRole(chunk.Role) || s.activeProv != chunk.Provenance ||
		s.activeAttr != chunk.UserAttribution ||
		s.activeConversationIndex != chunk.ConversationIndex ||
		s.activeTurnIndex != chunk.TurnIndex ||
		s.activeCurrentTurn != chunk.IsCurrentTurn ||
		s.activeScopeID != chunk.ScopeID || s.activeContentKind != chunk.ContentKind ||
		s.activeFieldPathHash != chunk.FieldPathHash {
		return errors.New("collector received a non-serial field chunk")
	}
	s.activeText.Write(chunk.Text)
	if !chunk.End {
		return nil
	}
	if !s.active || s.activeField != chunk.FieldID {
		return errors.New("collector received an out-of-order field end")
	}
	text := s.activeText.String()
	role := s.activeRole
	provenance := s.activeProv
	attribution := s.activeAttr
	conversationIndex := s.activeConversationIndex
	turnIndex := s.activeTurnIndex
	currentTurn := s.activeCurrentTurn
	scopeID := s.activeScopeID
	contentKind := s.activeContentKind
	fieldPathHash := s.activeFieldPathHash
	s.active = false
	s.activeField = 0
	s.activeAttr = UserAttributionUntrusted
	s.activeConversationIndex = 0
	s.activeTurnIndex = 0
	s.activeCurrentTurn = false
	s.activeScopeID = 0
	s.activeContentKind = ContentKindUnknown
	s.activeFieldPathHash = ""
	s.activeText.Reset()
	if strings.TrimSpace(text) == "" {
		return nil
	}
	s.parts = append(s.parts, text)
	s.segments = append(s.segments, Segment{
		Role:              role,
		Provenance:        provenance,
		UserAttribution:   attribution,
		ConversationIndex: conversationIndex,
		TurnIndex:         turnIndex,
		IsCurrentTurn:     currentTurn,
		ScopeID:           scopeID,
		ContentKind:       contentKind,
		FieldPathHash:     fieldPathHash,
		Text:              text,
	})
	return nil
}

func (s *collectingChunkSink) Abort() {
	s.aborted = true
	s.active = false
	s.activeField = 0
	s.activeAttr = UserAttributionUntrusted
	s.activeConversationIndex = 0
	s.activeTurnIndex = 0
	s.activeCurrentTurn = false
	s.activeScopeID = 0
	s.activeContentKind = ContentKindUnknown
	s.activeFieldPathHash = ""
	s.activeText.Reset()
	s.parts = nil
	s.segments = nil
}

func (s *collectingChunkSink) apply(result *Result) {
	if result == nil || s.aborted || result.TextCoverage != TextCoverageComplete {
		return
	}
	result.Parts = append(result.Parts[:0], s.parts...)
	result.Segments = append(result.Segments[:0], s.segments...)
	if len(result.Segments) == 0 {
		result.RoleAware = false
	}
}
