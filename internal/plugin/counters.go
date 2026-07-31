package plugin

import (
	"sync/atomic"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

// coverageIncompleteReason is deliberately closed and content-free. Adding a
// reason requires adding a constant and a metric name here; request data can
// never become a counter label by accident.
type coverageIncompleteReason uint8

const (
	coverageIncompleteNone coverageIncompleteReason = iota
	coverageIncompleteClassificationChunkLimit
	coverageIncompleteClassifierProofBudget
	coverageIncompleteClassifierWindow
	coverageIncompleteTextPartLimit
	coverageIncompleteTotalTextLimit
	coverageIncompleteRawScanLimit
	coverageIncompleteJSONDepth
	coverageIncompleteInvalidUTF8
	coverageIncompleteTimeout
	coverageIncompleteByteAccountingMismatch
	coverageIncompleteExtractorSink
	coverageIncompleteNormalizationCarry
	coverageIncompleteClassifierAborted
	coverageIncompleteParseError
	coverageIncompleteUnknownSourceFormat
	coverageIncompleteRPCBodyLimit
	coverageIncompleteOther
	coverageIncompleteReasonCount
)

var coverageIncompleteReasonNames = [...]string{
	coverageIncompleteClassificationChunkLimit: "classification_chunk_limit",
	coverageIncompleteClassifierProofBudget:    "classifier_proof_budget",
	coverageIncompleteClassifierWindow:         "classifier_window",
	coverageIncompleteTextPartLimit:            "text_part_limit",
	coverageIncompleteTotalTextLimit:           "total_text_limit",
	coverageIncompleteRawScanLimit:             "raw_scan_limit",
	coverageIncompleteJSONDepth:                "json_depth",
	coverageIncompleteInvalidUTF8:              "invalid_utf8",
	coverageIncompleteTimeout:                  "timeout",
	coverageIncompleteByteAccountingMismatch:   "byte_accounting_mismatch",
	coverageIncompleteExtractorSink:            "extractor_sink",
	coverageIncompleteNormalizationCarry:       "normalization_carry",
	coverageIncompleteClassifierAborted:        "classifier_aborted",
	coverageIncompleteParseError:               "parse_error",
	coverageIncompleteUnknownSourceFormat:      "unknown_source_format",
	coverageIncompleteRPCBodyLimit:             "rpc_body_limit",
	coverageIncompleteOther:                    "other",
}

var coverageIncompleteMetricNames = [...]string{
	coverageIncompleteClassificationChunkLimit: "coverage_reason_classification_chunk_limit",
	coverageIncompleteClassifierProofBudget:    "coverage_reason_classifier_proof_budget",
	coverageIncompleteClassifierWindow:         "coverage_reason_classifier_window",
	coverageIncompleteTextPartLimit:            "coverage_reason_text_part_limit",
	coverageIncompleteTotalTextLimit:           "coverage_reason_total_text_limit",
	coverageIncompleteRawScanLimit:             "coverage_reason_raw_scan_limit",
	coverageIncompleteJSONDepth:                "coverage_reason_json_depth",
	coverageIncompleteInvalidUTF8:              "coverage_reason_invalid_utf8",
	coverageIncompleteTimeout:                  "coverage_reason_timeout",
	coverageIncompleteByteAccountingMismatch:   "coverage_reason_byte_accounting_mismatch",
	coverageIncompleteExtractorSink:            "coverage_reason_extractor_sink",
	coverageIncompleteNormalizationCarry:       "coverage_reason_normalization_carry",
	coverageIncompleteClassifierAborted:        "coverage_reason_classifier_aborted",
	coverageIncompleteParseError:               "coverage_reason_parse_error",
	coverageIncompleteUnknownSourceFormat:      "coverage_reason_unknown_source_format",
	coverageIncompleteRPCBodyLimit:             "coverage_reason_rpc_body_limit",
	coverageIncompleteOther:                    "coverage_reason_other",
}

// coverageIncompleteReasonSet is a fixed bitset. A request may carry more than
// one independent extractor reason, but a single source reason is de-duplicated
// before counters are charged.
type coverageIncompleteReasonSet uint32

func (set *coverageIncompleteReasonSet) add(reason coverageIncompleteReason) {
	if set == nil || reason <= coverageIncompleteNone || reason >= coverageIncompleteReasonCount {
		return
	}
	*set |= 1 << reason
}

func (set coverageIncompleteReasonSet) contains(reason coverageIncompleteReason) bool {
	return reason > coverageIncompleteNone && reason < coverageIncompleteReasonCount && set&(1<<reason) != 0
}

type coverageIncompleteCounters struct {
	values [coverageIncompleteReasonCount]atomic.Uint64
}

func (c *coverageIncompleteCounters) add(set coverageIncompleteReasonSet) {
	if c == nil || set == 0 {
		return
	}
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		if set.contains(reason) {
			c.values[reason].Add(1)
		}
	}
}

func (c *coverageIncompleteCounters) snapshot() map[string]uint64 {
	snapshot := make(map[string]uint64, coverageIncompleteReasonCount-1)
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		snapshot[coverageIncompleteMetricNames[reason]] = c.values[reason].Load()
	}
	return snapshot
}

func (c *counters) coverageIncompleteCounters() *coverageIncompleteCounters {
	if c == nil {
		return nil
	}
	return &c.coverageIncompleteReasons
}

func (c *counters) addCoverageIncompleteReasons(set coverageIncompleteReasonSet) {
	if set == 0 {
		return
	}
	c.coverageIncompleteCounters().add(set)
}

func (c *counters) coverageIncompleteSnapshot() map[string]uint64 {
	if c == nil {
		return (&coverageIncompleteCounters{}).snapshot()
	}
	return c.coverageIncompleteReasons.snapshot()
}

// coverageRole is a closed projection of extract.Role. Unknown or future
// provider values are deliberately collapsed into one fixed bucket instead of
// becoming status keys.
type coverageRole uint8

const (
	coverageRoleSystem coverageRole = iota
	coverageRoleUser
	coverageRoleAssistant
	coverageRoleTool
	coverageRoleUnknown
	coverageRoleCount
)

var coverageRoleMetricNames = [...]string{
	coverageRoleSystem:    "system",
	coverageRoleUser:      "user",
	coverageRoleAssistant: "assistant",
	coverageRoleTool:      "tool",
	coverageRoleUnknown:   "unknown",
}

func coverageRoleFor(role extract.Role) coverageRole {
	switch role {
	case extract.RoleSystem:
		return coverageRoleSystem
	case extract.RoleUser:
		return coverageRoleUser
	case extract.RoleAssistant:
		return coverageRoleAssistant
	case extract.RoleTool:
		return coverageRoleTool
	default:
		return coverageRoleUnknown
	}
}

// coverageContentKind mirrors the extractor's closed structural kinds without
// using ContentKind.String as a metric label. A new or invalid value therefore
// remains bounded in the unknown bucket until it is explicitly reviewed here.
type coverageContentKind uint8

const (
	coverageContentUnknown coverageContentKind = iota
	coverageContentNaturalLanguageDirective
	coverageContentQuotedText
	coverageContentCodeBlock
	coverageContentLogOutput
	coverageContentToolSchema
	coverageContentToolCallArguments
	coverageContentToolResult
	coverageContentConfiguration
	coverageContentDocumentation
	coverageContentSecurityAnalysis
	coverageContentKindCount
)

var coverageContentKindMetricNames = [...]string{
	coverageContentUnknown:                  "unknown",
	coverageContentNaturalLanguageDirective: "natural_language_directive",
	coverageContentQuotedText:               "quoted_text",
	coverageContentCodeBlock:                "code_block",
	coverageContentLogOutput:                "log_output",
	coverageContentToolSchema:               "tool_schema",
	coverageContentToolCallArguments:        "tool_call_arguments",
	coverageContentToolResult:               "tool_result",
	coverageContentConfiguration:            "configuration",
	coverageContentDocumentation:            "documentation",
	coverageContentSecurityAnalysis:         "security_analysis",
}

func coverageContentKindFor(kind extract.ContentKind) coverageContentKind {
	switch kind {
	case extract.ContentKindNaturalLanguageDirective:
		return coverageContentNaturalLanguageDirective
	case extract.ContentKindQuotedText:
		return coverageContentQuotedText
	case extract.ContentKindCodeBlock:
		return coverageContentCodeBlock
	case extract.ContentKindLogOutput:
		return coverageContentLogOutput
	case extract.ContentKindToolSchema:
		return coverageContentToolSchema
	case extract.ContentKindToolCallArguments:
		return coverageContentToolCallArguments
	case extract.ContentKindToolResult:
		return coverageContentToolResult
	case extract.ContentKindConfiguration:
		return coverageContentConfiguration
	case extract.ContentKindDocumentation:
		return coverageContentDocumentation
	case extract.ContentKindSecurityAnalysis:
		return coverageContentSecurityAnalysis
	default:
		return coverageContentUnknown
	}
}

type coveragePosition uint8

const (
	coveragePositionFront coveragePosition = iota
	coveragePositionMiddle
	coveragePositionBack
	coveragePositionCount
)

var coveragePositionMetricNames = [...]string{
	coveragePositionFront:  "front",
	coveragePositionMiddle: "middle",
	coveragePositionBack:   "back",
}

// coverageFailurePosition adds an explicit unknown bucket for failures that
// happen before any classifier chunk is accepted (for example Strict unknown
// source formats and the native RPC body cap). Classification chunks retain
// the exact front/middle/back enum above; only failure attribution needs an
// unknown position.
type coverageFailurePosition uint8

const (
	coverageFailurePositionFront coverageFailurePosition = iota
	coverageFailurePositionMiddle
	coverageFailurePositionBack
	coverageFailurePositionUnknown
	coverageFailurePositionCount
)

var coverageFailurePositionMetricNames = [...]string{
	coverageFailurePositionFront:   "front",
	coverageFailurePositionMiddle:  "middle",
	coverageFailurePositionBack:    "back",
	coverageFailurePositionUnknown: "unknown",
}

var coverageFailureMetricNames = func() [coverageIncompleteReasonCount][coverageRoleCount][coverageContentKindCount][coverageFailurePositionCount]string {
	var names [coverageIncompleteReasonCount][coverageRoleCount][coverageContentKindCount][coverageFailurePositionCount]string
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		for role := coverageRole(0); role < coverageRoleCount; role++ {
			for kind := coverageContentKind(0); kind < coverageContentKindCount; kind++ {
				for position := coverageFailurePosition(0); position < coverageFailurePositionCount; position++ {
					names[reason][role][kind][position] = "coverage_failure_" +
						coverageIncompleteReasonNames[reason] + "_" +
						coverageRoleMetricNames[role] + "_" +
						coverageContentKindMetricNames[kind] + "_" +
						coverageFailurePositionMetricNames[position]
				}
			}
		}
	}
	return names
}()

// coverageDisposition is mutually exclusive per classified request. The three
// counters reconcile exactly to streaming_scan_requests: a request has either a
// complete classifier winner, a complete no-winner result, or an incomplete
// disposition. Coverage failure is decided separately from the winner object.
type coverageDisposition uint8

const (
	coverageDispositionSemanticWinner coverageDisposition = iota
	coverageDispositionCompleteNoWinner
	coverageDispositionIncomplete
	coverageDispositionCount
)

var coverageDispositionMetricNames = [...]string{
	coverageDispositionSemanticWinner:   "coverage_disposition_semantic_winner",
	coverageDispositionCompleteNoWinner: "coverage_disposition_complete_no_winner",
	coverageDispositionIncomplete:       "coverage_disposition_incomplete",
}

// finalRouteDisposition records either the finalized transport action or the
// fixed absence of one for a committed coverage request. It is deliberately
// separate from coverageDisposition: audit and observe may allow a complete
// semantic winner, while Strict may fail closed for incomplete coverage without
// manufacturing a semantic block.
//
// None is an internal input sentinel. Every committed coverage record
// normalizes it to Unclassified so streaming_scan_requests always reconciles
// exactly to the six exported, mutually exclusive, request-content-free
// counters. A router panic before any coverage commit remains zero/zero rather
// than fabricating a disposition.
type finalRouteDisposition uint8

const (
	finalRouteDispositionNone finalRouteDisposition = iota
	finalRouteDispositionSemanticBlock
	finalRouteDispositionCompleteNonsemanticBlock
	finalRouteDispositionCompleteAllow
	finalRouteDispositionIncompleteFailClosed
	finalRouteDispositionIncompleteAllow
	finalRouteDispositionUnclassified
	finalRouteDispositionCount
)

var finalRouteDispositionMetricNames = [...]string{
	finalRouteDispositionSemanticBlock:            "final_disposition_semantic_block",
	finalRouteDispositionCompleteNonsemanticBlock: "final_disposition_complete_nonsemantic_block",
	finalRouteDispositionCompleteAllow:            "final_disposition_complete_allow",
	finalRouteDispositionIncompleteFailClosed:     "final_disposition_incomplete_fail_closed",
	finalRouteDispositionIncompleteAllow:          "final_disposition_incomplete_allow",
	finalRouteDispositionUnclassified:             "final_disposition_unclassified",
}

func finalRouteDispositionFor(coverage coverageDisposition, decision inspectionDecision) finalRouteDisposition {
	if coverage == coverageDispositionIncomplete {
		if decision.Block {
			return finalRouteDispositionIncompleteFailClosed
		}
		return finalRouteDispositionIncompleteAllow
	}
	if coverage != coverageDispositionSemanticWinner && coverage != coverageDispositionCompleteNoWinner {
		return finalRouteDispositionNone
	}
	if decision.Block {
		if decision.Kind == decisionBlockMaliciousText {
			return finalRouteDispositionSemanticBlock
		}
		return finalRouteDispositionCompleteNonsemanticBlock
	}
	return finalRouteDispositionCompleteAllow
}

const (
	// SegmentChunk reserves bit 61 for decoded/derived views and bit 62 for
	// content-kind pieces. These are structural namespaces, not hashes or caller
	// fields. Keep the decoding local to the transient request observer.
	coverageDerivedFieldIDFlag      = uint64(1) << 61
	coverageContentPieceFieldIDFlag = uint64(1) << 62
	coverageDerivedFieldOrdinalBits = 8
	coverageContentPieceOrdinalBits = 16
)

func coverageLogicalFieldID(fieldID uint64) (uint64, bool) {
	if fieldID&coverageContentPieceFieldIDFlag != 0 {
		return (fieldID &^ coverageContentPieceFieldIDFlag) >> coverageContentPieceOrdinalBits, false
	}
	if fieldID&coverageDerivedFieldIDFlag != 0 {
		return (fieldID &^ coverageDerivedFieldIDFlag) >> coverageDerivedFieldOrdinalBits, true
	}
	return fieldID, false
}

func coverageToolCarrier(chunk extract.SegmentChunk) bool {
	if chunk.Role == extract.RoleTool || chunk.Provenance == extract.ProvenanceToolPayload {
		return true
	}
	switch chunk.ContentKind {
	case extract.ContentKindToolSchema, extract.ContentKindToolCallArguments, extract.ContentKindToolResult:
		return true
	default:
		return false
	}
}

// coverageDimensionObservation is one request's content-free accounting. Its
// memory is a fixed set of scalar arrays plus one pending chunk; no request text,
// field hash, tool-call ID, or dynamic label is retained. The pending chunk is
// necessary to distinguish the final chunk of a logical classifier field from
// a middle chunk without buffering the field itself.
type coverageDimensionObservation struct {
	logicalParts         [coverageRoleCount]uint64
	logicalBytes         [coverageRoleCount]uint64
	classificationChunks [coverageRoleCount][coverageContentKindCount][coveragePositionCount]uint64
	derivedCarrierBytes  uint64
	toolCarrierBytes     uint64

	hasLogicalField  bool
	lastLogicalField uint64

	hasPending       bool
	pendingFieldID   uint64
	pendingRole      coverageRole
	pendingKind      coverageContentKind
	pendingFieldSize uint64
	pendingEnded     bool
}

func (o *coverageDimensionObservation) add(chunk extract.SegmentChunk) {
	if o == nil || len(chunk.Text) == 0 {
		return
	}
	role := coverageRoleFor(chunk.Role)
	kind := coverageContentKindFor(chunk.ContentKind)
	bytes := uint64(len(chunk.Text))
	logicalField, derived := coverageLogicalFieldID(chunk.FieldID)

	if chunk.Start && !derived && (!o.hasLogicalField || o.lastLogicalField != logicalField) {
		o.logicalParts[role]++
		o.hasLogicalField = true
		o.lastLogicalField = logicalField
	}
	o.logicalBytes[role] += bytes
	if derived {
		o.derivedCarrierBytes += bytes
	}
	if coverageToolCarrier(chunk) {
		o.toolCarrierBytes += bytes
	}

	if !o.hasPending {
		o.setPending(chunk.FieldID, role, kind, 1, chunk.End)
		return
	}
	if o.pendingFieldID != chunk.FieldID {
		o.flushPendingField()
		o.setPending(chunk.FieldID, role, kind, 1, chunk.End)
		return
	}

	position := coveragePositionMiddle
	if o.pendingFieldSize == 1 {
		position = coveragePositionFront
	}
	o.classificationChunks[o.pendingRole][o.pendingKind][position]++
	o.setPending(chunk.FieldID, role, kind, o.pendingFieldSize+1, chunk.End)
}

func (o *coverageDimensionObservation) setPending(fieldID uint64, role coverageRole, kind coverageContentKind, size uint64, ended bool) {
	o.hasPending = true
	o.pendingFieldID = fieldID
	o.pendingRole = role
	o.pendingKind = kind
	o.pendingFieldSize = size
	o.pendingEnded = ended
}

func (o *coverageDimensionObservation) flushPendingField() {
	if o == nil || !o.hasPending {
		return
	}
	position := coveragePositionMiddle
	if o.pendingFieldSize == 1 {
		// A one-chunk field belongs to one exact bucket. Front is deterministic
		// and avoids double charging a chunk as both front and back.
		position = coveragePositionFront
	} else if o.pendingEnded {
		// Only an extractor-confirmed terminal chunk belongs in the back bucket.
		// Aborted/sink-failed fields retain their final observed chunk as middle;
		// request finalization must not manufacture tail coverage that never ran.
		position = coveragePositionBack
	}
	o.classificationChunks[o.pendingRole][o.pendingKind][position]++
	o.hasPending = false
	o.pendingFieldID = 0
	o.pendingFieldSize = 0
	o.pendingEnded = false
}

func (o *coverageDimensionObservation) failureDimension() (coverageRole, coverageContentKind, coverageFailurePosition) {
	if o == nil || !o.hasPending {
		return coverageRoleUnknown, coverageContentUnknown, coverageFailurePositionUnknown
	}
	position := coverageFailurePositionMiddle
	if o.pendingFieldSize == 1 {
		position = coverageFailurePositionFront
	} else if o.pendingEnded {
		position = coverageFailurePositionBack
	}
	return o.pendingRole, o.pendingKind, position
}

func (o *coverageDimensionObservation) textBytes() uint64 {
	if o == nil {
		return 0
	}
	var total uint64
	for role := coverageRole(0); role < coverageRoleCount; role++ {
		total += o.logicalBytes[role]
	}
	return total
}

func (o *coverageDimensionObservation) classificationChunkCount() uint64 {
	if o == nil {
		return 0
	}
	// Work on a copy so error-path reconciliation can account the pending chunk
	// without changing the observation later committed to the fixed counters.
	copy := *o
	copy.flushPendingField()
	var total uint64
	for role := coverageRole(0); role < coverageRoleCount; role++ {
		for kind := coverageContentKind(0); kind < coverageContentKindCount; kind++ {
			for position := coveragePosition(0); position < coveragePositionCount; position++ {
				total += copy.classificationChunks[role][kind][position]
			}
		}
	}
	return total
}

// coverageDimensionSink observes only chunks accepted by the real classifier
// sink. Abort is forwarded without clearing accounting for work already charged;
// this is what makes an incomplete request observable without retaining its raw
// request or invalidated semantic findings.
type coverageDimensionSink struct {
	sink        extract.ChunkSink
	observation coverageDimensionObservation
}

func newCoverageDimensionSink(sink extract.ChunkSink) *coverageDimensionSink {
	return &coverageDimensionSink{sink: sink}
}

func (s *coverageDimensionSink) AddSegment(chunk extract.SegmentChunk) error {
	if err := s.sink.AddSegment(chunk); err != nil {
		return err
	}
	s.observation.add(chunk)
	return nil
}

func (s *coverageDimensionSink) Abort() {
	s.sink.Abort()
}

type coverageDimensionCounters struct {
	logicalParts         [coverageRoleCount]atomic.Uint64
	logicalBytes         [coverageRoleCount]atomic.Uint64
	classificationChunks [coverageRoleCount][coverageContentKindCount][coveragePositionCount]atomic.Uint64
	failures             [coverageIncompleteReasonCount][coverageRoleCount][coverageContentKindCount][coverageFailurePositionCount]atomic.Uint64
	derivedCarrierBytes  atomic.Uint64
	toolCarrierBytes     atomic.Uint64
	dispositions         [coverageDispositionCount]atomic.Uint64
	finalDispositions    [finalRouteDispositionCount]atomic.Uint64
}

func (c *coverageDimensionCounters) add(observation *coverageDimensionObservation, disposition coverageDisposition) {
	c.addWithReasons(observation, disposition, 0)
}

func (c *coverageDimensionCounters) addFinalRouteDisposition(disposition finalRouteDisposition) {
	if c == nil || disposition <= finalRouteDispositionNone || disposition >= finalRouteDispositionCount {
		return
	}
	c.finalDispositions[disposition].Add(1)
}

func (c *coverageDimensionCounters) addWithReasons(
	observation *coverageDimensionObservation,
	disposition coverageDisposition,
	reasons coverageIncompleteReasonSet,
) {
	if c == nil || disposition >= coverageDispositionCount {
		return
	}
	failureRole, failureKind, failurePosition := observation.failureDimension()
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		if reasons.contains(reason) {
			c.failures[reason][failureRole][failureKind][failurePosition].Add(1)
		}
	}
	if observation != nil {
		observation.flushPendingField()
		for role := coverageRole(0); role < coverageRoleCount; role++ {
			if value := observation.logicalParts[role]; value != 0 {
				c.logicalParts[role].Add(value)
			}
			if value := observation.logicalBytes[role]; value != 0 {
				c.logicalBytes[role].Add(value)
			}
			for kind := coverageContentKind(0); kind < coverageContentKindCount; kind++ {
				for position := coveragePosition(0); position < coveragePositionCount; position++ {
					if value := observation.classificationChunks[role][kind][position]; value != 0 {
						c.classificationChunks[role][kind][position].Add(value)
					}
				}
			}
		}
		if observation.derivedCarrierBytes != 0 {
			c.derivedCarrierBytes.Add(observation.derivedCarrierBytes)
		}
		if observation.toolCarrierBytes != 0 {
			c.toolCarrierBytes.Add(observation.toolCarrierBytes)
		}
	}
	c.dispositions[disposition].Add(1)
}

func (c *coverageDimensionCounters) snapshot() map[string]uint64 {
	metricCount := int(coverageRoleCount)*2 +
		int(coverageRoleCount)*int(coverageContentKindCount)*int(coveragePositionCount) +
		2 + int(coverageDispositionCount) + int(finalRouteDispositionCount-1)
	snapshot := make(map[string]uint64, metricCount)
	for role := coverageRole(0); role < coverageRoleCount; role++ {
		roleName := coverageRoleMetricNames[role]
		snapshot["coverage_logical_parts_"+roleName] = c.logicalParts[role].Load()
		snapshot["coverage_logical_bytes_"+roleName] = c.logicalBytes[role].Load()
		for kind := coverageContentKind(0); kind < coverageContentKindCount; kind++ {
			kindName := coverageContentKindMetricNames[kind]
			for position := coveragePosition(0); position < coveragePositionCount; position++ {
				name := "coverage_classification_chunks_" + roleName + "_" + kindName + "_" + coveragePositionMetricNames[position]
				snapshot[name] = c.classificationChunks[role][kind][position].Load()
			}
		}
	}
	// The failure key universe is fixed above, but zero-valued combinations are
	// omitted from management snapshots. Emitting the full Cartesian product on
	// every status poll would add thousands of useless JSON fields to a path the
	// Linux audit runner reads after every request.
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		for role := coverageRole(0); role < coverageRoleCount; role++ {
			for kind := coverageContentKind(0); kind < coverageContentKindCount; kind++ {
				for position := coverageFailurePosition(0); position < coverageFailurePositionCount; position++ {
					value := c.failures[reason][role][kind][position].Load()
					if value == 0 {
						continue
					}
					name := coverageFailureMetricNames[reason][role][kind][position]
					snapshot[name] = value
				}
			}
		}
	}
	snapshot["coverage_derived_carrier_bytes"] = c.derivedCarrierBytes.Load()
	snapshot["coverage_tool_carrier_bytes"] = c.toolCarrierBytes.Load()
	for disposition := coverageDisposition(0); disposition < coverageDispositionCount; disposition++ {
		snapshot[coverageDispositionMetricNames[disposition]] = c.dispositions[disposition].Load()
	}
	for disposition := finalRouteDisposition(1); disposition < finalRouteDispositionCount; disposition++ {
		snapshot[finalRouteDispositionMetricNames[disposition]] = c.finalDispositions[disposition].Load()
	}
	return snapshot
}

func (c *counters) addCoverageDimensions(observation *coverageDimensionObservation, disposition coverageDisposition) {
	if c == nil {
		return
	}
	c.coverageDimensions.add(observation, disposition)
}

func (c *counters) coverageDimensionSnapshot() map[string]uint64 {
	if c == nil {
		return (&coverageDimensionCounters{}).snapshot()
	}
	return c.coverageDimensions.snapshot()
}
