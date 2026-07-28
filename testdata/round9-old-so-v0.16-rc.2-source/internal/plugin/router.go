package plugin

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo"
	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard/internal/subject"
)

var fallbackEventIDCounter atomic.Uint64

type modelRouteFailure struct {
	code   string
	reason string
}

// requestHashMemo defers the full-body digest until a route actually needs a
// subject idempotency key, a pending block correlation key, or a persisted
// audit field. It is local to one router callback and is never shared.
type requestHashMemo struct {
	body  []byte
	value string
}

func (memo *requestHashMemo) get(p *Plugin) string {
	if memo == nil {
		return ""
	}
	if memo.value == "" {
		hasher := audit.HashRequest
		if p != nil && p.requestHasher != nil {
			hasher = p.requestHasher
		}
		memo.value = hasher(memo.body)
	}
	return memo.value
}

const streamingScannerIdentity = buildinfo.StreamingScannerIdentity

// callModelRoute captures the runtime's failure policy under the same read
// lock that protects the runtime itself. The lock is released before a
// privacy-safe failure is reported, and the captured policy survives either a
// concurrent runtime swap or a recovered panic.
func (p *Plugin) callModelRoute(raw []byte) (response []byte, returnCode int) {
	p.opMu.RLock()
	state := p.runtime.Load()
	policy := modelRoutePolicyFromState(state)
	if state == nil && p.shutdown.Load() {
		policy = decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load())
	}
	locked := true
	defer func() {
		if locked {
			p.opMu.RUnlock()
		}
		if recovered := recover(); recovered != nil {
			p.counters.panicsRecovered.Add(1)
			response = p.modelRouteFailureWithPolicy(
				"panic_recovered",
				"cyber_abuse_guard_router_panic",
				policy,
			)
			returnCode = 0
		}
	}()

	var request pluginapi.ModelRouteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		p.opMu.RUnlock()
		locked = false
		return p.modelRouteFailureWithPolicy("invalid_request", "cyber_abuse_guard_invalid_request", policy), 0
	}
	if state == nil {
		p.opMu.RUnlock()
		locked = false
		code := "not_initialized"
		reason := "cyber_abuse_guard_not_initialized"
		if p.shutdown.Load() {
			code = "plugin_shutdown"
			reason = "cyber_abuse_guard_shutdown"
		}
		return p.modelRouteFailureWithPolicy(code, reason, policy), 0
	}

	response, failure := p.route(state, request)
	p.opMu.RUnlock()
	locked = false
	if failure != nil {
		return p.modelRouteFailureWithPolicy(failure.code, failure.reason, policy), 0
	}
	return response, 0
}

func (p *Plugin) route(state *runtimeState, request pluginapi.ModelRouteRequest) ([]byte, *modelRouteFailure) {
	if !state.config.Enabled || state.config.Mode == config.ModeOff {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false}), nil
	}
	started := time.Now()
	p.counters.total.Add(1)
	requestHash := requestHashMemo{body: request.Body}
	requestProfile, sourceFormatKnown := extractionProfile(request.SourceFormat)
	unknownSourceFormat := !sourceFormatKnown
	if unknownSourceFormat {
		p.counters.unknownSourceFormats.Add(1)
		p.reportUnknownSourceFormat()
		if state.config.Mode == config.ModeStrict && !multipartRequest(request.Headers) {
			hash := requestHash.get(p)
			subjectHash := p.auditSubjectHash(state, request)
			p.counters.blocked.Add(1)
			p.counters.incompleteInspections.Add(1)
			p.counters.incompleteBlocked.Add(1)
			p.counters.coverageIncomplete.Add(1)
			p.recordUnknownSourceBlock(state, hash, subjectHash, request.Stream, request.Body, time.Since(started))
			p.pending.put(hash, "unknown_source_format")
			return blockedRouteEnvelope("cyber_abuse_guard_unknown_source_format"), nil
		}
		// Balanced/audit/observe still run the format-tolerant bounded extractor
		// instead of silently bypassing policy. Strict blocks before interpretation
		// because a future provider shape may hide semantics under unknown fields.
	}

	mode := classifierMode(state.config.Mode)
	thresholds := classifier.Thresholds{
		Audit:         state.config.Thresholds.Audit,
		BalancedBlock: state.config.Thresholds.BalancedBlock,
		HardBlock:     state.config.Thresholds.HardBlock,
	}
	policy := classifierPolicy(state.config)
	session, sessionErr := state.classifier.NewScanSession(mode, thresholds, policy, classifier.ScanLimits{
		WindowBytes:   state.config.EffectiveTextWindowBytes(),
		MaxTotalBytes: state.config.MaxTotalTextBytes,
		MaxChunks:     state.config.EffectiveMaxClassificationChunks(),
	})
	if sessionErr != nil {
		return nil, &modelRouteFailure{code: "invalid_classifier_limits", reason: "cyber_abuse_guard_inspection_failure"}
	}
	limits := extract.Limits{
		// MaxScanBytes is now only the deprecated window alias. The streaming
		// entry points below never slice the raw JSON body by this value.
		MaxScanBytes:            state.config.MaxScanBytes,
		MaxRawBytes:             maxRPCRequestBytes,
		MaxTextWindowBytes:      state.config.EffectiveTextWindowBytes(),
		MaxTotalTextBytes:       state.config.MaxTotalTextBytes,
		MaxClassificationChunks: state.config.EffectiveMaxClassificationChunks(),
		MaxJSONDepth:            state.config.MaxJSONDepth,
		MaxTextParts:            state.config.MaxTextParts,
		MaxMultipartTextBytes:   extract.HardMaxMultipartTextBytes,
	}
	var extracted extract.Result
	var extractErr error
	if unknownSourceFormat {
		extracted, extractErr = extract.ScanUntrustedRequest(request.Body, request.Headers, limits, session)
	} else {
		extracted, extractErr = extract.ScanProfiledRequest(request.Body, request.Headers, requestProfile, limits, session)
	}
	if extractErr != nil && len(extracted.IncompleteReasons) == 0 {
		session.Abort()
		// Invalid limits or an extractor invariant failure is operational. It is
		// deliberately kept on the existing mode-aware runtime-failure path and
		// is never confused with request-content incompleteness.
		if errors.Is(extractErr, extract.ErrInvalidLimits) {
			return nil, &modelRouteFailure{code: "invalid_extractor_limits", reason: "cyber_abuse_guard_inspection_failure"}
		}
		return nil, &modelRouteFailure{code: "inspection_failure", reason: "cyber_abuse_guard_inspection_failure"}
	}
	result := session.Finish()
	incompleteReasons := append([]extract.IncompleteReason(nil), extracted.IncompleteReasons...)
	if !extracted.IsComplete() && len(incompleteReasons) == 0 {
		// Defensive invariant fallback. The category remains bounded and no raw
		// parser diagnostic is logged or persisted.
		incompleteReasons = append(incompleteReasons, extract.IncompleteParseError)
	}
	if len(incompleteReasons) == 0 {
		if reason := classifierCoverageReason(result.Coverage); reason != "" {
			incompleteReasons = appendIncompleteReason(incompleteReasons, reason)
		}
	}
	if len(incompleteReasons) == 0 && result.Coverage.State == classifier.CoverageComplete &&
		result.Coverage.Bytes != int64(extracted.TextBytesScanned) {
		// A byte-accounting mismatch means full classifier coverage was not
		// proven. Treat it as bounded classification exhaustion, never as a
		// complete finding or an operational fail-open.
		incompleteReasons = appendIncompleteReason(incompleteReasons, extract.IncompleteClassificationChunkLimit)
	}
	if len(incompleteReasons) != 0 {
		// The first Round6 implementation intentionally does not enable the
		// verified-hard-under-incomplete exception. Remove every partial score,
		// category, rule and behavior before disposition or subject accounting.
		result = incompleteClassificationResult(result, state.rulesVersion)
	}
	p.recordStreamingCounters(extracted, result, incompleteReasons, state.config.EffectiveTextWindowBytes())
	if len(incompleteReasons) == 0 && result.Behavior != nil && result.Behavior.Wrapper {
		// Control-plane observation is deliberately orthogonal to the winning
		// cyber-abuse taxonomy and subject-risk state. The management surface
		// exposes one fixed, low-cardinality counter only; no prompt fragment,
		// family name, dynamic key, repository identifier, or prompt hash is
		// retained as a label.
		p.counters.controlPlaneMetaOverride.Add(1)
	}

	opaqueAudit, opaqueBlock := opaqueMediaDisposition(state.config, extracted.OpaqueMedia)
	if len(incompleteReasons) != 0 && opaqueBlock {
		// Incomplete inspection is the primary disposition. Do not report a
		// policy-level opaque-media block when balanced actually allowed+audited
		// the request (or strict blocked it for the incomplete reason).
		opaqueAudit = true
		opaqueBlock = false
	}
	if extracted.OpaqueMedia {
		p.counters.opaqueMedia.Add(1)
		for _, kind := range extracted.OpaqueMediaKinds {
			switch kind {
			case extract.OpaqueMediaHTTPSImageURL:
				p.counters.opaqueMediaHTTPSImageURL.Add(1)
			case extract.OpaqueMediaDataURL:
				p.counters.opaqueMediaDataURL.Add(1)
			case extract.OpaqueMediaBase64Image:
				p.counters.opaqueMediaBase64Image.Add(1)
			case extract.OpaqueMediaAudio:
				p.counters.opaqueMediaAudio.Add(1)
			case extract.OpaqueMediaVideo:
				p.counters.opaqueMediaVideo.Add(1)
			case extract.OpaqueMediaDocument:
				p.counters.opaqueMediaDocument.Add(1)
			case extract.OpaqueMediaRemoteURL:
				p.counters.opaqueMediaRemoteURL.Add(1)
			default:
				p.counters.opaqueMediaOther.Add(1)
			}
		}
		switch {
		case opaqueBlock:
			p.counters.opaqueMediaBlocked.Add(1)
		case opaqueAudit:
			p.counters.opaqueMediaAudited.Add(1)
		default:
			p.counters.opaqueMediaAllowed.Add(1)
		}
	}

	outcome := inspectionOutcome{
		Classification: result,
		Incomplete:     incompleteReasons,
		OpaqueMedia:    extracted.OpaqueMedia,
	}
	decision := inspectionDisposition(state.config.Mode, outcome, state.config.EffectiveOpaqueMediaPolicy())
	subjectHash := ""
	subjectReason := ""
	if state.config.SubjectControl.Enabled && decision.EvaluateSubject {
		if p.identifier != nil {
			identity := p.identifier.FromHeaders(request.Headers)
			if authenticatedSubjectIdentity(identity) {
				subjectHash = identity.Hash
				accumulate := subjectAccumulationEligible(
					identity,
					result,
					incompleteReasons,
					state.config.Thresholds.HardBlock,
				)
				observation := subject.Observation{RiskScore: result.Score, Accumulate: accumulate}
				var subjectDecision subject.Decision
				if accumulate {
					subjectDecision = state.subject.ObserveRequest(subjectHash, requestHash.get(p), observation)
				} else {
					subjectDecision = state.subject.Observe(subjectHash, observation)
				}
				if subjectDecision.AddedScore > 0 {
					state.markSubjectPersistenceDirty()
				}
				subjectReason = string(subjectDecision.Reason)
				outcome.SubjectBlocked = subjectDecision.Blocked
				decision = inspectionDisposition(state.config.Mode, outcome, state.config.EffectiveOpaqueMediaPolicy())
			}
		}
	}
	persistDecision := shouldPersistInspectionDecision(state.config, outcome, decision)
	// Audit identity is independent from subject-risk accumulation. A disabled
	// controller must not erase the privacy-safe subject field from an event the
	// operator explicitly chose to persist. Counter-only wrapper observations do
	// not enter this path and therefore do not derive a subject correlation hash.
	if persistDecision && subjectHash == "" {
		subjectHash = p.auditSubjectHash(state, request)
	}

	if len(incompleteReasons) != 0 {
		p.recordIncompleteCounters(incompleteReasons, decision)
	}

	switch {
	case decision.Block:
		p.counters.blocked.Add(1)
	case decision.Audit:
		p.counters.audited.Add(1)
	case decision.Observe:
		p.counters.observed.Add(1)
	default:
		p.counters.allowed.Add(1)
	}

	if persistDecision {
		p.recordDecision(state, request, &requestHash, subjectHash, extracted.TextBytesScanned, result, decision, incompleteReasons, subjectReason, request.Body, time.Since(started))
	}
	if !decision.Block {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false}), nil
	}
	category := decision.Category
	if category == "" {
		category = string(result.Category)
	}
	p.pending.put(requestHash.get(p), category)
	reason := decision.RouteReason
	if reason == "" {
		reason = "cyber_abuse_guard_policy"
	}
	if decision.Code == "block_malicious_text" && result.Score >= state.config.Thresholds.HardBlock {
		reason = "cyber_abuse_guard_hard_policy"
	}
	return blockedRouteEnvelope(reason), nil
}

func (p *Plugin) auditSubjectHash(state *runtimeState, request pluginapi.ModelRouteRequest) string {
	if p == nil || p.identifier == nil || state == nil || state.audit == nil ||
		!state.config.Audit.Enabled || state.config.Mode == config.ModeObserve ||
		!state.config.Audit.LogSubjectHash {
		return ""
	}
	return p.identifier.FromHeaders(request.Headers).Hash
}

func authenticatedSubjectIdentity(identity subject.Identity) bool {
	if identity.Hash == "" {
		return false
	}
	switch identity.Source {
	case subject.SourceAuthorization, subject.SourceAPIKey:
		return true
	default:
		return false
	}
}

func subjectAccumulationEligible(identity subject.Identity, result classifier.Result, incompleteReasons []extract.IncompleteReason, hardBlock int) bool {
	return authenticatedSubjectIdentity(identity) &&
		len(incompleteReasons) == 0 && result.Coverage.State == classifier.CoverageComplete &&
		result.FindingConfidence == classifier.FindingCompleteRequest &&
		result.FindingOrigin == classifier.FindingOriginUserContent &&
		result.Behavior != nil && result.Behavior.BaseBehavior &&
		result.Action == classifier.ActionBlock && result.Score >= hardBlock
}

func opaqueMediaDisposition(cfg config.Config, present bool) (auditOnly, block bool) {
	if !present {
		return false, false
	}
	switch cfg.EffectiveOpaqueMediaPolicy() {
	case config.OpaqueMediaPolicyBlock:
		if cfg.Mode == config.ModeBalanced || cfg.Mode == config.ModeStrict {
			return false, true
		}
		// Observe/Audit modes never enforce, even when an explicit future
		// enforcing policy is being evaluated during a rollout.
		return true, false
	case config.OpaqueMediaPolicyAudit:
		return true, false
	default:
		return false, false
	}
}

func blockedRouteEnvelope(reason string) []byte {
	return okEnvelope(blockedRouteResponse(reason))
}

func blockedRouteResponse(reason string) pluginapi.ModelRouteResponse {
	return pluginapi.ModelRouteResponse{
		Handled:    true,
		TargetKind: pluginapi.ModelRouteTargetSelf,
		Reason:     reason,
	}
}

func classifierPolicy(cfg config.Config) classifier.Policy {
	policy := classifier.DefaultPolicy()
	policy.Allow.Defensive = cfg.AllowContext.DefensiveAnalysis
	policy.Allow.Remediation = cfg.AllowContext.Remediation
	policy.Allow.CTF = cfg.AllowContext.CTF
	policy.Allow.Lab = cfg.AllowContext.Lab
	policy.Allow.Authorized = cfg.AllowContext.AuthorizedTesting
	policy.Allow.StaticAnalysis = cfg.AllowContext.MalwareStaticAnalysis
	policy.HardBlockEvenIfAuthorized = classifier.HardBlockPolicy{
		CredentialTheft:      cfg.HardBlockEvenIfAuthorized.CredentialTheft,
		PhishingDeployment:   cfg.HardBlockEvenIfAuthorized.PhishingDeployment,
		RansomwareDeployment: cfg.HardBlockEvenIfAuthorized.RansomwareDeployment,
		DataExfiltration:     cfg.HardBlockEvenIfAuthorized.DataExfiltration,
	}
	return policy
}

func supportedSourceFormat(format string) bool {
	_, ok := extractionProfile(format)
	return ok
}

func extractionProfile(format string) (extract.RequestProfile, bool) {
	profile := extract.RequestProfile{Source: extract.SourceProfileUnknown}
	switch audit.CanonicalSourceFormat(format) {
	case "openai":
		profile.Source = extract.SourceProfileOpenAI
	case "openai-response":
		profile.Source = extract.SourceProfileOpenAIResponse
	case "interactions":
		profile.Source = extract.SourceProfileInteractions
	case audit.SourceFormatCodexAlphaSearch:
		// CPA v7.2.95 exposes Alpha Search request bodies directly to ModelRouter.
		// They have no chat-role envelope, so treat their model-visible strings as
		// direct untrusted text while retaining a distinct structural profile.
		profile.Source = extract.SourceProfileCodexAlphaSearch
	case "openai-image":
		profile.Source = extract.SourceProfileOpenAIImage
	case "openai-video":
		profile.Source = extract.SourceProfileOpenAIVideo
	case "claude":
		profile.Source = extract.SourceProfileClaude
	case "gemini":
		profile.Source = extract.SourceProfileGemini
	default:
		return profile, false
	}
	return profile, true
}

func multipartRequest(headers map[string][]string) bool {
	for name, values := range headers {
		if !strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			continue
		}
		for _, value := range values {
			mediaType, _, err := mime.ParseMediaType(value)
			if err == nil && strings.EqualFold(strings.TrimSpace(mediaType), "multipart/form-data") {
				return true
			}
		}
	}
	return false
}

func (p *Plugin) reportUnknownSourceFormat() {
	now := time.Now().UnixNano()
	for {
		previous := p.lastUnknownSourceNotice.Load()
		if previous != 0 && time.Duration(now-previous) < time.Minute {
			return
		}
		if p.lastUnknownSourceNotice.CompareAndSwap(previous, now) {
			p.log("warn", "cyber-abuse-guard received an unknown CPA source format; bounded generic inspection remains active", map[string]any{
				"plugin": ID,
				"code":   "unknown_source_format",
			})
			return
		}
	}
}

func classifierMode(mode config.Mode) classifier.Mode {
	switch mode {
	case config.ModeObserve:
		return classifier.ModeObserve
	case config.ModeAudit:
		return classifier.ModeAudit
	case config.ModeStrict:
		return classifier.ModeStrict
	case config.ModeBalanced:
		return classifier.ModeBalanced
	default:
		return classifier.ModeOff
	}
}

func classifierCoverageReason(coverage classifier.Coverage) extract.IncompleteReason {
	switch coverage.State {
	case classifier.CoverageComplete:
		return ""
	case classifier.CoverageBudgetExhausted:
		switch coverage.Reason {
		case classifier.CoverageReasonTotalTextLimit:
			return extract.IncompleteTotalTextLimit
		default:
			return extract.IncompleteClassificationChunkLimit
		}
	case classifier.CoverageUnavailable:
		if coverage.Reason == classifier.CoverageReasonInvalidUTF8 {
			return extract.IncompleteParseError
		}
		return extract.IncompleteClassificationChunkLimit
	default:
		return extract.IncompleteClassificationChunkLimit
	}
}

func appendIncompleteReason(reasons []extract.IncompleteReason, reason extract.IncompleteReason) []extract.IncompleteReason {
	if reason == "" {
		return reasons
	}
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func incompleteClassificationResult(result classifier.Result, rulesVersion string) classifier.Result {
	return classifier.Result{
		PolicyVersion:     result.PolicyVersion,
		PolicySHA256:      result.PolicySHA256,
		RuleSetVersion:    rulesVersion,
		Action:            classifier.ActionAllow,
		Coverage:          result.Coverage,
		FindingConfidence: classifier.FindingNone,
		FindingOrigin:     classifier.FindingOriginNone,
		Truncated:         true,
	}
}

func (p *Plugin) recordStreamingCounters(extracted extract.Result, result classifier.Result, reasons []extract.IncompleteReason, windowBytes int) {
	p.counters.streamingScanRequests.Add(1)
	if extracted.TextBytesScanned > 0 {
		p.counters.textBytesScannedTotal.Add(uint64(extracted.TextBytesScanned))
	}
	if result.Coverage.Windows > 0 {
		p.counters.classificationWindowsTotal.Add(uint64(result.Coverage.Windows))
	}
	if result.Coverage.BoundaryReconstructions > 0 {
		p.counters.windowBoundaryReconstructions.Add(uint64(result.Coverage.BoundaryReconstructions))
	}
	longText := extracted.TextBytesScanned > windowBytes
	maxWindows := result.Coverage.Reason == classifier.CoverageReasonClassificationLimit
	totalText := result.Coverage.Reason == classifier.CoverageReasonTotalTextLimit
	for _, reason := range reasons {
		switch reason {
		case extract.IncompleteClassificationChunkLimit:
			maxWindows = true
		case extract.IncompleteTotalTextLimit:
			totalText = true
			longText = true
		}
	}
	if longText {
		p.counters.longTextRequests.Add(1)
	}
	if len(reasons) == 0 && extracted.TextCoverage == extract.TextCoverageComplete && result.Coverage.State == classifier.CoverageComplete {
		p.counters.coverageComplete.Add(1)
	} else {
		p.counters.coverageIncomplete.Add(1)
	}
	if maxWindows {
		p.counters.maxWindowsExhausted.Add(1)
	}
	if totalText {
		p.counters.totalTextLimitExhausted.Add(1)
	}
}

func (p *Plugin) recordUnknownSourceBlock(state *runtimeState, requestHash, subjectHash string, stream bool, rawRequest []byte, latency time.Duration) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled {
		return
	}
	event := audit.Event{
		ID:               newEventID(),
		Timestamp:        time.Now().UTC(),
		Action:           "block",
		Mode:             string(state.config.Mode),
		Category:         "unknown_source_format",
		SourceFormat:     audit.SourceFormatUnknown,
		Stream:           stream,
		Classifier:       state.rulesVersion,
		Decision:         "block_unknown_source_format",
		Coverage:         "incomplete",
		IncompleteReason: "incomplete_inspection",
		Scanner:          streamingScannerIdentity,
		LatencyUS:        latency.Microseconds(),
	}
	if state.config.Audit.LogRequestHash {
		event.RequestHash = requestHash
	}
	if state.config.Audit.LogSubjectHash {
		event.SubjectHash = subjectHash
	}
	if state.config.Audit.RawCapture.Enabled {
		p.recordAuditEventWithRawCapture(state, event, rawRequest)
	} else {
		p.recordAuditEvent(state, event)
	}
}

func (p *Plugin) recordIncompleteCounters(reasons []extract.IncompleteReason, decision inspectionDecision) {
	p.counters.incompleteInspections.Add(1)
	if decision.Block {
		p.counters.incompleteBlocked.Add(1)
	} else {
		p.counters.incompleteAllowed.Add(1)
	}

	var parseError, scanLimit, jsonDepth, textPart, roleAttribution, multipartLimit, multipartSchema, toolSchema, deferredTextLimit, unsupported, rpcBody bool
	var truncated bool
	for _, reason := range reasons {
		switch reason {
		case extract.IncompleteParseError:
			parseError = true
		case extract.IncompleteScanByteLimit,
			extract.IncompleteJSONTokenLimit,
			extract.IncompleteJSONNodeLimit,
			extract.IncompleteTextPartByteLimit,
			extract.IncompleteRawBodyLimit:
			scanLimit = true
			truncated = true
		case extract.IncompleteJSONDepthLimit:
			jsonDepth = true
			truncated = true
		case extract.IncompleteTextPartLimit:
			textPart = true
			truncated = true
		case extract.IncompleteRoleAttribution:
			roleAttribution = true
		case extract.IncompleteTotalTextLimit, extract.IncompleteClassificationChunkLimit:
			truncated = true
		case extract.IncompleteMultipartBoundaryLimit,
			extract.IncompleteMultipartPartLimit,
			extract.IncompleteMultipartHeaderLimit,
			extract.IncompleteMultipartTextLimit,
			extract.IncompleteMultipartParseError:
			multipartLimit = true
			if reason != extract.IncompleteMultipartParseError {
				truncated = true
			}
		case extract.IncompleteMultipartUnknownField, extract.IncompleteMultipartTextFieldTypeMismatch:
			multipartSchema = true
		case extract.IncompleteToolSchema:
			toolSchema = true
		case extract.IncompleteDeferredTextCandidateLimit:
			deferredTextLimit = true
			truncated = true
		case extract.IncompleteUnsupportedMediaType, extract.IncompleteUnsupportedContentEncoding:
			unsupported = true
		case extract.IncompleteRPCBodyLimit:
			rpcBody = true
			truncated = true
		}
	}
	if parseError {
		p.counters.incompleteParseError.Add(1)
		p.counters.parseErrors.Add(1)
	}
	if scanLimit {
		p.counters.incompleteScanLimit.Add(1)
	}
	if jsonDepth {
		p.counters.incompleteJSONDepthLimit.Add(1)
	}
	if textPart {
		p.counters.incompleteTextPartLimit.Add(1)
	}
	if roleAttribution {
		p.counters.incompleteRoleAttribution.Add(1)
	}
	if multipartLimit {
		p.counters.incompleteMultipartLimit.Add(1)
	}
	if multipartSchema {
		p.counters.incompleteMultipartSchema.Add(1)
	}
	if toolSchema {
		p.counters.incompleteToolSchema.Add(1)
	}
	if deferredTextLimit {
		p.counters.incompleteDeferredTextLimit.Add(1)
	}
	if unsupported {
		p.counters.incompleteUnsupportedContentType.Add(1)
	}
	if rpcBody {
		p.counters.incompleteRPCBodyLimit.Add(1)
	}
	if truncated {
		p.counters.truncated.Add(1)
	}
}

func (p *Plugin) recordDecision(state *runtimeState, request pluginapi.ModelRouteRequest, requestHash *requestHashMemo, subjectHash string, scanned int, result classifier.Result, decision inspectionDecision, incompleteReasons []extract.IncompleteReason, subjectReason string, rawRequest []byte, latency time.Duration) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled || state.config.Mode == config.ModeObserve {
		return
	}
	action := "audit"
	decisionCode := decision.Code
	if decision.Observe {
		action = "observe"
	} else if decision.Block {
		action = "block"
		if subjectReason == "cooldown" {
			action = "cooldown"
			decisionCode = "cooldown_subject_risk"
		}
	}
	decisionExplanation := auditDecisionExplanationForDecision(
		result,
		decision.Category,
		len(incompleteReasons) == 0,
	)
	event := audit.Event{
		ID:               newEventID(),
		Timestamp:        time.Now().UTC(),
		Action:           action,
		Mode:             string(state.config.Mode),
		RiskScore:        result.Score,
		Model:            audit.HashModel(request.RequestedModel),
		SourceFormat:     audit.CanonicalSourceFormat(request.SourceFormat),
		Stream:           request.Stream,
		TextBytesScanned: scanned,
		Classifier:       result.RuleSetVersion,
		Decision:         decisionCode,
		Coverage:         "complete",
		Scanner:          streamingScannerIdentity,
		LatencyUS:        latency.Microseconds(),
		DecisionExplanation: applyAuditDecisionExplanationLoggingPolicy(
			decisionExplanation,
			state.config.Audit.LogCategory,
			state.config.Audit.LogRuleIDs,
		),
	}
	if len(incompleteReasons) != 0 {
		event.Coverage = "incomplete"
		event.IncompleteReason = incompleteCategory(incompleteReasons)
	}
	if state.config.Audit.LogCategory {
		event.Category = decision.Category
	}
	if state.config.Audit.LogRuleIDs {
		event.RuleIDs = append([]string(nil), result.RuleIDs...)
	}
	if state.config.Audit.LogRequestHash {
		event.RequestHash = requestHash.get(p)
	}
	if state.config.Audit.LogSubjectHash {
		event.SubjectHash = subjectHash
	}
	if decision.Block && state.config.Audit.RawCapture.Enabled {
		p.recordAuditEventWithRawCapture(state, event, rawRequest)
	} else {
		p.recordAuditEvent(state, event)
	}
}

func (p *Plugin) recordAuditEventWithRawCapture(state *runtimeState, event audit.Event, rawRequest []byte) {
	if state == nil || state.audit == nil {
		return
	}
	accepted, err := state.audit.EnqueueEventWithRawCapture(event, audit.RawCaptureInput{
		EventID:     event.ID,
		Timestamp:   event.Timestamp,
		RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash,
		Action:      event.Action,
		Decision:    event.Decision,
		RawRequest:  rawRequest,
	})
	if err == nil {
		return
	}
	if accepted {
		p.reportAuditQueueFailure(
			"cyber-abuse-guard blocked-request capture could not be queued; the audit event remains active",
			"raw_capture_queue_degraded",
		)
		return
	}
	p.reportAuditQueueFailure(
		"cyber-abuse-guard audit event and blocked-request capture could not be queued; enforcement remains active",
		"audit_queue_degraded",
	)
}

// recordAuditEvent deliberately ignores persistence failure for policy
// decisions. A full queue, locked/unavailable SQLite database, or a closing
// store must never turn a local block into an upstream request. The audit store
// exposes detailed counters; this helper adds a privacy-safe, rate-limited host
// log without including request-derived fields.
func (p *Plugin) recordAuditEvent(state *runtimeState, event audit.Event) bool {
	if state == nil || state.audit == nil || state.audit.Record(event) {
		return state != nil && state.audit != nil
	}
	p.reportAuditQueueFailure(
		"cyber-abuse-guard audit event could not be queued; enforcement remains active",
		"audit_queue_degraded",
	)
	return false
}

// reportAuditQueueFailure intentionally excludes errors and request-derived
// fields. A validation, queue, database, or closing-store failure therefore
// cannot disclose captured request text through the host log.
func (p *Plugin) reportAuditQueueFailure(message, code string) {
	now := time.Now().UnixNano()
	for {
		previous := p.lastAuditNotice.Load()
		if previous != 0 && time.Duration(now-previous) < time.Minute {
			return
		}
		if p.lastAuditNotice.CompareAndSwap(previous, now) {
			p.log("warn", message, map[string]any{
				"plugin": ID,
				"code":   code,
			})
			return
		}
	}
}

func newEventID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		// Event IDs are correlation values, not secrets. Preserve the UUID-shaped
		// management-query contract even if the operating system random source is
		// temporarily unavailable; nanoseconds plus a process-local counter keep
		// fallback values distinct for the lifetime of this plugin instance.
		binary.BigEndian.PutUint64(value[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(value[8:16], fallbackEventIDCounter.Add(1))
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}
