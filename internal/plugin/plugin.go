// Package plugin implements the CPA v7.2.125 schema-v2 RPC surface for the
// cyber-abuse guard. The native C boundary in cmd/cyber-abuse-guard is kept
// deliberately thin; policy state and lifecycle semantics live here so they
// can be race-tested without loading a shared object.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

const (
	ID = "cyber-abuse-guard"

	maxRPCRequestBytes = 8 << 20

	blockedErrorCode     = "cyber_abuse_guard_blocked"
	unsupportedErrorCode = "cyber_abuse_guard_unsupported"

	refusalMessage = "Request blocked by the local cyber-abuse policy. Defensive analysis, remediation, CTF/lab work, and explicitly authorized testing are supported."
)

var metadata = pluginapi.Metadata{
	Name:             "CPA Cyber Abuse Guard",
	Author:           "Cyber Abuse Guard Contributors",
	GitHubRepository: "https://github.com/yujianwudi/cyber-abuse-guard-next",
	ConfigFields: []pluginapi.ConfigField{
		{Name: "enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Enable local cyber-abuse classification."},
		{Name: "mode", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"off", "observe", "audit", "balanced", "strict"}, Description: "Select observation, auditing, or enforcement behavior."},
		{Name: "priority", Type: pluginapi.ConfigFieldTypeInteger, Description: "Run before provider and authentication selection."},
		{Name: "max_scan_bytes", Type: pluginapi.ConfigFieldTypeInteger, Description: "Deprecated compatibility alias for max_text_window_bytes; it no longer truncates raw JSON or total text coverage."},
		{Name: "max_text_window_bytes", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum decoded text retained in one bounded streaming-classifier window."},
		{Name: "max_total_text_bytes", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum cumulative model-visible text fully inspected per request."},
		{Name: "max_classification_chunks", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum bounded classifier chunks per request; logical text units use max_text_parts separately."},
		{Name: "max_json_depth", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum JSON nesting depth inspected by the bounded extractor."},
		{Name: "max_text_parts", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum number of text parts inspected per request."},
		{Name: "opaque_media_policy", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"block", "audit", "allow"}, Description: "Explicit policy for opaque image/audio/video content; omitted uses mode-aware defaults and never fetches remote URLs."},
		{Name: "thresholds", Type: pluginapi.ConfigFieldTypeObject, Description: "Audit, balanced-block, and hard-block score thresholds."},
		{Name: "allow_context", Type: pluginapi.ConfigFieldTypeObject, Description: "Explicit defensive, remediation, CTF, lab, authorization, and static-analysis allowances."},
		{Name: "hard_block_even_if_authorized", Type: pluginapi.ConfigFieldTypeObject, Description: "Categories whose operational abuse remains protected from authorization score reductions."},
		{Name: "subject_control", Type: pluginapi.ConfigFieldTypeObject, Description: "Rolling subject-risk, cooldown, and manual-block settings."},
		{Name: "audit", Type: pluginapi.ConfigFieldTypeObject, Description: "SQLite audit settings plus an explicit default-off, block-only, redacted and truncated operator request-preview capture."},
		{Name: "trusted_proxy", Type: pluginapi.ConfigFieldTypeObject, Description: "Reserved for a future verified-peer API; enabling it is rejected on CPA v7.2.125."},
		{Name: "classifier", Type: pluginapi.ConfigFieldTypeObject, Description: "Reserved local-classifier interface; enabling it is unsupported in v1.0.0 and rejected."},
	},
}

func currentMetadata() pluginapi.Metadata {
	current := metadata
	current.Version = buildinfo.Current().Version
	return current
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ModelRouter           bool                         `json:"model_router"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats"`
	RequestInterceptor    bool                         `json:"request_interceptor"`
	RequestLifecycle      bool                         `json:"request_lifecycle_plugin"`
	ManagementAPI         bool                         `json:"management_api"`
}

type rpcEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Category   string `json:"category,omitempty"`
}

type runtimeState struct {
	config       config.Config
	classifier   *classifier.Classifier
	rulesVersion string
	audit        *audit.Store
	auditStorage auditStorageVerification
	// auditStorageGate exists only for the explicit production persistence
	// contract. It latches a live failure until this runtime is replaced.
	auditStorageGate *auditStorageGate
	// auditStorageProbe is immutable after publication. Management invokes it
	// for every authenticated status read so readiness reflects current mount,
	// identity, permission, writability, and capacity state rather than the
	// startup snapshot.
	auditStorageProbe                            func(auditStorageVerification) auditStorageVerification
	auditStorageNeedsPostActivationCheck         bool
	auditStorageActivationDiscardRequired        bool
	subjectPersistenceNeedsPostActivationRestore bool
	subject                                      *subject.Controller
	persistence                                  *subjectPersistenceRuntime
	startedAt                                    time.Time
	configuredAt                                 time.Time
}

type preparedRuntimeRules struct {
	set        *rules.RuleSet
	classifier *classifier.Classifier
}

type auditActivationStage uint8

const (
	auditActivationBeforeSwap auditActivationStage = iota + 1
	auditActivationAfterSwapBeforeOpen
	auditActivationAfterPriorCloseBeforeOpen
	auditActivationAfterOpenBeforeBind
	auditActivationAfterMaintenanceBeforeFinalBind
)

type runtimeCloseOutcome struct {
	durable          bool
	sidecarsReleased bool
	err              error
}

func (state *runtimeState) close() runtimeCloseOutcome {
	if state == nil {
		return runtimeCloseOutcome{durable: true}
	}
	// Capture recovery eligibility before the close transition starts. The final
	// subject-persistence save below performs a live storage probe and may newly
	// latch the gate; such a transition-time failure must not be mistaken for an
	// already-visible degraded runtime that an explicit reconfigure may recover.
	latchedBeforeClose := state.auditStorageGate != nil && state.auditStorageGate.latchedBeforeClose()
	state.stopSubjectPersistence()
	if state.audit == nil {
		return runtimeCloseOutcome{durable: true}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state.audit.SetErrorHandler(nil)
	if !state.audit.IsActive() ||
		(state.auditStorageGate != nil && state.auditStorageGate.latchedBeforeClose()) {
		// Discard is an intentional no-checkpoint boundary. Even when it returns
		// nil, it is not durable. An explicit reconfigure may nevertheless recover
		// from a gate that was already visibly latched before close; a failure first
		// discovered by this close never receives that ownership-release grant.
		err := state.audit.DiscardContext(ctx)
		return runtimeCloseOutcome{sidecarsReleased: latchedBeforeClose && err == nil, err: err}
	}
	// The caller has already removed this runtime behind opMu's exclusive
	// admission boundary, and stopSubjectPersistence above has stopped its only
	// asynchronous producer. Quiesce also closes the Store's own admission gate,
	// drains every accepted item, and stops the worker/maintenance ticker without
	// checkpointing or closing SQLite. Individual worker failures are fail-open
	// and therefore are not returned by CloseContext.
	if err := state.audit.QuiesceContext(ctx); err != nil {
		discardErr := state.audit.DiscardContext(ctx)
		return runtimeCloseOutcome{err: errors.Join(err, discardErr)}
	}
	if state.auditStorageGate != nil {
		// readAccess bypasses the one-second write-hot-path cache. A worker may
		// have first latched the gate while satisfying the quiesce drain above;
		// in that case Discard must prevent the unsafe checkpoint that a normal
		// CloseContext would otherwise attempt.
		if err := state.auditStorageGate.readAccess(); err != nil {
			discardErr := state.audit.DiscardContext(ctx)
			return runtimeCloseOutcome{err: discardErr}
		}
	}
	err := state.audit.CloseContext(ctx)
	clean := err == nil && (state.auditStorageGate == nil || !state.auditStorageGate.latchedBeforeClose())
	return runtimeCloseOutcome{durable: clean, sidecarsReleased: clean, err: err}
}

func (p *Plugin) closeRuntime(state *runtimeState) runtimeCloseOutcome {
	outcome := state.close()
	if outcome.err != nil {
		// SQLite diagnostics may contain operator-selected paths. Keep the Host
		// log stable and content-free while ensuring checkpoint/close failures are
		// not silently discarded.
		p.log("error", "cyber-abuse-guard audit storage did not close cleanly", map[string]any{
			"plugin": ID,
			"code":   "audit_storage_close_failed",
		})
	}
	return outcome
}

// completePriorAuditStoreClose transfers exactly one sidecar lifecycle grant
// to a same-path prepared candidate. A failed or timed-out prior close cannot
// be rolled back after Swap, so the replacement is latched degraded and its
// prepared SQLite handle is discarded during the activation failure path.
func (state *runtimeState) completePriorAuditStoreClose(expected, sidecarsReleased bool, closeErr error) {
	if !expected || state == nil || state.auditStorageGate == nil {
		return
	}
	if sidecarsReleased && closeErr == nil {
		state.auditStorageGate.authorizePriorStoreSidecarRelease()
		return
	}
	state.auditStorage = state.auditStorageGate.latchPriorStoreCloseFailure()
	state.auditStorageNeedsPostActivationCheck = false
	state.auditStorageActivationDiscardRequired = true
}

// Plugin is safe for concurrent CPA callbacks. A validated runtime is built
// completely before the atomic pointer is swapped; failed reconfiguration
// never exposes a partially initialized policy.
type Plugin struct {
	runtime atomic.Pointer[runtimeState]

	lifecycleMu              sync.Mutex
	opMu                     sync.RWMutex
	migrationBackupMu        sync.Mutex
	shutdown                 atomic.Bool
	shutdownModelRoutePolicy atomic.Uint32

	lastConfigError      atomic.Pointer[string]
	lastReconfigureError atomic.Pointer[string]
	identifier           *subject.Identifier
	identifierErr        error
	loadRules            func() (*rules.RuleSet, error)
	auditStorageInspect  func(string, bool, bool, int64) auditStorageVerification
	// auditActivationHook is nil in production. Tests use the explicit lifecycle
	// boundaries to replace a directory/database deterministically instead of
	// relying on scheduler timing around Swap and post-open identity binding.
	auditActivationHook       func(auditActivationStage)
	requestHasher             func([]byte) string
	requestFingerprintKey     [32]byte
	requestFingerprintEnabled bool
	startupPrivacyInstanceID  string
	startupPrivacyChallenges  startupPrivacyChallengeStore
	pending                   pendingCache
	requestLifecycle          requestLifecycleCache
	counters                  counters
	lastAuditNotice           atomic.Int64
	lastRouterNotice          atomic.Int64
	lastUnknownSourceNotice   atomic.Int64
	lastPersistenceNotice     atomic.Int64
	abiLimitLogged            atomic.Bool
	loggerMu                  sync.RWMutex
	logger                    LogFunc
}

// LogFunc receives privacy-safe operational messages. The native entrypoint
// wires this only to CPA's host.log callback; execution paths never use it.
type LogFunc func(level, message string, fields map[string]any)

// New creates an unregistered plugin. Configuration and rules are activated
// only by plugin.register, matching the CPA native lifecycle.
func New() *Plugin {
	identifier, err := subject.NewIdentifier(subject.IdentifierConfig{})
	requestFingerprintKey, requestFingerprintEnabled := newRequestFingerprintKey()
	startupPrivacyInstanceID := newStartupPrivacyInstanceID()
	return &Plugin{
		identifier:                identifier,
		identifierErr:             err,
		loadRules:                 rules.LoadDefault,
		requestHasher:             audit.HashRequest,
		requestFingerprintKey:     requestFingerprintKey,
		requestFingerprintEnabled: requestFingerprintEnabled,
		startupPrivacyInstanceID:  startupPrivacyInstanceID,
		startupPrivacyChallenges:  newStartupPrivacyChallengeStore(),
		pending:                   newPendingCache(4096, 2*time.Minute),
		requestLifecycle: newRequestLifecycleCache(
			8192,
			10*time.Minute,
		),
	}
}

// Call dispatches one schema-v2 RPC method. Controlled protocol/policy errors
// use a valid error envelope with return code zero. A recovered panic uses a
// non-zero ABI return code while still returning a parseable envelope.
func (p *Plugin) Call(method string, request []byte) (response []byte, returnCode int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response, returnCode = p.recoverCallbackPanic(method)
		}
	}()
	if p == nil {
		return errorEnvelope("plugin_unavailable", "plugin is unavailable", 0, ""), 0
	}
	if len(request) > maxRPCRequestBytes {
		return p.CallOversized(method)
	}
	if method == "" {
		return errorEnvelope("invalid_method", "method is required", 0, ""), 0
	}
	if method == pluginabi.MethodPluginShutdown {
		p.Shutdown()
		return okEnvelope(struct{}{}), 0
	}
	if method == pluginabi.MethodRequestComplete {
		return p.handleRequestComplete(request), 0
	}
	if p.shutdown.Load() {
		if method == pluginabi.MethodModelRoute {
			return p.modelRouteFailureWithPolicy(
				"plugin_shutdown",
				"cyber_abuse_guard_shutdown",
				decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load()),
			), 0
		}
		if requestInterceptorMethod(method) {
			return p.requestInterceptorFailureWithPolicy(
				"plugin_shutdown",
				decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load()),
			), 0
		}
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, ""), 0
	}

	switch method {
	case pluginabi.MethodPluginRegister:
		return p.configure(request, false), 0
	case pluginabi.MethodPluginReconfigure:
		return p.configure(request, true), 0
	case pluginabi.MethodModelRoute:
		return p.callModelRoute(request)
	case pluginabi.MethodRequestInterceptBefore:
		return p.callRequestIntercept(request, true)
	case pluginabi.MethodRequestInterceptAfter:
		return p.callRequestIntercept(request, false)
	case pluginabi.MethodExecutorIdentifier:
		return okEnvelope(struct {
			Identifier string `json:"identifier"`
		}{Identifier: ID}), 0
	case pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream, pluginabi.MethodExecutorCountTokens:
		return p.blockExecution(request), 0
	case pluginabi.MethodExecutorHTTPRequest:
		return errorEnvelope(unsupportedErrorCode, "this policy executor does not provide HTTP forwarding", 405, ""), 0
	case pluginabi.MethodManagementRegister:
		return p.registerManagement(request), 0
	case pluginabi.MethodManagementHandle:
		return p.handleManagement(request), 0
	default:
		return errorEnvelope("unknown_method", "unknown plugin method", 0, ""), 0
	}
}

// CallOversized handles an RPC that exceeded the boundary-copy budget without
// parsing or copying its attacker-controlled payload. Schema-v2 request
// interception can terminate directly, so this content-incomplete condition is
// returned as a successful mode-specific response: strict terminates while
// balanced/audit/observe/off preserve the configured incomplete policy.
func (p *Plugin) CallOversized(method string) (response []byte, returnCode int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response, returnCode = p.recoverCallbackPanic(method)
		}
	}()
	if p == nil {
		return errorEnvelope("plugin_unavailable", "plugin is unavailable", 0, ""), 0
	}
	if p.shutdown.Load() {
		if method == pluginabi.MethodModelRoute {
			return p.modelRouteFailureWithPolicy(
				"plugin_shutdown",
				"cyber_abuse_guard_shutdown",
				decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load()),
			), 0
		}
		if requestInterceptorMethod(method) {
			return p.requestInterceptorFailureWithPolicy(
				"plugin_shutdown",
				decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load()),
			), 0
		}
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, ""), 0
	}
	switch method {
	case pluginabi.MethodModelRoute:
		return p.callOversizedModelRoute()
	case pluginabi.MethodRequestInterceptBefore:
		return p.callOversizedRequestIntercept()
	case pluginabi.MethodRequestInterceptAfter:
		return p.callOversizedRequestInterceptAfterAuth()
	case pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream, pluginabi.MethodExecutorCountTokens:
		return p.callOversizedExecutor()
	default:
		return errorEnvelope("request_too_large", "plugin RPC request exceeds the size limit", 0, ""), 0
	}
}

func (p *Plugin) callOversizedExecutor() ([]byte, int) {
	p.opMu.RLock()
	state := p.runtime.Load()
	strict := state != nil && state.config.Enabled && state.config.Mode == config.ModeStrict
	p.opMu.RUnlock()
	if strict {
		p.counters.executorBlocks.Add(1)
		return errorEnvelope(blockedErrorCode, refusalMessage, 403, "rpc_body_limit"), 0
	}
	// Non-strict inspection paths do not turn an oversized request into a policy
	// block. If a Host calls the executor directly anyway, report the boundary
	// failure without writing a duplicate decision event.
	return errorEnvelope("request_too_large", "plugin executor RPC exceeds the size limit", 413, "rpc_body_limit"), 0
}

// recoverCallbackPanic is deliberately mode-aware for ModelRouter and schema-v2
// request-interceptor callbacks. CPA continues after an RPC error, so an
// enforcing runtime must return a successful local block response. The
// recovered value is never logged because it can contain attacker-controlled
// data. Other RPC methods retain the ABI-level non-zero failure signal.
func (p *Plugin) recoverCallbackPanic(method string) ([]byte, int) {
	if p == nil {
		return errorEnvelope("panic_recovered", "plugin callback failed safely", 0, ""), 1
	}
	p.counters.panicsRecovered.Add(1)
	if method == pluginabi.MethodModelRoute {
		return p.modelRouteFailureWithPolicy(
			"panic_recovered",
			"cyber_abuse_guard_router_panic",
			p.snapshotModelRouteFailurePolicy(),
		), 0
	}
	if requestInterceptorMethod(method) {
		return p.requestInterceptorFailureWithPolicy(
			"panic_recovered",
			p.snapshotModelRouteFailurePolicy(),
		), 0
	}
	p.log("error", "cyber-abuse-guard recovered a plugin callback panic", map[string]any{
		"plugin": ID,
		"method": method,
		"code":   "panic_recovered",
	})
	return errorEnvelope("panic_recovered", "plugin callback failed safely", 0, ""), 1
}

// RecoverNativeCallbackPanic is the fail-safe used by the cgo export boundary
// if a panic occurs outside Call/CallOversized after the RPC method is known.
// Keeping the policy here ensures a model.route panic has exactly the same
// mode-aware self-route semantics at both Go and native ABI boundaries.
func (p *Plugin) RecoverNativeCallbackPanic(method string) ([]byte, int) {
	return p.recoverCallbackPanic(method)
}

type modelRouteFailurePolicy struct {
	initialized bool
	failClosed  bool
}

const (
	shutdownModelRouteAllow uint32 = iota + 1
	shutdownModelRouteFailClosed
)

func modelRoutePolicyFromState(state *runtimeState) modelRouteFailurePolicy {
	if state == nil {
		return modelRouteFailurePolicy{}
	}
	return modelRouteFailurePolicy{
		initialized: true,
		failClosed: state.config.Enabled &&
			(state.config.Mode == config.ModeBalanced || state.config.Mode == config.ModeStrict),
	}
}

func encodeModelRouteFailurePolicy(policy modelRouteFailurePolicy) uint32 {
	if policy.failClosed {
		return shutdownModelRouteFailClosed
	}
	return shutdownModelRouteAllow
}

func decodeModelRouteFailurePolicy(encoded uint32) modelRouteFailurePolicy {
	return modelRouteFailurePolicy{
		// Shutdown always publishes a terminal inspection policy before publishing
		// the shutdown flag. Treat even an unregistered shutdown as a valid
		// pass-through response instead of an RPC error.
		initialized: encoded != 0,
		failClosed:  encoded == shutdownModelRouteFailClosed,
	}
}

func (p *Plugin) snapshotModelRouteFailurePolicy() modelRouteFailurePolicy {
	if p == nil {
		return modelRouteFailurePolicy{}
	}
	if p.shutdown.Load() {
		return decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load())
	}
	policy := modelRoutePolicyFromState(p.runtime.Load())
	// Shutdown publishes its terminal policy and flag before removing the
	// runtime. Recheck after a nil load so a callback straddling the atomic
	// runtime removal cannot transiently produce an RPC error.
	if !policy.initialized && p.shutdown.Load() {
		return decodeModelRouteFailurePolicy(p.shutdownModelRoutePolicy.Load())
	}
	return policy
}

// modelRouteFailureWithPolicy records a privacy-safe operational error and
// uses the policy captured when the callback was admitted. This is crucial:
// shutdown and reconfiguration may replace or remove the runtime while a
// malformed outer RPC, invariant failure, or recovered panic is returning. An
// enforcing callback must retain its successful self-route response across
// that lifecycle race. Request-body parse errors never enter this path.
func (p *Plugin) modelRouteFailureWithPolicy(code, reason string, policy modelRouteFailurePolicy) []byte {
	if p == nil {
		return errorEnvelope("plugin_unavailable", "plugin is unavailable", 0, "")
	}
	p.counters.routerErrors.Add(1)
	p.reportRouterFailure(code)
	if policy.failClosed {
		return okEnvelope(pluginapi.ModelRouteResponse{
			Handled:    true,
			TargetKind: pluginapi.ModelRouteTargetSelf,
			Reason:     reason,
		})
	}
	if policy.initialized {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}
	return errorEnvelope(code, "model router request failed safely", 0, "")
}

func (p *Plugin) reportRouterFailure(code string) {
	now := time.Now().UnixNano()
	for {
		previous := p.lastRouterNotice.Load()
		if previous != 0 && time.Duration(now-previous) < time.Minute {
			return
		}
		if p.lastRouterNotice.CompareAndSwap(previous, now) {
			p.log("error", "cyber-abuse-guard handled a Router/RequestInterceptor protocol failure safely", map[string]any{
				"plugin": ID,
				"code":   code,
			})
			return
		}
	}
}

func (p *Plugin) callOversizedModelRoute() (response []byte, returnCode int) {
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
	response = p.routeOversized(state)
	p.opMu.RUnlock()
	locked = false
	return response, 0
}

func (p *Plugin) routeOversized(state *runtimeState) []byte {
	if !state.config.Enabled || state.config.Mode == config.ModeOff {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}
	p.counters.total.Add(1)
	reasons := []extract.IncompleteReason{extract.IncompleteRPCBodyLimit}
	decision := inspectionDisposition(state.config.Mode, inspectionOutcome{Incomplete: reasons}, state.config.EffectiveOpaqueMediaPolicy())
	p.recordIncompleteCounters(reasons, decision)
	p.recordUnscannedCoverageFailure(
		coverageIncompleteRPCBodyLimit,
		reasons,
		finalRouteDispositionFor(coverageDispositionIncomplete, decision),
	)
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
	p.recordOversizedRoute(state, decision)
	if !decision.Block {
		return okEnvelope(pluginapi.ModelRouteResponse{Handled: false})
	}
	return blockedRouteEnvelope(decision.RouteReason)
}

func (p *Plugin) recordOversizedRoute(state *runtimeState, decision inspectionDecision) {
	if state == nil || state.audit == nil || !state.config.Audit.Enabled ||
		state.config.Mode == config.ModeOff || state.config.Mode == config.ModeObserve {
		return
	}
	action := "audit"
	if decision.Observe {
		action = "observe"
	} else if decision.Block {
		action = "block"
	}
	event := audit.Event{
		ID:               newEventID(),
		Timestamp:        time.Now().UTC(),
		Action:           action,
		Mode:             string(state.config.Mode),
		Classifier:       state.rulesVersion,
		Decision:         decision.Code,
		DecisionKind:     string(decision.Kind),
		Coverage:         "incomplete",
		IncompleteReason: incompleteCategory([]extract.IncompleteReason{extract.IncompleteRPCBodyLimit}),
		Scanner:          streamingScannerIdentity,
	}
	if state.config.Audit.LogCategory {
		event.Category = decision.Category
	}
	p.recordAuditEvent(state, event)
}

func (p *Plugin) configure(raw []byte, reconfigure bool) []byte {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.shutdown.Load() {
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, "")
	}

	var request lifecycleRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		if reconfigure && p.runtime.Load() != nil {
			p.rejectReconfigure(errors.New("invalid lifecycle request"), "invalid_request")
			return okEnvelope(currentRegistration())
		}
		return errorEnvelope("invalid_request", "invalid lifecycle request", 0, "")
	}
	if request.SchemaVersion < pluginabi.SchemaVersion {
		if reconfigure && p.runtime.Load() != nil {
			p.rejectReconfigure(fmt.Errorf("unsupported schema version %d", request.SchemaVersion), "unsupported_schema")
			return okEnvelope(currentRegistration())
		}
		return errorEnvelope("unsupported_schema", fmt.Sprintf("unsupported schema version %d", request.SchemaVersion), 0, "")
	}

	currentBeforeBuild := p.runtime.Load()
	var preparedSubject *subject.Controller
	var candidateConfig config.Config
	var preparedRules *preparedRuntimeRules
	prepareAuditCandidate := false
	deferAuditCandidateMutation := false
	opLocked := false
	if reconfigure && currentBeforeBuild != nil {
		// Freeze request callbacks before copying subject state. Preparing the
		// independent controller is the last rejection point that depends on the
		// active in-memory state, and it deliberately precedes opening or migrating
		// any candidate audit database.
		var errParse error
		candidateConfig, errParse = config.Parse(request.ConfigYAML)
		if errParse != nil {
			p.setLastConfigError(errParse)
			p.rejectReconfigure(errParse, "invalid_config")
			return okEnvelope(currentRegistration())
		}
		if errParse = validateRuntimeConfig(candidateConfig); errParse != nil {
			p.setLastConfigError(errParse)
			p.rejectReconfigure(errParse, "invalid_config")
			return okEnvelope(currentRegistration())
		}
		// Loading and compiling the immutable rule set can be relatively slow and
		// does not depend on active request or subject state. Prepare it before the
		// exclusive operation barrier so ordinary callbacks keep using the current
		// runtime until the state-dependent clone and atomic swap begin.
		var prepareErr error
		preparedRules, prepareErr = p.prepareRuntimeRules()
		if prepareErr != nil {
			p.setLastConfigError(prepareErr)
			p.rejectReconfigure(prepareErr, "invalid_config")
			return okEnvelope(currentRegistration())
		}
		p.opMu.Lock()
		opLocked = true
		if p.shutdown.Load() {
			p.opMu.Unlock()
			return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, "")
		}
		currentBeforeBuild = p.runtime.Load()
		if currentBeforeBuild != nil {
			if errParse = preflightAuditDataDirReconfigure(currentBeforeBuild.config, candidateConfig); errParse != nil {
				p.opMu.Unlock()
				p.rejectReconfigure(errParse, "audit_data_dir_restart_required")
				return okEnvelope(currentRegistration())
			}
		}
		prepareAuditCandidate = currentBeforeBuild != nil && currentBeforeBuild.audit.IsActive() &&
			currentBeforeBuild.config.Audit.Enabled && candidateConfig.Audit.Enabled
		deferAuditCandidateMutation = candidateConfig.Audit.Enabled
		if currentBeforeBuild != nil && currentBeforeBuild.subject != nil &&
			currentBeforeBuild.config.SubjectControl.Enabled && candidateConfig.SubjectControl.Enabled {
			preparedSubject, errParse = currentBeforeBuild.subject.CloneReconfigured(subjectRuntimeConfig(candidateConfig))
			if errParse != nil {
				p.opMu.Unlock()
				p.setLastConfigError(errParse)
				p.setLastReconfigureError(errParse)
				p.log("warn", "cyber-abuse-guard rejected a reconfiguration that could not preserve subject state", map[string]any{
					"plugin": ID,
					"code":   "subject_state_migration_rejected",
				})
				return okEnvelope(currentRegistration())
			}
		}
		if currentBeforeBuild != nil {
			if errParse = preflightAuditRecoveryReconfigure(currentBeforeBuild, candidateConfig); errParse != nil {
				p.opMu.Unlock()
				p.rejectReconfigure(errParse, "audit_storage_restart_required")
				return okEnvelope(currentRegistration())
			}
		}
	}

	var state *runtimeState
	var err error
	if preparedRules != nil {
		state, err = p.buildRuntimeWithRules(
			request.ConfigYAML,
			deferAuditCandidateMutation,
			prepareAuditCandidate,
			preparedRules,
		)
	} else {
		state, err = p.buildRuntime(request.ConfigYAML, deferAuditCandidateMutation, prepareAuditCandidate)
	}
	if err != nil {
		if opLocked {
			p.opMu.Unlock()
		}
		p.setLastConfigError(err)
		if reconfigure && p.runtime.Load() != nil {
			p.rejectReconfigure(err, "invalid_config")
			return okEnvelope(currentRegistration())
		}
		return errorEnvelope("invalid_config", err.Error(), 0, "")
	}

	if !opLocked {
		p.opMu.Lock()
	}
	if p.shutdown.Load() {
		p.opMu.Unlock()
		p.closeRuntime(state)
		return errorEnvelope("plugin_shutdown", "plugin has shut down", 0, "")
	}
	current := p.runtime.Load()
	if reconfigure && current != nil {
		state.startedAt = current.startedAt
	}
	if preparedSubject != nil {
		state.subject = preparedSubject
	}
	if reconfigure && current != nil && current.config.Audit.Enabled && current.config.Audit.RawCapture.Enabled &&
		(!state.config.Audit.Enabled || !state.config.Audit.RawCapture.Enabled) {
		// p.opMu is exclusive here, every old inspection/management callback has
		// finished, and all other runtime migrations have succeeded. Purge and
		// WAL truncation therefore form the final hard privacy gate before Swap.
		// If the gate cannot complete, retain the previous runtime instead of
		// publishing a disabled configuration that merely hides sensitive rows.
		samePath := current.audit.IsActive() && state.audit != nil &&
			sameAuditStoragePath(current.auditStorage.DatabasePath, state.auditStorage.DatabasePath)
		if samePath {
			// The replacement Store cannot flush work admitted by the current
			// Store, even though both handles address the same SQLite file. Drain
			// the current queue before the replacement deletes and checkpoints so
			// close-time draining cannot reinsert a preview after the privacy gate.
			// A latched storage gate remains safe here: the old writer rechecks it
			// for every queued item and rejects those writes before this barrier.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flushErr := current.audit.Flush(ctx)
			cancel()
			if flushErr != nil {
				p.opMu.Unlock()
				p.closeRuntime(state)
				p.rejectReconfigure(
					fmt.Errorf("drain prior raw-capture queue before same-path purge: %w", flushErr),
					"raw_capture_drain_failed",
				)
				return okEnvelope(currentRegistration())
			}
		}
		stores := make([]*audit.Store, 0, 2)
		if samePath {
			// Use the queue owner as the same-path purge authority. Flush above
			// established its writer boundary, and a compensated post-delete
			// failure is then reflected on the Store that remains active.
			stores = append(stores, current.audit)
		} else {
			if state.audit != nil && state.audit.IsActive() {
				stores = append(stores, state.audit)
			}
			if current.audit.IsActive() {
				stores = append(stores, current.audit)
			}
		}
		if len(stores) == 0 {
			p.opMu.Unlock()
			p.closeRuntime(state)
			p.rejectReconfigure(
				errors.New("disabling raw capture or audit without an active purge Store requires restart so retained sensitive previews cannot be hidden"),
				"audit_storage_restart_required",
			)
			return okEnvelope(currentRegistration())
		}
		for _, store := range stores {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, purgeErr := store.PurgeRawCaptures(ctx)
			cancel()
			if purgeErr != nil {
				p.opMu.Unlock()
				p.closeRuntime(state)
				code := "raw_capture_purge_failed"
				if errors.Is(purgeErr, audit.ErrRawCapturePurgeUnrecovered) {
					code = "raw_capture_purge_unrecovered"
				}
				p.rejectReconfigure(purgeErr, code)
				return okEnvelope(currentRegistration())
			}
		}
	}
	if p.auditActivationHook != nil && state.audit != nil {
		p.auditActivationHook(auditActivationBeforeSwap)
	}
	previous := p.runtime.Swap(state)
	if p.auditActivationHook != nil && state.audit != nil {
		p.auditActivationHook(auditActivationAfterSwapBeforeOpen)
	}
	p.pending.clear()
	p.requestLifecycle.clear()
	p.startupPrivacyChallenges.clear()
	p.setLastConfigError(nil)
	p.setLastReconfigureError(nil)
	priorClose := p.closeRuntime(previous)
	if p.auditActivationHook != nil && state.audit != nil {
		p.auditActivationHook(auditActivationAfterPriorCloseBeforeOpen)
	}
	state.completePriorAuditStoreClose(prepareAuditCandidate, priorClose.sidecarsReleased, priorClose.err)
	if previous != nil && previous.audit != nil && !priorClose.sidecarsReleased {
		// Close diagnostics can contain an operator-selected SQLite path. Preserve
		// the concrete error only in the Store's internal status/log boundary and
		// expose a stable content-free lifecycle error through management JSON.
		message := "prior audit Store became unverified during runtime close"
		if priorClose.err != nil {
			message = "prior audit Store close or checkpoint failed before runtime activation"
		}
		p.setLastReconfigureError(errors.New(message))
	}
	var activationErr error
	if state.audit != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		activationErr = state.audit.Activate(ctx)
		cancel()
		if activationErr != nil {
			p.log("error", "cyber-abuse-guard activated a runtime with degraded audit maintenance", map[string]any{
				"plugin": ID,
				"code":   "audit_activation_degraded",
			})
			if state.auditStorageActivationDiscardRequired {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				discardErr := state.audit.DiscardContext(ctx)
				cancel()
				if discardErr != nil {
					p.log("error", "cyber-abuse-guard failed to discard a rejected audit activation", map[string]any{
						"plugin": ID,
						"code":   "audit_activation_discard_failed",
					})
				}
			}
			// Activation gates update and latch their own storage state before
			// returning an error. A failed Store is never retried in place.
			state.auditStorageNeedsPostActivationCheck = false
		}
	}
	if activationErr != nil {
		state.blockSubjectPersistenceForStorage()
		state.subjectPersistenceNeedsPostActivationRestore = false
	} else if state.subjectPersistenceNeedsPostActivationRestore {
		state.subjectPersistenceNeedsPostActivationRestore = false
		state.restoreSubjectPersistence(p)
	}
	if activationErr == nil {
		state.startSubjectPersistence(p)
	}
	p.opMu.Unlock()
	p.reportABICapabilityLimits()
	return okEnvelope(currentRegistration())
}

func (p *Plugin) reportABICapabilityLimits() {
	if !p.abiLimitLogged.CompareAndSwap(false, true) {
		return
	}
	p.log("warn", "cyber-abuse-guard cannot verify interceptor ordering or duplicate plugin binaries through the CPA v7.2.125 plugin ABI", map[string]any{
		"plugin": ID,
		"code":   "cpa_abi_conflict_detection_unavailable",
		"request_interceptor_enumeration_supported": false,
		"router_enumeration_supported":              false,
		"duplicate_plugin_binary_scan_supported":    false,
	})
}

func (p *Plugin) rejectReconfigure(err error, code string) {
	p.setLastConfigError(err)
	p.setLastReconfigureError(err)
	p.log("warn", "cyber-abuse-guard rejected a reconfiguration; the previous configuration remains active", map[string]any{
		"plugin": ID,
		"code":   code,
	})
}

// SetLogger replaces the optional operational logger. Passing nil disables
// immediate log delivery; last configuration/reconfiguration errors remain
// available via the authenticated management status.
func (p *Plugin) SetLogger(logger LogFunc) {
	if p == nil {
		return
	}
	p.loggerMu.Lock()
	p.logger = logger
	p.loggerMu.Unlock()
}

func (p *Plugin) log(level, message string, fields map[string]any) {
	p.loggerMu.RLock()
	logger := p.logger
	p.loggerMu.RUnlock()
	if logger == nil {
		return
	}
	defer func() { _ = recover() }()
	logger(level, message, fields)
}

func (p *Plugin) prepareRuntimeRules() (*preparedRuntimeRules, error) {
	loader := p.loadRules
	if loader == nil {
		loader = rules.LoadDefault
	}
	set, err := loader()
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	compiled, err := classifier.New(set)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	return &preparedRuntimeRules{set: set, classifier: compiled}, nil
}

func validateRuntimeConfig(cfg config.Config) error {
	if cfg.Classifier.Enabled {
		return fmt.Errorf("classifier.enabled is not supported in v%s; use deterministic local rules", buildinfo.Current().Version)
	}
	if cfg.TrustedProxy.Enabled {
		return errors.New("trusted_proxy.enabled is not supported because CPA v7.2.125 request interception does not provide a verified direct peer address")
	}
	if cfg.Audit.LogOriginalText {
		return errors.New("audit.log_original_text is not supported; use the explicit bounded audit.raw_capture feature")
	}
	return nil
}

func (p *Plugin) buildRuntime(rawConfig []byte, deferAuditCandidateMutation, prepareAuditCandidate bool) (*runtimeState, error) {
	return p.buildRuntimeWithRules(rawConfig, deferAuditCandidateMutation, prepareAuditCandidate, nil)
}

func (p *Plugin) buildRuntimeWithRules(
	rawConfig []byte,
	deferAuditCandidateMutation bool,
	prepareAuditCandidate bool,
	preparedRules *preparedRuntimeRules,
) (*runtimeState, error) {
	cfg, err := config.Parse(rawConfig)
	if err != nil {
		return nil, err
	}
	if err = validateRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if preparedRules == nil {
		preparedRules, err = p.prepareRuntimeRules()
		if err != nil {
			return nil, err
		}
	}
	if cfg.SubjectControl.Enabled && p.identifierErr != nil {
		p.log("error", "cyber-abuse-guard subject identifier initialization failed", map[string]any{
			"plugin": ID,
			"code":   "subject_identifier_init_failed",
			"error":  p.identifierErr.Error(),
		})
		return nil, errors.New("initialize subject identifier: HMAC key configuration is invalid")
	}
	if cfg.SubjectControl.Persistence {
		if p.identifier == nil || !p.identifier.Status().Stable || p.identifier.KeyID() == "" {
			return nil, fmt.Errorf("subject_control.persistence requires a stable HMAC key from %s or %s", subject.HMACKeyEnvironment, subject.HMACKeyFileEnvironment)
		}
	}

	controller, err := subject.NewController(subjectRuntimeConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("initialize subject risk: %w", err)
	}

	now := time.Now().UTC()
	state := &runtimeState{
		config:       cfg,
		classifier:   preparedRules.classifier,
		rulesVersion: preparedRules.set.Version,
		auditStorage: disabledAuditStorageVerification(),
		subject:      controller,
		startedAt:    now,
		configuredAt: now,
	}
	if cfg.Audit.Enabled {
		persistenceExpected := auditPersistenceExpected(cfg)
		path := ""
		var pathErr error
		if persistenceExpected || deferAuditCandidateMutation {
			// A required production volume is operator-owned infrastructure. Resolve
			// its configured database location without creating a missing mount or
			// directory; verification below must observe the volume as deployed.
			path, pathErr = auditDatabasePathLocation(cfg.Audit.DataDir)
		} else {
			path, pathErr = auditDatabasePath(cfg.Audit.DataDir)
		}
		inspectStorage := inspectAuditStorage
		if p.auditStorageInspect != nil {
			inspectStorage = p.auditStorageInspect
		}
		state.auditStorage = inspectStorage(
			path,
			strings.TrimSpace(cfg.Audit.DataDir) != "",
			persistenceExpected,
			int64(cfg.Audit.MaxDBMB)<<20,
		)
		state.auditStorageGate = newAuditStorageGate(state.auditStorage, int64(cfg.Audit.MaxDBMB)<<20, inspectStorage)
		if pathErr != nil {
			p.log("error", "cyber-abuse-guard could not prepare its audit directory", map[string]any{
				"plugin": ID,
				"code":   "audit_directory_unavailable",
			})
		}
		if state.auditStorage.blocksOperationalReadiness() {
			p.log("error", "cyber-abuse-guard audit persistence could not be verified", map[string]any{
				"plugin": ID,
				"code":   "audit_persistence_unverified",
				"reason": state.auditStorage.PersistenceReason,
			})
		}
		storageOpenPrevented := state.auditStorage.preventsDatabaseOpen()
		hadAuditArtifacts := false
		if !cfg.Audit.RawCapture.Enabled && !storageOpenPrevented {
			var inspectErr error
			hadAuditArtifacts, inspectErr = auditDatabaseArtifactsPresent(path)
			if inspectErr != nil {
				return nil, fmt.Errorf("inspect disabled raw-capture audit files: %w", inspectErr)
			}
		}
		if deferAuditCandidateMutation && !prepareAuditCandidate && !cfg.Audit.RawCapture.Enabled && hadAuditArtifacts {
			return nil, errors.New("hot reconfiguration cannot publish disabled raw capture over an unopened existing audit database; restart through the startup purge gate")
		}
		openPath := path
		if storageOpenPrevented {
			openPath = ""
		}
		var store *audit.Store
		var openErr error
		if state.auditStorage.blocksOperationalReadiness() {
			// Do not invoke the SQLite constructor at all when the explicit
			// persistence contract is unverified. A nil audit runtime is the
			// intentional fail-closed state exposed by management below.
			p.log("error", "cyber-abuse-guard audit storage is degraded", map[string]any{
				"plugin": ID,
				"code":   "audit_storage_degraded",
			})
		} else {
			var storageAccessGate func() error
			var storageActivationGate func() error
			var storagePostOpenBind func() error
			var storagePostMutationBind func() error
			var storagePostMaintenanceBind func() error
			var storageReadAccessGate func() error
			if state.auditStorageGate != nil {
				storageAccessGate = state.auditStorageGate.access
				storageActivationGate = state.auditStorageGate.activationAccess
				storageReadAccessGate = state.auditStorageGate.readAccess
				storagePostOpenBind = func() error {
					if deferAuditCandidateMutation && p.auditActivationHook != nil {
						p.auditActivationHook(auditActivationAfterOpenBeforeBind)
					}
					fresh, bindErr := state.auditStorageGate.bindAfterOpen()
					state.auditStorage = fresh
					return bindErr
				}
				storagePostMutationBind = func() error {
					fresh, bindErr := state.auditStorageGate.bindAfterOpen()
					state.auditStorage = fresh
					return bindErr
				}
				storagePostMaintenanceBind = func() error {
					return p.bindActivatedAuditStorage(state)
				}
			}
			store, openErr = audit.Open(audit.Config{
				Path:                        openPath,
				Retention:                   time.Duration(cfg.Audit.RetentionDays) * 24 * time.Hour,
				MaxBytes:                    int64(cfg.Audit.MaxDBMB) << 20,
				QueueSize:                   1024,
				BusyTimeout:                 2 * time.Second,
				CleanupInterval:             time.Hour,
				BackupBeforeMigration:       cfg.Audit.BackupBeforeMigration,
				MaxMigrationBackups:         cfg.Audit.MaxMigrationBackups,
				RequirePersistentStorage:    persistenceExpected,
				StorageAccessGate:           storageAccessGate,
				StorageActivationGate:       storageActivationGate,
				StoragePostOpenBind:         storagePostOpenBind,
				StoragePostMutationBind:     storagePostMutationBind,
				StoragePostMaintenanceBind:  storagePostMaintenanceBind,
				StorageReadAccessGate:       storageReadAccessGate,
				SkipDisabledPurgeOnOpen:     prepareAuditCandidate,
				SkipAllStartupMutation:      deferAuditCandidateMutation,
				AllowDeferredDatabaseCreate: deferAuditCandidateMutation,
				RawCapture: audit.RawCaptureConfig{
					Enabled:       cfg.Audit.RawCapture.Enabled,
					OnlyBlocked:   cfg.Audit.RawCapture.OnlyBlocked,
					MaxBytes:      cfg.Audit.RawCapture.MaxBytes,
					TTL:           time.Duration(cfg.Audit.RawCapture.TTLHours) * time.Hour,
					RedactSecrets: cfg.Audit.RawCapture.RedactSecrets,
				},
				OnError: func(error) {
					p.log("error", "cyber-abuse-guard audit storage is degraded", map[string]any{
						"plugin": ID,
						"code":   "audit_storage_degraded",
					})
				},
			})
		}
		if errors.Is(openErr, audit.ErrStorageBlocked) {
			if store != nil {
				openErr = errors.Join(openErr, store.Discard())
			}
			// A non-deferred enabled-capture runtime retains the discarded Store
			// solely as a terminal Status witness for the storage-blocked root cause.
			if deferAuditCandidateMutation || !cfg.Audit.RawCapture.Enabled {
				store = nil
			}
		}
		if deferAuditCandidateMutation && openErr != nil {
			if store != nil {
				openErr = errors.Join(openErr, store.Discard())
			}
			return nil, fmt.Errorf("prepare current-schema audit candidate without startup mutation: %w", openErr)
		}
		if !cfg.Audit.RawCapture.Enabled && !storageOpenPrevented && openErr != nil &&
			(hadAuditArtifacts || errors.Is(openErr, audit.ErrRawCapturePurge)) {
			if store != nil {
				openErr = errors.Join(openErr, store.Discard())
			}
			return nil, fmt.Errorf("initialize disabled raw-capture privacy gate: %w", openErr)
		}
		// Open intentionally returns a usable degraded store on database
		// failures, so enforcement remains available. A proven disabled-capture
		// purge failure is the exception above: publishing that runtime would hide
		// retained review text while claiming the feature was disabled.
		if store != nil && openErr == nil && !store.DatabaseAvailable() {
			state.auditStorageNeedsPostActivationCheck = true
		}
		state.audit = store
	}
	if cfg.SubjectControl.Persistence {
		state.persistence = newSubjectPersistenceRuntime(p.identifier.KeyID())
		if state.auditStorage.blocksOperationalReadiness() {
			// Do not even attempt a subject-state read when the production storage
			// contract failed. Blocking saves here also covers dirty, periodic,
			// reconfigure, and shutdown persistence boundaries.
			state.persistence.writesBlocked.Store(true)
			state.persistence.setError(errors.New("subject persistence requires verified audit storage"))
			p.logSubjectPersistenceError("subject_persistence_storage_unverified")
		} else if deferAuditCandidateMutation && state.audit != nil && !state.audit.DatabaseAvailable() {
			// A deferred-create candidate has no database to read until after it is
			// published and activated. Treat that lifecycle boundary as pending,
			// not as a permanent restore failure that would block all later saves.
			state.subjectPersistenceNeedsPostActivationRestore = true
		} else {
			state.restoreSubjectPersistence(p)
		}
	}
	return state, nil
}

func (p *Plugin) bindActivatedAuditStorage(state *runtimeState) error {
	if state == nil || state.audit == nil || !state.auditStorageNeedsPostActivationCheck {
		return nil
	}
	if p.auditActivationHook != nil {
		p.auditActivationHook(auditActivationAfterMaintenanceBeforeFinalBind)
	}
	inspectStorage := inspectAuditStorage
	if p.auditStorageInspect != nil {
		inspectStorage = p.auditStorageInspect
	}
	state.auditStorage = recheckAuditStorageWithInspector(
		state.auditStorage,
		int64(state.config.Audit.MaxDBMB)<<20,
		true,
		inspectStorage,
	)
	state.auditStorageNeedsPostActivationCheck = false
	if state.auditStorage.preventsDatabaseOpen() {
		state.auditStorageActivationDiscardRequired = true
		if state.auditStorageGate != nil {
			state.auditStorageGate.latch(state.auditStorage)
		}
		p.log("error", "cyber-abuse-guard audit storage changed while deferred activation opened SQLite", map[string]any{
			"plugin": ID,
			"code":   "audit_activation_identity_changed",
		})
		return auditStorageAccessError(state.auditStorage)
	}
	if state.auditStorageGate != nil {
		state.auditStorageGate.arm(state.auditStorage)
	}
	return nil
}

func auditDatabaseArtifactsPresent(path string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(candidate); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func subjectRuntimeConfig(cfg config.Config) subject.Config {
	return subject.Config{
		Enabled:          cfg.SubjectControl.Enabled,
		Window:           time.Duration(cfg.SubjectControl.WindowMinutes) * time.Minute,
		AuditThreshold:   cfg.Thresholds.Audit,
		CooldownScore:    float64(cfg.SubjectControl.CooldownScore),
		ManualBlockScore: float64(cfg.SubjectControl.ManualBlockScore),
		Cooldown:         time.Duration(cfg.SubjectControl.CooldownMinutes) * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
		MaxSubjects:      cfg.SubjectControl.MaxSubjects,
	}
}

func auditDatabasePath(dataDir string) (string, error) {
	databasePath, err := auditDatabasePathLocation(dataDir)
	if err != nil {
		return "", err
	}
	if err := prepareAuditStorageDirectory(filepath.Dir(databasePath)); err != nil {
		return databasePath, fmt.Errorf("create audit data directory: %w", err)
	}
	return databasePath, nil
}

func auditDatabasePathLocation(dataDir string) (string, error) {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve audit data directory: %w", err)
		}
		dataDir = filepath.Join(home, ".cli-proxy-api", "plugins", ID)
	}
	return filepath.Join(dataDir, "events.db"), nil
}

func preflightAuditDataDirReconfigure(current, candidate config.Config) error {
	if !current.Audit.Enabled || !candidate.Audit.Enabled {
		return nil
	}
	currentPath, err := auditDatabasePathLocation(current.Audit.DataDir)
	if err != nil {
		return fmt.Errorf("resolve current audit.data_dir before reconfigure: %w", err)
	}
	candidatePath, err := auditDatabasePathLocation(candidate.Audit.DataDir)
	if err != nil {
		return fmt.Errorf("resolve candidate audit.data_dir before reconfigure: %w", err)
	}
	if !sameAuditStoragePath(currentPath, candidatePath) {
		return errors.New("audit.data_dir changes require a plugin restart so candidate SQLite migration cannot precede configuration commit")
	}
	return nil
}

// preflightAuditRecoveryReconfigure is intentionally pathname-only. When no
// active Store owns an existing audit database, a hot candidate must not open
// it merely to inspect schema/journal mode: a read-write Ping can create or
// update WAL/SHM sidecars. Recovery of such a database therefore requires a
// restart through the normal startup gate. An empty, already existing data
// directory remains eligible for post-Swap creation.
func preflightAuditRecoveryReconfigure(current *runtimeState, candidate config.Config) error {
	if !candidate.Audit.Enabled || current == nil || current.audit.IsActive() {
		return nil
	}
	path, err := auditDatabasePathLocation(candidate.Audit.DataDir)
	if err != nil {
		return fmt.Errorf("resolve audit database recovery path: %w", err)
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("hot audit enablement requires an existing data directory; restart to create it through the startup storage gate")
	}
	if err != nil {
		return fmt.Errorf("inspect audit recovery directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("hot audit enablement requires a real existing data directory")
	}
	present, err := auditDatabaseArtifactsPresent(path)
	if err != nil {
		return fmt.Errorf("inspect audit recovery artifacts: %w", err)
	}
	if present {
		return errors.New("an existing audit DB/WAL/SHM without an active Store requires restart; hot recovery will not open or inspect it")
	}
	return nil
}

func currentRegistration() registration {
	formats := []string{"openai", "openai-response", "interactions", "codex-alpha-search", "openai-image", "openai-video", "claude", "gemini"}
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata:      currentMetadata(),
		Capabilities: registrationCapabilities{
			// CPA v7.2.125 does not invoke RequestInterceptor for Alpha Search.
			// ModelRouter is registered only as that narrow compatibility entry;
			// ordinary Host callbacks are rejected in callModelRouteRequest above.
			ModelRouter:           true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeStatic,
			ExecutorInputFormats:  append([]string(nil), formats...),
			ExecutorOutputFormats: append([]string(nil), formats...),
			RequestInterceptor:    true,
			RequestLifecycle:      true,
			ManagementAPI:         true,
		},
	}
}

func (p *Plugin) setLastConfigError(err error) {
	if err == nil {
		p.lastConfigError.Store(nil)
		return
	}
	message := err.Error()
	p.lastConfigError.Store(&message)
}

func (p *Plugin) lastConfigErrorMessage() string {
	value := p.lastConfigError.Load()
	if value == nil {
		return ""
	}
	return *value
}

func (p *Plugin) setLastReconfigureError(err error) {
	if err == nil {
		p.lastReconfigureError.Store(nil)
		return
	}
	message := err.Error()
	p.lastReconfigureError.Store(&message)
}

func (p *Plugin) lastReconfigureErrorMessage() string {
	value := p.lastReconfigureError.Load()
	if value == nil {
		return ""
	}
	return *value
}

func (p *Plugin) loadRuntime() (*runtimeState, error) {
	state := p.runtime.Load()
	if state == nil {
		return nil, errors.New("plugin is not registered")
	}
	return state, nil
}

// Shutdown is idempotent. It prevents new callbacks, waits for callbacks that
// hold the operation read lock, flushes audit work, and closes the store.
func (p *Plugin) Shutdown() {
	if p == nil {
		return
	}
	p.lifecycleMu.Lock()
	if p.shutdown.Load() {
		p.lifecycleMu.Unlock()
		return
	}
	// Publish one terminal enforcement policy before shutdown. CPA v7.2.125
	// continues after interceptor RPC errors, so late callbacks must receive a
	// successful direct response. An enforcing runtime remains fail-closed;
	// observe/audit/off remains an intentional pass-through.
	terminalPolicy := modelRoutePolicyFromState(p.runtime.Load())
	terminalPolicy.initialized = true
	p.shutdownModelRoutePolicy.Store(encodeModelRouteFailurePolicy(terminalPolicy))
	p.shutdown.Store(true)
	p.opMu.Lock()
	state := p.runtime.Swap(nil)
	p.pending.clear()
	p.requestLifecycle.clear()
	p.startupPrivacyChallenges.clear()
	p.opMu.Unlock()
	p.lifecycleMu.Unlock()
	p.closeRuntime(state)
}

func okEnvelope(value any) []byte {
	result, err := json.Marshal(value)
	if err != nil {
		return errorEnvelope("encode_error", "failed to encode plugin response", 0, "")
	}
	raw, err := json.Marshal(rpcEnvelope{OK: true, Result: result})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"encode_error","message":"failed to encode plugin response"}}`)
	}
	return raw
}

func errorEnvelope(code, message string, status int, category string) []byte {
	raw, err := json.Marshal(rpcEnvelope{OK: false, Error: &rpcError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
		Category:   category,
	}})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"plugin call failed"}}`)
	}
	return raw
}

type counters struct {
	// coverageMu makes one request's request/incomplete/reason/dimension/
	// disposition charge visible atomically to management snapshots. The hot
	// path takes it once per streamed request and retains fixed-size accounting.
	coverageMu                       sync.RWMutex
	total                            atomic.Uint64
	allowed                          atomic.Uint64
	observed                         atomic.Uint64
	audited                          atomic.Uint64
	blocked                          atomic.Uint64
	parseErrors                      atomic.Uint64
	truncated                        atomic.Uint64
	incompleteInspections            atomic.Uint64
	incompleteAllowed                atomic.Uint64
	incompleteBlocked                atomic.Uint64
	incompleteParseError             atomic.Uint64
	incompleteScanLimit              atomic.Uint64
	incompleteJSONDepthLimit         atomic.Uint64
	incompleteTextPartLimit          atomic.Uint64
	incompleteRoleAttribution        atomic.Uint64
	incompleteMultipartLimit         atomic.Uint64
	incompleteMultipartSchema        atomic.Uint64
	incompleteToolSchema             atomic.Uint64
	incompleteDeferredTextLimit      atomic.Uint64
	incompleteUnsupportedContentType atomic.Uint64
	incompleteRPCBodyLimit           atomic.Uint64
	incompleteClassifierProofBudget  atomic.Uint64
	executorBlocks                   atomic.Uint64
	managementTests                  atomic.Uint64
	routerErrors                     atomic.Uint64
	panicsRecovered                  atomic.Uint64
	opaqueMedia                      atomic.Uint64
	opaqueMediaAllowed               atomic.Uint64
	opaqueMediaAudited               atomic.Uint64
	opaqueMediaBlocked               atomic.Uint64
	opaqueMediaHTTPSImageURL         atomic.Uint64
	opaqueMediaDataURL               atomic.Uint64
	opaqueMediaBase64Image           atomic.Uint64
	opaqueMediaAudio                 atomic.Uint64
	opaqueMediaVideo                 atomic.Uint64
	opaqueMediaDocument              atomic.Uint64
	opaqueMediaRemoteURL             atomic.Uint64
	opaqueMediaOther                 atomic.Uint64
	unknownSourceFormats             atomic.Uint64
	controlPlaneMetaOverride         atomic.Uint64
	longTextRequests                 atomic.Uint64
	streamingScanRequests            atomic.Uint64
	textBytesScannedTotal            atomic.Uint64
	classificationChunksTotal        atomic.Uint64
	classificationWindowsTotal       atomic.Uint64
	coverageComplete                 atomic.Uint64
	coverageIncomplete               atomic.Uint64
	maxWindowsExhausted              atomic.Uint64
	totalTextLimitExhausted          atomic.Uint64
	windowBoundaryReconstructions    atomic.Uint64
	verifiedHardBlockUnderIncomplete atomic.Uint64
	coverageIncompleteReasons        coverageIncompleteCounters
	coverageDimensions               coverageDimensionCounters
}

func (c *counters) snapshot() map[string]uint64 {
	c.coverageMu.RLock()
	defer c.coverageMu.RUnlock()
	snapshot := map[string]uint64{
		"total":                                c.total.Load(),
		"allowed":                              c.allowed.Load(),
		"observed":                             c.observed.Load(),
		"audited":                              c.audited.Load(),
		"blocked":                              c.blocked.Load(),
		"parse_errors":                         c.parseErrors.Load(),
		"truncated":                            c.truncated.Load(),
		"incomplete_inspections":               c.incompleteInspections.Load(),
		"incomplete_allowed":                   c.incompleteAllowed.Load(),
		"incomplete_blocked":                   c.incompleteBlocked.Load(),
		"incomplete_parse_error":               c.incompleteParseError.Load(),
		"incomplete_scan_limit":                c.incompleteScanLimit.Load(),
		"incomplete_json_depth_limit":          c.incompleteJSONDepthLimit.Load(),
		"incomplete_text_part_limit":           c.incompleteTextPartLimit.Load(),
		"incomplete_role_attribution":          c.incompleteRoleAttribution.Load(),
		"incomplete_multipart_limit":           c.incompleteMultipartLimit.Load(),
		"incomplete_multipart_schema":          c.incompleteMultipartSchema.Load(),
		"incomplete_tool_schema":               c.incompleteToolSchema.Load(),
		"incomplete_deferred_text_limit":       c.incompleteDeferredTextLimit.Load(),
		"incomplete_unsupported_content_type":  c.incompleteUnsupportedContentType.Load(),
		"incomplete_rpc_body_limit":            c.incompleteRPCBodyLimit.Load(),
		"incomplete_classifier_proof_budget":   c.incompleteClassifierProofBudget.Load(),
		"rpc_body_limit":                       c.incompleteRPCBodyLimit.Load(),
		"executor_blocks":                      c.executorBlocks.Load(),
		"management_tests":                     c.managementTests.Load(),
		"router_errors":                        c.routerErrors.Load(),
		"panics_recovered":                     c.panicsRecovered.Load(),
		"opaque_media":                         c.opaqueMedia.Load(),
		"opaque_media_allowed":                 c.opaqueMediaAllowed.Load(),
		"opaque_media_audited":                 c.opaqueMediaAudited.Load(),
		"opaque_media_blocked":                 c.opaqueMediaBlocked.Load(),
		"opaque_media_https_image_url":         c.opaqueMediaHTTPSImageURL.Load(),
		"opaque_media_data_url":                c.opaqueMediaDataURL.Load(),
		"opaque_media_base64_image":            c.opaqueMediaBase64Image.Load(),
		"opaque_media_audio":                   c.opaqueMediaAudio.Load(),
		"opaque_media_video":                   c.opaqueMediaVideo.Load(),
		"opaque_media_document":                c.opaqueMediaDocument.Load(),
		"opaque_media_remote_url":              c.opaqueMediaRemoteURL.Load(),
		"opaque_media_other":                   c.opaqueMediaOther.Load(),
		"unknown_source_formats":               c.unknownSourceFormats.Load(),
		"control_plane_meta_override":          c.controlPlaneMetaOverride.Load(),
		"long_text_requests":                   c.longTextRequests.Load(),
		"streaming_scan_requests":              c.streamingScanRequests.Load(),
		"text_bytes_scanned_total":             c.textBytesScannedTotal.Load(),
		"classification_chunks_total":          c.classificationChunksTotal.Load(),
		"classification_windows_total":         c.classificationWindowsTotal.Load(),
		"coverage_complete":                    c.coverageComplete.Load(),
		"coverage_incomplete":                  c.coverageIncomplete.Load(),
		"max_windows_exhausted":                c.maxWindowsExhausted.Load(),
		"total_text_limit_exhausted":           c.totalTextLimitExhausted.Load(),
		"window_boundary_reconstructions":      c.windowBoundaryReconstructions.Load(),
		"verified_hard_block_under_incomplete": c.verifiedHardBlockUnderIncomplete.Load(),
	}
	for name, value := range c.coverageIncompleteSnapshot() {
		snapshot[name] = value
	}
	for name, value := range c.coverageDimensionSnapshot() {
		snapshot[name] = value
	}
	return snapshot
}
