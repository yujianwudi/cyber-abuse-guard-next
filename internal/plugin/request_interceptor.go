package plugin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
)

// requestLifecycleCache retains opaque CPA request IDs paired with HMAC-SHA256
// fingerprints of the security-relevant request representation. It is bounded
// and time-limited so a missing terminal callback cannot create unbounded
// state. No request text, raw header, credential, model name, trace ID, or
// completion error is retained.
type requestLifecycleCache struct {
	mu         sync.Mutex
	generation uint64
	active     pendingCache
}

func newRequestLifecycleCache(limit int, ttl time.Duration) requestLifecycleCache {
	return requestLifecycleCache{active: newPendingCache(limit, ttl)}
}

func (cache *requestLifecycleCache) generationToken() uint64 {
	if cache == nil {
		return 0
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.generation
}

// begin records a classification only when no successful runtime swap has
// occurred since the caller captured generation. Classification releases the
// runtime read lock before this small cache update, so the generation check is
// the fail-closed barrier that prevents an old-policy callback from refilling a
// cache which reconfigure has already cleared.
func (cache *requestLifecycleCache) begin(requestID, fingerprint string, generation uint64) bool {
	requestID = strings.TrimSpace(requestID)
	if cache == nil || requestID == "" || fingerprint == "" {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if generation != cache.generation {
		return false
	}
	cache.active.put(requestID, fingerprint)
	return true
}

func (cache *requestLifecycleCache) contains(requestID string) bool {
	requestID = strings.TrimSpace(requestID)
	if cache == nil || requestID == "" {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	_, ok := cache.active.get(requestID)
	return ok
}

func (cache *requestLifecycleCache) matches(requestID, fingerprint string, generation uint64) bool {
	requestID = strings.TrimSpace(requestID)
	if cache == nil || requestID == "" || fingerprint == "" {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if generation != cache.generation {
		return false
	}
	entry, ok := cache.active.get(requestID)
	return ok && entry.category == fingerprint
}

func (cache *requestLifecycleCache) complete(requestID string) bool {
	requestID = strings.TrimSpace(requestID)
	if cache == nil || requestID == "" {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.active.remove(requestID)
}

func (cache *requestLifecycleCache) clear() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.generation++
	cache.active.clear()
}

func requestInterceptorMethod(method string) bool {
	return method == pluginabi.MethodRequestInterceptBefore || method == pluginabi.MethodRequestInterceptAfter
}

type normalizedHeaderEntry struct {
	name         string
	originalName string
	values       []string
}

func newRequestFingerprintKey() (key [32]byte, available bool) {
	// crypto/rand.Read crashes the process irrecoverably when the operating
	// system random source fails on Go 1.26. Fingerprint caching is only a
	// performance optimization, so read the Linux random device through a
	// fallible interface instead. If it is unavailable, callers disable the
	// cache and safely classify both interceptor phases.
	random, err := os.Open("/dev/urandom")
	if err != nil {
		return key, false
	}
	defer random.Close()
	return requestFingerprintKeyFromReader(random)
}

func requestFingerprintKeyFromReader(reader io.Reader) (key [32]byte, available bool) {
	if reader == nil {
		return key, false
	}
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		clear(key[:])
		return key, false
	}
	return key, true
}

func (p *Plugin) requestSecurityFingerprint(requestID string, request pluginapi.RequestInterceptRequest) string {
	if p == nil || !p.requestFingerprintEnabled {
		return ""
	}
	digest := hmac.New(sha256.New, p.requestFingerprintKey[:])
	writeFingerprintField(digest, []byte("cyber-abuse-guard/request-lifecycle-fingerprint/v1"))
	writeFingerprintField(digest, []byte(requestID))
	writeFingerprintField(digest, []byte(audit.CanonicalSourceFormat(request.SourceFormat)))
	writeFingerprintField(digest, request.Body)

	headers := make([]normalizedHeaderEntry, 0, len(request.Headers))
	for name, values := range request.Headers {
		normalizedName := strings.ToLower(name)
		headers = append(headers, normalizedHeaderEntry{
			name:         normalizedName,
			originalName: name,
			values:       append([]string(nil), values...),
		})
	}
	sort.Slice(headers, func(i, j int) bool {
		if headers[i].name != headers[j].name {
			return headers[i].name < headers[j].name
		}
		// Differently cased duplicate map keys are invalid but representable in
		// http.Header. Use the original spelling only as a deterministic tie
		// breaker; the hashed name remains case-insensitive.
		return headers[i].originalName < headers[j].originalName
	})
	for _, header := range headers {
		writeFingerprintField(digest, []byte(header.name))
		var valueCount [8]byte
		binary.BigEndian.PutUint64(valueCount[:], uint64(len(header.values)))
		_, _ = digest.Write(valueCount[:])
		// Header field-value order can be semantically significant (for example
		// Cookie, Forwarded, and preference headers). Preserve both exact values
		// and their order so an after-auth mutation cannot be hidden by sorting or
		// whitespace normalization.
		for _, value := range header.values {
			writeFingerprintField(digest, []byte(value))
		}
	}
	if request.Stream {
		writeFingerprintField(digest, []byte{1})
	} else {
		writeFingerprintField(digest, []byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeFingerprintField(digest hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write(value)
}

func (p *Plugin) callRequestIntercept(raw []byte, beforeAuth bool) ([]byte, int) {
	policy := p.snapshotModelRouteFailurePolicy()
	var request pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return p.requestInterceptorFailureWithPolicy("invalid_request", policy), 0
	}
	requestID := strings.TrimSpace(request.RequestID)
	if requestID == "" {
		return p.requestInterceptorFailureWithPolicy("missing_request_id", policy), 0
	}
	fingerprint := p.requestSecurityFingerprint(requestID, request)

	var lifecycleGeneration uint64
	if !beforeAuth {
		// A cache hit is a complete inspection callback, not a free-standing map
		// lookup. Keep it inside the runtime read-side barrier so successful
		// reconfiguration cannot swap policy and return while an old-generation
		// after-auth fast path is still deciding to allow. The global lock order is
		// opMu -> requestLifecycle.mu, matching the exclusive clear path.
		p.opMu.RLock()
		lifecycleGeneration = p.requestLifecycle.generationToken()
		if p.requestLifecycle.matches(requestID, fingerprint, lifecycleGeneration) {
			response := okEnvelope(pluginapi.RequestInterceptResponse{})
			p.opMu.RUnlock()
			// CPA v7.2.142 passes the same RequestID to before-auth and after-auth.
			// Classification already ran on this exact security-relevant request
			// representation, so the second callback performs only the bounded input
			// fingerprint and pass-through instead of a duplicate classification,
			// audit, or subject-risk event. If a Host mutates the body, headers, source
			// format, or stream flag, the fingerprint changes and after-auth is
			// classified again.
			return response, 0
		}
		p.opMu.RUnlock()
	} else {
		lifecycleGeneration = p.requestLifecycle.generationToken()
	}

	// CPA v7.2.142 invokes the after-auth interceptor before request
	// translation. ToFormat names the future upstream representation, while
	// Body is still encoded in the original SourceFormat. This matters on the
	// defensive cache-miss path (for example after TTL/capacity eviction): using
	// ToFormat here would select the wrong extraction profile.
	sourceFormat := request.SourceFormat
	requestedModel := request.RequestedModel
	if strings.TrimSpace(requestedModel) == "" {
		requestedModel = request.Model
	}
	routeRequest := pluginapi.ModelRouteRequest{
		SourceFormat:   sourceFormat,
		RequestedModel: requestedModel,
		Stream:         request.Stream,
		Headers:        request.Headers,
		Body:           request.Body,
		Metadata:       request.Metadata,
	}
	result := p.callModelRouteRequest(routeRequest)
	if result.returnCode != 0 {
		return p.requestInterceptorFailureWithPolicy("model_route_failure", policy), 0
	}
	// Record only after a successful classification path. A recovered panic or
	// fail-open operational failure must not make a later after-auth invocation
	// look checked; after-auth remains a bounded retry opportunity in that case.
	// The captured generation also prevents this callback from refilling a cache
	// after a concurrent successful reconfiguration cleared the old policy.
	if !result.failureRecorded {
		p.requestLifecycle.begin(requestID, fingerprint, lifecycleGeneration)
	}
	return p.requestInterceptResponseFromModelRoute(
		result.response,
		result.blockCategory,
		result.policy,
		result.failureRecorded,
	), 0
}

func (p *Plugin) callOversizedRequestIntercept() ([]byte, int) {
	return p.callOversizedRequestInterceptWithRoute(p.routeOversized)
}

func (p *Plugin) callOversizedRequestInterceptWithRoute(route func(*runtimeState) []byte) ([]byte, int) {
	policy := p.snapshotModelRouteFailurePolicy()
	p.opMu.RLock()
	defer p.opMu.RUnlock()
	state := p.runtime.Load()
	if state == nil {
		return p.requestInterceptorFailureWithPolicy("not_initialized", policy), 0
	}
	rawResponse := route(state)
	return p.requestInterceptResponseFromModelRoute(rawResponse, "rpc_body_limit", policy, false), 0
}

func (p *Plugin) callOversizedRequestInterceptAfterAuth() ([]byte, int) {
	policy := p.snapshotModelRouteFailurePolicy()
	p.opMu.RLock()
	defer p.opMu.RUnlock()
	state := p.runtime.Load()
	if state == nil {
		return p.requestInterceptorFailureWithPolicy("not_initialized", policy), 0
	}
	if !state.config.Enabled || state.config.Mode != config.ModeStrict {
		// The oversized boundary does not expose RequestID, so non-strict modes
		// cannot distinguish a newly mutated after-auth request from harmless
		// envelope growth without risking duplicate incomplete events. Their
		// configured incomplete policy is pass-through. Strict must fail closed so
		// an interceptor mutation cannot bypass the before-auth decision.
		return okEnvelope(pluginapi.RequestInterceptResponse{}), 0
	}
	rawResponse := p.routeOversized(state)
	return p.requestInterceptResponseFromModelRoute(rawResponse, "rpc_body_limit", policy, false), 0
}

func (p *Plugin) requestInterceptResponseFromModelRoute(
	rawResponse []byte,
	blockCategory string,
	policy modelRouteFailurePolicy,
	failureRecorded bool,
) []byte {
	var envelope rpcEnvelope
	if err := json.Unmarshal(rawResponse, &envelope); err != nil || !envelope.OK {
		if failureRecorded {
			return p.requestInterceptorResponseWithPolicy(policy)
		}
		return p.requestInterceptorFailureWithPolicy("model_route_failure", policy)
	}
	var route pluginapi.ModelRouteResponse
	if err := json.Unmarshal(envelope.Result, &route); err != nil {
		return p.requestInterceptorFailureWithPolicy("model_route_decode_failure", policy)
	}
	if !route.Handled {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	if route.TargetKind != pluginapi.ModelRouteTargetSelf {
		return p.requestInterceptorFailureWithPolicy("unexpected_route_target", policy)
	}
	if failureRecorded && blockCategory == "" && policy.failClosed {
		blockCategory = "inspection_failure"
	}
	return okEnvelope(blockingRequestInterceptResponse(blockCategory))
}

func (p *Plugin) requestInterceptorFailureWithPolicy(code string, policy modelRouteFailurePolicy) []byte {
	if p != nil {
		p.counters.routerErrors.Add(1)
		p.reportRouterFailure(code)
	}
	return p.requestInterceptorResponseWithPolicy(policy)
}

func (p *Plugin) requestInterceptorResponseWithPolicy(policy modelRouteFailurePolicy) []byte {
	if policy.failClosed {
		return okEnvelope(blockingRequestInterceptResponse("inspection_failure"))
	}
	return okEnvelope(pluginapi.RequestInterceptResponse{})
}

func blockingRequestInterceptResponse(category string) pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{
		Terminate:  true,
		StatusCode: http.StatusForbidden,
		ResponseHeaders: http.Header{
			"Cache-Control":          []string{"no-store"},
			"Content-Type":           []string{"application/json; charset=utf-8"},
			"X-Content-Type-Options": []string{"nosniff"},
		},
		ResponseBody: []byte(blockedResponseMessage(category)),
	}
}

func (p *Plugin) handleRequestComplete(raw []byte) []byte {
	var completion pluginapi.RequestCompletion
	if err := json.Unmarshal(raw, &completion); err != nil {
		p.counters.requestLifecycleErrors.Add(1)
		return errorEnvelope("invalid_request", "invalid request completion", 0, "")
	}
	requestID := strings.TrimSpace(completion.RequestID)
	if requestID == "" {
		p.counters.requestLifecycleErrors.Add(1)
		return errorEnvelope("invalid_request", "request completion ID is required", 0, "")
	}
	// Duplicate or late terminal events are intentionally idempotent. The Host
	// promises exactly-once delivery, while the plugin remains safe if a future
	// Host retries an observational callback.
	p.requestLifecycle.complete(requestID)
	return okEnvelope(struct{}{})
}
