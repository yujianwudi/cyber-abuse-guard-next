package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestStartupPrivacyProofBindsManagementChallengeToResourceRequest(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	countersBefore := p.counters.snapshot()
	challenge := issueStartupPrivacyChallenge(t, p)
	response, body := callStartupPrivacyResource(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   startupPrivacyProofResourcePath,
		Headers: http.Header{
			"Connection":              []string{"close, " + startupPrivacyProofHeader},
			startupPrivacyProofHeader: []string{challenge},
		},
	})
	if response.StatusCode != startupPrivacyProofResponseCode {
		t.Fatalf("startup privacy proof status=%d body=%s", response.StatusCode, body)
	}
	if got := response.Headers.Values(startupPrivacyProofHeader); !reflect.DeepEqual(got, []string{challenge}) {
		t.Fatalf("startup privacy proof response challenge headers=%v", got)
	}
	if response.Headers.Get("Cache-Control") != "no-store" ||
		response.Headers.Get("Content-Type") != "application/json; charset=utf-8" ||
		response.Headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("startup privacy proof response headers=%v", response.Headers)
	}
	var responseBody struct {
		Challenge         string `json:"challenge"`
		InstanceID        string `json:"instance_id"`
		Consumed          bool   `json:"consumed"`
		LocalOnly         bool   `json:"local_only"`
		UpstreamAttempted bool   `json:"upstream_attempted"`
	}
	if err := json.Unmarshal(body, &responseBody); err != nil {
		t.Fatal(err)
	}
	if responseBody.Challenge != challenge || responseBody.InstanceID != p.startupPrivacyInstanceID ||
		!responseBody.Consumed || !responseBody.LocalOnly || responseBody.UpstreamAttempted {
		t.Fatalf("startup privacy proof body=%+v", responseBody)
	}
	assertStartupPrivacyChallengeConsumed(t, p, challenge)
	if got := p.counters.snapshot(); !reflect.DeepEqual(got, countersBefore) {
		t.Fatalf("startup privacy proof changed policy counters: before=%v after=%v", countersBefore, got)
	}
}

func TestStartupPrivacyProofRejectsReplayAfterManagementConfirmation(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	challenge := issueStartupPrivacyChallenge(t, p)
	request := pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   startupPrivacyProofResourcePath,
		Headers: http.Header{
			"Connection":              []string{startupPrivacyProofHeader},
			startupPrivacyProofHeader: []string{challenge},
		},
	}
	first, firstBody := callStartupPrivacyResource(t, p, request)
	if first.StatusCode != startupPrivacyProofResponseCode {
		t.Fatalf("first startup privacy proof status=%d body=%s", first.StatusCode, firstBody)
	}
	assertStartupPrivacyChallengeConsumed(t, p, challenge)

	replay, replayBody := callStartupPrivacyResource(t, p, request)
	if replay.StatusCode != http.StatusNotFound || bodyErrorCode(replayBody) != "not_found" {
		t.Fatalf("consumed startup challenge replay status=%d body=%s", replay.StatusCode, replayBody)
	}
	status, body := startupPrivacyChallengeStatus(t, p, challenge)
	if status != http.StatusNotFound || bodyErrorCode(body) != "challenge_not_found" {
		t.Fatalf("replayed startup privacy challenge status=%d body=%s", status, body)
	}
}

func TestStartupPrivacyProofPrematureStatusKeepsChallengeUsable(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	challenge := issueStartupPrivacyChallenge(t, p)
	status, body := startupPrivacyChallengeStatus(t, p, challenge)
	if status != http.StatusConflict || bodyErrorCode(body) != "challenge_not_consumed" {
		t.Fatalf("premature startup privacy status=%d body=%s", status, body)
	}
	response, responseBody := callStartupPrivacyResource(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   startupPrivacyProofResourcePath,
		Headers: http.Header{
			"Connection":              []string{startupPrivacyProofHeader},
			startupPrivacyProofHeader: []string{challenge},
		},
	})
	if response.StatusCode != startupPrivacyProofResponseCode {
		t.Fatalf("startup challenge was invalidated by premature status: status=%d body=%s",
			response.StatusCode, responseBody)
	}
	assertStartupPrivacyChallengeConsumed(t, p, challenge)
}

func TestStartupPrivacyProofCannotConsumeAnotherPluginInstanceChallenge(t *testing.T) {
	issuer := New()
	consumer := New()
	t.Cleanup(issuer.Shutdown)
	t.Cleanup(consumer.Shutdown)
	configuration := "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
	register(t, issuer, configuration)
	register(t, consumer, configuration)
	if !validStartupPrivacyChallenge(issuer.startupPrivacyInstanceID) ||
		!validStartupPrivacyChallenge(consumer.startupPrivacyInstanceID) ||
		issuer.startupPrivacyInstanceID == consumer.startupPrivacyInstanceID {
		t.Fatalf("startup privacy instance identities are not unique: issuer=%q consumer=%q",
			issuer.startupPrivacyInstanceID, consumer.startupPrivacyInstanceID)
	}
	challenge := issueStartupPrivacyChallenge(t, issuer)
	response, body := callStartupPrivacyResource(t, consumer, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   startupPrivacyProofResourcePath,
		Headers: http.Header{
			"Connection":              []string{startupPrivacyProofHeader},
			startupPrivacyProofHeader: []string{challenge},
		},
	})
	if response.StatusCode != http.StatusNotFound || bodyErrorCode(body) != "not_found" {
		t.Fatalf("different plugin instance consumed challenge: status=%d body=%s", response.StatusCode, body)
	}
	status, statusBody := startupPrivacyChallengeStatus(t, issuer, challenge)
	if status != http.StatusConflict || bodyErrorCode(statusBody) != "challenge_not_consumed" {
		t.Fatalf("issuer reported cross-instance consumption: status=%d body=%s", status, statusBody)
	}
}

func TestStartupPrivacyProofChallengeHasOneConcurrentWinner(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	challenge := issueStartupPrivacyChallenge(t, p)
	request := pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   startupPrivacyProofResourcePath,
		Headers: http.Header{
			"Connection":              []string{startupPrivacyProofHeader},
			startupPrivacyProofHeader: []string{challenge},
		},
	}
	const callers = 32
	var successes atomic.Int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			raw := p.startupPrivacyResourceResponse(request)
			var envelope rpcEnvelope
			if json.Unmarshal(raw, &envelope) != nil || !envelope.OK {
				return
			}
			var response pluginapi.ManagementResponse
			if json.Unmarshal(envelope.Result, &response) == nil && response.StatusCode == startupPrivacyProofResponseCode {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent startup privacy proof successes=%d, want 1", got)
	}
	assertStartupPrivacyChallengeConsumed(t, p, challenge)
}

func TestStartupPrivacyProofResourceRequiresHopByHopOneExactHeader(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	for _, mutate := range []func(*pluginapi.ManagementRequest, string){
		func(request *pluginapi.ManagementRequest, challenge string) {
			request.Headers = http.Header{startupPrivacyProofHeader: []string{challenge}}
		},
		func(request *pluginapi.ManagementRequest, challenge string) {
			request.Headers = http.Header{
				"Connection":              []string{startupPrivacyProofHeader},
				startupPrivacyProofHeader: []string{challenge, challenge},
			}
		},
		func(request *pluginapi.ManagementRequest, challenge string) {
			request.Headers = http.Header{
				"Connection":              []string{startupPrivacyProofHeader + ", " + startupPrivacyProofHeader},
				startupPrivacyProofHeader: []string{challenge},
			}
		},
		func(request *pluginapi.ManagementRequest, challenge string) {
			request.Headers = http.Header{
				"Connection":              []string{startupPrivacyProofHeader},
				startupPrivacyProofHeader: []string{challenge},
			}
			request.Query = url.Values{"unexpected": []string{"1"}}
		},
	} {
		challenge := issueStartupPrivacyChallenge(t, p)
		request := pluginapi.ManagementRequest{Method: http.MethodGet, Path: startupPrivacyProofResourcePath}
		mutate(&request, challenge)
		response, body := callStartupPrivacyResource(t, p, request)
		if response.StatusCode != http.StatusNotFound || bodyErrorCode(body) != "not_found" {
			t.Fatalf("invalid resource proof status=%d body=%s", response.StatusCode, body)
		}
		status, statusBody := startupPrivacyChallengeStatus(t, p, challenge)
		if status != http.StatusConflict || bodyErrorCode(statusBody) != "challenge_not_consumed" {
			t.Fatalf("invalid resource consumed challenge: status=%d body=%s", status, statusBody)
		}
	}
}

func TestStartupPrivacyProofHeaderDoesNotChangeRequestInterceptor(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	challenge := issueStartupPrivacyChallenge(t, p)
	request := pluginapi.RequestInterceptRequest{
		RequestID:      "startup-proof-header-is-resource-only",
		SourceFormat:   "openai",
		RequestedModel: "ordinary-model",
		Headers:        http.Header{startupPrivacyProofHeader: []string{challenge}},
		Body:           []byte(`{"model":"ordinary-model","messages":[]}`),
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := callRequestInterceptor(t, p, pluginabi.MethodRequestInterceptBefore, raw)
	if response.Terminate {
		t.Fatalf("startup proof header changed ordinary request interception: %+v", response)
	}
	resource, body := callStartupPrivacyResource(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   startupPrivacyProofResourcePath,
		Headers: http.Header{
			"Connection":              []string{startupPrivacyProofHeader},
			startupPrivacyProofHeader: []string{challenge},
		},
	})
	if resource.StatusCode != startupPrivacyProofResponseCode {
		t.Fatalf("request interceptor consumed resource challenge: status=%d body=%s", resource.StatusCode, body)
	}
}

func TestStartupPrivacyChallengeManagementValidationAndRandomFailure(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	for name, body := range map[string][]byte{
		"empty":    nil,
		"array":    []byte(`[]`),
		"unknown":  []byte(`{"nonce":"caller-controlled"}`),
		"trailing": []byte(`{} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			response, raw := callManagementResponse(t, p, authenticatedManagementRequest(
				http.MethodPost, managementStartupPrivacyProofPath, body))
			if response.StatusCode != http.StatusBadRequest || bodyErrorCode(raw) != "invalid_request" {
				t.Fatalf("invalid challenge body status=%d body=%s", response.StatusCode, raw)
			}
		})
	}

	p.startupPrivacyChallenges.random = func([]byte) error { return errors.New("injected random failure") }
	response, body := callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementStartupPrivacyProofPath, []byte(`{}`)))
	if response.StatusCode != http.StatusServiceUnavailable || bodyErrorCode(body) != "challenge_unavailable" {
		t.Fatalf("random failure challenge status=%d body=%s", response.StatusCode, body)
	}

	p.startupPrivacyInstanceID = ""
	response, body = callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementStartupPrivacyProofPath, []byte(`{}`)))
	if response.StatusCode != http.StatusServiceUnavailable || bodyErrorCode(body) != "instance_identity_unavailable" {
		t.Fatalf("missing process identity challenge status=%d body=%s", response.StatusCode, body)
	}
	response, body = callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodGet, managementBasePath+"/status", nil))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("missing process identity status=%d body=%s", response.StatusCode, body)
	}
	var status map[string]any
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if status["operational_ready"] != false ||
		!containsReadinessReason(status["readiness_reasons"], "startup_privacy_identity_unavailable") {
		t.Fatalf("missing process identity readiness=%+v", status)
	}
}

func TestStartupPrivacyChallengeExpiresAndReconfigureClearsIt(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	now := time.Unix(1_900_000_000, 0).UTC()
	p.startupPrivacyChallenges.now = func() time.Time { return now }
	expired := issueStartupPrivacyChallenge(t, p)
	now = now.Add(startupPrivacyChallengeTTL)
	status, body := startupPrivacyChallengeStatus(t, p, expired)
	if status != http.StatusNotFound || bodyErrorCode(body) != "challenge_not_found" {
		t.Fatalf("expired startup privacy challenge status=%d body=%s", status, body)
	}

	active := issueStartupPrivacyChallenge(t, p)
	instanceID := p.startupPrivacyInstanceID
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("plugin reconfigure code=%d envelope=%s", code, raw)
	}
	status, body = startupPrivacyChallengeStatus(t, p, active)
	if status != http.StatusNotFound || bodyErrorCode(body) != "challenge_not_found" {
		t.Fatalf("reconfigured startup privacy challenge status=%d body=%s", status, body)
	}
	if p.startupPrivacyInstanceID != instanceID {
		t.Fatalf("reconfigure changed process identity: before=%q after=%q", instanceID, p.startupPrivacyInstanceID)
	}
}

func TestStartupPrivacyChallengeCapacityRecoversAfterTTL(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	now := time.Unix(1_900_000_000, 0).UTC()
	p.startupPrivacyChallenges.now = func() time.Time { return now }
	for range startupPrivacyChallengeLimit {
		issueStartupPrivacyChallenge(t, p)
	}
	response, body := callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementStartupPrivacyProofPath, []byte(`{}`)))
	if response.StatusCode != http.StatusServiceUnavailable || bodyErrorCode(body) != "challenge_unavailable" {
		t.Fatalf("startup challenge capacity status=%d body=%s", response.StatusCode, body)
	}

	now = now.Add(startupPrivacyChallengeTTL)
	recovered := issueStartupPrivacyChallenge(t, p)
	if !validStartupPrivacyChallenge(recovered) || len(p.startupPrivacyChallenges.entries) != 1 {
		t.Fatalf("startup challenge capacity did not recover after TTL: challenge=%q entries=%d",
			recovered, len(p.startupPrivacyChallenges.entries))
	}
}

func TestStartupPrivacyChallengeShutdownClearsIt(t *testing.T) {
	p := New()
	register(t, p, "mode: off\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	challenge := issueStartupPrivacyChallenge(t, p)
	p.Shutdown()
	if known, consumed := p.startupPrivacyChallenges.statusAndDeleteConsumed(challenge); known || consumed {
		t.Fatalf("shutdown retained startup privacy challenge: known=%t consumed=%t", known, consumed)
	}
}

func issueStartupPrivacyChallenge(t testing.TB, p *Plugin) string {
	t.Helper()
	response, body := callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodPost, managementStartupPrivacyProofPath, []byte(`{}`)))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("issue startup privacy challenge status=%d body=%s", response.StatusCode, body)
	}
	var challenge managementStartupPrivacyChallenge
	if err := json.Unmarshal(body, &challenge); err != nil {
		t.Fatal(err)
	}
	if !validStartupPrivacyChallenge(challenge.Challenge) || challenge.ExpiresAtUnix <= 0 {
		t.Fatalf("issued startup privacy challenge=%+v", challenge)
	}
	if challenge.InstanceID != p.startupPrivacyInstanceID || !validStartupPrivacyChallenge(challenge.InstanceID) {
		t.Fatalf("issued startup privacy challenge has invalid process identity=%+v", challenge)
	}
	return challenge.Challenge
}

func startupPrivacyChallengeStatus(t testing.TB, p *Plugin, challenge string) (int, []byte) {
	t.Helper()
	request := authenticatedManagementRequest(http.MethodGet, managementStartupPrivacyProofPath, nil)
	request.Query = url.Values{"challenge": []string{challenge}}
	response, body := callManagementResponse(t, p, request)
	return response.StatusCode, body
}

func callStartupPrivacyResource(t testing.TB, p *Plugin, request pluginapi.ManagementRequest) (pluginapi.ManagementResponse, []byte) {
	t.Helper()
	return callManagementResponse(t, p, request)
}

func assertStartupPrivacyChallengeConsumed(t testing.TB, p *Plugin, challenge string) {
	t.Helper()
	status, body := startupPrivacyChallengeStatus(t, p, challenge)
	if status != http.StatusOK {
		t.Fatalf("startup privacy challenge status=%d body=%s", status, body)
	}
	var proof managementStartupPrivacyProofStatus
	if err := json.Unmarshal(body, &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Challenge != challenge || proof.InstanceID != p.startupPrivacyInstanceID || !proof.Consumed {
		t.Fatalf("startup privacy proof status=%+v", proof)
	}
}
