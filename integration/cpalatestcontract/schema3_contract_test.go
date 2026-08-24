package cpalatestcontract

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type schema3RequestLifecycleProbe struct{}

func (schema3RequestLifecycleProbe) InterceptRequestBeforeAuth(
	context.Context,
	pluginapi.RequestInterceptRequest,
) (pluginapi.RequestInterceptResponse, error) {
	return pluginapi.RequestInterceptResponse{}, nil
}

func (schema3RequestLifecycleProbe) InterceptRequestAfterAuth(
	context.Context,
	pluginapi.RequestInterceptRequest,
) (pluginapi.RequestInterceptResponse, error) {
	return pluginapi.RequestInterceptResponse{}, nil
}

func (schema3RequestLifecycleProbe) HandleRequestComplete(
	context.Context,
	pluginapi.RequestCompletion,
) error {
	return nil
}

var (
	_ pluginapi.RequestInterceptor     = schema3RequestLifecycleProbe{}
	_ pluginapi.RequestLifecyclePlugin = schema3RequestLifecycleProbe{}
)

func TestLatestCPASchema3RequestLifecycleCompileContract(t *testing.T) {
	if pluginabi.ABIVersion != 1 {
		t.Fatalf("C ABI version=%d, want 1", pluginabi.ABIVersion)
	}
	if pluginabi.SchemaVersion != 3 ||
		pluginabi.SchemaVersionStreamChunkOmitRequestBody != 3 {
		t.Fatalf("RPC schema version=%d omit-request-body version=%d, want 3/3",
			pluginabi.SchemaVersion,
			pluginabi.SchemaVersionStreamChunkOmitRequestBody)
	}
	if pluginabi.MethodRequestInterceptBefore != "request.intercept_before" ||
		pluginabi.MethodRequestInterceptAfter != "request.intercept_after" ||
		pluginabi.MethodRequestComplete != "request.complete" {
		t.Fatalf("schema-v3 lifecycle method names changed: before=%q after=%q complete=%q",
			pluginabi.MethodRequestInterceptBefore,
			pluginabi.MethodRequestInterceptAfter,
			pluginabi.MethodRequestComplete)
	}

	response := pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    []byte(`{"error":"blocked"}`),
	}
	if !response.Terminate || response.StatusCode != http.StatusForbidden ||
		response.ResponseHeaders.Get("Content-Type") != "application/json" ||
		len(response.ResponseBody) == 0 {
		t.Fatalf("schema-v3 termination response fields unavailable: %#v", response)
	}

	outcomes := []pluginapi.RequestCompletionOutcome{
		pluginapi.RequestCompletionSucceeded,
		pluginapi.RequestCompletionFailed,
		pluginapi.RequestCompletionRejected,
		pluginapi.RequestCompletionCanceled,
	}
	for _, outcome := range outcomes {
		completion := pluginapi.RequestCompletion{RequestID: "schema3-probe", Outcome: outcome}
		if completion.RequestID == "" || completion.Outcome == "" {
			t.Fatalf("schema-v3 completion fields unavailable for outcome %q", outcome)
		}
	}

	headerInit := pluginapi.StreamChunkInterceptRequest{
		OriginalRequest: []byte(`{"model":"fixture"}`),
		RequestBody:     []byte(`{"model":"fixture"}`),
		ChunkIndex:      pluginapi.StreamChunkHeaderInitIndex,
	}
	if headerInit.ChunkIndex != -1 || len(headerInit.OriginalRequest) == 0 ||
		len(headerInit.RequestBody) == 0 {
		t.Fatalf("schema-v3 header-init request-body contract unavailable: %#v", headerInit)
	}
	payload := pluginapi.StreamChunkInterceptRequest{
		Body:       []byte("data: fixture\n\n"),
		ChunkIndex: 0,
	}
	if payload.ChunkIndex != 0 || len(payload.OriginalRequest) != 0 ||
		len(payload.RequestBody) != 0 || len(payload.Body) == 0 {
		t.Fatalf("schema-v3 payload omission contract unavailable: %#v", payload)
	}
}
