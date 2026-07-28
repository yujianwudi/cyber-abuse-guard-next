package cpalatestcontract

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type schema2RequestLifecycleProbe struct{}

func (schema2RequestLifecycleProbe) InterceptRequestBeforeAuth(
	context.Context,
	pluginapi.RequestInterceptRequest,
) (pluginapi.RequestInterceptResponse, error) {
	return pluginapi.RequestInterceptResponse{}, nil
}

func (schema2RequestLifecycleProbe) InterceptRequestAfterAuth(
	context.Context,
	pluginapi.RequestInterceptRequest,
) (pluginapi.RequestInterceptResponse, error) {
	return pluginapi.RequestInterceptResponse{}, nil
}

func (schema2RequestLifecycleProbe) HandleRequestComplete(
	context.Context,
	pluginapi.RequestCompletion,
) error {
	return nil
}

var (
	_ pluginapi.RequestInterceptor     = schema2RequestLifecycleProbe{}
	_ pluginapi.RequestLifecyclePlugin = schema2RequestLifecycleProbe{}
)

func TestLatestCPASchema2RequestLifecycleCompileContract(t *testing.T) {
	if pluginabi.ABIVersion != 1 {
		t.Fatalf("C ABI version=%d, want 1", pluginabi.ABIVersion)
	}
	if pluginabi.SchemaVersion != 2 {
		t.Fatalf("RPC schema version=%d, want 2", pluginabi.SchemaVersion)
	}
	if pluginabi.MethodRequestInterceptBefore != "request.intercept_before" ||
		pluginabi.MethodRequestInterceptAfter != "request.intercept_after" ||
		pluginabi.MethodRequestComplete != "request.complete" {
		t.Fatalf("schema-v2 method names changed: before=%q after=%q complete=%q",
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
		t.Fatalf("schema-v2 termination response fields unavailable: %#v", response)
	}

	outcomes := []pluginapi.RequestCompletionOutcome{
		pluginapi.RequestCompletionSucceeded,
		pluginapi.RequestCompletionFailed,
		pluginapi.RequestCompletionRejected,
		pluginapi.RequestCompletionCanceled,
	}
	for _, outcome := range outcomes {
		completion := pluginapi.RequestCompletion{RequestID: "schema2-probe", Outcome: outcome}
		if completion.RequestID == "" || completion.Outcome == "" {
			t.Fatalf("schema-v2 completion fields unavailable for outcome %q", outcome)
		}
	}
}
