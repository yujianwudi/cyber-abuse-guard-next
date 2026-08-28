package cpalatestcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	cpaLatestModulePath        = "github.com/router-for-me/CLIProxyAPI/v7"
	cpaLatestPluginHostPackage = cpaLatestModulePath + "/internal/pluginhost"
	cpaLatestResponsesPackage  = cpaLatestModulePath + "/internal/translator/openai/openai/responses"
	cpaLatestResponsesHandler  = cpaLatestModulePath + "/sdk/api/handlers/openai"
	cpaLatestServicePackage    = cpaLatestModulePath + "/sdk/cliproxy"
	cpaLatestSessionPackage    = cpaLatestModulePath + "/sdk/cliproxy/session"
	cpaLatestMultiAgentPackage = cpaLatestModulePath + "/internal/client/codex/optimize-multi-agent-v2"
	cpaLatestUtilityPackage    = cpaLatestModulePath + "/internal/util"
	cpaLatestAntigravityGemini = cpaLatestModulePath + "/internal/translator/antigravity/gemini"
	cpaLatestGeminiTranslator  = cpaLatestModulePath + "/internal/translator/gemini/gemini"
	cpaLatestCachePackage      = cpaLatestModulePath + "/internal/cache"
	cpaLatestExecutorPackage   = cpaLatestModulePath + "/internal/runtime/executor"
	cpaLatestExecutorHelps     = cpaLatestModulePath + "/internal/runtime/executor/helps"
	cpaLatestClientError       = cpaLatestModulePath + "/internal/clienterror"
	cpaLatestAuthPackage       = cpaLatestModulePath + "/sdk/cliproxy/auth"
	cpaLatestTranslatorSDK     = cpaLatestModulePath + "/sdk/translator"
	cpaLatestAPIPackage        = cpaLatestModulePath + "/internal/api"
	cpaLatestCodexLive         = cpaLatestModulePath + "/internal/client/codex/live"
	cpaLatestFixtureSHA256     = "271390c596d31fe5db0022b2364375fa80e49ddc0f59c06da4b5532ab33aab13"

	cpaCompatibilityProfileEnv = "CPA_COMPAT_PROFILE"
	cpaCompatibilityModfileEnv = "CPA_COMPAT_MODFILE"
	cpaCompatibilityCommitEnv  = "CPA_COMPAT_EXPECTED_COMMIT"
	cpaCompatibilityOriginEnv  = "CPA_COMPAT_ORIGIN_FILE"
	cpaPrimaryProfile          = "primary"
	cpaOfficialOriginURL       = "https://github.com/router-for-me/CLIProxyAPI"
)

type cpaCompatibilityProfile struct {
	Name      string
	Version   string
	Commit    string
	ModuleSum string
	GoModSum  string
}

var cpaPinnedProfile = cpaCompatibilityProfile{
	Name:      cpaPrimaryProfile,
	Version:   "v7.2.144",
	Commit:    "d36b776c790a4d58027fd4fb434800fb5334bceb",
	ModuleSum: "h1:ZNLmwkaMZ+4KbR8BqLHUUDdDzWsQKpXZQbLYesh4ttk=",
	GoModSum:  "h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=",
}

var latestCriticalCPAHostTests = []string{
	"TestDecodeEnvelopeResultPreservesPluginHTTPStatus",
	"TestCompleteRequestDoesNotWaitForBlockingPlugin",
	"TestCompleteRequestUsesUncancelledContextAndClonesMetadata",
	"TestHostApplyConfigDispatchesInterceptorRPCMethods",
	"TestHostApplyConfigRegistersInterceptorOnlyPlugin",
	"TestHostApplyConfigSerializesLifecycleCalls",
	"TestInterceptRequestChainsByPriorityAndHeaders",
	"TestInterceptRequestAfterAuthPassesTargetFormat",
	"TestInterceptorsSkipErrorsAndFusePanics",
	"TestRegisterRPCPluginAcceptsModelRouterOnSchema1",
	"TestRegisterRPCPluginRejectsFutureSchemaVersion",
	"TestRegisterRPCPluginSendsHostSchemaVersion",
	"TestRequestInterceptorTerminationStopsChain",
	"TestRPCCapabilitiesAndAdapterIncludeRequestLifecycle",
	"TestRegisterRPCPluginRegistersWebSocketResponseObserver",
	"TestObserveWebSocketResponseEventRPCSanitizesMetadata",
	"TestRPCInterceptorsIncludeHostCallbackID",
	"TestSanitizePluginRequestRemovesNonJSONMetadata",
	"TestStreamChunkRequestBodyPolicyBySchemaVersion",
	"TestObserveWebSocketResponseEventClonesPayloadAndMetadata",
	"TestServeManagementHTMLEscapesJSONResponseStrings",
	"TestHostRouteModelAllowsExplicitExecutorPluginTarget",
	"TestHostRouteModelClonesPluginMetadata",
	"TestHostRouteModelContinuesAfterUnhandled",
	"TestHostRouteModelDefaultsHandledRouterToOwnExecutor",
	"TestHostRouteModelErrorAndPanicDoNotBreakFallback",
	"TestHostRouteModelPropagatesAvailableProviders",
	"TestHostRouteModelRejectsProviderAndExecutorBothSet",
	"TestHostRouteModelRoutesToBuiltinProvider",
	"TestHostRouteModelSkipsExecutorWithoutProviderIdentifier",
	"TestHostRouteModelSkipsExecutorWithUnsupportedFormats",
	"TestHostRouteModelSkipsOAuthOnlyExecutorTargets",
	"TestHostRouteModelSkipsOriginatingPlugin",
	"TestHostRouteModelSkipsUnavailableBuiltinProvider",
	"TestHostRouteModelSkipsUnavailableExecutorTargets",
	"TestHostRouteModelUsesHighestPriorityFirstMatch",
	"TestGuardedPluginClientShutdownContextDetachesBlockedCall",
	"TestHostCanceledBlockedLoadKeepsOneLoaderAndCleanupPerPlugin",
	"TestHostCanceledInitializationDiscardsBlockedClient",
	"TestHostCanceledLoadDiscardsLateClientWithoutReplacingCurrentPlugin",
	"TestHostCanceledRegisterRetainsLoadTokenUntilShutdownReturns",
	"TestHostCancellationUnderMutationLockDoesNotInsertLoadedPlugin",
	"TestHostShutdownAllRetainsBlockedLoadTokenUntilCleanup",
	"TestHostUnloadPluginContextDetachesBlockedCall",
	"TestOwnsExecutorDistinguishesHostAdapters",
	"TestPluginRefreshCompatExecutorDelegatesExecuteAndRefresh",
	"TestPluginRefreshCompatExecutorErrorsWhenRefreshUnavailable",
	"TestPluginRefreshCompatExecutorNoOpForAPIKeyAuth",
	"TestSortRecordsPriorityDescendingAndIDTieBreak",
}

var latestCriticalCPAHandlerTests = []string{
	"TestHandlerRequestInterceptorTerminatesBeforeAuth",
	"TestHandlerRequestInterceptorTerminatesAfterAuth",
	"TestHandlerStreamInterceptorRewritesAndDropsChunks",
	"TestHandlerStreamInterceptorLegacySchemaClonesRequestBodiesOnPayloadChunks",
	"TestHandlerStreamInterceptorInitializesHeadersBeforeReturn",
	"TestHandlerStreamInterceptorInitializesHeadersWithoutPayload",
}

var latestCriticalCPAServiceTests = []string{
	"TestRegisterExecutorForAuth_PluginAuthProviderWrapsOpenAICompatRefresh",
	"TestRegisterExecutorForAuth_OpenAICompatWithoutPluginAuthProviderStaysBare",
	"TestRegisterExecutorForAuth_OpenAICompatInfoPathAlsoWrapsPluginRefresh",
	"TestUnregisterOpenAICompatExecutorRemovesPluginRefreshWrapper",
}

type latestResolvedCPAModule struct {
	Path     string
	Version  string
	Dir      string
	Sum      string
	GoModSum string
	Replace  *latestResolvedCPAModule
}

type latestDownloadedCPAModule struct {
	Path     string
	Version  string
	Sum      string
	GoModSum string
	Error    string
	Origin   *latestCPAModuleOrigin
}

type latestCPAModuleOrigin struct {
	VCS  string
	URL  string
	Hash string
	Ref  string
}

// Compile-time binding proves that the pinned public plugin API, including the
// additive UsageRecord.Generate field required by both reviewed CPA contracts is available.
// The Guard does not register UsagePlugin; this is an API compatibility probe.
var _ = pluginapi.UsageRecord{Generate: true}

func TestLatestCPAOfficialHostRoutingSourceContract(t *testing.T) {
	goBinary, moduleArguments, _ := prepareLatestCPAModule(t)

	listed := runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", cpaLatestPluginHostPackage,
	)
	listedTests := make(map[string]struct{})
	for _, line := range strings.Split(listed, "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, "Test") && !strings.ContainsAny(name, " \t") {
			listedTests[name] = struct{}{}
		}
	}
	for _, name := range latestCriticalCPAHostTests {
		if _, ok := listedTests[name]; !ok {
			t.Fatalf("latest CPA host package no longer lists required test %q", name)
		}
	}
	handlerTests := runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", cpaLatestHandlersPackage,
	)
	for _, name := range latestCriticalCPAHandlerTests {
		if !linePresent(handlerTests, name) {
			t.Fatalf("latest CPA handler package no longer lists required test %q", name)
		}
	}
	serviceTests := runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", cpaLatestServicePackage,
	)
	for _, name := range latestCriticalCPAServiceTests {
		if !linePresent(serviceTests, name) {
			t.Fatalf("latest CPA service package no longer lists required test %q", name)
		}
	}

	// Execute the complete upstream Host suite for the current platform. The
	// required-name check above keeps the contract explicit, while running the
	// whole package prevents newly added lifecycle, cancellation, cleanup,
	// executor-ownership, or routing regressions from silently falling outside
	// a hand-maintained allowlist.
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		cpaLatestPluginHostPackage,
	)
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", "^("+strings.Join(latestCriticalCPAServiceTests, "|")+")$", cpaLatestServicePackage,
	)
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", "^("+strings.Join(latestCriticalCPAHandlerTests, "|")+")$", cpaLatestHandlersPackage,
	)
}

func TestLatestCPAResponsesAdditionalToolsSourceContract(t *testing.T) {
	goBinary, moduleArguments, module := prepareLatestCPAModule(t)
	const translatorTest = "TestConvertOpenAIResponsesRequestToOpenAIChatCompletions_FlattensNamespaceCustomTools"

	listed := runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^"+translatorTest+"$", cpaLatestResponsesPackage,
	)
	if !linePresent(listed, translatorTest) {
		t.Fatalf("latest CPA Responses translator no longer lists required test %q", translatorTest)
	}
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", "^"+translatorTest+"$", cpaLatestResponsesPackage,
	)

	handlerTests := []string{
		"TestNormalizeResponsesWebsocketRequestReplacesCodexLocalCompactionTranscript",
		"TestNormalizeResponsesWebsocketRequestWithPreviousResponseIDIncremental",
		"TestNormalizeResponsesWebsocketRequestInjectsPreviousResponseIDForIncremental",
		"TestCodexLocalCompactionSummaryAdditionalToolsConstraints",
		"TestPrepareCodexMultiAgentV2ToolsAtResponsesBoundary",
		"TestResponsesPreparesCodexMultiAgentV2ToolsForHTTPAndSSE",
		"TestResponsesWebsocketPreparesCodexMultiAgentV2Tools",
		"TestPrepareCodexMultiAgentV2ToolsAtResponsesBoundarySkipsOtherClients",
	}
	for _, upstreamTest := range handlerTests {
		listed = runLatestGoCommand(t, goBinary,
			"test", moduleArguments[0], moduleArguments[1], "-list", "^"+upstreamTest+"$", cpaLatestResponsesHandler,
		)
		if !linePresent(listed, upstreamTest) {
			t.Fatalf("latest CPA Responses handler no longer lists required test %q", upstreamTest)
		}
	}
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", "^("+strings.Join(handlerTests, "|")+")$", cpaLatestResponsesHandler,
	)

	sourcePath := filepath.Join(module.Dir, "internal", "translator", "openai", "openai", "responses", "openai_openai-responses_request.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read latest CPA Responses translator source: %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`for _, chatTool := range mergeResponsesRequestChatTools(root)`),
		[]byte(`chatCompletionsTools = append(chatCompletionsTools, gjson.ParseBytes(chatTool).Value())`),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("latest CPA Responses translator lost additional_tools contract marker %q", required)
		}
	}
	toolsSourcePath := filepath.Join(module.Dir, "internal", "translator", "openai", "openai", "responses", "openai_openai-responses_tools.go")
	toolsSource, err := os.ReadFile(toolsSourcePath)
	if err != nil {
		t.Fatalf("read latest CPA Responses tool-merge source: %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`func walkResponsesToolDeclarations(`),
		[]byte(`if item.Get("type").String() == "additional_tools"`),
		[]byte(`func mergeResponsesRequestChatTools(`),
	} {
		if !bytes.Contains(toolsSource, required) {
			t.Fatalf("latest CPA Responses tool-merge source lost contract marker %q", required)
		}
	}

	// CPA v7.2.144 keeps request normalization split out of the websocket transport
	// file. Pin the semantic implementation file while the upstream behavior
	// tests above continue to guard the public contract.
	handlerSourcePath := filepath.Join(module.Dir, "sdk", "api", "handlers", "openai", "openai_responses_websocket_requests.go")
	handlerSource, err := os.ReadFile(handlerSourcePath)
	if err != nil {
		t.Fatalf("read latest CPA Responses handler source: %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`if itemType == "additional_tools"`),
		[]byte(`strings.TrimSpace(item.Get("role").String()) != "developer"`),
		[]byte(`!tools.IsArray()`),
	} {
		if !bytes.Contains(handlerSource, required) {
			t.Fatalf("latest CPA Responses handler lost Responses Lite additional_tools marker %q", required)
		}
	}
}

func TestLatestCPANoCopyAndResponsesFailureContract(t *testing.T) {
	goBinary, moduleArguments, module := prepareLatestCPAModule(t)
	testGroups := []struct {
		packagePath string
		tests       []string
	}{
		{
			packagePath: cpaLatestUtilityPackage,
			tests: []string{
				"TestNoInPlaceSJSONWrites",
				"TestInPlaceByteWritesAreReviewed",
				"TestGetGJSONBytesNoCopy",
				"TestParseGJSONBytesNoCopyReferencesInput",
			},
		},
		{
			packagePath: cpaLatestAntigravityGemini,
			tests: []string{
				"TestFixCLIToolResponseReusesHistoryWithoutFunctionResponses",
				"TestConvertGeminiRequestToAntigravityBoundsLargePayloadCopies",
			},
		},
		{
			packagePath: cpaLatestGeminiTranslator,
			tests: []string{
				"TestConvertGeminiRequestToGeminiReusesLargeNormalizedPayload",
			},
		},
		{
			packagePath: cpaLatestHandlersPackage,
			tests: []string{
				"TestBuildOpenAIResponsesStreamFailedChunkPreservesNestedError",
			},
		},
		{
			packagePath: cpaLatestResponsesHandler,
			tests: []string{
				"TestForwardResponsesStreamUsesResponseFailedForCodex",
			},
		},
		{
			packagePath: cpaLatestMultiAgentPackage,
			tests: []string{
				"TestIsCodexMultiAgentClient",
				"TestPrepareCodexMultiAgentV2ToolsOnlyPreparesToolDefinitions",
			},
		},
		{
			packagePath: cpaLatestSessionPackage,
			tests: []string{
				"TestEnrichCarriesRequestPayloadIntoSelectionOptions",
			},
		},
		{
			packagePath: cpaLatestCachePackage,
			tests: []string{
				"TestClaudeThinkingReplayAppendsAssistantTurns",
				"TestClaudeThinkingReplayClearDoesNotClearKimiState",
			},
		},
		{
			packagePath: cpaLatestExecutorPackage,
			tests: []string{
				"TestClaudeThinkingReplayEnabledRequiresCompatClaudeAPIKey",
				"TestClaudeExecutorCompatThinkingReplayRestoresOmittedBlock",
				"TestClaudeExecutorCompatThinkingReplayRestoresOmittedBlockInStream",
				"TestClaudeExecutorCompatThinkingReplayClearsAfterUpstreamBadRequest",
				"TestClaudeExecutorCompatThinkingReplayRestoresMultipleOmittedBlocks",
			},
		},
	}

	for _, group := range testGroups {
		listed := runLatestGoCommand(t, goBinary,
			"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", group.packagePath,
		)
		for _, name := range group.tests {
			if !linePresent(listed, name) {
				t.Fatalf("latest CPA package %s no longer lists required test %q", group.packagePath, name)
			}
		}
		runLatestGoCommand(t, goBinary,
			"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
			"-run", "^("+strings.Join(group.tests, "|")+")$", group.packagePath,
		)
	}

	// CPA also recognizes official Codex clients from Originator when a proxy or
	// SDK supplies a generic User-Agent. Upstream's behavior test currently
	// exercises only User-Agent, so pin the alternate public request branch and
	// cover it end-to-end in integration/host_integration_test.go.
	handlerSourcePath := filepath.Join(
		module.Dir, "sdk", "api", "handlers", "openai", "openai_responses_handlers.go",
	)
	handlerSource, err := os.ReadFile(handlerSourcePath)
	if err != nil {
		t.Fatalf("read latest CPA Responses stream handler source: %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`c.GetHeader("Originator")`),
		[]byte(`case "codex desktop", "codex-tui", "codex_cli_rs":`),
		[]byte(`strings.HasPrefix(originator, "codex desktop/")`),
		[]byte(`strings.HasPrefix(originator, "codex-tui/")`),
		[]byte(`strings.HasPrefix(originator, "codex_cli_rs/")`),
	} {
		if !bytes.Contains(handlerSource, required) {
			t.Fatalf("latest CPA Responses handler lost Originator Codex marker %q", required)
		}
	}
}

func TestLatestCPAPluginHookNoCopyAuthAndRealtimeBoundaryContract(t *testing.T) {
	goBinary, moduleArguments, module := prepareLatestCPAModule(t)
	assertRealtimeSourceBoundary(t, module.Dir)
	testGroups := []struct {
		packagePath string
		tests       []string
	}{
		{
			packagePath: cpaLatestTranslatorSDK,
			tests:       []string{"TestHasPluginHooks"},
		},
		{
			packagePath: cpaLatestExecutorHelps,
			tests:       []string{"TestTranslateRequestPairPreservesPluginHookInvocations"},
		},
		{
			packagePath: cpaLatestExecutorPackage,
			tests: []string{
				"TestAntigravityReplayRequestIndexRandomizedDifferential",
				"TestApplyAntigravityReasoningReplayItemsRebuildsIndexAfterMutation",
				"TestAntigravityReplayMergeRandomizedDifferential",
				"TestAntigravityReplayNonArrayPartsFailsClosed",
				"TestAntigravityConcurrentRequestsReusePooledConnections",
				"TestAntigravityTransportScopeNeverLeaksToken",
			},
		},
		{
			packagePath: cpaLatestClientError,
			tests:       []string{"TestIsRequestFault"},
		},
		{
			packagePath: cpaLatestAuthPackage,
			tests: []string{
				"TestManager_DeepSeekInsufficientBalanceRotatesCredentialAndRebindsSession",
				"TestManager_DeepSeekCredentialFailuresRotateCredential",
			},
		},
		{
			packagePath: cpaLatestAPIPackage,
			tests:       []string{"TestRealtimeStandardRoutesAndClientSecretAuth"},
		},
		{
			packagePath: cpaLatestCodexLive,
			tests: []string{
				"TestCreateClientSecretMapsStandardRealtimeModel",
				"TestHandleHangupForwardsPinnedOAuthCall",
				"TestHandleDirectWebsocketRelaysStandardRealtimeFrames",
			},
		},
	}

	for _, group := range testGroups {
		listed := runLatestGoCommand(t, goBinary,
			"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", group.packagePath,
		)
		for _, name := range group.tests {
			if !linePresent(listed, name) {
				t.Fatalf("latest CPA package %s no longer lists required test %q", group.packagePath, name)
			}
		}
		runLatestGoCommand(t, goBinary,
			"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
			"-run", "^("+strings.Join(group.tests, "|")+")$", group.packagePath,
		)
	}
}

// assertRealtimeSourceBoundary binds the negative-coverage claim to the exact
// upstream handler source, rather than relying only on an unauthenticated HTTP
// probe. Realtime is intentionally registered outside the protected v1 group
// and its handler package has no CAG interceptor, model-router, or request
// lifecycle entry point. If CPA later moves this route into the plugin-aware
// execution path, this contract must be updated deliberately.
func assertRealtimeSourceBoundary(t *testing.T, moduleDir string) {
	t.Helper()
	read := func(relative string) []byte {
		data, err := os.ReadFile(filepath.Join(moduleDir, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read CPA v7.2.144 realtime source %s: %v", relative, err)
		}
		return data
	}

	routes := read("internal/api/server_routes.go")
	for _, marker := range [][]byte{
		// Keep one source marker for every v7.2.144 /v1/realtime* registration.
		// These routes intentionally do not inherit the protected v1 group.
		[]byte(`s.engine.GET("/v1/realtime", realtimeAuth, s.codexLiveHandler.HandleRealtimeWebsocket)`),
		[]byte(`s.engine.POST("/v1/realtime", realtimeAuth, s.codexLiveHandler.Handle)`),
		[]byte(`s.engine.POST("/v1/realtime/calls", realtimeAuth, s.codexLiveHandler.Handle)`),
		[]byte(`s.engine.GET("/v1/realtime/calls/:call_id", realtimeAuth, s.codexLiveHandler.HandleSideband)`),
		[]byte(`s.engine.POST("/v1/realtime/client_secrets", standardAuth, s.codexLiveHandler.CreateClientSecret)`),
		[]byte(`s.engine.POST("/v1/realtime/sessions", standardAuth, s.codexLiveHandler.CreateLegacySession)`),
		[]byte(`s.engine.POST("/v1/realtime/transcription_sessions", standardAuth, s.codexLiveHandler.HandleTranscriptionSession)`),
		[]byte(`s.engine.GET("/v1/realtime/translations", realtimeAuth, s.codexLiveHandler.HandleTranslation)`),
		[]byte(`s.engine.POST("/v1/realtime/translations", realtimeAuth, s.codexLiveHandler.HandleTranslation)`),
		[]byte(`s.engine.POST("/v1/realtime/translations/client_secrets", standardAuth, s.codexLiveHandler.HandleTranslation)`),
		[]byte(`s.engine.POST("/v1/realtime/calls/:call_id/hangup", standardAuth, s.codexLiveHandler.HandleHangup)`),
		[]byte(`s.engine.POST("/v1/realtime/calls/:call_id/accept", standardAuth, s.codexLiveHandler.HandleSIPControl)`),
		[]byte(`s.engine.POST("/v1/realtime/calls/:call_id/reject", standardAuth, s.codexLiveHandler.HandleSIPControl)`),
		[]byte(`s.engine.POST("/v1/realtime/calls/:call_id/refer", standardAuth, s.codexLiveHandler.HandleSIPControl)`),
	} {
		if count := bytes.Count(routes, marker); count != 1 {
			t.Fatalf("CPA v7.2.144 realtime route source marker %q occurs %d times, want exactly once", marker, count)
		}
	}
	for _, marker := range [][]byte{
		[]byte(`realtimeAuth := realtimeAuthMiddleware(s.accessManager, s.codexLiveHandler)`),
		[]byte(`standardAuth := realtimeStandardAuthMiddleware(s.accessManager)`),
	} {
		if count := bytes.Count(routes, marker); count != 1 {
			t.Fatalf("CPA v7.2.144 realtime auth source marker %q occurs %d times, want exactly once", marker, count)
		}
	}

	// The realtime route registrations must remain outside the v1 group that
	// installs AuthMiddleware and the normal request execution handlers.
	v1Start := bytes.Index(routes, []byte(`v1 := s.engine.Group("/v1")`))
	realtimeStart := bytes.Index(routes, []byte(`realtimeAuth := realtimeAuthMiddleware`))
	if v1Start < 0 || realtimeStart < 0 || realtimeStart <= v1Start {
		t.Fatal("CPA v7.2.144 realtime routes are not visibly registered after the protected v1 group")
	}

	for _, relative := range []string{
		"internal/client/codex/live/live.go",
		"internal/client/codex/live/websocket.go",
		"internal/client/codex/live/sideband.go",
		"internal/client/codex/live/capabilities.go",
		"internal/client/codex/live/client_secret.go",
	} {
		source := read(relative)
		for _, forbidden := range [][]byte{
			// Negative CAG/plugin-hook markers. Realtime handlers and their
			// capability stubs must stay outside the CAG execution lifecycle.
			[]byte("RequestInterceptor"),
			[]byte("ResponseInterceptor"),
			[]byte("StreamChunkInterceptor"),
			[]byte("InterceptRequest"),
			[]byte("InterceptResponse"),
			[]byte("InterceptStream"),
			[]byte("PluginHooks"),
			[]byte("SetPluginHooks"),
			[]byte("RouteModel("),
			[]byte("newRequestLifecycleTracker"),
			[]byte("applyRequestInterceptors"),
			[]byte("cyber-abuse-guard"),
			[]byte("CAG"),
		} {
			if bytes.Contains(source, forbidden) {
				t.Fatalf("CPA v7.2.144 realtime handler %s unexpectedly contains plugin-aware execution marker %q", relative, forbidden)
			}
		}
	}
}

func TestLatestCPAHostFailOpenFixtureContract(t *testing.T) {
	goBinary, _, module := prepareLatestCPAModule(t)
	profile := selectedCPACompatibilityProfile(t)
	fixturePath, errFixtureAbs := filepath.Abs(filepath.Join("..", "pluginstorecontract", "testfixtures", "host_failopen_overlay_test.go.txt"))
	if errFixtureAbs != nil {
		t.Fatalf("resolve shared Host fixture path: %v", errFixtureAbs)
	}
	fixtureData, errReadFixture := os.ReadFile(fixturePath)
	if errReadFixture != nil {
		t.Fatalf("read shared Host fixture: %v", errReadFixture)
	}
	// Git stores the fixture with LF, while a Windows worktree may materialize
	// it as CRLF. Pin the canonical Git content instead of platform-specific
	// checkout bytes, and write the same canonical source into the module copy.
	fixtureData = bytes.ReplaceAll(fixtureData, []byte("\r\n"), []byte("\n"))
	if bytes.ContainsRune(fixtureData, '\r') {
		t.Fatal("shared Host fixture contains a non-canonical carriage return")
	}
	fixtureHash := sha256.Sum256(fixtureData)
	if actual := hex.EncodeToString(fixtureHash[:]); actual != cpaLatestFixtureSHA256 {
		t.Fatalf("shared Host fixture sha256=%s, want %s", actual, cpaLatestFixtureSHA256)
	}

	moduleCopy := filepath.Join(t.TempDir(), "cpa-"+profile.Version)
	if errCopyModule := os.CopyFS(moduleCopy, os.DirFS(module.Dir)); errCopyModule != nil {
		t.Fatalf("copy latest CPA module for Host fixture: %v", errCopyModule)
	}
	targetPath := filepath.Join(moduleCopy, "internal", "pluginhost", "cyber_abuse_guard_host_fixture_test.go")
	if errWriteFixture := os.WriteFile(targetPath, fixtureData, 0o600); errWriteFixture != nil {
		t.Fatalf("write ephemeral Host fixture: %v", errWriteFixture)
	}
	const fixtureTestName = "TestCyberAbuseGuardHostFailOpenFixtureMatrix"
	listed := runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-list", "^"+fixtureTestName+"$", "./internal/pluginhost",
	)
	if !linePresent(listed, fixtureTestName) {
		t.Fatalf("ephemeral latest CPA Host overlay does not list required test %q", fixtureTestName)
	}
	runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-count=1", "-v",
		"-run", "^"+fixtureTestName+"$", "./internal/pluginhost",
	)
}

func prepareLatestCPAModule(t *testing.T) (string, []string, latestResolvedCPAModule) {
	t.Helper()
	profile := selectedCPACompatibilityProfile(t)
	goBinary, errLookPath := exec.LookPath("go")
	if errLookPath != nil {
		t.Fatalf("locate go tool: %v", errLookPath)
	}
	sourceModfile := strings.TrimSpace(os.Getenv(cpaCompatibilityModfileEnv))
	if sourceModfile == "" {
		sourceModfile = "go.mod"
	}
	if !filepath.IsAbs(sourceModfile) {
		absoluteModfile, errAbs := filepath.Abs(sourceModfile)
		if errAbs != nil {
			t.Fatalf("resolve CPA compatibility modfile: %v", errAbs)
		}
		sourceModfile = absoluteModfile
	}
	if filepath.Ext(sourceModfile) != ".mod" {
		t.Fatalf("CPA compatibility modfile must end in .mod: %s", sourceModfile)
	}
	moduleInfo, errModuleInfo := os.Lstat(sourceModfile)
	if errModuleInfo != nil {
		t.Fatalf("stat CPA compatibility modfile: %v", errModuleInfo)
	}
	if !moduleInfo.Mode().IsRegular() || moduleInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("CPA compatibility modfile must be a regular non-symlink file: %s", sourceModfile)
	}
	sourceSumfile := strings.TrimSuffix(sourceModfile, ".mod") + ".sum"
	sumInfo, errSumInfo := os.Lstat(sourceSumfile)
	if errSumInfo != nil {
		t.Fatalf("stat CPA compatibility sumfile: %v", errSumInfo)
	}
	if !sumInfo.Mode().IsRegular() || sumInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("CPA compatibility sumfile must be a regular non-symlink file: %s", sourceSumfile)
	}
	moduleData, errReadModule := os.ReadFile(sourceModfile)
	if errReadModule != nil {
		t.Fatalf("read CPA compatibility module: %v", errReadModule)
	}
	moduleSumData, errReadModuleSum := os.ReadFile(sourceSumfile)
	if errReadModuleSum != nil {
		t.Fatalf("read CPA compatibility checksums: %v", errReadModuleSum)
	}
	temporaryModule := filepath.Join(t.TempDir(), profile.Name+"-host-contract.mod")
	if errWriteModule := os.WriteFile(temporaryModule, moduleData, 0o600); errWriteModule != nil {
		t.Fatalf("write temporary latest module: %v", errWriteModule)
	}
	temporaryModuleSum := strings.TrimSuffix(temporaryModule, ".mod") + ".sum"
	if errWriteModuleSum := os.WriteFile(temporaryModuleSum, moduleSumData, 0o600); errWriteModuleSum != nil {
		t.Fatalf("write temporary latest checksums: %v", errWriteModuleSum)
	}
	// Official upstream package tests pull their own transitive test graph. Let
	// Go add those checksum-verified entries only to the temporary mod/sum pair;
	// the checked-in latest-contract module remains minimal and tidy-clean.
	moduleArguments := []string{"-mod=mod", "-modfile=" + temporaryModule}
	downloadJSON := runLatestGoJSONCommand(t, goBinary,
		"mod", "download", "-json", cpaLatestModulePath+"@"+profile.Version,
	)
	var download latestDownloadedCPAModule
	if errUnmarshal := json.Unmarshal([]byte(downloadJSON), &download); errUnmarshal != nil {
		t.Fatalf("decode CPA module download metadata: %v", errUnmarshal)
	}
	if strings.TrimSpace(download.Error) != "" {
		t.Fatalf("download CPA module metadata: %s", download.Error)
	}
	if download.Path != cpaLatestModulePath || download.Version != profile.Version {
		t.Fatalf("downloaded CPA module = %s@%s, want %s@%s",
			download.Path, download.Version, cpaLatestModulePath, profile.Version)
	}
	if download.Sum != profile.ModuleSum || download.GoModSum != profile.GoModSum {
		t.Fatalf("downloaded CPA checksums = module %q go.mod %q, want module %q go.mod %q",
			download.Sum, download.GoModSum, profile.ModuleSum, profile.GoModSum)
	}
	if download.Origin == nil {
		originFile := strings.TrimSpace(os.Getenv(cpaCompatibilityOriginEnv))
		if originFile != "" {
			originData, errReadOrigin := os.ReadFile(originFile)
			if errReadOrigin != nil {
				t.Fatalf("read isolated CPA Origin metadata: %v", errReadOrigin)
			}
			var isolated latestDownloadedCPAModule
			if errUnmarshal := json.Unmarshal(originData, &isolated); errUnmarshal != nil {
				t.Fatalf("decode isolated CPA Origin metadata: %v", errUnmarshal)
			}
			if isolated.Path != download.Path || isolated.Version != download.Version ||
				isolated.Sum != download.Sum || isolated.GoModSum != download.GoModSum {
				t.Fatalf("isolated CPA Origin identity differs from active module download")
			}
			download.Origin = isolated.Origin
		}
	}
	if download.Origin == nil {
		t.Fatal("downloaded CPA module metadata omits Origin")
	}
	wantOriginRef := "refs/tags/" + profile.Version
	if download.Origin.VCS != "git" || download.Origin.URL != cpaOfficialOriginURL ||
		download.Origin.Hash != profile.Commit || download.Origin.Ref != wantOriginRef {
		t.Fatalf("downloaded CPA Origin = vcs=%q url=%q hash=%q ref=%q, want git %q %q %q",
			download.Origin.VCS, download.Origin.URL, download.Origin.Hash, download.Origin.Ref,
			cpaOfficialOriginURL, profile.Commit, wantOriginRef)
	}

	moduleJSON := runLatestGoJSONCommand(t, goBinary,
		"list", moduleArguments[0], moduleArguments[1], "-m", "-json", cpaLatestModulePath,
	)
	var module latestResolvedCPAModule
	if errUnmarshal := json.Unmarshal([]byte(moduleJSON), &module); errUnmarshal != nil {
		t.Fatalf("decode latest CPA module metadata: %v", errUnmarshal)
	}
	if module.Replace != nil {
		t.Fatal("latest CPA module unexpectedly uses a replacement")
	}
	if module.Path != cpaLatestModulePath || module.Version != profile.Version || strings.TrimSpace(module.Dir) == "" {
		t.Fatalf("resolved latest CPA module = %s@%s dir=%q, want %s@%s with source dir",
			module.Path, module.Version, module.Dir, cpaLatestModulePath, profile.Version)
	}
	if module.Sum != profile.ModuleSum || module.GoModSum != profile.GoModSum {
		t.Fatalf("resolved latest CPA checksums = module %q go.mod %q, want module %q go.mod %q",
			module.Sum, module.GoModSum, profile.ModuleSum, profile.GoModSum)
	}
	t.Logf("CPA pinned compatibility source contract: profile=%s %s@%s commit=%s sum=%s go_mod_sum=%s",
		profile.Name, module.Path, module.Version, profile.Commit, module.Sum, module.GoModSum)
	return goBinary, moduleArguments, module
}

func selectedCPACompatibilityProfile(t *testing.T) cpaCompatibilityProfile {
	t.Helper()
	name := strings.TrimSpace(os.Getenv(cpaCompatibilityProfileEnv))
	if name == "" {
		name = cpaPrimaryProfile
	}
	if name != cpaPrimaryProfile {
		t.Fatalf("unsupported %s=%q; the only allowed value is %q",
			cpaCompatibilityProfileEnv, name, cpaPrimaryProfile)
	}
	profile := cpaPinnedProfile
	if expectedCommit := strings.TrimSpace(os.Getenv(cpaCompatibilityCommitEnv)); expectedCommit != "" && expectedCommit != profile.Commit {
		t.Fatalf("%s=%q does not match pinned %s commit %s",
			cpaCompatibilityCommitEnv, expectedCommit, profile.Name, profile.Commit)
	}
	return profile
}

func linePresent(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func runLatestGoCommand(t *testing.T, goBinary string, arguments ...string) string {
	t.Helper()
	return runLatestGoCommandInDir(t, "", goBinary, arguments...)
}

func runLatestGoJSONCommand(t *testing.T, goBinary string, arguments ...string) string {
	t.Helper()
	command := exec.Command(goBinary, arguments...)
	command.Env = append(os.Environ(), "GOWORK=off")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if errRun := command.Run(); errRun != nil {
		t.Fatalf("%s %s failed: %v\nstdout:\n%s\nstderr:\n%s",
			goBinary, strings.Join(arguments, " "), errRun, stdout.String(), stderr.String())
	}
	if stderr.Len() > 0 {
		t.Logf("%s", stderr.String())
	}
	return stdout.String()
}

func runLatestGoCommandInDir(t *testing.T, directory, goBinary string, arguments ...string) string {
	t.Helper()
	command := exec.Command(goBinary, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOWORK=off")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if errRun := command.Run(); errRun != nil {
		t.Fatalf("%s %s failed: %v\n%s", goBinary, strings.Join(arguments, " "), errRun, output.String())
	}
	t.Logf("%s", output.String())
	return output.String()
}
