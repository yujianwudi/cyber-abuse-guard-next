package pluginstorecontract

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	cpaModulePath        = "github.com/router-for-me/CLIProxyAPI/v7"
	cpaPinnedVersion     = "v7.2.137"
	cpaPinnedCommit      = "85d2faddd17e6f4f8675a84ee28b131f702e8eaa"
	cpaPinnedModuleSum   = "h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w="
	cpaPinnedGoModSum    = "h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ="
	cpaPluginHostPackage = cpaModulePath + "/internal/pluginhost"
	cpaHandlersPackage   = cpaModulePath + "/sdk/api/handlers"

	cpaCompatibilityOriginEnv = "CPA_COMPAT_ORIGIN_FILE"
	cpaOfficialOriginURL      = "https://github.com/router-for-me/CLIProxyAPI"
)

var criticalCPAHostTests = []string{
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
	"TestRPCInterceptorsIncludeHostCallbackID",
	"TestSanitizePluginRequestRemovesNonJSONMetadata",
	"TestStreamChunkRequestBodyPolicyBySchemaVersion",
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

var criticalCPAHandlerTests = []string{
	"TestHandlerRequestInterceptorTerminatesBeforeAuth",
	"TestHandlerRequestInterceptorTerminatesAfterAuth",
	"TestHandlerStreamInterceptorRewritesAndDropsChunks",
	"TestHandlerStreamInterceptorLegacySchemaClonesRequestBodiesOnPayloadChunks",
	"TestHandlerStreamInterceptorInitializesHeadersBeforeReturn",
	"TestHandlerStreamInterceptorInitializesHeadersWithoutPayload",
}

type resolvedCPAModule struct {
	Path     string
	Version  string
	Dir      string
	Sum      string
	GoModSum string
	Replace  *resolvedCPAModule
	Origin   *resolvedCPAOrigin
}

type resolvedCPAOrigin struct {
	VCS  string
	URL  string
	Hash string
	Ref  string
}

// TestOfficialCPAHostRoutingSourceContract runs the complete Host test suite
// shipped by the pinned CPA module. It deliberately tests the official source
// package instead of copying the host's priority, fail-open, lifecycle, fuse,
// target validation, or executor-readiness implementation into this repository.
func TestOfficialCPAHostRoutingSourceContract(t *testing.T) {
	goBinary, moduleArguments, _ := preparePinnedCPAModule(t)

	listed := runGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", cpaPluginHostPackage,
	)
	listedTests := make(map[string]struct{})
	for _, line := range strings.Split(listed, "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, "Test") && !strings.ContainsAny(name, " \t") {
			listedTests[name] = struct{}{}
		}
	}
	for _, name := range criticalCPAHostTests {
		if _, ok := listedTests[name]; !ok {
			t.Fatalf("pinned CPA host package no longer lists required test %q", name)
		}
	}
	handlerTests := runGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", cpaHandlersPackage,
	)
	for _, name := range criticalCPAHandlerTests {
		if !linePresent(handlerTests, name) {
			t.Fatalf("pinned CPA handler package no longer lists required test %q", name)
		}
	}

	// Execute the complete upstream Host suite for the current platform. The
	// required-name check above keeps the contract explicit, while running the
	// whole package prevents newly added lifecycle, cancellation, cleanup,
	// executor-ownership, or routing regressions from silently falling outside
	// a hand-maintained allowlist.
	runGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		cpaPluginHostPackage,
	)
	runGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", "^("+strings.Join(criticalCPAHandlerTests, "|")+")$", cpaHandlersPackage,
	)
}

// TestCPAHostFailOpenFixtureContract copies the checksum-verified pinned module
// to an ephemeral directory and adds only a _test.go file. The fixture can
// therefore exercise the real Host's private lifecycle, fuse, ordering, and
// readiness state without forking or changing any production CPA source.
func TestCPAHostFailOpenFixtureContract(t *testing.T) {
	goBinary, _, module := preparePinnedCPAModule(t)
	fixturePath, errFixtureAbs := filepath.Abs(filepath.Join("testfixtures", "host_failopen_overlay_test.go.txt"))
	if errFixtureAbs != nil {
		t.Fatalf("resolve Host fixture path: %v", errFixtureAbs)
	}
	if _, errFixtureStat := os.Stat(fixturePath); errFixtureStat != nil {
		t.Fatalf("stat Host fixture: %v", errFixtureStat)
	}
	moduleCopy := filepath.Join(t.TempDir(), "cpa-"+cpaPinnedVersion)
	if errCopyModule := os.CopyFS(moduleCopy, os.DirFS(module.Dir)); errCopyModule != nil {
		t.Fatalf("copy pinned CPA module for Host fixture: %v", errCopyModule)
	}
	fixtureData, errReadFixture := os.ReadFile(fixturePath)
	if errReadFixture != nil {
		t.Fatalf("read Host fixture: %v", errReadFixture)
	}
	targetPath := filepath.Join(moduleCopy, "internal", "pluginhost", "cyber_abuse_guard_host_fixture_test.go")
	if errWriteFixture := os.WriteFile(targetPath, fixtureData, 0o600); errWriteFixture != nil {
		t.Fatalf("write ephemeral Host fixture: %v", errWriteFixture)
	}
	const fixtureTestName = "TestCyberAbuseGuardHostFailOpenFixtureMatrix"
	listed := runGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=mod", "-list", "^"+fixtureTestName+"$", "./internal/pluginhost",
	)
	foundFixtureTest := false
	for _, line := range strings.Split(listed, "\n") {
		if strings.TrimSpace(line) == fixtureTestName {
			foundFixtureTest = true
			break
		}
	}
	if !foundFixtureTest {
		t.Fatalf("ephemeral CPA Host overlay does not list required test %q", fixtureTestName)
	}
	runGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=mod", "-count=1", "-v",
		"-run", "^"+fixtureTestName+"$", "./internal/pluginhost",
	)
}

func TestCPAReleaseCandidatePluginStoreInstallContract(t *testing.T) {
	goBinary, _, module := preparePinnedCPAModule(t)
	fixturePath, errFixtureAbs := filepath.Abs(filepath.Join("testfixtures", "release_rc_install_overlay_test.go.txt"))
	if errFixtureAbs != nil {
		t.Fatalf("resolve RC Plugin Store fixture path: %v", errFixtureAbs)
	}
	fixtureData, errReadFixture := os.ReadFile(fixturePath)
	if errReadFixture != nil {
		t.Fatalf("read RC Plugin Store fixture: %v", errReadFixture)
	}
	moduleCopy := filepath.Join(t.TempDir(), "cpa-"+cpaPinnedVersion)
	if errCopyModule := os.CopyFS(moduleCopy, os.DirFS(module.Dir)); errCopyModule != nil {
		t.Fatalf("copy pinned CPA module for RC Plugin Store fixture: %v", errCopyModule)
	}
	targetPath := filepath.Join(moduleCopy, "internal", "pluginstore", "cyber_abuse_guard_rc_install_test.go")
	if errWriteFixture := os.WriteFile(targetPath, fixtureData, 0o600); errWriteFixture != nil {
		t.Fatalf("write ephemeral RC Plugin Store fixture: %v", errWriteFixture)
	}
	const fixtureTestName = "TestCyberAbuseGuardRCPluginStoreContract"
	listed := runGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=mod", "-list", "^"+fixtureTestName+"$", "./internal/pluginstore",
	)
	if !linePresent(listed, fixtureTestName) {
		t.Fatalf("ephemeral CPA Plugin Store overlay does not list %q", fixtureTestName)
	}
	runGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=mod", "-count=1", "-v", "-run", "^"+fixtureTestName+"$", "./internal/pluginstore",
	)
}

func preparePinnedCPAModule(t *testing.T) (string, []string, resolvedCPAModule) {
	t.Helper()
	goBinary, errLookPath := exec.LookPath("go")
	if errLookPath != nil {
		t.Fatalf("locate go tool: %v", errLookPath)
	}

	moduleData, errReadModule := os.ReadFile("go.mod")
	if errReadModule != nil {
		t.Fatalf("read pinned module definition: %v", errReadModule)
	}
	moduleSumData, errReadModuleSum := os.ReadFile("go.sum")
	if errReadModuleSum != nil {
		t.Fatalf("read pinned module checksums: %v", errReadModuleSum)
	}
	temporaryModule := filepath.Join(t.TempDir(), "host-contract.mod")
	if errWriteModule := os.WriteFile(temporaryModule, moduleData, 0o600); errWriteModule != nil {
		t.Fatalf("write temporary module definition: %v", errWriteModule)
	}
	temporaryModuleSum := strings.TrimSuffix(temporaryModule, ".mod") + ".sum"
	if errWriteModuleSum := os.WriteFile(temporaryModuleSum, moduleSumData, 0o600); errWriteModuleSum != nil {
		t.Fatalf("write temporary module checksums: %v", errWriteModuleSum)
	}
	moduleArguments := []string{"-mod=mod", "-modfile=" + temporaryModule}

	moduleJSON := runGoJSONCommand(t, goBinary,
		"list", moduleArguments[0], moduleArguments[1], "-m", "-json", cpaModulePath,
	)
	var module resolvedCPAModule
	if errUnmarshal := json.Unmarshal([]byte(moduleJSON), &module); errUnmarshal != nil {
		t.Fatalf("decode resolved CPA module metadata: %v", errUnmarshal)
	}
	if module.Replace != nil {
		t.Fatal("resolved CPA module unexpectedly uses a replacement")
	}
	if module.Path != cpaModulePath || module.Version != cpaPinnedVersion || strings.TrimSpace(module.Dir) == "" {
		t.Fatalf("resolved CPA module = %s@%s dir=%q, want %s@%s with source dir",
			module.Path, module.Version, module.Dir, cpaModulePath, cpaPinnedVersion)
	}
	if module.Sum != cpaPinnedModuleSum || module.GoModSum != cpaPinnedGoModSum {
		t.Fatalf("resolved CPA checksums = module %q go.mod %q, want module %q go.mod %q",
			module.Sum, module.GoModSum, cpaPinnedModuleSum, cpaPinnedGoModSum)
	}
	downloadJSON := runGoJSONCommand(t, goBinary,
		"mod", "download", "-json", cpaModulePath+"@"+cpaPinnedVersion,
	)
	var downloaded resolvedCPAModule
	if errUnmarshalDownload := json.Unmarshal([]byte(downloadJSON), &downloaded); errUnmarshalDownload != nil {
		t.Fatalf("decode downloaded CPA module metadata: %v", errUnmarshalDownload)
	}
	if downloaded.Path != cpaModulePath || downloaded.Version != cpaPinnedVersion ||
		downloaded.Sum != cpaPinnedModuleSum || downloaded.GoModSum != cpaPinnedGoModSum {
		t.Fatalf("downloaded CPA module = %s@%s sums=(%q, %q), want %s@%s sums=(%q, %q)",
			downloaded.Path, downloaded.Version, downloaded.Sum, downloaded.GoModSum,
			cpaModulePath, cpaPinnedVersion, cpaPinnedModuleSum, cpaPinnedGoModSum)
	}
	if downloaded.Origin == nil {
		originFile := strings.TrimSpace(os.Getenv(cpaCompatibilityOriginEnv))
		if originFile != "" {
			originData, errReadOrigin := os.ReadFile(originFile)
			if errReadOrigin != nil {
				t.Fatalf("read isolated CPA Origin metadata: %v", errReadOrigin)
			}
			var isolated resolvedCPAModule
			if errUnmarshalOrigin := json.Unmarshal(originData, &isolated); errUnmarshalOrigin != nil {
				t.Fatalf("decode isolated CPA Origin metadata: %v", errUnmarshalOrigin)
			}
			if isolated.Path != downloaded.Path || isolated.Version != downloaded.Version ||
				isolated.Sum != downloaded.Sum || isolated.GoModSum != downloaded.GoModSum {
				t.Fatal("isolated CPA Origin identity differs from active module download")
			}
			downloaded.Origin = isolated.Origin
		}
	}
	if downloaded.Origin == nil {
		t.Fatal("downloaded CPA module metadata omits Origin")
	}
	wantOriginRef := "refs/tags/" + cpaPinnedVersion
	if downloaded.Origin.VCS != "git" || downloaded.Origin.URL != cpaOfficialOriginURL ||
		downloaded.Origin.Hash != cpaPinnedCommit || downloaded.Origin.Ref != wantOriginRef {
		t.Fatalf("downloaded CPA Origin = vcs=%q url=%q hash=%q ref=%q, want git %q %q %q",
			downloaded.Origin.VCS, downloaded.Origin.URL, downloaded.Origin.Hash, downloaded.Origin.Ref,
			cpaOfficialOriginURL, cpaPinnedCommit, wantOriginRef)
	}
	t.Logf("pinned CPA module: %s@%s commit=%s sum=%s go_mod_sum=%s",
		module.Path, module.Version, cpaPinnedCommit, module.Sum, module.GoModSum)
	return goBinary, moduleArguments, module
}

func runGoCommand(t *testing.T, goBinary string, arguments ...string) string {
	t.Helper()
	return runGoCommandInDir(t, "", goBinary, arguments...)
}

func runGoJSONCommand(t *testing.T, goBinary string, arguments ...string) string {
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

func runGoCommandInDir(t *testing.T, directory, goBinary string, arguments ...string) string {
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

func linePresent(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
