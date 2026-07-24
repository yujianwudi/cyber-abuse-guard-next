package pluginstorecontract

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	cpaModulePath        = "github.com/router-for-me/CLIProxyAPI/v7"
	cpaPinnedVersion     = "v7.2.95"
	cpaPinnedCommit      = "f71ec0eb6776854457892452cf28c47f0d658251"
	cpaPinnedModuleSum   = "h1:QHQuGuPwOOTdyk5G7s0gjirdQtCM7NtxHRGS1I2xNtA="
	cpaPinnedGoModSum    = "h1:he/Nx8K5RKvpcnedn0dmR8vVgHmetQ3/wutuPibWuRM="
	cpaPluginHostPackage = cpaModulePath + "/internal/pluginhost"
)

var criticalCPAHostTests = []string{
	"TestDecodeEnvelopeResultPreservesPluginHTTPStatus",
	"TestSanitizePluginRequestRemovesNonJSONMetadata",
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
	"TestSortRecordsPriorityDescendingAndIDTieBreak",
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

// TestOfficialCPAHostRoutingSourceContract runs the routing contract tests
// shipped by the pinned CPA module. It deliberately tests the official source
// package instead of copying the host's priority, fail-open, fuse, target
// validation, or executor-readiness implementation into this repository.
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

	exactNames := make([]string, 0, len(criticalCPAHostTests))
	for _, name := range criticalCPAHostTests {
		exactNames = append(exactNames, regexp.QuoteMeta(name))
	}
	testPattern := "^(" + strings.Join(exactNames, "|") + ")$"
	runGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", testPattern,
		cpaPluginHostPackage,
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
	moduleCopy := filepath.Join(t.TempDir(), "cpa-v7.2.95")
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
	if downloaded.Origin != nil {
		if downloaded.Origin.VCS != "git" || downloaded.Origin.Hash != cpaPinnedCommit ||
			downloaded.Origin.Ref != "refs/tags/"+cpaPinnedVersion {
			t.Fatalf("resolved CPA origin = %#v, want git commit %s at refs/tags/%s",
				downloaded.Origin, cpaPinnedCommit, cpaPinnedVersion)
		}
	} else {
		// Go may omit Origin after serving identical checksum-verified module
		// bytes from a warm cache. This Store test owns source and packaging
		// behavior, while scripts/cpa-latest-compat.sh separately enforces the
		// official Git URL/tag/commit (refreshing an isolated direct cache when
		// necessary). Do not turn harmless cache metadata loss into a package
		// failure after both pinned module checksums have already matched.
		t.Log("pinned CPA Origin omitted by warm module cache; exact checksums matched and remote Origin remains a separate compatibility gate")
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
