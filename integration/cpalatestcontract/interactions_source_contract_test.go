package cpalatestcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	cpaLatestHandlersPackage       = cpaLatestModulePath + "/sdk/api/handlers"
	cpaLatestGeminiHandlersPackage = cpaLatestHandlersPackage + "/gemini"
	cpaLatestInternalAPIPackage    = cpaLatestModulePath + "/internal/api"

	cpaLatestInteractionsHandlerFixture       = "latest_interactions_handler_overlay_test.go.txt"
	cpaLatestInteractionsHandlerFixtureSHA256 = "5f099850bdb6462b0daca4a730d0bde92739dc2435a9c33dfa38bd2eb0dafa66"
	cpaLatestInteractionsHostFixture          = "latest_interactions_pluginhost_overlay_test.go.txt"
	cpaLatestInteractionsHostFixtureSHA256    = "8338d3eb83ff1169adf433ee57f11fb5348e30afcde237216c382559558feecc"
)

var latestOfficialInteractionsTests = []struct {
	packagePath string
	testNames   []string
}{
	{
		packagePath: cpaLatestInternalAPIPackage,
		testNames: []string{
			"TestInteractionsRouteRegistered",
		},
	},
	{
		packagePath: cpaLatestGeminiHandlersPackage,
		testNames: []string{
			"TestBuildInteractionsExecutionRequestUsesAgentAuthSelectionModel",
			"TestInteractionsRejectsBothModelAndAgent",
			"TestInteractionsRejectsInvalidJSON",
			"TestInteractionsRejectsMissingModelAndAgent",
			"TestInteractionsRejectsNonBooleanStream",
			"TestParseInteractionsRequestTarget",
			"TestPrepareInteractionsExecutionTargetNormalizesModelResourceName",
		},
	},
	{
		packagePath: cpaLatestHandlersPackage,
		testNames: []string{
			"TestExecuteProtocolStreamWithAuthManagerAgentUsesSelectionModelForAuth",
			"TestExecuteProtocolWithAuthManagerAgentUsesSelectionModelForAuth",
			"TestExecuteProtocolWithAuthManagerUsesForcedProvider",
		},
	},
}

var latestPrimaryCodexAlphaSearchTests = []string{
	"TestCodexAlphaSearchFallsBackWhenPluginDoesNotHandleRoute",
	"TestCodexAlphaSearchRejectsUnsupportedPluginRouteTarget",
	"TestCodexAlphaSearchUsesPluginProviderTargetModel",
}

func TestLatestCPAOfficialInteractionsSourceContract(t *testing.T) {
	goBinary, moduleArguments, module := prepareLatestCPAModule(t)
	for _, contract := range latestOfficialInteractionsTests {
		contract := contract
		t.Run(filepath.Base(contract.packagePath), func(t *testing.T) {
			required := append([]string(nil), contract.testNames...)
			if contract.packagePath == cpaLatestInternalAPIPackage &&
				module.Version == cpaPinnedProfile.Version {
				required = append(required, latestPrimaryCodexAlphaSearchTests...)
			}
			runLatestRequiredPackageTests(t, goBinary, moduleArguments, contract.packagePath, required)
		})
	}
}

func TestLatestCPAInteractionsHandlerAndTranslatorOverlayContract(t *testing.T) {
	runLatestCPAOverlayFixture(t, latestCPAOverlayFixture{
		fixtureName:   cpaLatestInteractionsHandlerFixture,
		fixtureSHA256: cpaLatestInteractionsHandlerFixtureSHA256,
		targetPath:    filepath.Join("sdk", "api", "handlers", "gemini", "cyber_abuse_guard_interactions_contract_test.go"),
		packagePath:   "./sdk/api/handlers/gemini",
		testNames: []string{
			"TestCyberAbuseGuardInteractionsHandlerModelRouterContract",
			"TestCyberAbuseGuardInteractionsTranslatorRegistryContract",
		},
	})
}

func TestLatestCPAInteractionsDirectExecutorFormatOverlayContract(t *testing.T) {
	runLatestCPAOverlayFixture(t, latestCPAOverlayFixture{
		fixtureName:   cpaLatestInteractionsHostFixture,
		fixtureSHA256: cpaLatestInteractionsHostFixtureSHA256,
		targetPath:    filepath.Join("internal", "pluginhost", "cyber_abuse_guard_interactions_format_contract_test.go"),
		packagePath:   "./internal/pluginhost",
		testNames: []string{
			"TestCyberAbuseGuardInteractionsDirectExecutorFormatContract",
		},
	})
}

type latestCPAOverlayFixture struct {
	fixtureName   string
	fixtureSHA256 string
	targetPath    string
	packagePath   string
	testNames     []string
}

func runLatestRequiredPackageTests(t *testing.T, goBinary string, moduleArguments []string, packagePath string, required []string) {
	t.Helper()
	listed := runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", packagePath,
	)
	for _, name := range required {
		if !linePresent(listed, name) {
			t.Fatalf("latest CPA package %s no longer lists required test %q", packagePath, name)
		}
	}
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", exactLatestTestRegex(required), packagePath,
	)
}

func runLatestCPAOverlayFixture(t *testing.T, fixture latestCPAOverlayFixture) {
	t.Helper()
	goBinary, _, module := prepareLatestCPAModule(t)
	profile := selectedCPACompatibilityProfile(t)
	fixturePath, errFixtureAbs := filepath.Abs(filepath.Join("..", "pluginstorecontract", "testfixtures", fixture.fixtureName))
	if errFixtureAbs != nil {
		t.Fatalf("resolve latest CPA overlay fixture %s: %v", fixture.fixtureName, errFixtureAbs)
	}
	fixtureData, errReadFixture := os.ReadFile(fixturePath)
	if errReadFixture != nil {
		t.Fatalf("read latest CPA overlay fixture %s: %v", fixture.fixtureName, errReadFixture)
	}
	fixtureData = bytes.ReplaceAll(fixtureData, []byte("\r\n"), []byte("\n"))
	if bytes.ContainsRune(fixtureData, '\r') {
		t.Fatalf("latest CPA overlay fixture %s contains a non-canonical carriage return", fixture.fixtureName)
	}
	fixtureHash := sha256.Sum256(fixtureData)
	if actual := hex.EncodeToString(fixtureHash[:]); actual != fixture.fixtureSHA256 {
		t.Fatalf("latest CPA overlay fixture %s sha256=%s, want %s", fixture.fixtureName, actual, fixture.fixtureSHA256)
	}

	moduleCopy := filepath.Join(t.TempDir(), "cpa-"+profile.Version+"-interactions")
	if errCopyModule := os.CopyFS(moduleCopy, os.DirFS(module.Dir)); errCopyModule != nil {
		t.Fatalf("copy latest CPA module for interactions overlay: %v", errCopyModule)
	}
	targetPath := filepath.Join(moduleCopy, fixture.targetPath)
	if errWriteFixture := os.WriteFile(targetPath, fixtureData, 0o600); errWriteFixture != nil {
		t.Fatalf("write ephemeral latest CPA interactions fixture: %v", errWriteFixture)
	}

	listed := runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-list", exactLatestTestRegex(fixture.testNames), fixture.packagePath,
	)
	for _, name := range fixture.testNames {
		if !linePresent(listed, name) {
			t.Fatalf("ephemeral latest CPA package %s does not list required test %q", fixture.packagePath, name)
		}
	}
	runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-count=1", "-v",
		"-run", exactLatestTestRegex(fixture.testNames), fixture.packagePath,
	)
}

func exactLatestTestRegex(names []string) string {
	exactNames := make([]string, 0, len(names))
	for _, name := range names {
		exactNames = append(exactNames, regexp.QuoteMeta(name))
	}
	return "^(" + strings.Join(exactNames, "|") + ")$"
}
