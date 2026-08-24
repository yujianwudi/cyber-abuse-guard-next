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
	cpaLatestHandlersPackage           = cpaLatestModulePath + "/sdk/api/handlers"
	cpaLatestGeminiHandlersPackage     = cpaLatestHandlersPackage + "/gemini"
	cpaLatestInternalAPIPackage        = cpaLatestModulePath + "/internal/api"
	cpaLatestCliproxyAuthPackage       = cpaLatestModulePath + "/sdk/cliproxy/auth"
	cpaLatestGeminiInteractionsPackage = cpaLatestModulePath + "/internal/translator/gemini/interactions"
	cpaLatestGeminiGeminiPackage       = cpaLatestModulePath + "/internal/translator/gemini/gemini"
	cpaLatestOpenAIGeminiPackage       = cpaLatestModulePath + "/internal/translator/openai/gemini"

	cpaLatestInteractionsHandlerFixture       = "latest_interactions_handler_overlay_test.go.txt"
	cpaLatestInteractionsHandlerFixtureSHA256 = "8e581e3de82a7dd3ceff051d139cc35af4f8dff74b9c705346c399201a0c30a3"
	cpaLatestInteractionsHostFixture          = "latest_interactions_pluginhost_overlay_test.go.txt"
	cpaLatestInteractionsHostFixtureSHA256    = "48ad9948f4f2bc52a78d9d8c68a728ade7b1e6fedba8afa695ec69b4753db8b5"
	cpaLatestHomeOAuthRetryFixture            = "latest_home_oauth_retry_overlay_test.go.txt"
	cpaLatestHomeOAuthRetryFixtureSHA256      = "216e40962593363e269e8a3b30f7686137aca4654773168aa2025b0b16fa07cc"
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
		packagePath: cpaLatestCliproxyAuthPackage,
		testNames: []string{
			"TestHomeUnauthorizedRefreshesSameSelectionBeforeRedispatch",
			"TestHomeUnauthorizedRefreshUpdatesRetainedSelection",
			"TestRefreshHomeSelectionReusesConcurrentNewerToken",
			"TestHomeUnauthorizedRefreshIsAttemptedAtMostOnce",
			"TestHomeNoCandidateAfterRefreshFailurePreservesRefreshError",
			"TestHomeUnauthorizedTransientRefreshFailureIsReturned",
			"TestHomeUnauthorizedStreamRefreshesAtMostOnceAcrossRedispatch",
			"TestHomeUnauthorizedStartedStreamDoesNotReplay",
			"TestHomeUnauthorizedStreamRefreshesBeforeRedispatch",
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
	{
		packagePath: cpaLatestGeminiInteractionsPackage,
		testNames: []string{
			"TestConvertGeminiRequestToInteractionsFunctionCall",
		},
	},
	{
		packagePath: cpaLatestGeminiGeminiPackage,
		testNames: []string{
			"TestBackfillEmptyFunctionResponseNames_Parallel",
			"TestBackfillEmptyFunctionResponseNames_MoreResponsesThanCalls",
			"TestBackfillEmptyFunctionResponseNames_MultipleGroups",
		},
	},
	{
		packagePath: cpaLatestOpenAIGeminiPackage,
		testNames: []string{
			"TestConvertGeminiRequestToOpenAI_FunctionResponsesConsumeToolCallIDsFIFO",
			"TestConvertGeminiRequestToOpenAI_FunctionResponseWithoutPriorCallGetsFallbackID",
			"TestConvertGeminiRequestToOpenAI_ExtraFunctionResponsesUseFallbackID",
			"TestConvertGeminiRequestToOpenAI_PreservesExplicitFunctionCallIDs",
		},
	},
}

var latestPrimaryCodexAlphaSearchTests = []string{
	"TestCodexAlphaSearchFallsBackWhenPluginDoesNotHandleRoute",
	"TestCodexAlphaSearchRejectsUnsupportedPluginRouteTarget",
	"TestCodexAlphaSearchUsesPluginProviderTargetModel",
	"TestHomeCodexAlphaSearchRefreshesUnauthorizedSelectionOnce",
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
			"TestCyberAbuseGuardInteractionsHandlerRequestInterceptorContract",
			"TestCyberAbuseGuardInteractionsTranslatorRegistryContract",
		},
	})
}

func TestLatestCPAInteractionsSchema3RequestLifecycleOverlayContract(t *testing.T) {
	runLatestCPAOverlayFixture(t, latestCPAOverlayFixture{
		fixtureName:   cpaLatestInteractionsHostFixture,
		fixtureSHA256: cpaLatestInteractionsHostFixtureSHA256,
		targetPath:    filepath.Join("internal", "pluginhost", "cyber_abuse_guard_interactions_format_contract_test.go"),
		packagePath:   "./internal/pluginhost",
		testNames: []string{
			"TestCyberAbuseGuardInteractionsRequestLifecycleFormatContract",
		},
	})
}

func TestLatestCPAHomeOAuthUnauthorizedRetryOverlayContract(t *testing.T) {
	runLatestCPAOverlayFixture(t, latestCPAOverlayFixture{
		fixtureName:   cpaLatestHomeOAuthRetryFixture,
		fixtureSHA256: cpaLatestHomeOAuthRetryFixtureSHA256,
		targetPath:    filepath.Join("sdk", "api", "handlers", "cyber_abuse_guard_home_oauth_retry_contract_test.go"),
		packagePath:   "./sdk/api/handlers",
		testNames: []string{
			"TestCyberAbuseGuardHomeOAuthUnauthorizedRetrySingleLogicalLifecycle",
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
