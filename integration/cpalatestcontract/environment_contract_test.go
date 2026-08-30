package cpalatestcontract

import (
	"strings"
	"testing"
)

func TestLatestCPAEnvironmentDoesNotPropagateCredentialsOrGitRouting(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "redacted-token")
	t.Setenv("CPA_TEST_SECRET", "redacted-secret")
	t.Setenv("GIT_DIR", "/tmp/untrusted-git")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.bare")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	t.Setenv("GOPRIVATE", "attacker.example/redirect")
	t.Setenv("HTTPS_PROXY", "https://proxy.example")

	env := latestCPAEnvironmentWithOverrides(map[string]string{"GOPROXY": "off"})
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, forbidden := range []string{
		"GITHUB_TOKEN=",
		"CPA_TEST_SECRET=",
		"GIT_DIR=",
		"GIT_CONFIG_COUNT=",
		"GIT_CONFIG_KEY_0=",
		"GIT_CONFIG_VALUE_0=",
		"GOPRIVATE=attacker.example/redirect",
		"HTTPS_PROXY=https://proxy.example",
	} {
		if strings.Contains(joined, "\n"+forbidden) {
			t.Fatalf("sensitive or repository-routing environment escaped: %q", forbidden)
		}
	}
	for _, required := range []string{
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOENV=off",
		"GOFLAGS=-mod=readonly",
		"GOOS=linux",
		"GOARCH=amd64",
		"GOPROXY=off",
		"GOVCS=public:git|https",
		"GOPRIVATE=",
		"PATH=/usr/bin:/bin",
		"HTTPS_PROXY=",
	} {
		if !strings.Contains(joined, "\n"+required+"\n") {
			t.Fatalf("required deterministic environment entry missing: %q", required)
		}
	}
}
