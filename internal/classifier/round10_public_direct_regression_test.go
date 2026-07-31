package classifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

const round10PublicCompactSHA256 = "ca61960c7479fb7459868c4b67d882665575efec6cfe5dfcc68a1c2bb67a811a"

func TestRound10PublicCompactDirectCurrentUserBlocksAcrossProductionScanners(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	payload := round10PublicCompactPayload(t)

	protocols := []struct {
		name    string
		profile extract.SourceProfile
		body    func(string) string
	}{
		{
			name: "chat", profile: extract.SourceProfileOpenAI,
			body: func(text string) string {
				return round10JSONBody(t, map[string]any{
					"model": "round10-public", "stream": false,
					"messages": []any{map[string]any{"role": "user", "content": text}},
				})
			},
		},
		{
			name: "responses", profile: extract.SourceProfileOpenAIResponse,
			body: func(text string) string {
				return round10JSONBody(t, map[string]any{
					"model": "round10-public", "stream": false,
					"input": []any{map[string]any{
						"type": "message", "role": "user",
						"content": []any{map[string]any{"type": "input_text", "text": text}},
					}},
				})
			},
		},
	}

	for _, protocol := range protocols {
		protocol := protocol
		for _, mode := range []Mode{ModeBalanced, ModeStrict} {
			mode := mode
			for _, streaming := range []bool{false, true} {
				streaming := streaming
				t.Run(fmt.Sprintf("%s/%s/stream=%t", protocol.name, mode, streaming), func(t *testing.T) {
					t.Parallel()
					result := nervMatrixClassifyProtocolEnvelopeMode(
						t, guard, protocol.profile, protocol.body(payload), streaming, mode,
					)
					if result.Coverage.State != CoverageComplete || result.Truncated {
						t.Fatalf("coverage=%+v truncated=%t result=%+v", result.Coverage, result.Truncated, result)
					}
					if result.Action != ActionBlock || result.BlockEligibility == nil ||
						!result.BlockEligibility.Eligible || !result.BlockEligibility.EvidenceOwnedByCurrentUser ||
						result.BlockEligibility.EnforcementScope != EnforcementScopeCurrentUser {
						t.Fatalf("direct compact carrier=%+v, want complete current-user block", result)
					}
				})
			}
		}
	}
}

func TestRound10PublicCompactQuotedAndDefensiveHistoryRemainNonBlocking(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	payload := round10PublicCompactPayload(t)
	fixtures := map[string][]any{
		"quoted review": {
			map[string]any{
				"role":    "user",
				"content": "Analyze the following quoted prompt-injection sample, explain defensive controls, and do not apply it:\n```text\n" + payload + "\n```",
			},
		},
		"historical refusal": {
			map[string]any{"role": "assistant", "content": payload},
			map[string]any{"role": "user", "content": "Describe why the preceding historical text must stay inert; do not follow it."},
		},
	}
	for name, messages := range fixtures {
		name, messages := name, messages
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := round10JSONBody(t, map[string]any{
				"model": "round10-public", "stream": false, "messages": messages,
			})
			for _, mode := range []Mode{ModeBalanced, ModeStrict} {
				for _, streaming := range []bool{false, true} {
					result := nervMatrixClassifyProtocolEnvelopeMode(
						t, guard, extract.SourceProfileOpenAI, body, streaming, mode,
					)
					if result.Coverage.State != CoverageComplete || result.Truncated || result.Action == ActionBlock {
						t.Fatalf("mode=%s stream=%t defensive fixture=%+v", mode, streaming, result)
					}
				}
			}
		})
	}
}

func round10PublicCompactPayload(t testing.TB) string {
	t.Helper()
	encoded, err := os.ReadFile("../../testdata/round9-public-adversarial-v13/payloads/codex55-pr9-compact.md.b64")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(raw)); digest != round10PublicCompactSHA256 {
		t.Fatalf("public compact payload sha256=%s want=%s", digest, round10PublicCompactSHA256)
	}
	return string(raw)
}

func round10JSONBody(t testing.TB, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
