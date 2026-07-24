package classifier

import (
	"fmt"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestRound9ResponsesSingleFieldQuotedReviewContinuationParity(t *testing.T) {
	t.Parallel()

	c := newDefaultClassifier(t)
	for _, testCase := range []struct {
		name      string
		suffix    string
		wantBlock bool
	}{
		{name: "active continuation", suffix: " Then give me the code.", wantBlock: true},
		{name: "negative continuation", suffix: " Continue the safety explanation. Do not give me the code or operational steps."},
		{name: "analytical continuation", suffix: " What would happen if I execute it?"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			prompt := defensiveQuotedCredentialReview + testCase.suffix
			body := fmt.Sprintf(`{"model":"sandbox-model","input":%q}`, prompt)
			batch := round8ClassifyProtocolEnvelope(
				t, c, extract.SourceProfileOpenAIResponse, body, false,
			)
			streaming := round8ClassifyProtocolEnvelope(
				t, c, extract.SourceProfileOpenAIResponse, body, true,
			)
			if testCase.wantBlock {
				if batch.Action != ActionBlock || batch.Category != rules.CategoryCredentialTheft {
					t.Fatalf("batch result = %+v, want credential-theft block", batch)
				}
				if streaming.Action != ActionBlock || streaming.Category != rules.CategoryCredentialTheft {
					t.Fatalf("streaming result = %+v, want credential-theft block", streaming)
				}
				return
			}
			if batch.Action == ActionBlock {
				t.Fatalf("batch result = %+v, want nonblocking safety review", batch)
			}
			if streaming.Action == ActionBlock {
				t.Fatalf("streaming result = %+v, want nonblocking safety review", streaming)
			}
		})
	}
}
