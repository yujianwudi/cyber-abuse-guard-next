package audit

import (
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzRound9AuditDecisionExplanationV2(f *testing.F) {
	addSeed := func(explanation *DecisionExplanation) {
		f.Helper()
		encoded, err := json.Marshal(explanation)
		if err != nil {
			f.Fatalf("marshal seed: %v", err)
		}
		f.Add(encoded)
	}

	addSeed(round9EligibleDecisionExplanationFixture())
	addSeed(&DecisionExplanation{
		Kind:                       decisionExplanationKindIncomplete,
		IncompleteInspectionReason: "scan_limit",
	})
	addSeed(&DecisionExplanation{
		Kind:              decisionExplanationKindOpaque,
		OpaqueMediaReason: opaqueMediaExplanationReason,
	})
	addSeed(&DecisionExplanation{
		Kind:              decisionExplanationKindSubject,
		SubjectRiskAction: "block",
	})
	f.Add([]byte(`{"kind":"malicious","unknown_round9_field":"forbidden"}`))
	f.Add([]byte(`{"kind":"incomplete","incomplete_inspection_reason":"scan_limit"} {}`))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 33<<10 {
			t.Skip()
		}
		decoded, err := decodeDecisionExplanationForSchema(
			string(encoded),
			DecisionExplanationSchemaV2,
		)
		if err != nil {
			return
		}

		canonical, err := marshalDecisionExplanationForSchema(
			decoded,
			DecisionExplanationSchemaV2,
		)
		if err != nil {
			t.Fatalf("accepted explanation no longer marshals: %v", err)
		}
		if len(canonical) > 32768 {
			t.Fatalf("canonical explanation bytes=%d, want <=32768", len(canonical))
		}
		roundTripped, err := decodeDecisionExplanationForSchema(
			canonical,
			DecisionExplanationSchemaV2,
		)
		if err != nil {
			t.Fatalf("canonical explanation no longer decodes: %v", err)
		}
		if !reflect.DeepEqual(roundTripped, decoded) {
			t.Fatalf("Round 9 explanation round trip drifted: got=%#v want=%#v", roundTripped, decoded)
		}
	})
}
