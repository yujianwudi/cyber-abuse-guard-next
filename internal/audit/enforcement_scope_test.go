package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEnforcementScopeValidationAndJSONContract(t *testing.T) {
	t.Parallel()
	for _, scope := range []EnforcementScope{
		EnforcementScopeCurrentUser,
		EnforcementScopeRequestLocalSystem,
		EnforcementScopeRequestLocalTool,
	} {
		scope := scope
		t.Run(string(scope), func(t *testing.T) {
			t.Parallel()
			want := eligibleExplanationForEnforcementScope(scope)
			if err := validateDecisionExplanation(want); err != nil {
				t.Fatalf("valid %s explanation rejected: %v", scope, err)
			}
			encoded, err := marshalDecisionExplanationForSchema(want, DecisionExplanationSchemaV2)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(encoded, `"enforcement_scope":"`+string(scope)+`"`) {
				t.Fatalf("encoded explanation omitted enforcement scope: %s", encoded)
			}
			got, err := decodeDecisionExplanationForSchema(encoded, DecisionExplanationSchemaV2)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("JSON round trip = %#v, want %#v", got, want)
			}
		})
	}

	// Empty scope remains readable for legacy current-user v2 history when the
	// exact user/content/current-turn authority tuple is still present. Removing
	// the execution act therefore contributes only the no-current-directive
	// reason; it must not manufacture an untrusted-ownership contradiction.
	history := eligibleExplanationForEnforcementScope(EnforcementScopeCurrentUser)
	history.BlockEligible = false
	history.EnforcementScope = EnforcementScopeNone
	history.CurrentExecutionActProven = false
	history.PrimaryEligibilityReason = eligibilityReasonNoCurrentDirective
	history.EligibilityReasonFlags = eligibilityFlagNoCurrentDirective
	history.HardFloorApplied = false
	history.HardFloorReason = ""
	if err := validateDecisionExplanation(history); err != nil {
		t.Fatalf("safe non-eligible history rejected: %v", err)
	}
}

func TestRequestLocalToolScopeAcceptsCompleteCurrentUserActivationProof(t *testing.T) {
	t.Parallel()
	explanation := eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalTool)
	explanation.CurrentTurnEvidence = true
	explanation.ReferentLinkUsed = true
	explanation.ReferentProofComplete = true
	explanation.CurrentExecutionActProven = true
	explanation.CrossSegmentComposition = "explicit_referent"
	explanation.RelationType = ExplanationRelationHistoricalToolActivation
	explanation.EnforcementOwner = ExplanationEnforcementOwnerCurrentTrustedUser
	explanation.EvidenceSegmentCount = 2
	if err := validateDecisionExplanation(explanation); err != nil {
		t.Fatalf("complete historical-tool activation rejected: %v", err)
	}
	if !auditRequestBlockAuthorityProven(explanation) {
		t.Fatalf("complete historical-tool activation lost request authority: %#v", explanation)
	}
	encoded, err := marshalDecisionExplanationForSchema(explanation, DecisionExplanationSchemaV2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded, `"relation_type":"historical_tool_activation"`) ||
		!strings.Contains(encoded, `"enforcement_owner":"current_trusted_user"`) {
		t.Fatalf("encoded explanation omitted historical-tool relation: %s", encoded)
	}
	decoded, err := decodeDecisionExplanationForSchema(encoded, DecisionExplanationSchemaV2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, explanation) {
		t.Fatalf("historical-tool JSON round trip = %#v, want %#v", decoded, explanation)
	}
	legacy := cloneDecisionExplanation(explanation)
	legacy.RelationType = ExplanationRelationNone
	legacy.EnforcementOwner = ExplanationEnforcementOwnerNone
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyDecoded, err := decodeDecisionExplanationForSchema(
		string(legacyJSON), DecisionExplanationSchemaV2,
	)
	if err != nil {
		t.Fatalf("pre-RT10 historical-tool explanation rejected: %v", err)
	}
	if legacyDecoded.RelationType != ExplanationRelationNone ||
		legacyDecoded.EnforcementOwner != ExplanationEnforcementOwnerNone {
		t.Fatalf("pre-RT10 explanation manufactured a relation: %#v", legacyDecoded)
	}
	legacyEvent := round9MaliciousBlockEventFixture()
	legacyEvent.DecisionExplanation = legacy
	if _, err := prepareEvent(legacyEvent, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "relation_type") {
		t.Fatalf("canonical write accepted relation-free historical-tool explanation: %v", err)
	}

	for _, mutate := range []func(*DecisionExplanation){
		func(value *DecisionExplanation) { value.CurrentTurnEvidence = false },
		func(value *DecisionExplanation) { value.ReferentLinkUsed = false },
		func(value *DecisionExplanation) { value.ReferentProofComplete = false },
		func(value *DecisionExplanation) { value.CurrentExecutionActProven = false },
		func(value *DecisionExplanation) { value.CrossSegmentComposition = "none" },
		func(value *DecisionExplanation) { value.RelationType = ExplanationRelationNone },
		func(value *DecisionExplanation) { value.EnforcementOwner = ExplanationEnforcementOwnerNone },
		func(value *DecisionExplanation) { value.EvidenceSegmentCount = 1 },
	} {
		invalid := cloneDecisionExplanation(explanation)
		mutate(invalid)
		if err := validateDecisionExplanation(invalid); err == nil {
			t.Fatalf("accepted incomplete historical-tool activation: %#v", invalid)
		}
	}
	for name, mutate := range map[string]func(*DecisionExplanation){
		"unknown relation": func(value *DecisionExplanation) {
			value.RelationType = ExplanationRelationType("request_fragment")
		},
		"unknown owner": func(value *DecisionExplanation) {
			value.EnforcementOwner = ExplanationEnforcementOwner("caller_supplied_owner")
		},
		"wrong scope": func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeCurrentUser
			value.EvidenceOwnedByCurrentUser = true
			value.WinningRole = "user"
		},
	} {
		invalid := cloneDecisionExplanation(explanation)
		mutate(invalid)
		if err := validateDecisionExplanation(invalid); err == nil {
			t.Fatalf("accepted %s historical-tool relation: %#v", name, invalid)
		}
	}
}

func TestRequestLocalToolScopeRejectsActivationFieldsWithoutCurrentTurnProof(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*DecisionExplanation){
		func(value *DecisionExplanation) { value.ReferentLinkUsed = true },
		func(value *DecisionExplanation) { value.CrossSegmentComposition = "explicit_referent" },
		func(value *DecisionExplanation) {
			value.RelationType = ExplanationRelationHistoricalToolActivation
			value.EnforcementOwner = ExplanationEnforcementOwnerCurrentTrustedUser
		},
	} {
		explanation := eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalTool)
		if explanation.CurrentTurnEvidence {
			t.Fatalf("terminal fixture unexpectedly has current-turn proof: %#v", explanation)
		}
		mutate(explanation)
		if err := validateDecisionExplanation(explanation); err == nil {
			t.Fatalf("terminal tool result carried activation fields: %#v", explanation)
		}
	}
}

func TestEnforcementScopeLegacyCurrentUserV2JSONAndEventRemainReadable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 25, 9, 15, 0, 0, time.UTC)
	archived := eligibleExplanationForEnforcementScope(EnforcementScopeCurrentUser)
	archived.EnforcementScope = EnforcementScopeNone
	archivedJSON, err := json.Marshal(archived)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(archivedJSON), `"enforcement_scope"`) {
		t.Fatalf("archived v2 fixture unexpectedly contains enforcement_scope: %s", archivedJSON)
	}

	decoded, err := decodeDecisionExplanationForSchema(string(archivedJSON), DecisionExplanationSchemaV2)
	if err != nil {
		t.Fatalf("archived eligible v2 current-user JSON rejected: %v", err)
	}
	if decoded.EnforcementScope != EnforcementScopeNone || !auditRequestBlockAuthorityProven(decoded) ||
		decoded.RelationType != ExplanationRelationNone ||
		decoded.EnforcementOwner != ExplanationEnforcementOwnerNone {
		t.Fatalf("archived eligible v2 current-user authority not preserved: %#v", decoded)
	}

	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "legacy-current-user-v2.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	event := round9MaliciousBlockEventFixture()
	event.ID = "legacy-current-user-v2"
	event.Timestamp = now
	if !store.Record(event) {
		t.Fatal("Record() rejected valid explicit-scope seed event")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(
		`UPDATE audit_events SET decision_explanation = ? WHERE id = ?`,
		string(archivedJSON), event.ID,
	); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{DecisionKind: decisionKindBlockMaliciousText, Limit: 1})
	if err != nil {
		t.Fatalf("archived eligible v2 current-user event rejected: %v", err)
	}
	if len(events) != 1 || events[0].ID != event.ID || events[0].DecisionExplanation == nil ||
		events[0].DecisionExplanation.EnforcementScope != EnforcementScopeNone {
		t.Fatalf("archived eligible v2 current-user event = %#v", events)
	}
}

func TestEnforcementScopeRejectsEmptyUnknownAndMismatchedEligibleExplanations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*DecisionExplanation)
	}{
		{name: "empty non-user system", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.EvidenceOwnedByCurrentUser = false
			value.WinningRole = "system"
			value.CurrentTurnEvidence = false
		}},
		{name: "empty non-user tool", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.EvidenceOwnedByCurrentUser = false
			value.WinningRole = "tool"
			value.CurrentTurnEvidence = false
		}},
		{name: "empty mismatched ownership", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.EvidenceOwnedByCurrentUser = false
		}},
		{name: "empty mismatched role", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.WinningRole = "system"
		}},
		{name: "empty mismatched provenance", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.WinningProvenance = "tool_payload"
		}},
		{name: "empty mismatched turn", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.CurrentTurnEvidence = false
		}},
		{name: "unknown", mutate: func(value *DecisionExplanation) { value.EnforcementScope = EnforcementScope("future_scope") }},
		{name: "scope swapped to system", mutate: func(value *DecisionExplanation) { value.EnforcementScope = EnforcementScopeRequestLocalSystem }},
		{name: "current user without ownership", mutate: func(value *DecisionExplanation) { value.EvidenceOwnedByCurrentUser = false }},
		{name: "current user wrong role", mutate: func(value *DecisionExplanation) { value.WinningRole = "system" }},
		{name: "current user wrong provenance", mutate: func(value *DecisionExplanation) { value.WinningProvenance = "tool_payload" }},
		{name: "current user not current", mutate: func(value *DecisionExplanation) { value.CurrentTurnEvidence = false }},
		{name: "system claims user ownership", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalSystem)
			value.EvidenceOwnedByCurrentUser = true
		}},
		{name: "system wrong role", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalSystem)
			value.WinningRole = "assistant"
		}},
		{name: "system wrong provenance", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalSystem)
			value.WinningProvenance = "tool_payload"
		}},
		{name: "system marked current", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalSystem)
			value.CurrentTurnEvidence = true
		}},
		{name: "tool claims user ownership", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalTool)
			value.EvidenceOwnedByCurrentUser = true
		}},
		{name: "tool wrong role", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalTool)
			value.WinningRole = "system"
		}},
		{name: "tool payload is not a terminal result", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalTool)
			value.WinningProvenance = "tool_payload"
		}},
		{name: "tool marked current", mutate: func(value *DecisionExplanation) {
			*value = *eligibleExplanationForEnforcementScope(EnforcementScopeRequestLocalTool)
			value.CurrentTurnEvidence = true
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := eligibleExplanationForEnforcementScope(EnforcementScopeCurrentUser)
			test.mutate(value)
			if value.EnforcementScope == EnforcementScopeNone && auditRequestBlockAuthorityProven(value) {
				t.Fatalf("empty scope authorized an invalid legacy current-user tuple: %#v", value)
			}
			if err := validateDecisionExplanation(value); err == nil {
				t.Fatalf("accepted invalid enforcement-scope contract: %#v", value)
			}
		})
	}
}

func TestEnforcementScopePersistsThroughQueryAndExportsWithoutRequestText(t *testing.T) {
	t.Parallel()
	const forbiddenRequestText = "private request text must never be persisted"
	now := time.Date(2026, 7, 25, 9, 0, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "enforcement-scope.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	scopes := []EnforcementScope{
		EnforcementScopeCurrentUser,
		EnforcementScopeRequestLocalSystem,
		EnforcementScopeRequestLocalTool,
	}
	for index, scope := range scopes {
		event := round9MaliciousBlockEventFixture()
		event.ID = "enforcement-scope-" + string(scope)
		event.Timestamp = now.Add(time.Duration(index) * time.Nanosecond)
		event.DecisionExplanation = eligibleExplanationForEnforcementScope(scope)
		if !store.Record(event) {
			t.Fatalf("Record(%s) rejected a valid scope", scope)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	events, err := store.Query(context.Background(), Query{DecisionKind: decisionKindBlockMaliciousText, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(scopes) {
		t.Fatalf("Query() returned %d events, want %d", len(events), len(scopes))
	}
	seen := make(map[EnforcementScope]bool, len(events))
	for _, event := range events {
		if event.DecisionExplanation == nil {
			t.Fatalf("persisted event %s omitted its explanation", event.ID)
		}
		seen[event.DecisionExplanation.EnforcementScope] = true
	}
	for _, scope := range scopes {
		if !seen[scope] {
			t.Fatalf("query omitted persisted scope %q: %#v", scope, events)
		}
	}

	var jsonExport bytes.Buffer
	if err := store.ExportJSON(context.Background(), &jsonExport, Query{DecisionKind: decisionKindBlockMaliciousText, Limit: 10}); err != nil {
		t.Fatal(err)
	}
	var exported []Event
	if err := json.Unmarshal(jsonExport.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != len(scopes) {
		t.Fatalf("JSON export returned %d events, want %d", len(exported), len(scopes))
	}

	var csvExport bytes.Buffer
	if err := store.ExportCSV(context.Background(), &csvExport, Query{DecisionKind: decisionKindBlockMaliciousText, Limit: 10}); err != nil {
		t.Fatal(err)
	}
	combined := jsonExport.String() + csvExport.String()
	for _, scope := range scopes {
		if !strings.Contains(combined, `"enforcement_scope":"`+string(scope)+`"`) {
			t.Fatalf("exports omitted scope %q: %s", scope, combined)
		}
	}
	if strings.Contains(combined, forbiddenRequestText) {
		t.Fatalf("exports leaked request text: %s", combined)
	}
}

func TestEnforcementScopePersistedMutationFailsClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 25, 9, 30, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "enforcement-scope-mutation.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	event := round9MaliciousBlockEventFixture()
	event.ID = "enforcement-scope-mutation"
	event.Timestamp = now
	event.DecisionExplanation = eligibleExplanationForEnforcementScope(EnforcementScopeCurrentUser)
	if !store.Record(event) {
		t.Fatal("Record() rejected valid event")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	validJSON, err := marshalDecisionExplanationForSchema(event.DecisionExplanation, DecisionExplanationSchemaV2)
	if err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		mutate func(*DecisionExplanation)
	}{
		{name: "empty non-user system", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.EvidenceOwnedByCurrentUser = false
			value.WinningRole = "system"
			value.CurrentTurnEvidence = false
		}},
		{name: "empty mismatched current-user tuple", mutate: func(value *DecisionExplanation) {
			value.EnforcementScope = EnforcementScopeNone
			value.WinningProvenance = "tool_payload"
		}},
		{name: "unknown", mutate: func(value *DecisionExplanation) { value.EnforcementScope = EnforcementScope("future_scope") }},
		{name: "mismatched", mutate: func(value *DecisionExplanation) { value.EnforcementScope = EnforcementScopeRequestLocalTool }},
	}
	for _, test := range mutations {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := cloneDecisionExplanation(event.DecisionExplanation)
			test.mutate(value)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`UPDATE audit_events SET decision_explanation = ? WHERE id = ?`, string(encoded), event.ID); err != nil {
				t.Fatal(err)
			}
			if events, err := store.Query(context.Background(), Query{Limit: 1}); err == nil {
				t.Fatalf("Query() returned %d events after %s scope mutation; want error", len(events), test.name)
			}
			if _, err := store.db.Exec(`UPDATE audit_events SET decision_explanation = ? WHERE id = ?`, validJSON, event.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func eligibleExplanationForEnforcementScope(scope EnforcementScope) *DecisionExplanation {
	explanation := round9EligibleDecisionExplanationFixture()
	explanation.EnforcementScope = scope
	switch scope {
	case EnforcementScopeCurrentUser:
		explanation.EvidenceOwnedByCurrentUser = true
		explanation.WinningRole = "user"
		explanation.WinningProvenance = "content"
		explanation.CurrentTurnEvidence = true
	case EnforcementScopeRequestLocalSystem:
		explanation.EvidenceOwnedByCurrentUser = false
		explanation.WinningRole = "system"
		explanation.WinningProvenance = "content"
		explanation.CurrentTurnEvidence = false
	case EnforcementScopeRequestLocalTool:
		explanation.EvidenceOwnedByCurrentUser = false
		explanation.WinningRole = "tool"
		explanation.WinningProvenance = "content"
		explanation.CurrentTurnEvidence = false
	}
	return explanation
}
