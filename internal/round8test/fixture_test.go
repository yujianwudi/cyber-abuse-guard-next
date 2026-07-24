package round8test

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeFixtureRejectsSchemaAmbiguityAndPrivacyCanaries(t *testing.T) {
	validPair := `{"family":"family_one","provenance":"synthetic_from_production_fp_family","rule_id":"EVADE-002","category":"defense_evasion","benign":"ordinary benign text","malicious":"ordinary malicious text"}`
	remaining := make([]string, 0, FixturePairCount-1)
	counts := []struct {
		rule, category string
		count          int
	}{
		{rule: "EVADE-002", category: "defense_evasion", count: 15},
		{rule: "CRED-001", category: "credential_theft", count: 10},
		{rule: "CRED-002", category: "credential_theft", count: 10},
		{rule: "MAL-002", category: "malware_deployment", count: 2},
		{rule: "DISRUPT-001", category: "service_disruption", count: 4},
	}
	ordinal := 1
	for _, group := range counts {
		for index := 0; index < group.count; index++ {
			ordinal++
			remaining = append(remaining, fmt.Sprintf(
				`{"family":"family_%d","provenance":"synthetic_from_production_fp_family","rule_id":%q,"category":%q,"benign":"ordinary benign text %d","malicious":"ordinary malicious text %d"}`,
				ordinal, group.rule, group.category, ordinal, ordinal,
			))
		}
	}
	valid := `{"schema":"round8-balanced-readmission/v1","pairs":[` + validPair + `,` + strings.Join(remaining, ",") + `]}`
	if _, err := DecodeFixture([]byte(valid)); err != nil {
		t.Fatalf("valid exact fixture rejected: %v", err)
	}

	tests := map[string]string{
		"unknown field":  strings.Replace(valid, `"schema":`, `"unknown":true,"schema":`, 1),
		"duplicate key":  strings.Replace(valid, `"schema":`, `"schema":"round8-balanced-readmission/v1","schema":`, 1),
		"trailing value": valid + `{}`,
		"privacy canary": strings.Replace(valid, "ordinary benign text", "contact user@example.test", 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeFixture([]byte(raw)); err == nil {
				t.Fatal("invalid fixture was accepted")
			}
		})
	}
}

func TestGeneratePairedVariantsIsDeterministicAndOneSlot(t *testing.T) {
	document, err := LoadFixture("../../testdata/round8_balanced_readmission.json")
	if err != nil {
		t.Fatal(err)
	}
	first, err := GeneratePairedVariants(document, VariantSeed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePairedVariants(document, VariantSeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != FixturePairCount*VariantsPerFamily || len(second) != len(first) {
		t.Fatalf("variant counts=%d/%d, want %d", len(first), len(second), FixturePairCount*VariantsPerFamily)
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("fixed seed changed variant %d: %#v != %#v", index, first[index], second[index])
		}
		if err := ValidateMutationVariant(first[index]); err != nil {
			t.Fatalf("variant %s: %v", first[index].Name, err)
		}
	}
}
