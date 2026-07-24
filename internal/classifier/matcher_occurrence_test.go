package classifier

import "testing"

func buildOccurrenceTestMatcher(literal string, signalID int) *literalMatcher {
	builder := newMatcherBuilder()
	builder.add(literal, isASCII(literal), signalID)
	return builder.build()
}

func TestMatcherOccurrenceBudgetDeduplicatesStandardAndCompactViews(t *testing.T) {
	standard := buildOccurrenceTestMatcher("steal", 0)
	compact := buildOccurrenceTestMatcher("steal", 0)
	text := []rune("steal")
	signals := make([]bool, 1)
	occurrences := make([]signalOccurrence, 0, 1)

	var overflow bool
	occurrences, overflow = standard.matchWithOccurrences(text, signals, occurrences, 1)
	if overflow || len(occurrences) != 1 || occurrences[0].compact {
		t.Fatalf("standard occurrence=%+v overflow=%t, want one non-compact proof", occurrences, overflow)
	}
	occurrences, overflow = compact.matchCompactOccurrencesWithScratch(
		text, signals, nil, nil, occurrences, 1,
	)
	if overflow || len(occurrences) != 1 || occurrences[0].compact {
		t.Fatalf("duplicate compact occurrence=%+v overflow=%t, want the original physical proof only", occurrences, overflow)
	}
}

func TestMatcherOccurrenceBudgetOverflowsOnlyForNewPhysicalProof(t *testing.T) {
	standard := buildOccurrenceTestMatcher("steal", 0)
	compact := buildOccurrenceTestMatcher("cookie", 1)
	text := []rune("steal cookie")
	signals := make([]bool, 2)
	occurrences := make([]signalOccurrence, 0, 1)

	occurrences, overflow := standard.matchWithOccurrences(text, signals, occurrences, 1)
	if overflow || len(occurrences) != 1 {
		t.Fatalf("standard occurrence=%+v overflow=%t, want one proof", occurrences, overflow)
	}
	occurrences, overflow = compact.matchCompactOccurrencesWithScratch(
		text, signals, nil, nil, occurrences, 1,
	)
	if !overflow || len(occurrences) != 1 || !signals[1] {
		t.Fatalf("new compact proof occurrence=%+v overflow=%t signals=%v, want overflow with signal retained", occurrences, overflow, signals)
	}
}

func TestSignalOccurrenceLookupUsesFullPhysicalIdentity(t *testing.T) {
	existing := []signalOccurrence{{signalID: 7, clauseID: 3, start: 11, end: 19}}
	var lookup signalOccurrenceLookup
	lookup.seed(existing, maxEvidenceOccurrencesPerClause)

	for _, testCase := range []struct {
		name      string
		candidate signalOccurrence
		duplicate bool
	}{
		{name: "compact bit ignored", candidate: signalOccurrence{signalID: 7, clauseID: 3, start: 11, end: 19, compact: true}, duplicate: true},
		{name: "different signal", candidate: signalOccurrence{signalID: 8, clauseID: 3, start: 11, end: 19}},
		{name: "different clause", candidate: signalOccurrence{signalID: 7, clauseID: 4, start: 11, end: 19}},
		{name: "different start", candidate: signalOccurrence{signalID: 7, clauseID: 3, start: 12, end: 19}},
		{name: "different end", candidate: signalOccurrence{signalID: 7, clauseID: 3, start: 11, end: 20}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			duplicate, _ := lookup.duplicateOrSlot(existing, testCase.candidate)
			if duplicate != testCase.duplicate {
				t.Fatalf("duplicate=%t, want %t for %+v", duplicate, testCase.duplicate, testCase.candidate)
			}
		})
	}
}

func TestSignalOccurrenceLookupComparesKeysAfterHashCollision(t *testing.T) {
	var first, second signalOccurrence
	found := false
	seen := make(map[uint32]signalOccurrence, signalOccurrenceLookupCapacity)
	for signalID := int32(0); signalID < signalOccurrenceLookupCapacity*4; signalID++ {
		candidate := signalOccurrence{signalID: signalID, clauseID: 1, start: signalID + 2, end: signalID + 5}
		slot := signalOccurrenceHash(candidate) % signalOccurrenceLookupCapacity
		if prior, ok := seen[slot]; ok && !sameSignalOccurrenceIdentity(prior, candidate) {
			first, second, found = prior, candidate, true
			break
		}
		seen[slot] = candidate
	}
	if !found {
		t.Fatal("failed to construct a deterministic lookup collision")
	}

	existing := []signalOccurrence{first}
	var lookup signalOccurrenceLookup
	lookup.seed(existing, maxEvidenceOccurrencesPerClause)
	duplicate, _ := lookup.duplicateOrSlot(existing, second)
	if duplicate {
		t.Fatalf("hash collision incorrectly deduplicated distinct keys: first=%+v second=%+v", first, second)
	}
}
