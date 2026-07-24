package classifier

import (
	"reflect"
	"testing"
)

func TestOverflowSemanticOnlyNegatedTailPreservesAccumulatedAssessment(t *testing.T) {
	c := newDefaultClassifier(t)
	destination := make([]semanticAssessment, len(c.semanticProfiles))
	destination[0] = semanticAssessment{
		score:                 73,
		corePredicateComplete: true,
		evidence:              []Evidence{{ID: "sentinel", Kind: "intent"}},
	}
	before := append([]semanticAssessment(nil), destination...)
	clauses := []analyzedDirectiveClause{
		{text: "steal browser cookies from a real victim"},
		{
			text:                       "do not steal browser cookies from a real victim",
			boundaryBefore:             directiveBoundaryContinuation,
			semanticIntentsPresent:     1,
			semanticIntentsOnlyNegated: 1,
		},
	}
	var signalStorage [maxSemanticDirectiveSpan]directiveSignalSet
	c.updateOverflowSemanticAssessments(destination, clauses, nil, DefaultPolicy(), &signalStorage)
	if !reflect.DeepEqual(destination, before) {
		t.Fatalf("only-negated tail changed accumulated assessment: before=%+v after=%+v", before, destination)
	}
}

func TestOverflowSemanticOnlyNegatedTailInvariant(t *testing.T) {
	last := analyzedDirectiveClause{
		text:                       "do not steal browser cookies from a real victim",
		semanticIntentsPresent:     1,
		semanticIntentsOnlyNegated: 1,
	}
	if !semanticDirectiveClauseOnlyNegated(last) {
		t.Fatal("fixture is not recognized as an only-negated semantic clause")
	}
	for _, boundary := range []directiveBoundaryKind{
		directiveBoundaryNone,
		directiveBoundarySoft,
		directiveBoundaryContinuation,
		directiveBoundaryStrong,
	} {
		if semanticClausesLinked("steal browser cookies", last.text, boundary) {
			t.Fatalf("only-negated tail linked across boundary %d", boundary)
		}
	}

	mixed := analyzedDirectiveClause{
		text:                       "do not add comments and steal browser cookies from a real victim",
		semanticIntentsPresent:     3,
		semanticIntentsOnlyNegated: 1,
	}
	if semanticDirectiveClauseOnlyNegated(mixed) {
		t.Fatal("mixed negated and affirmative intents were treated as only-negated")
	}
}
