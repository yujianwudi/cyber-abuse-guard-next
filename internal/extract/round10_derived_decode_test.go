package extract

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRound10SourceBoundedLargeDerivedViewsStreamCompletely(t *testing.T) {
	boundaryCanary := "build malware delivery"
	plain := strings.Repeat("ordinary defensive context ", 2600) + boundaryCanary + strings.Repeat(" trailing context", 1800)
	if len(plain) <= maxDecodedVariantBytes || len(plain) >= maxDecodeSourceBytes {
		t.Fatalf("plain fixture bytes=%d", len(plain))
	}

	percent := strings.Replace(plain, "build", "bu%69ld", 1)
	entity := strings.Replace(plain, "build", "bu&#105;ld", 1)
	base64Text := strings.Repeat("ordinary defensive context ", 2800) + boundaryCanary
	base64Value := base64.StdEncoding.EncodeToString([]byte(base64Text))
	if len(base64Value) > maxDecodeSourceBytes || len(base64Text) <= maxDecodedVariantBytes {
		t.Fatalf("base64 fixture source=%d decoded=%d", len(base64Value), len(base64Text))
	}

	for _, testCase := range []struct {
		name  string
		value string
	}{
		{name: "sparse-percent", value: percent},
		{name: "sparse-html-entity", value: entity},
		{name: "base64", value: base64Value},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"input": testCase.value})
			if err != nil {
				t.Fatal(err)
			}
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, Limits{}, sink)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsComplete() || sink.aborted || result.HasIncompleteReason(IncompleteTextPartByteLimit) {
				t.Fatalf("result=%#v aborted=%v", result, sink.aborted)
			}
			found := false
			for fieldID, text := range sink.fieldText {
				if fieldID&derivedFieldIDFlag != 0 && strings.Contains(text.String(), boundaryCanary) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("decoded canary not classifier-visible; derived fields=%d", len(sink.fieldText))
			}
		})
	}
}

func TestRound10DerivedLocalDecodeWindowPreservesFencedFieldMetadata(t *testing.T) {
	t.Parallel()

	outside := strings.Repeat("review-only surrounding context\n", 180)
	code := strings.Repeat("x", ClassificationOverlapReserveBytes+256) +
		" bu%69ld malware " + strings.Repeat("y", ClassificationOverlapReserveBytes+256)
	prompt := outside + "```python\n" + code + "\n```\n" + outside
	windows, sparse := sparseEncodedWindows(prompt)
	if !sparse || len(windows) != 1 || windows[0].start == 0 || windows[0].end == len(prompt) {
		t.Fatalf("windows=%#v sparse=%t, want one local decode window", windows, sparse)
	}

	fields := round8ScanContentKindFields(
		t, SourceProfileOpenAI, round8ContentKindBody(t, "openai", prompt),
		Limits{MaxTextPartBytes: 2048},
	)
	var source, derived *round8ContentKindField
	for index := range fields {
		field := &fields[index]
		switch {
		case strings.Contains(field.text.String(), "bu%69ld malware"):
			source = field
		case strings.Contains(field.text.String(), "build malware"):
			derived = field
		}
	}
	if source == nil || derived == nil {
		t.Fatalf("source=%v derived=%v fields=%s", source != nil, derived != nil, round8DescribeContentKindFields(fields))
	}
	if derived.id == source.id || source.kind != ContentKindCodeBlock || derived.kind != source.kind ||
		derived.role != source.role || derived.provenance != source.provenance ||
		derived.userAttribution != source.userAttribution ||
		derived.conversationIndex != source.conversationIndex || derived.turnIndex != source.turnIndex ||
		derived.isCurrentTurn != source.isCurrentTurn || derived.scopeID != source.scopeID ||
		derived.fieldPathHash == "" || derived.fieldPathHash != source.fieldPathHash {
		t.Fatalf("derived local window lost parent metadata: source=%s derived=%s",
			round8DescribeContentKindFields([]round8ContentKindField{*source}),
			round8DescribeContentKindFields([]round8ContentKindField{*derived}))
	}
}

func TestRound10SparseMixedBinaryPercentEscapesExposeCanonicalText(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		text string
		want string
	}{
		{name: "nul separator", text: "bu%69ld%00malware", want: "build malware"},
		{name: "nul plus entity", text: "build%00malware&amp;", want: "build malware&"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			variants, ok := decodeSparseMixedWindow(testCase.text)
			if !ok || !containsDecodedVariant(variants, testCase.want) {
				t.Fatalf("decodeSparseMixedWindow(%q) = %#v, ok=%t, want canonical %q", testCase.text, variants, ok, testCase.want)
			}
			for _, variant := range variants {
				if !isInspectableDecodedText([]byte(variant)) {
					t.Fatalf("variant is not inspectable UTF-8: %q", variant)
				}
			}
		})
	}

	if variants, ok := decodeSparseMixedWindow("bu%69ld\x00malware"); ok || len(variants) != 0 {
		t.Fatalf("literal source control must remain fail-closed: variants=%#v ok=%t", variants, ok)
	}
}

func TestRound10InvalidUTF8PercentEscapesRemainIncomplete(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name string
		text string
	}{
		{name: "sparse", text: "bu%69ld%c0%afmalware"},
		{name: "sparse plus entity", text: "bu%69ld%c0%afmalware&amp;"},
		{name: "dense", text: strings.Repeat("%c0%af", 128)},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if variants, ok := decodeSparseMixedWindow(testCase.text); ok || len(variants) != 0 {
				t.Fatalf("decodeSparseMixedWindow(%q) = %#v, ok=%t, want fail-closed", testCase.text, variants, ok)
			}
			windows, sparse := sparseEncodedWindows(testCase.text)
			_, exactEncoded, exactIncomplete := decodeBoundedTextExact(testCase.text)
			_, encoded, incomplete := decodeBoundedText(testCase.text)
			if !encoded || !incomplete {
				t.Fatalf("decodeBoundedText(%q) encoded=%t incomplete=%t sparse=%t windows=%#v exact=%t/%t, want invalid UTF-8 incomplete",
					testCase.text, encoded, incomplete, sparse, windows, exactEncoded, exactIncomplete)
			}
		})
	}
}

func TestRound10InvalidUTF8CompletenessDoesNotDependOnFieldPadding(t *testing.T) {
	t.Parallel()
	short := "bu%69ld%c0%afmalware"
	prefix := strings.Repeat("ordinary defensive source documentation ", 1900)
	suffix := strings.Repeat(" trailing repository reference", 1700)
	value := prefix + short + suffix + " deploy%20ransomware"
	if len(value) <= maxDecodedVariantBytes || len(value) >= maxDecodeSourceBytes {
		t.Fatalf("fixture bytes=%d, want large source-bounded document", len(value))
	}
	windows, sparse := sparseEncodedWindows(value)
	if !sparse || len(windows) < 2 {
		t.Fatalf("sparse=%t windows=%#v", sparse, windows)
	}

	for name, candidate := range map[string]string{"short": short, "padded": value} {
		variants, encoded, incomplete := decodeBoundedText(candidate)
		if !encoded || !incomplete {
			t.Fatalf("%s variants=%d encoded=%t incomplete=%t, want invariant invalid UTF-8 fail-closed",
				name, len(variants), encoded, incomplete)
		}
		body, err := json.Marshal(map[string]string{"input": candidate})
		if err != nil {
			t.Fatal(err)
		}
		for _, partBytes := range []int{1024, DefaultMaxTextPartBytes} {
			sink := newRound6RecordingSink()
			result, err := ScanProfiledRequest(
				body, round6JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse},
				Limits{MaxTextPartBytes: partBytes}, sink,
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || !sink.aborted || !result.HasIncompleteReason(IncompleteTextPartByteLimit) {
				t.Fatalf("%s MaxTextPartBytes=%d result=%#v aborted=%t, want decode fail-closed",
					name, partBytes, result, sink.aborted)
			}
		}
	}
}

func TestRound10SparseRecoveryCannotClearNestedDataURLLayerLimit(t *testing.T) {
	t.Parallel()
	payload := "deploy ransomware against production endpoints"
	value := "d%2561ta:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(payload))
	variants, encoded, incomplete := decodeBoundedText(value)
	if !encoded || !incomplete {
		t.Fatalf("variants=%#v encoded=%t incomplete=%t, want third-layer fail-closed", variants, encoded, incomplete)
	}
	for _, variant := range variants {
		if strings.Contains(variant, payload) {
			t.Fatalf("third-layer payload was incorrectly declared covered: %q", variant)
		}
	}
}

func TestRound10SparsePrefixCannotHideWholeBase64Envelope(t *testing.T) {
	t.Parallel()
	canary := "build malware delivery"
	plain := strings.Repeat("ordinary context ", 5000) + canary
	base64Value := base64.StdEncoding.EncodeToString([]byte(plain))
	if len(base64Value) <= maxDecodedVariantBytes || len(base64Value) >= maxDecodeSourceBytes || base64Value[0] != 'b' {
		t.Fatalf("unexpected fixture: source=%d first=%q", len(base64Value), base64Value[0])
	}
	for name, value := range map[string]string{
		"percent": "%62" + base64Value[1:],
		"entity":  "&#98;" + base64Value[1:],
	} {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			variants, encoded, incomplete := decodeBoundedText(value)
			if !encoded || incomplete {
				firstSteps, firstRecognized, firstLimited := decodeOneLayer(value)
				canonical, _, _ := decodeSparseCanonicalLayerBounded(value, false, false, maxDecodeSourceBytes)
				secondSteps, secondRecognized, secondLimited := decodeOneLayer(canonical)
				t.Fatalf("variants=%d bytes=%v encoded=%t incomplete=%t first=%d/%t/%t second=%d/%t/%t canonical=%d whole=%t",
					len(variants), decodedVariantLengths(variants), encoded, incomplete,
					len(firstSteps), firstRecognized, firstLimited,
					len(secondSteps), secondRecognized, secondLimited, len(canonical),
					sparseSourceMayBecomeWholeEnvelope(value))
			}
			found := false
			for _, variant := range variants {
				found = found || strings.Contains(variant, canary)
			}
			if !found {
				t.Fatalf("whole-envelope canary was not decoded across %d variants", len(variants))
			}
		})
	}
}

func decodedVariantLengths(variants []string) []int {
	lengths := make([]int, len(variants))
	for index, variant := range variants {
		lengths[index] = len(variant)
	}
	return lengths
}

func TestRound10ControlEscapesCannotSplitWordsInsideLargeSparseSource(t *testing.T) {
	t.Parallel()
	short := "de%00ploy rans%00omware across production endpoints"
	shortVariants, encoded, incomplete := decodeBoundedText(short)
	if !encoded || incomplete || !containsDecodedVariant(shortVariants, "deploy ransomware across production endpoints") {
		t.Fatalf("short mixed control envelope variants=%#v encoded=%t incomplete=%t, want bounded recovery",
			shortVariants, encoded, incomplete)
	}

	value := strings.Repeat("ordinary defensive source ", 1900) + short +
		strings.Repeat(" trailing documentation ", 1900) + " bu%69ld"
	if len(value) <= maxDecodedVariantBytes || len(value) >= maxDecodeSourceBytes {
		t.Fatalf("large sparse fixture bytes=%d", len(value))
	}
	variants, encoded, incomplete := decodeBoundedText(value)
	if !encoded || incomplete {
		t.Fatalf("variants=%d encoded=%t incomplete=%t", len(variants), encoded, incomplete)
	}
	found := false
	for _, variant := range variants {
		found = found || strings.Contains(variant, "deploy ransomware across production endpoints")
	}
	if !found {
		t.Fatalf("control-byte deletion interpretation missing across %d variants", len(variants))
	}
}

func TestRound10DistinctSparseExplanationsOverBudgetRemainIncomplete(t *testing.T) {
	t.Parallel()

	separator := strings.Repeat(" ordinary source documentation ", 340)
	encodedChunk := "alpha%2520beta+gamma"
	value := strings.Join([]string{
		encodedChunk, encodedChunk, encodedChunk,
		encodedChunk, encodedChunk, encodedChunk,
	}, separator)
	if len(value) >= maxDecodeSourceBytes {
		t.Fatalf("fixture bytes=%d, want source-bounded input", len(value))
	}
	windows, sparse := sparseEncodedWindows(value)
	if !sparse || len(windows) < 5 || sparseWindowsNeedWholeSource(windows) {
		t.Fatalf("windows=%#v sparse=%t, want local-window path before aggregate fallback", windows, sparse)
	}

	variants, encoded, incomplete := decodeBoundedText(value)
	if !encoded || !incomplete || len(variants) != maxDecodedVariants {
		t.Fatalf("variants=%d encoded=%t incomplete=%t, want fail-closed distinct-view drop",
			len(variants), encoded, incomplete)
	}
	totalBytes := 0
	found := false
	unique := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		totalBytes += len(variant)
		found = found || strings.Contains(variant, "alpha beta gamma")
		unique[variant] = struct{}{}
	}
	if totalBytes > maxDecodedTotalBytes || !found || len(unique) != len(variants) {
		t.Fatalf("derived bytes=%d found=%t variants=%d unique=%d", totalBytes, found, len(variants), len(unique))
	}
}

func TestRound10RepeatedSparseWindowViewsConsumeGlobalVariantBudget(t *testing.T) {
	t.Parallel()

	const windowText = "alpha%2520beta"
	var source strings.Builder
	windows := make([]decodedWindowSpan, 0, 5)
	for index := 0; index < 5; index++ {
		if index != 0 {
			source.WriteString(" ordinary separator ")
		}
		start := source.Len()
		source.WriteString(windowText)
		windows = append(windows, decodedWindowSpan{start: start, end: source.Len()})
	}

	views, encoded, incomplete := decodeSparseEncodedWindowViews(source.String(), windows)
	if !encoded || !incomplete || len(views) != maxDecodedVariants {
		t.Fatalf("views=%d encoded=%t incomplete=%t, want every source window charged until fail-closed count limit",
			len(views), encoded, incomplete)
	}
	for index, view := range views {
		wantSpan := windows[index/2]
		if view.sourceStart != wantSpan.start || view.sourceEnd != wantSpan.end {
			t.Fatalf("view %d span=%d:%d, want %d:%d", index,
				view.sourceStart, view.sourceEnd, wantSpan.start, wantSpan.end)
		}
		wantText := "alpha%20beta"
		if index%2 != 0 {
			wantText = "alpha beta"
		}
		if view.text != wantText {
			t.Fatalf("view %d text=%q, want %q", index, view.text, wantText)
		}
	}
}

func TestRound10DecodedVariantBudgetExactBoundaries(t *testing.T) {
	t.Parallel()

	var bytesBudget decodedVariantBudget
	for index := 0; index < 4; index++ {
		if !bytesBudget.admit(maxDecodedVariantBytes) {
			t.Fatalf("64 KiB variant %d was rejected: %+v", index, bytesBudget)
		}
	}
	remaining := maxDecodedTotalBytes - 4*maxDecodedVariantBytes
	if remaining <= 0 || !bytesBudget.admit(remaining) ||
		bytesBudget.bytes != maxDecodedTotalBytes || bytesBudget.count != 5 {
		t.Fatalf("exact aggregate boundary rejected: remaining=%d budget=%+v", remaining, bytesBudget)
	}
	before := bytesBudget
	if bytesBudget.admit(1) || bytesBudget != before {
		t.Fatalf("aggregate budget+1 changed budget: before=%+v after=%+v", before, bytesBudget)
	}

	var countBudget decodedVariantBudget
	for index := 0; index < maxDecodedVariants; index++ {
		if !countBudget.admit(1) {
			t.Fatalf("variant %d rejected: %+v", index, countBudget)
		}
	}
	before = countBudget
	if countBudget.admit(1) || countBudget != before {
		t.Fatalf("variant %d changed budget: before=%+v after=%+v",
			maxDecodedVariants+1, before, countBudget)
	}

	for name, size := range map[string]int{
		"zero":                      0,
		"negative":                  -1,
		"single variant over limit": maxDecodedVariantBytes + 1,
	} {
		var budget decodedVariantBudget
		if budget.admit(size) || budget != (decodedVariantBudget{}) {
			t.Fatalf("%s size=%d admitted: %+v", name, size, budget)
		}
	}
}

func TestRound10OversizedBase64SourceRemainsFailClosed(t *testing.T) {
	t.Parallel()

	value := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("ordinary security text ", 5000)))
	if len(value) <= maxDecodeSourceBytes {
		t.Fatalf("fixture bytes=%d, want oversized Base64 source", len(value))
	}
	variants, encoded, incomplete := decodeBoundedText(value)
	if len(variants) != 0 || !encoded || !incomplete {
		t.Fatalf("variants=%d encoded=%t incomplete=%t, want oversized Base64 fail-closed", len(variants), encoded, incomplete)
	}
}

func TestRound10OversizedEncodingProbeDoesNotCopySource(t *testing.T) {
	base64Value := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 2200)
	if len(base64Value) <= maxDecodeSourceBytes || !looksPotentiallyEncodedOversized(base64Value) {
		t.Fatalf("oversized Base64 probe bytes=%d was not recognized", len(base64Value))
	}
	var recognized bool
	benchmark := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			recognized = looksPotentiallyEncodedOversized(base64Value)
		}
	})
	if !recognized || benchmark.AllocedBytesPerOp() > 1024 || benchmark.AllocsPerOp() > 1 {
		t.Fatalf("oversized Base64 probe bytes/op=%d allocs/op=%d recognized=%t, want fixed-size probe state",
			benchmark.AllocedBytesPerOp(), benchmark.AllocsPerOp(), recognized)
	}

	ordinary := strings.Repeat("ordinary repository documentation ", 5000)
	if looksPotentiallyEncodedOversized(ordinary) {
		t.Fatal("ordinary oversized prose was treated as an encoded envelope")
	}
	percent := strings.Repeat("ordinary", 20000) + "%41"
	if !looksPotentiallyEncodedOversized(percent) {
		t.Fatal("oversized percent envelope was not recognized")
	}
}

func containsDecodedVariant(variants []string, want string) bool {
	for _, variant := range variants {
		if variant == want {
			return true
		}
	}
	return false
}

func TestRound10SplitDecodedViewPreservesUTF8BoundaryOverlap(t *testing.T) {
	canary := "构建恶意软件"
	value := strings.Repeat("x", maxDecodedVariantBytes-len(canary)/2) + canary + strings.Repeat("后", 2000)
	fragments := splitDecodedView(value)
	if len(fragments) < 2 {
		t.Fatalf("fragments=%d, want boundary split", len(fragments))
	}
	found := false
	for index, fragment := range fragments {
		if len(fragment) > maxDecodedVariantBytes {
			t.Fatalf("fragment %d bytes=%d", index, len(fragment))
		}
		if !utf8.ValidString(fragment) {
			t.Fatalf("fragment %d is not valid UTF-8", index)
		}
		if index > 0 {
			previous := fragments[index-1]
			maxOverlap := minInt(
				minInt(len(previous), len(fragment)),
				ClassificationOverlapReserveBytes+utf8.UTFMax,
			)
			common := 0
			for size := maxOverlap; size > 0; size-- {
				if strings.HasSuffix(previous, fragment[:size]) {
					common = size
					break
				}
			}
			if common < ClassificationOverlapReserveBytes-utf8.UTFMax {
				t.Fatalf("fragments %d/%d overlap=%d, want UTF-8-safe reserve", index-1, index, common)
			}
		}
		if strings.Contains(fragment, canary) {
			found = true
		}
	}
	if !found {
		t.Fatal("overlap lost UTF-8 canary across derived-view boundary")
	}
}
