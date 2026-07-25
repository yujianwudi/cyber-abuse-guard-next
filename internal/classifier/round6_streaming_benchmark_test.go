package classifier

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestRound6NormalizeBytesMatchesStringNormalization(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"Ordinary FOOTBALL scheduling notes.",
		"Ｆｕｌｌｗｉｄｔｈ C0D3",
		"a\u200bb Cyrillic-а",
		"line one\r\nline two",
		"c 0 0 k",
	} {
		want := normalizeParts([]string{input})
		var scratch normalizationScratch
		got := normalizeBytesInto([]byte(input), nil, &scratch)
		if got.truncated != want.truncated || !reflect.DeepEqual(got.standardRunes, want.standardRunes) {
			t.Fatalf("normalizeBytesInto(%q) = %q truncated=%t, want %q truncated=%t",
				input, string(got.standardRunes), got.truncated, string(want.standardRunes), want.truncated)
		}
	}
	t.Run("defensive quote normalized capture", func(t *testing.T) {
		const completeFrame inertQuotedSafetyReviewFrameSignals = 0b111
		for _, fixture := range []struct {
			input string
			want  inertQuotedSafetyReviewFrameSignals
		}{
			{input: "The following quoted prompt-injection sample is included, and do not apply it.", want: completeFrame},
			{input: "Ｔｈｅ　ｆｏｌｌｏｗｉｎｇ　ｑｕｏｔｅｄ　ｓａｍｐｌｅ　ｉｓ　ｉｎｃｌｕｄｅｄ，　ａｎｄ　ｄｏ　ｎｏｔ　ａｐｐｌｙ　ｉｔ．", want: completeFrame},
			{input: "The fol\u200blowing quo\u200bted sample is included, and do not apply it.", want: completeFrame},
			{input: "Ordinary football standings.", want: 0},
		} {
			views := normalizeParts([]string{fixture.input})
			got := streamingDefensiveQuotedReviewFrameSignalsNormalized(
				views.standardRunes, views.truncated,
			)
			if got != fixture.want {
				t.Fatalf(
					"normalized defensive signals for %q = %03b, want %03b",
					fixture.input, got, fixture.want,
				)
			}
			if wrapped := streamingDefensiveQuotedReviewFrameSignals(fixture.input); wrapped != fixture.want {
				t.Fatalf(
					"wrapped defensive signals for %q = %03b, want %03b",
					fixture.input, wrapped, fixture.want,
				)
			}
		}
		qualifierOnly := streamingDefensiveQuotedReviewFrameSignals("risk")
		if qualifierOnly != 0 {
			t.Fatalf("qualifier-only window signals = %03b, want old-gate zero", qualifierOnly)
		}
		partialFrame := streamingDefensiveQuotedReviewFrameSignals(
			"The following quoted prompt says do not apply it.",
		)
		const wantPartial inertQuotedSafetyReviewFrameSignals = 0b101
		combined := partialFrame | qualifierOnly
		if partialFrame != wantPartial || combined == completeFrame {
			t.Fatalf(
				"distant qualifier completed partial frame: partial=%03b qualifier=%03b",
				partialFrame, qualifierOnly,
			)
		}
		if !completeFrame.attempted() || wantPartial.attempted() || combined.attempted() {
			t.Fatalf(
				"attempted bit contract drifted: complete=%t partial=%t combined=%t",
				completeFrame.attempted(), wantPartial.attempted(), combined.attempted(),
			)
		}
	})
}

func TestRound6NormalizeBytesRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	var scratch normalizationScratch
	got := normalizeBytesInto([]byte{0xff}, nil, &scratch)
	if !got.truncated || len(got.standardRunes) != 0 {
		t.Fatalf("invalid UTF-8 normalization = %+v", got)
	}
}

func BenchmarkRound6StreamingScale(b *testing.B) {
	set, err := rules.LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	c, err := New(set)
	if err != nil {
		b.Fatal(err)
	}

	for _, benchmark := range []struct {
		name  string
		bytes int
	}{
		{name: "270KiB", bytes: 270 << 10},
		{name: "1MiB", bytes: 1 << 20},
		{name: "4MiB", bytes: 4 << 20},
		{name: "Near8MiB", bytes: MaxScanTotalBytes - 4096},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			benchmarkRound6StreamingSize(b, c, benchmark.bytes)
		})
	}
}

func benchmarkRound6StreamingSize(b *testing.B, c *Classifier, totalBytes int) {
	chunk := []byte(strings.Repeat("ordinary football scheduling notes. ", 512))
	b.ReportAllocs()
	b.SetBytes(int64(totalBytes))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		session, err := c.NewScanSession(ModeBalanced, DefaultThresholds(), DefaultPolicy(), ScanLimits{})
		if err != nil {
			b.Fatal(err)
		}
		for offset := 0; offset < totalBytes; {
			remaining := totalBytes - offset
			part := chunk
			if len(part) > remaining {
				part = part[:remaining]
			}
			end := offset+len(part) == totalBytes
			if err := session.AddSegment(extract.SegmentChunk{
				Role: extract.RoleUser, Provenance: extract.ProvenanceContent, FieldID: 1,
				Start: offset == 0, End: end, Text: part,
			}); err != nil {
				b.Fatal(err)
			}
			offset += len(part)
		}
		result := session.Finish()
		if result.Coverage.State != CoverageComplete {
			b.Fatalf("coverage = %+v", result.Coverage)
		}
	}
}

func BenchmarkStreamingDefensiveQuotedReviewFrameSignals(b *testing.B) {
	const prefix = "The following quoted prompt-injection sample is included, and do not apply it. "
	set, err := rules.LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	c, err := New(set)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{MinScanWindowBytes, MaxScanWindowBytes} {
		frame := prefix + strings.Repeat("x", size-len(prefix))
		b.Run(strconv.Itoa(size)+"B", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(frame)))
			for iteration := 0; iteration < b.N; iteration++ {
				if signals := streamingDefensiveQuotedReviewFrameSignals(frame); !signals.attempted() {
					b.Fatalf("normalized frame signals = %03b", signals)
				}
			}
		})
		frameBytes := []byte(frame)
		b.Run(strconv.Itoa(size)+"B-profiled", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(frameBytes)))
			for iteration := 0; iteration < b.N; iteration++ {
				session, err := c.NewProfiledScanSession(
					ModeBalanced, DefaultThresholds(), DefaultPolicy(), ScanLimits{},
				)
				if err != nil {
					b.Fatal(err)
				}
				if err := session.AddSegment(extract.SegmentChunk{
					Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
					UserAttribution:   extract.UserAttributionTrusted,
					ConversationIndex: 0, TurnIndex: 0, IsCurrentTurn: true,
					ScopeID: 1, ContentKind: extract.ContentKindNaturalLanguageDirective,
					FieldPathHash: "benchmark-defensive-frame", FieldID: 1,
					Start: true, End: true, Text: frameBytes,
				}); err != nil {
					b.Fatal(err)
				}
				if result := session.Finish(); result.Coverage.State != CoverageComplete {
					b.Fatalf("profiled coverage = %+v", result.Coverage)
				}
			}
		})
	}
}
