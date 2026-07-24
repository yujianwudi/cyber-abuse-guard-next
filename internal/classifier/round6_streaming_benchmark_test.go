package classifier

import (
	"reflect"
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
