package extract

import (
	"bytes"
	"fmt"
	"net/http"
	"net/textproto"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExtractRequestMultipartUnknownFileFieldIsSchemaIncomplete(t *testing.T) {
	const payloadCanary = "ROUND5_PRIVATE_UNKNOWN_FILE_BYTES"
	tests := []struct {
		name       string
		profile    SourceProfile
		part       multipartTestPart
		forbidden  []string
		wantOpaque bool
	}{
		{
			name:       "known profile filename",
			profile:    SourceProfileOpenAIImage,
			part:       multipartTestPart{name: "round5_future_prompt", filename: "round5-private.txt", contentType: "text/plain", value: []byte(payloadCanary)},
			forbidden:  []string{"round5_future_prompt", "round5-private.txt", "text/plain"},
			wantOpaque: true,
		},
		{
			name:       "known profile image MIME",
			profile:    SourceProfileOpenAIImage,
			part:       multipartTestPart{name: "round5_future_image", contentType: "image/x-round5-private", value: []byte(payloadCanary)},
			forbidden:  []string{"round5_future_image", "image/x-round5-private"},
			wantOpaque: true,
		},
		{
			name:       "known profile application MIME",
			profile:    SourceProfileOpenAIImage,
			part:       multipartTestPart{name: "round5_future_binary", contentType: "application/x-round5-private", value: []byte(payloadCanary)},
			forbidden:  []string{"round5_future_binary", "application/x-round5-private"},
			wantOpaque: true,
		},
		{
			name:       "known profile attachment",
			profile:    SourceProfileOpenAIImage,
			part:       multipartTestPart{name: "round5_future_attachment", disposition: `attachment; name="round5_future_attachment"`, contentType: "text/plain", value: []byte(payloadCanary)},
			forbidden:  []string{"round5_future_attachment", "text/plain"},
			wantOpaque: true,
		},
		{
			name:       "known profile unnamed attachment",
			profile:    SourceProfileOpenAIImage,
			part:       multipartTestPart{disposition: `attachment; filename="round5-unnamed-private.bin"`, contentType: "application/octet-stream", value: []byte(payloadCanary)},
			forbidden:  []string{"round5-unnamed-private.bin", "application/octet-stream"},
			wantOpaque: true,
		},
		{
			name:       "known profile empty name",
			profile:    SourceProfileOpenAIImage,
			part:       multipartTestPart{disposition: `form-data; name=""; filename="round5-empty-name.bin"`, contentType: "application/octet-stream", value: []byte(payloadCanary)},
			forbidden:  []string{"round5-empty-name.bin", "application/octet-stream"},
			wantOpaque: true,
		},
		{
			name:    "known profile duplicate Content-Type",
			profile: SourceProfileOpenAIImage,
			part: multipartTestPart{
				name:        "round5_future_duplicate_mime",
				contentType: "image/x-round5-first-private",
				extraHeaders: textproto.MIMEHeader{
					"Content-Type": []string{"application/x-round5-second-private"},
				},
				value: []byte(payloadCanary),
			},
			forbidden: []string{"round5_future_duplicate_mime", "image/x-round5-first-private", "application/x-round5-second-private"},
		},
		{
			name:       "unknown profile known-looking file field",
			profile:    SourceProfileUnknown,
			part:       multipartTestPart{name: "image", filename: "round5-unknown-profile.png", contentType: "image/png", value: []byte(payloadCanary)},
			forbidden:  []string{"round5-unknown-profile.png", "image/png"},
			wantOpaque: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			body, contentType := multipartBody(t, []multipartTestPart{testCase.part})
			result, err := ExtractProfiledRequest(
				body,
				http.Header{"Content-Type": []string{contentType}},
				RequestProfile{Source: testCase.profile},
				Limits{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || !reflect.DeepEqual(result.IncompleteReasons, []IncompleteReason{IncompleteMultipartUnknownField}) {
				t.Fatalf("result=%s, want only multipart_unknown_field", multipartResultSummary(result))
			}
			if result.OpaqueMedia != testCase.wantOpaque {
				t.Fatalf("OpaqueMedia=%t, want %t; kinds=%v", result.OpaqueMedia, testCase.wantOpaque, result.OpaqueMediaKinds)
			}
			if result.TextBytesScanned != 0 || len(result.Parts) != 0 || len(result.Segments) != 0 {
				t.Fatalf("unknown field entered classifier-visible text: %s", multipartResultSummary(result))
			}
			surface := multipartResultSurface(result)
			for _, forbidden := range append(testCase.forbidden, payloadCanary) {
				if forbidden != "" && strings.Contains(surface, forbidden) {
					t.Fatal("result leaked private multipart input")
				}
			}
		})
	}
}

func TestExtractRequestMultipartUnknownFieldPrecedesFileEvidence(t *testing.T) {
	const (
		prompt = "round5 safe visible prompt"
		canary = "ROUND5_PRIVATE_ORDERED_UNKNOWN_BYTES"
	)
	unknown := multipartTestPart{
		name:        "round5_future_prompt",
		filename:    "round5-order-private.txt",
		contentType: "application/octet-stream",
		value:       []byte(canary),
	}
	orders := [][]multipartTestPart{
		{unknown, {name: "prompt", value: []byte(prompt)}},
		{{name: "prompt", value: []byte(prompt)}, unknown},
	}

	var baseline Result
	for index, parts := range orders {
		body, contentType := multipartBody(t, parts)
		result, err := extractOpenAIImageRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
		if err != nil || result.IsComplete() || !result.HasIncompleteReason(IncompleteMultipartUnknownField) {
			t.Fatalf("order %d result=%s err_present=%t", index, multipartResultSummary(result), err != nil)
		}
		if len(result.Parts) != 0 || len(result.Segments) != 0 || result.TextBytesScanned != 0 {
			t.Fatalf("order %d classifier text mismatch: parts=%d bytes=%d", index, len(result.Parts), result.TextBytesScanned)
		}
		if strings.Contains(multipartResultSurface(result), canary) {
			t.Fatalf("order %d leaked unknown payload", index)
		}
		if index == 0 {
			baseline = result
			continue
		}
		if !reflect.DeepEqual(result.Parts, baseline.Parts) ||
			!reflect.DeepEqual(result.Segments, baseline.Segments) ||
			!reflect.DeepEqual(result.IncompleteReasons, baseline.IncompleteReasons) ||
			!reflect.DeepEqual(result.OpaqueMediaKinds, baseline.OpaqueMediaKinds) ||
			result.TextBytesScanned != baseline.TextBytesScanned ||
			result.Completeness != baseline.Completeness ||
			result.OpaqueMedia != baseline.OpaqueMedia {
			t.Fatalf("field order changed multipart semantics: baseline=%s result=%s", multipartResultSummary(baseline), multipartResultSummary(result))
		}
	}
}

func TestExtractRequestMultipartUnnamedAttachmentIsSchemaIncomplete(t *testing.T) {
	body, contentType := multipartBody(t, []multipartTestPart{{
		disposition: `attachment; filename="round5-unnamed-private.bin"`,
		contentType: "application/octet-stream",
		value:       []byte("ROUND5_PRIVATE_UNNAMED_ATTACHMENT_BYTES"),
	}})
	result, err := extractOpenAIImageRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsComplete() || !reflect.DeepEqual(result.IncompleteReasons, []IncompleteReason{IncompleteMultipartUnknownField}) {
		t.Fatalf("unnamed attachment result=%s", multipartResultSummary(result))
	}
	if !result.OpaqueMedia || result.TextBytesScanned != 0 || len(result.Parts) != 0 || len(result.Segments) != 0 {
		t.Fatalf("unnamed attachment did not remain private opaque schema evidence: %s", multipartResultSummary(result))
	}
}

func TestExtractRequestMultipartUnknownFileAllocationsDoNotScaleWithPayload(t *testing.T) {
	if extractRaceEnabled {
		t.Skip("benchmark allocation and retained-heap acceptance is not meaningful under the race detector")
	}
	build := func(fileBytes int) ([]byte, http.Header) {
		body, contentType := multipartBody(t, []multipartTestPart{
			{name: "prompt", value: []byte("round5 safe visible prompt")},
			{name: "round5_future_prompt", filename: "round5-private.bin", contentType: "application/octet-stream", value: bytes.Repeat([]byte{0xa5}, fileBytes)},
		})
		return body, http.Header{"Content-Type": []string{contentType}}
	}
	smallBody, smallHeaders := build(1 << 20)
	largeBody, largeHeaders := build(8 << 20)
	type allocationStats struct {
		elapsed time.Duration
		bytes   int64
		allocs  int64
	}
	measure := func(body []byte, headers http.Header) allocationStats {
		result := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				extracted, err := extractOpenAIImageRequest(body, headers, Limits{})
				if err != nil || extracted.IsComplete() || !extracted.HasIncompleteReason(IncompleteMultipartUnknownField) {
					b.Fatalf("result=%s err_present=%t", multipartResultSummary(extracted), err != nil)
				}
			}
		})
		return allocationStats{
			elapsed: time.Duration(result.NsPerOp()),
			bytes:   result.AllocedBytesPerOp(),
			allocs:  result.AllocsPerOp(),
		}
	}
	small := measure(smallBody, smallHeaders)
	large := measure(largeBody, largeHeaders)
	t.Logf("multipart unknown-file performance 1MiB=%s %d B/op %d allocs/op; 8MiB=%s %d B/op %d allocs/op",
		small.elapsed, small.bytes, small.allocs, large.elapsed, large.bytes, large.allocs)
	if small.elapsed >= 100*time.Millisecond || large.elapsed >= 500*time.Millisecond {
		t.Errorf("multipart unknown-file CPU bound exceeded: 1MiB=%s 8MiB=%s", small.elapsed, large.elapsed)
	}
	if small.bytes >= 512<<10 || large.bytes >= 512<<10 {
		t.Errorf("multipart unknown-file allocation bound exceeded: 1MiB=%d B/op 8MiB=%d B/op", small.bytes, large.bytes)
	}
	if large.bytes > small.bytes+(128<<10) {
		t.Errorf("multipart unknown-file allocated bytes scaled with payload: 1MiB=%d B/op 8MiB=%d B/op", small.bytes, large.bytes)
	}
	if large.allocs > small.allocs+8 {
		t.Errorf("multipart unknown-file allocation count scaled with payload: 1MiB=%d 8MiB=%d", small.allocs, large.allocs)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var retained Result
	for range 16 {
		var err error
		retained, err = extractOpenAIImageRequest(largeBody, largeHeaders, Limits{})
		if err != nil || retained.IsComplete() || !retained.HasIncompleteReason(IncompleteMultipartUnknownField) {
			t.Fatalf("retained-heap probe result=%s err_present=%t", multipartResultSummary(retained), err != nil)
		}
	}
	retained = Result{}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(smallBody)
	runtime.KeepAlive(largeBody)
	retainedDelta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("multipart unknown-file retained_heap_delta=%d bytes after 16 x 8MiB", retainedDelta)
	if retainedDelta > 8<<20 {
		t.Errorf("multipart unknown-file retained heap grew by %d bytes after repeated 8MiB bodies", retainedDelta)
	}
}

func FuzzExtractRequestMultipartUnknownFieldEvidenceOrder(f *testing.F) {
	f.Add(uint8(0), []byte("seed-filename"))
	f.Add(uint8(1), []byte("seed-image-mime"))
	f.Add(uint8(3), []byte("seed-attachment"))
	f.Add(uint8(5), []byte("seed-duplicate-content-type"))
	f.Fuzz(func(t *testing.T, evidence uint8, suffix []byte) {
		if len(suffix) > 32<<10 {
			t.Skip()
		}
		payload := append([]byte("ROUND5_PRIVATE_FUZZ_PAYLOAD_"), suffix...)
		unknown := multipartTestPart{name: "round5_future_prompt", value: payload}
		switch evidence % 7 {
		case 0:
			unknown.filename = "round5-fuzz-private.txt"
			unknown.contentType = "text/plain"
		case 1:
			unknown.contentType = "image/x-round5-fuzz"
		case 2:
			unknown.contentType = "application/octet-stream"
		case 3:
			unknown.disposition = `attachment; name="round5_future_prompt"`
			unknown.contentType = "text/plain"
		case 4:
			unknown.name = ""
			unknown.disposition = `attachment; filename="round5-fuzz-private.bin"`
			unknown.contentType = "application/octet-stream"
		case 5:
			unknown.contentType = "image/x-round5-fuzz-first"
			unknown.extraHeaders = textproto.MIMEHeader{"Content-Type": []string{"application/x-round5-fuzz-second"}}
		case 6:
			unknown.name = ""
			unknown.disposition = `form-data; name=""; filename="round5-fuzz-empty.bin"`
			unknown.contentType = "application/octet-stream"
		}

		orders := [][]multipartTestPart{
			{unknown, {name: "prompt", value: []byte("round5 fuzz safe prompt")}},
			{{name: "prompt", value: []byte("round5 fuzz safe prompt")}, unknown},
		}
		var baseline Result
		for index, parts := range orders {
			body, contentType := multipartBody(t, parts)
			result, err := extractOpenAIImageRequest(body, http.Header{"Content-Type": []string{contentType}}, Limits{MaxRawBytes: 128 << 10})
			if err != nil || result.IsComplete() || !reflect.DeepEqual(result.IncompleteReasons, []IncompleteReason{IncompleteMultipartUnknownField}) {
				t.Fatalf("order=%d evidence=%d result=%s err_present=%t", index, evidence, multipartResultSummary(result), err != nil)
			}
			if strings.Contains(multipartResultSurface(result), "ROUND5_PRIVATE_FUZZ_PAYLOAD_") {
				t.Fatalf("order=%d evidence=%d leaked fuzz payload", index, evidence)
			}
			if index == 0 {
				baseline = result
				continue
			}
			if !reflect.DeepEqual(result.Parts, baseline.Parts) ||
				!reflect.DeepEqual(result.IncompleteReasons, baseline.IncompleteReasons) ||
				!reflect.DeepEqual(result.OpaqueMediaKinds, baseline.OpaqueMediaKinds) ||
				result.TextBytesScanned != baseline.TextBytesScanned ||
				result.Completeness != baseline.Completeness ||
				result.OpaqueMedia != baseline.OpaqueMedia {
				t.Fatalf("evidence=%d field order changed result: baseline=%s result=%s", evidence, multipartResultSummary(baseline), multipartResultSummary(result))
			}
		}
	})
}

func BenchmarkMultipartUnknownFileField1MiB(b *testing.B) {
	benchmarkMultipartUnknownFileField(b, 1<<20)
}

func BenchmarkMultipartUnknownFileField8MiB(b *testing.B) {
	benchmarkMultipartUnknownFileField(b, 8<<20)
}

func benchmarkMultipartUnknownFileField(b *testing.B, payloadBytes int) {
	body, contentType := multipartBody(b, []multipartTestPart{
		{name: "prompt", value: []byte("round5 benchmark safe prompt")},
		{name: "round5_future_prompt", filename: "round5-private.bin", contentType: "application/octet-stream", value: bytes.Repeat([]byte{0xa5}, payloadBytes)},
	})
	headers := http.Header{"Content-Type": []string{contentType}}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, err := extractOpenAIImageRequest(body, headers, Limits{})
		if err != nil || result.IsComplete() || !result.HasIncompleteReason(IncompleteMultipartUnknownField) {
			b.Fatalf("result=%s err_present=%t", multipartResultSummary(result), err != nil)
		}
	}
}

func multipartResultSurface(result Result) string {
	var surface strings.Builder
	for _, part := range result.Parts {
		surface.WriteString(part)
		surface.WriteByte('\n')
	}
	for _, segment := range result.Segments {
		surface.WriteString(segment.Text)
		surface.WriteByte('\n')
	}
	surface.WriteString(result.ParseError)
	for _, kind := range result.OpaqueMediaKinds {
		surface.WriteString(string(kind))
		surface.WriteByte('\n')
	}
	return surface.String()
}

func multipartResultSummary(result Result) string {
	return fmt.Sprintf(
		"complete=%t reasons=%v parts=%d segments=%d scanned=%d opaque=%t kinds=%v",
		result.IsComplete(),
		result.IncompleteReasons,
		len(result.Parts),
		len(result.Segments),
		result.TextBytesScanned,
		result.OpaqueMedia,
		result.OpaqueMediaKinds,
	)
}
