package extract

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExtractRequestScalarMediaCarrierMemberOrderInvariant(t *testing.T) {
	const (
		carrier = "https://example.test/private-media-canary"
		caption = "safe visible caption"
	)
	markers := []struct {
		name   string
		member string
	}{
		{name: "image", member: `"type":"image"`},
		{name: "input image", member: `"type":"input_image"`},
		{name: "image URL", member: `"type":"image_url"`},
		{name: "input audio", member: `"type":"input_audio"`},
		{name: "input file", member: `"type":"input_file"`},
		{name: "MIME type", member: `"mime_type":"image/png"`},
		{name: "media type", member: `"media_type":"image/jpeg"`},
	}
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		for _, marker := range markers {
			t.Run(key+"/"+marker.name, func(t *testing.T) {
				assertScalarMediaPermutations(t, key, carrier, marker.member, caption)
			})
		}
	}
}

func TestExtractRequestConflictingMediaMarkersAreOrderInvariant(t *testing.T) {
	t.Parallel()
	const carrier = "https://example.test/private-media-canary"
	tests := []struct {
		name   string
		bodies [][]byte
		want   OpaqueMediaKind
	}{
		{
			name: "ordinary media frame",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","mime_type":"audio/wav","url":"` + carrier + `"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","type":"image","url":"` + carrier + `"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"url":"` + carrier + `","type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"url":"` + carrier + `","mime_type":"audio/wav","type":"image"}]}]}`),
			},
			want: OpaqueMediaRemoteURL,
		},
		{
			name: "ordinary inherited source frame",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"image":{"type":"image","mime_type":"audio/wav","source":{"url":"` + carrier + `"}}}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"image":{"mime_type":"audio/wav","type":"image","source":{"url":"` + carrier + `"}}}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"image":{"source":{"url":"` + carrier + `"},"type":"image","mime_type":"audio/wav"}}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"image":{"source":{"url":"` + carrier + `"},"mime_type":"audio/wav","type":"image"}}]}]}`),
			},
			want: OpaqueMediaRemoteURL,
		},
		{
			name: "tool media frame",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"type":"image","mime_type":"audio/wav","source":{"url":"` + carrier + `"}}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"mime_type":"audio/wav","type":"image","source":{"url":"` + carrier + `"}}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"url":"` + carrier + `"},"type":"image","mime_type":"audio/wav"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"url":"` + carrier + `"},"mime_type":"audio/wav","type":"image"}}}}]}]}`),
			},
			want: OpaqueMediaRemoteURL,
		},
		{
			name: "ordinary object payload",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","data":{},"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","data":{},"type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"data":{},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"data":{},"mime_type":"audio/wav","type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","wrapper":{"data":{}},"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","wrapper":{"data":{}},"type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"data":{}},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"data":{}},"mime_type":"audio/wav","type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"bytes":{}},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"blob":{}},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"binary":{}},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"outer":{"inner":{"data":{}}},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","wrapper":[{"data":{}}],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":[{"data":{}}],"type":"image","mime_type":"audio/wav"}]}]}`),
			},
			want: OpaqueMediaOther,
		},
		{
			name: "ordinary array payload",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","data":[],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","data":[],"type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"data":[],"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"data":[],"mime_type":"audio/wav","type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","wrapper":{"data":[]},"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","wrapper":{"data":[]},"type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"data":[]},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"data":[]},"mime_type":"audio/wav","type":"image"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"bytes":[]},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"blob":[]},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"binary":[]},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"outer":{"inner":{"data":[]}},"type":"image","mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","wrapper":[{"data":[]}],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"wrapper":[{"data":[]}],"type":"image","mime_type":"audio/wav"}]}]}`),
			},
			want: OpaqueMediaOther,
		},
		{
			name: "tool object and array payload",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"type":"image","data":{},"mime_type":"audio/wav"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"mime_type":"audio/wav","data":{},"type":"image"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"data":[],"type":"image","mime_type":"audio/wav"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"data":[],"mime_type":"audio/wav","type":"image"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"type":"image","wrapper":{"data":{}},"mime_type":"audio/wav"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"mime_type":"audio/wav","wrapper":{"data":{}},"type":"image"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"wrapper":{"data":{}},"type":"image","mime_type":"audio/wav"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"wrapper":{"data":{}},"mime_type":"audio/wav","type":"image"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"type":"image","wrapper":{"data":[]},"mime_type":"audio/wav"}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"wrapper":{"data":[]},"type":"image","mime_type":"audio/wav"}}}}]}]}`),
			},
			want: OpaqueMediaOther,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var baseline Result
			for index, body := range testCase.bodies {
				result := extractRound5ScalarRequest(t, body, Limits{})
				if !reflect.DeepEqual(result.OpaqueMediaKinds, []OpaqueMediaKind{testCase.want}) {
					t.Fatalf("permutation %d conflicting marker kinds=%v, want fixed %s", index, result.OpaqueMediaKinds, testCase.want)
				}
				if index == 0 {
					baseline = result
					continue
				}
				if !reflect.DeepEqual(result.Parts, baseline.Parts) ||
					!reflect.DeepEqual(result.Segments, baseline.Segments) ||
					result.TextBytesScanned != baseline.TextBytesScanned ||
					result.Completeness != baseline.Completeness ||
					!reflect.DeepEqual(result.OpaqueMediaKinds, baseline.OpaqueMediaKinds) {
					t.Fatalf("permutation %d changed conflicting media semantics:\nbase=%#v\ngot=%#v", index, baseline, result)
				}
			}
		})
	}
}

func TestExtractRequestInheritedMediaKindUsesChildExplicitMarker(t *testing.T) {
	t.Parallel()
	const carrier = "https://example.test/child-audio-canary"
	tests := []struct {
		name   string
		bodies [][]byte
		want   OpaqueMediaKind
	}{
		{
			name: "ordinary inherited frame",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","source":{"mime_type":"audio/wav","url":"` + carrier + `"}}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"type":"image","source":{"url":"` + carrier + `","mime_type":"audio/wav"}}]}]}`),
			},
			want: OpaqueMediaAudio,
		},
		{
			name: "tool inherited frame",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"mime_type":"audio/wav","url":"` + carrier + `"}}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"url":"` + carrier + `","mime_type":"audio/wav"}}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"mime_type":"audio/wav","payload":{"url":"` + carrier + `"}}}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"payload":{"url":"` + carrier + `"},"mime_type":"audio/wav"}}}}}]}]}`),
			},
			want: OpaqueMediaAudio,
		},
		{
			name: "tool child explicit kind survives parent conflict",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"type":"image","mime_type":"audio/wav","source":{"mime_type":"video/mp4","url":"` + carrier + `"}}}}}]}]}`),
				[]byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image":{"source":{"url":"` + carrier + `","mime_type":"video/mp4"},"type":"image","mime_type":"audio/wav"}}}}]}]}`),
			},
			want: OpaqueMediaVideo,
		},
		{
			name: "self-owning image array is not also parent-owned",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"image":[],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","image":[]}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"images":[],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"image_data":[],"mime_type":"audio/wav"}]}]}`),
			},
			want: OpaqueMediaBase64Image,
		},
		{
			name: "self-owning audio array is not also parent-owned",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"audio":[],"mime_type":"image/png"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"image/png","audio":[]}]}]}`),
			},
			want: OpaqueMediaAudio,
		},
		{
			name: "self-owning video array is not also parent-owned",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"video":[],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","video":[]}]}]}`),
			},
			want: OpaqueMediaVideo,
		},
		{
			name: "self-owning document array is not also parent-owned",
			bodies: [][]byte{
				[]byte(`{"messages":[{"role":"user","content":[{"file":[],"mime_type":"audio/wav"}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","document":[]}]}]}`),
				[]byte(`{"messages":[{"role":"user","content":[{"file_data":[],"mime_type":"audio/wav"}]}]}`),
			},
			want: OpaqueMediaDocument,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			for index, body := range testCase.bodies {
				result := extractRound5ScalarRequest(t, body, Limits{})
				if !reflect.DeepEqual(result.OpaqueMediaKinds, []OpaqueMediaKind{testCase.want}) {
					t.Fatalf("permutation %d inherited child kind=%v, want %s", index, result.OpaqueMediaKinds, testCase.want)
				}
			}
		})
	}
}

func TestExtractRequestScalarMediaCarrierNeverEntersPartsOrSegments(t *testing.T) {
	const caption = "visible user caption"
	values := []string{
		"https://example.test/private-media-canary",
		"http://example.test/private-media-canary",
		"data:image/png;base64,UFJJVkFURV9NRURJQV9DQU5BUlk=",
		"ordinary prose that belongs to the media carrier",
		"../relative/private-media-canary.png",
		"provider-file-identifier-123",
		"",
	}
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		for index, value := range values {
			t.Run(key+"/value-"+strconv.Itoa(index), func(t *testing.T) {
				assertScalarMediaPermutations(t, key, value, `"type":"image"`, caption)
			})
		}
	}
}

func TestExtractRequestScalarMediaCarrierDoesNotConsumeTextBudget(t *testing.T) {
	const caption = "inspect only this caption"
	carrier := "https://example.test/" + strings.Repeat("private-media-canary-", 256)
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		body := scalarMediaRequestBody(key, carrier, `"type":"image"`, caption, 2)
		result := extractRound5ScalarRequest(t, body, Limits{})
		if result.TextBytesScanned != len(caption) {
			t.Fatalf("key=%q TextBytesScanned=%d want=%d parts=%#v", key, result.TextBytesScanned, len(caption), result.Parts)
		}
	}
}

func TestExtractRequestNonMediaSourceURIFallsBackToText(t *testing.T) {
	values := []struct {
		name  string
		value string
	}{
		{name: "ordinary prose", value: "ordinary inspectable prose"},
		{name: "HTTPS URL", value: "https://example.test/inspectable-non-media-value"},
		{name: "HTTP URL", value: "http://example.test/inspectable-non-media-value"},
		{name: "data URL", value: "data:image/png;base64,SU5TUEVDVEFCTEVfTk9OX01FRElB"},
		{name: "padded data URL", value: "data:image/png;base64,SU5TUEVDVEFCTEVfUEFERElORw=="},
		{name: "percent data URL", value: "data:image/svg+xml,%3Csvg%3E%3C/svg%3E"},
		{name: "relative path", value: "../inspectable-relative-value"},
		{name: "identifier", value: "provider-inspectable-identifier-123"},
		{name: "empty", value: ""},
	}
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		for _, testCase := range values {
			t.Run(key+"/"+testCase.name, func(t *testing.T) {
				assertScalarCarrierFallback(t, key, testCase.value)
			})
		}
	}

	t.Run("ordinary wrapper does not reclassify scalar carrier", func(t *testing.T) {
		const carrier = "https://example.test/inspectable-wrapper-value"
		bodies := [][]byte{
			[]byte(`{"messages":[{"role":"user","content":[{"type":"image","wrapper":{"url":"` + carrier + `"},"mime_type":"audio/wav"}]}]}`),
			[]byte(`{"messages":[{"role":"user","content":[{"wrapper":{"url":"` + carrier + `"},"type":"image","mime_type":"audio/wav"}]}]}`),
			[]byte(`{"messages":[{"role":"user","content":[{"mime_type":"audio/wav","wrapper":{"url":"` + carrier + `"},"type":"image"}]}]}`),
		}
		var baseline Result
		for index, body := range bodies {
			result := extractRound5ScalarRequest(t, body, Limits{})
			if result.OpaqueMedia || len(result.OpaqueMediaKinds) != 0 {
				t.Fatalf("permutation %d ordinary wrapper scalar became opaque: %#v", index, result)
			}
			if !containsPart(result.Parts, carrier) || result.TextBytesScanned != len(carrier) {
				t.Fatalf("permutation %d ordinary wrapper scalar was not inspectable text: %#v", index, result)
			}
			if index == 0 {
				baseline = result
				continue
			}
			if !reflect.DeepEqual(result.Parts, baseline.Parts) ||
				!reflect.DeepEqual(result.Segments, baseline.Segments) ||
				result.TextBytesScanned != baseline.TextBytesScanned ||
				result.Completeness != baseline.Completeness ||
				!reflect.DeepEqual(result.OpaqueMediaKinds, baseline.OpaqueMediaKinds) {
				t.Fatalf("permutation %d changed ordinary wrapper semantics:\nbase=%#v\ngot=%#v", index, baseline, result)
			}
		}
	})
}

func TestExtractRequestToolSourceURIRemainsInspectable(t *testing.T) {
	values := []struct {
		name  string
		value string
	}{
		{name: "ordinary", value: "ordinary tool argument that must remain inspectable"},
		{name: "data URL", value: "data:image/png;base64,SU5TUEVDVEFCTEVfVE9PTF9DQVJSSUVS"},
	}
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		for _, testCase := range values {
			t.Run(key+"/"+testCase.name, func(t *testing.T) {
				body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{` + strconv.Quote(key) + `:` + strconv.Quote(testCase.value) + `}}}]}]}`)
				result := extractRound5ScalarRequest(t, body, Limits{})
				if result.OpaqueMedia {
					t.Fatalf("tool key=%q value=%q became opaque: %#v", key, testCase.name, result)
				}
				if !strings.Contains(strings.Join(result.Parts, "\n"), testCase.value) {
					t.Fatalf("tool key=%q value=%q bypassed Parts: %#v", key, testCase.name, result.Parts)
				}
				if !segmentsContain(result.Segments, testCase.value) {
					t.Fatalf("tool key=%q value=%q bypassed Segments: %#v", key, testCase.name, result.Segments)
				}
			})
		}
	}
}

func TestExtractRequestScalarCarrierDoesNotCrossSiblingOrToolBoundary(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		inspectable string
	}{
		{
			name:        "unrelated sibling object",
			inspectable: "inspectable scalar sibling value",
			body:        `{"messages":[{"role":"user","content":[{"source":"inspectable scalar sibling value"},{"type":"image","image_url":"https://example.test/media.png"}]}]}`,
		},
		{
			name:        "image URL sibling stays text",
			inspectable: "inspectable image-url sibling value",
			body:        `{"messages":[{"role":"user","content":[{"image_url":"inspectable image-url sibling value"},{"type":"image","source":"https://example.test/media.png"}]}]}`,
		},
		{
			name:        "data URL sibling stays text",
			inspectable: "data:image/png;base64,SU5TUEVDVEFCTEVfU0lCTElORw==",
			body:        `{"messages":[{"role":"user","content":[{"uri":"data:image/png;base64,SU5TUEVDVEFCTEVfU0lCTElORw=="},{"type":"image","source":"https://example.test/media.png"}]}]}`,
		},
		{
			name:        "unrelated child container",
			inspectable: "inspectable nested scalar value",
			body:        `{"messages":[{"role":"user","content":[{"payload":{"uri":"inspectable nested scalar value"},"type":"image"}]}]}`,
		},
		{
			name:        "tool boundary below media block",
			inspectable: "data:image/png;base64,SU5TUEVDVEFCTEFCTEVfVE9PTF9CT1VOREFSWQ==",
			body:        `{"messages":[{"role":"assistant","content":[{"type":"image","tool_use":{"input":{"image_url":"data:image/png;base64,SU5TUEVDVEFCTEFCTEVfVE9PTF9CT1VOREFSWQ=="}}}]}]}`,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := extractRound5ScalarRequest(t, []byte(testCase.body), Limits{})
			if !strings.Contains(strings.Join(result.Parts, "\n"), testCase.inspectable) {
				t.Fatalf("candidate crossed a disallowed boundary: %#v", result)
			}
			if !segmentsContain(result.Segments, testCase.inspectable) {
				t.Fatalf("candidate crossed a disallowed Segments boundary: %#v", result.Segments)
			}
		})
	}
}

func TestExtractRequestScalarCarrierAllowedChildParentResolution(t *testing.T) {
	const (
		carrier = "https://example.test/nested-private-media-canary"
		caption = "safe nested caption"
	)
	bodies := []string{
		`{"messages":[{"role":"user","content":[{"source":{"uri":"` + carrier + `"},"caption":"` + caption + `","type":"image"}]}]}`,
		`{"messages":[{"role":"user","content":[{"source":{"uri":"` + carrier + `","media_type":"image/png"},"caption":"` + caption + `"}]}]}`,
		`{"messages":[{"role":"user","content":[{"source":{"image_url":"` + carrier + `"},"caption":"` + caption + `","type":"image"}]}]}`,
	}
	for index, body := range bodies {
		result := extractRound5ScalarRequest(t, []byte(body), Limits{})
		if strings.Contains(strings.Join(result.Parts, "\n"), carrier) || segmentsContain(result.Segments, carrier) {
			t.Fatalf("case %d nested carrier leaked: %#v", index, result)
		}
		if result.TextBytesScanned != len(caption) || !result.OpaqueMedia {
			t.Fatalf("case %d nested carrier disposition=%#v", index, result)
		}
	}
}

func TestExtractRequestScalarCarrierOverflowDisposition(t *testing.T) {
	limits := Limits{
		MaxRawBytes:      1 << 20,
		MaxScanBytes:     1 << 20,
		MaxTextPartBytes: 1 << 20,
	}
	payloads := []struct {
		name  string
		value string
	}{
		{name: "ordinary", value: strings.Repeat("Z", maxDeferredCandidateBytes+1)},
		{name: "data URL", value: "data:image/png;base64," + strings.Repeat("W", maxDeferredCandidateBytes+1)},
	}
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		for _, payload := range payloads {
			t.Run(key+"/"+payload.name, func(t *testing.T) {
				mediaBody := []byte(`{"messages":[{"role":"user","content":[{` + strconv.Quote(key) + `:` + strconv.Quote(payload.value) + `,"caption":"safe caption","type":"image"}]}]}`)
				mediaResult := extractRound5ScalarRequest(t, mediaBody, limits)
				if !mediaResult.IsComplete() || !mediaResult.OpaqueMedia || mediaResult.HasIncompleteReason(IncompleteDeferredTextCandidateLimit) {
					t.Fatalf("final-media overflow was not complete opaque: %#v", mediaResult)
				}
				if strings.Contains(strings.Join(mediaResult.Parts, "\n"), payload.value[:64]) || segmentsContain(mediaResult.Segments, payload.value[:64]) {
					t.Fatalf("final-media overflow classified a prefix: %#v", mediaResult)
				}

				nonMediaBody := []byte(`{"messages":[{"role":"user","content":[{` + strconv.Quote(key) + `:` + strconv.Quote(payload.value) + `}]}]}`)
				nonMediaResult, err := ExtractRequest(nonMediaBody, round5JSONHeaders(), limits)
				if err != nil {
					t.Fatal(err)
				}
				if !nonMediaResult.IsComplete() || nonMediaResult.HasIncompleteReason(IncompleteDeferredTextCandidateLimit) {
					t.Fatalf("final-nonmedia long carrier was not fully streamed: %#v", nonMediaResult)
				}
				if nonMediaResult.OpaqueMedia || nonMediaResult.TextBytesScanned < len(payload.value) || !strings.Contains(strings.Join(nonMediaResult.Parts, "\n"), payload.value[:64]) {
					t.Fatalf("final-nonmedia long carrier was not inspectable: %#v", nonMediaResult)
				}
			})
		}
	}
}

func TestExtractRequestToolScalarCarrierLongTextIsInspectable(t *testing.T) {
	payload := "data:image/png;base64," + strings.Repeat("V", maxDeferredCandidateBytes+1)
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":{"image_url":` + strconv.Quote(payload) + `}}}]}]}`)
	result, err := ExtractRequest(body, round5JSONHeaders(), Limits{
		MaxRawBytes:      1 << 20,
		MaxScanBytes:     1 << 20,
		MaxTextPartBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || result.HasIncompleteReason(IncompleteDeferredTextCandidateLimit) {
		t.Fatalf("tool scalar long text was not fully streamed: %#v", result)
	}
	if result.OpaqueMedia || result.TextBytesScanned < len(payload) || !strings.Contains(strings.Join(result.Parts, "\n"), payload[:64]) {
		t.Fatalf("tool scalar long text was not inspectable: %#v", result)
	}
}

func TestExtractRequestScalarCarrierPerformanceAcceptance(t *testing.T) {
	if extractRaceEnabled {
		t.Skip("wall-clock and allocation acceptance is not meaningful under the race detector")
	}
	type benchmarkCase struct {
		body       []byte
		wantOpaque bool
	}
	cases := make([]benchmarkCase, 0, 8)
	for index, key := range []string{"source", "uri", "url", "image_url"} {
		cases = append(cases,
			benchmarkCase{
				body:       scalarMediaRequestBody(key, "https://example.test/performance-media", `"type":"image"`, "visible performance caption", index%3),
				wantOpaque: true,
			},
			benchmarkCase{
				body: []byte(`{"messages":[{"role":"user","content":[{` + jsonQuote(key) + `:` + jsonQuote("data:image/png;base64,SU5TUEVDVEFCTEFCTEVfUEVSRk9STUFOQ0U=") + `}]}]}`),
			},
		)
	}
	headers := round5JSONHeaders()
	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			testCase := cases[index%len(cases)]
			extracted, err := ExtractRequest(testCase.body, headers, Limits{})
			if err != nil || !extracted.IsComplete() || extracted.OpaqueMedia != testCase.wantOpaque {
				b.Fatalf("case=%d result=%#v err=%v", index%len(cases), extracted, err)
			}
		}
	})
	elapsed := time.Duration(result.NsPerOp())
	bytesPerOp := result.AllocedBytesPerOp()
	allocsPerOp := result.AllocsPerOp()
	t.Logf("scalar carrier performance time=%s bytes/op=%d allocs/op=%d", elapsed, bytesPerOp, allocsPerOp)
	if elapsed >= 25*time.Millisecond {
		t.Errorf("scalar carrier time=%s/op, want <25ms/op", elapsed)
	}
	if bytesPerOp >= 512<<10 {
		t.Errorf("scalar carrier allocation=%d bytes/op, want <%d", bytesPerOp, 512<<10)
	}
	if allocsPerOp >= 2048 {
		t.Errorf("scalar carrier allocations=%d/op, want <2048", allocsPerOp)
	}
}

func FuzzExtractRequestScalarMediaCarrierPermutation(f *testing.F) {
	keys := []string{"source", "uri", "url", "image_url"}
	markers := []string{
		`"type":"image"`,
		`"type":"input_image"`,
		`"type":"image_url"`,
		`"type":"input_audio"`,
		`"type":"input_file"`,
		`"mime_type":"image/png"`,
		`"media_type":"image/jpeg"`,
	}
	f.Add(uint8(0), uint8(0), "https://example.test/fuzz-media")
	f.Add(uint8(1), uint8(3), "ordinary scalar carrier")
	f.Add(uint8(3), uint8(5), "../relative/media")
	f.Add(uint8(3), uint8(7), "data:image/png;base64,SU5TUEVDVEFCTEVfRlVaWg==")
	f.Add(uint8(0), uint8(len(markers)), "0+00000000000000")
	f.Add(uint8(0), uint8(len(markers)), "dAtA:0000000000,00000000000000000000000=")
	f.Fuzz(func(t *testing.T, keyIndex, markerIndex uint8, value string) {
		if len(value) > 4096 {
			value = value[:4096]
		}
		// Marshal first so arbitrary fuzz bytes always become valid JSON text.
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Skip()
		}
		var normalized string
		if err := json.Unmarshal(encoded, &normalized); err != nil {
			t.Fatal(err)
		}
		key := keys[int(keyIndex)%len(keys)]
		selection := int(markerIndex) % (len(markers) + 1)
		if selection == len(markers) {
			if containsBinaryControl(normalized) {
				t.Skip()
			}
			_, encoded, incomplete := decodeStreamingBoundedText(normalized, true)
			if encoded && incomplete {
				body := []byte(`{"messages":[{"role":"user","content":[{` + jsonQuote(key) + `:` + jsonQuote(normalized) + `}]}]}`)
				result, err := ExtractRequest(body, round5JSONHeaders(), Limits{})
				if err != nil {
					t.Fatal(err)
				}
				if result.IsComplete() || result.TextCoverage != TextCoverageUnavailable ||
					!result.HasIncompleteReason(IncompleteTextPartByteLimit) || result.OpaqueMedia {
					t.Fatalf("malformed encoded scalar carrier silently completed: %#v", result)
				}
				if len(result.Parts) != 0 || len(result.Segments) != 0 {
					t.Fatalf("aborted scalar carrier leaked text: parts=%#v segments=%#v", result.Parts, result.Segments)
				}
				return
			}
			assertScalarCarrierFallback(t, key, normalized)
			return
		}
		assertScalarMediaPermutations(t, key, normalized, markers[selection], "fuzz visible caption")
	})
}

func TestExtractRequestScalarMediaCarrierMalformedTextDataURLFailsClosed(t *testing.T) {
	const value = "dAtA:;"
	for _, key := range []string{"source", "uri", "url", "image_url"} {
		t.Run(key, func(t *testing.T) {
			body := []byte(`{"messages":[{"role":"user","content":[{` + jsonQuote(key) + `:` + jsonQuote(value) + `}]}]}`)
			result, err := ExtractRequest(body, round5JSONHeaders(), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || result.Envelope != EnvelopeComplete ||
				result.TextCoverage != TextCoverageUnavailable ||
				!reflect.DeepEqual(result.IncompleteReasons, []IncompleteReason{IncompleteTextPartByteLimit}) ||
				result.TextBytesScanned != 0 || result.RawBytesObserved != int64(len(body)) ||
				result.LogicalTextParts != 1 || result.ClassificationChunks != 0 ||
				!result.Truncated || result.OpaqueMedia {
				t.Fatalf("malformed textual data scalar carrier silently completed: %#v", result)
			}
			if len(result.Parts) != 0 || len(result.Segments) != 0 {
				t.Fatalf("aborted malformed scalar carrier leaked text: parts=%#v segments=%#v", result.Parts, result.Segments)
			}
		})
	}
}

func TestExtractRequestScalarMediaCarrierBareBinaryBase64FailsClosed(t *testing.T) {
	const value = "0+00000000000000"
	variants, encoded, incomplete := decodeBoundedText(value)
	if len(variants) != 0 || !encoded || !incomplete {
		t.Fatalf("fixture decode = variants:%q encoded:%v incomplete:%v", variants, encoded, incomplete)
	}

	for _, key := range []string{"source", "uri", "url", "image_url"} {
		t.Run(key, func(t *testing.T) {
			body := []byte(`{"messages":[{"role":"user","content":[{` + jsonQuote(key) + `:` + jsonQuote(value) + `}]}]}`)
			result, err := ExtractRequest(body, round5JSONHeaders(), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || result.TextCoverage != TextCoverageUnavailable ||
				!result.HasIncompleteReason(IncompleteTextPartByteLimit) || result.OpaqueMedia {
				t.Fatalf("scalar carrier silently completed: %#v", result)
			}
			if len(result.Parts) != 0 || len(result.Segments) != 0 {
				t.Fatalf("aborted scalar carrier leaked text: parts=%#v segments=%#v", result.Parts, result.Segments)
			}
		})
	}

	t.Run("oversized-source", func(t *testing.T) {
		oversized := "0+" + strings.Repeat("0", maxDecodeSourceBytes+2)
		variants, encoded, incomplete := decodeBoundedText(oversized)
		if len(variants) != 0 || !encoded || !incomplete {
			t.Fatalf("oversized fixture decode = variants:%d encoded:%v incomplete:%v", len(variants), encoded, incomplete)
		}
		body := []byte(`{"messages":[{"role":"user","content":[{"source":` + jsonQuote(oversized) + `}]}]}`)
		result, err := ExtractRequest(body, round5JSONHeaders(), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsComplete() || result.TextCoverage != TextCoverageUnavailable ||
			!result.HasIncompleteReason(IncompleteTextPartByteLimit) || result.OpaqueMedia {
			t.Fatalf("oversized scalar carrier silently completed: %#v", result)
		}
	})

	body := []byte(`{"messages":[{"role":"user","content":` + jsonQuote(value) + `}]}`)
	result, err := ExtractRequest(body, round5JSONHeaders(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsComplete() || result.OpaqueMedia || !reflect.DeepEqual(result.Parts, []string{value}) ||
		len(result.Segments) != 1 || result.Segments[0].Text != value {
		t.Fatalf("ordinary text identifier was affected: %#v", result)
	}
}

func TestExtractRequestScalarMediaCarrierMalformedMixedCaseDataURLFailsClosed(t *testing.T) {
	const value = "dAtA:0000000000,00000000000000000000000="
	variants, encoded, incomplete := decodeBoundedText(value)
	if len(variants) != 0 || !encoded || !incomplete {
		t.Fatalf("fixture decode = variants:%q encoded:%v incomplete:%v", variants, encoded, incomplete)
	}

	for _, key := range []string{"source", "uri", "url", "image_url"} {
		t.Run(key, func(t *testing.T) {
			body := []byte(`{"messages":[{"role":"user","content":[{` + jsonQuote(key) + `:` + jsonQuote(value) + `}]}]}`)
			result, err := ExtractRequest(body, round5JSONHeaders(), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsComplete() || result.TextCoverage != TextCoverageUnavailable ||
				!result.HasIncompleteReason(IncompleteTextPartByteLimit) || result.OpaqueMedia {
				t.Fatalf("malformed mixed-case data scalar carrier silently completed: %#v", result)
			}
			if len(result.Parts) != 0 || len(result.Segments) != 0 {
				t.Fatalf("aborted malformed scalar carrier leaked text: parts=%#v segments=%#v", result.Parts, result.Segments)
			}
		})
	}
}

func BenchmarkExtractRequestScalarCarrierPermutation(b *testing.B) {
	carrier := "https://example.test/" + strings.Repeat("bounded-media-carrier-", 32)
	bodies := make([][]byte, 3)
	for order := range bodies {
		bodies[order] = scalarMediaRequestBody("source", carrier, `"type":"image"`, "visible benchmark caption", order)
	}
	headers := round5JSONHeaders()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, err := ExtractRequest(bodies[index%len(bodies)], headers, Limits{})
		if err != nil || !result.IsComplete() || result.TextBytesScanned != len("visible benchmark caption") {
			b.Fatalf("result=%#v err=%v", result, err)
		}
	}
}

func assertScalarMediaPermutations(t testing.TB, key, carrier, marker, caption string) {
	t.Helper()
	var baseline Result
	for order := 0; order < 3; order++ {
		body := scalarMediaRequestBody(key, carrier, marker, caption, order)
		result := extractRound5ScalarRequest(t, body, Limits{})
		if carrier != "" && !strings.Contains(caption, carrier) {
			if strings.Contains(strings.Join(result.Parts, "\n"), carrier) {
				t.Fatalf("permutation %d carrier entered Parts: %#v", order, result.Parts)
			}
			if segmentsContain(result.Segments, carrier) {
				t.Fatalf("permutation %d carrier entered Segments: %#v", order, result.Segments)
			}
		}
		if result.TextBytesScanned != len(caption) {
			t.Fatalf("permutation %d TextBytesScanned=%d want=%d parts=%#v", order, result.TextBytesScanned, len(caption), result.Parts)
		}
		if !result.OpaqueMedia || len(result.OpaqueMediaKinds) == 0 {
			t.Fatalf("permutation %d did not produce opaque media: %#v", order, result)
		}
		if order == 0 {
			baseline = result
			continue
		}
		if !reflect.DeepEqual(result.Parts, baseline.Parts) ||
			!reflect.DeepEqual(result.Segments, baseline.Segments) ||
			result.TextBytesScanned != baseline.TextBytesScanned ||
			result.Completeness != baseline.Completeness ||
			!reflect.DeepEqual(result.IncompleteReasons, baseline.IncompleteReasons) ||
			!reflect.DeepEqual(result.OpaqueMediaKinds, baseline.OpaqueMediaKinds) {
			t.Fatalf("permutation %d changed semantics:\nbase=%#v\ngot=%#v", order, baseline, result)
		}
	}
}

func assertScalarCarrierFallback(t testing.TB, key, value string) {
	t.Helper()
	body := []byte(`{"messages":[{"role":"user","content":[{` + jsonQuote(key) + `:` + jsonQuote(value) + `}]}]}`)
	result := extractRound5ScalarRequest(t, body, Limits{})
	if result.OpaqueMedia || len(result.OpaqueMediaKinds) != 0 {
		t.Fatalf("non-media key=%q became opaque: %#v", key, result)
	}
	if strings.TrimSpace(value) == "" {
		if result.TextBytesScanned != 0 {
			t.Fatalf("blank non-media key=%q consumed text budget: %#v", key, result)
		}
		return
	}
	if result.TextBytesScanned < len(value) {
		t.Fatalf("non-media key=%q TextBytesScanned=%d want-at-least=%d result=%#v", key, result.TextBytesScanned, len(value), result)
	}
	if !strings.Contains(strings.Join(result.Parts, "\n"), value) {
		t.Fatalf("non-media key=%q did not fall back to Parts: %#v", key, result.Parts)
	}
	if !segmentsContain(result.Segments, value) {
		t.Fatalf("non-media key=%q did not fall back to Segments: %#v", key, result.Segments)
	}
}

func scalarMediaRequestBody(key, carrier, marker, caption string, order int) []byte {
	carrierMember := jsonQuote(key) + `:` + jsonQuote(carrier)
	captionMember := `"caption":` + jsonQuote(caption)
	var members string
	switch order {
	case 0:
		members = marker + `,` + carrierMember + `,` + captionMember
	case 1:
		members = carrierMember + `,` + marker + `,` + captionMember
	default:
		members = carrierMember + `,` + captionMember + `,` + marker
	}
	return []byte(`{"messages":[{"role":"user","content":[{` + members + `}]}]}`)
}

func jsonQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func extractRound5ScalarRequest(t testing.TB, body []byte, limits Limits) Result {
	t.Helper()
	result, err := ExtractRequest(body, round5JSONHeaders(), limits)
	if err != nil || !result.IsComplete() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	return result
}

func round5JSONHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}}
}

func segmentsContain(segments []Segment, value string) bool {
	for _, segment := range segments {
		if strings.Contains(segment.Text, value) {
			return true
		}
	}
	return false
}
