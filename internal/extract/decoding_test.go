package extract

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestExtractTextDecodesBoundedTextEncodings(t *testing.T) {
	t.Parallel()

	plain := "deploy ransomware to victim systems"
	percent := url.PathEscape(plain)
	queryEscaped := url.QueryEscape(plain + " + command")
	htmlEncoded := "deploy&#32;ransomware&#32;to&#32;victim&#32;systems"
	base64Encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	twoLayers := base64.StdEncoding.EncodeToString([]byte(percent))
	textDataURL := "data:text/plain;base64," + base64Encoded

	tests := []struct {
		name string
		text string
		want []string
	}{
		{name: "URL percent encoding", text: percent, want: []string{percent, plain}},
		{name: "URL query encoding", text: queryEscaped, want: []string{queryEscaped, "deploy+ransomware+to+victim+systems+++command", plain + " + command"}},
		{name: "HTML entities", text: htmlEncoded, want: []string{htmlEncoded, plain}},
		{name: "short Base64 text", text: base64Encoded, want: []string{base64Encoded, plain}},
		{name: "two layers", text: twoLayers, want: []string{twoLayers, percent, plain}},
		{name: "text data URL", text: textDataURL, want: []string{textDataURL, plain}},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, testCase.text)+`}`), Limits{})
			if err != nil {
				t.Fatalf("ExtractText() error = %v", err)
			}
			if !reflect.DeepEqual(result.Parts, testCase.want) {
				t.Fatalf("Parts = %#v, want %#v", result.Parts, testCase.want)
			}
			if result.Truncated || result.OpaqueMedia {
				t.Fatalf("result unexpectedly incomplete: %#v", result)
			}
		})
	}
}

func TestExtractTextDecodeLimitsAndBinary(t *testing.T) {
	t.Parallel()

	plain := "deploy ransomware to victim systems"
	one := base64.StdEncoding.EncodeToString([]byte(plain))
	two := base64.StdEncoding.EncodeToString([]byte(one))
	three := base64.StdEncoding.EncodeToString([]byte(two))
	result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, three)+`}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Parts, []string{three, two, one}) || !result.Truncated {
		t.Fatalf("three-layer result = %#v, want two decoded views plus truncation", result)
	}

	binary := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	result, err = ExtractText([]byte(`{"input":`+mustJSONString(t, binary)+`}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Parts, []string{binary}) || !result.Truncated {
		t.Fatalf("binary result = %#v, want preserved source plus truncation", result)
	}
}

func TestExtractTextOpaqueMediaIsSeparateFromTextTruncation(t *testing.T) {
	t.Parallel()

	result, err := ExtractText([]byte(`{"input":[{"type":"input_image","image_url":"https://example.test/a.png"}]}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OpaqueMedia || result.Truncated {
		t.Fatalf("result = %#v, want opaque media without text truncation", result)
	}
}

func TestExtractTextClassifiesOpaqueMediaWithoutRetainingPayload(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		body string
		kind OpaqueMediaKind
	}{
		{name: "HTTPS image URL", body: `{"input":[{"type":"input_image","image_url":"https://example.test/a.png"}]}`, kind: OpaqueMediaHTTPSImageURL},
		{name: "image data URL", body: `{"input":[{"type":"input_image","image_url":"data:image/svg+xml,%3Csvg%3E%3C/svg%3E"}]}`, kind: OpaqueMediaDataURL},
		{name: "Base64 image", body: `{"input":[{"type":"input_image","image_url":"data:image/png;base64,iVBORw0KGgo="}]}`, kind: OpaqueMediaBase64Image},
		{name: "audio", body: `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"UklGRg==","format":"wav"}}]}]}`, kind: OpaqueMediaAudio},
		{name: "document", body: `{"input":[{"type":"file","file_data":"JVBERi0xLjQ="}]}`, kind: OpaqueMediaDocument},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := ExtractText([]byte(testCase.body), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if !result.OpaqueMedia || result.Truncated || !reflect.DeepEqual(result.OpaqueMediaKinds, []OpaqueMediaKind{testCase.kind}) {
				t.Fatalf("result=%#v, want one content-free media kind %q", result, testCase.kind)
			}
		})
	}
}

func TestDecodeDoesNotTreatOrdinarySentenceAsBase64(t *testing.T) {
	t.Parallel()

	text := "ordinary defensive text"
	result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, text)+`}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Parts, []string{text}) || result.Truncated {
		t.Fatalf("result = %#v, want unchanged ordinary text", result)
	}
}

func TestDecodeDoesNotTreatBareIdentifierAsOpaqueBase64(t *testing.T) {
	t.Parallel()

	text := "abcdefghijklmnop"
	result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, text)+`}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Parts, []string{text}) || result.Truncated {
		t.Fatalf("result = %#v, want unchanged identifier", result)
	}
}

func TestDecodeMarksMixedValidAndInvalidPercentEscapesIncomplete(t *testing.T) {
	t.Parallel()

	text := "deploy%20ransomware%20to%20victim%20systems%ZZ"
	result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, text)+`}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Parts, []string{text}) || !result.Truncated {
		t.Fatalf("result = %#v, want preserved source plus truncation", result)
	}
}

func TestDecodeMarksMalformedStrongBase64Incomplete(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		text      string
		wantParts []string
	}{
		{
			name:      "excess terminal padding",
			text:      "ZGVwbG95IHJhbnNvbXdhcmU===",
			wantParts: []string{"ZGVwbG95IHJhbnNvbXdhcmU===", "deploy ransomware"},
		},
		{
			name:      "characters after valid padding",
			text:      "ZGVwbG95IHJhbnNvbXdhcmU=AAAAA",
			wantParts: []string{"ZGVwbG95IHJhbnNvbXdhcmU=AAAAA", "deploy ransomware"},
		},
		{
			name:      "multiline without padding",
			text:      "ZGVwbG95IHJhbnNvbXdhcmU\nYY",
			wantParts: []string{"ZGVwbG95IHJhbnNvbXdhcmU\nYY"},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, testCase.text)+`}`), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Parts, testCase.wantParts) || !result.Truncated {
				t.Fatalf("result = %#v, want preserved source plus truncation", result)
			}
		})
	}
}

func TestDecodeRecoversHorizontallySpacedBase64Text(t *testing.T) {
	t.Parallel()

	plain := "deploy ransomware"
	for _, encoded := range []string{
		"ZGVw bG95 IHJh bnNv bXdh cmU=",
		"ZGVw\tbG95\tIHJh\tbnNv\tbXdh\tcmU=",
	} {
		result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, encoded)+`}`), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.Parts, []string{encoded, plain}) || result.Truncated {
			t.Fatalf("result = %#v, want recovered Base64 text without truncation", result)
		}
	}
}

func TestOversizedHorizontallySpacedBase64IsIncomplete(t *testing.T) {
	t.Parallel()

	value := strings.Repeat("QUJD ", maxDecodeSourceBytes/5+1)
	variants, encoded, incomplete := decodeBoundedText(value)
	if len(variants) != 0 || !encoded || !incomplete {
		t.Fatalf("decodeBoundedText oversized spaced Base64 = variants:%d encoded:%v incomplete:%v", len(variants), encoded, incomplete)
	}
}

func TestDecodeDoesNotTreatOrdinaryPercentOrAssignmentAsIncomplete(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"Save 50% on defensive security training.",
		"account=abcdefghijklmnop",
		"ZGVwbG95IHJhbnNvbXdhcmU=, notes",
		"https://example.test/defensive/path",
	} {
		result, err := ExtractText([]byte(`{"input":`+mustJSONString(t, text)+`}`), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.Parts, []string{text}) || result.Truncated {
			t.Fatalf("result = %#v, want unchanged ordinary text", result)
		}
	}
}

func mustJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
