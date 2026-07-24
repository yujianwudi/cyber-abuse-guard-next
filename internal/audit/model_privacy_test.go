package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestHashModelIsDeterministicAndDomainSeparated(t *testing.T) {
	const model = "MODEL_PRIVACY_CANARY_secret-requested-model"

	first := HashModel(model)
	second := HashModel(model)
	if first != second {
		t.Fatal("HashModel is not deterministic")
	}
	if first == HashRequest([]byte(model)) {
		t.Fatal("model and request hash domains collided")
	}
	if !strings.HasPrefix(first, modelHashPrefix) || strings.Contains(first, model) {
		t.Fatal("HashModel returned an unsafe value")
	}

	wantSum := sha256.Sum256([]byte(modelHashDomain + model))
	want := modelHashPrefix + hex.EncodeToString(wantSum[:])
	if first != want {
		t.Fatal("HashModel did not match the documented domain-separated digest")
	}
	if HashModel("") != "" {
		t.Fatal("HashModel(empty) must remain empty")
	}
}

func TestHashRequestIsDeterministicAndDomainSeparated(t *testing.T) {
	const request = "REQUEST_PRIVACY_CANARY_secret-body"
	first := HashRequest([]byte(request))
	second := HashRequest([]byte(request))
	if first != second || !strings.HasPrefix(first, "sha256:") || strings.Contains(first, request) {
		t.Fatal("request hash is not a deterministic privacy-safe digest")
	}
	plain := sha256.Sum256([]byte(request))
	if first == "sha256:"+hex.EncodeToString(plain[:]) {
		t.Fatal("request hash omitted its domain separator")
	}
	wantHash := sha256.New()
	_, _ = wantHash.Write([]byte(requestHashDomain))
	_, _ = wantHash.Write([]byte(request))
	want := "sha256:" + hex.EncodeToString(wantHash.Sum(nil))
	if first != want {
		t.Fatal("request hash does not match the documented domain")
	}
}

func TestCanonicalSourceFormatNeverRetainsUnknownCallerText(t *testing.T) {
	tests := map[string]string{
		"openai":                     "openai",
		" OPENAI-RESPONSE ":          "openai-response",
		" Interactions ":             "interactions",
		"OpenAI-Image":               "openai-image",
		"OpenAI-Video":               "openai-video",
		"anthropic":                  "claude",
		"Claude":                     "claude",
		"gemini":                     "gemini",
		"SOURCE_FORMAT_CANARY_value": SourceFormatUnknown,
		"":                           SourceFormatUnknown,
	}
	for input, want := range tests {
		if got := CanonicalSourceFormat(input); got != want {
			t.Errorf("CanonicalSourceFormat(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPrepareEventSanitizesCallerControlledMetadata(t *testing.T) {
	const modelCanary = "MODEL_PREPARE_EVENT_CANARY_secret-model"
	const sourceCanary = "SOURCE_PREPARE_EVENT_CANARY_secret-provider"
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

	event, err := prepareEvent(Event{
		ID:           "privacy-event",
		Timestamp:    now,
		Action:       "audit",
		Mode:         "audit",
		Model:        modelCanary,
		SourceFormat: sourceCanary,
	}, now)
	if err != nil {
		t.Fatalf("prepareEvent() error = %v", err)
	}
	if event.Model != HashModel(modelCanary) || strings.Contains(event.Model, modelCanary) {
		t.Fatal("prepared event retained unsafe model metadata")
	}
	if event.SourceFormat != SourceFormatUnknown {
		t.Fatal("prepared event retained an unknown caller-controlled source format")
	}
}
