package round9corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	publicV9ManifestBytes   = 105888
	publicV9ManifestSHA256  = "dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38"
	publicV10ManifestBytes  = 183752
	publicV10ManifestSHA256 = "bda9f4e70b9e3a050e7e40d025024fa8a9ebb1ffa2fb46f9f7ac47d27691526d"
)

type publicIdentityPayload struct {
	ID                 string `json:"id"`
	UniquePayloadIndex *int   `json:"unique_payload_index"`
	EncodedFile        string `json:"encoded_file"`
	DecodedBytes       int    `json:"decoded_bytes"`
	DecodedSHA256      string `json:"decoded_sha256"`
}

type publicIdentityManifest struct {
	Schema                            string                  `json:"schema"`
	Dataset                           string                  `json:"dataset"`
	DevelopmentOnly                   bool                    `json:"development_only"`
	IndependentHoldout                bool                    `json:"independent_holdout"`
	ThirdPartyCodeExecuted            bool                    `json:"third_party_code_executed"`
	UniqueFormalPayloads              int                     `json:"unique_formal_payloads"`
	NondefaultBranchCandidateCarriers int                     `json:"nondefault_branch_candidate_carriers"`
	ReleaseAssetsReviewed             int                     `json:"release_assets_reviewed"`
	ReleaseAssetsWithPromptEntries    int                     `json:"release_assets_with_prompt_entries"`
	RefreshHistory                    []publicIdentityHistory `json:"refresh_history"`
	Payloads                          []publicIdentityPayload `json:"payloads"`
}

type publicIdentityHistory struct {
	ManifestBytes  int    `json:"manifest_bytes"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func TestRound9PublicCorpusV9RetentionIdentity(t *testing.T) {
	t.Parallel()
	root := round9CorpusRepositoryRoot(t)
	v9 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v9", publicV9ManifestBytes, publicV9ManifestSHA256)
	if v9.Schema != "round9-public-adversarial-corpus/v9" || v9.Dataset != "round9-public-adversarial-v9" {
		t.Fatalf("unexpected v9 identity: schema=%q dataset=%q", v9.Schema, v9.Dataset)
	}

	v10 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v10", publicV10ManifestBytes, publicV10ManifestSHA256)
	matches := 0
	for _, history := range v10.RefreshHistory {
		if history.ManifestBytes == publicV9ManifestBytes && history.ManifestSHA256 == publicV9ManifestSHA256 {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("v10 refresh history contains v9 identity %d times, want 1", matches)
	}
}

func TestRound9PublicCorpusV10Identity(t *testing.T) {
	t.Parallel()
	root := round9CorpusRepositoryRoot(t)
	v9 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v9", publicV9ManifestBytes, publicV9ManifestSHA256)
	v10 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v10", publicV10ManifestBytes, publicV10ManifestSHA256)
	if v10.Schema != "round9-public-adversarial-corpus/v10" || v10.Dataset != "round9-public-adversarial-v10" ||
		!v10.DevelopmentOnly || v10.IndependentHoldout || v10.ThirdPartyCodeExecuted ||
		v10.UniqueFormalPayloads != 23 || v10.NondefaultBranchCandidateCarriers != 5 ||
		v10.ReleaseAssetsReviewed != 16 || v10.ReleaseAssetsWithPromptEntries != 4 {
		t.Fatalf(
			"unexpected v10 contract: schema=%q dataset=%q development=%v holdout=%v executed=%v unique=%d branches=%d assets=%d prompt_assets=%d",
			v10.Schema,
			v10.Dataset,
			v10.DevelopmentOnly,
			v10.IndependentHoldout,
			v10.ThirdPartyCodeExecuted,
			v10.UniqueFormalPayloads,
			v10.NondefaultBranchCandidateCarriers,
			v10.ReleaseAssetsReviewed,
			v10.ReleaseAssetsWithPromptEntries,
		)
	}

	v9ByIndex := publicPayloadsByIndex(v9.Payloads)
	v10ByIndex := publicPayloadsByIndex(v10.Payloads)
	for index := 1; index <= 23; index++ {
		before, beforeOK := v9ByIndex[index]
		after, afterOK := v10ByIndex[index]
		if !beforeOK || !afterOK {
			t.Fatalf("public payload index %d missing: v9=%v v10=%v", index, beforeOK, afterOK)
		}
		if before.ID != after.ID || before.EncodedFile != after.EncodedFile ||
			before.DecodedBytes != after.DecodedBytes || before.DecodedSHA256 != after.DecodedSHA256 {
			t.Fatalf("public payload index %d identity drift", index)
		}
		v9Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v9", filepath.FromSlash(before.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		v10Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v10", filepath.FromSlash(after.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v9Encoded, v10Encoded) {
			t.Fatalf("public payload index %d encoded bytes drifted", index)
		}
	}
}

func loadPublicIdentityManifest(t *testing.T, root, dataset string, wantBytes int, wantSHA256 string) publicIdentityManifest {
	t.Helper()
	path := filepath.Join(root, "testdata", dataset, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != wantBytes || fmt.Sprintf("%x", sum) != wantSHA256 {
		t.Fatalf("%s manifest identity drift: bytes=%d sha256=%x", dataset, len(raw), sum)
	}
	var manifest publicIdentityManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func publicPayloadsByIndex(payloads []publicIdentityPayload) map[int]publicIdentityPayload {
	result := make(map[int]publicIdentityPayload, 23)
	for _, payload := range payloads {
		if payload.UniquePayloadIndex != nil {
			result[*payload.UniquePayloadIndex] = payload
		}
	}
	return result
}

func round9CorpusRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
