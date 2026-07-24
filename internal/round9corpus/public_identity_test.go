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
	publicV11ManifestBytes  = 476165
	publicV11ManifestSHA256 = "297c01072eb8bea3c6102b957c741722e621860c1116b65450b68a8704e75038"
	publicV12ManifestBytes  = 485221
	publicV12ManifestSHA256 = "eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387"
	publicV13ManifestBytes  = 481448
	publicV13ManifestSHA256 = "91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6"
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
	ThirdPartyRepositoryAccess        string                  `json:"third_party_repository_access"`
	BinaryReleaseAssetsDownloaded     bool                    `json:"binary_release_assets_downloaded"`
	BinaryReleaseAssetsOpened         bool                    `json:"binary_release_assets_opened"`
	ReleaseAssetMetadataRecords       int                     `json:"release_asset_metadata_records"`
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

func TestRound9PublicCorpusV11Identity(t *testing.T) {
	t.Parallel()
	root := round9CorpusRepositoryRoot(t)
	v10 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v10", publicV10ManifestBytes, publicV10ManifestSHA256)
	v11 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v11", publicV11ManifestBytes, publicV11ManifestSHA256)
	if v11.Schema != "round9-public-adversarial-corpus/v11" || v11.Dataset != "round9-public-adversarial-v11" ||
		!v11.DevelopmentOnly || v11.IndependentHoldout || v11.ThirdPartyCodeExecuted ||
		v11.ThirdPartyRepositoryAccess != "github_api_text_and_metadata_read_only" ||
		v11.BinaryReleaseAssetsDownloaded || v11.BinaryReleaseAssetsOpened ||
		v11.UniqueFormalPayloads != 23 || v11.NondefaultBranchCandidateCarriers != 5 ||
		v11.ReleaseAssetsReviewed != 16 || v11.ReleaseAssetsWithPromptEntries != 4 ||
		v11.ReleaseAssetMetadataRecords != 199 {
		t.Fatalf("unexpected v11 contract: %+v", v11)
	}

	matches := 0
	for _, history := range v11.RefreshHistory {
		if history.ManifestBytes == publicV10ManifestBytes && history.ManifestSHA256 == publicV10ManifestSHA256 {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("v11 refresh history contains v10 identity %d times, want 1", matches)
	}

	v10ByIndex := publicPayloadsByIndex(v10.Payloads)
	v11ByIndex := publicPayloadsByIndex(v11.Payloads)
	for index := 1; index <= 23; index++ {
		before, beforeOK := v10ByIndex[index]
		after, afterOK := v11ByIndex[index]
		if !beforeOK || !afterOK || before.ID != after.ID || before.EncodedFile != after.EncodedFile ||
			before.DecodedBytes != after.DecodedBytes || before.DecodedSHA256 != after.DecodedSHA256 {
			t.Fatalf("public payload index %d identity drift from v10 to v11", index)
		}
		v10Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v10", filepath.FromSlash(before.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		v11Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v11", filepath.FromSlash(after.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v10Encoded, v11Encoded) {
			t.Fatalf("public payload index %d encoded bytes drifted from v10 to v11", index)
		}
	}
}

func TestRound9PublicCorpusV12Identity(t *testing.T) {
	t.Parallel()
	root := round9CorpusRepositoryRoot(t)
	v11 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v11", publicV11ManifestBytes, publicV11ManifestSHA256)
	v12 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v12", publicV12ManifestBytes, publicV12ManifestSHA256)
	if v12.Schema != "round9-public-adversarial-corpus/v12" || v12.Dataset != "round9-public-adversarial-v12" ||
		!v12.DevelopmentOnly || v12.IndependentHoldout || v12.ThirdPartyCodeExecuted ||
		v12.ThirdPartyRepositoryAccess != "github_api_text_and_metadata_read_only" ||
		v12.BinaryReleaseAssetsDownloaded || v12.BinaryReleaseAssetsOpened ||
		v12.UniqueFormalPayloads != 23 || v12.NondefaultBranchCandidateCarriers != 5 ||
		v12.ReleaseAssetsReviewed != 16 || v12.ReleaseAssetsWithPromptEntries != 4 ||
		v12.ReleaseAssetMetadataRecords != 199 {
		t.Fatalf("unexpected v12 contract: %+v", v12)
	}

	matches := 0
	for _, history := range v12.RefreshHistory {
		if history.ManifestBytes == publicV11ManifestBytes && history.ManifestSHA256 == publicV11ManifestSHA256 {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("v12 refresh history contains v11 identity %d times, want 1", matches)
	}

	v11ByIndex := publicPayloadsByIndex(v11.Payloads)
	v12ByIndex := publicPayloadsByIndex(v12.Payloads)
	for index := 1; index <= 23; index++ {
		before, beforeOK := v11ByIndex[index]
		after, afterOK := v12ByIndex[index]
		if !beforeOK || !afterOK || before.ID != after.ID || before.EncodedFile != after.EncodedFile ||
			before.DecodedBytes != after.DecodedBytes || before.DecodedSHA256 != after.DecodedSHA256 {
			t.Fatalf("public payload index %d identity drift from v11 to v12", index)
		}
		v11Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v11", filepath.FromSlash(before.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		v12Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v12", filepath.FromSlash(after.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v11Encoded, v12Encoded) {
			t.Fatalf("public payload index %d encoded bytes drifted from v11 to v12", index)
		}
	}
}

func TestRound9PublicCorpusV13Identity(t *testing.T) {
	t.Parallel()
	root := round9CorpusRepositoryRoot(t)
	v12 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v12", publicV12ManifestBytes, publicV12ManifestSHA256)
	v13 := loadPublicIdentityManifest(t, root, "round9-public-adversarial-v13", publicV13ManifestBytes, publicV13ManifestSHA256)
	if v13.Schema != "round9-public-adversarial-corpus/v13" || v13.Dataset != "round9-public-adversarial-v13" ||
		!v13.DevelopmentOnly || v13.IndependentHoldout || v13.ThirdPartyCodeExecuted ||
		v13.ThirdPartyRepositoryAccess != "github_api_text_and_metadata_read_only" ||
		v13.BinaryReleaseAssetsDownloaded || v13.BinaryReleaseAssetsOpened ||
		v13.UniqueFormalPayloads != 23 || v13.NondefaultBranchCandidateCarriers != 5 ||
		v13.ReleaseAssetsReviewed != 16 || v13.ReleaseAssetsWithPromptEntries != 4 ||
		v13.ReleaseAssetMetadataRecords != 199 {
		t.Fatalf("unexpected v13 contract: %+v", v13)
	}

	matches := 0
	for _, history := range v13.RefreshHistory {
		if history.ManifestBytes == publicV12ManifestBytes && history.ManifestSHA256 == publicV12ManifestSHA256 {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("v13 refresh history contains v12 identity %d times, want 1", matches)
	}

	if len(v12.Payloads) != len(v13.Payloads) {
		t.Fatalf("public payload record count drift from v12 to v13: before=%d after=%d", len(v12.Payloads), len(v13.Payloads))
	}
	v13ByID := make(map[string]publicIdentityPayload, len(v13.Payloads))
	for _, payload := range v13.Payloads {
		if _, duplicate := v13ByID[payload.ID]; duplicate {
			t.Fatalf("v13 public payload id %q is duplicated", payload.ID)
		}
		v13ByID[payload.ID] = payload
	}
	for _, before := range v12.Payloads {
		after, afterOK := v13ByID[before.ID]
		sameIndex := before.UniquePayloadIndex == nil && after.UniquePayloadIndex == nil ||
			before.UniquePayloadIndex != nil && after.UniquePayloadIndex != nil && *before.UniquePayloadIndex == *after.UniquePayloadIndex
		if !afterOK || !sameIndex || before.EncodedFile != after.EncodedFile ||
			before.DecodedBytes != after.DecodedBytes || before.DecodedSHA256 != after.DecodedSHA256 {
			t.Fatalf("public payload %q identity drift from v12 to v13", before.ID)
		}
		v12Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v12", filepath.FromSlash(before.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		v13Encoded, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v13", filepath.FromSlash(after.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v12Encoded, v13Encoded) {
			t.Fatalf("public payload %q encoded bytes drifted from v12 to v13", before.ID)
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
