package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
)

func TestRound9PublicCorpusV13RetainsV1ThroughV12UniquePayloads(t *testing.T) {
	t.Parallel()
	root := publicCorpusRepositoryRoot(t)
	historical := []struct {
		dataset string
		bytes   int
		sha256  string
	}{
		{dataset: "round9-public-adversarial-v1", bytes: 27297, sha256: "55c05fa407f05ffe21a87791f3b7a4e7d2e68bc026e0d8ced7654bb13932f386"},
		{dataset: "round9-public-adversarial-v2", bytes: 27194, sha256: "06625e48f0cd7ae8e43ebfb82da266e9b98061a3411262c305277a6ec2fdfe8e"},
		{dataset: "round9-public-adversarial-v3", bytes: 30838, sha256: "5ec0f9ca9bf3987ffd80b155e08664af6fdd1d026d3108282b18348bcd156748"},
		{dataset: "round9-public-adversarial-v4", bytes: 51815, sha256: "080d50d83debbffdd1496973ab88d8a2bcb2d0020cadf67c7fefe882bf3691d5"},
		{dataset: "round9-public-adversarial-v5", bytes: 150645, sha256: "7ea0dfefde513f973da5f0a85df5e0ac19c09b0f6eb8caf0b035af327b548c43"},
		{dataset: "round9-public-adversarial-v6", bytes: 101408, sha256: "74096af7ac49578e0ca82105563cac83e7541e2505d9943f0569a148240ce34c"},
		{dataset: "round9-public-adversarial-v7", bytes: 101925, sha256: "74716fd006490b7f2b57448ac1c87922d2c91f1eaabfb929fac15acaf184f500"},
		{dataset: "round9-public-adversarial-v8", bytes: 105299, sha256: "5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f"},
		{dataset: "round9-public-adversarial-v9", bytes: 105888, sha256: "dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38"},
		{dataset: "round9-public-adversarial-v10", bytes: 183752, sha256: "bda9f4e70b9e3a050e7e40d025024fa8a9ebb1ffa2fb46f9f7ac47d27691526d"},
		{dataset: "round9-public-adversarial-v11", bytes: 476165, sha256: "297c01072eb8bea3c6102b957c741722e621860c1116b65450b68a8704e75038"},
		{dataset: "round9-public-adversarial-v12", bytes: 485221, sha256: "eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387"},
	}
	for _, identity := range historical {
		data, err := os.ReadFile(filepath.Join(root, "testdata", identity.dataset, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if len(data) != identity.bytes || fmt.Sprintf("%x", sum) != identity.sha256 {
			t.Fatalf("%s manifest identity drift: bytes=%d sha256=%x", identity.dataset, len(data), sum)
		}
	}

	previousDirectory := filepath.Join(root, "testdata", "round9-public-adversarial-v12")
	previousManifestData, err := os.ReadFile(filepath.Join(previousDirectory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var previous struct {
		Schema   string          `json:"schema"`
		Dataset  string          `json:"dataset"`
		Payloads []publicPayload `json:"payloads"`
	}
	if err := json.Unmarshal(previousManifestData, &previous); err != nil {
		t.Fatal(err)
	}
	if previous.Schema != "round9-public-adversarial-corpus/v12" || previous.Dataset != "round9-public-adversarial-v12" {
		t.Fatalf("unexpected prior corpus identity: schema=%q dataset=%q", previous.Schema, previous.Dataset)
	}

	current := loadPublicManifest(t)
	previousByIndex := uniquePayloadIndex(previous.Payloads)
	currentByIndex := uniquePayloadIndex(current.Payloads)
	for index := 1; index <= 23; index++ {
		before, beforeOK := previousByIndex[index]
		after, afterOK := currentByIndex[index]
		if !beforeOK || !afterOK {
			t.Fatalf("unique payload index %d missing: previous=%v current=%v", index, beforeOK, afterOK)
		}
		if before.ID != after.ID || before.DecodedBytes != after.DecodedBytes || before.DecodedSHA256 != after.DecodedSHA256 || before.EncodedFile != after.EncodedFile {
			t.Fatalf("unique payload index %d identity drift: previous=%+v current=%+v", index, before, after)
		}
		previousEncoded, err := os.ReadFile(filepath.Join(previousDirectory, filepath.FromSlash(before.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		currentEncoded, err := os.ReadFile(filepath.Join(root, "testdata", datasetName, filepath.FromSlash(after.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(previousEncoded, currentEncoded) {
			t.Fatalf("unique payload index %d encoded bytes differ from frozen v12", index)
		}
	}
}

func TestRound9PublicCorpusV6FrozenInvalidReviewIdentity(t *testing.T) {
	t.Parallel()
	root := publicCorpusRepositoryRoot(t)
	manifestData, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v6", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestData)
	if len(manifestData) != 101408 || fmt.Sprintf("%x", manifestSum) != "74096af7ac49578e0ca82105563cac83e7541e2505d9943f0569a148240ce34c" {
		t.Fatalf("round9 public v6 historical manifest identity drift: bytes=%d sha256=%x", len(manifestData), manifestSum)
	}
	var manifest publicManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	computed := promptLikeReviewSHA256Legacy(manifest.PromptLikeDeltaReview.ExcludedSources)
	if manifest.PromptLikeDeltaReview.ReviewSHA256 != "eb7b1350059a7f2f1a07fd246522f18287e4c47c9712b97e7b6f9dfcf6723abe" ||
		computed != "4efc428894f048fe3474ddbe4c47a17dc618932e710f7f6de6cb3c6aaf89af30" ||
		computed == manifest.PromptLikeDeltaReview.ReviewSHA256 {
		t.Fatalf("v6 frozen-invalid review contract drift: declared=%s computed=%s", manifest.PromptLikeDeltaReview.ReviewSHA256, computed)
	}
}

func TestRound9PublicCorpusV8FrozenInvalidReviewIdentity(t *testing.T) {
	t.Parallel()
	root := publicCorpusRepositoryRoot(t)
	manifestData, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v8", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestData)
	if len(manifestData) != 105299 || fmt.Sprintf("%x", manifestSum) != "5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f" {
		t.Fatalf("round9 public v8 historical manifest identity drift: bytes=%d sha256=%x", len(manifestData), manifestSum)
	}
	var manifest publicManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	computed := promptLikeReviewSHA256Legacy(manifest.PromptLikeDeltaReview.ExcludedSources)
	if manifest.PromptLikeDeltaReview.ReviewSHA256 != "52b1e97c33f9c0221b0feb0cd069c176a663094badd8ef903c0624ed4f6cd48e" ||
		computed != "6772278f4dc5779564b17403ae73c2a9f8350a9405ea5796f96538d5c357ce6b" || computed == manifest.PromptLikeDeltaReview.ReviewSHA256 {
		t.Fatalf("v8 immutable-invalid review contract drift: declared=%s computed=%s", manifest.PromptLikeDeltaReview.ReviewSHA256, computed)
	}
}

func TestRound9PublicCorpusV9LegacyReviewRetention(t *testing.T) {
	t.Parallel()
	root := publicCorpusRepositoryRoot(t)
	manifestData, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v9", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestData)
	if len(manifestData) != 105888 || fmt.Sprintf("%x", manifestSum) != "dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38" {
		t.Fatalf("round9 public v9 historical manifest identity drift: bytes=%d sha256=%x", len(manifestData), manifestSum)
	}
	var manifest publicManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	legacy := promptLikeReviewSHA256Legacy(manifest.PromptLikeDeltaReview.ExcludedSources)
	current := promptLikeReviewSHA256(manifest.PromptLikeDeltaReview.ExcludedSources)
	if manifest.Schema != "round9-public-adversarial-corpus/v9" || manifest.Dataset != "round9-public-adversarial-v9" ||
		manifest.PromptLikeDeltaReview.ReviewSHA256 != "6772278f4dc5779564b17403ae73c2a9f8350a9405ea5796f96538d5c357ce6b" ||
		legacy != manifest.PromptLikeDeltaReview.ReviewSHA256 || current == legacy {
		t.Fatalf("v9 legacy review retention drift: declared=%s legacy=%s current=%s", manifest.PromptLikeDeltaReview.ReviewSHA256, legacy, current)
	}
}

func TestRound9PublicCorpusV8RejectedRebindRetention(t *testing.T) {
	t.Parallel()
	root := publicCorpusRepositoryRoot(t)
	rejectedDirectory := filepath.Join(root, "testdata", "round9-public-adversarial-v8-rejected-rebind")
	rejectedData, err := os.ReadFile(filepath.Join(rejectedDirectory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	rejectedSum := sha256.Sum256(rejectedData)
	if len(rejectedData) != 105298 || fmt.Sprintf("%x", rejectedSum) != "2f953da42d3bb485b08562e4011f20fdeae6ebe76be02da31c27bb3b151e727d" {
		t.Fatalf("round9 public v8 rejected rebind identity drift: bytes=%d sha256=%x", len(rejectedData), rejectedSum)
	}
	var rejected publicManifest
	if err := decodeStrictJSON(rejectedData, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Schema != "round9-public-adversarial-corpus/v8" || rejected.Dataset != "round9-public-adversarial-v8" ||
		rejected.PromptLikeDeltaReview.ReviewSHA256 != "6772278f4dc5779564b17403ae73c2a9f8350a9405ea5796f96538d5c357ce6b" ||
		promptLikeReviewSHA256Legacy(rejected.PromptLikeDeltaReview.ExcludedSources) != rejected.PromptLikeDeltaReview.ReviewSHA256 {
		t.Fatal("rejected v8 rebind content identity drift")
	}

	frozenData, err := os.ReadFile(filepath.Join(root, "testdata", "round9-public-adversarial-v8", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	declaredLine := []byte(`"review_sha256":  "52b1e97c33f9c0221b0feb0cd069c176a663094badd8ef903c0624ed4f6cd48e"` + "\r\n")
	correctedLine := []byte(`"review_sha256":  "6772278f4dc5779564b17403ae73c2a9f8350a9405ea5796f96538d5c357ce6b"` + "\n")
	if bytes.Count(frozenData, declaredLine) != 1 || !bytes.Equal(bytes.Replace(frozenData, declaredLine, correctedLine, 1), rejectedData) {
		t.Fatal("rejected v8 rebind differs from frozen v8 by more than the declared digest and its review-line CR")
	}

	active := loadPublicManifest(t)
	activeDirectory := filepath.Join(root, "testdata", datasetName)
	activePayloads := make(map[string]publicPayload, len(active.Payloads))
	for _, payload := range active.Payloads {
		activePayloads[payload.ID] = payload
	}
	if len(rejected.Payloads) != len(active.Payloads) {
		t.Fatalf("rejected payload records=%d active=%d", len(rejected.Payloads), len(active.Payloads))
	}
	for _, before := range rejected.Payloads {
		after, ok := activePayloads[before.ID]
		if !ok || before.EncodedFile != after.EncodedFile || before.DecodedBytes != after.DecodedBytes || before.DecodedSHA256 != after.DecodedSHA256 {
			t.Fatalf("payload %q identity differs between rejected v8 rebind and active v13", before.ID)
		}
		beforeEncoded, err := os.ReadFile(filepath.Join(rejectedDirectory, filepath.FromSlash(before.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		afterEncoded, err := os.ReadFile(filepath.Join(activeDirectory, filepath.FromSlash(after.EncodedFile)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(beforeEncoded, afterEncoded) {
			t.Fatalf("payload %q encoded bytes differ between rejected v8 rebind and active v13", before.ID)
		}
	}
}

func TestRound9PublicCorpusV13Identity(t *testing.T) {
	t.Parallel()
	root := publicCorpusRepositoryRoot(t)
	manifestData, err := os.ReadFile(filepath.Join(root, "testdata", datasetName, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestData)
	if len(manifestData) != 481448 || fmt.Sprintf("%x", manifestSum) != "91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6" {
		t.Fatalf("round9 public v13 manifest identity drift: bytes=%d sha256=%x", len(manifestData), manifestSum)
	}
	var manifest publicManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != manifestSchema || manifest.Dataset != datasetName ||
		manifest.NondefaultBranchCandidateCarriers != expectedNondefaultBranches ||
		manifest.ReleaseAssetsReviewed != expectedReleaseAssets ||
		manifest.ReleaseAssetsWithPromptEntries != expectedPromptAssets ||
		manifest.ReleaseAssetMetadataRecords != expectedAssetMetadata ||
		promptLikeReviewSHA256(manifest.PromptLikeDeltaReview.ExcludedSources) != expectedDeltaReviewSHA256 {
		t.Fatalf(
			"round9 public v13 structural identity drift: schema=%q dataset=%q branches=%d assets=%d prompt_assets=%d metadata_assets=%d review=%q",
			manifest.Schema,
			manifest.Dataset,
			manifest.NondefaultBranchCandidateCarriers,
			manifest.ReleaseAssetsReviewed,
			manifest.ReleaseAssetsWithPromptEntries,
			manifest.ReleaseAssetMetadataRecords,
			manifest.PromptLikeDeltaReview.ReviewSHA256,
		)
	}
	metrics, err := validatePublicCorpus(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.PayloadRecords != 24 || metrics.UniquePayloads != 23 || metrics.UnmergedCandidateCarriers != 1 ||
		metrics.CandidateCarrierExecutions != 1 || metrics.CandidateCarriersNotProvided != 0 ||
		metrics.ScenarioPayloadExecutions != 24 || metrics.SerializedRouteExecutions != 120 {
		t.Fatalf("unexpected public corpus metrics: %+v", metrics)
	}
}

func TestRound9PublicCorpusV13ClassifierScenarios(t *testing.T) {
	metrics, err := validatePublicCorpus(publicCorpusRepositoryRoot(t), true)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.DirectBlocked != 12 || metrics.DirectAllowed != 12 || metrics.QuotedBlocked != 0 ||
		metrics.HistoricalBlocked != 0 || metrics.SystemBlocked != 0 || metrics.ToolBlocked != 0 ||
		metrics.SerializedRouteExecutions != 120 {
		t.Fatalf("unexpected classifier metrics: %+v", metrics)
	}
}

func TestRound9PublicCorpusV13PromptLikeDefensiveScenarios(t *testing.T) {
	root := publicCorpusRepositoryRoot(t)
	manifest := loadPublicManifest(t)
	directory := filepath.Join(root, "testdata", datasetName)
	filtered := make([]publicPayload, 0, expectedDefensivePayloads)
	decoded := make(map[string][]byte, expectedDefensivePayloads)
	for _, payload := range manifest.Payloads {
		if payload.CorpusRole != "current_default_prompt_like_payload" ||
			payload.DirectCurrentUserGroundTruth != groundTruthAllowOrAudit {
			continue
		}
		data, err := decodePayload(directory, payload)
		if err != nil {
			t.Fatal(err)
		}
		filtered = append(filtered, payload)
		decoded[payload.ID] = data
	}
	if len(filtered) != expectedDefensivePayloads {
		t.Fatalf("prompt-like defensive payloads=%d want %d", len(filtered), expectedDefensivePayloads)
	}
	manifest.Payloads = filtered
	metrics, err := classifyScenarios(manifest, decoded, nil, validationMetrics{
		ScenarioPayloadExecutions: expectedDefensivePayloads,
		SerializedRouteExecutions: expectedDefensivePayloads * expectedContextsPerPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if metrics.DirectAllowed != expectedDefensivePayloads || metrics.DirectBlocked != 0 ||
		metrics.QuotedBlocked != 0 || metrics.HistoricalBlocked != 0 || metrics.SystemBlocked != 0 || metrics.ToolBlocked != 0 {
		t.Fatalf("unexpected prompt-like defensive metrics: %+v", metrics)
	}
}

func TestRound9PublicCorpusRejectsDuplicateJSONKeys(t *testing.T) {
	t.Parallel()
	var value map[string]any
	err := decodeStrictJSON([]byte(`{"schema":"one","schema":"two"}`), &value)
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate-key error=%v", err)
	}
}

func TestRound9PublicCorpusRejectsCarrierSourceAndReviewProvenanceDrift(t *testing.T) {
	t.Parallel()
	manifest := loadPublicManifest(t)
	repositories := repositoryIndex(manifest.Repositories)
	payloads := make(map[string]publicPayload, len(manifest.Payloads))
	for _, payload := range manifest.Payloads {
		payloads[payload.ID] = payload
	}

	manifest.CandidateCarriers[0].Commit = strings.Repeat("0", 40)
	if _, _, err := validateCandidateCarriers(manifest, payloads, repositories); err == nil {
		t.Fatal("mutated candidate carrier provenance was accepted")
	}

	manifest = loadPublicManifest(t)
	payload := manifest.Payloads[0]
	payload.Sources[0].Bytes++
	if err := validatePayloadSchema(payload, map[int]string{}, map[string]string{}, repositoryIndex(manifest.Repositories)); err == nil {
		t.Fatal("mutated source byte identity was accepted")
	}

	manifest = loadPublicManifest(t)
	manifest.PromptLikeDeltaReview.ReviewSHA256 = strings.Repeat("0", 64)
	if err := validatePromptLikeDeltaReview(manifest.PromptLikeDeltaReview, repositoryIndex(manifest.Repositories), manifest.Payloads); err == nil {
		t.Fatal("mutated excluded-source provenance was accepted")
	}

	manifest = loadPublicManifest(t)
	manifest.PromptLikeDeltaReview.ExcludedSources[0].SHA256 = strings.Repeat("0", 64)
	if err := validatePromptLikeDeltaReview(manifest.PromptLikeDeltaReview, repositoryIndex(manifest.Repositories), manifest.Payloads); err == nil {
		t.Fatal("mutated v13 excluded-source file digest was accepted")
	}
}

func TestRound9PublicCorpusRejectsNondefaultBranchProvenanceDrift(t *testing.T) {
	t.Parallel()
	manifest := loadPublicManifest(t)
	if len(manifest.NondefaultBranchCarriers) != expectedNondefaultBranches {
		t.Fatalf("non-default branch carriers=%d want %d", len(manifest.NondefaultBranchCarriers), expectedNondefaultBranches)
	}
	manifest.NondefaultBranchCarriers[0].Commit = strings.Repeat("0", 40)
	if err := validateNondefaultBranchCarriers(
		manifest.NondefaultBranchCarriers,
		repositoryIndex(manifest.Repositories),
		manifest.Payloads,
	); err == nil {
		t.Fatal("mutated non-default branch provenance was accepted")
	}
}

func TestRound9PublicCorpusRejectsReleaseAssetProvenanceDrift(t *testing.T) {
	t.Parallel()
	manifest := loadPublicManifest(t)
	if len(manifest.ReleaseAssetReviews) != expectedReleaseAssets {
		t.Fatalf("Release asset reviews=%d want %d", len(manifest.ReleaseAssetReviews), expectedReleaseAssets)
	}
	manifest.ReleaseAssetReviews[0].Digest = "sha256:" + strings.Repeat("0", 64)
	if err := validateReleaseAssetReviews(
		manifest.ReleaseAssetReviews,
		repositoryIndex(manifest.Repositories),
		manifest.Payloads,
	); err == nil {
		t.Fatal("mutated Release asset digest was accepted")
	}

	manifest = loadPublicManifest(t)
	mutated := false
	var mutatedPayload publicPayload
	for payloadIndex := range manifest.Payloads {
		for sourceIndex := range manifest.Payloads[payloadIndex].Sources {
			source := &manifest.Payloads[payloadIndex].Sources[sourceIndex]
			if source.SourceKind != "release_asset_archive_entry" {
				continue
			}
			source.SourceKind = "repository_archive_entry"
			mutatedPayload = manifest.Payloads[payloadIndex]
			mutated = true
			break
		}
		if mutated {
			break
		}
	}
	if !mutated {
		t.Fatal("missing Release asset archive-entry provenance fixture")
	}
	if err := validatePayloadSchema(mutatedPayload, map[int]string{}, map[string]string{}, repositoryIndex(manifest.Repositories)); err == nil {
		t.Fatal("Release asset archive entry was accepted as Git repository archive provenance")
	}
}

func TestRound9PublicCorpusRejectsMetadataOnlyAssetDrift(t *testing.T) {
	t.Parallel()
	manifest := loadPublicManifest(t)
	if len(manifest.ReleaseAssetMetadata) != expectedAssetMetadata ||
		manifest.BinaryReleaseAssetsDownloaded || manifest.BinaryReleaseAssetsOpened {
		t.Fatalf("unexpected metadata-only asset boundary: records=%d downloaded=%t opened=%t",
			len(manifest.ReleaseAssetMetadata),
			manifest.BinaryReleaseAssetsDownloaded,
			manifest.BinaryReleaseAssetsOpened,
		)
	}
	manifest.ReleaseAssetMetadata[0].Digest = "sha256:" + strings.Repeat("0", 64)
	if err := validateReleaseAssetMetadata(manifest.ReleaseAssetMetadata, repositoryIndex(manifest.Repositories)); err == nil {
		t.Fatal("mutated metadata-only Release asset digest was accepted")
	}
}

func TestRound9PublicCorpusRejectsCodexXHeadAdvanceDrift(t *testing.T) {
	t.Parallel()
	manifest := loadPublicManifest(t)
	if computed := codexXHeadAdvanceReviewSHA256(manifest.CodexXHeadAdvanceReview); computed != expectedCodexXReviewSHA256 {
		t.Fatalf("Codex-X head-advance review digest=%s want %s", computed, expectedCodexXReviewSHA256)
	}
	manifest.CodexXHeadAdvanceReview.ChangedPaths[0].GitBlobSHA = strings.Repeat("0", 40)
	if err := validateCodexXHeadAdvanceReview(
		manifest.CodexXHeadAdvanceReview,
		repositoryIndex(manifest.Repositories),
		manifest.Payloads,
	); err == nil {
		t.Fatal("mutated Codex-X head-advance provenance was accepted")
	}
}

func TestRound9PublicCorpusGroundTruthMutationRejected(t *testing.T) {
	t.Parallel()
	manifest := loadPublicManifest(t)
	repositories := repositoryIndex(manifest.Repositories)

	malicious := manifest.Payloads[0]
	if malicious.DirectCurrentUserGroundTruth != groundTruthBlockMalicious {
		t.Fatalf("unexpected malicious fixture ground truth %q", malicious.DirectCurrentUserGroundTruth)
	}
	malicious.DirectCurrentUserGroundTruth = groundTruthAllowOrAudit
	if err := validatePayloadSchema(malicious, map[int]string{}, map[string]string{}, repositories); err == nil {
		t.Fatal("mutated malicious direct ground truth was accepted")
	}

	var defensive publicPayload
	for _, payload := range manifest.Payloads {
		if payload.CorpusRole == "current_default_prompt_like_payload" {
			defensive = payload
			break
		}
	}
	if defensive.ID == "" {
		t.Fatal("missing defensive prompt-like payload")
	}
	defensive.DirectCurrentUserGroundTruth = groundTruthBlockMalicious
	if err := validatePayloadSchema(defensive, map[int]string{}, map[string]string{}, repositories); err == nil {
		t.Fatal("mutated defensive direct ground truth was accepted")
	}

	blocked := classifier.Result{
		Action:           classifier.ActionBlock,
		BlockEligibility: &classifier.CandidateBlockEligibility{Eligible: true},
	}
	if _, err := enforceGroundTruth("mutation", "direct_current_user", groundTruthAllowOrAudit, blocked); err == nil {
		t.Fatal("allow_or_audit ground truth did not reject an observed block")
	}
	if blockedResult, err := enforceGroundTruth("control", "direct_current_user", groundTruthBlockMalicious, blocked); err != nil || !blockedResult {
		t.Fatalf("block_malicious_text control rejected: blocked=%v err=%v", blockedResult, err)
	}
}

func loadPublicManifest(t *testing.T) publicManifest {
	t.Helper()
	path := filepath.Join(publicCorpusRepositoryRoot(t), "testdata", datasetName, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest publicManifest
	if err := decodeStrictJSON(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func publicCorpusRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func uniquePayloadIndex(payloads []publicPayload) map[int]publicPayload {
	result := make(map[int]publicPayload, expectedFormalPayloads)
	for _, payload := range payloads {
		if payload.UniquePayloadIndex != nil {
			result[*payload.UniquePayloadIndex] = payload
		}
	}
	return result
}
