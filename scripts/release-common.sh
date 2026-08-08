#!/usr/bin/env bash
# Shared, side-effect-free release metadata helpers. Callers are responsible
# for enabling `set -euo pipefail` before sourcing this file.

RELEASE_ROOT="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
export LC_ALL=C
export TZ=UTC
readonly RELEASE_CYCLONEDX_MAIN_MODULE="github.com/yujianwudi/cyber-abuse-guard-next"

# Every release helper addresses repositories explicitly with git -C. Clear
# inherited repository-routing variables before any helper can create or
# inspect a fixture: Git gives these variables precedence over -C, so carrying
# a caller's worktree into a temporary-repository contract test can otherwise
# mutate the real checkout.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \
  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE

release_error() {
  printf 'release error: %s\n' "$*" >&2
}

release_die() {
  release_error "$*"
  exit 1
}

release_require_commands() {
  local command_name
  for command_name in "$@"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      printf 'required release command not found: %s\n' "$command_name" >&2
      exit 127
    fi
  done
}

# release_assert_no_sensitive_env_values rejects a generated text artifact if
# it contains any configured secret value that the release process can inherit.
# Diagnostics identify only the environment variable name and never echo the
# value. Every non-empty configured value is checked, including short secrets.
release_assert_no_sensitive_env_values() {
  local artifact="$1"
  shift
  [[ -f "$artifact" && ! -L "$artifact" ]] || \
    release_die "privacy scan input must be a regular non-symlink file"
  # Keep inherited secrets out of child-process argv. Release evidence is a
  # bounded text artifact, so comparing it inside Bash avoids exposing the
  # values through a transient grep/awk process while preserving multiline
  # substring matching.
  release_require_commands cat
  local artifact_text sentinel="__CAG_RELEASE_PRIVACY_SCAN_EOF__"
  if ! artifact_text="$({ cat -- "$artifact" || exit 1; printf '%s' "$sentinel"; })"; then
    release_die "privacy scan could not read its input artifact"
  fi
  artifact_text="${artifact_text%"$sentinel"}"
  local name value
  for name in "$@"; do
    [[ "$name" =~ ^[A-Z][A-Z0-9_]*$ ]] || \
      release_die "privacy scan received an invalid environment variable name"
    value="${!name:-}"
    [[ -n "$value" ]] || continue
    if [[ "$artifact_text" == *"$value"* ]]; then
      release_die "generated release output contains a sensitive value from $name"
    fi
  done
}

release_ruleset_files() {
  local file
  shopt -s nullglob
  local files=("$RELEASE_ROOT"/rules/*.yaml)
  shopt -u nullglob
  ((${#files[@]} > 0)) || release_die "no embedded rule YAML files found"
  for file in "${files[@]}"; do
    printf '%s\n' "$file"
  done | LC_ALL=C sort
}

release_ruleset_hash() {
  local file relative hash
  while IFS= read -r file; do
    relative="${file#"$RELEASE_ROOT"/}"
    hash="$(sha256sum "$file" | awk '{print $1}')"
    printf '%s  %s\n' "$hash" "$relative"
  done < <(release_ruleset_files) | sha256sum | awk '{print $1}'
}

release_round6_safe_sparse_path() {
  local path="${1,,}"
  case "$path" in
    cmd/*evaluation*|cmd/*holdout*|cmd/*consumed*|cmd/*private*|cmd/*blind*|cmd/*retired*|\
    docs/*evaluation_*|docs/*holdout_*|\
    docs/*consumed*|docs/*private*|docs/*blind*|docs/*retired*|\
    internal/classifier/*evaluation*|internal/classifier/*holdout*|\
    internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*blind*|internal/classifier/*retired*|\
    testdata/*evaluation*|testdata/*holdout*|testdata/*consumed*|testdata/*private*|testdata/*blind*|testdata/*retired*|\
    testdata/round9-independent-benign-v1/*|testdata/round9-independent-malicious-v1/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

release_init() {
	release_require_commands git sed awk sha256sum sort head
	local buildinfo_ruleset_version unsafe_index_entries

  RELEASE_SOURCE_VERSION="$(sed -nE 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$RELEASE_ROOT/internal/buildinfo/buildinfo.go" | head -n 1)"
  [[ "$RELEASE_SOURCE_VERSION" =~ ^[0-9]+\.[0-9]+$ ]] || \
    release_die "cannot read the exact two-component source version from internal/buildinfo/buildinfo.go"

  RELEASE_RULESET_VERSION="$(sed -nE 's/^[[:space:]]*version:[[:space:]]*"([^"]+)".*/\1/p' \
    "$RELEASE_ROOT/rules/manifest.yaml" | head -n 1)"
	[[ "$RELEASE_RULESET_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
		release_die "cannot read a semantic ruleset version from rules/manifest.yaml"
	buildinfo_ruleset_version="$(sed -nE 's/^[[:space:]]*RulesetVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
		"$RELEASE_ROOT/internal/buildinfo/buildinfo.go" | head -n 1)"
	[[ "$buildinfo_ruleset_version" == "$RELEASE_RULESET_VERSION" ]] || \
		release_die "buildinfo ruleset version $buildinfo_ruleset_version does not match manifest $RELEASE_RULESET_VERSION"

  RELEASE_CLASSIFIER_POLICY_VERSION="$(sed -nE 's/^[[:space:]]*const[[:space:]]+ClassifierPolicyVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$RELEASE_ROOT/internal/classifier/policy_identity.go" | head -n 1)"
  [[ "$RELEASE_CLASSIFIER_POLICY_VERSION" =~ ^classifier-policy-v[0-9]+$ ]] || \
    release_die "cannot read classifier policy version from internal/classifier/policy_identity.go"
  RELEASE_CLASSIFIER_POLICY_SHA256="$(sed -nE 's/^[[:space:]]*const[[:space:]]+ClassifierPolicySHA256[[:space:]]*=[[:space:]]*"([0-9a-f]+)".*/\1/p' \
    "$RELEASE_ROOT/internal/classifier/policy_identity.go" | head -n 1)"
  [[ "$RELEASE_CLASSIFIER_POLICY_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
    release_die "cannot read classifier policy SHA-256 from internal/classifier/policy_identity.go"
  RELEASE_STREAMING_SCANNER="$(sed -nE 's/^[[:space:]]*const[[:space:]]+StreamingScannerIdentity[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$RELEASE_ROOT/internal/buildinfo/buildinfo.go" | head -n 1)"
  [[ "$RELEASE_STREAMING_SCANNER" =~ ^streaming-scanner-v[0-9]+$ ]] || \
    release_die "cannot read streaming scanner identity from internal/buildinfo/buildinfo.go"

  RELEASE_VERSION="${VERSION:-$RELEASE_SOURCE_VERSION}"
  [[ "$RELEASE_VERSION" == "$RELEASE_SOURCE_VERSION" ]] || \
    release_die "VERSION=$RELEASE_VERSION does not match source version $RELEASE_SOURCE_VERSION"

  RELEASE_GIT_COMMIT="$(git -C "$RELEASE_ROOT" rev-parse --verify HEAD)"
  [[ "$RELEASE_GIT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || \
    release_die "Git HEAD is not a full commit SHA"
  RELEASE_GIT_TREE="$(git -C "$RELEASE_ROOT" rev-parse --verify 'HEAD^{tree}')"
  [[ "$RELEASE_GIT_TREE" =~ ^[0-9a-f]{40}$ ]] || \
    release_die "Git HEAD tree is not a full tree SHA"

  RELEASE_DIRTY_STATUS="$(git -C "$RELEASE_ROOT" status --porcelain --untracked-files=normal)"
  local dirty_build="${ALLOW_DIRTY_BUILD:-0}"
  local candidate_build="${RELEASE_CANDIDATE_BUILD:-0}"
  local rc_build="${RELEASE_RC_BUILD:-0}"
  case "$dirty_build:$candidate_build:$rc_build" in
    0:0:0|0:1:0|0:0:1)
      if [[ -n "$RELEASE_DIRTY_STATUS" ]]; then
        release_error "clean formal, candidate, and RC builds require a clean Git worktree"
        printf '%s\n' "$RELEASE_DIRTY_STATUS" >&2
        release_error "set ALLOW_DIRTY_BUILD=1 only for a non-release development build"
        exit 1
      fi
      unsafe_index_entries="$(git -C "$RELEASE_ROOT" ls-files -v | \
        awk 'substr($0, 1, 1) == "S" || substr($0, 1, 1) ~ /[a-z]/')"
      if [[ -n "$unsafe_index_entries" ]]; then
        if [[ "${ROUND6_SAFE_SPARSE_BUILD:-0}" == 1 ]]; then
          git -C "$RELEASE_ROOT" sparse-checkout list >/dev/null 2>&1 || \
            release_die "ROUND6_SAFE_SPARSE_BUILD requires an active sparse checkout"
          while IFS= read -r entry; do
            status="${entry:0:1}"
            path="${entry:2}"
            if [[ "$status" != S ]] || ! release_round6_safe_sparse_path "$path"; then
              release_die "Round6 sparse checkout contains an unapproved index flag or excluded path: $path"
            fi
          done <<<"$unsafe_index_entries"
        else
          release_error "formal builds reject skip-worktree and assume-unchanged index flags"
          printf '%s\n' "$unsafe_index_entries" >&2
          release_error "clear the flags and verify the tracked worktree before releasing"
          exit 1
        fi
      fi
      RELEASE_DIRTY=false
      if [[ "$candidate_build" == 1 ]]; then
        RELEASE_ARTIFACT_VERSION="$RELEASE_VERSION"
        [[ "${RELEASE_CANDIDATE_EXPECTED_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || \
          release_die "candidate builds require RELEASE_CANDIDATE_EXPECTED_COMMIT"
        [[ "${RELEASE_CANDIDATE_EXPECTED_TREE:-}" =~ ^[0-9a-f]{40}$ ]] || \
          release_die "candidate builds require RELEASE_CANDIDATE_EXPECTED_TREE"
        [[ "$RELEASE_CANDIDATE_EXPECTED_COMMIT" == "$RELEASE_GIT_COMMIT" ]] || \
          release_die "candidate expected commit does not match HEAD"
        [[ "$RELEASE_CANDIDATE_EXPECTED_TREE" == "$RELEASE_GIT_TREE" ]] || \
          release_die "candidate expected tree does not match HEAD"
        RELEASE_BUILD_KIND=candidate
      elif [[ "$rc_build" == 1 ]]; then
        [[ "${RELEASE_RC_TAG:-}" =~ ^v${RELEASE_SOURCE_VERSION//./\\.}-rc\.[1-9][0-9]*$ ]] || \
          release_die "RC builds require RELEASE_RC_TAG=v${RELEASE_SOURCE_VERSION}-rc.N with N >= 1 and no leading zero"
        [[ "${RELEASE_RC_EXPECTED_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || \
          release_die "RC builds require RELEASE_RC_EXPECTED_COMMIT"
        [[ "${RELEASE_RC_EXPECTED_TREE:-}" =~ ^[0-9a-f]{40}$ ]] || \
          release_die "RC builds require RELEASE_RC_EXPECTED_TREE"
        [[ "$RELEASE_RC_EXPECTED_COMMIT" == "$RELEASE_GIT_COMMIT" ]] || \
          release_die "RC expected commit does not match HEAD"
        [[ "$RELEASE_RC_EXPECTED_TREE" == "$RELEASE_GIT_TREE" ]] || \
          release_die "RC expected tree does not match HEAD"
        RELEASE_ARTIFACT_VERSION="${RELEASE_RC_TAG#v}"
        RELEASE_BUILD_KIND=rc
      else
        RELEASE_ARTIFACT_VERSION="$RELEASE_VERSION"
        RELEASE_BUILD_KIND=formal
      fi
      ;;
    1:0:0)
      RELEASE_DIRTY=true
      RELEASE_ARTIFACT_VERSION="${RELEASE_VERSION}-dirty"
      RELEASE_BUILD_KIND=development
      printf 'warning: ALLOW_DIRTY_BUILD=1 creates development-only artifacts marked %s\n' \
        "$RELEASE_ARTIFACT_VERSION" >&2
      ;;
    *)
      release_die "ALLOW_DIRTY_BUILD, RELEASE_CANDIDATE_BUILD, and RELEASE_RC_BUILD must each be 0 or 1 and are mutually exclusive"
      ;;
  esac

  RELEASE_RULESET_SHA256="$(release_ruleset_hash)"
  [[ "$RELEASE_RULESET_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
    release_die "failed to calculate the embedded ruleset SHA256"

  local commit_source_date_epoch
  commit_source_date_epoch="$(git -C "$RELEASE_ROOT" show -s --format=%ct HEAD)"
  RELEASE_SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$commit_source_date_epoch}"
  [[ "$RELEASE_SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || \
    release_die "SOURCE_DATE_EPOCH must be an integer"
  ((RELEASE_SOURCE_DATE_EPOCH >= 315532800)) || \
    release_die "SOURCE_DATE_EPOCH must be at or after 1980-01-01"
  if [[ "$RELEASE_BUILD_KIND" != development && \
    "$RELEASE_SOURCE_DATE_EPOCH" != "$commit_source_date_epoch" ]]; then
    release_die "clean candidate, RC, and formal builds require the exact commit timestamp"
  fi

  export RELEASE_ROOT RELEASE_SOURCE_VERSION RELEASE_RULESET_VERSION
  export RELEASE_VERSION RELEASE_GIT_COMMIT RELEASE_GIT_TREE RELEASE_DIRTY RELEASE_ARTIFACT_VERSION
  export RELEASE_BUILD_KIND
  export RELEASE_RULESET_SHA256 RELEASE_CLASSIFIER_POLICY_VERSION RELEASE_CLASSIFIER_POLICY_SHA256
  export RELEASE_STREAMING_SCANNER RELEASE_SOURCE_DATE_EPOCH
}

release_cyclonedx_component_version() {
  local commit_timestamp
  commit_timestamp="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y%m%d%H%M%S')"
  case "$RELEASE_BUILD_KIND" in
    candidate)
      printf 'v0.0.0-%s-%s\n' "$commit_timestamp" "${RELEASE_GIT_COMMIT:0:12}"
      ;;
    formal)
      printf 'v%s\n' "$RELEASE_SOURCE_VERSION"
      ;;
    rc)
      printf '%s\n' "$RELEASE_RC_TAG"
      ;;
    development)
      printf 'v%s.%s\n' "$RELEASE_ARTIFACT_VERSION" "${RELEASE_GIT_COMMIT:0:12}"
      ;;
    *)
      release_die "cannot derive CycloneDX identity for unknown build kind"
      ;;
  esac
}

# cyclonedx-gomod v1.9.0 treats main-module version discovery as optional and
# silently omits it when go-git cannot traverse a linked-worktree common object
# directory. Canonicalize the generated main component from release_init's
# exact source identity so root and independent sparse builds cannot diverge or
# accidentally claim a formal version. Dependency components remain entirely
# generator-owned.
release_normalize_cyclonedx_sbom() {
  local input="$1"
  local output="$2"
  local timestamp="$3"
  local module="$RELEASE_CYCLONEDX_MAIN_MODULE"
  local component_version component_base component_ref component_purl
  local generated_git_version_pattern old_ref allow_other_version=false
  local commit_property="cag:source:git-commit"
  local tree_property="cag:source:git-tree"
  local kind_property="cag:build:kind"

  release_require_commands jq date
  [[ -f "$input" && ! -L "$input" ]] || \
    release_die "CycloneDX normalization input must be a regular non-symlink file"
  [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    release_die "CycloneDX normalization timestamp is invalid"

  component_version="$(release_cyclonedx_component_version)"
  # cyclonedx-gomod may derive its pseudo-version from an older formal tag and
  # uses Git author time rather than release_init's committer epoch. Accept
  # only the pinned Go pseudo-version shape whose terminal revision is the
  # exact current HEAD prefix; the authoritative build-kind identity still
  # replaces it below.
  generated_git_version_pattern="^v[0-9]+[.][0-9]+[.][0-9]+-([0-9A-Za-z.-]+[.])?[0-9]{14}-${RELEASE_GIT_COMMIT:0:12}([+][0-9A-Za-z.-]+)?$"
  component_base="pkg:golang/$module"
  component_ref="${component_base}@${component_version}?type=module"
  component_purl="${component_ref}&goos=linux&goarch=amd64"
  if [[ "$RELEASE_BUILD_KIND" == development ]]; then
    allow_other_version=true
  fi
  old_ref="$(jq -er '.metadata.component["bom-ref"] | select(type == "string" and length > 0)' "$input")" || \
    release_die "CycloneDX generated main component reference is missing"

  if ! jq -S -e \
    --arg timestamp "$timestamp" \
    --arg module "$module" \
    --arg base "$component_base" \
    --arg version "$component_version" \
    --arg generated_git_version_pattern "$generated_git_version_pattern" \
    --arg ref "$component_ref" \
    --arg purl "$component_purl" \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    --arg kind "$RELEASE_BUILD_KIND" \
    --arg commit_property "$commit_property" \
    --arg tree_property "$tree_property" \
    --arg kind_property "$kind_property" \
    --argjson allow_other_version "$allow_other_version" \
    '(.metadata.component["bom-ref"]) as $old_ref |
     (.metadata.component.version // null) as $old_version |
     ($base + "?type=module") as $unversioned_ref |
     ((.metadata.component.properties // [])) as $properties |
     if (
       .bomFormat == "CycloneDX" and .specVersion == "1.6" and
       (.metadata | type) == "object" and
       (.metadata.component | type) == "object" and
       .metadata.component.type == "application" and
       .metadata.component.name == $module and
       (.metadata.component.purl | type) == "string" and
       (
         ($old_version == null and $old_ref == $unversioned_ref) or
         (
           $old_version != null and ($old_version | type) == "string" and
           ($old_version | length) > 0 and
           (
             $old_version == $version or
             ($old_version | test($generated_git_version_pattern)) or
             ($allow_other_version and
               ($old_version | test("^v[0-9]+[.][0-9]+([.][0-9]+)?([-+][0-9A-Za-z.-]+)?$")))
           ) and
           $old_ref == ($base + "@" + $old_version + "?type=module")
         )
       ) and
       .metadata.component.purl == ($old_ref + "&goos=linux&goarch=amd64") and
       (.components | type) == "array" and
       ([.components[] | select(type == "object" and .name == $module)] | length) == 0 and
       (.dependencies | type) == "array" and
       all(.dependencies[];
         type == "object" and (.ref | type) == "string" and
         ((has("dependsOn") | not) or
           ((.dependsOn | type) == "array" and all(.dependsOn[]; type == "string")))) and
       ([.dependencies[] | select(.ref == $old_ref)] | length) == 1 and
       ($old_ref == $ref or ([.dependencies[] | select(.ref == $ref)] | length) == 0) and
       ($properties | type) == "array" and
       all($properties[]; type == "object" and (.name | type) == "string") and
       ([$properties[] |
         select(.name == $commit_property or .name == $tree_property or
           .name == $kind_property)] | length) == 0
     ) then
       .metadata.timestamp = $timestamp |
       .metadata.component.version = $version |
       .metadata.component["bom-ref"] = $ref |
       .metadata.component.purl = $purl |
       .metadata.component.properties = ($properties + [
         {name: $commit_property, value: $commit},
         {name: $tree_property, value: $tree},
         {name: $kind_property, value: $kind}
       ]) |
       .dependencies |= map(
         (if .ref == $old_ref then .ref = $ref else . end) |
         (if has("dependsOn") then
            .dependsOn |= map(if . == $old_ref then $ref else . end)
          else . end)
       )
     else
       error("generated CycloneDX main component identity is ambiguous")
     end' \
    "$input" >"$output"; then
    release_die "failed to normalize the exact CycloneDX main component identity"
  fi

  jq -e \
    --arg version "$component_version" \
    --arg ref "$component_ref" \
    --arg purl "$component_purl" \
    --arg old_ref "$old_ref" \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    --arg kind "$RELEASE_BUILD_KIND" \
    --arg commit_property "$commit_property" \
    --arg tree_property "$tree_property" \
    --arg kind_property "$kind_property" \
    '.metadata.component.version == $version and
     .metadata.component["bom-ref"] == $ref and
     .metadata.component.purl == $purl and
     ([.metadata.component.properties[] |
       select(.name == $commit_property and .value == $commit)] | length) == 1 and
     ([.metadata.component.properties[] |
       select(.name == $tree_property and .value == $tree)] | length) == 1 and
     ([.metadata.component.properties[] |
       select(.name == $kind_property and .value == $kind)] | length) == 1 and
     ([.dependencies[] | select(.ref == $ref)] | length) == 1 and
     ($old_ref == $ref or
       (([.dependencies[] | select(.ref == $old_ref)] | length) == 0 and
        ([.dependencies[] | .dependsOn[]? | select(. == $old_ref)] | length) == 0))' \
    "$output" >/dev/null || \
    release_die "normalized CycloneDX main component identity did not verify"
}

release_assert_tag() {
  local tag
  case "$RELEASE_BUILD_KIND" in
    development)
      printf 'development build: annotated release tag check skipped\n' >&2
      return 0
      ;;
    candidate)
      printf 'candidate build: exact commit/tree binding replaces release-tag authorization\n' >&2
      return 0
      ;;
    formal)
      tag="v$RELEASE_SOURCE_VERSION"
      ;;
    rc)
      tag="$RELEASE_RC_TAG"
      ;;
    *)
      release_die "unknown release build kind: ${RELEASE_BUILD_KIND:-<unset>}"
      ;;
  esac
  if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
		[[ "${GITHUB_REF_TYPE:-}" == tag ]] || \
			release_die "clean GitHub release must be triggered by a tag ref"
		[[ "${GITHUB_REF_NAME:-}" == "$tag" ]] || \
			release_die "GitHub trigger tag ${GITHUB_REF_NAME:-<unset>} does not match release tag $tag"
	fi
	[[ "$(git -C "$RELEASE_ROOT" cat-file -t "refs/tags/$tag" 2>/dev/null || true)" == tag ]] || \
    release_die "clean release requires annotated tag $tag at HEAD"
  [[ "$(git -C "$RELEASE_ROOT" rev-list -n 1 "$tag")" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "tag $tag does not point to HEAD $RELEASE_GIT_COMMIT"
}

release_assert_formal_build() {
  [[ "$RELEASE_BUILD_KIND" == formal ]] || \
    release_die "this operation requires a formal annotated-tag build"
  [[ "$RELEASE_DIRTY" == false ]] || \
    release_die "formal operations refuse dirty development builds"
}

release_assert_candidate_build() {
  [[ "$RELEASE_BUILD_KIND" == candidate ]] || \
    release_die "this operation requires an exact-commit candidate build"
  [[ "$RELEASE_DIRTY" == false ]] || \
    release_die "candidate builds must use clean release bytes"
  local formal_tag="v$RELEASE_SOURCE_VERSION"
  if git -C "$RELEASE_ROOT" show-ref --verify --quiet "refs/tags/$formal_tag"; then
    release_die "candidate builds are forbidden after any formal tag ref $formal_tag exists"
  fi
}

release_assert_rc_build() {
  [[ "$RELEASE_BUILD_KIND" == rc ]] || \
    release_die "this operation requires a clean annotated-tag RC build"
  [[ "$RELEASE_DIRTY" == false ]] || \
    release_die "RC builds must use clean release bytes"
  [[ "$RELEASE_ARTIFACT_VERSION" =~ ^${RELEASE_SOURCE_VERSION//./\\.}-rc\.[1-9][0-9]*$ ]] || \
    release_die "RC artifact version does not match source version $RELEASE_SOURCE_VERSION"
  [[ "$RELEASE_RC_TAG" == "v$RELEASE_ARTIFACT_VERSION" ]] || \
    release_die "RC tag and artifact version do not match"
  local formal_tag="v$RELEASE_SOURCE_VERSION"
  if git -C "$RELEASE_ROOT" show-ref --verify --quiet "refs/tags/$formal_tag"; then
    release_die "RC builds are forbidden after the formal tag $formal_tag exists"
  fi
}

release_assert_source_unchanged() {
  [[ "$RELEASE_BUILD_KIND" == development ]] && return 0
  [[ "$(git -C "$RELEASE_ROOT" rev-parse --verify HEAD)" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "Git HEAD changed during the release operation"
  local current_status
  current_status="$(git -C "$RELEASE_ROOT" status --porcelain --untracked-files=normal)"
  if [[ -n "$current_status" ]]; then
    release_error "Git worktree changed during the release operation"
    printf '%s\n' "$current_status" >&2
    exit 1
  fi
}
