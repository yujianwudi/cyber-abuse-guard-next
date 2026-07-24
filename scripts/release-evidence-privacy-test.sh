#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
safe="$work/release-evidence.md"
diagnostic="$work/diagnostic.log"
short_artifact="$work/short-secret.md"
short_diagnostic="$work/short-diagnostic.log"

export CPA_MANAGEMENT_KEY="RELEASE_EVIDENCE_MANAGEMENT_CANARY_91f2a63c"
export CYBER_ABUSE_GUARD_HMAC_KEY="RELEASE_EVIDENCE_HMAC_CANARY_d5c04b78"
export OPENAI_API_KEY="RELEASE_EVIDENCE_API_CANARY_0f87d3a1"
export GH_TOKEN="S7xK2qZ"

printf '# Development release evidence fixture\n\nOnly hashes and coarse status are allowed.\n' >"$safe"
release_assert_no_sensitive_env_values "$safe" \
  CPA_MANAGEMENT_KEY CYBER_ABUSE_GUARD_HMAC_KEY OPENAI_API_KEY

printf 'unsafe=%s\n' "$CPA_MANAGEMENT_KEY" >>"$safe"
if (release_assert_no_sensitive_env_values "$safe" \
    CPA_MANAGEMENT_KEY CYBER_ABUSE_GUARD_HMAC_KEY OPENAI_API_KEY) \
    >"$diagnostic" 2>&1; then
  printf 'release evidence privacy scan accepted a canary\n' >&2
  exit 1
fi
for canary in "$CPA_MANAGEMENT_KEY" "$CYBER_ABUSE_GUARD_HMAC_KEY" "$OPENAI_API_KEY"; do
  if grep -Fq -- "$canary" "$diagnostic"; then
    printf 'release evidence privacy diagnostic reflected a canary\n' >&2
    exit 1
  fi
done

printf '# Short-secret fixture\n' >"$short_artifact"
printf 'unsafe=%s\n' "$GH_TOKEN" >>"$short_artifact"
if (release_assert_no_sensitive_env_values "$short_artifact" GH_TOKEN) \
    >"$short_diagnostic" 2>&1; then
  printf 'release evidence privacy scan accepted a short secret\n' >&2
  exit 1
fi
if grep -Fq -- "$GH_TOKEN" "$short_diagnostic"; then
  printf 'release evidence short-secret diagnostic reflected a canary\n' >&2
  exit 1
fi

printf 'release evidence privacy canary test: PASS\n'
