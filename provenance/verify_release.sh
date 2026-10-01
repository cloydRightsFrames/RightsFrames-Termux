#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

OWNER=${1:?owner required}
REPO=${2:?repo required}
TAG=${3:?tag required}
ARTIFACT=${4:?artifact required}

REPO_FULL="${OWNER}/${REPO}"
BASE="https://github.com/${REPO_FULL}"

command -v gh >/dev/null
command -v sha256sum >/dev/null
command -v python3 >/dev/null

test -f "$ARTIFACT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MANIFEST="${TMP}/release-manifest.json"

gh api \
  "repos/${REPO_FULL}/releases/tags/${TAG}" \
  > "${TMP}/release.json"

python3 - "${TMP}/release.json" "$MANIFEST" "$ARTIFACT" "$REPO_FULL" "$TAG" <<'PY'
import json
import sys

release=json.load(open(sys.argv[1],encoding='utf-8'))
manifest={
    "repository":sys.argv[4],
    "tag":sys.argv[5],
    "artifact":sys.argv[3],
}

assets=release.get("assets",[])
target=next((x for x in assets if x["name"]=="release-manifest.json"),None)

if target is None:
    raise SystemExit("release-manifest.json missing")

import urllib.request
with urllib.request.urlopen(target["browser_download_url"]) as r:
    data=r.read()

open(sys.argv[2],"wb").write(data)

m=json.loads(data)

for k,v in manifest.items():
    if m.get(k)!=v:
        raise SystemExit(f"manifest mismatch: {k}")

if m.get("predicateType")!="https://slsa.dev/provenance/v1":
    raise SystemExit("unexpected predicate type")

if not m.get("commit"):
    raise SystemExit("missing immutable commit")

if not m.get("sha256"):
    raise SystemExit("missing subject digest")
PY

EXPECTED="$(python3 - "$MANIFEST" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))["sha256"])
PY
)"

ACTUAL="$(sha256sum "$ARTIFACT" | awk '{print $1}')"

test "$ACTUAL" = "$EXPECTED"

gh attestation verify \
  "$ARTIFACT" \
  --repo "$REPO_FULL" \
  --predicate-type 'https://slsa.dev/provenance/v1' \
  --signer-workflow "${REPO_FULL}/.github/workflows/provenance-gate.yml" \
  --source-ref "refs/tags/${TAG}" \
  --deny-self-hosted-runners

printf '%s\n' 'RIGHTSFRAMES_PROVENANCE=VERIFIED'
printf '%s\n' "REPOSITORY=${REPO_FULL}"
printf '%s\n' "TAG=${TAG}"
printf '%s\n' "SHA256=${ACTUAL}"
printf '%s\n' 'EXTERNAL_ATTESTATION=VERIFIED'
printf '%s\n' 'INDEPENDENT_VERIFICATION=PASSED'
