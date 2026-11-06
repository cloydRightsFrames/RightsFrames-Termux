#!/usr/bin/env bash
set -euo pipefail

REPO='cloydRightsFrames/RightsFrames-Termux'
TAG="${1:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

command -v gh >/dev/null
command -v git >/dev/null
command -v sha256sum >/dev/null
command -v python3 >/dev/null

if [ -z "$TAG" ]; then
  TAG="$(gh release list --repo "$REPO" --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName')"
fi

case "$TAG" in
  v*) ;;
  *) echo 'ERROR: version tag required' >&2; exit 1 ;;
esac

echo "VERIFYING_REPOSITORY=$REPO"
echo "VERIFYING_TAG=$TAG"


gh release download "$TAG"   --repo "$REPO"   --pattern "RightsFrames-Termux-$TAG.tar.gz"   --pattern SHA256SUMS   --pattern release-manifest.json   --dir "$TMP/release"

ART="$TMP/release/RightsFrames-Termux-$TAG.tar.gz"
MANIFEST="$TMP/release/release-manifest.json"

test -s "$ART"
test -s "$TMP/release/SHA256SUMS"
test -s "$MANIFEST"

(
  cd "$TMP/release"
  sha256sum -c SHA256SUMS
)

TAG_OBJECT="$(git ls-remote "https://github.com/$REPO.git" "refs/tags/$TAG" | awk '{print $1}')"
TAG_TARGET="$(git ls-remote "https://github.com/$REPO.git" "refs/tags/$TAG^{}" | awk '{print $1}')"

test "${#TAG_OBJECT}" -eq 40
test "${#TAG_TARGET}" -eq 40

git clone --quiet --filter=blob:none --no-checkout "https://github.com/$REPO.git" "$TMP/source"
git -C "$TMP/source" fetch --quiet --depth=1 origin "refs/tags/$TAG"
git -C "$TMP/source" checkout --quiet --detach "$TAG_TARGET"

SOURCE_COMMIT="$(git -C "$TMP/source" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$TMP/source" rev-parse HEAD^{tree})"

test "$SOURCE_COMMIT" = "$TAG_TARGET"

python3 - "$MANIFEST" "$ART" "$REPO" "$TAG" "$TAG_TARGET" "$SOURCE_TREE" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
artifact = pathlib.Path(sys.argv[2])
repo = sys.argv[3]
tag = sys.argv[4]
commit = sys.argv[5]
tree = sys.argv[6]

digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

assert manifest['repository'] == repo
assert manifest['tag'] == tag
assert manifest['ref'] == f'refs/tags/{tag}'
assert manifest['commit'] == commit
assert manifest['tree'] == tree
assert manifest['artifact'] == artifact.name
assert manifest['sha256'] == digest
assert manifest['predicateType'] == 'https://slsa.dev/provenance/v1'
assert manifest.get('workflowRef') == f'{repo}/.github/workflows/provenance-gate.yml@refs/tags/{tag}'
if 'slsaBuildLevel' in manifest:
    assert manifest['slsaBuildLevel'] == 3
if 'signerWorkflow' in manifest:
    assert manifest['signerWorkflow'] == f'{repo}/.github/workflows/provenance-gate.yml'
assert manifest['runner'] == 'GitHub-hosted'
assert manifest['reproducible'] is True
assert manifest['independentBuilds'] == 2
PY

rm -f "$TMP/reproduced.tar" "$TMP/reproduced.tar.gz"
git -C "$TMP/source" archive   --format=tar   --prefix="RightsFrames-Termux-$TAG/"   "$TAG_TARGET" > "$TMP/reproduced.tar"
gzip -n "$TMP/reproduced.tar"

cmp "$TMP/reproduced.tar.gz" "$ART"

ATTEST_DIR="$TMP/attestation"
mkdir -p "$ATTEST_DIR"
(
  cd "$ATTEST_DIR"
  ( cd "$ATTEST_DIR" && gh attestation download \
    "$ART" \
    --repo "$REPO" \
    --predicate-type 'https://slsa.dev/provenance/v1' \
    --limit 30
  )
)
ATTEST_BUNDLE="$(find "$ATTEST_DIR" -maxdepth 1 -type f -name 'sha256:*' -print -quit)"
test -s "$ATTEST_BUNDLE"

TRUSTED_ROOT="$ATTEST_DIR/trusted_root.jsonl"
gh attestation trusted-root > "$TRUSTED_ROOT"
test -s "$TRUSTED_ROOT"

gh attestation verify \
  "$ART" \
  --repo "$REPO" \
  --bundle "$ATTEST_BUNDLE" \
  --custom-trusted-root "$TRUSTED_ROOT" \
  --predicate-type 'https://slsa.dev/provenance/v1' \
  --signer-workflow "$REPO/.github/workflows/provenance-gate.yml" \
  --source-ref "refs/tags/$TAG" \
  --deny-self-hosted-runners

SBOM_NAME="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("sbom", ""))' "$MANIFEST")"
if [ -z "$SBOM_NAME" ]; then
  python3 - "$TAG" <<'PY'
import re
import sys

match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', sys.argv[1])
assert match and tuple(map(int, match.groups())) < (0, 3, 0), 'releases from v0.3.0 on must publish an SBOM'
PY
  SBOM_RESULT='NOT_PUBLISHED_BEFORE_V0_3_0'
else
  test "$SBOM_NAME" = "RightsFrames-Termux-$TAG.cdx.json"
  gh release download "$TAG" --repo "$REPO" --pattern "$SBOM_NAME" --dir "$TMP/release"
  SBOM="$TMP/release/$SBOM_NAME"
  test -s "$SBOM"
  python3 - "$MANIFEST" "$SBOM" <<'PY'
import hashlib
import json
import sys

manifest = json.load(open(sys.argv[1], encoding='utf-8'))
assert manifest['sbomSha256'] == hashlib.sha256(open(sys.argv[2], 'rb').read()).hexdigest()
assert manifest['sbomPredicateType'] == 'https://cyclonedx.org/bom'
PY
  # The SBOM checker is taken from the release's own source tree.
  python3 "$TMP/source/tools/rf_release_sbom.py" verify \
    --sbom "$SBOM" \
    --requirements "$TMP/source/core/requirements.txt" \
    --version "${TAG#v}"
  gh attestation verify \
    "$ART" \
    --repo "$REPO" \
    --predicate-type https://cyclonedx.org/bom \
    --signer-workflow "$REPO/.github/workflows/provenance-gate.yml" \
    --source-ref "refs/tags/$TAG" \
    --deny-self-hosted-runners \
    --format json > "$TMP/sbom-attestation.json"
  python3 - "$TMP/sbom-attestation.json" "$SBOM" <<'PY'
import json
import sys

results = json.load(open(sys.argv[1], encoding='utf-8'))
published = json.load(open(sys.argv[2], encoding='utf-8'))
predicates = [
    item['verificationResult']['statement']['predicate']
    for item in results
    if item['verificationResult']['statement']['predicateType'] == 'https://cyclonedx.org/bom'
]
assert predicates, 'no verified SBOM attestation'
assert any(p == published for p in predicates), 'published SBOM differs from the attested SBOM'
PY
  SBOM_RESULT='VERIFIED'
fi

echo 'RELEASE_ATTESTATION=VERIFIED'
echo 'SOURCE_COMMIT=VERIFIED'
echo 'SOURCE_TREE=VERIFIED'
echo 'ARTIFACT_DIGEST=VERIFIED'
echo 'REPRODUCIBLE_FROM_PUBLIC_SOURCE=VERIFIED'
echo 'SLSA_BUILD_LEVEL=3'
echo "SBOM=$SBOM_RESULT"
echo 'INDEPENDENT_EXTERNAL_VERIFICATION=PASSED'
