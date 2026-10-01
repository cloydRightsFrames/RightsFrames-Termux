#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

OWNER='cloydRightsFrames'
REPO='RightsFrames-Termux'
BRANCH='provenance-gate-v1'
WORKFLOW='.github/workflows/provenance-gate.yml'

die() {
    printf 'RIGHTSFRAMES_AUTOMATION=FAIL\nREASON=%s\n' "$1" >&2
    exit 1
}

command -v git >/dev/null || die 'git missing'
command -v gh >/dev/null || die 'gh missing'
command -v python3 >/dev/null || die 'python3 missing'

git switch "$BRANCH" >/dev/null 2>&1 || die 'provenance branch unavailable'

cat > "$WORKFLOW" <<'YAML'
name: RightsFrames Enterprise Provenance Gate

on:
  pull_request:
  push:
    branches:
      - main
      - provenance-gate-v1
    tags:
      - 'v*'

permissions:
  contents: read
  id-token: write
  attestations: write

concurrency:
  group: rightsframes-provenance-${{ github.ref }}
  cancel-in-progress: true

jobs:
  source-integrity:
    name: Source integrity
    runs-on: ubuntu-latest
    steps:
      - name: Checkout immutable revision
        uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
          fetch-depth: 0
          persist-credentials: false

      - name: Verify repository identity
        shell: bash
        run: |
          set -euo pipefail
          test "$(git remote get-url origin)" = "https://github.com/cloydRightsFrames/RightsFrames-Termux"
          test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"

      - name: Parse Python without modifying checkout
        shell: bash
        run: |
          set -euo pipefail
          python3 - <<'PY'
          import ast
          from pathlib import Path

          for path in sorted(Path('core').glob('*.py')):
              ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
          PY

      - name: Required source files
        shell: bash
        run: |
          set -euo pipefail
          test -f core/rf_core.py
          test -f core/app.py

      - name: Verify clean checkout
        shell: bash
        run: |
          set -euo pipefail
          test -z "$(git status --porcelain=v1)"

      - name: Record source identity
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p dist/source-integrity
          printf '%s\n' "${GITHUB_SHA}" > dist/source-integrity/source.sha256
          git rev-parse HEAD^{tree} > dist/source-integrity/source.tree
          git show -s --format='%H%n%T%n%P%n%ct%n%s' HEAD > dist/source-integrity/source.commit

  test:
    name: Core verification
    runs-on: ubuntu-latest
    steps:
      - name: Checkout immutable revision
        uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
          fetch-depth: 0
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        shell: bash
        run: |
          set -euo pipefail
          python -m pip install --disable-pip-version-check -r core/requirements.txt

      - name: Smoke test
        shell: bash
        run: |
          set -euo pipefail
          test -f core/rf_core.py
          test -f core/app.py
          python -m py_compile core/*.py

  provenance:
    name: External provenance
    needs:
      - source-integrity
      - test
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - name: Checkout immutable tag target
        uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
          fetch-depth: 0
          persist-credentials: false

      - name: Verify tag resolves to checked revision
        shell: bash
        run: |
          set -euo pipefail
          TAG="${GITHUB_REF_NAME}"
          git fetch --force --tags origin
          TAG_TARGET="$(git rev-parse "refs/tags/${TAG}^{commit}")"
          test "$TAG_TARGET" = "${GITHUB_SHA}"

      - name: Build immutable source subject
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p dist

          git archive \
            --format=tar \
            --prefix="RightsFrames-Termux-${GITHUB_REF_NAME}/" \
            "${GITHUB_SHA}" \
            > "dist/RightsFrames-Termux-${GITHUB_REF_NAME}.tar"

          gzip -n \
            "dist/RightsFrames-Termux-${GITHUB_REF_NAME}.tar"

          sha256sum \
            "dist/RightsFrames-Termux-${GITHUB_REF_NAME}.tar.gz" \
            > dist/SHA256SUMS

          sha256sum \
            "dist/RightsFrames-Termux-${GITHUB_REF_NAME}.tar.gz" \
            | awk '{print $1}' \
            > dist/SUBJECT_SHA256

      - name: Generate SLSA provenance
        uses: actions/attest@v4
        with:
          subject-path: dist/RightsFrames-Termux-${{ github.ref_name }}.tar.gz
          show-summary: true

      - name: Preserve machine-verifiable manifest
        shell: bash
        run: |
          set -euo pipefail

          ARTIFACT="RightsFrames-Termux-${GITHUB_REF_NAME}.tar.gz"
          DIGEST="$(sha256sum "dist/${ARTIFACT}" | awk '{print $1}')"

          python3 - <<PY
          import json

          manifest = {
              "schema": "https://rightsframes.online/provenance/release-manifest/v1",
              "repository": "cloydRightsFrames/RightsFrames-Termux",
              "ref": "${GITHUB_REF}",
              "tag": "${GITHUB_REF_NAME}",
              "commit": "${GITHUB_SHA}",
              "artifact": "${ARTIFACT}",
              "sha256": "${DIGEST}",
              "predicateType": "https://slsa.dev/provenance/v1",
              "workflow": "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}",
              "workflowRef": "${GITHUB_WORKFLOW_REF}",
              "runner": "GitHub-hosted",
              "repositoryVisibility": "public"
          }

          with open("dist/release-manifest.json", "w", encoding="utf-8") as f:
              json.dump(manifest, f, indent=2, sort_keys=True)
              f.write("\n")
          PY

      - name: Verify final workspace
        shell: bash
        run: |
          set -euo pipefail
          test -s dist/SHA256SUMS
          test -s dist/SUBJECT_SHA256
          test -s dist/release-manifest.json
          python3 -m json.tool dist/release-manifest.json >/dev/null

  release-policy:
    name: Release policy gate
    needs:
      - source-integrity
      - test
      - provenance
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - name: Require all provenance prerequisites
        shell: bash
        run: |
          set -euo pipefail
          test "${{ needs.source-integrity.result }}" = success
          test "${{ needs.test.result }}" = success
          test "${{ needs.provenance.result }}" = success

      - name: Require immutable tag event
        shell: bash
        run: |
          set -euo pipefail
          test "${GITHUB_REF_TYPE}" = tag
          case "${GITHUB_REF_NAME}" in
            v*) ;;
            *) exit 1 ;;
          esac
YAML

python3 - "$WORKFLOW" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')

required = [
    'name: RightsFrames Enterprise Provenance Gate',
    'jobs:',
    '  source-integrity:',
    '  test:',
    '  provenance:',
    '  release-policy:',
    'uses: actions/checkout@v4',
    'uses: actions/attest@v4',
    'subject-path:',
    'attestations: write',
    'id-token: write',
    'release-policy:',
    'git archive',
    'gzip -n',
    'release-manifest.json',
]

for x in required:
    if x not in s:
        raise SystemExit('MISSING_INVARIANT=' + x)

lines = s.splitlines()
step_keys = {'name', 'uses', 'with', 'shell', 'run', 'if'}
inside_step = False
step_indent = None
seen = set()

for line in lines:
    if not line.strip():
        continue

    indent = len(line) - len(line.lstrip())
    stripped = line.strip()

    if stripped.startswith('- name:'):
        inside_step = True
        step_indent = indent
        seen = {'name'}
        continue

    if inside_step and indent == step_indent and ':' in stripped:
        key = stripped.split(':', 1)[0]
        if key in step_keys:
            if key in seen:
                raise SystemExit(
                    'DUPLICATE_STEP_KEY=%s:%s' % (key, stripped)
                )
            seen.add(key)

if s.count('      - name: Record source identity') != 1:
    raise SystemExit('RECORD_SOURCE_IDENTITY_COUNT_INVALID')

if '          test "$TAG_TARGET" = "${GITHUB_SHA}"' not in s:
    raise SystemExit('TAG_TARGET_INDENTATION_INVALID')

print('WORKFLOW_STRUCTURAL_AUDIT=PASS')
PY

bash -n provenance/rf_automation.sh
git --no-pager diff --check

git add "$WORKFLOW" provenance/rf_automation.sh

if ! git diff --cached --quiet; then
    git diff --cached --check
    git commit -m 'Repair provenance workflow execution graph'
fi

git push --force-with-lease origin "$BRANCH"

sleep 5

GH_PAGER=cat gh run list \
  --repo "$OWNER/$REPO" \
  --branch "$BRANCH" \
  --limit 5 \
  --json databaseId,status,conclusion,headSha,event,workflowName \
  --jq '.[] | [.databaseId,.status,.conclusion,.headSha,.event,.workflowName] | @tsv'

printf 'RIGHTSFRAMES_AUTOMATION=PASS\n'
printf 'HEAD=%s\n' "$(git rev-parse HEAD)"
printf 'REMOTE=%s\n' "$(git rev-parse "origin/$BRANCH")"
