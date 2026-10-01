#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

OWNER='cloydRightsFrames'
REPO='RightsFrames-Termux'
BRANCH='provenance-gate-v1'
WORKFLOW='.github/workflows/provenance-gate.yml'
VERIFY='provenance/verify_release.sh'
ADV='provenance/adversarial_verify.sh'

die() {
    printf 'RIGHTSFRAMES_AUTOMATION=FAIL\nREASON=%s\n' "$1" >&2
    exit 1
}

command -v git >/dev/null || die 'git missing'
command -v python3 >/dev/null || die 'python3 missing'
command -v gh >/dev/null || die 'gh missing'

git switch "$BRANCH" >/dev/null 2>&1 || die 'provenance branch unavailable'

test -f "$WORKFLOW" || die 'workflow missing'
test -f "$VERIFY" || die 'release verifier missing'
test -f "$ADV" || die 'adversarial verifier missing'

python3 "$ROOT/provenance/rf_repair.py" "$ROOT/$WORKFLOW"

chmod +x "$VERIFY" "$ADV"

git --no-pager diff --check
bash -n "$VERIFY"
bash -n "$ADV"

python3 - "$WORKFLOW" "$VERIFY" "$ADV" <<'PY'
from pathlib import Path
import sys

w = Path(sys.argv[1]).read_text(encoding='utf-8')
v = Path(sys.argv[2]).read_text(encoding='utf-8')
a = Path(sys.argv[3]).read_text(encoding='utf-8')

required = (
    'name: RightsFrames Enterprise Provenance Gate',
    'uses: actions/checkout@v4',
    'uses: actions/attest@v4',
    'git archive',
    'gzip -n',
    'release-manifest.json',
    'subject-path:',
    'attestations: write',
    'id-token: write',
    'release-policy:',
)

for x in required:
    if x not in w:
        raise SystemExit('missing workflow invariant: ' + x)

for x in (
    'enance/verify_release.sh',
    'git status --short --branch',
):
    if x in w:
        raise SystemExit('workflow corruption remains: ' + x)

if 'TAMPERED_ARTIFACT=REJECTED' not in a:
    raise SystemExit('adversarial verifier invariant missing')

if 'gh attestation verify' not in v:
    raise SystemExit('attestation verifier invariant missing')

print('STATIC_AUDIT=PASS')
PY

git add "$WORKFLOW" "$VERIFY" "$ADV" provenance/rf_repair.py provenance/rf_automation.sh

if ! git diff --cached --quiet; then
    git diff --cached --check
    git commit -m 'Harden automated provenance verification'
fi

git push --force-with-lease origin "$BRANCH"

printf 'RIGHTSFRAMES_AUTOMATION=PASS\n'
printf 'BRANCH=%s\n' "$BRANCH"
printf 'HEAD=%s\n' "$(git rev-parse HEAD)"
printf 'REMOTE=%s\n' "$(git rev-parse "origin/$BRANCH")"
