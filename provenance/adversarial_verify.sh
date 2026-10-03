#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

VERIFY=${1:?verifier required}
OWNER=${2:?owner required}
REPO=${3:?repo required}
TAG=${4:?tag required}
ARTIFACT=${5:?artifact required}

fail() {
    printf '%s\n' 'ADVERSARIAL_TAMPER_TEST=FAIL'
    printf 'FAILURE_CODE=%s\n' "$1"
    exit 1
}

test -x "$VERIFY" || fail 'VERIFIER_NOT_EXECUTABLE'
test -f "$ARTIFACT" || fail 'ARTIFACT_MISSING'
test -s "$ARTIFACT" || fail 'ARTIFACT_EMPTY'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ARTIFACT_NAME="$(basename -- "$ARTIFACT")"
ORIGINAL_DIR="$TMP/original"
TAMPERED_DIR="$TMP/tampered"
mkdir -p -- "$ORIGINAL_DIR" "$TAMPERED_DIR"

ORIGINAL="$ORIGINAL_DIR/$ARTIFACT_NAME"
TAMPERED="$TAMPERED_DIR/$ARTIFACT_NAME"

cp -- "$ARTIFACT" "$ORIGINAL"
cp -- "$ARTIFACT" "$TAMPERED"

ORIGINAL_SHA256="$(sha256sum "$ORIGINAL" | awk '{print $1}')"
TAMPERED_SHA256_BEFORE="$(sha256sum "$TAMPERED" | awk '{print $1}')"

python3 - "$TAMPERED" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
b = bytearray(p.read_bytes())

if not b:
    raise SystemExit('empty artifact')

index = len(b) // 2
b[index] ^= 0x01

if bytes(b) == p.read_bytes():
    raise SystemExit('mutation failed')

p.write_bytes(bytes(b))
PY

TAMPERED_SHA256="$(sha256sum "$TAMPERED" | awk '{print $1}')"

test "$ORIGINAL_SHA256" != "$TAMPERED_SHA256_BEFORE" && \
    fail 'UNEXPECTED_ORIGINAL_MUTATION'

test "$ORIGINAL_SHA256" != "$TAMPERED_SHA256" || \
    fail 'TAMPER_MUTATION_FAILED'

printf 'ORIGINAL_SHA256=%s\n' "$ORIGINAL_SHA256"
printf 'TAMPERED_SHA256=%s\n' "$TAMPERED_SHA256"

if ! "$VERIFY" "$OWNER" "$REPO" "$TAG" "$ORIGINAL" >"$TMP/original.out" 2>"$TMP/original.err"; then
    cat "$TMP/original.out"
    cat "$TMP/original.err" >&2
    fail 'ORIGINAL_ARTIFACT_REJECTED'
fi

grep -q '^RELEASE_ARTIFACT_VERIFICATION=PASS$' "$TMP/original.out" || \
    fail 'ORIGINAL_VERIFIER_SUCCESS_MARKER_MISSING'

if "$VERIFY" "$OWNER" "$REPO" "$TAG" "$TAMPERED" >"$TMP/tampered.out" 2>"$TMP/tampered.err"; then
    cat "$TMP/tampered.out"
    cat "$TMP/tampered.err" >&2
    fail 'TAMPERED_ARTIFACT_ACCEPTED'
fi

grep -Eq '^FAILURE_CODE=ARTIFACT_(DIGEST|SIZE)_MISMATCH$' \
    "$TMP/tampered.out" || {
        cat "$TMP/tampered.out"
        cat "$TMP/tampered.err" >&2
        fail 'TAMPERED_ARTIFACT_REJECTED_FOR_UNEXPECTED_REASON'
    }

printf '%s\n' 'ORIGINAL_ARTIFACT=ACCEPTED'
printf '%s\n' 'TAMPERED_ARTIFACT=REJECTED'
printf '%s\n' 'ADVERSARIAL_TAMPER_TEST=PASSED'
