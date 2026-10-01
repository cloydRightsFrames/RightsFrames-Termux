#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

VERIFY=${1:?verifier required}
OWNER=${2:?owner required}
REPO=${3:?repo required}
TAG=${4:?tag required}
ARTIFACT=${5:?artifact required}

test -x "$VERIFY"
test -f "$ARTIFACT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ARTIFACT" "$TMP/original"
cp "$ARTIFACT" "$TMP/tampered"

python3 - "$TMP/tampered" <<'PY'
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
b = bytearray(p.read_bytes())

if not b:
    raise SystemExit('empty artifact')

i = len(b) // 2
b[i] ^= 1
p.write_bytes(bytes(b))
PY

ORIGINAL="$(sha256sum "$TMP/original" | awk '{print $1}')"
TAMPERED="$(sha256sum "$TMP/tampered" | awk '{print $1}')"

test "$ORIGINAL" != "$TAMPERED"

printf 'ORIGINAL_SHA256=%s\n' "$ORIGINAL"
printf 'TAMPERED_SHA256=%s\n' "$TAMPERED"

if "$VERIFY" "$OWNER" "$REPO" "$TAG" "$TMP/tampered" >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: tampered artifact accepted'
    exit 1
fi

printf '%s\n' 'TAMPERED_ARTIFACT=REJECTED'
printf '%s\n' 'ADVERSARIAL_TAMPER_TEST=PASSED'
