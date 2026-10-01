#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

VERIFY="${1:?verifier required}"
ARTIFACT="${2:?artifact required}"

test -x "$VERIFY"
test -f "$ARTIFACT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ARTIFACT" "$TMP/original"
cp "$ARTIFACT" "$TMP/tampered"

python3 - "$TMP/tampered" <<'PY'
import pathlib
p=pathlib.Path(__import__('sys').argv[1])
b=bytearray(p.read_bytes())
if not b:
    raise SystemExit("empty artifact")
b[len(b)//2] ^= 1
p.write_bytes(bytes(b))
PY

ORIGINAL="$(sha256sum "$TMP/original" | awk '{print $1}')"
TAMPERED="$(sha256sum "$TMP/tampered" | awk '{print $1}')"

test "$ORIGINAL" != "$TAMPERED"

printf '%s\n' 'TAMPERED_ARTIFACT_DIGEST=REJECTED'

if "$VERIFY" "$TMP/tampered" >/dev/null 2>&1; then
    printf '%s\n' 'FAIL: tampered artifact accepted'
    exit 1
fi

printf '%s\n' 'ADVERSARIAL_TAMPER_TEST=PASSED'
