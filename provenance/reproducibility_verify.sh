#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

A=${1:?artifact A required}
B=${2:?artifact B required}

test -f "$A"
test -f "$B"

HA="$(sha256sum "$A" | awk '{print $1}')"
HB="$(sha256sum "$B" | awk '{print $1}')"

printf 'A=%s\n' "$HA"
printf 'B=%s\n' "$HB"

test "$HA" = "$HB"

printf '%s\n' 'REPRODUCIBILITY=VERIFIED'
