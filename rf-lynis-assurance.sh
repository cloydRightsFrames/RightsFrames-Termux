#!/data/data/com.termux/files/usr/bin/bash
set -u

ROOT="${HOME}/RightsFrames-Termux"
OUT="${ROOT}/artifacts/lynis"
STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
RUN="${OUT}/${STAMP}"
HOST="$(hostname 2>/dev/null || printf 'unknown')"

mkdir -p "$RUN"

umask 077

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

fail() {
    log "FAIL: $*"
    exit 1
}

command -v lynis >/dev/null 2>&1 ||
    fail "Lynis is not installed or is not in PATH."

command -v sha256sum >/dev/null 2>&1 ||
    fail "sha256sum is required."

VERSION="$(
    lynis show version 2>&1 |
    sed -n 's/^[[:space:]]*Version[[:space:]]*:[[:space:]]*//p' |
    head -n 1
)"

[ -n "$VERSION" ] || VERSION="$(
    lynis --version 2>&1 |
    head -n 1
)"

{
    printf '{\n'
    printf '  "framework": "RightsFrames Lynis Assurance",\n'
    printf '  "schema": "1.0",\n'
    printf '  "timestamp_utc": "%s",\n' "$STAMP"
    printf '  "hostname": "%s",\n' "$HOST"
    printf '  "uid": "%s",\n' "$(id -u)"
    printf '  "user": "%s",\n' "$(id -un 2>/dev/null || printf unknown)"
    printf '  "platform": "%s",\n' "$(uname -s 2>/dev/null || printf unknown)"
    printf '  "kernel": "%s",\n' "$(uname -r 2>/dev/null || printf unknown)"
    printf '  "architecture": "%s",\n' "$(uname -m 2>/dev/null || printf unknown)"
    printf '  "lynis_version": "%s",\n' "$(
        printf '%s' "$VERSION" |
        sed 's/\\/\\\\/g; s/"/\\"/g'
    )"
    printf '  "root_required": false\n'
    printf '}\n'
} > "$RUN/metadata.json"

log "RightsFrames Lynis Assurance"
log "Output: $RUN"
log "Lynis: $VERSION"

log "Collecting Lynis version/configuration information..."

lynis show version \
    --no-colors \
    > "$RUN/lynis-version.txt" 2>&1 || true

lynis show settings \
    --no-colors \
    > "$RUN/lynis-settings.txt" 2>&1 || true

log "Running Lynis system audit..."

AUDIT_RC=0

lynis audit system \
    --quick \
    --no-colors \
    --log-file "$RUN/lynis.log" \
    --report-file "$RUN/lynis-report.dat" \
    > "$RUN/lynis-console.txt" 2>&1 || AUDIT_RC=$?

printf '%s\n' "$AUDIT_RC" > "$RUN/lynis-exit-code.txt"

log "Parsing audit results..."

{
    printf '{\n'
    printf '  "audit_exit_code": %s,\n' "$AUDIT_RC"

    TESTED="$(grep -E 'Tests performed|Tests performed:' "$RUN/lynis-console.txt" |
        tail -n 1 |
        sed -E 's/.*Tests performed[^0-9]*([0-9]+).*/\1/' || true)"

    HARDENING="$(grep -E 'Hardening index' "$RUN/lynis-console.txt" |
        tail -n 1 |
        sed -E 's/.*Hardening index[^0-9]*([0-9]+).*/\1/' || true)"

    WARNINGS="$(grep -E 'Warnings' "$RUN/lynis-console.txt" |
        tail -n 1 |
        sed -E 's/.*Warnings[^0-9]*([0-9]+).*/\1/' || true)"

    SUGGESTIONS="$(grep -E 'Suggestions' "$RUN/lynis-console.txt" |
        tail -n 1 |
        sed -E 's/.*Suggestions[^0-9]*([0-9]+).*/\1/' || true)"

    printf '  "tests_performed": %s,\n' "${TESTED:-null}"
    printf '  "hardening_index": %s,\n' "${HARDENING:-null}"
    printf '  "warnings": %s,\n' "${WARNINGS:-null}"
    printf '  "suggestions": %s\n' "${SUGGESTIONS:-null}"
    printf '}\n'
} > "$RUN/assessment.json"

log "Extracting findings..."

grep -E '^[[:space:]]*-[[:space:]]*(Warning|Suggestion):|^[[:space:]]*Warning:|^[[:space:]]*Suggestion:' \
    "$RUN/lynis-console.txt" \
    > "$RUN/findings.txt" 2>/dev/null || true

grep -E '^[[:space:]]*(Hardening index|Tests performed|Warnings|Suggestions|Suggestions for improvement)' \
    "$RUN/lynis-console.txt" \
    > "$RUN/summary.txt" 2>/dev/null || true

log "Creating deterministic evidence manifest..."

(
    cd "$RUN" || exit 1

    find . -type f \
        ! -name 'SHA256SUMS' \
        -print0 |
        sort -z |
        xargs -0 sha256sum
) > "$RUN/SHA256SUMS"

chmod 600 "$RUN"/* 2>/dev/null || true

log "Verifying evidence manifest..."

(
    cd "$RUN" &&
    sha256sum -c SHA256SUMS
) > "$RUN/integrity-verification.txt" 2>&1

INTEGRITY_RC=$?
printf '%s\n' "$INTEGRITY_RC" > "$RUN/integrity-exit-code.txt"

if [ "$INTEGRITY_RC" -ne 0 ]; then
    log "FAIL: evidence integrity verification failed."
    exit 2
fi

log "Building assurance result..."

if [ "$AUDIT_RC" -eq 0 ]; then
    STATUS="AUDIT_COMPLETED"
else
    STATUS="AUDIT_COMPLETED_WITH_EXIT_CODE_${AUDIT_RC}"
fi

{
    printf '{\n'
    printf '  "framework": "RightsFrames Lynis Assurance",\n'
    printf '  "schema": "1.0",\n'
    printf '  "status": "%s",\n' "$STATUS"
    printf '  "timestamp_utc": "%s",\n' "$STAMP"
    printf '  "lynis_version": "%s",\n' \
        "$(printf '%s' "$VERSION" | sed 's/"/\\"/g')"
    printf '  "audit_exit_code": %s,\n' "$AUDIT_RC"
    printf '  "integrity_exit_code": %s,\n' "$INTEGRITY_RC"
    printf '  "evidence_directory": "%s",\n' "$RUN"
    printf '  "integrity_manifest": "%s/SHA256SUMS",\n' "$RUN"
    printf '  "root_required": false,\n'
    printf '  "scope": "Lynis system security audit only"\n'
    printf '}\n'
} > "$RUN/assurance-result.json"

sha256sum "$RUN/assurance-result.json" > "$RUN/assurance-result.sha256"

chmod 600 "$RUN/assurance-result.json" "$RUN/assurance-result.sha256"

printf '\n'
printf '%s\n' '=============================================='
printf '%s\n' ' RIGHTSFRAMES LYNIS ASSURANCE'
printf '%s\n' '=============================================='
printf 'Status:       %s\n' "$STATUS"
printf 'Lynis:        %s\n' "$VERSION"
printf 'Audit RC:     %s\n' "$AUDIT_RC"
printf 'Integrity RC: %s\n' "$INTEGRITY_RC"
printf 'Evidence:     %s\n' "$RUN"
printf '%s\n' '=============================================='
printf '\n'

exit "$AUDIT_RC"
