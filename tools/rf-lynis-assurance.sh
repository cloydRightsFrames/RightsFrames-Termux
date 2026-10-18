#!/data/data/com.termux/files/usr/bin/bash
set -u
set -o pipefail

ROOT="$HOME/RightsFrames-Termux"
LYNIS_DIR="$ROOT/tools/lynis-download/lynis-master"
ARTIFACT_ROOT="$ROOT/artifacts/lynis"
RUNTIME_TMP="$ROOT/artifacts/lynis-runtime/tmp"

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

command -v proot >/dev/null 2>&1 || die "proot not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
command -v date >/dev/null 2>&1 || die "date not found"

[ -d "$LYNIS_DIR" ] || die "Lynis source directory missing: $LYNIS_DIR"
[ -x "$LYNIS_DIR/lynis" ] || die "Lynis executable missing: $LYNIS_DIR/lynis"

mkdir -p "$ARTIFACT_ROOT" "$RUNTIME_TMP"

TMP_PROBE="$RUNTIME_TMP/.rf-lynis-tmp-probe"
printf '%s\n' 'rightsframes-lynis-probe' > "$TMP_PROBE"

PROOT_TMP_TEST="$(
    proot -b "$RUNTIME_TMP:/tmp" \
        sh -c 'printf "ok\n" > /tmp/.rf-lynis-runtime-test && cat /tmp/.rf-lynis-runtime-test && rm -f /tmp/.rf-lynis-runtime-test' \
        2>&1
)"
PROOT_TMP_STATUS=$?

rm -f "$TMP_PROBE"

[ "$PROOT_TMP_STATUS" -eq 0 ] || {
    printf '%s\n' "$PROOT_TMP_TEST" >&2
    die "PROOT writable /tmp test failed"
}

STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
OUT="$ARTIFACT_ROOT/$STAMP"
mkdir -p "$OUT"

CONSOLE="$OUT/lynis-console.txt"
REPORT="$OUT/lynis-report.dat"
LOG="$OUT/lynis.log"
METADATA="$OUT/metadata.json"
RESULT="$OUT/assurance-result.json"
MANIFEST="$OUT/evidence-manifest.sha256"

LYNIS_SHA="$(sha256sum "$LYNIS_DIR/lynis" | awk '{print $1}')"

ARCHIVE="$ROOT/tools/lynis-download/lynis-master.tar.gz"
ARCHIVE_SHA=""

if [ -f "$ARCHIVE" ]; then
    ARCHIVE_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
fi

START_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

printf '%s\n' '=== RIGHTSFRAMES LYNIS ASSURANCE RUN ===' | tee "$CONSOLE"
printf 'run_id=%s\n' "$STAMP" | tee -a "$CONSOLE"
printf 'start_utc=%s\n' "$START_UTC" | tee -a "$CONSOLE"
printf 'lynis_sha256=%s\n' "$LYNIS_SHA" | tee -a "$CONSOLE"
printf 'archive_sha256=%s\n' "${ARCHIVE_SHA:-NOT_PRESENT}" | tee -a "$CONSOLE"
printf 'execution=proot-bind-writable-tmp\n' | tee -a "$CONSOLE"
printf 'tmp_bind=%s:/tmp\n' "$RUNTIME_TMP" | tee -a "$CONSOLE"

cd "$LYNIS_DIR" || die "cannot enter Lynis directory"

printf '%s\n' '=== LYNIS AUDIT ===' | tee -a "$CONSOLE"

AUDIT_START="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

set +e
proot -b "$RUNTIME_TMP:/tmp" \
    ./lynis audit system --quick --no-colors \
    >>"$CONSOLE" 2>&1
AUDIT_STATUS=$?
set -e

AUDIT_END="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ -f "$HOME/lynis-report.dat" ]; then
    cp "$HOME/lynis-report.dat" "$REPORT"
fi

if [ -f "$HOME/lynis.log" ]; then
    cp "$HOME/lynis.log" "$LOG"
fi

REPORT_PRESENT=false
LOG_PRESENT=false

[ -s "$REPORT" ] && REPORT_PRESENT=true
[ -s "$LOG" ] && LOG_PRESENT=true

LYNIS_VERSION="$(
    sed -n 's/^lynis_version=//p' "$REPORT" 2>/dev/null |
    head -1
)"

[ -n "$LYNIS_VERSION" ] || LYNIS_VERSION="unknown"

HARDENING_INDEX="$(
    grep -E '^[[:space:]]*Hardening index' "$CONSOLE" |
    sed -E 's/.*:[[:space:]]*([0-9]+).*/\1/' |
    tail -1
)"

TESTS_PERFORMED="$(
    grep -E '^[[:space:]]*Tests performed' "$CONSOLE" |
    sed -E 's/.*:[[:space:]]*([0-9]+).*/\1/' |
    tail -1
)"

[ -n "$HARDENING_INDEX" ] || HARDENING_INDEX="null"
[ -n "$TESTS_PERFORMED" ] || TESTS_PERFORMED="null"

if grep -q 'Interrupt detected\.' "$CONSOLE"; then
    RUN_STATUS="INCOMPLETE"
elif [ "$AUDIT_STATUS" -eq 0 ]; then
    RUN_STATUS="COMPLETE"
else
    RUN_STATUS="FAILED"
fi

PROC_NET_DEV_LIMITED=false
PROC_NET_ROUTE_LIMITED=false
NETLINK_LIMITED=false

grep -q '/proc/net/dev.*Permission denied' "$CONSOLE" && PROC_NET_DEV_LIMITED=true
grep -q '/proc/net/route.*Permission denied' "$CONSOLE" && PROC_NET_ROUTE_LIMITED=true
grep -q 'Cannot open netlink socket: Permission denied' "$CONSOLE" && NETLINK_LIMITED=true

NONPRIVILEGED=true

if [ "$(id -u)" = "0" ]; then
    NONPRIVILEGED=false
fi

cat > "$METADATA" <<JSON
{
  "schema": "rightsframes.lynis.assurance.metadata.v3",
  "run_id": "$STAMP",
  "started_utc": "$START_UTC",
  "audit_started_utc": "$AUDIT_START",
  "completed_utc": "$AUDIT_END",
  "tool": "Lynis",
  "lynis_version": "$LYNIS_VERSION",
  "lynis_executable_sha256": "$LYNIS_SHA",
  "source_archive_sha256": "$ARCHIVE_SHA",
  "source_directory": "$LYNIS_DIR",
  "execution": {
    "engine": "proot",
    "tmp_bind": "$RUNTIME_TMP:/tmp",
    "audit_arguments": "audit system --quick --no-colors",
    "privileged": false,
    "uid": "$(id -u)"
  },
  "environment": {
    "termux": true,
    "android": true,
    "non_privileged_execution": $NONPRIVILEGED
  },
  "limitations": {
    "proc_net_dev_permission_restricted": $PROC_NET_DEV_LIMITED,
    "proc_net_route_permission_restricted": $PROC_NET_ROUTE_LIMITED,
    "netlink_permission_restricted": $NETLINK_LIMITED,
    "linux_checks_are_not_an_android_security_baseline": true,
    "android_controls_require_separate_applicability_mapping": true
  },
  "audit": {
    "status": "$RUN_STATUS",
    "exit_status": $AUDIT_STATUS,
    "hardening_index": $HARDENING_INDEX,
    "tests_performed": $TESTS_PERFORMED
  }
}
JSON

cat > "$RESULT" <<JSON
{
  "schema": "rightsframes.lynis.assurance.result.v3",
  "run_id": "$STAMP",
  "status": "$RUN_STATUS",
  "tool": "Lynis",
  "version": "$LYNIS_VERSION",
  "audit_exit_status": $AUDIT_STATUS,
  "raw_lynis": {
    "hardening_index": $HARDENING_INDEX,
    "tests_performed": $TESTS_PERFORMED
  },
  "evidence": {
    "console": "$CONSOLE",
    "report": "$REPORT",
    "log": "$LOG"
  },
  "evidence_presence": {
    "console": true,
    "report": $REPORT_PRESENT,
    "log": $LOG_PRESENT
  },
  "interpretation": {
    "hardening_index_is_raw_lynis_output": true,
    "hardening_index_is_not_a_security_percentage": true,
    "linux_server_recommendations_are_not_automatically_android_failures": true,
    "android_termux_applicability_requires_separate_control_mapping": true,
    "no_findings_were_silently_reclassified": true,
    "no_lynis_score_manipulation": true,
    "incomplete_runs_are_not_assurance_passes": true
  }
}
JSON

(
    cd "$OUT" || exit 1
    sha256sum \
        metadata.json \
        lynis-console.txt \
        lynis-report.dat \
        lynis.log \
        assurance-result.json \
        2>/dev/null
) > "$MANIFEST"

printf '%s\n' '=== ASSURANCE RUN COMPLETE ==='
printf 'run_id=%s\n' "$STAMP"
printf 'status=%s\n' "$RUN_STATUS"
printf 'directory=%s\n' "$OUT"
printf 'audit_exit_status=%s\n' "$AUDIT_STATUS"
printf 'lynis_version=%s\n' "$LYNIS_VERSION"
printf 'hardening_index=%s\n' "$HARDENING_INDEX"
printf 'tests_performed=%s\n' "$TESTS_PERFORMED"
printf 'console=%s\n' "$CONSOLE"
printf 'report=%s\n' "$REPORT"
printf 'log=%s\n' "$LOG"
printf 'manifest=%s\n' "$MANIFEST"

if [ "$RUN_STATUS" = "COMPLETE" ]; then
    exit 0
fi

exit 1
