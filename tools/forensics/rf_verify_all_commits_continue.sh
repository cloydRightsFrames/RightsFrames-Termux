#!/data/data/com.termux/files/usr/bin/bash
set -u
REPO_ROOT="$(git rev-parse --show-toplevel)"
HEAD_SHA="$(git rev-parse HEAD)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${HEAD_SHA}"
REPORT_DIR="${REPO_ROOT}/artifacts/all-commits-verification-${RUN_ID}"
VERIFY_ROOT="${HOME}/.cache/rightsframes-all-commits-${RUN_ID}"
mkdir -p "$REPORT_DIR" "$VERIFY_ROOT"
COMMITS_FILE="$REPORT_DIR/commits.txt"
RESULTS_FILE="$REPORT_DIR/results.tsv"
FAILURES_FILE="$REPORT_DIR/failures.tsv"
git rev-list --all --topo-order --reverse > "$COMMITS_FILE"
TOTAL="$(wc -l < "$COMMITS_FILE" | tr -d " ")"
INDEX=0
PASS_COUNT=0
FAIL_COUNT=0
printf "%s\n" "INDEX SHASUBJECTSTATUSTESTSCOVERAGESECURITY" > "$RESULTS_FILE"
printf "%s\n" "INDEX SHASUBJECTFAILURE" > "$FAILURES_FILE"
printf "Repository: %s\nHEAD: %s\nReachable commits: %s\nReport: %s\n\n" "$REPO_ROOT" "$HEAD_SHA" "$TOTAL" "$REPORT_DIR"
while IFS= read -r SHA; do
 INDEX=$((INDEX+1))
 SUBJECT="$(git log -1 --format=%s "$SHA")"
 COMMIT_DIR="$VERIFY_ROOT/$(printf "%03d" "$INDEX")-$SHA"
 rm -rf "$COMMIT_DIR"
 mkdir -p "$COMMIT_DIR"
 STATUS=PASS
 TESTS=NOT_RUN
 COVERAGE=NOT_RUN
 SECURITY=NOT_RUN
 FAILURE=
 printf "\n[%s/%s] %s %s\n" "$INDEX" "$TOTAL" "${SHA:0:7}" "$SUBJECT"
 if ! git cat-file -e "${SHA}^{commit}" 2>/dev/null; then STATUS=FAIL; FAILURE=COMMIT_OBJECT_UNAVAILABLE; fi
 if [ "$STATUS" = PASS ] && ! git archive "$SHA" | tar -xf - -C "$COMMIT_DIR"; then STATUS=FAIL; FAILURE=ARCHIVE_FAILED; fi
 if [ "$STATUS" = PASS ] && ! find "$COMMIT_DIR" -type f -name "*.py" -print0 | xargs -0 -r -n1 python -m py_compile >/dev/null 2>&1; then STATUS=FAIL; FAILURE=PYTHON_COMPILE_FAILED; fi
 if [ "$STATUS" = PASS ]; then
   if [ ! -d "$COMMIT_DIR/tests" ]; then
     TESTS=NO_TEST_DIRECTORY
     COVERAGE=NOT_APPLICABLE
   elif (cd "$COMMIT_DIR" && python -m pytest -q > pytest.log 2>&1); then
     TESTS=PASS
     if (cd "$COMMIT_DIR" && python -m pytest -q --cov=core --cov=enterprise --cov=provenance --cov=verifier --cov-branch --cov-report=json:coverage.json > coverage.log 2>&1); then
       if python - "$COMMIT_DIR/coverage.json" <<PY
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))["totals"]
raise SystemExit(not (
 d["missing_lines"] == 0 and
 d["num_partial_branches"] == 0 and
 d["missing_branches"] == 0 and
 d["covered_lines"] == d["num_statements"] and
 d["covered_branches"] == d["num_branches"] and
 float(d["percent_covered"]) == 100.0
))
PY
       then COVERAGE=100%
       else COVERAGE=FAIL; STATUS=FAIL; FAILURE=COVERAGE_NOT_100_PERCENT; fi
     else COVERAGE=FAIL; STATUS=FAIL; FAILURE=COVERAGE_COMMAND_FAILED; fi
   else
     TESTS=FAIL
     STATUS=FAIL
     FAILURE=PYTEST_FAILED
   fi
 fi
 if [ "$STATUS" = PASS ]; then
   if (cd "$COMMIT_DIR" && ! grep -RInE --exclude-dir=.git --exclude="*.lock" --exclude="*.sum" --exclude="*.json" --exclude="*.html" --exclude="*.xml" --exclude="*.log" "-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}" . >/dev/null 2>&1); then
     SECURITY=PASS
   else
     SECURITY=FAIL
     STATUS=FAIL
     FAILURE=SECRET_PATTERN_DETECTED
   fi
 fi
 if [ "$STATUS" = PASS ]; then PASS_COUNT=$((PASS_COUNT+1)); else FAIL_COUNT=$((FAIL_COUNT+1)); printf "%s\t%s\t%s\t%s\n" "$INDEX" "$SHA" "$SUBJECT" "$FAILURE" >> "$FAILURES_FILE"; fi
 printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$INDEX" "$SHA" "$SUBJECT" "$STATUS" "$TESTS" "$COVERAGE" "$SECURITY" >> "$RESULTS_FILE"
 printf "STATUS=%s TESTS=%s COVERAGE=%s SECURITY=%s\n" "$STATUS" "$TESTS" "$COVERAGE" "$SECURITY"
 [ "$STATUS" = FAIL ] && printf "FAILURE=%s\nCONTINUING TO NEXT COMMIT...\n" "$FAILURE"
done < "$COMMITS_FILE"
printf "\n=== FINAL SUMMARY ===\nTOTAL=%s\nPASSED=%s\nFAILED=%s\nRESULTS=%s\nFAILURES=%s\n" "$TOTAL" "$PASS_COUNT" "$FAIL_COUNT" "$RESULTS_FILE" "$FAILURES_FILE"
if [ "$FAIL_COUNT" -eq 0 ]; then
 printf "RIGHTSFRAMES_ALL_REACHABLE_COMMITS_VERIFIED=TRUE\n"
 exit 0
fi
cat "$FAILURES_FILE"
printf "RIGHTSFRAMES_ALL_REACHABLE_COMMITS_VERIFIED=FALSE\nFAILURE_COUNT=%s\n" "$FAIL_COUNT"
exit 1
