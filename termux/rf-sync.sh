#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
#  rf-sync.sh — safe git pull and sync of RightsFrames on the Termux node
# =============================================================================
#  Brings ~/RightsFrames-Termux up to date with GitHub main, then re-syncs what
#  depends on the code. Exit 4 keeps the updated checkout for a verification retry.
#
#    bash termux/rf-sync.sh                 # pull + sync
#    bash termux/rf-sync.sh --dry-run       # show incoming commits, change nothing
#    bash termux/rf-sync.sh status          # where the checkout stands vs GitHub
#    bash termux/rf-sync.sh --install       # make `rf-sync` a command (symlink)
#    bash termux/rf-sync.sh --restart rf-api --restart rf-worker   # also restart runit services
#
#  Safety properties:
#    * Fast-forward only. If GitHub main does not contain the local HEAD (local
#      commits, or history rewritten upstream) nothing is merged and the run stops.
#    * Origin pinned. The remote must be github.com/cloydRightsFrames/RightsFrames-Termux.
#    * Local edits preserved. Uncommitted changes to tracked files are stashed,
#      the update applied, and the edits re-applied. If they conflict with the
#      update, the checkout is rolled back to the exact pre-sync commit with the
#      edits restored, and the run reports it (exit 2). Nothing is ever discarded.
#    * Flaky links. Fetches retry with exponential backoff (2, 4, 8, 16 s).
#    * Power. Takes the Termux wake lock for the run and leaves it held; refuses
#      to start below RF_SYNC_MIN_BATTERY percent (default 10) while discharging,
#      unless --force. Termux has ONE wake lock and it is not counted: releasing
#      it here would also release the lock termux/rf-pinnacle.sh holds for the
#      stack, and Doze could then freeze the node. Set RF_SYNC_RELEASE_WAKE_LOCK=1
#      on a phone that does not run the stack to release it when the run ends.
#    * One at a time. A kernel lock covers this Git worktree, including stale PID-lock cleanup.
#
#  After a successful update it:
#    * reinstalls the hash-locked runtime dependencies if core/requirements.txt changed;
#    * byte-compiles core/, verifier/ and tools/ to catch a broken checkout early;
#    * if RF_DATA_DIR holds a ledger: checks the anchor log for a torn write and
#      verifies the hash chain and anchors (read-only; repairs are never automatic);
#    * restarts the runit services named with --restart only after all requested checks pass;
#    * points out when termux/rf-pinnacle.sh changed (re-run it to apply).
#
#  Exit codes: 0 synced or already current, 1 error, 2 local edits conflict with
#  the update (rolled back), 3 histories diverged (nothing changed),
#  4 post-sync verification failed (code updated, ledger needs attention).
#  Log: ~/.rightsframes/sync/rf-sync.log
# =============================================================================

set -Eeuo pipefail
umask 077

readonly RF_SYNC_VERSION="1.1.0"
readonly EXPECTED_REPO="cloydRightsFrames/RightsFrames-Termux"

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
RF_REPO_DIR="${RF_REPO_DIR:-$HOME/RightsFrames-Termux}"
RF_SYNC_BRANCH="${RF_SYNC_BRANCH:-main}"
RF_SYNC_HOME="${RF_SYNC_HOME:-$HOME/.rightsframes/sync}"
RF_SYNC_MIN_BATTERY="${RF_SYNC_MIN_BATTERY:-10}"
RF_SYNC_RETRIES="${RF_SYNC_RETRIES:-4}"
RF_SYNC_RELEASE_WAKE_LOCK="${RF_SYNC_RELEASE_WAKE_LOCK:-0}"
LOG_FILE="$RF_SYNC_HOME/rf-sync.log"
LOCK_DIR="$RF_SYNC_HOME/lock"
PYTHON="${PYTHON:-python3}"

DRY_RUN=0
FORCE=0
MODE="sync"
RESTARTS=()
STASH_SHA=""
PRE_HEAD=""
WAKE_LOCK_TAKEN=0
LOCK_OWNED=0
SYNC_GIT_DIR=""
DEPENDENCIES_PENDING=""

# ---------------------------------------------------------------- output ---
if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_DIM=$'\e[2m'; C_OFF=$'\e[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi

log()  { local line; line="$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || true; }
ok()   { printf '  %s●%s %-22s %s\n' "$C_OK" "$C_OFF" "$1" "${2:-}"; log "OK   $1 ${2:-}"; }
warn() { printf '  %s▲%s %-22s %s\n' "$C_WARN" "$C_OFF" "$1" "${2:-}"; log "WARN $1 ${2:-}"; }
info() { printf '  %s○ %-22s %s%s\n' "$C_DIM" "$1" "${2:-}" "$C_OFF"; log "INFO $1 ${2:-}"; }
fail() { printf '  %s✖%s %-22s %s\n' "$C_ERR" "$C_OFF" "$1" "${2:-}" >&2; log "FAIL $1 ${2:-}"; }
die()  { local code="${2:-1}"; fail "rf-sync" "$1"; exit "$code"; }

usage() {
  sed -n '/^#  Brings/,/^#  Log:/p' "${BASH_SOURCE[0]}" | sed 's/^#  \{0,1\}//'
}

# --------------------------------------------------------------- arguments ---
while (($#)); do
  case "$1" in
    sync) MODE="sync" ;;
    status) MODE="status" ;;
    --dry-run|-n) DRY_RUN=1 ;;
    --force) FORCE=1 ;;
    --install) MODE="install" ;;
    --restart)
      [[ $# -ge 2 && -n $2 ]] || die "--restart needs a runit service name"
      [[ $2 =~ ^[A-Za-z0-9._-]+$ && $2 != . && $2 != .. ]] || die "invalid service name: $2"
      RESTARTS+=("$2"); shift ;;
    --repo)
      [[ $# -ge 2 && -n $2 ]] || die "--repo needs a directory"
      RF_REPO_DIR="$2"; shift ;;
    --branch)
      [[ $# -ge 2 && $2 =~ ^[A-Za-z0-9._/-]+$ ]] || die "--branch needs a valid branch name"
      RF_SYNC_BRANCH="$2"; shift ;;
    --version) printf 'rf-sync %s\n' "$RF_SYNC_VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

[[ $RF_SYNC_RELEASE_WAKE_LOCK == 0 || $RF_SYNC_RELEASE_WAKE_LOCK == 1 ]] \
  || die "RF_SYNC_RELEASE_WAKE_LOCK must be 0 or 1"

mkdir -p "$RF_SYNC_HOME"

g() { git -C "$RF_REPO_DIR" "$@"; }

# ------------------------------------------------------------ lifecycle ---
# Only ever remove a lock this run created; a refused run must not free another's lock.
release_lock() {
  ((LOCK_OWNED)) || return 0
  rm -f -- "$LOCK_DIR/pid" && rmdir -- "$LOCK_DIR" || warn "Lock" "could not remove $LOCK_DIR"
  LOCK_OWNED=0
}

acquire_lock() {
  command -v flock >/dev/null || die "flock is required (pkg install util-linux)"
  exec {sync_lock_fd}<"$SYNC_GIT_DIR"
  flock -n "$sync_lock_fd" || die "another rf-sync is running for this worktree"
  if [[ ! $RF_SYNC_HOME -ef $SYNC_GIT_DIR ]]; then
    exec {sync_home_fd}<"$RF_SYNC_HOME"
    flock -n "$sync_home_fd" || die "another rf-sync is running in $RF_SYNC_HOME"
  fi
  # Keep the PID lock for older rf-sync processes that do not know about flock.
  local holder claim
  if [[ -e $LOCK_DIR ]]; then
    holder="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    [[ $holder =~ ^[1-9][0-9]*$ ]] || die "sync lock has no valid owner record: $LOCK_DIR"
    if kill -0 "$holder" 2>/dev/null; then
      die "another rf-sync is running (pid $holder)"
    fi
    warn "Lock" "reclaiming stale lock from pid $holder"
    rm -- "$LOCK_DIR/pid" && rmdir -- "$LOCK_DIR" || die "could not reclaim $LOCK_DIR"
  fi
  # Publish a complete owner record in one rename, even if Android kills the shell.
  claim="$(mktemp -d "$RF_SYNC_HOME/.claim.XXXXXXXX")"
  if ! printf '%s\n' "$$" >"$claim/pid" || ! mv -nT -- "$claim" "$LOCK_DIR" || [[ -d $claim ]]; then
    rm -f -- "$claim/pid"; rmdir -- "$claim"
    die "could not acquire $LOCK_DIR"
  fi
  LOCK_OWNED=1
}

# If anything fails while edits are stashed, put the checkout back exactly as it was.
restore_on_error() {
  local status=$?
  if [[ -n $STASH_SHA && -n $PRE_HEAD ]]; then
    g reset --quiet --hard "$PRE_HEAD" >/dev/null 2>&1 || true
    if g stash apply --index --quiet "$STASH_SHA" >/dev/null 2>&1; then
      drop_stash
      fail "Rollback" "checkout restored to $(short "$PRE_HEAD") with your local edits"
    else
      fail "Rollback" "edits kept in stash $STASH_SHA (git stash list); checkout at $(short "$PRE_HEAD")"
    fi
    STASH_SHA=""
  fi
  return "$status"
}

cleanup() {
  local status=$?
  log "END rc=$status"
  # Released only on request: the lock is shared with the running stack (see header).
  if ((WAKE_LOCK_TAKEN)) && [[ $RF_SYNC_RELEASE_WAKE_LOCK == 1 ]] \
      && command -v termux-wake-unlock >/dev/null 2>&1; then
    termux-wake-unlock >/dev/null 2>&1 || true
  fi
  release_lock
}

trap 'restore_on_error' ERR
trap 'cleanup' EXIT
trap 'restore_on_error; exit 130' INT TERM

short() { printf '%s' "${1:0:10}"; }

drop_stash() {
  local ref
  ref="$(g stash list --format='%gd %H' | awk -v sha="$STASH_SHA" '$2 == sha {print $1; exit}')"
  [[ -n $ref ]] && g stash drop --quiet "$ref" >/dev/null 2>&1 || true
}

# ----------------------------------------------------------- preflight ---
check_repo() {
  command -v git >/dev/null 2>&1 || die "git is not installed (pkg install git)"
  [[ -d $RF_REPO_DIR ]] || die "repository not found at $RF_REPO_DIR (set RF_REPO_DIR or use --repo)"
  g rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "$RF_REPO_DIR is not a git checkout"
  local url normalized
  # The configured URL, not `git remote get-url` (which expands insteadOf rewrites).
  url="$(g config --get remote.origin.url 2>/dev/null)" || die "checkout has no 'origin' remote"
  normalized="$(printf '%s' "$url" | tr '[:upper:]' '[:lower:]' | sed -E 's#^(https?://|ssh://)?(git@)?##; s#^github\.com[:/]#github.com/#; s#\.git$##; s#/+$##')"
  local expected
  expected="github.com/$(printf '%s' "$EXPECTED_REPO" | tr '[:upper:]' '[:lower:]')"
  [[ $normalized == "$expected" ]] || die "origin is $url, expected https://github.com/$EXPECTED_REPO"
  ok "Repository" "$RF_REPO_DIR"
  SYNC_GIT_DIR="$(g rev-parse --absolute-git-dir)"
  DEPENDENCIES_PENDING="$SYNC_GIT_DIR/rf-sync-requirements.pending"
  for marker in MERGE_HEAD rebase-merge rebase-apply CHERRY_PICK_HEAD REVERT_HEAD; do
    [[ -e $SYNC_GIT_DIR/$marker ]] && die "a git $marker operation is in progress in $RF_REPO_DIR; finish or abort it first"
  done
  local branch
  branch="$(g symbolic-ref --quiet --short HEAD 2>/dev/null)" || die "HEAD is detached; check out $RF_SYNC_BRANCH first"
  [[ $branch == "$RF_SYNC_BRANCH" ]] || die "on branch '$branch'; switch to $RF_SYNC_BRANCH first (git -C $RF_REPO_DIR switch $RF_SYNC_BRANCH)"
}

check_power() {
  command -v termux-battery-status >/dev/null 2>&1 || { info "Battery" "Termux:API not installed; not checked"; return 0; }
  local json pct plugged
  json="$(timeout 10 termux-battery-status 2>/dev/null || true)"
  pct="$(printf '%s' "$json" | sed -n 's/.*"percentage": *\([0-9]*\).*/\1/p' | head -n1)"
  plugged="$(printf '%s' "$json" | sed -n 's/.*"plugged": *"\([A-Z_]*\)".*/\1/p' | head -n1)"
  if [[ -z $pct ]]; then
    info "Battery" "status unavailable"
  elif [[ $plugged == "UNPLUGGED" ]] && ((pct < RF_SYNC_MIN_BATTERY)) && ((FORCE == 0)); then
    die "battery at ${pct}% and discharging (minimum $RF_SYNC_MIN_BATTERY%); charge the phone or use --force"
  else
    ok "Battery" "${pct}% ${plugged:-}"
  fi
  if command -v termux-wake-lock >/dev/null 2>&1; then
    if termux-wake-lock >/dev/null 2>&1; then
      WAKE_LOCK_TAKEN=1
      if [[ $RF_SYNC_RELEASE_WAKE_LOCK == 1 ]]; then
        ok "Wake lock" "held for this run"
      else
        ok "Wake lock" "held; left held for the stack"
      fi
    fi
  fi
}

fetch_remote() {
  local attempt=1 delay=2
  while :; do
    if g fetch --quiet --no-tags origin "+refs/heads/$RF_SYNC_BRANCH:refs/remotes/origin/$RF_SYNC_BRANCH" 2>>"$LOG_FILE"; then
      ok "Fetch" "origin/$RF_SYNC_BRANCH $(short "$(g rev-parse "origin/$RF_SYNC_BRANCH")")"
      return 0
    fi
    if ((attempt >= RF_SYNC_RETRIES)); then
      die "could not reach GitHub after $attempt attempts (see $LOG_FILE)"
    fi
    warn "Fetch" "attempt $attempt failed; retrying in ${delay}s"
    sleep "$delay"
    attempt=$((attempt + 1)); delay=$((delay * 2))
  done
}

# -------------------------------------------------------------- status ---
show_status() {
  local head remote ahead behind
  head="$(g rev-parse HEAD)"
  remote="$(g rev-parse "origin/$RF_SYNC_BRANCH")"
  behind="$(g rev-list --count "HEAD..origin/$RF_SYNC_BRANCH")"
  ahead="$(g rev-list --count "origin/$RF_SYNC_BRANCH..HEAD")"
  info "Local HEAD" "$(short "$head") $(g log -1 --format=%s HEAD | cut -c1-60)"
  info "GitHub" "$(short "$remote") $(g log -1 --format=%s "origin/$RF_SYNC_BRANCH" | cut -c1-60)"
  if ((behind == 0 && ahead == 0)); then ok "Status" "up to date"
  elif ((ahead == 0)); then warn "Status" "$behind commit(s) behind GitHub"
  else warn "Status" "$ahead local commit(s) not on GitHub, $behind behind"; fi
  local dirty
  dirty="$(g status --porcelain --untracked-files=no | wc -l | tr -d ' ')"
  if ((dirty == 0)); then
    ok "Working tree" "clean"
  else
    warn "Working tree" "$dirty locally modified file(s)"
  fi
}

# ---------------------------------------------------------- post-sync ---
post_sync() {
  local old="$1" new="$2" changed rc=0
  changed="$(g diff --name-only "$old" "$new")"

  if [[ -e $DEPENDENCIES_PENDING ]]; then
    info "Dependencies" "installing pending hash-locked runtime set"
    if (cd "$RF_REPO_DIR" && "$PYTHON" -m pip install --quiet --disable-pip-version-check \
          --require-hashes -r core/requirements.txt && "$PYTHON" -m pip check) >>"$LOG_FILE" 2>&1; then
      rm -- "$DEPENDENCIES_PENDING" || return 4
      ok "Dependencies" "installed and checked"
    else
      fail "Dependencies" "install or pip check failed (see $LOG_FILE); rf-sync will retry"
      rc=4
    fi
  else
    ok "Dependencies" "unchanged"
  fi

  if command -v "$PYTHON" >/dev/null 2>&1; then
    if (cd "$RF_REPO_DIR" && "$PYTHON" -m compileall -q core verifier tools >>"$LOG_FILE" 2>&1); then
      ok "Byte-compile" "core, verifier, tools"
    else
      fail "Byte-compile" "syntax errors after update (see $LOG_FILE)"
      rc=4
    fi
  else
    fail "Byte-compile" "$PYTHON not found"
    rc=4
  fi

  if [[ -z ${RF_DATA_DIR:-} ]]; then
    info "Ledger" "RF_DATA_DIR not set; not verified"
  elif [[ ! -f $RF_DATA_DIR/ledger.db ]]; then
    fail "Ledger" "configured RF_DATA_DIR has no ledger.db"
    rc=4
  else
    local data_dir
    data_dir="$(cd -- "$RF_DATA_DIR" && pwd -P)" || return 4
    local torn_rc=0
    (cd "$RF_REPO_DIR" && "$PYTHON" tools/rf_repair_anchor_log.py --data-dir "$data_dir" --check \
       >>"$LOG_FILE" 2>&1) || torn_rc=$?
    if ((torn_rc == 2)); then
      fail "Anchor log" "torn write detected; run: python tools/rf_repair_anchor_log.py --data-dir $RF_DATA_DIR"
      rc=4
    elif ((torn_rc != 0)); then
      fail "Anchor log" "check failed (see $LOG_FILE)"
      rc=4
    else
      ok "Anchor log" "intact"
      local report
      if report="$(cd "$RF_REPO_DIR" && RF_DATA_DIR="$data_dir" "$PYTHON" -c '
import json, sys
sys.path.insert(0, ".")
from core import rf_core
chain, anchors = rf_core.verify_existing_ledger()
print(json.dumps({"chain": chain, "anchors": anchors}))
sys.exit(0 if chain[0] and anchors[0] else 1)' 2>>"$LOG_FILE")"; then
        ok "Ledger" "$(printf '%s' "$report" | sed -E 's/.*"chain": \[true, "([^"]*)"\].*"anchors": \[true, "([^"]*)"\].*/\1; \2/')"
      else
        fail "Ledger" "verification failed: ${report:-see $LOG_FILE}"
        rc=4
      fi
    fi
  fi

  if grep -qx 'termux/rf-pinnacle.sh' <<<"$changed"; then
    warn "Node installer" "rf-pinnacle.sh changed; apply with: bash $RF_REPO_DIR/termux/rf-pinnacle.sh --dry-run"
  fi

  if ((rc != 0)); then
    ((${#RESTARTS[@]} == 0)) || warn "Restart" "verification failed; requested restarts skipped"
    return "$rc"
  fi
  local svc
  for svc in ${RESTARTS[@]+"${RESTARTS[@]}"}; do
    if ! command -v sv >/dev/null 2>&1; then
      fail "Restart $svc" "runit 'sv' not found (pkg install termux-services)"
      rc=4
    elif sv restart "$svc" >>"$LOG_FILE" 2>&1; then
      ok "Restart $svc" "$(sv status "$svc" 2>/dev/null | cut -d';' -f1)"
    else
      fail "Restart $svc" "sv restart failed (see $LOG_FILE)"
      rc=4
    fi
  done
  return "$rc"
}

# ---------------------------------------------------------------- sync ---
do_sync() {
  PRE_HEAD="$(g rev-parse HEAD)"
  local target incoming
  target="$(g rev-parse "origin/$RF_SYNC_BRANCH")"

  if [[ $PRE_HEAD == "$target" ]]; then
    ok "Update" "already at $(short "$target")"
    ((DRY_RUN)) && return 0
    post_sync "$PRE_HEAD" "$PRE_HEAD"
    return
  fi
  if ! g merge-base --is-ancestor "$PRE_HEAD" "$target"; then
    fail "History" "local $(short "$PRE_HEAD") is not an ancestor of GitHub $(short "$target")"
    info "Local commits" "$(g rev-list --count "$target..HEAD") not on GitHub"
    info "Next step" "inspect with: git -C $RF_REPO_DIR log --oneline origin/$RF_SYNC_BRANCH...HEAD"
    exit 3
  fi

  incoming="$(g rev-list --count "HEAD..$target")"
  info "Incoming" "$incoming commit(s)"
  g log --max-count=20 --format='      %h %s' "HEAD..$target"
  ((incoming > 20)) && printf '      … and %d more\n' "$((incoming - 20))"
  if ((DRY_RUN)); then
    g diff --stat "HEAD" "$target" | tail -n 1 | sed 's/^/      /'
    ok "Dry run" "nothing changed"
    return 0
  fi

  # Write before the fast-forward. A killed process cannot lose an installation
  # that still needs to run, even when the next sync is already at the target.
  local lock_change
  lock_change="$(g diff --name-only "$PRE_HEAD" "$target" -- core/requirements.txt)"
  if [[ -n $lock_change ]]; then
    touch -- "$DEPENDENCIES_PENDING" || die "could not record pending dependency installation"
  fi
  if [[ -n $(g status --porcelain --untracked-files=no) ]]; then
    g stash push --quiet -m "rf-sync $(date -u +%Y%m%dT%H%M%SZ) before $(short "$target")" \
      || die "could not stash local edits"
    STASH_SHA="$(g rev-parse 'stash@{0}')"
    info "Local edits" "stashed as $(short "$STASH_SHA")"
  fi

  if ! g merge --ff-only --no-overwrite-ignore --quiet "$target" 2>>"$LOG_FILE"; then
    # Most often an untracked file that the update would overwrite.
    fail "Update" "fast-forward refused (see $LOG_FILE); nothing changed"
    restore_on_error || true
    exit 1
  fi

  if [[ -n $STASH_SHA ]]; then
    if g stash apply --index --quiet "$STASH_SHA" >>"$LOG_FILE" 2>&1; then
      drop_stash
      STASH_SHA=""
      ok "Local edits" "re-applied on top of the update"
    else
      fail "Local edits" "conflict with the update"
      g reset --quiet --hard "$PRE_HEAD"
      if g stash apply --index --quiet "$STASH_SHA" >>"$LOG_FILE" 2>&1; then
        drop_stash
        warn "Rolled back" "checkout back at $(short "$PRE_HEAD") with your edits; commit or discard them, then re-run"
      else
        warn "Rolled back" "checkout at $(short "$PRE_HEAD"); edits kept in stash $STASH_SHA"
      fi
      STASH_SHA=""
      exit 2
    fi
  fi
  ok "Update" "$(short "$PRE_HEAD") → $(short "$target")"
  post_sync "$PRE_HEAD" "$target"
}

do_install() {
  local link_dir="$PREFIX/bin" script
  [[ -d $link_dir && -w $link_dir ]] || link_dir="$HOME/bin"
  mkdir -p "$link_dir"
  script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  ln -sfn "$script" "$link_dir/rf-sync"
  chmod 0700 "$script"
  ok "Installed" "$link_dir/rf-sync -> $script (updates with every pull)"
  [[ :$PATH: == *":$link_dir:"* ]] || warn "PATH" "add $link_dir to PATH"
}

# ---------------------------------------------------------------- main ---
main() {
  printf '%s\n' "── RightsFrames sync $RF_SYNC_VERSION ── $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  log "START mode=$MODE dry_run=$DRY_RUN repo=$RF_REPO_DIR branch=$RF_SYNC_BRANCH"
  if [[ $MODE == install ]]; then
    do_install
    return 0
  fi
  check_repo
  acquire_lock
  if [[ $MODE == status ]]; then
    fetch_remote
    show_status
    return 0
  fi
  ((DRY_RUN)) || check_power
  fetch_remote
  # Called directly (not in an || list) so errexit and the ERR rollback stay active inside.
  do_sync
}

main
