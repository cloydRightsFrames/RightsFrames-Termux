#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
#  rf-pinnacle.sh — RightsFrames Termux node hardening & self-healing installer
# =============================================================================
#  One self-contained, idempotent script. Run it; it creates everything itself.
#
#    bash termux/rf-pinnacle.sh                # diagnose + repair + install
#    bash termux/rf-pinnacle.sh --dry-run      # show every change, make none
#    bash termux/rf-pinnacle.sh diagnose       # read-only report
#    bash termux/rf-pinnacle.sh status         # state of the managed services
#    bash termux/rf-pinnacle.sh pause|resume   # suspend/resume watchdog actions
#    bash termux/rf-pinnacle.sh uninstall      # remove only what this created
#
#  What it does (install):
#    1. Preflight: Termux layout, runit (termux-services), runsvdir running.
#    2. Forensics: why the whole stack restarted at once (runsvdir age,
#       Android phantom-process killer exposure, memory/disk pressure).
#    3. PostgreSQL: waits out crash recovery, reads pg_controldata + server
#       log, clears a provably stale postmaster.pid, starts it if it's down.
#    4. rf-watchdog (runit): probes every service (redis PING, pg_isready,
#       HTTP /health, TCP), restarts only after consecutive failures, past a
#       start-up grace period, under per-service hourly and per-cycle budgets
#       so it can never mass-restart the stack. Writes JSON state.
#    5. rf-wifi-watch (runit): connectivity state machine; after an outage it
#       restarts the tunnels (Tailscale / Cloudflare) that wedge on network
#       changes; optionally cycles Wi-Fi via Termux:API when the link drops.
#    6. Threat Intel / Aletheia Bridge: supervised under runit with crash-loop
#       backoff, verified for 20s, and disabled again (with the log tail
#       shown) if they turn out not to be long-running daemons.
#    7. Wake lock, then a full verification pass and a saved report.
#
#  Managed services log to ~/.rightsframes/pinnacle/logs (rotated in-process),
#  NOT through extra svlogd processes: every extra process counts against
#  Android's phantom-process limit, which is the likeliest cause of the
#  simultaneous restarts this script was written for.
# =============================================================================

set -Eeuo pipefail
umask 077

readonly RF_VERSION="1.0.0"
readonly MARKER=".rf-pinnacle-managed"

# ----------------------------------------------------------------- layout ---
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
SVDIR="${SVDIR:-$PREFIX/var/service}"
RF_PINNACLE_HOME="${RF_PINNACLE_HOME:-$HOME/.rightsframes/pinnacle}"
BIN_DIR="$RF_PINNACLE_HOME/bin"
LOG_DIR="$RF_PINNACLE_HOME/logs"
STATE_DIR="$RF_PINNACLE_HOME/state"
BACKUP_DIR="$RF_PINNACLE_HOME/backups"
REPORT_DIR="$RF_PINNACLE_HOME/reports"
ENV_FILE="$RF_PINNACLE_HOME/pinnacle.env"
SERVICES_CONF="$RF_PINNACLE_HOME/services.conf"
PAUSE_FILE="$RF_PINNACLE_HOME/watchdog.pause"

# ------------------------------------------------- tunables (env override) ---
RF_REDIS_PORT="${RF_REDIS_PORT:-6380}"
RF_PG_PORT="${RF_PG_PORT:-5432}"
RF_API_PORT="${RF_API_PORT:-8888}"
RF_NGINX_PORT="${RF_NGINX_PORT:-8080}"
RF_TOR_PORT="${RF_TOR_PORT:-9050}"
RF_PG_WAIT="${RF_PG_WAIT:-180}"
RF_THREAT_INTEL="${RF_THREAT_INTEL:-$HOME/charlie2_prod/threat_intel.py}"
RF_ALETHEIA="${RF_ALETHEIA:-$HOME/start_aletheia.sh}"
RF_OBSERVE_SECONDS="${RF_OBSERVE_SECONDS:-20}"
RF_WIFI_CYCLE="${RF_WIFI_CYCLE:-1}"

DRY_RUN=0
COMMAND="install"
SKIP_PG=0
SKIP_DAEMONS=0

PASS=0 WARN=0 FAIL=0
declare -a ACTIONS=()

# ---------------------------------------------------------------- output ---
if [[ -t 1 ]]; then
  C_G=$'\e[32m' C_Y=$'\e[33m' C_R=$'\e[31m' C_B=$'\e[1m' C_D=$'\e[2m' C_0=$'\e[0m'
else
  C_G="" C_Y="" C_R="" C_B="" C_D="" C_0=""
fi
section() { printf '\n%s▸ %s%s\n' "$C_B" "$1" "$C_0"; }
ok()      { PASS=$((PASS + 1)); printf '  %s●%s %-24s %s\n' "$C_G" "$C_0" "$1" "${2:-}"; }
warn()    { WARN=$((WARN + 1)); printf '  %s▲%s %-24s %s\n' "$C_Y" "$C_0" "$1" "${2:-}"; ACTIONS+=("▲ $1: ${2:-}"); }
fail()    { FAIL=$((FAIL + 1)); printf '  %s✖%s %-24s %s\n' "$C_R" "$C_0" "$1" "${2:-}"; ACTIONS+=("✖ $1: ${2:-}"); }
info()    { printf '  %s○%s %-24s %s\n' "$C_D" "$C_0" "$1" "${2:-}"; }
detail()  { sed 's/^/      │ /'; }
die()     { printf '%s✖ %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Run a mutating command, or describe it under --dry-run.
act() {
  local desc=$1; shift
  if ((DRY_RUN)); then
    printf '      %s[dry-run]%s %s\n' "$C_Y" "$C_0" "$desc"
    return 0
  fi
  "$@"
}

# Write stdin to a file atomically with a mode; back up a differing original.
write_file() {
  local dest=$1 mode=$2 tmp
  tmp="$(mktemp "${dest%/*}/.rf-tmp.XXXXXX" 2>/dev/null || mktemp)"
  cat >"$tmp"
  if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    return 0
  fi
  if ((DRY_RUN)); then
    printf '      %s[dry-run]%s write %s (%s)\n' "$C_Y" "$C_0" "$dest" "$mode"
    rm -f "$tmp"
    return 0
  fi
  # Files this script generates are not backed up; anything else is.
  [[ -f $dest && $dest != "$RF_PINNACLE_HOME"/* ]] && backup_path "$dest"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dest"
}

backup_path() {
  local src=$1 stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$BACKUP_DIR"
  cp -a "$src" "$BACKUP_DIR/$(basename "$src").$stamp" 2>/dev/null || true
}

human_secs() {
  local s=${1:-0} d h m
  d=$((s / 86400)) h=$((s % 86400 / 3600)) m=$((s % 3600 / 60))
  if ((d)); then printf '%dd %dh' "$d" "$h"
  elif ((h)); then printf '%dh %dm' "$h" "$m"
  elif ((m)); then printf '%dm %ds' "$m" $((s % 60))
  else printf '%ds' "$s"; fi
}

proc_age() { ps -o etimes= -p "$1" 2>/dev/null | tr -d ' ' || true; }

# ------------------------------------------------------------------ runit ---
# Prints "<state> <pid> <uptime-seconds>" for a service directory.
sv_info() {
  local out pid up
  out="$(sv status "$SVDIR/$1" 2>/dev/null || true)"
  case $out in
    run:*)
      read -r pid up < <(sed -n 's/^run: [^:]*: (pid \([0-9]*\)) \([0-9]*\)s.*/\1 \2/p' <<<"$out")
      printf 'run %s %s\n' "${pid:-0}" "${up:-0}" ;;
    down:*)
      up="$(sed -n 's/^down: [^:]*: \([0-9]*\)s.*/\1/p' <<<"$out")"
      printf 'down 0 %s\n' "${up:-0}" ;;
    finish:*) printf 'finish 0 0\n' ;;
    *) printf 'unknown 0 0\n' ;;
  esac
}

# Regex for a run-script line that execs a given program.
exec_re() { printf '^[[:space:]]*exec[[:space:]](.*[/[:space:]"])?(%s)([[:space:]]|"|$)' "$1"; }

# First runit service whose run script mentions every given pattern.
find_service() {
  local dir run p hit
  for dir in "$SVDIR"/*/; do
    dir="${dir%/}"
    [[ -f $dir/run ]] || continue
    run="$dir/run"
    hit=1
    for p in "$@"; do
      grep -qE -- "$p" "$run" 2>/dev/null || { hit=0; break; }
    done
    if ((hit)); then
      basename "$dir"
      return 0
    fi
  done
  return 1
}

runsvdir_pid() { pgrep -f "runsvdir.*$SVDIR" 2>/dev/null | head -n1 || true; }

# ============================================================== preflight ===
preflight() {
  section "PREFLIGHT"
  [[ -d $PREFIX ]] || die "Termux prefix $PREFIX not found (set PREFIX=...)."
  ok "Termux prefix" "$PREFIX"

  local missing=()
  local t
  for t in curl ps pgrep sed awk grep timeout; do have "$t" || missing+=("$t"); done
  if ((${#missing[@]})); then
    if have pkg; then
      act "pkg install -y procps curl coreutils" pkg install -y procps curl coreutils >/dev/null
    else
      die "missing tools: ${missing[*]}"
    fi
  fi
  ok "Core tools" "curl ps pgrep sed awk grep timeout"

  if ! have sv || ! have runsv; then
    warn "runit" "not installed - installing termux-services"
    act "pkg install -y termux-services" pkg install -y termux-services >/dev/null
    have sv || ((DRY_RUN)) || die "runit still unavailable after install"
  else
    ok "runit" "$(command -v sv)"
  fi

  [[ -d $SVDIR ]] || act "mkdir -p $SVDIR" mkdir -p "$SVDIR"
  local rpid
  rpid="$(runsvdir_pid)"
  if [[ -z $rpid ]]; then
    warn "runsvdir" "not supervising $SVDIR - starting it"
    if have service-daemon; then
      act "service-daemon start" service-daemon start
    else
      act "runsvdir $SVDIR (background)" \
        bash -c 'nohup runsvdir -P "$1" >/dev/null 2>&1 &' _ "$SVDIR"
    fi
    sleep 2
    rpid="$(runsvdir_pid)"
  fi
  if [[ -n $rpid ]]; then
    ok "runsvdir" "pid $rpid, up $(human_secs "$(proc_age "$rpid")")"
  elif ((!DRY_RUN)); then
    die "runsvdir is not running and could not be started"
  fi

  if ((!DRY_RUN)); then
    mkdir -p "$BIN_DIR" "$LOG_DIR" "$STATE_DIR" "$BACKUP_DIR" "$REPORT_DIR"
    chmod 700 "$RF_PINNACLE_HOME"
  fi
}

# ============================================================== forensics ===
forensics() {
  section "RESTART FORENSICS"
  local rpid rage sdk procs mem_total mem_avail pct
  rpid="$(runsvdir_pid)"
  if [[ -n $rpid ]]; then
    rage="$(proc_age "$rpid")"
    if [[ -n $rage ]] && ((rage < 600)); then
      warn "Supervisor age" "runsvdir itself is only $(human_secs "$rage") old - the whole Termux service tree was restarted (Android killed Termux, Termux:Boot, or service-daemon restart), not individual services"
    else
      info "Supervisor age" "runsvdir up $(human_secs "${rage:-0}") - restarts came from inside the stack (a launcher, watchdog or rf-status --restart), not from Android"
    fi
  fi

  procs="$(ps -e -o pid= 2>/dev/null | wc -l | tr -d ' ')"
  local gp=getprop st=settings
  have getprop || gp=/system/bin/getprop
  have settings || st=/system/bin/settings
  sdk="$("$gp" ro.build.version.sdk 2>/dev/null || echo 0)"
  sdk="${sdk//[^0-9]/}"
  sdk="${sdk:-0}"
  local phantom_setting=""
  if have "$st"; then
    phantom_setting="$(timeout 5 "$st" get global settings_enable_monitor_phantom_procs 2>/dev/null | tr -d '\r' || true)"
  fi
  if ((sdk >= 31)); then
    if [[ $phantom_setting == "false" ]]; then
      ok "Phantom-process killer" "disabled (Android SDK $sdk, $procs processes)"
    elif ((procs > 32)); then
      fail "Phantom-process killer" "Android SDK $sdk with $procs processes; the default limit is 32 and Android kills the excess - this matches every daemon restarting together"
      printf '%s\n' \
        "Fix once from a computer (USB debugging on), then reboot:" \
        "  adb shell settings put global settings_enable_monitor_phantom_procs false" \
        "  adb shell \"/system/bin/device_config set_sync_disabled_for_tests persistent\"" \
        "  adb shell \"/system/bin/device_config put activity_manager max_phantom_processes 2147483647\"" \
        "Android 14+: Developer options -> 'Disable child process restrictions' does the same." | detail
    else
      warn "Phantom-process killer" "Android SDK $sdk, $procs processes (limit 32) - close to the kill threshold"
    fi
  else
    info "Phantom-process killer" "not applicable (SDK ${sdk:-unknown}, $procs processes)"
  fi

  if [[ -r /proc/meminfo ]] && grep -q '^MemAvailable:' /proc/meminfo; then
    mem_total="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
    mem_avail="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
    pct=$(((mem_total - mem_avail) * 100 / mem_total))
    if ((pct >= 85)); then
      warn "Memory pressure" "${pct}% used, $((mem_avail / 1024))MB available - Android's low-memory killer also targets Termux; largest consumers:"
      ps -e -o rss=,args= 2>/dev/null | sort -rn | head -n 5 |
        awk '{printf "%6.0fMB  ", $1/1024; $1=""; print substr($0,2,90)}' | detail
    else
      ok "Memory pressure" "${pct}% used"
    fi
  fi

  local used
  used="$(df -P "$HOME" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')"
  if [[ -n $used ]] && ((used >= 95)); then
    warn "Storage" "${used}% used - PostgreSQL WAL and Redis AOF rewrites need headroom"
  elif [[ -n $used ]]; then
    ok "Storage" "${used}% used"
  fi

  if have termux-wake-lock; then
    act "termux-wake-lock" termux-wake-lock
    ok "Wake lock" "held (stops Doze from freezing the stack)"
  else
    warn "Wake lock" "termux-wake-lock missing - pkg install termux-tools"
  fi
}

# ============================================================= postgresql ===
PG_SOCK="" PG_DATA="" PG_SVC=""

pg_ready_rc() {
  local rc=0
  pg_isready -q -h "$PG_SOCK" -p "$RF_PG_PORT" -t 3 >/dev/null 2>&1 || rc=$?
  echo "$rc"
}

pg_detect() {
  local cand pid args dirs=""
  pid="$(pgrep -x postgres 2>/dev/null | head -n1 || true)"
  if [[ -n $pid ]]; then
    args="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
    PG_DATA="$(sed -n 's/.*-D[[:space:]]*\([^[:space:]]*\).*/\1/p' <<<"$args")"
  fi
  if [[ -z $PG_DATA ]]; then
    for cand in "${PGDATA:-}" "$PREFIX/var/lib/postgresql" "$HOME/postgres" "$HOME/pgdata"; do
      [[ -n $cand && -f $cand/PG_VERSION ]] && { PG_DATA="$cand"; break; }
    done
  fi
  if [[ -n $PG_DATA ]]; then
    dirs="$(cat "$PG_DATA/postgresql.conf" "$PG_DATA/postgresql.auto.conf" 2>/dev/null |
      sed -n "s/^[[:space:]]*unix_socket_directories[[:space:]]*=[[:space:]]*'\([^',]*\).*/\1/p" | tail -n1 || true)"
  fi
  PG_SOCK=""
  for cand in $dirs "$PREFIX/var/run/postgresql" "$PREFIX/tmp" /tmp; do
    [[ -S $cand/.s.PGSQL.$RF_PG_PORT ]] && { PG_SOCK="$cand"; break; }
  done
  if [[ -z $PG_SOCK ]]; then
    for cand in $dirs "$PREFIX/var/run/postgresql" "$PREFIX/tmp"; do
      [[ -d $cand ]] && { PG_SOCK="$cand"; break; }
    done
  fi
  PG_SOCK="${PG_SOCK:-$PREFIX/tmp}"
  PG_SVC="$(find_service "$(exec_re 'postgres|pg_ctl')" || true)"
}

pg_cluster_state() {
  [[ -n $PG_DATA ]] && have pg_controldata || return 0
  pg_controldata "$PG_DATA" 2>/dev/null | sed -n 's/^Database cluster state:[[:space:]]*//p' || true
}

pg_log_tail() {
  local f newest=""
  for f in "$PREFIX/var/log/sv/${PG_SVC:-postgres}/current" \
           "$PG_DATA"/log/*.log "$PG_DATA"/pg_log/*.log "$PG_DATA"/*.log \
           "$PREFIX"/var/log/postgres*.log "$HOME"/*postgres*.log; do
    [[ -f $f ]] || continue
    if [[ -z $newest || $f -nt $newest ]]; then newest="$f"; fi
  done
  [[ -n $newest ]] || return 0
  printf '%s\n' "$newest"
  tail -n "${1:-25}" "$newest"
}

pg_start() {
  if [[ -n $PG_SVC ]]; then
    act "sv up $PG_SVC" sv up "$SVDIR/$PG_SVC"
  elif [[ -n $PG_DATA ]] && have pg_ctl; then
    act "pg_ctl start -D $PG_DATA" \
      pg_ctl -D "$PG_DATA" -l "$LOG_DIR/postgres-start.log" -w -t 120 start >/dev/null
  else
    fail "PostgreSQL start" "no runit service and no data directory found"
    return 1
  fi
}

fix_postgres() {
  section "POSTGRESQL"
  if ! have pg_isready; then
    info "PostgreSQL" "pg_isready not installed - skipped"
    return 0
  fi
  pg_detect
  info "Locations" "socket=$PG_SOCK data=${PG_DATA:-unknown} service=${PG_SVC:-none}"

  local rc state waited=0 last_state=""
  rc="$(pg_ready_rc)"

  if [[ $rc == 1 ]]; then
    info "PostgreSQL" "rejecting connections (start-up or crash recovery) - waiting up to ${RF_PG_WAIT}s"
    while [[ $rc == 1 ]] && ((waited < RF_PG_WAIT)); do
      state="$(pg_cluster_state)"
      if [[ -n $state && $state != "$last_state" ]]; then
        info "  cluster state" "$state (after ${waited}s)"
        last_state="$state"
      fi
      sleep 5
      waited=$((waited + 5))
      rc="$(pg_ready_rc)"
    done
    if [[ $rc == 0 ]]; then
      ok "PostgreSQL" "accepting connections after ${waited}s - it was replaying WAL after the stack restart"
      return 0
    fi
  fi

  if [[ $rc == 0 ]]; then
    ok "PostgreSQL" "accepting connections on $PG_SOCK:$RF_PG_PORT"
    return 0
  fi

  if [[ $rc == 1 ]]; then
    state="$(pg_cluster_state)"
    fail "PostgreSQL" "still rejecting after ${RF_PG_WAIT}s (cluster state: ${state:-unknown})"
    pg_log_tail 30 | detail
    case $state in
      "in crash recovery"|"in archive recovery")
        info "Assessment" "recovery is still running - interrupting it restarts recovery from scratch; leave it, rerun later" ;;
      "shutting down")
        info "Assessment" "stuck in shutdown - forcing a fast restart"
        if [[ -n $PG_SVC ]]; then
          act "sv -w 60 restart $PG_SVC" sv -w 60 restart "$SVDIR/$PG_SVC" || true
        elif have pg_ctl && [[ -n $PG_DATA ]]; then
          act "pg_ctl restart -m fast" pg_ctl -D "$PG_DATA" -m fast -w -t 120 restart >/dev/null || true
        fi ;;
    esac
    if [[ -n $PG_DATA && ( -f $PG_DATA/standby.signal || -f $PG_DATA/recovery.signal ) ]]; then
      warn "Recovery signal" "$PG_DATA contains standby.signal/recovery.signal - this server is configured as a replica; remove it only if that is unintended"
    fi
    return 0
  fi

  # rc 2/3: nothing answering.
  fail "PostgreSQL" "not responding on $PG_SOCK:$RF_PG_PORT"
  if [[ -n $PG_DATA && -f $PG_DATA/postmaster.pid ]]; then
    local ppid
    ppid="$(head -n1 "$PG_DATA/postmaster.pid" | tr -dc '0-9')"
    if [[ -n $ppid ]] && grep -q postgres "/proc/$ppid/cmdline" 2>/dev/null; then
      info "postmaster.pid" "pid $ppid is a live postgres - not touching it"
    else
      info "postmaster.pid" "stale (pid ${ppid:-?} is not postgres) - moving it aside"
      if ((!DRY_RUN)); then backup_path "$PG_DATA/postmaster.pid"; fi
      act "rm $PG_DATA/postmaster.pid" rm -f "$PG_DATA/postmaster.pid"
    fi
  fi
  [[ $PG_SOCK == 127.0.0.1 || -d $PG_SOCK ]] || act "mkdir -p $PG_SOCK" mkdir -p "$PG_SOCK"
  pg_start || return 0
  ((DRY_RUN)) && return 0

  waited=0
  rc="$(pg_ready_rc)"
  while [[ $rc != 0 ]] && ((waited < RF_PG_WAIT)); do
    sleep 3
    waited=$((waited + 3))
    rc="$(pg_ready_rc)"
  done
  if [[ $rc == 0 ]]; then
    FAIL=$((FAIL - 1))
    ACTIONS=("${ACTIONS[@]:0:${#ACTIONS[@]}-1}")
    ok "PostgreSQL" "started, accepting connections after ${waited}s"
  else
    fail "PostgreSQL" "start attempted, still not ready after ${RF_PG_WAIT}s"
    pg_log_tail 30 | detail
  fi
}

# ==================================================== generated programs ====
write_env() {
  local bash_bin
  bash_bin="$(command -v bash)"
  {
    printf '# Generated by rf-pinnacle.sh %s - edit freely, rerun to regenerate.\n' "$RF_VERSION"
    printf 'PREFIX=%q\nSVDIR=%q\nBASH_BIN=%q\n' "$PREFIX" "$SVDIR" "$bash_bin"
    printf 'WD_INTERVAL=30\n'
    printf 'WD_FAIL_THRESHOLD=3\n'
    printf 'WD_MAX_RESTARTS_PER_HOUR=3\n'
    printf 'WD_MAX_RESTARTS_PER_CYCLE=1\n'
    printf 'LOG_MAX_BYTES=5242880\n'
    printf 'NET_INTERVAL=30\n'
    printf 'NET_PROBE_URLS=%q\n' "http://connectivitycheck.gstatic.com/generate_204 http://cp.cloudflare.com/generate_204"
    printf 'NET_RECOVER_MIN_OUTAGE=60\n'
    printf 'NET_RECOVER_SERVICES=%q\n' "$(net_recover_services)"
    printf 'NET_RECOVER_COOLDOWN=600\n'
    printf 'WIFI_CYCLE=%q\n' "$RF_WIFI_CYCLE"
    printf 'WIFI_CYCLE_AFTER=90\n'
    printf 'WIFI_CYCLE_COOLDOWN=900\n'
  } | write_file "$ENV_FILE" 600
}

net_recover_services() {
  local out=() s
  s="$(find_service "$(exec_re tailscaled)" || true)"; [[ -n $s ]] && out+=("$s")
  s="$(find_service "$(exec_re cloudflared)" || true)"; [[ -n $s ]] && out+=("$s")
  printf '%s' "${out[*]:-}"
}

# label|runit-service-or-dash|probe|grace-seconds
write_services_conf() {
  if [[ -f $SERVICES_CONF ]] && ! grep -q '^# Generated by rf-pinnacle' "$SERVICES_CONF"; then
    info "services.conf" "hand-edited copy kept: $SERVICES_CONF"
    return 0
  fi
  local svc dir name probe grace mapped=" "
  {
    printf '# Generated by rf-pinnacle.sh %s\n' "$RF_VERSION"
    printf '# label|runit service (- = probe only, never restarted)|probe|grace seconds\n'
    printf '# probes: none | tcp:HOST:PORT | http:URL | redis:PORT | pg:SOCKDIR:PORT\n'
    printf '# Delete the first line to stop reruns from regenerating this file.\n'

    local -a known=(
      "redis|redis-server|redis:$RF_REDIS_PORT|30"
      "postgresql|postgres|pg_ctl|pg:${PG_SOCK:-$PREFIX/var/run/postgresql}:$RF_PG_PORT|900"
      "charlie2-api|uvicorn|gunicorn|http:http://127.0.0.1:$RF_API_PORT/health|60"
      "nginx|nginx|http:http://127.0.0.1:$RF_NGINX_PORT/health|30"
      "tor|tor|tcp:127.0.0.1:$RF_TOR_PORT|120"
    )
    # Only a run script that *execs* the program is mapped; anything else is
    # probe-only, so the watchdog can never restart the wrong service.
    local entry label patterns
    for entry in "${known[@]}"; do
      IFS='|' read -r -a parts <<<"$entry"
      label="${parts[0]}"
      grace="${parts[-1]}"
      probe="${parts[-2]}"
      patterns=("${parts[@]:1:${#parts[@]}-3}")
      svc=""
      local p
      for p in "${patterns[@]}"; do
        svc="$(find_service "$(exec_re "$p")" || true)"
        [[ -n $svc ]] && break
      done
      if [[ -n $svc && $mapped != *" $svc "* ]]; then
        mapped+="$svc "
        printf '%s|%s|%s|%s\n' "$label" "$svc" "$probe" "$grace"
      else
        printf '%s|-|%s|%s\n' "$label" "$probe" "$grace"
      fi
    done

    for dir in "$SVDIR"/*/; do
      dir="${dir%/}"
      name="$(basename "$dir")"
      [[ -f $dir/run && $mapped != *" $name "* ]] || continue
      [[ $name == rf-watchdog ]] && continue
      printf 'sv:%s|%s|none|30\n' "$name" "$name"
    done
  } | write_file "$SERVICES_CONF" 600
}

write_watchdog() {
  write_file "$BIN_DIR/rf-watchdog" 700 <<'WATCHDOG'
#!/usr/bin/env bash
# rf-watchdog - RightsFrames stack watchdog. Managed by rf-pinnacle.sh.
# Probes every service in services.conf. A runit service is restarted only
# after WD_FAIL_THRESHOLD consecutive failed probes, past its start-up grace,
# within WD_MAX_RESTARTS_PER_HOUR per service and WD_MAX_RESTARTS_PER_CYCLE
# across the stack - it can never mass-restart everything.
set -uo pipefail
: "${RF_PINNACLE_HOME:?}"
# shellcheck source=/dev/null
. "$RF_PINNACLE_HOME/pinnacle.env"
CONF="$RF_PINNACLE_HOME/services.conf"
STATE="$RF_PINNACLE_HOME/state"
LOGD="$RF_PINNACLE_HOME/logs"
LOG="$LOGD/rf-watchdog.log"
PAUSE="$RF_PINNACLE_HOME/watchdog.pause"
mkdir -p "$STATE/wd" "$LOGD"

rotate() {
  local f=$1 sz
  [[ -f $f ]] || return 0
  sz=$(wc -c <"$f" 2>/dev/null || echo 0)
  if ((sz > LOG_MAX_BYTES)); then cp -f "$f" "$f.1" && : >"$f"; fi
}
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG"; }
jesc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "${s//$'\n'/ }"; }

sv_info() {
  local out pid up
  out="$(sv status "$SVDIR/$1" 2>/dev/null || true)"
  case $out in
    run:*) read -r pid up < <(sed -n 's/^run: [^:]*: (pid \([0-9]*\)) \([0-9]*\)s.*/\1 \2/p' <<<"$out")
           echo "run ${pid:-0} ${up:-0}" ;;
    down:*) echo "down 0 $(sed -n 's/^down: [^:]*: \([0-9]*\)s.*/\1/p' <<<"$out")" ;;
    finish:*) echo "finish 0 0" ;;
    *) echo "unknown 0 0" ;;
  esac
}

probe() {
  local spec=$1 kind arg host port code rc
  kind=${spec%%:*}
  arg=${spec#*:}
  case $kind in
    none) return 0 ;;
    tcp)  host=${arg%:*}; port=${arg##*:}
          timeout 4 bash -c ': >"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null ;;
    http) code=$(curl --noproxy '*' -s -m 6 -o /dev/null -w '%{http_code}' "$arg" 2>/dev/null)
          [[ $code =~ ^[23] ]] ;;
    redis) if command -v redis-cli >/dev/null 2>&1; then
             [[ $(timeout 4 redis-cli -h 127.0.0.1 -p "$arg" ping 2>/dev/null) == PONG ]]
           else
             timeout 4 bash -c ': >"/dev/tcp/127.0.0.1/$1"' _ "$arg" 2>/dev/null
           fi ;;
    pg)   host=${arg%:*}; port=${arg##*:}; rc=0
          pg_isready -q -h "$host" -p "$port" -t 4 >/dev/null 2>&1 || rc=$?
          return "$rc" ;;
    *) return 0 ;;
  esac
}

budget_ok() {
  local f="$STATE/wd/$1.restarts" now cutoff n=0 t keep=()
  now=$(date +%s); cutoff=$((now - 3600))
  if [[ -f $f ]]; then
    while read -r t; do
      [[ $t =~ ^[0-9]+$ ]] && ((t >= cutoff)) && keep+=("$t")
    done <"$f"
    n=${#keep[@]}
    printf '%s\n' "${keep[@]}" >"$f"
    [[ $n -eq 0 ]] && : >"$f"
  fi
  ((n < WD_MAX_RESTARTS_PER_HOUR))
}

declare -A FAILS=() PREV=()
running=1
trap 'running=0' TERM INT
log "rf-watchdog started (pid $$, interval ${WD_INTERVAL}s)"

while ((running)); do
  # shellcheck source=/dev/null
  . "$RF_PINNACLE_HOME/pinnacle.env"
  paused=0; [[ -e $PAUSE ]] && paused=1
  restarts=0
  entries=()
  for f in "$LOG" "$LOGD"/*.log; do rotate "$f"; done

  while IFS='|' read -r label svc spec grace; do
    [[ -z $label || $label == \#* ]] && continue
    grace=${grace:-30}
    status="healthy"; pid=0; up=0; state="-"
    if [[ $svc != "-" ]]; then
      if [[ ! -d $SVDIR/$svc ]]; then
        status="missing"
      else
        read -r state pid up < <(sv_info "$svc")
        if [[ $state == down && ! -e $SVDIR/$svc/down ]]; then
          if ((paused)); then status="down-paused"
          else sv up "$SVDIR/$svc" >/dev/null 2>&1; status="started"
               log "$label: runit service was down (no down file) - sv up"; fi
        elif [[ $state == down ]]; then
          status="disabled"
        elif [[ $state != run ]]; then
          status="$state"
        elif ((up < grace)); then
          # Inside the start-up grace window: report, never count or restart.
          if probe "$spec"; then FAILS[$label]=0; else status="starting"; fi
        fi
      fi
    fi

    if [[ $status == healthy ]]; then
      if probe "$spec"; then
        FAILS[$label]=0
      else
        nfail=$(( ${FAILS[$label]:-0} + 1 ))
        FAILS[$label]=$nfail
        status="failing"
        if [[ $svc != "-" ]] && ((nfail >= WD_FAIL_THRESHOLD)); then
          if ((paused)); then
            status="failing-paused"
          elif ((restarts >= WD_MAX_RESTARTS_PER_CYCLE)); then
            status="failing-queued"
          elif ! budget_ok "$svc"; then
            status="failing-budget-exhausted"
          else
            log "$label: probe $spec failed ${nfail}x after ${up}s uptime - sv restart $svc"
            sv -w 30 restart "$SVDIR/$svc" >/dev/null 2>&1
            date +%s >>"$STATE/wd/$svc.restarts"
            restarts=$((restarts + 1))
            FAILS[$label]=0
            status="restarted"
          fi
        fi
      fi
    fi

    if [[ ${PREV[$label]:-} != "$status" ]]; then
      [[ -n ${PREV[$label]:-} || $status != healthy ]] &&
        log "$label: ${PREV[$label]:-new} -> $status (probe $spec, fails ${FAILS[$label]:-0})"
      PREV[$label]=$status
    fi
    entries+=("$(printf '{"label":"%s","service":"%s","probe":"%s","status":"%s","pid":%s,"uptime":%s,"fails":%s}' \
      "$(jesc "$label")" "$(jesc "$svc")" "$(jesc "$spec")" "$status" "${pid:-0}" "${up:-0}" "${FAILS[$label]:-0}")")
  done <"$CONF"

  tmp="$STATE/watchdog.json.tmp"
  { printf '{"ts":"%s","pid":%s,"paused":%s,"services":[' "$(date -u +%FT%TZ)" "$$" "$paused"
    (IFS=,; printf '%s' "${entries[*]}")
    printf ']}\n'; } >"$tmp" && mv -f "$tmp" "$STATE/watchdog.json"

  sleep "$WD_INTERVAL" &
  wait $! 2>/dev/null || true
done
log "rf-watchdog stopping (pid $$)"
WATCHDOG
}

write_wifi_watch() {
  write_file "$BIN_DIR/rf-wifi-watch" 700 <<'WIFI'
#!/usr/bin/env bash
# rf-wifi-watch - RightsFrames network watchdog. Managed by rf-pinnacle.sh.
# Tracks connectivity; after an outage it restarts the tunnel services that
# wedge on network changes; if Wi-Fi drops while we were on Wi-Fi it can
# cycle the radio through Termux:API (WIFI_CYCLE=1).
set -uo pipefail
: "${RF_PINNACLE_HOME:?}"
# shellcheck source=/dev/null
. "$RF_PINNACLE_HOME/pinnacle.env"
STATE="$RF_PINNACLE_HOME/state"
LOG="$RF_PINNACLE_HOME/logs/rf-wifi-watch.log"
mkdir -p "$STATE" "${LOG%/*}"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG"; }
jesc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "${s//$'\n'/ }"; }

online() {
  local url code
  for url in $NET_PROBE_URLS; do
    code=$(curl --noproxy '*' -s -m 6 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
    [[ $code == 204 || $code == 200 ]] && return 0
  done
  return 1
}

WIFI_STATE="" WIFI_SSID="" WIFI_RSSI=""
wifi_info() {
  WIFI_STATE="" WIFI_SSID="" WIFI_RSSI=""
  command -v termux-wifi-connectioninfo >/dev/null 2>&1 || return 0
  local j
  # Termux:API calls hang forever when the companion app is missing.
  j=$(timeout 10 termux-wifi-connectioninfo 2>/dev/null) || return 0
  WIFI_STATE=$(sed -n 's/.*"supplicant_state": *"\([^"]*\)".*/\1/p' <<<"$j" | head -n1)
  WIFI_SSID=$(sed -n 's/.*"ssid": *"\([^"]*\)".*/\1/p' <<<"$j" | head -n1)
  WIFI_RSSI=$(sed -n 's/.*"rssi": *\(-\{0,1\}[0-9]*\).*/\1/p' <<<"$j" | head -n1)
}

is_online=1 down_since=0 outages=0 last_recover=0 last_cycle=0 was_on_wifi=0 tick=0
running=1
trap 'running=0' TERM INT
log "rf-wifi-watch started (pid $$, interval ${NET_INTERVAL}s)"

while ((running)); do
  # shellcheck source=/dev/null
  . "$RF_PINNACLE_HOME/pinnacle.env"
  now=$(date +%s)
  tick=$((tick + 1))
  # Termux:API is slow; sample it every 10th tick unless something's wrong.
  if ((tick % 10 == 1)) || ((!is_online)); then wifi_info; fi

  if online; then
    [[ $WIFI_STATE == COMPLETED ]] && was_on_wifi=1
    [[ -n $WIFI_STATE && $WIFI_STATE != COMPLETED ]] && was_on_wifi=0
    if ((!is_online)); then
      outage=$((now - down_since))
      log "network restored after ${outage}s (ssid=${WIFI_SSID:-?} rssi=${WIFI_RSSI:-?})"
      if ((outage >= NET_RECOVER_MIN_OUTAGE)) && [[ -n $NET_RECOVER_SERVICES ]] &&
         ((now - last_recover >= NET_RECOVER_COOLDOWN)); then
        for svc in $NET_RECOVER_SERVICES; do
          [[ -d $SVDIR/$svc && ! -e $SVDIR/$svc/down ]] || continue
          log "restarting tunnel service $svc after outage"
          sv -w 20 restart "$SVDIR/$svc" >/dev/null 2>&1
        done
        last_recover=$now
      fi
      is_online=1
    fi
  else
    if ((is_online)); then
      is_online=0; down_since=$now; outages=$((outages + 1))
      log "network DOWN (wifi=${WIFI_STATE:-n/a} ssid=${WIFI_SSID:-?})"
    elif [[ $WIFI_CYCLE == 1 ]] && ((was_on_wifi)) &&
         ((now - down_since >= WIFI_CYCLE_AFTER)) && ((now - last_cycle >= WIFI_CYCLE_COOLDOWN)) &&
         [[ $WIFI_STATE != COMPLETED ]] && command -v termux-wifi-enable >/dev/null 2>&1; then
      log "offline $((now - down_since))s, Wi-Fi state ${WIFI_STATE:-unknown} - cycling Wi-Fi radio"
      timeout 15 termux-wifi-enable false >/dev/null 2>&1
      sleep 5
      timeout 15 termux-wifi-enable true >/dev/null 2>&1
      last_cycle=$now
    fi
  fi

  tmp="$STATE/wifi-watch.json.tmp"
  printf '{"ts":"%s","pid":%s,"online":%s,"down_since":%s,"outages":%s,"wifi_state":"%s","ssid":"%s","rssi":"%s","last_tunnel_recover":%s,"last_wifi_cycle":%s}\n' \
    "$(date -u +%FT%TZ)" "$$" "$is_online" "$down_since" "$outages" "$(jesc "$WIFI_STATE")" \
    "$(jesc "$WIFI_SSID")" "$(jesc "$WIFI_RSSI")" "$last_recover" "$last_cycle" >"$tmp" &&
    mv -f "$tmp" "$STATE/wifi-watch.json"

  sleep "$NET_INTERVAL" &
  wait $! 2>/dev/null || true
done
log "rf-wifi-watch stopping (pid $$)"
WIFI
}

# Create (or refresh) a runit service atomically. runsvdir ignores dot-dirs,
# so the service is assembled under .name.tmp and renamed into place.
# $1 name  $2 run-script body  $3 finish-script body (optional)
install_service() {
  local name=$1 run_body=$2 finish_body=${3:-} dest="$SVDIR/$1" tmp="$SVDIR/.$1.rf-tmp" bash_bin
  bash_bin="$(command -v bash)"
  if [[ -d $dest && ! -e $dest/$MARKER ]]; then
    warn "$name" "an unmanaged runit service with this name exists - left untouched"
    return 1
  fi
  if ((DRY_RUN)); then
    printf '      %s[dry-run]%s install runit service %s\n' "$C_Y" "$C_0" "$dest"
    return 0
  fi
  if [[ -d $dest ]]; then
    printf '#!%s\n%s\n' "$bash_bin" "$run_body" | write_file "$dest/run" 700
    if [[ -n $finish_body ]]; then
      printf '#!%s\n%s\n' "$bash_bin" "$finish_body" | write_file "$dest/finish" 700
    fi
    return 0
  fi
  rm -rf "$tmp"
  mkdir -p "$tmp"
  printf '#!%s\n%s\n' "$bash_bin" "$run_body" >"$tmp/run"
  [[ -n $finish_body ]] && printf '#!%s\n%s\n' "$bash_bin" "$finish_body" >"$tmp/finish"
  printf 'rf-pinnacle %s %s\n' "$RF_VERSION" "$(date -u +%FT%TZ)" >"$tmp/$MARKER"
  chmod 700 "$tmp"/run "$tmp"/finish 2>/dev/null || chmod 700 "$tmp/run"
  mv "$tmp" "$dest"
}

# Wait until runsv has picked up a new service and reports it running.
await_running() {
  local name=$1 limit=${2:-15} i state pid up
  for ((i = 0; i < limit; i++)); do
    read -r state pid up < <(sv_info "$name")
    [[ $state == run ]] && return 0
    sleep 1
  done
  return 1
}

install_watchdogs() {
  section "WATCHDOGS"
  write_env
  write_services_conf
  write_watchdog
  write_wifi_watch

  local q_home
  q_home="$(printf '%q' "$RF_PINNACLE_HOME")"
  local name
  for name in rf-watchdog rf-wifi-watch; do
    local body existed=0
    [[ -e $SVDIR/$name/$MARKER ]] && existed=1
    body="exec 2>&1
export RF_PINNACLE_HOME=$q_home
export PATH=$(printf '%q' "$PREFIX/bin"):\"\$PATH\"
exec $(printf '%q' "$(command -v bash)") $q_home/bin/$name"
    if install_service "$name" "$body"; then
      ((DRY_RUN)) && continue
      ((existed)) && sv -w 10 restart "$SVDIR/$name" >/dev/null 2>&1 || true
      if await_running "$name" 15; then
        local state pid up
        read -r state pid up < <(sv_info "$name")
        ok "$name" "runit service up, pid $pid"
      else
        fail "$name" "service created but not running: $(sv status "$SVDIR/$name" 2>&1)"
      fi
    fi
  done
}

# ============================================================ daemon wrap ===
# Supervise a script under runit with crash-loop backoff and a 20s
# verification; disable it again if it is not a long-running daemon.
supervise_script() {
  local label=$1 name=$2 path=$3
  shift 3
  local -a interp=("$@")
  local existing state pid up dir base
  dir="$(dirname "$path")"
  base="$(basename "$path")"

  existing="$(find_service "$(printf '%s' "$path" | sed 's/[.[\*^$()+?{|]/\\&/g')" || find_service "$base" || true)"
  if [[ -n $existing && ! -e $SVDIR/$existing/$MARKER ]]; then
    read -r state pid up < <(sv_info "$existing")
    if [[ $state == run ]]; then
      ok "$label" "already supervised by runit service $existing (pid $pid)"
    else
      act "sv up $existing" sv up "$SVDIR/$existing"
      info "$label" "existing runit service $existing brought up"
    fi
    return 0
  fi

  local live
  live="$(pgrep -f -- "$base" 2>/dev/null | grep -vx "$$" | head -n1 || true)"
  if [[ -n $live && -z $existing ]]; then
    ok "$label" "running unsupervised (pid $live) - leaving it; rerun after it stops to supervise it"
    return 0
  fi

  local log="$LOG_DIR/$name.log" st="$STATE_DIR/$name"
  local q_log q_st q_dir q_interp q_path
  q_log="$(printf '%q' "$log")" q_st="$(printf '%q' "$st")" q_dir="$(printf '%q' "$dir")"
  q_interp="$(printf '%q ' "${interp[@]}")" q_path="$(printf '%q' "$path")"
  local run_body finish_body
  run_body="mkdir -p $q_st $(printf '%q' "$LOG_DIR")
exec >>$q_log 2>&1
printf '%s [rf-pinnacle] starting $base\\n' \"\$(date -u +%FT%TZ)\"
date +%s >$q_st/start
export PATH=$(printf '%q' "$PREFIX/bin"):\"\$PATH\"
cd $q_dir || exit 1
exec $q_interp$q_path"
  finish_body="# Crash-loop backoff: exponential, capped at 300s, reset after 60s uptime.
start=\$(cat $q_st/start 2>/dev/null || echo 0)
n=\$(cat $q_st/quick_exits 2>/dev/null || echo 0)
ran=\$(( \$(date +%s) - start ))
if (( ran < 60 )); then n=\$((n + 1)); else n=0; fi
echo \"\$n\" >$q_st/quick_exits
if (( n > 0 )); then
  d=\$(( 1 << (n < 9 ? n : 9) )); (( d > 300 )) && d=300
  printf '%s [rf-pinnacle] $base exited (code %s) after %ss; quick exit #%s, backing off %ss\\n' \"\$(date -u +%FT%TZ)\" \"\$1\" \"\$ran\" \"\$n\" \"\$d\" >>$q_log
  sleep \"\$d\"
fi"

  if ((!DRY_RUN)); then
    mkdir -p "$st"
    echo 0 >"$st/quick_exits"
  fi
  install_service "$name" "$run_body" "$finish_body" || return 0
  ((DRY_RUN)) && return 0
  rm -f "$SVDIR/$name/down"
  sv up "$SVDIR/$name" >/dev/null 2>&1 || true

  info "$label" "verifying for ${RF_OBSERVE_SECONDS}s"
  sleep "$RF_OBSERVE_SECONDS"
  read -r state pid up < <(sv_info "$name")
  local quick
  quick="$(cat "$st/quick_exits" 2>/dev/null || echo 0)"
  if [[ $state == run ]] && ((quick == 0)); then
    ok "$label" "supervised by runit service $name, pid $pid, stable ${up}s"
  else
    touch "$SVDIR/$name/down"
    sv down "$SVDIR/$name" >/dev/null 2>&1 || true
    fail "$label" "exits immediately ($quick exit(s) in ${RF_OBSERVE_SECONDS}s) - service $name left disabled; log tail:"
    tail -n 15 "$log" 2>/dev/null | detail
    info "  re-enable" "fix the script, then: rm $SVDIR/$name/down && sv up $SVDIR/$name"
  fi
}

python_for() {
  local dir=$1 c
  for c in "$dir/venv/bin/python" "$dir/.venv/bin/python" "$dir/../venv/bin/python"; do
    [[ -x $c ]] && { printf '%s' "$c"; return; }
  done
  command -v python3 || command -v python
}

daemons() {
  section "THREAT & INTEGRITY DAEMONS"
  local err
  if [[ -f $RF_THREAT_INTEL ]]; then
    local py
    py="$(python_for "$(dirname "$RF_THREAT_INTEL")")"
    if [[ -z $py ]]; then
      fail "Threat Intel" "no python interpreter found"
    elif ! err="$("$py" -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$RF_THREAT_INTEL" 2>&1)"; then
      fail "Threat Intel" "syntax error in $RF_THREAT_INTEL:"
      tail -n 5 <<<"$err" | detail
    else
      supervise_script "Threat Intel" rf-threat-intel "$RF_THREAT_INTEL" "$py" -u
    fi
  else
    warn "Threat Intel" "$RF_THREAT_INTEL not found (set RF_THREAT_INTEL=/path)"
  fi

  if [[ -f $RF_ALETHEIA ]]; then
    if ! err="$(bash -n "$RF_ALETHEIA" 2>&1)"; then
      fail "Aletheia Bridge" "syntax error in $RF_ALETHEIA:"
      tail -n 5 <<<"$err" | detail
    elif grep -vE '^[[:space:]]*#' "$RF_ALETHEIA" |
         grep -qE '(nohup|setsid|disown|daemonize|--daemon)|[^&]&[[:space:]]*($|#)'; then
      # A launcher that backgrounds its children cannot be supervised (runit
      # would relaunch it on every exit and duplicate the bridge). Run it once.
      info "Aletheia Bridge" "launcher backgrounds its own processes - running it once, not under runit"
      local rc=0
      act "bash $RF_ALETHEIA" \
        bash -c 'cd "$(dirname "$1")" && timeout 60 bash "$1" >>"$2" 2>&1' _ "$RF_ALETHEIA" "$LOG_DIR/rf-aletheia.log" || rc=$?
      if ((rc == 0)); then
        ok "Aletheia Bridge" "launcher exited 0; output in $LOG_DIR/rf-aletheia.log"
      else
        fail "Aletheia Bridge" "launcher exited $rc; log tail:"
        tail -n 15 "$LOG_DIR/rf-aletheia.log" 2>/dev/null | detail
      fi
    else
      supervise_script "Aletheia Bridge" rf-aletheia "$RF_ALETHEIA" "$(command -v bash)"
    fi
  else
    warn "Aletheia Bridge" "$RF_ALETHEIA not found (set RF_ALETHEIA=/path)"
  fi
  # Re-map so the watchdog covers services created above.
  write_services_conf
}

# ================================================================ verify ====
verify() {
  section "VERIFICATION"
  local rc
  if have redis-cli; then
    if [[ $(timeout 4 redis-cli -h 127.0.0.1 -p "$RF_REDIS_PORT" ping 2>/dev/null) == PONG ]]; then
      ok "Redis" "PONG on :$RF_REDIS_PORT"
    else
      fail "Redis" "no PONG on :$RF_REDIS_PORT"
    fi
  fi
  if have pg_isready; then
    [[ -n $PG_SOCK ]] || pg_detect
    rc="$(pg_ready_rc)"
    case $rc in
      0) ok "PostgreSQL" "accepting connections" ;;
      1) fail "PostgreSQL" "rejecting connections (cluster: $(pg_cluster_state || true))" ;;
      *) fail "PostgreSQL" "no response" ;;
    esac
  fi
  local url code
  for url in "http://127.0.0.1:$RF_API_PORT/health" "http://127.0.0.1:$RF_NGINX_PORT/health"; do
    code="$(curl --noproxy '*' -s -m 6 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    if [[ $code =~ ^2 ]]; then ok "HTTP" "$code $url"; else fail "HTTP" "${code:-000} $url"; fi
  done
  local name state pid up
  for name in rf-watchdog rf-wifi-watch rf-threat-intel rf-aletheia; do
    [[ -d $SVDIR/$name ]] || continue
    read -r state pid up < <(sv_info "$name")
    if [[ $state == run ]]; then ok "$name" "run, pid $pid, up $(human_secs "$up")"
    elif [[ -e $SVDIR/$name/down ]]; then info "$name" "disabled (down file present)"
    else fail "$name" "$state"; fi
  done
  if [[ -f $STATE_DIR/watchdog.json ]]; then
    ok "Watchdog state" "$STATE_DIR/watchdog.json"
  fi
}

# ============================================================ subcommands ===
cmd_status() {
  section "MANAGED SERVICES"
  local dir name state pid up
  for dir in "$SVDIR"/*/; do
    dir="${dir%/}"
    [[ -e $dir/$MARKER ]] || continue
    name="$(basename "$dir")"
    read -r state pid up < <(sv_info "$name")
    printf '  %-18s %-7s pid %-7s up %s%s\n' "$name" "$state" "$pid" "$(human_secs "$up")" \
      "$([[ -e $dir/down ]] && echo ' (disabled)')"
  done
  [[ -e $PAUSE_FILE ]] && printf '  %swatchdog actions PAUSED%s (resume: %s resume)\n' "$C_Y" "$C_0" "$0"
  if [[ -f $STATE_DIR/watchdog.json ]]; then
    section "WATCHDOG VIEW ($(sed -n 's/.*"ts":"\([^"]*\)".*/\1/p' "$STATE_DIR/watchdog.json" | head -n1))"
    grep -o '{"label"[^}]*}' "$STATE_DIR/watchdog.json" |
      sed 's/{"label":"\([^"]*\)","service":"\([^"]*\)","probe":"\([^"]*\)","status":"\([^"]*\)".*"fails":\([0-9]*\)}/  \1|\2|\4|\5|\3/' |
      awk -F'|' '{printf "%-20s %-18s %-26s fails=%-3s %s\n", $1, $2, $3, $4, $5}'
  fi
  if [[ -f $STATE_DIR/wifi-watch.json ]]; then
    section "NETWORK VIEW"
    printf '  %s\n' "$(cat "$STATE_DIR/wifi-watch.json")"
  fi
  section "RECENT EVENTS"
  tail -n 10 "$LOG_DIR/rf-watchdog.log" "$LOG_DIR/rf-wifi-watch.log" 2>/dev/null | sed 's/^/  /' || true
}

cmd_uninstall() {
  section "UNINSTALL"
  local dir name
  for dir in "$SVDIR"/*/; do
    dir="${dir%/}"
    [[ -e $dir/$MARKER ]] || continue
    name="$(basename "$dir")"
    act "sv down $name" sv -w 15 down "$dir" >/dev/null 2>&1 || true
    act "sv exit $name" sv exit "$dir" >/dev/null 2>&1 || true
    act "rm -rf $dir" rm -rf "$dir"
    ok "$name" "removed"
  done
  info "Kept" "$RF_PINNACLE_HOME (logs, state, backups) - delete it manually if wanted"
}

summary() {
  section "SUMMARY"
  local score=100 total=$((PASS + WARN + FAIL))
  ((total)) && score=$(((PASS * 100 + WARN * 50) / total))
  printf '  PASS %d   WARN %d   FAIL %d   score %d%%\n' "$PASS" "$WARN" "$FAIL" "$score"
  if ((${#ACTIONS[@]})); then
    printf '\n  ACTION ITEMS\n'
    printf '  %s\n' "${ACTIONS[@]}"
  fi
  printf '\n  status: bash %s status    pause: bash %s pause\n' "$0" "$0"
}

usage() {
  sed -n '5,/^# =====*$/{/^# =====*$/d;s/^# \{0,1\}//;p}' "$0"
  cat <<EOF

Options:
  --dry-run        print every change, make none
  --no-postgres    skip the PostgreSQL repair step
  --no-daemons     skip Threat Intel / Aletheia supervision
  --pg-wait SECS   how long to wait out PostgreSQL recovery (default $RF_PG_WAIT)
Environment overrides: RF_REDIS_PORT RF_PG_PORT RF_API_PORT RF_NGINX_PORT
  RF_TOR_PORT RF_THREAT_INTEL RF_ALETHEIA RF_WIFI_CYCLE=0 RF_PINNACLE_HOME
EOF
}

main() {
  while (($#)); do
    case $1 in
      install|diagnose|status|uninstall|pause|resume) COMMAND=$1 ;;
      --dry-run) DRY_RUN=1 ;;
      --no-postgres) SKIP_PG=1 ;;
      --no-daemons) SKIP_DAEMONS=1 ;;
      --pg-wait) RF_PG_WAIT=${2:?--pg-wait needs seconds}; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
  done
  [[ $RF_PG_WAIT =~ ^[0-9]+$ ]] || die "--pg-wait must be a number"

  printf '%s╔═══════════════════════════════════════════════════════════════╗\n' "$C_B"
  printf '║          R I G H T S F R A M E S   ·   P I N N A C L E        ║\n'
  printf '╚═══════════════════════════════════════════════════════════════╝%s\n' "$C_0"
  printf '  %s  rf-pinnacle %s  %s%s\n' "$(date -u '+%F %T UTC')" "$RF_VERSION" "$COMMAND" \
    "$( ((DRY_RUN)) && echo ' (dry-run)')"

  case $COMMAND in
    status) cmd_status; return 0 ;;
    uninstall) cmd_uninstall; return 0 ;;
    pause) act "touch $PAUSE_FILE" touch "$PAUSE_FILE"; ok "Watchdog" "actions paused - it still probes and records"; return 0 ;;
    resume) act "rm $PAUSE_FILE" rm -f "$PAUSE_FILE"; ok "Watchdog" "actions resumed"; return 0 ;;
    diagnose) DRY_RUN=1 ;;
  esac

  # Single instance: a second concurrent run would race on service creation.
  if ((!DRY_RUN)); then
    mkdir -p "$RF_PINNACLE_HOME"
    exec 9>"$RF_PINNACLE_HOME/.lock"
    if have flock && ! flock -n 9; then die "another rf-pinnacle run is in progress"; fi
    mkdir -p "$REPORT_DIR"
    local report
    report="$REPORT_DIR/pinnacle-$(date -u +%Y%m%dT%H%M%SZ).txt"
    exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' >"$report")) 2>&1
  fi

  preflight
  forensics
  ((SKIP_PG)) || fix_postgres
  install_watchdogs
  ((SKIP_DAEMONS)) || daemons
  ((DRY_RUN)) || verify
  summary
  ((DRY_RUN)) || printf '  report: %s\n' "$report"
  ((FAIL == 0))
}

main "$@"
