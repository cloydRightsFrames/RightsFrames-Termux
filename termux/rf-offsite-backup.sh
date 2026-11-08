#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
#  rf-offsite-backup.sh — encrypted off-device PostgreSQL backups for Termux
# =============================================================================
#  One script, nothing to edit. Run it once:
#
#    bash termux/rf-offsite-backup.sh            # guided setup + first backup
#    bash termux/rf-offsite-backup.sh run        # one backup now (non-interactive)
#    bash termux/rf-offsite-backup.sh status     # last result, schedule, remote
#    bash termux/rf-offsite-backup.sh uninstall  # stop the daily schedule
#
#  Setup does, in order:
#    1. Installs age and rclone if missing.
#    2. Finds your age key (any file holding AGE-SECRET-KEY-1...) or asks you
#       to paste it once (public age1... or secret AGE-SECRET-KEY-1...).
#    3. Finds your rclone remote by itself (prefers Google Drive), or walks
#       you through creating one, then proves it can write there.
#    4. Saves the settings to ~/.rightsframes/offsite.env and loads them from
#       ~/.bashrc, so rf_apex_final sees RF_OFFSITE_REMOTE and
#       RF_OFFSITE_AGE_RECIPIENT in every new shell.
#    5. Takes a fresh backup (pg_dumpall globals + pg_dump per database, with
#       SHA256SUMS), encrypts it with age, uploads it, downloads it again and
#       compares hashes, and decrypts it when the secret key is on this device.
#    6. Installs the rf-offsite-backup runit service: one backup every 24h,
#       catching up after reboots.
#
#  Nothing is ever deleted from the remote. Locally the newest 7 backup
#  directories are kept.
# =============================================================================

set -Eeuo pipefail
umask 077

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
SVDIR="${SVDIR:-$PREFIX/var/service}"
RF_HOME="$HOME/.rightsframes"
OFF_HOME="$RF_HOME/offsite"
ENV_FILE="$RF_HOME/offsite.env"
KEY_FILE_DEFAULT="$RF_HOME/age.key"
BACKUP_ROOT="$RF_HOME/backups"
LOG_FILE="$OFF_HOME/offsite.log"
STATE_FILE="$OFF_HOME/last_success"
SERVICE="rf-offsite-backup"
MARKER=".rf-pinnacle-managed"
BASHRC_LINE='[ -f "$HOME/.rightsframes/offsite.env" ] && . "$HOME/.rightsframes/offsite.env"  # rf-offsite'
DEFAULT_FOLDER="rightsframes-backups"
KEEP_LOCAL=7
PG_PORT="${RF_PG_PORT:-5432}"

if [[ -t 1 ]]; then
  C_G=$'\e[32m' C_Y=$'\e[33m' C_R=$'\e[31m' C_B=$'\e[1m' C_0=$'\e[0m'
else
  C_G="" C_Y="" C_R="" C_B="" C_0=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s▸ %s%s\n' "$C_B" "$*" "$C_0"; }
ok()   { printf '  %s●%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s▲%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '  %s✖ %s%s\n' "$C_R" "$*" "$C_0" >&2; log "FAIL $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
log()  { mkdir -p "$OFF_HOME"; printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG_FILE"; }

readonly RECIPIENT_RE='^age1[0-9a-z]{58}$'
readonly SECRET_RE='^AGE-SECRET-KEY-1[0-9A-Z]{58}$'

# --------------------------------------------------------------- tooling ---
ensure_tools() {
  local need=()
  have age || need+=(age)
  have rclone || need+=(rclone)
  have pg_dump || need+=(postgresql)
  have sha256sum || need+=(coreutils)
  if ((${#need[@]})); then
    have pkg || die "missing: ${need[*]} (and pkg is not available to install them)"
    say "  installing: ${need[*]}"
    pkg install -y "${need[@]}" >/dev/null
  fi
  ok "age $(age --version 2>/dev/null | head -n1), $(rclone version 2>/dev/null | head -n1)"
}

# ------------------------------------------------------------------- key ---
RECIPIENT="" KEY_FILE=""

find_key_file() {
  local f
  for f in "${RF_AGE_KEY_FILE:-}" "$KEY_FILE_DEFAULT" "$RF_HOME"/*.key "$RF_HOME"/*.txt \
           "$HOME"/.config/sops/age/keys.txt "$HOME"/.age/*.txt "$HOME"/.age/*.key \
           "$HOME"/age*.key "$HOME"/age*.txt "$HOME"/key.txt "$HOME"/*.agekey; do
    [[ -n $f && -f $f && -r $f ]] || continue
    grep -q 'AGE-SECRET-KEY-1' "$f" 2>/dev/null && { printf '%s' "$f"; return 0; }
  done
  return 1
}

setup_key() {
  step "ENCRYPTION KEY"
  local f input
  if f="$(find_key_file)"; then
    KEY_FILE="$f"
    RECIPIENT="$(age-keygen -y "$f" 2>/dev/null | head -n1)"
    [[ $RECIPIENT =~ $RECIPIENT_RE ]] || die "found $f but could not derive its public key"
    chmod 600 "$f" 2>/dev/null || true
    ok "using existing key file $f"
    ok "public key $RECIPIENT"
    return 0
  fi
  if [[ ${RF_OFFSITE_AGE_RECIPIENT:-} =~ $RECIPIENT_RE ]]; then
    RECIPIENT="$RF_OFFSITE_AGE_RECIPIENT"
    ok "using public key from environment $RECIPIENT"
    warn "no secret key on this device: uploads are verified by hash, not by decrypting"
    return 0
  fi

  say "  Paste your age key and press Enter. Either form works:"
  say "    public key:  age1...                 (backups can be made, not opened here)"
  say "    secret key:  AGE-SECRET-KEY-1...     (saved to $KEY_FILE_DEFAULT, mode 600)"
  say "  Input is hidden. Press Enter on an empty line to generate a new key instead."
  while :; do
    IFS= read -r -s -p "  key> " input </dev/tty || die "no terminal to read the key from"
    printf '\n'
    input="$(printf '%s' "$input" | tr -d '[:space:]')"
    if [[ -z $input ]]; then
      mkdir -p "$RF_HOME" && chmod 700 "$RF_HOME"
      age-keygen -o "$KEY_FILE_DEFAULT" 2>/dev/null
      chmod 600 "$KEY_FILE_DEFAULT"
      KEY_FILE="$KEY_FILE_DEFAULT"
      RECIPIENT="$(age-keygen -y "$KEY_FILE")"
      ok "generated new key $KEY_FILE"
      warn "COPY $KEY_FILE OFF THIS PHONE (password manager). Without it the backups cannot be opened."
      break
    elif [[ $input =~ $SECRET_RE ]]; then
      mkdir -p "$RF_HOME" && chmod 700 "$RF_HOME"
      [[ -e $KEY_FILE_DEFAULT ]] && cp -a "$KEY_FILE_DEFAULT" "$KEY_FILE_DEFAULT.bak.$(date -u +%Y%m%dT%H%M%SZ)"
      printf '# created: %s (rf-offsite-backup)\n%s\n' "$(date -u +%FT%TZ)" "$input" >"$KEY_FILE_DEFAULT"
      chmod 600 "$KEY_FILE_DEFAULT"
      KEY_FILE="$KEY_FILE_DEFAULT"
      RECIPIENT="$(age-keygen -y "$KEY_FILE")"
      ok "secret key saved to $KEY_FILE"
      break
    elif [[ $input =~ $RECIPIENT_RE ]]; then
      RECIPIENT="$input"
      warn "public key only: backups are verified by hash, not by decrypting"
      break
    else
      warn "that is not an age key (expected age1... or AGE-SECRET-KEY-1...); try again"
    fi
  done
  ok "public key $RECIPIENT"
}

# ---------------------------------------------------------------- remote ---
REMOTE="" FOLDER=""

remote_works() {
  timeout 90 rclone lsjson --max-depth 1 "$1" >/dev/null 2>&1
}

create_drive_remote() {
  local name="gdrive" cid csec
  say "  No rclone remote found - creating a Google Drive remote named '$name'."
  say "  Google client ID (from Google Cloud Console > Credentials > OAuth client, Desktop app)."
  say "  Press Enter to skip and use rclone's shared client (being retired during 2026)."
  IFS= read -r -p "  client_id> " cid </dev/tty
  cid="$(printf '%s' "$cid" | tr -d '[:space:]')"
  csec=""
  if [[ -n $cid ]]; then
    IFS= read -r -s -p "  client_secret (hidden)> " csec </dev/tty
    printf '\n'
    csec="$(printf '%s' "$csec" | tr -d '[:space:]')"
  fi
  say ""
  say "  rclone will now print a line starting with:  rclone authorize \"drive\" ..."
  say "  ${C_B}Copy that whole line into PowerShell on your Windows PC${C_0} (rclone is installed there),"
  say "  sign in with Google in the browser that opens, then paste the token PowerShell"
  say "  prints back here at the config_token> prompt."
  say ""
  local args=(config create "$name" drive scope=drive.file config_is_local=false)
  [[ -n $cid ]] && args+=("client_id=$cid")
  [[ -n $csec ]] && args+=("client_secret=$csec")
  rclone "${args[@]}" </dev/tty || die "rclone could not create the Google Drive remote"
  REMOTE="$name"
}

setup_remote() {
  step "OFF-DEVICE DESTINATION"
  local -a all=() drives=()
  local line name type
  while read -r line; do
    [[ -z $line ]] && continue
    name="${line%%:*}"
    type="$(awk '{print $2}' <<<"$line")"
    all+=("$name")
    [[ $type == drive ]] && drives+=("$name")
  done < <(rclone listremotes --long 2>/dev/null || true)

  if [[ ${RF_OFFSITE_REMOTE:-} == *:* ]] && remote_works "${RF_OFFSITE_REMOTE%%:*}:"; then
    REMOTE="${RF_OFFSITE_REMOTE%%:*}"
    FOLDER="${RF_OFFSITE_REMOTE#*:}"
    ok "using saved destination $RF_OFFSITE_REMOTE"
  elif ((${#drives[@]} == 1)); then
    REMOTE="${drives[0]}"
    ok "found Google Drive remote '$REMOTE'"
  elif ((${#drives[@]} > 1 || ${#all[@]} > 0)); then
    local -a pick=("${drives[@]}")
    ((${#pick[@]})) || pick=("${all[@]}")
    if ((${#pick[@]} == 1)); then
      REMOTE="${pick[0]}"
      ok "found rclone remote '$REMOTE'"
    else
      say "  Your rclone remotes:"
      local i
      for i in "${!pick[@]}"; do say "    $((i + 1))) ${pick[$i]}"; done
      while :; do
        IFS= read -r -p "  number> " i </dev/tty
        [[ $i =~ ^[0-9]+$ ]] && ((i >= 1 && i <= ${#pick[@]})) && { REMOTE="${pick[$((i - 1))]}"; break; }
        warn "enter a number from 1 to ${#pick[@]}"
      done
    fi
  else
    create_drive_remote
  fi

  if ! remote_works "$REMOTE:"; then
    warn "remote '$REMOTE' did not answer - its Google sign-in has probably expired; reconnecting"
    say "  If rclone prints 'rclone authorize ...', run that line in PowerShell on your PC"
    say "  and paste the token back here."
    rclone config reconnect "$REMOTE:" </dev/tty || die "could not reconnect remote '$REMOTE'"
    remote_works "$REMOTE:" || die "remote '$REMOTE' is still unreachable"
  fi
  FOLDER="${FOLDER:-$DEFAULT_FOLDER}"
  local err
  err="$(rclone mkdir "$REMOTE:$FOLDER" 2>&1)" || die "cannot create folder $REMOTE:$FOLDER: $(tail -n1 <<<"$err")"
  ok "destination $REMOTE:$FOLDER is reachable"
}

# ------------------------------------------------------------ persistence ---
save_settings() {
  step "SAVING SETTINGS"
  mkdir -p "$RF_HOME" && chmod 700 "$RF_HOME"
  {
    printf '# rf-offsite-backup settings - regenerated by: bash termux/rf-offsite-backup.sh\n'
    printf 'export RF_OFFSITE_REMOTE=%q\n' "$REMOTE:$FOLDER"
    printf 'export RF_OFFSITE_AGE_RECIPIENT=%q\n' "$RECIPIENT"
    [[ -n $KEY_FILE ]] && printf 'export RF_AGE_KEY_FILE=%q\n' "$KEY_FILE"
  } >"$ENV_FILE.tmp"
  chmod 600 "$ENV_FILE.tmp"
  mv -f "$ENV_FILE.tmp" "$ENV_FILE"
  ok "wrote $ENV_FILE"

  touch "$HOME/.bashrc"
  if ! grep -qF '# rf-offsite' "$HOME/.bashrc"; then
    cp -a "$HOME/.bashrc" "$RF_HOME/bashrc.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    printf '\n%s\n' "$BASHRC_LINE" >>"$HOME/.bashrc"
    ok "$HOME/.bashrc now loads it (backup of the old one in $RF_HOME)"
  else
    ok "$HOME/.bashrc already loads it"
  fi
  # shellcheck source=/dev/null
  . "$ENV_FILE"
}

load_settings() {
  # shellcheck source=/dev/null
  [[ -f $ENV_FILE ]] && . "$ENV_FILE"
  [[ ${RF_OFFSITE_REMOTE:-} == *:* ]] || die "not set up yet - run: bash termux/rf-offsite-backup.sh"
  [[ ${RF_OFFSITE_AGE_RECIPIENT:-} =~ $RECIPIENT_RE ]] || die "invalid RF_OFFSITE_AGE_RECIPIENT in $ENV_FILE"
  REMOTE="${RF_OFFSITE_REMOTE%%:*}"
  FOLDER="${RF_OFFSITE_REMOTE#*:}"
  RECIPIENT="$RF_OFFSITE_AGE_RECIPIENT"
  KEY_FILE="${RF_AGE_KEY_FILE:-}"
  [[ -n $KEY_FILE && -r $KEY_FILE ]] || KEY_FILE=""
}

# ---------------------------------------------------------------- backup ---
pg_socket() {
  local d
  for d in "$PREFIX/var/run/postgresql" "$PREFIX/tmp" /tmp; do
    [[ -S $d/.s.PGSQL.$PG_PORT ]] && { printf '%s' "$d"; return 0; }
  done
  printf '127.0.0.1'
}

make_dump() {
  local sock dir stamp n=0 db
  sock="$(pg_socket)"
  pg_isready -q -h "$sock" -p "$PG_PORT" -t 5 || die "PostgreSQL is not accepting connections on $sock:$PG_PORT"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="$BACKUP_ROOT/rf-offsite-$stamp"
  mkdir -p "$dir"
  chmod 700 "$BACKUP_ROOT" "$dir"
  pg_dumpall -h "$sock" -p "$PG_PORT" --globals-only -f "$dir/globals.sql" 2>>"$LOG_FILE" ||
    die "pg_dumpall --globals-only failed (see $LOG_FILE)"
  : >"$dir/databases.private"
  while IFS= read -r db; do
    [[ -n $db ]] || continue
    n=$((n + 1))
    pg_dump -h "$sock" -p "$PG_PORT" -Fc -f "$dir/database-$n.dump" "$db" 2>>"$LOG_FILE" ||
      die "pg_dump of database #$n failed (see $LOG_FILE)"
    printf 'database-%s.dump\t%s\n' "$n" "$db" >>"$dir/databases.private"
  done < <(psql -h "$sock" -p "$PG_PORT" -d postgres -At \
             -c "select datname from pg_database where datallowconn and not datistemplate order by datname" 2>>"$LOG_FILE")
  ((n > 0)) || die "no databases found to back up"
  (cd "$dir" && sha256sum globals.sql databases.private database-*.dump >SHA256SUMS)
  for db in "$dir"/database-*.dump; do
    pg_restore -l "$db" >/dev/null 2>&1 || die "dump $(basename "$db") is not a readable archive"
  done
  DUMP_DIR="$dir"
  DUMP_COUNT=$n
}

prune_local() {
  local -a dirs
  mapfile -t dirs < <(ls -1d "$BACKUP_ROOT"/rf-offsite-* 2>/dev/null | sort -r)
  local d
  for d in "${dirs[@]:$KEEP_LOCAL}"; do rm -rf -- "$d"; done
}

do_backup() {
  step "BACKUP"
  make_dump
  ok "dumped $DUMP_COUNT database(s) + roles to $DUMP_DIR (checksums verified)"

  local tmp remote_path local_hash remote_hash
  tmp="$(mktemp "${TMPDIR:-$PREFIX/tmp}/rf-offsite.XXXXXXXX")"
  TMP_ARCHIVE="$tmp"
  trap 'rm -f -- "$TMP_ARCHIVE"' EXIT
  tar -C "$DUMP_DIR" -cf - . | age -r "$RECIPIENT" -o "$tmp" || die "age encryption failed; nothing uploaded"
  ok "encrypted ($(du -h "$tmp" | cut -f1)) for $RECIPIENT"

  remote_path="$REMOTE:$FOLDER/rightsframes-$(basename "$DUMP_DIR").tar.age"
  rclone copyto --immutable "$tmp" "$remote_path" 2>>"$LOG_FILE" || die "upload to $remote_path failed (see $LOG_FILE)"
  local_hash="$(sha256sum "$tmp" | awk '{print $1}')"
  remote_hash="$(rclone cat "$remote_path" 2>>"$LOG_FILE" | sha256sum | awk '{print $1}')"
  [[ $local_hash == "$remote_hash" ]] || die "readback mismatch for $remote_path"
  ok "uploaded $remote_path, readback sha256 matches"

  if [[ -n $KEY_FILE ]]; then
    if rclone cat "$remote_path" 2>>"$LOG_FILE" | age -d -i "$KEY_FILE" | tar -tf - 2>/dev/null | grep -qx './SHA256SUMS'; then
      ok "downloaded copy decrypts with $KEY_FILE and contains the checksummed dump"
    else
      die "uploaded copy did not decrypt with $KEY_FILE"
    fi
  fi

  date +%s >"$STATE_FILE"
  printf '%s\n' "$remote_path" >"$OFF_HOME/last_remote"
  prune_local
  log "PASS $remote_path sha256=$local_hash databases=$DUMP_COUNT"
  say ""
  say "  ${C_G}OFFSITE_BACKUP=PASS${C_0}  $remote_path"
}

# ------------------------------------------------------------- schedule ---
install_service() {
  step "DAILY SCHEDULE"
  have sv && [[ -d $SVDIR ]] || { warn "runit not available - run 'bash $0 run' daily yourself"; return 0; }
  local bin="$RF_HOME/bin/rf-offsite-backup" dest="$SVDIR/$SERVICE" tmp="$SVDIR/.$SERVICE.tmp" bash_bin
  bash_bin="$(command -v bash)"
  mkdir -p "$RF_HOME/bin"
  cp -f "$0" "$bin.new" && chmod 700 "$bin.new" && mv -f "$bin.new" "$bin"

  if [[ -d $dest && ! -e $dest/$MARKER ]]; then
    warn "an unmanaged service named $SERVICE exists - left untouched"
    return 0
  fi
  rm -rf "$tmp"
  mkdir -p "$tmp"
  cat >"$tmp/run" <<EOF
#!$bash_bin
# rf-offsite-backup scheduler: one backup per 24h, checked hourly, so a
# reboot or a dead network only delays the next backup instead of skipping it.
exec >>$(printf '%q' "$LOG_FILE") 2>&1
export HOME=$(printf '%q' "$HOME") PREFIX=$(printf '%q' "$PREFIX") PATH=$(printf '%q' "$PREFIX/bin"):"\$PATH"
while :; do
  last=\$(cat $(printf '%q' "$STATE_FILE") 2>/dev/null || echo 0)
  if (( \$(date +%s) - last >= 86400 )); then
    $(printf '%q' "$bash_bin") $(printf '%q' "$bin") run || echo "\$(date -u +%FT%TZ) scheduled backup failed; retrying in 1h"
  fi
  sleep 3600 & wait \$!
done
EOF
  chmod 700 "$tmp/run"
  printf 'rf-offsite-backup %s\n' "$(date -u +%FT%TZ)" >"$tmp/$MARKER"
  if [[ -d $dest ]]; then
    cp -f "$tmp/run" "$dest/run"
    rm -rf "$tmp"
    sv restart "$dest" >/dev/null 2>&1 || true
  else
    mv "$tmp" "$dest"
  fi
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sv status "$dest" 2>/dev/null | grep -q '^run:' && break
    sleep 1
  done
  if sv status "$dest" 2>/dev/null | grep -q '^run:'; then
    ok "runit service $SERVICE running: next backup 24h after the last successful one"
  else
    warn "service $SERVICE created but not running yet: $(sv status "$dest" 2>&1)"
  fi
}

cmd_status() {
  step "OFF-DEVICE BACKUP STATUS"
  if [[ -f $ENV_FILE ]]; then
    # shellcheck source=/dev/null
    . "$ENV_FILE"
    ok "destination ${RF_OFFSITE_REMOTE:-?}"
    ok "public key ${RF_OFFSITE_AGE_RECIPIENT:-?}"
  else
    warn "not set up - run: bash termux/rf-offsite-backup.sh"
  fi
  if [[ -f $STATE_FILE ]]; then
    local last age_h
    last="$(cat "$STATE_FILE")"
    age_h=$((($(date +%s) - last) / 3600))
    ok "last success $(date -d "@$last" '+%F %T' 2>/dev/null || echo "$last") (${age_h}h ago): $(cat "$OFF_HOME/last_remote" 2>/dev/null)"
    ((age_h <= 26)) || warn "last success is older than 26h - check $LOG_FILE"
  else
    warn "no successful backup recorded yet"
  fi
  [[ -d $SVDIR/$SERVICE ]] && ok "schedule: $(sv status "$SVDIR/$SERVICE" 2>&1)"
  [[ -f $LOG_FILE ]] && { say ""; tail -n 5 "$LOG_FILE" | sed 's/^/  /'; }
}

cmd_uninstall() {
  step "UNINSTALL SCHEDULE"
  if [[ -e $SVDIR/$SERVICE/$MARKER ]]; then
    sv -w 10 down "$SVDIR/$SERVICE" >/dev/null 2>&1 || true
    sv exit "$SVDIR/$SERVICE" >/dev/null 2>&1 || true
    rm -rf "${SVDIR:?}/$SERVICE"
    ok "removed runit service $SERVICE"
  else
    ok "no managed $SERVICE service present"
  fi
  ok "kept: settings, key, local backups and every remote archive"
}

main() {
  local cmd="${1:-setup}"
  mkdir -p "$OFF_HOME"
  chmod 700 "$RF_HOME" "$OFF_HOME" 2>/dev/null || true
  case $cmd in
    setup)
      printf '%s=== RIGHTSFRAMES OFF-DEVICE ENCRYPTED BACKUP SETUP ===%s\n' "$C_B" "$C_0"
      step "TOOLS"; ensure_tools
      setup_key
      setup_remote
      save_settings
      do_backup
      install_service
      say ""
      say "  Done. New Termux windows load the settings automatically; in THIS window run:"
      say "    . ~/.rightsframes/offsite.env && rf_apex_final"
      ;;
    run)
      exec 9>"$OFF_HOME/.lock"
      if have flock && ! flock -n 9; then say "another backup is running"; exit 0; fi
      load_settings
      do_backup
      ;;
    status) cmd_status ;;
    uninstall) cmd_uninstall ;;
    -h|--help) sed -n '5,27p' "$0" | sed 's/^# \{0,1\}//' ;;
    *) die "unknown command: $cmd (setup | run | status | uninstall)" ;;
  esac
}

main "$@"
