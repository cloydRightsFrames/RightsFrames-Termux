#!/data/data/com.termux/files/usr/bin/bash
set -u

umask 077

RF_ROOT="$HOME/RightsFrames-Termux"
OUT="$RF_ROOT/artifacts/lynis-hardening"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN="$OUT/$STAMP"
REPORT="$RUN/assurance.txt"
BACKUP="$RUN/backups"

mkdir -p "$RUN" "$BACKUP"
exec > >(tee -a "$REPORT") 2>&1

PASS=0
FAIL=0
WARN=0
CHANGES=0

pass() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '[FAIL] %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf '[WARN] %s\n' "$*"; }
change() { CHANGES=$((CHANGES+1)); printf '[CHANGE] %s\n' "$*"; }

backup_once() {
    src="$1"
    [ -e "$src" ] || return 0
    dst="$BACKUP/$(basename "$src").$STAMP"
    cp -p "$src" "$dst" || return 1
    printf '%s\n' "$dst"
}

write_if_changed() {
    target="$1"
    tmp="$2"

    if [ -f "$target" ] && cmp -s "$target" "$tmp"; then
        rm -f "$tmp"
        return 0
    fi

    if [ -f "$target" ]; then
        backup_once "$target" >/dev/null || return 1
    fi

    mv "$tmp" "$target"
    change "Updated $target"
    return 0
}

printf '%s\n' '============================================================'
printf '%s\n' 'RIGHTSFRAMES LYNIS PRODUCTION HARDENING'
printf 'UTC=%s\n' "$STAMP"
printf 'TERMUX_PREFIX=%s\n' "$PREFIX"
printf 'RF_ROOT=%s\n' "$RF_ROOT"
printf '%s\n' '============================================================'

printf '%s\n' '=== PLATFORM ==='
printf 'ID='; id -u
printf 'USER='; id -un 2>/dev/null || true
printf 'ARCH='; uname -m
printf 'KERNEL='; uname -r

printf '%s\n' '=== PACKAGE MANAGER ==='
if command -v pkg >/dev/null 2>&1; then
    pass 'Termux package manager available'
else
    fail 'Termux package manager unavailable'
fi

printf '%s\n' '=== HOME SECURITY ==='
HOME_MODE="$(stat -c '%a' "$HOME" 2>/dev/null || stat -f '%Lp' "$HOME" 2>/dev/null || printf unknown)"
HOME_OWNER="$(stat -c '%u:%g' "$HOME" 2>/dev/null || stat -f '%u:%g' "$HOME" 2>/dev/null || printf unknown)"
printf 'HOME_MODE=%s\n' "$HOME_MODE"
printf 'HOME_OWNER=%s\n' "$HOME_OWNER"

if chmod 700 "$HOME" 2>/dev/null; then
    NEW_HOME_MODE="$(stat -c '%a' "$HOME" 2>/dev/null || stat -f '%Lp' "$HOME" 2>/dev/null || printf unknown)"
    if [ "$NEW_HOME_MODE" = "700" ]; then
        pass 'Termux HOME restricted to mode 700'
        [ "$HOME_MODE" = "700" ] || change "HOME mode $HOME_MODE -> 700"
    else
        fail "HOME mode could not be verified as 700; observed $NEW_HOME_MODE"
    fi
else
    fail 'Unable to set HOME mode 700'
fi

UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
if chown "$UID_NOW:$GID_NOW" "$HOME" 2>/dev/null; then
    OWNER_AFTER="$(stat -c '%u:%g' "$HOME" 2>/dev/null || stat -f '%u:%g' "$HOME" 2>/dev/null || printf unknown)"
    if [ "$OWNER_AFTER" = "$UID_NOW:$GID_NOW" ]; then
        pass 'HOME ownership matches active Termux UID/GID'
    else
        fail "HOME ownership verification failed: $OWNER_AFTER"
    fi
else
    warn 'HOME ownership could not be changed; verifying existing ownership only'
    if [ "$HOME_OWNER" = "$UID_NOW:$GID_NOW" ]; then
        pass 'Existing HOME ownership matches active UID/GID'
    else
        warn "HOME ownership is $HOME_OWNER; active UID/GID is $UID_NOW:$GID_NOW"
    fi
fi

printf '%s\n' '=== DNS ==='
RESOLV="$PREFIX/etc/resolv.conf"
if [ -f "$RESOLV" ]; then
    backup_once "$RESOLV" >/dev/null || warn 'Could not create resolv.conf backup'
    printf '%s\n' '--- CURRENT RESOLV.CONF ---'
    cat "$RESOLV"
else
    warn "No $RESOLV found"
fi

DNS_TOOL=''
if command -v nslookup >/dev/null 2>&1; then
    DNS_TOOL='nslookup'
elif command -v dig >/dev/null 2>&1; then
    DNS_TOOL='dig'
fi

DNS_GOOD=''
if [ -n "$DNS_TOOL" ]; then
    for ns in 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220; do
        if [ "$DNS_TOOL" = nslookup ]; then
            if nslookup example.com "$ns" >/dev/null 2>&1; then
                printf '[DNS-PASS] %s responsive\n' "$ns"
                if [ -z "$DNS_GOOD" ]; then
                    DNS_GOOD="$ns"
                fi
            else
                printf '[DNS-FAIL] %s not responsive\n' "$ns"
            fi
        else
            if dig +time=2 +tries=1 @"$ns" example.com A >/dev/null 2>&1; then
                printf '[DNS-PASS] %s responsive\n' "$ns"
                if [ -z "$DNS_GOOD" ]; then
                    DNS_GOOD="$ns"
                fi
            else
                printf '[DNS-FAIL] %s not responsive\n' "$ns"
            fi
        fi
    done
else
    warn 'Neither nslookup nor dig is available; DNS responsiveness cannot be independently tested'
fi

DNS_SECOND=''
if [ -n "$DNS_TOOL" ]; then
    for ns in 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220; do
        [ "$ns" = "$DNS_GOOD" ] && continue
        if [ "$DNS_TOOL" = nslookup ]; then
            if nslookup example.com "$ns" >/dev/null 2>&1; then
                DNS_SECOND="$ns"
                break
            fi
        else
            if dig +time=2 +tries=1 @"$ns" example.com A >/dev/null 2>&1; then
                DNS_SECOND="$ns"
                break
            fi
        fi
    done
fi

if [ -n "$DNS_GOOD" ] && [ -n "$DNS_SECOND" ]; then
    pass "Two independently responsive DNS servers: $DNS_GOOD and $DNS_SECOND"

    if [ -f "$RESOLV" ] && [ ! -L "$RESOLV" ]; then
        TMP_RES="$RUN/resolv.conf.new"
        {
            printf '# RightsFrames DNS baseline; generated %s\n' "$STAMP"
            printf 'nameserver %s\n' "$DNS_GOOD"
            printf 'nameserver %s\n' "$DNS_SECOND"
        } > "$TMP_RES"

        if write_if_changed "$RESOLV" "$TMP_RES"; then
            pass 'resolv.conf contains two verified responsive nameservers'
        else
            warn 'Unable to update resolv.conf safely'
            rm -f "$TMP_RES"
        fi
    else
        warn 'resolv.conf is absent or symlinked; DNS configuration was not forcibly replaced'
    fi
else
    fail 'Could not independently establish two responsive DNS servers'
fi

printf '%s\n' '=== HOSTNAME/DNS DOMAIN ==='
HOSTNAME_NOW="$(hostname 2>/dev/null || printf unknown)"
printf 'HOSTNAME=%s\n' "$HOSTNAME_NOW"

if [ -n "$HOSTNAME_NOW" ] && [ "$HOSTNAME_NOW" != unknown ]; then
    if getent hosts "$HOSTNAME_NOW" >/dev/null 2>&1; then
        pass "Hostname resolves: $HOSTNAME_NOW"
    else
        warn "Hostname $HOSTNAME_NOW does not resolve through current resolver"
    fi
else
    warn 'Hostname could not be determined'
fi

printf '%s\n' '=== APACHE ==='
if command -v httpd >/dev/null 2>&1; then
    if httpd -t >/dev/null 2>&1; then
        pass 'Apache configuration syntax valid'
    else
        fail 'Apache configuration syntax invalid'
    fi

    printf '%s\n' '--- APACHE MODULES ---'
    httpd -M 2>&1 | tee "$RUN/apache-modules.txt"

    APACHE_PORTS="$(grep -RhoE '^[[:space:]]*Listen[[:space:]]+[^#]+' "$PREFIX/etc/apache2" 2>/dev/null || true)"
    printf '%s\n' '--- APACHE LISTEN DIRECTIVES ---'
    printf '%s\n' "$APACHE_PORTS"

    if printf '%s\n' "$APACHE_PORTS" | grep -Eq '127\.0\.0\.1:8090|127\.0\.0\.1:8443'; then
        pass 'Apache configuration is bound to loopback ports'
    else
        warn 'Apache loopback binding could not be established from Listen directives'
    fi

    if httpd -M 2>/dev/null | grep -Eq 'reqtimeout_module'; then
        pass 'Apache mod_reqtimeout available'
    else
        warn 'Apache mod_reqtimeout unavailable; Lynis HTTP-6641 cannot be remediated by enabling that module'
    fi

    if httpd -M 2>/dev/null | grep -Eq 'evasive_module'; then
        pass 'Apache mod_evasive available'
    else
        warn 'Apache mod_evasive unavailable; no unsupported installation was attempted'
    fi

    if httpd -M 2>/dev/null | grep -Eq 'security2_module'; then
        pass 'Apache ModSecurity module available'
    else
        warn 'Apache ModSecurity unavailable; no unsupported module installation was attempted'
    fi

    if ps -A -o pid=,ppid=,args= 2>/dev/null | grep -Eq '[[:space:]]httpd[[:space:]]+-k[[:space:]]+start([[:space:]]|$)'; then
        pass 'Apache httpd process independently detected'
    else
        warn 'Apache process not independently detected'
    fi
else
    warn 'Apache executable unavailable'
fi

printf '%s\n' '=== RIGHTSFRAMES INTEGRITY ==='
RF_INTEGRITY=''
for f in \
    "$RF_ROOT/tools/rf-security-audit" \
    "$RF_ROOT/tools/rf-doctor" \
    "$RF_ROOT/tools/rf-supervise" \
    "$RF_ROOT/tools/rf-health-loop" \
    "$RF_ROOT/rf"
do
    [ -f "$f" ] || continue
    RF_INTEGRITY="$RF_INTEGRITY
$f"
done

if [ -n "$RF_INTEGRITY" ]; then
    printf '%s\n' "$RF_INTEGRITY" | sed '/^$/d' | while IFS= read -r f; do
        sha256sum "$f"
    done > "$RUN/rf-critical-sha256.txt"

    if [ -s "$RUN/rf-critical-sha256.txt" ]; then
        pass 'RF critical executable cryptographic baseline generated'
    else
        fail 'RF critical executable baseline generation failed'
    fi
else
    warn 'No expected RF integrity-monitoring executables found at standard paths'
fi

printf '%s\n' '=== RF SECURITY AUDIT ==='
if command -v rf-security-audit >/dev/null 2>&1; then
    if rf-security-audit 2>&1 | tee "$RUN/rf-security-audit.txt"; then
        pass 'rf-security-audit completed successfully'
    else
        fail 'rf-security-audit reported failure'
    fi
elif [ -x "$RF_ROOT/tools/rf-security-audit" ]; then
    if "$RF_ROOT/tools/rf-security-audit" 2>&1 | tee "$RUN/rf-security-audit.txt"; then
        pass 'RF security audit completed successfully'
    else
        fail 'RF security audit reported failure'
    fi
else
    warn 'rf-security-audit executable not found'
fi

printf '%s\n' '=== PACKAGE AUDIT ==='
if command -v pkg >/dev/null 2>&1; then
    pkg list-installed > "$RUN/termux-packages.txt" 2>&1 || true
    if pkg search lynis 2>&1 | grep -qi '^lynis'; then
        pass 'Termux package repository exposes Lynis'
    else
        warn 'Lynis is not provided by the configured Termux package search'
    fi
fi

printf '%s\n' '=== MALWARE/ROOTKIT CONTROL ==='
for tool in rkhunter chkrootkit clamscan; do
    if command -v "$tool" >/dev/null 2>&1; then
        pass "$tool available"
    fi
done

if command -v rkhunter >/dev/null 2>&1 ||
   command -v chkrootkit >/dev/null 2>&1 ||
   command -v clamscan >/dev/null 2>&1; then
    pass 'A malware/rootkit scanning capability is available'
else
    warn 'No compatible malware/rootkit scanner available in current Termux environment; no unsupported Linux scanner was installed'
fi

printf '%s\n' '=== PRoot UBUNTU ==='
if command -v proot-distro >/dev/null 2>&1; then
    if proot-distro list 2>&1 | grep -Eq '^[[:space:]]*\*[[:space:]]+ubuntu[[:space:]]*$'; then
        if proot-distro login ubuntu -- /bin/bash -lc '
            set -eu
            test "$(id -u)" = 0
            test "$(uname -m)" = aarch64
            . /etc/os-release
            test "$ID" = ubuntu
            test -n "$VERSION_ID"
            t=$(mktemp -d)
            test -d "$t"
            rmdir "$t"
        ' >/dev/null 2>&1; then
            pass 'Existing Ubuntu PRoot container passes identity, architecture and writable-TMP checks'
        else
            fail 'Existing Ubuntu PRoot verification failed'
        fi
    else
        fail 'Expected existing Ubuntu PRoot container was not detected'
    fi
else
    fail 'proot-distro unavailable'
fi

printf '%s\n' '=== LYNIS BASELINE ==='
LYNIS_DIR="$RF_ROOT/tools/lynis-download/lynis-master"
if [ -x "$LYNIS_DIR/lynis" ]; then
    LYNIS_OUT="$RUN/lynis-post-hardening.out"
    if proot -b "$PREFIX/tmp:/tmp" "$LYNIS_DIR/lynis" audit system --quick --no-colors > "$LYNIS_OUT" 2>&1; then
        LYNIS_RC=0
    else
        LYNIS_RC=$?
    fi

    printf 'LYNIS_EXIT=%s\n' "$LYNIS_RC"

    if [ "$LYNIS_RC" -eq 0 ]; then
        pass 'Lynis completed with exit code 0'
    else
        fail "Lynis returned exit code $LYNIS_RC"
    fi

    grep -E 'Warnings \(|Suggestions \(|Hardening index|Tests performed|Plugins enabled' "$LYNIS_OUT" || true

    if grep -Eiq 'segmentation fault|SIGSEGV|fatal error' "$LYNIS_OUT"; then
        fail 'Lynis output contains crash/fatal-error evidence'
    else
        pass 'No crash/fatal-error signature found in Lynis output'
    fi
else
    fail "Lynis executable not found at $LYNIS_DIR/lynis"
fi

printf '%s\n' '=== FINAL ASSURANCE ==='
printf 'PASS=%s\n' "$PASS"
printf 'FAIL=%s\n' "$FAIL"
printf 'WARN=%s\n' "$WARN"
printf 'CHANGES=%s\n' "$CHANGES"
printf 'EVIDENCE_DIR=%s\n' "$RUN"

if [ "$FAIL" -eq 0 ]; then
    printf '%s\n' 'FINAL_LYNIS_HARDENING_ASSURANCE=PASS_WITH_PLATFORM_LIMITATIONS'
    exit 0
else
    printf '%s\n' 'FINAL_LYNIS_HARDENING_ASSURANCE=FAIL'
    exit 1
fi
