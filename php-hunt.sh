#!/usr/bin/env bash
# php-hunt — read-only hunt for PHP exploitation signs on Apache + PHP servers.
# One self-contained script: log analysis (phphunt.py) + on-host checks (postex.sh).
# Always runs the log scan first, then asks whether to run the host checks.
# Unix only: Linux (Debian/RHEL/SUSE/Alpine) and macOS. For Windows (Apache, XAMPP,
# WAMP, Laragon, Bitnami, IIS) use the native PowerShell port php-hunt.ps1 instead.
#
# One-liners:
#   curl -fsSL https://raw.githubusercontent.com/ChriZzn/phphunt/main/php-hunt.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/ChriZzn/phphunt/main/php-hunt.sh | sudo bash -s -- --postex
#   sudo bash php-hunt.sh --since 2026-10-01
#
# Read-only: prints a report and changes nothing on the system. It writes only
# inside its own mktemp -d directory (a reference timestamp and one file index
# per webroot) and removes that directory on exit, including on Ctrl-C.
export LC_ALL=C

VERSION="1.0"

# ---------------- defaults / options ----------------
NOPOSTEX=""; FORCE_POSTEX=""; ONLYPOSTEX=""; SINCE_IN=""; WEBUSER_FORCE=""; TUS=""; QUIET=""; RECENTLOGS=""
LOGDIRS=(); WEBROOTS=()

usage() {
cat <<'EOF'
php-hunt — read-only hunt for PHP exploitation signs on Apache + PHP servers.
Combines log analysis (phphunt.py) and on-host checks (postex.sh) in one script.
It always runs the log scan first, then asks whether to run the host checks.
Linux and macOS only — on Windows use the native PowerShell port php-hunt.ps1.

Usage:
  sudo bash php-hunt.sh [options]
  curl -fsSL https://raw.githubusercontent.com/ChriZzn/phphunt/main/php-hunt.sh | sudo bash

Options:
  --logdir DIR      Apache log directory (auto-detected by default; repeatable)
  --webroot DIR     webroot directory (auto-detected by default; repeatable)
  --webuser USER    web server user (alias: --user; auto-detected: www-data / apache / httpd / _www)
  --since DATE      flag files changed since YYYY-MM-DD (default: last 7 days)
  --trusted-ua S    user-agent substring to exclude from POST/UA sections (repeatable)
  --postex          run the host checks without asking
  --no-postex       skip the host checks (do not ask)
  --only-postex     skip the log scan, run only the host checks
  --recent-logs     only read log files modified since --since (skips old
                    rotations; much faster, but sections 9/10 lose history)
  -q, --quiet       no progress output on stderr (the report is unchanged)
  -h, --help        this help

The prompt is read from /dev/tty, so it still works through the pipe. Without a
terminal the host checks are skipped unless forced with --postex/--only-postex or
RUN_POSTEX=yes (or skipped with --no-postex / RUN_POSTEX=no).

Read-only: prints a report. Writes only inside its own temp dir, removed on exit.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --logdir)    [ $# -ge 2 ] || { echo "missing value for $1" >&2; exit 1; }; LOGDIRS+=("$2"); shift 2 ;;
    --webroot)   [ $# -ge 2 ] || { echo "missing value for $1" >&2; exit 1; }; WEBROOTS+=("$2"); shift 2 ;;
    --webuser|--user) [ $# -ge 2 ] || { echo "missing value for $1" >&2; exit 1; }; WEBUSER_FORCE="$2"; shift 2 ;;
    --since)     [ $# -ge 2 ] || { echo "missing value for $1" >&2; exit 1; }; SINCE_IN="$2"; shift 2 ;;
    --trusted-ua) [ $# -ge 2 ] || { echo "missing value for $1" >&2; exit 1; }; TUS="${TUS:+$TUS$'\001'}$2"; shift 2 ;;
    --postex)      FORCE_POSTEX=1; shift ;;
    --no-postex|--no-host) NOPOSTEX=1; shift ;;
    --only-postex|--no-logs) ONLYPOSTEX=1; shift ;;
    --recent-logs) RECENTLOGS=1; shift ;;
    -q|--quiet)  QUIET=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ---------------- environment detection ----------------
UNAME_S=$(uname -s 2>/dev/null || echo unknown)
OS="other"; WSL=""
case "$UNAME_S" in
  Darwin)  OS=macos ;;
  Linux)   OS=linux; grep -qiE 'microsoft|WSL' /proc/version 2>/dev/null && WSL=1 ;;
  MINGW*|MSYS*|CYGWIN*|INTERIX)
    echo "This is the Unix script. On Windows run the native PowerShell port instead:" >&2
    echo "  powershell -ExecutionPolicy Bypass -File php-hunt.ps1" >&2
    exit 1 ;;
esac

GNUFIND=0; GNUPS=0
find /dev/null -maxdepth 0 -printf '' >/dev/null 2>&1 && GNUFIND=1   # -printf is what we use
ps --version >/dev/null 2>&1     && GNUPS=1

# stat flavour, probed separately from find: busybox has GNU-style "stat -c" but
# no "find --version" and no "find -printf", so the two cannot be inferred
# from one another (this is what used to break the file listing on Alpine).
STATMODE=none
if stat -c '%Y' . >/dev/null 2>&1;  then STATMODE=gnu     # GNU coreutils / busybox
elif stat -f '%m' . >/dev/null 2>&1; then STATMODE=bsd    # macOS / *BSD
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/phphunt.XXXXXX") || { echo "cannot create temp dir" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM HUP

# Format an epoch as "<YYYY-MM-DD> <YYYYMMDDHHMM>". GNU and busybox take
# "-d @SECS"; BSD takes "-r SECS"; neither accepts the other's form.
fmt_epoch() {
  date -d "@$1" '+%F %Y%m%d%H%M' 2>/dev/null && return 0
  date -r "$1"  '+%F %Y%m%d%H%M' 2>/dev/null && return 0
  return 1
}

# reference timestamp: files newer than this are "changed since SINCE"
if [ -n "$SINCE_IN" ]; then
  SINCE="$SINCE_IN"
  STAMP=$(printf '%s' "$SINCE_IN" | tr -d '-')
  case ${#STAMP} in 8) STAMP="${STAMP}0000";; 12) :;; *) STAMP="${STAMP}00";; esac
else
  NOW_EPOCH=$(date +%s 2>/dev/null)
  case "$NOW_EPOCH" in
    ''|*[!0-9]*) echo "cannot read the clock; pass --since YYYY-MM-DD" >&2; exit 1 ;;
  esac
  # shellcheck disable=SC2046  # the two fields are meant to be split
  set -- $(fmt_epoch $((NOW_EPOCH - 7 * 86400)))
  SINCE="$1"; STAMP="$2"
  if [ -z "$STAMP" ]; then
    echo "cannot compute the default 7-day window on this system; pass --since YYYY-MM-DD" >&2
    exit 1
  fi
fi
REF="$TMP/ref.ts"
touch -t "$STAMP" "$REF" 2>/dev/null || {
  if [ -n "$SINCE_IN" ]; then echo "bad --since value: $SINCE_IN (use YYYY-MM-DD)" >&2
  else echo "cannot create the reference timestamp in $TMP" >&2; fi
  exit 1; }
# epoch of the window start, for the index-based checks below
SINCE_EPOCH=$(if [ "$STATMODE" = gnu ]; then stat -c '%Y' "$REF"; else stat -f '%m' "$REF"; fi 2>/dev/null)
case "$SINCE_EPOCH" in ''|*[!0-9]*) SINCE_EPOCH=0 ;; esac

# web server user
WEBUSER=""
if [ -n "$WEBUSER_FORCE" ]; then WEBUSER="$WEBUSER_FORCE"
else
  for u in www-data apache httpd _www nginx; do id "$u" >/dev/null 2>&1 && WEBUSER="$u" && break; done
fi

# ---------------- candidate paths ----------------
add_dirs() { local p; for p in "$@"; do [ -d "$p" ] && LOGDIRS+=("$p"); done; }
add_rdirs() { local p; for p in "$@"; do [ -d "$p" ] && WEBROOTS+=("$p"); done; }

CAND_LOG=(); CAND_ROOT=()
case "$OS" in
  linux)
    CAND_LOG=(/var/log/apache2 /var/log/httpd /usr/local/apache2/logs /etc/httpd/logs /var/log/nginx)
    CAND_ROOT=(/var/www /var/www/html /srv/www /srv/http /usr/share/nginx/html)
    ;;
  macos)
    CAND_LOG=(/usr/local/var/log/httpd /opt/homebrew/var/log/httpd /var/log/apache2)
    CAND_ROOT=(/Library/WebServer/Documents /usr/local/var/www /opt/homebrew/var/www)
    ;;
esac

# Auto-detect only when the user supplied nothing. The count has to be taken
# before the loop: add_dirs appends to the very array the guard tests, so a
# per-iteration check stops after the first candidate that exists.
[ ${#LOGDIRS[@]}  -gt 0 ] || add_dirs  "${CAND_LOG[@]}"
[ ${#WEBROOTS[@]} -gt 0 ] || add_rdirs "${CAND_ROOT[@]}"

# ---------------- helpers ----------------
sec() { echo; echo "=== $* ==="; }
# progress: transient status on stderr so the report (stdout) stays clean.
# On a terminal it rewrites one line in place; otherwise it prints plain lines.
PROG_TTY=0; [ -t 2 ] && PROG_TTY=1
progress() {
  [ "$QUIET" = 1 ] && return
  if [ "$PROG_TTY" = 1 ]; then printf '\r\033[K%s' "$1" >&2
  else printf '%s\n' "$1" >&2; fi
}
progress_done() { [ "$QUIET" = 1 ] && return; [ "$PROG_TTY" = 1 ] && printf '\r\033[K' >&2; }
fsize() { du -h "$1" 2>/dev/null | cut -f1; }   # human size, best-effort
readlog() {
  case "$1" in
    *.gz)        gzip  -cd "$1" 2>/dev/null ;;
    *.bz2)       bzip2 -cd "$1" 2>/dev/null ;;
    *.xz)        xz    -cd "$1" 2>/dev/null ;;
    *.zst)       zstd  -cd "$1" 2>/dev/null ;;
    *)           cat       "$1" 2>/dev/null ;;
  esac
}
# ---------------- webroot index ----------------
# ONE traversal per webroot. Every file-based host check reads this index
# instead of walking the tree again (sections 11-14 and 20-21 used to do a
# separate full walk each: seven per root).
# Format, tab separated: <mtime-epoch> <user>:<group> <path>
TAB=$(printf '\t')
INDEX_MAX=400000
PHPEXT_RX='\.([Pp][Hh][Pp][3-8s]?|[Pp][Hh][Tt][Mm][Ll]|[Pp][Hh][Aa][Rr]|[Ii][Nn][Cc])$|/\.htaccess$|/\.user\.ini$'
IMGEXT_RX='\.([Jj][Pp][Ee]?[Gg]|[Pp][Nn][Gg]|[Gg][Ii][Ff]|[Ii][Cc][Oo]|[Bb][Mm][Pp]|[Ww][Ee][Bb][Pp]|[Tt][Xx][Tt])$'
# A PHP extension that is not the final one: avatar.php.jpg
DBLEXT_RX='\.([Pp][Hh][Pp][3-8s]?|[Pp][Hh][Tt][Mm][Ll]|[Pp][Hh][Aa][Rr])\.[^./]+$'

NEWER_MIN="$SINCE_EPOCH"; MTIME_OK=1
if [ "$GNUFIND" != 1 ] && [ "$STATMODE" = none ]; then MTIME_OK=0; NEWER_MIN=1; fi

build_index() { # $1 root, $2 outfile
  { if   [ "$GNUFIND" = 1 ];    then find "$1" -xdev -type f -printf "%T@\t%u:%g\t%p\n" 2>/dev/null
    elif [ "$STATMODE" = gnu ]; then find "$1" -xdev -type f -exec stat -c "%Y${TAB}%U:%G${TAB}%n" {} + 2>/dev/null
    elif [ "$STATMODE" = bsd ]; then find "$1" -xdev -type f -exec stat -f "%m${TAB}%Su:%Sg${TAB}%N" {} + 2>/dev/null
    else   # no -printf and no stat: fall back to find -newer (POSIX) as a flag
      find "$1" -xdev -type f -newer "$REF"   2>/dev/null | sed "s|^|1${TAB}?:?${TAB}|"
      find "$1" -xdev -type f ! -newer "$REF" 2>/dev/null | sed "s|^|0${TAB}?:?${TAB}|"
    fi
  } | head -n "$INDEX_MAX" > "$2"
}

# "YYYY-MM-DD HH:MM" for one epoch; only ever called for displayed rows.
fmt_epoch_min() {
  date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null && return 0
  date -r "$1"  '+%Y-%m-%d %H:%M' 2>/dev/null && return 0
  echo '????-??-?? ??:??'
}
# stdin: "<epoch>\t<owner>\t<path>" -> "<date>  <owner>  <path>"
fmt_rows() {
  while IFS="$TAB" read -r e o pth; do
    if [ "$MTIME_OK" = 1 ]; then printf '%s  %s  %s\n' "$(fmt_epoch_min "${e%%.*}")" "$o" "$pth"
    else                         printf '%s  %s  %s\n' "(mtime n/a)"                 "$o" "$pth"; fi
  done
}

idx_changed()  { awk -F"$TAB" -v min="$NEWER_MIN" -v rx="$PHPEXT_RX" '$1+0 >= min && $3 ~ rx' "$1"; }
idx_php()      { awk -F"$TAB" -v rx="$PHPEXT_RX" '$3 ~ rx {print $3}' "$1"; }
idx_owned()    { awk -F"$TAB" -v u="$2" -v rx="$PHPEXT_RX" '$3 ~ rx { split($2,o,":"); if (o[1]==u) print $3 }' "$1"; }
idx_dblext()   { awk -F"$TAB" -v rx="$DBLEXT_RX" '$3 ~ rx' "$1"; }
idx_newimg()   { awk -F"$TAB" -v min="$NEWER_MIN" -v rx="$IMGEXT_RX" '$1+0 >= min && $3 ~ rx {print $3}' "$1"; }
# PHP files under upload/cache/tmp/image-ish directories. Matched on the path
# BELOW the webroot, so a webroot that itself lives in /srv/tmp is not all hits.
idx_uploadish() {
  awk -F"$TAB" -v rl="${#2}" -v rx="$PHPEXT_RX" '
    $3 ~ rx { rel = substr($3, rl + 1)
      if (rel ~ /\/(uploads?|cache|tmp|temp|images?|img|media|files|assets|avatars?|attachments?)\//) print $3 }' "$1"
}

# ---------------- content scans ----------------
# POSIX character classes instead of the GNU \s shorthand, and -a so that a
# shell hidden in a binary-looking file is still matched (grep -I skipped those).
WEBSHELL_RX='eval[[:space:]]*\([[:space:]]*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|gzuncompress|str_rot13)|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST)|(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|preg_replace[[:space:]]*\(.*/e[^a-z]|create_function[[:space:]]*\([[:space:]]*.?.?,|\$_(GET|POST|REQUEST|COOKIE)\[[^]]+\][[:space:]]*\('
RECON_RX='/dev/tcp/|fsockopen[[:space:]]*\(|proc_open[[:space:]]*\(|pcntl_exec[[:space:]]*\(|169\.254\.169\.254|aws/credentials|kubernetes\.io/serviceaccount|/etc/shadow'

# stdin: NUL-free list of paths, one per line -> files whose content matches $1
grep_list() { # $1 = ERE, $2 = max hits
  tr '\n' '\0' | xargs -0 -r grep -laE "$1" 2>/dev/null | head -"$2"
}

webshell_scan()   { idx_php      "$1"      | head -20000 | grep_list "$WEBSHELL_RX" 10; }
recon_strings()   { idx_changed  "$1" | awk -F"$TAB" '{print $3}' | head -5000 | grep_list "$RECON_RX" 15; }
dblext_polyglot() { # $1 index
  { idx_dblext "$1" | awk -F"$TAB" '{print $3}' | head -15
    idx_newimg "$1" | head -2000 | grep_list '<\?php|<\?=' 10
  } | awk '!seen[$0]++'
}

# ---- PHP version check: php2shell (CVE-2026-109618 / CVE-2026-109619) ----
assess_php() { # $1 = x.y.z -> verdict
  local v="${1:-}" maj min pat rest fix
  maj="${v%%.*}"; rest="${v#*.}"; min="${rest%%.*}"; pat="${v##*.}"
  case "$maj$min$pat" in *[!0-9]*|'') echo "could not parse '$v'"; return;; esac
  case "$maj.$min" in
    8.5) fix=12 ;; 8.4) fix=27 ;; 8.3) fix=36 ;; 8.2) fix=35 ;; *) fix="" ;;
  esac
  if [ -n "$fix" ]; then
    if [ "$pat" -lt "$fix" ]; then echo "VULNERABLE — $v < $maj.$min.$fix (update PHP)"
    else echo "patched ($v >= $maj.$min.$fix)"; fi
    return
  fi
  if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -le 1 ]; }; then
    echo "EOL branch $maj.$min — no mainline fix; needs a distro backport. TREAT AS VULNERABLE unless backported"
    return
  fi
  echo "branch $maj.$min newer than the advisory — assume patched, but verify"
}
php_version_check() {
  sec "0. PHP version vs php2shell fixes (CVE-2026-109618 / CVE-2026-109619)"
  local any=0 bin v seen=" " libs
  for bin in php php8.5 php8.4 php8.3 php8.2 php8.1 php7.4 php-cgi php-fpm \
             php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm7.4 lsphp frankenphp; do
    command -v "$bin" >/dev/null 2>&1 || continue
    v=$("$bin" -n -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$v" ] || v=$("$bin" -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$v" ] || continue
    case "$seen" in *" $v "*) continue ;; esac   # de-dupe by version
    seen="$seen$v "; any=1
    printf '  %-10s %-10s %s\n' "$bin" "$v" "$(assess_php "$v")"
  done
  libs=$(ls /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
            /etc/httpd/modules/libphp*.so 2>/dev/null)
  if [ -n "$libs" ]; then
    any=1
    echo "  mod_php module(s) present (version = what it was built against; check your live SAPI):"
    printf '%s\n' "$libs" | sed 's/^/    /'
  fi
  command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}\n' 'php*' 2>/dev/null \
    | awk -F'|' '$1 ~ /^i/ {print "  pkg " $2 " " $3}' | head -12
  command -v rpm  >/dev/null 2>&1 && rpm -qa 'php*'  2>/dev/null | sed 's/^/  pkg /' | head -12
  [ "$any" = 0 ] && echo "  (no PHP binary on PATH — if PHP runs only as an Apache module, check the package version)"
  echo "  fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 8.1 and older are EOL. mod_php is the highest-risk SAPI."
}

# ---------------- report header ----------------
DISTRO=""
[ -r /etc/os-release ] && DISTRO=$(. /etc/os-release && echo "$PRETTY_NAME" 2>/dev/null)
echo "phphunt v$VERSION — read-only PHP exploitation hunt"
echo "  host: $(hostname 2>/dev/null || echo '?')   date: $(date 2>/dev/null)"
echo "  platform: $OS${DISTRO:+ ($DISTRO)}${WSL:+ (WSL — Linux side only; use php-hunt.ps1 for the Windows stacks)}"
echo "  file window: since $SINCE   web user: ${WEBUSER:-(n/a — pass --user)}"
echo "  log dirs: $( [ ${#LOGDIRS[@]} -gt 0 ] && printf '%s ' "${LOGDIRS[@]}" || echo '(none found — pass --logdir)')"
echo "  webroots: $( [ ${#WEBROOTS[@]} -gt 0 ] && printf '%s ' "${WEBROOTS[@]}" || echo '(none found — pass --webroot)')"
if [ "$(id -u 2>/dev/null)" != 0 ]; then
  echo "  NOTE: not running as root — many checks will miss data. Try: sudo bash php-hunt.sh"
fi

php_version_check   # always — the primary php2shell signal, fast and read-only

# ================= PART A: log analysis =================
if [ "$ONLYPOSTEX" != 1 ]; then

ACCESS=(); ERRORS=()
for d in "${LOGDIRS[@]}"; do
  for f in "$d"/*access*log*; do
    [ -f "$f" ] || continue
    [ "$RECENTLOGS" = 1 ] && [ ! "$f" -nt "$REF" ] && continue
    ACCESS+=("$f")
  done
  for f in "$d"/*error*log*; do
    [ -f "$f" ] || continue
    [ "$RECENTLOGS" = 1 ] && [ ! "$f" -nt "$REF" ] && continue
    ERRORS+=("$f")
  done
done

progress "[logs] parsing ${#ACCESS[@]} access + ${#ERRORS[@]} error files (large logs can take a while)…"
: > "$TMP/err"
ne=${#ERRORS[@]}; ie=0
for f in "${ERRORS[@]}"; do
  ie=$((ie+1)); progress "[logs] error log $ie/$ne: ${f##*/} ($(fsize "$f"))"
  [ -r "$f" ] || { progress_done; echo "  !! cannot read $f"; continue; }
  readlog "$f" | awk -v F="${f##*/}" '
    function mnum(s) { return int((index("jan feb mar apr may jun jul aug sep oct nov dec", tolower(s)) + 3) / 4) }
    # Normalise every timestamp flavour to a sortable YYYY-MM-DD:
    #   22/Oct/2026            Apache access log
    #   22-Oct-2026 10:00 UTC  PHP error_log / php-fpm
    #   Wed Oct 22 ... 2026    Apache error log (year at the end)
    #   Oct 22                 Apache error log without a year
    #   2026-10-22             ISO
    function daykey(s,  a, mo, D, M, Y) {
      D = "[0-9][0-9]?"; M = "[A-Za-z][A-Za-z][A-Za-z]"; Y = "[0-9][0-9][0-9][0-9]"
      if (match(s, "^" D "[/-]" M "[/-]" Y)) {
        split(substr(s, RSTART, RLENGTH), a, /[\/-]/); mo = mnum(a[2])
        if (mo > 0) return sprintf("%04d-%02d-%02d", a[3], mo, a[1])
      }
      if (match(s, "^" Y "-[0-9][0-9]-[0-9][0-9]")) return substr(s, RSTART, 10)
      if (match(s, "^" M " +" M " +" D " +[0-9:.]+ +" Y)) {
        split(substr(s, RSTART, RLENGTH), a, / +/); mo = mnum(a[2])
        if (mo > 0) return sprintf("%04d-%02d-%02d", a[5], mo, a[3])
      }
      if (match(s, "^" M " +" D)) {
        split(substr(s, RSTART, RLENGTH), a, / +/); mo = mnum(a[1])
        if (mo > 0) return sprintf("0000-%02d-%02d", mo, a[2])
      }
      return "?"
    }
    function daykeyc(s,  k) {
      k = substr(s, 1, 11) SUBSEP substr(s, length(s) - 3, 4)
      if (k in DKC) return DKC[k]
      DKC[k] = daykey(s)
      return DKC[k]
    }
    { sub(/\r$/,""); l=tolower($0)
      i=index($0,"["); day="?"
      if (i>0) { j=index($0,"]"); if (j>i) day=daykeyc(substr($0,i+1,j-i-1)) }
      if (l ~ /exit signal|segmentation fault|segfault|aborted|core dump|zend_mm_heap corrupted|heap corrupt|double free|stack smashing|out of memory|possible integer overflow|cannot allocate memory|ah00052|ah00051/) {
        ct++
        if (cn<20) { cn++; line=$0; if (length(line)>260) line=substr(line,1,260); cs[cn]=line }
      }
      if (l ~ /input variables exceeded|post content-length|missing boundary|multipart|request body limit|allowed memory size|maximum execution time|unable to allocate|file created in the system|max_file_uploads|invalid argument supplied for foreach\(\) in unknown/) {
        et++
        if (en<15) { en++; line=$0; if (length(line)>260) line=substr(line,1,260); es[en]=line }
      }
      if (match(l, /php (fatal error|parse error|warning|notice|deprecated|catchable)[^:]*:/)) {
        msg=substr($0, RSTART, 160); gsub(/[0-9]+/,"N",msg); pc[msg]++
        if (day!="?") pd[day]++
      }
    }
    END{
      print "CRASHN|" ct+0
      for (i=1;i<=cn;i++) print "CRASHS|" F "|" cs[i]
      print "ENGN|" et+0
      for (i=1;i<=en;i++) print "ENGS|" F "|" es[i]
      for (msg in pc) print "PERR|" pc[msg] "|" msg
      for (d in pd) print "PERRDAY|" d "|" pd[d]
    }' >> "$TMP/err"
done

: > "$TMP/acc"
na=${#ACCESS[@]}; ia=0
for f in "${ACCESS[@]}"; do
  ia=$((ia+1)); progress "[logs] access log $ia/$na: ${f##*/} ($(fsize "$f"))"
  [ -r "$f" ] || { progress_done; echo "  !! cannot read $f"; continue; }
  readlog "$f" | awk -v F="${f##*/}" -v TUS="$TUS" -v tty="$PROG_TTY" -v quiet="${QUIET:-0}" -v tag="$ia/$na" '
    (tty==1 && quiet!=1 && NR % 500000 == 0){ printf "\r\033[K  [logs] access log %s: %s: %d lines…", tag, F, NR > "/dev/stderr" }
    function mnum(s) { return int((index("jan feb mar apr may jun jul aug sep oct nov dec", tolower(s)) + 3) / 4) }
    # Normalise every timestamp flavour to a sortable YYYY-MM-DD:
    #   22/Oct/2026            Apache access log
    #   22-Oct-2026 10:00 UTC  PHP error_log / php-fpm
    #   Wed Oct 22 ... 2026    Apache error log (year at the end)
    #   Oct 22                 Apache error log without a year
    #   2026-10-22             ISO
    function daykey(s,  a, mo, D, M, Y) {
      D = "[0-9][0-9]?"; M = "[A-Za-z][A-Za-z][A-Za-z]"; Y = "[0-9][0-9][0-9][0-9]"
      if (match(s, "^" D "[/-]" M "[/-]" Y)) {
        split(substr(s, RSTART, RLENGTH), a, /[\/-]/); mo = mnum(a[2])
        if (mo > 0) return sprintf("%04d-%02d-%02d", a[3], mo, a[1])
      }
      if (match(s, "^" Y "-[0-9][0-9]-[0-9][0-9]")) return substr(s, RSTART, 10)
      if (match(s, "^" M " +" M " +" D " +[0-9:.]+ +" Y)) {
        split(substr(s, RSTART, RLENGTH), a, / +/); mo = mnum(a[2])
        if (mo > 0) return sprintf("%04d-%02d-%02d", a[5], mo, a[3])
      }
      if (match(s, "^" M " +" D)) {
        split(substr(s, RSTART, RLENGTH), a, / +/); mo = mnum(a[1])
        if (mo > 0) return sprintf("0000-%02d-%02d", mo, a[2])
      }
      return "?"
    }
    function daykeyc(s,  k) {
      k = substr(s, 1, 11) SUBSEP substr(s, length(s) - 3, 4)
      if (k in DKC) return DKC[k]
      DKC[k] = daykey(s)
      return DKC[k]
    }
    BEGIN{
      CAP=200000; SCAP=5000      # key caps: unbounded counters are how awk gets OOM-killed
      np=0
      np++; nm[np]="php ini injection (allow_url_include/auto_prepend/-d)"; P[np]="allow_url_include|auto_prepend_file|auto_append_file|%2dd\\+|(\\?|&)-d[+ %]|\\?-[sdn]([^a-z0-9]|$)"
      np++; nm[np]="soft-hyphen arg injection (CVE-2024-4577 style %AD)"; P[np]="%ad"
      np++; nm[np]="php:// / data:// / expect:// / phar:// wrappers"; P[np]="php(%3a|:)(%2f|/)(%2f|/)|data(%3a|:)(%2f|/)*text|expect(%3a|:)|phar(%3a|:)"
      np++; nm[np]="php-cgi / cgi-bin probing"; P[np]="/cgi-bin/|php-cgi|php5?\\.cgi"
      np++; nm[np]="phpunit eval-stdin / known PHP RCE paths"; P[np]="eval-stdin|invokefunction|call_user_func|_ignition|think\\\\app|vendor/phpunit"
      np++; nm[np]="code in URL (system/exec/base64/<?php)"; P[np]="(<|%3c)\\?php|base64_decode|shell_exec|passthru|(^|[^a-z0-9_])system\\(|(^|[^a-z0-9_])exec\\(|assert\\(|phpinfo|die\\(|md5\\("
      np++; nm[np]="security scanner fingerprints (watchTowr/calif/php2shell; CVE-2026-109618/109619 has no public request signature)"; P[np]="php2shell|calif\\.io|watchtowr|nuclei|projectdiscovery"
      np++; nm[np]="path traversal"; P[np]="\\.\\./|%2e%2e"
      np++; nm[np]="xdebug / php debug triggers"; P[np]="xdebug_session|xdebug_trigger|xdebug_profile"
      # One combined pattern as a gate: an ordinary log line then costs a
      # single regex match instead of one per pattern (2x faster overall).
      PRE=""
      for (i=1;i<=np;i++) PRE = PRE (i>1 ? "|" : "") P[i]
      nt=split(TUS, T, "\001")
      for (i=1;i<=nt;i++) T[i]=tolower(T[i])
    }
    function istrusted(s,  i){ for(i=1;i<=nt;i++) if(index(s,T[i])) return 1; return 0 }
    { sub(/\r$/,"")
      n=split($0, q, "\"")
      if (n<2) next
      pre=q[1]; req=q[2]; ua=(n>=7)?q[6]:""
      st=0
      if (n>=3) { m=split(q[3], s, " "); st=s[1]+0 }
      i=index(pre,"["); j=index(pre,"]")
      ts=(i>0 && j>i)? substr(pre,i+1,j-i-1) : ""
      c=index(ts,":"); day=daykeyc((c>1)? substr(ts,1,c-1) : ts)
      m=split(pre, t, " ")
      host="?"; ip=""
      if (m>=2 && t[2] ~ /[0-9]/) { ip=t[2]; host=t[1] }
      else if (m>=1 && t[1] ~ /[0-9]/) { ip=t[1] }
      if (host=="?") host="-"   # no vhost in this log format
      tot[day]++
      psplit=split(req, r, " ")
      meth=(psplit>0)? r[1] : ""
      path=(psplit>1)? r[2] : req
      sp=index(path,"?"); if (sp>0) path=substr(path,1,sp-1)
      # Collapse digit runs in the counter key. /orders/12345/ would otherwise
      # mint one key per request: 3M unique paths cost ~940MB of awk memory.
      pk=path
      if (path ~ /[0-9]/) {            # collapse wholly-numeric path segments
        gsub(/\/[0-9]+\//, "/N/", pk); gsub(/\/[0-9]+\//, "/N/", pk); sub(/\/[0-9]+$/, "/N", pk)
      }
      if (length(pk)>200) pk=substr(pk,1,200)
      lreq=tolower(req); lua=tolower(ua)
      if (st>=500) { e5[day]++; k5=host "\t" pk "\t" st
        if ((k5 in c5) || n5<CAP) { if (!(k5 in c5)) n5++; c5[k5]++ } else o5++ }
      if (meth=="POST") { post[day]++
        if (!istrusted(lua)) { kp=host "\t" pk "\t" st
          if ((kp in cp) || ncp<CAP) { if (!(kp in cp)) ncp++; cp[kp]++ } else ocp++ } }
      if (meth!="" && meth!="GET" && meth!="POST" && meth!="HEAD" && meth!="OPTIONS" && meth!="PUT" && meth!="DELETE" && meth!="PATCH") {
        mk=(length(meth)>20)? substr(meth,1,20) : meth
        if ((mk in od) || nod<SCAP) { if (!(mk in od)) nod++; od[mk]++ }
        if (nb<8) { nb++; print "BADREQ|" $0 }
      }
      if (lreq ~ PRE || lua ~ PRE)
      for (k=1;k<=np;k++) {
        if (lreq ~ P[k] || lua ~ P[k]) {
          it[k]++; if (st>=200 && st<300) i2[k]++
          kd=k SUBSEP day; idc[kd]++
          if (ip!="") { ki=k SUBSEP ip; if ((ki in ipc) || nip<200000) { if (!(ki in ipc)) nip++; ipc[ki]++ } }
          if (ic[k]<6) { ic[k]++; line=$0; if (length(line)>240) line=substr(line,1,240); print "IOCSAMPLE|" nm[k] "|" line }
        }
      }
      if (lua ~ /php/ && !istrusted(lua)) { uk=substr(lua,1,90)
        if ((uk in up) || nup<SCAP) { if (!(uk in up)) nup++; up[uk]++ } }
    }
    END{
      for (d in tot)  print "TRAFFIC|" d "|" tot[d]+0 "|" post[d]+0 "|" e5[d]+0
      for (k in c5)   print "PATH5|" k "|" c5[k]
      for (k in cp)   print "PATHPOST|" k "|" cp[k]
      for (k in od)   print "METHOD|" k "|" od[k]
      for (k in up)   print "UAPHP|" k "|" up[k]
      # single pass over ipc, keeping only the best five per pattern
      for (x in ipc) {
        split(x, kk, SUBSEP); k=kk[1]+0; c=ipc[x]
        for (j=1;j<=5;j++) {
          if (c > t5c[k,j]) {
            for (jj=5; jj>j; jj--) { t5c[k,jj]=t5c[k,jj-1]; t5i[k,jj]=t5i[k,jj-1] }
            t5c[k,j]=c; t5i[k,j]=kk[2]; break
          }
        }
      }
      for (k=1;k<=np;k++) if (it[k]>0) {
        print "IOC|" k "|" nm[k] "|" it[k] "|" i2[k]+0
        for (x in idc) { split(x, kk, SUBSEP); if (kk[1]==k) print "IOCDAY|" nm[k] "|" kk[2] "|" idc[x] }
        for (j=1;j<=5;j++) if (t5c[k,j]>0) print "IOCIP|" nm[k] "|" t5i[k,j] "|" t5c[k,j]
      }
      if (o5>0)  print "CAPPED|5xx paths|" o5
      if (ocp>0) print "CAPPED|POST paths|" ocp
    }' >> "$TMP/acc"
done
progress_done

echo; echo "---- part A: logs (${#ACCESS[@]} access, ${#ERRORS[@]} error files) ----"

# 1. crashes
sec "1. WORKER CRASHES (segfault/abort/heap corruption)"
echo "  total: $(awk -F'|' '$1=="CRASHN"{s+=$2}END{print s+0}' "$TMP/err")"
awk -F'|' '$1=="CRASHS"{b=$2; sub(/^CRASHS\|[^|]*\|/,""); printf "  %s: %s\n", b, $0}' "$TMP/err"

# 2. engine / request-parsing errors
sec "2. PHP ENGINE/REQUEST-PARSING ERRORS (multipart, limits, memory)"
echo "  total: $(awk -F'|' '$1=="ENGN"{s+=$2}END{print s+0}' "$TMP/err")"
awk -F'|' '$1=="ENGS"{b=$2; sub(/^ENGS\|[^|]*\|/,""); printf "  %s: %s\n", b, $0}' "$TMP/err"

# 3. PHP errors top messages
sec "3. PHP errors in error logs (top messages, numbers normalised)"
awk -F'|' '$1=="PERR"{s[$3]+=$2} END{for(m in s) print s[m] "\t" m}' "$TMP/err" | sort -rn | head -15 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'

# 4. IOC patterns
sec "4. KNOWN PHP-ATTACK PATTERNS IN REQUESTS"
awk -F'|' '$1=="IOC" { k=$2+0; nm[k]=$3; t[k]+=$4; o[k]+=$5 }
  END { for (k in t) printf "%d|%d|%d|%s\n", k, t[k], o[k], nm[k] }' "$TMP/acc" \
| sort -t'|' -k1,1n | while IFS='|' read -r _idx tot ok name; do
  echo "  [$(printf '%5d' "$tot" | tr -d ' ') hits, $ok answered 2xx] $name"
  awk -F'|' -v n="$name" '$1=="IOCSAMPLE" && $2==n { sub(/^IOCSAMPLE\|[^|]*\|/,""); print "        " $0 }' "$TMP/acc" | awk '!seen[$0]++' | head -6
  days=$(awk -F'|' -v n="$name" '$1=="IOCDAY" && $2==n {s[$3]+=$4} END{for(d in s) print d"\t"s[d]}' "$TMP/acc" | sort | tail -8 | awk -F'\t' '{printf "%s=%s ", $1, $2}')
  [ -n "$days" ] && echo "        by day: $days"
  ips=$(awk -F'|' -v n="$name" '$1=="IOCIP" && $2==n {s[$3]+=$4} END{for(i in s) print s[i]"\t"i}' "$TMP/acc" | sort -rn | head -5 | awk -F'\t' '{printf "%s=%s ", $2, $1}')
  [ -n "$ips" ] && echo "        top IPs: $ips"
done

# 5. unexpected POSTs
sec "5. POST requests (host, path, status)"
awk -F'|' '$1=="PATHPOST"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -25 | sed 's/\t/  /g; s/^/  /'
awk -F'|' '$1=="CAPPED" && $2=="POST paths"{s+=$3} END{if (s>0) print "  (" s " further requests fell past the " 200000 "-key cap)"}' "$TMP/acc"

# 6. 5xx responses
sec "6. 5xx responses (host, path, status)"
awk -F'|' '$1=="PATH5"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -15 | sed 's/\t/  /g; s/^/  /'

# 7. odd methods / malformed
sec "7. Unusual HTTP methods / malformed requests"
awk -F'|' '$1=="METHOD"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -10 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
awk -F'|' '$1=="BADREQ"{ $1=""; sub(/^\|/,""); print "        " $0 }' "$TMP/acc" | awk '!seen[$0]++'

# 8. PHP-ish user agents
sec "8. Untrusted user agents mentioning PHP"
awk -F'|' '$1=="UAPHP"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -8 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'

# 9. traffic per day
sec "9. Traffic per day (total / POST / 5xx)"
awk -F'|' '$1=="TRAFFIC"{t[$2]+=$3; p[$2]+=$4; e[$2]+=$5} END{for(d in t) printf "%s\t%d\t%d\t%d\n", d, t[d], p[d], e[d]}' "$TMP/acc" | sort | tail -16 | awk -F'\t' '{printf "  %-12s %7d / %6d / %5d\n", $1, $2, $3, $4}'

# 10. PHP errors per day
sec "10. PHP errors per day (error logs)"
pdays=$(awk -F'|' '$1=="PERRDAY"{print $2"\t"$3}' "$TMP/err" | awk -F'\t' '{s[$1]+=$2} END{for(d in s) print d "\t" s[d]}' | sort | tail -16 | awk -F'\t' '{printf "%s=%s ", $1, $2}')
[ -n "$pdays" ] && echo "  $pdays"

fi  # ONLYPOSTEX

# ================= PART B: on-host checks =================
postex_unix() {

  # ---- index every webroot once; sections 11-14 and 20-21 all read it ----
  nroots=0; IDX_LIST=""
  for r in "${WEBROOTS[@]}"; do
    [ -d "$r" ] || continue
    nroots=$((nroots+1))
    progress "[host] indexing $r ..."
    build_index "$r" "$TMP/idx.$nroots"
    IDX_LIST="$IDX_LIST $nroots"
    eval "IDX_ROOT_$nroots=\$r"
  done
  progress_done

  sec "11. PHP-executable files changed in webroots since $SINCE (newest first)"
  tot=0
  for i in $IDX_LIST; do
    eval "r=\$IDX_ROOT_$i"
    out=$(idx_changed "$TMP/idx.$i")
    n=$(printf '%s\n' "$out" | grep -c .)
    tot=$((tot+n))
    nidx=$(grep -c . "$TMP/idx.$i")
    trunc=""
    [ "$nidx" -ge "$INDEX_MAX" ] && trunc=", TRUNCATED at $INDEX_MAX"
    echo "  -- $r ($n changed of $nidx files indexed$trunc)"
    printf '%s\n' "$out" | sort -rn | head -40 | fmt_rows | sed 's/^/  /'
  done
  [ "$tot" = 0 ] && echo "   total: 0"

  if [ -n "$WEBUSER" ]; then
    sec "12. files owned by $WEBUSER in webroots (writable by the web user)"
    for i in $IDX_LIST; do idx_owned "$TMP/idx.$i" "$WEBUSER"; done | head -20 | sed 's/^/  /'
  else
    sec "12. files owned by the web user in webroots"
    echo "   (web server user not found - pass --user NAME)"
  fi

  # 13 and 14 do not depend on the web user. They used to sit inside the
  # "if WEBUSER" block, so on any host without a www-data/apache/_www account
  # the webshell scan - the strongest host check here - was silently skipped.
  sec "13. PHP files under upload/cache/tmp-like dirs in webroots"
  n13=0
  for i in $IDX_LIST; do
    eval "r=\$IDX_ROOT_$i"
    out=$(idx_uploadish "$TMP/idx.$i" "$r")
    [ -n "$out" ] && { printf '%s\n' "$out" | head -10 | sed 's/^/  /'; n13=1; }
  done
  [ "$n13" = 0 ] && echo "   (none)"

  sec "14. webshell-ish code in webroot PHP (eval/assert/exec on request input, base64+eval)"
  wf=0
  for i in $IDX_LIST; do
    eval "r=\$IDX_ROOT_$i"
    progress "[host] webshell scan: $r ..."
    out=$(webshell_scan "$TMP/idx.$i")
    progress_done
    [ -n "$out" ] && { printf '%s\n' "$out" | sed 's/^/  /'; wf=1; }
  done
  [ "$wf" = 0 ] && echo "   (none)"

  if [ -n "$WEBUSER" ]; then
    sec "15. processes running as $WEBUSER (anything other than apache/httpd is suspicious)"
    if [ "$GNUPS" = 1 ]; then
      ps -u "$WEBUSER" -o pid,ppid,lstart,cmd --no-headers 2>/dev/null | grep -vE 'apache2|httpd' | head | sed 's/^/  /'
      echo "   apache/httpd workers: $(ps -u "$WEBUSER" -o cmd --no-headers 2>/dev/null | grep -cE 'apache2|httpd')"
    else
      ps -U "$WEBUSER" -o pid,ppid,lstart,command 2>/dev/null | grep -vE 'PID|apache2|httpd' | head | sed 's/^/  /'
      echo "   apache/httpd workers: $(ps -U "$WEBUSER" -o command 2>/dev/null | grep -cE 'apache2|httpd')"
    fi

    sec "16. files owned by $WEBUSER in /tmp /var/tmp /dev/shm"
    if [ "$GNUFIND" = 1 ]; then
      find /tmp /var/tmp /dev/shm -xdev -user "$WEBUSER" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | grep -v '/sess_' | head -15 | sed 's/^/  /'
    elif [ "$STATMODE" = bsd ]; then
      find /tmp /var/tmp /dev/shm -user "$WEBUSER" -type f 2>/dev/null | grep -v '/sess_' | head -15 \
        | tr '\n' '\0' | xargs -0 -r stat -f '%Sm %N' -t '%Y-%m-%d %H:%M' 2>/dev/null | sed 's/^/  /'
    elif [ "$STATMODE" = gnu ]; then
      find /tmp /var/tmp /dev/shm -user "$WEBUSER" -type f 2>/dev/null | grep -v '/sess_' | head -15 \
        | tr '\n' '\0' | xargs -0 -r stat -c "%y${TAB}%n" 2>/dev/null \
        | awk -F"$TAB" '{printf "  %s %s\n", substr($1,1,16), $2}'
    else
      find /tmp /var/tmp /dev/shm -user "$WEBUSER" -type f 2>/dev/null | grep -v '/sess_' | head -15 | sed 's/^/  /'
    fi
    echo "   (php session files: $(find /tmp /var/lib/php/sessions /var/lib/php5 -user "$WEBUSER" -name 'sess_*' 2>/dev/null | wc -l | tr -d ' '))"

    sec "17. outbound/listening sockets owned by the web user"
    if command -v ss >/dev/null 2>&1; then
      # [[:space:]] rather than the GNU-only \s shorthand
      ss -tunap 2>/dev/null | grep -E "apache2|httpd|$WEBUSER" | grep -vE ':(80|443)[[:space:]]' | grep -vE 'LISTEN' | awk '{print $1,$2,$5,$6}' | sort | uniq -c | sort -rn | head -12 | sed 's/^/  /'
    elif command -v lsof >/dev/null 2>&1; then
      # lsof writes "local:port->remote:port", so the old ':(80|443)\s' filter
      # could never match and nothing was ever excluded. Pull the remote port out.
      lsof -nP -i 2>/dev/null | awk -v u="$WEBUSER" '
        NR>1 && ($1 ~ /httpd/ || $3==u) {
          if (match($0, /->[^ ]+/)) {
            rp = substr($0, RSTART+2, RLENGTH-2); sub(/.*:/, "", rp)
            if (rp == "80" || rp == "443") next
          }
          print }' | head -12 | sed 's/^/  /'
    else
      echo "   (no ss/lsof available)"
    fi

    sec "18. $WEBUSER crontab / .ssh in webroots"
    if command -v crontab >/dev/null 2>&1; then
      cout=$(crontab -u "$WEBUSER" -l 2>&1 | head -3)
      case "$cout" in *"must be privileged"*) : ;; *) printf '%s\n' "$cout" | sed 's/^/  /' ;; esac
    fi
    for r in "${WEBROOTS[@]}"; do ls -la "$r/.ssh" 2>/dev/null | sed 's/^/  /'; done
  else
    sec "15.-18. web-user process, socket and ownership checks"
    echo "   (web server user not found - pass --user NAME to enable them)"
  fi

  # ---- php2shell behavioural checks ----
  sec "19. web server spawning shells / payload commands (Elastic 'Payload Execution by Web Server')"
  if command -v ps >/dev/null 2>&1; then
    { if [ "$GNUPS" = 1 ]; then ps -eo pid=,ppid=,user=,comm=,args= 2>/dev/null
      else ps -axo pid=,ppid=,user=,comm=,args= 2>/dev/null; fi; } | awk '
      # macOS prints comm as a full path (/usr/sbin/httpd), so strip the
      # directory before the anchored match or this never fires there.
      { c=$4; sub(/.*\//,"",c)
        P[NR]=$1; PP[NR]=$2; U[NR]=$3; C[NR]=c
        a=""; for (i=5;i<=NF;i++) a=a (i>5?" ":"") $i
        A[NR]=a; commby[$1]=c; n=NR }
      END {
        for (i=1;i<=n;i++) {
          pc=commby[PP[i]]; if (pc=="") continue
          if (pc !~ /^(apache2|httpd|nginx|php-cgi|php-fpm|lsphp|frankenphp|sw-engine-fpm)/) continue
          shell=(C[i] ~ /^(bash|sh|dash|zsh|ksh|ash|busybox)$/)
          susp =(A[i] ~ /\/dev\/tcp|base64[ ]*-d|(^|[ \/])(curl|wget|nc|ncat|socat)[ ]|mkfifo|fsockopen|pty\.spawn|\/etc\/(shadow|passwd)|169\.254\.169\.254|\|[ ]*(sh|bash)/)
          bare =(A[i] ~ /(^|[ ])(id|whoami|hostname|uname)([ ]|$)/)
          if (shell||susp||bare) printf "  pid=%s ppid=%s(%s) user=%s  %s\n", P[i], PP[i], pc, U[i], substr(A[i],1,160)
        }
      }'
    echo "  (point-in-time: empty = no web-server process currently has a shell/tool child)"
  else
    echo "  (ps unavailable)"
  fi

  sec "20. suspicious uploads: PHP double-extensions & image polyglots"
  up2=0
  for i in $IDX_LIST; do
    eval "r=\$IDX_ROOT_$i"
    progress "[host] upload/polyglot scan: $r ..."
    out=$(dblext_polyglot "$TMP/idx.$i"); progress_done
    [ -n "$out" ] && { printf '%s\n' "$out" | sed 's/^/  /'; up2=1; }
  done
  [ "$up2" = 0 ] && echo "   (none)"

  sec "21. recon / reverse-shell / cloud-metadata strings in files changed since $SINCE"
  rs2=0
  for i in $IDX_LIST; do
    eval "r=\$IDX_ROOT_$i"
    progress "[host] recon-string scan: $r ..."
    out=$(recon_strings "$TMP/idx.$i"); progress_done
    [ -n "$out" ] && { printf '%s\n' "$out" | sed 's/^/  /'; rs2=1; }
  done
  [ "$rs2" = 0 ] && echo "   (none)"

  sec "22. persistence: systemd units & cron entries changed since $SINCE"
  if [ "$GNUFIND" = 1 ]; then
    find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /run/systemd/system \
      -xdev -type f -newer "$REF" 2>/dev/null | head -15 | sed 's/^/  /'
  else
    find /etc/systemd/system /lib/systemd/system /run/systemd/system \
      -type f -newer "$REF" 2>/dev/null | head -15 | sed 's/^/  /'
  fi
  find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/crontab /var/spool/cron \
    -type f -newer "$REF" 2>/dev/null | head -15 | sed 's/^/  /'
}

# decide whether to run the host checks: --no-postex / --postex / --only-postex /
# RUN_POSTEX=yes|no, otherwise ask on the terminal (read from /dev/tty so it works
# through the piped one-liner; without a terminal the checks are skipped)
ask_postex() {
  [ "$NOPOSTEX" = 1 ] && return 1
  { [ -n "$FORCE_POSTEX" ] || [ "$ONLYPOSTEX" = 1 ]; } && return 0
  case "${RUN_POSTEX:-}" in
    [Yy]|[Yy][Ee][Ss]|1) return 0 ;;
    [Nn]|[Nn][Oo]|0) return 1 ;;
  esac
  ans=""
  if { printf '' > /dev/tty; } 2>/dev/null; then
    printf '\nLog scan finished. Run the post-exploitation host checks now? [y/N] ' > /dev/tty 2>/dev/null
    IFS= read -r ans < /dev/tty 2>/dev/null || return 1
  elif [ -t 0 ]; then
    printf '\nLog scan finished. Run the post-exploitation host checks now? [y/N] '
    IFS= read -r ans || return 1
  else
    return 1
  fi
  case "$ans" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

if ask_postex; then
  postex_unix
elif [ "$NOPOSTEX" = 1 ]; then
  echo; echo "---- host checks skipped (--no-postex) ----"
elif [ -n "${RUN_POSTEX:-}" ]; then
  echo; echo "---- host checks skipped (RUN_POSTEX=${RUN_POSTEX}) ----"
else
  echo; echo "---- host checks skipped (no terminal to ask — re-run with --postex, --only-postex or RUN_POSTEX=yes to force) ----"
fi

echo
echo "---- done (read-only; report may contain visitor IPs, hostnames and file paths — do not publish) ----"
