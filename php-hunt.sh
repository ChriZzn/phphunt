#!/usr/bin/env bash
# php-hunt — read-only hunt for PHP exploitation signs on Apache + PHP servers.
# One self-contained script: log analysis (phphunt.py) + on-host checks (postex.sh).
# Always runs the log scan first, then asks whether to run the host checks.
# Cross-platform: Linux (Debian/RHEL/SUSE/Alpine), macOS, Windows (Git Bash / MSYS2 / Cygwin / WSL).
#
# One-liners:
#   curl -fsSL https://raw.githubusercontent.com/ChriZzn/php2shell-detect/main/php-hunt.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/ChriZzn/php2shell-detect/main/php-hunt.sh | sudo bash -s -- --postex
#   sudo bash php-hunt.sh --since 2026-10-01
#
# Read-only: prints a report and changes nothing on the system (it only creates a
# short-lived timestamp reference file in the temp dir and deletes it afterwards).
export LC_ALL=C

VERSION="1.0"

# ---------------- defaults / options ----------------
NOLOGS=""; NOPOSTEX=""; FORCE_POSTEX=""; ONLYPOSTEX=""; SINCE_IN=""; WEBUSER_FORCE=""; TUS=""
LOGDIRS=(); WEBROOTS=()

usage() {
cat <<'EOF'
php-hunt — read-only hunt for PHP exploitation signs on Apache + PHP servers.
Combines log analysis (phphunt.py) and on-host checks (postex.sh) in one script.
It always runs the log scan first, then asks whether to run the host checks.

Usage:
  sudo bash php-hunt.sh [options]
  curl -fsSL https://raw.githubusercontent.com/ChriZzn/php2shell-detect/main/php-hunt.sh | sudo bash

Options:
  --logdir DIR      Apache log directory (auto-detected by default; repeatable)
  --webroot DIR     webroot directory (auto-detected by default; repeatable)
  --webuser USER    web server user (alias: --user; auto-detected: www-data / apache / httpd / _www)
  --since DATE      flag files changed since YYYY-MM-DD (default: last 7 days)
  --trusted-ua S    user-agent substring to exclude from POST/UA sections (repeatable)
  --postex          run the host checks without asking
  --no-postex       skip the host checks (do not ask)
  --only-postex     skip the log scan, run only the host checks
  -h, --help        this help

The prompt is read from /dev/tty, so it still works through the pipe. Without a
terminal the host checks are skipped unless forced with --postex/--only-postex or
RUN_POSTEX=yes (or skipped with --no-postex / RUN_POSTEX=no).

Read-only: prints a report, writes nothing to the system.
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

  MINGW*|MSYS*|CYGWIN*|INTERIX) OS=windows ;;
esac

GNUDATE=0; GNUFIND=0; GNUPS=0
date -d now >/dev/null 2>&1      && GNUDATE=1
find --version >/dev/null 2>&1   && GNUFIND=1
ps --version >/dev/null 2>&1     && GNUPS=1

TMP=$(mktemp -d "${TMPDIR:-/tmp}/phphunt.XXXXXX") || { echo "cannot create temp dir" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT

# reference timestamp: files newer than this are "changed since SINCE"
if [ -n "$SINCE_IN" ]; then
  SINCE="$SINCE_IN"
  STAMP=$(printf '%s' "$SINCE_IN" | tr -d '-')
  case ${#STAMP} in 8) STAMP="${STAMP}0000";; 12) :;; *) STAMP="${STAMP}00";; esac
else
  if [ "$GNUDATE" = 1 ]; then SINCE=$(date -d '7 days ago' +%F); STAMP=$(date -d '7 days ago' +%Y%m%d%H%M)
  else SINCE=$(date -v-7d +%F 2>/dev/null); STAMP=$(date -v-7d +%Y%m%d%H%M 2>/dev/null); fi
fi
REF="$TMP/ref.ts"
touch -t "$STAMP" "$REF" 2>/dev/null || { echo "bad --since value: $SINCE_IN (use YYYY-MM-DD)" >&2; exit 1; }

# web server user
WEBUSER=""
if [ -n "$WEBUSER_FORCE" ]; then WEBUSER="$WEBUSER_FORCE"
elif [ "$OS" != windows ]; then
  for u in www-data apache httpd _www nginx; do id "$u" >/dev/null 2>&1 && WEBUSER="$u" && break; done
fi

# ---------------- candidate paths ----------------
add_dirs() { local p; for p in "$@"; do [ -d "$p" ] && LOGDIRS+=("$p"); done; }
add_rdirs() { local p; for p in "$@"; do [ -d "$p" ] && WEBROOTS+=("$p"); done; }

CAND_LOG=(); CAND_ROOT=()
case "$OS" in
  linux)
    CAND_LOG="/var/log/apache2 /var/log/httpd /usr/local/apache2/logs /etc/httpd/logs"
    CAND_ROOT="/var/www /var/www/html /srv/www /usr/share/nginx/html"
    ;;
  macos)
    CAND_LOG="/usr/local/var/log/httpd /opt/homebrew/var/log/httpd /var/log/apache2"
    CAND_ROOT="/Library/WebServer/Documents /usr/local/var/www /opt/homebrew/var/www"
    ;;
  windows)
    for dr in /c /d /e /f; do
      [ -d "$dr" ] || continue
      for p in "$dr/xampp/apache/logs" "$dr/wamp64/logs" "$dr/wamp/logs" "$dr/Apache24/logs" \
               "$dr/Apache2.4/logs" "$dr/Program Files/Apache Software Foundation/Apache2.4/logs" \
               "$dr/Bitnami"/*/apache2/logs; do [ -d "$p" ] && CAND_LOG="$CAND_LOG $p"; done
      for p in "$dr/xampp/htdocs" "$dr/wamp64/www" "$dr/wamp/www" "$dr/Apache24/htdocs" \
               "$dr/inetpub/wwwroot" "$dr/Bitnami"/*/apache2/htdocs; do [ -d "$p" ] && CAND_ROOT="$CAND_ROOT $p"; done
    done
    ;;
esac

# WSL: also probe Windows-side stacks under /mnt/<drive>
if [ "$WSL" = 1 ]; then
  for dr in /mnt/[a-z]; do
    [ -d "$dr" ] || continue
    for p in "$dr/xampp/apache/logs" "$dr/wamp64/logs" "$dr/wamp/logs" "$dr/Apache24/logs"; do
      [ -d "$p" ] && { CAND_LOG="$CAND_LOG $p"; WINMODE=1; }
    done
    for p in "$dr/xampp/htdocs" "$dr/wamp64/www" "$dr/wamp/www" "$dr/Apache24/htdocs" "$dr/inetpub/wwwroot"; do
      [ -d "$p" ] && { CAND_ROOT="$CAND_ROOT $p"; WINMODE=1; }
    done
  done
fi

for d in $CAND_LOG;  do [ ${#LOGDIRS[@]} -gt 0 ] || add_dirs  "$d"; done
for d in $CAND_ROOT; do [ ${#WEBROOTS[@]} -gt 0 ] || add_rdirs "$d"; done

# ---------------- helpers ----------------
sec() { echo; echo "=== $* ==="; }
readlog() { case "$1" in *.gz) gzip -cd "$1" 2>/dev/null;; *) cat "$1" 2>/dev/null;; esac; }
changed() { # list php-ish files under $1 changed since $REF
  if [ "$GNUFIND" = 1 ]; then
    find "$1" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' -o -name '.user.ini' \) -newer "$REF" -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n' 2>/dev/null
  else
    find "$1" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' -o -name '.user.ini' \) -newer "$REF" -exec stat -f '%Sm  %Su:%Sg  %N' -t '%Y-%m-%d %H:%M' {} + 2>/dev/null
  fi
}
webshell_scan() { # $1 root
  grep -rlE --include='*.php' --include='*.phtml' --include='*.phar' --include='*.inc' 'eval\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|gzuncompress|str_rot13)|assert\s*\(\s*\$_(GET|POST|REQUEST)|(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|preg_replace\s*\(.*/e[^a-z]|create_function\s*\(\s*.?.?,|\$_(GET|POST|REQUEST|COOKIE)\[[^]]+\]\s*\(' "$1" 2>/dev/null | head -10
}
upload_php() { # $1 root
  find "$1" -xdev -type f -name '*.php' \( -path '*upload*' -o -path '*cache*' -o -path '*/tmp/*' -o -path '*/images/*' -o -path '*/img/*' \) 2>/dev/null | head -10
}
# php-ish files whose PHP extension is NOT final (avatar.php.jpg), plus image/text
# files that actually contain PHP (polyglot shells), changed since $REF.
dblext_polyglot() { # $1 root
  { find "$1" -type f \( -iname '*.php.*' -o -iname '*.phtml.*' -o -iname '*.phar.*' \) 2>/dev/null | head -15
    find "$1" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.ico' -o -iname '*.txt' \) -newer "$REF" 2>/dev/null \
      | head -2000 | tr '\n' '\0' | xargs -0 grep -lI '<?php' 2>/dev/null | head -10
  } | awk '!seen[$0]++'
}
# files changed since $REF that contain recon / reverse-shell / cloud-metadata markers
recon_strings() { # $1 root
  find "$1" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.inc' \) -newer "$REF" 2>/dev/null \
    | head -5000 | tr '\n' '\0' | xargs -0 grep -lIE \
      '/dev/tcp/|fsockopen\s*\(|proc_open\s*\(|pcntl_exec\s*\(|169\.254\.169\.254|aws/credentials|kubernetes\.io/serviceaccount|/etc/shadow' 2>/dev/null | head -15
}
# sort "day<TAB>..." lines chronologically (day = "14/Oct/2026" or "Oct 14")
sortdays() { awk -F'\t' 'BEGIN{m="jan feb mar apr may jun jul aug sep oct nov dec"}
  function mnum(s){ return int((index(m, tolower(s))+3)/4) }
  { d=$1
    if (d ~ /\//) { split(d,a,"/"); k=sprintf("%04d-%02d-%02d", a[3], mnum(a[2]), a[1]) }
    else          { split(d,a," "); k=sprintf("0000-%02d-%02d", mnum(a[1]), a[2]) }
    print k "\t" $0 }' | sort | cut -f2-; }

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
    v=$("$bin" -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
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
  command -v dpkg >/dev/null 2>&1 && dpkg -l 'php*' 2>/dev/null | awk '/^ii/{print "  pkg "$2" "$3}' | head -12
  command -v rpm  >/dev/null 2>&1 && rpm -qa 'php*'  2>/dev/null | sed 's/^/  pkg /' | head -12
  [ "$any" = 0 ] && echo "  (no PHP binary on PATH — if PHP runs only as an Apache module, check the package version)"
  echo "  fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 8.1 and older are EOL. mod_php is the highest-risk SAPI."
}

# ---------------- report header ----------------
DISTRO=""
[ -r /etc/os-release ] && DISTRO=$(. /etc/os-release && echo "$PRETTY_NAME" 2>/dev/null)
echo "phphunt v$VERSION — read-only PHP exploitation hunt"
echo "  host: $(hostname 2>/dev/null || echo '?')   date: $(date 2>/dev/null)"
echo "  platform: $OS${DISTRO:+ ($DISTRO)}${WSL:+ (WSL — Windows stacks probed too)}"
echo "  file window: since $SINCE   web user: ${WEBUSER:-(n/a — pass --user)}"
echo "  log dirs: $( [ ${#LOGDIRS[@]} -gt 0 ] && printf '%s ' "${LOGDIRS[@]}" || echo '(none found — pass --logdir)')"
echo "  webroots: $( [ ${#WEBROOTS[@]} -gt 0 ] && printf '%s ' "${WEBROOTS[@]}" || echo '(none found — pass --webroot)')"
if [ "$OS" != windows ] && [ "$(id -u 2>/dev/null)" != 0 ]; then
  echo "  NOTE: not running as root — many checks will miss data. Try: sudo bash php-hunt.sh"
fi

php_version_check   # always — the primary php2shell signal, fast and read-only

# ================= PART A: log analysis =================
if [ "$ONLYPOSTEX" != 1 ]; then

ACCESS=(); ERRORS=()
for d in "${LOGDIRS[@]}"; do
  for f in "$d"/*access*log*; do [ -f "$f" ] && ACCESS+=("$f"); done
  for f in "$d"/*error*log*;   do [ -f "$f" ] && ERRORS+=("$f"); done
done

: > "$TMP/err"
for f in "${ERRORS[@]}"; do
  [ -r "$f" ] || { echo "  !! cannot read $f"; continue; }
  readlog "$f" | awk -v F="${f##*/}" '
    { sub(/\r$/,""); l=tolower($0)
      i=index($0,"["); day="?"
      if (i>0) { s0=substr($0,i+1,32); split(s0,w," "); if (w[2]!="" && w[3]!="") day=w[2]" "w[3] }
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
for f in "${ACCESS[@]}"; do
  [ -r "$f" ] || { echo "  !! cannot read $f"; continue; }
  readlog "$f" | awk -v F="${f##*/}" -v TUS="$TUS" '
    BEGIN{
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
      c=index(ts,":"); day=(c>1)? substr(ts,1,c-1) : "?"
      m=split(pre, t, " ")
      host="?"; ip=""
      if (m>=2 && t[2] ~ /[0-9]/) { ip=t[2]; host=t[1] }
      else if (m>=1 && t[1] ~ /[0-9]/) { ip=t[1] }
      if (host=="?") host=F
      tot[day]++
      psplit=split(req, r, " ")
      meth=(psplit>0)? r[1] : ""
      path=(psplit>1)? r[2] : req
      sp=index(path,"?"); if (sp>0) path=substr(path,1,sp-1)
      lreq=tolower(req); lua=tolower(ua)
      if (st>=500) { e5[day]++; k5=host "\t" path "\t" st; c5[k5]++ }
      if (meth=="POST") { post[day]++; if (!istrusted(lua)) { kp=host "\t" path "\t" st; cp[kp]++ } }
      if (meth!="" && meth!="GET" && meth!="POST" && meth!="HEAD" && meth!="OPTIONS" && meth!="PUT" && meth!="DELETE" && meth!="PATCH") {
        od[meth]++
        if (nb<8) { nb++; print "BADREQ|" $0 }
      }
      for (k=1;k<=np;k++) {
        if (lreq ~ P[k] || lua ~ P[k]) {
          it[k]++; if (st>=200 && st<300) i2[k]++
          kd=k SUBSEP day; idc[kd]++
          if (ip!="") { ki=k SUBSEP ip; if ((ki in ipc) || nip<200000) { if (!(ki in ipc)) nip++; ipc[ki]++ } }
          if (ic[k]<6) { ic[k]++; line=$0; if (length(line)>240) line=substr(line,1,240); print "IOCSAMPLE|" nm[k] "|" line }
        }
      }
      if (lua ~ /php/ && !istrusted(lua)) up[substr(lua,1,90)]++
    }
    END{
      for (d in tot)  print "TRAFFIC|" d "|" tot[d]+0 "|" post[d]+0 "|" e5[d]+0
      for (k in c5)   print "PATH5|" k "|" c5[k]
      for (k in cp)   print "PATHPOST|" k "|" cp[k]
      for (k in od)   print "METHOD|" k "|" od[k]
      for (k in up)   print "UAPHP|" k "|" up[k]
      for (k=1;k<=np;k++) if (it[k]>0) {
        print "IOC|" nm[k] "|" it[k] "|" i2[k]+0
        for (x in idc) { split(x, kk, SUBSEP); if (kk[1]==k) print "IOCDAY|" nm[k] "|" kk[2] "|" idc[x] }
        for (x in ipc) { split(x, kk, SUBSEP); if (kk[1]==k) print "IOCIP|" nm[k] "|" kk[2] "|" ipc[x] }
      }
    }' >> "$TMP/acc"
done

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
sed -n 's/^IOC|//p' "$TMP/acc" | while IFS='|' read -r name tot ok; do
  echo "  [$(printf '%5d' "$tot" | tr -d ' ') hits, $ok answered 2xx] $name"
  awk -F'|' -v n="$name" '$1=="IOCSAMPLE" && $2==n { sub(/^IOCSAMPLE\|[^|]*\|/,""); print "        " $0 }' "$TMP/acc"
  days=$(awk -F'|' -v n="$name" '$1=="IOCDAY" && $2==n {print $3"\t"$4}' "$TMP/acc" | sortdays | tail -8 | awk '{printf "%s=%s ", $1, $2}')
  [ -n "$days" ] && echo "        by day: $days"
  ips=$(awk -F'|' -v n="$name" '$1=="IOCIP" && $2==n {print $3 "|" $4}' "$TMP/acc" | sort -t'|' -k2,2nr | head -5 | awk -F'|' '{printf "%s=%s ", $1, $2}')
  [ -n "$ips" ] && echo "        top IPs: $ips"
done

# 5. unexpected POSTs
sec "5. POST requests (host, path, status)"
awk -F'|' '$1=="PATHPOST"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -25 | sed 's/\t/  /g; s/^/  /'

# 6. 5xx responses
sec "6. 5xx responses (host, path, status)"
awk -F'|' '$1=="PATH5"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -15 | sed 's/\t/  /g; s/^/  /'

# 7. odd methods / malformed
sec "7. Unusual HTTP methods / malformed requests"
awk -F'|' '$1=="METHOD"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -10 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'
awk -F'|' '$1=="BADREQ"{ $1=""; sub(/^\|/,""); print "        " $0 }' "$TMP/acc"

# 8. PHP-ish user agents
sec "8. Untrusted user agents mentioning PHP"
awk -F'|' '$1=="UAPHP"{k[$2]+=$3} END{for(x in k) print k[x] "\t" x}' "$TMP/acc" | sort -rn | head -8 | awk -F'\t' '{printf "  %6d  %s\n", $1, $2}'

# 9. traffic per day
sec "9. Traffic per day (total / POST / 5xx)"
awk -F'|' '$1=="TRAFFIC"{t[$2]+=$3; p[$2]+=$4; e[$2]+=$5} END{for(d in t) printf "%s\t%d\t%d\t%d\n", d, t[d], p[d], e[d]}' "$TMP/acc" | sortdays | tail -16 | awk -F'\t' '{printf "  %-12s %7d / %6d / %5d\n", $1, $2, $3, $4}'

# 10. PHP errors per day
sec "10. PHP errors per day (error logs)"
pdays=$(awk -F'|' '$1=="PERRDAY"{print $2"\t"$3}' "$TMP/err" | awk -F'\t' '{s[$1]+=$2} END{for(d in s) print d "\t" s[d]}' | sortdays | tail -16 | awk -F'\t' '{printf "%s=%s ", $1, $2}')
[ -n "$pdays" ] && echo "  $pdays"

fi  # ONLYPOSTEX

# ================= PART B: on-host checks =================
postex_unix() {

  sec "11. PHP-executable files changed in webroots since $SINCE (newest first)"
  tot=0
  for r in $WEBROOTS; do
    [ -d "$r" ] || continue
    out=$(changed "$r")
    n=$(printf '%s\n' "$out" | grep -c .)
    tot=$((tot+n))
    echo "  -- $r ($n)"
    printf '%s\n' "$out" | sort -r | head -40 | sed 's/^/  /'
  done
  [ "$tot" = 0 ] && echo "   total: 0"

  if [ -n "$WEBUSER" ]; then
    sec "12. files owned by $WEBUSER in webroots (writable by the web user)"
    for r in $WEBROOTS; do
      [ -d "$r" ] || continue
      if [ "$GNUFIND" = 1 ]; then
        find "$r" -xdev -user "$WEBUSER" -type f \( -name '*.php' -o -name '*.phtml' -o -name '.htaccess' -o -name '.user.ini' \) 2>/dev/null
      else
        find "$r" -user "$WEBUSER" -type f \( -name '*.php' -o -name '*.phtml' -o -name '.htaccess' -o -name '.user.ini' \) 2>/dev/null
      fi
    done | head -20 | sed 's/^/  /'

  sec "13. PHP files under upload/cache/tmp-like dirs in webroots"
  for r in $WEBROOTS; do [ -d "$r" ] || continue; upload_php "$r"; done | head -10 | sed 's/^/  /'

  sec "14. webshell-ish code in webroot PHP (eval/assert/exec on request input, base64+eval)"
  wf=0
  for r in $WEBROOTS; do
    [ -d "$r" ] || continue
    out=$(webshell_scan "$r")
    [ -n "$out" ] && { printf '%s\n' "$out" | sed 's/^/  /'; wf=1; }
  done
  [ "$wf" = 0 ] && echo "   (none)"

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
    else
      find /tmp /var/tmp /dev/shm -user "$WEBUSER" -type f 2>/dev/null | head -15 | while read -r p; do stat -f '%Sm %N' -t '%Y-%m-%d %H:%M' "$p" 2>/dev/null; done | grep -v '/sess_'
    fi
    echo "   (php session files: $(find /tmp /var/lib/php/sessions /var/lib/php5 -user "$WEBUSER" -name 'sess_*' 2>/dev/null | wc -l | tr -d ' '))"

    sec "17. outbound/listening sockets owned by the web user"
    if command -v ss >/dev/null 2>&1; then
      ss -tunap 2>/dev/null | grep -E "apache2|httpd|$WEBUSER" | grep -vE ':(80|443)\s' | grep -vE 'LISTEN' | awk '{print $1,$2,$5,$6}' | sort | uniq -c | sort -rn | head -12 | sed 's/^/  /'
    elif command -v lsof >/dev/null 2>&1; then
      lsof -nP -i 2>/dev/null | awk -v u="$WEBUSER" 'NR>1 && ($1 ~ /httpd/ || $3==u)' | grep -vE ':(80|443)\s' | head -12 | sed 's/^/  /'
    else
      echo "   (no ss/lsof available)"
    fi

    sec "18. $WEBUSER crontab / .ssh in webroots"
    if command -v crontab >/dev/null 2>&1; then
      cout=$(crontab -u "$WEBUSER" -l 2>&1 | head -3)
      case "$cout" in *"must be privileged"*) : ;; *) printf '%s\n' "$cout" | sed 's/^/  /' ;; esac
    fi
    for r in $WEBROOTS; do ls -la "$r/.ssh" 2>/dev/null | sed 's/^/  /'; done
  else
    echo; echo "   (web server user not found — pass --user NAME to enable ownership/process/socket checks)"
  fi

  # ---- php2shell behavioural checks (run regardless of WEBUSER) ----
  sec "19. web server spawning shells / payload commands (Elastic 'Payload Execution by Web Server')"
  if command -v ps >/dev/null 2>&1; then
    { [ "$GNUPS" = 1 ] && ps -eo pid=,ppid=,user=,comm=,args= 2>/dev/null \
                       || ps -axo pid=,ppid=,user=,comm=,args= 2>/dev/null; } | awk '
      { P[NR]=$1; PP[NR]=$2; U[NR]=$3; C[NR]=$4
        a=""; for (i=5;i<=NF;i++) a=a (i>5?" ":"") $i
        A[NR]=a; commby[$1]=$4; n=NR }
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
  for r in "${WEBROOTS[@]}"; do
    [ -d "$r" ] || continue
    out=$(dblext_polyglot "$r"); [ -n "$out" ] && { printf '%s\n' "$out" | sed 's/^/  /'; up2=1; }
  done
  [ "$up2" = 0 ] && echo "   (none)"

  sec "21. recon / reverse-shell / cloud-metadata strings in files changed since $SINCE"
  rs2=0
  for r in "${WEBROOTS[@]}"; do
    [ -d "$r" ] || continue
    out=$(recon_strings "$r"); [ -n "$out" ] && { printf '%s\n' "$out" | sed 's/^/  /'; rs2=1; }
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

postex_windows() {
  local TL NETST SCH
  TL=$(command -v tasklist || command -v tasklist.exe)
  NETST=$(command -v netstat || command -v netstat.exe)
  SCH=$(command -v schtasks || command -v schtasks.exe)

  sec "11. PHP-executable files changed in webroots since $SINCE (newest first)"
  tot=0
  for r in $WEBROOTS; do
    [ -d "$r" ] || continue
    out=$(changed "$r")
    n=$(printf '%s\n' "$out" | grep -c .)
    tot=$((tot+n))
    echo "  -- $r ($n)"
    printf '%s\n' "$out" | sort -r | head -40 | sed 's/^/  /'
  done
  [ "$tot" = 0 ] && echo "   total: 0"

  sec "12. webshell-ish code in webroot PHP (eval/assert/exec on request input, base64+eval)"
  found=0
  for r in $WEBROOTS; do [ -d "$r" ] || continue; webshell_scan "$r" | sed 's/^/  /' && found=1; done
  [ "$found" = 0 ] && echo "   (none)"

  sec "13. PHP files under upload/cache/tmp-like dirs in webroots"
  for r in $WEBROOTS; do [ -d "$r" ] || continue; upload_php "$r" | sed 's/^/  /'; done | head -10

  sec "14. httpd / php processes"
  if [ -n "$TL" ]; then
    "$TL" //NH 2>/dev/null | grep -iE 'httpd|php' | head -20 | sed 's/^/  /'
    echo "   httpd.exe instances: $("$TL" //NH 2>/dev/null | grep -ci 'httpd.exe')"
  else
    echo "   (tasklist not available)"
  fi

  sec "15. PHP files in temp / session dirs changed since $SINCE"
  WTMP=""
  if command -v cygpath >/dev/null 2>&1 && [ -n "$LOCALAPPDATA" ]; then WTMP=$(cygpath -u "$LOCALAPPDATA\\Temp" 2>/dev/null); fi
  if [ -z "$WTMP" ]; then for p in /mnt/c/Users/*/AppData/Local/Temp /c/Users/*/AppData/Local/Temp; do [ -d "$p" ] && WTMP="$p" && break; done; fi
  if [ -n "$WTMP" ]; then
    find "$WTMP" -maxdepth 2 -name '*.php' -newer "$REF" 2>/dev/null | head -10 | sed 's/^/  /'
    echo "   (temp dir: $WTMP)"
  else
    echo "   (temp dir not found)"
  fi
  for dr in /c /d /e /f /mnt/[a-z]; do
    [ -d "$dr" ] || continue
    for p in "$dr/xampp/tmp" "$dr/wamp64/tmp" "$dr/wamp/tmp"; do
      [ -d "$p" ] && echo "   php sessions in $p: $(find "$p" -name 'sess_*' 2>/dev/null | wc -l | tr -d ' ')"
    done
  done

  sec "16. network connections of httpd / php (non-80/443 remote, or php listeners)"
  if [ -n "$NETST" ] && [ -n "$TL" ]; then
    "$TL" //NH //FO CSV 2>/dev/null | awk -F'","' '{n=$1; p=$2; gsub(/"/,"",n); gsub(/"/,"",p); if (n!="") print p, n}' > "$TMP/pids"
    "$NETST" -ano 2>/dev/null | awk '
      NR==FNR { pid2name[$1]=$2; next }
      $1=="TCP" && $NF ~ /^[0-9]+$/ {
        tn=tolower(pid2name[$NF]); name=pid2name[$NF]
        if (tn !~ /httpd|php/) next
        if ($4=="LISTENING") {
          lp=$2; sub(/^.*:/,"",lp)
          if (lp!=80 && lp!=443) print "  LISTEN  " $2 "  [" name " pid " $NF "]"
        } else if ($4 ~ /ESTABLISHED|SYN_SENT/) {
          f=$3; sub(/^.*:/,"",f)
          if (f!=80 && f!=443) print "  " $2 " -> " $3 "  [" name " pid " $NF "]"
        }
      }' "$TMP/pids" -
  else
    echo "   (netstat/tasklist not available)"
  fi

  sec "17. scheduled tasks mentioning php/httpd + .ssh in webroots"
  [ -n "$SCH" ] && "$SCH" //query //fo csv //nh 2>/dev/null | grep -iE 'php|httpd' | head -5 | sed 's/^/  /'
  for r in $WEBROOTS; do ls -la "$r/.ssh" 2>/dev/null | sed 's/^/  /'; done

  sec "18. suspicious uploads: PHP double-extensions & image polyglots"
  for r in "${WEBROOTS[@]}"; do [ -d "$r" ] || continue; dblext_polyglot "$r" | sed 's/^/  /'; done

  sec "19. recon / reverse-shell / cloud-metadata strings in files changed since $SINCE"
  for r in "${WEBROOTS[@]}"; do [ -d "$r" ] || continue; recon_strings "$r" | sed 's/^/  /'; done
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
  if [ "$OS" = windows ]; then postex_windows
  else
    postex_unix
    [ "$WSL" = 1 ] && [ -n "$WINMODE" ] && postex_windows
  fi
elif [ "$NOPOSTEX" = 1 ]; then
  echo; echo "---- host checks skipped (--no-postex) ----"
elif [ -n "${RUN_POSTEX:-}" ]; then
  echo; echo "---- host checks skipped (RUN_POSTEX=${RUN_POSTEX}) ----"
else
  echo; echo "---- host checks skipped (no terminal to ask — re-run with --postex, --only-postex or RUN_POSTEX=yes to force) ----"
fi

echo
echo "---- done (read-only; report may contain visitor IPs, hostnames and file paths — do not publish) ----"
