<#
.SYNOPSIS
  php-hunt.ps1 - read-only hunt for PHP exploitation signs on Windows web servers.

.DESCRIPTION
  Native PowerShell port of php-hunt.sh for Windows stacks: Apache httpd (Apache
  Lounge / ASF), XAMPP, WampServer, Laragon, Bitnami, UniServer and IIS. No Git
  Bash, MSYS, Cygwin or WSL required - it uses only PowerShell and WMI/CIM.

  It always runs the log scan first, then asks whether to run the host checks.

  Read-only: it prints a report and changes nothing on the system. It writes no
  files at all (the Unix script needs a temp timestamp file; this one does not).

.PARAMETER LogDir
  Apache/IIS log directory. Repeatable. Auto-detected by default.
.PARAMETER WebRoot
  Web root to inspect. Repeatable. Auto-detected by default (incl. DocumentRoot
  parsed out of httpd.conf and its vhost includes).
.PARAMETER Since
  Flag files changed since this date (yyyy-MM-dd). Default: last 7 days.
.PARAMETER TrustedUa
  User-agent substring of a known client to leave out of the POST / UA sections.
  Repeatable.
.PARAMETER Postex
  Run the host checks without asking.
.PARAMETER NoPostex
  Skip the host checks (do not ask).
.PARAMETER OnlyPostex
  Skip the log scan, run only the host checks.
.PARAMETER Quiet
  No progress output on stderr (the report itself is unchanged).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\php-hunt.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\php-hunt.ps1 -Postex -Since 2026-10-01

.EXAMPLE
  .\php-hunt.ps1 -WebRoot C:\xampp\htdocs -LogDir C:\xampp\apache\logs -Postex

.NOTES
  Run as Administrator: the log files, other users' processes, service
  configuration and the ACL checks are not fully readable otherwise.
  The report can contain visitor IPs, hostnames and file paths - do not publish it.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
  [string[]]$LogDir,
  [string[]]$WebRoot,
  [string]$Since,
  [string[]]$TrustedUa,
  [switch]$Postex,
  [switch]$NoPostex,
  [switch]$OnlyPostex,
  [switch]$Quiet
)

$VERSION = '1.0'

# A read-only scanner touches a lot of things it is not allowed to read. Swallow
# those errors the way the Unix script's 2>/dev/null does, and report what we got.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Hard caps so a huge log or webroot cannot exhaust memory (see README notes).
$MAX_KEYS      = 200000    # distinct path/IP keys kept per counter
$MAX_SMALLKEYS = 5000      # distinct methods / user-agents kept
$MAX_FILES     = 250000    # files indexed per webroot
$MAX_SCAN_MB   = 8         # per-file size limit for content scans
$MAX_POLYGLOT  = 20000     # image/text files byte-scanned for embedded PHP

$script:PhpTmpDirs = @()   # filled in from php.ini (upload_tmp_dir / session.save_path)

# ---------------- output helpers ----------------
# Report goes to stdout so it can be redirected; progress goes to stderr so a
# redirected report stays clean.
$script:ProgOn  = $false
$script:ProgTty = $false
try { $script:ProgTty = -not [Console]::IsErrorRedirected } catch { $script:ProgTty = $false }

function Say  { param([string]$Text = '') Write-Output $Text }
function Sec  { param([string]$Text) Write-Output ''; Write-Output "=== $Text ===" }

function Prog {
  param([string]$Text)
  if ($Quiet) { return }
  if (-not $script:ProgTty) { try { [Console]::Error.WriteLine($Text) } catch {} ; return }
  $w = 78
  try { $w = [Console]::WindowWidth - 2 } catch {}
  if ($w -lt 20) { $w = 20 }
  if ($Text.Length -gt $w) { $Text = $Text.Substring(0, $w) }
  try { [Console]::Error.Write("`r" + $Text.PadRight($w)) ; $script:ProgOn = $true } catch {}
}

function ProgDone {
  if ($Quiet -or -not $script:ProgOn) { return }
  $w = 80
  try { $w = [Console]::WindowWidth - 1 } catch {}
  try { [Console]::Error.Write("`r" + (' ' * $w) + "`r") } catch {}
  $script:ProgOn = $false
}

function HumanSize {
  param([long]$Bytes)
  if ($Bytes -ge 1073741824) { return ('{0:N1}G' -f ($Bytes / 1073741824)) }
  if ($Bytes -ge 1048576)    { return ('{0:N0}M' -f ($Bytes / 1048576)) }
  if ($Bytes -ge 1024)       { return ('{0:N0}K' -f ($Bytes / 1024)) }
  return "${Bytes}B"
}

# Bounded counter: stops minting new keys past $Cap, tallying the rest as overflow.
function Bump {
  param([hashtable]$Table, [string]$Key, [int]$By = 1, [int]$Cap = 0)
  if ($Table.ContainsKey($Key)) { $Table[$Key] += $By; return }
  if ($Cap -gt 0 -and $Table.Count -ge $Cap) {
    if ($Table.ContainsKey('(capped)')) { $Table['(capped)'] += $By } else { $Table['(capped)'] = $By }
    return
  }
  $Table[$Key] = $By
}

function Top {
  param([hashtable]$Table, [int]$Count = 15)
  $Table.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First $Count
}

# ---------------- environment ----------------
$IsAdmin = $false
try {
  $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

if ($Since) {
  # One format per call: PowerShell binds a string[] to the single-format
  # TryParseExact overload (stringifying the array), so the array form never matches.
  $SinceDate = [datetime]::MinValue
  $ok = $false
  foreach ($fmt in @('yyyy-MM-dd', 'yyyy-MM-dd HH:mm', 'yyyy/MM/dd', 'yyyyMMdd')) {
    $tmp = [datetime]::MinValue
    if ([datetime]::TryParseExact($Since, $fmt, [Globalization.CultureInfo]::InvariantCulture,
          [Globalization.DateTimeStyles]::None, [ref]$tmp)) {
      $SinceDate = $tmp; $ok = $true; break
    }
  }
  if (-not $ok) {
    [Console]::Error.WriteLine("bad -Since value: $Since (use yyyy-MM-dd)")
    exit 1
  }
} else {
  $SinceDate = (Get-Date).Date.AddDays(-7)
}
$SinceLabel = $SinceDate.ToString('yyyy-MM-dd')

$FixedTrail = 'fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 8.1 and older are EOL.'
$FIXED = @{ '8.5' = 12; '8.4' = 27; '8.3' = 36; '8.2' = 35 }

$FixedDrives = @()
try {
  $FixedDrives = [System.IO.DriveInfo]::GetDrives() |
    Where-Object { $_.IsReady -and ($_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Ram') } |
    ForEach-Object { $_.RootDirectory.FullName.TrimEnd('\') }
} catch {}
if (-not $FixedDrives) { $FixedDrives = @($env:SystemDrive) }

function Expand-Candidates {
  # Expands wildcards and keeps only existing directories, de-duplicated.
  param([string[]]$Paths)
  $out = New-Object System.Collections.Generic.List[string]
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($p in $Paths) {
    if (-not $p) { continue }
    $hits = @()
    if ($p -match '[\*\?]') { $hits = (Get-Item -Path $p -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }).FullName }
    elseif (Test-Path -LiteralPath $p -PathType Container) { $hits = @((Get-Item -LiteralPath $p).FullName) }
    foreach ($h in $hits) { if ($h -and $seen.Add($h)) { $out.Add($h) } }
  }
  $out
}

# ---------------- discovery: Apache layout from the running server ----------------
# Most reliable source first: the httpd.exe that is actually running (or the
# installed service), then its httpd.conf, then the well-known stack layouts.
function Get-HttpdBinaries {
  $bins = New-Object System.Collections.Generic.List[string]
  foreach ($n in @('httpd.exe','Apache.exe','nginx.exe','caddy.exe')) {
    foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='$n'" | ForEach-Object { $_.ExecutablePath })) {
      if ($p) { $bins.Add($p) }
    }
  }
  foreach ($svc in (Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'httpd\.exe|nginx\.exe' })) {
    $m = [regex]::Match($svc.PathName, '"?([A-Za-z]:\\[^"]*?(?:httpd|nginx)\.exe)"?')
    if ($m.Success) { $bins.Add($m.Groups[1].Value) }
  }
  $bins | Sort-Object -Unique
}

function Get-ApacheConfValues {
  # Parses ServerRoot / DocumentRoot / ErrorLog / CustomLog out of httpd.conf and
  # one level of Include/IncludeOptional (that is where vhost DocumentRoots live).
  param([string]$ConfPath, [string]$ServerRoot)
  $res = @{ Roots = (New-Object System.Collections.Generic.List[string]);
            Logs  = (New-Object System.Collections.Generic.List[string]) }
  if (-not (Test-Path -LiteralPath $ConfPath -PathType Leaf)) { return $res }

  $confs = New-Object System.Collections.Generic.List[string]
  $confs.Add($ConfPath)

  function Resolve-ApachePath {
    param([string]$Raw, [string]$Base)
    if (-not $Raw) { return $null }
    $v = $Raw.Trim().Trim('"').Trim("'").Replace('/', '\')
    if ($v -match '^[A-Za-z]:\\' -or $v -match '^\\\\') { return $v }
    if (-not $Base) { return $null }
    return (Join-Path $Base $v)
  }

  # first pass: collect includes
  foreach ($line in (Get-Content -LiteralPath $ConfPath -ErrorAction SilentlyContinue)) {
    $t = $line.Trim()
    if ($t.StartsWith('#')) { continue }
    $m = [regex]::Match($t, '^Include(?:Optional)?\s+(.+)$', 'IgnoreCase')
    if ($m.Success) {
      $inc = Resolve-ApachePath $m.Groups[1].Value $ServerRoot
      if ($inc) {
        foreach ($f in (Get-Item -Path $inc -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
          $confs.Add($f.FullName)
        }
      }
    }
  }

  foreach ($cf in ($confs | Sort-Object -Unique)) {
    foreach ($line in (Get-Content -LiteralPath $cf -ErrorAction SilentlyContinue)) {
      $t = $line.Trim()
      if ($t.StartsWith('#')) { continue }
      $m = [regex]::Match($t, '^DocumentRoot\s+(.+)$', 'IgnoreCase')
      if ($m.Success) {
        $v = Resolve-ApachePath $m.Groups[1].Value $ServerRoot
        if ($v) { $res.Roots.Add($v) }
        continue
      }
      $m = [regex]::Match($t, '^(?:ErrorLog|CustomLog|TransferLog)\s+("[^"]+"|\S+)', 'IgnoreCase')
      if ($m.Success) {
        $v = $m.Groups[1].Value
        if ($v -match '^\|') { continue }   # piped logger - nothing on disk to read
        $v = Resolve-ApachePath $v $ServerRoot
        if ($v) { $res.Logs.Add((Split-Path -Parent $v)) }
      }
    }
  }
  $res
}

$DiscoveredRoots = New-Object System.Collections.Generic.List[string]
$DiscoveredLogs  = New-Object System.Collections.Generic.List[string]
$ServerRoots     = New-Object System.Collections.Generic.List[string]

foreach ($bin in (Get-HttpdBinaries)) {
  $binDir = Split-Path -Parent $bin
  $sroot  = Split-Path -Parent $binDir          # ...\Apache24\bin\httpd.exe -> ...\Apache24
  if (-not $sroot) { continue }
  $ServerRoots.Add($sroot)
  foreach ($conf in @("$sroot\conf\httpd.conf", "$sroot\conf\nginx.conf", "$binDir\httpd.conf")) {
    $v = Get-ApacheConfValues -ConfPath $conf -ServerRoot $sroot
    foreach ($r in $v.Roots) { $DiscoveredRoots.Add($r) }
    foreach ($l in $v.Logs)  { $DiscoveredLogs.Add($l) }
  }
  $DiscoveredLogs.Add("$sroot\logs")
}

# Well-known stack layouts, per fixed drive.
$CandLog  = New-Object System.Collections.Generic.List[string]
$CandRoot = New-Object System.Collections.Generic.List[string]
foreach ($d in $FixedDrives) {
  $CandLog.AddRange([string[]]@(
    "$d\xampp\apache\logs",
    "$d\wamp64\logs", "$d\wamp\logs",
    "$d\wamp64\bin\apache\apache*\logs", "$d\wamp\bin\apache\apache*\logs",
    "$d\laragon\bin\apache\*\logs", "$d\laragon\usr\log",
    "$d\Apache24\logs", "$d\Apache2.4\logs", "$d\Apache22\logs", "$d\Apache2\logs",
    "$d\Program Files\Apache Software Foundation\Apache2.4\logs",
    "$d\Program Files (x86)\Apache Software Foundation\Apache2.4\logs",
    "$d\Bitnami\*\apache2\logs", "$d\Bitnami\*\apache\logs",
    "$d\UniServerZ\core\apache2\logs",
    "$d\nginx\logs", "$d\tools\nginx*\logs",
    "$d\inetpub\logs\LogFiles", "$d\inetpub\logs\LogFiles\*"
  ))
  $CandRoot.AddRange([string[]]@(
    "$d\xampp\htdocs",
    "$d\wamp64\www", "$d\wamp\www",
    "$d\laragon\www",
    "$d\Apache24\htdocs", "$d\Apache2.4\htdocs", "$d\Apache22\htdocs", "$d\Apache2\htdocs",
    "$d\Program Files\Apache Software Foundation\Apache2.4\htdocs",
    "$d\Program Files (x86)\Apache Software Foundation\Apache2.4\htdocs",
    "$d\Bitnami\*\apache2\htdocs", "$d\Bitnami\*\apps\*\htdocs",
    "$d\UniServerZ\www",
    "$d\nginx\html",
    "$d\inetpub\wwwroot"
  ))
}

if ($LogDir)  { $LOGDIRS  = Expand-Candidates $LogDir }
else          { $LOGDIRS  = Expand-Candidates (@($DiscoveredLogs)  + @($CandLog)) }
if ($WebRoot) { $WEBROOTS = Expand-Candidates $WebRoot }
else          { $WEBROOTS = Expand-Candidates (@($DiscoveredRoots) + @($CandRoot)) }

# ---------------- PHP discovery + version verdict ----------------
function Get-PhpVersionVerdict {
  param([string]$V)
  $m = [regex]::Match($V, '^(\d+)\.(\d+)\.(\d+)')
  if (-not $m.Success) { return "could not parse '$V'" }
  $maj = [int]$m.Groups[1].Value; $min = [int]$m.Groups[2].Value; $pat = [int]$m.Groups[3].Value
  $branch = "$maj.$min"
  if ($FIXED.ContainsKey($branch)) {
    $fix = $FIXED[$branch]
    if ($pat -lt $fix) { return "VULNERABLE - $V < $branch.$fix (update PHP)" }
    return "patched ($V >= $branch.$fix)"
  }
  if ($maj -lt 8 -or ($maj -eq 8 -and $min -le 1)) {
    return "EOL branch $branch - no mainline fix; needs a vendor backport. TREAT AS VULNERABLE unless backported"
  }
  return "branch $branch newer than the advisory - assume patched, but verify"
}

function Get-FileVersionTriple {
  param([string]$Path)
  try {
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    foreach ($cand in @($vi.ProductVersion, $vi.FileVersion)) {
      if ($cand) {
        $m = [regex]::Match($cand, '(\d+)\.(\d+)\.(\d+)')
        if ($m.Success) { return $m.Value }
      }
    }
  } catch {}
  return $null
}

function Find-PhpBinaries {
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($c in (Get-Command php.exe, php-cgi.exe, php-win.exe -ErrorAction SilentlyContinue)) {
    if ($c.Source) { $out.Add($c.Source) }
  }
  foreach ($n in @('php.exe','php-cgi.exe','php-fpm.exe')) {
    foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='$n'" | ForEach-Object { $_.ExecutablePath })) {
      if ($p) { $out.Add($p) }
    }
  }
  $globs = New-Object System.Collections.Generic.List[string]
  foreach ($d in $FixedDrives) {
    $globs.AddRange([string[]]@(
      "$d\xampp\php\php.exe", "$d\xampp\php\php-cgi.exe",
      "$d\wamp64\bin\php\php*\php.exe", "$d\wamp\bin\php\php*\php.exe",
      "$d\laragon\bin\php\*\php.exe",
      "$d\php\php.exe", "$d\php*\php.exe",
      "$d\Program Files\php\php.exe", "$d\Program Files\PHP\v*\php-cgi.exe",
      "$d\Program Files (x86)\PHP\v*\php-cgi.exe",
      "$d\Bitnami\*\php\php.exe", "$d\UniServerZ\core\php*\php.exe",
      "$d\tools\php*\php.exe"
    ))
  }
  foreach ($sr in $ServerRoots) { $globs.Add("$sr\php\php.exe") }
  foreach ($g in $globs) {
    foreach ($f in (Get-Item -Path $g -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
      $out.Add($f.FullName)
    }
  }
  $out | Sort-Object -Unique
}

function Find-PhpApacheModules {
  $globs = New-Object System.Collections.Generic.List[string]
  foreach ($d in $FixedDrives) {
    $globs.AddRange([string[]]@(
      "$d\xampp\apache\modules\php*apache*.dll", "$d\xampp\php\php*apache*.dll",
      "$d\wamp64\bin\apache\apache*\modules\php*apache*.dll",
      "$d\laragon\bin\apache\*\modules\php*apache*.dll",
      "$d\Apache24\modules\php*apache*.dll",
      "$d\Program Files\Apache Software Foundation\Apache2.4\modules\php*apache*.dll",
      "$d\Bitnami\*\php\php*apache*.dll"
    ))
  }
  foreach ($sr in $ServerRoots) { $globs.Add("$sr\modules\php*apache*.dll") }
  $res = New-Object System.Collections.Generic.List[object]
  foreach ($g in $globs) {
    foreach ($f in (Get-Item -Path $g -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
      $res.Add($f)
    }
  }
  $res | Sort-Object -Property FullName -Unique
}

function Invoke-PhpVersionCheck {
  Sec "0. PHP version vs php2shell fixes (CVE-2026-109618 / CVE-2026-109619)"
  $any = $false
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

  # Versions come from the PE resource, not from running the binary: faster, and
  # it does not execute a possibly tampered php.ini (auto_prepend_file) on a
  # host we are still deciding whether to trust.
  foreach ($bin in (Find-PhpBinaries)) {
    $v = Get-FileVersionTriple $bin
    if (-not $v) { continue }
    if (-not $seen.Add("$v|$(Split-Path -Leaf $bin)")) { continue }
    $any = $true
    Say ('  {0,-14} {1,-10} {2}' -f (Split-Path -Leaf $bin), $v, (Get-PhpVersionVerdict $v))
    Say ("                 $bin")
  }

  $mods = Find-PhpApacheModules
  if ($mods) {
    $any = $true
    Say '  mod_php module(s) present - this is the highest-risk SAPI:'
    foreach ($m in $mods) {
      $v = Get-FileVersionTriple $m.FullName
      if ($v) { Say ('    {0,-10} {1}  [{2}]' -f $v, (Get-PhpVersionVerdict $v), $m.FullName) }
      else    { Say ("    (version unreadable)  [{0}]" -f $m.FullName) }
    }
  }

  # Which SAPI is actually serving right now?
  $running = Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match '^(php|php-cgi|php-fpm|httpd|nginx|w3wp)\.exe$' } |
    Group-Object -Property Name
  if ($running) {
    Say ('  running: ' + (($running | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '))
  }

  if (-not $any) {
    Say '  (no PHP binary or module found - pass -WebRoot/-LogDir if this stack lives somewhere unusual)'
  }
  Say "  $FixedTrail mod_php is the highest-risk SAPI."
}

# ---------------- log reading ----------------
# Opens a plain or .gz log as a StreamReader. Caller disposes.
function Open-LogReader {
  param([string]$Path)
  try {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  } catch { return $null }
  if ($Path -match '\.gz$') {
    try {
      $gz = New-Object System.IO.Compression.GzipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
      return New-Object System.IO.StreamReader($gz)
    } catch { $fs.Dispose(); return $null }
  }
  return New-Object System.IO.StreamReader($fs)
}

function Get-LogFiles {
  param([string[]]$Dirs, [string]$Kind)   # Kind: access | error
  $res = New-Object System.Collections.Generic.List[object]
  foreach ($d in $Dirs) {
    foreach ($f in (Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)) {
      $n = $f.Name
      $isGz = $n -match '\.gz$'
      $isLog = $n -match '\.(log|txt)(\.\d+|\.gz)?$' -or $isGz -or $n -match '_log(\.\d+)?$'
      if (-not $isLog) { continue }
      if ($Kind -eq 'access') {
        # IIS W3C logs (u_ex*.log / ex*.log) are access logs too.
        if ($n -match 'access|^u?_?ex\d|^W3SVC') { $res.Add($f) }
      } else {
        if ($n -match 'error|php_error|php-error') { $res.Add($f) }
      }
    }
  }
  $res
}

# IIS writes W3C extended logs: space separated, no quotes, and the column
# order is declared by a "#Fields:" header that can reappear mid-file.
function Get-W3cField {
  param([string[]]$Tokens, [hashtable]$Map, [string]$Name)
  if (-not $Map.ContainsKey($Name)) { return '' }
  $ix = $Map[$Name]
  if ($ix -ge $Tokens.Length) { return '' }
  $v = $Tokens[$ix]
  if ($v -eq '-') { return '' }
  return $v
}

# "14/Oct/2026" (Apache access), "Oct 22" (Apache error), "22-Oct-2026" (PHP
# error_log) and "2026-10-22" (IIS) all normalise to a sortable yyyy-MM-dd.
$MONTHS = @{ jan=1; feb=2; mar=3; apr=4; may=5; jun=6; jul=7; aug=8; sep=9; oct=10; nov=11; dec=12 }
function ConvertTo-DayKey {
  param([string]$Raw)
  if (-not $Raw) { return '?' }
  $m = [regex]::Match($Raw, '^(\d{1,2})[/-]([A-Za-z]{3})[/-](\d{4})')
  if ($m.Success) {
    $mo = $MONTHS[$m.Groups[2].Value.ToLower()]
    if ($mo) { return ('{0:d4}-{1:d2}-{2:d2}' -f [int]$m.Groups[3].Value, [int]$mo, [int]$m.Groups[1].Value) }
  }
  $m = [regex]::Match($Raw, '^(\d{4})-(\d{2})-(\d{2})')
  if ($m.Success) { return $m.Value }
  # Apache error log: "Wed Oct 22 10:00:06.123456 2026" - the year is at the end.
  $m = [regex]::Match($Raw, '^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+[\d:.]+\s+(\d{4})')
  if ($m.Success) {
    $mo = $MONTHS[$m.Groups[1].Value.ToLower()]
    if ($mo) { return ('{0:d4}-{1:d2}-{2:d2}' -f [int]$m.Groups[3].Value, [int]$mo, [int]$m.Groups[2].Value) }
  }
  $m = [regex]::Match($Raw, '^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})')   # no year available
  if ($m.Success) {
    $mo = $MONTHS[$m.Groups[1].Value.ToLower()]
    if ($mo) { return ('0000-{0:d2}-{1:d2}' -f [int]$mo, [int]$m.Groups[2].Value) }
  }
  return '?'
}

# ---------------- IOC pattern set (mirrors php-hunt.sh) ----------------
$IOC_DEFS = @(
  @{ Name = 'php ini injection (allow_url_include/auto_prepend/-d)'
     Rx   = 'allow_url_include|auto_prepend_file|auto_append_file|%2dd\+|(\?|&)-d[+ %]|\?-[sdn]([^a-z0-9]|$)' },
  @{ Name = 'soft-hyphen arg injection (CVE-2024-4577 style %AD)'
     Rx   = '%ad' },
  @{ Name = 'php:// / data:// / expect:// / phar:// wrappers'
     Rx   = 'php(%3a|:)(%2f|/)(%2f|/)|data(%3a|:)(%2f|/)*text|expect(%3a|:)|phar(%3a|:)' },
  @{ Name = 'php-cgi / cgi-bin probing'
     Rx   = '/cgi-bin/|php-cgi|php5?\.cgi' },
  @{ Name = 'phpunit eval-stdin / known PHP RCE paths'
     Rx   = 'eval-stdin|invokefunction|call_user_func|_ignition|think\\app|vendor/phpunit' },
  @{ Name = 'code in URL (system/exec/base64/<?php)'
     Rx   = '(<|%3c)\?php|base64_decode|shell_exec|passthru|(^|[^a-z0-9_])system\(|(^|[^a-z0-9_])exec\(|assert\(|phpinfo|die\(|md5\(' },
  @{ Name = 'security scanner fingerprints (watchTowr/calif/php2shell; CVE-2026-109618/109619 has no public request signature)'
     Rx   = 'php2shell|calif\.io|watchtowr|nuclei|projectdiscovery' },
  @{ Name = 'path traversal'
     Rx   = '\.\./|%2e%2e|\.\.\\|%5c\.\.' },
  @{ Name = 'xdebug / php debug triggers'
     Rx   = 'xdebug_session|xdebug_trigger|xdebug_profile' },
  @{ Name = 'Windows-specific LOLBin / UNC in request'
     Rx   = 'cmd(\.exe)?(\+|%20|\?)|powershell|certutil|bitsadmin|mshta|wscript|cscript|%5c%5c[a-z0-9]|c(:|%3a)(/|\\|%5c)' }
)

$CRASH_RX  = [regex]::new('exit signal|segmentation fault|segfault|aborted|core dump|zend_mm_heap corrupted|heap corrupt|double free|stack smashing|out of memory|possible integer overflow|cannot allocate memory|ah00052|ah00051|child process .* exited|parent: child process exited with status',
              'Compiled, IgnoreCase')
$ENGINE_RX = [regex]::new('input variables exceeded|post content-length|missing boundary|multipart|request body limit|allowed memory size|maximum execution time|unable to allocate|file created in the system|max_file_uploads|invalid argument supplied for foreach\(\) in unknown',
              'Compiled, IgnoreCase')
$PHPERR_RX = [regex]::new('php (fatal error|parse error|warning|notice|deprecated|catchable)[^:]*:', 'Compiled, IgnoreCase')
$NUM_RX    = [regex]::new('\d+', 'Compiled')

# Compile the IOC regexes once, plus one combined pre-filter so the common
# (uninteresting) log line costs a single match instead of one per pattern.
$IOC_RX = @()
foreach ($d in $IOC_DEFS) { $IOC_RX += [regex]::new($d.Rx, 'Compiled, IgnoreCase') }
$IOC_PRE = [regex]::new((($IOC_DEFS | ForEach-Object { $_.Rx }) -join '|'), 'Compiled, IgnoreCase')

$TRUSTED = @()
if ($TrustedUa) { $TRUSTED = $TrustedUa | ForEach-Object { $_.ToLower() } }
function Test-Trusted {
  param([string]$UaLower)
  if (-not $TRUSTED) { return $false }
  foreach ($t in $TRUSTED) { if ($t -and $UaLower.Contains($t)) { return $true } }
  return $false
}

# ---------------- report header ----------------
$osName = (Get-CimInstance Win32_OperatingSystem).Caption
$psVer  = $PSVersionTable.PSVersion.ToString()
Say "phphunt v$VERSION - read-only PHP exploitation hunt (Windows / PowerShell)"
Say ("  host: {0}   date: {1}" -f $env:COMPUTERNAME, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Say ("  platform: {0} (PowerShell {1})" -f $osName, $psVer)
Say ("  file window: since {0}" -f $SinceLabel)
if ($LOGDIRS)  { Say ("  log dirs: " + ($LOGDIRS  -join '  ')) } else { Say "  log dirs: (none found - pass -LogDir)" }
if ($WEBROOTS) { Say ("  webroots: " + ($WEBROOTS -join '  ')) } else { Say "  webroots: (none found - pass -WebRoot)" }
if (-not $IsAdmin) {
  Say "  NOTE: not elevated - logs, other users' processes and ACLs will be partly unreadable."
  Say "        Re-run from an Administrator PowerShell for full coverage."
}

Invoke-PhpVersionCheck

# ================= PART A: log analysis =================
if (-not $OnlyPostex) {

  $accessFiles = Get-LogFiles -Dirs $LOGDIRS -Kind access
  $errorFiles  = Get-LogFiles -Dirs $LOGDIRS -Kind error

  # --- error logs ---
  $crashTotal = 0; $crashSamples = New-Object System.Collections.Generic.List[string]
  $engTotal   = 0; $engSamples   = New-Object System.Collections.Generic.List[string]
  $phpErr = @{}; $phpErrDay = @{}
  $unreadable = New-Object System.Collections.Generic.List[string]

  $i = 0
  foreach ($f in $errorFiles) {
    $i++
    Prog ("[logs] error log {0}/{1}: {2} ({3})" -f $i, $errorFiles.Count, $f.Name, (HumanSize $f.Length))
    $r = Open-LogReader $f.FullName
    if (-not $r) { $unreadable.Add($f.FullName); continue }
    try {
      while ($null -ne ($line = $r.ReadLine())) {
        if ($CRASH_RX.IsMatch($line)) {
          $crashTotal++
          if ($crashSamples.Count -lt 20) {
            $s = $line; if ($s.Length -gt 260) { $s = $s.Substring(0, 260) }
            $crashSamples.Add("$($f.Name): $s")
          }
        }
        if ($ENGINE_RX.IsMatch($line)) {
          $engTotal++
          if ($engSamples.Count -lt 15) {
            $s = $line; if ($s.Length -gt 260) { $s = $s.Substring(0, 260) }
            $engSamples.Add("$($f.Name): $s")
          }
        }
        $m = $PHPERR_RX.Match($line)
        if ($m.Success) {
          $msg = $line.Substring($m.Index)
          if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) }
          Bump $phpErr $($NUM_RX.Replace($msg, 'N')) 1 $MAX_KEYS
          $lb = $line.IndexOf('[')
          if ($lb -ge 0) {
            $rb = $line.IndexOf(']', $lb)
            if ($rb -gt $lb) {
              $inside = $line.Substring($lb + 1, $rb - $lb - 1)
              # Apache: "Wed Oct 22 10:00:05 2026"  PHP: "22-Oct-2026 10:00:07 UTC"
              $day = ConvertTo-DayKey $inside
              if ($day -eq '?' -and $inside.Length -gt 4) { $day = ConvertTo-DayKey ($inside.Substring(4)) }
              if ($day -ne '?') { Bump $phpErrDay $day 1 $MAX_SMALLKEYS }
            }
          }
        }
      }
    } finally { $r.Dispose() }
  }

  # --- access logs ---
  $tot = @{}; $postDay = @{}; $e5Day = @{}
  $path5 = @{}; $pathPost = @{}; $methods = @{}; $uaPhp = @{}
  $badReq = New-Object System.Collections.Generic.List[string]
  $iocHits = @{}; $ioc2xx = @{}; $iocDay = @{}; $iocIp = @{}; $iocSample = @{}
  for ($k = 0; $k -lt $IOC_DEFS.Count; $k++) {
    $iocHits[$k] = 0; $ioc2xx[$k] = 0
    $iocDay[$k] = @{}; $iocIp[$k] = @{}
    $iocSample[$k] = New-Object System.Collections.Generic.List[string]
  }

  $i = 0
  foreach ($f in $accessFiles) {
    $i++
    $tag = "[logs] access log {0}/{1}: {2} ({3})" -f $i, $accessFiles.Count, $f.Name, (HumanSize $f.Length)
    Prog $tag
    $r = Open-LogReader $f.FullName
    if (-not $r) { $unreadable.Add($f.FullName); continue }
    $n = 0
    $w3c = $null          # non-null once a "#Fields:" header is seen: IIS format
    try {
      while ($null -ne ($line = $r.ReadLine())) {
        $n++
        if (($n % 200000) -eq 0) { Prog ("$tag - $n lines...") }
        if ($line.Length -lt 8) { continue }

        if ($line[0] -eq '#') {
          if ($line.StartsWith('#Fields:', [StringComparison]::OrdinalIgnoreCase)) {
            $w3c = @{}
            $names = $line.Substring(8).Trim().Split([char[]]@(' '), [StringSplitOptions]::RemoveEmptyEntries)
            for ($x = 0; $x -lt $names.Length; $x++) { $w3c[$names[$x].ToLower()] = $x }
          }
          continue
        }

        $req = ''; $ua = ''; $st = 0; $day = '?'; $ip = ''; $vhost = ''; $meth = ''; $path = ''

        if ($w3c) {
          # ---- IIS / W3C extended ----
          $t = $line.Split([char[]]@(' '), [StringSplitOptions]::RemoveEmptyEntries)
          $meth  = Get-W3cField $t $w3c 'cs-method'
          $path  = Get-W3cField $t $w3c 'cs-uri-stem'
          $query = Get-W3cField $t $w3c 'cs-uri-query'
          $ip    = Get-W3cField $t $w3c 'c-ip'
          $ua    = (Get-W3cField $t $w3c 'cs(user-agent)').Replace('+', ' ')
          $vhost = Get-W3cField $t $w3c 'cs-host'
          if (-not $vhost) { $vhost = Get-W3cField $t $w3c 's-ip' }
          [void][int]::TryParse((Get-W3cField $t $w3c 'sc-status'), [ref]$st)
          $day = ConvertTo-DayKey (Get-W3cField $t $w3c 'date')
          # Rebuild a request line so the IOC patterns see method + path + query.
          $req = $meth + ' ' + $path + $(if ($query) { '?' + $query } else { '' })
        } else {
          # ---- Apache / NCSA combined ----
          $q = $line.Split([char]34)
          if ($q.Length -lt 2) { continue }
          $pre = $q[0]; $req = $q[1]
          $ua  = if ($q.Length -ge 7) { $q[5] } else { '' }

          if ($q.Length -ge 3) {
            $rest = $q[2].Trim()
            if ($rest) {
              $sp = $rest.IndexOf(' ')
              $stTok = if ($sp -gt 0) { $rest.Substring(0, $sp) } else { $rest }
              [void][int]::TryParse($stTok, [ref]$st)
            }
          }

          $lb = $pre.IndexOf('['); $rb = $pre.IndexOf(']')
          if ($lb -ge 0 -and $rb -gt $lb) {
            $ts = $pre.Substring($lb + 1, $rb - $lb - 1)
            $c = $ts.IndexOf(':')
            $day = ConvertTo-DayKey $(if ($c -gt 1) { $ts.Substring(0, $c) } else { $ts })
          }

          # char[] overload: Split(char, StringSplitOptions) does not exist on
          # .NET Framework 4.x, i.e. on stock PowerShell 5.1.
          $t = $pre.Split([char[]]@(' '), [StringSplitOptions]::RemoveEmptyEntries)
          if ($t.Length -ge 2 -and $t[1] -match '\d') { $ip = $t[1]; $vhost = $t[0] }
          elseif ($t.Length -ge 1 -and $t[0] -match '\d') { $ip = $t[0] }

          $rp = $req.Split(' ')
          $meth = if ($rp.Length -gt 0) { $rp[0] } else { '' }
          $path = if ($rp.Length -gt 1) { $rp[1] } else { $req }
          $qm = $path.IndexOf('?')
          if ($qm -ge 0) { $path = $path.Substring(0, $qm) }
        }

        if (-not $vhost) { $vhost = $f.Name }
        Bump $tot $day 1 $MAX_SMALLKEYS
        # Normalising digit runs in the key keeps /orders/12345/ from minting a
        # new counter per request - bounds memory and makes the table readable.
        $pk = $path
        if ($path -match '\d') {
          $segs = $path.Split('/')
          for ($z = 0; $z -lt $segs.Length; $z++) { if ($segs[$z] -match '^\d+$') { $segs[$z] = 'N' } }
          $pk = $segs -join '/'
        }
        if ($pk.Length -gt 200) { $pk = $pk.Substring(0, 200) }

        $lreq = $req.ToLower(); $lua = $ua.ToLower()

        if ($st -ge 500) {
          Bump $e5Day $day 1 $MAX_SMALLKEYS
          Bump $path5 "$vhost`t$pk`t$st" 1 $MAX_KEYS
        }
        if ($meth -eq 'POST') {
          Bump $postDay $day 1 $MAX_SMALLKEYS
          if (-not (Test-Trusted $lua)) { Bump $pathPost "$vhost`t$pk`t$st" 1 $MAX_KEYS }
        }
        if ($meth -and @('GET','POST','HEAD','OPTIONS','PUT','DELETE','PATCH') -notcontains $meth) {
          $mk = if ($meth.Length -gt 20) { $meth.Substring(0, 20) } else { $meth }
          Bump $methods $mk 1 $MAX_SMALLKEYS
          if ($badReq.Count -lt 8) {
            $s = $line; if ($s.Length -gt 240) { $s = $s.Substring(0, 240) }
            $badReq.Add($s)
          }
        }

        if ($IOC_PRE.IsMatch($lreq) -or ($lua -and $IOC_PRE.IsMatch($lua))) {
          for ($k = 0; $k -lt $IOC_RX.Count; $k++) {
            if ($IOC_RX[$k].IsMatch($lreq) -or ($lua -and $IOC_RX[$k].IsMatch($lua))) {
              $iocHits[$k]++
              if ($st -ge 200 -and $st -lt 300) { $ioc2xx[$k]++ }
              Bump $iocDay[$k] $day 1 $MAX_SMALLKEYS
              if ($ip) { Bump $iocIp[$k] $ip 1 $MAX_KEYS }
              if ($iocSample[$k].Count -lt 6) {
                $s = $line; if ($s.Length -gt 240) { $s = $s.Substring(0, 240) }
                $iocSample[$k].Add($s)
              }
            }
          }
        }

        if ($lua -and $lua.Contains('php') -and -not (Test-Trusted $lua)) {
          $k2 = if ($lua.Length -gt 90) { $lua.Substring(0, 90) } else { $lua }
          Bump $uaPhp $k2 1 $MAX_SMALLKEYS
        }
      }
    } finally { $r.Dispose() }
  }
  ProgDone

  Say ''
  Say ("---- part A: logs ({0} access, {1} error files) ----" -f $accessFiles.Count, $errorFiles.Count)
  foreach ($u in $unreadable) { Say "  !! cannot read $u" }

  Sec '1. WORKER CRASHES (segfault/abort/heap corruption)'
  Say "  total: $crashTotal"
  foreach ($s in $crashSamples) { Say "  $s" }

  Sec '2. PHP ENGINE/REQUEST-PARSING ERRORS (multipart, limits, memory)'
  Say "  total: $engTotal"
  foreach ($s in $engSamples) { Say "  $s" }

  Sec '3. PHP errors in error logs (top messages, numbers normalised)'
  foreach ($e in (Top $phpErr 15)) { Say ('  {0,6}  {1}' -f $e.Value, $e.Key) }

  Sec '4. KNOWN PHP-ATTACK PATTERNS IN REQUESTS'
  for ($k = 0; $k -lt $IOC_DEFS.Count; $k++) {
    if ($iocHits[$k] -le 0) { continue }
    Say ('  [{0,5} hits, {1} answered 2xx] {2}' -f $iocHits[$k], $ioc2xx[$k], $IOC_DEFS[$k].Name)
    foreach ($s in $iocSample[$k]) { Say "        $s" }
    $days = (Top $iocDay[$k] 8 | Sort-Object -Property Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
    if ($days) { Say "        by day: $days" }
    $ips = (Top $iocIp[$k] 5 | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
    if ($ips) { Say "        top IPs: $ips" }
  }

  Sec '5. POST requests (host, path, status)'
  foreach ($e in (Top $pathPost 25)) { Say ('  {0}  {1}' -f $e.Value, ($e.Key -replace "`t", '  ')) }

  Sec '6. 5xx responses (host, path, status)'
  foreach ($e in (Top $path5 15)) { Say ('  {0}  {1}' -f $e.Value, ($e.Key -replace "`t", '  ')) }

  Sec '7. Unusual HTTP methods / malformed requests'
  foreach ($e in (Top $methods 10)) { Say ('  {0,6}  {1}' -f $e.Value, $e.Key) }
  foreach ($s in $badReq) { Say "        $s" }

  Sec '8. Untrusted user agents mentioning PHP'
  foreach ($e in (Top $uaPhp 8)) { Say ('  {0,6}  {1}' -f $e.Value, $e.Key) }

  Sec '9. Traffic per day (total / POST / 5xx)'
  foreach ($d in ($tot.Keys | Sort-Object | Select-Object -Last 16)) {
    $p = 0; if ($postDay.ContainsKey($d)) { $p = $postDay[$d] }
    $e = 0; if ($e5Day.ContainsKey($d))   { $e = $e5Day[$d] }
    Say ('  {0,-12} {1,7} / {2,6} / {3,5}' -f $d, $tot[$d], $p, $e)
  }

  Sec '10. PHP errors per day (error logs)'
  $pd = ($phpErrDay.Keys | Sort-Object | Select-Object -Last 16 | ForEach-Object { "$_=$($phpErrDay[$_])" }) -join ' '
  if ($pd) { Say "  $pd" }
}

# ================= PART B: on-host checks =================
$PHP_EXT  = @('.php','.phtml','.phar','.php3','.php4','.php5','.php7','.php8','.phps','.inc')
$PHP_NAME = @('.htaccess','.user.ini','web.config')
$IMG_EXT  = @('.jpg','.jpeg','.png','.gif','.ico','.bmp','.svg','.webp','.txt','.log','.css','.pdf')

# Latin-1 maps every byte to one char, so a binary file (an image with PHP
# appended) is searched as reliably as a text file and nothing is mis-decoded.
$LATIN1 = [System.Text.Encoding]::GetEncoding(28591)

$WEBSHELL_RX = [regex]::new(
  'eval\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|gzuncompress|str_rot13)' +
  '|assert\s*\(\s*\$_(GET|POST|REQUEST)' +
  '|(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)' +
  '|preg_replace\s*\(.*/e[^a-z]' +
  '|create_function\s*\(\s*.?.?,' +
  '|\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*\(' +
  '|new\s+COM\s*\(\s*[''"]WScript\.Shell|Shell\.Application', 'Compiled, IgnoreCase')

$RECON_RX = [regex]::new(
  '/dev/tcp/|fsockopen\s*\(|proc_open\s*\(|pcntl_exec\s*\(|169\.254\.169\.254|aws/credentials' +
  '|kubernetes\.io/serviceaccount|/etc/shadow' +
  '|WScript\.Shell|powershell\s+(-|/)(e|enc|encodedcommand|nop|w\s+hidden)' +
  '|Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|certutil\s+(-|/)urlcache' +
  '|bitsadmin\s+/transfer|cmd(\.exe)?\s*/c\s|reg\s+add\s+.*\\Run', 'Compiled, IgnoreCase')

$PHP_MARK_RX = [regex]::new('<\?php|<\?=', 'Compiled, IgnoreCase')

function Read-ScanText {
  param([System.IO.FileInfo]$File)
  if ($File.Length -le 0 -or $File.Length -gt ($MAX_SCAN_MB * 1MB)) { return $null }
  try { return $LATIN1.GetString([System.IO.File]::ReadAllBytes($File.FullName)) } catch { return $null }
}

function Test-PhpIsh {
  param([System.IO.FileInfo]$File)
  ($PHP_EXT -contains $File.Extension.ToLower()) -or ($PHP_NAME -contains $File.Name.ToLower())
}

# One enumeration per webroot, reused by every file-based section below.
function Get-WebrootIndex {
  param([string]$Root)
  $files = New-Object System.Collections.Generic.List[object]
  $stack = New-Object System.Collections.Generic.Stack[string]
  $stack.Push($Root)
  $truncated = $false; $dirs = 0; $denied = 0
  while ($stack.Count -gt 0) {
    $d = $stack.Pop(); $dirs++
    if (($dirs % 400) -eq 0) { Prog ("[host] indexing {0}: {1} dirs, {2} files..." -f $Root, $dirs, $files.Count) }
    $di = $null
    try { $di = New-Object System.IO.DirectoryInfo $d } catch { continue }
    try {
      foreach ($sd in $di.EnumerateDirectories()) {
        # never follow junctions/symlinks: they make the walk cyclic
        if (($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) { continue }
        $stack.Push($sd.FullName)
      }
    } catch { $denied++ }
    try {
      foreach ($f in $di.EnumerateFiles()) {
        if ($files.Count -ge $MAX_FILES) { $truncated = $true; break }
        $files.Add($f)
      }
    } catch { $denied++ }
    if ($truncated) { break }
  }
  [pscustomobject]@{ Root = $Root; Files = $files; Dirs = $dirs; Denied = $denied; Truncated = $truncated }
}

function Invoke-PostexWindows {

  # ---- index every webroot once ----
  $index = New-Object System.Collections.Generic.List[object]
  foreach ($r in $WEBROOTS) {
    Prog "[host] indexing $r..."
    $index.Add((Get-WebrootIndex $r))
  }
  ProgDone

  Sec "11. PHP-executable files changed in webroots since $SinceLabel (newest first)"
  $totChanged = 0
  $changedAll = New-Object System.Collections.Generic.List[object]
  foreach ($ix in $index) {
    $hits = @($ix.Files | Where-Object { $_.LastWriteTime -ge $SinceDate -and (Test-PhpIsh $_) })
    $totChanged += $hits.Count
    foreach ($h in $hits) { $changedAll.Add($h) }
    Say ('  -- {0} ({1} changed of {2} files indexed{3})' -f $ix.Root, $hits.Count, $ix.Files.Count,
         $(if ($ix.Truncated) { ", TRUNCATED at $MAX_FILES" } else { '' }))
    if ($ix.Denied -gt 0) { Say ("     ({0} directories unreadable - re-run elevated)" -f $ix.Denied) }
    foreach ($h in ($hits | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 40)) {
      Say ('  {0:yyyy-MM-dd HH:mm}  {1,9}  {2}' -f $h.LastWriteTime, $h.Length, $h.FullName)
    }
  }
  if ($totChanged -eq 0) { Say '   total: 0' }

  Sec '12. webroot PHP writable by low-privilege identities (ACL audit)'
  # The Windows analogue of "owned by www-data": a PHP file the web identity or
  # any interactive user can rewrite is a webshell waiting to happen.
  $loose = @('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users','IUSR',
             'BUILTIN\IIS_IUSRS','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\IUSR','Tous','Jeder')
  $checked = 0; $flagged = 0
  # Build the sample explicitly: `@($list) + @($array)` of FileInfo throws
  # "Argument types do not match" (PowerShell tries to keep the left operand's
  # element type), and with SilentlyContinue that failure is invisible.
  $sample = New-Object System.Collections.Generic.List[object]
  $seenAcl = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($f in $changedAll) { if ($seenAcl.Add($f.FullName)) { $sample.Add($f) } }
  foreach ($ix in $index) {
    $taken = 0
    foreach ($f in $ix.Files) {
      if ($sample.Count -ge 400) { break }
      if (-not (Test-PhpIsh $f)) { continue }
      if (-not $seenAcl.Add($f.FullName)) { continue }
      $sample.Add($f); $taken++
      if ($taken -ge 200) { break }
    }
  }
  foreach ($f in $sample) {
    $checked++
    if (($checked % 50) -eq 0) { Prog "[host] ACL audit: $checked files..." }
    $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction SilentlyContinue
    if (-not $acl) { continue }
    foreach ($ace in $acl.Access) {
      if ($ace.AccessControlType -ne 'Allow') { continue }
      if ($loose -notcontains $ace.IdentityReference.Value) { continue }
      if ($ace.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles|ChangePermissions|TakeOwnership') {
        if ($flagged -lt 20) {
          Say ('  {0}  <- {1} : {2}' -f $f.FullName, $ace.IdentityReference.Value, $ace.FileSystemRights)
        }
        $flagged++
        break
      }
    }
  }
  ProgDone
  if (-not (Get-Command Get-Acl -ErrorAction SilentlyContinue)) {
    Say '   (Get-Acl unavailable on this platform - ACL audit skipped)'
  } else {
    Say ("   ({0} of {1} sampled files grant write to a low-privilege identity)" -f $flagged, $checked)
  }

  Sec '13. PHP files under upload/cache/tmp-like dirs in webroots'
  $n13 = 0
  $uploadish = [regex]::new('[\\/](uploads?|cache|tmp|temp|images?|img|media|files|assets|avatars?|attachments?)([\\/]|$)', 'Compiled, IgnoreCase')
  foreach ($ix in $index) {
    # Match only the part of the path below the webroot: a webroot that itself
    # sits in C:\temp\www must not make every file a hit.
    $rootLen = $ix.Root.TrimEnd('\', '/').Length
    foreach ($f in $ix.Files) {
      if (-not (Test-PhpIsh $f)) { continue }
      $dir = $f.DirectoryName
      $rel = if ($dir.Length -gt $rootLen) { $dir.Substring($rootLen) } else { '' }
      if (-not $uploadish.IsMatch($rel)) { continue }
      if ($n13 -lt 20) { Say ('  {0:yyyy-MM-dd HH:mm}  {1}' -f $f.LastWriteTime, $f.FullName) }
      $n13++
    }
  }
  if ($n13 -eq 0) { Say '   (none)' } elseif ($n13 -gt 20) { Say "   ... and $($n13 - 20) more" }

  Sec '14. webshell-ish code in webroot PHP (eval/assert/exec on request input, base64+eval, COM/WScript.Shell)'
  $n14 = 0; $scanned = 0
  foreach ($ix in $index) {
    foreach ($f in $ix.Files) {
      if (-not (Test-PhpIsh $f)) { continue }
      $scanned++
      if (($scanned % 500) -eq 0) { Prog "[host] webshell scan: $scanned files..." }
      $txt = Read-ScanText $f
      if (-not $txt) { continue }
      if ($WEBSHELL_RX.IsMatch($txt)) {
        if ($n14 -lt 25) { Say ('  {0:yyyy-MM-dd HH:mm}  {1}' -f $f.LastWriteTime, $f.FullName) }
        $n14++
      }
    }
  }
  ProgDone
  if ($n14 -eq 0) { Say "   (none in $scanned PHP files)" } elseif ($n14 -gt 25) { Say "   ... and $($n14 - 25) more" }

  Sec '15. Apache / PHP processes'
  $procs = @(Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match '^(httpd|Apache|php|php-cgi|php-fpm|nginx|caddy|w3wp)\.exe$' })
  if ($procs) {
    foreach ($g in ($procs | Group-Object -Property Name)) { Say ('  {0,-14} x{1}' -f $g.Name, $g.Count) }
    foreach ($p in ($procs | Select-Object -First 15)) {
      $owner = ''
      try {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)" }
      } catch {}
      $cl = $p.CommandLine; if ($cl -and $cl.Length -gt 140) { $cl = $cl.Substring(0, 140) }
      Say ('  pid={0} ppid={1} user={2} started={3:yyyy-MM-dd HH:mm}  {4}' -f $p.ProcessId, $p.ParentProcessId, $owner, $p.CreationDate, $cl)
    }
  } else { Say '   (no Apache/PHP/IIS worker process running)' }

  Sec "16. web server spawning shells / payload commands (Elastic 'Payload Execution by Web Server')"
  $all = @(Get-CimInstance Win32_Process)
  $byPid = @{}
  foreach ($p in $all) { $byPid[[string]$p.ProcessId] = $p }
  $webParents = '^(httpd|Apache|php|php-cgi|php-fpm|nginx|caddy|w3wp)\.exe$'
  $expected   = @('httpd.exe','apache.exe','php.exe','php-cgi.exe','php-fpm.exe','rotatelogs.exe','conhost.exe','nginx.exe','caddy.exe','w3wp.exe')
  $badChild   = '^(cmd|powershell|pwsh|wscript|cscript|mshta|certutil|bitsadmin|curl|ftp|net|net1|whoami|systeminfo|reg|rundll32|regsvr32|schtasks|sc|nltest|ping|nslookup|tasklist|attrib|icacls|vssadmin|wmic|msiexec|hh|installutil|regasm|regsvcs|forfiles|at)\.exe$'
  $n16 = 0
  foreach ($p in $all) {
    $par = $byPid[[string]$p.ParentProcessId]
    if (-not $par) { continue }
    if ($par.Name -notmatch $webParents) { continue }
    if ($expected -contains $p.Name.ToLower()) { continue }
    $mark = if ($p.Name -match $badChild) { '!!' } else { '  ' }
    $cl = $p.CommandLine; if ($cl -and $cl.Length -gt 160) { $cl = $cl.Substring(0, 160) }
    Say ('  {0} pid={1} ppid={2}({3})  {4}' -f $mark, $p.ProcessId, $p.ParentProcessId, $par.Name, $(if ($cl) { $cl } else { $p.Name }))
    $n16++
  }
  if ($n16 -eq 0) { Say '  (point-in-time: empty = no web-server process currently has a non-PHP child)' }
  else { Say '  (!! = known payload/LOLBin. An httpd.exe or w3wp.exe with a cmd/powershell child is a webshell signature.)' }

  Sec '17. network connections of httpd / php (non-80/443 remote, or unexpected listeners)'
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $n17 = 0
    foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
      $op = $byPid[[string]$c.OwningProcess]
      if (-not $op -or $op.Name -notmatch $webParents) { continue }
      if ($c.State -eq 'Listen') {
        if (@(80, 443, 8080, 8443) -contains $c.LocalPort) { continue }
        Say ('  LISTEN  {0}:{1}  [{2} pid {3}]' -f $c.LocalAddress, $c.LocalPort, $op.Name, $c.OwningProcess)
      } else {
        if (@(80, 443) -contains $c.RemotePort) { continue }
        if ($c.RemoteAddress -eq '0.0.0.0' -or $c.RemoteAddress -eq '::') { continue }
        Say ('  {0,-22} -> {1}:{2}  {3}  [{4} pid {5}]' -f "$($c.LocalAddress):$($c.LocalPort)", $c.RemoteAddress, $c.RemotePort, $c.State, $op.Name, $c.OwningProcess)
      }
      $n17++
      if ($n17 -ge 20) { break }
    }
    if ($n17 -eq 0) { Say '   (none)' }
  } else {
    # Pre-Win8 fallback. The State column is localised, so key off the remote
    # address (0.0.0.0:0 = listening) instead of matching "LISTENING".
    $n17 = 0
    foreach ($l in (& netstat.exe -ano 2>$null)) {
      $t = $l.Trim() -split '\s+'
      if ($t.Count -lt 4 -or $t[0] -ne 'TCP') { continue }
      $procPid = $t[$t.Count - 1]
      $op = $byPid[$procPid]
      if (-not $op -or $op.Name -notmatch $webParents) { continue }
      $rport = ($t[2] -split ':')[-1]
      if (@('80','443','0') -contains $rport) { continue }
      Say ('  {0} -> {1}  [{2} pid {3}]' -f $t[1], $t[2], $op.Name, $procPid)
      $n17++
      if ($n17 -ge 20) { break }
    }
    if ($n17 -eq 0) { Say '   (none)' }
  }

  Sec '18. suspicious uploads: PHP double-extensions & image polyglots'
  $n18 = 0
  foreach ($ix in $index) {
    foreach ($f in $ix.Files) {
      if ($f.Name -match '\.(php|phtml|phar|php[3-8]|phps)\.[a-z0-9]+$') {
        if ($n18 -lt 25) { Say ('  double-ext  {0:yyyy-MM-dd HH:mm}  {1}' -f $f.LastWriteTime, $f.FullName) }
        $n18++
      }
    }
  }
  $polyScanned = 0
  foreach ($ix in $index) {
    foreach ($f in $ix.Files) {
      if ($polyScanned -ge $MAX_POLYGLOT) { break }
      if ($IMG_EXT -notcontains $f.Extension.ToLower()) { continue }
      if ($f.LastWriteTime -lt $SinceDate) { continue }
      $polyScanned++
      if (($polyScanned % 500) -eq 0) { Prog "[host] polyglot scan: $polyScanned files..." }
      $txt = Read-ScanText $f
      if (-not $txt) { continue }
      if ($PHP_MARK_RX.IsMatch($txt)) {
        if ($n18 -lt 25) { Say ('  polyglot    {0:yyyy-MM-dd HH:mm}  {1}' -f $f.LastWriteTime, $f.FullName) }
        $n18++
      }
    }
  }
  ProgDone
  if ($n18 -eq 0) { Say "   (none; $polyScanned image/text files byte-scanned for embedded PHP)" }
  elseif ($n18 -gt 25) { Say "   ... and $($n18 - 25) more" }

  Sec "19. recon / reverse-shell / LOLBin / cloud-metadata strings in files changed since $SinceLabel"
  $n19 = 0
  foreach ($f in $changedAll) {
    $txt = Read-ScanText $f
    if (-not $txt) { continue }
    $m = $RECON_RX.Match($txt)
    if ($m.Success) {
      if ($n19 -lt 25) { Say ('  {0}   [{1}]' -f $f.FullName, $m.Value) }
      $n19++
    }
  }
  if ($n19 -eq 0) { Say '   (none)' } elseif ($n19 -gt 25) { Say "   ... and $($n19 - 25) more" }

  Sec '20. php.ini review (risky settings, and whether it changed in the window)'
  $inis = New-Object System.Collections.Generic.List[string]
  if ($env:PHPRC) { $inis.Add((Join-Path $env:PHPRC 'php.ini')) }
  foreach ($b in (Find-PhpBinaries)) { $inis.Add((Join-Path (Split-Path -Parent $b) 'php.ini')) }
  foreach ($d in $FixedDrives) {
    $inis.AddRange([string[]]@("$d\xampp\php\php.ini", "$d\Windows\php.ini",
      "$d\wamp64\bin\php\php*\php.ini", "$d\laragon\bin\php\*\php.ini", "$d\php\php.ini"))
  }
  $iniFound = $false
  foreach ($pat in ($inis | Sort-Object -Unique)) {
    foreach ($ini in (Get-Item -Path $pat -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
      $iniFound = $true
      $age = if ($ini.LastWriteTime -ge $SinceDate) { '  <-- CHANGED IN WINDOW' } else { '' }
      Say ('  {0}  (modified {1:yyyy-MM-dd HH:mm}){2}' -f $ini.FullName, $ini.LastWriteTime, $age)
      $risky = @()
      foreach ($line in (Get-Content -LiteralPath $ini.FullName -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith(';')) { continue }
        $m = [regex]::Match($t, '^(allow_url_include|allow_url_fopen|auto_prepend_file|auto_append_file|disable_functions|open_basedir|display_errors|expose_php|enable_dl|register_globals|upload_tmp_dir|session\.save_path|extension_dir)\s*=\s*(.*)$', 'IgnoreCase')
        if (-not $m.Success) { continue }
        $key = $m.Groups[1].Value.ToLower(); $val = $m.Groups[2].Value.Trim().Trim('"')
        switch ($key) {
          'allow_url_include' { if ($val -match '^(1|on|true|yes)$') { $risky += "allow_url_include=$val  <-- remote code include enabled" } }
          'auto_prepend_file' { if ($val) { $risky += "auto_prepend_file=$val  <-- runs on EVERY request; classic webshell persistence" } }
          'auto_append_file'  { if ($val) { $risky += "auto_append_file=$val  <-- runs on EVERY request" } }
          'register_globals'  { if ($val -match '^(1|on|true|yes)$') { $risky += "register_globals=$val  <-- removed in PHP 5.4; ancient config" } }
          'disable_functions' { if (-not $val) { $risky += 'disable_functions= (empty: exec/system/proc_open all callable)' } }
          'open_basedir'      { if (-not $val) { $risky += 'open_basedir= (empty: PHP can read the whole disk)' } }
          'enable_dl'         { if ($val -match '^(1|on|true|yes)$') { $risky += "enable_dl=$val" } }
          default             { }
        }
        if ($key -eq 'upload_tmp_dir' -or $key -eq 'session.save_path') {
          if ($val) { $script:PhpTmpDirs += $val }
        }
      }
      foreach ($x in $risky) { Say "      $x" }
      if (-not $risky) { Say '      (no high-risk directive found)' }
    }
  }
  if (-not $iniFound) { Say '   (no php.ini found - pass -WebRoot or check the SAPI configuration)' }

  Sec "21. persistence: services, scheduled tasks, Run keys and startup items touching php/httpd"
  $n21 = 0
  foreach ($svc in (Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'php|httpd|nginx|apache' })) {
    Say ('  service  {0,-22} {1,-9} {2}' -f $svc.Name, $svc.State, $svc.PathName)
    $n21++
  }
  if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    foreach ($tk in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
      $acts = @($tk.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
      if ($acts -notmatch 'php|httpd|apache|cmd\.exe|powershell|wscript|cscript|certutil|bitsadmin') { continue }
      Say ('  task     {0}{1}  [{2}]' -f $tk.TaskPath, $tk.TaskName, $acts.Trim())
      $n21++
      if ($n21 -gt 40) { break }
    }
  }
  foreach ($tf in (Get-ChildItem -LiteralPath "$env:SystemRoot\System32\Tasks" -Recurse -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -ge $SinceDate } | Select-Object -First 10)) {
    Say ('  task-file changed {0:yyyy-MM-dd HH:mm}  {1}' -f $tf.LastWriteTime, $tf.FullName)
    $n21++
  }
  foreach ($k in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
    $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($pn in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
      if ($pn.Value -notmatch 'php|httpd|apache|cmd\.exe|powershell|wscript|cscript|certutil|\.hta|mshta') { continue }
      Say ('  run-key  {0}\{1} = {2}' -f $k, $pn.Name, $pn.Value)
      $n21++
    }
  }
  foreach ($sf in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                    "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
    foreach ($f in (Get-ChildItem -LiteralPath $sf -File -ErrorAction SilentlyContinue)) {
      Say ('  startup  {0:yyyy-MM-dd HH:mm}  {1}' -f $f.LastWriteTime, $f.FullName)
      $n21++
    }
  }
  try {
    foreach ($c in (Get-CimInstance -Namespace 'root/subscription' -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)) {
      Say ('  wmi-consumer {0}  [{1} {2}]' -f $c.Name, $c.ExecutablePath, $c.CommandLineTemplate)
      $n21++
    }
  } catch {}
  if ($n21 -eq 0) { Say '   (nothing matching php/httpd/LOLBin)' }

  Sec "22. PHP session and temp dirs (files changed since $SinceLabel)"
  $tmpDirs = New-Object System.Collections.Generic.List[string]
  foreach ($d in $script:PhpTmpDirs) { if ($d) { $tmpDirs.Add($d) } }
  foreach ($d in $FixedDrives) {
    $tmpDirs.AddRange([string[]]@("$d\xampp\tmp", "$d\wamp64\tmp", "$d\wamp\tmp", "$d\laragon\tmp", "$d\Windows\Temp"))
  }
  if ($env:TEMP) { $tmpDirs.Add($env:TEMP) }
  $any22 = $false
  foreach ($d in (Expand-Candidates $tmpDirs)) {
    $sess = @(Get-ChildItem -LiteralPath $d -Filter 'sess_*' -File -ErrorAction SilentlyContinue)
    $phps = @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue |
              Where-Object { (Test-PhpIsh $_) -and $_.LastWriteTime -ge $SinceDate })
    Say ('  {0}: {1} session files, {2} PHP-executable files changed in window' -f $d, $sess.Count, $phps.Count)
    foreach ($f in ($phps | Select-Object -First 10)) { Say ('      {0:yyyy-MM-dd HH:mm}  {1}' -f $f.LastWriteTime, $f.FullName) }
    $any22 = $true
  }
  if (-not $any22) { Say '   (no PHP temp/session dir found)' }
}

# ---- decide whether to run the host checks ----
function Test-RunPostex {
  if ($NoPostex)               { return $false }
  if ($Postex -or $OnlyPostex) { return $true }
  if ($env:RUN_POSTEX) {
    if ($env:RUN_POSTEX -match '^(y|yes|1|true)$') { return $true }
    if ($env:RUN_POSTEX -match '^(n|no|0|false)$') { return $false }
  }
  if (-not [Environment]::UserInteractive) { return $false }
  $ans = $null
  try { $ans = Read-Host "`nLog scan finished. Run the post-exploitation host checks now? [y/N]" } catch { return $false }
  return ($ans -match '^(y|yes)$')
}

if (Test-RunPostex) {
  Invoke-PostexWindows
} elseif ($NoPostex) {
  Say ''; Say '---- host checks skipped (-NoPostex) ----'
} elseif ($env:RUN_POSTEX) {
  Say ''; Say "---- host checks skipped (RUN_POSTEX=$($env:RUN_POSTEX)) ----"
} else {
  Say ''; Say '---- host checks skipped (no interactive console - re-run with -Postex, -OnlyPostex or RUN_POSTEX=yes) ----'
}

Say ''
Say '---- done (read-only; report may contain visitor IPs, hostnames and file paths - do not publish) ----'
