# phphunt

Two self-contained, read-only scripts that check an Apache + PHP server for signs
of exploitation. Both scan the web server's access and error logs, then — after a
prompt — inspect the host itself (changed files, webshell-ish code, suspicious
processes, sockets and persistence).

| Script | Platform | Stacks |
|---|---|---|
| `php-hunt.sh`  | Linux (Debian/RHEL/SUSE/Alpine), macOS | Apache httpd, nginx, mod_php, php-fpm, php-cgi |
| `php-hunt.ps1` | Windows (PowerShell 5.1+, native) | Apache Lounge/ASF, XAMPP, WampServer, Laragon, Bitnami, UniServer, IIS |

They change nothing: they only read and print a report. The shell script writes
a reference timestamp and a file index under its own `mktemp -d` directory, and
removes that directory on exit (including on Ctrl-C); the PowerShell script
writes nothing at all. Neither touches anything outside that temp directory.

The PowerShell script is a native port, not a wrapper — **no Git Bash, MSYS2,
Cygwin or WSL is needed on Windows**. It uses only PowerShell, .NET and CIM/WMI.

---

# Linux / macOS: `php-hunt.sh`

## Run it with a one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/ChriZzn/phphunt/main/php-hunt.sh | sudo bash
```

Root is needed to read the logs and the webroots. The prompt is read from
`/dev/tty`, so it still works through the pipe. If there is no terminal (e.g. a
CI pipe), the host checks are skipped unless you force them. Or run it locally:

```bash
sudo bash php-hunt.sh
```

## Options

```
--logdir DIR        Apache log directory (auto-detected by default; repeatable)
--webroot DIR       web root to inspect (auto-detected by default; repeatable)
--webuser USER      web-server account (alias --user; auto: www-data/apache/httpd/_www/nginx)
--since DATE        flag files changed since YYYY-MM-DD (default: last 7 days)
--trusted-ua STR    user-agent substring of a known client to leave out of the
                    POST / user-agent sections (repeatable)
--postex            run the host checks without asking
--no-postex         skip the host checks (do not ask)
--only-postex       skip the log scan, run only the host checks
--recent-logs       only read log files modified since --since (skips old
                    rotations; much faster, but sections 9/10 lose history)
-q, --quiet         no progress output on stderr (the report is unchanged)
-h, --help          show this help
```

The prompt can be pre-answered non-interactively with `RUN_POSTEX=yes` or `RUN_POSTEX=no`
(useful for the piped one-liner). The script auto-detects Debian (`apache2`/`www-data`)
vs RHEL (`httpd`/`apache`) defaults; override any of them with the flags above.

It adapts to three different userlands, probed by capability rather than by
name: GNU (`find -printf`, `date -d @N`, `stat -c`), BSD/macOS (`date -r N`,
`stat -f`) and busybox/Alpine (`stat -c`, but no `find -printf`). The file
window is a temporary reference timestamp compared with `find -newer`, so it
behaves the same on all three. Rotated `.gz`, `.bz2`, `.xz` and `.zst` logs are
read in place. Under WSL it checks the Linux side only — run `php-hunt.ps1` on
the Windows side for the Windows stacks.

### Limits and safeguards

- Each webroot is walked **once**; sections 11-14 and 20-21 all read that one
  index (they used to do a separate full walk each — seven per root).
- Counters for paths, methods and user-agents are capped (200k / 5k keys) and
  wholly-numeric path segments are collapsed (`/orders/12345/` → `/orders/N/`),
  so a REST API with IDs in the URL cannot grow awk's tables without bound. The
  report says so if a cap was reached.
- Only the top five source IPs per pattern are kept, in awk, rather than writing
  every IP seen to the temp file and sorting it afterwards.
- The index is capped at 400k files per root and the report states when it was
  truncated.
- The temp directory is removed on `INT`/`TERM`/`HUP` as well as on exit.
- `php -n -v` is used to read versions, so a tampered `auto_prepend_file` in
  `php.ini` does not execute during the scan.

## What it checks

**Log scan (always runs):**

- PHP/Apache worker crashes (segfaults, aborts, heap / OOM corruption)
- PHP request-parsing and memory-limit errors
- PHP-CGI argument injection (CVE-2024-4577 style `%AD` / `allow_url_include`)
- `php://`, `data://`, `expect://`, `phar://` wrappers in requests
- phpunit `eval-stdin.php`, Laravel Ignition and similar known PHP RCE paths
- code in URLs (`<?php`, `base64_decode`, `system(`, `phpinfo` …)
- path traversal and Xdebug triggers
- security-scanner fingerprints (watchTowr / calif / nuclei …)
- unexpected POSTs, 5xx responses, malformed requests, and requests per day

**Host checks (after the prompt, or `--postex` / `--only-postex`):**

- PHP-executable files in the webroots changed since the window start
- files owned by the web-server user (writable by the server)
- PHP files under upload / cache / tmp / image dirs
- webshell-ish code (eval/assert/exec on request input, base64+eval)
- processes running as the web user other than Apache
- files owned by the web user in `/tmp`, `/var/tmp`, `/dev/shm`
- outbound / listening sockets other than 80/443
- web-user crontab / SSH keys
- plus the php2shell checks below

---

# Windows: `php-hunt.ps1`

A native PowerShell port. Same report, same section numbers, no Unix tooling.

## Run it

PowerShell is script-blocked by default, so pass the policy for this process only:

```powershell
powershell -ExecutionPolicy Bypass -File .\php-hunt.ps1
```

Or download and run in one go (from an **Administrator** PowerShell):

```powershell
iwr -UseBasicParsing https://raw.githubusercontent.com/ChriZzn/phphunt/main/php-hunt.ps1 -OutFile $env:TEMP\php-hunt.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\php-hunt.ps1
```

Run it elevated: the logs, other users' processes, service configuration and the
ACL audit are only partly readable otherwise (the report says so when it is not).

## Options

```
-LogDir    DIR[,DIR]   log directory (auto-detected by default)
-WebRoot   DIR[,DIR]   web root to inspect (auto-detected by default)
-Since     yyyy-MM-dd  flag files changed since this date (default: last 7 days)
-TrustedUa STR[,STR]   user-agent substring to leave out of the POST / UA sections
-Postex                run the host checks without asking
-NoPostex              skip the host checks (do not ask)
-OnlyPostex            skip the log scan, run only the host checks
-Quiet                 no progress output on stderr (the report is unchanged)
-?                     full help (comment-based; also `Get-Help .\php-hunt.ps1 -Full`)
```

`RUN_POSTEX=yes` / `RUN_POSTEX=no` pre-answers the prompt non-interactively, as on
Unix. Without an interactive console the host checks are skipped unless forced.

## How it finds your stack

Detection is layered, most reliable first:

1. The running `httpd.exe` / `nginx.exe` process, and any matching service — its
   path gives the ServerRoot.
2. That ServerRoot's `conf\httpd.conf`, plus one level of `Include` /
   `IncludeOptional` (where vhost `DocumentRoot`s live), parsed for
   `DocumentRoot`, `ErrorLog`, `CustomLog` and `TransferLog`. Piped loggers
   (`|rotatelogs`) are skipped — there is no file to read.
3. Well-known layouts on every fixed drive: `xampp`, `wamp64`/`wamp`, `laragon`,
   `Apache24`/`Apache2.4`, `Program Files\Apache Software Foundation`, `Bitnami`,
   `UniServerZ`, `nginx`, `inetpub`.

PHP versions are read from the **PE version resource** of every `php.exe`,
`php-cgi.exe`, `php-fpm.exe` and `php*apache2_4.dll` found — the binary is never
executed, so a tampered `php.ini` (`auto_prepend_file`) cannot run during the scan.

Both Apache/NCSA combined logs and **IIS W3C extended logs** (`u_ex*.log`, with
the column order read from the `#Fields:` header) are parsed, as are `.gz`
rotations.

## What the Windows host checks add

Beyond the Unix checks, translated to Windows:

- **ACL audit** instead of file ownership — webroot PHP files that grant Write /
  Modify / FullControl to `Everyone`, `BUILTIN\Users`, `Authenticated Users`,
  `IUSR`, `IIS_IUSRS` or `NETWORK SERVICE`. A PHP file the web identity can
  rewrite is a webshell waiting to happen, and XAMPP installs are routinely wide open.
- **Web server spawning a child** — the Windows form of Elastic's *Payload
  Execution by Web Server*: any child of `httpd.exe`, `php-cgi.exe`, `php-fpm.exe`,
  `nginx.exe` or `w3wp.exe` that is not itself a PHP/Apache process. Known
  LOLBins (`cmd`, `powershell`, `wscript`, `certutil`, `bitsadmin`, `mshta`,
  `rundll32`, `regsvr32`, …) are marked `!!`.
- **`php.ini` review** — `allow_url_include`, an empty `disable_functions` or
  `open_basedir`, `enable_dl`, and especially a non-empty `auto_prepend_file` /
  `auto_append_file` (code that runs on *every* request: classic webshell
  persistence). It also flags a `php.ini` modified inside the window.
- **Image polyglots are byte-scanned.** Files are read as Latin-1, so a real JPEG
  or GIF with PHP appended is matched as reliably as a text file.
- **Windows persistence** — services and scheduled tasks whose action touches
  php/httpd or a LOLBin, task files changed in the window, `Run`/`RunOnce` keys,
  Startup folders, and WMI `CommandLineEventConsumer` subscriptions.
- **Windows LOLBin IOC pattern** in requests — `cmd.exe`, `powershell`,
  `certutil`, `bitsadmin`, `mshta`, UNC paths and drive-letter paths in a URL.
- **Session / temp dirs** — `upload_tmp_dir` and `session.save_path` taken from
  the `php.ini` that was actually found, plus `xampp\tmp`, `wamp*\tmp`,
  `laragon\tmp`, `C:\Windows\Temp` and `%TEMP%`.

## Limits and safeguards

The script is built not to fall over on a busy server:

- Each webroot is enumerated **once** and the index reused by every file-based
  section; junctions and symlinks are never followed, so the walk cannot loop.
- Counters for paths, IPs, methods and user-agents are capped (200k / 5k keys),
  and digit runs in a path are normalised (`/orders/12345/` → `/orders/N/`) so a
  REST API with IDs in the URL cannot grow the tables without bound.
- Caps: 250k files indexed per webroot, 8 MB per file for content scans, 20k
  image/text files byte-scanned. The report states when a cap was hit.
- Unreadable directories are counted and reported rather than silently skipped.

---

# php2shell coverage (CVE-2026-109618 / CVE-2026-109619)

Applies to both scripts.

"php2shell" is the nickname for two PHP-core RCE flaws that leaked before coordinated
disclosure: **CVE-2026-109618** (RCE via out-of-memory corruption) and **CVE-2026-109619**
(RCE via stale global state). They are fixed in **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**
(8.1 and older are EOL and need a distro backport). `mod_php` is the highest-risk SAPI.

Per [Elastic Security Labs](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)
there is **no public request signature** for these bugs, so they are detected by
version and behaviour rather than by log pattern:

- **PHP version check** (always runs) — every PHP SAPI found, the `mod_php` module files
  and the installed packages are compared against the fixed versions above. On Unix the
  version comes from `php -v` and `dpkg`/`rpm`; on Windows from each binary's PE version
  resource, so nothing is executed.
- **"Web server spawns a shell"** — a point-in-time port of Elastic's *Payload Execution
  by Web Server* rule. Unix: any process whose parent is `apache2`/`httpd`/`nginx`/
  `php-fpm*`/`lsphp*`/`php-cgi`/`frankenphp` and which is a shell, or runs
  `curl`/`wget`/`nc`/`socat`, `/dev/tcp`, `base64 -d`, reads `/etc/shadow`, or hits
  `169.254.169.254`. Windows: any non-PHP child of `httpd.exe`/`php-cgi.exe`/
  `php-fpm.exe`/`nginx.exe`/`w3wp.exe`, with LOLBins marked `!!`.
- **OOM / memory-corruption** terms added to the error-log crash scan (the OOM-corruption
  flaw tends to crash workers).
- **Webshell, upload and persistence sweeps** — expanded webshell signatures (exec on
  request input, `proc_open`/`popen`/`pcntl_exec`), PHP double-extensions (`avatar.php.jpg`),
  image polyglots (image/text files that contain `<?php`), recon/reverse-shell/cloud-metadata
  strings in recently-changed files, and new/changed `systemd` units and cron entries.

Most of this lives in the host checks, so answer **yes** at the prompt (or pass
`--postex` / `-Postex`) to get the php2shell-specific coverage. The version check
runs regardless.

# Notes

- It looks for general signs of PHP attacks, not a signature for any one CVE (php2shell
  included — those two bugs have no public request signature).
- Access logs don't record POST bodies, so payloads sent in a request body won't show up
  in the log scan. That is what the host checks are for: crashes, unexpected files,
  processes and persistence.
- The report can contain visitor IPs, hostnames and file paths. Don't publish it.

# Credits

This project builds on, and borrows parts from, prior work:

- **[ghostinthecable/php-hunting](https://github.com/ghostinthecable/php-hunting)** —
  the original `php-hunt.sh` log-scan and on-host check logic this script is based on.
- **[Elastic Security Labs — "php2shell: PHP RCE detection"](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)**
  by Ruben Groenewoud and Bryan Porras Blanch — source of the php2shell
  (CVE-2026-109618 / CVE-2026-109619) analysis, fixed-version list, and the
  *Payload Execution by Web Server* detection logic adapted here.

All copied material belongs to its respective authors; thanks to them.

# License

MIT
