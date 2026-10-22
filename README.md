# phphunt

`php-hunt.sh` is a single, self-contained, read-only bash script that checks an
Apache + PHP server for signs of exploitation. It scans the Apache access and
error logs, then — after a prompt — inspects the host itself (changed files,
webshell-ish code, suspicious processes, sockets and persistence).

It changes nothing: it only reads and prints a report. (It writes one short-lived
timestamp reference file in a temp dir and removes it on exit.) It runs on Linux
(Debian/RHEL/SUSE/Alpine), macOS and Windows (Git Bash / MSYS2 / Cygwin / WSL).

## Run it with a one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/ChriZzn/phphunt/main/php-hunt.sh | sudo bash
```

Root is needed to read the logs and the webroots (on Windows, run Git Bash as
Administrator if the logs are not readable by your account). The prompt is read
from `/dev/tty`, so it still works through the pipe. If there is no terminal
(e.g. a CI pipe), the host checks are skipped unless you force them. Or run it
locally:

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
-h, --help          show this help
```

The prompt can be pre-answered non-interactively with `RUN_POSTEX=yes` or `RUN_POSTEX=no`
(useful for the piped one-liner). The script auto-detects Debian (`apache2`/`www-data`)
vs RHEL (`httpd`/`apache`) defaults; override any of them with the flags above.

On macOS and Windows it adapts: under Git Bash / MSYS2 / Cygwin it checks XAMPP,
WAMP, Apache24 and Bitnami installs (`netstat`/`tasklist` instead of `ss`/`ps`),
and under WSL it checks the Linux side plus Windows stacks under `/mnt/<drive>`.
The file-window check uses `find -newer` against a temporary reference timestamp,
so it works with GNU and BSD `find` alike.

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

## php2shell coverage (CVE-2026-109618 / CVE-2026-109619)

"php2shell" is the nickname for two PHP-core RCE flaws that leaked before coordinated
disclosure: **CVE-2026-109618** (RCE via out-of-memory corruption) and **CVE-2026-109619**
(RCE via stale global state). They are fixed in **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**
(8.1 and older are EOL and need a distro backport). `mod_php` is the highest-risk SAPI.

Per [Elastic Security Labs](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)
there is **no public request signature** for these bugs, so this script detects them by
version and behaviour rather than by log pattern:

- **PHP version check** (always runs) — every PHP SAPI on `PATH`, the `mod_php` module
  files and the installed packages are compared against the fixed versions above.
- **"Web server spawns a shell"** — a point-in-time port of Elastic's *Payload Execution
  by Web Server* rule: any process whose parent is `apache2`/`httpd`/`nginx`/`php-fpm*`/
  `lsphp*`/`php-cgi`/`frankenphp` and which is a shell, or runs `curl`/`wget`/`nc`/`socat`,
  `/dev/tcp`, `base64 -d`, reads `/etc/shadow`, or hits `169.254.169.254`.
- **OOM / memory-corruption** terms added to the error-log crash scan (the OOM-corruption
  flaw tends to crash workers).
- **Webshell, upload and persistence sweeps** — expanded webshell signatures (exec on
  request input, `proc_open`/`popen`/`pcntl_exec`), PHP double-extensions (`avatar.php.jpg`),
  image polyglots (image/text files that contain `<?php`), recon/reverse-shell/cloud-metadata
  strings in recently-changed files, and new/changed `systemd` units and cron entries.

Most of this lives in the host checks, so answer **yes** at the prompt (or pass `--postex`)
to get the php2shell-specific coverage. The version check runs regardless.

## Notes

- It looks for general signs of PHP attacks, not a signature for any one CVE (php2shell
  included — those two bugs have no public request signature).
- Access logs don't record POST bodies, so payloads sent in a request body won't show up
  in the log scan. That is what the host checks are for: crashes, unexpected files,
  processes and persistence.
- The report can contain visitor IPs, hostnames and file paths. Don't publish it.

## Credits

This project builds on, and borrows parts from, prior work:

- **[ghostinthecable/php-hunting](https://github.com/ghostinthecable/php-hunting)** —
  the original `php-hunt.sh` log-scan and on-host check logic this script is based on.
- **[Elastic Security Labs — "php2shell: PHP RCE detection"](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)**
  by Ruben Groenewoud and Bryan Porras Blanch — source of the php2shell
  (CVE-2026-109618 / CVE-2026-109619) analysis, fixed-version list, and the
  *Payload Execution by Web Server* detection logic adapted here.

All copied material belongs to its respective authors; thanks to them.

## License

MIT
